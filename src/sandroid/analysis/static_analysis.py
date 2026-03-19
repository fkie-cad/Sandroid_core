import json
import os
import shutil
import time
from logging import getLogger

import click

from sandroid.core.adb_utils import (
    format_adb_error,
    is_adb_error_actionable,
    log_adb_result,
)
from sandroid.core.console import SandroidConsole
from sandroid.core.events.events import AnalysisCompleted, TaskOutput

from .base_di import DataGatherBase

try:
    from sandroid.config import get_config
except ImportError:
    get_config = None


def _get_display_value(field: str, default):
    """Read a display config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().display, field, default)
    except Exception:
        pass
    return default


try:
    from dexray_insight import asam
except ImportError:
    logger = getLogger(__name__)
    logger.warning(
        "dexray-insight package not installed. Static analysis will be disabled."
    )
    asam = None

logger = getLogger(__name__)


class StaticAnalysis(DataGatherBase):
    """Handles static analysis of APK files using dexray-insight (formerly ASAM).

    Supports two analysis modes:
    1. Local APK: Analyze an APK file directly from the filesystem
    2. Device APK: Pull and analyze an app installed on the connected device

    Examples:
        # Analyze local APK file
        analyzer = StaticAnalysis(apk_path="/path/to/app.apk")
        analyzer.gather(interactive=False)

        # Analyze installed app (pulls from device)
        analyzer = StaticAnalysis()
        analyzer.gather()  # Uses spotlight app from Toolbox
    """

    def __init__(self, apk_path: str | None = None, **kwargs):
        """Initialize StaticAnalysis.

        Args:
            apk_path: Optional path to local APK file. If provided, the APK is
                analyzed directly without device interaction. If not provided,
                the spotlight app is pulled from the connected device.
            **kwargs: Arguments passed to DataGatherBase (forensic_service, adb, config, logger)
        """
        super().__init__(**kwargs)
        self._apk_path = apk_path  # Local APK path (optional)
        # Instance variables (migrated from class variables for proper encapsulation)
        self.last_results = {}
        self.last_analysed_app = "no app name yet"
        self._analysis_config = {
            "run_security_analysis": True,
            "verbose_output": False,
        }
        self._output_files = []

    def _interactive_configuration(self) -> dict | None:
        """Interactive configuration menu for dexray-insight options.

        Returns:
            Configuration dict if user confirms, None if cancelled
        """
        from sandroid.core.ui_request_bus import UIRequestBus, request_toggle_config

        # Check if TUI mode is active
        bus = UIRequestBus.get()
        if bus.has_active_handler():
            # TUI mode - use toggle config modal
            toggle_options = {
                "Security Analysis (vulnerability scan)": True,
                "Verbose Output (detailed logging)": False,
            }

            result = request_toggle_config(
                title="Dexray-Insight Configuration",
                options=toggle_options,
                message="Configure static analysis options",
            )

            if result is None:
                return None

            return {
                "run_security_analysis": result.get(
                    "Security Analysis (vulnerability scan)", True
                ),
                "verbose_output": result.get(
                    "Verbose Output (detailed logging)", False
                ),
            }

        # Rich mode - use console and click.getchar()
        from sandroid.tui.utils.box_renderer import make_box_line

        console = SandroidConsole.get()

        # Box width (inner content width) - read from config
        _DEFAULT_BOX_WIDTH = 60
        BOX_WIDTH = _get_display_value("box_width", _DEFAULT_BOX_WIDTH)

        _box_line = make_box_line(BOX_WIDTH)

        settings = {
            "run_security_analysis": True,
            "verbose_output": False,
        }

        while True:
            console.clear()

            console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
            console.print(_box_line("[bold]Dexray-Insight Configuration[/bold]"))
            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")

            sec_status = (
                "[success]●[/success]"
                if settings["run_security_analysis"]
                else "[error]○[/error]"
            )
            verbose_status = (
                "[success]●[/success]"
                if settings["verbose_output"]
                else "[error]○[/error]"
            )

            console.print(
                _box_line(
                    f"[accent]\\[S][/accent] Security Analysis: {sec_status} (vulnerability scan)",
                    align="left",
                )
            )
            console.print(
                _box_line(
                    f"[accent]\\[V][/accent] Verbose Output:    {verbose_status} (detailed logging)",
                    align="left",
                )
            )

            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
            console.print(
                _box_line(
                    "[success]\\[Enter][/success] Start Analysis    [warning]\\[Esc/Q][/warning] Cancel",
                    align="left",
                )
            )
            console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")

            try:
                choice = click.getchar().lower()
            except (KeyboardInterrupt, EOFError):
                return None

            if choice in ("\r", "\n"):
                return settings
            if choice in ("\x1b", "q"):
                return None
            if choice == "s":
                settings["run_security_analysis"] = not settings[
                    "run_security_analysis"
                ]
            elif choice == "v":
                settings["verbose_output"] = not settings["verbose_output"]

    def gather(self, interactive: bool = True) -> bool:
        """Gathers and analyzes an APK file using dexray-insight.

        Supports two modes:
        1. Local APK: If `apk_path` was provided at init, analyzes that file directly
        2. Device APK: Otherwise, pulls the spotlight app from the connected device

        Args:
            interactive: If True, show interactive configuration menu first

        Returns:
            True if analysis completed, False if cancelled or failed

        Raises:
            Exception: If dexray-insight returns None or there is an error during analysis.
        """
        if asam is None:
            logger.error("dexray-insight not available. Static analysis skipped.")
            self.last_results = {"error": "dexray-insight not installed"}
            return False

        # Track analysis start time for duration calculation
        start_time = time.time()

        # Show interactive configuration if requested
        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("Dexray-insight configuration cancelled")
                return False
            self._analysis_config = config

        # Route to appropriate analysis method
        if self._apk_path:
            return self._analyze_local_apk(self._apk_path, start_time)
        return self._analyze_device_apk(start_time)

    def _analyze_local_apk(self, apk_path: str, start_time: float) -> bool:
        """Analyze a local APK file without device interaction.

        Args:
            apk_path: Path to the local APK file
            start_time: Analysis start time for duration tracking

        Returns:
            True if analysis completed, False if failed
        """
        from pathlib import Path

        apk_file = Path(apk_path)

        # Validate the APK file exists
        if not apk_file.exists():
            logger.error(f"APK file not found: {apk_path}")
            self.last_results = {"error": f"APK file not found: {apk_path}"}
            return False

        if not apk_file.suffix.lower() == ".apk":
            logger.error(f"File is not an APK: {apk_path}")
            self.last_results = {"error": f"File is not an APK: {apk_path}"}
            return False

        # Extract app name from filename (without .apk extension)
        apk_name = apk_file.stem
        self.last_analysed_app = apk_name

        # Use dexray_insight folder at results root
        insight_dir = f"{os.getenv('RESULTS_PATH', '')}dexray_insight/"
        os.makedirs(insight_dir, exist_ok=True)

        logger.info(f"Analyzing local APK: {apk_path}")
        logger.info("Running dexray-insight static analysis. This might take a while.")

        return self._run_dexray_analysis(
            str(apk_file), apk_name, insight_dir, start_time, cleanup_apk=False
        )

    def _analyze_device_apk(self, start_time: float) -> bool:
        """Pull and analyze an APK from the connected device.

        Uses the spotlight app from Toolbox to determine which app to analyze.

        Args:
            start_time: Analysis start time for duration tracking

        Returns:
            True if analysis completed, False if failed
        """
        # Use dexray_insight folder at results root (sibling to raw/, like dexray_intercept/)
        insight_dir = f"{os.getenv('RESULTS_PATH', '')}dexray_insight/"
        os.makedirs(insight_dir, exist_ok=True)

        spotlight_app = self._get_toolbox().get_spotlight_application()
        # Handle both string and tuple returns for backwards compatibility
        apk_name = (
            spotlight_app[0]
            if isinstance(spotlight_app, (list, tuple))
            else spotlight_app
        )
        self.last_analysed_app = apk_name

        # Get APK path on device
        apk_path, stderr = self._send_adb_command("shell pm path " + apk_name)
        log_adb_result(f"shell pm path {apk_name}", apk_path, stderr)
        if stderr and is_adb_error_actionable(stderr):
            logger.warning(f"Could not get APK path for {apk_name}: {stderr}")
            self.last_results = {
                "error": f"Could not get APK path: {stderr}",
                "app_name": apk_name,
            }
            return False

        # Parse APK path (format: "package:/path/to/app.apk")
        device_apk_path = apk_path[8:-1]
        local_apk_path = f"{insight_dir}{apk_name}.apk"

        logger.debug(
            f"Running dexray-insight for {apk_name} located at {local_apk_path}"
        )
        logger.info(
            "Statically analyzing spotlight App with dexray-insight. This might take a while."
        )

        # Pull APK from device
        pull_stdout, pull_stderr = self._send_adb_command(
            f"pull {device_apk_path} {local_apk_path}"
        )
        log_adb_result(f"pull {device_apk_path}", pull_stdout, pull_stderr)
        if pull_stderr and is_adb_error_actionable(pull_stderr):
            logger.error(
                format_adb_error(f"pull {device_apk_path}", pull_stdout, pull_stderr)
            )
            self.last_results = {
                "error": f"APK pull failed: {pull_stderr}",
                "app_name": apk_name,
            }
            return False

        if not os.path.exists(local_apk_path):
            logger.error("Something went wrong pulling spotlight apk")
            self.last_results = {
                "error": "APK file not found after pull",
                "app_name": apk_name,
            }
            return False

        return self._run_dexray_analysis(
            local_apk_path, apk_name, insight_dir, start_time, cleanup_apk=True
        )

    def _run_dexray_analysis(
        self,
        apk_file_path: str,
        apk_name: str,
        insight_dir: str,
        start_time: float,
        cleanup_apk: bool = False,
    ) -> bool:
        """Run dexray-insight analysis on an APK file.

        This is the shared analysis logic used by both local and device APK modes.

        Args:
            apk_file_path: Full path to the APK file to analyze
            apk_name: Name/identifier for the APK (used in results)
            insight_dir: Directory where result files should be stored
            start_time: Analysis start time for duration tracking
            cleanup_apk: If True, delete the APK file after analysis (for pulled APKs)

        Returns:
            True if analysis completed, False if failed
        """
        try:
            # Use dexray-insight API with configuration
            results, result_file_name, security_result_file_name = (
                asam.start_apk_static_analysis(
                    apk_file_path=apk_file_path,
                    do_signature_check=False,
                    apk_to_diff=None,
                    print_results_to_terminal=True,
                    is_verbose=self._analysis_config.get("verbose_output", False),
                    do_sec_analysis=self._analysis_config.get(
                        "run_security_analysis", True
                    ),
                    exclude_net_libs=None,
                )
            )

            if results is None:
                raise Exception("dexray-insight returned None")

            # Move output files to insight_dir if they were created in cwd
            if result_file_name and os.path.exists(result_file_name):
                # File exists at returned path (might be in cwd)
                if not os.path.dirname(result_file_name):
                    # No directory in path - file is in cwd, move it
                    dest_path = os.path.join(insight_dir, result_file_name)
                    shutil.move(result_file_name, dest_path)
                    result_file_name = dest_path
                    logger.debug(f"Moved result file to {dest_path}")

            if security_result_file_name and os.path.exists(security_result_file_name):
                # File exists at returned path (might be in cwd)
                if not os.path.dirname(security_result_file_name):
                    # No directory in path - file is in cwd, move it
                    dest_path = os.path.join(insight_dir, security_result_file_name)
                    shutil.move(security_result_file_name, dest_path)
                    security_result_file_name = dest_path
                    logger.debug(f"Moved security result file to {dest_path}")

            # Convert results to dictionary for compatibility
            self.last_results = {
                "analysis_results": results.to_dict(),
                "json_output": results.to_json(),
                "app_name": apk_name,
                "result_files": {
                    "main_result": result_file_name,
                    "security_result": security_result_file_name,
                },
            }

            # Track output files for exit summary
            self._output_files = []
            if result_file_name:
                self._output_files.append(result_file_name)
            if security_result_file_name:
                self._output_files.append(security_result_file_name)

            # Register tool usage for exit summary
            self._get_toolbox().mark_tool_used(
                "dexray-insight", files=self._output_files
            )

            logger.info(f"Static analysis completed successfully for {apk_name}")

            # Calculate analysis duration
            duration = time.time() - start_time

            # Publish TaskOutput events for important findings
            self._publish_analysis_events(duration)

            return True

        except Exception as e:
            logger.error("dexray-insight produced an error.")
            logger.error("This is not an issue with Sandroid. Empty output appended.")
            logger.error(str(e))
            self.last_results = {"error": str(e), "app_name": apk_name}
            return False

        finally:
            # Clean up APK file if requested (for pulled APKs)
            if cleanup_apk:
                try:
                    os.remove(apk_file_path)
                except OSError as e:
                    logger.warning(f"Could not remove APK file: {e}")

    def _publish_analysis_events(self, duration: float) -> None:
        """Publish events for analysis findings.

        Args:
            duration: Analysis duration in seconds
        """
        analysis_data = self.last_results.get("analysis_results", {})
        if isinstance(analysis_data, dict):
            # Report permissions found
            permissions = analysis_data.get("permissions", [])
            if permissions:
                TaskOutput(
                    task_name="static_analysis",
                    message=f"Found {len(permissions)} permissions",
                    level="info",
                    source="static_analysis",
                ).publish()

            # Report activities found
            activities = analysis_data.get("activities", [])
            if activities:
                TaskOutput(
                    task_name="static_analysis",
                    message=f"Found {len(activities)} activities",
                    level="info",
                    source="static_analysis",
                ).publish()

            # Report services found
            services = analysis_data.get("services", [])
            if services:
                TaskOutput(
                    task_name="static_analysis",
                    message=f"Found {len(services)} services",
                    level="info",
                    source="static_analysis",
                ).publish()

            # Report receivers found
            receivers = analysis_data.get("receivers", [])
            if receivers:
                TaskOutput(
                    task_name="static_analysis",
                    message=f"Found {len(receivers)} receivers",
                    level="info",
                    source="static_analysis",
                ).publish()

        # Publish analysis completion event
        AnalysisCompleted(
            run_number=1,
            total_runs=1,
            files_changed=0,
            new_files=len(self._output_files),
            duration_seconds=duration,
            source="static_analysis",
        ).publish()

    def return_data(self):
        """Returns the results of the last static analysis using dexray-insight.

        :returns: The results of the last static analysis.
        :rtype: dict
        """
        if not self.last_results:
            return {}

        # Return structured results from dexray-insight
        final_json = {self.last_analysed_app: self.last_results}
        return final_json

    def pretty_print(self):
        """Pretty prints the results of the last static analysis using dexray-insight."""
        if not self.last_results:
            print("No static analysis results available.")
            return

        if "error" in self.last_results:
            print(
                f"Static analysis error for {self.last_analysed_app}: {self.last_results['error']}"
            )
            return

        print(f"\n=== Static Analysis Results for {self.last_analysed_app} ===")

        # Print structured results from dexray-insight
        if "analysis_results" in self.last_results:
            analysis_data = self.last_results["analysis_results"]
            if isinstance(analysis_data, dict):
                for key, value in analysis_data.items():
                    if isinstance(value, (dict, list)):
                        print(f"{key}: {json.dumps(value, indent=2)}")
                    else:
                        print(f"{key}: {value}")
            else:
                print(f"Analysis results: {analysis_data}")

        if "result_files" in self.last_results:
            files = self.last_results["result_files"]
            print("\nResult files generated:")
            for file_type, file_path in files.items():
                if file_path:
                    print(f"  {file_type}: {file_path}")
