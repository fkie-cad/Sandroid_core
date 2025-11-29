import json
import os
import shutil
from logging import getLogger

import click

from sandroid.core.adb import Adb
from sandroid.core.console import SandroidConsole
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

try:
    from dexray_insight import asam
except ImportError:
    logger = getLogger(__name__)
    logger.warning(
        "dexray-insight package not installed. Static analysis will be disabled."
    )
    asam = None

logger = getLogger(__name__)


class StaticAnalysis(DataGather):
    """Handles static analysis of APK files using dexray-insight (formerly ASAM)."""

    last_results = {}
    last_analysed_app = "no app name yet"

    def __init__(self):
        """Initialize StaticAnalysis."""
        self._config = {
            "run_security_analysis": True,
            "verbose_output": False,
        }
        self._output_files = []

    def _interactive_configuration(self) -> dict | None:
        """Interactive configuration menu for dexray-insight options.

        Returns:
            Configuration dict if user confirms, None if cancelled
        """
        import re
        console = SandroidConsole.get()

        # Box width (inner content width)
        BOX_WIDTH = 60

        def _box_line(content: str, align: str = "center") -> str:
            """Create a box line with proper alignment accounting for Rich markup."""
            # Strip Rich markup to calculate visual width
            PLACEHOLDER = "\x00LBRACKET\x00"
            temp = content.replace("\\[", PLACEHOLDER)
            RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
            visual_text = RICH_MARKUP_RE.sub("", temp)
            visual_text = visual_text.replace(PLACEHOLDER, "[")
            visual_len = len(visual_text)

            # Calculate padding
            if align == "center":
                left_pad = (BOX_WIDTH - visual_len) // 2
                right_pad = BOX_WIDTH - visual_len - left_pad
            else:  # left align
                left_pad = 1
                right_pad = BOX_WIDTH - visual_len - left_pad

            return f"[primary]║[/primary]{' ' * left_pad}{content}{' ' * right_pad}[primary]║[/primary]"

        settings = {
            "run_security_analysis": True,
            "verbose_output": False,
        }

        while True:
            console.clear()

            console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
            console.print(_box_line("[bold]Dexray-Insight Configuration[/bold]"))
            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")

            sec_status = "[success]●[/success]" if settings["run_security_analysis"] else "[error]○[/error]"
            verbose_status = "[success]●[/success]" if settings["verbose_output"] else "[error]○[/error]"

            console.print(_box_line(f"[accent]\\[S][/accent] Security Analysis: {sec_status} (vulnerability scan)", align="left"))
            console.print(_box_line(f"[accent]\\[V][/accent] Verbose Output:    {verbose_status} (detailed logging)", align="left"))

            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
            console.print(_box_line("[success]\\[Enter][/success] Start Analysis    [warning]\\[Esc/Q][/warning] Cancel", align="left"))
            console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")

            try:
                choice = click.getchar().lower()
            except (KeyboardInterrupt, EOFError):
                return None

            if choice in ('\r', '\n'):
                return settings
            elif choice in ('\x1b', 'q'):
                return None
            elif choice == 's':
                settings["run_security_analysis"] = not settings["run_security_analysis"]
            elif choice == 'v':
                settings["verbose_output"] = not settings["verbose_output"]

    def gather(self, interactive: bool = True) -> bool:
        """Gathers and analyzes the APK file of the spotlight application using dexray-insight.

        Args:
            interactive: If True, show interactive configuration menu first

        Returns:
            True if analysis completed, False if cancelled

        :raises Exception: If `asam` returns None or if there is an error during analysis.
        """
        if asam is None:
            logger.error("dexray-insight not available. Static analysis skipped.")
            self.last_results = {"error": "dexray-insight not installed"}
            return False

        # Show interactive configuration if requested
        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("Dexray-insight configuration cancelled")
                return False
            self._config = config

        # Use dexray_insight folder at results root (sibling to raw/, like dexray_intercept/)
        insight_dir = f"{os.getenv('RESULTS_PATH', '')}dexray_insight/"
        apk_name = Toolbox.get_spotlight_application()[0]
        self.last_analysed_app = apk_name
        apk_path, stderr = Adb.send_adb_command("shell pm path " + apk_name)
        apk_path = apk_path[8:-1]
        logger.debug(
            f"running dexray-insight for {apk_name} located at {insight_dir}{apk_name}.apk"
        )
        logger.info(
            "Statically analyzing spotlight App with dexray-insight. This might take a while."
        )
        Adb.send_adb_command(f"pull {apk_path} {insight_dir}{apk_name}.apk")

        if os.path.exists(f"{insight_dir}{apk_name}.apk"):
            try:
                # Use new dexray-insight API with configuration
                results, result_file_name, security_result_file_name = (
                    asam.start_apk_static_analysis(
                        apk_file_path=f"{insight_dir}{apk_name}.apk",
                        do_signature_check=False,
                        apk_to_diff=None,
                        print_results_to_terminal=True,
                        is_verbose=self._config.get("verbose_output", False),
                        do_sec_analysis=self._config.get("run_security_analysis", True),
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
                Toolbox.mark_tool_used("dexray-insight", files=self._output_files)

                logger.info(f"Static analysis completed successfully for {apk_name}")

            except Exception as e:
                logger.error("dexray-insight produced an error.")
                logger.error(
                    "This is not an issue with Sandroid. Empty output appended."
                )
                logger.error(str(e))
                self.last_results = {"error": str(e), "app_name": apk_name}

            # Clean up APK file
            try:
                os.remove(f"{insight_dir}{apk_name}.apk")
            except OSError as e:
                logger.warning(f"Could not remove APK file: {e}")
        else:
            logger.error("Something went wrong pulling spotlight apk")
            self.last_results = {"error": "APK file not found", "app_name": apk_name}

        return True

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
