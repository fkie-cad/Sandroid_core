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
    quote_host_arg,
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


def _insight_counts(analysis_results: dict) -> dict[str, int]:
    """Count permissions/components in a Dexray Insight result dict.

    Insight (1.0.0.1 and 2.0.0 alike) nests them under ``apk_overview``:
    ``apk_overview.permissions.permissions`` (a list inside a dict) and
    ``apk_overview.components.{activities,services,receivers}``. Flat
    top-level lists (older shapes) are still honoured.

    Args:
        analysis_results: Insight's main result dict.

    Returns:
        ``{"permissions": n, "activities": n, "services": n, "receivers": n}``.
    """
    overview = analysis_results.get("apk_overview") or {}
    components = overview.get("components") or {}
    permissions = overview.get("permissions")
    if isinstance(permissions, dict):
        permissions = permissions.get("permissions")
    counts = {"permissions": permissions}
    for key in ("activities", "services", "receivers"):
        counts[key] = components.get(key) if isinstance(components, dict) else None
    result = {}
    for key, value in counts.items():
        if not value:
            value = analysis_results.get(key)
        result[key] = len(value) if isinstance(value, (list, tuple, dict)) else 0
    return result


def _insight_version() -> str | None:
    """Installed Dexray Insight version, if known."""
    try:
        from importlib import metadata

        return metadata.version("dexray-insight")
    except Exception:
        return None


def _insight_supports_cache_dir() -> bool:
    """True for Insight >= 2.0.0 (configurable analysis cache).

    Feature-detected (``Configuration.DEFAULT_CONFIG["caching"]`` plus the
    ``start_apk_static_analysis_new`` entry point) so 1.0.0.1 keeps using the
    legacy call unchanged.
    """
    configuration = getattr(asam, "Configuration", None)
    defaults = getattr(configuration, "DEFAULT_CONFIG", None)
    return (
        hasattr(asam, "start_apk_static_analysis_new")
        and isinstance(defaults, dict)
        and "caching" in defaults
    )


def _merge_dict(base: dict, update: dict) -> None:
    """Recursively merge *update* into *base* (in place)."""
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge_dict(base[key], value)
        else:
            base[key] = value


def _insight_offline_config(configuration) -> dict:
    """Insight config that keeps an analysis off the network.

    Keys are feature-detected against ``Configuration.DEFAULT_CONFIG``:
    Insight >= 2.0.0 has ``tracker_analysis.exodus_offline`` (use the cached
    Exodus list if present, otherwise skip Exodus); older versions only get
    ``fetch_exodus_trackers: false``. The IzzyOnDroid library-definition
    auto-update (gitlab.com), library version analysis (Maven/npm/PyPI) and
    CVE scanning are switched off as well; unknown keys are ignored by
    Insight's config merge.
    """
    defaults = getattr(configuration, "DEFAULT_CONFIG", None)
    modules = defaults.get("modules", {}) if isinstance(defaults, dict) else {}
    tracker_defaults = modules.get("tracker_analysis", {})
    tracker = (
        {"exodus_offline": True}
        if "exodus_offline" in tracker_defaults
        else {"fetch_exodus_trackers": False}
    )
    return {
        "modules": {
            "tracker_analysis": tracker,
            "library_detection": {
                "apktool_detection": {"auto_update_definitions": False},
                "version_analysis": {"enabled": False},
            },
        },
        "security": {"cve_scanning": {"enabled": False}},
    }


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
            # Per-run "don't cache" switch for the shared APK/Insight cache.
            "use_cache": True,
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
            self._analysis_config = {**self._analysis_config, **config}

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
            str(apk_file),
            apk_name,
            insight_dir,
            start_time,
            cleanup_apk=False,
            other_split_sha256s=[],
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

        # Parse APK path(s) (one "package:/path/to/x.apk" line per split;
        # base.apk is analysed, the other splits only feed the cache key).
        from sandroid.services.app_info_service import parse_pm_path_output

        device_paths = parse_pm_path_output(apk_path)
        if not device_paths:
            logger.warning(f"No APK path for {apk_name}")
            self.last_results = {"error": "No APK path found", "app_name": apk_name}
            return False
        device_apk_path = next(
            (p for p in device_paths if p.endswith("/base.apk")), device_paths[0]
        )
        # Per-device config splits (ABI/density/locale) are not part of the
        # cache key, so the same app on two devices shares one entry.
        from sandroid.services.app_info_service import is_config_split

        other_splits = [
            p for p in device_paths if p != device_apk_path and not is_config_split(p)
        ]
        local_apk_path = f"{insight_dir}{apk_name}.apk"

        logger.debug(
            f"Running dexray-insight for {apk_name} located at {local_apk_path}"
        )
        logger.info(
            "Statically analyzing spotlight App with dexray-insight. This might take a while."
        )

        # Pull APK from device
        pull_stdout, pull_stderr = self._send_adb_command(
            f"pull {quote_host_arg(device_apk_path)} {quote_host_arg(str(local_apk_path))}"
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
            local_apk_path,
            apk_name,
            insight_dir,
            start_time,
            cleanup_apk=True,
            other_split_sha256s=(
                self._remote_split_hashes(other_splits)
                if self._analysis_config.get("use_cache", True)
                else None
            ),
        )

    def _remote_split_hashes(self, device_paths: list[str]) -> list[str] | None:
        """sha256 of the non-base key splits, hashed on the device.

        Returns:
            The hashes (empty for a single-APK app), or ``None`` when any
            split could not be hashed (the run is then not recorded in the
            APK cache, whose key covers every split).
        """
        if not device_paths:
            return []
        try:
            import shlex

            from sandroid.core.adb_utils import device_shell_command
            from sandroid.services.app_info_service import parse_sha256sum_output

            stdout, _stderr = self._send_adb_command(
                device_shell_command(
                    "sha256sum " + " ".join(shlex.quote(p) for p in device_paths)
                )
            )
            hashes = parse_sha256sum_output(stdout)
            if all(p in hashes for p in device_paths):
                return [hashes[p] for p in device_paths]
        except Exception as e:
            logger.debug(f"Hashing APK splits on device failed: {e}")
        return None

    def _run_dexray_analysis(
        self,
        apk_file_path: str,
        apk_name: str,
        insight_dir: str,
        start_time: float,
        cleanup_apk: bool = False,
        other_split_sha256s: list[str] | None = None,
    ) -> bool:
        """Run dexray-insight analysis on an APK file.

        This is the shared analysis logic used by both local and device APK modes.

        Args:
            apk_file_path: Full path to the APK file to analyze
            apk_name: Name/identifier for the APK (used in results)
            insight_dir: Directory where result files should be stored
            start_time: Analysis start time for duration tracking
            cleanup_apk: If True, delete the APK file after analysis (for pulled APKs)
            other_split_sha256s: sha256 of the app's other splits (``[]`` for a
                single APK); ``None`` skips recording the run in the APK cache.

        Returns:
            True if analysis completed, False if failed
        """
        try:
            results, result_file_name, security_result_file_name = self._start_insight(
                apk_file_path
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

            # Convert results to dictionary for compatibility. Insight 2.0.0
            # returns a plain ``{"main": ..., "security": ...}`` dict on a
            # full-hit cache re-run instead of a results object.
            if isinstance(results, dict):
                analysis_results = results.get("main", results)
                json_output = json.dumps(analysis_results, indent=4, default=str)
            else:
                analysis_results = results.to_dict()
                json_output = results.to_json()
            self.last_results = {
                "analysis_results": analysis_results,
                "json_output": json_output,
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

            if other_split_sha256s is not None:
                self._record_in_apk_cache(
                    apk_file_path,
                    other_split_sha256s,
                    analysis_results,
                    result_file_name,
                    security_result_file_name,
                )

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

    def _apk_cache(self):
        """The shared APK cache, honouring the per-run ``use_cache`` switch."""
        from sandroid.services.app_info_service import ApkCache

        return ApkCache(enabled=self._analysis_config.get("use_cache", True))

    def _insight_offline(self) -> bool:
        """``analysis.insight_offline`` (default True), per-run overridable."""
        if "insight_offline" in self._analysis_config:
            return bool(self._analysis_config["insight_offline"])
        try:
            if get_config is not None:
                return bool(getattr(get_config().analysis, "insight_offline", True))
        except Exception:
            pass
        return True

    def _start_insight(self, apk_file_path: str):
        """Call Dexray Insight with the shared cache dir and offline settings.

        Uses ``start_apk_static_analysis_new`` + ``Configuration`` whenever the
        installed Insight has them (1.0.0.1 and 2.0.0 do; the legacy wrapper
        is exactly that call with a fixed config). Cache and offline keys are
        feature-detected; an Insight without that entry point gets the legacy
        call unchanged.

        Returns:
            Insight's ``(results, result_file_name, security_result_file_name)``.
        """
        verbose = self._analysis_config.get("verbose_output", False)
        do_sec = self._analysis_config.get("run_security_analysis", True)
        offline = self._insight_offline()
        configuration = getattr(asam, "Configuration", None)
        if configuration is None or not hasattr(asam, "start_apk_static_analysis_new"):
            if offline:
                logger.warning(
                    "This Dexray Insight version cannot be configured; "
                    "it may contact the network"
                )
            return asam.start_apk_static_analysis(
                apk_file_path=apk_file_path,
                do_signature_check=False,
                apk_to_diff=None,
                print_results_to_terminal=True,
                is_verbose=verbose,
                do_sec_analysis=do_sec,
                exclude_net_libs=None,
            )
        # Same config the legacy wrapper builds, plus cache/offline sections.
        config_dict: dict = {
            "modules": {
                "signature_detection": {"enabled": False},
                "apk_diffing": {"enabled": False},
            },
            "security": {"enable_owasp_assessment": do_sec},
            "logging": {"level": "DEBUG" if verbose else "INFO"},
        }
        if _insight_supports_cache_dir():
            cache = self._apk_cache()
            caching = {"enabled": cache.enabled}
            if cache.enabled:
                cache.insight_dir.mkdir(parents=True, exist_ok=True)
                caching["cache_dir"] = str(cache.insight_dir)
            config_dict["caching"] = caching
        if offline:
            _merge_dict(config_dict, _insight_offline_config(configuration))
            logger.info(
                "Dexray Insight runs offline (no Exodus fetch, no library-"
                "definition update, no version/CVE lookups)"
            )
        return asam.start_apk_static_analysis_new(
            apk_file_path,
            configuration(config_dict=config_dict),
            print_results_to_terminal=True,
            verbose=verbose,
        )

    def _record_in_apk_cache(
        self,
        apk_file_path: str,
        other_split_sha256s: list[str],
        analysis_results: dict,
        result_file: str | None,
        security_result_file: str | None,
    ) -> None:
        """Record this run in the APK cache's meta.json (best effort)."""
        try:
            import hashlib

            from sandroid.services.app_info_service import (
                record_insight_result,
                sha256_file,
            )

            cache = self._apk_cache()
            if not cache.enabled:
                return
            md5 = hashlib.md5(usedforsecurity=False)
            with open(apk_file_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    md5.update(chunk)
            key = record_insight_result(
                [sha256_file(apk_file_path), *other_split_sha256s],
                analysis_results if isinstance(analysis_results, dict) else {},
                result_file=result_file or None,
                security_result_file=security_result_file or None,
                insight_version=_insight_version(),
                insight_cache_used=_insight_supports_cache_dir(),
                apk_md5=md5.hexdigest(),
                package=self.last_analysed_app,
                cache=cache,
            )
            if key:
                logger.debug(f"Recorded Insight result in APK cache entry {key}")
        except Exception as e:
            logger.debug(f"Recording Insight result in APK cache failed: {e}")

    def _publish_analysis_events(self, duration: float) -> None:
        """Publish events for analysis findings.

        Args:
            duration: Analysis duration in seconds
        """
        analysis_data = self.last_results.get("analysis_results", {})
        if isinstance(analysis_data, dict):
            # Report permissions/components found (nested under apk_overview)
            for key, count in _insight_counts(analysis_data).items():
                if count:
                    TaskOutput(
                        task_name="static_analysis",
                        message=f"Found {count} {key}",
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
