import contextlib
import copy
import inspect
import json
import logging
import os
import shutil
import tempfile
import time
from logging import getLogger
from pathlib import Path

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

#: ``tui_state.json`` key remembering the last ``a`` dialog choice.
_UI_STATE_KEY = "static_analysis"


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


_OFF = {"enabled": False}

#: Insight's ``privacy`` profile (``dexray_insight.core.profiles``), for an
#: Insight without analysis profiles (< 2.2): exactly the same overrides,
#: merged under Sandroid's own keys. Unknown keys are ignored by Insight's
#: config merge. Keep in sync with Insight's ``_PRIVACY_OVERRIDES``.
_PRIVACY_PROFILE_FALLBACK: dict = {
    "modules": {
        "apk_overview": {"enabled": True},
        "manifest_analysis": {"enabled": True},
        "permission_analysis": {"enabled": True},
        "api_invocation": {"enabled": True},
        "string_analysis": {"enabled": True},
        "tracker_analysis": {"enabled": True},
        "behaviour_analysis": {"enabled": True, "deep_mode": False},
        "library_detection": {
            "enabled": True,
            "enable_similarity": False,
            "version_analysis": {"enabled": False},
        },
        "native_analysis": dict(_OFF),
        "signature_detection": dict(_OFF),
        "dotnet_analysis": dict(_OFF),
        "apk_diffing": dict(_OFF),
    },
    "tools": {
        "apktool": dict(_OFF),
        "jadx": dict(_OFF),
        "kavanoz": dict(_OFF),
    },
    "temporal_analysis": dict(_OFF),
    "security": {
        "cve_scanning": dict(_OFF),
        "assessments": {
            name: dict(_OFF)
            for name in (
                "injection",
                "authentication_failures",
                "logging_monitoring_failures",
                "vulnerable_components",
                "cve_scanning",
                "ssrf",
                "integrity_failures",
                "insecure_design",
            )
        },
    },
}

#: Where Insight keeps the IzzyOnDroid library definitions (``libsmali.jsonl``,
#: ``libinfo.jsonl``). Insight >= 2.2 defaults to it; older versions default
#: to the working directory, so Sandroid always passes it explicitly.
_LIBRARY_DEFINITIONS_DIR = Path.home() / ".dexray_insight" / "library_definitions"

#: Per-run folders in the work root older than this are left over from a
#: process that exited mid-run and are removed at the next start.
_STALE_WORK_SECONDS = 24 * 3600


def _accepts_kwarg(func, name: str) -> bool:
    """True when callable *func* takes a keyword argument *name*."""
    try:
        return name in inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False


def insight_work_root() -> Path:
    """Stable per-user root for Insight's scratch files.

    ``<paths.cache_path>/insight-work`` (default ``~/.cache/sandroid/insight-work``).
    The path is the same for every run, so it never changes Insight's cache
    key (Insight < 2.2 hashes ``temporal_analysis.base_directory``); each run
    works in its own subfolder below it.
    """
    root = None
    try:
        if get_config is not None:
            configured = getattr(get_config().paths, "cache_path", None)
            if configured:
                root = Path(configured).expanduser()
    except Exception:
        root = None
    return (root or Path("~/.cache/sandroid").expanduser()) / "insight-work"


def _clean_stale_work(root: Path, max_age: float = _STALE_WORK_SECONDS) -> None:
    """Remove entries in *root* last modified more than *max_age* seconds ago."""
    cutoff = time.time() - max_age
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.stat().st_mtime < cutoff:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
        except OSError:
            continue


def _work_dir_config(work_root: str) -> dict:
    """Insight config keeping its scratch files out of the working directory.

    The temporal directory (unzipped APK, apktool/JADX output, tool logs) goes
    below the stable *work_root* (Insight creates one subfolder per run and
    removes it; leftovers are swept after a day); the library definitions go to
    the per-user Insight directory. Every value is constant across runs, so
    the config, and with it Insight's cache key, is the same for every run.
    """
    return {
        "temporal_analysis": {
            "base_directory": work_root,
            "cleanup_after_analysis": True,
            "preserve_on_error": False,
        },
        "modules": {
            "library_detection": {
                "apktool_detection": {
                    "libsmali_path": str(_LIBRARY_DEFINITIONS_DIR / "libsmali.jsonl"),
                    "libinfo_path": str(_LIBRARY_DEFINITIONS_DIR / "libinfo.jsonl"),
                }
            }
        },
    }


def _insight_keeps_host_logging() -> bool:
    """True for an Insight (>= 2.2) that only ever moves its own debug handler."""
    try:
        from dexray_insight.Utils import log as insight_log

        return hasattr(insight_log, "INSIGHT_HANDLER_MARK")
    except Exception:
        return False


@contextlib.contextmanager
def _preserved_root_logging(work_root: str | Path):
    """Undo Insight 2.1.0's debug-log swap on the root logger.

    At DEBUG, Insight < 2.2 removes every root FileHandler (Sandroid's session
    and error logs) and adds its own log file inside its temporal folder below
    *work_root*. When that happened, the handlers it added there are closed
    and removed and the file handlers that were present before are put back.
    Nothing else is touched (Insight never changes the root level outside
    its own CLI), and a newer Insight is left alone entirely.
    """
    if _insight_keeps_host_logging():
        yield
        return
    root = logging.getLogger()
    before = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    work = Path(work_root).resolve()
    try:
        yield
    finally:
        added = []
        for handler in root.handlers:
            if not isinstance(handler, logging.FileHandler) or handler in before:
                continue
            with contextlib.suppress(Exception):
                if Path(handler.baseFilename).resolve().is_relative_to(work):
                    added.append(handler)
        if added:
            for handler in added:
                root.removeHandler(handler)
                with contextlib.suppress(Exception):
                    handler.close()
            for handler in before:
                if handler not in root.handlers:
                    root.addHandler(handler)


def _short_error(error: object, limit: int = 160) -> str:
    """First line of an error, trimmed, for an event or a status line."""
    text = str(error).strip().splitlines()[0] if str(error).strip() else ""
    text = text or type(error).__name__
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def describe_static_options(options: dict) -> str:
    """Plain-words summary of a static analysis choice.

    Example: ``"privacy profile, trackers on, security analysis off"``.
    """
    profile = options.get("profile") or "generic"
    trackers = "on" if options.get("trackers", True) else "off"
    security = "on" if options.get("security", True) else "off"
    return f"{profile} profile, trackers {trackers}, security analysis {security}"


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
            # Insight analysis profile ("generic" = full, "privacy").
            "profile": "generic",
            "run_tracker_analysis": True,
            # Per-run "don't cache" switch for the shared APK/Insight cache.
            "use_cache": True,
        }
        self._output_files = []
        # Package name for the state events: the spotlight package in device
        # mode, Insight's package_name in local mode once known.
        self._package: str | None = None
        self._final_state_sent = False

    def _options(self) -> dict:
        """The current choice as ``{"profile", "trackers", "security", "verbose"}``."""
        cfg = self._analysis_config
        return {
            "profile": cfg.get("profile") or "generic",
            "trackers": bool(cfg.get("run_tracker_analysis", True)),
            "security": bool(cfg.get("run_security_analysis", True)),
            "verbose": bool(cfg.get("verbose_output", False)),
        }

    @staticmethod
    def _config_from_choice(choice: dict) -> dict:
        """Map a dialog choice onto ``_analysis_config`` keys."""
        return {
            "profile": choice["profile"],
            "run_tracker_analysis": choice["trackers"],
            "run_security_analysis": choice["security"],
            "verbose_output": choice["verbose"],
        }

    def _dialog_target(self) -> str:
        """Package (device mode) or APK file name (local mode) for the dialog."""
        if self._apk_path:
            return os.path.basename(self._apk_path)
        try:
            from sandroid.services import get_spotlight_service

            return get_spotlight_service().get_effective_package() or ""
        except Exception:
            return ""

    def _interactive_configuration(self) -> dict | None:
        """Ask for the Insight profile and options (the ``a`` dialog).

        The last confirmed choice is remembered per user in ``tui_state.json``
        (key ``static_analysis``) and preselected next time.

        Returns:
            ``_analysis_config`` updates if the user confirms, None if cancelled
        """
        from sandroid.config.ui_state import load_ui_state, update_ui_state
        from sandroid.core.ui_request_bus import UIRequestBus, request_modal
        from sandroid.tui.modals.static_analysis_modal import normalize_choice

        remembered = normalize_choice(load_ui_state().get(_UI_STATE_KEY))

        bus = UIRequestBus.get()
        if bus.has_active_handler():
            from sandroid.tui.modals.static_analysis_modal import StaticAnalysisModal

            result = request_modal(
                StaticAnalysisModal, choice=remembered, target=self._dialog_target()
            )
        else:
            result = self._console_configuration(remembered)
        if result is None:
            return None
        choice = normalize_choice(result)
        try:
            update_ui_state(_UI_STATE_KEY, choice)
        except Exception as e:
            logger.debug(f"Could not remember the static analysis choice: {e}")
        return self._config_from_choice(choice)

    def _console_configuration(self, choice: dict) -> dict | None:
        """Rich console version of the dialog (no TUI running)."""
        from sandroid.tui.modals.static_analysis_modal import STATIC_ANALYSIS_PROFILES
        from sandroid.tui.utils.box_renderer import make_box_line

        console = SandroidConsole.get()

        # Box width (inner content width) - read from config
        _DEFAULT_BOX_WIDTH = 60
        BOX_WIDTH = _get_display_value("box_width", _DEFAULT_BOX_WIDTH)

        _box_line = make_box_line(BOX_WIDTH)
        settings = dict(choice)
        profiles = [name for name, _ in STATIC_ANALYSIS_PROFILES]
        rows = (
            ("T", "trackers", "Trackers"),
            ("S", "security", "Security analysis"),
            ("V", "verbose", "Verbose output"),
        )

        while True:
            console.clear()

            console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
            console.print(_box_line("[bold]Static analysis (Dexray Insight)[/bold]"))
            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
            console.print(
                _box_line(
                    f"[accent]\\[P][/accent] Profile:           "
                    f"[bold]{settings['profile']}[/bold]",
                    align="left",
                )
            )
            for key, setting, label in rows:
                state = (
                    "[success]on[/success]"
                    if settings[setting]
                    else "[error]off[/error]"
                )
                console.print(
                    _box_line(
                        f"[accent]\\[{key}][/accent] {label + ':':<18} {state}",
                        align="left",
                    )
                )

            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
            console.print(
                _box_line(
                    "[success]\\[Enter][/success] Start Analysis    "
                    "[warning]\\[Esc/Q][/warning] Cancel",
                    align="left",
                )
            )
            console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")

            try:
                key = click.getchar().lower()
            except (KeyboardInterrupt, EOFError):
                return None

            if key in ("\r", "\n"):
                return settings
            if key in ("\x1b", "q"):
                return None
            if key == "p":
                index = profiles.index(settings["profile"])
                settings["profile"] = profiles[(index + 1) % len(profiles)]
            for row_key, setting, _label in rows:
                if key == row_key.lower():
                    settings[setting] = not settings[setting]

    def _publish_state(self, state: str, message: str, **data) -> None:
        """Publish a static analysis TaskOutput with ``data.state``.

        ``state`` is one of ``started``, ``finished``, ``failed``,
        ``cancelled``; ``data`` always carries the package (``None`` while
        unknown), the profile and, for a local APK, its file name (``apk``).
        """
        payload = {
            "state": state,
            "package": self._package,
            "profile": self._options()["profile"],
        }
        if self._apk_path:
            payload["apk"] = os.path.basename(self._apk_path)
        payload.update(data)
        self._final_state_sent = state in ("finished", "failed", "cancelled")
        TaskOutput(
            task_name="static_analysis",
            message=message,
            level="error" if state == "failed" else "info",
            data=payload,
            source="static_analysis",
        ).publish()

    def gather(self, interactive: bool = True) -> bool:
        """Gathers and analyzes an APK file using dexray-insight.

        Supports two modes:
        1. Local APK: If `apk_path` was provided at init, analyzes that file directly
        2. Device APK: Otherwise, pulls the spotlight app from the connected device

        Publishes ``static_analysis`` TaskOutputs with ``data.state``
        ``started``, then ``finished``, ``failed`` or ``cancelled``.

        Args:
            interactive: If True, show interactive configuration menu first

        Returns:
            True if analysis completed, False if cancelled or failed
        """
        if asam is None:
            logger.error("dexray-insight not available. Static analysis skipped.")
            self.last_results = {"error": "dexray-insight not installed"}
            return False

        # Track analysis start time for duration calculation
        start_time = time.time()
        self._final_state_sent = False

        # Show interactive configuration if requested
        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("Dexray-insight configuration cancelled")
                self._publish_state("cancelled", "Static analysis cancelled")
                return False
            self._analysis_config = {**self._analysis_config, **config}

        # Route to appropriate analysis method
        try:
            if self._apk_path:
                ok = self._analyze_local_apk(self._apk_path, start_time)
            else:
                ok = self._analyze_device_apk(start_time)
        except BaseException:
            if not self._final_state_sent:
                self._publish_state("cancelled", "Static analysis stopped")
            raise
        if not ok and not self._final_state_sent:
            error = _short_error(self.last_results.get("error") or "unknown error")
            self._publish_state(
                "failed", f"Static analysis failed: {error}", error=error
            )
        return ok

    def _analyze_local_apk(self, apk_path: str, start_time: float) -> bool:
        """Analyze a local APK file without device interaction.

        Args:
            apk_path: Path to the local APK file
            start_time: Analysis start time for duration tracking

        Returns:
            True if analysis completed, False if failed
        """
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

        Uses the spotlight app (SpotlightService) to determine which app to
        analyze. The APK is pulled into this run's work folder (never next to
        the results), so whatever Insight writes beside it is removed too.

        Args:
            start_time: Analysis start time for duration tracking

        Returns:
            True if analysis completed, False if failed
        """
        # Use dexray_insight folder at results root (sibling to raw/, like dexray_intercept/)
        insight_dir = f"{os.getenv('RESULTS_PATH', '')}dexray_insight/"
        os.makedirs(insight_dir, exist_ok=True)

        # The spotlight package, whether the app runs or not.
        apk_name = None
        try:
            from sandroid.services import get_spotlight_service

            apk_name = get_spotlight_service().get_effective_package()
        except Exception:
            logger.debug("spotlight service lookup failed", exc_info=True)
        if not apk_name:
            logger.error("No spotlight app selected; static analysis skipped.")
            self.last_results = {"error": "no spotlight app selected"}
            return False
        self.last_analysed_app = apk_name
        self._package = apk_name

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
        run_dir = self._new_run_dir()
        local_apk_path = str(run_dir / f"{apk_name}.apk")

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
            shutil.rmtree(run_dir, ignore_errors=True)
            return False

        if not os.path.exists(local_apk_path):
            logger.error("Something went wrong pulling spotlight apk")
            self.last_results = {
                "error": "APK file not found after pull",
                "app_name": apk_name,
            }
            shutil.rmtree(run_dir, ignore_errors=True)
            return False

        return self._run_dexray_analysis(
            local_apk_path,
            apk_name,
            insight_dir,
            start_time,
            other_split_sha256s=(
                self._remote_split_hashes(other_splits)
                if self._analysis_config.get("use_cache", True)
                else None
            ),
            run_dir=str(run_dir),
        )

    @staticmethod
    def _new_run_dir() -> Path:
        """A fresh per-run folder below :func:`insight_work_root`.

        Leftovers of runs that died more than a day ago are removed first.
        """
        root = insight_work_root()
        root.mkdir(parents=True, exist_ok=True)
        _clean_stale_work(root)
        return Path(tempfile.mkdtemp(prefix="run-", dir=root))

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
        run_dir: str | None = None,
    ) -> bool:
        """Run dexray-insight analysis on an APK file.

        This is the shared analysis logic used by both local and device APK
        modes. The APK is analysed from this run's own folder below
        :func:`insight_work_root` (hard-linked or copied there unless it
        already is), so files Insight writes next to the APK (``apktool_out/``)
        are removed with that folder after the run. Insight removes its own
        temporal folder; leftovers are swept after a day.

        Args:
            apk_file_path: Full path to the APK file to analyze
            apk_name: Name/identifier for the APK (used in results)
            insight_dir: Directory where result files should be stored
            start_time: Analysis start time for duration tracking
            cleanup_apk: If True, delete the APK file after analysis
            other_split_sha256s: sha256 of the app's other splits (``[]`` for a
                single APK); ``None`` skips recording the run in the APK cache.
            run_dir: This run's work folder (created when ``None``).

        Returns:
            True if analysis completed, False if failed
        """
        options = self._options()
        self._publish_state(
            "started",
            f"Static analysis started: {describe_static_options(options)}",
            **{k: v for k, v in options.items() if k != "profile"},
        )
        run_path = Path(run_dir) if run_dir else self._new_run_dir()
        work_root = run_path.parent
        try:
            analysed_apk = self._stage_apk(apk_file_path, run_path)
            results, result_file_name, security_result_file_name = self._start_insight(
                str(analysed_apk), insight_dir=insight_dir, work_dir=str(work_root)
            )

            if results is None:
                raise Exception("dexray-insight returned None")

            # Insight < 2.2 writes its files to the working directory: move them.
            result_file_name = self._move_into(result_file_name, insight_dir)
            security_result_file_name = self._move_into(
                security_result_file_name, insight_dir
            )
            if security_result_file_name:
                markdown = Path(security_result_file_name).stem + ".md"
                self._move_into(markdown, insight_dir)

            # Convert results to dictionary for compatibility. Insight 2.0.0
            # returns a plain ``{"main": ..., "security": ...}`` dict on a
            # full-hit cache re-run instead of a results object.
            if isinstance(results, dict):
                analysis_results = results.get("main", results)
                json_output = json.dumps(analysis_results, indent=4, default=str)
            else:
                analysis_results = results.to_dict()
                json_output = results.to_json()
            overview = analysis_results.get("apk_overview") or {}
            package = (overview.get("general_info") or {}).get("package_name")
            if package:
                self._package = package
            self.last_results = {
                "analysis_results": analysis_results,
                "json_output": json_output,
                "app_name": apk_name,
                "options": options,
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
                    str(analysed_apk),
                    other_split_sha256s,
                    analysis_results,
                    result_file_name,
                    security_result_file_name,
                    options,
                )

            # Calculate analysis duration
            duration = time.time() - start_time

            # Publish TaskOutput events for important findings
            self._publish_analysis_events(duration)
            self._publish_state(
                "finished",
                f"Static analysis finished in {duration:.0f} seconds",
                duration_s=round(duration, 1),
                results_dir=os.path.abspath(insight_dir),
            )

            return True

        except Exception as e:
            logger.error("dexray-insight produced an error.")
            logger.error("This is not an issue with Sandroid. Empty output appended.")
            logger.error(str(e))
            self.last_results = {"error": str(e), "app_name": apk_name}
            error = _short_error(e)
            self._publish_state(
                "failed", f"Static analysis failed: {error}", error=error
            )
            return False

        except BaseException:
            self._publish_state("cancelled", "Static analysis stopped")
            raise

        finally:
            # Insight removes its own temporal folder (cleanup_after_analysis);
            # one left by a crash is removed by _clean_stale_work after a day.
            shutil.rmtree(run_path, ignore_errors=True)
            if cleanup_apk and os.path.exists(apk_file_path):
                try:
                    os.remove(apk_file_path)
                except OSError as e:
                    logger.warning(f"Could not remove APK file: {e}")

    @staticmethod
    def _stage_apk(apk_file_path: str, run_path: Path) -> Path:
        """The APK inside *run_path*: as is, hard-linked or copied there."""
        source = Path(apk_file_path)
        if source.resolve().parent == run_path.resolve():
            return source
        target = run_path / source.name
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)
        return target

    @staticmethod
    def _move_into(file_name: str, directory: str) -> str:
        """Move a bare file name from the working directory into *directory*."""
        if not file_name or os.path.dirname(file_name):
            return file_name
        if not os.path.exists(file_name):
            return file_name
        dest_path = os.path.join(directory, file_name)
        shutil.move(file_name, dest_path)
        logger.debug(f"Moved {file_name} to {dest_path}")
        return dest_path

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

    def _start_insight(
        self,
        apk_file_path: str,
        insight_dir: str | None = None,
        work_dir: str | None = None,
    ):
        """Call Dexray Insight with the shared cache dir and offline settings.

        Uses ``start_apk_static_analysis_new`` + ``Configuration`` whenever the
        installed Insight has them (1.0.0.1 and 2.0.0 do; the legacy wrapper
        is exactly that call with a fixed config). Cache and offline keys are
        feature-detected; an Insight without that entry point gets the legacy
        call unchanged.

        The analysis profile goes to Insight's ``profile`` argument when it has
        one (>= 2.2) and is otherwise merged in from
        :data:`_PRIVACY_PROFILE_FALLBACK`; trackers map to
        ``modules.tracker_analysis.enabled``.

        Args:
            apk_file_path: The APK to analyse.
            insight_dir: Directory for Insight's result files (passed as
                ``output_dir`` when Insight accepts it; otherwise the files
                land in the working directory and the caller moves them).
            work_dir: Stable root for Insight's temporal files
                (:func:`insight_work_root`).

        Returns:
            Insight's ``(results, result_file_name, security_result_file_name)``.
        """
        verbose = self._analysis_config.get("verbose_output", False)
        do_sec = self._analysis_config.get("run_security_analysis", True)
        profile = self._analysis_config.get("profile") or "generic"
        trackers = self._analysis_config.get("run_tracker_analysis", True)
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
        # Same config the legacy wrapper builds, plus profile, tracker,
        # scratch-dir, cache and offline sections.
        native_profiles = _accepts_kwarg(configuration, "profile")
        config_dict: dict = {}
        if profile == "privacy" and not native_profiles:
            _merge_dict(config_dict, copy.deepcopy(_PRIVACY_PROFILE_FALLBACK))
        _merge_dict(
            config_dict,
            {
                "modules": {
                    "signature_detection": {"enabled": False},
                    "apk_diffing": {"enabled": False},
                },
                "security": {"enable_owasp_assessment": do_sec},
                "logging": {"level": "DEBUG" if verbose else "INFO"},
            },
        )
        if not trackers:
            _merge_dict(
                config_dict, {"modules": {"tracker_analysis": {"enabled": False}}}
            )
        if work_dir:
            _merge_dict(config_dict, _work_dir_config(work_dir))
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
        profile_kwargs = {"profile": profile} if native_profiles else {}
        output_kwargs = (
            {"output_dir": insight_dir}
            if insight_dir
            and _accepts_kwarg(asam.start_apk_static_analysis_new, "output_dir")
            else {}
        )
        with _preserved_root_logging(work_dir or insight_work_root()):
            return asam.start_apk_static_analysis_new(
                apk_file_path,
                configuration(config_dict=config_dict, **profile_kwargs),
                print_results_to_terminal=True,
                verbose=verbose,
                **output_kwargs,
            )

    def _record_in_apk_cache(
        self,
        apk_file_path: str,
        other_split_sha256s: list[str],
        analysis_results: dict,
        result_file: str | None,
        security_result_file: str | None,
        options: dict | None = None,
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
                options=options,
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
