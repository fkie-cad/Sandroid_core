# Standard library imports
from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from sandroid.core.device import Device, DeviceCapability
    from sandroid.core.device_manager import DeviceManager

# Local imports
from .adb import Adb
from .console import SandroidConsole
from .formatting import OutputFormatter
from .models import (
    BackgroundTask,
    ForensicAPK,
    ServiceProperty,
)

# Re-export dataclasses for backwards compatibility
__all__ = ["BackgroundTask", "ForensicAPK", "Toolbox"]


# ---------------------------------------------------------------------------
# Declarative property table: each entry becomes a metaclass @property
# that delegates reads/writes to a service.
#
# Format: (toolbox_attr_name, service_getter_name, attr_or_getter, setter)
#   - If 3rd arg is a plain string and 4th is None  -> simple attr r/w
#   - If 3rd is getter method name and 4th is setter method name -> method pair
# ---------------------------------------------------------------------------

_SERVICE_PROPERTY_TABLE: list[tuple[str, str, str | None, str | None]] = [
    # ---- SessionStateService ----
    ("args", "get_session_state_service", "args", None),
    ("logger", "get_session_state_service", "logger", None),
    ("frida_manager", "get_session_state_service", "frida_manager", None),
    ("scan_directories", "get_session_state_service", "scan_directories", None),
    ("device_name", "get_session_state_service", "device_name", None),
    (
        "android_emulator_path",
        "get_session_state_service",
        "android_emulator_path",
        None,
    ),
    # ---- FridaSessionService ----
    (
        "malware_monitor_running",
        "get_frida_session_service",
        "malware_monitor_running",
        None,
    ),
    # ---- SpotlightService (method-based) ----
    (
        "_spotlight_application",
        "get_spotlight_service",
        "get_application",
        "set_application",
    ),
    (
        "_spotlight_application_pid",
        "get_spotlight_service",
        "get_application_pid",
        "set_application_pid",
    ),
    ("_spawn_mode", "get_spotlight_service", "is_spawn_mode", "_spawn_mode"),
    (
        "_spotlight_spawn_application",
        "get_spotlight_service",
        "get_spawn_application",
        "_spotlight_spawn_application",
    ),
    (
        "_auto_resume_after_spawn",
        "get_spotlight_service",
        "get_auto_resume_after_spawn",
        "set_auto_resume_after_spawn",
    ),
    (
        "_spotlight_files",
        "get_spotlight_service",
        "get_spotlight_files",
        "set_spotlight_files",
    ),
    (
        "_spotlight_pull_one",
        "get_spotlight_service",
        "get_spotlight_pull_one",
        "set_spotlight_pull_one",
    ),
    (
        "_spotlight_pull_two",
        "get_spotlight_service",
        "get_spotlight_pull_two",
        "set_spotlight_pull_two",
    ),
    # ---- ForensicService ----
    (
        "_timestamps_shadow_dict_list",
        "get_forensic_service",
        "timestamps_shadow_dict_list",
        None,
    ),
    ("noise_files", "get_forensic_service", "noise_files_ref", None),
    ("baseline", "get_forensic_service", "baseline_ref", None),
    ("noise_processes", "get_forensic_service", "noise_processes", None),
    (
        "other_output_data_collector",
        "get_forensic_service",
        "other_output_data_collector",
        None,
    ),
    ("file_paths_whitelist", "get_forensic_service", "file_paths_whitelist", None),
    # ---- ActionWindowService (method-based) ----
    (
        "changed_files_cache",
        "get_action_window_service",
        "get_changed_files_cache",
        "set_changed_files_cache",
    ),
    # ---- TrigDroidConfigService ----
    ("trigdroid_bypass_config", "get_trigdroid_config_service", "bypass_config", None),
    ("trigdroid_spawn_mode", "get_trigdroid_config_service", "spawn_mode", None),
    ("trigdroid_auto_resume", "get_trigdroid_config_service", "auto_resume", None),
]


def _build_toolbox_meta() -> type:
    """Build the _ToolboxMeta metaclass from the declarative property table.

    For each row in ``_SERVICE_PROPERTY_TABLE`` a ``ServiceProperty`` descriptor
    is installed on the metaclass, replacing ~370 lines of hand-written
    @property/@setter pairs.
    """
    namespace: dict = {}
    for prop_name, svc_getter, third, fourth in _SERVICE_PROPERTY_TABLE:
        if fourth is None:
            # Simple attribute delegation: third is the attr name on the service
            descriptor = ServiceProperty(svc_getter, attr_name=third)
        else:
            # Method-based delegation: third is getter method, fourth is setter
            descriptor = ServiceProperty(
                svc_getter, getter_name=third, setter_name=fourth
            )
        namespace[prop_name] = descriptor

    return type("_ToolboxMeta", (type,), namespace)


_ToolboxMeta = _build_toolbox_meta()


# Module-level cache for singleton utility references (not class state)
_menu_renderer_cache: dict = {}


def _service(name: str):
    """Lazy import helper for service getters.

    Returns the service instance by calling the named getter from
    ``sandroid.services``.  Avoids repeating the same two-line
    ``from sandroid.services import ...; return ...()`` pattern.
    """
    from sandroid import services as svc_module

    return getattr(svc_module, name)()


class Toolbox(metaclass=_ToolboxMeta):
    """Stateless delegation facade for Android forensic analysis utilities.

    Toolbox is a backwards-compatible static class that delegates ALL operations
    to focused services. It holds zero mutable state -- all state lives in services
    accessed via lazy imports. This class exists for compatibility with 42+ files
    that import it.

    State delegation (via _ToolboxMeta metaclass properties):
    - args, logger, frida_manager, scan_directories, device_name,
      android_emulator_path -> SessionStateService
    - malware_monitor_running -> FridaSessionService
    - _spotlight_application, _spotlight_application_pid, _spawn_mode,
      _spotlight_spawn_application, _auto_resume_after_spawn,
      _spotlight_files, _spotlight_pull_one, _spotlight_pull_two -> SpotlightService
    - baseline, noise_files, _timestamps_shadow_dict_list, noise_processes,
      other_output_data_collector, file_paths_whitelist -> ForensicService
    - changed_files_cache -> ActionWindowService
    - trigdroid_bypass_config, trigdroid_spawn_mode, trigdroid_auto_resume -> TrigDroidConfigService

    Method delegation (via classmethod one-liners):
    - Frida operations -> FridaSessionService
    - Device management -> DeviceService
    - Emulator operations -> EmulatorService
    - Spotlight/app management -> SpotlightService
    - Background tasks -> TaskService
    - Tool usage tracking -> ToolUsageService
    - Network capture -> NetworkCaptureService
    - UI operations -> UIService
    - Setup/checks -> SetupService
    - File extraction -> FileExtractionService
    - Configuration -> ConfigurationService
    - Initialization -> InitializationService
    """

    def __new__(cls):
        raise TypeError("This is a static class and cannot be instantiated.")

    # ==================== UI Delegation ====================

    @classmethod
    def safe_input(cls, prompt: str = "") -> str:
        """Delegates to UIService for safe stdin input with buffer flushing."""
        return _service("get_ui_service").safe_input(prompt)

    @classmethod
    def buffer_background_output(cls, task_name: str, message: str) -> None:
        """Delegates to UIService to buffer background task output."""
        _service("get_ui_service").buffer_background_output(task_name, message)

    @classmethod
    def get_recent_background_output(cls, count: int = 5) -> list[tuple[str, str, str]]:
        """Delegates to UIService. Returns list of (timestamp, task_name, message)."""
        return _service("get_ui_service").get_recent_background_output(count)

    @classmethod
    def clear_background_output_buffer(cls) -> None:
        """Delegates to UIService to clear the output buffer."""
        _service("get_ui_service").clear_output()

    @classmethod
    def _get_menu_renderer(cls):
        """Get or create the MenuRenderer singleton (module-level cache, not class state)."""
        if _menu_renderer_cache.get("instance") is None:
            from .menu_renderer import MenuRenderer

            _menu_renderer_cache["instance"] = MenuRenderer(cls)
        return _menu_renderer_cache["instance"]

    # ==================== Initialization ====================

    @classmethod
    def init(cls):
        """Delegates to InitializationService for session, logging, args, and FridaManager."""
        init_service = _service("get_initialization_service")
        result = init_service.initialize_application(
            args=cls.args or init_service.parse_arguments(),
            device_serial=cls._get_active_device_serial(),
        )
        cls.args = result.args
        cls.logger = cls.logger or result.logger
        cls.frida_manager = cls.frida_manager or result.frida_manager
        cls.scan_directories = result.scan_directories

    @classmethod
    def _get_active_device_serial(cls) -> str | None:
        """Delegates to DeviceService to get the active device serial."""
        try:
            device = _service("get_device_service").get_active_device()
            return device.serial if device else None
        except Exception:
            return None

    # Standard folder structure for device-specific results
    _folders_for_raw = [
        "first_pull",
        "second_pull",
        "noise_pull",
        "new_pull",
        "network_trace_pull",
        "screenshots",
        "spotlight_files",
    ]
    _folders_for_result = ["spotlight_files", "forensic_apks"]
    _tool_folders = ["fritap", "dexray_insight"]

    @classmethod
    def init_files(cls):
        """Delegates to InitializationService to create session folder and logging."""
        session_paths = _service("get_initialization_service").create_session(
            setup_logging=True
        )
        if cls.logger:
            cls.logger.debug(f"Session initialized: {session_paths.session_path}")

    @classmethod
    def _setup_file_logging(cls, log_file_path: str) -> None:
        """Delegates to InitializationService for file logging setup."""
        _service("get_initialization_service").setup_file_logging(log_file_path)

    @classmethod
    def switch_device_folder(cls, device_name: str) -> None:
        """Delegates to InitializationService.switch_device()."""
        init_service = _service("get_initialization_service")
        if init_service.get_session_path() is None:
            init_service.create_session(setup_logging=False)
        device_path = init_service.switch_device(device_name)
        if cls.logger:
            cls.logger.debug(f"Switched to device folder: {device_path}")

    @classmethod
    def _create_device_folders(cls, device_path: str) -> None:
        """Delegates to InitializationService.create_device_folder()."""
        from pathlib import Path

        init_service = _service("get_initialization_service")
        if init_service.get_session_path() is None:
            init_service.create_session(setup_logging=False)
        init_service.create_device_folder(Path(device_path).name, clean_existing=True)

    @classmethod
    def get_session_path(cls) -> str:
        """Delegates to ConfigurationService.get_session_path()."""
        return _service("get_configuration_service").get_session_path()

    # ==================== Forensic APK Management ====================

    @classmethod
    def add_forensic_apk(cls, apk: ForensicAPK) -> None:
        """Add a forensic APK to the session tracking.

        Delegates to ForensicAPKService.

        Args:
            apk: ForensicAPK instance to track
        """
        _service("get_forensic_apk_service").add(apk)

    @classmethod
    def get_forensic_apks(cls) -> list[ForensicAPK]:
        """Get all forensic APKs tracked in this session.

        Delegates to ForensicAPKService.

        Returns:
            List of ForensicAPK instances
        """
        return _service("get_forensic_apk_service").get_all()

    @classmethod
    def get_forensic_apks_for_device(cls, device_serial: str) -> list[ForensicAPK]:
        """Get forensic APKs pulled from a specific device.

        Delegates to ForensicAPKService.

        Args:
            device_serial: Device serial to filter by

        Returns:
            List of ForensicAPK instances from that device
        """
        return _service("get_forensic_apk_service").get_by_device(device_serial)

    @classmethod
    def remove_forensic_apk(cls, package_name: str, source_device: str) -> bool:
        """Remove a forensic APK from tracking.

        Delegates to ForensicAPKService.

        Args:
            package_name: Package name of the APK
            source_device: Device serial it was pulled from

        Returns:
            True if found and removed, False otherwise
        """
        return _service("get_forensic_apk_service").remove(package_name, source_device)

    @classmethod
    def get_forensic_install_warned(cls) -> bool:
        """Check if the forensic APK install warning has been shown.

        Delegates to ForensicAPKService.

        Returns:
            True if warning was already shown
        """
        return _service("get_forensic_apk_service").get_install_warned()

    @classmethod
    def set_forensic_install_warned(cls, warned: bool = True) -> None:
        """Set the forensic APK install warning flag.

        Delegates to ForensicAPKService.

        Args:
            warned: Whether warning has been shown
        """
        _service("get_forensic_apk_service").set_install_warned(warned)

    @classmethod
    def clear_forensic_apks(cls) -> None:
        """Clear all tracked forensic APKs.

        Delegates to ForensicAPKService.
        """
        _service("get_forensic_apk_service").clear()

    @classmethod
    def has_forensic_apks(cls) -> bool:
        """Check if any forensic APKs are available.

        Delegates to ForensicAPKService.

        Returns:
            True if at least one forensic APK is tracked
        """
        return _service("get_forensic_apk_service").has_apks()

    @staticmethod
    def is_dexray_insight_available() -> bool:
        """Check if dexray-insight package is installed.

        Returns:
            True if dexray-insight is importable, False otherwise
        """
        try:
            from dexray_insight import asam

            return asam is not None
        except ImportError:
            return False

    # ==================== Setup & Checks ====================

    @classmethod
    def check_setup(cls):
        """Delegates to SetupService to verify adb, root, and SELinux."""
        result = _service("get_setup_service").check_setup(auto_start_emulator=True)
        if not result.success:
            for error in result.errors:
                cls.logger.critical(error)
            exit(1)
        if result.adb_connected:
            SandroidConsole.add_startup_message(
                "[info]adb root enabled successfully.[/info]"
            )
        if result.selinux_permissive:
            SandroidConsole.add_startup_message(
                "[info]SELinux set to permissive mode.[/info]"
            )
        for warning in result.warnings:
            SandroidConsole.add_startup_message(f"[warning]{warning}[/warning]")

    @classmethod
    def check_sqldiff_binary(cls):
        """Checks if the sqldiff binary is available (delegates to SetupService).

        :returns: True if the sqldiff binary is available, False otherwise.
        :rtype: bool
        """
        result = _service("get_setup_service")._check_sqldiff()
        if not result.passed:
            cls.logger.info(result.message)
            SandroidConsole.add_startup_message(f"[info]{result.message}[/info]")
        return result.passed

    @classmethod
    def check_objection_binary(cls):
        """Checks if objection is available (delegates to SetupService).

        :returns: True if objection is available, False otherwise.
        :rtype: bool
        """
        result = _service("get_setup_service")._check_objection()
        if not result.passed:
            cls.logger.warning(result.message)
            SandroidConsole.add_startup_message(f"[warning]{result.message}[/warning]")
        return result.passed

    @classmethod
    def initialize_logger(cls):
        """Initialize Toolbox logger reference.

        NOTE: File logging is set up by init_files() to ensure logs go to the
        timestamped session folder. Console logging is set up by cli.py setup_logging().
        This method only sets the class logger reference and log level.
        """
        if cls.logger is None:
            cls.logger = logging.getLogger(__name__)
            if cls.args:
                cls.logger.setLevel(cls.args.loglevel)

    # ==================== Emulator Operations ====================

    @classmethod
    def create_snapshot(cls, name):
        """Delegates to EmulatorService.create_snapshot()."""
        _service("get_emulator_service").create_snapshot(
            name if isinstance(name, str) else name.decode("utf-8")
        )

    @classmethod
    def load_snapshot(cls, name):
        """Delegates to EmulatorService.load_snapshot()."""
        _service("get_emulator_service").load_snapshot(
            name if isinstance(name, str) else name.decode("utf-8")
        )

    @classmethod
    def delete_snapshot(cls, name) -> bool:
        """Delegates to EmulatorService.delete_snapshot().

        Unlike create/load, the success ``bool`` is propagated so callers can
        surface a real failure — delete is destructive and the ``avd snapshot
        del`` verb has no in-repo precedent, so masking a rejection is unsafe.
        """
        return _service("get_emulator_service").delete_snapshot(
            name if isinstance(name, str) else name.decode("utf-8")
        )

    # ==================== Forensic Analysis ====================

    @classmethod
    def fetch_changed_files(cls, fetch_all=False):
        """Returns a dictionary of file paths and change times of all files that were changed.

        The function uses a caching system to only list the file system after a new action.

        :param fetch_all: Whether to fetch all changed files or only those within the action time range.
        :type fetch_all: bool
        :returns: Dictionary of changed files and their change times while the action took place.
        :rtype: dict
        """
        service = _service("get_action_window_service")
        if service.is_filesystem_checked() and not fetch_all:
            cls.logger.debug("Reading filesystem timestamps from cache")
            return service.get_changed_files_cache()
        return cls._fetch_changed_files(fetch_all)

    @classmethod
    def print_emulator_information(cls):
        """Prints information about the emulator.

        Delegates to DeviceService for data gathering and UIService for display.
        """
        device_service = _service("get_device_service")
        ui_service = _service("get_ui_service")
        emulator_info = device_service.get_emulator_info()
        ui_service.print_emulator_information(emulator_info)

    @classmethod
    def _fetch_changed_files(cls, fetch_all=False):
        """Delegates to ForensicService.fetch_changed_files()."""
        action_service = _service("get_action_window_service")
        forensic_service = _service("get_forensic_service")
        forensic_service.set_action_window(
            action_service.get_action_time(), action_service.get_duration()
        )
        forensic_service.set_scan_directories(cls.scan_directories)
        forensic_service._timeline_callback = cls.add_to_shadow_ts_list
        result = forensic_service.fetch_changed_files(fetch_all)
        if not fetch_all:
            action_service.set_changed_files_cache(result)
            action_service.set_filesystem_checked(True)
        return result

    @classmethod
    def add_to_shadow_ts_list(
        cls, currentDir, filename, secondsTimestamp, color="#1A535C", fetch_all=False
    ):
        """Delegates to ForensicService.add_to_shadow_ts_list()."""
        action_service = _service("get_action_window_service")
        forensic_service = _service("get_forensic_service")
        forensic_service.set_action_window(
            action_service.get_action_time(), action_service.get_duration()
        )
        forensic_service.add_to_shadow_ts_list(
            currentDir, filename, secondsTimestamp, color, fetch_all
        )

    # ==================== Action Window Methods ====================

    @classmethod
    def set_action_time(cls):
        """Sets the action time by fetching the current time from the emulator.

        Delegates to ActionWindowService.
        """
        _service("get_action_window_service").set_action_time_from_device()

    @classmethod
    def set_action_duration(cls, seconds):
        """Sets the action duration.

        Delegates to ActionWindowService.

        :param seconds: The duration of the action in seconds.
        :type seconds: int
        """
        _service("get_action_window_service").set_duration(seconds)

    @classmethod
    def get_action_time(cls):
        """Returns the action time.

        Delegates to ActionWindowService.

        :returns: The action time.
        :rtype: int
        """
        return _service("get_action_window_service").get_action_time()

    @classmethod
    def get_action_duration(cls):
        """Returns the action duration.

        Delegates to ActionWindowService.

        :returns: The action duration.
        :rtype: int
        """
        return _service("get_action_window_service").get_duration()

    @classmethod
    def started_dry_run(cls):
        """Marks the start of a dry run.

        Delegates to ActionWindowService.
        """
        _service("get_action_window_service").start_dry_run()

    @classmethod
    def is_dry_run(cls):
        """Checks if a dry run is in progress.

        Delegates to ActionWindowService.

        :returns: True if a dry run is in progress, False otherwise.
        :rtype: bool
        """
        return _service("get_action_window_service").is_dry_run()

    @classmethod
    def get_run_counter(cls):
        """Returns the run counter.

        Delegates to ActionWindowService.

        :returns: The run counter.
        :rtype: int
        """
        return _service("get_action_window_service").get_run_counter()

    @classmethod
    def increase_run_counter(cls):
        """Increases the run counter by one.

        Delegates to ActionWindowService.
        """
        _service("get_action_window_service").increase_run_counter()

    # ==================== Spotlight / App Management ====================

    @classmethod
    def get_spotlight_application(cls):
        """Returns the spotlight application. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_application()

    @classmethod
    def set_spotlight_application(cls, spotlight_application):
        """Sets the spotlight application. Delegates to SpotlightService."""
        _service("get_spotlight_service").set_application(spotlight_application)

    @classmethod
    def get_spotlight_application_pid(cls):
        """Returns the PID of the spotlight application. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_application_pid()

    @classmethod
    def set_spotlight_application_pid(cls, spotlight_application_pid):
        """Sets the PID of the spotlight application. Delegates to SpotlightService."""
        _service("get_spotlight_service").set_application_pid(spotlight_application_pid)

    @classmethod
    def reset_spotlight_application(cls):
        """Resets the spotlight application. Delegates to SpotlightService."""
        _service("get_spotlight_service").reset_application()
        cls.logger.debug("Spotlight application information has been reset.")

    # ==================== Device Management ====================

    @classmethod
    def get_device_manager(cls) -> DeviceManager:
        """Delegates to DeviceService.get_device_manager()."""
        return _service("get_device_service").get_device_manager()

    @classmethod
    def get_active_device(cls) -> Device | None:
        """Delegates to DeviceService.get_active_device()."""
        return _service("get_device_service").get_active_device()

    @classmethod
    def check_device_capability(cls, capability: DeviceCapability) -> bool:
        """Delegates to DeviceService.check_capability()."""
        return _service("get_device_service").check_capability(capability)

    @classmethod
    def is_physical_device(cls) -> bool:
        """Delegates to DeviceService.is_physical_device()."""
        return _service("get_device_service").is_physical_device()

    @classmethod
    def is_emulator_device(cls) -> bool:
        """Delegates to DeviceService.is_emulator_device()."""
        return _service("get_device_service").is_emulator_device()

    # ==================== Spawn Mode ====================

    @classmethod
    def is_spawn_mode(cls):
        """Returns whether spawn mode is enabled. Delegates to SpotlightService."""
        return _service("get_spotlight_service").is_spawn_mode()

    @classmethod
    def set_spotlight_spawn_application(cls, package_name):
        """Sets the spawn application. Delegates to SpotlightService."""
        _service("get_spotlight_service").set_spawn_application(package_name)
        cls.logger.debug(f"Spotlight spawn application set to: {package_name}")

    @classmethod
    def get_spotlight_spawn_application(cls):
        """Returns the spawn package name. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_spawn_application()

    @classmethod
    def set_auto_resume_after_spawn(cls, enabled):
        """Sets auto-resume after spawn. Delegates to SpotlightService."""
        _service("get_spotlight_service").set_auto_resume_after_spawn(enabled)
        cls.logger.debug(f"Auto-resume after spawn: {enabled}")

    @classmethod
    def get_auto_resume_after_spawn(cls):
        """Returns auto-resume setting. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_auto_resume_after_spawn()

    @classmethod
    def resume_spawned_process_after_hooks(cls, device, pid):
        """Delegates to FridaSessionService.resume_spawned_process()."""
        return _service("get_frida_session_service").resume_spawned_process(device, pid)

    @classmethod
    def get_frida_session_for_spotlight(cls):
        """Returns appropriate Frida session based on current mode (spawn/attach).

        Delegates to FridaSessionService for the implementation.

        :returns: A tuple of (session, mode, app_info)
        :raises: Exception if Frida setup fails
        """
        return _service("get_frida_session_service").get_session_for_spotlight()

    @classmethod
    def ensure_spotlight_app_for_tools(cls, tool_name: str = "this tool") -> bool:
        """Ensure a spotlight app is set, prompting user to select if not.

        Delegates to SpotlightService for the implementation.

        Args:
            tool_name: Name of the tool requiring spotlight (for display)

        Returns:
            True if spotlight is now set, False if user cancelled
        """
        return _service("get_spotlight_service").ensure_app_for_tools(tool_name)

    @classmethod
    def select_app_with_fuzzy_search(cls, recently_installed_package=None):
        """Interactive app selection with fuzzy search capability.

        Delegates to AppSelectionService for the implementation.

        :param recently_installed_package: Package name of a recently installed app.
        :returns: Selected package name, or None if cancelled.
        """
        return _service("get_app_selection_service").select_app_with_fuzzy_search(
            recently_installed_package=recently_installed_package
        )

    @classmethod
    def get_spotlighted_app_data_path(cls):
        """Returns the app data path. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_spotlighted_app_data_path()

    @classmethod
    def set_network_capture_path(cls, path):
        """Delegates to NetworkCaptureService to set the capture file path."""
        _service("get_network_capture_service").start_capture(output_file=path)

    @classmethod
    def get_spotlight_files(cls):
        """Returns the spotlight files list. Delegates to SpotlightService."""
        return _service("get_spotlight_service").get_spotlight_files()

    @classmethod
    def add_spotlight_file(cls, file_path):
        """Adds a file to the spotlight files list for monitoring.

        Delegates to ForensicService.add_spotlight_file().

        :param file_path: Path to the file or pattern to add
        :type file_path: str
        :return: True if the file(s) were added, False otherwise
        :rtype: bool
        """
        return _service("get_forensic_service").add_spotlight_file(file_path, adb=Adb)

    @classmethod
    def remove_spotlight_file(cls, file_path=None):
        """Removes a file from the spotlight files list. Delegates to SpotlightService."""
        _service("get_spotlight_service").remove_spotlight_file(file_path)

    # ==================== File Operations ====================

    @classmethod
    def pull_file(cls, number, file_to_pull):
        """Pulls a file from the emulator and saves it to the specified directory.

        Delegates to FileExtractionService for the implementation.

        :param number: The pull id, used as the folder name (e.g., "first", "second", "noise").
        :type number: str
        :param file_to_pull: The file to pull from the emulator.
        :type file_to_pull: str
        """
        _service("get_file_extraction_service").pull_file_legacy(number, file_to_pull)

    @classmethod
    def pull_spotlight_files(cls, description=None):
        """Delegates to FileExtractionService to pull spotlight files."""
        spotlight_files = _service("get_forensic_service").get_spotlight_files()
        if not spotlight_files:
            cls.logger.warning("No spotlight files are set.")
            return False
        pulled = _service("get_file_extraction_service").pull_spotlight_files(
            files=list(spotlight_files), description=description
        )
        return len(pulled) > 0

    @classmethod
    def highlight_timestamps(cls, s, restColor):
        """Delegates to OutputFormatter.highlight_timestamps()."""
        svc = _service("get_action_window_service")
        return OutputFormatter.highlight_timestamps(
            text=s,
            rest_color=restColor,
            action_time=svc.get_action_time(),
            action_duration=svc.get_duration(),
        )

    @classmethod
    def truncate(cls, input_string, line_length_cutoff=150, line_number_cutoff=50):
        """Truncates the input string to a specific length.

        Delegates to OutputFormatter.truncate() for the implementation.

        :param input_string: The input string.
        :param line_length_cutoff: Maximum characters per line (default: 150).
        :param line_number_cutoff: Maximum number of lines (default: 50).
        :returns: The truncated string.
        """
        return OutputFormatter.truncate(
            input_string=input_string,
            line_length_cutoff=line_length_cutoff,
            line_number_cutoff=line_number_cutoff,
        )

    @classmethod
    def restart_emulator(cls):
        """Restarts the Android emulator.

        Delegates to EmulatorService.restart() for the implementation.
        """
        _service("get_emulator_service").restart()

    # ==================== Proxy ====================

    @classmethod
    def get_proxy_settings(cls):
        """Gets the current HTTP proxy settings from the device.

        Delegates to ProxyService for the implementation.

        :returns: The current HTTP proxy settings as a string or "Not set" if no proxy is configured.
        :rtype: str
        """
        return _service("get_proxy_service").get_proxy_string()

    @classmethod
    def show_blocking_warning(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Delegates to UIService."""
        return _service("get_ui_service").show_blocking_warning(
            title, message, action_hint, action_key
        )

    @classmethod
    def show_blocking_error(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Delegates to UIService."""
        return _service("get_ui_service").show_blocking_error(
            title, message, action_hint, action_key
        )

    @classmethod
    def show_blocking_info(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Delegates to UIService."""
        return _service("get_ui_service").show_blocking_info(
            title, message, action_hint, action_key
        )

    @classmethod
    def set_unset_proxy(cls):
        """Toggles the network proxy on the emulator.

        Delegates to ProxyService for the implementation.
        """
        _service("get_proxy_service").set_unset_proxy()

    @classmethod
    def get_host_ip(cls):
        """Gets the host's IP address (delegated to SetupService).

        :returns: The host's IP address or "127.0.0.1" if no suitable IP is found.
        :rtype: str
        """
        return _service("get_setup_service").get_host_ip()

    # ==================== Screenshot & Recording ====================

    @classmethod
    def take_screenshot(cls, filename=None):
        """Takes a screenshot of the Android device.

        Delegates to EmulatorService for the actual implementation.

        :param filename: Optional custom filename, otherwise a timestamped name is used
        :type filename: str
        :returns: Path to the saved screenshot file
        :rtype: str
        """
        result = _service("get_emulator_service").take_screenshot(filename)
        if result:
            cls.mark_tool_used("screenshots", files=[result])
        return result

    @classmethod
    def start_screen_recording(cls, filename=None):
        """Delegates to EmulatorService.start_recording()."""
        return _service("get_emulator_service").start_recording(filename)

    @classmethod
    def stop_screen_recording(cls):
        """Stops the current screen recording.

        Delegates to EmulatorService for the actual implementation.

        :returns: Path to recording file if successful, False otherwise
        :rtype: str or bool
        """
        result = _service("get_emulator_service").stop_recording()
        return result if result else False

    @classmethod
    def print_interactive_menu(cls):
        """Prints the interactive main menu with view-based filtering.

        Delegates to MenuRenderer for the actual rendering logic.
        """
        renderer = cls._get_menu_renderer()
        renderer.render()

    @classmethod
    def _create_colored_box(
        cls, text: str, title: str, border_color: str = "cyan"
    ) -> str:
        """Delegates to MenuRenderer for creating a colored box.

        :param text: The text to be enclosed in the box.
        :param title: The title of the box (can include Rich markup).
        :param border_color: Color for the box borders.
        :returns: The formatted box with Rich color markup.
        """
        renderer = cls._get_menu_renderer()
        return renderer._create_colored_box(text, title, border_color)

    @classmethod
    def _create_ascii_box(cls, text: str, title: str) -> str:
        """Delegates to MenuRenderer for creating an ASCII box.

        :param text: The text to be enclosed in the ASCII box.
        :param title: The title of the ASCII box.
        :returns: The formatted ASCII box.
        """
        renderer = cls._get_menu_renderer()
        return renderer._create_ascii_box(text, title)

    @classmethod
    def wrap_up(cls):
        """Closing routine to handle tasks before the program finishes."""
        if cls.args.hash:
            cls.calculate_hashes()
        if cls.args.apk:
            cls.pull_and_hash_apks()
        cls.submit_other_data("Timeline Data", cls._timestamps_shadow_dict_list)

    # ==================== Tool Usage Tracking ====================

    @classmethod
    def mark_tool_used(cls, tool_name: str, files: list = None):
        """Delegates to ToolUsageService.mark_used()."""
        _service("get_tool_usage_service").mark_used(tool_name, files=files)

    @classmethod
    def get_tools_used(cls) -> dict:
        """Delegates to ToolUsageService.get_usage()."""
        return _service("get_tool_usage_service").get_usage()

    # ==================== Background Task Management ====================

    @classmethod
    def register_background_task(
        cls,
        name: str,
        display_name: str,
        instance: object,
        stop_callback: Callable,
        started_by: str = None,
        app_name: str = None,
        target_pid: int = None,
    ):
        """Register a new background task. Delegates to TaskService."""
        _service("get_task_service").register(
            name=name,
            display_name=display_name,
            instance=instance,
            stop_callback=stop_callback,
            started_by=started_by,
            app_name=app_name,
            target_pid=target_pid,
        )

    @classmethod
    def unregister_background_task(cls, name: str):
        """Remove a task from tracking. Delegates to TaskService."""
        _service("get_task_service").unregister(name)

    @classmethod
    def is_task_running(cls, name: str) -> bool:
        """Check if a specific task is running. Delegates to TaskService."""
        return _service("get_task_service").is_running(name)

    @classmethod
    def get_running_tasks(cls) -> list[str]:
        """Get list of all running task names. Delegates to TaskService."""
        return _service("get_task_service").get_running()

    @classmethod
    def get_task(cls, name: str) -> BackgroundTask | None:
        """Get a specific background task by name. Delegates to TaskService."""
        return _service("get_task_service").get_task(name)

    @classmethod
    def get_tasks_started_by(cls, parent_name: str) -> list[str]:
        """Get tasks started by a specific parent. Delegates to TaskService."""
        return _service("get_task_service").get_tasks_started_by(parent_name)

    @classmethod
    def stop_task(cls, name: str) -> bool:
        """Stop a single task. Delegates to TaskService."""
        return _service("get_task_service").stop(name)

    @classmethod
    def stop_task_with_prompt(cls, name: str) -> bool:
        """Stop a task with user prompt for dependents. Delegates to TaskService."""
        return _service("get_task_service").stop_with_prompt(name)

    @classmethod
    def stop_all_background_tasks(cls):
        """Stop all running background tasks. Delegates to TaskService."""
        _service("get_task_service").stop_all()

    @classmethod
    def get_background_tasks_status_string(cls) -> str:
        """Get formatted string showing running tasks. Delegates to TaskService."""
        return _service("get_task_service").get_status_string()

    # ==================== Exit & Summary ====================

    @classmethod
    def print_exit_summary(cls):
        """Delegates to UIService.print_exit_summary()."""
        _service("get_ui_service").print_exit_summary(
            tools_used=_service("get_tool_usage_service").get_usage()
        )

    @classmethod
    def calculate_hashes(cls):
        """Calculates MD5 hashes for new and changed files.

        Delegates to FileExtractionService for the implementation.
        """
        hashes = _service("get_file_extraction_service").calculate_hashes()
        cls.submit_other_data("Artifact Hashes", hashes)

    @classmethod
    def pull_and_hash_apks(cls):
        """Pulls APKs from the emulator, calculates their hashes and submits them.

        Delegates to FileExtractionService for the implementation.
        """
        result = _service("get_file_extraction_service").pull_and_hash_apks()
        cls.submit_other_data("APK Hashes", result.get("apk_hashes", []))

    @classmethod
    def exclude_whitelist(cls, file_paths):
        """Delegates to ForensicService.exclude_whitelist()."""
        if not cls.args or not cls.args.whitelist:
            return file_paths
        service = _service("get_forensic_service")
        service.set_whitelist_path(cls.args.whitelist)
        return service.exclude_whitelist(file_paths)

    @classmethod
    def submit_other_data(cls, identifier, data):
        """Submits data to the 'other' section of the output file."""
        cls.logger.debug(f'Submitting Data of type {identifier} into "other" section')
        if identifier not in cls.other_output_data_collector:
            cls.other_output_data_collector[identifier] = [data]
        else:
            cls.other_output_data_collector[identifier].append(data)

    # ==================== Frida Session Management ====================

    @classmethod
    def get_frida_job_manager(cls):
        """Returns the Frida job manager instance.

        Delegates to FridaSessionService for job management.

        :returns: The Frida job manager instance.
        :rtype: JobManager
        """
        return _service("get_frida_session_service").get_job_manager()

    @classmethod
    def update_frida_device_serial(cls, serial: str) -> None:
        """Update the device serial on FridaManager and JobManager.

        Delegates to FridaSessionService for device serial management.

        :param serial: The device serial to target
        """
        _service("get_frida_session_service").update_device_serial(serial)

    @classmethod
    def has_active_frida_session(cls) -> bool:
        """Delegates to FridaSessionService.has_active_session()."""
        return _service("get_frida_session_service").has_active_session()

    @classmethod
    def get_frida_session_info(cls) -> dict | None:
        """Delegates to FridaSessionService.get_session_info()."""
        return _service("get_frida_session_service").get_session_info()

    @classmethod
    def get_running_frida_jobs(cls) -> list:
        """Delegates to FridaSessionService.get_running_jobs()."""
        return _service("get_frida_session_service").get_running_jobs()

    @classmethod
    def check_frida_hook_conflicts(cls, hooks: list) -> dict:
        """Delegates to FridaSessionService.check_hook_conflicts()."""
        return _service("get_frida_session_service").check_hook_conflicts(hooks)

    @classmethod
    def register_frida_hooks(cls, job_id: str, hooks: list) -> list:
        """Delegates to FridaSessionService.register_hooks()."""
        return _service("get_frida_session_service").register_hooks(job_id, hooks)

    @classmethod
    def unregister_frida_hooks(cls, job_id: str) -> None:
        """Delegates to FridaSessionService.unregister_hooks()."""
        return _service("get_frida_session_service").unregister_hooks(job_id)

    # ==================== Spawn Mode Helpers ====================

    @classmethod
    def spawn_app_paused(cls, package_name: str) -> tuple:
        """Delegates to SpotlightService. Returns (JobManager, pid) or (None, -1)."""
        service = _service("get_spotlight_service")
        result = service.spawn_app_paused(package_name)
        cls._spawn_mode = service.is_spawn_mode()
        cls._auto_resume_after_spawn = service.get_auto_resume()
        cls._spotlight_spawn_application = service.get_spawn_package()
        return result

    @classmethod
    def resume_paused_app(cls) -> bool:
        """Resume a paused app after tools have been loaded.

        Delegates to SpotlightService for the implementation.

        Returns:
            True if app was resumed successfully, False otherwise.
        """
        service = _service("get_spotlight_service")
        result = service.resume_paused_app()
        # Keep local state in sync
        cls._auto_resume_after_spawn = service.get_auto_resume()
        return result

    @classmethod
    def is_app_paused(cls) -> bool:
        """Check if there's a paused app waiting to be resumed.

        Delegates to SpotlightService for the implementation.

        Returns:
            True if an app is paused, False otherwise.
        """
        return _service("get_spotlight_service").is_app_paused()

    @classmethod
    def get_spawn_mode(cls) -> str:
        """Get the current spawn mode setting.

        Delegates to SpotlightService for the implementation.

        Returns:
            One of: 'multi_tool', 'single_tool', 'late_attach'
        """
        return _service("get_spotlight_service").get_spawn_mode_string()

    @classmethod
    def set_spawn_mode(cls, mode) -> None:
        """Delegates to SpotlightService.set_spawn_mode()."""
        service = _service("get_spotlight_service")
        service.set_spawn_mode(mode)
        cls._spawn_mode = service.is_spawn_mode()
        cls._auto_resume_after_spawn = service.get_auto_resume()

    @classmethod
    def reset_frida_session(cls) -> None:
        """Delegates to FridaSessionService.reset_session()."""
        return _service("get_frida_session_service").reset_session()

    # ==================== Export & Recording ====================

    @classmethod
    def export_action(cls, snapshot_name="tmp"):
        """Export a snapshot and recording as an action archive.

        Delegates to FileExtractionService.export_action() for the implementation.
        """
        _service("get_file_extraction_service").export_action(
            snapshot_name=snapshot_name,
            device_name=cls.device_name,
            user_input_callback=cls.safe_input,
        )

    @classmethod
    def toggle_screen_record(cls):
        """Starts or stops screen recording on the emulator.

        Delegates to EmulatorService.toggle_recording() for backwards compatibility.
        """
        _is_now_recording, message = _service("get_emulator_service").toggle_recording()
        cls.logger.info(message)
