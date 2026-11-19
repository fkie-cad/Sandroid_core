import logging
import os
import re
import threading
import time

import click
from friTap import SSL_Logger

from sandroid.core.analysis_logging import setup_analysis_logging
from sandroid.core.console import SandroidConsole
from sandroid.core.enums import SpawnMode
from sandroid.core.events import Event, EventBus, EventType
from sandroid.core.frida_manager import (
    _crash_summary,
    install_stale_detach_guard,
    stop_frida_job_bounded,
)
from sandroid.services import (
    get_network_capture_service,
    get_task_service,
)

from .base_di import DataGatherBase
from .fritap_config import configure_fritap_cli, configure_fritap_tui
from .fritap_formatter import FriTapMessageFormatter

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


logger = logging.getLogger(__name__)

#: Max seconds stop() waits for friTap's agent to unload before finalizing.
_STOP_TIMEOUT = 4.0

#: Extra seconds a watchdog gives an agent unload that outlived
#: ``_STOP_TIMEOUT``. An unload still blocked after that left the app frozen
#: ("isn't responding") for good in the phase-4 live test: a spawned target
#: is then force-stopped, for an attached one the user is told how to recover.
_HUNG_UNLOAD_GRACE = 15.0

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$")

#: Max seconds the target-death handler waits for the command layer to
#: register the task (the target can die while start() is still returning).
_REGISTER_WAIT = 5.0

#: PIDs that carried a friTap agent in this Sandroid process, per device.
#: Loading friTap's agent a second time into the same process (re-attach after
#: a stop) crashed the app 3/3 times in phase 3 (SIGSEGV in frida-agent, JNI
#: GetStringChars); fresh processes 0/2.
_INJECTED_PIDS: dict[str, set[int]] = {}
_INJECTED_LOCK = threading.Lock()

# -- lifecycle ---------------------------------------------------------------
#
# The task registry only knows "registered or not": friTap registers after
# its (slow) attach and unregisters after its (slow) agent unload, so the UI
# said "stopped" for ~50 s while friTap was starting and "running" for ~20 s
# after a stop. The phase below follows the real lifecycle; the Network lens
# shows it and listens for its STATE_CHANGED events (source "fritap").

#: starting -> running (-> hung) -> stopping -> stopped, or -> failed
FRITAP_PHASES = ("stopped", "starting", "running", "hung", "stopping", "failed")
_LIFECYCLE = {"phase": "stopped", "detail": ""}
_LIFECYCLE_LOCK = threading.Lock()

#: Seconds between "is the target app frozen?" checks while friTap runs.
_ANR_POLL_SECONDS = 8.0


def lifecycle() -> tuple[str, str]:
    """``(phase, detail)`` of friTap, see :data:`FRITAP_PHASES`."""
    with _LIFECYCLE_LOCK:
        return _LIFECYCLE["phase"], _LIFECYCLE["detail"]


def set_lifecycle(phase: str, detail: str = "") -> None:
    """Record friTap's phase and tell the UI (STATE_CHANGED, source fritap)."""
    with _LIFECYCLE_LOCK:
        if _LIFECYCLE["phase"] == phase and _LIFECYCLE["detail"] == detail:
            return
        _LIFECYCLE["phase"] = phase
        _LIFECYCLE["detail"] = detail
    try:
        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"component": "fritap", "phase": phase, "detail": detail},
                source="fritap",
            )
        )
    except Exception as e:
        logger.debug(f"friTap lifecycle event failed: {e}")


def app_not_responding(package: str | None) -> bool | None:
    """True while Android shows an "isn't responding" dialog for ``package``.

    Reads the window list (``dumpsys window windows``): the ANR dialog is a
    window titled ``Application Not Responding: <package>``. None when the
    device could not be asked.
    """
    if not package:
        return None
    try:
        from sandroid.core.adb import Adb
        from sandroid.core.adb_utils import quiet_adb_warnings

        with quiet_adb_warnings():
            out, _ = Adb.send_adb_command("shell dumpsys window windows", timeout=10)
    except Exception as e:
        logger.debug(f"ANR check failed: {e}")
        return None
    if not out:
        return None
    return f"Application Not Responding: {package}" in out


class FriTapTargetError(RuntimeError):
    """The target can't take friTap right now (user-actionable, no traceback)."""

    expected = True


def _device_key() -> str:
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device() or "default"
    except Exception:
        return "default"


def remember_injected_pid(pid: int | None) -> None:
    """Record that friTap's agent was loaded into *pid* on the current device."""
    if not pid:
        return
    with _INJECTED_LOCK:
        _INJECTED_PIDS.setdefault(_device_key(), set()).add(int(pid))


def forget_injected_pid(pid: int | None) -> None:
    """Drop *pid* (its process is gone, the number may be reused)."""
    if not pid:
        return
    with _INJECTED_LOCK:
        _INJECTED_PIDS.get(_device_key(), set()).discard(int(pid))


def was_injected(pid: int | None) -> bool:
    """True if friTap's agent was loaded into *pid* earlier in this session."""
    if not pid:
        return False
    with _INJECTED_LOCK:
        return int(pid) in _INJECTED_PIDS.get(_device_key(), set())


def frida_agent_mapped(pid: int) -> bool | None:
    """True if ``/proc/<pid>/maps`` shows a loaded frida-agent.

    Catches agents left behind by an earlier Sandroid process (or another
    Frida client) that the in-memory PID set cannot know about. Returns None
    if the maps could not be read (no root, adb error).
    """
    try:
        from sandroid.core.adb import Adb
    except Exception:
        return None
    for prefix in ("shell", "shell su 0"):
        try:
            out, err = Adb.send_adb_command(
                f"{prefix} grep -c frida-agent /proc/{int(pid)}/maps"
            )
        except Exception as e:
            logger.debug(f"Reading maps of {pid} failed: {e}")
            return None
        text = (out or "").strip().splitlines()
        if text and text[-1].strip().isdigit():
            return int(text[-1].strip()) > 0
        if (
            "denied" not in (err or "").lower()
            and "not found" not in (err or "").lower()
        ):
            break
    return None


def _force_stop_if_running(package: str | None, pid: int | None) -> bool:
    """Force-stop *package* if *pid* is still its process. True if stopped.

    The PID check keeps a process the user restarted in the meantime alive.
    """
    if not package or not _PACKAGE_NAME.match(str(package)) or not pid:
        return False
    try:
        from sandroid.core.adb import Adb

        out, _err = Adb.send_adb_command(f"shell pidof {package}")
        if str(int(pid)) not in (out or "").split():
            logger.debug(f"{package} PID {pid} is gone, nothing to force-stop")
            return False
        Adb.send_adb_command(f"shell am force-stop {package}")
        return True
    except Exception as e:
        logger.debug(f"Force-stop of {package} failed: {e}")
        return False


def _job_state(job) -> str | None:
    """AFM Job state ("initialized", "running", "error", "stopping", "stopped").

    AndroidFridaManager 2.0.7's ``Job`` exposes a plain ``state`` attribute
    (no ``get_state()``); accept both.
    """
    get_state = getattr(job, "get_state", None)
    if callable(get_state):
        return get_state()
    return getattr(job, "state", None)


# FriTap hooks SSL/TLS functions - used for conflict detection with other Frida tools
FRITAP_SSL_HOOKS = [
    "SSL_read",
    "SSL_write",
    "SSL_get_fd",
    "SSL_get_session",
    "SSL_SESSION_get_id",
    "SSL_new",
    "SSL_do_handshake",
    "SSL_connect",
    "SSL_accept",
    "SSLRead",  # iOS/macOS
    "SSLWrite",  # iOS/macOS
    "SSLHandshake",  # iOS/macOS
    "boringssl_read",
    "boringssl_write",
    "PR_Read",  # NSS
    "PR_Write",  # NSS
    "gnutls_record_recv",
    "gnutls_record_send",
]


# Custom logging handler that forwards to EventBus for activity log display
class EventBusHandler(logging.Handler):
    """Logging handler that forwards messages to the EventBus for TUI display."""

    def __init__(self, task_name: str = "FriTap"):
        super().__init__()
        self.task_name = task_name
        self._event_bus = None

    @property
    def event_bus(self):
        """Lazy load EventBus to avoid circular imports."""
        if self._event_bus is None:
            from sandroid.core.events import EventBus

            self._event_bus = EventBus.get()
        return self._event_bus

    def emit(self, record: logging.LogRecord):
        """Emit a log record to the EventBus."""
        try:
            from sandroid.core.events import Event, EventType

            msg = self.format(record)
            # Add level indicator for visual distinction
            if record.levelno >= logging.ERROR:
                msg = f"[error]{msg}[/error]"
            elif record.levelno >= logging.WARNING:
                msg = f"[warning]{msg}[/warning]"
            _publish_fritap_event(self.event_bus, msg)
        except Exception:
            # Don't let logging errors break the application
            pass


def _get_device_results_path() -> str:
    """Get the device-specific results path, falling back to RESULTS_PATH env var."""
    try:
        from sandroid.services import get_initialization_service

        device_path = get_initialization_service().get_device_path()
        if device_path:
            return str(device_path) + (
                "/" if not str(device_path).endswith("/") else ""
            )
    except Exception as e:
        logger.debug(f"Could not get device path from InitializationService: {e}")

    # Fallback: RESULTS_PATH should already point to device dir
    results_path = os.getenv("RESULTS_PATH", "")
    if results_path:
        return results_path

    # Last resort: session root
    return os.getenv("SESSION_PATH", "")


def _session_stamp(fritap_dir: str) -> str:
    """A timestamp naming one friTap session's files, unique in *fritap_dir*."""
    base = time.strftime("%Y%m%d_%H%M%S")
    stamp, n = base, 1
    while any(
        os.path.exists(os.path.join(fritap_dir, name))
        for name in (
            f"fritap_keylog_{stamp}.log",
            f"fritap_output_{stamp}.json",
            f"fritap_capture_{stamp}_1.pcap",
        )
    ):
        n += 1
        stamp = f"{base}_{n}"
    return stamp


def _detach_quietly(session, timeout: float = 2.0) -> None:
    """Detach a frida session on a daemon thread, bounded (never raises)."""
    if session is None or not hasattr(session, "detach"):
        return

    def _work() -> None:
        try:
            session.detach()
        except Exception as e:
            logger.debug(f"Detaching probe session: {e}")

    worker = threading.Thread(target=_work, name="fritap-probe-detach", daemon=True)
    worker.start()
    worker.join(timeout)


def _is_console_message(message: dict) -> bool:
    """True for agent ``console`` payloads (also emitted via the friTap logger)."""
    payload = message.get("payload") if isinstance(message, dict) else None
    return isinstance(payload, dict) and payload.get("contentType") == "console"


def _publish_fritap_event(event_bus, message: str):
    """Publish a FriTap TASK_OUTPUT event to the EventBus.

    Consolidates the repeated EventBus.publish pattern used throughout FriTap.

    Args:
        event_bus: The EventBus instance to publish on.
        message: The message string to include in the event.
    """
    event_bus.publish(
        Event(
            type=EventType.TASK_OUTPUT,
            data={
                "task_name": "FriTap",
                "message": message,
            },
            source="fritap",
        )
    )


# Set up dedicated fritap log file
def _setup_fritap_logging():
    """Set up dedicated file logging for friTap in the fritap results folder."""
    fritap_dir = f"{_get_device_results_path()}fritap/"
    log_path = setup_analysis_logging(
        logger_name="friTap",
        log_dir=fritap_dir,
        log_filename="fritap.log",
    )
    if log_path:
        logger.debug(f"FriTap logs will be saved to {log_path}")


def _setup_activity_log_handler():
    """Add EventBus handler to friTap logger for activity log display."""
    fritap_logger = logging.getLogger("friTap")

    # Check if we already have an EventBus handler
    has_eventbus_handler = any(
        isinstance(handler, EventBusHandler) for handler in fritap_logger.handlers
    )

    if not has_eventbus_handler:
        handler = EventBusHandler(task_name="FriTap")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        fritap_logger.addHandler(handler)
        return handler
    return None


def _remove_activity_log_handler():
    """Remove EventBus handler from friTap logger."""
    fritap_logger = logging.getLogger("friTap")
    handlers_to_remove = [
        h for h in fritap_logger.handlers if isinstance(h, EventBusHandler)
    ]
    for handler in handlers_to_remove:
        fritap_logger.removeHandler(handler)


class FriTap(DataGatherBase):
    def __init__(self, **kwargs):
        """Initialize FriTap without process_id - will get session info when starting."""
        super().__init__(**kwargs)
        self.last_results = {}
        self.job_manager = self._get_toolbox().get_frida_job_manager()
        self.process_id = None
        self.app_package = None
        self.mode = None
        self.ssl_log = None
        self.frida_script_path = None
        self.show_in_activity_log = False
        self.print_to_console = (
            False  # Print key captures to console (for CLI/headless mode)
        )
        # Agent console lines are also logged by the "friTap" logger; callers
        # that route that logger to the terminal set this to False so each
        # line is printed once.
        self.print_console_messages = True
        self.message_handler = None  # Will be set up in _setup_session
        # Set once stop() gave up waiting for the agent: late messages from a
        # still-unloading agent must not race the finalized output files.
        self._outputs_closed = False
        # Explicit keylog path (CLI --output) set before start(); kept.
        self.keylog_path = None
        self.json_output_path = None
        self.network_capture_path = None
        self._network_instance = None
        self._target_session = None
        self._stop_lock = threading.Lock()
        self._stopping = False
        self._stopped = False
        self.target_gone: str | None = None

    def _create_activity_log_wrapper(self, original_handler):
        """Create a wrapper that forwards messages to the activity log and/or console.

        Args:
            original_handler: The original on_fritap_message handler from SSL_Logger

        Returns:
            A wrapped handler that also publishes to the EventBus and/or prints to console
        """
        event_bus = EventBus.get()
        formatter = FriTapMessageFormatter()

        def wrapper(job, message, data):
            if getattr(self, "_outputs_closed", False):
                return None
            # Forward to activity log (TUI) and/or console (CLI/headless)
            should_forward = self.show_in_activity_log or self.print_to_console

            if should_forward:
                try:
                    msg = formatter.format_message(message, data)
                    if msg is not None:
                        if self.show_in_activity_log:
                            _publish_fritap_event(event_bus, msg)
                        if self.print_to_console and (
                            self.print_console_messages
                            or not _is_console_message(message)
                        ):
                            print(f"[friTap] {msg}")
                except Exception as e:
                    # Log at warning level for visibility during debugging
                    logger.warning(
                        f"Error forwarding FriTap message to activity log: {e}"
                    )

            # Always call the original handler
            return original_handler(job, message, data)

        return wrapper

    def _setup_session(self, config: dict = None):
        """Set up FriTap session following the old proven pattern.

        Creates Frida device AND session in the SAME worker thread via
        get_frida_session_for_spotlight(), avoiding the thread-affinity
        violation that caused FriTap to hang in TUI mode.

        Args:
            config: Optional configuration dict from interactive menu

        Raises:
            ValueError: If no spotlight app is selected or app not running
        """
        from sandroid.core.toolbox import Toolbox

        # Use config or defaults
        output_keylog = config.get("output_keylog", True) if config else True
        output_json = config.get("output_json", True) if config else True
        verbose = config.get("verbose", False) if config else False
        debug_output = config.get("debug_output", False) if config else False
        self.show_in_activity_log = (
            config.get("show_in_activity_log", False) if config else False
        )

        # Set up activity log handler for friTap's verbose/debug output
        if self.show_in_activity_log:
            _setup_activity_log_handler()

        # Set up file logging NOW (device path is available)
        _setup_fritap_logging()

        # Use fritap folder in device-specific results path. Every session
        # gets its own files: a later session must never overwrite the keys
        # of an earlier one (phase 3 lost cycle 1's 20-key keylog).
        fritap_dir = f"{_get_device_results_path()}fritap/"
        # Created here, not with the session (no empty folders); the log
        # handler of an earlier device does not create this one.
        os.makedirs(fritap_dir, exist_ok=True)
        self.session_stamp = _session_stamp(fritap_dir)
        if output_keylog and not self.keylog_path:
            self.keylog_path = f"{fritap_dir}fritap_keylog_{self.session_stamp}.log"
        elif not output_keylog:
            self.keylog_path = None
        if output_json and not self.json_output_path:
            self.json_output_path = (
                f"{fritap_dir}fritap_output_{self.session_stamp}.json"
            )
        elif not output_json:
            self.json_output_path = None
        self.log_path = f"{fritap_dir}fritap.log"

        # Attach mode: re-resolve the PID (the cached one may belong to a
        # crashed process) and refuse a second friTap agent in one process.
        self._check_attach_target()

        # Get session via unified getter (creates fresh device on worker thread)
        # This is the old proven pattern — no pre-initialized devices, no fork issues.
        probe_session, mode, app_info = Toolbox.get_frida_session_for_spotlight()
        self.process_id = app_info["pid"]
        self.app_package = app_info["package_name"]
        self.mode = mode
        self.frida_device = app_info["device"]
        # The device that spawned the target (kept: frida_device is replaced by
        # the JobManager's device below).
        self._spawn_device = app_info["device"]

        logger.debug(
            f"Frida session created: {self.app_package} "
            f"(PID: {self.process_id}, mode: {self.mode})"
        )

        # Initialize SSL_Logger (use app_package for spawn, process_id for attach)
        target = self.app_package if self.mode == "spawn" else self.process_id
        self.ssl_log = SSL_Logger(
            target,
            verbose=verbose,
            keylog=self.keylog_path,
            debug_output=debug_output,
            json_output=self.json_output_path,
        )
        # SSL_Logger only drives the agent here (Sandroid owns spawn/attach),
        # so record the real target mode in fritap_output.json's session_info.
        try:
            info = self.ssl_log.session_data["session_info"]
            info["spawn"] = self.mode in (SpawnMode.SPAWN, SpawnMode.SPAWN.value)
            info["mobile"] = True
            info["target_app"] = self.app_package
            info["pid"] = self.process_id
        except Exception:
            pass

        # Log the configuration
        if verbose or debug_output:
            logger.debug(f"FriTap started with verbose={verbose}, debug={debug_output}")
        if self.show_in_activity_log:
            logger.debug("FriTap output will be shown in activity log")

        # Create message handler - wrap with activity log forwarder if enabled
        self.message_handler = self._create_activity_log_wrapper(
            self.ssl_log.on_fritap_message
        )

        # Get the Frida script path from SSL_Logger
        # (friTap 2.0 renamed get_fritap_frida_script_path() -> get_agent_script_path())
        self.frida_script_path = self.ssl_log.get_agent_script_path()

        # Register with JobManager using setup_frida_session (old proven pattern).
        # setup_frida_session(should_spawn=False) will:
        # 1. Call setup_frida_handler() → creates fresh device on worker thread
        # 2. Call attach_app() → does device.attach(pid) (second attach, harmless)
        install_stale_detach_guard(self.job_manager)
        self.job_manager.setup_frida_session(
            self.process_id,
            self.message_handler,
            should_spawn=False,
        )
        self.frida_device = self.job_manager.device
        # The getter's own session is not used by anyone; leaving it attached
        # kept an agent session open in the app after friTap stopped.
        _detach_quietly(probe_session)
        self._watch_target(self.job_manager.process_session)

        logger.debug(
            f"FriTap initialized in {self.mode.upper()} mode for "
            f"{self.app_package} (PID: {self.process_id})"
        )

    def _check_attach_target(self) -> None:
        """Validate the attach target before any Frida session touches it.

        - Re-resolves the spotlight PID: after a crash the cached PID belonged
          to a dead process and every start failed with ProcessNotFoundError
          until the app was re-selected.
        - Refuses a PID that already carries friTap's (or another stale)
          Frida agent: re-attaching crashed the app every time in phase 3.

        Raises:
            FriTapTargetError: The app is not running, or the process already
                carries an agent.
        """
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        if spotlight.is_spawn_mode() and spotlight.get_spawn_package():
            return  # a spawn always gives a fresh process
        app_tuple = spotlight.get_app_tuple()
        if not app_tuple:
            return  # the session getter raises its own guidance
        package = app_tuple[0]
        cached = spotlight.get_pid()

        from sandroid.core.adb import Adb

        live = Adb.get_pid_for_package_name(package, quiet=True)
        if live != cached:
            if cached:
                logger.info(
                    f"Spotlight PID {cached} of {package} is stale; "
                    f"now {live or 'not running'}"
                )
            spotlight.announce_pid(live, package)
        if not live:
            raise FriTapTargetError(
                f"{package} is not running. Start it (Spotlight Enter) or use "
                "spawn mode (Shift+C)."
            )

        why = None
        if was_injected(live):
            why = "friTap already ran in this process earlier"
        elif frida_agent_mapped(live) and not self._shared_live_session():
            why = "the process still carries a Frida agent from an earlier session"
        if why:
            raise FriTapTargetError(
                f"Not attaching friTap to {package} (PID {live}): {why}. "
                "Injecting a second agent into the same process crashes the app. "
                "Restart the app (Spotlight ⇧R) or use spawn mode (Shift+C) "
                "for a fresh process."
            )

    def _shared_live_session(self) -> bool:
        """True if another Sandroid tool has jobs running on the JobManager.

        Its agent is live and wanted (multi-script on a running process is
        fine); only a leftover agent from an earlier session is refused.
        """
        try:
            return bool(
                self.job_manager.has_active_session()
                and self.job_manager.running_jobs()
            )
        except Exception:
            return False

    def _watch_target(self, session) -> None:
        """Get told when the target process dies (crash, kill, respawn)."""
        self._target_session = session
        if session is None or not hasattr(session, "on"):
            return
        try:
            session.on(
                "detached",
                lambda reason, crash=None: self._on_target_detached(reason, crash),
            )
        except Exception as e:
            logger.debug(f"Could not watch the friTap target: {e}")

    def _on_target_detached(self, reason, crash=None) -> None:
        """Frida thread: the session ended. React off-thread (never blocks)."""
        if getattr(self, "_stopping", False) or getattr(self, "_stopped", False):
            return
        if str(reason) == "application-requested":
            return  # our own detach
        threading.Thread(
            target=self._handle_target_death,
            args=(str(reason), crash),
            name="fritap-target-gone",
            daemon=True,
        ).start()

    def _handle_target_death(self, reason: str, crash=None) -> None:
        """Stop friTap after its target died, so nothing stays "running".

        Finalizes the outputs, stops the friTap network capture, unregisters
        the task (the panel flips to stopped) and clears the dead PID from the
        Spotlight so the next start re-resolves it.
        """
        pid, package = self.process_id, self.app_package
        summary = _crash_summary(crash)
        self.target_gone = reason
        what = "crashed" if crash else "is gone"
        set_lifecycle("stopping", f"{package} {what}")
        msg = (
            f"Target {package} (PID {pid}) {what} ({reason}"
            + (f": {summary}" if summary else "")
            + ") - friTap stopped, outputs finalized"
        )
        logger.warning(msg)
        try:
            _publish_fritap_event(EventBus.get(), f"[warning]{msg}[/warning]")
        except Exception:
            pass
        forget_injected_pid(pid)
        try:
            from sandroid.services import get_spotlight_service

            spotlight = get_spotlight_service()
            if spotlight.get_pid() == pid:
                spotlight.announce_pid(None, package)
        except Exception as e:
            logger.debug(f"Could not clear the spotlight PID: {e}")

        # The command layer registers the task right after start() returns;
        # an attach crash can beat it.
        task_service = get_task_service()
        deadline = time.monotonic() + _REGISTER_WAIT
        while time.monotonic() < deadline:
            task = task_service.get_task("fritap")
            if task is not None and getattr(task, "instance", None) is self:
                task_service.stop("fritap")
                return
            if getattr(self, "_stopping", False) or getattr(self, "_stopped", False):
                return
            time.sleep(0.2)
        self.stop()

    def _interactive_configuration(self) -> dict | None:
        """Interactive configuration menu for FriTap options.

        Returns:
            Configuration dict if user confirms, None if cancelled
        """
        from sandroid.core.ui_request_bus import UIRequestBus

        bus = UIRequestBus.get()
        if bus.has_active_handler():
            return configure_fritap_tui()

        return configure_fritap_cli()

    def start(self, interactive: bool = True) -> bool:
        """Start FriTap monitoring.

        Args:
            interactive: If True, show interactive configuration menu first

        Returns:
            True if started successfully, False if cancelled
        """
        config = None
        network_instance = None
        network_started = False
        toolbox = self._get_toolbox()

        self.cancelled = False
        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("FriTap configuration cancelled")
                self.cancelled = True
                return False

            # Log the configured options for diagnostics
            logger.debug("=== FriTap Configuration Applied ===")
            logger.debug(f"  verbose: {config.get('verbose', False)}")
            logger.debug(f"  debug_output: {config.get('debug_output', False)}")
            logger.debug(
                f"  show_in_activity_log: {config.get('show_in_activity_log', False)}"
            )
            logger.debug(
                f"  enable_network_capture: {config.get('enable_network_capture', False)}"
            )
            logger.debug(f"  output_keylog: {config.get('output_keylog', True)}")
            logger.debug(f"  output_json: {config.get('output_json', True)}")

        set_lifecycle("starting", self.app_package or "")
        try:
            # Set up session FIRST (before starting network) to fail fast
            logger.debug("=== FriTap Session Setup Starting ===")
            if self.process_id is None:
                self._setup_session(config)
            logger.debug("=== FriTap Session Setup Complete ===")
            logger.debug(f"  PID: {self.process_id}")
            logger.debug(f"  Package: {self.app_package}")
            logger.debug(f"  Mode: {self.mode}")

            # Now start network capture if requested (after session setup succeeded)
            if (
                config
                and config.get("enable_network_capture")
                and not get_network_capture_service().is_capturing()
            ):
                # Set long action duration for FriTap sessions (1 hour)
                toolbox.action_duration = 3600
                from sandroid.analysis.network import Network

                network_instance = Network()
                # Own file next to the keylog: never network_trace_run_<n>.pcap,
                # which the analysis runs write (and read back) themselves.
                fritap_dir = os.path.dirname(self.log_path)
                network_instance._get_path = lambda: f"{fritap_dir}/"
                network_instance._trace_file_name = (
                    f"fritap_capture_{self.session_stamp}_"
                )
                network_instance.internal_run_counter = 1
                self.network_capture_path = network_instance.get_expected_capture_path()
                network_instance.gather()  # This starts tcpdump capture
                network_started = True
                self._network_instance = network_instance
                logger.info(
                    f"Network capture started for FriTap: {self.network_capture_path}"
                )

                # Register network as background task (started by fritap)
                get_task_service().register(
                    name="network",
                    display_name="Network Capture",
                    instance=network_instance,
                    stop_callback=network_instance.stop,
                    started_by="fritap",
                )

            # Check for hook conflicts with other running Frida jobs
            conflicts = self._prune_dead_hook_owners(
                toolbox, toolbox.check_frida_hook_conflicts(FRITAP_SSL_HOOKS)
            )
            if conflicts:
                conflict_details = ", ".join(
                    f"{hook} (job: {job_id[:8]}...)"
                    for hook, job_id in conflicts.items()
                )
                logger.warning(
                    f"FriTap may conflict with existing hooks: {conflict_details}"
                )

            # Guard against frida-java-bridge #218: loading friTap's agent (a
            # 2nd Java bridge) onto a STILL-PAUSED spawn that already carries
            # another Java-bridge script (e.g. a detection bypass) SIGSEGVs the
            # agent. The natural flow avoids this — bypasses load paused, the app
            # is resumed, THEN friTap attaches live — so refuse with guidance
            # rather than crash. friTap as the first/only script on a paused
            # spawn is fine (one bridge); only refuse when other jobs are
            # already loaded on the still-paused process.
            if self.job_manager.is_paused() and self.job_manager.running_jobs():
                msg = (
                    "Resume the app before loading friTap on a paused spawn — "
                    "it attaches live, and stacking a 2nd Frida script on a "
                    "still-paused spawn can crash the agent "
                    "(frida-java-bridge #218). Press Enter/Resume first, then "
                    "start friTap."
                )
                logger.error(msg)
                raise FriTapTargetError(msg)

            # Start the job with metadata for job coordination
            # Use wrapped handler that forwards to activity log if enabled
            logger.debug(
                f"FriTap.start(): Calling job_manager.start_job() with script: {self.frida_script_path}"
            )
            job = self.job_manager.start_job(
                self.frida_script_path,
                custom_hooking_handler_name=self.message_handler,
                job_type="fritap",
                display_name="FriTap SSL Logger",
                hooks_registry=FRITAP_SSL_HOOKS,
                priority=10,  # High priority for SSL interception
            )
            logger.debug(f"FriTap.start(): job_manager.start_job() returned: {job}")
            self.job_id = job.get_id() if job else None
            logger.debug(f"FriTap.start(): job_id={self.job_id}")

            # Diagnostic logging for job state
            logger.debug("=== FriTap Job Created ===")
            logger.debug(f"  job_id: {self.job_id}")
            if job:
                job_state = (
                    job.get_state()
                    if hasattr(job, "get_state")
                    else getattr(job, "state", "unknown")
                )
                logger.debug(f"  job.state: {job_state}")
                logger.debug(f"  job.job_type: {getattr(job, 'job_type', 'unknown')}")
            logger.debug(
                f"  job_manager.has_active_session(): {self.job_manager.has_active_session()}"
            )
            logger.debug(
                f"  job_manager.running_jobs(): {self.job_manager.get_running_jobs_info()}"
            )

            # Validate job was actually started
            if not self.job_id:
                raise RuntimeError(
                    "job_manager.start_job() failed to return a valid job"
                )

            # NOTE: We do NOT wait for hooks to load here.
            # The job thread handles hook loading in the background.
            # friTap's own "[+] hooks successfully loaded" message provides user feedback
            # via the friTap logger (which is forwarded to EventBus for TUI display).
            #
            # First-time Frida attach can be slow (15-30s for JIT compilation/caching).
            # Blocking here with a timeout would fail on cold starts.
            # Instead, we return immediately and let friTap's messages show progress.
            logger.debug(
                f"FriTap job started for {self.app_package} (PID: {self.process_id})"
            )

            # Register hooks for conflict detection by other tools
            if self.job_id:
                toolbox.register_frida_hooks(self.job_id, FRITAP_SSL_HOOKS)
            # This process now carries friTap's agent: never inject it twice.
            remember_injected_pid(self.process_id)

            # Resume spawned process now that hooks are installed
            if self.mode == SpawnMode.SPAWN or self.mode == SpawnMode.SPAWN.value:
                self._resume_spawned_target(toolbox, job)

            # Register tool usage and files for exit summary
            files = [self.log_path]
            if self.keylog_path:
                files.append(self.keylog_path)
            if self.json_output_path:
                files.append(self.json_output_path)
            if self.network_capture_path:
                files.append(self.network_capture_path)
            toolbox.mark_tool_used("fritap", files=files)

            # Note: Task registration is handled by the command layer (FriTapCommand.start_task)
            # to avoid duplicate registration and ensure proper lifecycle management

            logger.debug(
                f"FriTap job started with ID: {self.job_id} in {self.mode.upper()} mode for {self.app_package}"
            )

            # Send test message to verify EventBus → ActivityLog path works
            if self.show_in_activity_log:
                event_bus = EventBus.get()
                _publish_fritap_event(
                    event_bus,
                    f"FriTap started for {self.app_package} - activity log enabled",
                )
                logger.debug(
                    "FriTap sent test message to EventBus for activity log verification"
                )

            set_lifecycle("running", self.app_package or "")
            self._start_anr_watch()
            return True

        except Exception as e:
            set_lifecycle("failed", str(e)[:200])
            logger.error(f"Failed to start FriTap: {e}")
            # Shown in the friTap panel, too (it only tails friTap events).
            try:
                _publish_fritap_event(
                    EventBus.get(), f"[error]friTap not started: {e}[/error]"
                )
            except Exception:
                pass
            # Clean up network capture if we started it
            if network_started and network_instance:
                logger.info("Cleaning up network capture due to FriTap startup failure")
                self._stop_network_capture()
            raise  # Re-raise so the caller knows it failed

    def _resume_spawned_target(self, toolbox, job, load_timeout: float = 5.0):
        """Resume the spawned (paused) target once friTap's agent is loaded.

        The spawn happens in ``FridaSessionService._spawn_session`` -- outside
        AFM's JobManager, which then only *attaches* to the pid. JobManager
        therefore neither auto-resumes it nor reports ``is_paused()``, so
        ``resume_spawned_process_after_hooks`` skipped the resume and Android
        killed the still-paused app ~10 s later ("start timeout"), leaving
        friTap "running" on a dead pid with 0 keys.
        """
        if self.job_manager.is_paused():
            # JobManager owns the spawn: keep the existing (A2-guarded) path.
            toolbox.resume_spawned_process_after_hooks(
                self.frida_device, self.process_id
            )
            return

        try:
            from sandroid.services import get_spotlight_service

            auto_resume = get_spotlight_service().get_auto_resume()
        except Exception:
            auto_resume = True
        if not auto_resume:
            logger.info(
                f"Process {self.process_id} remains PAUSED (auto-resume off). "
                "Resume it manually -- Android kills a paused app after ~10 s."
            )
            return

        # Give the agent a moment to install its hooks before the app runs, but
        # stay well inside Android's 10 s process-start timeout.
        deadline = time.monotonic() + load_timeout
        while time.monotonic() < deadline:
            if _job_state(job) in ("running", "error", "stopped", None):
                break
            time.sleep(0.1)

        device = getattr(self, "_spawn_device", None) or self.frida_device
        try:
            device.resume(self.process_id)
            logger.info(f"Resumed spawned process {self.process_id}")
            time.sleep(1)  # let Java.perform settle (same as AFM/JobManager)
        except Exception as e:  # e.g. already running
            logger.debug(f"Resume of {self.process_id} skipped: {e}")

    def _start_anr_watch(self) -> None:
        """Watch the target for an "isn't responding" freeze while friTap runs.

        friTap's hooks can park an app thread (seen with Wikipedia) and the
        app then shows an ANR dialog; nothing told the user that friTap was
        the likely cause until they pressed ``h``. Polls the window list every
        ``_ANR_POLL_SECONDS`` and, on a freeze, says so once (log + friTap
        events) and marks the lifecycle ``hung``; it recovers to ``running``
        when the dialog is gone. It does not stop friTap on its own: stopping
        unloads the agent, which can itself take the app down.
        """
        package = getattr(self, "app_package", None)
        if not package:
            return

        def _watch() -> None:
            frozen = False
            while not (
                getattr(self, "_stopping", False) or getattr(self, "_stopped", False)
            ):
                time.sleep(_ANR_POLL_SECONDS)
                if getattr(self, "_stopping", False) or getattr(
                    self, "_stopped", False
                ):
                    return
                state = app_not_responding(package)
                if state is None or state == frozen:
                    continue
                frozen = state
                if frozen:
                    msg = (
                        f"{package} is not responding while friTap is attached: "
                        "friTap's hooks may be blocking it. Press h to stop "
                        "friTap; if the app stays frozen, restart it (App lens "
                        f"Shift+R) or run: adb shell am force-stop {package}"
                    )
                    logger.warning(msg)
                    try:
                        _publish_fritap_event(
                            EventBus.get(), f"[warning]{msg}[/warning]"
                        )
                    except Exception:
                        pass
                    set_lifecycle("hung", f"{package} is not responding")
                else:
                    logger.info(f"{package} responds again")
                    set_lifecycle("running", package)

        threading.Thread(target=_watch, name="fritap-anr-watch", daemon=True).start()

    def target_problem(self) -> str | None:
        """Why the friTap job is not actually capturing, or None if it is.

        Cheap enough for UI refreshes: reads the JobManager's in-memory job
        state and session flag only (no adb/frida round trips).
        """
        job_id = getattr(self, "job_id", None)
        if not job_id:
            return None
        try:
            job = self.job_manager.get_job_by_id(job_id)
        except ValueError:
            return "job ended"
        except Exception:
            return None
        if _job_state(job) == "error":
            error = job.get_error() if hasattr(job, "get_error") else None
            return error or "agent error"
        try:
            if not self.job_manager.has_active_session():
                return "target process gone"
        except Exception:
            pass
        return None

    _AFM_JOB_ID = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )

    def _prune_dead_hook_owners(self, toolbox, conflicts: dict) -> dict:
        """Drop hook registrations whose owning JobManager job is gone.

        A friTap job that died with its app (or a previous run whose stop never
        ran) kept its SSL_* hooks registered, so every later start logged ~15
        bogus "already registered" conflicts. Only real JobManager job ids
        (UUIDs) are pruned; virtual ids of other tools (e.g. MalwareMonitor's
        hook registry) are left alone.
        """
        if not conflicts:
            return conflicts
        dead = set()
        for job_id in set(conflicts.values()):
            if not isinstance(job_id, str) or not self._AFM_JOB_ID.match(job_id):
                continue
            try:
                job = self.job_manager.get_job_by_id(job_id)
            except ValueError:
                dead.add(job_id)
                continue
            except Exception:
                continue
            if _job_state(job) in ("error", "stopped"):
                dead.add(job_id)
        for job_id in dead:
            try:
                toolbox.unregister_frida_hooks(job_id)
                logger.debug(f"Unregistered stale hooks of dead job {job_id}")
            except Exception as e:
                logger.debug(f"Could not unregister hooks of {job_id}: {e}")
        return {hook: jid for hook, jid in conflicts.items() if jid not in dead}

    def stop(self):
        """Stop FriTap monitoring and finalize outputs.

        Note: This stops Frida hooks but keeps the target app running.
        Uses timeout parameters for graceful shutdown even if Frida hangs.
        Idempotent: the target-death handler and the user can both call it.
        """
        with self._lock_for_stop():
            if self._stopped or self._stopping:
                return
            self._stopping = True
        set_lifecycle("stopping", getattr(self, "app_package", None) or "")
        try:
            self._stop()
        finally:
            self._stopped = True
            if lifecycle()[0] == "stopping":
                set_lifecycle("stopped", getattr(self, "_stop_note", "") or "")

    def _lock_for_stop(self):
        # Instances built with __new__ (tests) have no lock yet.
        lock = getattr(self, "_stop_lock", None)
        if lock is None:
            lock = self._stop_lock = threading.Lock()
        for name in ("_stopping", "_stopped"):
            if not hasattr(self, name):
                setattr(self, name, False)
        return lock

    def _stop(self) -> None:
        # Remove activity log handler if it was added
        if self.show_in_activity_log:
            _remove_activity_log_handler()

        # Check job state for any errors that occurred during execution
        # Since we don't wait for hooks on start, errors may surface here
        if self.job_id:
            try:
                job = self.job_manager.get_job_by_id(self.job_id)
                if job:
                    job_state = (
                        job.get_state()
                        if hasattr(job, "get_state")
                        else getattr(job, "state", None)
                    )
                    if job_state == "error":
                        error_msg = (
                            job.get_error()
                            if hasattr(job, "get_error")
                            else "Unknown error"
                        )
                        logger.warning(
                            f"FriTap encountered errors during execution: {error_msg}"
                        )
            except ValueError:
                # Job already removed from manager
                pass
            except Exception as e:
                logger.debug(f"Error checking job state: {e}")

        # Unload the agent (and detach when no other tool uses the session)
        # with a hard bound: an app thread parked in a hooked SSL_read keeps
        # unload/detach blocked for a long time, which left the panel
        # "running" and fritap_output.json unfinalized (no force-stop: the
        # app keeps running).
        try:
            if stop_frida_job_bounded(
                self.job_manager, getattr(self, "job_id", None), timeout=_STOP_TIMEOUT
            ):
                logger.info(f"FriTap detached from {self.app_package}")
            else:
                logger.info(
                    f"FriTap stopped for {self.app_package} (agent unload "
                    "continues in the background)"
                )
                self._stop_note = "agent still unloading"
                self._watch_hung_unload(
                    getattr(self.job_manager, "_sandroid_pending_teardown", None)
                )
        except Exception as e:
            logger.warning(f"Error stopping FriTap jobs: {e}")
        self._outputs_closed = True

        # Release this job's hook registrations so the next start does not
        # report conflicts with a job that no longer exists.
        if getattr(self, "job_id", None):
            try:
                self._get_toolbox().unregister_frida_hooks(self.job_id)
            except Exception as e:
                logger.debug(f"Could not unregister friTap hooks: {e}")

        # Finalize outputs only after the agent is gone, so no late message
        # races the file close.
        self._finalize_outputs()

        # A capture friTap started ends with friTap (it used to run on until
        # the TUI quit).
        self._stop_network_capture()

    def _is_spawned_target(self) -> bool:
        mode = getattr(self, "mode", None)
        return mode in (SpawnMode.SPAWN, SpawnMode.SPAWN.value)

    def _watch_hung_unload(self, worker) -> None:
        """Watch an agent unload that outlived ``_STOP_TIMEOUT`` (never blocks).

        The unload waits for every app thread to leave friTap's hooks; a
        thread parked in a hooked ``SSL_read`` on an idle connection can keep
        it waiting forever while the app's main thread blocks on the agent
        (ANR). After ``_HUNG_UNLOAD_GRACE`` more seconds the target counts as
        hung, see :meth:`_handle_hung_target`.
        """
        if worker is None or not hasattr(worker, "join"):
            return
        package = getattr(self, "app_package", None)
        pid = getattr(self, "process_id", None)
        spawned = self._is_spawned_target()

        def _watch() -> None:
            worker.join(_HUNG_UNLOAD_GRACE)
            if not worker.is_alive():
                logger.info(f"friTap agent finished unloading from {package}")
                return
            self._handle_hung_target(package, pid, spawned)

        threading.Thread(
            target=_watch, name="fritap-unload-watchdog", daemon=True
        ).start()

    def _handle_hung_target(self, package, pid, spawned: bool) -> None:
        """The agent never unloaded: recover a spawned app, warn otherwise."""
        waited = _STOP_TIMEOUT + _HUNG_UNLOAD_GRACE
        cause = (
            f"friTap's agent could not unload from {package} (PID {pid}) within "
            f"{waited:.0f}s: an app thread is stuck in a hooked SSL call, which "
            "leaves the app frozen ('isn't responding')."
        )
        if spawned and _force_stop_if_running(package, pid):
            msg = (
                f"{cause} Sandroid spawned it, so it was force-stopped. Spawn "
                "it again (Shift+C) or start it from the launcher."
            )
            forget_injected_pid(pid)
            try:
                from sandroid.services import get_spotlight_service

                spotlight = get_spotlight_service()
                if spotlight.get_pid() == pid:
                    spotlight.announce_pid(None, package)
            except Exception as e:
                logger.debug(f"Could not clear the spotlight PID: {e}")
        else:
            msg = (
                f"{cause} If it does not respond, restart it (Spotlight "
                f"Shift+R) or run: adb shell am force-stop {package}"
            )
        set_lifecycle("failed", f"agent stuck in {package}: app frozen")
        logger.warning(msg)
        try:
            _publish_fritap_event(EventBus.get(), f"[warning]{msg}[/warning]")
        except Exception:
            pass

    def _stop_network_capture(self) -> None:
        """Stop the network capture this friTap session started. Idempotent.

        Goes through TaskService when the capture is registered there (the
        header/net indicator and TASK_STOPPED stay consistent), else stops the
        instance directly. ``Network.stop`` sends the emulator's ``network
        capture stop``, which closes the pcap, and joins the capture thread.
        """
        net = getattr(self, "_network_instance", None)
        if net is None:
            return
        self._network_instance = None
        try:
            task_service = get_task_service()
            task = task_service.get_task("network")
            if task is not None and getattr(task, "instance", None) is net:
                task_service.stop("network")
            else:
                net.stop()
        except Exception as e:
            logger.warning(f"Error stopping the friTap network capture: {e}")
            return
        path = getattr(self, "network_capture_path", None)
        if path and os.path.isfile(path):
            logger.info(
                f"FriTap network capture closed: {path} ({os.path.getsize(path)} bytes)"
            )

    def _finalize_outputs(self) -> None:
        """Flush and close friTap's keylog/JSON writers. Idempotent.

        friTap >= 2.6 writes keylog and JSON through output handlers created in
        ``SSL_Logger.__init__``; the JSON document is only assembled from its
        ``.events.jsonl`` sidecar when those handlers are closed
        (``close_output_handlers``). ``_finalize_json_output`` alone leaves the
        start-time skeleton (empty arrays) behind. It is still called for the
        legacy inline-writer path; both calls are idempotent.
        """
        if not self.ssl_log:
            return
        for name in ("close_output_handlers", "_finalize_json_output"):
            method = getattr(self.ssl_log, name, None)
            if method is None:
                continue
            try:
                method()
            except Exception as e:
                logger.warning(f"Error finalizing friTap output ({name}): {e}")
        logger.info("FriTap output finalized")

    def gather(self) -> None:
        """Not supported: friTap is driven by :meth:`start` and :meth:`stop`.

        ``gather`` is abstract on the base class, so it stays, but the old
        start/stop toggle is gone: it read a spotlight getter that no longer
        exists and never took the spawn-mode path.

        Raises:
            NotImplementedError: Always; call :meth:`start` / :meth:`stop`.
        """
        raise NotImplementedError(
            "FriTap.gather() is not supported; use FriTap.start() to begin "
            "capturing and FriTap.stop() to end it."
        )

    def has_new_results(self):
        """Check if there are new results available.

        :returns: True if there are new results, False otherwise.
        :rtype: bool
        """
        if self.running:
            return False
        return getattr(self, "_new_results_available", False)

    def return_data(self):
        """Return the last profiling data.

        This method returns the last profiling data and resets the new results flag.

        :returns: The last profiling data in JSON format.
        :rtype: str
        """
        self._new_results_available = False
        return self.last_output

    def pretty_print(self):
        """Not implemented"""
