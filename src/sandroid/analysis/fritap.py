import logging
import os

import click
from friTap import SSL_Logger

from sandroid.core.analysis_logging import setup_analysis_logging
from sandroid.core.console import SandroidConsole
from sandroid.core.enums import SpawnMode
from sandroid.core.events import Event, EventBus, EventType
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
        self.message_handler = None  # Will be set up in _setup_session

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
            # Forward to activity log (TUI) and/or console (CLI/headless)
            should_forward = self.show_in_activity_log or self.print_to_console

            if should_forward:
                try:
                    msg = formatter.format_message(message, data)
                    if msg is not None:
                        if self.show_in_activity_log:
                            _publish_fritap_event(event_bus, msg)
                        if self.print_to_console:
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

        # Use fritap folder in device-specific results path
        fritap_dir = f"{_get_device_results_path()}fritap/"
        self.keylog_path = f"{fritap_dir}fritap_keylog.log" if output_keylog else None
        self.json_output_path = (
            f"{fritap_dir}fritap_output.json" if output_json else None
        )
        self.log_path = f"{fritap_dir}fritap.log"

        # Get session via unified getter (creates fresh device on worker thread)
        # This is the old proven pattern — no pre-initialized devices, no fork issues.
        _session, mode, app_info = Toolbox.get_frida_session_for_spotlight()
        self.process_id = app_info["pid"]
        self.app_package = app_info["package_name"]
        self.mode = mode
        self.frida_device = app_info["device"]

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
        self.job_manager.setup_frida_session(
            self.process_id,
            self.message_handler,
            should_spawn=False,
        )
        self.frida_device = self.job_manager.device

        logger.debug(
            f"FriTap initialized in {self.mode.upper()} mode for "
            f"{self.app_package} (PID: {self.process_id})"
        )

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

        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("FriTap configuration cancelled")
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
                network_instance.gather()  # This starts tcpdump capture
                network_started = True
                logger.info("Network capture started for FriTap")

                # Register network as background task (started by fritap)
                get_task_service().register(
                    name="network",
                    display_name="Network Capture",
                    instance=network_instance,
                    stop_callback=network_instance.stop,
                    started_by="fritap",
                )

            # Check for hook conflicts with other running Frida jobs
            conflicts = toolbox.check_frida_hook_conflicts(FRITAP_SSL_HOOKS)
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
                raise RuntimeError(msg)

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

            # Resume spawned process now that hooks are installed
            if self.mode == SpawnMode.SPAWN or self.mode == SpawnMode.SPAWN.value:
                toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            # Register tool usage and files for exit summary
            files = [self.log_path]
            if self.keylog_path:
                files.append(self.keylog_path)
            if self.json_output_path:
                files.append(self.json_output_path)
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

            return True

        except Exception as e:
            logger.error(f"Failed to start FriTap: {e}")
            # Clean up network capture if we started it
            if network_started and network_instance:
                logger.info("Cleaning up network capture due to FriTap startup failure")
                try:
                    network_instance.stop()
                    task_service = get_task_service()
                    if task_service.is_running("network"):
                        task_service.unregister("network")
                except Exception as cleanup_error:
                    logger.warning(f"Error during network cleanup: {cleanup_error}")
            raise  # Re-raise so the caller knows it failed

    def stop(self):
        """Stop FriTap monitoring and finalize outputs.

        Note: This stops Frida hooks but keeps the target app running.
        Uses timeout parameters for graceful shutdown even if Frida hangs.
        """
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

        # Finalize JSON output before stopping
        if self.ssl_log:
            if hasattr(self.ssl_log, "_finalize_json_output"):
                try:
                    self.ssl_log._finalize_json_output()
                    logger.info("FriTap JSON output finalized")
                except Exception as e:
                    logger.warning(f"Error finalizing JSON output: {e}")

        # Stop Frida jobs and detach WITH TIMEOUT to prevent hanging
        # Use stop_jobs + detach instead of stop_app_with_closing_frida
        # which would call `adb shell am force-stop` and kill the app
        try:
            results = self.job_manager.stop_jobs(timeout_per_job=3.0)
            timed_out = [jid for jid, ok in results.items() if not ok]
            if timed_out:
                logger.warning(f"Jobs timed out: {timed_out}")

            self.job_manager.detach_from_app(timeout=2.0)
            logger.info(f"FriTap detached from {self.app_package} (app still running)")
        except Exception as e:
            logger.warning(f"Error stopping FriTap jobs: {e}")

    def gather(self):
        """Gather data from the monitored application.

        .. warning::
            Context dependent behavior: Calling this method acts as a toggle, it starts or stops the monitoring process based on the current state.
        """
        toolbox = self._get_toolbox()
        if self.running:
            # Stop Frida jobs and detach WITH TIMEOUT to prevent hanging
            try:
                self.job_manager.stop_jobs(timeout_per_job=3.0)
                self.job_manager.detach_from_app(timeout=2.0)
            except Exception as e:
                logger.warning(f"Error stopping FriTap jobs: {e}")
            self.last_output = self.profiler.get_profiling_log_as_JSON()
            self.running = False
            toolbox.malware_monitor_running = False
            self._new_results_available = True
        elif not self.running:
            self.app_package, _ = toolbox.get_spotlight_application()
            # self.logger.warning("Next: Setup Frida Session")
            self.job_manager.setup_frida_session(
                self.app_package, self.profiler.on_appProfiling_message
            )
            # Check for hook conflicts
            conflicts = toolbox.check_frida_hook_conflicts(FRITAP_SSL_HOOKS)
            if conflicts:
                logger.warning(
                    f"FriTap may conflict with existing hooks: {list(conflicts.keys())}"
                )

            # Start job with metadata for coordination
            job = self.job_manager.start_job(
                self.frida_script_path,
                custom_hooking_handler_name=self.profiler.on_appProfiling_message,
                job_type="fritap",
                display_name="FriTap SSL Logger",
                hooks_registry=FRITAP_SSL_HOOKS,
                priority=10,
            )

            # Register hooks if job started
            if job:
                self.job_id = job.get_id()
                toolbox.register_frida_hooks(self.job_id, FRITAP_SSL_HOOKS)

            # Resume spawned process now that hooks are installed (if in spawn mode)
            if (
                hasattr(self, "mode")
                and (self.mode == SpawnMode.SPAWN or self.mode == SpawnMode.SPAWN.value)
                and hasattr(self, "frida_device")
                and hasattr(self, "process_id")
            ):
                toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            self.running = True
            toolbox.malware_monitor_running = True

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
