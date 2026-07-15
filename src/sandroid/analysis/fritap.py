import logging
import os
import threading

import click
from friTap import SSL_Logger

from sandroid.core.analysis_logging import setup_analysis_logging
from sandroid.core.console import SandroidConsole
from sandroid.core.enums import SpawnMode
from sandroid.core.events import Event, EventBus, EventType
from sandroid.services import (
    get_network_capture_service,
    get_spotlight_service,
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


def _spawn_resume_delay_seconds() -> int:
    """Seconds friTap should hold a freshly-spawned (paused) process before it
    resumes it, so the agent's base hooks finish arming first.

    Default 0 — friTap resumes the spawn immediately after the synchronous
    ``Script.load`` (exactly like standalone friTap). The Signal spawn crash that
    motivated this delay was actually root-caused and fixed in the friTap agent
    (the executable-range guard that refuses to ``Interceptor.attach`` a pattern
    match landing in libsignal_jni.so's statically-linked BoringSSL *data*), so
    no delay is needed for Signal. It stays as an opt-in escape hatch: set
    ``SANDROID_FRITAP_SPAWN_RESUME_DELAY`` to N>0 for any hardened app that still
    resume-crashes, which wires friTap's ``--timeout`` / ``DeviceConfig.timeout``
    pre-resume sleep (``session_manager.start_session``).
    """
    raw = os.getenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", "0")
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _count_keys(path: str) -> int | None:
    """Count non-empty, non-comment lines in a keylog file (None if unreadable)."""
    try:
        with open(path) as f:
            return sum(
                1 for line in f if (s := line.strip()) and not s.startswith("#")
            )
    except OSError:
        return None


def _file_size_str(path: str) -> str | None:
    """Return a human-readable size for *path* (e.g. ``160.4 KB``), or None."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    try:
        from friTap.flow.models import format_byte_size

        return format_byte_size(size)
    except Exception:
        return f"{size / 1024:.1f} KB"


def _pcapng_has_packets(f) -> bool:
    """Return True if a pcapng stream contains >=1 packet block.

    Ported from friTap's TUI (capture_controller.py) so the analysis layer stays
    free of any textual dependency.
    """
    import struct

    head = f.read(12)
    if len(head) < 12:
        return False
    bom = head[8:12]
    if bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    elif bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    else:
        return True  # unknown byte order -> fail open, don't hide a real capture
    packet_block_types = {0x00000006, 0x00000003, 0x00000002}  # EPB, SPB, obsolete PB
    f.seek(0)
    while True:
        block_hdr = f.read(8)
        if len(block_hdr) < 8:
            break
        block_type, block_len = struct.unpack(endian + "II", block_hdr)
        if block_len < 12:
            break  # malformed
        if block_type in packet_block_types:
            return True
        f.seek(block_len - 8, 1)
    return False


def _pcap_has_packets(path: str) -> bool:
    """Best-effort check whether a capture file holds >=1 packet.

    Supports pcapng and classic pcap. Fails open (returns True) on any parsing
    uncertainty so a real capture is never hidden; returns False only when the
    file is confidently empty (header only, no packet records).
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            if magic == b"\x0a\x0d\x0d\x0a":  # pcapng Section Header Block
                f.seek(0)
                return _pcapng_has_packets(f)
            classic_magics = {
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",  # microsecond
                b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # nanosecond
            }
            if magic in classic_magics:
                f.seek(24)  # skip 24-byte global header
                return len(f.read(16)) == 16  # one full record header present
    except OSError:
        return True
    return True


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
    # Max seconds to hold a spawned (paused) process while waiting for friTap's
    # base hooks to load. Generous because first-time Frida attach can JIT for
    # 15-30s; the app is paused so the wait is harmless, and we resume anyway on
    # timeout rather than hang.
    _SPAWN_HOOK_WAIT_SECONDS = 30

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
        # Output paths (set in _setup_session); pcap only used for wizard-driven
        # full/plaintext capture, kept here so getattr-based collectors are safe.
        self.keylog_path = None
        self.json_output_path = None
        self.pcap_path = None
        self.log_path = None
        # Capture protocol (e.g. "tls", "signal"); set in _setup_session and used
        # at stop() to resolve the per-protocol (possibly split) keylog files.
        self.protocol = "tls"
        # Populated by stop() once a full capture is finalized, so the TUI can
        # surface a "Capture Results" summary and offer the decrypt-to-tap flow.
        # result_paths maps a display label ("PCAP", "Key log (signal)", ...) to
        # the on-disk path; result_keylogs is the authoritative {protocol: path}
        # map for the decrypt step; result_stats maps the same labels to a short
        # stat string ("1.2 KB", "42 keys").
        self.result_paths: dict[str, str] = {}
        self.result_keylogs: dict[str, str] = {}
        self.result_stats: dict[str, str] = {}
        self.full_capture_done = False
        self.pcap_has_packets = False
        self.show_in_activity_log = False
        self.print_to_console = (
            False  # Print key captures to console (for CLI/headless mode)
        )
        self.message_handler = None  # Will be set up in _setup_session
        # Set once friTap reports "hooks successfully loaded". A spawn is held
        # paused until this fires so the agent's base hooks (incl. the dynamic
        # loader hook that catches later library loads such as libsignal) are in
        # place before the app runs — mirroring standalone friTap's
        # instrument-then-resume ordering and preventing the Signal spawn crash.
        self._hooks_loaded = threading.Event()

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
            # Detect friTap readiness ("hooks successfully loaded") so a spawn can
            # wait for the agent's base hooks before resuming the app. Independent
            # of forwarding so it works even when the activity log is disabled.
            if not self._hooks_loaded.is_set():
                try:
                    payload = message.get("payload") if isinstance(message, dict) else None
                    if isinstance(payload, dict) and payload.get("contentType") == "console":
                        if "hooks successfully loaded" in str(
                            payload.get("console", "")
                        ).lower():
                            self._hooks_loaded.set()
                except Exception:
                    pass

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

    def _setup_session(self, config: dict = None, session_config=None):
        """Set up FriTap session following the old proven pattern.

        Creates Frida device AND session in the SAME worker thread via
        get_frida_session_for_spotlight(), avoiding the thread-affinity
        violation that caused FriTap to hang in TUI mode.

        Args:
            config: Optional configuration dict from the interactive menu
                (legacy / no-wizard path).
            session_config: Optional ``FriTapSessionConfig`` from the TUI capture
                wizard. When provided, a modern ``FriTapConfig`` is built so the
                selected protocol and capture mode reach the agent.

        Raises:
            ValueError: If no spotlight app is selected or app not running
        """
        from sandroid.core.toolbox import Toolbox

        # Resolve verbosity + output toggles from whichever config is present.
        if session_config is not None:
            verbose = session_config.verbose
            debug_output = session_config.debug_log
            # Remember the chosen protocol so stop() can resolve the per-protocol
            # (possibly split) keylog files written by a multi-protocol run.
            self.protocol = session_config.protocol or "tls"
            # The wizard is only reachable from the TUI, so mirror the TUI
            # activity-log behaviour of the interactive path.
            self.show_in_activity_log = True
        else:
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
        if session_config is not None:
            self.keylog_path, self.pcap_path, self.json_output_path = (
                self._resolve_session_paths(session_config, fritap_dir)
            )
        else:
            self.keylog_path = (
                f"{fritap_dir}fritap_keylog.log" if output_keylog else None
            )
            self.json_output_path = (
                f"{fritap_dir}fritap_output.json" if output_json else None
            )
        self.log_path = f"{fritap_dir}fritap.log"

        # Resolve spawn-vs-attach WITHOUT pre-spawning a throwaway session.
        #
        # SINGLE-SESSION RULE (critical for hardened apps like Signal): for a
        # SPAWN we must NOT call get_frida_session_for_spotlight here — that does
        # its own device.spawn()+device.attach() (one Frida session) and then the
        # JobManager below attaches AGAIN (a second session) to the same pid.
        # Two live Frida sessions on a freshly-spawned app crash it during
        # startup (Signal terminates ~10s in, libsignal hooks never fire).
        # Instead we let the JobManager own the spawn (should_spawn=True) so there
        # is exactly ONE session, mirroring standalone friTap. ATTACH keeps the
        # existing unified path (the app is already running, so it is tolerant).
        spotlight = get_spotlight_service()
        spawn_package = (
            spotlight.get_spawn_package() if spotlight.is_spawn_mode() else None
        )

        if spawn_package:
            self.mode = "spawn"
            self.app_package = spawn_package
            self.process_id = None  # assigned after the JobManager spawns
            target = self.app_package
            job_target = spawn_package
            should_spawn = True
            logger.debug(f"FriTap spawn (single session) for {self.app_package}")
        else:
            # Unified getter resolves the running process for ATTACH mode.
            _session, mode, app_info = Toolbox.get_frida_session_for_spotlight()
            self.process_id = app_info["pid"]
            self.app_package = app_info["package_name"]
            self.mode = mode
            self.frida_device = app_info["device"]
            target = self.process_id
            job_target = self.process_id
            should_spawn = False
            logger.debug(
                f"Frida session created: {self.app_package} "
                f"(PID: {self.process_id}, mode: {self.mode})"
            )
        if session_config is not None:
            # Wizard-driven: build a modern FriTapConfig so the chosen protocol
            # and capture mode are carried to the agent via the config handshake.
            self.ssl_log = self._build_ssl_logger_from_session_config(
                target, session_config, verbose, debug_output
            )
        else:
            self.ssl_log = SSL_Logger(
                target,
                verbose=verbose,
                keylog=self.keylog_path,
                debug_output=debug_output,
                json_output=self.json_output_path,
            )

        # Mark the logger as TUI-owned so its cleanup() finalizes the capture
        # WITHOUT calling os._exit(0) (which would kill the whole Sandroid
        # process). Mirrors friTap's own TUI (capture_controller.py:590).
        try:
            self.ssl_log._tui_mode = True
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

        if self._no_job_mode():
            # NO-JOB TEST PATH: do NOT create a JobManager session. friTap will
            # spawn/attach + instrument + resume itself in start() via
            # SSL_Logger.start_fritap_session() (single native session, exactly
            # like standalone friTap). The JobManager is not involved at all.
            self.ssl_log._tui_mode = bool(self.show_in_activity_log)
            # Render extracted keys with the 🔑 symbol/colour in the friTap panel
            # (the native path bypasses the activity-log wrapper that used to do
            # this, so subscribe to friTap's own KeylogEvent instead).
            self._wire_native_key_display()
            logger.info(
                "FriTap no-job mode: skipping JobManager; friTap owns the "
                f"{self.mode} session for {self.app_package}"
            )
        else:
            # Create the single Frida session via the JobManager. For SPAWN it
            # spawns+attaches the app (paused); for ATTACH it attaches to the
            # running pid. The spawn stays PAUSED — start_job() runs with
            # auto_resume=False and we resume only after hooks load (see start()).
            self.job_manager.setup_frida_session(
                job_target,
                self.message_handler,
                should_spawn=should_spawn,
            )
            if should_spawn:
                # JobManager owns the spawn; adopt its pid for the rest of the run.
                self.process_id = self.job_manager.pid
                try:
                    spotlight.set_pid(self.process_id)
                except Exception:
                    pass
            self.frida_device = self.job_manager.device

            logger.debug(
                f"FriTap initialized in {self.mode.upper()} mode for "
                f"{self.app_package} (PID: {self.process_id})"
            )

    def _resolve_session_paths(self, session_config, fritap_dir):
        """Resolve ``(keylog, pcap, json)`` output paths for a wizard session.

        Bare filenames (the wizard's defaults like ``keys.log``) are placed
        under the device's ``fritap/`` folder; user-entered absolute or
        directory paths are kept verbatim. A keylog is produced for key-bearing
        modes (full/keys); a pcap for modes that write a capture file
        (full/plaintext). JSON output stays on, matching the legacy default.
        """
        import os

        def _resolve(path, default_name):
            if path:
                if os.path.isabs(path) or os.path.dirname(path):
                    return path
                return f"{fritap_dir}{path}"
            return f"{fritap_dir}{default_name}" if default_name else None

        mode = session_config.capture_mode
        wants_keylog = mode in ("full", "keys")
        wants_pcap = mode in ("full", "plaintext")
        keylog = _resolve(
            session_config.keylog_path,
            "fritap_keylog.log" if wants_keylog else None,
        )
        pcap = _resolve(
            session_config.pcap_path,
            "fritap_capture.pcapng" if wants_pcap else None,
        )
        json_output = f"{fritap_dir}fritap_output.json"
        return keylog, pcap, json_output

    def _build_ssl_logger_from_session_config(
        self, target, session_config, verbose, debug_output
    ):
        """Build a modern ``SSL_Logger`` from the wizard's session config.

        Mirrors the mapping in friTap's ``CaptureController.build_config`` so the
        selected protocol, capture mode, and hooking options reach the Frida
        agent (the protocol is delivered to the agent via friTap's ``config``
        handshake in ``SSL_Logger.on_fritap_message``). Falls back to the legacy
        constructor — without protocol selection — if friTap's config API is
        unavailable, so a friTap version mismatch degrades gracefully.
        """
        try:
            from friTap.config import (
                DeviceConfig,
                FriTapConfig,
                HookingConfig,
                OutputConfig,
            )
        except Exception as exc:  # pragma: no cover - depends on friTap version
            logger.warning(
                "friTap config API unavailable (%s); falling back to legacy "
                "SSL_Logger without protocol selection.",
                exc,
            )
            return SSL_Logger(
                target,
                verbose=verbose,
                keylog=self.keylog_path,
                debug_output=debug_output,
                json_output=self.json_output_path,
            )

        mode = session_config.capture_mode
        live = mode in ("wireshark", "live_pcapng")
        full_capture = mode == "full"
        is_spawn = str(getattr(self.mode, "value", self.mode)) == "spawn"

        device = DeviceConfig(spawn=is_spawn)
        # Route full/plaintext capture through the on-device tcpdump path for the
        # mobile target (carry the serial when known, else auto-detect USB).
        serial = self._active_device_serial()
        device.mobile = serial or True
        # In no-job mode friTap acquires its OWN Frida device; device_id pins it
        # to the active device (e.g. panther) instead of the first USB device.
        if serial:
            device.device_id = serial
        # SPAWN: hold the paused app for a moment so friTap's base hooks finish
        # arming before it resumes (session_manager sleeps device.timeout then
        # resumes). Without this, hardened apps like Signal are resumed mid-arming
        # and crash "inside an instrumented hook". 0 keeps friTap's immediate
        # resume. ATTACH leaves timeout unset (the app is already running).
        if is_spawn:
            delay = _spawn_resume_delay_seconds()
            if delay > 0:
                device.timeout = delay

        output = OutputConfig(
            pcap=self.pcap_path or None,
            keylog=self.keylog_path or None,
            json_output=self.json_output_path or None,
            verbose=verbose,
            live=live,
            live_mode=mode if live else "",
            full_capture=full_capture,
        )

        return SSL_Logger(
            config=FriTapConfig(
                target=str(target),
                device=device,
                output=output,
                hooking=HookingConfig(
                    library_scan=session_config.library_scan,
                    encapsulated_protocols=session_config.encapsulated_protocols,
                    quic_capture_mode=session_config.quic_capture_mode,
                ),
                protocol=session_config.protocol,
                debug_output=debug_output,
            )
        )

    def _wire_native_key_display(self) -> None:
        """Mirror friTap ``KeylogEvent``s into Sandroid's TASK_OUTPUT stream as
        ``🔑 KEY: preview`` lines (no-job / native path only).

        In the JobManager path the activity-log wrapper formatted keylog
        messages with a key symbol via :class:`FriTapMessageFormatter`. The
        native path processes messages inside friTap, so instead we subscribe to
        friTap's own ``KeylogEvent`` and publish the same line. The friTap panel
        renders any ``🔑`` line in purple and counts it in its "keys" glance.
        Covers TLS and Signal keys alike — both protocols emit ``KeylogEvent``.
        """
        if self.ssl_log is None:
            return
        try:
            from friTap.events import KeylogEvent
        except Exception as exc:  # pragma: no cover - friTap version skew
            logger.debug("friTap KeylogEvent unavailable; key display not wired: %s", exc)
            return

        bus = EventBus.get()

        def _on_keylog(event) -> None:
            try:
                key_data = getattr(event, "key_data", "") or ""
                if key_data:
                    # TLS secrets + Signal libsignal HKDF keys (keys.signal.log)
                    # arrive as a pre-formatted keylog line.
                    msg = FriTapMessageFormatter._format_keylog({"keylog": key_data})
                else:
                    # Structured key material (e.g. Signal Secret-Chat / E2E keys)
                    # arrives as a payload dict with no flat keylog line — still
                    # surface it with the key symbol so the panel shows + counts it.
                    payload = getattr(event, "payload", None)
                    if not payload:
                        return
                    proto = (getattr(event, "protocol", "") or "key").upper()
                    msg = f"🔑 {proto}: key material captured"
                if msg:
                    _publish_fritap_event(bus, msg)
            except Exception:
                pass

        try:
            self.ssl_log._event_bus.subscribe(KeylogEvent, _on_keylog)
        except Exception as exc:
            logger.debug("Could not subscribe to friTap KeylogEvent: %s", exc)

    @staticmethod
    def _no_job_mode() -> bool:
        """Whether to bypass the AndroidFridaManager JobManager.

        TEST TOGGLE: when enabled (the default), friTap runs its OWN native
        session (``SSL_Logger.start_fritap_session`` → spawn + instrument +
        resume in a single Frida session), exactly like standalone friTap, and
        the JobManager is not used at all. Set ``SANDROID_FRITAP_NO_JOB=0`` to
        revert to the JobManager path.
        """
        return os.getenv("SANDROID_FRITAP_NO_JOB", "1").lower() not in (
            "0",
            "false",
            "no",
            "off",
        )

    @staticmethod
    def _active_device_serial():
        """Best-effort active-device serial for mobile capture routing."""
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            dev = getattr(dm, "active_device", None)
            return getattr(dev, "serial", None) if dev else None
        except Exception:
            return None

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

    def start(self, interactive: bool = True, session_config=None) -> bool:
        """Start FriTap monitoring.

        Args:
            interactive: If True, show interactive configuration menu first
            session_config: Optional ``FriTapSessionConfig`` collected by the TUI
                capture wizard. When provided, the interactive menu is skipped
                and the session is built from these selections.

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
                self._setup_session(config, session_config=session_config)
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

            # NO-JOB TEST PATH: let friTap own the entire session lifecycle
            # (spawn → instrument → resume in ONE native Frida session, like
            # standalone friTap). Bypasses the JobManager entirely. Returns once
            # the session is set up; the capture runs in friTap's background
            # threads + the device's Frida reactor.
            if self._no_job_mode():
                logger.info(
                    "FriTap no-job mode: starting native friTap session "
                    f"(friTap spawns/hooks {self.app_package})"
                )
                self.ssl_log.start_fritap_session()
                self.job_id = None
                # friTap owns the spawn, so adopt the real PID it assigned (set on
                # the logger's Frida process). Otherwise self.process_id stays None
                # and the UI/log report "PID: None".
                try:
                    proc = getattr(self.ssl_log, "process", None)
                    pid = getattr(proc, "pid", None)
                    if pid:
                        self.process_id = pid
                        get_spotlight_service().set_pid(pid)
                except Exception:
                    logger.debug("Could not read spawned PID from friTap", exc_info=True)
                files = [
                    f
                    for f in (
                        self.log_path,
                        self.keylog_path,
                        self.pcap_path,
                        self.json_output_path,
                    )
                    if f
                ]
                toolbox.mark_tool_used("fritap", files=files)
                logger.info(
                    f"FriTap (no-job) started for {self.app_package} "
                    f"(mode: {self.mode}, PID: {self.process_id})"
                )
                return True

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
                # Don't let the JobManager resume the spawn on script-load: it
                # would run the app before hooks finish installing. We hold the
                # spawn paused and resume explicitly after the hooks-loaded signal.
                auto_resume=False,
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

            # For ATTACH we don't block (the app is already running and
            # first-time JIT can be slow); friTap's messages show progress.
            logger.debug(
                f"FriTap job started for {self.app_package} (PID: {self.process_id})"
            )

            # Register hooks for conflict detection by other tools
            if self.job_id:
                toolbox.register_frida_hooks(self.job_id, FRITAP_SSL_HOOKS)

            # Resume spawned process — but ONLY after the agent's base hooks are
            # installed. Resuming immediately lets the app run before the dynamic
            # loader hook is in place, so later library loads (e.g. libsignal) are
            # missed → protocol hooks never fire, and hooking a concurrently
            # starting app destabilises it (observed: Signal spawn crash). The app
            # is paused, so waiting is safe; the bounded timeout covers a cold-start
            # JIT and falls back to resuming anyway rather than hanging.
            if self.mode == SpawnMode.SPAWN or self.mode == SpawnMode.SPAWN.value:
                if not self._hooks_loaded.wait(timeout=self._SPAWN_HOOK_WAIT_SECONDS):
                    logger.warning(
                        "friTap hooks not confirmed loaded within %ss; resuming "
                        "spawned process anyway (capture may be incomplete).",
                        self._SPAWN_HOOK_WAIT_SECONDS,
                    )
                else:
                    logger.debug("friTap hooks loaded; resuming spawned process")
                toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            # Register tool usage and files for exit summary
            files = [self.log_path]
            if self.keylog_path:
                files.append(self.keylog_path)
            if self.pcap_path:
                files.append(self.pcap_path)
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

        # NO-JOB TEST PATH: friTap owns the session, so stop it natively
        # (request_stop drains the consumer; finish_fritap detaches/cleans up).
        if self._no_job_mode() and self.ssl_log is not None:
            try:
                if hasattr(self.ssl_log, "request_stop"):
                    self.ssl_log.request_stop()
                if hasattr(self.ssl_log, "finish_fritap"):
                    self.ssl_log.finish_fritap()
                logger.info(
                    f"FriTap (no-job) stopped for {self.app_package} (app still running)"
                )
            except Exception as e:
                logger.warning(f"Error stopping native FriTap session: {e}")

            # Finalize a full capture: pull the on-device pcap to the host and
            # write the final pcap (with embedded TLS keys) + close the keylog
            # handlers. finish_fritap() alone only unloads the Frida script — it
            # does NOT pull/finalize the capture. Standalone friTap reaches these
            # via its SIGINT handler; its TUI calls them explicitly
            # (capture_controller.py:715-717). _tui_mode (set in _setup_session)
            # stops cleanup() from calling os._exit(0). Each step is guarded so a
            # finalize hiccup never strands the TaskService stop.
            self._finalize_full_capture()
            self._collect_capture_results()
            return

        # TODO(jobmanager-finalize): the JobManager (frida-job) stop path below
        # does NOT finalize a full capture — friTap does not own the session
        # there, so pcap_cleanup()/cleanup() would need a different hook. Full
        # capture is currently only finalized in the no-job path above.

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

    def _finalize_full_capture(self) -> None:
        """Pull the on-device pcap to the host and finalize the capture outputs.

        A full capture writes its pcap to ``/data/local/tmp/_<name>`` via
        on-device ``tcpdump``; ``pcap_cleanup()`` pulls it to the host and
        ``cleanup()`` embeds the TLS keys (DSB) into the final pcap and closes
        the keylog handlers (flushing every protocol's keys to disk).
        ``finish_fritap()`` alone only unloads the Frida script. This mirrors the
        order friTap's own TUI uses (capture_controller.py:715-717). ``_tui_mode``
        (set in ``_setup_session``) keeps ``cleanup()`` from calling
        ``os._exit(0)``. Each step is guarded so one failure can't strand stop().
        """
        sl = self.ssl_log
        if sl is None:
            return
        is_full = bool(getattr(sl, "full_capture", False))
        if is_full:
            try:
                sl.pcap_cleanup(sl.full_capture, sl.mobile, sl.pcap_name)
            except Exception as e:
                logger.warning(f"Error pulling full-capture pcap from device: {e}")
        # Always run cleanup() — it closes the keylog handlers (flush to disk)
        # for keys-only captures too, and finalizes the pcap for full captures.
        try:
            sl.cleanup(sl.live, sl.socket_trace, sl.full_capture, sl.debug_output)
        except Exception as e:
            logger.warning(f"Error finalizing capture: {e}")
        self.full_capture_done = is_full

    def _collect_capture_results(self) -> None:
        """Resolve the real on-disk outputs and expose them for the TUI.

        Populates ``result_paths`` / ``result_stats`` / ``result_keylogs`` and
        ``pcap_has_packets`` so the panel can show a "Capture Results" summary and
        offer the decrypt-to-tap flow. Also re-registers the ACTUAL files with the
        tool-usage tracker so the "Sandroid Session Complete" summary lists the
        real (possibly split) keylogs + finalized pcap rather than the planned
        base paths (which a multi-protocol run never writes verbatim).
        """
        # Per-protocol keylog files actually written. A multi-protocol run (e.g.
        # --protocol signal, which also emits TLS keys) splits the base -k path
        # into <stem>.tls.log + <stem>.signal.log. Mirrors friTap's controller.
        keylog_files: dict[str, str] = {}
        if self.keylog_path:
            try:
                from friTap.output.factory import active_keylog_paths

                registry = getattr(self.ssl_log, "_protocol_registry", None)
                candidates = active_keylog_paths(
                    self.keylog_path, self.protocol, registry
                )
            except Exception:
                candidates = {self.protocol: self.keylog_path}
            keylog_files = {
                proto: path
                for proto, path in candidates.items()
                if path and os.path.isfile(path)
            }
            if not keylog_files and os.path.isfile(self.keylog_path):
                keylog_files = {self.protocol: self.keylog_path}
        self.result_keylogs = keylog_files

        result_paths: dict[str, str] = {}
        result_stats: dict[str, str] = {}
        multi = len(keylog_files) > 1
        for proto, path in keylog_files.items():
            label = f"Key log ({proto})" if multi else "Key log"
            result_paths[label] = path
            count = _count_keys(path)
            if count is not None:
                result_stats[label] = f"{count} key{'s' if count != 1 else ''}"

        # Resolve the finalized pcap; fall back to the "_"-prefixed temp if the
        # finalize step left it there (mirrors friTap's _gather_result_stats).
        pcap_path = self.pcap_path
        if pcap_path:
            if not os.path.isfile(pcap_path):
                d, b = os.path.split(pcap_path)
                alt = os.path.join(d, f"_{b}")
                if os.path.isfile(alt):
                    pcap_path = alt
            if os.path.isfile(pcap_path):
                result_paths["PCAP"] = pcap_path
                size = _file_size_str(pcap_path)
                if size:
                    result_stats["PCAP"] = size
                self.pcap_has_packets = _pcap_has_packets(pcap_path)

        self.result_paths = result_paths
        self.result_stats = result_stats

        # Register the files the start-time registration could NOT know: the
        # split per-protocol keylogs (a multi-protocol run never writes the base
        # -k path verbatim) and the finalized pcap when it differs from the
        # planned path (the "_"-temp fallback). mark_tool_used EXTENDS the file
        # list, so re-adding the already-registered base paths (log/json/base
        # keylog/pcap) would duplicate them in the session summary — only the new
        # files are appended here. The (possibly non-existent) base keylog from
        # the start-time registration is silently skipped by the exit renderer.
        new_files: list[str] = [
            path for path in keylog_files.values() if path and path != self.keylog_path
        ]
        resolved_pcap = result_paths.get("PCAP")
        if resolved_pcap and resolved_pcap != self.pcap_path:
            new_files.append(resolved_pcap)
        if new_files:
            try:
                self._get_toolbox().mark_tool_used("fritap", files=new_files)
            except Exception as e:
                logger.debug(f"Could not re-register fritap output files: {e}")

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
