"""Emulator Service for Sandroid.

This service manages Android emulator operations including screenshots,
screen recording, snapshots, and emulator lifecycle.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_emulator_service
    from sandroid.services.emulator_service import EmulatorService

    # Using service locator
    emulator_service = get_emulator_service()

    # Or with dependency injection
    emulator_service = EmulatorService(
        adb=adb_instance,
        config_service=config_service
    )

    # Take a screenshot
    path = emulator_service.take_screenshot()

    # Screen recording
    emulator_service.start_recording("my_session")
    # ... do stuff ...
    emulator_service.stop_recording()
"""

import logging
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from sandroid.core.adb_utils import quote_host_arg, validate_snapshot_name
from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class ScreenRecordingState:
    """State for an active screen recording.

    Attributes:
        is_running: Whether recording is currently active
        filename: Path to the recording file on device
        local_path: Path to the pulled file on host
        started_at: When recording started
        max_duration: Maximum recording duration in seconds (Android limit is ~180s)
    """

    is_running: bool = False
    filename: str | None = None
    local_path: str | None = None
    started_at: datetime | None = None
    max_duration: int = 178  # Android screenrecord max is 180s, we use 178 for safety


@dataclass
class SnapshotInfo:
    """Information about an emulator snapshot.

    Attributes:
        name: Snapshot name/tag
        date: When the snapshot was created
    """

    name: str
    date: str


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_telnet_command(command: Any, serial: str | None = None) -> tuple[str, str]:
        """Send a telnet command to the emulator."""
        ...

    @staticmethod
    def send_adb_command(command: str, serial: str | None = None) -> tuple[str, str]:
        """Send an ADB command."""
        ...

    @staticmethod
    def get_avd_snapshots() -> list[dict]:
        """Get list of available snapshots."""
        ...


class ConfigServiceProtocol(Protocol):
    """Protocol for ConfigurationService dependency injection."""

    def get_raw_results_path(self) -> str:
        """Get the raw results path."""
        ...

    def get_emulator_path(self) -> str:
        """Get the emulator executable path."""
        ...

    def get_device_name(self) -> str:
        """Get the device name."""
        ...


def _snapshot_command(verb: str, name: str | bytes) -> str:
    """Build ``avd snapshot <verb> <name>`` for a validated snapshot name.

    Snapshot names reach the emulator console through ``adb emu`` (host
    shell) and become directory names in the AVD, so only
    :data:`~sandroid.core.adb_utils.SNAPSHOT_NAME_RE` names are accepted.

    Raises:
        ValueError: *name* is not a safe snapshot name.
    """
    return f"avd snapshot {verb} {validate_snapshot_name(name)}"


def _name_text(name: str | bytes) -> str:
    if isinstance(name, bytes):
        return name.decode("utf-8", "replace")
    return str(name)


def _snapshot_line(
    verb: str,
    name: str | bytes,
    ok: bool,
    serial: str | None,
    error: str | None = None,
) -> None:
    """A ``snapshot/<save|load|delete>`` session-timeline line (never raises).

    A successful load is a world change and is written by
    :func:`_world_change` instead.
    """
    text = _name_text(name)
    data: dict = {"name": text, "ok": ok}
    if error:
        data["error"] = error.strip()[:500]
    done = {"save": "saved", "load": "loaded", "delete": "deleted"}.get(verb, verb)
    summary = f"snapshot '{text}' {done}" if ok else f"snapshot '{text}' {verb} failed"
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().emit(
            "snapshot",
            verb,
            summary=summary,
            data=data,
            dev=serial if isinstance(serial, str) else None,
            level="info" if ok else "warn",
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "timeline: snapshot line failed", exc_info=True
        )


def _world_change(cause: str, **kwargs) -> None:
    """:meth:`TimelineService.on_world_change` (never raises)."""
    if not isinstance(kwargs.get("dev"), str):
        kwargs["dev"] = None
    if cause in ("snapshot-load", "cold-boot"):
        # The guest has its old SIM cached again: allow a new SIM re-read.
        try:
            from sandroid.services.identity import get_identity_service

            get_identity_service().sim_launch_changed(kwargs["dev"])
        except Exception:
            logging.getLogger(__name__).debug(
                "identity: SIM launch change failed", exc_info=True
            )
    data = kwargs.get("data")
    if isinstance(data, dict) and isinstance(data.get("name"), bytes):
        data["name"] = _name_text(data["name"])
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().on_world_change(cause, **kwargs)
    except Exception:
        logging.getLogger(__name__).debug(
            "timeline: world change failed", exc_info=True
        )
    try:
        # The identity service's memory of the device may be stale now (a
        # snapshot load or a cold boot): it reads the device record again.
        from sandroid.services.identity import get_identity_service

        get_identity_service().forget(kwargs.get("dev"), restored=True)
    except Exception:
        logging.getLogger(__name__).debug(
            "identity: forget after a world change failed", exc_info=True
        )


# ---------------------------------------------------------------------------
# Snapshot loads: state, after-load hooks, device handle reset
# ---------------------------------------------------------------------------

#: Hook run at the end of every successful snapshot load (worker thread).
AfterLoadHook = Callable[[str | None], None]

_LOAD_LOCK = threading.Lock()
_LOAD_GENERATION = 0
#: serial (or "" for "the current target") -> loads in flight.
_LOADS_ACTIVE: dict[str, int] = {}
_AFTER_LOAD_HOOKS: list[AfterLoadHook] = []


def snapshot_load_generation() -> int:
    """Counter bumped when a snapshot load starts (any serial)."""
    with _LOAD_LOCK:
        return _LOAD_GENERATION


def snapshot_load_active(serial: str | None = None) -> bool:
    """Whether a snapshot load is in flight (on *serial*, or on any device)."""
    with _LOAD_LOCK:
        if serial is None:
            return any(_LOADS_ACTIVE.values())
        return bool(_LOADS_ACTIVE.get(serial) or _LOADS_ACTIVE.get(""))


def _load_started(serial: str | None) -> None:
    global _LOAD_GENERATION
    with _LOAD_LOCK:
        _LOAD_GENERATION += 1
        key = serial or ""
        _LOADS_ACTIVE[key] = _LOADS_ACTIVE.get(key, 0) + 1


def _load_finished(serial: str | None) -> None:
    with _LOAD_LOCK:
        key = serial or ""
        left = _LOADS_ACTIVE.get(key, 0) - 1
        if left > 0:
            _LOADS_ACTIVE[key] = left
        else:
            _LOADS_ACTIVE.pop(key, None)


def register_after_load_hook(hook: AfterLoadHook) -> None:
    """Run ``hook(serial)`` at the end of every successful snapshot load.

    For long-lived device streams a load kills (the tracking logcat follower,
    the file monitor): they restart themselves here. Hooks run on the
    loader's worker thread after the proxy restore, in registration order;
    an exception is logged and swallowed. Registering twice is a no-op.
    """
    with _LOAD_LOCK:
        if hook not in _AFTER_LOAD_HOOKS:
            _AFTER_LOAD_HOOKS.append(hook)


def unregister_after_load_hook(hook: AfterLoadHook) -> None:
    """Remove an after-load hook (no-op if it is not registered)."""
    with _LOAD_LOCK:
        if hook in _AFTER_LOAD_HOOKS:
            _AFTER_LOAD_HOOKS.remove(hook)


def _run_after_load_hooks(serial: str | None) -> None:
    with _LOAD_LOCK:
        hooks = list(_AFTER_LOAD_HOOKS)
    for hook in hooks:
        try:
            hook(serial)
        except Exception:
            logging.getLogger(__name__).warning(
                "after-load hook %r failed", hook, exc_info=True
            )


def reset_device_handles_after_snapshot_load() -> None:
    """Forget device state that an emulator snapshot load has invalidated.

    Loading a snapshot kills every app process and the emulator's frida
    device object. Afterwards the cached ``JobManager.device`` raised
    "device is gone" on every spawn until the TUI was restarted, and
    Spotlight kept showing the dead PID. Drops the job manager's session
    and device handle (it re-creates the handle lazily on the next spawn),
    the frida device cache and the Spotlight PID, then publishes
    ``STATE_CHANGED`` so the panels refresh. Runs on every load (TUI, Play,
    AI, headless) from :meth:`EmulatorService.load_snapshot`. Never raises;
    call it from a worker thread (the session reset may wait on frida for a
    few seconds).
    """
    from sandroid import services

    log = logging.getLogger(__name__)
    try:
        frida_svc = services.get_frida_session_service()
        jm = getattr(frida_svc, "_job_manager", None)
        if jm is not None:
            try:
                jm.reset_session(timeout_per_job=1.0, detach_timeout=1.0)
            except Exception:
                log.debug("JobManager reset after snapshot load failed", exc_info=True)
            jm.device = None
        frida_svc.invalidate_frida_device_cache()
    except Exception:
        log.debug("Could not reset frida state after snapshot load", exc_info=True)
    try:
        services.get_spotlight_service().set_pid(None)
    except Exception:
        log.debug("Could not clear the Spotlight PID", exc_info=True)
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"change_type": "snapshot_loaded"},
                source="emulator_service",
            )
        )
    except Exception:
        log.debug("Could not publish the snapshot-load refresh", exc_info=True)


def is_active_serial(serial: str | None) -> bool:
    """Whether *serial* is the device the TUI works on (None: unknown = yes).

    The host Frida handles, the Spotlight PID and the FridaSessionService's
    manager all belong to that device; a load on another serial (AI,
    headless, a second emulator) must not touch them.
    """
    if not serial:
        return True
    try:
        from sandroid.core.adb import Adb

        active = Adb.selected_serial()
    except Exception:
        return True
    return active is None or active == serial


def _publish_frida_after_load(serial: str | None, ok: bool, reason: str) -> None:
    """Tell the TUI (glance Frida row, failure toast) how the start went."""
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": "frida_server_after_load",
                    "serial": serial,
                    "ok": ok,
                    "reason": reason,
                },
                source="emulator_service",
            )
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "Could not publish the frida-server start", exc_info=True
        )


def _auto_start_frida_after_load(serial: str | None) -> None:
    """Honour ``frida.server_auto_start`` after a load (daemon thread).

    The load reverts the device's processes to the snapshot, so a
    frida-server started this session may be gone. Runs on its own thread,
    pinned to the loaded *serial*, so the load itself does not wait for
    frida-server; the outcome is published as ``STATE_CHANGED``
    (``frida_server_after_load``) for the TUI's toast and glance refresh.
    Never raises.
    """

    def _run() -> None:
        log = logging.getLogger(__name__)
        try:
            from sandroid.core.adb import Adb
            from sandroid.core.frida_manager import (
                auto_start_frida_server,
                frida_server_auto_start_enabled,
            )

            if not frida_server_auto_start_enabled():
                return
            with Adb.targeting(serial):
                if not Adb.get_target_device():
                    return
                ok, reason = auto_start_frida_server()
        except Exception as exc:
            ok, reason = False, str(exc)
        if ok:
            log.info(f"Frida after the snapshot load: {reason}")
        else:
            log.warning(
                f"frida-server auto-start after the snapshot load failed: {reason}"
            )
        _publish_frida_after_load(serial, ok, reason)

    threading.Thread(target=_run, name="sandroid-frida-after-load", daemon=True).start()


class EmulatorService:
    """Service for managing Android emulator operations.

    This service handles:
    - Screenshot capture
    - Screen recording (start/stop/toggle)
    - Snapshot management (create/load/list)
    - Emulator restart

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = EmulatorService()

        # Screenshot
        path = service.take_screenshot("my_screenshot.png")

        # Screen recording
        service.start_recording()
        # ... wait ...
        service.stop_recording()

        # Snapshots
        service.create_snapshot("clean_state")
        service.load_snapshot("clean_state")
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        config_service: ConfigServiceProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize the EmulatorService.

        Args:
            adb: Optional ADB interface. If not provided, uses global Adb class.
            config_service: Optional configuration service for paths.
            event_bus: Optional EventBus for publishing events.
        """
        self._lock = threading.Lock()
        self._adb = adb
        self._config_service = config_service
        self._event_bus = event_bus
        self._logger = logger

        # Screen recording state with thread safety
        self._recording = ScreenRecordingState()
        self._recording_lock = threading.Lock()
        self._recording_stop_event = threading.Event()
        self._recording_process: subprocess.Popen | None = None
        self._recording_thread: threading.Thread | None = None

        # Tool usage tracking
        self._tools_used: dict = {}

    # =========================================================================
    # Screenshot Methods
    # =========================================================================

    def take_screenshot(self, filename: str | None = None) -> str | None:
        """Take a screenshot of the Android device.

        Captures via the emulator console (``screenrecord screenshot``); when
        that leaves no file -- the console answers ``OK`` even when it could
        not write, it splits paths on spaces, and it doesn't exist on a
        physical device -- falls back to ``screencap`` on the device + pull.

        Args:
            filename: Optional custom filename. If None, generates timestamped name.

        Returns:
            Absolute path to the saved screenshot file, or None if failed.
        """
        # Absolute: the emulator console resolves a relative path against
        # the emulator process's working directory, not Sandroid's.
        screenshots_dir = os.path.abspath(self._get_screenshots_dir())
        os.makedirs(screenshots_dir, exist_ok=True)

        # Generate filename if not provided
        if filename is None:
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"screenshot_{timestamp}.png"

        # Ensure .png extension
        if not filename.endswith(".png"):
            filename += ".png"

        full_path = os.path.join(screenshots_dir, os.path.basename(filename))

        self._logger.info(f"Taking screenshot: {full_path}")
        adb = self._get_adb()
        # A file of the same name may already exist: only a newer one counts.
        target = Path(full_path)
        before = target.stat().st_mtime if target.exists() else None

        try:
            if " " not in full_path:
                _stdout, stderr = adb.send_telnet_command(
                    f"screenrecord screenshot {full_path}"
                )
                if stderr:
                    self._logger.debug(f"Console screenshot failed: {stderr}")
            if not self._wait_for_file(full_path, before, timeout=1.0):
                self._logger.debug("No console screenshot; trying screencap")
                self._screencap_and_pull(adb, full_path)
            if not self._wait_for_file(full_path, before, timeout=0):
                self._logger.error(f"Failed to capture screenshot to {full_path}")
                return None

            self._logger.info(f"Screenshot saved to {full_path}")
            self._mark_tool_used("screenshots", [full_path])
            self._publish_screenshot_taken(full_path)

            return full_path

        except Exception as e:
            self._logger.error(f"Screenshot failed: {e}")
            return None

    @staticmethod
    def _wait_for_file(
        path: str, older_mtime: float | None, timeout: float = 1.0
    ) -> bool:
        """Return True once a non-empty *path* newer than *older_mtime* exists."""
        deadline = time.monotonic() + timeout
        while True:
            target = Path(path)
            if target.is_file():
                stat = target.stat()
                if stat.st_size > 0 and (
                    older_mtime is None or stat.st_mtime > older_mtime
                ):
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def _screencap_and_pull(self, adb: Any, local_path: str) -> None:
        """Capture with ``screencap`` on the device and pull it to *local_path*."""
        remote = "/data/local/tmp/sandroid_screenshot.png"
        _out, err = adb.send_adb_command(f"shell screencap -p {remote}")
        if err:
            self._logger.debug(f"screencap: {err}")
        _out, err = adb.send_adb_command(f"pull {remote} {quote_host_arg(local_path)}")
        if err:
            self._logger.debug(f"pull screenshot: {err}")
        adb.send_adb_command(f"shell rm -f {remote}")

    # =========================================================================
    # Screen Recording Methods
    # =========================================================================

    def start_recording(self, filename: str | None = None) -> bool:
        """Start screen recording using ADB subprocess.

        This method starts a background thread that manages the screen recording
        process. The recording is saved to the device and pulled when stopped.

        Args:
            filename: Optional custom filename for local storage. If None,
                     generates timestamped name.

        Returns:
            True if recording started successfully, False otherwise.
        """
        with self._recording_lock:
            if self._recording.is_running:
                self._logger.warning("Screen recording is already running")
                return False

            # Clear any previous stop signal
            self._recording_stop_event.clear()

            # Generate local filename
            if filename is None:
                timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
                filename = f"screenrecord_{timestamp}.webm"
            elif not filename.endswith(".webm"):
                filename += ".webm"

            # Get local path for the recording
            local_path = self._get_recording_local_path(filename)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            # Device path for recording
            device_path = "sdcard/screenrecord.webm"

            # Update state before starting thread
            self._recording = ScreenRecordingState(
                is_running=True,
                filename=device_path,
                local_path=local_path,
                started_at=datetime.now(),
            )

            # Start recording thread
            self._recording_thread = threading.Thread(
                target=self._screenrecorder_thread,
                args=(device_path,),
                daemon=True,
                name="ScreenRecorderThread",
            )
            self._recording_thread.start()

            self._logger.info(f"Started screen recording (will save to {local_path})")
            self._publish_recording_started(local_path)
            return True

    def stop_recording(self, timeout: float = 5.0) -> str | None:
        """Stop the current screen recording and pull file from device.

        Args:
            timeout: Time to wait for graceful shutdown.

        Returns:
            Path to the local recording file if successful, None otherwise.
        """
        with self._recording_lock:
            if not self._recording.is_running:
                self._logger.warning("No screen recording is currently running")
                return None

            local_path = self._recording.local_path
            device_path = self._recording.filename

        # Signal the recording thread to stop
        self._recording_stop_event.set()

        # Wait for thread to finish
        if self._recording_thread and self._recording_thread.is_alive():
            self._recording_thread.join(timeout=timeout + 2)
            if self._recording_thread.is_alive():
                self._logger.warning("Recording thread did not stop in time")

        # Give device time to finalize the file
        time.sleep(0.5)

        # Pull the recording from device
        try:
            adb = self._get_adb()
            _stdout, stderr = adb.send_adb_command(
                f"pull {quote_host_arg(device_path)} {quote_host_arg(str(local_path))}"
            )

            if stderr and "error" in stderr.lower():
                self._logger.error(f"Failed to pull recording: {stderr}")
                return None

            # Clean up device file
            adb.send_adb_command(f"shell rm -f {device_path}")

            self._logger.info(f"Screen recording saved to {local_path}")

            with self._recording_lock:
                self._recording = ScreenRecordingState()

            self._mark_tool_used("screen_recording", [local_path])
            self._publish_recording_stopped(local_path)
            return local_path

        except Exception as e:
            self._logger.error(f"Failed to pull recording: {e}")
            return None

    def toggle_recording(self, filename: str | None = None) -> tuple[bool, str]:
        """Toggle screen recording on/off.

        Args:
            filename: Optional filename for new recording.

        Returns:
            Tuple of (is_now_recording, message)
        """
        if self.is_recording():
            result = self.stop_recording()
            if result:
                return False, f"Recording stopped: {result}"
            return True, "Failed to stop recording"
        result = self.start_recording(filename)
        if result:
            with self._recording_lock:
                local_path = self._recording.local_path
            return True, f"Recording started (will save to {local_path})"
        return False, "Failed to start recording"

    def is_recording(self) -> bool:
        """Check if screen recording is active.

        Returns:
            True if recording is running.
        """
        with self._recording_lock:
            return self._recording.is_running

    def get_recording_info(self) -> ScreenRecordingState | None:
        """Get current recording state.

        Returns:
            ScreenRecordingState if recording, None otherwise.
        """
        with self._recording_lock:
            if self._recording.is_running:
                return self._recording
            return None

    def get_recording_file(self) -> str | None:
        """Get the local path of the current or last recording.

        Returns:
            Path to the recording file if available, None otherwise.
        """
        with self._recording_lock:
            return self._recording.local_path

    def _screenrecorder_thread(self, device_path: str) -> None:
        """Thread function to handle screen recording.

        Manages the ADB screenrecord subprocess with proper cleanup.

        Args:
            device_path: Path on device where recording is stored.
        """
        try:
            self._recording_process = self._start_recording_subprocess(device_path)
            self._logger.debug(f"Started screen recording to device: {device_path}")
            self._wait_for_recording_end()

            # Stop the recording if it's still running
            if self._recording_process and self._recording_process.poll() is None:
                self._graceful_stop_recording()

        except Exception as e:
            self._logger.error(f"Error in screen recording thread: {e}")
        finally:
            with self._recording_lock:
                self._recording.is_running = False
            self._recording_process = None

    def _start_recording_subprocess(self, device_path: str) -> subprocess.Popen:
        """Start the ADB screenrecord subprocess.

        Args:
            device_path: Path on device where recording is stored.

        Returns:
            The started subprocess.

        Raises:
            RuntimeError: If the subprocess cannot be started.
        """
        from sandroid.core.adb import Adb

        try:
            # Honor ADB_PATH (adb may not be on PATH) and the active device
            # (-s serial) instead of a bare "adb".
            return subprocess.Popen(
                [*Adb.base_argv(), "shell", "screenrecord", device_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as e:
            error_msg = f"ADB not found. Ensure Android SDK is installed and adb is in PATH: {e}"
            self._logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except (OSError, subprocess.SubprocessError) as e:
            error_msg = f"Failed to start screen recording subprocess: {e}"
            self._logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def _wait_for_recording_end(self) -> None:
        """Wait for the recording to end via stop signal, max duration, or process exit."""
        start_time = time.time()
        max_duration = self._recording.max_duration

        while not self._recording_stop_event.is_set():
            if self._recording_process.poll() is not None:
                self._logger.debug("Recording process ended on its own")
                break

            elapsed = time.time() - start_time
            if elapsed > max_duration:
                self._logger.warning(
                    f"Maximum screen recording duration ({max_duration}s) reached"
                )
                break

            time.sleep(0.5)

    def _graceful_stop_recording(self) -> None:
        """Gracefully stop the screen recording subprocess."""
        import signal

        if self._recording_process is None:
            return

        try:
            # Send SIGINT (Ctrl+C equivalent) to stop recording gracefully
            self._recording_process.send_signal(signal.SIGINT)
            self._recording_process.wait(timeout=5)
            self._logger.debug("Screen recording stopped gracefully via SIGINT")
        except subprocess.TimeoutExpired:
            # Try SIGTERM
            try:
                self._logger.warning("SIGINT timeout, trying SIGTERM")
                self._recording_process.terminate()
                self._recording_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Last resort - SIGKILL
                self._logger.warning("SIGTERM timeout, using SIGKILL")
                self._recording_process.kill()
                self._recording_process.wait()
        except Exception as e:
            self._logger.error(f"Error stopping recording process: {e}")
            # Try to kill anyway
            try:
                self._recording_process.kill()
            except Exception:
                pass

    def _get_recording_local_path(self, filename: str) -> str:
        """Get local path for recording file.

        Args:
            filename: Recording filename.

        Returns:
            Full local path for the recording.
        """
        # Try to get from config service first
        if self._config_service:
            raw_path = self._config_service.get_raw_results_path()
            return os.path.join(raw_path, filename)

        # Fall back to environment variable
        raw_path = os.getenv("RAW_RESULTS_PATH", "")
        if raw_path:
            return os.path.join(raw_path, filename)

        # Last resort - current directory
        return os.path.join("recordings", filename)

    # =========================================================================
    # Snapshot Methods
    # =========================================================================

    def create_snapshot(self, name: str, serial: str | None = None) -> bool:
        """Create a snapshot of the emulator state.

        Args:
            name: Name for the snapshot.
            serial: Device serial to target for this call only, without
                mutating the shared ``Adb._target_device`` global. Omit to
                use the current global target (default behavior, unchanged).

        Returns:
            True if snapshot was created successfully.
        """
        self._logger.info(f"Creating snapshot: {name}")
        adb = self._get_adb()

        try:
            command = _snapshot_command("save", name)

            stdout, stderr = adb.send_telnet_command(command, serial=serial)

            # The console reports failures as "KO: ..." on stdout (adb exit 0).
            if stderr or "KO:" in str(stdout or ""):
                self._logger.error(f"Failed to create snapshot: {stderr or stdout}")
                _snapshot_line("save", name, False, serial, str(stderr or stdout))
                return False

            self._logger.info(f"Snapshot '{name}' created successfully")
            _snapshot_line("save", name, True, serial)
            return True

        except Exception as e:
            self._logger.error(f"Failed to create snapshot: {e}")
            _snapshot_line("save", name, False, serial, str(e))
            return False

    def load_snapshot(self, name: str, serial: str | None = None) -> bool:
        """Load a previously created snapshot.

        Args:
            name: Name of the snapshot to load.
            serial: Device serial to target for this call only, without
                mutating the shared ``Adb._target_device`` global. Omit to
                use the current global target (default behavior, unchanged).

        Returns:
            True if snapshot was loaded successfully.
        """
        self._logger.info(f"Loading snapshot: {name}")
        adb = self._get_adb()
        _load_started(serial)
        try:
            return self._load_snapshot(adb, name, serial)
        finally:
            _load_finished(serial)

    def _load_snapshot(self, adb: Any, name: str, serial: str | None) -> bool:
        """:meth:`load_snapshot` body (the in-flight marker is held)."""
        try:
            command = _snapshot_command("load", name)

            t_sent = time.time()
            stdout, stderr = adb.send_telnet_command(command, serial=serial)
            t_ret = time.time()

            # The console reports failures (e.g. unknown snapshot) as
            # "KO: ..." on stdout while adb itself exits 0.
            if stderr or "KO:" in str(stdout or ""):
                self._logger.error(f"Failed to load snapshot: {stderr or stdout}")
                _snapshot_line("load", name, False, serial, str(stderr or stdout))
                return False

            # No device-prepared step while the restored device re-attaches:
            # the load restores SELinux / clock / proxy itself, and the boot
            # it restored is recorded on exit (no second preparation, no
            # device_prepared hooks).
            from sandroid.core import device_prep

            with device_prep.hold(serial, "snapshot-load"):
                # The device's state was replaced: a new world on the session
                # timeline, BEFORE anything samples the restored clocks (the
                # device-clock barrier keeps fresh monotonic times off the old
                # offset).
                _world_change(
                    "snapshot-load",
                    src="snapshot",
                    kind="load",
                    summary=f"snapshot '{_name_text(name)}' loaded",
                    t=t_ret,
                    t_err_ms=(t_ret - t_sent) * 500,
                    dev=serial,
                    data={
                        "name": name,
                        "ok": True,
                        "console_ms": round((t_ret - t_sent) * 1000, 1),
                    },
                )

                # Reverting VM state disrupts the ADB transport for a variable
                # window (offline -> unauthorized -> device); poll get-state for
                # real readiness instead of blindly sleeping a fixed 2s, which
                # was sometimes too short (a race) and often too long (needless
                # latency on a device that recovers quickly).
                self._wait_for_device_ready(adb, serial)
                # The snapshot also restores the kernel's SELinux mode. One saved
                # before startup's ``setenforce 0`` comes back Enforcing, and then
                # root binder calls (settings, dumpsys, screencap, frida) fail with
                # FAILED_TRANSACTION until Sandroid is restarted. Re-apply it
                # first: the clock step's root reads of /proc/timer_list and its
                # ``date`` may be denied under Enforcing.
                self._restore_selinux_permissive(adb, serial)
                # A snapshot restores the guest clock to the moment it was saved,
                # so every revert rewinds device time (minutes after a few
                # replays), skewing file timestamps / the timeline against the
                # host. Record the offset in the session timeline and, with
                # ``emulator.sync_device_clock`` on, set it to host time.
                self._record_device_clock(adb, name, serial)
                # ...and the device settings, including ``http_proxy``: a
                # snapshot saved without the proxy drops mitmproxy's device
                # proxy, so the replays were never intercepted. Re-apply it.
                self._restore_device_proxy(serial)
                # Then everything else the load invalidated, for every caller
                # (TUI, Play, AI, headless): Frida handles, App Proxy lanes and
                # the CA, frida-server, long-lived streams.
                self._after_snapshot_load(adb, serial)

            self._logger.info(f"Snapshot '{name}' loaded successfully")
            return True

        except Exception as e:
            self._logger.error(f"Failed to load snapshot: {e}")
            _snapshot_line("load", name, False, serial, str(e))
            return False

    def _after_snapshot_load(self, adb: AdbProtocol, serial: str | None) -> None:
        """Post-load steps after the device proxy (best-effort, never raises).

        1. Drop the host Frida handles and the Spotlight PID (dead now),
           only when *serial* is the active device.
        2. :func:`~sandroid.services.proxy_restore.restore_proxy_infra`:
           App Proxy lanes, then the CA (no-restart re-inject only when the
           user injected it on this serial this session).
        3. frida-server auto-start on that serial (own thread, active device
           only; the outcome is published for the TUI).
        4. after-load hooks (tracking logcat, file monitor restarts).
        """
        target = serial or self._target_serial(adb)
        # The Frida handles, Spotlight PID and frida-server manager belong
        # to the active device: a load on another serial leaves them alone.
        active = is_active_serial(target)
        if active:
            reset_device_handles_after_snapshot_load()
        try:
            from sandroid.services.proxy_restore import restore_proxy_infra

            restore_proxy_infra(target, "snapshot-load", device_proxy=False)
        except Exception as exc:
            self._logger.warning(f"Proxy restore after snapshot load failed: {exc}")
        if active:
            _auto_start_frida_after_load(target)
        _run_after_load_hooks(target)

    def _record_device_clock(
        self, adb: AdbProtocol, name: str, serial: str | None
    ) -> None:
        """Best-effort: :func:`sandroid.core.device_clock.after_snapshot_load`
        (``snapshot-load`` sample, the optional clock sync, the warnings).
        The service's adb is only the one-shot fallback of the ``date``
        commands (the persistent clock shell runs them). Never raises.
        """
        try:
            from sandroid.core import device_clock

            device_clock.after_snapshot_load(
                name,
                serial,
                send=lambda command: adb.send_adb_command(command, serial=serial),
            )
        except Exception as exc:
            self._logger.debug(f"Device clock after snapshot load failed: {exc}")

    def _restore_device_proxy(self, serial: str | None) -> str:
        """Best-effort: re-apply mitmproxy's device proxy after a load.

        Only acts when Sandroid itself set the device proxy (see
        ``MitmproxyService.reapply_device_proxy``); costs no adb call
        otherwise. Never raises.
        """
        try:
            from sandroid.services.mitmproxy_service import peek_mitmproxy_service

            service = peek_mitmproxy_service()
            if service is None:
                return "none"
            return service.reapply_device_proxy(serial)
        except Exception as exc:
            self._logger.debug(f"Device proxy check after snapshot load failed: {exc}")
            return "failed"

    def _restore_selinux_permissive(self, adb: AdbProtocol, serial: str | None) -> bool:
        """Best-effort: put SELinux back to Permissive after a snapshot load.

        Mirrors the startup preparation (``setup_checks.check_and_set_selinux``):
        only acts when ``getenforce`` says Enforcing; tries ``setenforce 0``,
        then via ``su``, then after ``adb root``. Never raises; returns whether
        the device ends up (or already was) Permissive.
        """

        def mode() -> str:
            try:
                stdout, _stderr = adb.send_adb_command(
                    "shell getenforce", serial=serial
                )
            except Exception:
                return ""
            return str(stdout or "").strip().lower()

        if mode() != "enforcing":
            return True
        attempts = (
            ("shell setenforce 0",),
            ("shell su 0 setenforce 0",),
            ("root", "wait-for-device", "shell setenforce 0"),
        )
        for commands in attempts:
            for command in commands:
                try:
                    adb.send_adb_command(command, serial=serial)
                except Exception as exc:
                    self._logger.debug(f"{command!r} after snapshot load failed: {exc}")
                    break
            if mode() == "permissive":
                from sandroid.services.setup_checks import log_selinux_change

                log_selinux_change(
                    "enforcing",
                    "permissive",
                    "snapshot load had restored Enforcing",
                    serial,
                )
                return True
        self._logger.warning(
            "SELinux is Enforcing after the snapshot load and could not be set "
            "to Permissive (needs root): adb/frida tooling may fail"
        )
        return False

    def _wait_for_device_ready(
        self,
        adb: AdbProtocol,
        serial: str | None,
        timeout: float = 10.0,
        interval: float = 0.4,
    ) -> bool:
        """Poll ``adb get-state`` until the device reports ``"device"``.

        Used after a snapshot load in place of a blind ``time.sleep(2)`` —
        reverting VM state disrupts the ADB transport for a variable window
        (offline -> unauthorized -> occasionally a duplicate listing -> back
        to device), so a fixed sleep is both a race (too short on a slow
        revert) and needless latency (too long on a fast one).

        Args:
            adb: ADB interface to poll through.
            serial: Device serial to target, or ``None`` for the current
                global target.
            timeout: Max seconds to wait before giving up.
            interval: Seconds between polls.

        Returns:
            True if the device reported ready within ``timeout``; False if
            the wait timed out. Never raises — a timeout is logged as a
            warning only, since the snapshot load itself already succeeded
            and the caller has no better fallback than "continue anyway".
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                stdout, _stderr = adb.send_adb_command("get-state", serial=serial)
                if stdout.strip() == "device":
                    return True
            except Exception:
                pass
            time.sleep(interval)
        self._logger.warning(
            f"Device not confirmed ready within {timeout}s after snapshot "
            "load -- continuing anyway"
        )
        return False

    def delete_snapshot(self, name: str, serial: str | None = None) -> bool:
        """Delete a previously created snapshot.

        Mirrors :meth:`create_snapshot` exactly, changing only the console
        verb. Blocking call (no worker); callers wrap it off the UI thread.

        NOTE: ``avd snapshot del`` is the documented emulator-console verb but
        has no in-repo precedent (create/load use ``save``/``load``). It must
        be confirmed on a live emulator.

        Args:
            name: Name of the snapshot to delete.
            serial: Device serial to target for this call only (as for
                :meth:`create_snapshot`); omit for the current global target.

        Returns:
            True if the snapshot was deleted successfully.
        """
        self._logger.info(f"Deleting snapshot: {name}")
        adb = self._get_adb()

        try:
            command = _snapshot_command("del", name)

            if serial is None:
                stdout, stderr = adb.send_telnet_command(command)
            else:
                stdout, stderr = adb.send_telnet_command(command, serial=serial)

            # Like save/load, the console reports failures (unknown snapshot,
            # bad sub-command) as "KO: ..." on stdout while adb exits 0.
            if stderr or "KO:" in str(stdout or ""):
                self._logger.error(f"Failed to delete snapshot: {stderr or stdout}")
                _snapshot_line("delete", name, False, serial, str(stderr or stdout))
                return False

            self._logger.info(f"Snapshot '{name}' deleted successfully")
            _snapshot_line("delete", name, True, serial)
            return True

        except Exception as e:
            self._logger.error(f"Failed to delete snapshot: {e}")
            _snapshot_line("delete", name, False, serial, str(e))
            return False

    def list_snapshots(self) -> list[SnapshotInfo]:
        """List available snapshots.

        Returns:
            List of SnapshotInfo objects.
        """
        adb = self._get_adb()

        try:
            snapshots = adb.get_avd_snapshots()
            return [
                SnapshotInfo(name=s.get("tag", ""), date=s.get("date", ""))
                for s in snapshots
            ]
        except Exception as e:
            self._logger.error(f"Failed to list snapshots: {e}")
            return []

    # =========================================================================
    # Emulator Lifecycle Methods
    # =========================================================================

    def restart(self, boot_timeout: float = 180.0) -> bool:
        """Restart the target emulator and wait until it has booted.

        Delegates to :func:`sandroid.core.emulator.restart_emulator` with the
        explicit target serial: exactly that emulator is stopped (``adb -s
        <serial> emu kill``) and the AVD it was running is relaunched on the
        same port (same serial) with the safe launch flags. Success is only
        reported once it is ready again (``sys.boot_completed=1`` and the
        package manager answers).

        Args:
            boot_timeout: Seconds to wait for the restarted emulator to boot.

        Returns:
            True once the restarted emulator has booted; False if it could
            not be restarted, crashed on startup or did not boot in time.

        Raises:
            RuntimeError: No emulator executable, or no target emulator.
        """
        from sandroid.core import emulator
        from sandroid.core.exceptions import EmulatorLaunchError

        self._logger.info("Restarting emulator")
        adb = self._get_adb()
        serial = self._target_serial(adb)
        if not serial or emulator.serial_port(serial) is None:
            raise RuntimeError(f"No target emulator to restart (target: {serial})")
        if emulator.emulator_binary() is None:
            raise RuntimeError("Emulator executable not found (emulator path unset)")

        try:
            launch = emulator.restart_emulator(serial, adb=adb)
        except EmulatorLaunchError as e:
            self._logger.error(f"Could not restart {serial}: {e}")
            return False

        if not emulator.wait_until_ready(serial, timeout=boot_timeout, adb=adb):
            self._logger.error(
                f"Emulator '{launch.avd}' did not finish booting within "
                f"{boot_timeout:.0f}s (log: {launch.log_path})"
            )
            return False

        self._logger.info(f"Emulator {launch.avd} restarted")
        # The device-prepared step records the reboot (world change "reboot")
        # and re-prepares the device; only while it is off is the cold boot
        # recorded here.
        if not self._prepare_after_restart(serial):
            _world_change(
                "cold-boot",
                src="device",
                kind="boot",
                summary=f"⟲ emulator {launch.avd} cold-booted",
                dev=serial,
                data={"avd": launch.avd, "ok": True},
            )
            # ...and once only: a later attach of this boot (the step was
            # on but did not prepare it) records no second "reboot".
            try:
                from sandroid.core import device_prep

                device_prep.note_world_recorded(serial)
            except Exception as exc:
                self._logger.debug(f"Could not note the cold boot: {exc}")
        # A cold boot wiped the CA mounts, gost, the lane rules and adb
        # reverse. DeviceManager's device-prepared hook (fresh_boot=True)
        # restores them when it exists, device preparation is enabled
        # (checked now, not at import) AND this is the active device (the
        # step only prepares that one); otherwise restore here.
        try:
            from sandroid.services import proxy_restore

            # TODO(device-prepared-hook): drop this call once DeviceManager's
            # register_device_prepared_hook is on main and always enabled.
            if not (
                proxy_restore.device_prepared_hook_active() and is_active_serial(serial)
            ):
                proxy_restore.restore_proxy_infra(serial, "cold-boot", fresh_boot=True)
        except Exception as exc:
            self._logger.warning(f"Proxy restore after the restart failed: {exc}")
        return True

    #: Seconds :meth:`restart` waits for the device-prepared step.
    RESTART_PREP_TIMEOUT = 180.0

    def _prepare_after_restart(self, serial: str) -> bool:
        """Re-attach the restarted device and wait for the device-prepared
        step (reboot world change, root + SELinux, hooks).

        Returns:
            False when the step is off or does not prepare ``serial`` (not
            the active device); the caller then records the cold boot.
        """
        try:
            from sandroid.core import device_prep
            from sandroid.core.device_manager import DeviceManager

            if not device_prep.is_enabled():
                return False
            manager = DeviceManager.get()
            manager.refresh_devices()  # re-attaches the previous device
            if not (
                device_prep.is_preparing(serial)
                or device_prep.request_prepare(serial, "restart", manager=manager)
            ):
                return False
            if not device_prep.wait_prepared(serial, self.RESTART_PREP_TIMEOUT):
                self._logger.warning(
                    f"{serial} is still being prepared after "
                    f"{self.RESTART_PREP_TIMEOUT:g} s"
                )
            return True
        except Exception as exc:
            self._logger.debug(f"Device preparation after restart failed: {exc}")
            return False

    @staticmethod
    def _target_serial(adb: Any) -> str | None:
        """The target serial: the adb target, else the active device."""
        getter = getattr(adb, "get_target_device", None)
        if callable(getter):
            try:
                serial = getter()
            except Exception:
                serial = None
            if serial:
                return serial
        try:
            from sandroid.core.device_manager import DeviceManager

            device = DeviceManager.get().active_device
        except Exception:
            device = None
        return device.serial if device is not None else None

    def kill(self) -> bool:
        """Stop the target emulator (``adb -s <serial> emu kill``).

        Delegates to :func:`sandroid.core.emulator.stop_emulator`; never
        kills processes by name, so other emulators are untouched.

        Returns:
            True once the emulator has left ``adb devices``.
        """
        from sandroid.core.emulator import stop_emulator

        self._logger.info("Killing emulator")
        adb = self._get_adb()
        serial = self._target_serial(adb)
        if not serial:
            self._logger.error("Failed to kill emulator: no target device")
            return False
        try:
            return stop_emulator(serial, adb)
        except Exception as e:
            self._logger.error(f"Failed to kill emulator: {e}")
            return False

    # =========================================================================
    # Tool Usage Tracking
    # =========================================================================

    def get_tools_used(self) -> dict:
        """Get dictionary of tools used and their output files.

        Returns:
            Dict mapping tool names to usage info.
        """
        return self._tools_used.copy()

    def reset_tools_used(self) -> None:
        """Reset tool usage tracking."""
        self._tools_used = {}

    # =========================================================================
    # Service Management
    # =========================================================================

    def reset(self) -> None:
        """Reset service state (useful for testing)."""
        # Stop any active recording
        if self.is_recording():
            self.stop_recording()

        with self._recording_lock:
            self._recording = ScreenRecordingState()
            self._recording_stop_event.clear()
            self._recording_process = None
            self._recording_thread = None

        with self._lock:
            self._tools_used = {}

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _get_adb(self) -> AdbProtocol:
        """Get ADB instance, falling back to global class.

        Returns:
            ADB interface for device communication.

        Raises:
            RuntimeError: If ADB is not available and no instance was injected.
        """
        if self._adb is not None:
            return self._adb

        # Fallback to global Adb class
        try:
            from sandroid.core.adb import Adb

            return Adb
        except ImportError:
            raise RuntimeError("ADB not available and no ADB instance provided")

    def _get_screenshots_dir(self) -> str:
        """Get screenshots directory path."""
        if self._config_service:
            raw_path = self._config_service.get_raw_results_path()
            return os.path.join(raw_path, "screenshots")

        # Fallback to environment
        raw_path = os.getenv("RAW_RESULTS_PATH", "")
        if raw_path:
            return os.path.join(raw_path, "screenshots")
        return "screenshots"

    def _mark_tool_used(self, tool_name: str, files: list[str]) -> None:
        """Mark a tool as used with associated files."""
        if tool_name not in self._tools_used:
            self._tools_used[tool_name] = {"used": True, "files": []}
        self._tools_used[tool_name]["files"].extend(files)

    def _publish_screenshot_taken(self, path: str) -> None:
        """Publish screenshot event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"action": "screenshot_taken", "path": path},
                source="emulator_service",
            )
        )

    def _publish_recording_started(self, path: str) -> None:
        """Publish recording started event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.TASK_STARTED,
                data={
                    "task_name": "screen_recording",
                    "display_name": "Screen Recording",
                    "path": path,
                },
                source="emulator_service",
            )
        )

    def _publish_recording_stopped(self, path: str) -> None:
        """Publish recording stopped event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.TASK_STOPPED,
                data={
                    "task_name": "screen_recording",
                    "display_name": "Screen Recording",
                    "path": path,
                    "success": True,
                },
                source="emulator_service",
            )
        )


# Backwards compatibility exports
__all__ = [
    "EmulatorService",
    "ScreenRecordingState",
    "SnapshotInfo",
]
