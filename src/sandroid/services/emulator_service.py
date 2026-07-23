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
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

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

        Uses the emulator's telnet screenrecord command to capture.

        Args:
            filename: Optional custom filename. If None, generates timestamped name.

        Returns:
            Path to the saved screenshot file, or None if failed.
        """
        # Get screenshots directory
        screenshots_dir = self._get_screenshots_dir()
        os.makedirs(screenshots_dir, exist_ok=True)

        # Generate filename if not provided
        if filename is None:
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"screenshot_{timestamp}.png"

        # Ensure .png extension
        if not filename.endswith(".png"):
            filename += ".png"

        full_path = os.path.join(screenshots_dir, filename)

        # Take screenshot via telnet
        self._logger.info(f"Taking screenshot: {full_path}")
        adb = self._get_adb()

        try:
            _stdout, stderr = adb.send_telnet_command(
                f"screenrecord screenshot {full_path}"
            )

            if stderr:
                self._logger.error(f"Failed to capture screenshot: {stderr}")
                return None

            self._logger.info(f"Screenshot saved to {full_path}")
            self._mark_tool_used("screenshots", [full_path])
            self._publish_screenshot_taken(full_path)

            return full_path

        except Exception as e:
            self._logger.error(f"Screenshot failed: {e}")
            return None

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
            _stdout, stderr = adb.send_adb_command(f"pull {device_path} {local_path}")

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
        try:
            return subprocess.Popen(
                ["adb", "shell", "screenrecord", device_path],
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
            # Handle both string and bytes for name
            if isinstance(name, str):
                command = f"avd snapshot save {name}"
            else:
                command = b"avd snapshot save " + name

            _stdout, stderr = adb.send_telnet_command(command, serial=serial)

            if stderr:
                self._logger.error(f"Failed to create snapshot: {stderr}")
                return False

            self._logger.info(f"Snapshot '{name}' created successfully")
            return True

        except Exception as e:
            self._logger.error(f"Failed to create snapshot: {e}")
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

        try:
            # Handle both string and bytes for name
            if isinstance(name, str):
                command = f"avd snapshot load {name}"
            else:
                command = b"avd snapshot load " + name

            _stdout, stderr = adb.send_telnet_command(command, serial=serial)

            if stderr:
                self._logger.error(f"Failed to load snapshot: {stderr}")
                return False

            # Reverting VM state disrupts the ADB transport for a variable
            # window (offline -> unauthorized -> device); poll get-state for
            # real readiness instead of blindly sleeping a fixed 2s, which
            # was sometimes too short (a race) and often too long (needless
            # latency on a device that recovers quickly).
            self._wait_for_device_ready(adb, serial)

            self._logger.info(f"Snapshot '{name}' loaded successfully")
            return True

        except Exception as e:
            self._logger.error(f"Failed to load snapshot: {e}")
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

    def delete_snapshot(self, name: str) -> bool:
        """Delete a previously created snapshot.

        Mirrors :meth:`create_snapshot` exactly, changing only the console
        verb. Blocking call (no worker); callers wrap it off the UI thread.

        NOTE: ``avd snapshot del`` is the documented emulator-console verb but
        has no in-repo precedent (create/load use ``save``/``load``). It must
        be confirmed on a live emulator.

        Args:
            name: Name of the snapshot to delete.

        Returns:
            True if the snapshot was deleted successfully.
        """
        self._logger.info(f"Deleting snapshot: {name}")
        adb = self._get_adb()

        try:
            # Handle both string and bytes for name
            if isinstance(name, str):
                command = f"avd snapshot del {name}"
            else:
                command = b"avd snapshot del " + name

            _stdout, stderr = adb.send_telnet_command(command)

            if stderr:
                self._logger.error(f"Failed to delete snapshot: {stderr}")
                return False

            self._logger.info(f"Snapshot '{name}' deleted successfully")
            return True

        except Exception as e:
            self._logger.error(f"Failed to delete snapshot: {e}")
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

    def restart(self) -> bool:
        """Restart the Android emulator.

        Attempts to kill the current emulator and start a new instance.

        Returns:
            True if restart initiated successfully.
        """
        self._logger.info("Restarting emulator")
        adb = self._get_adb()

        # Get emulator configuration
        device_name = self._get_device_name()
        emulator_path = self._get_emulator_path()

        # Try to kill existing emulator
        try:
            _stdout, stderr = adb.send_telnet_command(b"kill")

            if stderr:
                self._logger.warning(
                    f"Emulator {device_name} was not running, starting now"
                )

        except Exception as e:
            self._logger.debug(
                f"Kill command failed (emulator may not be running): {e}"
            )

        # Start new emulator instance
        try:
            subprocess.Popen(
                [
                    emulator_path,
                    "@",
                    device_name,
                    "-feature",
                    "-Vulkan",
                    "-gpu",
                    "host",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            # Wait for emulator to start
            time.sleep(5)

            self._logger.info(f"Emulator {device_name} restart initiated")
            return True

        except FileNotFoundError as e:
            error_msg = f"Emulator executable not found at '{emulator_path}': {e}"
            self._logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except (OSError, subprocess.SubprocessError) as e:
            error_msg = f"Failed to start emulator '{device_name}': {e}"
            self._logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except Exception as e:
            self._logger.error(f"Failed to start emulator: {e}")
            return False

    def kill(self) -> bool:
        """Kill the running emulator.

        Returns:
            True if kill command was sent.
        """
        self._logger.info("Killing emulator")
        adb = self._get_adb()

        try:
            _stdout, _stderr = adb.send_telnet_command(b"kill")
            return True
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

    def _get_device_name(self) -> str:
        """Get device name from config or default."""
        if self._config_service:
            return self._config_service.get_device_name()
        return "Pixel_6_Pro_API_31"

    def _get_emulator_path(self) -> str:
        """Get emulator path from config or auto-detect."""
        if self._config_service:
            path = self._config_service.get_emulator_path()
            if path:
                return path
        return ""

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
