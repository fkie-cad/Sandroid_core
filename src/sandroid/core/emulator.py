import os
import platform
import re
import shutil
import subprocess
import time
from logging import getLogger
from pathlib import Path

logger = getLogger(__name__)

# Keywords indicating emulator startup failure in stderr output
EMULATOR_ERROR_KEYWORDS = ("PANIC", "ERROR", "WARNING", "Fatal")
_STARTUP_GRACE_PERIOD = 3


#: Where detached emulators write their stdout/stderr (one file per AVD).
EMULATOR_LOG_DIR = Path("~/.cache/sandroid/emulator").expanduser()


def emulator_log_path(avd_name: str) -> Path:
    """Return the log file a detached emulator for *avd_name* writes to."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", avd_name or "") or "emulator"
    return EMULATOR_LOG_DIR / f"{safe}.log"


def spawn_emulator(
    command: list[str], avd_name: str, env: dict[str, str] | None = None
) -> tuple[subprocess.Popen, Path | None]:
    """Start a detached emulator whose output goes to a log file.

    The emulator outlives the call (``start_new_session=True``), so its
    output must never go to a pipe nobody drains: once the ~64 KiB pipe
    buffer fills the emulator blocks on its next log write. stdout and
    stderr are written to :func:`emulator_log_path` instead (truncated per
    launch), or discarded if the log file cannot be created.

    Returns:
        ``(process, log_path)``; ``log_path`` is ``None`` when output is
        discarded.

    Raises:
        OSError / subprocess.SubprocessError: The process could not start.
    """
    log_path: Path | None = emulator_log_path(avd_name)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        sink = open(log_path, "wb")
    except OSError:
        log_path, sink = None, None
    try:
        process = subprocess.Popen(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sink if sink is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if sink is not None else subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        if sink is not None:
            sink.close()  # the child keeps its own descriptor
    return process, log_path


def check_emulator_startup(
    process: subprocess.Popen, log_path: str | Path | None = None
) -> tuple[bool, str]:
    """Check whether an emulator process survived initial startup.

    Waits briefly, then checks if the process is still running.
    If it exited, reads its output and filters for error keywords.

    Args:
        process: The emulator Popen process.
        log_path: Log file the process writes to (see :func:`spawn_emulator`).
            Without it, ``process.stderr`` is read if it is a pipe.

    Returns:
        Tuple of (success, error_message). On success error_message is empty.
    """
    time.sleep(_STARTUP_GRACE_PERIOD)
    exit_code = process.poll()
    if exit_code is None:
        return True, ""

    stderr_output = ""
    try:
        if log_path is not None:
            stderr_output = Path(log_path).read_bytes().decode(errors="replace")
        elif process.stderr is not None:
            stderr_output = process.stderr.read().decode(errors="replace")
    except OSError:
        pass
    error_lines = [
        line
        for line in stderr_output.strip().splitlines()
        if any(kw in line for kw in EMULATOR_ERROR_KEYWORDS)
    ]
    error_msg = "; ".join(error_lines) if error_lines else f"exit code {exit_code}"
    return False, error_msg


class Emulator:
    """Utility class for working with Android emulators."""

    # Class variable to store the emulator path
    _emulator_path = None

    @classmethod
    def detect_emulator_path(cls) -> str | None:
        """Detects the path to the Android emulator executable.

        Returns:
            str: Path to the emulator executable if found, None otherwise
        """
        # Return cached path if already detected
        if cls._emulator_path:
            return cls._emulator_path

        # Common locations to check
        possible_paths = []

        # Check environment variables first
        android_home = os.environ.get("ANDROID_HOME")
        android_sdk_root = os.environ.get("ANDROID_SDK_ROOT")

        if android_home:
            possible_paths.append(os.path.join(android_home, "emulator", "emulator"))
            possible_paths.append(os.path.join(android_home, "tools", "emulator"))

        if android_sdk_root:
            possible_paths.append(
                os.path.join(android_sdk_root, "emulator", "emulator")
            )
            possible_paths.append(os.path.join(android_sdk_root, "tools", "emulator"))

        # Common installation locations based on platform
        system = platform.system()
        if system == "Darwin":  # macOS
            possible_paths.extend(
                [
                    "/Applications/Android Studio.app/Contents/sdk/emulator/emulator",
                    os.path.expanduser("~/Library/Android/sdk/emulator/emulator"),
                ]
            )
        elif system == "Windows":
            possible_paths.extend(
                [
                    r"C:\Program Files\Android\Android Studio\sdk\emulator\emulator.exe",
                    os.path.expanduser(
                        "~/AppData/Local/Android/sdk/emulator/emulator.exe"
                    ),
                ]
            )
        elif system == "Linux":
            possible_paths.extend(
                [
                    os.path.expanduser("~/Android/Sdk/emulator/emulator"),
                    "/opt/android-sdk/emulator/emulator",
                ]
            )

        # Try to find emulator on PATH (cross-platform)
        which_result = shutil.which("emulator")
        if which_result:
            possible_paths.append(which_result)

        # Check each path
        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                cls._emulator_path = path
                return path

        return None

    @classmethod
    def list_available_avds(cls) -> list[str]:
        """Lists all available Android Virtual Devices (AVDs).

        Returns:
            List[str]: Names of available emulator AVDs
        """
        emulator_path = cls.detect_emulator_path()
        if not emulator_path:
            return []

        try:
            result = subprocess.run(
                [emulator_path, "-list-avds"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if result.returncode == 0:
                # Split the output by lines and filter out empty lines
                avds = [
                    line.strip() for line in result.stdout.split("\n") if line.strip()
                ]
                return avds
            return []
        except OSError as e:
            logger.error(f"Failed to start emulator process: {e}")
            return []
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error listing AVDs: {e}")
            return []

    @classmethod
    def start_avd(
        cls,
        avd_name: str,
        extra_args: list[str] = None,
        boot_mode: str = "default",
        snapshot_name: str = None,
    ) -> bool:
        """Starts the specified Android Virtual Device (AVD).

        Args:
            avd_name: The name of the AVD to start.
            extra_args: Additional arguments for the emulator command.
            boot_mode: How to boot the AVD:
                - "default": Load default_boot snapshot (standard behavior)
                - "cold": Don't load any snapshot (-no-snapshot-load)
                - "snapshot": Load specific snapshot (requires snapshot_name)
                - "wipe": Wipe all data and start fresh (-wipe-data)
            snapshot_name: Name of snapshot to load (only when boot_mode="snapshot")

        Returns:
            True if the emulator process was started successfully, False otherwise.
        """
        emulator_path = cls.detect_emulator_path()
        if not emulator_path:
            print("Error: Emulator path could not be detected.")
            return False

        from sandroid.core.emulator_guard import emulator_launch_args

        command = [emulator_path, "-avd", avd_name]
        # Guest Vulkan off: SwiftShader Vulkan leaks host memory on every
        # snapshot load (see core/emulator_guard.py).
        command.extend(emulator_launch_args())

        # Add boot mode flags
        if boot_mode == "cold":
            command.append("-no-snapshot-load")
        elif boot_mode == "wipe":
            command.append("-wipe-data")
        elif boot_mode == "snapshot" and snapshot_name:
            command.extend(["-snapshot", snapshot_name])
        # "default" mode: no additional flags (uses default_boot automatically)

        if extra_args:
            command.extend(extra_args)

        try:
            logger.info(
                f"Starting emulator '{avd_name}' with command: {' '.join(command)}"
            )
            # Non-blocking, detached (start_new_session isolates it from
            # terminal signals such as Ctrl+C); output goes to a log file.
            process, log_path = spawn_emulator(command, avd_name)
            logger.info(
                f"Emulator '{avd_name}' is starting up (PID {process.pid}, "
                f"log {log_path})..."
            )

            ok, error_msg = check_emulator_startup(process, log_path)
            if not ok:
                logger.error(
                    f"Emulator '{avd_name}' crashed during startup: {error_msg}"
                )
                return False

            return True
        except OSError as e:
            logger.error(f"Failed to start emulator process '{avd_name}': {e}")
            return False
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error starting emulator '{avd_name}': {e}")
            return False
