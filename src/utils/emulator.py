import os
import platform
import subprocess
import time
from logging import getLogger

logger = getLogger(__name__)


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

        # Try command which emulator if available (for Unix-like systems)
        try:
            result = subprocess.run(
                ["which", "emulator"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                possible_paths.append(result.stdout.strip())
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            logger.debug(f"Could not detect emulator using 'which' command: {e}")
            # Continue with other detection methods

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
        except Exception as e:
            print(f"Error listing available AVDs: {e}")
            return []

    @classmethod
    def start_avd(cls, avd_name: str, extra_args: list[str] = None) -> bool:
        """Starts the specified Android Virtual Device (AVD).

        Args:
            avd_name (str): The name of the AVD to start.
            extra_args (List[str], optional): Additional arguments for the emulator command. Defaults to None.

        Returns:
            bool: True if the emulator process was started successfully, False otherwise.
        """
        emulator_path = cls.detect_emulator_path()
        if not emulator_path:
            print("Error: Emulator path could not be detected.")
            return False

        command = [emulator_path, "-avd", avd_name]
        # Add common performance flags (adjust as needed)
        command.extend(["-feature", "-Vulkan", "-gpu", "host"])

        if extra_args:
            command.extend(extra_args)

        try:
            print(f"Starting emulator '{avd_name}' with command: {' '.join(command)}")
            # Use Popen for non-blocking start
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Emulator '{avd_name}' is starting up. Please wait...")
            # Note: A fixed sleep might not be reliable. Consider adding checks later.
            time.sleep(10)
            return True
        except Exception as e:
            print(f"Error starting emulator '{avd_name}': {e}")
            return False
