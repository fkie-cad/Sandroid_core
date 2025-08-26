import os
import re
import shutil
import subprocess
from logging import getLogger
from subprocess import PIPE

logger = getLogger(__name__)


class Adb:
    """Represents the Android Debug Bridge (ADB) functionality.

    **Attributes:**
        ADB_PATH (str): Path to the ADB executable.
        logger (Logger): Logger instance for ADB operations.
    """

    ADB_PATH = None

    @classmethod
    # TODO: make sure adb root is run
    def init(cls):
        """Initializes the ADB class by setting the ADB path and logger.

        .. note::
            This method ensures that the ADB path is correctly set and logs the path.
        """
        if not cls.ADB_PATH:
            try:
                cls.ADB_PATH = shutil.which("adb")
            except shutil.Error:
                logger.critical("Could not find ADB path")
                exit(1)
            if cls.ADB_PATH is None:
                logger.critical('"which adb" returned none')
                exit(1)
            logger.debug("Android debug bridge path found: " + cls.ADB_PATH)

    @classmethod
    def send_adb_command(cls, command):
        """Sends an ADB command and returns the output.

        :param command: The ADB command to be executed.
        :type command: str
        :returns: A tuple containing the stdout and stderr of the command.
        :rtype: tuple
        """
        logger.debug("Running ADB command " + command)
        output = subprocess.run(
            [cls.ADB_PATH + " " + command],
            check=False,
            capture_output=True,
            text=True,
            shell=True,
        )
        return output.stdout, output.stderr.strip()

    @classmethod
    def send_adb_command_popen(cls, command):
        """Executes an ADB command using subprocess.Popen.

        :param command: The ADB command to be executed.
        :type command: str
        :returns: The Popen object representing the running process.
        :rtype: subprocess.Popen
        """
        logger.debug("Running ADB command " + command)
        process = subprocess.Popen(
            [cls.ADB_PATH + " " + command],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            shell=True,
        )

        return process

    # TODO: This should also handle APK / package names and search online repos
    @classmethod
    def install_apk(cls, apk_path):
        """Installs an APK file on the device.

        :param apk_path: The path to the APK file.
        :type apk_path: str
        """
        apk_file = os.path.basename(apk_path)
        logger.info(f"Installing local APK {apk_file}")
        # TODO: catch errors
        Adb.send_adb_command(f"install {apk_path}")

    @classmethod
    def send_telnet_command(cls, command):
        """Sends a telnet command to the emulator.

        :param command: The telnet command to be executed.
        :type command: str or bytes
        :returns: A tuple containing the stdout and stderr of the command.
        :rtype: tuple
        """
        if isinstance(command, bytes):
            command = command.decode("utf-8")
        stdout, stderr = cls.send_adb_command("emu " + command)
        if stderr:
            logger.error('Telnet command "' + command + '" failed. ' + stderr.strip())

        return stdout, stderr

    @classmethod
    def get_focused_app(cls):
        """Retrieves the package name and activity name of the currently focused app.

        :returns: A tuple containing the package name and activity name of the focused app.
        :rtype: tuple
        """
        output = cls.send_adb_command("shell dumpsys window")[0]

        for line in output.split("\n"):
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                match = re.search(r"([^ ]+)/([^ ]+)\}", line)
                if match:
                    package_name = match.group(1)
                    activity_name = match.group(2)
                    return package_name, activity_name
        return None, None

    @classmethod
    def get_pid_for_package_name(cls, package_name):
        """Get the process ID (PID) for a given package name.

        :param package_name: The name of the package.
        :type package_name: str
        :returns: The process ID if found, None otherwise.
        :rtype: int or None
        """
        output = cls.send_adb_command(f"shell pidof {package_name}")[0]

        # TODO: check, if output can be more than one process id
        if output:
            return int(output.strip())
        return None

    @classmethod
    def get_network_info(cls):
        """Get network information.

        :returns: A list of tuples where each tuple contains the interface name and its corresponding IPv4 address.
        :rtype: list of tuple
        """
        output = cls.send_adb_command("shell ifconfig")[0]
        interfaces = re.findall(
            r"(\w+)(?:\s+Link encap.+?\n)?\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            output,
            re.DOTALL,
        )
        return interfaces

    @classmethod
    def get_installed_packages(cls):
        """Get a list of installed packages along with their installation dates.

        :returns: A list of dictionaries where each dictionary contains the package name and installation date.
        :rtype: list of dict
        """
        output, error = cls.send_adb_command("shell pm list packages")
        if error:
            logger.error(f"Error getting installed packages: {error}")
            return []

        packages = []
        package_pattern = re.compile(r"package:(.+)")

        for line in output.strip().split("\n"):
            match = package_pattern.search(line)
            if match:
                package_name = match.group(1)

                detail_output, detail_error = cls.send_adb_command(
                    f"shell dumpsys package {package_name} | grep firstInstallTime"
                )
                install_date = None

                if not detail_error and detail_output:
                    install_match = re.search(r"firstInstallTime=(.+)", detail_output)
                    if install_match:
                        install_date = install_match.group(1)

                packages.append(
                    {"package_name": package_name, "install_date": install_date}
                )

        return packages

    @classmethod
    def send_adb_exec_out_command(cls, command):
        """Sends an ADB exec-out command and returns the output.

        :param command: The ADB command to be executed (without 'exec-out' prefix).
        :type command: str
        :returns: A tuple containing the stdout and stderr of the command.
        :rtype: tuple
        """
        full_command = f"exec-out {command}"
        logger.debug("Running ADB command " + full_command)
        output = subprocess.run(
            [cls.ADB_PATH + " " + full_command],
            check=False,
            capture_output=True,
            text=True,
            shell=True,
        )
        return output.stdout, output.stderr.strip()

    @classmethod
    def get_current_avd_name(cls):
        """Gets the name of the currently running AVD.

        :returns: The name of the current AVD or None if it cannot be determined
        :rtype: str or None
        """
        stdout, stderr = Adb.send_telnet_command("avd name")

        if stderr:
            cls.logger.error(f"Failed to get AVD name: {stderr}")
            return None

        if stdout:
            # The output format is typically:
            # AVD_NAME
            # OK
            lines = stdout.strip().split("\n")
            if lines:
                # The first line contains the AVD name
                avd_name = lines[0].strip()
                return avd_name

        return None

    @classmethod
    def get_current_avd_path(cls):
        """Gets the path of the currently running AVD.

        :returns: The file system path of the current AVD or None if it cannot be determined
        :rtype: str or None
        """
        stdout, stderr = cls.send_telnet_command("avd path")

        if stderr:
            logger.error(f"Failed to get AVD path: {stderr}")
            return None

        if stdout:
            # The output format is typically:
            # /path/to/avd/directory.avd
            # OK
            lines = stdout.strip().split("\n")
            if lines:
                # The first line contains the AVD path
                avd_path = lines[0].strip()
                return avd_path

        return None

    @classmethod
    def get_avd_snapshots(cls):
        """Gets a list of snapshots for the currently running AVD.

        :returns: A list of dictionaries containing snapshot information (id, tag, size, date, clock)
        :rtype: list of dict
        """
        stdout, stderr = cls.send_telnet_command("avd snapshot list")

        if stderr:
            logger.error(f"Failed to get AVD snapshots: {stderr}")
            return []

        snapshots = []

        if stdout:
            lines = stdout.strip().split("\n")
            # Skip the first two lines (header)
            for line in lines[2:]:
                if line.strip() and not line.startswith("OK"):
                    # Parse the snapshot information
                    # Format: ID   TAG                  VM SIZE    DATE              VM CLOCK
                    try:
                        parts = line.split(None, 1)  # Split on first whitespace
                        if len(parts) < 2:
                            continue

                        id_value = parts[0]
                        remaining = parts[1].strip()

                        # Extract tag (preserving spaces in the tag name)
                        # Look for multiple spaces followed by a size (e.g., "69M")
                        tag_size_split = re.search(r"(.*?)\s{2,}(\d+M)", remaining)
                        if not tag_size_split:
                            continue

                        tag = tag_size_split.group(1).strip()
                        size = tag_size_split.group(2)

                        # Extract the remaining part (date and clock)
                        remaining = remaining[tag_size_split.end() :].strip()
                        date_clock_split = re.search(
                            r"([\d-]+ [\d:]+)\s+([\d:\.]+)", remaining
                        )

                        if date_clock_split:
                            date = date_clock_split.group(1)
                            clock = date_clock_split.group(2)
                        else:
                            date = remaining
                            clock = ""

                        snapshots.append(
                            {
                                "id": id_value,
                                "tag": tag,
                                "size": size,
                                "date": date,
                                "clock": clock,
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Error parsing snapshot line '{line}': {e!s}")

        return snapshots

    @classmethod
    def get_device_time(cls):
        """Retrieves the current date and time of the connected device.

        :returns: The current date and time of the device as a string, or None if an error occurs.
        :rtype: str or None
        """
        stdout, stderr = cls.send_adb_command("shell date")

        if stderr:
            logger.error(f"Failed to get device time: {stderr}")
            return None

        return stdout.strip()

    @classmethod
    def get_device_locale(cls):
        """Retrieves the locale of the connected device.

        :returns: The locale of the device as a string, or None if an error occurs.
        :rtype: str or None
        """
        stdout, stderr = cls.send_adb_command("shell getprop ro.product.locale")

        if stderr:
            logger.error(f"Failed to get device locale: {stderr}")
            return None

        return stdout.strip() if stdout else None

    @classmethod
    def get_android_version_and_api_level(cls):
        """Retrieves the Android version and API level of the connected device.

        :returns: A dictionary containing the Android version and API level, or None if an error occurs.
        :rtype: dict or None
        """
        version_stdout, version_stderr = cls.send_adb_command(
            "shell getprop ro.build.version.release"
        )
        api_level_stdout, api_level_stderr = cls.send_adb_command(
            "shell getprop ro.build.version.sdk"
        )

        if version_stderr or api_level_stderr:
            logger.error(
                f"Failed to get Android version or API level: {version_stderr or api_level_stderr}"
            )
            return None

        return {
            "android_version": version_stdout.strip() if version_stdout else None,
            "api_level": api_level_stdout.strip() if api_level_stdout else None,
        }

    @classmethod
    def start_network_capture(cls, filename):
        """Starts capturing network packets from the emulator to a file.

        :param filename: Name of the file to save the network capture
        :type filename: str
        :returns: True if capture started successfully, False otherwise
        :rtype: bool
        """
        if not filename:
            logger.error("Filename cannot be empty for network capture")
            return False

        stdout, stderr = cls.send_telnet_command(f"network capture start {filename}")

        if stderr:
            logger.error(f"Failed to start network capture: {stderr}")
            return False

        if "OK" in stdout:
            logger.info(f"Network capture started, saving to: {filename}")
            return True
        logger.warning(f"Unexpected response when starting network capture: {stdout}")
        return False

    @classmethod
    def stop_network_capture(cls):
        """Stops the currently running network capture.

        :returns: True if capture stopped successfully, False otherwise
        :rtype: bool
        """
        stdout, stderr = cls.send_telnet_command("network capture stop")

        if stderr:
            logger.error(f"Failed to stop network capture: {stderr}")
            return False

        if "OK" in stdout:
            logger.info("Network capture stopped")
            return True
        logger.warning(f"Unexpected response when stopping network capture: {stdout}")
        return False
