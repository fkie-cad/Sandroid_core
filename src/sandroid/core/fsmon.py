import logging
import os
import subprocess
import tempfile

import requests

from .adb import Adb


class FSMon:
    # Base binary name pattern
    FS_MON_BINARY_BASE = "/data/local/tmp/fsmon-{arch}"

    # URLs for different architectures
    FS_MON_URLS = {
        "arm64": "https://github.com/nowsecure/fsmon/releases/download/1.8.6/fsmon-android-arm64",
        "arm": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-arm",
        "x86": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86",
        "x86_64": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86_64",
    }

    # Default to arm64 until architecture is detected
    FS_MON_BINARY = "/data/local/tmp/fsmon-arm64"

    # Logger
    logger = logging.getLogger(__name__)

    @classmethod
    def get_device_architecture(cls):
        """Detects the architecture of the connected Android device using ADB.

        :return: Architecture string (arm64, arm, x86, or x86_64)
        :rtype: str
        """
        stdout, stderr = Adb.send_adb_command("shell getprop ro.product.cpu.abi")
        abi = stdout.strip()

        if "arm64" in abi:
            return "arm64"
        if "armeabi" in abi:
            return "arm"
        if "x86_64" in abi:
            return "x86_64"
        if "x86" in abi:
            return "x86"
        # Default to arm64 if detection fails
        return "arm64"

    @classmethod
    def check_and_install_fsmon(cls):
        """Checks if the appropriate fsmon binary exists.
        If not, downloads it into a temporary directory,
        then pushes it to the device and makes it executable.
        """
        # Detect device architecture
        arch = cls.get_device_architecture()

        # Set binary path and URL based on architecture
        binary_path = cls.FS_MON_BINARY_BASE.format(arch=arch)
        binary_url = cls.FS_MON_URLS.get(arch)

        if not binary_url:
            binary_url = cls.FS_MON_URLS["arm64"]  # Default to arm64 if arch not found
            binary_path = cls.FS_MON_BINARY_BASE.format(arch="arm64")

        # Update class variable to use the architecture-specific binary
        cls.FS_MON_BINARY = binary_path

        # Check if fsmon exists on the device
        stdout, stderr = Adb.send_adb_command(
            f"shell [ -f {binary_path} ] && echo 'exists' || echo 'notfound'"
        )
        if "exists" in stdout:
            cls.logger.info(f"FSMon binary found on device at {binary_path}")
            return  # fsmon is already installed

        # Otherwise, download fsmon to a temporary directory
        cls.logger.info(f"FSMon binary not found. Downloading {arch} version...")
        with tempfile.TemporaryDirectory() as tmp_dir:
            local_fsmon_path = os.path.join(tmp_dir, f"fsmon-{arch}")
            response = requests.get(binary_url, allow_redirects=True, timeout=30)
            with open(local_fsmon_path, "wb") as f:
                f.write(response.content)

            # Push fsmon to device
            cls.logger.info(f"Copying FSMon binary to device at {binary_path}...")
            Adb.send_adb_command(f"push {local_fsmon_path} {binary_path}")

            # Make fsmon executable
            Adb.send_adb_command(f"shell chmod +x {binary_path}")
            cls.logger.info("FSMon binary installed successfully")

    @classmethod
    def run_fsmon_by_path(cls, path):
        """Starts fsmon in a subprocess via 'adb exec-out', monitoring the specified path.
        Returns the subprocess.Popen object so the caller can terminate it later.

        :param path: The directory/path to monitor with fsmon.
        :type path: str
        :return: A subprocess.Popen object representing the running fsmon process.
        :rtype: subprocess.Popen
        """
        if not path:
            cls.logger.error("Path cannot be empty for path-based monitoring")
            return None

        cmd = ["adb", "exec-out", cls.FS_MON_BINARY, path]
        cls.logger.info(f"Monitoring path: {path}")
        cls.logger.debug(f"Running command: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        return proc

    @classmethod
    def run_fsmon_by_pid(cls, pid, path="/data/"):
        """Starts fsmon in a subprocess via 'adb exec-out', monitoring the specified process ID.
        Returns the subprocess.Popen object so the caller can terminate it later.

        :param pid: The process ID to monitor with fsmon.
        :type pid: int or str
        :return: A subprocess.Popen object representing the running fsmon process.
        :rtype: subprocess.Popen
        """
        if not pid:
            cls.logger.error("PID cannot be empty for process-based monitoring")
            return None

        cmd = ["adb", "exec-out", cls.FS_MON_BINARY, "-p", str(pid), path]
        cls.logger.info(f"Monitoring process with PID: {pid}")
        cls.logger.debug(f"Running command: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        return proc
