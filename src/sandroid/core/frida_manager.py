#!/usr/bin/env python3

import logging
import lzma
import os
import re
import shlex
import subprocess
import tempfile

import frida
import requests

from .adb import Adb

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

# some parts are taken from ttps://github.com/Mind0xP/Frida-Python-Binding/


class FridaManager:
    def __init__(
        self,
        logger=None,
        is_remote=False,
        socket="",
        verbose=False,
        frida_install_dst="/data/local/tmp/",
        device_serial=None,
    ):
        """Constructor of the current FridaManager instance

        :param is_remote: The number to multiply.
        :type number: bool
        :param socket: The socket to connect to the remote device. The remote device needs to be set by <ip:port>. By default this string will be empty in order to indicate that FridaManger is working with the first connected USB device.
        :type number: string
        :param verbose: Set the output to verbose, so that the logging information gets printed. By default set to False.
        :type number: bool
        :param frida_install_dst: The path where the frida server should be installed. By default it will be installed to /data/local/tmp/.
        :type number: bool
        :param device_serial: Serial number of the target device for multi-device support.
        :type device_serial: str

        """
        self.is_remote = is_remote
        self.device_socket = socket
        self.verbose = verbose
        self.is_magisk_mode = False
        self.frida_install_dst = frida_install_dst
        self.frida_started_properly = False
        self.logger = logging.getLogger(__name__)
        self.device_serial = device_serial  # For multi-device support

        if self.is_remote:
            frida.get_device_manager().add_remote_device(self.socket)

    def _get_adb_base_cmd(self) -> list:
        """Get the base ADB command with device targeting if set.

        Returns:
            List starting with 'adb' and optionally '-s <serial>'
        """
        if self.device_serial:
            return ["adb", "-s", self.device_serial]
        return ["adb"]

    def run_frida_server(self, frida_server_path="/data/local/tmp/"):
        """This function is used to run the frida server on the connected device.

        :param frida_server_path: The path where the frida server is located.
                                  Default is "/data/local/tmp/".
        :type frida_server_path: str

        :return: True if the frida server started successfully, False otherwise.
        :rtype: bool
        """
        # Check if frida-server is already running
        if self.is_frida_server_running():
            if self.verbose:
                self.logger.debug("[*] frida-server is already running, skipping start")
            return True

        if frida_server_path is self.run_frida_server.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server &"
        else:
            cmd = frida_server_path + "frida-server &"

        # Build command with device targeting
        adb_base = self._get_adb_base_cmd()
        if self.is_magisk_mode:
            shell_cmd = f"su -c 'sh -c \"{cmd}\"'"
        else:
            shell_cmd = f'su 0 sh -c "{cmd}"'

        full_cmd = adb_base + ["shell", shell_cmd]

        try:
            process = subprocess.Popen(
                full_cmd,
                stdin=subprocess.DEVNULL,  # Prevent consuming terminal input
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Give it a moment to start and potentially fail
            import time

            time.sleep(1)

            # Check if process failed immediately
            if process.poll() is not None:
                _stdout, stderr = process.communicate()
                if "Address already in use" in stderr.decode():
                    self.logger.debug(
                        "[*] frida-server is already running on the device"
                    )
                    return True
                self.logger.error(f"Failed to start frida-server: {stderr.decode()}")
                process.kill()
                return False
            # Process is still running (background), which is expected for frida-server
            if self.verbose:
                self.logger.debug("[*] frida-server started successfully in background")

            if self.is_frida_server_running():
                return True
            self.logger.error(
                "frida-server process started but not detected as running"
            )
            return False

        except OSError as e:
            self.logger.error(f"Failed to start frida-server process: {e}")
            return False
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess error starting frida-server: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error starting frida-server: {e}")
            return False

    def _get_device_path(self, field: str, default: str) -> str:
        """Read a device path from config with fallback.

        Args:
            field: Field name on DevicePathsConfig (e.g. 'pidof_binary')
            default: Fallback value if config unavailable

        Returns:
            The configured value or the default.
        """
        try:
            if get_config is not None:
                return getattr(get_config().device_paths, field, default)
        except Exception:
            pass
        return default

    def _get_external_url(self, field: str, default: str) -> str:
        """Read an external URL from config with fallback.

        Args:
            field: Field name on ExternalURLsConfig (e.g. 'frida_releases_url')
            default: Fallback value if config unavailable

        Returns:
            The configured value or the default.
        """
        try:
            if get_config is not None:
                return getattr(get_config().external_urls, field, default)
        except Exception:
            pass
        return default

    def is_frida_server_running(self) -> bool:
        """Checks if on the connected device a frida server is running.

        The test is done by the Android system command pidof and is looking for
        the string frida-server. This method is safe to call on non-rooted devices
        and will return False if the check cannot be performed.

        :return: True if a frida-server is running otherwise False.
        :rtype: bool
        """
        try:
            # Try pidof first (most reliable)
            pidof_binary = self._get_device_path("pidof_binary", "/system/bin/pidof")
            stdout, stderr = Adb.send_adb_command(f"shell {pidof_binary} frida-server")

            if stdout and len(stdout.strip()) > 0:
                # pidof returns PID if process exists
                try:
                    int(stdout.strip().split()[0])  # Validate it's a number
                    return True
                except (ValueError, IndexError):
                    pass

            # Fallback to ps grep if pidof doesn't work
            stdout, stderr = Adb.send_adb_command(
                "shell ps | grep frida-server | grep -v grep"
            )
            if stdout and stdout.strip():
                return True

            # Try alternative ps command format (newer Android versions)
            stdout, _stderr = Adb.send_adb_command(
                "shell ps -A | grep frida-server | grep -v grep"
            )
            if stdout and stdout.strip():
                return True

            return False

        except Exception as e:
            # Log but don't crash - this is a status check, not a critical operation
            self.logger.debug(
                f"Could not check Frida server status: {e}. "
                "This may happen on non-rooted devices."
            )
            return False

    def stop_frida_server(self):
        killall_binary = self._get_device_path("killall_binary", "/system/bin/killall")
        self.run_adb_command_as_root(f"{killall_binary} frida-server")

    def remove_frida_server(self, frida_server_path="/data/local/tmp/"):
        if frida_server_path is self.remove_frida_server.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server"
        else:
            cmd = frida_server_path + "frida-server"

        self.stop_frida_server()
        self._adb_remove_file_if_exist(cmd)

    def install_frida_server(self, dst_dir="/data/local/tmp/", version="latest"):
        """Install the frida server binary on the Android device.
        This includes downloading the frida-server, decompress it and pushing it to the Android device.
        By default it is pushed into the /data/local/tmp/ directory.
        Further the binary will be set to executable in order to run it.

        :param dst_dir: The destination folder where the frida-server binary should be installed (pushed).
        :type number: string
        :param version: The version. By default the latest version will be used.
        :type number: string

        """
        self.logger.info("Installing frida-server now...")
        if dst_dir is self.install_frida_server.__defaults__[0]:
            frida_dir = self.frida_install_dst
        else:
            frida_dir = dst_dir

        with tempfile.TemporaryDirectory() as dir:
            self.logger.info(f"Downloading frida-server to {dir}")
            file_path = self.download_frida_server(dir, version)
            tmp_frida_server = self.extract_frida_server_comp(file_path)
            # ensure's that we always overwrite the current installation with our recent downloaded version
            # TODO: Replace with adb class methods
            self._adb_remove_file_if_exist(frida_dir + "frida-server")
            self._adb_push_file(tmp_frida_server, frida_dir)
            self.make_frida_server_executable()

    # by default the latest frida-server version will be downloaded
    def download_frida_server(self, path, version="latest"):
        """Downloads a frida server. By default the latest version is used.
        If you want to download a specific version you have to provide it trough the version parameter.

        :param path: The path where the compressed frida-server should be downloded.
        :type number: string
        :param version: The version. By default the latest version will be used.
        :type number: string

        :return: The location of the downloaded frida server in its compressed form.
        :rtype: string
        """
        url = self.get_frida_server_for_android_url(version)
        if url is None:
            raise RuntimeError("Failed to get Frida server download URL")

        # Get configurable timeout for Frida server download
        try:
            if get_config is not None:
                config = get_config()
                download_timeout = config.timeouts.frida_download
            else:
                download_timeout = 300  # Default fallback
        except Exception:
            download_timeout = 300  # Fallback if config unavailable

        # Download with timeout, using context manager to close the response
        try:
            with requests.get(
                url, timeout=download_timeout, allow_redirects=True
            ) as res:
                res.raise_for_status()

                content = res.content
                if not content:
                    error_msg = (
                        f"Frida server download returned empty content from {url}"
                    )
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)

                with open(path + "/frida-server", "wb") as fsb:
                    fsb.write(content)
                    if self.verbose:
                        self.logger.debug(f"[*] writing frida-server to {path}")
        except requests.Timeout:
            error_msg = (
                f"Frida server download timed out after {download_timeout}s -- "
                "increase timeouts.frida_download in sandroid.toml"
            )
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        except requests.RequestException as e:
            error_msg = f"Failed to download Frida server from {url}: {e}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e

        return path + "/frida-server"

    def extract_frida_server_comp(self, file_path):
        if self.verbose:
            self.logger.debug(f"[*] extracting {file_path} ...")
        # create a subdir for the specified filename
        frida_server_dir = file_path[:-3]
        try:
            os.makedirs(frida_server_dir)
        except OSError as e:
            self.logger.error(f"Failed to create directory {frida_server_dir}: {e}")
            raise
        try:
            with lzma.open(file_path, "rb") as f:
                decompressed_file = f.read()
        except lzma.LZMAError as e:
            self.logger.error(f"Failed to decompress frida server archive {file_path}: {e}")
            raise
        with open(frida_server_dir + "/frida-server", "wb") as f:
            f.write(decompressed_file)

        # del compressed file
        os.remove(file_path)
        return frida_server_dir + "/frida-server"

    def get_frida_server_for_android_url(self, version):
        arch = self._get_android_device_arch()
        arch_str = "x86"

        if arch == "arm64":
            arch_str = "arm64"
        elif arch == "arm":
            arch_str = "arm"
        elif arch == "ia32":
            arch_str = "x86"
        elif arch == "x64":
            arch_str = "x86_64"
        else:
            arch_str = "x86"

        download_url = self._get_frida_server_donwload_url(arch_str, version)
        return download_url

    def _get_frida_server_donwload_url(self, arch, version):
        frida_download_prefix = self._get_external_url(
            "frida_releases_url", "https://github.com/frida/frida/releases"
        )

        if version == "latest":
            frida_api_url = self._get_external_url(
                "frida_api_url",
                "https://api.github.com/repos/frida/frida/releases/",
            )
            url = frida_api_url + version

            # Get configurable timeout for API calls
            try:
                if get_config is not None:
                    config = get_config()
                    api_timeout = config.timeouts.api_call
                else:
                    api_timeout = 10  # Default fallback
            except Exception:
                api_timeout = 10  # Fallback if config unavailable

            # Make API request with timeout and proper error handling
            try:
                res = requests.get(url, timeout=api_timeout)
                res.raise_for_status()
            except requests.Timeout:
                error_msg = (
                    f"Frida API request timed out after {api_timeout}s -- "
                    "check network or increase timeouts.api_call in sandroid.toml"
                )
                self.logger.error(error_msg)
                return None
            except requests.RequestException as e:
                error_msg = f"Frida API request failed: {e}"
                self.logger.error(error_msg)
                return None

            frida_server_path = re.findall(
                r"\/download\/\d+\.\d+\.\d+\/frida\-server\-\d+\.\d+\.\d+\-android\-"
                + arch
                + ".xz",
                res.text,
            )  #'\.xz'

            if not frida_server_path:
                error_msg = f"Could not find Frida server for architecture {arch} in API response"
                self.logger.error(error_msg)
                return None

            final_url = frida_download_prefix + frida_server_path[0]

        else:
            frida_download_url = self._get_external_url(
                "frida_download_url",
                "https://github.com/frida/frida/releases/download/",
            )
            final_url = (
                frida_download_url
                + version
                + "/frida-server-"
                + version
                + "-android-"
                + arch
                + ".xz"
            )

        if self.verbose:
            print(f"[*] frida-server download url: {final_url}")

        return final_url

    def make_frida_server_executable(self, frida_server_path="/data/tmp/local/tmp/"):
        if frida_server_path is self.make_frida_server_executable.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server"
        else:
            cmd = frida_server_path + "frida-server"

        self.run_adb_command_as_root(f"chmod +x {shlex.quote(cmd)}")

    ### some functions to work with adb ###

    def run_adb_command_as_root(self, command):
        if not self.adb_check_root():
            error_msg = (
                "Non-rooted device. Please root it before using FridaAndroidManager "
                "and ensure that you are able to run commands with the su-binary."
            )
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)

        adb_base = self._get_adb_base_cmd()
        try:
            if self.is_magisk_mode:
                output = subprocess.run(
                    adb_base + ["shell", "su -c " + command],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            else:
                output = subprocess.run(
                    adb_base + ["shell", "su 0 " + command],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            return output
        except OSError as e:
            self.logger.error(f"Failed to start ADB process: {e}")
            return None
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess error running ADB command as root: {e}")
            return None

    def _adb_push_file(self, file, dst):
        adb_base = self._get_adb_base_cmd()
        try:
            output = subprocess.run(
                adb_base + ["push", file, dst],
                check=False,
                capture_output=True,
                text=True,
            )
            return output
        except OSError as e:
            self.logger.error(f"Failed to start ADB push process: {e}")
            return None
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess error pushing file via ADB: {e}")
            return None

    def _adb_pull_file(self, src_file, dst):
        adb_base = self._get_adb_base_cmd()
        try:
            output = subprocess.run(
                adb_base + ["pull", src_file, dst],
                check=False,
                capture_output=True,
                text=True,
            )
            return output
        except OSError as e:
            self.logger.error(f"Failed to start ADB pull process: {e}")
            return None
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess error pulling file via ADB: {e}")
            return None

    def _get_android_device_arch(self):
        if self.is_remote:
            frida_usb_json_data = frida.get_remote_device().query_system_parameters()
        elif self.device_serial:
            # Use specific device by serial for multi-device support
            device = frida.get_device(self.device_serial)
            frida_usb_json_data = device.query_system_parameters()
        else:
            frida_usb_json_data = frida.get_usb_device().query_system_parameters()
        return frida_usb_json_data["arch"]

    def _adb_make_binary_executable(self, path):
        output = self.run_adb_command_as_root("chmod +x " + shlex.quote(path))

    def _adb_does_file_exist(self, path):
        output = self.run_adb_command_as_root("ls " + shlex.quote(path))
        if output is None:
            return False
        if len(output.stderr) > 1:
            return False
        return True

    def adb_check_root(self):
        adb_base = self._get_adb_base_cmd()
        try:
            result = subprocess.run(
                adb_base + ["shell", "su -v"],
                check=False,
                capture_output=True,
                text=True,
            )
            if bool(result.stdout):
                self.is_magisk_mode = True
                return True

            result = subprocess.run(
                adb_base + ["shell", "su 0 id -u"],
                check=False,
                capture_output=True,
                text=True,
            )
            return bool(result.stdout)
        except OSError as e:
            self.logger.error(f"Failed to start ADB process for root check: {e}")
            return False
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess error checking root access: {e}")
            return False

    def _adb_remove_file_if_exist(self, path="/data/local/tmp/frida-server"):
        output = self.run_adb_command_as_root("rm -f " + shlex.quote(path))
