"""Android Debug Bridge (ADB) interface.

This module provides the :class:`Adb` class which is the single entry-point
for all ADB operations.  The actual logic is split across focused modules:

- :mod:`adb_queries`   -- device property queries (``getprop``, date, etc.)
- :mod:`adb_packages`  -- APK install / uninstall / package listing
- :mod:`adb_process`   -- PID lookup with multiple fallback strategies
- :mod:`adb_emulator`  -- emulator telnet commands (geo, sensors, snapshots, network)
- :mod:`adb_dumpsys`   -- ``dumpsys activity`` parsing (services, activity stack)
- :mod:`adb_network`   -- ``/proc/net/tcp[6]`` connection listing
- :mod:`adb_utils`     -- error handling & stderr filtering

All public methods remain accessible on the ``Adb`` class so that callers
do not need any changes.
"""

import functools
import re
import shlex
import shutil
import subprocess
from logging import getLogger
from typing import Any

# Import delegation modules
from sandroid.core import adb_dumpsys as _dumpsys
from sandroid.core import adb_emulator as _emu
from sandroid.core import adb_network as _net
from sandroid.core import adb_packages as _pkg
from sandroid.core import adb_process as _proc
from sandroid.core import adb_queries as _qry
from sandroid.core.adb_utils import is_adb_error_actionable, log_adb_result

PIPE = subprocess.PIPE

logger = getLogger(__name__)


class Adb:
    """Represents the Android Debug Bridge (ADB) functionality.

    **Attributes:**
        ADB_PATH (str): Path to the ADB executable.
        _target_device (str): Serial number of the target device for multi-device support.
        logger (Logger): Logger instance for ADB operations.
    """

    ADB_PATH = None
    _target_device: str | None = None

    # ------------------------------------------------------------------
    # Device targeting
    # ------------------------------------------------------------------

    @classmethod
    def set_target_device(cls, serial: str | None) -> None:
        """Set the target device for all ADB commands.

        When a target device is set, all ADB commands will include the -s flag
        to target that specific device.

        Args:
            serial: Device serial number, or None to clear targeting
        """
        cls._target_device = serial
        if serial:
            logger.debug(f"ADB targeting device: {serial}")
        else:
            logger.debug("ADB device targeting cleared")

    @classmethod
    def get_target_device(cls) -> str | None:
        """Get the current target device serial.

        Returns:
            The target device serial, or None if not set
        """
        return cls._target_device

    @classmethod
    def _build_command(cls, command: str, serial: str | None = None) -> str:
        """Build an ADB command with optional device targeting.

        If a target device is set, prepends -s <serial> to the command.

        Args:
            command: The ADB command to build
            serial: Device serial to target for this call only, overriding
                the shared ``_target_device`` global without mutating it.
                Falls back to ``_target_device`` when ``None`` (default).

        Returns:
            The command with device targeting if applicable
        """
        target = serial if serial is not None else cls._target_device
        if target:
            return f"-s {target} {command}"
        return command

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Core ADB communication
    # ------------------------------------------------------------------

    @classmethod
    def send_adb_command(
        cls, command: str, serial: str | None = None
    ) -> tuple[str, str]:
        """Send an ADB command and return the output.

        If a target device is set via set_target_device(), the command will
        automatically include the -s flag to target that device.

        Args:
            command: The ADB command to be executed.
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            A tuple containing (stdout, stderr) from the command execution.

        Raises:
            OSError: If the ADB process fails to start.
            subprocess.SubprocessError: If there is a subprocess error during execution.
        """
        # Ensure ADB path is initialized
        if not cls.ADB_PATH:
            cls.init()

        full_command = cls._build_command(command, serial=serial)
        logger.debug("Running ADB command " + full_command)
        try:
            output = subprocess.run(
                [cls.ADB_PATH + " " + full_command],
                check=False,
                capture_output=True,
                text=True,
                shell=True,
                timeout=30,  # 30 second timeout to prevent hangs
            )
            log_adb_result(full_command, output.stdout, output.stderr)
            return output.stdout, output.stderr.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"ADB command timed out: {full_command}")
            return "", "Command timed out after 30 seconds"
        except OSError as e:
            logger.error(f"Failed to start ADB process: {e}")
            return "", f"OSError: {e}"
        except subprocess.SubprocessError as e:
            logger.error(f"ADB subprocess error: {e}")
            return "", f"SubprocessError: {e}"

    @classmethod
    def send_adb_command_popen(
        cls, command: str, serial: str | None = None
    ) -> subprocess.Popen:
        """Execute an ADB command using subprocess.Popen for streaming output.

        Use this method when you need to process output as it arrives, or when
        the command produces large output that should not be buffered entirely.
        If a target device is set via set_target_device(), the command will
        automatically include the -s flag to target that device.

        Args:
            command: The ADB command to be executed.
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            A Popen object representing the running process with stdout and stderr pipes.

        Raises:
            OSError: If the ADB process fails to start.
            subprocess.SubprocessError: If there is a subprocess error during execution.
        """
        full_command = cls._build_command(command, serial=serial)
        logger.debug("Running ADB command " + full_command)
        try:
            process = subprocess.Popen(
                [cls.ADB_PATH + " " + full_command],
                stdout=PIPE,
                stdin=subprocess.DEVNULL,  # Changed from PIPE - ADB doesn't need stdin
                stderr=PIPE,
                shell=True,
            )
            return process
        except OSError as e:
            logger.error(f"Failed to start ADB Popen process: {e}")
            raise
        except subprocess.SubprocessError as e:
            logger.error(f"ADB Popen subprocess error: {e}")
            raise

    @classmethod
    def send_adb_exec_out_command(cls, command: str) -> tuple[str, str]:
        """Send an ADB exec-out command and return the output.

        The exec-out command runs a shell command on the device and returns
        the raw output without line-ending conversion, which is useful for
        binary data or when exact output preservation is needed.

        If a target device is set via set_target_device(), the command will
        automatically include the -s flag to target that device.

        Args:
            command: The shell command to execute (without 'exec-out' prefix).

        Returns:
            A tuple containing (stdout, stderr) from the command execution.

        Raises:
            OSError: If the ADB process fails to start.
            subprocess.SubprocessError: If there is a subprocess error during execution.
        """
        full_command = cls._build_command(f"exec-out {command}")
        logger.debug("Running ADB command " + full_command)
        try:
            output = subprocess.run(
                [cls.ADB_PATH + " " + full_command],
                check=False,
                capture_output=True,
                text=True,
                shell=True,
            )
            return output.stdout, output.stderr.strip()
        except OSError as e:
            logger.error(f"Failed to start ADB exec-out process: {e}")
            return "", f"OSError: {e}"
        except subprocess.SubprocessError as e:
            logger.error(f"ADB exec-out subprocess error: {e}")
            return "", f"SubprocessError: {e}"

    @classmethod
    def send_root_shell(cls, command: str) -> tuple[str, str]:
        """Run a shell command as root using ``su`` on the device.

        Executes ``adb shell su 0 <command>`` to run the given command
        with root privileges.

        Args:
            command: The shell command to execute as root.

        Returns:
            A tuple of (stdout, stderr) from the ADB command.
        """
        logger.debug(f"Executing root shell command: {command}")
        stdout, stderr = cls.send_adb_command(f"shell su 0 {command}")

        if stderr:
            logger.error(f"Root shell command failed: {stderr}")

        return stdout, stderr

    # ------------------------------------------------------------------
    # Port reversing (host port reachable from the device at 127.0.0.1)
    # ------------------------------------------------------------------

    @classmethod
    def reverse(cls, remote: str, local: str) -> tuple[str, str]:
        """Forward a device-side socket spec to a host-side one (``adb reverse``).

        ``adb reverse <remote> <local>`` makes connections the device opens to
        ``<remote>`` (e.g. ``tcp:8080`` on the device's ``127.0.0.1``) land on
        the host's ``<local>`` socket. This is transport-independent of the
        device's network, so it reaches the host even when the auto-detected
        host LAN IP is unreachable (e.g. on a physical device over USB).

        Args:
            remote: Device-side spec, e.g. ``"tcp:8080"``.
            local: Host-side spec, e.g. ``"tcp:8080"``.

        Returns:
            A tuple of (stdout, stderr) from the ADB command.
        """
        return cls.send_adb_command(f"reverse {remote} {local}")

    @classmethod
    def reverse_remove(cls, remote: str) -> tuple[str, str]:
        """Remove a single reverse binding (per-port, never ``--remove-all``).

        Args:
            remote: Device-side spec to remove, e.g. ``"tcp:8080"``.

        Returns:
            A tuple of (stdout, stderr) from the ADB command.
        """
        return cls.send_adb_command(f"reverse --remove {remote}")

    @classmethod
    def reverse_list(cls) -> tuple[str, str]:
        """List active reverse bindings (``adb reverse --list``).

        Live output carries a transport-id prefix per line, e.g.
        ``host-16 tcp:8080 tcp:8080`` — callers must match by substring, never
        exact-line equality.

        Returns:
            A tuple of (stdout, stderr) from the ADB command.
        """
        return cls.send_adb_command("reverse --list")

    # ------------------------------------------------------------------
    # Delegated: Device property queries  (adb_queries)
    # ------------------------------------------------------------------

    @classmethod
    def _getprop(cls, prop_name: str) -> str | None:
        """Get a system property value via getprop.

        Args:
            prop_name: The property name (e.g., 'ro.product.model').

        Returns:
            The property value, or None if an error occurs.
        """
        return _qry._getprop(cls.send_adb_command, prop_name)

    @classmethod
    def get_device_model(cls) -> str | None:
        """Retrieve the device model name.

        Queries the 'ro.product.model' system property.

        Returns:
            The device model as a string (e.g., 'Pixel 6 Pro', 'SM-G998B'),
            or None if an error occurs.
        """
        return _qry.get_device_model(cls.send_adb_command)

    @classmethod
    def get_device_brand(cls) -> str | None:
        """Retrieve the device brand name.

        Queries the 'ro.product.brand' system property.

        Returns:
            The device brand as a string (e.g., 'google', 'samsung'),
            or None if an error occurs.
        """
        return _qry.get_device_brand(cls.send_adb_command)

    @classmethod
    def get_device_locale(cls) -> str | None:
        """Retrieve the locale setting of the connected device.

        Queries the 'ro.product.locale' system property.

        Returns:
            The device locale as a string (e.g., 'en-US', 'de-DE'),
            or None if an error occurs or the property is not set.
        """
        return _qry.get_device_locale(cls.send_adb_command)

    @classmethod
    def get_android_version_and_api_level(
        cls, serial: str | None = None
    ) -> dict[str, str | None] | None:
        """Retrieve the Android version and API level of the connected device.

        Queries the 'ro.build.version.release' and 'ro.build.version.sdk'
        system properties.

        Args:
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            A dictionary containing:
                - 'android_version': The Android version string (e.g., '14', '13')
                - 'api_level': The API level as a string (e.g., '34', '33')
            Returns None if an error occurs while querying the properties.
        """
        send_command = (
            functools.partial(cls.send_adb_command, serial=serial)
            if serial is not None
            else cls.send_adb_command
        )
        return _qry.get_android_version_and_api_level(send_command)

    @classmethod
    def get_device_time(cls) -> str | None:
        """Retrieve the current date and time from the connected device.

        Executes the 'date' command on the device to get the current
        system time as configured on the device.

        Returns:
            The current date and time as a formatted string
            (e.g., 'Fri Jan 16 12:34:56 UTC 2026'),
            or None if an error occurs.
        """
        return _qry.get_device_time(cls.send_adb_command)

    @classmethod
    def get_selinux_status(cls) -> str | None:
        """Retrieve the device's SELinux enforcement mode.

        Queries via ``getenforce``.

        Returns:
            The raw trimmed status string (e.g. ``'Enforcing'``,
            ``'Permissive'``), or None if an error occurs.
        """
        return _qry.get_selinux_status(cls.send_adb_command)

    # ------------------------------------------------------------------
    # Delegated: Package management  (adb_packages)
    # ------------------------------------------------------------------

    @classmethod
    def install_apk(cls, apk_path: str) -> str | None:
        """Install an APK file on the device and return the package name.

        Installs the APK using the -r flag to allow replacement of existing
        installations. After installation, attempts to extract the package name
        using aapt (either from PATH or from the Android SDK build-tools).

        Args:
            apk_path: The file system path to the APK file to install.

        Returns:
            The package name of the installed APK, or None if the package name
            could not be determined.

        Raises:
            APKInstallError: If the APK installation fails due to compatibility
                issues, missing signatures, or other installation errors.
        """
        return _pkg.install_apk(cls.send_adb_command, apk_path)

    @classmethod
    def uninstall_apk(cls, package_name: str) -> bool:
        """Uninstall a package from the device.

        Checks if the package is installed before attempting uninstallation.
        Returns True if the package was successfully uninstalled or was not
        installed in the first place.

        Args:
            package_name: The fully qualified package name to uninstall
                (e.g., 'com.example.app').

        Returns:
            True if the package was successfully uninstalled or was not installed,
            False if an error occurred during uninstallation.
        """
        return _pkg.uninstall_apk(cls.send_adb_command, package_name)

    @staticmethod
    def _find_aapt_paths() -> list[str]:
        """Find all candidate aapt executable paths.

        Checks PATH first, then falls back to Android SDK build-tools.

        Returns:
            List of candidate aapt paths to try.
        """
        return _pkg.find_aapt_paths()

    @staticmethod
    def _extract_package_name_with_aapt(aapt_path: str, apk_path: str) -> str | None:
        """Extract package name from an APK using a specific aapt binary.

        Args:
            aapt_path: Path to the aapt executable.
            apk_path: Path to the APK file.

        Returns:
            The package name if extraction succeeds, None otherwise.
        """
        return _pkg.extract_package_name_with_aapt(aapt_path, apk_path)

    @classmethod
    def _is_package_installed(cls, package_name: str) -> bool:
        """Check if a package is installed on the device.

        Uses 'pm path' which returns the APK path if installed, empty if not.
        This is more reliable than 'pm list packages' which does substring matching.

        Args:
            package_name: Package name to check

        Returns:
            True if package is installed, False otherwise
        """
        return _pkg.is_package_installed(cls.send_adb_command, package_name)

    @classmethod
    def get_installed_packages(
        cls, user_only: bool = False
    ) -> list[dict[str, str | bool | None]]:
        """Get a list of installed packages along with their installation dates.

        Queries the package manager to get installed packages and retrieves
        the first install time for each package via dumpsys.

        Args:
            user_only: If True, only return user-installed (third-party) apps,
                excluding system apps (default: False).

        Returns:
            A list of dictionaries, each containing:
                - 'package_name': The fully qualified package name
                - 'install_date': The first installation timestamp or None
                - 'is_user_app': Boolean indicating if it's a user-installed app
        """
        return _pkg.get_installed_packages(cls.send_adb_command, user_only)

    @classmethod
    def get_focused_app(
        cls, max_retries: int = 3, retry_delay: float = 0.2
    ) -> tuple[str | None, str | None]:
        """Retrieve the package name and activity name of the currently focused app.

        Queries the window manager via 'dumpsys window' to determine which app
        currently has focus. Validates that the app is actually installed on
        the device before returning, preventing stale window manager data from
        returning non-existent apps.

        Uses retry logic to handle transient failures when the window manager
        data is temporarily unavailable or inconsistent.

        Args:
            max_retries: Maximum number of retry attempts (default: 3).
            retry_delay: Delay in seconds between retry attempts (default: 0.2).

        Returns:
            A tuple containing (package_name, activity_name) of the focused app,
            or (None, None) if no valid focused app is found after all retries.
        """
        return _pkg.get_focused_app(cls.send_adb_command, max_retries, retry_delay)

    @classmethod
    def launch_app(
        cls, package_name: str, activity_name: str | None = None
    ) -> tuple[bool, str]:
        """Launch an app on the device.

        Uses ``am start -n <package>/<activity>`` when an activity is known,
        otherwise falls back to the monkey launcher intent.

        Args:
            package_name: The package to launch (e.g. ``com.example.app``).
            activity_name: Optional launchable activity. May be a short
                (``.MainActivity``) or fully-qualified name.

        Returns:
            Tuple of (success, message).
        """
        if activity_name:
            component = f"{package_name}/{activity_name}"
            stdout, stderr = cls.send_adb_command(f"shell am start -n {component}")
        else:
            stdout, stderr = cls.send_adb_command(
                f"shell monkey -p {package_name} "
                "-c android.intent.category.LAUNCHER 1"
            )

        combined = f"{stdout or ''}\n{stderr or ''}".strip()
        lc = combined.lower()
        if (
            "error" in lc
            or "exception" in lc
            or "does not exist" in lc
            or "no activities found" in lc
        ):
            logger.warning(f"launch_app failed for {package_name}: {combined}")
            return False, combined or "launch failed"
        return True, f"Launched {package_name}"

    @classmethod
    def force_stop(cls, package_name: str) -> tuple[bool, str]:
        """Force-stop a running app via ``am force-stop``.

        Used by the spotlight Kill/Restart actions to tear the target app
        down before respawning it with hooks. ``am force-stop`` is a no-op if
        the app is not running, so this is safe to call unconditionally.

        Args:
            package_name: The package to stop (e.g. ``com.example.app``).

        Returns:
            Tuple of (success, message).
        """
        stdout, stderr = cls.send_adb_command(f"shell am force-stop {package_name}")
        combined = f"{stdout or ''}\n{stderr or ''}".strip()
        lc = combined.lower()
        if "error" in lc or "exception" in lc:
            logger.warning(f"force_stop failed for {package_name}: {combined}")
            return False, combined or "force-stop failed"
        return True, f"Force-stopped {package_name}"

    @classmethod
    def push_file(cls, local_path: str, remote_path: str) -> tuple[bool, str]:
        """Push a local file to the device via ``adb push``.

        Generic host-to-device file transfer primitive -- unlike the
        frida-server/CA-cert/fsmon-binary pushes elsewhere in this codebase,
        this one is not scoped to a specific file kind. ``push`` is an
        adb-level verb (not a ``shell`` command), so it is run directly.

        Args:
            local_path: Path to the file on the host.
            remote_path: Destination path on the device.

        Returns:
            Tuple of (success, message).
        """
        stdout, stderr = cls.send_adb_command(
            f"push {shlex.quote(local_path)} {shlex.quote(remote_path)}"
        )
        combined = f"{stdout or ''}\n{stderr or ''}".strip()
        lc = combined.lower()
        if (
            "error" in lc
            or "no such file" in lc
            or "failed to copy" in lc
            or "permission denied" in lc
        ):
            logger.warning(
                f"push_file failed for {local_path} -> {remote_path}: {combined}"
            )
            return False, combined or "push failed"
        return True, f"Pushed {local_path} to {remote_path}"

    # ------------------------------------------------------------------
    # Delegated: Process identification  (adb_process)
    # ------------------------------------------------------------------

    @classmethod
    def get_pid_for_package_name(
        cls,
        package_name: str,
        use_frida_fallback: bool = True,
        quiet: bool = False,
    ) -> int | None:
        """Get the process ID (PID) for a given package name.

        Tries multiple methods in order of preference:
        1. pidof command - Fast and standard on most Android versions
        2. ps -A command - More compatible across Android versions
        3. ps -o PID,NAME - Alternative format for some Android versions
        4. Frida enumerate_processes - Last resort, requires Frida to be available

        Args:
            package_name: The fully qualified package name (e.g., 'com.example.app').
            use_frida_fallback: When True (default), try Frida's
                enumerate_processes if the ADB strategies fail. Set False for
                hot paths (periodic polls) where the Frida round-trip is too
                heavy.
            quiet: When True, log a final miss at debug instead of warning —
                for paths where "not running" is an expected outcome (e.g. the
                running-state poll on a stopped app).

        Returns:
            The process ID if the app is running and found, None otherwise.
        """
        return _proc.get_pid_for_package_name(
            cls.send_adb_command,
            package_name,
            use_frida_fallback=use_frida_fallback,
            quiet=quiet,
        )

    @classmethod
    def list_processes(
        cls, package_filter: str | None = None
    ) -> list[dict[str, str | int]]:
        """List running processes on the device via ``ps -A``.

        Args:
            package_filter: Optional substring to match against each
                process name. Omit to list every running process.

        Returns:
            A list of dicts, each with keys ``'pid'`` (int), ``'user'``
            (str), and ``'name'`` (str).
        """
        return _proc.list_processes(cls.send_adb_command, package_filter)

    @classmethod
    def get_process_detail(cls, pid: int) -> dict[str, Any] | None:
        """Get detailed process info from ``/proc/<pid>``.

        Args:
            pid: The process ID to inspect.

        Returns:
            A dict with process status fields (name, state, ppid, threads,
            uid, memory, fd/map counts), or None if the process is gone or
            unreadable.
        """
        return _proc.get_process_detail(cls.send_adb_command, pid)

    @classmethod
    def kill_pid(cls, pid: int, signal: str = "TERM") -> tuple[bool, bool]:
        """Send a signal to a process, retrying as root if it doesn't die.

        Args:
            pid: The target process ID. Coerced with ``int()``.
            signal: Signal name to send -- one of ``'TERM'``, ``'KILL'``,
                ``'HUP'``, ``'INT'``.

        Returns:
            A tuple of ``(killed, used_root)``.

        Raises:
            ValueError: *pid* is not coercible to ``int``, or *signal* is
                not one of the allowed values.
        """
        return _proc.kill_pid(cls.send_adb_command, cls.send_root_shell, pid, signal)

    # ------------------------------------------------------------------
    # Delegated: Dumpsys queries  (adb_dumpsys)
    # ------------------------------------------------------------------

    @classmethod
    def list_services(cls, package_name: str | None = None) -> list[dict[str, Any]]:
        """List running Android services via ``dumpsys activity services``.

        Args:
            package_name: Optional package to filter to. Omit to list every
                running service device-wide.

        Returns:
            A list of parsed service-record dicts.
        """
        return _dumpsys.list_services(cls.send_adb_command, package_name)

    @classmethod
    def get_activity_stack(cls) -> list[dict[str, Any]]:
        """Get the device's activity task stack.

        Queries via ``dumpsys activity activities``.

        Returns:
            A list of task dicts, each containing its activities.
        """
        return _dumpsys.get_activity_stack(cls.send_adb_command)

    # ------------------------------------------------------------------
    # Delegated: Network queries  (adb_network)
    # ------------------------------------------------------------------

    @classmethod
    def list_connections(cls) -> list[dict[str, Any]]:
        """List TCP sockets via ``/proc/net/tcp`` and ``/proc/net/tcp6``.

        Returns:
            A list of connection dicts (protocol, local/remote
            address+port, state, uid, and cross-referenced package_name).
        """
        return _net.list_connections(cls.send_adb_command)

    # ------------------------------------------------------------------
    # Delegated: Emulator operations  (adb_emulator)
    # ------------------------------------------------------------------

    @classmethod
    def send_telnet_command(
        cls, command: str | bytes, serial: str | None = None
    ) -> tuple[str, str]:
        """Send a telnet command to the Android emulator console.

        Uses ADB's 'emu' command to send telnet commands to the emulator console.
        This allows control of emulator features like network simulation, GPS,
        and snapshot management.

        Args:
            command: The telnet command to be executed. Can be a string or bytes;
                bytes will be decoded to UTF-8.
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            A tuple containing (stdout, stderr) from the command execution.
        """
        send_command = (
            functools.partial(cls.send_adb_command, serial=serial)
            if serial is not None
            else cls.send_adb_command
        )
        return _emu.send_telnet_command(send_command, command)

    @classmethod
    def _get_avd_property(
        cls, avd_command: str, label: str, serial: str | None = None
    ) -> str | None:
        """Query an AVD property via the telnet console.

        Sends the given ``avd`` sub-command and returns the first line of
        output, which is how the emulator reports scalar AVD properties.

        Args:
            avd_command: The telnet sub-command (e.g., ``"avd name"``).
            label: Human-readable label for error messages.
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            The property value, or None if it cannot be determined.
        """
        send_telnet = functools.partial(cls.send_telnet_command, serial=serial)
        return _emu._get_avd_property(send_telnet, avd_command, label)

    @classmethod
    def get_current_avd_name(cls, serial: str | None = None) -> str | None:
        """Get the name of the currently running Android Virtual Device (AVD).

        Args:
            serial: Device serial to target for this call only, without
                mutating the shared ``_target_device`` global. Omit to use
                the current global target (default behavior, unchanged).

        Returns:
            The name of the current AVD (e.g., 'Pixel_6_API_34'),
            or None if it cannot be determined.
        """
        send_telnet = functools.partial(cls.send_telnet_command, serial=serial)
        return _emu.get_current_avd_name(send_telnet)

    @classmethod
    def get_current_avd_path(cls) -> str | None:
        """Get the file system path of the currently running AVD.

        Returns:
            The file system path to the AVD directory (e.g., '/path/to/avd.avd'),
            or None if it cannot be determined.
        """
        return _emu.get_current_avd_path(cls.send_telnet_command)

    @classmethod
    def get_avd_snapshots(cls) -> list[dict[str, str]]:
        """Get a list of snapshots for the currently running AVD.

        Uses the telnet console command 'avd snapshot list' to retrieve
        all saved snapshots for the current emulator instance.

        Returns:
            A list of dictionaries, each containing:
                - 'id': The snapshot ID
                - 'tag': The snapshot tag/name
                - 'size': The VM memory size (e.g., '69M')
                - 'date': The creation date and time
                - 'clock': The VM clock value at snapshot time
        """
        return _emu.get_avd_snapshots(cls.send_telnet_command)

    @classmethod
    def set_geo_fix(cls, lon: float, lat: float) -> tuple[str, str]:
        """Set GPS coordinates on the emulator via telnet.

        Sends a ``geo fix`` command to the emulator console.  The emulator
        expects **longitude first**, then latitude.

        Args:
            lon: Longitude value (e.g., 11.5820).
            lat: Latitude value (e.g., 48.1351).

        Returns:
            A tuple of (stdout, stderr) from the telnet command.
        """
        return _emu.set_geo_fix(cls.send_telnet_command, lon, lat)

    @classmethod
    def set_sensor_value(cls, sensor: str, values: str) -> tuple[str, str]:
        """Set a sensor value on the emulator via telnet.

        Sends a ``sensor set`` command to the emulator console to update
        the specified sensor with the given values.

        Args:
            sensor: The sensor name (e.g., 'acceleration', 'gyroscope').
            values: The sensor values as a colon-separated string
                (e.g., '0:9.8:0').

        Returns:
            A tuple of (stdout, stderr) from the telnet command.
        """
        return _emu.set_sensor_value(cls.send_telnet_command, sensor, values)

    @classmethod
    def get_geo_location(cls) -> dict | None:
        """Retrieve the last known geo location from the device.

        Parses the output of 'dumpsys location' to find the last known
        location coordinates, provider, and accuracy.

        Returns:
            Dictionary with keys 'latitude', 'longitude', 'provider',
            and 'accuracy', or None if location is unavailable.
        """
        return _emu.get_geo_location(cls.send_adb_command)

    @classmethod
    def get_network_info(cls) -> list[tuple[str, str]]:
        """Get network interface information from the device.

        Parses the output of 'ifconfig' to extract network interface names
        and their corresponding IPv4 addresses.

        Returns:
            A list of tuples where each tuple contains (interface_name, ipv4_address).
            For example: [('wlan0', '192.168.1.100'), ('lo', '127.0.0.1')].
        """
        return _emu.get_network_info(cls.send_adb_command)

    @classmethod
    def start_network_capture(cls, filename: str) -> bool:
        """Start capturing network packets from the emulator to a file.

        Uses the emulator telnet console to start packet capture. The capture
        file will be saved on the host machine at the specified path.

        Args:
            filename: The file path where the network capture (pcap) will be saved.

        Returns:
            True if capture started successfully, False otherwise.
        """
        return _emu.start_network_capture(cls.send_telnet_command, filename)

    @classmethod
    def stop_network_capture(cls) -> bool:
        """Stop the currently running network capture.

        Sends a stop command to the emulator telnet console to end the
        active packet capture session.

        Returns:
            True if capture stopped successfully, False otherwise.
        """
        return _emu.stop_network_capture(cls.send_telnet_command)
