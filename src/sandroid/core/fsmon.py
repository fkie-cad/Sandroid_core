import logging
import os
import subprocess
import tempfile

import requests

from .adb import Adb

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None


class FSMon:
    # Default base binary name pattern (kept as fallback)
    _DEFAULT_BINARY_BASE = "/data/local/tmp/fsmon-{arch}"

    # Default URLs for different architectures (kept as fallback)
    _DEFAULT_URLS = {
        "arm64": "https://github.com/nowsecure/fsmon/releases/download/1.8.6/fsmon-android-arm64",
        "arm": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-arm",
        "x86": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86",
        "x86_64": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86_64",
    }

    # Default to arm64 until architecture is detected
    FS_MON_BINARY = "/data/local/tmp/fsmon-arm64"

    # Default monitor path (kept as fallback)
    _DEFAULT_MONITOR_PATH = "/data/"

    # Logger
    logger = logging.getLogger(__name__)

    @classmethod
    def _get_binary_base(cls) -> str:
        """Get FSMon binary base path from config with fallback.

        Returns:
            Binary base path template with {arch} placeholder.
        """
        try:
            if get_config is not None:
                return get_config().device_paths.fsmon_binary_base
        except Exception:
            pass
        return cls._DEFAULT_BINARY_BASE

    @classmethod
    def _get_urls(cls) -> dict[str, str]:
        """Get FSMon download URLs from config with fallback.

        Returns:
            Dict mapping architecture to download URL.
        """
        try:
            if get_config is not None:
                return get_config().external_urls.fsmon_urls
        except Exception:
            pass
        return cls._DEFAULT_URLS

    @classmethod
    def _get_monitor_path(cls) -> str:
        """Get default monitor path from config with fallback.

        Returns:
            Default filesystem path for monitoring.
        """
        try:
            if get_config is not None:
                return get_config().device_paths.default_monitor_path
        except Exception:
            pass
        return cls._DEFAULT_MONITOR_PATH

    @classmethod
    def get_device_architecture(cls):
        """Detects the architecture of the connected Android device using ADB.

        :return: Architecture string (arm64, arm, x86, or x86_64)
        :rtype: str
        """
        stdout, _stderr = Adb.send_adb_command("shell getprop ro.product.cpu.abi")
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
        binary_base = cls._get_binary_base()
        urls = cls._get_urls()
        binary_path = binary_base.format(arch=arch)
        binary_url = urls.get(arch)

        if not binary_url:
            binary_url = urls.get("arm64", cls._DEFAULT_URLS["arm64"])
            binary_path = binary_base.format(arch="arm64")

        # Update class variable to use the architecture-specific binary
        cls.FS_MON_BINARY = binary_path

        # Check if fsmon exists on the device
        stdout, _stderr = Adb.send_adb_command(
            f"shell [ -f {binary_path} ] && echo 'exists' || echo 'notfound'"
        )
        if "exists" in stdout:
            cls.logger.debug(f"FSMon binary found on device at {binary_path}")
            return  # fsmon is already installed

        # Otherwise, download fsmon to a temporary directory
        cls.logger.info(f"FSMon binary not found. Downloading {arch} version...")

        # Get configurable timeout for network downloads
        try:
            if get_config is not None:
                config = get_config()
                download_timeout = config.timeouts.network_download
            else:
                download_timeout = 120  # Default fallback
        except Exception:
            download_timeout = 120  # Fallback if config unavailable

        with tempfile.TemporaryDirectory() as tmp_dir:
            local_fsmon_path = os.path.join(tmp_dir, f"fsmon-{arch}")

            # Download with timeout and proper error handling
            try:
                response = requests.get(
                    binary_url, allow_redirects=True, timeout=download_timeout
                )
                response.raise_for_status()
            except requests.Timeout:
                error_msg = (
                    f"FSMon download timed out after {download_timeout}s -- "
                    "check network or increase timeouts.network_download in sandroid.toml"
                )
                cls.logger.error(error_msg)
                raise RuntimeError(error_msg)
            except requests.RequestException as e:
                error_msg = f"Failed to download FSMon binary from {binary_url}: {e}"
                cls.logger.error(error_msg)
                raise RuntimeError(error_msg) from e

            # Verify we got content
            if not response.content:
                error_msg = f"FSMon download returned empty content from {binary_url}"
                cls.logger.error(error_msg)
                raise RuntimeError(error_msg)

            # Write to local file with error handling
            try:
                with open(local_fsmon_path, "wb") as f:
                    f.write(response.content)
            except OSError as e:
                error_msg = f"Failed to write FSMon binary to {local_fsmon_path}: {e}"
                cls.logger.error(error_msg)
                raise RuntimeError(error_msg) from e

            # Push fsmon to device
            cls.logger.debug(f"Copying FSMon binary to device at {binary_path}...")
            Adb.send_adb_command(f"push {local_fsmon_path} {binary_path}")

            # Make fsmon executable
            Adb.send_adb_command(f"shell chmod +x {binary_path}")
            cls.logger.info("FSMon binary installed successfully")

    @classmethod
    def _build_adb_cmd(cls, *args: str) -> list[str]:
        """Build an ADB command list with optional device targeting.

        Uses Adb.ADB_PATH for the executable and includes -s <serial>
        when a target device is set.

        Args:
            *args: ADB subcommand and arguments.

        Returns:
            Complete command list for subprocess.
        """
        adb_path = Adb.ADB_PATH or "adb"
        cmd = [adb_path]
        serial = Adb.get_target_device()
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(args)
        return cmd

    @classmethod
    def _start_process(cls, cmd):
        """Start an fsmon subprocess with line-buffered stdout.

        :param cmd: Command list for subprocess.Popen.
        :type cmd: list[str]
        :return: A subprocess.Popen object, or None on failure.
        :rtype: subprocess.Popen | None
        """
        cls.logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            return subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as e:
            cls.logger.error(f"Failed to start fsmon process: {e}")
            return None
        except subprocess.SubprocessError as e:
            cls.logger.error(f"Subprocess error starting fsmon: {e}")
            return None

    @classmethod
    def run_fsmon_by_path(cls, path):
        """Starts fsmon in a subprocess via 'adb shell -tt', monitoring the specified path.
        Returns the subprocess.Popen object so the caller can terminate it later.

        :param path: The directory/path to monitor with fsmon.
        :type path: str
        :return: A subprocess.Popen object representing the running fsmon process.
        :rtype: subprocess.Popen
        """
        if not path:
            cls.logger.error("Path cannot be empty for path-based monitoring")
            return None

        cmd = cls._build_adb_cmd("shell", "-tt", cls.FS_MON_BINARY, path)
        cls.logger.debug(f"Monitoring path: {path}")
        return cls._start_process(cmd)

    # Per-device-serial memoization for fanotify_supported(), so switching
    # the active device (the 'D' key) never reuses a stale verdict from a
    # previously-connected device.
    _fanotify_cache: dict[str, bool] = {}

    # TODO: on fanotify-less devices, real per-PID attribution is achievable
    # via kernel tracefs kprobes (do_sys_openat2/do_unlinkat/do_renameat2/
    # do_mkdirat + common_pid filtering via /sys/kernel/tracing/kprobe_events
    # +trace_pipe) -- tested and confirmed viable (kernel-verified
    # attribution, ~single-digit-15% overhead, zero binaries pushed to the
    # device). Would need a new KprobeTracer class (mirroring FSMon's shape)
    # producing the same FSMonEvent shape this module already parses into.
    # strace/ptrace was also tested and rejected as a default (~67x overhead,
    # needs 9 pushed shared-library dependencies) -- worth keeping only as a
    # separate, manually-invoked "deep single-PID capture" tool, never wired
    # into automatic PID-mode.
    @classmethod
    def run_fsmon_by_pid(cls, pid, path=None):
        """Starts fsmon in a subprocess via 'adb shell -tt', monitoring the specified process ID.
        Returns the subprocess.Popen object so the caller can terminate it later.

        :param pid: The process ID to monitor with fsmon.
        :type pid: int or str
        :return: A subprocess.Popen object representing the running fsmon process.
        :rtype: subprocess.Popen
        """
        if not pid:
            cls.logger.error("PID cannot be empty for process-based monitoring")
            return None

        if path is None:
            path = cls._get_monitor_path()
        cmd = cls._build_adb_cmd(
            "shell", "-tt", cls.FS_MON_BINARY, "-B", "fanotify", "-p", str(pid), path
        )
        cls.logger.debug(f"Monitoring process with PID: {pid}")
        return cls._start_process(cmd)

    # Signature fsmon prints near-instantly when the device kernel doesn't
    # support fanotify at all (confirmed empirically against production
    # fsmon builds 1.8.6/1.8.8, which otherwise silently produce wrong data
    # under -p with an inotify backend instead of erroring cleanly).
    _FANOTIFY_UNSUPPORTED_SIGNATURE = "fanotify_init"

    @classmethod
    def fanotify_supported(cls) -> bool:
        """Probe whether the active device's kernel supports fanotify.

        Runs a minimal, one-shot preflight (``fsmon -B fanotify -a 1
        /data/local/tmp``) via ``subprocess.run`` (NOT ``_start_process`` --
        that returns a long-lived streaming ``Popen`` meant for the real
        reader thread, the wrong shape for a one-shot capture-and-check
        probe). On a fanotify-capable device this same command blocks
        waiting for a real filesystem event on the probed (idle) path, so a
        ``subprocess.TimeoutExpired`` is treated as "supported" (no ENOSYS
        signature appeared in the time given -- fanotify itself initialized
        fine, it's just waiting on real activity). Only a clean, fast exit
        containing the ``fanotify_init``/"not implemented" signature is
        treated as "unsupported".

        Memoized per device serial (``Adb.get_target_device()``) rather than
        a bare process-lifetime bool, since Sandroid supports switching the
        active device mid-session (the 'D' key) and a stale verdict from one
        device must not silently apply to another.

        Returns:
            True if fanotify appears supported (or the probe timed out
            without an ENOSYS-style signature), False if the device
            explicitly reported fanotify as unsupported.
        """
        serial = Adb.get_target_device() or ""
        if serial in cls._fanotify_cache:
            return cls._fanotify_cache[serial]

        cmd = cls._build_adb_cmd(
            "shell",
            "-tt",
            cls.FS_MON_BINARY,
            "-B",
            "fanotify",
            "-a",
            "1",
            "/data/local/tmp",
        )
        supported = True
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            combined = ((result.stdout or "") + (result.stderr or "")).lower()
            if (
                cls._FANOTIFY_UNSUPPORTED_SIGNATURE in combined
                or "not implemented" in combined
            ):
                supported = False
            elif (
                not combined.strip()
                or "no such file or directory" in combined
                or "not found" in combined
                or "permission denied" in combined
            ):
                # The probe didn't actually run fsmon at all (binary missing
                # -- e.g. called before check_and_install_fsmon() -- or some
                # other shell-level failure) -- this is inconclusive, not a
                # real fanotify verdict. Caching "supported" here would wrongly
                # poison every later call for this serial (confirmed by a real
                # on-device repro: a stale True cached from a pre-install probe
                # let a real PID-mode session spawn against a device that
                # actually lacks fanotify, dying immediately). Return without
                # memoizing so a later, real probe (after the binary is
                # installed) gets a genuine answer.
                return False
        except subprocess.TimeoutExpired:
            # No ENOSYS-style signature appeared before the timeout fired --
            # fanotify itself initialized fine, it's just blocked waiting for
            # a real filesystem event on the idle probed path (expected,
            # working behavior). subprocess.run()'s own timeout handling
            # already kills the child and waits on it (Popen.communicate()
            # calls process.kill() + process.wait() internally before
            # re-raising TimeoutExpired) -- nothing further to clean up here.
            supported = True
        except (OSError, subprocess.SubprocessError) as e:
            cls.logger.warning(
                f"fanotify_supported probe failed, assuming supported: {e}"
            )
            supported = True

        cls._fanotify_cache[serial] = supported
        return supported
