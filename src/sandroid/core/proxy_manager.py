"""Proxy and CA Certificate management for Sandroid.

This module provides TUI-agnostic business logic for:
- HTTP proxy configuration via ADB
- CA certificate detection and management
- Zygote CA injection for system-wide SSL interception
"""

import atexit
import hashlib
import io
import logging
import os
import re
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import requests

from sandroid.core.adb import Adb

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


def _is_emulator() -> bool:
    """Whether the current target device is an Android emulator.

    True when the ADB serial starts with ``emulator-`` or the device reports
    ``ro.boot.qemu == 1``. Shared by both proxy paths so the device proxy and
    app proxies resolve the host IP the same way.
    """
    serial = Adb.get_target_device()
    if serial and serial.startswith("emulator-"):
        return True
    try:
        out, _ = Adb.send_adb_command("shell getprop ro.boot.qemu")
        if (out or "").strip() == "1":
            return True
    except Exception:
        pass
    return False


def resolve_proxy_host_ip() -> str:
    """Host IP the device should route proxy traffic to (emulator-aware).

    One resolver shared by the Device Proxy and the App Proxies so they never
    disagree on where the host is:

    * ``focus.host_ip_override`` wins (one knob, no new config key);
    * else ``10.0.2.2`` on an emulator (the SLIRP loopback alias);
    * else the auto-detected host LAN IP (``ProxyManager.get_host_ip()``).

    NOTE: this is the *reachability* IP. ``device_info.get_host_ip()`` stays the
    display IP for system_info and is intentionally left unchanged.
    """
    try:
        if get_config is not None:
            override = (get_config().focus.host_ip_override or "").strip()
            if override:
                return override
    except Exception:
        pass
    if _is_emulator():
        return "10.0.2.2"
    return ProxyManager.get_host_ip()


def _reverse_registered(proxy_port: int) -> bool:
    """Whether an ``adb reverse tcp:<proxy_port> tcp:<proxy_port>`` is active.

    Live ``adb reverse --list`` output carries a transport-id prefix per line
    (e.g. ``host-16 tcp:8080 tcp:8080``), so match by SUBSTRING, never exact
    line. Best-effort: any error reads as "not registered".
    """
    needle = f"tcp:{proxy_port} tcp:{proxy_port}"
    try:
        out, _ = Adb.reverse_list()
    except Exception:
        return False
    return needle in (out or "")


def classify_device_proxy(cfg_ip: str, cfg_port: int, proxy_port: int) -> str:
    """Classify a device http_proxy as ``"ours"`` / ``"other"``.

    The single shared rule used by every "is this our proxy?" call site (the
    panel's three classifiers and ``MitmproxyService.capture_view``) so they
    never disagree:

    * port must equal our ``proxy_port``; AND
    * ``cfg_ip`` is the resolved host IP (emulator-aware), OR ``127.0.0.1``
      *only when* an ``adb reverse tcp:<proxy_port>`` binding is registered
      (our circumvention tunnel). A loopback proxy without that binding is a
      foreign proxy, not ours.

    Returns ``"ours"`` or ``"other"`` (callers handle the ``"none"`` /
    unset case before calling).
    """
    if cfg_port != proxy_port:
        return "other"
    if cfg_ip == resolve_proxy_host_ip():
        return "ours"
    if cfg_ip == "127.0.0.1" and _reverse_registered(proxy_port):
        return "ours"
    return "other"


class ProxyStatus(Enum):
    """Status of the HTTP proxy configuration."""

    NOT_SET = "not_set"
    SET = "set"
    ERROR = "error"


class CASource(Enum):
    """Source of CA certificate."""

    MITMPROXY = "mitmproxy"
    HTTP_TOOLKIT = "http_toolkit"
    BURP_SUITE = "burp_suite"
    CUSTOM = "custom"


@dataclass
class ProxyConfig:
    """Proxy configuration settings."""

    ip: str
    port: int

    @property
    def address(self) -> str:
        """Return the full proxy address."""
        return f"{self.ip}:{self.port}"

    @classmethod
    def from_string(cls, address: str) -> "ProxyConfig":
        """Parse a proxy address string (e.g., '192.168.1.1:8080')."""
        try:
            ip, port_str = address.rsplit(":", 1)
            return cls(ip=ip, port=int(port_str))
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid proxy address format: {address}")


@dataclass
class CAInfo:
    """Information about a CA certificate file."""

    source: CASource
    path: Path
    display_name: str

    @property
    def exists(self) -> bool:
        """Check if the certificate file exists."""
        return self.path.exists()


@dataclass
class ZygoteStatus:
    """Status of Zygote CA injection."""

    injected: bool
    cert_hash: str | None
    zygote64_pid: int | None
    zygote_pid: int | None
    error_message: str | None = None


class InjectionStrategy(Enum):
    """Strategy for CA injection based on Android version."""

    LEGACY = "legacy"
    BIND_MOUNT = "bind_mount"


@dataclass
class InjectionResult:
    """Result of a CA injection attempt."""

    success: bool
    message: str
    strategy: InjectionStrategy | None = None
    api_level: int | None = None
    needs_root: bool = False


class ProxyManager:
    """Manages HTTP proxy configuration for Android devices via ADB."""

    def __init__(self, adb: Adb | None = None):
        """Initialize ProxyManager.

        Args:
            adb: Optional Adb instance. If not provided, creates a new one.
        """
        self._adb = adb

    @property
    def adb(self) -> Adb:
        """Get ADB wrapper, creating if needed."""
        if self._adb is None:
            self._adb = Adb()
        return self._adb

    def get_proxy_settings(self) -> tuple[ProxyStatus, ProxyConfig | None]:
        """Get the current proxy settings from the device.

        Returns:
            Tuple of (status, config). Config is None if proxy not set.
        """
        try:
            stdout, stderr = Adb.send_adb_command(
                "shell settings get global http_proxy"
            )
            if stderr:
                logger.warning(
                    f"ADB command warning while getting proxy settings: {stderr}"
                )
            proxy_value = stdout.strip() if stdout else ""

            if not proxy_value or proxy_value == "null" or proxy_value == ":0":
                return ProxyStatus.NOT_SET, None

            try:
                config = ProxyConfig.from_string(proxy_value)
                return ProxyStatus.SET, config
            except ValueError:
                logger.warning(f"Invalid proxy format from device: {proxy_value}")
                return ProxyStatus.ERROR, None

        except Exception as e:
            logger.error(f"Error getting proxy settings: {e}")
            return ProxyStatus.ERROR, None

    def set_proxy(self, config: ProxyConfig) -> tuple[bool, str]:
        """Set the HTTP proxy on the device.

        Args:
            config: ProxyConfig with IP and port.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Set the proxy
            Adb.send_adb_command(
                f"shell settings put global http_proxy {config.address}"
            )

            # Verify it was set correctly
            status, current = self.get_proxy_settings()
            if (
                status == ProxyStatus.SET
                and current
                and current.address == config.address
            ):
                logger.info(f"Proxy set to {config.address}")
                return True, f"Proxy set to {config.address}"
            return False, "Proxy was not set correctly"

        except Exception as e:
            logger.error(f"Error setting proxy: {e}")
            return False, f"Error setting proxy: {e}"

    def unset_proxy(self) -> tuple[bool, str]:
        """Remove the HTTP proxy from the device.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Clear the proxy setting
            Adb.send_adb_command("shell settings put global http_proxy :0")

            # Verify it was cleared
            status, _ = self.get_proxy_settings()
            if status == ProxyStatus.NOT_SET:
                logger.info("Proxy cleared")
                return True, "Proxy cleared"
            return False, "Failed to clear proxy"

        except Exception as e:
            logger.error(f"Error clearing proxy: {e}")
            return False, f"Error clearing proxy: {e}"

    @staticmethod
    def get_host_ip() -> str:
        """Get the host machine's IP address (delegated to SetupService).

        Returns the IP that's likely accessible from the Android device.
        """
        from sandroid.services import get_setup_service

        return get_setup_service().get_host_ip()

    @classmethod
    def get_default_config(cls) -> ProxyConfig:
        """Get a default proxy configuration using host IP and port 8080."""
        return ProxyConfig(ip=cls.get_host_ip(), port=8080)


class CAManager:
    """Manages CA certificates for SSL interception."""

    # Common CA certificate locations
    CA_LOCATIONS = {
        CASource.MITMPROXY: [
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer",
        ],
        CASource.HTTP_TOOLKIT: [
            Path.home() / ".config" / "httptoolkit" / "ca.pem",
            Path.home() / ".httptoolkit" / "ca.pem",
        ],
        CASource.BURP_SUITE: [
            Path.home() / ".BurpSuite" / "burp-ca-cert.der",
            Path.home() / "BurpSuite" / "PortSwigger" / "burp-ca-cert.der",
        ],
    }

    # Default device paths (kept as fallbacks)
    _DEFAULT_DEVICE_CERT_PATH = "/data/local/tmp/cert-der.crt"
    _DEFAULT_SYSTEM_CA_PATH = "/system/etc/security/cacerts"
    _DEFAULT_APEX_CA_PATH = "/apex/com.android.conscrypt/cacerts"

    @property
    def DEVICE_CERT_PATH(self) -> str:
        """Get device cert path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.device_cert_path
        except Exception:
            pass
        return self._DEFAULT_DEVICE_CERT_PATH

    @property
    def SYSTEM_CA_PATH(self) -> str:
        """Get system CA path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.system_ca_path
        except Exception:
            pass
        return self._DEFAULT_SYSTEM_CA_PATH

    @property
    def APEX_CA_PATH(self) -> str:
        """Get APEX CA path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.apex_ca_path
        except Exception:
            pass
        return self._DEFAULT_APEX_CA_PATH

    # Display names for CA sources
    SOURCE_NAMES = {
        CASource.MITMPROXY: "mitmproxy",
        CASource.HTTP_TOOLKIT: "HTTP Toolkit",
        CASource.BURP_SUITE: "Burp Suite",
        CASource.CUSTOM: "Custom Certificate",
    }

    def __init__(self, adb: Adb | None = None):
        """Initialize CAManager.

        Args:
            adb: Optional Adb instance. If not provided, creates a new one.
        """
        self._adb = adb
        self._use_su: bool = True

    @property
    def adb(self) -> Adb:
        """Get ADB wrapper, creating if needed."""
        if self._adb is None:
            self._adb = Adb()
        return self._adb

    def detect_ca_certificates(self) -> list[CAInfo]:
        """Auto-detect available CA certificates on the host.

        Returns:
            List of CAInfo for detected certificates.
        """
        found = []

        for source, paths in self.CA_LOCATIONS.items():
            for path in paths:
                if path.exists():
                    found.append(
                        CAInfo(
                            source=source,
                            path=path,
                            display_name=self.SOURCE_NAMES[source],
                        )
                    )
                    break  # Only add first found for each source

        return found

    def convert_pem_to_der(
        self, pem_path: Path, der_path: Path | None = None
    ) -> tuple[bool, str, Path | None]:
        """Convert a PEM certificate to DER format.

        Args:
            pem_path: Path to the PEM certificate.
            der_path: Optional output path. If not provided, uses temp directory.

        Returns:
            Tuple of (success, message, output_path).
        """
        if der_path is None:
            der_path = Path(tempfile.gettempdir()) / "sandroid-ca-cert.der"

        try:
            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(pem_path),
                    "-outform",
                    "DER",
                    "-out",
                    str(der_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                logger.debug(f"Converted PEM to DER: {der_path}")
                return True, f"Certificate converted to {der_path}", der_path
            error = result.stderr or "Unknown error"
            return False, f"OpenSSL error: {error}", None

        except FileNotFoundError:
            return False, "OpenSSL not found. Please install OpenSSL.", None
        except OSError as e:
            logger.error(f"Failed to start OpenSSL process: {e}")
            return False, f"Failed to start OpenSSL process: {e}", None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error during certificate conversion: {e}")
            return False, f"Subprocess error during certificate conversion: {e}", None

    def get_cert_hash(self, cert_path: Path) -> str | None:
        """Get the OpenSSL hash of a certificate.

        This hash is used for naming certificates in Android's CA store.

        Args:
            cert_path: Path to the certificate (PEM or DER).

        Returns:
            The certificate hash, or None on error.
        """
        try:
            # Determine format
            inform = "PEM" if cert_path.suffix.lower() in (".pem", ".crt") else "DER"

            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    inform,
                    "-in",
                    str(cert_path),
                    "-noout",
                    "-subject_hash_old",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return result.stdout.strip()
            return None

        except OSError as e:
            logger.error(f"Failed to start OpenSSL process: {e}")
            return None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error getting certificate hash: {e}")
            return None

    def push_cert_to_device(self, local_path: Path) -> tuple[bool, str]:
        """Push a certificate to the device's temp directory.

        Args:
            local_path: Path to the local certificate file.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Ensure the certificate is in DER format
            if local_path.suffix.lower() in (".pem", ".crt"):
                success, message, der_path = self.convert_pem_to_der(local_path)
                if not success:
                    return False, message
                local_path = der_path

            # Push to device
            Adb.send_adb_command(f"push {local_path} {self.DEVICE_CERT_PATH}")

            # Verify
            check_stdout, check_stderr = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH}"
            )
            if check_stderr:
                logger.warning(
                    f"ADB command warning while verifying certificate push: {check_stderr}"
                )
            if self.DEVICE_CERT_PATH in (check_stdout or ""):
                logger.debug(f"Certificate pushed to {self.DEVICE_CERT_PATH}")
                return True, f"Certificate pushed to {self.DEVICE_CERT_PATH}"
            return False, "Certificate was not pushed correctly"

        except Exception as e:
            logger.error(f"Error pushing certificate: {e}")
            return False, f"Error pushing certificate: {e}"

    def push_cert_for_injection(self, local_path: Path) -> tuple[bool, str]:
        """Push a certificate to the device in PEM format for system store injection.

        Unlike push_cert_to_device() which converts to DER, this ensures PEM
        format since Android's system CA store expects PEM.

        Args:
            local_path: Path to the local certificate file (PEM or DER).

        Returns:
            Tuple of (success, message).
        """
        try:
            push_path = local_path

            # If DER, convert to PEM first
            if local_path.suffix.lower() in (".der", ".cer"):
                pem_path = Path(tempfile.gettempdir()) / "sandroid-ca-cert.pem"
                result = subprocess.run(
                    [
                        "openssl", "x509",
                        "-inform", "DER",
                        "-in", str(local_path),
                        "-outform", "PEM",
                        "-out", str(pem_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    error = result.stderr or "Unknown error"
                    return False, f"OpenSSL DER→PEM conversion error: {error}"
                push_path = pem_path

            Adb.send_adb_command(f"push {push_path} {self.DEVICE_CERT_PATH}")

            check_stdout, _ = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH} 2>/dev/null"
            )
            if self.DEVICE_CERT_PATH in (check_stdout or ""):
                return True, f"Certificate (PEM) pushed to {self.DEVICE_CERT_PATH}"
            return False, "Certificate was not pushed correctly"

        except FileNotFoundError:
            return False, "OpenSSL not found. Please install OpenSSL."
        except Exception as e:
            logger.error(f"Error pushing certificate for injection: {e}")
            return False, f"Error pushing certificate: {e}"

    def get_zygote_pids(self) -> tuple[int | None, int | None]:
        """Get the PIDs of Zygote processes.

        Returns:
            Tuple of (zygote_pid, zygote64_pid). Either may be None.
        """
        zygote_pid = None
        zygote64_pid = None

        try:
            stdout, stderr = Adb.send_adb_command("shell ps -A | grep zygote")
            if stderr:
                logger.warning(
                    f"ADB command warning while getting Zygote PIDs: {stderr}"
                )
            if stdout:
                for line in stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            # Classify on the EXACT process name (last field)
                            # so webview_zygote / usap32 / usap64 etc. are
                            # ignored and not misassigned to zygote_pid.
                            name = parts[-1]
                            if name == "zygote64":
                                zygote64_pid = pid
                            elif name == "zygote":
                                zygote_pid = pid
                        except ValueError:
                            continue

        except Exception as e:
            logger.error(f"Error getting Zygote PIDs: {e}")

        return zygote_pid, zygote64_pid

    def get_device_api_level(self) -> int | None:
        """Get the API level of the connected Android device.

        Tries DeviceManager first, falls back to ADB shell query.

        Returns:
            API level as int, or None if unavailable.
        """
        try:
            from sandroid.core.device_manager import DeviceManager

            dm = DeviceManager.get_instance()
            if dm.active_device and dm.active_device.api_level:
                return int(dm.active_device.api_level)
        except Exception:
            pass

        try:
            stdout, _ = Adb.send_adb_command(
                "shell getprop ro.build.version.sdk"
            )
            if stdout and stdout.strip().isdigit():
                return int(stdout.strip())
        except Exception:
            pass

        return None

    def determine_injection_strategy(
        self,
    ) -> tuple[InjectionStrategy, int | None]:
        """Determine which CA injection strategy to use.

        Uses API level (>= 34 → BIND_MOUNT) with a fallback check for
        the APEX cacerts directory existence.

        Returns:
            Tuple of (strategy, api_level).
        """
        api_level = self.get_device_api_level()

        if api_level is not None and api_level >= 34:
            return InjectionStrategy.BIND_MOUNT, api_level

        # Fallback: check if APEX cacerts dir exists on device
        if api_level is None or api_level >= 33:
            try:
                stdout, _ = Adb.send_adb_command(
                    f"shell '[ -d {self.APEX_CA_PATH} ] && echo EXISTS'"
                )
                if "EXISTS" in (stdout or ""):
                    return InjectionStrategy.BIND_MOUNT, api_level
            except Exception:
                pass

        return InjectionStrategy.LEGACY, api_level

    def _check_root_access(self) -> bool:
        """Verify root access on the device.

        Tries direct shell (adb root mode) first, then falls back to su binary.
        Sets `_use_su` flag so subsequent commands use the right method.
        """
        # Try direct shell first (adb root mode — shell already runs as root)
        try:
            stdout, _ = Adb.send_adb_command("shell id")
            if "uid=0" in (stdout or ""):
                self._use_su = False
                return True
        except Exception:
            pass
        # Fall back to su binary (Magisk, SuperSU, etc.)
        try:
            stdout, _ = Adb.send_adb_command("shell su -c id")
            if "uid=0" in (stdout or ""):
                self._use_su = True
                return True
        except Exception:
            pass
        return False

    def _root_cmd(self, cmd: str) -> str:
        """Wrap a command for root execution on the device.

        Always single-quotes the command so shell metacharacters (&&, *, etc.)
        are interpreted by the device shell, not the host shell.
        Uses `su -c '...'` when root is via su binary, or plain quoting
        when the shell is already root (adb root).
        """
        if self._use_su:
            return f"su -c '{cmd}'"
        return f"'{cmd}'"

    def enable_adb_root(self) -> tuple[bool, str]:
        """Enable ADB root access on the device.

        Runs `adb root` to restart adbd as root, then verifies.

        Returns:
            Tuple of (success, message).
        """
        import time

        try:
            stdout, stderr = Adb.send_adb_command("root")
            combined = (stdout or "") + (stderr or "")

            if "adbd cannot run as root" in combined:
                return False, (
                    "Device does not support adb root. "
                    "Please ensure the device is rooted."
                )

            if "restarting" in combined.lower():
                time.sleep(0.5)

            stdout, _ = Adb.send_adb_command("shell id")
            if "uid=0" in (stdout or ""):
                self._use_su = False
                logger.info("ADB root enabled successfully")
                return True, "ADB root enabled successfully"

            return False, "ADB root command did not grant root access"

        except Exception as e:
            logger.error(f"Error enabling ADB root: {e}")
            return False, f"Error enabling root: {e}"

    def _get_cert_hash_from_device(self) -> str | None:
        """Pull cert from device and compute its hash."""
        try:
            local_temp = Path(tempfile.gettempdir()) / "sandroid-device-cert.pem"
            Adb.send_adb_command(f"pull {self.DEVICE_CERT_PATH} {local_temp}")
            if local_temp.exists():
                cert_hash = self.get_cert_hash(local_temp)
                local_temp.unlink()
                return cert_hash
        except Exception:
            pass
        return None

    def _inject_tmpfs_overlay(
        self,
        cert_name: str,
        zygote_pids: list[int],
        seed_dir: str,
        rbind_to_apex: bool,
    ) -> tuple[bool, str]:
        """Shared tmpfs-overlay CA injection for legacy and bind-mount paths.

        Stages the existing CA certs plus our cert, mounts a tmpfs over the
        system cacerts dir, then makes the overlay visible to newly spawned
        processes via the init (PID 1) mount namespace. On Android 14+
        (``rbind_to_apex=True``) the overlay is r-bound into the APEX cacerts
        dir; on Android 10-13 the system cacerts dir is read directly.

        Args:
            cert_name: Certificate filename (e.g. "a1b2c3d4.0").
            zygote_pids: List of Zygote PIDs to restart.
            seed_dir: Directory whose existing certs seed the overlay.
            rbind_to_apex: Whether to r-bind the overlay into APEX cacerts.

        Returns:
            Tuple of (success, message).
        """
        staging = "/data/local/tmp/sandroid-cacerts"
        sys_ca = self.SYSTEM_CA_PATH
        apex_ca = self.APEX_CA_PATH

        try:
            setup_cmds = [
                self._root_cmd(f"rm -rf {staging} && mkdir -p {staging}"),
                # Seed BEFORE the tmpfs mount hides the underlying dir.
                self._root_cmd(f"cp {seed_dir}/* {staging}/"),
                self._root_cmd(f"cp {self.DEVICE_CERT_PATH} {staging}/{cert_name}"),
                self._root_cmd(f"mount -t tmpfs tmpfs {sys_ca}"),
                self._root_cmd(f"cp {staging}/* {sys_ca}/"),
                self._root_cmd(f"chown root:root {sys_ca}/*"),
                self._root_cmd(f"chmod 644 {sys_ca}/*"),
                self._root_cmd(f"chcon -R u:object_r:system_file:s0 {sys_ca}/"),
            ]
            for cmd in setup_cmds:
                stdout, stderr = Adb.send_adb_command(f"shell {cmd}")
                if stderr:
                    logger.debug(f"tmpfs-overlay setup stderr: {stderr}")

            verify_path = apex_ca if rbind_to_apex else sys_ca

            if rbind_to_apex:
                init_mount = (
                    f"nsenter --mount=/proc/1/ns/mnt -- "
                    f"/bin/mount --rbind {sys_ca} {apex_ca}"
                )
                Adb.send_adb_command(f"shell {self._root_cmd(init_mount)}")
                init_verify = (
                    f"nsenter --mount=/proc/1/ns/mnt -- ls {apex_ca}/{cert_name}"
                )
                stdout, _ = Adb.send_adb_command(
                    f"shell {self._root_cmd(init_verify)}"
                )
                if cert_name not in (stdout or ""):
                    return False, "Bind-mount into init namespace failed"
                logger.info("Bind-mount into init namespace (PID 1) succeeded")
            else:
                init_verify = (
                    f"nsenter --mount=/proc/1/ns/mnt -- ls {sys_ca}/{cert_name}"
                )
                stdout, _ = Adb.send_adb_command(
                    f"shell {self._root_cmd(init_verify)}"
                )
                if cert_name not in (stdout or ""):
                    return False, "tmpfs overlay not visible in init namespace"
                logger.info("tmpfs CA overlay visible in init namespace (PID 1)")

            # Kill Zygote so init restarts it. The new Zygote inherits
            # init's mount namespace and Conscrypt reads the updated certs.
            import time

            for pid in zygote_pids:
                try:
                    Adb.send_adb_command(f"shell {self._root_cmd(f'kill {pid}')}")
                except Exception:
                    pass

            # The kill -> init-respawn -> Conscrypt-reload cycle routinely takes
            # well over the old fixed 3s on a busy device. Poll until a deadline
            # before declaring failure, re-reading PIDs each round since init
            # assigns a fresh Zygote PID as it respawns.
            verify_timeout = 20.0
            poll_interval = 1.0
            verified = 0
            deadline = time.monotonic() + verify_timeout
            while time.monotonic() < deadline:
                time.sleep(poll_interval)
                new_zyg, new_zyg64 = self.get_zygote_pids()
                new_pids = [p for p in [new_zyg, new_zyg64] if p is not None]
                if not new_pids:
                    continue  # init hasn't respawned Zygote yet
                verified = 0
                for pid in new_pids:
                    try:
                        verify_inner = (
                            f"nsenter --mount=/proc/{pid}/ns/mnt -- "
                            f"ls {verify_path}/{cert_name}"
                        )
                        stdout, _ = Adb.send_adb_command(
                            f"shell {self._root_cmd(verify_inner)}"
                        )
                        if cert_name in (stdout or ""):
                            verified += 1
                    except Exception:
                        pass
                if verified:
                    break

            if verified == 0:
                return False, "Cert not visible in restarted Zygote"

            label = "Bind-mount" if rbind_to_apex else "Legacy (tmpfs)"
            return True, (
                f"{label}: injected into init + {verified} restarted Zygote(s)"
            )

        except Exception as e:
            logger.error(f"tmpfs-overlay injection error: {e}")
            return False, f"Injection error: {e}"
        finally:
            # Cleanup staging
            try:
                Adb.send_adb_command(f"shell {self._root_cmd(f'rm -rf {staging}')}")
            except Exception:
                pass

    def _inject_legacy(
        self, cert_name: str, zygote_pids: list[int]
    ) -> tuple[bool, str]:
        """Pre-Android-14 injection via a tmpfs overlay on system cacerts.

        Seeds the overlay from the existing system cacerts dir and makes it
        visible to restarted Zygotes through the init mount namespace.

        Args:
            cert_name: Certificate filename (e.g. "a1b2c3d4.0").
            zygote_pids: List of Zygote PIDs to inject into.

        Returns:
            Tuple of (success, message).
        """
        return self._inject_tmpfs_overlay(
            cert_name,
            zygote_pids,
            seed_dir=self.SYSTEM_CA_PATH,
            rbind_to_apex=False,
        )

    def _inject_bind_mount(
        self, cert_name: str, zygote_pids: list[int]
    ) -> tuple[bool, str]:
        """Android 14+ injection: tmpfs overlay + bind-mount into APEX.

        Args:
            cert_name: Certificate filename (e.g. "a1b2c3d4.0").
            zygote_pids: List of Zygote PIDs to inject into.

        Returns:
            Tuple of (success, message).
        """
        return self._inject_tmpfs_overlay(
            cert_name,
            zygote_pids,
            seed_dir=self.APEX_CA_PATH,
            rbind_to_apex=True,
        )

    def _inject_into_app_processes(
        self, zygote_pids: list[int], sys_ca: str, apex_ca: str
    ) -> int:
        """Bind-mount CA certs into already-running app processes.

        Sweeps children of all Zygote processes.

        Returns:
            Number of app processes successfully injected.
        """
        count = 0
        for zpid in zygote_pids:
            try:
                stdout, _ = Adb.send_adb_command(
                    f"shell {self._root_cmd(f'ps -o PID -P {zpid}')}"
                )
                if not stdout:
                    continue
                for line in stdout.strip().split("\n"):
                    line = line.strip()
                    if not line or "PID" in line:
                        continue
                    try:
                        app_pid = int(line.strip())
                    except ValueError:
                        continue
                    try:
                        mount_inner = (
                            f"nsenter --mount=/proc/{app_pid}/ns/mnt -- "
                            f"/bin/mount --rbind {sys_ca} {apex_ca}"
                        )
                        Adb.send_adb_command(f"shell {self._root_cmd(mount_inner)}")
                        count += 1
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error sweeping children of Zygote {zpid}: {e}")
        return count

    def get_cert_spki_hash(self, cert_path: Path) -> str | None:
        """Get the SPKI (Subject Public Key Info) SHA-256 hash of a certificate.

        Used by Chrome's --ignore-certificate-errors-spki-list flag.

        Returns:
            Base64-encoded SPKI hash, or None on error.
        """
        try:
            import base64

            pubkey = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                check=True, capture_output=True,
            )
            der = subprocess.run(
                ["openssl", "pkey", "-pubin", "-outform", "der"],
                input=pubkey.stdout, check=True, capture_output=True,
            )
            dgst = subprocess.run(
                ["openssl", "dgst", "-sha256", "-binary"],
                input=der.stdout, check=True, capture_output=True,
            )
            return base64.b64encode(dgst.stdout).decode("ascii")
        except Exception as e:
            logger.error(f"Failed to compute SPKI hash: {e}")
            return None

    def bypass_chrome_ct(self, cert_path: Path) -> tuple[bool, str]:
        """Bypass Chrome Certificate Transparency enforcement for a CA cert.

        Chrome 99+ enforces CT for system CAs, rejecting mitmproxy certs.
        Writes chrome-command-line files with --ignore-certificate-errors-spki-list
        to skip CT for our specific cert. Covers Chrome, WebView, and
        content-shell variants (same approach as HTTP Toolkit).

        Args:
            cert_path: Path to the CA certificate (PEM).

        Returns:
            Tuple of (success, message).
        """
        spki_hash = self.get_cert_spki_hash(cert_path)
        if not spki_hash:
            return False, "Could not compute SPKI hash (is OpenSSL installed?)"

        flag_line = (
            f"chrome --ignore-certificate-errors-spki-list={spki_hash}"
        )
        logger.info(f"Chrome CT bypass SPKI: {spki_hash}")

        try:
            local_tmp = Path(tempfile.gettempdir()) / "chrome-command-line"
            local_tmp.write_text(flag_line)

            # All 8 locations matching HTTP Toolkit's approach:
            # 4 variants x 2 paths (/data/local + /data/local/tmp)
            variants = [
                "chrome-command-line",
                "android-webview-command-line",
                "webview-command-line",
                "content-shell-command-line",
            ]
            for variant in variants:
                for base in ["/data/local", "/data/local/tmp"]:
                    target = f"{base}/{variant}"
                    try:
                        Adb.send_adb_command(f"push {local_tmp} {target}")
                        Adb.send_adb_command(
                            f"shell {self._root_cmd(f'chmod 744 {target}')}"
                        )
                        Adb.send_adb_command(
                            f"shell {self._root_cmd(f'chcon u:object_r:shell_data_file:s0 {target}')}"
                        )
                    except Exception:
                        pass

            local_tmp.unlink(missing_ok=True)

            # On user builds, Chrome only reads flags if set as debug app
            Adb.send_adb_command(
                "shell settings put global debug_app com.android.chrome"
            )

            # Force-stop Chrome so it picks up the new flags on next launch
            Adb.send_adb_command("shell am force-stop com.android.chrome")

            logger.info("Chrome CT bypass flags installed (8 locations)")
            return True, f"Chrome CT bypass installed (SPKI: {spki_hash[:12]}...)"

        except Exception as e:
            logger.error(f"Chrome CT bypass failed: {e}")
            return False, f"Chrome CT bypass failed: {e}"

    def check_zygote_injection_status(self) -> ZygoteStatus:
        """Check whether the CA cert is present inside Zygote's mount namespace.

        Verifies by actually looking inside the namespace, not just checking
        the staging path.

        Returns:
            ZygoteStatus with current state.
        """
        zygote_pid, zygote64_pid = self.get_zygote_pids()
        target_pid = zygote64_pid or zygote_pid

        # Check if cert exists on device
        try:
            stdout, _ = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH} 2>/dev/null"
            )
            cert_exists = self.DEVICE_CERT_PATH in (stdout or "")
        except Exception:
            cert_exists = False

        cert_hash = None
        if cert_exists:
            cert_hash = self._get_cert_hash_from_device()

        # Verify cert inside Zygote namespace
        injected = False
        if cert_hash and target_pid:
            cert_name = f"{cert_hash}.0"
            # Check system CA path in namespace
            try:
                verify_inner = (
                    f"nsenter --mount=/proc/{target_pid}/ns/mnt -- "
                    f"ls {self.SYSTEM_CA_PATH}/{cert_name} 2>/dev/null"
                )
                stdout, _ = Adb.send_adb_command(
                    f"shell {self._root_cmd(verify_inner)}"
                )
                if cert_name in (stdout or ""):
                    injected = True
            except Exception:
                pass

            # Also check APEX path for Android 14+
            if not injected:
                try:
                    verify_inner = (
                        f"nsenter --mount=/proc/{target_pid}/ns/mnt -- "
                        f"ls {self.APEX_CA_PATH}/{cert_name} 2>/dev/null"
                    )
                    stdout, _ = Adb.send_adb_command(
                        f"shell {self._root_cmd(verify_inner)}"
                    )
                    if cert_name in (stdout or ""):
                        injected = True
                except Exception:
                    pass

        return ZygoteStatus(
            injected=injected,
            cert_hash=cert_hash,
            zygote_pid=zygote_pid,
            zygote64_pid=zygote64_pid,
        )

    def inject_ca_into_zygote(
        self, cert_path: Path | None = None
    ) -> InjectionResult:
        """Inject CA certificate into Zygote namespace for system-wide trust.

        Version-aware: uses legacy cp for API < 34, tmpfs + bind-mount for
        API >= 34 (or when APEX cacerts dir is detected).

        Args:
            cert_path: Path to local certificate. Uses device cert if not provided.

        Returns:
            InjectionResult with outcome details.
        """
        try:
            # 1. Check root access
            if not self._check_root_access():
                return InjectionResult(
                    success=False,
                    message="Root access required. Is the device rooted with 'su'?",
                    needs_root=True,
                )

            # 2. Push cert to device in PEM format
            if cert_path and cert_path.exists():
                success, message = self.push_cert_for_injection(cert_path)
                if not success:
                    return InjectionResult(success=False, message=message)

            # Verify cert is on device
            stdout, _ = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH} 2>/dev/null"
            )
            if self.DEVICE_CERT_PATH not in (stdout or ""):
                return InjectionResult(
                    success=False,
                    message="No certificate on device. Push certificate first.",
                )

            # 3. Get Zygote PIDs
            zygote_pid, zygote64_pid = self.get_zygote_pids()
            zygote_pids = [
                p for p in [zygote_pid, zygote64_pid] if p is not None
            ]
            if not zygote_pids:
                return InjectionResult(
                    success=False,
                    message="Could not find Zygote process. Is device running?",
                )

            # 4. Get cert hash
            cert_hash = self._get_cert_hash_from_device()
            if not cert_hash:
                return InjectionResult(
                    success=False,
                    message="Could not determine certificate hash (is OpenSSL installed?)",
                )
            cert_name = f"{cert_hash}.0"

            # 5. Determine strategy
            strategy, api_level = self.determine_injection_strategy()
            logger.info(
                f"Using {strategy.value} injection (API level: {api_level})"
            )

            # 6. Dispatch
            if strategy == InjectionStrategy.BIND_MOUNT:
                success, message = self._inject_bind_mount(cert_name, zygote_pids)
            else:
                success, message = self._inject_legacy(cert_name, zygote_pids)

            return InjectionResult(
                success=success,
                message=message,
                strategy=strategy,
                api_level=api_level,
            )

        except Exception as e:
            logger.error(f"Error injecting CA: {e}")
            return InjectionResult(
                success=False, message=f"Error injecting CA: {e}"
            )


class FocusManager:
    """Per-app proxy ("App Proxies") lane pool.

    Each app proxy gets its own *lane*: a full vertical slice of app UID →
    on-device iptables REDIRECT port → its own ``gost`` redirector. gost's
    ``red://`` listener forwards to the lane's upstream — our host mitmproxy
    SOCKS5 port (the default; the arrival SOCKS port *is* the app identity the
    mitmproxy addon reads to label flows) or an external HTTP proxy (Burp/ZAP).

    App Proxies coexist with the global Device Proxy: the per-UID REDIRECT
    short-circuits in the kernel before the userspace ``http_proxy`` is read, so
    a proxied app follows its lane and everyone else follows the device proxy —
    no double-capture.

    Composition (not inheritance): the reused root/host helpers live on two
    different classes, so this class holds a :class:`CAManager` (for
    ``_check_root_access``/``_root_cmd``/``_use_su`` root-command wrapping) and
    uses :meth:`ProxyManager.get_host_ip`.

    Lane ``i`` (0-based) uses fixed ports:
        host SOCKS5 port   = ``mitmproxy.socks_base + i`` (our-mitmproxy lanes)
        device REDIRECT port = ``focus.redirect_base + i``

    The pool size ``N`` is ``mitmproxy.focus_lanes``. All mutating public
    methods are guarded by a single :class:`threading.Lock`. (The class and its
    ``enable_focus``/``focused_apps`` API keep their internal names for
    continuity; user-facing surfaces say "App Proxies".)
    """

    # Valid mitmproxy ``flow.marked`` emoji keys (any other non-empty string
    # collapses to a single red dot, so the per-app palette must use these).
    PALETTE = [
        ":green_circle:",
        ":large_blue_circle:",
        ":purple_circle:",
        ":orange_circle:",
        ":yellow_circle:",
        ":brown_circle:",
        ":red_circle:",
        ":black_circle:",
    ]

    _RULE_TAG = "sandroid-focus"

    def __init__(self) -> None:
        """Initialize the lane pool and register crash-safe cleanup."""
        self._lock = threading.Lock()
        self._ca = CAManager()
        # lane index 0..N-1 → package or None (free). Sized lazily from config.
        self._lanes: dict[int, str | None] = {}
        # Per-lane upstream target chosen by the user: "ours" (our mitmproxy,
        # the default) or an external "http://host:port". Parallel to _lanes;
        # session-ephemeral (never persisted — lanes are live state).
        self._lane_targets: dict[int, str] = {}
        # Per-lane exact iptables rule specs to delete on teardown (populated
        # when xt_comment is unavailable and we fall back to tuple-match).
        self._lane_rule_specs: dict[int, list[tuple[str, str]]] = {}
        # Per-lane app UID, recorded at enable so set_quic_blocking() can
        # add/remove the QUIC REJECT for a live lane without re-resolving it.
        # Tracked/cleared exactly like _lane_rule_specs/_lane_targets so a
        # freed or reused lane never carries a stale uid.
        self._lane_uids: dict[int, int] = {}
        # Per-lane filter-table QUIC-block (UDP/443 REJECT) rule specs, kept
        # separate from _lane_rule_specs (which are nat REDIRECT rules) so the
        # toggle can add/remove just the QUIC rules.
        self._lane_quic_specs: dict[int, list[tuple[str, str]]] = {}
        self._binary_pushed = False
        # cleanup_stale() runs once at the first enable of a session.
        self._cleaned_this_session = False
        # Tri-state cache: is the ip6tables `nat` table usable? Probed once
        # (IPv4-only emulators lack it); when False we skip all ip6tables ops
        # so we don't spam "Table does not exist" warnings on every rule.
        self._ip6_ok: bool | None = None
        atexit.register(self._atexit_cleanup)

    # ── config helpers ────────────────────────────────────────────────

    @property
    def _pool_size(self) -> int:
        """Number of lanes (``mitmproxy.focus_lanes``)."""
        try:
            if get_config is not None:
                return int(get_config().mitmproxy.focus_lanes)
        except Exception:
            pass
        return 5

    @property
    def _socks_base(self) -> int:
        try:
            if get_config is not None:
                return int(get_config().mitmproxy.socks_base)
        except Exception:
            pass
        return 8082

    @property
    def _redirect_base(self) -> int:
        try:
            if get_config is not None:
                return int(get_config().focus.redirect_base)
        except Exception:
            pass
        return 60080

    @property
    def _binary_dst(self) -> str:
        try:
            if get_config is not None:
                return get_config().focus.gost_binary_dst
        except Exception:
            pass
        return "/data/local/tmp/gost"

    def _quic_blocking_enabled(self) -> bool:
        """Whether new lanes should REJECT QUIC (``focus.block_quic``)."""
        try:
            if get_config is not None:
                return bool(get_config().focus.block_quic)
        except Exception:
            pass
        return True

    def _socks_port(self, lane: int) -> int:
        return self._socks_base + lane

    def _redirect_port(self, lane: int) -> int:
        return self._redirect_base + lane

    def _marker(self, lane: int) -> str:
        return self.PALETTE[lane % len(self.PALETTE)]

    def _ensure_lanes(self) -> None:
        """Materialize the lane dict to the current pool size (free slots)."""
        n = self._pool_size
        for i in range(n):
            self._lanes.setdefault(i, None)
        # Drop any lanes beyond the (possibly shrunk) pool that are free.
        for i in list(self._lanes):
            if i >= n and self._lanes[i] is None:
                self._lanes.pop(i, None)
                self._lane_rule_specs.pop(i, None)
                self._lane_targets.pop(i, None)
                self._lane_uids.pop(i, None)
                self._lane_quic_specs.pop(i, None)

    # ── public API ────────────────────────────────────────────────────

    def enable_focus(
        self, package: str | None = None, target: str | None = None
    ) -> tuple[bool, str]:
        """Assign an app-proxy lane to ``package`` (listener-first, rules-last).

        Resolves the package (falling back to the spotlight app), allocates a
        free lane, downloads/pushes/launches gost for that lane, confirms it is
        listening, then installs the iptables OUTPUT redirect rules. Fails loud
        at each capability gate without leaving a half-applied lane.

        Args:
            package: Target package, or None to use the spotlight app.
            target: Lane upstream — ``None`` routes to our mitmproxy (default);
                an ``http://host:port`` (or bare ``host:port``) string routes the
                app to an external HTTP proxy (Burp/ZAP). The host is resolved to
                an IP host-side before gost launches.

        Returns:
            ``(ok, message)``.
        """
        with self._lock:
            self._ensure_lanes()

            # 1. Resolve package.
            if not package:
                package = self._spotlight_package()
            if not package:
                return False, "No spotlight app set — pick one first."

            # 2. Already proxied / pool exhausted.
            if package in self._lanes.values():
                return True, f"{package} already proxied"
            free = self._first_free_lane()
            if free is None:
                n = self._pool_size
                return False, (
                    f"All {n} app-proxy lanes in use — remove an app or raise "
                    "mitmproxy.focus_lanes."
                )

            # 3. Root probe (sets _use_su, required by every device command
            #    below — including the stale-rule cleanup, which must wrap with
            #    the right su/non-su form to actually clear leftovers).
            if not self._ca._check_root_access():
                return False, "Focus requires root (su)."

            # 4. Housekeeping: clear stale rules/processes once per session.
            if not self._cleaned_this_session:
                self._cleanup_stale_locked()
                self._cleaned_this_session = True

            # 5. owner-match capability probe.
            ok, msg = self._probe_owner_match()
            if not ok:
                return False, msg

            # 6. Resolve UID.
            uid = self._resolve_uid(package)
            if uid is None:
                return False, f"Could not resolve Linux UID for {package}."

            # 7. Ensure the gost binary is present (once per session).
            ok, msg = self._ensure_binary()
            if not ok:
                return False, msg

            lane = free
            redirect_port = self._redirect_port(lane)

            # 8. Resolve the lane's upstream host-side BEFORE launching, so a bad
            #    external target fails loud without leaving a half-applied lane.
            ok, upstream = self._build_upstream(target, lane)
            if not ok:
                return False, upstream  # upstream holds the error message
            lane_target = "ours" if target is None else upstream

            # 9. Launch the lane's gost redirector backgrounded as root.
            self._launch_gost(redirect_port, upstream)

            # 10. Confirm it is listening before touching iptables.
            if not self._wait_listening(redirect_port):
                self._kill_lane_process(redirect_port)
                return False, f"gost failed to bind port {redirect_port}."

            # 10b. For our-mitmproxy lanes, confirm gost's UPSTREAM (our SOCKS
            #      port at host_ip) is actually reachable from the device — the
            #      same host-IP-reachability blind spot the device proxy hits,
            #      one layer down. gost binds the listener fine even when its
            #      upstream blackholes, so a listening port is NOT proof of a
            #      working lane. Fail loud with a remedy hint rather than report
            #      a half-working "App proxy → <pkg>". Only a real connect
            #      failure aborts: an "unknown" verdict (no toybox nc) is
            #      tolerated.
            if target is None:
                host_ip = self._resolve_host_ip()
                socks_port = self._socks_port(lane)
                verdict = self._device_tcp_reachable(host_ip, socks_port)
                if verdict == "unreachable":
                    self._kill_lane_process(redirect_port)
                    return False, (
                        f"App proxy upstream {host_ip}:{socks_port} is "
                        "unreachable from the device — gost is listening but "
                        "can't reach our mitmproxy. Set focus.host_ip_override, "
                        "or route the device proxy via adb reverse "
                        "(Proxy Settings)."
                    )

            # 11. Install the redirect rules LAST (v4 + v6). The IPv4 table is
            #     fatal: on a genuine add failure, roll back (drop any partial
            #     rules + kill the lane's gost) so we never leave a redirector
            #     running with no working rule while claiming success.
            ok, msg = self._add_rules(lane, uid, redirect_port)
            if not ok:
                self._remove_lane_rules(lane)
                self._kill_lane_process(redirect_port)
                return False, msg

            # 12. Commit lane state, target, sidecar, and shared MitmproxyState.
            self._lanes[lane] = package
            self._lane_targets[lane] = lane_target
            self._lane_uids[lane] = uid
            # Block QUIC (UDP/443) so the app falls back to interceptable
            # TCP/TLS — the TCP-only nat REDIRECT can't touch HTTP/3. Tracked
            # even when off so set_quic_blocking() can toggle it later.
            if self._quic_blocking_enabled():
                self._add_quic_block(lane, uid)
            self._write_sidecar()
            self._add_to_state(package)
            dest = "our mitmproxy" if target is None else upstream
            logger.warning(
                "App proxy lane %d → %s (uid %s) upstream %s",
                lane,
                package,
                uid,
                dest,
            )
            label = package if target is None else f"{package} → {upstream}"
            return True, f"App proxy → {label} (lane {lane})"

    def disable_focus(self, package: str | None = None) -> tuple[bool, str]:
        """Free one lane (by package) or ALL lanes (``package=None``).

        Rules-first removal then process kill, so iptables never points at a
        dead port. Idempotent: freeing an already-free lane / disabling when
        nothing is active is a harmless no-op.

        Args:
            package: Package to unfocus, or None to free every lane.

        Returns:
            ``(ok, message)``.
        """
        with self._lock:
            self._ensure_lanes()
            if package is None:
                targets = [i for i, p in self._lanes.items() if p is not None]
                if not targets:
                    return True, "No app proxies to disable"
                for lane in targets:
                    self._teardown_lane(lane)
                self._write_sidecar()
                return True, "App proxies disabled (all lanes freed)"

            lane = self._lane_index_for(package)
            if lane is None:
                return True, f"{package} has no app proxy"
            self._teardown_lane(lane)
            self._write_sidecar()
            return True, f"App proxy removed for {package}"

    def focused_apps(self) -> list[str]:
        """Return the packages currently assigned to a lane."""
        with self._lock:
            return [p for p in self._lanes.values() if p]

    def app_proxies(self) -> dict[str, str]:
        """Return ``{package: "ours" | "http://ip:port"}`` for live lanes.

        ``"ours"`` means the app routes to our mitmproxy; an ``http://`` value is
        the resolved external HTTP-proxy upstream (Burp/ZAP). In-process read.
        """
        with self._lock:
            return {
                pkg: self._lane_targets.get(lane, "ours")
                for lane, pkg in self._lanes.items()
                if pkg
            }

    def lane_for(self, package: str) -> int | None:
        """Return the host SOCKS port serving ``package``, or None."""
        with self._lock:
            lane = self._lane_index_for(package)
            return None if lane is None else self._socks_port(lane)

    def is_focus_active(self) -> bool:
        """Whether any lane is currently assigned."""
        with self._lock:
            return any(p for p in self._lanes.values())

    def set_quic_blocking(self, enabled: bool) -> None:
        """Add/remove the QUIC (UDP/443) REJECT across all session lanes.

        Public, so it takes the lock itself and calls ONLY the lock-free
        internals (``_add_quic_block``/``_delete_rule_loop``) — never the public
        ``enable_focus``/``disable_focus``, which would re-acquire the
        non-reentrant ``self._lock`` and deadlock. Re-syncs the session-tracked
        lanes in ``_lanes`` via ``_lane_uids``: enabling adds the block to lanes
        that lack it; disabling deletes the rules and drops the tracked specs.

        Only affects lanes created this session — there is no cross-restart
        ``_lanes`` rebuild, which is consistent with the modal (after a restart
        the app rows are empty, so re-adding an app re-runs ``enable_focus`` and
        reapplies QUIC fresh).
        """
        with self._lock:
            for lane, package in self._lanes.items():
                if not package:
                    continue
                if enabled:
                    uid = self._lane_uids.get(lane)
                    if uid is None or lane in self._lane_quic_specs:
                        continue  # unknown uid, or already blocked.
                    self._add_quic_block(lane, uid)
                else:
                    for tbl, body in self._lane_quic_specs.get(lane, []):
                        self._delete_rule_loop(tbl, body)
                    self._lane_quic_specs.pop(lane, None)

    def cleanup_stale(self) -> None:
        """Remove every tagged rule + stray gost/ipt2socks and clear lane state.

        Self-heals after a SIGKILL'd prior run that would otherwise blackhole
        apps. Probes root first so the su/non-su command wrapping is correct
        when called standalone (e.g. at app startup). Swallows all errors.
        """
        with self._lock:
            try:
                self._ca._check_root_access()
            except Exception:
                pass
            self._cleanup_stale_locked()

    # ── internals (assume lock held unless noted) ─────────────────────

    def _spotlight_package(self) -> str | None:
        """Resolve the effective spotlight package (lazy import)."""
        try:
            from sandroid.services import get_spotlight_service

            return get_spotlight_service().get_effective_package()
        except Exception:
            return None

    def _first_free_lane(self) -> int | None:
        for i in range(self._pool_size):
            if self._lanes.get(i) is None:
                return i
        return None

    def _lane_index_for(self, package: str) -> int | None:
        for i, p in self._lanes.items():
            if p == package:
                return i
        return None

    def _resolve_uid(self, package: str) -> int | None:
        """Resolve the app's Linux UID, robust across Android versions.

        Strategy 1 (authoritative, version-independent): the owner UID of the
        app's private data dir via ``stat -c %u /data/data/<pkg>`` as root
        (Focus already requires root). The data dir is chowned to the app's UID
        on every Android release, so this needs no per-version parsing.

        Strategy 2 (fallback): parse ``dumpsys package``. The field name drifts
        across versions — older builds print ``userId=<n>`` while Android 15
        (API 35) prints ``appId=<n>`` (== the per-user-0 UID) and dropped
        ``userId=`` entirely — so match either. The previous code matched only
        ``userId=`` and so returned None (and "Could not resolve UID") on 15.
        """
        # 1. Data-dir owner — the exact Linux UID, no version dependence.
        try:
            out, _ = Adb.send_adb_command(
                "shell "
                + self._ca._root_cmd(f"stat -c %u /data/data/{package}")
            )
            val = (out or "").strip()
            if val.isdigit():
                return int(val)
        except Exception:
            pass

        # 2. dumpsys fallback (userId= pre-15, appId= on API 35+).
        try:
            out, _ = Adb.send_adb_command(f"shell dumpsys package {package}")
        except Exception:
            return None
        m = re.search(r"\b(?:userId|appId)=(\d+)", out or "")
        if not m:
            return None
        try:
            return int(m.group(1))
        except ValueError:
            return None

    #: UID well outside Android's entire allocation space (system <10000,
    #: apps 10000-19999, isolated 90000-99999, +100000*userId per profile),
    #: so the probe rule matches no real process for its brief lifetime.
    _PROBE_UID = "2000000000"

    def _probe_owner_match(self) -> tuple[bool, str]:
        """Probe that the kernel supports the per-app lane rule shape.

        Probes by installing the feature's EXACT rule (UID ``_PROBE_UID``,
        which matches no real process) and immediately deleting it — NOT
        ``iptables -C``. The legacy backend (iptables 1.8.x) reports the
        generic "No chain/target/match by that name" for a *non-existent*
        nat/REDIRECT rule even when the owner match AND the REDIRECT target
        are both compiled in, so a ``-C`` probe false-negatives and wrongly
        disabled App Proxies on perfectly capable kernels (e.g. Android 15).
        An add that loads the modules either succeeds or fails for an
        unrelated reason; only a missing-module error on the add is
        conclusive. ip6tables absence is a warning only.
        """
        ok, _ = self._probe_lane_rule("iptables")
        if not ok:
            return False, (
                "iptables owner/REDIRECT rule unavailable on this kernel "
                "(netfilter module missing) — Focus can't scope by app UID."
            )
        # IPv6 is best-effort. Only probe when the ip6tables nat table even
        # exists (cached + stderr-suppressed via _ip6_available); otherwise the
        # add/delete spew "Table does not exist" on IPv4-only kernels
        # (CONFIG_IP6_NF_NAT off), which is exactly what _add_rules skips too.
        if self._ip6_available() and not self._probe_lane_rule("ip6tables")[0]:
            logger.warning(
                "ip6tables owner/REDIRECT unavailable — Focus will only "
                "scope IPv4 traffic on this device."
            )
        return True, "owner match available"

    def _probe_lane_rule(self, binary: str) -> tuple[bool, str]:
        """Add the feature's exact lane rule (bogus UID), then delete it.

        Returns ``(supported, add_output)``. ``supported`` is False only when
        the ADD failed with a missing-module error; the DELETE is best-effort
        cleanup that runs regardless. A probe that can't run at all (ADB
        error) is treated as supported so a transient failure never disables
        the feature. Appends (``-A``) so the throwaway rule is evaluated last.
        """
        add = (
            f"{binary} -t nat -A OUTPUT -m owner --uid-owner {self._PROBE_UID} "
            "-p tcp -j REDIRECT --to-ports 1"
        )
        dele = (
            f"{binary} -t nat -D OUTPUT -m owner --uid-owner {self._PROBE_UID} "
            "-p tcp -j REDIRECT --to-ports 1"
        )
        try:
            out, err = Adb.send_adb_command(f"shell {self._ca._root_cmd(add)}")
        except Exception:
            return True, ""
        # Clean up whether or not the add reported success (a failed add just
        # makes the delete a harmless no-op).
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd(dele)}")
        except Exception:
            pass
        return (not self._is_missing_match(f"{out}\n{err}")), err

    @staticmethod
    def _is_missing_match(err: str) -> bool:
        # iptables phrases a missing extension/module several ways: "Couldn't
        # load match `owner'" (kernel module absent), "Couldn't find match
        # `…'" (userspace extension absent), or the generic "No chain/target/
        # match by that name." Match any so a real capability gap is caught.
        text = err or ""
        return bool(
            re.search(r"Couldn't (load|find) (match|target)", text)
            or "No chain/target/match" in text
        )

    # ── binary acquisition ────────────────────────────────────────────

    def _ensure_binary(self) -> tuple[bool, str]:
        """Download (cached, sha256-verified), then push gost to device.

        Idempotent across a session: the host cache download is skipped when a
        matching file already exists; the device push always runs (the binary
        is tiny) so a wiped /data/local/tmp self-heals.
        """
        from sandroid.core.fsmon import FSMon

        abi = FSMon.get_device_architecture()
        try:
            assets = get_config().focus.gost_assets
            asset = assets[abi]
        except Exception:
            return False, f"No gost asset configured for ABI '{abi}'."

        url = asset.get("url", "")
        sha256 = asset.get("sha256", "")
        if not url:
            return False, f"No gost URL configured for ABI '{abi}'."

        cache_dir = os.path.expanduser("~/.cache/sandroid/gost/")
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError as exc:
            return False, f"Cannot create gost cache dir: {exc}"
        cached = os.path.join(cache_dir, f"gost-{abi}")

        # Reuse a cached file only if it is non-empty and (when a hash is
        # configured) matches it. The cached file is the EXTRACTED ELF.
        need_download = True
        if os.path.exists(cached) and os.path.getsize(cached) > 0:
            if not sha256 or self._file_sha256(cached) == sha256:
                need_download = False

        if need_download:
            ok, msg = self._download_binary(url, cached, sha256)
            if not ok:
                return False, msg

        # Push to the device (rm -f first, then push, then chmod 755 as root).
        dst = self._binary_dst
        try:
            Adb.send_adb_command(
                f"shell {self._ca._root_cmd(f'rm -f {dst}')}"
            )
            push_out = subprocess.run(
                ["adb", "push", cached, dst],
                check=False,
                capture_output=True,
                text=True,
            )
            if push_out.returncode != 0:
                return False, (
                    "Failed to push gost: "
                    f"{(push_out.stderr or push_out.stdout or '').strip()}"
                )
            Adb.send_adb_command(
                f"shell {self._ca._root_cmd(f'chmod 755 {dst}')}"
            )
        except Exception as exc:
            return False, f"Failed to install gost: {exc}"

        self._binary_pushed = True
        return True, "gost installed"

    def _download_binary(
        self, url: str, dst: str, sha256: str
    ) -> tuple[bool, str]:
        """Download the gost ``.tar.gz``, extract the ``gost`` ELF to ``dst``.

        The gost release ships gzip tarballs (``LICENSE``, ``README*``, and a
        ``gost`` binary), so we read the archive from memory, ``extractfile`` the
        member whose basename is ``gost`` (NOT ``extractall`` — that is path-
        traversal-safe and avoids writing the docs), write only that ELF, then
        verify the sha256 of the EXTRACTED file. Mirrors the frida-server
        cached-download pattern otherwise.
        """
        try:
            with requests.get(url, timeout=300, allow_redirects=True) as res:
                res.raise_for_status()
                content = res.content
            if not content:
                return False, f"gost download returned empty content: {url}"
        except requests.RequestException as exc:
            return False, f"Failed to download gost from {url}: {exc}"

        # Extract only the `gost` member (traversal-safe: never extractall).
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
                member = next(
                    (
                        m
                        for m in tf.getmembers()
                        if m.isfile() and os.path.basename(m.name) == "gost"
                    ),
                    None,
                )
                if member is None:
                    return False, (
                        f"gost archive has no 'gost' member: {url}"
                    )
                extracted = tf.extractfile(member)
                if extracted is None:
                    return False, "Could not read 'gost' member from archive."
                data = extracted.read()
        except (tarfile.TarError, OSError, EOFError) as exc:
            return False, f"Failed to extract gost from {url}: {exc}"

        try:
            with open(dst, "wb") as f:
                f.write(data)
        except OSError as exc:
            return False, f"Failed to write gost binary: {exc}"

        if sha256:
            actual = self._file_sha256(dst)
            if actual != sha256:
                try:
                    os.unlink(dst)
                except OSError:
                    pass
                return False, (
                    "gost sha256 mismatch "
                    f"(expected {sha256[:12]}…, got {actual[:12]}…). "
                    "Note: the checksum is of the extracted ELF, not the tarball."
                )
        else:
            logger.warning(
                "No sha256 configured for gost asset — skipping "
                "verification (configure focus.gost_assets)."
            )
        return True, "gost downloaded"

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── upstream resolution ───────────────────────────────────────────

    @staticmethod
    def _resolve_to_ip(host: str) -> tuple[bool, str]:
        """Resolve ``host`` to an IPv4 address host-side (gost stays IP-only).

        gost is kept IP-only (never ``?sniffing``) and the device's resolv.conf
        can't be relied on, so any external-proxy hostname is resolved HERE. A
        numeric IP is returned unchanged. ``gethostbyname`` is v4-only — switch
        to ``getaddrinfo`` if IPv6 upstreams are ever needed.

        Returns ``(ok, ip_or_error)``.
        """
        host = (host or "").strip()
        if not host:
            return False, "External proxy host is empty."
        try:
            return True, socket.gethostbyname(host)
        except OSError as exc:
            return False, f"Could not resolve external proxy host '{host}': {exc}"

    def _build_upstream(
        self, target: str | None, lane: int
    ) -> tuple[bool, str]:
        """Build the gost ``-F`` upstream for a lane (host-side resolved).

        ``target=None`` ⇒ our mitmproxy: ``socks5://<host_ip>:<socks_port>`` (the
        lane's SOCKS port is the app identity the addon reads). Otherwise
        ``target`` is an external HTTP proxy as ``http://host:port`` or bare
        ``host:port``; the host is resolved to an IP here, yielding
        ``http://<ip>:<port>``. Non-http schemes are rejected and a resolve
        failure fails loud (returned as the message) before gost launches.

        Returns ``(ok, upstream_or_error)``.
        """
        if target is None:
            host_ip = self._resolve_host_ip()
            return True, f"socks5://{host_ip}:{self._socks_port(lane)}"

        spec = (target or "").strip()
        if "://" in spec:
            scheme, spec = spec.split("://", 1)
            if scheme.lower() != "http":
                return False, (
                    f"Unsupported proxy scheme '{scheme}://' — external app "
                    "proxies must be http://host:port (Burp/ZAP)."
                )
        if ":" not in spec:
            return False, (
                f"External proxy '{target}' must include a port (host:port)."
            )
        host, port_str = spec.rsplit(":", 1)
        # Strip brackets from a bracketed host; note _resolve_to_ip uses
        # gethostbyname (IPv4-only), so a real IPv6 literal still fails loud.
        host = host.strip().strip("[]")
        try:
            port = int(port_str)
        except ValueError:
            return False, f"External proxy port not a number: '{port_str}'."
        ok, ip_or_err = self._resolve_to_ip(host)
        if not ok:
            return False, ip_or_err
        return True, f"http://{ip_or_err}:{port}"

    # ── gost process lifecycle ────────────────────────────────────────

    def _resolve_host_ip(self) -> str:
        """Host IP our-mitmproxy lanes forward SOCKS traffic to.

        Delegates to the module-level :func:`resolve_proxy_host_ip` so the
        Device Proxy and App Proxies share one resolver:
        ``focus.host_ip_override`` wins; else ``10.0.2.2`` on an emulator
        (SLIRP loopback alias); else the auto-detected host LAN IP.
        """
        return resolve_proxy_host_ip()

    @staticmethod
    def _is_emulator() -> bool:
        return _is_emulator()

    def _launch_gost(self, redirect_port: int, upstream: str) -> None:
        """Launch one gost redirector backgrounded as root.

        ``gost -L red://:<redirect_port> -F <upstream>``: the ``red://`` listener
        reads ``SO_ORIGINAL_DST`` from the existing iptables REDIRECT rule and
        forwards to the lane's upstream (our mitmproxy SOCKS5, or an external
        HTTP proxy). The args carry no shell metacharacters so they are passed
        unquoted — keeping the exact ``su ... sh -c "<cmd> &"`` backgrounding via
        a detached Popen (mirrors ``frida_manager.run_frida_server``).
        """
        inner = (
            f"{self._binary_dst} -L red://:{redirect_port} -F {upstream} &"
        )
        if self._ca._use_su:
            shell_cmd = f"su -c 'sh -c \"{inner}\"'"
        else:
            shell_cmd = f'sh -c "{inner}"'
        adb_path = Adb.ADB_PATH or "adb"
        full_cmd = [adb_path]
        serial = Adb.get_target_device()
        if serial:
            full_cmd += ["-s", serial]
        full_cmd += ["shell", shell_cmd]
        try:
            subprocess.Popen(
                full_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.warning("Failed to launch gost: %s", exc)

    def _wait_listening(self, redirect_port: int) -> bool:
        """Poll ~2s for gost to be running and bound to ``redirect_port``."""
        needle = f":{redirect_port}"
        for _ in range(10):
            try:
                pid_out, _ = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd('pidof gost')}"
                )
            except Exception:
                pid_out = ""
            if (pid_out or "").strip():
                listening = self._port_listening(redirect_port, needle)
                if listening:
                    return True
            time.sleep(0.2)
        return False

    def _port_listening(self, redirect_port: int, needle: str) -> bool:
        for tool in ("ss -ltn", "netstat -ltn"):
            try:
                out, _ = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd(tool)}"
                )
            except Exception:
                continue
            if needle in (out or ""):
                return True
        return False

    @staticmethod
    def _device_tcp_reachable(host: str, port: int, *, timeout: int = 4) -> str:
        r"""Open a SOCKS5 handshake from the device to ``host:port``.

        Used by the App-Proxy lane to confirm gost's *upstream* (our mitmproxy
        SOCKS5 port) is actually reachable from the device — the same host-IP-
        reachability blind spot the device proxy hits, one layer down. Sends
        the SOCKS5
        greeting ``\\x05\\x01\\x00`` and treats a 2-byte ``\\x05\\x00`` reply as
        proof the upstream answered.

        QUOTING: ``Adb.send_adb_command`` runs the whole string through the host
        shell (``shell=True``), so the device-side pipe and ``printf`` byte
        escapes are wrapped in a single double-quoted ``shell "..."`` argument so
        the *device* shell interprets them — a bare pipe would be split by the
        *host* shell. ``toybox nc`` closes the socket on stdin EOF before the
        reply arrives, so we hold stdin open with ``{ ...; sleep N; }`` — do NOT
        simplify it back to a bare pipe or stdout comes back empty.

        Returns:
            ``"reachable"`` (got the SOCKS5 reply), ``"unreachable"`` (a real
            connect failure), or ``"unknown"`` (``toybox nc`` missing/errored —
            never report a false ``"unreachable"`` on a device without the tool).
        """
        inner = (
            f"{{ printf '\\x05\\x01\\x00'; sleep 2; }} | "
            f"toybox nc -w {timeout} {host} {port} | "
            "toybox xxd -p"
        )
        try:
            out, err = Adb.send_adb_command(f'shell "{inner}"')
        except Exception:
            return "unknown"
        text = (out or "").strip().lower()
        if "0500" in text:
            return "reachable"
        # Distinguish "tool missing" from "connect failed": toybox reports the
        # absent applet / a usage error on stderr without ever connecting
        # (toybox's own wording for a missing applet is "Unknown command nc").
        blob = (err or "").lower()
        if (
            "not found" in blob
            or "no such" in blob
            or "usage" in blob
            or "unknown command" in blob
        ):
            return "unknown"
        return "unreachable"

    def _kill_lane_process(self, redirect_port: int) -> None:
        """Kill the gost instance bound to ``redirect_port``."""
        pat = f"gost .*red://:{redirect_port}"
        inner = 'pkill -f "' + pat + '"'
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd(inner)}")
        except Exception:
            pass

    # ── iptables rule management ──────────────────────────────────────

    def _ip6_available(self) -> bool:
        """Whether the device has a usable ip6tables ``nat`` table (cached).

        IPv4-only emulators lack it. We probe once with stderr suppressed (so
        the probe itself is quiet) and decide from stdout: a working table
        always lists at least the chain's default policy (``-P OUTPUT ...``).
        When absent, all ip6tables operations are skipped.
        """
        if self._ip6_ok is None:
            try:
                out, _ = Adb.send_adb_command(
                    "shell "
                    + self._ca._root_cmd(
                        "ip6tables -t nat -S OUTPUT 2>/dev/null"
                    )
                )
                self._ip6_ok = "OUTPUT" in (out or "")
            except Exception:
                self._ip6_ok = False
            if not self._ip6_ok:
                logger.info(
                    "ip6tables nat unavailable — IPv6 redirect rules skipped "
                    "(IPv4-only device)."
                )
        return self._ip6_ok

    def _rule_body(self, uid: int, redirect_port: int, tagged: bool) -> str:
        comment = (
            f'-m comment --comment "{self._RULE_TAG}" ' if tagged else ""
        )
        return (
            f"-t nat {{op}} OUTPUT -m owner --uid-owner {uid} -p tcp "
            f"{comment}-j REDIRECT --to-ports {redirect_port}"
        )

    def _add_rules(
        self, lane: int, uid: int, redirect_port: int
    ) -> tuple[bool, str]:
        """Add the v4+v6 redirect rules for a lane (delete-then-add, tagged).

        Falls back to an untagged exact-tuple rule if ``xt_comment`` is
        unavailable, recording the spec so disable can delete it precisely.
        The IPv4 table is fatal — a genuine add failure there is returned so the
        caller can roll back, because a redirector with no rule would silently
        capture nothing. ip6tables failure is a warning only (emulator is
        IPv4-only).

        Returns:
            ``(ok, message)`` reflecting the fatal IPv4 table.
        """
        self._lane_rule_specs.pop(lane, None)
        specs: list[tuple[str, str]] = []
        v4_ok = True
        v4_err = ""
        tables = [("iptables", True)]
        if self._ip6_available():
            tables.append(("ip6tables", False))
        for tbl, fatal in tables:
            body = self._rule_body(uid, redirect_port, tagged=True)
            # Idempotent delete of any existing identical rule first.
            self._delete_rule_loop(tbl, body)
            add_cmd = f"{tbl} {body.format(op='-A')}"
            try:
                _, err = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd(add_cmd)}"
                )
            except Exception as exc:
                err = str(exc)
            if self._is_comment_error(err):
                # Retry without the comment match.
                body = self._rule_body(uid, redirect_port, tagged=False)
                self._delete_rule_loop(tbl, body)
                add_cmd = f"{tbl} {body.format(op='-A')}"
                try:
                    _, err = Adb.send_adb_command(
                        f"shell {self._ca._root_cmd(add_cmd)}"
                    )
                except Exception as exc:
                    err = str(exc)
            # Record the spec we actually used so teardown can delete it,
            # even if this add failed (delete of a missing rule is harmless).
            specs.append((tbl, body))
            if err and err.strip():
                if fatal:
                    v4_ok = False
                    v4_err = err.strip()
                else:
                    logger.warning(
                        "ip6tables rule add warning: %s", err.strip()
                    )
        self._lane_rule_specs[lane] = specs
        if not v4_ok:
            return False, f"iptables redirect rule failed: {v4_err}"
        return True, "rules added"

    def _quic_rule_body(
        self, uid: int, tagged: bool, target: str = "REJECT"
    ) -> str:
        """A filter-table OUTPUT rule REJECTing the UID's QUIC (UDP/443).

        No ``-t nat`` ⇒ the (default) filter table, kept separate from the nat
        REDIRECT rules. ``uid``/``comment``/``target`` are interpolated now and
        ONLY ``{{op}}`` is left for ``.format(op=...)`` — so the stored spec is
        directly delete-able via the shared ``_delete_rule_loop`` (if ``{uid}``
        survived into the spec, ``body.format(op='-D')`` would raise KeyError).
        """
        comment = (
            f'-m comment --comment "{self._RULE_TAG}" ' if tagged else ""
        )
        return (
            f"{{op}} OUTPUT -m owner --uid-owner {uid} -p udp --dport 443 "
            f"{comment}-j {target}"
        )

    def _add_quic_block(self, lane: int, uid: int) -> None:
        """Best-effort REJECT of the lane UID's QUIC (UDP/443), v4 (+v6).

        Forces the app off HTTP/3 — which the TCP-only nat REDIRECT can't
        intercept — back onto interceptable TCP/TLS. Filter-table OUTPUT rules,
        tracked in ``_lane_quic_specs`` (separate from the nat redirect specs)
        so the toggle/teardown can delete just them. Mirrors ``_add_rules``'
        delete-then-add + tagged/untagged-comment fallback, plus a REJECT→DROP
        fallback if the kernel lacks the REJECT target. Non-fatal: a failure
        leaves the TCP redirect working, so we log and move on.
        """
        self._lane_quic_specs.pop(lane, None)
        specs: list[tuple[str, str]] = []
        tbls = ["iptables"]
        if self._ip6_available():
            tbls.append("ip6tables")
        for tbl in tbls:
            tagged, target, err, body = True, "REJECT", "", ""
            # At most 4 passes: REJECT±comment, then DROP±comment.
            for _ in range(4):
                body = self._quic_rule_body(uid, tagged=tagged, target=target)
                self._delete_rule_loop(tbl, body)
                add_cmd = f"{tbl} {body.format(op='-A')}"
                try:
                    _, err = Adb.send_adb_command(
                        f"shell {self._ca._root_cmd(add_cmd)}"
                    )
                except Exception as exc:
                    err = str(exc)
                if self._is_comment_error(err) and tagged:
                    tagged = False
                    continue
                if self._is_reject_error(err) and target == "REJECT":
                    target = "DROP"
                    continue
                break
            specs.append((tbl, body))
            if err and err.strip():
                logger.warning(
                    "%s QUIC-block (uid %s) add warning: %s",
                    tbl,
                    uid,
                    err.strip(),
                )
        self._lane_quic_specs[lane] = specs

    @staticmethod
    def _is_reject_error(err: str) -> bool:
        """Whether a REJECT add failed because the target isn't loadable.

        Legacy iptables names it (``Couldn't load target `REJECT'``), but
        nf_tables kernels (Android 10+) emit a bare ``No chain/target/match by
        that name`` with no target token. The caller checks this ONLY on a
        REJECT add and ONLY after the xt_comment fallback, so any load/match
        failure that reaches here means REJECT is unavailable → fall back to
        DROP (matching only the legacy ``reject`` token would silently skip the
        fallback on nf_tables and leave QUIC unblocked).
        """
        text = (err or "").lower()
        return "couldn't load" in text or "no chain/target/match" in text

    def _delete_rule_loop(self, tbl: str, body: str) -> None:
        """Delete every copy of a rule (ignore errors)."""
        del_cmd = f"{tbl} {body.format(op='-D')}"
        for _ in range(10):
            try:
                _, err = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd(del_cmd)}"
                )
            except Exception:
                return
            if err and ("No chain/target/match" in err or "does a matching" in err):
                return
            if err and err.strip():
                # Any other error (e.g. bad rule) — stop trying.
                return

    @staticmethod
    def _is_comment_error(err: str) -> bool:
        text = (err or "").lower()
        return "comment" in text and (
            "couldn't load" in text or "no chain/target/match" in text
        )

    def _remove_lane_rules(self, lane: int) -> None:
        """Delete a lane's recorded rule specs (v4+v6), ignoring errors.

        Removes both the nat REDIRECT specs and the filter-table QUIC-block
        specs, so disabling an app proxy leaves no stray rule in either table.
        """
        for tbl, body in self._lane_rule_specs.get(lane, []):
            self._delete_rule_loop(tbl, body)
        self._lane_rule_specs.pop(lane, None)
        for tbl, body in self._lane_quic_specs.get(lane, []):
            self._delete_rule_loop(tbl, body)
        self._lane_quic_specs.pop(lane, None)

    # ── lane teardown / cleanup ───────────────────────────────────────

    def _teardown_lane(self, lane: int) -> None:
        """Rules-first removal, then kill the lane's gost; free the slot."""
        package = self._lanes.get(lane)
        self._remove_lane_rules(lane)
        self._kill_lane_process(self._redirect_port(lane))
        self._lanes[lane] = None
        self._lane_targets.pop(lane, None)
        self._lane_uids.pop(lane, None)
        if package:
            self._remove_from_state(package)

    def _cleanup_stale_locked(self) -> None:
        """Remove every tagged OUTPUT rule + stray gost; clear lane state.

        Sweeps the tagged ``-A OUTPUT`` rules out of BOTH the ``nat`` table
        (REDIRECT rules) and the ``filter`` table (QUIC-block REJECT rules) so a
        SIGKILL'd prior run self-heals in either table. The table flag is
        parameterized per pass — ``-t nat`` for the nat pass, omitted for the
        filter pass — and the reconstructed ``-D`` delete reuses the SAME flag
        it listed (a stale ``-t nat`` copied into the filter delete would miss).

        Also kills/removes any leftover ipt2socks (the pre-gost redirector) so a
        device transitioned from the old build self-heals.
        """
        tbls = ["iptables"]
        if self._ip6_available():
            tbls.append("ip6tables")
        # ("-t nat ", "") — trailing space so f"{tbl} {flag}-S OUTPUT" stays
        # well-formed; "" targets the default (filter) table.
        for table_flag in ("-t nat ", ""):
            for tbl in tbls:
                try:
                    out, _ = Adb.send_adb_command(
                        f"shell {self._ca._root_cmd(f'{tbl} {table_flag}-S OUTPUT')}"
                    )
                except Exception:
                    continue
                for line in (out or "").splitlines():
                    if self._RULE_TAG not in line:
                        continue
                    spec = line.strip()
                    if not spec.startswith("-A "):
                        continue
                    del_spec = "-D " + spec[len("-A "):]
                    del_cmd = f"{tbl} {table_flag}{del_spec}"
                    try:
                        Adb.send_adb_command(
                            f"shell {self._ca._root_cmd(del_cmd)}"
                        )
                    except Exception:
                        pass
        # Kill any stray gost redirectors (current) and ipt2socks (legacy),
        # then remove the legacy ipt2socks binary so transitioned devices
        # self-heal. Runs once per session (mount/atexit/stop), not per-lane.
        for kill in (f"pkill -f {self._binary_dst}", "pkill -f ipt2socks"):
            try:
                Adb.send_adb_command(f"shell {self._ca._root_cmd(kill)}")
            except Exception:
                pass
        try:
            Adb.send_adb_command(
                f"shell {self._ca._root_cmd('rm -f /data/local/tmp/ipt2socks')}"
            )
        except Exception:
            pass
        self._lanes.clear()
        self._lane_targets.clear()
        self._lane_rule_specs.clear()
        self._lane_uids.clear()
        self._lane_quic_specs.clear()
        try:
            self._write_sidecar()
        except Exception:
            pass

    def _atexit_cleanup(self) -> None:
        try:
            self.disable_focus()
        except Exception:
            pass

    # ── sidecar map ───────────────────────────────────────────────────

    @staticmethod
    def _sidecar_path() -> str:
        default = os.path.expanduser("~/.cache/sandroid/focus_lanes.json")
        try:
            if get_config is not None:
                return os.path.expanduser(get_config().focus.sidecar_path)
        except Exception:
            pass
        return default

    def _write_sidecar(self) -> None:
        """Atomically write the lane→app sidecar map (string SOCKS-port keys).

        Shape: ``{"8082": {"package": "com.foo", "marker": ":green_circle:"}}``.
        Empty when no lane is assigned.
        """
        import json

        data: dict[str, dict[str, str]] = {}
        for lane, package in self._lanes.items():
            if not package:
                continue
            # External lanes forward to an HTTP proxy (Burp/ZAP) and never reach
            # our mitmweb SOCKS listener, so there is no arrival port to key on —
            # the addon can't (and shouldn't) attribute them. Skip them; only
            # our-mitmproxy lanes get a sidecar entry.
            if self._lane_targets.get(lane, "ours") != "ours":
                continue
            data[str(self._socks_port(lane))] = {
                "package": package,
                "marker": self._marker(lane),
            }
        path = self._sidecar_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix="focus_lanes_", suffix=".json", dir=os.path.dirname(path)
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            Path(tmp).replace(path)
        except OSError as exc:
            logger.warning("Failed to write Focus sidecar map: %s", exc)

    # ── shared MitmproxyState mirroring ───────────────────────────────

    @staticmethod
    def _mitm_state():
        try:
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            return get_mitmproxy_service().state
        except Exception:
            return None

    def _add_to_state(self, package: str) -> None:
        state = self._mitm_state()
        if state is not None and package not in state.focus_apps:
            state.focus_apps.append(package)

    def _remove_from_state(self, package: str) -> None:
        state = self._mitm_state()
        if state is not None and package in state.focus_apps:
            try:
                state.focus_apps.remove(package)
            except ValueError:
                pass


_FOCUS_INSTANCE: FocusManager | None = None
_FOCUS_INSTANCE_LOCK = threading.Lock()


def get_focus_manager() -> FocusManager:
    """Module-level accessor for the singleton FocusManager."""
    global _FOCUS_INSTANCE
    if _FOCUS_INSTANCE is None:
        with _FOCUS_INSTANCE_LOCK:
            if _FOCUS_INSTANCE is None:
                _FOCUS_INSTANCE = FocusManager()
    return _FOCUS_INSTANCE


# Convenience functions for use without class instantiation
def get_proxy_status() -> tuple[ProxyStatus, ProxyConfig | None]:
    """Get current proxy status using default ADB wrapper."""
    return ProxyManager().get_proxy_settings()


def set_proxy(ip: str, port: int) -> tuple[bool, str]:
    """Set proxy using default ADB wrapper."""
    return ProxyManager().set_proxy(ProxyConfig(ip=ip, port=port))


def unset_proxy() -> tuple[bool, str]:
    """Unset proxy using default ADB wrapper."""
    return ProxyManager().unset_proxy()


def detect_ca_certificates() -> list[CAInfo]:
    """Detect available CA certificates on host."""
    return CAManager().detect_ca_certificates()
