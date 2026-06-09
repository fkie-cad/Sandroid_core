"""Proxy and CA Certificate management for Sandroid.

This module provides TUI-agnostic business logic for:
- HTTP proxy configuration via ADB
- CA certificate detection and management
- Zygote CA injection for system-wide SSL interception
"""

import logging
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sandroid.core.adb import Adb

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


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
            time.sleep(3)

            new_zyg, new_zyg64 = self.get_zygote_pids()
            new_pids = [p for p in [new_zyg, new_zyg64] if p is not None]

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
