"""Proxy and CA Certificate management for Sandroid.

This module provides TUI-agnostic business logic for:
- HTTP proxy configuration via ADB
- CA certificate detection and management
- Zygote CA injection for system-wide SSL interception
"""

import logging
import subprocess
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
            der_path = Path("/tmp") / "sandroid-ca-cert.der"

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
                            if "zygote64" in line:
                                zygote64_pid = pid
                            elif "zygote" in line:
                                zygote_pid = pid
                        except ValueError:
                            continue

        except Exception as e:
            logger.error(f"Error getting Zygote PIDs: {e}")

        return zygote_pid, zygote64_pid

    def check_zygote_injection_status(self) -> ZygoteStatus:
        """Check the current status of Zygote CA injection.

        Returns:
            ZygoteStatus with current state.
        """
        zygote_pid, zygote64_pid = self.get_zygote_pids()

        # Check if cert exists on device
        try:
            stdout, stderr = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH} 2>/dev/null"
            )
            if stderr:
                logger.warning(
                    f"ADB command warning while checking device certificate: {stderr}"
                )
            cert_exists = self.DEVICE_CERT_PATH in (stdout or "")
        except Exception:
            cert_exists = False

        # Get cert hash if exists
        cert_hash = None
        if cert_exists:
            try:
                # Pull cert and get hash
                local_temp = Path("/tmp/sandroid-device-cert.der")
                Adb.send_adb_command(f"pull {self.DEVICE_CERT_PATH} {local_temp}")
                if local_temp.exists():
                    cert_hash = self.get_cert_hash(local_temp)
                    local_temp.unlink()  # Clean up
            except Exception:
                pass

        # Check if CA appears in system trust store (via Zygote namespace)
        # This would require injecting and checking - for now just report what we know
        injected = cert_exists and cert_hash is not None

        return ZygoteStatus(
            injected=injected,
            cert_hash=cert_hash,
            zygote_pid=zygote_pid,
            zygote64_pid=zygote64_pid,
        )

    def inject_ca_into_zygote(self, cert_path: Path | None = None) -> tuple[bool, str]:
        """Inject CA certificate into Zygote namespace for system-wide trust.

        This requires root access and works by:
        1. Pushing cert to device
        2. Using nsenter to access Zygote's mount namespace
        3. Adding cert to the system CA store within that namespace

        Args:
            cert_path: Path to local certificate. Uses device cert if not provided.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Ensure cert is on device
            if cert_path and cert_path.exists():
                success, message = self.push_cert_to_device(cert_path)
                if not success:
                    return False, message

            # Check device cert exists
            stdout, stderr = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH} 2>/dev/null"
            )
            if stderr:
                logger.warning(
                    f"ADB command warning while checking device certificate before injection: {stderr}"
                )
            if self.DEVICE_CERT_PATH not in (stdout or ""):
                return False, "No certificate on device. Push certificate first."

            # Get Zygote PID
            zygote_pid, zygote64_pid = self.get_zygote_pids()
            target_pid = zygote64_pid or zygote_pid
            if not target_pid:
                return False, "Could not find Zygote process. Is device rooted?"

            # Get certificate hash for naming
            status = self.check_zygote_injection_status()
            if not status.cert_hash:
                return False, "Could not determine certificate hash"

            cert_name = f"{status.cert_hash}.0"

            # Inject into Zygote namespace
            # This requires root access
            inject_cmd = (
                f"su -c 'nsenter --mount=/proc/{target_pid}/ns/mnt -- "
                f"cp {self.DEVICE_CERT_PATH} {self.SYSTEM_CA_PATH}/{cert_name} && "
                f"chmod 644 {self.SYSTEM_CA_PATH}/{cert_name}'"
            )

            Adb.send_adb_command(f"shell {inject_cmd}")

            # Verify injection
            verify_cmd = f"su -c 'nsenter --mount=/proc/{target_pid}/ns/mnt -- ls {self.SYSTEM_CA_PATH}/{cert_name}'"
            verify_stdout, verify_stderr = Adb.send_adb_command(f"shell {verify_cmd}")
            if verify_stderr:
                logger.error(
                    f"ADB command error while verifying CA injection: {verify_stderr}"
                )

            if cert_name in (verify_stdout or ""):
                logger.info(f"CA injected into Zygote namespace: {cert_name}")
                return True, f"CA certificate injected as {cert_name}"
            return False, "Injection may have failed. Verify root access."

        except Exception as e:
            logger.error(f"Error injecting CA: {e}")
            return False, f"Error injecting CA: {e}"


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
