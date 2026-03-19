"""Proxy Service for Sandroid.

This service manages HTTP proxy settings on Android devices/emulators.
It handles configuring, clearing, and querying proxy state.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_proxy_service
    from sandroid.services.proxy_service import ProxyService

    # Using service locator
    proxy_service = get_proxy_service()

    # Check current proxy settings
    current = proxy_service.get_proxy_settings()
    print(f"Current proxy: {current}")

    # Set a proxy
    if proxy_service.set_proxy("192.168.1.100", "8080"):
        print("Proxy configured")

    # Clear proxy
    if proxy_service.clear_proxy():
        print("Proxy cleared")

    # Toggle (interactive mode)
    result = proxy_service.toggle_proxy()
"""

import logging
from dataclasses import dataclass
from typing import Any, Protocol

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class ProxySettings:
    """Represents HTTP proxy settings.

    Attributes:
        ip: Proxy IP address (None if not set)
        port: Proxy port (None if not set)
        enabled: Whether a proxy is currently configured
    """

    ip: str | None = None
    port: str | None = None
    enabled: bool = False

    def __str__(self) -> str:
        """Return string representation of proxy settings."""
        if self.enabled and self.ip and self.port:
            return f"{self.ip}:{self.port}"
        return "Not set"


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return (stdout, stderr)."""
        ...


class SetupServiceProtocol(Protocol):
    """Protocol for SetupService dependency injection."""

    def get_host_ip(self) -> str:
        """Get the host machine's IP address."""
        ...


class ProxyService:
    """Service for managing HTTP proxy settings on Android devices.

    This service handles:
    - Getting current proxy settings
    - Setting proxy with IP and port
    - Clearing proxy settings
    - Interactive toggle (set/unset)

    Thread Safety:
        All operations are thread-safe (stateless - reads/writes via ADB).

    Example:
        service = ProxyService()

        # Check current settings
        settings = service.get_proxy_settings()
        if settings.enabled:
            print(f"Proxy: {settings}")

        # Set a new proxy
        service.set_proxy("192.168.1.100", "8080")

        # Clear proxy
        service.clear_proxy()
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        setup_service: SetupServiceProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize the ProxyService.

        Args:
            adb: Optional ADB interface. If not provided, uses global Adb class.
            setup_service: Optional SetupService for get_host_ip().
            event_bus: Optional EventBus for publishing events.
        """
        self._adb = adb
        self._setup_service = setup_service
        self._event_bus = event_bus
        self._logger = logger

    def _get_adb(self) -> AdbProtocol:
        """Get ADB instance, falling back to global class."""
        if self._adb is not None:
            return self._adb

        try:
            from sandroid.core.adb import Adb

            return Adb
        except ImportError:
            raise RuntimeError("ADB not available and no ADB instance provided")

    def _get_setup_service(self) -> SetupServiceProtocol:
        """Get SetupService instance, falling back to service locator."""
        if self._setup_service is not None:
            return self._setup_service

        from sandroid.services import get_setup_service

        return get_setup_service()

    def get_proxy_settings(self) -> ProxySettings:
        """Get the current HTTP proxy settings from the device.

        Returns:
            ProxySettings object with current configuration.
        """
        adb = self._get_adb()
        stdout, _stderr = adb.send_adb_command("shell settings get global http_proxy")

        raw_value = stdout.strip() if stdout else ""

        # Check for various "not set" indicators
        if not raw_value or raw_value in ["", ":0", "null"]:
            return ProxySettings(enabled=False)

        # Try to parse IP:port format
        if ":" in raw_value:
            parts = raw_value.rsplit(":", 1)  # Split from right to handle IPv6
            if len(parts) == 2:
                ip, port = parts
                if port and port != "0":
                    return ProxySettings(ip=ip, port=port, enabled=True)

        # Fallback - enabled but couldn't parse
        return ProxySettings(enabled=True)

    def get_proxy_string(self) -> str:
        """Get proxy settings as a string for display.

        Returns:
            Proxy string like "192.168.1.100:8080" or "Not set".
        """
        settings = self.get_proxy_settings()
        return str(settings)

    def set_proxy(self, ip: str, port: str) -> bool:
        """Set HTTP proxy on the device.

        Args:
            ip: Proxy IP address.
            port: Proxy port number.

        Returns:
            True if proxy was set successfully, False otherwise.
        """
        adb = self._get_adb()

        # Validate inputs
        if not ip or not port:
            self._logger.error("Proxy IP and port are required")
            return False

        # Set the proxy
        command = f"shell settings put global http_proxy {ip}:{port}"
        _stdout, stderr = adb.send_adb_command(command)

        if stderr:
            self._logger.error(f"Failed to set proxy: {stderr}")
            return False

        self._logger.info(f"Proxy set to {ip}:{port}")
        self._publish_proxy_changed(ip, port)
        return True

    def clear_proxy(self) -> bool:
        """Clear HTTP proxy settings on the device.

        Returns:
            True if proxy was cleared successfully, False otherwise.
        """
        adb = self._get_adb()

        # Clear the proxy by setting to :0
        _stdout, stderr = adb.send_adb_command(
            "shell settings put global http_proxy :0"
        )

        if stderr:
            self._logger.error(f"Failed to clear proxy: {stderr}")
            return False

        self._logger.info("Proxy unset successfully")
        self._publish_proxy_changed(None, None)
        return True

    def toggle_proxy(
        self,
        default_ip: str | None = None,
        default_port: str = "8080",
        input_callback=None,
    ) -> tuple[bool, str]:
        """Toggle proxy settings - unset if set, prompt for settings if not.

        This is an interactive method that prompts for user input when
        setting a new proxy.

        Args:
            default_ip: Default IP to suggest (if None, uses host IP).
            default_port: Default port to suggest.
            input_callback: Callable for getting user input.
                           Signature: (prompt: str) -> str
                           If None, uses Toolbox.safe_input.

        Returns:
            Tuple of (success, message).
        """
        current = self.get_proxy_settings()

        if current.enabled:
            # Proxy is set, clear it
            self._logger.info(f"Current proxy is set to: {current}")
            if self.clear_proxy():
                return True, "Proxy unset successfully"
            return False, "Failed to unset proxy"

        # Proxy not set, prompt for settings
        # Get default IP if not provided
        if default_ip is None:
            default_ip = self._get_setup_service().get_host_ip()

        # Get input callback
        if input_callback is None:
            from sandroid.core.toolbox import Toolbox

            input_callback = Toolbox.safe_input

        # Prompt for IP
        self._logger.info(f"Enter proxy IP (default: {default_ip})")
        proxy_ip = input_callback("") or default_ip

        # Prompt for port
        self._logger.info(f"Enter proxy port (default: {default_port})")
        proxy_port = input_callback("") or default_port

        # Set the proxy
        if self.set_proxy(proxy_ip, proxy_port):
            return True, f"Proxy set to {proxy_ip}:{proxy_port}"
        return False, f"Failed to set proxy to {proxy_ip}:{proxy_port}"

    def set_unset_proxy(self) -> None:
        """Toggle proxy settings (legacy interface).

        This method provides backwards compatibility with the original
        Toolbox.set_unset_proxy() method.
        """
        success, message = self.toggle_proxy()
        self._logger.info(message) if success else self._logger.error(message)

    # =========================================================================
    # Event Publishing
    # =========================================================================

    def _publish_proxy_changed(self, ip: str | None, port: str | None) -> None:
        """Publish event when proxy settings change."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "component": "proxy",
                    "action": "proxy_changed",
                    "enabled": ip is not None and port is not None,
                    "ip": ip,
                    "port": port,
                },
                source="proxy_service",
            )
        )


__all__ = [
    "ProxyService",
    "ProxySettings",
]
