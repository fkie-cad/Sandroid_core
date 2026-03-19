"""TrigDroid Configuration Service for Sandroid.

This service manages TrigDroid bypass configuration state including
bypass config dict, spawn mode flag, and auto-resume flag.

Extracted from Toolbox class to follow Single Responsibility Principle.
Pure storage service with no imports from other sandroid modules.

Usage:
    from sandroid.services import get_trigdroid_config_service

    # Get service
    service = get_trigdroid_config_service()

    # Set bypass config
    service.bypass_config = {"root_detection": {"enabled": True}}

    # Check spawn mode
    if service.spawn_mode:
        ...
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class TrigDroidConfigService:
    """Service for TrigDroid bypass configuration management.

    This service manages:
    - Bypass configuration dict (Frida hook configurations)
    - Spawn mode flag (spawn vs attach)
    - Auto-resume flag (resume after hooks loaded)

    Thread Safety:
        Basic get/set operations are thread-safe for simple types.
        The bypass_config dict should be set atomically (not mutated
        in-place from multiple threads).

    Example:
        service = TrigDroidConfigService()

        # Configure bypass
        service.bypass_config = {
            "root_detection": {"enabled": True, "script": "..."},
            "ssl_pinning": {"enabled": False},
        }

        # Set execution mode
        service.spawn_mode = True
        service.auto_resume = True

        # Get state
        state = service.get_state_dict()
    """

    def __init__(self) -> None:
        """Initialize the TrigDroidConfigService with default values."""
        self._bypass_config: dict[str, Any] | None = None
        self._spawn_mode: bool = True
        self._auto_resume: bool = True
        self._logger = logger

    # =========================================================================
    # Bypass Configuration
    # =========================================================================

    @property
    def bypass_config(self) -> dict[str, Any] | None:
        """Get the TrigDroid bypass configuration.

        Returns:
            Bypass config dict, or None if not configured
        """
        return self._bypass_config

    @bypass_config.setter
    def bypass_config(self, value: dict[str, Any] | None) -> None:
        """Set the TrigDroid bypass configuration.

        The config dict can have various value types:
        - Dict values with "enabled" key: {"root_detection": {"enabled": True}}
        - Bool values: {"bypass_ssl": True}
        - Any other structure

        Args:
            value: Bypass config dict, or None to clear
        """
        self._bypass_config = value
        if value is not None:
            enabled = self._get_enabled_hook_names(value)
            self._logger.debug(
                f"TrigDroid bypass config set: {len(enabled)} hooks enabled"
            )
        else:
            self._logger.debug("TrigDroid bypass config cleared")

    # =========================================================================
    # Spawn Mode
    # =========================================================================

    @property
    def spawn_mode(self) -> bool:
        """Get the TrigDroid spawn mode flag.

        Returns:
            True for spawn mode, False for attach mode
        """
        return self._spawn_mode

    @spawn_mode.setter
    def spawn_mode(self, value: bool) -> None:
        """Set the TrigDroid spawn mode flag.

        Args:
            value: True for spawn mode, False for attach mode
        """
        self._spawn_mode = bool(value)
        self._logger.debug(f"TrigDroid spawn mode: {self._spawn_mode}")

    # =========================================================================
    # Auto-Resume
    # =========================================================================

    @property
    def auto_resume(self) -> bool:
        """Get the TrigDroid auto-resume flag.

        Returns:
            True if auto-resume is enabled after hooks are loaded
        """
        return self._auto_resume

    @auto_resume.setter
    def auto_resume(self, value: bool) -> None:
        """Set the TrigDroid auto-resume flag.

        Args:
            value: True to enable auto-resume after hooks loaded
        """
        self._auto_resume = bool(value)
        self._logger.debug(f"TrigDroid auto-resume: {self._auto_resume}")

    # =========================================================================
    # State Management
    # =========================================================================

    @staticmethod
    def _get_enabled_hook_names(config: dict[str, Any]) -> list[str]:
        """Get names of enabled hooks from a bypass config dict.

        Args:
            config: Bypass configuration dictionary.

        Returns:
            List of hook names that are enabled.
        """
        return [
            k
            for k, v in config.items()
            if (isinstance(v, dict) and v.get("enabled"))
            or (not isinstance(v, dict) and v)
        ]

    def reset(self) -> None:
        """Reset all TrigDroid configuration to defaults."""
        self._bypass_config = None
        self._spawn_mode = True
        self._auto_resume = True
        self._logger.info("Reset TrigDroid config service state")

    def get_state_dict(self) -> dict[str, Any]:
        """Get complete service state as dictionary.

        Useful for serialization and debugging.

        Returns:
            Dictionary with all service state
        """
        bypass_info = None
        if self._bypass_config is not None:
            enabled = self._get_enabled_hook_names(self._bypass_config)
            bypass_info = {
                "total_hooks": len(self._bypass_config),
                "enabled_hooks": len(enabled),
                "enabled_names": enabled,
            }

        return {
            "bypass_config": bypass_info,
            "spawn_mode": self._spawn_mode,
            "auto_resume": self._auto_resume,
        }


__all__ = [
    "TrigDroidConfigService",
]
