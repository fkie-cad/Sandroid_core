"""TrigDroid Configuration Service for Sandroid.

This service holds the execution-mode flags of TrigDroid's trigger runner
(:class:`sandroid.features.trigdroid.Trigdroid`): the spawn-mode flag and the
auto-resume flag. It carries no bypass configuration: detection bypasses come
only from :class:`sandroid.analysis.detection_bypass.BypassService`.

Extracted from Toolbox class to follow Single Responsibility Principle.
Pure storage service with no imports from other sandroid modules.

Usage:
    from sandroid.services import get_trigdroid_config_service

    service = get_trigdroid_config_service()
    if service.spawn_mode:
        ...
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class TrigDroidConfigService:
    """Execution-mode flags for TrigDroid's trigger runner.

    This service manages:
    - Spawn mode flag (spawn vs attach)
    - Auto-resume flag (resume after hooks loaded)

    Thread Safety:
        Basic get/set operations are thread-safe for simple types.

    Example:
        service = TrigDroidConfigService()
        service.spawn_mode = True
        service.auto_resume = True
        state = service.get_state_dict()
    """

    def __init__(self) -> None:
        """Initialize the TrigDroidConfigService with default values."""
        self._spawn_mode: bool = True
        self._auto_resume: bool = True
        #: The trigger run needs a fresh process: on a running app TrigDroid
        #: then refuses (restart it with ⇧R first). Without it a running app
        #: is attached to, whatever ``spawn_mode`` says.
        self.fresh: bool = False
        self._logger = logger

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

    def reset(self) -> None:
        """Reset all TrigDroid configuration to defaults."""
        self._spawn_mode = True
        self._auto_resume = True
        self.fresh = False
        self._logger.info("Reset TrigDroid config service state")

    def get_state_dict(self) -> dict[str, Any]:
        """Get complete service state as dictionary.

        Useful for serialization and debugging.

        Returns:
            Dictionary with all service state
        """
        return {
            "spawn_mode": self._spawn_mode,
            "auto_resume": self._auto_resume,
        }


__all__ = [
    "TrigDroidConfigService",
]
