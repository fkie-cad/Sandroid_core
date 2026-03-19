"""Session State Service for Sandroid.

Pure storage service for cross-cutting session state that is accessed
by multiple services and modules. No validation logic -- validation
happens at point of use in domain services.

State is read via pull model -- services read when they need it.

Usage:
    from sandroid.services import get_session_state_service

    state = get_session_state_service()
    state.args = parsed_args
    print(state.args)
"""

import threading
from typing import Any


class SessionStateService:
    """Pure storage service for cross-cutting session state.

    Holds state variables that are accessed by 2+ services or modules,
    providing thread-safe getters and setters via @property pairs.

    No validation logic -- that happens at point of use.
    No imports from other sandroid modules (prevents circular imports).

    Thread Safety:
        All operations are thread-safe via threading.Lock().

    Example:
        state = SessionStateService()
        state.args = parsed_args
        state.device_name = "Pixel_8_Pro_API_34"
        print(state.get_state_dict())
    """

    def __init__(self) -> None:
        """Initialize SessionStateService with default values."""
        self._lock = threading.Lock()
        self._args: Any = None
        self._logger: Any = None
        self._frida_manager: Any = None
        self._scan_directories: list = []
        self._device_name: str = "Pixel_6_Pro_API_31"
        self._android_emulator_path: str = ""

    @property
    def args(self) -> Any:
        """Get the CLI args namespace.

        Returns:
            The current args namespace, or None if not set.
        """
        with self._lock:
            return self._args

    @args.setter
    def args(self, value: Any) -> None:
        """Set the CLI args namespace.

        Args:
            value: The args namespace to store.
        """
        with self._lock:
            self._args = value

    @property
    def logger(self) -> Any:
        """Get the session logger reference.

        Returns:
            The current logger, or None if not set.
        """
        with self._lock:
            return self._logger

    @logger.setter
    def logger(self, value: Any) -> None:
        """Set the session logger reference.

        Args:
            value: The logger instance to store.
        """
        with self._lock:
            self._logger = value

    @property
    def frida_manager(self) -> Any:
        """Get the FridaManager instance.

        Returns:
            The current FridaManager, or None if not set.
        """
        with self._lock:
            return self._frida_manager

    @frida_manager.setter
    def frida_manager(self, value: Any) -> None:
        """Set the FridaManager instance.

        Args:
            value: The FridaManager instance to store.
        """
        with self._lock:
            self._frida_manager = value

    @property
    def scan_directories(self) -> list:
        """Get the list of scan directories for forensic analysis.

        Returns:
            List of directory paths to scan.
        """
        with self._lock:
            return list(self._scan_directories)

    @scan_directories.setter
    def scan_directories(self, value: list) -> None:
        """Set the list of scan directories for forensic analysis.

        Args:
            value: List of directory paths to scan.
        """
        with self._lock:
            self._scan_directories = list(value) if value else []

    @property
    def device_name(self) -> str:
        """Get the device name.

        Returns:
            The current device name.
        """
        with self._lock:
            return self._device_name

    @device_name.setter
    def device_name(self, value: str) -> None:
        """Set the device name.

        Args:
            value: The device name to store.
        """
        with self._lock:
            self._device_name = value

    @property
    def android_emulator_path(self) -> str:
        """Get the Android emulator path.

        Returns:
            The current emulator path.
        """
        with self._lock:
            return self._android_emulator_path

    @android_emulator_path.setter
    def android_emulator_path(self, value: str) -> None:
        """Set the Android emulator path.

        Args:
            value: The emulator path to store.
        """
        with self._lock:
            self._android_emulator_path = value

    def reset(self) -> None:
        """Reset all state to default values.

        Useful for testing to ensure clean state between tests.
        """
        with self._lock:
            self._args = None
            self._logger = None
            self._frida_manager = None
            self._scan_directories = []
            self._device_name = "Pixel_6_Pro_API_31"
            self._android_emulator_path = ""

    def get_state_dict(self) -> dict[str, Any]:
        """Get all state as a dictionary for debugging and API responses.

        Returns:
            Dictionary with all current state values.
        """
        with self._lock:
            return {
                "args": repr(self._args) if self._args is not None else None,
                "logger": repr(self._logger) if self._logger is not None else None,
                "frida_manager": (
                    repr(self._frida_manager)
                    if self._frida_manager is not None
                    else None
                ),
                "scan_directories": list(self._scan_directories),
                "device_name": self._device_name,
                "android_emulator_path": self._android_emulator_path,
            }


__all__ = [
    "SessionStateService",
]
