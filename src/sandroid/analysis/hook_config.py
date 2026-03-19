"""Hook configuration management for Sandroid analysis modules.

This module provides the HookConfiguration class for managing dexray-intercept
hook configurations. It extracts the hook groups and configuration logic from
malwaremonitor.py into a reusable, testable component.

The hook configuration supports:
    - Hook group definitions with metadata (name, description, hooks)
    - Individual hook enable/disable state management
    - Group-level operations (toggle, enable all, disable all)
    - Conflict detection with other running Frida tools
    - Thread-safe state management

Usage:
    from sandroid.analysis.hook_config import HookConfiguration

    # Create with default configuration
    config = HookConfiguration()

    # Or with custom initial configuration
    config = HookConfiguration(initial_config={"aes_hooks": False})

    # Toggle a group
    new_state = config.toggle_group("crypto")

    # Get enabled hooks for Frida
    hooks = config.get_enabled_hooks()

Example with MalwareMonitor:
    class MalwareMonitor:
        def __init__(self):
            self.hook_config = HookConfiguration()

        def start_monitoring(self):
            # Get hooks to register with JobManager
            registry_hooks = self.hook_config.get_hooks_for_registry()

            # Check for conflicts before starting
            conflicts = self.hook_config.check_conflicts()
            if conflicts:
                logger.warning(f"Hook conflicts detected: {conflicts}")

Protocol Support:
    The module defines HookConfigurationProtocol for dependency injection,
    allowing mock implementations in tests.
"""

import logging
import threading
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HookGroupInfo:
    """Immutable metadata for a hook group.

    Attributes:
        key: Internal identifier (e.g., "crypto", "network")
        name: Human-readable name (e.g., "Crypto Hooks")
        description: Description of what the group monitors
        hooks: List of hook names in this group
    """

    key: str
    name: str
    description: str
    hooks: tuple[str, ...]  # Immutable tuple instead of list

    @classmethod
    def from_dict(cls, key: str, data: dict[str, Any]) -> "HookGroupInfo":
        """Create a HookGroupInfo from a dictionary.

        Args:
            key: The group key
            data: Dictionary with name, description, and hooks

        Returns:
            HookGroupInfo instance
        """
        return cls(
            key=key,
            name=data["name"],
            description=data["description"],
            hooks=tuple(data["hooks"]),
        )


@runtime_checkable
class HookConfigurationProtocol(Protocol):
    """Protocol for hook configuration implementations.

    This protocol enables dependency injection and testing by defining
    the interface that hook configuration implementations must satisfy.
    """

    def get_default_config(self) -> dict[str, bool]:
        """Get the default hook configuration."""
        ...

    def get_hook_groups(self) -> dict[str, HookGroupInfo]:
        """Get all hook groups with metadata."""
        ...

    def is_group_enabled(self, group_key: str) -> bool:
        """Check if any hook in a group is enabled."""
        ...

    def toggle_group(self, group_key: str) -> bool:
        """Toggle all hooks in a group, return new state."""
        ...

    def enable_all(self) -> None:
        """Enable all hooks."""
        ...

    def disable_all(self) -> None:
        """Disable all hooks."""
        ...

    def get_enabled_hooks(self) -> list[str]:
        """Get list of enabled hook names."""
        ...

    def get_config(self) -> dict[str, bool]:
        """Get current hook configuration."""
        ...

    def set_config(self, config: dict[str, bool]) -> None:
        """Set hook configuration."""
        ...

    def get_hooks_for_registry(self) -> list[str]:
        """Get hooks in format for Toolbox registry."""
        ...

    def check_conflicts(self) -> dict[str, str]:
        """Check for hook conflicts with running tools."""
        ...


class HookConfiguration:
    """Manages hook configuration for dexray-intercept.

    This class encapsulates all hook configuration logic, providing
    thread-safe operations for managing which hooks are enabled for
    malware monitoring.

    The hook groups are organized by functionality:
        - crypto: AES, encodings, keystore operations
        - network: Web requests, sockets
        - filesystem: File operations, database access
        - ipc: Shared preferences, binder, intents, broadcasts
        - process: DEX unpacking, native libraries, runtime
        - services: Bluetooth, camera, clipboard, location, telephony
        - bypass: Anti-analysis detection bypass

    Thread Safety:
        All state-modifying operations are protected by a lock.
        Read operations are also protected for consistency.

    Example:
        config = HookConfiguration()

        # Enable crypto monitoring
        config.toggle_group("crypto")

        # Check what will be monitored
        enabled = config.get_enabled_hooks()
        print(f"Monitoring: {enabled}")

        # Get hooks for Frida
        registry_hooks = config.get_hooks_for_registry()

    Attributes:
        _config: Dictionary mapping hook names to enabled state
        _lock: Threading lock for thread-safe operations
    """

    # Class-level constants for hook groups
    # These define the structure of available hook categories
    HOOK_GROUPS_DATA: dict[str, dict[str, Any]] = {
        "crypto": {
            "name": "Crypto Hooks",
            "description": "AES, encodings, keystore operations",
            "hooks": ["aes_hooks", "encodings_hooks", "keystore_hooks"],
        },
        "network": {
            "name": "Network Hooks",
            "description": "Web requests, sockets, HTTP/HTTPS traffic",
            "hooks": ["web_hooks", "socket_hooks"],
        },
        "filesystem": {
            "name": "Filesystem Hooks",
            "description": "File operations, database access",
            "hooks": ["file_system_hooks", "database_hooks"],
        },
        "ipc": {
            "name": "IPC Hooks",
            "description": "Binder, intents, broadcasts, shared preferences",
            "hooks": [
                "shared_prefs_hooks",
                "binder_hooks",
                "intent_hooks",
                "broadcast_hooks",
            ],
        },
        "process": {
            "name": "Process Hooks",
            "description": "Native libraries, runtime, DEX unpacking",
            "hooks": [
                "dex_unpacking_hooks",
                "java_dex_unpacking_hooks",
                "native_library_hooks",
                "process_hooks",
                "runtime_hooks",
            ],
        },
        "services": {
            "name": "Service Hooks",
            "description": "Bluetooth, camera, clipboard, location, telephony",
            "hooks": [
                "bluetooth_hooks",
                "camera_hooks",
                "clipboard_hooks",
                "location_hooks",
                "telephony_hooks",
            ],
        },
        "bypass": {
            "name": "Anti-Analysis Bypass Hooks",
            "description": "Root, frida, debugger, emulator detection",
            "hooks": ["bypass_hooks"],
        },
    }

    # Default hook configuration matching malwaremonitor.py defaults
    # These are the critical hooks enabled by default for malware analysis
    DEFAULT_CONFIG: dict[str, bool] = {
        # Crypto hooks
        "aes_hooks": True,
        # Network hooks (--hooks-network)
        "web_hooks": True,
        "socket_hooks": True,
        # Filesystem hooks (--hooks-filesystem)
        "file_system_hooks": True,
        "database_hooks": False,
        # DEX unpacking hooks (--enable-dex-unpacking)
        "dex_unpacking_hooks": True,
        "java_dex_unpacking_hooks": True,
        # Other hooks default to False
        "encodings_hooks": False,
        "keystore_hooks": False,
        "shared_prefs_hooks": False,
        "binder_hooks": False,
        "intent_hooks": False,
        "broadcast_hooks": False,
        "native_library_hooks": False,
        "process_hooks": False,
        "runtime_hooks": False,
        "bluetooth_hooks": False,
        "camera_hooks": False,
        "clipboard_hooks": False,
        "location_hooks": False,
        "telephony_hooks": False,
        "bypass_hooks": False,
    }

    def __init__(
        self,
        initial_config: dict[str, bool] | None = None,
        *,
        hooks: dict[str, bool] | None = None,
    ):
        """Initialize the hook configuration.

        Args:
            initial_config: Optional dictionary of initial hook settings.
                Keys should be hook names (e.g., "aes_hooks"), values
                are boolean enabled states. Any hooks not specified will
                use defaults from DEFAULT_CONFIG.
            hooks: Legacy keyword alias for *initial_config* (kept for
                backward compatibility with callers that used the simpler
                HookConfiguration from hook_config_ui).

        Example:
            # Use all defaults
            config = HookConfiguration()

            # Override some defaults
            config = HookConfiguration({"aes_hooks": False, "bypass_hooks": True})

            # Legacy keyword form
            config = HookConfiguration(hooks={"aes_hooks": False})
        """
        # Support legacy ``hooks=`` keyword
        effective_config = initial_config or hooks

        self._lock = threading.RLock()

        # Start with default configuration
        self._config: dict[str, bool] = self.DEFAULT_CONFIG.copy()

        # Apply any initial overrides
        if effective_config:
            for hook_name, enabled in effective_config.items():
                if hook_name in self._config:
                    self._config[hook_name] = enabled
                else:
                    logger.warning(f"Unknown hook in initial config: {hook_name}")

        # Pre-compute hook groups as HookGroupInfo objects
        self._hook_groups: dict[str, HookGroupInfo] = {
            key: HookGroupInfo.from_dict(key, data)
            for key, data in self.HOOK_GROUPS_DATA.items()
        }

        logger.debug(f"HookConfiguration initialized with {len(self._config)} hooks")

    def get_default_config(self) -> dict[str, bool]:
        """Get the default hook configuration.

        Returns:
            Dictionary mapping hook names to their default enabled state.
            This is a copy to prevent modification of class defaults.

        Example:
            defaults = config.get_default_config()
            print(f"AES hooks default: {defaults['aes_hooks']}")  # True
        """
        return self.DEFAULT_CONFIG.copy()

    def get_hook_groups(self) -> dict[str, HookGroupInfo]:
        """Get all hook groups with their metadata.

        Returns:
            Dictionary mapping group keys to HookGroupInfo objects.
            The returned dictionary is a shallow copy; HookGroupInfo
            objects are immutable.

        Example:
            groups = config.get_hook_groups()
            crypto = groups["crypto"]
            print(f"{crypto.name}: {crypto.description}")
        """
        with self._lock:
            return self._hook_groups.copy()

    def is_group_enabled(self, group_key: str) -> bool:
        """Check if any hook in a group is enabled.

        A group is considered enabled if at least one of its hooks
        is enabled. This matches the UI behavior where a group toggle
        shows as "ON" if any hook is active.

        Args:
            group_key: The group key (e.g., "crypto", "network")

        Returns:
            True if any hook in the group is enabled, False otherwise.
            Returns False if the group key is not found.

        Example:
            if config.is_group_enabled("crypto"):
                print("Crypto monitoring is active")
        """
        with self._lock:
            group = self._hook_groups.get(group_key)
            if not group:
                logger.warning(f"Unknown group key: {group_key}")
                return False

            return any(self._config.get(hook, False) for hook in group.hooks)

    def toggle_group(self, group_key: str) -> bool:
        """Toggle all hooks in a group on or off.

        If any hook in the group is currently enabled, all hooks
        in the group will be disabled. If all hooks are disabled,
        all will be enabled.

        Args:
            group_key: The group key (e.g., "crypto", "network")

        Returns:
            The new enabled state for the group (True if now enabled).
            Returns False if the group key is not found.

        Example:
            # Enable crypto if disabled, or disable if any enabled
            new_state = config.toggle_group("crypto")
            print(f"Crypto is now {'enabled' if new_state else 'disabled'}")
        """
        with self._lock:
            group = self._hook_groups.get(group_key)
            if not group:
                logger.warning(f"Unknown group key: {group_key}")
                return False

            # Check current state
            currently_enabled = any(
                self._config.get(hook, False) for hook in group.hooks
            )

            # Toggle to opposite state
            new_state = not currently_enabled
            for hook in group.hooks:
                if hook in self._config:
                    self._config[hook] = new_state

            logger.debug(
                f"Toggled group '{group_key}' to {'enabled' if new_state else 'disabled'}"
            )
            return new_state

    def enable_all(self) -> None:
        """Enable all hooks in all groups.

        This sets every hook to enabled state. Useful for comprehensive
        monitoring at the cost of potential performance overhead.

        Example:
            config.enable_all()
            print(f"All {len(config.get_enabled_hooks())} hooks enabled")
        """
        with self._lock:
            for hook_name in self._config:
                self._config[hook_name] = True
            logger.debug("All hooks enabled")

    def disable_all(self) -> None:
        """Disable all hooks in all groups.

        This sets every hook to disabled state. The result will be
        no monitoring (dexray-intercept will run but capture nothing).

        Example:
            config.disable_all()
            # Warning: No hooks will be active
        """
        with self._lock:
            for hook_name in self._config:
                self._config[hook_name] = False
            logger.debug("All hooks disabled")

    def get_enabled_hooks(self) -> list[str]:
        """Get list of currently enabled hook names.

        Returns:
            List of hook names that are currently enabled.
            The order is consistent but not guaranteed to be
            in any particular sequence.

        Example:
            enabled = config.get_enabled_hooks()
            print(f"Active hooks: {', '.join(enabled)}")
        """
        with self._lock:
            return [hook_name for hook_name, enabled in self._config.items() if enabled]

    def get_config(self) -> dict[str, bool]:
        """Get the current hook configuration.

        Returns:
            Dictionary mapping hook names to their enabled state.
            This is a copy to prevent external modification.

        Example:
            current = config.get_config()
            # Safe to modify - it's a copy
            current["aes_hooks"] = False
        """
        with self._lock:
            return self._config.copy()

    def set_config(self, config: dict[str, bool]) -> None:
        """Set the hook configuration.

        This replaces the current configuration with the provided one.
        Unknown hooks are logged as warnings but ignored.

        Args:
            config: Dictionary mapping hook names to enabled states.
                Only known hooks will be updated.

        Example:
            config.set_config({
                "aes_hooks": True,
                "web_hooks": True,
                "socket_hooks": False,
            })
        """
        with self._lock:
            for hook_name, enabled in config.items():
                if hook_name in self._config:
                    self._config[hook_name] = enabled
                else:
                    logger.warning(f"Unknown hook in set_config: {hook_name}")

            logger.debug(f"Configuration updated with {len(config)} settings")

    def get_hooks_for_registry(self) -> list[str]:
        """Get hooks in format for Toolbox/JobManager registry.

        This method returns the actual hook function names that will be
        registered with Frida, based on the current configuration.
        It uses the known_hooks module to map configuration keys to
        actual hook names.

        Returns:
            List of hook names suitable for registry with JobManager.
            Returns empty list if known_hooks module is unavailable.

        Example:
            hooks = config.get_hooks_for_registry()
            job_manager.start_job(
                script_path,
                hooks_registry=hooks,
            )
        """
        try:
            from sandroid.core.known_hooks import get_malwaremonitor_hooks_for_config

            with self._lock:
                native_hooks, java_hooks = get_malwaremonitor_hooks_for_config(
                    self._config
                )
                return native_hooks + java_hooks

        except ImportError:
            logger.debug("known_hooks module not available for registry hooks")
            return []
        except Exception as e:
            logger.debug(f"Could not get hooks for registry: {e}")
            return []

    def check_conflicts(self) -> dict[str, str]:
        """Check for hook conflicts with other running Frida tools.

        This method checks the Toolbox hook registry for potential
        conflicts based on the currently enabled hooks.

        Returns:
            Dictionary mapping conflicting hook names to the job IDs
            that registered them. Empty dict if no conflicts or if
            conflict checking is unavailable.

        Example:
            conflicts = config.check_conflicts()
            if conflicts:
                for hook, job_id in conflicts.items():
                    print(f"Warning: {hook} conflicts with job {job_id}")
        """
        try:
            from sandroid.core.toolbox import Toolbox

            # Get hooks that would be registered
            hooks_to_check = self.get_hooks_for_registry()

            if not hooks_to_check:
                return {}

            # Check for conflicts using Toolbox
            return Toolbox.check_frida_hook_conflicts(hooks_to_check)

        except ImportError:
            logger.debug("Toolbox not available for conflict checking")
            return {}
        except AttributeError:
            logger.debug("Toolbox does not have check_frida_hook_conflicts method")
            return {}
        except Exception as e:
            logger.debug(f"Could not check for hook conflicts: {e}")
            return {}

    def enable_hook(self, hook_name: str) -> bool:
        """Enable a specific hook.

        Args:
            hook_name: The name of the hook to enable

        Returns:
            True if the hook was found and enabled, False otherwise

        Example:
            if config.enable_hook("aes_hooks"):
                print("AES monitoring enabled")
        """
        with self._lock:
            if hook_name in self._config:
                self._config[hook_name] = True
                logger.debug(f"Enabled hook: {hook_name}")
                return True
            logger.warning(f"Unknown hook: {hook_name}")
            return False

    def disable_hook(self, hook_name: str) -> bool:
        """Disable a specific hook.

        Args:
            hook_name: The name of the hook to disable

        Returns:
            True if the hook was found and disabled, False otherwise

        Example:
            if config.disable_hook("bypass_hooks"):
                print("Bypass hooks disabled")
        """
        with self._lock:
            if hook_name in self._config:
                self._config[hook_name] = False
                logger.debug(f"Disabled hook: {hook_name}")
                return True
            logger.warning(f"Unknown hook: {hook_name}")
            return False

    def is_hook_enabled(self, hook_name: str) -> bool:
        """Check if a specific hook is enabled.

        Args:
            hook_name: The name of the hook to check

        Returns:
            True if the hook is enabled, False otherwise or if unknown

        Example:
            if config.is_hook_enabled("aes_hooks"):
                print("AES monitoring is active")
        """
        with self._lock:
            return self._config.get(hook_name, False)

    def get_hooks_in_group(self, group_key: str) -> list[str]:
        """Get all hook names in a specific group.

        Args:
            group_key: The group key (e.g., "crypto", "network")

        Returns:
            List of hook names in the group, empty list if group not found

        Example:
            crypto_hooks = config.get_hooks_in_group("crypto")
            print(f"Crypto group contains: {crypto_hooks}")
        """
        with self._lock:
            group = self._hook_groups.get(group_key)
            if not group:
                return []
            return list(group.hooks)

    def get_group_status(self) -> dict[str, bool]:
        """Get the enabled status of all groups.

        Returns:
            Dictionary mapping group keys to their enabled status
            (True if any hook in the group is enabled)

        Example:
            status = config.get_group_status()
            for group, enabled in status.items():
                print(f"{group}: {'ON' if enabled else 'OFF'}")
        """
        with self._lock:
            return {
                group_key: self.is_group_enabled(group_key)
                for group_key in self._hook_groups
            }

    def reset_to_defaults(self) -> None:
        """Reset all hooks to their default configuration.

        Example:
            config.reset_to_defaults()
            print("Configuration reset to defaults")
        """
        with self._lock:
            self._config = self.DEFAULT_CONFIG.copy()
            logger.debug("Configuration reset to defaults")

    # -------------------------------------------------------------------------
    # Backward-compatible aliases
    # -------------------------------------------------------------------------
    # These aliases preserve the simpler API originally defined in
    # hook_config_ui.py so that existing callers (malwaremonitor, tests)
    # continue to work without changes.

    #: Alias for :attr:`DEFAULT_CONFIG` (legacy name from hook_config_ui).
    DEFAULT_HOOKS = DEFAULT_CONFIG

    def get_hooks(self) -> dict[str, bool]:
        """Alias for :meth:`get_config` (legacy hook_config_ui API)."""
        return self.get_config()

    def set_hooks(self, hooks: dict[str, bool]) -> None:
        """Update hook configuration (legacy hook_config_ui API).

        Unlike :meth:`set_config`, this accepts unknown hook names
        without logging warnings, matching the original permissive
        ``dict.update`` behaviour of the hook_config_ui version.
        """
        with self._lock:
            self._config.update(hooks)

    def is_enabled(self, hook_name: str) -> bool:
        """Alias for :meth:`is_hook_enabled` (legacy hook_config_ui API)."""
        return self.is_hook_enabled(hook_name)

    def enable(self, hook_name: str) -> bool:
        """Alias for :meth:`enable_hook` (legacy hook_config_ui API)."""
        return self.enable_hook(hook_name)

    def disable(self, hook_name: str) -> bool:
        """Alias for :meth:`disable_hook` (legacy hook_config_ui API)."""
        return self.disable_hook(hook_name)

    def toggle(self, hook_name: str) -> bool:
        """Toggle an individual hook on/off.

        Args:
            hook_name: The name of the hook to toggle.

        Returns:
            The new state of the hook after toggling.
        """
        with self._lock:
            current = self._config.get(hook_name, False)
            self._config[hook_name] = not current
            return self._config[hook_name]

    def get_enabled_count(self) -> int:
        """Get count of enabled hooks.

        Returns:
            Number of hooks currently enabled.
        """
        with self._lock:
            return sum(1 for v in self._config.values() if v)

    def __repr__(self) -> str:
        """Return a string representation of the configuration."""
        enabled_count = len(self.get_enabled_hooks())
        total_count = len(self._config)
        return f"HookConfiguration({enabled_count}/{total_count} hooks enabled)"


# Singleton instance for global access (optional pattern)
_default_hook_config: HookConfiguration | None = None


def get_hook_configuration() -> HookConfiguration:
    """Get or create the default HookConfiguration singleton.

    This provides a convenient way to access a shared hook configuration
    instance across the application, similar to other Sandroid services.

    Returns:
        The default HookConfiguration instance

    Example:
        from sandroid.analysis.hook_config import get_hook_configuration

        config = get_hook_configuration()
        if config.is_group_enabled("crypto"):
            print("Crypto monitoring is globally enabled")
    """
    global _default_hook_config
    if _default_hook_config is None:
        _default_hook_config = HookConfiguration()
    return _default_hook_config


def reset_hook_configuration() -> None:
    """Reset the default HookConfiguration singleton.

    Useful for testing to ensure a clean state between tests.

    Example:
        reset_hook_configuration()
        config = get_hook_configuration()  # Fresh instance
    """
    global _default_hook_config
    _default_hook_config = None


# Backward-compatible constant: HOOK_GROUPS in the dict format originally
# defined in hook_config_ui.py.  This is derived from the canonical
# HOOK_GROUPS_DATA on HookConfiguration so there is a single source of truth.
HOOK_GROUPS: dict[str, dict[str, Any]] = HookConfiguration.HOOK_GROUPS_DATA


__all__ = [
    # Backward-compatible constant
    "HOOK_GROUPS",
    # Main class
    "HookConfiguration",
    # Protocol for DI
    "HookConfigurationProtocol",
    # Data class
    "HookGroupInfo",
    # Service locator functions
    "get_hook_configuration",
    "reset_hook_configuration",
]
