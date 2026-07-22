"""Bridge between ActionQ and the Command system.

This module provides functions to execute commands from ActionQ's
parse_interactive_char method, bridging the legacy architecture
with the new command pattern.

Usage:
    from sandroid.core.actionq_commands import execute_command_from_actionq, is_command_key

    # In parse_interactive_char:
    if is_command_key(char):
        result = execute_command_from_actionq(self, char)
        if result.should_return_to_menu:
            self.q.append("interactive")

Return:
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.commands import CommandRegistry, CommandResult
    from sandroid.core.actionQ import ActionQ

logger = logging.getLogger(__name__)


# Keys that are handled specially by ActionQ (not via command system)
# These require special handling that cannot be easily encapsulated in commands
SPECIAL_KEYS: set[str] = {
    # Snapshot keys (0-8) - handled by digit detection in parse_interactive_char
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    # TAB for view switching - needs direct access to Toolbox.cycle_view()
    "\t",
    # Help key - handled differently between TUI and Rich modes
    "?",
}


# Keys that are handled by the command system
# These correspond to CommandHandler implementations in sandroid.commands.*
COMMAND_KEYS: set[str] = {
    # Capture commands
    " ",  # Pull spotlight file
    "s",  # Screenshot
    "g",  # Screen recording (toggle)
    # Functionality commands
    "r",  # Record
    "p",  # Playback
    "t",  # TrigDroid
    # Frida commands
    "f",  # Frida server (toggle)
    # App commands
    "n",  # New APK installation
    "c",  # Attach mode - set spotlight app
    "C",  # Spawn mode - select app to spawn
    # Analysis commands
    "a",  # Static analysis
    "F",  # Forensic evidence scan (MVT)
    "d",  # Memory dump (Fridump)
    # Instrumentation commands
    "m",  # Dexray-Intercept (toggle)
    "k",  # Reconfigure hooks
    # Network commands
    "h",  # FriTap (toggle)
    "y",  # Proxy configuration
    "w",  # Network capture (toggle)
    # Monitoring commands
    "o",  # FSMon monitoring
    # Objection commands
    "b",  # Objection interactive shell
    "O",  # Objection resume session
    # Device commands
    "D",  # Device selector
    # IO commands
    "x",  # Export action
    "i",  # Import action
    # System commands
    "q",  # Quit
    "e",  # Emulator information
    "E",  # Device settings (Shift+E)
    # Forensic commands
    "l",  # Add spotlight file
    "v",  # Remove spotlight file
    "u",  # Pull spotlight files
}


def is_command_key(char: str) -> bool:
    r"""Check if a key is handled by the command system.

    This function determines whether a given keystroke should be
    routed to the command system or handled by ActionQ's legacy
    special-case logic.

    Args:
        char: The character/key pressed by the user

    Returns:
        True if the key should be handled by the command system,
        False if it should be handled by ActionQ's special logic

    Examples:
        >>> is_command_key("s")  # Screenshot
        True
        >>> is_command_key("0")  # Snapshot management
        False
        >>> is_command_key("\\t")  # Tab for view switching
        False
    """
    return char in COMMAND_KEYS


def is_special_key(char: str) -> bool:
    """Check if a key is a special key handled outside the command system.

    Args:
        char: The character/key pressed

    Returns:
        True if the key requires special handling by ActionQ
    """
    return char in SPECIAL_KEYS


def get_command_registry() -> CommandRegistry:
    """Get the initialized command registry singleton.

    This function ensures the registry is initialized with all default
    commands before returning it. Safe to call multiple times.

    Returns:
        CommandRegistry singleton instance with all commands registered

    Raises:
        ImportError: If the commands module cannot be imported
    """
    from sandroid.commands import CommandRegistry

    registry = CommandRegistry.get()

    # Initialize default commands if not already done
    if not registry._initialized:
        try:
            registry.initialize_default_commands()
            logger.debug("Command registry initialized with default commands")
        except Exception as e:
            logger.error(f"Failed to initialize command registry: {e}")
            raise

    return registry


def execute_command_from_actionq(
    action_queue: ActionQ, char: str, app: Any | None = None
) -> CommandResult:
    """Execute a command from ActionQ context.

    This function bridges ActionQ's parse_interactive_char method with
    the new command system. It creates a CommandContext from the current
    ActionQ state, looks up and executes the appropriate command handler,
    and returns the result.

    Args:
        action_queue: The ActionQ instance managing the analysis queue
        char: The character/key pressed by the user
        app: Optional reference to the running ``SandroidTUI`` app instance
            (passed through to the built ``CommandContext``). Only the TUI's
            live worker-thread dispatch (``MainScreen._execute_action_sync``)
            has one to pass.

    Returns:
        CommandResult containing:
            - success: Whether the command executed successfully
            - message: Human-readable result message
            - data: Optional structured data from the command
            - error: Optional error message if command failed
            - should_return_to_menu: Whether to append "interactive" to queue

    Example:
        result = execute_command_from_actionq(self, "s")
        if result.success:
            logger.info(result.message)
        if result.should_return_to_menu:
            self.q.append("interactive")
    """
    from sandroid.commands import CommandResult
    from sandroid.commands.context_factory import create_context_from_actionq

    try:
        # Get the command registry (initializes if needed)
        registry = get_command_registry()

        # Check if this key has a registered command
        if not registry.has(char):
            logger.warning(f"No command handler registered for key '{char}'")
            return CommandResult(
                success=False,
                message=f"No command handler for key '{char}'",
                error=f"Key '{char}' not found in command registry",
                should_return_to_menu=True,
            )

        # Create context from ActionQ
        context = create_context_from_actionq(action_queue, app=app)

        # Execute the command synchronously (ActionQ is not async)
        result = registry.execute_sync(char, context)

        # Log the result
        if result.success:
            logger.debug(f"Command '{char}' executed successfully: {result.message}")
        elif result.error == "Precondition not met":
            # Don't log warning for precondition failures - modal is shown to user
            logger.debug(f"Command '{char}' precondition not met: {result.message}")
        else:
            logger.warning(f"Command '{char}' failed: {result.error or result.message}")

        return result

    except ImportError as e:
        logger.error(f"Failed to import command system: {e}")
        return CommandResult(
            success=False,
            message="Command system not available",
            error=str(e),
            should_return_to_menu=True,
        )
    except Exception as e:
        logger.exception(f"Unexpected error executing command '{char}'")
        return CommandResult(
            success=False,
            message=f"Command execution failed: {e!s}",
            error=str(e),
            should_return_to_menu=True,
        )


def can_execute_command(
    char: str, action_queue: ActionQ | None = None
) -> tuple[bool, str]:
    """Check if a command can be executed in the current state.

    This function checks the preconditions for a command without
    actually executing it. Useful for updating UI state (e.g.,
    disabling menu items that cannot be executed).

    Args:
        char: The character/key to check
        action_queue: Optional ActionQ instance for full context

    Returns:
        Tuple of (can_execute, reason_if_not)
        - can_execute: True if the command can be executed
        - reason_if_not: Empty string if can execute, otherwise explanation

    Examples:
        >>> can_execute, reason = can_execute_command("m")
        >>> if not can_execute:
        ...     print(f"Cannot start monitoring: {reason}")
    """
    from sandroid.commands.context_factory import (
        create_context_from_actionq,
        create_minimal_context,
    )

    try:
        registry = get_command_registry()
        handler = registry.get_handler(char)

        if handler is None:
            return False, f"Unknown command: '{char}'"

        # Create context for checking preconditions
        if action_queue is not None:
            context = create_context_from_actionq(action_queue)
        else:
            context = create_minimal_context()

        return handler.can_execute(context)

    except Exception as e:
        logger.warning(f"Error checking command preconditions: {e}")
        return False, str(e)


def get_command_info(char: str) -> dict | None:
    """Get information about a command.

    Returns metadata about a command handler including its name,
    description, category, and available views.

    Args:
        char: The character/key to get info for

    Returns:
        Dictionary with command information or None if not found:
        {
            "key": "s",
            "name": "Screenshot",
            "description": "Take a screenshot of the current screen",
            "category": "capture",
            "views": ["forensic", "malware", "security"]
        }
    """
    try:
        registry = get_command_registry()
        handler = registry.get_handler(char)

        if handler is None:
            return None

        return {
            "key": handler.key,
            "name": handler.name,
            "description": handler.description,
            "category": handler.category.value if handler.category else None,
            "views": handler.views or [],
        }

    except Exception as e:
        logger.warning(f"Error getting command info: {e}")
        return None


def get_all_command_keys() -> set[str]:
    """Get all registered command keys.

    Returns:
        Set of all keyboard shortcuts that have registered handlers
    """
    try:
        registry = get_command_registry()
        return set(registry.get_keys())
    except Exception:
        # Fall back to static set if registry unavailable
        return COMMAND_KEYS.copy()


__all__ = [
    "COMMAND_KEYS",
    "SPECIAL_KEYS",
    "can_execute_command",
    "execute_command_from_actionq",
    "get_all_command_keys",
    "get_command_info",
    "get_command_registry",
    "is_command_key",
    "is_special_key",
]
