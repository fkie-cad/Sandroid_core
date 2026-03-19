"""Sandroid Command System.

This package implements the Command pattern for handling user interactions,
extracting the logic from the monolithic parse_interactive_char() method
into focused, testable command handlers.

Usage:
    from sandroid.commands import CommandRegistry, CommandContext, CommandResult

    # Get registry singleton
    registry = CommandRegistry.get()

    # Execute a command
    result = await registry.execute("s", context)  # Take screenshot

    # Check if command exists
    handler = registry.get("s")
    if handler:
        can_exec, reason = handler.can_execute(context)
"""

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
)
from .context_factory import (
    create_context_from_actionq,
    create_context_with_toolbox,
    create_minimal_context,
)
from .registry import CommandRegistry

__all__ = [
    "CommandCategory",
    "CommandContext",
    "CommandHandler",
    "CommandRegistry",
    "CommandResult",
    "create_context_from_actionq",
    "create_context_with_toolbox",
    "create_minimal_context",
]
