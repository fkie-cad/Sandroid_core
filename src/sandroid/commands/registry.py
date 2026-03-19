"""Command Registry for managing command handlers.

This module provides a singleton registry for all command handlers,
enabling lookup by key and execution of commands.

Usage:
    from sandroid.commands.registry import CommandRegistry

    # Get singleton instance
    registry = CommandRegistry.get()

    # Execute a command
    result = await registry.execute("s", context)

    # Get all commands in a category
    forensic_commands = registry.get_by_category(CommandCategory.FORENSIC)

    # Register a custom command
    registry.register(MyCustomCommand())
"""

import logging
from typing import Optional

from typing_extensions import Self

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class CommandRegistry:
    """Singleton registry for command handlers.

    The registry maintains a mapping of keyboard shortcuts to command
    handlers and provides methods for executing commands, querying
    available commands, and filtering by category or view.

    Thread Safety:
        The registry is thread-safe for registration and lookup.
        Command execution thread safety depends on the handler.

    Example:
        registry = CommandRegistry.get()

        # Register commands
        registry.register(ScreenshotCommand())
        registry.register(RecordingCommand())

        # Execute by key
        result = await registry.execute("s", context)

        # Get available commands for a view
        commands = registry.get_by_view("forensic")
    """

    _instance: Optional["CommandRegistry"] = None
    _handlers: dict[str, CommandHandler]
    _initialized: bool

    def __new__(cls) -> Self:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._handlers = {}
            cls._instance._initialized = False
        return cls._instance

    @classmethod
    def get(cls) -> "CommandRegistry":
        """Get the singleton registry instance.

        Returns:
            CommandRegistry singleton instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None

    def register(self, handler: CommandHandler) -> None:
        """Register a command handler.

        Args:
            handler: CommandHandler instance to register

        Raises:
            ValueError: If handler.key is empty or already registered
        """
        if not handler.key:
            raise ValueError(f"Command handler {handler.__class__.__name__} has no key")

        if handler.key in self._handlers:
            logger.warning(
                f"Overwriting existing handler for key '{handler.key}': "
                f"{self._handlers[handler.key].name} -> {handler.name}"
            )

        self._handlers[handler.key] = handler
        logger.debug(f"Registered command: [{handler.key}] {handler.name}")

    def register_class(self, handler_class: type[CommandHandler]) -> None:
        """Register a command handler from its class.

        Creates an instance of the handler class and registers it.

        Args:
            handler_class: CommandHandler subclass to instantiate and register
        """
        handler = handler_class()
        self.register(handler)

    def unregister(self, key: str) -> bool:
        """Unregister a command handler.

        Args:
            key: Keyboard shortcut to unregister

        Returns:
            True if handler was found and removed, False otherwise
        """
        if key in self._handlers:
            del self._handlers[key]
            logger.debug(f"Unregistered command: [{key}]")
            return True
        return False

    def get_handler(self, key: str) -> CommandHandler | None:
        """Get a command handler by key.

        Args:
            key: Keyboard shortcut

        Returns:
            CommandHandler instance or None if not found
        """
        return self._handlers.get(key)

    def has(self, key: str) -> bool:
        """Check if a handler is registered for a key.

        Args:
            key: Keyboard shortcut

        Returns:
            True if handler exists for this key
        """
        return key in self._handlers

    def get_all(self) -> list[CommandHandler]:
        """Get all registered command handlers.

        Returns:
            List of all registered handlers
        """
        return list(self._handlers.values())

    def get_by_category(self, category: CommandCategory) -> list[CommandHandler]:
        """Get all handlers in a specific category.

        Args:
            category: Category to filter by

        Returns:
            List of handlers in the category
        """
        return [h for h in self._handlers.values() if h.category == category]

    def get_by_view(self, view: str) -> list[CommandHandler]:
        """Get all handlers available in a specific view.

        Args:
            view: View name (e.g., "forensic", "malware", "security")

        Returns:
            List of handlers available in the view
        """
        return [h for h in self._handlers.values() if not h.views or view in h.views]

    def get_keys(self) -> list[str]:
        """Get all registered keyboard shortcuts.

        Returns:
            List of registered keys
        """
        return list(self._handlers.keys())

    async def execute(self, key: str, ctx: CommandContext) -> CommandResult:
        """Execute a command by its keyboard shortcut.

        Args:
            key: Keyboard shortcut
            ctx: Command context

        Returns:
            CommandResult from the handler or error result if not found
        """
        handler = self.get_handler(key)
        if handler is None:
            return CommandResult(
                success=False,
                message=f"Unknown command: '{key}'",
                error=f"No handler registered for key '{key}'",
            )

        # Check preconditions
        can_exec, reason = handler.can_execute(ctx)
        if not can_exec:
            return CommandResult(
                success=False, message=reason, error="Precondition not met"
            )

        # Execute the command
        try:
            logger.debug(f"Executing command: [{key}] {handler.name}")
            result = await handler.execute(ctx)

            # Publish event if event bus available
            self._publish_command_event(handler, result, ctx)

            return result
        except Exception as e:
            logger.exception(f"Error executing command [{key}] {handler.name}")
            return CommandResult(
                success=False, message=f"Command failed: {e!s}", error=str(e)
            )

    def execute_sync(self, key: str, ctx: CommandContext) -> CommandResult:
        """Execute a command synchronously (for non-async contexts).

        For commands with blocking I/O (is_blocking_io=True), calls execute_blocking()
        directly to avoid asyncio.run() conflicts with libraries like Frida.

        Args:
            key: Keyboard shortcut
            ctx: Command context

        Returns:
            CommandResult from the handler
        """
        import asyncio
        import threading

        # Get the handler to check if it needs blocking execution
        handler = self._handlers.get(key)
        if handler and getattr(handler, "is_blocking_io", False):
            # Command has blocking I/O - call execute_blocking() directly
            # This avoids asyncio.run() which can conflict with Frida's threading
            logger.debug(f"Using blocking execution path for {handler.name}")
            try:
                # Check preconditions first
                can_exec, reason = handler.can_execute(ctx)
                if not can_exec:
                    return CommandResult(
                        success=False,
                        message=reason,
                        error="Precondition not met",
                    )
                return handler.execute_blocking(ctx)
            except Exception as e:
                logger.exception(f"Error in blocking execution of {handler.name}")
                return CommandResult(
                    success=False, message=f"Command failed: {e!s}", error=str(e)
                )

        # Normal async path for non-blocking commands
        try:
            # Check if we're in the main thread
            if threading.current_thread() is not threading.main_thread():
                # We're in a worker thread - can safely use asyncio.run()
                # This avoids the blocking issue when TUI spawns worker threads
                return asyncio.run(self.execute(key, ctx))

            # We're in the main thread - check event loop state
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Main thread with running loop - need to use a new thread
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.execute(key, ctx))
                    return future.result()
            else:
                return loop.run_until_complete(self.execute(key, ctx))
        except RuntimeError:
            # No event loop, create one
            return asyncio.run(self.execute(key, ctx))

    def _publish_command_event(
        self, handler: CommandHandler, result: CommandResult, ctx: CommandContext
    ) -> None:
        """Publish a command executed event."""
        try:
            from sandroid.core.events import Event, EventBus, EventType

            event_bus = EventBus.get()
            event_bus.publish(
                Event(
                    type=EventType.STATE_CHANGED,
                    data={
                        "change_type": "command_executed",
                        "command_key": handler.key,
                        "command_name": handler.name,
                        "success": result.success,
                        "message": result.message,
                    },
                    source="command_registry",
                )
            )
        except ImportError:
            pass  # Events module not available

    # All command module names to load during initialization
    _COMMAND_MODULES = [
        "capture_commands",
        "forensic_commands",
        "app_commands",
        "frida_commands",
        "analysis_commands",
        "network_commands",
        "instrumentation_commands",
        "monitoring_commands",
        "objection_commands",
        "functionality_commands",
        "io_commands",
        "system_commands",
        "snapshot_commands",
        "device_commands",
        "memory_commands",
    ]

    def initialize_default_commands(self) -> None:
        """Register all default command handlers.

        This method imports and registers all built-in command handlers.
        Call this once during application startup.
        """
        if self._initialized:
            logger.debug("Command registry already initialized")
            return

        logger.info("Initializing default command handlers")

        import importlib

        for module_name in self._COMMAND_MODULES:
            try:
                module = importlib.import_module(f".{module_name}", package=__package__)
                module.register_commands(self)
            except ImportError as e:
                logger.warning(f"Could not load {module_name}: {e}")

        self._initialized = True
        logger.info(f"Registered {len(self._handlers)} command handlers")


__all__ = ["CommandRegistry"]
