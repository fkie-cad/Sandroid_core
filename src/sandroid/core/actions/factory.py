"""Factory for creating ActionStrategy instances from queue items.

This module provides factory functions and a registry for creating
ActionStrategy instances from various types of queue items.

The Factory Pattern centralizes strategy creation logic, making it
easy to:
1. Handle different input types (Functionality, DataGather, str, callable)
2. Register custom strategy creators for new types
3. Maintain backwards compatibility with existing code

Usage:
    from sandroid.core.actions.factory import ActionFactory

    factory = ActionFactory()

    # Create strategy from various types
    strategy = factory.create(player_instance)      # FunctionalityAdapter
    strategy = factory.create(changed_files)        # DataGatherAdapter
    strategy = factory.create("baseline")           # StringCommandStrategy
    strategy = factory.create(lambda: do_thing())   # CallableAdapter

    # Check if item can be converted
    if factory.can_create(item):
        strategy = factory.create(item)

Custom Registration:
    # Register a custom creator
    def create_my_strategy(item):
        return MyCustomStrategy(item)

    factory.register(MyClass, create_my_strategy)
"""

import logging
from collections.abc import Callable
from typing import Any, Optional

from sandroid.core.actions.adapters import (
    CallableAdapter,
    DataGatherAdapter,
    FunctionalityAdapter,
)
from sandroid.core.actions.base import ActionStrategy

logger = logging.getLogger(__name__)


class StringCommandStrategy(ActionStrategy):
    """Strategy for string-based commands in the ActionQ.

    This strategy handles the string commands that the ActionQ processes,
    such as "baseline", "load_snapshot", "interactive", etc.

    The actual command execution is delegated to a command handler function
    that encapsulates the logic previously in ActionQ.do_next().

    Attributes:
        _command: The string command to execute
        _handler: Function that handles command execution
        _result_data: Optional data produced by the command

    Example:
        def handle_baseline():
            Toolbox.baseline = Toolbox.fetch_changed_files(fetch_all=True)

        strategy = StringCommandStrategy("baseline", handle_baseline)
        strategy.execute()
    """

    # Known commands that produce data
    DATA_PRODUCING_COMMANDS = frozenset(
        [
            "baseline",
            "pull0",
            "pull1",
            "pull_dry_run",
        ]
    )

    def __init__(self, command: str, handler: Callable[[], Any] | None = None) -> None:
        """Initialize with a string command.

        Args:
            command: The command string (e.g., "baseline", "load_snapshot")
            handler: Optional function to handle command execution.
                     If not provided, execute() will be a no-op.
        """
        self._command = command
        self._handler = handler
        self._result_data: dict[str, Any] = {}

    def execute(self) -> None:
        """Execute the string command.

        Calls the handler function if one was provided.
        The handler's return value is stored if it's a dictionary.
        """
        if self._handler is not None:
            result = self._handler()
            if isinstance(result, dict):
                self._result_data = result

    def get_name(self) -> str:
        """Get the command name.

        Returns:
            str: The string command
        """
        return self._command

    def get_data(self) -> dict[str, Any]:
        """Get any data produced by the command.

        Returns:
            Dict[str, Any]: Data from command execution, or empty dict
        """
        return self._result_data

    def is_data_gatherer(self) -> bool:
        """Check if this command produces data.

        Returns:
            bool: True if command is known to produce data
        """
        return self._command in self.DATA_PRODUCING_COMMANDS

    def get_command(self) -> str:
        """Get the raw command string.

        Returns:
            str: The command string
        """
        return self._command

    def __repr__(self) -> str:
        """Return string representation for debugging.

        Returns:
            str: String representation including command
        """
        has_handler = self._handler is not None
        return f"StringCommandStrategy(command={self._command!r}, has_handler={has_handler})"


# Type for strategy creator functions
StrategyCreator = Callable[[Any], ActionStrategy]


class ActionFactory:
    """Factory for creating ActionStrategy instances from queue items.

    This factory handles the creation of appropriate ActionStrategy
    implementations based on the type of item being added to the queue.

    It supports:
    - Functionality objects -> FunctionalityAdapter
    - DataGather objects -> DataGatherAdapter
    - String commands -> StringCommandStrategy
    - Callables -> CallableAdapter
    - Custom types via registration

    The factory can be extended with custom type handlers using register().

    Attributes:
        _creators: Registry of type -> creator function mappings
        _string_handlers: Registry of command -> handler function mappings

    Example:
        factory = ActionFactory()

        # Default handling
        strategy = factory.create(ChangedFiles())  # DataGatherAdapter

        # Register custom type
        factory.register(MyType, lambda x: MyStrategy(x))
        strategy = factory.create(MyType())  # MyStrategy
    """

    _instance: Optional["ActionFactory"] = None

    def __init__(self) -> None:
        """Initialize the factory with default creators."""
        self._creators: dict[type, StrategyCreator] = {}
        self._string_handlers: dict[str, Callable[[], Any]] = {}
        self._setup_default_creators()

    @classmethod
    def get(cls) -> "ActionFactory":
        """Get the singleton factory instance.

        Returns:
            ActionFactory: The singleton instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance.

        Primarily used for testing to ensure clean state.
        """
        cls._instance = None

    def _setup_default_creators(self) -> None:
        """Set up default type creators.

        Registers creators for Functionality and DataGather types.
        """
        # Import lazily to avoid circular imports
        try:
            from sandroid.features.functionality import Functionality

            self._creators[Functionality] = FunctionalityAdapter
        except ImportError:
            logger.debug("Functionality class not available for registration")

        try:
            from sandroid.analysis.datagather import DataGather

            self._creators[DataGather] = DataGatherAdapter
        except ImportError:
            logger.debug("DataGather class not available for registration")

    def register(self, item_type: type, creator: StrategyCreator) -> None:
        """Register a creator function for a type.

        Args:
            item_type: The type to register a creator for
            creator: Function that creates ActionStrategy from type instance

        Example:
            factory.register(MyClass, lambda x: MyStrategy(x))
        """
        self._creators[item_type] = creator
        logger.debug(f"Registered strategy creator for {item_type.__name__}")

    def register_string_handler(self, command: str, handler: Callable[[], Any]) -> None:
        """Register a handler for a string command.

        Args:
            command: The command string (e.g., "baseline")
            handler: Function to execute when the command runs

        Example:
            factory.register_string_handler(
                "baseline",
                lambda: Toolbox.baseline = Toolbox.fetch_changed_files()
            )
        """
        self._string_handlers[command] = handler
        logger.debug(f"Registered handler for command '{command}'")

    def can_create(self, item: Any) -> bool:
        """Check if the factory can create a strategy for the item.

        Args:
            item: The item to check

        Returns:
            bool: True if a strategy can be created for this item
        """
        # Check for direct type match
        if type(item) in self._creators:
            return True

        # Check for inheritance match
        for registered_type in self._creators:
            if isinstance(item, registered_type):
                return True

        # Strings are always supported
        if isinstance(item, str):
            return True

        # Callables are always supported
        if callable(item) and not isinstance(item, type):
            return True

        # Check if item already is an ActionStrategy
        if isinstance(item, ActionStrategy):
            return True

        return False

    def create(self, item: Any) -> ActionStrategy:
        """Create an ActionStrategy for the given item.

        Args:
            item: The item to create a strategy for. Can be:
                - Functionality instance
                - DataGather instance
                - String command
                - Callable
                - ActionStrategy (returned as-is)

        Returns:
            ActionStrategy: The appropriate strategy for the item

        Raises:
            TypeError: If no strategy can be created for the item

        Example:
            factory = ActionFactory.get()
            strategy = factory.create(ChangedFiles())
            strategy.execute()
        """
        # Already an ActionStrategy - return as-is
        if isinstance(item, ActionStrategy):
            return item

        # Check for direct type match first
        item_type = type(item)
        if item_type in self._creators:
            return self._creators[item_type](item)

        # Check for inheritance match
        for registered_type, creator in self._creators.items():
            if isinstance(item, registered_type):
                return creator(item)

        # Handle strings
        if isinstance(item, str):
            handler = self._string_handlers.get(item)
            return StringCommandStrategy(item, handler)

        # Handle callables
        if callable(item) and not isinstance(item, type):
            name = getattr(item, "__name__", "anonymous")
            return CallableAdapter(item, name=name)

        # Cannot create strategy
        raise TypeError(
            f"Cannot create ActionStrategy for item of type {item_type.__name__}. "
            f"Register a creator using factory.register({item_type.__name__}, creator_func)"
        )

    def create_batch(self, items: list[Any]) -> list[ActionStrategy]:
        """Create strategies for multiple items.

        Args:
            items: List of items to create strategies for

        Returns:
            List[ActionStrategy]: List of created strategies

        Raises:
            TypeError: If any item cannot be converted
        """
        return [self.create(item) for item in items]

    def get_registered_types(self) -> list[type]:
        """Get list of types with registered creators.

        Returns:
            List[Type]: List of registered types
        """
        return list(self._creators.keys())

    def get_registered_commands(self) -> list[str]:
        """Get list of string commands with registered handlers.

        Returns:
            List[str]: List of registered command strings
        """
        return list(self._string_handlers.keys())


def create_strategy(item: Any) -> ActionStrategy:
    """Convenience function to create a strategy using the singleton factory.

    Args:
        item: The item to create a strategy for

    Returns:
        ActionStrategy: The appropriate strategy for the item

    Example:
        from sandroid.core.actions.factory import create_strategy

        strategy = create_strategy(ChangedFiles())
        strategy.execute()
    """
    return ActionFactory.get().create(item)


def register_type(item_type: type, creator: StrategyCreator) -> None:
    """Convenience function to register a type creator.

    Args:
        item_type: The type to register
        creator: Function that creates ActionStrategy from type instance

    Example:
        register_type(MyClass, lambda x: MyStrategy(x))
    """
    ActionFactory.get().register(item_type, creator)


def register_command(command: str, handler: Callable[[], Any]) -> None:
    """Convenience function to register a string command handler.

    Args:
        command: The command string
        handler: Function to execute when command runs

    Example:
        register_command("my_command", lambda: do_something())
    """
    ActionFactory.get().register_string_handler(command, handler)


__all__ = [
    # Main classes
    "ActionFactory",
    # Type aliases
    "StrategyCreator",
    "StringCommandStrategy",
    # Convenience functions
    "create_strategy",
    "register_command",
    "register_type",
]
