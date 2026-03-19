"""Strategy pattern for ActionQ action execution.

This module provides a clean strategy pattern implementation for handling
different action types in the ActionQ. It abstracts the action execution
logic into separate strategy classes, making the code more maintainable
and testable.

Classes:
    ActionStrategy: Abstract base class for action strategies.
    FunctionalityAdapter: Strategy adapter for Functionality objects.
    DataGatherAdapter: Strategy adapter for DataGather objects.
    StringActionAdapter: Strategy adapter for string command actions.
    ActionFactory: Factory for creating appropriate strategies.
"""

from abc import ABC, abstractmethod
from typing import Any

from sandroid.analysis.datagather import DataGather
from sandroid.features.functionality import Functionality


class ActionStrategy(ABC):
    """Abstract base class for action execution strategies.

    All action strategies must implement the execute() method, which
    performs the actual action. The strategy pattern allows the ActionQ
    to handle different action types uniformly.

    Attributes:
        action: The wrapped action object.
    """

    def __init__(self, action: Any) -> None:
        """Initialize the strategy with an action.

        Args:
            action: The action to be executed by this strategy.
        """
        self._action = action

    @property
    def action(self) -> Any:
        """Get the wrapped action.

        Returns:
            The action object wrapped by this strategy.
        """
        return self._action

    @abstractmethod
    def execute(self) -> None:
        """Execute the action.

        This method must be implemented by concrete strategy classes
        to perform the actual action execution.

        Raises:
            NotImplementedError: If not implemented by subclass.
        """

    @abstractmethod
    def get_action_type(self) -> str:
        """Get the type of action for logging/display.

        Returns:
            A string describing the action type.
        """

    def get_action_name(self) -> str:
        """Get a human-readable name for the action.

        Returns:
            A string name for the action.
        """
        if isinstance(self._action, str):
            return self._action
        return type(self._action).__name__


class FunctionalityAdapter(ActionStrategy):
    """Strategy adapter for Functionality objects.

    Wraps Functionality objects and delegates execution to their
    perform() method. Functionality objects represent actions that
    perform some operation on the emulator.

    Example:
        >>> recorder = Recorder()
        >>> adapter = FunctionalityAdapter(recorder)
        >>> adapter.execute()  # Calls recorder.perform()
    """

    def __init__(self, functionality: Functionality) -> None:
        """Initialize with a Functionality object.

        Args:
            functionality: The Functionality object to wrap.

        Raises:
            TypeError: If functionality is not a Functionality instance.
        """
        if not isinstance(functionality, Functionality):
            raise TypeError(
                f"Expected Functionality instance, got {type(functionality).__name__}"
            )
        super().__init__(functionality)

    def execute(self) -> None:
        """Execute the functionality by calling perform().

        Delegates to the wrapped Functionality's perform() method.
        """
        self._action.perform()

    def get_action_type(self) -> str:
        """Get the action type.

        Returns:
            String 'functionality'.
        """
        return "functionality"

    @property
    def functionality(self) -> Functionality:
        """Get the wrapped Functionality object.

        Returns:
            The Functionality instance.
        """
        return self._action


class DataGatherAdapter(ActionStrategy):
    """Strategy adapter for DataGather objects.

    Wraps DataGather objects and delegates execution to their
    gather() method. DataGather objects collect data from the
    emulator during analysis.

    Example:
        >>> changed_files = ChangedFiles()
        >>> adapter = DataGatherAdapter(changed_files)
        >>> adapter.execute()  # Calls changed_files.gather()
    """

    def __init__(self, data_gather: DataGather) -> None:
        """Initialize with a DataGather object.

        Args:
            data_gather: The DataGather object to wrap.

        Raises:
            TypeError: If data_gather is not a DataGather instance.
        """
        if not isinstance(data_gather, DataGather):
            raise TypeError(
                f"Expected DataGather instance, got {type(data_gather).__name__}"
            )
        super().__init__(data_gather)

    def execute(self) -> None:
        """Execute the data gatherer by calling gather().

        Delegates to the wrapped DataGather's gather() method.
        """
        self._action.gather()

    def get_action_type(self) -> str:
        """Get the action type.

        Returns:
            String 'data_gather'.
        """
        return "data_gather"

    @property
    def data_gather(self) -> DataGather:
        """Get the wrapped DataGather object.

        Returns:
            The DataGather instance.
        """
        return self._action

    def return_data(self) -> dict[str, Any]:
        """Get data from the wrapped DataGather.

        Returns:
            Dictionary of gathered data.
        """
        return self._action.return_data()

    def pretty_print(self) -> str:
        """Get pretty-printed output from the DataGather.

        Returns:
            Formatted string representation of gathered data.
        """
        return self._action.pretty_print()


class StringActionAdapter(ActionStrategy):
    """Strategy adapter for string command actions.

    Wraps string actions that represent built-in commands like
    'baseline', 'load_snapshot', 'interactive', etc. Execution
    requires a callback handler that implements the actual logic.

    Example:
        >>> adapter = StringActionAdapter('load_snapshot', handler=my_handler)
        >>> adapter.execute()  # Calls my_handler('load_snapshot')
    """

    def __init__(self, action: str, handler: callable | None = None) -> None:
        """Initialize with a string action.

        Args:
            action: The string command to wrap.
            handler: Optional callback to handle execution.

        Raises:
            TypeError: If action is not a string.
        """
        if not isinstance(action, str):
            raise TypeError(f"Expected str instance, got {type(action).__name__}")
        super().__init__(action)
        self._handler = handler

    def execute(self) -> None:
        """Execute the string action through the handler.

        If a handler was provided, it is called with the action string.
        Otherwise, this is a no-op (the caller should handle execution).
        """
        if self._handler is not None:
            self._handler(self._action)

    def get_action_type(self) -> str:
        """Get the action type.

        Returns:
            String 'string_command'.
        """
        return "string_command"

    @property
    def command(self) -> str:
        """Get the command string.

        Returns:
            The string command.
        """
        return self._action

    def set_handler(self, handler: callable) -> None:
        """Set the execution handler.

        Args:
            handler: Callable to handle execution.
        """
        self._handler = handler

    def has_handler(self) -> bool:
        """Check if a handler is set.

        Returns:
            True if handler is set, False otherwise.
        """
        return self._handler is not None


class ActionFactory:
    """Factory for creating appropriate ActionStrategy instances.

    The factory inspects the action type and creates the appropriate
    strategy adapter. It supports Functionality, DataGather, and
    string actions.

    Example:
        >>> factory = ActionFactory()
        >>> strategy = factory.create(recorder)  # FunctionalityAdapter
        >>> strategy = factory.create(changed_files)  # DataGatherAdapter
        >>> strategy = factory.create('baseline')  # StringActionAdapter
    """

    def __init__(self, string_handler: callable | None = None) -> None:
        """Initialize the factory.

        Args:
            string_handler: Optional default handler for string actions.
        """
        self._string_handler = string_handler
        self._custom_handlers: dict[type, type[ActionStrategy]] = {}

    def create(
        self, action: Any, string_handler: callable | None = None
    ) -> ActionStrategy:
        """Create an appropriate strategy for the given action.

        Args:
            action: The action to wrap in a strategy.
            string_handler: Optional handler specifically for this string action.

        Returns:
            An ActionStrategy instance appropriate for the action type.

        Raises:
            ValueError: If the action type is not supported.
        """
        # Check for custom handlers first
        action_type = type(action)
        if action_type in self._custom_handlers:
            return self._custom_handlers[action_type](action)

        # Built-in type handling
        if isinstance(action, Functionality):
            return FunctionalityAdapter(action)

        if isinstance(action, DataGather):
            return DataGatherAdapter(action)

        if isinstance(action, str):
            handler = string_handler or self._string_handler
            return StringActionAdapter(action, handler=handler)

        raise ValueError(
            f"Unsupported action type: {type(action).__name__}. "
            f"Expected Functionality, DataGather, or str."
        )

    def register_handler(
        self, action_type: type, strategy_class: type[ActionStrategy]
    ) -> None:
        """Register a custom handler for an action type.

        This allows extending the factory with custom action types
        and their corresponding strategy classes.

        Args:
            action_type: The type of action to handle.
            strategy_class: The strategy class to use for this type.
        """
        self._custom_handlers[action_type] = strategy_class

    def unregister_handler(self, action_type: type) -> bool:
        """Unregister a custom handler.

        Args:
            action_type: The action type to unregister.

        Returns:
            True if handler was removed, False if not found.
        """
        if action_type in self._custom_handlers:
            del self._custom_handlers[action_type]
            return True
        return False

    def supports(self, action: Any) -> bool:
        """Check if the factory can handle this action type.

        Args:
            action: The action to check.

        Returns:
            True if the action type is supported.
        """
        action_type = type(action)

        if action_type in self._custom_handlers:
            return True

        return isinstance(action, (Functionality, DataGather, str))

    def get_supported_types(self) -> list:
        """Get list of supported action types.

        Returns:
            List of supported type names.
        """
        base_types = ["Functionality", "DataGather", "str"]
        custom_types = [t.__name__ for t in self._custom_handlers.keys()]
        return base_types + custom_types

    def set_default_string_handler(self, handler: callable) -> None:
        """Set the default handler for string actions.

        Args:
            handler: Callable to use as default string handler.
        """
        self._string_handler = handler
