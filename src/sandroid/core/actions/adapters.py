"""Adapter strategies for Functionality and DataGather objects.

This module provides adapter classes that wrap existing Functionality
and DataGather objects to conform to the ActionStrategy interface.

The Adapter Pattern allows legacy classes to work with the new strategy-based
ActionQ without modification, enabling gradual migration while maintaining
backwards compatibility.

Key Adapters:
    - FunctionalityAdapter: Wraps Functionality objects (perform actions)
    - DataGatherAdapter: Wraps DataGather objects (collect data)

Usage:
    from sandroid.features.player import Player
    from sandroid.analysis.changedfiles import ChangedFiles

    # Wrap a Functionality object
    player = Player()
    strategy = FunctionalityAdapter(player)
    strategy.execute()  # Calls player.perform()

    # Wrap a DataGather object
    gatherer = ChangedFiles()
    strategy = DataGatherAdapter(gatherer)
    strategy.execute()  # Calls gatherer.gather()
    output = strategy.get_formatted_output()  # Calls gatherer.pretty_print()
    data = strategy.get_data()  # Calls gatherer.return_data()
"""

from typing import Any

from sandroid.core.actions.base import ActionStrategy


class FunctionalityAdapter(ActionStrategy):
    """Adapter that wraps Functionality objects to the ActionStrategy interface.

    This adapter allows Functionality objects (Player, Recorder, Trigdroid, etc.)
    to be used uniformly with other action types in the ActionQ.

    Functionality objects:
        - Have a perform() method that executes their action
        - May modify emulator state
        - Set action_time in Toolbox when performing
        - Do not produce data for output (not data gatherers)

    Attributes:
        _functionality: The wrapped Functionality instance
        _name_override: Optional custom name for this action

    Example:
        from sandroid.features.player import Player

        player = Player()
        strategy = FunctionalityAdapter(player)

        # Check name
        print(strategy.get_name())  # "Player"

        # Execute the functionality
        strategy.execute()

        # Check if it produces data
        strategy.is_data_gatherer()  # False
    """

    def __init__(self, functionality, name_override: str | None = None) -> None:
        """Initialize the adapter with a Functionality object.

        Args:
            functionality: A Functionality instance (Player, Recorder, etc.)
            name_override: Optional custom name to use instead of class name

        Raises:
            TypeError: If functionality doesn't have a perform() method
        """
        if not hasattr(functionality, "perform") or not callable(functionality.perform):
            raise TypeError(
                f"Expected Functionality object with perform() method, "
                f"got {type(functionality).__name__}"
            )
        self._functionality = functionality
        self._name_override = name_override

    def execute(self) -> None:
        """Execute the wrapped functionality.

        Calls the perform() method on the wrapped Functionality object.
        The perform() method is expected to set action_time in Toolbox.
        """
        self._functionality.perform()

    def get_name(self) -> str:
        """Get the name of this action.

        Returns the custom name if provided, otherwise returns the
        class name of the wrapped Functionality object.

        Returns:
            str: Human-readable name for this action
        """
        if self._name_override:
            return self._name_override
        return type(self._functionality).__name__

    def get_functionality(self):
        """Get the wrapped Functionality instance.

        Provides access to the underlying Functionality object for
        cases where direct access is needed.

        Returns:
            The wrapped Functionality instance
        """
        return self._functionality

    def __repr__(self) -> str:
        """Return string representation for debugging.

        Returns:
            str: String representation including wrapped class name
        """
        return (
            f"FunctionalityAdapter("
            f"functionality={type(self._functionality).__name__}, "
            f"name={self.get_name()!r})"
        )


class DataGatherAdapter(ActionStrategy):
    """Adapter that wraps DataGather objects to the ActionStrategy interface.

    This adapter allows DataGather objects (ChangedFiles, NewFiles, Processes,
    etc.) to be used uniformly with other action types in the ActionQ.

    DataGather objects:
        - Have a gather() method that collects data
        - Have a return_data() method that returns collected data as dict
        - Have a pretty_print() method that returns formatted output
        - Are data producers (is_data_gatherer() returns True)

    Attributes:
        _gatherer: The wrapped DataGather instance
        _name_override: Optional custom name for this action
        _gathered: Flag indicating if gather() has been called

    Example:
        from sandroid.analysis.changedfiles import ChangedFiles

        gatherer = ChangedFiles()
        strategy = DataGatherAdapter(gatherer)

        # Execute data gathering
        strategy.execute()

        # Get results
        data = strategy.get_data()
        output = strategy.get_formatted_output()

        # Check if it produces data
        strategy.is_data_gatherer()  # True
    """

    def __init__(self, gatherer, name_override: str | None = None) -> None:
        """Initialize the adapter with a DataGather object.

        Args:
            gatherer: A DataGather instance (ChangedFiles, NewFiles, etc.)
            name_override: Optional custom name to use instead of class name

        Raises:
            TypeError: If gatherer doesn't have required methods
        """
        if not hasattr(gatherer, "gather") or not callable(gatherer.gather):
            raise TypeError(
                f"Expected DataGather object with gather() method, "
                f"got {type(gatherer).__name__}"
            )
        self._gatherer = gatherer
        self._name_override = name_override
        self._gathered = False

    def execute(self) -> None:
        """Execute data gathering.

        Calls the gather() method on the wrapped DataGather object.
        Sets the _gathered flag to indicate data is available.
        """
        self._gatherer.gather()
        self._gathered = True

    def get_name(self) -> str:
        """Get the name of this action.

        Returns the custom name if provided, otherwise returns the
        class name of the wrapped DataGather object.

        Returns:
            str: Human-readable name for this action
        """
        if self._name_override:
            return self._name_override
        return type(self._gatherer).__name__

    def get_formatted_output(self) -> str:
        """Get formatted output from the gatherer.

        Calls pretty_print() on the wrapped DataGather object to
        get a human-readable representation of the collected data.

        Returns:
            str: Formatted output string, or empty if not gathered
        """
        if hasattr(self._gatherer, "pretty_print"):
            return self._gatherer.pretty_print()
        return ""

    def get_data(self) -> dict[str, Any]:
        """Get collected data from the gatherer.

        Calls return_data() on the wrapped DataGather object to
        get the data in dictionary format for JSON serialization.

        Returns:
            Dict[str, Any]: Data dictionary, or empty if not gathered
        """
        if hasattr(self._gatherer, "return_data"):
            return self._gatherer.return_data()
        return {}

    def is_data_gatherer(self) -> bool:
        """Check if this is a data gatherer.

        DataGatherAdapter always returns True since it wraps
        data gathering objects.

        Returns:
            bool: Always True
        """
        return True

    def has_gathered(self) -> bool:
        """Check if gather() has been called.

        Returns:
            bool: True if execute() has been called, False otherwise
        """
        return self._gathered

    def get_gatherer(self):
        """Get the wrapped DataGather instance.

        Provides access to the underlying DataGather object for
        cases where direct access is needed.

        Returns:
            The wrapped DataGather instance
        """
        return self._gatherer

    def __repr__(self) -> str:
        """Return string representation for debugging.

        Returns:
            str: String representation including wrapped class name
        """
        return (
            f"DataGatherAdapter("
            f"gatherer={type(self._gatherer).__name__}, "
            f"name={self.get_name()!r}, "
            f"gathered={self._gathered})"
        )


class CallableAdapter(ActionStrategy):
    """Adapter that wraps a callable (function/lambda) as an ActionStrategy.

    This adapter allows arbitrary callables to be used in the ActionQ,
    enabling custom actions without creating full strategy classes.

    Example:
        def my_custom_action():
            print("Doing something custom")

        strategy = CallableAdapter(my_custom_action, name="CustomAction")
        strategy.execute()
    """

    def __init__(
        self, callable_obj, name: str = "Callable", data_producer: bool = False
    ) -> None:
        """Initialize the adapter with a callable.

        Args:
            callable_obj: A callable (function, lambda, method)
            name: Human-readable name for this action
            data_producer: Whether this callable produces data

        Raises:
            TypeError: If callable_obj is not callable
        """
        if not callable(callable_obj):
            raise TypeError(f"Expected callable, got {type(callable_obj).__name__}")
        self._callable = callable_obj
        self._name = name
        self._data_producer = data_producer
        self._result = None

    def execute(self) -> None:
        """Execute the callable.

        The return value is stored and available via get_data() if
        it returns a dictionary.
        """
        self._result = self._callable()

    def get_name(self) -> str:
        """Get the name of this action.

        Returns:
            str: The name provided during initialization
        """
        return self._name

    def get_data(self) -> dict[str, Any]:
        """Get data from the callable's result.

        If the callable returned a dictionary, returns it.
        Otherwise returns an empty dictionary.

        Returns:
            Dict[str, Any]: Result dictionary or empty dict
        """
        if isinstance(self._result, dict):
            return self._result
        return {}

    def is_data_gatherer(self) -> bool:
        """Check if this callable produces data.

        Returns:
            bool: Value of data_producer parameter
        """
        return self._data_producer

    def __repr__(self) -> str:
        """Return string representation for debugging.

        Returns:
            str: String representation including callable info
        """
        callable_name = getattr(self._callable, "__name__", str(self._callable))
        return f"CallableAdapter(callable={callable_name}, name={self._name!r})"


__all__ = [
    "CallableAdapter",
    "DataGatherAdapter",
    "FunctionalityAdapter",
]
