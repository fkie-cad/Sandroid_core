"""Base strategy interface for ActionQ actions.

This module defines the ActionStrategy abstract base class that provides
a unified interface for all actions that can be executed by the ActionQ.

The Strategy Pattern allows the ActionQ to treat different action types
(Functionality, DataGather, string commands) uniformly through a common
interface, enabling:

1. Single Responsibility: Each strategy handles one type of action
2. Open/Closed: New action types can be added without modifying ActionQ
3. Dependency Inversion: ActionQ depends on abstraction, not concretions
4. Testability: Strategies can be easily mocked for unit testing

Architecture:
    ActionQ --> ActionStrategy (abstract)
                    |
                    +-- FunctionalityAdapter
                    +-- DataGatherAdapter
                    +-- StringCommandStrategy
                    +-- CustomActionStrategy

Usage:
    # Create a strategy
    strategy = FunctionalityAdapter(my_functionality)

    # Execute through common interface
    strategy.execute()

    # Get results if available
    if strategy.get_data():
        data = strategy.get_data()
        output = strategy.get_formatted_output()
"""

from abc import ABC, abstractmethod
from typing import Any


class ActionStrategy(ABC):
    """Base strategy interface for all action queue actions.

    This abstract base class defines the contract that all action
    strategies must fulfill. It enables the ActionQ to execute
    different types of actions uniformly.

    The interface provides:
    - execute(): Core execution method (required)
    - get_name(): Human-readable name for logging/display (required)
    - get_formatted_output(): Optional formatted output for display
    - get_data(): Optional data dictionary for JSON serialization
    - is_data_gatherer(): Check if strategy produces data

    Implementations:
        - FunctionalityAdapter: Wraps Functionality objects
        - DataGatherAdapter: Wraps DataGather objects
        - StringCommandStrategy: Handles string-based commands

    Example:
        class CustomStrategy(ActionStrategy):
            def __init__(self, callback):
                self._callback = callback
                self._result = None

            def execute(self) -> None:
                self._result = self._callback()

            def get_name(self) -> str:
                return "CustomAction"

            def get_data(self) -> Dict[str, Any]:
                return {"result": self._result} if self._result else {}
    """

    @abstractmethod
    def execute(self) -> None:
        """Execute the action.

        This method performs the primary operation of the strategy.
        It should be idempotent when possible and handle its own
        error reporting through logging.

        Raises:
            Exception: Implementation-specific exceptions may be raised
        """

    @abstractmethod
    def get_name(self) -> str:
        """Get a human-readable name for this action.

        Used for logging, progress display, and debugging. Should
        return a concise, descriptive name.

        Returns:
            str: Human-readable name for the action (e.g., "ChangedFiles",
                "Recorder", "load_snapshot")
        """

    def get_formatted_output(self) -> str:
        """Get formatted output suitable for display.

        This method returns a string representation of the action's
        results formatted for human consumption. Override this method
        in strategies that produce displayable output.

        Returns:
            str: Formatted output string, or empty string if no output
        """
        return ""

    def get_data(self) -> dict[str, Any]:
        """Get structured data from the action.

        This method returns a dictionary containing the action's
        results in a format suitable for JSON serialization.
        Override this in strategies that collect data.

        Returns:
            Dict[str, Any]: Data dictionary, or empty dict if no data
        """
        return {}

    def is_data_gatherer(self) -> bool:
        """Check if this strategy produces data.

        This method indicates whether the strategy collects data
        that should be included in the final results.

        Returns:
            bool: True if the strategy produces data, False otherwise
        """
        return False

    def get_priority(self) -> int:
        """Get execution priority for this action.

        Lower values indicate higher priority. Default is 100 (normal).
        Override for actions that should execute before or after others.

        Returns:
            int: Priority value (lower = higher priority)
        """
        return 100

    def can_execute(self) -> tuple[bool, str | None]:
        """Check if this action can be executed.

        Override to add precondition checks. Returns a tuple of
        (can_execute, reason) where reason explains why execution
        is not possible.

        Returns:
            tuple[bool, Optional[str]]: (True, None) if can execute,
                (False, reason) if cannot execute
        """
        return (True, None)

    def __repr__(self) -> str:
        """Return string representation for debugging.

        Returns:
            str: String representation including class and action name
        """
        return f"{self.__class__.__name__}(name={self.get_name()!r})"


class AsyncActionStrategy(ActionStrategy):
    """Base class for actions that support async execution.

    This class extends ActionStrategy to support both synchronous
    and asynchronous execution. Use this base class for actions
    that involve I/O operations or need async/await support.

    The execute() method provides synchronous compatibility,
    while execute_async() enables async execution.

    Example:
        class NetworkAction(AsyncActionStrategy):
            async def execute_async(self) -> None:
                result = await self._fetch_network_data()
                self._data = result

            def get_name(self) -> str:
                return "NetworkAction"
    """

    async def execute_async(self) -> None:
        """Async version of execute.

        Override this method for async action implementations.
        The default implementation calls the synchronous execute().

        Raises:
            Exception: Implementation-specific exceptions may be raised
        """
        self.execute()

    def is_async(self) -> bool:
        """Check if this action supports async execution.

        Returns:
            bool: True if execute_async is overridden, False otherwise
        """
        # Check if execute_async is overridden (not just using default)
        return type(self).execute_async is not AsyncActionStrategy.execute_async


__all__ = [
    "ActionStrategy",
    "AsyncActionStrategy",
]
