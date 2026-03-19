from abc import ABC, abstractmethod


class Functionality(ABC):
    """Abstract base class for all functionality modules on the emulator.

    Subclasses must implement ``perform()`` and should set ``action_time``
    in the Toolbox when performing an action.
    """

    @abstractmethod
    def perform(self) -> None:
        """Execute the functionality. Must set action_time in the Toolbox."""
