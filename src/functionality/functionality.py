from abc import ABC, abstractmethod


class Functionality(ABC):
    """Abstract base class for all modules that perform some functionality on the emulator.

    This class defines the common interface for all functionality modules. Subclasses must implement the
    `perform` method, which carries out the specific functionality. Additionally, when performing an action,
    it is essential to set the `action_time` in the toolbox.

    Attributes:
        None

    Methods:
        perform(): Abstract method to be implemented by subclasses. Performs the specific functionality.
            Must set the `action_time` in the toolbox.
            :returns: None
            :rtype: None
    """

    @abstractmethod
    def perform(self):
        # remember to always set the action_time in the toolbox when performing an action
        pass
