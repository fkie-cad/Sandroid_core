from abc import ABC, abstractmethod


class DataGather(ABC):
    """Abstract base class for all modules that perform some data gathering.

    **Methods:**

    - :meth:`gather`: Abstract method to gather data.
    - :meth:`return_data`: Abstract method to return gathered data.
    - :meth:`pretty_print`: Abstract method to pretty print the gathered data.
    """

    @abstractmethod
    def gather(self):
        """Gather data.

        **Raises:**

        - :class:`NotImplementedError`: If the method is not implemented in a subclass.
        """

    @abstractmethod
    def return_data(self):
        """Return gathered data.

        **Returns:**

        - **Any**: The gathered data.

        **Raises:**

        - :class:`NotImplementedError`: If the method is not implemented in a subclass.
        """

    @abstractmethod
    def pretty_print(self):
        """Pretty print the gathered data.

        **Raises:**

        - :class:`NotImplementedError`: If the method is not implemented in a subclass.
        """
