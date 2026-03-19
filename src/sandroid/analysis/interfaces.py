"""Segregated interfaces for data gathering modules.

This module provides segregated interfaces following the Interface Segregation
Principle (ISP). Instead of forcing all implementations to provide gather(),
return_data(), AND pretty_print() methods, components can implement only
the interfaces they need.

The original DataGather class forced all three methods on every implementation,
even though:
- Some modules only need to gather data
- Some modules don't need formatting
- Presentation logic should be separate from data gathering

New Interface Structure:
    - DataGatherer: Core data collection (gather method)
    - DataProvider: Data retrieval (return_data method)
    - Formattable: Optional formatting (format_output method)
    - DataGatherModule: Composite interface for backwards compatibility

Usage:
    # New approach - implement only what you need
    class MyCollector(DataGatherer):
        def gather(self) -> None:
            self._data = collect_something()

    # Or use the composite for full functionality
    class FullModule(DataGatherModule):
        def gather(self) -> None: ...
        def return_data(self) -> Dict[str, Any]: ...
        def format_output(self, formatter: OutputFormatter) -> str: ...

Migration Path:
    Existing DataGather implementations can continue to work by:
    1. Inheriting from DataGatherModule (composite interface)
    2. Renaming pretty_print() to format_output() with formatter parameter
    3. Gradually refactoring to use dependency injection
"""

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from sandroid.core.formatting import OutputFormatter


class DataGatherer(ABC):
    """Interface for components that collect data.

    This is the core interface for data collection. Implementations should
    focus solely on gathering data, not on how that data is formatted or
    presented.

    Example:
        class FileChangeGatherer(DataGatherer):
            def __init__(self, adb_service):
                self.adb = adb_service
                self._changes = []

            def gather(self) -> None:
                self._changes = self.adb.get_file_changes()
    """

    @abstractmethod
    def gather(self) -> None:
        """Gather data from the source.

        This method should collect data and store it internally.
        It should NOT return the data directly - use DataProvider
        interface for data retrieval.

        Raises:
            NotImplementedError: If not implemented in subclass
        """


class DataProvider(ABC):
    """Interface for components that provide collected data.

    This interface is for retrieving data that has been gathered.
    It's separate from DataGatherer to allow read-only access to
    data without triggering collection.

    Example:
        class FileChangeProvider(DataProvider):
            def return_data(self) -> Dict[str, Any]:
                return {
                    "changed_files": self._changed_files,
                    "new_files": self._new_files,
                    "count": len(self._changed_files)
                }
    """

    @abstractmethod
    def return_data(self) -> dict[str, Any]:
        """Return the gathered data as a dictionary.

        Returns:
            Dictionary containing the gathered data.
            Structure depends on implementation.

        Raises:
            NotImplementedError: If not implemented in subclass
        """


class Formattable(ABC):
    """Interface for components that can format their output.

    This is an OPTIONAL interface. Not all data gatherers need
    presentation logic. When formatting is needed, this interface
    allows injecting a formatter rather than hard-coding presentation.

    Example:
        class FileChangeFormatter(Formattable):
            def format_output(self, formatter: OutputFormatter) -> str:
                header = formatter.create_section_header("CHANGED FILES")
                content = self._format_changes()
                footer = formatter.create_section_footer()
                return header + content + footer
    """

    @abstractmethod
    def format_output(self, formatter: OutputFormatter) -> str:
        """Format the data for output/display.

        Args:
            formatter: OutputFormatter instance to use for formatting

        Returns:
            Formatted string representation of the data

        Raises:
            NotImplementedError: If not implemented in subclass
        """


@runtime_checkable
class HasData(Protocol):
    """Protocol for checking if an object has data available.

    This protocol allows runtime checking of whether an object
    can provide data, without requiring inheritance.

    Example:
        if isinstance(obj, HasData):
            data = obj.return_data()
    """

    def return_data(self) -> dict[str, Any]:
        """Return the gathered data."""
        ...


@runtime_checkable
class CanGather(Protocol):
    """Protocol for checking if an object can gather data.

    This protocol allows runtime checking of whether an object
    can perform data gathering, without requiring inheritance.

    Example:
        if isinstance(obj, CanGather):
            obj.gather()
    """

    def gather(self) -> None:
        """Gather data from the source."""
        ...


# =============================================================================
# Service Protocols for Dependency Injection
# =============================================================================


@runtime_checkable
class ToolUsageProtocol(Protocol):
    """Protocol for tool usage tracking.

    Defines the interface for marking tools as used during analysis,
    which is displayed in the exit summary.

    Example:
        class MyAnalysis(DataGatherBase):
            def gather(self):
                # Mark tool as used
                self._mark_tool_used("my-tool", "My Analysis Tool")
    """

    def mark_tool_used(
        self,
        tool_name: str,
        display_name: str,
        instance: Any = None,
        stop_callback: Any | None = None,
    ) -> None:
        """Mark a tool as currently in use.

        Args:
            tool_name: Internal identifier for the tool
            display_name: Human-readable name for display
            instance: Optional tool instance reference
            stop_callback: Optional callback to stop the tool
        """
        ...

    def is_tool_running(self, tool_name: str) -> bool:
        """Check if a tool is currently running.

        Args:
            tool_name: Internal identifier for the tool

        Returns:
            True if the tool is currently running
        """
        ...

    def get_tools_used(self) -> list[str]:
        """Get list of tools that have been used.

        Returns:
            List of tool display names
        """
        ...


@runtime_checkable
class StateManagementProtocol(Protocol):
    """Protocol for application state management.

    Defines the interface for managing boolean state flags that
    are used across different analysis modules.

    Example:
        if state_service.is_capturing_network():
            # Skip network-related hooks
            pass
    """

    def is_capturing_network(self) -> bool:
        """Check if network capture is currently active.

        Returns:
            True if network capture is running
        """
        ...

    def set_capturing_network(self, value: bool) -> None:
        """Set the network capture state.

        Args:
            value: True to mark capture as active
        """
        ...

    def is_malware_monitor_running(self) -> bool:
        """Check if malware monitor is currently running.

        Returns:
            True if malware monitor is active
        """
        ...

    def set_malware_monitor_running(self, value: bool) -> None:
        """Set the malware monitor state.

        Args:
            value: True to mark monitor as active
        """
        ...

    def get_state(self, key: str, default: Any = None) -> Any:
        """Get a state value by key.

        Args:
            key: State key to retrieve
            default: Default value if key not found

        Returns:
            State value or default
        """
        ...

    def set_state(self, key: str, value: Any) -> None:
        """Set a state value.

        Args:
            key: State key to set
            value: Value to store
        """
        ...


@runtime_checkable
class FormattingProtocol(Protocol):
    """Protocol for text formatting utilities.

    Defines the interface for formatting output text, including
    timestamp highlighting and text truncation.

    Example:
        formatted = formatter.highlight_timestamps(raw_output)
        truncated = formatter.truncate(formatted, max_length=100)
    """

    def highlight_timestamps(self, text: str, color: str = "") -> str:
        """Highlight timestamps in text.

        Finds and highlights Unix timestamps and date patterns
        in the provided text using the specified color.

        Args:
            text: Text containing timestamps to highlight
            color: ANSI color code to use (empty for default)

        Returns:
            Text with highlighted timestamps
        """
        ...

    def truncate(self, text: str, max_length: int = 80) -> str:
        """Truncate text to maximum length.

        Truncates long lines and adds ellipsis indicator
        when text exceeds the specified length.

        Args:
            text: Text to truncate
            max_length: Maximum line length

        Returns:
            Truncated text
        """
        ...

    def truncate_lines(
        self,
        text: str,
        max_lines: int = 50,
        max_line_length: int = 150,
    ) -> str:
        """Truncate text by both line count and line length.

        Args:
            text: Text to truncate
            max_lines: Maximum number of lines
            max_line_length: Maximum length per line

        Returns:
            Truncated text with indicators
        """
        ...


class DataGatherModule(DataGatherer, DataProvider, Formattable):
    """Composite interface combining all data gather capabilities.

    This is the full interface equivalent to the original DataGather class.
    Use this when a module needs to:
    1. Gather data
    2. Provide data for consumption
    3. Format output for display

    This interface exists primarily for backwards compatibility and
    for modules that genuinely need all three capabilities.

    New modules should prefer implementing only the interfaces they need.

    Example:
        class ChangedFilesModule(DataGatherModule):
            def __init__(self, forensic_service, formatter):
                self.forensic = forensic_service
                self._formatter = formatter

            def gather(self) -> None:
                self._files = self.forensic.fetch_changed_files()

            def return_data(self) -> Dict[str, Any]:
                return {"changed_files": self._files}

            def format_output(self, formatter: OutputFormatter) -> str:
                return formatter.create_section_header("CHANGED FILES") + ...
    """


class LegacyDataGatherAdapter(DataGatherModule):
    """Adapter to bridge legacy DataGather implementations to new interfaces.

    This adapter allows existing DataGather subclasses to be used with
    the new interface system without modification. It wraps the legacy
    pretty_print() method into format_output().

    Usage:
        legacy_module = LegacyChangedFiles()  # Old DataGather subclass
        adapted = LegacyDataGatherAdapter(legacy_module)
        output = adapted.format_output(formatter)  # Calls pretty_print internally
    """

    def __init__(self, legacy_module: Any):
        """Initialize the adapter with a legacy DataGather module.

        Args:
            legacy_module: An instance of a legacy DataGather subclass
        """
        self._legacy = legacy_module

    def gather(self) -> None:
        """Delegate to legacy gather method."""
        self._legacy.gather()

    def return_data(self) -> dict[str, Any]:
        """Delegate to legacy return_data method."""
        return self._legacy.return_data()

    def format_output(self, formatter: OutputFormatter) -> str:
        """Call legacy pretty_print method.

        Note: The formatter parameter is ignored since legacy modules
        have hard-coded formatting. This maintains backwards compatibility.

        Args:
            formatter: Unused, exists for interface compliance

        Returns:
            Output from legacy pretty_print() method
        """
        return self._legacy.pretty_print()


# Type aliases for cleaner type hints
DataGathererType = DataGatherer
DataProviderType = DataProvider
FormattableType = Formattable
DataGatherModuleType = DataGatherModule


__all__ = [
    "CanGather",
    # Composite interface
    "DataGatherModule",
    "DataGatherModuleType",
    # Core interfaces
    "DataGatherer",
    # Type aliases
    "DataGathererType",
    "DataProvider",
    "DataProviderType",
    "Formattable",
    "FormattableType",
    "FormattingProtocol",
    # Protocols for runtime checking
    "HasData",
    # Adapter for backwards compatibility
    "LegacyDataGatherAdapter",
    "StateManagementProtocol",
    # Service protocols for dependency injection
    "ToolUsageProtocol",
]
