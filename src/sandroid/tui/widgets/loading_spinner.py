"""Reusable loading spinner widget.

Combines a Textual LoadingIndicator with status message and optional hint text.
"""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.widgets import LoadingIndicator, Static


class LoadingSpinner(Vertical):
    """A compound loading widget with animated spinner, message, and optional hint.

    Usage:
        spinner = LoadingSpinner(message="Loading...", hint="Please wait")
        spinner.update_message("Still loading...")
        spinner.update_hint("Almost done")
    """

    DEFAULT_CSS = """
    LoadingSpinner {
        align: center middle;
        height: auto;
        width: 100%;
        padding: 1 2;
    }

    LoadingSpinner LoadingIndicator {
        height: 1;
        width: 100%;
    }

    LoadingSpinner .spinner-message {
        color: $warning;
        text-align: center;
        text-style: bold;
        width: 100%;
        height: auto;
    }

    LoadingSpinner .spinner-hint {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
    }
    """

    def __init__(
        self,
        message: str = "",
        hint: str = "",
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the loading spinner.

        Args:
            message: Status message displayed below the spinner.
            hint: Optional hint text displayed below the message.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(id=id, classes=classes)
        self._message = message
        self._hint = hint

    def compose(self) -> ComposeResult:
        """Create the spinner layout."""
        yield LoadingIndicator()
        yield Static(self._message, classes="spinner-message")
        hint_classes = "spinner-hint" if self._hint else "spinner-hint hidden"
        yield Static(self._hint, classes=hint_classes)

    def update_message(self, message: str) -> None:
        """Update the status message.

        Args:
            message: New status message text.
        """
        self._message = message
        try:
            self.query_one(".spinner-message", Static).update(message)
        except NoMatches:
            pass

    def update_hint(self, hint: str) -> None:
        """Update the hint text.

        Args:
            hint: New hint text. If empty, hides the hint widget.
        """
        self._hint = hint
        try:
            hint_widget = self.query_one(".spinner-hint", Static)
            hint_widget.update(hint)
            if hint:
                hint_widget.remove_class("hidden")
            else:
                hint_widget.add_class("hidden")
        except NoMatches:
            pass
