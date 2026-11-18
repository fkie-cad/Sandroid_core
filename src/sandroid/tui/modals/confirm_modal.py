"""Confirmation modal dialog."""

import time

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label

from .base import ForensicModal, KeyHintFooter


class ConfirmModal(ForensicModal[bool]):
    """Modal for yes/no confirmation.

    Features:
    - Yes/No buttons
    - Keyboard shortcuts (y/n)
    - Escape defaults to No
    - Returns True for Yes, False for No
    - ``guard_typing=True`` (Play, stop replay): the dialog guards a
      destructive single-letter command against stray typing -- a word typed
      while focus was not in a text field ("places" → ``p`` Play). No has the
      focus (Enter declines), ``y``/Yes are ignored for ``ARM_SECONDS`` after
      the dialog opened (typed-ahead keys), and any other letter or digit
      closes it as No ("that looked like typing").
    """

    DEFAULT_CSS = """
    ConfirmModal .modal-container {
        width: 50;
        max-width: 80%;
        max-height: 80%;
    }

    ConfirmModal .modal-message {
        width: 100%;
        padding-bottom: 1;
    }

    /* Yes button - primary action */
    ConfirmModal Button.-primary {
        background: $success;
        color: #ffffff;
    }

    ConfirmModal Button.-primary:hover {
        background: $success-darken-1;
    }

    /* Override Textual's default button styling for primary */
    ConfirmModal .button-row Button.-style-default.-primary,
    ConfirmModal .button-row Button.-style-default.-primary:hover,
    ConfirmModal .button-row Button.-style-default.-primary:focus {
        background: $success;
        color: #ffffff;
    }

    ConfirmModal .button-row Button.-style-default.-primary:hover {
        background: $success-darken-1;
    }
    """

    BINDINGS = [
        Binding("y", "yes", "Yes", show=False),
        Binding("n", "no", "No", show=False),
    ]

    #: Seconds a guarded dialog ignores ``y`` / Yes after it opened.
    ARM_SECONDS = 0.4

    def __init__(
        self,
        title: str,
        message: str = "",
        yes_label: str = "Yes",
        no_label: str = "No",
        name: str = None,
        id: str = None,
        classes: str = None,
        guard_typing: bool = False,
    ):
        """Initialize the confirmation modal.

        Args:
            title: Dialog title
            message: Optional description text
            yes_label: Label for the Yes button
            no_label: Label for the No button
            name: Widget name
            id: Widget ID
            classes: CSS classes
            guard_typing: Guard against stray typing (see the class doc).
        """
        super().__init__(name=name, id=id, classes=classes)
        self.guard_typing = guard_typing
        self._opened_at = time.monotonic()
        self._stray = False
        if guard_typing:
            self.AUTO_FOCUS = "#no"  # Enter declines
        self.title_text = title
        self.message_text = message
        self.yes_label = yes_label
        self.no_label = no_label

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")
            with Horizontal(classes="button-row"):
                yield Button(self.yes_label, id="yes", classes="-primary")
                yield Button(self.no_label, id="no", classes="-secondary")
            yield KeyHintFooter(hints={"button": "[dim]y=Yes  n=No  Esc=Cancel[/dim]"})

    def _armed(self) -> bool:
        """False while a guarded dialog is too fresh to accept Yes."""
        return (
            not self.guard_typing
            or time.monotonic() - self._opened_at >= self.ARM_SECONDS
        )

    def on_key(self, event: events.Key) -> None:
        """Guarded: a letter/digit other than y/n is stray typing -> No."""
        if not self.guard_typing:
            return
        char = event.character or ""
        if len(char) == 1 and char.isalnum() and event.key not in ("y", "n"):
            event.stop()
            event.prevent_default()
            if self._stray:
                return  # the rest of the word, before the dialog is gone
            self._stray = True
            self.app.notify(
                f"{self.title_text}: not started — that looked like typing.",
                severity="warning",
                timeout=4,
            )
            start_typing_guard(self.app)
            self._dismiss_with_refresh(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "yes" and not self._armed():
            return
        self._dismiss_with_refresh(event.button.id == "yes")

    def action_yes(self) -> None:
        """Confirm and close the modal."""
        if not self._armed() or self._stray:
            return  # typed ahead: the dialog was not read yet
        self._dismiss_with_refresh(True)

    def action_no(self) -> None:
        """Decline and close the modal."""
        self._dismiss_with_refresh(False)


def start_typing_guard(app) -> None:
    """Swallow the rest of a stray word on the main screen (if there is one)."""
    for screen in reversed(getattr(app, "screen_stack", [])):
        guard = getattr(screen, "start_typing_guard", None)
        if guard is not None:
            try:
                guard()
            except Exception:
                pass
            return
