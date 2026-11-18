"""Quit confirmation modal dialog."""

from collections.abc import Callable

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Label, Static

from .base import DangerModal, KeyHintFooter


class QuitConfirmModal(DangerModal[bool]):
    """Compact centered modal for quit confirmation.

    Features:
    - Small centered overlay
    - Yes/No buttons with keyboard shortcuts (y/n)
    - Escape defaults to No (cancel quit)
    - Returns True to quit, False to cancel
    - With ``on_confirm``: confirming does not close the dialog; it turns into
      "Quitting Sandroid…" (no buttons, every key ignored) and calls
      ``on_confirm``, which cleans up off the UI thread and exits. Keys typed
      meanwhile cannot reach the screens below (e.g. ``y`` = Proxy Settings).
    """

    BINDINGS = [
        # Keep modal-specific bindings (y/n/q/enter) - ESC inherited from SandroidModal
        Binding("q", "cancel", "Cancel", show=False, priority=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
        # Enter should always quit, even when Cancel button is focused
        Binding("enter", "confirm", "Confirm", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    QuitConfirmModal .modal-container {
        width: 44;
        max-width: 80%;
        max-height: 80%;
    }
    QuitConfirmModal #quit-notes {
        width: 100%;
        height: auto;
        text-align: center;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
        notes: list[str] | None = None,
        on_confirm: Callable[[], None] | None = None,
    ):
        """Initialize the quit confirmation modal.

        Args:
            notes: What quitting tears down (e.g. "stops mitmweb", "clears
                the device proxy"), shown under the question.
            on_confirm: Called on confirm instead of dismissing (see above).
        """
        super().__init__(name=name, id=id, classes=classes)
        self._notes = list(notes or [])
        self._on_confirm = on_confirm
        self.quitting = False
        self._stray = False

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Quit Sandroid?", classes="modal-title", id="quit-title")
            yield Label(
                "Are you sure you want to exit?",
                classes="modal-message",
                id="quit-question",
            )
            if self._notes:
                yield Static(
                    "Quitting " + ", ".join(self._notes) + ".",
                    classes="modal-message",
                    id="quit-notes",
                )
            with Horizontal(classes="button-row", id="quit-buttons"):
                yield Button("Quit", classes="-primary", id="btn-quit")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")
            yield KeyHintFooter(
                hints={"button": "[dim]y/Enter=Quit  n/q/Esc=Cancel[/dim]"},
                id="quit-hints",
            )

    def on_mount(self) -> None:
        """Focus the Cancel button on mount (safer default)."""
        try:
            self.query_one("#btn-cancel", Button).focus()
        except NoMatches:
            pass

    def on_key(self, event) -> None:
        """A letter/digit other than y/n/q is stray typing: cancel the quit.

        ``q`` is one key: a word typed while no text field had focus
        ("sqlite") opened this dialog, and its Enter must not quit.
        """
        if self.quitting:
            return
        char = event.character or ""
        if len(char) == 1 and char.isalnum() and event.key not in ("y", "n", "q"):
            event.stop()
            event.prevent_default()
            if self._stray:
                return  # the rest of the word, before the dialog is gone
            self._stray = True
            self.app.notify(
                "Quit cancelled — that looked like typing.", severity="warning"
            )
            from .confirm_modal import start_typing_guard

            start_typing_guard(self.app)
            self._dismiss_with_refresh(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if self.quitting:
            return
        if event.button.id == "btn-quit":
            self.action_confirm()
        else:
            self._dismiss_with_refresh(False)

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Once quitting, no key does anything here (nor below: modal)."""
        return not self.quitting

    def action_confirm(self) -> None:
        """Confirm quit.

        The exit watchdog is armed right here, in the dialog's own message
        loop: if the app's loop is stuck the dismiss callback never runs, and
        the watchdog still tears down mitmweb / the device proxy and exits.
        """
        if self.quitting or self._stray:
            return
        try:
            from sandroid.tui.controllers.quit_controller import arm_exit_watchdog

            arm_exit_watchdog()
        except Exception:
            pass
        if self._on_confirm is None:
            self.dismiss(True)
            return
        self._show_quitting()
        self._on_confirm()

    def _show_quitting(self) -> None:
        """Turn the dialog into the "Quitting…" progress note."""
        self.quitting = True
        try:
            self.query_one("#quit-title", Label).update("Quitting Sandroid…")
            # One short line: the label does not wrap (44-column dialog).
            self.query_one("#quit-question", Label).update(
                "Cleaning up, a few seconds…"
            )
            self.query_one("#quit-buttons").display = False
            self.query_one("#quit-hints").display = False
            self.set_focus(None)
        except NoMatches:
            pass

    def action_cancel(self) -> None:
        """Cancel quit and close modal."""
        if self.quitting:
            return
        self._dismiss_with_refresh(False)
