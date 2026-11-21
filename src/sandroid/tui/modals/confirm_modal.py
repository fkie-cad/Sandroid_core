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
    - ``yes_keys``: further keys that answer Yes, like ``y`` (the command
      the dialog confirms, e.g. ``R`` for "Restart now?": pressing Shift+R
      again restarts instead of reading as typing).
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
        yes_keys: tuple[str, ...] = (),
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
            yes_keys: Keys that answer Yes besides ``y`` (see the class doc).
        """
        super().__init__(name=name, id=id, classes=classes)
        self.guard_typing = guard_typing
        self.yes_keys = tuple(yes_keys)
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
                # Guarded: No is the default (focused), so Yes must not look
                # like the primary action (E2E L5).
                yes_style = "-secondary" if self.guard_typing else "-primary"
                yield Button(self.yes_label, id="yes", classes=yes_style)
                yield Button(self.no_label, id="no", classes="-secondary")
            yield KeyHintFooter(hints=dict.fromkeys(("default", "button"), self.hint))

    @property
    def hint(self) -> str:
        """The key hint, named after the buttons (Esc answers like No)."""
        from sandroid.tui.key_display import format_key
        from sandroid.tui.utils.markup import escape

        yes, no = escape(self.yes_label), escape(self.no_label)
        # yes_keys answer Yes too (Shift+R in "Restart ... now?").
        keys = " or ".join(["y", *(format_key(k) for k in self.yes_keys)])
        return f"[dim]{keys} {yes}  n or {format_key('escape')} {no}[/dim]"

    def on_descendant_focus(self, _event) -> None:
        mark_focused_button(self)

    def on_descendant_blur(self, _event) -> None:
        self.call_after_refresh(mark_focused_button, self)

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
        if self._stray:
            # Closed as typing: the rest of the word (y/n included) is
            # neither an answer here nor a command below.
            event.stop()
            event.prevent_default()
            return
        if event.key in self.yes_keys:
            event.stop()
            event.prevent_default()
            self.action_yes()
            return
        char = event.character or ""
        if len(char) == 1 and char.isalnum() and event.key not in ("y", "n"):
            event.stop()
            event.prevent_default()
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


def mark_focused_button(screen) -> None:
    """Make the focused dialog button stand out: the themes paint Yes/No
    (or Quit/Cancel) by role only, so the focused one looked unfocused
    (E2E L5). Inline styles beat every theme's ``Button`` rules.
    """
    for button in screen.query(".button-row Button"):
        # screen.focused, not has_focus: that one lags a focus change.
        focused = button is screen.focused
        # The whole button, not just the label (reverse only flips the label).
        button.styles.background = "#38bdf8" if focused else "#1f2a3d"
        button.styles.color = "#050811" if focused else "#94a3b8"
        button.styles.text_style = "bold" if focused else "none"
        button.notify_style_update()  # else the old colours stay cached
        button.refresh()


def typing_guard_active(app) -> bool:
    """True right after stray typing closed a dialog (see start_typing_guard)."""
    for screen in getattr(app, "screen_stack", []):
        active = getattr(screen, "typing_guard_active", None)
        if active is not None:
            try:
                if active():
                    return True
            except Exception:
                pass
    return False


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
