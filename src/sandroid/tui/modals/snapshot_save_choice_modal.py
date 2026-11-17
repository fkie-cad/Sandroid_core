"""Snapshot modals: the picker (S / 0), the slot chooser and the save choice."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Label, RadioButton, RadioSet

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class SnapshotSaveChoiceResult:
    """Result from the save-to-occupied-slot choice modal.

    Attributes:
        cancelled: Whether the modal was cancelled.
        mode: ``"overwrite"`` (re-save the slot's current tag in place) or
            ``"fresh"`` (create a new timestamped snapshot and re-point the slot).
        remember: Whether to persist ``mode`` as the default (skip this prompt
            in future saves).
    """

    cancelled: bool = True
    mode: str = "overwrite"
    remember: bool = False


class SnapshotSaveChoiceModal(ForensicModal[SnapshotSaveChoiceResult]):
    """Ask how to save into a slot that already holds a snapshot.

    Two outcomes: overwrite the existing snapshot in place, or keep it and save
    a fresh (timestamped) snapshot, re-pointing the slot. A "Don't ask again"
    checkbox persists the chosen mode to ``tui.snapshot_save_mode``.
    """

    BINDINGS = [
        Binding("enter", "continue", "Continue", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    SnapshotSaveChoiceModal .modal-container {
        width: 68;
        max-width: 90%;
        max-height: 85%;
    }

    SnapshotSaveChoiceModal #save-choice-description {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    SnapshotSaveChoiceModal #save-options {
        padding: 1 0;
        height: auto;
        background: transparent;
        border: none;
    }

    SnapshotSaveChoiceModal #save-options > RadioButton {
        height: auto;
        padding: 0;
        margin: 0 0 1 0;
        background: transparent;
    }

    SnapshotSaveChoiceModal #save-options > RadioButton:focus {
        text-style: bold;
    }

    SnapshotSaveChoiceModal #remember-section {
        padding: 1 0;
        height: auto;
        border-top: solid $panel;
        margin-top: 1;
    }

    SnapshotSaveChoiceModal #remember-checkbox {
        padding-left: 1;
    }

    SnapshotSaveChoiceModal .button-row {
        align: center middle;
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        slot: str,
        existing_tag: str,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the save-choice modal.

        Args:
            slot: The slot number being saved into (e.g. ``"3"``).
            existing_tag: The snapshot tag the slot currently points at.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._slot = slot
        self._existing_tag = existing_tag
        self._mode = "overwrite"  # default selection

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Save to slot", classes="modal-title")
            yield Label(
                f"Slot {self._slot} already holds [b]{self._existing_tag}[/]. "
                "How should the current state be saved?",
                id="save-choice-description",
            )

            with RadioSet(id="save-options"):
                yield RadioButton(
                    f"Overwrite '{self._existing_tag}' in place",
                    id="option-overwrite",
                    value=True,
                )
                yield RadioButton(
                    "Keep it — save a new snapshot and re-point the slot",
                    id="option-fresh",
                )

            with Vertical(id="remember-section"):
                yield Checkbox(
                    "Don't ask again (remember this choice)",
                    id="remember-checkbox",
                )

            with Horizontal(classes="button-row"):
                yield Button("Save", classes="-primary", id="btn-continue")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the option set on mount."""
        try:
            self.query_one("#save-options", RadioSet).focus()
        except Exception:
            pass

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Track the selected save mode."""
        self._mode = "fresh" if event.pressed.id == "option-fresh" else "overwrite"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-continue":
            self.action_continue()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        """Cancel and close the modal."""
        self._dismiss_with_refresh(SnapshotSaveChoiceResult(cancelled=True))

    def action_continue(self) -> None:
        """Commit the selection and dismiss."""
        try:
            remember = self.query_one("#remember-checkbox", Checkbox).value
        except Exception:
            remember = False
        self.dismiss(
            SnapshotSaveChoiceResult(
                cancelled=False,
                mode=self._mode,
                remember=remember,
            )
        )


class SnapshotSlotPickerModal(ForensicModal[str]):
    """Pick a slot (1-8) to save the current state into -- key ``S``.

    Terminal-safe fallback for the ``Ctrl+1``-``Ctrl+8`` save keys: most
    terminals (Terminal.app, VTE/GNOME Terminal, tmux without extended keys)
    cannot send Ctrl+digit at all, only terminals speaking the kitty keyboard
    protocol can. Here a plain digit picks the slot; Esc cancels. Dismisses
    with the slot string (``"1"``-``"8"``) or ``None``.
    """

    BINDINGS = [
        Binding(str(i), f"pick('{i}')", f"Slot {i}", show=False, priority=True)
        for i in range(1, 9)
    ]

    DEFAULT_CSS = """
    SnapshotSlotPickerModal .modal-container {
        width: 60;
        max-width: 90%;
        height: auto;
    }

    SnapshotSlotPickerModal #slot-picker-description {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    SnapshotSlotPickerModal .button-row {
        align: center middle;
        width: 100%;
        height: 3;
    }

    SnapshotSlotPickerModal .button-row > Button {
        min-width: 5;
        width: 5;
        margin: 0;
    }
    """

    def __init__(self, slots: dict[str, str] | None = None, **kwargs) -> None:
        """Initialize the picker.

        Args:
            slots: Current ``{slot: tag}`` assignments, shown as a hint.
            **kwargs: Passed to the modal base.
        """
        super().__init__(**kwargs)
        self._slots = dict(slots or {})

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        used = ", ".join(f"{s}={t}" for s, t in sorted(self._slots.items()))
        with Vertical(classes="modal-container"):
            yield Label("Save to slot", classes="modal-title")
            yield Label(
                "Press [b]1[/b]-[b]8[/b] to save the current state into that "
                "slot, Esc to cancel."
                + (f"\n[dim]In use: {used}[/dim]" if used else ""),
                id="slot-picker-description",
            )
            with Horizontal(classes="button-row"):
                for i in range(1, 9):
                    yield Button(str(i), id=f"slot-pick-{i}")
            yield KeyHintFooter()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """A slot button was clicked."""
        button_id = event.button.id or ""
        if button_id.startswith("slot-pick-"):
            self.action_pick(button_id.rsplit("-", 1)[-1])

    def action_pick(self, slot: str) -> None:
        """Dismiss with the chosen slot."""
        self.dismiss(str(slot))


class SnapshotPickerModal(ForensicModal[None]):
    """Snapshot picker -- keys ``S`` / ``0`` (snapshots are no longer a tab).

    Hosts a :class:`~sandroid.tui.widgets.snapshots_panel.SnapshotsPanel`
    (list, create, load / delete with confirm, assign to slot) and adds the
    slot keys: ``1``-``8`` load that slot after a confirm, ``s`` then a digit
    saves the current state into a slot. Esc closes.

    ``then(panel)`` (optional) runs once the panel is mounted -- the app's
    Ctrl+1-8 save keys use it to save through the picker's panel.
    """

    BINDINGS = [
        *[
            Binding(str(i), f"load_slot('{i}')", f"Load slot {i}", show=False)
            for i in range(1, 9)
        ],
        Binding("s", "save_to_slot", "Save to slot", show=False),
    ]

    DEFAULT_CSS = """
    SnapshotPickerModal .modal-container {
        width: 84;
        max-width: 96%;
        height: auto;
        padding: 0 1;
    }
    SnapshotPickerModal .modal-title {
        height: 1;
        margin-bottom: 0;
    }
    SnapshotPickerModal #snapshots-panel {
        height: auto;
        max-height: 24;
    }
    SnapshotPickerModal SnapshotsPanel > #snapshots-list {
        height: auto;
        min-height: 3;
        max-height: 14;
    }
    SnapshotPickerModal SnapshotsPanel > #snapshots-actions {
        dock: none;
    }
    SnapshotPickerModal KeyHintFooter {
        margin-top: 0;
    }
    """

    #: Hint line for the picker (the panel's own action row shows c/l/d/a).
    HINT = "[dim]⏎ load · 1-8 load slot · s save to slot · Esc close[/dim]"

    def __init__(self, then=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._then = then

    def compose(self) -> ComposeResult:
        from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

        with Vertical(classes="modal-container"):
            yield Label("Snapshots", classes="modal-title")
            yield SnapshotsPanel(id="snapshots-panel")
            yield KeyHintFooter(
                hints=dict.fromkeys(("default", "list", "button"), self.HINT)
            )

    def on_mount(self) -> None:
        super().on_mount()
        if self._then is not None:
            then, self._then = self._then, None
            self.call_after_refresh(self.run_with_panel, then)

    def panel(self):
        """The hosted SnapshotsPanel, or None."""
        try:
            return self.query_one("#snapshots-panel")
        except Exception:
            return None

    def run_with_panel(self, fn) -> None:
        panel = self.panel()
        if panel is not None:
            fn(panel)

    def on_option_list_option_selected(self, event) -> None:
        """Enter / click on a row loads it (with the panel's confirm)."""
        panel = self.panel()
        if panel is not None:
            event.stop()
            panel.action_load()

    def action_load_slot(self, slot: str) -> None:
        """Load ``slot`` after a confirm; empty slots are explained instead."""
        panel = self.panel()
        if panel is None:
            return
        tag = panel.slot_tag(slot)
        if not tag:
            panel.load_slot(slot)  # explains: empty slot / no emulator
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        def on_result(yes: bool | None) -> None:
            if yes:
                panel.load_slot(slot)

        self.app.push_screen(
            ConfirmModal(
                title="Load snapshot",
                message=f"Load slot {slot} ('{tag}')? Current state will be lost.",
            ),
            on_result,
        )

    def action_save_to_slot(self) -> None:
        """``s``: pick a slot digit, then save the current state into it."""
        panel = self.panel()
        if panel is None:
            return
        try:
            slots = panel._slot_map()
        except Exception:
            slots = {}

        def on_pick(slot: str | None) -> None:
            if slot:
                panel.save_slot(slot)

        self.app.push_screen(SnapshotSlotPickerModal(slots), on_pick)
