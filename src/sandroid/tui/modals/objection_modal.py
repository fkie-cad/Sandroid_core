"""Objection Launch Configuration Modal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, Static

from sandroid.tui.modals.base import FridaModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult


#: The ONE digit -> bypass category table for the App lens's ``b`` chord
#: (``spotlight_panel.BypassChordModal``). Kept here so existing imports keep
#: working; every bypass comes from ``BypassService`` (key, category, label).
BYPASS_KEYS: tuple[tuple[str, str, str], ...] = (
    ("1", "ssl", "SSL"),
    ("2", "root", "Root"),
    ("3", "frida", "Frida"),
    ("4", "debug", "Debug"),
    ("5", "integrity", "Integrity"),
    ("6", "emulator", "Emulator"),
)


@dataclass
class ObjectionConfig:
    """Configuration for objection launch."""

    spawn_mode: bool = True  # True for spawn (-s), False for attach


class ObjectionModal(FridaModal[ObjectionConfig | None]):
    """Modal for configuring an objection launch (spawn or attach).

    Objection creates its own Frida session, so it cannot use JobManager or
    the BypassService script. Detection bypasses come from the App lens's
    ``b`` chord (BypassService) only; this modal no longer loads TrigDroid's
    bypass script.

    Returns:
        ObjectionConfig with selected options, or None if cancelled.
    """

    DEFAULT_CSS = """
    ObjectionModal .modal-container {
        border: solid $success;
        width: 80;
        max-height: 22;
        max-width: 90%;
    }

    ObjectionModal .modal-title {
        color: $success;
    }

    ObjectionModal #objection-target {
        color: $foreground;
        text-align: center;
        width: 100%;
        height: 1;
    }

    ObjectionModal #spawn-mode-option {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin-top: 1;
        background: $panel;
        color: $foreground;
    }

    ObjectionModal #objection-bypass-note {
        width: 100%;
        height: auto;
        padding: 0 2;
        margin-top: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("enter", "confirm", "Launch", priority=True),
        Binding("s", "toggle_spawn", "Spawn Mode", show=False),
    ]

    AUTO_FOCUS = ".modal-container"

    def __init__(
        self,
        package_name: str = "com.example.app",
        initial_spawn_mode: bool = True,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the objection modal.

        Args:
            package_name: Target package name
            initial_spawn_mode: Initial spawn mode (True=spawn, False=attach)
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.package_name = package_name
        self.config = ObjectionConfig(spawn_mode=initial_spawn_mode)

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Objection Configuration", classes="modal-title")
            yield Static(
                f"Target: [$accent]{self.package_name}[/]", id="objection-target"
            )

            yield Static(self._spawn_text(), id="spawn-mode-option")
            yield Static(
                "[dim]Objection loads no bypass hooks: detection bypasses "
                "come only from the App lens's b chord.[/dim]",
                id="objection-bypass-note",
            )

            yield KeyHintFooter(
                hints={
                    "default": "[dim]s mode · Enter launch · Esc cancel[/dim]",
                }
            )

    def on_mount(self) -> None:
        super().on_mount()
        self._update_display()

    def _spawn_text(self) -> str:
        if self.config.spawn_mode:
            return (
                "[b]s[/] Mode: [bold $accent]● SPAWN[/] - "
                "Launch app with objection from start"
            )
        return "[b]s[/] Mode: [bold $success]● ATTACH[/] - Attach to running app"

    def _update_display(self) -> None:
        """Update the spawn-mode row."""
        try:
            spawn_option = self.query_one("#spawn-mode-option", Static)
        except Exception:
            return
        spawn_option.update(self._spawn_text())
        spawn_option.set_class(self.config.spawn_mode, "spawn-enabled")

    def action_toggle_spawn(self) -> None:
        """Toggle spawn mode."""
        self.config.spawn_mode = not self.config.spawn_mode
        self._update_display()

    def action_confirm(self) -> None:
        """Confirm and close modal."""
        self._dismiss_with_refresh(self.config)


def _objection_executable() -> str:
    """``objection`` from PATH, else the one next to this interpreter.

    pipx/uv-tool installs put objection in the tool venv's bin, which is not on
    PATH unless the venv is activated.
    """
    import shutil
    import sys
    from pathlib import Path

    found = shutil.which("objection")
    if found:
        return found
    sibling = Path(sys.executable).parent / "objection"
    return str(sibling) if sibling.exists() else "objection"


def build_objection_command(
    package_name: str,
    config: ObjectionConfig,
    serial: str | None = None,
) -> list:
    """Build the objection (>= 1.12) command line.

    objection 1.12: ``-n/--name`` replaces the hidden ``-g``, ``explore`` is
    deprecated for ``start``, ``-S`` is ``--serial`` (spawn is ``-s``) and the
    startup script is ``start -S``. The old
    ``objection -g pkg -S explore -s script`` failed: ``-S`` swallowed
    "explore" as a serial ("Missing command"), and ``explore -s`` treats its
    value as a REPL startup *command*, not a script path.

    Spawn mode passes ``-p/--no-pause``: objection 1.12 otherwise leaves the
    spawned app suspended until ``resume`` is typed, and Android kills an app
    that has not attached within 10 s ("start timeout") -- verified on
    API 36, the session died before the REPL was usable.

    Args:
        package_name: Target package name
        config: Objection configuration
        serial: adb serial of the target device; defaults to the active
            Sandroid device (objection would otherwise pick the first USB
            device)

    Returns:
        List of command line arguments
    """
    if serial is None:
        try:
            from sandroid.core.adb import Adb

            serial = Adb.get_target_device()
        except Exception:
            serial = None

    cmd = [_objection_executable()]
    if serial:
        cmd.extend(["-S", serial])
    cmd.extend(["-n", package_name])
    if config.spawn_mode:
        cmd.extend(["-s", "-p"])

    cmd.append("start")
    return cmd
