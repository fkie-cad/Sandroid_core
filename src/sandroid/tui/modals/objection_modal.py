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


#: The ONE digit -> bypass category table. The App lens's ``b`` chord
#: (``spotlight_panel.BypassChordModal``) and this Objection modal both read
#: it, so the same digit never toggles a different hook in the two menus.
#: (key, category, short label)
BYPASS_KEYS: tuple[tuple[str, str, str], ...] = (
    ("1", "ssl", "SSL"),
    ("2", "root", "Root"),
    ("3", "frida", "Frida"),
    ("4", "debug", "Debug"),
    ("5", "integrity", "Integrity"),
)

#: Objection's TrigDroid script has no integrity hooks but an emulator one:
#: emulator detection gets its own letter (``e``) instead of a digit, so the
#: digits keep the meaning they have in the ``b`` chord.
_EMULATOR_KEY = "e"

#: Bypass category -> (ObjectionConfig field, row label, note).
_OBJECTION_OPTIONS: dict[str, tuple[str, str, str]] = {
    "ssl": ("ssl_unpinning", "SSL/TLS Unpinning", ""),
    "root": ("root_detection", "Root Detection Bypass", ""),
    "frida": (
        "frida_detection",
        "Frida Detection Bypass",
        " [dim](requires SPAWN)[/dim]",
    ),
    "debug": ("debug_detection", "Debug Detection Bypass", ""),
    "emulator": ("emulator_detection", "Emulator Detection Bypass", ""),
}


def objection_option_keys() -> list[tuple[str, str]]:
    """``[(key, category)]`` the Objection modal offers, in display order."""
    keys = [(k, c) for k, c, _label in BYPASS_KEYS if c in _OBJECTION_OPTIONS]
    keys.append((_EMULATOR_KEY, "emulator"))
    return keys


@dataclass
class ObjectionConfig:
    """Configuration for objection launch."""

    spawn_mode: bool = True  # True for spawn (-s), False for attach
    ssl_unpinning: bool = True
    root_detection: bool = True
    emulator_detection: bool = False
    frida_detection: bool = False
    debug_detection: bool = False
    use_bypass_script: bool = True  # Load trigdroid_bypass_rpc.js (start -S)


class ObjectionModal(FridaModal[ObjectionConfig | None]):
    """Modal for configuring objection launch with bypass hooks.

    Objection creates its own Frida session, so it cannot use JobManager.
    Instead, the TrigDroid bypass script can be loaded via the -s flag:
        objection -n com.example.app start -S trigdroid_bypass_rpc.js

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

    ObjectionModal .bypass-section {
        width: 100%;
        padding: 0;
        margin: 0;
    }

    ObjectionModal .bypass-section-title {
        color: $success;
        text-style: bold;
        height: 1;
        margin-top: 1;
    }

    ObjectionModal .bypass-option {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin: 0;
        background: $panel;
    }

    ObjectionModal .bypass-option.enabled {
        color: $success;
    }

    ObjectionModal .bypass-option.disabled {
        color: $text-muted;
    }

    ObjectionModal #spawn-mode-option {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin-top: 1;
        background: $panel;
        color: $foreground;
    }
    """

    BINDINGS = [
        Binding("enter", "confirm", "Launch", priority=True),
        Binding("s", "toggle_spawn", "Spawn Mode", show=False),
        *[
            Binding(
                key,
                f"toggle_{category}",
                _OBJECTION_OPTIONS[category][1],
                show=False,
            )
            for key, category in objection_option_keys()
        ],
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

            # Bypass options section (same digits as the App lens's b chord)
            with Vertical(classes="bypass-section"):
                yield Label("TrigDroid Bypass Hooks:", classes="bypass-section-title")
                for key, category in objection_option_keys():
                    yield Static("", id=f"option-{category}", classes="bypass-option")

            keys = "/".join(k for k, _c in objection_option_keys())
            yield KeyHintFooter(
                hints={
                    "default": (
                        f"[dim]s mode · {keys} toggle · Enter launch · Esc cancel[/dim]"
                    ),
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
        """Update the visual state of all options."""
        try:
            spawn_option = self.query_one("#spawn-mode-option", Static)
        except Exception:
            return
        spawn_option.update(self._spawn_text())
        spawn_option.set_class(self.config.spawn_mode, "spawn-enabled")
        for key, category in objection_option_keys():
            field_name, label, note = _OBJECTION_OPTIONS[category]
            self._update_bypass_option(
                f"option-{category}",
                key,
                bool(getattr(self.config, field_name)),
                label + note,
            )

    def _update_bypass_option(
        self, option_id: str, key: str, enabled: bool, label: str
    ) -> None:
        """Update a single bypass option's display and CSS classes."""
        option = self.query_one(f"#{option_id}", Static)
        mark = "[$success]● on [/]" if enabled else "[dim]○ off[/]"
        option.update(f"[b]{key}[/]  {mark}  {label}")
        if enabled:
            option.remove_class("disabled")
            option.add_class("enabled")
        else:
            option.remove_class("enabled")
            option.add_class("disabled")

    def action_toggle_spawn(self) -> None:
        """Toggle spawn mode."""
        self.config.spawn_mode = not self.config.spawn_mode
        # Frida bypass works best in spawn mode
        if not self.config.spawn_mode and self.config.frida_detection:
            self.config.frida_detection = False
        self._update_display()

    def action_toggle_integrity(self) -> None:
        """No Objection equivalent (kept so a stray binding is harmless)."""

    def action_toggle_ssl(self) -> None:
        """Toggle SSL unpinning."""
        self.config.ssl_unpinning = not self.config.ssl_unpinning
        self._update_display()

    def action_toggle_root(self) -> None:
        """Toggle root detection bypass."""
        self.config.root_detection = not self.config.root_detection
        self._update_display()

    def action_toggle_emulator(self) -> None:
        """Toggle emulator detection bypass."""
        self.config.emulator_detection = not self.config.emulator_detection
        self._update_display()

    def action_toggle_frida(self) -> None:
        """Toggle Frida detection bypass."""
        self.config.frida_detection = not self.config.frida_detection
        # Frida bypass requires spawn mode
        if self.config.frida_detection and not self.config.spawn_mode:
            self.config.spawn_mode = True
        self._update_display()

    def action_toggle_debug(self) -> None:
        """Toggle debug detection bypass."""
        self.config.debug_detection = not self.config.debug_detection
        self._update_display()

    def action_confirm(self) -> None:
        """Confirm and close modal."""
        self.config.use_bypass_script = any(
            (
                self.config.ssl_unpinning,
                self.config.root_detection,
                self.config.emulator_detection,
                self.config.frida_detection,
                self.config.debug_detection,
            )
        )
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
    bypass_script_path: str | None = None,
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
        bypass_script_path: Path to the trigdroid_bypass_rpc.js script
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

    # start's -S/--startup-script must come AFTER the subcommand
    if config.use_bypass_script and bypass_script_path:
        cmd.extend(["-S", bypass_script_path])

    return cmd
