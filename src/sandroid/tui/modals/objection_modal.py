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


@dataclass
class ObjectionConfig:
    """Configuration for objection launch."""

    spawn_mode: bool = True  # True for spawn (-S), False for attach
    ssl_unpinning: bool = True
    root_detection: bool = True
    emulator_detection: bool = False
    frida_detection: bool = False
    debug_detection: bool = False
    use_bypass_script: bool = True  # Load trigdroid_bypass_rpc.js via -s


class ObjectionModal(FridaModal[ObjectionConfig | None]):
    """Modal for configuring objection launch with bypass hooks.

    Objection creates its own Frida session, so it cannot use JobManager.
    Instead, the TrigDroid bypass script can be loaded via the -s flag:
        objection -g com.example.app explore -s trigdroid_bypass_rpc.js

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
        Binding("1", "toggle_ssl", "SSL Unpinning", show=False),
        Binding("2", "toggle_root", "Root Detection", show=False),
        Binding("3", "toggle_emulator", "Emulator Detection", show=False),
        Binding("4", "toggle_frida", "Frida Detection", show=False),
        Binding("5", "toggle_debug", "Debug Detection", show=False),
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

            # Mode toggle - show correct initial state
            if self.config.spawn_mode:
                spawn_text = "[S] Mode: [bold $accent]* SPAWN[/] - Launch app with objection from start"
                spawn_class = "spawn-enabled"
            else:
                spawn_text = (
                    "[S] Mode: [bold $success]* ATTACH[/] - Attach to running app"
                )
                spawn_class = ""
            yield Static(spawn_text, id="spawn-mode-option", classes=spawn_class)

            # Bypass options section
            with Vertical(classes="bypass-section"):
                yield Label("TrigDroid Bypass Hooks:", classes="bypass-section-title")

                yield Static(
                    "[1] * SSL/TLS Unpinning",
                    id="option-ssl",
                    classes="bypass-option enabled",
                )
                yield Static(
                    "[2] * Root Detection Bypass",
                    id="option-root",
                    classes="bypass-option enabled",
                )
                yield Static(
                    "[3] o Emulator Detection Bypass",
                    id="option-emulator",
                    classes="bypass-option disabled",
                )
                yield Static(
                    "[4] o Frida Detection Bypass [dim](requires SPAWN)[/dim]",
                    id="option-frida",
                    classes="bypass-option disabled",
                )
                yield Static(
                    "[5] o Debug Detection Bypass",
                    id="option-debug",
                    classes="bypass-option disabled",
                )

            yield KeyHintFooter(
                hints={
                    "default": "[dim]S=Mode  1-5=Toggle  Enter=Launch  Esc=Cancel[/dim]",
                }
            )

    def _update_display(self) -> None:
        """Update the visual state of all options."""
        spawn_option = self.query_one("#spawn-mode-option", Static)
        if self.config.spawn_mode:
            spawn_option.update(
                "[S] Mode: [bold $accent]* SPAWN[/] - Launch app with objection from start"
            )
            spawn_option.add_class("spawn-enabled")
        else:
            spawn_option.update(
                "[S] Mode: [bold $success]* ATTACH[/] - Attach to running app"
            )
            spawn_option.remove_class("spawn-enabled")

        bypasses = [
            ("option-ssl", self.config.ssl_unpinning, "SSL/TLS Unpinning", ""),
            ("option-root", self.config.root_detection, "Root Detection Bypass", ""),
            (
                "option-emulator",
                self.config.emulator_detection,
                "Emulator Detection Bypass",
                "",
            ),
            (
                "option-frida",
                self.config.frida_detection,
                "Frida Detection Bypass",
                " [dim](requires SPAWN)[/dim]",
            ),
            ("option-debug", self.config.debug_detection, "Debug Detection Bypass", ""),
        ]

        for i, (option_id, enabled, label, note) in enumerate(bypasses, 1):
            self._update_bypass_option(option_id, i, enabled, label + note)

    def _update_bypass_option(
        self, option_id: str, num: int, enabled: bool, label: str
    ) -> None:
        """Update a single bypass option's display and CSS classes."""
        option = self.query_one(f"#{option_id}", Static)
        indicator = "*" if enabled else "o"
        style = "$success" if enabled else "dim"
        option.update(f"[{num}] [{style}]{indicator}[/] {label}")
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


def build_objection_command(
    package_name: str,
    config: ObjectionConfig,
    bypass_script_path: str | None = None,
) -> list:
    """Build the objection command line arguments.

    Args:
        package_name: Target package name
        config: Objection configuration
        bypass_script_path: Path to the trigdroid_bypass_rpc.js script

    Returns:
        List of command line arguments
    """
    cmd = ["objection", "-g", package_name]

    if config.spawn_mode:
        cmd.append("-S")

    cmd.append("explore")

    # -s flag must come AFTER 'explore' subcommand
    if config.use_bypass_script and bypass_script_path:
        cmd.extend(["-s", bypass_script_path])

    return cmd
