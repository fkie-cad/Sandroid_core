"""TrigDroid configuration modal for bypass settings.

Styled to match ObjectionModal with keyboard-only navigation.
"""

import logging
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, Static

from sandroid.core.enums import SpawnMode
from sandroid.tui.modals.base import FridaModal, KeyHintFooter

logger = logging.getLogger(__name__)


@dataclass
class TrigDroidConfig:
    """TrigDroid configuration result.

    Attributes:
        cancelled: Whether the dialog was cancelled.
        mode: Spawn or attach mode.
        package_name: Target package name.
        ssl_unpinning: Enable SSL/TLS unpinning bypass.
        root_detection_bypass: Enable root detection bypass.
        emulator_detection_bypass: Enable emulator detection bypass.
        frida_detection_bypass: Enable Frida detection bypass (SPAWN only).
        debug_detection_bypass: Enable debug detection bypass.
        auto_resume: Auto-resume after hooks are loaded (SPAWN only).
    """

    cancelled: bool = True
    mode: SpawnMode = SpawnMode.ATTACH
    package_name: str | None = None
    ssl_unpinning: bool = False
    root_detection_bypass: bool = False
    emulator_detection_bypass: bool = False
    frida_detection_bypass: bool = False
    debug_detection_bypass: bool = False
    auto_resume: bool = True


class TrigDroidModal(FridaModal[TrigDroidConfig]):
    """Modal for configuring TrigDroid bypass options.

    Features:
    - Mode indicator (SPAWN/ATTACH) with visual styling
    - Target package display
    - Static text with [n] bullet indicators (no switch widgets)
    - Frida Detection disabled in ATTACH mode with explanation
    - Number keys (1-5) to toggle options
    - Enter to start, Escape to cancel
    - No buttons - keyboard shortcuts only
    """

    DEFAULT_CSS = """
    TrigDroidModal .modal-container {
        border: solid $success;
        width: 80;
        max-height: 22;
        max-width: 90%;
    }

    TrigDroidModal .modal-title {
        color: $success;
    }

    TrigDroidModal #mode-indicator {
        color: $foreground;
        text-align: center;
        width: 100%;
        height: 1;
    }

    TrigDroidModal #package-info {
        color: $foreground;
        text-align: center;
        width: 100%;
        height: 1;
    }

    TrigDroidModal .section-title {
        color: $success;
        text-style: bold;
        height: 1;
        margin-top: 1;
    }

    TrigDroidModal .bypass-option {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin: 0;
        background: $panel;
    }

    TrigDroidModal .bypass-option.enabled {
        color: $success;
    }

    TrigDroidModal .bypass-option.disabled {
        color: $text-muted;
    }

    TrigDroidModal #disabled-note {
        color: $error;
        text-align: center;
        width: 100%;
        height: 1;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "submit", "Start", priority=True),
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
        mode: SpawnMode = SpawnMode.ATTACH,
        package_name: str | None = None,
        initial_config: TrigDroidConfig | None = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the TrigDroid configuration modal.

        Args:
            mode: Spawn or attach mode.
            package_name: Target package name.
            initial_config: Optional initial configuration.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.mode = mode
        self.package_name = package_name or "Unknown"

        # Set initial values from config or defaults
        if initial_config:
            self.ssl_unpinning = initial_config.ssl_unpinning
            self.root_detection = initial_config.root_detection_bypass
            self.emulator_detection = initial_config.emulator_detection_bypass
            self.frida_detection = initial_config.frida_detection_bypass
            self.debug_detection = initial_config.debug_detection_bypass
        else:
            self.ssl_unpinning = False
            self.root_detection = False
            self.emulator_detection = False
            self.frida_detection = False
            self.debug_detection = False

        # Frida detection bypass is only effective in SPAWN mode
        self.frida_detection_disabled = mode == SpawnMode.ATTACH

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("TrigDroid Configuration", classes="modal-title")

            # Mode indicator - ATTACH is green, SPAWN is accent
            mode_text = self.mode.value.upper()
            mode_color = "$accent" if self.mode == SpawnMode.SPAWN else "$success"
            yield Static(
                f"Mode: [bold {mode_color}]{mode_text}[/]",
                id="mode-indicator",
            )

            # Package info
            yield Static(
                f"Target: [$accent]{self.package_name}[/]",
                id="package-info",
            )

            yield Label("Security Bypasses", classes="section-title")

            initial_options = [
                (1, "SSL/TLS Unpinning", self.ssl_unpinning, "option-ssl", False),
                (2, "Root Detection Bypass", self.root_detection, "option-root", False),
                (
                    3,
                    "Emulator Detection Bypass",
                    self.emulator_detection,
                    "option-emulator",
                    False,
                ),
                (
                    4,
                    "Frida Detection Bypass",
                    self.frida_detection,
                    "option-frida",
                    self.frida_detection_disabled,
                ),
                (
                    5,
                    "Debug Detection Bypass",
                    self.debug_detection,
                    "option-debug",
                    False,
                ),
            ]

            for num, label, enabled, option_id, disabled in initial_options:
                display_label = label
                if option_id == "option-frida" and disabled:
                    display_label = f"{label} [dim](requires SPAWN)[/dim]"
                is_active = enabled and not disabled
                state_class = "enabled" if is_active else "disabled"
                yield Static(
                    self._format_option(num, display_label, enabled, disabled),
                    id=option_id,
                    classes=f"bypass-option {state_class}",
                )

            if self.frida_detection_disabled:
                yield Static(
                    "[dim]Frida Detection bypass requires SPAWN mode[/dim]",
                    id="disabled-note",
                )

            yield KeyHintFooter(
                hints={
                    "default": "[dim]S=Mode  1-5=Toggle  Enter=Start  Esc=Cancel[/dim]",
                }
            )

    def _format_option(
        self, num: int, label: str, enabled: bool, disabled: bool = False
    ) -> str:
        """Format an option with bullet indicator."""
        is_active = enabled and not disabled
        indicator = "*" if is_active else "o"
        style = "$success" if is_active else "dim"
        return f"[{num}] [{style}]{indicator}[/] {label}"

    def _update_display(self) -> None:
        """Update the visual state of all options."""
        options = [
            ("option-ssl", self.ssl_unpinning, "SSL/TLS Unpinning", False),
            ("option-root", self.root_detection, "Root Detection Bypass", False),
            (
                "option-emulator",
                self.emulator_detection,
                "Emulator Detection Bypass",
                False,
            ),
            (
                "option-frida",
                self.frida_detection,
                "Frida Detection Bypass",
                self.frida_detection_disabled,
            ),
            ("option-debug", self.debug_detection, "Debug Detection Bypass", False),
        ]

        for idx, (option_id, enabled, label, disabled) in enumerate(options, 1):
            try:
                option = self.query_one(f"#{option_id}", Static)
                display_label = label
                if option_id == "option-frida" and disabled:
                    display_label = f"{label} [dim](requires SPAWN)[/dim]"

                is_active = enabled and not disabled
                option.update(
                    self._format_option(idx, display_label, enabled, disabled)
                )
                if is_active:
                    option.remove_class("disabled")
                    option.add_class("enabled")
                else:
                    option.remove_class("enabled")
                    option.add_class("disabled")
            except Exception:
                pass

        self.call_later(self._restore_focus)

    def _restore_focus(self) -> None:
        """Restore focus to the modal container after widget updates."""
        try:
            container = self.query_one(".modal-container")
            if container.can_focus:
                container.focus()
        except Exception as e:
            logger.debug(f"Focus restoration failed: {e}")

    def action_toggle_spawn(self) -> None:
        """Toggle spawn mode."""
        self.mode = (
            SpawnMode.SPAWN if self.mode == SpawnMode.ATTACH else SpawnMode.ATTACH
        )
        self.frida_detection_disabled = self.mode == SpawnMode.ATTACH

        # Update mode indicator - ATTACH is green, SPAWN is accent
        mode_text = self.mode.value.upper()
        mode_color = "$accent" if self.mode == SpawnMode.SPAWN else "$success"
        mode_widget = self.query_one("#mode-indicator", Static)
        mode_widget.update(f"Mode: [bold {mode_color}]{mode_text}[/]")

        # If switching to attach mode and Frida bypass was enabled, disable it
        if self.frida_detection_disabled and self.frida_detection:
            self.frida_detection = False

        self._update_display()

    def action_toggle_ssl(self) -> None:
        """Toggle SSL unpinning."""
        self.ssl_unpinning = not self.ssl_unpinning
        self._update_display()

    def action_toggle_root(self) -> None:
        """Toggle root detection bypass."""
        self.root_detection = not self.root_detection
        self._update_display()

    def action_toggle_emulator(self) -> None:
        """Toggle emulator detection bypass."""
        self.emulator_detection = not self.emulator_detection
        self._update_display()

    def action_toggle_frida(self) -> None:
        """Toggle Frida detection bypass."""
        if not self.frida_detection_disabled:
            self.frida_detection = not self.frida_detection
            self._update_display()

    def action_toggle_debug(self) -> None:
        """Toggle debug detection bypass."""
        self.debug_detection = not self.debug_detection
        self._update_display()

    def action_submit(self) -> None:
        """Submit the configuration and start TrigDroid."""
        result = TrigDroidConfig(
            cancelled=False,
            mode=self.mode,
            package_name=self.package_name,
            ssl_unpinning=self.ssl_unpinning,
            root_detection_bypass=self.root_detection,
            emulator_detection_bypass=self.emulator_detection,
            frida_detection_bypass=self.frida_detection,
            debug_detection_bypass=self.debug_detection,
            auto_resume=True,
        )
        self._dismiss_with_refresh(result)
