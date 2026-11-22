"""Settings screen for Sandroid TUI.

Full-screen ModalScreen with TabbedContent for runtime configuration.
Changes are tracked in-memory and only applied on Save (Ctrl+S).
Theme preview is applied live and reverted on Cancel.
"""

import contextlib
import logging
import threading
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.validation import ValidationResult, Validator
from textual.widgets import (
    Button,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
    Tabs,
)

from sandroid.config import SandroidConfig, get_config
from sandroid.config.schema import LogLevel, validate_setting
from sandroid.core.adb import Adb
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.tui.controllers.settings_controller import SettingsController
from sandroid.tui.key_display import key_words
from sandroid.tui.themes import THEME_ORDER, THEMES
from sandroid.tui.utils import apply_compact_widgets

logger = logging.getLogger(__name__)

# Per-category Monitor visibility rows. The widget id uses "__" (not
# "--") after the field name so it doesn't collide with _id_to_key's "--"->"."
# section-separator convention -- these 6 Selects are assembled into a single
# dict and saved under one key ("tui.monitor_event_visibility"), never routed
# through the generic per-widget key path.
_MONITOR_VISIBILITY_CATEGORIES = (
    "create",
    "modify",
    "delete",
    "rename",
    "attrs",
    "noise",
)
# Base label for the Monitor Source kprobe RadioButton. Availability suffixes
# ("— unavailable on this device" / "— checking…") are appended to it so a
# greyed-out kprobe is never visually indistinguishable from an enabled one
# (the label is the only persistent, always-visible signal; a toast is
# transient). Kept as one constant so compose() and the state helper agree.
_KPROBE_BASE_LABEL = "kprobe (kernel tracefs)"

_MONITOR_VISIBILITY_ID_PREFIX = "setting-tui--monitor_event_visibility__"
_MONITOR_VISIBILITY_LABELS = {
    "create": "Monitor Create:",
    "modify": "Monitor Modify:",
    "delete": "Monitor Delete:",
    "rename": "Monitor Rename:",
    "attrs": "Monitor Attrs:",
    "noise": "Monitor Noise (open/close):",
}


# Settings → Timeline (session timeline policy, Tracking capture, masking).
# Only 2-part config keys are staged: ``timeline.sources`` (dict) and the
# ``timeline.kinds_off`` / ``timeline.count_only`` lists are staged WHOLE, like
# ``tui.monitor_event_visibility``; per-source switches use ``__`` after the
# field name so ``_id_to_key`` never makes a 3-part key of them.
_TIMELINE_SOURCES_PREFIX = "setting-timeline--sources__"
_TIMELINE_SOURCE_ORDER = ("files", "monitor", "net", "input", "screen", "shot", "ai")
_TIMELINE_LIST_IDS = {
    "setting-timeline--kinds_off": "timeline.kinds_off",
    "setting-timeline--count_only": "timeline.count_only",
}
#: Config sections of the Timeline tab (unchanged values are never saved).
_POLICY_PREFIXES = ("timeline.", "tracking.")
_MISSING = object()


class _FieldCheck(Validator):
    """Textual validator around a ``value -> reason | None`` function."""

    def __init__(self, check: Any) -> None:
        super().__init__()
        self._check = check

    def validate(self, value: str) -> ValidationResult:
        reason = self._check(value)
        return self.success() if reason is None else self.failure(reason)


def _acting_as_user() -> Any:
    """``timeline.acting_as("user")``, or a no-op without the timeline."""
    try:
        from sandroid.core.timeline import acting_as
    except Exception:
        return contextlib.nullcontext()
    return acting_as("user")


#: (field, label, input type) of the numeric timeline / Tracking fields.
_TIMELINE_NUMBERS = (
    ("files_modify_coalesce_ms", "Coalesce modify (ms, 0 off):", "integer"),
    ("count_window_s", "Count window (s):", "number"),
    ("queue_max", "Queue max (lines):", "integer"),
    ("clock_every_s", "Clock sample every (s, 0 off):", "integer"),
)
_TRACKING_SWITCHES = (
    ("auto_on_record", "On while recording:"),
    ("shot_before_tap", "Shot before tap:"),
    ("shot_screen_change", "Shot on screen change:"),
    ("shot_after_tap", "Shot after tap:"),
    ("shot_label", "Shot on label:"),
    ("mark_screenshots", "Mark screenshots:"),
    ("capture_text", "Capture typed text:"),
    ("logcat_screen_backup", "Logcat screen backup:"),
)
_TRACKING_NUMBERS = (
    ("settle_interval_ms", "Settle interval (ms):"),
    ("settle_max_ms", "Settle max (ms):"),
    ("text_idle_ms", "Text idle (ms):"),
    ("long_press_ms", "Long press (ms):"),
    ("swipe_slop_px", "Swipe slop (px):"),
)


class SettingsScreen(ModalScreen[SandroidConfig | None]):
    """Modal settings screen with tabbed configuration panels.

    Returns SandroidConfig on save, None on cancel.
    """

    DEFAULT_CSS = """
    SettingsScreen {
        align: center middle;
        background: rgba(5, 8, 17, 0.85);
    }

    #settings-container {
        /* 90 columns cut the nine tabs off at "Ti" (Timeline): the tab bar
           needs about 92 inside the border and padding. */
        width: 100%;
        max-width: 100;
        height: auto;
        max-height: 42;
        background: #0d1117;
        border: solid #2f81f7;
        padding: 1 2;
    }

    #settings-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
        width: 100%;
    }

    #settings-tabs {
        height: auto;
        max-height: 32;
    }

    TabPane {
        padding: 1;
        height: auto;
    }

    .setting-row {
        height: auto;
        margin-bottom: 1;
        layout: horizontal;
    }

    .setting-label {
        width: 30;
        padding: 0 1 0 0;
        content-align: right middle;
        color: #e5e9f0;
    }

    .setting-control {
        width: 1fr;
    }

    .setting-input {
        width: 40;
    }

    .setting-select {
        width: 40;
    }

    .setting-switch {
        width: auto;
        background: $panel;
        border: none;
        padding: 0 1;
        height: 1;
        min-height: 1;
    }

    .setting-switch:focus {
        background: $accent;
        border: none;
        text-style: bold;
    }

    .switch-state {
        width: auto;
        height: 1;
        padding: 0 0 0 1;
    }

    .switch-state-on {
        color: $success;
        text-style: bold;
    }

    .switch-state-off {
        color: $text-muted;
    }

    .setting-help {
        width: 100%;
        height: auto;
        content-align: left top;
        padding: 0 0 0 1;
        margin-bottom: 1;
    }

    .theme-option {
        height: 1;
        margin-bottom: 0;
    }

    .theme-swatch {
        width: auto;
        margin-left: 2;
    }

    .section-header {
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
        margin-top: 1;
    }

    .settings-error {
        color: $error;
        width: 100%;
        height: auto;
        margin-top: 1;
    }

    .settings-footer {
        text-align: center;
        color: #8b949e;
        margin-top: 1;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("ctrl+s", "save", "Save", priority=True),
        # Not priority: a focused text field keeps Shift+Left/Right for
        # selecting text (same rule as Device settings).
        Binding("shift+left", "cycle_tab(-1)", "Previous tab", show=False),
        Binding("shift+right", "cycle_tab(1)", "Next tab", show=False),
    ]

    #: Focus is placed explicitly (first field of the active tab) once the
    #: screen is mounted; Textual's auto focus picked whatever widget was
    #: focusable first, which differed between opens.
    AUTO_FOCUS = None

    #: Rows of the container around the tabs (border, padding, title,
    #: error line, footer): the tabs get the rest of the screen, at most 32.
    _CHROME_ROWS = 12

    # Dotted config keys that must take effect immediately (not just on
    # Save) because a live, already-mounted widget reads them straight off
    # ``Toolbox.config`` -- e.g. ``ChatPanel._mascot_enabled``/
    # ``_show_verbose_thinking`` -- and would otherwise silently keep
    # showing/using the stale value for the rest of the session (SAVE only
    # rewrites the on-disk file plus the app's own ``SandroidConfig`` copy;
    # it never touches ``Toolbox.config``, see ``_apply_ai_toggle_live``).
    _LIVE_AI_TOGGLE_KEYS = frozenset(
        {"ai.show_chat_mascot", "ai.show_verbose_thinking"}
    )

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the settings screen."""
        super().__init__(name=name, id=id, classes=classes)
        self._pending: dict[str, Any] = {}
        self._controller: SettingsController | None = None
        # Original values of any ``_LIVE_AI_TOGGLE_KEYS`` overwritten via
        # ``_apply_ai_toggle_live`` (parallel to the theme's
        # ``_original_theme_name``) -- restored by
        # ``_revert_ai_toggle_previews`` if the user cancels instead of
        # saving.
        self._ai_toggle_originals: dict[str, bool] = {}
        # Async reentrancy guard for the Monitor Source RadioSet: flipping a
        # ``RadioButton.value`` programmatically re-fires ``RadioSet.Changed``
        # via a queued ``post_message`` (handled a couple of loop iterations
        # later), so the guard is set before the flip and cleared *inside*
        # the re-entrant ``on_radio_set_changed`` call (see
        # ``_revert_backend_to_fsmon``).
        self._reverting_backend = False
        # widget id -> reason of numeric fields holding a bad value (shown
        # red, never staged; Save is refused while any is left).
        self._invalid: dict[str, str] = {}

    def _get_config(self) -> SandroidConfig:
        """Get current config, falling back to defaults."""
        try:
            if hasattr(self.app, "sandroid_config") and self.app.sandroid_config:
                return self.app.sandroid_config
        except Exception:
            pass
        return get_config()

    def _switch_with_state(self, value: bool, id: str) -> ComposeResult:
        """Yield a Switch plus a live 'ON'/'OFF' label reflecting its value.

        The Switch's own slider is subtle at a glance, so every switch row
        gets a colored text label beside it (kept in sync by
        ``on_switch_changed`` via the ``f"{id}-state"`` id convention).
        """
        yield Switch(value=value, id=id, classes="setting-switch")
        yield Static(
            "on" if value else "off",
            id=f"{id}-state",
            classes=f"switch-state {'switch-state-on' if value else 'switch-state-off'}",
        )

    def compose(self) -> ComposeResult:
        """Build the settings screen layout."""
        config = self._get_config()

        with Vertical(id="settings-container"):
            yield Static("Settings", id="settings-title")

            with TabbedContent(id="settings-tabs"):
                with TabPane("General", id="tab-general"):
                    with ScrollableContainer():
                        yield from self._compose_general_tab(config)
                with TabPane("Monitor", id="tab-monitor"):
                    with ScrollableContainer():
                        yield from self._compose_monitor_tab(config)
                with TabPane("Analysis", id="tab-analysis"):
                    with ScrollableContainer():
                        yield from self._compose_analysis_tab(config)
                with TabPane("Network & Frida", id="tab-network"):
                    with ScrollableContainer():
                        yield from self._compose_network_tab(config)
                with TabPane("Appearance", id="tab-appearance"):
                    with ScrollableContainer():
                        yield from self._compose_appearance_tab(config)
                with TabPane("MVT", id="tab-mvt"):
                    with ScrollableContainer():
                        yield from self._compose_mvt_tab(config)
                with TabPane("AI Chat", id="tab-ai-chat"):
                    with ScrollableContainer():
                        yield from self._compose_ai_chat_tab(config)
                with TabPane("Timeouts", id="tab-timeouts"):
                    with ScrollableContainer():
                        yield from self._compose_timeouts_tab(config)
                with TabPane("Timeline", id="tab-timeline"):
                    with ScrollableContainer():
                        yield from self._compose_timeline_tab(config)

            yield Static("", id="settings-error", classes="settings-error")
            yield Static(
                # main's keys, in the one hint style (Key action · …, Esc last)
                "[dim]"
                + key_words(
                    "Ctrl+S save · Tab / Shift+Tab next / previous field · "
                    "Shift+Left / Shift+Right tab · Esc cancel"
                )
                + "[/dim]",
                classes="settings-footer",
            )

    def _compose_general_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the General settings tab."""
        # Log Level
        with Horizontal(classes="setting-row"):
            yield Label("Log Level:", classes="setting-label")
            yield Select(
                [(level.value, level.value) for level in LogLevel],
                value=(
                    config.log_level.value
                    if isinstance(config.log_level, LogLevel)
                    else str(config.log_level)
                ),
                id="setting-log_level",
                classes="setting-select",
            )

        # (No "Default View" row: the TUI has no views since 2.1, and
        # ``analysis.default_view`` only matters to the legacy CLI.)

        # Emulator Device Name
        with Horizontal(classes="setting-row"):
            yield Label("AVD Device Name:", classes="setting-label")
            yield Input(
                value=config.emulator.device_name,
                id="setting-emulator--device_name",
                classes="setting-input",
            )

        # AVD Headless
        with Horizontal(classes="setting-row"):
            yield Label("AVD Headless:", classes="setting-label")
            yield from self._switch_with_state(
                config.emulator.avd_headless, "setting-emulator--avd_headless"
            )

        # Device clock sync at session start and after a snapshot load
        # (offsets go to the session timeline either way)
        with Horizontal(classes="setting-row"):
            yield Label(
                "Sync device clock to host (session start + snapshot loads)",
                classes="setting-label",
            )
            yield from self._switch_with_state(
                config.emulator.sync_device_clock,
                "setting-emulator--sync_device_clock",
            )

        # Frida Auto-Start
        with Horizontal(classes="setting-row"):
            yield Label("Frida Auto-Start:", classes="setting-label")
            yield from self._switch_with_state(
                config.frida.server_auto_start, "setting-frida--server_auto_start"
            )

        # Persona snapshots: fresh texts up to now when one is loaded
        world = getattr(config, "world", None)
        with Horizontal(classes="setting-row"):
            yield Label("Persona top-up:", classes="setting-label")
            yield from self._switch_with_state(
                bool(getattr(world, "persona_topup", True)),
                "setting-world--persona_topup",
            )
        yield Static(
            "[dim]A loaded persona snapshot gets new SMS, calls and events "
            "for the time since it was saved; off keeps the saved texts as "
            "they are.[/dim]",
            classes="setting-help",
        )

        # Flush Package Cache
        with Horizontal(classes="setting-row"):
            yield Label("Package Cache:", classes="setting-label")
            yield Button(
                "Flush Cache",
                id="btn-flush-pkg-cache",
                variant="warning",
            )

    def _compose_monitor_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the File System Monitor settings tab.

        Holds every live FS-Monitor setting: the backend Source selector
        (fsmon vs kprobe), the default monitor path, buffer/line limits, and
        the per-category event-visibility Selects. The Source uses a
        ``RadioSet`` (not a ``Select``) because Textual's ``Select`` cannot
        disable a single option -- kprobe must be greyed out (via
        ``RadioButton.disabled``) on devices whose kernel lacks kprobe
        support.
        """
        # Source (backend) selector -- kprobe preferred, fsmon fallback.
        yield Static("Source", classes="section-header")
        with RadioSet(id="setting-tui--monitor_backend"):
            yield RadioButton(
                _KPROBE_BASE_LABEL,
                value=(config.tui.monitor_backend == "kprobe"),
                id="backend-kprobe",
            )
            yield RadioButton(
                "fsmon (binary)",
                value=(config.tui.monitor_backend == "fsmon"),
                id="backend-fsmon",
            )
        yield Static(
            "[dim]kprobe reads the kernel's tracefs and auto-falls-back to "
            "fsmon when the kernel lacks support. Multi-path monitoring needs "
            "kprobe.[/dim]",
            classes="setting-help",
        )

        # Default monitor path (drives the monitor session modal's prefill).
        with Horizontal(classes="setting-row"):
            yield Label("Default Path:", classes="setting-label")
            yield Input(
                value=config.device_paths.default_monitor_path,
                id="setting-device_paths--default_monitor_path",
                classes="setting-input",
            )

        # Monitor Buffer Interval
        with Horizontal(classes="setting-row"):
            yield Label("Monitor Buffer (s):", classes="setting-label")
            yield Input(
                value=str(config.tui.monitor_buffer_interval),
                id="setting-tui--monitor_buffer_interval",
                type="number",
                classes="setting-input",
            )

        # Monitor Max Lines
        with Horizontal(classes="setting-row"):
            yield Label("Monitor Max Lines:", classes="setting-label")
            yield Input(
                value=str(config.tui.monitor_max_lines),
                id="setting-tui--monitor_max_lines",
                type="integer",
                classes="setting-input",
            )

        # Files lens: auto-pull ★ files when the monitor sees a write.
        with Horizontal(classes="setting-row"):
            yield Label("Auto-pull ★ on change:", classes="setting-label")
            yield from self._switch_with_state(
                config.tui.auto_pull_on_change, "setting-tui--auto_pull_on_change"
            )
        yield Static(
            "[dim]Files lens: a watched file is pulled, versioned and diffed "
            "~1.5 s after the monitor's last write to it (u/U pull by hand).[/dim]",
            classes="setting-help",
        )

        # App mode: follow the app (all processes, restarts), not one PID.
        with Horizontal(classes="setting-row"):
            yield Label("Follow the app:", classes="setting-label")
            yield from self._switch_with_state(
                config.tui.monitor_follow_app, "setting-tui--monitor_follow_app"
            )
        yield Static(
            "[dim]App mode watches every process of the app and picks up "
            "restarts and new processes (kprobe); off = one PID and its "
            "children. Default for the monitor dialog's checkbox.[/dim]",
            classes="setting-help",
        )

        # Monitor per-category event visibility (Always / Only in verbose / Never)
        for category in _MONITOR_VISIBILITY_CATEGORIES:
            with Horizontal(classes="setting-row"):
                yield Label(
                    _MONITOR_VISIBILITY_LABELS[category], classes="setting-label"
                )
                yield Select(
                    [
                        ("Always", "always"),
                        ("Only in verbose", "verbose"),
                        ("Never", "never"),
                    ],
                    value=config.tui.monitor_event_visibility.get(category, "always"),
                    id=f"{_MONITOR_VISIBILITY_ID_PREFIX}{category}",
                    classes="setting-select",
                )

    def _compose_analysis_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the Analysis settings tab."""
        # Number of Runs
        with Horizontal(classes="setting-row"):
            yield Label("Number of Runs:", classes="setting-label")
            yield Input(
                value=str(config.analysis.number_of_runs),
                id="setting-analysis--number_of_runs",
                type="integer",
                classes="setting-input",
            )

        # Replay settle time
        with Horizontal(classes="setting-row"):
            yield Label("Replay Settle (s):", classes="setting-label")
            yield Input(
                value=str(config.analysis.replay_settle_seconds),
                id="setting-analysis--replay_settle_seconds",
                type="integer",
                classes="setting-input",
            )

        # Network reset after each snapshot load (stale snapshot sockets)
        with Horizontal(classes="setting-row"):
            yield Label("Network Reset After Load:", classes="setting-label")
            yield Select(
                [
                    ("Airplane mode on/off", "airplane"),
                    ("svc wifi/data off/on", "svc"),
                    ("Off", "off"),
                ],
                value=config.analysis.network_reset_after_snapshot,
                id="setting-analysis--network_reset_after_snapshot",
                allow_blank=False,
                classes="setting-select",
            )

        # Capture Processes
        with Horizontal(classes="setting-row"):
            yield Label("Capture Processes:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.capture_processes, "setting-analysis--capture_processes"
            )

        # Capture Sockets
        with Horizontal(classes="setting-row"):
            yield Label("Capture Sockets:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.capture_sockets, "setting-analysis--capture_sockets"
            )

        # Capture Network Traffic
        with Horizontal(classes="setting-row"):
            yield Label("Capture Network Traffic:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.capture_network, "setting-analysis--capture_network"
            )

        # Hash Files
        with Horizontal(classes="setting-row"):
            yield Label("Hash Files:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.hash_files, "setting-analysis--hash_files"
            )

        # Show Deleted Files
        with Horizontal(classes="setting-row"):
            yield Label("Show Deleted Files:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.show_deleted_files,
                "setting-analysis--show_deleted_files",
            )

        # List APKs
        with Horizontal(classes="setting-row"):
            yield Label("List APKs:", classes="setting-label")
            yield from self._switch_with_state(
                config.analysis.list_apks, "setting-analysis--list_apks"
            )

        # Results Path (§11 configurable data-storage root). Run bundles
        # (runs/<id>/) live under this directory; run_history/run_bundle
        # resolve their storage root from get_config().paths.results_path, so
        # saving here (SettingsController.save updates the live config in
        # place) moves future Record->Play runs to the new root.
        with Horizontal(classes="setting-row"):
            yield Label("Results Path:", classes="setting-label")
            yield Input(
                value=str(config.paths.results_path),
                id="setting-paths--results_path",
                classes="setting-input",
            )
        yield Static(
            "[dim]Root directory for analysis results and Record->Play run "
            "bundles. Takes effect on the next run after Save.[/dim]",
            classes="setting-help",
        )

    def _compose_network_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the Network & Frida settings tab."""
        yield Static("Frida", classes="section-header")

        # Frida Server Port
        with Horizontal(classes="setting-row"):
            yield Label("Server Port:", classes="setting-label")
            yield Input(
                value=str(config.frida.server_port),
                id="setting-frida--server_port",
                type="integer",
                classes="setting-input",
            )

        # Frida Spawn Timeout
        with Horizontal(classes="setting-row"):
            yield Label("Spawn Timeout (s):", classes="setting-label")
            yield Input(
                value=str(config.frida.spawn_timeout),
                id="setting-frida--spawn_timeout",
                type="integer",
                classes="setting-input",
            )

        # Frida Server Version
        try:
            import frida as _frida_mod

            host_frida_ver = _frida_mod.__version__
        except Exception:
            host_frida_ver = "unknown"

        saved = config.frida.server_version or "host"
        # Legacy alias: 'auto' resolves to 'host' canonically
        normalized = "host" if saved == "auto" else saved

        options: list[tuple[str, str]] = [
            (f"Match host ({host_frida_ver})", "host"),
            ("Latest (fetching…)", "latest"),
        ]
        # If the saved value is a specific version, include it so the Select
        # can pre-select it. The async populate will replace this with the
        # full GitHub-fetched list.
        if normalized not in ("host", "latest"):
            options.append((normalized, normalized))
        options.append(("Custom…", "__custom__"))

        with Horizontal(classes="setting-row"):
            yield Label("Server Version:", classes="setting-label")
            yield Select(
                options,
                value=normalized,
                id="setting-frida--server_version",
                classes="setting-select",
                allow_blank=False,
            )

        # Custom version input row — visibility is toggled in on_mount and
        # via on_select_changed when "Custom…" is picked.
        with Horizontal(classes="setting-row", id="frida-version-custom-row"):
            yield Label("Custom version:", classes="setting-label")
            yield Input(
                value="",
                placeholder="e.g. 17.9.11",
                id="setting-frida--server_version_custom",
                classes="setting-input",
            )

        # Info lines — Host / Latest / Installed. Updated by background thread.
        yield Static(
            f"[dim]Host frida:     {host_frida_ver}[/dim]",
            id="frida-info-host",
            classes="setting-label",
        )
        yield Static(
            "[dim]Latest frida:   fetching…[/dim]",
            id="frida-info-latest",
            classes="setting-label",
        )
        yield Static(
            "[dim]Installed:      checking…[/dim]",
            id="frida-info-installed",
            classes="setting-label",
        )

        yield Static("Network", classes="section-header")

        # PCAP Buffer Size
        with Horizontal(classes="setting-row"):
            yield Label("PCAP Buffer Size:", classes="setting-label")
            yield Input(
                value=str(config.network.pcap_buffer_size),
                id="setting-network--pcap_buffer_size",
                type="integer",
                classes="setting-input",
            )

        # Connection Timeout
        with Horizontal(classes="setting-row"):
            yield Label("Connection Timeout (s):", classes="setting-label")
            yield Input(
                value=str(config.network.connection_timeout),
                id="setting-network--connection_timeout",
                type="integer",
                classes="setting-input",
            )

        yield Static("mitmproxy", classes="section-header")

        # Device proxy on mitmproxy start
        with Horizontal(classes="setting-row"):
            yield Label("Set device proxy on start:", classes="setting-label")
            yield from self._switch_with_state(
                config.mitmproxy.auto_device_proxy,
                "setting-mitmproxy--auto_device_proxy",
            )

        # App-proxy lanes (per-app proxy pool size; config key stays focus_lanes).
        with Horizontal(classes="setting-row"):
            yield Label("App proxy lanes:", classes="setting-label")
            yield Input(
                value=str(config.mitmproxy.focus_lanes),
                id="setting-mitmproxy--focus_lanes",
                type="integer",
                classes="setting-input",
            )
        yield Static(
            "[dim]Max number of apps that can have their own proxy at once. "
            "Each lane = one on-device redirector + one mitmproxy SOCKS port; "
            "higher = more device/host resources. Takes effect on next "
            "mitmproxy start.[/dim]",
            classes="setting-label",
        )

    def _compose_appearance_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the Appearance settings tab."""
        current_theme = config.tui.theme if config.tui else "default"

        yield Static("Theme", classes="section-header")

        with RadioSet(id="setting-tui--theme"):
            for theme_name in THEME_ORDER:
                theme = THEMES[theme_name]
                # Show color swatches: primary, accent, success
                swatch = (
                    f"[{theme.primary}]\u2588\u2588[/]"
                    f"[{theme.accent}]\u2588\u2588[/]"
                    f"[{theme.success}]\u2588\u2588[/]"
                )
                label = f"{theme.display_name}  {swatch}"
                yield RadioButton(
                    label,
                    value=(theme_name == current_theme),
                    id=f"theme-{theme_name}",
                    classes="theme-option",
                )

        # Show Theme Indicator
        with Horizontal(classes="setting-row"):
            yield Label("Show Theme Indicator:", classes="setting-label")
            yield from self._switch_with_state(
                config.tui.show_theme_indicator if config.tui else False,
                "setting-tui--show_theme_indicator",
            )

        # Immediate Exit on Ctrl+C
        with Horizontal(classes="setting-row"):
            yield Label("Immediate Ctrl+C Exit:", classes="setting-label")
            yield from self._switch_with_state(
                config.tui.immediate_exit_on_ctrl_c if config.tui else False,
                "setting-tui--immediate_exit_on_ctrl_c",
            )

    def _compose_mvt_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the MVT settings tab."""
        mvt = config.mvt

        # MVT Enabled
        with Horizontal(classes="setting-row"):
            yield Label("MVT Enabled:", classes="setting-label")
            yield from self._switch_with_state(mvt.enabled, "setting-mvt--enabled")

        # Scan SMS
        with Horizontal(classes="setting-row"):
            yield Label("Scan SMS:", classes="setting-label")
            yield from self._switch_with_state(mvt.scan_sms, "setting-mvt--scan_sms")

        # Scan Calls
        with Horizontal(classes="setting-row"):
            yield Label("Scan Calls:", classes="setting-label")
            yield from self._switch_with_state(
                mvt.scan_calls, "setting-mvt--scan_calls"
            )

        # Scan Apps
        with Horizontal(classes="setting-row"):
            yield Label("Scan Apps:", classes="setting-label")
            yield from self._switch_with_state(mvt.scan_apps, "setting-mvt--scan_apps")

        # Scan Files
        with Horizontal(classes="setting-row"):
            yield Label("Scan Files:", classes="setting-label")
            yield from self._switch_with_state(
                mvt.scan_files, "setting-mvt--scan_files"
            )

        # Output Format
        with Horizontal(classes="setting-row"):
            yield Label("Output Format:", classes="setting-label")
            yield Select(
                [("json", "json"), ("csv", "csv"), ("both", "both")],
                value=mvt.output_format,
                id="setting-mvt--output_format",
                classes="setting-select",
            )

    def _compose_ai_chat_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the AI Chat settings tab."""
        yield Static("AI Chat", classes="section-header")

        # Show Verbose Thinking
        with Horizontal(classes="setting-row"):
            yield Label("Show Verbose Thinking:", classes="setting-label")
            yield from self._switch_with_state(
                config.ai.show_verbose_thinking, "setting-ai--show_verbose_thinking"
            )
        yield Static(
            "[dim]When on, the model's full reasoning/thinking text stays "
            "visible in the transcript. When off (default), it collapses "
            "into a single 'Thought for Ns' line once the reasoning phase "
            "ends.[/dim]",
            classes="setting-help",
        )

        # Show Chat Mascot
        with Horizontal(classes="setting-row"):
            yield Label("Show Chat Mascot:", classes="setting-label")
            yield from self._switch_with_state(
                config.ai.show_chat_mascot, "setting-ai--show_chat_mascot"
            )
        yield Static(
            "[dim]Show the small animated mascot beside the Chat panel's "
            "message input while Sandroid is thinking or replying.[/dim]",
            classes="setting-help",
        )

    def _compose_timeouts_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the Timeouts settings tab."""
        timeouts = config.timeouts

        timeout_fields = [
            ("ADB Command (s):", "timeouts--adb_command", timeouts.adb_command),
            ("ADB Pull (s):", "timeouts--adb_pull", timeouts.adb_pull),
            (
                "ADB Pull Large (s):",
                "timeouts--adb_pull_large",
                timeouts.adb_pull_large,
            ),
            ("ADB Push (s):", "timeouts--adb_push", timeouts.adb_push),
            (
                "Network Download (s):",
                "timeouts--network_download",
                timeouts.network_download,
            ),
            ("Subprocess (s):", "timeouts--subprocess", timeouts.subprocess),
        ]

        for label_text, setting_id, current_value in timeout_fields:
            with Horizontal(classes="setting-row"):
                yield Label(label_text, classes="setting-label")
                yield Input(
                    value=str(current_value),
                    id=f"setting-{setting_id}",
                    type="integer",
                    classes="setting-input",
                )

    def _compose_timeline_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the Timeline tab: policy, masking, Tracking capture."""
        timeline = getattr(config, "timeline", None)
        tracking = getattr(config, "tracking", None)
        ai = getattr(config, "ai", None)
        if timeline is None and tracking is None:
            yield Static(
                "[dim]The session timeline is not installed in this build.[/dim]",
                classes="setting-help",
            )
            return
        if timeline is not None:
            yield Static("Session timeline", classes="section-header")
            sources = dict(getattr(timeline, "sources", None) or {})
            order = [s for s in _TIMELINE_SOURCE_ORDER if s in sources]
            order += sorted(s for s in sources if s not in order)
            for src in order:
                with Horizontal(classes="setting-row"):
                    yield Label(f"Record {src}:", classes="setting-label")
                    yield from self._switch_with_state(
                        bool(sources[src]), f"{_TIMELINE_SOURCES_PREFIX}{src}"
                    )
            yield Static(
                "[dim]Labels, snapshots, devices, runs and clock lines are "
                "always recorded.[/dim]",
                classes="setting-help",
            )
            for field, label in (
                ("kinds_off", "Kinds off (src.kind, …):"),
                ("count_only", "Count only (src.kind, …):"),
            ):
                with Horizontal(classes="setting-row"):
                    yield Label(label, classes="setting-label")
                    yield Input(
                        value=", ".join(getattr(timeline, field, None) or []),
                        id=f"setting-timeline--{field}",
                        classes="setting-input",
                    )
            with Horizontal(classes="setting-row"):
                yield Label("File attrs:", classes="setting-label")
                yield Select(
                    [
                        ("Lines in the app's dirs", "app_dirs"),
                        ("Always lines", "lines"),
                        ("Counts only", "counts"),
                    ],
                    value=getattr(timeline, "files_attrs", "app_dirs"),
                    id="setting-timeline--files_attrs",
                    classes="setting-select",
                    allow_blank=False,
                )
            for field, label, kind in _TIMELINE_NUMBERS:
                with Horizontal(classes="setting-row"):
                    yield Label(label, classes="setting-label")
                    yield Input(
                        value=str(getattr(timeline, field, "")),
                        id=f"setting-timeline--{field}",
                        type=kind,
                        classes="setting-input",
                    )
            yield Static("Masking", classes="section-header")
            with Horizontal(classes="setting-row"):
                yield Label("Mask sensitive lines:", classes="setting-label")
                yield from self._switch_with_state(
                    bool(getattr(timeline, "mask_sensitive", False)),
                    "setting-timeline--mask_sensitive",
                )
            yield Static(
                "[dim]Typed text and other sensitive lines show masked in the "
                "Timeline lens, exports and reports (V reveals one, "
                "recorded).[/dim]",
                classes="setting-help",
            )
        if ai is not None and hasattr(ai, "mask_sensitive"):
            with Horizontal(classes="setting-row"):
                yield Label("Mask for the AI:", classes="setting-label")
                yield from self._switch_with_state(
                    bool(ai.mask_sensitive), "setting-ai--mask_sensitive"
                )
        if tracking is not None:
            yield Static("Tracking (Ctrl+T)", classes="section-header")
            with Horizontal(classes="setting-row"):
                yield Label("UI helper:", classes="setting-label")
                yield Select(
                    [
                        ("Full (accessibility)", "full"),
                        ("Invisible (no a11y)", "invisible"),
                        ("Off", "off"),
                    ],
                    value=getattr(tracking, "helper_mode", "full"),
                    id="setting-tracking--helper_mode",
                    classes="setting-select",
                    allow_blank=False,
                )
            for field, label in _TRACKING_SWITCHES:
                with Horizontal(classes="setting-row"):
                    yield Label(label, classes="setting-label")
                    yield from self._switch_with_state(
                        bool(getattr(tracking, field, False)),
                        f"setting-tracking--{field}",
                    )
            for field, label in _TRACKING_NUMBERS:
                with Horizontal(classes="setting-row"):
                    yield Label(label, classes="setting-label")
                    yield Input(
                        value=str(getattr(tracking, field, "")),
                        id=f"setting-tracking--{field}",
                        type="integer",
                        classes="setting-input",
                    )

    def _timeline_sources(self) -> dict[str, bool]:
        """Every per-source switch, as the whole ``timeline.sources`` dict."""
        sources: dict[str, bool] = {}
        for switch in self.query(Switch):
            wid = switch.id or ""
            if wid.startswith(_TIMELINE_SOURCES_PREFIX):
                sources[wid[len(_TIMELINE_SOURCES_PREFIX) :]] = bool(switch.value)
        return sources

    # -------------------------------------------------------------------------
    # Event Handlers
    # -------------------------------------------------------------------------

    def on_mount(self) -> None:
        """Initialize controller after mount."""
        apply_compact_widgets(self)
        self._controller = SettingsController(self.app)
        # Hide the custom-version input until the user picks "Custom…"
        try:
            select = self.query_one("#setting-frida--server_version", Select)
            row = self.query_one("#frida-version-custom-row", Horizontal)
            row.display = select.value == "__custom__"
        except Exception:
            pass
        # Populate the Frida version dropdown asynchronously — fetching from
        # GitHub on the UI thread would freeze the TUI for up to 10 seconds.
        threading.Thread(
            target=self._fetch_frida_versions,
            name="settings-frida-versions",
            daemon=True,
        ).start()
        # Grey out / re-select the Monitor Source per this device's kprobe
        # verdict (and warm the cache off-thread when it is unknown).
        self.refresh_backend_availability()
        self.query_one("#settings-error", Static).display = False
        self._attach_field_checks()
        self._fit_to_screen()
        self.call_after_refresh(self._focus_first_field)

    def on_resize(self, event: Any = None) -> None:
        """Keep the footer on screen: the tab body scrolls instead."""
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        """Cap the tabs' height so the container fits the screen height."""
        try:
            tabs = self.query_one("#settings-tabs", TabbedContent)
        except Exception:
            return
        height = self.size.height or self.app.size.height
        tabs.styles.max_height = max(8, min(32, height - self._CHROME_ROWS))

    def _focus_first_field(self) -> None:
        """Focus the first focusable field of the active tab (deterministic)."""
        try:
            tabs = self.query_one("#settings-tabs", TabbedContent)
            pane = tabs.get_pane(tabs.active)
        except Exception:
            return
        for widget in pane.query("Input, Select, Switch, RadioSet, Button"):
            if widget.focusable and widget.display:
                widget.focus()
                return

    def action_cycle_tab(self, delta: int) -> None:
        """Shift+Left/Right: the previous / next tab (wraps); the tab bar
        gets the focus, so Left/Right go on from there.
        """
        try:
            tabs = self.query_one("#settings-tabs", TabbedContent)
        except Exception:
            return
        panes = [pane.id for pane in tabs.query(TabPane) if pane.id]
        if not panes:
            return
        current = panes.index(tabs.active) if tabs.active in panes else 0
        tabs.active = panes[(current + delta) % len(panes)]
        with contextlib.suppress(Exception):
            tabs.query_one(Tabs).focus()

    def _fetch_frida_versions(self) -> None:
        """Background worker: pull available + installed frida versions."""
        tags: list[str] = []
        installed: str | None = None
        try:
            from sandroid.services import get_frida_session_service

            fm = get_frida_session_service().get_frida_manager()
            if fm is not None:
                try:
                    tags = fm.list_available_versions(limit=15) or []
                except Exception as e:
                    logger.debug(f"list_available_versions failed: {e}")
                try:
                    installed = fm.get_installed_server_version()
                except Exception as e:
                    logger.debug(f"get_installed_server_version failed: {e}")
        except Exception as e:
            logger.debug(f"Could not access FridaSessionService: {e}")

        try:
            self.app.call_from_thread(self._populate_frida_versions, tags, installed)
        except Exception:
            # Screen already dismissed
            pass

    def _populate_frida_versions(self, tags: list[str], installed: str | None) -> None:
        """UI-thread callback: rebuild the version Select and info lines."""
        try:
            select = self.query_one("#setting-frida--server_version", Select)
        except Exception:
            return

        host_ver = "unknown"
        try:
            import frida as _frida_mod

            host_ver = _frida_mod.__version__
        except Exception:
            pass

        latest_label = f"Latest ({tags[0]})" if tags else "Latest (offline)"
        current = select.value
        options: list[tuple[str, str]] = [
            (f"Match host ({host_ver})", "host"),
            (latest_label, "latest"),
        ]
        # Up to 10 recent specific versions after Latest
        for tag in tags[:10]:
            options.append((tag, tag))
        # Preserve the currently-selected explicit version if it would
        # otherwise disappear from the list
        existing_values = {v for _, v in options}
        if current and current not in existing_values and current != "__custom__":
            options.append((str(current), str(current)))
        options.append(("Custom…", "__custom__"))

        try:
            select.set_options(options)
            if current and current in {v for _, v in options}:
                select.value = current
        except Exception as e:
            logger.debug(f"Could not update version Select: {e}")

        # Update info lines
        try:
            self.query_one("#frida-info-latest", Static).update(
                f"[dim]Latest frida:   {tags[0] if tags else 'offline'}[/dim]"
            )
        except Exception:
            pass
        try:
            self.query_one("#frida-info-installed", Static).update(
                f"[dim]Installed:      {installed or 'not installed'}[/dim]"
            )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Monitor Source (backend) availability
    # -------------------------------------------------------------------------

    def _set_kprobe_button_state(self, state: str) -> None:
        """Reflect a kprobe availability verdict on the Source RadioButton.

        ``state`` is ``"available"`` / ``"unavailable"`` / ``"checking"``.
        Updates BOTH ``disabled`` and the visible ``label`` -- the label is the
        only persistent, always-visible signal (a toast is transient), so a
        greyed-out kprobe must say WHY. No-ops if the tab isn't mounted.
        """
        try:
            kprobe_btn = self.query_one("#backend-kprobe", RadioButton)
        except Exception:
            return
        if state == "available":
            kprobe_btn.disabled = False
            kprobe_btn.label = _KPROBE_BASE_LABEL
        elif state == "checking":
            kprobe_btn.disabled = True
            kprobe_btn.label = f"{_KPROBE_BASE_LABEL} — checking…"
        else:  # "unavailable"
            kprobe_btn.disabled = True
            kprobe_btn.label = f"{_KPROBE_BASE_LABEL} — unavailable on this device"

    def refresh_backend_availability(self) -> None:
        """Re-sync the Monitor Source selector to this device's kprobe verdict.

        Public so the app's device-change wiring can call it whenever the
        active device changes. ``True`` -> kprobe enabled; ``False`` -> kprobe
        greyed with an "unavailable on this device" label and (per Decision C)
        the visible selection flipped to fsmon if kprobe was checked; ``None``
        with a device connected -> a transient "checking…" state (kprobe
        disabled so the user can't pick an unconfirmed source) while an
        off-thread warm-up probe runs. No-ops safely if the tab isn't mounted.
        """
        try:
            self.query_one("#backend-kprobe", RadioButton)
        except Exception:
            return  # Monitor tab not mounted

        verdict = KprobeTracer.cached_availability()
        if verdict is True:
            self._set_kprobe_button_state("available")
            return
        if verdict is False:
            self._set_kprobe_button_state("unavailable")
            self._select_fsmon_visually()
            return

        # Unknown (None): probe off-thread if a device is connected, showing a
        # transient "checking…" state so the user can't select an unconfirmed
        # source (avoids the confusing select-then-snap-back). With no device
        # there is nothing to probe and nothing to monitor -- leave kprobe
        # selectable/optimistic (the runtime falls back per-device anyway).
        if Adb.get_target_device():
            self._set_kprobe_button_state("checking")
            threading.Thread(
                target=self._warm_kprobe_availability,
                name="settings-kprobe-warmup",
                daemon=True,
            ).start()
        else:
            self._set_kprobe_button_state("available")

    def _warm_kprobe_availability(self) -> None:
        """Off-thread: probe kprobe support, then apply the boolean verdict.

        Runs the heavy :meth:`KprobeTracer.kprobe_supported` (adb round-trip)
        off the UI thread and marshals its BOOLEAN result back. We act on that
        bool -- not a re-read of :meth:`cached_availability` -- because an
        inconclusive probe leaves the cache ``None`` while the bool is
        ``False``; keying off the cache would wrongly leave a known-unusable
        kprobe selectable.
        """
        try:
            supported = KprobeTracer.kprobe_supported()
        except Exception as e:
            logger.debug(f"kprobe warm-up probe failed: {e}")
            return
        try:
            self.app.call_from_thread(self._apply_warmed_availability, supported)
        except Exception:
            # Screen already dismissed
            pass

    def _apply_warmed_availability(self, supported: bool) -> None:
        """UI-thread callback: apply a warmed kprobe boolean to the selector."""
        try:
            kprobe_btn = self.query_one("#backend-kprobe", RadioButton)
        except Exception:
            return
        if supported:
            self._set_kprobe_button_state("available")
            return
        was_selected = kprobe_btn.value
        self._set_kprobe_button_state("unavailable")
        if was_selected:
            self._select_fsmon_visually()
            self.notify(
                "kprobe unavailable on this device — using fsmon",
                severity="warning",
            )

    def _select_fsmon_visually(self) -> None:
        """Flip the visible Source selection to fsmon WITHOUT persisting it.

        kprobe availability is per-device, but ``tui.monitor_backend`` is a
        GLOBAL preference. When kprobe is unavailable on the current device we
        show fsmon (the source that will actually run) but must NOT overwrite a
        saved ``kprobe`` preference -- so any optimistic pending backend
        override is DROPPED rather than replaced with ``fsmon``. On Ctrl+S the
        untouched saved value (e.g. ``kprobe``) is preserved, and a later
        capable device re-enables kprobe. Only an EXPLICIT user pick of fsmon
        (in :meth:`_handle_monitor_backend_changed`) persists ``fsmon``.

        Sets :attr:`_reverting_backend` before the programmatic
        ``RadioButton.value = True`` because that assignment re-fires
        ``RadioSet.Changed`` via a queued ``post_message``; the guard is
        cleared inside that re-entrant :meth:`_handle_monitor_backend_changed`
        call. Only guards when the button actually needs flipping (an unchanged
        ``value`` posts nothing).
        """
        self._pending.pop("tui.monitor_backend", None)
        try:
            fsmon_btn = self.query_one("#backend-fsmon", RadioButton)
        except Exception:
            return
        if not fsmon_btn.value:
            self._reverting_backend = True
            try:
                fsmon_btn.value = True
            except Exception:
                # Guard against a stuck _reverting_backend if the assignment
                # itself ever raised (no RadioSet.Changed would then fire to
                # clear it via the normal re-entrant path).
                self._reverting_backend = False
                raise

    def _probe_kprobe_after_select(self) -> None:
        """Off-thread: probe kprobe after the user interactively selects it.

        Called with an unknown (``None``) cached verdict, after
        :meth:`_handle_monitor_backend_changed` already set the button to
        "checking...". Marshals BOTH outcomes back to the UI thread: a
        confirmed-unavailable result reverts to fsmon (with a toast); a
        confirmed-available result restores the plain "available" state (else
        the button would be stuck reading "checking..." forever).
        """
        try:
            supported = KprobeTracer.kprobe_supported()
        except Exception as e:
            logger.debug(f"kprobe select-probe failed: {e}")
            supported = False
        try:
            self.app.call_from_thread(self._on_kprobe_select_probed, supported)
        except Exception:
            # Screen already dismissed
            pass

    def _on_kprobe_select_probed(self, supported: bool) -> None:
        """UI-thread callback: apply the interactive select-probe's verdict."""
        if supported:
            self._set_kprobe_button_state("available")
            return
        self._on_kprobe_select_unavailable()

    def _on_kprobe_select_unavailable(self) -> None:
        """UI-thread callback: an interactively-selected kprobe was unavailable."""
        self._set_kprobe_button_state("unavailable")
        # Drops the optimistic pending "kprobe" and flips the view to fsmon.
        self._select_fsmon_visually()
        self.notify(
            "kprobe unavailable on this device — using fsmon",
            severity="warning",
        )

    @staticmethod
    def _id_to_key(widget_id: str) -> str:
        """Convert widget ID to dotted config key.

        Widget IDs use ``--`` as the section separator because Textual
        forbids dots in identifiers.  This helper strips the ``setting-``
        prefix and converts ``--`` back to ``.`` so the controller
        receives standard dotted paths like ``frida.server_port``.
        """
        return widget_id[len("setting-") :].replace("--", ".")

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Track switch changes.

        Most switches only stage into ``self._pending`` (applied on Save).
        The AI Chat switches are the exception -- ``ChatPanel`` reads
        ``Toolbox.config.ai.*`` live off whichever object is currently
        installed there, so those two apply immediately, mirroring how the
        Appearance tab's theme radio already live-previews before Save (see
        ``_apply_ai_toggle_live``).
        """
        widget_id = event.switch.id
        if widget_id and widget_id.startswith("setting-"):
            if widget_id.startswith(_TIMELINE_SOURCES_PREFIX):
                # Staged whole (2-part key), like monitor_event_visibility.
                self._pending["timeline.sources"] = self._timeline_sources()
            else:
                key = self._id_to_key(widget_id)
                self._pending[key] = event.value
                if key in self._LIVE_AI_TOGGLE_KEYS:
                    self._apply_ai_toggle_live(key, event.value)
            try:
                state_label = self.query_one(f"#{widget_id}-state", Static)
                state_label.update("on" if event.value else "off")
                state_label.set_class(event.value, "switch-state-on")
                state_label.set_class(not event.value, "switch-state-off")
            except Exception:
                pass

    def _apply_ai_toggle_live(self, key: str, value: bool) -> None:
        """Apply an AI Chat switch to the live config, then repaint ChatPanel.

        ``ChatPanel._mascot_enabled``/``_show_verbose_thinking`` read
        ``Toolbox.config.ai`` at the moment they're needed -- not
        ``self.app.sandroid_config`` and not ``get_config()``'s cache -- so
        a value that only sits in ``self._pending`` (or even one that's been
        saved: ``SettingsController.save()`` builds an entirely new
        ``SandroidConfig`` from disk and never reassigns ``Toolbox.config``)
        would stay invisible to the live Chat tab until the app restarts.
        Writing the live object's attribute directly is what actually makes
        the toggle real *right now*; poking the mounted ``ChatPanel``
        afterwards (mascot only -- see its docstring for why verbose
        thinking needs no repaint) is what makes that take visible effect
        without waiting for the next chat turn.
        """
        try:
            from sandroid.core.toolbox import Toolbox

            ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        except Exception:
            ai_cfg = None
        if ai_cfg is None:
            return

        field = key.split(".", 1)[1]
        if key not in self._ai_toggle_originals:
            self._ai_toggle_originals[key] = getattr(ai_cfg, field, value)
        setattr(ai_cfg, field, value)

        if key == "ai.show_chat_mascot":
            self._refresh_chat_panel()

    def _revert_ai_toggle_previews(self) -> None:
        """Undo any ``_apply_ai_toggle_live`` writes on Cancel.

        Parallel to ``SettingsController.revert_theme_preview`` -- a switch
        flipped live for preview but never saved must not silently stick.
        """
        if not self._ai_toggle_originals:
            return
        try:
            from sandroid.core.toolbox import Toolbox

            ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        except Exception:
            ai_cfg = None
        if ai_cfg is not None:
            for key, original in self._ai_toggle_originals.items():
                setattr(ai_cfg, key.split(".", 1)[1], original)
        self._ai_toggle_originals.clear()
        self._refresh_chat_panel()

    def _refresh_chat_panel(self) -> None:
        """Best-effort: make an already-mounted ``ChatPanel`` re-sync its
        mascot to whatever ``config.ai.show_chat_mascot`` is now.

        ``ChatPanel`` lives on ``MainScreen``, underneath this modal in the
        screen stack, so ``self.app.query_one`` (which only searches the
        active/default screen) can't see it -- walking ``screen_stack`` is
        the established fallback for reaching a widget on a screen below a
        pushed modal (see ``HelpScreen._snapshots_panel``,
        ``ProxyModal._set_glance_device_proxy``). A no-op if the Chat tab
        was never mounted (e.g. another view is active, or no MainScreen at
        all -- some tests push this screen standalone).
        """
        from sandroid.tui.widgets.chat_panel import ChatPanel

        for screen in self.app.screen_stack:
            try:
                panel = screen.query_one(ChatPanel)
            except Exception:
                continue
            # refresh_header() is ChatPanel's existing public repaint hook
            # (already used cross-widget by MainScreen.toggle_chat_panel)
            # -- it re-renders the header text (no-op here, header state is
            # untouched) and, as its docstring says, is "the single choke
            # point that syncs the mascot to _header_state", i.e. exactly
            # the re-check-config-and-repaint this bug needs. No new
            # cross-widget notification mechanism needed.
            panel.refresh_header()
            return

    def on_select_changed(self, event: Select.Changed) -> None:
        """Track select changes."""
        widget_id = event.select.id
        if not widget_id or not widget_id.startswith("setting-"):
            return
        key = self._id_to_key(widget_id)

        # Frida version Select uses a "__custom__" sentinel to reveal a
        # free-text Input. Never persist the sentinel itself — store the
        # custom Input's current text instead, and toggle the row's
        # visibility based on the selection.
        if key == "frida.server_version":
            try:
                custom_row = self.query_one("#frida-version-custom-row", Horizontal)
                custom_input = self.query_one(
                    "#setting-frida--server_version_custom", Input
                )
            except Exception:
                custom_row = None
                custom_input = None

            if event.value == "__custom__":
                if custom_row is not None:
                    custom_row.display = True
                if custom_input is not None:
                    self._pending[key] = custom_input.value or "host"
                return

            if custom_row is not None:
                custom_row.display = False

        # Monitor per-category visibility Selects don't map to a single flat
        # key -- they must be assembled into one dict written under
        # "tui.monitor_event_visibility". SettingsController.save (via
        # config.update_config) does a full REPLACE (not a merge), so re-read ALL 6
        # Selects' *current* values every time any one of them fires
        # Changed (the one that just changed has already updated its
        # .value by now) and write the complete dict. This makes each edit
        # self-contained and correct regardless of save/reload timing --
        # never accumulate partial state across edits, or a save would
        # silently wipe the other categories.
        if widget_id.startswith(_MONITOR_VISIBILITY_ID_PREFIX):
            visibility: dict[str, str] = {}
            for category in _MONITOR_VISIBILITY_CATEGORIES:
                try:
                    select = self.query_one(
                        f"#{_MONITOR_VISIBILITY_ID_PREFIX}{category}", Select
                    )
                    visibility[category] = select.value
                except Exception:
                    pass
            self._pending["tui.monitor_event_visibility"] = visibility
            return

        self._pending[key] = event.value

    def _set_field_error(self, widget: Input, reason: str | None) -> None:
        """Mark *widget* red with *reason* (or clear it) and show the reason."""
        widget_id = widget.id or ""
        if reason:
            self._invalid[widget_id] = reason
        else:
            self._invalid.pop(widget_id, None)
        widget.set_class(bool(reason), "-invalid")
        self._show_field_errors()

    def _field_label(self, widget_id: str) -> str:
        """The row label of a setting widget (its key when there is none)."""
        try:
            widget = self.query_one(f"#{widget_id}")
            label = widget.parent.query_one(Label) if widget.parent else None
            text = str(label.render()).strip().rstrip(":") if label else ""
        except Exception:
            text = ""
        return text or self._id_to_key(widget_id)

    def _show_field_errors(self) -> None:
        """Show the first bad field's reason in red above the footer."""
        try:
            line = self.query_one("#settings-error", Static)
        except Exception:
            return
        if not self._invalid:
            line.update("")
            line.display = False
            return
        widget_id, reason = next(iter(self._invalid.items()))
        more = len(self._invalid) - 1
        text = f"{self._field_label(widget_id)}: {reason}"
        if more:
            text += f" (and {more} more)"
        line.update(text)
        line.display = True

    @staticmethod
    def _numeric_reason(input_type: str, key: str, value: str) -> str | None:
        """Why *value* is not a good *key* (schema type + bounds), or None."""
        cast = int if input_type == "integer" else float
        try:
            number = cast(value)
        except ValueError:
            return "needs a whole number" if cast is int else "needs a number"
        return validate_setting(key, number)

    def _device_name_reason(self, name: str) -> str | None:
        """Why *name* is not a known AVD, or None (unchanged / cannot check)."""
        from sandroid.core.emulator import known_avd_names

        if name == self._get_config().emulator.device_name:
            return None
        if not name.strip():
            return "needs an AVD name"
        known = known_avd_names()
        if known is None or name in known:
            return None
        listed = ", ".join(sorted(known)[:4]) or "none"
        if len(known) > 4:
            listed += ", ..."
        return f"no AVD named {name!r} (known: {listed})"

    def _field_check(self, widget: Input) -> Any:
        """The reason function for a checked field, or None if unchecked."""
        widget_id = widget.id or ""
        if widget_id == "setting-emulator--device_name":
            return self._device_name_reason
        if widget_id.startswith("setting-") and widget.type in ("integer", "number"):
            key = self._id_to_key(widget_id)
            return lambda value: self._numeric_reason(widget.type, key, value)
        return None

    def _attach_field_checks(self) -> None:
        """Give checked fields a validator, so Textual keeps them red."""
        for widget in self.query(Input):
            check = self._field_check(widget)
            if check is not None:
                widget.validators = [*widget.validators, _FieldCheck(check)]

    def on_input_changed(self, event: Input.Changed) -> None:
        """Track input changes."""
        widget_id = event.input.id
        if not widget_id or not widget_id.startswith("setting-"):
            return

        # Numeric fields (schema type + bounds) and the AVD name: a bad
        # value is shown red and never staged (e.g. a negative timeout).
        check = self._field_check(event.input)
        if check is not None:
            reason = check(event.value)
            self._set_field_error(event.input, reason)
            if reason:
                self._pending.pop(self._id_to_key(widget_id), None)
                return

        # Custom Frida version Input writes into frida.server_version (not
        # its own key) so the saved config never contains "__custom__".
        if widget_id == "setting-frida--server_version_custom":
            try:
                select = self.query_one("#setting-frida--server_version", Select)
            except Exception:
                select = None
            if select is not None and select.value == "__custom__":
                self._pending["frida.server_version"] = event.value
            return

        # Timeline kinds_off / count_only: a comma list staged as one list.
        if widget_id in _TIMELINE_LIST_IDS:
            self._pending[_TIMELINE_LIST_IDS[widget_id]] = [
                item.strip() for item in event.value.split(",") if item.strip()
            ]
            return

        # The default monitor path must never be staged empty:
        # ``DevicePathsConfig.validate_non_empty_path`` runs only at
        # construction (not on the setattr save path), so persisting a blank
        # ``""`` would break the *next* config load. Drop any pending value
        # and skip staging when the field is blanked (reverting to the
        # current on-disk value on save).
        if widget_id == "setting-device_paths--default_monitor_path":
            if not event.value.strip():
                self._pending.pop("device_paths.default_monitor_path", None)
                return
            self._pending["device_paths.default_monitor_path"] = event.value
            return

        # The two Monitor-tab numeric fields must not stage an out-of-schema-
        # range value. ``SettingsController.save`` validates the whole config
        # and refuses to save, but dropping the override here keeps the
        # established "drop rather than stage a bad value" behaviour of the
        # blank-default-path guard above for these live-validated fields.
        if widget_id == "setting-tui--monitor_buffer_interval":
            try:
                value = float(event.value)
            except ValueError:
                value = None
            if value is None or not (0.0 <= value <= 5.0):
                self._pending.pop("tui.monitor_buffer_interval", None)
                return
            self._pending["tui.monitor_buffer_interval"] = value
            return
        if widget_id == "setting-tui--monitor_max_lines":
            try:
                value = int(event.value)
            except ValueError:
                value = None
            if value is None or not (50 <= value <= 10000):
                self._pending.pop("tui.monitor_max_lines", None)
                return
            self._pending["tui.monitor_max_lines"] = value
            return

        if widget_id == "setting-analysis--replay_settle_seconds":
            try:
                value = int(event.value)
            except ValueError:
                value = None
            if value is None or not (0 <= value <= 600):
                self._pending.pop("analysis.replay_settle_seconds", None)
                return
            self._pending["analysis.replay_settle_seconds"] = value
            return

        key = self._id_to_key(widget_id)
        # Convert integer inputs
        if event.input.type == "integer":
            try:
                self._pending[key] = int(event.value)
            except ValueError:
                pass  # Don't store invalid integers
        elif event.input.type == "number":
            try:
                self._pending[key] = float(event.value)
            except ValueError:
                pass  # Don't store invalid floats
        else:
            self._pending[key] = event.value

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Track theme and Monitor Source radio changes."""
        radio_set_id = event.radio_set.id
        if radio_set_id == "setting-tui--theme":
            # Extract theme name from radio button id (e.g., "theme-cyberpunk" -> "cyberpunk")
            button_id = event.pressed.id
            if button_id and button_id.startswith("theme-"):
                theme_name = button_id[len("theme-") :]
                self._pending["tui.theme"] = theme_name
                # Live preview
                if self._controller:
                    self._controller.preview_theme(theme_name)
            return

        if radio_set_id == "setting-tui--monitor_backend":
            self._handle_monitor_backend_changed(event)

    def _handle_monitor_backend_changed(self, event: RadioSet.Changed) -> None:
        """Stage the Monitor Source backend, probing kprobe when needed.

        fsmon stages immediately. kprobe stages per the cached verdict:
        ``True`` -> stage ``kprobe``; ``None`` with a device connected ->
        stage ``kprobe`` optimistically, show "checking..." (so the button
        can't be re-clicked mid-probe), and probe off-thread (reverting to
        fsmon + toast if it turns out unavailable, restoring "available" if
        confirmed); ``None`` with no device connected -> nothing to probe,
        leave the optimistic stage as-is (mirrors
        :meth:`refresh_backend_availability`'s no-device policy); ``False``
        -> defensively revert (the button should already be disabled).
        """
        # Reentrancy guard: a programmatic ``RadioButton.value = True``
        # (from ``_revert_backend_to_fsmon``) re-fires this event via a
        # queued ``post_message`` -- clear the flag HERE, inside the
        # re-entrant call, and swallow it so it doesn't re-trigger a probe.
        if self._reverting_backend:
            self._reverting_backend = False
            return

        button_id = event.pressed.id if event.pressed else None
        if button_id == "backend-fsmon":
            self._pending["tui.monitor_backend"] = "fsmon"
            return
        if button_id != "backend-kprobe":
            return

        verdict = KprobeTracer.cached_availability()
        if verdict is True:
            self._pending["tui.monitor_backend"] = "kprobe"
            return
        if verdict is False:
            # Button should already be disabled; defensively fall back
            # (visual only -- don't overwrite the saved kprobe preference).
            self._select_fsmon_visually()
            return

        # Unknown: stage kprobe optimistically. With no device connected
        # there is nothing to probe (mirrors refresh_backend_availability's
        # no-device policy) -- leave the optimistic stage as-is. With a
        # device connected, show "checking..." BEFORE spawning the thread so
        # the user can't select an unconfirmed kprobe mid-probe (matches
        # refresh_backend_availability's ordering).
        self._pending["tui.monitor_backend"] = "kprobe"
        if not Adb.get_target_device():
            return
        self._set_kprobe_button_state("checking")
        threading.Thread(
            target=self._probe_kprobe_after_select,
            name="settings-kprobe-select-probe",
            daemon=True,
        ).start()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-flush-pkg-cache":
            try:
                from sandroid.services import get_app_selection_service

                get_app_selection_service().flush_package_cache()
                self.notify("Package cache flushed", severity="information")
            except Exception as e:
                self.notify(f"Failed to flush cache: {e}", severity="error")

    # -------------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------------

    def action_cancel(self) -> None:
        """Cancel settings - revert theme/AI-toggle previews and dismiss."""
        if self._controller:
            self._controller.revert_theme_preview()
        self._revert_ai_toggle_previews()
        self.app.call_later(self._refresh_app)
        self.dismiss(None)

    def _drop_unchanged_timeline_keys(self) -> None:
        """Unstage ``timeline.*`` / ``tracking.*`` values equal to the config.

        Their Inputs/Selects post ``Changed`` while mounting, which staged
        every one of them (written to the save target and, through the
        config listener, a ``sandroid/policy`` line) although nothing was
        changed. Only these keys: the other tabs keep their behaviour.
        """
        config = self._get_config()
        for key in [k for k in self._pending if k.startswith(_POLICY_PREFIXES)]:
            section, _, field = key.partition(".")
            current = getattr(getattr(config, section, None), field, _MISSING)
            if current is not _MISSING and current == self._pending[key]:
                del self._pending[key]

    def action_save(self) -> None:
        """Save pending settings and dismiss."""
        if self._invalid:
            # A field still holds a bad value (shown red): keep the screen
            # open on it instead of silently saving the old value.
            widget_id = next(iter(self._invalid))
            self._show_field_errors()
            self.notify(
                f"Not saved: {self._field_label(widget_id)}: "
                f"{self._invalid[widget_id]}",
                severity="error",
                title="Invalid setting",
            )
            with contextlib.suppress(Exception):
                widget = self.query_one(f"#{widget_id}")
                tabs = self.query_one("#settings-tabs", TabbedContent)
                pane = next(a for a in widget.ancestors if isinstance(a, TabPane))
                tabs.active = pane.id or tabs.active
                widget.focus()
            return
        self._drop_unchanged_timeline_keys()
        if not self._pending:
            # Nothing changed
            self.app.call_later(self._refresh_app)
            self.dismiss(None)
            return

        from sandroid.config import ConfigUpdateError

        try:
            if self._controller:
                # A Settings save is the user's: the timeline policy line
                # written by the config listener (same thread) says so.
                with _acting_as_user():
                    updated_config = self._controller.save(self._pending)
                # Values already applied live (see _apply_ai_toggle_live)
                # are now persisted -- nothing left to revert.
                self._ai_toggle_originals.clear()
                self.app.call_later(self._refresh_app)
                self.dismiss(updated_config)
            else:
                self.app.call_later(self._refresh_app)
                self.dismiss(None)
        except ConfigUpdateError as e:
            # Invalid value (e.g. Number of Runs < 2): nothing was applied or
            # written -- keep the screen open so the user can correct it.
            logger.warning(f"Settings not saved: {e}")
            self.notify(f"Not saved: {e}", severity="error", title="Invalid setting")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}", exc_info=True)
            self.notify(f"Save failed: {e}", severity="error")

    def _refresh_app(self) -> None:
        """Refresh the app display after modal closes."""
        try:
            self.app.refresh(layout=True)
        except Exception:
            pass
