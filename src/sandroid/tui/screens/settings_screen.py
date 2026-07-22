"""Settings screen for Sandroid TUI.

Full-screen ModalScreen with TabbedContent for runtime configuration.
Changes are tracked in-memory and only applied on Save (Ctrl+S).
Theme preview is applied live and reverted on Cancel.
"""

import logging
import threading
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen
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
)

from sandroid.config import SandroidConfig, get_config
from sandroid.config.schema import LogLevel
from sandroid.tui.controllers.settings_controller import SettingsController
from sandroid.tui.themes import THEME_ORDER, THEMES

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
_MONITOR_VISIBILITY_ID_PREFIX = "setting-tui--monitor_event_visibility__"
_MONITOR_VISIBILITY_LABELS = {
    "create": "Monitor Create:",
    "modify": "Monitor Modify:",
    "delete": "Monitor Delete:",
    "rename": "Monitor Rename:",
    "attrs": "Monitor Attrs:",
    "noise": "Monitor Noise (open/close):",
}


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
        width: 90;
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
    ]

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

    def _get_config(self) -> SandroidConfig:
        """Get current config, falling back to defaults."""
        try:
            if hasattr(self.app, "sandroid_config") and self.app.sandroid_config:
                return self.app.sandroid_config
        except Exception:
            pass
        return get_config()

    def compose(self) -> ComposeResult:
        """Build the settings screen layout."""
        config = self._get_config()

        with Vertical(id="settings-container"):
            yield Static("[bold #58a6ff]=== Settings ===[/]", id="settings-title")

            with TabbedContent(id="settings-tabs"):
                with TabPane("General", id="tab-general"):
                    with ScrollableContainer():
                        yield from self._compose_general_tab(config)
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

            yield Static(
                "[dim]Ctrl+S=Save  Esc=Cancel  Tab/Shift+Tab=Navigate[/dim]",
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

        # Default View
        with Horizontal(classes="setting-row"):
            yield Label("Default View:", classes="setting-label")
            yield Select(
                [
                    ("forensic", "forensic"),
                    ("malware", "malware"),
                    ("security", "security"),
                ],
                value=config.analysis.default_view,
                id="setting-analysis--default_view",
                classes="setting-select",
            )

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
            yield Switch(
                value=config.emulator.avd_headless,
                id="setting-emulator--avd_headless",
                classes="setting-switch",
            )

        # AVD Auto-Start
        with Horizontal(classes="setting-row"):
            yield Label("AVD Auto-Start:", classes="setting-label")
            yield Switch(
                value=config.emulator.avd_auto_start,
                id="setting-emulator--avd_auto_start",
                classes="setting-switch",
            )

        # Frida Auto-Start
        with Horizontal(classes="setting-row"):
            yield Label("Frida Auto-Start:", classes="setting-label")
            yield Switch(
                value=config.frida.server_auto_start,
                id="setting-frida--server_auto_start",
                classes="setting-switch",
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

        # Flush Package Cache
        with Horizontal(classes="setting-row"):
            yield Label("Package Cache:", classes="setting-label")
            yield Button(
                "Flush Cache",
                id="btn-flush-pkg-cache",
                variant="warning",
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

        # Monitor Processes
        with Horizontal(classes="setting-row"):
            yield Label("Monitor Processes:", classes="setting-label")
            yield Switch(
                value=config.analysis.monitor_processes,
                id="setting-analysis--monitor_processes",
                classes="setting-switch",
            )

        # Monitor Sockets
        with Horizontal(classes="setting-row"):
            yield Label("Monitor Sockets:", classes="setting-label")
            yield Switch(
                value=config.analysis.monitor_sockets,
                id="setting-analysis--monitor_sockets",
                classes="setting-switch",
            )

        # Monitor Network
        with Horizontal(classes="setting-row"):
            yield Label("Monitor Network:", classes="setting-label")
            yield Switch(
                value=config.analysis.monitor_network,
                id="setting-analysis--monitor_network",
                classes="setting-switch",
            )

        # Hash Files
        with Horizontal(classes="setting-row"):
            yield Label("Hash Files:", classes="setting-label")
            yield Switch(
                value=config.analysis.hash_files,
                id="setting-analysis--hash_files",
                classes="setting-switch",
            )

        # Show Deleted Files
        with Horizontal(classes="setting-row"):
            yield Label("Show Deleted Files:", classes="setting-label")
            yield Switch(
                value=config.analysis.show_deleted_files,
                id="setting-analysis--show_deleted_files",
                classes="setting-switch",
            )

        # List APKs
        with Horizontal(classes="setting-row"):
            yield Label("List APKs:", classes="setting-label")
            yield Switch(
                value=config.analysis.list_apks,
                id="setting-analysis--list_apks",
                classes="setting-switch",
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
            yield Switch(
                value=config.tui.show_theme_indicator if config.tui else False,
                id="setting-tui--show_theme_indicator",
                classes="setting-switch",
            )

        # Immediate Exit on Ctrl+C
        with Horizontal(classes="setting-row"):
            yield Label("Immediate Ctrl+C Exit:", classes="setting-label")
            yield Switch(
                value=config.tui.immediate_exit_on_ctrl_c if config.tui else False,
                id="setting-tui--immediate_exit_on_ctrl_c",
                classes="setting-switch",
            )

    def _compose_mvt_tab(self, config: SandroidConfig) -> ComposeResult:
        """Compose the MVT settings tab."""
        mvt = config.mvt

        # MVT Enabled
        with Horizontal(classes="setting-row"):
            yield Label("MVT Enabled:", classes="setting-label")
            yield Switch(
                value=mvt.enabled,
                id="setting-mvt--enabled",
                classes="setting-switch",
            )

        # Scan SMS
        with Horizontal(classes="setting-row"):
            yield Label("Scan SMS:", classes="setting-label")
            yield Switch(
                value=mvt.scan_sms,
                id="setting-mvt--scan_sms",
                classes="setting-switch",
            )

        # Scan Calls
        with Horizontal(classes="setting-row"):
            yield Label("Scan Calls:", classes="setting-label")
            yield Switch(
                value=mvt.scan_calls,
                id="setting-mvt--scan_calls",
                classes="setting-switch",
            )

        # Scan Apps
        with Horizontal(classes="setting-row"):
            yield Label("Scan Apps:", classes="setting-label")
            yield Switch(
                value=mvt.scan_apps,
                id="setting-mvt--scan_apps",
                classes="setting-switch",
            )

        # Scan Files
        with Horizontal(classes="setting-row"):
            yield Label("Scan Files:", classes="setting-label")
            yield Switch(
                value=mvt.scan_files,
                id="setting-mvt--scan_files",
                classes="setting-switch",
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
            yield Switch(
                value=config.ai.show_verbose_thinking,
                id="setting-ai--show_verbose_thinking",
                classes="setting-switch",
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
            yield Switch(
                value=config.ai.show_chat_mascot,
                id="setting-ai--show_chat_mascot",
                classes="setting-switch",
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

    # -------------------------------------------------------------------------
    # Event Handlers
    # -------------------------------------------------------------------------

    def on_mount(self) -> None:
        """Initialize controller after mount."""
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
            key = self._id_to_key(widget_id)
            self._pending[key] = event.value
            if key in self._LIVE_AI_TOGGLE_KEYS:
                self._apply_ai_toggle_live(key, event.value)

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
        # "tui.monitor_event_visibility". SettingsController._apply_setting
        # does a full setattr() REPLACE (not a merge), so re-read ALL 6
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

    def on_input_changed(self, event: Input.Changed) -> None:
        """Track input changes."""
        widget_id = event.input.id
        if not widget_id or not widget_id.startswith("setting-"):
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
        """Track theme radio changes and preview."""
        if event.radio_set.id == "setting-tui--theme":
            # Extract theme name from radio button id (e.g., "theme-cyberpunk" -> "cyberpunk")
            button_id = event.pressed.id
            if button_id and button_id.startswith("theme-"):
                theme_name = button_id[len("theme-") :]
                self._pending["tui.theme"] = theme_name
                # Live preview
                if self._controller:
                    self._controller.preview_theme(theme_name)

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

    def action_save(self) -> None:
        """Save pending settings and dismiss."""
        if not self._pending:
            # Nothing changed
            self.app.call_later(self._refresh_app)
            self.dismiss(None)
            return

        try:
            if self._controller:
                updated_config = self._controller.save(self._pending)
                # Values already applied live (see _apply_ai_toggle_live)
                # are now persisted -- nothing left to revert.
                self._ai_toggle_originals.clear()
                self.app.call_later(self._refresh_app)
                self.dismiss(updated_config)
            else:
                self.app.call_later(self._refresh_app)
                self.dismiss(None)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}", exc_info=True)
            self.notify(f"Save failed: {e}", severity="error")

    def _refresh_app(self) -> None:
        """Refresh the app display after modal closes."""
        try:
            self.app.refresh(layout=True)
        except Exception:
            pass
