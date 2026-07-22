"""Main Sandroid TUI Application.

Textual-based terminal UI for Sandroid providing a mitmproxy-like experience.

Extracted modules:
- ``terminal_reset`` -- terminal cleanup sequences
- ``launcher`` -- ``run_tui`` / ``run_tui_guarded``
- ``activity_log_adapter`` -- safe activity-log wrapper
- ``callback_bundle`` -- ``TUICallbackBundle`` dataclass
- ``css_resolver`` -- CSS file resolution logic
"""

import atexit
import concurrent.futures
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from textual.app import App
from textual.binding import Binding

from sandroid.tui.terminal_reset import reset_terminal

atexit.register(reset_terminal)

from sandroid.core.adb_device_monitor import AdbDeviceMonitor
from sandroid.core.enums import ViewMode
from sandroid.core.menu_controller import MenuController
from sandroid.services import get_spotlight_service, get_task_service, get_ui_service
from sandroid.tui.activity_log_adapter import ActivityLogAdapter
from sandroid.tui.callback_bundle import TUICallbackBundle
from sandroid.tui.controllers import (
    APKInstallController,
    DeviceController,
    ForensicAPKController,
    ForensicController,
    MonitorController,
    NetworkCaptureController,
    ObjectionResumeController,
    ProxyController,
    QuitController,
    RecordingController,
    ScreenshotController,
    SpotlightController,
    TrigDroidController,
    WidgetRefreshController,
)
from sandroid.tui.css_resolver import (
    DEFAULT_CSS_PATH,
    load_css_content,
    resolve_css_path,
)
from sandroid.tui.launcher import run_tui, run_tui_guarded
from sandroid.tui.modal_manager import ModalManager
from sandroid.tui.screens.command_palette import CommandPalette
from sandroid.tui.screens.help_screen import HelpScreen
from sandroid.tui.screens.main_screen import MainScreen
from sandroid.tui.themes import THEMES, get_theme
from sandroid.tui.utils import copy_to_clipboard
from sandroid.tui.widgets import ActivityLog

if TYPE_CHECKING:
    from sandroid.config import SandroidConfig
    from sandroid.core.actionQ import ActionQ

logger = logging.getLogger(__name__)

# Interval (seconds) for the periodic background device-state poll. This is
# now a safety-net BACKSTOP behind the real-time AdbDeviceMonitor fast path
# (host:track-devices); it covers adb-server-restart windows and any stream
# failure, so a slower cadence keeps fallback latency acceptable with minimal
# churn.
DEVICE_POLL_SECONDS = 10.0

# Module-level reference for cross-thread access (ContextVars don't work across threads).
_current_tui_app: Optional["SandroidTUI"] = None


def get_tui_app() -> Optional["SandroidTUI"]:
    """Get the currently running TUI app instance (or None)."""
    return _current_tui_app


class SandroidTUI(App):
    """Textual-based TUI for Android forensic analysis (mitmproxy-like UX)."""

    TITLE = "Sandroid"
    CSS_PATH = None  # loaded dynamically via css_resolver
    ENABLE_COMMAND_PALETTE = False  # we use our own CommandPalette

    # fmt: off
    BINDINGS = [
        # Navigation
        Binding("D", "show_device_selector", "Devices", priority=True),
        Binding("q", "quit", "Quit"),
        Binding("escape", "maybe_quit", "Back/Quit", priority=True),
        Binding("ctrl+c", "request_quit", "Quit", show=False, priority=True),
        Binding("question_mark", "show_help", "Help", priority=True),
        Binding("ctrl+shift+p", "show_palette", "Commands", show=False),
        Binding("ctrl+p", "toggle_ssl_unpin", "SSL Unpin", show=False),
        Binding("ctrl+b", "focus_tools", "Tools", show=True),
        Binding("ctrl+y", "toggle_chat", "AI Chat", show=True),
        # Vim-style scrolling
        Binding("j", "scroll_down", "Down", show=False),
        Binding("ctrl+j", "scroll_down", "Down", show=False),
        Binding("ctrl+k", "scroll_up", "Up", show=False),
        Binding("ctrl+d", "scroll_half_down", "Half Down", show=False),
        Binding("ctrl+u", "scroll_half_up", "Half Up", show=False),
        Binding("home", "scroll_top", "Top", show=False),
        Binding("end", "scroll_bottom", "Bottom", show=False),
        Binding("G", "handle_shift_g", "Forensic APKs", show=False),
        # Recording
        Binding("r", "record", "Record", show=False, id="record"),
        Binding("p", "play", "Play", show=False, id="play"),
        Binding("x", "export_action", "Export", show=False, id="export"),
        Binding("i", "action_key('i')", "Import", show=False, id="import"),
        # Spotlight
        Binding(
            "c", "action_key('c')", "Spotlight Attach", show=False,
            id="spotlight_attach",
        ),
        Binding(
            "C", "action_key('C')", "Spotlight Spawn", show=False,
            id="spotlight_spawn",
        ),
        Binding("d", "action_key('d')", "Dump Memory", show=False, id="dump_memory"),
        # Files
        Binding("l", "spotlight_files", "Spotlight Files", show=False, id="list_files"),
        Binding("o", "monitor", "Monitor", show=False, id="monitor"),
        # Emulator
        Binding(
            "e", "action_key('e')", "Emulator Info", show=False, id="emulator_info"
        ),
        Binding(
            "E", "action_key('E')", "Device Settings", show=False, id="device_settings"
        ),
        Binding("f", "action_key('f')", "Frida", show=False, id="frida"),
        Binding("s", "screenshot", "Screenshot", show=False, id="screenshot"),
        Binding("g", "action_key('g')", "Screen Record", show=False, id="screenrecord"),
        # Analysis
        Binding("m", "action_key('m')", "Dexray", show=False, id="dexray"),
        Binding("t", "trigdroid", "TrigDroid", show=False, id="trigdroid"),
        Binding(
            "k", "action_key('k')", "Reconfigure Hooks", show=False,
            id="reconfigure_hooks",
        ),
        Binding("a", "action_key('a')", "Analyze", show=False, id="static_analysis"),
        Binding("b", "objection", "Objection", show=False, id="objection"),
        Binding(
            "O", "resume_objection", "Resume Objection", show=False,
            id="objection_resume",
        ),
        Binding(
            "F", "forensic_evidence", "Forensic Evidence", show=False,
            id="forensic_evidence",
        ),
        # Network
        Binding("y", "proxy", "Proxy", show=False, id="proxy"),
        Binding("h", "action_key('h')", "FriTap", show=False, id="fritap"),
        Binding(
            "w", "network_capture", "Network Capture", show=False, id="network_capture"
        ),
        # Other
        Binding("n", "install_apk", "Install APK", show=False, id="new_apk"),
        # Snapshots — [0] opens the tab, [1-8] load slots, [Ctrl+1-8] save to slots.
        Binding("0", "open_snapshots", "Snapshots", show=False, id="show_snapshots"),
        Binding("1", "load_slot('1')", "Load slot 1", show=False, id="load_slot_1"),
        Binding("2", "load_slot('2')", "Load slot 2", show=False, id="load_slot_2"),
        Binding("3", "load_slot('3')", "Load slot 3", show=False, id="load_slot_3"),
        Binding("4", "load_slot('4')", "Load slot 4", show=False, id="load_slot_4"),
        Binding("5", "load_slot('5')", "Load slot 5", show=False, id="load_slot_5"),
        Binding("6", "load_slot('6')", "Load slot 6", show=False, id="load_slot_6"),
        Binding("7", "load_slot('7')", "Load slot 7", show=False, id="load_slot_7"),
        Binding("8", "load_slot('8')", "Load slot 8", show=False, id="load_slot_8"),
        Binding(
            "ctrl+1", "save_slot('1')", "Save slot 1", show=False, id="save_slot_1"
        ),
        Binding(
            "ctrl+2", "save_slot('2')", "Save slot 2", show=False, id="save_slot_2"
        ),
        Binding(
            "ctrl+3", "save_slot('3')", "Save slot 3", show=False, id="save_slot_3"
        ),
        Binding(
            "ctrl+4", "save_slot('4')", "Save slot 4", show=False, id="save_slot_4"
        ),
        Binding(
            "ctrl+5", "save_slot('5')", "Save slot 5", show=False, id="save_slot_5"
        ),
        Binding(
            "ctrl+6", "save_slot('6')", "Save slot 6", show=False, id="save_slot_6"
        ),
        Binding(
            "ctrl+7", "save_slot('7')", "Save slot 7", show=False, id="save_slot_7"
        ),
        Binding(
            "ctrl+8", "save_slot('8')", "Save slot 8", show=False, id="save_slot_8"
        ),
        # Clipboard / Settings
        Binding("Y", "copy_log", "Copy Log", show=False),
        Binding("comma", "show_settings", "Settings", show=True),
    ]
    # fmt: on

    def __init__(
        self,
        action_queue: "ActionQ" = None,
        initial_theme: str = "default",
        custom_css_path: Path | str | None = None,
        startup_config: "SandroidConfig | None" = None,
        **kwargs,
    ):
        """Initialize the TUI.

        Args:
            action_queue: ActionQ instance for menu actions.
            initial_theme: Name of the initial theme.
            custom_css_path: Optional path to custom CSS file.
            startup_config: Config to pass to StartupScreen for deferred init.
                If None, initialization is assumed to have already happened.
        """
        logger.debug("start for real")
        # Pre-super init (Textual may access attributes during __init__)
        self.action_queue = action_queue
        self._startup_config = startup_config
        self._controller = None
        self._sandroid_config = self._load_config()
        self._sandroid_css_path = resolve_css_path(
            custom_css_path, self._sandroid_config
        )
        self._css_content: str | None = None
        self._sandroid_theme_name = (
            initial_theme if initial_theme in THEMES else "default"
        )
        self._sandroid_theme = get_theme(self._sandroid_theme_name)
        self._modal_manager: ModalManager | None = None
        self._sub_title = "Android Analysis"

        # Textual only loads a stylesheet file it's told about via its own
        # `css_path` constructor kwarg -- `_sandroid_css_path` was resolved
        # above but never reached here, so styles.tcss/themes/*.tcss were
        # silently never registered in `self.stylesheet` (confirmed via
        # `self.stylesheet.source`): every rule in those files -- borders,
        # `#activity-title`'s color, `ActivityLog`'s `scrollbar-size: 1 1`,
        # etc. -- was a no-op, and every theme rendered identically (only
        # each widget's own hardcoded Python `DEFAULT_CSS` ever applied).
        super().__init__(css_path=self._sandroid_css_path, **kwargs)

        # Post-super init
        self._controller = MenuController.get()
        self._activity_log = ActivityLogAdapter(self)
        self._cb = self._build_callback_bundle()
        self._init_controllers()

    def _build_callback_bundle(self) -> TUICallbackBundle:
        """Create the callback bundle used by controller initialisation."""
        return TUICallbackBundle(
            log_info=self._activity_log.log_info,
            log_warning=self._activity_log.log_warning,
            log_error=self._activity_log.log_error,
            log_success=self._activity_log.log_success,
            log_message=self._activity_log.log_message,
            log_task_started=self._activity_log.log_task_started,
            log_task_stopped=self._activity_log.log_task_stopped,
            push_modal=self.push_screen,
            run_worker=self.run_worker,
            call_from_thread=self.call_from_thread,
            force_ui_refresh=self._force_ui_refresh,
            refresh_status_bar=self._refresh_status_bar,
            get_current_view=self._get_current_view,
            scroll_to_bottom=self._activity_log.scroll_to_bottom,
        )

    def _init_controllers(self) -> None:
        """Initialize all TUI controllers with UI callbacks."""
        cb = self._cb

        self._recording_controller = RecordingController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            run_worker=cb.run_worker,
            call_from_thread=cb.call_from_thread,
            force_ui_refresh=cb.force_ui_refresh,
            on_run_saved=self._notify_diffs_new_run,
            on_monitor_stopped_for_playback=self._notify_monitor_stopped_for_playback,
            on_monitor_resume_available=self._notify_monitor_resume_available,
        )

        self._monitor_controller = MonitorController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            log_task_started=cb.log_task_started,
            log_task_stopped=cb.log_task_stopped,
            push_modal=cb.push_modal,
            call_from_thread=cb.call_from_thread,
            force_ui_refresh=cb.force_ui_refresh,
            get_current_view=cb.get_current_view,
            open_files_tab=self._open_monitor_tab,
            on_pid_mode_fallback=self._notify_pid_mode_fallback,
            on_backend_fallback=self._notify_backend_fallback,
        )

        self._spotlight_controller = SpotlightController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            get_current_view=cb.get_current_view,
        )

        self._trigdroid_controller = TrigDroidController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            force_ui_refresh=cb.force_ui_refresh,
        )

        self._forensic_apk_controller = ForensicAPKController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            force_ui_refresh=cb.force_ui_refresh,
            get_current_view=cb.get_current_view,
            scroll_to_bottom=cb.scroll_to_bottom,
        )

        self._forensic_controller = ForensicController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            push_modal=cb.push_modal,
        )

        self._device_controller = DeviceController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            push_modal=cb.push_modal,
            schedule_timer=self.set_timer,
            refresh_ui=cb.force_ui_refresh,
            call_from_thread=cb.call_from_thread,
        )

        self._widget_refresh_controller = WidgetRefreshController(
            query_widget=self.query_one,
            query_from_screen=lambda w_id, w_type: (
                self.screen.query_one(w_id, w_type)
                if isinstance(self.screen, MainScreen)
                else None
            ),
            is_main_screen=lambda: isinstance(self.screen, MainScreen),
            refresh_app=self.refresh,
            refresh_screen=lambda: (
                self.screen.refresh(layout=True)
                if isinstance(self.screen, MainScreen)
                else None
            ),
        )

        self._quit_controller = QuitController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_task_stopped=cb.log_task_stopped,
            push_modal=cb.push_modal,
            get_running_tasks=get_task_service().get_running,
            get_task=get_task_service().get_task,
            stop_task=get_task_service().stop,
            is_main_screen=lambda: isinstance(self.screen, MainScreen),
            get_screen_stack=lambda: self.screen_stack,
            get_current_screen=lambda: self.screen,
            pop_screen=self.pop_screen,
            exit_app=lambda: super(SandroidTUI, self).exit(),
            force_ui_refresh=cb.force_ui_refresh,
        )

        self._network_capture_controller = NetworkCaptureController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            run_worker=cb.run_worker,
            call_from_thread=cb.call_from_thread,
        )

        self._proxy_controller = ProxyController(
            log_info=cb.log_info,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            refresh_status_bar=cb.refresh_status_bar,
        )

        self._screenshot_controller = ScreenshotController(
            log_info=cb.log_info,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
        )

        self._apk_install_controller = APKInstallController(
            log_info=cb.log_info,
            log_error=cb.log_error,
            log_success=cb.log_success,
            push_modal=cb.push_modal,
            force_ui_refresh=cb.force_ui_refresh,
        )

        self._objection_resume_controller = ObjectionResumeController(
            log_info=cb.log_info,
            log_warning=cb.log_warning,
            log_error=cb.log_error,
            push_modal=cb.push_modal,
        )

    def _load_config(self):
        """Load Sandroid config for TUI settings (returns None on failure)."""
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            return loader.load()
        except Exception as e:
            logger.debug(f"Could not load config: {e}")
            return None

    @property
    def sandroid_config(self):
        """Get the Sandroid config (for logo colors, etc.)."""
        return self._sandroid_config

    @property
    def css(self) -> str:
        """Get the CSS content (lazy-loaded, cached)."""
        if self._css_content is None:
            self._css_content = load_css_content(self._sandroid_css_path)
            if not self._css_content:
                logger.warning("CSS content empty, loading default")
                self._css_content = load_css_content(DEFAULT_CSS_PATH)
        return self._css_content

    @property
    def sandroid_css_path(self) -> Path:
        """Get the path to the currently loaded CSS file."""
        return self._sandroid_css_path

    def on_mount(self) -> None:
        """Called when the app is mounted."""
        global _current_tui_app
        _current_tui_app = self
        logger.debug("[APP MOUNT] Starting Sandroid TUI app mount")
        self._modal_manager = ModalManager(self)
        self._modal_manager.activate()
        self._apply_theme(self._sandroid_theme)

        if self._startup_config is not None:
            # Deferred init: show startup screen, run init in background
            from sandroid.tui.screens.startup_screen import StartupScreen

            self.push_screen(StartupScreen(config=self._startup_config))
        else:
            # Already initialized (e.g. tests or Rich-mode fallback)
            self._push_main_screen()

    def on_startup_screen_init_complete(self, message) -> None:
        """Handle successful initialization from StartupScreen."""
        logger.debug(
            "[APP] Received StartupScreen.InitComplete, switching to MainScreen"
        )
        self.call_later(self._transition_to_main_screen)

    def _transition_to_main_screen(self) -> None:
        """Replace StartupScreen with MainScreen via switch_screen.

        Uses switch_screen (not push_screen) to remove StartupScreen from
        the stack, stopping LoadingIndicator repaints that interfere with
        MainScreen's mount chain.
        """
        logger.debug("[APP] Switching to MainScreen (replacing StartupScreen)")
        try:
            self.switch_screen(MainScreen(action_queue=self.action_queue))
            logger.debug("[APP] MainScreen switched successfully")
        except Exception as e:
            logger.exception(f"[APP] Failed to switch to MainScreen: {e}")
            return
        self._post_main_screen_setup()

    def _push_main_screen(self) -> None:
        """Push MainScreen directly (used when no StartupScreen is shown)."""
        logger.debug("[APP] Pushing MainScreen")
        try:
            self.push_screen(MainScreen(action_queue=self.action_queue))
            logger.debug("[APP] MainScreen pushed successfully")
        except Exception as e:
            logger.exception(f"[APP] Failed to push MainScreen: {e}")
            return
        self._post_main_screen_setup()

    def _post_main_screen_setup(self) -> None:
        """Run common setup after MainScreen is installed."""
        self._register_frida_device_change_callback()
        # Apply user keybinding overrides from the static config (live).
        try:
            cfg = self._sandroid_config
            if cfg is not None and getattr(cfg, "tui", None) is not None:
                self.set_keymap(cfg.tui.keybindings or {})
        except Exception as exc:
            logger.debug(f"Failed to apply keybindings: {exc}")
        # Start the periodic background device-state poll (detects an active
        # device shutting down mid-session). Guard flag prevents stacking
        # workers when a poll is blocked on a dying device's ADB. This is the
        # safety-net BACKSTOP behind the real-time monitor started below.
        self._device_poll_in_flight = False
        # Trailing-debounce flag: set when a poll arrives while one is already
        # in flight, re-triggered once on completion so a boot/reconnect burst
        # leaves the final ready state observed even with a slow backstop.
        self._device_poll_pending = False
        self.set_interval(DEVICE_POLL_SECONDS, self._poll_device_state)
        # Fast path: stream adb's host:track-devices so a connect/disconnect is
        # reflected near-instantly (sub-second) instead of waiting for the poll
        # backstop. It's a pure edge trigger that re-uses _poll_device_state, so
        # the stream and timer paths converge and share every guard. A monitor
        # failure must never break app setup, so guard the whole thing.
        self._adb_device_monitor: AdbDeviceMonitor | None = None
        try:
            self._adb_device_monitor = AdbDeviceMonitor(
                on_change=self._on_adb_devices_changed
            )
            self._adb_device_monitor.start()
        except Exception as exc:
            logger.debug(f"Failed to start adb device monitor: {exc}")
        logger.debug(
            f"[APP MOUNT] Complete. Stack: {[type(s).__name__ for s in self.screen_stack]}"
        )
        self.call_later(self._check_devices_on_startup)
        self.call_later(self._show_welcome_if_first_run)
        # Pre-initialize command registry and package cache in background
        self.run_worker(self._pre_init_commands, exclusive=False)
        self.run_worker(self._pre_fetch_packages, exclusive=False)
        # Connect every enabled config.mcp.servers entry (e.g. the bundled
        # dummy server) and bridge their tools into the shared ToolRegistry,
        # so the Chat tab's tool-calling loop can see them immediately. A
        # broken/unreachable MCP server must never break app startup.
        self.run_worker(self._start_mcp_tools, exclusive=False, thread=True)

    async def _pre_init_commands(self) -> None:
        """Eagerly initialize command registry so first keypress is fast."""
        try:
            from sandroid.core.actionq_commands import get_command_registry

            get_command_registry()
        except Exception as e:
            logger.debug(f"Pre-init commands failed: {e}")

    async def _pre_fetch_packages(self) -> None:
        """Pre-populate package cache so app selection modal opens fast."""
        try:
            from sandroid.services import get_app_selection_service

            get_app_selection_service().get_installed_packages(user_only=True)
        except Exception as e:
            logger.debug(f"Pre-fetch packages failed: {e}")

    def _start_mcp_tools(self) -> None:
        """Start the MCP client manager and bridge its tools into the registry.

        Plain sync function run via ``run_worker(..., thread=True)`` (not
        ``async def`` on Textual's own event loop) -- ``MCPClientManager
        .start()`` is a blocking call with up to ~35s of combined per-server
        connect timeout and no ``await`` inside it, so running it as an
        "async" worker without ``thread=True`` would actually block the UI
        thread for however long that takes, not yield to it.

        Wrapped in try/except: a broken or unreachable MCP server must never
        break app startup -- the Chat tab still works with native tools only
        if this fails, it just won't have any ``mcp:<server>:*`` tools.
        """
        try:
            from sandroid.ai import bridge_mcp_tools, get_mcp_client_manager

            get_mcp_client_manager().start()
            bridge_mcp_tools()
        except Exception as e:
            logger.warning(
                f"MCP client startup failed (Chat MCP tools unavailable): {e}"
            )

    def _show_welcome_if_first_run(self) -> None:
        """Show a welcome modal on the very first TUI launch.

        Uses a marker file in the user config directory to track whether
        the modal has already been displayed.
        """
        marker = self._get_user_config_dir() / ".tui_welcome_shown"
        if marker.exists():
            return

        from sandroid.tui.modals.message_modal import MessageModal

        def _on_dismiss(_result) -> None:
            try:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
            except OSError as e:
                logger.warning(f"Could not create welcome marker file: {e}")

        self.push_screen(
            MessageModal(
                title="Welcome to Sandroid TUI",
                message=(
                    "This is the new default mode for Sandroid.\n"
                    "\n"
                    "For the legacy Rich interactive mode, use:\n"
                    "  sandroid -i\n"
                    "\n"
                    "Press OK to continue."
                ),
            ),
            _on_dismiss,
        )

    @staticmethod
    def _get_user_config_dir() -> Path:
        """Get the user config directory, respecting XDG_CONFIG_HOME."""
        import os

        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return Path(xdg) / "sandroid"
        return Path.home() / ".config" / "sandroid"

    def _register_frida_device_change_callback(self) -> None:
        """Register callback to invalidate Frida device cache on device change."""
        try:
            from sandroid.services import get_device_service, get_frida_session_service

            device_service = get_device_service()
            frida_service = get_frida_session_service()

            def on_device_change(device) -> None:
                """Handle device change - invalidate Frida device cache."""
                frida_service.invalidate_frida_device_cache()
                if device:
                    logger.info(f"Device changed to: {device.serial}")
                    frida_service.update_device_serial(device.serial)
                    # Re-warm the per-serial kprobe availability cache for the
                    # new device (off-thread) and re-sync an open SettingsScreen.
                    self._warm_kprobe_cache_on_device_change()
                else:
                    logger.info("Device changed to: None")

                # This callback now also fires on disconnect (from the device
                # poll worker thread). Marshal UI work to the main thread and
                # guard against teardown races (same convention as status_bar).
                try:
                    self.call_from_thread(self._update_status_bar)
                except Exception:
                    pass

                # Disconnect-only reactions. A normal device *switch* (device is
                # not None) already runs _reset_device_state() in
                # set_active_device(), so only act on the None branch here.
                if device is None:
                    try:
                        if get_task_service().get_running():
                            self._device_controller.stop_all_tasks()
                    except Exception as exc:
                        logger.debug(f"stop_all_tasks on disconnect failed: {exc}")
                    try:
                        self.call_from_thread(
                            self.notify,
                            "Device disconnected — stopped running tasks. "
                            "Press D to reconnect.",
                            severity="warning",
                        )
                    except Exception:
                        pass

            device_service.register_device_change_callback(on_device_change)
            logger.debug("Registered Frida device change callback")

        except Exception as e:
            logger.warning(f"Failed to register Frida device change callback: {e}")

    def _on_adb_devices_changed(self) -> None:
        """Fast-path edge trigger from the adb host:track-devices stream.

        Invoked on the monitor's reader thread on every streamed device-list
        block. Marshals to the app thread and re-uses the existing guarded
        ``_poll_device_state`` so the stream and timer paths converge and share
        every guard (_device_poll_in_flight, is_polling(), MainScreen). Firing
        while a modal is open is skipped (same as the timer) — a known, accepted
        limitation that the backstop / modal-close covers.
        """
        try:
            self.call_from_thread(self._poll_device_state)
        except Exception:
            pass

    def _poll_device_state(self) -> None:
        """Periodically refresh device state off the UI thread.

        Detects an active-device shutdown (emu kill / unplug / crash) within a
        few seconds. The ADB enumeration can block up to 30s on a dying device,
        so it must never run on the Textual event loop — offload to a worker
        thread. The DeviceManager's change callback does the reaction.
        """
        # Avoid piling up workers if a prior poll is still blocked on ADB.
        if getattr(self, "_device_poll_in_flight", False):
            # Remember to run once more after the in-flight poll finishes so a
            # burst (offline→authorizing→device) doesn't leave the final ready
            # state unobserved now the backstop is a slow 10s.
            self._device_poll_pending = True
            return
        try:
            # DeviceController polls refresh_devices() itself during AVD boot;
            # and a modal / device selector owns device interactions.
            if self._device_controller.is_polling():
                return
            if not isinstance(self.screen, MainScreen):
                return
        except Exception:
            return
        self._device_poll_in_flight = True
        try:
            self.run_worker(
                self._refresh_devices_bg, name="device_state_poll", thread=True
            )
        except Exception:
            # If dispatch fails synchronously (e.g. during teardown), reset the
            # guard so the poll isn't wedged "in flight" for the rest of the run.
            self._device_poll_in_flight = False

    def _refresh_devices_bg(self) -> None:
        """Worker body: refresh the device list (may block on ADB)."""
        try:
            from sandroid.core.toolbox import Toolbox

            Toolbox.get_device_manager().refresh_devices()
        except Exception as e:
            logger.debug(f"Device state poll failed: {e}")
        finally:
            self._device_poll_in_flight = False
            # Trailing debounce: if a poll arrived while this one was running,
            # run once more so the latest state is read (coalesces a burst into
            # "run now + once more after"). Re-arming is bounded — the trailing
            # poll re-checks _device_poll_in_flight, it is not an unbounded loop.
            if getattr(self, "_device_poll_pending", False):
                self._device_poll_pending = False
                try:
                    self.call_from_thread(self._poll_device_state)
                except Exception:
                    pass

    def _check_devices_on_startup(self) -> None:
        """Check for connected devices on startup - delegates to DeviceController."""
        import threading

        def _background_check():
            self._device_controller.check_devices_on_startup()
            self._run_deferred_setup_checks()
            self._warm_kprobe_cache_on_startup()

        thread = threading.Thread(target=_background_check, daemon=True)
        thread.start()

    def _warm_kprobe_cache_on_startup(self) -> None:
        """Warm the per-serial kprobe availability cache at startup.

        Runs inside the already-off-thread startup check, so the heavy adb
        probe never touches the UI thread. Skips the probe when no device is
        active: an inconclusive probe would not memoize, and the device-change
        path warms the cache once a device appears.
        """
        try:
            from sandroid.core.adb import Adb

            if not Adb.get_target_device():
                return
            from sandroid.core.kprobe_tracer import KprobeTracer

            KprobeTracer.kprobe_supported()
        except Exception as exc:
            logger.debug(f"Startup kprobe availability probe failed: {exc}")

    def _warm_kprobe_cache_on_device_change(self) -> None:
        """Warm the kprobe availability cache for the newly active device.

        Spawns a short daemon thread so the heavy adb probe never stalls the
        device-change callback chain. ``Adb.set_target_device`` has already run
        before callbacks fire, so ``kprobe_supported`` reads the new serial.
        Afterwards, if a ``SettingsScreen`` is open, its Source disabled-state
        is re-synced on the UI thread.
        """
        import threading

        def _probe() -> None:
            try:
                from sandroid.core.kprobe_tracer import KprobeTracer

                KprobeTracer.kprobe_supported()
            except Exception as exc:
                logger.debug(f"Device-change kprobe probe failed: {exc}")
            self._refresh_open_settings_backend()

        threading.Thread(target=_probe, daemon=True).start()

    def _refresh_open_settings_backend(self) -> None:
        """Re-sync an open SettingsScreen's backend availability (UI thread).

        The stack scan and the refresh call both run on the UI thread via
        ``call_from_thread``. No-op (guarded) when no SettingsScreen is open or
        the method is absent.
        """

        def _do_refresh() -> None:
            from sandroid.tui.screens.settings_screen import SettingsScreen

            for screen in self.screen_stack:
                if isinstance(screen, SettingsScreen):
                    refresh = getattr(screen, "refresh_backend_availability", None)
                    if callable(refresh):
                        refresh()
                    break

        try:
            self.call_from_thread(_do_refresh)
        except Exception as exc:
            logger.debug(f"Settings backend availability refresh failed: {exc}")

    def _run_deferred_setup_checks(self) -> None:
        """Run deferred (non-critical) setup checks in background."""
        try:
            from sandroid.services import get_setup_service

            logger.debug("Running deferred setup checks in background")
            get_setup_service().check_deferred_setup(publish_event=True)
            logger.debug("Deferred setup checks completed")
        except Exception as e:
            logger.warning(f"Deferred setup checks failed: {e}")

    def on_key(self, event) -> None:
        """Debug handler to log key presses (only when DEBUG level is enabled)."""
        if not logger.isEnabledFor(logging.DEBUG):
            return
        screen_name = type(self.screen).__name__
        stack_names = [type(s).__name__ for s in self.screen_stack]
        logger.debug(
            f"[KEY EVENT] key={event.key!r}, screen={screen_name}, stack={stack_names}"
        )
        if event.key == "escape":
            logger.warning(
                f"[ESCAPE PRESSED] screen={screen_name}, stack_len={len(self.screen_stack)}"
            )

    def _get_current_view(self) -> str:
        """Get the current view from UIService."""
        try:
            return get_ui_service().get_current_view()
        except Exception:
            return ViewMode.FORENSIC.value

    def action_request_quit(self) -> None:
        """Show quit confirmation or stop running tasks."""
        self._quit_controller.request_quit()

    def action_maybe_quit(self) -> None:
        """Handle ESC -- dismiss modal or show quit confirmation."""
        self._quit_controller.maybe_quit()

    def exit(self, result=None, return_code: int = 0) -> None:
        """Exit with cleanup of sessions and workers."""
        global _current_tui_app
        _current_tui_app = None
        self._quit_controller.force_exit()
        # Stop the real-time device monitor before cancelling workers. Guard
        # getattr (the monitor may never have been created if the app exits
        # during StartupScreen) and the call (stop() is idempotent).
        monitor = getattr(self, "_adb_device_monitor", None)
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass
        try:
            if hasattr(self, "workers") and self.workers:
                self.workers.cancel_all()
        except Exception:
            pass
        super().exit(result, return_code)

    def on_unmount(self) -> None:
        """Stop the real-time device monitor on teardown.

        Belt-and-suspenders for teardown paths that bypass the overridden
        exit(). Runs on the app thread, so stop() (which only sets an Event,
        shuts down/closes the socket, and joins the reader thread) is safe to
        call directly. No super() call is needed — Textual dispatches both
        Widget._on_unmount and this public on_unmount, so worker cleanup is
        unaffected (matches every other on_unmount in this repo).
        """
        monitor = getattr(self, "_adb_device_monitor", None)
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass

        # Tear down every connected MCP server cleanly. Wrapped in try/except
        # so a hung shutdown (e.g. an unresponsive server subprocess) never
        # blocks app exit -- MCPClientManager.stop() itself already bounds
        # every wait with its own timeouts.
        try:
            from sandroid.ai import get_mcp_client_manager

            get_mcp_client_manager().stop()
        except Exception:
            pass

    def _get_main_screen(self) -> MainScreen | None:
        return self.screen if isinstance(self.screen, MainScreen) else None

    def action_show_help(self) -> None:
        """Toggle the help & keybindings overlay.

        ``?`` is an app-level priority binding, so it fires before the editor's
        own ``?``-to-close binding. Toggle here so pressing ``?`` inside Help
        closes it instead of stacking a second copy.
        """
        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return
        self.push_screen(HelpScreen())

    def _snapshots_panel(self):
        """The SnapshotsPanel on the main screen, or None if unavailable."""
        screen = self._get_main_screen()
        if screen is None:
            return None
        try:
            from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

            return screen.query_one("#snapshots-panel", SnapshotsPanel)
        except Exception:
            return None

    def action_load_slot(self, slot: str) -> None:
        """Load the snapshot assigned to ``slot`` (keys 1-8)."""
        panel = self._snapshots_panel()
        if panel is not None:
            panel.load_slot(slot)

    def action_save_slot(self, slot: str) -> None:
        """Save the current state into ``slot`` (keys Ctrl+1-8)."""
        panel = self._snapshots_panel()
        if panel is not None:
            panel.save_slot(slot)

    def action_open_snapshots(self) -> None:
        """Open the Snapshots tab in the bottom strip (key 0)."""
        screen = self._get_main_screen()
        if screen is not None:
            screen.open_snapshots_tab()

    def action_toggle_chat(self) -> None:
        """Toggle the AI Chat dock at the bottom of the right panel (Ctrl+Y)."""
        screen = self._get_main_screen()
        if screen is not None:
            screen.toggle_chat_panel()

    def action_show_settings(self) -> None:
        """Show the settings screen."""
        from sandroid.tui.screens.settings_screen import SettingsScreen

        def on_settings_result(result) -> None:
            if result is not None:
                self._sandroid_config = result
                if hasattr(result, "tui") and result.tui:
                    self._sandroid_theme_name = result.tui.theme
                    self._sandroid_theme = get_theme(result.tui.theme)
                self._activity_log.log_success("Settings saved")

        self.push_screen(SettingsScreen(), on_settings_result)

    def action_show_palette(self) -> None:
        """Show the command palette."""
        current_view = self._get_current_view()

        def on_action_selected(action_name: str):
            main_screen = self._get_main_screen()
            if main_screen:
                main_screen.execute_action(action_name)

        self.push_screen(
            CommandPalette(current_view=current_view, on_action=on_action_selected)
        )

    #: Bounded watchdog for the off-thread SSL toggle (> the BypassService's
    #: 15s readiness wait + session-setup overhead), so a wedged Frida call can
    #: never leave the toggle silent.
    _SSL_UNPIN_TIMEOUT = 30.0

    def action_toggle_ssl_unpin(self) -> None:
        """Toggle SSL pinning bypass for the spotlight app.

        Works from anywhere in the TUI — delegates to MitmproxyService which
        owns the SSLUnpinManager instance. The toggle can block on Frida script
        readiness, so it runs on a worker thread (under a bounded watchdog) and
        results are marshalled back to the UI thread. Does not require mitmweb;
        SSL unpin is purely a Frida operation.
        """
        from sandroid.services import get_spotlight_service
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        svc = get_mitmproxy_service()

        if not svc.ssl_unpin_is_active():
            try:
                spotlight = get_spotlight_service()
                if not spotlight.get_app_tuple():
                    self.notify(
                        "No spotlight app. Press C (attach) or Shift+C "
                        "(spawn) first.",
                        severity="warning",
                    )
                    return
            except Exception as exc:
                logger.warning("SSL unpin spotlight check failed: %s", exc)
                self.notify(f"SSL unpin: {exc}", severity="error")
                return

        # Snapshot intent on the UI thread; the worker only does the toggle.
        was_active = svc.ssl_unpin_is_active()

        def _job() -> None:
            ok, msg = False, ""
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(svc.toggle_ssl_unpin)
                try:
                    ok, msg = future.result(timeout=self._SSL_UNPIN_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    ok, msg = False, "SSL unpin timed out — see logs"
                    logger.error(
                        "SSL unpin toggle exceeded %.0fs watchdog; abandoning",
                        self._SSL_UNPIN_TIMEOUT,
                    )
            except Exception as exc:
                ok, msg = False, str(exc)
                logger.warning("SSL unpin toggle failed: %s", exc)
            finally:
                executor.shutdown(wait=False)

            # Preserve the three-way branch: a successful turn-OFF returns
            # now_active=False and must NOT render as an error.
            def _report() -> None:
                if was_active:
                    self.notify("SSL pinning bypass stopped", severity="information")
                elif ok:
                    self.notify(msg, severity="information")
                else:
                    self.notify(f"SSL unpin failed: {msg}", severity="error")

            try:
                self.call_from_thread(_report)
            except Exception:
                pass

        def _dispatch() -> None:
            self.run_worker(_job, name="ssl_unpin_toggle", thread=True)

        # Turning ON against a live (non-paused) spotlight process attaches
        # Frida — gate on frida-server being up so the cryptic frida-core
        # "need Gadget to attach on jailed Android" error never surfaces; show
        # the install modal instead. Turning OFF (detach) and a not-running or
        # paused app never attach, so dispatch directly.
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            app_running = get_bypass_service()._spotlight_running()
        except Exception:
            app_running = False

        if not was_active and app_running:
            from sandroid.tui.modals import ensure_frida_running

            ensure_frida_running(
                self,
                "SSL unpin",
                on_ready=_dispatch,
                on_cancel=lambda: self.notify(
                    "SSL unpin requires frida-server — cancelled.",
                    severity="warning",
                ),
            )
        else:
            _dispatch()

    def action_focus_tools(self) -> None:
        """Focus the active tool panel (Ctrl+B).

        The tool strip is always visible now; this just moves focus into it so
        Shift+Arrow level/tab-cycling and per-panel keys work. All tool logic
        lives on MainScreen (which owns the widgets); the app just forwards
        the key.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            from textual.widgets import ContentSwitcher

            current = ms.query_one("#tool-body", ContentSwitcher).current
            if current:
                ms.query_one(f"#{current}").focus()
        except Exception:
            pass

    def action_show_device_selector(self) -> None:
        """Show the device selection modal."""
        from sandroid.core.toolbox import Toolbox
        from sandroid.tui.modals import DeviceSelectionModal

        dm = Toolbox.get_device_manager()
        devices = dm.refresh_devices()
        current_serial = dm.active_device.serial if dm.active_device else None
        worker_kw = {
            "run_worker": self.run_worker,
            "call_from_thread": self.call_from_thread,
            "notify": self.notify,
        }

        def _parse_encoded_serial(serial: str):
            """Parse ``__start_avd__`` / ``__restart_emulator__`` encoded serial."""
            parts = serial.split("__")
            if len(parts) >= 4:
                snapshot = parts[4] if len(parts) > 4 and parts[4] else None
                return parts[2], parts[3], snapshot
            return None, None, None

        def on_device_selected(serial: str | None) -> None:
            if serial is None:
                return
            if serial.startswith("__start_avd__"):
                name, mode, snap = _parse_encoded_serial(serial)
                if name:
                    self._device_controller.start_avd_with_boot_mode(
                        name, mode, snap, **worker_kw
                    )
                return
            if serial.startswith("__restart_emulator__"):
                emu, mode, snap = _parse_encoded_serial(serial)
                if emu:
                    self._device_controller.restart_emulator_with_boot_mode(
                        emu, mode, snap, **worker_kw
                    )
                return
            if serial != current_serial:
                if self._has_active_session():
                    self._device_controller.show_device_switch_confirmation(
                        serial, current_serial, on_confirm=self._perform_device_switch
                    )
                else:
                    self._perform_device_switch(serial)
            else:
                self._update_status_bar()

        self.push_screen(
            DeviceSelectionModal(devices=devices, current_serial=current_serial),
            on_device_selected,
        )

    def _has_active_session(self) -> bool:
        """True if background tasks or spotlight app are active."""
        if get_task_service().get_running():
            return True
        spotlight = get_spotlight_service()
        return bool(spotlight.get_app_tuple() or spotlight.get_spawn_package())

    def _perform_device_switch(self, target_serial: str, cleanup: bool = False) -> None:
        """Switch device and refresh UI."""
        self._device_controller.switch_device(target_serial, cleanup=cleanup)
        self.call_later(self._force_ui_refresh)

    def _force_ui_refresh(self) -> None:
        self._widget_refresh_controller.refresh_all()

    def _update_status_bar(self) -> None:
        self._widget_refresh_controller.refresh_status_bar()

    def refresh_menu(self) -> None:
        """Refresh the menu panel to reflect current state."""
        self._widget_refresh_controller.refresh_menu()

    def action_forensic_evidence(self) -> None:
        """Run MVT forensic evidence scan."""
        self._forensic_controller.show_forensic_evidence_modal(
            get_current_view=self._get_current_view,
            run_worker=self.run_worker,
            call_from_thread=self.call_from_thread,
            force_ui_refresh=self._force_ui_refresh,
            on_mvt_result=self._handle_mvt_result,
        )

    def _handle_mvt_result(self, result) -> None:
        self._forensic_apk_controller.handle_mvt_result(result)

    def action_handle_shift_g(self) -> None:
        self._forensic_apk_controller.handle_shift_g()

    def action_manage_forensic_apks(self) -> None:
        self._forensic_apk_controller.show_forensic_apk_modal()

    def action_monitor(self) -> None:
        self._monitor_controller.show_config_modal()

    def _open_monitor_tab(self) -> None:
        """MonitorController's ``open_files_tab`` hook: land on Files > Monitor.

        Fires once monitor has actually *started* (called from inside
        ``MonitorController._start_monitor`` after it registers with
        TaskService), not merely when the config modal opens — mirrors
        ``action_action_key``'s ``h`` -> ``open_fritap_tab()`` jump for
        friTap. Injected as a callback (constructed in ``_init_controllers``)
        rather than the controller importing ``MainScreen`` directly.
        """
        ms = self._get_main_screen()
        if ms is not None:
            ms.open_files_tab(sub_tab="files-monitor")

    def action_spotlight_files(self) -> None:
        """``l`` — land on Files > Watchlist (mirrors ``o``'s Monitor jump).

        Rewired from the now-retired ``SpotlightFilesModal`` popup to the
        in-tab Watchlist sub-view, which owns add/remove/pull/diff.
        """
        ms = self._get_main_screen()
        if ms is not None:
            ms.open_files_tab(sub_tab="files-watchlist")

    def _apply_theme(self, theme, css_path: Path | str | None = None) -> None:
        """Apply a theme to the app.

        Args:
            theme: Theme to apply -- controls Textual's own binary
                dark/light flag (``self.dark``/``self.theme``), which is a
                much narrower thing than swapping which ``.tcss`` FILE is
                loaded (our themes only differ by literal hex values inside
                ``styles.tcss``/``themes/*.tcss``, not by Textual's design
                tokens).
            css_path: If given, also swap the live stylesheet to this
                theme's ``.tcss`` file via :meth:`_reload_theme_css` -- used
                by the Settings preview/revert path, where the user has
                just explicitly picked a named theme. Deliberately omitted
                from the ``on_mount`` startup call: at startup the correct
                file was already loaded via the ``css_path`` constructor
                kwarg, which (unlike this method) also honours
                ``tui.custom_css_path`` -- an override the named-theme
                mapping knows nothing about -- so recomputing it here would
                wrongly clobber that override.
        """
        self.dark = theme.is_dark
        try:
            if hasattr(self, "theme"):
                self.theme = "textual-dark" if theme.is_dark else "textual-light"
        except Exception:
            pass

        if css_path is not None:
            self._reload_theme_css(css_path)

        logger.debug(f"Applied theme: {theme.display_name}")

    def _reload_theme_css(self, css_path: Path | str) -> None:
        """Swap a theme's ``.tcss`` file into the live running stylesheet.

        Textual only ever loads a ``.tcss`` file it's told about via the
        ``css_path`` constructor kwarg, once, at startup (see
        ``App.__init__``/``App._process_messages``'s ``app_prelude``). There
        is no built-in "switch to a different CSS file at runtime" API --
        the closest existing precedent is Textual's own CSS hot-reload
        (``App._on_css_change``, the mechanism behind ``watch_css=True``),
        which re-reads the *same* file(s) after an on-disk edit. This mirrors
        that exact approach but swaps in a *different* file:

        1. Copy the current stylesheet (``Stylesheet.copy()``) so every
           already-registered per-widget ``DEFAULT_CSS`` source survives --
           those are added lazily, once, via ``Widget._post_register`` when
           a widget instance first mounts, so rebuilding from scratch would
           silently lose them for anything already on screen.
        2. Drop whichever raw ``.tcss`` FILE source is currently loaded.
           ``Stylesheet.source`` is keyed by ``(path, class_var)``; a source
           added via ``read``/``read_all`` (i.e. an actual file) always has
           an empty ``class_var`` half, while default CSS added via
           ``add_source`` (widget ``DEFAULT_CSS``, ``App.CSS``) never does
           -- so that's an unambiguous way to find "the old theme file" to
           remove, without needing to know its exact former path.
        3. Read and parse the new file, then swap the rebuilt stylesheet in
           and re-apply it to the app and every currently pushed screen --
           exactly what ``_on_css_change`` does after re-parsing.
        """
        css_path = Path(css_path)
        try:
            stylesheet = self.stylesheet.copy()
            for key in list(stylesheet.source):
                _, class_var = key
                if class_var == "":
                    del stylesheet.source[key]
            stylesheet.read_all([css_path])
            stylesheet.parse()
        except Exception:
            logger.exception(f"Failed to reload theme CSS from {css_path}")
            return

        self.stylesheet = stylesheet
        self.css_path = [css_path]
        self._sandroid_css_path = css_path
        self._css_content = None  # invalidate the lazily-cached `.css` text

        self.stylesheet.update(self)
        for screen in self.screen_stack:
            self.stylesheet.update(screen)

    @property
    def sandroid_theme_name(self) -> str:
        return self._sandroid_theme_name

    @property
    def sandroid_theme(self):
        return self._sandroid_theme

    @property
    def sub_title(self) -> str:
        return self._sub_title

    @sub_title.setter
    def sub_title(self, value: str) -> None:
        self._sub_title = value

    def update_subtitle_for_view(self, view: str) -> None:
        """Set the fixed app subtitle.

        TODO(modes-as-presets): View modes were removed, so the subtitle is now
        fixed. The ``view`` argument is retained for caller compatibility and
        will drive presets again in a later feature.
        """
        self._sub_title = "Android Analysis"

    # -- Vim-style scrolling --------------------------------------------------

    def _scroll_log(self, method_name: str, *args, **kwargs) -> None:
        try:
            getattr(self.query_one("#activity-log", ActivityLog), method_name)(
                *args, **kwargs
            )
        except Exception:
            pass

    def action_scroll_down(self) -> None:
        self._scroll_log("scroll_down_line")

    def action_scroll_up(self) -> None:
        self._scroll_log("scroll_up_line")

    def action_scroll_half_down(self) -> None:
        self._scroll_log("scroll_relative", y=10)

    def action_scroll_half_up(self) -> None:
        self._scroll_log("scroll_relative", y=-10)

    def action_scroll_top(self) -> None:
        self._scroll_log("scroll_to_top")

    def action_scroll_bottom(self) -> None:
        self._scroll_log("scroll_to_bottom")

    def _copy_to_clipboard(self, text: str) -> bool:
        return copy_to_clipboard(text, textual_copy_fn=self.copy_to_clipboard)

    def action_copy_log(self) -> None:
        """Copy activity log content to clipboard (Y key - vim yank)."""
        try:
            activity_log = None
            for screen in self.screen_stack:
                try:
                    activity_log = screen.query_one("#activity-log", ActivityLog)
                    break
                except Exception:
                    continue

            if activity_log is None:
                self.notify("Activity log not found", severity="warning")
                return

            text = activity_log.get_plain_text()

            if not text.strip():
                self.notify("Activity log is empty", severity="warning")
                return

            line_count = activity_log.get_line_count()

            if self._copy_to_clipboard(text):
                self.notify(
                    f"Copied {line_count} lines to clipboard",
                    severity="information",
                )
            else:
                self.notify(
                    "Copy failed - no clipboard tool available",
                    severity="error",
                )
        except Exception as e:
            logger.error(f"Copy log failed: {e}", exc_info=True)
            self.notify(f"Copy failed: {type(e).__name__}", severity="error")

    def action_install_apk(self) -> None:
        self._apk_install_controller.show_install_modal()

    def action_screenshot(self) -> None:
        self._screenshot_controller.show_screenshot_modal()

    def action_objection(self) -> None:
        """Launch objection terminal for spotlight app."""
        spotlight = get_spotlight_service()
        if not spotlight.has_app():
            self._activity_log.log_warning(
                "No spotlight app selected. Press 'c' to choose an app first."
            )
            return

        package_name = spotlight.get_app_tuple()[0]
        from sandroid.tui.modals.objection_modal import (
            ObjectionModal,
            build_objection_command,
        )
        from sandroid.tui.screens.objection_terminal_screen import (
            ObjectionTerminalScreen,
        )

        def on_config(config):
            if config is None:
                return
            bypass_script = (
                self._find_bypass_script() if config.use_bypass_script else None
            )
            cmd = build_objection_command(package_name, config, bypass_script)
            self.push_screen(
                ObjectionTerminalScreen(
                    cmd=cmd, package_name=package_name, spawn_mode=config.spawn_mode
                )
            )

        self.push_screen(ObjectionModal(package_name=package_name), on_config)

    @staticmethod
    def _find_bypass_script() -> str | None:
        """Locate the TrigDroid bypass RPC script."""
        try:
            import importlib.resources as pkg_resources

            ref = (
                pkg_resources.files("trigdroid") / "scripts" / "trigdroid_bypass_rpc.js"
            )
            path = str(ref)
            if Path(path).exists():
                return path
        except Exception:
            pass
        local = Path(__file__).parent.parent / "analysis" / "trigdroid_bypass_rpc.js"
        return str(local) if local.exists() else None

    def action_resume_objection(self) -> None:
        self._objection_resume_controller.resume_session()

    def action_record(self) -> None:
        self._recording_controller.start_recording()

    def action_play(self) -> None:
        # Tab-switch on Play-*press* always happens, regardless of what run
        # history looks like (the other, gated half of the unified focus
        # rule — whether the completed run also steals the rail's current
        # *selection* — lives in DiffsView.on_new_run via _notify_diffs_new_run).
        ms = self._get_main_screen()
        if ms is not None:
            ms.open_files_tab(sub_tab="files-diffs")
        self._recording_controller.start_playback()

    def _notify_diffs_new_run(self, run_id: str) -> None:
        """Tell DiffsView a new run was saved (RecordingController's on_run_saved).

        Always safe to call even if the Files tab isn't showing right now —
        DiffsView keeps its own selection/unread state; the gated
        auto-select-vs-unread-marker logic lives entirely in
        DiffsView.on_new_run, not here.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            view = ms.query_one("#files-diffs")
        except Exception:
            return
        if hasattr(view, "on_new_run"):
            try:
                view.on_new_run(run_id)
            except Exception:
                logger.warning("DiffsView.on_new_run failed", exc_info=True)

    def _notify_monitor_stopped_for_playback(self) -> None:
        """RecordingController's ``on_monitor_stopped_for_playback``.

        Fires the moment Play's snapshot-revert safety-net force-stops a
        running monitor session (see
        ``RecordingController._stop_monitor_before_revert``). Same
        query_one + hasattr-guard dispatch pattern as
        ``_notify_diffs_new_run`` — the controller only knows about a plain
        callback, app.py owns reaching into the concrete widget.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            view = ms.query_one("#files-monitor")
        except Exception:
            return
        if hasattr(view, "notify_monitor_stopped_for_playback"):
            try:
                view.notify_monitor_stopped_for_playback()
            except Exception:
                logger.warning(
                    "MonitorView.notify_monitor_stopped_for_playback failed",
                    exc_info=True,
                )

    def _notify_pid_mode_fallback(self, path: str) -> None:
        """MonitorController's ``on_pid_mode_fallback``.

        Fires the moment ``MonitorController._start_monitor``'s PID-mode branch
        silently substitutes path-mode because ``FSMon.fanotify_supported()``
        reports the device's kernel lacks fanotify. Same query_one +
        hasattr-guard dispatch pattern as ``_notify_monitor_stopped_for_playback``
        — the controller only knows about a plain callback, app.py owns
        reaching into the concrete widget.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            view = ms.query_one("#files-monitor")
        except Exception:
            return
        if hasattr(view, "notify_pid_mode_fallback"):
            try:
                view.notify_pid_mode_fallback(path)
            except Exception:
                logger.warning(
                    "MonitorView.notify_pid_mode_fallback failed", exc_info=True
                )

    def _notify_backend_fallback(self, reason: str) -> None:
        """MonitorController's ``on_backend_fallback``.

        Fires when the requested/auto-selected kprobe backend is unavailable
        and the monitor falls back to fsmon. Marshaled back onto the main
        thread by ``MonitorController._start_monitor`` before this is called,
        so it dispatches straight into the concrete widget (same query_one +
        hasattr-guard pattern as ``_notify_pid_mode_fallback``). Distinct from
        that path-only, fanotify-worded notice.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            view = ms.query_one("#files-monitor")
        except Exception:
            return
        if hasattr(view, "notify_backend_fallback"):
            try:
                view.notify_backend_fallback(reason)
            except Exception:
                logger.warning(
                    "MonitorView.notify_backend_fallback failed", exc_info=True
                )

    def _notify_monitor_resume_available(self, config) -> None:
        """RecordingController's ``on_monitor_resume_available``.

        Fires once Play has fully finished, only if monitor was auto-stopped
        for it — surfaces MonitorView's one-click "Resume monitoring" offer.
        """
        ms = self._get_main_screen()
        if ms is None:
            return
        try:
            view = ms.query_one("#files-monitor")
        except Exception:
            return
        if hasattr(view, "offer_resume"):
            try:
                view.offer_resume(config)
            except Exception:
                logger.warning("MonitorView.offer_resume failed", exc_info=True)

    def resume_monitor_after_playback(self, config) -> None:
        """MonitorView's "Resume monitoring" button handler.

        Delegates entirely to ``MonitorController.resume_after_playback``,
        which owns the PID re-resolution (target app likely relaunched with
        a new PID during replay) and the path-mode/refuse-to-start
        fallbacks. On success, monitor's own TASK_STARTED event clears the
        Resume offer (MonitorView._on_monitor_started) — no extra plumbing
        needed here.
        """
        self._monitor_controller.resume_after_playback(config)

    def action_export_action(self) -> None:
        self._recording_controller.show_export_modal()

    def action_proxy(self) -> None:
        self._proxy_controller.show_proxy_modal()

    def action_network_capture(self) -> None:
        self._network_capture_controller.toggle_or_show_modal()

    def action_trigdroid(self) -> None:
        self._trigdroid_controller.toggle_trigdroid()

    def _refresh_status_bar(self) -> None:
        try:
            ms = self._get_main_screen()
            if ms:
                bar = ms.query_one("#status-bar")
                if hasattr(bar, "refresh_status"):
                    bar.refresh_status()
        except Exception:
            pass

    def action_action_key(self, key: str) -> None:
        ms = self._get_main_screen()
        if ms:
            ms.execute_action_by_key(key)
            # friTap (h) gets a first-class tab — jump to it so the toggle has
            # a visible home (mirrors 0 → open_snapshots_tab).
            if key == "h":
                ms.open_fritap_tab()
        # Spotlight selection (C attach / Shift+C spawn) does NOT force the
        # panel open — it stays minimized by default. The panel live-updates
        # via the EventBus whether shown or hidden; press Ctrl+B to view it.

    def on_command_palette_action_selected(
        self,
        message: CommandPalette.ActionSelected,
    ) -> None:
        """Handle action selected from command palette."""
        dispatch = {
            "device_selector": self.action_show_device_selector,
            "help": self.action_show_help,
            "quit": self.action_quit,
        }
        handler = dispatch.get(message.action_name)
        if handler:
            handler()
            return
        ms = self._get_main_screen()
        if ms:
            ms.execute_action(message.action_name)
