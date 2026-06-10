"""Status bar widget showing application state."""

import os
import threading

from rich.box import ROUNDED
from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from sandroid.core.adb import Adb
from sandroid.core.enums import ViewMode
from sandroid.services import (
    get_frida_session_service,
    get_network_capture_service,
    get_spotlight_service,
    get_task_service,
    get_ui_service,
)
from sandroid.tui.themes import FIXED_COLORS


class StatusBar(Static):
    """Status bar showing current application state.

    Displays:
    - Current view mode (FORENSIC/MALWARE/SECURITY)
    - Active device (emulator/physical)
    - Frida server status
    - Spotlight application name
    - Background tasks (when running)

    Status indicators (running/stopped, spawn/attach) use fixed colors
    that don't change with theme for instant recognition.
    View colors and text colors are pulled from the current theme.

    All status properties are regular instance attributes (not Textual reactives).
    Using 19 reactive() descriptors caused Textual's mount chain to stall,
    preventing MainScreen.on_mount() from firing. Regular attributes work
    identically here because there are no watch_* methods and all callers
    explicitly call self.refresh() after setting values.
    """

    def __init__(self, **kwargs):
        # Initialize all status properties as regular attributes BEFORE super().__init__
        # (avoids Textual reactive descriptor overhead that blocks mount chain)
        self.frida_status = "Not running"
        self.spotlight_app = "None"
        self.spawn_mode = False
        self.current_view = "FORENSIC"
        self.current_theme = ""
        self.show_theme_indicator = False
        self.active_device = ""
        self.device_type = ""
        self.device_count = 0
        # Cached device metadata (populated at discovery — no ADB on refresh):
        self.device_android_version = ""
        self.device_api_level = 0
        self.device_rooted: bool | None = None  # None = unknown
        self.background_tasks_count = 0
        self.background_tasks_display = ""
        self.forensic_apks_count = 0
        self.proxy_address = ""
        self.network_capture_running = False
        self.network_capture_file = ""
        # Glance-band datums (cheap, in-process reads — no ADB):
        self.spotlight_pid: int | None = None
        self.spotlight_paused = False
        self.hook_count = 0  # running hook tasks for the spotlight app
        self.bypass_categories: list[str] = []  # 0-4 of ssl/root/frida/debug
        self.tools_checking = True
        self.sqldiff_available = False
        self.objection_available = False
        self.frida_available_check = False
        self._frida_version_mismatch: bool | None = None  # None = not checked yet
        self._frida_last_status: str = ""  # Track status transitions
        super().__init__(**kwargs)

    def on_mount(self) -> None:
        """Initialize theme name and visibility from app/config on mount."""
        try:
            if hasattr(self.app, "sandroid_theme"):
                self.current_theme = self.app.sandroid_theme.display_name
            # Check config for show_theme_indicator setting
            if hasattr(self.app, "sandroid_config") and self.app.sandroid_config:
                self.show_theme_indicator = (
                    self.app.sandroid_config.tui.show_theme_indicator
                )
        except Exception:
            self.current_theme = "Default"
            self.show_theme_indicator = False

        # Defer EventBus subscription to avoid deadlocks during mount chain
        # (same pattern as MainScreen lines 81-84)
        self.call_later(self._subscribe_to_tool_events)

    def _subscribe_to_tool_events(self) -> None:
        """Subscribe to TOOL_AVAILABILITY_UPDATED event from SetupService."""
        try:
            from sandroid.core.events import EventBus, EventType

            EventBus.get().subscribe(
                EventType.TOOL_AVAILABILITY_UPDATED,
                self._on_tool_availability_updated,
            )
        except ImportError:
            pass  # Events module not available

    def _on_tool_availability_updated(self, event) -> None:
        """Handle tool availability update from deferred setup checks.

        Args:
            event: Event with tool availability data
        """
        try:
            data = event.data
            # Update reactive properties from background thread safely
            self.app.call_from_thread(
                self._apply_tool_availability,
                data.get("sqldiff_available", False),
                data.get("objection_available", False),
                data.get("frida_available", False),
            )
        except Exception:
            pass  # Ignore errors during app shutdown

    def _apply_tool_availability(
        self, sqldiff: bool, objection: bool, frida: bool
    ) -> None:
        """Apply tool availability updates to reactive properties.

        Args:
            sqldiff: Whether sqldiff is available
            objection: Whether objection is available
            frida: Whether frida module is available
        """
        self.tools_checking = False
        self.sqldiff_available = sqldiff
        self.objection_available = objection
        self.frida_available_check = frida
        self.refresh()

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for status bar rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",
            "success": "#00ff00",
            "error": "#fb7185",
            "warning": "#facc15",
            "text_muted": "#8f9bb3",
            ViewMode.FORENSIC: "#2dd4bf",
            ViewMode.MALWARE: "#fb7185",
            ViewMode.SECURITY: "#facc15",
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["success"] = theme.success
                colors["error"] = theme.error
                colors["warning"] = theme.warning
                colors["text_muted"] = theme.text_muted
                colors[ViewMode.FORENSIC] = theme.forensic_color
                colors[ViewMode.MALWARE] = theme.malware_color
                colors[ViewMode.SECURITY] = theme.security_color
        except Exception:
            pass

        return colors

    def render(self) -> RenderableType:
        r"""Render the glance band as an aligned label/value grid.

        Returns a borderless Rich grid: right-justified muted labels, a faint
        gutter rule, then the value column. FIXED_COLORS drive the status
        glyphs (running/stopped, spawn/attach) so they read identically across
        themes; theme colors drive labels and primary text. Multi-part items
        (Device, App) use a continuation row (blank label) for their detail
        line. Per-task detail still lives in the footer's task bar.
        """
        colors = self._get_theme_colors()
        muted = colors["text_muted"]
        primary = colors["primary"]
        run = FIXED_COLORS["running"]
        stop = FIXED_COLORS["stopped"]

        grid = Table.grid(padding=(0, 1))
        grid.add_column(justify="right", style=muted, no_wrap=True)  # label
        grid.add_column(style=muted, no_wrap=True)  # gutter rule
        grid.add_column(overflow="fold")  # value

        def row(label: str, value_markup: str) -> None:
            grid.add_row(label, "│", Text.from_markup(value_markup))

        # -- Device specs (the device NAME rides the panel's top border) --
        # All specs are cached on the Device object — no ADB on render.
        if self.active_device:
            specs = []
            if self.device_android_version or self.device_api_level:
                ver = self.device_android_version or "?"
                api = self.device_api_level or "?"
                specs.append(f"Android {ver} [{muted}]· API {api}[/]")
            if self.device_rooted is True:
                specs.append(f"[{run}]root ✓[/]")
            elif self.device_rooted is False:
                specs.append(f"[{stop}]root ✗[/]")
            if specs:
                row("OS", f" [{muted}]·[/] ".join(specs))

        # -- Frida (FIXED colors; version-mismatch logic untouched) -------
        if self.frida_status == "Running":
            if self._frida_version_mismatch:
                frida_display = "[#facc15 bold]● Running[/] [#facc15]⚠ mismatch[/]"
            else:
                frida_display = f"[{run} bold]● Running[/]"
        elif self.frida_status == "Checking...":
            frida_display = f"[{muted}]○ Checking…[/]"
        else:
            frida_display = f"[{stop}]○ Not running[/]"
        row("Frida", frida_display)

        # -- App: package + mode, then pid/state continuation line --------
        if self.spotlight_app and self.spotlight_app != "None":
            mode = "SPAWN" if self.spawn_mode else "ATTACH"
            mode_color = (
                FIXED_COLORS["spawn_mode"]
                if self.spawn_mode
                else FIXED_COLORS["attach_mode"]
            )
            row(
                "App",
                f"[{primary}]{self.spotlight_app}[/] "
                f"[{mode_color} bold]\\[{mode}][/]",
            )
            if self.spotlight_pid and self.spotlight_paused:
                state = "[#fbbf24]◐ paused[/]"
            elif self.spotlight_pid:
                state = f"[{run}]● running[/]"
            else:
                state = f"[{stop}]○ not running[/]"
            pid_part = (
                f"[{muted}]pid[/] [b]{self.spotlight_pid}[/]  "
                if self.spotlight_pid
                else ""
            )
            row("", f"{pid_part}{state}")
        else:
            row("App", f"[{muted}]None[/]")

        # -- Hooks + Bypass -----------------------------------------------
        on = set(self.bypass_categories)
        bypass_cells = [
            f"[{run}]●[/] {label}"
            for category, label in (
                ("ssl", "SSL"),
                ("root", "Root"),
                ("frida", "Frida"),
                ("debug", "Debug"),
            )
            if category in on
        ]
        bypass_display = " ".join(bypass_cells) if bypass_cells else f"[{muted}]none[/]"
        row(
            "Hooks",
            f"[b]{self.hook_count}[/] [{muted}]active · bypass[/] {bypass_display}",
        )

        # -- Proxy / Net --------------------------------------------------
        if self.proxy_address:
            row("Proxy", f"[{run}]● {self.proxy_address}[/]")
        else:
            row("Proxy", f"[{muted}]○ none[/]")
        if self.network_capture_running:
            filename = (
                os.path.basename(self.network_capture_file)
                if self.network_capture_file
                else "capture.pcap"
            )
            row("Net", f"[{run}]● {filename}[/]")
        else:
            row("Net", f"[{muted}]○ idle[/]")

        # Optional theme indicator as its own row.
        if self.show_theme_indicator:
            row("Theme", f"[{primary}]{self.current_theme}[/] [{muted}](^t)[/]")

        # Wrap the grid in a titled box; the device name rides the top border.
        if self.active_device:
            title = Text.from_markup(
                f"[{primary} bold] {self.device_type} {self.active_device} [/]"
            )
        else:
            title = Text.from_markup(f"[{muted}] No device [/]")
        return Panel(
            grid,
            title=title,
            title_align="left",
            border_style=primary,
            box=ROUNDED,
            padding=(0, 1),
            expand=True,
        )

    def update_from_toolbox(self) -> None:
        """Update status from Toolbox state."""
        try:
            from sandroid.core.toolbox import Toolbox

            # Update view
            self.current_view = get_ui_service().get_current_view().upper()

            # Frida status check is DEFERRED to background thread
            # is_frida_server_running() makes 3 sequential ADB shell commands
            # which blocks the UI for several hundred milliseconds
            # Show "Checking..." and schedule async check
            if self.frida_status not in ("Running", "Not running", "N/A"):
                # Only show "Checking..." if we haven't gotten a result yet
                self.frida_status = "Checking..."

            # Schedule background check (doesn't block UI)
            self._schedule_frida_check()

            # Update spotlight app
            spotlight = get_spotlight_service()
            app = spotlight.get_app_tuple()
            spawn_app = spotlight.get_spawn_package()
            self.spawn_mode = spotlight.is_spawn_mode()

            if self.spawn_mode and spawn_app:
                # spawn_app is just the package name string
                self.spotlight_app = spawn_app
            elif app:
                # app is a tuple (package_name, activity_name) - extract just the package name
                if isinstance(app, tuple):
                    self.spotlight_app = app[0] if app[0] else "None"
                else:
                    self.spotlight_app = str(app)
            else:
                self.spotlight_app = "None"

            # PID + paused state (cheap, cached — no ADB on the hot path).
            try:
                self.spotlight_pid = spotlight.get_pid()
            except Exception:
                self.spotlight_pid = None
            try:
                self.spotlight_paused = bool(spotlight.is_app_paused())
            except Exception:
                self.spotlight_paused = False

            # Hook count: running hook tasks bound to the spotlight package.
            # Mirrors SpotlightPanel._hooks_for_app — this is the HOOK count,
            # which is a different datum from the bypass-category list below.
            try:
                package = spotlight.get_effective_package()
            except Exception:
                package = None
            try:
                tasks = get_task_service().get_running_tasks()
                self.hook_count = sum(
                    1
                    for t in tasks
                    if package and getattr(t, "app_name", None) == package
                )
            except Exception:
                self.hook_count = 0

        except Exception:
            pass

        # Bypass categories armed/active (0-4 of ssl/root/frida/debug).
        # In-process read — NOT the hook count above.
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            self.bypass_categories = list(get_bypass_service().on_categories())
        except Exception:
            self.bypass_categories = []

        # Update device info (separate try to ensure it always runs)
        # Use Toolbox.get_device_manager() to ensure auto-refresh on first access
        try:
            dm = Toolbox.get_device_manager()
            device = dm.active_device
            if device:
                self.active_device = device.short_name
                self.device_type = "\\[E]" if device.is_emulator else "\\[P]"
                # android_version / api_level are cached on the Device at
                # discovery (ro.build.version.*); root is a cached capability
                # flag — all cheap in-memory reads, no ADB on this path.
                self.device_android_version = getattr(
                    device, "android_version", ""
                ) or ""
                self.device_api_level = getattr(device, "api_level", 0) or 0
                try:
                    from sandroid.core.device import DeviceCapability

                    self.device_rooted = device.has_capability(
                        DeviceCapability.ADB_ROOT
                    )
                except Exception:
                    self.device_rooted = None
            else:
                self.active_device = ""
                self.device_type = ""
                self.device_android_version = ""
                self.device_api_level = 0
                self.device_rooted = None
            self.device_count = dm.device_count
        except Exception:
            pass

        # Update theme name from app (separate try to ensure it always runs)
        try:
            if hasattr(self.app, "sandroid_theme"):
                self.current_theme = self.app.sandroid_theme.display_name
        except Exception:
            pass

        # Update background tasks (separate try to ensure it always runs)
        try:
            running_tasks = get_task_service().get_running()
            self.background_tasks_count = len(running_tasks)
            if running_tasks:
                # Build display string with task names and PIDs
                # Use warning color for PIDs (consistent with filenames in menus)
                warn_color = FIXED_COLORS.get("warning_status", "#facc15")
                task_parts = []
                for task_name in running_tasks:
                    task = get_task_service().get_task(task_name)
                    if task:
                        if task.target_pid:
                            task_parts.append(
                                f"[{FIXED_COLORS['running']}]●[/] {task.display_name} ([{warn_color}]{task.target_pid}[/])"
                            )
                        else:
                            task_parts.append(
                                f"[{FIXED_COLORS['running']}]●[/] {task.display_name}"
                            )
                self.background_tasks_display = " ".join(task_parts)
            else:
                self.background_tasks_display = ""
        except Exception:
            self.background_tasks_count = 0
            self.background_tasks_display = ""

        # Update forensic APKs count (separate try to ensure it always runs)
        try:
            forensic_apks = Toolbox.get_forensic_apks()
            self.forensic_apks_count = len(forensic_apks)
        except Exception:
            self.forensic_apks_count = 0

        # Update proxy status (separate try to ensure it always runs)
        try:
            from sandroid.core.proxy_manager import ProxyManager, ProxyStatus

            status, config = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and config:
                self.proxy_address = config.address
            else:
                self.proxy_address = ""
        except Exception:
            self.proxy_address = ""

        # Update network capture status (separate try to ensure it always runs)
        try:
            network_service = get_network_capture_service()
            self.network_capture_running = network_service.is_capturing()
            self.network_capture_file = network_service.get_capture_file() or ""
        except Exception:
            self.network_capture_running = False
            self.network_capture_file = ""

    def refresh_status(self) -> None:
        """Refresh all status bar information.

        Called when settings change (e.g., proxy configured).
        """
        self.update_from_toolbox()
        self.refresh()

    def _schedule_frida_check(self) -> None:
        """Schedule Frida status check in background thread.

        This avoids blocking the UI thread with ADB calls.
        The is_frida_server_running() method makes 3 sequential ADB shell
        commands which can take several hundred milliseconds.
        """
        # Avoid scheduling multiple checks
        if hasattr(self, "_frida_check_pending") and self._frida_check_pending:
            return
        self._frida_check_pending = True

        def _check_frida():
            """Background thread function to check Frida status."""
            try:
                frida_service = get_frida_session_service()
                frida_manager = frida_service.get_frida_manager()
                if frida_manager and frida_manager.is_frida_server_running():
                    status = "Running"
                else:
                    status = "Not running"
            except ImportError:
                status = "N/A"
            except (RuntimeError, Exception):
                # AndroidFridaManager throws RuntimeError on non-rooted devices
                status = "N/A"

            # Update UI from background thread safely
            try:
                self.app.call_from_thread(self._update_frida_status, status)
            except Exception:
                pass  # App may have exited
            finally:
                self._frida_check_pending = False

        # Start background thread
        thread = threading.Thread(target=_check_frida, daemon=True)
        thread.start()

    def _update_frida_status(self, status: str) -> None:
        """Update Frida status from background thread result.

        Args:
            status: The Frida status string
        """
        prev_status = self._frida_last_status
        self._frida_last_status = status
        self.frida_status = status

        # Check version mismatch only on transition to Running
        if status == "Running" and prev_status != "Running":
            self._frida_version_mismatch = None  # Reset until checked
            self._schedule_frida_version_check()
        elif status != "Running":
            self._frida_version_mismatch = None

        self.refresh()

    def _schedule_frida_version_check(self) -> None:
        """Check frida-server version against host frida in background."""

        def _check_version():
            try:
                import frida as _frida_mod

                host_version = _frida_mod.__version__
                stdout, _stderr = Adb.send_adb_command(
                    "shell /data/local/tmp/frida-server --version"
                )
                if stdout and stdout.strip():
                    server_version = stdout.strip()
                    mismatch = server_version != host_version
                else:
                    mismatch = False  # Can't determine, assume OK
            except Exception:
                mismatch = False  # Can't determine, assume OK

            try:
                self.app.call_from_thread(self._apply_version_mismatch, mismatch)
            except Exception:
                pass

        thread = threading.Thread(target=_check_version, daemon=True)
        thread.start()

    def _apply_version_mismatch(self, mismatch: bool) -> None:
        """Apply version mismatch result from background thread."""
        self._frida_version_mismatch = mismatch
        self.refresh()
