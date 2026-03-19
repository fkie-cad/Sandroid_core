"""Status bar widget showing application state."""

import os
import threading

from textual.widgets import Static

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
        self.background_tasks_count = 0
        self.background_tasks_display = ""
        self.forensic_apks_count = 0
        self.proxy_address = ""
        self.network_capture_running = False
        self.network_capture_file = ""
        self.tools_checking = True
        self.sqldiff_available = False
        self.objection_available = False
        self.frida_available_check = False
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

    def render(self) -> str:
        """Render the status bar content.

        Uses FIXED_COLORS for status indicators (running/stopped, spawn/attach)
        so they remain consistent across all themes for instant recognition.
        View colors and text colors come from the active theme.
        """
        colors = self._get_theme_colors()

        # View indicator with theme-specific view colors
        view_colors = {
            ViewMode.FORENSIC.value.upper(): colors[ViewMode.FORENSIC],
            ViewMode.MALWARE.value.upper(): colors[ViewMode.MALWARE],
            ViewMode.SECURITY.value.upper(): colors[ViewMode.SECURITY],
        }
        view_color = view_colors.get(self.current_view, colors["primary"])

        # Frida status with FIXED colors (always same green/red regardless of theme)
        if self.frida_status == "Running":
            frida_display = f"[{FIXED_COLORS['running']} bold]Running[/]"
        else:
            frida_display = f"[{FIXED_COLORS['stopped']}]Not running[/]"

        # Spotlight with attach/spawn indicator using FIXED mode colors
        # SPAWN = cyan (launching fresh), ATTACH = green (connected to running)
        if self.spotlight_app and self.spotlight_app != "None":
            mode = "SPAWN" if self.spawn_mode else "ATTACH"
            mode_color = (
                FIXED_COLORS["spawn_mode"]
                if self.spawn_mode
                else FIXED_COLORS["attach_mode"]
            )
            app_display = f"[{colors['primary']}]{self.spotlight_app}[/] [{mode_color} bold]\\[{mode}][/]"
        else:
            app_display = f"[{colors['text_muted']}]None[/]"

        # Device indicator - keep it simple, footer shows [D] shortcut
        if self.active_device:
            device_display = (
                f"[{colors['primary']}]{self.device_type} {self.active_device}[/]"
            )
        else:
            device_display = f"[{colors['text_muted']}]None[/]"

        # Build status bar - theme indicator is optional
        status_parts = [
            f"[{view_color} bold]{self.current_view}[/]",
            f"Device: {device_display}",
            f"Frida: {frida_display}",
            f"App: {app_display}",
        ]

        # Add proxy status if configured
        if self.proxy_address:
            status_parts.append(
                f"Proxy: [{FIXED_COLORS['running']}]{self.proxy_address}[/]"
            )

        # Add network capture indicator when capturing
        if self.network_capture_running:
            filename = (
                os.path.basename(self.network_capture_file)
                if self.network_capture_file
                else "capture.pcap"
            )
            status_parts.append(
                f"[{FIXED_COLORS['running']}]NET ●[/] [{colors['text_muted']}]{filename}[/]"
            )

        # Add background tasks if any are running
        if self.background_tasks_count > 0 and self.background_tasks_display:
            status_parts.append(f"Tasks: {self.background_tasks_display}")

        # Add forensic APKs indicator in FORENSIC view when APKs exist
        if (
            self.current_view == ViewMode.FORENSIC.value.upper()
            and self.forensic_apks_count > 0
        ):
            status_parts.append(
                f"[{FIXED_COLORS['warning_status']}]APKs: {self.forensic_apks_count}[/] [{colors['text_muted']}](Shift+G)[/]"
            )

        # Only add theme indicator if enabled in config
        if self.show_theme_indicator:
            theme_display = f"[{colors['text_muted']}]^t[/] [{colors['primary']}]{self.current_theme}[/]"
            status_parts.append(theme_display)

        return " | ".join(status_parts)

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

        except Exception:
            pass

        # Update device info (separate try to ensure it always runs)
        # Use Toolbox.get_device_manager() to ensure auto-refresh on first access
        try:
            dm = Toolbox.get_device_manager()
            device = dm.active_device
            if device:
                self.active_device = device.short_name
                self.device_type = "\\[E]" if device.is_emulator else "\\[P]"
            else:
                self.active_device = ""
                self.device_type = ""
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
        self.frida_status = status
        self.refresh()
