"""Menu rendering logic extracted from Toolbox.

This module provides the MenuRenderer class responsible for building
and displaying the interactive menu with view-based filtering.
"""

import os
import re

from wcwidth import wcswidth

from sandroid.services import (
    get_emulator_service,
    get_frida_session_service,
    get_network_capture_service,
    get_task_service,
)
from sandroid.services.forensic_utils import is_wal_or_journal

from .console import SandroidConsole
from .enums import ViewMode

# Pre-compiled regexes for stripping ANSI and Rich markup
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
_BRACKET_PLACEHOLDER = "\x00LBRACKET\x00"


def _strip_rich_markup(s: str) -> str:
    """Strip Rich markup tags but preserve escaped brackets as visible text."""
    s = s.replace("\\[", _BRACKET_PLACEHOLDER)
    s = _RICH_MARKUP_RE.sub("", s)
    return s.replace(_BRACKET_PLACEHOLDER, "[")


def _strip_formatting(s: str) -> str:
    """Strip both ANSI codes and Rich markup from a string."""
    return _strip_rich_markup(_ANSI_RE.sub("", s))


def _strip_ansi(s: str) -> str:
    """Strip ANSI escape codes from a string."""
    return _ANSI_RE.sub("", s)


def _cell_width(s: str) -> int:
    """Get display width in terminal cells (handles emoji, combining marks)."""
    w = wcswidth(s)
    return 0 if w < 0 else w


def _is_fritap_running() -> bool:
    """Check if FriTap is running with fallback to FridaSessionService.

    This handles the case where FriTap registration failed but the job
    is still running.

    Returns:
        True if FriTap is running, False otherwise.
    """
    # Primary: Check TaskService
    task_service = get_task_service()
    if task_service.is_running("fritap"):
        return True

    # Fallback: Check FridaSessionService for active FriTap jobs
    try:
        frida_service = get_frida_session_service()
        if frida_service.has_active_session():
            for job_info in frida_service.get_running_jobs():
                if job_info.get("job_type") == "fritap":
                    return True
    except Exception:
        pass

    return False


class MenuRenderer:
    """Handles rendering the interactive menu for Sandroid.

    This class extracts menu rendering logic from Toolbox, building
    menu content for each view (forensic, malware, security) and
    managing status displays.
    """

    def __init__(self, toolbox_cls):
        """Initialize the MenuRenderer with a reference to Toolbox.

        Args:
            toolbox_cls: The Toolbox class (not instance) for accessing state
        """
        self.toolbox = toolbox_cls

    def render(self) -> None:
        """Main render method - clears screen, prints logo, renders menu.

        This method orchestrates the complete menu rendering process,
        including status header, view-specific content, and footer.
        """
        console = SandroidConsole.get()

        # Clear screen and show logo at top
        SandroidConsole.clear()
        SandroidConsole.print_logo()
        console.print()  # Add blank line after logo

        # Get current view from UIService
        from sandroid.services import get_ui_service

        current_view = get_ui_service().get_current_view()
        view_display = current_view.upper()

        # Build menu content
        menu_content = []

        # Header with status info (always shown in all views)
        menu_content.extend(self._build_header_status())
        menu_content.append("")  # Blank line

        # Mode indicator for Frida-based tools
        mode_indicator = self._get_mode_indicator()

        # View-specific content
        if current_view == ViewMode.FORENSIC:
            menu_content.extend(self._build_forensic_view(mode_indicator))
        elif current_view == ViewMode.MALWARE:
            menu_content.extend(self._build_malware_view(mode_indicator))
        elif current_view == ViewMode.SECURITY:
            menu_content.extend(self._build_security_view(mode_indicator))

        # Background Activity Section
        menu_content.extend(self._build_background_activity())

        # Footer
        menu_content.extend(self._build_footer())

        # Create the menu with view-specific title using custom bordered box
        title = f"Sandroid Interactive Menu - [bold yellow]{view_display} VIEW[/bold yellow]"
        content = "\n".join(menu_content)

        # Create the bordered box
        box_output = self._create_colored_box(content, title, border_color="cyan")
        console.print(box_output)

        # Print any buffered startup messages below the menu
        SandroidConsole.print_startup_messages()

    def _get_mode_indicator(self) -> str:
        """Get the mode indicator string (SPAWN/ATTACH) based on spotlight state.

        Returns:
            Rich markup string for mode indicator or empty string
        """
        # Import lazily to avoid circular imports
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        is_spawn = spotlight.is_spawn_mode()
        app_tuple = spotlight.get_app_tuple()

        if is_spawn:
            return " [mode.spawn]\\[SPAWN][/mode.spawn]"
        if app_tuple:
            return " [mode.attach]\\[ATTACH][/mode.attach]"
        return ""

    def _build_header_status(self) -> list[str]:
        """Build status header lines (frida, proxy, spotlight app, files, tasks).

        Returns:
            List of status line strings with Rich markup
        """
        # Import lazily to avoid circular imports
        from sandroid.services import get_spotlight_service, get_ui_service

        lines = []
        current_view = get_ui_service().get_current_view()

        # Frida server status
        is_frida_running = self.toolbox.frida_manager.is_frida_server_running()
        if is_frida_running:
            frida_server_string = "[status.running]Running[/status.running]"
        else:
            frida_server_string = "[status.stopped]Not running[/status.stopped]"
        lines.append(f"Frida Server: [{frida_server_string}]")

        # Proxy settings (shown in all views)
        proxy_settings = self.toolbox.get_proxy_settings()
        if proxy_settings == "Not set":
            proxy_string = "[status.stopped]Not set[/status.stopped]"
        else:
            proxy_string = f"[success]{proxy_settings}[/success]"

        # Add adjustment note if not in a view where it can be modified
        if current_view == ViewMode.SECURITY:
            proxy_string = f"HTTP Proxy: [{proxy_string}] [warning](adjust in forensic/malware view)[/warning]"
        else:
            proxy_string = f"HTTP Proxy: [{proxy_string}]"
        lines.append(proxy_string)

        # Spotlight application (shown in all views) - via SpotlightService
        spotlight = get_spotlight_service()

        spawn_package = spotlight.get_spawn_package()
        is_spawn = spotlight.is_spawn_mode()
        app_tuple = spotlight.get_app_tuple()
        app_pid = spotlight.get_pid()

        if is_spawn and spawn_package:
            # SPAWN MODE. Resume behavior is chosen per action in the
            # spotlight panel now, so no (auto-resume)/(manual resume) tag.
            spotlight_application_string = f"[warning]{spawn_package}[/warning]"
            spotlight_application_string = f"Spotlight Application: [{spotlight_application_string}] [mode.spawn]\\[SPAWN MODE][/mode.spawn]"
        elif app_tuple:
            # ATTACH MODE
            spotlight_application_string = f"Spotlight Application: [[warning]{app_tuple[0]}, PID: {app_pid}[/warning]] [mode.attach]\\[ATTACH MODE][/mode.attach]"
        else:
            spotlight_application_string = (
                "Spotlight Application: [[status.stopped]Not set[/status.stopped]]"
            )
        lines.append(spotlight_application_string)

        # Spotlight files (shown in all views)
        spotlight_files = [
            file
            for file in self.toolbox._spotlight_files
            if not is_wal_or_journal(file)
        ]

        if not spotlight_files:
            spotlight_files_display = "[status.stopped]Not set[/status.stopped]"
        elif len(spotlight_files) == 1:
            spotlight_files_display = f"[warning]{spotlight_files[0]}[/warning]"
        else:
            spotlight_files_display = (
                f"[warning]{len(spotlight_files)} files set[/warning]"
            )

        # Add adjustment note if not in forensic view
        if current_view == ViewMode.FORENSIC:
            spotlight_files_string = f"Spotlight Files: [{spotlight_files_display}]"
        else:
            spotlight_files_string = f"Spotlight Files: [{spotlight_files_display}] [warning](adjust in forensic view)[/warning]"
        lines.append(spotlight_files_string)

        # Background tasks status
        bg_tasks_status = get_task_service().get_status_string()
        if bg_tasks_status:
            lines.append(f"Background Tasks: {bg_tasks_status}")

        return lines

    def _build_forensic_view(self, mode_indicator: str) -> list[str]:
        """Build forensic view sections.

        Args:
            mode_indicator: The SPAWN/ATTACH mode indicator string

        Returns:
            List of menu content lines with Rich markup
        """
        lines = []

        # Action Recording & Playback
        lines.extend(
            [
                "    [menu.section]=== Action Recording & Playback ===[/menu.section]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]r[/menu.key][menu.key.bracket]][/menu.key.bracket]ecord an action",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]p[/menu.key][menu.key.bracket]][/menu.key.bracket]lay the currently loaded action",
                "    * e[menu.key.bracket]\\[[/menu.key.bracket][menu.key]x[/menu.key][menu.key.bracket]][/menu.key.bracket]port currently loaded action",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]i[/menu.key][menu.key.bracket]][/menu.key.bracket]mport action",
                "",
            ]
        )

        # Spotlight Application
        lines.extend(
            [
                "    [menu.section]=== Spotlight Application ===[/menu.section]",
                "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
                "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
                f"    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]d[/menu.key][menu.key.bracket]][/menu.key.bracket]ump memory of spotlight app{mode_indicator}",
                "",
            ]
        )

        # Spotlight Files
        lines.extend(
            [
                "    [menu.section]=== Spotlight Files ===[/menu.section]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]l[/menu.key][menu.key.bracket]][/menu.key.bracket]ist/add spotlight file",
                "    * remo[menu.key.bracket]\\[[/menu.key.bracket][menu.key]v[/menu.key][menu.key.bracket]][/menu.key.bracket]e spotlight file",
                "    * p[menu.key.bracket]\\[[/menu.key.bracket][menu.key]u[/menu.key][menu.key.bracket]][/menu.key.bracket]ll spotlight files",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]o[/menu.key][menu.key.bracket]][/menu.key.bracket]bserve file system changes",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]space[/menu.key][menu.key.bracket]][/menu.key.bracket] pull spotlight DB file",
                "",
            ]
        )

        # Emulator Management
        screen_recording_string = self._get_screen_recording_string()
        lines.extend(
            [
                "    [menu.section]=== Emulator Management ===[/menu.section]",
                "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information, [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+E[/menu.key][menu.key.bracket]][/menu.key.bracket] edit settings",
                "    * keys [menu.key.bracket]\\[[/menu.key.bracket][menu.key]1-8[/menu.key][menu.key.bracket]][/menu.key.bracket] create snapshots, key [menu.key.bracket]\\[[/menu.key.bracket][menu.key]0[/menu.key][menu.key.bracket]][/menu.key.bracket] lists/loads snapshots",
                "    * take [menu.key.bracket]\\[[/menu.key.bracket][menu.key]s[/menu.key][menu.key.bracket]][/menu.key.bracket]creenshot of device",
                f"    {screen_recording_string}",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                "",
            ]
        )

        # Network Management (no friTap in forensic view)
        network_capture_string = self._get_network_capture_string()
        lines.extend(
            [
                "    [menu.section]=== Network Management ===[/menu.section]",
                "    * set/unset network prox[menu.key.bracket]\\[[/menu.key.bracket][menu.key]y[/menu.key][menu.key.bracket]][/menu.key.bracket]",
                f"    {network_capture_string}",
                "",
            ]
        )

        # Analysis (MVT Forensic Evidence Scan)
        lines.extend(
            [
                "    [menu.section]=== Analysis ===[/menu.section]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+F[/menu.key][menu.key.bracket]][/menu.key.bracket] Forensic Evidence Scan (MVT)",
                "",
            ]
        )

        return lines

    def _build_malware_view(self, mode_indicator: str) -> list[str]:
        """Build malware view sections.

        Args:
            mode_indicator: The SPAWN/ATTACH mode indicator string

        Returns:
            List of menu content lines with Rich markup
        """
        lines = []

        # Action Recording & Playback
        lines.extend(
            [
                "    [menu.section]=== Action Recording & Playback ===[/menu.section]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]r[/menu.key][menu.key.bracket]][/menu.key.bracket]ecord an action",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]p[/menu.key][menu.key.bracket]][/menu.key.bracket]lay the currently loaded action",
                "    * e[menu.key.bracket]\\[[/menu.key.bracket][menu.key]x[/menu.key][menu.key.bracket]][/menu.key.bracket]port currently loaded action",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]i[/menu.key][menu.key.bracket]][/menu.key.bracket]mport action",
                "",
            ]
        )

        # Spotlight Application (malware-specific tools)
        malware_monitor_string = ""
        hook_config_string = ""
        task_service = get_task_service()
        if task_service.is_running("dexray-intercept"):
            dexray_task = task_service.get_task("dexray-intercept")
            # Show app name in [warning] color for consistency with filenames
            current_app = (
                dexray_task.app_name if dexray_task and dexray_task.app_name else "app"
            )
            malware_monitor_string = f"* stop android [menu.key.bracket]\\[[/menu.key.bracket][menu.key]m[/menu.key][menu.key.bracket]][/menu.key.bracket]alware monitor (dexray-intercept) on [warning]{current_app}[/warning]"
            # Show option to reconfigure hooks while running
            hook_config_string = "    * reconfigure hoo[menu.key.bracket]\\[[/menu.key.bracket][menu.key]k[/menu.key][menu.key.bracket]][/menu.key.bracket]s (stops, reconfigures, restarts)"
        else:
            malware_monitor_string = f"* start android [menu.key.bracket]\\[[/menu.key.bracket][menu.key]m[/menu.key][menu.key.bracket]][/menu.key.bracket]alware monitor (dexray-intercept){mode_indicator}"

        menu_items = [
            "    [menu.section]=== Spotlight Application ===[/menu.section]",
            "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
            "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
            f"    {malware_monitor_string}",
        ]
        # Add hook config option only when dexray-intercept is running
        if hook_config_string:
            menu_items.append(hook_config_string)
        menu_items.extend(
            [
                f"    * start o[menu.key.bracket]\\[[/menu.key.bracket][menu.key]b[/menu.key][menu.key.bracket]][/menu.key.bracket]jection interactive shell{mode_indicator}",
                "    * run [menu.key.bracket]\\[[/menu.key.bracket][menu.key]t[/menu.key][menu.key.bracket]][/menu.key.bracket]rigdroid malware triggers",
                "",
            ]
        )
        lines.extend(menu_items)

        # Emulator Management
        screen_recording_string = self._get_screen_recording_string()
        lines.extend(
            [
                "    [menu.section]=== Emulator Management ===[/menu.section]",
                "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information, [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+E[/menu.key][menu.key.bracket]][/menu.key.bracket] edit settings",
                "    * keys [menu.key.bracket]\\[[/menu.key.bracket][menu.key]1-8[/menu.key][menu.key.bracket]][/menu.key.bracket] create snapshots, key [menu.key.bracket]\\[[/menu.key.bracket][menu.key]0[/menu.key][menu.key.bracket]][/menu.key.bracket] lists/loads snapshots",
                "    * take [menu.key.bracket]\\[[/menu.key.bracket][menu.key]s[/menu.key][menu.key.bracket]][/menu.key.bracket]creenshot of device",
                f"    {screen_recording_string}",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                "",
            ]
        )

        # Network Management (includes friTap)
        network_capture_string = self._get_network_capture_string()

        # FriTap menu item with toggle state
        # Use helper that checks both TaskService and FridaSessionService fallback
        if _is_fritap_running():
            fritap_task = task_service.get_task("fritap")
            # Show app name in [warning] color for consistency with filenames
            # Try to get app name from TaskService, or from FridaSessionService
            fritap_app = "app"
            if fritap_task and fritap_task.app_name:
                fritap_app = fritap_task.app_name
            else:
                # Fallback: try to get from FridaSessionService
                try:
                    frida_service = get_frida_session_service()
                    for job_info in frida_service.get_running_jobs():
                        if job_info.get("job_type") == "fritap":
                            fritap_app = job_info.get("target_app", "app")
                            break
                except Exception:
                    pass
            fritap_string = f"* stop friTap [menu.key.bracket]\\[[/menu.key.bracket][menu.key]h[/menu.key][menu.key.bracket]][/menu.key.bracket]ooking on [warning]{fritap_app}[/warning]"
        else:
            fritap_string = f"* start friTap [menu.key.bracket]\\[[/menu.key.bracket][menu.key]h[/menu.key][menu.key.bracket]][/menu.key.bracket]ooking{mode_indicator}"

        lines.extend(
            [
                "    [menu.section]=== Network Management ===[/menu.section]",
                "    * set/unset network prox[menu.key.bracket]\\[[/menu.key.bracket][menu.key]y[/menu.key][menu.key.bracket]][/menu.key.bracket]",
                f"    {fritap_string}",
                f"    {network_capture_string}",
                "",
            ]
        )

        return lines

    def _build_security_view(self, mode_indicator: str) -> list[str]:
        """Build security view sections.

        Args:
            mode_indicator: The SPAWN/ATTACH mode indicator string (unused in security view)

        Returns:
            List of menu content lines with Rich markup
        """
        lines = []

        # Minimal view - only static analysis and basic controls
        lines.extend(
            [
                "    [menu.section]=== Application Management ===[/menu.section]",
                "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
                "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                "",
                "    [menu.section]=== Static Analysis ===[/menu.section]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]a[/menu.key][menu.key.bracket]][/menu.key.bracket]nalyze spotlight app with dexray-insight",
                "",
                "    [menu.section]=== System ===[/menu.section]",
                "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information, [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+E[/menu.key][menu.key.bracket]][/menu.key.bracket] edit settings",
                "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                "",
            ]
        )

        return lines

    def _build_background_activity(self) -> list[str]:
        """Build background activity section.

        Shows running tasks and recent output from background processes.

        Returns:
            List of menu content lines with Rich markup
        """
        from sandroid.services import get_ui_service

        lines = []
        task_service = get_task_service()
        ui_service = get_ui_service()
        running_task_names = task_service.get_running()

        recent_lines = ui_service.get_recent_output(5)
        recent_output = [
            (line.timestamp.strftime("%H:%M:%S"), line.task_name or "", line.message)
            for line in recent_lines
        ]
        if recent_output or running_task_names:
            lines.append("")
            lines.append("    [menu.section]=== Background Activity ===[/menu.section]")
            if recent_output:
                for timestamp, task_name, msg in recent_output:
                    # Truncate long messages to fit in menu
                    display_msg = msg[:65] + "..." if len(msg) > 65 else msg
                    # Escape any brackets in the message to prevent Rich markup issues
                    display_msg = display_msg.replace("[", "\\[").replace("]", "\\]")
                    lines.append(
                        f"    [dim]{timestamp}[/dim] [accent]{task_name}:[/accent] {display_msg}"
                    )
                # Show hint for more output
                total_buffered = ui_service.get_output_count()
                if total_buffered > 5:
                    lines.append(
                        f"    [dim]... {total_buffered - 5} more messages buffered[/dim]"
                    )
            else:
                # Show that tasks are running but no output yet
                running_tasks = ", ".join(running_task_names)
                lines.append(
                    f"    [dim]Tasks running: {running_tasks} (no output yet)[/dim]"
                )

        return lines

    def _build_footer(self) -> list[str]:
        """Build footer with tips and quit.

        Returns:
            List of footer content lines with Rich markup
        """
        return [
            "",
            "    [dim]Tip: Press the same key again to stop/toggle active background processes[/dim]",
            "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]TAB[/menu.key][menu.key.bracket]][/menu.key.bracket] switch view  |  [menu.key.bracket]\\[[/menu.key.bracket][menu.key]q[/menu.key][menu.key.bracket]][/menu.key.bracket]uit",
        ]

    def _get_screen_recording_string(self) -> str:
        """Get the screen recording menu item string based on current state.

        Returns:
            Menu item string for screen recording toggle
        """
        emulator_service = get_emulator_service()
        if emulator_service.is_recording():
            recording_file = emulator_service.get_recording_file()
            return f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rabbing video of screen ([warning]{os.path.basename(recording_file)}[/warning])"
        return "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rab video of screen"

    def _get_network_capture_string(self) -> str:
        """Get the network capture menu item string based on current state.

        Returns:
            Menu item string for network capture toggle
        """
        network_service = get_network_capture_service()
        if network_service.is_capturing():
            capture_file = network_service.get_capture_file()
            filename = (
                os.path.basename(capture_file) if capture_file else "capture.pcap"
            )
            return f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]riting network capture file ([warning]{filename}[/warning])"
        return "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]rite network capture file"

    def _create_colored_box(
        self, text: str, title: str, border_color: str = "cyan"
    ) -> str:
        """Create a bordered box with colored borders and a title section.

        The title gets its own row with a separator line below it.

        Args:
            text: The text to be enclosed in the box.
            title: The title of the box (can include Rich markup).
            border_color: Color for the box borders.

        Returns:
            The formatted box with Rich color markup.
        """
        raw_lines = text.splitlines()
        stripped_lines = [_strip_formatting(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [_cell_width(ln) for ln in stripped_lines]

        stripped_title = _strip_formatting(title)
        title_w = _cell_width(stripped_title)

        content_max_width = max(visible_widths) if visible_widths else 0
        inner_width = max(content_max_width, title_w) + 4

        bc = border_color

        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        h_line = "\u2500" * inner_width
        top = (
            f"[{bc}]\u250c{h_line}\u2510[/{bc}]\n"
            f"[{bc}]\u2502[/{bc}]{' ' * pad_left}{title}{' ' * pad_right}[{bc}]\u2502[/{bc}]\n"
            f"[{bc}]\u251c{h_line}\u2524[/{bc}]\n"
        )

        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = max(inner_width - _cell_width(stripped), 0)
            body_parts.append(f"[{bc}]\u2502[/{bc}]{raw}{' ' * pad}[{bc}]\u2502[/{bc}]")
        body = "\n".join(body_parts)

        bottom = f"\n[{bc}]\u2514{h_line}\u2518[/{bc}]"

        return f"{top}{body}{bottom}"

    def _create_ascii_box(self, text: str, title: str) -> str:
        """Create an ASCII box with a title.

        Args:
            text: The text to be enclosed in the ASCII box.
            title: The title of the ASCII box.

        Returns:
            The formatted ASCII box.
        """
        raw_lines = text.splitlines()
        stripped_lines = [_strip_ansi(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [_cell_width(ln) for ln in stripped_lines]
        inner_width = (max(visible_widths) if visible_widths else 0) + 2

        stripped_title = _strip_ansi(title)
        title_w = _cell_width(stripped_title)
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        h_line = "\u2500" * inner_width
        top = (
            f"\u250c{h_line}\u2510\n"
            f"\u2502{' ' * pad_left}{title}{' ' * pad_right}\u2502\n"
            f"\u251c{h_line}\u2524\n"
        )

        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = max(inner_width - _cell_width(stripped), 0)
            body_parts.append(f"\u2502{raw}{' ' * pad}\u2502")
        body = "\n".join(body_parts)

        bottom = f"\n\u2514{h_line}\u2518"
        return f"{top}{body}{bottom}"
