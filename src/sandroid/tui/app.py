"""Main Sandroid TUI Application.

This module implements the Textual-based terminal user interface for Sandroid.
It provides a split-pane layout with menu navigation and real-time background
activity monitoring.
"""

import logging
from datetime import datetime

from rich.panel import Panel
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Label, RichLog, Static

logger = logging.getLogger(__name__)


class MenuSection(Static):
    """A section in the menu with a title and items."""

    def __init__(self, title: str, items: list[tuple[str, str]], **kwargs):
        """Initialize a menu section.

        Args:
            title: Section title (e.g., "Action Recording & Playback")
            items: List of (key, description) tuples
        """
        super().__init__(**kwargs)
        self.section_title = title
        self.items = items

    def compose(self) -> ComposeResult:
        yield Static(
            f"[bold cyan]=== {self.section_title} ===[/bold cyan]",
            classes="menu-section-title",
        )
        for key, description in self.items:
            yield Static(f"  [{key}] {description}", classes="menu-item")


class StatusBar(Static):
    """Status bar showing current application state."""

    frida_status = reactive("Not running")
    spotlight_app = reactive("Not set")
    current_view = reactive("FORENSIC")

    def render(self) -> str:
        frida_color = "green" if self.frida_status == "Running" else "red"
        return (
            f"Frida: [{frida_color}]{self.frida_status}[/{frida_color}] | "
            f"App: [yellow]{self.spotlight_app}[/yellow] | "
            f"View: [bold cyan]{self.current_view}[/bold cyan]"
        )


class BackgroundActivityLog(RichLog):
    """Log widget for displaying background task output."""

    def __init__(self, **kwargs):
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)


class MenuPanel(ScrollableContainer):
    """Scrollable menu panel with all menu sections."""

    current_view = reactive("forensic")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._menu_sections = {}

    def compose(self) -> ComposeResult:
        """Compose the menu based on current view."""
        yield Static("[bold]Sandroid Interactive Menu[/bold]", id="menu-title")
        yield Static("", id="menu-content")

    def update_menu(self, view: str = None):
        """Update menu content based on view."""
        if view:
            self.current_view = view

        content = self._build_menu_content()
        menu_content = self.query_one("#menu-content", Static)
        menu_content.update(content)

    def _build_menu_content(self) -> str:
        """Build menu content string based on current view."""
        lines = []

        if self.current_view == "forensic":
            lines.extend(
                [
                    "",
                    "[bold cyan]=== Action Recording & Playback ===[/bold cyan]",
                    "  [r] record an action",
                    "  [p] play the currently loaded action",
                    "  [x] export currently loaded action",
                    "  [i] import action",
                    "",
                    "[bold cyan]=== Spotlight Application ===[/bold cyan]",
                    "  [c] set current app as spotlight app [ATTACH]",
                    "  [C] select app for spawning [SPAWN]",
                    "  [d] dump memory of spotlight app",
                    "",
                    "[bold cyan]=== Spotlight Files ===[/bold cyan]",
                    "  [l] list/add spotlight file",
                    "  [v] remove spotlight file",
                    "  [u] pull spotlight files",
                    "  [o] observe file system changes (fsmon)",
                    "  [SPACE] pull spotlight DB file",
                    "",
                    "[bold cyan]=== Emulator Management ===[/bold cyan]",
                    "  [e] show emulator information",
                    "  [f] run/install frida server",
                    "  [s] take screenshot",
                    "  [g] grab video of screen",
                    "",
                ]
            )
        elif self.current_view == "malware":
            lines.extend(
                [
                    "",
                    "[bold cyan]=== Spotlight Application ===[/bold cyan]",
                    "  [c] set current app as spotlight app [ATTACH]",
                    "  [C] select app for spawning [SPAWN]",
                    "",
                    "[bold cyan]=== Dynamic Analysis ===[/bold cyan]",
                    "  [m] start dexray-intercept monitoring",
                    "  [t] run trigdroid automatic malware trigger",
                    "",
                    "[bold cyan]=== Network Management ===[/bold cyan]",
                    "  [y] set/unset network proxy",
                    "  [h] start friTap hooking",
                    "  [w] write network capture file",
                    "",
                ]
            )
        elif self.current_view == "security":
            lines.extend(
                [
                    "",
                    "[bold cyan]=== Application Management ===[/bold cyan]",
                    "  [c] set current app as spotlight app [ATTACH]",
                    "  [C] select app for spawning [SPAWN]",
                    "  [n] new APK installation",
                    "",
                    "[bold cyan]=== Static Analysis ===[/bold cyan]",
                    "  [a] analyze spotlight app with dexray-insight",
                    "",
                    "[bold cyan]=== System ===[/bold cyan]",
                    "  [e] show emulator information",
                    "  [f] run/install frida server",
                    "",
                ]
            )

        # Common footer
        lines.extend(
            [
                "",
                "[dim]Tip: Press the same key to stop/toggle active background processes[/dim]",
                "",
                "[TAB] switch view  |  [q] quit",
            ]
        )

        return "\n".join(lines)


class SandroidTUI(App):
    """Main Sandroid TUI Application.

    A Textual-based terminal user interface with split-pane layout showing
    the menu on the left and background activity on the right.
    """

    CSS = """
    Screen {
        layout: horizontal;
    }

    #left-panel {
        width: 50%;
        height: 100%;
        border: solid cyan;
        padding: 1;
    }

    #right-panel {
        width: 50%;
        height: 100%;
        border: solid green;
        padding: 1;
    }

    #menu-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }

    #menu-content {
        height: auto;
    }

    #status-bar {
        dock: top;
        height: 1;
        background: $surface;
        padding: 0 1;
    }

    #activity-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }

    #activity-log {
        height: 100%;
    }

    .menu-section-title {
        color: cyan;
        text-style: bold;
        margin-top: 1;
    }

    .menu-item {
        padding-left: 2;
    }

    Footer {
        background: $surface;
    }
    """

    BINDINGS = [
        Binding("tab", "switch_view", "Switch View"),
        Binding("q", "quit", "Quit"),
        # Forensic view bindings
        Binding("r", "menu_action('record')", "Record", show=False),
        Binding("p", "menu_action('play')", "Play", show=False),
        Binding("x", "menu_action('export')", "Export", show=False),
        Binding("i", "menu_action('import')", "Import", show=False),
        Binding(
            "c", "menu_action('spotlight_attach')", "Spotlight (Attach)", show=False
        ),
        Binding("C", "menu_action('spotlight_spawn')", "Spotlight (Spawn)", show=False),
        Binding("d", "menu_action('dump_memory')", "Dump Memory", show=False),
        Binding("l", "menu_action('list_files')", "List Files", show=False),
        Binding("v", "menu_action('remove_file')", "Remove File", show=False),
        Binding("u", "menu_action('pull_files')", "Pull Files", show=False),
        Binding("o", "menu_action('fsmon')", "FSMon", show=False),
        Binding("space", "menu_action('pull_spotlight')", "Pull Spotlight", show=False),
        Binding("e", "menu_action('emulator_info')", "Emulator Info", show=False),
        Binding("f", "menu_action('frida')", "Frida", show=False),
        Binding("s", "menu_action('screenshot')", "Screenshot", show=False),
        Binding("g", "menu_action('screenrecord')", "Screen Record", show=False),
        # Malware view bindings
        Binding("m", "menu_action('dexray')", "Dexray", show=False),
        Binding("t", "menu_action('trigdroid')", "TrigDroid", show=False),
        Binding("y", "menu_action('proxy')", "Proxy", show=False),
        Binding("h", "menu_action('fritap')", "FriTap", show=False),
        Binding("w", "menu_action('network_capture')", "Network Capture", show=False),
        # Security view bindings
        Binding("n", "menu_action('new_apk')", "New APK", show=False),
        Binding("a", "menu_action('analyze')", "Analyze", show=False),
    ]

    current_view = reactive("forensic")
    view_cycle = ["forensic", "malware", "security"]

    def __init__(self, action_queue=None, **kwargs):
        """Initialize the TUI.

        Args:
            action_queue: Optional ActionQ instance for executing menu actions
        """
        super().__init__(**kwargs)
        self.action_queue = action_queue
        self._event_handlers = []

    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        yield Header(show_clock=True)

        with Horizontal():
            with Vertical(id="left-panel"):
                yield StatusBar(id="status-bar")
                yield MenuPanel(id="menu-panel")

            with Vertical(id="right-panel"):
                yield Static("[bold]Background Activity[/bold]", id="activity-title")
                yield BackgroundActivityLog(id="activity-log")

        yield Footer()

    def on_mount(self) -> None:
        """Called when the app is mounted."""
        # Update menu with initial view
        menu_panel = self.query_one("#menu-panel", MenuPanel)
        menu_panel.update_menu(self.current_view)

        # Subscribe to events
        self._subscribe_to_events()

        # Log startup message
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        activity_log.write(
            "[dim]Sandroid TUI started. Background activity will appear here.[/dim]"
        )

    def _subscribe_to_events(self) -> None:
        """Subscribe to EventBus events."""
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            # Task output handler
            def on_task_output(event):
                self.call_from_thread(self._handle_task_output, event)

            bus.subscribe(EventType.TASK_OUTPUT, on_task_output)
            self._event_handlers.append((EventType.TASK_OUTPUT, on_task_output))

            # Task started handler
            def on_task_started(event):
                self.call_from_thread(self._handle_task_started, event)

            bus.subscribe(EventType.TASK_STARTED, on_task_started)
            self._event_handlers.append((EventType.TASK_STARTED, on_task_started))

            # Task stopped handler
            def on_task_stopped(event):
                self.call_from_thread(self._handle_task_stopped, event)

            bus.subscribe(EventType.TASK_STOPPED, on_task_stopped)
            self._event_handlers.append((EventType.TASK_STOPPED, on_task_stopped))

        except ImportError:
            logger.warning(
                "Events module not available, TUI will not receive background updates"
            )

    def _handle_task_output(self, event) -> None:
        """Handle task output event."""
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        timestamp = event.data.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        task_name = event.data.get("task_name", "unknown")
        message = event.data.get("message", "")
        activity_log.write(
            f"[dim]{timestamp}[/dim] [cyan]{task_name}:[/cyan] {message}"
        )

    def _handle_task_started(self, event) -> None:
        """Handle task started event."""
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        display_name = event.data.get("display_name", event.data.get("name", "Unknown"))
        app_name = event.data.get("app_name", "")
        if app_name:
            activity_log.write(
                f"[green]>>> Task started: {display_name} on {app_name}[/green]"
            )
        else:
            activity_log.write(f"[green]>>> Task started: {display_name}[/green]")

    def _handle_task_stopped(self, event) -> None:
        """Handle task stopped event."""
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        display_name = event.data.get("display_name", event.data.get("name", "Unknown"))
        activity_log.write(f"[red]<<< Task stopped: {display_name}[/red]")

    def action_switch_view(self) -> None:
        """Switch to the next view in the cycle."""
        current_idx = self.view_cycle.index(self.current_view)
        next_idx = (current_idx + 1) % len(self.view_cycle)
        self.current_view = self.view_cycle[next_idx]

        # Update menu
        menu_panel = self.query_one("#menu-panel", MenuPanel)
        menu_panel.update_menu(self.current_view)

        # Update status bar
        status_bar = self.query_one("#status-bar", StatusBar)
        status_bar.current_view = self.current_view.upper()

        # Log the view change
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        activity_log.write(
            f"[yellow]Switched to {self.current_view.upper()} view[/yellow]"
        )

    def action_menu_action(self, action: str) -> None:
        """Handle a menu action.

        Args:
            action: The action identifier
        """
        activity_log = self.query_one("#activity-log", BackgroundActivityLog)
        activity_log.write(f"[dim]Action triggered: {action}[/dim]")

        # If we have an action queue, delegate to it
        if self.action_queue:
            # Map action names to menu characters for compatibility
            action_map = {
                "record": "r",
                "play": "p",
                "export": "x",
                "import": "i",
                "spotlight_attach": "c",
                "spotlight_spawn": "C",
                "dump_memory": "d",
                "list_files": "l",
                "remove_file": "v",
                "pull_files": "u",
                "fsmon": "o",
                "pull_spotlight": " ",
                "emulator_info": "e",
                "frida": "f",
                "screenshot": "s",
                "screenrecord": "g",
                "dexray": "m",
                "trigdroid": "t",
                "proxy": "y",
                "fritap": "h",
                "network_capture": "w",
                "new_apk": "n",
                "analyze": "a",
            }
            char = action_map.get(action, action)
            try:
                self.action_queue.parse_interactive_char(char)
            except Exception as e:
                activity_log.write(f"[red]Error executing action: {e}[/red]")

    def update_status(
        self, frida_status: str = None, spotlight_app: str = None
    ) -> None:
        """Update the status bar.

        Args:
            frida_status: New frida status string
            spotlight_app: New spotlight application name
        """
        status_bar = self.query_one("#status-bar", StatusBar)
        if frida_status is not None:
            status_bar.frida_status = frida_status
        if spotlight_app is not None:
            status_bar.spotlight_app = spotlight_app

    def on_unmount(self) -> None:
        """Clean up when the app is unmounted."""
        # Unsubscribe from events
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, handler in self._event_handlers:
                bus.unsubscribe(event_type, handler)
        except ImportError:
            pass


def run_tui(action_queue=None):
    """Run the Sandroid TUI application.

    Args:
        action_queue: Optional ActionQ instance for executing menu actions

    Returns:
        The exit code from the TUI application
    """
    app = SandroidTUI(action_queue=action_queue)
    return app.run()
