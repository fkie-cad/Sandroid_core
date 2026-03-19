"""Application selection modal with filter toggles.

Provides a modal for selecting Android applications with options to:
- Show all user-installed apps (not just recently installed)
- Include system apps
- Filter by name
- Auto-select a default package
"""

from collections.abc import Callable
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter
from sandroid.tui.widgets import LoadingSpinner


@dataclass
class AppSelectionResult:
    """Result from the application selection modal.

    Attributes:
        cancelled: Whether the dialog was cancelled.
        package_name: Selected package name (None if cancelled).
        show_all_user_apps: State of the 'all user apps' toggle.
        include_system_apps: State of the 'include system apps' toggle.
    """

    cancelled: bool = True
    package_name: str | None = None
    show_all_user_apps: bool = False
    include_system_apps: bool = False


class AppSelectionModal(ForensicModal[AppSelectionResult]):
    """Modal for selecting an Android application.

    Features:
    - Toggle to show all user apps (not just recently installed)
    - Toggle to include system apps
    - Real-time filter as you type
    - Keyboard navigation (j/k or arrow keys)
    - Enter to select, Escape to cancel
    - Auto-select default package if provided
    """

    DEFAULT_CSS = """
    AppSelectionModal .modal-container {
        width: 80;
        max-width: 90%;
        max-height: 75%;
    }

    AppSelectionModal #toggle-row {
        width: 100%;
        height: 1;
        margin-bottom: 1;
        padding: 0 2;
    }

    AppSelectionModal .toggle-option {
        width: auto;
        height: 1;
        margin-right: 3;
    }

    AppSelectionModal .toggle-option.enabled {
        color: $success;
    }

    AppSelectionModal .toggle-option.disabled {
        color: $foreground-muted;
    }

    AppSelectionModal #app-list {
        width: 100%;
        height: auto;
        max-height: 15;
        background: $surface;
        border: solid $panel;
    }

    AppSelectionModal #app-list:focus {
        border: solid $primary;
    }

    AppSelectionModal #app-list > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }

    AppSelectionModal .hidden {
        display: none;
    }
    """

    BINDINGS = [
        Binding("enter", "select", "Select", priority=True),
        Binding("a", "toggle_all_user", "All User Apps", show=False),
        Binding("s", "toggle_system", "System Apps", show=False),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#filter-input"

    def __init__(
        self,
        title: str = "Select Application",
        packages: list[dict] | None = None,
        default_package: str | None = None,
        package_loader: Callable[[bool, bool], list[dict]] | None = None,
        include_system_apps: bool = False,
        initial_loader: Callable[..., list[dict]] | None = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the application selection modal.

        Args:
            title: Dialog title.
            packages: Initial list of packages (each dict has 'package_name', 'install_date').
            default_package: Package to pre-select/highlight.
            package_loader: Optional callback to reload packages when toggles change.
                           Signature: (show_all_user: bool, include_system: bool) -> List[dict]
            include_system_apps: Initial state of the system apps toggle.
            initial_loader: Optional callback to load packages asynchronously on mount.
                           When provided and packages is empty, the modal shows a loading
                           indicator and calls this to populate the list.
                           Signature: () -> List[dict]
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.all_packages = packages or []
        self.filtered_packages = self.all_packages.copy()
        self.default_package = default_package
        self.package_loader = package_loader
        self.initial_loader = initial_loader

        # Toggle states
        self.show_all_user_apps = False
        self.include_system_apps = include_system_apps

        # Loading state
        self._is_loading = False

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")

            # Toggle row
            with Horizontal(id="toggle-row"):
                yield Static(
                    self._format_toggle(
                        "A", "Show all user apps", self.show_all_user_apps
                    ),
                    id="toggle-all-user",
                    classes="toggle-option disabled",
                )
                yield Static(
                    self._format_toggle(
                        "S", "Include system apps", self.include_system_apps
                    ),
                    id="toggle-system",
                    classes="toggle-option disabled",
                )

            yield Input(placeholder="Type to filter...", id="filter-input")

            yield OptionList(
                *self._create_options(),
                id="app-list",
            )

            yield LoadingSpinner(id="loading-indicator", classes="hidden")

            yield KeyHintFooter(
                hints={
                    "input": "[dim]A/S=Toggle  Enter=Select  Esc=Cancel[/dim]",
                    "list": "[dim]A/S=Toggle  Enter=Select  Esc=Cancel  j/k=Navigate[/dim]",
                    "default": "[dim]A/S=Toggle  Enter=Select  Esc=Cancel[/dim]",
                }
            )

    def _format_toggle(self, key: str, label: str, enabled: bool) -> str:
        """Format a toggle option with bullet indicator."""
        indicator = "\u25cf" if enabled else "\u25cb"  # or
        if enabled:
            return f"[{key}] [green]{indicator}[/] {label}"
        return f"[{key}] [dim]{indicator}[/] {label}"

    def _create_options(self) -> list[Option]:
        """Create option list items from filtered packages."""
        options = []
        for pkg in self.filtered_packages:
            display_text = self._format_package(pkg)
            options.append(Option(display_text))
        return options

    def _format_package(self, pkg: dict) -> str:
        """Format a package for display."""
        name = pkg.get("package_name", "Unknown")
        install_date = pkg.get("install_date", "")
        if install_date:
            # Format: package.name [2025-12-03 12:00:00]
            return f"{name} [{install_date}]"
        return name

    def on_mount(self) -> None:
        """Focus the filter input and select default on mount.

        If an initial_loader is provided and there are no packages yet,
        shows a prominent loading state and loads packages asynchronously.
        """
        super().on_mount()
        if self.initial_loader and not self.all_packages:
            self._is_loading = True
            # Hide interactive elements during loading
            self.query_one("#filter-input", Input).add_class("hidden")
            self.query_one("#app-list", OptionList).add_class("hidden")
            self.query_one("#toggle-row", Horizontal).add_class("hidden")
            spinner = self.query_one("#loading-indicator", LoadingSpinner)
            spinner.remove_class("hidden")
            spinner.update_message("Enumerating installed apps on device...")
            spinner.update_hint(
                "This may take a moment on first run.\n"
                "Results will be cached for this session."
            )
            self.run_worker(self._initial_load_async, exclusive=True)
        else:
            self._highlight_default_or_first()

    def _highlight_default_or_first(self) -> None:
        """Highlight the default package or first option."""
        app_list = self.query_one("#app-list", OptionList)

        if self.default_package and self.filtered_packages:
            for idx, pkg in enumerate(self.filtered_packages):
                if pkg.get("package_name") == self.default_package:
                    app_list.highlighted = idx
                    return

        if self.filtered_packages:
            app_list.highlighted = 0

    async def _initial_load_async(self) -> None:
        """Load packages asynchronously using the initial_loader callback.

        Runs initial_loader in a real thread so that call_from_thread works
        for live status updates while the (potentially slow) ADB call runs.
        """
        import asyncio

        try:
            if self.initial_loader:
                spinner = self.query_one("#loading-indicator", LoadingSpinner)

                def update_status(msg: str) -> None:
                    self.app.call_from_thread(spinner.update_message, msg)

                new_packages = await asyncio.to_thread(
                    self.initial_loader, on_status=update_status
                )
                self.all_packages = new_packages or []
                self.filtered_packages = self.all_packages.copy()

                if not self.default_package and self.all_packages:
                    self.default_package = self.all_packages[0].get("package_name")

                self._update_option_list()
        finally:
            self._is_loading = False
            self.query_one("#loading-indicator", LoadingSpinner).add_class("hidden")
            # Reveal interactive elements
            filter_input = self.query_one("#filter-input", Input)
            filter_input.remove_class("hidden")
            self.query_one("#app-list", OptionList).remove_class("hidden")
            self.query_one("#toggle-row", Horizontal).remove_class("hidden")
            filter_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle filter input changes."""
        if event.input.id != "filter-input":
            return

        query = event.value.lower().strip()
        if query:
            self.filtered_packages = [
                p
                for p in self.all_packages
                if query in p.get("package_name", "").lower()
            ]
        else:
            self.filtered_packages = self.all_packages.copy()

        self._update_option_list()

    def _update_option_list(self) -> None:
        """Update the option list with filtered packages."""
        app_list = self.query_one("#app-list", OptionList)
        app_list.clear_options()

        for pkg in self.filtered_packages:
            app_list.add_option(Option(self._format_package(pkg)))

        self._highlight_default_or_first()

    def _update_toggle_widget(
        self, widget_id: str, key: str, label: str, enabled: bool
    ) -> None:
        """Update a single toggle widget's text and class."""
        toggle = self.query_one(f"#{widget_id}", Static)
        toggle.update(self._format_toggle(key, label, enabled))
        toggle.remove_class("enabled" if not enabled else "disabled")
        toggle.add_class("enabled" if enabled else "disabled")

    def _update_toggles(self) -> None:
        """Update toggle display."""
        self._update_toggle_widget(
            "toggle-all-user", "A", "Show all user apps", self.show_all_user_apps
        )
        self._update_toggle_widget(
            "toggle-system", "S", "Include system apps", self.include_system_apps
        )

    def action_toggle_all_user(self) -> None:
        """Toggle 'show all user apps' option."""
        self.show_all_user_apps = not self.show_all_user_apps
        self._update_toggles()
        self._reload_packages()

    def action_toggle_system(self) -> None:
        """Toggle 'include system apps' option."""
        self.include_system_apps = not self.include_system_apps
        self._update_toggles()
        self._reload_packages()

    def _reload_packages(self) -> None:
        """Reload packages based on current toggle states."""
        if not self.package_loader:
            return

        spinner = self.query_one("#loading-indicator", LoadingSpinner)
        spinner.update_message("Loading packages...")
        spinner.update_hint("")
        spinner.remove_class("hidden")
        self.run_worker(self._load_packages_async, exclusive=True)

    async def _load_packages_async(self) -> None:
        """Load packages asynchronously."""
        try:
            if self.package_loader:
                # Call the loader with current toggle states
                new_packages = self.package_loader(
                    self.show_all_user_apps, self.include_system_apps
                )
                self.all_packages = new_packages
                self.filtered_packages = new_packages.copy()

                # Clear filter
                filter_input = self.query_one("#filter-input", Input)
                filter_input.value = ""

                # Update list
                self._update_option_list()
        finally:
            self.query_one("#loading-indicator", LoadingSpinner).add_class("hidden")

    def action_select(self) -> None:
        """Select the currently highlighted option."""
        self._select_current()

    def _select_current(self) -> None:
        """Select the current highlighted package."""
        app_list = self.query_one("#app-list", OptionList)
        if app_list.highlighted is not None and app_list.highlighted < len(
            self.filtered_packages
        ):
            selected_pkg = self.filtered_packages[app_list.highlighted]
            result = AppSelectionResult(
                cancelled=False,
                package_name=selected_pkg.get("package_name"),
                show_all_user_apps=self.show_all_user_apps,
                include_system_apps=self.include_system_apps,
            )
            self._dismiss_with_refresh(result)

    def action_next(self) -> None:
        """Move to next option."""
        app_list = self.query_one("#app-list", OptionList)
        app_list.action_cursor_down()

    def action_prev(self) -> None:
        """Move to previous option."""
        app_list = self.query_one("#app-list", OptionList)
        app_list.action_cursor_up()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()
