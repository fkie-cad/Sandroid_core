"""APK Installation modal for searching and installing APKs.

Supports multiple APK sources:
- APKPure: Large catalog, direct downloads
- F-Droid: Open source apps
- Aptoide: Legacy fallback
"""

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Label, OptionList, ProgressBar, Static
from textual.widgets.option_list import Option
from textual.worker import Worker, WorkerState

from sandroid.tui.modals.base import ExtractionModal, KeyHintFooter
from sandroid.tui.widgets import LoadingSpinner

if TYPE_CHECKING:
    from sandroid.core.apk_sources import APKVersion


@dataclass
class APKInstallResult:
    """Result from APK install modal.

    Attributes:
        cancelled: True if user cancelled
        installed_package: Package name if installation succeeded
        error: Error message if installation failed
    """

    cancelled: bool = True
    installed_package: str | None = None
    error: str | None = None


class APKInstallModal(ExtractionModal[APKInstallResult]):
    """Modal for installing APKs from file or online search.

    Features:
    - Enter file path or search term
    - Per-source search animation with status indicators
    - Download progress bar with MB/percentage
    - Version selection via OptionList when multiple versions found
    - Error display with Retry option
    - Proper centered styling
    """

    # Maps source backend names to (widget_id, display_name)
    _SOURCES = {
        "fdroid": ("source-fdroid", "F-Droid"),
        "apkpure": ("source-apkpure", "APKPure"),
        "aptoide": ("source-aptoide", "Aptoide"),
    }

    BINDINGS = [
        Binding("enter", "submit", "Submit", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    APKInstallModal .modal-container {
        width: 70;
        max-width: 90%;
        max-height: 85%;
    }

    APKInstallModal .modal-container.error-state {
        border: solid $error;
    }

    APKInstallModal .modal-title.error-state {
        color: $error;
    }

    APKInstallModal #apk-input-label {
        color: $foreground;
        height: 1;
        padding-top: 1;
    }

    APKInstallModal #apk-input.error {
        border: solid $error;
    }

    APKInstallModal #apk-input-hint {
        color: $foreground-muted;
        height: 1;
        padding-top: 0;
    }

    APKInstallModal #search-container {
        width: 100%;
        height: auto;
        padding: 1;
        align: center middle;
    }

    APKInstallModal #search-spinner {
        padding: 0;
    }

    APKInstallModal #search-spinner .spinner-message {
        color: $accent;
    }

    APKInstallModal .source-status {
        height: 1;
        padding-left: 2;
        color: $foreground-muted;
    }

    APKInstallModal .source-status.active {
        color: $accent;
    }

    APKInstallModal .source-status.done {
        color: $success;
    }

    APKInstallModal .source-status.error {
        color: $error;
    }

    APKInstallModal #download-progress-container {
        width: 100%;
        height: auto;
        padding: 1;
        align: center middle;
    }

    APKInstallModal #download-label {
        color: $accent;
        text-align: center;
        width: 100%;
        height: 1;
    }

    APKInstallModal #download-progress-bar {
        width: 100%;
        margin: 1 2;
    }

    APKInstallModal #install-phase-label {
        color: $foreground-muted;
        text-align: center;
        width: 100%;
        height: 1;
    }

    APKInstallModal #version-container {
        width: 100%;
        height: auto;
        padding-top: 1;
    }

    APKInstallModal #version-label {
        color: $foreground;
        height: 1;
        text-style: bold;
    }

    APKInstallModal #version-list-container {
        height: 10;
        width: 100%;
        background: $panel;
        border: solid $foreground-muted;
    }

    APKInstallModal #version-list-container:focus-within {
        border: solid $accent;
    }

    APKInstallModal #version-list {
        width: 100%;
        height: 100%;
        background: transparent;
    }

    APKInstallModal #version-list > .option-list--option-highlighted {
        background: $panel-lighten-1;
        color: $accent;
    }

    APKInstallModal #error-container {
        width: 100%;
        height: auto;
        padding: 1;
        margin-top: 1;
        background: $surface;
        border: solid $error;
    }

    APKInstallModal #error-message {
        color: $error;
        text-align: center;
        width: 100%;
    }

    APKInstallModal .hidden {
        display: none;
    }

    APKInstallModal #btn-install {
        background: $success;
        color: #ffffff;
    }

    APKInstallModal #btn-install:hover {
        background: $success-darken-1;
    }

    APKInstallModal #btn-retry {
        background: $primary;
        color: #ffffff;
    }

    APKInstallModal #btn-retry:hover {
        background: $primary-darken-1;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the APK install modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._state = "input"  # input, searching, version_select, installing, error
        self._versions: list[APKVersion] = []
        self._selected_version: APKVersion | None = None
        self._error_message: str = ""
        self._search_term: str = ""

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Install APK", classes="modal-title")

            # Input section
            yield Label("Enter file path or search term:", id="apk-input-label")
            yield Input(
                placeholder="e.g., ~/Downloads/app.apk or firefox",
                id="apk-input",
                classes="no-compact",
            )
            yield Label(
                "[dim]Searches: APKPure, F-Droid, Aptoide[/dim]",
                id="apk-input-hint",
            )

            # Search progress section (hidden by default)
            with Vertical(id="search-container", classes="hidden"):
                yield LoadingSpinner(
                    message="Searching for APKs...", id="search-spinner"
                )
                yield Label("○ F-Droid", id="source-fdroid", classes="source-status")
                yield Label("○ APKPure", id="source-apkpure", classes="source-status")
                yield Label("○ Aptoide", id="source-aptoide", classes="source-status")

            # Download progress section (hidden by default)
            with Vertical(id="download-progress-container", classes="hidden"):
                yield Label("Downloading...", id="download-label")
                yield ProgressBar(id="download-progress-bar", show_eta=False)
                yield Label("", id="install-phase-label")

            # Version selection section (hidden by default)
            with Vertical(id="version-container", classes="hidden"):
                yield Label("Select version to install:", id="version-label")
                with Vertical(id="version-list-container"):
                    yield OptionList(id="version-list")

            # Error section (hidden by default)
            with Vertical(id="error-container", classes="hidden"):
                yield Static("Error message here", id="error-message")

            with Horizontal(classes="button-row"):
                yield Button("Search", id="btn-search", classes="-primary")
                yield Button("Install", id="btn-install", classes="hidden")
                yield Button("Retry", id="btn-retry", classes="hidden")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus input on mount."""
        super().on_mount()
        try:
            self.query_one("#apk-input", Input).focus()
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "btn-cancel":
            self.action_cancel()
        elif button_id == "btn-search":
            self._do_search()
        elif button_id == "btn-install":
            self._do_install()
        elif button_id == "btn-retry":
            self._reset_to_input()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter in input field."""
        if event.input.id == "apk-input" and self._state in ("input", "error"):
            self._do_search()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle version selection from option list."""
        if event.option_list.id == "version-list":
            self._do_install()

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        """Track highlighted version."""
        if event.option_list.id == "version-list" and event.option_index is not None:
            if event.option_index < len(self._versions):
                self._selected_version = self._versions[event.option_index]

    def action_submit(self) -> None:
        """Handle Enter key based on current state."""
        if self._state == "input":
            self._do_search()
        elif self._state == "version_select":
            self._do_install()
        elif self._state == "error":
            # In error state, user can edit and search again directly
            self._do_search()

    def _do_search(self) -> None:
        """Initiate search for APK."""
        try:
            # Clear any error styling from previous attempt
            self._clear_error_styling()

            input_field = self.query_one("#apk-input", Input)
            search_term = input_field.value.strip()

            if not search_term:
                self._show_error("Please enter a file path or search term")
                return

            self._search_term = search_term

            # Check if it's a local file
            expanded_path = os.path.abspath(os.path.expanduser(search_term))
            if os.path.isfile(expanded_path):
                # Local file - install directly
                self._show_install_progress("Installing local APK...")
                self._state = "installing"
                self.run_worker(
                    lambda: self._install_local_apk(expanded_path),
                    name="install_local",
                    exclusive=True,
                    thread=True,
                    exit_on_error=False,  # Handle errors in on_worker_state_changed
                )
            else:
                # Online search
                self._show_search_progress()
                self._state = "searching"
                self.run_worker(
                    lambda: self._search_online(search_term),
                    name="search_online",
                    exclusive=True,
                    thread=True,
                    exit_on_error=False,  # Handle errors in on_worker_state_changed
                )
        except Exception as e:
            self._show_error(str(e))

    def _install_local_apk(self, path: str) -> str:
        """Install APK from local file (runs in worker)."""
        from sandroid.core.adb import Adb

        result = Adb.install_apk(path)
        return result or os.path.basename(path)

    def _search_online(self, search_term: str) -> list["APKVersion"]:
        """Search for APK online across multiple sources (runs in worker)."""
        from sandroid.core.apk_sources import APKSearcher

        def search_progress(source_name: str, status: str) -> None:
            self.app.call_from_thread(self._update_source_status, source_name, status)

        searcher = APKSearcher()
        return searcher.search(
            search_term, limit=15, search_progress_callback=search_progress
        )

    def _install_version(self, version: "APKVersion") -> str:
        """Install specific version (runs in worker)."""
        from sandroid.core.apk_sources import PROGRESS_INSTALL_PHASE, APKSearcher

        last_update = 0.0

        def download_progress(bytes_downloaded: int, total_bytes: int) -> None:
            nonlocal last_update
            # Always forward the install-phase sentinel
            if (bytes_downloaded, total_bytes) == PROGRESS_INSTALL_PHASE:
                self.app.call_from_thread(
                    self._update_download_progress, bytes_downloaded, total_bytes
                )
                return
            # Throttle to max 10 updates/sec to avoid flooding the UI thread
            now = time.monotonic()
            if now - last_update < 0.1 and bytes_downloaded < total_bytes:
                return
            last_update = now
            self.app.call_from_thread(
                self._update_download_progress, bytes_downloaded, total_bytes
            )

        searcher = APKSearcher()
        return searcher.install(version, progress_callback=download_progress)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker completion."""
        if event.state == WorkerState.SUCCESS:
            worker_name = event.worker.name

            if worker_name == "search_online":
                self._show_versions(event.worker.result)

            elif worker_name in ("install_local", "install_version"):
                self._installation_complete(event.worker.result)

        elif event.state == WorkerState.ERROR:
            error = event.worker.error
            if error:
                # Check for specific exception types
                error_msg = str(error)
                if (
                    "APKNotFoundError" in type(error).__name__
                    or "not found" in error_msg.lower()
                ):
                    self._show_error(
                        f"Package not found: {self._search_term}\nTry using the full package name"
                    )
                else:
                    self._show_error(str(error))
            else:
                self._show_error("An unknown error occurred")

    def _set_visibility(self, show: list[str], hide: list[str]) -> None:
        """Show/hide elements by selector."""
        for selector in hide:
            try:
                self.query_one(selector).add_class("hidden")
            except NoMatches:
                pass
        for selector in show:
            try:
                self.query_one(selector).remove_class("hidden")
            except NoMatches:
                pass

    def _show_search_progress(self) -> None:
        """Show search progress with per-source indicators."""
        try:
            self._set_visibility(
                show=["#search-container"],
                hide=[
                    "#apk-input-label",
                    "#apk-input",
                    "#apk-input-hint",
                    "#version-container",
                    "#error-container",
                    "#download-progress-container",
                    "#btn-search",
                    "#btn-install",
                    "#btn-retry",
                ],
            )
            for widget_id, display_name in self._SOURCES.values():
                try:
                    label = self.query_one(f"#{widget_id}", Label)
                    label.remove_class("active", "done", "error")
                    label.update(f"○ {display_name}")
                except Exception:
                    pass
        except Exception:
            pass

    def _show_install_progress(self, message: str) -> None:
        """Show download/install progress bar."""
        try:
            self._set_visibility(
                show=["#download-progress-container"],
                hide=[
                    "#apk-input-label",
                    "#apk-input",
                    "#apk-input-hint",
                    "#search-container",
                    "#version-container",
                    "#error-container",
                    "#btn-search",
                    "#btn-install",
                    "#btn-retry",
                ],
            )
            self.query_one("#download-label", Label).update(message)
            self.query_one("#install-phase-label", Label).update("")
            progress_bar = self.query_one("#download-progress-bar", ProgressBar)
            progress_bar.update(total=100, progress=0)
        except Exception:
            pass

    def _update_source_status(self, source_name: str, status: str) -> None:
        """Update individual source status indicator."""
        source_info = self._SOURCES.get(source_name)
        if not source_info:
            return
        widget_id, display_name = source_info
        try:
            label = self.query_one(f"#{widget_id}", Label)
            label.remove_class("active", "done", "error")
            if status == "searching":
                label.add_class("active")
                label.update(f"● {display_name} searching...")
            elif status == "done":
                label.add_class("done")
                label.update(f"✓ {display_name}")
            elif status in ("not_found", "error"):
                label.add_class("error")
                icon = "✗" if status == "error" else "–"
                label.update(f"{icon} {display_name}")
        except Exception:
            pass

    def _update_download_progress(
        self, bytes_downloaded: int, total_bytes: int
    ) -> None:
        """Update download progress bar and label.

        Called from the main thread via call_from_thread. Throttling is handled
        in the worker-thread closure to avoid unnecessary cross-thread dispatches.
        """
        from sandroid.core.apk_sources import PROGRESS_INSTALL_PHASE

        if (bytes_downloaded, total_bytes) == PROGRESS_INSTALL_PHASE:
            try:
                self.query_one("#download-label", Label).update("Installing via ADB...")
                progress_bar = self.query_one("#download-progress-bar", ProgressBar)
                progress_bar.update(total=None, progress=0)
                self.query_one("#install-phase-label", Label).update("Please wait...")
            except Exception:
                pass
            return

        try:
            downloaded_mb = bytes_downloaded / (1024 * 1024)
            if total_bytes > 0:
                total_mb = total_bytes / (1024 * 1024)
                pct = int(bytes_downloaded * 100 / total_bytes)
                self.query_one("#download-label", Label).update(
                    f"Downloading... {downloaded_mb:.1f} / {total_mb:.1f} MB ({pct}%)"
                )
                progress_bar = self.query_one("#download-progress-bar", ProgressBar)
                progress_bar.update(total=100, progress=pct)
            else:
                self.query_one("#download-label", Label).update(
                    f"Downloading... {downloaded_mb:.1f} MB"
                )
        except Exception:
            pass

    def _show_versions(self, versions: list["APKVersion"]) -> None:
        """Show version selection list - ALWAYS let user choose."""
        self._versions = versions
        self._state = "version_select"

        try:
            self._set_visibility(
                show=["#version-container", "#btn-install"],
                hide=[
                    "#search-container",
                    "#download-progress-container",
                    "#apk-input-label",
                    "#apk-input",
                    "#apk-input-hint",
                    "#error-container",
                    "#btn-search",
                    "#btn-retry",
                ],
            )

            self.query_one("#version-label", Label).update(
                f"Found {len(versions)} result(s) - select to install:"
            )

            option_list = self.query_one("#version-list", OptionList)
            option_list.clear_options()

            for idx, v in enumerate(versions):
                version_str = v.version or "latest"
                option_list.add_option(
                    Option(
                        f"{v.name} [{version_str}] [dim][{v.source}][/dim]",
                        id=str(idx),
                    )
                )

            if versions:
                self._selected_version = versions[0]
                option_list.highlighted = 0

            option_list.focus()

            try:
                self.query_one(KeyHintFooter).set_hint(
                    "list", "[dim]j/k=Navigate  Enter=Install  Esc=Cancel[/dim]"
                )
            except Exception:
                pass
        except Exception as e:
            self._show_error(f"Error displaying versions: {e}")

    def _do_install(self) -> None:
        """Install selected version."""
        if self._state == "version_select" and self._selected_version:
            version = self._selected_version
            self._show_install_progress(f"Downloading {version.name}...")
            self._state = "installing"
            self.run_worker(
                lambda: self._install_version(version),
                name="install_version",
                exclusive=True,
                thread=True,
                exit_on_error=False,  # Handle errors in on_worker_state_changed
            )

    def _clear_error_styling(self) -> None:
        """Clear error styling from previous search attempt."""
        try:
            container = self.query_one(".modal-container", Vertical)
            container.remove_class("error-state")
            self.query_one(".modal-title", Label).remove_class("error-state")
            self.query_one("#apk-input", Input).remove_class("error")
            self.query_one("#error-container", Vertical).add_class("hidden")
        except Exception:
            pass

    def _show_error(self, message: str) -> None:
        """Show error message while keeping input editable."""
        self._state = "error"
        self._error_message = message

        try:
            self._set_visibility(
                show=[
                    "#apk-input-label",
                    "#apk-input",
                    "#error-container",
                    "#btn-search",
                ],
                hide=[
                    "#search-container",
                    "#download-progress-container",
                    "#version-container",
                    "#apk-input-hint",
                    "#btn-install",
                    "#btn-retry",
                ],
            )

            input_field = self.query_one("#apk-input", Input)
            input_field.add_class("error")
            input_field.focus()

            self.query_one("#error-message", Static).update(message)
            self.query_one(".modal-container", Vertical).add_class("error-state")
            self.query_one(".modal-title", Label).add_class("error-state")

            try:
                self.query_one(KeyHintFooter).set_hint(
                    "input", "[dim]Edit and press Enter  Esc=Cancel[/dim]"
                )
            except Exception:
                pass
        except Exception:
            pass

    def _reset_to_input(self) -> None:
        """Reset modal to input state."""
        self._state = "input"
        self._versions = []
        self._selected_version = None
        self._error_message = ""

        try:
            self._set_visibility(
                show=[
                    "#apk-input-label",
                    "#apk-input",
                    "#apk-input-hint",
                    "#btn-search",
                ],
                hide=[
                    "#search-container",
                    "#download-progress-container",
                    "#version-container",
                    "#error-container",
                    "#btn-install",
                    "#btn-retry",
                ],
            )

            self.query_one(".modal-container", Vertical).remove_class("error-state")
            self.query_one(".modal-title", Label).remove_class("error-state")

            input_field = self.query_one("#apk-input", Input)
            input_field.remove_class("error")
            input_field.value = ""
            input_field.focus()
        except Exception:
            pass

    def _installation_complete(self, package_name: str) -> None:
        """Handle successful installation."""
        self._dismiss_with_refresh(
            APKInstallResult(
                cancelled=False,
                installed_package=package_name,
            )
        )
