"""Startup screen shown while Sandroid initializes.

Displays the Sandroid logo with a loading indicator and live status
updates while blocking initialization (ADB checks, root, SELinux)
runs in a background thread.
"""

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.containers import Center, Middle
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Label, Static

from sandroid._version import __version__
from sandroid.core.console import SANDROID_LOGO
from sandroid.tui.widgets import LoadingSpinner

if TYPE_CHECKING:
    from textual.worker import Worker

logger = logging.getLogger(__name__)


class StartupScreen(Screen):
    """Branded startup screen with background initialization.

    Posts :class:`StartupScreen.InitComplete` on success so the host app
    can transition to the main screen without a private-method coupling.
    """

    class InitComplete(Message):
        """Posted when initialization succeeds."""

    DEFAULT_CSS = """
    StartupScreen {
        background: $surface;
    }

    #startup-logo {
        text-align: center;
        color: $success;
        margin-bottom: 1;
    }

    #startup-version {
        text-align: center;
        color: $text-muted;
        margin-bottom: 1;
    }

    .hidden {
        display: none;
    }

    #startup-loading {
        padding: 0;
        margin-bottom: 1;
    }

    #startup-loading LoadingIndicator {
        height: 3;
    }

    #startup-loading .spinner-message {
        color: $primary;
    }

    #startup-error {
        text-align: center;
        color: $error;
        display: none;
        margin: 1 4;
        padding: 1 2;
        border: solid $error;
    }

    #startup-hint {
        text-align: center;
        color: $text-muted;
        display: none;
    }
    """

    status_text: reactive[str] = reactive("Initializing...")
    error_text: reactive[str] = reactive("")

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        self._config = config
        self._init_worker: Worker | None = None

    @property
    def has_error(self) -> bool:
        """Whether initialization has failed (derived from error_text)."""
        return bool(self.error_text)

    def compose(self) -> ComposeResult:
        with Middle(), Center():
            yield Static(SANDROID_LOGO, id="startup-logo")
            yield Label(f"v{__version__}", id="startup-version")
            yield LoadingSpinner(message=self.status_text, id="startup-loading")
            yield Static("", id="startup-error")
            yield Label("", id="startup-hint")

    def on_mount(self) -> None:
        self._start_init_worker()

    def watch_status_text(self, value: str) -> None:
        try:
            self.query_one("#startup-loading", LoadingSpinner).update_message(value)
        except NoMatches:
            pass

    def watch_error_text(self, value: str) -> None:
        if not value:
            return
        try:
            self.query_one("#startup-error", Static).update(value)
            self.query_one("#startup-error", Static).display = True
            self.query_one("#startup-loading", LoadingSpinner).add_class("hidden")
        except NoMatches:
            pass

    def _start_init_worker(self) -> None:
        """Start (or restart) the initialization worker, cancelling any prior one."""
        if self._init_worker is not None and self._init_worker.is_running:
            self._init_worker.cancel()
        self._init_worker = self.run_worker(self._run_initialization, thread=True)

    def _run_initialization(self) -> None:
        """Run blocking initialization in a background thread."""
        try:
            logger.debug("[STARTUP] Beginning core initialization")
            self._update_status("Initializing core...")
            from sandroid.core.initializer import initialize_core

            initialize_core(self._config)
            logger.debug("[STARTUP] Core initialization complete")

            self._update_status("Checking ADB...")
            logger.debug("[STARTUP] Running critical setup checks")
            from sandroid.services import get_setup_service

            result = get_setup_service().check_critical_setup()
            logger.debug(f"[STARTUP] Setup checks done, success={result.success}")

            if result.success:
                self._update_status("Ready!")
                logger.debug(
                    "[STARTUP] Scheduling _finish_startup via call_from_thread"
                )
                # call_from_thread is thread-safe (uses loop.call_soon_threadsafe).
                # call_later uses post_message which is NOT safe from worker threads.
                self.app.call_from_thread(self._finish_startup)
                logger.debug("[STARTUP] _finish_startup scheduled")
            else:
                error_msg = result.message or "Setup failed"
                details = "\n".join(f"  - {e}" for e in result.errors)
                if details:
                    error_msg = f"{error_msg}\n{details}"
                logger.error(f"[STARTUP] Setup failed: {error_msg}")
                self.app.call_from_thread(self._show_error, error_msg)
        except Exception as e:
            logger.exception(f"[STARTUP] Initialization failed: {e}")
            try:
                self.app.call_from_thread(self._show_error, str(e))
            except Exception:
                logger.error(f"[STARTUP] Could not show error UI: {e}")

    def _update_status(self, msg: str) -> None:
        try:
            self.app.call_from_thread(setattr, self, "status_text", msg)
        except Exception:
            logger.debug(f"[STARTUP] Could not update status to: {msg}")

    def _finish_startup(self) -> None:
        """Signal the host app that initialization is complete."""
        logger.debug(
            "[STARTUP] _finish_startup called, deferring InitComplete via set_timer"
        )
        self.set_timer(0.01, self._post_init_complete)
        logger.debug("[STARTUP] _finish_startup: set_timer scheduled, returning")

    def _post_init_complete(self) -> None:
        """Post InitComplete message (runs from timer, outside call_from_thread)."""
        logger.debug("[STARTUP] _post_init_complete: posting InitComplete")
        self.post_message(self.InitComplete())
        logger.debug("[STARTUP] _post_init_complete: InitComplete posted")

    def _show_error(self, error_msg: str) -> None:
        """Show error state with retry/quit hints."""
        self.status_text = "Initialization failed"
        self.error_text = error_msg
        try:
            hint = self.query_one("#startup-hint", Label)
            hint.update(
                "Press [bold]R[/bold] to retry  |  Press [bold]Q[/bold] to quit"
            )
            hint.display = True
        except NoMatches:
            pass

    def key_r(self) -> None:
        """Retry initialization."""
        if not self.has_error:
            return
        self.error_text = ""
        try:
            self.query_one("#startup-error", Static).display = False
            self.query_one("#startup-hint", Label).display = False
            self.query_one("#startup-loading", LoadingSpinner).remove_class("hidden")
        except NoMatches:
            pass
        self.status_text = "Retrying..."
        self._start_init_worker()

    def key_q(self) -> None:
        """Quit on error."""
        if self.has_error:
            self.app.exit()

    def on_unmount(self) -> None:
        """Cancel background worker when screen is removed."""
        if self._init_worker is not None and self._init_worker.is_running:
            self._init_worker.cancel()
            self._init_worker = None
