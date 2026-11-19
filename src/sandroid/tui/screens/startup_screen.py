"""Startup screen shown while Sandroid initializes.

Displays the Sandroid logo with a loading indicator and live status
updates while blocking initialization (ADB checks, root, SELinux)
runs in a background thread.

While it is up the screen owns the keyboard: ``SandroidTUI.check_action``
refuses every app-level action (Record, Play, lenses, ...), so only the keys
below work. On a failed start: ``r`` retries, ``d`` opens the Devices screen
(attach, start or stop a device, e.g. after ``--serial`` named a missing
one), ``q`` quits with :data:`EXIT_STARTUP_FAILED`. Upper-case works too.

The Devices screen (:class:`~sandroid.tui.screens.devices_screen.DevicesScreen`
in ``startup`` mode) opens by itself when the device is the problem:

* several online devices and no ``--serial`` / ``$ANDROID_SERIAL`` /
  ``emulator.serial`` -- ``initialize_core`` refuses to guess
  (:class:`~sandroid.core.exceptions.MultipleDevicesError`) before any device
  work;
* adb works but no usable device is connected (none, or the requested one
  is missing / unauthorized).

The device it closes with is pinned like ``--serial`` and the start retried
(an AVD started there is taken once it has booted). Esc leaves the error
screen with its keys.
"""

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
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

#: Process exit code after quitting from the startup error screen.
EXIT_STARTUP_FAILED = 2
#: Process exit code after aborting (Ctrl+C) while startup is still running.
EXIT_STARTUP_ABORTED = 130

#: The error shown when the user quit from the error screen (for the CLI to
#: repeat on the terminal once the TUI is gone); None otherwise.
_startup_failure: str | None = None


def startup_failure() -> str | None:
    """The startup error the user quit on, or None (see ``EXIT_STARTUP_FAILED``)."""
    return _startup_failure


class StartupScreen(Screen):
    """Branded startup screen with background initialization.

    Posts :class:`StartupScreen.InitComplete` on success so the host app
    can transition to the main screen without a private-method coupling.
    """

    class InitComplete(Message):
        """Posted when initialization succeeds."""

    # Screen bindings come before the App's in the binding chain, so these
    # keys never reach the global ones (r = Record, ...); every other
    # app-level action is refused by ``SandroidTUI.check_action`` while this
    # screen is in the stack.
    BINDINGS = [
        Binding("r", "retry", "Retry", show=False),
        Binding("R", "retry", "Retry", show=False),
        Binding("d", "devices", "Devices", show=False),
        Binding("D", "devices", "Devices", show=False),
        Binding("q", "quit_startup", "Quit", show=False),
        Binding("Q", "quit_startup", "Quit", show=False),
        Binding("ctrl+c", "abort", "Quit", show=False),
        Binding("ctrl+q", "abort", "Quit", show=False),
    ]

    DEFAULT_CSS = """
    StartupScreen {
        background: $surface;
    }

    #startup-logo {
        text-align: left;
        content-align-horizontal: center;
        color: $success;
        margin-bottom: 1;
    }

    #startup-version {
        width: 100%;
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
        width: 100%;
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
        #: Shown at the top of the Devices screen (why it opened).
        self._devices_reason = ""

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
        from sandroid.core.exceptions import MultipleDevicesError

        try:
            logger.debug("[STARTUP] Beginning core initialization")
            self._update_status("Initializing core...")
            from sandroid.core.initializer import initialize_core

            try:
                initialize_core(self._config)
            except MultipleDevicesError as e:
                # Several devices and no --serial: ask before anything (adb
                # root, setenforce, frida-server) touches one of them.
                logger.info(f"[STARTUP] {e}")
                self.app.call_from_thread(self._ask_for_device, e.serials)
                return
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
                # adb works but the device does not: open the Devices screen.
                device_problem = bool(
                    getattr(result, "adb_available", False)
                    and not getattr(result, "device_connected", False)
                )
                if device_problem:
                    self.app.call_from_thread(self._device_error, error_msg)
                else:
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

    def _show_error(self, error_msg: str, device_problem: bool = False) -> None:
        """Show error state with retry/quit (and Devices) hints."""
        self.status_text = "Initialization failed"
        self.error_text = error_msg
        self._devices_reason = error_msg.splitlines()[0] if error_msg else ""
        try:
            hint = self.query_one("#startup-hint", Label)
            keys = ["[bold]r[/bold] retry"]
            if device_problem:
                keys.append("[bold]d[/bold] devices")
            keys.append("[bold]q[/bold] quit")
            hint.update("Press " + "  ·  ".join(keys))
            hint.display = True
        except NoMatches:
            pass

    def _device_error(self, error_msg: str) -> None:
        """No usable device: show the error, then open the Devices screen.

        Cancelling the Devices screen (Esc) leaves the error state with ``d``
        (Devices again), ``r`` (retry) and ``q`` (quit).
        """
        self._show_error(error_msg, device_problem=True)
        self.action_devices()

    def _ask_for_device(self, serials: list[str]) -> None:
        """Several devices are online and none is pinned: open Devices.

        Nothing has been done to any device yet (no adb root, setenforce or
        frida-server).
        """
        self._device_error(
            f"More than one device is connected ({', '.join(serials)}).\n"
            "Choose the device for this session (or start with --serial)."
        )
        self.status_text = "Choose a device"

    def action_retry(self) -> None:
        """Retry initialization (``r`` / ``R``)."""
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

    def action_quit_startup(self) -> None:
        """Quit after a failed start (``q`` / ``Q``) with a non-zero exit code."""
        if self.has_error:
            self._exit(EXIT_STARTUP_FAILED)

    def action_abort(self) -> None:
        """Ctrl+C / Ctrl+Q: quit now, also while initialization still runs."""
        self._exit(EXIT_STARTUP_FAILED if self.has_error else EXIT_STARTUP_ABORTED)

    def _exit(self, return_code: int) -> None:
        global _startup_failure
        _startup_failure = self.error_text or None
        self.app.exit(return_code=return_code)

    # -- Devices screen (d) -------------------------------------------------

    def action_devices(self) -> None:
        """Open the Devices screen after a failed start (``d`` / ``D``).

        The device it closes with is pinned for this session (like
        ``--serial``) and the start retried; Esc returns here.
        """
        from sandroid.tui.screens.devices_screen import DevicesScreen

        if not self.has_error or not self.is_attached:
            return
        if any(isinstance(s, DevicesScreen) for s in self.app.screen_stack):
            return
        self.app.push_screen(
            DevicesScreen(mode="startup", reason=self._devices_reason),
            self._on_devices_closed,
        )

    def _on_devices_closed(self, serial: str | None) -> None:
        if serial and self.is_attached:
            self.use_device(serial)

    def use_device(self, serial: str) -> None:
        """Pin ``serial`` for this session (like ``--serial``) and retry."""
        from sandroid.core.initializer import apply_serial_selection

        emulator_cfg = getattr(self._config, "emulator", None)
        if emulator_cfg is not None:
            try:
                emulator_cfg.serial = serial  # retry re-applies the config serial
            except Exception:
                logger.debug("[STARTUP] could not set emulator.serial", exc_info=True)
        apply_serial_selection(serial)
        self.app.notify(f"Using device {serial}", timeout=3)
        self.action_retry()

    def on_unmount(self) -> None:
        """Cancel background worker when screen is removed."""
        if self._init_worker is not None and self._init_worker.is_running:
            self._init_worker.cancel()
            self._init_worker = None
