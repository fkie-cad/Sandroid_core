"""Frida server installation confirmation modal."""

import logging
from collections.abc import Callable
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, Static

from sandroid.tui.modals.base import FridaModal, KeyHintFooter

logger = logging.getLogger(__name__)


def _frida_server_running() -> bool:
    """True if frida-server is up on the active device (best-effort)."""
    try:
        from sandroid.services import get_frida_session_service

        fm = get_frida_session_service().get_frida_manager()
        return bool(fm and fm.is_frida_server_running())
    except Exception:
        return False


def _active_device_name() -> str:
    """Display name of the active device, or ``"device"`` as a fallback."""
    try:
        from sandroid.core.toolbox import Toolbox

        dm = Toolbox.get_device_manager()
        if dm and dm.active_device:
            return dm.active_device.display_name
    except Exception:
        pass
    return "device"


def ensure_frida_running(
    app,
    feature_name: str,
    on_ready: Callable[[], None],
    on_cancel: Callable[[], None] | None = None,
) -> None:
    """Run ``on_ready`` once frida-server is confirmed running on the device.

    If frida-server is already up, ``on_ready`` is called immediately. Otherwise
    a :class:`FridaInstallModal` is shown; on confirm the server is installed and
    started on a worker thread, then ``on_ready`` is marshalled back to the UI
    thread. On cancel or install failure ``on_cancel`` (if given) is called so
    the caller can clear any inflight/pending message.

    This is the shared gate that keeps the cryptic frida-core "need Gadget to
    attach on jailed Android" error from surfacing on the SSL-unpin entry points
    (Ctrl+P, panel-focused) when frida-server is down. It works both from the
    App (pass ``self``) and from a widget (pass ``self.app``); ``app`` only needs
    ``push_screen``, ``run_worker``, ``call_from_thread``, and ``notify``.
    Mirrors ``SpotlightPanel._install_frida_then`` semantics.
    """
    if _frida_server_running():
        on_ready()
        return

    def _cancel() -> None:
        if on_cancel is not None:
            on_cancel()

    def on_result(result: "FridaInstallResult | None") -> None:
        if not result or not result.install:
            _cancel()
            return
        _install_frida_then(app, on_ready, _cancel)

    app.push_screen(
        FridaInstallModal(
            device_name=_active_device_name(), feature_name=feature_name
        ),
        on_result,
    )


def _install_frida_then(
    app,
    on_ready: Callable[[], None],
    on_cancel: Callable[[], None],
) -> None:
    """Install + start frida-server on a worker, then run ``on_ready``.

    ``app.notify`` is thread-safe; the ``on_ready``/``on_cancel`` callbacks may
    touch widgets, so they are marshalled to the UI thread via
    ``call_from_thread``.
    """
    try:
        app.notify("Installing & starting frida-server…", severity="information")
    except Exception:
        pass

    def _job() -> None:
        ok = False
        try:
            from sandroid.services import get_frida_session_service

            svc = get_frida_session_service()
            fm = svc.get_frida_manager()
            if fm is None:
                raise RuntimeError("Frida manager unavailable")
            fm.install_frida_server()
            # run_frida_server blocks until the frida client can reach the
            # server, so ok reflects real readiness (not just that a process
            # exists) — the gated action won't race it.
            ok = bool(fm.run_frida_server())
            if ok:
                # Drop any frida device handle cached while the server was down
                # so the next attach resolves a fresh, ready device.
                try:
                    svc.invalidate_frida_device_cache()
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Frida install/start failed: %s", exc)
            try:
                app.notify(f"Frida install failed: {exc}", severity="error")
            except Exception:
                pass

        if ok:
            try:
                app.notify("frida-server started.", severity="information")
            except Exception:
                pass
            try:
                app.call_from_thread(on_ready)
            except Exception:
                pass
        else:
            try:
                app.notify("frida-server still not running.", severity="error")
            except Exception:
                pass
            try:
                app.call_from_thread(on_cancel)
            except Exception:
                pass

    app.run_worker(_job, name="ensure_frida_running", thread=True)


@dataclass
class FridaInstallResult:
    """Result from Frida installation confirmation."""

    install: bool  # True to install, False to cancel
    device_name: str  # Name of the target device


class FridaInstallModal(FridaModal[FridaInstallResult]):
    """Modal for confirming Frida server installation.

    Shows a warning-styled overlay asking if the user wants to install
    Frida server on the target device.

    Returns FridaInstallResult with install=True/False.
    """

    DEFAULT_CSS = """
    FridaInstallModal .modal-container {
        border: solid $success;
        width: 55;
        max-width: 80%;
        max-height: 50%;
    }

    FridaInstallModal .modal-title {
        color: $success;
    }

    FridaInstallModal .modal-message {
        margin-bottom: 1;
    }

    FridaInstallModal #frida-device {
        color: $accent;
        text-align: center;
        margin-bottom: 1;
    }

    FridaInstallModal #frida-note {
        color: $text-muted;
        text-align: center;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "install", "Install", show=False, priority=True),
        Binding("y", "install", "Yes", show=False, priority=True),
        Binding("n", "cancel", "No", show=False, priority=True),
        Binding("f", "install", "Install Frida", show=False, priority=True),
    ]

    AUTO_FOCUS = "#btn-install"

    def __init__(
        self,
        device_name: str = "device",
        feature_name: str = "this feature",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the Frida installation modal.

        Args:
            device_name: Display name of the target device
            feature_name: Name of the feature that requires Frida
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.device_name = device_name
        self.feature_name = feature_name

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Frida Server Required", classes="modal-title")
            yield Label(
                f"{self.feature_name} requires Frida server to be running.",
                classes="modal-message",
            )
            yield Label(
                f"Target: [bold]{self.device_name}[/bold]",
                id="frida-device",
            )
            yield Static(
                "[dim]This will download and install frida-server on the device.[/dim]",
                id="frida-note",
            )

            with Horizontal(classes="button-row"):
                yield Button("Install & Start", id="btn-install", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Enter/Y/F=Install  Esc/N=Cancel[/dim]",
                    "button": "[dim]Enter/Y/F=Install  Esc/N=Cancel[/dim]",
                }
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-install":
            self._install()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_install(self) -> None:
        """Install Frida server."""
        self._install()

    def _install(self) -> None:
        """Confirm installation and dismiss."""
        self._dismiss_with_refresh(
            FridaInstallResult(install=True, device_name=self.device_name)
        )

    def action_cancel(self) -> None:
        """Cancel and dismiss."""
        self._dismiss_with_refresh(
            FridaInstallResult(install=False, device_name=self.device_name)
        )
