"""Proxy configuration modal for Sandroid TUI.

Provides a modal dialog for:
- Setting/unsetting HTTP proxy
- Managing CA certificates for SSL interception
- Zygote CA injection status and controls

Styled to match ObjectionModal with keyboard-only navigation.
"""

from dataclasses import dataclass
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Input, Label, RadioButton, RadioSet, Static

from sandroid.core.proxy_manager import (
    CAInfo,
    CAManager,
    CASource,
    ProxyConfig,
    ProxyManager,
    ProxyStatus,
    ZygoteStatus,
)
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class ProxyModalResult:
    """Result returned from the ProxyModal."""

    cancelled: bool = True
    action: str = "close"  # "set_proxy", "unset_proxy", "push_ca", "inject_ca"
    proxy_config: ProxyConfig | None = None
    ca_path: Path | None = None
    ca_source: CASource | None = None


class ProxyModal(ForensicModal[ProxyModalResult]):
    """Modal for configuring proxy and CA certificates.

    Features:
    - Current proxy status display
    - IP:PORT input with default (host IP:8080)
    - Auto-detect CA certs (mitmproxy, http-toolkit, burp suite)
    - Radio buttons for CA selection + custom path option
    - Zygote injection status
    - Keyboard shortcuts for all actions (no buttons)
    """

    DEFAULT_CSS = """
    ProxyModal .modal-container {
        width: 80;
        max-height: 28;
        max-width: 90%;
    }

    ProxyModal .section-header {
        color: #6ba3ff;
        text-style: bold;
        height: 1;
        margin-top: 1;
    }

    ProxyModal .status-line {
        padding: 0 2;
        background: $panel;
    }

    ProxyModal #proxy-input-row {
        height: auto;
        padding: 0 2;
    }

    ProxyModal #proxy-input-row Label {
        width: 10;
        padding-top: 1;
        color: $foreground;
    }

    ProxyModal #proxy-input {
        width: 1fr;
    }

    ProxyModal #ca-section {
        height: auto;
        max-height: 8;
        padding: 0 2;
        margin: 0;
        scrollbar-size: 0 0;
    }

    ProxyModal #ca-radio-set {
        padding: 0;
    }

    ProxyModal #custom-path-row {
        height: auto;
        padding: 0 2;
    }

    ProxyModal #custom-path-row Label {
        width: 10;
        padding-top: 1;
        color: $foreground;
    }

    ProxyModal #custom-path-input {
        width: 1fr;
    }

    ProxyModal .zygote-status {
        padding: 0 2;
        background: $panel;
    }
    """

    BINDINGS = [
        Binding("s", "set_proxy", "Set Proxy", show=False),
        Binding("u", "unset_proxy", "Unset Proxy", show=False),
        Binding("p", "push_ca", "Push CA", show=False),
        Binding("i", "inject_ca", "Inject CA", show=False),
    ]

    proxy_status = reactive(ProxyStatus.NOT_SET)
    current_proxy = reactive(None)

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        super().__init__(name=name, id=id, classes=classes)
        self._proxy_manager = ProxyManager()
        self._ca_manager = CAManager()
        self._detected_cas: list[CAInfo] = []
        self._zygote_status: ZygoteStatus | None = None

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Proxy & CA Configuration", classes="modal-title")

            # Proxy Status Section
            yield Label("Proxy Status", classes="section-header")
            yield Static("Checking...", id="proxy-status", classes="status-line")

            # Proxy Input Section
            yield Label("Proxy Settings", classes="section-header")
            with Horizontal(id="proxy-input-row"):
                yield Label("Address:")
                default = self._proxy_manager.get_default_config()
                yield Input(
                    placeholder=f"{default.ip}:{default.port}",
                    value=f"{default.ip}:{default.port}",
                    id="proxy-input",
                )

            # CA Certificate Section
            yield Label("CA Certificate", classes="section-header")
            with VerticalScroll(id="ca-section"):
                with RadioSet(id="ca-radio-set"):
                    # Will be populated on mount
                    pass

            # Custom Path Input
            with Horizontal(id="custom-path-row"):
                yield Label("Custom:")
                yield Input(
                    placeholder="Path to custom certificate...",
                    id="custom-path-input",
                )

            # Zygote Injection Section
            yield Label("Zygote Injection", classes="section-header")
            yield Static("Checking...", id="zygote-status", classes="zygote-status")

            # Dynamic key hints via footer
            yield KeyHintFooter(
                hints={
                    "default": "[dim]S=Set Proxy  U=Unset  P=Push CA  I=Inject CA  Esc=Cancel[/dim]",
                    "input": "[dim]S=Set Proxy  U=Unset  P=Push CA  I=Inject CA  Tab=Next  Esc=Cancel[/dim]",
                    "radioset": "[dim]S=Set Proxy  U=Unset  P=Push CA  I=Inject CA  Space=Select  Esc=Cancel[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Initialize the modal with current status."""
        self._refresh_proxy_status()
        self._detect_certificates()
        self._refresh_zygote_status()

        # Focus proxy input
        proxy_input = self.query_one("#proxy-input", Input)
        proxy_input.focus()

    def _refresh_proxy_status(self) -> None:
        """Refresh and display current proxy status."""
        status, config = self._proxy_manager.get_proxy_settings()
        self.proxy_status = status
        self.current_proxy = config

        status_widget = self.query_one("#proxy-status", Static)
        if status == ProxyStatus.SET and config:
            status_widget.update(
                f"[green]\u25cf[/green] Proxy set to: [bold]{config.address}[/bold]"
            )

            # Update input with current value
            proxy_input = self.query_one("#proxy-input", Input)
            proxy_input.value = config.address
        elif status == ProxyStatus.NOT_SET:
            status_widget.update("[red]\u25cf[/red] Proxy not configured")
        else:
            status_widget.update("[yellow]\u25cf[/yellow] Error reading proxy status")

    def _detect_certificates(self) -> None:
        """Detect available CA certificates and populate radio buttons."""
        self._detected_cas = self._ca_manager.detect_ca_certificates()

        radio_set = self.query_one("#ca-radio-set", RadioSet)

        # Clear existing options
        radio_set.remove_children()

        if self._detected_cas:
            for idx, ca_info in enumerate(self._detected_cas):
                radio_set.mount(
                    RadioButton(
                        f"{ca_info.display_name} ({ca_info.path.name})",
                        id=f"ca-radio-{idx}",
                    )
                )
            # Add custom option
            radio_set.mount(RadioButton("Custom path...", id="ca-radio-custom"))
        else:
            radio_set.mount(
                RadioButton(
                    "No CA certificates detected", id="ca-radio-none", disabled=True
                )
            )
            radio_set.mount(RadioButton("Custom path...", id="ca-radio-custom"))

    def _refresh_zygote_status(self) -> None:
        """Refresh and display Zygote injection status."""
        self._zygote_status = self._ca_manager.check_zygote_injection_status()
        status_widget = self.query_one("#zygote-status", Static)

        if self._zygote_status.injected:
            status_widget.update(
                f"[green]\u25cf[/green] CA injected (hash: {self._zygote_status.cert_hash})"
            )
        else:
            pid_info = ""
            if self._zygote_status.zygote64_pid:
                pid_info = f" [dim](zygote64: {self._zygote_status.zygote64_pid})[/dim]"
            elif self._zygote_status.zygote_pid:
                pid_info = f" [dim](zygote: {self._zygote_status.zygote_pid})[/dim]"
            status_widget.update(f"[yellow]\u25cf[/yellow] Not injected{pid_info}")

    def _get_selected_ca_path(self) -> Path | None:
        """Get the currently selected CA certificate path."""
        # Check if custom is selected
        try:
            custom_radio = self.query_one("#ca-radio-custom", RadioButton)
            if custom_radio.value:
                custom_input = self.query_one("#custom-path-input", Input)
                if custom_input.value:
                    return Path(custom_input.value)
                return None
        except Exception:
            pass

        # Check detected CAs
        for idx, ca_info in enumerate(self._detected_cas):
            try:
                radio = self.query_one(f"#ca-radio-{idx}", RadioButton)
                if radio.value:
                    return ca_info.path
            except Exception:
                continue

        return None

    def _get_proxy_config(self) -> ProxyConfig | None:
        """Get the proxy configuration from input."""
        proxy_input = self.query_one("#proxy-input", Input)
        try:
            return ProxyConfig.from_string(proxy_input.value)
        except ValueError:
            return None

    def action_set_proxy(self) -> None:
        """Set the proxy with current configuration."""
        config = self._get_proxy_config()
        if config:
            success, message = self._proxy_manager.set_proxy(config)
            if success:
                self._refresh_proxy_status()
                self._dismiss_with_refresh(
                    ProxyModalResult(
                        cancelled=False,
                        action="set_proxy",
                        proxy_config=config,
                    )
                )
            else:
                self.notify(message, severity="error")
        else:
            self.notify("Invalid proxy address format", severity="error")

    def action_unset_proxy(self) -> None:
        """Unset/remove the current proxy."""
        success, message = self._proxy_manager.unset_proxy()
        if success:
            self._refresh_proxy_status()
            self._dismiss_with_refresh(
                ProxyModalResult(
                    cancelled=False,
                    action="unset_proxy",
                )
            )
        else:
            self.notify(message, severity="error")

    def action_push_ca(self) -> None:
        """Push the selected CA certificate to the device."""
        ca_path = self._get_selected_ca_path()
        if ca_path and ca_path.exists():
            success, message = self._ca_manager.push_cert_to_device(ca_path)
            if success:
                self._refresh_zygote_status()
                self.notify(message, severity="information")
            else:
                self.notify(message, severity="error")
        else:
            self.notify("Please select a valid CA certificate", severity="warning")

    def action_inject_ca(self) -> None:
        """Inject the CA into Zygote."""
        ca_path = self._get_selected_ca_path()
        success, message = self._ca_manager.inject_ca_into_zygote(ca_path)
        if success:
            self._refresh_zygote_status()
            self._dismiss_with_refresh(
                ProxyModalResult(
                    cancelled=False,
                    action="inject_ca",
                    ca_path=ca_path,
                )
            )
        else:
            self.notify(message, severity="error")

    def action_cancel(self) -> None:
        """Cancel and close the modal."""
        self._dismiss_with_refresh(ProxyModalResult(cancelled=True))
