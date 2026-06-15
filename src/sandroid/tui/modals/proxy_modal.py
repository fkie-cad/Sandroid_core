"""Unified proxy-settings modal for the Sandroid TUI.

One modal with three stacked sections:

- **Device Proxy** — point the whole device at no proxy, Sandroid's own
  mitmproxy, or an external HTTP proxy (Burp/ZAP/remote mitmproxy).
- **App Proxies** — per-app redirectors, each routing one app at our
  mitmproxy (default) or an external HTTP proxy.
- **CA Certificate** — detect/push/inject the interception CA, with Zygote
  injection status.

Device Proxy and App Proxies are applied together via "Apply" (Ctrl+S). The
CA section keeps its own Push / Inject controls. Styled to match the other
forensic modals with keyboard-first navigation.
"""

import threading
from dataclasses import dataclass
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Static,
    TabbedContent,
    TabPane,
)

from sandroid.config import get_config
from sandroid.core.proxy_manager import (
    CAInfo,
    CAManager,
    CASource,
    InjectionStrategy,
    ProxyConfig,
    ProxyManager,
    ProxyStatus,
    ZygoteStatus,
    get_focus_manager,
)
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class ProxyModalResult:
    """Result returned from the :class:`ProxyModal`.

    Attributes:
        cancelled: Whether the dialog was dismissed without applying.
        action: What happened — ``"applied"`` (Device + App proxies applied),
            ``"push_ca"``, ``"inject_ca"``, or ``"close"``.
        proxy_config: The device proxy config that was applied, if any.
        ca_path: The CA path involved in a CA action, if any.
        ca_source: The CA source involved in a CA action, if any.
    """

    cancelled: bool = True
    action: str = "close"
    proxy_config: ProxyConfig | None = None
    ca_path: Path | None = None
    ca_source: CASource | None = None


class ProxyModal(ForensicModal[ProxyModalResult]):
    """Unified modal for Device Proxy, App Proxies, and the CA certificate.

    Features:
    - Device Proxy radio (Off / our mitmproxy / external) with a live
      ground-truth status line probed off the UI thread.
    - App Proxies: dynamic per-app rows, each with a target input (empty =
      our mitmproxy, or an ``http://host:port`` for an external proxy).
    - CA Certificate: detect/push/inject controls and Zygote injection status.
    - Apply (Ctrl+S) commits Device + App proxies together; CA keeps its own
      Push / Inject controls.
    """

    DEFAULT_CSS = """
    ProxyModal .modal-container {
        width: 84;
        height: 90%;
        max-width: 95%;
    }

    /* 1fr (not auto) so the tabs fill the gap between the title and the
       pinned Apply row and SCROLL their overflow internally. .modal-container
       is a fixed 90% height; with auto the content would grow to its full
       height and push the Apply button off the bottom of the clipped
       container — it would vanish entirely (why the old #proxy-body used 1fr,
       and why TabPane here is 1fr, not the `auto` device_settings uses). */
    ProxyModal TabbedContent {
        width: 100%;
        height: 1fr;
    }

    ProxyModal TabPane {
        padding: 1;
        height: 1fr;
    }

    ProxyModal .tab-scroll {
        scrollbar-size: 1 1;
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

    ProxyModal #device-radio-set {
        width: 100%;
        height: auto;
        padding: 0 2;
    }

    ProxyModal #device-ext-row {
        height: auto;
        padding: 0 2;
    }

    ProxyModal #device-ext-row Label {
        width: 10;
        padding-top: 1;
        color: $foreground;
    }

    ProxyModal #device-ext-input {
        width: 1fr;
    }

    ProxyModal #app-proxy-list {
        width: 100%;
        height: auto;
        max-height: 10;
        padding: 0 2;
        scrollbar-size: 1 1;
    }

    ProxyModal .app-proxy-row {
        width: 100%;
        height: auto;
        margin-bottom: 1;
        border: round $panel;
        padding: 0 1;
    }

    ProxyModal .app-proxy-name {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $foreground;
    }

    ProxyModal .app-proxy-controls {
        width: 100%;
        height: auto;
    }

    ProxyModal .app-proxy-target {
        width: 1fr;
    }

    ProxyModal .app-proxy-remove {
        min-width: 10;
        margin-left: 1;
    }

    ProxyModal #app-proxy-empty {
        color: $text-muted;
        padding: 0 2;
    }

    ProxyModal #app-proxy-lanes-line {
        color: $foreground;
        padding: 0 2;
    }

    ProxyModal #app-proxy-note {
        color: $text-muted;
        padding: 0 2;
    }

    ProxyModal .app-proxy-buttons {
        height: auto;
        padding: 0 2;
    }

    ProxyModal .app-proxy-buttons Button {
        margin: 0 1;
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

    ProxyModal .device-info {
        padding: 0 2;
        background: $panel;
    }

    ProxyModal .zygote-status {
        padding: 0 2;
        background: $panel;
    }

    ProxyModal .button-row {
        height: auto;
        padding: 0 2;
        margin-top: 1;
    }

    ProxyModal Button.-primary {
        background: $success;
        color: #ffffff;
    }

    ProxyModal Button.-primary:hover {
        background: $success-darken-1;
    }

    ProxyModal .button-row Button.-style-default.-primary,
    ProxyModal .button-row Button.-style-default.-primary:hover,
    ProxyModal .button-row Button.-style-default.-primary:focus {
        background: $success;
        color: #ffffff;
    }

    ProxyModal .button-row Button.-style-default.-primary:hover {
        background: $success-darken-1;
    }
    """

    BINDINGS = [
        Binding("ctrl+s", "apply", "Apply", show=False),
        Binding("a", "add_app", "Add app", show=False),
        Binding("f", "add_spotlight", "Proxy spotlight app", show=False),
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
        self._pending_ca_path = None
        self._pending_device_config: ProxyConfig | None = None
        # Working state for App Proxies: (package, target_string) where
        # target_string == "" routes the app at our mitmproxy.
        self._app_rows: list[tuple[str, str]] = []
        # Last ground-truth device proxy snapshot from the threaded probe.
        self._device_truth: dict = {"state": "none", "addr": ""}

    # ------------------------------------------------------------------ #
    # Layout                                                             #
    # ------------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Proxy Settings", classes="modal-title")

            with TabbedContent(id="proxy-tabs"):
                # ----- Tab 1: Device Proxy ----- #
                with (
                    TabPane("Device", id="tab-device"),
                    VerticalScroll(classes="tab-scroll"),
                ):
                    yield Static(
                        "Checking…", id="device-status", classes="status-line"
                    )
                    with RadioSet(id="device-radio-set"):
                        yield RadioButton(
                            "Off — no device proxy",
                            value=True,
                            id="device-radio-off",
                        )
                        yield RadioButton(
                            f"Our mitmproxy ({self._mitmweb_addr()})",
                            id="device-radio-ours",
                        )
                        yield RadioButton(
                            "External proxy", id="device-radio-external"
                        )
                    with Horizontal(id="device-ext-row"):
                        yield Label("External:")
                        yield Input(
                            placeholder="host:port",
                            value=self._default_external_addr(),
                            id="device-ext-input",
                        )

                # ----- Tab 2: App Proxies ----- #
                with (
                    TabPane("App Proxies", id="tab-apps"),
                    VerticalScroll(classes="tab-scroll"),
                ):
                    yield VerticalScroll(id="app-proxy-list")
                    yield Static("", id="app-proxy-lanes-line")
                    yield Static(
                        "[dim]Each app proxy = one on-device redirector.[/dim]",
                        id="app-proxy-note",
                    )
                    yield Checkbox(
                        "Block QUIC (UDP 443) — force apps onto interceptable "
                        "TCP/TLS",
                        value=get_config().focus.block_quic,
                        id="block-quic-checkbox",
                    )
                    with Horizontal(classes="app-proxy-buttons"):
                        yield Button(
                            "Add app", id="app-add-btn", classes="-secondary"
                        )
                        yield Button(
                            "Proxy spotlight app",
                            id="app-add-spotlight-btn",
                            classes="-secondary",
                        )

                # ----- Tab 3: CA Certificate ----- #
                with (
                    TabPane("Certificate", id="tab-ca"),
                    VerticalScroll(classes="tab-scroll"),
                ):
                    with VerticalScroll(id="ca-section"):
                        with RadioSet(id="ca-radio-set"):
                            # Populated on mount.
                            pass
                    with Horizontal(id="custom-path-row"):
                        yield Label("Custom:")
                        yield Input(
                            placeholder="Path to custom certificate...",
                            id="custom-path-input",
                        )
                    yield Label("Device Info", classes="section-header")
                    yield Static(
                        "Checking...", id="device-info", classes="device-info"
                    )
                    yield Label("Zygote Injection", classes="section-header")
                    yield Static(
                        "Checking...", id="zygote-status", classes="zygote-status"
                    )
                    with Horizontal(classes="button-row"):
                        yield Button(
                            "Push CA", id="btn-push-ca", classes="-secondary"
                        )
                        yield Button(
                            "Inject CA", id="btn-inject-ca", classes="-secondary"
                        )

            # ----- Global action button ----- #
            with Horizontal(classes="button-row"):
                yield Button("Apply", id="btn-apply", classes="-primary")

            yield KeyHintFooter(
                hints={
                    "default": (
                        "[dim]Ctrl+S=Apply  A=Add app  F=Spotlight  "
                        "P=Push CA  I=Inject CA  Esc=Cancel[/dim]"
                    ),
                    "input": (
                        "[dim]Ctrl+S=Apply  Tab=Next  Esc=Cancel[/dim]"
                    ),
                    "radioset": (
                        "[dim]Ctrl+S=Apply  Space=Select  P=Push CA  "
                        "I=Inject CA  Esc=Cancel[/dim]"
                    ),
                    "button": (
                        "[dim]Enter=Activate  Ctrl+S=Apply  A=Add app  "
                        "F=Spotlight  Tab=Next  Esc=Cancel[/dim]"
                    ),
                }
            )

    def on_mount(self) -> None:
        """Initialize the modal with current status."""
        self._refresh_device_proxy_status()
        self._init_app_rows()
        self._rebuild_app_list()
        self._detect_certificates()
        self._refresh_device_info()
        self._refresh_zygote_status()

        try:
            self.query_one("#device-radio-set", RadioSet).focus()
        except NoMatches:
            pass

    # ------------------------------------------------------------------ #
    # Section 1 — Device Proxy                                           #
    # ------------------------------------------------------------------ #

    def _mitmweb_addr(self) -> str:
        """The ``host_ip:port`` Sandroid's own mitmproxy listens on."""
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        host_ip = ProxyManager.get_host_ip()
        port = get_mitmproxy_service().state.proxy_port
        return f"{host_ip}:{port}"

    def _default_external_addr(self) -> str:
        """A sensible default external address (``host_ip:8080``)."""
        try:
            return f"{ProxyManager.get_host_ip()}:8080"
        except Exception:
            return "127.0.0.1:8080"

    def _refresh_device_proxy_status(self) -> None:
        """Probe the device's current proxy off the UI thread.

        ``capture_view`` reads the device ``http_proxy`` over ADB (blocking),
        so it runs on a daemon thread and marshals the result back with
        ``call_from_thread``.
        """
        status_widget = self.query_one("#device-status", Static)
        status_widget.update("[dim]Checking…[/dim]")

        def worker() -> None:
            try:
                from sandroid.services.mitmproxy_service import (
                    get_mitmproxy_service,
                )

                view = get_mitmproxy_service().capture_view()
            except Exception as exc:  # pragma: no cover - defensive
                self.app.call_from_thread(
                    self._on_device_probe_failed, str(exc)
                )
                return
            self.app.call_from_thread(self._on_device_probe_done, view)

        threading.Thread(target=worker, daemon=True).start()

    def _on_device_probe_failed(self, _exc: str) -> None:
        """Render a fallback when the device proxy probe could not run."""
        try:
            self.query_one("#device-status", Static).update(
                "[yellow]●[/yellow] Device proxy status unavailable"
            )
        except NoMatches:
            pass

    def _on_device_probe_done(self, view: dict) -> None:
        """Render the probed device proxy state and pre-select the radio."""
        device = view.get("device", {}) if isinstance(view, dict) else {}
        state = device.get("state", "none")
        addr = device.get("addr", "")
        self._device_truth = {"state": state, "addr": addr}

        try:
            status_widget = self.query_one("#device-status", Static)
        except NoMatches:
            return

        if state == "ours":
            status_widget.update(
                f"[green]●[/green] Device points at our mitmproxy "
                f"— [bold]{addr}[/bold]"
            )
            self._select_device_radio("device-radio-ours")
        elif state == "external":
            status_widget.update(
                f"[#6ba3ff]●[/] Device points at external proxy "
                f"— [bold]{addr}[/bold]"
            )
            try:
                self.query_one("#device-ext-input", Input).value = addr
            except NoMatches:
                pass
            self._select_device_radio("device-radio-external")
        else:
            status_widget.update(
                "[#5b6479]○[/] No device proxy configured"
            )
            self._select_device_radio("device-radio-off")

    def _select_device_radio(self, radio_id: str) -> None:
        """Pre-select one device-proxy radio button by id."""
        try:
            self.query_one(f"#{radio_id}", RadioButton).value = True
        except NoMatches:
            pass

    def _selected_device_choice(self) -> str:
        """Return the selected device radio: ``off`` / ``ours`` / ``external``."""
        try:
            radio_set = self.query_one("#device-radio-set", RadioSet)
        except NoMatches:
            return "off"
        pressed = radio_set.pressed_button
        if pressed is not None and pressed.id:
            return pressed.id[len("device-radio-") :]
        return "off"

    # ------------------------------------------------------------------ #
    # Section 2 — App Proxies                                            #
    # ------------------------------------------------------------------ #

    def _max_lanes(self) -> int:
        """Lane-pool size (upper bound on app proxies) from service state."""
        try:
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            return max(1, int(get_mitmproxy_service().state.focus_lanes))
        except Exception:
            return 5

    def _init_app_rows(self) -> None:
        """Seed the working app-proxy rows from the live lane assignments.

        Maps ``"ours"`` to an empty target string; any ``http://`` upstream is
        kept verbatim as the row's target.
        """
        try:
            proxies = get_focus_manager().app_proxies()
        except Exception:
            proxies = {}
        rows: list[tuple[str, str]] = []
        for pkg, target in proxies.items():
            rows.append((pkg, "" if target == "ours" else target))
        self._app_rows = rows

    def _rebuild_app_list(self) -> None:
        """Redraw the app-proxy rows and the lanes-used line."""
        try:
            container = self.query_one("#app-proxy-list", VerticalScroll)
        except NoMatches:
            return
        container.remove_children()
        if self._app_rows:
            for idx, (pkg, target) in enumerate(self._app_rows):
                # Stacked "card": the full-width package name on its own line
                # above a controls row (target Input + Remove), so long package
                # names no longer wrap and squeeze the input.
                row = Vertical(classes="app-proxy-row")
                container.mount(row)
                row.mount(Static(pkg, classes="app-proxy-name"))
                controls = Horizontal(classes="app-proxy-controls")
                row.mount(controls)
                controls.mount(
                    Input(
                        value=target,
                        placeholder="mitmproxy (default) — or http://host:port",
                        id=f"app-target-{idx}",
                        classes="app-proxy-target",
                    )
                )
                controls.mount(
                    Button(
                        "Remove",
                        id=f"app-remove-{idx}",
                        classes="-secondary app-proxy-remove",
                    )
                )
        else:
            container.mount(
                Static("[dim]No app proxies yet.[/dim]", id="app-proxy-empty")
            )
        try:
            line = self.query_one("#app-proxy-lanes-line", Static)
            line.update(f"{len(self._app_rows)}/{self._max_lanes()} app proxies")
        except NoMatches:
            pass

    def _sync_app_targets_from_inputs(self) -> None:
        """Pull the current per-app target inputs back into ``_app_rows``."""
        for idx, (pkg, _target) in enumerate(self._app_rows):
            try:
                value = self.query_one(f"#app-target-{idx}", Input).value
            except NoMatches:
                continue
            self._app_rows[idx] = (pkg, value.strip())

    def action_add_app(self) -> None:
        """Push the reused single-select picker to add an app proxy."""
        self._sync_app_targets_from_inputs()
        max_lanes = self._max_lanes()
        if len(self._app_rows) >= max_lanes:
            self.notify(
                f"All {max_lanes} app proxies in use — remove one first.",
                severity="warning",
            )
            return
        try:
            from sandroid.services import (
                get_app_selection_service,
                get_spotlight_service,
            )
            from sandroid.tui.modals.app_selection_modal import AppSelectionModal
        except Exception as exc:  # pragma: no cover - defensive
            self.notify(f"App picker unavailable: {exc}", severity="error")
            return

        app_svc = get_app_selection_service()

        try:
            default_package = get_spotlight_service().get_effective_package()
        except Exception:
            default_package = None

        def load_packages(include_system: bool) -> list:
            return app_svc.get_installed_packages_with_fallback(
                prefer_user_only=not include_system
            )

        def initial_loader(on_status=None) -> list:
            return app_svc.get_installed_packages_with_fallback(
                prefer_user_only=True,
                on_status=on_status,
            )

        self.app.push_screen(
            AppSelectionModal(
                title="Select App to Proxy",
                packages=[],
                default_package=default_package,
                package_loader=load_packages,
                include_system_apps=False,
                initial_loader=initial_loader,
            ),
            self._on_app_selected,
        )

    def _on_app_selected(self, result) -> None:
        """Append the package chosen in the picker (dedup; respect the cap)."""
        if result is None or result.cancelled or not result.package_name:
            return
        self._add_app_row(result.package_name)

    def _add_app_row(self, pkg: str) -> None:
        """Add an app-proxy row for ``pkg`` (dedup; respect the lane cap)."""
        if not pkg:
            return
        if any(p == pkg for p, _ in self._app_rows):
            self.notify(f"{pkg} already has an app proxy.", severity="information")
            return
        max_lanes = self._max_lanes()
        if len(self._app_rows) >= max_lanes:
            self.notify(
                f"All {max_lanes} app proxies in use — remove one first.",
                severity="warning",
            )
            return
        self._app_rows.append((pkg, ""))
        self._rebuild_app_list()

    def action_add_spotlight(self) -> None:
        """Add an app proxy for the spotlight app directly (no picker)."""
        try:
            from sandroid.services import get_spotlight_service

            pkg = get_spotlight_service().get_effective_package()
        except Exception as exc:  # pragma: no cover - defensive
            self.notify(f"Spotlight app unavailable: {exc}", severity="error")
            return
        if not pkg:
            self.notify("No spotlight app set.", severity="warning")
            return
        self._sync_app_targets_from_inputs()
        self._add_app_row(pkg)

    # ------------------------------------------------------------------ #
    # Section 3 — CA Certificate (unchanged behavior)                    #
    # ------------------------------------------------------------------ #

    def _refresh_device_info(self) -> None:
        """Refresh and display device API level and injection strategy."""
        info_widget = self.query_one("#device-info", Static)
        try:
            strategy, api_level = self._ca_manager.determine_injection_strategy()
            strategy_label = (
                "Bind-mount (Android 14+)"
                if strategy == InjectionStrategy.BIND_MOUNT
                else "Legacy (pre-Android 14)"
            )
            api_str = str(api_level) if api_level is not None else "unknown"
            info_widget.update(
                f"API level: [bold]{api_str}[/bold]  "
                f"Strategy: [bold]{strategy_label}[/bold]"
            )
        except Exception:
            info_widget.update("[yellow]●[/yellow] Could not detect device info")

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
                f"[green]●[/green] CA verified in Zygote namespace "
                f"(hash: {self._zygote_status.cert_hash})"
            )
        else:
            pid_info = ""
            if self._zygote_status.zygote64_pid:
                pid_info = f" [dim](zygote64: {self._zygote_status.zygote64_pid})[/dim]"
            elif self._zygote_status.zygote_pid:
                pid_info = f" [dim](zygote: {self._zygote_status.zygote_pid})[/dim]"
            status_widget.update(f"[yellow]●[/yellow] Not injected{pid_info}")

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
        """Confirm Zygote restart, then inject the CA into Zygote."""
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        ca_path = self._get_selected_ca_path()
        self._pending_ca_path = ca_path
        self.app.push_screen(
            ConfirmModal(
                title="Restart Zygote to install CA?",
                message=(
                    "Installing the CA certificate requires restarting Zygote, "
                    "the process every Android app is forked from.\n\n"
                    "All running apps will close and the screen may flicker for "
                    "a few seconds. The device does NOT reboot; it recovers on "
                    "its own.\n\n"
                    "Continue?"
                ),
                yes_label="Restart Zygote",
                no_label="Cancel",
            ),
            self._on_restart_confirm,
        )

    def _on_restart_confirm(self, confirmed: bool) -> None:
        """Handle Zygote restart confirmation result."""
        if not confirmed:
            self.notify(
                "CA injection cancelled — Zygote not restarted",
                severity="warning",
            )
            return
        self._do_inject_ca(self._pending_ca_path)

    def _do_inject_ca(self, ca_path) -> None:
        """Inject the CA into Zygote."""
        result = self._ca_manager.inject_ca_into_zygote(ca_path)
        if result.success:
            self._refresh_zygote_status()
            # Also bypass Chrome Certificate Transparency
            if ca_path and ca_path.exists():
                ct_ok, ct_msg = self._ca_manager.bypass_chrome_ct(ca_path)
                if ct_ok:
                    self.notify(ct_msg, severity="information")
            self._dismiss_with_refresh(
                ProxyModalResult(
                    cancelled=False,
                    action="inject_ca",
                    ca_path=ca_path,
                )
            )
        elif result.needs_root:
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            self.app.push_screen(
                ConfirmModal(
                    title="Enable ADB Root?",
                    message=(
                        "CA injection requires root access.\n"
                        "Enable adb root now?"
                    ),
                ),
                self._on_root_confirm,
            )
        else:
            self.notify(result.message, severity="error")

    def _on_root_confirm(self, confirmed: bool) -> None:
        """Handle root confirmation result."""
        if not confirmed:
            return
        success, msg = self._ca_manager.enable_adb_root()
        if success:
            self.notify("ADB root enabled", severity="information")
            self._do_inject_ca(self._pending_ca_path)
        else:
            self.notify(f"Failed to enable root: {msg}", severity="error")

    # ------------------------------------------------------------------ #
    # Apply (Device Proxy + App Proxies)                                 #
    # ------------------------------------------------------------------ #

    def action_apply(self) -> None:
        """Apply the Device Proxy and App Proxies (CA stays separate).

        Determines the desired device action from the radio, confirms first if
        it would overwrite a foreign device proxy, then runs the device + app
        reconciliation in :meth:`_apply_commit`.
        """
        self._sync_app_targets_from_inputs()
        choice = self._selected_device_choice()

        desired_config: ProxyConfig | None = None
        if choice == "ours":
            desired_config = ProxyConfig.from_string(self._mitmweb_addr())
        elif choice == "external":
            ext = self.query_one("#device-ext-input", Input).value.strip()
            try:
                desired_config = ProxyConfig.from_string(ext)
            except ValueError:
                self.notify(
                    "Invalid external proxy address (use host:port)",
                    severity="error",
                )
                return
        # choice == "off" => desired_config stays None (unset).

        # Confirm before overwriting/clearing a foreign device proxy.
        truth = self._device_truth or {}
        live_state = truth.get("state", "none")
        live_addr = truth.get("addr", "")
        desired_addr = desired_config.address if desired_config else ""
        overwriting_foreign = (
            live_state == "external" and live_addr != desired_addr
        )
        if overwriting_foreign:
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            if desired_config is None:
                msg = (
                    f"The device proxy currently points to {live_addr} — "
                    "clear it?"
                )
            else:
                msg = (
                    f"The device proxy currently points to {live_addr} — "
                    f"switch it to {desired_addr}?"
                )
            self._pending_device_config = desired_config
            self.app.push_screen(
                ConfirmModal(
                    title="Change device proxy?",
                    message=msg,
                    yes_label="Change",
                    no_label="Cancel",
                ),
                self._on_device_overwrite_confirm,
            )
            return

        self._apply_commit(desired_config)

    def _on_device_overwrite_confirm(self, confirmed: bool) -> None:
        """Continue Apply after the foreign-device-proxy confirmation."""
        if not confirmed:
            self.notify(
                "Device proxy left unchanged", severity="warning"
            )
            return
        self._apply_commit(self._pending_device_config)

    def _apply_commit(self, desired_config: ProxyConfig | None) -> None:
        """Apply the device proxy then reconcile the app proxies, then dismiss.

        Synchronous — matches the panel's existing device-setup precedent.
        """
        # 1. Device proxy.
        if desired_config is None:
            ok, message = self._proxy_manager.unset_proxy()
            if ok:
                self._set_glance_device_proxy("")
            else:
                self.notify(message, severity="error")
        else:
            ok, message = self._proxy_manager.set_proxy(desired_config)
            if ok:
                self._set_glance_device_proxy(desired_config.address)
            else:
                self.notify(message, severity="error")

        # 2. App proxies. Read the QUIC-block setting and commit it to the
        #    shared config BEFORE reconciling, so lanes newly enabled by the
        #    reconcile pick it up; then sync any pre-existing lanes.
        try:
            block_quic = self.query_one("#block-quic-checkbox", Checkbox).value
        except NoMatches:
            block_quic = get_config().focus.block_quic
        get_config().focus.block_quic = block_quic
        self._reconcile_app_proxies()
        try:
            get_focus_manager().set_quic_blocking(block_quic)
        except Exception as exc:  # pragma: no cover - defensive
            self.notify(f"QUIC-block sync failed: {exc}", severity="warning")

        self._dismiss_with_refresh(
            ProxyModalResult(
                cancelled=False,
                action="applied",
                proxy_config=desired_config,
            )
        )

    def _reconcile_app_proxies(self) -> None:
        """Diff ``_app_rows`` against the live app proxies and apply deltas."""
        try:
            fm = get_focus_manager()
        except Exception as exc:
            self.notify(f"App proxies unavailable: {exc}", severity="error")
            return

        try:
            live = fm.app_proxies()  # {pkg: "ours" | "http://ip:port"}
        except Exception:
            live = {}
        # Normalize live targets to the working-state convention ("" == ours).
        live_norm = {
            pkg: ("" if target == "ours" else target)
            for pkg, target in live.items()
        }
        desired = dict(self._app_rows)

        results: list[tuple[bool, str]] = []

        # Removed packages.
        for pkg in set(live_norm) - set(desired):
            results.append(fm.disable_focus(pkg))

        # Added or changed packages.
        for pkg, target in desired.items():
            target_arg = None if target == "" else target
            if pkg not in live_norm:
                results.append(fm.enable_focus(pkg, target_arg))
            elif live_norm[pkg] != target:
                fm.disable_focus(pkg)
                results.append(fm.enable_focus(pkg, target_arg))

        if not results:
            return
        failures = [msg for ok, msg in results if not ok]
        if failures:
            summary = "; ".join(failures[:3])
            self.notify(
                f"Some app proxies failed: {summary}", severity="error"
            )
        else:
            self.notify(
                f"App proxies updated ({len(results)} change"
                f"{'s' if len(results) != 1 else ''})",
                severity="information",
            )

    def _set_glance_device_proxy(self, address: str) -> None:
        """Push the just-applied device proxy straight into the glance band.

        We already know the address we set, so write it to the status bar
        directly instead of relying on the post-dismiss ADB re-read that lags
        or races (the glance "Device" line and the mitmproxy tab read the same
        device proxy — they must never disagree). The modal sits on its own
        screen, so reach the status bar on whichever screen below hosts it.
        ``address`` is "ip:port", or "" when cleared. Best-effort.
        """
        for screen in self.app.screen_stack:
            try:
                screen.query_one("#status-bar").set_device_proxy(address)
                return
            except Exception:
                continue

    # ------------------------------------------------------------------ #
    # Buttons / dismiss                                                  #
    # ------------------------------------------------------------------ #

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks (Apply / CA / Add app / per-row Remove)."""
        btn_id = event.button.id or ""
        if btn_id == "btn-apply":
            self.action_apply()
        elif btn_id == "btn-push-ca":
            self.action_push_ca()
        elif btn_id == "btn-inject-ca":
            self.action_inject_ca()
        elif btn_id == "app-add-btn":
            self.action_add_app()
        elif btn_id == "app-add-spotlight-btn":
            self.action_add_spotlight()
        elif btn_id.startswith("app-remove-"):
            try:
                idx = int(btn_id[len("app-remove-") :])
            except ValueError:
                return
            self._sync_app_targets_from_inputs()
            if 0 <= idx < len(self._app_rows):
                self._app_rows.pop(idx)
                self._rebuild_app_list()

    def action_cancel(self) -> None:
        """Cancel and close the modal (sync — required for ESC)."""
        self._dismiss_with_refresh(ProxyModalResult(cancelled=True))
