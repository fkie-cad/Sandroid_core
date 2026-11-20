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
import time
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
    Tabs,
)

from sandroid.config import get_config
from sandroid.core.adb import Adb
from sandroid.core.proxy_manager import (
    CA_RUNNING_APPS_NOTE,
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


class _ProxyInput(Input):
    """Text field of the Proxy dialog: Shift+Left/Right switch the dialog's
    tabs while the field is empty, else they select text (Textual's Input
    default), like the lens inputs (``files_panel._LensInput``).
    """

    BINDINGS = [
        Binding("shift+left", "nav_or_select(-1)", show=False),
        Binding("shift+right", "nav_or_select(1)", show=False),
    ]

    def action_nav_or_select(self, delta: int) -> None:
        if self.value:
            if delta < 0:
                self.action_cursor_left(select=True)
            else:
                self.action_cursor_right(select=True)
            return
        cycle = getattr(self.screen, "action_cycle_tab", None)
        if cycle is not None:
            cycle(delta)


#: The dialog's single-letter keys, shown in every hint line (either case).
_LETTER_HINTS = "A=Add app  F=Spotlight  P=Push CA  I=Inject CA  R=Remove CA"


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

    #: Letter keys work in both cases: the hints show them upper-case (R
    #: = Remove CA), and Shift+R used to do nothing. Shift+Left/Right cycle
    #: the tabs (the project's Shift+Arrow level navigation); a focused
    #: non-empty text field keeps them for selecting text (``_ProxyInput``).
    BINDINGS = [
        Binding("ctrl+s", "apply", "Apply", show=False),
        Binding("a,A", "add_app", "Add app", show=False),
        Binding("f,F", "add_spotlight", "Proxy spotlight app", show=False),
        Binding("p,P", "push_ca", "Push CA", show=False),
        Binding("i,I", "inject_ca", "Inject CA", show=False),
        Binding("r,R", "remove_ca", "Remove CA", show=False),
        Binding("shift+left", "cycle_tab(-1)", "Previous tab", show=False),
        Binding("shift+right", "cycle_tab(1)", "Next tab", show=False),
    ]

    #: Focus the Device radio set on open: the base modal would focus the
    #: first Input (the external-proxy field), which then swallowed the
    #: modal's single-letter keys (I, P, R).
    AUTO_FOCUS = "#device-radio-set"

    proxy_status = reactive(ProxyStatus.NOT_SET)
    current_proxy = reactive(None)

    #: A bare Enter is not an Apply this soon after the dialog opened
    #: (typed-ahead keys) -- nor while stray typing has just closed another
    #: dialog: the device's proxy must not change from a stray key.
    ENTER_ARM_SECONDS = 0.6

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        super().__init__(name=name, id=id, classes=classes)
        self._opened_at = time.monotonic()
        self._proxy_manager = ProxyManager()
        self._ca_manager = CAManager()
        self._detected_cas: list[CAInfo] = []
        self._zygote_status: ZygoteStatus | None = None
        self._pending_ca_path = None
        #: A CA install/removal worker is running.
        self._ca_busy = False
        self._pending_device_config: ProxyConfig | None = None
        self._pending_via_reverse: bool = False
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
                    yield Static("Checking…", id="device-status", classes="status-line")
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
                        yield RadioButton("External proxy", id="device-radio-external")
                        yield RadioButton(
                            "Our mitmproxy via adb reverse (127.0.0.1)",
                            id="device-radio-reverse",
                        )
                        yield Static(
                            "[dim]reach the host through adbd — for physical "
                            "devices or when the host IP isn't directly "
                            "reachable.[/dim]",
                            id="device-reverse-caption",
                        )
                    with Horizontal(id="device-ext-row"):
                        yield Label("External:")
                        yield _ProxyInput(
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
                        "Block QUIC (UDP 443) — force apps onto interceptable TCP/TLS",
                        value=get_config().focus.block_quic,
                        id="block-quic-checkbox",
                    )
                    with Horizontal(classes="app-proxy-buttons"):
                        yield Button("Add app", id="app-add-btn", classes="-secondary")
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
                        yield _ProxyInput(
                            placeholder="Path to custom certificate...",
                            id="custom-path-input",
                        )
                    yield Label("Device Info", classes="section-header")
                    yield Static("Checking...", id="device-info", classes="device-info")
                    yield Label("System trust store", classes="section-header")
                    yield Static(
                        "Checking...", id="zygote-status", classes="zygote-status"
                    )
                    with Horizontal(classes="button-row"):
                        yield Button("Push CA", id="btn-push-ca", classes="-secondary")
                        yield Button(
                            "Inject CA", id="btn-inject-ca", classes="-secondary"
                        )
                        yield Button(
                            "Remove CA", id="btn-remove-ca", classes="-secondary"
                        )

            # ----- Global action button ----- #
            with Horizontal(classes="button-row"):
                yield Button("Apply", id="btn-apply", classes="-primary")

            yield KeyHintFooter(
                hints={
                    "default": (
                        "[dim]Shift+←/→=Tabs  Tab=Next  Ctrl+S=Apply  "
                        f"{_LETTER_HINTS}  Esc=Cancel[/dim]"
                    ),
                    "input": (
                        "[dim]Shift+←/→=Tabs (empty field)  Tab=Next  "
                        "Ctrl+S=Apply  Esc=Cancel[/dim]"
                    ),
                    "radioset": (
                        "[dim]Shift+←/→=Tabs  Space=Select  Ctrl+S=Apply  "
                        f"{_LETTER_HINTS}  Esc=Cancel[/dim]"
                    ),
                    "button": (
                        "[dim]Shift+←/→=Tabs  Enter=Activate  Ctrl+S=Apply  "
                        f"{_LETTER_HINTS}  Esc=Cancel[/dim]"
                    ),
                }
            )

    def action_cycle_tab(self, delta: int) -> None:
        """Shift+Left/Right: the previous / next tab (wraps), focus its first
        control (never a text field, so letter keys stay commands).
        """
        try:
            tabs = self.query_one("#proxy-tabs", TabbedContent)
        except NoMatches:
            return
        panes = [pane.id for pane in tabs.query(TabPane) if pane.id]
        if not panes:
            return
        current = panes.index(tabs.active) if tabs.active in panes else 0
        tabs.active = panes[(current + delta) % len(panes)]
        self.call_after_refresh(self._focus_active_tab)

    def _focus_active_tab(self) -> None:
        """Focus the first control of the active tab (else the tab strip)."""
        try:
            tabs = self.query_one("#proxy-tabs", TabbedContent)
            pane = tabs.query_one(f"#{tabs.active}", TabPane)
        except NoMatches:
            return
        for widget in pane.query("*"):
            if isinstance(widget, (RadioSet, Checkbox, Button)) and widget.focusable:
                widget.focus()
                return
        try:
            tabs.query_one(Tabs).focus()
        except NoMatches:
            pass

    def on_mount(self) -> None:
        """Initialize the modal with current status."""
        self._refresh_device_proxy_status()
        self._init_app_rows()
        self._rebuild_app_list()
        self._detect_certificates()
        self._refresh_device_info()

        try:
            self.query_one("#device-radio-set", RadioSet).focus()
        except NoMatches:
            pass

    # ------------------------------------------------------------------ #
    # Section 1 — Device Proxy                                           #
    # ------------------------------------------------------------------ #

    def _mitmweb_addr(self) -> str:
        """The ``host_ip:port`` the device reaches Sandroid's mitmproxy at.

        Emulator-aware (``10.0.2.2`` on an emulator, the host loopback), like
        the Mitmproxy panel and the glance band. The raw LAN IP would not
        reach mitmproxy, which listens on 127.0.0.1 by default.
        """
        from sandroid.core.proxy_manager import resolve_proxy_host_ip
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        try:
            host_ip = resolve_proxy_host_ip()
        except Exception:
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
                self.app.call_from_thread(self._on_device_probe_failed, str(exc))
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
                f"[green]●[/green] Device points at our mitmproxy — [bold]{addr}[/bold]"
            )
            if addr.startswith("127.0.0.1:"):
                self._select_device_radio("device-radio-reverse")
            else:
                self._select_device_radio("device-radio-ours")
        elif state == "external":
            status_widget.update(
                f"[#6ba3ff]●[/] Device points at external proxy — [bold]{addr}[/bold]"
            )
            try:
                self.query_one("#device-ext-input", Input).value = addr
            except NoMatches:
                pass
            self._select_device_radio("device-radio-external")
        else:
            status_widget.update("[#5b6479]○[/] No device proxy configured")
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
            # Never wait for the lock on the UI thread (a reconcile may hold
            # it across seconds of adb work): the last value read is fine.
            proxies = get_focus_manager().app_proxies_cached()
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
                    _ProxyInput(
                        value=target,
                        placeholder="mitmproxy (default) — or http://host:port",
                        id=f"app-target-{idx}",
                        classes="app-proxy-target",
                        compact=True,
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

        self.app.push_screen(
            AppSelectionModal(
                title="Select App to Proxy",
                default_package=default_package,
                **app_svc.picker_loaders(show_system=False),
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

    def _refresh_device_info(self) -> None:
        """Probe API level, store and CA status off the UI thread (adb)."""
        self._kick_ca_probe()

    def _kick_ca_probe(self) -> None:
        """One worker: strategy + CA status in Zygote's namespace."""
        try:
            selected = self._get_selected_ca_path()
        except Exception:
            selected = None
        manager = self._ca_manager
        app = self.app

        def worker() -> None:
            try:
                strategy, api_level = manager.determine_injection_strategy()
            except Exception:
                strategy, api_level = None, None
            try:
                status = manager.check_zygote_injection_status(selected)
            except Exception as exc:  # pragma: no cover - defensive
                status = ZygoteStatus(
                    injected=False,
                    cert_hash=None,
                    zygote64_pid=None,
                    zygote_pid=None,
                    error_message=str(exc),
                    verdict="unknown",
                )
            try:
                app.call_from_thread(self._on_ca_probe, strategy, api_level, status)
            except Exception:
                pass

        threading.Thread(
            target=worker, name="proxy-modal-ca-probe", daemon=True
        ).start()

    def _on_ca_probe(self, strategy, api_level, status: ZygoteStatus) -> None:
        """Render the probe result (UI thread)."""
        try:
            info_widget = self.query_one("#device-info", Static)
        except NoMatches:
            return
        if strategy is None:
            info_widget.update("[$warning]Could not detect device info[/]")
        else:
            store = (
                "APEX store (Android 14+)"
                if strategy == InjectionStrategy.BIND_MOUNT
                else "system store (Android 13 and older)"
            )
            api_str = str(api_level) if api_level is not None else "unknown"
            info_widget.update(
                f"API level: [bold]{api_str}[/bold]  Trust store: [bold]{store}"
                "[/bold], installed without a Zygote restart"
            )
        self._show_zygote_status(status)

    def _refresh_zygote_status(self) -> None:
        """Re-read the CA status (off the UI thread)."""
        self._kick_ca_probe()

    def _show_zygote_status(self, status: ZygoteStatus) -> None:
        """Render a CA status in words and colours (UI thread)."""
        self._zygote_status = status
        try:
            status_widget = self.query_one("#zygote-status", Static)
        except NoMatches:
            return
        if status.verdict == "injected":
            status_widget.update(
                f"[$success]Installed[/] in Zygote and the running apps "
                f"(hash {status.cert_hash})"
            )
        elif status.verdict == "partial":
            status_widget.update(
                f"[$success]Installed[/] for new apps; [$warning]{status.lacking} "
                "running app namespace(s) lack it[/] (I installs it there)"
            )
        elif status.error_message:
            status_widget.update(f"[$warning]{status.error_message}[/]")
        else:
            status_widget.update("[$warning]Not installed[/]  (I installs it)")

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
        """Install the selected CA system-wide (no Zygote restart, worker)."""
        ca_path = self._get_selected_ca_path()
        if ca_path is None:
            ca_path = self._ca_manager._sandroid_ca_path()
        if ca_path is None or not ca_path.exists():
            self.notify("Please select a valid CA certificate", severity="warning")
            return
        self._pending_ca_path = ca_path
        self._run_ca_job("inject", ca_path)

    def action_remove_ca(self) -> None:
        """Ask, then remove Sandroid's CA from the system trust store."""
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        if self._ca_busy:
            self.notify("A CA operation is still running", severity="warning")
            return
        self._pending_ca_path = self._get_selected_ca_path()
        self.app.push_screen(
            ConfirmModal(
                title="Remove the CA?",
                message=(
                    "Sandroid's CA is removed from the system trust store, so "
                    "Mitmproxy can no longer read HTTPS of newly started apps, "
                    "and it is not installed again after a snapshot load. "
                    f"{CA_RUNNING_APPS_NOTE}\n\nRemove it?"
                ),
                yes_label="Remove CA",
                no_label="Cancel",
            ),
            self._on_remove_confirm,
        )

    def _on_remove_confirm(self, confirmed: bool | None) -> None:
        """The user decided on Remove CA (Esc counts as No)."""
        if not confirmed:
            self.notify("CA kept", severity="information")
            return
        self._run_ca_job("remove", self._pending_ca_path)

    def _run_ca_job(self, kind: str, ca_path: Path | None) -> None:
        """Run a CA install / fallback restart / removal off the UI thread.

        ``kind`` is ``inject`` (no Zygote restart), ``restart`` (the
        user-confirmed fallback) or ``remove``. The result lands in
        :meth:`_on_ca_job_done` on the UI thread.
        """
        if self._ca_busy:
            self.notify("A CA operation is still running", severity="warning")
            return
        self._ca_busy = True
        labels = {
            "inject": "Installing the CA…",
            "restart": "Restarting Zygote to install the CA…",
            "remove": "Removing the CA…",
        }
        try:
            self.query_one("#zygote-status", Static).update(
                f"[$text-muted]{labels.get(kind, 'Working…')}[/]"
            )
        except NoMatches:
            pass
        manager = self._ca_manager
        # Captured on the UI thread: once the modal is dismissed, self.app
        # no longer resolves from the worker and the result would be lost.
        app = self.app

        def worker() -> None:
            ct = None
            status = None
            try:
                if kind == "remove":
                    result = manager.uninject_ca()
                elif kind == "restart":
                    from sandroid.services.proxy_restore import (
                        restart_framework_for_ca,
                    )

                    held: dict = {}

                    def _while_held(_res) -> None:
                        # Still under the fallback's WORLD lease.
                        if ca_path is not None:
                            held["ct"] = manager.bypass_chrome_ct(ca_path)
                        held["status"] = manager.check_zygote_injection_status(ca_path)

                    result = restart_framework_for_ca(ca_path, while_held=_while_held)
                    ct = held.get("ct")
                    status = held.get("status")
                else:
                    result = manager.inject_ca_into_zygote(ca_path)
                    if result.success and ca_path is not None:
                        ct = manager.bypass_chrome_ct(ca_path)
                if status is None:
                    status = manager.check_zygote_injection_status(ca_path)
            except Exception as exc:
                result = exc
            try:
                app.call_from_thread(
                    self._on_ca_job_done, kind, ca_path, result, ct, status, app
                )
            except Exception:
                pass

        threading.Thread(
            target=worker, name=f"proxy-modal-ca-{kind}", daemon=True
        ).start()

    def _on_ca_job_done(self, kind, ca_path, result, ct, status, app=None) -> None:
        """Report a CA job (UI thread): toasts, the fallback offer, dismiss.

        When the modal was closed meanwhile the result still reaches the
        user as an app-level toast; no dialog is pushed over whatever screen
        is up now (the restart fallback is offered again on the next
        Inject CA).
        """
        self._ca_busy = False
        app = app or self.app
        if self not in app.screen_stack:
            self._report_ca_job_closed(app, kind, result, ct)
            return
        if status is not None:
            self._show_zygote_status(status)
        if isinstance(result, Exception):
            self.notify(f"CA operation failed: {result}", severity="error")
            return
        if kind == "remove":
            ok, message = result
            self.notify(message, severity="information" if ok else "error")
            if ok:
                self._dismiss_with_refresh(
                    ProxyModalResult(cancelled=False, action="remove_ca")
                )
            return
        if result.success:
            message = result.message
            if ct is not None and ct[0]:
                message += f". {ct[1]}"
            self.notify(message, severity="information")
            self._dismiss_with_refresh(
                ProxyModalResult(cancelled=False, action="inject_ca", ca_path=ca_path)
            )
        elif result.needs_root:
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            self.app.push_screen(
                ConfirmModal(
                    title="Enable ADB Root?",
                    message=(
                        "CA injection requires root access.\nEnable adb root now?"
                    ),
                ),
                self._on_root_confirm,
            )
        elif result.restart_required and kind == "inject":
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            self.app.push_screen(
                ConfirmModal(
                    title="Restart Zygote to install the CA?",
                    message=(
                        f"{result.message}\n\nThe CA can still be installed by "
                        "restarting Zygote, the process every Android app is "
                        "forked from. All running apps close, Frida sessions "
                        "end and the screen may flicker for a while. The device "
                        "does NOT reboot.\n\nContinue?"
                    ),
                    yes_label="Restart Zygote",
                    no_label="Cancel",
                ),
                self._on_restart_confirm,
            )
        else:
            self.notify(result.message, severity="error")

    @staticmethod
    def _report_ca_job_closed(app, kind, result, ct) -> None:
        """A CA job finished after the modal was closed: toast via the app."""
        if isinstance(result, Exception):
            app.notify(f"CA operation failed: {result}", severity="error")
            return
        if kind == "remove":
            ok, message = result
            app.notify(message, severity="information" if ok else "error")
            return
        if result.success:
            message = result.message
            if ct is not None and ct[0]:
                message += f". {ct[1]}"
            app.notify(message, severity="information")
            return
        message = result.message
        if result.restart_required:
            message += (
                ". Open Proxy Settings (y) and press I again to be offered the "
                "Zygote restart"
            )
        app.notify(message, severity="error", timeout=10)

    def _on_restart_confirm(self, confirmed: bool) -> None:
        """The user decided on the Zygote-restart fallback."""
        if not confirmed:
            self.notify("CA not installed: Zygote not restarted", severity="warning")
            return
        self._run_ca_job("restart", self._pending_ca_path)

    def _on_root_confirm(self, confirmed: bool) -> None:
        """Handle root confirmation result."""
        if not confirmed:
            return
        success, msg = self._ca_manager.enable_adb_root()
        if success:
            self.notify("ADB root enabled", severity="information")
            self._run_ca_job("inject", self._pending_ca_path)
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
        via_reverse = False
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
        elif choice == "reverse":
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            port = get_mitmproxy_service().state.proxy_port
            desired_config = ProxyConfig.from_string(f"127.0.0.1:{port}")
            via_reverse = True
        # choice == "off" => desired_config stays None (unset).

        # Confirm before overwriting/clearing a foreign device proxy.
        truth = self._device_truth or {}
        live_state = truth.get("state", "none")
        live_addr = truth.get("addr", "")
        desired_addr = desired_config.address if desired_config else ""
        overwriting_foreign = live_state == "external" and live_addr != desired_addr
        if overwriting_foreign:
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            if desired_config is None:
                msg = f"The device proxy currently points to {live_addr} — clear it?"
            else:
                msg = (
                    f"The device proxy currently points to {live_addr} — "
                    f"switch it to {desired_addr}?"
                )
            self._pending_device_config = desired_config
            self._pending_via_reverse = via_reverse
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

        self._apply_commit(desired_config, via_reverse=via_reverse)

    def _on_device_overwrite_confirm(self, confirmed: bool) -> None:
        """Continue Apply after the foreign-device-proxy confirmation."""
        if not confirmed:
            self.notify("Device proxy left unchanged", severity="warning")
            return
        self._apply_commit(
            self._pending_device_config,
            via_reverse=getattr(self, "_pending_via_reverse", False),
        )

    def _apply_commit(
        self, desired_config: ProxyConfig | None, via_reverse: bool = False
    ) -> None:
        """Apply the device proxy then reconcile the app proxies, then dismiss.

        Synchronous — matches the panel's existing device-setup precedent.

        Args:
            desired_config: The device proxy to set, or ``None`` to clear it.
            via_reverse: When ``True``, set up an ``adb reverse`` tunnel for our
                proxy port before pointing the device at ``127.0.0.1:<port>``.
                When ``False`` and a reverse binding for our port is live, it is
                torn down first so switching away cleans up after itself.
        """
        from sandroid.core.proxy_manager import _reverse_registered
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        port = get_mitmproxy_service().state.proxy_port

        def _teardown_reverse() -> None:
            """Drop our reverse tunnel when switching away (best-effort)."""
            try:
                if _reverse_registered(port):
                    Adb.reverse_remove(f"tcp:{port}")
            except Exception as exc:  # pragma: no cover - defensive
                self.notify(f"adb reverse teardown failed: {exc}", severity="warning")

        # 1. Device proxy.
        if desired_config is None:
            _teardown_reverse()
            ok, message = self._proxy_manager.unset_proxy()
            if ok:
                get_mitmproxy_service().note_device_proxy(None)
                self._set_glance_device_proxy("")
            else:
                self.notify(message, severity="error")
        else:
            if via_reverse:
                # Establish the tunnel BEFORE pointing the proxy at it; a
                # failure here means 127.0.0.1 would be a dead address, so
                # surface it and apply nothing rather than set a broken proxy.
                try:
                    Adb.reverse(f"tcp:{port}", f"tcp:{port}")
                except Exception as exc:
                    self.notify(f"adb reverse failed: {exc}", severity="error")
                    return
            else:
                _teardown_reverse()
            ok, message = self._proxy_manager.set_proxy(desired_config)
            if ok:
                # Remember a route to OUR mitmproxy so stop/exit clears it;
                # an external proxy (Burp/ZAP) is the user's to keep.
                ours = via_reverse or desired_config.address == self._mitmweb_addr()
                get_mitmproxy_service().note_device_proxy(
                    desired_config.address if ours else None
                )
                self._set_glance_device_proxy(desired_config.address)
            else:
                self.notify(message, severity="error")

        # 2. App proxies. Read the QUIC-block setting and commit it to the
        #    shared config BEFORE reconciling, so lanes newly enabled by the
        #    reconcile pick it up. The device work runs off the UI thread.
        try:
            block_quic = self.query_one("#block-quic-checkbox", Checkbox).value
        except NoMatches:
            block_quic = get_config().focus.block_quic
        get_config().focus.block_quic = block_quic
        self._sync_app_targets_from_inputs()
        self._start_app_proxy_apply(dict(self._app_rows), block_quic)

        self._dismiss_with_refresh(
            ProxyModalResult(
                cancelled=False,
                action="applied",
                proxy_config=desired_config,
            )
        )

    def _start_app_proxy_apply(self, desired: dict[str, str], block_quic: bool) -> None:
        """Apply the App Proxy rows on a worker; toasts via the app."""
        app = self.app

        def notify(message: str, severity: str) -> None:
            try:
                app.call_from_thread(app.notify, message, severity=severity)
            except Exception:
                pass

        def worker() -> None:
            try:
                for message, severity in self._reconcile_app_proxies(
                    desired, block_quic
                ):
                    notify(message, severity)
            except Exception as exc:  # pragma: no cover - defensive
                notify(f"App proxies failed: {exc}", "error")

        threading.Thread(target=worker, name="proxy-modal-apply", daemon=True).start()

    @staticmethod
    def _reconcile_app_proxies(
        desired: dict[str, str], block_quic: bool
    ) -> list[tuple[str, str]]:
        """Apply the App Proxy rows, then reconcile EVERY lane with the device.

        Diffs the rows against the requested lanes (enable/disable deltas),
        then always reconciles: Ctrl+S with an unchanged list used to do
        nothing, so a lane whose gost had died stayed dead. Blocking (adb);
        runs on a worker.

        Args:
            desired: ``{package: target}``; target ``""`` routes to our
                mitmproxy.
            block_quic: The QUIC-block checkbox.

        Returns:
            ``[(message, severity)]`` toasts.
        """
        try:
            fm = get_focus_manager()
            live = fm.app_proxies()  # {pkg: "ours" | "http://ip:port"}
        except Exception as exc:
            return [(f"App proxies unavailable: {exc}", "error")]
        live_norm = {
            pkg: ("" if target == "ours" else target) for pkg, target in live.items()
        }
        results: list[tuple[bool, str]] = []
        for pkg in set(live_norm) - set(desired):
            results.append(fm.disable_focus(pkg))
        for pkg, target in desired.items():
            target_arg = None if target == "" else target
            if pkg not in live_norm:
                results.append(fm.enable_focus(pkg, target_arg))
            elif live_norm[pkg] != target:
                fm.disable_focus(pkg)
                results.append(fm.enable_focus(pkg, target_arg))
        toasts: list[tuple[str, str]] = []
        try:
            fm.set_quic_blocking(block_quic)
        except Exception as exc:  # pragma: no cover - defensive
            toasts.append((f"QUIC-block sync failed: {exc}", "warning"))
        reports = fm.reconcile(None, "apply") if desired else []
        failures = [msg for ok, msg in results if not ok]
        if failures:
            summary = "; ".join(failures[:3])
            toasts.append((f"Some app proxies failed: {summary}", "error"))
        elif results:
            toasts.append(
                (
                    f"App proxies updated ({len(results)} change"
                    f"{'s' if len(results) != 1 else ''})",
                    "information",
                )
            )
        repaired = [r for r in reports if r.repaired]
        for report in repaired:
            toasts.append(
                (
                    f"App Proxy {report.package} repaired: "
                    f"{', '.join(report.repaired)}",
                    "information",
                )
            )
        for report in reports:
            if not report.health.ok:
                severity = "error" if report.health.state == "failed" else "warning"
                toasts.append(
                    (f"App Proxy {report.package}: {report.health.label}", severity)
                )
        return toasts

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
        elif btn_id == "btn-remove-ca":
            self.action_remove_ca()
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

    def on_key(self, event) -> None:
        """Enter does not apply right after opening or after stray typing."""
        if event.key != "enter" or self._enter_armed():
            return
        event.stop()
        event.prevent_default()
        self.app.notify(
            "Proxy Settings: Enter ignored, too soon after the dialog opened "
            "or after stray typing. Press Enter again (or Ctrl+S) to apply.",
            severity="warning",
            timeout=4,
        )

    def _enter_armed(self) -> bool:
        from sandroid.tui.modals.confirm_modal import typing_guard_active

        if time.monotonic() - self._opened_at < self.ENTER_ARM_SECONDS:
            return False
        return not typing_guard_active(self.app)

    def action_cancel(self) -> None:
        """Cancel and close the modal (sync — required for ESC)."""
        self._dismiss_with_refresh(ProxyModalResult(cancelled=True))
