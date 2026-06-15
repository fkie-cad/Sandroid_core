"""TUI panel that hosts and observes a mitmweb subprocess.

Interactive flow inspection happens in mitmweb's web UI (press ``o`` to
open it in the default browser). The panel itself shows lifecycle state
and a tail of mitmweb's log output.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog, Static

from sandroid.services.mitmproxy_service import get_mitmproxy_service

logger = logging.getLogger(__name__)


class MitmproxyPanel(Widget):
    """Bottom-left panel: mitmweb status header + log tail.

    Starting the mitmweb process is decoupled from routing device traffic into
    it. Enter only starts/stops the process; the Device Proxy and per-app App
    Proxies are independent, coexisting layers managed separately.

    Each setup step is its own keystroke — start, route, trust — so none has a
    surprising side effect on the others.

    Bindings (when focused):
        Enter:  start / stop mitmweb (bare — touches nothing on the device)
        Ctrl+D: toggle the Device Proxy on/off (our mitmproxy)
        Ctrl+N: install the mitmproxy CA into the system trust store
        Ctrl+R: restart mitmweb and re-apply device + app proxies
        Ctrl+O: open web UI in browser
        Ctrl+L: clear log view
        Ctrl+V: toggle verbose plumbing
        Ctrl+P: toggle SSL unpin
        Ctrl+A: manage addons
        y:      open Proxy Settings (device + app proxies + CA)
    """

    DEFAULT_CSS = """
    MitmproxyPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    MitmproxyPanel > #mitm-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    MitmproxyPanel > #mitm-log {
        height: 1fr;
        background: #050811;
        scrollbar-size: 1 1;
    }
    """

    BINDINGS = [
        ("enter", "toggle_running", "Start/Stop"),
        ("ctrl+d", "toggle_device", "Device proxy"),
        ("ctrl+n", "inject_ca", "Install CA"),
        ("ctrl+r", "restart", "Restart"),
        ("ctrl+o", "open_browser", "Open web UI"),
        ("ctrl+l", "clear_log", "Clear log"),
        ("ctrl+v", "toggle_verbose", "Verbose plumbing"),
        ("ctrl+p", "toggle_ssl_unpin", "SSL Unpin"),
        ("ctrl+a", "manage_addons", "Addons"),
    ]

    #: Bounded watchdog for the off-thread SSL toggle (> the BypassService's
    #: 15s readiness wait + session-setup overhead).
    _SSL_UNPIN_TIMEOUT = 30.0

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._service = get_mitmproxy_service()
        # Ownership flag: only clear a proxy that *we* set, on stop.
        self._proxy_set_by_us = False
        # Ground-truth setup state, refreshed off the UI thread so the
        # checklist reflects the device, not just what this panel did.
        self._proxy_state = "none"  # "ours" | "other" | "none"
        self._proxy_addr = ""
        self._ca_ok = False
        self._ct_ok = False
        self._unpin_hint_shown = False
        self._pending_mitm_cert = None
        self.can_focus = True

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="mitm-header")
        yield RichLog(
            highlight=False,
            markup=True,
            wrap=False,
            auto_scroll=True,
            id="mitm-log",
        )

    def on_mount(self) -> None:
        self._service.add_listener(self._on_service_line)
        self._refresh_header()
        try:
            log = self.query_one("#mitm-log", RichLog)
            log.write(
                "[#5b6479]Enter: start/stop · Ctrl+D: device proxy · "
                "Ctrl+N: install CA · Ctrl+P: SSL unpin · y: proxy settings[/]"
            )
        except Exception:
            pass
        self._kick_state_refresh()
        self._kick_focus_cleanup()

    def _kick_focus_cleanup(self) -> None:
        """Self-heal leftover Focus rules/redirectors from a crashed prior run.

        Runs once at mount in a daemon thread (touches the device, so never on
        the UI thread); swallows all errors. Satisfies the crash-safety
        guarantee that relaunching Sandroid clears a SIGKILL'd session's state.
        """

        def _run() -> None:
            try:
                from sandroid.core.proxy_manager import get_focus_manager

                get_focus_manager().cleanup_stale()
            except Exception as exc:
                logger.debug("Focus stale-cleanup skipped: %s", exc)

        threading.Thread(
            target=_run, name="mitm-focus-cleanup", daemon=True
        ).start()

    def on_unmount(self) -> None:
        try:
            self._service.remove_listener(self._on_service_line)
        except Exception:
            pass
        # Best-effort: free app-proxy lanes/iptables so they don't leak when the
        # panel closes (disable_focus() with no active lanes is a no-op).
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            if get_focus_manager().is_focus_active():
                get_focus_manager().disable_focus()
        except Exception:
            pass

    def _on_service_line(self, line: str) -> None:
        # Reader thread → marshal to Textual's main thread
        try:
            self.app.call_from_thread(self._append_line, line)
        except Exception:
            pass

    def _append_line(self, line: str) -> None:
        try:
            log = self.query_one("#mitm-log", RichLog)
            if line.startswith("[FLOW]|"):
                log.write(self._format_flow(line))
            elif line.startswith("[TLS_FAIL]|"):
                log.write(self._format_tls_fail(line))
                if (
                    not self._service.ssl_unpin_is_active()
                    and not self._unpin_hint_shown
                ):
                    self._unpin_hint_shown = True
                    log.write(
                        "[#7dd3fc][INFO] TLS pinning detected? "
                        "Press Ctrl+P to bypass for spotlight app[/]"
                    )
            elif line.startswith("[ERROR]"):
                log.write(f"[#fb7185]{line}[/]")
            elif line.startswith("[INFO]"):
                log.write(f"[#7dd3fc]{line}[/]")
            else:
                # mitmweb's own chatter (only visible when verbose mode is on)
                log.write(f"[#5b6479]{line}[/]")
            self._refresh_header()
        except Exception:
            pass

    @staticmethod
    def _status_color(code: int) -> str:
        if 200 <= code < 300:
            return "#4ade80"
        if 300 <= code < 400:
            return "#7dd3fc"
        if 400 <= code < 500:
            return "#facc15"
        return "#fb7185"

    @staticmethod
    def _protocol_color(proto: str) -> str:
        # Plaintext stands out (red-ish), TLS is muted, WebSocket is amber.
        if proto.startswith("WS"):
            return "#facc15"
        if proto.startswith("HTTPS"):
            return "#a78bfa"
        return "#fb7185"  # plain HTTP — interesting because it's unencrypted

    def _format_flow(self, line: str) -> str:
        # Focus:  [FLOW]|HH:MM:SS|protocol|status|method|host_path|size|app
        # New:    [FLOW]|HH:MM:SS|protocol|status|method|host_path|size
        # Legacy: [FLOW]|HH:MM:SS|status|method|host_path|size
        parts = line.split("|", 7)
        app = ""
        if len(parts) == 8:
            _, ts, proto, status, method, host_path, size, app = parts
        elif len(parts) == 7:
            _, ts, proto, status, method, host_path, size = parts
        elif len(parts) == 6:
            _, ts, status, method, host_path, size = parts
            proto = "?"
        else:
            return line
        try:
            code = int(status)
        except ValueError:
            code = 0
        color = self._status_color(code)
        proto_color = self._protocol_color(proto)
        app_col = (
            f"  [#22d3ee]{self._short_name(app):<14}[/]" if app else ""
        )
        return (
            f"[#5b6479]{ts}[/]  "
            f"[{proto_color}]{proto:<8}[/]  "
            f"[{color}]{status:>3}[/]  "
            f"[#7dd3fc]{method:<4}[/]  "
            f"{host_path:<40}  "
            f"[#5b6479]{size:>8}[/]"
            f"{app_col}"
        )

    def _format_tls_fail(self, line: str) -> str:
        # Focus:  [TLS_FAIL]|HH:MM:SS|host|reason|app
        # Legacy: [TLS_FAIL]|HH:MM:SS|host|reason
        parts = line.split("|", 4)
        app = ""
        if len(parts) == 5:
            _, ts, host, reason, app = parts
        elif len(parts) == 4:
            _, ts, host, reason = parts
        else:
            return line
        app_col = f"  [#22d3ee]{self._short_name(app)}[/]" if app else ""
        return (
            f"[#5b6479]{ts}[/]  "
            f"[#fb7185 bold]✗  [/]  "
            f"[#fb7185]TLS [/]  "
            f"{host}  "
            f"[#5b6479]({reason})[/]"
            f"{app_col}"
        )

    @staticmethod
    def _check_tag(label: str, ok: bool) -> str:
        if ok:
            return f"[#4ade80]{label} ✓[/]"
        return f"[#5b6479]{label} ○[/]"

    @staticmethod
    def _short_name(pkg: str) -> str:
        """Last package segment, capped to ~14 chars (blank-safe)."""
        seg = (pkg or "").rsplit(".", 1)[-1]
        return seg if len(seg) <= 14 else seg[:13] + "…"

    def _capture_tag(self) -> str:
        """Status token derived from ground truth: device + app proxies.

        Two independent, coexisting layers are rendered:

        * Device part — from the async-probed device-proxy state
          (``_proxy_state``/``_proxy_addr``): our mitmproxy, an external proxy,
          or off.
        * Apps part — from ``get_focus_manager().app_proxies()`` (a cheap
          in-process read): how many apps route to our mitmproxy vs. external.

        Stopped → empty (the header's ``○ stopped`` already says it all).
        """
        if not self._service.is_running():
            return ""

        # Device part.
        if self._proxy_state == "ours":
            device = f"[#4ade80]● Device → our mitmproxy {self._proxy_addr}[/]"
        elif self._proxy_state == "other":
            device = f"[#7dd3fc]● Device → {self._proxy_addr} [#5b6479](external)[/][/]"
        else:
            device = "[#5b6479]○ Device off[/]"

        # Apps part — only when there are app proxies.
        apps = ""
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            routes = get_focus_manager().app_proxies()
        except Exception:
            routes = {}
        if routes:
            ours = sum(1 for target in routes.values() if target == "ours")
            ext = len(routes) - ours
            if ours:
                apps += f"  [#22d3ee]· Apps {ours} → mitmproxy[/]"
            if ext:
                apps += f"  [#7dd3fc]· {ext} → ext[/]"

        return f"{device}{apps}"

    def _unpin_tag(self) -> str:
        if self._service.ssl_unpin_is_active():
            target = self._service.ssl_unpin_target() or ""
            suffix = f" [#5b6479]({target})[/]" if target else ""
            return f"[#4ade80]unpin ✓[/]{suffix}"
        return "[#5b6479]unpin ○[/]"

    def _render_header(self) -> str:
        st = self._service.state
        running = self._service.is_running()
        head = (
            f"[#4ade80]● running[/]   :{st.proxy_port} [#5b6479]→[/] :{st.web_port}"
            if running
            else "[#fb7185]○ stopped[/]"
        )

        # Always-visible, ground-truth setup checklist. The proxy-state token
        # is empty when stopped, so drop empties to avoid a leading gap.
        checks = "  ".join(
            tag
            for tag in (
                self._capture_tag(),
                self._check_tag("CA", self._ca_ok),
                self._check_tag("CT", self._ct_ok),
                self._unpin_tag(),
            )
            if tag
        )

        extras = []
        if st.tls_failures:
            extras.append(f"[#fb7185]tls✗ {st.tls_failures}[/]")
        if running:
            extras.append(f"flows [b]{st.flows_seen}[/]")
        try:
            addon_count = len(self._service.get_enabled_addons())
        except Exception:
            addon_count = 0
        if addon_count:
            extras.append(f"[#a78bfa]addons {addon_count}[/]")
        if st.verbose:
            extras.append("[#facc15]verbose[/]")
        extra_str = ("   " + "  ".join(extras)) if extras else ""

        return f"{head}   {checks}{extra_str}"

    def _refresh_header(self) -> None:
        try:
            self.query_one("#mitm-header", Static).update(self._render_header())
        except Exception:
            pass

    def action_toggle_running(self) -> None:
        """Enter — bare Start/Stop of the mitmweb process.

        Touches NOTHING on the device when starting (a foreign device proxy is
        left alone). Stopping first clears OUR device proxy so we never leave it
        pointing at a dead mitmweb; App Proxies are independent and left alone.
        Routing the device (Ctrl+D) and installing the CA (Ctrl+N) are separate,
        deliberate keystrokes — start never triggers them as a side effect.
        """
        if self._service.is_running():
            self._disarm()
            self._service.stop()
        else:
            self._service.start()
            self._append_line("[INFO] running")
        # Reconcile the checklist with real device state off the UI thread.
        self._kick_state_refresh()
        self._refresh_header()

    # ── Device Proxy ──────────────────────────────────────────────────
    #
    # The Device Proxy is the emulator's global http_proxy. It is independent
    # of the per-app App Proxies (owned by FocusManager / the proxy modal):
    # toggling it here never touches app lanes. _disarm/_arm_device only ever
    # set or clear OUR device proxy — the CA is a separate step (Ctrl+N).

    def _disarm(self) -> None:
        """Clear OUR device proxy (exact ip+port). Idempotent.

        A foreign proxy is left alone. App Proxies are independent and are NOT
        touched here.
        """
        self._clear_device_proxy()
        self._kick_state_refresh()
        self._refresh_header()

    def action_toggle_device(self) -> None:
        """Ctrl+D — toggle the Device Proxy between our mitmproxy and off.

        Decides the current state via a fresh probe: if it already points at
        our mitmproxy, clear it; otherwise set it to our mitmproxy (confirming
        first when an external proxy is in the way). The CA is handled
        separately by Ctrl+N — arming the device proxy no longer installs it.
        """
        state, _ = self._probe_proxy_state()
        if state == "ours":
            self._disarm()
        else:
            self._arm_device()

    def action_inject_ca(self) -> None:
        """Ctrl+N — install the mitmproxy CA into the system trust store.

        Self-contained and independent of the Device Proxy: it injects the CA
        (prompting to restart Zygote) and ensures the Chrome CT bypass, then
        is a no-op on subsequent presses once the CA is in. It does not start
        mitmweb or touch the device proxy; if the CA cert hasn't been generated
        yet, ``_auto_inject_ca`` says to start mitmproxy once first.
        """
        self._auto_inject_ca()
        self._kick_state_refresh()
        self._refresh_header()

    def _arm_device(self) -> None:
        """Set the Device Proxy to our mitmproxy.

        Ensures mitmweb is running, then classifies the current device proxy.
        An external proxy gets one confirmation before being overwritten; an
        ``ours``/``none`` proxy is set silently. App Proxies are untouched.
        """
        self._ensure_running()
        state, addr = self._probe_proxy_state()
        if state == "other":
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            host_ip, port = self._our_proxy_addr()
            self.app.push_screen(
                ConfirmModal(
                    title="Switch device proxy?",
                    message=(
                        f"Device proxy currently points to {addr} — switch to "
                        f"mitmproxy at {host_ip}:{port}?"
                    ),
                    yes_label="Switch",
                    no_label="Cancel",
                ),
                self._on_device_proxy_confirm,
            )
            return
        self._arm_device_commit()

    def _on_device_proxy_confirm(self, confirmed: bool) -> None:
        """Continue setting the Device Proxy after the external-proxy confirm."""
        if not confirmed:
            self._append_line("[INFO] Device proxy unchanged")
            self._refresh_header()
            return
        self._arm_device_commit()

    def _arm_device_commit(self) -> None:
        """Point the Device Proxy at our mitmproxy — and only that.

        Routing and trust are separate keystrokes now: this sets the device
        proxy but does NOT install the CA (press Ctrl+N for that). If the CA
        isn't in yet, the header's ``CA ✗`` flags it and ``_nudge_ca`` hints
        the key. ``_set_device_proxy`` sets ``_proxy_state="ours"``
        synchronously so the header doesn't flicker before the async probe.
        """
        self._set_device_proxy()
        self._nudge_ca()
        self._kick_state_refresh()
        self._refresh_header()

    def _ensure_running(self) -> None:
        """Start mitmweb if it isn't already (arming implies a live process)."""
        if not self._service.is_running():
            self._service.start()
            self._append_line("[INFO] running")

    def _our_proxy_addr(self) -> tuple[str, str]:
        """Return ``(host_ip, port)`` for our mitmweb proxy as strings."""
        from sandroid.core.proxy_manager import ProxyManager

        try:
            from sandroid.services import get_proxy_service

            host_ip = get_proxy_service()._get_setup_service().get_host_ip()
        except Exception:
            host_ip = ProxyManager.get_host_ip()
        return host_ip, str(self._service.state.proxy_port)

    def _probe_proxy_state(self) -> tuple[str, str]:
        """Classify the device's current http_proxy synchronously.

        Returns ``(state, addr)`` where ``state`` is ``"ours"`` (ip==host_ip
        AND port==proxy_port), ``"other"`` (anything else set), or ``"none"``.
        Blocking (one ADB read) — called only on deliberate device-proxy
        actions, which matches the panel's synchronous device-setup precedent.
        """
        from sandroid.core.proxy_manager import ProxyManager, ProxyStatus

        try:
            status, cfg = ProxyManager().get_proxy_settings()
            if status != ProxyStatus.SET or cfg is None:
                return "none", ""
            host_ip, _ = self._our_proxy_addr()
            ours = cfg.ip == host_ip and cfg.port == self._service.state.proxy_port
            return ("ours" if ours else "other"), cfg.address
        except Exception as exc:
            logger.debug("proxy classify failed: %s", exc)
            return "none", ""

    def _nudge_unpin(self) -> None:
        """Hint at Ctrl+P when a spotlight app is set but unpin is off."""
        if self._service.ssl_unpin_is_active():
            return
        try:
            from sandroid.services import get_spotlight_service

            app = get_spotlight_service().get_app_tuple()
        except Exception:
            app = None
        if app:
            # Use [~] not [i] — RichLog markup parses [i] as an italic tag and
            # swallows it.
            self._append_line(f"[INFO] [~] spotlight {app[0]} — Ctrl+P to unpin TLS")

    def _nudge_ca(self) -> None:
        """Hint Ctrl+N to install the CA when the device is routed but untrusted.

        Best-effort and non-blocking: keys off the last-known CA flag (the
        async state probe refreshes it right after). HTTPS won't decrypt until
        the CA is in the trust store, so this points at the now-separate
        Ctrl+N step rather than installing it as a side effect of routing.
        """
        if not self._ca_ok:
            self._append_line(
                "[INFO] [~] device routed — press Ctrl+N to install the CA "
                "for HTTPS"
            )

    def _kick_state_refresh(self) -> None:
        """Probe real device setup state in a daemon thread, then apply."""

        def _run() -> None:
            result = self._compute_setup_state()
            try:
                self.app.call_from_thread(self._apply_setup_state, *result)
            except Exception:
                pass

        threading.Thread(target=_run, name="mitm-setup-probe", daemon=True).start()

    def _apply_setup_state(
        self, proxy_state: str, proxy_addr: str, ca_ok: bool, ct_ok: bool
    ) -> None:
        self._proxy_state = proxy_state
        self._proxy_addr = proxy_addr
        self._ca_ok = ca_ok
        self._ct_ok = ct_ok
        self._refresh_header()
        # The glance band reads proxy state off ground truth, but nothing else
        # nudges it on a device-proxy change. This callback fires only at
        # transitions (never per-flow), so it is the right chokepoint to keep
        # the status bar in sync.
        self._refresh_status_bar()

    def _refresh_status_bar(self) -> None:
        """Re-render the app's glance band (main thread only; best-effort).

        Resolve via ``self.screen`` (the panel's owning MainScreen), NOT
        ``self.app`` — ``App.query_one`` searches the default screen, not the
        pushed MainScreen, so it raises ``NoMatches`` here and the glance never
        updates. ``self.screen`` is the panel's ancestor screen even when a
        modal is on top, so this always finds the status bar.
        """
        try:
            self.screen.query_one("#status-bar").refresh_status()
        except Exception:
            pass

    def _set_glance_device_proxy(self, address: str) -> None:
        """Push the just-set device proxy straight into the glance band.

        We already know the address we set, so write it to the status bar
        directly instead of relying on an ADB re-read that lags or races
        (the glance "Device" line and this tab read the same device proxy —
        they must never disagree). ``address`` is "ip:port", or "" when
        cleared. Main thread only; best-effort.

        Resolve via ``self.screen`` (the owning MainScreen): ``App.query_one``
        searches the default screen and raises ``NoMatches`` from a panel, so
        the value would silently never reach the glance.
        """
        try:
            self.screen.query_one("#status-bar").set_device_proxy(address)
        except Exception:
            pass

    def _compute_setup_state(self) -> tuple[str, str, bool, bool]:
        """Query the device for proxy / CA / CT state (blocking).

        Returns ``(proxy_state, proxy_addr, ca_ok, ct_ok)`` where
        ``proxy_state`` is ``"ours"`` (points at our mitmweb), ``"other"``
        (set to a different host), or ``"none"``.
        """
        from sandroid.core.adb import Adb
        from sandroid.core.proxy_manager import (
            CAManager,
            ProxyManager,
            ProxyStatus,
        )

        proxy_state, proxy_addr = "none", ""
        ca_ok = ct_ok = False
        try:
            status, cfg = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and cfg is not None:
                proxy_addr = cfg.address
                try:
                    from sandroid.services import get_proxy_service

                    host_ip = get_proxy_service()._get_setup_service().get_host_ip()
                except Exception:
                    host_ip = ProxyManager.get_host_ip()
                ours = cfg.ip == host_ip and cfg.port == self._service.state.proxy_port
                proxy_state = "ours" if ours else "other"
        except Exception as exc:
            logger.debug("proxy state probe failed: %s", exc)

        try:
            ca_mgr = CAManager()
            ca_ok = ca_mgr.check_zygote_injection_status().injected
            if ca_ok:
                stdout, _ = Adb.send_adb_command(
                    "shell ls /data/local/tmp/chrome-command-line 2>/dev/null"
                )
                ct_ok = "chrome-command-line" in (stdout or "")
        except Exception as exc:
            logger.debug("CA state probe failed: %s", exc)

        return proxy_state, proxy_addr, ca_ok, ct_ok

    def _set_device_proxy(self) -> None:
        """Ensure the device proxy routes through mitmweb (idempotent)."""
        try:
            from sandroid.core.proxy_manager import ProxyManager, ProxyStatus
            from sandroid.services import get_proxy_service

            svc = get_proxy_service()
            host_ip = svc._get_setup_service().get_host_ip()
            port = str(self._service.state.proxy_port)
            addr = f"{host_ip}:{port}"

            status, cfg = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and cfg and cfg.address == addr:
                self._proxy_set_by_us = True
                self._proxy_state = "ours"
                self._proxy_addr = addr
                self._set_glance_device_proxy(addr)
                self._append_line(f"[INFO] [~] device proxy already {addr}")
                return

            if svc.set_proxy(host_ip, port):
                self._proxy_set_by_us = True
                self._proxy_state = "ours"
                self._proxy_addr = addr
                self._set_glance_device_proxy(addr)
                self._append_line(f"[INFO] [OK] device proxy → {addr}")
            else:
                self._append_line("[ERROR] Failed to set device proxy")
        except Exception as exc:
            logger.warning("Auto-proxy setup failed: %s", exc)
            self._append_line(f"[ERROR] Proxy setup: {exc}")

    def _clear_device_proxy(self) -> None:
        """Remove device proxy if we set it."""
        if not self._proxy_set_by_us:
            return
        try:
            from sandroid.services import get_proxy_service

            svc = get_proxy_service()
            if svc.clear_proxy():
                self._append_line("[INFO] Device proxy cleared")
            self._proxy_set_by_us = False
            self._proxy_state = "none"
            self._proxy_addr = ""
            self._set_glance_device_proxy("")
        except Exception as exc:
            logger.warning("Failed to clear device proxy: %s", exc)
            self._append_line(f"[ERROR] Proxy clear: {exc}")

    def _auto_inject_ca(self) -> None:
        """Auto-inject mitmproxy CA cert into Android system trust store."""
        try:
            from sandroid.core.proxy_manager import CAManager, CASource

            ca_mgr = CAManager()

            # Check if already injected
            status = ca_mgr.check_zygote_injection_status()
            if status.injected:
                self._ca_ok = True
                self._append_line("[INFO] [~] CA already injected (Zygote)")
                # Still ensure Chrome CT bypass is in place
                certs = ca_mgr.detect_ca_certificates()
                mitm_cert = next(
                    (c for c in certs if c.source == CASource.MITMPROXY), None
                )
                if mitm_cert:
                    ct_ok, ct_msg = ca_mgr.bypass_chrome_ct(mitm_cert.path)
                    if ct_ok:
                        self._ct_ok = True
                        self._append_line(f"[INFO] {ct_msg}")
                self._nudge_unpin()
                return

            # Find mitmproxy cert
            certs = ca_mgr.detect_ca_certificates()
            mitm_cert = next((c for c in certs if c.source == CASource.MITMPROXY), None)
            if not mitm_cert:
                self._append_line(
                    "[INFO] No mitmproxy CA cert found. Start mitmproxy once "
                    "to generate it (~/.mitmproxy/), then restart."
                )
                self._nudge_unpin()
                return

            self._append_line(f"[INFO] Injecting CA cert: {mitm_cert.path.name}")
            # Injection restarts Zygote — confirm before proceeding.
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            self._pending_mitm_cert = mitm_cert.path
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
            return
        except Exception as exc:
            logger.warning("Auto CA injection failed: %s", exc)
            self._append_line(f"[ERROR] CA injection: {exc}")
            self._nudge_unpin()

    def _on_restart_confirm(self, confirmed: bool) -> None:
        """Handle Zygote restart confirmation from the ConfirmModal."""
        if not confirmed:
            self._append_line("[INFO] CA injection cancelled — Zygote not restarted")
            self._refresh_header()
            self._nudge_unpin()
            return
        self._do_inject_ca(self._pending_mitm_cert)

    def _do_inject_ca(self, cert_path) -> None:
        """Inject the CA cert into Zygote (after restart confirmation)."""
        try:
            from sandroid.core.proxy_manager import CAManager

            ca_mgr = CAManager()
            result = ca_mgr.inject_ca_into_zygote(cert_path)
            if result.success:
                self._ca_ok = True
                strategy_label = result.strategy.value if result.strategy else "unknown"
                self._append_line(
                    f"[INFO] [OK] CA injected ({strategy_label}, "
                    f"API {result.api_level}): {result.message}"
                )

                # Bypass Chrome Certificate Transparency enforcement
                ct_ok, ct_msg = ca_mgr.bypass_chrome_ct(cert_path)
                if ct_ok:
                    self._ct_ok = True
                    self._append_line(f"[INFO] {ct_msg}")
                else:
                    self._append_line(f"[INFO] Chrome CT bypass skipped: {ct_msg}")
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
                return
            else:
                self._append_line(f"[ERROR] CA injection failed: {result.message}")
        except Exception as exc:
            logger.warning("Auto CA injection failed: %s", exc)
            self._append_line(f"[ERROR] CA injection: {exc}")

        self._refresh_header()
        self._kick_state_refresh()
        self._nudge_unpin()

    def _on_root_confirm(self, confirmed: bool) -> None:
        """Handle root confirmation from the ConfirmModal."""
        if not confirmed:
            self._append_line("[INFO] Root not enabled — CA injection skipped")
            self._nudge_unpin()
            return
        try:
            from sandroid.core.proxy_manager import CAManager

            ca_mgr = CAManager()
            success, msg = ca_mgr.enable_adb_root()
            if success:
                self._append_line("[INFO] ADB root enabled, retrying CA injection")
                self._do_inject_ca(self._pending_mitm_cert)
            else:
                self._append_line(f"[ERROR] Failed to enable root: {msg}")
                self._nudge_unpin()
        except Exception as exc:
            logger.warning("Root enable failed: %s", exc)
            self._append_line(f"[ERROR] Root enable: {exc}")
            self._nudge_unpin()

    def action_toggle_ssl_unpin(self) -> None:
        """Toggle SSL pinning bypass via the service.

        The action is also bound at the app level (Ctrl+P) so it works
        outside the panel; both paths share the same service-owned
        SSLUnpinManager instance. Does not require mitmweb to be running
        — SSL unpin is a Frida-only operation. Without mitmweb you just
        won't see the decrypted traffic in the panel below.
        """
        if not self._service.ssl_unpin_is_active():
            # Validate spotlight before delegating so we can produce a
            # specific error from inside the panel.
            try:
                from sandroid.services import get_spotlight_service

                spotlight = get_spotlight_service()
                if not spotlight.get_app_tuple():
                    self._append_line(
                        "[ERROR] No spotlight app. "
                        "Press C (attach) or Shift+C (spawn) first."
                    )
                    self._refresh_header()
                    return
                self._append_line(
                    f"[INFO] Starting SSL unpin for {spotlight.get_app_tuple()[0]}..."
                )
            except Exception as exc:
                self._append_line(f"[ERROR] {exc}")
                self._refresh_header()
                return

        # The toggle can block on Frida script readiness — run it off the UI
        # thread (under a bounded watchdog) and marshal results back.
        was_active = self._service.ssl_unpin_is_active()

        def _job() -> None:
            ok, msg = False, ""
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(
                    self._service.toggle_ssl_unpin, self._on_unpin_message
                )
                try:
                    ok, msg = future.result(timeout=self._SSL_UNPIN_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    ok, msg = False, "SSL unpin timed out — see logs"
                    logger.error(
                        "SSL unpin toggle exceeded %.0fs watchdog; abandoning",
                        self._SSL_UNPIN_TIMEOUT,
                    )
            except Exception as exc:
                ok, msg = False, str(exc)
                logger.warning("SSL unpin toggle failed: %s", exc)
            finally:
                executor.shutdown(wait=False)

            def _report() -> None:
                if was_active:
                    self._append_line("[INFO] SSL pinning bypass stopped")
                elif ok:
                    self._append_line(f"[INFO] {msg}")
                else:
                    self._append_line(f"[ERROR] SSL unpin failed: {msg}")
                self._refresh_header()

            try:
                self.app.call_from_thread(_report)
            except Exception:
                pass

        def _dispatch() -> None:
            self.run_worker(_job, name="mitm_ssl_unpin_toggle", thread=True)

        # Turning ON against a live (non-paused) spotlight process attaches
        # Frida — gate on frida-server being up so the cryptic frida-core
        # "need Gadget to attach on jailed Android" error never surfaces; show
        # the install modal instead. Turning OFF (detach) and a not-running or
        # paused app never attach, so dispatch directly.
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            app_running = get_bypass_service()._spotlight_running()
        except Exception:
            app_running = False

        if not was_active and app_running:
            from sandroid.tui.modals import ensure_frida_running

            def _on_cancel() -> None:
                self._append_line(
                    "[INFO] SSL unpin cancelled — frida-server required"
                )
                self._refresh_header()

            ensure_frida_running(
                self.app,
                "SSL unpin",
                on_ready=_dispatch,
                on_cancel=_on_cancel,
            )
        else:
            _dispatch()

    def _on_unpin_message(self, payload) -> None:
        """Handle messages from the SSL unpin Frida script.

        Fires on the Frida message-delivery thread, so it must NOT touch the
        RichLog directly — marshal to the UI thread (mirror _on_service_line).
        """
        if not isinstance(payload, dict):
            return
        ptype = payload.get("type", "")
        hook = payload.get("hook", "")
        if ptype == "info":
            line = f"[INFO] Hooked: {hook}"
        elif ptype == "ready":
            line = f"[INFO] {payload.get('message', 'SSL hooks loaded')}"
        else:
            return
        try:
            self.app.call_from_thread(self._append_line, line)
        except Exception:
            pass

    def action_restart(self) -> None:
        # Ctrl+R: restart mitmweb, then re-apply BOTH the device proxy and the
        # app proxies against the fresh process. service.restart() tears down
        # the lanes + proxy, so snapshot ground truth BEFORE restarting and
        # re-create from the snapshot.
        device_state, _ = self._probe_proxy_state()
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            app_routes = dict(get_focus_manager().app_proxies())
        except Exception:
            app_routes = {}

        self._service.restart()

        if device_state == "ours":
            # No external-proxy confirm — the proxy was already ours. Re-runs
            # the idempotent CA/CT re-verify (only prompts if the CA was lost).
            self._arm_device_commit()

        if app_routes:
            try:
                from sandroid.core.proxy_manager import get_focus_manager

                fm = get_focus_manager()
                for pkg, target in app_routes.items():
                    ok, msg = fm.enable_focus(
                        pkg, None if target == "ours" else target
                    )
                    self._append_line(f"[{'INFO' if ok else 'ERROR'}] {msg}")
            except Exception as exc:
                self._append_line(f"[ERROR] App proxy re-apply: {exc}")

        self._append_line("[INFO] Restarted mitmproxy — proxies re-applied")
        self._kick_state_refresh()
        self._refresh_header()

    def action_open_browser(self) -> None:
        url = self._service.web_url()
        try:
            webbrowser.open(url)
        except Exception as exc:
            logger.warning("Failed to open browser: %s", exc)

    def action_clear_log(self) -> None:
        try:
            self.query_one("#mitm-log", RichLog).clear()
        except Exception:
            pass

    def action_toggle_verbose(self) -> None:
        self._service.set_verbose(not self._service.state.verbose)
        self._refresh_header()

    def action_manage_addons(self) -> None:
        """Open the custom-addons checklist modal."""
        from sandroid.tui.modals.mitmproxy_addons_modal import (
            MitmproxyAddonsModal,
        )

        self.app.push_screen(
            MitmproxyAddonsModal(service=self._service),
            self._on_addons_selected,
        )

    def _on_addons_selected(self, result) -> None:
        """Apply the addon selection returned by the modal.

        Runs on the UI thread (push_screen dismiss callback), so it touches
        the log directly — no ``call_from_thread`` needed.

        Args:
            result: A ``MitmproxyAddonsResult`` (or ``None`` if dismissed
                without a value).
        """
        if result is None or result.cancelled:
            return

        restarted = self._service.set_enabled_addons(result.enabled_paths)
        count = len(self._service.get_enabled_addons())
        suffix = " — restarted mitmweb" if restarted else ""
        self._append_line(f"[INFO] {count} addon(s) enabled{suffix}")

        if result.open_folder:
            self._open_addons_folder()

        self._refresh_header()

    def _open_addons_folder(self) -> None:
        """Open the user addons directory in the OS file manager.

        Best-effort: a raw ``webbrowser.open()`` on a folder is unreliable
        (macOS opens a browser tab), so use a platform opener and fall back
        to a ``file://`` URI.
        """
        target = self._service.user_addons_dir
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)])
            else:
                webbrowser.open(Path(target).as_uri())
        except Exception as exc:
            logger.warning("Failed to open addons folder %s: %s", target, exc)
