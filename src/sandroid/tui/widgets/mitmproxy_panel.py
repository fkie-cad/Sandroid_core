"""TUI panel that hosts and observes a mitmweb subprocess.

Interactive flow inspection happens in mitmweb's web UI (press ``o`` to
open it in the default browser). The panel itself shows lifecycle state
and a tail of mitmweb's log output.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import webbrowser

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog, Static

from sandroid.services.mitmproxy_service import get_mitmproxy_service

logger = logging.getLogger(__name__)


class MitmproxyPanel(Widget):
    """Bottom-left panel: mitmweb status header + log tail.

    Bindings (when focused):
        s: start / stop mitmweb
        r: restart mitmweb
        o: open web UI in browser
        x: clear log view
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
        ("ctrl+r", "restart", "Restart"),
        ("ctrl+o", "open_browser", "Open web UI"),
        ("ctrl+l", "clear_log", "Clear log"),
        ("ctrl+v", "toggle_verbose", "Verbose plumbing"),
        ("ctrl+p", "toggle_ssl_unpin", "SSL Unpin"),
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
                "[#5b6479]Ready. Press Enter to start mitmweb "
                "(auto-sets device proxy). Ctrl+B to close.[/]"
            )
        except Exception:
            pass
        self._kick_state_refresh()

    def on_unmount(self) -> None:
        try:
            self._service.remove_listener(self._on_service_line)
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
        # New format: [FLOW]|HH:MM:SS|protocol|status|method|host_path|size
        # Legacy:     [FLOW]|HH:MM:SS|status|method|host_path|size
        parts = line.split("|", 6)
        if len(parts) == 7:
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
        return (
            f"[#5b6479]{ts}[/]  "
            f"[{proto_color}]{proto:<8}[/]  "
            f"[{color}]{status:>3}[/]  "
            f"[#7dd3fc]{method:<4}[/]  "
            f"{host_path:<40}  "
            f"[#5b6479]{size:>8}[/]"
        )

    def _format_tls_fail(self, line: str) -> str:
        # [TLS_FAIL]|HH:MM:SS|host|reason
        parts = line.split("|", 3)
        if len(parts) != 4:
            return line
        _, ts, host, reason = parts
        return (
            f"[#5b6479]{ts}[/]  "
            f"[#fb7185 bold]✗  [/]  "
            f"[#fb7185]TLS [/]  "
            f"{host}  "
            f"[#5b6479]({reason})[/]"
        )

    @staticmethod
    def _check_tag(label: str, ok: bool) -> str:
        if ok:
            return f"[#4ade80]{label} ✓[/]"
        return f"[#5b6479]{label} ○[/]"

    def _proxy_tag(self) -> str:
        if self._proxy_state == "ours":
            return "[#4ade80]proxy ✓[/]"
        if self._proxy_state == "other":
            return f"[#facc15]proxy⚠ {self._proxy_addr}[/]"
        return "[#5b6479]proxy ○[/]"

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

        # Always-visible, ground-truth setup checklist.
        checks = "  ".join(
            (
                self._proxy_tag(),
                self._check_tag("CA", self._ca_ok),
                self._check_tag("CT", self._ct_ok),
                self._unpin_tag(),
            )
        )

        extras = []
        if st.tls_failures:
            extras.append(f"[#fb7185]tls✗ {st.tls_failures}[/]")
        if running:
            extras.append(f"flows [b]{st.flows_seen}[/]")
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
        if self._service.is_running():
            self._clear_device_proxy()
            self._service.stop()
        else:
            self._start_with_setup()
        # Reconcile the checklist with real device state off the UI thread.
        self._kick_state_refresh()
        self._refresh_header()

    def _start_with_setup(self) -> None:
        """Start mitmweb, then idempotently ensure proxy + CA + Chrome CT.

        Each step reports ``[OK]`` (just done), ``[~]`` (already in place),
        or ``[ERROR]``. SSL unpin stays a separate, opt-in decision
        (Ctrl+P) — Start only nudges when a spotlight app is set and the
        bypass is off.
        """
        self._service.start()
        self._set_device_proxy()
        self._auto_inject_ca()
        self._nudge_unpin()

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
            self._append_line(
                f"[INFO] [~] spotlight {app[0]} — Ctrl+P to unpin TLS"
            )

    def _kick_state_refresh(self) -> None:
        """Probe real device setup state in a daemon thread, then apply."""

        def _run() -> None:
            result = self._compute_setup_state()
            try:
                self.app.call_from_thread(self._apply_setup_state, *result)
            except Exception:
                pass

        threading.Thread(
            target=_run, name="mitm-setup-probe", daemon=True
        ).start()

    def _apply_setup_state(
        self, proxy_state: str, proxy_addr: str, ca_ok: bool, ct_ok: bool
    ) -> None:
        self._proxy_state = proxy_state
        self._proxy_addr = proxy_addr
        self._ca_ok = ca_ok
        self._ct_ok = ct_ok
        self._refresh_header()

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

                    host_ip = (
                        get_proxy_service()._get_setup_service().get_host_ip()
                    )
                except Exception:
                    host_ip = ProxyManager.get_host_ip()
                ours = (
                    cfg.ip == host_ip
                    and cfg.port == self._service.state.proxy_port
                )
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
                self._append_line(f"[INFO] [~] device proxy already {addr}")
                return

            if svc.set_proxy(host_ip, port):
                self._proxy_set_by_us = True
                self._proxy_state = "ours"
                self._proxy_addr = addr
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
                return

            # Find mitmproxy cert
            certs = ca_mgr.detect_ca_certificates()
            mitm_cert = next(
                (c for c in certs if c.source == CASource.MITMPROXY), None
            )
            if not mitm_cert:
                self._append_line(
                    "[INFO] No mitmproxy CA cert found. Start mitmproxy once "
                    "to generate it (~/.mitmproxy/), then restart."
                )
                return

            self._append_line(
                f"[INFO] Injecting CA cert: {mitm_cert.path.name}"
            )
            result = ca_mgr.inject_ca_into_zygote(mitm_cert.path)
            if result.success:
                self._ca_ok = True
                strategy_label = (
                    result.strategy.value if result.strategy else "unknown"
                )
                self._append_line(
                    f"[INFO] [OK] CA injected ({strategy_label}, "
                    f"API {result.api_level}): {result.message}"
                )
                self._refresh_header()

                # Bypass Chrome Certificate Transparency enforcement
                ct_ok, ct_msg = ca_mgr.bypass_chrome_ct(mitm_cert.path)
                if ct_ok:
                    self._ct_ok = True
                    self._append_line(f"[INFO] {ct_msg}")
                else:
                    self._append_line(
                        f"[INFO] Chrome CT bypass skipped: {ct_msg}"
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
                self._append_line(f"[ERROR] CA injection failed: {result.message}")
        except Exception as exc:
            logger.warning("Auto CA injection failed: %s", exc)
            self._append_line(f"[ERROR] CA injection: {exc}")

    def _on_root_confirm(self, confirmed: bool) -> None:
        """Handle root confirmation from the ConfirmModal."""
        if not confirmed:
            self._append_line("[INFO] Root not enabled — CA injection skipped")
            return
        try:
            from sandroid.core.proxy_manager import CAManager

            ca_mgr = CAManager()
            success, msg = ca_mgr.enable_adb_root()
            if success:
                self._append_line("[INFO] ADB root enabled, retrying CA injection")
                self._auto_inject_ca()
            else:
                self._append_line(f"[ERROR] Failed to enable root: {msg}")
        except Exception as exc:
            logger.warning("Root enable failed: %s", exc)
            self._append_line(f"[ERROR] Root enable: {exc}")

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
                    f"[INFO] Starting SSL unpin for "
                    f"{spotlight.get_app_tuple()[0]}..."
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

        self.run_worker(_job, name="mitm_ssl_unpin_toggle", thread=True)

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
        self._service.restart()
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
