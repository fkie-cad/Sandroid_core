"""Non-visual controller that hosts and observes a mitmweb subprocess.

The Network lens (:class:`~sandroid.tui.widgets.network_panel.NetworkPanel`)
owns everything on screen: the flow table, the caption (``Mitmproxy on
:<port> · CA installed``, the configured ``mitmproxy.proxy_port``), the empty-state hint and the "Capture status" Inspector page. This
widget is mounted *hidden* inside the lens and keeps all of the proxy
plumbing it always had -- start/stop, Device Proxy, CA injection, SSL unpin,
addons, reachability probes, focus-lane cleanup -- so none of that logic
moved. The lens forwards its keys here (``NetworkPanel.action_mitm``).

Output routing (was a RichLog tail):

* ``[INFO]``/``[ERROR]`` lines and mitmweb chatter (verbose mode only) go to
  the ActivityLog drawer (`` ` ``), tagged ``mitm``;
* ``[TLS_FAIL]`` lines become ✗ rows in the lens (``owner.add_tls_failure``);
* ``[FLOW]`` lines only nudge the lens to poll ``flows.jsonl`` early (the
  table reads the structured log, not stdout).

Interactive flow inspection beyond the lens's Inspector still happens in
mitmweb's web UI (Ctrl+O).
"""

from __future__ import annotations

import collections
import concurrent.futures
import logging
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from rich.markup import escape
from textual.widget import Widget

from sandroid.services.mitmproxy_service import get_mitmproxy_service
from sandroid.tui.utils.ui_thread import UiDispatcher

if TYPE_CHECKING:
    import asyncio

    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


def install_or_adopt_ca(manager, cert_path, where=None):
    """Ctrl+N's CA step (blocking adb, worker thread).

    An already installed CA is only re-checked, but recorded as this
    serial's re-inject intent like a fresh install: a later snapshot load or
    cold boot onto a state without it then installs it again. Otherwise the
    no-restart install runs (it records the intent itself).

    Returns:
        :class:`~sandroid.core.proxy_manager.InjectionResult`.
    """
    from sandroid.core.adb import Adb
    from sandroid.core.proxy_manager import InjectionResult, remember_ca_intent

    status = manager.check_zygote_injection_status(cert_path)
    if status.verdict != "injected":
        return manager.inject_ca_into_zygote(cert_path)
    spec = manager.ca_spec(cert_path)
    if spec is not None:
        remember_ca_intent(Adb.get_target_device(), spec)
    note = where(status) if where is not None else "Zygote"
    return InjectionResult(
        success=True,
        message=f"CA already in the trust store ({note})",
        verdict="injected",
    )


class MitmproxyPanel(Widget):
    """Hidden mitmweb controller for the Network lens (id ``mitm-panel``).

    Starting the mitmweb process is decoupled from routing device traffic into
    it. Start/Stop only starts/stops the process; the Device Proxy and per-app
    App Proxies are independent, coexisting layers managed separately.

    Each setup step is its own keystroke — start, route, trust — so none has a
    surprising side effect on the others. The keys are bound on the Network
    lens (see ``NetworkPanel.BINDINGS``) and call the ``action_*`` methods
    below:

        Space: start mitmweb · M: start / stop it (bare — touches nothing on the device)
        Ctrl+D: toggle the Device Proxy on/off (our mitmproxy)
        Ctrl+N: install the mitmproxy CA into the system trust store
        Ctrl+R: restart mitmweb and re-apply device + app proxies
        Ctrl+O: open web UI in browser
        Ctrl+V: toggle verbose plumbing
        Ctrl+P: toggle SSL unpin
        Ctrl+A: manage addons
        y:      open Proxy Settings (device + app proxies + CA; global key)
    """

    DEFAULT_CSS = """
    MitmproxyPanel {
        display: none;
        height: 0;
    }
    """

    #: Recent controller lines kept for the "Capture status" Inspector page.
    RECENT_LINES = 40

    #: Bounded watchdog for the off-thread SSL toggle (> the BypassService's
    #: 15s readiness wait + session-setup overhead).
    _SSL_UNPIN_TIMEOUT = 30.0

    #: Seconds between re-probes while the verdict is "unreachable" (the last
    #: value repeats), so a wrong or outdated verdict corrects itself.
    _REPROBE_DELAYS = (15.0, 30.0, 60.0)

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
        # Where the CA was found / why it doesn't count (set off-thread).
        self._ca_detail = ""
        self._unpin_hint_shown = False
        # Last device→mitmproxy reachability verdict, set off-thread by the
        # reachability probe and rendered in the header / log. Distinct from
        # _proxy_state: the proxy can be "ours" yet the device can't reach it.
        # "checking" = a settle-wait + probe is in flight (after a Zygote
        # restart or device reconnect), so no stale verdict is shown meanwhile.
        self._reach_state = "unknown"  # ok | unreachable | checking | unknown
        # Bumped on every probe kick / disarm / disconnect: a probe result
        # carrying an older generation is stale and is dropped.
        self._probe_gen = 0
        # Follow-up re-probe while the verdict is "unreachable" (backoff
        # index into _REPROBE_DELAYS), so a wrong verdict never stands.
        self._reprobe_timer = None
        self._reprobe_step = 0
        self._device_cb_registered = False
        self._unmounted = False
        self._liveness_busy = False
        # When the device proxy was last armed (for the steady-state 0-flows
        # soft signal) and a one-shot guard so that hint logs only once. Its
        # OWN flag — never reuse _unpin_hint_shown (taken by the TLS hint).
        self._armed_at = None
        self._zero_flow_hint_shown = False
        self._pending_mitm_cert = None
        # Set on Enter-start so the next ground-truth probe announces CA status
        # once (already injected vs. press Ctrl+N); cleared after it fires.
        self._announce_ca_on_start = False
        # Re-entrancy guard: an injection runs in a worker thread, so a second
        # Ctrl+N must not start a parallel install.
        self._injecting = False
        # Captured in on_mount(); lets background threads marshal log lines
        # onto the main loop with a non-blocking call_soon_threadsafe instead
        # of call_from_thread (see _on_service_line).
        self._main_loop: asyncio.AbstractEventLoop | None = None
        self._ui = UiDispatcher()
        # Plain-text tail of what this controller reported (Inspector page).
        self.recent_lines: collections.deque[str] = collections.deque(
            maxlen=self.RECENT_LINES
        )
        self.can_focus = False

    def compose(self) -> ComposeResult:
        return iter(())

    def on_mount(self) -> None:
        # Thread -> UI hand-off in the UI's contextvars context (see
        # sandroid.tui.utils.ui_thread: a bare loop callback lacks Textual's
        # active_app, so every mitmweb line's caption timer raised
        # LookupError during live traffic).
        self._ui = UiDispatcher.capture()
        self._main_loop = self._ui.loop
        self._service.add_listener(self._on_service_line)
        self._refresh_header()
        self._kick_state_refresh()
        self._kick_focus_cleanup()
        self._kick_reverse_cleanup()
        self._subscribe_device_changes()
        try:
            self.set_interval(self._BYPASS_LIVENESS_SECONDS, self._kick_bypass_liveness)
        except Exception:
            pass

    #: How often active bypass hooks are checked against their process.
    _BYPASS_LIVENESS_SECONDS = 3.0

    def _kick_bypass_liveness(self) -> None:
        """Drop "SSL unpin ✓" (and other bypass hooks) once their app died.

        A Zygote restart (Ctrl+N) or an app crash kills the hooked process;
        the indicators used to keep claiming active hooks. Checked off the UI
        thread (it may stop a Frida job), only while something is active.
        """
        if self._liveness_busy or self._unmounted:
            return
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            svc = get_bypass_service()
            if not svc.active_categories():
                return
        except Exception:
            return
        self._liveness_busy = True

        def _run() -> None:
            dropped: list[str] = []
            try:
                dropped = svc.reconcile_liveness()
            except Exception as exc:
                logger.debug("bypass liveness check failed: %s", exc)
            finally:
                self._ui.post(self._apply_bypass_liveness, dropped)

        threading.Thread(target=_run, name="bypass-liveness", daemon=True).start()

    def _apply_bypass_liveness(self, dropped: list[str]) -> None:
        self._liveness_busy = False
        if not dropped:
            return
        self._refresh_header()
        self._refresh_status_bar()

    def _subscribe_device_changes(self) -> None:
        """Re-probe after a device reconnect (once per panel; best-effort).

        DeviceManager has no unregister, so the callback checks
        ``_unmounted`` and becomes a no-op once the panel is gone.
        """
        if self._device_cb_registered:
            return
        try:
            from sandroid.services import get_device_service

            get_device_service().register_device_change_callback(self._on_device_change)
            self._device_cb_registered = True
        except Exception as exc:
            logger.debug("mitm panel device-change subscription failed: %s", exc)

    def _on_device_change(self, device) -> None:
        """Device-poll thread → UI thread (non-blocking, like _on_service_line)."""
        if self._unmounted:
            return
        self._ui.post(self._handle_device_change, device)

    def _handle_device_change(self, device) -> None:
        """Drop the verdict on disconnect; re-check on (re)connect (UI thread).

        A verdict from before a disconnect says nothing about the device that
        comes back, so it is cleared. On reconnect, when mitmproxy runs and
        the device proxy is ours, wait for the device to settle and re-probe.
        """
        if self._unmounted:
            return
        self._cancel_reprobe()
        self._probe_gen += 1
        if device is None:
            if self._reach_state != "unknown":
                self._reach_state = "unknown"
                self._refresh_header()
            return
        self._kick_state_refresh()
        if self._service.is_running() and (
            self._proxy_state == "ours" or self._service.owned_device_proxy
        ):
            self._kick_reachability_probe(settle=True, reason="device reconnected")

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

        threading.Thread(target=_run, name="mitm-focus-cleanup", daemon=True).start()

    def _kick_reverse_cleanup(self) -> None:
        """Drop a SIGKILL'd prior run's stale ``adb reverse`` tunnel at mount.

        Runs once at mount in a daemon thread (touches adbd, so never on the UI
        thread); swallows all errors. Mirrors ``_kick_focus_cleanup``: only the
        proxy-port binding we ever create is removed (per-port ``--remove``,
        never ``--remove-all``), matched by substring against the transport-id-
        prefixed ``adb reverse --list`` output.
        """

        def _run() -> None:
            try:
                from sandroid.core.adb import Adb

                port = self._service.state.proxy_port
                needle = f"tcp:{port} tcp:{port}"
                out, _ = Adb.reverse_list()
                if needle in (out or ""):
                    Adb.reverse_remove(f"tcp:{port}")
            except Exception as exc:
                logger.debug("Reverse stale-cleanup skipped: %s", exc)

        threading.Thread(target=_run, name="mitm-reverse-cleanup", daemon=True).start()

    def on_unmount(self) -> None:
        self._unmounted = True
        self._cancel_reprobe()
        try:
            self._service.remove_listener(self._on_service_line)
        except Exception:
            pass
        # Best-effort: free app-proxy lanes/iptables so they don't leak when the
        # panel closes (disable_focus() with no active lanes is a no-op). Off
        # the UI thread: it waits for FocusManager's lock and runs adb; the
        # FocusManager's atexit cleanup is the backstop at exit.
        self._release_app_proxies_async()
        # Best-effort: never leave the device pointed at a mitmproxy that dies
        # with Sandroid. Only the exact address we set is cleared (a proxy
        # changed since is left alone). The service's atexit hook is the
        # backstop if the TUI exits without unmounting.
        try:
            self._service.release_device_proxy()
        except Exception:
            pass
        # Best-effort: drop our adb-reverse tunnel so it doesn't leak.
        self._remove_our_reverse()

    @staticmethod
    def _release_app_proxies_async() -> None:
        def _run() -> None:
            try:
                from sandroid.core.proxy_manager import get_focus_manager

                manager = get_focus_manager()
                if manager.app_proxies_cached():
                    manager.disable_focus()
            except Exception:
                pass

        threading.Thread(
            target=_run, name="mitm-app-proxy-release", daemon=True
        ).start()

    def _on_service_line(self, line: str) -> None:
        # Reader/AI-tool-worker thread → non-blocking schedule onto the main
        # loop. NOT call_from_thread: start()/stop() call _emit() (which
        # invokes this listener) while holding MitmproxyService._lock, and
        # call_from_thread blocks the caller until the main loop runs it —
        # if StatusBar's poll timer (main thread) tries to acquire that same
        # lock via is_running() in that window, the two threads deadlock and
        # the whole TUI freezes.
        self._ui.post(self._append_line, line)

    # -- output routing (lens rows + ActivityLog drawer) ---------------------

    def _owner(self):
        """The Network lens hosting this controller (duck-typed), or None."""
        node = self.parent
        while node is not None:
            if hasattr(node, "add_tls_failure"):
                return node
            node = node.parent
        return None

    def _log(self, line: str) -> None:
        """Write one controller line to the ActivityLog drawer, tagged ``mitm``.

        ``line`` keeps its ``[INFO]``/``[ERROR]`` prefix convention; the prefix
        picks the colour and is dropped from the text. Best-effort: without a
        mounted MainScreen (unit tests) the line only lands in
        ``recent_lines``.
        """
        if line.startswith("[ERROR]"):
            text, color = line[len("[ERROR]") :].strip(), "#fb7185"
        elif line.startswith("[INFO]"):
            text, color = line[len("[INFO]") :].strip(), ""
        else:
            text, color = line.strip(), "#5b6479"
        if not text:
            return
        self.recent_lines.append(("✗ " if color == "#fb7185" else "") + text)
        body = escape(text)
        if color:
            body = f"[{color}]{body}[/]"
        try:
            from sandroid.tui.widgets.activity_log import ActivityLog

            self.screen.query_one("#activity-log", ActivityLog).log_message(
                body, "mitm"
            )
        except Exception:
            pass

    def _append_line(self, line: str) -> None:
        """Route one service/controller line (UI thread)."""
        owner = self._owner()
        try:
            if line.startswith("[FLOW]|"):
                self._note_direct_flow(line)
                if owner is not None:
                    owner.flow_hint()
            elif line.startswith("[FLOW_ERR]|"):
                # Errored flows are in flows.jsonl (with ``error``) too.
                if owner is not None:
                    owner.flow_hint()
            elif line.startswith("[TLS_FAIL]|"):
                parsed = self._parse_tls_fail(line)
                if owner is not None and parsed is not None:
                    owner.add_tls_failure(*parsed)
                if (
                    not self._service.ssl_unpin_is_active()
                    and not self._unpin_hint_shown
                ):
                    self._unpin_hint_shown = True
                    self._log(
                        "[INFO] TLS pinning detected? Press Ctrl+P to bypass "
                        "for the spotlight app"
                    )
            elif line.startswith(("[ERROR]", "[INFO]")):
                self._log(line)
            elif self._service.state.verbose:
                # mitmweb's own chatter (only shown when verbose mode is on)
                self._log(line)
            self._refresh_header()
        except Exception:
            logger.debug("mitm line routing failed", exc_info=True)

    @staticmethod
    def _parse_tls_fail(line: str) -> tuple[str, str, str, str] | None:
        """``[TLS_FAIL]|HH:MM:SS|host|reason[|app]`` -> (ts, host, reason, app)."""
        parts = line.split("|", 4)
        if len(parts) == 5:
            _, ts, host, reason, app = parts
        elif len(parts) == 4:
            _, ts, host, reason = parts
            app = ""
        else:
            return None
        return ts, host, reason, app

    def _note_direct_flow(self, line: str) -> None:
        """Retract an "unreachable" verdict once Device-Proxy flows arrive.

        A flow on the regular listener (no app-proxy lane) can only have come
        through the device proxy, so the device evidently reaches us.
        """
        if self._reach_state not in ("unreachable", "checking"):
            return
        from sandroid.services.mitmproxy_service import _is_direct_flow_line

        if not _is_direct_flow_line(line):
            return
        was_unreachable = self._reach_state == "unreachable"
        self._reach_state = "ok"
        self._cancel_reprobe()
        if not was_unreachable:
            return
        self._log(
            "[INFO] [OK] device traffic is arriving — "
            "device→mitmproxy reachable after all"
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
        * Apps part — from ``get_focus_manager().app_proxies_cached()`` (a
          lock-free, last-known read): how many apps route to our mitmproxy vs.
          external.

        Stopped → empty (the header's ``○ stopped`` already says it all).
        """
        if not self._service.is_running():
            return ""

        # Device part.
        if self._proxy_state == "ours" and self._reach_state == "unreachable":
            # The load-bearing fix: the proxy IS set to ours, but the device
            # can't reach it — show red instead of a lying green.
            device = (
                f"[#fb7185]✗ Device → mitmproxy {self._proxy_addr} (unreachable)[/]"
            )
        elif self._proxy_state == "ours" and self._reach_state == "checking":
            device = (
                f"[#facc15]◌ Device → our mitmproxy {self._proxy_addr} (re-checking)[/]"
            )
        elif self._proxy_state == "ours":
            device = f"[#4ade80]● Device → our mitmproxy {self._proxy_addr}[/]"
        elif self._proxy_state == "other":
            device = f"[#7dd3fc]● Device → {self._proxy_addr} [#5b6479](external)[/][/]"
        else:
            device = "[#5b6479]○ Device off[/]"

        # Apps part — only when there are app proxies.
        apps = ""
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            routes = get_focus_manager().app_proxies_cached()
        except Exception:
            routes = {}
        if routes:
            ours = sum(1 for target in routes.values() if target == "ours")
            ext = len(routes) - ours
            if ours:
                apps += f"  [#22d3ee]· Apps {ours} → mitmproxy[/]"
            if ext:
                apps += f"  [#7dd3fc]· {ext} → ext[/]"
        problems = self._lane_problems()
        if problems:
            from sandroid.tui.themes import lens_palette

            apps += f"  [{lens_palette().warn}]{escape(problems)}[/]"

        return f"{device}{apps}"

    @staticmethod
    def _lane_problems() -> str:
        """App Proxy lanes that pass no traffic, in words ("" when all fine).

        Non-blocking read of the last reconcile verdicts (no adb).
        """
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            health = get_focus_manager().lane_health_cached()
        except Exception:
            return ""
        if not health:
            return ""
        bad = [
            f"{pkg.rsplit('.', 1)[-1]} {h.label}"
            for pkg, h in sorted(health.items())
            if not h.ok
        ]
        return "App Proxy " + ", ".join(bad) if bad else ""

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
            f"[#4ade80]● running[/]   {st.listen_host}:{st.proxy_port} "
            f"[#5b6479]→[/] :{st.web_port}"
            if running
            else f"[#fb7185]○ stopped[/] [#5b6479](port {st.proxy_port})[/]"
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
        # Steady-state soft signal: armed at our mitmproxy but no flows after a
        # grace period — likely a reachability problem OR a QUIC-only app.
        if self._zero_flow_soft_signal():
            extras.append(
                "[#5b6479]0 flows — device reaching proxy? QUIC app? "
                "(use App Proxy + block_quic)[/]"
            )
        extra_str = ("   " + "  ".join(extras)) if extras else ""

        return f"{head}   {checks}{extra_str}"

    def _zero_flow_soft_signal(self) -> bool:
        """Whether the steady-state 0-flows soft signal should show.

        True when running + device proxy is ours + ``flows_seen == 0`` + the
        proxy was armed more than ~20s ago. Free (no extra I/O) — it reads only
        in-process state. Does NOT distinguish a broken path from a QUIC-only
        app; the active reachability probe does that. The wording stays neutral.
        """
        st = self._service.state
        return (
            self._service.is_running()
            and self._proxy_state == "ours"
            and st.flows_seen == 0
            and self._armed_at is not None
            and (time.monotonic() - self._armed_at) > 20.0
        )

    def _refresh_header(self) -> None:
        """Tell the lens the status changed (caption, empty state, Inspector)."""
        owner = self._owner()
        if owner is not None:
            try:
                owner.refresh_status()
            except Exception:
                logger.debug("network lens status refresh failed", exc_info=True)
        # Emit the steady-state 0-flows hint once (this method is the per-line
        # chokepoint). Guarded by its OWN flag so it never spams the log.
        if self._zero_flow_soft_signal() and not self._zero_flow_hint_shown:
            self._zero_flow_hint_shown = True
            self._log(
                "[INFO] [~] 0 flows since arming — is the device reaching the "
                "proxy? A QUIC-only app (YouTube) won't show here; use an App "
                "Proxy with block_quic."
            )

    # -- compact status for the lens -----------------------------------------

    def status_caption(self) -> str:
        """One calm caption fragment in words and theme colours, e.g.
        ``Mitmproxy on :8090 · device routed · CA installed``.

        The port is the live process's, else the configured
        ``mitmproxy.proxy_port`` -- never a hard-coded default.
        """
        from sandroid.tui.themes import lens_palette

        pal = lens_palette()
        st = self._service.state
        if not self._service.is_running():
            return f"[{pal.dim}]Mitmproxy off[/]"
        parts = [f"[{pal.ok}]Mitmproxy on[/] :{st.proxy_port}"]
        if self._proxy_state == "ours" and self._reach_state == "unreachable":
            parts.append(f"[{pal.bad}]device can't reach it[/]")
        elif self._proxy_state == "ours":
            parts.append("device routed")
        elif self._proxy_state == "other":
            parts.append(f"[{pal.dim}]device on another proxy[/]")
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            routes = get_focus_manager().app_proxies_cached()
        except Exception:
            routes = {}
        if routes:
            parts.append(f"app proxies {len(routes)}")
        problems = self._lane_problems()
        if problems:
            parts.append(f"[{pal.warn}]{escape(problems)}[/]")
        parts.append(
            "CA installed" if self._ca_ok else f"[{pal.dim}]CA not installed[/]"
        )
        if self._service.ssl_unpin_is_active():
            parts.append("unpin on")
        return " · ".join(parts)

    def empty_hint(self) -> tuple[str, str]:
        """``(headline, dim hint)`` for the lens when nothing is captured."""
        st = self._service.state
        if not self._service.is_running():
            return (
                f"No flows yet — space starts mitmproxy on :{st.proxy_port}",
                "then ^D routes the device · ^N installs the CA · y proxy settings",
            )
        if self._proxy_state == "ours" and self._reach_state == "unreachable":
            addr = escape(self._proxy_addr or f":{st.proxy_port}")
            return (
                f"[#fb7185]The device can't reach mitmproxy at {addr}[/]",
                "check the host IP, or route via adb reverse in Proxy Settings (y)",
            )
        if self._zero_flow_soft_signal():
            return (
                "Still no flows since the device was routed",
                "device reaching the proxy?  QUIC-only app?  "
                "use an App Proxy with block_quic (y)",
            )
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            routed_apps = bool(get_focus_manager().app_proxies_cached())
        except Exception:
            routed_apps = False
        if self._proxy_state != "ours" and not routed_apps:
            return (
                f"mitmproxy is listening on :{st.proxy_port} — waiting for traffic",
                "^D routes the device through it · y sets per-app proxies",
            )
        hint = "" if self._ca_ok else "^N installs the CA so HTTPS can be read"
        return ("Waiting for the first flow…", hint)

    def status_rows(self) -> list[tuple[str, str]]:
        """``[(label, markup)]`` for the "Capture status" Inspector page."""
        st = self._service.state
        running = self._service.is_running()
        rows = [
            (
                "mitmweb",
                (
                    f"[#4ade80]● running[/]  {st.listen_host}:{st.proxy_port} → "
                    f"web :{st.web_port}"
                    if running
                    else f"[#5b6479]○ stopped[/]  (port {st.proxy_port})"
                ),
            )
        ]
        capture = self._capture_tag()
        if capture:
            rows.append(("routing", capture))
        rows.append(
            (
                "CA",
                (
                    "[#4ade80]✓[/] in the system trust store"
                    if self._ca_ok
                    else "[#5b6479]○ not installed[/]  ^N"
                ),
            )
        )
        rows.append(
            ("Chrome CT", "[#4ade80]✓[/] bypassed" if self._ct_ok else "[#5b6479]○[/]")
        )
        if self._service.ssl_unpin_is_active():
            target = escape(self._service.ssl_unpin_target() or "")
            rows.append(("SSL unpin", f"[#4ade80]✓[/] {target}"))
        else:
            rows.append(("SSL unpin", "[#5b6479]○ off[/]  ^P"))
        try:
            addon_count = len(self._service.get_enabled_addons())
        except Exception:
            addon_count = 0
        if addon_count:
            rows.append(("addons", str(addon_count)))
        if st.verbose:
            rows.append(("verbose", "[#facc15]on[/]"))
        if running:
            rows.append(("flows seen", str(st.flows_seen)))
        if st.tls_failures:
            rows.append(("TLS failures", f"[#fb7185]{st.tls_failures}[/]"))
        return rows

    def is_running(self) -> bool:
        """True while the mitmweb process runs."""
        try:
            return bool(self._service.is_running())
        except Exception:
            return False

    def action_toggle_running(self) -> None:
        """M (Space starts only) — bare Start/Stop of the mitmweb process.

        Touches NOTHING on the device when starting (a foreign device proxy is
        left alone). Stopping first clears OUR device proxy so we never leave it
        pointing at a dead mitmweb; App Proxies are independent and left alone.
        Routing the device (Ctrl+D) and installing the CA (Ctrl+N) are separate,
        deliberate keystrokes — start never triggers them as a side effect,
        unless the user opted in with ``mitmproxy.auto_device_proxy`` (then
        start also arms the Device Proxy, exactly as Ctrl+D would).
        """
        if self._service.is_running():
            self._disarm()
            self._service.stop()
        else:
            self._service.start()
            self._append_line("[INFO] running")
            # Let the upcoming ground-truth probe report CA status once.
            self._announce_ca_on_start = True
            if self._auto_device_proxy_enabled() and self._service.is_running():
                # Opt-in (mitmproxy.auto_device_proxy): route the device too.
                self._arm_device()
        # Reconcile the checklist with real device state off the UI thread.
        self._kick_state_refresh()
        self._refresh_header()

    @staticmethod
    def _auto_device_proxy_enabled() -> bool:
        """``mitmproxy.auto_device_proxy`` (default False). Never raises."""
        try:
            from sandroid.config import get_config

            return bool(getattr(get_config().mitmproxy, "auto_device_proxy", False))
        except Exception:
            return False

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

        Self-contained and independent of the Device Proxy: it installs the
        CA without restarting Zygote (running apps and Frida sessions keep
        going) and ensures the Chrome CT bypass, then is a no-op on
        subsequent presses once the CA is in. Only when that cannot work on
        the device does it offer a Zygote restart, after confirmation. It does not start
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

        After pointing the proxy, fires an off-thread reachability probe to
        catch a silent failure (proxy set but the device can't reach it).
        """
        self._set_device_proxy()
        self._nudge_ca()
        # Mark the arm time and reset the 0-flow hint guard so the steady-state
        # soft signal can fire once for this fresh arm.
        self._armed_at = time.monotonic()
        self._zero_flow_hint_shown = False
        self._kick_state_refresh()
        self._kick_reachability_probe()
        self._refresh_header()

    def _ensure_running(self) -> None:
        """Start mitmweb if it isn't already (arming implies a live process)."""
        if not self._service.is_running():
            self._service.start()
            self._append_line("[INFO] running")

    def _our_proxy_addr(self) -> tuple[str, str]:
        """Return ``(host_ip, port)`` for our mitmweb proxy as strings.

        Uses the emulator-aware ``resolve_proxy_host_ip`` (so the device proxy
        and app proxies agree on where the host is), falling back to the LAN IP
        only if that resolver itself fails. When our adb-reverse tunnel is
        registered the device is pointed at ``127.0.0.1`` instead — but this
        returns the *resolved* host IP; the loopback case is handled by the
        shared ``classify_device_proxy`` classifier.
        """
        from sandroid.core.proxy_manager import (
            ProxyManager,
            resolve_proxy_host_ip,
        )

        try:
            host_ip = resolve_proxy_host_ip()
        except Exception:
            host_ip = ProxyManager.get_host_ip()
        return host_ip, str(self._service.state.proxy_port)

    def _probe_proxy_state(self) -> tuple[str, str]:
        """Classify the device's current http_proxy synchronously.

        Returns ``(state, addr)`` where ``state`` is ``"ours"`` (our host IP, or
        ``127.0.0.1`` while our adb-reverse tunnel is registered, AND
        port==proxy_port), ``"other"`` (anything else set), or ``"none"``.
        Blocking (one ADB read) — called only on deliberate device-proxy
        actions, which matches the panel's synchronous device-setup precedent.
        Uses the shared ``classify_device_proxy`` so all classifiers agree.
        """
        from sandroid.core.proxy_manager import (
            ProxyManager,
            ProxyStatus,
            classify_device_proxy,
        )

        try:
            status, cfg = ProxyManager().get_proxy_settings()
            if status != ProxyStatus.SET or cfg is None:
                return "none", ""
            state = classify_device_proxy(
                cfg.ip, cfg.port, self._service.state.proxy_port
            )
            return state, cfg.address
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
            # Use [~] not [i] — log markup parses [i] as an italic tag and
            # swallows it.
            self._append_line(
                f"[INFO] [~] spotlight {app[0]} — Ctrl+P to unpin TLS (exp.)"
            )

    def _nudge_ca(self) -> None:
        """Hint Ctrl+N to install the CA when the device is routed but untrusted.

        Best-effort and non-blocking: keys off the last-known CA flag (the
        async state probe refreshes it right after). HTTPS won't decrypt until
        the CA is in the trust store, so this points at the now-separate
        Ctrl+N step rather than installing it as a side effect of routing.
        """
        if not self._ca_ok:
            self._append_line(
                "[INFO] [~] device routed — press Ctrl+N to install the CA for HTTPS"
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

    def _kick_reachability_probe(
        self, *, settle: bool = False, reason: str = "", quiet: bool = False
    ) -> None:
        """Prove the device can reach our mitmproxy off the UI thread.

        Mirrors ``_kick_state_refresh``: the probe blocks on a device round-trip
        + a short settle poll, so it runs in a daemon thread and marshals the
        verdict back via ``call_from_thread``. The address probed is the one the
        device is actually pointed at — the live ``http_proxy`` IP when set
        (e.g. ``127.0.0.1`` for an adb-reverse route), else the resolved host IP.

        Args:
            settle: First wait for the device to settle (boot completed +
                package manager up) and retry a negative probe a few times.
                Used after a Zygote restart and a device reconnect, where an
                immediate probe hits a device without network.
            reason: Shown in the log while waiting (e.g. "Zygote restart").
            quiet: A periodic re-probe: log only when the verdict changes.
        """
        self._probe_gen += 1
        gen = self._probe_gen
        if settle:
            # Never show a pre-restart verdict while the device comes back.
            self._cancel_reprobe()
            self._reach_state = "checking"
            why = f" after {reason}" if reason else ""
            self._append_line(
                f"[INFO] [~] waiting for the device to settle{why}, "
                "then re-checking device→mitmproxy…"
            )
            self._refresh_header()

        def _run() -> None:
            try:
                from sandroid.core.proxy_manager import (
                    ProxyManager,
                    ProxyStatus,
                    resolve_proxy_host_ip,
                )
                from sandroid.services.mitmproxy_service import (
                    _not_settled_result,
                )

                port = self._service.state.proxy_port
                # Settle BEFORE reading http_proxy: settings is served by
                # system_server, which is down during a Zygote restart.
                if settle and not self._service.wait_device_settled(timeout=120.0):
                    result, addr = _not_settled_result(), ""
                else:
                    if settle:
                        self._close_system_dialogs()
                    status, cfg = ProxyManager().get_proxy_settings()
                    if status == ProxyStatus.SET and cfg is not None:
                        host = cfg.ip
                    else:
                        host = resolve_proxy_host_ip()
                    if settle:
                        # The network comes back after the package manager:
                        # retry for ~30 s before any "CANNOT reach" verdict.
                        result = self._service.probe_after_device_restart(
                            host, port, wait_settle=False, attempts=7
                        )
                    else:
                        result = self._service.probe_device_reachability(host, port)
                    addr = f"{host}:{port}"
            except Exception as exc:  # marshal a failure as a quiet unknown
                logger.debug("reachability probe kick failed: %s", exc)
                result, addr = None, ""
            try:
                self.app.call_from_thread(
                    self._apply_reachability_result, result, addr, gen, quiet
                )
                if settle:
                    # A state refresh during the restart could not read the
                    # device proxy (system_server down); re-read it now.
                    self.app.call_from_thread(self._kick_state_refresh)
            except Exception:
                pass

        threading.Thread(target=_run, name="mitm-reach-probe", daemon=True).start()

    @staticmethod
    def _close_system_dialogs() -> None:
        """Close leftover system dialogs once the device settled (any thread).

        After a Zygote restart a slow emulator shows "System UI isn't
        responding" while it catches up; once it has settled the dialog is
        stale. CLOSE_SYSTEM_DIALOGS (allowed for the shell user) closes
        system dialogs, the shade and recents; it touches no app state.
        """
        try:
            from sandroid.core.adb import Adb
            from sandroid.core.adb_utils import quiet_adb_warnings

            with quiet_adb_warnings():
                Adb.send_adb_command(
                    "shell am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS"
                )
        except Exception as exc:
            logger.debug("closing system dialogs failed: %s", exc)

    def _kick_settle_watch(self, reason: str) -> None:
        """Wait (off-thread) for the device to settle, then tidy up and say so.

        Used after a Zygote restart when no device proxy needs re-probing.
        """
        self._append_line(
            f"[INFO] [~] waiting for the device to settle after {reason}…"
        )

        def _run() -> None:
            settled = self._service.wait_device_settled(timeout=120.0)
            if settled:
                self._close_system_dialogs()
                line = f"[INFO] [OK] device settled after {reason}"
            else:
                line = (
                    f"[INFO] [~] the device is still busy 2 min after {reason}; "
                    "it should recover on its own (choose Wait on 'isn't "
                    "responding' dialogs)"
                )
            self._ui.post(self._append_line, line)

        threading.Thread(target=_run, name="mitm-settle-watch", daemon=True).start()

    def _cancel_reprobe(self) -> None:
        """Stop a pending follow-up re-probe (idempotent)."""
        timer, self._reprobe_timer = self._reprobe_timer, None
        self._reprobe_step = 0
        if timer is not None:
            try:
                timer.stop()
            except Exception:
                pass

    def _schedule_reprobe(self) -> None:
        """Re-probe later while the verdict is "unreachable" (backoff)."""
        if self._unmounted or self._reprobe_timer is not None:
            return
        delays = self._REPROBE_DELAYS
        delay = delays[min(self._reprobe_step, len(delays) - 1)]
        self._reprobe_step += 1
        try:
            self._reprobe_timer = self.set_timer(delay, self._reprobe_due)
        except Exception as exc:  # not mounted (tests) — nothing to schedule
            logger.debug("re-probe scheduling skipped: %s", exc)
            self._reprobe_timer = None

    def _reprobe_due(self) -> None:
        """Timer callback: re-check an "unreachable" verdict (UI thread)."""
        self._reprobe_timer = None
        if (
            self._unmounted
            or self._reach_state != "unreachable"
            or self._proxy_state != "ours"
            or not self._service.is_running()
        ):
            self._reprobe_step = 0
            return
        self._kick_reachability_probe(quiet=True)

    def _apply_reachability_result(
        self, result, addr: str, gen: int | None = None, quiet: bool = False
    ) -> None:
        """Render the device→mitmproxy reachability verdict (UI thread).

        ``result`` is a ``ReachabilityResult``. Unreachable flips the header's
        Device token red, logs an ``[ERROR]`` + a neutral remedy hint and
        schedules a follow-up re-probe; reachable logs one quiet confirmation.
        A result from a superseded probe (``gen`` older than the latest kick)
        is dropped. Uses ``[~]`` for hints, never ``[i]`` (log markup parses
        ``[i]`` as italic markup).
        """
        if gen is not None and gen != self._probe_gen:
            return  # stale: a newer probe / disarm / disconnect superseded it
        if result is None:
            if self._reach_state == "checking":
                self._reach_state = "unknown"
                self._refresh_header()
            return
        previous = self._reach_state
        if getattr(result, "reachable", False):
            self._reach_state = "ok"
            self._cancel_reprobe()
            detail = getattr(result, "detail", "") or "device→mitmproxy reachable"
            if previous == "unreachable":
                self._append_line(
                    f"[INFO] [OK] {detail} — the earlier 'CANNOT reach' no "
                    "longer applies"
                )
            elif not quiet:
                self._append_line(f"[INFO] [OK] {detail}")
        elif getattr(result, "inconclusive", False):
            # Not a verdict on the device (mitmweb not bound yet / gone, the
            # device still restarting, or no toybox nc): never claim "CANNOT
            # reach" here, and never keep a stale "unreachable" either.
            self._reach_state = "unknown"
            self._cancel_reprobe()
            detail = getattr(result, "detail", "") or "reachability unknown"
            if not quiet:
                self._append_line(f"[INFO] [~] reachability not checked: {detail}")
        elif quiet and previous == "unreachable":
            # Still unreachable on a periodic re-probe: no repeated error.
            self._schedule_reprobe()
        else:
            self._reach_state = "unreachable"
            self._schedule_reprobe()
            self._append_line(
                f"[ERROR] device CANNOT reach mitmproxy at {addr} — traffic "
                "will silently time out (0 flows)"
            )
            hint = getattr(result, "hint", "") or (
                f"device can't reach the proxy at {addr} — check the host IP, "
                "or route via adb reverse in Proxy Settings (y)"
            )
            self._append_line(f"[INFO] [~] {hint}")
        self._refresh_header()

    def _apply_setup_state(
        self, proxy_state: str, proxy_addr: str, ca_ok: bool, ct_ok: bool
    ) -> None:
        self._proxy_state = proxy_state
        self._proxy_addr = proxy_addr
        self._ca_ok = ca_ok
        self._ct_ok = ct_ok
        if self._announce_ca_on_start:
            self._announce_ca_on_start = False
            if self._service.is_running():
                detail = self._ca_detail
                if ca_ok:
                    where = f" ({detail})" if detail else ""
                    self._append_line(f"[INFO] [OK] CA already in trust store{where}")
                elif detail:
                    self._append_line(f"[INFO] [~] {detail} — press Ctrl+N")
                else:
                    self._append_line(
                        "[INFO] [~] no CA in trust store yet — press Ctrl+N to "
                        "install it for HTTPS"
                    )
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
            classify_device_proxy,
        )

        proxy_state, proxy_addr = "none", ""
        ca_ok = ct_ok = False
        try:
            status, cfg = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and cfg is not None:
                proxy_addr = cfg.address
                proxy_state = classify_device_proxy(
                    cfg.ip, cfg.port, self._service.state.proxy_port
                )
        except Exception as exc:
            logger.debug("proxy state probe failed: %s", exc)

        try:
            ca_mgr = CAManager()
            ca_status = ca_mgr.check_zygote_injection_status()
            ca_ok = ca_status.injected
            self._ca_detail = (
                self._ca_where(ca_status) if ca_ok else ca_status.error_message or ""
            )
            if ca_ok:
                stdout, _ = Adb.send_adb_command(
                    "shell ls /data/local/tmp/chrome-command-line 2>/dev/null"
                )
                ct_ok = "chrome-command-line" in (stdout or "")
        except Exception as exc:
            logger.debug("CA state probe failed: %s", exc)

        return proxy_state, proxy_addr, ca_ok, ct_ok

    @staticmethod
    def _ca_where(status) -> str:
        """Short "where/how" note for an injected CA status."""
        where = getattr(status, "location", None) or "Zygote"
        if getattr(status, "fingerprint_verified", False):
            return f"{where}, fingerprint verified"
        return where

    def _set_device_proxy(self) -> None:
        """Ensure the device proxy routes through mitmweb (idempotent).

        Uses the emulator-aware ``resolve_proxy_host_ip`` so the device proxy
        targets the same host the app proxies do (e.g. ``10.0.2.2`` on an
        emulator) instead of the display LAN IP.
        """
        try:
            from sandroid.core.proxy_manager import (
                ProxyManager,
                ProxyStatus,
                resolve_proxy_host_ip,
            )
            from sandroid.services import get_proxy_service

            svc = get_proxy_service()
            host_ip = resolve_proxy_host_ip()
            port = str(self._service.state.proxy_port)
            addr = f"{host_ip}:{port}"

            status, cfg = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and cfg and cfg.address == addr:
                self._proxy_set_by_us = True
                self._service.note_device_proxy(addr)
                self._proxy_state = "ours"
                self._proxy_addr = addr
                self._set_glance_device_proxy(addr)
                self._append_line(f"[INFO] [~] device proxy already {addr}")
                return

            if svc.set_proxy(host_ip, port):
                self._proxy_set_by_us = True
                self._service.note_device_proxy(addr)
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
        """Remove device proxy if we set it (and our adb-reverse tunnel)."""
        if not (self._proxy_set_by_us or self._service.owned_device_proxy):
            return
        try:
            from sandroid.services import get_proxy_service

            svc = get_proxy_service()
            if svc.clear_proxy():
                self._append_line("[INFO] Device proxy cleared")
            self._proxy_set_by_us = False
            self._service.note_device_proxy(None)
            self._proxy_state = "none"
            self._proxy_addr = ""
            self._reach_state = "unknown"
            self._probe_gen += 1  # drop an in-flight probe's verdict
            self._cancel_reprobe()
            self._armed_at = None
            self._set_glance_device_proxy("")
        except Exception as exc:
            logger.warning("Failed to clear device proxy: %s", exc)
            self._append_line(f"[ERROR] Proxy clear: {exc}")
        # Drop our adb-reverse tunnel if we created one (disarm should leave no
        # stale binding behind).
        self._remove_our_reverse()

    def _remove_our_reverse(self) -> None:
        """Remove the ``adb reverse tcp:<proxy_port>`` binding if one is live.

        Owner-agnostic: keyed on the live ``adb reverse --list`` (per-port
        ``--remove``, never ``--remove-all``), so a tunnel created by the Proxy
        modal is still torn down here on disarm/close. No-op when none is
        registered. Best-effort; swallows errors.
        """
        try:
            from sandroid.core.adb import Adb
            from sandroid.core.proxy_manager import _reverse_registered

            port = self._service.state.proxy_port
            if _reverse_registered(port):
                Adb.reverse_remove(f"tcp:{port}")
        except Exception as exc:
            logger.debug("Failed to remove our reverse tunnel: %s", exc)

    def _auto_inject_ca(self) -> None:
        """Install the mitmproxy CA system-wide (no Zygote restart).

        Only host-side work here (finding the CA file); the status check, the
        install and the Chrome CT bypass run on a worker (:meth:`_do_inject_ca`).
        """
        if self._injecting:
            return
        try:
            from sandroid.core.proxy_manager import CAManager, CASource

            certs = CAManager().detect_ca_certificates()
        except Exception as exc:
            logger.warning("Auto CA injection failed: %s", exc)
            self._append_line(f"[ERROR] CA injection: {exc}")
            self._nudge_unpin()
            return
        mitm_cert = next((c for c in certs if c.source == CASource.MITMPROXY), None)
        if not mitm_cert:
            self._append_line(
                "[INFO] No mitmproxy CA cert found. Start mitmproxy once "
                "to generate it (~/.mitmproxy/), then restart."
            )
            self._nudge_unpin()
            return
        self._pending_mitm_cert = mitm_cert.path
        self._do_inject_ca(mitm_cert.path)

    def _on_restart_confirm(self, confirmed: bool) -> None:
        """The user decided on the Zygote-restart fallback."""
        if not confirmed:
            self._append_line("[INFO] CA not installed: Zygote not restarted")
            self._refresh_header()
            self._nudge_unpin()
            return
        self._do_inject_ca(self._pending_mitm_cert, restart=True)

    def _do_inject_ca(self, cert_path, *, restart: bool = False) -> None:
        """Check, install and CT-bypass the CA off the UI thread.

        Without ``restart`` nothing is restarted: an already installed CA is
        only re-checked; otherwise the no-restart install runs. ``restart``
        is the user-confirmed fallback (Zygote restart). Results land in
        :meth:`_apply_inject_result` on the UI thread.
        """
        if self._injecting:
            return  # an injection is already in flight — ignore re-entry
        self._injecting = True
        if restart:
            self._append_line(
                "[INFO] [~] restarting Zygote to install the CA (up to ~2 min)…"
            )
        else:
            self._append_line("[INFO] [~] installing the CA (no Zygote restart)…")

        def _run() -> None:
            ct = None
            try:
                from sandroid.core.proxy_manager import CAManager

                manager = CAManager()
                if restart:
                    from sandroid.services.proxy_restore import (
                        restart_framework_for_ca,
                    )

                    result = restart_framework_for_ca(cert_path)
                else:
                    result = install_or_adopt_ca(manager, cert_path, self._ca_where)
                if result.success and cert_path is not None:
                    ct = manager.bypass_chrome_ct(cert_path)
            except Exception as exc:  # marshal the failure to the UI thread
                result = exc
            try:
                self.app.call_from_thread(
                    self._apply_inject_result, result, cert_path, ct
                )
            except Exception:
                pass

        threading.Thread(target=_run, name="mitm-ca-inject", daemon=True).start()

    def _apply_inject_result(self, result, cert_path, ct=None) -> None:
        """Handle the injection outcome on the UI thread (messages + modals)."""
        # The worker has finished by the time this runs, so the in-flight guard
        # is cleared here — including before the modals so their re-entry
        # into _do_inject_ca can proceed.
        self._injecting = False
        if isinstance(result, Exception):
            logger.warning("Auto CA injection failed: %s", result)
            self._append_line(f"[ERROR] CA injection: {result}")
            self._refresh_header()
            self._kick_state_refresh()
            self._nudge_unpin()
            return
        try:
            if result.success:
                self._ca_ok = True
                self._append_line(f"[INFO] [OK] {result.message}")
                if ct is not None:
                    ct_ok, ct_msg = ct
                    if ct_ok:
                        self._ct_ok = True
                        self._append_line(f"[INFO] {ct_msg}")
                    else:
                        self._append_line(f"[INFO] Chrome CT bypass skipped: {ct_msg}")
                # Only the fallback restarts Zygote (and with it system_server
                # and netd): then re-prove reachability once the device has
                # settled; an immediate probe would report a false "CANNOT
                # reach". The normal install restarts nothing.
                if getattr(result, "restarted", False):
                    if self._proxy_state == "ours" or self._service.owned_device_proxy:
                        self._kick_reachability_probe(
                            settle=True, reason="the Zygote restart"
                        )
                    else:
                        self._kick_settle_watch("the Zygote restart")
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
            elif getattr(result, "restart_required", False):
                from sandroid.tui.modals.confirm_modal import ConfirmModal

                self._append_line(f"[ERROR] {result.message}")
                self.app.push_screen(
                    ConfirmModal(
                        title="Restart Zygote to install the CA?",
                        message=(
                            "The CA could not be installed without a restart on "
                            "this device. Restarting Zygote, the process every "
                            "Android app is forked from, installs it: all "
                            "running apps close, Frida sessions end and System "
                            "UI restarts. The device does NOT reboot, but on a "
                            "busy emulator it can take a minute or more to "
                            "settle.\n\nContinue?"
                        ),
                        yes_label="Restart Zygote",
                        no_label="Cancel",
                    ),
                    self._on_restart_confirm,
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
        if not self._service.ssl_unpin_is_on():
            # Validate spotlight before delegating so we can produce a
            # specific error from inside the panel.
            try:
                from sandroid.services import get_spotlight_service

                spotlight = get_spotlight_service()
                if not spotlight.get_app_tuple():
                    self._append_line(
                        "[ERROR] No spotlight app. "
                        "Press c (use the foreground app) or ⇧C (pick an app…) first."
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
        # Armed counts as on: Ctrl+P disarms an SSL unpin armed for a stopped app.
        was_active = self._service.ssl_unpin_is_on()

        def _job() -> None:
            ok, msg, failed = False, "", False
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(
                    self._service.toggle_ssl_unpin, self._on_unpin_message
                )
                try:
                    ok, msg = future.result(timeout=self._SSL_UNPIN_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    ok, msg, failed = False, "SSL unpin timed out — see logs", True
                    logger.error(
                        "SSL unpin toggle exceeded %.0fs watchdog; abandoning",
                        self._SSL_UNPIN_TIMEOUT,
                    )
            except Exception as exc:
                ok, msg, failed = False, str(exc), True
                logger.warning("SSL unpin toggle failed: %s", exc)
            finally:
                executor.shutdown(wait=False)

            def _report() -> None:
                if failed:
                    self._append_line(f"[ERROR] SSL unpin failed: {msg}")
                elif was_active:
                    self._append_line(f"[INFO] {msg or 'SSL pinning bypass stopped'}")
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
                self._append_line("[INFO] SSL unpin cancelled — frida-server required")
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
        log directly — marshal to the UI thread (mirror _on_service_line).
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
        self._ui.post(self._append_line, line)

    def action_restart(self) -> None:
        # Ctrl+R: restart mitmweb, then re-apply the device proxy against the
        # fresh process. App Proxy lanes survive a restart (they fail closed
        # meanwhile); the service's start reconciles them off-thread.
        device_state, _ = self._probe_proxy_state()

        self._service.restart()

        if device_state == "ours":
            # No external-proxy confirm — the proxy was already ours. Re-runs
            # the idempotent CA/CT re-verify (only prompts if the CA was lost).
            self._arm_device_commit()

        self._append_line("[INFO] Restarted mitmproxy — proxies re-applied")
        self._kick_state_refresh()
        self._refresh_header()

    def action_open_browser(self) -> None:
        """Ctrl+O -- open mitmweb's UI, logged in (its token is in the URL)."""
        if not self._service.is_running():
            self._notify("mitmweb is not running — M starts it", "warning")
            return
        url = self._service.web_url()
        shown = self._service.web_url(with_token=False)
        try:
            opened = webbrowser.open(url)
        except Exception as exc:
            logger.warning("Failed to open browser: %s", exc)
            opened = False
        if not opened:
            self._append_line(f"[ERROR] Could not open a browser — mitmweb UI: {url}")
            self._notify(f"No browser opened — the URL is in the log (` ): {shown}")
            return
        token_note = (
            " (logged in with its token)"
            if self._service.has_web_token
            else " (mitmweb may ask for the token it printed on start)"
        )
        self._append_line(f"[INFO] Opened mitmweb UI {shown}{token_note}")
        self._notify(f"Opened mitmweb UI {shown}{token_note}")

    def _notify(self, message: str, severity: str = "information") -> None:
        try:
            self.app.notify(message, severity=severity, timeout=4)
        except Exception:
            pass

    def action_clear_log(self) -> None:
        """Forget the recent-lines tail (the drawer keeps its own history)."""
        self.recent_lines.clear()

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
                subprocess.Popen(["open", str(target)], stdin=subprocess.DEVNULL)
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)], stdin=subprocess.DEVNULL)
            else:
                webbrowser.open(Path(target).as_uri())
        except Exception as exc:
            logger.warning("Failed to open addons folder %s: %s", target, exc)
