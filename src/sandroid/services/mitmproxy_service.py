"""Service that manages an embedded mitmweb subprocess.

This is the engine side of Sandroid's mitmproxy integration. The actual
interactive flow inspection happens in mitmweb's web UI; the TUI panel
controls lifecycle and tails the log.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# Embedded mitmproxy addon. Written to a temp file at start, loaded with -s.
# Emits compact tagged lines on mitmweb's stdout. The TUI panel parses them.
_ADDON_SOURCE = r'''
"""Sandroid TUI logging addon for mitmweb.

Tag format on stdout:
    [FLOW]|HH:MM:SS|protocol|status|method|host_and_path|size_str
    [TLS_FAIL]|HH:MM:SS|host_or_sni|short_reason

`protocol` is a compact token like "HTTPS/2", "HTTP/1.1", "WS", "WSS".
"""
from __future__ import annotations

import time
from mitmproxy import http
from mitmproxy import tls as _tls


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _size(n) -> str:
    if not n:
        return "0 B"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _host_path(req: http.Request, maxlen: int = 40) -> str:
    host = req.pretty_host or "?"
    path = req.path or "/"
    s = f"{host}{path}"
    if len(s) > maxlen:
        s = s[: maxlen - 1] + "…"
    return s


def _protocol(flow: http.HTTPFlow) -> str:
    """Compact protocol token: scheme + HTTP version, or WS/WSS for WebSocket."""
    req = flow.request
    scheme = (req.scheme or "http").lower()
    is_tls = scheme == "https" or scheme == "wss"
    if getattr(flow, "websocket", None) is not None:
        return "WSS" if is_tls else "WS"
    ver = (req.http_version or "").replace("HTTP/", "")
    base = "HTTPS" if is_tls else "HTTP"
    return f"{base}/{ver}" if ver else base


class SandroidLogger:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        body_len = len(flow.response.raw_content) if flow.response.raw_content else 0
        line = "|".join((
            "[FLOW]",
            _ts(),
            _protocol(flow),
            str(flow.response.status_code),
            (flow.request.method or "?")[:4],
            _host_path(flow.request),
            _size(body_len),
        ))
        print(line, flush=True)

    def tls_failed_client(self, data: _tls.TlsData) -> None:
        host = "?"
        try:
            client = data.context.client
            host = getattr(client, "sni", None) or "?"
            if host == "?":
                addr = getattr(client, "peername", None) or getattr(client, "address", None)
                if addr:
                    host = addr[0] if isinstance(addr, tuple) else str(addr)
        except Exception:
            pass
        reason = "tls"
        try:
            err = getattr(data.conn, "error", "") or ""
            err_lc = str(err).lower()
            if "certificate" in err_lc or "cert" in err_lc:
                reason = "cert"
            elif "version" in err_lc:
                reason = "ver"
        except Exception:
            pass
        print(f"[TLS_FAIL]|{_ts()}|{host}|{reason}", flush=True)


addons = [SandroidLogger()]
'''


@dataclass
class MitmproxyState:
    """Runtime state visible to UI consumers."""

    running: bool = False
    proxy_port: int = 8080
    web_port: int = 8081
    web_host: str = "127.0.0.1"
    pid: int | None = None
    flows_seen: int = 0
    tls_failures: int = 0
    verbose: bool = False
    last_error: str | None = None
    ssl_unpin_active: bool = False
    ssl_unpin_app: str | None = None


class MitmproxyService:
    """Manages a single mitmweb subprocess.

    Only one instance may run at a time. ``start`` while running is a
    no-op and records the reason in ``state.last_error``; ``stop`` is
    idempotent. Subscribers added via ``add_listener`` receive raw output
    lines from a background reader thread.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._listeners: list[Callable[[str], None]] = []
        self._state = MitmproxyState()
        self._addon_path: str | None = None
        # SSL unpin is owned by the process-wide BypassService (category
        # "ssl") so every surface — mitm panel, Ctrl+P, the Spotlight panel —
        # toggles the same manager instance. These methods are thin forwards.
        # We only auto-tear-down SSL on mitmweb stop when *we* started it.
        self._ssl_via_mitm: bool = False
        atexit.register(self._atexit_cleanup)

    @property
    def state(self) -> MitmproxyState:
        return self._state

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def add_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[str], None]) -> None:
        try:
            self._listeners.remove(callback)
        except ValueError:
            pass

    def web_url(self) -> str:
        return f"http://{self._state.web_host}:{self._state.web_port}/"

    def start(
        self,
        proxy_port: int = 8080,
        web_port: int = 8081,
        web_host: str = "127.0.0.1",
    ) -> bool:
        with self._lock:
            if self.is_running():
                self._state.last_error = "already running"
                return False

            binary = shutil.which("mitmweb")
            if binary is None:
                self._state.last_error = (
                    "mitmweb not found on PATH (pip install mitmproxy)"
                )
                self._emit(f"[ERROR] {self._state.last_error}")
                return False

            self._write_addon()
            verbosity = "info" if self._state.verbose else "warn"
            cmd = [
                binary,
                "--listen-port",
                str(proxy_port),
                "--web-port",
                str(web_port),
                "--web-host",
                web_host,
                "--no-web-open-browser",
                "--set",
                f"termlog_verbosity={verbosity}",
            ]
            if self._addon_path:
                cmd += ["-s", self._addon_path]

            try:
                self._proc = subprocess.Popen(  # noqa: S603
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    text=True,
                )
            except Exception as exc:
                self._state.last_error = f"spawn failed: {exc}"
                logger.exception("Failed to spawn mitmweb")
                self._emit(f"[ERROR] {self._state.last_error}")
                return False

            self._state.running = True
            self._state.proxy_port = proxy_port
            self._state.web_port = web_port
            self._state.web_host = web_host
            self._state.pid = self._proc.pid
            self._state.last_error = None
            self._state.flows_seen = 0
            self._state.tls_failures = 0

            self._reader_thread = threading.Thread(
                target=self._read_loop,
                name="mitmweb-reader",
                daemon=True,
            )
            self._reader_thread.start()

            self._emit(
                f"[INFO] mitmweb started "
                f"(proxy :{proxy_port}, web http://{web_host}:{web_port}/)"
            )
            return True

    def stop(self, timeout: float = 3.0) -> None:
        with self._lock:
            proc = self._proc
            if proc is None:
                return

            # Tear down SSL unpin alongside mitmweb so we don't leak a
            # Frida job pointing at a (possibly dead) spotlight process —
            # but only the bypass *we* started, not one toggled elsewhere.
            if self._ssl_via_mitm:
                self.stop_ssl_unpin()

            self._state.running = False
            self._emit("[INFO] Stopping mitmweb...")

            try:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1.0)
            except Exception as exc:
                logger.warning("Error stopping mitmweb: %s", exc)
            finally:
                self._proc = None
                self._state.pid = None
                self._cleanup_addon()

            self._emit("[INFO] mitmweb stopped")

    def restart(self, **kwargs) -> bool:
        self.stop()
        return self.start(**kwargs)

    def set_verbose(self, verbose: bool) -> None:
        """Toggle mitmweb's own log chatter (TCP/TLS plumbing).

        Always emits the structured flow lines via the addon; this just
        controls whether mitmweb's built-in INFO output is also shown.
        Restarts the subprocess so the new verbosity takes effect.
        """
        if self._state.verbose == verbose:
            return
        self._state.verbose = verbose
        if self.is_running():
            self.restart(
                proxy_port=self._state.proxy_port,
                web_port=self._state.web_port,
                web_host=self._state.web_host,
            )

    # ── SSL pinning bypass (forwards to BypassService) ────────────────

    @staticmethod
    def _bypass_service():
        from sandroid.analysis.detection_bypass import get_bypass_service

        return get_bypass_service()

    def ssl_unpin_is_active(self) -> bool:
        return self._bypass_service().is_active("ssl")

    def ssl_unpin_target(self) -> str | None:
        return self._bypass_service().target_app("ssl")

    def start_ssl_unpin(
        self,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Start SSL pinning bypass for the current spotlight app.

        Idempotent: returns success with an "already running" message if a
        bypass job is already active. Delegates to the process-wide
        BypassService so the manager survives TUI screen changes.

        The (possibly slow, readiness-blocking) ``svc.start`` call runs OUTSIDE
        ``self._lock`` — state is snapshotted under the lock first, then applied
        under the lock after — so header rendering (``is_running``) never stalls
        behind a Frida load. Mirrors task_service's "callback outside lock".
        """
        svc = self._bypass_service()
        with self._lock:
            # Only claim ownership for auto-teardown if mitmweb is actually
            # running now — SSL toggled standalone (Ctrl+P with mitmweb down)
            # must survive a later, unrelated mitmweb stop.
            owns = self.is_running()
            if svc.is_active("ssl"):
                target = svc.target_app("ssl") or "spotlight app"
                msg = f"SSL unpin already active for {target}"
                self._ssl_via_mitm = self._ssl_via_mitm or owns
                self._state.ssl_unpin_active = True
                self._state.ssl_unpin_app = svc.target_app("ssl")
                self._emit(f"[INFO] {msg}")
                return True, msg

        try:
            success, msg = svc.start("ssl", on_message=on_message)
        except Exception as exc:
            logger.exception("SSL unpin start raised")
            return False, str(exc)

        with self._lock:
            if success:
                self._ssl_via_mitm = owns
                self._state.ssl_unpin_active = True
                self._state.ssl_unpin_app = svc.target_app("ssl")
                self._emit(f"[INFO] {msg}")
            else:
                self._state.ssl_unpin_active = False
                self._state.ssl_unpin_app = None
                self._emit(f"[ERROR] SSL unpin failed: {msg}")
        return success, msg

    def stop_ssl_unpin(self) -> bool:
        """Stop SSL pinning bypass. Idempotent.

        Like ``start_ssl_unpin``, the BypassService call runs outside the lock.
        """
        svc = self._bypass_service()
        stopped = svc.stop("ssl")
        with self._lock:
            self._ssl_via_mitm = False
            self._state.ssl_unpin_active = False
            self._state.ssl_unpin_app = None
            if stopped:
                self._emit("[INFO] SSL pinning bypass stopped")
        return stopped

    def toggle_ssl_unpin(
        self,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Toggle SSL unpin. Returns (now_active, message)."""
        if self.ssl_unpin_is_active():
            self.stop_ssl_unpin()
            return False, "SSL pinning bypass stopped"
        return self.start_ssl_unpin(on_message=on_message)

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for raw in proc.stdout:
                line = raw.rstrip("\n")
                if not line:
                    continue
                # Structured tags emitted by our embedded addon
                if line.startswith("[FLOW]|"):
                    self._state.flows_seen += 1
                elif line.startswith("[TLS_FAIL]|"):
                    self._state.tls_failures += 1
                self._emit(line)
        except Exception as exc:
            logger.debug("mitmweb reader exited: %s", exc)
        finally:
            with self._lock:
                if self._proc is not None and self._proc.poll() is not None:
                    self._state.running = False
                    self._state.pid = None
                    self._emit("[INFO] mitmweb exited")

    def _emit(self, line: str) -> None:
        for cb in list(self._listeners):
            try:
                cb(line)
            except Exception:
                logger.exception("mitmweb listener failed")

    def _atexit_cleanup(self) -> None:
        try:
            if self.is_running():
                self.stop(timeout=1.0)
        except Exception:
            pass
        self._cleanup_addon()

    def _write_addon(self) -> None:
        try:
            fd, path = tempfile.mkstemp(prefix="sandroid_mitm_", suffix=".py")
            with os.fdopen(fd, "w") as f:
                f.write(_ADDON_SOURCE)
            self._addon_path = path
        except Exception as exc:
            logger.warning("Failed to write addon: %s", exc)
            self._addon_path = None

    def _cleanup_addon(self) -> None:
        path = self._addon_path
        self._addon_path = None
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


_INSTANCE: MitmproxyService | None = None
_INSTANCE_LOCK = threading.Lock()


def get_mitmproxy_service() -> MitmproxyService:
    """Module-level accessor for the singleton MitmproxyService."""
    global _INSTANCE
    if _INSTANCE is None:
        with _INSTANCE_LOCK:
            if _INSTANCE is None:
                _INSTANCE = MitmproxyService()
    return _INSTANCE
