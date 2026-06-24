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
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Import config helpers with a fallback for standalone usage (mirrors
# core/proxy_manager.py).
try:
    from sandroid.config import ConfigLoader, get_config, reset_config_cache
except ImportError:  # pragma: no cover - config package always present in app
    get_config = None
    ConfigLoader = None
    reset_config_cache = None

logger = logging.getLogger(__name__)


# Embedded mitmproxy addon. Written to a temp file at start, loaded with -s.
# Emits compact tagged lines on mitmweb's stdout. The TUI panel parses them.
_ADDON_SOURCE = r'''
"""Sandroid TUI logging addon for mitmweb.

Tag format on stdout:
    [FLOW]|HH:MM:SS|protocol|status|method|host_and_path|size_str|app
    [TLS_FAIL]|HH:MM:SS|host_or_sni|short_reason|app

`protocol` is a compact token like "HTTPS/2", "HTTP/1.1", "WS", "WSS".
`app` is the focused package the flow was attributed to (empty when not in a
Focus lane). Attribution uses the lane's SOCKS5 listen port as the key into a
sidecar map written by FocusManager and pointed to by SANDROID_FOCUS_MAP.
"""
from __future__ import annotations

import json
import os
import time
from mitmproxy import http
from mitmproxy import tls as _tls


# Cache of the sidecar lane→app map, re-read only when the file's mtime
# changes. Shape: {"8082": {"package": "com.foo", "marker": ":green_circle:"}}.
_FOCUS_MAP: dict = {}
_FOCUS_MTIME: float = -1.0


def _focus_map() -> dict:
    """Return the lane→app map, re-reading the sidecar file on mtime change.

    Tolerates a missing/unset path and invalid JSON by returning an empty map.
    """
    global _FOCUS_MAP, _FOCUS_MTIME
    path = os.environ.get("SANDROID_FOCUS_MAP")
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _FOCUS_MAP = {}
        _FOCUS_MTIME = -1.0
        return _FOCUS_MAP
    if mtime != _FOCUS_MTIME:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            _FOCUS_MAP = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            _FOCUS_MAP = {}
        _FOCUS_MTIME = mtime
    return _FOCUS_MAP


def _lane_entry(proxy_mode) -> dict | None:
    """Map a connection's proxy_mode to its sidecar entry, or None.

    Defensive: a flow on a non-lane mode (e.g. regular) or any attribute/lookup
    error yields None so the caller degrades to app="" and never throws.
    """
    try:
        port = proxy_mode.listen_port()
    except Exception:
        return None
    entry = _focus_map().get(str(port))
    return entry if isinstance(entry, dict) else None


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

        # Per-flow app attribution via the arrival SOCKS lane port. Any failure
        # degrades to app="" and never breaks emission.
        app = ""
        try:
            entry = _lane_entry(flow.client_conn.proxy_mode)
            if entry is not None:
                app = entry.get("package") or ""
                flow.comment = app
                flow.metadata["sandroid_app"] = app
                flow.marked = entry.get("marker") or ""
        except Exception:
            app = ""

        line = "|".join((
            "[FLOW]",
            _ts(),
            _protocol(flow),
            str(flow.response.status_code),
            (flow.request.method or "?")[:4],
            _host_path(flow.request),
            _size(body_len),
            app,
        ))
        print(line, flush=True)

    def tls_failed_client(self, data: _tls.TlsData) -> None:
        host = "?"
        app = ""
        try:
            client = data.context.client
            host = getattr(client, "sni", None) or "?"
            if host == "?":
                addr = getattr(client, "peername", None) or getattr(client, "address", None)
                if addr:
                    host = addr[0] if isinstance(addr, tuple) else str(addr)
            # No flow exists here, so we can only label the emitted line.
            entry = _lane_entry(getattr(client, "proxy_mode", None))
            if entry is not None:
                app = entry.get("package") or ""
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
        print(f"[TLS_FAIL]|{_ts()}|{host}|{reason}|{app}", flush=True)


addons = [SandroidLogger()]
'''


# Markdown written into the user addons dir on first run (drop-in instructions
# plus a security warning).
_ADDON_README = """\
# Sandroid mitmproxy addons

Drop a `.py` mitmproxy addon into this folder, then pick it from the addons
checklist in the Sandroid TUI (the mitmproxy panel, `Ctrl+A`). Only the addons
you enable are loaded into mitmweb via `-s`.

## How it works

- Any top-level `*.py` file in this folder is scanned and offered in the
  checklist. The `examples/` subfolder is **ignored** by the scanner — use it
  for templates and snippets you do not want auto-listed.
- A project-local `./mitm_addons/` folder (relative to where Sandroid runs) is
  scanned too, so you can keep per-project addons next to your work.
- Editing an already-loaded addon **hot-reloads** it with no restart and no
  dropped flows. Adding or removing *which* addons load triggers a mitmweb
  restart.

## Minimal addon

```python
from mitmproxy import http


class MyAddon:
    def response(self, flow: http.HTTPFlow) -> None:
        print(f"saw {flow.request.pretty_url}", flush=True)


addons = [MyAddon()]
```

See `examples/example_logger.py` for a working template.

## SECURITY WARNING

mitmproxy addons are **arbitrary Python** that runs in-process at the
**privileges of the proxy** (i.e. your user account). A malicious or buggy
addon can read/write files, open network connections, and execute commands.
Only load addons you wrote or fully trust. Treat third-party addons like any
other code you would run on your machine.
"""


# Minimal working addon template written to ``examples/example_logger.py`` on
# first run. Mirrors the internal logger's shape so users have a real starting
# point.
_EXAMPLE_ADDON = '''\
"""Example mitmproxy addon: log each response to stdout.

Copy this file up one level (into the addons folder) and enable it from the
Sandroid mitmproxy panel (Ctrl+A) to load it.
"""
from __future__ import annotations

from mitmproxy import http


class ExampleLogger:
    """Logs a single line for every HTTP response that passes through."""

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        print(
            f"[example] {flow.request.method} {flow.request.pretty_url} "
            f"-> {flow.response.status_code}",
            flush=True,
        )


addons = [ExampleLogger()]
'''


@dataclass
class ReachabilityResult:
    """Outcome of a device→mitmproxy end-to-end reachability probe.

    Attributes:
        reachable: True when the device's HTTP round-trip through the proxy
            produced a mitmproxy response (``"HTTP/"`` in the device output).
        flows_incremented: True when ``flows_seen`` rose during the probe —
            independent host-side proof the proxy counted the flow.
        detail: A short human-readable summary for the log.
        hint: An optional remediation hint (e.g. check the host IP / route via
            adb reverse), or ``""`` when none applies.
    """

    reachable: bool
    flows_incremented: bool
    detail: str
    hint: str = ""


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
    socks_base: int = 8082
    focus_lanes: int = 5
    capture_scope: str = "none"
    focus_apps: list[str] = field(default_factory=list)


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
        # User-supplied addon configuration. ``_user_addons_dir`` is the
        # configured drop-in folder; ``_enabled_addons`` is the cached,
        # resolved list of addons to load (kept off the hot path). The
        # project-local ``./mitm_addons/`` dir is deliberately NOT cached
        # here — it is resolved at scan time so a lazily-built singleton does
        # not freeze to the wrong CWD.
        self._user_addons_dir: Path = Path(
            "~/.config/sandroid/mitm_addons/"
        ).expanduser()
        self._enabled_addons: list[Path] = []
        self._load_config()
        # SSL unpin is owned by the process-wide BypassService (category
        # "ssl") so every surface — mitm panel, Ctrl+P, the Spotlight panel —
        # toggles the same manager instance. These methods are thin forwards.
        # We only auto-tear-down SSL on mitmweb stop when *we* started it.
        self._ssl_via_mitm: bool = False
        atexit.register(self._atexit_cleanup)

    @property
    def state(self) -> MitmproxyState:
        return self._state

    @property
    def user_addons_dir(self) -> Path:
        """The configured user addons directory."""
        return self._user_addons_dir

    def _load_config(self) -> None:
        """Load addons dir, enabled addons, and ports from config.

        Best-effort: on any failure the defaults set in ``__init__`` stand and
        a warning is logged. Never raises.
        """
        if get_config is None:
            return
        try:
            cfg = get_config().mitmproxy
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load mitmproxy config: %s", exc)
            return
        self._user_addons_dir = Path(cfg.addons_dir).expanduser()
        resolved: list[Path] = []
        seen: set[Path] = set()
        for entry in cfg.enabled_addons:
            p = Path(entry).expanduser().resolve()
            if p not in seen:
                seen.add(p)
                resolved.append(p)
        self._enabled_addons = resolved
        # Focus capture-scope settings (lane pool is allocated at start()).
        # ``focus_apps`` is intentionally left empty at load — FocusManager is
        # authoritative for live lane assignments.
        self._state.socks_base = cfg.socks_base
        self._state.focus_lanes = cfg.focus_lanes
        self._state.capture_scope = cfg.capture_scope

    @staticmethod
    def _focus_sidecar_path() -> str:
        """Resolve the expanded Focus sidecar map path from config.

        Falls back to the default cache location if config is unavailable.
        """
        default = os.path.expanduser("~/.cache/sandroid/focus_lanes.json")
        if get_config is None:
            return default
        try:
            return os.path.expanduser(get_config().focus.sidecar_path)
        except Exception:  # pragma: no cover - defensive
            return default

    def _ensure_addons_dir(self) -> None:
        """First-run scaffold for the user addons directory.

        Creates the directory and, if missing, writes a ``README.md`` with
        drop-in instructions plus a security warning, and an
        ``examples/example_logger.py`` template. Best-effort: logs a warning
        and returns on any failure. Never raises; never blocks startup.
        """
        try:
            self._user_addons_dir.mkdir(parents=True, exist_ok=True)
            readme = self._user_addons_dir / "README.md"
            if not readme.exists():
                readme.write_text(_ADDON_README, encoding="utf-8")
            examples = self._user_addons_dir / "examples"
            examples.mkdir(parents=True, exist_ok=True)
            example_addon = examples / "example_logger.py"
            if not example_addon.exists():
                example_addon.write_text(_EXAMPLE_ADDON, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to scaffold addons dir: %s", exc)

    def list_available_addons(self) -> list[Path]:
        """Scan the user and project-local dirs for addon scripts.

        Scans two locations: the configured user addons dir and
        ``Path.cwd() / "mitm_addons"`` (evaluated here, not cached). For each
        that is a directory, collects top-level ``*.py`` files (non-recursive,
        so an ``examples/`` subdir is excluded), resolves them, and dedupes by
        resolved path with user-dir entries taking precedence. Missing dirs are
        tolerated.

        Returns:
            Resolved, deduplicated absolute paths of available addon scripts.
        """
        self._ensure_addons_dir()
        locations = [self._user_addons_dir, Path.cwd() / "mitm_addons"]
        results: list[Path] = []
        seen: set[Path] = set()
        for location in locations:
            try:
                if not location.is_dir():
                    continue
                for py_file in location.glob("*.py"):
                    resolved = py_file.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        results.append(resolved)
            except OSError as exc:
                logger.warning("Failed to scan addons dir %s: %s", location, exc)
        return results

    def get_enabled_addons(self) -> list[Path]:
        """Return the cached, resolved list of enabled addons.

        Cheap: reads from the in-memory cache, no disk I/O on the hot path.
        """
        return list(self._enabled_addons)

    def set_enabled_addons(self, paths: list) -> bool:
        """Set which addons load, persist the choice, and restart if running.

        Resolves and dedupes ``paths``, updates the in-memory cache, persists
        to config (best-effort), and — if mitmweb is running — restarts it with
        the current ports so the new addon set takes effect.

        Args:
            paths: Addon paths (str or Path) to enable.

        Returns:
            True if mitmweb was restarted as a result, False otherwise.
        """
        resolved: list[Path] = []
        seen: set[Path] = set()
        for entry in paths:
            p = Path(entry).expanduser().resolve()
            if p not in seen:
                seen.add(p)
                resolved.append(p)
        self._enabled_addons = resolved

        if ConfigLoader is not None and reset_config_cache is not None:
            try:
                ConfigLoader().load_and_update_section(
                    "mitmproxy",
                    {"enabled_addons": [str(p) for p in resolved]},
                )
                reset_config_cache()
            except Exception as exc:
                logger.warning("Failed to persist enabled addons: %s", exc)

        if self.is_running():
            self.restart(
                proxy_port=self._state.proxy_port,
                web_port=self._state.web_port,
                web_host=self._state.web_host,
            )
            return True
        return False

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def capture_view(self) -> dict:
        """Snapshot both proxy layers from ground truth (NOT the stored mode).

        Returns the Device Proxy and App Proxies derived from reality:

            {
                "mitmweb_running": bool,
                "mitmweb_addr": "host_ip:port",      # our proxy, even if stopped
                "device": {
                    "state": "ours" | "external" | "none",
                    "addr":  "ip:port" | "",         # set unless "none"
                },
                "apps": {package: "ours" | "http://ip:port", ...},
            }

        The device classification uses the shared ``classify_device_proxy``
        helper (the same rule the panel's classifiers use): ``ours`` iff the
        port matches our proxy port AND the ip is the resolved host IP (or
        ``127.0.0.1`` while our adb-reverse tunnel is registered); any other
        set value is ``external``; unset is ``none``.

        WARNING: reads the device http_proxy over ADB (blocking). Call this OFF
        the UI thread. The app layer (``app_proxies``) is a cheap in-process
        read; this method bundles both so callers get a consistent snapshot.
        """
        from sandroid.core.proxy_manager import (
            ProxyManager,
            ProxyStatus,
            classify_device_proxy,
            get_focus_manager,
        )

        try:
            host_ip = ProxyManager.get_host_ip()
        except Exception:
            host_ip = ""
        proxy_port = self.state.proxy_port
        mitmweb_addr = f"{host_ip}:{proxy_port}" if host_ip else ""

        device = {"state": "none", "addr": ""}
        try:
            status, cfg = ProxyManager().get_proxy_settings()
            if status == ProxyStatus.SET and cfg is not None:
                ours = classify_device_proxy(cfg.ip, cfg.port, proxy_port) == "ours"
                device = {
                    "state": "ours" if ours else "external",
                    "addr": cfg.address,
                }
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("capture_view device probe failed: %s", exc)

        try:
            apps = get_focus_manager().app_proxies()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("capture_view app probe failed: %s", exc)
            apps = {}

        return {
            "mitmweb_running": self.is_running(),
            "mitmweb_addr": mitmweb_addr,
            "device": device,
            "apps": apps,
        }

    def probe_device_reachability(
        self, host: str, port: int, *, timeout: int = 4
    ) -> ReachabilityResult:
        r"""Prove the device can actually reach our mitmproxy at ``host:port``.

        ``set_proxy`` only verifies the proxy *string* was written, never that
        the device can reach it. The auto-detected host IP can be unreachable
        from the device, so the device silently times out (0 flows) while the
        header reads green. This fires a real device→proxy round-trip and
        cross-checks ``flows_seen`` for end-to-end proof.

        Two independent signals (so an ``nc`` quirk alone can't flip the
        verdict):

        1. Device bytes — a forced-HTTP request through the proxy to
           ``http://mitm.it/`` (mitmproxy's onboarding addon answers it itself,
           offline, even with no upstream). Reachable iff stdout is non-empty
           AND contains ``"HTTP/"`` (NOT the ``nc`` exit code — unreliable).
        2. Host counter — ``flows_seen`` rising during the probe is independent
           proof the proxy received and counted the flow.

        QUOTING: ``Adb.send_adb_command`` runs the whole string through the host
        shell (``shell=True``), so the device-side pipe + ``printf`` ``\\r\\n``
        escapes are wrapped in a single double-quoted ``shell "..."`` argument so
        the *device* shell interprets them; a bare pipe would be split by the
        host shell. ``toybox nc`` closes the socket on stdin EOF before the reply
        arrives, so we hold stdin open with ``{ ...; sleep N; }`` — do NOT
        simplify it back to a bare pipe or stdout comes back empty.

        WARNING: blocking (one device round-trip + a short settle poll). Call
        this OFF the UI thread.

        Args:
            host: Proxy host the device is pointed at (the resolved host IP, or
                ``127.0.0.1`` when routed via adb reverse).
            port: Proxy port.
            timeout: ``nc`` connect/read timeout in seconds.

        Returns:
            A :class:`ReachabilityResult`.
        """
        from sandroid.core.adb import Adb

        before = self._state.flows_seen
        addr = f"{host}:{port}"
        request = (
            "GET http://mitm.it/ HTTP/1.1\\r\\n"
            "Host: mitm.it\\r\\n"
            "Connection: close\\r\\n\\r\\n"
        )
        # toybox nc closes the socket on stdin EOF before the reply arrives
        # (-w is a connect timeout, not a read timeout; -q doesn't keep the
        # read side alive on this build). Hold stdin open with `sleep` so nc
        # reads the response — a bare pipe yields empty stdout (false negative).
        inner = (
            f"{{ printf '{request}'; sleep 2; }} | "
            f"toybox nc -w {timeout} {host} {port}"
        )
        try:
            out, _ = Adb.send_adb_command(f'shell "{inner}"')
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("reachability probe failed: %s", exc)
            out = ""
        got_http = bool((out or "").strip()) and "HTTP/" in (out or "")

        # Short settle poll (~0.3s x5, mirroring _wait_listening cadence) so a
        # just-counted flow has a moment to land before we re-read.
        after = self._state.flows_seen
        for _ in range(5):
            if self._state.flows_seen > before:
                break
            time.sleep(0.3)
            after = self._state.flows_seen
        flows_incremented = after > before

        reachable = got_http or flows_incremented
        if reachable:
            detail = f"device→mitmproxy reachable ({addr})"
            hint = ""
        else:
            detail = f"device CANNOT reach mitmproxy at {addr}"
            hint = (
                f"device can't reach the proxy at {addr} — check the host IP, "
                "or route via adb reverse in Proxy Settings (y)"
            )
        return ReachabilityResult(
            reachable=reachable,
            flows_incremented=flows_incremented,
            detail=detail,
            hint=hint,
        )

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

            # Override-on-default: when the caller used the signature defaults
            # (i.e. did not pass explicit ports), pull ports from config. This
            # keeps explicit-int callers like restart()/set_verbose() working
            # unchanged while honouring [mitmproxy] config for fresh starts.
            if (
                proxy_port == 8080
                and web_port == 8081
                and web_host == "127.0.0.1"
                and get_config is not None
            ):
                try:
                    cfg = get_config().mitmproxy
                    proxy_port = cfg.proxy_port
                    web_port = cfg.web_port
                    web_host = cfg.web_host
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("Failed to read mitmproxy ports: %s", exc)

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

            # Append user-enabled addons AFTER the internal logger so the
            # logger stays first and _read_loop's [FLOW]|/[TLS_FAIL]| parsing
            # is unaffected. Missing addons are skipped (not fatal).
            for addon in self._enabled_addons:
                if addon.exists():
                    cmd += ["-s", str(addon)]
                else:
                    self._emit(f"[INFO] Skipping missing addon: {addon}")
                    logger.warning("Skipping missing addon: %s", addon)

            # Allocate the Focus lane pool: one regular listener plus one SOCKS5
            # listener per lane. mitmweb accepts multiple --mode at once; the
            # arrival SOCKS port is the per-app attribution key (see addon).
            cmd += ["--mode", "regular"]
            for i in range(self._state.focus_lanes):
                cmd += ["--mode", f"socks5@{self._state.socks_base + i}"]

            # The addon reads the lane→app sidecar map from this env var; the
            # path is stable even as the map contents change at runtime.
            sidecar_path = self._focus_sidecar_path()

            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    text=True,
                    env={**os.environ, "SANDROID_FOCUS_MAP": sidecar_path},
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

            # Tear down any active Focus lanes so stopping the proxy never
            # leaves an app's network redirected at a dead SOCKS port. Lazy
            # import avoids a proxy_manager↔service import cycle. disable_focus()
            # with no active lanes is a harmless no-op.
            try:
                from sandroid.core.proxy_manager import get_focus_manager

                get_focus_manager().disable_focus()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Focus teardown on stop failed: %s", exc)

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
