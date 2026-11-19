"""Service that manages an embedded mitmweb subprocess.

This is the engine side of Sandroid's mitmproxy integration. The actual
interactive flow inspection happens in mitmweb's web UI; the TUI panel
controls lifecycle and tails the log.
"""

from __future__ import annotations

import atexit
import logging
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

# Import config helpers with a fallback for standalone usage (mirrors
# core/proxy_manager.py).
try:
    from sandroid.config import get_config, update_config
except ImportError:  # pragma: no cover - config package always present in app
    get_config = None
    update_config = None

logger = logging.getLogger(__name__)


# Embedded mitmproxy addon. Written to a temp file at start, loaded with -s.
# Emits compact tagged lines on mitmweb's stdout. The TUI panel parses them.
_ADDON_SOURCE = r'''
"""Sandroid TUI logging addon for mitmweb.

Tag format on stdout:
    [FLOW]|HH:MM:SS|protocol|status|method|host_and_path|size_str|app
    [TLS_FAIL]|HH:MM:SS|host_or_sni|short_reason|app
    [FLOW_ERR]|HH:MM:SS|host_and_path|reason|app

`protocol` is a compact token like "HTTPS/2", "HTTP/1.1", "WS", "WSS".
`app` is the focused package the flow was attributed to (empty when not in a
Focus lane). Attribution uses the lane's SOCKS5 listen port as the key into a
sidecar map written by FocusManager and pointed to by SANDROID_FOCUS_MAP.

Structured flow log (Track 2): every completed or errored flow is also
appended as a JSON record to SANDROID_FLOW_LOG (empty/unset disables this at
zero cost), with a full-headers/capped-body detail file alongside it. See
_append_flow_record's docstring for the on-disk layout and the write-safety
property that makes clearing the log safe while mitmweb keeps running.
"""
from __future__ import annotations

import base64
import json
import os
import time
from mitmproxy import http
from mitmproxy import tls as _tls


# Cache of the sidecar lane→app map, re-read only when the file's mtime
# changes. Shape: {"8082": {"package": "com.foo", "marker": ":green_circle:"}}.
_FOCUS_MAP: dict = {}
_FOCUS_MTIME: float = -1.0

# Monotonic per-flow sequence counter, resumed once per addon-process-load
# (see _resume_seq). Never reset by clear_captured_flows -- that is exactly
# the point (see _resume_seq's docstring).
_SEQ: dict = {"n": 0, "initialized": False}

# In-memory flows.jsonl line count, lazily initialized once per addon-
# process-load (one real file read) and then updated in memory on every
# append/trim -- _maybe_trim used to re-`readlines()` the entire file on
# EVERY single flow just to learn its current length, which turns into an
# O(current file size) cost on every flow once traffic has passed
# max_stored_flows. Keyed by log_path so a mid-process device/session switch
# (a fresh path) re-measures rather than reusing a stale count.
_LINE_COUNT: dict[str, int] = {}

# Env vars are read once and cached -- they never change for the lifetime of
# one mitmweb subprocess (a config change takes effect on the next restart,
# which is a fresh addon load with fresh globals anyway).
_FLOW_LOG_PATH: str | None = None
_FLOW_MAX_STORED: int | None = None
_FLOW_MAX_BODY_BYTES: int | None = None


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
    if ver in ("2.0", "3.0"):
        ver = ver[0]
    base = "HTTPS" if is_tls else "HTTP"
    return f"{base}/{ver}" if ver else base


def _attribute_and_tag(flow: http.HTTPFlow) -> str:
    """Attribute a flow to its Focus app and tag it, degrading to app="".

    Shared by response() and error() so this per-flow app-attribution logic
    (arrival SOCKS lane port -> sidecar map -> flow.comment/metadata/marked)
    lives in exactly one place. Any failure degrades to app="" and never
    raises -- never breaks emission of the flow itself.
    """
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
    return app


def _flow_log_path() -> str:
    global _FLOW_LOG_PATH
    if _FLOW_LOG_PATH is None:
        _FLOW_LOG_PATH = os.environ.get("SANDROID_FLOW_LOG", "")
    return _FLOW_LOG_PATH


def _flow_max_stored() -> int:
    global _FLOW_MAX_STORED
    if _FLOW_MAX_STORED is None:
        try:
            _FLOW_MAX_STORED = int(os.environ.get("SANDROID_FLOW_MAX_STORED", "5000"))
        except ValueError:
            _FLOW_MAX_STORED = 5000
    return _FLOW_MAX_STORED


def _flow_max_body_bytes() -> int:
    global _FLOW_MAX_BODY_BYTES
    if _FLOW_MAX_BODY_BYTES is None:
        try:
            _FLOW_MAX_BODY_BYTES = int(
                os.environ.get("SANDROID_FLOW_MAX_BODY_BYTES", "65536")
            )
        except ValueError:
            _FLOW_MAX_BODY_BYTES = 65536
    return _FLOW_MAX_BODY_BYTES


def _details_dir(log_path: str) -> str:
    return os.path.join(os.path.dirname(log_path), "details")


def _meta_path(log_path: str) -> str:
    return os.path.join(os.path.dirname(log_path), "meta.json")


def _read_meta(log_path: str) -> dict:
    try:
        with open(_meta_path(log_path), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _write_meta(log_path: str, meta: dict) -> None:
    """Write meta.json atomically (temp file + os.replace).

    meta.json is read on every addon (re)load to resume `seq` (see
    _resume_seq) and by the reader module to detect a retention trim -- a
    process killed mid-write must never leave it half-written.
    """
    meta_path = _meta_path(log_path)
    tmp_path = f"{meta_path}.tmp-{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)
        os.replace(tmp_path, meta_path)
    except OSError:
        pass


def _resume_seq(log_path: str) -> None:
    """Resume the `seq` counter once per addon-process-load.

    THE BUG THIS FIXES: resuming only from flows.jsonl's tail breaks the
    moment that file is deleted (e.g. by the clear_captured_flows AI tool)
    while mitmweb isn't running -- the addon would restart the counter at 0,
    colliding with any pre-clear seq numbers a caller's cached since_cursor
    still references. Falling back to meta.json's latest_seq (which
    clear_captured_flows deliberately preserves) closes that gap.
    """
    if _SEQ["initialized"]:
        return
    _SEQ["initialized"] = True
    # 1) Prefer the tail of flows.jsonl (cheapest, most common case).
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read().decode("utf-8", "ignore").splitlines()
        for line in reversed(tail):
            try:
                _SEQ["n"] = json.loads(line)["seq"]
                return
            except (ValueError, KeyError):
                continue
    except OSError:
        pass
    # 2) Fall back to meta.json's latest_seq -- survives clear_captured_flows
    # wiping flows.jsonl itself.
    try:
        with open(_meta_path(log_path), encoding="utf-8") as f:
            _SEQ["n"] = json.load(f).get("latest_seq", 0)
    except (OSError, ValueError):
        _SEQ["n"] = 0


def _next_seq(log_path: str) -> int:
    _resume_seq(log_path)
    _SEQ["n"] = _SEQ["n"] + 1
    return _SEQ["n"]


def _cap_body(raw, max_bytes: int) -> dict:
    """Cap raw body bytes at write time, mirroring read_host_file's shape.

    Body capping happens ONCE here -- there is no later re-cap opportunity
    since the live flow object (the only source of the body) won't exist
    once mitmweb restarts.
    """
    raw = raw or b""
    size_bytes = len(raw)
    capped = raw[:max_bytes]
    truncated = size_bytes > len(capped)
    try:
        content = capped.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = base64.b64encode(capped).decode("ascii")
        encoding = "base64"
    return {
        "content": content,
        "encoding": encoding,
        "truncated": truncated,
        "size_bytes": size_bytes,
        "bytes_read": len(capped),
    }


def _body_record(msg, max_bytes: int) -> dict:
    """The capped body of one side, decoded (gzip, br, deflate, zstd).

    ``raw_content`` is what went over the wire: a gzip JSON response showed
    as a hex dump. The decoded body is stored (still capped); the encoding
    and the on-the-wire size are noted. A body that cannot be decoded is
    stored as received, with ``decode_failed``.
    """
    if msg is None:
        return _cap_body(None, max_bytes)
    raw = msg.raw_content or b""
    encoding = ""
    try:
        encoding = (msg.headers.get("content-encoding") or "").strip().lower()
    except Exception:
        encoding = ""
    if not raw or encoding in ("", "identity", "none"):
        return _cap_body(raw, max_bytes)
    decoded = None
    try:
        decoded = msg.get_content(strict=True)
    except Exception:
        decoded = None
    if decoded is None:
        body = _cap_body(raw, max_bytes)
        body["content_encoding"] = encoding
        body["decode_failed"] = True
        return body
    body = _cap_body(decoded, max_bytes)
    body["content_encoding"] = encoding
    body["encoded_bytes"] = len(raw)
    return body


def _flow_ts_end(flow: http.HTTPFlow) -> float:
    if flow.response is not None:
        return flow.response.timestamp_end or flow.response.timestamp_start or time.time()
    if flow.error is not None:
        return flow.error.timestamp
    return time.time()


def _write_detail_file(log_path: str, flow: http.HTTPFlow, error) -> None:
    """Write details/<flow_id>.json: full headers + capped body per side.

    Headers are stored as [[name, value], ...] pairs via .items(multi=True)
    -- NOT a plain dict, since mitmproxy.http.Headers is a MultiDict and a
    bare dict() would silently collapse duplicate header names (e.g. two
    Set-Cookie headers).
    """
    max_body = _flow_max_body_bytes()
    req = flow.request
    resp = flow.response
    detail = {
        "id": flow.id,
        "request_headers": list(req.headers.items(multi=True)) if req else [],
        "response_headers": list(resp.headers.items(multi=True)) if resp else [],
        "request_body": _body_record(req, max_body),
        "response_body": _body_record(resp, max_body),
        "error": error,
    }
    details_dir = _details_dir(log_path)
    try:
        os.makedirs(details_dir, exist_ok=True)
        detail_path = os.path.join(details_dir, f"{flow.id}.json")
        with open(detail_path, "w", encoding="utf-8") as f:
            json.dump(detail, f)
    except OSError:
        pass


def _update_meta_on_append(log_path: str, seq: int) -> None:
    meta = _read_meta(log_path)
    if meta.get("earliest_seq") is None:
        meta["earliest_seq"] = seq
    meta["latest_seq"] = seq
    meta["total_flows_lifetime"] = meta.get("total_flows_lifetime", 0) + 1
    meta.setdefault("generation", 0)
    _write_meta(log_path, meta)


def _line_count_after_append(log_path: str) -> int:
    """Track flows.jsonl's line count in memory, lazily seeded once.

    Called AFTER the line has already been appended to disk, so the first
    call per (addon-process, log_path) pays for one real line-count read
    that already reflects this very append -- it seeds the counter directly
    from that read rather than also adding +1 on top of it (which would
    permanently overcount by one for the rest of the process's life). Every
    call after that first one is a pure in-memory increment -- see the
    ``_LINE_COUNT`` module docstring for why this matters.
    """
    if log_path not in _LINE_COUNT:
        try:
            with open(log_path, "rb") as f:
                _LINE_COUNT[log_path] = sum(1 for _ in f)
        except OSError:
            _LINE_COUNT[log_path] = 0
        return _LINE_COUNT[log_path]
    _LINE_COUNT[log_path] += 1
    return _LINE_COUNT[log_path]


def _maybe_trim(log_path: str, line_count: int) -> None:
    """Rewrite flows.jsonl to the newest N records once over the cap.

    ``line_count`` is the in-memory-tracked count (see
    ``_line_count_after_append``) -- this function only actually opens the
    file when a trim might be due, not on every single flow.

    The rewrite itself is a temp-file + ``os.replace`` swap, exactly like
    ``_write_meta``'s own atomicity guarantee: a plain truncating
    ``open(log_path, "w")`` would let a concurrent reader (a different OS
    process from this addon) observe a momentarily empty or partially
    written file mid-rewrite. This is the ONLY thing that ever changes
    existing records' byte offsets, so it bumps meta.json's `generation` in
    the same pass -- the reader module's cursor cache uses a `generation`
    mismatch as proof a cached byte offset is no longer valid (see
    mitmproxy_flow_log.py). A narrow window remains between this atomic swap
    and the following meta.json write where a reader could still observe the
    new file against the old generation; unlike a torn/partial file, that
    combination only ever produces a stale-but-well-formed read that
    self-corrects on the next poll once `generation` catches up -- accepted
    for the same reason as this feature's other documented, narrow,
    self-healing races.
    """
    max_stored = _flow_max_stored()
    if line_count <= max_stored:
        return
    try:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return
    if len(lines) <= max_stored:
        _LINE_COUNT[log_path] = len(lines)
        return

    keep = lines[-max_stored:]
    dropped = lines[:-max_stored]

    tmp_path = f"{log_path}.tmp-{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.writelines(keep)
        os.replace(tmp_path, log_path)
    except OSError:
        return
    _LINE_COUNT[log_path] = len(keep)

    details_dir = _details_dir(log_path)
    for line in dropped:
        try:
            flow_id = json.loads(line).get("id")
        except ValueError:
            continue
        if not flow_id:
            continue
        try:
            os.unlink(os.path.join(details_dir, f"{flow_id}.json"))
        except OSError:
            pass

    new_earliest = None
    for line in keep:
        try:
            new_earliest = json.loads(line)["seq"]
            break
        except (ValueError, KeyError):
            continue

    meta = _read_meta(log_path)
    meta["earliest_seq"] = new_earliest
    meta["generation"] = meta.get("generation", 0) + 1
    _write_meta(log_path, meta)


def _append_flow_record(flow: http.HTTPFlow, error, app: str) -> None:
    """Append one JSON record to flows.jsonl and write its detail file.

    WRITE-SAFETY: opens flows.jsonl in append mode and closes it on every
    single call -- never a long-lived, held-open handle. This is what makes
    clear_captured_flows safe against a still-running mitmweb: the next
    flow's write reopens (and, if needed, recreates) the path instead of
    silently writing into an unlinked, invisible inode.
    """
    log_path = _flow_log_path()
    if not log_path:
        return

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except OSError:
        return

    seq = _next_seq(log_path)
    req = flow.request
    resp = flow.response
    request_bytes = len(req.raw_content) if req and req.raw_content else 0
    response_bytes = None
    status_code = None
    response_content_type = None
    if resp is not None:
        response_bytes = len(resp.raw_content) if resp.raw_content else 0
        status_code = resp.status_code
        response_content_type = resp.headers.get("content-type")

    record = {
        "seq": seq,
        "id": flow.id,
        "ts_start": req.timestamp_start if req else time.time(),
        "ts_end": _flow_ts_end(flow),
        "protocol": _protocol(flow),
        "method": (req.method or "?") if req else "?",
        "host": (req.pretty_host or "?") if req else "?",
        "path": (req.path or "/") if req else "/",
        "status_code": status_code,
        "error": error,
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
        "app": app,
        "request_content_type": req.headers.get("content-type") if req else None,
        "response_content_type": response_content_type,
    }

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        return

    line_count = _line_count_after_append(log_path)
    _write_detail_file(log_path, flow, error)
    _update_meta_on_append(log_path, seq)
    _maybe_trim(log_path, line_count)


class SandroidLogger:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        body_len = len(flow.response.raw_content) if flow.response.raw_content else 0

        app = _attribute_and_tag(flow)
        _append_flow_record(flow, error=None, app=app)

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

    def error(self, flow: http.HTTPFlow) -> None:
        """Fires when a request went out but never got a response (reset,
        DNS failure, killed flow, client disconnect) -- disjoint from
        tls_failed_client, which fires pre-flow at the TLS layer with no
        HTTPFlow object at all.
        """
        if flow.response is not None:
            return  # defensive: never double-count if both hooks ever fire
        app = _attribute_and_tag(flow)
        reason = str(flow.error.msg) if flow.error else "unknown error"
        _append_flow_record(flow, error=reason, app=app)
        print(
            f"[FLOW_ERR]|{_ts()}|{_host_path(flow.request)}|{reason[:40]}|{app}",
            flush=True,
        )

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
        _append_tls_failure(host, reason, app)


def _append_tls_failure(host: str, reason: str, app: str) -> None:
    """Persist a TLS handshake failure in flows.jsonl (``kind: "tls"``).

    There is no HTTP flow for it, so it used to exist only as a stdout line:
    a later session or a reviewed run could not show which hosts pinned.
    Same write-safety as _append_flow_record; no detail file.
    """
    log_path = _flow_log_path()
    if not log_path:
        return
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except OSError:
        return
    now = time.time()
    seq = _next_seq(log_path)
    record = {
        "seq": seq,
        "id": f"tls-{seq}",
        "kind": "tls",
        "ts_start": now,
        "ts_end": now,
        "protocol": "TLS",
        "method": "TLS",
        "host": host or "?",
        "path": "",
        "status_code": None,
        "error": f"TLS handshake failed ({reason})",
        "tls_reason": reason,
        "request_bytes": 0,
        "response_bytes": None,
        "app": app,
        "request_content_type": None,
        "response_content_type": None,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        return
    line_count = _line_count_after_append(log_path)
    _update_meta_on_append(log_path, seq)
    _maybe_trim(log_path, line_count)


def _watch_parent() -> None:
    """Exit when Sandroid is gone, so mitmweb is never left orphaned.

    SANDROID_PARENT_PID is set by Sandroid when it starts mitmweb. If that
    process dies without stopping us (SIGKILL, a hard exit), our parent
    changes; then shut down (SIGTERM, then a hard exit).
    """
    try:
        parent = int(os.environ.get("SANDROID_PARENT_PID") or 0)
    except ValueError:
        parent = 0
    if parent <= 0 or not hasattr(os, "getppid"):
        return
    import signal
    import threading

    def _run() -> None:
        while os.getppid() == parent:
            time.sleep(2.0)
        print("[INFO] Sandroid is gone; mitmweb exits", flush=True)
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            pass
        time.sleep(5.0)
        os._exit(0)

    threading.Thread(target=_run, name="sandroid-parent-watch", daemon=True).start()


_watch_parent()

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
    #: True when the probe could not reach a verdict (mitmweb not listening
    #: yet, ``toybox nc`` missing on the device). Never reported as an error.
    inconclusive: bool = False


@dataclass
class MitmproxyState:
    """Runtime state visible to UI consumers."""

    running: bool = False
    proxy_port: int = 8080
    web_port: int = 8081
    web_host: str = "127.0.0.1"
    #: Bind address of the proxy + SOCKS listeners (``mitmproxy.listen_host``).
    listen_host: str = "127.0.0.1"
    pid: int | None = None
    flows_seen: int = 0
    tls_failures: int = 0
    flow_errors: int = 0
    verbose: bool = False
    last_error: str | None = None
    ssl_unpin_active: bool = False
    ssl_unpin_app: str | None = None
    socks_base: int = 8082
    focus_lanes: int = 5
    capture_scope: str = "none"
    focus_apps: list[str] = field(default_factory=list)
    #: ``time.monotonic()`` of the last flow that arrived on the regular proxy
    #: listener (no app-proxy lane), i.e. through the Device Proxy. 0 = none.
    last_direct_flow_at: float = 0.0


def _not_settled_result() -> ReachabilityResult:
    """Inconclusive verdict for a device that has not come back yet."""
    return ReachabilityResult(
        reachable=False,
        flows_incremented=False,
        detail="device has not settled yet (still restarting?)",
        inconclusive=True,
    )


def _is_direct_flow_line(line: str) -> bool:
    """Whether a ``[FLOW]|`` line came in on the regular proxy listener.

    App-proxy (SOCKS lane) flows carry the app package in the last column;
    regular-listener flows (the Device Proxy) leave it empty.
    """
    parts = line.split("|")
    return len(parts) < 8 or not parts[7].strip()


def _pid_listening(pid: int, port: int, host: str = "127.0.0.1") -> bool:
    """Whether process ``pid`` (or a child) has a TCP listener on ``port``.

    Checks the process itself rather than just connecting to the port, so a
    *different* process holding that port (e.g. another mitmproxy) is never
    mistaken for ours. Falls back to a plain connect when psutil cannot
    inspect the process.
    """
    try:
        import psutil

        proc = psutil.Process(pid)
        for p in [proc, *proc.children(recursive=True)]:
            for conn in p.net_connections(kind="tcp"):
                if (
                    conn.status == psutil.CONN_LISTEN
                    and conn.laddr
                    and conn.laddr.port == port
                ):
                    return True
        return False
    except Exception:
        import socket

        target = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host  # nosec B104
        try:
            with socket.create_connection((target, port), timeout=0.5):
                return True
        except OSError:
            return False


def _find_mitmweb() -> str | None:
    """Locate ``mitmweb``: PATH first, then next to this interpreter.

    mitmproxy is a Sandroid dependency, so its console scripts live in the
    same bin/ as ``sandroid`` -- which is not on PATH for pipx/uv-tool
    installs or an unactivated venv (``/path/to/venv/bin/sandroid``).
    """
    found = shutil.which("mitmweb")
    if found:
        return found
    import sys

    sibling = Path(sys.executable).parent / (
        "mitmweb.exe" if os.name == "nt" else "mitmweb"
    )
    return str(sibling) if sibling.exists() else None


def _web_password_supported(binary: str) -> bool:
    """Whether ``binary`` is a mitmweb that knows ``--set web_password``.

    mitmweb >= 11.1 protects its UI with a token (a URL without it is 403).
    Only a mitmweb from this Python environment can be version-checked
    without running it; for any other one the option is not passed (an
    unknown option would stop mitmweb from starting).
    """
    try:
        from importlib.metadata import version

        parts = version("mitmproxy").split(".")
        major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except Exception:
        return False
    if (major, minor) < (11, 1):
        return False
    prefix = os.path.abspath(sys.prefix) + os.sep
    return os.path.abspath(binary).startswith(prefix)


def _hash_web_password(token: str) -> str:
    """argon2 hash of the UI token (so ``ps`` never shows it), else the token."""
    try:
        from argon2 import PasswordHasher

        return PasswordHasher().hash(token)
    except Exception:
        return token


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
        #: Session-timeline ``net/flow`` lines while mitmweb runs (WP4).
        self._net_source: Any = None
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
        # The device http_proxy address ("ip:port") Sandroid pointed at this
        # mitmproxy, so it can be cleared on stop and on exit -- also when the
        # TUI did not get to unmount cleanly. None = we set nothing.
        self._owned_device_proxy: str | None = None
        # Serial of the device that proxy was set on (cleanup targets it).
        self._owned_device_proxy_serial: str | None = None
        # Token for mitmweb's web UI (None: not set by us / not supported).
        self._web_token: str | None = None
        # True when mitmweb runs in its own process group (killed as one).
        self._own_group = False
        atexit.register(self._atexit_cleanup)

    @property
    def state(self) -> MitmproxyState:
        # While stopped, the ports shown (glance band, panel, AI tools) are the
        # configured ones, so a config edit shows up without a start. While
        # running they are the ports the live process was started with.
        if self._proc is None:
            self._sync_ports_from_config()
        return self._state

    def _sync_ports_from_config(self) -> None:
        """Copy the configured ports / bind hosts into the (stopped) state.

        Best-effort and cheap (``get_config`` is cached); never raises.
        """
        if get_config is None:
            return
        try:
            cfg = get_config().mitmproxy
            self._state.proxy_port = int(cfg.proxy_port)
            self._state.web_port = int(cfg.web_port)
            self._state.web_host = str(cfg.web_host)
            self._state.listen_host = str(
                getattr(cfg, "listen_host", "127.0.0.1") or "127.0.0.1"
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("mitmproxy port sync failed: %s", exc)

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
        # Ports too: before this, state kept the dataclass default 8080 until
        # the first start, so the glance showed ":8080 (stopped)" while the
        # configured port was e.g. 8090.
        self._sync_ports_from_config()

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

    @staticmethod
    def _resolve_flow_log_env() -> dict[str, str]:
        """Resolve the structured flow log's env vars for the mitmweb subprocess.

        The folder is the session's (``mitmproxy_flow_log.session_raw_root``,
        the same one the reader resolves) -- never a running Play's bundle,
        whose ``RAW_RESULTS_PATH`` pin would otherwise send a mitmweb started
        mid-Play into the bundle.

        Returns an empty dict (leaving the feature disabled at zero cost on
        the addon side) if config says it's off, or if path resolution fails
        for any reason -- never raises, never blocks ``start()``.
        """
        try:
            cfg = get_config().mitmproxy if get_config is not None else None
            enabled = (
                getattr(cfg, "flow_log_enabled", True) if cfg is not None else True
            )
            if not enabled:
                return {}

            from sandroid.services.mitmproxy_flow_log import session_raw_root

            raw_root = session_raw_root()
            flows_dir = raw_root / "mitm_flows"
            flows_dir.mkdir(parents=True, exist_ok=True)
            (flows_dir / "details").mkdir(parents=True, exist_ok=True)

            max_stored = getattr(cfg, "max_stored_flows", 5000) if cfg else 5000
            max_body = getattr(cfg, "max_captured_body_bytes", 65536) if cfg else 65536
            return {
                "SANDROID_FLOW_LOG": str(flows_dir / "flows.jsonl"),
                "SANDROID_FLOW_MAX_STORED": str(max_stored),
                "SANDROID_FLOW_MAX_BODY_BYTES": str(max_body),
            }
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to resolve flow log path: %s", exc)
            return {}

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

        if update_config is not None:
            # Update the live config in place and persist just this key to
            # the config file in use -- never reset the cache, which would
            # drop --config/--environment/CLI overrides on the next
            # get_config().
            try:
                update_config({"mitmproxy.enabled_addons": [str(p) for p in resolved]})
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
            resolve_proxy_host_ip,
        )

        try:
            host_ip = resolve_proxy_host_ip()
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

    #: A Device-Proxy flow seen this recently counts as proof of reachability.
    _RECENT_DIRECT_FLOW_S = 30.0

    def probe_device_reachability(
        self,
        host: str,
        port: int,
        *,
        timeout: int = 4,
        listen_timeout: float = 8.0,
    ) -> ReachabilityResult:
        r"""Prove the device can actually reach our mitmproxy at ``host:port``.

        ``set_proxy`` only verifies the proxy *string* was written, never that
        the device can reach it. The auto-detected host IP can be unreachable
        from the device, so the device silently times out (0 flows) while the
        header reads green. This fires a real device→proxy round-trip and
        cross-checks ``flows_seen`` for end-to-end proof.

        Our own end is checked first: Ctrl+D / Ctrl+R start mitmweb and probe
        straight away, before it has bound its port, which used to produce a
        false "device CANNOT reach mitmproxy" although flows arrived seconds
        later. Not listening yet (or not running) is ``inconclusive``.

        Independent signals, any one of which proves reachability (so an
        ``nc`` quirk alone can't flip the verdict):

        1. Device bytes — a forced-HTTP request through the proxy to
           ``http://mitm.it/`` (mitmproxy's onboarding addon answers it itself,
           offline, even with no upstream). Reachable iff stdout is non-empty
           AND contains ``"HTTP/"`` (NOT the ``nc`` exit code — unreliable).
           Retried once after a short pause.
        2. Host counter — ``flows_seen`` rising during the probe is independent
           proof the proxy received and counted the flow.
        3. Recent Device-Proxy traffic — a flow on the regular listener within
           the last ``_RECENT_DIRECT_FLOW_S`` seconds: if flows arrive, the
           device evidently reaches us.

        On an emulator ``10.0.2.2`` is the host's loopback, so this works with
        the default ``listen_host = 127.0.0.1``; so does ``127.0.0.1`` on the
        device via ``adb reverse``.

        QUOTING: ``Adb.send_adb_command`` runs the whole string through the host
        shell (``shell=True``), so the device-side pipe + ``printf`` ``\\r\\n``
        escapes are passed as ONE host-quoted word (``device_shell_command``) so
        only the *device* shell interprets them; a bare pipe would be split by
        the host shell. ``toybox nc`` closes the socket on stdin EOF before the reply
        arrives, so we hold stdin open with ``{ ...; sleep N; }`` — do NOT
        simplify it back to a bare pipe or stdout comes back empty.

        WARNING: blocking (listen wait + device round-trips + a short settle
        poll). Call this OFF the UI thread.

        Args:
            host: Proxy host the device is pointed at (the resolved host IP, or
                ``127.0.0.1`` when routed via adb reverse).
            port: Proxy port.
            timeout: ``nc`` connect/read timeout in seconds.
            listen_timeout: How long to wait for mitmweb to bind its port.

        Returns:
            A :class:`ReachabilityResult`.
        """
        from sandroid.core.adb_utils import quiet_adb_warnings

        with quiet_adb_warnings():
            return self._probe_device_reachability(
                host, port, timeout=timeout, listen_timeout=listen_timeout
            )

    def _probe_device_reachability(
        self, host: str, port: int, *, timeout: int, listen_timeout: float
    ) -> ReachabilityResult:
        from sandroid.core.adb import Adb
        from sandroid.core.adb_utils import device_shell_command

        addr = f"{host}:{port}"
        if not self.wait_listening(timeout=listen_timeout):
            detail = (
                f"mitmproxy is not listening on :{port} yet"
                if self.is_running()
                else "mitmproxy is not running"
            )
            return ReachabilityResult(
                reachable=False,
                flows_incremented=False,
                detail=detail,
                inconclusive=True,
            )

        before = self._state.flows_seen
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
            f"{{ printf '{request}'; sleep 2; }} | toybox nc -w {timeout} {host} {port}"
        )
        got_http = False
        tool_missing = False
        for attempt in range(2):
            try:
                out, err = Adb.send_adb_command(device_shell_command(inner))
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("reachability probe failed: %s", exc)
                out, err = "", ""
            out = out or ""
            if out.strip() and "HTTP/" in out:
                got_http = True
                break
            blob = (err or "").lower()
            # toybox's wording for a missing applet is "Unknown command nc";
            # adb's for a vanished device is "device ... not found".
            if not out.strip() and any(
                k in blob for k in ("not found", "no such", "usage", "unknown command")
            ):
                tool_missing = True
                break
            if self._state.flows_seen > before or attempt:
                break
            time.sleep(1.5)

        # Short settle poll (~0.3s x5, mirroring _wait_listening cadence) so a
        # just-counted flow has a moment to land before we re-read.
        after = self._state.flows_seen
        for _ in range(5):
            if after > before:
                break
            time.sleep(0.3)
            after = self._state.flows_seen
        flows_incremented = after > before

        last_direct = self._state.last_direct_flow_at
        recent_direct = bool(last_direct) and (
            time.monotonic() - last_direct <= self._RECENT_DIRECT_FLOW_S
        )

        reachable = got_http or flows_incremented or recent_direct
        hint = ""
        inconclusive = False
        if reachable:
            how = (
                "flow round-trip confirmed"
                if (got_http or flows_incremented)
                else "device traffic is arriving"
            )
            detail = f"device→mitmproxy reachable ({addr}, {how})"
        elif tool_missing:
            inconclusive = True
            detail = f"could not probe {addr} from the device (no toybox nc?)"
        else:
            detail = f"device CANNOT reach mitmproxy at {addr}"
            hint = (
                f"device can't reach the proxy at {addr} — check the host IP, "
                "or route via adb reverse in Proxy Settings (y)"
            )
            listen_host = self._state.listen_host
            if listen_host.startswith("127.") and host not in (
                "10.0.2.2",
                "127.0.0.1",
            ):
                hint = (
                    f"mitmproxy listens on {listen_host} only, which {host} "
                    "does not reach — route via adb reverse in Proxy Settings "
                    '(y), or set mitmproxy.listen_host = "0.0.0.0" for a '
                    "device on Wi-Fi (exposes the proxy to the LAN)"
                )
        return ReachabilityResult(
            reachable=reachable,
            flows_incremented=flows_incremented,
            detail=detail,
            hint=hint,
            inconclusive=inconclusive,
        )

    @staticmethod
    def wait_device_settled(
        timeout: float = 60.0, poll: float = 1.0, stable_polls: int = 2
    ) -> bool:
        """Block until the device has settled after a Zygote restart/reconnect.

        Killing Zygote (CA injection) takes system_server down with it, and
        init's ``onrestart`` for Zygote also restarts ``netd`` -- so for a
        few seconds the device has no package manager and no routes. A
        reachability probe fired in that window reports a false "device
        CANNOT reach mitmproxy". The same goes for a device that just came
        back after a disconnect.

        Settled means ``sys.boot_completed == 1`` AND the package manager
        answers (``pm path android``), seen on ``stable_polls`` consecutive
        polls (one good poll can still come from the dying system_server).
        Blocking: call it off the UI thread.

        Returns:
            True once settled, False when ``timeout`` passed first.
        """
        from sandroid.core.adb import Adb
        from sandroid.core.adb_utils import quiet_adb_warnings

        deadline = time.monotonic() + timeout
        good = 0
        while True:
            ready = False
            try:
                with quiet_adb_warnings():
                    boot, _ = Adb.send_adb_command("shell getprop sys.boot_completed")
                    if (boot or "").strip() == "1":
                        pm_out, _ = Adb.send_adb_command("shell pm path android")
                        ready = "package:" in (pm_out or "")
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("settle poll failed: %s", exc)
            good = good + 1 if ready else 0
            if good >= max(1, stable_polls):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)

    def probe_after_device_restart(
        self,
        host: str,
        port: int,
        *,
        settle_timeout: float = 60.0,
        attempts: int = 3,
        retry_delay: float = 5.0,
        wait_settle: bool = True,
    ) -> ReachabilityResult:
        """Wait for the device to settle, then probe reachability with retries.

        Used after a Zygote restart (Ctrl+N) and after a device reconnect.
        Even once the package manager answers, the default network may need a
        few more seconds to come back, so a negative probe is retried
        ``attempts`` times ``retry_delay`` seconds apart before it counts. A
        device that never settles yields an ``inconclusive`` result, never a
        "CANNOT reach" verdict. ``wait_settle=False`` skips the settle wait
        (the caller already did it).

        WARNING: blocking (up to ``settle_timeout`` + the probe retries).
        Call this OFF the UI thread.
        """
        if wait_settle and not self.wait_device_settled(timeout=settle_timeout):
            return _not_settled_result()
        result = self.probe_device_reachability(host, port)
        for _ in range(max(0, attempts - 1)):
            if result.reachable or result.inconclusive:
                break
            time.sleep(retry_delay)
            result = self.probe_device_reachability(host, port)
        return result

    def wait_listening(self, timeout: float = 8.0) -> bool:
        """Block until our mitmweb accepts connections on its proxy port.

        ``start()`` returns as soon as the process is spawned; mitmweb needs
        a moment (Python start-up, addons, one listener per lane) before it
        binds. Returns False if the process is gone or the deadline passes.
        Blocking: call it off the UI thread.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                proc = self._proc
            if proc is None or proc.poll() is not None:
                return False
            if _pid_listening(
                proc.pid, self._state.proxy_port, self._state.listen_host
            ):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.2)

    def add_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[str], None]) -> None:
        try:
            self._listeners.remove(callback)
        except ValueError:
            pass

    def web_url(self, *, with_token: bool = True) -> str:
        """The mitmweb UI address, with its access token when one is known.

        mitmweb >= 11.1 answers a URL without the token with 403.
        """
        base = f"http://{self._state.web_host}:{self._state.web_port}/"
        if with_token and self._web_token and self.is_running():
            return f"{base}?token={self._web_token}"
        return base

    @property
    def has_web_token(self) -> bool:
        return bool(self._web_token) and self.is_running()

    def start(
        self,
        proxy_port: int = 8080,
        web_port: int = 8081,
        web_host: str = "127.0.0.1",
        listen_host: str | None = None,
    ) -> bool:
        """Spawn mitmweb.

        Args:
            proxy_port: Proxy listen port (the default means "use config").
            web_port: Web UI port (the default means "use config").
            web_host: Web UI bind host (the default means "use config").
            listen_host: Bind address for the proxy and SOCKS listeners;
                ``None`` reads ``mitmproxy.listen_host`` (default
                ``127.0.0.1``, i.e. not reachable from the LAN).

        Returns:
            True when the process was spawned.
        """
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
            if not listen_host:
                listen_host = "127.0.0.1"
                if get_config is not None:
                    try:
                        listen_host = get_config().mitmproxy.listen_host or "127.0.0.1"
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning("Failed to read listen_host: %s", exc)

            binary = _find_mitmweb()
            if binary is None:
                self._state.last_error = (
                    "mitmweb not found on PATH (pip install mitmproxy)"
                )
                self._emit(f"[ERROR] {self._state.last_error}")
                return False

            self._write_addon()
            verbosity = "info" if self._state.verbose else "warn"
            # --listen-host applies to every --mode below (the regular proxy
            # and each SOCKS5 lane). mitmproxy's own default is all
            # interfaces, which would expose intercepted traffic to the LAN.
            cmd = [
                binary,
                "--listen-host",
                listen_host,
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
            # Our own UI token, so Ctrl+O can open mitmweb already logged in
            # (otherwise mitmweb prints a random one we never see: 403).
            self._web_token = None
            if _web_password_supported(binary):
                token = secrets.token_urlsafe(18)
                cmd += ["--set", f"web_password={_hash_web_password(token)}"]
                self._web_token = token

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

            # Structured flow log (Track 2): resolved fresh here, independently
            # of mitmproxy_flow_log.py's own resolution (see that module's
            # docstring for why this small duplication is deliberate rather
            # than a shared import -- services -> ai/tools would be a
            # backwards dependency). Empty SANDROID_FLOW_LOG disables the
            # whole feature at zero cost on the addon side.
            flow_log_env = self._resolve_flow_log_env()

            try:
                # Own process group: stop() terminates mitmweb with anything
                # it spawned, and a terminal signal aimed at Sandroid does not
                # race our orderly stop. SANDROID_PARENT_PID lets the addon
                # exit if Sandroid dies without stopping it.
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    text=True,
                    env={
                        **os.environ,
                        "SANDROID_FOCUS_MAP": sidecar_path,
                        "SANDROID_PARENT_PID": str(os.getpid()),
                        **flow_log_env,
                    },
                    start_new_session=os.name == "posix",
                    stdin=subprocess.DEVNULL,
                )
                self._own_group = os.name == "posix"
            except Exception as exc:
                self._state.last_error = f"spawn failed: {exc}"
                logger.exception("Failed to spawn mitmweb")
                self._emit(f"[ERROR] {self._state.last_error}")
                return False

            self._state.running = True
            self._state.proxy_port = proxy_port
            self._state.web_port = web_port
            self._state.web_host = web_host
            self._state.listen_host = listen_host
            self._state.pid = self._proc.pid
            self._state.last_error = None
            self._state.flows_seen = 0
            self._state.last_direct_flow_at = 0.0
            self._state.tls_failures = 0
            self._state.flow_errors = 0

            self._reader_thread = threading.Thread(
                target=self._read_loop,
                name="mitmweb-reader",
                daemon=True,
            )
            self._reader_thread.start()
            self._start_net_source()

            self._emit(
                f"[INFO] mitmweb started "
                f"(proxy {listen_host}:{proxy_port}, "
                f"web http://{web_host}:{web_port}/)"
            )
            return True

    def stop(self, timeout: float = 3.0, *, release_device_proxy: bool = True) -> None:
        """Stop mitmweb (idempotent).

        Args:
            timeout: Seconds to wait for a graceful exit before killing it.
            release_device_proxy: Also clear the device proxy Sandroid pointed
                at this mitmproxy (see :meth:`release_device_proxy`), so the
                device is never left routed to a dead proxy. ``restart()``
                passes False because the caller re-applies it.
        """
        if release_device_proxy and self._proc is not None:
            # Outside the lock: this is ADB I/O.
            self.release_device_proxy()
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
                self._terminate(proc, timeout)
            except Exception as exc:
                logger.warning("Error stopping mitmweb: %s", exc)
            finally:
                # After mitmweb is gone: its last flows are in flows.jsonl and
                # the source's final poll writes them (stop() drains once).
                self._stop_net_source()
                self._proc = None
                self._state.pid = None
                self._web_token = None
                self._cleanup_addon()

            self._emit("[INFO] mitmweb stopped")

    def _start_net_source(self) -> None:
        """One ``net/flow`` timeline line per finished flow (never raises)."""
        self._stop_net_source()
        try:
            from sandroid.services.tracking_service import NetFlowSource

            source = NetFlowSource()
            source.start()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("net flow source failed to start: %s", exc)
            return
        self._net_source = source
        self.add_listener(source.on_line)

    def _stop_net_source(self) -> None:
        source, self._net_source = self._net_source, None
        if source is None:
            return
        self.remove_listener(source.on_line)
        try:
            source.stop()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("net flow source failed to stop: %s", exc)

    def _signal_group(self, proc, sig: int) -> bool:
        """Signal mitmweb's process group (True) or report it can't (False)."""
        if not (self._own_group and isinstance(proc, subprocess.Popen)):
            return False
        try:
            pgid = os.getpgid(proc.pid)
        except (OSError, AttributeError):
            return False
        if pgid != proc.pid:  # not the leader of its own group: leave it
            return False
        try:
            os.killpg(pgid, sig)
        except OSError:
            return False
        return True

    def _terminate(self, proc, timeout: float) -> None:
        """SIGTERM mitmweb (its whole group), SIGKILL after ``timeout``."""
        if not self._signal_group(proc, signal.SIGTERM):
            proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if not self._signal_group(proc, signal.SIGKILL):
                proc.kill()
            proc.wait(timeout=1.0)

    def shutdown(self, timeout: float = 2.0) -> None:
        """Quit-time teardown: device proxy, SSL unpin, mitmweb. Never raises.

        Every quit path (dialog, Ctrl+C/Ctrl+Q, SIGTERM, the exit watchdog)
        runs this; it is idempotent.
        """
        try:
            self.release_device_proxy()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("release_device_proxy on shutdown failed: %s", exc)
        try:
            if self._proc is not None:
                self.stop(timeout=timeout, release_device_proxy=False)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("mitmweb stop on shutdown failed: %s", exc)

    def restart(self, **kwargs) -> bool:
        self.stop(release_device_proxy=False)
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
                    if _is_direct_flow_line(line):
                        self._state.last_direct_flow_at = time.monotonic()
                elif line.startswith("[TLS_FAIL]|"):
                    self._state.tls_failures += 1
                elif line.startswith("[FLOW_ERR]|"):
                    self._state.flow_errors += 1
                elif "?token=" in line and self._web_token is None:
                    # A mitmweb we could not hand a token (another install)
                    # prints its own: remember it for Ctrl+O.
                    token = line.split("?token=", 1)[1].split()[0].strip("/")
                    if token:
                        self._web_token = token
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

    # ── Device proxy ownership ────────────────────────────────────────

    @property
    def owned_device_proxy(self) -> str | None:
        """The device proxy address Sandroid set to this mitmproxy, if any."""
        return self._owned_device_proxy

    @property
    def owned_device_proxy_serial(self) -> str | None:
        """Serial of the device :attr:`owned_device_proxy` was set on."""
        return self._owned_device_proxy_serial

    def note_device_proxy(self, address: str | None, serial: str | None = None) -> None:
        """Record (``"ip:port"``) or forget (``None``) the device proxy we set.

        Args:
            address: The proxy address set on the device, or None to forget.
            serial: Device it was set on; defaults to the current adb target.
        """
        self._owned_device_proxy = address or None
        if not self._owned_device_proxy:
            self._owned_device_proxy_serial = None
            return
        if serial is None:
            try:
                from sandroid.core.adb import Adb

                serial = Adb.get_target_device()
            except Exception:
                serial = None
        self._owned_device_proxy_serial = serial

    def release_device_proxy(self, serial: str | None = None) -> bool:
        """Clear the device http_proxy if it still points where we set it.

        Runs against the device the proxy was SET on (recorded by
        :meth:`note_device_proxy`), not whatever device is selected now. A
        proxy someone else changed in the meantime is left alone. Also drops
        the ``adb reverse`` tunnel when the proxy we set was a loopback route.
        Blocking (ADB); best-effort, never raises.

        Args:
            serial: Only release when the proxy was set on this device
                (used on device switch); None releases it wherever it is.

        Returns:
            True when a proxy was cleared.
        """
        addr = self._owned_device_proxy
        owner = self._owned_device_proxy_serial
        if not addr:
            return False
        if serial is not None and owner is not None and owner != serial:
            return False
        self._owned_device_proxy = None
        self._owned_device_proxy_serial = None
        cleared = False
        try:
            from sandroid.core.adb import Adb
            from sandroid.core.proxy_manager import (
                ProxyManager,
                ProxyStatus,
                _reverse_registered,
            )

            with Adb.targeting(owner):
                pm = ProxyManager()
                status, cfg = pm.get_proxy_settings()
                if (
                    status == ProxyStatus.SET
                    and cfg is not None
                    and cfg.address == addr
                ):
                    cleared, _ = pm.unset_proxy()
                if addr.startswith("127.0.0.1:"):
                    port = int(addr.rsplit(":", 1)[1])
                    if _reverse_registered(port):
                        Adb.reverse_remove(f"tcp:{port}")
        except Exception as exc:
            logger.debug("Releasing device proxy %s failed: %s", addr, exc)
        return cleared

    def reapply_device_proxy(self, serial: str | None = None) -> str:
        """Put the device proxy back after a snapshot load reset it.

        A snapshot restores the device's settings, so loading one taken
        without the proxy (e.g. Play's ``tmp``) silently set ``http_proxy``
        back to ``:0`` and mitmproxy saw none of the replays (M-29). Called
        by ``EmulatorService.load_snapshot`` after every load. Blocking
        (ADB), never raises.

        Args:
            serial: The device the snapshot was loaded on (None: current).

        Returns:
            ``"none"`` (no device proxy of ours), ``"kept"`` (still set),
            ``"restored"`` (re-applied), ``"stopped"`` (lost, but mitmproxy
            no longer runs: forgotten) or ``"failed"`` (lost, could not be
            re-applied; logged as an error).
        """
        addr = self._owned_device_proxy
        owner = self._owned_device_proxy_serial
        if not addr:
            return "none"
        if serial is not None and owner is not None and owner != serial:
            return "none"
        try:
            from sandroid.core.adb import Adb
            from sandroid.core.proxy_manager import (
                ProxyConfig,
                ProxyManager,
                ProxyStatus,
                _reverse_registered,
            )

            with Adb.targeting(owner or serial):
                pm = ProxyManager()
                status, cfg = pm.get_proxy_settings()
                if (
                    status == ProxyStatus.SET
                    and cfg is not None
                    and cfg.address == addr
                ):
                    return "kept"
                if not self.is_running():
                    self.note_device_proxy(None)
                    logger.warning(
                        "The snapshot load reset the device proxy (was %s); "
                        "mitmproxy is not running, so it was not re-applied",
                        addr,
                    )
                    return "stopped"
                ok, _msg = pm.set_proxy(ProxyConfig.from_string(addr))
                if ok and addr.startswith("127.0.0.1:"):
                    port = int(addr.rsplit(":", 1)[1])
                    if not _reverse_registered(port):
                        Adb.reverse(f"tcp:{port}", f"tcp:{port}")
        except Exception as exc:
            logger.debug("Re-applying device proxy %s failed: %s", addr, exc)
            ok = False
        if ok:
            logger.warning(
                "The snapshot load reset the device proxy; re-applied %s so "
                "mitmproxy keeps capturing",
                addr,
            )
            return "restored"
        logger.error(
            "The snapshot load reset the device proxy (was %s) and it could not "
            "be re-applied: mitmproxy will NOT see the device's traffic "
            "(Ctrl+D in the Network lens sets it again)",
            addr,
        )
        return "failed"

    def _atexit_cleanup(self) -> None:
        # Never leave the device pointed at a mitmproxy that is about to die.
        self.shutdown(timeout=1.0)
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


def peek_mitmproxy_service() -> MitmproxyService | None:
    """The singleton if it was created already, else None (never creates it).

    For hooks on hot paths (every snapshot load, every Play) that only care
    about a mitmproxy the user started.
    """
    return _INSTANCE
