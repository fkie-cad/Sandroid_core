"""Network lens: who is the app talking to, and what did it send?

One full-width flow table (``#net-flows``; columns Time, App, Recipient,
Request, TLS, Identity, Status, Size; narrow widths drop Size, TLS, Time and
App in that order so Request stays readable) fed from the structured flow
log the embedded mitmweb addon writes
(``<raw_results>/mitm_flows/flows.jsonl``, read through
:mod:`sandroid.services.mitmproxy_flow_log`). Details live only in the
Inspector (Enter on a row): Summary / Request / Response.

Data flow
---------
* A 1 s timer kicks an off-thread poll while the lens is visible. The poll is
  cursor-based (``query_flows(since_cursor=...)``) and skips the read entirely
  when ``flows.jsonl`` has not changed (size + mtime), so an idle lens costs
  one ``stat``. A ``[FLOW]`` line from mitmweb's stdout triggers an early
  poll so new rows show up promptly.
* The in-memory model is bounded (``MAX_ROWS``); the table appends new rows
  at the bottom and follows them while *live* (``follow.py``, the same rules
  as the Timeline and Files lenses): ↑, PgUp, Home, a wheel up or a click on
  a row above the newest one stop following (capturing goes on), ``End``
  resumes (an open flow Inspector then follows the newest flow), so a user
  who scrolled or selected a row is never yanked. The caption title says
  ``live`` or ``scrolled back · 12 new below · End = live``.
* ``[TLS_FAIL]`` lines become "TLS failed" rows at once; the addon also writes them to
  ``flows.jsonl`` (``kind: "tls"``, no detail file), and the poll pairs that
  record with the stdout row instead of adding it twice. While the lens is
  not in view they count into the lens-bar badge (``27 TLS failed``) until
  the lens is activated again.
  Errored flows come from ``flows.jsonl`` (their ``error`` field) as
  "error" rows.

Filters: ``/`` text (host, path, app, recipient, status; Esc clears it),
``T`` (target) spotlight app only, ``N`` show OS noise (connectivity checks,
Play services background traffic, Google ``*-pa`` APIs, Sandroid's own
``mitm.it`` probe; hidden by default, the caption counts what it hides). ``N`` is "show hidden noise" in the Files lens
too, and ``v`` is only the Sessions lens's "review". The frame caption carries the
counts ("38 of 412").

Identity profile values (:mod:`sandroid.services.privacy_scan`): a flow that
carries a seeded value gets a faint warn-tinted row and, from 100 columns, an
Identity column naming the values in words (``Ad ID, GPS``; third party in
the warn colour, first party in the accent colour; shown whenever identity
mode is on, the scan has markers or hits are loaded); ``!`` only filters the
rows to those flows, ``/`` matches the value names too, and the Inspector gains an Identity
tab (where, how encoded, to whom, how sure, the matched text highlighted).
Hits the scanner finds later re-mark rows already drawn (at most once a
second).

Proxy & friTap plumbing: :class:`MitmproxyPanel` and :class:`FriTapPanel` are
mounted hidden inside this lens as controllers; this lens binds their keys
(``Ctrl+D`` device proxy, ``Ctrl+N`` CA, ``Ctrl+P`` unpin, ...) and shows
their state in the caption (``Mitmproxy on :<port> · device routed · CA
installed · friTap on``,
``<port>`` = the configured ``mitmproxy.proxy_port``)
and on the "Capture status" Inspector page (``I``; ``h`` opens its friTap
tab). Their log lines go to the ActivityLog drawer (`` ` ``).

REVIEW scope: ``on_scope_changed`` loads the run's flows from its bundle
(``<run>/network/flows.jsonl``, written at run finalisation and covered by the
run's ``SHA256SUMS``; each record carries the ``phase`` it happened in). Runs
from before in-bundle flows fall back to the session's flow log filtered by
the run's time window (only works in the session that ran it), which the
caption says. Flows of the replays are shown; the dry run (noise baseline) and
setup phases (snapshot loads, baseline scan, collecting results) are hidden
and counted, ``A`` shows them marked ``dry``/``setup``. With no flows the
empty state says why (mitmproxy off, none captured, pre-bundle run) and
points to the run's pcap. ``L`` (MainScreen) returns to LIVE.
"""

from __future__ import annotations

import base64
import bisect
import contextlib
import functools
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from rich.markup import escape
from rich.style import Style
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Input, Static

from sandroid.services.row_highlights import RowSnapshot, tls_row_key
from sandroid.tui.row_annotations import (
    LENS_NETWORK,
    AnnotationFeed,
    AnnotationTintMixin,
)
from sandroid.tui.themes import lens_palette
from sandroid.tui.utils.ui_thread import UiDispatcher, in_app_context
from sandroid.tui.widgets.follow import Follow
from sandroid.tui.widgets.fritap_panel import FriTapPanel
from sandroid.tui.widgets.highlight_bar import (
    HL_WIDTH,
    HighlightBar,
    HighlightView,
    flow_snapshot,
)
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown
from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import RenderableType
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

LENS_ID = "network"

#: Inspector key of the "Capture status" page (mitmproxy + friTap tabs).
STATUS_KEY = "network:capture-status"
#: A narrow lens drops columns (this order, first goes first) until Request
#: has this many cells; Time | App | Recipient | Request | TLS | Identity |
#: Status | Size is the full order.
REQUEST_MIN_WIDTH = 26
LAYOUT_DROP_ORDER = ("size", "tls", "time", "app")

# --------------------------------------------------------------------------
# recipients + OS noise
# --------------------------------------------------------------------------

#: (domain suffix, recipient label), most specific first. Fallback only:
#: :func:`recipient_of` asks Dexray Insight's tracker database
#: (``label_for_domain``) first and uses this table when that import fails
#: (Insight older than 2.0).
_RECIPIENTS: tuple[tuple[str, str], ...] = (
    ("app-measurement.com", "Google Analytics"),
    ("google-analytics.com", "Google Analytics"),
    ("firebaselogging-pa.googleapis.com", "Google Analytics"),
    ("firebaselogging.googleapis.com", "Google Analytics"),
    ("crashlytics.com", "Crashlytics"),
    ("firebaseinstallations.googleapis.com", "Firebase"),
    ("firebaseremoteconfig.googleapis.com", "Firebase"),
    ("firebaseio.com", "Firebase"),
    ("fcm.googleapis.com", "Firebase"),
    ("doubleclick.net", "Google Ads"),
    ("googleadservices.com", "Google Ads"),
    ("googlesyndication.com", "Google Ads"),
    ("admob.com", "Google Ads"),
    ("googleapis.com", "Google"),
    ("gstatic.com", "Google"),
    ("google.com", "Google"),
    ("facebook.com", "Meta"),
    ("facebook.net", "Meta"),
    ("fbcdn.net", "Meta"),
    ("instagram.com", "Meta"),
    ("appsflyer.com", "AppsFlyer"),
    ("appsflyersdk.com", "AppsFlyer"),
    ("adjust.com", "Adjust"),
    ("adjust.io", "Adjust"),
    ("branch.io", "Branch"),
    ("amplitude.com", "Amplitude"),
    ("mixpanel.com", "Mixpanel"),
    ("segment.io", "Segment"),
    ("segment.com", "Segment"),
    ("sentry.io", "Sentry"),
    ("onesignal.com", "OneSignal"),
    ("braze.com", "Braze"),
    ("appboy.com", "Braze"),
    ("usercentrics.eu", "Usercentrics"),
    ("onetrust.com", "OneTrust"),
    ("cookielaw.org", "OneTrust"),
    ("applovin.com", "AppLovin"),
    ("unity3d.com", "Unity Ads"),
    ("tiktokv.com", "TikTok"),
    ("bytedance.com", "TikTok"),
    ("hotjar.com", "Hotjar"),
    ("newrelic.com", "New Relic"),
    ("nr-data.net", "New Relic"),
    ("datadoghq.com", "Datadog"),
    ("bugsnag.com", "Bugsnag"),
)

#: Hosts the OS talks to on its own (connectivity checks, Play services).
_NOISE_SUFFIXES: tuple[str, ...] = (
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "play.googleapis.com",
    "play-fe.googleapis.com",
    "android.clients.google.com",
    "android.googleapis.com",
    "android.apis.google.com",
    "mtalk.google.com",
    "gvt1.com",
    "gvt2.com",
    "gvt3.com",
    "time.android.com",
    "ota.googlezip.net",
    "update.googleapis.com",
    "digitalassetlinks.googleapis.com",
    "instantmessaging-pa.googleapis.com",
    "people-pa.googleapis.com",
    "semanticlocation-pa.googleapis.com",
    "cryptauthenrollment.googleapis.com",
    "cryptauthdevicesync.googleapis.com",
    "mobilenetworkscoring-pa.googleapis.com",
    "growth-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "youtubei.googleapis.com",
    "lamssettings-pa.googleapis.com",
    "play-lh.googleusercontent.com",
    "android-safebrowsing.google.com",
    "safebrowsing.googleapis.com",
    "remoteprovisioning.googleapis.com",
    "dl.google.com",
    # Sandroid's own device->mitmproxy reachability probe (GET http://mitm.it/).
    "mitm.it",
)
#: Google's private ("-pa") API hosts are the OS / Play services / Google
#: apps talking to Google (infinitedata-pa, phonedeviceverification-pa,
#: playstoregatewayadapter-pa, geller-pa, locationhistory-pa, ...). An app
#: under analysis reaches Google through public hosts -- except Firebase
#: Analytics, which is the app's own tracker and stays visible.
_PA_SUFFIX = "-pa.googleapis.com"
_PA_NOT_NOISE = ("firebaselogging-pa.googleapis.com",)
#: www.googleapis.com paths only Play services uses (experiments/config,
#: anti-abuse, attestation, device check-in).
_NOISE_GOOGLEAPIS_PATHS = (
    "/experimentsandconfigs/",
    "/androidantiabuse/",
    "/androidcheck/",
    "/checkin",
    "/playatoms/",
)
_NOISE_HOST_PREFIXES = ("clients1.", "clients2.", "clients3.", "clients4.")
_NOISE_APPS = frozenset(
    {"com.google.android.gms", "com.android.vending", "com.google.android.gsf"}
)
_NOISE_PATHS = ("/generate_204", "/gen_204")

_TWO_PART_TLDS = ("co.uk", "com.au", "co.jp", "com.br", "co.in", "co.kr")


def _host_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def registrable_domain(host: str) -> str:
    """``api.fittrack.de`` -> ``fittrack.de`` (good enough for a label)."""
    host = (host or "").lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2 or host.replace(".", "").isdigit():
        return host
    keep = 3 if ".".join(parts[-2:]) in _TWO_PART_TLDS else 2
    return ".".join(parts[-keep:])


_INSIGHT_LABELLER: Any = None


def _insight_labeller() -> Any:
    """Dexray Insight's ``label_for_domain`` or ``False`` (imported once)."""
    global _INSIGHT_LABELLER
    if _INSIGHT_LABELLER is None:
        try:
            from dexray_insight.modules.tracker_analysis import label_for_domain

            _INSIGHT_LABELLER = label_for_domain
        except Exception:
            _INSIGHT_LABELLER = False
    return _INSIGHT_LABELLER


def recipient_of(host: str) -> tuple[str, bool]:
    """``(label, known)``: a known tracker/vendor name, else the domain.

    The name comes from Dexray Insight's tracker database (one source for
    the App lens's SDK list and these labels); a host Insight does not
    know, or no Insight 2.x at all, falls back to the built-in
    ``_RECIPIENTS`` table before the bare domain.
    """
    h = (host or "").lower()
    labeller = _insight_labeller()
    if labeller:
        try:
            match = labeller(h)
        except Exception:
            match = None
        if match:
            return str(match[0]), True
        # Not in Insight's database: the built-in table may still know it.
    for suffix, label in _RECIPIENTS:
        if _host_matches(h, suffix):
            return label, True
    return registrable_domain(h) or "?", False


def is_noise(host: str, path: str, app: str, focus_app: str | None = None) -> bool:
    """True for background OS traffic the lens hides by default.

    A flow attributed to the spotlight app is never noise.
    """
    if focus_app and app == focus_app:
        return False
    if app in _NOISE_APPS:
        return True
    h = (host or "").lower().rstrip(".")
    if any(_host_matches(h, s) for s in _NOISE_SUFFIXES):
        return True
    if h.endswith(_PA_SUFFIX) and not any(_host_matches(h, s) for s in _PA_NOT_NOISE):
        return True
    if h.startswith(_NOISE_HOST_PREFIXES) and h.endswith(".google.com"):
        return True
    p = (path or "").split("?", 1)[0]
    if h == "www.googleapis.com" and p.startswith(_NOISE_GOOGLEAPIS_PATHS):
        return True
    return p.endswith(_NOISE_PATHS)


# --------------------------------------------------------------------------
# formatting helpers
# --------------------------------------------------------------------------


def human_size(n: int | None) -> str:
    if n is None:
        return "–"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _ellipsize(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def smart_request(method: str, host: str, path: str, width: int) -> Text:
    """``POST api.example.com/v2/…/summary`` fitted into ``width`` cells.

    Drops the query string first, then elides middle path segments (keeping
    the first and the last), then cuts the end.
    """
    method = (method or "?").upper()
    path = path or "/"
    base = path.split("?", 1)[0]
    candidates = [path]
    if base != path:
        candidates.append(base + "?…")
    segs = [s for s in base.split("/") if s]
    if len(segs) > 2:
        candidates.append(f"/{segs[0]}/…/{segs[-1]}")
    if len(segs) > 1:
        candidates.append(f"/…/{segs[-1]}")
    room = width - len(method) - 1 - len(host)
    chosen = None
    for cand in candidates:
        if len(cand) <= room:
            chosen = cand
            break
    text = Text(no_wrap=True, overflow="ellipsis")
    text.append(method, style=lens_palette().muted)
    text.append(" ")
    if chosen is None:
        rest = _ellipsize(host + candidates[-1], max(1, width - len(method) - 1))
        hlen = min(len(host), len(rest))
        text.append(rest[:hlen], style=lens_palette().text)
        text.append(rest[hlen:], style=lens_palette().muted)
        return text
    text.append(host, style=lens_palette().text)
    text.append(chosen, style=lens_palette().muted)
    return text


def protocol_label(protocol: str) -> str:
    """``HTTPS/2.0`` -> ``HTTPS/2`` (older flow logs carry the long form)."""
    proto = (protocol or "").strip()
    for long, short in (("/2.0", "/2"), ("/3.0", "/3")):
        if proto.endswith(long):
            return proto[: -len(long)] + short
    return proto


def _short_error(error: str) -> str:
    e = (error or "").lower()
    for needle, word in (
        ("reset", "reset"),
        ("timed out", "timeout"),
        ("timeout", "timeout"),
        ("refused", "refused"),
        ("name or service", "dns"),
        ("dns", "dns"),
        ("killed", "killed"),
        ("disconnect", "closed"),
        ("closed", "closed"),
        ("certificate", "cert"),
        ("tls", "TLS"),
    ):
        if needle in e:
            return word
    return ""


def error_status(error: str | None) -> str:
    """The Status words of an errored flow: ``error timeout``, or ``error``
    alone when the reason is not one of the known kinds (never twice).
    """
    word = _short_error(error or "")
    return f"error {word}" if word else "error"


def cell_size(n: int) -> str:
    """``human_size`` for the Size cell: no decimal from 100 on (fits 16)."""
    if n < 1024:
        return f"{n} B"
    value, unit = n / 1024, "KB"
    if value >= 1024:
        value, unit = value / 1024, "MB"
    return f"{value:.1f} {unit}" if value < 100 else f"{value:.0f} {unit}"


def size_words(row: FlowRow) -> str:
    """The Size cell: ``sent 2.0 KB`` (a request body), else
    ``received 5.0 KB``; nothing when neither is known.
    """
    if row.req_bytes:
        return f"sent {cell_size(row.req_bytes)}"
    if row.resp_bytes:
        return f"received {cell_size(row.resp_bytes)}"
    return ""


def tls_word(row: FlowRow) -> str:
    """The TLS cell, from what the flow log records (never guessed).

    ``TLS failed`` for a failed handshake row, ``TLS`` when mitmproxy saw the
    flow over https / wss, ``plain`` over http / ws, nothing when the record
    has no protocol (older flow logs).
    """
    if row.kind == "tls":
        return "TLS failed"
    proto = (row.protocol or "").strip().upper()
    if proto.startswith("HTTPS") or proto == "WSS":
        return "TLS"
    if proto.startswith("HTTP") or proto == "WS":
        return "plain"
    return ""


def app_label(package: str, width: int) -> str:
    """The App cell: the package, or its trailing name parts when it does
    not fit (``com.ebay.kleinanzeigen`` -> ``kleinanzeigen``), cut without
    a glyph; nothing for a flow with no app.
    """
    package = package or ""
    if width <= 0 or len(package) <= width:
        return package
    parts = package.split(".")
    for i in range(1, len(parts)):
        tail = ".".join(parts[i:])
        if len(tail) <= width:
            return tail
    return parts[-1][:width]


def app_matches(app: str, package: str) -> bool:
    """Whether a flow's ``app`` is *package* (Shift+T "App only").

    App Proxy flows and device-proxy flows named by the identity relay carry
    the package; apps sharing one UID carry ``"a.b,c.d"`` (any of them
    matches).
    """
    if not app or not package:
        return False
    return app == package or package in app.split(",")


_TLS_REASONS = {
    "cert": (
        "The app rejected mitmproxy's certificate — likely certificate "
        "pinning, or the CA is not trusted yet."
    ),
    "ver": "TLS version mismatch between the app and mitmproxy.",
    "tls": "The TLS handshake with mitmproxy failed.",
}


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------


@dataclass
class FlowRow:
    """One row of the lens: a captured flow, or a TLS failure (``kind``)."""

    key: str
    ts: float
    method: str = "?"
    host: str = "?"
    path: str = "/"
    status: int | None = None
    error: str | None = None
    app: str = ""
    req_bytes: int = 0
    resp_bytes: int | None = None
    req_type: str | None = None
    resp_type: str | None = None
    protocol: str = ""
    ts_start: float | None = None
    seq: int | None = None
    flow_id: str | None = None
    flow_dir: Path | None = None
    kind: str = "flow"  # "flow" | "tls"
    reason: str = ""
    #: A flow-log TLS row already matched with its mitmweb stdout line.
    paired: bool = False
    #: Phase of the reviewed run the flow belongs to ("replay 1", "dry run",
    #: "setup"); "" when unknown (live rows, runs without phase data).
    phase: str = ""

    @classmethod
    def from_record(cls, rec: dict[str, Any], flow_dir: Path | None) -> FlowRow:
        seq = rec.get("seq")
        ts_end = rec.get("ts_end") or rec.get("ts_start") or 0.0
        if rec.get("kind") == "tls":
            # A persisted TLS handshake failure (no HTTP flow behind it). Its
            # flow-log record id ``tls-<seq>``, namespaced by the flow dir
            # (``tls_row_key``), is the annotation key (AI highlights, the
            # tools' row key); there is no detail file.
            fid = tls_row_key(
                flow_dir, rec.get("id") or (f"tls-{seq}" if seq is not None else None)
            )
            return cls(
                key=f"f{seq}" if seq is not None else f"f{rec.get('id')}",
                ts=float(ts_end or 0.0),
                method="TLS",
                host=str(rec.get("host") or "?"),
                path="",
                app=str(rec.get("app") or ""),
                seq=seq,
                flow_id=str(fid) if fid else None,
                kind="tls",
                reason=str(rec.get("tls_reason") or "tls"),
                phase=str(rec.get("phase") or ""),
            )
        return cls(
            key=f"f{seq}" if seq is not None else f"f{rec.get('id')}",
            ts=float(ts_end or 0.0),
            method=str(rec.get("method") or "?"),
            host=str(rec.get("host") or "?"),
            path=str(rec.get("path") or "/"),
            status=rec.get("status_code"),
            error=rec.get("error"),
            app=str(rec.get("app") or ""),
            req_bytes=int(rec.get("request_bytes") or 0),
            resp_bytes=rec.get("response_bytes"),
            req_type=rec.get("request_content_type"),
            resp_type=rec.get("response_content_type"),
            protocol=str(rec.get("protocol") or ""),
            ts_start=rec.get("ts_start"),
            seq=seq,
            flow_id=rec.get("id"),
            flow_dir=flow_dir,
            phase=str(rec.get("phase") or ""),
        )

    @property
    def failed(self) -> bool:
        return self.kind == "tls" or bool(self.error)

    @property
    def recipient(self) -> tuple[str, bool]:
        return recipient_of(self.host)

    def url(self) -> str:
        scheme = "https" if "HTTPS" in self.protocol.upper() else "http"
        if self.protocol.upper().startswith("WS"):
            scheme = "wss" if self.protocol.upper() == "WSS" else "ws"
        return f"{scheme}://{self.host}{self.path}"


def _flow_dir() -> Path:
    """The live session's ``mitm_flows`` directory (patched in tests)."""
    from sandroid.services.mitmproxy_flow_log import resolve_flow_dir

    return resolve_flow_dir()


def _run_window(scope: str) -> tuple[str, float | None, float | None] | None:
    """``(label, start epoch, end epoch)`` of the scoped run, or None.

    Thin adapter over the shared ``run_history.resolve_scope`` (``scope`` is
    the run folder as an absolute path; times are the Play press and the end
    of its analysis, from ``run.json``).
    """
    from sandroid.core import run_history

    run = run_history.resolve_scope(scope)
    if run is None:
        return None
    start = run.started_at.timestamp() if run.started_at else None
    end = run.ended_at.timestamp() if run.ended_at else start
    if start is not None and end is not None:
        end = max(start, end)
    return run.label, start, end


#: Phases of a reviewed run hidden by default (``A`` shows them).
HIDDEN_PHASES = ("dry run", "setup")


def _phase_tag(phase: str) -> str:
    """Short marker in the Request cell for a hidden-by-default phase."""
    return {"dry run": "dry", "setup": "setup"}.get(phase, "")


def run_pcaps(run_dir: Path | None) -> list[tuple[str, int]]:
    """``[(path relative to the run folder, bytes)]`` of the run's pcaps."""
    if run_dir is None:
        return []
    out: list[tuple[str, int]] = []
    try:
        for path in sorted(Path(run_dir).rglob("*.pcap*")):
            if path.is_file():
                out.append((path.relative_to(run_dir).as_posix(), path.stat().st_size))
    except OSError:
        pass
    return out


@dataclass
class ReviewData:
    """What ``NetworkPanel.load_run_flows`` found for a reviewed run."""

    rows: list[FlowRow]
    #: "bundle" (the run's own flows), "window" (session log, old run) or a
    #: reason the run could not be read.
    source: str
    window: tuple[float, float] | None
    label: str | None
    #: The bundle's ``network/meta.json`` (None: no flows stored in it).
    meta: dict[str, Any] | None = None
    pcaps: list[tuple[str, int]] | None = None
    run_dir: Path | None = None
    phases_known: bool = False


# --------------------------------------------------------------------------
# inspector rendering
# --------------------------------------------------------------------------

#: Body text shown in the Inspector at most (the capture itself is capped
#: by the addon; this keeps a huge JSON from stalling the render).
BODY_DISPLAY_CAP = 16 * 1024


def _grid() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=lens_palette().muted, no_wrap=True)
    grid.add_column(overflow="fold")
    return grid


def _headers_renderable(headers: Any) -> RenderableType:
    if not headers:
        return Text("none", style=lens_palette().dim)
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=lens_palette().muted, no_wrap=True)
    grid.add_column(overflow="fold")
    for i, pair in enumerate(headers):
        if i >= 60:
            grid.add_row(
                "…", Text(f"{len(headers) - 60} more", style=lens_palette().dim)
            )
            break
        try:
            name, value = pair[0], pair[1]
        except (IndexError, TypeError, KeyError):
            continue
        value = str(value)
        if len(value) > 300:
            value = value[:299] + "…"
        grid.add_row(Text(str(name)), Text(value))
    return grid


def _hex_preview(raw: bytes, limit: int = 128, per_line: int = 8) -> Text:
    """Hex + ASCII preview; 8 bytes a line fit the Inspector without wrapping."""
    out = Text(style=lens_palette().muted)
    chunk = raw[:limit]
    width = per_line * 3 - 1
    for off in range(0, len(chunk), per_line):
        line = chunk[off : off + per_line]
        hexpart = " ".join(f"{b:02x}" for b in line)
        asc = "".join(chr(b) if 32 <= b < 127 else "·" for b in line)
        out.append(f"{off:04x}  {hexpart:<{width}}  {asc}\n")
    return out


def body_renderable(body: Any, content_type: str | None) -> RenderableType:
    """Decoded, capped body: pretty JSON, form fields, text, or a hex note."""
    if not isinstance(body, dict) or not body.get("size_bytes"):
        return Text("empty", style=lens_palette().dim)
    size = int(body.get("size_bytes") or 0)
    note = ""
    if body.get("truncated"):
        note = f"captured {human_size(body.get('bytes_read'))} of {human_size(size)}"
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    content = body.get("content") or ""
    parts: list[RenderableType] = []
    encoding = str(body.get("content_encoding") or "")
    if encoding and body.get("decode_failed"):
        parts.append(
            Text(
                f"{encoding}-encoded; could not be decoded, shown as received",
                style=lens_palette().warn,
            )
        )
    elif encoding:
        wire = body.get("encoded_bytes")
        on_wire = f" · {human_size(int(wire))} on the wire" if wire else ""
        parts.append(
            Text(f"decoded from {encoding}{on_wire}", style=lens_palette().dim)
        )
    if body.get("encoding") == "base64":
        try:
            raw = base64.b64decode(content)
        except (ValueError, TypeError):
            raw = b""
        label = f"binary · {human_size(size)}" + (f" · {ctype}" if ctype else "")
        parts.append(Text(label, style=lens_palette().muted))
        if raw:
            parts.append(_hex_preview(raw))
    else:
        text = content[:BODY_DISPLAY_CAP]
        if len(content) > BODY_DISPLAY_CAP:
            note = (
                note or f"showing {human_size(BODY_DISPLAY_CAP)} of {human_size(size)}"
            )
        stripped = text.lstrip()
        rendered: RenderableType | None = None
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                pretty = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
                rendered = Syntax(
                    pretty,
                    "json",
                    theme="ansi_dark",
                    word_wrap=True,
                    background_color="default",
                )
            except ValueError:
                rendered = None
        if rendered is None and "x-www-form-urlencoded" in ctype:
            pairs = parse_qsl(text, keep_blank_values=True)
            if pairs:
                rendered = _headers_renderable(pairs)
        if rendered is None:
            rendered = Text(text)
        parts.append(rendered)
    if note:
        parts.append(Text(note, style=lens_palette().dim))
    from rich.console import Group

    return Group(*parts)


# --------------------------------------------------------------------------
# identity profile values (privacy scan): words, colours, snippets
# --------------------------------------------------------------------------
#
# Shared by the Network, Files, Timeline and Sessions lenses. Everything here
# reads the privacy scan service's in-memory records only (no file reads) and
# speaks in plain words: no glyphs, colours from the lens theme tokens.

#: The Identity column is shown from this lens width on (the row tint stays).
PRIVACY_COLUMN_MIN_WIDTH = 100


def flow_record_of(hit: Any) -> dict[str, Any]:
    """A flow-log record (the shape ``FlowRow.from_record`` reads) built
    from a privacy hit's source, to open a flow that is not listed.
    """
    src = hit.source or {}
    return {
        "id": hit.flow_id,
        "seq": src.get("flow_seq"),
        "method": src.get("method"),
        "host": src.get("host"),
        "path": src.get("path"),
        "app": src.get("app"),
        "ts_start": hit.t,
        "ts_end": hit.t,
    }


def privacy_service() -> Any | None:
    """The privacy scan service, or None when it is not available."""
    try:
        from sandroid.services import privacy_scan

        return privacy_scan.get_privacy_scan_service()
    except Exception:
        logger.debug("privacy scan service unavailable", exc_info=True)
        return None


def encoding_words(transform: str) -> str:
    """``sha256(lower(value))`` -> ``sha256 of the lower-case value``;
    ``value`` -> ``as is``; ``round(value, 4)`` -> ``rounded to 4 decimals``.
    """
    from sandroid.core.report_engine import transform_words

    return transform_words(transform)


def where_words(part: str, source: dict | None = None, offsets: Any = ()) -> str:
    """Where in a flow or file a value was found, in words.

    ``url`` is ``query string`` when the match lies after the ``?`` (else
    ``URL path`` / ``host name``); headers name the header; ``file:<member>``
    names a companion file (``-wal``) when it is not the file itself.
    """
    part = part or ""
    if part == "url":
        src = source or {}
        host = str(src.get("host") or "")
        full = host + str(src.get("path") or "")
        first = next(iter(offsets or ()), None)
        query = full.find("?")
        if isinstance(first, int):
            if query >= 0 and first > query:
                return "query string"
            if first < len(host):
                return "host name"
            return "URL path"
        return "URL"
    head, _, name = part.partition(":")
    if head == "req.header":
        return f"header {name}"
    if head == "resp.header":
        return f"response header {name}"
    if head == "req.body":
        return "request body"
    if head == "resp.body":
        return "response body"
    if head == "file":
        device_path = str((source or {}).get("device_path") or "")
        if not name or device_path.rsplit("/", 1)[-1] == name:
            return "file"
        return f"file {name}"
    return part.replace(".", " ")


def party_words(party: str | None) -> str:
    from sandroid.services.privacy_scan import party_words as words

    return words(party)


def confidence_words(confidence: str | None) -> str:
    return f"{confidence or 'low'} confidence"


def party_color(party: str | None) -> str:
    """Theme colour of a party: third = warn, first / stored = accent."""
    from sandroid.services.privacy_scan import party_role

    return str(getattr(lens_palette(), party_role(party)))


def _distinct_tags(tags: Any) -> list:
    """One tag per shown word: markers can share one (GPS latitude and
    longitude are both ``GPS``); the first, strongest, one stays.
    """
    seen: set[str] = set()
    out = []
    for tag in tags or ():
        word = str(tag.tag or tag.label)
        if word not in seen:
            seen.add(word)
            out.append(tag)
    return out


def tag_words(tags: Any, width: int | None = None) -> Text:
    """``Ad ID, GPS, Email`` coloured by party (strongest first)."""
    text = Text(no_wrap=True, overflow="ellipsis")
    for i, tag in enumerate(_distinct_tags(tags)):
        if i:
            text.append(", ")
        text.append(str(tag.tag or tag.label), style=party_color(tag.party))
    if width is not None and width > 0:
        text.truncate(width, overflow="ellipsis")
    return text


def tags_plain(tags: Any) -> str:
    return ", ".join(str(t.tag or t.label) for t in _distinct_tags(tags))


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in str(text or ""))


def snippet_text(snippet: Any) -> Text:
    """``(before, match, after)`` with the match on a warn-coloured background."""
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    before, match, after = (list(snippet or ()) + ["", "", ""])[:3]
    text = Text(overflow="fold")
    text.append(_clean(before), style=pal.dim)
    text.append(_clean(match), style=Style(color=pal.bg, bgcolor=pal.warn, bold=True))
    text.append(_clean(after), style=pal.dim)
    return text


def _hit_order(hit: Any) -> tuple:
    from sandroid.core.privacy_markers import CONFIDENCES

    rank = {"sent": 0, "stored": 1, "received": 2}
    conf = CONFIDENCES.index(hit.confidence) if hit.confidence in CONFIDENCES else 9
    return (rank.get(hit.direction, 9), conf, str(hit.label).lower(), hit.part)


def hit_lines(hit: Any, *, with_snippet: bool = True) -> Text:
    """One hit in words: value, where, encoding, party, confidence, snippet."""
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    recipient = hit.recipient or {}
    party = recipient.get("party") if hit.direction != "stored" else "stored"
    out = Text()
    out.append(str(hit.label), style=Style(color=party_color(party), bold=True))
    if hit.count > 1:
        out.append(f"  {hit.count} times", style=pal.dim)
    out.append("\n  ")
    out.append(where_words(hit.part, hit.source, hit.offsets), style=pal.text)
    out.append(", ", style=pal.dim)
    out.append(encoding_words(hit.transform), style=pal.text)
    if hit.approx:
        out.append(", less precise than seeded", style=pal.dim)
    out.append("\n  ")
    if hit.direction == "received":
        out.append("came back in the response", style=pal.muted)
        if hit.echo:
            out.append(" after it was sent", style=pal.muted)
    elif hit.direction == "stored":
        out.append("stored on the device", style=party_color("stored"))
    else:
        label = recipient.get("label") or hit.source.get("host") or "unknown"
        out.append(f"sent to {label}, ", style=pal.muted)
        out.append(party_words(party), style=party_color(party))
    out.append(", ", style=pal.dim)
    conf_style = pal.dim if hit.confidence == "low" else pal.muted
    out.append(confidence_words(hit.confidence), style=conf_style)
    if with_snippet and any(hit.snippet or ()):
        out.append("\n  ")
        out.append_text(snippet_text(hit.snippet))
    return out


def hits_renderable(hits: Any) -> RenderableType:
    """Every hit of a flow or file, strongest first, one block each."""
    from rich.console import Group

    blocks: list[RenderableType] = []
    for i, hit in enumerate(sorted(hits or (), key=_hit_order)):
        if i:
            blocks.append(Text(""))
        blocks.append(hit_lines(hit))
    return Group(*blocks)


def _privacy_tags_for_flow(flow_id: str | None, service: Any = None) -> list:
    if not flow_id:
        return []
    if service is None:
        service = privacy_service()
    if service is None:
        return []
    try:
        return list(service.tags_for_flow(flow_id))
    except Exception:
        return []


def privacy_has_hits(service: Any) -> bool:
    """The service has loaded hit records (``has_hits``; no copy of them)."""
    if service is None:
        return False
    has_hits = getattr(service, "has_hits", None)
    if has_hits is not None:
        return bool(has_hits())
    return bool(service.hits())


def identity_mode_on() -> bool:
    """The ``[identity]`` mode is ``profile`` (in-memory config, no I/O)."""
    try:
        from sandroid.config import get_config

        return get_config().identity.mode == "profile"
    except Exception:
        return False


def privacy_annotations() -> Any | None:
    """The registered privacy row-annotation provider (cached tag lookups
    shared by the row tint, the Identity column, ``!`` and ``/``), or None.
    """
    try:
        from sandroid.services.privacy_scan import annotations_provider

        return annotations_provider()
    except Exception:
        return None


# --------------------------------------------------------------------------
# the lens
# --------------------------------------------------------------------------


class FlowTable(AnnotationTintMixin, DataTable):
    """The flow table: Home / End jump to the first / last row.

    DataTable's own Home / End scroll sideways (the cursor is a row cursor
    here, so they did nothing visible; End never reached the newest flow).

    Rows are tinted by their row annotations (``row_annotations``: flows
    carrying identity-profile values, AI marks); the annotation key of a row
    is its mitmproxy flow id (TLS failures: ``tls_row_key`` of the flow-log
    id), not the row key ``f<seq>``.

    Moving up (↑, PgUp, Home, a wheel up, a click above the newest row) stops
    following the newest flow; End resumes (``follow.py``).
    """

    BINDINGS = [
        Binding("home", "scroll_top", "First row", show=False),
        Binding("end", "scroll_bottom", "Newest row, live", show=False),
    ]

    annotation_lens = LENS_NETWORK

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._owner_panel: NetworkPanel | None = None

    def annotation_key(self, row_key_value: Any) -> str | None:
        """Row key ``f<seq>`` -> the flow id (TLS failures: ``tls_row_key``)."""
        panel = self._owner_panel
        if panel is None:
            panel = self._owner_panel = self._panel()
        return panel.annotation_flow_id(row_key_value) if panel is not None else None

    def _panel(self) -> NetworkPanel | None:
        for node in self.ancestors:
            if isinstance(node, NetworkPanel):
                return node
        return None

    def _follow(self, live: bool) -> None:
        panel = self._panel()
        if panel is not None:
            panel.set_following(live)

    def action_cursor_up(self) -> None:
        super().action_cursor_up()
        self._follow(False)

    def action_page_up(self) -> None:
        super().action_page_up()
        self._follow(False)

    def action_scroll_top(self) -> None:
        super().action_scroll_top()
        self._follow(False)

    def action_scroll_bottom(self) -> None:
        super().action_scroll_bottom()
        self._follow(True)

    def on_click(self, event) -> None:
        try:
            row = event.style.meta.get("row")
        except Exception:
            row = None
        if isinstance(row, int) and 0 <= row < self.row_count - 1:
            self._follow(False)

    def on_mouse_scroll_up(self, _event) -> None:
        self._follow(False)


class NetworkPanel(Widget):
    """Network lens (id ``network-panel``): flow table + hidden controllers."""

    can_focus = True

    #: Rows kept in memory (live and per reviewed run).
    MAX_ROWS = 2000
    POLL_SECONDS = 1.0

    BINDINGS = [
        # Shown in the footer, which keeps two lens keys: "␣ start mitm" and
        # "^D device proxy" while nothing is captured, then "/" and "T".
        # Space, not Enter: Enter means "inspect" in every lens (MainScreen).
        # Space only STARTS mitmproxy; stopping it (which also clears our
        # device proxy) stays on the deliberate M.
        Binding("space", "start_mitm", "Start mitm", key_display="␣"),
        Binding("slash", "filter", "Filter"),
        Binding("T", "toggle_app_only", "App only"),
        Binding("W", "network_method", "Network method", show=False),
        Binding("ctrl+d", "mitm('toggle_device')", "Device proxy"),
        Binding("N", "toggle_noise", "Show OS noise", show=False),
        Binding("H", "cycle_highlight_filter", "AI filter: next set / off", show=False),
        Binding("X", "clear_highlights", "Clear the AI highlights", show=False),
        Binding("I", "status", "Capture status", show=False),
        Binding("M", "mitm('toggle_running')", "Start/stop mitm", show=False),
        Binding("ctrl+n", "mitm('inject_ca')", "Install CA", show=False),
        Binding("ctrl+p", "mitm('toggle_ssl_unpin')", "SSL unpin", show=False),
        Binding("ctrl+r", "mitm('restart')", "Restart mitm", show=False),
        Binding("ctrl+a", "mitm('manage_addons')", "Addons", show=False),
        Binding("ctrl+o", "mitm('open_browser')", "Open mitmweb", show=False),
        Binding("ctrl+v", "mitm('toggle_verbose')", "Verbose plumbing", show=False),
        Binding("ctrl+l", "clear_view", "Clear view", show=False),
        Binding("ctrl+f", "fritap_output", "friTap output", show=False),
        Binding("A", "toggle_phases", "Review: show dry-run/setup flows", show=False),
        Binding(
            "exclamation_mark",
            "toggle_profile_only",
            "Only flows with profile values",
            key_display="!",
            show=False,
        ),
    ]

    DEFAULT_CSS = """
    NetworkPanel {
        layout: vertical;
        height: 1fr;
        background: $lens-bg;
    }
    NetworkPanel > #net-method {
        height: auto;
        padding: 0 1;
        background: $lens-bg;
        color: $lens-text;
    }
    NetworkPanel > #net-method.-hidden {
        display: none;
    }
    NetworkPanel > #net-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: $lens-input-bg;
        color: $lens-input-text;
    }
    NetworkPanel > #net-filter.-open {
        display: block;
    }
    NetworkPanel > #net-filter:focus {
        border: none;
        background: $lens-input-focus-bg;
    }
    NetworkPanel > #net-flows {
        height: 1fr;
        background: $lens-bg;
        color: $lens-text;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 0;
    }
    NetworkPanel > #net-flows.-empty {
        display: none;
    }
    NetworkPanel > #net-flows.-filtered-empty {
        height: 2;
    }
    NetworkPanel > #net-flows > .datatable--header {
        background: $lens-bg;
        color: $lens-header;
        text-style: none;
    }
    NetworkPanel > #net-flows > .datatable--cursor {
        background: $lens-input-focus-bg;
        text-style: none;
    }
    NetworkPanel > #net-flows:focus > .datatable--cursor {
        background: $lens-cursor-focus;
    }
    NetworkPanel > #net-flows > .datatable--hover {
        background: $lens-cursor;
    }
    NetworkPanel > #net-empty {
        display: none;
        height: 1fr;
        align: center middle;
    }
    NetworkPanel > #net-empty.-shown {
        display: block;
    }
    NetworkPanel #net-empty-head {
        width: 100%;
        content-align: center middle;
        text-align: center;
        color: $lens-text;
    }
    NetworkPanel #net-empty-hint {
        width: 100%;
        margin: 1 0 0 0;
        text-align: center;
        color: $lens-dim;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        # live model
        self._live: list[FlowRow] = []
        self._cursor: int | None = None
        self._live_dir: Path | None = None
        self._stat: tuple[int, int] | None = None
        self._poll_busy = False
        self._poll_again = False
        #: ``(flow id, record)`` a ``J`` asked for before it was loaded: the
        #: next poll reveals it (see :meth:`reveal_flow`).
        self._pending_reveal: tuple[str, dict | None] | None = None
        self._tls_n = 0
        self._unseen_tls = 0
        self._floor_seq = 0
        # review model
        self._scope: str | None = None
        self._scope_label: str | None = None
        self._scope_label_given = False
        self._review: list[FlowRow] = []
        self._review_note = ""
        self._review_window: tuple[float, float] | None = None
        self._review_loading = False
        self._review_data: ReviewData | None = None
        #: Show the reviewed run's dry-run / setup flows too (``A``).
        self._show_all_phases = False
        #: Rows hidden only because of their phase (caption counts them).
        self._phase_hidden: dict[str, int] = {}
        # view state
        self._filter = ""
        self._app_only = False
        self._show_noise = False
        self._focus_app: str | None = None
        self._shown = 0
        # Rows hidden only because they are OS noise (shown in the caption).
        self._noise_hidden = 0
        self._width = -1
        self._net_layout: list[tuple[str, str, int]] = []
        self._status_pending = False
        self._filter_timer = None
        # identity profile values (privacy scan; see the _privacy_* methods)
        self._profile_only = False
        #: Row annotations (privacy, AI marks) of drawn flows changed.
        self._privacy_feed = AnnotationFeed(self, LENS_NETWORK, self._privacy_flush)
        #: (model, its length, row key -> row): the flow id of a row key.
        self._flow_index: tuple[Any, int, dict[str, FlowRow]] = (None, 0, {})
        #: Follow the newest flow (``follow.py``); live rows only.
        self._follow = Follow()
        #: AI highlight sets (``highlight_bar``), keyed by flow id.
        self._hl = HighlightView(LENS_NETWORK, noun="flow")

    # -- compose / mount -------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("", id="net-method")
        yield HighlightBar("", id="net-highlights")
        yield Input(
            placeholder="filter: host · path · app · status (Esc clears)",
            id="net-filter",
        )
        table: DataTable = FlowTable(
            id="net-flows",
            cursor_type="row",
            zebra_stripes=False,
            classes="-empty",
        )
        table.cell_padding = 1
        yield table
        with Vertical(id="net-empty", classes="-shown"):
            yield Static("", id="net-empty-head")
            yield Static("", id="net-empty-hint")
        yield MitmproxyPanel(id="mitm-panel")
        yield FriTapPanel(id="fritap-panel")

    def on_mount(self) -> None:
        # Recipient labels come from Dexray Insight; its first import takes
        # ~0.2 s (androguard), so warm it off the UI thread.
        self.run_worker(_insight_labeller, thread=True, name="net-insight-labels")
        self._privacy_feed.attach()
        self._rebuild()
        try:
            self.set_interval(self.POLL_SECONDS, self._tick)
        except Exception:
            pass
        self._do_refresh_status()
        self._hl.attach(self, self._redraw_highlights, self._highlight_rows_snapshot)
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            pass
        self._method_attach()

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        """A live theme switch: cells and the highlight bar take the new
        palette (their Rich styles are built from ``lens_palette()``).
        """
        if self.is_attached:
            self._rebuild()

    # -- accessors ---------------------------------------------------------

    @property
    def mitm(self) -> MitmproxyPanel | None:
        try:
            return self.query_one("#mitm-panel", MitmproxyPanel)
        except Exception:
            return None

    @property
    def fritap(self) -> FriTapPanel | None:
        try:
            return self.query_one("#fritap-panel", FriTapPanel)
        except Exception:
            return None

    @property
    def table(self) -> DataTable:
        return self.query_one("#net-flows", DataTable)

    @property
    def in_review(self) -> bool:
        return self._scope is not None

    def _model(self) -> list[FlowRow]:
        return self._review if self.in_review else self._live

    def _main_screen(self):
        screen = getattr(self, "screen", None)
        return screen if hasattr(screen, "set_lens_caption") else None

    def _lens_active(self) -> bool:
        ms = self._main_screen()
        try:
            return bool(
                ms is not None and ms.is_lens_active(LENS_ID) and is_shown(self)
            )
        except Exception:
            return False

    # -- focus -------------------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Focus the flow table when it is visible, else the lens itself."""
        try:
            table = self.table
            if table.display and not table.has_class("-empty"):
                table.focus(scroll_visible)
                return self
        except Exception:
            pass
        return super().focus(scroll_visible)

    # -- polling -----------------------------------------------------------

    def _tick(self) -> None:
        if is_shown(self):
            self._sync_privacy_column()
            self.poll_now()

    def flow_hint(self) -> None:
        """A ``[FLOW]`` line arrived: poll soon if the lens is visible."""
        if is_shown(self):
            self.poll_now()

    def poll_now(self) -> None:
        """Kick one off-thread poll (coalesced while one is in flight)."""
        if self._poll_busy:
            self._poll_again = True
            return
        self._poll_busy = True
        cursor, live_dir, stat = self._cursor, self._live_dir, self._stat
        try:
            self.run_worker(
                lambda: self._poll_job(cursor, live_dir, stat),
                thread=True,
                group="network-poll",
                exit_on_error=False,
            )
        except Exception:
            self._poll_busy = False

    def _poll_job(
        self,
        cursor: int | None,
        live_dir: Path | None,
        stat: tuple[int, int] | None,
    ) -> None:
        result = None
        try:
            result = self.fetch_new(cursor, live_dir, stat)
        except Exception:
            logger.debug("network lens poll failed", exc_info=True)
        try:
            self.app.call_from_thread(self._apply_poll, result)
        except Exception:
            self._poll_busy = False

    def fetch_new(
        self,
        cursor: int | None,
        live_dir: Path | None,
        stat: tuple[int, int] | None,
    ) -> tuple[Path, list[dict], int | None, tuple[int, int] | None, bool] | None:
        """Read flows newer than ``cursor`` (any thread; no UI access).

        Returns ``(flow dir, records, new cursor, file stat, reset)`` or None
        when nothing changed. ``reset`` means the flow directory changed (a
        device switch) and the live model must start over.
        """
        from sandroid.services.mitmproxy_flow_log import HARD_LIMIT_CAP, query_flows

        flow_dir = _flow_dir()
        reset = live_dir is not None and flow_dir != live_dir
        if reset:
            cursor, stat = None, None
        try:
            st = (flow_dir / "flows.jsonl").stat()
            new_stat: tuple[int, int] | None = (st.st_size, st.st_mtime_ns)
        except OSError:
            new_stat = None
        if new_stat is not None and new_stat == stat and not reset:
            return None
        if new_stat is None:
            return (flow_dir, [], cursor, None, reset)
        records: list[dict] = []
        if cursor is None:
            res = query_flows(flow_dir, limit=min(HARD_LIMIT_CAP, self.MAX_ROWS))
            records = list(res["flows"])
            cursor = res["next_cursor"] if records else res.get("next_cursor") or 0
        else:
            for _ in range(5):
                res = query_flows(flow_dir, since_cursor=cursor, limit=HARD_LIMIT_CAP)
                records.extend(res["flows"])
                cursor = res["next_cursor"]
                if not res["truncated"] or len(records) >= self.MAX_ROWS:
                    break
        return (flow_dir, records[-self.MAX_ROWS :], cursor, new_stat, reset)

    def _apply_poll(self, result) -> None:
        self._poll_busy = False
        if result is not None:
            flow_dir, records, cursor, stat, reset = result
            if reset:
                # Another flow dir (a device switch): its seqs and TLS keys
                # mean nothing here. Only stdout TLS rows not paired yet stay.
                self._live = [
                    r
                    for r in self._live
                    if r.kind == "tls" and r.seq is None and r.flow_id is None
                ]
                self._floor_seq = 0
            self._live_dir = flow_dir
            self._cursor = cursor
            self._stat = stat
            rows = [
                FlowRow.from_record(r, flow_dir)
                for r in records
                if (r.get("seq") or 0) > self._floor_seq
            ]
            n = len(rows)
            rows = [r for r in rows if not self._claim_live_tls(r)]
            if reset:
                self._rebuild_if_live()
            if rows:
                self._add_live(rows)
            if len(rows) < n and self._hl.active and not self.in_review:
                # A stdout TLS row adopted its key: an AI highlight made
                # meanwhile (the tools pair it) shows in its cell now.
                self._rebuild()
        if self._poll_again:
            self._poll_again = False
            self.poll_now()
        if not self._poll_busy and self._pending_reveal is not None:
            self._resolve_pending_reveal()

    # -- live rows -------------------------------------------------------

    def add_tls_failure(self, ts: str, host: str, reason: str, app: str) -> None:
        """A ``[TLS_FAIL]`` line from mitmweb (UI thread)."""
        self._tls_n += 1
        now = time.time()
        # The flow-log poll can beat mitmweb's stdout: then the row is there
        # (oldest unpaired first, as the failures happened in that order).
        for r in self._live[-50:]:
            if (
                r.kind == "tls"
                and r.key.startswith("f")
                and not r.paired
                and r.host == (host or "?")
                and abs(r.ts - now) <= 10.0
            ):
                r.paired = True
                break
        else:
            row = FlowRow(
                key=f"t{self._tls_n}",
                ts=now,
                host=host or "?",
                path="",
                method="TLS",
                app=app or "",
                kind="tls",
                reason=reason or "tls",
            )
            self._add_live([row])
        if not self._lens_active():
            self._unseen_tls += 1
            ms = self._main_screen()
            if ms is not None:
                ms.set_lens_badge(LENS_ID, f"{self._unseen_tls} TLS failed")

    def _claim_live_tls(self, row: FlowRow) -> bool:
        """A persisted TLS failure that is already on screen (from mitmweb's
        stdout, which is faster than the flow log): adopt its ``seq`` and
        drop the duplicate. Returns True when ``row`` was a duplicate.

        Records come in ``seq`` order, so the oldest unpaired stdout row is
        taken first (two failures to one host within 10 s keep their order).
        The AI tools pair the same way off the UI thread (``lens_rows``).
        """
        if row.kind != "tls":
            return False
        for live in self._live[-400:]:
            if (
                live.kind == "tls"
                and live.seq is None
                and live.key.startswith("t")
                and live.host == row.host
                and abs(live.ts - row.ts) <= 10.0
            ):
                # Adopt the record's id too: from now on the stdout row has
                # the stable annotation key (``tls_row_key``, AI highlights).
                live.seq = row.seq
                live.flow_id = row.flow_id
                return True
        return False

    def _add_live(self, rows: list[FlowRow]) -> None:
        """Add live rows in time order (``FlowRow.ts``, the request start).

        A flow reaches the lens when it finishes, a TLS failure at once, so a
        long request can arrive after rows that started later: such a row is
        put in its place and the table is redrawn (the cursor stays on its
        flow); rows that are newest go to the bottom as before.
        """
        rows = sorted(rows, key=lambda r: r.ts)
        if self._live and rows[0].ts < self._live[-1].ts:
            for row in rows:
                bisect.insort_right(self._live, row, key=lambda r: r.ts)
            if len(self._live) > self.MAX_ROWS:
                self._live = self._live[-self.MAX_ROWS :]
            if not self.in_review:
                passing = sum(1 for row in rows if self._passes(row))
                self._rebuild()
                self._follow.added(passing)
            self._do_refresh_status()
            return
        self._live.extend(rows)
        if len(self._live) > self.MAX_ROWS + 200:
            passing = sum(1 for row in rows if self._passes(row))
            self._live = self._live[-self.MAX_ROWS :]
            self._rebuild_if_live()
            if not self.in_review:
                self._follow.added(passing)
        elif not self.in_review:
            self._append_rows(rows)
        self._do_refresh_status()

    def _rebuild_if_live(self) -> None:
        if not self.in_review:
            self._rebuild()

    # -- filters -----------------------------------------------------------

    def _spotlight_package(self) -> str | None:
        try:
            from sandroid.services import get_spotlight_service

            app = get_spotlight_service().get_app_tuple()
        except Exception:
            app = None
        return app[0] if app else None

    def _passes(self, row: FlowRow, *, noise: bool = True, ai: bool = True) -> bool:
        """Whether ``row`` is shown (``noise=False``: ignore the noise filter;
        ``ai=False``: ignore the AI filter, see ``highlight_bar``).
        """
        if self.in_review and not self._show_all_phases and row.phase in HIDDEN_PHASES:
            return False
        if self._profile_only and not self._flow_tags(row):
            return False
        if (
            self._app_only
            and self._focus_app
            and not app_matches(row.app, self._focus_app)
        ):
            return False
        if (
            noise
            and not self._show_noise
            and is_noise(row.host, row.path, row.app, self._focus_app)
            and not self._hl.bypass_noise(row.flow_id)
        ):
            return False
        if ai and not self._hl.passes(row.flow_id):
            return False
        if self._filter:
            needle = self._filter.lower()
            if needle not in self._haystack(row):
                return False
        return True

    def _haystack(self, row: FlowRow) -> str:
        """What ``/`` matches: host, path, method, app, recipient, status.

        The status column's words are included, so ``/404``, ``/tls`` or
        ``/error`` (every errored flow) work too.
        """
        if row.kind == "tls":
            status = f"tls failed {row.reason}"
        elif row.error:
            status = error_status(row.error)
        else:
            status = str(row.status) if row.status is not None else ""
        hay = f"{row.method} {row.host}{row.path} {row.app} {row.recipient[0]} {status}"
        hay += " " + tags_plain(self._flow_tags(row))
        return hay.lower()

    def _count_phase_hidden(self) -> dict[str, int]:
        """``{phase: n}`` of reviewed rows hidden only by the phase filter."""
        if not self.in_review or self._show_all_phases:
            return {}
        out: dict[str, int] = {}
        for row in self._review:
            if row.phase in HIDDEN_PHASES:
                out[row.phase] = out.get(row.phase, 0) + 1
        return out

    def _count_noise(self, rows: list[FlowRow]) -> int:
        """How many of ``rows`` the noise filter alone hides."""
        if self._show_noise:
            return 0
        return sum(
            1
            for row in rows
            if is_noise(row.host, row.path, row.app, self._focus_app)
            and self._passes(row, noise=False)
            and not self._hl.bypass_noise(row.flow_id)
        )

    # -- table -------------------------------------------------------------

    def _layout(self) -> list[tuple[str, str, int]]:
        """``[(key, label, width)]`` of the visible columns for this width.

        Time | App | Recipient | Request | TLS | Identity | Status | Size when
        there is room; a narrow lens (e.g. 100 columns with the Inspector
        open) drops Size, then TLS, then Time, then App (``LAYOUT_DROP_ORDER``)
        until Request has ``REQUEST_MIN_WIDTH`` cells, instead of scrolling
        sideways. Identity keeps its own rule (``_privacy_columns``).
        """
        avail = self.size.width or 120
        who = 18 if avail >= 110 else (16 if avail >= 58 else 12)
        app = 20 if avail >= 140 else 14
        cols = [
            ("time", "Time", 8),
            ("app", "App", app),
            ("who", "Recipient", who),
            ("req", "Request", 0),
            ("tls", "TLS", 10),
        ]
        cols += self._privacy_columns(avail)
        cols += [("status", "Status", 13), ("size", "Size", 16)]

        def fixed_of(columns: list[tuple[str, str, int]]) -> int:
            # 2 cells padding per column + 1 scrollbar column
            return sum(w for _, _, w in columns) + 2 * len(columns) + 1

        for key in LAYOUT_DROP_ORDER:
            if avail - fixed_of(cols) >= REQUEST_MIN_WIDTH:
                break
            cols = [c for c in cols if c[0] != key]
        # The Highlight column (AI highlights exist) may take Size's place,
        # but only while Request keeps a readable width (with the Identity
        # column too, a ~100 column lens has no room).
        if self._hl.show_column(avail):
            with_hl = [*cols, ("hl", "Highlight", HL_WIDTH)]
            if avail - fixed_of(with_hl) < REQUEST_MIN_WIDTH:
                with_hl = [c for c in with_hl if c[0] != "size"]
            if avail - fixed_of(with_hl) >= REQUEST_MIN_WIDTH:
                cols = with_hl
        req = max(12, avail - fixed_of(cols))
        return [(k, label, w or req) for k, label, w in cols]

    def _cells(self, row: FlowRow, layout: list[tuple[str, str, int]]) -> list[Text]:
        widths = {k: w for k, _, w in layout}
        req_w, who_w = widths["req"], widths["who"]
        t = Text(
            time.strftime("%H:%M:%S", time.localtime(row.ts)), style=lens_palette().dim
        )
        label, known = row.recipient
        who = Text(_ellipsize(label, who_w), style=lens_palette().text)
        app = Text(
            app_label(row.app, widths.get("app", 0)),
            style=lens_palette().muted,
            no_wrap=True,
            overflow="crop",
        )
        tls = tls_word(row)
        tls_cell = Text(
            tls,
            style={
                "TLS failed": f"bold {lens_palette().bad}",
                "plain": lens_palette().warn,
            }.get(tls, lens_palette().muted),
        )
        tag = _phase_tag(row.phase) if self.in_review else ""
        if row.kind == "tls":
            req = Text(no_wrap=True, overflow="ellipsis")
            if tag:  # a dry-run / setup TLS failure is marked like its flows
                req.append(f"{tag} ", style=lens_palette().warn)
            req.append("TLS ", style=lens_palette().muted)
            host_w = req_w - 4 - (len(tag) + 1 if tag else 0)
            req.append(_ellipsize(row.host, host_w), style=lens_palette().text)
            status = Text("TLS failed", style=f"bold {lens_palette().bad}")
            size = Text("")
        else:
            if tag:
                req = Text(no_wrap=True, overflow="ellipsis")
                req.append(f"{tag} ", style=lens_palette().warn)
                req.append_text(
                    smart_request(row.method, row.host, row.path, req_w - len(tag) - 1)
                )
            else:
                req = smart_request(row.method, row.host, row.path, req_w)
            if row.error:
                status = Text(error_status(row.error), style=lens_palette().bad)
            elif row.status is None:
                status = Text("")  # no response (yet): nothing, not a glyph
            else:
                code = int(row.status)
                color = lens_palette().muted
                if 400 <= code < 500:
                    color = lens_palette().warn
                elif code >= 500:
                    color = lens_palette().bad
                status = Text(str(code), style=color)
            size = Text(
                size_words(row),
                style=lens_palette().text if row.req_bytes else lens_palette().dim,
            )
        size.justify = "right"
        cells = {
            "time": t,
            "app": app,
            "who": who,
            "req": req,
            "tls": tls_cell,
            "status": status,
            "size": size,
        }
        cells["ident"] = self._privacy_cell(row, widths.get("ident", 0))
        if "hl" in widths:
            cells["hl"] = self._hl.cell(row.flow_id)
        return [cells[k] for k, _, _ in layout]

    def _columns(self, table: DataTable) -> list[tuple[str, str, int]]:
        layout = self._layout()
        table.clear(columns=True)
        for key, label, width in layout:
            table.add_column(label, key=key, width=width)
        self._width = self.size.width
        self._net_layout = layout
        return layout

    def _at_tail(self, table: DataTable) -> bool:
        """True when the cursor sits on the last row (or there is none)."""
        return table.row_count == 0 or table.cursor_row >= table.row_count - 1

    @property
    def following(self) -> bool:
        """The table sticks to the newest flow (``live``)."""
        return self._follow.live

    def set_following(self, live: bool) -> None:
        """Stop following (a move up) or resume it (End: the newest row)."""
        if live:
            changed = self._follow.resume()
            try:
                table = self.table
                if table.row_count:
                    table.move_cursor(row=table.row_count - 1, animate=False)
                    table.scroll_end(animate=False)
            except Exception:
                pass
        else:
            changed = self._follow.stop()
        if changed:
            self._do_refresh_status()

    def _check_follow(self, table: DataTable) -> None:
        """The cursor left the newest row some other way: stop following."""
        if self._follow.live and table.row_count and not self._at_tail(table):
            self._follow.stop()

    def _rebuild(self, *, to_top: bool = False) -> None:
        """Re-render the table from the current model + filters.

        Keeps the cursor on the same flow when the user had moved it off the
        last row; otherwise lands on the newest row (tail-follow).
        """
        try:
            table = self.table
        except Exception:
            return
        self._focus_app = self._spotlight_package()
        keep = None
        if not to_top:
            self._check_follow(table)
        if table.row_count and not self._follow.live:
            keep = self._cursor_key()
        layout = self._columns(table)
        rows = [r for r in self._model() if self._passes(r)]
        self._noise_hidden = self._count_noise(self._model())
        self._phase_hidden = self._count_phase_hidden()
        for row in rows:
            table.add_row(*self._cells(row, layout), key=row.key)
        self._shown = len(rows)
        self._update_highlight_bar()
        target = None
        if keep is not None and not to_top:
            try:
                target = table.get_row_index(keep)
            except Exception:
                target = None
        if rows:
            if to_top:
                table.move_cursor(row=0, animate=False)
                table.scroll_home(animate=False)
            elif target is not None:
                table.move_cursor(row=target, animate=False)
            else:
                # Back at the newest row (the kept flow is gone): live again.
                if not self.in_review:
                    self._follow.resume()
                table.move_cursor(row=len(rows) - 1, animate=False)
                table.scroll_end(animate=False)
        self._update_empty()

    def _append_rows(self, rows: list[FlowRow]) -> None:
        """Append new live rows; follow them only from the tail.

        A user who moved the cursor up, or has a flow open in the Inspector,
        is never yanked to the newest row.
        """
        try:
            table = self.table
        except Exception:
            return
        if self.size.width != self._width or not self._net_layout:
            passing = sum(1 for row in rows if self._passes(row))
            self._rebuild()
            self._follow.added(passing)
            return
        # While live an open flow Inspector follows the newest flow too (End
        # is the user's choice; ↑ / a click above stops it).
        self._check_follow(table)
        added = 0
        self._noise_hidden += self._count_noise(rows)
        for row in rows:
            if self._passes(row):
                table.add_row(*self._cells(row, self._net_layout), key=row.key)
                self._shown += 1
                added += 1
        if added and self._follow.live:
            table.move_cursor(row=table.row_count - 1, animate=False)
            table.scroll_end(animate=False)
        else:
            self._follow.added(added)
        self._update_highlight_bar()
        self._update_empty()

    def _cursor_key(self) -> str | None:
        try:
            table = self.table
            if not table.row_count:
                return None
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            return row_key.value
        except Exception:
            return None

    def _row_by_key(self, key: str | None) -> FlowRow | None:
        if key is None:
            return None
        for row in reversed(self._model()):
            if row.key == key:
                return row
        return None

    def on_resize(self, event) -> None:
        if self.size.width != self._width:
            self._rebuild()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """↑/↓ while a flow is open in the Inspector: show that row instead."""
        if not self._inspecting_flow():
            return
        ms = self._main_screen()
        key = event.row_key.value if event.row_key is not None else None
        current = ms.inspector_content if ms is not None else None
        if key is None or current is None or current.key == f"network:row:{key}":
            return
        row = self._row_by_key(key)
        if row is not None:
            ms.update_inspector(self.flow_content(row))

    # -- empty state -------------------------------------------------------

    def _update_empty(self) -> None:
        try:
            table = self.table
            box = self.query_one("#net-empty")
            head = self.query_one("#net-empty-head", Static)
            hint = self.query_one("#net-empty-hint", Static)
        except Exception:
            return
        model_empty = not self._model()
        filtered_empty = not model_empty and self._shown == 0
        was_hidden = table.has_class("-empty")
        table.set_class(model_empty, "-empty")
        table.set_class(filtered_empty, "-filtered-empty")
        box.set_class(model_empty or filtered_empty, "-shown")
        if model_empty or filtered_empty:
            title, sub = self._empty_text(filtered_empty)
            head.update(Text.from_markup(title))
            hint.update(Text.from_markup(sub) if sub else "")
            hint.display = bool(sub)
        focused = self.screen.focused if self.is_attached else None
        if model_empty and focused is table:
            super().focus()
        elif was_hidden and not model_empty and focused is self:
            table.focus()
        if model_empty != was_hidden:
            try:
                self.screen.refresh_bindings()
            except Exception:
                pass

    def _empty_text(self, filtered: bool) -> tuple[str, str]:
        if filtered:
            widen = []
            if self._filter:
                widen.append("/ edits the filter")
            if self._app_only:
                widen.append("T shows all apps")
            if not self._show_noise:
                widen.append("N shows OS noise")
            if self._profile_only:
                widen.append("! shows flows without profile values")
            head = "Nothing matches"
            if self._app_only and self._focus_app:
                head = f"No flows attributed to {escape(self._focus_app)}"
                widen.append(
                    "apps are named through an App Proxy or the device proxy (y)"
                )
            ai = self._hl.empty_text(escape(self._filter))
            if ai is not None:
                head = ai[0]
                widen.insert(0, ai[1])
            return head, " · ".join(widen)
        if self.in_review:
            label = escape(self._scope_label or "this run")
            if self._review_loading:
                return f"Loading the flows of {label}…", ""
            if self._review_window is not None:
                return self._review_empty_text(label)
            return f"No flow data for {label}", self._review_note
        mitm = self.mitm
        if mitm is None:
            return "No flows yet", ""
        return mitm.empty_hint()

    def _review_empty_text(self, label: str) -> tuple[str, str]:
        """Why a reviewed run shows no flows, and where its network data is."""
        data = self._review_data
        meta = (data.meta if data is not None else None) or {}
        pcaps = (data.pcaps if data is not None else None) or []
        hints: list[str] = []
        if pcaps:
            rel, size = max(pcaps, key=lambda p: p[1])
            more = f" (+{len(pcaps) - 1} more)" if len(pcaps) > 1 else ""
            hints.append(
                f"its packet capture: {escape(rel)} · {human_size(size)}{more} "
                "(Sessions ⏎ → Report shows the folder; open it in Wireshark)"
            )
        hints.append("L back to LIVE")
        if self._phase_hidden and not self._show_all_phases:
            n = sum(self._phase_hidden.values())
            return (
                f"No flows during the replays of {label}",
                f"A shows {n} dry-run / setup flow"
                + ("s" if n != 1 else "")
                + " · "
                + " · ".join(hints),
            )
        if data is not None and data.source == "bundle":
            if meta.get("mitm_running") is False:
                head = f"mitmproxy was not running during {label}"
            else:
                head = f"No flows were captured during {label}"
        else:
            a, b = self._review_window or (0.0, 0.0)
            span = (
                time.strftime("%H:%M:%S", time.localtime(a))
                + "–"
                + time.strftime("%H:%M:%S", time.localtime(b))
            )
            head = f"No flows were captured during {label}"
            hints.insert(
                0,
                f"this run predates flows stored in its bundle; this session's "
                f"flow log has none between {span}",
            )
        return head, " · ".join(hints)

    # -- status / caption ----------------------------------------------------

    def refresh_status(self) -> None:
        """Controllers changed state: refresh caption, empty state, Inspector."""
        if self._status_pending:
            return
        self._status_pending = True
        if not in_app_context():
            # Reached from a bare loop callback (no Textual app context): a
            # timer started here would die with LookupError(active_app) and
            # leave the caption stuck. call_later needs no context.
            if not self.call_later(self._do_refresh_status):
                self._status_pending = False
            return
        try:
            self.set_timer(0.1, self._do_refresh_status)
        except Exception:
            self._do_refresh_status()

    def refresh_header(self) -> None:  # MainScreen lens-activation hook
        self._do_refresh_status()

    def _caption_title(self) -> str:
        if self.in_review:
            label = escape(self._scope_label or "run")
            note = self._review_note_short()
            warn = lens_palette().warn
            return f"[{warn}]review {label}[/]" + (f" · {note}" if note else "")
        mitm = self.mitm
        title = mitm.status_caption() if mitm is not None else ""
        fritap = self.fritap
        token = fritap.caption_token() if fritap is not None else ""
        if token:
            title += f" · {token}"
        if self._live:
            # Follow state: in ONE place, the title (as in every lens).
            title = f"{self._follow.text} · {title}"
        return title

    def _review_note_short(self) -> str:
        if self._review_window is None:
            return ""
        data = self._review_data
        if data is not None and data.source == "bundle":
            if not data.phases_known:
                return "flows stored with the run"
            return "all phases" if self._show_all_phases else "flows of the replays"
        return "flows in the run's time window (session log)"

    def _caption_info(self) -> str:
        total = len(self._model())
        if not total:
            return ""
        parts = []
        # M of the AI filter: the rows shown without it (the footer's base).
        ai = self._hl.caption_count(self._shown, self._hl.view_total)
        if ai is not None:
            parts.append(escape(ai))
        elif self._shown != total:
            parts.append(f"{self._shown} of {total}")
        else:
            parts.append(f"{total} flow" + ("s" if total != 1 else ""))
        if self._app_only and self._focus_app:
            parts.append("app only")
        if self._show_noise:
            parts.append("+ OS noise")
        elif self._noise_hidden:
            parts.append(f"N: {self._noise_hidden} OS noise hidden")
        if self.in_review and self._phase_hidden:
            hidden = " · ".join(
                f"{n} {phase}" for phase, n in sorted(self._phase_hidden.items())
            )
            parts.append(f"A: {hidden} hidden")
        elif self.in_review and self._show_all_phases:
            parts.append("+ dry run/setup")
        parts += self._privacy_caption_parts()
        if self._filter:
            parts.append(f"“{escape(self._filter)}”")
        if self._shown:
            parts.append("Enter inspects")
        return " · ".join(parts)

    def _do_refresh_status(self) -> None:
        self._status_pending = False
        self._update_method_line()
        ms = self._main_screen()
        if ms is not None:
            try:
                ms.set_lens_caption(
                    LENS_ID, title=self._caption_title(), info=self._caption_info()
                )
            except Exception:
                logger.debug("network caption failed", exc_info=True)
        if not self._model():
            self._update_empty()
        if ms is not None:
            content = ms.inspector_content
            if (
                ms.inspector_is_open
                and content is not None
                and content.key == STATUS_KEY
            ):
                ms.update_inspector(self.status_content())

    # -- lens hooks ------------------------------------------------------

    def on_lens_activated(self) -> None:
        self._kick_method_refresh(with_ca=True)
        self._unseen_tls = 0
        ms = self._main_screen()
        if ms is not None:
            ms.set_lens_badge(LENS_ID, None)
        pkg = self._spotlight_package()
        if pkg != self._focus_app:
            self._rebuild()
        self.poll_now()
        self._do_refresh_status()

    def on_scope_changed(self, message) -> None:
        run_id = getattr(message, "run_id", None)
        self._scope = run_id
        given = getattr(message, "label", None)
        self._scope_label_given = bool(given)
        self._scope_label = given or (f"Run {Path(run_id).name}" if run_id else None)
        self._review = []
        self._review_window = None
        self._review_note = ""
        self._review_data = None
        self._show_all_phases = False
        if run_id is None:
            self._review_loading = False
            self._follow.resume()
            self._rebuild()
            self._do_refresh_status()
            return
        self._review_loading = True
        self._rebuild()
        self._do_refresh_status()
        try:
            self.run_worker(
                lambda: self._review_job(run_id),
                thread=True,
                group="network-review",
                exit_on_error=False,
            )
        except Exception:
            self._apply_review(run_id, self.load_run_flows(run_id))

    def _review_job(self, run_id: str) -> None:
        try:
            result = self.load_run_flows(run_id)
        except Exception:
            logger.debug("network review load failed", exc_info=True)
            result = ReviewData([], "", None, None)
        try:
            self.app.call_from_thread(self._apply_review, run_id, result)
        except Exception:
            pass

    def load_run_flows(self, run_id: str) -> ReviewData:
        """The flows of a reviewed run (any thread).

        The run bundle's own copy (``<run>/network/``, phase-tagged) wins;
        older runs fall back to the session's ``flows.jsonl`` filtered by the
        run's time window (Play press -> end of analysis, from
        ``run_history.resolve_scope``), tagged with the run's phases when it
        has them. The run's pcap files are listed for the empty state.
        """
        from sandroid.core import run_history
        from sandroid.services.mitmproxy_flow_log import (
            HARD_LIMIT_CAP,
            query_flows,
            read_run_flows,
        )

        run = run_history.resolve_scope(run_id)
        if run is None:
            return ReviewData([], "this run's record could not be read", None, None)
        label = run.label
        start = run.started_at.timestamp() if run.started_at else None
        end = run.ended_at.timestamp() if run.ended_at else start
        pcaps = run_pcaps(run.run_dir)
        phases = list(run.phases)
        net_dir = run.run_dir / run_history.NETWORK_DIR_NAME
        stored = read_run_flows(net_dir)
        if stored is not None:
            records, meta = stored
            rows = [FlowRow.from_record(r, net_dir) for r in records]
            window = meta.get("window")
            if not (isinstance(window, list) and len(window) == 2):
                window = [start or 0.0, end or start or 0.0]
            return ReviewData(
                rows,
                "bundle",
                (float(window[0]), float(window[1])),
                label,
                meta=meta,
                pcaps=pcaps,
                run_dir=run.run_dir,
                phases_known=bool(phases),
            )
        if start is None or end is None:
            return ReviewData(
                [], "no start/end time recorded for this run", None, label, pcaps=pcaps
            )
        end = max(start, end)
        start -= 2.0
        end += 2.0
        flow_dir = _flow_dir()
        rows: list[FlowRow] = []
        if (flow_dir / "flows.jsonl").is_file():
            res = query_flows(
                flow_dir,
                start_time=datetime.fromtimestamp(start).isoformat(),
                end_time=datetime.fromtimestamp(end).isoformat(),
                limit=HARD_LIMIT_CAP,
            )
            rows = [FlowRow.from_record(r, flow_dir) for r in res["flows"]]
        for row in rows:
            row.phase = run_history.phase_of(row.ts_start or row.ts, phases)
        return ReviewData(
            rows,
            "window",
            (start, end),
            label,
            pcaps=pcaps,
            run_dir=run.run_dir,
            phases_known=bool(phases),
        )

    def _apply_review(self, run_id: str, result: ReviewData) -> None:
        if run_id != self._scope:
            return  # the scope moved on while loading
        rows, source, window, label = (
            result.rows,
            result.source,
            result.window,
            result.label,
        )
        if window is not None and source == "window":
            a, b = window
            # stdout-only TLS rows (not in the flow log: older mitmweb addon)
            rows = rows + [
                r
                for r in self._live
                if r.kind == "tls" and r.seq is None and a <= r.ts <= b
            ]
            rows.sort(key=lambda r: r.ts)
        if label and not self._scope_label_given:
            self._scope_label = label
        self._review = rows[-self.MAX_ROWS :]
        self._review_note = source
        self._review_window = window
        self._review_data = result
        self._review_loading = False
        self._rebuild(to_top=True)
        self._do_refresh_status()

    # -- inspector -------------------------------------------------------

    def _inspecting_flow(self) -> bool:
        ms = self._main_screen()
        if ms is None or not ms.inspector_is_open:
            return False
        content = ms.inspector_content
        return bool(
            content is not None
            and content.lens == LENS_ID
            and isinstance(content.key, str)
            and content.key.startswith("network:row:")
        )

    def inspect_selected(self) -> InspectorContent | None:
        """Enter on a row: Summary / Request / Response of that flow."""
        if not self._shown:
            return None
        row = self._row_by_key(self._cursor_key())
        if row is None:
            return None
        return self.flow_content(row)

    def reveal_flow(self, flow_id: str, record: dict | None = None) -> bool:
        """Show the flow ``flow_id`` (the Timeline lens's ``J`` on a net line).

        The listed row (``f{seq}``) gets the cursor and the Inspector; a flow
        that is not listed (filtered, cleared, an older session page) opens
        from ``record`` -- the flow-log record shape, built from the timeline
        line -- with ``FlowRow.from_record``. False when neither is there.
        """
        row = self._listed_flow(flow_id)
        if row is not None:
            self._show_flow(row)
            return True
        if not self.in_review:
            # Not loaded yet: a hidden lens polls only while it is shown.
            # Poll now and put the cursor on the flow once it is listed; the
            # record (if any) opens it in the meantime.
            # False when nothing could be opened yet, so the caller can fall
            # back (the cursor still lands on the flow once it is listed).
            self._pending_reveal = (flow_id, record)
            self.poll_now()
            row = self._listed_flow(flow_id)
            if row is not None:
                self._pending_reveal = None
                self._show_flow(row)
                return True
            row = self._record_row(flow_id, record)
            if row is None:
                return False
            self._show_flow(row, cursor=False)
            return True
        row = self._record_row(flow_id, record)
        if row is None:
            return False
        self._show_flow(row, cursor=False)
        return True

    def _listed_flow(self, flow_id: str) -> FlowRow | None:
        return next((r for r in reversed(self._model()) if r.flow_id == flow_id), None)

    @staticmethod
    def _record_row(flow_id: str, record: dict | None) -> FlowRow | None:
        if record is None or record.get("id") != flow_id:
            return None
        try:
            return FlowRow.from_record(
                {k: v for k, v in record.items() if v is not None}, _flow_dir()
            )
        except Exception:
            logger.debug("reveal_flow: bad record", exc_info=True)
            return None

    def _show_flow(self, row: FlowRow, *, cursor: bool = True) -> None:
        if cursor:
            try:
                table = self.table
                index = table.get_row_index(row.key)
                if index < table.row_count - 1:
                    self._follow.stop()
                table.move_cursor(row=index, animate=False)
            except Exception:
                pass
        ms = self._main_screen()
        if ms is not None:
            ms.open_inspector(self.flow_content(row))

    def _resolve_pending_reveal(self) -> None:
        """The poll after a ``J`` landed: show the flow, or say it is gone."""
        flow_id, record = self._pending_reveal or ("", None)
        self._pending_reveal = None
        row = self._listed_flow(flow_id)
        if row is not None:
            self._show_flow(row)
        elif record is None:
            with contextlib.suppress(Exception):
                self.app.notify("That flow is not in the flow log.", timeout=3)

    def flow_content(self, row: FlowRow) -> InspectorContent:
        key = f"network:row:{row.key}"
        label, _known = row.recipient
        when = time.strftime("%H:%M:%S", time.localtime(row.ts))
        if row.kind == "tls":
            grid = _grid()
            grid.add_row("recipient", Text(label))
            grid.add_row("host", Text(row.host))
            grid.add_row("time", when)
            if row.app:
                grid.add_row("app", Text(row.app))
            grid.add_row(
                "result",
                Text(f"TLS failed ({row.reason})", style=lens_palette().bad),
            )
            why = _TLS_REASONS.get(row.reason, _TLS_REASONS["tls"])
            return InspectorContent(
                title=f"TLS failed · {label}",
                subtitle=escape(row.host),
                sections=[
                    ("", grid),
                    *(self._hl.sections(row.flow_id) if row.flow_id else []),
                    ("Why", why),
                    (
                        "Next",
                        "[b]^P[/b] unpins the spotlight app (exp.) · "
                        "[b]^N[/b] installs the CA",
                    ),
                ],
                key=key,
                lens=LENS_ID,
            )
        detail = None
        if row.flow_dir is not None and row.flow_id:
            try:
                from sandroid.services.mitmproxy_flow_log import read_flow_detail

                detail = read_flow_detail(row.flow_dir, row.flow_id)
            except Exception:
                detail = None
        grid = _grid()
        grid.add_row("recipient", Text(label))
        if row.app:
            grid.add_row("app", Text(row.app))
        grid.add_row("time", when)
        if row.phase and self.in_review:
            grid.add_row(
                "phase",
                Text(
                    row.phase,
                    style=lens_palette().warn if row.phase in HIDDEN_PHASES else "",
                ),
            )
        if row.error:
            grid.add_row(
                "result", Text(f"error: {row.error}", style=lens_palette().bad)
            )
        elif row.status is not None:
            grid.add_row(
                "status",
                f"{row.status}"
                + (f" · {protocol_label(row.protocol)}" if row.protocol else ""),
            )
        if row.ts_start:
            ms_taken = max(0.0, (row.ts - float(row.ts_start)) * 1000)
            grid.add_row("duration", f"{ms_taken:.0f} ms")
        grid.add_row(
            "sent",
            f"{human_size(row.req_bytes)}"
            + (f" · {row.req_type}" if row.req_type else ""),
        )
        grid.add_row(
            "received",
            f"{human_size(row.resp_bytes)}"
            + (f" · {row.resp_type}" if row.resp_type else ""),
        )
        summary = [("", grid), ("URL", Text(row.url(), style=lens_palette().text))]
        summary += self._hl.sections(row.flow_id)
        if detail is None:
            missing = Text(
                "details not stored (trimmed by retention or never captured)",
                style=lens_palette().dim,
            )
            request = [("", missing)]
            response = [("", missing)]
        else:
            request = [
                ("Headers", _headers_renderable(detail.get("request_headers"))),
                ("Body", body_renderable(detail.get("request_body"), row.req_type)),
            ]
            response = [
                ("Headers", _headers_renderable(detail.get("response_headers"))),
                ("Body", body_renderable(detail.get("response_body"), row.resp_type)),
            ]
            if detail.get("error"):
                response.insert(
                    0, ("Error", Text(str(detail["error"]), style=lens_palette().bad))
                )
        tabs = [("Summary", summary), ("Request", request), ("Response", response)]
        tabs += self._identity_tabs(row)
        return InspectorContent(
            title=f"{row.method} {label}",
            subtitle=escape(_ellipsize(row.host + row.path, 300)),
            tabs=tabs,
            footer="←/→ tab",
            key=key,
            lens=LENS_ID,
        )

    def status_content(self) -> InspectorContent:
        """The "Capture status" page: mitmproxy and friTap tabs."""
        mitm, fritap = self.mitm, self.fritap
        m_grid = _grid()
        for label, value in mitm.status_rows() if mitm is not None else []:
            m_grid.add_row(label, Text.from_markup(value))
        m_keys = (
            "[b]M[/b] start/stop  [b]^D[/b] device proxy  [b]^N[/b] install CA\n"
            "[b]^P[/b] SSL unpin  [b]^R[/b] restart  [b]^A[/b] addons\n"
            "[b]^O[/b] mitmweb UI  [b]^V[/b] verbose  [b]y[/b] proxy settings"
        )
        m_recent = list(mitm.recent_lines)[-8:] if mitm is not None else []
        m_sections: list[tuple[str, Any]] = [("", m_grid), ("Keys", m_keys)]
        if m_recent:
            m_sections.append(
                ("Recent", Text("\n".join(m_recent), style=lens_palette().muted))
            )
        f_grid = _grid()
        for label, value in fritap.status_rows() if fritap is not None else []:
            f_grid.add_row(label, Text.from_markup(value))
        f_recent = list(fritap.recent_lines)[-12:] if fritap is not None else []
        f_sections: list[tuple[str, Any]] = [
            ("", f_grid),
            ("Keys", "[b]h[/b] start/stop friTap  [b]^F[/b] output folder"),
        ]
        if f_recent:
            f_sections.append(
                ("Recent", Text("\n".join(f_recent), style=lens_palette().muted))
            )
        return InspectorContent(
            title="Capture status",
            tabs=[("mitmproxy", m_sections), ("friTap", f_sections)],
            footer="←/→ tab",
            key=STATUS_KEY,
            lens=LENS_ID,
        )

    def open_status(self, tab: int = 0) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        ms.open_inspector(self.status_content())
        try:
            from sandroid.tui.widgets.lens_shell import Inspector

            ms.query_one("#inspector", Inspector).select_tab(tab)
        except Exception:
            pass

    def select_subtab(self, panel_id: str) -> None:
        """Legacy hook (``MainScreen.open_fritap_tab``, key ``h``)."""
        self.open_status(1 if panel_id == "fritap-panel" else 0)

    # -- identity profile values (privacy scan) ----------------------------
    #
    # Flows carrying values of the active identity profile get a faint warn
    # tint (FlowTable, through the shared row annotations), an Identity
    # column (from PRIVACY_COLUMN_MIN_WIDTH, while identity mode is on, the
    # scan has markers or hits are loaded; the poll tick adds it when that
    # changes later) and an Identity Inspector tab. ``!`` only filters rows.
    # Hits found later (the scan worker) redraw rows already drawn through
    # an AnnotationFeed (UI redraw at most once a second).

    def on_unmount(self) -> None:
        self._privacy_feed.detach()
        self._hl.detach()
        self._method_detach()

    # -- Network method line (services.network_method) -----------------------

    def _method_attach(self) -> None:
        """Follow ``network_method`` events; show the last derived method."""
        from sandroid.core.events import EventBus, EventType

        self._method_ui = UiDispatcher.capture()
        self._method_bus = EventBus.get()
        self._method_bus.subscribe(EventType.STATE_CHANGED, self._on_method_event)
        self._update_method_line()
        self._kick_method_refresh(with_ca=False)

    def _method_detach(self) -> None:
        from sandroid.core.events import EventType

        bus = getattr(self, "_method_bus", None)
        self._method_bus = None
        if bus is not None:
            try:
                bus.unsubscribe(EventType.STATE_CHANGED, self._on_method_event)
            except Exception:
                pass

    def _on_method_event(self, event) -> None:
        """Any thread: repaint the line on the UI thread (never blocks)."""
        data = getattr(event, "data", None) or {}
        if data.get("change_type") != "network_method":
            return
        ui = getattr(self, "_method_ui", None)
        if ui is not None:
            ui.post(self._update_method_line)

    @staticmethod
    def _kick_method_refresh(*, with_ca: bool) -> None:
        try:
            from sandroid.services.network_method import get_network_method_service

            get_network_method_service().refresh(with_ca=with_ca)
        except Exception:
            logger.debug("network method refresh not started", exc_info=True)

    def method_line(self) -> str:
        """The status line markup (cached view; UI thread)."""
        from sandroid.services.network_method import get_network_method_service

        pal = lens_palette()
        view = get_network_method_service().view_cached()
        return (
            view.markup(pal.ok, pal.warn, pal.bad, pal.dim)
            + f" [{pal.dim}]W changes it[/]"
        )

    def _update_method_line(self) -> None:
        if not self.is_attached:
            return
        try:
            line = self.query_one("#net-method", Static)
        except Exception:
            return
        line.set_class(self.in_review, "-hidden")
        try:
            line.update(Text.from_markup(self.method_line()))
        except Exception:
            logger.debug("network method line failed", exc_info=True)

    def action_network_method(self) -> None:
        """``W``: pick the Network method (Off / Whole device / This app ...)."""
        from sandroid.tui.modals.proxy_modal import NetworkMethodModal

        self.app.push_screen(NetworkMethodModal())

    def _privacy_wanted(self) -> bool:
        """Identity mode is on, the scan has markers or hits are loaded (the
        Identity column has a use). Independent of the ``!`` row filter.
        """
        service = privacy_service()
        if service is None:
            return False
        try:
            if service.is_active or privacy_has_hits(service):
                return True
        except Exception:
            return False
        return identity_mode_on()

    def _sync_privacy_column(self) -> None:
        """Add or drop the Identity column when its use changed (markers
        found after the first draw, identity mode switched, a session with
        stored hits loaded); rows already drawn keep their cursor.
        """
        keys = [k for k, _, _ in self._net_layout]
        if not keys:
            return
        wants = bool(self._privacy_columns(self.size.width or 120))
        if wants != ("ident" in keys):
            self._rebuild()
            self._do_refresh_status()

    def _flow_tags(self, row: FlowRow) -> list:
        """The row's profile tags (the provider caches them per revision)."""
        flow_id = row.flow_id
        if not flow_id:
            return []
        provider = privacy_annotations()
        if provider is not None:
            return provider.flow_tags(flow_id)
        return _privacy_tags_for_flow(flow_id)

    def annotation_flow_id(self, key: Any) -> str | None:
        """The annotation key (flow id) of table row ``key``.

        Flows: the mitmproxy flow id. TLS failures: ``tls_row_key`` of the
        flow-log record id; a stdout-only TLS row (``t<n>``, not in the flow log
        yet) has none until the poll pairs it with its record.
        """
        if key is None:
            return None
        model = self._model()
        owner, size, index = self._flow_index
        if owner is not model or size != len(model):
            index = {r.key: r for r in model}
            self._flow_index = (model, len(model), index)
        row = index.get(str(key))
        if row is None:
            return None
        return row.flow_id

    def _privacy_columns(self, avail: int) -> list[tuple[str, str, int]]:
        if avail < PRIVACY_COLUMN_MIN_WIDTH or not self._privacy_wanted():
            return []
        return [("ident", "Identity", 18 if avail >= 130 else 14)]

    def _privacy_cell(self, row: FlowRow, width: int) -> Text:
        """The Identity cell (the row tint comes from the row annotations)."""
        tags = self._flow_tags(row) if row.kind == "flow" else []
        return tag_words(tags, width or None)

    def _profile_rows(self) -> int:
        """Drawn flows that carry profile values (the caption count)."""
        provider = privacy_annotations()
        if provider is None:
            return 0
        try:
            keys = [k.value for k in self.table.rows]
        except Exception:
            return 0
        return sum(
            1 for key in keys if provider.flow_tags(self.annotation_flow_id(key) or "")
        )

    def _privacy_caption_parts(self) -> list[str]:
        parts = []
        if self._profile_only:
            parts.append("!: profile values only")
        elif n := self._profile_rows():
            parts.append(f"{n} carry profile values")
        return parts

    def _identity_tabs(self, row: FlowRow) -> list:
        """``[("Identity", sections)]`` when the flow carries profile values."""
        if row.kind != "flow" or not row.flow_id:
            return []
        service = privacy_service()
        try:
            hits = list(service.hits_for_flow(row.flow_id)) if service else []
        except Exception:
            hits = []
        if not hits:
            return []
        values = len({h.marker_id for h in hits})
        heading = f"{values} profile value{'s' if values != 1 else ''} in this flow"
        return [("Identity", [(heading, hits_renderable(hits))])]

    def _privacy_flush(self, pending: set[str] | None) -> None:
        """Redraw the rows (and the open Inspector) of flows whose row
        annotations changed (``pending``: flow ids; None: every flow).
        """
        try:
            table = self.table
        except Exception:
            return
        keys = [k for k, _, _ in self._net_layout]
        has_col = "ident" in keys
        wants_col = bool(self._privacy_columns(self.size.width or 120))
        everything = pending is None
        pending = pending or set()
        if everything or self._profile_only or has_col != wants_col or not keys:
            self._rebuild()
        else:
            column = "ident" if has_col else "req"
            for row in self._model():
                if row.flow_id not in pending:
                    continue
                try:
                    table.get_row_index(row.key)
                except Exception:
                    continue
                cells = dict(
                    zip(keys, self._cells(row, self._net_layout), strict=False)
                )
                table.update_cell(row.key, column, cells[column])
        if self._inspecting_flow():
            ms = self._main_screen()
            key = str(ms.inspector_content.key).removeprefix("network:row:")
            row = self._row_by_key(key)
            if row is not None and (everything or row.flow_id in pending):
                ms.update_inspector(self.flow_content(row))
        self._do_refresh_status()

    def action_toggle_profile_only(self) -> None:
        """``!``: show only the flows that carry identity-profile values."""
        self._profile_only = not self._profile_only
        self._rebuild()
        self._do_refresh_status()

    # -- AI highlights (highlight_bar) ----------------------------------

    def _update_highlight_bar(self) -> None:
        """Count the view per highlight set and redraw the bar."""
        try:
            bar = self.query_one("#net-highlights", HighlightBar)
        except Exception:
            return
        if self._hl.active:
            live = not self.in_review
            self._hl.measure(
                (
                    (r.flow_id, self._passes(r, ai=False), r.seq, r.ts)
                    for r in self._model()
                ),
                live=live,
            )
        bar.show_text(self._hl.bar_text(self.size.width or 160))

    def _redraw_highlights(self, _keys: set[str] | None = None) -> None:
        """Highlights changed (AnnotationFeed, H, X): redraw, keep the cursor."""
        self._rebuild()
        self._do_refresh_status()
        try:
            self.screen.refresh_bindings()
        except Exception:
            pass
        ms = self._main_screen()
        if ms is not None and self._inspecting_flow():
            row = self._row_by_key(ms.inspector_content.key[len("network:row:") :])
            if row is not None:
                ms.update_inspector(self.flow_content(row))

    def _highlight_rows_snapshot(self) -> list[dict] | None:
        """Every row of this view (live or the reviewed run) for the AI tools.

        ``shown`` = passes the lens's own filters (noise, app only, ``/``,
        phases), NOT the AI filter: the tools and the bar's "hidden by lens
        filters" agree, and a new query or an extend of the filter set sees
        every row the lens filters let through. TLS failures carry their
        ``tls_row_key``. Rows without one (a stdout-only TLS failure the poll
        has not paired yet) come with key None and ``flow_dir`` = the polled
        flow dir: the tools pair them with the flow log themselves.

        None while the live lens never polled (it was never shown): the
        tools then read the flow log instead of an empty view. Live, the
        result says how far the lens has read the flow log
        (``polled_through``, its cursor): a hidden lens does not poll, so
        the tools add the newer records themselves.
        """
        if not self.in_review and self._live_dir is None:
            return None
        live_dir = str(self._live_dir) if self._live_dir is not None else None
        out = RowSnapshot(
            polled_through=None if self.in_review else int(self._cursor or 0),
            flow_dir=None if self.in_review else live_dir,
        )
        for r in self._model():
            snap = flow_snapshot(r, self._passes(r, ai=False), self._scope)
            if r.flow_id is None and snap["flow_dir"] is None:
                snap["flow_dir"] = live_dir
            out.append(snap)
        return out

    def _leave_highlight_filter(self) -> bool:
        if not self._hl.leave_filter():
            return False
        self._redraw_highlights()
        try:
            self.app.notify(
                "AI filter off — the rows stay highlighted", timeout=2, markup=False
            )
        except Exception:
            pass
        return True

    def action_cycle_highlight_filter(self) -> None:
        """``H``: AI filter off -> set 1 -> ... -> off."""
        notice = self._hl.cycle_filter()
        self._redraw_highlights()
        if notice:
            # The notice holds the set's label (chat agent text): no markup.
            self.app.notify(notice, timeout=3, markup=False)

    def action_clear_highlights(self) -> None:
        """``X``: remove this lens's highlight sets (asks first)."""
        self._hl.confirm_clear(self.app, self._redraw_highlights)

    # -- actions ---------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "start_mitm":
            # Only while nothing is captured (footer room); M works always.
            return not self.in_review and not self._model()
        if action == "toggle_phases":
            return self.in_review
        if action in ("cycle_highlight_filter", "clear_highlights"):
            return self._hl.active
        if action in ("filter", "toggle_app_only"):
            # Nothing to filter yet: hidden, so the footer shows ^D instead.
            return bool(self._model())
        return True

    def action_start_mitm(self) -> None:
        """Space: start mitmproxy; never stops it (M does)."""
        mitm = self.mitm
        if mitm is not None and mitm.is_running():
            self.app.notify("mitmproxy is already running — M stops it", timeout=3)
            return
        self.action_mitm("toggle_running")

    def action_mitm(self, name: str) -> None:
        mitm = self.mitm
        action = getattr(mitm, f"action_{name}", None) if mitm is not None else None
        if action is not None:
            action()
        self._do_refresh_status()

    def action_status(self) -> None:
        self.open_status(0)

    def action_fritap_output(self) -> None:
        fritap = self.fritap
        if fritap is not None:
            fritap.action_open_output()

    def action_clear_view(self) -> None:
        """Hide everything captured so far (on screen only; disk untouched)."""
        if self.in_review:
            return
        seqs = [r.seq for r in self._live if r.seq is not None]
        if seqs:
            self._floor_seq = max(self._floor_seq, *seqs)
        self._live = []
        self._follow.resume()
        self._rebuild()
        self._do_refresh_status()

    def action_filter(self) -> None:
        try:
            box = self.query_one("#net-filter", Input)
        except Exception:
            return
        box.add_class("-open")
        box.focus()

    def action_toggle_app_only(self) -> None:
        self._focus_app = self._spotlight_package()
        if not self._app_only and not self._focus_app:
            self.app.notify(
                "No spotlight app — c uses the foreground app, ⇧C picks one.",
                timeout=3,
            )
            return
        self._app_only = not self._app_only
        self._rebuild()
        self._do_refresh_status()

    def action_toggle_phases(self) -> None:
        """REVIEW: show / hide the run's dry-run and setup flows."""
        if not self.in_review:
            return
        self._show_all_phases = not self._show_all_phases
        self._rebuild()
        self._do_refresh_status()

    def action_toggle_noise(self) -> None:
        self._show_noise = not self._show_noise
        self._rebuild()
        self._do_refresh_status()

    def set_filter(self, text: str) -> None:
        self._filter = (text or "").strip()
        self._rebuild()
        self._do_refresh_status()

    def handle_escape(self) -> bool:
        """Esc (MainScreen hook): clear an active ``/`` filter, then the AI one.

        Esc in the filter input clears it and returns to the table; with the
        input closed, Esc clears a filter that is still applied; with none,
        it leaves the AI filter (the rows stay highlighted). Returns True
        when Esc was used here.
        """
        try:
            box = self.query_one("#net-filter", Input)
        except Exception:
            return False
        focused = self.screen.focused if self.is_attached else None
        if focused is not box and not self._filter:
            return self._leave_highlight_filter()
        if self._filter_timer is not None:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
            self._filter_timer = None
        had_filter = bool(self._filter or box.value.strip())
        # No Input.Changed: its debounce would re-apply "" 150 ms later,
        # over a filter set meanwhile.
        with self.prevent(Input.Changed):
            box.value = ""
        box.remove_class("-open")
        self.set_filter("")
        self.focus()
        if had_filter:
            try:
                self.app.notify("Filter cleared", timeout=2)
            except Exception:
                pass
        return True

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "net-filter":
            return
        event.stop()
        if self._filter_timer is not None:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
        value = event.value
        try:
            self._filter_timer = self.set_timer(0.15, lambda: self.set_filter(value))
        except Exception:
            self.set_filter(value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "net-filter":
            return
        event.stop()
        self.set_filter(event.value)
        if not event.value.strip():
            event.input.remove_class("-open")
        self.focus()

    def on_descendant_blur(self, event) -> None:
        widget = getattr(event, "widget", None)
        if getattr(widget, "id", None) != "net-filter":
            return
        if not widget.value.strip():
            widget.remove_class("-open")
        # Esc left the input with focus nowhere: return to the table.
        self.call_after_refresh(self._refocus_after_filter)

    def _refocus_after_filter(self) -> None:
        try:
            if self.screen.focused is None and is_shown(self):
                self.focus()
        except Exception:
            pass
