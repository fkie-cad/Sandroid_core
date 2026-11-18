"""Network lens: who is the app talking to, and what did it send?

One full-width flow table (``#net-flows``, five columns: time · recipient ·
request · status · size) fed from the structured flow log the embedded
mitmweb addon writes (``<raw_results>/mitm_flows/flows.jsonl``, read through
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
  at the bottom and only follows them while the cursor sits on the last row
  and no flow is open in the Inspector -- a user who scrolled or selected a
  row is never yanked.
* ``[TLS_FAIL]`` lines become ✗ rows at once; the addon also writes them to
  ``flows.jsonl`` (``kind: "tls"``, no detail file), and the poll pairs that
  record with the stdout row instead of adding it twice. While the lens is
  not in view they count into the lens-bar badge (``⚑N``) until the lens is
  activated again.
  Errored flows come from ``flows.jsonl`` (their ``error`` field) as ✗ rows.

Filters: ``/`` text (host, path, app, recipient, status; Esc clears it),
``T`` (target) spotlight app only, ``N`` show OS noise (connectivity checks,
Play services background traffic, Google ``*-pa`` APIs, Sandroid's own
``mitm.it`` probe; hidden by default, the caption counts what it hides). ``N`` is "show hidden noise" in the Files lens
too, and ``v`` is only the Runs lens's "review". The frame caption carries the
counts ("38 of 412").

Proxy & friTap plumbing: :class:`MitmproxyPanel` and :class:`FriTapPanel` are
mounted hidden inside this lens as controllers; this lens binds their keys
(``Ctrl+D`` device proxy, ``Ctrl+N`` CA, ``Ctrl+P`` unpin, ...) and shows
their state in the caption (``mitm ● :<port> · device ✓ · CA ✓ · friTap ●``,
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
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Input, Static

from sandroid.tui.utils.ui_thread import in_app_context
from sandroid.tui.widgets.fritap_panel import FriTapPanel
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown
from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

if TYPE_CHECKING:
    from rich.console import RenderableType
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

LENS_ID = "network"

#: Inspector key of the "Capture status" page (mitmproxy + friTap tabs).
STATUS_KEY = "network:capture-status"

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
    the App lens's SDK list and these labels); without Insight 2.x the
    built-in ``_RECIPIENTS`` table is used.
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
        return registrable_domain(h) or "?", False
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
    text.append(method, style="#8f9bb3")
    text.append(" ")
    if chosen is None:
        rest = _ellipsize(host + candidates[-1], max(1, width - len(method) - 1))
        hlen = min(len(host), len(rest))
        text.append(rest[:hlen], style="#e5e9f0")
        text.append(rest[hlen:], style="#8f9bb3")
        return text
    text.append(host, style="#e5e9f0")
    text.append(chosen, style="#8f9bb3")
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
    return "error"


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
            # A persisted TLS handshake failure (no HTTP flow behind it).
            return cls(
                key=f"f{seq}" if seq is not None else f"f{rec.get('id')}",
                ts=float(ts_end or 0.0),
                method="TLS",
                host=str(rec.get("host") or "?"),
                path="",
                app=str(rec.get("app") or ""),
                seq=seq,
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
    grid.add_column(style="#8f9bb3", no_wrap=True)
    grid.add_column(overflow="fold")
    return grid


def _headers_renderable(headers: Any) -> RenderableType:
    if not headers:
        return Text("none", style="#5b6479")
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="#8f9bb3", no_wrap=True)
    grid.add_column(overflow="fold")
    for i, pair in enumerate(headers):
        if i >= 60:
            grid.add_row("…", Text(f"{len(headers) - 60} more", style="#5b6479"))
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
    out = Text(style="#8f9bb3")
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
        return Text("empty", style="#5b6479")
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
                style="#facc15",
            )
        )
    elif encoding:
        wire = body.get("encoded_bytes")
        on_wire = f" · {human_size(int(wire))} on the wire" if wire else ""
        parts.append(Text(f"decoded from {encoding}{on_wire}", style="#5b6479"))
    if body.get("encoding") == "base64":
        try:
            raw = base64.b64decode(content)
        except (ValueError, TypeError):
            raw = b""
        label = f"binary · {human_size(size)}" + (f" · {ctype}" if ctype else "")
        parts.append(Text(label, style="#8f9bb3"))
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
        parts.append(Text(note, style="#5b6479"))
    from rich.console import Group

    return Group(*parts)


# --------------------------------------------------------------------------
# the lens
# --------------------------------------------------------------------------


class FlowTable(DataTable):
    """The flow table: Home / End jump to the first / last row.

    DataTable's own Home / End scroll sideways (the cursor is a row cursor
    here, so they did nothing visible; End never reached the newest flow).
    """

    BINDINGS = [
        Binding("home", "scroll_top", "First row", show=False),
        Binding("end", "scroll_bottom", "Last row", show=False),
    ]


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
        Binding("space", "start_stop", "Start/stop mitm", key_display="␣"),
        Binding("slash", "filter", "Filter"),
        Binding("T", "toggle_app_only", "App only"),
        Binding("ctrl+d", "mitm('toggle_device')", "Device proxy"),
        Binding("N", "toggle_noise", "Show OS noise", show=False),
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
    ]

    DEFAULT_CSS = """
    NetworkPanel {
        layout: vertical;
        height: 1fr;
        background: #050811;
    }
    NetworkPanel > #net-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: #0b1628;
        color: #e5e9f0;
    }
    NetworkPanel > #net-filter.-open {
        display: block;
    }
    NetworkPanel > #net-filter:focus {
        border: none;
        background: #11203a;
    }
    NetworkPanel > #net-flows {
        height: 1fr;
        background: #050811;
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
        background: #050811;
        color: #5b6479;
        text-style: none;
    }
    NetworkPanel > #net-flows > .datatable--cursor {
        background: #11203a;
        text-style: none;
    }
    NetworkPanel > #net-flows:focus > .datatable--cursor {
        background: #1d3557;
    }
    NetworkPanel > #net-flows > .datatable--hover {
        background: #0b1628;
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
        color: #cbd5e1;
    }
    NetworkPanel #net-empty-hint {
        width: 100%;
        margin: 1 0 0 0;
        text-align: center;
        color: #5b6479;
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

    # -- compose / mount -------------------------------------------------

    def compose(self) -> ComposeResult:
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
        self._rebuild()
        try:
            self.set_interval(self.POLL_SECONDS, self._tick)
        except Exception:
            pass
        self._do_refresh_status()

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
                self._live = [r for r in self._live if r.kind == "tls"]
                self._floor_seq = 0
            self._live_dir = flow_dir
            self._cursor = cursor
            self._stat = stat
            rows = [
                FlowRow.from_record(r, flow_dir)
                for r in records
                if (r.get("seq") or 0) > self._floor_seq
            ]
            rows = [r for r in rows if not self._claim_live_tls(r)]
            if reset:
                self._rebuild_if_live()
            if rows:
                self._add_live(rows)
        if self._poll_again:
            self._poll_again = False
            self.poll_now()

    # -- live rows -------------------------------------------------------

    def add_tls_failure(self, ts: str, host: str, reason: str, app: str) -> None:
        """A ``[TLS_FAIL]`` line from mitmweb (UI thread)."""
        self._tls_n += 1
        now = time.time()
        # The flow-log poll can beat mitmweb's stdout: then the row is there.
        for r in reversed(self._live[-50:]):
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
                ms.set_lens_badge(LENS_ID, f"⚑{self._unseen_tls}")

    def _claim_live_tls(self, row: FlowRow) -> bool:
        """A persisted TLS failure that is already on screen (from mitmweb's
        stdout, which is faster than the flow log): adopt its ``seq`` and
        drop the duplicate. Returns True when ``row`` was a duplicate.
        """
        if row.kind != "tls":
            return False
        for live in reversed(self._live[-400:]):
            if (
                live.kind == "tls"
                and live.seq is None
                and live.key.startswith("t")
                and live.host == row.host
                and abs(live.ts - row.ts) <= 10.0
            ):
                live.seq = row.seq
                return True
        return False

    def _add_live(self, rows: list[FlowRow]) -> None:
        self._live.extend(rows)
        if len(self._live) > self.MAX_ROWS + 200:
            self._live = self._live[-self.MAX_ROWS :]
            self._rebuild_if_live()
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

    def _passes(self, row: FlowRow, *, noise: bool = True) -> bool:
        """Whether ``row`` is shown (``noise=False``: ignore the noise filter)."""
        if self.in_review and not self._show_all_phases and row.phase in HIDDEN_PHASES:
            return False
        if self._app_only and self._focus_app and row.app != self._focus_app:
            return False
        if (
            noise
            and not self._show_noise
            and is_noise(row.host, row.path, row.app, self._focus_app)
        ):
            return False
        if self._filter:
            needle = self._filter.lower()
            if needle not in self._haystack(row):
                return False
        return True

    @staticmethod
    def _haystack(row: FlowRow) -> str:
        """What ``/`` matches: host, path, method, app, recipient, status.

        The status column's words are included, so ``/404``, ``/tls`` or
        ``/✗`` (every failed row) work too.
        """
        if row.kind == "tls":
            status = f"✗ tls failed {row.reason}"
        elif row.error:
            status = f"✗ {_short_error(row.error)} error"
        else:
            status = str(row.status) if row.status is not None else ""
        hay = f"{row.method} {row.host}{row.path} {row.app} {row.recipient[0]} {status}"
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
        )

    # -- table -------------------------------------------------------------

    def _layout(self) -> list[tuple[str, str, int]]:
        """``[(key, label, width)]`` of the visible columns for this width.

        Five columns when there is room; a narrow lens (e.g. 100 columns
        with the Inspector open) drops Size, then Time, so Request keeps a
        readable width instead of scrolling sideways.
        """
        avail = self.size.width or 120
        who = 18 if avail >= 110 else (16 if avail >= 58 else 12)
        cols = [("time", "Time", 8), ("who", "Recipient", who)]
        cols += [("req", "Request", 0), ("status", "Status", 9), ("size", "Size", 10)]
        if avail < 76:
            cols = [c for c in cols if c[0] != "size"]
        if avail < 58:
            cols = [c for c in cols if c[0] != "time"]
        # 2 cells padding per column + 1 scrollbar column
        fixed = sum(w for _, _, w in cols) + 2 * len(cols) + 1
        req = max(12, avail - fixed)
        return [(k, label, w or req) for k, label, w in cols]

    def _cells(self, row: FlowRow, layout: list[tuple[str, str, int]]) -> list[Text]:
        widths = {k: w for k, _, w in layout}
        req_w, who_w = widths["req"], widths["who"]
        t = Text(time.strftime("%H:%M:%S", time.localtime(row.ts)), style="#5b6479")
        label, known = row.recipient
        who = Text(_ellipsize(label, who_w), style="#e5e9f0" if known else "#cbd5e1")
        tag = _phase_tag(row.phase) if self.in_review else ""
        if row.kind == "tls":
            req = Text(no_wrap=True, overflow="ellipsis")
            if tag:  # a dry-run / setup TLS failure is marked like its flows
                req.append(f"{tag} ", style="#fbbf24")
            req.append("TLS ", style="#8f9bb3")
            host_w = req_w - 4 - (len(tag) + 1 if tag else 0)
            req.append(_ellipsize(row.host, host_w), style="#e5e9f0")
            status = Text("✗ TLS", style="bold #fb7185")
            size = Text("")
        else:
            if tag:
                req = Text(no_wrap=True, overflow="ellipsis")
                req.append(f"{tag} ", style="#fbbf24")
                req.append_text(
                    smart_request(row.method, row.host, row.path, req_w - len(tag) - 1)
                )
            else:
                req = smart_request(row.method, row.host, row.path, req_w)
            if row.error:
                status = Text(f"✗ {_short_error(row.error)}", style="#fb7185")
            elif row.status is None:
                status = Text("…", style="#5b6479")
            else:
                code = int(row.status)
                color = "#8f9bb3"
                if 400 <= code < 500:
                    color = "#facc15"
                elif code >= 500:
                    color = "#fb7185"
                status = Text(str(code), style=color)
            if row.req_bytes:
                size = Text(f"↑ {human_size(row.req_bytes)}", style="#cbd5e1")
            elif row.resp_bytes:
                size = Text(f"↓ {human_size(row.resp_bytes)}", style="#5b6479")
            else:
                size = Text("–", style="#5b6479")
        size.justify = "right"
        cells = {"time": t, "who": who, "req": req, "status": status, "size": size}
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
        if table.row_count and not self._at_tail(table):
            keep = self._cursor_key()
        layout = self._columns(table)
        rows = [r for r in self._model() if self._passes(r)]
        self._noise_hidden = self._count_noise(self._model())
        self._phase_hidden = self._count_phase_hidden()
        for row in rows:
            table.add_row(*self._cells(row, layout), key=row.key)
        self._shown = len(rows)
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
            self._rebuild()
            return
        follow = self._at_tail(table) and not self._inspecting_flow()
        added = False
        self._noise_hidden += self._count_noise(rows)
        for row in rows:
            if self._passes(row):
                table.add_row(*self._cells(row, self._net_layout), key=row.key)
                self._shown += 1
                added = True
        if added and follow:
            table.move_cursor(row=table.row_count - 1, animate=False)
            table.scroll_end(animate=False)
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
            head = "Nothing matches"
            if self._app_only and self._focus_app:
                head = f"No flows attributed to {escape(self._focus_app)}"
                widen.append("per-app attribution needs an App Proxy (y)")
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
                "(Runs ⏎ → Report shows the folder; open it in Wireshark)"
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
            return f"[#fbbf24]◆ {label}[/]" + (f" · {note}" if note else "")
        mitm = self.mitm
        title = mitm.status_caption() if mitm is not None else ""
        fritap = self.fritap
        token = fritap.caption_token() if fritap is not None else ""
        if token:
            title += f" · {token}"
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
        if self._shown != total:
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
        if self._filter:
            parts.append(f"“{escape(self._filter)}”")
        if self._shown:
            parts.append("⏎ inspect")
        return " · ".join(parts)

    def _do_refresh_status(self) -> None:
        self._status_pending = False
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
                "result", Text(f"✗ TLS failed ({row.reason})", style="#fb7185")
            )
            why = _TLS_REASONS.get(row.reason, _TLS_REASONS["tls"])
            return InspectorContent(
                title=f"✗ TLS · {label}",
                subtitle=escape(row.host),
                sections=[
                    ("", grid),
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
                    style="#fbbf24" if row.phase in HIDDEN_PHASES else "",
                ),
            )
        if row.error:
            grid.add_row("result", Text(f"✗ {row.error}", style="#fb7185"))
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
        summary = [("", grid), ("URL", Text(row.url(), style="#cbd5e1"))]
        if detail is None:
            missing = Text(
                "details not stored (trimmed by retention or never captured)",
                style="#5b6479",
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
                    0, ("Error", Text(str(detail["error"]), style="#fb7185"))
                )
        return InspectorContent(
            title=f"{row.method} {label}",
            subtitle=escape(_ellipsize(row.host + row.path, 300)),
            tabs=[("Summary", summary), ("Request", request), ("Response", response)],
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
            m_sections.append(("Recent", Text("\n".join(m_recent), style="#8f9bb3")))
        f_grid = _grid()
        for label, value in fritap.status_rows() if fritap is not None else []:
            f_grid.add_row(label, Text.from_markup(value))
        f_recent = list(fritap.recent_lines)[-12:] if fritap is not None else []
        f_sections: list[tuple[str, Any]] = [
            ("", f_grid),
            ("Keys", "[b]h[/b] start/stop friTap  [b]^F[/b] output folder"),
        ]
        if f_recent:
            f_sections.append(("Recent", Text("\n".join(f_recent), style="#8f9bb3")))
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

    # -- actions ---------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "start_stop":
            # Only while nothing is captured (footer room); M works always.
            return not self.in_review and not self._model()
        if action == "toggle_phases":
            return self.in_review
        if action in ("filter", "toggle_app_only"):
            # Nothing to filter yet: hidden, so the footer shows ^D instead.
            return bool(self._model())
        return True

    def action_start_stop(self) -> None:
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
                "No spotlight app — pick one in the App lens (c / Shift+C).",
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
        """Esc (MainScreen hook): clear an active ``/`` filter.

        Esc in the filter input clears it and returns to the table; with the
        input closed, Esc clears a filter that is still applied. Returns True
        when Esc was used here.
        """
        try:
            box = self.query_one("#net-filter", Input)
        except Exception:
            return False
        focused = self.screen.focused if self.is_attached else None
        if focused is not box and not self._filter:
            return False
        if self._filter_timer is not None:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
            self._filter_timer = None
        had_filter = bool(self._filter or box.value.strip())
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
