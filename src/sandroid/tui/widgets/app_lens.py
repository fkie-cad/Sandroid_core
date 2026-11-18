"""App lens sections: what the spotlight app is, may do, exposes and resists.

The App lens (:class:`~sandroid.tui.widgets.spotlight_panel.SpotlightPanel`)
keeps its live state, bypass row and lifecycle actions on top; below them
:class:`AppLensSections` holds seven sections, each one
:class:`LensSection` (a ``DataTable`` whose top border carries the title and
a one-line summary):

IDENTITY · PERMISSIONS · EXPOSURE · MANIFEST & NETWORK · TRACKERS & SDKs ·
DATA · SUSPECTED DEFENCES (static)

Every row is inspectable (Enter → Inspector with Evidence / Raw tabs); the
sections take part in the normal focus order (Tab / Shift+Tab), ``z`` folds
the focused one, ``/`` filters the rows of all sections and ``u`` refreshes
the runtime facts. The keys are bound on the panel and delegate here.

Data
----
:class:`AppFacts` holds what is known about the spotlight app; the pure
``build_*`` functions turn it into :class:`SectionData` (rows + summary),
so they are testable without Textual. Everything comes from
:class:`sandroid.services.app_info_service.AppInfoService` (never raises).

Threading
---------
* Every device / androguard call runs in a thread worker
  (``run_worker(thread=True)``); results come back through a
  :class:`UiDispatcher` (non-blocking ``call_soon_threadsafe`` in the UI
  context) and are applied on the UI thread only.
* The device serial is captured on the UI thread when the app is tracked
  and passed to ``AppInfoService(serial)``.
* Requests are tagged with ``(package, generation)``; the generation bumps
  whenever the spotlighted package or the device changes, so a late result
  for a previous app is dropped. Each fact kind also carries a request id
  and an older request never overwrites a newer one.
* First paint: package details, the static overview from the cache only
  (``allow_pull=False``) and the runtime facts. Without a cache entry the
  APK is pulled and decoded afterwards in the same worker, shown as
  "analysing manifest…".
* Runtime facts (grants, AppOps, services; the footprint -- ``du``, can
  take a minute -- in its own worker, on load and ``u`` only)
  refresh on ``STATE_CHANGED`` (throttled to one fetch per
  :data:`RUNTIME_MIN_INTERVAL` seconds, trailing), on lens activation when
  stale, and AppOps alone is polled every :data:`RUNTIME_MIN_INTERVAL`
  seconds while the lens is visible. Nothing polls while it is hidden.
"""

from __future__ import annotations

import functools
import json
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.containers import Vertical
from textual.widgets import DataTable

from sandroid.tui.utils.ui_thread import UiDispatcher
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

#: Lens id in ``LENSES`` (Inspector keys and captions).
LENS_ID = "app"
#: Prefix of every Inspector key this lens opens.
KEY_PREFIX = "app:"
#: Minimum seconds between two runtime fetches (and the AppOps poll period).
RUNTIME_MIN_INTERVAL = 10.0
#: An AppOps access within this many seconds counts as "used recently".
RECENT_SECONDS = 24 * 3600
#: Runtime fact kinds (``u`` refreshes all of them).
RUNTIME_KINDS = ("permissions", "appops", "services", "footprint", "details")
#: Runtime kinds refreshed on STATE_CHANGED / lens activation (cheap ones).
EVENT_KINDS = ("permissions", "appops", "services")

#: Keys of the "+N more" / "hide" toggle rows (``SectionData.hidden_rows``).
MORE_KEY = "_more"
LESS_KEY = "_less"

#: (section id, title) in display order.
SECTIONS: tuple[tuple[str, str], ...] = (
    ("identity", "IDENTITY"),
    ("permissions", "PERMISSIONS"),
    ("exposure", "EXPOSURE"),
    ("manifest", "MANIFEST & NETWORK"),
    ("trackers", "TRACKERS & SDKs"),
    ("data", "DATA"),
    ("defences", "SUSPECTED DEFENCES (static — not observed)"),
)
SECTION_TITLES = dict(SECTIONS)

_DIM = "#5b6479"
_OK = "#4ade80"
_WARN = "#fbbf24"
_BAD = "#fb7185"
_ROUTE_LABELS = {
    "h": "h friTap",
    "b1": "b1 ssl",
    "b2": "b2 root",
    "b3": "b3 frida",
    "b4": "b4 debug",
    "b5": "b5 integrity",
    "b6": "b6 emulator",
}


def make_service(serial: str | None) -> Any:
    """The data facade for ``serial`` (tests replace this function)."""
    from sandroid.services.app_info_service import AppInfoService

    return AppInfoService(serial)


def active_serial() -> str | None:
    """Serial of the active device (UI thread; reads state, no adb call)."""
    try:
        from sandroid.core.device_manager import DeviceManager

        device = DeviceManager.get().active_device
        serial = getattr(device, "serial", None) if device else None
        if serial:
            return str(serial)
    except Exception:
        pass
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# facts + rows (pure)
# ---------------------------------------------------------------------------


@dataclass
class AppFacts:
    """Everything the sections know about one app (UI-thread owned).

    ``static_state``: ``"checking"`` (cache lookup running), ``"analysing"``
    (APK pull + decode running), ``"ready"`` or ``"missing"`` (see
    ``static.reason``).
    """

    package: str
    pid: int | None = None
    details: Any = None
    permissions: Any = None
    appops: Any = None
    footprint: Any = None
    services: Any = None
    static: Any = None
    defences: list[Any] = field(default_factory=list)
    static_state: str = "checking"
    appops_at: float = 0.0


@dataclass
class Row:
    """One table row plus what the Inspector shows for it."""

    key: str
    cells: tuple[Any, ...]
    title: str = ""
    subtitle: str | None = None
    evidence: list[tuple[str, Any]] = field(default_factory=list)
    raw: Any = None
    inspectable: bool = True

    @property
    def text(self) -> str:
        """Plain text of all cells (filter + change detection)."""
        return " ".join(
            c.plain if isinstance(c, Text) else str(c) for c in self.cells
        ).strip()


@dataclass
class SectionData:
    """A section's columns, rows and one-line summary."""

    columns: tuple[str, ...]
    rows: list[Row]
    summary: str = ""
    show_header: bool = True
    #: Rows shown only on request (z / ⏎ on the "+N" row) or while filtering.
    hidden_rows: list[Row] = field(default_factory=list)
    hidden_label: str = "more"


def _t(text: Any, style: str = "") -> Text:
    return Text(str(text) if text is not None else "", style=style)


def _cut(text: str, width: int) -> str:
    text = str(text or "")
    return text if len(text) <= width else text[: max(1, width - 1)] + "…"


def ago(seconds: float | None) -> str:
    """``42s ago`` / ``5m ago`` / ``3h ago`` / ``2d ago`` (``""`` if None)."""
    if seconds is None:
        return ""
    s = max(0, int(seconds))
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def human_kb(kb: int | None) -> str:
    if kb is None:
        return "?"
    size = float(kb)
    for unit in ("KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "KB" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{kb} KB"


def human_bytes(n: int | None) -> str:
    return "?" if n is None else human_kb(int(n) // 1024)


def _to_dict(obj: Any) -> Any:
    if obj is None:
        return None
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:
            pass
    return obj


def _grid(pairs: Iterable[tuple[str, Any]]) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_DIM, no_wrap=True)
    grid.add_column(overflow="fold")
    for key, value in pairs:
        grid.add_row(key, value if isinstance(value, Text) else _t(value))
    return grid


def _kv(key: str, label: str, value: Any, *, style: str = "", **extra: Any) -> Row:
    """A two-column key/value row (identity, manifest, data)."""
    value_text = value if isinstance(value, Text) else _t(value, style)
    return Row(
        key=key,
        cells=(_t(label, _DIM), value_text),
        title=label,
        evidence=extra.pop("evidence", None) or [("", _grid([(label, value_text)]))],
        raw=extra.pop("raw", None),
        **extra,
    )


def _placeholder(key: str, text: str, width: int, style: str = _DIM) -> Row:
    cells = (_t(text, style),) + tuple(_t("") for _ in range(width - 1))
    return Row(key=f"_{key}", cells=cells, inspectable=False)


def _overview(f: AppFacts) -> dict[str, Any]:
    static = f.static
    overview = getattr(static, "overview", None) if static is not None else None
    return overview if isinstance(overview, dict) else {}


def _details(f: AppFacts) -> dict[str, Any]:
    fact = f.details
    value = getattr(fact, "value", None) if fact is not None else None
    return value if isinstance(value, dict) else {}


def static_note(f: AppFacts) -> str | None:
    """Why the static facts are missing (``None`` once they are there)."""
    if _overview(f):
        return None
    if f.static_state == "checking":
        return "checking the APK cache…"
    if f.static_state == "analysing":
        return "analysing manifest… (APK pull + decode, cached per APK)"
    reason = getattr(f.static, "reason", None) if f.static is not None else None
    return f"no static facts: {reason or 'unknown'}"


# -- IDENTITY --------------------------------------------------------------


def build_identity(f: AppFacts) -> SectionData:
    d = _details(f)
    ov = _overview(f)
    static = f.static
    meta = getattr(static, "meta", None) if static is not None else None
    meta = meta if isinstance(meta, dict) else {}
    rows: list[Row] = []
    raw_details = d or _to_dict(f.details)

    version = d.get("version_name") or ov.get("version_name")
    code = d.get("version_code") or ov.get("version_code")
    rows.append(
        _kv(
            "version",
            "version",
            f"{version or '?'}" + (f" ({code})" if code else ""),
            raw=raw_details,
        )
    )
    target = d.get("target_sdk") or ov.get("target_sdk")
    min_sdk = d.get("min_sdk") or ov.get("min_sdk")
    rows.append(
        _kv("sdk", "SDK", f"target {target or '?'} · min {min_sdk or '?'}", raw=d)
    )
    installer = d.get("install_source")
    if d:
        installer_text = installer or "none (sideloaded / adb install)"
    else:
        installer_text = "?"
    rows.append(_kv("installer", "installer", installer_text, raw=d))
    rows.append(_kv("uid", "uid", d.get("uid") or "?", raw=d))

    signer = ov.get("signer") if isinstance(ov.get("signer"), dict) else {}
    certs = [c for c in signer.get("certificates") or [] if isinstance(c, dict)]
    if certs:
        digest = str(certs[0].get("sha256") or "?")
        schemes = ",".join(signer.get("schemes") or []) or "?"
        more = f" (+{len(certs) - 1})" if len(certs) > 1 else ""
        value = f"sha256 {digest[:16]}…{more} · {schemes}"
        evidence = [
            (
                f"certificate {i + 1}",
                _grid(
                    (k, str(c.get(k) or "?"))
                    for k in ("subject", "issuer", "sha256", "sha1", "not_after")
                ),
            )
            for i, c in enumerate(certs)
        ]
        evidence.insert(0, ("", _grid([("schemes", schemes)])))
        rows.append(_kv("signer", "signer", value, evidence=evidence, raw=signer))
    else:
        rows.append(
            _kv(
                "signer",
                "signer",
                static_note(f) or "no certificate",
                style=_DIM,
                raw=d.get("signing_info"),
            )
        )
    installed = d.get("install_date") or "?"
    updated = d.get("last_update")
    rows.append(
        _kv(
            "installed",
            "installed",
            f"first {installed}" + (f" · updated {updated}" if updated else ""),
            raw=d,
        )
    )
    splits = [s for s in meta.get("splits") or [] if isinstance(s, dict)]
    if splits:
        total = sum(int(s.get("size") or 0) for s in splits)
        names = [str(s.get("name") or "?") for s in splits]
        value = f"{human_bytes(total)} · {len(splits)} file" + (
            "s" if len(splits) != 1 else ""
        )
        if len(splits) > 1:
            value += f" ({', '.join(n for n in names if n != 'base.apk')[:40]})"
        evidence = [
            (
                "splits",
                _grid(
                    (
                        str(s.get("name") or "?"),
                        f"{human_bytes(s.get('size'))}"
                        + (" · config" if s.get("config") else "")
                        + f"\nsha256 {s.get('sha256') or '?'}",
                    )
                    for s in splits
                ),
            )
        ]
        rows.append(_kv("apk", "APK", value, evidence=evidence, raw=splits))
    else:
        rows.append(
            _kv("apk", "APK", static_note(f) or d.get("apk_path") or "?", style=_DIM)
        )
    key = getattr(static, "key", None) if static is not None else None
    if ov:
        insight = getattr(static, "insight", None)
        cache = "cached" if getattr(static, "from_cache", False) else "analysed now"
        cache += f" · key {str(key)[:12]}…" if key else ""
        cache += " · Insight ✓" if insight else " · Insight — (a = static analysis)"
        style = ""
    else:
        cache = static_note(f) or "?"
        style = _WARN if f.static_state == "analysing" else _DIM
    rows.append(
        _kv(
            "cache",
            "static cache",
            cache,
            style=style,
            raw={"key": key, "meta": meta, "reason": getattr(static, "reason", None)},
        )
    )
    services = f.services
    svc_list = list(getattr(services, "services", None) or [])
    fg = [s for s in svc_list if getattr(s, "foreground", False)]
    proc = f"PID {f.pid}" if f.pid else "not running"
    if services is not None and not getattr(services, "ok", True):
        svc_text = f"services: {getattr(services, 'reason', '?')}"
    else:
        svc_text = f"{len(svc_list)} service" + ("s" if len(svc_list) != 1 else "")
        if fg:
            types = sorted({t for s in fg for t in (getattr(s, "types", None) or [])})
            svc_text += f" ({len(fg)} foreground" + (
                f": {', '.join(types)})" if types else ")"
            )
    rows.append(
        _kv(
            "process",
            "process",
            f"{proc} · {svc_text}",
            evidence=[
                (
                    getattr(s, "component", "?"),
                    _grid(
                        [
                            ("foreground", "yes" if s.foreground else "no"),
                            ("types", ", ".join(s.types) or "—"),
                            ("process", f"{s.process or '?'} (pid {s.pid or '?'})"),
                            ("created", s.created or "?"),
                        ]
                    ),
                )
                for s in svc_list
            ]
            or [("", _t("no running services", _DIM))],
            raw=_to_dict(services),
        )
    )
    reason = getattr(f.details, "reason", None) if f.details is not None else None
    summary = f"{f.package}"
    if version:
        summary += f" {version}"
    if f.details is None:
        summary += " · loading…"
    elif reason:
        summary += f" · {reason}"
    return SectionData(("field", "value"), rows, summary, show_header=False)


# -- PERMISSIONS -----------------------------------------------------------

_PERM_PREFIX = "android.permission."
_LOOSE = ("allow", "foreground")


def _short_perm(name: str) -> str:
    return name[len(_PERM_PREFIX) :] if name.startswith(_PERM_PREFIX) else name


def _manifest_perm_line(name: str) -> str:
    return f'<uses-permission android:name="{name}" />'


def _op_cell(ops: list[Any]) -> Text:
    """``allow · 5m ago ✗2h`` -- effective mode, last access, last reject."""
    if not ops:
        return _t("—", _DIM)

    def age(o: Any) -> float:
        return o.last_access_ago_s if o.last_access_ago_s is not None else 1e12

    op = min(ops, key=age)  # the most recent access
    mode = op.mode or "?"
    style = _OK if mode in _LOOSE else (_BAD if mode in ("deny", "ignore") else "")
    text = Text(mode, style=style)
    if any(o.running for o in ops):
        text.append(" ● now", style=f"bold {_WARN}")
    elif op.last_access_ago_s is not None:
        text.append(f" · {ago(op.last_access_ago_s)}")
    elif op.last_access:
        text.append(f" · {_cut(op.last_access, 12)}")
    rejects = [o.last_reject_ago_s for o in ops if o.last_reject_ago_s is not None]
    if rejects:
        text.append(f" ✗{ago(min(rejects)).replace(' ago', '')}", style=_BAD)
    elif any(o.last_reject for o in ops):
        text.append(" ✗", style=_BAD)
    return text


def _op_evidence(op: Any) -> Table:
    proxy = ", ".join(op.proxy_packages) or "—"
    return _grid(
        [
            (
                "mode",
                f"{op.mode or '?'} (uid {op.uid_mode or '—'}, package "
                f"{op.package_mode or '—'})",
            ),
            (
                "last access",
                f"{op.last_access or '—'}"
                + (
                    f"  ({ago(op.last_access_ago_s)})"
                    if op.last_access_ago_s is not None
                    else ""
                )
                + (
                    f"  states {', '.join(op.access_states)}"
                    if op.access_states
                    else ""
                ),
            ),
            (
                "last reject",
                f"{op.last_reject or '—'}"
                + (
                    f"  ({ago(op.last_reject_ago_s)})"
                    if op.last_reject_ago_s is not None
                    else ""
                ),
            ),
            ("duration", op.duration or "—"),
            ("running", "yes" if op.running else "no"),
            ("fg / bg", f"{op.foreground} / {op.background}"),
            ("proxied by", proxy),
        ]
    )


def _grant_cell(g: Any, ops: list[Any]) -> Text:
    if g.granted is None:
        return _t("req → ?", _DIM)
    if g.granted and getattr(g, "revoked", False):
        text = Text("req → ", style=_DIM)
        text.append("✓ revoked", style=_BAD)
        return text
    if not g.granted:
        text = Text("req → ✗", style=_DIM)
    else:
        text = Text("req → ", style=_DIM)
        text.append("✓", style=_OK)
        if any(o.mode == "foreground" for o in ops):
            text.append(" while-in-use", style=_WARN)
        elif "ONE_TIME" in (g.flags or []):
            text.append(" once", style=_WARN)
        elif g.kind == "install":
            text.append(" install", style=_DIM)
    return text


def _perm_note(g: Any, ops: list[Any]) -> tuple[str, str]:
    """``(note, style)`` for a permission row."""
    notes = []
    style = _DIM
    used = [o for o in ops if o.last_access_ago_s is not None]
    if any(o.running for o in ops):
        notes.append("in use now")
        style = _WARN
    elif used and min(o.last_access_ago_s for o in used) <= RECENT_SECONDS:
        notes.append("used recently")
        style = _WARN
    elif (
        g.granted
        and g.protection == "dangerous"
        and ops
        and not any(o.last_access for o in ops)
    ):
        notes.append("no recorded use")
    flags = set(g.flags or [])
    if "USER_FIXED" in flags:
        notes.append("user-fixed")
    elif "POLICY_FIXED" in flags or "SYSTEM_FIXED" in flags:
        notes.append("fixed")
    if g.restricted:
        notes.append("restricted")
    if getattr(g, "revoked", False):
        notes.append(f"granted but revoked ({g.revoked_reason})")
    if any(o.last_reject for o in ops):
        notes.append("rejected")
    return ", ".join(notes), style


def build_permissions(f: AppFacts) -> SectionData:
    cols = ("permission", "protection", "grant", "AppOps", "note")
    state = f.permissions
    if state is None:
        return SectionData(cols, [_placeholder("loading", "loading…", 5)], "loading…")
    appops = f.appops
    ops = list(getattr(appops, "ops", None) or [])
    by_perm: dict[str, list[Any]] = {}
    for op in ops:
        if op.permission:
            by_perm.setdefault(op.permission, []).append(op)
    if appops is not None and hasattr(state, "permissions"):
        from sandroid.services.app_info_service import apply_appops_revocations

        apply_appops_revocations(state, appops)
    grants = list(getattr(state, "permissions", None) or [])
    names = {g.name for g in grants}
    order = {"dangerous": 0, "signature": 2, "normal": 3}

    def sort_key(g: Any) -> tuple:
        return (order.get(g.protection or "", 1), not g.granted, g.name)

    rows: list[Row] = []
    dangerous = granted_dangerous = recent = unused = 0
    for g in sorted(grants, key=sort_key):
        g_ops = by_perm.get(g.name, [])
        note, note_style = _perm_note(g, g_ops)
        prot = g.protection or "?"
        if prot == "dangerous":
            dangerous += 1
            if g.granted and not getattr(g, "revoked", False):
                granted_dangerous += 1
        if "used recently" in note or "in use now" in note:
            recent += 1
        if "no recorded use" in note:
            unused += 1
        prot_style = (
            _WARN if prot == "dangerous" else (_DIM if prot == "normal" else "")
        )
        evidence: list[tuple[str, Any]] = [
            ("Manifest", _t(_manifest_perm_line(g.name))),
            (
                "Grant",
                _grid(
                    [
                        ("requested", "yes" if g.requested else "no"),
                        ("kind", g.kind),
                        (
                            "granted",
                            {True: "yes", False: "no", None: "unknown"}[g.granted],
                        ),
                        ("flags", ", ".join(g.flags or []) or "—"),
                        ("restricted", "yes" if g.restricted else "no"),
                        (
                            "revoked",
                            g.revoked_reason if getattr(g, "revoked", False) else "no",
                        ),
                        (
                            "protection",
                            f"{prot} (from {g.protection_source or '?'})",
                        ),
                    ]
                ),
            ),
        ]
        for op in g_ops:
            evidence.append((f"AppOps {op.op}", _op_evidence(op)))
        if not g_ops:
            evidence.append(("AppOps", _t("no AppOps op for this permission", _DIM)))
        rows.append(
            Row(
                key=f"perm:{g.name}",
                cells=(
                    _t(_cut(_short_perm(g.name), 30)),
                    _t(prot, prot_style),
                    _grant_cell(g, g_ops),
                    _op_cell(g_ops),
                    _t(_cut(note, 22), note_style),
                ),
                title=_short_perm(g.name),
                subtitle=escape(g.name),
                evidence=evidence,
                raw={
                    "grant": _to_dict(g),
                    "appops": [_to_dict(o) for o in g_ops],
                },
            )
        )
    # Ops without a (requested) permission: READ_CLIPBOARD, *_AUDIO_FOCUS...
    # Most are the platform's own uid-level bookkeeping ("ignore" for every
    # runtime-permission op the app did not get): only notable ones get a
    # row, the rest collapse into one "+N other ops" row (z / ⏎ / filter).
    extra = [o for o in ops if not o.permission or o.permission not in names]
    hidden: list[Row] = []
    for op in sorted(
        extra,
        key=lambda o: (o.last_access_ago_s is None, o.last_access_ago_s or 0, o.op),
    ):
        used = op.running or (
            op.last_access_ago_s is not None and op.last_access_ago_s <= RECENT_SECONDS
        )
        if used:
            recent += 1
        never = not op.running and not op.last_access
        if never:
            unused += 1
        # The protection column already says "op".
        parts = ["used recently"] if used else []
        parts += ["no recorded use"] if never else []
        parts += ["rejected"] if op.last_reject else []
        note = ", ".join(parts) or "op only"
        (rows if op_is_notable(op) else hidden).append(
            Row(
                key=f"op:{op.op}",
                cells=(
                    _t(_cut(op.op, 30)),
                    _t("op", _DIM),
                    _t("—", _DIM),
                    _op_cell([op]),
                    _t(_cut(note, 22), _WARN if used else _DIM),
                ),
                title=op.op,
                subtitle="AppOps op without a requested permission",
                evidence=[(f"AppOps {op.op}", _op_evidence(op))],
                raw={"appops": [_to_dict(op)]},
            )
        )
    if not getattr(state, "ok", True):
        rows.insert(
            0,
            _placeholder("perm-reason", f"⚠ {state.reason or 'unavailable'}", 5, _BAD),
        )
    if appops is not None and not getattr(appops, "ok", True):
        rows.append(
            _placeholder(
                "appops-reason", f"AppOps: {appops.reason or 'unavailable'}", 5, _DIM
            )
        )
    requested = sum(1 for g in grants if g.requested)
    summary = (
        f"{requested} requested · {dangerous} dangerous ({granted_dangerous} "
        f"granted) · {recent} used recently · {unused} no recorded use"
    )
    return SectionData(
        cols,
        rows,
        summary,
        hidden_rows=hidden,
        hidden_label="other ops (no recorded use)",
    )


def op_is_notable(op: Any) -> bool:
    """An op-only AppOps entry worth its own row.

    Recorded access or rejection, running, or a mode the platform does not
    set on its own: ``deny`` / ``foreground`` / ``errored`` or an explicit
    package-level mode. A bare uid-level ``ignore`` (every runtime-permission
    op the app was not granted) or ``default`` is bookkeeping.
    """
    if op.running or op.last_access or op.last_reject:
        return True
    if op.mode in ("deny", "foreground", "errored"):
        return True
    return op.package_mode not in (None, "default", op.uid_mode)


# -- EXPOSURE --------------------------------------------------------------

_KIND_SINGULAR = {
    "activities": "activity",
    "services": "service",
    "receivers": "receiver",
    "providers": "provider",
}


def _short_component(name: str, package: str) -> str:
    if package and name.startswith(package + "."):
        return name[len(package) :]
    return name


def _component_xml(kind: str, comp: dict[str, Any]) -> str:
    tag = _KIND_SINGULAR.get(kind, kind)
    attrs = [f'android:name="{comp.get("name")}"']
    attrs.append(f'android:exported="{str(bool(comp.get("exported"))).lower()}"')
    for key, attr in (
        ("permission", "permission"),
        ("read_permission", "readPermission"),
        ("write_permission", "writePermission"),
    ):
        if comp.get(key):
            attrs.append(f'android:{attr}="{comp[key]}"')
    if comp.get("authorities"):
        attrs.append(f'android:authorities="{";".join(comp["authorities"])}"')
    lines = [f"<{tag} " + " ".join(attrs) + ">"]
    for filt in comp.get("intent_filters") or []:
        lines.append("  <intent-filter>")
        for action in filt.get("actions") or []:
            lines.append(f'    <action android:name="{action}" />')
        for cat in filt.get("categories") or []:
            lines.append(f'    <category android:name="{cat}" />')
        for data in filt.get("data") or []:
            inner = " ".join(f'android:{k}="{v}"' for k, v in data.items() if v)
            lines.append(f"    <data {inner} />")
        lines.append("  </intent-filter>")
    lines.append(f"</{tag}>")
    return "\n".join(lines)


def build_exposure(f: AppFacts) -> SectionData:
    cols = ("kind", "component / link", "guard", "filters")
    ov = _overview(f)
    note = static_note(f)
    if note:
        style = _WARN if f.static_state == "analysing" else _DIM
        return SectionData(cols, [_placeholder("static", note, 4, style)], note)
    comps = ov.get("components") if isinstance(ov.get("components"), dict) else {}
    rows: list[Row] = []
    exported = unguarded = 0
    for kind in ("activities", "services", "receivers", "providers"):
        for comp in comps.get(kind) or []:
            if not isinstance(comp, dict) or not comp.get("exported"):
                continue
            exported += 1
            name = str(comp.get("name") or "?")
            if kind == "providers":
                perms = [
                    p
                    for p in (comp.get("read_permission"), comp.get("write_permission"))
                    if p
                ]
            else:
                perms = [comp["permission"]] if comp.get("permission") else []
            if perms:
                guard = _t(_cut(_short_perm(perms[0]), 26))
            else:
                unguarded += 1
                guard = _t("no permission", _WARN)
            filters = comp.get("intent_filters") or []
            actions = [a for flt in filters for a in flt.get("actions") or []]
            if kind == "providers":
                filt_text = ", ".join(comp.get("authorities") or []) or "—"
            else:
                filt_text = (
                    f"{len(filters)} filter" + ("s" if len(filters) != 1 else "")
                    if filters
                    else "—"
                )
                if actions:
                    filt_text += f" · {_short_action(actions[0])}"
            rows.append(
                Row(
                    key=f"comp:{kind}:{name}",
                    cells=(
                        _t(_KIND_SINGULAR[kind], _DIM),
                        _t(_cut(_short_component(name, f.package), 40)),
                        guard,
                        _t(_cut(filt_text, 30), _DIM),
                    ),
                    title=_short_component(name, f.package),
                    subtitle=escape(name),
                    evidence=[
                        (
                            "Manifest (reconstructed from the parsed manifest)",
                            Syntax(
                                _component_xml(kind, comp),
                                "xml",
                                theme="ansi_dark",
                                word_wrap=True,
                                background_color="default",
                            ),
                        ),
                        (
                            "Guard",
                            _t(
                                ", ".join(perms)
                                if perms
                                else "exported without a permission: any app can "
                                "start / bind / query it"
                            ),
                        ),
                    ],
                    raw=comp,
                )
            )
    links = [lk for lk in ov.get("deep_links") or [] if isinstance(lk, dict)]
    schemes: set[str] = set()
    for i, link in enumerate(links):
        scheme = str(link.get("scheme") or "")
        host = str(link.get("host") or "")
        path = str(
            link.get("path") or link.get("pathPrefix") or link.get("pathPattern") or ""
        )
        if scheme:
            schemes.add(scheme)
        url = f"{scheme or '*'}://{host or '*'}{path}"
        comp = str(link.get("component") or "?")
        rows.append(
            Row(
                key=f"link:{i}:{url}",
                cells=(
                    _t("deep link", _DIM),
                    _t(_cut(url, 40)),
                    _t(
                        "exported" if link.get("exported") else "not exported",
                        "" if link.get("exported") else _DIM,
                    ),
                    _t(_cut(_short_component(comp, f.package), 30), _DIM),
                ),
                title=url,
                subtitle=escape(comp),
                evidence=[("", _grid((k, str(v)) for k, v in link.items() if v))],
                raw=link,
            )
        )
    if not rows:
        rows.append(_placeholder("none", "nothing exported", 4))
    hosts = {str(lk.get("host")) for lk in links if lk.get("host")}
    summary = (
        f"{exported} exported ({unguarded} without permission) · "
        f"{len(schemes)} deep-link scheme" + ("s" if len(schemes) != 1 else "")
    )
    if schemes:
        summary += f" ({', '.join(sorted(schemes))[:30]})"
    if hosts:
        summary += f" · {len(hosts)} host" + ("s" if len(hosts) != 1 else "")
    return SectionData(cols, rows, summary)


def _short_action(action: str) -> str:
    for prefix in ("android.intent.action.", "android.intent."):
        if action.startswith(prefix):
            return action[len(prefix) :]
    return action


# -- MANIFEST & NETWORK ----------------------------------------------------


def _yes_no(value: Any, *, bad_when: bool | None = None) -> Text:
    if value is None:
        return _t("?", _DIM)
    style = _BAD if bad_when is not None and bool(value) == bad_when else ""
    return _t("yes" if value else "no", style)


def build_manifest(f: AppFacts) -> SectionData:
    cols = ("fact", "value")
    ov = _overview(f)
    note = static_note(f)
    if note:
        style = _WARN if f.static_state == "analysing" else _DIM
        return SectionData(
            cols, [_placeholder("static", note, 2, style)], note, show_header=False
        )
    nsc = ov.get("nsc") if isinstance(ov.get("nsc"), dict) else {}
    rows: list[Row] = []
    rows.append(
        _kv(
            "debuggable",
            "debuggable",
            _yes_no(ov.get("debuggable"), bad_when=True),
            evidence=[
                (
                    "Manifest",
                    _t(
                        '<application android:debuggable="'
                        f'{str(bool(ov.get("debuggable"))).lower()}" … />'
                    ),
                )
            ],
            raw={"debuggable": ov.get("debuggable")},
        )
    )
    rows.append(
        _kv(
            "allow_backup",
            "allowBackup",
            _yes_no(ov.get("allow_backup"), bad_when=True),
            evidence=[
                (
                    "Manifest",
                    _t(
                        '<application android:allowBackup="'
                        f'{str(bool(ov.get("allow_backup"))).lower()}" … />'
                        "  (absent = true)"
                    ),
                )
            ],
            raw={"allow_backup": ov.get("allow_backup")},
        )
    )
    clear = nsc.get("cleartext_effective")
    clear_text = _yes_no(clear, bad_when=True)
    domains = list(nsc.get("cleartext_domains") or [])
    if domains:
        clear_text.append(f" + {len(domains)} domain(s)", style=_WARN)
    clear_text.append(f"  {nsc.get('cleartext_source') or ''}", style=_DIM)
    rows.append(
        _kv(
            "cleartext",
            "cleartext",
            clear_text,
            evidence=[
                (
                    "",
                    _grid(
                        [
                            ("effective", str(clear)),
                            ("source", str(nsc.get("cleartext_source") or "?")),
                            (
                                "usesCleartextTraffic",
                                str(nsc.get("uses_cleartext_traffic")),
                            ),
                            ("NSC base-config", str(nsc.get("cleartext_base"))),
                            ("cleartext domains", ", ".join(domains) or "—"),
                            ("NSC file", str(nsc.get("path") or "none")),
                        ]
                    ),
                )
            ],
            raw=nsc,
        )
    )
    user_ca = nsc.get("trust_user_ca")
    ca_domains = list(nsc.get("trust_user_ca_domains") or [])
    ca_text = _t("yes" if user_ca else "no", _OK if user_ca else "")
    if ca_domains:
        ca_text.append(f" · scoped: {_cut(', '.join(ca_domains), 40)}", style=_OK)
    elif nsc.get("trust_user_ca_debug_only"):
        ca_text.append(" · debug-overrides only (app not debuggable)", style=_DIM)
    if nsc.get("trust_user_ca_source"):
        ca_text.append(f"  {nsc.get('trust_user_ca_source')}", style=_DIM)
    rows.append(
        _kv(
            "user_ca",
            "user-CA trust",
            ca_text,
            evidence=[
                (
                    "",
                    _grid(
                        [
                            ("trusted app-wide", str(user_ca)),
                            ("source", str(nsc.get("trust_user_ca_source") or "—")),
                            ("scoped domains", ", ".join(ca_domains) or "—"),
                            (
                                "debug-overrides only",
                                str(nsc.get("trust_user_ca_debug_only")),
                            ),
                            ("bundled CA", str(nsc.get("bundled_ca"))),
                        ]
                    ),
                )
            ],
            raw=nsc,
        )
    )
    pins = [p for p in nsc.get("pin_sets") or [] if isinstance(p, dict)]
    if pins:
        pin_domains = sorted({d for p in pins for d in p.get("domains") or []})
        pin_text = _t(
            f"{len(pins)} pin-set(s): {_cut(', '.join(pin_domains), 50)}", _WARN
        )
    else:
        pin_text = _t("none in the NSC", _DIM)
    if nsc.get("override_pins"):
        pin_text.append(" · overridePins", style=_OK)
    rows.append(
        _kv(
            "pins",
            "pin-sets",
            pin_text,
            evidence=[
                (
                    ", ".join(p.get("domains") or []) or "pin-set",
                    _grid(
                        [
                            ("pins", str(p.get("pins"))),
                            ("expiration", str(p.get("expiration") or "—")),
                        ]
                    ),
                )
                for p in pins
            ]
            or [("", _t("no <pin-set> in the network security config", _DIM))],
            raw=pins,
        )
    )
    tls = [d for d in f.defences if getattr(d, "category", "") == "tls_stack"]
    if tls:
        tls_text = _t(", ".join(d.title for d in tls), _WARN)
    else:
        tls_text = _t("no bundled native TLS lib found", _DIM)
    libs = list(ov.get("native_libs") or [])
    rows.append(
        _kv(
            "tls",
            "TLS stacks",
            tls_text,
            evidence=[
                (d.title, _t("\n".join(d.evidence) + (f"\n{d.hint}" if d.hint else "")))
                for d in tls
            ]
            + [("native libs", _t(", ".join(libs) or "none", _DIM))],
            raw={"tls_stacks": [_to_dict(d) for d in tls], "native_libs": libs},
        )
    )
    flags = []
    if ov.get("debuggable"):
        flags.append("debuggable")
    if clear:
        flags.append("cleartext")
    if user_ca or ca_domains:
        flags.append("user CA")
    if pins:
        flags.append(f"{len(pins)} pin-set(s)")
    if tls:
        flags.append(f"{len(tls)} TLS lib(s)")
    summary = " · ".join(flags) if flags else "nothing notable"
    return SectionData(cols, rows, summary, show_header=False)


# -- TRACKERS & SDKs -------------------------------------------------------

ANALYSIS_HINT = "press a to run static analysis (cached per APK)"


def build_trackers(f: AppFacts) -> SectionData:
    cols = ("SDK", "category", "version", "vendor")
    insight = getattr(f.static, "insight", None) if f.static is not None else None
    if not isinstance(insight, dict):
        note = static_note(f) if f.static_state in ("checking", "analysing") else None
        text = note or ANALYSIS_HINT
        return SectionData(
            cols,
            [_placeholder("hint", text, 4, _WARN if note else _DIM)],
            note or "no Insight result",
        )
    libs_block = insight.get("library_detection")
    libs = libs_block.get("detected_libraries") if isinstance(libs_block, dict) else []
    libs = [lib for lib in libs or [] if isinstance(lib, dict)]
    rows: list[Row] = []
    cats: dict[str, int] = {}
    trackers = getattr(f.static, "trackers", None)
    if not trackers:
        from sandroid.services.app_info_service import insight_trackers

        trackers = insight_trackers(insight)
    for i, trk in enumerate(
        sorted(trackers, key=lambda x: (str(x.get("category")), str(x.get("name"))))
    ):
        name = str(trk.get("name") or "?")
        domains = trk.get("network_domains") or trk.get("network_signature") or ""
        if isinstance(domains, list):
            domains = ", ".join(str(d) for d in domains)
        rows.append(
            Row(
                key=f"trk:{i}:{name}",
                cells=(
                    _t(_cut(name, 30), _WARN),
                    _t(_cut(str(trk.get("category") or "tracker"), 18), _DIM),
                    _t(_cut(str(trk.get("version") or "—"), 12), _DIM),
                    _t(_cut(str(domains or trk.get("website") or "—"), 20), _DIM),
                ),
                title=name,
                subtitle="tracker (Insight)",
                evidence=[("", _grid((k, str(v)) for k, v in trk.items() if v))],
                raw=trk,
            )
        )
    for i, lib in enumerate(
        sorted(libs, key=lambda x: (str(x.get("category")), str(x.get("name"))))
    ):
        name = str(lib.get("name") or lib.get("package_name") or "?")
        cat = str(lib.get("category") or "?")
        cats[cat] = cats.get(cat, 0) + 1
        tracker = any(k in cat.lower() for k in ("analytic", "advert", "track"))
        rows.append(
            Row(
                key=f"sdk:{i}:{name}",
                cells=(
                    _t(_cut(name, 30), _WARN if tracker else ""),
                    _t(_cut(cat, 18), _DIM),
                    _t(_cut(str(lib.get("version") or "—"), 12), _DIM),
                    _t(_cut(str(lib.get("vendor") or "—"), 20), _DIM),
                ),
                title=name,
                subtitle=escape(str(lib.get("package_name") or "")),
                evidence=[("", _grid((k, str(v)) for k, v in lib.items() if v))],
                raw=lib,
            )
        )
    overview = insight.get("apk_overview")
    framework = (
        overview.get("cross_platform_framework") if isinstance(overview, dict) else None
    )
    if framework:
        rows.insert(
            0,
            Row(
                key="sdk:framework",
                cells=(_t(str(framework)), _t("framework", _DIM), _t(""), _t("")),
                title=str(framework),
                evidence=[("", _t("cross-platform framework (Insight)"))],
                raw={"cross_platform_framework": framework},
            ),
        )
    if not rows:
        rows.append(_placeholder("none", "no SDKs detected by Insight", 4))
    summary = f"{len(libs)} SDK" + ("s" if len(libs) != 1 else "")
    if trackers:
        summary = f"{len(trackers)} tracker" + "s" * (len(trackers) != 1)
        summary += f" · {len(libs)} SDK" + "s" * (len(libs) != 1)
    if cats:
        top = sorted(cats.items(), key=lambda kv: -kv[1])[:3]
        summary += " · " + ", ".join(f"{n} {c}" for c, n in top)
    return SectionData(cols, rows, summary + " (Insight, cached)")


# -- DATA ------------------------------------------------------------------


def build_data(f: AppFacts) -> SectionData:
    cols = ("field", "value")
    fp = f.footprint
    if fp is None:
        return SectionData(
            cols, [_placeholder("loading", "measuring…", 2)], "measuring…", False
        )
    raw = _to_dict(fp)

    def size(kb: int | None, reason: str | None) -> Text:
        text = _t(human_kb(kb) if kb is not None else "?")
        if reason:
            text.append(f"  {reason}", style=_DIM)
        return text

    data_dir = getattr(fp, "data_dir", None)
    rows = [
        _kv(
            "private",
            "private (CE)",
            size(fp.private_kb, fp.private_reason),
            evidence=[
                (
                    "",
                    _grid(
                        [("path", fp.private_dir or "?"), ("dataDir", data_dir or "?")]
                    ),
                ),
            ],
            raw=raw,
        ),
        _kv(
            "private_de",
            "private (DE)",
            size(getattr(fp, "de_kb", None), getattr(fp, "de_reason", None)),
            evidence=[("", _grid([("path", getattr(fp, "de_dir", "") or "?")]))],
            raw=raw,
        ),
        _kv(
            "external",
            "external",
            size(fp.external_kb, fp.external_reason),
            evidence=[("", _grid([("path", fp.external_dir or "?")]))],
            raw=raw,
        ),
    ]
    if fp.shared_prefs_count is None and fp.databases_count is None:
        why = fp.private_reason or fp.reason or "needs root"
        rows.append(_kv("files", "prefs / dbs", f"? ({why})", style=_DIM, raw=raw))
    else:
        rows.append(
            _kv(
                "files",
                "prefs / dbs",
                f"{fp.shared_prefs_count if fp.shared_prefs_count is not None else '?'}"
                " shared_prefs · "
                f"{fp.databases_count if fp.databases_count is not None else '?'}"
                " databases",
                raw=raw,
            )
        )
    rows.append(
        _kv("root", "read as", fp.root_method or "shell (no root)", style=_DIM, raw=raw)
    )
    rows.append(
        _kv(
            "files_lens",
            "files",
            "3 → Files lens (watch, pull, diff)",
            style=_DIM,
            evidence=[
                (
                    "",
                    _t(
                        "The Files lens (3) watches the app's files live, pulls "
                        "them and diffs versions."
                    ),
                )
            ],
        )
    )
    summary = f"private {human_kb(fp.private_kb)} · external {human_kb(fp.external_kb)}"
    if fp.reason:
        summary += f" · {fp.reason}"
    return SectionData(cols, rows, summary, show_header=False)


# -- SUSPECTED DEFENCES ----------------------------------------------------

_CONF = {"high": "●●●", "medium": "●●○", "low": "●○○"}


def _chord_digits() -> set[str]:
    try:
        from sandroid.tui.modals.objection_modal import BYPASS_KEYS

        return {key for key, _cat, _label in BYPASS_KEYS}
    except Exception:
        return set()


def route_text(routes: Iterable[str]) -> str:
    """``h friTap · b2 root`` (``v`` verify is not offered yet).

    A ``bN`` the bypass chord does not have (``b6`` emulator today) is
    marked "n/a" instead of pointing at a dead key.
    """
    digits = _chord_digits()
    parts = []
    for route in routes:
        if route == "v":
            continue
        label = _ROUTE_LABELS.get(route, route)
        if route.startswith("b") and route[1:] not in digits:
            label += " (n/a)"
        parts.append(label)
    return " · ".join(parts)


def build_defences(f: AppFacts) -> SectionData:
    cols = ("conf.", "suspected defence", "evidence", "route")
    note = static_note(f)
    if note:
        style = _WARN if f.static_state == "analysing" else _DIM
        return SectionData(cols, [_placeholder("static", note, 4, style)], note)
    rows: list[Row] = []
    defences = [d for d in f.defences if getattr(d, "category", "") != "tls_stack"]
    weak = 0
    for d in defences:
        evidence = list(d.evidence or [])
        first = evidence[0] if evidence else "—"
        more = f" +{len(evidence) - 1}" if len(evidence) > 1 else ""
        title = d.title + (" (eases analysis)" if d.weakness else "")
        if d.weakness:
            weak += 1
        conf_style = {"high": _BAD, "medium": _WARN}.get(d.confidence, _DIM)
        rows.append(
            Row(
                key=f"def:{d.id}",
                cells=(
                    _t(_CONF.get(d.confidence, "?"), _OK if d.weakness else conf_style),
                    _t(_cut(title, 30), _OK if d.weakness else ""),
                    _t(_cut(first, 34) + more, _DIM),
                    _t(_cut(route_text(d.routes), 24)),
                ),
                title=d.title,
                subtitle=f"{d.category} · {d.status} · source {d.source or '?'}",
                evidence=[
                    ("Evidence (static)", _t("\n".join(f"• {e}" for e in evidence))),
                    (
                        "Suggested route",
                        _t((route_text(d.routes) or "—") + "\n" + (d.hint or "")),
                    ),
                    (
                        "Status",
                        _t(
                            "Suspected from static facts only; not observed at "
                            f"runtime. Confidence: {d.confidence}.",
                            _DIM,
                        ),
                    ),
                ],
                raw=_to_dict(d),
            )
        )
    if not rows:
        rows.append(_placeholder("none", "none suspected from static facts", 4))
    n = len(defences) - weak
    summary = f"{n} suspected" + (f" · {weak} weakness(es)" if weak else "")
    insight = getattr(f.static, "insight", None) if f.static is not None else None
    if not insight:
        summary += " · manifest + native libs only (a = deeper)"
    return SectionData(cols, rows, summary)


BUILDERS: dict[str, Callable[[AppFacts], SectionData]] = {
    "identity": build_identity,
    "permissions": build_permissions,
    "exposure": build_exposure,
    "manifest": build_manifest,
    "trackers": build_trackers,
    "data": build_data,
    "defences": build_defences,
}


def row_content(section: str, row: Row) -> InspectorContent:
    """The Inspector page of one row: Evidence and Raw tabs."""
    try:
        raw = json.dumps(row.raw, indent=2, default=str, sort_keys=True)
    except Exception:
        raw = str(row.raw)
    raw_body: Any = (
        Syntax(
            raw, "json", theme="ansi_dark", word_wrap=True, background_color="default"
        )
        if row.raw is not None
        else _t("no raw data for this row", _DIM)
    )
    return InspectorContent(
        title=f"{SECTION_TITLES.get(section, section).split(' (')[0]} · {row.title}",
        subtitle=row.subtitle,
        tabs=(
            ("Evidence", row.evidence or [("", _t("—", _DIM))]),
            ("Raw", [("", raw_body)]),
        ),
        footer="u refresh",
        key=f"{KEY_PREFIX}{section}:{row.key}",
    )


# ---------------------------------------------------------------------------
# widgets
# ---------------------------------------------------------------------------


class LensSection(DataTable):
    """One foldable section: a row-cursor table titled on its top border."""

    DEFAULT_CSS = """
    LensSection {
        height: auto;
        max-height: 60vh;
        margin: 0;
        border: none;
        border-top: solid #1f2d4d;
        border-title-color: #7dd3fc;
        border-title-style: bold;
        background: #050811;
        scrollbar-size-vertical: 1;
    }
    LensSection:focus {
        border-top: heavy #38bdf8;
    }
    LensSection.-folded {
        height: 1;
        max-height: 1;
        overflow-y: hidden;
    }
    LensSection > .datatable--header {
        background: #050811;
        color: #5b6479;
        text-style: none;
    }
    LensSection > .datatable--cursor {
        background: #0b1628;
        text-style: none;
    }
    LensSection:focus > .datatable--cursor {
        background: #1d3557;
    }
    """

    def __init__(self, section_id: str) -> None:
        super().__init__(
            id=f"app-sec-{section_id}",
            cursor_type="row",
            zebra_stripes=False,
            classes="app-section",
        )
        self.section_id = section_id
        self.folded = False
        self.data: SectionData | None = None
        self.rows_shown: list[Row] = []
        self._signature: tuple | None = None
        self._shape: tuple | None = None
        self._column_keys: list[Any] = []
        self._summary = ""
        self._filter_text = ""
        #: The section's hidden rows (``SectionData.hidden_rows``) are shown.
        self.expanded = False
        self.cell_padding = 1

    def toggle_expanded(self) -> None:
        """Show / hide the section's hidden rows (the "+N" row).

        The cursor goes to the first revealed row, or back to the "+N" row.
        """
        data = self.data
        self.expanded = not self.expanded
        if data is None:
            return
        self.show(data, self._filter_text)
        target = (
            data.hidden_rows[0].key if self.expanded and data.hidden_rows else MORE_KEY
        )
        for index, row in enumerate(self.rows_shown):
            if row.key == target:
                self.move_cursor(row=index, animate=False)
                break

    def set_folded(self, folded: bool) -> None:
        self.folded = folded
        self.set_class(folded, "-folded")
        self._update_title()

    def _update_title(self) -> None:
        arrow = "▸" if self.folded else "▾"
        title = SECTION_TITLES.get(self.section_id, self.section_id)
        summary = f" · {self._summary}" if self._summary else ""
        self.border_title = Text(f"{arrow} {title}{summary}")

    def _visible_rows(self, data: SectionData, filter_text: str) -> list[Row]:
        """Rows to show: matching ones while filtering (hidden rows too),
        else the rows plus a "+N" (or "hide") row for the hidden ones.
        """
        needle = filter_text.lower()
        hidden = data.hidden_rows
        if needle:
            rows = [
                r
                for r in [*data.rows, *hidden]
                if r.inspectable and needle in r.text.lower()
            ] or [
                _placeholder(
                    "nomatch", f"no rows match “{filter_text}”", len(data.columns)
                )
            ]
            total = sum(1 for r in [*data.rows, *hidden] if r.inspectable)
            shown = sum(1 for r in rows if r.inspectable)
            self._summary = f"{shown} of {total} · {data.summary}"
            return rows
        self._summary = data.summary
        if not hidden:
            return list(data.rows)
        width = len(data.columns)
        if self.expanded:
            toggle = _placeholder(
                LESS_KEY[1:], f"− hide the {len(hidden)} {data.hidden_label} (z)", width
            )
            return [*data.rows, *hidden, toggle]
        toggle = _placeholder(
            MORE_KEY[1:],
            f"+{len(hidden)} {data.hidden_label} — z shows them, / filters",
            width,
        )
        return [*data.rows, toggle]

    def show(self, data: SectionData, filter_text: str = "") -> None:
        """Render ``data`` (rows matching ``filter_text``); keeps the cursor."""
        self.data = data
        self._filter_text = filter_text
        rows = self._visible_rows(data, filter_text)
        self._update_title()
        signature = (
            data.columns,
            data.show_header,
            tuple((r.key, r.text) for r in rows),
        )
        if signature == self._signature:
            # Same text; refresh the renderables (styles) only via rows_shown.
            self.rows_shown = rows
            return
        shape = (data.columns, data.show_header, tuple(r.key for r in rows))
        old_rows = self.rows_shown
        self._signature = signature
        if shape == self._shape and len(old_rows) == len(rows):
            # Same columns and rows (e.g. "5m ago" -> "5m ago" + 10 s): update
            # the changed cells in place; cursor and scroll stay put.
            self._update_cells(old_rows, rows)
            self.rows_shown = rows
            return
        self._shape = shape
        cursor_key = self.cursor_key()
        scroll_x, scroll_y = self.scroll_x, self.scroll_y
        self.show_header = data.show_header
        self.clear(columns=True)
        self._column_keys = list(self.add_columns(*data.columns))
        for row in rows:
            self.add_row(*row.cells, key=row.key)
        self.rows_shown = rows
        if cursor_key is not None:
            for index, row in enumerate(rows):
                if row.key == cursor_key:
                    self.move_cursor(row=index, animate=False, scroll=False)
                    break
        if scroll_x or scroll_y:
            # clear() scrolled home; put the view back once the new virtual
            # size is known (rows added or removed: clamped to the new end).
            self.call_after_refresh(self._restore_scroll, scroll_x, scroll_y)

    def _restore_scroll(self, x: float, y: float) -> None:
        self.scroll_to(x=x, y=y, animate=False)

    def _update_cells(self, old_rows: list[Row], rows: list[Row]) -> None:
        for old, new in zip(old_rows, rows, strict=True):
            if old.text == new.text and old.cells == new.cells:
                continue
            for column, (before, after) in enumerate(
                zip(old.cells, new.cells, strict=True)
            ):
                if before == after or column >= len(self._column_keys):
                    continue
                try:
                    self.update_cell(
                        new.key, self._column_keys[column], after, update_width=True
                    )
                except Exception:
                    logger.debug("update_cell failed", exc_info=True)

    def cursor_key(self) -> str | None:
        rows = self.rows_shown
        if not rows:
            return None
        index = self.cursor_row
        if 0 <= index < len(rows):
            return rows[index].key
        return None

    def cursor_item(self) -> Row | None:
        key = self.cursor_key()
        return next((r for r in self.rows_shown if r.key == key), None)

    def row_by_key(self, key: str) -> Row | None:
        data = self.data
        if data is None:
            return None
        return next((r for r in [*data.rows, *data.hidden_rows] if r.key == key), None)


class AppLensSections(Vertical):
    """The App lens's seven sections and the off-thread data behind them."""

    DEFAULT_CSS = """
    AppLensSections {
        height: auto;
        padding: 0 0 1 0;
    }
    AppLensSections.-hidden {
        display: none;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs["classes"] = (kwargs.get("classes", "") + " -hidden").strip()
        super().__init__(**kwargs)
        self._ui = UiDispatcher()
        self.facts: AppFacts | None = None
        self._gen = 0
        self._serial: str | None = None
        self._rid = 0
        self._applied: dict[str, int] = {}
        self._runtime_rid: int | None = None
        self._pending: set[str] = set()
        self._explicit: set[str] = set()
        self._last_runtime = 0.0
        self._trail_timer: Any = None
        self._stale = False
        self._filter = ""
        self._last_section: str | None = None
        self._poll_timer: Any = None
        self._folded: set[str] = set()
        self._footprint_inflight: tuple[tuple[str | None, int], int] | None = None

    # -- compose ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        for section_id, _title in SECTIONS:
            yield LensSection(section_id)

    def on_mount(self) -> None:
        if not self._ui.bound:
            self._ui = UiDispatcher.capture()
        try:
            self._poll_timer = self.set_interval(RUNTIME_MIN_INTERVAL, self._poll_tick)
        except Exception:
            self._poll_timer = None

    def on_unmount(self) -> None:
        for timer in (self._poll_timer, self._trail_timer):
            if timer is not None:
                try:
                    timer.stop()
                except Exception:
                    pass
        self._poll_timer = self._trail_timer = None

    # -- accessors ---------------------------------------------------------

    def sections(self) -> list[LensSection]:
        return list(self.query(LensSection))

    def section(self, section_id: str) -> LensSection | None:
        try:
            return self.query_one(f"#app-sec-{section_id}", LensSection)
        except Exception:
            return None

    @property
    def package(self) -> str | None:
        return self.facts.package if self.facts is not None else None

    def _token(self) -> tuple[str | None, int]:
        return (self.package, self._gen)

    def current_section(self) -> LensSection | None:
        """The focused section, else the last one that had focus."""
        try:
            focused = self.screen.focused
        except Exception:
            focused = None
        if isinstance(focused, LensSection) and focused.parent is self:
            return focused
        if self._last_section:
            return self.section(self._last_section)
        return None

    def on_descendant_focus(self, event: Any) -> None:
        widget = getattr(event, "widget", None)
        if isinstance(widget, LensSection):
            self._last_section = widget.section_id

    # -- tracking ----------------------------------------------------------

    def track(self, package: str | None, pid: int | None = None) -> None:
        """Show ``package`` (UI thread). A new app or device reloads all."""
        serial = active_serial() if package else None
        if package == self.package and serial == self._serial:
            if self.facts is not None and pid != self.facts.pid:
                self.facts.pid = pid
                self.note_state_changed()  # restarted / died: grants may change
                self._render_sections(("identity",))
            return
        self._gen += 1
        self._serial = serial
        self._applied = {}
        self._pending = set()
        self._explicit = set()
        self._runtime_rid = None
        self._footprint_inflight = None
        self._stale = False
        if not package:
            self.facts = None
            self.set_class(True, "-hidden")
            return
        self.facts = AppFacts(package=package, pid=pid)
        self.set_class(False, "-hidden")
        self._render_sections()
        self._start_full_load()

    def _next_rid(self) -> int:
        self._rid += 1
        return self._rid

    @property
    def _runtime_inflight(self) -> bool:
        """A runtime fetch (full load or refresh) of this generation runs."""
        return self._runtime_rid is not None

    def _start_full_load(self) -> None:
        token = self._token()
        package, serial = token[0], self._serial
        if package is None:
            return
        rid = self._next_rid()
        self._runtime_rid = rid
        self._last_runtime = time.monotonic()

        def work() -> None:
            post = self._ui.post
            svc = make_service(serial)
            details = svc.details(package)
            post(self._apply, token, rid, {"details": details})
            # The footprint (own worker, can take a minute) reuses the
            # dataDir dumpsys just printed: one adb call less.
            post(self._start_footprint_for, token, _data_dir_of(details))
            static = svc.static_overview(package, allow_pull=False)
            cached = getattr(static, "overview", None) is not None
            # Only a plain cache miss is worth a pull (not a failed hash).
            pull = not cached and getattr(static, "reason", None) == "not cached yet"
            state = "ready" if cached else ("analysing" if pull else "missing")
            post(
                self._apply,
                token,
                rid,
                {
                    "static": static,
                    "defences": svc.defences(static) if cached else [],
                    "static_state": state,
                },
            )
            overview = getattr(static, "overview", None)
            post(
                self._apply,
                token,
                rid,
                {"permissions": svc.permissions(package, overview)},
            )
            post(self._apply, token, rid, {"appops": svc.appops(package)})
            post(self._apply, token, rid, {"services": svc.services(package)})
            post(self._runtime_done, token, rid)
            if not pull:
                return
            pulled = svc.static_overview(package, allow_pull=True)
            ok = getattr(pulled, "overview", None) is not None
            post(
                self._apply,
                token,
                rid,
                {
                    "static": pulled,
                    "defences": svc.defences(pulled) if ok else [],
                    "static_state": "ready" if ok else "missing",
                },
            )

        self._run(
            work, "app-lens-load", functools.partial(self._runtime_done, token, rid)
        )

    def _start_footprint_for(
        self, token: tuple[str | None, int], data_dir: str | None
    ) -> None:
        if token == self._token():
            self._start_footprint(data_dir)

    def _start_footprint(self, data_dir: str | None = None) -> None:
        """``du`` of the data dirs: own worker (it can take a minute)."""
        token = self._token()
        package, serial = token[0], self._serial
        if package is None:
            return
        if self._footprint_inflight is not None and (
            self._footprint_inflight[0] == token
        ):
            return
        if data_dir is None and self.facts is not None:
            data_dir = _data_dir_of(self.facts.details)
        rid = self._next_rid()
        self._footprint_inflight = (token, rid)

        def work() -> None:
            footprint = make_service(serial).footprint(package, data_dir=data_dir)
            self._ui.post(self._apply, token, rid, {"footprint": footprint})
            self._ui.post(self._footprint_done, token, rid)

        self._run(
            work,
            "app-lens-footprint",
            functools.partial(self._footprint_done, token, rid),
        )

    def _footprint_done(self, token: tuple[str | None, int], rid: int) -> None:
        if self._footprint_inflight == (token, rid):
            self._footprint_inflight = None

    def _run(
        self, work: Callable[[], None], name: str, on_fail: Callable[[], None]
    ) -> None:
        """Run ``work`` in a thread worker; ``on_fail`` (UI thread) if it raises.

        ``on_fail`` carries the worker's own token / request id, so a failed
        worker only clears its own in-flight flag, never a newer one's.
        """
        if not self._ui.bound:
            self._ui = UiDispatcher.capture()  # UI thread: bind before posting

        def guarded() -> None:
            try:
                work()
            except Exception:
                logger.debug("%s worker failed", name, exc_info=True)
                self._ui.post(on_fail)

        try:
            self.run_worker(guarded, name=name, thread=True, exclusive=False)
        except Exception:
            logger.debug("could not start %s", name, exc_info=True)
            on_fail()

    # -- runtime refresh ---------------------------------------------------

    def refresh_runtime(
        self,
        kinds: Iterable[str] = RUNTIME_KINDS,
        *,
        throttle: bool = False,
        static: bool = False,
        explicit: bool = False,
    ) -> bool:
        """Re-fetch runtime facts off-thread. Returns False if nothing ran now.

        ``throttle``: at most one fetch per :data:`RUNTIME_MIN_INTERVAL`
        seconds; a request inside that window runs once at its end.
        ``static``: also re-read the static cache (Insight may have run).
        ``explicit``: the user asked (``u``) -- never throttled; while a
        fetch is in flight it runs right after that one, not 10 s later.
        """
        if self.facts is None:
            return False
        wanted = set(kinds) | ({"static_cache"} if static else set())
        now = time.monotonic()
        if throttle:
            wait = self._last_runtime + RUNTIME_MIN_INTERVAL - now
            if wait > 0:
                self._pending |= wanted
                if self._trail_timer is None:
                    try:
                        self._trail_timer = self.set_timer(wait, self._fire_trailing)
                    except Exception:
                        self._trail_timer = None
                return False
        if self._runtime_inflight:
            if explicit:
                self._explicit |= wanted
            else:
                self._pending |= wanted
            return False
        self._start_runtime(wanted)
        return True

    def _fire_trailing(self) -> None:
        self._trail_timer = None
        kinds, self._pending = self._pending, set()
        if not kinds or self.facts is None:
            return
        if not is_shown(self):
            self._stale = True
            return
        if self._runtime_inflight:
            self._pending |= kinds
            return
        self._start_runtime(kinds)

    def _start_runtime(self, kinds: set[str]) -> None:
        token = self._token()
        package, serial = token[0], self._serial
        if package is None:
            return
        if "footprint" in kinds:
            kinds = kinds - {"footprint"}
            self._start_footprint()
        rid = self._next_rid()
        self._runtime_rid = rid
        self._last_runtime = time.monotonic()
        overview = _overview(self.facts) if self.facts else {}

        def work() -> None:
            post = self._ui.post
            svc = make_service(serial)
            if "static_cache" in kinds:
                static = svc.static_overview(package, allow_pull=False)
                if getattr(static, "overview", None) is not None:
                    post(
                        self._apply,
                        token,
                        rid,
                        {
                            "static": static,
                            "defences": svc.defences(static),
                            "static_state": "ready",
                        },
                    )
            fetch = {
                "details": lambda: svc.details(package),
                "permissions": lambda: svc.permissions(package, overview or None),
                "appops": lambda: svc.appops(package),
                "services": lambda: svc.services(package),
            }
            for kind in RUNTIME_KINDS:
                if kind in kinds and kind in fetch:
                    post(self._apply, token, rid, {kind: fetch[kind]()})
            post(self._runtime_done, token, rid)

        self._run(
            work, "app-lens-refresh", functools.partial(self._runtime_done, token, rid)
        )

    def _runtime_done(self, token: tuple[str | None, int], rid: int) -> None:
        """A runtime fetch ended (or failed): clear only its own flag."""
        if token != self._token() or self._runtime_rid != rid:
            return
        self._runtime_rid = None
        if self._explicit:
            kinds, self._explicit = self._explicit | self._pending, set()
            self._pending = set()
            self.refresh_runtime(kinds, throttle=False)
        elif self._pending:
            kinds, self._pending = self._pending, set()
            self.refresh_runtime(kinds, throttle=True)

    def static_analysis_finished(self) -> None:
        """Static analysis (``a``) recorded Insight results: re-read the cache."""
        if self.facts is None:
            return
        if not is_shown(self):
            self._stale = True  # on_lens_activated re-reads (no insight yet)
            return
        self.refresh_runtime((), static=True, explicit=True)

    def note_state_changed(self) -> None:
        """STATE_CHANGED (or a new PID): refresh grants/AppOps/services."""
        if self.facts is None:
            return
        if not is_shown(self):
            self._stale = True
            return
        self.refresh_runtime(EVENT_KINDS, throttle=True)

    def on_lens_activated(self) -> None:
        """The App lens became visible: catch up if stale."""
        if self.facts is None:
            return
        age = time.monotonic() - self._last_runtime
        # Static analysis may have finished elsewhere: no Insight yet means
        # the TRACKERS section still says "press a" -- re-read the cache.
        static = self._insight_missing()
        if self._stale or age >= RUNTIME_MIN_INTERVAL:
            self._stale = False
            self.refresh_runtime(EVENT_KINDS, static=static, explicit=static)
        elif static:
            self.refresh_runtime((), static=True, explicit=True)

    def _insight_missing(self) -> bool:
        facts = self.facts
        if facts is None or facts.static_state in ("checking", "analysing"):
            return False
        return not getattr(facts.static, "insight", None)

    def _poll_tick(self) -> None:
        """AppOps poll: only while visible, at most every 10 s."""
        facts = self.facts
        if facts is None or self._runtime_inflight or not is_shown(self):
            return
        if time.monotonic() - max(facts.appops_at, self._last_runtime) < (
            RUNTIME_MIN_INTERVAL - 0.5
        ):
            return
        self._start_runtime({"appops"})

    # -- applying results (UI thread) --------------------------------------

    def _apply(
        self, token: tuple[str | None, int], rid: int, updates: dict[str, Any]
    ) -> None:
        if token != self._token() or self.facts is None:
            return  # a result for a previous app / device
        facts = self.facts
        had_overview = bool(_overview(facts))
        changed: set[str] = set()
        for kind, value in updates.items():
            if rid < self._applied.get(kind, -1):
                continue  # an older request; a newer one already landed
            self._applied[kind] = rid
            setattr(facts, kind, value)
            changed.add(kind)
            if kind == "appops":
                facts.appops_at = time.monotonic()
        if changed:
            self._render_sections(_affected(changed))
        if "static" in changed and not had_overview and _overview(facts):
            # The APK was just decoded: re-read grants with the manifest's
            # protection levels (dumpsys lacks them for app-defined ones).
            self.refresh_runtime(("permissions",))

    # -- rendering ---------------------------------------------------------

    def set_filter(self, text: str) -> None:
        self._filter = (text or "").strip()
        self._render_sections()

    @property
    def filter_text(self) -> str:
        return self._filter

    def _render_sections(self, section_ids: Iterable[str] | None = None) -> None:
        facts = self.facts
        if facts is None:
            return
        wanted = set(section_ids) if section_ids is not None else set(BUILDERS)
        for section_id, builder in BUILDERS.items():
            if section_id not in wanted:
                continue
            widget = self.section(section_id)
            if widget is None:
                continue
            try:
                data = builder(facts)
            except Exception as exc:
                logger.debug("App lens section %s failed", section_id, exc_info=True)
                data = SectionData(
                    ("",),
                    [_placeholder("error", f"could not render: {exc}", 1, _BAD)],
                    "error",
                )
            widget.show(data, self._filter)
            if section_id in self._folded and not widget.folded:
                widget.set_folded(True)
        self._refresh_open_inspector()

    def _refresh_open_inspector(self) -> None:
        """Keep an open Inspector page of one of our rows current."""
        try:
            screen = self.screen
            content = screen.inspector_content
            if not screen.inspector_is_open or content is None:
                return
        except Exception:
            return
        key = content.key
        if content.lens != LENS_ID or not isinstance(key, str):
            return
        if not key.startswith(KEY_PREFIX):
            return
        section_id, _, row_key = key[len(KEY_PREFIX) :].partition(":")
        widget = self.section(section_id)
        row = widget.row_by_key(row_key) if widget is not None else None
        if row is None or not row.inspectable:
            return
        new = row_content(section_id, row)
        try:
            screen.update_inspector(new)
        except Exception:
            pass

    # -- keys (called by the panel) ----------------------------------------

    def toggle_fold(self) -> LensSection | None:
        widget = self.current_section()
        if widget is None:
            sections = self.sections()
            widget = sections[0] if sections else None
        if widget is None:
            return None
        if not widget.folded and widget.cursor_key() in (MORE_KEY, LESS_KEY):
            widget.toggle_expanded()  # z on "+N other ops": show / hide them
            return widget
        widget.set_folded(not widget.folded)
        if widget.folded:
            self._folded.add(widget.section_id)
        else:
            self._folded.discard(widget.section_id)
        return widget

    def inspect_selected(self) -> InspectorContent | None:
        widget = self.current_section()
        if widget is None:
            return None
        row = widget.cursor_item()
        if row is not None and row.key in (MORE_KEY, LESS_KEY):
            widget.toggle_expanded()  # ⏎ on "+N other ops" shows them
            return None
        if row is None or not row.inspectable:
            return None
        return row_content(widget.section_id, row)

    def focus_first(self) -> bool:
        """Focus the last-used (or first) section. False if none is shown."""
        if self.facts is None or not is_shown(self):
            return False
        widget = self.current_section() or (self.sections() or [None])[0]
        if widget is None:
            return False
        widget.focus()
        return True


def _data_dir_of(details: Any) -> str | None:
    """``dataDir`` from a ``details`` Fact (``None`` when unknown)."""
    value = getattr(details, "value", None) if details is not None else None
    data_dir = value.get("data_dir") if isinstance(value, dict) else None
    return str(data_dir) if data_dir else None


def _affected(kinds: set[str]) -> set[str]:
    """Sections that show the given fact kinds."""
    out: set[str] = set()
    for kind in kinds:
        out |= {
            "details": {"identity"},
            "permissions": {"permissions"},
            "appops": {"permissions"},
            "services": {"identity"},
            "footprint": {"data"},
            "static": set(BUILDERS),
            "defences": {"defences", "manifest"},
            "static_state": set(BUILDERS),
            "pid": {"identity"},
        }.get(kind, set(BUILDERS))
    return out


__all__ = [
    "ANALYSIS_HINT",
    "AppFacts",
    "AppLensSections",
    "LensSection",
    "Row",
    "SectionData",
    "build_data",
    "build_defences",
    "build_exposure",
    "build_identity",
    "build_manifest",
    "build_permissions",
    "build_trackers",
    "row_content",
]
