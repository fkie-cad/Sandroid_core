"""Identity lens (lens 6): the identity profile and where its values went.

The lens shows the active identity profile (:mod:`sandroid.services.identity`)
as one table, grouped into Identifiers / Telephony / Place & language /
Personal data. Each row is one seeded value::

    Value           Status    Found         Profile value  Device now  Via ...
    Advertising ID  verified  3 recipients  3b9f...        3b9f...     native

**Found** comes from the privacy scan
(:mod:`sandroid.services.privacy_scan`): plain words (``3 recipients``,
``stored on device``, ``sent and stored``) or a dim ``not seen``. A value
that was found gets a subtle warn tint on its row.

**Inspector** (Enter): a *Found* tab (the default when there are hits) lists
the value's hits grouped by recipient (flows) or file (pulled files), each
in words: time, recipient and party, where, how it was encoded, confidence
and the snippet with the matched part highlighted. ``{`` / ``}`` move the
selected hit, ``J`` jumps to its source (Network, Files or Timeline lens).
The *Value* tab holds the profile value, markers, apply mechanism, the
permission an app needs, the status and the value before the apply.

Keys (lens-local): ``space`` apply, ``e`` edit value, ``v`` verify,
``R`` regenerate, ``P`` profiles, ``I`` import, ``X`` export, ``M`` mode
on/off, ``J`` jump, ``/`` filter.

Threading: every device call (plan / apply / verify) and the profile read
on activation run in a thread worker; results come back through a
:class:`UiDispatcher`. The services'
listeners (identity status, privacy hits) fire on worker threads: they only
mark the lens dirty and post one refresh, which runs at most once per
second. Rows keep their order and the cursor stays on its value when data
changes.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Label, Static

from sandroid.tui.modals.base import KeyHintFooter
from sandroid.tui.modals.input_modal import InputModal
from sandroid.tui.themes import lens_palette
from sandroid.tui.utils.ui_thread import UiDispatcher
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

LENS_ID = "identity"
#: Prefix of every Inspector key this lens opens.
KEY_PREFIX = "identity:"
#: Minimum seconds between two table refreshes caused by live updates.
REFRESH_MIN_S = 1.0
#: Seconds before the lens's own device read is tried again after a device
#: that did not answer (offline, still booting) or a failed read.
AUTO_READ_RETRY_S = 30.0
#: Row key prefix of the section header rows.
SECTION_PREFIX = "_sec:"
#: Longest profile / device value shown in a cell.
CELL_WIDTH = 30

SECTIONS: tuple[str, ...] = (
    "Identifiers",
    "Telephony",
    "Place & language",
    "Personal data",
)
_SECTION_OF: dict[str, str] = {
    **dict.fromkeys(
        ("android_id", "gaid", "app_set_id", "device_name", "build_model", "serial"),
        "Identifiers",
    ),
    **dict.fromkeys(
        ("phone_number", "sim_operator", "sim_mccmnc", "imei", "imsi", "iccid"),
        "Telephony",
    ),
    **dict.fromkeys(("gps", "timezone", "locale"), "Place & language"),
    **dict.fromkeys(
        ("account", "clipboard", "contacts", "sms", "calls"), "Personal data"
    ),
}
LIST_IDS = ("contacts", "sms", "calls")

STATUS_WORDS = {
    "verified": "verified",
    "applied": "applied",
    "pending": "pending",
    "failed": "failed",
    "hook-only": "hook only",
    "skipped": "skipped",
}
RESTART_WORDS = {"none": "none", "gms": "Play services", "framework": "framework"}

#: Status and Found come right after the label: with the Inspector open the
#: lens is ~90 columns wide and the columns after them scroll off.
COLUMNS: tuple[tuple[str, str], ...] = (
    ("value", "Value"),
    ("status", "Status"),
    ("found", "Found"),
    ("profile", "Profile value"),
    ("device", "Device now"),
    ("via", "Via"),
    ("restart", "Restart"),
)


# ---------------------------------------------------------------------------
# services (looked up per call, so tests can patch the getters)
# ---------------------------------------------------------------------------


def identity_service() -> Any | None:
    """The identity service, or None when it cannot be built."""
    try:
        from sandroid.services import identity as mod

        return mod.get_identity_service()
    except Exception:
        logger.debug("identity lens: no identity service", exc_info=True)
        return None


def privacy_service() -> Any | None:
    """The privacy scan service, or None when it cannot be built."""
    try:
        from sandroid.services import privacy_scan as mod

        return mod.get_privacy_scan_service()
    except Exception:
        logger.debug("identity lens: no privacy scan service", exc_info=True)
        return None


def _spotlight() -> Any | None:
    try:
        from sandroid.services import get_spotlight_service

        return get_spotlight_service()
    except Exception:
        return None


def _target_serial() -> str | None:
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# apply state (the header's "PRIVACY applying")
# ---------------------------------------------------------------------------

_applying_lock = threading.Lock()
_applying = 0


def _set_applying(on: bool) -> None:
    global _applying
    with _applying_lock:
        _applying = max(0, _applying + (1 if on else -1))


def apply_in_progress() -> bool:
    """True while an apply started from the Identity lens runs (O(1))."""
    return _applying > 0


def privacy_indicator() -> tuple[str | None, str]:
    """``(text, kind)`` for the header's privacy piece (no I/O).

    ``kind`` is ``"applying"``, ``"found"`` or ``""``; ``text`` None hides the
    piece (no profile applied / scan inactive).
    """
    if apply_in_progress():
        return "PRIVACY applying", "applying"
    service = privacy_service()
    if service is None:
        return None, ""
    try:
        summary = service.summary()
    except Exception:
        return None, ""
    if not getattr(summary, "active", False):
        return None, ""
    found = int(getattr(summary, "values_found", 0) or 0)
    total = int(getattr(summary, "values_total", 0) or 0)
    if found > 0:
        return f"PRIVACY {found}/{total} found", "found"
    profile_id = ""
    ident = identity_service()
    if ident is not None:
        try:
            profile_id = str(ident.config().profile or "")
        except Exception:
            profile_id = ""
    return (f"PRIVACY {profile_id}" if profile_id else "PRIVACY on"), ""


# ---------------------------------------------------------------------------
# pure helpers (words)
# ---------------------------------------------------------------------------


def row_id_for_marker(marker_id: str) -> str:
    """The lens row of a marker: ``android_id@pkg`` -> ``android_id``,
    ``gps.latitude`` -> ``gps``, ``contacts.0.name`` -> ``contacts``.
    """
    return marker_id.split("@", 1)[0].split(".", 1)[0]


def section_of(kind: str) -> str:
    return _SECTION_OF.get(kind, "Identifiers")


def _clip(text: str, width: int = CELL_WIDTH) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _split_call(transform: str) -> tuple[str, list[str]] | None:
    """``sha256(lower(value))`` -> ``("sha256", ["lower(value)"])``."""
    transform = transform.strip()
    if not transform.endswith(")") or "(" not in transform:
        return None
    name, _, rest = transform.partition("(")
    inner = rest[:-1]
    args: list[str] = []
    depth = 0
    current = ""
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
            continue
        current += ch
    args.append(current.strip())
    return name.strip(), args


_ENCODINGS = {
    "utf16": "UTF-16 of",
    "hex": "hex of",
    "url": "URL-encoded",
    "base64": "base64 of",
    "base64url": "base64url of",
}
_SUFFIXES = {
    "strip_dashes": " without dashes",
    "strip_separators": " without separators",
    "dashes": " with dashes",
    "colons": " with colons",
    "intl_00": " with a 00 prefix",
}


def _phrase(transform: str) -> str:
    """A noun phrase for ``transform``: ``the lower-case value``."""
    if transform == "value":
        return "the value"
    call = _split_call(transform)
    if call is None:
        return transform
    name, args = call
    inner = _phrase(args[0]) if args else "the value"
    if name in ("lower", "upper"):
        case = "lower-case" if name == "lower" else "upper-case"
        return inner.replace("the ", f"the {case} ", 1)
    if name in _SUFFIXES:
        return inner + _SUFFIXES[name]
    if name == "digits":
        return f"the digits of {inner}"
    if name == "bytes":
        return f"the raw bytes of {inner}"
    if name in ("round", "truncate"):
        places = args[1] if len(args) > 1 else "?"
        verb = "rounded" if name == "round" else "cut"
        return f"{inner} {verb} to {places} decimals"
    if name == "e7":
        return f"{inner} times 10 million"
    if name in ("double_le", "double_be"):
        size = "float" if name.startswith("float") else "double"
        return f"{inner} as a binary {size}"
    if name == "url":
        return inner.replace("the ", "the URL-encoded ", 1)
    if name in _ENCODINGS:
        return f"{_ENCODINGS[name]} {inner}"
    return f"{name} of {inner}"


def describe_transform(transform: str) -> str:
    """How a value was encoded, in words.

    ``value`` -> ``as is``; ``sha256(lower(value))`` -> ``sha256 of the
    lower-case value``; ``round(value, 4)`` -> ``rounded to 4 decimals``.
    """
    transform = (transform or "value").strip()
    if transform == "value":
        return "as is"
    phrase = _phrase(transform)
    if phrase.startswith("the value "):
        return phrase[len("the value ") :]
    return phrase


def part_words(part: str) -> str:
    """``req.body`` -> ``request body``; ``url`` -> ``in the URL``."""
    if part == "url":
        return "in the URL"
    head, _, name = part.partition(":")
    if head == "file":
        return f"in {name}" if name else "in the file"
    side = {"req": "request", "resp": "response"}.get(head.split(".")[0], head)
    what = head.split(".", 1)[1] if "." in head else ""
    text = f"{side} {what}".strip()
    return f"{text} {name}" if name else text


def party_word(hit: Any) -> tuple[str, str]:
    """``(word, palette token)`` for the hit's recipient."""
    if getattr(hit, "direction", "") == "stored":
        return "on device", "muted"
    party = ((getattr(hit, "recipient", None) or {}).get("party")) or "unknown"
    if party == "third":
        return "third party", "warn"
    if party == "first":
        return "first party", "accent"
    return "unknown party", "dim"


def recipient_name(hit: Any) -> str:
    rec = getattr(hit, "recipient", None) or {}
    src = getattr(hit, "source", None) or {}
    return str(rec.get("label") or rec.get("domain") or src.get("host") or "unknown")


@dataclass
class Found:
    """The privacy scan's hits for one lens row."""

    hits: list[Any] = field(default_factory=list)

    @property
    def recipients(self) -> set[str]:
        return {recipient_name(h) for h in self.hits if h.direction == "sent"}

    @property
    def stored(self) -> bool:
        return any(h.direction == "stored" for h in self.hits)

    @property
    def received(self) -> bool:
        return any(h.direction == "received" for h in self.hits)

    def words(self) -> str:
        """``3 recipients`` / ``stored on device`` / ``sent and stored`` /
        ``received`` / ``not seen``.
        """
        n = len(self.recipients)
        if n and self.stored:
            return "sent and stored"
        if n:
            return f"{n} recipient{'s' if n != 1 else ''}"
        if self.stored:
            return "stored on device"
        if self.received:
            return "received"
        return "not seen"


def group_hits(hits: Iterable[Any]) -> dict[str, list[Any]]:
    """Hits by lens row id (see :func:`row_id_for_marker`)."""
    out: dict[str, list[Any]] = {}
    for hit in hits:
        out.setdefault(row_id_for_marker(hit.marker_id), []).append(hit)
    return out


def _hit_time(hit: Any) -> float:
    t = getattr(hit, "t", None)
    return float(t if t is not None else getattr(hit, "at", 0.0) or 0.0)


def _group_key(hit: Any) -> tuple[str, str]:
    src = hit.source or {}
    if src.get("type") == "file":
        return "file", str(src.get("device_path") or "file")
    return "flow", recipient_name(hit)


def ordered_hits(hits: Iterable[Any]) -> list[tuple[tuple[str, str], list[Any]]]:
    """Hits grouped by recipient / file; groups and entries by time."""
    groups: dict[tuple[str, str], list[Any]] = {}
    for hit in sorted(hits, key=_hit_time):
        groups.setdefault(_group_key(hit), []).append(hit)
    return list(groups.items())


def flat_hits(hits: Iterable[Any]) -> list[Any]:
    """The hits in Inspector order (the ``{`` / ``}`` selection order)."""
    return [h for _key, group in ordered_hits(hits) for h in group]


def where_words(hit: Any) -> str:
    """``POST t.appsflyer.com/api/v1/…, request body`` or the file."""
    src = hit.source or {}
    if src.get("type") == "file":
        path = str(src.get("device_path") or "")
        member = str(src.get("member") or "")
        bits = [member or path.rsplit("/", 1)[-1]]
        if src.get("version"):
            bits.append(f"version {src['version']}")
        return ", ".join(b for b in bits if b)
    target = f"{src.get('host') or ''}{src.get('path') or ''}"
    method = str(src.get("method") or "").upper()
    head = _clip(f"{method} {target}".strip(), 56)
    return f"{head}, {part_words(hit.part)}"


# ---------------------------------------------------------------------------
# the value edit modal (InputModal with inline validation)
# ---------------------------------------------------------------------------


class ValueEditModal(InputModal):
    """An :class:`InputModal` that validates before it closes.

    ``validate(text) -> error | None``; an error is shown under the input and
    the dialog stays open.
    """

    DEFAULT_CSS = """
    ValueEditModal #edit-error {
        color: $error;
        height: auto;
        padding-top: 1;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        default: str,
        validate: Callable[[str], str | None],
    ) -> None:
        super().__init__(title=title, message=message, default=default)
        self._validate = validate

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")
            yield Input(
                value=self.default,
                placeholder=self.placeholder,
                id="input-field",
                classes="no-compact",
            )
            yield Label("", id="edit-error")
            with Horizontal(classes="button-row"):
                yield Button("Save", id="submit", classes="-primary")
                yield Button("Cancel", id="cancel", classes="-secondary")
            yield KeyHintFooter()

    def _submit(self) -> None:
        value = self.query_one("#input-field", Input).value
        try:
            error = self._validate(value)
        except Exception as exc:
            error = str(exc)
        if error:
            self.query_one("#edit-error", Label).update(Text(error))
            return
        self._dismiss_with_refresh(value)


# ---------------------------------------------------------------------------
# table
# ---------------------------------------------------------------------------


class IdentityTable(DataTable):
    """The value table: section rows, a warn tint on values that were found."""

    COMPONENT_CLASSES = DataTable.COMPONENT_CLASSES | {
        "identity--found",
        "identity--section",
    }

    DEFAULT_CSS = """
    IdentityTable {
        height: 1fr;
        background: $lens-bg;
        color: $lens-text;
        scrollbar-size-vertical: 1;
    }
    IdentityTable > .datatable--header {
        background: $lens-bg;
        color: $lens-header;
        text-style: none;
    }
    IdentityTable > .identity--found {
        background: $lens-warn 12%;
    }
    IdentityTable > .identity--section {
        background: $lens-panel;
        color: $lens-muted;
        text-style: bold;
    }
    IdentityTable > .datatable--cursor {
        background: $lens-cursor;
        text-style: none;
    }
    IdentityTable:focus > .datatable--cursor {
        background: $lens-cursor-focus;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(cursor_type="row", zebra_stripes=False, **kwargs)
        self.found_keys: set[str] = set()
        self._last_row = 0

    def _get_row_style(self, row_index: int, base_style: Any) -> Any:
        if 0 <= row_index < self.row_count:
            try:
                key = self.ordered_rows[row_index].key.value
            except Exception:
                key = None
            if isinstance(key, str):
                if key.startswith(SECTION_PREFIX):
                    return self.get_component_styles("identity--section").rich_style
                if key in self.found_keys:
                    return self.get_component_styles("identity--found").rich_style
        return super()._get_row_style(row_index, base_style)

    def current_key(self) -> str | None:
        if not self.row_count:
            return None
        try:
            key = self.coordinate_to_cell_key(self.cursor_coordinate).row_key.value
        except Exception:
            return None
        return key if isinstance(key, str) else None

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Section rows are not selectable: step over them."""
        row = event.cursor_row
        key = event.row_key.value if event.row_key is not None else None
        if isinstance(key, str) and key.startswith(SECTION_PREFIX):
            step = 1 if row >= self._last_row else -1
            target = row + step
            if not 0 <= target < self.row_count:
                target = row - step
            if 0 <= target < self.row_count and target != row:
                self._last_row = row
                self.move_cursor(row=target, animate=False)
                return
        self._last_row = row


# ---------------------------------------------------------------------------
# the lens
# ---------------------------------------------------------------------------


@dataclass
class LensRow:
    """One value row of the table."""

    id: str
    section: str
    info: Any
    found: Found


class IdentityLens(Vertical):
    """The Identity lens (id ``identity-panel``); see the module docstring."""

    can_focus = True

    BINDINGS = [
        Binding("space", "apply", "Apply", key_display="space"),
        Binding("e", "edit", "Edit value"),
        Binding("v", "verify", "Verify"),
        Binding("P", "profiles", "Profiles"),
        Binding("R", "regenerate", "Regenerate values…", show=False),
        Binding("I", "import_profile", "Import a profile…", show=False),
        Binding("X", "export_profile", "Export the profile…", show=False),
        Binding("M", "toggle_mode", "Identity mode on/off", show=False),
        Binding("J", "jump", "Jump to the selected hit's source", show=False),
        Binding("slash", "filter", "Filter rows", show=False),
    ]

    DEFAULT_CSS = """
    IdentityLens {
        height: 1fr;
        background: $lens-bg;
    }
    IdentityLens > #identity-notice {
        display: none;
        height: auto;
        padding: 0 1;
        color: $lens-warn;
        text-style: bold;
    }
    IdentityLens > #identity-notice.-shown {
        display: block;
    }
    IdentityLens > #identity-empty {
        display: none;
        height: auto;
        padding: 1 2;
        color: $lens-text;
    }
    IdentityLens.-empty > #identity-empty {
        display: block;
    }
    IdentityLens.-empty > IdentityTable {
        display: none;
    }
    IdentityLens > #identity-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: $lens-input-bg;
        color: $lens-input-text;
    }
    IdentityLens > #identity-filter:focus {
        background: $lens-input-focus-bg;
    }
    IdentityLens > #identity-filter.-shown {
        display: block;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._ui = UiDispatcher()
        self.profile: Any | None = None
        self.profile_error = ""
        self.library_count = 0
        self.rows: list[LensRow] = []
        self._statuses: dict[str, Any] = {}
        self._hits_by_row: dict[str, list[Any]] = {}
        self._hit_sel: dict[str, int] = {}
        self._filter = ""
        self._row_keys: list[str] = []
        self._cells: dict[str, tuple] = {}
        self._last_refresh = 0.0
        self._refresh_timer: Any = None
        self._post_pending = threading.Event()
        self._status_lock = threading.Lock()
        self._incoming_statuses: list[Any] | None = None
        self._listening: tuple[Any, Any] = (None, None)
        self._busy = False
        #: A profile read is running in a worker; only the newest one counts.
        self._loading = False
        self._reload_seq = 0
        #: (package, pid) of the spotlight app that ran during the last apply.
        self._stale_app: tuple[str, int] | None = None
        self._inspector_sig: tuple | None = None
        #: (serial, profile id) the lens read the device for on its own (a
        #: TUI restart starts without statuses; see _auto_read).
        self._auto_read_done: set[tuple[str, str]] = set()
        #: (serial, profile id) -> monotonic time of the next try after a
        #: failed read; a read in flight.
        self._auto_read_retry: dict[tuple[str, str], float] = {}
        self._auto_read_busy = False

    # -- compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("", id="identity-notice")
        yield Static("", id="identity-empty")
        yield Input(
            id="identity-filter",
            placeholder="filter values   enter keep   esc clear",
        )
        yield IdentityTable(id="identity-table")

    def on_mount(self) -> None:
        self._ui = UiDispatcher.capture()
        table = self.table
        for key, label in COLUMNS:
            table.add_column(label, key=key)
        self._attach_listeners()
        self.set_interval(1.0, self._tick, name="identity tick")
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            pass
        ident = identity_service()
        if ident is not None:
            try:
                self._statuses = {s.id: s for s in ident.statuses()}
            except Exception:
                self._statuses = {}
        self.reload()

    def on_unmount(self) -> None:
        ident, privacy = self._listening
        if ident is not None:
            try:
                ident.remove_status_listener(self._on_status)
            except Exception:
                pass
        if privacy is not None:
            try:
                privacy.remove_listener(self._on_hit)
            except Exception:
                pass
        self._listening = (None, None)

    def _attach_listeners(self) -> None:
        ident = identity_service()
        privacy = privacy_service()
        if ident is not None:
            try:
                ident.add_status_listener(self._on_status)
            except Exception:
                ident = None
        if privacy is not None:
            try:
                privacy.add_listener(self._on_hit)
            except Exception:
                privacy = None
        self._listening = (ident, privacy)

    @property
    def table(self) -> IdentityTable:
        return self.query_one("#identity-table", IdentityTable)

    def focus(self, scroll_visible: bool = True):
        try:
            if self.has_class("-empty"):
                return super().focus(scroll_visible)
            self.table.focus(scroll_visible)
            return self
        except Exception:
            return super().focus(scroll_visible)

    def _main_screen(self):
        screen = getattr(self, "screen", None)
        return screen if hasattr(screen, "set_lens_caption") else None

    def on_lens_activated(self) -> None:
        self.reload()

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        self._cells.clear()
        self._render_rows(force=True)

    # -- listeners (worker threads) -----------------------------------------

    def _on_status(self, statuses: list[Any]) -> None:
        with self._status_lock:
            self._incoming_statuses = list(statuses)
        self._post_refresh()

    def _on_hit(self, _record: Any) -> None:
        self._post_refresh()

    def _post_refresh(self) -> None:
        if self._post_pending.is_set():
            return
        self._post_pending.set()
        if not self._ui.post(self._refresh_from_post):
            self._post_pending.clear()

    def _refresh_from_post(self) -> None:
        self._post_pending.clear()
        self.request_refresh()

    def request_refresh(self) -> None:
        """Refresh now, or once when :data:`REFRESH_MIN_S` has passed."""
        wait = REFRESH_MIN_S - (time.monotonic() - self._last_refresh)
        if wait <= 0:
            self.refresh_data()
            return
        if self._refresh_timer is None:
            self._refresh_timer = self.set_timer(wait, self._timer_refresh)

    def _timer_refresh(self) -> None:
        self._refresh_timer = None
        self.refresh_data()

    def _tick(self) -> None:
        self._update_notice()
        self._auto_read()

    # -- data -----------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the profile (library file) in a worker, then refresh.

        The library listing, the profile file and the session's frozen
        apply record are file reads: they never run on the UI thread. The
        lens keeps showing what it has until the newest read is back.
        """
        self._reload_seq += 1
        seq = self._reload_seq
        ident = identity_service()
        if ident is None:
            self._loaded(seq, (0, None, ""))
            return
        self._loading = True
        if self.profile is None:
            self._update_empty()
        self._run_bg(
            lambda: _read_library(ident),
            lambda result: self._loaded(seq, result),
            group="identity-load",
        )

    def _loaded(self, seq: int, result: Any) -> None:
        """Apply a finished profile read (UI thread)."""
        if seq != self._reload_seq:
            return  # a newer read is on its way
        self._loading = False
        if isinstance(result, Exception):
            count, profile, error = 0, None, str(result)
        else:
            count, profile, error = result
        self.library_count, self.profile, self.profile_error = count, profile, error
        self.refresh_data()
        self._auto_read()

    def _auto_read(self) -> None:
        """Read the device once in the background when there are no statuses.

        After a TUI restart the service has no statuses yet and every value
        would show "pending" until ``v``. While the lens is shown with
        identity mode on, a device targeted and no apply running, it plans
        (one read, no writes) in a thread worker; the statuses arrive through
        the status listener. A device that does not answer publishes nothing
        and is tried again after :data:`AUTO_READ_RETRY_S` (from the lens
        tick, never a tight loop). Once per device and profile after a
        successful read, never on the UI thread.
        """
        if self._auto_read_busy or self._statuses or self.profile is None:
            return
        if not is_shown(self):
            return
        ident = identity_service()
        if ident is None:
            return
        try:
            if ident.config().mode != "profile":
                return
            running = getattr(ident, "apply_running", None)
            if running is not None and running():
                return  # the apply publishes its own statuses
        except Exception:
            return
        serial = _target_serial()
        if not serial:
            return
        key = (serial, self.profile.id)
        if key in self._auto_read_done:
            return
        if time.monotonic() < self._auto_read_retry.get(key, 0.0):
            return
        self._auto_read_busy = True

        def done(result: Any) -> None:
            self._auto_read_busy = False
            if isinstance(result, Exception):
                logger.info(f"identity lens: reading the device failed: {result}")
                self._auto_read_retry[key] = time.monotonic() + AUTO_READ_RETRY_S
                return
            self._auto_read_done.add(key)
            self._auto_read_retry.pop(key, None)
            if not self._statuses:
                self._statuses = {i.id: i for i in result.infos.values()}
                self.refresh_data()

        self._run_bg(
            lambda: ident.plan(serial, require_answer=True),
            done,
            group="identity-auto-read",
        )

    def refresh_data(self) -> None:
        """Rebuild rows from the profile, statuses and hits (UI thread)."""
        self._last_refresh = time.monotonic()
        with self._status_lock:
            incoming, self._incoming_statuses = self._incoming_statuses, None
        if incoming is not None:
            self._statuses = {s.id: s for s in incoming}
        self._hits_by_row = group_hits(self._current_hits())
        self.rows = self._build_rows()
        self._render_rows()
        self._update_empty()
        self._update_notice()
        self._update_caption()
        self._update_badge()
        self._follow_inspector()

    def _current_hits(self) -> list[Any]:
        service = privacy_service()
        if service is None:
            return []
        try:
            fp = service.summary().fingerprint
            hits = service.hits()
        except Exception:
            return []
        if fp:
            hits = [h for h in hits if getattr(h, "fp", fp) == fp]
        return list(hits)

    def _infos(self) -> list[Any]:
        profile = self.profile
        ident = identity_service()
        if profile is None or ident is None:
            return []
        try:
            infos = list(ident.describe(profile))
        except Exception:
            logger.debug("identity lens: describe failed", exc_info=True)
            return []
        out = []
        for info in infos:
            status = self._statuses.get(info.id)
            owner = getattr(status, "profile_id", "") if status is not None else ""
            if owner and owner != profile.id:
                status = None  # read for another profile: stale here
            out.append(status if status is not None else info)
        return out

    def _build_rows(self) -> list[LensRow]:
        by_section: dict[str, list[LensRow]] = {name: [] for name in SECTIONS}
        for info in self._infos():
            section = section_of(info.kind)
            by_section.setdefault(section, []).append(
                LensRow(
                    info.id,
                    section,
                    info,
                    Found(list(self._hits_by_row.get(info.id, ()))),
                )
            )
        rows: list[LensRow] = []
        for name, items in by_section.items():
            rows.extend(items)
        return rows

    def _matches(self, row: LensRow) -> bool:
        if not self._filter:
            return True
        needle = self._filter.lower()
        info = row.info
        hay = " ".join(
            str(x)
            for x in (
                info.label,
                info.id,
                info.kind,
                info.rendered,
                info.current,
                STATUS_WORDS.get(info.status, info.status),
                row.found.words(),
                row.section,
            )
        ).lower()
        return needle in hay

    # -- rendering -------------------------------------------------------------

    def _cells_for(self, row: LensRow) -> tuple:
        c = lens_palette()
        info = row.info
        if info.rendered:
            profile_value = Text(_clip(info.rendered))
        elif info.per_app:
            profile_value = Text(f"per app ({len(info.per_app)})", style=c.dim)
        else:
            profile_value = Text("per app", style=c.dim)
        current = Text(_clip(info.current)) if info.current else Text("", style=c.dim)
        status = info.status
        word = STATUS_WORDS.get(status, status)
        status_style = {
            "verified": c.ok,
            "failed": f"bold {c.bad}",
            "pending": c.dim,
            "hook-only": c.dim,
            "skipped": c.dim,
        }.get(status, c.text)
        found_words = row.found.words()
        found = Text(
            found_words,
            style=c.dim if found_words == "not seen" else f"bold {c.warn}",
        )
        return (
            Text(info.label),
            Text(word, style=status_style),
            found,
            profile_value,
            current,
            Text(info.provider, style=c.dim if info.provider == "hook" else ""),
            Text(RESTART_WORDS.get(info.restart, info.restart)),
        )

    def _section_cells(self, name: str) -> tuple:
        c = lens_palette()
        return (Text(name.upper(), style=f"bold {c.muted}"),) + tuple(
            Text("") for _ in COLUMNS[1:]
        )

    def _render_rows(self, force: bool = False) -> None:
        try:
            table = self.table
        except Exception:
            return
        shown = [r for r in self.rows if self._matches(r)]
        keys: list[str] = []
        cells: dict[str, tuple] = {}
        section = None
        for row in shown:
            if row.section != section:
                section = row.section
                skey = SECTION_PREFIX + section
                keys.append(skey)
                cells[skey] = self._section_cells(section)
            keys.append(row.id)
            cells[row.id] = self._cells_for(row)
        table.found_keys = {r.id for r in shown if r.found.hits}
        if keys != self._row_keys or force:
            current = table.current_key()
            table.clear()
            for key in keys:
                table.add_row(*cells[key], key=key)
            self._row_keys = keys
            self._cells = dict(cells)
            target = None
            if current in keys:
                target = keys.index(current)
            else:
                target = next(
                    (i for i, k in enumerate(keys) if not k.startswith(SECTION_PREFIX)),
                    None,
                )
            if target is not None:
                table._last_row = target
                table.move_cursor(row=target, animate=False)
            return
        changed = False
        for key in keys:
            new = cells[key]
            old = self._cells.get(key)
            for index, (col_key, _label) in enumerate(COLUMNS):
                if old is not None and _text_sig(old[index]) == _text_sig(new[index]):
                    continue
                try:
                    # Grow the column: it was sized for the first words
                    # ("not seen", an empty "Device now").
                    table.update_cell(key, col_key, new[index], update_width=True)
                except Exception:
                    logger.debug("identity lens: update_cell failed", exc_info=True)
                changed = True
            self._cells[key] = new
        if changed:
            table.refresh()

    def _update_empty(self) -> None:
        empty = self.profile is None
        self.set_class(empty, "-empty")
        if not empty:
            return
        c = lens_palette()
        text = Text()
        if self._loading and not self.profile_error:
            text.append("Reading the identity profile.", c.dim)
        elif self.profile_error:
            text.append("The active identity profile could not be read.\n", "bold")
            text.append(self.profile_error + "\n\n", c.bad)
            text.append("P", f"bold {c.accent}")
            text.append(" to choose or create another profile.")
        else:
            text.append("No identity profile yet.\n\n", "bold")
            text.append(
                "An identity profile seeds distinctive fake values on the "
                "emulator: Android ID, advertising ID, device name, phone "
                "number, GPS position, contacts, SMS and more. The privacy "
                "scan then shows where each of them ends up: which "
                "recipients got it, and whether the app stored it.\n\n"
            )
            text.append("P", f"bold {c.accent}")
            if self.library_count:
                text.append(" to choose or create a profile, ")
            else:
                text.append(" to create a profile, ")
            text.append("I", f"bold {c.accent}")
            text.append(" to import one.")
        try:
            self.query_one("#identity-empty", Static).update(text)
        except Exception:
            pass

    def notice_text(self) -> str | None:
        """The notices for this profile, one per line, or None: the "restart
        the app" notice, a changed ``extends`` parent and a problem in the
        world section (which never blocks an apply).
        """
        lines = [t for t in (self._stale_notice(), *self._profile_notes()) if t]
        return "\n".join(lines) or None

    def _profile_notes(self) -> list[str]:
        profile = self.profile
        if profile is None:
            return []
        out = []
        if getattr(profile, "parent_changed", False):
            out.append(
                f"The profile it extends ({profile.extends}) changed since the "
                "last save; values may differ."
            )
        ident = identity_service()
        check = getattr(ident, "world_warnings", None)
        if check is not None:
            try:
                issues = check(profile)
            except Exception:
                issues = []
            if issues:
                out.append(
                    f"World section: {_oneline(issues[0].message)} "
                    "(the identity values are not affected)."
                )
        return out

    def _stale_notice(self) -> str | None:
        """The "restart the app" notice, or None."""
        stale = self._stale_app
        if stale is None:
            return None
        spot = _spotlight()
        if spot is None:
            return None
        try:
            package = spot.get_effective_package()
            pid = spot.get_pid()
        except Exception:
            return None
        if package != stale[0] or pid != stale[1] or not pid:
            self._stale_app = None
            return None
        return (
            f"{package} was started before this identity was applied: "
            "restart the app with Shift+R to use this identity."
        )

    def _update_notice(self) -> None:
        text = self.notice_text()
        try:
            notice = self.query_one("#identity-notice", Static)
        except Exception:
            return
        notice.update(Text(text or ""))
        notice.set_class(bool(text), "-shown")

    def _update_caption(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        profile = self.profile
        if profile is None:
            ms.set_lens_caption(LENS_ID, title="no profile", info=None)
            return
        mode = "off"
        ident = identity_service()
        if ident is not None:
            try:
                mode = "on" if ident.config().mode == "profile" else "off"
            except Exception:
                mode = "off"
        name = profile.name or profile.id
        title = f"{name} rev {profile.revision}, mode {mode}"
        applied_at, verified_at = self._apply_times(ident, profile)
        bits = []
        if applied_at:
            bits.append(f"applied {datetime.fromtimestamp(applied_at):%H:%M:%S}")
        if verified_at:
            bits.append(f"verified {datetime.fromtimestamp(verified_at):%H:%M:%S}")
        if not bits:
            bits.append("not applied yet")
        bits.append("enter inspect")
        ms.set_lens_caption(LENS_ID, title=title, info=", ".join(bits))

    @staticmethod
    def _apply_times(ident: Any, profile: Any) -> tuple[float, float]:
        """``(applied_at, verified_at)`` of this profile on the target device,
        from the service: every apply and verify, whoever ran it (this lens,
        an app start, an earlier TUI process through the device record).
        ``0.0`` when not known.
        """
        serial = _target_serial()
        last = getattr(ident, "last_apply", None)
        if not serial or last is None:
            return 0.0, 0.0
        try:
            from sandroid.services.identity import fingerprint

            times = last(serial, fingerprint(profile))
        except Exception:
            times = None
        if not times:
            return 0.0, 0.0
        return times[0] or 0.0, times[1] or 0.0

    def failed_count(self) -> int:
        return sum(1 for r in self.rows if r.info.status == "failed")

    def _update_badge(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        n = self.failed_count()
        ms.set_lens_badge(LENS_ID, str(n) if n else None)

    # -- selection -----------------------------------------------------------

    def selected_row(self) -> LensRow | None:
        try:
            key = self.table.current_key()
        except Exception:
            return None
        return next((r for r in self.rows if r.id == key), None)

    def select_value(self, value_id: str) -> bool:
        """Put the cursor on ``value_id`` (tests, other lenses)."""
        if value_id not in self._row_keys:
            return False
        index = self._row_keys.index(value_id)
        self.table._last_row = index
        self.table.move_cursor(row=index, animate=False)
        return True

    def _hits_of(self, row: LensRow) -> list[Any]:
        return flat_hits(row.found.hits)

    def selected_hit(self, row: LensRow | None = None) -> Any | None:
        row = row or self.selected_row()
        if row is None:
            return None
        hits = self._hits_of(row)
        if not hits:
            return None
        index = min(self._hit_sel.get(row.id, 0), len(hits) - 1)
        return hits[index]

    def move_hit(self, delta: int, row_id: str | None = None) -> None:
        row = next((r for r in self.rows if r.id == row_id), None) or (
            self.selected_row()
        )
        if row is None:
            return
        hits = self._hits_of(row)
        if not hits:
            return
        index = self._hit_sel.get(row.id, 0)
        self._hit_sel[row.id] = max(0, min(len(hits) - 1, index + delta))
        ms = self._main_screen()
        if ms is not None:
            ms.update_inspector(self.content_for(row))

    # -- inspector -------------------------------------------------------------

    def inspect_selected(self) -> InspectorContent | None:
        row = self.selected_row()
        if row is None:
            return None
        return self.content_for(row)

    def _signature(self, row: LensRow) -> tuple:
        info = row.info
        return (
            row.id,
            info.status,
            info.current,
            info.rendered,
            len(row.found.hits),
            self._hit_sel.get(row.id, 0),
        )

    def _follow_inspector(self) -> None:
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        content = getattr(ms, "inspector_content", None)
        key = getattr(content, "key", None)
        if not (isinstance(key, str) and key.startswith(KEY_PREFIX)):
            return
        row = next((r for r in self.rows if KEY_PREFIX + r.id == key), None)
        if row is None:
            return
        sig = self._signature(row)
        if sig == self._inspector_sig:
            return
        ms.update_inspector(self.content_for(row))

    def content_for(self, row: LensRow) -> InspectorContent:
        c = lens_palette()
        info = row.info
        self._inspector_sig = self._signature(row)
        hits = self._hits_of(row)
        found_tab = ("Found", self._found_sections(row, hits))
        value_tab = ("Value", self._value_sections(row))
        tabs = [found_tab, value_tab] if hits else [value_tab, found_tab]
        word = STATUS_WORDS.get(info.status, info.status)
        found_words = row.found.words()
        subtitle = f"{escape(word)}, " + (
            f"[{c.dim}]not seen[/]"
            if found_words == "not seen"
            else f"[bold {c.warn}]{escape(found_words)}[/]"
        )
        footer = "{ } hit   J jump" if hits else "e edit"
        return InspectorContent(
            title=info.label,
            subtitle=subtitle,
            tabs=tabs,
            footer=footer,
            key=KEY_PREFIX + row.id,
            keys={
                "left_curly_bracket": lambda _tab, rid=row.id: self.move_hit(-1, rid),
                "right_curly_bracket": lambda _tab, rid=row.id: self.move_hit(1, rid),
            },
        )

    def _found_sections(self, row: LensRow, hits: list[Any]) -> list[tuple[str, Any]]:
        c = lens_palette()
        if not hits:
            service = privacy_service()
            active = False
            if service is not None:
                try:
                    active = bool(service.summary().active)
                except Exception:
                    active = False
            msg = (
                "Not seen in traffic or files yet."
                if active
                else "The privacy scan is not running: apply the profile "
                "(space) to start it."
            )
            return [("", Text(msg, style=c.dim))]
        selected = self.selected_hit(row)
        sections: list[tuple[str, Any]] = []
        for (kind, name), group in ordered_hits(row.found.hits):
            text = Text()
            text.append(name, "bold")
            word, token = party_word(group[0])
            text.append("   ")
            text.append(word, f"bold {getattr(c, token)}")
            for hit in group:
                text.append("\n")
                self._hit_lines(text, hit, hit is selected)
            sections.append(("", text))
        return sections

    def _hit_lines(self, text: Text, hit: Any, selected: bool) -> None:
        c = lens_palette()
        when = datetime.fromtimestamp(_hit_time(hit)).strftime("%H:%M:%S")
        line = f"{when}  {where_words(hit)}"
        style = f"reverse bold {c.accent}" if selected else c.text
        text.append("  ")
        text.append(line, style)
        how = describe_transform(hit.transform)
        conf = f"{hit.confidence} confidence"
        text.append("\n    ")
        text.append(how, c.text)
        text.append(", ")
        text.append(conf, c.dim if hit.confidence == "low" else c.muted)
        extras = []
        if getattr(hit, "count", 1) and hit.count > 1:
            extras.append(f"{hit.count} times")
        if getattr(hit, "echo", False):
            extras.append("echoed back by the server")
        if getattr(hit, "direction", "") == "received":
            extras.append("received")
        if extras:
            text.append(", " + ", ".join(extras), c.muted)
        before, match, after = (tuple(hit.snippet) + ("", "", ""))[:3]
        text.append("\n    ")
        text.append(_oneline(before), c.dim)
        text.append(_oneline(match), f"bold {c.accent_text} on {c.warn}")
        text.append(_oneline(after), c.dim)

    def _value_sections(self, row: LensRow) -> list[tuple[str, Any]]:
        c = lens_palette()
        info = row.info
        profile = self.profile

        def grid(pairs: list[tuple[str, Any]]) -> Table:
            table = Table.grid(padding=(0, 2))
            table.add_column(style=c.label, no_wrap=True)
            table.add_column()
            for label, value in pairs:
                if isinstance(value, Text):
                    table.add_row(label, value)
                else:
                    table.add_row(label, Text(str(value)))
            return table

        source = ""
        vs = getattr(profile, "values", {}).get(row.id) if profile else None
        if vs is not None:
            if vs.value is not None:
                source = "fixed value"
            elif vs.template is not None:
                source = f"template {vs.template}"
            elif vs.derive:
                source = f"derived ({vs.derive})"
        elif row.id in LIST_IDS and profile is not None:
            source = f"{len(getattr(profile, row.id, []) or [])} items"
        pairs: list[tuple[str, Any]] = [
            ("Profile value", info.rendered or Text("per app", style=c.dim)),
        ]
        if source:
            pairs.append(("Source", source))
        pairs.append(("Device now", info.current or Text("not read yet", style=c.dim)))
        pairs.append(("Before", info.before or Text("not recorded", style=c.dim)))
        for pkg, data in sorted((info.per_app or {}).items()):
            value = data.get("value") or data.get("desired") or ""
            status = data.get("status") or ""
            pairs.append((f"  {pkg}", f"{value} {status}".strip()))
        word = STATUS_WORDS.get(info.status, info.status)
        status = Text(word, style={"verified": c.ok, "failed": c.bad}.get(info.status))
        if info.reason:
            status.append(f", {info.reason}", c.muted)
        apply_pairs: list[tuple[str, Any]] = [
            ("Status", status),
            ("Via", info.provider),
            ("Mechanism", info.mechanism or "none"),
            ("Restart", RESTART_WORDS.get(info.restart, info.restart)),
            (
                "Apps need",
                info.permission or Text("no permission", style=c.dim),
            ),
        ]
        if info.volatile:
            apply_pairs.append(("Note", "the device forgets it on reboot"))
        markers = self._markers_of(row.id)
        marker_text = Text()
        for i, (mid, value) in enumerate(markers):
            if i:
                marker_text.append("\n")
            marker_text.append(mid, c.label)
            marker_text.append("  ")
            marker_text.append(value)
        if not markers:
            marker_text.append("not searched for (no marker)", c.dim)
        return [
            ("Value", grid(pairs)),
            ("Apply", grid(apply_pairs)),
            ("Markers", marker_text),
        ]

    def _markers_of(self, row_id: str) -> list[tuple[str, str]]:
        markers: list[Any] = []
        ident = identity_service()
        if ident is not None:
            try:
                active = ident.active_markers(load=False)
            except Exception:
                active = None
            if active:
                markers = list(active[1])
        if not markers and self.profile is not None:
            try:
                from sandroid.services.identity import markers_for

                markers = markers_for(self.profile, {})
            except Exception:
                markers = []
        return [(m.id, m.value) for m in markers if row_id_for_marker(m.id) == row_id]

    # -- jump ------------------------------------------------------------------

    def action_jump(self) -> None:
        """``J``: the selected hit's source in its own lens."""
        hit = self.selected_hit()
        if hit is None:
            self.app.notify("No hit selected (Enter shows a value's hits).", timeout=3)
            return
        ok = self.jump_to(hit)
        if ok is None:
            self.app.notify("This hit has no source to jump to.", timeout=3)
        elif ok is False:
            self.app.notify("Its source is not available any more.", timeout=3)

    def jump_to(self, hit: Any) -> bool | None:
        """Show ``hit``'s source: True done, False missing, None no target."""
        ms = self._main_screen()
        if ms is None:
            return None
        src = hit.source or {}
        if src.get("type") == "flow" and src.get("flow_id"):
            ms.switch_lens("network")
            panel = ms.lens_widget("network")
            reveal = getattr(panel, "reveal_flow", None)
            from .network_panel import flow_record_of

            # The record opens a flow the (hidden) lens has not loaded yet.
            record = flow_record_of(hit)
            if reveal is not None and reveal(str(src["flow_id"]), record=record):
                return True
            if hit.tl_seq is None:
                return False
        elif src.get("type") == "file" and src.get("device_path"):
            ms.switch_lens("files")
            panel = ms.lens_widget("files")
            reveal = getattr(panel, "reveal", None)
            if reveal is not None and reveal(
                str(src["device_path"]), version=src.get("version")
            ):
                return True
            if hit.tl_seq is None:
                return False
        if hit.tl_seq is None:
            return None
        ms.switch_lens("timeline")
        self._select_timeline(int(hit.tl_seq), tries=6)
        return True

    def _select_timeline(self, seq: int, tries: int) -> None:
        """Select timeline line ``seq``; the lens may still be loading."""
        ms = self._main_screen()
        panel = ms.lens_widget("timeline") if ms is not None else None
        select = getattr(panel, "select_seq", None) or getattr(
            panel, "_select_seq", None
        )
        if select is not None:
            try:
                if select(seq):
                    return
            except Exception:
                logger.debug("identity lens: timeline select failed", exc_info=True)
        if tries > 0:
            self.set_timer(0.5, lambda: self._select_timeline(seq, tries - 1))
        else:
            self.app.notify("That timeline line is not loaded.", timeout=3)

    # -- filter ------------------------------------------------------------------

    def action_filter(self) -> None:
        field = self.query_one("#identity-filter", Input)
        field.value = self._filter
        field.set_class(True, "-shown")
        field.focus()
        field.cursor_position = len(field.value)

    def set_filter(self, text: str) -> None:
        self._filter = text.strip()
        self._render_rows()

    def close_filter(self, clear: bool = False) -> None:
        field = self.query_one("#identity-filter", Input)
        if clear:
            self.set_filter("")
        field.set_class(False, "-shown")
        self.table.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "identity-filter" and event.input.has_class("-shown"):
            event.stop()
            self.set_filter(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "identity-filter":
            event.stop()
            self.set_filter(event.value)
            self.close_filter()

    def handle_escape(self) -> bool:
        """Esc (MainScreen): close the filter input, else clear the filter."""
        try:
            field = self.query_one("#identity-filter", Input)
        except Exception:
            return False
        if field.has_class("-shown"):
            self.close_filter(clear=True)
            return True
        if self._filter:
            self.set_filter("")
            return True
        return False

    # -- device actions (workers) ----------------------------------------------

    def _run_bg(
        self,
        fn: Callable[[], Any],
        done: Callable[[Any], None],
        group: str = "identity-device",
    ) -> None:
        """Run ``fn`` in a thread worker; ``done(result | exception)`` on the UI."""

        def work() -> None:
            try:
                result = fn()
            except Exception as exc:
                result = exc
            if not self._ui.post(done, result):
                logger.debug("identity lens: result dropped (not mounted)")

        self.run_worker(work, thread=True, exclusive=False, group=group)

    def _refresh_header(self) -> None:
        ms = self._main_screen()
        refresh = getattr(ms, "refresh_privacy_indicator", None)
        if refresh is not None:
            try:
                refresh()
            except Exception:
                pass

    def _require_profile(self) -> bool:
        if self.profile is None:
            self.app.notify("No identity profile yet: P creates one.", timeout=4)
            return False
        return True

    def action_apply(self) -> None:
        """``space``: plan on the device, ask before a framework restart, apply."""
        if not self._require_profile():
            return
        if self._busy:
            self.app.notify("The identity profile is being applied.", timeout=3)
            return
        ident = identity_service()
        if ident is None:
            return
        try:
            errors = [i for i in ident.validate(self.profile) if i.severity == "error"]
        except Exception:
            errors = []
        if errors:
            self.app.notify(
                f"The profile has errors: {errors[0].path}: {errors[0].message}",
                severity="error",
                timeout=6,
            )
            return
        serial = _target_serial()
        if not serial:
            self.app.notify("No device connected (D selects one).", timeout=4)
            return
        package = None
        spot = _spotlight()
        if spot is not None:
            try:
                package = spot.get_effective_package()
            except Exception:
                package = None
        try:
            cfg = ident.config()
            mode_off = cfg.mode != "profile"
            policy = cfg.restart
        except Exception:
            mode_off, policy = False, "ask"
        self._busy = True
        _set_applying(True)
        self._refresh_header()

        def plan() -> Any:
            if mode_off:
                ident.set_active(mode="profile")
            return ident.plan(serial, package)

        def planned(result: Any) -> None:
            _set_applying(False)
            if isinstance(result, Exception):
                self._busy = False
                self._refresh_header()
                self._failed("Planning the identity apply failed", result)
                return
            if mode_off:
                self.app.notify("Identity mode is on now.", timeout=3)
            self._statuses = {i.id: i for i in result.infos.values()}
            self.refresh_data()
            if not result.disruptive or policy == "always":
                self._start_apply(serial, package, None)
                return
            if policy == "never":
                self._start_apply(serial, package, False)
                return
            self._ask_restart(result, serial, package)

        self._run_bg(plan, planned)

    def _ask_restart(self, plan: Any, serial: str, package: str | None) -> None:
        from sandroid.tui.modals.selection_modal import SelectionModal

        labels = sorted(
            {
                plan.infos[s.value_id].label
                for s in plan.steps
                if s.restart == "framework" and s.value_id in plan.infos
            }
        )
        restart = "Restart Android & apply"
        no_restart = "Apply without restart"
        message = (
            "Some values only take effect after Android restarts (every app "
            "stops): " + (", ".join(labels) or "a pending restart") + "."
        )

        def chosen(choice: Any) -> None:
            if choice == restart:
                self._start_apply(serial, package, True)
            elif choice == no_restart:
                self._start_apply(serial, package, False)
            else:
                self._busy = False
                self._refresh_header()
                self.app.notify("Apply cancelled.", timeout=3)

        self.app.push_screen(
            SelectionModal(
                title="Apply identity profile",
                options=[restart, no_restart],
                message=message,
            ),
            chosen,
        )

    def _start_apply(
        self, serial: str, package: str | None, allow_restart: bool | None
    ) -> None:
        ident = identity_service()
        if ident is None:
            self._busy = False
            return
        self._busy = True
        _set_applying(True)
        self._refresh_header()

        def apply() -> Any:
            return ident.apply(serial, package, allow_restart=allow_restart)

        def applied(result: Any) -> None:
            _set_applying(False)
            self._busy = False
            self._refresh_header()
            if isinstance(result, Exception):
                self._failed("Applying the identity profile failed", result)
                self.refresh_data()
                return
            self._statuses = {i.id: i for i in result.infos.values()}
            self._note_running_app(package)
            counts: dict[str, int] = {}
            for info in result.infos.values():
                word = STATUS_WORDS.get(info.status, info.status)
                counts[word] = counts.get(word, 0) + 1
            summary = ", ".join(f"{n} {w}" for w, n in sorted(counts.items()))
            failed = counts.get("failed", 0)
            self.app.notify(
                f"Identity profile applied: {summary}.",
                severity="warning" if failed else "information",
                timeout=5,
            )
            self.refresh_data()

        self._run_bg(apply, applied)

    def _note_running_app(self, package: str | None) -> None:
        """Remember the spotlight app if it ran during the apply (notice)."""
        spot = _spotlight()
        if spot is None or not package:
            self._stale_app = None
            return
        try:
            pid = spot.get_pid()
            current = spot.get_effective_package()
        except Exception:
            pid, current = None, None
        self._stale_app = (package, pid) if pid and current == package else None

    def action_verify(self) -> None:
        """``v``: read the device back and refresh the statuses."""
        if not self._require_profile():
            return
        ident = identity_service()
        serial = _target_serial()
        if ident is None:
            return
        if not serial:
            self.app.notify("No device connected (D selects one).", timeout=4)
            return

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                self._failed("Verify failed", result)
                return
            # The service's statuses: a verify that read while an apply ran
            # is not published, and must not replace the apply's result here.
            current = ident.statuses()
            infos = current or list(result.infos.values())
            self._statuses = {i.id: i for i in infos}
            self.app.notify("Identity values read back from the device.", timeout=3)
            self.refresh_data()

        self.app.notify("Reading the identity values from the device…", timeout=2)
        self._run_bg(lambda: ident.verify(serial), done)

    def _failed(self, what: str, exc: Exception) -> None:
        logger.info(f"identity lens: {what}: {exc}")
        self.app.notify(f"{what}: {exc}", severity="error", timeout=6)

    # -- library actions (local files, UI thread) ---------------------------

    def action_edit(self) -> None:
        """``e``: edit the selected value (a plain value or a template)."""
        if not self._require_profile():
            return
        row = self.selected_row()
        if row is None:
            return
        if row.id in LIST_IDS:
            self.app.notify(
                "Contacts, SMS and calls are edited in the profile file "
                "(X exports it, I imports it back).",
                timeout=5,
            )
            return
        profile = self.profile
        vs = profile.values.get(row.id)
        if vs is None:
            return
        if vs.value is not None:
            default = vs.value
        elif vs.template is not None:
            default = vs.template
        else:
            default = ""
        derived = vs.derive is not None and vs.value is None and vs.template is None
        message = (
            "A plain value, or a template with {token}, {digits:N}, {hex:N}, "
            "{luhn}, {uuid} or an owner field: {owner.first}, {owner.last}, "
            "{owner.phone}, {owner.email}."
        )
        if derived:
            message += " Empty keeps it derived per app."
        ident = identity_service()

        def apply_text(target: Any, text: str) -> None:
            spec = target.values[row.id]
            if not text.strip():
                if not derived:
                    raise ValueError("a value is needed")
                return
            if "{" in text or "}" in text:
                spec.template, spec.value = text, None
            else:
                spec.value, spec.template = text, None
            spec.derive = None

        def validate(text: str) -> str | None:
            if not text.strip() and not derived:
                return "A value is needed."
            try:
                draft = profile.copy()
            except Exception:
                draft = None
            if draft is None or ident is None:
                return None
            try:
                apply_text(draft, text)
            except Exception as exc:
                return str(exc)
            for issue in ident.validate(draft):
                if issue.severity != "error":
                    continue
                if issue.path == f"values.{row.id}" or (
                    issue.path.startswith("values.") and row.id in issue.message
                ):
                    return issue.message
            return None

        def done(text: Any) -> None:
            if text is None or ident is None:
                return
            if not text.strip() and derived:
                return
            try:
                apply_text(profile, text)
                saved = ident.save(profile)
            except Exception as exc:
                self._failed("Saving the profile failed", exc)
                return
            self._statuses.pop(row.id, None)
            self.profile = saved
            self.app.notify(
                f"Saved {row.info.label} (revision {saved.revision}); "
                "space applies it.",
                timeout=4,
            )
            self.refresh_data()

        self.app.push_screen(
            ValueEditModal(
                title=f"Edit {row.info.label}",
                message=message,
                default=default,
                validate=validate,
            ),
            done,
        )

    def action_regenerate(self) -> None:
        """``R``: fresh token and seed for every value (asks first)."""
        if not self._require_profile():
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        profile = self.profile
        ident = identity_service()

        def done(ok: Any) -> None:
            if not ok or ident is None:
                return
            try:
                ident.regenerate(profile.id)
            except Exception as exc:
                self._failed("Regenerating failed", exc)
                return
            self._statuses.clear()
            self.app.notify(
                "New values generated; space applies them (the old ones are "
                "removed from the device).",
                timeout=5,
            )
            self.reload()

        self.app.push_screen(
            ConfirmModal(
                title="Regenerate identity values",
                message=(
                    f"Give every value of '{profile.name or profile.id}' a new "
                    "token and seed? The old values are removed from the "
                    "device at the next apply."
                ),
                yes_label="Regenerate",
                no_label="Cancel",
                guard_typing=True,
            ),
            done,
        )

    def action_toggle_mode(self) -> None:
        """``M``: identity mode on / off."""
        ident = identity_service()
        if ident is None:
            return
        try:
            on = ident.config().mode == "profile"
            ident.set_active(mode="off" if on else "profile")
        except Exception as exc:
            self._failed("Changing the identity mode failed", exc)
            return
        self.app.notify(
            "Identity mode off: apps start with the device's own values."
            if on
            else "Identity mode on: space applies the profile.",
            timeout=4,
        )
        self.reload()
        self._refresh_header()

    def action_profiles(self) -> None:
        """``P``: switch / create / duplicate / rename / delete profiles."""
        from sandroid.tui.modals.selection_modal import SelectionModal

        ident = identity_service()
        if ident is None:
            return
        try:
            infos = ident.list_profiles()
        except Exception:
            infos = []
        active = self.profile.id if self.profile is not None else ""
        options: list[tuple[str, str, str]] = []
        for info in infos:
            if info.error:
                continue
            tag = "   (active)" if info.id == active else ""
            options.append(
                ("use", info.id, f"Use {info.name or info.id}  [{info.id}]{tag}")
            )
        try:
            presets = ident.builtins()
        except Exception:
            presets = []
        if not presets:
            try:
                from sandroid.services.device_settings_service import (
                    COUNTRY_PRESETS,
                )

                presets = [(k, v.name) for k, v in COUNTRY_PRESETS.items()]
            except Exception:
                presets = [("de", "Germany")]
        for key, name in presets:
            options.append(("new", key, f"New profile from preset: {name}"))
        if active:
            options += [
                ("duplicate", active, f"Duplicate '{active}'"),
                ("rename", active, f"Rename '{active}'…"),
                ("delete", active, f"Delete '{active}'…"),
            ]

        def chosen(choice: Any) -> None:
            if not choice:
                return
            self._profile_choice(choice[0], choice[1])

        self.app.push_screen(
            SelectionModal(
                title="Identity profiles",
                options=options,
                message="Type to filter; enter picks.",
                display_func=lambda o: o[2],
            ),
            chosen,
        )

    def _profile_choice(self, action: str, arg: str) -> None:
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        ident = identity_service()
        if ident is None:
            return
        try:
            if action == "use":
                ident.set_active(profile_id=arg)
                self._statuses.clear()
                self.app.notify(f"Active identity profile: {arg}.", timeout=3)
            elif action == "new":
                profile = ident.create(arg)
                ident.set_active(profile_id=profile.id)
                self._statuses.clear()
                self.app.notify(
                    f"Created profile '{profile.id}'; space applies it.", timeout=4
                )
            elif action == "duplicate":
                profile = ident.duplicate(arg)
                ident.set_active(profile_id=profile.id)
                self._statuses.clear()
                self.app.notify(f"Duplicated as '{profile.id}'.", timeout=3)
            elif action == "rename":

                def renamed(name: Any) -> None:
                    if not name or not str(name).strip():
                        return
                    try:
                        ident.rename(arg, str(name).strip())
                    except Exception as exc:
                        self._failed("Renaming failed", exc)
                        return
                    self.reload()

                current = self.profile.name if self.profile is not None else arg
                self.app.push_screen(
                    InputModal(
                        title="Rename identity profile",
                        message="The display name (the id stays).",
                        default=current,
                        select_all=True,
                    ),
                    renamed,
                )
                return
            elif action == "delete":

                def deleted(ok: Any) -> None:
                    if not ok:
                        return
                    try:
                        ident.delete(arg)
                        if ident.config().profile == arg:
                            ident.set_active(profile_id="")
                    except Exception as exc:
                        self._failed("Deleting failed", exc)
                        return
                    self._statuses.clear()
                    self.reload()

                self.app.push_screen(
                    ConfirmModal(
                        title="Delete identity profile",
                        message=f"Delete the profile file '{arg}'? Session "
                        "records of earlier applies stay.",
                        yes_label="Delete",
                        no_label="Cancel",
                        guard_typing=True,
                    ),
                    deleted,
                )
                return
        except Exception as exc:
            self._failed("Profile action failed", exc)
            return
        self.reload()
        self._refresh_header()

    def action_import_profile(self) -> None:
        """``I``: import a profile file into the library."""
        ident = identity_service()
        if ident is None:
            return

        def done(path: Any) -> None:
            if not path or not str(path).strip():
                return
            try:
                pid, outcome = ident.import_profile(
                    Path(str(path).strip()).expanduser()
                )
            except Exception as exc:
                self._failed("Import failed", exc)
                return
            words = {
                "imported": f"Imported '{pid}'.",
                "renamed": f"Imported as '{pid}' (another profile had that id).",
                "identical": f"Already in the library as '{pid}'.",
            }.get(outcome, f"Imported '{pid}'.")
            self.app.notify(words + " P switches to it.", timeout=5)
            self.reload()

        self.app.push_screen(
            InputModal(
                title="Import identity profile",
                message="Path of a profile file (.yaml, or an older .toml).",
                default=str(Path.cwd()) + "/",
            ),
            done,
        )

    def action_export_profile(self) -> None:
        """``X``: copy the profile file to a folder or file."""
        if not self._require_profile():
            return
        ident = identity_service()
        profile = self.profile
        if ident is None:
            return

        def done(path: Any) -> None:
            if not path or not str(path).strip():
                return
            try:
                target = ident.export_profile(
                    profile.id, Path(str(path).strip()).expanduser()
                )
            except Exception as exc:
                self._failed("Export failed", exc)
                return
            self.app.notify(f"Exported to {target}.", timeout=5)

        self.app.push_screen(
            InputModal(
                title="Export identity profile",
                message="A folder or a file name.",
                default=str(Path.cwd()) + "/",
            ),
            done,
        )


def _read_library(ident: Any) -> tuple[int, Any, str]:
    """``(profiles in the library, active profile, error)`` (worker thread)."""
    try:
        count = len(ident.list_profiles())
    except Exception:
        count = 0
    try:
        profile_id = str(ident.config().profile or "")
    except Exception:
        profile_id = ""
    profile, error = None, ""
    if profile_id:
        try:
            profile = ident.load(profile_id)
        except Exception as exc:
            error = f"{profile_id}: {exc}"
    try:
        ident.active_markers()  # reads the session's frozen record once
    except Exception:
        logger.debug("identity lens: active markers failed", exc_info=True)
    return count, profile, error


def _text_sig(text: Text) -> tuple:
    return (text.plain, str(text.style), tuple(text.spans))


def _oneline(text: str) -> str:
    return str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")


__all__ = [
    "LENS_ID",
    "Found",
    "IdentityLens",
    "IdentityTable",
    "ValueEditModal",
    "apply_in_progress",
    "describe_transform",
    "flat_hits",
    "group_hits",
    "ordered_hits",
    "part_words",
    "privacy_indicator",
    "row_id_for_marker",
]
