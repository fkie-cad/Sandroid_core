"""Lens shell: the pieces of the "Lenses + Inspector" main-screen layout.

Layout (top to bottom, see ``MainScreen.compose``)::

    ShellHeader   #shell-header   crumb · snapshot · label · Tracking · pill · clock
    StatusBar     #status-bar     1-2 rows of live tool state
    LensBar       #lens-bar       1 App  2 Network  3 Files  4 Sessions  5 Timeline
    #workspace    Horizontal
      #lens-host  framed ContentSwitcher #lens-body holding the five lenses
      #side-slot  right-hand slot: Inspector #inspector  OR  chat #chat-dock
    LogTicker     #log-ticker     newest log line + "` log" hint
    LogDrawer     #log-drawer     hidden; ` toggles it; holds ActivityLog #activity-log
    SandroidFooter

Contract for lens authors (phase B)
===================================

Lenses
------
``LENSES`` below is the single registry. Each lens is one widget that is a
direct child of the ``#lens-body`` ContentSwitcher, addressed by its widget
id:

=========  ===  ===========  =====================  =============================
lens id    key  label        widget id              widget (module)
=========  ===  ===========  =====================  =============================
``app``    1    App          ``spotlight-panel``    SpotlightPanel (spotlight_panel)
``network``2    Network      ``network-panel``      NetworkPanel (network_panel)
``files``  3    Files        ``files-panel``        FilesPanel (files_panel)
``runs``   4    Sessions     ``runs-panel``         DiffsView (diffs_view)
``timeline`` 5  Timeline     ``timeline-panel``     TimelineLens (timeline_lens)
=========  ===  ===========  =====================  =============================

To replace a lens body, keep the widget id (or change it here *and* in
``MainScreen.compose``). ``MainScreen`` API (all main-thread):

* ``switch_lens(lens_id)`` / ``cycle_lens(delta)`` / ``active_lens`` (id) /
  ``lens_widget(lens_id)`` / ``is_lens_active(lens_id)``.
* ``set_lens_badge(lens_id, text | None)`` -- alert badge after the lens
  name in the lens bar, e.g. ``set_lens_badge("network", "⚑2")``.
* ``set_lens_caption(lens_id, title=None, info=None)`` -- the lens frame
  shows ``"<Label> · <title>"`` top-left and ``info`` top-right (e.g.
  ``"10 of 247 events"``) while that lens is active.

Optional duck-typed hooks a lens widget may implement:

* ``on_lens_activated()`` -- called every time the lens becomes active
  (after focus moved into it). Legacy hooks ``refresh_snapshots``,
  ``refresh_header``, ``refresh_glance``, ``on_activated`` are still called.
* ``inspect_selected() -> InspectorContent | None`` -- Enter→Inspector.
  ``MainScreen`` calls it (a) when Enter reaches the screen unhandled, and
  (b) when an ``OptionList.OptionSelected`` or ``DataTable.RowSelected``
  message bubbles out of the *active* lens (that is what Enter or a click on
  a row of those widgets posts). Returning ``None`` does nothing. Every
  lens inspects on Enter now; lens-level "do it" actions live on Space
  (App: Start/Resume, Network: start/stop mitmproxy).
  Note: the footer shows one binding per key, the focused widget's first;
  a focused OptionList/DataTable owns a hidden Enter binding, so advertise
  "⏎ inspect" in the lens itself (e.g. via ``set_lens_caption`` info).
* ``on_scope_changed(message: ScopeChanged)`` -- normal Textual message
  handler; ``MainScreen`` posts a (non-bubbling) ``ScopeChanged`` to every
  lens widget whenever the scope changes. Alternatively watch the reactive:
  ``self.watch(self.screen, "scope_run", callback)``.

Use ``is_shown(widget)`` (below) instead of querying ``#lens-body`` to gate
slow polls on visibility.

Focus and keys: ``MainScreen`` gives focus back to the active lens (its
``focus()``) whenever focus lands on nothing or inside a hidden view -- e.g.
a lens hid its focused table -- and a key the focus chain does not bind but
the active lens does runs on the lens. A lens may still hide its own focused
widget; it does not need to re-home focus itself. ``/`` in a lens without a
``slash`` binding starts a short typing guard (single-letter app commands
are swallowed while the word is typed).

Inspector
---------
``InspectorContent`` (dataclass) describes what the right-hand Inspector
shows: ``title``, optional ``subtitle``, ordered ``sections`` of
``(heading, renderable)`` (a ``str`` is Rich markup; any Rich renderable --
``Table.grid()``, ``Syntax``, ``Text`` -- works), optional ``footer`` key
hints (shown on the frame's bottom edge), optional ``tabs`` (a sequence of
``(tab name, sections)``; when given, ``sections`` is ignored and ``[``/``]``
-- or ←/→ unless a text input has focus -- or a click switches
tabs), and an optional ``key`` identifying the inspected row.

Interactive content (optional): ``keys`` maps ``left_curly_bracket`` /
``right_curly_bracket`` / ``asterisk`` to ``callback(active tab name)`` --
MainScreen binds ``{`` ``}`` ``*`` to them while the Inspector is open, e.g.
the Files lens picks a version or a table with ``{``/``}`` and sets a diff
base with ``*``. Keep these keys free in every lens and globally: a lens
binding on the same key would win while the lens has focus and silently
change what the key does; ``click(active tab name, body line) -> handled`` receives
clicks in the body (line 0 = first line of the tab's first section).

* ``MainScreen.open_inspector(content)`` -- opens the side slot (closing the
  AI chat if it was there) or replaces the content in place.
* ``MainScreen.update_inspector(content)`` -- replace in place, only if the
  Inspector is open (no-op otherwise): use it for live row changes. Compare
  ``MainScreen.inspector_content.key`` to know whether the open Inspector
  still shows your row. The active tab is kept when the tab names match.
* ``MainScreen.close_inspector()`` / ``MainScreen.inspector_is_open``.
* Switching to another lens closes the Inspector (its content and key hints
  belong to the lens that opened it).
* Focus stays in the lens when the Inspector opens, so ↑/↓ + Enter keep
  working; Tab or a click moves focus into the Inspector to scroll it.
* Esc closes the side slot (Inspector or chat) before anything else on the
  main screen; with nothing open it falls through to the old behaviour.

Scope (LIVE / REVIEW)
---------------------
* ``MainScreen.set_scope(run_id | None, label=None)`` -- ``None`` = live.
  The header pill shows ``● LIVE`` or ``◆ REVIEW <label or "Run <id>">``
  (the Runs lens passes ``"#<n> <label>"``), ``● REC`` while recording and
  ``● REPLAY · <phase>`` while a Play runs. The app pushes every
  recorder/player transition and phase change through
  ``MainScreen.refresh_scope_pill()`` (state on the StatusBar:
  ``recording_active``, ``replay_active``, ``replay_phase``).
* ``MainScreen.scope_run`` -- reactive (watchable) current run id or None;
  ``MainScreen.scope`` is the plain getter.
* ``ScopeChanged(run_id, label)`` is posted to every lens widget on change.
* **Scope id** (the ``run_id`` above): the run's bundle folder as an
  *absolute path string* -- ``str(<results_path>/runs/<run id>)``, made by
  ``run_history.scope_for_run(run id)``. The Runs lens sets it (``v`` on a
  run); ``L`` (``MainScreen.action_back_to_live``, footer-pinned while in
  REVIEW), ``v`` again on the same run, deleting that run, and the start of
  a recording or replay all go back to LIVE (``set_scope(None)``).
* Resolve it with ``sandroid.core.run_history`` (folder reads only, safe off
  the UI thread; nothing there needs the app):

  - ``run_dir_for_scope(scope) -> Path | None`` -- the run folder (holds
    ``run.json``, ``sandroid.json``, ``raw/``, ``manifest.json``...).
  - ``resolve_scope(scope) -> ScopedRun | None`` -- ``run_id``, ``run_dir``,
    ``label``, ``device_name``, ``started_at``, ``ended_at``, ``error``,
    ``phases`` (replay / dry-run windows; empty for older runs).
  - ``run_time_window(scope) -> (started_at, ended_at)`` -- tz-aware
    datetimes (stored naive values are local time), ``(None, None)`` if
    unknown: Play start → end of its analysis (includes the dry run).
  - ``phase_of(epoch, phases)`` -- ``"replay N"`` / ``"dry run"`` /
    ``"setup"`` (``""`` without phase data).
  - ``<run_dir>/NETWORK_DIR_NAME`` (``network/``) -- the run's own flows
    (``mitmproxy_flow_log.read_run_flows``), phase-tagged; covered by the
    run's ``SHA256SUMS``. Prefer it over the session's flow log.
  - ``file_diff_rows(scope | RunRecord) -> list[FileDiffRow]`` -- the run's
    files as ``FileDiffRow(kind, path, diff)``, ``kind`` in
    ``"changed"/"new"/"deleted"``, ``diff`` = diff lines (Rich markup) or
    None. Same loader the Runs lens uses (``load_run_dir`` → ``run.json``).
  - ``read_results_doc(run_dir) -> dict | None`` -- the full results JSON
    (``"Run Metadata"``, ``"Run Errors"``, ``"Network"`` ...); can be large.

Marks and labels
----------------
Labels live in the session timeline (``sandroid.core.timeline``, ``Labels``):
``#`` starts a top-level label (closing every open one), ``+`` a sub-label
(or a sibling of the innermost sub-label), ``-`` stops the innermost one and
``B`` drops a point -- App keys, in every lens, each asking for an optional
name (``InputModal``; Esc writes nothing).

* ``MainScreen.marks`` -- a :class:`SessionMarks` *view* rebuilt from
  ``labels.boundaries()``: top-level label starts, top-level label ends and
  every point, in time order (:class:`Mark` with ``kind``
  ``"start"``/``"end"``/``"point"``). Without the timeline core it is a plain
  in-memory list of points.
* ``MainScreen.add_mark(name="", when=None) -> Mark`` -- drops a point
  (``labels.point``), writes a separator line to the log (and so the ticker)
  and posts a (non-bubbling) :class:`MarksChanged` to every lens widget. Any
  lens can use the marks (segment = mark n up to mark n+1); the Files lens
  does. While a label name prompt is open, ``MarksChanged.pending`` carries
  the key-press time (the Files lens pre-splits its segments there).

Log
---
``#activity-log`` is unchanged (``query_one("#activity-log", ActivityLog)``
keeps working); it lives in the hidden ``#log-drawer``. Every non-blank line
written to it is mirrored to ``#log-ticker``. `` ` `` (``grave_accent``)
toggles the drawer: ``MainScreen.toggle_log_drawer()`` /
``log_drawer_is_open``.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.markup import escape
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widgets import Header, Static
from textual.widgets._header import HeaderClock, HeaderTitle

from sandroid.tui.themes import lens_palette

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable, Mapping, Sequence

    from rich.console import RenderableType
    from textual.app import ComposeResult
    from textual.widget import Widget


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LensSpec:
    """One lens: its id, digit key, label and the id of its body widget."""

    id: str
    key: str
    label: str
    widget_id: str


LENSES: tuple[LensSpec, ...] = (
    LensSpec("app", "1", "App", "spotlight-panel"),
    LensSpec("network", "2", "Network", "network-panel"),
    LensSpec("files", "3", "Files", "files-panel"),
    # Labelled "Sessions" (id and widget id stay "runs" / "runs-panel").
    LensSpec("runs", "4", "Sessions", "runs-panel"),
    LensSpec("timeline", "5", "Timeline", "timeline-panel"),
)
LENS_BY_ID: dict[str, LensSpec] = {spec.id: spec for spec in LENSES}
LENS_BY_WIDGET: dict[str, LensSpec] = {spec.widget_id: spec for spec in LENSES}


def is_shown(widget: Widget) -> bool:
    """True if ``widget`` is mounted and neither it nor an ancestor is hidden.

    A ContentSwitcher hides its inactive children with ``display: none``, so
    this answers "is this lens / sub-view the visible one?" without knowing
    the switcher ids. A widget on a screen below a modal still counts.
    """
    from textual.screen import Screen

    try:
        if not widget.is_attached:
            return False
        node = widget
        while node is not None and not isinstance(node, Screen):
            if not node.display:
                return False
            node = node.parent
        return node is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# inspector content + scope message
# ---------------------------------------------------------------------------

Section = tuple[str, Any]


@dataclass
class InspectorContent:
    """What the Inspector shows. See the module docstring for the contract."""

    title: str
    subtitle: str | None = None
    sections: Sequence[Section] = ()
    footer: str | None = None
    tabs: Sequence[tuple[str, Sequence[Section]]] = ()
    key: Hashable | None = None
    #: Optional interactive keys: ``{key name: callback(active tab name)}``.
    #: ``MainScreen`` binds ``{``, ``}`` and ``*`` (``left_curly_bracket``,
    #: ``right_curly_bracket``, ``asterisk``) to them while the Inspector is
    #: open; no lens binds these keys.
    keys: Mapping[str, Callable[[str | None], Any]] = field(
        default_factory=dict, compare=False
    )
    #: Optional click handler ``(active tab name, body line) -> handled``;
    #: the line counts from the top of the tab's sections (headings and the
    #: blank line between sections included).
    click: Callable[[str | None, int], bool] | None = field(default=None, compare=False)
    #: Filled in by ``MainScreen.open_inspector`` (the active lens id).
    lens: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Mark:
    """A boundary in the live session: a point ("tap login") or the start /
    end of a top-level label.

    ``number`` is the label number (one sequence over starts and points per
    timeline file; an end repeats its start's number); ``name`` is optional
    (``""`` = unnamed). ``kind`` is ``"point"``, ``"start"`` or ``"end"``;
    ``parent`` the enclosing label of a point; ``seq`` the timeline line.
    """

    number: int
    when: datetime
    name: str = ""
    kind: str = "point"
    parent: int | None = None
    seq: int | None = None

    def label(self) -> str:
        """``mark 3 'tap login'`` (point), ``label 7 'x'`` (start) or
        ``after label 7`` (end); the name is left out when empty.
        """
        if self.kind == "end":
            return f"after label {self.number}"
        word = "label" if self.kind == "start" else "mark"
        named = f" '{self.name}'" if self.name else ""
        return f"{word} {self.number}{named}"

    @classmethod
    def from_event(cls, event: Any) -> Mark:
        """A Mark from a timeline ``LabelEvent`` (host epoch ``t``)."""
        return cls(
            number=int(event.number),
            when=datetime.fromtimestamp(float(event.t)),
            name=event.name or "",
            kind=event.kind,
            parent=event.parent,
            seq=event.seq,
        )


class SessionMarks:
    """The shell's one list of marks (``MainScreen.marks``), shared by lenses.

    Pure Python. With the timeline core it is a view: ``rebuild`` replaces
    the list from ``labels.boundaries()``. Without it ``add`` appends a point
    and returns the new :class:`Mark` (in-memory fallback). Every change is
    announced to the lenses with :class:`MarksChanged` by ``MainScreen``. A
    lens turns the list into segments: segment 0 is before the first mark,
    segment ``n`` is from mark ``n`` up to the next mark (or now).
    """

    def __init__(self) -> None:
        self._marks: list[Mark] = []

    def __iter__(self):
        return iter(self._marks)

    def __len__(self) -> int:
        return len(self._marks)

    def __getitem__(self, index: int) -> Mark:
        return self._marks[index]

    @property
    def marks(self) -> list[Mark]:
        return list(self._marks)

    def add(self, name: str = "", when: datetime | None = None) -> Mark:
        number = max((m.number for m in self._marks), default=0) + 1
        mark = Mark(number, when or datetime.now(), name.strip())
        self._marks.append(mark)
        return mark

    def rebuild(self, events: Sequence[Any]) -> None:
        """Replace the list with ``labels.boundaries()`` (LabelEvents)."""
        self._marks = [Mark.from_event(e) for e in events]

    def clear(self) -> None:
        self._marks.clear()


class MarksChanged(Message):
    """Posted to every lens widget when a mark is added (or marks cleared).

    ``pending``: a label name prompt is open for a boundary at that time
    (nothing is written yet); a later ``MarksChanged`` without it settles it.
    """

    bubble = False

    def __init__(
        self,
        marks: list[Mark],
        added: Mark | None = None,
        pending: datetime | None = None,
    ) -> None:
        super().__init__()
        self.marks = marks
        self.added = added
        self.pending = pending


class ScopeChanged(Message):
    """Posted to every lens widget when the LIVE/REVIEW scope changes."""

    bubble = False

    def __init__(self, run_id: str | None, label: str | None = None) -> None:
        super().__init__()
        self.run_id = run_id
        self.label = label


def _as_renderable(body: Any) -> RenderableType:
    if isinstance(body, str):
        try:
            return Text.from_markup(body)
        except Exception:
            return Text(body)
    return body


def _as_text(markup: str) -> Text:
    try:
        return Text.from_markup(markup)
    except Exception:
        return Text(markup)


# ---------------------------------------------------------------------------
# header
# ---------------------------------------------------------------------------


class ShellHeader(Header):
    """One-row header: ``○ Sandroid ▸ device ▸ app ◇ snapshot``, the open
    label (``▶ 7 'accept cookies' 0:12``), the Tracking dot, a timeline
    banner (locked / failed), pill, clock.

    Subclasses Textual's ``Header`` so theme rules for ``Header`` apply and the
    clock/title plumbing is reused; only the title formatting and the extra
    pieces are ours. The 1 s tick only *displays* (device clock offset, open
    label, Tracking, timeline state); periodic device clock samples are taken
    by the timeline's writer thread.
    """

    DEFAULT_CSS = """
    ShellHeader {
        layout: horizontal;
        background: #0b1628;
        color: #7dd3fc;
    }
    ShellHeader HeaderTitle {
        width: 1fr;
        content-align: left middle;
        padding: 0 1;
    }
    ShellHeader #scope-pill {
        width: auto;
        padding: 0 1;
        margin: 0 1 0 0;
        text-style: bold;
        color: #4ade80;
    }
    ShellHeader #scope-pill.-review {
        color: #06121f;
        background: #fbbf24;
    }
    ShellHeader #scope-pill.-rec {
        color: #fb7185;
    }
    ShellHeader #scope-pill.-blind {
        color: #fb923c;
    }
    ShellHeader #device-clock {
        display: none;
        width: auto;
        padding: 0 1 0 0;
        color: $lens-dim;
    }
    ShellHeader #device-clock.-sync,
    ShellHeader #device-clock.-unknown {
        display: block;
    }
    ShellHeader #device-clock.-off {
        display: block;
        color: $lens-warn;
    }
    ShellHeader #label-note,
    ShellHeader #tracking-dot,
    ShellHeader #timeline-banner {
        display: none;
        width: auto;
        padding: 0 1 0 0;
    }
    ShellHeader #label-note {
        color: #facc15;
    }
    ShellHeader #tracking-dot {
        color: #4ade80;
        text-style: bold;
    }
    ShellHeader #timeline-banner {
        color: #fb923c;
        text-style: bold;
    }
    ShellHeader #label-note.-on,
    ShellHeader #tracking-dot.-on,
    ShellHeader #timeline-banner.-on {
        display: block;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(show_clock=True, **kwargs)
        self._crumb = ""
        self._snapshot = ""
        self._pill = ("● LIVE", "")
        #: Why LIVE is not quite live ("monitor blind"), set by the Files
        #: lens; shown instead of the plain "● LIVE" pill.
        self._live_note: str | None = None
        self._label_note: str | None = None
        self._tracking = False
        self._banner: str | None = None

    def compose(self) -> ComposeResult:
        yield HeaderTitle()
        yield Static("", id="label-note")
        yield Static("", id="tracking-dot")
        yield Static("", id="timeline-banner")
        yield Static(self._pill[0], id="scope-pill", classes="-live")
        yield Static("", id="device-clock")
        yield HeaderClock().data_bind(Header.time_format)

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick, name="header tick")

    def _tick(self) -> None:
        self.update_device_clock()
        self.refresh_timeline_state()

    # -- open label, Tracking, timeline state ----------------------------------

    def _set_piece(self, wid: str, text: str | None) -> None:
        try:
            label = self.query_one(f"#{wid}", Static)
        except Exception:
            return
        label.update(Text(text or ""))
        label.set_class(bool(text), "-on")

    def set_label_note(self, text: str | None) -> None:
        """The innermost open label, e.g. ``▶ 7 'accept cookies' 0:12``."""
        text = text or None
        if text != self._label_note:
            self._label_note = text
            self._set_piece("label-note", text)

    def set_tracking(self, active: bool) -> None:
        """The Tracking indicator (``◉ TRK`` while Tracking runs)."""
        if active != self._tracking:
            self._tracking = active
            self._set_piece("tracking-dot", "◉ TRK" if active else None)

    def set_timeline_banner(self, text: str | None) -> None:
        """``⚠ timeline locked (PID 4711 on host)`` / ``⚠ timeline failed``."""
        text = text or None
        if text != self._banner:
            self._banner = text
            self._set_piece("timeline-banner", text)

    @property
    def label_note(self) -> str | None:
        return self._label_note

    @property
    def tracking_on(self) -> bool:
        return self._tracking

    @property
    def timeline_banner(self) -> str | None:
        return self._banner

    def refresh_timeline_state(self, now: float | None = None) -> None:
        """Open label, Tracking and the timeline state (cheap, no I/O)."""
        from sandroid.tui.widgets.timeline_lens import (
            timeline_service,
            tracking_module,
        )

        now = time.time() if now is None else now
        note = None
        banner = None
        svc = timeline_service()
        if svc is not None:
            try:
                spans = svc.labels.open_spans()
            except Exception:
                spans = []
            if spans:
                inner = spans[-1]
                elapsed = max(0, int(now - float(inner.t)))
                named = f" '{inner.name}'" if inner.name else ""
                note = f"▶ {inner.number}{named} {elapsed // 60}:{elapsed % 60:02d}"
            try:
                status = svc.status()
            except Exception:
                status = None
            state = getattr(status, "state", None)
            if state == "locked":
                who = getattr(status, "locked_by", None)
                banner = f"⚠ timeline locked ({who})" if who else "⚠ timeline locked"
            elif state == "failed":
                banner = "⚠ timeline failed"
        self.set_label_note(note)
        self.set_timeline_banner(banner)
        active = False
        tracking = tracking_module()
        if tracking is not None:
            try:
                active = bool(tracking.is_active())
            except Exception:
                active = False
        self.set_tracking(active)

    def update_device_clock(self, now: float | None = None) -> str:
        """The device's wall time beside the host clock, always while a
        device is targeted (display only, no adb call: host now -
        ``off_wall`` of the last sample; the timeline's writer thread takes
        the periodic samples):

        * within 1 s of the host, dimmed: ``dev 17:16:02 ✓``
        * more than 1 s off, amber: ``dev 16:01:02 -75 min ⚠``
        * no sample of the current world yet (startup, or after a snapshot
          load / cold boot, when the old offset is stale), dimmed: ``dev ?``

        Hidden without a target device. Returns the text shown.
        """
        from sandroid.core import device_clock
        from sandroid.core.adb import Adb

        now = time.time() if now is None else now
        serial = Adb.get_target_device()
        sample = (
            device_clock.last_sample(serial, current_world=True) if serial else None
        )
        if not serial:
            text, state = "", ""
        elif sample is None or sample.get("off_wall") is None:
            text, state = "dev ?", "-unknown"
        else:
            when = datetime.fromtimestamp(now - sample["off_wall"])
            if device_clock.notable(sample):
                offset = device_clock.format_offset(
                    device_clock.device_minus_host(sample)
                )
                text, state = f"dev {when:%H:%M:%S} {offset} ⚠", "-off"
            else:
                text, state = f"dev {when:%H:%M:%S} ✓", "-sync"
        try:
            label = self.query_one("#device-clock", Static)
            label.update(text)
            for cls in ("-sync", "-off", "-unknown"):
                label.set_class(cls == state, cls)
        except Exception:
            pass
        return text

    def _on_click(self) -> None:  # no tall toggle
        return

    def format_title(self) -> Content:
        parts = [f"[b]{self.app.title or 'Sandroid'}[/b]"]
        if self._crumb:
            parts.append(self._crumb)
        markup = "○ " + "  [dim]▸[/dim]  ".join(parts)
        if self._snapshot:
            markup += f"   [dim]◇ {self._snapshot}[/dim]"
        try:
            return Content.from_markup(markup)
        except Exception:
            return Content(re.sub(r"\[/?[^\]]*\]", "", markup))

    def _update_title(self) -> None:
        try:
            self.query_one(HeaderTitle).update(self.format_title())
        except Exception:
            pass

    def set_crumb(self, markup: str) -> None:
        """Breadcrumb after the app name (Rich-style markup, may be empty)."""
        if markup != self._crumb:
            self._crumb = markup
            self._update_title()

    def set_snapshot(self, label: str) -> None:
        """Last loaded snapshot / slot, shown dim after the breadcrumb."""
        if label != self._snapshot:
            self._snapshot = label
            self._update_title()

    def set_pill(self, text: str, kind: str = "") -> None:
        """``kind`` is ``""`` (live), ``"review"`` or ``"rec"``."""
        self._pill = (text, kind)
        try:
            pill = self.query_one("#scope-pill", Static)
        except Exception:
            return
        blind = kind == "" and bool(self._live_note)
        shown = f"○ LIVE · {self._live_note}" if blind else text
        pill.update(Text(shown))  # a label may contain "[", never markup
        pill.set_class(kind == "" and not blind, "-live")
        pill.set_class(blind, "-blind")
        pill.set_class(kind == "review", "-review")
        pill.set_class(kind == "rec", "-rec")

    def set_live_note(self, note: str | None) -> None:
        """Qualify the LIVE pill (``"monitor blind"``); ``None`` clears it."""
        note = note or None
        if note != self._live_note:
            self._live_note = note
            self.set_pill(*self._pill)

    @property
    def pill_text(self) -> str:
        text, kind = self._pill
        if kind == "" and self._live_note:
            return f"○ LIVE · {self._live_note}"
        return text


# ---------------------------------------------------------------------------
# lens bar
# ---------------------------------------------------------------------------


class LensBar(Horizontal):
    """``1 App  2 Network  3 Files  4 Sessions  5 Timeline`` + per-lens badges.

    Clicks are routed by ``MainScreen.on_click`` (ids ``lens-tab-<lens id>``).
    Carries ``-level-active`` while Shift+←/→ cycles lenses (vs. a lens's own
    sub-tab bar after Shift+↓).
    """

    DEFAULT_CSS = """
    LensBar {
        height: 1;
        background: #0a1124;
        padding: 0 0 0 1;
        border-left: heavy #0a1124;
    }
    LensBar.-level-active {
        border-left: heavy #38bdf8;
    }
    LensBar .lens-tab {
        width: auto;
        padding: 0 2;
        margin: 0 1 0 0;
        color: #8f9bb3;
        background: #0a1124;
    }
    LensBar .lens-tab:hover {
        color: #cbd5e1;
        background: #1f2937;
    }
    LensBar .lens-tab.-active {
        color: #06121f;
        background: #38bdf8;
        text-style: bold;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._badges: dict[str, str] = {}
        self._active = LENSES[0].id

    def compose(self) -> ComposeResult:
        for spec in LENSES:
            yield Static(
                self._label(spec),
                id=f"lens-tab-{spec.id}",
                classes="lens-tab" + (" -active" if spec.id == self._active else ""),
            )

    def _label(self, spec: LensSpec) -> Text:
        text = Text()
        text.append(spec.key, style="bold")
        text.append(f" {spec.label}")
        badge = self._badges.get(spec.id)
        if badge:
            text.append(f" {badge}", style=f"bold {lens_palette().warn}")
        return text

    def _repaint(self, lens_id: str) -> None:
        spec = LENS_BY_ID.get(lens_id)
        if spec is None:
            return
        try:
            tab = self.query_one(f"#lens-tab-{lens_id}", Static)
        except Exception:
            return
        tab.update(self._label(spec))
        tab.set_class(lens_id == self._active, "-active")

    def set_active(self, lens_id: str) -> None:
        self._active = lens_id
        for spec in LENSES:
            self._repaint(spec.id)

    def set_badge(self, lens_id: str, text: str | None) -> None:
        if text:
            self._badges[lens_id] = text
        else:
            self._badges.pop(lens_id, None)
        self._repaint(lens_id)

    def badge(self, lens_id: str) -> str | None:
        return self._badges.get(lens_id)


# ---------------------------------------------------------------------------
# inspector
# ---------------------------------------------------------------------------


class Inspector(Vertical):
    """Right-hand detail view; content comes from an ``InspectorContent``."""

    DEFAULT_CSS = """
    Inspector {
        height: 1fr;
        border: round $lens-rule;
        border-title-color: $lens-title;
        border-subtitle-color: $lens-dim;
        background: $lens-bg;
        padding: 0 1;
    }
    Inspector:focus-within {
        border: round $lens-rule-focus;
    }
    Inspector #inspector-subtitle {
        height: auto;
        color: $lens-muted;
    }
    Inspector #inspector-tabs {
        height: 1;
        margin: 0 0 1 0;
        display: none;
    }
    Inspector.-tabbed #inspector-tabs {
        display: block;
    }
    Inspector #inspector-scroll {
        height: 1fr;
        scrollbar-size: 1 1;
    }
    Inspector #inspector-body {
        height: auto;
    }
    """

    BINDINGS = [
        # Display-only: Esc is an App priority binding that reaches
        # MainScreen.handle_escape first, which closes the slot.
        Binding("escape", "close", "Close"),
        # No description: the help lists MainScreen's [ ] / ←/→ instead,
        # which reach the Inspector wherever focus is.
        Binding("left", "tab(-1)", "", show=False),
        Binding("right", "tab(1)", "", show=False),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.content: InspectorContent | None = None
        self.tab_index = 0

    def on_mount(self) -> None:
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            pass

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        """Re-render the tab strip and headings (lens token colors)."""
        self._show_content()

    def compose(self) -> ComposeResult:
        yield Static("", id="inspector-subtitle")
        yield Static("", id="inspector-tabs")
        with VerticalScroll(id="inspector-scroll"):
            yield Static("", id="inspector-body")

    def show(self, content: InspectorContent) -> None:
        """Render ``content``; keeps the tab index when the tab names match."""
        old = self.content
        same_tabs = (
            old is not None
            and [t[0] for t in old.tabs] == [t[0] for t in content.tabs]
            and content.tabs
        )
        self.content = content
        if not same_tabs:
            self.tab_index = 0
        self._show_content()

    def _show_content(self) -> None:
        content = self.content
        if content is None:
            return
        self.border_title = f"Inspector · {content.title}"
        hints = [content.footer] if content.footer else []
        if content.tabs:
            hints.append(r"\[ ] tabs")
        hints.append("esc close")
        self.border_subtitle = "   ".join(hints)
        try:
            sub = self.query_one("#inspector-subtitle", Static)
            sub.update(_as_text(content.subtitle) if content.subtitle else "")
            sub.display = bool(content.subtitle)
        except Exception:
            pass
        self.set_class(bool(content.tabs), "-tabbed")
        c = lens_palette()
        if content.tabs:
            self.tab_index %= len(content.tabs)
            strip = Text()
            for i, (name, _sections) in enumerate(content.tabs):
                style = (
                    f"bold {c.accent_text} on {c.accent}"
                    if i == self.tab_index
                    else c.muted
                )
                strip.append(f" {name} ", style=style)
                strip.append("  ")
            try:
                self.query_one("#inspector-tabs", Static).update(strip)
            except Exception:
                pass
            sections = content.tabs[self.tab_index][1]
        else:
            sections = content.sections
        parts: list[RenderableType] = []
        for heading, body in sections:
            if parts:
                parts.append(Text(""))
            if heading:
                parts.append(Text(heading, style=f"bold {c.muted}"))
            parts.append(_as_renderable(body))
        try:
            self.query_one("#inspector-body", Static).update(Group(*parts))
        except Exception:
            pass

    @property
    def tab_name(self) -> str | None:
        """Name of the active tab (None without tabs)."""
        content = self.content
        if content is None or not content.tabs:
            return None
        return content.tabs[self.tab_index % len(content.tabs)][0]

    def select_tab(self, index: int) -> None:
        if self.content is None or not self.content.tabs:
            return
        self.tab_index = index % len(self.content.tabs)
        self._show_content()

    async def on_key(self, event) -> None:
        """Keys of the owning lens work while the Inspector has focus.

        The Inspector's footer advertises the lens's keys (``u pull``,
        ``z zoom`` ...), but with focus in the Inspector (Tab, or a click to
        scroll) the lens is not in the focus chain, so its bindings never
        fired. A key the focused Inspector widgets don't bind themselves is
        run as the active lens's binding instead.
        """
        lens = self._owner_lens()
        if lens is None:
            return
        focused = self.app.focused
        node = focused
        while node is not None and node is not self.parent:
            if event.key in node._bindings.key_to_bindings:
                return  # the Inspector (or its scroller) uses this key itself
            node = node.parent
        for binding in lens._bindings.key_to_bindings.get(event.key, ()):
            action_name = binding.action.split("(", 1)[0]
            if lens.check_action(action_name, ()) is False:
                continue
            event.stop()
            event.prevent_default()
            await self.app.run_action(binding.action, lens)
            return

    def _owner_lens(self):
        """The lens whose row the Inspector shows (the active lens)."""
        screen = self.screen
        getter = getattr(screen, "lens_widget", None)
        if getter is None:
            return None
        try:
            return getter()
        except Exception:
            return None

    def action_tab(self, delta: int) -> None:
        self.select_tab(self.tab_index + delta)

    def action_close(self) -> None:
        close = getattr(self.screen, "close_inspector", None)
        if close is not None:
            close()

    def on_click(self, event) -> None:
        """A click on the tab strip selects the tab under the pointer; a click
        in the body goes to the content's ``click`` handler (if any).
        """
        if self.content is None:
            return
        widget = getattr(event, "widget", None)
        if getattr(widget, "id", None) == "inspector-body" and self.content.click:
            try:
                offset = event.get_content_offset(widget)
            except Exception:
                offset = None
            if offset is not None:
                try:
                    handled = self.content.click(self.tab_name, offset.y)
                except Exception:
                    handled = False
                if handled:
                    event.stop()
            return
        if not self.content.tabs:
            return
        if getattr(widget, "id", None) != "inspector-tabs":
            return
        try:
            offset = event.get_content_offset(widget)
        except Exception:
            offset = None
        if offset is None:
            return
        x = offset.x
        pos = 0
        for i, (name, _s) in enumerate(self.content.tabs):
            width = len(name) + 4
            if pos <= x < pos + width:
                self.select_tab(i)
                return
            pos += width


# ---------------------------------------------------------------------------
# log ticker + drawer
# ---------------------------------------------------------------------------

_ALNUM = re.compile(r"[0-9A-Za-z]")
_MARKUP = re.compile(r"\[/?[^\]]*\]")
_ADB_RAW = re.compile(r"ADB command (?:warning|info) \(.*\):\s*")


def humanize_log_line(line: str) -> str:
    """Ticker form of one log line: no raw adb command lines.

    ``ADB command warning (-s emulator-5554 shell '{ printf ...}'): <stderr>``
    becomes ``adb: <stderr> (` log has the command)``; the drawer and the log
    file keep the full line.
    """
    match = _ADB_RAW.search(line)
    if match is None:
        return line
    # The command itself may contain "): " -- the stderr is what follows the
    # last one.
    head = line[: match.start()]
    rest = line[match.start() :]
    detail = rest.rsplit("): ", 1)[-1].strip() if "): " in rest else ""
    detail = detail.splitlines()[0][:160] if detail else "command failed"
    return f"{head}adb: {escape(detail)} [dim](` log has the command)[/dim]"


class LogTicker(Horizontal):
    """One row: the newest meaningful log line, plus a dim "` log" hint."""

    DEFAULT_CSS = """
    LogTicker {
        height: 1;
        background: #080c18;
        color: #93a4c3;
        padding: 0 1;
    }
    LogTicker #log-ticker-line {
        width: 1fr;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    LogTicker #log-ticker-hint {
        width: auto;
        color: #5b6479;
        padding: 0 0 0 2;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.last_line = ""

    def compose(self) -> ComposeResult:
        yield Static("", id="log-ticker-line")
        yield Static("` log", id="log-ticker-hint")

    def show_line(self, content: Any) -> None:
        """Mirror one ActivityLog line (markup string or renderable)."""
        if isinstance(content, str):
            plain = _MARKUP.sub("", content).strip()
            if not _ALNUM.search(plain):
                return  # blank lines, separators, logo art
            # A multi-line entry (a traceback, a block of tool output) shows
            # its first line -- "ERROR: Task exception ..." reads better than
            # the exception repr at the bottom.
            lines = [ln for ln in content.strip().splitlines() if _ALNUM.search(ln)]
            first = humanize_log_line(lines[0] if lines else content.strip())
            plain = _MARKUP.sub("", first).strip()
            renderable: Any = _as_text(first)
            renderable.no_wrap = True
            renderable.overflow = "ellipsis"
        else:
            plain = str(content)
            renderable = content
        self.last_line = plain
        try:
            self.query_one("#log-ticker-line", Static).update(renderable)
        except Exception:
            pass

    def set_drawer_open(self, is_open: bool) -> None:
        try:
            self.query_one("#log-ticker-hint", Static).update(
                "` close log" if is_open else "` log"
            )
        except Exception:
            pass

    def on_click(self) -> None:
        toggle = getattr(self.screen, "toggle_log_drawer", None)
        if toggle is not None:
            toggle()


class LogDrawer(Vertical):
    """Bottom drawer (~12 rows) holding the ActivityLog; hidden by default."""

    DEFAULT_CSS = """
    LogDrawer {
        display: none;
        height: 12;
        border-top: solid #1f2d4d;
        background: #080c18;
        padding: 0 0 0 1;
    }
    LogDrawer.-open {
        display: block;
    }
    LogDrawer > ActivityLog {
        /* Lines wrap to the drawer; a horizontal scrollbar only left a
           stray thumb glyph in the bottom row at 80-100 columns. */
        overflow-x: hidden;
    }
    """
