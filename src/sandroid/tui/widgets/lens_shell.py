"""Lens shell: the pieces of the "Lenses + Inspector" main-screen layout.

Layout (top to bottom, see ``MainScreen.compose``)::

    ShellHeader   #shell-header   breadcrumb · snapshot · scope pill · clock
    StatusBar     #status-bar     1-2 rows of live tool state
    LensBar       #lens-bar       1 App  2 Network  3 Files  4 Runs  (+ badges)
    #workspace    Horizontal
      #lens-host  framed ContentSwitcher #lens-body holding the four lenses
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
``runs``   4    Runs         ``runs-panel``         DiffsView (diffs_view)
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
  a row of those widgets posts). Returning ``None`` does nothing. A lens
  that handles Enter itself (SpotlightPanel's Start/Resume) simply does not
  implement the hook, or calls ``self.screen.open_inspector(...)`` itself.
  Note: the footer shows one binding per key, the focused widget's first;
  a focused OptionList/DataTable owns a hidden Enter binding, so advertise
  "⏎ inspect" in the lens itself (e.g. via ``set_lens_caption`` info).
* ``on_scope_changed(message: ScopeChanged)`` -- normal Textual message
  handler; ``MainScreen`` posts a (non-bubbling) ``ScopeChanged`` to every
  lens widget whenever the scope changes. Alternatively watch the reactive:
  ``self.watch(self.screen, "scope_run", callback)``.

Use ``is_shown(widget)`` (below) instead of querying ``#lens-body`` to gate
slow polls on visibility.

Inspector
---------
``InspectorContent`` (dataclass) describes what the right-hand Inspector
shows: ``title``, optional ``subtitle``, ordered ``sections`` of
``(heading, renderable)`` (a ``str`` is Rich markup; any Rich renderable --
``Table.grid()``, ``Syntax``, ``Text`` -- works), optional ``footer`` key
hints (shown on the frame's bottom edge), optional ``tabs`` (a sequence of
``(tab name, sections)``; when given, ``sections`` is ignored and ←/→ or a
click switches tabs), and an optional ``key`` identifying the inspected row.

* ``MainScreen.open_inspector(content)`` -- opens the side slot (closing the
  AI chat if it was there) or replaces the content in place.
* ``MainScreen.update_inspector(content)`` -- replace in place, only if the
  Inspector is open (no-op otherwise): use it for live row changes. Compare
  ``MainScreen.inspector_content.key`` to know whether the open Inspector
  still shows your row. The active tab is kept when the tab names match.
* ``MainScreen.close_inspector()`` / ``MainScreen.inspector_is_open``.
* Focus stays in the lens when the Inspector opens, so ↑/↓ + Enter keep
  working; Tab or a click moves focus into the Inspector to scroll it.
* Esc closes the side slot (Inspector or chat) before anything else on the
  main screen; with nothing open it falls through to the old behaviour.

Scope (LIVE / REVIEW)
---------------------
* ``MainScreen.set_scope(run_id | None, label=None)`` -- ``None`` = live.
  The header pill shows ``● LIVE`` or ``◆ REVIEW <label or "Run <id>">``
  (``● REC`` / ``● REPLAY`` while recording/replaying in live scope).
* ``MainScreen.scope_run`` -- reactive (watchable) current run id or None;
  ``MainScreen.scope`` is the plain getter.
* ``ScopeChanged(run_id, label)`` is posted to every lens widget on change.

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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widgets import Header, Static
from textual.widgets._header import HeaderClock, HeaderTitle

if TYPE_CHECKING:
    from collections.abc import Hashable, Sequence

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
    LensSpec("runs", "4", "Runs", "runs-panel"),
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
    #: Filled in by ``MainScreen.open_inspector`` (the active lens id).
    lens: str | None = field(default=None, compare=False)


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
    """One-row header: ``○ Sandroid ▸ device ▸ app ◇ snapshot``, pill, clock.

    Subclasses Textual's ``Header`` so theme rules for ``Header`` apply and the
    clock/title plumbing is reused; only the title formatting and the extra
    scope pill are ours.
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
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(show_clock=True, **kwargs)
        self._crumb = ""
        self._snapshot = ""
        self._pill = ("● LIVE", "")

    def compose(self) -> ComposeResult:
        yield HeaderTitle()
        yield Static(self._pill[0], id="scope-pill", classes="-live")
        yield HeaderClock().data_bind(Header.time_format)

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
        pill.update(text)
        pill.set_class(kind == "", "-live")
        pill.set_class(kind == "review", "-review")
        pill.set_class(kind == "rec", "-rec")

    @property
    def pill_text(self) -> str:
        return self._pill[0]


# ---------------------------------------------------------------------------
# lens bar
# ---------------------------------------------------------------------------


class LensBar(Horizontal):
    """``1 App  2 Network  3 Files  4 Runs`` with optional per-lens badges.

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
            text.append(f" {badge}", style="bold #fbbf24")
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
        border: round #1f2d4d;
        border-title-color: #7dd3fc;
        border-subtitle-color: #5b6479;
        background: #050811;
        padding: 0 1;
    }
    Inspector:focus-within {
        border: round #38bdf8;
    }
    Inspector #inspector-subtitle {
        height: auto;
        color: #8f9bb3;
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
        Binding("left", "tab(-1)", "Prev tab", show=False),
        Binding("right", "tab(1)", "Next tab", show=False),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.content: InspectorContent | None = None
        self.tab_index = 0

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
        hints = f"{content.footer}   esc close" if content.footer else "esc close"
        self.border_subtitle = hints
        try:
            sub = self.query_one("#inspector-subtitle", Static)
            sub.update(_as_text(content.subtitle) if content.subtitle else "")
            sub.display = bool(content.subtitle)
        except Exception:
            pass
        self.set_class(bool(content.tabs), "-tabbed")
        if content.tabs:
            self.tab_index %= len(content.tabs)
            strip = Text()
            for i, (name, _sections) in enumerate(content.tabs):
                style = "bold #06121f on #38bdf8" if i == self.tab_index else "#8f9bb3"
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
                parts.append(Text(heading, style="bold #8f9bb3"))
            parts.append(_as_renderable(body))
        try:
            self.query_one("#inspector-body", Static).update(Group(*parts))
        except Exception:
            pass

    def select_tab(self, index: int) -> None:
        if self.content is None or not self.content.tabs:
            return
        self.tab_index = index % len(self.content.tabs)
        self._show_content()

    def action_tab(self, delta: int) -> None:
        self.select_tab(self.tab_index + delta)

    def action_close(self) -> None:
        close = getattr(self.screen, "close_inspector", None)
        if close is not None:
            close()

    def on_click(self, event) -> None:
        """A click on the tab strip selects the tab under the pointer."""
        if self.content is None or not self.content.tabs:
            return
        widget = getattr(event, "widget", None)
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
            renderable: Any = _as_text(content.strip().splitlines()[-1])
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
    """
