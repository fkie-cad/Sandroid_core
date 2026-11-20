"""TUI panel giving on-screen feedback + control for the spotlight app.

The spotlight is one app *selection* (``c`` use the foreground app /
``Shift+C`` pick an app…) with no spawn/attach mode. This panel shows which
app, its **live running state** (running pid N / paused / not running) and
which Frida hooks/bypasses are active, and offers explicit lifecycle actions
(Start / Restart / Kill / Attach, plus the advanced Start-paused / Resume)
together with immediate bypass toggles. Tools decide per start whether they
join, attach or start the app (:mod:`sandroid.services.app_start`); a restart
of a running app always asks, except ⇧R, the explicit restart key.

It is intentionally **stateless**: it owns no manager instances and reads
everything live from the process-wide services (BypassService, SpotlightService,
TaskService). Textual recreates widgets on screen change, so keeping state here
would orphan running Frida jobs — the services are the single source of truth.

Blocking lifecycle actions (spawn + wait-for-hooks + resume) run on worker
threads; UI updates are always marshalled back to the Textual main thread.

Below the live state the lens shows what the app is, may do, exposes and
resists (IDENTITY · PERMISSIONS · EXPOSURE · MANIFEST & NETWORK · TRACKERS &
SDKs · DATA · SUSPECTED DEFENCES): :class:`~.app_lens.AppLensSections`,
which owns that data (off-thread loads, generation-tagged results). Enter
inspects the selected row, Space starts / resumes the app.
"""

from __future__ import annotations

import concurrent.futures
import functools
import logging
import re
import threading
import time
from typing import TYPE_CHECKING

from rich.markup import escape
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Input, Static

from sandroid.tui.modals.base import FridaModal as _FridaModalBase
from sandroid.tui.modals.objection_modal import BYPASS_KEYS
from sandroid.tui.themes import lens_palette
from sandroid.tui.utils.ui_thread import UiDispatcher
from sandroid.tui.widgets.app_lens import LABEL_WIDTH, LENS_ID, AppLensSections

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from sandroid.tui.widgets.lens_shell import InspectorContent

logger = logging.getLogger(__name__)

# (chord digit, category, label) for the immediate bypass toggles: ``b`` then
# the digit (BypassChordModal). Built from the one digit table the Objection
# modal uses too (``BYPASS_KEYS``). All bypass tiers are experimental, hence
# the "(exp.)" tag.
_BYPASS_TOGGLES = [(key, cat, f"{label} (exp.)") for key, cat, label in BYPASS_KEYS]

# Clickable action-cell id -> panel action method. Routed from
# MainScreen.on_click (same dispatch as the bottom tab bar / arrow).
_ACTION_CELLS = {
    "act-primary": "action_primary",
    "act-restart": "action_restart_app",
    "act-attach": "action_attach_app",
    "act-paused": "action_start_paused",
    "act-kill": "action_kill_app",
    "act-clear": "action_clear_spotlight",
}

# Action-row cell id -> (label, label below _NARROW_WIDTH columns).
_ACTION_LABELS = {
    "act-restart": ("⇧R restart", "⇧R"),
    "act-attach": ("⇧A attach", "⇧A"),
    "act-paused": ("⇧P pause", "⇧P"),
    "act-kill": ("⇧K kill", "⇧K"),
    "act-clear": ("⇧X clear", "⇧X"),
}
# Below this panel width the action row shows the keys only.
_NARROW_WIDTH = 60
# Below this width the bypass toggles collapse to one "b bypass: ..." line
# (the full row is ~95 columns).
_COMPACT_WIDTH = 98

# How often the slow fallback poll re-checks the app's PID (seconds).
_POLL_INTERVAL = 4.0
# While another tab is shown, poll only every Nth tick: the header's App row
# reads the same PID and showed a dead attach PID as "running" for >= 49 s
# after an external restart (phase 4) when the poll stopped with the tab.
_HIDDEN_POLL_EVERY = 2


#: ``ProcessRecord{<hash> <pid>:<name>/<uid>}`` in ``dumpsys activity
#: processes`` (the PID is matched as a whole number, never a prefix).
_AM_RECORD = re.compile(r"ProcessRecord\{[0-9a-fA-F]+ (\d+):")


def _is_static_analysis_end(event) -> bool:
    """True for the event that ends a static analysis (``a``).

    ``StaticAnalysis`` publishes ``AnalysisCompleted`` (a STATE_CHANGED with
    source ``static_analysis``) after recording the Insight result in the
    APK cache; a task-runner TASK_STOPPED of a static-analysis task counts
    too.
    """
    try:
        from sandroid.core.events import EventType

        if getattr(event, "type", None) == EventType.TASK_STARTED:
            return False
        if getattr(event, "source", None) == "static_analysis":
            return True
        data = getattr(event, "data", None) or {}
        name = str(data.get("task_name") or "") if isinstance(data, dict) else ""
        return "static" in name.lower() and "analysis" in name.lower()
    except Exception:
        return False


class SpotlightPanel(Widget):
    """Bottom-left panel: spotlight app status + live state + actions.

    Bindings (when focused):
        b then 1-6: toggle/arm SSL / Root / Frida / Debug / Integrity /
                 Emulator bypass
                 (``b`` then ``o`` launches Objection, the global ``b``)
        Space:   primary (Start if stopped · Resume if paused; never restarts)
        Enter:   inspect the selected section row (MainScreen → Inspector)
        /:       filter the rows of all sections (Esc clears)
        z:       fold / unfold the focused section
        u:       refresh runtime facts (grants, AppOps, footprint, services)
        R:       restart (force-stop + respawn with armed hooks; no dialog)
        A:       attach to the live process + apply armed hooks
        P:       start paused (advanced; Space then resumes; asks before
                 restarting a running app; Android ends a hold after ~10 s)
        K:       kill the app and stop its tools; the bypasses that were on
                 stay armed, so Space starts with them
        X:       clear the spotlight selection

    Lowercase s/r/a/p/x are deliberately NOT bound — they shadow the
    destructive global shortcuts (Screenshot/Record/Analyze/Play/Export);
    ``a`` (static analysis) is what the TRACKERS section points to. ``/``,
    ``z`` and ``u`` are no global keys (``u`` is the Files lens's pull, in
    that lens only), and the focused section tables (DataTable) bind none of
    Space / ``/`` / ``z`` / ``u`` / ``b``.
    Digits are the global lens keys, so the bypass toggles are a ``b`` chord
    (shadowing the global ``b`` = Objection only while this lens has focus;
    the chord offers Objection as ``o``).
    The action row is also clickable.
    """

    DEFAULT_CSS = """
    SpotlightPanel {
        layout: vertical;
        height: 1fr;
        background: $lens-panel;
    }
    SpotlightPanel > #spotlight-header {
        height: 1;
        color: $lens-accent;
        text-style: bold;
        padding: 0 1;
    }
    SpotlightPanel > #spotlight-scroll {
        height: 1fr;
        background: $lens-bg;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }
    SpotlightPanel #spotlight-body {
        height: auto;
        margin: 0;
        background: $lens-bg;
        color: $lens-text;
    }
    SpotlightPanel > #app-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: $lens-input-bg;
        color: $lens-input-text;
    }
    SpotlightPanel > #app-filter.-open {
        display: block;
    }
    SpotlightPanel > #app-filter:focus {
        border: none;
        background: $lens-input-focus-bg;
    }
    SpotlightPanel > #spotlight-actions {
        height: 1;
        dock: bottom;
        background: $lens-action-bg;
    }
    SpotlightPanel .act-cell {
        width: auto;
        padding: 0 1;
        color: $lens-action-text;
    }
    SpotlightPanel .act-cell:hover {
        background: $lens-action-hover-bg;
        color: $lens-action-hover-text;
        text-style: bold;
    }
    """

    # Only Start/Resume goes into the global footer: the bypass toggles and
    # the Shift-letter actions are already shown (and clickable) inside the
    # panel itself, and listing all 11 pushed the global keys (r Record,
    # p Play, ? Help, ...) off a 200-column footer. Enter is MainScreen's
    # "inspect" (a focused section table posts RowSelected); the lens frame
    # caption advertises ⏎ / z / u.
    BINDINGS = [
        Binding("space", "primary", "Start/Resume", key_display="␣"),
        Binding("b", "bypass_chord", "Bypass…"),
        Binding("slash", "filter", "Filter rows", show=False),
        Binding("z", "fold", "Fold/unfold section", show=False),
        Binding("u", "refresh_facts", "Refresh app facts", show=False),
        Binding("R", "restart_app", "Restart", show=False),
        Binding("A", "attach_app", "Attach", show=False),
        Binding("P", "start_paused", "Start paused", show=False),
        Binding("K", "kill_app", "Kill", show=False),
        Binding("X", "clear_spotlight", "Clear", show=False),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        self._ui = UiDispatcher()
        # Slow fallback poll bookkeeping.
        self._poll_timer = None
        self._poll_inflight = False
        self._hidden_ticks = 0
        self._last_running_state: bool | None = None
        # Guard against overlapping blocking actions (spawn/kill/restart).
        self._action_inflight = False
        self._filter_timer = None
        # Layout mode from the panel width (on_resize).
        self._compact = False
        self._narrow = False
        # (package, profile id) while the identity profile was not applied
        # to the app; read off the UI thread (poll, identity status events).
        self._identity_gap: tuple[str, str] | None = None

    # -- services (lazy) --------------------------------------------------

    @staticmethod
    def _spotlight():
        from sandroid.services import get_spotlight_service

        return get_spotlight_service()

    @staticmethod
    def _bypass():
        from sandroid.analysis.detection_bypass import get_bypass_service

        return get_bypass_service()

    @staticmethod
    def _tasks():
        from sandroid.services import get_task_service

        return get_task_service()

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="spotlight-header")
        yield Input(
            placeholder="filter rows of all sections (Esc clears)", id="app-filter"
        )
        with VerticalScroll(id="spotlight-scroll", can_focus=False):
            yield Static(self._render_body(), id="spotlight-body")
            yield AppLensSections(id="app-sections")
        with Horizontal(id="spotlight-actions"):
            yield Static(self._primary_label(), id="act-primary", classes="act-cell")
            # Shift-letters, shown as ⇧X so they never read like the global
            # lower-case r/p/a/k/x keys.
            for cell_id, (wide, _short) in _ACTION_LABELS.items():
                yield Static(wide, id=cell_id, classes="act-cell")

    def on_resize(self, event) -> None:
        """Compact bypass row / key-only action row on a narrow lens."""
        width = event.size.width
        compact, narrow = width < _COMPACT_WIDTH, width < _NARROW_WIDTH
        if (compact, narrow) == (self._compact, self._narrow):
            # The bypass key hint comes and goes with the width.
            try:
                self.query_one("#spotlight-body", Static).update(self._render_body())
            except Exception:
                pass
            return
        self._compact, self._narrow = compact, narrow
        for cell_id, (wide, short) in _ACTION_LABELS.items():
            try:
                self.query_one(f"#{cell_id}", Static).update(short if narrow else wide)
            except Exception:
                pass
        self.refresh_panel()

    def on_mount(self) -> None:
        self._subscribe_events()
        self.refresh_panel()
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_text)
        except Exception:
            logger.debug("Spotlight panel: no theme signal", exc_info=True)
        # Event-driven transitions cover the common cases; this slow poll is
        # the safety net that catches the app dying on its own. Stopped in
        # on_unmount; each tick is a no-op when no app is selected or the
        # strip is collapsed.
        self._poll_timer = self.set_interval(_POLL_INTERVAL, self._poll_running_state)
        try:
            from sandroid.services.identity import get_identity_service

            get_identity_service().add_status_listener(self._on_identity_status)
        except Exception:
            logger.debug("Spotlight panel: no identity status", exc_info=True)
        from sandroid.services.app_start import add_pre_start_status_listener

        add_pre_start_status_listener(self._on_pre_start_status)

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        try:
            from sandroid.services.identity import get_identity_service

            get_identity_service().remove_status_listener(self._on_identity_status)
        except Exception:
            pass
        from sandroid.services.app_start import remove_pre_start_status_listener

        remove_pre_start_status_listener(self._on_pre_start_status)
        if self._poll_timer is not None:
            try:
                self._poll_timer.stop()
            except Exception:
                pass
            self._poll_timer = None

    def _on_pre_start_status(self) -> None:
        """A pre-start step began or ended (any thread): repaint the header."""
        self._post(self._repaint_text)

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            # Thread -> UI hand-off in the UI's contextvars context (see
            # sandroid.tui.utils.ui_thread: a bare loop callback lacks
            # Textual's active_app and its timers raised LookupError).
            self._ui = UiDispatcher.capture()
            self._main_loop = self._ui.loop

            bus = EventBus.get()

            def _make_cb(state_changed: bool):
                def _cb(event) -> None:
                    # Fire-and-forget onto the main loop; never blocks the
                    # publisher's thread (avoids the call_from_thread deadlock).
                    self._ui.post(self.refresh_panel)
                    if state_changed:
                        self._ui.post(self._facts_state_changed)
                    if _is_static_analysis_end(event):
                        self._ui.post(self._static_analysis_finished)

                return _cb

            for event_type in (
                EventType.STATE_CHANGED,
                EventType.TASK_STARTED,
                EventType.TASK_STOPPED,
            ):
                cb = _make_cb(event_type == EventType.STATE_CHANGED)
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"SpotlightPanel event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    # -- thread marshalling ----------------------------------------------

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread (fire-and-forget).

        Safe to call from worker threads. Used for refresh + notify so we
        never touch widgets off the main thread.
        """
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        self._ui.post(fn, *args)

    # -- rendering --------------------------------------------------------

    def _current_package(self) -> str | None:
        try:
            return self._spotlight().get_effective_package()
        except Exception:
            return None

    def _safe_pid(self) -> int | None:
        try:
            return self._spotlight().get_pid()
        except Exception:
            return None

    def _is_paused(self) -> bool:
        try:
            return bool(self._spotlight().is_app_paused())
        except Exception:
            return False

    def _restarting(self) -> bool:
        try:
            return bool(self._spotlight().is_restarting())
        except Exception:
            return False

    def _on_categories(self) -> list[str]:
        """Categories that are armed OR active (rendered ON)."""
        try:
            return self._bypass().on_categories()
        except Exception:
            return []

    def _hooks_for_app(self, package: str | None) -> list:
        if not package:
            return []
        try:
            tasks = self._tasks().get_running_tasks()
        except Exception:
            return []
        # The file monitor registers with the app's name too; not a hook.
        return [
            t
            for t in tasks
            if getattr(t, "app_name", None) == package
            and getattr(t, "name", None) != "monitor"
        ]

    def _render_header(self) -> str:
        c = lens_palette()
        package = self._current_package()
        if not package:
            return (
                f"[{c.bad}]○ no app[/] — [b]c[/] use the foreground app · "
                "[b]⇧C[/] pick an app…"
            )

        pid = self._safe_pid()
        paused = self._is_paused()
        hooks = self._hooks_for_app(package)
        on = self._on_categories()

        from sandroid.services.app_start import pre_start_status

        step = pre_start_status(package)
        if step and self.size.width and len(step) + len(package) + 40 > self.size.width:
            step = pre_start_status(package, short=True)
        if step:
            # Identity's apply can take minutes: say so, not "not running".
            state = f"[{c.warn}]{escape(step)}[/]"
        elif paused:
            pid_part = f" pid [b]{pid}[/]" if pid else ""
            state = f"[{c.warn}]◐ paused[/]{pid_part} [{c.dim}]· ␣ resume[/]"
        elif pid:
            state = f"[{c.ok}]● running[/] pid [b]{pid}[/]"
        elif self._restarting():
            state = f"[{c.warn}]◌ restarting…[/]"
        else:
            state = f"[{c.bad}]○ not running[/] [{c.dim}]· ␣ start[/]"

        bypass_tag = (
            f"[{c.ok}]bypass: {','.join(on)}[/]" if on else f"[{c.dim}]bypass: none[/]"
        )
        return f"{state}  [b]{package}[/]  hooks: [b]{len(hooks)}[/]  {bypass_tag}"

    def _render_body(self) -> str:
        c = lens_palette()
        spotlight = self._spotlight()
        package = self._current_package()

        if not package:
            return (
                f"[{c.dim}]No app selected.\n\n"
                "Press [b]c[/] to use the foreground app or [b]⇧C[/] to pick "
                "an app…; then [b]␣[/] starts it, [b]⇧A[/] attaches.[/]"
            )

        # Three rows on the gutter the sections below use (right-aligned
        # labels, values in one column): activity, hooks, bypass toggles.
        # Package, PID and counts are on the header line above.
        width = 9 if self._compact else LABEL_WIDTH

        def row(label: str, value: str, sep: str = "  ") -> str:
            return f" [{c.label}]{label.rjust(width)}[/]{sep}{value}"

        lines: list[str] = []
        try:
            activity = spotlight.get_activity_name() or "—"
        except Exception:
            activity = "—"
        lines.append(row("activity", escape(str(activity))))

        hooks = self._hooks_for_app(package)
        names = [
            escape(str(getattr(t, "display_name", getattr(t, "name", "task"))))
            for t in hooks
        ]
        lines.append(
            row(
                "hooks",
                "  ".join(f"[{c.ok}]●[/] {n}" for n in names) or f"[{c.dim}]none[/]",
            )
        )
        identity = self._identity_line(package, width)

        # Immediate bypass toggles (armed | active)
        on = set(self._on_categories())
        if self._compact:
            # Narrow lens (e.g. 100x30 with the Inspector open): one line.
            names = [c for _k, c, _l in _BYPASS_TOGGLES if c in on]
            state = f"[{c.ok}]{','.join(names)}[/]" if names else f"[{c.dim}]none[/]"
            lines.append(
                row(
                    "b bypass:",
                    f"{state} [{c.dim}](b then 1-{len(_BYPASS_TOGGLES)})[/]",
                    " ",
                )
            )
            if identity:
                lines.append(row("identity", identity))
            return "\n".join(lines)
        # Toggles wrap onto continuation lines aligned with the values; the
        # key hint follows when there is room for it.
        room = self.size.width - 2 - (width + 3)
        gap = "   "
        cells = []
        for key, category, label in _BYPASS_TOGGLES:
            is_on = category in on
            color = c.ok if is_on else c.dim
            mark = "●" if is_on else "○"
            plain = f"{key} {mark} {label}"
            cells.append((len(plain), f"[{color}][b]{key}[/] {mark} {label}[/]"))
        hint = f"b then 1-{len(_BYPASS_TOGGLES)} · armed applies on Start"
        cells.append((len(hint), f"[{c.dim}]{hint}[/]"))
        rows: list[list[str]] = [[]]
        used = 0
        for index, (length, markup) in enumerate(cells):
            extra = length + (len(gap) if rows[-1] else 0)
            if rows[-1] and used + extra > room:
                if index == len(cells) - 1:
                    break  # the hint only goes where it fits
                rows.append([])
                used, extra = 0, length
            rows[-1].append(markup)
            used += extra
        lines.append(row("bypass", gap.join(rows[0])))
        lines += [" " * (width + 3) + gap.join(r) for r in rows[1:]]
        if identity:
            lines.append(row("identity", identity))
        return "\n".join(lines)

    def _identity_line(self, package: str, label_width: int) -> str:
        """One warn line while the running app lacks the identity profile.

        Not while the app is stopped: the pre-start step covers its next
        start. Shortened when the full sentence does not fit.
        """
        gap = self._identity_gap
        if gap is None or gap[0] != package:
            return ""
        if not (self._safe_pid() or self._is_paused()):
            return ""
        name = escape(gap[1])
        full = (
            f"Identity profile '{name}' not applied to this app — it started "
            "before the profile. ⇧R restarts it with the profile; Space in the "
            "Identity lens applies the live values without a restart."
        )
        short = (
            f"Identity profile '{name}' not applied to this app — ⇧R restarts "
            "it with the profile"
        )
        room = self.size.width - 2 - (label_width + 3)
        text = full if self.size.width and len(full) <= room else short
        return f"[{lens_palette().warn}]{text}[/]"

    def _read_identity_gap(self, package: str | None) -> bool:
        """Re-read whether ``package`` lacks the identity profile (worker
        thread: loads the profile file). Returns True when it changed.
        """
        gap = None
        if package:
            try:
                from sandroid.services.identity import get_identity_service

                svc = get_identity_service()
                if svc.applied_state(package) == "not_applied":
                    gap = (package, str(svc.config().profile))
            except Exception:
                logger.debug("Identity applied state unreadable", exc_info=True)
        changed = gap != self._identity_gap
        self._identity_gap = gap
        return changed

    def _on_identity_status(self, _statuses: list) -> None:
        """Identity plan/apply/verify finished (worker thread)."""
        if self._read_identity_gap(self._current_package()):
            self._post(self._repaint_text)

    def _primary_label(self) -> str:
        """Context-sensitive label for the Space / primary action cell."""
        if not self._current_package():
            return "␣ Start"
        if self._is_paused():
            return "␣ Resume"
        if self._safe_pid():
            return f"[{lens_palette().dim}]● running[/]"
        return "␣ Start"

    def _repaint_text(self, _theme: object = None) -> None:
        """Re-render the header, body and primary cell (also on theme change:
        their markup colors come from the theme's lens tokens).
        """
        try:
            self.query_one("#spotlight-header", Static).update(self._render_header())
            self.query_one("#spotlight-body", Static).update(self._render_body())
            self.query_one("#act-primary", Static).update(self._primary_label())
        except Exception:
            pass

    def refresh_panel(self) -> None:
        self._repaint_text()
        package = self._current_package()
        sections = self._sections()
        if sections is not None:
            try:
                sections.track(package, self._safe_pid() if package else None)
            except Exception:
                logger.debug("App lens sections track failed", exc_info=True)
        self._update_caption()
        # The header's App row reads the same (cached) PID: keep both in step
        # (it said "not running" while this panel showed the live PID).
        try:
            self.screen._safe_refresh_status_bar()
        except Exception:
            pass

    # -- sections (App lens body) -----------------------------------------

    def _sections(self) -> AppLensSections | None:
        try:
            return self.query_one("#app-sections", AppLensSections)
        except Exception:
            return None

    def _has_sections(self) -> bool:
        sections = self._sections()
        return sections is not None and sections.facts is not None

    def _update_caption(self) -> None:
        """Lens frame caption: the lens keys (footers show one key per row)."""
        info = None
        if self._has_sections():
            sections = self._sections()
            info = "⏎ inspect · / filter · z or click title: fold · u refresh"
            primary = self._primary_hint()
            if primary:
                info += f" · {primary}"
            if sections is not None and sections.filter_text:
                info = f"“{sections.filter_text}” · " + info
        try:
            self.screen.set_lens_caption(LENS_ID, info=info)
        except Exception:
            pass

    def _primary_hint(self) -> str:
        """``␣ start`` / ``␣ resume`` / ``""`` (running: Space does nothing)."""
        if self._is_paused():
            return "␣ resume"
        if self._safe_pid():
            return ""
        return "␣ start"

    def _facts_state_changed(self) -> None:
        sections = self._sections()
        if sections is not None:
            sections.note_state_changed()

    def _static_analysis_finished(self) -> None:
        sections = self._sections()
        if sections is not None:
            sections.static_analysis_finished()

    def focus(self, scroll_visible: bool = True):
        """Focus the last-used section table when an app is shown.

        ``MainScreen`` focuses the lens on activation; ↑/↓ and Enter then
        work on the section rows right away. Without an app the panel
        itself keeps focus.
        """
        sections = self._sections()
        if sections is not None and sections.focus_first():
            return self
        return super().focus(scroll_visible)

    def on_lens_activated(self) -> None:
        sections = self._sections()
        if sections is not None:
            sections.on_lens_activated()
        self._update_caption()

    def inspect_selected(self) -> InspectorContent | None:
        """Enter: the Inspector page of the selected section row."""
        sections = self._sections()
        if sections is None or sections.facts is None:
            return None
        return sections.inspect_selected()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("filter", "fold", "refresh_facts"):
            return self._has_sections()
        return True

    def action_fold(self) -> None:
        """``z``: fold / unfold the focused (or last focused) section."""
        sections = self._sections()
        if sections is not None:
            sections.toggle_fold()

    def action_refresh_facts(self) -> None:
        """``u``: re-read grants, AppOps, footprint, services (+ static cache)."""
        sections = self._sections()
        if sections is None:
            return
        if sections.refresh_runtime(static=True, explicit=True):
            self._notify("Refreshing app facts…", "information")
        else:
            self._notify(
                "Refreshing app facts right after the running fetch…", "information"
            )

    def action_filter(self) -> None:
        try:
            box = self.query_one("#app-filter", Input)
        except Exception:
            return
        box.add_class("-open")
        box.focus()

    def _set_filter(self, text: str) -> None:
        self._filter_timer = None
        sections = self._sections()
        if sections is not None:
            sections.set_filter(text)
        self._update_caption()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "app-filter":
            return
        event.stop()
        if self._filter_timer is not None:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
        value = event.value
        try:
            self._filter_timer = self.set_timer(0.15, lambda: self._set_filter(value))
        except Exception:
            self._set_filter(value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "app-filter":
            return
        event.stop()
        self._set_filter(event.value)
        if not event.value.strip():
            event.input.remove_class("-open")
        self.focus()

    def handle_escape(self) -> bool:
        """Esc (MainScreen hook): clear the ``/`` filter (input or applied)."""
        try:
            box = self.query_one("#app-filter", Input)
        except Exception:
            return False
        sections = self._sections()
        applied = sections.filter_text if sections is not None else ""
        focused = self.screen.focused if self.is_attached else None
        if focused is not box and not applied:
            return False
        if self._filter_timer is not None:
            try:
                self._filter_timer.stop()
            except Exception:
                pass
            self._filter_timer = None
        had_filter = bool(applied or box.value.strip())
        box.value = ""
        box.remove_class("-open")
        self._set_filter("")
        self.focus()
        if had_filter:
            self._notify("Filter cleared", "information")
        return True

    # -- live running-state poll (slow fallback) --------------------------

    def _is_active_child(self) -> bool:
        """True if this panel (the App lens) is the visible lens."""
        from .lens_shell import is_shown

        return is_shown(self)

    def _poll_running_state(self) -> None:
        """Timer tick (main thread): re-check the app's PID off-thread.

        No-op when nothing is selected or a lifecycle action is in flight
        (Start/Restart/Kill own the PID while they run — the poll must not
        clobber their set_pid with a stale sample taken during the force-stop
        window). While another tab is shown only every
        ``_HIDDEN_POLL_EVERY``-th tick polls. A single in-flight guard also
        skips the tick if the previous worker is still running so a slow ADB
        call can never stack up.
        """
        if self._poll_inflight or self._action_inflight:
            return
        package = self._current_package()
        if not package:
            return
        if not self._is_active_child():
            # Hidden: still notice an app that died or was restarted outside
            # Sandroid (the header shows this PID), at a lower rate.
            self._hidden_ticks += 1
            if self._hidden_ticks % _HIDDEN_POLL_EVERY:
                return
        self._poll_inflight = True
        self.run_worker(
            functools.partial(self._poll_worker, package),
            name="spotlight_pid_poll",
            exclusive=False,
            thread=True,
        )

    def _poll_worker(self, package: str) -> None:
        """Worker-thread body of the poll. Writes PID; refreshes on change."""
        pid = None
        try:
            from sandroid.core.adb import Adb

            # Skip the heavyweight Frida fallback in this hot path, and stay
            # quiet about misses — "not running" is the expected state for a
            # spawn-selected app awaiting Start, so it must not spam warnings.
            pid = Adb.get_pid_for_package_name(
                package, use_frida_fallback=False, quiet=True
            )
        except Exception as exc:
            logger.debug(f"PID poll failed for {package}: {exc}")
        finally:
            self._poll_inflight = False

        # A lifecycle action that started while we were sampling owns the PID;
        # don't overwrite its set_pid with this (now stale) reading.
        if self._action_inflight:
            return

        try:
            previous_pid = self._spotlight().get_pid()
            self._spotlight().set_pid(pid)
        except Exception:
            previous_pid = pid

        # Self-heal a stale "paused" indicator against the live process.
        self._reconcile_paused_flag(pid)

        running = pid is not None
        identity_changed = self._read_identity_gap(package)
        # A respawn (dexray/friTap spawn, crash + relaunch) keeps the app
        # "running" but changes its PID: repaint then too, or the panel keeps
        # showing the old PID.
        if running != self._last_running_state or pid != previous_pid:
            self._last_running_state = running
            self._post(self.refresh_panel)
        elif identity_changed:
            self._post(self._repaint_text)

    @staticmethod
    def _parse_am_process_attached(dump: str, pid: int) -> bool:
        """True if ``dumpsys activity processes`` shows *pid* bound to the system.

        ``/proc/<pid>/status`` cannot tell a held spawn from a running app:
        frida 17 holds it without ptrace, so it reads ``State S`` and
        ``TracerPid 0`` either way (verified on API 35). ActivityManager can:
        a held spawn never ran ``attachApplication``, so its ProcessRecord has
        ``thread=null``; a resumed app has an ``IApplicationThread`` proxy.
        Conservative — no matching record or any doubt returns False, so a
        held app is never mislabeled as running.
        """
        if not dump:
            return False
        in_record = False
        for line in dump.splitlines():
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            record = _AM_RECORD.search(stripped)
            # Every record header ends the previous record: *APP* / *PERS* /
            # *IMP* ..., "Isolated #n:", "PID #n:" and section titles. Titles
            # sit at indent <= 2; a record's own sub-headers (``processInfo:``,
            # indent 4) are inside the record and must not end it.
            if (
                record
                or stripped.startswith(("*", "Isolated #"))
                or (indent <= 2 and stripped.endswith(":") and "=" not in stripped)
            ):
                in_record = bool(record) and int(record.group(1)) == pid
                continue
            if in_record and stripped.startswith("thread="):
                first = stripped.split()[0]
                return not first.startswith("thread=null")
        return False

    def _proc_resumed(self, pid: int) -> bool:
        """Worker-thread: is *pid* attached to ActivityManager? Blocking ADB."""
        try:
            from sandroid.core.adb import Adb

            package = self._current_package()
            if not package:
                return False
            out, _ = Adb.send_adb_command(f"shell dumpsys activity processes {package}")
            return self._parse_am_process_attached(out, pid)
        except Exception:
            logger.debug("activity-process read failed", exc_info=True)
            return False

    def _reconcile_paused_flag(self, pid: int | None) -> None:
        """Clear a stale AFM ``_paused`` flag when the process is actually running.

        Some AFM resume paths (e.g. ``JobManager.run_last_created_job``) resume
        the spawned process without clearing the in-memory ``_paused`` flag, so
        the header would show "◐ paused" forever though the app runs. When the
        flag says paused but ActivityManager shows the process attached (a
        held spawn never is), clear it at the source (``mark_resumed``) so every reader — header,
        status bar, primary label — self-corrects. Worker-thread only (does a
        blocking ADB read); never call from the UI thread.
        """
        if pid is None:
            return
        try:
            if not self._spotlight().is_app_paused():
                return
            if not self._proc_resumed(pid):
                return
            from sandroid.core.toolbox import Toolbox

            jm = Toolbox.get_frida_job_manager()
            if jm is not None:
                jm.mark_resumed()
                logger.info("Cleared stale paused flag for pid %s (resumed)", pid)
                self._post(self.refresh_panel)
        except Exception:
            logger.debug("paused-state reconciliation failed", exc_info=True)

    # -- bypass toggles ---------------------------------------------------

    def action_bypass_chord(self) -> None:
        """``b``: open the bypass chord; a digit toggles, ``o`` = Objection."""
        try:
            on = set(self._on_categories())
        except Exception:
            on = set()

        def on_pick(choice: str | None) -> None:
            if not choice:
                return
            if choice == "objection":
                action = getattr(self.app, "action_objection", None)
                if action is not None:
                    action()
                return
            self.action_toggle_bypass(choice)

        self.app.push_screen(BypassChordModal(on), on_pick)

    def action_toggle_bypass(self, category: str) -> None:
        """Toggle/arm a bypass category via the process-wide BypassService.

        Runs off the UI thread: toggling a category on against a running app
        loads/flips the combined Frida script, which can block on script
        readiness — synchronously here would freeze the whole TUI.

        ``toggle`` returns ``(now_on, msg)`` where the first element is *state*,
        not success, so the closure returns ``(True, msg)`` — otherwise
        ``_run_action_bg``'s severity-from-bool would redden a successful
        turn-OFF (``now_on=False``).
        """
        if not self._require_package():
            return

        def _work() -> tuple[bool, str]:
            now_on, msg = self._bypass().toggle(category)
            if now_on and self._bypass().is_active(category):
                try:
                    early = self._bypass().applies_at_spawn(category)
                except Exception:
                    early = False
                if early:
                    self._post(self._offer_restart_for, category)
            return True, msg

        label = f"toggle {category}"
        # Only an ON toggle against a live (non-paused) process attaches Frida.
        # OFF, arm-only (app stopped, applied on Start), and paused-spawn
        # toggles keep the fast path; Start is already frida-gated by
        # _run_frida_action. turning_on mirrors toggle()'s armed-or-active check
        # (on_categories); needs_frida mirrors BypassService._spotlight_running.
        turning_on = category not in self._bypass().on_categories()
        needs_frida = turning_on and (
            self._safe_pid() is not None and not self._is_paused()
        )
        if needs_frida and not self._frida_server_running():
            # frida-server is down — prompt to install/start it via the shared
            # modal instead of letting the attach fail with the cryptic
            # frida-core "need Gadget to attach on jailed Android" error.
            self._prompt_install_frida(
                self._bypass().display_name(category),
                lambda: self._run_action_bg(_work, label),
            )
        else:
            self._run_action_bg(_work, label)

    def _offer_restart_for(self, category: str) -> None:
        """Offer a restart so a start-time bypass (emulator) sees app start.

        The bypass is live already; No keeps the app and its state.
        """
        package = self._current_package()
        if not package or not self._safe_pid():
            return
        from sandroid.tui.modals import ConfirmModal

        name = self._bypass().display_name(category)
        stops = self._restart_stops(package)

        def on_result(yes: bool | None) -> None:
            if yes:
                self._run_frida_action(self._work_restart, "restart", "Restarting")

        self.app.push_screen(
            ConfirmModal(
                title=f"Restart {package} now?",
                message=(
                    f"{name} is active, but checks {package} ran at startup "
                    "missed it. Restart the app so they see it too? No keeps "
                    f"it running as it is.{stops}"
                ),
                yes_label="Restart",
                no_label="Keep running",
                guard_typing=True,
            ),
            on_result,
        )

    @staticmethod
    def _restart_stops(package: str) -> str:
        """`` This stops: …`` -- the tools a restart of ``package`` stops."""
        from sandroid.services import app_start

        try:
            return app_start.stops_sentence(app_start.app_tools(package))
        except Exception:
            return ""

    # -- lifecycle actions (main-thread entry points) ---------------------

    def action_primary(self) -> None:
        """Space: Start if stopped, Resume if paused, else inform."""
        if not self._require_package():
            return
        if self._is_paused():
            # Resuming a paused spawn — frida is already attached, no gate.
            self._run_action_bg(self._work_resume, "resume")
        elif self._safe_pid():
            # The cached PID may be stale (app died, snapshot load): the poll
            # only refreshes it every few seconds while this tab is shown.
            # Re-check the device before refusing to start.
            self._recheck_pid_then_start()
        else:
            self._run_frida_action(self._work_start, "start", "Spawning an app")

    def _recheck_pid_then_start(self) -> None:
        """Re-read the app's PID off-thread; start it if it is really gone."""
        package = self._current_package()

        def _check() -> None:
            pid = None
            try:
                from sandroid.core.adb import Adb

                pid = Adb.get_pid_for_package_name(
                    package, use_frida_fallback=False, quiet=True
                )
            except Exception as exc:
                logger.debug(f"PID re-check failed for {package}: {exc}")
            try:
                self._spotlight().set_pid(pid)
            except Exception:
                pass
            self._last_running_state = pid is not None
            self._post(self._after_pid_recheck, pid)

        self.run_worker(_check, name="spotlight_pid_recheck", thread=True)

    def _after_pid_recheck(self, pid: int | None) -> None:
        self.refresh_panel()
        if pid:
            self._notify(
                "Already running — ⇧R restart · ⇧A re-attach · ⇧K kill",
                "information",
            )
        else:
            self._run_frida_action(self._work_start, "start", "Spawning an app")

    def action_restart_app(self) -> None:
        # No dialog (used often), but never inside the stray-typing window:
        # an R in a typed word must not restart the app.
        from sandroid.tui.modals.confirm_modal import typing_guard_active

        if typing_guard_active(self.app):
            self.stray_key_swallowed("R")
            return
        if not self._require_package():
            return
        self._run_frida_action(self._work_restart, "restart", "Restarting an app")

    def stray_key_swallowed(self, key: str) -> None:
        """The main screen swallowed ``key`` as stray typing (notice for R)."""
        if key == "R":
            self._notify("Restart not run — that looked like typing.", "warning")

    def action_kill_app(self) -> None:
        if not self._require_package():
            return
        from sandroid.tui.modals import ConfirmModal

        def on_result(yes: bool | None) -> None:
            if yes:
                # Kill only force-stops + tears down; no frida-server needed.
                self._run_action_bg(self._work_kill, "kill")

        # guard_typing: No focused, a typed-ahead y ignored, other letters
        # cancel (as Play).
        self.app.push_screen(
            ConfirmModal(
                title="Kill app",
                message=f"Force-stop {self._current_package()} and stop its "
                "tools? The bypasses that are on stay armed for the next start.",
                guard_typing=True,
            ),
            on_result,
        )

    def action_attach_app(self) -> None:
        if not self._require_package():
            return
        # Attaching only needs frida-server when there are bypasses to load;
        # a bare attach (no armed bypasses) just tracks the running app.
        try:
            needs_frida = bool(self._bypass().armed_categories())
        except Exception:
            needs_frida = False
        if needs_frida:
            self._run_frida_action(
                self._work_attach, "attach", "Attaching with bypasses"
            )
        else:
            self._run_action_bg(self._work_attach, "attach")

    def action_start_paused(self) -> None:
        """⇧P: start paused; a running app is only restarted after a Yes."""
        if not self._require_package():
            return
        package = self._current_package()

        def _check() -> None:
            from sandroid.services.app_start import probe_liveness

            try:
                liveness, pid = probe_liveness(package)
            except Exception as exc:
                logger.debug(f"⇧P liveness check failed: {exc}")
                liveness, pid = None, None
            self._post(self._after_paused_check, package, liveness, pid)

        self.run_worker(_check, name="spotlight_paused_check", thread=True)

    def _after_paused_check(self, package: str, liveness, pid: int | None) -> None:
        """Main thread: start paused, or ask before restarting a running app."""
        from sandroid.services.app_start import Liveness

        if liveness == Liveness.NOT_RUNNING:
            self._run_frida_action(
                self._work_start_paused, "start-paused", "Spawning an app"
            )
            return
        if liveness != Liveness.RUNNING:
            self._notify(
                f"Could not tell whether {package} is running — not started.",
                "error",
            )
            return
        from sandroid.tui.modals import ConfirmModal

        def on_result(yes: bool | None) -> None:
            if yes:
                self._run_frida_action(
                    self._work_restart_paused, "restart-paused", "Restarting"
                )
            else:
                self._notify(f"{package} keeps running.", "information")

        self.app.push_screen(
            ConfirmModal(
                title=f"Restart {package} paused?",
                message=(
                    f"{package} is running (pid {pid}). Start paused "
                    "force-stops it and starts it again, held paused with the "
                    "armed bypasses until ␣ (Android ends the hold after "
                    f"about 10 s).{self._restart_stops(package)}"
                ),
                yes_label="Restart paused",
                no_label="Keep running",
                guard_typing=True,
            ),
            on_result,
        )

    def action_stop_all(self) -> None:
        """Stop all bypasses + background tasks for the app (keep it running).

        Fixed: stops the BypassService even when there are zero TaskService
        tasks (the old early-return left bypass jobs running), and clears the
        armed set via BypassService.stop_all().
        """
        package = self._current_package()
        if not package:
            self._notify("No spotlight app.", "warning")
            return
        self._run_action_bg(
            lambda: (True, f"Stopped {self._stop_everything_for(package)} item(s)"),
            "stop-all",
        )

    def action_clear_spotlight(self) -> None:
        """Clear the spotlight selection (leaves any running app alone)."""
        try:
            self._spotlight().reset()
            self._last_running_state = None
            self._notify("Spotlight cleared", "information")
        except Exception as exc:
            logger.warning(f"Clear spotlight failed: {exc}")
        self.refresh_panel()

    def dispatch_action_cell(self, wid: str) -> None:
        """Run the action bound to a clicked action cell (from MainScreen)."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    # -- blocking work bodies (run on worker threads) ---------------------

    # The bodies live in sandroid.services.app_start so the AI reuses them.

    def _work_start(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.start_app()

    def _work_start_paused(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.start_app(paused=True)

    def _work_resume(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.resume_app()

    def _work_restart(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.restart_app()

    def _work_restart_paused(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.restart_app(paused=True)

    def _work_kill(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        from sandroid.core.adb import Adb

        # force_stop FIRST (see _work_restart): unloading on a live process can
        # hang; killing first makes the teardown unloads/detach fast-fail.
        # What was on is armed before the kill: the liveness poll drops the
        # active set as soon as the process is gone.
        try:
            self._bypass().arm_active(package)
        except Exception as exc:
            logger.warning(f"Keeping the bypasses armed failed: {exc}")
        Adb.force_stop(package)
        time.sleep(0.5)
        # The bypasses that were on stay armed (intent): ␣ starts with them.
        kept: list[str] = []
        try:
            kept = self._bypass().keep_armed_and_forget(package)
        except Exception as exc:
            logger.warning(f"Bypass teardown failed: {exc}")
        self._stop_app_tasks(package)
        self._reset_frida_session()
        spotlight.set_pid(None)
        self._last_running_state = False
        if kept:
            return True, (
                f"Killed {package} — bypass {', '.join(kept)} stay armed; "
                "␣ starts with them"
            )
        return True, f"Killed {package}"

    def _work_attach(self) -> tuple[bool, str]:
        from sandroid.services import app_start

        return app_start.attach_app()

    # -- shared teardown helpers ------------------------------------------

    def _reset_frida_session(self) -> None:
        try:
            from sandroid.core.toolbox import Toolbox

            Toolbox.get_frida_job_manager().reset_session()
        except Exception as exc:
            logger.warning(f"reset_session failed: {exc}")

    def _stop_everything_for(self, package: str) -> int:
        """Stop bypasses (clears armed) + any background tasks for the app.

        Stop all: clearing the armed set is the explicit "done" (⇧K keeps
        it). Returns the number of items stopped. Does NOT early-return when
        there are no TaskService tasks — the bypasses are stopped regardless.
        """
        stopped = 0
        try:
            stopped += len(self._bypass().stop_all())
        except Exception as exc:
            logger.warning(f"Bypass stop_all failed: {exc}")
        return stopped + self._stop_app_tasks(package)

    def _stop_app_tasks(self, package: str) -> int:
        """Stop the app's background tasks except the bypass (done apart)."""
        stopped = 0
        try:
            svc = self._tasks()
            for t in self._hooks_for_app(package):
                name = getattr(t, "name", "")
                if name == "bypass":
                    continue  # its stop callback would clear the armed set
                try:
                    if svc.stop(name):
                        stopped += 1
                except Exception as exc:
                    logger.warning(f"Stop task failed: {exc}")
        except Exception:
            pass
        return stopped

    # -- helpers ----------------------------------------------------------

    def _require_package(self) -> bool:
        if not self._current_package():
            self._notify(
                "No spotlight app. Press c (use the foreground app) or ⇧C "
                "(pick an app…) first.",
                "warning",
            )
            return False
        return True

    #: Upper bound for any single spotlight action. The fixed teardown/spawn
    #: paths complete in 1-3s; this only ever trips on a genuine regression
    #: (e.g. a frida call wedging), and exists so _action_inflight can NEVER
    #: stay stuck and permanently disable the panel.
    _ACTION_TIMEOUT = 90.0

    def _run_action_bg(self, work, label: str) -> None:
        """Run a blocking spotlight action off the UI thread, then refresh.

        ``work`` returns ``(success, message)`` and must be safe to run on a
        worker thread (no widget access). A single in-flight guard prevents
        overlapping spawns/kills. ``work`` is run under a bounded watchdog so a
        hung frida call can never wedge ``_action_inflight`` (which would show
        "already in progress" forever); on timeout the flag is cleared and the
        orphaned worker is abandoned (``shutdown(wait=False)`` — never block on
        the hang we are escaping).
        """
        if self._action_inflight:
            self._notify("Spotlight action already in progress…", "warning")
            return
        self._action_inflight = True

        def _job() -> None:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(work)
                try:
                    ok, msg = self._await_action(future)
                except concurrent.futures.TimeoutError:
                    ok, msg = (
                        False,
                        f"{label} timed out after "
                        f"{int(self._ACTION_TIMEOUT)}s — see logs",
                    )
                    logger.error(
                        "Spotlight action %s exceeded %.0fs watchdog; abandoning",
                        label,
                        self._ACTION_TIMEOUT,
                    )
                self._notify(msg, "information" if ok else "error")
            except Exception as exc:
                logger.warning(f"{label} failed: {exc}")
                self._notify(f"{label} failed: {exc}", "error")
            finally:
                # Never wedge: clear the guard no matter how work() ended, and
                # do not wait on a possibly-hung worker thread.
                executor.shutdown(wait=False)
                self._action_inflight = False
                self._post(self.refresh_panel)

        self.run_worker(_job, name=f"spotlight_{label}", exclusive=False, thread=True)

    def _await_action(self, future) -> tuple[bool, str]:
        """``future.result()`` under the watchdog (worker thread).

        A pre-start step (the "Apply before starting" dialog, a framework
        restart) is not a hang: the watchdog starts over once it is done.

        Raises:
            concurrent.futures.TimeoutError: The watchdog tripped.
        """
        from sandroid.services.app_start import pre_start_running

        deadline = time.monotonic() + self._ACTION_TIMEOUT
        while True:
            wait = min(1.0, max(0.0, deadline - time.monotonic()))
            try:
                return future.result(timeout=wait)
            except concurrent.futures.TimeoutError:
                if pre_start_running():
                    deadline = time.monotonic() + self._ACTION_TIMEOUT
                elif time.monotonic() >= deadline:
                    raise

    # -- frida-server pre-flight ------------------------------------------

    def _run_frida_action(self, work, label: str, feature: str) -> None:
        """Run a spotlight action that needs frida-server on the device.

        If frida-server is running, behaves like ``_run_action_bg``. If it is
        NOT running, prompt the user to install & start it (via the shared
        ``FridaInstallModal``) and only then run the action — instead of
        letting the spawn fail with the cryptic frida fallback error
        ("need Gadget to attach on jailed Android").
        """
        if self._frida_server_running():
            self._run_action_bg(work, label)
        else:
            self._prompt_install_frida(
                feature, lambda: self._run_action_bg(work, label)
            )

    @staticmethod
    def _frida_server_running() -> bool:
        """True if frida-server is up on the active device (best-effort)."""
        try:
            from sandroid.services import get_frida_session_service

            fm = get_frida_session_service().get_frida_manager()
            return bool(fm and fm.is_frida_server_running())
        except Exception:
            return False

    def _prompt_install_frida(self, feature: str, then) -> None:
        """Show the FridaInstallModal; on confirm install+start, then run ``then``."""
        from sandroid.core.frida_manager import frida_server_auto_start_enabled
        from sandroid.tui.modals import FridaInstallModal, FridaInstallResult

        if frida_server_auto_start_enabled():  # frida.server_auto_start: no prompt
            self._install_frida_then(then)
            return

        device_name = "device"
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            if dm and dm.active_device:
                device_name = dm.active_device.display_name
        except Exception:
            pass

        def on_result(result: FridaInstallResult | None) -> None:
            if not result or not result.install:
                # Derived from ``feature`` so the wording fits every caller
                # (spawn/restart/attach AND the bypass toggle) instead of always
                # saying "spawn". Mirrors the modal's own "{feature} requires…".
                self._notify(f"{feature} requires frida-server — cancelled.", "warning")
                return
            self._install_frida_then(then)

        self.app.push_screen(
            FridaInstallModal(device_name=device_name, feature_name=feature),
            on_result,
        )

    def _install_frida_then(self, then) -> None:
        """Install + start frida-server on a worker, then run ``then`` on success."""
        if self._action_inflight:
            self._notify("Spotlight action already in progress…", "warning")
            return
        self._action_inflight = True
        self._notify("Installing & starting frida-server…", "information")

        def _job() -> None:
            ok = False
            try:
                from sandroid.services import get_frida_session_service

                svc = get_frida_session_service()
                fm = svc.get_frida_manager()
                if fm is None:
                    raise RuntimeError("Frida manager unavailable")
                from sandroid.core.frida_manager import (
                    ensure_frida_server_started,
                )

                # run_frida_server now blocks until the frida CLIENT can reach
                # the server, so its result reflects real readiness (not just
                # that the process exists) — the next spawn won't race it.
                ok = ensure_frida_server_started(fm)
                if ok:
                    # Drop any frida device handle cached while the server was
                    # down so the next spawn resolves a fresh, ready device.
                    try:
                        svc.invalidate_frida_device_cache()
                    except Exception:
                        pass
            except Exception as exc:
                from sandroid.core.frida_manager import describe_frida_install_error

                reason = describe_frida_install_error(exc)
                logger.warning(f"Frida install/start failed: {reason}")
                self._notify(f"Frida install failed: {reason}", "error")
            finally:
                self._action_inflight = False
                self._post(self.refresh_panel)
                self._post(self._refresh_status_bar)
            if ok:
                self._notify("frida-server started.", "information")
                self._post(then)
            else:
                self._notify("frida-server still not running — cannot spawn.", "error")

        self.run_worker(
            _job, name="spotlight_frida_install", exclusive=False, thread=True
        )

    def _refresh_status_bar(self) -> None:
        """Nudge the status bar to re-check frida status (main thread only).

        Resolve via ``self.screen`` (the panel's owning MainScreen), not
        ``self.app`` — ``App.query_one`` searches the default screen and raises
        ``NoMatches`` from a panel, so the refresh would silently never fire.
        """
        try:
            self.screen.query_one("#status-bar").update_from_toolbox()
        except Exception:
            pass

    def _notify(self, message: str, severity: str = "information") -> None:
        """Notify the user. Safe to call from worker threads."""
        self._post(self._do_notify, message, severity)

    def _do_notify(self, message: str, severity: str) -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass


class BypassChordModal(_FridaModalBase):
    """``b`` then a digit: toggle a bypass category (``o`` = Objection).

    Same style as the ``S`` slot picker: a plain digit picks, Esc cancels.
    Dismisses with the category name, ``"objection"`` or ``None``.
    """

    BINDINGS = [
        *[
            Binding(key, f"pick('{category}')", label, show=False, priority=True)
            for key, category, label in _BYPASS_TOGGLES
        ],
        Binding("o", "pick('objection')", "Objection", show=False, priority=True),
        Binding("b", "pick('objection')", "Objection", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    BypassChordModal .modal-container {
        width: 64;
        max-width: 90%;
        height: auto;
    }
    BypassChordModal #bypass-chord-list {
        height: auto;
        width: 100%;
    }
    """

    def __init__(self, on_categories: set[str] | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._on = set(on_categories or ())

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical
        from textual.widgets import Label

        from sandroid.tui.modals.base import KeyHintFooter

        c = lens_palette()
        rows = []
        for key, category, label in _BYPASS_TOGGLES:
            is_on = category in self._on
            mark = f"[{c.ok}]● on [/]" if is_on else f"[{c.dim}]○ off[/]"
            rows.append(f"  [b]{key}[/]  {mark}  {label}")
        rows.append("")
        rows.append("  [b]o[/]  Objection shell [dim](b b works too)[/dim]")
        with Vertical(classes="modal-container"):
            yield Label("Bypass", classes="modal-title")
            yield Static("\n".join(rows), id="bypass-chord-list")
            yield KeyHintFooter(
                hints={"default": "[dim]1-6 toggle · o Objection · Esc cancel[/dim]"}
            )

    def action_pick(self, choice: str) -> None:
        self.dismiss(choice)
