"""Diffs sub-tab: Play's persistent Changed/New/Deleted run history.

Replaces the old one-shot ``AnalysisSummaryModal`` popup: every completed
Play is now a row in a collapsible bottom "Runs" bar (an ``OptionList``,
styled like :class:`~sandroid.tui.widgets.snapshots_panel.SnapshotsPanel`'s
bottom bar), with the selected run's Changed/New/Deleted results in a
full-width diff pane above it — colored like
:class:`~sandroid.tui.widgets.monitor_view.MonitorView` — each changed file
with real diff content rendered via a
:class:`~sandroid.tui.widgets.diff_view.DiffView`.

Data flow: ``RecordingController._run_playback_analysis`` persists a
``RunRecord`` via ``core/run_history.py`` and then calls back into
``on_new_run(run_id)`` (wired through ``app.py._notify_diffs_new_run``).
This view never talks to the recorder directly — it only reads
``run_history``'s on-disk index/records.

Key scoping note: ``n`` (rename) and ``delete``/``backspace`` (delete) are
bound here on this Widget, not the App — they only fire while this view has
focus, exactly the same non-priority-binding-on-a-focused-ancestor mechanism
``SnapshotsPanel`` uses for its own ``c``/``l``/``d``/``a``/``r``. ``n``
deliberately **shadows the GLOBAL ``n``=Install APK binding** (``app.py``'s
``action_install_apk``, id ``"new_apk"``) while Diffs has focus — Install APK
is irrelevant while reviewing Play results, the same precedent already
established by Watchlist's ``a``/Analyze shadow over the global Analyze
action. ``delete``/``backspace`` are unbound anywhere else in the app
(``help_screen.py`` uses backspace on a separate screen), so no shadowing
concern there. ``[`` (collapse the Runs bar) is likewise confirmed unbound.
"""

from __future__ import annotations

import functools
import logging
import threading
from typing import TYPE_CHECKING, Any

from textual.containers import Vertical, VerticalScroll
from textual.widgets import ContentSwitcher, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.core import run_history

from .diff_view import DiffView
from .files_panel import FilesSubViewBase

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

#: id used for the OptionList's single disabled placeholder row when there
#: are no runs yet — never a real run_id, so selection/highlight handlers
#: can cheaply ignore it.
_EMPTY_OPTION_ID = "__no_runs__"


class DiffsView(FilesSubViewBase):
    """Play run-history sub-tab: full-width diff detail + bottom Runs bar.

    Bindings (when focused):
        r: start recording (idea A: panel-scoped, routes to ``app.record``;
           the global ``r`` binding was removed from ``app.py`` so Record
           only fires while this Diff panel is focused).
        p: replay the current recording (panel-scoped, routes to
           ``app.play``; likewise removed from the global map).
        n: rename the selected run (shadows global "n"=Install APK — see
           module docstring).
        delete / backspace: delete the selected run, through a ConfirmModal
           first (never on a bare keypress).
        [: collapse/expand the bottom Runs bar (reclaims height for a taller
           diff pane; a "run i/N ▸" breadcrumb stays visible while
           collapsed).
    """

    _LABEL = "Diffs"

    can_focus = True

    BINDINGS = [
        # Panel-scoped Record/Play (idea A). The ``app.`` namespace routes
        # these to SandroidTUI.action_record / action_play; the global r/p
        # bindings were removed from app.py so they fire only while the Diff
        # panel is focused — the same focused-ancestor mechanism as n/[.
        ("r", "app.record", "Record"),
        ("p", "app.play", "Play"),
        ("n", "rename_run", "Rename run"),
        ("delete", "delete_run", "Delete run"),
        ("backspace", "delete_run", "Delete run"),
        ("[", "toggle_rail", "Collapse rail"),
    ]

    DEFAULT_CSS = """
    DiffsView {
        layout: vertical;
        padding: 0;
    }
    DiffsView #diffs-body {
        layout: vertical;
        height: 1fr;
    }
    DiffsView #diffs-detail {
        height: 1fr;
        layout: vertical;
        padding: 0 1;
        background: #050811;
    }
    DiffsView #diffs-rail {
        dock: bottom;
        height: 12;
        background: #060a14;
        border-top: solid #1f2937;
    }
    DiffsView #diffs-rail.-collapsed {
        display: none;
    }
    DiffsView #diffs-rail-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    DiffsView #runs-list {
        height: 1fr;
        background: #050811;
    }
    DiffsView #diffs-actions {
        height: 1;
        dock: bottom;
        background: #0b1628;
        color: #93a4c3;
        padding: 0 1;
    }
    DiffsView #diffs-breadcrumb {
        height: 1;
        color: #93a4c3;
        display: none;
    }
    DiffsView #diffs-breadcrumb.-visible {
        display: block;
    }
    DiffsView #diffs-banner {
        height: 1;
        color: #f59e0b;
        display: none;
    }
    DiffsView #diffs-banner.-visible {
        display: block;
    }
    DiffsView #diffs-scroll {
        height: 1fr;
    }
    DiffsView .diffs-category-header {
        text-style: bold;
        padding-top: 1;
    }
    DiffsView .diffs-plain-changed {
        color: #facc15;
    }
    DiffsView .diffs-plain-new {
        color: #22c55e;
    }
    DiffsView .diffs-plain-deleted {
        color: #ef4444;
    }
    DiffsView .diffs-error {
        color: #ef4444;
        text-style: bold;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        self._device_name: str | None = None
        #: Lightweight per-run summaries (run_history.load_index shape),
        #: newest run first.
        self._summaries: list[dict[str, Any]] = []
        self._selected_run_id: str | None = None
        self._unread_run_ids: set[str] = set()
        self._rail_collapsed = False
        #: Full RunRecord for the currently-selected run, once loaded.
        self._detail_record: run_history.RunRecord | None = None

    # -- compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="diffs-body"):
            with Vertical(id="diffs-detail"):
                yield Static("", id="diffs-breadcrumb")
                yield Static("", id="diffs-banner")
                with VerticalScroll(id="diffs-scroll"):
                    yield Static(
                        "[dim]No runs yet — press [b]r[/b] to record, "
                        "[b]p[/b] to replay.[/dim]",
                        id="diffs-empty",
                    )
            with Vertical(id="diffs-rail"):
                yield Static("Runs", id="diffs-rail-header")
                yield OptionList(id="runs-list")
                yield Static(
                    "r record · p replay · n rename · del delete · [ collapse",
                    id="diffs-actions",
                )

    def on_mount(self) -> None:
        import asyncio

        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None
        self._subscribe_events()
        self._reload_index()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    # -- focus forwarding ----------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the OptionList so row navigation works.

        Mirrors ``SnapshotsPanel.focus()``: ``FilesPanel.focus()`` forwards
        to this widget, but up/down navigation needs the OptionList itself
        focused. n/delete/backspace/[ are not OptionList bindings, so they
        still bubble up to this widget afterwards.
        """
        try:
            self.query_one("#runs-list", OptionList).focus(scroll_visible)
        except Exception:
            super().focus(scroll_visible)
        return self

    # -- FilesPanel hooks ----------------------------------------------------

    def on_activated(self) -> None:
        """Called by ``FilesPanel._select_subtab`` when Diffs becomes active."""
        self._reload_index()

    def glance_fragment(self) -> str:
        total = len(self._summaries)
        unread = len(self._unread_run_ids)
        if total == 0:
            return "Diffs — no runs yet"
        plural = "s" if total != 1 else ""
        if unread:
            return f"Diffs — {total} run{plural} · {unread} unread"
        return f"Diffs — {total} run{plural}"

    # -- device / index (main thread; index reads are cheap, JSON only) ----

    @staticmethod
    def _toolbox():
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _current_device_name(self) -> str:
        try:
            name = self._toolbox().device_name
        except Exception:
            name = None
        return name or "unknown"

    def _fetch_summaries(self) -> tuple[list[dict[str, Any]], str]:
        device_name = self._current_device_name()
        try:
            summaries = run_history.load_index(device_name=device_name)
        except Exception as exc:
            logger.warning(f"DiffsView: failed to load run index: {exc}")
            summaries = []
        return summaries, device_name

    def _reload_index(self) -> None:
        """Refresh the rail from disk (tab activation / device change / poll)."""
        summaries, device_name = self._fetch_summaries()
        device_changed = device_name != self._device_name
        self._device_name = device_name
        self._summaries = summaries
        if device_changed:
            # A device switch shows THAT device's own history from scratch —
            # never mix selection/unread state across devices.
            self._selected_run_id = None
            self._unread_run_ids.clear()
            self._detail_record = None
        if self._selected_run_id is None and self._summaries:
            self._select_run(self._summaries[0]["run_id"])
            return
        self._rebuild_rail()
        if self._detail_record is not None:
            self._render_detail(self._detail_record)
        self._set_breadcrumb()

    def on_new_run(self, run_id: str) -> None:
        """Called (main thread) once a new RunRecord has been saved.

        Gated auto-focus (plan's "Run-selection" rule, separate from the
        always-on "tab-switch on Play-press" handled in app.py/main_screen):
        only steal the current selection if the user was already viewing the
        latest run, or the rail was empty. Otherwise just insert the row with
        an unread ``●`` marker and leave the current selection untouched —
        never steal focus from someone reviewing an older run.
        """
        was_on_latest_or_empty = (
            not self._summaries or self._selected_run_id == self._summaries[0]["run_id"]
        )
        summaries, device_name = self._fetch_summaries()
        self._device_name = device_name
        self._summaries = summaries
        if was_on_latest_or_empty:
            self._select_run(run_id)
        else:
            self._unread_run_ids.add(run_id)
            self._rebuild_rail()
            self._toast_new_run(run_id)

    # -- selection / detail loading -----------------------------------------

    def _index_of(self, run_id: str | None) -> int | None:
        if run_id is None:
            return None
        for i, s in enumerate(self._summaries):
            if s.get("run_id") == run_id:
                return i
        return None

    def _current_label(self, run_id: str) -> str:
        for s in self._summaries:
            if s.get("run_id") == run_id:
                return s.get("label") or run_id
        return run_id

    def _select_run(self, run_id: str) -> None:
        self._selected_run_id = run_id
        self._unread_run_ids.discard(run_id)
        self._rebuild_rail()
        self._set_breadcrumb()
        self._load_run_detail(run_id)

    def _load_run_detail(self, run_id: str) -> None:
        """Read the full RunRecord (disk I/O) off the main thread."""
        self._run_bg(
            functools.partial(self._load_run_worker, run_id), f"diffs_load_{run_id}"
        )

    def _run_bg(self, fn, name: str) -> None:
        """Run ``fn`` on a worker thread, or inline if no app context exists.

        The inline fallback (no exception, no dependency on a live App/
        event loop) is what lets ``action_rename_run``/``action_delete_run``/
        selection be exercised directly in unit tests without a full
        Textual ``Pilot`` harness.
        """
        if self._run_worker_available():
            self.run_worker(fn, name=name, exclusive=False, thread=True)
        else:
            fn()

    def _run_worker_available(self) -> bool:
        try:
            return bool(self.is_running)
        except Exception:
            return False

    def _load_run_worker(self, run_id: str) -> None:
        record = None
        error = None
        try:
            record = run_history.load_run(run_id)
        except Exception as exc:
            error = str(exc)
        self._post(self._apply_loaded_run, run_id, record, error)

    def _apply_loaded_run(
        self, run_id: str, record: run_history.RunRecord | None, error: str | None
    ) -> None:
        if run_id != self._selected_run_id:
            return  # user navigated away before the read finished
        if record is None:
            self._detail_record = None
            self._render_load_error(run_id, error)
            return
        self._detail_record = record
        self._render_detail(record)

    # -- OptionList events ----------------------------------------------------

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option_list.id != "runs-list":
            return
        run_id = event.option_id
        if not run_id or run_id == _EMPTY_OPTION_ID:
            return
        if run_id != self._selected_run_id:
            self._select_run(run_id)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "runs-list":
            return
        run_id = event.option_id
        if not run_id or run_id == _EMPTY_OPTION_ID:
            return
        if run_id != self._selected_run_id:
            self._select_run(run_id)

    # -- rail rendering --------------------------------------------------

    def _rebuild_rail(self) -> None:
        try:
            option_list = self.query_one("#runs-list", OptionList)
        except Exception:
            return
        option_list.clear_options()
        if not self._summaries:
            option_list.add_option(
                Option(
                    "[#5b6479]no runs yet — r record · p replay[/]",
                    id=_EMPTY_OPTION_ID,
                )
            )
            return
        for s in self._summaries:
            option_list.add_option(Option(self._row_label(s), id=s["run_id"]))
        idx = self._index_of(self._selected_run_id)
        if idx is not None:
            try:
                option_list.highlighted = idx
            except Exception:
                pass

    def _row_label(self, s: dict[str, Any]) -> str:
        run_id = s.get("run_id", "")
        marker = "[#38bdf8]▶[/] " if run_id == self._selected_run_id else "  "
        unread = "[#22d3ee]●[/] " if run_id in self._unread_run_ids else ""
        label = s.get("label") or run_id
        ts = self._format_timestamp(s.get("recorded_at"))
        counts = s.get("counts") or {}
        changed = counts.get("changed", 0)
        new = counts.get("new", 0)
        deleted = counts.get("deleted", 0)
        bits = []
        if changed:
            bits.append(f"[#facc15]{changed}c[/]")
        if new:
            bits.append(f"[#22c55e]{new}n[/]")
        if deleted:
            bits.append(f"[#ef4444]{deleted}d[/]")
        count_str = " ".join(bits) if bits else "[dim]no changes[/]"
        err = " [#ef4444]✕[/]" if s.get("error") else ""
        return f"{marker}{unread}[b]{label}[/]  [dim]{ts}[/]  {count_str}{err}"

    @staticmethod
    def _format_timestamp(iso: str | None) -> str:
        if not iso:
            return "--:--"
        try:
            from datetime import datetime

            return datetime.fromisoformat(iso).strftime("%H:%M")
        except Exception:
            return "--:--"

    # -- detail rendering --------------------------------------------------

    def _set_banner(self, text: str | None) -> None:
        try:
            banner = self.query_one("#diffs-banner", Static)
        except Exception:
            return
        if text:
            banner.update(f"[#f59e0b]{text}[/]")
            banner.set_class(True, "-visible")
        else:
            banner.update("")
            banner.set_class(False, "-visible")

    def _set_breadcrumb(self) -> None:
        try:
            bc = self.query_one("#diffs-breadcrumb", Static)
        except Exception:
            return
        if not self._rail_collapsed:
            bc.set_class(False, "-visible")
            return
        idx = self._index_of(self._selected_run_id)
        total = len(self._summaries)
        text = "no runs" if idx is None or total == 0 else f"run {idx + 1}/{total} ▸"
        bc.update(f"[dim]{text}[/]")
        bc.set_class(True, "-visible")

    def _render_load_error(self, run_id: str, error: str | None) -> None:
        try:
            scroll = self.query_one("#diffs-scroll", VerticalScroll)
        except Exception:
            return
        scroll.remove_children()
        scroll.mount(Static(f"[#ef4444]Could not load run '{run_id}': {error}[/]"))

    def _render_detail(self, record: run_history.RunRecord) -> None:
        try:
            scroll = self.query_one("#diffs-scroll", VerticalScroll)
        except Exception:
            return
        scroll.remove_children()

        is_latest = bool(self._summaries) and record.run_id == self._summaries[0].get(
            "run_id"
        )
        self._set_banner(
            None
            if is_latest
            else f"viewing: {record.label or record.run_id} — not the latest"
        )
        self._set_breadcrumb()

        widgets: list[Any] = []
        if record.error:
            widgets.append(
                Static(
                    f"[#ef4444]Playback error: {record.error}[/]",
                    classes="diffs-error",
                )
            )

        changed = record.changed_files or []
        widgets.append(self._category_header("Changed", "#facc15", len(changed)))
        if changed:
            for entry in changed:
                if isinstance(entry, dict):
                    for path, lines in entry.items():
                        widgets.append(DiffView(diff=lines, title=path))
                else:
                    widgets.append(
                        Static(f"[#facc15]{entry}[/]", classes="diffs-plain-changed")
                    )
        else:
            widgets.append(Static("[dim](no changed files)[/]"))

        new_files = record.new_files or []
        widgets.append(self._category_header("New", "#22c55e", len(new_files)))
        if new_files:
            for path in new_files:
                widgets.append(
                    Static(f"[#22c55e]+ {path}[/]", classes="diffs-plain-new")
                )
        else:
            widgets.append(Static("[dim](no new files)[/]"))

        deleted_files = record.deleted_files or []
        widgets.append(self._category_header("Deleted", "#ef4444", len(deleted_files)))
        if deleted_files:
            for path in deleted_files:
                widgets.append(
                    Static(f"[#ef4444]✕ {path}[/]", classes="diffs-plain-deleted")
                )
        else:
            widgets.append(Static("[dim](no deleted files)[/]"))

        scroll.mount(*widgets)

    @staticmethod
    def _category_header(title: str, color: str, count: int) -> Static:
        return Static(
            f"[bold {color}]{title} ({count})[/bold {color}]",
            classes="diffs-category-header",
        )

    # -- actions (main-thread entry points) ---------------------------------

    def action_toggle_rail(self) -> None:
        """``[`` — collapse/expand the bottom Runs bar to reclaim height for
        a taller diff pane.
        """
        self._rail_collapsed = not self._rail_collapsed
        try:
            self.query_one("#diffs-rail").set_class(self._rail_collapsed, "-collapsed")
        except Exception:
            pass
        self._set_breadcrumb()

    def action_rename_run(self) -> None:
        """``n`` — rename the selected run.

        Deliberately shadows the GLOBAL ``n``=Install APK binding while this
        view has focus (see module docstring) — a deliberate, previously-
        verified-safe shadow, the same precedent as Watchlist's ``a``/Analyze
        shadow elsewhere in this plan.
        """
        run_id = self._selected_run_id
        if not run_id:
            self._notify("No run selected to rename.", "warning")
            return
        from sandroid.tui.modals import InputModal

        current = self._current_label(run_id)

        def on_result(value: str | None) -> None:
            if value is None:
                return
            label = value.strip()
            if not label:
                return
            self._rename_run_bg(run_id, label)

        self.app.push_screen(
            InputModal(
                title="Rename run",
                default=current,
                placeholder="run label",
            ),
            on_result,
        )

    def _rename_run_bg(self, run_id: str, label: str) -> None:
        self._run_bg(
            functools.partial(self._rename_run_worker, run_id, label), "diffs_rename"
        )

    def _rename_run_worker(self, run_id: str, label: str) -> None:
        try:
            run_history.update_label(run_id, label)
            ok, msg = True, f"Renamed to '{label}'"
        except Exception as exc:
            ok, msg = False, f"Rename failed: {exc}"
        self._post(self._after_rename, run_id, label, ok, msg)

    def _after_rename(self, run_id: str, label: str, ok: bool, msg: str) -> None:
        if ok:
            if self._detail_record is not None and self._detail_record.run_id == run_id:
                self._detail_record.label = label
            self._reload_index()
        self._notify(msg, "information" if ok else "error")

    def action_delete_run(self) -> None:
        """``delete``/``backspace`` — delete the selected run (confirm first).

        Never deletes on a bare keypress — mirrors ``SnapshotsPanel``'s
        delete-slot confirm-modal convention.
        """
        run_id = self._selected_run_id
        if not run_id:
            self._notify("No run selected to delete.", "warning")
            return
        from sandroid.tui.modals import ConfirmModal

        label = self._current_label(run_id)

        def on_result(yes: bool | None) -> None:
            if not yes:
                return
            self._delete_run_bg(run_id)

        self.app.push_screen(
            ConfirmModal(
                title="Delete run",
                message=f"Delete run '{label}'? This removes its saved "
                "diff data and cannot be undone.",
            ),
            on_result,
        )

    def _delete_run_bg(self, run_id: str) -> None:
        self._run_bg(functools.partial(self._delete_run_worker, run_id), "diffs_delete")

    def _delete_run_worker(self, run_id: str) -> None:
        try:
            run_history.delete_run(run_id)
            ok, msg = True, "Run deleted."
        except Exception as exc:
            ok, msg = False, f"Delete failed: {exc}"
        self._post(self._after_delete, run_id, ok, msg)

    def _after_delete(self, run_id: str, ok: bool, msg: str) -> None:
        if ok:
            self._unread_run_ids.discard(run_id)
            if self._selected_run_id == run_id:
                self._selected_run_id = None
                self._detail_record = None
            self._reload_index()
        self._notify(msg, "information" if ok else "error")

    # -- EventBus wiring (device-switch detection; thread-safe) -------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            def _cb(_event) -> None:
                loop = self._main_loop
                try:
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(self._refresh_if_visible)
                except RuntimeError:
                    pass

            bus.subscribe(EventType.STATE_CHANGED, _cb)
            self._event_handlers.append((EventType.STATE_CHANGED, _cb))
        except Exception as exc:
            logger.debug(f"DiffsView event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    def _is_on_screen(self) -> bool:
        """True if the Files tab is showing AND Diffs is its active sub-tab."""
        try:
            outer = self.screen.query_one("#tool-body", ContentSwitcher)
            if outer.current != "files-panel":
                return False
            inner = self.screen.query_one("#files-body", ContentSwitcher)
            return inner.current == "files-diffs"
        except Exception:
            return False

    def _refresh_if_visible(self) -> None:
        if self._is_on_screen():
            self._reload_index()

    # -- thread marshalling / notifications ---------------------------------

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread.

        Deliberately ``call_from_thread`` (blocking the calling thread until
        ``fn`` completes), NOT the ``loop.call_soon_threadsafe`` idiom used
        elsewhere in this app (``FilesPanel``/``SnapshotsPanel``'s EventBus
        callbacks) — those callbacks only touch simple reactive
        updates/``OptionList`` rows, while ``fn`` here (``_apply_loaded_run``
        etc.) *mounts brand-new widgets* (``DiffView``/``Collapsible``),
        which needs Textual's ``active_app`` contextvar set. A bare
        ``call_soon_threadsafe`` callback runs with whatever (empty) context
        the worker thread had, causing a ``NoActiveAppError`` deep inside
        mounting; ``call_from_thread`` explicitly re-establishes the app
        context (see its implementation's ``with self._context():``).
        Blocking is safe here — unlike the EventBus case, ``fn`` is only
        ever called from a ``run_worker(thread=True)`` background thread
        this view spawned itself solely to report this one result back, so
        there is nothing else waiting on that thread that could deadlock.
        """
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            logger.debug("DiffsView: call_from_thread marshal failed", exc_info=True)

    def _notify(self, message: str, severity: str = "information") -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass

    def _toast_new_run(self, run_id: str) -> None:
        label = self._current_label(run_id)
        self._notify(
            f"New run ready: {label} (viewing an older run — see ● in Runs)",
            "information",
        )
