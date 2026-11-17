"""Runs lens: "which runs do I have, and what did each change?"

Every completed Play is one row of a full-width table (newest first):
``#`` · run label · when · how long · what changed. Details are on demand:
Enter opens the run in the Inspector (Summary / Changes / Report tabs), and
``v`` puts the whole UI in REVIEW scope for that run, so the Files and
Network lenses show *that* run instead of the live session
(``MainScreen.set_scope``; the scope id is the run folder, see
:func:`sandroid.core.run_history.scope_for_run`).

Data flow: ``RecordingController._run_playback_analysis`` persists a
``RunRecord`` via ``core/run_history.py`` and then calls back into
``on_new_run(run_id)`` (wired through ``app.py._notify_diffs_new_run``).
This view never talks to the recorder directly -- it only reads the on-disk
run index, each run's ``run.json`` and (off the UI thread) its results JSON
for errors, settings and contacted hosts.

Key scoping note: ``n`` (rename) and ``delete``/``backspace`` (delete) are
bound here on this Widget, not the App -- they only fire while this view has
focus. ``n`` renames only while the runs table has focus with a run
highlighted, and only after a confirm; anywhere else it falls through
(``SkipAction``) to the GLOBAL ``n`` = Install APK (``app.py``'s
``action_install_apk``, id ``"new_apk"``). ``v``, ``=``, ``z`` and ``P`` are
unbound globally. Record ``r`` / Play ``p`` are global app keys.
"""

from __future__ import annotations

import functools
import logging
import threading
from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.widgets import DataTable, Static

from sandroid.core import run_history

from .files_panel import FilesSubViewBase

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from .lens_shell import InspectorContent

logger = logging.getLogger(__name__)

# Muted palette for the Inspector renderables (Rich, not CSS). Red/yellow only
# for real problems.
_MUTED = "#8f9bb3"
_DIM = "#5b6479"
_ACCENT = "#38bdf8"
_WARN = "#f59e0b"
_BAD = "#ef4444"
_GOOD = "#22c55e"

#: Rows listed per category in the Inspector before "… N more".
_LIST_LIMIT = 12

_COLUMNS = (
    ("num", "#"),
    ("label", "Run"),
    ("when", "When"),
    ("took", "Took"),
    ("changes", "Changes"),
)
#: Below this lens width (e.g. Inspector open on a small terminal) the table
#: drops Took/Changes -- the Inspector shows them.
_COMPACT_BELOW = 80


class DiffsView(FilesSubViewBase):
    """Runs lens (id ``runs-panel``): the run table + Inspector + REVIEW scope.

    Bindings (when focused):
        Enter: open the highlighted run in the Inspector.
        v: review this run (REVIEW scope); again on the same run = back to LIVE.
        P: generate the PDF report for the highlighted run (Shift+P).
        n: rename the highlighted run, with a confirm (table focused only;
           elsewhere the global "n"=Install APK runs -- see module docstring).
        delete / backspace: delete the highlighted run, through a confirm.
        =: compare the highlighted run with the run under review (or, in
           LIVE, with the run before it) in the Inspector.
        z: the run's full file diff in the search/export view.
    """

    _LABEL = "Diffs"

    can_focus = True

    BINDINGS = [
        # Record/Play (r/p) are global app bindings (SandroidTUI.BINDINGS).
        # Order matters: the footer shows only the first context keys.
        Binding("v", "review_run", "Review"),
        Binding("P", "generate_pdf", "PDF report"),
        Binding("n", "rename_run", "Rename"),
        Binding("delete", "delete_run", "Delete"),
        # Same action as Del -- keep it out of the footer (listed once).
        Binding("backspace", "delete_run", "Delete", show=False),
        Binding("equals_sign", "compare_runs", "Compare", key_display="="),
        Binding("z", "zoom_diff", "Full diff"),
    ]

    DEFAULT_CSS = """
    DiffsView {
        layout: vertical;
        padding: 0 1;
        background: transparent;
    }
    DiffsView #runs-table {
        height: 1fr;
        background: transparent;
        scrollbar-size-vertical: 1;
    }
    DiffsView #runs-table > .datatable--header {
        background: transparent;
        color: #5b6479;
        text-style: none;
    }
    DiffsView #runs-table > .datatable--cursor {
        background: #12304d;
        color: #e5edf7;
        text-style: none;
    }
    DiffsView #runs-table > .datatable--hover {
        background: transparent;
    }
    DiffsView #runs-empty {
        height: 1fr;
        width: 1fr;
        content-align: center middle;
        text-align: center;
        color: #5b6479;
    }
    DiffsView.-has-runs #runs-empty {
        display: none;
    }
    DiffsView #runs-table {
        display: none;
    }
    DiffsView.-has-runs #runs-table {
        display: block;
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
        #: Full RunRecord for the currently-selected run, once loaded.
        self._detail_record: run_history.RunRecord | None = None
        #: run_id -> facts read from the run's results JSON (see _read_facts).
        self._facts: dict[str, dict[str, Any]] = {}
        self._facts_pending: set[str] = set()
        #: run_id -> evidence state ("checking" / "verified" / ... ).
        self._evidence: dict[str, str] = {}
        #: run id of the run under review (REVIEW scope), if any.
        self._scope_run_id: str | None = None
        #: Width of the label column (padded so the table spans the lens).
        self._width = 0
        self._compact = False

    # -- compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(
            Text.assemble(
                ("No runs yet\n\n", "bold #8f9bb3"),
                ("r", "bold"),
                (" record a flow  ·  ", _DIM),
                ("p", "bold"),
                (" replay it", _DIM),
            ),
            id="runs-empty",
        )
        table: DataTable = DataTable(
            id="runs-table", cursor_type="row", zebra_stripes=False
        )
        yield table

    def on_mount(self) -> None:
        import asyncio

        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None
        self._setup_columns()
        self._subscribe_events()
        self._reload_index()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    def _table(self) -> DataTable | None:
        try:
            return self.query_one("#runs-table", DataTable)
        except Exception:
            return None

    # -- focus forwarding ----------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the table so row navigation works.

        n/delete/v/... are not DataTable bindings, so they still bubble up to
        this widget afterwards.
        """
        table = self._table()
        if table is not None and self._summaries:
            table.focus(scroll_visible)
        else:
            super().focus(scroll_visible)
        return self

    # -- lens hooks ------------------------------------------------------------

    def on_activated(self) -> None:
        """Called when the Runs lens becomes active."""
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

    def _main_screen(self):
        """The MainScreen (lens API), or None under a bare test harness."""
        try:
            screen = self.screen
        except Exception:
            return None
        return screen if hasattr(screen, "set_lens_caption") else None

    def _update_caption(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        total = len(self._summaries)
        info = None
        if total:
            info = f"{total} run{'s' if total != 1 else ''} · ⏎ details"
        try:
            ms.set_lens_caption("runs", None, info)
            unread = len(self._unread_run_ids)
            ms.set_lens_badge("runs", f"●{unread}" if unread else None)
        except Exception:
            logger.debug("DiffsView: caption update failed", exc_info=True)

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
        """Refresh the table from disk (lens activation / device change / poll)."""
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
        if self._index_of(self._selected_run_id) is None:
            self._selected_run_id = None
            self._detail_record = None
        if self._selected_run_id is None and self._summaries:
            self._select_run(self._summaries[0]["run_id"])
            return
        self._rebuild_table()

    def on_new_run(self, run_id: str) -> None:
        """Called (main thread) once a new RunRecord has been saved.

        Gated auto-select (separate from the always-on "switch to the Runs
        lens on Play-press" handled in app.py): the cursor only moves to the
        new run if the user was on the latest run, or there were none.
        Otherwise the row arrives with an unread ``●`` marker and a toast,
        and the cursor stays on the older run the user is looking at.
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
            self._rebuild_table()
            self._toast_new_run(run_id)

    # -- selection / detail loading -----------------------------------------

    def _index_of(self, run_id: str | None) -> int | None:
        if run_id is None:
            return None
        for i, s in enumerate(self._summaries):
            if s.get("run_id") == run_id:
                return i
        return None

    def _summary(self, run_id: str | None) -> dict[str, Any] | None:
        idx = self._index_of(run_id)
        return None if idx is None else self._summaries[idx]

    def _current_label(self, run_id: str) -> str:
        s = self._summary(run_id)
        return (s.get("label") or run_id) if s else run_id

    def _run_number(self, run_id: str) -> int:
        """1-based chronological number (oldest run = #1)."""
        idx = self._index_of(run_id)
        return 0 if idx is None else len(self._summaries) - idx

    def _select_run(self, run_id: str) -> None:
        self._selected_run_id = run_id
        self._unread_run_ids.discard(run_id)
        if self._detail_record is not None and self._detail_record.run_id != run_id:
            self._detail_record = None
        self._rebuild_table()
        self._load_run_detail(run_id)
        self._follow_in_inspector()

    def _load_run_detail(self, run_id: str) -> None:
        """Read the full RunRecord (disk I/O) off the main thread."""
        self._run_bg(
            functools.partial(self._load_run_worker, run_id), f"diffs_load_{run_id}"
        )

    def _run_bg(self, fn, name: str) -> None:
        """Run ``fn`` on a worker thread, or inline if no app context exists.

        The inline fallback is what lets the actions be exercised directly in
        unit tests without a full Textual ``Pilot`` harness.
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
        self._detail_record = record
        if record is None:
            logger.warning("DiffsView: could not load run %s: %s", run_id, error)
        self._follow_in_inspector()

    # -- facts from the results JSON (worker thread) -------------------------

    def _load_missing_facts(self) -> None:
        missing = [
            s["run_id"]
            for s in self._summaries
            if s.get("run_id")
            and s["run_id"] not in self._facts
            and s["run_id"] not in self._facts_pending
        ]
        if not missing:
            return
        self._facts_pending.update(missing)
        self._run_bg(functools.partial(self._facts_worker, missing), "diffs_facts")

    def _facts_worker(self, run_ids: list[str]) -> None:
        facts = {run_id: self._read_facts(run_id) for run_id in run_ids}
        self._post(self._apply_facts, facts)

    @staticmethod
    def _read_facts(run_id: str) -> dict[str, Any]:
        """Errors, settings, hosts and report files of one run (disk I/O)."""
        run_dir = run_history.run_dir_for_scope(run_id)
        facts: dict[str, Any] = {"run_dir": str(run_dir) if run_dir else None}
        if run_dir is None:
            return facts
        doc = run_history.read_results_doc(run_dir) or {}
        meta = doc.get("Run Metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        settings = meta.get("run_settings")
        if not isinstance(settings, dict):
            settings = ((meta.get("settings") or {}).get("analysis")) or {}
        facts["settings"] = settings if isinstance(settings, dict) else {}
        errors = doc.get("Run Errors") or meta.get("run_errors")
        facts["run_errors"] = errors if isinstance(errors, dict) else None
        facts["status"] = meta.get("run_status")
        facts["mode"] = meta.get("mode")
        facts["app"] = meta.get("app") or meta.get("package")
        hosts = doc.get("Network")
        if not isinstance(hosts, list) or not hosts:
            hosts = doc.get("Network IP:Port (send/recv)")
        facts["hosts"] = (
            [str(h) for h in hosts if h] if isinstance(hosts, list) else None
        )
        facts["has_results"] = bool(doc)
        try:
            facts["pdfs"] = sorted(p.name for p in run_dir.glob("*.pdf"))
        except OSError:
            facts["pdfs"] = []
        return facts

    def _apply_facts(self, facts: dict[str, dict[str, Any]]) -> None:
        self._facts.update(facts)
        self._facts_pending.difference_update(facts)
        self._rebuild_table()
        self._follow_in_inspector()

    # -- evidence verification (worker thread) ------------------------------

    def _check_evidence(self, run_id: str) -> None:
        if run_id in self._evidence:
            return
        self._evidence[run_id] = "checking"
        self._run_bg(
            functools.partial(self._evidence_worker, run_id), f"diffs_verify_{run_id}"
        )

    def _evidence_worker(self, run_id: str) -> None:
        from sandroid.core import run_report

        run_dir = run_history.run_dir_for_scope(run_id)
        if run_dir is None:
            state = "missing"
        else:
            try:
                check = run_report.verify_hash_manifest(run_dir)
                if not check.present:
                    state = "unsealed"
                elif check.ok:
                    state = "verified"
                else:
                    bad = len(check.mismatched) + len(check.missing)
                    state = f"modified:{bad}"
            except Exception as exc:
                logger.debug("verify %s failed: %s", run_id, exc)
                state = "error"
        self._post(self._apply_evidence, run_id, state)

    def _apply_evidence(self, run_id: str, state: str) -> None:
        self._evidence[run_id] = state
        self._follow_in_inspector()

    # -- DataTable events ------------------------------------------------------

    def _cursor_run_id(self) -> str | None:
        table = self._table()
        if table is None or table.row_count == 0:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            return None
        return None if key is None else key.value

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "runs-table":
            return
        # Read the live cursor, not the event: a rebuild can leave stale
        # highlight events for rows that moved.
        run_id = self._cursor_run_id()
        if run_id and run_id != self._selected_run_id:
            self._select_run(run_id)

    # -- table rendering --------------------------------------------------

    #: Run actions -- hidden from the footer (and skipped) while there are
    #: no runs, so ``n`` still reaches the global Install APK then.
    _RUN_ACTIONS = frozenset(
        {
            "review_run",
            "generate_pdf",
            "rename_run",
            "delete_run",
            "compare_runs",
            "zoom_diff",
        }
    )

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in self._RUN_ACTIONS:
            return bool(self._summaries)
        return True

    def _rebuild_table(self) -> None:
        if self.has_class("-has-runs") != bool(self._summaries):
            self.refresh_bindings()
        self.set_class(bool(self._summaries), "-has-runs")
        self._update_caption()
        table = self._table()
        if table is None:
            return
        width = min(
            max([len(s.get("label") or "") for s in self._summaries] + [20]), 40
        )
        if self._compact:
            # "#" + marker + short When (+ cell padding, scrollbar) take ~20.
            width = max(10, min(width, self.size.width - 22))
        keys = [s.get("run_id", "") for s in self._summaries]
        if keys and keys == [k.value for k in table.rows] and width == self._width:
            # Same rows: update the cells in place (keeps scroll + cursor).
            columns = [str(key.value) for key in table.columns]
            for s in self._summaries:
                for column, cell in zip(
                    columns, self._row_cells(s, width), strict=True
                ):
                    table.update_cell(
                        s.get("run_id", ""), column, cell, update_width=True
                    )
        else:
            table.clear()
            for s in self._summaries:
                table.add_row(*self._row_cells(s, width), key=s.get("run_id", ""))
        self._width = width
        idx = self._index_of(self._selected_run_id)
        if idx is not None and table.cursor_row != idx:
            try:
                table.move_cursor(row=idx, animate=False)
            except Exception:
                pass
        if self._summaries:
            self._load_missing_facts()

    def _row_cells(self, s: dict[str, Any], label_width: int) -> list[Text]:
        run_id = s.get("run_id", "")
        number = Text(f"{self._run_number(run_id)}", style=_DIM, justify="right")
        label = Text()
        if run_id == self._scope_run_id:
            label.append("◆ ", style=_ACCENT)
        elif run_id in self._unread_run_ids:
            label.append("● ", style="#22d3ee")
        else:
            label.append("  ")
        name = s.get("label") or run_id
        if len(name) > label_width:
            name = name[: label_width - 1] + "…"
        label.append(name.ljust(label_width))
        when = Text(
            self._format_when(s.get("recorded_at"), short=self._compact),
            style=_MUTED,
        )
        took = Text(self._format_duration(s.get("duration")), style=_MUTED)
        replays = self._replays(run_id)
        if replays > 1:
            took.append(f"  ×{replays}", style=_DIM)
        if self._compact:
            return [number, label, when]
        return [number, label, when, took, self._changes_cell(s)]

    def _setup_columns(self) -> None:
        table = self._table()
        if table is None:
            return
        table.clear(columns=True)
        for key, label in _COLUMNS[: 3 if self._compact else len(_COLUMNS)]:
            table.add_column(label, key=key)
        self._width = 0

    def on_resize(self, event) -> None:
        compact = event.size.width < _COMPACT_BELOW
        if compact == self._compact and not compact:
            return
        if compact != self._compact:
            self._compact = compact
            self._setup_columns()
        self._rebuild_table()

    def _replays(self, run_id: str) -> int:
        settings = (self._facts.get(run_id) or {}).get("settings") or {}
        try:
            return int(settings.get("number_of_runs") or 1)
        except (TypeError, ValueError):
            return 1

    def _changes_cell(self, s: dict[str, Any]) -> Text:
        counts = s.get("counts") or {}
        files = sum(int(counts.get(k, 0) or 0) for k in ("changed", "new", "deleted"))
        facts = self._facts.get(s.get("run_id", "")) or {}
        parts: list[tuple[str, str]] = []
        if files:
            parts.append((f"{files} file{'s' if files != 1 else ''}", ""))
        hosts = facts.get("hosts")
        if hosts:
            parts.append((f"{len(hosts)} host{'s' if len(hosts) != 1 else ''}", ""))
        cell = Text()
        for i, (text, style) in enumerate(parts):
            if i:
                cell.append(" · ", style=_DIM)
            cell.append(text, style=style)
        if not parts:
            cell.append("no changes", style=_DIM)
        problem = self._problem(s)
        if problem:
            text, style = problem
            cell.append("   ")
            cell.append(text, style=style)
        return cell

    def _problem(self, s: dict[str, Any]) -> tuple[str, str] | None:
        """The run's error badge: aborted (red) or step errors (yellow)."""
        facts = self._facts.get(s.get("run_id", "")) or {}
        errors = facts.get("run_errors") or {}
        steps = len(errors.get("steps") or [])
        if s.get("error") or errors.get("fatal"):
            if s.get("error") == "Replay cancelled":
                return "◼ stopped", _WARN
            return "✕ aborted", _BAD
        if steps:
            return f"⚠ {steps} error{'s' if steps != 1 else ''}", _WARN
        return None

    @staticmethod
    def _parse(iso: str | None) -> datetime | None:
        if not iso:
            return None
        try:
            return datetime.fromisoformat(iso)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _format_when(
        cls, iso: str | None, now: datetime | None = None, short: bool = False
    ) -> str:
        """``today 10:42`` / ``yesterday`` / weekday / date (``short``: 6 chars)."""
        dt = cls._parse(iso)
        if dt is None:
            return "--:--"
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        now = now or datetime.now()
        days = (now.date() - dt.date()).days
        clock = dt.strftime("%H:%M")
        if short:
            return clock if days == 0 else f"{dt.day} {dt.strftime('%b')}"
        if days == 0:
            return f"today {clock}"
        if days == 1:
            return f"yesterday {clock}"
        if 1 < days < 7:
            return f"{dt.strftime('%a')} {clock}"
        return f"{dt.day} {dt.strftime('%b')} {clock}"

    @staticmethod
    def _format_timestamp(iso: str | None) -> str:
        if not iso:
            return "--:--"
        try:
            return datetime.fromisoformat(iso).strftime("%H:%M")
        except Exception:
            return "--:--"

    @staticmethod
    def _format_duration(seconds: Any) -> str:
        try:
            total = int(seconds or 0)
        except (TypeError, ValueError):
            total = 0
        if total <= 0:
            return "–"
        minutes, secs = divmod(total, 60)
        if minutes >= 60:
            hours, minutes = divmod(minutes, 60)
            return f"{hours}h {minutes:02d}m"
        if minutes:
            return f"{minutes}m {secs:02d}s"
        return f"{secs}s"

    # -- Inspector ---------------------------------------------------------

    def inspect_selected(self) -> InspectorContent | None:
        """Enter → Inspector: Summary / Changes / Report of the highlighted run."""
        run_id = self._cursor_run_id() or self._selected_run_id
        if not run_id or self._summary(run_id) is None:
            return None
        if run_id != self._selected_run_id:
            self._select_run(run_id)
        self._check_evidence(run_id)
        return self._run_content(run_id)

    def _inspector_shows_run(self) -> bool:
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return False
        content = ms.inspector_content
        key = getattr(content, "key", None)
        return isinstance(key, tuple) and key[:1] == ("run",)

    def _follow_in_inspector(self) -> None:
        """Keep an open run Inspector on the highlighted run (live update)."""
        if not self._inspector_shows_run():
            return
        run_id = self._selected_run_id
        if not run_id:
            return
        self._check_evidence(run_id)
        content = self._run_content(run_id)
        if content is not None:
            self._main_screen().update_inspector(content)

    def _run_content(self, run_id: str) -> InspectorContent | None:
        from .lens_shell import InspectorContent

        s = self._summary(run_id)
        if s is None:
            return None
        record = (
            self._detail_record
            if self._detail_record is not None and self._detail_record.run_id == run_id
            else None
        )
        facts = self._facts.get(run_id) or {}
        label = s.get("label") or run_id
        subtitle = None
        if run_id == self._scope_run_id:
            subtitle = f"[{_ACCENT}]◆ in review[/] [{_DIM}]· L back to live[/]"
        return InspectorContent(
            title=label,
            subtitle=subtitle,
            tabs=[
                ("Summary", self._summary_sections(s, facts)),
                ("Changes", self._changes_sections(s, record, facts)),
                ("Report", self._report_sections(run_id, facts)),
            ],
            footer="v review · = compare · z diff · ⇧P pdf",
            key=("run", run_id),
        )

    @staticmethod
    def _grid() -> Table:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=_DIM, no_wrap=True, min_width=12)
        grid.add_column()
        return grid

    def _summary_sections(
        self, s: dict[str, Any], facts: dict[str, Any]
    ) -> list[tuple[str, Any]]:
        run_id = s.get("run_id", "")
        grid = self._grid()
        start = self._parse(s.get("recorded_at"))
        end = self._parse(s.get("completed_at"))
        when = self._format_when(s.get("recorded_at"))
        if start is not None and end is not None:
            when = f"{start.strftime('%a %d %b %Y · %H:%M')} → {end.strftime('%H:%M')}"
        grid.add_row("When", when)
        took = self._format_duration(s.get("duration"))
        replays = self._replays(run_id)
        if replays > 1:
            took += f"  ·  {replays} replays"
        grid.add_row("Took", took)
        grid.add_row("Device", Text(str(s.get("device_name") or "unknown")))
        if facts.get("app"):
            grid.add_row("App", Text(str(facts["app"])))
        grid.add_row("Status", self._status_text(s, facts))
        grid.add_row("Evidence", self._evidence_text(run_id))

        settings = facts.get("settings") or {}
        cfg = self._grid()
        if "replay_settle_seconds" in settings:
            cfg.add_row("Settle", f"{settings['replay_settle_seconds']} s after replay")
        if "network_reset_after_snapshot" in settings:
            cfg.add_row("Net reset", str(settings["network_reset_after_snapshot"]))
        if "avoid_strong_noise_filter" in settings:
            noise = "off" if settings["avoid_strong_noise_filter"] else "on"
            cfg.add_row("Noise filter", noise)
        if "capture_network" in settings:
            cfg.add_row("Capture", self._capture_text(settings))

        sections: list[tuple[str, Any]] = [("", grid)]
        errors = self._error_lines(s, facts)
        if errors is not None:
            sections.append(("Errors", errors))
        if cfg.row_count:
            sections.append(("Settings", cfg))
        sections.append(
            ("", Text("n rename · del delete", style=_DIM)),
        )
        return sections

    @staticmethod
    def _capture_text(settings: dict[str, Any]) -> str:
        names = [
            name
            for key, name in (
                ("capture_network", "network"),
                ("capture_processes", "processes"),
                ("capture_sockets", "sockets"),
                ("hash_files", "hashes"),
            )
            if settings.get(key)
        ]
        return ", ".join(names) if names else "files only"

    def _status_text(self, s: dict[str, Any], facts: dict[str, Any]) -> Text:
        problem = self._problem(s)
        if problem is None:
            return Text("✓ completed", style=_GOOD)
        text, style = problem
        return Text(text, style=style)

    def _error_lines(self, s: dict[str, Any], facts: dict[str, Any]) -> Text | None:
        errors = facts.get("run_errors") or {}
        fatal = s.get("error") or errors.get("fatal")
        steps = errors.get("steps") or []
        if not fatal and not steps:
            return None
        out = Text()
        if fatal:
            out.append(str(fatal), style=_BAD)
        for step in steps[:_LIST_LIMIT]:
            if out:
                out.append("\n")
            name = str(step.get("step") or "step") if isinstance(step, dict) else ""
            msg = str(step.get("error") or "") if isinstance(step, dict) else str(step)
            run = step.get("run") if isinstance(step, dict) else None
            out.append(f"{name}", style=_WARN)
            if run:
                out.append(f" (replay {run})", style=_DIM)
            out.append(f"  {msg}")
        if len(steps) > _LIST_LIMIT:
            out.append(f"\n… {len(steps) - _LIST_LIMIT} more", style=_DIM)
        return out

    def _evidence_text(self, run_id: str) -> Text:
        state = self._evidence.get(run_id, "checking")
        if state == "verified":
            return Text("✓ verified (SHA256SUMS)", style=_GOOD)
        if state.startswith("modified:"):
            n = state.split(":", 1)[1]
            return Text(f"✕ {n} file(s) changed since sealing", style=_BAD)
        if state == "unsealed":
            return Text("not sealed (no SHA256SUMS)", style=_DIM)
        if state == "missing":
            return Text("run folder missing", style=_BAD)
        if state == "error":
            return Text("could not verify", style=_WARN)
        return Text("checking…", style=_DIM)

    def _changes_sections(
        self,
        s: dict[str, Any],
        record: run_history.RunRecord | None,
        facts: dict[str, Any],
    ) -> list[tuple[str, Any]]:
        counts = s.get("counts") or {}
        head = Text()
        for i, (key, name, color) in enumerate(
            (
                ("changed", "changed", "#facc15"),
                ("new", "new", _GOOD),
                ("deleted", "deleted", _BAD),
            )
        ):
            if i:
                head.append("   ")
            head.append(f"{int(counts.get(key, 0) or 0)}", style=f"bold {color}")
            head.append(f" {name}", style=_MUTED)
        sections: list[tuple[str, Any]] = [("", head)]
        if record is None:
            sections.append(("", Text("loading…", style=_DIM)))
            return sections
        rows = run_history.file_diff_rows(record)
        for kind, title in (
            ("changed", "Changed"),
            ("new", "New"),
            ("deleted", "Deleted"),
        ):
            subset = [r for r in rows if r.kind == kind]
            if not subset:
                continue
            body = Text()
            for row in subset[:_LIST_LIMIT]:
                if body:
                    body.append("\n")
                body.append(self._short_path(row.path, 38))
                if row.diff:
                    n = len(row.diff)
                    body.append(f"  {n} line{'s' if n != 1 else ''}", style=_DIM)
            if len(subset) > _LIST_LIMIT:
                body.append(f"\n… {len(subset) - _LIST_LIMIT} more", style=_DIM)
            sections.append((title, body))
        hosts = facts.get("hosts")
        if hosts:
            body = Text("\n".join(hosts[:_LIST_LIMIT]))
            if len(hosts) > _LIST_LIMIT:
                body.append(f"\n… {len(hosts) - _LIST_LIMIT} more", style=_DIM)
            sections.append((f"Hosts ({len(hosts)})", body))
        sections.append(("", Text("z full diff · v review in Files", style=_DIM)))
        return sections

    @staticmethod
    def _short_path(path: str, limit: int = 52) -> str:
        if len(path) <= limit:
            return path
        return "…" + path[-(limit - 1) :]

    def _report_sections(
        self, run_id: str, facts: dict[str, Any]
    ) -> list[tuple[str, Any]]:
        run_dir = facts.get("run_dir") or str(run_history.scope_for_run(run_id))
        grid = self._grid()
        pdfs = facts.get("pdfs") or []
        if pdfs:
            grid.add_row("PDF", Text("\n".join(pdfs)))
        else:
            grid.add_row("PDF", Text("none yet", style=_DIM))
        if facts.get("has_results"):
            grid.add_row("Results", run_history.RESULTS_JSON_NAME)
        grid.add_row("Evidence", self._evidence_text(run_id))
        return [
            ("", grid),
            ("Folder", Text(run_dir, style=_MUTED)),
            ("", Text("⇧P write a new PDF report", style=_DIM)),
        ]

    # -- actions (main-thread entry points) ---------------------------------

    def _highlighted_run(self) -> str | None:
        return self._cursor_run_id() or self._selected_run_id

    def action_review_run(self) -> None:
        """``v`` -- review the highlighted run (REVIEW scope); again = LIVE."""
        run_id = self._highlighted_run()
        ms = self._main_screen()
        if not run_id or ms is None:
            return
        if run_id == self._scope_run_id:
            ms.set_scope(None)
            return
        ms.set_scope(run_history.scope_for_run(run_id), self._current_label(run_id))
        self._notify(f"Reviewing '{self._current_label(run_id)}' · L back to live")

    def on_scope_changed(self, message) -> None:
        """MainScreen's ``ScopeChanged``: mark the reviewed row with ◆."""
        run_dir = run_history.run_dir_for_scope(getattr(message, "run_id", None))
        scope_run_id = run_dir.name if run_dir is not None else None
        if scope_run_id == self._scope_run_id:
            return
        self._scope_run_id = scope_run_id
        self._rebuild_table()
        self._follow_in_inspector()

    def action_rename_run(self) -> None:
        """``n`` — rename the highlighted run, after an explicit confirm.

        Only acts while the runs table has focus with a run highlighted;
        otherwise the key falls through (``SkipAction``) to the global
        ``n`` = Install APK. The new label is applied only after a Yes in a
        confirm dialog (a tester once typed an APK path here).
        """
        from textual.actions import SkipAction

        run_id = self._highlighted_run()
        table = self._table()
        table_focused = bool(table is not None and table.has_focus)
        if not run_id or not table_focused:
            raise SkipAction
        from sandroid.tui.modals import ConfirmModal, InputModal

        current = self._current_label(run_id)

        def on_confirm(yes: bool | None, label: str) -> None:
            if yes:
                self._rename_run_bg(run_id, label)

        def on_result(value: str | None) -> None:
            if value is None:
                return
            label = value.strip()
            if not label or label == current:
                return
            message = f"Rename run '{current}' to '{label}'?"
            if label.lower().endswith(".apk") or "/" in label:
                message += (
                    "\nThis looks like a file path. To install an APK, "
                    "choose No and press n outside the Runs lens."
                )
            self.app.push_screen(
                ConfirmModal(title="Rename run", message=message),
                lambda yes: on_confirm(yes, label),
            )

        self.app.push_screen(
            InputModal(
                title=f"Rename run '{current}'",
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
            ms = self._main_screen()
            if ms is not None and run_id == self._scope_run_id:
                ms.set_scope(ms.scope, label)  # the pill shows the new name
            self._follow_in_inspector()
        self._notify(msg, "information" if ok else "error")

    def action_generate_pdf(self) -> None:
        """``P`` -- (re)generate the PDF report for the highlighted run.

        Falls back to the newest run when nothing is selected. Runs
        :func:`sandroid.core.run_report.report_from_folder` on the run's
        bundle directory in a worker thread.
        """
        run_id = self._highlighted_run() or (
            self._summaries[0]["run_id"] if self._summaries else None
        )
        if not run_id:
            self._notify("No run to generate a report for.", "warning")
            return
        self._notify(f"Generating PDF report for {self._current_label(run_id)}...")
        self._run_bg(
            functools.partial(self._generate_pdf_worker, run_id), f"diffs_pdf_{run_id}"
        )

    def _generate_pdf_worker(self, run_id: str) -> None:
        from sandroid.core import run_bundle, run_report

        try:
            outcome = run_report.report_from_folder(run_bundle.bundle_dir(run_id))
        except Exception as e:
            logger.warning("PDF report for %s failed: %s", run_id, e, exc_info=True)
            self._post(self._notify, f"PDF report failed: {e}", "error")
            return
        message = f"PDF report written: {outcome.pdf}"
        severity = "information"
        if outcome.check.present and not outcome.check.ok:
            message += " (WARNING: evidence manifest verification failed)"
            severity = "warning"
        self._post(self._after_pdf, run_id, message, severity)

    def _after_pdf(self, run_id: str, message: str, severity: str) -> None:
        # New files in the folder: re-read the report list and re-verify.
        self._facts.pop(run_id, None)
        self._evidence.pop(run_id, None)
        self._load_missing_facts()
        self._notify(message, severity)

    def action_delete_run(self) -> None:
        """``delete``/``backspace`` — delete the highlighted run (confirm first).

        Never deletes on a bare keypress.
        """
        run_id = self._highlighted_run()
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
            self._facts.pop(run_id, None)
            self._evidence.pop(run_id, None)
            if self._selected_run_id == run_id:
                self._selected_run_id = None
                self._detail_record = None
            ms = self._main_screen()
            if ms is not None:
                if run_id == self._scope_run_id:
                    ms.set_scope(None)
                if self._inspector_shows_run():
                    content = ms.inspector_content
                    if content is not None and run_id in content.key:
                        ms.close_inspector()
            self._reload_index()
        self._notify(msg, "information" if ok else "error")

    def action_zoom_diff(self) -> None:
        """``z`` -- the highlighted run's full file diff (search / export)."""
        run_id = self._highlighted_run()
        record = self._detail_record
        if not run_id or record is None or record.run_id != run_id:
            self._notify("Run still loading — try again.", "warning")
            return
        lines: list[str] = []
        for row in run_history.file_diff_rows(record):
            sign = {"changed": "~", "new": "+", "deleted": "-"}[row.kind]
            lines.append(f"{sign} {row.path}")
            lines.extend(f"    {x}" for x in row.diff or [])
        if not lines:
            self._notify("This run changed no files.")
            return
        from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal

        self.app.push_screen(
            DiffZoomModal(diff_text="\n".join(lines), title=self._current_label(run_id))
        )

    def action_compare_runs(self) -> None:
        """``=`` -- compare the highlighted run with another in the Inspector.

        The other run is the one under review (REVIEW scope) or, in LIVE /
        when the highlighted run *is* the reviewed one, the run before it.
        """
        run_b = self._highlighted_run()
        if not run_b:
            return
        run_a = self._scope_run_id if self._scope_run_id != run_b else None
        if run_a is None:
            idx = self._index_of(run_b)
            if idx is None or idx + 1 >= len(self._summaries):
                self._notify("No earlier run to compare with.", "warning")
                return
            run_a = self._summaries[idx + 1]["run_id"]
        self._run_bg(
            functools.partial(self._compare_worker, run_a, run_b), "diffs_compare"
        )

    def _compare_worker(self, run_a: str, run_b: str) -> None:
        try:
            rec_a = run_history.load_run(run_a)
            rec_b = run_history.load_run(run_b)
        except Exception as exc:
            self._post(self._notify, f"Compare failed: {exc}", "error")
            return
        facts = {r: self._facts.get(r) or self._read_facts(r) for r in (run_a, run_b)}
        self._post(self._show_compare, rec_a, rec_b, facts)

    def _show_compare(
        self,
        rec_a: run_history.RunRecord,
        rec_b: run_history.RunRecord,
        facts: dict[str, dict[str, Any]],
    ) -> None:
        from .lens_shell import InspectorContent

        ms = self._main_screen()
        if ms is None:
            return
        numbers = (self._run_number(rec_a.run_id), self._run_number(rec_b.run_id))
        content = InspectorContent(
            title=f"#{numbers[0]} ⇄ #{numbers[1]}",
            sections=self.compare_sections(rec_a, rec_b, facts, numbers),
            footer="= compare · ⏎ run",
            key=("compare", rec_a.run_id, rec_b.run_id),
        )
        ms.open_inspector(content)

    @classmethod
    def compare_sections(
        cls,
        rec_a: run_history.RunRecord,
        rec_b: run_history.RunRecord,
        facts: dict[str, dict[str, Any]] | None = None,
        numbers: tuple[int, int] = (0, 0),
    ) -> list[tuple[str, Any]]:
        """What differs between two runs: files (and hosts, when known)."""

        def paths(record: run_history.RunRecord) -> dict[str, str]:
            return {r.path: r.kind for r in run_history.file_diff_rows(record)}

        a, b = paths(rec_a), paths(rec_b)
        only_a = sorted(set(a) - set(b))
        only_b = sorted(set(b) - set(a))
        both = len(set(a) & set(b))
        sections: list[tuple[str, Any]] = []
        num_a = f"#{numbers[0]}" if numbers[0] else "A"
        num_b = f"#{numbers[1]}" if numbers[1] else "B"
        head = Text.assemble(
            (f"{len(only_b)}", "bold"),
            (f" files only in {num_b}   ", _MUTED),
            (f"{len(only_a)}", "bold"),
            (f" only in {num_a}   ", _MUTED),
            (f"{both}", "bold"),
            (" in both", _MUTED),
        )
        sections.append(("", head))
        for title, items, kinds in (
            (f"Only in {num_b} · {rec_b.label}", only_b, b),
            (f"Only in {num_a} · {rec_a.label}", only_a, a),
        ):
            if not items:
                continue
            body = Text()
            for p in items[:_LIST_LIMIT]:
                if body:
                    body.append("\n")
                body.append(f"{kinds[p]:<8}", style=_DIM)
                body.append(cls._short_path(p, 38))
            if len(items) > _LIST_LIMIT:
                body.append(f"\n… {len(items) - _LIST_LIMIT} more", style=_DIM)
            sections.append((title, body))
        facts = facts or {}
        hosts_a = set((facts.get(rec_a.run_id) or {}).get("hosts") or [])
        hosts_b = set((facts.get(rec_b.run_id) or {}).get("hosts") or [])
        if hosts_a or hosts_b:
            body = Text()
            for sign, items, style in (
                ("+", sorted(hosts_b - hosts_a), _WARN),
                ("−", sorted(hosts_a - hosts_b), _MUTED),
            ):
                for h in items[:_LIST_LIMIT]:
                    if body:
                        body.append("\n")
                    body.append(f"{sign} {h}", style=style)
            if not body:
                body = Text("same hosts in both runs", style=_DIM)
            sections.append(("Hosts", body))
        return sections

    # -- EventBus wiring (device-switch detection; thread-safe) -------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            def _cb(_event) -> None:
                # Post through this widget's own message queue (thread-safe,
                # non-blocking), NOT loop.call_soon_threadsafe: a bare loop
                # callback runs in the publisher's empty contextvars context
                # and crashed the TUI with NoActiveAppError (P2-H1). The
                # message handler runs with the app context set.
                try:
                    self.call_later(self._refresh_if_visible)
                except Exception:
                    logger.debug("DiffsView: refresh scheduling failed", exc_info=True)

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
        """True if the Runs lens (this view) is the visible one."""
        from .lens_shell import is_shown

        return is_shown(self)

    def _refresh_if_visible(self) -> None:
        if self._is_on_screen():
            self._reload_index()

    # -- thread marshalling / notifications ---------------------------------

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread.

        Deliberately ``call_from_thread`` (blocking the worker until ``fn``
        completes): it re-establishes the app context that widget updates
        need. Blocking is safe -- ``fn`` is only ever called from a
        ``run_worker(thread=True)`` thread this view spawned for this one
        result.
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
        self._notify(f"New run ready: {label} (marked ● in Runs)", "information")


__all__ = ["DiffsView"]
