"""Runs lens: "which runs do I have, and what did each change?"

Every completed Rewind run is one row of a full-width table (newest first):
``#`` · run label · when · how long · what changed. Details are on demand:
Enter opens the run in the Inspector (Summary / Changes / Report / Privacy
tabs), and
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
unbound globally. Record ``r`` / Review ``p`` are global app keys.

Privacy tab: the identity-profile values the privacy scan found during the
run (its time window, plus the end-of-run sweep's records that carry the run
id), grouped by recipient, in words. A run of another session (its record
names its timeline folder) reads that session's ``privacy/hits.jsonl`` off
the UI thread, once.
``{``/``}`` (Inspector keys) or a click picks a finding and ``J`` jumps to
its flow (Network), file (Files) or timeline line.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.style import Style
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.widgets import DataTable, Static

from sandroid.core import run_history
from sandroid.tui.row_annotations import AnnotationFeed

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

#: What an empty Privacy tab means (plain words).
_PRIVACY_NONE = "No profile values found in this run."
_PRIVACY_NOT_ACTIVE = "No identity profile was active."
_PRIVACY_LOADING = "Reading the findings of this run's session."
#: Runs saved before the run record named its session: only the loaded
#: session's findings can be matched.
_PRIVACY_NONE_HERE = (
    "No profile values found for this run in this session's findings. "
    "Findings for runs of other sessions are not loaded."
)
_PRIVACY_NOT_ACTIVE_HERE = (
    "No identity profile was active in this session. "
    "Findings for runs of other sessions are not loaded."
)

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

#: Two runs of the same recording "diverge" when their file counts differ by
#: at least this many files *and* by at least this factor (hosts: below).
_DIVERGE_FILES = (10, 2.0)
_DIVERGE_HOSTS = (5, 2.0)
#: A non-forced evidence re-check (cursor moves, refreshes) stats the bundle
#: at most this often per run.
_EVIDENCE_RECHECK_S = 5.0

_HOST_SUFFIX = re.compile(r"\s*\(.*\)\s*$")


def host_key(host: str) -> str:
    """Normalise a host entry for comparisons.

    The results list hosts as ``"api.example.com. (also seen in background:
    2 queries)"``; the suffix depends on the run's noise counts, so the same
    host appeared as both ``+`` and ``-`` in ``=`` compare (M-32).
    """
    return _HOST_SUFFIX.sub("", str(host)).strip().rstrip(".").lower()


def _diverges(a: int, b: int, limits: tuple[int, float]) -> bool:
    least, factor = limits
    lo, hi = sorted((int(a), int(b)))
    return hi - lo >= least and hi >= factor * max(lo, 1)


def replay_divergence(
    files_a: int, files_b: int, hosts_a: int | None = None, hosts_b: int | None = None
) -> list[str]:
    """Why two runs of the same recording disagree (empty: they agree).

    Large gaps mean at least one replay did not do what the recording did
    (a tap that did not take, a slow app); the results cannot both be right.
    """
    out = []
    if _diverges(files_a, files_b, _DIVERGE_FILES):
        out.append(f"{files_a} vs {files_b} files")
    if (
        hosts_a is not None
        and hosts_b is not None
        and _diverges(hosts_a, hosts_b, _DIVERGE_HOSTS)
    ):
        out.append(f"{hosts_a} vs {hosts_b} hosts")
    return out


def bundle_fingerprint(run_dir) -> str:
    """Cheap fingerprint (paths, sizes, mtimes) of every file in a bundle.

    Lets the evidence check skip a full re-hash while nothing changed, and
    re-verify as soon as any file's size or mtime differs (M-34).
    """
    digest = hashlib.sha256()
    try:
        for dirpath, dirnames, filenames in os.walk(run_dir):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                try:
                    st = path.stat()
                except OSError:
                    continue
                digest.update(f"{path}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    except OSError:
        pass
    return digest.hexdigest()


class _AnyLensFeed(AnnotationFeed):
    """An :class:`AnnotationFeed` of every lens's row changes (the run
    Inspector's Privacy tab lists network and file findings alike).
    """

    def on_change(self, lens: str | None, keys: frozenset[str] | None) -> None:
        super().on_change(None, keys)


class RunsTable(DataTable):
    """The runs table: Home / End move the cursor to the newest / oldest run."""

    BINDINGS = [
        Binding("home", "scroll_top", "Newest run", show=False),
        Binding("end", "scroll_bottom", "Oldest run", show=False),
    ]


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
        Binding("J", "privacy_jump", "Jump to the picked privacy finding", show=False),
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
        #: run_id -> bundle fingerprint the evidence state was computed for.
        self._evidence_fp: dict[str, str] = {}
        #: run_id -> monotonic time of the last evidence (re-)check start.
        self._evidence_at: dict[str, float] = {}
        self._evidence_busy: set[str] = set()
        #: Phase of a running Play (shown while there is no run yet).
        self._play_phase: str | None = None
        #: run id of the run under review (REVIEW scope), if any.
        self._scope_run_id: str | None = None
        #: Width of the label column (padded so the table spans the lens).
        self._width = 0
        self._cursor_synced_to: str | None = None
        self._compact = False
        #: run_id -> index of the picked finding on the Privacy tab.
        self._privacy_pick: dict[str, int] = {}
        #: timeline folder -> (records, scanned) of other sessions' findings
        #: (read once, off the UI thread).
        self._privacy_other: dict[str, tuple[list, bool]] = {}
        self._privacy_other_pending: set[str] = set()
        #: Privacy findings (row annotations of any lens) changed: keep an
        #: open run Inspector current, at most once a second.
        self._privacy_feed = _AnyLensFeed(
            self, "", lambda _keys: self._follow_in_inspector()
        )

    # -- compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._empty_text(), id="runs-empty")
        table: DataTable = RunsTable(
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
        self._privacy_feed.attach()
        self._reload_index()

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        self._privacy_feed.detach()

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

    def set_run_phase(self, phase: str | None, kind: str | None = None) -> None:
        """The Record / Rewind status line (app.py), in the caption and the
        empty state.

        Args:
            phase: The controller's plain status line, or None when nothing
                runs.
            kind: ``"Rewind"`` or ``"Replay"`` while a Rewind (or Rewind +
                Replay) runs, else None (a recording's line says what it is).
        """
        self._play_phase = phase
        self._update_caption()
        try:
            empty = self.query_one("#runs-empty", Static)
        except Exception:
            return
        empty.update(self.phase_text(phase, kind) if phase else self._empty_text())

    @staticmethod
    def phase_text(phase: str, kind: str | None = None) -> Text:
        """The empty state while ``phase`` runs (``"Rewind running · ..."``)."""
        if not kind:
            return Text(phase, style="bold #8f9bb3")
        return Text.assemble(
            (f"{kind} running · ", "bold #fb7185"),
            (f"{phase}\n\n", "bold #8f9bb3"),
            ("the run appears here when the rewind is done", _DIM),
        )

    @staticmethod
    def _empty_text() -> Text:
        return Text.assemble(
            ("No runs yet\n\n", "bold #8f9bb3"),
            ("r", "bold"),
            (" record a flow  ·  ", _DIM),
            ("p", "bold"),
            (" review it", _DIM),
        )

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
        title = self._play_phase or None
        try:
            ms.set_lens_caption("runs", title, info)
            unread = len(self._unread_run_ids)
            ms.set_lens_badge("runs", f"{unread} new" if unread else None)
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

    def select_run(self, run_id: str) -> bool:
        """Select ``run_id`` and show it in the Inspector (the Timeline lens's
        ``J`` on a line with ``ref.run``). False for an unknown run.
        """
        if self._summary(run_id) is None:
            return False
        self._select_run(run_id)
        ms = self._main_screen()
        if ms is not None:
            self._check_evidence(run_id, force=True)
            content = self._run_content(run_id)
            if content is not None:
                ms.open_inspector(content)
        return True

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
        facts["recording"] = run_history.recording_digest(run_dir)
        # The recording's own length (first to last input event); the run's
        # "duration" is the replay window (replay + settle).
        from sandroid.tui.controllers.recording_controller import (
            RecordingController,
        )

        # Tracking's raw getevent copy (new runs), else the legacy file.
        recording = run_dir / "recording.getevent.txt"
        if not recording.exists():
            recording = run_dir / "recording.txt"
        facts["recording_seconds"] = RecordingController.recording_seconds(
            str(recording)
        )
        try:
            facts["pcaps"] = sorted(
                (p.relative_to(run_dir).as_posix(), p.stat().st_size)
                for p in run_dir.rglob("*.pcap*")
                if p.is_file()
            )
        except OSError:
            facts["pcaps"] = []
        try:
            import json as _json

            net_meta = run_dir / run_history.NETWORK_DIR_NAME / "meta.json"
            facts["flows"] = _json.loads(net_meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            facts["flows"] = None
        return facts

    def _apply_facts(self, facts: dict[str, dict[str, Any]]) -> None:
        self._facts.update(facts)
        self._facts_pending.difference_update(facts)
        self._rebuild_table()
        self._follow_in_inspector()

    # -- evidence verification (worker thread) ------------------------------

    def _check_evidence(self, run_id: str, force: bool = False) -> None:
        """(Re-)verify a run's bundle against its ``SHA256SUMS`` off-thread.

        The result used to be cached for the whole session, so a file
        changed after the first check still showed "✓ verified" (M-34).
        Now ``force`` (Enter on a run, ``v``) always re-hashes; other calls
        (cursor moves, refreshes) re-hash only when the bundle's
        fingerprint (sizes + mtimes) changed, at most every few seconds.
        """
        if run_id in self._evidence_busy:
            return
        now = time.monotonic()
        if (
            not force
            and run_id in self._evidence
            and now - self._evidence_at.get(run_id, 0.0) < _EVIDENCE_RECHECK_S
        ):
            return
        self._evidence_at[run_id] = now
        self._evidence_busy.add(run_id)
        self._evidence.setdefault(run_id, "checking")
        self._run_bg(
            functools.partial(
                self._evidence_worker, run_id, force, self._evidence_fp.get(run_id)
            ),
            f"diffs_verify_{run_id}",
        )

    def _evidence_worker(
        self, run_id: str, force: bool = True, known_fp: str | None = None
    ) -> None:
        from sandroid.core import run_report

        run_dir = run_history.run_dir_for_scope(run_id)
        fp = ""
        if run_dir is None:
            state = "missing"
        else:
            fp = bundle_fingerprint(run_dir)
            if not force and known_fp is not None and fp == known_fp:
                self._post(self._apply_evidence, run_id, None, fp)
                return
            try:
                check = run_report.verify_hash_manifest(run_dir)
                if not check.present:
                    state = "unsealed"
                elif check.ok:
                    state = "verified"
                else:
                    bad = check.mismatched + check.missing
                    state = f"modified:{len(bad)}:" + ",".join(bad[:3])
            except Exception as exc:
                logger.debug("verify %s failed: %s", run_id, exc)
                state = "error"
        self._post(self._apply_evidence, run_id, state, fp)

    def _apply_evidence(self, run_id: str, state: str | None, fp: str = "") -> None:
        self._evidence_busy.discard(run_id)
        if state is not None:
            self._evidence[run_id] = state
            self._evidence_fp[run_id] = fp
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
            # Leave the cursor alone unless the selection changed: a refresh
            # (facts loaded, resize, scope) must not undo a cursor move whose
            # RowHighlighted event is still queued.
            sync_cursor = self._selected_run_id != self._cursor_synced_to
        else:
            table.clear()
            for s in self._summaries:
                table.add_row(*self._row_cells(s, width), key=s.get("run_id", ""))
            sync_cursor = True
        self._width = width
        idx = self._index_of(self._selected_run_id)
        if sync_cursor:
            self._cursor_synced_to = self._selected_run_id
        if sync_cursor and idx is not None and table.cursor_row != idx:
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
        # In review / new: colour and weight, no marker symbol.
        style = ""
        if run_id == self._scope_run_id:
            style = f"bold {_ACCENT}"
        elif run_id in self._unread_run_ids:
            style = "bold"
        label.append("  ")
        name = s.get("label") or run_id
        if len(name) > label_width:
            name = name[: label_width - 1] + "…"
        label.append(name.ljust(label_width), style=style)
        when = Text(
            self._format_when(s.get("recorded_at"), short=self._compact),
            style=_MUTED,
        )
        took = Text(self._format_duration(self._run_seconds(s)), style=_MUTED)
        replays = self._replays(run_id)
        if replays > 1:
            took.append(f"  {replays} replays", style=_DIM)
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

    @classmethod
    def _run_seconds(cls, s: dict[str, Any]) -> int:
        """Play press → end of analysis (the run's own wall time).

        "Took" used to show the recording length (``duration``), so a 7
        minute Play read "1m 33s" (L4); the recording length is in the
        Inspector.
        """
        start = cls._parse(s.get("recorded_at"))
        end = cls._parse(s.get("completed_at"))
        if start is None or end is None:
            return int(s.get("duration") or 0)
        try:
            return max(0, int((end - start).total_seconds()))
        except (TypeError, ValueError):
            return int(s.get("duration") or 0)

    def _file_count(self, run_id: str) -> int:
        counts = (self._summary(run_id) or {}).get("counts") or {}
        return sum(int(counts.get(k, 0) or 0) for k in ("changed", "new", "deleted"))

    def _host_count(self, run_id: str) -> int | None:
        hosts = (self._facts.get(run_id) or {}).get("hosts")
        if hosts is None:
            return None
        return len({host_key(h) for h in hosts})

    def same_recording_runs(self, run_id: str) -> list[str]:
        """Other listed runs that replayed the same recording (by its SHA-256)."""
        digest = (self._facts.get(run_id) or {}).get("recording")
        if not digest:
            return []
        return [
            other
            for other, facts in self._facts.items()
            if other != run_id
            and (facts or {}).get("recording") == digest
            and self._summary(other) is not None
        ]

    def divergence(self, run_id: str) -> list[tuple[str, list[str]]]:
        """``[(other run id, reasons)]`` for runs of the same recording that
        disagree with ``run_id`` (replay-consistency signal, M-28).
        """
        out = []
        for other in self.same_recording_runs(run_id):
            reasons = replay_divergence(
                self._file_count(run_id),
                self._file_count(other),
                self._host_count(run_id),
                self._host_count(other),
            )
            if reasons:
                out.append((other, reasons))
        return out

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
        if s.get("mode") and "recorded" in counts:
            # A Rewind run: what your run changed and what was compared
            # ("159 changed, 0 compared"), never "no changes".
            recorded = int(counts.get("recorded") or 0)
            compared = int(counts.get("compared") or 0)
            parts.append(
                (f"{recorded} changed, {compared} compared", "" if compared else _DIM)
            )
        elif files:
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
        diverged = self.divergence(s.get("run_id", ""))
        if diverged:
            others = ",".join(f"#{self._run_number(o)}" for o, _ in diverged[:3])
            cell.append("   ")
            cell.append(f"differs from {others}", style=_WARN)
        return cell

    def _problem(self, s: dict[str, Any]) -> tuple[str, str] | None:
        """The run's error badge: aborted (red) or step errors (yellow)."""
        facts = self._facts.get(s.get("run_id", "")) or {}
        errors = facts.get("run_errors") or {}
        steps = len(errors.get("steps") or [])
        if s.get("result") == "diverged":
            return "diverged", _BAD  # the replay did not reach your run
        if s.get("result") == "unchecked":
            from sandroid.core import rewind

            return rewind.result_words(s), _WARN  # done, N steps unchecked
        if s.get("error") or errors.get("fatal"):
            if s.get("error") == "Replay cancelled" or s.get("mode"):
                return "stopped", _WARN  # a Rewind stops, it never aborts
            return "aborted", _BAD
        if steps:
            return f"{steps} error{'s' if steps != 1 else ''}", _WARN
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
        self._check_evidence(run_id, force=True)
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
            subtitle = f"[{_ACCENT}]in review[/] [{_DIM}]· L back to live[/]"
        return InspectorContent(
            title=label,
            subtitle=subtitle,
            tabs=[
                ("Summary", self._summary_sections(s, facts)),
                ("Changes", self._changes_sections(s, record, facts)),
                ("Report", self._report_sections(run_id, facts)),
                ("Privacy", self._privacy_sections(run_id, s)),
            ],
            footer="v review · = compare · z diff · ⇧P pdf",
            key=("run", run_id),
            keys=self._privacy_keys(run_id),
            click=lambda tab, line: self._privacy_click(run_id, tab, line),
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
            when = f"{start.strftime('%a %d %b %Y · %H:%M')} to {end.strftime('%H:%M')}"
        grid.add_row("Run", Text(f"#{self._run_number(run_id)} · {run_id}"))
        grid.add_row("When", when)
        grid.add_row("Took", self._format_duration(self._run_seconds(s)))
        recording = self._format_duration(
            facts.get("recording_seconds") or s.get("duration")
        )
        replays = self._replays(run_id)
        if replays > 1:
            recording += f"  ·  {replays} replays"
        grid.add_row("Recording", recording)
        same = self.same_recording_runs(run_id)
        if same:
            diverged = dict(self.divergence(run_id))
            text = Text("same recording as ")
            text.append(", ".join(f"#{self._run_number(o)}" for o in same))
            if diverged:
                for other, reasons in diverged.items():
                    text.append(
                        f"\n⚠ diverges from #{self._run_number(other)}: "
                        f"{', '.join(reasons)} -- a replay may not have done "
                        "what the recording did",
                        style=_WARN,
                    )
            else:
                text.append("  ✓ consistent", style=_GOOD)
            grid.add_row("Replays", text)
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
            return Text("completed", style=_GOOD)
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
            _, n, names = (state.split(":", 2) + ["", ""])[:3]
            text = Text(f"✕ {n} file(s) changed since sealing", style=_BAD)
            if names:
                text.append(f": {names.replace(',', ', ')}", style=_BAD)
            return text
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
        if getattr(record, "mode", ""):
            return [*sections, *self._rewind_sections(record)]
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

    def _rewind_sections(self, record: Any) -> list[tuple[str, Any]]:
        """A Rewind run: per selected file its result, the replayed steps,
        the compared requests and the requests per run (plain words).
        """
        from sandroid.core import rewind

        info = getattr(record, "rewind", None) or {}
        out: list[tuple[str, Any]] = []
        verdicts = getattr(record, "verdicts", None) or {}
        if info.get("diverged_at_step"):
            at = info.get("diverged_at_step")
            body = Text(str(info.get("diverged") or f"step {at}"), style=_BAD)
            if info.get("note"):
                body.append(f"\n{info['note']}")
            out.append(("The replay diverged", body))
        elif info.get("unchecked_steps"):
            body = Text(str(info.get("result_words") or "unchecked"), style=_WARN)
            if info.get("note"):
                body.append(f"\n{info['note']}")
            out.append(("Replay steps unchecked", body))
        if verdicts:
            body = Text()
            for path, verdict in verdicts.items():
                if body:
                    body.append("\n")
                body.append(self._short_path(path, 44))
                color = {rewind.SAME: _GOOD, rewind.DIFFERENT: _WARN}.get(
                    verdict, _MUTED
                )
                body.append(f"  {verdict}", style=color)
            out.append(("What your action changed", body))
        steps = info.get("steps") or []
        if steps:
            body = Text()
            for st in steps:
                if body:
                    body.append("\n")
                way = st.get("way") or ""
                if way in ("failed", "diverged"):
                    way = f"{way}: {st.get('reason')}"
                elif st.get("check") == "unchecked" and st.get("reason"):
                    way = f"{way} ({st.get('reason')}), unchecked"
                body.append(f"{st.get('i')}. {st.get('what')}  ")
                bad = way.startswith(("failed", "diverged"))
                warn = st.get("check") == "unchecked"
                body.append(way, style=_BAD if bad else _WARN if warn else _MUTED)
            out.append(("Replayed steps", body))
        flows = info.get("flows") or []
        if flows:
            lines = [ln for f in flows for ln in f]
            out.append(("Compared requests", Text("\n".join(lines))))
        for title, reqs in (info.get("requests") or {}).items():
            body = Text("\n".join(reqs[:_LIST_LIMIT]) or "none")
            if len(reqs) > _LIST_LIMIT:
                body.append(f"\n… {len(reqs) - _LIST_LIMIT} more", style=_DIM)
            out.append((f"Requests · {title} ({len(reqs)})", body))
        out.append(("", Text("z full results · v review in Files", style=_DIM)))
        return out

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
        flows = facts.get("flows")
        if isinstance(flows, dict):
            n = int(flows.get("count") or 0)
            grid.add_row(
                "Flows",
                f"{n} mitmproxy flow{'s' if n != 1 else ''} in "
                f"{run_history.NETWORK_DIR_NAME}/flows.jsonl"
                if n
                else Text("no mitmproxy flows in this run", style=_DIM),
            )
        pcaps = facts.get("pcaps") or []
        if pcaps:
            body = Text()
            for rel, size in pcaps:
                if body:
                    body.append("\n")
                body.append(rel)
                body.append(f"  {size / 1024 / 1024:.1f} MB", style=_DIM)
            grid.add_row("Pcap", body)
        grid.add_row("Evidence", self._evidence_text(run_id))
        return [
            ("", grid),
            ("Folder", Text(run_dir, style=_MUTED)),
            ("", Text("⇧P write a new PDF report", style=_DIM)),
        ]

    # -- Privacy tab (identity profile values found during the run) ---------

    def _privacy_hits(self, s: dict[str, Any]) -> tuple[list | None, str]:
        """``(hits of the run, what an empty list means)``; hits are None
        while another session's findings are still being read.

        The live session's hits come from the scan service; a run that
        names another session's timeline folder reads that folder's
        findings (cached). A run without one (saved before runs stored it)
        can only be matched against the loaded session.
        """
        from sandroid.services.privacy_scan import run_hits, run_scope_of

        from .network_panel import privacy_service

        scope = run_scope_of(s)
        if scope is None:
            return [], _PRIVACY_NOT_ACTIVE
        folder = str(s.get("timeline_folder") or "")
        service = privacy_service()
        live = getattr(service, "folder", None) if service is not None else None
        if folder and (live is None or Path(folder) != Path(live)):
            cached = self._privacy_other.get(folder)
            if cached is None:
                self._load_privacy_other(folder)
                cached = self._privacy_other.get(folder)  # inline without an app
            if cached is None:
                return None, _PRIVACY_LOADING
            records, scanned = cached
            why = _PRIVACY_NONE if scanned else _PRIVACY_NOT_ACTIVE
            return run_hits(records, scope), why
        if service is None:
            return [], _PRIVACY_NOT_ACTIVE
        try:
            hits = list(service.hits_for_run(scope))
            has_hits = getattr(service, "has_hits", None)
            known = bool(
                service.is_active
                or hits
                or (has_hits() if has_hits is not None else service.hits())
            )
        except Exception:
            return [], _PRIVACY_NOT_ACTIVE
        if folder:
            return hits, _PRIVACY_NONE if known else _PRIVACY_NOT_ACTIVE
        return hits, _PRIVACY_NONE_HERE if known else _PRIVACY_NOT_ACTIVE_HERE

    def _load_privacy_other(self, folder: str) -> None:
        """Read another session's findings off the UI thread (once)."""
        if folder in self._privacy_other_pending:
            return
        self._privacy_other_pending.add(folder)
        self._run_bg(
            functools.partial(self._privacy_other_worker, folder),
            f"diffs_privacy_{abs(hash(folder))}",
        )

    def _privacy_other_worker(self, folder: str) -> None:
        from sandroid.services.privacy_scan import read_hits

        try:
            result = read_hits(folder)
        except Exception:
            logger.debug("DiffsView: cannot read %s", folder, exc_info=True)
            result = ([], False)
        self._post(self._apply_privacy_other, folder, result)

    def _apply_privacy_other(self, folder: str, result: tuple[list, bool]) -> None:
        self._privacy_other_pending.discard(folder)
        self._privacy_other[folder] = result
        self._follow_in_inspector()

    def _privacy_findings(self, s: dict[str, Any]) -> tuple[list, str]:
        """``(findings, what no findings means)`` of the run: the first hit
        per recipient x value x encoding (stored: per file x value x
        encoding), grouped by recipient.
        """
        from sandroid.core.adb_utils import canonical_device_path

        hits, why = self._privacy_hits(s)
        if not hits:
            return [], why
        first: dict[tuple, Any] = {}
        for hit in sorted(hits, key=lambda h: (h.t or 0.0, h.at)):
            if hit.direction == "received":
                continue
            if hit.direction == "stored":
                # One group per file, whatever alias its path was seen under.
                where = ("stored", canonical_device_path(str(hit.device_path or "")))
            else:
                rcpt = hit.recipient or {}
                label = rcpt.get("label") or hit.source.get("host") or "unknown"
                where = (str(rcpt.get("party") or "unknown"), str(label))
            first.setdefault((where, hit.marker_id, hit.transform), hit)
        groups: dict[tuple, list] = {}
        for (where, _m, _t), hit in first.items():
            groups.setdefault(where, []).append(hit)
        rank = {"third": 0, "unknown": 1, "first": 2, "stored": 3}
        ordered = sorted(groups.items(), key=lambda g: (rank.get(g[0][0], 9), g[0][1]))
        findings = []
        for where, group in ordered:
            for hit in sorted(group, key=lambda h: (str(h.label).lower(), h.t or 0)):
                findings.append((where, hit))
        return findings, why

    def _privacy_render(self, run_id: str, findings: list) -> tuple[Text, list]:
        """The finding list (one line each, no wrap) and ``line -> index``."""
        from sandroid.tui.themes import lens_palette

        from .network_panel import (
            encoding_words,
            party_color,
            party_words,
            where_words,
        )

        pal = lens_palette()
        pick = self._privacy_pick.get(run_id, 0) % max(1, len(findings))
        text = Text(no_wrap=True, overflow="ellipsis")
        lines: list[int | None] = []
        group = None
        for i, (where, hit) in enumerate(findings):
            if where != group:
                if group is not None:
                    text.append("\n")
                    lines.append(None)
                group = where
                party, label = where
                if party == "stored":
                    head = self._stored_head(label, party_color("stored"), pal.dim)
                else:
                    head = Text(label, style=Style(color=party_color(party), bold=True))
                    head.append(f"  {party_words(party)}", style=pal.dim)
                text.append_text(head)
                text.append("\n")
                lines.append(None)
            line = Text("  ")
            line.append(str(hit.label), style=Style(color=pal.text, bold=True))
            words = [
                encoding_words(hit.transform),
                where_words(hit.part, hit.source, hit.offsets),
            ]
            line.append(", " + ", ".join(words), style=pal.muted)
            if hit.t:
                line.append(f", {time.strftime('%H:%M:%S', time.localtime(hit.t))}")
            if hit.confidence == "low":
                line.append(", low confidence", style=pal.dim)
            if i == pick:
                line.stylize(Style(bgcolor=pal.cursor_focus))
            text.append_text(line)
            text.append("\n")
            lines.append(i)
        return text, lines

    @staticmethod
    def _stored_head(path: str, color: str, dim: str) -> Text:
        """``Stored in shared_prefs/p.xml  com.app``: the file, relative to
        the app's data folder, then the app (a path outside one: as is).
        """
        from sandroid.core.watchlist_store import DEVICE_OWNER, owner_and_relative

        try:
            owner, relative = owner_and_relative(path)
        except Exception:
            owner, relative = DEVICE_OWNER, path
        if owner == DEVICE_OWNER:
            relative = path
        head = Text(f"Stored in {relative}", style=Style(color=color, bold=True))
        if owner != DEVICE_OWNER:
            head.append(f"  {owner}", style=dim)
        return head

    def _privacy_sections(self, run_id: str, s: dict[str, Any]) -> list:
        findings, why = self._privacy_findings(s)
        if not findings:
            return [("", Text(why, style=_DIM))]
        values = len({hit.marker_id for _w, hit in findings})
        recipients = len({w for w, _h in findings if w[0] != "stored"})
        summary = Text()
        summary.append(f"{values} profile value{'s' if values != 1 else ''}")
        if recipients:
            summary.append(
                f" sent to {recipients} recipient{'s' if recipients != 1 else ''}"
            )
        if any(w[0] == "stored" for w, _h in findings):
            summary.append(" or stored" if recipients else " stored on the device")
        body, _lines = self._privacy_render(run_id, findings)
        hint = Text("{ } pick a finding, J jumps to its source", style=_DIM)
        return [("", summary), ("", body), ("", hint)]

    def _privacy_keys(self, run_id: str) -> dict:
        def step(delta: int):
            def go(tab: str | None) -> None:
                if tab != "Privacy":
                    return
                self._privacy_pick[run_id] = self._privacy_pick.get(run_id, 0) + delta
                self._follow_in_inspector()

            return go

        return {"left_curly_bracket": step(-1), "right_curly_bracket": step(1)}

    def _privacy_click(self, run_id: str, tab: str | None, line: int) -> bool:
        """A click on a finding picks it (body lines: summary, blank, list)."""
        if tab != "Privacy":
            return False
        s = self._summary(run_id)
        if s is None:
            return False
        findings, _why = self._privacy_findings(s)
        if not findings:
            return False
        _text, lines = self._privacy_render(run_id, findings)
        index = line - 2  # the summary line and the blank line before the list
        if 0 <= index < len(lines) and lines[index] is not None:
            self._privacy_pick[run_id] = lines[index]
            self._follow_in_inspector()
            return True
        return False

    def action_privacy_jump(self) -> None:
        """``J``: jump to the picked finding's flow, file or timeline line."""
        ms = self._main_screen()
        run_id = self._selected_run_id
        s = self._summary(run_id) if run_id else None
        findings = self._privacy_findings(s)[0] if s is not None else []
        if ms is None or not findings or not self._inspector_shows_run():
            self._notify("Open a run's Privacy tab and pick a finding first.")
            return
        hit = findings[self._privacy_pick.get(run_id, 0) % len(findings)][1]
        if not self.privacy_jump(hit):
            self._notify("The finding's source is not available any more.", "warning")

    def privacy_jump(self, hit: Any) -> bool:
        """Show ``hit``'s source: its flow, its file version, else its line."""
        ms = self._main_screen()
        if ms is None:
            return False
        src = hit.source or {}
        if hit.flow_id:
            ms.switch_lens("network")
            reveal = getattr(ms.lens_widget("network"), "reveal_flow", None)
            from .network_panel import flow_record_of

            record = flow_record_of(hit)
            if reveal is not None and reveal(hit.flow_id, record=record):
                return True
        elif hit.device_path:
            ms.switch_lens("files")
            reveal = getattr(ms.lens_widget("files"), "reveal", None)
            if reveal is not None and reveal(
                hit.device_path, version=src.get("version")
            ):
                return True
        if hit.tl_seq is not None:
            ms.switch_lens("timeline")
            select = getattr(ms.lens_widget("timeline"), "select_seq", None)
            return bool(select(int(hit.tl_seq))) if select else False
        return False

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
        ms.set_scope(run_history.scope_for_run(run_id), self._scope_label(run_id))
        self._check_evidence(run_id, force=True)
        self._notify(f"Reviewing {self._scope_label(run_id)} · L back to live")

    def _scope_label(self, run_id: str) -> str:
        """``"#3 Label"``: the pill and dialogs identify runs by number too."""
        return f"#{self._run_number(run_id)} {self._current_label(run_id)}"

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
            # Name the run like the input dialog did (# and id), not by its
            # label alone.
            message = (
                f"Rename run #{self._run_number(run_id)} '{current}' "
                f"({run_id}) to '{label}'?"
            )
            if label.lower().endswith(".apk") or "/" in label:
                message += (
                    "\nThis looks like a file path. To install an APK, "
                    "choose No and press n outside the Runs lens."
                )
            self.app.push_screen(
                ConfirmModal(
                    title=f"Rename run #{self._run_number(run_id)}", message=message
                ),
                lambda yes: on_confirm(yes, label),
            )

        self.app.push_screen(
            InputModal(
                title=f"Rename run #{self._run_number(run_id)}",
                message=f"{run_id} · typing replaces it",
                default=current,
                placeholder="run label",
                select_all=True,
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
                # the pill shows the new name
                ms.set_scope(ms.scope, self._scope_label(run_id))
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
                message=f"Delete run #{self._run_number(run_id)} '{label}' "
                f"({run_id})? This removes its whole bundle (recording, pulled "
                "files, pcaps, flows, reports) and cannot be undone.",
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
        from sandroid.core.file_diff import diff_markup
        from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal

        # Plain diff lines are escaped (brackets in data are not markup);
        # legacy runs' markup lines pass through and are rendered.
        self.app.push_screen(
            DiffZoomModal(
                diff_text=diff_markup(lines), title=self._current_label(run_id)
            )
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
        fa = facts.get(rec_a.run_id) or {}
        fb = facts.get(rec_b.run_id) or {}
        if fa.get("recording") and fa.get("recording") == fb.get("recording"):
            reasons = replay_divergence(
                len(a),
                len(b),
                len({host_key(h) for h in fa.get("hosts") or []}),
                len({host_key(h) for h in fb.get("hosts") or []}),
            )
            if reasons:
                note = Text(
                    f"⚠ Same recording, but the replays diverged: "
                    f"{', '.join(reasons)}. At least one replay did not do what "
                    "the recording did (a tap that did not take, a slow app); "
                    "check its screenshots before trusting either run.",
                    style=_WARN,
                )
            else:
                note = Text("✓ Same recording; the runs agree in size.", style=_GOOD)
            sections.insert(1, ("Replay consistency", note))
        hosts_a = {host_key(h) for h in fa.get("hosts") or [] if host_key(h)}
        hosts_b = {host_key(h) for h in fb.get("hosts") or [] if host_key(h)}
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
        self._notify(
            f"New run ready: {label} (shown in bold in Sessions)", "information"
        )


__all__ = ["DiffsView"]
