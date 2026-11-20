"""Persistent history of Record→Play analysis runs (the Files tab's Diffs).

Each completed Play produces a :class:`RunRecord` — the full, un-flattened
Changed/New/Deleted results (see ``analysis/changedfiles.py``'s native
``{file: [diff_lines]} | str`` shape) plus label/timing metadata. Each run
owns a *bundle directory* holding its manifest, the recording that produced
it, and the raw pull tree the diff engine wrote (see ``core/run_bundle.py``);
this module persists the manifest and a lightweight ``index.json`` used for
cheap rail rendering (label/timestamps/counts only — never the full diff
text).

Storage layout (schema v2)::

    <results_path>/runs/<run_id>/run.json   # one full RunRecord per Play
    <results_path>/runs/<run_id>/...        # recording.txt + raw/ (run_bundle)
    <results_path>/runs/index.json          # [{run_id, label, ...}, ...]

The storage root ``<results_path>`` is resolved config-first from
``get_config().paths.results_path`` (§11) so the bundle location is stable and
independent of the per-run ``RAW_RESULTS_PATH``/``RESULTS_PATH`` env pinning
the analysis engine does mid-run; the ``RESULTS_PATH`` env var and
``./results/`` are used only as fallbacks.

Atomicity: ``save_run`` writes the run file *first*, then atomically replaces
``index.json`` (temp file in the same directory + ``os.replace``). A crash
between the two leaves at worst an orphaned run file that the next
``index.json`` rebuild will pick up — never an index entry pointing at a
missing run. Every JSON write in this module goes through the same
``_atomic_write_json`` helper for that reason.

Corruption safety: a missing ``index.json`` is rebuilt by scanning
``runs/*/run.json`` (with a one-time fallback scan of the pre-v2 flat
``runs/run_*.json`` layout so old runs still appear); any individual run file
that fails to parse is skipped with a logged warning rather than aborting the
whole rebuild.

Device scoping: every record carries ``device_name``, and every reader here
accepts an optional ``device_name`` filter. Runs from every device live under
the same ``runs/`` directory (one directory-per-run), but callers scope reads/
writes by the *currently active* device so switching devices mid-session shows
that device's own history rather than a mixed list.

No auto-eviction: runs are kept forever unless explicitly removed via
``delete_run``/``clear_all`` (each ``rmtree``s the whole ``<run_id>/`` bundle).
``is_run_count_high`` is a cheap soft-warning flag (past
``RUN_COUNT_WARNING_THRESHOLD``) for callers that want to nudge the user toward
pruning — this module never deletes anything on its own.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import os
import shutil
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

#: Bumped whenever RunRecord's on-disk shape changes incompatibly.
#: v2: per-run bundle directories (``runs/<id>/run.json`` + ``recording.txt`` +
#: ``raw/``) replacing the flat ``runs/run_<id>.json`` layout; ``RunRecord``
#: gains ``bundle_dir`` and ``recording_path`` is now the absolute in-bundle
#: copy.
SCHEMA_VERSION = 2

#: Soft warning threshold — the UI may show a "consider pruning" banner past
#: this; this module itself never evicts anything automatically.
RUN_COUNT_WARNING_THRESHOLD = 50


class RunHistoryError(Exception):
    """Raised when a specific run cannot be loaded (missing or corrupt)."""


@dataclass
class RunRecord:
    """Full persisted record of one Play's analysis results.

    ``changed_files`` keeps ``ChangedFiles.return_data()``'s native shape —
    a list whose entries are either ``{path: [diff_lines]}`` (diffed
    sqlite/xml/txt files) or a bare ``str`` path (undiffable files). This is
    the exact shape the data-loss fix in ``recording_controller.py`` now
    threads all the way through, instead of the old
    ``_extract_file_names()``/``_flatten_file_list()`` that discarded the
    diff text.

    ``recording_path`` is the absolute path of the recording *inside the run
    bundle* (``run_bundle.import_recording`` copies the live recording there
    at run start), and ``bundle_dir`` is the absolute bundle root
    (``<results_path>/runs/<run_id>/``). ``bundle_dir`` defaults to ``""`` so
    pre-v2 records (which lack it) still load via :meth:`from_dict` instead of
    being treated as corrupt.
    """

    schema_version: int
    run_id: str
    label: str
    recorded_at: str
    completed_at: str
    device_name: str
    recording_path: str
    duration: int
    bundle_dir: str = ""
    error: str | None = None
    changed_files: Any = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    #: Wall-clock phase windows (``RunResult.phases``): ``{"kind": "replay" |
    #: "dry_run", "run": n, "start": epoch, "end": epoch}``. Empty for runs
    #: recorded before phases were stored.
    phases: list[dict[str, Any]] = field(default_factory=list)
    #: The session timeline folder the run was recorded in (where its
    #: privacy findings are, ``<folder>/privacy/hits.jsonl``). Empty for
    #: runs saved before it was stored.
    timeline_folder: str = ""
    #: ``[start, stop]`` (epoch s) of the recording this run replays: the
    #: run's privacy findings cover it as well as the Play
    #: (:class:`~sandroid.services.privacy_scan.RunScope`). Empty when
    #: unknown (runs saved before it was stored, a Play without a recording
    #: of this session).
    record_window: list[float] = field(default_factory=list)
    #: Rewind runs (``core/rewind.py``): ``"rewind"`` or ``"rewind-replay"``;
    #: empty for a batch Play (command line / headless).
    mode: str = ""
    #: The recording this Rewind belongs to (``recordings/<rec_id>/``).
    rec_id: str = ""
    #: A Rewind's result word: ``rewound``, ``replayed``, ``diverged`` (the
    #: replay did not reach what your run did) or ``stopped``; empty for a
    #: batch Play and runs saved before it was stored.
    result: str = ""
    #: Per selected file: its result word (``same change in the replay`` ...).
    verdicts: dict[str, str] = field(default_factory=dict)
    #: Rewind details: ``steps`` (way per step), ``stopped_at_step``,
    #: ``flows`` (compared requests, plain lines), ``requests`` (per run).
    rewind: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunRecord:
        """Build a record from parsed JSON, ignoring unknown/extra keys.

        Missing *required* fields (no default) raise ``TypeError``, which
        callers treat as "corrupt" — deliberate, since a truncated or
        hand-edited run file should be skipped, not half-loaded.
        """
        known = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def new_run_id() -> str:
    """Timestamp-based run id, e.g. ``20260721_143205_ab12cd``.

    Real wall-clock time via ``datetime.now()`` (not a mocked/frozen clock —
    fine for this codebase's tooling; the disallowed pattern is JS-style
    ``Date.now()`` nondeterminism elsewhere, not Python's real clock). The
    trailing hex suffix guards against two runs starting within the same
    second colliding on disk.
    """
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"


def _results_path() -> Path:
    """Resolve the run-storage root directory, config-first.

    Order (§11): the configured ``paths.results_path`` — the source of truth
    that keeps the bundle location stable and independent of the analysis
    engine's per-run ``RESULTS_PATH`` env pinning — then the ``RESULTS_PATH``
    env var, then ``./results/``. A config-load failure degrades gracefully to
    the env/default path so a broken config never crashes run-history reads.

    ``run_bundle`` shares this helper so manifests and bundle directories
    always resolve to the same root.
    """
    try:
        from sandroid.config import get_config

        configured = get_config().paths.results_path
    except Exception as exc:  # config unavailable/broken -> fall back below
        logger.debug("run_history: config results_path unavailable (%s)", exc)
        configured = None
    if configured:
        return Path(configured).expanduser()
    env_value = os.environ.get("RESULTS_PATH")
    if env_value:
        return Path(env_value).expanduser()
    return Path("./results/").expanduser()


def _runs_dir() -> Path:
    directory = _results_path() / "runs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _bundle_dir(run_id: str) -> Path:
    """Absolute bundle directory for a run (``runs/<run_id>/``)."""
    return _runs_dir() / run_id


def _legacy_run_file(run_id: str) -> Path:
    """Pre-v2 flat run-file path (``runs/run_<run_id>.json``)."""
    return _runs_dir() / f"run_{run_id}.json"


def _run_file(run_id: str) -> Path:
    return _bundle_dir(run_id) / "run.json"


def _index_file() -> Path:
    return _runs_dir() / "index.json"


def _labels_file() -> Path:
    """User-assigned run labels (``runs/labels.json``, outside every bundle).

    Renaming a run must not rewrite its sealed ``run.json`` (that would break
    the bundle's ``SHA256SUMS``), so the new label lives here and in
    ``index.json``; readers prefer it over the label stored in ``run.json``.
    """
    return _runs_dir() / "labels.json"


def _read_labels() -> dict[str, str]:
    path = _labels_file()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        labels = data.get("labels") if isinstance(data, dict) else None
        if not isinstance(labels, dict):
            return {}
        return {str(k): str(v) for k, v in labels.items()}
    except Exception as exc:
        logger.warning("run_history: labels.json unreadable (%s); ignoring", exc)
        return {}


def _write_labels(labels: dict[str, str]) -> None:
    _atomic_write_json(_labels_file(), {"labels": labels})


def _apply_label(record: RunRecord, labels: dict[str, str] | None = None) -> RunRecord:
    labels = _read_labels() if labels is None else labels
    if record.run_id in labels:
        record.label = labels[record.run_id]
    return record


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write ``data`` as JSON to ``path`` atomically.

    Ensures the parent directory exists (per-run bundle dirs are created
    on first manifest write), then writes to a temp file in the *same*
    directory (so ``os.replace`` is a same-filesystem rename, never a
    cross-device copy) and replaces the real file in one step — a crash
    mid-write leaves the original untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    tmp_path.replace(path)


def _summary_from_record(record: RunRecord) -> dict[str, Any]:
    """The lightweight per-run summary stored in ``index.json``.

    Deliberately excludes ``changed_files``/``new_files``/``deleted_files`` —
    the whole point of the index is cheap rail rendering without reading
    every run's full diff text.
    """
    return {
        "run_id": record.run_id,
        "label": record.label,
        "device_name": record.device_name,
        "recorded_at": record.recorded_at,
        "completed_at": record.completed_at,
        "duration": record.duration,
        "error": record.error,
        "counts": dict(record.counts),
        "timeline_folder": record.timeline_folder,
        "record_window": list(record.record_window),
        "mode": record.mode,
        "rec_id": record.rec_id,
        "result": record.result,
    }


def _read_index_raw() -> list[dict[str, Any]] | None:
    """Best-effort read of ``index.json``. ``None`` means "rebuild me"."""
    path = _index_file()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("runs")
        if not isinstance(entries, list):
            return None
        return entries
    except Exception as exc:
        logger.warning("run_history: index.json unreadable (%s); rebuilding", exc)
        return None


def _safe_load_record(path: Path) -> RunRecord | None:
    """Parse one run file, returning ``None`` (with a warning) if corrupt.

    A run file that fails to parse (truncated write, hand-edited garbage) is
    skipped rather than aborting a bulk rebuild — one bad file must never take
    down the whole rail.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return RunRecord.from_dict(data)
    except Exception as exc:
        logger.warning("run_history: skipping corrupt run file %s: %s", path, exc)
        return None


def _rebuild_index() -> list[dict[str, Any]]:
    """Scan the ``runs/`` tree and rebuild the index from scratch.

    Globs the v2 layout (``runs/<id>/run.json``) first, then does a one-time
    fallback scan of the pre-v2 flat layout (``runs/run_*.json``) so runs
    written before the bundle migration still appear in the rail. A run whose
    id was already seen in the v2 pass wins over any stale flat file.
    """
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    labels = _read_labels()

    def _collect(path: Path) -> None:
        record = _safe_load_record(path)
        if record is None or record.run_id in seen_ids:
            return
        seen_ids.add(record.run_id)
        entries.append(_summary_from_record(_apply_label(record, labels)))

    for path in sorted(_runs_dir().glob("*/run.json")):
        _collect(path)
    # Legacy fallback: pre-v2 flat run files (one-time until re-saved).
    for path in sorted(_runs_dir().glob("run_*.json")):
        _collect(path)

    try:
        _atomic_write_json(
            _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
        )
    except Exception as exc:
        logger.warning("run_history: could not persist rebuilt index: %s", exc)
    return entries


def _load_all_index_entries() -> list[dict[str, Any]]:
    entries = _read_index_raw()
    if entries is None:
        entries = _rebuild_index()
    return entries


def load_index(device_name: str | None = None) -> list[dict[str, Any]]:
    """Lightweight per-run summaries for the Runs rail, newest run first.

    Scoped to ``device_name`` when given — a device switch mid-session must
    show that device's own run history, not a mixed list.
    """
    entries = _load_all_index_entries()
    if device_name is not None:
        entries = [e for e in entries if e.get("device_name") == device_name]
    entries.sort(key=lambda e: e.get("run_id", ""), reverse=True)
    return entries


def save_run(record: RunRecord) -> None:
    """Persist ``record``'s full data, then atomically update the index.

    Write order matters for crash-safety: the run file lands first, so a
    crash between the two writes leaves at worst an orphaned run file (which
    the next index rebuild picks up) — never an index entry pointing at a
    run file that doesn't exist.
    """
    _atomic_write_json(_run_file(record.run_id), record.to_dict())

    with _index_lock():
        entries = _load_all_index_entries()
        entries = [e for e in entries if e.get("run_id") != record.run_id]
        entries.append(_summary_from_record(record))
        entries.sort(key=lambda e: e.get("run_id", ""), reverse=True)
        _atomic_write_json(
            _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
        )


_INDEX_THREAD_LOCK = threading.Lock()


@contextlib.contextmanager
def _index_lock() -> Iterator[None]:
    """Serialise index rewrites (threads and processes: ``index.lock``)."""
    with _INDEX_THREAD_LOCK:
        handle = None
        try:
            handle = open(_runs_dir() / "index.lock", "a")
            try:
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
        except OSError:
            handle = None
        try:
            yield
        finally:
            if handle is not None:
                handle.close()


def load_run(run_id: str) -> RunRecord:
    """Load one run's full data (diffs included).

    Raises :class:`RunHistoryError` if the run is missing or its file is
    corrupt — callers asking for a *specific* run by id want a clear error,
    unlike ``load_index``'s "skip and warn" behaviour for bulk listing.
    """
    path = _run_file(run_id)
    if not path.exists():
        raise RunHistoryError(f"Run '{run_id}' not found")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        record = RunRecord.from_dict(data)
    except Exception as exc:
        raise RunHistoryError(f"Run '{run_id}' is corrupt: {exc}") from exc
    return _apply_label(record)


def update_label(run_id: str, label: str) -> RunRecord:
    """Rename one specific run's label.

    Independent of the recording-time "seed" label
    (``RecordingController._current_recording_label``). The run's
    ``run.json`` is part of its sealed evidence bundle and is left
    untouched: the label is stored in ``runs/labels.json`` and
    ``index.json`` (both outside the bundle), and :func:`load_run` /
    :func:`load_index` return it.
    """
    record = load_run(run_id)
    labels = _read_labels()
    labels[run_id] = label
    _write_labels(labels)
    record.label = label

    entries = _load_all_index_entries()
    for entry in entries:
        if entry.get("run_id") == run_id:
            entry["label"] = label
            break
    else:
        entries.append(_summary_from_record(record))
    entries.sort(key=lambda e: e.get("run_id", ""), reverse=True)
    _atomic_write_json(
        _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
    )
    return record


def _forget_labels(run_ids: list[str]) -> None:
    labels = _read_labels()
    if any(run_id in labels for run_id in run_ids):
        for run_id in run_ids:
            labels.pop(run_id, None)
        _write_labels(labels)


def _remove_run_storage(run_id: str) -> None:
    """Delete a run's whole bundle dir (v2) plus any pre-v2 flat file.

    Each removal is guarded so a missing dir/file is a no-op, and a failure
    to remove one form never blocks the other or the index update.
    """
    bundle = _bundle_dir(run_id)
    try:
        if bundle.exists():
            shutil.rmtree(bundle)
    except Exception as exc:
        logger.warning(
            "run_history: could not remove bundle dir for %s: %s", run_id, exc
        )
    try:
        _legacy_run_file(run_id).unlink(missing_ok=True)
    except Exception as exc:
        logger.warning(
            "run_history: could not remove legacy run file for %s: %s", run_id, exc
        )


def delete_run(run_id: str) -> None:
    """Remove one run's whole on-disk bundle and its index entry."""
    _remove_run_storage(run_id)
    entries = _load_all_index_entries()
    entries = [e for e in entries if e.get("run_id") != run_id]
    _atomic_write_json(
        _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
    )
    _forget_labels([run_id])


def clear_all(device_name: str | None = None) -> None:
    """Delete every run, optionally scoped to a single ``device_name``.

    When scoped, other devices' runs and index entries are left untouched.
    """
    entries = _load_all_index_entries()
    keep: list[dict[str, Any]] = []
    removed: list[str] = []
    for entry in entries:
        if device_name is not None and entry.get("device_name") != device_name:
            keep.append(entry)
            continue
        run_id = entry.get("run_id")
        if run_id:
            _remove_run_storage(run_id)
            removed.append(run_id)
    _atomic_write_json(_index_file(), {"schema_version": SCHEMA_VERSION, "runs": keep})
    _forget_labels(removed)


def run_count(device_name: str | None = None) -> int:
    """Number of stored runs, optionally scoped to ``device_name``."""
    return len(load_index(device_name))


def is_run_count_high(device_name: str | None = None) -> bool:
    """Soft-warning flag once run count passes ``RUN_COUNT_WARNING_THRESHOLD``.

    Purely informational — this module never auto-evicts. The UI decides
    whether/how to nudge the user toward pruning.
    """
    return run_count(device_name) > RUN_COUNT_WARNING_THRESHOLD


# ---------------------------------------------------------------------------
# Review scope: resolve a run for the TUI's REVIEW mode
# ---------------------------------------------------------------------------
#
# ``MainScreen.set_scope(run_id, label)`` takes a *scope id*: the run's bundle
# directory as an absolute path string (``str(Path)``), see
# :func:`scope_for_run`. Lenses resolve it with the helpers below; they read
# only the run folder, so a scope stays valid even if the configured results
# path changes later.

#: Results JSON written into every run bundle by ``run_report.finalize_run``.
RESULTS_JSON_NAME = "sandroid.json"

#: Folder inside a run bundle holding the run's own copy of its mitmproxy
#: flows (``flows.jsonl`` + ``details/`` + ``meta.json``), written at run
#: finalisation (``mitmproxy_flow_log.export_run_flows``) and covered by the
#: bundle's ``SHA256SUMS``.
NETWORK_DIR_NAME = "network"


@dataclass(frozen=True)
class FileDiffRow:
    """One file a run changed, created or deleted.

    ``diff`` holds the diff lines (Rich markup included) for a changed file
    the diff engine could diff (sqlite/xml/text), else ``None``.
    """

    kind: str  # "changed" | "new" | "deleted"
    path: str
    diff: list[str] | None = None


@dataclass(frozen=True)
class ScopedRun:
    """What a lens needs to show one run in REVIEW scope."""

    run_id: str
    run_dir: Path
    label: str
    device_name: str
    started_at: datetime | None
    ended_at: datetime | None
    error: str | None = None
    #: Phase windows (see :attr:`RunRecord.phases`); empty for older runs.
    phases: tuple[dict[str, Any], ...] = ()


def scope_for_run(run_id: str) -> str:
    """The scope id of ``run_id``: its bundle folder as an absolute path string."""
    return str(_bundle_dir(run_id).resolve())


def run_dir_for_scope(scope: str | os.PathLike[str] | None) -> Path | None:
    """The run folder of a scope id, or ``None`` (LIVE / unknown run).

    ``scope`` is the absolute run folder (what :func:`scope_for_run` returns
    and ``MainScreen.scope`` holds); a bare run id is accepted as well. Only a
    folder that holds a ``run.json`` counts.
    """
    if not scope:
        return None
    candidate = Path(scope).expanduser()
    if not candidate.is_absolute():
        candidate = _bundle_dir(str(scope))
    try:
        if (candidate / "run.json").is_file():
            return candidate.resolve()
    except OSError:
        pass
    return None


def load_run_dir(run_dir: str | os.PathLike[str]) -> RunRecord:
    """Load the :class:`RunRecord` stored in a run folder (label applied).

    Raises :class:`RunHistoryError` if ``run.json`` is missing or corrupt.
    """
    path = Path(run_dir) / "run.json"
    if not path.is_file():
        raise RunHistoryError(f"No run in '{run_dir}'")
    try:
        with open(path, encoding="utf-8") as f:
            record = RunRecord.from_dict(json.load(f))
    except Exception as exc:
        raise RunHistoryError(f"Run in '{run_dir}' is corrupt: {exc}") from exc
    return _apply_label(record)


def read_results_doc(run_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The run's full results JSON (``sandroid.json``), or ``None``.

    Holds ``"Run Metadata"`` (start/end, settings used), ``"Run Errors"``,
    ``"Network"`` and the other gatherer outputs. Can be large: read it off
    the UI thread.
    """
    path = Path(run_dir) / RESULTS_JSON_NAME
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        logger.debug("run_history: no results doc in %s (%s)", run_dir, exc)
        return None
    return data if isinstance(data, dict) else None


def _parse_time(value: Any) -> datetime | None:
    """ISO string -> timezone-aware datetime (naive values are local time)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.astimezone()


def resolve_scope(scope: str | os.PathLike[str] | None) -> ScopedRun | None:
    """Everything a lens needs about the run under review, or ``None``.

    ``started_at``/``ended_at`` are timezone-aware (stored naive values are
    local time): the Play's start and the end of its analysis, from
    ``run.json`` (``recorded_at``/``completed_at``), falling back to the
    results JSON's ``"Run Metadata"``. Use them as the run's time window.
    """
    run_dir = run_dir_for_scope(scope)
    if run_dir is None:
        return None
    try:
        record = load_run_dir(run_dir)
    except RunHistoryError as exc:
        logger.debug("run_history: cannot resolve scope %s: %s", scope, exc)
        return None
    started = _parse_time(record.recorded_at)
    ended = _parse_time(record.completed_at)
    if started is None or ended is None:
        meta = (read_results_doc(run_dir) or {}).get("Run Metadata") or {}
        started = started or _parse_time(meta.get("started_at"))
        ended = ended or _parse_time(meta.get("ended_at"))
    return ScopedRun(
        run_id=record.run_id,
        run_dir=run_dir,
        label=record.label,
        device_name=record.device_name,
        started_at=started,
        ended_at=ended,
        error=record.error,
        phases=tuple(p for p in record.phases or [] if isinstance(p, dict)),
    )


def run_time_window(
    scope: str | os.PathLike[str] | None,
) -> tuple[datetime | None, datetime | None]:
    """``(started_at, ended_at)`` of the scoped run; ``(None, None)`` if unknown."""
    run = resolve_scope(scope)
    if run is None:
        return None, None
    return run.started_at, run.ended_at


def phase_of(ts: float | None, phases: Any) -> str:
    """Name the phase a wall-clock time (epoch) falls in.

    Returns ``"replay N"`` / ``"dry run"`` / ``"capture"`` for a time inside a
    phase window (see :attr:`RunRecord.phases`), ``"setup"`` for anything
    outside them (snapshot loads, network resets, baseline scan, collecting
    results, analysis), or ``""`` when no phases are known.
    """
    windows = [p for p in phases or () if isinstance(p, dict)]
    if not windows:
        return ""
    if ts is None:
        return "setup"
    for p in windows:
        try:
            start, end = float(p["start"]), float(p["end"])
        except (KeyError, TypeError, ValueError):
            continue
        if start <= ts <= end:
            kind = str(p.get("kind") or "")
            if kind == "replay":
                return f"replay {p.get('run') or '?'}"
            if kind == "dry_run":
                return "dry run"
            return kind or "setup"
    return "setup"


def recording_digest(run_dir: str | os.PathLike[str] | None) -> str | None:
    """SHA-256 of the run's recording (``recording.getevent.txt``, or a
    legacy ``recording.txt``), or ``None``.

    Runs with the same digest replayed the same recording, so their results
    should agree (see the Runs lens's replay-consistency signal).
    """
    if not run_dir:
        return None
    import hashlib

    from sandroid.core.run_bundle import recording_path

    path = recording_path(run_dir)
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def file_diff_rows(
    source: RunRecord | str | os.PathLike[str] | None,
) -> list[FileDiffRow]:
    """The run's changed / new / deleted files as flat rows.

    ``source`` is a loaded :class:`RunRecord` or a scope id / run folder.
    Same data the Runs lens shows: changed files first (with their diff lines
    where the engine produced one), then new, then deleted.
    """
    if isinstance(source, RunRecord):
        record: RunRecord | None = source
    else:
        run_dir = run_dir_for_scope(source)
        try:
            record = load_run_dir(run_dir) if run_dir is not None else None
        except RunHistoryError:
            record = None
    if record is None:
        return []
    rows: list[FileDiffRow] = []
    for entry in record.changed_files or []:
        if isinstance(entry, dict):
            for path, lines in entry.items():
                diff = [str(x) for x in lines] if isinstance(lines, list) else None
                rows.append(FileDiffRow("changed", str(path), diff))
        else:
            rows.append(FileDiffRow("changed", str(entry)))
    rows.extend(FileDiffRow("new", str(p)) for p in record.new_files or [])
    rows.extend(FileDiffRow("deleted", str(p)) for p in record.deleted_files or [])
    return rows


__all__ = [
    "NETWORK_DIR_NAME",
    "RESULTS_JSON_NAME",
    "RUN_COUNT_WARNING_THRESHOLD",
    "SCHEMA_VERSION",
    "FileDiffRow",
    "RunHistoryError",
    "RunRecord",
    "ScopedRun",
    "clear_all",
    "delete_run",
    "file_diff_rows",
    "is_run_count_high",
    "load_index",
    "load_run",
    "load_run_dir",
    "new_run_id",
    "phase_of",
    "read_results_doc",
    "recording_digest",
    "resolve_scope",
    "run_count",
    "run_dir_for_scope",
    "run_time_window",
    "save_run",
    "scope_for_run",
    "update_label",
]
