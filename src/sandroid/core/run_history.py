"""Persistent history of Record→Play analysis runs (the Files tab's Diffs).

Each completed Play produces a :class:`RunRecord` — the full, un-flattened
Changed/New/Deleted results (see ``analysis/changedfiles.py``'s native
``{file: [diff_lines]} | str`` shape) plus label/timing metadata. Records are
persisted as one JSON file per run under ``RESULTS_PATH/runs/``, alongside a
lightweight ``index.json`` used for cheap rail rendering (label/timestamps/
counts only — never the full diff text).

Storage layout::

    RESULTS_PATH/runs/run_<run_id>.json   # one full RunRecord per Play
    RESULTS_PATH/runs/index.json          # [{run_id, label, ...}, ...]

Atomicity: ``save_run`` writes the run file *first*, then atomically replaces
``index.json`` (temp file in the same directory + ``os.replace``). A crash
between the two leaves at worst an orphaned run file that the next
``index.json`` rebuild will pick up — never an index entry pointing at a
missing run. Every JSON write in this module goes through the same
``_atomic_write_json`` helper for that reason.

Corruption safety: a missing ``index.json`` is rebuilt by scanning
``runs/run_*.json``; any individual run file that fails to parse is skipped
with a logged warning rather than aborting the whole rebuild.

Device scoping: every record carries ``device_name``, and every reader here
accepts an optional ``device_name`` filter. Runs from every device live in
the same ``runs/`` directory (one file-per-run, not one-directory-per-device
— simpler on disk), but callers scope reads/writes by the *currently active*
device so switching devices mid-session shows that device's own history
rather than a mixed list.

No auto-eviction: runs are kept forever unless explicitly removed via
``delete_run``/``clear_all``. ``is_run_count_high`` is a cheap soft-warning
flag (past ``RUN_COUNT_WARNING_THRESHOLD``) for callers that want to nudge
the user toward pruning — this module never deletes anything on its own.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Bumped whenever RunRecord's on-disk shape changes incompatibly.
SCHEMA_VERSION = 1

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
    """

    schema_version: int
    run_id: str
    label: str
    recorded_at: str
    completed_at: str
    device_name: str
    recording_path: str
    duration: int
    error: str | None = None
    changed_files: Any = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

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
    return Path(os.environ.get("RESULTS_PATH", "./results/")).expanduser()


def _runs_dir() -> Path:
    directory = _results_path() / "runs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _run_file(run_id: str) -> Path:
    return _runs_dir() / f"run_{run_id}.json"


def _index_file() -> Path:
    return _runs_dir() / "index.json"


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write ``data`` as JSON to ``path`` atomically.

    Writes to a temp file in the *same* directory (so ``os.replace`` is a
    same-filesystem rename, never a cross-device copy) then replaces the
    real file in one step — a crash mid-write leaves the original untouched.
    """
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


def _rebuild_index() -> list[dict[str, Any]]:
    """Scan ``runs/run_*.json`` and rebuild the index from scratch.

    A run file that fails to parse (truncated write, hand-edited garbage) is
    skipped with a warning — one bad file must never take down the whole
    rail.
    """
    entries: list[dict[str, Any]] = []
    for path in sorted(_runs_dir().glob("run_*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            record = RunRecord.from_dict(data)
        except Exception as exc:
            logger.warning("run_history: skipping corrupt run file %s: %s", path, exc)
            continue
        entries.append(_summary_from_record(record))
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

    entries = _load_all_index_entries()
    entries = [e for e in entries if e.get("run_id") != record.run_id]
    entries.append(_summary_from_record(record))
    entries.sort(key=lambda e: e.get("run_id", ""), reverse=True)
    _atomic_write_json(
        _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
    )


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
        return RunRecord.from_dict(data)
    except Exception as exc:
        raise RunHistoryError(f"Run '{run_id}' is corrupt: {exc}") from exc


def update_label(run_id: str, label: str) -> RunRecord:
    """Rename one specific run's label.

    Independent of the recording-time "seed" label
    (``RecordingController._current_recording_label``) — this only rewrites
    the one on-disk ``RunRecord``, never anything that seeds future Plays of
    the same recording.
    """
    record = load_run(run_id)
    record.label = label
    save_run(record)
    return record


def delete_run(run_id: str) -> None:
    """Remove one run's on-disk file and its index entry."""
    try:
        _run_file(run_id).unlink(missing_ok=True)
    except Exception as exc:
        logger.warning("run_history: could not remove run file for %s: %s", run_id, exc)
    entries = _load_all_index_entries()
    entries = [e for e in entries if e.get("run_id") != run_id]
    _atomic_write_json(
        _index_file(), {"schema_version": SCHEMA_VERSION, "runs": entries}
    )


def clear_all(device_name: str | None = None) -> None:
    """Delete every run, optionally scoped to a single ``device_name``.

    When scoped, other devices' runs and index entries are left untouched.
    """
    entries = _load_all_index_entries()
    keep: list[dict[str, Any]] = []
    for entry in entries:
        if device_name is not None and entry.get("device_name") != device_name:
            keep.append(entry)
            continue
        run_id = entry.get("run_id")
        if run_id:
            try:
                _run_file(run_id).unlink(missing_ok=True)
            except Exception as exc:
                logger.warning(
                    "run_history: could not remove run file for %s: %s", run_id, exc
                )
    _atomic_write_json(_index_file(), {"schema_version": SCHEMA_VERSION, "runs": keep})


def run_count(device_name: str | None = None) -> int:
    """Number of stored runs, optionally scoped to ``device_name``."""
    return len(load_index(device_name))


def is_run_count_high(device_name: str | None = None) -> bool:
    """Soft-warning flag once run count passes ``RUN_COUNT_WARNING_THRESHOLD``.

    Purely informational — this module never auto-evicts. The UI decides
    whether/how to nudge the user toward pruning.
    """
    return run_count(device_name) > RUN_COUNT_WARNING_THRESHOLD


__all__ = [
    "RUN_COUNT_WARNING_THRESHOLD",
    "SCHEMA_VERSION",
    "RunHistoryError",
    "RunRecord",
    "clear_all",
    "delete_run",
    "is_run_count_high",
    "load_index",
    "load_run",
    "new_run_id",
    "run_count",
    "save_run",
    "update_label",
]
