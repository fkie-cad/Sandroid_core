"""Self-contained run-bundle storage for Record→Play analysis runs.

A *run bundle* is a single directory holding everything one Play produced:
the JSON manifest (``run.json``), an absolute-path copy of the recording that
drove it (``recording.txt``), and the ``raw/`` pull tree the diff engine wrote
into. This module owns the *bundle directory* shape and composes
:mod:`sandroid.core.run_history` for manifest/index persistence — both resolve
their storage root from the same :func:`run_history._results_path` so a config
change moves them together.

Layout::

    <results_path>/runs/<run_id>/
        run.json                # RunRecord manifest (via run_history.save_run)
        recording.txt           # absolute-path copy of the live recording
        raw/
            first_pull/         # created on demand by the pull consumers
            second_pull/
            noise_pull/
            new_pull/

Why a bundle fixes the recording bug: the live recording's path used to be
re-derived from the process-global ``RAW_RESULTS_PATH`` at read time, and that
global is re-pointed to a fresh empty folder on every device switch — so a
disconnect mid-flow orphaned the recording and Play read the wrong path. Here
the recording is copied into the bundle up-front and addressed by *absolute*
path thereafter (see :func:`import_recording`), so a mid-flow device switch can
no longer orphan it.
"""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

from sandroid.core import run_history

if TYPE_CHECKING:
    from pathlib import Path

#: Raw pull sub-directory names the diff engine / pull consumers populate under
#: a bundle's ``raw/`` directory. Created lazily by the consumers rather than
#: eagerly here (matching how the legacy pull steps behave).
RAW_PULL_SLOTS = ("first_pull", "second_pull", "noise_pull", "new_pull")

#: Basename of the recording copy stored inside each bundle.
RECORDING_FILENAME = "recording.txt"


def bundle_dir(run_id: str) -> Path:
    """Absolute bundle directory for ``run_id`` (may not exist yet)."""
    return run_history._results_path() / "runs" / run_id


def create_bundle(run_id: str) -> Path:
    """Create the bundle directory and its ``raw/`` root for ``run_id``.

    Makes ``<results_path>/runs/<run_id>/`` and ``<...>/raw/``. The per-slot
    pull directories (``first_pull``/``second_pull``/``noise_pull``/
    ``new_pull``) are created on demand by the pull consumers, not here.

    Args:
        run_id: The run identifier (see :func:`run_history.new_run_id`).

    Returns:
        The absolute bundle directory path.
    """
    bundle = bundle_dir(run_id)
    (bundle / "raw").mkdir(parents=True, exist_ok=True)
    return bundle


def import_recording(run_id: str, live_recording_path: str | Path) -> str:
    """Copy the live recording into the bundle and return its absolute path.

    The copy is what every later step reads, so the recording is immune to the
    process-global ``RAW_RESULTS_PATH`` being re-pointed by a mid-flow device
    switch.

    Args:
        run_id: The run identifier.
        live_recording_path: Path to the live ``recording.txt`` to import.

    Returns:
        The absolute path of the imported recording inside the bundle.

    Raises:
        FileNotFoundError: If ``live_recording_path`` does not exist.
    """
    bundle = create_bundle(run_id)
    dst = bundle / RECORDING_FILENAME
    shutil.copy2(str(live_recording_path), str(dst))
    return str(dst.resolve())


def raw_dir(run_id: str) -> str:
    """Absolute path to the bundle's ``raw/`` directory (no trailing sep).

    The engine appends ``os.sep`` when pinning ``RAW_RESULTS_PATH`` (consumers
    concatenate ``f"{base}first_pull"`` with no separator of their own), so the
    trailing separator is intentionally *not* added here.

    Args:
        run_id: The run identifier.

    Returns:
        The absolute ``raw/`` directory path as a string.
    """
    raw = bundle_dir(run_id) / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    return str(raw.resolve())


def write_manifest(record: run_history.RunRecord) -> None:
    """Persist the run manifest, delegating to :func:`run_history.save_run`.

    Args:
        record: The fully populated :class:`run_history.RunRecord`.
    """
    run_history.save_run(record)


__all__ = [
    "RAW_PULL_SLOTS",
    "RECORDING_FILENAME",
    "bundle_dir",
    "create_bundle",
    "import_recording",
    "raw_dir",
    "write_manifest",
]
