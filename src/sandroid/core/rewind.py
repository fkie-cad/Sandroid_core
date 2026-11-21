"""Rewind: record once, review what changed, go back to the start point.

The user-approved flow (see ``docs/REWIND_PLAN.md``):

1. ``r`` saves a **start point** (an emulator snapshot named
   ``sandroid_rec_<YYYYmmdd_HHMMSS>``) and starts recording (Tracking input
   lines + the file monitor). A file list of the app's folders is taken.
2. The user does the action on the device.
3. ``r`` again stops: a second file list is taken, the two lists plus the
   file monitor's paths give the **Review** list (new / changed / deleted),
   with the requests seen during the recording.
4. Selecting a file watches it (★) and pulls it at once: that pull is
   **After**.
5. **Rewind** loads the start point and pulls **Before** of every selected
   file (with the app paused). **Rewind + Replay** then repeats the recorded
   steps (``features/player.py``: by element, else by position) and pulls
   **After (replay)**.

This module holds the data model (``recording.json``), the file lists, the
timeline reading, the role diffs and verdicts, and :class:`RewindRunner`,
the device-side orchestration. It never touches widgets: the TUI controller
(``tui/controllers/recording_controller.py``) supplies the callables in
:class:`RewindDeps`. File contents live in the Files lens's version folders
(``watchlist_store``); ``recording.json`` only maps roles to version names.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Every start point Sandroid saves carries this prefix; nothing else is ever
#: deleted or replaced by Rewind.
START_POINT_PREFIX = "sandroid_rec_"
_START_POINT_RE = re.compile(r"^sandroid_rec_\d{8}_\d{6}(?:_\d+)?$")
#: Free disk needed for a start point on top of the guest RAM.
DISK_MARGIN_BYTES = 10 * 1024**3
#: Seconds the Review list keeps filling after Stop (late app writes).
LATE_WRITES_S = 10.0
#: The roles a pulled version can have for a recording.
ROLES = ("before", "after", "after_replay")
ROLE_WORDS = {"before": "Before", "after": "After", "after_replay": "After (replay)"}
#: Verdict words (plain, shown as they are).
SAME = "same change in the replay"
#: Both runs changed the same fields; some to different values that a rule
#: explains (a time of its own run, ...; ``core/replay_verdict.py``).
VOLATILE = "differs only in volatile fields"
DIFFERENT = "replay changed it differently"
UNCHANGED = "replay did not change it"
#: A copy's file is gone from the Files lens folder: nothing to compare.
NOT_COMPARED = "could not compare"
NO_REPLAY = "no replay yet"
NOT_COPIED = "After (replay) was not copied"
#: A Rewind + Replay whose steps did not reach what your run did (a typed
#: field reads something else, or steps missed their elements): never a
#: success.
DIVERGED = "diverged"
#: A Rewind + Replay that went through but with steps nothing confirmed
#: (element not found or off-screen, field not read back): not a success.
#: Shown as ``done, N steps unchecked`` (:func:`result_words`).
UNCHECKED = "unchecked"


def _steps_list(steps: Any) -> str:
    nums = [str(i) for i in steps or []]
    if len(nums) <= 1:
        return "".join(nums)
    return ", ".join(nums[:-1]) + " and " + nums[-1]


def result_words(run: dict[str, Any] | None) -> str:
    """A run's result in plain words: ``replayed``, ``diverged at step 2``,
    ``done, 2 steps unchecked`` ... (``run``: a recording.json run dict).
    """
    run = run or {}
    result = run.get("result") or "stopped"
    if result == DIVERGED and run.get("diverged_at_step"):
        return f"diverged at step {run['diverged_at_step']}"
    if result == UNCHECKED:
        n = len(run.get("unchecked_steps") or []) or int(
            run.get("unchecked_count") or 0
        )
        return f"done, {n} step{'s' if n != 1 else ''} unchecked"
    return str(result)


#: ``pull`` outcome for a file that is not on the device.
ABSENT = "absent"
#: Requests seen up to this many seconds after Stop still count (the
#: mitmproxy log is read a moment later than the request).
REQUEST_SLACK_S = 2.0

#: App data roots listed for the Review (``{pkg}`` is filled in).
APP_DIRS = (
    "/data/data/{pkg}",
    "/data/user_de/0/{pkg}",
    "/sdcard/Android/data/{pkg}",
    "/sdcard/Android/media/{pkg}",
)

_FILE_OPS = {"create": "new", "modify": "changed", "delete": "deleted"}
_STATE_ORDER = {"changed": 0, "new": 1, "deleted": 2}
_SAVE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


def start_point_name(when: datetime | None = None) -> str:
    """The snapshot name of a new start point (``sandroid_rec_<stamp>``)."""
    return f"{START_POINT_PREFIX}{(when or datetime.now()).strftime('%Y%m%d_%H%M%S')}"


def is_start_point_name(name: object) -> bool:
    """``name`` is a start point Sandroid made (the only names it deletes)."""
    return isinstance(name, str) and bool(_START_POINT_RE.match(name))


def pinned_start_points(
    results_root: Path | None, must_see: Path | None = None
) -> set[str] | None:
    """Start point names a pinned (or imported) recording of any session
    under ``results_root`` (``results/<session>/<device>/recordings``)
    refers to; a recording file that is not valid JSON keeps every start
    point name it mentions.

    None (nothing may be deleted) when the root is unknown, a folder or
    file cannot be read, or the scan did not see ``must_see`` (the current
    recording's file: the layout is not what it expects).
    """
    if results_root is None:
        return None
    keep: set[str] = set()
    seen = False
    try:
        for path in results_root.glob("*/*/recordings/rec-*/recording.json"):
            text = path.read_text()
            if must_see is not None and path.resolve() == must_see.resolve():
                seen = True
            try:
                sp = json.loads(text).get("start_point") or {}
                if sp.get("pinned") or sp.get("imported"):
                    keep.add(str(sp.get("name") or ""))
            except (ValueError, AttributeError):
                keep.update(re.findall(START_POINT_PREFIX + r"[0-9_]+", text))
    except OSError:
        logger.debug("pinned start points: scan failed", exc_info=True)
        return None
    if must_see is not None and not seen:
        return None
    keep.discard("")
    return keep


def old_start_points(avd_folder: Path | None, keep: set[str]) -> list[tuple[str, int]]:
    """``[(name, bytes)]`` of the start points in the AVD's ``snapshots``
    folder that may go: Sandroid's names only (:func:`is_start_point_name`),
    none of ``keep``. Oldest first.
    """
    out: list[tuple[str, int]] = []
    folder = avd_folder / "snapshots" if avd_folder is not None else None
    if folder is None or not folder.is_dir():
        return out
    with contextlib.suppress(OSError):
        for entry in sorted(folder.iterdir()):
            if not entry.is_dir() or not is_start_point_name(entry.name):
                continue
            if entry.name in keep:
                continue
            size = 0
            with contextlib.suppress(OSError):
                size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
            out.append((entry.name, size))
    return out


def size_words(n: int) -> str:
    """``11 GB`` / ``2.5 GB`` / ``300 MB`` (plain, for one line)."""
    gb = n / 1e9
    if gb >= 10:
        return f"{gb:.0f} GB"
    if gb >= 1:
        return f"{gb:.1f} GB"
    return f"{n / 1e6:.0f} MB"


def default_name(when: datetime | None = None) -> str:
    """The recording's automatic name, ``Recording HH:MM``."""
    return f"Recording {(when or datetime.now()).strftime('%H:%M')}"


def new_rec_id(when: datetime | None = None) -> str:
    """``rec-YYYYmmdd-HHMMSS-<hex4>``."""
    stamp = (when or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"rec-{stamp}-{uuid.uuid4().hex[:4]}"


# ---------------------------------------------------------------------------
# recording.json
# ---------------------------------------------------------------------------


@dataclass
class Recording:
    """One recording: its start point, Review list, selection and runs.

    ``versions`` maps a device path to ``{role: version name}``; a role's
    value is the Files lens version folder name holding that content, or
    :data:`ABSENT` when the file was not on the device. ``after_replay`` is a
    list (one entry per replay, newest last).
    """

    rec_id: str
    name: str
    pkg: str | None
    serial: str | None
    avd: str | None = None
    start_point: dict[str, Any] = field(default_factory=dict)
    seq: dict[str, int | None] = field(default_factory=dict)
    started: float | None = None
    stopped: float | None = None
    timeline_offset: int = 0
    file_lists: dict[str, str] = field(default_factory=dict)
    changed: list[dict[str, Any]] = field(default_factory=list)
    selected: list[str] = field(default_factory=list)
    runs: list[dict[str, Any]] = field(default_factory=list)
    versions: dict[str, dict[str, Any]] = field(default_factory=dict)
    emulator: bool = True
    note: str = ""
    #: Requests seen during the recording (Review rows, see :func:`requests_in`).
    requests: list[dict[str, Any]] = field(default_factory=list)
    #: Selected requests (their Review rows); compared after Rewind + Replay.
    selected_flows: list[dict[str, Any]] = field(default_factory=list)
    #: When each file's After was copied (epoch s): the replay waits as long
    #: after its last step, so both copies see the app write for as long.
    after_at: dict[str, float] = field(default_factory=dict)
    #: Files selected after a Rewind ran: the device had left the state after
    #: your action, so they have no After from your run.
    late_selected: list[str] = field(default_factory=list)
    #: The device's timezone at the start (``persist.sys.timezone``); the
    #: verdict reads ISO times without a zone in it. None: unknown.
    device_tz: str | None = None

    @property
    def start_point_name(self) -> str | None:
        name = self.start_point.get("name")
        return name if self.start_point.get("saved_ok") and name else None

    @property
    def pinned(self) -> bool:
        return bool(self.start_point.get("pinned"))

    @property
    def stopped_ok(self) -> bool:
        return self.stopped is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Recording:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def role_version(self, path: str, role: str) -> str | None:
        """The version name of ``role`` (newest for ``after_replay``)."""
        value = self.versions.get(path, {}).get(role)
        if isinstance(value, list):
            return value[-1] if value else None
        return value

    def set_role(self, path: str, role: str, version: str | None) -> None:
        roles = self.versions.setdefault(path, {})
        if role == "after_replay":
            roles.setdefault("after_replay", []).append(version)
        else:
            roles[role] = version


def device_timezone(shell: Callable[[str], str]) -> str | None:
    """The device's timezone (an IANA name from ``persist.sys.timezone``)
    through ``shell`` (a device shell runner); None when it is unset, not a
    known zone or the device did not answer. Never raises.
    """
    from sandroid.core.replay_verdict import device_zone

    try:
        name = str(shell("getprop persist.sys.timezone") or "").strip()
    except Exception:
        logger.debug("rewind: reading the device timezone failed", exc_info=True)
        return None
    return name if device_zone(name) is not None else None


def recordings_root() -> Path:
    """``<session device folder>/recordings``."""
    from sandroid.core.timeline import timeline_folder

    return timeline_folder() / "recordings"


def recording_dir(rec_id: str) -> Path:
    if not re.match(r"^rec-[0-9A-Za-z-]+$", rec_id or ""):
        raise ValueError(f"not a recording id: {rec_id!r}")
    return recordings_root() / rec_id


def save_recording(rec: Recording) -> Path:
    """Write ``recording.json`` atomically (temp file + ``os.replace``)."""
    folder = recording_dir(rec.rec_id)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "recording.json"
    with _SAVE_LOCK:
        tmp = folder / f".recording.{os.getpid()}.{threading.get_ident()}.tmp"
        tmp.write_text(json.dumps(rec.to_dict(), indent=2, default=str))
        tmp.replace(target)
    return target


def load_recording(rec_id: str) -> Recording | None:
    """The recording ``rec_id`` of this session folder, or None."""
    try:
        data = json.loads((recording_dir(rec_id) / "recording.json").read_text())
        return Recording.from_dict(data)
    except (OSError, ValueError, TypeError):
        return None


def list_recordings() -> list[Recording]:
    """Every recording of this session folder, oldest first."""
    root = recordings_root()
    out = []
    with contextlib.suppress(OSError):
        for folder in sorted(root.iterdir()):
            rec = load_recording(folder.name) if folder.is_dir() else None
            if rec is not None:
                out.append(rec)
    return out


def latest_recording() -> Recording | None:
    """The newest stopped recording of this session folder, or None."""
    done = [rec for rec in list_recordings() if rec.stopped is not None]
    return max(done, key=lambda rec: (rec.started or 0, rec.rec_id), default=None)


# ---------------------------------------------------------------------------
# export / import (the TUI's ``x`` and ``i``)
# ---------------------------------------------------------------------------

#: The manifest at the top of an exported recording (a zip, ``.action``).
EXPORT_MANIFEST = "rewind_export.json"
EXPORT_FORMAT = "sandroid-rewind"
EXPORT_VERSION = 1


def start_point_folder(rec: Recording, avd: str | None = None) -> Path | None:
    """The AVD snapshot folder of ``rec``'s start point when it still exists.

    Args:
        rec: The recording.
        avd: The AVD to look in (default: the one the recording was made on).
    """
    name = rec.start_point_name
    avd = avd or rec.avd
    if not is_start_point_name(name) or not avd:
        return None
    try:
        from sandroid.core.emulator import avd_dir

        folder = avd_dir(avd)
    except Exception:
        return None
    if folder is None:
        return None
    snapshot = folder / "snapshots" / name
    return snapshot if snapshot.is_dir() else None


def _version_folders(rec: Recording) -> list[tuple[str, Path]]:
    """``(device path, version folder)`` of every copy ``rec`` refers to."""
    from sandroid.core import watchlist_store

    out = []
    for path, roles in rec.versions.items():
        names: list[Any] = []
        for value in roles.values():
            names.extend(value if isinstance(value, list) else [value])
        for name in dict.fromkeys(names):
            if not isinstance(name, str) or name == ABSENT or "/" in name:
                continue
            with contextlib.suppress(Exception):
                folder = watchlist_store.row_dir(path) / name
                if folder.is_dir():
                    out.append((path, folder))
    return out


def export_recording(
    rec: Recording,
    archive: Path,
    *,
    with_recording: bool = True,
    with_start_point: bool = False,
) -> Path:
    """Write ``rec`` into the zip ``archive`` (the TUI's ``x`` Export).

    The archive holds ``rewind_export.json``, ``recording/`` (always its
    ``recording.json``; with ``with_recording`` also the recorded steps, the
    file lists and ``pulls/``, the copied Before / After versions) and, with
    ``with_start_point``, ``start_point/<name>/`` (the emulator snapshot).

    Args:
        rec: The recording to export.
        archive: The zip file to write (it must not exist).
        with_recording: Include the steps, file lists and copied files.
        with_start_point: Include the start point snapshot.

    Returns:
        The archive path.

    Raises:
        FileExistsError: ``archive`` exists.
        FileNotFoundError: The start point is asked for but is gone.
    """
    import zipfile

    from sandroid.core import watchlist_store

    if archive.exists():
        raise FileExistsError(f"{archive} already exists")
    snapshot = start_point_folder(rec) if with_start_point else None
    if with_start_point and snapshot is None:
        raise FileNotFoundError("The start point is gone.")
    folder = recording_dir(rec.rec_id)
    manifest = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "rec_id": rec.rec_id,
        "name": rec.name,
        "package": rec.pkg,
        "avd": rec.avd,
        "with_recording": with_recording,
        "start_point": snapshot.name if snapshot is not None else None,
    }
    tmp = archive.with_name(f".{archive.name}.part")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(EXPORT_MANIFEST, json.dumps(manifest, indent=2))
            zf.writestr(
                "recording/recording.json",
                json.dumps(rec.to_dict(), indent=2, default=str),
            )
            if with_recording:
                for file in sorted(folder.rglob("*")):
                    rel = file.relative_to(folder).as_posix()
                    if file.is_file() and not file.name.startswith("."):
                        if rel != "recording.json":
                            zf.write(file, f"recording/{rel}")
                root = watchlist_store.files_root()
                for _path, version in _version_folders(rec):
                    for file in sorted(version.rglob("*")):
                        if file.is_file():
                            rel = file.relative_to(root).as_posix()
                            zf.write(file, f"pulls/{rel}")
            if snapshot is not None:
                for file in sorted(snapshot.rglob("*")):
                    if file.is_file():
                        rel = file.relative_to(snapshot.parent).as_posix()
                        # Snapshots are big binaries: store, do not deflate.
                        zf.write(file, f"start_point/{rel}", zipfile.ZIP_STORED)
        tmp.replace(archive)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()
    return archive


def is_recording_export(archive: str | Path) -> bool:
    """``archive`` is a zip written by :func:`export_recording`."""
    import zipfile

    try:
        with zipfile.ZipFile(archive) as zf:
            return EXPORT_MANIFEST in zf.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def _safe_member(name: str, prefix: str) -> list[str] | None:
    """The parts of zip member ``name`` below ``prefix``, or None when it is
    outside it, a folder, or tries to leave it (``..``, absolute paths).
    """
    if not name.startswith(prefix) or name.endswith("/"):
        return None
    parts = name[len(prefix) :].split("/")
    if not parts or any(p in ("", ".", "..") or "\\" in p for p in parts):
        return None
    return parts


def _extract(zf: Any, prefix: str, target: Path, *, overwrite: bool) -> int:
    """Extract the members below ``prefix`` into ``target``; the count."""
    count = 0
    for name in zf.namelist():
        parts = _safe_member(name, prefix)
        if parts is None:
            continue
        dest = target.joinpath(*parts)
        if dest.exists() and not overwrite:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(name) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        count += 1
    return count


def import_recording(
    archive: str | Path, avd: str | None = None
) -> tuple[Recording, str]:
    """Add an exported recording to this session folder (the TUI's ``i``).

    The recording gets a new id when its id is already here. Its copied
    files go to the Files lens folders (existing copies are kept). Its start
    point is put back into the AVD's snapshots when the archive has it and
    that AVD has no snapshot of that name yet; the imported start point is
    pinned, so a new recording never deletes it.

    Args:
        archive: The ``.action`` zip written by :func:`export_recording`.
        avd: The AVD to put the start point into (default: the recording's).

    Returns:
        ``(the imported recording, a plain sentence about its start point)``.

    Raises:
        ValueError: ``archive`` is not an exported recording.
    """
    import zipfile

    from sandroid.core import watchlist_store

    try:
        zf = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Not an exported recording: {exc}") from exc
    with zf:
        try:
            manifest = json.loads(zf.read(EXPORT_MANIFEST))
            data = json.loads(zf.read("recording/recording.json"))
        except (KeyError, ValueError) as exc:
            raise ValueError("Not an exported recording.") from exc
        if manifest.get("format") != EXPORT_FORMAT:
            raise ValueError("Not an exported recording.")
        rec = Recording.from_dict(data)
        recording_dir(rec.rec_id)  # a valid id, or ValueError
        if recording_dir(rec.rec_id).exists():
            rec.rec_id = new_rec_id()
        folder = recording_dir(rec.rec_id)
        folder.mkdir(parents=True, exist_ok=True)
        _extract(zf, "recording/", folder, overwrite=True)
        _extract(zf, "pulls/", watchlist_store.files_root(), overwrite=False)
        name = manifest.get("start_point")
        target_avd = avd or rec.avd
        prefix = f"start_point/{name}/"
        has_snapshot = is_start_point_name(name) and any(
            n.startswith(prefix) for n in zf.namelist()
        )
        rec.start_point = dict(rec.start_point or {})
        existing = start_point_folder(rec, target_avd)
        if existing is not None:
            note = f"The start point {existing.name} is on this computer."
        elif has_snapshot and target_avd:
            avd_folder = None
            with contextlib.suppress(Exception):
                from sandroid.core.emulator import avd_dir

                avd_folder = avd_dir(target_avd)
            if avd_folder is not None:
                dest = avd_folder / "snapshots" / name
                _extract(zf, prefix, dest, overwrite=False)
                rec.start_point.update(name=name, saved_ok=True)
                rec.avd = target_avd
                note = f"The start point {name} was added to {target_avd}."
            else:
                rec.start_point["saved_ok"] = False
                note = f"No AVD named {target_avd}: the start point was not added."
        else:
            rec.start_point["saved_ok"] = False
            note = "No start point: Review works, Rewind does not."
    rec.start_point["pinned"] = True
    rec.start_point["imported"] = True
    rec.note = f"Imported from {os.path.basename(str(archive))}"
    save_recording(rec)
    return rec, note


# ---------------------------------------------------------------------------
# file lists
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileFact:
    """``size`` bytes, ``mtime`` (epoch s on the device clock), ``stamp``
    (the exact modification time text, sub-second where the device has it).
    """

    size: int
    mtime: int
    stamp: str


def app_dirs(pkg: str) -> list[str]:
    from sandroid.core.adb_utils import validate_package_name

    pkg = validate_package_name(pkg)
    return [d.format(pkg=pkg) for d in APP_DIRS]


def file_list_command(pkg: str) -> str:
    """Device shell command listing every file of the app's folders.

    One line per file: ``<size> <mtime s> <mtime text> <path>`` (toybox
    ``stat -c '%s %Y %y %n'``). Missing folders are skipped quietly.
    """
    dirs = " ".join(shlex.quote(d) for d in app_dirs(pkg))
    return (
        f'for d in {dirs}; do [ -d "$d" ] && '
        "find \"$d\" -type f -exec stat -c '%s %Y %y %n' {} + ; "
        "done 2>/dev/null"
    )


_LIST_RE = re.compile(r"^(\d+) (\d+) (\S+ \S+(?: [+-]\d{4})?) (/.*)$")
_LIST_SHORT_RE = re.compile(r"^(\d+) (\d+) (/.*)$")


def parse_file_list(text: str) -> dict[str, FileFact]:
    """``{path: FileFact}`` of :func:`file_list_command` output."""
    out: dict[str, FileFact] = {}
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        m = _LIST_RE.match(line)
        if m:
            out[m[4]] = FileFact(int(m[1]), int(m[2]), m[3])
            continue
        m = _LIST_SHORT_RE.match(line)
        if m:
            out[m[3]] = FileFact(int(m[1]), int(m[2]), m[2])
    return out


def write_file_list(path: Path, facts: dict[str, FileFact]) -> None:
    """Keep a list as TSV (size, mtime, stamp, path) next to recording.json."""
    lines = [f"{f.size}\t{f.mtime}\t{f.stamp}\t{p}" for p, f in sorted(facts.items())]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def diff_file_lists(
    start: dict[str, FileFact], stop: dict[str, FileFact]
) -> list[dict[str, Any]]:
    """New, changed and deleted files between two lists."""
    out: list[dict[str, Any]] = []
    for path, fact in stop.items():
        old = start.get(path)
        if old is None:
            out.append(_entry(path, "new", fact))
        elif (old.size, old.stamp) != (fact.size, fact.stamp):
            out.append(_entry(path, "changed", fact))
    for path, fact in start.items():
        if path not in stop:
            out.append(_entry(path, "deleted", fact))
    return sort_changes(out)


def _entry(path: str, state: str, fact: FileFact | None) -> dict[str, Any]:
    return {
        "path": path,
        "state": state,
        "size": fact.size if fact else None,
        "mtime": fact.mtime if fact else None,
        "source": "list",
    }


def main_database(path: str) -> str:
    """The database a SQLite companion (``-wal``/``-journal``/``-shm``)
    belongs to; any other path unchanged.
    """
    for suffix in ("-wal", "-journal", "-shm"):
        if path.endswith(suffix) and len(path) > len(suffix):
            return path[: -len(suffix)]
    return path


def sort_changes(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Changed first, then new, then deleted; newest first in each."""
    return sorted(
        entries,
        key=lambda e: (
            _STATE_ORDER.get(e.get("state"), 9),
            -(e.get("mtime") or 0),
            e.get("path", ""),
        ),
    )


def in_app_dirs(path: str, pkg: str | None) -> bool:
    """``path`` is inside one of the app's data folders."""
    from sandroid.core.adb_utils import canonical_device_path

    if not pkg:
        return False
    path = canonical_device_path(path)
    for d in APP_DIRS:
        root = canonical_device_path(d.format(pkg=pkg))
        if path == root or path.startswith(root + "/"):
            return True
    return False


def monitor_changes(lines: Iterable[dict], pkg: str | None) -> list[dict[str, Any]]:
    """The file monitor's paths (``files/create|modify|delete|rename``)."""
    seen: dict[str, dict[str, Any]] = {}
    for line in lines:
        if line.get("src") != "files":
            continue
        data = line.get("data") or {}
        kind = line.get("kind")
        if data.get("dir"):
            continue
        targets: list[tuple[str, str]] = []
        if kind in _FILE_OPS and data.get("path"):
            targets.append((data["path"], _FILE_OPS[kind]))
        elif kind == "rename":
            if data.get("path"):
                targets.append((data["path"], "deleted"))
            if data.get("new_path"):
                targets.append((data["new_path"], "new"))
        for path, state in targets:
            prev = seen.get(path)
            if prev is not None and prev["state"] == "new" and state == "changed":
                state = "new"
            seen[path] = {
                "path": path,
                "state": state,
                "size": None,
                "mtime": None,
                "source": "monitor",
                "outside_app": not in_app_dirs(path, pkg),
            }
    return list(seen.values())


def merge_changes(
    listed: list[dict[str, Any]], monitored: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The list's entries, plus monitor paths the list does not have."""
    from sandroid.core.adb_utils import canonical_device_path

    by_path = {canonical_device_path(e["path"]): e for e in listed}
    out = list(listed)
    for entry in monitored:
        key = canonical_device_path(entry["path"])
        if key in by_path:
            by_path[key]["source"] = "list+monitor"
            continue
        by_path[key] = entry
        out.append(entry)
    return sort_changes(out)


# ---------------------------------------------------------------------------
# timeline reading
# ---------------------------------------------------------------------------


def timeline_path() -> Path:
    from sandroid.core.timeline import FILE_NAME, timeline_folder

    return timeline_folder() / FILE_NAME


def timeline_size() -> int:
    """Current size of the timeline file (a cheap start offset)."""
    from sandroid.core.timeline import flush_timeline

    with contextlib.suppress(Exception):
        flush_timeline(1.0)
    try:
        return timeline_path().stat().st_size
    except OSError:
        return 0


def lines_between(
    start_seq: int | None,
    stop_seq: int | None,
    *,
    offset: int = 0,
    path: Path | None = None,
) -> list[dict]:
    """Timeline lines with ``start_seq <= seq <= stop_seq`` (unmasked)."""
    from sandroid.core.timeline import flush_timeline, read_lines

    with contextlib.suppress(Exception):
        flush_timeline(1.0)
    path = path or timeline_path()
    out: list[dict] = []
    if start_seq is None:
        return out
    try:
        for _off, line in read_lines(
            path, start=offset, reader="export", mask_sensitive=False
        ):
            seq = line.get("seq")
            if not isinstance(seq, int) or seq < start_seq:
                continue
            if stop_seq is not None and seq > stop_seq:
                break
            out.append(line)
    except OSError:
        logger.debug("rewind: timeline not readable", exc_info=True)
    if not out and offset:
        return lines_between(start_seq, stop_seq, offset=0, path=path)
    return out


def line_time(line: dict) -> float | None:
    """Epoch seconds of a timeline line's ``t`` (ISO text on disk)."""
    value = line.get("t")
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def in_time(lines: Iterable[dict], t0: float | None, t1: float | None) -> list[dict]:
    """The lines whose ``t`` lies in ``[t0, t1]`` (an open end: no bound)."""
    out = []
    for line in lines:
        t = line_time(line)
        if t is None:
            continue
        if (t0 is not None and t < t0) or (t1 is not None and t > t1):
            continue
        out.append(line)
    return out


def requests_in(lines: Iterable[dict]) -> list[dict[str, Any]]:
    """``net/flow`` and ``net/tls-fail`` lines as Review rows.

    ``order``: the request's position among the earlier ones with the same
    method + host + path (0 = first), the tie-break of :func:`match_flow`.
    """
    out = []
    counts: dict[tuple, int] = {}
    for line in lines:
        if line.get("src") != "net" or line.get("kind") not in ("flow", "tls-fail"):
            continue
        data = line.get("data") or {}
        row = {
            "seq": line.get("seq"),
            "kind": line.get("kind"),
            "flow_id": (line.get("ref") or {}).get("id"),
            "method": data.get("method") or "",
            "host": data.get("host") or "",
            "path": data.get("path") or "",
            "status": data.get("status"),
            "reason": data.get("reason"),
        }
        key = flow_key(row)
        row["order"] = counts.get(key, 0)
        counts[key] = row["order"] + 1
        out.append(row)
    return out


def flow_key(req: dict[str, Any]) -> tuple[str, str, str]:
    """What identifies a request across runs: method + host + path."""
    return (
        str(req.get("method") or "").upper(),
        str(req.get("host") or "").lower(),
        str(req.get("path") or ""),
    )


def match_flow(
    selected: dict[str, Any], replay: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The replay's counterpart of a selected request, or None.

    Same method + host + path; when the replay has several, the one at the
    same order position (the last one when the replay has fewer).
    """
    key = flow_key(selected)
    same = [r for r in replay if r.get("kind") == "flow" and flow_key(r) == key]
    if not same:
        return None
    order = int(selected.get("order") or 0)
    return same[order] if order < len(same) else same[-1]


def _body_bytes(body: Any) -> bytes | None:
    import base64

    if not isinstance(body, dict):
        return None
    content = body.get("content")
    if content is None:
        return b""
    if body.get("encoding") == "base64":
        try:
            return base64.b64decode(content)
        except Exception:
            return str(content).encode()
    return str(content).encode("utf-8", "replace")


def _body_text(body: Any, limit: int = 4000) -> str:
    raw = _body_bytes(body)
    if raw is None:
        return "(no body captured)"
    if not raw:
        return "(empty)"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"(binary, {len(raw)} bytes)"
    if len(text) > limit:
        text = text[:limit] + f"… ({len(text) - limit} more characters)"
    if isinstance(body, dict) and body.get("truncated"):
        text += "\n(the capture was cut off)"
    return text


def _headers_text(headers: Any) -> list[str]:
    out = []
    for item in headers or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append(f"{item[0]}: {item[1]}")
        elif isinstance(item, dict):
            out.append(f"{item.get('name')}: {item.get('value')}")
    return out


@dataclass
class FlowResult:
    """One selected request compared with its replay counterpart."""

    original: dict[str, Any]
    replay: dict[str, Any] | None
    found: str
    body: str = ""
    status: str = ""
    sides: dict[str, dict[str, Any]] = field(default_factory=dict)


def flow_side(req: dict[str, Any] | None, detail: dict | None) -> dict[str, Any]:
    """URL, headers and body of one request, as plain text parts."""
    if req is None:
        return {"url": "", "headers": [], "body": "", "status": ""}
    detail = detail or {}
    status = req.get("status")
    return {
        "url": f"{req.get('method')} {req.get('host')}{req.get('path') or ''}",
        "headers": _headers_text(detail.get("request_headers")),
        "body": _body_text(detail.get("request_body")),
        "status": str(status) if status is not None else "no answer",
    }


def compare_flow(
    selected: dict[str, Any],
    replay_reqs: list[dict[str, Any]],
    detail: Callable[[str | None], dict | None],
) -> FlowResult:
    """``found in the replay`` / ``not seen in the replay``, then one
    same / different verdict for the request body and the response status.
    """
    match = match_flow(selected, replay_reqs)
    orig_detail = detail(selected.get("flow_id"))
    res = FlowResult(
        original=selected,
        replay=match,
        found="found in the replay" if match else "not seen in the replay",
    )
    res.sides["your run"] = flow_side(selected, orig_detail)
    if match is None:
        return res
    rep_detail = detail(match.get("flow_id"))
    res.sides["replay"] = flow_side(match, rep_detail)
    a = _body_bytes((orig_detail or {}).get("request_body"))
    b = _body_bytes((rep_detail or {}).get("request_body"))
    if a is None or b is None:
        res.body = "not captured"
    else:
        res.body = "same" if a == b else "different"
    res.status = (
        "same" if selected.get("status") == match.get("status") else "different"
    )
    return res


def flow_result_lines(res: FlowResult) -> list[str]:
    """A compared request as plain lines (Sessions lens, AI)."""
    out = [f"{request_text(res.original)}: {res.found}"]
    if res.replay is None:
        return out
    out.append(f"  request body: {res.body}; response status: {res.status}")
    for side in ("your run", "replay"):
        part = res.sides.get(side) or {}
        out.append(f"  {side}: {part.get('url')}  status {part.get('status')}")
    return out


def flow_detail_reader() -> Callable[[str | None], dict | None]:
    """``flow_id -> details json`` of this session's mitmproxy flow log."""

    def read(flow_id: str | None) -> dict | None:
        if not flow_id:
            return None
        try:
            from sandroid.services.mitmproxy_flow_log import (
                read_flow_detail,
                resolve_flow_dir,
            )

            return read_flow_detail(resolve_flow_dir(), str(flow_id))
        except Exception:
            logger.debug("rewind: flow detail unreadable", exc_info=True)
            return None

    return read


def request_text(req: dict[str, Any]) -> str:
    """One request as plain words."""
    if req.get("kind") == "tls-fail":
        return f"TLS failed  {req.get('host')}"
    status = req.get("status")
    shown = status if status is not None else "no answer"
    path = req.get("path") or ""
    if len(path) > 60:
        path = path[:59] + "…"
    return f"{req.get('method') or '?':<6} {req.get('host')}{path}  {shown}"


# ---------------------------------------------------------------------------
# device helpers
# ---------------------------------------------------------------------------


def app_pids(ps_text: str, pkg: str) -> list[int]:
    """PIDs of ``pkg`` and its ``pkg:name`` processes (``ps -A -o PID,NAME``)."""
    out = []
    for line in (ps_text or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        name = parts[-1]
        if name == pkg or name.startswith(f"{pkg}:"):
            out.append(int(parts[0]))
    return out


def guest_ram_bytes(avd_folder: Path | None) -> int | None:
    """``hw.ramSize`` of the AVD (MB, or with a unit) in bytes."""
    if avd_folder is None:
        return None
    try:
        text = (avd_folder / "config.ini").read_text(errors="replace")
    except OSError:
        return None
    m = re.search(r"^hw\.ramSize\s*=\s*(\d+)\s*([MmGg]?)", text, re.MULTILINE)
    if not m:
        return None
    value = int(m[1])
    return value * (1024**3 if m[2].lower() == "g" else 1024**2)


def disk_problem(avd_folder: Path | None) -> str | None:
    """A plain sentence when the disk is too full for a start point."""
    if avd_folder is None:
        return None
    try:
        free = shutil.disk_usage(avd_folder).free
    except OSError:
        return None
    need = (guest_ram_bytes(avd_folder) or 2 * 1024**3) + DISK_MARGIN_BYTES
    if free >= need:
        return None
    return (
        f"Not enough disk for a start point: needs about {need / 1024**3:.0f} GB, "
        f"{free / 1024**3:.0f} GB free"
    )


# ---------------------------------------------------------------------------
# role diffs and verdicts
# ---------------------------------------------------------------------------


@dataclass
class FileResult:
    """``What your action changed`` (and the replay) for one file."""

    path: str
    before: str | None
    after: str | None
    after_replay: str | None = None
    action_text: str = ""
    replay_text: str = ""
    verdict: str = NO_REPLAY
    only_run: list[str] = field(default_factory=list)
    only_replay: list[str] = field(default_factory=list)
    error: str = ""
    #: Set when the replay this verdict compares diverged (plain sentence).
    note: str = ""
    #: Selected after a Rewind ran: no After from your run.
    late: bool = False
    #: ``field by field`` (the Files lens's smart diff) or ``byte for byte``
    #: (no structure to compare); empty when the copies are one version.
    compared: str = ""
    #: Fields both runs changed to different values that a rule explains:
    #: ``{"field", "your_run", "replay", "rule"}`` each (never hidden).
    volatile: list[dict[str, str]] = field(default_factory=list)


def _version_main(path: str, version: str | None) -> Path | None:
    from sandroid.core import watchlist_store

    if not version or version == ABSENT:
        return None
    folder = watchlist_store.row_dir(path) / version
    return watchlist_store.version_file(folder, path) if folder.is_dir() else None


def _diff_lines(path: str, old: str | None, new: str | None) -> tuple[list[str], str]:
    """Plain diff body lines from version ``old`` to ``new`` and a note."""
    from sandroid.core import file_inspect

    if old in (None, ABSENT) and new in (None, ABSENT):
        return [], "not on the device"
    if old == new:
        return [], "no change"
    if old == ABSENT:
        return [], "new file (did not exist before)"
    if new == ABSENT:
        return [], "deleted (no longer on the device)"
    old_file, new_file = _version_main(path, old), _version_main(path, new)
    if old_file is None or new_file is None:
        return [], "a copy is missing"
    diff = file_inspect.structured_diff(old_file, new_file)
    if diff.error:
        return [], diff.error
    if diff.empty:
        return [], diff.note or "no change in the content"
    doc = file_inspect.diff_document(diff, device_path=path, file=old_file.name)
    lines = file_inspect.render_plain_diff(doc).splitlines()
    header = len(file_inspect._plain_header(doc, diff))
    body = lines[header:] if 0 < header < len(lines) else lines
    return [ln for ln in body if ln.strip()], ""


def diverged_note(run: dict[str, Any] | None) -> str:
    """The note a verdict carries when ``run`` (a Rewind + Replay) diverged
    or left steps unchecked ("" otherwise).
    """
    at = (run or {}).get("diverged_at_step")
    if (run or {}).get("result") == UNCHECKED:
        steps = (run or {}).get("unchecked_steps") or []
        return (
            f"Replay step{'s' if len(steps) != 1 else ''} {_steps_list(steps)} "
            "could not be checked: this result may not show what your run did."
        )
    if (run or {}).get("result") != DIVERGED or not at:
        return ""
    return (
        f"The replay diverged at step {at}: this result does not show what "
        "your run did."
    )


def file_result(
    rec: Recording,
    path: str,
    *,
    with_replay: bool = True,
    secrets: Collection[str] = (),
) -> FileResult:
    """Before to After and Before to After (replay) of one selected file.

    ``with_replay=False``: the latest run was a plain Rewind, so an older
    replay's copy is not compared (its verdict would be stale). The verdict
    compares what both runs changed field by field (``core/replay_verdict``).
    ``secrets`` (:func:`hidden_texts`) are masked in every value shown.
    """
    before = rec.role_version(path, "before")
    after = rec.role_version(path, "after")
    replays = rec.versions.get(path, {}).get("after_replay") or []
    replay = rec.role_version(path, "after_replay") if with_replay else None
    res = FileResult(path, before, after, replay)
    res.late = after is None and path in rec.late_selected
    try:
        run_lines, run_note = _diff_lines(path, before, after)
        res.action_text = "\n".join(run_lines) if run_lines else run_note
        if replay is None:
            res.verdict = NOT_COPIED if with_replay and replays else NO_REPLAY
            return res
        res.note = diverged_note(rec.runs[-1] if rec.runs else None)
        rep_lines, rep_note = _diff_lines(path, before, replay)
        res.replay_text = "\n".join(rep_lines) if rep_lines else rep_note
        if after == replay:
            res.verdict = SAME  # one version: the same content
        elif replay == before:
            res.verdict = UNCHANGED
        else:
            _compare(rec, path, res, run_lines, rep_lines, secrets)
    except Exception as exc:  # a result view must never crash
        logger.debug("rewind: file result failed", exc_info=True)
        res.error = str(exc)
    if secrets:
        _hide_values(res, secrets)
    return res


def run_windows(rec: Recording, path: str) -> tuple[Any, Any]:
    """``(your run, the latest replay)`` as :class:`~sandroid.core.
    replay_verdict.RunWindow` (None when unknown).

    Your run: record start to Stop (or to when ``path``'s After was copied,
    if later). The replay: the latest one that copied After (replay), from
    its first step to its end. Rule 2 measures both from their step 1.
    """
    from sandroid.core.replay_verdict import RunWindow

    def num(v: Any) -> float | None:
        return float(v) if isinstance(v, (int, float)) and v else None

    run = None
    start = num(rec.started)
    if start is not None:
        ends = [e for e in (num(rec.stopped), num(rec.after_at.get(path))) if e]
        run = RunWindow(start, max(ends + [start]))
    replays = [r for r in rec.runs if r.get("kind") == "rewind-replay"]
    # Runs saved before ``replay_copied`` existed: the latest replay.
    copied = [r for r in replays if r.get("replay_copied", True)]
    last = (copied or replays or [None])[-1]
    replay = None
    if last is not None:
        r_start = num(last.get("replay_started")) or num(last.get("started"))
        if r_start is not None:
            replay = RunWindow(
                r_start,
                max(num(last.get("ended")) or 0.0, r_start),
                num(last.get("first_step_at")),
            )
        if run is not None:
            run = RunWindow(run.start, run.end, num(last.get("recorded_first_step_at")))
    return run, replay


_OUTCOME_WORDS = {
    "same": SAME,
    "volatile": VOLATILE,
    "different": DIFFERENT,
    "unchanged": UNCHANGED,
}


def _compare(
    rec: Recording,
    path: str,
    res: FileResult,
    run_lines: list[str],
    rep_lines: list[str],
    secrets: Collection[str] = (),
) -> None:
    """The verdict from the Files lens's smart diff of the three copies."""
    from sandroid.core import replay_verdict

    if res.before is None or res.after is None:
        # Before not copied (it is not "a new file"), or selected late: no
        # After from your run.
        res.verdict = NOT_COMPARED
        return
    copies = []
    for version in (res.before, res.after, res.after_replay):
        if version in (None, ABSENT):
            copies.append(None)
            continue
        local = _version_main(path, version)
        if local is None or not local.is_file():
            res.verdict = NOT_COMPARED
            res.error = "a copy of this file is missing"
            return
        copies.append(local)
    run, replay = run_windows(rec, path)
    cmp = replay_verdict.compare(
        *copies,
        run=run,
        replay_run=replay,
        secrets=secrets,
        device_tz=rec.device_tz,
    )
    res.verdict = _OUTCOME_WORDS[cmp.outcome]
    res.compared = cmp.compared
    res.volatile = [v.as_dict() for v in cmp.volatile]
    if cmp.compared == replay_verdict.FIELD_BY_FIELD:
        res.only_run, res.only_replay = cmp.only_run, cmp.only_replay
    elif res.verdict == DIFFERENT:
        run_set, rep_set = set(run_lines), set(rep_lines)
        res.only_run = [ln for ln in run_lines if ln not in rep_set]
        res.only_replay = [ln for ln in rep_lines if ln not in run_set]


def _hide_values(res: FileResult, secrets: Collection[str]) -> None:
    """Mask what was typed into sensitive fields in the diff texts (the
    compared fields were masked before they were cut to length).
    """
    from sandroid.core.replay_verdict import hide

    res.action_text = hide(res.action_text, secrets)
    res.replay_text = hide(res.replay_text, secrets)
    res.only_run = [hide(ln, secrets) for ln in res.only_run]
    res.only_replay = [hide(ln, secrets) for ln in res.only_replay]


def sensitive_texts(rec: Recording) -> frozenset[str]:
    """What was typed into sensitive fields (passwords ...) during the
    recording: the values masking hides in its results.
    """
    out: set[str] = set()
    for line in lines_between(
        rec.seq.get("start"), rec.seq.get("stop"), offset=rec.timeline_offset
    ):
        data = line.get("data")
        if not isinstance(data, dict):
            continue
        if not (
            line.get("sensitive") or data.get("password") or data.get("data_sensitive")
        ):
            continue
        text = data.get("text")
        if isinstance(text, str) and len(text.strip()) >= SECRET_MIN_LEN:
            out.add(text)
    return frozenset(out)


#: Shorter typed text is not masked inside file values (it would mask
#: every occurrence of one or two characters).
SECRET_MIN_LEN = 3


def hidden_texts(rec: Recording | None, reader: str = "ui") -> frozenset[str]:
    """:func:`sensitive_texts` while masking is on for ``reader`` (``ui``:
    ``timeline.mask_sensitive``; ``ai``: ``ai.mask_sensitive``; ``any``:
    either, for what both read later, like run.json), else none.
    """
    if rec is None:
        return frozenset()
    try:
        from sandroid.core.timeline import should_mask

        readers = ("ui", "ai") if reader == "any" else (reader,)
        if not any(should_mask(r) for r in readers):  # type: ignore[arg-type]
            return frozenset()
        return sensitive_texts(rec)
    except Exception:
        logger.debug("rewind: sensitive texts not read", exc_info=True)
        return frozenset()


#: A file selected after a Rewind ran (Review, Sessions, results).
LATE_WORDS = (
    "  No After from your run: this file was selected after a Rewind, when "
    "the device no longer showed what your action left."
)


#: ``FileResult.compared`` of a file without fields to compare.
BYTE_WORDS_KEY = "byte for byte"
BYTE_WORDS = "Compared byte for byte (this file has no fields to compare)."
VOLATILE_HEADING = "Volatile fields (both runs changed them; a rule explains why):"


def volatile_line(v: dict[str, str]) -> str:
    """``field: A in your run, B in the replay (rule)``."""
    return (
        f"{v.get('field')}: {v.get('your_run')} in your run, "
        f"{v.get('replay')} in the replay ({v.get('rule')})"
    )


def result_lines(res: FileResult) -> list[str]:
    """The result of one file as plain lines (Sessions lens, AI, report)."""
    words = ROLE_WORDS
    out = ["What your action changed (Before to After):"]
    if res.late:
        out.append(LATE_WORDS)
    if res.before is None:
        out.append("  Before was not copied (no rewind yet).")
    out.extend(f"  {ln}" for ln in (res.action_text or "no change").splitlines())
    if res.after_replay is not None:
        out.append(f"What the replay changed (Before to {words['after_replay']}):")
        out.extend(f"  {ln}" for ln in (res.replay_text or "no change").splitlines())
        for ln in res.only_run:
            out.append(f"  only in your run: {ln}")
        for ln in res.only_replay:
            out.append(f"  only in the replay: {ln}")
    out.append(f"Result: {res.verdict}")
    if res.compared == BYTE_WORDS_KEY:
        out.append(BYTE_WORDS)
    if res.volatile:
        out.append(VOLATILE_HEADING)
        out.extend(f"  {volatile_line(v)}" for v in res.volatile)
    if res.note:
        out.append(f"Note: {res.note}")
    if res.error:
        out.append(f"Could not compare: {res.error}")
    return out


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


class RewindStoppedError(Exception):
    """The run stopped; ``str(exc)`` is the plain reason."""


@dataclass
class PullOutcome:
    """``version`` holds the content (``ABSENT``: not on the device)."""

    version: str | None
    error: str | None = None


@dataclass
class RewindDeps:
    """What :class:`RewindRunner` needs from the app (all thread-safe).

    ``shell`` runs a device shell command line and returns stdout.
    ``pull(path, role, rec_id, run)`` pulls one file through the Files lens
    (watch versions) and returns the version that holds its content.
    ``replay(rec, runner)`` repeats the steps (Step 2; ``None``: not built).
    ``stop_reason()`` says why the run was stopped once ``cancelled()`` is
    true (``stopped``, ``stopped by quit``).
    """

    load_snapshot: Callable[[str, str | None], bool]
    shell: Callable[[str], str]
    pull: Callable[[str, str, str, int], PullOutcome]
    after_load: Callable[[], None] = lambda: None
    stop_monitor: Callable[[], Any] = lambda: None
    progress: Callable[[str], None] = lambda _text: None
    cancelled: Callable[[], bool] = lambda: False
    replay: Callable[[Recording, RewindRunner], dict[str, Any]] | None = None
    clock_fix: Callable[[], None] = lambda: None
    emit: Callable[..., int | None] | None = None
    stop_reason: Callable[[], str] = lambda: "stopped"


@dataclass
class RunOutcome:
    """What one Rewind / Rewind + Replay did."""

    n: int
    mode: str
    result: str = ""
    error: str | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    stopped_at_step: int | None = None
    #: The first step that diverged, and why (plain sentence).
    diverged_at_step: int | None = None
    diverged: str | None = None
    #: Steps nothing confirmed (element not found / off-screen ...).
    unchecked_steps: list[int] = field(default_factory=list)
    seq: dict[str, int | None] = field(default_factory=dict)
    monitor_config: Any = None
    paused: list[int] = field(default_factory=list)
    #: The start point was loaded (the device left the after-the-action state).
    loaded: bool = False
    #: When step 1 ran in the replay and in your run (wall clock, epoch s).
    first_step_at: float | None = None
    recorded_first_step_at: float | None = None
    #: This run copied After (replay) (its window is the one compared).
    replay_copied: bool = False


def unchecked_words(out: RunOutcome) -> str:
    """What a replay with unchecked steps tells you (never "Done.")."""
    steps = out.unchecked_steps
    n = len(steps)
    return (
        f"Replay done, {n} step{'s' if n != 1 else ''} unchecked "
        f"(step{'s' if n != 1 else ''} {_steps_list(steps)}): the device may not "
        "show what your run did."
    )


def diverged_words(out: RunOutcome) -> str:
    """What a diverged replay tells you (plain sentence, no success)."""
    why = out.diverged or f"step {out.diverged_at_step}"
    return f"The replay diverged at {why}. The device does not show what your run did."


class RewindRunner:
    """Rewind (+ Replay) of one recording; call :meth:`run` on a worker."""

    def __init__(self, rec: Recording, deps: RewindDeps) -> None:
        self.rec = rec
        self.deps = deps
        self.start_seq: int | None = None
        self._what = "Rewind"

    # -- small helpers ------------------------------------------------------

    def _emit(self, *args: Any, **kw: Any) -> int | None:
        emit = self.deps.emit
        if emit is None:
            from sandroid.core.timeline import get_timeline

            emit = get_timeline().set_phase
        try:
            return emit(*args, **kw)
        except Exception:
            logger.debug("rewind: timeline line failed", exc_info=True)
            return None

    def _check(self) -> None:
        if self.deps.cancelled():
            raise RewindStoppedError(self._stop_words())

    def _stop_words(self) -> str:
        """``Replay stopped by quit.`` / ``Rewind stopped.`` (the real reason)."""
        try:
            reason = str(self.deps.stop_reason() or "stopped")
        except Exception:
            reason = "stopped"
        return f"{self._what} {reason}."

    def pause_app(self) -> list[int]:
        """``kill -STOP`` every process of the app (best effort)."""
        pkg = self.rec.pkg
        if not pkg:
            return []
        try:
            pids = app_pids(self.deps.shell("ps -A -o PID,NAME"), pkg)
        except Exception:
            logger.debug("rewind: ps failed", exc_info=True)
            return []
        if pids:
            with contextlib.suppress(Exception):
                self.deps.shell("kill -STOP " + " ".join(str(p) for p in pids))
        return pids

    def resume_app(self, pids: list[int]) -> None:
        if pids:
            with contextlib.suppress(Exception):
                self.deps.shell("kill -CONT " + " ".join(str(p) for p in pids))

    def pull_role(self, role: str, run: int) -> dict[str, str]:
        """Pull ``role`` of every selected file; ``{path: error}``."""
        errors: dict[str, str] = {}
        paths = list(self.rec.selected)
        word = ROLE_WORDS[role]
        for i, path in enumerate(paths, 1):
            self.deps.progress(
                f"Saving {word} of {len(paths)} file{'s' if len(paths) != 1 else ''}"
                + (f" ({i})" if len(paths) > 1 else "")
            )
            try:
                out = self.deps.pull(path, role, self.rec.rec_id, run)
            except Exception as exc:
                out = PullOutcome(None, str(exc))
            if out.error and out.version is None:
                errors[path] = out.error
                if role != "after_replay":
                    continue  # keep an earlier good copy of this role
            self.rec.set_role(path, role, out.version)
        return errors

    # -- the run ------------------------------------------------------------

    def run(self, *, replay: bool) -> RunOutcome:
        """Load the start point, pull Before, optionally replay + After (replay).

        Never raises: a stop or a failure is the outcome's ``error`` (a
        plain sentence); Before and After stay as far as they got.
        """
        rec = self.rec
        mode = "rewind-replay" if replay else "rewind"
        self._what = "Replay" if replay else "Rewind"
        n = len(rec.runs) + 2  # run 1 is the original
        t0 = time.time()
        t_replay: float | None = None
        out = RunOutcome(n=n, mode=mode)
        name = rec.start_point_name
        words = "rewind and replay started" if replay else "rewind started"
        out.seq["start"] = self._emit(
            "setup",
            f"{rec.rec_id}#{n}",
            kind="play-start",
            summary=f"{words} · {rec.name}",
            data={"mode": mode, "rec_id": rec.rec_id, "run": n, "start_point": name},
        )
        #: This run's play-start line: the recording's lines end before it.
        self.start_seq = out.seq["start"]
        pids: list[int] = []
        try:
            if not name:
                raise RewindStoppedError(
                    "The start point is gone. Record again to rewind."
                )
            self._check()
            out.monitor_config = self.deps.stop_monitor()
            self.deps.progress("Going back to the start point")
            try:
                loaded = self.deps.load_snapshot(name, rec.serial)
            except RewindStoppedError:
                # The load may have happened (it timed out): count the
                # device as no longer after the action.
                out.loaded = True
                raise
            if not loaded:
                raise RewindStoppedError(
                    "Could not go back to the start point: the emulator refused "
                    "to load it. The device was not changed."
                )
            out.loaded = True
            self.deps.clock_fix()
            self.deps.after_load()
            self._check()
            pids = self.pause_app()
            out.paused = list(pids)
            try:
                errors = self.pull_role("before", n)
            finally:
                self.resume_app(pids)
            for path, err in errors.items():
                self.deps.progress(f"Could not copy {path}: {err}.")
            if not replay:
                out.result = "rewound"
                self.deps.progress("Done. The device is at the start point.")
                return out
            if self.deps.replay is None:
                raise RewindStoppedError("Replay is not available yet.")
            t_replay = time.time()
            out.seq["replay"] = self._emit(
                "replay",
                f"{rec.rec_id}#{n}",
                kind="phase",
                summary=f"replaying the steps of {rec.name}",
                data={"rec_id": rec.rec_id, "run": n},
            )
            report = self.deps.replay(rec, self) or {}
            out.steps = list(report.get("steps") or [])
            out.stopped_at_step = report.get("stopped_at_step")
            out.diverged_at_step = report.get("diverged_at_step")
            out.diverged = report.get("diverged")
            out.unchecked_steps = list(report.get("unchecked_steps") or [])
            out.first_step_at = report.get("first_step_at")
            out.recorded_first_step_at = report.get("recorded_first_step_at")
            self._emit(
                "setup",
                f"{rec.rec_id}#{n}",
                kind="phase",
                summary="saving After (replay)",
                data={"rec_id": rec.rec_id, "run": n},
            )
            errors = self.pull_role("after_replay", n)
            out.replay_copied = True
            for path, err in errors.items():
                self.deps.progress(f"Could not copy {path}: {err}.")
            if report.get("error"):
                out.error = report["error"]
                out.result = "stopped"
            elif out.diverged_at_step:
                out.result = DIVERGED
                self.deps.progress(diverged_words(out))
            elif out.unchecked_steps:
                out.result = UNCHECKED
                self.deps.progress(unchecked_words(out))
            else:
                out.result = "replayed"
                self.deps.progress("Done. The device shows the replayed result.")
            return out
        except RewindStoppedError as exc:
            out.error = str(exc)
            out.result = "stopped"
            return out
        except Exception as exc:  # the worker must never die silently
            if self.deps.cancelled():
                # A stop that surfaced as another error (a step stopped
                # mid-way): the reason is the stop, not a failure.
                logger.debug("rewind stopped: %s", exc, exc_info=True)
                out.error = self._stop_words()
            else:
                logger.exception("rewind failed")
                out.error = f"Rewind failed: {exc}"
            out.result = "stopped"
            return out
        finally:
            run = {
                "n": n,
                "kind": mode,
                "started": t0,
                "replay_started": t_replay,
                "ended": time.time(),
                "result": out.result or "stopped",
                "error": out.error,
                "stopped_at_step": out.stopped_at_step,
                "diverged_at_step": out.diverged_at_step,
                "diverged": out.diverged,
                "unchecked_steps": out.unchecked_steps,
                "steps": out.steps,
                "loaded": out.loaded,
                "first_step_at": out.first_step_at,
                "recorded_first_step_at": out.recorded_first_step_at,
                "replay_copied": out.replay_copied,
            }
            rec.runs.append(run)
            summary = {
                "rewound": "rewind finished · the device is at the start point",
                "replayed": "replay finished",
            }.get(out.result)
            if out.result == UNCHECKED:
                summary = "replay " + result_words(run)
            if out.result == DIVERGED:
                summary = f"replay diverged at step {out.diverged_at_step}" + (
                    f" · {out.diverged}" if out.diverged else ""
                )
            if summary is None:
                at = out.stopped_at_step
                summary = (
                    f"replay stopped at step {at}" if at else "rewind stopped"
                ) + (f" · {out.error}" if out.error else "")
            out.seq["end"] = self._emit(
                "live",
                None,
                kind="play-end",
                summary=summary,
                data={
                    "mode": mode,
                    "rec_id": rec.rec_id,
                    "run": n,
                    "result": out.result or "stopped",
                    "error": out.error,
                    "stopped_at_step": out.stopped_at_step,
                    "diverged_at_step": out.diverged_at_step,
                    "unchecked_steps": out.unchecked_steps,
                },
                level={DIVERGED: "error", UNCHECKED: "warn"}.get(out.result, "info"),
                ref={"of": out.seq["start"]} if out.seq.get("start") else None,
            )
            run["seq"] = dict(out.seq)
            with contextlib.suppress(Exception):
                save_recording(rec)
