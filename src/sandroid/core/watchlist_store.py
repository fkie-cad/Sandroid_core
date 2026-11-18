"""On-disk state of the Files lens watchlist: ★ membership + pulled versions.

Two different lifetimes, two places:

1. **Membership** (what is ★ watched) persists across sessions, per package,
   in the user config directory -- one small, readable JSON file per app::

       ~/.config/sandroid/watchlists/<package>.json     (or $XDG_CONFIG_HOME)
       ~/.config/sandroid/watchlists/_device.json       paths outside an app dir

       {"schema_version": 3, "package": "com.app",
        "paths": ["/data/data/com.app/databases/app.db"],
        "patterns": ["/data/data/com.app/shared_prefs/*"]}

   Nothing else is persisted there (no pull state, no auto mode). The older
   per-device store (``watchlists/<device>/index.json`` + versions) is
   ignored -- it is neither read nor migrated nor deleted.

2. **Pulled versions** are evidence of *this* session and live in the
   session results folder, readable, and are never pruned::

       <session results>/marks.jsonl          every mark (B), append-only
       <session results>/files/
           timeline.jsonl                     every file-monitor event, append-only
           <package>/<app-relative path>/
               checks.jsonl                   pulls that found no change (no copy)
               v001_10-42-07/
                   app.db  app.db-wal         the pulled copy (+ db companions)
                   diff.json                  the diff against the version before
                                              (canonical, structured; not in v001)
                   diff.txt                   the same diff as plain text, rendered
                                              from diff.json
                   acquisition.json           device path; per member (db, -wal,
                                              -journal) device mtime/size/sha256 and
                                              local sha256; the combined set hash;
                                              pull time, trigger, active mark

   A version is kept only for a real change: when the on-device sha256 of
   the file *and* its ``-wal``/``-journal`` equals the newest version's, the
   file is not pulled again and one line goes to ``checks.jsonl`` instead
   (:func:`append_check`). Every timestamp written here is ISO 8601 with
   the UTC offset (:func:`iso_tz`).

   ``<app-relative path>`` keeps the device layout below the app's data
   directory (``databases/app.db``); the device-encrypted and external app
   directories get an ``@de/`` / ``@ext/`` marker as in the lens. Files
   outside an app directory go under ``files/_device/<absolute path>/``. The
   session results folder is the initialization service's device folder
   (``results/<session>/<device>/``, not a running Play's bundle), else
   ``$RESULTS_PATH``.

Storage API used by the lens and the Inspector (keep names/semantics):
:func:`version_dirs` (oldest → newest), :func:`version_time`,
:func:`version_diff` (diff text vs the previous version, ``None`` for the
first), :func:`version_diff_doc` (``diff.json``), :func:`version_record`
(``acquisition.json``), :func:`version_file` (the local copy of the main
file in a version) and :func:`version_checks` (``checks.jsonl``).

A pull goes ``reset_current`` (staging ``.current/``) → pull into it →
:func:`keep_version` (structured diff against the newest version, then
:func:`promote`: renames the staging directory to the next
``vNNN_HH-MM-SS`` with ``diff.json`` + ``diff.txt`` + ``acquisition.json``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sandroid.core.adb_utils import canonical_device_path

logger = logging.getLogger(__name__)

#: Membership file schema (v3: per package, paths + patterns only).
SCHEMA_VERSION = 3

#: Overrides the membership directory (tests point it at a temp directory).
WATCHLIST_DIR_ENV = "SDROID_WATCHLIST_DIR"
#: Overrides the pulled-versions root (``<session results>/files``).
FILES_DIR_ENV = "SDROID_FILES_DIR"

#: Owner name for files that are not inside an app's data directory.
DEVICE_OWNER = "_device"

_DIFF_FILE = "diff.txt"
_DIFF_JSON = "diff.json"
_RECORD_FILE = "acquisition.json"
_CHECKS_FILE = "checks.jsonl"
_STAGING = ".current"
#: Session-wide logs in the files root (append-only JSON Lines).
MARKS_FILE = "marks.jsonl"
TIMELINE_FILE = "timeline.jsonl"
#: Files of a version folder that are not part of the pulled copy.
META_FILES = frozenset({_DIFF_FILE, _DIFF_JSON, _RECORD_FILE})
#: SQLite files kept with a database (``-shm`` changes on every read).
SQLITE_COMPANIONS = ("-wal", "-journal")
_APPEND_LOCK = threading.Lock()
_SEQ_LOCK = threading.Lock()
_VERSION_RE = re.compile(r"^v(\d+)_(\d{2})-(\d{2})-(\d{2})$")

#: ``(regex, marker)``: app data roots and the marker kept for the
#: app-relative path (same convention as the Files lens).
_APP_ROOTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/data/(?:data|user/\d+)/([^/]+)(?:/|$)"), ""),
    (re.compile(r"^/data/user_de/\d+/([^/]+)(?:/|$)"), "@de/"),
    (
        re.compile(r"^/(?:sdcard|storage/emulated/\d+)/Android/data/([^/]+)(?:/|$)"),
        "@ext/",
    ),
)


# ---------------------------------------------------------------------------
# timestamps (everything written to disk carries its UTC offset)
# ---------------------------------------------------------------------------


def iso_tz(when: datetime | float | None = None, timespec: str = "seconds") -> str:
    """``when`` (a naive local / aware datetime or an epoch, default now) as
    ISO 8601 with the UTC offset: ``2026-11-18T12:33:13+01:00``.
    ``timespec="milliseconds"`` (the event logs ``timeline.jsonl`` /
    ``marks.jsonl``) gives ``2026-11-18T12:33:13.042+01:00``.
    """
    if when is None:
        when = datetime.now()
    elif isinstance(when, (int, float)) and not isinstance(when, bool):
        when = datetime.fromtimestamp(when)
    return when.astimezone().isoformat(timespec=timespec)


def local_naive(when: datetime) -> datetime:
    """An aware datetime as naive host-local time (naive ones unchanged)."""
    if when.tzinfo is None:
        return when
    return when.astimezone().replace(tzinfo=None)


# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------


def owner_and_relative(path: str) -> tuple[str, str]:
    """``(package, app-relative path)`` of a device path.

    ``/data/data/com.app/databases/app.db`` -> ``("com.app", "databases/app.db")``,
    ``/data/user_de/0/com.app/x`` -> ``("com.app", "@de/x")``,
    ``/data/local/tmp/x`` -> ``("_device", "data/local/tmp/x")``.
    """
    path = canonical_device_path(path)
    for regex, marker in _APP_ROOTS:
        match = regex.match(path)
        if match:
            rest = path[match.end() :].strip("/")
            return match.group(1), marker + rest if rest else marker + "_root"
    return DEVICE_OWNER, path.strip("/") or "_root"


def package_of(path: str) -> str | None:
    """The package whose data directory holds ``path`` (``None`` otherwise)."""
    owner, _rel = owner_and_relative(path)
    return None if owner == DEVICE_OWNER else owner


def _safe_parts(relative: str) -> list[str]:
    """Path components that cannot climb out of the files root."""
    out = []
    for part in relative.split("/"):
        if part in ("", ".", ".."):
            part = f"_{part}" if part else "_"
        out.append(part)
    return out


def session_results_dir() -> Path:
    """The live session's results folder (``results/<session>/<device>/``).

    The initialization service's device folder wins (a running Play pins
    ``RESULTS_PATH`` to its bundle; pulls belong to the session), then
    ``$RESULTS_PATH``, then ``./results``.
    """
    try:
        from sandroid.services import get_initialization_service

        device_path = get_initialization_service().get_device_path()
        if device_path:
            return Path(device_path).expanduser()
    except Exception:
        logger.debug("watchlist_store: no initialized session", exc_info=True)
    env_value = os.environ.get("RESULTS_PATH")
    return Path(env_value).expanduser() if env_value else Path("./results")


def files_root() -> Path:
    """Root of the pulled versions: ``<session results>/files``."""
    override = os.environ.get(FILES_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return session_results_dir() / "files"


def row_dir(path: str) -> Path:
    """The folder holding every pulled version of ``path`` (created)."""
    owner, relative = owner_and_relative(path)
    directory = files_root().joinpath(owner, *_safe_parts(relative))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _main_name(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or "pulled_file"


# ---------------------------------------------------------------------------
# versions (read API)
# ---------------------------------------------------------------------------


def _version_number(version: Path) -> int | None:
    match = _VERSION_RE.match(version.name)
    return int(match.group(1)) if match else None


def version_dirs(path: str) -> list[Path]:
    """Every pulled version of ``path``, oldest first (``vNNN_HH-MM-SS/``)."""
    owner, relative = owner_and_relative(path)
    root = files_root().joinpath(owner, *_safe_parts(relative))
    if not root.is_dir():
        return []
    found = [
        (number, d)
        for d in root.iterdir()
        if d.is_dir() and (number := _version_number(d)) is not None
    ]
    return [d for _n, d in sorted(found, key=lambda pair: pair[0])]


def version_record(version: Path) -> dict | None:
    """The version's ``acquisition.json`` (``None`` if missing/unreadable)."""
    try:
        data = json.loads((version / _RECORD_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def version_time(version: Path) -> datetime | None:
    """When a version was pulled (host local time).

    From ``acquisition.json``'s ``pulled_at``; else the ``HH-MM-SS`` of the
    folder name on the folder's modification date.
    """
    record = version_record(version) or {}
    stamp = record.get("pulled_at")
    if isinstance(stamp, str):
        try:
            return local_naive(datetime.fromisoformat(stamp))
        except ValueError:
            pass
    match = _VERSION_RE.match(version.name)
    if match is None:
        return None
    try:
        day = datetime.fromtimestamp(version.stat().st_mtime)
    except OSError:
        return None
    hour, minute, second = (int(match.group(i)) for i in (2, 3, 4))
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def version_diff(version: Path) -> str | None:
    """The diff stored with a version (against the version before it).

    ``None`` for the first version (nothing to diff against) or when no diff
    was stored; ``""`` when the pull found no change.
    """
    try:
        return (version / _DIFF_FILE).read_text(encoding="utf-8")
    except OSError:
        return None


def version_diff_doc(version: Path) -> dict | None:
    """The version's ``diff.json`` (``None`` for the first version, for
    versions kept before ``diff.json`` existed, or when unreadable).
    """
    try:
        data = json.loads((version / _DIFF_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def version_checks(path: str) -> list[dict]:
    """The "checked, no change" records of ``path`` (``checks.jsonl``), oldest
    first; unreadable lines are skipped.
    """
    owner, relative = owner_and_relative(path)
    file = files_root().joinpath(owner, *_safe_parts(relative), _CHECKS_FILE)
    return read_jsonl(file)


def read_jsonl(file: Path) -> list[dict]:
    """The JSON objects of a JSON Lines file (``[]`` if missing)."""
    out: list[dict] = []
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def version_file(version: Path, path: str) -> Path:
    """The local copy of ``path``'s main file inside ``version``."""
    record = version_record(version) or {}
    name = (record.get("local") or {}).get("file") if record else None
    return version / (name if isinstance(name, str) and name else _main_name(path))


def previous_dir(path: str) -> Path:
    """The newest version of ``path`` (a non-existent folder if none)."""
    dirs = version_dirs(path)
    return dirs[-1] if dirs else row_dir(path) / "v000_none"


def has_baseline(path: str) -> bool:
    """True once a version exists to diff the next pull against."""
    return bool(version_dirs(path))


# ---------------------------------------------------------------------------
# versions (write API)
# ---------------------------------------------------------------------------


def reset_current(path: str) -> Path:
    """Clear and recreate the staging folder (``.current/``) for a pull."""
    directory = row_dir(path) / _STAGING
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def discard_current(path: str) -> None:
    """Drop the staging folder (a pull that is not kept as a version)."""
    directory = row_dir(path) / _STAGING
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)


def next_version_name(path: str, when: datetime | None = None) -> str:
    """The folder name the next kept version of ``path`` gets."""
    root = row_dir(path)
    existing = version_dirs(path)
    number = (_version_number(existing[-1]) or 0) + 1 if existing else 1
    stamp = local_naive(when or datetime.now()).strftime("%H-%M-%S")
    name = f"v{number:03d}_{stamp}"
    while (root / name).exists():
        number += 1
        name = f"v{number:03d}_{stamp}"
    return name


def promote(
    path: str,
    diff_text: str | None = None,
    record: dict | None = None,
    when: datetime | None = None,
    diff_doc: dict | None = None,
) -> Path:
    """Keep the staged pull as the next version of ``path``.

    The staging folder becomes ``vNNN_HH-MM-SS/`` (numbered after the newest
    version). ``diff_doc`` (the ``diff.json`` document against the version
    before) goes to ``diff.json`` and, rendered as plain text, to
    ``diff.txt``; a bare ``diff_text`` (legacy callers) goes to ``diff.txt``
    alone. Both stay ``None`` for the first pull. ``record`` goes to
    ``acquisition.json`` (``"version"`` is filled in). Nothing is ever pruned.
    Returns the new version folder.
    """
    staging = row_dir(path) / _STAGING
    staging.mkdir(parents=True, exist_ok=True)
    target = staging.parent / next_version_name(path, when)
    if diff_doc is not None:
        from sandroid.core.file_inspect import render_plain_diff

        doc = dict(diff_doc)
        doc["version"] = target.name
        _atomic_write_json(staging / _DIFF_JSON, doc)
        if diff_text is None:
            diff_text = render_plain_diff(doc)
    if diff_text is not None:
        (staging / _DIFF_FILE).write_text(diff_text, encoding="utf-8")
    if record is not None:
        payload = dict(record)
        payload["version"] = target.name
        _atomic_write_json(staging / _RECORD_FILE, payload)
    staging.replace(target)
    return target


# -- the file set of a version (a database with its -wal / -journal) --------


def sha256_file(file: Path) -> str | None:
    """sha256 of a local file (``None`` if unreadable)."""
    digest = hashlib.sha256()
    try:
        with open(file, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def set_sha256(members: dict[str, str]) -> str:
    r"""One hash over a file set: sha256 of the sorted ``"<name> <sha256>\n"``
    lines (``sha256sum`` output order). Same set, same hash; any member
    changing, appearing or disappearing changes it.
    """
    lines = "".join(f"{name} {sha}\n" for name, sha in sorted(members.items()))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def local_members(directory: Path, basename: str) -> list[dict]:
    """The local copy of a version: main file + companions present, each as
    ``{"file", "role", "size", "sha256"}`` (``role``: main / -wal / -journal).
    """
    out: list[dict] = []
    for role in ("main", *SQLITE_COMPANIONS):
        name = basename if role == "main" else basename + role
        file = directory / name
        if not file.is_file():
            continue
        try:
            size = file.stat().st_size
        except OSError:
            size = None
        out.append(
            {"file": name, "role": role, "size": size, "sha256": sha256_file(file)}
        )
    return out


def record_set(record: dict | None, side: str) -> dict[str, str] | None:
    """``{file name: sha256}`` of a version's set as the record has it.

    ``side`` is ``"device"`` (on-device hashes taken before the pull) or
    ``"local"`` (the kept copy). From ``set.<side>`` of a schema-2 record,
    else rebuilt from the main + companion entries of an older one. ``None``
    when any member hash is unknown (no comparison possible).
    """
    if not record:
        return None
    file_set = record.get("set")
    if isinstance(file_set, dict) and isinstance(file_set.get(side), dict):
        members = file_set[side]
        if members and all(isinstance(v, str) and v for v in members.values()):
            return dict(members)
        return None
    main_local = record.get("local") or {}
    name = main_local.get("file") or os.path.basename(
        str(record.get("device_path") or "").rstrip("/")
    )
    entries = [(name, record.get(side) or {})]
    for companion in record.get("companions") or []:
        local = companion.get("local") or {}
        entries.append((local.get("file") or "", companion.get(side) or {}))
    out: dict[str, str] = {}
    for member, entry in entries:
        sha = entry.get("sha256") if isinstance(entry, dict) else None
        if not member or not sha:
            return None
        out[member] = sha
    return out or None


@dataclass
class KeptVersion:
    """What :func:`keep_version` kept: the folder, the diff against the
    version before (``None`` for the first one) and its plain text.
    """

    dir: Path
    diff: Any = None  # file_inspect.StructuredDiff | None
    text: str | None = None

    @property
    def changed(self) -> bool:
        return self.diff is not None and not self.diff.empty


def keep_version(
    path: str, record: dict | None = None, when: datetime | None = None
) -> KeptVersion:
    """Keep the staged pull (``.current/``) as the next version of ``path``.

    Diffs the staged main file against the newest version
    (:func:`sandroid.core.file_inspect.structured_diff`, folding pending
    ``-wal``/``-journal`` content into temporary copies) and writes
    ``diff.json`` (with the compared files and their sha256) and the plain
    ``diff.txt`` rendered from it, then :func:`promote`. The first version
    gets neither.
    """
    from sandroid.core import file_inspect

    staging = row_dir(path) / _STAGING
    basename = ((record or {}).get("local") or {}).get("file") or _main_name(path)
    when = when or datetime.now()
    dirs = version_dirs(path)
    if not dirs:
        return KeptVersion(promote(path, None, record, when=when))
    previous = dirs[-1]
    previous_main = version_file(previous, path)
    diff = file_inspect.structured_diff(previous_main, staging / basename)
    if diff.empty and not diff.error and not diff.note:
        diff.note = (
            "The bytes changed, but not the content (e.g. a SQLite WAL "
            "checkpoint or a page rewrite)."
        )
    doc = file_inspect.diff_document(
        diff,
        device_path=path,
        file=basename,
        version=next_version_name(path, when),
        base_version=previous.name,
        created_at=iso_tz(),
        compared={
            "base": local_members(previous, previous_main.name),
            "new": local_members(staging, basename),
        },
    )
    target = promote(path, None, record, when=when, diff_doc=doc)
    return KeptVersion(target, diff, version_diff(target))


def append_check(path: str, entry: dict) -> dict:
    """Append one "checked, no change" line to ``checks.jsonl`` of ``path``."""
    append_jsonl(row_dir(path) / _CHECKS_FILE, [entry])
    return entry


# -- session-wide logs: marks and the file-monitor timeline -----------------


def append_jsonl(file: Path, entries: list[dict]) -> None:
    """Append ``entries`` as JSON Lines (one write; never rewrites the file)."""
    if not entries:
        return
    text = "".join(
        json.dumps(e, ensure_ascii=False, default=str) + "\n" for e in entries
    )
    with _APPEND_LOCK:
        file.parent.mkdir(parents=True, exist_ok=True)
        with open(file, "a", encoding="utf-8") as handle:
            handle.write(text)


#: ``timeline.jsonl``: the last ``seq`` written, per file (continues an
#: existing file after a restart within the same session folder).
_TIMELINE_SEQ: dict[Path, int] = {}


def marks_file() -> Path:
    """``<session results>/marks.jsonl`` -- the session root, next to
    ``files/``: marks are the session's, not only the Files lens's.
    """
    return files_root().parent / MARKS_FILE


def timeline_file() -> Path:
    """``<session results>/files/timeline.jsonl``."""
    return files_root() / TIMELINE_FILE


def mark_entry(number: int, name: str, when: datetime) -> dict:
    """A mark as written to ``marks.jsonl`` and into acquisition records."""
    return {
        "number": number,
        "name": name or "",
        "at": iso_tz(when, "milliseconds"),
    }


def append_mark(number: int, name: str, when: datetime) -> dict:
    """Record a dropped mark in ``marks.jsonl``.

    One JSON object per line: ``number``, ``name`` (``""`` = unnamed), ``at``
    (when the mark was dropped) and ``recorded_at`` (when it was written),
    ISO 8601 with milliseconds and UTC offset. The format grows additively:
    readers (:func:`read_jsonl`) ignore fields they do not know.
    """
    entry = {
        **mark_entry(number, name, when),
        "recorded_at": iso_tz(None, "milliseconds"),
    }
    append_jsonl(marks_file(), [entry])
    return entry


def _last_seq(file: Path) -> int:
    """The highest ``seq`` already in ``file`` (0 if none)."""
    last = 0
    for item in read_jsonl(file):
        seq = item.get("seq")
        if isinstance(seq, int) and seq > last:
            last = seq
    return last


def append_timeline(entries: list[dict]) -> None:
    """Record file-monitor events in ``timeline.jsonl``.

    Each entry gets ``seq`` first: an integer that increases by one per
    event over the whole file (continued after a restart). Readers ignore
    fields they do not know, so the format can grow additively.
    """
    if not entries:
        return
    file = timeline_file()
    with _SEQ_LOCK:
        last = _TIMELINE_SEQ.get(file)
        if last is None:
            last = _last_seq(file)
        numbered = []
        for entry in entries:
            last += 1
            numbered.append({"seq": last, **entry})
        _TIMELINE_SEQ[file] = last
        append_jsonl(file, numbered)


# ---------------------------------------------------------------------------
# membership (per package, in the user config directory)
# ---------------------------------------------------------------------------


def _user_dir() -> Path:
    """Sandroid's per-user directory (``$XDG_CONFIG_HOME/sandroid`` or
    ``~/.config/sandroid``).
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sandroid"


def watchlist_dir() -> Path:
    """The membership directory (``<user dir>/watchlists/``, created)."""
    override = os.environ.get(WATCHLIST_DIR_ENV)
    directory = Path(override).expanduser() if override else _user_dir() / "watchlists"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def membership_file(owner: str) -> Path:
    """``<watchlists>/<package>.json`` (``_device.json`` outside app dirs)."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in owner)
    return watchlist_dir() / f"{safe.strip('.') or DEVICE_OWNER}.json"


def _atomic_write_json(path: Path, data) -> None:
    """Write ``data`` as JSON to ``path`` atomically (same-directory temp + replace)."""
    tmp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    tmp_path.replace(path)


def _membership_files() -> list[Path]:
    return sorted(
        p for p in watchlist_dir().glob("*.json") if not p.name.startswith(".")
    )


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"watchlist_store: {path.name} unreadable ({exc})")
        return {}
    return data if isinstance(data, dict) else {}


def save_membership(paths: list[str], patterns: list[str] | None = None) -> None:
    """Persist the ★ paths and patterns, one file per package.

    A package that no longer has any watch keeps its file with empty lists
    (nothing in the user's config directory is deleted behind their back).
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for kind, items in (("paths", paths), ("patterns", patterns or [])):
        for item in items:
            if not isinstance(item, str) or not item:
                continue
            owner, _rel = owner_and_relative(item)
            entry = grouped.setdefault(owner, {"paths": [], "patterns": []})
            if item not in entry[kind]:
                entry[kind].append(item)
    owners = set(grouped)
    for existing in _membership_files():
        owner = str(_read(existing).get("package") or existing.stem)
        if owner not in owners and existing == membership_file(owner):
            grouped[owner] = {"paths": [], "patterns": []}
    for owner, entry in grouped.items():
        _atomic_write_json(
            membership_file(owner),
            {
                "schema_version": SCHEMA_VERSION,
                "package": owner,
                "paths": entry["paths"],
                "patterns": entry["patterns"],
            },
        )


def _load(kind: str) -> list[str]:
    out: list[str] = []
    for path in _membership_files():
        items = _read(path).get(kind)
        if not isinstance(items, list):
            continue
        out.extend(i for i in items if isinstance(i, str) and i not in out)
    return out


def load_membership() -> list[str]:
    """Every persisted ★ path (all packages); ``[]`` when none/unreadable."""
    return _load("paths")


def load_patterns() -> list[str]:
    """Every persisted ★ wildcard pattern (all packages)."""
    return _load("patterns")


__all__ = [
    "DEVICE_OWNER",
    "FILES_DIR_ENV",
    "MARKS_FILE",
    "META_FILES",
    "SCHEMA_VERSION",
    "SQLITE_COMPANIONS",
    "TIMELINE_FILE",
    "WATCHLIST_DIR_ENV",
    "KeptVersion",
    "append_check",
    "append_jsonl",
    "append_mark",
    "append_timeline",
    "discard_current",
    "files_root",
    "has_baseline",
    "iso_tz",
    "keep_version",
    "load_membership",
    "load_patterns",
    "local_members",
    "local_naive",
    "mark_entry",
    "marks_file",
    "membership_file",
    "next_version_name",
    "owner_and_relative",
    "package_of",
    "previous_dir",
    "promote",
    "read_jsonl",
    "record_set",
    "reset_current",
    "row_dir",
    "save_membership",
    "session_results_dir",
    "set_sha256",
    "sha256_file",
    "timeline_file",
    "version_checks",
    "version_diff",
    "version_diff_doc",
    "version_dirs",
    "version_file",
    "version_record",
    "version_time",
    "watchlist_dir",
]
