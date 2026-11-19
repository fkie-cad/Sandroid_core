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
    from collections.abc import Callable, Iterable
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
DIFFERENT = "replay changed it differently"
UNCHANGED = "replay did not change it"
NO_REPLAY = "no replay yet"
#: ``pull`` outcome for a file that is not on the device.
ABSENT = "absent"

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


def _version_main(path: str, version: str | None) -> Path | None:
    from sandroid.core import watchlist_store

    if not version or version == ABSENT:
        return None
    folder = watchlist_store.row_dir(path) / version
    return watchlist_store.version_file(folder, path) if folder.is_dir() else None


def _diff_lines(path: str, old: str | None, new: str | None) -> tuple[list[str], str]:
    """Plain diff body lines from version ``old`` to ``new`` and a note."""
    from sandroid.core import file_inspect

    if old == new and old is not None:
        return [], "no change"
    if old in (None, ABSENT) and new in (None, ABSENT):
        return [], "not on the device"
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


def file_result(rec: Recording, path: str) -> FileResult:
    """Before → After and Before → After (replay) of one selected file."""
    before = rec.role_version(path, "before")
    after = rec.role_version(path, "after")
    replay = rec.role_version(path, "after_replay")
    res = FileResult(path, before, after, replay)
    try:
        run_lines, run_note = _diff_lines(path, before, after)
        res.action_text = "\n".join(run_lines) if run_lines else run_note
        if replay is None:
            res.verdict = NO_REPLAY
            return res
        rep_lines, rep_note = _diff_lines(path, before, replay)
        res.replay_text = "\n".join(rep_lines) if rep_lines else rep_note
        if replay == before or (not rep_lines and rep_note == "no change"):
            res.verdict = UNCHANGED
        elif (run_lines == rep_lines and run_note == rep_note) or after == replay:
            res.verdict = SAME
        else:
            res.verdict = DIFFERENT
            run_set, rep_set = set(run_lines), set(rep_lines)
            res.only_run = [ln for ln in run_lines if ln not in rep_set]
            res.only_replay = [ln for ln in rep_lines if ln not in run_set]
    except Exception as exc:  # a result view must never crash
        logger.debug("rewind: file result failed", exc_info=True)
        res.error = str(exc)
    return res


def result_lines(res: FileResult) -> list[str]:
    """The result of one file as plain lines (Sessions lens, AI, report)."""
    words = ROLE_WORDS
    out = ["What your action changed (Before → After):"]
    if res.before is None:
        out.append("  Before was not copied (no rewind yet).")
    out.extend(f"  {ln}" for ln in (res.action_text or "no change").splitlines())
    if res.after_replay is not None:
        out.append(f"What the replay changed (Before → {words['after_replay']}):")
        out.extend(f"  {ln}" for ln in (res.replay_text or "no change").splitlines())
        for ln in res.only_run:
            out.append(f"  only in your run: {ln}")
        for ln in res.only_replay:
            out.append(f"  only in the replay: {ln}")
    out.append(f"Result: {res.verdict}")
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


@dataclass
class RunOutcome:
    """What one Rewind / Rewind + Replay did."""

    n: int
    mode: str
    result: str = ""
    error: str | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    stopped_at_step: int | None = None
    seq: dict[str, int | None] = field(default_factory=dict)
    monitor_config: Any = None
    paused: list[int] = field(default_factory=list)


class RewindRunner:
    """Rewind (+ Replay) of one recording; call :meth:`run` on a worker."""

    def __init__(self, rec: Recording, deps: RewindDeps) -> None:
        self.rec = rec
        self.deps = deps

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
            raise RewindStoppedError("you pressed Esc")

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
        n = len(rec.runs) + 2  # run 1 is the original
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
        pids: list[int] = []
        try:
            if not name:
                raise RewindStoppedError(
                    "The start point is gone. Record again to rewind."
                )
            self._check()
            out.monitor_config = self.deps.stop_monitor()
            self.deps.progress("Going back to the start point")
            if not self.deps.load_snapshot(name, rec.serial):
                raise RewindStoppedError(
                    "Could not go back to the start point: the emulator refused "
                    "to load it. The device was not changed."
                )
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
            self._emit(
                "replay",
                f"{rec.rec_id}#{n}",
                kind="phase",
                summary=f"replaying the steps of {rec.name}",
                data={"rec_id": rec.rec_id, "run": n},
            )
            report = self.deps.replay(rec, self) or {}
            out.steps = list(report.get("steps") or [])
            out.stopped_at_step = report.get("stopped_at_step")
            self._emit(
                "setup",
                f"{rec.rec_id}#{n}",
                kind="phase",
                summary="saving After (replay)",
                data={"rec_id": rec.rec_id, "run": n},
            )
            errors = self.pull_role("after_replay", n)
            for path, err in errors.items():
                self.deps.progress(f"Could not copy {path}: {err}.")
            if report.get("error"):
                out.error = report["error"]
                out.result = "stopped"
            else:
                out.result = "replayed"
                self.deps.progress("Done. The device shows the replayed result.")
            return out
        except RewindStoppedError as exc:
            out.error = str(exc)
            out.result = "stopped"
            return out
        except Exception as exc:  # the worker must never die silently
            logger.exception("rewind failed")
            out.error = f"Rewind failed: {exc}"
            out.result = "stopped"
            return out
        finally:
            run = {
                "n": n,
                "kind": mode,
                "started": out.seq.get("start"),
                "ended": time.time(),
                "result": out.result or "stopped",
                "error": out.error,
                "stopped_at_step": out.stopped_at_step,
                "steps": out.steps,
            }
            rec.runs.append(run)
            summary = {
                "rewound": "rewind finished · the device is at the start point",
                "replayed": "replay finished",
            }.get(out.result)
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
                },
                ref={"of": out.seq["start"]} if out.seq.get("start") else None,
            )
            run["seq"] = dict(out.seq)
            with contextlib.suppress(Exception):
                save_recording(rec)
