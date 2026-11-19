"""Monitor Controller for TUI.

This controller manages Monitor filesystem monitoring operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop Monitor monitoring
- Configure monitoring paths and PIDs
- Process and display filesystem events
- Handle monitoring lifecycle
- Publish live events to the Files tab's Monitor sub-tab via the EventBus

Usage:
    from sandroid.tui.controllers import MonitorController

    controller = MonitorController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        call_from_thread=app.call_from_thread,
        force_ui_refresh=app._force_ui_refresh,
    )

    # Start Monitor monitoring
    controller.start_monitor()
"""

import logging
import re
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from rich.markup import escape

from sandroid.core.adb_utils import canonical_device_path
from sandroid.core.kprobe_tracer import (
    FMODE_CREATED,
    WriteScope,
    chain_names,
    guess_write_scope,
    parse_task_newtask,
    resolve_chain,
)

logger = logging.getLogger(__name__)


@dataclass
class MonitorConfig:
    """Configuration for Monitor monitoring."""

    mode: str = "path"  # "pid" or "path"
    target_path: str = "/data/"
    # Canonical multi-path list (kprobe-only; fsmon stays single-path). When
    # set, the invariant ``target_paths[0] == target_path`` holds -- ``target_path``
    # remains the PRIMARY/first path used by ``_resolve_prefix_candidates``,
    # MonitorView display, and the fsmon single-path launch. Empty by default,
    # in which case only ``target_path`` is consulted.
    target_paths: list[str] = field(default_factory=list)
    target_pid: int | None = None
    app_name: str = ""
    cancelled: bool = False
    # Which backend this session resolved to. Starts "auto", the internal
    # unresolved sentinel (the modal doesn't set it) -- it is NEVER persisted;
    # the on-disk config value is only ever "fsmon"/"kprobe". _start_monitor
    # rewrites it to the concrete backend it launched ("fsmon"/"kprobe"), and
    # it is threaded through every config rebuild (fanotify fallback + both
    # resume rebuilds) so resume doesn't reset the backend or re-run the
    # (expensive) kprobe preflight for a session that already fell back to fsmon.
    backend: str = "auto"
    # App mode ("pid") only: follow the APP rather than one PID -- every
    # process of the app (its UID, or named <pkg> / <pkg>:<sub>), seeded at
    # start and added as they start or restart (kprobe only; see
    # MonitorWatch). With it the session may start before the app runs
    # (target_pid None). Default from ``tui.monitor_follow_app`` via the
    # dialog; False keeps the old "this PID + its children" scope.
    follow: bool = False


# Regex to strip ANSI escape sequences and carriage returns from PTY output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\r")

#: Hard ceiling on ``MonitorController.get_recent_events``'s ``limit``,
#: regardless of what is requested -- mirrors ``ai/tools/flow_query.py``'s
#: ``_MAX_LIMIT`` hard-cap convention.
_MAX_RECENT_EVENTS_LIMIT = 2000

# Regex matching a package-scoped Android data directory prefix, e.g.
# "/data/data/com.example.app/" or "/data/user/0/com.example.app/".
_PKG_PATH_RE = re.compile(r"^(/data/(?:data|user/\d+)/[^/]+/)")


@dataclass(frozen=True)
class MonitorEvent:
    r"""A parsed monitor filesystem-event line.

    monitor's raw wire format is tab-separated:
    ``<FSE_EVENT_TYPE>\t<pid>\t"<process_name>"\t<path>``, or for renames:
    ``FSE_RENAME\t<pid>\t"<process_name>"\t<old_path> -> <new_path>``.
    """

    event_type: str
    pid: int | None
    process: str
    path: str
    new_path: str | None = None


@dataclass(frozen=True)
class MonitorEventMeta:
    """Display metadata for one ``FSE_*`` token."""

    label: str
    color: str
    category: str


# Exact-token lookup for monitor event metadata (fixes the old substring-keyword
# matching, which silently missed real tokens like FSE_CONTENT_MODIFIED and
# FSE_CLOSE). No icon glyphs -- plain colored uppercase labels only (explicit
# user feedback rejecting an earlier icon-based design).
MONITOR_EVENT_INFO: dict[str, MonitorEventMeta] = {
    "FSE_CREATE_FILE": MonitorEventMeta("CREATE", "#4ade80", "create"),
    "FSE_CREATE_DIR": MonitorEventMeta("CREATE DIR", "#4ade80", "create"),
    "FSE_CONTENT_MODIFIED": MonitorEventMeta("MODIFY", "#a78bfa", "modify"),
    "FSE_DELETE": MonitorEventMeta("DELETE", "#fb7185", "delete"),
    "FSE_RENAME": MonitorEventMeta("RENAME", "#facc15", "rename"),
    "FSE_STAT_CHANGED": MonitorEventMeta("ATTRS", "#7dd3fc", "attrs"),
    "FSE_ATTRIB": MonitorEventMeta("ATTRS", "#7dd3fc", "attrs"),
    "FSE_XATTR_MODIFIED": MonitorEventMeta("XATTR", "#7dd3fc", "attrs"),
    "FSE_OPEN": MonitorEventMeta("OPEN", "#5b6479", "noise"),
    "FSE_CLOSE": MonitorEventMeta("CLOSE", "#5b6479", "noise"),
    # kprobe: an O_CREAT open of a file that already existed (SQLite reopening
    # its db, a ">>" append) -- not a creation; its writes show as MODIFY.
    "FSE_OPEN_WRITE": MonitorEventMeta("OPEN W", "#5b6479", "noise"),
}


def parse_monitor_line(line: str) -> MonitorEvent | None:
    """Tokenize one raw monitor output line into an :class:`MonitorEvent`.

    Defensive by design: a future monitor version drifting slightly in its
    wire format must degrade gracefully (return ``None``) rather than crash
    the reader thread.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.

    Returns:
        The parsed event, or ``None`` if the line doesn't look like a valid
        monitor event line.
    """
    try:
        parts = line.split("\t")
        if len(parts) < 4:
            return None

        event_type = parts[0].strip()
        pid_str = parts[1].strip()
        process = parts[2].strip().strip('"')
        rest = "\t".join(parts[3:]).strip()

        pid: int | None
        try:
            pid = int(pid_str)
        except ValueError:
            pid = None

        new_path: str | None = None
        if event_type == "FSE_RENAME" and " -> " in rest:
            old_path, new_path = rest.split(" -> ", 1)
            path = old_path.strip()
            new_path = new_path.strip()
        else:
            path = rest

        if not event_type or not path:
            return None

        return MonitorEvent(
            event_type=event_type,
            pid=pid,
            process=process,
            path=path,
            new_path=new_path,
        )
    except Exception:
        return None


def colorize_monitor_line(line: str, max_width: int = 0) -> str:
    """Apply color markup to an monitor output line.

    Escapes raw content first to prevent Rich markup interpretation,
    then wraps in color tags based on the parsed event's exact ``FSE_*``
    token (via :func:`parse_monitor_line`/``MONITOR_EVENT_INFO``).

    Args:
        line: Raw monitor output line.
        max_width: Truncate to this width before escaping. 0 means no truncation.

    Returns:
        Escaped and optionally colorized Rich markup string.
    """
    truncated = line[:max_width] if max_width > 0 else line
    escaped = escape(truncated)
    event = parse_monitor_line(line)
    if event is not None:
        meta = MONITOR_EVENT_INFO.get(event.event_type)
        if meta is not None:
            return f"[{meta.color}]{escaped}[/{meta.color}]"
    return escaped


def _resolve_prefix_candidates(config: Any) -> tuple[str, ...]:
    """Build redundant-path-prefix candidates from an ``MonitorConfig``-like object.

    Used to strip a redundant ``/data/data/<pkg>/`` or ``/data/user/0/<pkg>/``
    prefix from displayed paths in Monitor's compact row -- computed once per
    batch flush (not per line).

    Args:
        config: An ``MonitorConfig`` (or duck-typed equivalent) with optional
            ``app_name``/``target_path`` attributes.

    Returns:
        A tuple of candidate prefixes (longest-match stripping is done by the
        caller).
    """
    candidates: list[str] = []
    if config is None:
        return ()

    app_name = getattr(config, "app_name", None)
    if app_name:
        candidates.append(f"/data/data/{app_name}/")
        candidates.append(f"/data/user/0/{app_name}/")

    target_path = getattr(config, "target_path", None)
    if target_path:
        match = _PKG_PATH_RE.match(target_path)
        if match:
            candidates.append(match.group(1))

    return tuple(candidates)


def _strip_prefix(path: str, prefix_candidates: tuple[str, ...]) -> str:
    """Strip the longest matching redundant path prefix (strip-only step).

    Split out of the old ``_display_path`` (which coupled prefix-stripping
    with truncate-keep-tail) so the strip step can be reused standalone --
    the grouped view's directory/filename split and the full-path view's
    untruncated display both need prefix-stripped (but NOT truncated)
    paths; ``_display_path`` below now just layers truncation on top of
    this.
    """
    best = ""
    for prefix in prefix_candidates:
        if path.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    return path[len(best) :] if best else path


def _display_path(
    path: str, prefix_candidates: tuple[str, ...], width: int = 36
) -> str:
    """Strip the longest matching prefix, then left-truncate keeping the tail.

    Mirrors the truncate-keep-tail idiom in ``tui/widgets/watchlist_view.py``
    (``_row_label``), since the filename/extension is the distinguishing part
    of long Android cache/data paths.
    """
    display = _strip_prefix(path, prefix_candidates)

    if len(display) > width:
        display = "…" + display[-(width - 1) :]
    return display


def _split_dir_filename(path: str) -> tuple[str, str]:
    """Split an already prefix-stripped path into ``(directory, filename)``.

    Used by :func:`build_monitor_item` for MonitorView's own
    grouping/breadcrumb pass (Part B) -- the view groups consecutive items
    by exact ``directory`` match and renders a ``▸ <directory>/`` breadcrumb
    for runs of 2+. ``directory`` has no trailing slash (the view adds its
    own when rendering the breadcrumb); a bare filename with no ``/`` at
    all yields an empty directory string (never groups into a breadcrumb
    run with anything else, which is correct -- it has no directory to
    share).
    """
    if "/" in path:
        directory, _, filename = path.rpartition("/")
        return directory, filename
    return "", path


def format_monitor_event_row(
    line: str, prefix_candidates: tuple[str, ...] = ()
) -> tuple[str, str | None]:
    """Format one raw monitor line into Monitor's compact row.

    Format: ``HH:MM:SS  [color]LABEL[/]  <path>`` (renames show
    ``old -> new``, a plain ASCII arrow matching monitor's own raw format).
    Unparseable lines or tokens missing from ``MONITOR_EVENT_INFO`` still
    produce a row (falling back to a plain, uncolored line) -- a line is
    never silently dropped.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.
        prefix_candidates: Redundant path prefixes to strip before display
            (see :func:`_resolve_prefix_candidates`).

    Returns:
        A ``(rich_markup_row, category)`` tuple. ``category`` is ``None`` if
        the line is unparseable or its token is unknown.
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    event = parse_monitor_line(line)

    if event is None:
        return f"{timestamp}  {escape(line)}", None

    meta = MONITOR_EVENT_INFO.get(event.event_type)

    if event.new_path is not None:
        old_display = _display_path(event.path, prefix_candidates)
        new_display = _display_path(event.new_path, prefix_candidates)
        path_display = f"{old_display} -> {new_display}"
    else:
        path_display = _display_path(event.path, prefix_candidates)

    escaped_path = escape(path_display)

    if meta is None:
        label = event.event_type
        return f"{timestamp}  {escape(label):<10}  {escaped_path}", None

    label = f"{meta.label:<10}"
    return f"{timestamp}  [{meta.color}]{label}[/]  {escaped_path}", meta.category


@dataclass(frozen=True)
class MonitorItem:
    """Backend-neutral base for one parsed monitor event.

    A typed hierarchy so future non-filesystem items (e.g. network) can share
    MonitorView's rendering pipeline. ``kind`` names the item family and
    ``source`` records which backend produced it (``"fsmon"`` | ``"kprobe"``);
    both carry defaults so builders/subclasses only set what they need.
    """

    label: str
    color: str | None
    category: str | None
    kind: str = "filesystem"
    source: str = "fsmon"


@dataclass(frozen=True)
class FileSystemMonitorItem(MonitorItem):
    """One parsed+categorized monitor line, structured for MonitorView's own
    grouping/dedup/visibility-filtering/tallying/width-aware rendering
    pipeline (Part B of the monitor follow-up plan).

    NOT a final rendered string -- see B1's "Defect 1"/"Defect 2" for why:
    grouping, dedup, visibility filtering, tallying, and width-aware
    formatting all need to live in ``MonitorView`` (the only place with a
    real widget reference and the "always tally, conditionally render"
    invariant the header/badge depend on), so the controller hands over
    parsed, prefix-stripped, directory/filename-split data instead of a
    finished row.

    ``directory``/``filename`` are prefix-stripped (see ``_strip_prefix``)
    but deliberately NOT truncated -- MonitorView decides truncation width
    itself (from its own RichLog's rendered content width) and whether to
    truncate at all (the 'u' full-path toggle bypasses truncation
    entirely).

    For a plain create/modify/delete/attrs event, only ``directory``/
    ``filename`` are set. For ``FSE_RENAME``, ``new_directory``/
    ``new_filename`` are also set (the new path, same prefix-stripping
    treatment) -- ``directory``/``filename`` describe the OLD path, which
    is what determines whether the rename joins the current directory-run
    (a rename groups based on where it originated).
    """

    directory: str = ""
    filename: str = ""
    new_directory: str | None = None
    new_filename: str | None = None
    #: The process (fsmon) / kernel ``comm`` (kprobe) behind the event, and
    #: the full on-device paths before prefix stripping -- the Files lens
    #: keys rows and the watchlist by them. Excluded from equality so the
    #: display identity above stays what it was.
    process: str = field(default="", compare=False)
    path: str = field(default="", compare=False)
    new_path: str | None = field(default=None, compare=False)
    #: When the reader thread captured the line (``time.time()``, the value
    #: ``recent_events`` uses) and the writing process's PID (fsmon: as
    #: reported; kprobe: the thread's TGID -- from the trace line, else the
    #: follow table -- and only when neither knows it the thread id). None
    #: when unknown.
    timestamp: float | None = field(default=None, compare=False)
    pid: int | None = field(default=None, compare=False)
    #: The writing thread's id (kprobe; None for fsmon).
    tid: int | None = field(default=None, compare=False)


def build_monitor_item(
    line: str,
    prefix_candidates: tuple[str, ...] = (),
    timestamp: float | None = None,
) -> FileSystemMonitorItem:
    """Parse+categorize one raw monitor line into a structured display item.

    Supersedes ``format_monitor_event_row`` for production wiring (Part B):
    grouping/dedup/tallying/width-aware truncation all now live in
    MonitorView, so the controller only needs to hand over parsed,
    prefix-stripped, directory/filename-split data -- not a final Rich
    markup string. ``format_monitor_event_row`` itself is left unchanged
    (still directly exercised by tests and available as a standalone
    formatter), it's simply no longer called by ``_log_monitor_output_batch``.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.
        prefix_candidates: Redundant path prefixes to strip before display
            (see :func:`_resolve_prefix_candidates`).

    Returns:
        A structured :class:`FileSystemMonitorItem`. Malformed/unparseable
        input never raises and is never silently dropped -- it becomes an
        item with the raw line as its ``filename`` (no directory to
        derive), matching ``format_monitor_event_row``'s own "never drop a
        line" contract.
    """
    event = parse_monitor_line(line)

    if event is None:
        return FileSystemMonitorItem(
            label="",
            color=None,
            category=None,
            directory="",
            filename=line,
            timestamp=timestamp,
        )

    meta = MONITOR_EVENT_INFO.get(event.event_type)
    label = meta.label if meta is not None else event.event_type
    color = meta.color if meta is not None else None
    category = meta.category if meta is not None else None

    directory, filename = _split_dir_filename(
        _strip_prefix(event.path, prefix_candidates)
    )

    new_directory: str | None = None
    new_filename: str | None = None
    if event.new_path is not None:
        new_directory, new_filename = _split_dir_filename(
            _strip_prefix(event.new_path, prefix_candidates)
        )

    # Rows/watches are keyed by ONE form of each path (/data/user/0/<pkg>
    # is /data/data/<pkg>; no trailing slash).
    return FileSystemMonitorItem(
        label=label,
        color=color,
        category=category,
        directory=directory,
        filename=filename,
        new_directory=new_directory,
        new_filename=new_filename,
        process=event.process,
        timestamp=timestamp,
        pid=event.pid,
        path=canonical_device_path(event.path),
        new_path=(
            canonical_device_path(event.new_path)
            if event.new_path is not None
            else None
        ),
    )


# Maps each kprobe trace event name to the ``FSE_*`` token whose
# MONITOR_EVENT_INFO metadata (label/color/category) it should reuse, so
# kprobe rows render identically to fsmon rows. ``dfo``/``dfor``/``fput`` are
# correlation-only (no emitted row). ``openat2`` splits at translate time
# (O_CREAT vs plain open).
_KPROBE_EVENT_TO_FSE: dict[str, str] = {
    "mkdir": "FSE_CREATE_DIR",
    "unlink": "FSE_DELETE",
    "rmdir": "FSE_DELETE",
    "rename": "FSE_RENAME",
    "vw": "FSE_CONTENT_MODIFIED",
    "diw": "FSE_CONTENT_MODIFIED",
    "nc": "FSE_STAT_CHANGED",
    "sx": "FSE_XATTR_MODIFIED",
}

# One ftrace ``trace_pipe`` line, e.g.::
#
#   <...>-1234  [000] ...1 12345.678901: openat2: (do_sys_openat2+0x0/0x..) fname="/x" flags=0x241
#
# With the instance's ``record-tgid`` option the thread id is followed by
# the process id, ``(   1200)``, or ``(-------)`` while the kernel doesn't
# know it yet. The ``.*?`` after ``[cpu]`` non-greedily absorbs the
# (kernel-version-varying) latency-flags column(s) up to the timestamp.
_KPROBE_HEADER_RE = re.compile(
    r"^\s*(?P<comm>.+?)-(?P<tid>\d+)\s+(?:\(\s*(?P<tgid>\d+|-+)\)\s+)?"
    r"\[\d+\]\s+.*?\s+[\d.]+:\s+"
    r"(?P<event>\w+):\s+(?P<rest>.*)$"
)

# ``field=value`` pairs; a value is either a double-quoted string (``:string``/
# ``:ustring`` args) or a bare token (``:x64``/``:u64`` hex/decimal). The
# leading ``(symbol+0x../0x..)`` has no ``=`` and is skipped.
_KPROBE_FIELD_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

# O_CREAT bit in openat2 flags (create vs plain open); O_TRUNC truncates an
# existing file (a content change).
_O_CREAT = 0x40
_O_TRUNC = 0x200

#: comm prefixes of Sandroid's own device-side helpers: adbd names its
#: file-sync threads "sync svc <n>" (every ``adb pull`` of a watched file).
_SELF_COMMS = ("sync svc",)


# Kernel ERR_PTR range: the top 4 KiB (MAX_ERRNO) of the 64-bit address space.
# do_filp_open returns an ERR_PTR (e.g. -ENOENT) on a FAILED open, and its
# r:dfor return probe reports that value as the "file*". Storing it in the
# file* map would leak an entry that no __fput ever invalidates, so the
# translator skips any file* at/above this threshold.
_ERR_PTR_MIN = 0xFFFFFFFFFFFFF000


def _is_err_ptr(file_ptr: str) -> bool:
    """True if a ``file*`` hex string falls in the kernel ERR_PTR range."""
    try:
        return int(file_ptr, 16) >= _ERR_PTR_MIN
    except (ValueError, TypeError):
        return False


def _parse_kprobe_fields(rest: str) -> dict[str, str]:
    """Extract ``field=value`` pairs from a trace line's payload."""
    fields: dict[str, str] = {}
    for key, value in _KPROBE_FIELD_RE.findall(rest):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        fields[key] = value
    return fields


class KprobeStreamTranslator:
    """Correlate a raw kprobe ``trace_pipe`` stream into FileSystemMonitorItems.

    ONE long-lived instance per monitor session (stored on the
    MonitorProcessWrapper, reset on each start). It MUST run in the reader
    thread AHEAD of the ``deque(maxlen=...)`` ring buffer: a dropped
    ``do_filp_open``-return or ``__fput`` line would corrupt the
    ``file* -> (path, tgid)`` map and defeat ``__fput`` invalidation, so the
    ring buffer must never sit between the raw stream and this correlator.

    Correlation:
      * ``dfo`` (do_filp_open entry)  -> ``pending[tid] = path``
      * ``dfor`` (do_filp_open return)-> ``filemap[file] = (pending.pop(tid), tid)``;
        its ``mode`` (``f_mode``) decides a pending ``O_CREAT`` open:
        ``FMODE_CREATED`` -> CREATE, else OPEN W (or MODIFY with ``O_TRUNC``)
      * ``fput`` (__fput)             -> ``del filemap[file]`` (MANDATORY: file*
        values are reused by the kernel, so without this a later write to a
        recycled ``file*`` would be mis-attributed to the old path)
      * ``vw`` / ``diw`` (writes)     -> the path from the line's dentry chain
        (``n0``..``n7`` + ``dev``, see ``kprobe_tracer.resolve_chain``) --
        the kernel's own name for the file at write time, so it also names
        files opened BEFORE the monitor started and is preferred over the
        open-time map (which goes stale if a ``__fput`` line is lost);
        ``filemap[file]`` names what the chain can't (too deep)
      * ``mkdir`` + ``mkdirr``        -> CREATE DIR only when do_mkdirat
        returned 0 (``mkdir -p`` on an existing directory is ``-EEXIST``)

    Reuses ``_strip_prefix`` / ``_split_dir_filename`` and MONITOR_EVENT_INFO
    for display parity with fsmon. Emits ``FileSystemMonitorItem(source=
    "kprobe")``. MonitorView is unchanged.

    PATH-MODE WRITE-FIREHOSE LIMITATION: in pure path mode the write path
    (vfs_write/do_iter_write) is only filtered in-kernel by the targets'
    filesystem and directory name (when the write scope resolved), and the
    do_filp_open-return/__fput correlation lines fire system-wide. Under
    heavy system write load the KERNEL ring buffer can drop the sparse
    ``dfor``/``fput`` control lines *before* this correlator ever sees them --
    that loss is upstream of the reader-thread deque, so the
    translate-ahead-of-deque design here cannot recover it. Writes still
    carry their own name (the chain); the 64 MB/CPU buffer mitigates the
    rest, and when a target PID is known ``KprobeTracer.run_by_pid(pid,
    path)`` bounds the firehose via ``set_event_pid`` and is strongly
    preferred over pure path mode.
    """

    def __init__(self) -> None:
        self.reset(None)

    def reset(self, config: Any) -> None:
        """Clear all correlation state and recompute path-prefix candidates.

        Called on each session start. ``config`` (an ``MonitorConfig`` or
        None) drives the redundant-prefix stripping so kprobe paths display
        exactly like fsmon paths, and gives the targets that write chains
        are matched against (until :meth:`set_write_scope` provides the
        device's view).
        """
        self._pending: dict[int, str] = {}
        self._filemap: dict[str, tuple[str, int]] = {}
        self._prefix = _resolve_prefix_candidates(config) if config is not None else ()
        self._comm = ""  # comm of the trace line being translated (see _feed)
        #: tid -> (path, flags) of an O_CREAT open waiting for its dfor.
        self._pending_create: dict[int, tuple[str, int]] = {}
        #: tid -> path of a mkdir waiting for its result (mkdirr).
        self._pending_mkdir: dict[int, str] = {}
        #: basename -> the full path last seen with it (fallback for attr
        #: lines without a usable dentry chain; see _resolve_basename).
        self._by_name: dict[str, str] = {}
        #: tid -> comm seen on an earlier line (ftrace prints "<...>" once a
        #: tid falls out of its comm cache).
        self._tid_comm: dict[int, str] = {}
        #: In PID scoping every event comes from the app's process tree, so
        #: an unresolvable comm is attributed to the app.
        pid_scoped = config is not None and (
            bool(getattr(config, "target_pid", None))
            or (
                getattr(config, "follow", False)
                and getattr(config, "mode", "") == "pid"
            )
        )
        self._scoped_app = (getattr(config, "app_name", "") or "") if pid_scoped else ""
        targets: list[str] = []
        if config is not None:
            targets = list(getattr(config, "target_paths", None) or [])
            if not targets and getattr(config, "target_path", ""):
                targets = [config.target_path]
        #: What dentry chains are matched against (a guess from the targets'
        #: path components until the session's resolved scope arrives).
        self._scope: WriteScope | None = guess_write_scope(targets) if targets else None
        #: tid -> the app process it belongs to ("main", "tab_17", ...), from
        #: the session's MonitorWatch (None: no app scope).
        self._labels: Callable[[int], str | None] | None = None
        self._owner: Callable[[int], int | None] | None = None
        #: The line being translated: its thread, and its process (TGID;
        #: None when neither the line nor the follow table knows it).
        self._tid: int | None = None
        self._pid: int | None = None
        #: tid -> TGID seen on an earlier line (a later one may print
        #: "(-------)" until the kernel's pid->tgid map has it).
        self._tgid: dict[int, int] = {}
        #: The session's MonitorWatch (set by ``_kprobe_setup``).
        self.watch: Any = None

    def set_process_labels(
        self,
        labels: Callable[[int], str | None] | None,
        owner: Callable[[int], int | None] | None = None,
    ) -> None:
        """Prefix each event's thread name with its app process's label.

        ``labels`` maps a process (or thread) id to the app process's label;
        ``owner`` maps a thread id to its process id, used when the trace
        line carries no TGID.
        """
        self._labels = labels
        self._owner = owner

    def set_write_scope(self, scope: WriteScope | None) -> None:
        """Use the device's view of the targets (mounts + real paths)."""
        if scope is not None and scope.targets:
            self._scope = scope

    def _note(self, path: str) -> None:
        if path.startswith("/"):
            self._by_name[path.rsplit("/", 1)[-1]] = path

    def _resolve_basename(self, name: str) -> str | None:
        """Full path for a dentry basename (attr probes), or None.

        Only for attr lines whose dentry chain names nothing under the
        targets: the basename is mapped to the most recent full path seen
        with it this session; an unknown basename is dropped rather than
        shown as an orphan row.
        """
        if name.startswith("/"):
            return name
        return self._by_name.get(name.rsplit("/", 1)[-1])

    def _chain_path(self, fields: dict[str, str]) -> str | None:
        """The watched path a line's dentry chain names (None: not one)."""
        names = chain_names(fields)
        if names is None:
            return None
        dev_raw = fields.get("dev")
        dev = int(dev_raw) if dev_raw and dev_raw.isdigit() else None
        return resolve_chain(names, dev, self._scope)

    def _process(self, tid: int, comm: str) -> str:
        if comm and comm != "<...>":
            self._tid_comm[tid] = comm
            return comm
        known = self._tid_comm.get(tid)
        if known:
            return known
        return self._scoped_app or f"tid {tid}"

    def _resolve_tgid(self, tid: int, raw: str | None) -> int | None:
        """The process (TGID) of thread ``tid``: the line's own ``(tgid)``,
        else the follow table, else a TGID an earlier line of it carried.
        """
        if raw and raw.isdigit() and int(raw) > 0:
            tgid = int(raw)
            self._tgid[tid] = tgid
            return tgid
        owner = self._owner(tid) if self._owner is not None else None
        if owner:
            return owner
        return self._tgid.get(tid)

    def _process_name(self) -> str:
        """``"<process> · <thread>"`` in app scope (``"main · Cache2 I/O"``).

        The process part is the watch's label for the event's TGID, or
        ``pid N`` for a process the watch has no name for yet; the same
        label for every event of the process, whichever probe reported it.
        """
        comm = self._comm
        if self._labels is None:
            return comm
        pid, tid = self._pid, self._tid
        label = self._labels(pid if pid is not None else tid)
        if label:
            return f"{label} · {comm}"
        if pid is not None:
            return f"pid {pid} · {comm}"
        return comm

    def _item(
        self, fse_token: str, path: str, new_path: str | None = None
    ) -> FileSystemMonitorItem:
        path = canonical_device_path(path)
        if new_path is not None:
            new_path = canonical_device_path(new_path)
        meta = MONITOR_EVENT_INFO.get(fse_token)
        label = meta.label if meta is not None else fse_token
        color = meta.color if meta is not None else None
        category = meta.category if meta is not None else None
        directory, filename = _split_dir_filename(_strip_prefix(path, self._prefix))
        new_directory: str | None = None
        new_filename: str | None = None
        if new_path is not None:
            new_directory, new_filename = _split_dir_filename(
                _strip_prefix(new_path, self._prefix)
            )
        return FileSystemMonitorItem(
            label=label,
            color=color,
            category=category,
            source="kprobe",
            directory=directory,
            filename=filename,
            new_directory=new_directory,
            new_filename=new_filename,
            process=self._process_name(),
            pid=self._pid if self._pid is not None else self._tid,
            tid=self._tid,
            path=path,
            new_path=new_path,
        )

    def feed(self, line: str) -> list[FileSystemMonitorItem]:
        """Consume one raw trace_pipe line, returning 0+ display items.

        Never raises -- a line that doesn't parse yields ``[]`` so the reader
        thread degrades gracefully instead of dying.
        """
        try:
            return self._feed(line)
        except Exception:
            logger.debug("KprobeStreamTranslator failed on a line", exc_info=True)
            return []

    def _open_result(self, tid: int, fields: dict[str, str]) -> list:
        """Decide a pending O_CREAT open of ``tid`` from its dfor line."""
        pending = self._pending_create.pop(tid, None)
        if pending is None:
            return []
        path, flags = pending
        file_ptr = fields.get("file")
        if not file_ptr or _is_err_ptr(file_ptr):
            return []  # the open failed: nothing was created or opened
        mode_raw = fields.get("mode")
        try:
            mode = int(mode_raw, 16) if mode_raw is not None else None
        except ValueError:
            mode = None
        if mode is None or mode & FMODE_CREATED:
            return [self._item("FSE_CREATE_FILE", path)]
        # O_CREAT on an existing file: SQLite reopening its db, a ">>" append.
        token = "FSE_CONTENT_MODIFIED" if flags & _O_TRUNC else "FSE_OPEN_WRITE"
        return [self._item(token, path)]

    def _feed(self, line: str) -> list[FileSystemMonitorItem]:
        m = _KPROBE_HEADER_RE.match(line)
        if m is None:
            return []
        tid = int(m.group("tid"))
        self._tid = tid
        self._pid = self._resolve_tgid(tid, m.group("tgid"))
        self._comm = self._process(tid, m.group("comm").strip())
        event = m.group("event")
        if event == "task_newtask":
            # The creator's line names the new task before it runs: a thread
            # (CLONE_THREAD) belongs to the creator's process, anything else
            # is a process of its own. The new thread's first lines print
            # "(-------)" (the kernel's pid->tgid map has it only after its
            # first context switch) and were recorded as pid = TID.
            new = parse_task_newtask(m.group("rest"))
            if new is not None:
                child, is_thread = new
                owner = self._pid if is_thread else child
                if owner:
                    self._tgid[child] = owner
            return []
        fields = _parse_kprobe_fields(m.group("rest"))
        if self._comm.startswith(_SELF_COMMS) and event not in ("dfor", "fput"):
            # adbd's file-sync service: Sandroid's own pulls (and stat polls
            # via adb). Never app activity. dfor/fput still run so the file*
            # map stays consistent.
            if event == "dfo":
                self._pending.pop(tid, None)
            return []

        # --- correlation-only events (never emit a row directly) ---
        if event == "dfo":
            path = fields.get("path")
            if path:
                self._pending[tid] = path
            return []
        if event == "dfor":
            file_ptr = fields.get("file")
            path = self._pending.pop(tid, None)
            # Skip ERR_PTR returns (failed open): they have no matching __fput,
            # so storing them would leak file* map entries. pending is still
            # popped above -- the open attempt is over either way.
            if file_ptr and path is not None and not _is_err_ptr(file_ptr):
                self._filemap[file_ptr] = (path, tid)
            return self._open_result(tid, fields)
        if event == "fput":
            file_ptr = fields.get("file")
            if file_ptr:
                self._filemap.pop(file_ptr, None)
            return []

        # --- write events: the dentry chain, else the file* map ---
        if event in ("vw", "diw"):
            path = self._chain_path(fields)
            if path is None:
                file_ptr = fields.get("file")
                entry = self._filemap.get(file_ptr) if file_ptr else None
                if entry is None:
                    # Not under a target (a socket, pipe, another app's
                    # file), or deeper than the chain reaches and opened
                    # before the monitor started (or a dropped control line).
                    return []
                path = canonical_device_path(entry[0])
            self._note(path)
            return [self._item("FSE_CONTENT_MODIFIED", path)]

        # --- openat2: OPEN (noise); an O_CREAT open waits for its dfor ---
        if event == "openat2":
            fname = fields.get("fname")
            if not fname:
                return []
            flags_raw = fields.get("flags", "0")
            try:
                flags = (
                    int(flags_raw, 16) if flags_raw.startswith("0x") else int(flags_raw)
                )
            except ValueError:
                flags = 0
            path = canonical_device_path(fname)
            self._note(path)
            if not flags & _O_CREAT:
                return [self._item("FSE_OPEN", path)]
            # O_CREAT means "create if missing": SQLite reopening its db and
            # every ">>" append pass it too. do_filp_open's result says which.
            self._pending_create[tid] = (path, flags)
            return []

        # --- mkdir: a creation only if do_mkdirat succeeded ---
        if event == "mkdir":
            name = fields.get("name")
            if name:
                self._pending_mkdir[tid] = canonical_device_path(name)
            return []
        if event == "mkdirr":
            path = self._pending_mkdir.pop(tid, None)
            if path is None or fields.get("ret") != "0":
                return []  # -EEXIST (mkdir -p) or another failure
            self._note(path)
            return [self._item("FSE_CREATE_DIR", path)]

        # --- rename: old + new path ---
        if event == "rename":
            frm = fields.get("from")
            if not frm:
                return []
            frm = canonical_device_path(frm)
            to = fields.get("to")
            if to:
                to = canonical_device_path(to)
                self._note(to)
            return [self._item("FSE_RENAME", frm, new_path=to)]

        # --- direct metadata / attrs events ---
        token = _KPROBE_EVENT_TO_FSE.get(event)
        if token is None:
            return []
        value = fields.get("name") or fields.get("dentry")
        if not value:
            return []
        if event in ("nc", "sx"):
            # The dentry chain names the file. Without a complete chain (none,
            # or deeper than eight names) the basename seen earlier this
            # session is used; anything else is dropped.
            names = chain_names(fields)
            resolved = self._chain_path(fields)
            if resolved is None and (
                names is None or "/" not in names or self._scope is None
            ):
                resolved = self._resolve_basename(value)
            if resolved is None:
                return []
            self._note(resolved)
            return [self._item(token, resolved)]
        return [self._item(token, canonical_device_path(value))]


def _publish_monitor_batch(items: list[FileSystemMonitorItem]) -> None:
    """Publish a WHOLE BATCH of parsed monitor items as a single EventBus event.

    Supersedes the old per-line ``_publish_monitor_event`` (Part B, see B1):
    one call per BATCH, not one per line -- ``MonitorView`` needs the
    batch's items in order (with a real widget reference) to run its own
    grouping/dedup/visibility-filtering/tallying/width-aware rendering
    pass, none of which can happen here anymore. Mirrors
    ``analysis/fritap.py``'s ``_publish_fritap_event`` for the EventBus
    idiom itself (lazy import, ``source="monitor"``, silently-logged
    failure).

    Args:
        items: The batch's parsed items, in the original line order.
            A no-op on an empty list (nothing to publish).
    """
    if not items:
        return
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "Monitor", "batch": items},
                source="monitor",
            )
        )
    except Exception:
        logger.debug("Failed to publish monitor EventBus event", exc_info=True)


def _publish_monitor_info(data: dict[str, Any]) -> None:
    """Publish a monitor note/status change (the Files lens listens)."""
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "Monitor", **data},
                source="monitor",
            )
        )
    except Exception:
        logger.debug("Failed to publish monitor info", exc_info=True)


_NOTE_LEVELS = {"warning": "warn", "error": "error"}


def _timeline_monitor(
    kind: str,
    summary: str,
    *,
    level: str = "info",
    when: datetime | float | None = None,
    data: dict[str, Any] | None = None,
    dev: str | None = None,
    pkg: str | None = None,
    t_err_ms: float | None = None,
) -> None:
    """A ``monitor/<kind>`` session-timeline line (any thread; never raises)."""
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().emit(
            "monitor",
            kind,
            summary=summary,
            data=data,
            t=when,
            t_err_ms=t_err_ms,
            dev=dev,
            pkg=pkg or None,
            level=_NOTE_LEVELS.get(
                level, level if level in ("info", "warn") else "info"
            ),
        )
    except Exception:
        logger.debug("timeline: monitor line failed", exc_info=True)


def _timeline_serial() -> str | None:
    """The adb target now (the device a monitor session records)."""
    try:
        from sandroid.core.adb import Adb

        serial = Adb.get_target_device()
    except Exception:
        return None
    return serial if isinstance(serial, str) and serial else None


def _item_path(item: Any) -> str:
    directory = getattr(item, "directory", "")
    filename = getattr(item, "filename", "")
    return f"{directory}/{filename}" if directory else filename


def _timeline_file_event(wrapper: Any) -> Callable[..., None]:
    """The reader thread's session-timeline sink for one monitor session:
    ``(op, path, t, backend, new_path, process, pid, tid)`` ->
    :meth:`TimelineService.file_event` with the session's device, app and
    followed pids. Never raises, never blocks.
    """
    try:
        from sandroid.core.timeline import get_timeline

        service = get_timeline()
    except Exception:
        return lambda *args: None
    serial = getattr(wrapper, "timeline_serial", None)
    watch = getattr(wrapper, "watch", None)
    config = getattr(wrapper, "config", None)
    package = getattr(watch, "package", None)
    if package is None and getattr(config, "mode", "") == "pid":
        package = getattr(config, "app_name", "") or None
    # The followed app processes (a live dict: membership tests only), else
    # the session's target PID.
    pids = getattr(watch, "procs", None)
    if pids is None:
        target = getattr(config, "target_pid", None)
        pids = frozenset({target}) if isinstance(target, int) else frozenset()

    def file_event(op, path, t, backend, new_path, process, pid, tid) -> None:
        try:
            service.file_event(
                op=op,
                path=path,
                t=t,
                backend=backend,
                new_path=new_path,
                process=process or None,
                pid=pid,
                tid=tid,
                dev=serial,
                app_pkg=package or None,
                app_pids=pids,
            )
        except Exception:
            logger.debug("timeline: file event failed", exc_info=True)

    return file_event


def _recent_event_from_monitor_event(
    event: MonitorEvent, source: str, timestamp: float | None = None
) -> dict[str, Any]:
    """Build one ``MonitorProcessWrapper.recent_events`` entry from a raw fsmon event.

    Unlike kprobe's already-correlated items (see
    :func:`_recent_event_from_item`), fsmon's raw ``MonitorEvent`` still
    carries the FULL, un-prefix-stripped on-device path -- kept as-is here
    (not run through ``build_monitor_item``'s prefix stripping) since a full
    absolute path is more useful to the AI chat's ``get_file_diff`` tool than
    the display-truncated form MonitorView shows.

    Args:
        event: The parsed fsmon event (see :func:`parse_monitor_line`).
        source: Backend tag, always ``"fsmon"`` for this helper.

    Returns:
        A plain dict (``seq`` is added later by
        ``MonitorProcessWrapper.record_event``).
    """
    return {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "event_type": event.event_type,
        "pid": event.pid,
        "process": event.process,
        "path": event.path,
        "new_path": event.new_path,
        "source": source,
    }


def _recent_event_from_item(item: FileSystemMonitorItem) -> dict[str, Any]:
    """Build one ``MonitorProcessWrapper.recent_events`` entry from a kprobe item.

    Unlike fsmon's raw-line path (:func:`_recent_event_from_monitor_event`),
    kprobe's ``KprobeStreamTranslator`` only ever emits prefix-STRIPPED
    ``FileSystemMonitorItem``s (correlated, display-ready) -- there is no raw
    full-path equivalent available here without reaching into the
    translator's own file*-map internals, which is out of scope for this
    tool. ``path``/``new_path`` below are therefore reconstructed from the
    already-stripped ``directory``/``filename`` fields, NOT the full
    on-device absolute path.

    Args:
        item: One item yielded by ``KprobeStreamTranslator.feed()``.

    Returns:
        A plain dict (``seq`` is added later by
        ``MonitorProcessWrapper.record_event``).
    """
    path = f"{item.directory}/{item.filename}" if item.directory else item.filename
    new_path: str | None = None
    if item.new_filename is not None:
        new_path = (
            f"{item.new_directory}/{item.new_filename}"
            if item.new_directory
            else item.new_filename
        )
    # The translator now carries the full canonical path; prefer it.
    path = item.path or path
    new_path = item.new_path or new_path
    return {
        "timestamp": item.timestamp if item.timestamp is not None else time.time(),
        "event_type": item.label,
        "pid": item.pid,
        "tid": item.tid,
        "process": item.process or None,
        "path": path,
        "new_path": new_path,
        "source": item.source,
    }


# =============================================================================
# MonitorWatch: follow the app, notice when the monitor goes blind, count
# lost events (one per monitor session)
# =============================================================================

#: ``ps`` NAME of a zygote child before it set its own name (``setArgV0``).
_UNNAMED = ("zygote64", "zygote", "usap64", "usap32", "<pre-initialized>")


class _TracerDevice:
    """MonitorWatch's device side: KprobeTracer's adb round-trips (a seam)."""

    def listing(self, package: str, tracked: list[int]) -> Any:
        from sandroid.core.kprobe_tracer import KprobeTracer

        return KprobeTracer.list_app_processes(package, tracked)

    def add(self, pids: list[int]) -> Any:
        from sandroid.core.kprobe_tracer import KprobeTracer

        return KprobeTracer.add_pids(pids)

    def start_rename(self, package: str) -> Any:
        from sandroid.core.kprobe_tracer import KprobeTracer

        return KprobeTracer.start_rename_watch(package)

    def stop_rename(self) -> None:
        from sandroid.core.kprobe_tracer import KprobeTracer

        KprobeTracer.stop_rename_watch()

    def lost(self) -> int | None:
        from sandroid.core.kprobe_tracer import KprobeTracer

        return KprobeTracer.read_lost_events()


@dataclass
class FollowedProcess:
    """One app process in the monitor's scope."""

    pid: int
    name: str
    label: str
    tids: list[int] = field(default_factory=list)
    #: Seconds between its start and being added (None: unknown).
    gap: float | None = None
    #: How it joined: "seed" (running at start), "poll", "spawn".
    via: str = "seed"
    #: Its start/restart line was emitted (waits for its final name).
    announced: bool = False


class MonitorWatch:
    """Keeps a monitor session honest about what it records.

    * **App scope** (``mode == "pid"`` with an app): tracks the app's
      processes. With ``follow`` (kprobe) every process of the app -- its
      UID, or named ``<pkg>`` / ``<pkg>:<sub>`` -- is in the trace scope:
      the ones running at start are seeded, new and restarted ones are added
      to ``set_event_pid`` (all TIDs) as they start. Starts are noticed by
      ``task:task_rename`` in a separate tracefs instance (a zygote child
      names itself right after taking the app's UID) and by a ``ps`` poll
      every :attr:`POLL_SECONDS` as the fallback (and the only way when the
      tracepoint is missing); every candidate is checked against the
      process table before it is added. A paused spawn (Sandroid's own
      Start) is handed over by :meth:`on_spawned` BEFORE the app resumes:
      no gap. Exited processes leave the kernel's list by themselves (with
      event-fork on, an exiting task is dropped from ``set_event_pid``);
      the watch drops them from its own table on the next poll.
    * **Blind**: without follow (or on fsmon), once every process the
      session started with is gone the monitor records nothing for the
      app; :meth:`caption` then says "monitor blind since HH:MM:SS · target
      gone" instead of LIVE, with how to re-target.
    * **Lost events** (kprobe): the ring buffer's per-CPU overrun counters
      are read every :attr:`LOST_SECONDS` and at stop; "N events lost" is
      shown when > 0.

    Timeline notes (a restart with its gap, an exit, a loss) go to
    ``on_note(text, level, when)``; any change of what :meth:`caption`
    shows to ``on_change()``. Both are called from worker threads.
    """

    POLL_SECONDS = 2.0
    #: Poll pace while task_rename reports starts (the poll then only
    #: notices exits and late names; a ``ps -A`` costs the device ~50 ms).
    POLL_SECONDS_WITH_RENAME = 5.0
    #: Re-poll pace for a short while after a task_rename candidate.
    BURST_SECONDS = 0.3
    BURST_FOR = 1.5
    LOST_SECONDS = 5.0

    def __init__(
        self,
        config: Any,
        backend: str,
        device: Any = None,
        on_note: Callable[[str, str, datetime], None] | None = None,
        on_change: Callable[[], None] | None = None,
        now: Callable[[], datetime] = datetime.now,
    ) -> None:
        self.config = config
        self.backend = backend
        self.package = (
            (getattr(config, "app_name", "") or "")
            if getattr(config, "mode", "") == "pid"
            else ""
        )
        #: Process tracking (app scope).
        self.track = bool(self.package)
        self.kprobe = backend == "kprobe"
        #: Follow the app (add new / restarted processes): kprobe only.
        self.follow = bool(
            self.track and self.kprobe and getattr(config, "follow", False)
        )
        self.device = device or _TracerDevice()
        self.on_note = on_note
        self.on_change = on_change
        self._now = now
        self.procs: dict[int, FollowedProcess] = {}
        self._tid_owner: dict[int, int] = {}
        self.app_uid: int | None = None
        self.main_pid: int | None = None
        #: A main process was seen this session (a new one is a restart).
        self._main_seen = False
        self.blind_since: datetime | None = None
        #: Why the monitor is blind ("target gone" / "can't follow").
        self.blind_reason = ""
        #: App processes running that the monitor does NOT record.
        self.unfollowed: set[int] = set()
        self.lost_events = 0
        #: True/False once the task_rename watch was tried (None: not tried).
        self.rename_ok: bool | None = None
        self._rename_proc: Any = None
        #: The session's trace stream (see bind_process).
        self._process: Any = None
        #: Main pids that exited / the main's (re)start, within one poll.
        self._exited: list[int] = []
        self._restart_at: datetime | None = None
        #: pid -> when its exit line arrived (sched_process_exit, see
        #: on_rename_line); the poll drops it and dates the exit by it.
        self._exit_seen: dict[int, datetime] = {}
        #: Exited pids still listed (a zombie until reaped): never re-added.
        self._gone: set[int] = set()
        #: The latest main exit noted (a later restart is ordered after it).
        self._last_exit_at: datetime | None = None
        #: Notes of the running poll, emitted in time order at its end:
        #: (text, level, when, kind, data).
        self._pending_notes: list[tuple] | None = None
        #: The device this session records (session-timeline ``dev``).
        self.serial: str | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._burst_until = 0.0
        self._started = False
        self._stopped = False
        #: A stop was asked for and is running (the caption says so).
        self.stopping = False
        self._last_state: tuple = ()

    # -- setup (off the UI thread, before tracing starts) ---------------------

    def initial_processes(self) -> Any:
        """The app's processes right now (for seeding the session)."""
        listing = self.device.listing(self.package, [])
        if getattr(listing, "app_uid", None):
            self.app_uid = listing.app_uid
        return listing

    def seed(self, tasks: dict[int, list[int]], listing: Any = None) -> None:
        """Record the processes the session started with (no timeline line)."""
        known = getattr(listing, "processes", None) or {}
        with self._lock:
            for pid, tids in tasks.items():
                info = known.get(pid)
                name = info.name if info is not None else self.package
                proc = FollowedProcess(pid, name, "", list(tids))
                proc.announced = name not in _UNNAMED
                self._add_proc(proc)
                if name == self.package:
                    self.main_pid = pid
                    self._main_seen = True
            if self.track and not tasks and not self.follow:
                self._set_blind("target gone")

    def start_rename_watch(self) -> None:
        """Start the task_rename stream (follow mode; None = poll only)."""
        if not self.follow:
            return
        try:
            self._rename_proc = self.device.start_rename(self.package)
        except Exception:
            logger.debug("task_rename watch failed to start", exc_info=True)
            self._rename_proc = None
        self.rename_ok = self._rename_proc is not None

    # -- lifecycle --------------------------------------------------------------

    def start(self) -> None:
        """Start the poll (and rename reader) threads + the spawn hand-off."""
        if self._started:
            return
        self._started = True
        if self.track or self.kprobe:
            threading.Thread(
                target=self._poll_loop, daemon=True, name="monitor-watch-poll"
            ).start()
        if self._rename_proc is not None:
            threading.Thread(
                target=self._rename_loop, daemon=True, name="monitor-watch-rename"
            ).start()
        if self.follow:
            try:
                from sandroid.services.spotlight_service import SpotlightService

                SpotlightService.add_spawn_listener(self.on_spawned)
            except Exception:
                logger.debug("spawn listener registration failed", exc_info=True)

    def stop(self) -> None:
        """Stop the threads, the rename stream and the spawn hand-off."""
        if self._stopped:
            return
        self._stopped = True
        self._stop.set()
        self._wake.set()
        try:
            from sandroid.services.spotlight_service import SpotlightService

            SpotlightService.remove_spawn_listener(self.on_spawned)
        except Exception:
            pass
        proc = self._rename_proc
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                self.device.stop_rename()
            except Exception:
                logger.debug("task_rename watch teardown failed", exc_info=True)

    def bind_process(self, process: Any) -> None:
        """Tie the threads to the session's stream: they end with it."""
        self._process = process

    def _session_alive(self) -> bool:
        process = getattr(self, "_process", None)
        if process is None:
            return True
        try:
            return process.poll() is None
        except Exception:
            return False

    def _poll_loop(self) -> None:
        next_lost = time.monotonic() + self.LOST_SECONDS
        while not self._stop.is_set() and self._session_alive():
            burst = time.monotonic() < self._burst_until
            pace = (
                self.POLL_SECONDS_WITH_RENAME if self.rename_ok else self.POLL_SECONDS
            )
            self._wake.wait(self.BURST_SECONDS if burst else pace)
            self._wake.clear()
            if self._stop.is_set() or not self._session_alive():
                break
            try:
                if self.track:
                    self.poll_once()
                if self.kprobe and time.monotonic() >= next_lost:
                    next_lost = time.monotonic() + self.LOST_SECONDS
                    self.check_lost()
            except Exception:
                logger.debug("monitor watch poll failed", exc_info=True)

    def _rename_loop(self) -> None:
        proc = self._rename_proc
        try:
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                self.on_rename_line(line)
        except Exception:
            logger.debug("task_rename reader ended", exc_info=True)
        if not self._stop.is_set():
            # The stream died (adb hiccup): the poll carries on alone.
            self.rename_ok = False
            self._changed()

    # -- events -------------------------------------------------------------

    def on_rename_line(self, line: str) -> None:
        """A ``task_rename`` line: re-poll soon if it may be a new app process.

        The rename itself proves nothing (any zygote child renames from
        "main"); the next polls check the candidate's UID and name. A
        ``sched_process_exit`` of a followed process's main thread (same
        stream, see ``KprobeTracer.start_rename_watch``) re-polls too: the
        exit is noticed in a poll's time, not up to
        :attr:`POLL_SECONDS_WITH_RENAME` later.
        """
        from sandroid.core.kprobe_tracer import parse_process_exit, parse_task_rename

        exited = parse_process_exit(line)
        if exited is not None:
            if exited in self.procs:
                # Dated now (not when a poll gets to it), without the lock: a
                # poll in flight must not delay the time the exit is known.
                self._exit_seen.setdefault(exited, self._now())
                self._burst_until = time.monotonic() + self.BURST_FOR
                self._wake.set()
            return
        parsed = parse_task_rename(line)
        if parsed is None or parsed[0] in self.procs:
            return
        self._burst_until = time.monotonic() + self.BURST_FOR
        self._wake.set()

    def on_spawned(self, pid: int, package: str) -> None:
        """Sandroid spawned ``package`` paused: follow it before it resumes."""
        if not self.follow or package != self.package or self._stopped:
            return
        with self._lock:
            proc = self.procs.get(pid)
            if proc is not None:
                # The poll found it first (still paused): it is Sandroid's
                # own spawn all the same -- no gap, hooks loading.
                if not proc.announced:
                    proc.via, proc.gap = "spawn", 0.0
                return
            self._adopt([pid], {}, via="spawn")
            self._update_state()

    def poll_once(self) -> None:
        """One look at the process table: drop exits, follow starts."""
        with self._lock:
            listing = self.device.listing(self.package, list(self.procs))
            if not getattr(listing, "ok", False):
                return  # adb hiccup: never read as "every process exited"
            if listing.app_uid:
                self.app_uid = listing.app_uid
            self._exited = []
            self._restart_at = None
            self._gone &= set(listing.processes)
            self._pending_notes = []
            try:
                self._poll_table(listing)
            finally:
                notes, self._pending_notes = self._pending_notes, None
                # In time order: an exit is never logged after the restart
                # that followed it.
                for text, level, when, kind, data in sorted(notes, key=lambda n: n[2]):
                    self._note(text, level, when, kind=kind, data=data)
            self._update_state()

    def _poll_table(self, listing: Any) -> None:
        """:meth:`poll_once` with the listing read (lock held)."""
        for pid in list(self.procs):
            if pid not in listing.processes or pid in self._exit_seen:
                if pid in listing.processes:
                    self._gone.add(pid)  # exited, not reaped yet
                self._drop(pid)
                continue
            proc = self.procs[pid]
            tids = listing.tasks.get(pid)
            if tids:
                self._set_tids(proc, tids)
            name = listing.processes[pid].name
            # A spawned (paused) process may still show the zygote's
            # name: never trade a real name for that.
            if name != proc.name and name not in _UNNAMED:
                proc.name = name
                proc.label = ""
                self._label(proc)
            self._announce(proc)
        noticed = self._now()
        # An exit seen by its trace line is dated by it (exact); one found
        # by this poll only is dated by the poll (it happened before).
        exits = []
        for pid in self._exited:
            seen = self._exit_seen.pop(pid, None)
            exits.append((pid, seen or noticed, seen is not None))
            if seen is not None and (
                self._last_exit_at is None or seen > self._last_exit_at
            ):
                self._last_exit_at = seen
        self._exited = []
        new = [
            p for p in listing.processes if p not in self.procs and p not in self._gone
        ]
        if self.follow:
            self.unfollowed = set()
            if new:
                self._adopt(new, listing.processes, via="poll")
        else:
            self.unfollowed = set(new)
        for pid, when, exact in exits:
            stamp = when
            if not exact and self._restart_at is not None and self._restart_at <= when:
                # Found together with the restart: it exited before that.
                when = self._restart_at - timedelta(microseconds=1)
            if self._last_exit_at is None or when > self._last_exit_at:
                self._last_exit_at = when
            self._note(
                f"{self.package} exited · PID {pid} · noticed {stamp:%H:%M:%S}",
                "warning",
                when,
                kind="proc-exit",
                data={"pid": pid, "exact": exact, "noticed": stamp},
            )

    def check_lost(self) -> int:
        """Read the ring buffer's overrun counters; note any new loss."""
        try:
            lost = self.device.lost()
        except Exception:
            lost = None
        if lost is not None and lost > self.lost_events:
            new = lost - self.lost_events
            self.lost_events = lost
            self._note(
                f"{new} trace events lost {self._now():%H:%M:%S} "
                f"(ring buffer overrun, {lost} this session)",
                "warning",
                kind="lost",
                data={"new": new, "total": lost},
            )
            self._changed()
        return self.lost_events

    # -- table ---------------------------------------------------------------

    def _label(self, proc: FollowedProcess) -> None:
        from sandroid.core.kprobe_tracer import process_label

        if not proc.label:
            proc.label = (
                f"pid {proc.pid}"
                if proc.name in _UNNAMED
                else process_label(proc.name, self.package)
            )

    def _add_proc(self, proc: FollowedProcess) -> None:
        self._label(proc)
        self.procs[proc.pid] = proc
        self._set_tids(proc, proc.tids or [proc.pid])

    def _set_tids(self, proc: FollowedProcess, tids: list[int]) -> None:
        for tid in proc.tids:
            if self._tid_owner.get(tid) == proc.pid:
                del self._tid_owner[tid]
        proc.tids = list(tids)
        for tid in proc.tids:
            self._tid_owner[tid] = proc.pid
        self._tid_owner[proc.pid] = proc.pid

    def _drop(self, pid: int) -> None:
        proc = self.procs.pop(pid, None)
        if proc is None:
            return
        for tid in [*proc.tids, pid]:
            if self._tid_owner.get(tid) == pid:
                del self._tid_owner[tid]
        if pid == self.main_pid:
            self.main_pid = None
            # Noted at the end of the poll: a restart found in the same poll
            # dates it (the old process was gone before the new one started).
            self._exited.append(pid)
        else:
            self._exit_seen.pop(pid, None)

    def _adopt(self, pids: list[int], known: dict, via: str) -> None:
        """Add ``pids`` (all TIDs) to the trace scope and the table."""
        result = self.device.add(pids)
        for pid in pids:
            tids = result.tasks.get(pid)
            if not tids:
                continue  # exited before it could be added
            info = known.get(pid)
            name = info.name if info is not None else self.package
            gap = 0.0 if via == "spawn" else result.gap(pid)
            proc = FollowedProcess(pid, name, "", list(tids), gap=gap, via=via)
            self._add_proc(proc)
            self._announce(proc)
        if getattr(result, "error", False):
            self._set_blind("can't follow")

    def _announce(self, proc: FollowedProcess) -> None:
        """The timeline line for a process that joined (once its name is final)."""
        if proc.announced or proc.name in _UNNAMED:
            return
        proc.announced = True
        if proc.via == "spawn":
            gap = "spawned paused · no gap"
        elif proc.gap is None:
            gap = "gap unknown"
        else:
            gap = f"gap ≈{proc.gap:.1f} s"
        started = self._now()
        if proc.gap is not None and proc.via != "spawn":
            started -= timedelta(seconds=proc.gap)
        if proc.name == self.package:
            restarted = self._main_seen
            self._main_seen = True
            self.main_pid = proc.pid
            self._restart_at = started
            what = "restarted" if restarted else "started"
            new = "new PID" if restarted else "PID"
            text = (
                f"{self.package} {what} {started:%H:%M:%S} · {new} {proc.pid} · {gap}"
            )
            if restarted and self._sandroid_restarting():
                text += " · restarted by ⇧R"
            elif restarted and proc.via != "spawn":
                text += " · Frida hooks are gone (⇧R re-applies)"
            when = started
            last_exit = self._last_exit_at
            if restarted and last_exit is not None and when <= last_exit:
                # The start is estimated from its gap; the exit before it was
                # seen: keep them in that order.
                when = last_exit + timedelta(microseconds=1)
            data = {"pid": proc.pid, "gap_s": proc.gap, "via": proc.via}
            if restarted:
                data["new_pid"] = proc.pid
            self._note(
                text,
                "warning" if restarted else "info",
                when,
                kind="proc-restart" if restarted else "proc-start",
                data=data,
            )
        else:
            # "follow": one line per burst in a file's Events (FilesPanel).
            self._note(
                f"+ {proc.label} (PID {proc.pid}) followed · {gap}",
                "follow",
                started,
                kind="follow",
                data={"pid": proc.pid, "label": proc.label, "gap_s": proc.gap},
            )

    def _sandroid_restarting(self) -> bool:
        """Sandroid's own ⇧R is restarting this package right now."""
        try:
            from sandroid.services import get_spotlight_service

            return bool(get_spotlight_service().is_restarting(self.package))
        except Exception:
            return False

    def _set_blind(self, reason: str) -> None:
        if self.blind_since is None:
            self.blind_since = self._now()
            self.blind_reason = reason
            _timeline_monitor(
                "blind",
                f"monitor blind · {reason}",
                level="warning",
                when=self.blind_since,
                data={"reason": reason},
                dev=self.serial,
                pkg=self.package,
            )

    def _update_state(self) -> None:
        if self.follow:
            if self.blind_reason != "can't follow":
                if self.blind_since is not None:
                    _timeline_monitor(
                        "sight",
                        "monitor sees the app again",
                        data={"reason": self.blind_reason},
                        dev=self.serial,
                        pkg=self.package,
                    )
                self.blind_since, self.blind_reason = None, ""
        elif self.track and not self.procs:
            self._set_blind("target gone")
        self._changed()

    def _changed(self) -> None:
        state = (
            tuple(sorted(self.procs)),
            self.blind_since,
            self.lost_events,
            self.rename_ok,
            tuple(sorted(self.unfollowed)),
        )
        if state == self._last_state:
            return
        self._last_state = state
        if self.on_change is not None:
            try:
                self.on_change()
            except Exception:
                logger.debug("monitor watch on_change failed", exc_info=True)

    def _note(
        self,
        text: str,
        level: str,
        when: datetime | None = None,
        *,
        kind: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        """A timeline note: ``on_note(text, level, when)`` for the lens and,
        with ``kind``, a ``monitor/<kind>`` session-timeline line (emitted on
        this, the calling worker thread).
        """
        if self._pending_notes is not None:
            self._pending_notes.append((text, level, when or self._now(), kind, data))
            return
        if kind is not None:
            gap = (data or {}).get("gap_s")
            estimated = (
                kind in ("proc-start", "proc-restart")
                and isinstance(gap, (int, float))
                and (data or {}).get("via") != "spawn"
            )
            _timeline_monitor(
                kind,
                text,
                level=level,
                when=when or self._now(),
                data=data,
                dev=self.serial,
                pkg=self.package,
                t_err_ms=gap * 1000 if estimated and gap else None,
            )
        if self.on_note is not None:
            try:
                self.on_note(text, level, when or self._now())
            except Exception:
                logger.debug("monitor watch on_note failed", exc_info=True)

    # -- reads (any thread) --------------------------------------------------

    def pid_for_tid(self, tid: int) -> int | None:
        """The app process a thread belongs to (None: not known)."""
        return self._tid_owner.get(tid)

    def label_for_tid(self, tid: int) -> str | None:
        """The app process (``main``, ``tab_17``...) a thread belongs to."""
        owner = self._tid_owner.get(tid)
        proc = self.procs.get(owner) if owner is not None else None
        return proc.label if proc is not None else None

    def describe(self) -> str:
        """The scope in a few words ("app org.x · 5 processes · following")."""
        if not self.track:
            return ""
        n = len(self.procs)
        if self.follow:
            if not n:
                return f"app {self.package} · not running yet · following"
            plural = "es" if n != 1 else ""
            return f"app {self.package} · {n} process{plural} · following"
        return f"app {self.package} · PID {self.main_pid or '?'} + children"

    def caption(self) -> tuple[str | None, list[str]]:
        """``(title, info parts)`` for the Files lens frame.

        ``title`` replaces "LIVE" while the monitor is blind (else None).
        """
        config = self.config
        parts: list[str] = []
        title = None
        if self.stopping:
            # Shown the moment ``o`` is pressed; the device clean-up runs
            # off the UI thread (MonitorController.stop).
            title = "monitor stopping…"
            if self.track:
                parts.append(f"App {self.package}")
            return title, parts
        if self.blind_since is not None:
            title = (
                f"monitor blind since {self.blind_since:%H:%M:%S} · {self.blind_reason}"
            )
            parts.append(f"App {self.package}")
            hint = "o stops · o again re-targets"
            if not self.follow:
                hint += " · follow restarts: monitor dialog / Settings"
            parts.append(hint)
        elif self.track:
            n = len(self.procs)
            if self.follow:
                if n:
                    parts.append(f"App {self.package} · {n} proc · following")
                else:
                    parts.append(
                        f"App {self.package} · not running · follows its start"
                    )
                if self.rename_ok is False:
                    parts.append("start detection by poll")
            else:
                main = self.main_pid or next(iter(self.procs), None)
                parts.append(f"App {self.package} · PID {main} + children")
                if self.unfollowed:
                    n_un = len(self.unfollowed)
                    plural = "es" if n_un != 1 else ""
                    parts.append(f"{n_un} app process{plural} not followed")
        else:
            paths = list(getattr(config, "target_paths", None) or [])
            first = paths[0] if paths else getattr(config, "target_path", "")
            more = f" +{len(paths) - 1}" if len(paths) > 1 else ""
            pid = getattr(config, "target_pid", None)
            scope = f"PID {pid}" if pid else "every process"
            parts.append(f"Path {first}{more} · {scope}")
        if self.lost_events:
            parts.append(f"{self.lost_events} events lost")
        if title is None:
            parts.append("o stops")
        return title, parts


def _load_generation() -> int | None:
    try:
        from sandroid.services.emulator_service import snapshot_load_generation

        return snapshot_load_generation()
    except Exception:
        return None


def _load_running() -> bool:
    try:
        from sandroid.services.emulator_service import snapshot_load_active

        return snapshot_load_active()
    except Exception:
        return False


#: Live controllers that restart a monitor a snapshot load ended.
_LOAD_WATCHERS: "weakref.WeakSet[MonitorController]" = weakref.WeakSet()
_AFTER_LOAD_REGISTERED = False


def _after_snapshot_load(_serial: str | None) -> None:
    """EmulatorService after-load hook (loader worker thread)."""
    for controller in list(_LOAD_WATCHERS):
        try:
            controller._call_from_thread(controller._resume_monitor_after_load)
        except Exception:
            logger.debug("monitor resume after load not scheduled", exc_info=True)


def _register_after_load() -> None:
    global _AFTER_LOAD_REGISTERED
    if _AFTER_LOAD_REGISTERED:
        return
    try:
        from sandroid.services.emulator_service import register_after_load_hook

        register_after_load_hook(_after_snapshot_load)
        _AFTER_LOAD_REGISTERED = True
    except Exception:
        logger.debug("monitor after-load hook not registered", exc_info=True)


class MonitorController:
    """Controller for Monitor filesystem monitoring.

    This controller handles all Monitor-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of Monitor logic from UI rendering
    - Reusable Monitor management across different UI modes

    Thread Safety:
        Monitor output reading runs in background threads.
        Log callbacks are invoked via call_from_thread.

    Example:
        controller = MonitorController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            call_from_thread=lambda fn, *args: fn(*args),
            force_ui_refresh=lambda: None,
        )

        # Start Monitor
        controller.start_monitor()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        log_task_started: Callable[[str, str], None] | None = None,
        log_task_stopped: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        call_from_thread: Callable[..., None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        get_current_view: Callable[[], str] | None = None,
        open_files_tab: Callable[[], None] | None = None,
        on_pid_mode_fallback: Callable[[str], None] | None = None,
        on_backend_fallback: Callable[[str], None] | None = None,
        run_off_thread: Callable[[Callable[[], None]], None] | None = None,
    ):
        """Initialize MonitorController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            log_task_started: Callback when task starts (name, description)
            log_task_stopped: Callback when task stops (name)
            push_modal: Callback to push a modal screen with result callback
            call_from_thread: Callback to execute function on main thread
            force_ui_refresh: Callback to force UI refresh after state changes
            get_current_view: Callback to get current view mode
            open_files_tab: Callback to switch the TUI to the Files tab's
                Monitor sub-tab, invoked once monitor has actually *started*
                (after ``_start_monitor`` registers with TaskService) — not
                merely when the config modal opens. Mirrors friTap's
                ``h`` key -> ``MainScreen.open_fritap_tab()`` jump
                (``app.py``'s ``action_action_key``). Injected rather than
                importing ``app.py``/``MainScreen`` directly here, same
                reasoning as every other UI callback on this controller.
            on_pid_mode_fallback: Callback invoked (with the path now being
                monitored instead) when a PID-mode start silently falls back
                to path-mode because ``FSMon.fanotify_supported()`` reports
                the device's kernel lacks fanotify. ``_start_monitor`` already
                runs on the main thread (see the ``_open_files_tab`` callback
                above for the same reasoning), so this is invoked directly,
                no ``call_from_thread`` marshaling needed.
            on_backend_fallback: Callback invoked (with a human-readable
                reason) when the requested/auto-selected kprobe backend is
                unavailable and the monitor falls back to fsmon. Distinct from
                ``on_pid_mode_fallback`` (which is path-only and hardcodes the
                fanotify wording); both can fire in ``auto`` mode (backend
                fallback first, then the fsmon pid->path notice). Invoked from
                the preflight-completion callback, which is already marshaled
                back to the main thread.
            run_off_thread: Runs a zero-arg callable off the UI thread. The
                kprobe preflight (kallsyms scan + test-attach + offset
                self-check) is several adb round-trips and would freeze
                Textual if run on the main thread where ``_start_monitor``
                lives. Defaults to spawning a daemon thread; tests inject a
                synchronous runner.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._log_task_started = log_task_started
        self._log_task_stopped = log_task_stopped
        self._push_modal = push_modal
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._force_ui_refresh = force_ui_refresh
        self._get_current_view = get_current_view
        self._open_files_tab = open_files_tab
        self._on_pid_mode_fallback = on_pid_mode_fallback
        self._on_backend_fallback = on_backend_fallback
        self._run_off_thread = run_off_thread or self._default_run_off_thread
        # "A start is in progress" latch (Fix 6). Set the instant _start_monitor
        # begins and cleared when the launch finalizes (success OR failure),
        # including the off-thread kprobe path where the task doesn't register
        # until after the preflight+setup worker finishes -- so is_running() is
        # False during that window. Guards against a second 'o' press (or resume)
        # opening the config modal / starting a concurrent session mid-preflight.
        self._start_pending = False
        #: A stop is running off the UI thread (see :meth:`stop`): no new
        #: start until the device is cleaned up.
        self._stop_pending = False
        #: Snapshot-load generation when the monitor last started, and the
        #: config to restart with once a load that ended it has finished.
        self._load_gen_at_start: int | None = None
        self._resume_after_load: MonitorConfig | None = None
        _LOAD_WATCHERS.add(self)
        _register_after_load()

    @staticmethod
    def _default_run_off_thread(target: Callable[[], None]) -> None:
        """Run ``target`` on a daemon thread (production default)."""
        threading.Thread(
            target=target, daemon=True, name="monitor-kprobe-preflight"
        ).start()

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_task_service(self) -> Any:
        """Get task service instance."""
        from sandroid.services import get_task_service

        return get_task_service()

    # =========================================================================
    # Monitor Status
    # =========================================================================

    def is_running(self) -> bool:
        """Check if Monitor is currently running.

        Returns:
            True if Monitor is active
        """
        return self._get_task_service().is_running("monitor")

    def can_start(self) -> tuple[bool, str]:
        """Check if Monitor can be started.

        Returns:
            Tuple of (can_start, reason_if_not)
        """
        if self._stop_pending:
            return (
                False,
                "Monitor is still stopping — please wait.",
            )
        if self.is_running():
            return (
                False,
                "Monitor is already running. Press 'o' to stop it.",
            )

        # A start already in flight (e.g. the off-thread kprobe preflight is
        # still running, before the task registers) -> refuse a second start.
        if self._start_pending:
            return (
                False,
                "Monitor is already starting — please wait.",
            )

        return True, ""

    def get_status(self) -> dict[str, Any]:
        """Return the running monitor session's status for the AI chat.

        No new state needed: ``MonitorProcessWrapper`` already stores
        ``self.config`` (already read elsewhere via
        ``task.instance.config``, e.g. :meth:`_get_running_monitor_config`),
        so this just reads it back out through ``TaskService``.

        Returns:
            ``{"running": bool, "backend": str | None, "mode": str | None,
            "target_path": str | None, "target_paths": list[str],
            "target_pid": int | None, "app_name": str | None}``. Every field
            besides ``running`` is ``None``/empty when monitor isn't
            running.
        """
        running = self.is_running()
        task = self._get_task_service().get_task("monitor") if running else None
        config = getattr(getattr(task, "instance", None), "config", None)
        if config is None:
            return {
                "running": running,
                "backend": None,
                "mode": None,
                "target_path": None,
                "target_paths": [],
                "target_pid": None,
                "app_name": None,
            }
        return {
            "running": running,
            "backend": config.backend,
            "mode": config.mode,
            "target_path": config.target_path,
            "target_paths": list(config.target_paths),
            "target_pid": config.target_pid,
            "app_name": config.app_name,
        }

    def get_recent_events(
        self, since_seq: int | None = None, limit: int = 200
    ) -> dict[str, Any]:
        """Return recent parsed filesystem events for the AI chat.

        Reads the bounded, non-cleared ``recent_events`` deque on the
        running monitor's ``MonitorProcessWrapper`` -- NOT the transient
        per-flush ``item_buffer``/``line_buffer`` closures inside
        :meth:`_start_output_reader`, which are ``.clear()``-ed on every
        ``flush_to_ui()`` call (every ~0.15s by default) and hold at most
        one flush interval's worth of events at any instant.

        Args:
            since_seq: Only return events with ``seq`` strictly greater than
                this value (cursor-style polling -- pass a prior call's
                ``next_seq`` for "what's new"). ``None`` (the default)
                returns the most recent ``limit`` events instead.
            limit: Max events to return. Hard-capped at
                :data:`_MAX_RECENT_EVENTS_LIMIT`, mirroring
                ``ai/tools/flow_query.py``'s ``_MAX_LIMIT`` convention.

        Returns:
            ``{"events": [...], "next_seq": int, "count": int, "truncated":
            bool}``. ``events`` is oldest-first. ``next_seq`` is the highest
            ``seq`` currently in the underlying buffer (``0`` if empty or
            monitor isn't running) -- pass it back as ``since_seq`` on the
            next call to page forward. ``truncated`` is True when more
            matching events existed than ``limit`` allowed through.
        """
        limit = max(1, min(int(limit), _MAX_RECENT_EVENTS_LIMIT))

        task = self._get_task_service().get_task("monitor")
        wrapper = getattr(task, "instance", None)
        events: list[dict[str, Any]] = list(
            getattr(wrapper, "recent_events", None) or []
        )

        next_seq = events[-1]["seq"] if events else 0

        if since_seq is not None:
            events = [e for e in events if e["seq"] > since_seq]

        truncated = len(events) > limit
        if truncated:
            events = events[-limit:]

        return {
            "events": events,
            "next_seq": next_seq,
            "count": len(events),
            "truncated": truncated,
        }

    # =========================================================================
    # Monitor Operations
    # =========================================================================

    def start_with_config(self, config: MonitorConfig) -> dict[str, Any]:
        """Start monitor from the AI chat -- thin wrapper around ``_start_monitor``.

        ``_start_monitor`` is already backend-agnostic and modal-free (the
        UI-only piece is :meth:`show_config_modal`, which this bypasses
        entirely). The kprobe/auto path resolves ASYNCHRONOUSLY: preflight +
        session setup run on a spawned thread, and ``_start_monitor`` returns
        ``True`` "optimistically" before the task actually registers (see
        that method's own docstring). This method therefore does NOT report
        ``success``/``backend`` as settled fact for that case -- it returns
        ``pending=True`` when the concrete backend/registration isn't known
        synchronously yet, and the AI is expected to follow up with
        :meth:`get_status` (the ``get_file_monitor_status`` tool) rather than
        trusting this return value alone.

        Threading note: ``_start_monitor`` touches UI callbacks directly
        (``_log_info``/``_log_task_started``/``_open_files_tab``/
        ``_force_ui_refresh``) in its synchronous fsmon path (and one log
        line at the top of the kprobe/auto path, before the off-thread
        preflight is even spawned) -- safe when called from Textual's main
        thread (the ``show_config_modal`` path), but a genuine cross-thread
        Textual violation when called from the AI tool-dispatch thread
        (never the main thread). Rather than splitting ``_launch_fsmon``
        into a device-heavy/cheap-finalize pair the way the kprobe path
        already is, this method marshals the ENTIRE ``_start_monitor`` call
        through ``call_from_thread`` -- mirroring exactly how
        ``RecordingController.start_playback_chat`` wraps its call to
        ``start_playback``. This briefly blocks both the calling
        (tool-dispatch) thread and the main thread for the fsmon branch's
        adb push/spawn (the same blocking the manual/keybinding path already
        does today), and merely marshals the cheap "kick off the off-thread
        kprobe preflight" call for the async path -- so it's safe either way.

        Args:
            config: The ``MonitorConfig`` to start with (mode/target/app_name
                already resolved by the caller -- see
                ``ai/tools/monitor_control.py``'s ``start_file_monitor``).

        Returns:
            ``{"success": bool, "backend": str | None, "mode": str,
            "target": str | int | None, "pending": bool}``. ``target`` is
            the PID for ``mode == "pid"``, else the target path.
            ``pending`` is True only for the async kprobe/auto case where
            the real outcome isn't known yet.
        """
        launched = self._call_from_thread(self._start_monitor, config)
        fallback_target = (
            config.target_pid if config.mode == "pid" else config.target_path
        )
        if not launched:
            return {
                "success": False,
                "backend": None,
                "mode": config.mode,
                "target": fallback_target,
                "pending": False,
            }

        task = self._get_task_service().get_task("monitor")
        resolved_config = getattr(getattr(task, "instance", None), "config", None)
        if resolved_config is None:
            # Async kprobe/auto path: preflight+setup still running off
            # the main thread, the task hasn't registered yet.
            return {
                "success": True,
                "backend": None,
                "mode": config.mode,
                "target": fallback_target,
                "pending": True,
            }

        resolved_target = (
            resolved_config.target_pid
            if resolved_config.mode == "pid"
            else resolved_config.target_path
        )
        return {
            "success": True,
            "backend": resolved_config.backend,
            "mode": resolved_config.mode,
            "target": resolved_target,
            "pending": False,
        }

    def show_config_modal(self) -> bool:
        """Show Monitor configuration modal.

        Returns:
            True if modal was shown
        """
        from sandroid.tui.modals import MonitorConfigModal

        can_start, reason = self.can_start()

        if not can_start:
            # Already running -> toggle it off (mirrors the old
            # already-running-in-background-mode behavior; there is no
            # observer modal to restore anymore, Monitor is the only
            # display surface).
            if self.is_running():
                return self.stop()
            self._log_warning(reason)
            return False

        if not self._push_modal:
            self._log_error("Cannot show config modal - push_modal not configured")
            return False

        def on_config(config: MonitorConfig) -> None:
            if config is None or config.cancelled:
                return
            self._start_monitor(config)

        self._push_modal(MonitorConfigModal(), on_config)
        return True

    def _get_buffer_interval(self) -> float:
        """Read monitor_buffer_interval from config.

        Returns:
            Interval in seconds (minimum 0.01 when set to 0).
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            interval = config.tui.monitor_buffer_interval
            return max(interval, 0.01) if interval > 0 else 0.01
        except Exception:
            return 0.15

    def _get_monitor_backend(self) -> str:
        """Read ``tui.monitor_backend`` from config (default ``"kprobe"``).

        On any read error the preference falls back to ``"kprobe"`` (the schema
        default), which the start path preflights and auto-falls-back to fsmon
        when the kernel lacks kprobe support.
        """
        try:
            from sandroid.config.loader import ConfigLoader

            return ConfigLoader().load().tui.monitor_backend
        except Exception:
            return "kprobe"

    def _resolve_backend_pref(self, config: MonitorConfig) -> str:
        """Resolve the effective backend preference for this start.

        A config whose ``backend`` was already resolved to a concrete backend
        (``"fsmon"``/``"kprobe"``) -- e.g. a resume after a prior run/fallback
        -- is honored directly, so resume doesn't reset the backend or re-run
        the (expensive) kprobe preflight for a session that already fell back
        to fsmon. Otherwise (``"auto"``, the modal default) the global
        ``tui.monitor_backend`` preference decides.
        """
        pref = getattr(config, "backend", None) or "auto"
        if pref == "auto":
            pref = self._get_monitor_backend()
        return pref if pref in ("fsmon", "kprobe") else "kprobe"

    def _start_monitor(self, config: MonitorConfig) -> bool:
        """Start Monitor, selecting the backend ABOVE any fsmon binary install.

        The backend decision precedes ``FSMon.check_and_install_fsmon`` so a
        kprobe session pushes no ELF. For an fsmon-resolved preference the
        start is fully synchronous. For kprobe/auto BOTH the preflight (kallsyms
        scan + test-attach + offset self-check) AND, on success, the
        device-heavy session SETUP (``KprobeTracer.run_by_*`` -- ~40-60
        synchronous ``adb shell`` round-trips: self-clean + install + enable +
        buffer + filters, each with a 30s timeout) run OFF the UI thread via
        ``run_off_thread``. Only the CHEAP finalization (constructing/
        registering the wrapper, starting the reader thread, focusing the tab)
        is marshaled back to the main thread via ``call_from_thread`` -- so
        Textual never freezes for seconds (or minutes if adb is wedged). In
        that async case ``_start_monitor`` returns ``True`` optimistically; when
        the runner + marshaler are synchronous (tests) the return reflects the
        real launch outcome.

        Args:
            config: MonitorConfig from the configuration modal.

        Returns:
            True if Monitor was started (or a kprobe start was initiated).
        """
        # Fix 6: refuse a start while one is already running or pending (the
        # off-thread kprobe preflight/setup window, before the task registers).
        if self.is_running() or self._start_pending:
            self._log_warning("Monitor is already starting — please wait.")
            return False
        self._load_gen_at_start = _load_generation()
        self._resume_after_load = None
        self._start_pending = True

        pref = self._resolve_backend_pref(config)

        if pref == "fsmon":
            # No preflight needed -> fully synchronous fsmon start (unchanged).
            try:
                return self._launch_fsmon(config)
            finally:
                self._start_pending = False

        # kprobe or auto: preflight AND device-heavy setup off the UI thread;
        # only the cheap finalization is marshaled back to the main thread.
        self._log_info("Checking kprobe backend support on this device…")
        result = {"ok": True}

        def _preflight_worker() -> None:
            supported = False
            try:
                from sandroid.core.kprobe_tracer import KprobeTracer

                supported = KprobeTracer.kprobe_supported()
            except Exception:
                logger.debug("kprobe preflight errored", exc_info=True)
                supported = False

            if not supported:
                # kprobe unavailable -> fall back to fsmon on the main thread
                # (fsmon's own threading behavior is unchanged).
                def _fallback() -> None:
                    try:
                        result["ok"] = self._fall_back_to_fsmon(config, pref)
                    finally:
                        self._start_pending = False

                try:
                    self._call_from_thread(_fallback)
                except Exception:
                    self._start_pending = False
                    logger.debug("kprobe fallback finalize failed", exc_info=True)
                return

            # Supported: run the DEVICE-HEAVY session setup HERE, off the main
            # thread. Only the finalization is marshaled back.
            try:
                setup = self._kprobe_setup(config)
            except Exception:
                logger.debug("kprobe setup errored", exc_info=True)
                setup = None

            def _finish() -> None:
                try:
                    result["ok"] = self._finish_kprobe_launch(config, setup)
                finally:
                    self._start_pending = False

            try:
                self._call_from_thread(_finish)
            except Exception:
                self._start_pending = False
                logger.debug("kprobe launch finalize failed", exc_info=True)

        self._run_off_thread(_preflight_worker)
        return result["ok"]

    def _fall_back_to_fsmon(self, config: MonitorConfig, pref: str) -> bool:
        """Main-thread continuation when the kprobe backend is unavailable.

        Surfaces a reason-carrying notice (distinct from the fsmon pid->path
        notice, which may ALSO fire afterwards inside ``_launch_fsmon`` in auto
        mode) then launches fsmon.

        With ``tui.monitor_backend`` now defaulting to ``"kprobe"``, the resolved
        ``pref`` is ``"kprobe"`` for nearly every session, so it can no longer
        tell an explicit per-session request apart from the default. The
        distinguishing signal is the session's own ``MonitorConfig.backend``:
        ``"kprobe"`` means the user explicitly chose it, while the ``"auto"``
        sentinel means it merely landed on the default. Only the explicit case
        says "kprobe backend was requested".
        """
        if getattr(config, "backend", None) == "kprobe":
            reason = (
                "kprobe backend was requested but this device's kernel lacks "
                "the required tracefs/kprobe support — using fsmon instead."
            )
        else:
            reason = "kprobe backend unavailable on this device — using fsmon instead."
        _timeline_monitor(
            "fallback",
            "monitor · kprobe unavailable, using fsmon",
            level="warning",
            data={"from": "kprobe", "to": "fsmon", "reason": reason},
            dev=_timeline_serial(),
        )
        if self._on_backend_fallback:
            try:
                self._on_backend_fallback(reason)
            except Exception:
                logger.debug("on_backend_fallback callback failed", exc_info=True)
        return self._launch_fsmon(config)

    def _register_and_start(
        self, config: MonitorConfig, wrapper: Any, mode_desc: str
    ) -> bool:
        """Shared finalize: log started, register the task, start the reader,
        and jump to the Monitor sub-tab. Backend-agnostic.
        """
        if self._log_task_started:
            self._log_task_started("Monitor", mode_desc)
        else:
            self._log_info(f"Monitor started monitoring {mode_desc}")

        # Register as background task
        self._get_task_service().register(
            name="monitor",
            display_name="Monitor",
            instance=wrapper,
            stop_callback=wrapper.stop,
            app_name=config.app_name if config.app_name else config.target_path,
        )

        # The device this session records: every file/monitor line of the
        # session goes to its timeline, also after a device switch.
        serial = _timeline_serial()
        wrapper.timeline_serial = serial
        watch = getattr(wrapper, "watch", None)
        if isinstance(watch, MonitorWatch):
            watch.serial = serial
        paths = list(getattr(config, "target_paths", None) or []) or (
            [config.target_path] if getattr(config, "target_path", "") else []
        )
        _timeline_monitor(
            "start",
            f"monitor started · {mode_desc}",
            data={
                "backend": getattr(config, "backend", None),
                "mode": getattr(config, "mode", None),
                "app": getattr(config, "app_name", "") or None,
                "paths": paths,
                "follow": bool(getattr(config, "follow", False)),
            },
            dev=serial,
            pkg=getattr(config, "app_name", "") or None,
        )

        # Start output reader thread
        self._start_output_reader(wrapper)

        # Follow the app / notice blindness / count lost events -- for as
        # long as the session's stream runs.
        if isinstance(watch, MonitorWatch):
            watch.bind_process(getattr(wrapper, "process", None))
            watch.start()

        # monitor actually STARTED (not just the config modal opening) —
        # jump to the Files tab's Monitor sub-tab so the live stream is
        # immediately visible, mirroring "h" (friTap) ->
        # MainScreen.open_fritap_tab(). This runs on the main thread (fsmon
        # path: direct from the modal dismiss callback; kprobe path: marshaled
        # back via call_from_thread in _start_monitor), so invoke directly.
        if self._open_files_tab:
            try:
                self._open_files_tab()
            except Exception:
                logger.debug(
                    "Failed to open Files tab after monitor start", exc_info=True
                )

        return True

    def _launch_fsmon(self, config: MonitorConfig) -> bool:
        """Start the fsmon backend (unchanged behavior; now behind the selector)."""
        from sandroid.core.fsmon import FSMon
        from sandroid.tui.utils import MonitorProcessWrapper

        config.backend = "fsmon"
        self._log_info("Installing/checking monitor binary...")

        # Check and install monitor binary
        try:
            FSMon.check_and_install_fsmon()
        except Exception as e:
            self._log_error(f"Failed to install monitor: {e}")
            return False

        # Start monitor based on mode
        try:
            if config.mode == "pid" and config.target_pid:
                if FSMon.fanotify_supported():
                    process = FSMon.run_fsmon_by_pid(
                        config.target_pid, config.target_path
                    )
                    mode_desc = f"PID {config.target_pid}"
                else:
                    # No fanotify on this device -- PID-mode attribution
                    # would silently be wrong (production monitor builds fall
                    # back to inotify and never error cleanly on -p). Fall
                    # back to path-mode instead, and make the substitution
                    # honest everywhere it's visible: mode_desc here, and
                    # the MonitorConfig registered below (so the header/
                    # resume-after-playback logic sees the actual running
                    # mode, not the originally requested one). Real
                    # fanotify-less PID attribution is what the kprobe backend
                    # (KprobeTracer) provides -- this notice is the fsmon-only
                    # path.
                    #
                    # Known caveat (found via real on-device E2E testing,
                    # not fixed here -- an upstream monitor/inotify limitation,
                    # not something this fallback introduces): monitor adds
                    # inotify watches dynamically as new directories appear.
                    # If a brand-new, multi-level-deep directory tree is
                    # created and immediately written into (no delay between
                    # mkdir and the write), the deepest directory's contents
                    # can be silently missed -- a real forensic blind spot
                    # specific to the inotify backend this fallback relies
                    # on. Not present on real fanotify-backed PID-mode.
                    process = FSMon.run_fsmon_by_path(config.target_path)
                    mode_desc = (
                        f"path {config.target_path} "
                        "(PID mode unavailable — no fanotify on this device)"
                    )
                    config = MonitorConfig(
                        mode="path",
                        target_path=config.target_path,
                        target_pid=None,
                        app_name=config.app_name,
                        backend="fsmon",
                    )
                    if self._on_pid_mode_fallback:
                        try:
                            self._on_pid_mode_fallback(config.target_path)
                        except Exception:
                            logger.debug(
                                "on_pid_mode_fallback callback failed", exc_info=True
                            )
            else:
                process = FSMon.run_fsmon_by_path(config.target_path)
                mode_desc = f"path {config.target_path}"
                if config.mode == "pid":
                    # App mode before the app runs needs kprobe (follow);
                    # fsmon watches the path instead -- say so everywhere.
                    mode_desc += " (app not running; fsmon can't follow it)"
                    config = MonitorConfig(
                        mode="path",
                        target_path=config.target_path,
                        target_pid=None,
                        app_name=config.app_name,
                        backend="fsmon",
                    )

            watch = self._make_watch(config, "fsmon")
            if watch.track and config.target_pid:
                watch.seed({config.target_pid: []})
            if getattr(config, "follow", False) and watch.track:
                mode_desc += " (fsmon can't follow restarts)"
            wrapper = MonitorProcessWrapper(process, config, teardown=watch.stop)
            wrapper.watch = watch
            return self._register_and_start(config, wrapper, mode_desc)

        except Exception as e:
            self._log_error(f"Failed to start monitor: {e}")
            return False

    def _kprobe_setup(self, config: MonitorConfig) -> tuple[Any, Any, str] | None:
        """DEVICE-HEAVY kprobe session setup -- MUST run OFF the UI thread.

        Every ``KprobeTracer.run_by_*`` issues several synchronous (batched)
        ``adb shell`` round-trips (self-clean + probe install + enable +
        buffer + filters), each with a 30s timeout, so this would freeze
        Textual for seconds (or minutes if adb is wedged) on the main thread. The cheap finalization is
        split out into :meth:`_finish_kprobe_launch`.

        Returns ``(process, translator, mode_desc)`` on success, or ``None`` if
        the tracer couldn't start the streaming process.

        PID preference (firehose bounding): whenever a target PID is known --
        even for a ``"path"``-mode config -- ``run_by_pid(pid, path)`` is
        preferred over pure ``run_by_path``. It seeds ``set_event_pid`` (which
        bounds the system-wide write firehose to the target's task tree) AND
        applies the same path glob, so pure path mode is used only when no PID
        is available.
        """
        from sandroid.core.kprobe_tracer import KprobeTracer

        config.backend = "kprobe"

        # kprobe is the multi-path backend: forward the canonical
        # ``target_paths`` list when it is set (its OR-filter matches every
        # path), otherwise the single primary ``target_path``. fsmon stays
        # single-path (``_launch_fsmon`` consumes only ``target_path``).
        paths = config.target_paths or config.target_path

        # The device's view of the targets (mount table + real paths, one adb
        # call) BEFORE tracing starts: the write probes' dentry chains are
        # matched against it -- which names writes through files opened
        # before the monitor started -- and the tracer filters the write
        # probes in-kernel by it.
        scope = None
        if paths:
            try:
                scope = self._write_scope(paths)
            except Exception:
                logger.debug("monitor write-scope read failed", exc_info=True)

        watch = self._make_watch(config, "kprobe")
        if watch.follow:
            # App scope: every process of the app, seeded now and followed
            # (new/restarted ones are added as they start). The table is read
            # again after the rename watch is up, so a process that started
            # in between is added too -- no window without either.
            listing = watch.initial_processes()
            pids = sorted(getattr(listing, "processes", None) or {})
            process = KprobeTracer.run_by_app(pids, paths or None)
            if process is not None:
                watch.seed(dict(KprobeTracer.last_seeded), listing)
                watch.start_rename_watch()
                try:
                    watch.poll_once()
                except Exception:
                    logger.debug("monitor watch first poll failed", exc_info=True)
            mode_desc = f"{watch.describe()} (kprobe)"
        elif config.target_pid:
            process = KprobeTracer.run_by_pid(config.target_pid, paths or None)
            if watch.track:
                watch.seed({config.target_pid: []})
            if config.mode == "pid":
                mode_desc = f"PID {config.target_pid} + children (kprobe)"
            else:
                mode_desc = (
                    f"path {config.target_path} + PID {config.target_pid} (kprobe)"
                )
        elif config.mode == "path" and config.target_path:
            process = KprobeTracer.run_by_path(paths)
            mode_desc = f"path {config.target_path} (kprobe)"
        else:
            process = KprobeTracer.run_capture_all()
            mode_desc = "all processes (kprobe)"

        # Surface the extra paths in the mode description (the primary path is
        # already shown above); only when there is genuinely more than one.
        extra = len(config.target_paths) - 1
        if extra > 0:
            mode_desc += f" (+{extra} path{'s' if extra != 1 else ''})"

        if process is None:
            watch.stop()
            return None

        # One long-lived translator per session, reset now; the reader thread
        # runs it AHEAD of its ring buffer (see _start_output_reader).
        translator = KprobeStreamTranslator()
        translator.reset(config)
        translator.set_write_scope(scope)
        translator.watch = watch
        if watch.track:
            translator.set_process_labels(watch.label_for_tid, watch.pid_for_tid)
        return process, translator, mode_desc

    def _make_watch(self, config: MonitorConfig, backend: str) -> MonitorWatch:
        """The session's :class:`MonitorWatch` (notes/status reach the UI)."""
        return MonitorWatch(
            config,
            backend,
            device=self._watch_device(),
            on_note=self._watch_note,
            on_change=self._watch_changed,
        )

    def _watch_device(self) -> Any:
        """The watch's device side (``None`` = KprobeTracer); a test seam."""
        return None

    def _on_ui(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run ``fn`` on the UI thread (directly when already there)."""
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        try:
            self._call_from_thread(fn, *args)
        except Exception:
            logger.debug("monitor watch UI hand-off failed", exc_info=True)

    def _watch_note(self, text: str, level: str, when: datetime) -> None:
        """A timeline line: the log, and a separator in the Files Events."""

        def emit() -> None:
            (self._log_warning if level == "warning" else self._log_info)(text)
            _publish_monitor_info(
                {"monitor_note": {"text": text, "level": level, "when": when}}
            )

        self._on_ui(emit)

    def _watch_changed(self) -> None:
        """What the Files caption shows about the monitor changed."""
        self._on_ui(_publish_monitor_info, {"monitor_status": True})

    def _write_scope(self, paths) -> Any:
        """``KprobeTracer.resolve_write_scope`` -- only on a device whose
        kprobe preflight passed (adb root is on there); a seam for tests.
        """
        from sandroid.core.kprobe_tracer import KprobeTracer

        if KprobeTracer.cached_availability() is not True:
            return None
        return KprobeTracer.resolve_write_scope(paths)

    def _finish_kprobe_launch(
        self, config: MonitorConfig, setup: tuple[Any, Any, str] | None
    ) -> bool:
        """CHEAP main-thread finalize of a kprobe launch.

        Constructs the wrapper (carrying ``KprobeTracer.teardown``, run AFTER
        the pipe is killed), registers the task, starts the reader thread and
        focuses the tab. The device-heavy work already happened off-thread in
        :meth:`_kprobe_setup`.
        """
        from sandroid.core.kprobe_tracer import KprobeTracer
        from sandroid.tui.utils import MonitorProcessWrapper

        if setup is None:
            self._log_error("Failed to start kprobe monitor")
            return False
        process, translator, mode_desc = setup
        watch = getattr(translator, "watch", None)
        if watch is None:
            watch = self._make_watch(config, "kprobe")

        def _teardown() -> None:
            # Runs after the trace_pipe reader was killed, before the
            # instance is removed: the overrun counters are still there.
            # The follow instance's removal and the lost-events read are
            # independent adb round-trips: run side by side.
            stopper = threading.Thread(
                target=watch.stop, daemon=True, name="monitor-watch-stop"
            )
            stopper.start()
            try:
                watch.check_lost()
            finally:
                stopper.join(10)
            KprobeTracer.teardown()

        wrapper = MonitorProcessWrapper(
            process,
            config,
            teardown=_teardown,
            translator=translator,
        )
        wrapper.watch = watch
        return self._register_and_start(config, wrapper, mode_desc)

    def _launch_kprobe(self, config: MonitorConfig) -> bool:
        """Synchronous kprobe launch: device-heavy setup THEN cheap finalize.

        The production async path calls :meth:`_kprobe_setup` (off-thread) and
        :meth:`_finish_kprobe_launch` (main thread) separately; this method
        keeps them combined for direct/synchronous callers (e.g. tests). No ELF
        is pushed.
        """
        self._log_info("Starting kprobe filesystem monitor (no binary pushed)…")
        try:
            setup = self._kprobe_setup(config)
        except Exception as e:
            self._log_error(f"Failed to start kprobe monitor: {e}")
            return False
        return self._finish_kprobe_launch(config, setup)

    def _start_output_reader(self, monitor_process_wrapper: Any) -> None:
        """Start a thread to read monitor output with batched UI delivery.

        Instead of calling ``call_from_thread`` for every single monitor line
        (which floods Textual's event loop at high event rates), the reader
        thread accumulates output in a thread-safe deque and flushes it to the
        main thread in a single batch every ``flush_interval`` seconds.

        Two backends, two pipelines:
          * **fsmon** (no translator): the deque holds RAW lines; the main
            thread turns them into items (``_log_monitor_output_batch`` ->
            ``build_monitor_item``) -- stateless, so the ring buffer sitting
            before it is harmless.
          * **kprobe** (wrapper carries a translator): each raw line is run
            through the per-session ``KprobeStreamTranslator`` IN THIS READER
            THREAD, AHEAD of the deque, and the deque holds already-correlated
            ITEMS. This is mandatory -- a dropped ``do_filp_open``-return or
            ``__fput`` line would corrupt the file* map and defeat ``__fput``
            invalidation, so the bounded ring buffer must never sit between the
            raw stream and the correlator.

        In BOTH pipelines, every parsed line/item is ALSO recorded into
        ``monitor_process_wrapper.recent_events`` (via ``record_event()``) --
        a genuinely separate, non-cleared per-session history for the AI
        chat's ``get_recent_file_changes`` tool. This is IN ADDITION to (not
        instead of) the transient ``item_buffer``/``line_buffer`` above,
        which stay exactly as they were (cleared on every flush) since
        MonitorView's own live-rendering pipeline still depends on that
        batching behavior.

        Args:
            monitor_process_wrapper: MonitorProcessWrapper instance
        """
        translator = getattr(monitor_process_wrapper, "translator", None)
        flush_interval = self._get_buffer_interval()
        file_event = _timeline_file_event(monitor_process_wrapper)

        if translator is not None:
            # kprobe: deque of already-correlated items (translate-ahead).
            item_buffer: deque[FileSystemMonitorItem] = deque(maxlen=2000)

            def ingest(line_str: str) -> None:
                now = time.time()
                for item in translator.feed(line_str):
                    item = replace(item, timestamp=now)
                    # The session timeline: before the lossy deque below.
                    file_event(
                        item.label,
                        item.path or _item_path(item),
                        now,
                        "kprobe",
                        item.new_path,
                        item.process,
                        item.pid,
                        item.tid,
                    )
                    item_buffer.append(item)
                    try:
                        monitor_process_wrapper.record_event(
                            _recent_event_from_item(item)
                        )
                    except Exception:
                        logger.debug(
                            "Failed to record kprobe event history", exc_info=True
                        )

            def flush_to_ui() -> None:
                if not item_buffer:
                    return
                batch = list(item_buffer)
                item_buffer.clear()
                try:
                    self._call_from_thread(_publish_monitor_batch, batch)
                except Exception:
                    logger.debug("Failed to flush kprobe batch to UI", exc_info=True)

        else:
            # fsmon: deque of raw lines; items built on the main thread.
            # (line, capture time): the item built later keeps the time.
            line_buffer: deque[tuple[str, float]] = deque(maxlen=2000)

            def ingest(line_str: str) -> None:
                now = time.time()
                event = parse_monitor_line(line_str)
                if event is not None:
                    # The session timeline: before the lossy deque below.
                    file_event(
                        event.event_type,
                        event.path,
                        now,
                        "fsmon",
                        event.new_path,
                        event.process,
                        event.pid,
                        None,
                    )
                line_buffer.append((line_str, now))
                if event is not None:
                    try:
                        monitor_process_wrapper.record_event(
                            _recent_event_from_monitor_event(event, "fsmon", now)
                        )
                    except Exception:
                        logger.debug(
                            "Failed to record fsmon event history", exc_info=True
                        )

            def flush_to_ui() -> None:
                if not line_buffer:
                    return
                batch = list(line_buffer)
                line_buffer.clear()
                try:
                    self._call_from_thread(self._log_monitor_output_batch, batch)
                except Exception:
                    logger.debug("Failed to flush monitor batch to UI", exc_info=True)

        def read_output():
            """Read monitor output in background thread."""
            logger.info("monitor output reader thread started")
            process = monitor_process_wrapper.process
            last_flush = 0.0  # ensure first line triggers immediate flush
            first_line = True

            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                except Exception:
                    break
                if line:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if first_line:
                        logger.info("monitor reader: first output line received")
                        first_line = False
                    if line_str:
                        ingest(line_str)
                        now = time.monotonic()
                        if now - last_flush >= flush_interval:
                            flush_to_ui()
                            last_flush = now
                else:
                    time.sleep(0.01)

            # Final flush of remaining output
            flush_to_ui()

            # Drain remaining buffered output after process exits
            try:
                for line in process.stdout:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        ingest(line_str)
                flush_to_ui()
            except Exception:
                logger.debug("Failed to drain monitor output", exc_info=True)

            # Log process exit diagnostics
            exit_code = process.poll()
            logger.info("monitor process exited with code %s", exit_code)
            # A stop we asked for (o, Play's safety stop, quit) terminates the
            # reader with SIGTERM (-15): that is a normal stop, not a crash.
            intentional = bool(
                getattr(monitor_process_wrapper, "stop_requested", False)
            )
            if exit_code is not None and exit_code != 0 and not intentional:
                try:
                    self._call_from_thread(
                        self._log_warning,
                        f"monitor process exited unexpectedly (code {exit_code})",
                    )
                except Exception:
                    logger.debug("Failed to log monitor exit warning", exc_info=True)

            # Process ended
            try:
                self._call_from_thread(self._monitor_ended)
            except Exception:
                logger.debug("Failed to signal monitor ended", exc_info=True)

        thread = threading.Thread(target=read_output, daemon=True)
        thread.start()

    def _get_running_monitor_config(self) -> Any:
        """Best-effort fetch of the running monitor task's ``MonitorConfig``.

        Used once per batch flush to compute path-prefix candidates for
        ``build_monitor_item`` -- not looked up per line.
        """
        try:
            task = self._get_task_service().get_task("monitor")
            inst = getattr(task, "instance", None)
            return getattr(inst, "config", None)
        except Exception:
            return None

    def _log_monitor_output_batch(self, lines: list[str]) -> None:
        """Process a batch of monitor output lines (called from main thread).

        This replaces per-line ``_log_monitor_output`` to avoid flooding
        Textual's event loop. One ``call_from_thread`` delivers the entire
        batch instead of one message per event.

        Part B change: instead of formatting a final Rich-markup string per
        line and publishing one EventBus event per line, each line is
        parsed+categorized+prefix-stripped into a structured
        ``FileSystemMonitorItem`` (see ``build_monitor_item``), and the
        WHOLE BATCH is published as a SINGLE event (``_publish_monitor_batch``)
        -- grouping/dedup/visibility-filtering/tallying/width-aware
        rendering all now live in ``MonitorView`` (see B1), which needs the
        batch's items in order, with a real widget reference, to do any of
        that. Bus-publish only -- the old direct call into the Background
        Activity log was removed (that log now gets monitor lines a second
        time via the bus if not filtered by source, see
        ``MainScreen._handle_task_output``'s
        ``_ACTIVITY_LOG_EXCLUDED_SOURCES`` guard).

        Args:
            lines: Batch of output lines from the reader thread
        """
        prefix_candidates = _resolve_prefix_candidates(
            self._get_running_monitor_config()
        )

        items: list[FileSystemMonitorItem] = []
        for entry in lines:
            # A raw line, or (line, capture time) from the reader thread.
            line, stamp = entry if isinstance(entry, tuple) else (entry, None)
            try:
                items.append(build_monitor_item(line, prefix_candidates, stamp))
            except Exception:
                logger.debug("Failed to parse monitor line for batch", exc_info=True)

        # _publish_monitor_batch is a no-op on an empty list and swallows its
        # own EventBus-publish failures internally (matches the old
        # per-line _publish_monitor_event's error handling).
        _publish_monitor_batch(items)

    def _log_monitor_error(self, error: str) -> None:
        """Log monitor error to activity log.

        Args:
            error: Error message
        """
        self._log_error(f"Monitor error: {error}")

    def _monitor_ended(self) -> None:
        """Handle monitor process ending."""
        try:
            inst = getattr(
                self._get_task_service().get_task("monitor"), "instance", None
            )
        except Exception:
            inst = None
        process = getattr(inst, "process", None)
        try:
            exit_code = process.poll() if process is not None else None
        except Exception:
            exit_code = None
        intentional = getattr(inst, "stop_requested", False) is True
        # A snapshot load (not Play's own safety stop, which is intentional)
        # cut the monitor's adb stream: restart it with the same config once
        # the load has finished.
        resume_config = None
        if (
            not intentional
            and self._load_gen_at_start is not None
            and _load_generation() != self._load_gen_at_start
        ):
            resume_config = getattr(inst, "config", None)
        _timeline_monitor(
            "end",
            "monitor ended" if intentional else "monitor ended unexpectedly",
            level="info" if intentional else "warning",
            data={
                "exit_code": exit_code if isinstance(exit_code, int) else None,
                "intentional": intentional,
            },
            dev=getattr(inst, "timeline_serial", None),
        )
        if self._log_task_stopped:
            self._log_task_stopped("Monitor")
        else:
            self._log_info("Monitor stopped")

        task_service = self._get_task_service()

        # Teardown on the natural-exit path (process died / adb death). This
        # path calls unregister() and does NOT trigger stop_callback, so
        # without this a kprobe session's instance/probes/set_event_pid/buffer
        # would leak and wedge the next start. Idempotent (guarded by the
        # wrapper's _torn_down), so double-firing with stop() is harmless; a
        # no-op for fsmon (teardown=None). Run BEFORE unregister so the
        # instance is still fetchable.
        try:
            task = task_service.get_task("monitor")
            inst = getattr(task, "instance", None)
            # A requested stop (MonitorController.stop, Play's safety stop)
            # runs the teardown itself, off the UI thread: never here too.
            requested = getattr(inst, "stop_requested", False) is True
            if inst is not None and hasattr(inst, "run_teardown") and not requested:
                inst.run_teardown()
        except Exception:
            logger.debug("monitor teardown on natural exit failed", exc_info=True)

        # Unregister background task
        if task_service.is_running("monitor"):
            task_service.unregister("monitor")

        # Update UI
        if self._force_ui_refresh:
            self._force_ui_refresh()

        if resume_config is not None:
            self._resume_after_load = resume_config
            if _load_running():
                self._log_info(
                    "Monitor ended by the snapshot load: it restarts when the "
                    "load is done"
                )
            else:
                self._resume_monitor_after_load()

    def _resume_monitor_after_load(self) -> None:
        """Restart a monitor a snapshot load ended (UI thread; at most once)."""
        config, self._resume_after_load = self._resume_after_load, None
        if config is None or self.is_running() or self._start_pending:
            return
        self._log_info("Restarting the monitor after the snapshot load")
        self.resume_after_playback(config)

    def stop(self) -> bool:
        """Stop Monitor if running.

        Returns:
            True if Monitor was stopped
        """
        if not self.is_running():
            return False
        if self._stop_pending:
            return True  # already stopping

        # Say so at once: the caption shows "monitor stopping…" while the
        # trace reader is killed and the device cleaned up OFF the UI thread
        # (on the UI thread a stop froze the TUI for 12-18 s, with the old
        # caption still up).
        task_service = self._get_task_service()
        task = task_service.get_task("monitor")
        watch = getattr(getattr(task, "instance", None), "watch", None)
        if isinstance(watch, MonitorWatch):
            watch.stopping = True
        _timeline_monitor(
            "stop",
            "monitor stop requested",
            data={"requested": True},
            dev=getattr(getattr(task, "instance", None), "timeline_serial", None),
        )
        self._stop_pending = True
        _publish_monitor_info({"monitor_status": True})

        def _done() -> None:
            self._stop_pending = False
            self._log_info("Monitor stopped")
            if self._force_ui_refresh:
                self._force_ui_refresh()

        def _work() -> None:
            try:
                task_service.stop("monitor")
            except Exception:
                logger.debug("monitor stop failed", exc_info=True)
            finally:
                self._on_ui(_done)

        try:
            self._run_off_thread(_work)
        except Exception:
            logger.debug("monitor stop thread failed to start", exc_info=True)
            self._stop_pending = False
            task_service.stop("monitor")
            _done()

        return True

    def stop_from_ai(self) -> bool:
        """Stop the monitor from the AI tool-dispatch thread.

        ``stop()`` touches ``_log_info``/``_force_ui_refresh`` directly and
        assumes a main-thread caller, same class of issue as
        ``start_with_config``'s docstring describes on the start side. This
        marshals the whole call through ``call_from_thread`` instead of
        calling ``stop()`` directly.
        """
        return self._call_from_thread(self.stop)

    # =========================================================================
    # Resume after Play's snapshot-revert safety stop
    # =========================================================================

    def resume_after_playback(self, config: "MonitorConfig | None") -> bool:
        """Re-fork monitor after Play's snapshot revert auto-stopped it.

        Called from the main thread (this is a direct handler for
        MonitorView's "Resume monitoring" button — see ``app.py``'s
        ``resume_monitor_after_playback``), with the ``MonitorConfig`` monitor was
        running with just before ``RecordingController._stop_monitor_before_
        revert`` stopped it.

        In PID-mode, ``config.target_pid`` is almost always stale by the
        time Play finishes: the target app typically relaunches with a new
        PID during replay. This re-resolves the PID from ``config.app_name``
        (``Adb.get_pid_for_package_name``) before re-forking rather than
        trusting the stored one. If the app can no longer be found running,
        it falls back to path-mode (when ``config.target_path`` is
        available) instead of silently forking against a dead PID; if
        neither a fresh PID nor a path is available, it refuses to start at
        all and logs an explicit reason rather than failing silently.

        Reuses ``_start_monitor`` for the actual (re-)start rather than
        duplicating its binary-check/register/output-reader/open-files-tab
        sequence.

        Args:
            config: The MonitorConfig monitor was running with before the
                Play-triggered auto-stop. ``None`` (e.g. if it couldn't be
                recovered at stop time) is handled explicitly, not silently.

        Returns:
            True if monitor was successfully re-forked.
        """
        if config is None:
            self._log_warning(
                "Cannot resume monitoring: no prior Monitor configuration available."
            )
            return False

        if self.is_running() or self._start_pending:
            self._log_warning("Monitor is already running.")
            return False

        resolved = config
        if (
            config.mode == "pid"
            and getattr(config, "follow", False)
            and config.app_name
        ):
            # Following the app: no PID to re-resolve -- the session seeds
            # whatever of the app runs now and follows the rest.
            resolved = MonitorConfig(
                mode="pid",
                target_path=config.target_path,
                target_paths=config.target_paths,
                target_pid=None,
                app_name=config.app_name,
                backend=config.backend,
                follow=True,
            )
        elif config.mode == "pid":
            new_pid = None
            if config.app_name:
                try:
                    from sandroid.core.adb import Adb

                    new_pid = Adb.get_pid_for_package_name(
                        config.app_name, use_frida_fallback=False, quiet=True
                    )
                except Exception:
                    logger.debug("PID re-resolution failed", exc_info=True)
                    new_pid = None

            if new_pid:
                resolved = MonitorConfig(
                    mode="pid",
                    target_path=config.target_path,
                    target_paths=config.target_paths,
                    target_pid=new_pid,
                    app_name=config.app_name,
                    # Preserve the resolved backend so resume doesn't reset it
                    # (or re-run the kprobe preflight for an fsmon session).
                    backend=config.backend,
                )
            elif config.target_path:
                self._log_warning(
                    f"{config.app_name or 'Target app'} is no longer running — "
                    f"resuming in path mode ({config.target_path}) instead of "
                    "PID mode."
                )
                resolved = MonitorConfig(
                    mode="path",
                    target_path=config.target_path,
                    target_paths=config.target_paths,
                    target_pid=None,
                    app_name=config.app_name,
                    backend=config.backend,
                )
            else:
                self._log_warning(
                    f"Could not resume monitoring: {config.app_name or 'the target app'} "
                    "is no longer running and no path fallback was configured. "
                    "Start Monitor manually with 'o'."
                )
                return False

        return self._start_monitor(resolved)


__all__ = [
    "MONITOR_EVENT_INFO",
    "FileSystemMonitorItem",
    "KprobeStreamTranslator",
    "MonitorConfig",
    "MonitorController",
    "MonitorEvent",
    "MonitorItem",
    "build_monitor_item",
    "colorize_monitor_line",
    "format_monitor_event_row",
    "parse_monitor_line",
]
