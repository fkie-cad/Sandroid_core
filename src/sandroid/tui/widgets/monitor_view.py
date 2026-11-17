"""File-activity model behind the Files lens (non-visual).

The file monitor (``tui/controllers/monitor_controller.py``) publishes each
flush batch as ONE ``EventType.TASK_OUTPUT`` event with ``source="monitor"``
and ``data["batch"]`` a list of structured ``FileSystemMonitorItem``s. The
Files lens (:class:`~sandroid.tui.widgets.files_panel.FilesPanel`) feeds
those batches into :class:`FileActivity`, which owns everything that used to
live in the old Monitor sub-tab's ``MonitorView`` except the drawing:

* **tally** -- per-category counters, bumped for EVERY item unconditionally
  (the "always tally, conditionally render" invariant: the hidden-count in
  the lens caption must never undercount);
* **collapse per path** -- one :class:`PathActivity` per file (keyed by the
  full on-device path when the monitor provides it) with the ops seen, the
  event count, first/last time, the processes and a short event history.
  SQLite ``-wal``/``-journal`` writes fold onto their database (that is what
  the watchlist pulls, companions included);
* **visibility** -- ``tui.monitor_event_visibility`` (always/verbose/never per
  category, OPEN/CLOSE "noise" is verbose by default) plus path-based noise
  (caches, tmp files, OS paths). ``show_all`` (key ``v`` in the lens) reveals
  verbose categories and noisy paths; "never" stays hidden;
* **cap** -- ``tui.monitor_max_lines`` (default 500) bounds the number of
  tracked paths (least-recently touched paths are dropped first).

Pure Python, no Textual imports: unit-testable without a Pilot harness.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sandroid.tui.controllers.monitor_controller import FileSystemMonitorItem

#: category -> (op letter, colour). Order = display order of the ops column.
OPS: dict[str, tuple[str, str]] = {
    "create": ("C", "#4ade80"),
    "modify": ("M", "#a78bfa"),
    "rename": ("R", "#facc15"),
    "delete": ("D", "#fb7185"),
    "attrs": ("A", "#7dd3fc"),
    "noise": ("o", "#5b6479"),
}

#: Events kept per path for the Inspector's Events tab.
EVENTS_PER_PATH = 30

#: App-private data roots; stripped for the app-relative display path.
_APP_ROOT_RE = re.compile(r"^/data/(?:data|user/\d+|user_de/\d+)/[^/]+/")
_EXT_APP_ROOT_RE = re.compile(r"^/(?:sdcard|storage/emulated/\d+)/Android/data/[^/]+/")

#: Path segments that mark a file as noise (caches and temp files).
_NOISE_SEGMENTS = frozenset(
    {"cache", "code_cache", "app_webview", "tmp", "temp", ".tmp", "no_backup"}
)
#: Absolute prefixes of OS paths that are never the app's own data.
_OS_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/",
    "/system/",
    "/apex/",
    "/vendor/",
    "/product/",
    "/data/dalvik-cache/",
    "/data/misc/",
    "/data/system/",
    "/data/app/",
    "/data/local/tmp/",
)
_NOISE_SUFFIXES = (".tmp", ".bak", ".lck", ".lock", ".flock", "-shm")


def app_relative(path: str) -> str:
    """``/data/data/<pkg>/shared_prefs/x.xml`` -> ``shared_prefs/x.xml``."""
    for regex in (_APP_ROOT_RE, _EXT_APP_ROOT_RE):
        match = regex.match(path)
        if match:
            return path[match.end() :] or path
    return path


def is_noise_path(path: str) -> bool:
    """Caches, temp/lock files and OS paths (hidden unless "show all")."""
    if not path:
        return False
    if path.startswith(_OS_PREFIXES):
        return True
    rel = app_relative(path)
    parts = [p for p in rel.split("/") if p]
    if any(part.lower() in _NOISE_SEGMENTS for part in parts[:-1]):
        return True
    name = parts[-1].lower() if parts else ""
    return name.endswith(_NOISE_SUFFIXES) or name.startswith(".")


def smart_truncate(path: str, width: int) -> str:
    """Shorten ``path`` to ``width`` cells, keeping the filename whole.

    ``files/a/b/c/d/report.json`` -> ``files/…/d/report.json`` (head kept
    when it fits), ``databases/fittrack.db`` -> ``…/fittrack.db``; only a
    filename longer than ``width`` itself loses its start.
    """
    if width <= 1:
        return "…" if path else ""
    if len(path) <= width:
        return path
    parts = path.split("/")
    name = parts[-1]
    dirs = parts[:-1]
    for head in ([dirs[0] + "/…/"] if len(dirs) > 1 else []) + ["…/"]:
        if not dirs or len(head) + len(name) > width:
            continue
        tail = name
        for part in reversed(dirs[1:] if head != "…/" else dirs):
            candidate = f"{part}/{tail}"
            if len(head) + len(candidate) > width:
                break
            tail = candidate
        return head + tail
    return "…" + path[-(width - 1) :]


@dataclass
class FileEvent:
    """One monitor event on a path (for the Inspector's Events tab)."""

    when: datetime
    label: str
    category: str | None
    color: str | None
    process: str = ""
    other: str | None = None  # rename: the other side of the rename
    via: str = ""  # "-wal"/"-journal" when folded onto the database


@dataclass
class PathActivity:
    """Everything the monitor reported for one file, collapsed."""

    key: str  # full on-device path when known, else the monitor's display path
    count: int = 0
    ops: dict[str, int] = field(default_factory=dict)  # category -> count
    first: datetime | None = None
    last: datetime | None = None
    processes: dict[str, int] = field(default_factory=dict)
    events: deque[FileEvent] = field(
        default_factory=lambda: deque(maxlen=EVENTS_PER_PATH)
    )

    @property
    def rel(self) -> str:
        return app_relative(self.key)

    @property
    def last_category(self) -> str | None:
        return self.events[-1].category if self.events else None

    def op_letters(self) -> list[tuple[str, str]]:
        """``[(letter, colour)]`` in display order (``C M R D A o``)."""
        return [OPS[c] for c in OPS if self.ops.get(c)]

    def add(self, event: FileEvent) -> None:
        self.count += 1
        cat = event.category or "other"
        self.ops[cat] = self.ops.get(cat, 0) + 1
        if self.first is None:
            self.first = event.when
        self.last = event.when
        if event.process:
            self.processes[event.process] = self.processes.get(event.process, 0) + 1
        self.events.append(event)


_COMPANIONS = ("-wal", "-journal")


def split_companion(path: str) -> tuple[str, str]:
    """``app.db-wal`` -> ``("app.db", "-wal")``; other paths pass through."""
    for suffix in _COMPANIONS:
        if path.endswith(suffix) and len(path) > len(suffix):
            return path[: -len(suffix)], suffix
    return path, ""


def _join(directory: str | None, filename: str | None) -> str:
    directory = directory or ""
    filename = filename or ""
    return f"{directory}/{filename}" if directory else filename


class FileActivity:
    """Collapses monitor batches into one :class:`PathActivity` per file."""

    _CATEGORIES = ("create", "modify", "delete", "rename", "attrs", "noise")

    def __init__(
        self, visibility: dict[str, str] | None = None, max_paths: int = 500
    ) -> None:
        self.visibility: dict[str, str] = dict(visibility or {})
        self.max_paths = max(50, int(max_paths or 500))
        self.show_all = False
        self.paths: dict[str, PathActivity] = {}
        self.counts: dict[str, int] = dict.fromkeys(self._CATEGORIES, 0)
        self.total = 0

    # -- config ---------------------------------------------------------------

    @staticmethod
    def config_max_paths() -> int:
        """``tui.monitor_max_lines`` (the old log cap), default 500."""
        try:
            from sandroid.config.loader import ConfigLoader

            return ConfigLoader().load().tui.monitor_max_lines
        except Exception:
            return 500

    @staticmethod
    def config_visibility() -> dict[str, str]:
        """``tui.monitor_event_visibility``; ``{}`` (all "always") on error."""
        try:
            from sandroid.config.loader import ConfigLoader

            return dict(ConfigLoader().load().tui.monitor_event_visibility)
        except Exception:
            return {}

    # -- ingest ---------------------------------------------------------------

    def reset(self) -> None:
        self.paths.clear()
        self.counts = dict.fromkeys(self._CATEGORIES, 0)
        self.total = 0

    def _tally(self, category: str | None) -> None:
        """Bump the counters -- for EVERY item, visible or not."""
        self.total += 1
        if category in self.counts:
            self.counts[category] += 1

    def ingest(
        self, batch: Iterable[FileSystemMonitorItem], now: datetime | None = None
    ) -> set[str]:
        """Fold one monitor batch in; returns the keys of the touched paths.

        A rename is recorded on its destination (the file that exists
        afterwards) with the source noted on the event.
        """
        now = now or datetime.now()
        touched: set[str] = set()
        for item in batch:
            category = getattr(item, "category", None)
            self._tally(category)
            if self.category_mode(category) == "never":
                continue
            old = getattr(item, "path", "") or _join(item.directory, item.filename)
            new = getattr(item, "new_path", None)
            if new is None and getattr(item, "new_filename", None) is not None:
                new = _join(item.new_directory, item.new_filename)
            key, other = (new, old) if new else (old, None)
            if not key:
                continue
            key, via = split_companion(key)
            row = self.paths.get(key)
            if row is None:
                row = self.paths[key] = PathActivity(key=key)
            row.add(
                FileEvent(
                    when=now,
                    label=getattr(item, "label", "") or "",
                    category=category,
                    color=getattr(item, "color", None),
                    process=getattr(item, "process", "") or "",
                    other=other,
                    via=via,
                )
            )
            touched.add(key)
        self._evict()
        return touched

    def _evict(self) -> None:
        excess = len(self.paths) - self.max_paths
        if excess <= 0:
            return
        oldest = sorted(
            self.paths.values(),
            key=lambda r: (r.last is not None, r.last.timestamp() if r.last else 0),
        )
        for row in oldest[:excess]:
            self.paths.pop(row.key, None)

    # -- visibility -------------------------------------------------------------

    def category_mode(self, category: str | None) -> str:
        if not category:
            return "always"
        return self.visibility.get(category, "always")

    def is_quiet(self, row: PathActivity) -> bool:
        """True if ``row`` is noise: a noisy path or only verbose-tier ops."""
        if is_noise_path(row.key):
            return True
        return all(self.category_mode(c) == "verbose" for c in row.ops)

    def is_visible(self, row: PathActivity) -> bool:
        return self.show_all or not self.is_quiet(row)

    def visible_rows(self) -> list[PathActivity]:
        return [r for r in self.paths.values() if self.is_visible(r)]

    def hidden_count(self) -> int:
        """Paths currently hidden as noise (0 while showing all)."""
        if self.show_all:
            return 0
        return sum(1 for r in self.paths.values() if self.is_quiet(r))


__all__ = [
    "OPS",
    "FileActivity",
    "FileEvent",
    "PathActivity",
    "app_relative",
    "is_noise_path",
    "smart_truncate",
    "split_companion",
]
