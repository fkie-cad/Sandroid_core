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
  SQLite ``-wal``/``-journal``/``-shm`` events fold onto their database
  (that is what the watchlist pulls, companions included; a ``-shm`` write
  is no content change of the database, so it never counts as a write for
  auto-pull: SQLite touches it on every read). Keys are canonical
  (``adb_utils.canonical_device_path``): ``/data/user/0/<pkg>`` and
  ``/data/data/<pkg>`` are one row, ``databases/`` is ``databases``. A
  rename marks its source row "→ new name"; a deleted directory marks its
  known files deleted (``rm -r`` unlinks them by relative name, which the
  probes don't match);
* **visibility** -- ``tui.monitor_event_visibility`` (always/verbose/never per
  category, OPEN/CLOSE "noise" is verbose by default, i.e. open-only rows are
  hidden) plus the editable path rules ``tui.files_noise_rules``
  (:class:`NoiseRules`): *hide* rules (by default only OS paths such as
  ``/proc/`` or ``/data/dalvik-cache/`` -- never the app's own data, and not
  ``/data/local/tmp``) and *group* rules (``cache/``, ``code_cache/``: one
  expandable row per folder). ``show_all`` (key ``N`` in the lens) shows every
  path raw; "never" stays hidden;
* **segments** -- marks (``set_marks``) split the session into segments;
  every path keeps per-segment stats (:class:`SegmentStats`) so the lens can
  show "only what happened since mark N";
* **writes** -- after each :meth:`FileActivity.ingest`, ``writes`` lists the
  create/modify/rename-into events of that batch (what auto-pull acts on);
* **auto-groups** -- :func:`auto_group_folders`: many sibling files touched
  in one folder (``tui.files_auto_group_min``, default 20; machine-made
  names such as ``123`` / hex / UUIDs from 2/5 of it) fold into one group
  row, like a group rule's;
* **cap** -- ``tui.monitor_max_lines`` (default 500) bounds the number of
  rows (a group row is one slot). Over it, rule-hidden rows go first, then
  open-only rows, then the oldest shown rows; ``protected`` rows (the lens:
  watched and AI-highlighted files) are never dropped. ``dropped`` counts
  the files dropped, never silently.

Pure Python, no Textual imports: unit-testable without a Pilot harness.
"""

from __future__ import annotations

import bisect
import fnmatch
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from sandroid.config.schema import (
    FILES_OS_PREFIXES,
    FILES_RULE_ACTIONS,
    FILES_RULE_KINDS,
    default_files_noise_rules,
    files_noise_rules_overrides,
    merge_files_noise_rules,
)
from sandroid.core.adb_utils import canonical_device_path

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

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
#: category -> the lens theme token its letter / label is drawn in (the
#: colours above are the default theme's; ``op_color`` follows the theme).
OP_TOKENS: dict[str, str] = {
    "create": "ok",
    "modify": "screen",
    "rename": "warn",
    "delete": "bad",
    "attrs": "title",
    "noise": "dim",
}


def op_color(category: str | None) -> str | None:
    """The running theme's colour of an op category (None: unknown)."""
    token = OP_TOKENS.get(category or "")
    if token is None:
        return None
    from sandroid.tui.themes import lens_palette

    return str(getattr(lens_palette(), token))


#: Events kept per path for the Inspector's Events tab.
EVENTS_PER_PATH = 30

#: App-private data roots; stripped for the app-relative display path. The
#: device-encrypted (``user_de``) and external (``Android/data``) roots are
#: different directories, so they keep a short marker (``@de/``, ``@ext/``)
#: and never read like the main data directory's ``files/x``.
_APP_ROOT_RE = re.compile(r"^/data/(?:data|user/\d+)/[^/]+/")
_DE_APP_ROOT_RE = re.compile(r"^/data/user_de/\d+/[^/]+/")
_EXT_APP_ROOT_RE = re.compile(r"^/(?:sdcard|storage/emulated/\d+)/Android/data/[^/]+/")

#: The default hide prefixes, rule kinds/actions and rules live with the
#: config schema (``tui.files_noise_rules``).
OS_PREFIXES = FILES_OS_PREFIXES
RULE_KINDS = FILES_RULE_KINDS
RULE_ACTIONS = FILES_RULE_ACTIONS
DEFAULT_NOISE_RULES: tuple[dict, ...] = tuple(default_files_noise_rules())


@dataclass(frozen=True)
class NoiseRule:
    """One path rule of the Files lens.

    ``kind``: ``prefix`` (absolute path starts with it), ``segment`` (a
    directory of the path is named so, case-insensitive), ``suffix`` (the
    file name ends with it, case-insensitive) or ``glob`` (``fnmatch`` on the
    absolute or the app-relative path). ``action``: ``hide`` the row, or
    ``group`` it into one row per folder.
    """

    action: str
    kind: str
    pattern: str
    enabled: bool = True
    #: A rule for this session only (``M`` in the lens): never saved.
    session: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> NoiseRule | None:
        try:
            action = str(data.get("action", "hide"))
            kind = str(data.get("kind", ""))
            pattern = str(data.get("pattern", ""))
        except AttributeError:
            return None
        if action not in RULE_ACTIONS or kind not in RULE_KINDS or not pattern:
            return None
        return cls(
            action,
            kind,
            pattern,
            bool(data.get("enabled", True)),
            bool(data.get("session", False)),
        )

    def to_dict(self) -> dict:
        out = {
            "action": self.action,
            "kind": self.kind,
            "pattern": self.pattern,
            "enabled": self.enabled,
        }
        if self.session:
            out["session"] = True
        return out

    def folder_for(self, path: str) -> str | None:
        """The folder this rule matches ``path`` by (``None``: no match).

        ``segment``: the path up to the matching directory; ``prefix``: the
        prefix itself; ``suffix``/``glob``: the file's own directory.
        """
        if not path:
            return None
        head, _sep, name = path.rpartition("/")
        if self.kind == "prefix":
            prefix = self.pattern
            if path.startswith(prefix) or path == prefix.rstrip("/"):
                return prefix.rstrip("/") or "/"
            return None
        if self.kind == "segment":
            wanted = self.pattern.strip("/").lower()
            parts = path.split("/")
            for i, part in enumerate(parts[:-1]):
                if part and part.lower() == wanted:
                    return "/".join(parts[: i + 1])
            return None
        if self.kind == "suffix":
            return head if name.lower().endswith(self.pattern.lower()) else None
        if self.kind == "glob":
            rel = app_relative(path)
            hit = fnmatch.fnmatchcase(path, self.pattern) or (
                rel != path and fnmatch.fnmatchcase(rel, self.pattern)
            )
            return head if hit else None
        return None

    def label(self) -> str:
        return f"{self.kind} {self.pattern}"


class NoiseRules:
    """The ordered rule list; :meth:`classify` answers per path (cached)."""

    def __init__(self, rules: Iterable[NoiseRule | dict] | None = None) -> None:
        parsed: list[NoiseRule] = []
        source = DEFAULT_NOISE_RULES if rules is None else rules
        for rule in source:
            if isinstance(rule, dict):
                rule = NoiseRule.from_dict(rule)
            if isinstance(rule, NoiseRule):
                parsed.append(rule)
        self.rules: list[NoiseRule] = parsed
        self._cache: dict[str, tuple[str, NoiseRule, str] | None] = {}

    @classmethod
    def from_config(cls) -> NoiseRules:
        """``tui.files_noise_rules`` of the live config (defaults on error)."""
        try:
            from sandroid.config import get_config

            return cls(merge_files_noise_rules(get_config().tui.files_noise_rules))
        except Exception:
            return cls()

    def to_list(self) -> list[dict]:
        return [rule.to_dict() for rule in self.rules]

    def saved_list(self) -> list[dict]:
        """What to save in the config: the user's changes to the defaults
        (own rules, defaults turned off); session-only rules left out.
        """
        return files_noise_rules_overrides(
            [rule.to_dict() for rule in self.rules if not rule.session]
        )

    def classify(self, path: str) -> tuple[str, NoiseRule, str] | None:
        """``("hide", rule, folder)`` / ``("group", rule, folder)`` or None.

        Hide rules win over group rules; within an action the first enabled
        matching rule wins.
        """
        if path in self._cache:
            return self._cache[path]
        result = None
        for action in RULE_ACTIONS:
            for rule in self.rules:
                if not rule.enabled or rule.action != action:
                    continue
                folder = rule.folder_for(path)
                if folder is not None:
                    result = (action, rule, folder)
                    break
            if result is not None:
                break
        if len(self._cache) > 20000:
            self._cache.clear()
        self._cache[path] = result
        return result

    def hidden_by(self, path: str) -> NoiseRule | None:
        hit = self.classify(path)
        return hit[1] if hit is not None and hit[0] == "hide" else None

    def group_of(self, path: str) -> str | None:
        """The group folder of ``path`` (``None`` if not grouped)."""
        hit = self.classify(path)
        return hit[2] if hit is not None and hit[0] == "group" else None


_PKG_OF_RE = re.compile(
    r"^/(?:data/(?:data|user/\d+|user_de/\d+)|"
    r"(?:sdcard|storage/emulated/\d+)/Android/data)/([^/]+)/"
)


def app_package(path: str) -> str | None:
    """The package whose data directory holds ``path`` (``None`` otherwise)."""
    match = _PKG_OF_RE.match(path)
    return match.group(1) if match else None


def app_relative(path: str) -> str:
    """``/data/data/<pkg>/shared_prefs/x.xml`` -> ``shared_prefs/x.xml``.

    ``/data/user_de/0/<pkg>/x`` -> ``@de/x`` and
    ``/sdcard/Android/data/<pkg>/x`` -> ``@ext/x`` (other directories).
    """
    for regex, marker in (
        (_APP_ROOT_RE, ""),
        (_DE_APP_ROOT_RE, "@de/"),
        (_EXT_APP_ROOT_RE, "@ext/"),
    ):
        match = regex.match(path)
        if match:
            rest = path[match.end() :]
            return marker + rest if rest else path
    return path


#: A machine-made file name (after one short extension is dropped): all
#: digits, 8+ hex digits, or a UUID.
_MACHINE_NAME_RE = re.compile(
    r"^(?:\d+|[0-9a-f]{8,}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_SHORT_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,5}$")


def machine_name(name: str) -> bool:
    """``123``, ``0a1b2c3d4e``, ``<uuid>.tmp``, ``<hash>.0.tmp`` (an atomic
    write's temp file): a name no person typed. Up to two short
    extensions are dropped.
    """
    stem = name
    for _ in range(2):
        if _MACHINE_NAME_RE.match(stem):
            return True
        stem = _SHORT_EXT_RE.sub("", stem) or stem
    return bool(_MACHINE_NAME_RE.match(stem))


def machine_group_min(min_count: int) -> int:
    """The auto-group threshold for machine-made names: 2/5 of
    ``min_count`` (8 at the default 20), at least 2; 0 when grouping is off.
    """
    if min_count <= 0:
        return 0
    return min(min_count, max(2, (min_count * 2) // 5))


def auto_group_folders(keys: Iterable[str], min_count: int) -> dict[str, list[str]]:
    """``{folder: member keys}`` for the folders with many touched siblings.

    A folder folds when ``min_count`` (0 = never) of ``keys`` are directly
    in it, or when :func:`machine_group_min` of them have machine-made names
    (an IndexedDB attachment store's ``1``, ``2``, ... ``445``) and those
    are at least 80 % of the members -- a few companions such as a
    DiskLruCache ``journal`` beside its ``<hash>.0`` files do not stop it.
    Generic on purpose: no app or path list.
    """
    if min_count <= 0:
        return {}
    by_folder: dict[str, list[str]] = {}
    for key in keys:
        folder, sep, name = key.rpartition("/")
        if sep and folder and name:
            by_folder.setdefault(folder, []).append(key)
    low = machine_group_min(min_count)
    out: dict[str, list[str]] = {}
    for folder, members in by_folder.items():
        n = len(members)
        machine = sum(1 for k in members if machine_name(k.rpartition("/")[2]))
        if n >= min_count or (machine >= low and machine * 5 >= n * 4):
            out[folder] = members
    return out


_DEFAULT_RULES: NoiseRules | None = None


def is_noise_path(path: str) -> bool:
    """A path the *default* hide rules hide (OS paths; never app data)."""
    global _DEFAULT_RULES
    if _DEFAULT_RULES is None:
        _DEFAULT_RULES = NoiseRules()
    return bool(path) and _DEFAULT_RULES.hidden_by(path) is not None


def smart_truncate(path: str, width: int) -> str:
    """Shorten ``path`` to ``width`` cells, keeping the filename whole.

    ``files/a/b/c/d/report.json`` -> ``files/…/d/report.json`` (head kept
    when it fits), ``databases/fittrack.db`` -> ``…/fittrack.db``; only a
    filename longer than ``width`` itself loses its start.

    A directory that does not fit whole is not dropped when there is room
    for a useful part of it: its middle is elided instead. The per-origin
    storage of a browser is ``…/storage/default/<origin>/ls/data.sqlite``
    -- the origin is what tells the rows apart (E2E: every one read
    ``files/…/ls/data.sqlite``), so at 40 cells it reads
    ``files/…/688012…,heise.de)/ls/data.sqlite`` (scheme dropped, %XX decoded).
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
        rest = list(dirs[1:] if head != "…/" else dirs)
        while rest:
            candidate = f"{rest[-1]}/{tail}"
            if len(head) + len(candidate) > width:
                break
            tail = candidate
            rest.pop()
        room = width - len(head) - len(tail) - 1
        if rest and room >= _MIN_PARTIAL:
            tail = f"{_mid_elide(_readable_dir(rest[-1]), room)}/{tail}"
        return head + tail
    return "…" + path[-(width - 1) :]


#: The smallest useful part of an elided directory name (``smart_truncate``).
_MIN_PARTIAL = 8


def _readable_dir(name: str) -> str:
    """A browser origin directory, shortened for an elided path:
    ``https+++a.net^partitionKey=%28https%2Cheise.de%29`` ->
    ``a.net^(https,heise.de)`` (scheme prefix dropped, %XX decoded).
    """
    from urllib.parse import unquote

    text = re.sub(r"^[a-z][a-z0-9.+-]*\+\+\+", "", name)
    return unquote(text.replace("^partitionKey=", "^"))


def _mid_elide(text: str, width: int) -> str:
    """``text`` in ``width`` cells: its start and (a bit more of) its end."""
    if len(text) <= width:
        return text
    left = (width - 1) * 2 // 5
    right = width - 1 - left
    return text[:left] + "…" + text[-right:]


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
    #: Set when the event was derived rather than reported for this path:
    #: "parent" (its directory was deleted), "renamed" (moved away).
    source: str = ""
    #: The writing process (kprobe: its TGID; fsmon: as reported) and
    #: thread (kprobe only: ``process`` is then "<process> · <thread>" or
    #: the thread's name; fsmon's ``process`` is the process's name).
    pid: int | None = None
    tid: int | None = None


@dataclass
class SegmentStats:
    """What happened to one path within one mark segment."""

    count: int = 0
    ops: dict[str, int] = field(default_factory=dict)
    first: datetime | None = None
    last: datetime | None = None

    def op_letters(self) -> list[tuple[str, str]]:
        return [(OPS[c][0], op_color(c) or OPS[c][1]) for c in OPS if self.ops.get(c)]

    def add(self, event: FileEvent) -> None:
        self.count += 1
        cat = event.category or "other"
        self.ops[cat] = self.ops.get(cat, 0) + 1
        if self.first is None:
            self.first = event.when
        if cat != "noise" or self.last is None or set(self.ops) == {"noise"}:
            self.last = event.when


@dataclass
class PathActivity:
    """Everything the monitor reported for one file, collapsed."""

    key: str  # full on-device path when known, else the monitor's display path
    count: int = 0
    ops: dict[str, int] = field(default_factory=dict)  # category -> count
    first: datetime | None = None
    last: datetime | None = None
    processes: dict[str, int] = field(default_factory=dict)
    #: Events per writing process (pid), and the app-process label each
    #: pid was seen with ("main", "tab_17"; "" when none).
    pids: dict[int, int] = field(default_factory=dict)
    pid_labels: dict[int, str] = field(default_factory=dict)
    events: deque[FileEvent] = field(
        default_factory=lambda: deque(maxlen=EVENTS_PER_PATH)
    )
    #: Where the file went when it was renamed away (cleared by any later
    #: event on this path, e.g. a re-create).
    moved_to: str | None = None
    #: A directory (mkdir seen, or files below it).
    is_dir: bool = False
    #: Per mark segment (0 = before the first mark): see ``FileActivity``.
    segments: dict[int, SegmentStats] = field(default_factory=dict)

    @property
    def rel(self) -> str:
        return app_relative(self.key)

    @property
    def last_category(self) -> str | None:
        return self.events[-1].category if self.events else None

    @property
    def deleted(self) -> bool:
        """The last real (non-noise) event on the file itself deleted it.

        Companion events (``-wal``/``-journal`` folded onto the database)
        never decide: SQLite deletes its rollback journal at the end of
        every transaction while the database stays.
        """
        for event in reversed(self.events):
            if event.category != "noise" and not event.via:
                return event.category == "delete"
        return False

    def op_letters(self) -> list[tuple[str, str]]:
        """``[(letter, colour)]`` in display order (``C M R D A o``), in the
        running theme's colours.
        """
        return [(OPS[c][0], op_color(c) or OPS[c][1]) for c in OPS if self.ops.get(c)]

    def stats(self, segment: int | None) -> SegmentStats | None:
        """The stats of one segment (``None``: the whole session)."""
        if segment is None:
            return SegmentStats(self.count, self.ops, self.first, self.last)
        return self.segments.get(segment)

    def add(self, event: FileEvent, segment: int = 0) -> None:
        self.segments.setdefault(segment, SegmentStats()).add(event)
        self.count += 1
        cat = event.category or "other"
        self.ops[cat] = self.ops.get(cat, 0) + 1
        if self.first is None:
            self.first = event.when
        # OPEN/CLOSE noise never re-dates a row that has real activity.
        if cat != "noise" or self.last is None or set(self.ops) == {"noise"}:
            self.last = event.when
        if event.process:
            self.processes[event.process] = self.processes.get(event.process, 0) + 1
        if event.pid is not None:
            self.pids[event.pid] = self.pids.get(event.pid, 0) + 1
            head, sep, _thread = event.process.partition(" · ")
            if sep and not head.startswith("pid "):
                self.pid_labels[event.pid] = head
            elif event.tid is None and event.process:
                self.pid_labels[event.pid] = event.process  # fsmon
            else:
                self.pid_labels.setdefault(event.pid, "")
        if event.source != "renamed" and cat != "noise":
            self.moved_to = None
        if event.label == "CREATE DIR":
            self.is_dir = True
        self.events.append(event)


_COMPANIONS = ("-wal", "-journal", "-shm")
#: Companions whose writes say nothing about the database's content
#: (``-shm`` is the WAL index, rewritten on reads too): no auto-pull.
_INDEX_COMPANIONS = ("-shm",)


def split_companion(path: str) -> tuple[str, str]:
    """``app.db-wal`` -> ``("app.db", "-wal")`` (also ``-journal``,
    ``-shm``); other paths pass through.
    """
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

    #: Categories whose event on a path means its content may have changed.
    WRITE_CATEGORIES = ("create", "modify", "rename")

    #: Tracked files never exceed this many times ``max_paths``, groups
    #: included (memory bound; the oldest group members go, counted).
    HARD_CAP_FACTOR = 20

    def __init__(
        self,
        visibility: dict[str, str] | None = None,
        max_paths: int = 500,
        rules: NoiseRules | None = None,
        auto_group_min: int = 20,
    ) -> None:
        self.visibility: dict[str, str] = dict(visibility or {})
        self.max_paths = max(50, int(max_paths or 500))
        #: ``tui.files_auto_group_min`` (0 = no auto-groups).
        self.auto_group_min = max(0, int(auto_group_min or 0))
        #: ``protected(key)``: a row the cap never drops (the lens: watched
        #: and AI-highlighted files).
        self.protected: Callable[[str], bool] | None = None
        #: Files dropped at the row cap (never silently: the caption says
        #: so), each counted once however often it comes back and goes again.
        self._dropped_keys: set[str] = set()
        self.show_all = False
        self.rules: NoiseRules = rules if rules is not None else NoiseRules()
        self.paths: dict[str, PathActivity] = {}
        self.counts: dict[str, int] = dict.fromkeys(self._CATEGORIES, 0)
        self.total = 0
        #: Sorted mark times; an event's segment = marks at or before it.
        self.mark_times: list[datetime] = []
        #: ``(key, when, category)`` of the last batch's writes (create,
        #: modify, rename-into; companions folded onto their database).
        self.writes: list[tuple[str, datetime, str]] = []
        #: thread id -> its process (TGID), from every event that carried
        #: both: a thread's first events may name only the thread (kprobe
        #: "(-------)" without a follow table, i.e. Path mode).
        self.thread_pids: dict[int, int] = {}

    @property
    def dropped(self) -> int:
        """How many different files the row cap has dropped."""
        return len(self._dropped_keys)

    def set_marks(self, times: Iterable[datetime]) -> None:
        self.mark_times = sorted(times)

    def segment_of(self, when: datetime) -> int:
        """0 before the first mark, N after the N-th mark."""
        return bisect.bisect_right(self.mark_times, when)

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
    def config_auto_group_min() -> int:
        """``tui.files_auto_group_min``, default 20 (0 = off)."""
        try:
            from sandroid.config.loader import ConfigLoader

            return int(ConfigLoader().load().tui.files_auto_group_min)
        except Exception:
            return 20

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
        self._dropped_keys.clear()
        self.thread_pids.clear()

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
        self.writes = []
        segment = self.segment_of(now)
        for item in batch:
            category = getattr(item, "category", None)
            self._tally(category)
            if self.category_mode(category) == "never":
                continue
            old = getattr(item, "path", "") or _join(item.directory, item.filename)
            new = getattr(item, "new_path", None)
            if new is None and getattr(item, "new_filename", None) is not None:
                new = _join(item.new_directory, item.new_filename)
            old = canonical_device_path(old) if old else old
            new = canonical_device_path(new) if new else new
            key, other = (new, old) if new else (old, None)
            if not key:
                continue
            if category == "attrs" and "/" not in key:
                continue  # an unresolved dentry basename: no orphan rows
            key, via = split_companion(key)
            row = self.paths.get(key)
            if row is None:
                row = self.paths[key] = PathActivity(key=key)
                parent = self.paths.get(key.rsplit("/", 1)[0])
                if parent is not None:
                    parent.is_dir = True
            event = FileEvent(
                when=now,
                label=getattr(item, "label", "") or "",
                category=category,
                color=getattr(item, "color", None),
                process=getattr(item, "process", "") or "",
                other=other,
                via=via,
                pid=getattr(item, "pid", None),
                tid=getattr(item, "tid", None),
            )
            if event.pid is not None and event.tid is not None:
                if event.pid != event.tid:
                    self.thread_pids[event.tid] = event.pid
            row.add(event, segment)
            touched.add(key)
            if (
                category in self.WRITE_CATEGORIES
                and event.label != "CREATE DIR"
                and via not in _INDEX_COMPANIONS
            ):
                self.writes.append((key, now, category))
            if other and category == "rename":
                touched |= self._mark_moved(
                    split_companion(other)[0], key, event, segment
                )
            if category == "delete":
                touched |= self._mark_descendants_deleted(row, event, segment)
        self._evict()
        return touched

    def _mark_moved(
        self, old: str, new: str, event: FileEvent, segment: int = 0
    ) -> set[str]:
        """The source row of a rename says where the file went."""
        row = self.paths.get(old)
        if row is None or old == new:
            return set()
        row.add(
            FileEvent(
                when=event.when,
                label="RENAMED",
                category="rename",
                color=event.color,
                process=event.process,
                other=new,
                source="renamed",
                pid=event.pid,
                tid=event.tid,
            ),
            segment,
        )
        row.moved_to = new
        return {old}

    def _mark_descendants_deleted(
        self, row: PathActivity, event: FileEvent, segment: int = 0
    ) -> set[str]:
        """A deleted directory takes its known files with it.

        ``rm -r`` unlinks the children with relative names, which the
        path-filtered probes don't match; only the directory itself shows up.
        """
        prefix = row.key.rstrip("/") + "/"
        touched: set[str] = set()
        for key, child in self.paths.items():
            if key.startswith(prefix) and not child.deleted:
                child.add(
                    FileEvent(
                        when=event.when,
                        label="DELETE",
                        category="delete",
                        color=event.color,
                        process=event.process,
                        other=row.key,
                        source="parent",
                        pid=event.pid,
                        tid=event.tid,
                    ),
                    segment,
                )
                touched.add(key)
        if touched:
            row.is_dir = True
        return touched

    def _is_protected(self, key: str) -> bool:
        check = self.protected
        if check is None:
            return False
        try:
            return bool(check(key))
        except Exception:
            return False

    def drop_tier(self, row: PathActivity) -> int:
        """Eviction order at the cap: 0 hidden by a rule, 1 open-only,
        2 shown (whatever ``show_all`` says: the default view decides).
        """
        if self.rules.hidden_by(row.key) is not None:
            return 0
        if row.ops and all(self.category_mode(c) == "verbose" for c in row.ops):
            return 1
        return 2

    @staticmethod
    def _age(row: PathActivity) -> float:
        return row.last.timestamp() if row.last else 0.0

    def slots(self) -> tuple[list[tuple[int, float, list[str]]], int]:
        """``([(tier, last, keys)], protected)``: the rows the cap counts.

        A group row (a group rule's folder or an auto-group) is ONE slot
        with all its files; protected rows are counted, never listed.
        """
        out: list[tuple[int, float, list[str]]] = []
        groups: dict[str, list[PathActivity]] = {}
        candidates: list[PathActivity] = []
        n_protected = 0
        for key, row in self.paths.items():
            if self._is_protected(key):
                n_protected += 1
                continue
            tier = self.drop_tier(row)
            if tier < 2:
                out.append((tier, self._age(row), [key]))
                continue
            folder = self.rules.group_of(key)
            if folder is not None:
                groups.setdefault(folder, []).append(row)
            else:
                candidates.append(row)
        auto = auto_group_folders((r.key for r in candidates), self.auto_group_min)
        grouped = {k for members in auto.values() for k in members}
        for row in candidates:
            if row.key in grouped:
                groups.setdefault(row.key.rpartition("/")[0], []).append(row)
            else:
                out.append((2, self._age(row), [row.key]))
        for members in groups.values():
            last = max(self._age(r) for r in members)
            out.append((2, last, [r.key for r in members]))
        return out, n_protected

    def _evict(self) -> None:
        """Keep the rows within ``max_paths`` (see the module docstring)."""
        if len(self.paths) <= self.max_paths:
            return  # never more slots than files
        slots, n_protected = self.slots()
        excess = len(slots) + n_protected - self.max_paths
        if excess > 0:
            slots.sort(key=lambda s: (s[0], s[1]))
            for _tier, _last, keys in slots[:excess]:
                for key in keys:
                    if self.paths.pop(key, None) is not None:
                        self._dropped_keys.add(key)
        hard = self.max_paths * self.HARD_CAP_FACTOR
        if len(self.paths) > hard:
            rows = sorted(
                (r for k, r in self.paths.items() if not self._is_protected(k)),
                key=lambda r: (self.drop_tier(r), self._age(r)),
            )
            for row in rows[: len(self.paths) - hard]:
                self.paths.pop(row.key, None)
                self._dropped_keys.add(row.key)

    # -- visibility -------------------------------------------------------------

    def category_mode(self, category: str | None) -> str:
        if not category:
            return "always"
        return self.visibility.get(category, "always")

    def hide_reason(self, row: PathActivity, segment: int | None = None) -> str | None:
        """Why ``row`` is hidden by default: a rule kind or ``"open-only"``.

        ``None`` when it is shown (also for every row while ``show_all``).
        ``segment`` judges "open-only" by that segment's ops.
        """
        if self.show_all:
            return None
        rule = self.rules.hidden_by(row.key)
        if rule is not None:
            return rule.kind
        stats = row.stats(segment)
        ops = stats.ops if stats is not None else row.ops
        if ops and all(self.category_mode(c) == "verbose" for c in ops):
            return "open-only"
        return None

    def is_quiet(self, row: PathActivity) -> bool:
        """True if ``row`` is hidden by a rule or has only verbose-tier ops."""
        if self.rules.hidden_by(row.key) is not None:
            return True
        return all(self.category_mode(c) == "verbose" for c in row.ops)

    def is_visible(self, row: PathActivity) -> bool:
        return self.show_all or not self.is_quiet(row)

    def visible_rows(self) -> list[PathActivity]:
        return [r for r in self.paths.values() if self.is_visible(r)]

    def hidden_count(self) -> int:
        """Paths currently hidden (0 while showing all)."""
        if self.show_all:
            return 0
        return sum(1 for r in self.paths.values() if self.is_quiet(r))


__all__ = [
    "DEFAULT_NOISE_RULES",
    "OPS",
    "OS_PREFIXES",
    "RULE_ACTIONS",
    "RULE_KINDS",
    "FileActivity",
    "FileEvent",
    "NoiseRule",
    "NoiseRules",
    "PathActivity",
    "SegmentStats",
    "app_package",
    "app_relative",
    "auto_group_folders",
    "is_noise_path",
    "machine_group_min",
    "machine_name",
    "smart_truncate",
    "split_companion",
]
