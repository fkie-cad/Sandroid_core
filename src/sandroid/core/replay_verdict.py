"""The Rewind + Replay verdict of one file, from the Files lens's smart diff.

Rewind keeps three copies of every selected file: **Before**, **After** (your
run) and **After (replay)**. This module compares what the two runs changed
using the same structured diff the Files lens shows
(:func:`sandroid.core.file_inspect.structured_diff`): SQLite rows and
columns by their key, preference keys, JSON paths and text line blocks. It
builds no diff of its own; it only reads that diff as a change set.

* A = Before to After, R = Before to After (replay); each a change set
  ``{location: Change(old, new)}``.
* A location changed in only one of them, or with different old values:
  ``replay changed it differently``. Same location, same new value: same.
* Same location, different new value: a *volatile field* only when one rule
  matches (:func:`volatile_rule`), never by the field's name:

  1. ``time of its own run``: both values read as a time and each lies in
     its own run's window (start..end, :data:`SLACK_S` either side);
  2. ``same distance from its run``: both read as a time and their distance
     from their own run's start agrees within :data:`SLACK_S`;
  3. ``freshly generated ID``: same length and character class, random
     looking, and neither occurs anywhere in Before (:data:`FRESH_IDS`).

Volatile fields are never hidden: the result lists each with both values and
its rule. Files without a structured diff (binary, unknown, too many changed
rows) are compared byte for byte.
"""

from __future__ import annotations

import contextlib
import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sandroid.core import file_inspect

if TYPE_CHECKING:
    from collections.abc import Callable, Collection
    from pathlib import Path

#: Seconds a time may lie outside its run window (rules 1 and 2).
SLACK_S = 10.0
#: Rule 3 (freshly generated IDs). One switch, so the rule can be dropped.
FRESH_IDS = True
#: Shortest value rule 3 takes for an ID.
ID_MIN_LEN = 8
#: Changed rows per table a verdict reads (the Files lens keeps fewer).
VERDICT_ROW_LIMIT = 20_000
#: Longest value shown in a result line.
VALUE_MAX = 120

RULE_OWN_RUN = "time of its own run"
RULE_SAME_DISTANCE = "same distance from its run"
RULE_FRESH_ID = "freshly generated ID"

#: How the two runs were compared.
FIELD_BY_FIELD = "field by field"
BYTE_FOR_BYTE = "byte for byte"

#: Shown for a value that masking hides.
HIDDEN = "hidden (sensitive)"
#: Masked text inside a diff line.
MASK = "•••"

# outcomes (``rewind`` maps them to its plain words)
SAME = "same"
VOLATILE = "volatile"
DIFFERENT = "different"
UNCHANGED = "unchanged"


class _Absent:
    """A side where the field (row, key, file, lines) is not there."""

    def __repr__(self) -> str:
        return "ABSENT"


#: The value of a field that does not exist on that side.
ABSENT = _Absent()


@dataclass(frozen=True)
class RunWindow:
    """One run's time on the host clock (epoch seconds)."""

    start: float
    end: float


@dataclass
class Change:
    """One changed location: plain words for it, its old and new value."""

    where: str
    old: Any
    new: Any


@dataclass
class Volatile:
    """A field both runs changed to different values that a rule explains."""

    where: str
    run: str
    replay: str
    rule: str

    def as_dict(self) -> dict[str, str]:
        return {
            "field": self.where,
            "your_run": self.run,
            "replay": self.replay,
            "rule": self.rule,
        }


@dataclass
class Comparison:
    """The verdict of one file and why."""

    outcome: str
    compared: str = FIELD_BY_FIELD
    volatile: list[Volatile] = field(default_factory=list)
    only_run: list[str] = field(default_factory=list)
    only_replay: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# change sets from the Files lens's structured diff
# ---------------------------------------------------------------------------


def _row_where(table: str, key_text: str, column: str | None) -> str:
    row = f"row {key_text}" if key_text else "row"
    return f"{table}, {row}" + (f", column {column}" if column else "")


def _sqlite_changes(diff: file_inspect.StructuredDiff) -> dict[tuple, Change] | None:
    out: dict[tuple, Change] = {}
    for table in diff.tables:
        if table.truncated:
            return None
        if table.note:
            out[("table", table.name)] = Change(
                f"table {table.name}", ABSENT, table.note
            )
        for row in table.rows:
            key = tuple(row.key) if row.key else tuple(sorted(row.values.items()))
            if row.op == "update":
                for column, old, new in row.changes:
                    out[("cell", table.name, key, column)] = Change(
                        _row_where(table.name, row.key_text, column), old, new
                    )
                continue
            for column, value in row.values.items():
                old, new = (ABSENT, value) if row.op == "insert" else (value, ABSENT)
                out[("cell", table.name, key, column)] = Change(
                    _row_where(table.name, row.key_text, column), old, new
                )
    return out


def _key_changes(diff: file_inspect.StructuredDiff) -> dict[tuple, Change]:
    word = "path" if diff.kind == "json" else "key"
    out: dict[tuple, Change] = {}
    for kc in diff.keys:
        old = ABSENT if kc.op == "added" else kc.old
        new = ABSENT if kc.op == "removed" else kc.new
        out[("key", kc.key)] = Change(f"{word} {kc.key}", old, new)
    return out


def _block_where(at: int, n_old: int) -> str:
    if not n_old:
        return f"new lines after line {at - 1}" if at > 1 else "new lines at the start"
    return f"line {at}" if n_old == 1 else f"lines {at} to {at + n_old - 1}"


def _text_changes(diff: file_inspect.StructuredDiff) -> dict[tuple, Change]:
    """Line blocks keyed by where they start in the old file."""
    out: dict[tuple, Change] = {}
    for hunk in diff.hunks:
        pos = hunk.old_start - 1  # old lines before the current one
        block: list[Any] | None = None  # [at, old lines, new lines]

        def flush(b: list[Any] | None) -> None:
            if b is not None:
                at, old, new = b
                out[("lines", at)] = Change(
                    _block_where(at, len(old)),
                    tuple(old) if old else ABSENT,
                    tuple(new) if new else ABSENT,
                )

        for line in hunk.lines:
            if line.tag == " ":
                flush(block)
                block = None
                pos = line.old_no or pos
                continue
            if block is None:
                block = [pos + 1, [], []]
            if line.tag == "-":
                block[1].append(line.text)
                pos = line.old_no or pos
            else:
                block[2].append(line.text)
        flush(block)
    return out


def change_set(diff: file_inspect.StructuredDiff) -> dict[tuple, Change] | None:
    """``{location: Change}`` of a structured diff; None when the diff has
    no structure to compare (binary, unknown, an error, cut-off rows).
    """
    if diff.error:
        return None
    if diff.kind == "sqlite":
        return _sqlite_changes(diff)
    if diff.kind in ("xml", "abx", "json"):
        return _key_changes(diff)
    if diff.kind == "text":
        return _text_changes(diff)
    return None


def _structured(old: Path, new: Path) -> dict[tuple, Change] | None:
    diff = file_inspect.structured_diff(old, new)
    if diff.kind == "sqlite" and any(t.truncated for t in diff.tables):
        diff = file_inspect.sqlite_structured_diff(
            old, new, row_limit=VERDICT_ROW_LIMIT
        )
    return change_set(diff)


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------

_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_ISO = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?"
    r"(?:Z|[+-]\d{2}(?::?\d{2})?)?"
)
#: A token inside a string value: an ISO time first, else a word of
#: ID characters; everything between tokens must match exactly.
_TOKEN = re.compile(_ISO.pattern + r"|[A-Za-z0-9_.-]+")


def as_time(value: Any) -> float | None:
    """Epoch seconds of a value that reads as a time, else None.

    Unix seconds, milli-, micro- or nanoseconds (int, float or digit text;
    2001..2096 by magnitude) and ISO-8601 text (no zone: local time).
    """
    if isinstance(value, bool) or value is None or value is ABSENT:
        return None
    num: float | None = None
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if _NUMBER.fullmatch(text):
            num = float(text)
        elif _ISO.fullmatch(text):
            with contextlib.suppress(ValueError, OverflowError, OSError):
                when = datetime.fromisoformat(text.replace(",", "."))
                return when.timestamp()
            return None
    if num is None or not math.isfinite(num):
        return None
    for low, high, div, _unit in file_inspect._EPOCH_RANGES:
        if low <= abs(num) < high:
            return num / div
    return None


_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CLASSES = (
    ("UUID", _UUID),
    ("hex", re.compile(r"[0-9a-fA-F]+")),
    ("alnum", re.compile(r"[A-Za-z0-9]+")),
    ("base64url", re.compile(r"[A-Za-z0-9_-]+=*")),
)


def char_class(value: str) -> str | None:
    """``UUID`` / ``hex`` / ``alnum`` / ``base64url`` (the narrowest), else None."""
    for name, pattern in _CLASSES:
        if pattern.fullmatch(value):
            return name
    return None


def _same_class(a: str, b: str) -> bool:
    ca, cb = char_class(a), char_class(b)
    if ca is None or cb is None:
        return False
    # A random base64url value often has no ``-``/``_``: one class with alnum.
    wide = {"alnum", "base64url"}
    return ca == cb or (ca in wide and cb in wide)


def _random_looking(value: str) -> bool:
    if len(value) < ID_MIN_LEN:
        return False
    letters = value.replace("-", "").replace("_", "").rstrip("=")
    if letters.isalpha() and (
        letters.islower() or letters.isupper() or letters.istitle()
    ):
        return False  # a word, not an ID
    # Not one or two characters repeated (``00000001``, ``abababab``).
    return len(set(value)) >= max(3, min(len(value), 16) // 3)


def is_fresh_id(a: str, b: str, before: Callable[[], bytes]) -> bool:
    """Rule 3: ``a`` and ``b`` look like two freshly generated IDs."""
    if len(a) != len(b) or not _same_class(a, b):
        return False
    if not (_random_looking(a) and _random_looking(b)):
        return False
    blob = before()
    return a.encode() not in blob and b.encode() not in blob


@dataclass
class _Context:
    run: RunWindow | None
    replay: RunWindow | None
    before: Callable[[], bytes]
    fresh_ids: bool


def _in_window(t: float, w: RunWindow) -> bool:
    return w.start - SLACK_S <= t <= w.end + SLACK_S


def _scalar_rule(a: Any, b: Any, ctx: _Context) -> str | None:
    ta, tb = as_time(a), as_time(b)
    if ta is not None and tb is not None and ctx.run and ctx.replay:
        if _in_window(ta, ctx.run) and _in_window(tb, ctx.replay):
            return RULE_OWN_RUN
        if abs((ta - ctx.run.start) - (tb - ctx.replay.start)) <= SLACK_S:
            return RULE_SAME_DISTANCE
    if (
        ctx.fresh_ids
        and isinstance(a, str)
        and isinstance(b, str)
        and is_fresh_id(a, b, ctx.before)
    ):
        return RULE_FRESH_ID
    return None


def _split(text: str) -> list[str]:
    """Separators and tokens, alternating (separators at even indexes)."""
    out: list[str] = []
    pos = 0
    for m in _TOKEN.finditer(text):
        out += [text[pos : m.start()], m.group()]
        pos = m.end()
    out.append(text[pos:])
    return out


def _string_rules(a: str, b: str, ctx: _Context) -> list[str] | None:
    """Rules of every differing token of two strings that only differ in
    tokens (same text around them); None when one has no rule.
    """
    pa, pb = _split(a), _split(b)
    if len(pa) != len(pb) or len(pa) < 3:
        return None
    rules: list[str] = []
    for i, (x, y) in enumerate(zip(pa, pb, strict=True)):
        if x == y:
            continue
        rule = _scalar_rule(x, y, ctx) if i % 2 else None
        if rule is None:
            return None
        rules.append(rule)
    return rules or None


def volatile_rule(a: Any, b: Any, ctx: _Context) -> str | None:
    """The rule that explains two different new values, else None."""
    if a is ABSENT or b is ABSENT:
        return None
    if isinstance(a, tuple) and isinstance(b, tuple):  # a block of lines
        if len(a) != len(b):
            return None
        rules: list[str] = []
        for x, y in zip(a, b, strict=True):
            if x == y:
                continue
            found = _string_rules(x, y, ctx)
            if not found:
                return None
            rules += found
        return _join_rules(rules)
    rule = _scalar_rule(a, b, ctx)
    if rule is not None:
        return rule
    if isinstance(a, str) and isinstance(b, str):
        return _join_rules(_string_rules(a, b, ctx) or [])
    return None


def _join_rules(rules: list[str]) -> str | None:
    seen = list(dict.fromkeys(rules))
    return " and ".join(seen) if seen else None


# ---------------------------------------------------------------------------
# comparing
# ---------------------------------------------------------------------------


def value_text(value: Any) -> str:
    """A value as one short line (``not there`` for an absent side)."""
    if value is ABSENT:
        return "not there"
    if isinstance(value, tuple):
        text = " | ".join(value)
    else:
        text = file_inspect.format_value(value)
    return text if len(text) <= VALUE_MAX else text[: VALUE_MAX - 1] + "…"


def _change_line(c: Change) -> str:
    return f"{c.where}: {value_text(c.old)} to {value_text(c.new)}"


def _companions(path: Path) -> list[Path]:
    return [path] + [
        path.with_name(path.name + s)
        for s in file_inspect.SQLITE_COMPANIONS
        if path.with_name(path.name + s).is_file()
    ]


def _digest(path: Path | None) -> str | None:
    if path is None:
        return None
    h = hashlib.sha256()
    for p in _companions(path):
        with contextlib.suppress(OSError):
            h.update(p.name.encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def _bytes_of(path: Path | None) -> Callable[[], bytes]:
    cache: list[bytes] = []

    def read() -> bytes:
        if not cache:
            data = b""
            if path is not None:
                for p in _companions(path):
                    with contextlib.suppress(OSError):
                        data += p.read_bytes() + b"\0"
            cache.append(data)
        return cache[0]

    return read


def _byte_comparison(
    before: Path | None, after: Path | None, replay: Path | None
) -> Comparison:
    b, a, r = _digest(before), _digest(after), _digest(replay)
    if a == r:
        outcome = SAME
    elif r == b:
        outcome = UNCHANGED
    else:
        outcome = DIFFERENT
    return Comparison(outcome, compared=BYTE_FOR_BYTE)


def _deleted() -> dict[tuple, Change]:
    return {("file",): Change("the file", "there", ABSENT)}


def _changes(old: Path | None, new: Path | None) -> dict[tuple, Change] | None:
    if old is None and new is None:
        return {}
    if new is None:
        return _deleted()
    if old is None:
        return None  # a new file: compared After to After (replay)
    return _structured(old, new)


def _new_file(after: Path, replay: Path, ctx: _Context) -> Comparison:
    """A file both runs made: compare After to After (replay) directly."""
    diff = _structured(after, replay)
    if diff is None:
        return _byte_comparison(None, after, replay)
    res = Comparison(SAME)
    for c in diff.values():
        rule = volatile_rule(c.old, c.new, ctx)
        if rule:
            res.volatile.append(
                Volatile(c.where, value_text(c.old), value_text(c.new), rule)
            )
            continue
        if c.old is not ABSENT:
            res.only_run.append(f"{c.where}: {value_text(c.old)}")
        if c.new is not ABSENT:
            res.only_replay.append(f"{c.where}: {value_text(c.new)}")
    res.outcome = (
        DIFFERENT
        if res.only_run or res.only_replay
        else (VOLATILE if res.volatile else SAME)
    )
    return res


def compare(
    before: Path | None,
    after: Path | None,
    replay: Path | None,
    *,
    run: RunWindow | None = None,
    replay_run: RunWindow | None = None,
    fresh_ids: bool | None = None,
) -> Comparison:
    """The verdict of one file from its three local copies.

    ``None`` for a copy means the file was not on the device. ``run`` and
    ``replay_run`` are the two runs' windows (rules 1 and 2 need both);
    ``fresh_ids`` overrides :data:`FRESH_IDS`.
    """
    ctx = _Context(
        run,
        replay_run,
        _bytes_of(before),
        FRESH_IDS if fresh_ids is None else fresh_ids,
    )
    if before is None and after is not None and replay is not None:
        return _new_file(after, replay, ctx)
    run_set, rep_set = _changes(before, after), _changes(before, replay)
    if run_set is None or rep_set is None:
        return _byte_comparison(before, after, replay)
    if not rep_set:
        return Comparison(SAME if not run_set else UNCHANGED)
    res = Comparison(SAME)
    for loc in list(run_set) + [k for k in rep_set if k not in run_set]:
        a, r = run_set.get(loc), rep_set.get(loc)
        if r is None:
            res.only_run.append(_change_line(a))
        elif a is None:
            res.only_replay.append(_change_line(r))
        elif a.old != r.old or type(a.old) is not type(r.old):
            res.only_run.append(_change_line(a))
            res.only_replay.append(_change_line(r))
        elif a.new == r.new and type(a.new) is type(r.new):
            continue
        elif rule := volatile_rule(a.new, r.new, ctx):
            res.volatile.append(
                Volatile(a.where, value_text(a.new), value_text(r.new), rule)
            )
        else:
            res.only_run.append(_change_line(a))
            res.only_replay.append(_change_line(r))
    if res.only_run or res.only_replay:
        res.outcome = DIFFERENT
    elif res.volatile:
        res.outcome = VOLATILE
    return res


# ---------------------------------------------------------------------------
# masking
# ---------------------------------------------------------------------------


def hide(text: str, secrets: Collection[str]) -> str:
    """``text`` with every secret replaced by :data:`MASK`."""
    for s in sorted(secrets, key=len, reverse=True):
        if s:
            text = text.replace(s, MASK)
    return text


def hide_value(text: str, secrets: Collection[str]) -> str:
    """A shown value: :data:`HIDDEN` when it holds a secret."""
    return HIDDEN if any(s and s in text for s in secrets) else text
