"""Files lens Inspector: the Versions and Content tabs and the diff renderer.

* **Versions** -- every kept pull of a watched file, newest first
  (``v3 · 10:42:07 · 1.2 MB · auto · moz_places +3 ~1 · moz_meta ~3``).
  The selected version's diff against the version before it (or against a
  marked base) is drawn below the list.
* **Content** -- a first look inside the selected version's local copy:
  SQLite tables (row counts) and the rows of one table, preference keys,
  JSON, text, image facts or a hex dump.

Data comes from :mod:`sandroid.core.file_inspect` (structured diffs and
previews of the local copies; never the device) and
:mod:`sandroid.core.watchlist_store` (``version_dirs`` / ``version_time`` /
``version_diff`` / ``version_record`` / ``version_file``).

Every renderable here adapts to the width it is drawn at: a SQLite row is a
horizontal table when its columns fit, otherwise a "card" (column names
down the left, one or more rows side by side). The Inspector is ~55 columns
wide; the zoom view (``z``) draws the same data with nothing truncated.

Keys (MainScreen bindings that act on ``InspectorContent.keys``): ``<``/``>``
older/newer version (Versions tab) or previous/next table (Content tab),
``B`` diff the selected version against this one (base) -- press again to
clear; a click on a version or table selects it.

Heavy work (SQLite diffs of large files) runs on a thread with a
"computing..." placeholder; results are cached per version pair (kept
versions never change).
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from textual.binding import Binding
from textual.containers import ScrollableContainer, Vertical
from textual.widgets import Label, Static

from sandroid.core import file_inspect as fi
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import Console, ConsoleOptions, RenderableType, RenderResult
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

_DIM = "#5b6479"
_MUTED = "#8f9bb3"
_TEXT = "#d6deeb"
_ACCENT = "#7dd3fc"
_ADD = "#4ade80"
_ADD_SOFT = "#a7f3c5"
_DEL = "#fb7185"
_DEL_SOFT = "#fecdd3"
_CHG = "#facc15"
_SEL = "on #142640"
_HEAD = "bold #e2e8f0 on #1d3150"

#: Rows of one table shown in the Inspector (the zoom view shows all kept).
INSPECTOR_ROWS = 6
#: Keys / text lines shown in the Inspector before "z for all".
INSPECTOR_KEYS = 40
INSPECTOR_LINES = 60
#: Files up to this size are diffed / previewed on the UI thread.
INLINE_BYTES = 4 * 1024 * 1024

HINT_VERSIONS = "< > older/newer · B base · z zoom · click picks"
HINT_TABLES = "< > previous/next table · z zoom · click picks"

Section = tuple[str, Any]


# ---------------------------------------------------------------------------
# small text helpers
# ---------------------------------------------------------------------------


def _clip(text: str, limit: int | None) -> str:
    if limit is None or len(text) <= limit:
        return text
    return text[: max(1, limit - 1)] + "…"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _when(when: datetime | None) -> str:
    if when is None:
        return "—"
    if when.date() == datetime.now().date():
        return when.strftime("%H:%M:%S")
    return when.strftime("%m-%d %H:%M")


def value_text(
    value: Any, column: str = "", style: str = "", full: bool = False
) -> Text:
    """One cell: the raw value plus a dim time hint for epoch-like ints."""
    if value is None:
        return Text("NULL", style=f"italic {_DIM}")
    raw = fi.format_value(value)
    text = Text(raw if full else _clip(raw, 400), style=style)
    hint = fi.timestamp_hint(value, column)
    if hint:
        text.append("\n" + hint, style=_DIM)
    return text


def _common_affixes(old: str, new: str) -> tuple[int, int]:
    prefix = 0
    limit = min(len(old), len(new))
    while prefix < limit and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and old[-1 - suffix] == new[-1 - suffix]:
        suffix += 1
    return prefix, suffix


def _marked(
    value: str, prefix: int, suffix: int, budget: int | None, style: str
) -> Text:
    """``value`` with its changed middle emphasised, clipped around it."""
    mid_end = len(value) - suffix
    start = 0
    if budget is not None and len(value) > budget:
        start = max(0, min(prefix - 8, len(value) - budget + 1))
    out = Text(style=style)
    if start:
        out.append("…", style=_DIM)
    out.append(value[start:prefix])
    out.append(value[prefix:mid_end], style=f"bold underline {style}")
    out.append(value[mid_end:])
    if budget is not None and out.cell_len > budget:
        out.truncate(budget, overflow="ellipsis")
    return out


def change_text(old: Any, new: Any, column: str = "", budget: int | None = 40) -> Text:
    """``old → new`` (one line when short, else ``- old`` / ``+ new``) with
    the changed part of long strings emphasised and time hints for epochs.
    """
    o, n = fi.format_value(old), fi.format_value(new)
    old_style = _DEL if old is not None else f"italic {_DIM}"
    new_style = _ADD if new is not None else f"italic {_DIM}"
    out = Text()
    if budget is None or len(o) + len(n) + 3 <= budget:
        out.append(o, style=old_style)
        out.append(" → ", style=_DIM)
        out.append(n, style=f"bold {new_style}")
    else:
        prefix, suffix = _common_affixes(o, n)
        width = None if budget is None else max(8, budget - 2)
        out.append("− ", style=_DEL)
        out.append_text(_marked(o, prefix, suffix, width, old_style))
        out.append("\n+ ", style=_ADD)
        out.append_text(_marked(n, prefix, suffix, width, new_style))
    h_old, h_new = fi.timestamp_hint(old, column), fi.timestamp_hint(new, column)
    if h_old or h_new:
        out.append(f"\n{h_old or '—'} → {h_new or '—'}", style=_DIM)
    return out


def _counts_text(table: fi.TableDiff, width: int) -> Text:
    words = width >= 52
    out = Text()
    for n, sym, word, style in (
        (table.inserted, "+", "inserted", _ADD),
        (table.updated, "~", "updated", _CHG),
        (table.deleted, "−", "deleted", _DEL),
    ):
        if n:
            out.append(f"{sym}{n}" + (f" {word}" if words else ""), style=style)
            out.append("  ")
    out.rstrip()
    return out


# ---------------------------------------------------------------------------
# structured diff renderer
# ---------------------------------------------------------------------------


class DiffRenderable:
    """A :class:`~sandroid.core.file_inspect.StructuredDiff`, laid out for the
    width it is drawn at. ``full`` (zoom): every kept row, nothing clipped.
    """

    def __init__(self, diff: fi.StructuredDiff, full: bool = False) -> None:
        self.diff = diff
        self.full = full

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        width = max(30, options.max_width)
        yield from render_diff_parts(self.diff, width, self.full)


def render_diff_parts(diff: fi.StructuredDiff, width: int, full: bool) -> list:
    parts: list = []
    if diff.error:
        parts.append(Text(diff.error, style=_DEL))
        return parts
    if diff.empty:
        parts.append(Text("No change.", style=_DIM))
        return parts
    if diff.kind == "sqlite":
        for i, table in enumerate(diff.tables):
            if i:
                parts.append(Text(""))
            parts.extend(_sqlite_table_parts(table, width, full))
        if diff.source == "text" and not full:
            parts.append(Text(""))
            parts.append(
                Text("Column names: the stored text diff has none.", style=_DIM)
            )
    elif diff.keys:
        parts.extend(_key_parts(diff, width, full))
    elif diff.hunks:
        parts.extend(_hunk_parts(diff, width, full))
    elif diff.binary is not None:
        parts.extend(_binary_parts(diff.binary, width))
    return parts


def _sqlite_table_parts(table: fi.TableDiff, width: int, full: bool) -> list:
    head = Text()
    head.append(f" {table.name} ", style=_HEAD)
    head.append("  ")
    head.append_text(_counts_text(table, width - len(table.name) - 4))
    parts: list = [head]
    if table.note:
        parts.append(Text(table.note, style=f"italic {_MUTED}"))
    rows = table.rows if full else table.rows[:INSPECTOR_ROWS]
    shown = 0
    for op in ("insert", "update", "delete"):
        batch = [r for r in rows if r.op == op]
        if not batch:
            continue
        if op == "update":
            parts.append(_updates_grid(batch, width, full))
        else:
            parts.extend(_record_parts(table, batch, op, width, full))
        shown += len(batch)
    hidden = table.total - shown
    if hidden > 0:
        more = f"… {hidden} more row{'s' if hidden != 1 else ''}"
        if not full:
            more += " — z shows " + (
                "all" if not table.truncated else f"{len(table.rows)}"
            )
        parts.append(Text(more, style=_DIM))
    return parts


def _row_label(row: fi.RowChange, index: int) -> str:
    if row.key:
        if len(row.key) == 1:
            col, value = row.key[0]
            v = fi.format_value(value)
            return f"{col} {v}" if col in ("rowid", "id", "_id") else f"{col}={v}"
        return row.key_text
    return f"row {index + 1}"


def _record_parts(
    table: fi.TableDiff, rows: list[fi.RowChange], op: str, width: int, full: bool
) -> list:
    mark, style, soft = (
        ("+", _ADD, _ADD_SOFT) if op == "insert" else ("−", _DEL, _DEL_SOFT)
    )
    cols = list(table.columns) or sorted({c for r in rows for c in r.values})
    if len(cols) * 11 + 2 <= width:
        return [_horizontal_rows(cols, rows, mark, style, soft, full)]
    word = "+ inserted" if op == "insert" else "− deleted"
    name_w = min(18, max([len(c) for c in cols] + [len(word)]))
    per = 1 if width < 52 else max(1, min(len(rows), (width - name_w - 2) // 20))
    # A single-column key is in the card's header; not repeated below it.
    key_cols = {r.key[0][0] for r in rows if len(r.key) == 1}
    parts: list = []
    for start in range(0, len(rows), per):
        chunk = rows[start : start + per]
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(width=name_w, no_wrap=True, overflow="ellipsis", style=_MUTED)
        for _ in chunk:
            grid.add_column(
                ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis"
            )
        grid.add_row(
            Text(word, style=f"bold {style}"),
            *[
                Text(_row_label(r, start + i), style=f"bold {style}")
                for i, r in enumerate(chunk)
            ],
        )
        nulls = []
        for col in cols:
            if col in key_cols:
                continue
            values = [r.values.get(col) for r in chunk]
            if all(v is None for v in values):
                nulls.append(col)
                continue
            grid.add_row(col, *[value_text(v, col, soft, full) for v in values])
        parts.append(grid)
        if nulls:
            parts.append(
                Text(
                    _clip("NULL: " + ", ".join(nulls), None if full else width),
                    style=_DIM,
                )
            )
    return parts


def _horizontal_rows(cols, rows, mark, style, soft, full) -> Table:
    table = Table(
        box=None,
        padding=(0, 1),
        show_edge=False,
        header_style=f"bold {_MUTED}",
        expand=False,
        pad_edge=False,
    )
    table.add_column("", style=f"bold {style}", no_wrap=True, width=1)
    for col in cols:
        table.add_column(
            col,
            no_wrap=not full,
            overflow="fold" if full else "ellipsis",
            max_width=None if full else 40,
            min_width=min(8, len(col)),
        )
    for row in rows:
        table.add_row(
            mark, *[value_text(row.values.get(c), c, soft, full) for c in cols]
        )
    return table


def _updates_grid(rows: list[fi.RowChange], width: int, full: bool) -> Table:
    key_w = max((len(_row_label(r, i)) for i, r in enumerate(rows)), default=4) + 2
    col_w = max((len(c) for r in rows for c, _o, _n in r.changes), default=5)
    need = max(
        (
            len(fi.format_value(o)) + len(fi.format_value(n)) + 3
            for r in rows
            for _c, o, n in r.changes
        ),
        default=10,
    )
    if not full:
        # The change gets what it needs (up to 24 cells); key / column
        # names shrink first, but not below 12 / 10.
        room = width - 2 - min(need, 24)
        while key_w + col_w > room and (key_w > 12 or col_w > 10):
            if key_w > 12 and key_w >= col_w:
                key_w -= 1
            elif col_w > 10:
                col_w -= 1
            else:
                key_w -= 1
    budget = None if full else max(16, width - key_w - col_w - 2)
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(width=key_w, no_wrap=True, overflow="ellipsis")
    grid.add_column(width=col_w, no_wrap=True, overflow="ellipsis", style=_TEXT)
    grid.add_column(ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis")
    for i, row in enumerate(rows):
        label = Text("~ ", style=f"bold {_CHG}")
        label.append(_row_label(row, i), style=_MUTED)
        if not row.changes:
            grid.add_row(label, "", Text("changed (values unknown)", style=_DIM))
        for j, (col, old, new) in enumerate(row.changes):
            grid.add_row(
                label if j == 0 else "", col, change_text(old, new, col, budget)
            )
    return grid


def _key_parts(diff: fi.StructuredDiff, width: int, full: bool) -> list:
    keys = diff.keys if full else diff.keys[:INSPECTOR_KEYS]
    added, changed, removed = diff.counts()
    head = Text()
    title = {"json": "JSON keys", "abx": "ABX keys", "xml": "keys"}.get(
        diff.kind, "keys"
    )
    head.append(f" {title} ", style=_HEAD)
    head.append("  ")
    for n, label, style in (
        (changed, "~", _CHG),
        (added, "+", _ADD),
        (removed, "−", _DEL),
    ):
        if n:
            word = {"~": "changed", "+": "added", "−": "removed"}[label]
            head.append(f"{label}{n} {word}", style=style)
            head.append("  ")
    head.rstrip()
    show_type = width >= 46 and any(k.type for k in keys)
    key_w = min(28 if not full else 60, max((len(k.key) for k in keys), default=4))
    type_w = min(8, max((len(k.type) for k in keys), default=0)) if show_type else 0
    budget = None if full else max(14, width - key_w - type_w - 6)
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(width=1, no_wrap=True)
    grid.add_column(
        width=key_w, no_wrap=not full, overflow="fold" if full else "ellipsis"
    )
    if show_type:
        grid.add_column(width=type_w, no_wrap=True, overflow="ellipsis", style=_DIM)
    grid.add_column(ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis")
    for change in keys:
        mark, style = {
            "changed": ("~", _CHG),
            "added": ("+", _ADD),
            "removed": ("−", _DEL),
        }[change.op]
        key = Text(
            change.key, style=f"bold {style}" if change.op == "changed" else style
        )
        if change.op == "changed":
            value: Text = change_text(change.old, change.new, change.key, budget)
        elif change.op == "added":
            value = value_text(change.new, change.key, _ADD_SOFT, full)
        else:
            value = value_text(change.old, change.key, _DEL_SOFT, full)
        cells = [Text(mark, style=f"bold {style}"), key]
        if show_type:
            cells.append(Text(change.type))
        cells.append(value)
        grid.add_row(*cells)
    parts: list = [head, grid]
    if len(keys) < len(diff.keys):
        parts.append(
            Text(f"… {len(diff.keys) - len(keys)} more — z shows all", style=_DIM)
        )
    return parts


def _hunk_parts(diff: fi.StructuredDiff, width: int, full: bool) -> list:
    numbers = [
        n for h in diff.hunks for ln in h.lines for n in (ln.old_no, ln.new_no) if n
    ]
    num_w = max(2, len(str(max(numbers, default=1))))
    added, _changed, removed = diff.counts()
    head = Text()
    head.append(" lines ", style=_HEAD)
    head.append("  ")
    if added:
        head.append(f"+{added} added  ", style=_ADD)
    if removed:
        head.append(f"−{removed} removed", style=_DEL)
    head.rstrip()
    parts: list = [head]
    budget = INSPECTOR_LINES
    for hunk in diff.hunks:
        if not full and budget <= 0:
            break
        old_n = sum(1 for ln in hunk.lines if ln.tag != "+")
        new_n = sum(1 for ln in hunk.lines if ln.tag != "-")
        parts.append(
            Text(
                f"@@ −{hunk.old_start},{old_n} +{hunk.new_start},{new_n} @@",
                style=f"{_ACCENT}",
            )
        )
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(width=num_w, justify="right", style=_DIM, no_wrap=True)
        grid.add_column(width=num_w, justify="right", style=_DIM, no_wrap=True)
        grid.add_column(
            ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis"
        )
        lines = hunk.lines if full else hunk.lines[: max(0, budget)]
        budget -= len(lines)
        for ln in lines:
            style = {
                "+": f"{_ADD_SOFT} on #10261b",
                "-": f"{_DEL_SOFT} on #2b1419",
            }.get(ln.tag, "#9aa5b8")
            mark = {"+": "+", "-": "−"}.get(ln.tag, " ")
            grid.add_row(
                str(ln.old_no or ""),
                str(ln.new_no or ""),
                Text(f"{mark} {ln.text.expandtabs(4)}", style=style),
            )
        parts.append(grid)
    total = sum(len(h.lines) for h in diff.hunks)
    if not full and total > INSPECTOR_LINES:
        parts.append(Text(f"… {total} diff lines — z shows all", style=_DIM))
    return parts


def _hex_line(
    data: bytes, other: bytes, start: int, per: int, style: str, ascii_: bool
) -> Text:
    out = Text()
    for i in range(per):
        if i < len(data):
            differs = i >= len(other) or data[i] != other[i]
            out.append(f"{data[i]:02x}", style=f"bold {style}" if differs else _MUTED)
        else:
            out.append("  ")
        out.append(" ")
    if ascii_:
        out.append(" ")
        for i, b in enumerate(data[:per]):
            ch = chr(b) if 32 <= b < 127 else "·"
            differs = i >= len(other) or b != other[i]
            out.append(ch, style=f"bold {style}" if differs else _DIM)
    return out


def _binary_parts(change: fi.BinaryChange, width: int) -> list:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_DIM, no_wrap=True)
    grid.add_column()
    grid.add_row(
        "size",
        change_text(fi.format_size(change.old_size), fi.format_size(change.new_size)),
    )
    grid.add_row(
        "sha256",
        Text.assemble(
            (change.old_sha256[:12] + "…", _DEL),
            (" → ", _DIM),
            (change.new_sha256[:12] + "…", _ADD),
        ),
    )
    if change.offset is not None:
        grid.add_row(
            "first diff",
            Text(f"at byte {change.offset} (0x{change.offset:x})", style=_CHG),
        )
    parts: list = [Text(" binary ", style=_HEAD), grid]
    if change.offset is None:
        return parts
    per = 16 if width >= 58 else 8
    ascii_ = width >= 76
    hexes = Table.grid(padding=(0, 1))
    hexes.add_column(style=_DIM, no_wrap=True)
    hexes.add_column(no_wrap=True)
    hexes.add_column(no_wrap=True)
    end = max(len(change.old_bytes), len(change.new_bytes))
    for off in range(0, end, per):
        old = change.old_bytes[off : off + per]
        new = change.new_bytes[off : off + per]
        addr = f"{change.window_start + off:06x}"
        if old:
            hexes.add_row(
                addr, Text("−", style=_DEL), _hex_line(old, new, off, per, _DEL, ascii_)
            )
        if new:
            hexes.add_row(
                "" if old else addr,
                Text("+", style=_ADD),
                _hex_line(new, old, off, per, _ADD, ascii_),
            )
    parts.append(hexes)
    return parts


# ---------------------------------------------------------------------------
# content (preview) renderer
# ---------------------------------------------------------------------------


class PreviewRenderable:
    """A :class:`~sandroid.core.file_inspect.Preview`; ``full`` = zoom."""

    def __init__(self, preview: fi.Preview, full: bool = False) -> None:
        self.preview = preview
        self.full = full

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        yield from render_preview_body(
            self.preview, max(30, options.max_width), self.full
        )


def table_list(preview: fi.Preview, width: int = 60) -> Table:
    """One line per SQLite table / view; the shown one highlighted."""
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(width=1, no_wrap=True)
    grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
    grid.add_column(no_wrap=True, justify="right")
    for t in preview.tables:
        selected = t.name == preview.table
        rows = (
            "virtual"
            if t.kind == "virtual"
            else (
                "?" if t.rows is None else f"{t.rows:,} row{'s' if t.rows != 1 else ''}"
            )
        )
        if t.kind == "view":
            rows = "view · " + rows
        name_style = f"bold {_ACCENT}" if selected else _TEXT
        grid.add_row(
            Text("▸" if selected else " ", style=f"bold {_ACCENT}"),
            Text(t.name, style=name_style),
            Text(f"{rows} · {len(t.columns)} cols", style=_MUTED if selected else _DIM),
            style=_SEL if selected else "",
        )
    return grid


def _rows_table(
    columns: list[str], rows: list[tuple], width: int, full: bool
) -> tuple[Table, int]:
    """Rows of a table as a horizontal table; columns that do not fit the
    width are left out (returned count) unless ``full``.
    """
    shown = list(range(len(columns)))
    if not full:
        widths = []
        for i, col in enumerate(columns):
            sample = [len(fi.format_value(r[i])) for r in rows[:50]]
            widths.append(max(min(len(col), 14), min(max(sample, default=4), 22)))
        used, keep = 2, []
        for i, w in enumerate(widths):
            if used + w + 1 > width and keep:
                break
            keep.append(i)
            used += w + 1
        shown = keep
    table = Table(
        box=None,
        padding=(0, 1),
        show_edge=False,
        header_style=f"bold {_MUTED}",
        row_styles=["", "on #0b1220"],
        pad_edge=False,
        expand=False,
    )
    for i in shown:
        table.add_column(
            columns[i],
            no_wrap=True,
            overflow="ellipsis",
            max_width=60 if full else 22,
        )
    for row in rows:
        cells = []
        for i in shown:
            value = row[i] if i < len(row) else None
            if value is None:
                cells.append(Text("NULL", style=f"italic {_DIM}"))
                continue
            text = Text(fi.format_value(value))
            hint = fi.timestamp_hint(value, columns[i])
            if hint and full:
                text.append(f" ({hint})", style=_DIM)
            cells.append(text)
        table.add_row(*cells)
    return table, len(columns) - len(shown)


def _json_tree(data: Any, label: str = "$", budget: list[int] | None = None) -> Tree:
    budget = budget if budget is not None else [400]
    tree = Tree(Text(label, style=_ACCENT), guide_style=_DIM)

    def add(node: Tree, value: Any) -> None:
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, child in items:
            if budget[0] <= 0:
                node.add(Text("…", style=_DIM))
                return
            budget[0] -= 1
            name = f"{key}" if isinstance(value, dict) else f"[{key}]"
            if isinstance(child, (dict, list)) and child:
                kind = (
                    f"{{{len(child)}}}"
                    if isinstance(child, dict)
                    else f"[{len(child)}]"
                )
                add(node.add(Text.assemble((name, _TEXT), (f" {kind}", _DIM))), child)
            else:
                leaf = Text.assemble((name, _TEXT), (": ", _DIM))
                leaf.append_text(
                    value_text(
                        child, str(key), _ADD_SOFT if isinstance(child, str) else ""
                    )
                )
                node.add(leaf)

    if isinstance(data, (dict, list)):
        add(tree, data)
    else:
        tree.add(value_text(data))
    return tree


def _hex_dump(head: bytes, width: int) -> Table:
    per = 16 if width >= 58 else 8
    ascii_ = width >= 76 or per == 8
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=_DIM, no_wrap=True)
    grid.add_column(no_wrap=True, style=_MUTED)
    if ascii_:
        grid.add_column(no_wrap=True, style=_DIM)
    for off in range(0, len(head), per):
        chunk = head[off : off + per]
        cells = [f"{off:06x}", " ".join(f"{b:02x}" for b in chunk)]
        if ascii_:
            cells.append("".join(chr(b) if 32 <= b < 127 else "·" for b in chunk))
        grid.add_row(*cells)
    return grid


def render_preview_body(preview: fi.Preview, width: int, full: bool) -> list:
    """The content below the facts line (the SQLite table list is separate)."""
    parts: list = []
    if preview.error:
        parts.append(Text(preview.error, style=_DEL))
    kind = preview.kind
    if kind == "sqlite":
        if preview.table is None:
            parts.append(Text("No tables.", style=_DIM))
            return parts
        rows = preview.rows if full else preview.rows[:60]
        table, hidden = _rows_table(preview.columns, rows, width, full)
        parts.append(table)
        notes = []
        if hidden:
            notes.append(f"+{hidden} more columns")
        total = next((t.rows for t in preview.tables if t.name == preview.table), None)
        if len(rows) < (total or 0):
            notes.append(f"{len(rows)} of {total:,} rows")
        if notes and not full:
            parts.append(Text(" · ".join(notes) + " — z shows them", style=_DIM))
        elif notes:
            parts.append(Text(" · ".join(notes), style=_DIM))
        return parts
    if kind in ("xml", "abx"):
        keys = preview.keys if full else preview.keys[: INSPECTOR_KEYS * 2]
        key_w = min(
            30 if not full else 70, max((len(k) for k, _t, _v in keys), default=4)
        )
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(
            width=key_w,
            no_wrap=not full,
            overflow="fold" if full else "ellipsis",
            style=_TEXT,
        )
        grid.add_column(
            width=min(8, max((len(t) for _k, t, _v in keys), default=0)),
            style=_DIM,
            no_wrap=True,
        )
        grid.add_column(
            ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis"
        )
        for key, typ, value in keys:
            grid.add_row(
                key,
                typ,
                value_text(value, key, _ADD_SOFT if typ == "string" else "", full),
            )
        parts.append(grid)
        if len(keys) < len(preview.keys):
            parts.append(Text(f"… {len(preview.keys)} keys — z shows all", style=_DIM))
        return parts
    if kind == "json":
        parts.append(_json_tree(preview.data, "$", [10_000 if full else 150]))
        return parts
    if kind == "text":
        lines = preview.lines if full else preview.lines[:120]
        grid = Table.grid(padding=(0, 1), expand=True)
        num_w = len(str(max(1, len(lines))))
        grid.add_column(width=num_w, justify="right", style=_DIM, no_wrap=True)
        grid.add_column(
            ratio=1, no_wrap=not full, overflow="fold" if full else "ellipsis"
        )
        for i, line in enumerate(lines, 1):
            grid.add_row(str(i), Text(line.expandtabs(4), style=_TEXT))
        parts.append(grid)
        if preview.total_lines > len(lines):
            more = f"{len(lines)} of {preview.total_lines} lines"
            parts.append(
                Text(more + ("" if full else " — z shows the first 400"), style=_DIM)
            )
        return parts
    if kind == "image":
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=_DIM)
        grid.add_column()
        info = preview.image
        grid.add_row("format", info.get("format", preview.type_guess))
        if "width" in info:
            grid.add_row("pixels", f"{info['width']} × {info.get('height', '?')}")
        if "bit_depth" in info:
            grid.add_row("bit depth", str(info["bit_depth"]))
        parts.append(grid)
        parts.append(Text("First bytes", style=f"bold {_MUTED}"))
        parts.append(_hex_dump(preview.head[:64], width))
        return parts
    parts.append(Text(f"First {len(preview.head)} bytes", style=f"bold {_MUTED}"))
    parts.append(_hex_dump(preview.head, width))
    return parts


# ---------------------------------------------------------------------------
# state, cache, background jobs
# ---------------------------------------------------------------------------


@dataclass
class InspectState:
    """Per inspected file: selected version (dir name; None = newest), the
    marked base version, and the SQLite table shown in Content.
    """

    selected: str | None = None
    base: str | None = None
    table: str | None = None


_STATES: dict[str, InspectState] = {}


def state_for(key: str) -> InspectState:
    state = _STATES.get(key)
    if state is None:
        state = _STATES[key] = InspectState()
    return state


class _LRU:
    def __init__(self, size: int) -> None:
        self.size = size
        self.data: OrderedDict = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            if key in self.data:
                self.data.move_to_end(key)
                return self.data[key]
        return None

    def put(self, key, value) -> None:
        with self.lock:
            self.data[key] = value
            self.data.move_to_end(key)
            while len(self.data) > self.size:
                self.data.popitem(last=False)

    def clear(self) -> None:
        with self.lock:
            self.data.clear()


_DIFFS = _LRU(48)
_PREVIEWS = _LRU(32)
_SUMMARIES = _LRU(512)
_PENDING: set = set()
_PENDING_LOCK = threading.Lock()


def clear_caches() -> None:
    _DIFFS.clear()
    _PREVIEWS.clear()
    _SUMMARIES.clear()
    _STATES.clear()


def _size_of(*paths: Path | None) -> int:
    total = 0
    for p in paths:
        if p is None:
            continue
        for suffix in ("", "-wal", "-journal"):
            try:
                total += Path(str(p) + suffix).stat().st_size
            except OSError:
                pass
    return total


def _computed(
    cache: _LRU, key, fn: Callable[[], Any], size: int, notify
) -> tuple[Any, bool]:
    """``(value, pending)``: cached, computed inline, or started on a thread."""
    value = cache.get(key)
    if value is not None:
        return value, False
    if size <= INLINE_BYTES or notify is None:
        value = fn()
        cache.put(key, value)
        return value, False
    with _PENDING_LOCK:
        if key in _PENDING:
            return None, True
        _PENDING.add(key)

    def work() -> None:
        try:
            cache.put(key, fn())
        except Exception:
            logger.debug("file_inspect job failed", exc_info=True)
        finally:
            with _PENDING_LOCK:
                _PENDING.discard(key)
        try:
            notify()
        except Exception:
            logger.debug("file_inspect notify failed", exc_info=True)

    threading.Thread(target=work, name="file-inspect", daemon=True).start()
    return None, True


def structured_for(
    old: Path, new: Path, notify=None
) -> tuple[fi.StructuredDiff | None, bool]:
    key = ("diff", str(old), str(new))
    return _computed(
        _DIFFS, key, lambda: fi.structured_diff(old, new), _size_of(old, new), notify
    )


def preview_for(
    path: Path, table: str | None, notify=None
) -> tuple[fi.Preview | None, bool]:
    key = ("preview", str(path), table)
    return _computed(
        _PREVIEWS, key, lambda: fi.preview_file(path, table), _size_of(path), notify
    )


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------


@dataclass
class Version:
    number: int  # 1 = oldest kept
    dir: Path
    file: Path
    when: datetime | None
    size: int | None
    record: dict | None

    @property
    def name(self) -> str:
        return self.dir.name

    @property
    def trigger(self) -> str:
        record = self.record or {}
        return str(record.get("trigger") or "")


def load_versions(path: str) -> list[Version]:
    """Kept versions of ``path``, oldest first."""
    from sandroid.core import watchlist_store as store

    out: list[Version] = []
    try:
        dirs = store.version_dirs(path)
    except Exception:
        return out
    for n, d in enumerate(dirs, 1):
        file = _version_file(store, d, path)
        size = _size_of(file) if file.exists() else None
        try:
            record = (
                store.version_record(d) if hasattr(store, "version_record") else None
            )
        except Exception:
            record = None
        out.append(Version(n, d, file, store.version_time(d), size, record))
    return out


def _version_file(store, version: Path, path: str) -> Path:
    getter = getattr(store, "version_file", None)
    if getter is not None:
        try:
            return Path(getter(version, path))
        except Exception:
            pass
    return version / (Path(path.rstrip("/")).name or "pulled_file")


def _stored_diff(version: Version) -> str | None:
    from sandroid.core import watchlist_store as store

    try:
        return store.version_diff(version.dir)
    except Exception:
        return None


#: Versions up to this size (both sides) get their list summary from a
#: structured diff of the copies; larger ones from the stored text diff.
SUMMARY_DIFF_BYTES = 1024 * 1024


def version_summary(version: Version, previous: Version | None = None) -> str:
    """Short change summary of a version against the one before it.

    From a structured diff of the two copies when it is cached or both are
    small, else from the diff stored with the version (no file opened).
    """
    key = ("summary", str(version.dir), str(previous.dir) if previous else "")
    cached = _SUMMARIES.get(key)
    if cached is not None:
        return cached
    summary = None
    if previous is not None and previous.file.exists() and version.file.exists():
        dkey = ("diff", str(previous.file), str(version.file))
        diff = _DIFFS.get(dkey)
        if diff is None and _size_of(previous.file, version.file) <= SUMMARY_DIFF_BYTES:
            diff, _pending = structured_for(previous.file, version.file)
        if diff is not None and not diff.error:
            summary = diff.summary()
    if summary is None:
        text = _stored_diff(version)
        if text is None:
            summary = "first pull" if previous is None else "no diff stored"
        elif not text.strip():
            summary = "no change" if previous is not None else "first pull"
        else:
            parsed = fi.parse_text_diff(text)
            if parsed is None:
                summary = f"changed ({_plural(len(text.splitlines()), 'line')})"
            else:
                summary = parsed.summary()
    _SUMMARIES.put(key, summary)
    return summary


def _selected_index(versions: list[Version], state: InspectState) -> int:
    for i, v in enumerate(versions):
        if v.name == state.selected:
            return i
    return len(versions) - 1


class VersionList:
    """The version list (one line per version, newest first)."""

    def __init__(
        self, versions: list[Version], selected: int, base: str | None
    ) -> None:
        self.versions = versions
        self.selected = selected
        self.base = base

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        width = options.max_width
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(width=1, no_wrap=True)
        grid.add_column(no_wrap=True)  # v3
        grid.add_column(no_wrap=True)  # time
        if width >= 50:
            grid.add_column(no_wrap=True, justify="right")  # size
        if width >= 58:
            grid.add_column(no_wrap=True)  # trigger
        grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for i in range(len(self.versions) - 1, -1, -1):
            v = self.versions[i]
            sel = i == self.selected
            cells: list = [
                Text("▸" if sel else " ", style=f"bold {_ACCENT}"),
                Text(
                    f"v{v.number}", style=f"bold {_ACCENT}" if sel else f"bold {_TEXT}"
                ),
                Text(_when(v.when), style=_TEXT if sel else _MUTED),
            ]
            if width >= 50:
                cells.append(Text(fi.format_size(v.size), style=_DIM))
            if width >= 58:
                cells.append(Text(v.trigger or "", style=_DIM))
            summary = Text()
            if v.name == self.base:
                summary.append("◆ base ", style=f"bold {_CHG}")
            text = version_summary(v, self.versions[i - 1] if i else None)
            summary.append(
                text,
                style=_TEXT
                if sel
                else (_DIM if text in ("no change", "first pull") else _MUTED),
            )
            cells.append(summary)
            grid.add_row(*cells, style=_SEL if sel else "")
        yield grid


def _stamp(value: Any) -> str:
    """An ISO string or epoch number from a record as a short time."""
    when = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 10**11 else value
        try:
            when = datetime.fromtimestamp(seconds)
        except (OverflowError, OSError, ValueError):
            when = None
    elif isinstance(value, str):
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            return value[:19]
    return _when(when) if when is not None else ""


class RecordLines:
    """The acquisition record in (at most) two dim lines; the facts that do
    not fit the width are left out rather than wrapped.
    """

    def __init__(self, version: Version) -> None:
        record = version.record or {}
        local = record.get("local_sha256")
        self.first = [
            f"pulled {_stamp(record.get('pulled_at')) or _when(version.when)}"
        ]
        if record.get("trigger"):
            self.first.append(str(record["trigger"]))
        self.first.append(fi.format_size(version.size))
        if local:
            self.first.append(f"sha256 {str(local)[:10]}…")
        self.second: list[str] = []
        if record.get("device_mtime") is not None:
            self.second.append(f"device mtime {_stamp(record['device_mtime'])}")
        if record.get("device_size") is not None:
            self.second.append(fi.format_size(record.get("device_size")))
        dsha = record.get("device_sha256")
        if dsha:
            same = local and dsha == local
            self.second.append(
                "sha256 = local ✓" if same else f"sha256 {str(dsha)[:10]}…"
            )
        if self.second and not self.second[0].startswith("device"):
            self.second[0] = "device " + self.second[0]

    @staticmethod
    def _fit(bits: list[str], width: int) -> str:
        out = ""
        for bit in bits:
            candidate = f"{out} · {bit}" if out else bit
            if len(candidate) > width and out:
                break
            out = candidate
        return out

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        width = options.max_width
        yield Text(self._fit(self.first, width), style=_DIM, no_wrap=True)
        if self.second:
            yield Text(self._fit(self.second, width), style=_DIM, no_wrap=True)


def record_text(version: Version) -> RecordLines:
    """The acquisition record of a version (one or two dim lines)."""
    return RecordLines(version)


def versions_sections(
    path: str,
    notify: Callable[[], None] | None = None,
    status: Text | None = None,
) -> list[Section]:
    """The Versions tab of a watched file."""
    versions = load_versions(path)
    sections: list[Section] = []
    if not versions:
        msg = Text("Not pulled yet — ", style=_DIM)
        msg.append("u", style="bold")
        msg.append(" pulls a first version; with auto-pull (", style=_DIM)
        msg.append("a", style="bold")
        msg.append(") every change is kept as one.", style=_DIM)
        if status is not None:
            sections.append(("", status))
        sections.append(("", msg))
        return sections
    state = state_for(path)
    index = _selected_index(versions, state)
    sections.append(("", VersionList(versions, index, state.base)))
    sections.append(("", Text(HINT_VERSIONS, style=_DIM)))
    if status is not None:
        sections.append(("", status))
    heading, body = version_diff_body(path, versions, index, state, notify, full=False)
    sections.append((heading, body))
    return sections


def _diff_pair(
    versions: list[Version], index: int, state: InspectState
) -> tuple[Version | None, Version]:
    """``(older, newer)`` to diff for the selection (base or the one before)."""
    selected = versions[index]
    if state.base and state.base != selected.name:
        base = next((v for v in versions if v.name == state.base), None)
        if base is not None:
            return (
                (base, selected) if base.number < selected.number else (selected, base)
            )
    return (versions[index - 1] if index > 0 else None), selected


def version_diff_body(
    path: str,
    versions: list[Version],
    index: int,
    state: InspectState,
    notify,
    full: bool,
) -> tuple[str, Any]:
    older, newer = _diff_pair(versions, index, state)
    selected = versions[index]
    if older is None:
        heading = f"v{selected.number} · first kept version"
        body = Group(
            record_text(selected),
            Text(""),
            Text(
                "Nothing to compare with — the next pull is diffed against it. "
                "The Content tab shows what is inside.",
                style=_DIM,
            ),
        )
        return heading, body
    based = " (base)" if state.base in (older.name, newer.name) and state.base else ""
    heading = (
        f"Diff  v{newer.number} {_when(newer.when)} ← "
        f"v{older.number} {_when(older.when)}{based}"
    )
    parts: list = [record_text(selected), Text("")]
    if older.file.exists() and newer.file.exists():
        diff, pending = structured_for(older.file, newer.file, notify)
        if pending:
            parts.append(Text("Computing the diff…", style=f"italic {_MUTED}"))
            return heading, Group(*parts)
        if diff is not None and not diff.error:
            parts.append(DiffRenderable(diff, full))
            return heading, Group(*parts)
    # Copies gone (legacy store) or not diffable: the stored text diff.
    stored = _stored_diff(newer) if older.number == newer.number - 1 else None
    parsed = fi.parse_text_diff(stored) if stored is not None else None
    if parsed is not None:
        parts.append(DiffRenderable(parsed, full))
    elif stored:
        from .files_panel import render_diff

        parts.append(render_diff(stored))
    else:
        parts.append(Text("No diff available for this pair.", style=_DIM))
    return heading, Group(*parts)


# ---------------------------------------------------------------------------
# content
# ---------------------------------------------------------------------------


def _facts_line(file: Path, preview: fi.Preview, label: str) -> Text:
    out = Text()
    out.append(file.name, style=f"bold {_TEXT}")
    out.append(f" · {label}" if label else "", style=_MUTED)
    out.append(f" · {fi.format_size(_size_of(file))}", style=_DIM)
    if preview.kind != "sqlite":
        out.append(f" · {preview.type_guess}", style=_DIM)
    return out


def content_sections_for_file(
    file: Path | None,
    state: InspectState,
    label: str,
    notify=None,
    empty_message: str | None = None,
) -> list[Section]:
    if file is None or not file.exists():
        return [
            ("", Text(empty_message or "No local copy of this file yet.", style=_DIM))
        ]
    preview, pending = preview_for(file, state.table, notify)
    if pending or preview is None:
        return [("", Text("Reading the file…", style=f"italic {_MUTED}"))]
    sections: list[Section] = []
    if preview.kind == "sqlite" and preview.tables:
        sections.append(("", table_list(preview)))
        sections.append(("", Text(HINT_TABLES, style=_DIM)))
        sections.append(("", _facts_line(file, preview, label)))
        shown = len(preview.rows)
        total = next((t.rows for t in preview.tables if t.name == preview.table), None)
        heading = f"{preview.table} · {shown if total is None else f'{shown} of {total:,}'} rows"
        sections.append((heading, PreviewRenderable(preview)))
        return sections
    sections.append(("", _facts_line(file, preview, label)))
    sections.append(("", PreviewRenderable(preview)))
    return sections


def content_label(path: str) -> str:
    """``v3 10:42:07 (newest)`` -- the version the Content tab shows."""
    versions = load_versions(path)
    if not versions:
        return ""
    v = versions[_selected_index(versions, state_for(path))]
    return f"v{v.number} {_when(v.when)}" + (" (newest)" if v is versions[-1] else "")


def content_sections(path: str, notify=None) -> list[Section]:
    """The Content tab of a watched file: the selected version's copy."""
    versions = load_versions(path)
    if not versions:
        msg = Text("Pull the file (", style=_DIM)
        msg.append("u", style="bold")
        msg.append(
            ") to look inside a local copy. Nothing here reads the device.", style=_DIM
        )
        return [("", msg)]
    state = state_for(path)
    v = versions[_selected_index(versions, state)]
    return content_sections_for_file(v.file, state, content_label(path), notify)


# ---------------------------------------------------------------------------
# REVIEW scope (a run's files)
# ---------------------------------------------------------------------------


def run_copies(scope: str | None, path: str) -> tuple[Path | None, Path | None]:
    """``(before, after)`` copies of ``path`` a run kept under ``raw/``."""
    if not scope:
        return None, None
    try:
        from sandroid.core import run_history

        run_dir = run_history.run_dir_for_scope(scope)
    except Exception:
        run_dir = None
    if run_dir is None:
        return None, None
    rel = path.lstrip("/")

    def find(*slots: str) -> Path | None:
        for base in (run_dir / "raw", run_dir):
            for slot in slots:
                candidate = base / slot / rel
                if candidate.is_file():
                    return candidate
        return None

    return find("first_pull"), find("second_pull", "new_pull")


def review_diff_body(
    scope: str | None,
    path: str,
    lines: list[str] | None,
    notify=None,
    full: bool = False,
):
    """The run's diff of ``path`` through the structured renderer: from the
    run's file copies when it kept them (column names), else parsed from the
    stored diff lines; None when neither works (caller shows the text).
    """
    before, after = run_copies(scope, path)
    if before is not None and after is not None:
        diff, pending = structured_for(before, after, notify)
        if pending:
            return Text("Computing the diff…", style=f"italic {_MUTED}")
        if diff is not None and not diff.error:
            return DiffRenderable(diff, full)
    parsed = fi.parse_text_diff(lines) if lines else None
    if parsed is not None and not parsed.empty:
        return DiffRenderable(parsed, full)
    return None


def review_content_sections(
    scope: str | None, path: str, kind: str, notify=None
) -> list[Section] | None:
    before, after = run_copies(scope, path)
    file = before if kind == "deleted" else after
    if file is None:
        return None
    label = "before the run" if file is before else "after the run"
    return content_sections_for_file(file, state_for(f"{scope}|{path}"), label, notify)


# ---------------------------------------------------------------------------
# interaction (keys / clicks) and zoom
# ---------------------------------------------------------------------------


def step_version(path: str, delta: int) -> bool:
    """``delta`` -1 = older, +1 = newer. True when the selection moved."""
    versions = load_versions(path)
    if not versions:
        return False
    state = state_for(path)
    index = _selected_index(versions, state)
    new = max(0, min(len(versions) - 1, index + delta))
    if new == index:
        return False
    state.selected = None if new == len(versions) - 1 else versions[new].name
    return True


def select_version_row(path: str, row: int) -> bool:
    """Select the version on list line ``row`` (0 = newest)."""
    versions = load_versions(path)
    if not 0 <= row < len(versions):
        return False
    index = len(versions) - 1 - row
    state_for(path).selected = None if row == 0 else versions[index].name
    return True


def toggle_base(path: str) -> str | None:
    """Mark the selected version as the diff base (again: clear). Returns a
    short notice for the user.
    """
    versions = load_versions(path)
    if len(versions) < 2:
        return "Needs two kept versions."
    state = state_for(path)
    selected = versions[_selected_index(versions, state)]
    if state.base == selected.name:
        state.base = None
        return "Base cleared: each version is diffed against the one before."
    state.base = selected.name
    return f"v{selected.number} is the base: pick another version to diff against it."


def _preview_of(key: str, file: Path | None) -> fi.Preview | None:
    if file is None or not file.exists():
        return None
    preview, _pending = preview_for(file, state_for(key).table)
    return preview


def content_file(path: str) -> Path | None:
    versions = load_versions(path)
    if not versions:
        return None
    return versions[_selected_index(versions, state_for(path))].file


def step_table(key: str, file: Path | None, delta: int) -> bool:
    preview = _preview_of(key, file)
    if preview is None or preview.kind != "sqlite" or not preview.tables:
        return False
    names = [t.name for t in preview.tables]
    index = names.index(preview.table) if preview.table in names else 0
    new = max(0, min(len(names) - 1, index + delta))
    if new == index:
        return False
    state_for(key).table = names[new]
    return True


def select_table_row(key: str, file: Path | None, row: int) -> bool:
    preview = _preview_of(key, file)
    if (
        preview is None
        or preview.kind != "sqlite"
        or not 0 <= row < len(preview.tables)
    ):
        return False
    state_for(key).table = preview.tables[row].name
    return True


def zoom_versions(path: str) -> tuple[str, Any] | None:
    versions = load_versions(path)
    if not versions:
        return None
    state = state_for(path)
    index = _selected_index(versions, state)
    heading, body = version_diff_body(path, versions, index, state, None, full=True)
    return heading, body


def zoom_content(
    key: str, file: Path | None, label: str = ""
) -> tuple[str, Any, bool] | None:
    if file is None or not file.exists():
        return None
    preview = fi.preview_file(file, state_for(key).table, row_limit=fi.PREVIEW_ROWS)
    if preview.kind == "text":
        preview.lines = preview.lines[: fi.PREVIEW_LINES]
    title = f"{file.name} · {label}" if label else file.name
    if preview.kind == "sqlite" and preview.table:
        title += f" · {preview.table}"
        table, _hidden = _rows_table(preview.columns, preview.rows, 10_000, True)
        return title, table, True
    return title, PreviewRenderable(preview, full=True), False


class InspectZoomModal(ForensicModal[None]):
    """Full-screen view of one Inspector renderable (diff or content).

    ``wide`` content (a table's rows) keeps its natural width and scrolls
    sideways; a diff is laid out for the modal's width with nothing cut.
    """

    BINDINGS = [
        Binding("j", "scroll_by(1)", "Down", show=False),
        Binding("k", "scroll_by(-1)", "Up", show=False),
    ]

    AUTO_FOCUS = "#izoom-scroll"

    DEFAULT_CSS = """
    InspectZoomModal .modal-container {
        width: 94%;
        height: 90%;
        max-width: 94%;
        max-height: 90%;
    }
    InspectZoomModal #izoom-scroll {
        height: 1fr;
        background: #050811;
        border: solid #1f2d4d;
        scrollbar-size: 1 1;
    }
    InspectZoomModal #izoom-body {
        width: 100%;
        height: auto;
    }
    InspectZoomModal #izoom-body.-wide {
        width: auto;
    }
    """

    def __init__(
        self, title: str, renderable: RenderableType, wide: bool = False
    ) -> None:
        super().__init__()
        self._title = title
        self._renderable = renderable
        self._wide = wide

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label(self._title, classes="modal-title")
            with ScrollableContainer(id="izoom-scroll"):
                yield Static(
                    self._renderable,
                    id="izoom-body",
                    classes="-wide" if self._wide else "",
                )
            yield KeyHintFooter(
                hints={"default": "[dim]↑↓/j k scroll  ←→ sideways  Esc close[/dim]"}
            )

    def action_scroll_by(self, delta: int) -> None:
        try:
            self.query_one("#izoom-scroll", ScrollableContainer).scroll_relative(
                y=delta, animate=False
            )
        except Exception:
            pass


__all__ = [
    "DiffRenderable",
    "InspectState",
    "InspectZoomModal",
    "PreviewRenderable",
    "Version",
    "change_text",
    "clear_caches",
    "content_file",
    "content_sections",
    "load_versions",
    "review_content_sections",
    "review_diff_body",
    "select_table_row",
    "select_version_row",
    "state_for",
    "step_table",
    "step_version",
    "toggle_base",
    "value_text",
    "version_summary",
    "versions_sections",
    "zoom_content",
    "zoom_versions",
]
