"""Timeline figure for the PDF report.

Originally based on https://github.com/sukhbinder/timeline_in_python.

The figure is a vertical time axis (seconds after action start). Changed files
are labelled on the left, new files on the right. Labels are spread evenly in
timestamp order and connected to their point on the axis, so they never
overlap regardless of how many events share a timestamp. Output is
deterministic (no sampling); events beyond :data:`MAX_LABELS_PER_SIDE` per side
are summarised in a note instead of being drawn.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

#: Colours: changed files (dark teal, as recorded by the timeline collector)
#: and new files (dark green, readable on white).
CHANGED_COLOR = "#1A535C"
NEW_COLOR = "#2E7D32"

#: Maximum labels drawn per side before the remainder is summarised.
MAX_LABELS_PER_SIDE = 45

#: Maximum label length (characters) before middle-truncation.
MAX_LABEL_LEN = 48

#: Default figure size in inches (fits an A4 frame with margins).
FIGSIZE = (7.0, 9.2)


def _timeline_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten the list-wrapped ``Other Data -> Timeline Data`` entries."""
    raw = (data.get("Other Data") or {}).get("Timeline Data") or []
    entries: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, list):
            entries.extend(e for e in item if isinstance(e, dict))
        elif isinstance(item, dict):
            entries.append(item)
    return entries


def build_timeline_events(data: dict[str, Any]) -> list[tuple[str, float, str, str]]:
    """Derive ``(label, seconds, colour, kind)`` events from a results mapping.

    Only files that are reported as changed or new are placed on the
    timeline. Several observations of the same file are averaged.

    Args:
        data: Parsed results JSON.

    Returns:
        Events sorted by time, ``kind`` is ``"changed"`` or ``"new"``.
    """
    changed_ids: set[str] = set()
    for entry in data.get("Changed Files") or []:
        if isinstance(entry, str):
            changed_ids.add(entry)
        elif isinstance(entry, dict) and entry:
            changed_ids.add(next(iter(entry)))
    new_ids = {f for f in data.get("New Files") or [] if isinstance(f, str)}

    times: dict[str, list[float]] = {}
    names: dict[str, str] = {}
    colours: dict[str, str] = {}
    for entry in _timeline_entries(data):
        fid = entry.get("id")
        if fid is None:
            continue
        try:
            ts = float(entry.get("seconds_after_start", 0))
        except (TypeError, ValueError):
            continue
        times.setdefault(fid, []).append(ts)
        names.setdefault(fid, str(entry.get("name") or os.path.basename(fid)))
        colours.setdefault(fid, str(entry.get("timeline_color") or CHANGED_COLOR))

    events: list[tuple[str, float, str, str]] = []
    for fid, ts_list in times.items():
        avg = sum(ts_list) / len(ts_list)
        if fid in new_ids:
            events.append((names[fid], avg, NEW_COLOR, "new"))
        elif fid in changed_ids:
            events.append((names[fid], avg, colours[fid], "changed"))
    events.sort(key=lambda e: (e[1], e[0]))
    return events


def parse_timeline(output_file: str | os.PathLike[str], png_path: str | None = None):
    """Render the timeline PNG for a results JSON file.

    Args:
        output_file: Path of the results JSON.
        png_path: Where to write the PNG. Defaults to ``timeline.png`` next to
            the JSON file (no environment variables involved).

    Returns:
        The PNG path, or ``None`` if there are no timeline events.
    """
    with open(output_file, encoding="utf-8") as json_file:
        data = json.load(json_file)
    events = build_timeline_events(data)
    if not events:
        return None
    if png_path is None:
        png_path = str(Path(output_file).resolve().parent / "timeline.png")
    duration = data.get("Action Duration") or 0
    create_timeline(events, png_path, duration)
    return png_path


def _short(label: str) -> str:
    if len(label) <= MAX_LABEL_LEN:
        return label
    keep = MAX_LABEL_LEN - 1
    return label[: keep // 2] + "…" + label[-(keep - keep // 2) :]


def _spread_labels(times: list[float], stop: float) -> list[float]:
    """Place labels as close to their time as possible without overlapping.

    ``times`` must be sorted. Labels keep a minimum vertical gap; a forward
    pass pushes crowded labels down, a backward pass pulls them back inside
    ``[0, stop]``.
    """
    if not times:
        return []
    gap = stop / (MAX_LABELS_PER_SIDE + 2)
    ys: list[float] = []
    for t in times:
        ys.append(max(t, ys[-1] + gap) if ys else max(t, 0.0))
    limit = stop
    for i in range(len(ys) - 1, -1, -1):
        ys[i] = min(ys[i], limit)
        limit = ys[i] - gap
    return ys


def create_timeline(events, filename, duration):
    """Draw the timeline and save it as PNG.

    Args:
        events: ``(label, seconds, colour[, kind])`` tuples. Without ``kind``
            the event is treated as a changed file.
        filename: Output PNG path.
        duration: Action duration in seconds (sets the axis length).

    Returns:
        The matplotlib axes.
    """
    norm = []
    for ev in events:
        label, ts, colour = ev[0], float(ev[1]), ev[2]
        kind = ev[3] if len(ev) > 3 else "changed"
        norm.append((label, ts, colour, kind))
    norm.sort(key=lambda e: (e[1], e[0]))

    max_ts = max([e[1] for e in norm], default=0.0)
    stop = max(float(duration or 0), max_ts, 1.0)

    fig, ax = plt.subplots(figsize=FIGSIZE, dpi=200)
    # Room for MAX_LABEL_LEN-character labels on both sides of the axis.
    ax.set_xlim(-2.0, 1.5)
    ax.set_ylim(stop * 1.02, -stop * 0.02)  # time runs downward
    ax.plot((0, 0), (0, stop), color="#555555", linewidth=1.2, zorder=1)

    notes = []
    for side, kind in ((-1, "changed"), (1, "new")):
        group = [e for e in norm if e[3] == kind]
        hidden = max(0, len(group) - MAX_LABELS_PER_SIDE)
        group = group[:MAX_LABELS_PER_SIDE]
        if hidden:
            notes.append(f"+{hidden} more {kind} file(s) not drawn (see results JSON)")
        label_ys = _spread_labels([e[1] for e in group], stop)
        for (label, ts, colour, _kind), y_label in zip(group, label_ys, strict=True):
            x_label = side * 0.18
            ax.scatter(
                0,
                ts,
                s=22,
                facecolor=colour,
                edgecolor="black",
                linewidth=0.4,
                zorder=3,
            )
            ax.plot(
                (0, side * 0.08, x_label),
                (ts, ts, y_label),
                color=colour,
                linewidth=0.6,
                alpha=0.8,
                zorder=2,
            )
            ax.text(
                x_label + side * 0.01,
                y_label,
                f"{_short(label)}  ({ts:.0f}s)"
                if side < 0
                else f"({ts:.0f}s)  {_short(label)}",
                ha="right" if side < 0 else "left",
                va="center",
                fontsize=6.5,
                color=colour,
            )

    ax.set_ylabel("Seconds after action start", fontsize=8)
    ax.tick_params(axis="y", labelsize=7)
    ax.get_yaxis().set_major_locator(plt.MaxNLocator(integer=True))
    ax.set_xticks([])
    for spine in ("top", "right", "bottom"):
        ax.spines[spine].set_visible(False)
    ax.text(
        -0.9,
        -stop * 0.02,
        "Changed files",
        ha="center",
        va="bottom",
        fontsize=8,
        fontweight="bold",
        color=CHANGED_COLOR,
    )
    ax.text(
        0.5,
        -stop * 0.02,
        "New files",
        ha="center",
        va="bottom",
        fontsize=8,
        fontweight="bold",
        color=NEW_COLOR,
    )
    if notes:
        fig.text(0.5, 0.005, "; ".join(notes), ha="center", fontsize=7, style="italic")
    fig.tight_layout()
    fig.savefig(filename, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)
    return ax


if __name__ == "__main__":  # pragma: no cover
    import sys

    print(parse_timeline(sys.argv[1] if len(sys.argv) > 1 else "sandroid.json"))
