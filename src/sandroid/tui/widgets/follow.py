"""Follow the newest row: one behaviour for the Timeline, Files and Network lenses.

The rules are the same in all three live lists:

* new entries always appear at the bottom (newest last);
* while *live*, the view sticks to the newest row;
* a click on a row above the newest one, or moving the cursor up, stops the
  auto-scroll -- recording never pauses, only the view stays where it is;
* ``End`` resumes.

Each lens shows it in ONE place, its caption title: ``live`` while
following, ``scrolled back · 12 new below · End = live`` otherwise
(``scrolled back · End = live`` while nothing new arrived; :func:`follow_text`). :class:`Follow` is the small state object each lens
keeps; the lens decides what counts as "new" (lines, flows, changed files).
"""

from __future__ import annotations

#: Caption / chip text while the view follows the newest row.
LIVE_TEXT = "live"


def follow_text(live: bool, new_below: int = 0) -> str:
    """``live``, ``scrolled back · 12 new below · End = live`` or (nothing
    new yet) ``scrolled back · End = live``.
    """
    if live:
        return LIVE_TEXT
    if new_below <= 0:
        return "scrolled back · End = live"
    return f"scrolled back · {new_below:,} new below · End = live"


class Follow:
    """Whether a live list follows its newest row, and what arrived since.

    ``live`` starts True. :meth:`stop` (cursor up, a click above the newest
    row, a wheel up) and :meth:`resume` (``End``) return True when the state
    changed, so the caller repaints its caption only then.
    """

    __slots__ = ("live", "new_below")

    def __init__(self, live: bool = True) -> None:
        self.live = live
        self.new_below = 0

    def stop(self) -> bool:
        """Stop following (the view stays put; nothing stops recording)."""
        if not self.live:
            return False
        self.live = False
        self.new_below = 0
        return True

    def resume(self) -> bool:
        """Follow the newest row again (``End``)."""
        changed = not self.live or self.new_below != 0
        self.live = True
        self.new_below = 0
        return changed

    def added(self, n: int = 1) -> None:
        """``n`` new entries arrived below (counted only while scrolled back)."""
        if not self.live and n > 0:
            self.new_below += n

    def clicked(self, index: int, last: int) -> bool:
        """A click on row ``index`` of ``last + 1`` rows: above the newest one
        stops following. Returns True when that changed the state.
        """
        if 0 <= index < last:
            return self.stop()
        return False

    @property
    def text(self) -> str:
        return follow_text(self.live, self.new_below)


__all__ = ["LIVE_TEXT", "Follow", "follow_text"]
