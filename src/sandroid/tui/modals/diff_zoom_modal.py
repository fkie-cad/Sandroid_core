"""Full-screen diff search/export modal, opened by ``DiffView``'s ``z`` key.

Renders the complete, untruncated diff (Rich markup stripped to plain text)
in a scrollable ``RichLog`` and adds:

    /       open a real ``Input`` for substring search
    n / N   jump to next / previous match
    e       export the full diff (markup stripped) to a ``.txt`` temp file
    o       hand that temp file to the OS opener

Search matches against markup-STRIPPED text (never the literal
``[success]``/``[warning]`` pseudo-tags friTap/fsmon/file_diff wrap lines
in), then re-highlights matches with ``[reverse]...[/reverse]`` in the
rendered view. This is pure TUI-layer post-processing — no changes to
``core/file_diff.py`` or any diff producer.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, RichLog, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


class DiffZoomModal(ForensicModal[None]):
    """Full search/export view for one diff (90% x 85%).

    Two base-modal (``SandroidModal``) conflicts this class resolves
    explicitly:

    1. ``SandroidModal``'s ``escape -> cancel`` binding is ``priority=True``,
       so it fires regardless of what has focus. Left alone, pressing Esc
       while the search ``Input`` is focused would close the entire modal
       instead of just exiting search mode. Fixed with a plain (sync, NOT
       async) ``action_cancel`` override that checks whether the search
       input currently has focus first — this exact ESC/``action_cancel``
       pattern (a modal/screen needing its own sync override or Esc silently
       no-ops) already exists in this codebase, e.g.
       ``HelpScreen.action_cancel``.

    2. ``SandroidModal`` binds ``j``/``k`` to ``cursor_down``/``cursor_up``,
       but no ``action_cursor_down``/``action_cursor_up`` exists on the base
       (only specific OptionList-owning modals define them). Left
       un-overridden they would be silent no-ops here, so — following the
       exact precedent already used by ``DeviceInfoModal`` (which redefines
       ``j``/``k`` to ``scroll_down``/``scroll_up`` for its own scrollable
       content) — this class REMAPS them explicitly to scroll the diff
       ``RichLog``, rather than leaving them dead. Plain arrow-key scrolling
       inside the RichLog is untouched (this class does not bind up/down),
       so there is no fight with RichLog's own scroll handling.

    ``e``/``o`` reuse global app keys (Emulator Info / fsmon) — harmless,
    since a focused modal captures all keys before they reach app-level
    bindings; noted here so it doesn't read as an oversight.
    """

    BINDINGS = [
        Binding("slash", "start_search", "Search", show=False),
        Binding("n", "next_match", "Next match", show=False),
        Binding("N", "prev_match", "Prev match", show=False),
        Binding("e", "export", "Export"),
        Binding("o", "open_external", "Open"),
        # Remapped, not inherited no-ops — see class docstring point 2.
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
    ]

    # No primary button exists in this modal; without this, the base's
    # Enter-while-Input-focused handling would swallow Enter in the search
    # box (event.stop()) before Input's own "submit" binding ever runs,
    # so Input.Submitted would never fire.
    ENTER_SUBMITS_FROM_INPUT = False

    # Focus the diff log by default (not the — initially hidden — search
    # Input), since the base's generic _auto_focus() fallback chain tries
    # "Input" before "OptionList"/"Button"/".modal-container" and would
    # otherwise grab focus into the search box on open.
    AUTO_FOCUS = "#zoom-log"

    DEFAULT_CSS = """
    DiffZoomModal .modal-container {
        width: 90%;
        height: 85%;
        max-width: 90%;
        max-height: 85%;
    }

    DiffZoomModal #zoom-status {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }

    DiffZoomModal #zoom-log {
        height: 1fr;
        background: $panel;
        border: solid $foreground-muted;
        scrollbar-size: 1 1;
    }

    DiffZoomModal #zoom-search-input {
        margin-top: 1;
    }
    """

    def __init__(
        self,
        diff_text: str,
        title: str = "diff",
        name: str = None,
        id: str = None,
        classes: str = None,
    ) -> None:
        """Args:
        diff_text: The full, untruncated diff (with Rich markup) owned by
            the specific ``DiffView`` instance that opened this modal.
        title: Label shown in the modal title / status line.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._title = title
        # Markup-stripped once up front: all search/export/render operates on
        # this plain text, never the raw markup-bearing string, so pseudo
        # tags like "[success]"/"[warning]" are never mistaken for content.
        self._plain = Text.from_markup(diff_text).plain
        self._lines = self._plain.split("\n")
        self._query = ""
        self._match_lines: list[int] = []
        self._match_cursor = -1
        self._exported_path: Path | None = None

    # -- compose / mount -----------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label(self._title, classes="modal-title")
            yield Static("", id="zoom-status")
            yield RichLog(
                id="zoom-log",
                markup=True,
                highlight=False,
                wrap=False,
                auto_scroll=False,
            )
            yield Input(placeholder="search diff…", id="zoom-search-input")
            yield KeyHintFooter(
                hints={
                    "default": "[dim]/=Search  n/N=Next/Prev  e=Export  "
                    "o=Open  j/k=Scroll  Esc=Close[/dim]",
                    "input": "[dim]Type to search  Enter/Esc=Exit search[/dim]",
                }
            )

    def on_mount(self) -> None:
        super().on_mount()  # runs _auto_focus() -> #zoom-log
        self._render_lines()
        self._update_status()
        try:
            self.query_one("#zoom-search-input", Input).display = False
        except NoMatches:
            pass

    # -- search mode ----------------------------------------------------

    def action_start_search(self) -> None:
        try:
            search_input = self.query_one("#zoom-search-input", Input)
        except NoMatches:
            return
        search_input.display = True
        search_input.focus()

    def _exit_search_mode(self) -> None:
        try:
            search_input = self.query_one("#zoom-search-input", Input)
        except NoMatches:
            return
        search_input.display = False
        try:
            self.query_one("#zoom-log", RichLog).focus()
        except Exception:
            pass

    def action_cancel(self) -> None:
        """Escape: exit search mode if searching, else close (see class doc)."""
        try:
            search_input = self.query_one("#zoom-search-input", Input)
        except NoMatches:
            search_input = None
        if search_input is not None and search_input.has_focus:
            self._exit_search_mode()
            return
        self._dismiss_with_refresh(None)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "zoom-search-input":
            return
        self._query = event.value
        self._recompute_matches()
        self._render_lines()
        self._update_status()
        if self._match_lines:
            self._scroll_to_match()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "zoom-search-input":
            return
        self._exit_search_mode()

    # -- matching / rendering ---------------------------------------------

    def _recompute_matches(self) -> None:
        query = self._query
        if not query:
            self._match_lines = []
            self._match_cursor = -1
            return
        needle = query.lower()
        self._match_lines = [
            i for i, line in enumerate(self._lines) if needle in line.lower()
        ]
        self._match_cursor = 0 if self._match_lines else -1

    def _render_lines(self) -> None:
        try:
            log = self.query_one("#zoom-log", RichLog)
        except Exception:
            return
        log.clear()
        query = self._query
        if not query:
            for line in self._lines:
                log.write(escape(line))
            return
        needle = query.lower()
        qlen = len(query)
        for line in self._lines:
            lower_line = line.lower()
            if needle not in lower_line:
                log.write(escape(line))
                continue
            segments: list[str] = []
            pos = 0
            while True:
                idx = lower_line.find(needle, pos)
                if idx == -1:
                    segments.append(escape(line[pos:]))
                    break
                segments.append(escape(line[pos:idx]))
                segments.append(f"[reverse]{escape(line[idx : idx + qlen])}[/reverse]")
                pos = idx + qlen
            log.write("".join(segments))

    def _update_status(self) -> None:
        try:
            status = self.query_one("#zoom-status", Static)
        except Exception:
            return
        n = len(self._lines)
        if self._query:
            count = len(self._match_lines)
            pos = f"{self._match_cursor + 1}/{count}" if count else "0/0"
            status.update(
                f"[b]{self._title}[/] — {n} lines · search '{self._query}' "
                f"· match {pos} (n/N)"
            )
        else:
            status.update(
                f"[b]{self._title}[/] — {n} lines · / search · e export · o open"
            )

    # -- match navigation --------------------------------------------------

    def action_next_match(self) -> None:
        self._jump_match(1)

    def action_prev_match(self) -> None:
        self._jump_match(-1)

    def _jump_match(self, delta: int) -> None:
        if not self._match_lines:
            self._notify_safe("No matches.", "warning")
            return
        if self._match_cursor < 0:
            self._match_cursor = 0
        else:
            self._match_cursor = (self._match_cursor + delta) % len(self._match_lines)
        self._scroll_to_match()
        self._update_status()

    def _scroll_to_match(self) -> None:
        if not self._match_lines or self._match_cursor < 0:
            return
        line_idx = self._match_lines[self._match_cursor]
        try:
            log = self.query_one("#zoom-log", RichLog)
            log.scroll_to(y=max(0, line_idx - 3), animate=False)
        except Exception:
            pass

    # -- j/k remapped to scroll the RichLog (see class docstring point 2) --

    def action_scroll_down(self) -> None:
        try:
            self.query_one("#zoom-log", RichLog).action_scroll_down()
        except Exception:
            pass

    def action_scroll_up(self) -> None:
        try:
            self.query_one("#zoom-log", RichLog).action_scroll_up()
        except Exception:
            pass

    # -- export / open -------------------------------------------------------

    def action_export(self) -> None:
        """E — export the full, untruncated (markup-stripped) diff to .txt.

        On failure: notify with severity="error" and stay open (no dismiss).
        """
        try:
            path = self._write_export_file()
        except Exception as exc:
            logger.warning("Diff export failed: %s", exc)
            self._notify_safe(f"Export failed: {exc}", "error")
            return
        self._exported_path = path
        self._notify_safe(f"Exported to {path}", "information")

    def action_open_external(self) -> None:
        """O — hand the exported temp file to the OS opener.

        Exports first if nothing has been exported yet this session, so `o`
        works standalone without requiring `e` first.
        """
        path = self._exported_path
        if path is None or not path.exists():
            try:
                path = self._write_export_file()
                self._exported_path = path
            except Exception as exc:
                logger.warning("Diff export (for open) failed: %s", exc)
                self._notify_safe(f"Export failed: {exc}", "error")
                return
        self._open_externally(path)

    def _write_export_file(self) -> Path:
        fd, path_str = tempfile.mkstemp(prefix="sandroid_diff_", suffix=".txt")
        path = Path(path_str)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(self._plain)
        return path

    def _open_externally(self, target: Path) -> None:
        """Hand ``target`` to the OS opener (mirrors ``FriTapPanel._open_folder``)."""
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)])
            else:
                webbrowser.open(target.as_uri())
        except Exception as exc:
            logger.warning("Failed to open diff export %s: %s", target, exc)
            self._notify_safe(f"Could not open {target}: {exc}", "error")

    # -- notifications --------------------------------------------------

    def _notify_safe(self, message: str, severity: str = "information") -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass
