"""Review: what the recorded action changed, and the two Rewind buttons.

Opens when a recording stops (``r`` again) and on ``p``. It lists the files
that changed (new / changed / deleted) and, when Network data exists, the
requests seen during the recording. Selecting a file watches it (★ in the
Files lens) and saves its current version as **After**. Selecting a request
marks it for the comparison after **Rewind + Replay**.

The buttons: **Rewind + Replay** (back to the start point, Before, replay
the steps, After (replay)) and **Rewind** (back to the start point,
Before). Nothing runs until one is pressed. Esc closes Review, or, while a
rewind runs, asks whether to stop it.

Plain words only, no symbols for states (★ is the Files lens's mark for a
watched file): colours come from theme tokens via CSS classes.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any

from rich.markup import escape
from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from .base import ForensicModal

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


def _size(n: Any) -> str:
    if not isinstance(n, int):
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _short(path: str, pkg: str | None, limit: int = 60) -> str:
    for root in (f"/data/data/{pkg}/", f"/data/user/0/{pkg}/"):
        if pkg and path.startswith(root):
            path = path[len(root) :]
            break
    return path if len(path) <= limit else "…" + path[-(limit - 1) :]


class ReviewModal(ForensicModal[None]):
    """Review of one recording (see the module docstring).

    Args:
        rec: The recording (:class:`sandroid.core.rewind.Recording`).
        controller: The ``RecordingController`` that owns it.
    """

    DEFAULT_CSS = """
    ReviewModal .modal-container {
        width: 92%;
        height: 90%;
        max-height: 90%;
    }
    ReviewModal #review-body {
        height: 1fr;
    }
    ReviewModal .review-head {
        color: $text-muted;
    }
    ReviewModal .review-section {
        text-style: bold;
        margin-top: 1;
    }
    ReviewModal .review-hint {
        color: $text-muted;
    }
    ReviewModal .review-warn {
        color: $warning;
    }
    ReviewModal #review-results {
        height: auto;
    }
    ReviewModal #review-name-row {
        height: auto;
    }
    ReviewModal #review-name {
        width: 50;
        height: 1;
        border: none;
    }
    ReviewModal SelectionList {
        height: auto;
        max-height: 14;
        border: none;
    }
    ReviewModal .verdict-same {
        color: $success;
    }
    ReviewModal .verdict-different {
        color: $warning;
    }
    ReviewModal .verdict-none {
        color: $text-muted;
    }
    ReviewModal .side {
        width: 1fr;
        padding-right: 2;
    }
    ReviewModal #review-progress {
        color: $accent;
        height: auto;
    }
    ReviewModal #review-buttons {
        height: 1;
        margin-top: 1;
    }
    ReviewModal #review-keep {
        height: 1;
        border: none;
        padding: 0;
    }
    """

    # Enter in the name field must never press Rewind + Replay (the primary
    # button): that would revert the device while the user types a name.
    ENTER_SUBMITS_FROM_INPUT = False

    def __init__(self, rec: Any, controller: Any) -> None:
        super().__init__()
        self.rec = rec
        self.controller = controller
        self._results_gen = 0
        self._file_state: dict[str, str] = {}
        self._filling = False
        self._building = False
        #: Rewind with no file selected was asked about once already.
        self._asked_empty = False

    # -- layout ----------------------------------------------------------------

    def compose(self) -> ComposeResult:
        rec = self.rec
        with Vertical(classes="modal-container"):
            yield Label(f"Review · Recording '{rec.name}'", classes="modal-title")
            yield Static(self._head_text(), id="review-head", classes="review-head")
            with Horizontal(id="review-name-row", classes="review-row"):
                yield Label("Name  ")
                yield Input(value=rec.name, id="review-name")
            with VerticalScroll(id="review-body"):
                yield Static(
                    "Files that changed", id="files-title", classes="review-section"
                )
                yield SelectionList[str](id="review-files")
                yield Static(
                    "Select a file to watch it. Its current version is saved as After.",
                    classes="review-hint",
                    id="files-hint",
                )
                yield Static("", id="requests-title", classes="review-section")
                yield SelectionList[str](id="review-requests")
                yield Static("", id="requests-hint", classes="review-hint")
                yield Vertical(id="review-results")
            yield Static(
                "Rewind takes the device back to the start point. Replay repeats "
                "your steps"
                + (" and sends the same requests again." if rec.requests else "."),
                classes="review-hint",
            )
            yield Static("", id="review-problem", classes="review-warn")
            yield Static("", id="review-progress")
            with Horizontal(id="review-buttons", classes="button-row"):
                yield Button("Rewind + Replay", id="rewind-replay", classes="-primary")
                yield Button("Rewind", id="rewind", classes="-secondary")
                yield Button("Close", id="close", classes="-secondary")
                yield Checkbox("Keep this start point", rec.pinned, id="review-keep")

    def on_mount(self) -> None:
        super().on_mount()
        self.refresh_lists()

    # -- content ---------------------------------------------------------------

    def _head_text(self) -> str:
        rec = self.rec
        secs = int((rec.stopped or 0) - (rec.started or 0)) if rec.started else 0
        parts = [f"{secs // 60}:{secs % 60:02d}"]
        if rec.started:
            from datetime import datetime

            parts.append(
                "started " + datetime.fromtimestamp(rec.started).strftime("%H:%M:%S")
            )
        if rec.pkg:
            parts.append(f"app {rec.pkg}")
        if rec.start_point_name:
            parts.append("start point saved")
        elif not rec.emulator:
            parts.append("no start point on a physical device")
        return escape("   ".join(parts))

    def refresh_lists(self, filling: bool | None = None) -> None:
        """Rebuild the file and request lists, results and buttons."""
        if filling is not None:
            self._filling = filling
        self._building = True
        try:
            self._fill_files()
            self._fill_requests()
            self._fill_results()
            self._update_buttons()
        except Exception:
            logger.debug("Review refresh failed", exc_info=True)
        finally:
            self._building = False

    def _file_prompt(self, entry: dict[str, Any]) -> Text:
        path = entry.get("path") or ""
        line = Text()
        line.append(f"{entry.get('state', ''):<8} ")
        line.append(_short(path, self.rec.pkg))
        size = _size(entry.get("size"))
        if size:
            line.append(f"  {size}", style="dim")
        mtime = entry.get("mtime")
        if isinstance(mtime, (int, float)) and mtime > 0:
            from datetime import datetime

            stamp = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
            line.append(f"  modified {stamp}", style="dim")
        if entry.get("outside_app"):
            line.append("  outside the app's folders", style="dim")
        from sandroid.core.rewind import main_database

        main = main_database(path)
        state = self._file_state.get(main)
        if main in self.rec.selected:
            line.append("  ★ watched", style="bold")
            if main != path:
                line.append(" (its database)", style="dim")
            if state:
                line.append(f" · {state}", style="dim")
        return line

    def _fill_files(self) -> None:
        from sandroid.core import rewind

        sel = self.query_one("#review-files", SelectionList)
        sel.clear_options()
        changed = self.rec.changed
        title = "Files that changed"
        if self._filling:
            title += "   (still filling: the app is writing)"
        self.query_one("#files-title", Static).update(title)
        if not changed:
            self.query_one("#files-hint", Static).update(
                "No file in the app's folders changed during the recording."
            )
            sel.display = False
            return
        sel.display = True
        sel.add_options(
            [
                Selection(
                    self._file_prompt(e),
                    e["path"],
                    rewind.main_database(e["path"]) in self.rec.selected,
                )
                for e in changed
            ]
        )

    def _fill_requests(self) -> None:
        from sandroid.core import rewind

        sel = self.query_one("#review-requests", SelectionList)
        sel.clear_options()
        reqs = self.rec.requests
        title = self.query_one("#requests-title", Static)
        hint = self.query_one("#requests-hint", Static)
        if not reqs:
            # No Network data: nothing about requests at all.
            for widget in (sel, title, hint):
                widget.display = False
            return
        for widget in (sel, title, hint):
            widget.display = True
        title.update(f"Requests during the recording ({len(reqs)})")
        hint.update(
            "Select a request to compare it with the replay. Requests are "
            "compared after Rewind + Replay; Rewind alone does not compare them."
        )
        chosen = {(r.get("seq"), r.get("flow_id")) for r in self.rec.selected_flows}
        sel.add_options(
            [
                Selection(
                    Text(rewind.request_text(r)),
                    str(i),
                    (r.get("seq"), r.get("flow_id")) in chosen,
                    disabled=r.get("kind") != "flow",
                )
                for i, r in enumerate(reqs)
            ]
        )

    def _fill_results(self) -> None:
        """Compare the copies on a worker (structured diffs of large files,
        timeline and flow reads never run on the UI thread), then show them.
        """
        box = self.query_one("#review-results", Vertical)
        rec = self.rec
        self._results_gen += 1
        gen = self._results_gen
        if not rec.runs:
            box.remove_children()
            return
        if not box.children:
            box.mount(Static("Comparing the copies", classes="review-hint"))
        controller = self.controller

        def work() -> None:
            try:
                res = controller.results(rec)
                per_run = controller.run_requests(rec)
            except Exception:
                logger.debug("results failed", exc_info=True)
                res, per_run = None, {}
            with contextlib.suppress(Exception):
                self.app.call_from_thread(self._show_results, gen, res, per_run)

        self.run_worker(work, name="review_results", thread=True, exclusive=False)

    def _show_results(self, gen: int, res: Any, per_run: dict) -> None:
        if gen != self._results_gen or not self.is_mounted:
            return  # a newer refresh is on its way
        box = self.query_one("#review-results", Vertical)
        box.remove_children()
        rec = self.rec
        if res is None or not rec.runs:
            return
        last = rec.runs[-1]
        word = "Rewind + Replay" if last.get("kind") == "rewind-replay" else "Rewind"
        from sandroid.core import rewind as _rewind

        result = _rewind.result_words(last) if last.get("result") else ""
        widgets: list[Any] = [
            Static(f"Results of the last {word} ({result})", classes="review-section")
        ]
        if last.get("error"):
            widgets.append(Static(escape(str(last["error"])), classes="review-warn"))
        if last.get("result") == "diverged":
            from sandroid.core import rewind

            words = rewind.diverged_words(
                rewind.RunOutcome(
                    n=0,
                    mode="rewind-replay",
                    diverged_at_step=last.get("diverged_at_step"),
                    diverged=last.get("diverged"),
                )
            )
            widgets.append(Static(escape(words), classes="review-warn"))
        elif last.get("result") == "unchecked":
            note = _rewind.diverged_note(last)
            widgets.append(Static(escape(note), classes="review-warn"))
        widgets.extend(self._step_widgets(last))
        for fr in res["files"]:
            widgets.extend(self._file_widgets(fr))
        widgets.extend(self._flow_widgets(res["flows"]))
        widgets.extend(self._request_widgets(per_run))
        box.mount_all(widgets)

    @staticmethod
    def _step_widgets(run: dict[str, Any]) -> list[Any]:
        steps = run.get("steps") or []
        if not steps:
            return []
        lines = []
        for s in steps:
            way = s.get("way") or ""
            if way in ("failed", "diverged"):
                way = f"{way}: {s.get('reason')}"
            elif s.get("check") == "unchecked" and s.get("reason"):
                way = f"{way} ({s.get('reason')}), unchecked"
            lines.append(f"  step {s.get('i')}: {s.get('what')} · {way}")
        return [Static("Replayed steps", classes="review-section"),
                Static(escape("\n".join(lines)))]  # fmt: skip

    def _file_widgets(self, fr: Any) -> list[Any]:
        from sandroid.core import rewind

        cls = {
            rewind.SAME: "verdict-same",
            rewind.DIFFERENT: "verdict-different",
        }.get(fr.verdict, "verdict-none")
        out: list[Any] = [
            Static(escape(_short(fr.path, self.rec.pkg, 90)), classes="review-section"),
            Static("What your action changed (Before to After)"),
            Static(escape(_clip_lines(fr.action_text or "no change"))),
        ]
        if fr.before is None:
            out.append(Static("Before was not copied.", classes="review-warn"))
        if fr.after is None:
            text = (
                rewind.LATE_WORDS.strip()
                if getattr(fr, "late", False)
                else "After was not copied."
            )
            out.append(Static(text, classes="review-warn"))
        if fr.after_replay is not None:
            out.append(Static("What the replay changed (Before to After (replay))"))
            out.append(Static(escape(_clip_lines(fr.replay_text or "no change"))))
            extra = [f"only in your run: {ln}" for ln in fr.only_run[:20]]
            extra += [f"only in the replay: {ln}" for ln in fr.only_replay[:20]]
            if extra:
                text = _clip_lines("\n".join(extra))
                out.append(Static(escape(text), classes="review-hint"))
        out.append(Static(fr.verdict, classes=cls))
        if getattr(fr, "note", ""):
            out.append(Static(escape(fr.note), classes="review-warn"))
        return out

    def _flow_widgets(self, flows: list[Any]) -> list[Any]:
        from sandroid.core import rewind

        out: list[Any] = []
        for f in flows:
            out.append(
                Static(
                    escape(rewind.request_text(f.original)), classes="review-section"
                )
            )
            found_cls = "verdict-same" if f.replay is not None else "verdict-different"
            out.append(Static(f.found, classes=found_cls))
            if f.replay is None:
                continue
            for part, value in (
                ("request body", f.body),
                ("response status", f.status),
            ):
                vcls = "verdict-same" if value == "same" else "verdict-different"
                out.append(Static(f"{part}: {value}", classes=vcls))
            cols = []
            for side in ("your run", "replay"):
                s = f.sides.get(side) or {}
                text = "\n".join(
                    [
                        side.capitalize() if side == "replay" else "Your run",
                        s.get("url", ""),
                        f"status {s.get('status', '')}",
                        *s.get("headers", [])[:30],
                        "",
                        _clip_lines(s.get("body", ""), 30),
                    ]
                )
                cols.append(Static(escape(text), classes="side"))
            row = Horizontal(*cols)
            row.styles.height = "auto"
            out.append(row)
        return out

    @staticmethod
    def _request_widgets(per_run: dict) -> list[Any]:
        from sandroid.core import rewind

        if not any((per_run or {}).values()):
            return []
        cols = []
        for title, reqs in per_run.items():
            body = "\n".join(rewind.request_text(r) for r in reqs[:40]) or "none"
            if len(reqs) > 40:
                body += f"\n… {len(reqs) - 40} more"
            cols.append(
                Static(escape(f"{title} ({len(reqs)})\n{body}"), classes="side")
            )
        row = Horizontal(*cols)
        row.styles.height = "auto"
        return [Static("Requests per run", classes="review-section"), row]

    def _current(self) -> bool:
        """This Review shows the controller's current recording."""
        return getattr(self.controller, "recording", self.rec) is self.rec

    def refresh_buttons(self) -> None:
        with contextlib.suppress(Exception):
            self._update_buttons()

    def _update_buttons(self) -> None:
        problem = self.controller.rewind_problem(self.rec)
        if not self._current():
            problem = "This Review shows an older recording. Press p for the new one."
        running = bool(getattr(self.controller, "is_replaying", False))
        for bid in ("#rewind-replay", "#rewind"):
            with contextlib.suppress(Exception):
                self.query_one(bid, Button).disabled = bool(problem) or running
        for lid in ("#review-files", "#review-requests"):
            with contextlib.suppress(Exception):
                # No selection while a rewind runs: the device is not after
                # the action then.
                self.query_one(lid, SelectionList).disabled = (
                    running or not self._current()
                )
        text = "" if running else (problem or self.rec.note or "")
        self.query_one("#review-problem", Static).update(escape(text))
        keep = self.query_one("#review-keep", Checkbox)
        keep.disabled = not self.rec.start_point_name
        self.query_one("#review-head", Static).update(self._head_text())

    # -- controller callbacks ---------------------------------------------------

    def set_progress(self, text: str) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#review-progress", Static).update(escape(text or ""))
            self._update_buttons()

    def set_file_state(self, path: str, text: str) -> None:
        from sandroid.core.rewind import main_database

        path = main_database(path)
        self._file_state[path] = text
        with contextlib.suppress(Exception):
            sel = self.query_one("#review-files", SelectionList)
            for idx in range(sel.option_count):
                option = sel.get_option_at_index(idx)
                if main_database(option.value) == path:
                    # Each row keeps its own name and size (a -wal row stays
                    # the -wal row; it only shows that its database is
                    # watched).
                    entry = next(
                        (e for e in self.rec.changed if e.get("path") == option.value),
                        {"path": option.value, "state": ""},
                    )
                    sel.replace_option_prompt_at_index(idx, self._file_prompt(entry))

    # -- events -----------------------------------------------------------------

    def on_selection_list_selection_toggled(
        self, event: SelectionList.SelectionToggled
    ) -> None:
        if self._building or not self._current():
            return
        event.stop()
        value = event.selection.value
        on = value in event.selection_list.selected
        if event.selection_list.id == "review-files":
            self.controller.select_file(value, on)
            if not on:
                self._file_state.pop(value, None)
            self.set_file_state(value, self._file_state.get(value, ""))
        elif event.selection_list.id == "review-requests":
            with contextlib.suppress(ValueError, IndexError):
                self.controller.select_flow(self.rec.requests[int(value)], on)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "review-name" and event.value.strip():
            self.controller.rename(event.value)
            with contextlib.suppress(Exception):
                self.query_one(".modal-title", Label).update(
                    f"Review · Recording '{self.rec.name}'"
                )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()  # Enter in the name field never starts a rewind

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "review-keep":
            self.controller.set_pinned(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        bid = event.button.id
        if bid == "close":
            self.action_cancel()
        elif bid in ("rewind", "rewind-replay") and self._current():
            replay = bid == "rewind-replay"
            if not self.rec.selected and not self._asked_empty:
                self._ask_empty(replay)
                return
            self._start(replay)

    def _start(self, replay: bool) -> None:
        if self.controller.start_rewind(replay=replay):
            self.set_progress("Going back to the start point")

    def _ask_empty(self, replay: bool) -> None:
        """No file selected: say that nothing will be compared and ask once
        (never blocks: Yes goes on, and the next press does not ask again).
        """
        from .confirm_modal import ConfirmModal

        self._asked_empty = True
        if replay and self.rec.selected_flows:
            message = (
                "No files selected: only the selected requests will be compared. Go on?"
            )
        else:
            message = "No files selected: nothing will be compared. Go on?"

        def answer(go: bool | None) -> None:
            if go and self._current():
                self._start(replay)

        self.app.push_screen(
            ConfirmModal(
                title="Rewind + Replay" if replay else "Rewind",
                message=message,
                yes_label="Go on",
                no_label="Back",
            ),
            answer,
        )

    def close_for_new_recording(self) -> None:
        """A new recording started: this Review shows an older one. Close it
        when it is on top (never pop a screen above it).
        """
        with contextlib.suppress(Exception):
            if self.is_attached and self.app.screen is self:
                self._dismiss_with_refresh(None)

    def action_cancel(self) -> None:
        """Esc: close, or ask to stop a running rewind (sync, see the base)."""
        if getattr(self.controller, "is_replaying", False):
            from .confirm_modal import ConfirmModal

            def answer(stop: bool | None) -> None:
                if stop:
                    self.controller.stop_rewind()

            self.app.push_screen(
                ConfirmModal(
                    title="Stop the replay?",
                    message="Before and After stay as far as they got.",
                    yes_label="Stop",
                    no_label="Continue",
                ),
                answer,
            )
            return
        self.controller.review_closed(self)
        self._dismiss_with_refresh(None)


#: Characters of one diff line the Review shows (a minified file is one line).
LINE_CHARS = 400


def _clip_line(line: str) -> str:
    if len(line) <= LINE_CHARS:
        return line
    return line[:LINE_CHARS] + f"… ({len(line) - LINE_CHARS} more characters)"


def _clip_lines(text: str, limit: int = 60) -> str:
    lines = (text or "").splitlines()
    shown = [_clip_line(ln) for ln in lines[:limit]]
    if len(lines) <= limit:
        return "\n".join(shown)
    return "\n".join(shown) + f"\n… {len(lines) - limit} more lines"
