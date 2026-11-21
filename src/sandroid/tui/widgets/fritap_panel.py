"""Non-visual friTap observer for the Network lens.

friTap already has a "manager": the ``FriTapCommand`` (key ``h``) plus the AFM
``JobManager`` + ``TaskService`` + the EventBus message stream. So this panel is
deliberately **thin and stateless** — it adds NO new service and NO config
schema. It reads live state from ``TaskService`` and tails the EventBus
``TASK_OUTPUT`` stream; Start/Stop is delegated verbatim to the existing
command (the same path the ``h`` key runs), which owns all preconditions, the
config modal, task registration, the paused-spawn guard, and dual-path cleanup
— all on a worker thread so the UI never blocks.

Mounted *hidden* inside the Network lens (like ``MitmproxyPanel``): the lens
shows friTap's state in its caption (``friTap on``) and on the friTap tab of its
"Network status" Inspector page (``h`` or ``I``), built from
:meth:`FriTapPanel.status_rows` and the bounded ``recent_lines`` tail. friTap's
output itself reaches the ActivityLog drawer through ``MainScreen``'s generic
TASK_OUTPUT handler, so this widget does not write it there a second time.

Uses ``SpotlightPanel``'s thread-safe EventBus idiom: capture the running loop
in ``on_mount`` and marshal callbacks with ``loop.call_soon_threadsafe`` —
never ``call_from_thread``, which would deadlock when friTap publishes from its
Frida / logger threads.

Actions (bound on the Network lens):
    h (global):  start / stop friTap (delegates to FriTapCommand)
    Ctrl+F:      open the friTap results folder in the OS file manager
"""

from __future__ import annotations

import collections
import logging
import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from rich.markup import escape
from textual.widget import Widget

from sandroid.services import get_network_capture_service, get_task_service
from sandroid.tui.utils.ui_thread import UiDispatcher

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


class FriTapPanel(Widget):
    """Hidden friTap observer (id ``fritap-panel``): state + bounded log tail.

    Stateless: owns no manager instances. The single source of truth is the
    process-wide ``TaskService`` (lifecycle/state) + the EventBus (log tail),
    so a Textual widget recreation never orphans a running friTap job.
    """

    DEFAULT_CSS = """
    FriTapPanel {
        display: none;
        height: 0;
    }
    """

    #: friTap lines kept for the Inspector page.
    RECENT_LINES = 200

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = False
        # Plain-text tail for the lens's friTap Inspector page.
        self.recent_lines: collections.deque[str] = collections.deque(
            maxlen=self.RECENT_LINES
        )
        # Captured in on_mount; used to marshal EventBus callbacks (which fire
        # on Frida/logger threads) back onto the Textual main thread.
        self._main_loop = None
        self._ui = UiDispatcher()
        self._event_handlers: list = []
        # Glance-only, string-shape-based activity counters.
        self._keys = 0
        self._datalog = 0
        self._errors = 0

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        return iter(())

    def on_mount(self) -> None:
        self._subscribe_events()
        self.refresh_header()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            # Thread -> UI hand-off in the UI's contextvars context (see
            # sandroid.tui.utils.ui_thread: a bare loop callback lacks
            # Textual's active_app and its timers raised LookupError).
            self._ui = UiDispatcher.capture()
            self._main_loop = self._ui.loop

            bus = EventBus.get()

            # Fire-and-forget onto the main loop; never blocks the
            # publisher's thread (avoids the call_from_thread deadlock).
            _schedule = self._ui.post

            def _output_cb(event) -> None:
                _schedule(self._on_task_output, event)

            bus.subscribe(EventType.TASK_OUTPUT, _output_cb)
            self._event_handlers.append((EventType.TASK_OUTPUT, _output_cb))

            # Lifecycle transitions flip the header (running ⇄ stopped). The
            # start/stop runs on FriTapCommand's worker thread, so the toggle's
            # own refresh_header() fires too early — without these the header
            # stays stale until the next tab switch.
            def _make_refresh_cb():
                def _cb(_event) -> None:
                    _schedule(self.refresh_header)

                return _cb

            for event_type in (EventType.TASK_STARTED, EventType.TASK_STOPPED):
                cb = _make_refresh_cb()
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))

            # friTap's own lifecycle (starting / stopping / hung / failed),
            # which the task registry does not see.
            def _phase_cb(event) -> None:
                if getattr(event, "source", None) == "fritap":
                    _schedule(self.refresh_header)

            bus.subscribe(EventType.STATE_CHANGED, _phase_cb)
            self._event_handlers.append((EventType.STATE_CHANGED, _phase_cb))
        except Exception as exc:
            logger.debug(f"FriTapPanel event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    def _on_task_output(self, event) -> None:
        """Handle a TASK_OUTPUT event (runs on the UI thread).

        Source-only match: another task that happens to emit the same
        ``task_name`` ("FriTap") must not leak into this panel, so we filter on
        ``event.source == "fritap"`` and nothing else.
        """
        if getattr(event, "source", None) != "fritap":
            return
        data = getattr(event, "data", None) or {}
        message = data.get("message", "")
        if message:
            self._append_line(message)

    # -- log rendering ----------------------------------------------------

    @staticmethod
    def _strip_pseudo_tags(line: str) -> tuple[str, bool, bool]:
        """Strip friTap's semantic pseudo-tags, reporting what was present.

        ``EventBusHandler.emit`` wraps error/warning log lines in
        ``[error]…[/error]`` / ``[warning]…[/warning]``. These are NOT Rich
        styles — left in place they would render in the Inspector page
        as the literal text ``[error]``. Strip them, but remember they were
        there so the colour/counter dispatch can still treat the line as an
        error/warning.
        """
        was_error = "[error]" in line or "[/error]" in line
        was_warning = "[warning]" in line or "[/warning]" in line
        for tag in ("[error]", "[/error]", "[warning]", "[/warning]"):
            line = line.replace(tag, "")
        return line, was_error, was_warning

    def _append_line(self, line: str) -> None:
        # A fresh session resets the glance counters (the engine emits this
        # sentinel only when activity-log output is enabled).
        if "FriTap started for" in line:
            self._keys = self._datalog = self._errors = 0

        stripped, was_error, was_warning = self._strip_pseudo_tags(line)

        # Prefix/substring dispatch. Shapes come from fritap_formatter.py:
        # keylog "TLS key …" (older engines: "🔑 …"), datalog "… (N bytes)",
        # error "ERROR: …". A key emoji is shown as the words (N3-V4).
        if stripped.startswith("🔑"):
            stripped = "TLS key" + stripped[1:].rstrip()
        if stripped.startswith("TLS key"):
            self._keys += 1
        elif "bytes)" in stripped:
            self._datalog += 1
        elif was_error or "ERROR:" in stripped:
            self._errors += 1
            stripped = f"✗ {stripped}"
        elif was_warning:
            stripped = f"! {stripped}"
        self.recent_lines.append(stripped)

        self.refresh_header()

    # -- header -----------------------------------------------------------

    @staticmethod
    def _check_tag(label: str, ok: bool) -> str:
        if ok:
            return f"[#4ade80]{label} ● on[/]"
        return f"[#5b6479]{label} ○ off[/]"

    @staticmethod
    def _phase() -> tuple[str, str]:
        """The lifecycle phase of friTap (see ``sandroid.analysis.fritap``)."""
        try:
            from sandroid.analysis.fritap import lifecycle

            return lifecycle()
        except Exception:
            return "stopped", ""

    def caption_token(self) -> str:
        """The lens caption's friTap fragment: a problem or a transition
        (starting, stopping, failed, not responding) in words and theme
        colours; ``""`` while it runs fine or is cleanly stopped.
        """
        from sandroid.tui.themes import lens_palette

        pal = lens_palette()
        running = self.is_running()
        phase, _detail = self._phase()
        if phase == "starting" and not running:
            return f"[{pal.warn}]friTap ◌ starting[/]"
        if phase == "stopping":
            return f"[{pal.warn}]friTap ◌ stopping[/]"
        if phase == "failed" and not running:
            if _detail.startswith("did not start"):
                return f"[{pal.bad}]friTap did not start[/]"
            # e.g. an agent stuck in a frozen app: not a clean stop.
            return f"[{pal.bad}]friTap failed[/]"
        if not running:
            return ""
        if phase == "hung":
            return f"[{pal.warn}]friTap app not responding[/]"
        # Running fine: the status bar and the friTap tab say so (N3-V2; main's R3
        # "friTap ● running" would be the only running state in the title).
        return ""

    @staticmethod
    def _mark(ok: bool) -> str:
        from sandroid.tui.themes import lens_palette

        pal = lens_palette()
        return f"[{pal.ok}]● on[/]" if ok else f"[{pal.dim}]○ off[/]"

    def _render_header(self) -> str:
        from sandroid.tui.themes import lens_palette

        pal = lens_palette()
        task = None
        running = False
        try:
            task = get_task_service().get_task("fritap")
        except Exception:
            pass
        running = self.is_running()

        inst = getattr(task, "instance", None)

        if running:
            app = (
                getattr(inst, "app_package", None)
                or getattr(task, "app_name", None)
                or "?"
            )
            pid = getattr(inst, "process_id", None) or getattr(task, "target_pid", None)
            mode = getattr(inst, "mode", None)
            mode = getattr(mode, "value", mode)  # SpawnMode enum or str
            problem = None
            try:
                problem = inst.target_problem() if inst is not None else None
            except Exception:
                problem = None
            if isinstance(problem, str) and problem:
                # Don't claim "running" for a job whose app/agent died.
                head = f"[{pal.warn}]not capturing[/] ({problem[:60]})   [b]{app}[/]"
            else:
                head = f"[{pal.ok}]● running[/]   [b]{app}[/]"
            if mode:
                head += f"  [#5b6479]{mode}[/]"
            if pid:
                head += f"  [#5b6479]pid {pid}[/]"
        else:
            head = f"[{pal.dim}]○ stopped[/]"
        phase, detail = self._phase()
        if phase == "starting" and not running:
            head = f"[{pal.warn}]◌ starting[/] (attaching, loading the agent)"
        elif phase == "stopping":
            head = f"[{pal.warn}]◌ stopping[/] (unloading the agent)"
        elif phase == "hung" and running:
            head = (
                f"[{pal.warn}]{escape(detail or 'app not responding')}[/] — "
                "h stops friTap"
            )
        elif phase == "failed" and not running and detail.startswith("did not start"):
            # A start that failed or hung: the reason in red words.
            head = f"[{pal.bad}]{escape(detail[:120])}[/]"
        elif phase == "failed" and not running:
            head = f"[{pal.bad}]failed[/] {escape(detail[:80])}"
        elif phase == "stopped" and not running and detail:
            head = f"[{pal.dim}]○ stopped ({escape(detail)})[/]"

        checks = []
        if running:
            checks.append(
                self._check_tag("keylog", bool(getattr(inst, "keylog_path", None)))
            )
            checks.append(
                self._check_tag("json", bool(getattr(inst, "json_output_path", None)))
            )
        # Network capture is an independent, coexisting layer (friTap can start
        # it); read its ground truth regardless of friTap's own state.
        try:
            net_on = bool(get_network_capture_service().is_capturing())
        except Exception:
            net_on = False
        checks.append("[#4ade80]net ●[/]" if net_on else "[#5b6479]net ○[/]")

        err_tag = (
            f"[#fb7185]err {self._errors}[/]" if self._errors else "[#5b6479]err 0[/]"
        )
        counters = f"keys [b]{self._keys}[/]  data [b]{self._datalog}[/]  {err_tag}"

        return f"{head}   {'  '.join(checks)}   {counters}"

    def refresh_header(self) -> None:
        """Tell the Network lens friTap's state changed (main thread)."""
        node = self.parent
        while node is not None and not hasattr(node, "refresh_status"):
            node = node.parent
        if node is not None:
            try:
                node.refresh_status()
            except Exception:
                logger.debug("network lens status refresh failed", exc_info=True)

    def is_running(self) -> bool:
        try:
            return bool(get_task_service().is_running("fritap"))
        except Exception:
            return False

    def status_rows(self) -> list[tuple[str, str]]:
        """``[(label, markup)]`` for the friTap Inspector page."""
        rows = [("friTap", self._render_header().split("   ", 1)[0])]
        task = None
        try:
            task = get_task_service().get_task("fritap")
        except Exception:
            pass
        inst = getattr(task, "instance", None)
        if self.is_running():
            rows.append(
                ("keylog", self._mark(bool(getattr(inst, "keylog_path", None))))
            )
            rows.append(
                ("json", self._mark(bool(getattr(inst, "json_output_path", None))))
            )
        try:
            net_on = bool(get_network_capture_service().is_capturing())
        except Exception:
            net_on = False
        from sandroid.tui.themes import lens_palette

        pal = lens_palette()
        rows.append(
            (
                "pcap",
                f"[{pal.ok}]● capturing[/]" if net_on else f"[{pal.dim}]○ off[/]",
            )
        )
        err = f"[#fb7185]{self._errors}[/]" if self._errors else "0"
        rows.append(
            ("seen", f"keys {self._keys} · data {self._datalog} · errors {err}")
        )
        return rows

    # -- actions ----------------------------------------------------------

    def action_toggle_running(self) -> None:
        """Enter — delegate Start/Stop to the existing FriTap command (key h).

        The command owns ALL preconditions (frida-server up, spotlight app),
        the config modal, task registration, the paused-spawn guard, and the
        dual-path cleanup — and dispatches the blocking Frida work to its own
        worker thread (``is_blocking_io=True``). So we just trigger it; do NOT
        wrap this in a second worker (double-dispatch).
        """
        self.recent_lines.append("friTap toggle requested…")
        try:
            self.app.action_action_key("h")
        except Exception as exc:
            logger.warning("FriTap toggle failed: %s", exc)
        self.refresh_header()

    def action_clear_log(self) -> None:
        self.recent_lines.clear()
        self._keys = self._datalog = self._errors = 0
        self.refresh_header()

    def action_open_output(self) -> None:
        """Ctrl+O — open the friTap results folder in the OS file manager."""
        folder = self._output_folder()
        if folder is None or not folder.exists():
            try:
                self.app.notify(
                    "friTap output folder not found yet — start friTap first.",
                    severity="warning",
                )
            except Exception:
                pass
            return
        self._open_folder(folder)

    # -- helpers ----------------------------------------------------------

    def _output_folder(self) -> Path | None:
        """Resolve the friTap results folder via PUBLIC paths only.

        When running, derive it from the live instance's ``log_path`` (a public
        attribute) rather than importing the engine's private
        ``_get_device_results_path``. Otherwise fall back to the canonical
        ``<device>/fritap/`` folder. Never creates the folder.
        """
        try:
            task = get_task_service().get_task("fritap")
            log_path = getattr(getattr(task, "instance", None), "log_path", None)
            if log_path:
                return Path(log_path).parent
        except Exception:
            pass
        try:
            from sandroid.services import get_initialization_service

            device_path = get_initialization_service().get_device_path()
            if device_path:
                return Path(device_path) / "fritap"
        except Exception:
            pass
        return None

    def _open_folder(self, target: Path) -> None:
        """Open ``target`` in the OS file manager (mirrors MitmproxyPanel).

        Best-effort: a raw ``webbrowser.open()`` on a folder is unreliable
        (macOS opens a browser tab), so use a platform opener and fall back to
        a ``file://`` URI.
        """
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target)], stdin=subprocess.DEVNULL)
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)], stdin=subprocess.DEVNULL)
            else:
                webbrowser.open(Path(target).as_uri())
        except Exception as exc:
            logger.warning("Failed to open friTap output folder %s: %s", target, exc)
