"""TUI panel that observes and drives the friTap SSL/TLS interception engine.

friTap already has a "manager": the ``FriTapCommand`` (key ``h``) plus the AFM
``JobManager`` + ``TaskService`` + the EventBus message stream. So this panel is
deliberately **thin and stateless** — it adds NO new service and NO config
schema. It reads live state from ``TaskService`` and tails the EventBus
``TASK_OUTPUT`` stream; Start/Stop is delegated verbatim to the existing
command (the same path the ``h`` key runs), which owns all preconditions, the
config modal, task registration, the paused-spawn guard, and dual-path cleanup
— all on a worker thread so the UI never blocks.

Mirrors ``MitmproxyPanel`` (panel structure, header/log, OS folder opener) and
``SpotlightPanel`` (the thread-safe EventBus idiom: capture the running loop in
``on_mount`` and marshal callbacks with ``loop.call_soon_threadsafe`` — never
``call_from_thread``, which would deadlock when friTap publishes from its Frida
/ logger threads).

Bindings (when focused):
    Enter:  start / stop friTap (delegates to FriTapCommand)
    Ctrl+O: open the friTap results folder in the OS file manager
    Ctrl+L: clear the log view + reset the activity counters
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog, Static

from sandroid.services import get_network_capture_service, get_task_service

logger = logging.getLogger(__name__)


class FriTapPanel(Widget):
    """Bottom-left panel: friTap status header + live log tail.

    Stateless: owns no manager instances. The single source of truth is the
    process-wide ``TaskService`` (lifecycle/state) + the EventBus (log tail),
    so a Textual widget recreation never orphans a running friTap job.
    """

    DEFAULT_CSS = """
    FriTapPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    FriTapPanel > #fritap-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    FriTapPanel > #fritap-log {
        height: 1fr;
        background: #050811;
        scrollbar-size: 1 1;
    }
    """

    BINDINGS = [
        ("enter", "toggle_running", "Start/Stop"),
        ("ctrl+o", "open_output", "Open output"),
        ("ctrl+l", "clear_log", "Clear log"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        # Captured in on_mount; used to marshal EventBus callbacks (which fire
        # on Frida/logger threads) back onto the Textual main thread.
        self._main_loop = None
        self._event_handlers: list = []
        # Glance-only, string-shape-based activity counters.
        self._keys = 0
        self._datalog = 0
        self._errors = 0

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="fritap-header")
        yield RichLog(
            highlight=False,
            markup=True,
            wrap=False,
            auto_scroll=True,
            id="fritap-log",
        )

    def on_mount(self) -> None:
        self._subscribe_events()
        try:
            self.query_one("#fritap-log", RichLog).write(
                "[#5b6479]Enter: start/stop · Ctrl+O: open output · Ctrl+L: clear[/]"
            )
        except Exception:
            pass
        self.refresh_header()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------

    def _subscribe_events(self) -> None:
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            try:
                self._main_loop = asyncio.get_running_loop()
            except RuntimeError:
                self._main_loop = None

            bus = EventBus.get()

            def _schedule(fn, *args) -> None:
                # Fire-and-forget onto the main loop; never blocks the
                # publisher's thread (avoids the call_from_thread deadlock).
                loop = self._main_loop
                try:
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(fn, *args)
                except RuntimeError:
                    pass

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
        styles — the RichLog has ``markup=True``, so left in place they render
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
        try:
            log = self.query_one("#fritap-log", RichLog)
        except Exception:
            return

        # A fresh session resets the glance counters (the engine emits this
        # sentinel only when activity-log output is enabled).
        if "FriTap started for" in line:
            self._keys = self._datalog = self._errors = 0

        stripped, was_error, was_warning = self._strip_pseudo_tags(line)

        # Prefix/substring dispatch with explicit hex colours. Shapes come from
        # fritap_formatter.py: keylog "🔑 …", datalog "… (N bytes)", error
        # "ERROR: …".
        if "🔑" in stripped:
            self._keys += 1
            log.write(f"[#a78bfa]{stripped}[/]")
        elif "bytes)" in stripped:
            self._datalog += 1
            log.write(f"[#7dd3fc]{stripped}[/]")
        elif was_error or "ERROR:" in stripped:
            self._errors += 1
            log.write(f"[#fb7185]{stripped}[/]")
        elif was_warning:
            log.write(f"[#facc15]{stripped}[/]")
        else:
            log.write(f"[#5b6479]{stripped}[/]")

        self.refresh_header()

    # -- header -----------------------------------------------------------

    @staticmethod
    def _check_tag(label: str, ok: bool) -> str:
        if ok:
            return f"[#4ade80]{label} ✓[/]"
        return f"[#5b6479]{label} ○[/]"

    def _render_header(self) -> str:
        task = None
        running = False
        try:
            svc = get_task_service()
            running = bool(svc.is_running("fritap"))
            task = svc.get_task("fritap")
        except Exception:
            pass

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
            head = f"[#4ade80]● running[/]   [b]{app}[/]"
            if mode:
                head += f"  [#5b6479]{mode}[/]"
            if pid:
                head += f"  [#5b6479]pid {pid}[/]"
        else:
            head = "[#fb7185]○ stopped[/]"

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
        """Re-render the status header (main thread; best-effort).

        Public so ``MainScreen._select_bottom_tab`` can refresh it the moment
        the friTap tab is activated, avoiding a stale header.
        """
        try:
            self.query_one("#fritap-header", Static).update(self._render_header())
        except Exception:
            pass

    # -- actions ----------------------------------------------------------

    def action_toggle_running(self) -> None:
        """Enter — delegate Start/Stop to the existing FriTap command (key h).

        The command owns ALL preconditions (frida-server up, spotlight app),
        the config modal, task registration, the paused-spawn guard, and the
        dual-path cleanup — and dispatches the blocking Frida work to its own
        worker thread (``is_blocking_io=True``). So we just trigger it; do NOT
        wrap this in a second worker (double-dispatch).
        """
        try:
            self.query_one("#fritap-log", RichLog).write(
                "[#7dd3fc][INFO] friTap toggle requested…[/]"
            )
        except Exception:
            pass
        try:
            self.app.action_action_key("h")
        except Exception as exc:
            logger.warning("FriTap toggle failed: %s", exc)
        self.refresh_header()

    def action_clear_log(self) -> None:
        try:
            self.query_one("#fritap-log", RichLog).clear()
        except Exception:
            pass
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
                subprocess.Popen(["open", str(target)])
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)])
            else:
                webbrowser.open(Path(target).as_uri())
        except Exception as exc:
            logger.warning("Failed to open friTap output folder %s: %s", target, exc)
