"""TUI panel that observes and drives dexray-intercept malware monitoring.

dexray-intercept already has a "manager": the ``MalwareMonitorCommand`` (key
``m``) plus the AFM ``JobManager`` + ``TaskService`` + the EventBus message
stream. So this panel is deliberately **thin and stateless** for lifecycle —
it reads live state from ``TaskService`` and tails the EventBus ``TASK_OUTPUT``
stream, and delegates Start/Stop verbatim to the existing command (the same
path the ``m`` key runs), which owns all preconditions, task registration, the
spawn/attach session, and dual-path cleanup — all on a worker thread.

What this panel adds over ``FriTapPanel`` is **in-tab configuration**: the hook
groups and a couple of AppProfiler options are toggled here as ●/○ cells, with
DEX **unpacking** pulled into its own highlighted section. The chosen config is
held in the process-wide ``DexrayConfigService`` (a single source of truth that
survives Textual widget recreation) and consumed on Start, so the legacy
interactive prompt is skipped. See ``MalwareMonitor._apply_panel_config_if_present``.

Mirrors ``SpotlightPanel`` (toggle-body + clickable action cells + the
thread-safe EventBus idiom) and ``FriTapPanel`` (stateless header/log,
``self.app.action_action_key(...)`` delegation, OS folder opener).

Bindings (when focused):
    u:       toggle DEX unpacking (both native + Java DEX hooks)
    d / j:   toggle native-DEX / java-DEX unpacking individually
    1-6:     toggle Crypto / Network / Filesystem / IPC / Services / Bypass
    7:       toggle Process (native library / runtime / process hooks)
    f / t:   toggle FriTap (TLS capture) / full stacktrace
    Enter:   start / stop dexray-intercept (delegates to MalwareMonitorCommand)
    Ctrl+R:  reset config to defaults
    Ctrl+O:  open the unpacked-DEX output folder
    Ctrl+L:  clear the log + reset activity counters
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import RichLog, Static

from sandroid.services import get_task_service

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# TaskService name + EventBus source string the MalwareMonitor publishes under.
_TASK_NAME = "dexray-intercept"
_EVENT_SOURCE = "malwaremonitor"

# Amber: the "unpacking" accent colour, set apart from the blue section heads.
_AMBER = "#f59e0b"
_GREEN = "#4ade80"
_DIM = "#5b6479"

# (binding key, group key, label) for the category group toggles. "process" is
# intentionally absent — its DEX hooks are surfaced in the dedicated Unpacking
# section and its remaining hooks under "Process" (key 7).
_GROUP_TOGGLES = [
    ("1", "crypto", "Crypto"),
    ("2", "network", "Network"),
    ("3", "filesystem", "Filesystem"),
    ("4", "ipc", "IPC"),
    ("5", "services", "Services"),
    ("6", "bypass", "Bypass"),
]

# The two DEX-unpacking hook keys (the highlighted Unpacking section).
_DEX_HOOKS = ("dex_unpacking_hooks", "java_dex_unpacking_hooks")

# The "process" group minus the two DEX hooks (toggled together by key 7).
_PROCESS_REST_HOOKS = ("native_library_hooks", "process_hooks", "runtime_hooks")

# (binding key, profiler_settings key, label) for the AppProfiler options.
_OPTION_TOGGLES = [
    ("f", "enable_fritap", "FriTap (TLS)"),
    ("t", "enable_stacktrace", "Stacktrace"),
]

# Clickable action-cell id -> panel action method. Routed from
# MainScreen.on_click (same dispatch as SpotlightPanel's act-* cells).
_ACTION_CELLS = {
    "dx-primary": "action_toggle_running",
    "dx-unpack": "action_toggle_unpacking",
    "dx-reset": "action_reset_config",
    "dx-output": "action_open_output",
    "dx-clear": "action_clear_log",
}


class DEXrayPanel(Widget):
    """Bottom-left panel: dexray-intercept config + status + live log tail.

    Stateless for lifecycle (TaskService + EventBus are the source of truth);
    the in-tab hook/profiler configuration lives in the process-wide
    ``DexrayConfigService`` so it also survives widget recreation.
    """

    DEFAULT_CSS = """
    DEXrayPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    DEXrayPanel > #dexray-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    DEXrayPanel > #dexray-config {
        height: auto;
        background: #0a0f1e;
        padding: 0 1;
        border-bottom: solid #1f2d4d;
    }
    DEXrayPanel > #dexray-log {
        height: 1fr;
        background: #050811;
        scrollbar-size: 1 1;
    }
    DEXrayPanel > #dexray-actions {
        height: 1;
        dock: bottom;
        background: #0b1628;
    }
    DEXrayPanel .act-cell {
        width: auto;
        padding: 0 1;
        color: #93a4c3;
    }
    DEXrayPanel .act-cell:hover {
        background: #1f2937;
        color: #7dd3fc;
        text-style: bold;
    }
    """

    BINDINGS = [
        # Unpacking (highlighted section)
        ("u", "toggle_unpacking", "Unpacking"),
        ("d", "toggle_hook('dex_unpacking_hooks')", "Native DEX"),
        ("j", "toggle_hook('java_dex_unpacking_hooks')", "Java DEX"),
        # Category groups
        ("1", "toggle_group('crypto')", "Crypto"),
        ("2", "toggle_group('network')", "Network"),
        ("3", "toggle_group('filesystem')", "Filesystem"),
        ("4", "toggle_group('ipc')", "IPC"),
        ("5", "toggle_group('services')", "Services"),
        ("6", "toggle_group('bypass')", "Bypass"),
        ("7", "toggle_process_rest", "Process"),
        # AppProfiler options
        ("f", "toggle_option('enable_fritap')", "FriTap"),
        ("t", "toggle_option('enable_stacktrace')", "Stacktrace"),
        # Lifecycle / utility
        ("enter", "toggle_running", "Start/Stop"),
        ("ctrl+r", "reset_config", "Reset config"),
        ("ctrl+o", "open_output", "Open output"),
        ("ctrl+l", "clear_log", "Clear log"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        # Captured in on_mount; marshals EventBus callbacks (Frida/logger
        # threads) back onto the Textual main thread.
        self._main_loop = None
        self._event_handlers: list = []
        # Glance-only, string-shape-based activity counters.
        self._unpacked = 0
        self._errors = 0

    # -- services (lazy) --------------------------------------------------

    @staticmethod
    def _svc():
        from sandroid.services import get_dexray_config_service

        return get_dexray_config_service()

    @staticmethod
    def _is_running() -> bool:
        try:
            return bool(get_task_service().is_running(_TASK_NAME))
        except Exception:
            return False

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="dexray-header")
        yield Static(self._render_config(), id="dexray-config")
        yield RichLog(
            highlight=False,
            markup=True,
            wrap=False,
            auto_scroll=True,
            id="dexray-log",
        )
        with Horizontal(id="dexray-actions"):
            yield Static(self._primary_label(), id="dx-primary", classes="act-cell")
            yield Static("u unpack", id="dx-unpack", classes="act-cell")
            yield Static("^R reset", id="dx-reset", classes="act-cell")
            yield Static("^O output", id="dx-output", classes="act-cell")
            yield Static("^L clear", id="dx-clear", classes="act-cell")

    def on_mount(self) -> None:
        self._subscribe_events()
        try:
            self.query_one("#dexray-log", RichLog).write(
                "[#5b6479]Toggle hooks above · Enter: start/stop · "
                "Ctrl+O: open unpacked/ · Ctrl+L: clear[/]"
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
            # start/stop runs on MalwareMonitorCommand's worker thread, so the
            # toggle's own refresh_header() fires too early — without these the
            # header stays stale until the next tab switch.
            def _make_refresh_cb():
                def _cb(_event) -> None:
                    _schedule(self.refresh_header)

                return _cb

            for event_type in (EventType.TASK_STARTED, EventType.TASK_STOPPED):
                cb = _make_refresh_cb()
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"DEXrayPanel event subscribe failed: {exc}")

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

        Source-only match: another task that emits the same ``task_name`` must
        not leak into this panel, so we filter on ``event.source`` and nothing
        else (mirrors FriTapPanel).
        """
        if getattr(event, "source", None) != _EVENT_SOURCE:
            return
        data = getattr(event, "data", None) or {}
        message = data.get("message", "")
        if message:
            self._append_line(message)

    # -- log rendering ----------------------------------------------------

    @staticmethod
    def _strip_pseudo_tags(line: str) -> tuple[str, bool, bool]:
        """Strip the EventBus handler's ``[error]``/``[warning]`` pseudo-tags.

        These are NOT Rich styles (the RichLog has ``markup=True``), so left in
        place they render as the literal text ``[error]``. Strip them but
        remember they were present for colour/counter dispatch.
        """
        was_error = "[error]" in line or "[/error]" in line
        was_warning = "[warning]" in line or "[/warning]" in line
        for tag in ("[error]", "[/error]", "[warning]", "[/warning]"):
            line = line.replace(tag, "")
        return line, was_error, was_warning

    def _append_line(self, line: str) -> None:
        try:
            log = self.query_one("#dexray-log", RichLog)
        except Exception:
            return

        stripped, was_error, was_warning = self._strip_pseudo_tags(line)
        low = stripped.lower()

        # Best-effort DEX-dump detection. The exact wording is produced inside
        # the external dexray_intercept package, so match a tunable substring
        # set rather than a fixed string. A miss only costs an un-incremented
        # counter — never an exception.
        if "dex" in low and any(
            token in low for token in ("dump", "unpack", "written", "saved", ".dex")
        ):
            self._unpacked += 1
            log.write(f"[{_AMBER}]{stripped}[/]")
        elif was_error or "ERROR:" in stripped:
            self._errors += 1
            log.write(f"[#fb7185]{stripped}[/]")
        elif was_warning:
            log.write(f"[#facc15]{stripped}[/]")
        else:
            log.write(f"[{_DIM}]{stripped}[/]")

        self.refresh_header()

    # -- header + config rendering ----------------------------------------

    def _render_header(self) -> str:
        running = self._is_running()
        cfg = self._svc().hook_configuration
        count = cfg.get_enabled_count()
        unpack_on = any(cfg.is_hook_enabled(h) for h in _DEX_HOOKS)

        if running:
            task = None
            try:
                task = get_task_service().get_task(_TASK_NAME)
            except Exception:
                pass
            inst = getattr(task, "instance", None)
            app = (
                getattr(inst, "app_package", None)
                or getattr(task, "app_name", None)
                or "?"
            )
            pid = getattr(task, "target_pid", None) or getattr(inst, "_app_pid", None)
            head = f"[{_GREEN}]● running[/]   [b]{app}[/]"
            if pid:
                head += f"  [{_DIM}]pid {pid}[/]"
        else:
            head = f"[#fb7185]○ stopped[/]   [{_DIM}]hooks {count} armed[/]"

        unpack_tag = (
            f"[{_AMBER}]unpack ●[/]" if unpack_on else f"[{_DIM}]unpack ○[/]"
        )
        dex_tag = (
            f"[{_AMBER}]DEX {self._unpacked}[/]"
            if self._unpacked
            else f"[{_DIM}]DEX 0[/]"
        )
        err_tag = (
            f"[#fb7185]err {self._errors}[/]" if self._errors else f"[{_DIM}]err 0[/]"
        )
        if running:
            return f"{head}   hooks [b]{count}[/]   {unpack_tag}   {dex_tag}   {err_tag}"
        return f"{head}   {unpack_tag}   {dex_tag}   {err_tag}"

    @staticmethod
    def _toggle_cell(key: str, on: bool, label: str, on_color: str = _GREEN) -> str:
        color = on_color if on else _DIM
        mark = "●" if on else "○"
        return f"[{color}][b]{key}[/] {mark} {label}[/]"

    def _render_config(self) -> str:
        svc = self._svc()
        cfg = svc.hook_configuration
        lines: list[str] = []

        # 1. Unpacking — highlighted (amber), at the top.
        dex_native = cfg.is_hook_enabled("dex_unpacking_hooks")
        dex_java = cfg.is_hook_enabled("java_dex_unpacking_hooks")
        unpack_on = dex_native or dex_java
        lines.append(
            f"[{_AMBER} bold]⬇ UNPACKING[/]  "
            f"[{_DIM}](dumps DEX to unpacked/)[/]"
        )
        lines.append(
            "  "
            + self._toggle_cell("u", unpack_on, "All DEX", on_color=_AMBER)
            + "   "
            + self._toggle_cell("d", dex_native, "Native DEX", on_color=_AMBER)
            + "   "
            + self._toggle_cell("j", dex_java, "Java DEX", on_color=_AMBER)
        )
        lines.append("")

        # 2. Hook groups.
        lines.append("[#7dd3fc bold]Hook groups[/]")
        cells = [
            self._toggle_cell(key, cfg.is_group_enabled(group), label)
            for key, group, label in _GROUP_TOGGLES
        ]
        proc_on = any(cfg.is_hook_enabled(h) for h in _PROCESS_REST_HOOKS)
        cells.append(self._toggle_cell("7", proc_on, "Process"))
        lines.append("  " + "   ".join(cells))
        lines.append("")

        # 3. AppProfiler options.
        lines.append("[#7dd3fc bold]Options[/]")
        opt_cells = [
            self._toggle_cell(key, bool(svc.get_profiler_setting(skey)), label)
            for key, skey, label in _OPTION_TOGGLES
        ]
        lines.append("  " + "   ".join(opt_cells))

        # 4. Hint — wording depends on running state (armed-applies-on-restart).
        if self._is_running():
            lines.append(
                f"[{_DIM}](toggle to arm · Enter to restart DEXray with new hooks)[/]"
            )
        else:
            lines.append(f"[{_DIM}](toggle to arm · applies on Start)[/]")

        return "\n".join(lines)

    def _primary_label(self) -> str:
        """Context-sensitive label for the Enter / primary action cell."""
        return "■ Stop" if self._is_running() else "⏎ Start"

    def refresh_header(self) -> None:
        """Re-render the status header + config body (main thread; best-effort).

        Public so ``MainScreen._select_bottom_tab`` can refresh it the moment
        the DEXray tab is activated, avoiding a stale header/config.
        """
        try:
            self.query_one("#dexray-header", Static).update(self._render_header())
        except Exception:
            pass
        self._refresh_config()

    def _refresh_config(self) -> None:
        try:
            self.query_one("#dexray-config", Static).update(self._render_config())
            self.query_one("#dx-primary", Static).update(self._primary_label())
        except Exception:
            pass

    # -- config toggle actions --------------------------------------------

    def action_toggle_group(self, group: str) -> None:
        self._svc().hook_configuration.toggle_group(group)
        self.refresh_header()

    def action_toggle_hook(self, hook: str) -> None:
        self._svc().hook_configuration.toggle(hook)
        self.refresh_header()

    def action_toggle_unpacking(self) -> None:
        """Toggle BOTH DEX-unpacking hooks together (mirrors toggle_group)."""
        cfg = self._svc().hook_configuration
        new_state = not any(cfg.is_hook_enabled(h) for h in _DEX_HOOKS)
        for hook in _DEX_HOOKS:
            cfg.enable_hook(hook) if new_state else cfg.disable_hook(hook)
        self.refresh_header()

    def action_toggle_process_rest(self) -> None:
        """Toggle the non-DEX process hooks (native library / runtime / process)."""
        cfg = self._svc().hook_configuration
        new_state = not any(cfg.is_hook_enabled(h) for h in _PROCESS_REST_HOOKS)
        for hook in _PROCESS_REST_HOOKS:
            cfg.enable_hook(hook) if new_state else cfg.disable_hook(hook)
        self.refresh_header()

    def action_toggle_option(self, key: str) -> None:
        self._svc().toggle_profiler_setting(key)
        self.refresh_header()

    def action_reset_config(self) -> None:
        self._svc().reset()
        try:
            self.app.notify("DEXray config reset to defaults.", severity="information")
        except Exception:
            pass
        self.refresh_header()

    # -- lifecycle / utility actions --------------------------------------

    def action_toggle_running(self) -> None:
        """Enter — delegate Start/Stop to the existing Dexray command (key m).

        The command owns ALL preconditions (frida-server up, spotlight app),
        session setup, task registration and dual-path cleanup — and dispatches
        the blocking Frida work to its own worker thread (``is_blocking_io``).
        So we just arm the in-tab config (consumed by MalwareMonitor at start,
        skipping the legacy interactive prompt) and trigger the command; do NOT
        wrap this in a second worker (double-dispatch).
        """
        if not self._is_running():
            # Arm the in-tab config + reset glance counters for the new session.
            self._svc().mark_configured()
            self._unpacked = self._errors = 0
        try:
            self.query_one("#dexray-log", RichLog).write(
                "[#7dd3fc][INFO] DEXray toggle requested…[/]"
            )
        except Exception:
            pass
        try:
            self.app.action_action_key("m")
        except Exception as exc:
            logger.warning("DEXray toggle failed: %s", exc)
        self.refresh_header()

    def action_clear_log(self) -> None:
        try:
            self.query_one("#dexray-log", RichLog).clear()
        except Exception:
            pass
        self._unpacked = self._errors = 0
        self.refresh_header()

    def action_open_output(self) -> None:
        """Ctrl+O — open the unpacked-DEX output folder in the OS file manager."""
        folder = self._output_folder()
        if folder is None or not folder.exists():
            try:
                self.app.notify(
                    "DEXray output folder not found yet — start DEXray first.",
                    severity="warning",
                )
            except Exception:
                pass
            return
        self._open_folder(folder)

    def dispatch_action_cell(self, wid: str) -> None:
        """Run the action bound to a clicked action cell (from MainScreen)."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _output_folder() -> Path | None:
        """Resolve the dexray results folder (prefers the unpacked/ subdir).

        Mirrors MalwareMonitor's path layout: ``$RESULTS_PATH/dexray_intercept``
        with unpacked DEX under ``unpacked/``. Never creates the folder.
        """
        results_path = os.getenv("RESULTS_PATH", "./results/")
        base = Path(results_path) / "dexray_intercept"
        unpacked = base / "unpacked"
        if unpacked.exists():
            return unpacked
        if base.exists():
            return base
        return None

    def _open_folder(self, target: Path) -> None:
        """Open ``target`` in the OS file manager (mirrors FriTapPanel)."""
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
            logger.warning("Failed to open DEXray output folder %s: %s", target, exc)
