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
import shlex
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from textual.widget import Widget
from textual.widgets import RichLog, Static

from sandroid.services import get_network_capture_service, get_task_service

if TYPE_CHECKING:
    from textual.app import ComposeResult

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
        ("r", "replay_capture", "Replay capture"),
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
        # The running FriTap instance, captured on TASK_STARTED so the
        # post-capture flow can read its result_paths after TASK_STOPPED (the
        # task is unregistered by then, but the Python object outlives it).
        self._results_instance = None

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
                "[#5b6479]Enter: start/stop · r: replay capture · "
                "Ctrl+O: open output · Ctrl+L: clear[/]"
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

            # Capture the friTap instance when its task starts, and run the
            # post-capture flow (Capture Results → Decrypt offer) when it stops.
            # stop() finalizes the capture synchronously inside the task's
            # stop_callback BEFORE TASK_STOPPED fires, so result_paths is ready.
            def _started_cb(event) -> None:
                if (getattr(event, "data", None) or {}).get("task_name") != "fritap":
                    return
                _schedule(self._capture_fritap_instance)

            def _stopped_cb(event) -> None:
                if (getattr(event, "data", None) or {}).get("task_name") != "fritap":
                    return
                _schedule(self._on_fritap_stopped)

            bus.subscribe(EventType.TASK_STARTED, _started_cb)
            self._event_handlers.append((EventType.TASK_STARTED, _started_cb))
            bus.subscribe(EventType.TASK_STOPPED, _stopped_cb)
            self._event_handlers.append((EventType.TASK_STOPPED, _stopped_cb))
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
        """Enter — start via the capture wizard, or stop the running session.

        On **start** (no friTap task running) this launches the Sandroid friTap
        capture wizard (capture mode → protocol → … → confirm). When the wizard
        confirms, it arms ``FriTapConfigService`` and triggers the existing
        FriTap command (key ``h``), which consumes the armed config and runs the
        blocking Frida work on its own worker thread (``is_blocking_io=True``).

        On **stop** (a friTap task is running) Enter delegates straight to the
        command, exactly as before. The command still owns ALL preconditions
        (frida-server up, spotlight app), task registration, the paused-spawn
        guard, and the dual-path cleanup — so we never double-dispatch here.
        """
        try:
            running = bool(get_task_service().is_running("fritap"))
        except Exception:
            running = False

        # --- Stop path (unchanged): delegate to the command. ---
        if running:
            # Capture the instance now (in case TASK_STARTED was missed, e.g. the
            # panel mounted after the session began) so the post-stop Capture
            # Results flow can read its result_paths.
            self._capture_fritap_instance()
            try:
                self.query_one("#fritap-log", RichLog).write(
                    "[#7dd3fc][INFO] friTap stop requested…[/]"
                )
            except Exception:
                pass
            try:
                self.app.action_action_key("h")
            except Exception as exc:
                logger.warning("FriTap toggle failed: %s", exc)
            self.refresh_header()
            return

        # --- Start path: require a target app, then run the wizard. ---
        from sandroid.services import get_spotlight_service

        if not get_spotlight_service().get_effective_package():
            try:
                self.app.notify(
                    "Select a target app in Spotlight before starting friTap.",
                    severity="warning",
                )
            except Exception:
                pass
            return

        try:
            self.query_one("#fritap-log", RichLog).write(
                "[#7dd3fc][INFO] friTap capture wizard…[/]"
            )
        except Exception:
            pass
        try:
            from sandroid.tui.widgets.fritap_capture_wizard import (
                FriTapCaptureWizard,
            )

            FriTapCaptureWizard(self.app).start()
        except Exception as exc:
            logger.warning("FriTap wizard launch failed: %s", exc)
            # Fallback to the command's own interactive configuration path.
            try:
                self.app.action_action_key("h")
            except Exception:
                pass
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

    def action_replay_capture(self) -> None:
        """Open a captured pcap with ``fritap -r`` in a NEW terminal (``r`` key).

        Replay (offline) friTap analysis runs in its own terminal, independent
        of the TUI — Sandroid only resolves the capture + the ``fritap``
        executable and launches the terminal. The capture defaults to the newest
        ``*.pcap`` under the device results folder; the user can override it.
        """
        from sandroid.tui.modals import InputModal

        default = self._latest_capture() or ""

        def on_result(value: str | None) -> None:
            if value is None:
                return
            path = value.strip()
            if not path:
                try:
                    self.app.notify("No capture path provided.", severity="warning")
                except Exception:
                    pass
                return
            self._launch_fritap_replay(Path(path).expanduser())

        self.app.push_screen(
            InputModal(
                title="Replay friTap capture",
                message="Open a .pcap with `fritap -r` in a new terminal window.",
                default=default,
                placeholder="/path/to/capture.pcap",
            ),
            on_result,
        )

    # -- post-capture flow (results → decrypt → replay) -------------------

    def _capture_fritap_instance(self) -> None:
        """Remember the running friTap instance (UI thread, on TASK_STARTED)."""
        try:
            task = get_task_service().get_task("fritap")
            self._results_instance = getattr(task, "instance", None)
        except Exception:
            self._results_instance = None

    def _on_fritap_stopped(self) -> None:
        """On TASK_STOPPED for friTap: show the Capture Results summary, then
        (for a full capture with keys) offer to decrypt into a ``.tap``.

        Runs on the UI thread. ``stop()`` finalized the capture synchronously
        before this fired, so ``result_paths`` is already populated.
        """
        inst = self._results_instance
        self._results_instance = None
        if inst is None:
            return
        result_paths = getattr(inst, "result_paths", None) or {}
        if not result_paths:
            return
        # This runs via loop.call_soon_threadsafe, which does NOT set Textual's
        # active_app ContextVar. Creating a modal here directly makes compose()
        # fail with NoActiveAppError (it builds unparented widgets in a `with`
        # block). call_later re-enters the app's message loop where the context
        # is set — non-blocking, unlike call_from_thread (which deadlocks against
        # friTap's Frida publisher threads).
        self.app.call_later(self._show_capture_results, inst, result_paths)

    def _show_capture_results(self, inst, result_paths: dict) -> None:
        """Push the "Capture Results" modal, then chain the decrypt offer."""
        from sandroid.tui.modals import MessageModal

        stats = getattr(inst, "result_stats", None) or {}
        app = getattr(inst, "app_package", None) or "target"
        lines = [f"Capture of [bold]{app}[/] completed.\n"]
        for label, path in result_paths.items():
            stat = stats.get(label)
            suffix = f" ({stat})" if stat else ""
            lines.append(f"  {label}: [bold]{path}[/]{suffix}")

        def _after_results(_result=None) -> None:
            self._maybe_offer_decrypt(inst)

        try:
            self.app.push_screen(
                MessageModal(
                    title="Capture Results",
                    message="\n".join(lines),
                    level="info",
                ),
                _after_results,
            )
        except Exception as exc:
            logger.warning("Failed to show Capture Results modal: %s", exc)

    def _maybe_offer_decrypt(self, inst) -> None:
        """Offer to decrypt a full capture's pcap+keys into a layered flow view.

        Only for full captures that produced both a pcap with packets and at
        least one keylog on disk — mirrors friTap's own decrypt offer.
        """
        if not getattr(inst, "full_capture_done", False):
            return
        keylogs = getattr(inst, "result_keylogs", None) or {}
        pcap = (getattr(inst, "result_paths", None) or {}).get("PCAP")
        has_packets = getattr(inst, "pcap_has_packets", False)
        if not (keylogs and pcap and has_packets):
            return

        from sandroid.tui.modals import ConfirmModal

        def _on_choice(ok: bool | None) -> None:
            if ok:
                self._start_decrypt_to_tap(pcap, keylogs)

        try:
            self.app.push_screen(
                ConfirmModal(
                    title="Decrypt captured traffic?",
                    message=(
                        "Decrypt the captured pcap with the captured keys into a "
                        "layered flow view?"
                    ),
                    yes_label="Decrypt",
                    no_label="Skip",
                ),
                _on_choice,
            )
        except Exception as exc:
            logger.warning("Failed to show decrypt offer modal: %s", exc)

    def _start_decrypt_to_tap(self, pcap: str, keylogs: dict) -> None:
        """Decrypt ``pcap`` + ``keylogs`` into a ``.tap`` on a worker thread,
        then open it with ``fritap -r`` in a new terminal.

        ``convert_pcap_to_tap`` shells out to tshark (slow + blocking), so it
        runs on a Textual thread-worker to keep the TUI responsive; UI work is
        marshalled back via ``app.call_from_thread`` (the documented pattern for
        thread-workers — distinct from the EventBus publisher threads this
        panel must NOT call_from_thread on).
        """
        tap_path = os.path.splitext(pcap)[0] + ".tap"
        tls_keylog = keylogs.get("tls")
        protocol_keylogs = {p: f for p, f in keylogs.items() if p != "tls"}

        try:
            self.app.notify(
                f"Decrypting capture into {os.path.basename(tap_path)} …"
            )
        except Exception:
            pass

        def _work() -> None:
            try:
                from friTap.offline.pcap_to_tap import convert_pcap_to_tap
            except Exception as exc:
                self._notify_from_thread(
                    f"friTap offline converter unavailable: {exc}", "error"
                )
                return
            try:
                result = convert_pcap_to_tap(
                    pcap,
                    tap_path=tap_path,
                    keylog_path=tls_keylog,
                    signal_keylog=protocol_keylogs.get("signal"),
                    mtproto_keylog=protocol_keylogs.get("mtproto"),
                    protocol_keylogs=protocol_keylogs or None,
                )
            except Exception as exc:
                # Most common cause: tshark not installed. Surface it plainly.
                self._notify_from_thread(f"Decrypt failed: {exc}", "error")
                return

            try:
                from sandroid.core.toolbox import Toolbox

                Toolbox.mark_tool_used("fritap", files=[tap_path])
            except Exception:
                pass

            flows = getattr(result, "flow_count", None)
            if flows is not None:
                msg = (
                    f"Decrypted {flows} flow{'s' if flows != 1 else ''} → "
                    f"{os.path.basename(tap_path)}"
                )
            else:
                msg = f"Decrypted → {os.path.basename(tap_path)}"
            self._notify_from_thread(msg, "information")
            # Open the replay TUI in a new terminal (existing infra).
            try:
                self.app.call_from_thread(
                    self._launch_fritap_replay, Path(tap_path)
                )
            except Exception as exc:
                logger.warning("Failed to launch replay after decrypt: %s", exc)

        try:
            self.run_worker(_work, thread=True, exclusive=False)
        except Exception as exc:
            logger.warning("Failed to start decrypt worker: %s", exc)
            try:
                self.app.notify(f"Could not start decrypt: {exc}", severity="error")
            except Exception:
                pass

    def _notify_from_thread(self, message: str, severity: str = "information") -> None:
        """Marshal an ``app.notify`` onto the UI thread from a worker thread."""
        try:
            self.app.call_from_thread(self.app.notify, message, severity=severity)
        except Exception:
            pass

    # -- helpers ----------------------------------------------------------

    def _latest_capture(self) -> str | None:
        """Newest ``*.pcap`` under the device results folder, or None.

        Searches the device root (covers both ``fritap/`` and
        ``network_trace_pull/``); the results tree is small so rglob is cheap.
        """
        folder = self._output_folder()
        if folder is None:
            return None
        root = folder.parent if (folder.parent and folder.parent.exists()) else folder
        candidates: list[Path] = []
        try:
            if root.exists():
                candidates = list(root.rglob("*.pcap"))
        except Exception:
            return None
        if not candidates:
            return None
        try:
            return str(max(candidates, key=lambda p: p.stat().st_mtime))
        except Exception:
            return None

    @staticmethod
    def _resolve_fritap() -> list[str]:
        """Resolve a runnable ``fritap`` command with an ABSOLUTE path.

        The spawned terminal uses the user's login shell, which may not have the
        venv on PATH — so resolve to the absolute executable rather than relying
        on a bare ``fritap`` lookup there.
        """
        exe = shutil.which("fritap")
        if exe:
            return [exe]
        candidate = Path(sys.executable).parent / "fritap"
        if candidate.exists():
            return [str(candidate)]
        return [sys.executable, "-m", "friTap"]

    def _launch_fritap_replay(self, capture: Path) -> None:
        if not capture.exists():
            try:
                self.app.notify(f"Capture not found: {capture}", severity="error")
            except Exception:
                pass
            return
        argv = self._resolve_fritap() + ["-r", str(capture)]
        try:
            self._open_terminal_with_command(argv)
            self.app.notify(
                f"Opening fritap -r in a new terminal: {capture.name}",
            )
        except Exception as exc:
            logger.warning("Failed to launch fritap replay: %s", exc)
            try:
                self.app.notify(f"Failed to open terminal: {exc}", severity="error")
            except Exception:
                pass

    def _open_terminal_with_command(self, argv: list[str]) -> None:
        """Open a new OS terminal window running ``argv`` (cross-platform).

        Mirrors :meth:`_open_folder`'s platform-dispatch shape. macOS uses
        ``osascript`` to drive Terminal.app; Linux tries the common emulators
        and keeps the window open after the command exits; Windows uses
        ``start cmd /k``.
        """
        cmd = " ".join(shlex.quote(a) for a in argv)
        if sys.platform == "darwin":
            # Escape for the AppleScript double-quoted string literal.
            ascript_cmd = cmd.replace("\\", "\\\\").replace('"', '\\"')
            script = (
                'tell application "Terminal"\n'
                f'    do script "{ascript_cmd}"\n'
                "    activate\n"
                "end tell"
            )
            subprocess.Popen(["osascript", "-e", script])
        elif sys.platform.startswith("win"):
            subprocess.Popen(["cmd", "/c", "start", "cmd", "/k", cmd])
        else:
            keep = f"{cmd}; exec bash"
            for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xterm"):
                path = shutil.which(term)
                if not path:
                    continue
                if term == "gnome-terminal":
                    subprocess.Popen([path, "--", "bash", "-c", keep])
                else:
                    subprocess.Popen([path, "-e", f"bash -c {shlex.quote(keep)}"])
                return
            # No terminal emulator found — run detached so it still executes.
            subprocess.Popen(argv)

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
