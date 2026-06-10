"""TUI panel giving on-screen feedback + control for the spotlight app.

The spotlight (``C`` attach / ``Shift+C`` spawn) was previously invisible —
no indication of which app, running state, PID, or which Frida hooks/bypasses
were active. This panel surfaces all of that, shows **live running state**, and
offers explicit lifecycle actions (Start / Restart / Kill / Attach, plus the
advanced Start-paused / Resume) together with immediate bypass toggles.

It is intentionally **stateless**: it owns no manager instances and reads
everything live from the process-wide services (BypassService, SpotlightService,
TaskService). Textual recreates widgets on screen change, so keeping state here
would orphan running Frida jobs — the services are the single source of truth.

Blocking lifecycle actions (spawn + wait-for-hooks + resume) run on worker
threads; UI updates are always marshalled back to the Textual main thread.
"""

from __future__ import annotations

import concurrent.futures
import functools
import logging
import threading
import time

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Static

logger = logging.getLogger(__name__)

# (binding key, category, label) for the four immediate bypass toggles.
_BYPASS_TOGGLES = [
    ("1", "ssl", "SSL"),
    ("2", "root", "Root"),
    ("3", "frida", "Frida"),
    ("4", "debug", "Debug"),
]

# Clickable action-cell id -> panel action method. Routed from
# MainScreen.on_click (same dispatch as the bottom tab bar / arrow).
_ACTION_CELLS = {
    "act-primary": "action_primary",
    "act-restart": "action_restart_app",
    "act-attach": "action_attach_app",
    "act-paused": "action_start_paused",
    "act-kill": "action_kill_app",
    "act-clear": "action_clear_spotlight",
}

# How often the slow fallback poll re-checks the app's PID (seconds).
_POLL_INTERVAL = 4.0


class SpotlightPanel(Widget):
    """Bottom-left panel: spotlight app status + live state + actions.

    Bindings (when focused):
        1/2/3/4: toggle/arm SSL / Root / Frida / Debug bypass
        Enter:   primary (Start if stopped · Resume if paused)
        R:       restart (force-stop + respawn with armed hooks)
        A:       attach to the live process + apply armed hooks
        P:       start paused (advanced; Enter then resumes)
        K:       kill the app + tear down all hooks
        X:       clear the spotlight selection

    Lowercase s/r/a/p/x are deliberately NOT bound — they shadow the
    destructive global shortcuts (Screenshot/Record/Analyze/Play/Export).
    The action row is also clickable.
    """

    DEFAULT_CSS = """
    SpotlightPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    SpotlightPanel > #spotlight-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    SpotlightPanel > #spotlight-body {
        height: 1fr;
        background: #050811;
        padding: 0 1;
    }
    SpotlightPanel > #spotlight-actions {
        height: 1;
        dock: bottom;
        background: #0b1628;
    }
    SpotlightPanel .act-cell {
        width: auto;
        padding: 0 1;
        color: #93a4c3;
    }
    SpotlightPanel .act-cell:hover {
        background: #1f2937;
        color: #7dd3fc;
        text-style: bold;
    }
    """

    BINDINGS = [
        ("1", "toggle_bypass('ssl')", "SSL"),
        ("2", "toggle_bypass('root')", "Root"),
        ("3", "toggle_bypass('frida')", "Frida"),
        ("4", "toggle_bypass('debug')", "Debug"),
        ("enter", "primary", "Start/Resume"),
        ("R", "restart_app", "Restart"),
        ("A", "attach_app", "Attach"),
        ("P", "start_paused", "Start paused"),
        ("K", "kill_app", "Kill"),
        ("X", "clear_spotlight", "Clear"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        # Slow fallback poll bookkeeping.
        self._poll_timer = None
        self._poll_inflight = False
        self._last_running_state: bool | None = None
        # Guard against overlapping blocking actions (spawn/kill/restart).
        self._action_inflight = False

    # -- services (lazy) --------------------------------------------------

    @staticmethod
    def _spotlight():
        from sandroid.services import get_spotlight_service

        return get_spotlight_service()

    @staticmethod
    def _bypass():
        from sandroid.analysis.detection_bypass import get_bypass_service

        return get_bypass_service()

    @staticmethod
    def _tasks():
        from sandroid.services import get_task_service

        return get_task_service()

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="spotlight-header")
        yield Static(self._render_body(), id="spotlight-body")
        with Horizontal(id="spotlight-actions"):
            yield Static(self._primary_label(), id="act-primary", classes="act-cell")
            yield Static("R restart", id="act-restart", classes="act-cell")
            yield Static("A attach", id="act-attach", classes="act-cell")
            yield Static("P pause", id="act-paused", classes="act-cell")
            yield Static("K kill", id="act-kill", classes="act-cell")
            yield Static("X clear", id="act-clear", classes="act-cell")

    def on_mount(self) -> None:
        self._subscribe_events()
        self.refresh_panel()
        # Event-driven transitions cover the common cases; this slow poll is
        # the safety net that catches the app dying on its own. Stopped in
        # on_unmount; each tick is a no-op when no app is selected or the
        # strip is collapsed.
        self._poll_timer = self.set_interval(_POLL_INTERVAL, self._poll_running_state)

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        if self._poll_timer is not None:
            try:
                self._poll_timer.stop()
            except Exception:
                pass
            self._poll_timer = None

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

            def _make_cb():
                def _cb(_event) -> None:
                    # Fire-and-forget onto the main loop; never blocks the
                    # publisher's thread (avoids the call_from_thread deadlock).
                    loop = self._main_loop
                    try:
                        if loop is not None and not loop.is_closed():
                            loop.call_soon_threadsafe(self.refresh_panel)
                    except RuntimeError:
                        pass

                return _cb

            for event_type in (
                EventType.STATE_CHANGED,
                EventType.TASK_STARTED,
                EventType.TASK_STOPPED,
            ):
                cb = _make_cb()
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"SpotlightPanel event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    # -- thread marshalling ----------------------------------------------

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread (fire-and-forget).

        Safe to call from worker threads. Used for refresh + notify so we
        never touch widgets off the main thread.
        """
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        loop = self._main_loop
        try:
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            pass

    # -- rendering --------------------------------------------------------

    def _current_package(self) -> str | None:
        try:
            return self._spotlight().get_effective_package()
        except Exception:
            return None

    def _safe_pid(self) -> int | None:
        try:
            return self._spotlight().get_pid()
        except Exception:
            return None

    def _is_paused(self) -> bool:
        try:
            return bool(self._spotlight().is_app_paused())
        except Exception:
            return False

    def _on_categories(self) -> list[str]:
        """Categories that are armed OR active (rendered ON)."""
        try:
            return self._bypass().on_categories()
        except Exception:
            return []

    def _hooks_for_app(self, package: str | None) -> list:
        if not package:
            return []
        try:
            tasks = self._tasks().get_running_tasks()
        except Exception:
            return []
        return [t for t in tasks if getattr(t, "app_name", None) == package]

    def _render_header(self) -> str:
        package = self._current_package()
        if not package:
            return "[#fb7185]○ no app[/] — press [b]C[/] (attach) / [b]Shift+C[/] (spawn)"

        pid = self._safe_pid()
        paused = self._is_paused()
        hooks = self._hooks_for_app(package)
        on = self._on_categories()

        if paused and pid:
            state = f"[#fbbf24]◐ paused[/] PID [b]{pid}[/]"
        elif pid:
            state = f"[#4ade80]● running[/] PID [b]{pid}[/]"
        else:
            state = "[#fb7185]○ not running[/]"

        bypass_tag = (
            f"[#4ade80]bypass: {','.join(on)}[/]" if on else "[#5b6479]bypass: none[/]"
        )
        return (
            f"{state}  [b]{package}[/]  hooks: [b]{len(hooks)}[/]  {bypass_tag}"
        )

    def _render_body(self) -> str:
        spotlight = self._spotlight()
        package = self._current_package()

        if not package:
            return (
                "[#5b6479]No spotlight app selected.\n\n"
                "Press [b]C[/] to attach to the focused app, or [b]Shift+C[/] to "
                "pick an app to spawn with hooks from the start.[/]"
            )

        lines: list[str] = []

        # 1. App info
        try:
            activity = spotlight.get_activity_name() or "—"
        except Exception:
            activity = "—"
        pid = self._safe_pid()

        lines.append("[#7dd3fc bold]App[/]")
        lines.append(f"  package   [b]{package}[/]")
        lines.append(f"  activity  {activity}")
        lines.append(f"  pid       {pid if pid else '[#5b6479]—[/]'}")
        lines.append("")

        # 2. Active hooks (filtered to this app)
        hooks = self._hooks_for_app(package)
        lines.append(f"[#7dd3fc bold]Active hooks[/] ([b]{len(hooks)}[/])")
        if hooks:
            for t in hooks:
                name = getattr(t, "display_name", getattr(t, "name", "task"))
                lines.append(f"  [#4ade80]●[/] {name}")
        else:
            lines.append("  [#5b6479]none[/]")
        lines.append("")

        # 3. Immediate bypass toggles (armed ∪ active)
        on = set(self._on_categories())
        lines.append(
            "[#7dd3fc bold]Bypass[/] "
            "[#5b6479](1-4 toggle · armed applies on Start)[/]"
        )
        toggle_cells = []
        for key, category, label in _BYPASS_TOGGLES:
            is_on = category in on
            color = "#4ade80" if is_on else "#5b6479"
            mark = "●" if is_on else "○"
            toggle_cells.append(f"[{color}][b]{key}[/] {mark} {label}[/]")
        lines.append("  " + "   ".join(toggle_cells))

        return "\n".join(lines)

    def _primary_label(self) -> str:
        """Context-sensitive label for the Enter / primary action cell."""
        if not self._current_package():
            return "⏎ Start"
        if self._is_paused():
            return "⏎ Resume"
        if self._safe_pid():
            return "[#5b6479]● running[/]"
        return "⏎ Start"

    def refresh_panel(self) -> None:
        try:
            self.query_one("#spotlight-header", Static).update(self._render_header())
            self.query_one("#spotlight-body", Static).update(self._render_body())
            self.query_one("#act-primary", Static).update(self._primary_label())
        except Exception:
            pass

    # -- live running-state poll (slow fallback) --------------------------

    def _strip_visible(self) -> bool:
        """True if the collapsible bottom strip is currently expanded."""
        try:
            return self.screen.query_one("#bottom-panel").has_class("-visible")
        except Exception:
            return False

    def _poll_running_state(self) -> None:
        """Timer tick (main thread): re-check the app's PID off-thread.

        No-op when nothing is selected, the strip is collapsed, or a
        lifecycle action is in flight (Start/Restart/Kill own the PID while
        they run — the poll must not clobber their set_pid with a stale
        sample taken during the force-stop window). A single in-flight guard
        also skips the tick if the previous worker is still running so a slow
        ADB call can never stack up.
        """
        if self._poll_inflight or self._action_inflight:
            return
        package = self._current_package()
        if not package:
            return
        if not self._strip_visible():
            return
        self._poll_inflight = True
        self.run_worker(
            functools.partial(self._poll_worker, package),
            name="spotlight_pid_poll",
            exclusive=False,
            thread=True,
        )

    def _poll_worker(self, package: str) -> None:
        """Worker-thread body of the poll. Writes PID; refreshes on change."""
        pid = None
        try:
            from sandroid.core.adb import Adb

            # Skip the heavyweight Frida fallback in this hot path, and stay
            # quiet about misses — "not running" is the expected state for a
            # spawn-selected app awaiting Start, so it must not spam warnings.
            pid = Adb.get_pid_for_package_name(
                package, use_frida_fallback=False, quiet=True
            )
        except Exception as exc:
            logger.debug(f"PID poll failed for {package}: {exc}")
        finally:
            self._poll_inflight = False

        # A lifecycle action that started while we were sampling owns the PID;
        # don't overwrite its set_pid with this (now stale) reading.
        if self._action_inflight:
            return

        try:
            self._spotlight().set_pid(pid)
        except Exception:
            pass

        running = pid is not None
        if running != self._last_running_state:
            self._last_running_state = running
            self._post(self.refresh_panel)

    # -- bypass toggles ---------------------------------------------------

    def action_toggle_bypass(self, category: str) -> None:
        """Toggle/arm a bypass category via the process-wide BypassService.

        Runs off the UI thread: toggling a category on against a running app
        loads/flips the combined Frida script, which can block on script
        readiness — synchronously here would freeze the whole TUI.

        ``toggle`` returns ``(now_on, msg)`` where the first element is *state*,
        not success, so the closure returns ``(True, msg)`` — otherwise
        ``_run_action_bg``'s severity-from-bool would redden a successful
        turn-OFF (``now_on=False``).
        """
        if not self._require_package():
            return

        def _work() -> tuple[bool, str]:
            _now_on, msg = self._bypass().toggle(category)
            return True, msg

        label = f"toggle {category}"
        # Only an ON toggle against a live (non-paused) process attaches Frida.
        # OFF, arm-only (app stopped, applied on Start), and paused-spawn
        # toggles keep the fast path; Start is already frida-gated by
        # _run_frida_action. turning_on mirrors toggle()'s armed-or-active check
        # (on_categories); needs_frida mirrors BypassService._spotlight_running.
        turning_on = category not in self._bypass().on_categories()
        needs_frida = turning_on and (
            self._safe_pid() is not None and not self._is_paused()
        )
        if needs_frida and not self._frida_server_running():
            # frida-server is down — prompt to install/start it via the shared
            # modal instead of letting the attach fail with the cryptic
            # frida-core "need Gadget to attach on jailed Android" error.
            self._prompt_install_frida(
                self._bypass().display_name(category),
                lambda: self._run_action_bg(_work, label),
            )
        else:
            self._run_action_bg(_work, label)

    # -- lifecycle actions (main-thread entry points) ---------------------

    def action_primary(self) -> None:
        """Enter: Start if stopped, Resume if paused, else inform."""
        if not self._require_package():
            return
        if self._is_paused():
            # Resuming a paused spawn — frida is already attached, no gate.
            self._run_action_bg(self._work_resume, "resume")
        elif self._safe_pid():
            self._notify(
                "Already running — R restart · A re-attach · K kill",
                "information",
            )
        else:
            self._run_frida_action(self._work_start, "start", "Spawning an app")

    def action_restart_app(self) -> None:
        if not self._require_package():
            return
        self._run_frida_action(self._work_restart, "restart", "Restarting an app")

    def action_kill_app(self) -> None:
        if not self._require_package():
            return
        # Kill only force-stops + tears down; it does not need frida-server.
        self._run_action_bg(self._work_kill, "kill")

    def action_attach_app(self) -> None:
        if not self._require_package():
            return
        # Attaching only needs frida-server when there are bypasses to load;
        # a bare attach (no armed bypasses) just tracks the running app.
        try:
            needs_frida = bool(self._bypass().armed_categories())
        except Exception:
            needs_frida = False
        if needs_frida:
            self._run_frida_action(
                self._work_attach, "attach", "Attaching with bypasses"
            )
        else:
            self._run_action_bg(self._work_attach, "attach")

    def action_start_paused(self) -> None:
        if not self._require_package():
            return
        self._run_frida_action(
            self._work_start_paused, "start-paused", "Spawning an app"
        )

    def action_stop_all(self) -> None:
        """Stop all bypasses + background tasks for the app (keep it running).

        Fixed: stops the BypassService even when there are zero TaskService
        tasks (the old early-return left bypass jobs running), and clears the
        armed set via BypassService.stop_all().
        """
        package = self._current_package()
        if not package:
            self._notify("No spotlight app.", "warning")
            return
        self._run_action_bg(
            lambda: (True, f"Stopped {self._stop_everything_for(package)} item(s)"),
            "stop-all",
        )

    def action_clear_spotlight(self) -> None:
        """Clear the spotlight selection (leaves any running app alone)."""
        try:
            self._spotlight().reset()
            self._last_running_state = None
            self._notify("Spotlight cleared", "information")
        except Exception as exc:
            logger.warning(f"Clear spotlight failed: {exc}")
        self.refresh_panel()

    def dispatch_action_cell(self, wid: str) -> None:
        """Run the action bound to a clicked action cell (from MainScreen)."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    # -- blocking work bodies (run on worker threads) ---------------------

    def _work_start(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        bypass = self._bypass()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        return bypass.apply_to_fresh_spawn(package, bypass.armed_categories())

    def _work_start_paused(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        bypass = self._bypass()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        return bypass.apply_to_fresh_spawn(
            package, bypass.armed_categories(), resume=False
        )

    def _work_resume(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        if not spotlight.is_app_paused():
            return False, "No paused app to resume"
        # Start-paused already loaded the FULL bypass set as one merged script
        # while paused (AFM bundle), so resume is just resume — every hook is
        # installed. No post-resume re-apply (which would also risk #218).
        ok = spotlight.resume_paused_app()
        if not ok:
            return False, "Resume failed"
        return True, "Resumed app"

    def _work_restart(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        bypass = self._bypass()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        from sandroid.core.adb import Adb

        # Capture armed intent BEFORE stop_all clears it.
        armed = bypass.armed_categories()
        # Teardown — force_stop FIRST. Unloading a Frida script on a LIVE
        # process can hang indefinitely (close_job → script.unload), so kill
        # the process before any unload/detach: every subsequent unload/detach
        # then fast-fails on the dead session. (The old order unloaded on the
        # live app first and could wedge the worker → "action in progress".)
        Adb.force_stop(package)
        time.sleep(0.5)  # let the process die so the session connection breaks
        bypass.stop_all()  # now fast: unloads fast-fail on the dead process
        self._reset_frida_session()  # clears jobs/session, is_first_job=True
        spotlight.set_pid(None)
        return bypass.apply_to_fresh_spawn(package, armed)

    def _work_kill(self) -> tuple[bool, str]:
        spotlight = self._spotlight()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        from sandroid.core.adb import Adb

        # force_stop FIRST (see _work_restart): unloading on a live process can
        # hang; killing first makes the teardown unloads/detach fast-fail.
        Adb.force_stop(package)
        time.sleep(0.5)
        self._stop_everything_for(package)
        self._reset_frida_session()
        spotlight.set_pid(None)
        self._last_running_state = False
        return True, f"Killed {package}"

    def _work_attach(self) -> tuple[bool, str]:
        from sandroid.core.adb import Adb
        from sandroid.core.enums import SpawnMode

        spotlight = self._spotlight()
        bypass = self._bypass()
        package = spotlight.get_effective_package()
        if not package:
            return False, "No spotlight app selected"
        pid = Adb.get_pid_for_package_name(package)
        if not pid:
            return False, f"{package} is not running — use Start to spawn it"
        spotlight.set_app(package_name=package, pid=pid, mode=SpawnMode.ATTACH)
        spotlight.set_spawn_mode(False)
        # Apply armed bypasses live against the running process (no resume).
        return bypass.apply_armed()

    # -- shared teardown helpers ------------------------------------------

    def _reset_frida_session(self) -> None:
        try:
            from sandroid.core.toolbox import Toolbox

            Toolbox.get_frida_job_manager().reset_session()
        except Exception as exc:
            logger.warning(f"reset_session failed: {exc}")

    def _stop_everything_for(self, package: str) -> int:
        """Stop bypasses (clears armed) + any background tasks for the app.

        Returns the number of items stopped. Does NOT early-return when there
        are no TaskService tasks — the bypasses are stopped regardless.
        """
        stopped = 0
        try:
            stopped += len(self._bypass().stop_all())
        except Exception as exc:
            logger.warning(f"Bypass stop_all failed: {exc}")
        try:
            svc = self._tasks()
            for t in self._hooks_for_app(package):
                try:
                    if svc.stop(getattr(t, "name", "")):
                        stopped += 1
                except Exception as exc:
                    logger.warning(f"Stop task failed: {exc}")
        except Exception:
            pass
        return stopped

    # -- helpers ----------------------------------------------------------

    def _require_package(self) -> bool:
        if not self._current_package():
            self._notify(
                "No spotlight app. Press C (attach) or Shift+C (spawn) first.",
                "warning",
            )
            return False
        return True

    #: Upper bound for any single spotlight action. The fixed teardown/spawn
    #: paths complete in 1–3s; this only ever trips on a genuine regression
    #: (e.g. a frida call wedging), and exists so _action_inflight can NEVER
    #: stay stuck and permanently disable the panel.
    _ACTION_TIMEOUT = 90.0

    def _run_action_bg(self, work, label: str) -> None:
        """Run a blocking spotlight action off the UI thread, then refresh.

        ``work`` returns ``(success, message)`` and must be safe to run on a
        worker thread (no widget access). A single in-flight guard prevents
        overlapping spawns/kills. ``work`` is run under a bounded watchdog so a
        hung frida call can never wedge ``_action_inflight`` (which would show
        "already in progress" forever); on timeout the flag is cleared and the
        orphaned worker is abandoned (``shutdown(wait=False)`` — never block on
        the hang we are escaping).
        """
        if self._action_inflight:
            self._notify("Spotlight action already in progress…", "warning")
            return
        self._action_inflight = True

        def _job() -> None:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(work)
                try:
                    ok, msg = future.result(timeout=self._ACTION_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    ok, msg = (
                        False,
                        f"{label} timed out after "
                        f"{int(self._ACTION_TIMEOUT)}s — see logs",
                    )
                    logger.error(
                        "Spotlight action %s exceeded %.0fs watchdog; abandoning",
                        label, self._ACTION_TIMEOUT,
                    )
                self._notify(msg, "information" if ok else "error")
            except Exception as exc:
                logger.warning(f"{label} failed: {exc}")
                self._notify(f"{label} failed: {exc}", "error")
            finally:
                # Never wedge: clear the guard no matter how work() ended, and
                # do not wait on a possibly-hung worker thread.
                executor.shutdown(wait=False)
                self._action_inflight = False
                self._post(self.refresh_panel)

        self.run_worker(
            _job, name=f"spotlight_{label}", exclusive=False, thread=True
        )

    # -- frida-server pre-flight ------------------------------------------

    def _run_frida_action(self, work, label: str, feature: str) -> None:
        """Run a spotlight action that needs frida-server on the device.

        If frida-server is running, behaves like ``_run_action_bg``. If it is
        NOT running, prompt the user to install & start it (via the shared
        ``FridaInstallModal``) and only then run the action — instead of
        letting the spawn fail with the cryptic frida fallback error
        ("need Gadget to attach on jailed Android").
        """
        if self._frida_server_running():
            self._run_action_bg(work, label)
        else:
            self._prompt_install_frida(
                feature, lambda: self._run_action_bg(work, label)
            )

    @staticmethod
    def _frida_server_running() -> bool:
        """True if frida-server is up on the active device (best-effort)."""
        try:
            from sandroid.services import get_frida_session_service

            fm = get_frida_session_service().get_frida_manager()
            return bool(fm and fm.is_frida_server_running())
        except Exception:
            return False

    def _prompt_install_frida(self, feature: str, then) -> None:
        """Show the FridaInstallModal; on confirm install+start, then run ``then``."""
        from sandroid.tui.modals import FridaInstallModal, FridaInstallResult

        device_name = "device"
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            if dm and dm.active_device:
                device_name = dm.active_device.display_name
        except Exception:
            pass

        def on_result(result: FridaInstallResult | None) -> None:
            if not result or not result.install:
                # Derived from ``feature`` so the wording fits every caller
                # (spawn/restart/attach AND the bypass toggle) instead of always
                # saying "spawn". Mirrors the modal's own "{feature} requires…".
                self._notify(
                    f"{feature} requires frida-server — cancelled.", "warning"
                )
                return
            self._install_frida_then(then)

        self.app.push_screen(
            FridaInstallModal(device_name=device_name, feature_name=feature),
            on_result,
        )

    def _install_frida_then(self, then) -> None:
        """Install + start frida-server on a worker, then run ``then`` on success."""
        if self._action_inflight:
            self._notify("Spotlight action already in progress…", "warning")
            return
        self._action_inflight = True
        self._notify("Installing & starting frida-server…", "information")

        def _job() -> None:
            ok = False
            try:
                from sandroid.services import get_frida_session_service

                svc = get_frida_session_service()
                fm = svc.get_frida_manager()
                if fm is None:
                    raise RuntimeError("Frida manager unavailable")
                fm.install_frida_server()
                # run_frida_server now blocks until the frida CLIENT can reach
                # the server, so its result reflects real readiness (not just
                # that the process exists) — the next spawn won't race it.
                ok = bool(fm.run_frida_server())
                if ok:
                    # Drop any frida device handle cached while the server was
                    # down so the next spawn resolves a fresh, ready device.
                    try:
                        svc.invalidate_frida_device_cache()
                    except Exception:
                        pass
            except Exception as exc:
                logger.warning(f"Frida install/start failed: {exc}")
                self._notify(f"Frida install failed: {exc}", "error")
            finally:
                self._action_inflight = False
                self._post(self.refresh_panel)
                self._post(self._refresh_status_bar)
            if ok:
                self._notify("frida-server started.", "information")
                self._post(then)
            else:
                self._notify(
                    "frida-server still not running — cannot spawn.", "error"
                )

        self.run_worker(
            _job, name="spotlight_frida_install", exclusive=False, thread=True
        )

    def _refresh_status_bar(self) -> None:
        """Nudge the status bar to re-check frida status (main thread only)."""
        try:
            self.app.query_one("#status-bar").update_from_toolbox()
        except Exception:
            pass

    def _notify(self, message: str, severity: str = "information") -> None:
        """Notify the user. Safe to call from worker threads."""
        self._post(self._do_notify, message, severity)

    def _do_notify(self, message: str, severity: str) -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass
