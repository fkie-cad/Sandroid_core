"""One rule for how a Frida tool gets the spotlight app's process.

The spotlight is a plain app *selection* (package, plus PID/activity when
known). It has no spawn/attach mode. Every caller that needs a Frida session
on the selected app (friTap ``h``, Dexray ``m``, the bypass toggles, fridump,
TrigDroid, the AI) asks :func:`resolve_start` / :func:`negotiate_start`, and
the lifecycle keys (Space, ⇧P, ⇧R, ⇧A) and the AI go through
:func:`start_app` / :func:`restart_app` / :func:`resume_app` /
:func:`attach_app`.

The rule (:func:`decide_start`, pure, rows evaluated top to bottom):

====  =========================================  ==================================
row   condition                                  action
====  =========================================  ==================================
R0    another start/restart is in flight         REFUSE (busy)
R0b   adb could not tell whether it runs         REFUSE (unknown)
R1    JobManager holds a *paused* session of     JOIN (paused); REFUSE when a Java
      the app (also a still-unnamed spawn)       agent would join live jobs (#218)
                                                 or the tool that spawned it still
                                                 loads its hooks
R2    the app is not running                     SPAWN (owned) or REFUSE when
                                                 spawning is not allowed / Frida is
                                                 busy with another target
R3    running, ``fresh`` and no consent          NEEDS_CONFIRM
R4    running, ``fresh`` and consent             RESPAWN (owned)
R5    JobManager holds a live session on it      JOIN (running)
R6    otherwise                                  ATTACH; REFUSE while Frida runs
                                                 live jobs on another (or an
                                                 unnamable) target; only an idle
                                                 or dead session is reset
====  =========================================  ==================================

A running app is never killed without consent: only RESPAWN kills, and
RESPAWN needs ``consent`` (the caller's own, e.g. ⇧R or an API ``fresh=True``)
or the user's answer to the confirmation dialog :func:`negotiate_start` shows.
Resume follows ownership: only the caller that spawned a process
(``owns_spawn``) resumes it; a joined paused process waits for Space.

Pre-spawn hooks (:func:`register_pre_spawn_hook`, e.g. the identity profile)
run before every start of an app by Sandroid, inside the lifecycle lock:
Space/⇧P (:func:`start_app`), ⇧R and the AI restart (:func:`restart_app`),
a tool's SPAWN/RESPAWN (:func:`open_session`), and via
:func:`prepare_launch` TrigDroid's spawn and the AI ``launch_app``. A hook's
plan that restarts the Android framework (every running app stops) needs the
user's OK (a dialog; headless: the caller's ``consent``). A plan that fails
aborts the start. They never run on JOIN, ATTACH or resume (the process
already runs). Not covered: launches outside Sandroid (the launcher, an
intent from another app).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

#: Job states that no longer hold a script in the process.
_DEAD_JOB_STATES = ("stopped", "error")
#: TaskService tasks that are not Frida tools on the app.
_NOT_A_TOOL = ("monitor",)


class Liveness(str, Enum):
    """What adb says about the app's process."""

    RUNNING = "running"
    NOT_RUNNING = "not_running"
    UNKNOWN = "unknown"


class StartAction(str, Enum):
    """What a tool does to get a session on the spotlight app."""

    JOIN = "join"  # reuse the JobManager's live session (running or paused)
    ATTACH = "attach"  # the JobManager attaches to the running PID
    SPAWN = "spawn"  # app not running: spawn paused (kills nothing)
    RESPAWN = "respawn"  # running + fresh + consent: force-stop, spawn paused
    NEEDS_CONFIRM = "needs_confirm"
    REFUSE = "refuse"


class AppStartError(RuntimeError):
    """The app cannot be started/attached as asked (user-actionable)."""

    expected = True


@dataclass(frozen=True)
class StartInputs:
    """Everything :func:`decide_start` looks at (gathered by resolve_start).

    Attributes:
        package: The spotlight package.
        liveness: What adb says about the app.
        live_pid: The app's PID when it runs.
        session_pid: PID of the JobManager's *live* session, else None.
        session_package: Package the JobManager spawned, else None.
        session_paused: The JobManager holds its process paused.
        live_jobs: Names of JobManager jobs not stopped/errored.
        has_session: The JobManager holds any session state (live or dead).
        session_alive: The JobManager's session is attached (its PID may
            still be unreadable).
        setup_owner: A tool that spawned the app and is still loading its
            hooks (nobody else may join or resume it meanwhile).
        app_tools: Tools running on the app (stopped by a RESPAWN).
        busy: Why a start is in flight right now, else None.
        fresh: The tool needs a process that has not run yet.
        consent: The caller already has the OK to kill a running app.
        allow_spawn: The caller may start a stopped app.
        java_agent: The caller loads its own Java-bridge script (#218).
        tool: User-facing tool name for messages.
    """

    package: str
    liveness: Liveness
    live_pid: int | None = None
    session_pid: int | None = None
    session_package: str | None = None
    session_paused: bool = False
    live_jobs: tuple[str, ...] = ()
    has_session: bool = False
    session_alive: bool = False
    setup_owner: str | None = None
    app_tools: tuple[str, ...] = ()
    busy: str | None = None
    fresh: bool = False
    consent: bool = False
    allow_spawn: bool = True
    java_agent: bool = True
    tool: str = "this tool"


@dataclass(frozen=True)
class StartDecision:
    """The outcome of :func:`decide_start`.

    Attributes:
        action: What to do.
        package: The spotlight package.
        pid: Target PID (JOIN/ATTACH/NEEDS_CONFIRM); None for spawns.
        paused: JOIN onto a held (paused) spawn.
        owns_spawn: SPAWN/RESPAWN: the caller resumes, nobody else.
        reset_session: Drop the JobManager's dead/idle session first.
        reason: Why (REFUSE / NEEDS_CONFIRM).
        code: Short machine-readable refusal kind.
        stops: Tools a RESPAWN stops (shown in the dialog).
        tool: The tool that asked.
        consent: The caller's own consent (headless ``fresh=True``); without
            a dialog it also covers a pre-spawn step that stops every app.
    """

    action: StartAction
    package: str
    pid: int | None = None
    paused: bool = False
    owns_spawn: bool = False
    reset_session: bool = False
    reason: str = ""
    code: str = ""
    stops: tuple[str, ...] = ()
    tool: str = "this tool"
    consent: bool = False


def stops_sentence(tools: tuple[str, ...] | list[str]) -> str:
    """`` This stops: A, B.`` for a restart dialog ("" without tools)."""
    return f" This stops: {', '.join(tools)}." if tools else ""


def _refuse(i: StartInputs, code: str, reason: str) -> StartDecision:
    return StartDecision(
        StartAction.REFUSE, i.package, reason=reason, code=code, tool=i.tool
    )


def decide_start(i: StartInputs) -> StartDecision:
    """Pick the start action for ``i`` (pure, no I/O). See the module doc."""
    pkg = i.package
    if i.busy:
        return _refuse(i, "busy", f"{i.busy}; {i.tool} not started.")
    if i.liveness == Liveness.UNKNOWN:
        return _refuse(
            i,
            "unknown",
            f"Could not tell whether {pkg} is running (adb error); "
            f"{i.tool} not started and nothing was restarted.",
        )
    running = i.liveness == Liveness.RUNNING and i.live_pid is not None
    # The JobManager's session is on this app: same PID, or a spawn of the
    # package that pidof cannot name yet / that is still held paused.
    ours = i.session_pid is not None and (
        (running and i.session_pid == i.live_pid)
        or (i.session_package == pkg and (not running or i.session_paused))
    )
    # R1: a held spawn has not run yet, so it already counts as fresh.
    if ours and i.session_paused:
        if i.setup_owner:
            return _refuse(
                i,
                "setup",
                f"{i.setup_owner} is still loading its hooks; {i.tool} not started.",
            )
        if i.java_agent and i.live_jobs:
            return _refuse(
                i,
                "paused_hooks",
                f"{pkg} is paused with hooks loaded; a second Frida script on "
                f"a paused app crashes it (frida #218). Press ␣ to resume, "
                f"then start {i.tool}.",
            )
        return StartDecision(
            StartAction.JOIN,
            pkg,
            pid=i.session_pid,
            paused=True,
            tool=i.tool,
        )
    if i.session_alive and i.session_pid is None and i.live_jobs:
        # An attached session whose PID cannot be read: never reset it.
        return _refuse(
            i,
            "frida_busy",
            f"Frida runs {', '.join(i.live_jobs)} on a process it cannot "
            f"name; stop those first. {i.tool} not started.",
        )
    busy_elsewhere = i.session_pid is not None and not ours and bool(i.live_jobs)
    if busy_elsewhere:
        jobs = ", ".join(i.live_jobs)
        return _refuse(
            i,
            "frida_busy",
            f"Frida is busy with another process (pid {i.session_pid}: {jobs}); "
            f"stop those first. {i.tool} not started.",
        )
    # R2: not running.
    if not running and not ours:
        if not i.allow_spawn:
            return _refuse(
                i, "not_running", f"{pkg} is not running — press ␣ to start it."
            )
        return StartDecision(
            StartAction.SPAWN,
            pkg,
            owns_spawn=True,
            reset_session=i.has_session and not i.live_jobs,
            tool=i.tool,
            consent=i.consent,
        )
    target = i.live_pid if running else i.session_pid
    # R3/R4: the tool needs a process that has not run yet.
    if i.fresh:
        if not i.consent:
            stops = stops_sentence(i.app_tools)
            return StartDecision(
                StartAction.NEEDS_CONFIRM,
                pkg,
                pid=target,
                reason=(
                    f"{i.tool} needs a fresh start: {pkg} (pid {target}) is "
                    f"running and would be force-stopped and started again "
                    f"with the armed bypasses.{stops}"
                ),
                code="needs_confirm",
                stops=i.app_tools,
                tool=i.tool,
            )
        return StartDecision(
            StartAction.RESPAWN,
            pkg,
            owns_spawn=True,
            stops=i.app_tools,
            tool=i.tool,
            consent=i.consent,
        )
    # R5: our live session.
    if ours:
        return StartDecision(StartAction.JOIN, pkg, pid=i.session_pid, tool=i.tool)
    # R6: attach (a dead or idle session is dropped first).
    return StartDecision(
        StartAction.ATTACH,
        pkg,
        pid=target,
        reset_session=i.has_session and not i.live_jobs,
        tool=i.tool,
    )


# ---------------------------------------------------------------------------
# Lifecycle lock: one start/restart at a time (panel keys, AI, tool spawns)
# ---------------------------------------------------------------------------


class _LifecycleLock:
    """A non-blocking, re-entrant-per-thread lock for app starts."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner: int | None = None
        self._depth = 0

    def try_acquire(self) -> bool:
        me = threading.get_ident()
        if self._owner == me:
            self._depth += 1
            return True
        if not self._lock.acquire(blocking=False):
            return False
        self._owner, self._depth = me, 1
        return True

    def release(self) -> None:
        if self._owner != threading.get_ident():
            return
        self._depth -= 1
        if self._depth <= 0:
            self._owner, self._depth = None, 0
            self._lock.release()

    def held_by_caller(self) -> bool:
        """Held by this thread (a lifecycle action resolving for itself)."""
        return self._owner == threading.get_ident()

    def busy_for_caller(self) -> bool:
        """Held by another thread."""
        return self._lock.locked() and self._owner != threading.get_ident()

    def locked(self) -> bool:
        return self._lock.locked()


_LIFECYCLE = _LifecycleLock()
_BUSY_MSG = "Another start/restart of the app is in progress"


#: Poll interval of :func:`lifecycle_lock` while it waits.
_LOCK_POLL_S = 0.05


@contextmanager
def lifecycle_lock(timeout: float = 0.0) -> Iterator[None]:
    """Hold the app lifecycle lock outside a spawn.

    For steps that must not overlap an app start, e.g. the CA injection or
    the identity profile's framework restart. Re-entrant on the same thread
    (a start inside it works).

    Never call it on the UI thread with ``timeout > 0``: waiting would block
    the event loop, so it logs and refuses there.

    Args:
        timeout: Seconds to wait for a start in flight (0: do not wait).

    Raises:
        AppStartError: Another start holds the lock after ``timeout``, or a
            wait was asked for on the UI thread.
    """
    if timeout > 0 and threading.current_thread() is threading.main_thread():
        logger.error("lifecycle_lock(timeout=%s) on the UI thread; refused", timeout)
        raise AppStartError(f"{_BUSY_MSG} (cannot wait for it on the UI thread)")
    deadline = time.monotonic() + max(0.0, timeout)
    while not _LIFECYCLE.try_acquire():
        if time.monotonic() >= deadline:
            raise AppStartError(_BUSY_MSG)
        time.sleep(_LOCK_POLL_S)
    try:
        yield
    finally:
        _LIFECYCLE.release()


#: Hold the lifecycle lock or raise :class:`AppStartError` when busy.
_lifecycle = lifecycle_lock


# ---------------------------------------------------------------------------
# Setup owner: a tool between its own spawn and its resume
# ---------------------------------------------------------------------------

_SETUP_LOCK = threading.Lock()
#: ``(tool, package, pid)`` of a tool that spawned the app and is still
#: loading its hooks, else None. ``pid`` is None while the spawn is under
#: way. Set by :func:`open_session`, cleared by its owner only
#: (:func:`finish_owned_spawn` / :func:`abort_owned_spawn` /
#: :func:`end_setup`).
_SETUP: tuple[str, str, int | None] | None = None


def _begin_setup(tool: str, package: str, pid: int | None = None) -> None:
    global _SETUP
    with _SETUP_LOCK:
        _SETUP = (tool, package, pid)


def _setup_spawned(tool: str, pid: int) -> None:
    """The owner's spawn has its PID now (placeholder -> real marker)."""
    global _SETUP
    with _SETUP_LOCK:
        if _SETUP is not None and _SETUP[0] == tool and _SETUP[2] is None:
            _SETUP = (tool, _SETUP[1], pid)


def end_setup(tool: str, pid: int | None = None) -> None:
    """The owner resumed (or gave up) its spawn. Idempotent.

    Clears only the marker of ``tool`` (and of ``pid`` when given): a later
    owner's marker -- a ⇧R or another tool spawned meanwhile -- stays.
    """
    global _SETUP
    with _SETUP_LOCK:
        marker = _SETUP
        if marker is None or marker[0] != tool:
            return
        if pid is not None and marker[2] is not None and marker[2] != pid:
            return
        _SETUP = None


def _reset_setup() -> None:
    """Forget any marker (tests)."""
    global _SETUP
    with _SETUP_LOCK:
        _SETUP = None


def _drop_if_current(marker: tuple[str, str, int | None]) -> None:
    global _SETUP
    with _SETUP_LOCK:
        if _SETUP is marker:
            _SETUP = None


def setup_owner(jm: Any = None) -> str | None:
    """The tool still loading its hooks into its own paused spawn, or None.

    A marker whose process is gone (the JobManager's live session is another
    PID or none) is stale and dropped -- only that very marker (compare and
    swap). A placeholder (spawn under way, no PID yet) is never stale.
    """
    with _SETUP_LOCK:
        marker = _SETUP
    if marker is None:
        return None
    tool, _package, pid = marker
    if pid is None:
        return tool
    if jm is None:
        jm = _job_manager()
    spid = session_pid(jm)
    if spid is not None and spid != pid:
        _drop_if_current(marker)
        return None
    if spid is None and jm is not None:
        try:
            alive = bool(jm.has_active_session())
        except Exception:
            alive = True
        if not alive:
            _drop_if_current(marker)
            return None
    return tool


# ---------------------------------------------------------------------------
# Gathering the inputs (I/O; never on the UI thread)
# ---------------------------------------------------------------------------


def _parse_pid(output: str) -> int | None:
    try:
        return int(output.strip().split()[0])
    except (ValueError, IndexError):
        return None


def probe_liveness(
    package: str, *, frida_fallback: bool = False
) -> tuple[Liveness, int | None]:
    """Ask the device whether ``package`` runs, telling "no" from "no idea".

    ``Adb.get_pid_for_package_name`` returns None both when the app is not
    running and when adb failed; a spawn decided on an adb error would kill a
    running app. Here an adb error (no ``pidof`` answer and an actionable
    stderr from both ``pidof`` and ``ps -A``) is :attr:`Liveness.UNKNOWN`.

    Args:
        package: The package to look up.
        frida_fallback: Also ask frida-server when adb finds nothing.

    Returns:
        ``(liveness, pid)``.
    """
    from sandroid.core.adb import Adb
    from sandroid.core.adb_utils import device_shell_arg, is_adb_error_actionable

    try:
        out, err = Adb.send_adb_command(f"shell pidof {device_shell_arg(package)}")
    except Exception as exc:
        logger.debug("pidof %s failed: %s", package, exc)
        out, err = "", str(exc) or "adb error"
    pid = _parse_pid(out or "")
    if pid:
        return Liveness.RUNNING, pid
    if err and is_adb_error_actionable(err):
        # pidof may be missing on old devices: ps -A must answer then.
        try:
            ps_out, ps_err = Adb.send_adb_command("shell ps -A")
        except Exception as exc:
            ps_out, ps_err = "", str(exc) or "adb error"
        if not (ps_out or "").strip():
            logger.warning("Liveness of %s unknown: %s", package, err.strip())
            return Liveness.UNKNOWN, None
        for line in ps_out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == package:
                found = _parse_pid(parts[1])
                if found:
                    return Liveness.RUNNING, found
    if frida_fallback:
        try:
            from sandroid.core.adb_process import _try_frida

            found = _try_frida(package)
        except Exception:
            found = None
        if found:
            return Liveness.RUNNING, found
    return Liveness.NOT_RUNNING, None


def _job_manager() -> Any | None:
    try:
        from sandroid.core.toolbox import Toolbox

        return Toolbox.get_frida_job_manager()
    except Exception as exc:
        logger.debug("No JobManager: %s", exc)
        return None


def session_pid(jm: Any) -> int | None:
    """PID of the JobManager's *live* session, or None.

    AFM sets ``jm.pid`` only for spawns; for an attach the PID is only on the
    frida session (``process_session._impl.pid``).
    """
    if jm is None:
        return None
    try:
        if not jm.has_active_session():
            return None
    except Exception:
        return None
    session = getattr(jm, "process_session", None)
    for holder in (getattr(session, "_impl", None), session):
        pid = getattr(holder, "pid", None)
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            return pid
    pid = getattr(jm, "pid", None)
    if isinstance(pid, int) and pid > 0:
        return pid
    target = getattr(jm, "package_name", None)
    if isinstance(target, int) and target > 0:
        return target
    return None


def live_job_names(jm: Any) -> tuple[str, ...]:
    """Display names of JobManager jobs that still hold a script.

    "initialized" counts: such a job is loading its script right now
    (``running_jobs()`` only counts "running").
    """
    jobs = getattr(jm, "jobs", None) if jm is not None else None
    if not isinstance(jobs, dict):
        return ()
    names = []
    for job in list(jobs.values()):
        if getattr(job, "state", None) in _DEAD_JOB_STATES:
            continue
        names.append(
            str(
                getattr(job, "display_name", None)
                or getattr(job, "job_type", None)
                or "Frida job"
            )
        )
    return tuple(names)


def _has_session_state(jm: Any) -> bool:
    if jm is None:
        return False
    if getattr(jm, "process_session", None) is not None:
        return True
    if isinstance(getattr(jm, "jobs", None), dict) and jm.jobs:
        return True
    pid = getattr(jm, "pid", -1)
    return isinstance(pid, int) and pid > 0


def _session_package(jm: Any) -> str | None:
    target = getattr(jm, "package_name", None) if jm is not None else None
    if isinstance(target, str) and target and not target.isdigit():
        return target
    return None


def app_tools(package: str) -> tuple[str, ...]:
    """Display names of the tools running on ``package`` (TaskService)."""
    return tuple(name for _key, name in _app_tasks(package))


def _app_tasks(package: str) -> list[tuple[str, str]]:
    try:
        from sandroid.services import get_task_service

        tasks = get_task_service().get_running_tasks()
    except Exception:
        return []
    out = []
    for task in tasks:
        name = getattr(task, "name", "")
        if getattr(task, "app_name", None) != package or name in _NOT_A_TOOL:
            continue
        out.append((name, str(getattr(task, "display_name", None) or name)))
    return out


def _busy_reason(spotlight: Any, package: str) -> str | None:
    if _LIFECYCLE.held_by_caller():
        return None  # the start/restart in flight is this thread's own
    try:
        if spotlight.is_restarting(package):
            return f"⇧R restart of {package} in progress"
    except Exception:
        pass
    if _LIFECYCLE.busy_for_caller():
        return _BUSY_MSG
    return None


def gather_inputs(
    package: str,
    *,
    tool: str = "this tool",
    fresh: bool = False,
    consent: bool = False,
    allow_spawn: bool = True,
    java_agent: bool = True,
    frida_fallback: bool = False,
) -> StartInputs:
    """Read adb, the JobManager and the TaskService into a StartInputs."""
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    liveness, live_pid = probe_liveness(package, frida_fallback=frida_fallback)
    jm = _job_manager()
    spid = session_pid(jm)
    # Correct a stale cached PID -- but a held spawn pidof cannot name yet
    # keeps the PID its spawn announced.
    try:
        cached = spotlight.get_pid()
        stale = liveness == Liveness.RUNNING and cached != live_pid
        gone = liveness == Liveness.NOT_RUNNING and cached and cached != spid
        if stale or gone:
            spotlight.announce_pid(live_pid, package)
    except Exception as exc:
        logger.debug("Could not update the spotlight PID: %s", exc)
    try:
        alive = bool(jm.has_active_session()) if jm is not None else False
    except Exception:
        alive = False
    try:
        paused = bool(jm.is_paused()) if jm is not None and spid else False
    except Exception:
        paused = False
    return StartInputs(
        package=package,
        liveness=liveness,
        live_pid=live_pid,
        session_pid=spid,
        session_package=_session_package(jm),
        session_paused=paused,
        live_jobs=live_job_names(jm) if alive else (),
        has_session=_has_session_state(jm),
        session_alive=alive,
        setup_owner=setup_owner(jm) if spid else None,
        app_tools=app_tools(package),
        busy=_busy_reason(spotlight, package),
        fresh=fresh,
        consent=consent,
        allow_spawn=allow_spawn,
        java_agent=java_agent,
        tool=tool,
    )


def _no_app(tool: str) -> StartDecision:
    return StartDecision(
        StartAction.REFUSE,
        "",
        reason=(
            "No spotlight app. Press c (use the foreground app) or ⇧C "
            "(pick an app…) first."
        ),
        code="no_app",
        tool=tool,
    )


def resolve_start(
    package: str | None = None,
    *,
    tool: str = "this tool",
    fresh: bool = False,
    consent: bool = False,
    allow_spawn: bool = True,
    java_agent: bool = True,
) -> StartDecision:
    """Decide how ``tool`` gets the spotlight app (blocking adb; worker only).

    Args:
        package: The app; defaults to the spotlight package.
        tool: User-facing tool name for messages.
        fresh: The tool needs a process that has not run yet.
        consent: The caller already has the OK to kill a running app.
        allow_spawn: The caller may start a stopped app.
        java_agent: The caller loads its own Java-bridge script.

    Returns:
        The decision (see :func:`decide_start`).
    """
    if package is None:
        from sandroid.services import get_spotlight_service

        package = get_spotlight_service().get_effective_package()
    if not package:
        return _no_app(tool)
    return decide_start(
        gather_inputs(
            package,
            tool=tool,
            fresh=fresh,
            consent=consent,
            allow_spawn=allow_spawn,
            java_agent=java_agent,
        )
    )


def confirm_restart_dialog(decision: StartDecision) -> bool | None:
    """Show the restart confirmation for ``decision`` via the UI request bus.

    Blocks the calling worker thread until the user answers. Returns None
    when no dialog can be shown (no UI, or called on the UI thread, where
    the bus would deadlock the event loop).
    """
    if threading.current_thread() is threading.main_thread():
        logger.error(
            "Restart confirmation requested on the UI thread (%s); refused",
            decision.tool,
        )
        return None
    from sandroid.core.ui_request_bus import UIRequestBus, request_modal

    if not UIRequestBus.get().has_active_handler():
        return None
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    answer = request_modal(
        ConfirmModal,
        title=f"Restart {decision.package}?",
        message=decision.reason,
        yes_label="Restart",
        no_label="Keep running",
        guard_typing=True,
    )
    return answer is True


def negotiate_start(tool: str, **kwargs: Any) -> StartDecision:
    """:func:`resolve_start`, asking the user before any restart.

    A NEEDS_CONFIRM decision shows "Restart {pkg}?" (from a worker thread,
    via the UI request bus). Only Restart turns it into RESPAWN; Keep
    running, Esc, a timeout and "no UI" all refuse.

    Args:
        tool: User-facing tool name.
        **kwargs: Passed to :func:`resolve_start`.

    Returns:
        A decision that is never NEEDS_CONFIRM.
    """
    decision = resolve_start(tool=tool, **kwargs)
    if decision.action != StartAction.NEEDS_CONFIRM:
        return decision
    if threading.current_thread() is threading.main_thread():
        logger.error("negotiate_start(%s) on the UI thread; refused", tool)
        return replace(
            decision,
            action=StartAction.REFUSE,
            code="ui_thread",
            reason=f"{tool} not started — cannot ask about a restart from here.",
        )
    answer = confirm_restart_dialog(decision)
    if answer is None:
        from sandroid.core.ui_request_bus import UIRequestBus

        if not UIRequestBus.get().has_active_handler():
            return replace(
                decision,
                action=StartAction.REFUSE,
                code="no_ui",
                reason=(
                    f"{tool} needs a fresh start of the running "
                    f"{decision.package} and there is no dialog to confirm "
                    "it; pass fresh=True (the caller consents) to restart it."
                ),
            )
    if answer:
        return replace(decision, action=StartAction.RESPAWN, owns_spawn=True, code="")
    return replace(
        decision,
        action=StartAction.REFUSE,
        code="declined",
        reason=f"{tool} not started — {decision.package} keeps running.",
    )


# ---------------------------------------------------------------------------
# Pre-spawn hooks: steps that must run before the app's process starts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreSpawnPlan:
    """What a pre-spawn hook needs done before the app starts.

    Attributes:
        description: What ``apply`` does, a verb phrase for messages
            ("apply identity profile 'x' (ssaid, locale)").
        disruptive: ``apply`` restarts the Android framework: every running
            app on the device stops (needs the user's OK).
        apply: Does it, blocking, on a worker thread. Raising aborts the
            start. It returns once the framework is back (or never went
            down).
    """

    description: str
    disruptive: bool
    apply: Callable[[], None]


#: Gets the package about to start; returns a plan, or None (nothing to do).
#: Decide quickly, no device writes: start paths call it inside the lifecycle
#: lock, prepare_launch() just before taking it (no plans = no lock).
PreSpawnHook = Callable[[str], PreSpawnPlan | None]

_HOOKS_LOCK = threading.Lock()
_PRE_SPAWN_HOOKS: list[PreSpawnHook] = []
#: Pre-start steps (dialog or apply) in progress, see pre_spawn_running().
_PHASES = 0
#: ``(package, text, short text)`` while a pre-start step applies, see
#: pre_spawn_status().
_STATUS: tuple[str, ...] | None = None
_STATUS_LISTENERS: list[Callable[[], None]] = []
#: Poll interval of recover_after_framework_restart().
_RECOVERY_POLL_S = 1.0


def register_pre_spawn_hook(hook: PreSpawnHook) -> None:
    """Run ``hook`` before every start of an app by Sandroid.

    Hooks run in registration order. Registering a hook again (also an
    equal bound method) is a no-op.
    """
    with _HOOKS_LOCK:
        if hook not in _PRE_SPAWN_HOOKS:
            _PRE_SPAWN_HOOKS.append(hook)


def unregister_pre_spawn_hook(hook: PreSpawnHook) -> None:
    """Remove ``hook`` (a no-op when it is not registered)."""
    with _HOOKS_LOCK:
        if hook in _PRE_SPAWN_HOOKS:
            _PRE_SPAWN_HOOKS.remove(hook)


def pre_spawn_running() -> bool:
    """A pre-start step (its dialog or its apply) is in progress."""
    with _HOOKS_LOCK:
        return _PHASES > 0


def pre_spawn_status(package: str | None = None, *, short: bool = False) -> str | None:
    """What the pre-start step applying right now does (for the App lens).

    Args:
        package: Only for this app (None: any).
        short: The few-word form for a narrow lens.

    Returns:
        One plain sentence, or None when no step applies (also while its
        dialog waits: the dialog says it).
    """
    with _HOOKS_LOCK:
        status = _STATUS
    if status is None or (package is not None and status[0] != package):
        return None
    return status[2] if short and len(status) > 2 else status[1]


def add_pre_spawn_status_listener(cb: Callable[[], None]) -> None:
    """Call ``cb()`` (any thread) when :func:`pre_spawn_status` changes."""
    with _HOOKS_LOCK:
        if cb not in _STATUS_LISTENERS:
            _STATUS_LISTENERS.append(cb)


def remove_pre_spawn_status_listener(cb: Callable[[], None]) -> None:
    """Stop calling ``cb``."""
    with _HOOKS_LOCK:
        if cb in _STATUS_LISTENERS:
            _STATUS_LISTENERS.remove(cb)


def _set_status(status: tuple[str, ...] | None) -> None:
    global _STATUS
    with _HOOKS_LOCK:
        _STATUS = status
        listeners = list(_STATUS_LISTENERS)
    for cb in listeners:
        try:
            cb()
        except Exception:
            logger.debug("Pre-start status listener failed", exc_info=True)


@contextmanager
def _pre_spawn_phase(status: tuple[str, ...] | None = None) -> Iterator[None]:
    global _PHASES
    with _HOOKS_LOCK:
        _PHASES += 1
    if status is not None:
        _set_status(status)
    try:
        yield
    finally:
        with _HOOKS_LOCK:
            _PHASES -= 1
        if status is not None:
            _set_status(None)


def _progress_text(plans: list[PreSpawnPlan]) -> tuple[str, str]:
    """``Applying identity profile 'x' (…) — the Android framework restarts;
    this can take a few minutes`` and a short form (``Applying identity
    profile 'x', framework restarts``) for the App lens.
    """
    what = _plans_text(plans)
    if what.startswith("apply "):
        what = "Applying " + what[len("apply ") :]
    else:
        what = f"Before the start: {what}"
    brief = plans[0].description.split(" (", 1)[0]
    if brief.startswith("apply "):
        brief = "Applying " + brief[len("apply ") :]
    if len(plans) > 1:
        brief += f" (+{len(plans) - 1})"
    if any(plan.disruptive for plan in plans):
        return (
            f"{what} — the Android framework restarts; this can take a few minutes",
            f"{brief}, framework restarts",
        )
    return f"{what} — the app starts after it", brief


def _hook_name(hook: Any) -> str:
    return str(
        getattr(hook, "__qualname__", None) or getattr(hook, "__name__", None) or hook
    )


def _collect_pre_spawn(package: str, tool: str) -> list[PreSpawnPlan]:
    """Ask every hook (registration order) what it needs before the start.

    Raises:
        AppStartError: A hook raised.
    """
    with _HOOKS_LOCK:
        hooks = list(_PRE_SPAWN_HOOKS)
    plans = []
    for hook in hooks:
        try:
            plan = hook(package)
        except Exception as exc:
            raise AppStartError(
                f"{tool} not started — pre-start step {_hook_name(hook)} failed: {exc}"
            ) from exc
        if plan is not None:
            plans.append(plan)
    return plans


def _plans_text(plans: list[PreSpawnPlan]) -> str:
    return "; ".join(plan.description for plan in plans)


def _confirm_pre_spawn(
    plans: list[PreSpawnPlan], package: str, tool: str, consent: bool
) -> None:
    """Get the OK for plans that stop every app (no-op without such a plan).

    With a UI: "Apply before starting {pkg}?" (worker thread only; refused
    on the UI thread, where the bus would deadlock). Without a UI only the
    caller's ``consent`` (headless ``fresh=True``) lets it proceed.

    Raises:
        AppStartError: Declined, Esc, a timeout, the UI thread, or headless
            without consent.
    """
    if not any(plan.disruptive for plan in plans):
        return
    what = _plans_text(plans)
    from sandroid.core.ui_request_bus import UIRequestBus, request_modal

    if not UIRequestBus.get().has_active_handler():
        if consent:
            logger.info("%s: applying %s with the caller's consent", tool, what)
            return
        raise AppStartError(
            f"{package} not started — {what} restarts the Android framework "
            "(every running app on the device stops) and there is no dialog "
            "to confirm it; pass fresh=True (the caller consents) to apply it."
        )
    if threading.current_thread() is threading.main_thread():
        logger.error("Pre-start confirmation for %s on the UI thread; refused", tool)
        raise AppStartError(
            f"{package} not started — cannot ask about {what} from the UI thread."
        )
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    with _pre_spawn_phase():
        answer = request_modal(
            ConfirmModal,
            title=f"Apply before starting {package}?",
            message=(
                f"Before {package} starts, Sandroid will {what}. This restarts "
                "the Android framework: every running app on the device stops."
                f"{stops_sentence(_restart_victims(package))}"
            ),
            yes_label="Apply and start",
            no_label="Cancel",
            guard_typing=True,
        )
    if answer is not True:
        raise AppStartError(f"{package} not started — {what} not applied")


def _spotlight_pkg() -> str | None:
    try:
        from sandroid.services import get_spotlight_service

        return get_spotlight_service().get_effective_package()
    except Exception:
        return None


def _restart_victims(package: str) -> tuple[str, ...]:
    """The tools a framework restart stops: on ``package`` and on the
    spotlight app (an AI launch of another app kills those too).
    """
    tools = list(app_tools(package))
    spot = _spotlight_pkg()
    if spot and spot != package:
        tools += [t for t in app_tools(spot) if t not in tools]
    return tuple(tools)


def _system_server_pid(serial: str | None = None) -> int | None:
    """PID of system_server (None: not running or adb failed)."""
    from sandroid.core.adb import Adb

    try:
        out, _err = Adb.send_adb_command("shell pidof system_server", serial=serial)
    except Exception as exc:
        logger.debug("pidof system_server failed: %s", exc)
        return None
    return _parse_pid(out or "")


def _apply_pre_spawn(plans: list[PreSpawnPlan], package: str) -> None:
    """Run every plan's ``apply`` in order; fail closed (no spawn).

    The system_server PID is read before any plan runs (one adb call): any
    ``apply`` may restart the framework, whatever its ``disruptive`` said.
    When the PID changed afterwards the Frida state is recovered
    (:func:`recover_after_framework_restart`), also after a failed plan.
    An ``apply`` is synchronous, so an unchanged PID means no restart.

    Raises:
        AppStartError: A plan failed, or the framework did not come back.
    """
    if not plans:
        return
    error: AppStartError | None = None
    with _pre_spawn_phase((package, *_progress_text(plans))):
        previous = _system_server_pid()
        for plan in plans:
            try:
                plan.apply()
            except Exception as exc:
                error = AppStartError(
                    f"Could not {plan.description}: {exc} — {package} not started"
                )
                error.__cause__ = exc
                break
        try:
            _after_framework_restart(
                previous, package, any(p.disruptive for p in plans)
            )
        except AppStartError as exc:
            if error is None:
                raise AppStartError(f"{exc} — {package} not started") from exc
            logger.warning("Recovery after the failed pre-start step: %s", exc)
    if error is not None:
        raise error


def _after_framework_restart(
    previous: int | None, package: str, disruptive: bool
) -> None:
    """Recover when system_server changed since ``previous``.

    Without a ``previous`` reading (adb failed) there is nothing to wait
    for: when a plan said it restarts the framework, recover if
    system_server runs again, else just drop the dead Frida handles (no
    wait); without that claim skip (logged).
    """
    now = _system_server_pid()
    if previous is None:
        if not disruptive:
            logger.info(
                "Pre-start step for %s: system_server unreadable before it "
                "(now %s); not waiting for a framework restart",
                package,
                now,
            )
            return
        if now is None:
            logger.info(
                "Pre-start step for %s: system_server unreadable before and "
                "after it; dropping the Frida handles without waiting",
                package,
            )
            _drop_dead_frida_state()
            _stop_launched_tools(package)
            return
    elif now == previous:
        logger.debug(
            "Pre-start step for %s left the framework running (system_server "
            "%s); nothing to recover",
            package,
            previous,
        )
        return
    try:
        recover_after_framework_restart(previous)
    finally:
        _stop_launched_tools(package)
    logger.info(
        "The Android framework restarted before %s started: Frida handles "
        "dropped, armed bypasses kept",
        package,
    )


def _stop_launched_tools(package: str) -> None:
    """The launched app's tools died too (the spotlight app's: in the drop)."""
    if package != _spotlight_pkg():
        stop_app_tools(package)


def _drop_dead_frida_state() -> None:
    """Drop the handles a framework restart killed (the armed set stays).

    The spotlight app's tools died with it: their tasks are stopped so none
    stays "running" on a dead process.
    """
    spot = _spotlight_pkg()
    if spot:
        stop_app_tools(spot)
    jm = _job_manager()
    drop_session(jm)  # bypass forget_process + the dead JobManager session
    try:
        from sandroid.services import get_frida_session_service

        # Also nulls JobManager.device: its transport died with the framework.
        get_frida_session_service().invalidate_frida_device_cache()
    except Exception as exc:
        logger.debug("Could not invalidate the Frida device cache: %s", exc)
    if jm is not None:
        try:
            jm.device = None
        except Exception:
            pass
    try:
        from sandroid.services import get_spotlight_service

        get_spotlight_service().announce_pid(None)
    except Exception as exc:
        logger.debug("Could not clear the spotlight PID: %s", exc)


#: Per-call adb timeout of the package-manager probe (seconds).
_PM_PROBE_TIMEOUT_S = 5.0


def _package_manager_ready(serial: str | None = None) -> bool:
    """``pm path android`` answers (the new framework serves binder calls)."""
    from sandroid.core.adb import Adb

    try:
        out, _err = Adb.send_adb_command(
            "shell pm path android", serial=serial, timeout=_PM_PROBE_TIMEOUT_S
        )
    except Exception as exc:
        logger.debug("pm path android failed: %s", exc)
        return False
    return "package:" in (out or "")


def _refresh_frida_server() -> str:
    """Restart frida-server when it died or predates the new system_server.

    A fresh one (the identity apply may have restarted it already) is left
    alone; a dead one is started as ``frida.server_auto_start`` says.
    """
    try:
        from sandroid.core.frida_manager import auto_start_frida_server

        _running, reason = auto_start_frida_server()
    except Exception as exc:
        return f"frida-server check failed: {exc}"
    return reason


def recover_after_framework_restart(
    previous_system_server_pid: int | None,
    timeout: float = 90.0,
    *,
    serial: str | None = None,
) -> None:
    """Bring Sandroid's Frida state back after an Android framework restart.

    For any restart of system_server (``stop``/``start``, a Zygote kill by
    the CA injection), also outside a spawn:

    1. Waits until system_server runs with a PID other than
       ``previous_system_server_pid`` (None: no PID gate, only "runs" --
       the old system_server answers for seconds after a Zygote kill, so
       pass the PID read before the restart), then, within
       the same timeout, until the package manager answers (``pm path
       android``): frida-server restarted earlier hits the post-restart ANR
       burst. Not ``sys.boot_completed``: it stays 1 across a restart.
    2. Drops the dead handles: the spotlight app's tools, the bypass script
       (the armed set stays), the JobManager session and device, the cached
       Frida device, the spotlight PID. Also when the wait timed out.
    3. Restarts frida-server if it died or predates the new system_server
       (it then fails every call with DeadSystemException). Idempotent: a
       fresh one is left alone.

    Blocking (polls adb): call it on a worker thread, never the UI thread.

    Steps 2 and 3 concern the active device's Frida handles: for another
    ``serial`` only the wait runs.

    Args:
        previous_system_server_pid: system_server's PID before the restart.
        timeout: Seconds to wait for the new system_server.
        serial: The restarted device (every adb read targets it); None: the
            active device.

    Raises:
        AppStartError: No new system_server, or no package manager, within
            ``timeout``.
    """
    from sandroid.core.adb import Adb

    active = serial is None or serial == Adb.get_target_device()

    def drop() -> None:
        if active:
            _drop_dead_frida_state()

    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        pid = _system_server_pid(serial=serial)
        if pid is not None and pid != previous_system_server_pid:
            break
        if time.monotonic() >= deadline:
            drop()
            raise AppStartError(
                f"The Android framework did not come back within {timeout:.0f} s "
                "(no new system_server)"
            )
        time.sleep(_RECOVERY_POLL_S)
    while not _package_manager_ready(serial=serial):
        if time.monotonic() >= deadline:
            drop()
            raise AppStartError(
                f"The Android framework did not come back within {timeout:.0f} s "
                "(the package manager does not answer)"
            )
        time.sleep(_RECOVERY_POLL_S)
    if not active:
        logger.info("Framework back on %s (not the active device)", serial)
        return
    _drop_dead_frida_state()
    logger.info("After the framework restart: %s", _refresh_frida_server())


def prepare_launch(
    package: str, tool: str, *, consent: bool = False, restart: bool = False
) -> bool:
    """Run the pre-spawn hooks before a start outside the Frida spawn path.

    For launches that do not go through :func:`open_session` /
    :func:`start_app` (TrigDroid's own spawn, the AI ``launch_app``, an
    Objection spawn); the caller's launch follows. The hooks are asked
    first: with nothing to do it returns at once (no lifecycle lock, no
    adb). Otherwise it runs under the lifecycle lock and only for an app
    that is not running.

    Args:
        package: The app about to start.
        tool: User-facing name for messages.
        consent: Headless consent for a step that stops every app.
        restart: The user already agreed to restart a running app (Objection
            spawn on a running app): it is stopped after the dialog, then
            the plans run.

    Returns:
        True when the caller may start the app now (no hook had anything to
        do, or the app is not running and the plans ran); False when it
        already runs (or Frida holds it) and ``restart`` is not set: nothing
        was run.

    Raises:
        AppStartError: A hook failed; with plans also busy, an adb error, a
            failed plan, declined.
    """
    plans = _collect_pre_spawn(package, tool)
    if not plans:
        return True
    with _lifecycle():
        liveness, _pid = probe_liveness(package, frida_fallback=True)
        if liveness == Liveness.UNKNOWN:
            raise AppStartError(
                f"Could not tell whether {package} is running (adb error); "
                f"{tool} not started."
            )
        jm = _job_manager()
        held = session_pid(jm) is not None and _session_package(jm) == package
        if (liveness == Liveness.RUNNING or held) and not restart:
            return False
        _confirm_pre_spawn(plans, package, tool, consent)
        if liveness == Liveness.RUNNING or held:
            from sandroid.services import get_spotlight_service

            spotlight = get_spotlight_service()
            try:
                respawn_teardown(package)  # after the OK: Cancel keeps it
            finally:
                spotlight.end_restart()
        _apply_pre_spawn(plans, package)
        return True


# ---------------------------------------------------------------------------
# Acting on a decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Opened:
    """The process a tool got from :func:`open_session`."""

    pid: int | None
    owns_spawn: bool
    paused: bool
    device: Any = None
    package: str = ""
    tool: str = ""


def _bypass() -> Any:
    from sandroid.analysis.detection_bypass import get_bypass_service

    return get_bypass_service()


def drop_session(jm: Any) -> None:
    """Drop the JobManager session (dead or idle) and the bypass handles.

    Only for sessions without live jobs (``reset_session`` stops every AFM
    job): the decision table refuses otherwise.
    """
    try:
        _bypass().forget_process()
    except Exception as exc:
        logger.debug("bypass forget_process failed: %s", exc)
    if jm is not None:
        try:
            jm.reset_session()
        except Exception as exc:
            logger.warning("reset_session failed: %s", exc)


def drop_idle_session(jm: Any, tool: str = "this tool") -> None:
    """:func:`drop_session`, but only when no job runs on it.

    Re-checked right before the reset, and check plus reset run under the
    lifecycle lock: a dialog (Dexray's snapshot prompt) may sit between the
    decision and this call.

    Raises:
        AppStartError: Live jobs appeared meanwhile, or another start holds
            the lifecycle lock.
    """
    with _lifecycle():
        try:
            alive = bool(jm.has_active_session()) if jm is not None else False
        except Exception:
            alive = True
        jobs = live_job_names(jm) if alive else ()
        if jobs:
            raise AppStartError(
                f"Frida started {', '.join(jobs)} meanwhile; {tool} not started."
            )
        drop_session(jm)


def stop_app_tools(package: str) -> list[str]:
    """Stop the TaskService tools on ``package`` (not the bypass/monitor).

    The bypass job is dropped by ``forget_process`` (keeps the armed set);
    stopping its task would clear the armed set. A tool with a ``quiet_stop``
    (Dexray) is stopped through it: no dialog (snapshot revert) may pop up
    while a restart holds the lifecycle lock.
    """
    stopped = []
    try:
        from sandroid.services import get_task_service

        svc = get_task_service()
        tasks = {getattr(t, "name", ""): t for t in svc.get_running_tasks()}
    except Exception:
        return stopped
    for name, display in _app_tasks(package):
        if name == "bypass":
            continue
        quiet = getattr(getattr(tasks.get(name), "instance", None), "quiet_stop", None)
        if callable(quiet):
            tasks[name].stop_callback = quiet
        try:
            if svc.stop(name):
                stopped.append(display)
        except Exception as exc:
            logger.warning("Stopping %s failed: %s", name, exc)
    return stopped


def respawn_teardown(package: str) -> None:
    """Kill ``package`` and clear every Frida state on it (⇧R order).

    force-stop FIRST: unloading a script on a live process can hang, while
    every unload/detach on a dead one fails fast. The header says
    "restarting…" until :meth:`SpotlightService.end_restart` (the caller's
    ``finally``).
    """
    from sandroid.core.adb import Adb
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    try:
        # Bypasses turned on live (Ctrl+P) join the armed set, as on ⇧K,
        # before the kill: the liveness poll drops them once the app is gone.
        if _spotlight_pkg() == package:  # not after a selection change
            _bypass().arm_active(package)
    except Exception as exc:
        logger.warning("Keeping the live bypasses armed failed: %s", exc)
    Adb.force_stop(package)
    spotlight.begin_restart(package)
    time.sleep(0.5)  # let the process die so the session connection breaks
    stop_app_tools(package)
    try:
        _bypass().keep_armed_and_forget(package)  # drops the dead script
    except Exception as exc:
        logger.warning("Dropping the bypass script failed: %s", exc)
    drop_session(_job_manager())


def _spawn_paused(package: str, tool: str = "") -> Opened:
    """Spawn ``package`` paused as ``tool``'s own (setup marker first).

    The marker is set before the spawn, so Space cannot resume the new
    process in the gap before the PID is known; a failed spawn clears it.
    """
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    _begin_setup(tool, package)
    try:
        jm, pid = spotlight.spawn_app_paused(package)
        if not pid or pid <= 0:
            reason = getattr(spotlight, "last_spawn_error", None) or "no PID"
            raise AppStartError(f"Failed to spawn {package}: {reason}")
    except BaseException:
        end_setup(tool)
        raise
    _setup_spawned(tool, pid)
    try:
        spotlight.announce_pid(pid, package)
    except Exception:
        pass
    return Opened(pid, True, True, getattr(jm, "device", None), package, tool)


def open_session(decision: StartDecision, handler: Any = None) -> Opened:
    """Give the caller a JobManager session as ``decision`` says (worker only).

    JOIN does nothing; ATTACH attaches the JobManager to the PID; SPAWN
    re-checks liveness right before spawning (a config dialog or snapshot
    prompt may have passed since the decision) and refuses when the app came
    up meanwhile; RESPAWN runs the ⇧R teardown first. SPAWN and RESPAWN run
    the pre-spawn hooks right before the spawn (RESPAWN asks before the
    teardown, so Cancel leaves the app running).

    Raises:
        AppStartError: REFUSE/NEEDS_CONFIRM decisions, a busy lifecycle, an
            app that started meanwhile, a failed or declined pre-start step,
            a failed spawn.
    """
    jm = _job_manager()
    pkg = decision.package
    action = decision.action
    if action == StartAction.JOIN:
        return Opened(
            decision.pid, False, decision.paused, getattr(jm, "device", None), pkg
        )
    if action == StartAction.ATTACH:
        if jm is None:
            raise AppStartError("Frida JobManager unavailable")
        if decision.reset_session:
            drop_idle_session(jm, decision.tool)
        from sandroid.core.frida_manager import install_stale_detach_guard

        install_stale_detach_guard(jm)
        jm.setup_frida_session(decision.pid, handler, should_spawn=False)
        return Opened(decision.pid, False, False, getattr(jm, "device", None), pkg)
    if action == StartAction.SPAWN:
        with _lifecycle():
            liveness, pid = probe_liveness(pkg, frida_fallback=True)
            if liveness == Liveness.UNKNOWN:
                raise AppStartError(
                    f"Could not tell whether {pkg} is running; "
                    f"{decision.tool} not started."
                )
            if pid:
                raise AppStartError(
                    f"{pkg} started meanwhile (pid {pid}); start "
                    f"{decision.tool} again to attach to it."
                )
            if decision.reset_session:
                drop_idle_session(jm, decision.tool)
            plans = _collect_pre_spawn(pkg, decision.tool)
            _confirm_pre_spawn(plans, pkg, decision.tool, decision.consent)
            _apply_pre_spawn(plans, pkg)
            return _spawn_paused(pkg, decision.tool)
    if action == StartAction.RESPAWN:
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        with _lifecycle():
            plans = _collect_pre_spawn(pkg, decision.tool)
            _confirm_pre_spawn(plans, pkg, decision.tool, decision.consent)
            try:
                respawn_teardown(pkg)
                _apply_pre_spawn(plans, pkg)
                return _spawn_paused(pkg, decision.tool)
            finally:
                spotlight.end_restart()
    raise AppStartError(decision.reason or f"{decision.tool} not started")


def apply_armed_after_launch(tool: str = "the tool") -> str:
    """Apply the armed bypasses live after a tool resumed its own spawn.

    Returns:
        A note for the user ("" when nothing was armed or all is well).
    """
    bypass = _bypass()
    try:
        armed = set(bypass.armed_categories())
    except Exception:
        return ""
    if not armed:
        return ""
    ok, msg = bypass.apply_armed()
    if not ok:
        return f"armed bypasses not applied: {msg}"
    early = [
        bypass.display_name(c)
        for c in sorted(armed)
        if c == "root" or bypass.applies_at_spawn(c)
    ]
    if early:
        return (
            f"{', '.join(early)} applied after launch, so checks at startup "
            f"missed them — next time ␣ start first, then {tool} joins live"
        )
    return ""


def finish_owned_spawn(opened: Opened, tool: str = "the tool") -> str:
    """Resume a spawn the caller owns, then apply the armed bypasses live.

    A process the caller did not spawn is never resumed (a ⇧P hold waits
    for Space).

    Returns:
        A note for the user, possibly "".

    Raises:
        frida.ProcessNotFoundError: The process died during hook load.
    """
    if not opened.owns_spawn:
        return "app still paused — ␣ resumes" if opened.paused else ""
    from sandroid.services import get_frida_session_service

    jm = _job_manager()
    device = getattr(jm, "device", None) or opened.device
    try:
        get_frida_session_service().resume_spawned_process(device, opened.pid)
    finally:
        end_setup(opened.tool, opened.pid)
    # Resumed: from here on nothing may fail the tool's start (its caller
    # would treat the running app as a frozen spawn).
    try:
        return apply_armed_after_launch(tool)
    except Exception as exc:
        logger.warning("Applying armed bypasses after launch failed: %s", exc)
        return f"armed bypasses not applied: {exc}"


def abort_owned_spawn(opened: Opened | None) -> None:
    """A tool failed after spawning the app itself: leave nothing frozen.

    Force-stops the spawn (first: unloads on a live process can hang), drops
    the JobManager session and the bypass handles, clears the PID so the
    header shows ○ -- but only while the spawn is still the app's process
    (pidof or the JobManager's session PID): after a ⇧R / AI restart or a
    die-and-respawn the new process is never touched. The tool's setup
    marker is always ended. A process the tool did not spawn is left alone.
    """
    if opened is None or not opened.owns_spawn:
        return
    try:
        jm = _job_manager()
        spid = session_pid(jm)
        try:
            liveness, live = probe_liveness(opened.package)
        except Exception:
            liveness, live = Liveness.UNKNOWN, None
        # A held spawn has no name pidof can find; if its session is gone too
        # (died on its own, e.g. an anti-Frida self-kill), it is still ours
        # unless another start holds the lifecycle lock (its new process
        # would be just as nameless). Never act on an adb error.
        nameless_and_sessionless = (
            liveness is Liveness.NOT_RUNNING
            and spid is None
            and not _LIFECYCLE.busy_for_caller()
        )
        ours = (
            live == opened.pid
            or (live is None and spid == opened.pid)
            or nameless_and_sessionless
        )
        if not ours:
            logger.info(
                "Not stopping %s: pid %s is no longer the failed spawn %s",
                opened.package,
                live or spid,
                opened.pid,
            )
            return
        try:
            from sandroid.core.adb import Adb

            if opened.package:
                Adb.force_stop(opened.package)
        except Exception as exc:
            logger.warning("force_stop of the failed spawn failed: %s", exc)
        drop_session(jm)
        try:
            from sandroid.services import get_spotlight_service

            get_spotlight_service().announce_pid(None, opened.package or None)
        except Exception as exc:
            logger.debug("Could not clear the spotlight PID: %s", exc)
    finally:
        end_setup(opened.tool, opened.pid)


# ---------------------------------------------------------------------------
# Lifecycle (Space, ⇧P, ⇧R, ⇧A, AI start_spotlight_app)
# ---------------------------------------------------------------------------


def _spotlight_package() -> str | None:
    from sandroid.services import get_spotlight_service

    return get_spotlight_service().get_effective_package()


def start_app(paused: bool = False, *, consent: bool = False) -> tuple[bool, str]:
    """Start the stopped spotlight app with the armed bypasses (Space / ⇧P).

    Never restarts: a running app (also one opened from the launcher since
    the last poll) or a held spawn is reported, not killed. The pre-spawn
    hooks run right before the spawn.

    Args:
        paused: Keep the app paused after the hooks loaded (⇧P).
        consent: Headless consent for a pre-start step that stops every app
            (with a UI the dialog always asks).

    Returns:
        ``(ok, message)``.
    """
    if not _LIFECYCLE.try_acquire():
        return False, _BUSY_MSG
    try:
        pkg = _spotlight_package()
        if not pkg:
            return False, _no_app("Start").reason
        decision = decide_start(gather_inputs(pkg, tool="Start", frida_fallback=True))
        if decision.action == StartAction.REFUSE:
            return False, decision.reason
        if decision.action == StartAction.JOIN and decision.paused:
            return False, f"{pkg} is already started paused — ␣ resumes it"
        if decision.action != StartAction.SPAWN:
            return False, (
                f"{pkg} is already running (pid {decision.pid}) — ⇧R restarts "
                "it, ⇧A attaches"
            )
        # The armed set now: a selection change during the dialog or the
        # framework restart disarms, and this app must keep its bypasses.
        bypass = _bypass()
        armed = bypass.armed_categories()
        try:
            if decision.reset_session:
                drop_idle_session(_job_manager(), "Start")
            plans = _collect_pre_spawn(pkg, pkg)
            _confirm_pre_spawn(plans, pkg, pkg, consent)
            _apply_pre_spawn(plans, pkg)
        except AppStartError as exc:
            return False, str(exc)
        return bypass.apply_to_fresh_spawn_with_retry(pkg, armed, resume=not paused)
    finally:
        _LIFECYCLE.release()


def restart_app(paused: bool = False, *, consent: bool = False) -> tuple[bool, str]:
    """Force-stop and start the spotlight app again (⇧R; the AI after consent).

    The caller is the consent to restart this app: ⇧R is the explicit restart
    key, the AI tool asks through its approval gate. Tools on the app are
    stopped cleanly; the armed bypass set is kept and applied to the new
    process. A pre-start step that stops every app is asked about first
    (before the teardown: Cancel leaves the app running) -- ⇧R's "no dialog"
    covers this app only.

    Args:
        paused: Keep the new process paused after the hooks loaded.
        consent: Headless consent for a pre-start step that stops every app
            (with a UI the dialog always asks).

    Returns:
        ``(ok, message)``.
    """
    if not _LIFECYCLE.try_acquire():
        return False, _BUSY_MSG
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    try:
        pkg = spotlight.get_effective_package()
        if not pkg:
            return False, _no_app("Restart").reason
        # Armed or on live, now: a selection change during the dialog disarms.
        bypass = _bypass()
        armed = bypass.carried_categories(pkg)
        try:
            plans = _collect_pre_spawn(pkg, pkg)
            _confirm_pre_spawn(plans, pkg, pkg, consent)
        except AppStartError as exc:
            return False, str(exc)  # nothing was torn down
        try:
            respawn_teardown(pkg)
            try:
                _apply_pre_spawn(plans, pkg)
            except AppStartError as exc:
                return False, str(exc)
            return bypass.apply_to_fresh_spawn_with_retry(pkg, armed, resume=not paused)
        finally:
            spotlight.end_restart()
    finally:
        _LIFECYCLE.release()


def resume_app() -> tuple[bool, str]:
    """Resume the held (paused) spotlight app (Space on ◐ paused).

    Bypasses armed while the app was paused are applied live right after.
    """
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    if not spotlight.is_app_paused():
        return False, "No paused app to resume"
    if _LIFECYCLE.busy_for_caller():
        return False, _BUSY_MSG
    owner = setup_owner()
    if owner:
        return False, f"{owner} is still loading its hooks — ␣ resumes after it"
    if not spotlight.resume_paused_app():
        return False, "Resume failed"
    bypass = _bypass()
    try:
        missing = set(bypass.armed_categories()) - set(bypass.active_categories())
    except Exception:
        missing = set()
    if missing:
        _ok, msg = bypass.apply_armed()
        return True, f"Resumed app · {msg}"
    return True, "Resumed app"


def attach_app() -> tuple[bool, str]:
    """Attach to the running spotlight app and apply the armed bypasses (⇧A)."""
    from sandroid.services import get_spotlight_service

    spotlight = get_spotlight_service()
    pkg = spotlight.get_effective_package()
    if not pkg:
        return False, _no_app("Attach").reason
    liveness, pid = probe_liveness(pkg, frida_fallback=True)
    if liveness == Liveness.UNKNOWN:
        return False, f"Could not tell whether {pkg} is running (adb error)"
    if not pid:
        return False, f"{pkg} is not running — ␣ starts it"
    spotlight.set_app(pkg, pid=pid)
    return _bypass().apply_armed()


__all__ = [
    "AppStartError",
    "Liveness",
    "Opened",
    "PreSpawnHook",
    "PreSpawnPlan",
    "StartAction",
    "StartDecision",
    "StartInputs",
    "abort_owned_spawn",
    "add_pre_spawn_status_listener",
    "apply_armed_after_launch",
    "attach_app",
    "decide_start",
    "end_setup",
    "finish_owned_spawn",
    "lifecycle_lock",
    "negotiate_start",
    "open_session",
    "pre_spawn_running",
    "pre_spawn_status",
    "prepare_launch",
    "probe_liveness",
    "recover_after_framework_restart",
    "register_pre_spawn_hook",
    "remove_pre_spawn_status_listener",
    "resolve_start",
    "restart_app",
    "resume_app",
    "setup_owner",
    "start_app",
    "stops_sentence",
    "unregister_pre_spawn_hook",
]
