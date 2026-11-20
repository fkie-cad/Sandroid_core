"""The "device prepared" step: re-prepare the active device on every attach.

adb root and SELinux Permissive used to be set once, at startup. A device
attached later (Devices screen), or the active device after a reboot (adb
reboot, emulator restart, crash and relaunch) came back Enforcing and
without root, and nothing re-prepared it. This module runs one step on
every attach / reconnect of the ACTIVE device, off the UI thread, in a
fixed order::

    0. settle      the device is ``device`` + booted, stable for ~1 s
    1. classify    boot_id / ro.runtime.firstboot / uptime (one adb call):
                   ``first`` (new to this process), ``new-world`` (rebooted,
                   or restarted from a snapshot -- see :func:`_classify`:
                   a timeline world change before anything else),
                   ``reattach`` (same boot, new adb transport; also a
                   retry when root / SELinux failed last time) or
                   ``unchanged`` (nothing to do)
    2. clock       ``device_clock.after_device_connect``
    3. root        ``adb root`` (by ``Device.root_kind``), ``setenforce 0``,
                   then the waiting session-start clock sync; the adb
                   transport is read here (after adb root's adbd restart)
    4. stages      blocking stages in their order, each with its own
                   budget (:func:`register_prepare_stage`): a persona check
                   (registered by its owner), then the identity profile
                   (``IdentityService.ensure_applied``; nothing when identity
                   mode is off). They run before the hooks: a framework
                   restart would kill what the hooks set up. A failing
                   stage is a warning; the step goes on.
    5. hooks       :func:`register_device_prepared_hook` callbacks,
                   ``hook(serial, fresh_boot)`` (e.g. the proxy restore)
    6. done        record the boot + transport, release waiters, fire
                   ``DeviceManager.on_device_prepared`` listeners (Frida,
                   app work)

A new Sandroid launch of the serial (a new ``launch_id`` in
:func:`sandroid.core.emulator.launch_record`) is always a new world, even
with the same boot id (two boots from one snapshot).

The listeners also get ``failed`` runs (and ``held`` after a snapshot
load that dropped a re-attach), never ``aborted`` ones; an ``unchanged``
run reaches them only when they have not seen this prepared state yet
(e.g. after a switch away and back).

Only the active serial is ever prepared (requests for other serials are
ignored), so the ``--serial`` pin rules and other sessions' devices stay
untouched. The step is off until a path that prepares devices turns it on
(:func:`set_enabled`: ``initialize_core(prepare=True)`` and the startup
check); everything else keeps today's behaviour.

Public API: :func:`register_device_prepared_hook`,
:func:`unregister_device_prepared_hook`, :func:`register_prepare_stage`,
:func:`unregister_prepare_stage`, :func:`request_prepare`,
:func:`ensure_prepared`, :func:`wait_prepared`, :func:`is_preparing`,
:func:`hold`, :func:`note_adb_server_restart`, :func:`note_world_recorded`,
:func:`set_enabled`, :func:`is_enabled`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: ``hook(serial, fresh_boot)``: idempotent, may take ~10 s, never on the
#: UI thread. ``fresh_boot`` is False for a re-attach in the same boot.
DevicePreparedHook = Callable[[str, bool], None]

#: ``stage(serial, fresh_boot, budget_s)``: a blocking stage before the
#: hooks (worker thread, adb pinned to ``serial``). Returns ``None``, a
#: one-line info text or a :class:`StageNote`; raising is a warning.
PrepStage = Callable[[str, bool, float], Any]

#: Seconds a hook may run before the step warns and goes on without it.
HOOK_TIMEOUT_S = 60.0
#: Budget of the built-in identity stage (a framework window included).
IDENTITY_BUDGET_S = 240.0
#: A framework window that started near the end of the budget still waits
#: the identity service's full restart timeout (RESTART_TIMEOUT_S, 180 s).
IDENTITY_OVERRUN_S = 190.0
#: Seconds a stage may overrun its budget before the step goes on.
STAGE_GRACE_S = 10.0
#: Seconds the settle step waits for a booting device.
SETTLE_TIMEOUT_S = 300.0
#: Seconds the device must stay ready before the step starts.
SETTLE_STABLE_S = 1.0
#: Minimum seconds between two ``fresh_boot=False`` (re-attach) runs.
REATTACH_MIN_INTERVAL_S = 5.0
#: Uptime this far below the recorded one is a rewind (a new world).
UPTIME_REWIND_S = 2.0
#: Seconds the boot start (host monotonic - device uptime) may move LATER
#: and still be the same world (adb latency jitter). A quickboot from a
#: snapshot keeps the boot_id and restores the snapshot's uptime, so its
#: boot start jumps later by about the time the device was down plus the
#: time since the snapshot was saved. An EARLIER boot start is never a new
#: world: a restore or reboot cannot put the uptime ahead of the host's
#: clock, but host sleep can (host monotonic -- mach_absolute_time /
#: CLOCK_MONOTONIC -- stops while the host sleeps, a physical device's
#: uptime keeps counting, an emulator may catch up). Where host sleep moves
#: it later instead (a guest paused while the host clock counts sleep), the
#: result is one extra world change and an idempotent re-preparation.
BOOT_START_TOLERANCE_S = 5.0
#: Seconds the first run waits for a connect clock sample that started
#: while the step was off (before its ``adb root`` restarts adbd).
CONNECT_JOIN_S = 15.0
#: The thread name of ``device_clock.after_device_connect_async``.
_CLOCK_CONNECT_THREAD = "device-clock-connect"
#: Seconds a preparing active device may be missing from ``adb devices``
#: (``adb root`` restarts adbd) before the device manager declares it lost.
LOSS_GRACE_S = 20.0
#: Seconds step 3 waits for the session-start clock sync.
CLOCK_SYNC_WAIT_S = 10.0
#: Seconds the Frida / app-start backstops wait for a running step.
GATE_TIMEOUT_S = 90.0
#: Seconds startup / headless preparation waits for the step.
ENSURE_TIMEOUT_S = 360.0

#: One adb call, no root: boot id, first-boot time, uptime.
BOOT_INFO_COMMAND = (
    'shell "cat /proc/sys/kernel/random/boot_id; '
    'getprop ro.runtime.firstboot; cat /proc/uptime"'
)
_BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_FIRSTBOOT = re.compile(r"^\d{6,}$")
_UPTIME = re.compile(r"^(\d+(?:\.\d+)?)\s+\d+(?:\.\d+)?$")

#: Result kinds of a run that prepared (or found prepared) the device.
DONE_KINDS = frozenset({"first", "new-world", "reattach", "unchanged"})
#: Result kinds that ran steps 2-4.
RAN_KINDS = frozenset({"first", "new-world", "reattach"})
_KIND_LABEL = {
    "first": "attach",
    "new-world": "reboot",
    "reattach": "reconnect",
    "unchanged": "unchanged",
}


@dataclass
class PrepResult:
    """What one run of the step did.

    Attributes:
        serial: The device.
        kind: ``first`` / ``new-world`` / ``reattach`` / ``unchanged`` (see
            the module doc), ``aborted`` (the device was lost or switched
            away mid-run), ``failed`` (never became ready, or an error),
            ``disabled`` / ``ignored`` (not the active device) / ``refused``
            (UI thread) / ``timeout`` / ``held`` (a snapshot load).
        reason: What asked for the run (``attach``, ``transport``, ...).
        fresh_boot: The value the hooks got.
        boot_token: boot_id (``fb:<firstboot>`` as fallback; None unknown).
        root: ``ok`` / ``failed`` / ``su`` (adb root skipped) / ``none``.
        root_check: The ``adb root`` SetupCheckResult (None when skipped).
        selinux_check: The ``setenforce 0`` SetupCheckResult.
        hooks_total: Hooks run.
        hook_errors: ``"<hook>: <error>"`` per failed / timed-out hook.
        duration_s: Wall time of the run.
        error: Why a ``failed`` run failed.
        stage_notes: ``(stage, level, text)`` per stage that said
            something; ``level`` is ``info`` or ``warning``.
        launch_id: Sandroid's launch of the serial (``None``: not ours).
    """

    serial: str
    kind: str
    reason: str = ""
    fresh_boot: bool = False
    boot_token: str | None = None
    root: str = ""
    root_check: Any = None
    selinux_check: Any = None
    hooks_total: int = 0
    hook_errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    error: str = ""
    stage_notes: list[tuple[str, str, str]] = field(default_factory=list)
    launch_id: str | None = None

    @property
    def prepared(self) -> bool:
        """The device is prepared (this run or an earlier one)."""
        return self.kind in DONE_KINDS

    @property
    def ran(self) -> bool:
        """This run went through root / SELinux / hooks."""
        return self.kind in RAN_KINDS

    @property
    def selinux_mode(self) -> str:
        """``getenforce`` after the SELinux step ("" unknown)."""
        check = self.selinux_check
        return str(getattr(check, "details", {}).get("mode", "")) if check else ""

    @property
    def has_problems(self) -> bool:
        """The run failed, root or SELinux failed, a stage warned or a hook
        failed.
        """
        root_bad = self.root == "failed"
        selinux_bad = self.selinux_check is not None and not self.selinux_check.passed
        failed = self.kind == "failed"
        warned = any(level == "warning" for _n, level, _t in self.stage_notes)
        return bool(self.hook_errors) or root_bad or selinux_bad or failed or warned

    def summary(self) -> str:
        """One activity-log line, e.g. ``Prepared emulator-5554 (reboot):
        root ok; SELinux Permissive; identity: 9 set; hooks 1/1; 3.2 s``.
        """
        if not self.ran:
            why = f" ({self.error})" if self.error else ""
            return f"Device {self.serial}: preparation {self.kind}{why}"
        label = _KIND_LABEL.get(self.kind, self.kind)
        root = {
            "ok": "root ok",
            "failed": "root failed",
            "su": "root via su",
            "none": "no root",
        }.get(self.root, "root unknown")
        parts = [root]
        if self.selinux_check is not None:
            failed = "" if self.selinux_check.passed else " (failed)"
            parts.append(f"SELinux {self.selinux_mode or 'unknown'}{failed}")
        parts += [f"{name}: {text}" for name, _level, text in self.stage_notes]
        if self.hooks_total:
            good = self.hooks_total - len(self.hook_errors)
            parts.append(f"hooks {good}/{self.hooks_total}")
        return (
            f"Prepared {self.serial} ({label}): {'; '.join(parts)}; "
            f"{self.duration_s:.1f} s"
        )


@dataclass(frozen=True)
class StageNote:
    """What a stage reports: ``level`` ``info`` or ``warning``, one line."""

    level: str
    text: str


@dataclass(frozen=True)
class _StageSpec:
    name: str
    fn: PrepStage
    order: int
    budget_s: float
    #: Extra seconds the stage may legitimately run past its budget.
    overrun_s: float = 0.0


@dataclass
class _Record:
    """The last prepared state of a serial."""

    token: str | None
    uptime: float | None
    transport_id: str
    root: str = ""
    root_check: Any = None
    selinux_check: Any = None
    #: Host monotonic time the boot started (host now - uptime; None unknown).
    boot_start: float | None = None
    #: Host monotonic time the boot was read: a Sandroid launch of the
    #: serial after it is a new world.
    recorded_at: float = field(default_factory=lambda: _host_now())
    #: Sandroid's launch of the serial then (another one: a new world).
    launch_id: str | None = None


@dataclass
class _Serial:
    """Per-serial bookkeeping (guarded by ``_LOCK``)."""

    record: _Record | None = None
    running: bool = False
    pending: str | None = None
    #: ``gen`` when the pending request was made: a detach / hold after it
    #: cancels it, a request after a detach is valid.
    pending_gen: int = 0
    gen: int = 0
    stage: str = ""
    result: PrepResult | None = None
    manager: Any = None
    last_reattach: float = float("-inf")
    connect_started: bool = False
    world_token: str | None = None
    #: Boot start (host monotonic - uptime) of the last world change.
    world_boot_start: float | None = None
    #: ``started_at`` of the Sandroid launch the last world change was for.
    world_launch_at: float | None = None
    #: The listeners have seen the current prepared state (an ``unchanged``
    #: run then does not fire them again); cleared on detach.
    delivered: bool = False
    held: int = 0
    held_dropped: bool = False
    progress: list[Callable[[str], None]] = field(default_factory=list)
    #: Host monotonic end of the blocking stage running now (its budget
    #: plus grace): waiters wait at least that long.
    stage_deadline: float | None = None


_LOCK = threading.RLock()
_IDLE = threading.Condition(_LOCK)
_STATES: dict[str, _Serial] = {}
_HOOKS_LOCK = threading.Lock()
_HOOKS: list[DevicePreparedHook] = []
_STAGES: list[_StageSpec] = []
#: Thread idents of prepare workers and their hook threads (their
#: ``wait_prepared`` returns at once: no self-deadlock).
_PREP_THREADS: set[int] = set()
_WARNED_NO_ROOT: set[str] = set()
_ENABLED = False


# --------------------------------------------------------------- registry


def register_device_prepared_hook(hook: DevicePreparedHook) -> None:
    """Run ``hook(serial, fresh_boot)`` in step 5 of every prepare run.

    Thread-safe and idempotent (an equal hook is registered once). Each
    hook runs in its own thread with the adb target pinned to ``serial``;
    an exception is logged and swallowed, a hook still running after
    :data:`HOOK_TIMEOUT_S` is warned about and the step goes on.
    """
    with _HOOKS_LOCK:
        if hook not in _HOOKS:
            _HOOKS.append(hook)


def unregister_device_prepared_hook(hook: DevicePreparedHook) -> bool:
    """Remove ``hook``; False when it was not registered."""
    with _HOOKS_LOCK:
        try:
            _HOOKS.remove(hook)
        except ValueError:
            return False
        return True


#: Order of the built-in identity stage (a persona check goes before it).
IDENTITY_STAGE_ORDER = 20


def register_prepare_stage(
    name: str,
    stage: PrepStage,
    *,
    order: int,
    budget_s: float,
    overrun_s: float = 0.0,
) -> None:
    """Run ``stage(serial, fresh_boot, budget_s)`` before the hooks.

    Blocking stages run in ``order`` (lowest first; the identity stage is
    :data:`IDENTITY_STAGE_ORDER`), each in its own thread with the adb
    target pinned, for at most ``budget_s`` + ``overrun_s`` (what the stage
    may legitimately run past its budget) + :data:`STAGE_GRACE_S`; the
    app-start / Frida gates wait for them. A stage returns ``None``, an info
    text or a :class:`StageNote`; an exception or an overrun is a warning in
    the result, the log and the timeline, and the step goes on. Registering
    a name again replaces it.
    """
    if not callable(stage):
        raise TypeError("stage must be callable")
    spec = _StageSpec(name, stage, int(order), float(budget_s), float(overrun_s))
    with _HOOKS_LOCK:
        _STAGES[:] = [s for s in _STAGES if s.name != name]
        _STAGES.append(spec)
        _STAGES.sort(key=lambda s: s.order)


def unregister_prepare_stage(name: str) -> bool:
    """Remove the stage *name*; False when there was none."""
    with _HOOKS_LOCK:
        before = len(_STAGES)
        _STAGES[:] = [s for s in _STAGES if s.name != name]
        return len(_STAGES) != before


# ---------------------------------------------------------------- control


def set_enabled(enabled: bool) -> None:
    """Turn the step on (a path that prepares devices) or off.

    Off (the default) every request is ignored; a running step aborts at
    its next stage.
    """
    global _ENABLED
    with _LOCK:
        _ENABLED = bool(enabled)
        _IDLE.notify_all()


def is_enabled() -> bool:
    """Whether the step runs on attach / reconnect."""
    return _ENABLED


def reset(*, hooks: bool = False) -> None:
    """Forget every serial and turn the step off (tests; a new session).

    Args:
        hooks: Also drop the registered hooks.
    """
    global _ENABLED
    with _LOCK:
        for state in _STATES.values():
            state.gen += 1
            state.running = False
            state.stage_deadline = None
        _STATES.clear()
        _WARNED_NO_ROOT.clear()
        _ENABLED = False
        _IDLE.notify_all()
    if hooks:
        with _HOOKS_LOCK:
            _HOOKS.clear()


def _state(serial: str) -> _Serial:
    state = _STATES.get(serial)
    if state is None:
        state = _STATES[serial] = _Serial()
    return state


def _peek_manager() -> Any:
    """The DeviceManager singleton, without creating it."""
    try:
        from sandroid.core.device_manager import DeviceManager

        return DeviceManager._instance
    except Exception:
        return None


def _active_serial(manager: Any = None) -> str | None:
    manager = manager if manager is not None else _peek_manager()
    device = getattr(manager, "active_device", None) if manager else None
    return getattr(device, "serial", None) if device is not None else None


def _on_ui_thread() -> bool:
    """True on a thread that runs an asyncio loop (the Textual UI thread)."""
    if threading.current_thread() is not threading.main_thread():
        return False
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _merge_reason(old: str | None, new: str) -> str:
    """A transport-only pending request is absorbed more easily."""
    if old is None or old == "transport":
        return new
    return old


def request_prepare(serial: str, reason: str, *, manager: Any = None) -> bool:
    """Ask for a prepare run of ``serial`` (never blocks; UI-safe).

    Only the active serial is prepared. A request while a run is in flight
    is coalesced into one more run afterwards; during :func:`hold` it is
    dropped.

    Args:
        serial: The device.
        reason: ``attach``, ``transport``, ``ready``, ``restart``,
            ``adb-server``, ``ensure`` ...
        manager: The DeviceManager whose active device counts and whose
            ``on_device_prepared`` listeners fire (default: the singleton).

    Returns:
        True when the request was taken (started, coalesced or dropped by
        a hold); False when the step is off or ``serial`` is not active.
    """
    if not _ENABLED or not serial:
        return False
    manager = manager if manager is not None else _peek_manager()
    if _active_serial(manager) != serial:
        logger.debug(f"device prep: {serial} is not the active device; ignored")
        return False
    with _LOCK:
        state = _state(serial)
        if state.held:
            state.held_dropped = True
            logger.debug(f"device prep: {reason} request for {serial} held")
            return True
        state.manager = manager
        state.pending_gen = state.gen
        if state.running:
            state.pending = _merge_reason(state.pending, reason)
            return True
        state.running = True
        state.pending = reason
        state.stage = "queued"
        thread = threading.Thread(
            target=_worker, args=(serial,), name=f"device-prep-{serial}", daemon=True
        )
        thread.start()
    return True


def connect_clock_only(serial: str) -> None:
    """The step is off: only the device-clock connect sample, as before.

    A later first run of the step (startup turns it on after the device
    was attached) then skips its clock step: it already ran for this
    attach.
    """
    try:
        from sandroid.core import device_clock

        device_clock.after_device_connect_async(serial)
    except Exception as e:
        logger.debug(f"Could not sample the device clock: {e}")
        return
    with _LOCK:
        _state(serial).connect_started = True


def note_detached(serial: str) -> None:
    """``serial`` stopped being the active device (lost / switched away).

    A run in flight for it aborts at its next stage (no hooks, no
    listeners, its waiters are released).
    """
    with _LOCK:
        state = _STATES.get(serial)
        if state is not None:
            state.gen += 1
            state.delivered = False
            state.stage_deadline = None  # its waiters need not wait for it
            _IDLE.notify_all()


def note_adb_server_restart() -> None:
    """The adb server restarted (track-devices EOF): transport ids are
    reused, so forget the recorded ones, and re-attach the active device
    (``fresh_boot=False``: the proxy re-adds its ``adb reverse`` rules).
    """
    with _LOCK:
        for state in _STATES.values():
            if state.record is not None:
                state.record.transport_id = ""
    serial = _active_serial()
    if serial:
        request_prepare(serial, "adb-server")


def note_world_recorded(serial: str) -> None:
    """The caller recorded the world change of ``serial``'s current boot
    itself (``EmulatorService.restart``'s cold boot while the step did not
    prepare it): a later run that finds this boot new records no second
    one (it still re-prepares the device). Blocks for one adb call.
    """
    with _LOCK:
        state = _STATES.get(serial)
        if state is None or state.record is None:
            return  # a first run records no world change anyway
    try:
        from sandroid.core.adb import Adb

        with Adb.targeting(serial):
            token, _uptime, boot_start, _at = _read_boot(serial)
    except Exception:
        logger.debug("device prep: reading the boot failed", exc_info=True)
        return
    if token is None:
        return
    with _LOCK:
        state.world_token = token
        state.world_boot_start = boot_start
        state.world_launch_at = _launch_started_at(serial)


def is_preparing(serial: str | None = None) -> bool:
    """A run for ``serial`` (None: any serial) is in flight or queued."""
    with _LOCK:
        if serial is None:
            return any(state.running for state in _STATES.values())
        state = _STATES.get(serial)
        return bool(state and state.running)


def preparing_stage() -> tuple[str, str] | None:
    """``(serial, stage)`` of a run in flight, for the status bar."""
    with _LOCK:
        for serial, state in _STATES.items():
            if state.running:
                return serial, state.stage or "queued"
    return None


def prepared_transport(serial: str) -> str | None:
    """The adb transport id the last run recorded (None: never prepared;
    ``""``: unknown).
    """
    with _LOCK:
        state = _STATES.get(serial)
        if state is None or state.record is None:
            return None
        return state.record.transport_id


def last_result(serial: str) -> PrepResult | None:
    """The result of the last finished run for ``serial``."""
    with _LOCK:
        state = _STATES.get(serial)
        return state.result if state else None


def wait_prepared(serial: str | None = None, timeout: float = GATE_TIMEOUT_S) -> bool:
    """Wait until no run for ``serial`` (default: the active one) is pending.

    Returns at once when nothing is pending, inside a prepare run or one of
    its hooks (no self-deadlock), and on the UI thread (never blocks it;
    then False while a run is pending).

    Returns:
        True when the device is idle (prepared, or never asked for);
        False on a timeout.
    """
    serial = serial or _active_serial()
    if not serial:
        return True
    with _LOCK:
        if threading.get_ident() in _PREP_THREADS:
            return True
        state = _STATES.get(serial)
        if state is None or not state.running:
            return True
    if _on_ui_thread():
        return False
    deadline = time.monotonic() + max(0.0, timeout)
    with _IDLE:
        while state.running and _STATES.get(serial) is state:
            # A blocking stage (identity) may take longer than the gate:
            # wait until its own budget ran out.
            until = max(deadline, state.stage_deadline or 0.0)
            remaining = until - time.monotonic()
            if remaining <= 0:
                return False
            _IDLE.wait(min(remaining, 1.0))
    return True


def gate(what: str, timeout: float = GATE_TIMEOUT_S) -> bool:
    """Backstop before Frida / app work: wait for the active device's run.

    Off the UI thread only (there it never blocks). On a timeout it warns
    and lets the caller continue.

    Returns:
        False when it timed out.
    """
    if not _ENABLED or _on_ui_thread():
        return True
    serial = _active_serial()
    if not serial or not is_preparing(serial):
        return True
    logger.info(f"{what}: waiting for device {serial} to be prepared")
    if wait_prepared(serial, timeout):
        return True
    logger.warning(
        f"{what}: device {serial} is still being prepared after {timeout:g} s; "
        "continuing"
    )
    return False


def ensure_prepared(
    serial: str | None = None,
    timeout: float = ENSURE_TIMEOUT_S,
    on_progress: Callable[[str], None] | None = None,
) -> PrepResult:
    """Prepare ``serial`` now: join a run in flight, or start one, and wait.

    Refused on the UI thread. Used by the startup check and headless
    ``initialize_core(prepare=True)``.

    Args:
        serial: The device (default: the active one).
        timeout: Seconds to wait.
        on_progress: Called with each stage name (on the worker thread).

    Returns:
        The run's result (``kind`` says what happened).
    """
    serial = serial or _active_serial() or ""
    if _on_ui_thread():
        logger.warning("ensure_prepared refused on the UI thread")
        return PrepResult(serial, "refused")
    if not _ENABLED:
        return PrepResult(serial, "disabled")
    with _LOCK:
        state = _state(serial) if serial else None
        if state is not None and state.held:
            return PrepResult(serial, "held")
        if state is not None and on_progress is not None:
            state.progress.append(on_progress)
        joined = bool(state and state.running)
    try:
        if not joined and not request_prepare(serial, "ensure"):
            return PrepResult(serial, "ignored")
        if not wait_prepared(serial, timeout):
            return PrepResult(serial, "timeout")
        with _LOCK:
            result = state.result if state is not None else None
        return result or PrepResult(serial, "aborted")
    finally:
        if state is not None and on_progress is not None:
            with _LOCK, contextlib.suppress(ValueError):
                state.progress.remove(on_progress)


@contextlib.contextmanager
def hold(serial: str | None, cause: str = "snapshot-load") -> Iterator[None]:
    """No prepare runs for ``serial`` inside the block (a snapshot load).

    A run in flight aborts; requests are dropped. On exit the restored boot
    is recorded, so the poll's re-attach afterwards finds it ``unchanged``
    (no second preparation, no hooks: the snapshot load restores what it
    needs itself). When a request was dropped, ``on_device_prepared``
    listeners fire once (Frida / app work, as a re-attach did before).
    No-op while the step is off.
    """
    if serial is None:
        try:
            from sandroid.core.adb import Adb

            serial = Adb.get_target_device()
        except Exception:
            serial = None
    if not _ENABLED or not serial:
        yield
        return
    with _LOCK:
        state = _state(serial)
        state.held += 1
        state.gen += 1
        state.stage_deadline = None
        if state.held == 1:
            state.held_dropped = False
        _IDLE.notify_all()
    logger.debug(f"device prep: {serial} held ({cause})")
    try:
        yield
    finally:
        with _LOCK:
            state.held -= 1
            last = state.held == 0
            dropped = last and state.held_dropped
            known = state.record is not None
        if last and _ENABLED:
            if known:
                _record_after_hold(serial, state, dropped, cause)
            elif dropped:
                # Never prepared: nothing to record, but the re-attach the
                # hold dropped still reaches the listeners (Frida / app).
                manager = state.manager or _peek_manager()
                if _active_serial(manager) == serial:
                    held = PrepResult(serial, "held", reason=cause)
                    _deliver(state, manager, serial, held)


def _record_after_hold(serial: str, state: _Serial, dropped: bool, cause: str) -> None:
    """Record the boot a snapshot load restored; fire listeners if asked."""
    from sandroid.core.adb import Adb

    try:
        with Adb.targeting(serial):
            token, uptime, boot_start, read_at = _read_boot(serial)
            transport, _ready = _read_transport(serial)
    except Exception:
        logger.debug("device prep: recording after a hold failed", exc_info=True)
        return
    with _LOCK:
        old = state.record
        if old is None:
            return
        state.record = _Record(
            token,
            uptime,
            transport,
            old.root,
            old.root_check,
            old.selinux_check,
            boot_start=boot_start,
            recorded_at=read_at,
            launch_id=_launch_id(serial),
        )
        if token:
            # The load recorded its own world change ("snapshot-load").
            state.world_token = token
            state.world_boot_start = boot_start
            state.world_launch_at = _launch_started_at(serial)
        manager = state.manager or _peek_manager()
    if dropped and _active_serial(manager) == serial:
        _deliver(state, manager, serial, PrepResult(serial, "held", reason=cause))


# ------------------------------------------------------------------ worker


def _worker(serial: str) -> None:
    """Thread body: run until no request is pending, then go idle."""
    from sandroid.core.adb import Adb

    ident = threading.get_ident()
    with _LOCK:
        state = _STATES.get(serial)
        if state is None:
            return
        _PREP_THREADS.add(ident)
    idle = False
    try:
        while not idle:
            with _LOCK:
                if _STATES.get(serial) is not state or not state.running:
                    idle = True
                    break
                reason = state.pending or "attach"
                state.pending = None
                gen = state.pending_gen
                manager = state.manager
            t0 = time.monotonic()
            try:
                with Adb.targeting(serial):
                    result = _run(serial, state, reason, gen, manager)
            except (Exception, SystemExit) as e:
                logger.debug(f"Preparing {serial} raised", exc_info=True)
                if _alive(serial, state, gen, manager):
                    result = PrepResult(serial, "failed", reason=reason, error=str(e))
                    _finish(serial, state, manager, result, t0)
                else:
                    result = PrepResult(serial, "aborted", reason=reason)
            if not result.duration_s:
                result.duration_s = time.monotonic() - t0
            with _LOCK:
                state.result = result
                transport_only = state.pending == "transport"
            if transport_only and _transport_absorbed(serial, state):
                with _LOCK:
                    if state.pending == "transport":
                        state.pending = None
            with _LOCK:
                if state.pending is None:
                    state.running = False
                    state.stage = ""
                    idle = True
                    _IDLE.notify_all()
    finally:
        with _LOCK:
            _PREP_THREADS.discard(ident)
            if not idle:
                # Unexpected exit: never leave waiters hanging.
                state.running = False
                state.stage = ""
            _IDLE.notify_all()


def _transport_absorbed(serial: str, state: _Serial) -> bool:
    """A transport request that came in during a run is our own ``adb
    root`` (adbd restart) when the transport now matches the record.
    """
    try:
        transport, ready = _read_transport(serial)
    except Exception:
        return False
    with _LOCK:
        record = state.record
    return bool(ready and record is not None and transport == record.transport_id)


def _stage(state: _Serial, name: str) -> None:
    with _LOCK:
        state.stage = name
        callbacks = list(state.progress)
    for callback in callbacks:
        try:
            callback(name)
        except Exception:
            logger.debug("device prep progress callback failed", exc_info=True)


def _run(
    serial: str, state: _Serial, reason: str, gen: int, manager: Any
) -> PrepResult:
    """One prepare run (worker thread, adb pinned to ``serial``)."""
    t0 = time.monotonic()

    def alive() -> bool:
        return _alive(serial, state, gen, manager)

    def aborted() -> PrepResult:
        logger.info(f"Preparing {serial} aborted (device lost or switched)")
        return PrepResult(serial, "aborted", reason=reason)

    _stage(state, "waiting for the device")
    if not _settle(serial, lambda: not alive()):
        if not alive():
            return aborted()
        result = PrepResult(
            serial, "failed", reason=reason, error="device did not become ready"
        )
        _finish(serial, state, manager, result, t0)
        return result
    if not alive():
        return aborted()

    _stage(state, "checking the boot")
    token, uptime, boot_start, read_at = _read_boot(serial)
    transport, _ready = _read_transport(serial)
    launch_at = _launch_started_at(serial)
    launch_id = _launch_id(serial)
    with _LOCK:
        record = state.record
    kind = _classify(record, token, uptime, transport, boot_start, launch_at, launch_id)
    if kind == "unchanged" and record is not None:
        if not alive():
            return aborted()
        with _LOCK:
            if uptime is not None:
                # Same boot: keep the rewind checks against a current read.
                record.uptime = uptime
                record.boot_start = boot_start
            record.recorded_at = read_at
            deliver = not state.delivered
        result = PrepResult(
            serial,
            "unchanged",
            reason=reason,
            boot_token=token,
            root=record.root,
            root_check=record.root_check,
            selinux_check=record.selinux_check,
            launch_id=launch_id,
        )
        _finish(serial, state, manager, result, t0, deliver=deliver)
        return result
    fresh_boot = kind != "reattach"
    if kind == "reattach":
        wait = state.last_reattach + REATTACH_MIN_INTERVAL_S - time.monotonic()
        if wait > 0 and _sleep_unless(lambda: not alive(), wait):
            return aborted()
    if kind == "new-world":
        same_boot_id = record is not None and token == record.token
        _world_change(
            serial,
            state,
            token,
            boot_start,
            reason,
            launch_at,
            same_boot_id,
            launch_id,
        )
    _note_boot(serial, token, uptime)
    if not alive():
        return aborted()

    _stage(state, "device clock")
    with _LOCK:
        skip_connect = kind == "first" and state.connect_started
        state.connect_started = False
    if skip_connect:
        # Sampled when the step was off: let it finish before adb root.
        _join_connect_sample(CONNECT_JOIN_S)
    else:
        _clock_connect(serial)
    if not alive():
        return aborted()

    _stage(state, "root")
    root, root_check = _root_step(serial, manager)
    if not alive():
        return aborted()
    _stage(state, "SELinux")
    selinux_check = _selinux_step(serial)
    if not alive():
        return aborted()
    # The transport after adb root's adbd restart, BEFORE the hooks: a
    # reset during the hooks (after the proxy re-added ``adb reverse``) is
    # then a real one and causes exactly one more run.
    transport, _ready = _read_transport(serial)

    notes = _run_stages(serial, state, fresh_boot, alive)
    if not alive():
        return aborted()

    _stage(state, "hooks")
    total, errors = _run_hooks(serial, fresh_boot)
    if not alive():
        return aborted()

    _stage(state, "finishing")
    with _LOCK:
        state.record = _Record(
            token,
            uptime,
            transport,
            root,
            root_check,
            selinux_check,
            boot_start=boot_start,
            recorded_at=read_at,
            launch_id=launch_id,
        )
        if kind == "reattach":
            state.last_reattach = time.monotonic()
    result = PrepResult(
        serial,
        kind,
        reason=reason,
        fresh_boot=fresh_boot,
        boot_token=token,
        root=root,
        root_check=root_check,
        selinux_check=selinux_check,
        hooks_total=total,
        hook_errors=errors,
        stage_notes=notes,
        launch_id=launch_id,
    )
    _finish(serial, state, manager, result, t0)
    return result


def _alive(serial: str, state: _Serial, gen: int, manager: Any) -> bool:
    """The run may go on: step on, no detach / hold since, still active."""
    return _ENABLED and state.gen == gen and _active_serial(manager) == serial


def _finish(
    serial: str,
    state: _Serial,
    manager: Any,
    result: PrepResult,
    t0: float,
    *,
    deliver: bool = True,
) -> None:
    """Store, log and (``deliver``) hand ``result`` to the listeners."""
    result.duration_s = time.monotonic() - t0
    with _LOCK:
        state.result = result
    if result.ran or result.kind == "failed":
        log = logger.warning if result.has_problems else logger.info
        log(result.summary())
        for error in result.hook_errors:
            logger.warning(f"device_prepared hook failed on {serial}: {error}")
    if deliver:
        _deliver(state, manager, serial, result)


def _deliver(state: _Serial, manager: Any, serial: str, result: PrepResult) -> None:
    """Fire the listeners; remember whether they now saw a prepared state
    (a ``failed`` run's listeners see the next ``unchanged`` run again).
    """
    with _LOCK:
        state.delivered = result.prepared or result.kind == "held"
    _fire_listeners(manager, serial, result)


def _fire_listeners(manager: Any, serial: str, result: PrepResult) -> None:
    fire = getattr(manager, "_fire_device_prepared", None)
    if not callable(fire):
        return
    device = None
    try:
        device = manager.get_device(serial)
    except Exception:
        device = None
    if device is None:
        device = getattr(manager, "active_device", None)
    try:
        fire(device, result)
    except Exception:
        logger.debug("device prep: listeners failed", exc_info=True)


def _classify(
    record: _Record | None,
    token: str | None,
    uptime: float | None,
    transport: str,
    boot_start: float | None = None,
    launch_at: float | None = None,
    launch_id: str | None = None,
) -> str:
    """``first`` / ``new-world`` / ``reattach`` / ``unchanged``.

    A new world when ANY of: the boot token changed (a reboot); another
    Sandroid launch of this serial than the recorded one (``launch_id``),
    or one after the record was read (a restart from the Devices screen /
    AI: definitive); the uptime went back; or the boot
    start moved later than :data:`BOOT_START_TOLERANCE_S` -- the uptime
    is behind ``recorded uptime + host time since``, as after a quickboot
    from a snapshot, which keeps the boot_id and the snapshot's uptime.
    """
    if record is None or token is None:
        return "first"  # new, or the boot cannot be told: fresh, no barrier
    if record.token is not None and token != record.token:
        return "new-world"
    if launch_id is not None and launch_id != record.launch_id:
        return "new-world"
    if launch_at is not None and launch_at > record.recorded_at:
        return "new-world"
    if (
        uptime is not None
        and record.uptime is not None
        and uptime + UPTIME_REWIND_S < record.uptime
    ):
        return "new-world"
    if _boot_start_moved(record.boot_start, boot_start):
        return "new-world"
    if transport and transport == record.transport_id and _record_ok(record):
        return "unchanged"
    # A new transport -- or root / SELinux failed last time: try again.
    return "reattach"


def _record_ok(record: _Record) -> bool:
    """The recorded root and SELinux steps did not fail."""
    selinux = record.selinux_check
    selinux_bad = selinux is not None and not getattr(selinux, "passed", True)
    return record.root != "failed" and not selinux_bad


def _host_now() -> float:
    """Host monotonic time (one place, so tests can move the host clock)."""
    return time.monotonic()


def _boot_start_moved(old: float | None, new: float | None) -> bool:
    """The boot start moved later than the tolerance (see
    :data:`BOOT_START_TOLERANCE_S`; earlier never counts).
    """
    if old is None or new is None:
        return False
    return new - old > BOOT_START_TOLERANCE_S


def _launch_started_at(serial: str) -> float | None:
    """``started_at`` (host monotonic) of Sandroid's launch of ``serial``."""
    try:
        from sandroid.core import emulator

        launch = emulator.get_launch(serial)
    except Exception:
        return None
    started = getattr(launch, "started_at", None) if launch is not None else None
    return float(started) if isinstance(started, (int, float)) else None


def _launch_id(serial: str) -> str | None:
    """``launch_id`` of Sandroid's launch of ``serial`` (None: not ours)."""
    try:
        from sandroid.core import emulator

        launch = emulator.get_launch(serial)
    except Exception:
        return None
    if launch is None or not getattr(launch, "alive", True):
        return None  # an exited launch: another emulator may use the port
    value = getattr(launch, "launch_id", None)
    return value if isinstance(value, str) else None


def _note_boot(serial: str, token: str | None, uptime: float | None) -> None:
    """Keep the boot id + uptime in Sandroid's launch record (first wins)."""
    try:
        from sandroid.core import emulator

        emulator.note_boot(serial, token, uptime)
    except Exception:
        logger.debug("device prep: launch record boot failed", exc_info=True)


def _world_change(
    serial: str,
    state: _Serial,
    token: str | None,
    boot_start: float | None,
    reason: str,
    launch_at: float | None = None,
    same_boot_id: bool = False,
    launch_id: str | None = None,
) -> None:
    """The device rebooted: a new world on the session timeline (it starts
    a new device-clock epoch), once per world -- by the same rules as
    :func:`_classify`: the boot (token), its start time (a quickboot from a
    snapshot keeps the boot_id) and Sandroid's launch of the serial.

    Written before the step's device-connect clock sample, so the
    timeline's inferred "device clock went back" world change is
    suppressed for it (exactly one world change per restart).
    """
    with _LOCK:
        if token is not None and state.world_token == token:
            old = state.world_boot_start
            new_launch = launch_at is not None and (
                state.world_launch_at is None or launch_at > state.world_launch_at
            )
            if not new_launch and (
                boot_start is None
                or old is None
                or not _boot_start_moved(old, boot_start)
            ):
                return
        state.world_token = token
        state.world_boot_start = boot_start
        state.world_launch_at = launch_at
    _identity_new_world(serial)
    summary = (
        f"{serial} restarted from a snapshot" if same_boot_id else f"{serial} rebooted"
    )
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().on_world_change(
            "reboot",
            src="device",
            kind="boot",
            summary=summary,
            dev=serial,
            data={
                "boot_id": token,
                "trigger": reason,
                "same_boot_id": same_boot_id,
                "sandroid_launch": launch_at is not None,
                "launch_id": launch_id,
            },
        )
    except Exception:
        logger.debug("device prep: world change failed", exc_info=True)
        try:
            from sandroid.core import device_clock

            device_clock.begin_epoch(serial)
        except Exception:
            logger.debug("device prep: begin_epoch failed", exc_info=True)


# ------------------------------------------------------------------- steps


def _sleep_unless(cancel: Callable[[], bool], seconds: float) -> bool:
    """Sleep ``seconds``; True (early) when ``cancel()`` turns true."""
    deadline = time.monotonic() + seconds
    while True:
        if cancel():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.2, remaining))


def _settle(serial: str, cancel: Callable[[], bool]) -> bool:
    """Step 0: ``device`` + booted, and still so ~1 s later (cap 300 s)."""
    from sandroid.core import emulator

    deadline = time.monotonic() + SETTLE_TIMEOUT_S
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or cancel():
            return False
        if not emulator.wait_until_ready(
            serial, timeout=remaining, cancel=cancel, interval=1.0
        ):
            return False
        if _sleep_unless(cancel, SETTLE_STABLE_S):
            return False
        if emulator.boot_state(serial) == "ready":
            return True


def _adb() -> Any:
    from sandroid.core.adb import Adb

    return Adb


def _read_boot_info(serial: str) -> tuple[str | None, float | None]:
    """Step 1: (token, uptime) -- token = boot_id, else ``fb:<firstboot>``."""
    try:
        stdout, _stderr = _adb().send_adb_command(BOOT_INFO_COMMAND, serial=serial)
    except Exception:
        return None, None
    boot_id = firstboot = None
    uptime = None
    for raw in str(stdout or "").splitlines():
        line = raw.strip()
        if boot_id is None and _BOOT_ID.match(line.lower()):
            boot_id = line.lower()
        elif firstboot is None and _FIRSTBOOT.match(line):
            firstboot = line
        elif uptime is None and (match := _UPTIME.match(line)):
            uptime = float(match.group(1))
    token = boot_id or (f"fb:{firstboot}" if firstboot else None)
    return token, uptime


def _read_boot(serial: str) -> tuple[str | None, float | None, float | None, float]:
    """(token, uptime, boot start, read time): :func:`_read_boot_info`,
    with the boot start taken at the middle of the adb call.
    """
    before = _host_now()
    token, uptime = _read_boot_info(serial)
    after = _host_now()
    boot_start = None if uptime is None else (before + after) / 2 - uptime
    return token, uptime, boot_start, after


def _read_transport(serial: str) -> tuple[str, bool]:
    """(transport id or "", listed as ``device``) from ``adb devices -l``."""
    from sandroid.core.device import parse_adb_devices

    stdout, _stderr = _adb().send_adb_command("devices -l")
    for entry in parse_adb_devices(stdout or ""):
        if entry.serial == serial:
            return entry.props.get("transport_id", ""), entry.state == "device"
    return "", False


def _join_connect_sample(timeout: float) -> None:
    """Wait (bounded) for a running ``after_device_connect_async`` sample:
    startup selected the device while the step was off.
    """
    deadline = time.monotonic() + timeout
    for thread in threading.enumerate():
        if thread.name == _CLOCK_CONNECT_THREAD and thread.is_alive():
            thread.join(max(0.0, deadline - time.monotonic()))


def _clock_connect(serial: str) -> None:
    """Step 2: the device-connect clock sample (synchronous)."""
    try:
        from sandroid.core import device_clock

        device_clock.after_device_connect(serial)
    except Exception:
        logger.debug("device prep: clock connect failed", exc_info=True)


def _root_step(serial: str, manager: Any) -> tuple[str, Any]:
    """Step 3a: ``adb root`` by the probed root kind.

    ``su`` devices skip ``adb root`` (it cannot work there); devices
    without root are warned about once per serial.

    Returns:
        (``ok``/``failed``/``su``/``none``, the SetupCheckResult or None)
    """
    device = None
    try:
        device = manager.get_device(serial) if manager is not None else None
    except Exception:
        device = None
    kind = getattr(device, "root_kind", "") or ""
    if kind == "su":
        return "su", None
    if kind == "none":
        with _LOCK:
            first = serial not in _WARNED_NO_ROOT
            _WARNED_NO_ROOT.add(serial)
        if first:
            logger.warning(
                f"{serial} has no root: adb root and SELinux Permissive are "
                "skipped; operations that need root (APK install, Frida) may fail"
            )
        return "none", None
    from sandroid.services.setup_checks import check_and_enable_root

    check = check_and_enable_root(_adb())
    return ("ok" if check.passed else "failed"), check


def _selinux_step(serial: str) -> Any:
    """Step 3b: ``setenforce 0``, then the waiting clock sync (bounded)."""
    from sandroid.services.setup_checks import check_and_set_selinux

    check = check_and_set_selinux(_adb(), notify_clock=False)
    try:
        from sandroid.core import device_clock

        device_clock.after_selinux_step(serial, wait=CLOCK_SYNC_WAIT_S)
    except Exception:
        logger.debug("device prep: clock sync after SELinux failed", exc_info=True)
    return check


def _hook_name(hook: Any) -> str:
    return getattr(hook, "__qualname__", None) or repr(hook)


def _run_hooks(serial: str, fresh_boot: bool) -> tuple[int, list[str]]:
    """Step 4: each hook in its own thread (adb pinned), bounded."""
    from sandroid.core.adb import Adb

    with _HOOKS_LOCK:
        hooks = list(_HOOKS)
    errors: list[str] = []
    for hook in hooks:
        name = _hook_name(hook)
        box: dict[str, str] = {}

        def target(hook: DevicePreparedHook = hook, box: dict = box) -> None:
            ident = threading.get_ident()
            with _LOCK:
                _PREP_THREADS.add(ident)
            try:
                with Adb.targeting(serial):
                    hook(serial, fresh_boot)
            except (Exception, SystemExit) as e:
                box["error"] = f"{_hook_name(hook)}: {e!r}"
                logger.debug("device_prepared hook raised", exc_info=True)
            finally:
                with _LOCK:
                    _PREP_THREADS.discard(ident)

        thread = threading.Thread(
            target=target, name=f"device-prep-hook-{serial}", daemon=True
        )
        thread.start()
        thread.join(HOOK_TIMEOUT_S)
        if thread.is_alive():
            errors.append(f"{name}: still running after {HOOK_TIMEOUT_S:g} s")
        elif "error" in box:
            errors.append(box["error"])
    return len(hooks), errors


def _identity_new_world(serial: str) -> None:
    """A new world (once per world): the identity service reads the device
    again and allows a new SIM read (as after a snapshot load).
    """
    try:
        from sandroid.services.identity import get_identity_service

        service = get_identity_service()
        service.forget(serial, restored=True)
        service.sim_launch_changed(serial)
    except Exception:
        logger.debug("device prep: identity reset failed", exc_info=True)


def _as_note(value: Any) -> StageNote | None:
    if value is None:
        return None
    if isinstance(value, StageNote):
        return value
    return StageNote("info", str(value))


def _run_stages(
    serial: str, state: _Serial, fresh_boot: bool, alive: Callable[[], bool]
) -> list[tuple[str, str, str]]:
    """Step 4: the blocking stages, in order (see :func:`register_prepare_stage`)."""
    from sandroid.core.adb import Adb

    with _HOOKS_LOCK:
        stages = list(_STAGES)
    notes: list[tuple[str, str, str]] = []
    for spec in stages:
        if not alive():
            break
        _stage(state, spec.name)
        box: dict[str, Any] = {}

        def target(spec: _StageSpec = spec, box: dict = box) -> None:
            ident = threading.get_ident()
            with _LOCK:
                _PREP_THREADS.add(ident)
            try:
                with Adb.targeting(serial):
                    box["value"] = spec.fn(serial, fresh_boot, spec.budget_s)
            except (Exception, SystemExit) as e:
                box["error"] = str(e) or type(e).__name__
                logger.debug(f"prepare stage {spec.name} raised", exc_info=True)
            finally:
                with _LOCK:
                    _PREP_THREADS.discard(ident)

        limit = spec.budget_s + spec.overrun_s + STAGE_GRACE_S
        end = time.monotonic() + limit
        with _LOCK:
            state.stage_deadline = end
        thread = threading.Thread(
            target=target, name=f"device-prep-{spec.name}-{serial}", daemon=True
        )
        thread.start()
        # In slices: a detach / hold / switch ends the wait (the run aborts;
        # the stage thread finishes on its own).
        while thread.is_alive() and alive():
            left = end - time.monotonic()
            if left <= 0:
                break
            thread.join(min(left, 0.5))
        with _LOCK:
            if state.stage_deadline == end:
                state.stage_deadline = None
        if not alive():
            break
        if thread.is_alive():
            note = StageNote("warning", f"still running after {limit:g} s")
        elif "error" in box:
            note = StageNote("warning", f"failed: {box['error']}")
        else:
            note = _as_note(box.get("value"))
        if note is not None:
            notes.append((spec.name, note.level, note.text))
            _stage_line(serial, spec.name, note)
    return notes


def _stage_line(serial: str, name: str, note: StageNote) -> None:
    """A timeline line for what a stage reported (never raises)."""
    if note.level == "warning":
        logger.warning(f"Preparing {serial}: {name}: {note.text}")
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().emit(
            "device",
            "prep_stage",
            summary=f"{name}: {note.text}",
            data={"stage": name, "level": note.level, "text": note.text},
            dev=serial,
            level="warn" if note.level == "warning" else "info",
        )
    except Exception:
        logger.debug("timeline: prepare stage line failed", exc_info=True)


def _identity_stage(serial: str, fresh_boot: bool, budget_s: float) -> Any:
    """The identity profile (``IdentityService.ensure_applied``).

    Nothing when identity mode is off. Under the restart policy ``ask`` /
    ``never`` framework values wait for the first app start (info, not a
    warning); a value that failed or did not fit the budget is a warning.
    """
    from sandroid.services import identity

    plan = identity.get_identity_service().ensure_applied(serial, budget_s=budget_s)
    if plan is None:
        return None
    # Pending for an expected reason is information; only failed values
    # and ones the budget cut off are a warning.
    later = {
        identity.NEEDS_RESTART: "wait for a restart (asked at app start)",
        identity.NEEDS_EMULATOR_START: "set when the emulator starts",
        "no target app yet": "per app, set at app start",
        "not installed": "per app, set at app start",
    }
    done = 0
    info_parts: dict[str, int] = {}
    warn_parts: dict[str, int] = {}
    for info in getattr(plan, "infos", {}).values():
        status = getattr(info, "status", "")
        reason = getattr(info, "reason", "") or ""
        if status in ("applied", "verified"):
            done += 1
        elif status in ("skipped", "hook-only"):
            continue
        elif status == "pending" and reason in later:
            info_parts[later[reason]] = info_parts.get(later[reason], 0) + 1
        elif status == "pending" and reason != identity.OUT_OF_TIME:
            key = f"pending ({reason})" if reason else "pending"
            info_parts[key] = info_parts.get(key, 0) + 1
        else:
            key = "not done in time" if reason == identity.OUT_OF_TIME else status
            warn_parts[key] = warn_parts.get(key, 0) + 1
    parts = [f"{done} set"]
    parts += [f"{n} {text}" for text, n in info_parts.items()]
    parts += [f"{n} {text}" for text, n in warn_parts.items()]
    return StageNote("warning" if warn_parts else "info", ", ".join(parts))


def _persona_stage(serial: str, fresh_boot: bool, budget_s: float) -> Any:
    """A persona launch (``meta.persona_id``): :func:`sandroid.world.persona.persona_stage`.

    Other launches never import :mod:`sandroid.world`.
    """
    from sandroid.core.emulator import launch_record

    meta = (launch_record(serial) or {}).get("meta") or {}
    if not (isinstance(meta, dict) and meta.get("persona_id")):
        return None
    from sandroid.world import persona

    return persona.persona_stage(serial, fresh_boot, budget_s)


#: The persona stage runs before the identity stage (it bakes the identity
#: into the persona snapshot). Its budget covers prepare (15-20 s for a medium
#: world), the identity apply (a framework restart) and the save (about 9 s).
PERSONA_STAGE_ORDER = 10

register_prepare_stage(
    "persona",
    _persona_stage,
    order=PERSONA_STAGE_ORDER,
    budget_s=300.0,
    overrun_s=120.0,
)

register_prepare_stage(
    "identity",
    _identity_stage,
    order=IDENTITY_STAGE_ORDER,
    budget_s=IDENTITY_BUDGET_S,
    overrun_s=IDENTITY_OVERRUN_S,
)


__all__ = [
    "ENSURE_TIMEOUT_S",
    "GATE_TIMEOUT_S",
    "HOOK_TIMEOUT_S",
    "IDENTITY_BUDGET_S",
    "IDENTITY_OVERRUN_S",
    "IDENTITY_STAGE_ORDER",
    "LOSS_GRACE_S",
    "STAGE_GRACE_S",
    "DevicePreparedHook",
    "PrepResult",
    "PrepStage",
    "StageNote",
    "connect_clock_only",
    "ensure_prepared",
    "gate",
    "hold",
    "is_enabled",
    "is_preparing",
    "last_result",
    "note_adb_server_restart",
    "note_detached",
    "note_world_recorded",
    "prepared_transport",
    "preparing_stage",
    "register_device_prepared_hook",
    "register_prepare_stage",
    "request_prepare",
    "reset",
    "set_enabled",
    "unregister_device_prepared_hook",
    "unregister_prepare_stage",
    "wait_prepared",
]
