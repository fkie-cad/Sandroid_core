"""One restore entry point for Sandroid's proxy infrastructure.

After anything that replaced or reconnected the device's state (a snapshot
load, a cold boot or emulator restart, an adb reconnect) the device may lack
what the user set up: the device proxy and its ``adb reverse``, the App Proxy
lanes (gost + per-UID rules) and the system CA. :func:`restore_proxy_infra`
puts them back in a fixed order:

1. device proxy (+ ``adb reverse``), when Sandroid owns it on that serial;
   when it has to be set again, the Kill switch and the app naming
   (``core.device_guard``) go in first (``MitmproxyService.
   reapply_device_proxy``), so a restored proxy never runs open;
2. the device guard, checked against the device: the Kill switch follows the
   real device proxy, and a Kill switch whose proxy is gone is removed (it
   would take every app offline); a leftover from a snapshot too;
3. App Proxy lanes (reconciled against device truth): a missing lane is a
   silent bypass past mitmproxy, so it comes before the CA;
4. the CA, only when the user injected it on that serial in this session,
   and only through the no-restart path (never a Zygote restart here).

It never raises and costs no adb call when nothing is set up for the serial.
The user-confirmed Zygote-restart fallback for the CA lives here too
(:func:`restart_framework_for_ca`); it is TUI-only, never automatic and never
reachable from an AI tool.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Owner id of the TUI's WORLD lease while the CA fallback restarts Zygote.
FALLBACK_LEASE_OWNER = "tui:ca-framework-restart"


@dataclass
class RestoreReport:
    """What :func:`restore_proxy_infra` found and did."""

    serial: str | None
    cause: str
    device_proxy: str = "none"
    #: "none" | "kill switch on" | "apps named" ... (see _restore_guard).
    guard: str = "none"
    lanes: list[Any] = field(default_factory=list)
    ca: str = "none"
    skipped: str = ""

    def summary(self) -> str:
        """One log line in plain words."""
        if self.skipped:
            return f"proxy restore after {self.cause} skipped: {self.skipped}"
        parts = []
        if self.device_proxy not in ("none", ""):
            parts.append(f"device proxy {self.device_proxy}")
        if self.guard not in ("none", ""):
            parts.append(self.guard)
        for report in self.lanes:
            text = f"App Proxy {report.package} {report.health.label}"
            if report.repaired:
                text += f" ({', '.join(report.repaired)})"
            parts.append(text)
        if self.ca != "none":
            parts.append(f"CA {self.ca}")
        detail = "; ".join(parts) if parts else "nothing to restore"
        return f"proxy restore after {self.cause}: {detail}"

    @property
    def acted(self) -> bool:
        """Whether anything was set up for this serial at all."""
        return (
            bool(self.lanes)
            or self.device_proxy != "none"
            or self.guard != "none"
            or self.ca != "none"
        )


def _target(serial: str | None) -> str | None:
    if serial:
        return serial
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


def restore_proxy_infra(
    serial: str | None,
    cause: str,
    *,
    device_proxy: bool = True,
    fresh_boot: bool | None = None,
    device_proxy_result: str | None = None,
) -> RestoreReport:
    """Restore device proxy, App Proxy lanes and CA on *serial* (in that order).

    Both cases are one reconcile against device truth (one adb call to read
    the lanes, one for the CA status): after a fresh boot the RAM state is
    gone and everything recorded is rebuilt (gost relaunched, rules re-added,
    CA re-injected without a restart); after a re-attach without a fresh
    boot it is a cheap check that re-adds ``adb reverse`` and repairs a dead
    or doomed gost.

    Args:
        serial: Device; None uses the current adb target.
        cause: ``snapshot-load``, ``cold-boot``, ``reconnect`` or
            ``framework-restart`` (logged, and decides cache resets).
        device_proxy: Also re-apply the device proxy. ``load_snapshot`` has
            already done that one step earlier and passes False.
        fresh_boot: The device booted fresh (boot id changed): forces the
            ``cold-boot`` cause. None keeps *cause* as given.
        device_proxy_result: What the caller's own device-proxy step did
            (with ``device_proxy=False``), for the summary.

    Returns:
        A :class:`RestoreReport`. Never raises; blocking (adb), so call it
        from a worker thread.
    """
    serial = _target(serial)
    if fresh_boot:
        cause = "cold-boot"
    report = RestoreReport(serial=serial, cause=cause)
    if cause == "reconnect" and _snapshot_load_running(serial):
        # The load in flight restores everything itself when it finishes.
        report.skipped = "a snapshot load is restoring it"
        return report
    if device_proxy:
        report.device_proxy = _restore_device_proxy(serial)
    elif device_proxy_result:
        report.device_proxy = device_proxy_result
    report.guard = _restore_guard(serial, cause)
    report.lanes = _restore_lanes(serial, cause)
    report.ca = _restore_ca(serial)
    if report.acted:
        logger.info(report.summary())
        _publish(serial, cause)
    return report


def _anything_desired(serial: str | None) -> bool:
    """Cheap in-process check: is anything set up for *serial*?"""
    try:
        from sandroid.core.device_guard import peek_device_guard

        guard = peek_device_guard()
        if guard is not None and guard.has_state(serial):
            return True
    except Exception:
        pass
    try:
        from sandroid.core import proxy_manager

        if proxy_manager.ca_desired_for(serial) is not None:
            return True
        focus = proxy_manager._FOCUS_INSTANCE
        if focus is not None and focus.has_lanes(serial):
            return True
    except Exception:
        pass
    try:
        from sandroid.services.mitmproxy_service import peek_mitmproxy_service

        service = peek_mitmproxy_service()
        owner = service.owned_device_proxy_serial if service is not None else None
        return bool(service and service.owned_device_proxy) and owner in (
            None,
            serial,
        )
    except Exception:
        return False


def _snapshot_load_running(serial: str | None) -> bool:
    try:
        from sandroid.services.emulator_service import snapshot_load_active

        return snapshot_load_active(serial)
    except Exception:
        return False


def _restore_device_proxy(serial: str | None) -> str:
    try:
        from sandroid.services.mitmproxy_service import peek_mitmproxy_service

        service = peek_mitmproxy_service()
        if service is None:
            return "none"
        return service.reapply_device_proxy(serial)
    except Exception as exc:
        logger.debug("device proxy restore failed: %s", exc)
        return "failed"


def _restore_guard(serial: str | None, cause: str) -> str:
    """Kill switch + app naming against the device; a leftover is removed.

    Also with nothing set up in this session it reads the device (one adb
    call): a snapshot, a crashed session or a quit that timed out can leave
    our chains behind. A Kill switch the user had on comes back on the
    device's proxy (ours or a hand-set external one); one whose proxy is
    gone is removed (it would take every app offline).
    """
    try:
        from sandroid.core.adb import Adb
        from sandroid.core.device_guard import get_device_guard

        guard = get_device_guard()
        before = guard.view_cached(serial)
        with Adb.targeting(serial):
            view = guard.reconcile(serial, cause)
    except Exception as exc:
        logger.warning("Kill switch restore after %s failed: %s", cause, exc)
        return f"Kill switch restore failed: {exc}"
    parts = []
    if view.kill_switch:
        parts.append("Kill switch on")
    elif before.kill_switch:
        parts.append("Kill switch removed (no device proxy)")
    if view.attribution == "on":
        parts.append(f"apps named ({view.named_apps})")
    elif view.attribution == "failed":
        parts.append("apps not named")
    return ", ".join(parts) or "none"


def _restore_lanes(serial: str | None, cause: str) -> list[Any]:
    try:
        from sandroid.core import proxy_manager

        focus = proxy_manager._FOCUS_INSTANCE
        if focus is None or not focus.has_lanes(serial):
            if cause == "snapshot-load":
                # A snapshot saved by an earlier session can bring back its
                # App Proxy rules and gost: remove them (one adb read).
                proxy_manager.get_focus_manager().sweep_orphans(serial, cause)
            return []
        return focus.reconcile(serial, cause)
    except Exception as exc:
        logger.warning("App Proxy restore after %s failed: %s", cause, exc)
        return []


def _restore_ca(serial: str | None) -> str:
    try:
        from sandroid.core.proxy_manager import CAManager, ca_desired_for

        if ca_desired_for(serial) is None:
            return "none"
        result = CAManager().reconcile_ca(serial)
    except Exception as exc:
        return f"failed: {exc}"
    if result.startswith("failed"):
        logger.error("CA re-inject after a world change %s", result)
    return result


def _publish(serial: str | None, cause: str) -> None:
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"change_type": "proxy_infra", "serial": serial, "cause": cause},
                source="proxy_restore",
            )
        )
    except Exception:
        logger.debug("proxy restore publish failed", exc_info=True)


# ---------------------------------------------------------------------------
# Device attach / fresh boot: DeviceManager "device prepared" hook
# ---------------------------------------------------------------------------

_HOOK_LOCK = threading.Lock()
_HOOK_INSTALLED = False


def _device_prepared_hook(serial: str, fresh_boot: bool) -> None:
    """DeviceManager hook: *serial* was attached and prepared (root/SELinux,
    clock), on first attach, a fresh boot or a re-attach (adb reconnect).
    """
    if not _anything_desired(serial):
        # Nothing of this session to restore, but a leftover Kill switch
        # (crash, a quit that timed out) must not outlive its proxy.
        cause = "cold-boot" if fresh_boot else "reconnect"
        result = _restore_guard(serial, cause)
        if result != "none":
            logger.info("Proxy restore after %s on %s: %s", cause, serial, result)
            _publish(serial, cause)
        return
    restore_proxy_infra(
        serial, "cold-boot" if fresh_boot else "reconnect", fresh_boot=fresh_boot
    )


def install_device_prepared_hook() -> bool:
    """Register the restore with DeviceManager's device-prepared hook.

    Idempotent. Called whenever proxy state worth restoring is recorded
    (an App Proxy lane, an injected CA, our device proxy) and at service
    start.

    Returns:
        True when the hook registry exists and the hook is registered.
    """
    global _HOOK_INSTALLED
    with _HOOK_LOCK:
        if _HOOK_INSTALLED:
            return True
        register = _find_device_prepared_registry()
        if register is None:
            return False
        try:
            register(_device_prepared_hook)
        except Exception as exc:
            logger.debug("device-prepared hook registration failed: %s", exc)
            return False
        _HOOK_INSTALLED = True
        return True


def device_prepared_hook_active() -> bool:
    """Whether the device-prepared hook will restore after a fresh boot.

    True only when the hook is registered AND sandroid-startup's device
    preparation is enabled right now (``core.device_prep.is_enabled()``,
    read at call time): with preparation off the hook never fires, so a
    caller has to restore itself.
    """
    if not install_device_prepared_hook():
        return False
    from sandroid.core import device_prep

    try:
        return bool(device_prep.is_enabled())
    except Exception:
        return False


def _find_device_prepared_registry() -> Any:
    """``register_device_prepared_hook`` (``core.device_prep``) or None.

    The hook fires for the active device only, on its own thread with
    ``Adb.targeting(serial)`` set, after root/SELinux and the clock step:
    ``fresh_boot=True`` on the first attach in a process and on a new boot,
    False on a re-attach after an adb transport/server reset. Snapshot loads
    do not fire it (``EmulatorService.load_snapshot`` restores directly).
    """
    try:
        from sandroid.core import device_prep
    except ImportError:
        return None
    register = getattr(device_prep, "register_device_prepared_hook", None)
    return register if callable(register) else None


# ---------------------------------------------------------------------------
# CA fallback: user-confirmed Zygote restart (TUI only)
# ---------------------------------------------------------------------------


@contextmanager
def _lifecycle_guard() -> Iterator[None]:
    """Hold the app-start lifecycle lock (refuse when an app start runs).

    Raises:
        RuntimeError: an app start/restart is in progress.
    """
    from sandroid.services import app_start

    try:
        with app_start.lifecycle_lock(0.0):
            yield
    except app_start.AppStartError as exc:
        raise RuntimeError(str(exc)) from exc


def _system_server_pids(serial: str | None) -> list[str]:
    from sandroid.core.adb import Adb

    try:
        out, _ = Adb.send_adb_command("shell pidof system_server", serial=serial)
    except Exception:
        return []
    return [p for p in (out or "").split() if p.isdigit()]


def _wait_system_server_changed(
    previous: int | None,
    serial: str | None,
    timeout: float,
    *,
    seen: set[str] | None = None,
) -> bool:
    """Local framework gate: a NEW system_server PID, then services answer.

    ``sys.boot_completed`` stays 1 through a Zygote restart and the old
    system_server answers ``service check`` for seconds, so only the PID
    change is a valid first gate. With the old PID unknown, a PID counts as
    new only when it differs from every PID seen so far (``seen`` plus the
    first poll), or when it shows up after a poll found no system_server.
    """
    from sandroid.core.adb import Adb

    old = set(seen or ())
    if previous is not None:
        old.add(str(previous))
    deadline = time.monotonic() + timeout
    changed = False
    first = True
    gone = False
    while time.monotonic() < deadline:
        pids = _system_server_pids(serial)
        if previous is None and first and not old:
            # Nothing known about the old one: whatever runs now may be it.
            old.update(pids)
        first = False
        fresh = [p for p in pids if p not in old]
        if fresh or (pids and gone):
            changed = True
            break
        if not pids:
            gone = True
        time.sleep(1.0)
    if not changed:
        return False
    while time.monotonic() < deadline:
        try:
            out, _ = Adb.send_adb_command(
                "shell 'getprop sys.boot_completed; service check package'",
                serial=serial,
            )
        except Exception:
            out = ""
        text = out or ""
        if text.startswith("1") and ": found" in text:
            return True
        time.sleep(1.0)
    return False


def _recover_after_framework_restart(
    previous_ss_pid: int | None,
    serial: str | None,
    timeout: float = 120.0,
    *,
    seen: set[str] | None = None,
) -> str:
    """Wait for the new framework, then restart frida-server and drop handles.

    Delegates to :func:`app_start.recover_after_framework_restart` (PID gate,
    ``pm path android``, frida-server refresh, every host Frida handle). That
    function treats an unknown previous PID as "no PID gate", but right after
    a Zygote kill the OLD system_server still answers for seconds, so with the
    PID unknown a new one is awaited here first (``seen`` = PIDs before the
    kill).

    Returns:
        A short status for the log / toast.
    """
    from sandroid.services import app_start

    if previous_ss_pid is None and not _wait_system_server_changed(
        None, serial, timeout, seen=seen
    ):
        return f"system_server did not come back within {timeout:.0f} s"
    try:
        app_start.recover_after_framework_restart(
            previous_ss_pid, timeout=timeout, serial=serial
        )
    except Exception as exc:
        return f"framework recovery failed: {exc}"
    return "framework back"


def restart_framework_for_ca(
    cert_path: Path | None,
    serial: str | None = None,
    while_held: Callable[[Any], None] | None = None,
) -> Any:
    """CA fallback: install it WITH a Zygote restart (user-confirmed, TUI only).

    Only when the no-restart path cannot apply. Takes the app-start lifecycle
    lock (refuses while an app start runs) and a WORLD lease so no AI task
    works on the device meanwhile; mounts the CA (init's APEX bind is what
    the new Zygote inherits), kills the Zygote(s) whose parent is init, waits
    for a NEW system_server, restarts frida-server, drops the host Frida
    handles, re-checks the CA in the new Zygote's namespace and re-applies
    the device proxy and the App Proxy lanes. Never call it from an AI tool
    or a post-load path. Blocking: run it on a worker thread.

    Args:
        cert_path: The CA certificate to install.
        serial: Target device; the active device when omitted.
        while_held: Called with the successful result while the lifecycle
            lock and the WORLD lease are still held, for the caller's own
            follow-up device work (Chrome CT bypass, status read) so no AI
            task slips in between. Its exceptions are logged, not raised.

    Returns:
        :class:`~sandroid.core.proxy_manager.InjectionResult`
        (``restarted=True`` when Zygote was restarted).
    """
    from sandroid.core.proxy_manager import CAManager, InjectionResult

    serial = _target(serial)
    ca = CAManager()
    spec = ca.ca_spec(cert_path)
    if spec is None:
        return InjectionResult(success=False, message="No CA certificate to inject")
    try:
        from sandroid.ai.arbiter import Conflict, ResourceId, get_arbiter

        arbiter = get_arbiter()
        claim = arbiter.claim(FALLBACK_LEASE_OWNER, frozenset({ResourceId.WORLD}))
        if isinstance(claim, Conflict):
            return InjectionResult(
                success=False,
                message=(
                    "The AI assistant is using the device; try again when it is "
                    "done (Zygote not restarted)"
                ),
            )
    except Exception:
        arbiter = None
    try:
        with _lifecycle_guard():
            first = ca.inject_spec(spec, serial=serial)
            # Re-checked here, not taken from the caller: only when init's
            # namespace holds the CA does a new Zygote inherit it.
            if first.success or not first.restart_required:
                return first
            seen = set(_system_server_pids(serial))
            previous, killed = ca.kill_zygotes(serial=serial)
            if not killed:
                return InjectionResult(
                    success=False,
                    message=(
                        "No Zygote whose parent is init was found, nothing was "
                        "restarted; the CA is not installed"
                    ),
                )
            if previous is None and len(seen) == 1:
                previous = int(next(iter(seen)))
            note = _recover_after_framework_restart(previous, serial, seen=seen)
            status = ca.check_zygote_injection_status(spec.cert_path, serial=serial)
            if not status.injected:
                # The kill raced the binds: mount into the new Zygote now.
                retry = ca.inject_spec(spec, serial=serial)
                status = ca.check_zygote_injection_status(spec.cert_path, serial=serial)
                if not retry.success and not status.injected:
                    return InjectionResult(
                        success=False,
                        message=f"CA not visible after the Zygote restart ({note})",
                        restarted=True,
                    )
            from sandroid.core.proxy_manager import remember_ca_intent

            remember_ca_intent(serial, spec)
            restore_proxy_infra(serial, "framework-restart")
            _framework_world_change(serial)
            result = InjectionResult(
                success=True,
                message=f"CA installed with a Zygote restart ({note})",
                strategy=first.strategy,
                api_level=first.api_level,
                restarted=True,
                verdict=status.verdict,
            )
            if while_held is not None:
                try:
                    while_held(result)
                except Exception as exc:
                    logger.warning("CA fallback follow-up failed: %s", exc)
            return result
    except RuntimeError as exc:
        return InjectionResult(success=False, message=f"{exc}; Zygote not restarted")
    finally:
        if arbiter is not None:
            try:
                arbiter.release_all(FALLBACK_LEASE_OWNER)
            except Exception:
                pass


def _framework_world_change(serial: str | None) -> None:
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().on_world_change(
            "framework-restart",
            src="device",
            kind="restart",
            summary="Zygote restarted to install the CA",
            dev=serial,
            data={"ok": True},
        )
    except Exception:
        logger.debug("timeline: framework restart failed", exc_info=True)
