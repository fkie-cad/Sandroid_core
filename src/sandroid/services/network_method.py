"""The "Network method": one derived name for how app traffic is captured.

Every piece stays individually settable (device proxy incl. an external
proxy, App Proxy lanes incl. an external upstream, the Kill switch, CA,
bypass categories, friTap, QUIC block, Mitmproxy). This module only puts a
convenience on top:

* :func:`derive_method` -- a PURE function from one live-state
  :class:`MethodSnapshot` to a :class:`MethodView`: the preset name (never
  stored), the app, what is on, notes and problems. Only routing pieces
  (device proxy, Kill switch, App Proxy lanes, friTap) decide the name;
  a missing CA, QUIC, pinning or a stopped Mitmproxy are notes/problems,
  never "Custom".
* :func:`plan_apply` -- a PURE ordered, idempotent plan for a preset
  (fail-closed: Kill switch and app naming before the device proxy points
  at us; the target App Proxy before the device proxy goes). Applying turns
  off only routing pieces Sandroid set; an EXTERNAL proxy (device proxy or
  App Proxy upstream) is replaced only after a confirmation
  (``replace_external``). Off leaves Mitmproxy and the CA alone. Pressing
  the active preset again is the repair.
* :class:`NetworkMethodService` -- gathers the snapshot off the UI thread
  (one adb read), keeps the last view for the UI, re-derives on the state
  events and publishes ``STATE_CHANGED{change_type: "network_method"}``.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

OFF = "off"
WHOLE_DEVICE = "whole_device"
THIS_APP = "this_app"
KEYS_ONLY = "keys_only"
CUSTOM = "custom"

#: Selectable presets, in UI order (Custom is derived only).
PRESETS = (OFF, WHOLE_DEVICE, THIS_APP, KEYS_ONLY)

LABELS = {
    OFF: "Off",
    WHOLE_DEVICE: "Whole device",
    THIS_APP: "This app",
    KEYS_ONLY: "This app, keys only",
    CUSTOM: "Custom",
}

#: Shown while friTap has no non-interactive keys-only start on this build.
KEYS_ONLY_UNAVAILABLE = "needs friTap support"

#: friTap refusal reasons (``StartResult.reason``) in plain words.
FRITAP_REASONS = {
    "not_selected": "pick a spotlight app first",
    "other_device": "the spotlight app is on another device",
    "busy": "another start is running, try again",
    "needs_consent": "needs consent to restart the app",
    "declined": "the restart of the app was declined",
}


# ---------------------------------------------------------------------------
# State model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MethodSnapshot:
    """Everything the method is derived from (one read)."""

    spotlight: str | None = None
    mitm_running: bool = False
    #: "none" | "ours" | "external"
    device_proxy: str = "none"
    device_addr: str = ""
    #: The address our Mitmproxy is reached at from the device.
    our_addr: str = ""
    kill_switch: bool = False
    refused: int = 0
    #: "off" | "on" | "failed" | "external" | "unavailable"
    attribution: str = "off"
    named_apps: int = 0
    #: package -> "ours" | "http://ip:port"
    lanes: dict[str, str] = field(default_factory=dict)
    #: package -> health label, only lanes that pass no traffic.
    lane_problems: dict[str, str] = field(default_factory=dict)
    #: "installed" | "missing" | "unknown"
    ca: str = "unknown"
    #: "on" | "armed" | "off"
    pinning: str = "off"
    fritap: bool = False
    fritap_on_spotlight: bool = False
    quic_block: bool = True
    keys_only_available: bool = False


@dataclass(frozen=True)
class MethodView:
    """The derived method: name, what is on, notes, problems."""

    preset: str
    app: str | None = None
    covered: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return LABELS.get(self.preset, self.preset)

    @property
    def name(self) -> str:
        """``Whole device`` / ``This app (com.x)``."""
        return f"{self.label} ({self.app})" if self.app else self.label

    def line(self) -> str:
        """The status line in plain words."""
        text = f"Network method: {self.name}."
        for part in (self.covered, self.notes, self.problems):
            if part:
                text += " " + _sentence(part)
        return text

    def markup(self, ok: str, warn: str, bad: str, dim: str) -> str:
        """The status line in Rich markup (theme colours, no glyphs)."""
        from rich.markup import escape

        colour = bad if self.problems else (warn if self.preset == CUSTOM else ok)
        text = f"[{dim}]Network method:[/] [{colour}]{escape(self.name)}[/]."
        if self.covered:
            text += " " + escape(_sentence(self.covered))
        if self.notes:
            text += f" [{dim}]{escape(_sentence(self.notes))}[/]"
        if self.problems:
            text += f" [{bad}]{escape(_sentence(self.problems))}[/]"
        return text

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.preset,
            "label": self.label,
            "app": self.app,
            "covered": list(self.covered),
            "notes": list(self.notes),
            "problems": list(self.problems),
            "line": self.line(),
        }


def _sentence(parts: tuple[str, ...]) -> str:
    text = ", ".join(parts)
    return text[:1].upper() + text[1:] + "."


def _pinning_note(s: MethodSnapshot) -> str:
    if s.pinning == "on":
        return "pinning bypassed"
    if s.pinning == "armed":
        return "pinning bypass armed (takes effect when the app starts)"
    return "pinning not bypassed"


def _ca_problem(s: MethodSnapshot) -> list[str]:
    if s.ca == "missing":
        return ["CA not installed: HTTPS cannot be read"]
    return []


def _custom_pieces(s: MethodSnapshot) -> list[str]:
    pieces = []
    if s.device_proxy == "ours":
        pieces.append("device proxy to Mitmproxy")
    elif s.device_proxy == "external":
        pieces.append(
            f"device proxy to external proxy {s.device_addr} (apps not named)"
        )
    if s.kill_switch:
        pieces.append("Kill switch on")
    elif s.device_proxy != "none":
        pieces.append("Kill switch off")
    for pkg, target in sorted(s.lanes.items()):
        if target == "ours":
            pieces.append(f"App Proxy for {pkg}")
        else:
            pieces.append(f"App Proxy for {pkg} to {target}")
    if s.fritap:
        pieces.append("friTap running")
    return pieces


def derive_method(s: MethodSnapshot) -> MethodView:
    """The Network method of a state snapshot (pure; never stored)."""
    spot = s.spotlight
    no_lanes = not s.lanes
    if s.kill_switch and s.device_proxy == "none":
        return MethodView(
            CUSTOM,
            covered=tuple(_custom_pieces(s)),
            problems=("Kill switch without a device proxy: apps have no network",),
        )
    if s.device_proxy == "none" and no_lanes and not s.fritap:
        notes = ["nothing is routed through Mitmproxy"]
        if s.mitm_running:
            notes.append("Mitmproxy running")
        if s.ca == "installed":
            notes.append("CA installed")
        return MethodView(OFF, notes=tuple(notes))
    if s.device_proxy == "ours" and s.kill_switch and no_lanes and not s.fritap:
        covered = ["all apps through Mitmproxy"]
        covered.append(
            f"direct traffic refused ({s.refused})"
            if s.refused
            else "direct traffic refused"
        )
        problems: list[str] = []
        if s.attribution == "on":
            covered.append("apps named")
        elif s.attribution in ("failed", "unavailable"):
            problems.append("apps not named (identity relay not running)")
        if not s.mitm_running:
            problems.insert(
                0, "Mitmproxy stopped: app traffic is blocked until it runs again"
            )
        problems += _ca_problem(s)
        notes = [_pinning_note(s)] if spot else []
        if s.ca == "installed":
            notes.insert(0, "CA installed")
        return MethodView(
            WHOLE_DEVICE,
            covered=tuple(covered),
            notes=tuple(notes),
            problems=tuple(problems),
        )
    if s.device_proxy == "none" and spot and s.lanes == {spot: "ours"} and not s.fritap:
        covered = []
        problems = []
        if spot in s.lane_problems:
            problems.append(f"App Proxy {s.lane_problems[spot]}")
        else:
            covered.append("App Proxy active")
        if not s.mitm_running:
            problems.insert(
                0, "Mitmproxy stopped: the app has no network until it runs"
            )
        problems += _ca_problem(s)
        notes = ["QUIC blocked" if s.quic_block else "QUIC not blocked"]
        if s.ca == "installed":
            notes.append("CA installed")
        notes.append(_pinning_note(s))
        return MethodView(
            THIS_APP,
            app=spot,
            covered=tuple(covered),
            notes=tuple(notes),
            problems=tuple(problems),
        )
    if s.device_proxy == "none" and no_lanes and s.fritap and s.fritap_on_spotlight:
        return MethodView(
            KEYS_ONLY,
            app=spot,
            covered=("friTap writing TLS keys",),
            notes=("no proxy, no rows in this list", _pinning_note(s)),
        )
    return MethodView(CUSTOM, covered=tuple(_custom_pieces(s)))


# ---------------------------------------------------------------------------
# Apply plan (pure)
# ---------------------------------------------------------------------------


@dataclass
class ApplyPlan:
    """Ordered steps for a preset, or why it cannot run / must confirm."""

    steps: list[tuple] = field(default_factory=list)
    #: Non-empty: external pieces would be replaced; nothing runs without
    #: ``replace_external=True`` (the TUI asks, the AI passes the argument).
    confirm: str = ""
    error: str = ""


def _external_pieces(s: MethodSnapshot, keep_device: bool = False) -> list[str]:
    pieces = []
    if s.device_proxy == "external" and not keep_device:
        pieces.append(f"the device proxy points to {s.device_addr}")
    for pkg, target in sorted(s.lanes.items()):
        if target != "ours":
            pieces.append(f"the App Proxy of {pkg} goes to {target}")
    return pieces


def plan_apply(
    preset: str,
    s: MethodSnapshot,
    *,
    defeat_pinning: bool | None = None,
    replace_external: bool = False,
) -> ApplyPlan:
    """The ordered, idempotent steps that make *s* match *preset* (pure).

    Steps: ``("start_mitm",)``, ``("inject_ca",)``,
    ``("prepare_guard", addr)`` (Kill switch + app naming for a proxy about
    to be set), ``("set_device_proxy", addr)``, ``("clear_device_proxy",)``,
    ``("enable_lane", pkg)``, ``("disable_lane", pkg)``, ``("stop_fritap",)``,
    ``("start_fritap_keys", pkg)``, ``("pinning", bool)``.
    """
    if preset not in PRESETS:
        return ApplyPlan(error=f"Unknown Network method {preset!r}")
    spot = s.spotlight
    if preset in (THIS_APP, KEYS_ONLY) and not spot:
        return ApplyPlan(error="Pick a spotlight app first")
    if preset == KEYS_ONLY and not s.keys_only_available:
        return ApplyPlan(error=f"This app, keys only {KEYS_ONLY_UNAVAILABLE}")
    external = _external_pieces(s)
    if external and not replace_external:
        target = LABELS[preset]
        return ApplyPlan(
            confirm=(
                f"{'; '.join(external).capitalize()}. Applying {target} replaces "
                "that. Continue?"
            )
        )
    steps: list[tuple] = []
    pin = (
        [("pinning", defeat_pinning)]
        if defeat_pinning is not None and spot and preset != OFF
        else []
    )
    if preset == WHOLE_DEVICE:
        addr = s.device_addr if s.device_proxy == "ours" else s.our_addr
        if not s.mitm_running:
            steps.append(("start_mitm",))
        if s.ca != "installed":
            steps.append(("inject_ca",))
        steps.append(("prepare_guard", addr))
        if not (s.device_proxy == "ours" and s.device_addr == addr):
            steps.append(("set_device_proxy", addr))
        steps += [("disable_lane", pkg) for pkg in sorted(s.lanes)]
        if s.fritap:
            steps.append(("stop_fritap",))
        steps += pin
    elif preset == THIS_APP:
        if not s.mitm_running:
            steps.append(("start_mitm",))
        if s.ca != "installed":
            steps.append(("inject_ca",))
        if s.lanes.get(spot, "ours") != "ours":
            steps.append(("disable_lane", spot))
        steps.append(("enable_lane", spot))
        steps += [("disable_lane", pkg) for pkg in sorted(s.lanes) if pkg != spot]
        if s.device_proxy != "none":
            steps.append(("clear_device_proxy",))
        if s.fritap:
            steps.append(("stop_fritap",))
        steps += pin
    elif preset == KEYS_ONLY:
        if s.fritap and not s.fritap_on_spotlight:
            steps.append(("stop_fritap",))
        steps.append(("start_fritap_keys", spot))
        if s.device_proxy != "none":
            steps.append(("clear_device_proxy",))
        steps += [("disable_lane", pkg) for pkg in sorted(s.lanes)]
        steps += pin
    else:  # OFF
        if s.device_proxy != "none":
            steps.append(("clear_device_proxy",))
        steps += [("disable_lane", pkg) for pkg in sorted(s.lanes)]
        if s.fritap:
            steps.append(("stop_fritap",))
    return ApplyPlan(steps=steps)


# ---------------------------------------------------------------------------
# Optional APIs of peers (guarded lookups)
# ---------------------------------------------------------------------------


def _fritap_api(name: str) -> Callable[..., Any] | None:
    """``sandroid.analysis.fritap.<name>`` when this build has it.

    TODO(fritap-keys-only): app-lens adds ``start_fritap_keys`` /
    ``stop_fritap`` / ``fritap_running``; until then "This app, keys only"
    stays visible but disabled ("needs friTap support").
    """
    try:
        from sandroid.analysis import fritap
    except Exception:
        return None
    fn = getattr(fritap, name, None)
    return fn if callable(fn) else None


def keys_only_available() -> bool:
    return _fritap_api("start_fritap_keys") is not None


def _fritap_state(spotlight: str | None) -> tuple[bool, bool]:
    """``(friTap running, on the spotlight app)`` (in-process reads)."""
    running_fn = _fritap_api("fritap_running")
    if running_fn is not None:
        try:
            running = bool(running_fn())
            on_spot = bool(spotlight) and bool(running_fn(spotlight))
            return running, on_spot
        except Exception:
            logger.debug("fritap_running failed", exc_info=True)
    try:
        from sandroid.services import get_task_service

        task = get_task_service().get_task("fritap")
        if task is None or not get_task_service().is_running("fritap"):
            return False, False
        app = getattr(task, "app_name", None)
        return True, bool(spotlight) and (app in (None, "", spotlight))
    except Exception:
        return False, False


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


class Actions(Protocol):
    """What the apply steps do (real services, or a fake in tests)."""

    def run(self, step: tuple, serial: str | None) -> tuple[bool, str]: ...


class ServiceActions:
    """The real step implementations (blocking; worker threads only)."""

    def run(self, step: tuple, serial: str | None) -> tuple[bool, str]:
        name = step[0]
        handler = getattr(self, f"_{name}", None)
        if handler is None:
            return False, f"unknown step {name}"
        from sandroid.core.adb import Adb

        with Adb.targeting(serial):
            return handler(serial, *step[1:])

    @staticmethod
    def _start_mitm(_serial) -> tuple[bool, str]:
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        svc = get_mitmproxy_service()
        if not svc.is_running() and not svc.start():
            return False, f"Mitmproxy did not start ({svc.state.last_error})"
        svc.wait_listening(8.0)
        return True, "Mitmproxy running"

    @staticmethod
    def _inject_ca(serial) -> tuple[bool, str]:
        from sandroid.core.proxy_manager import CAManager
        from sandroid.services.app_start import AppStartError, lifecycle_lock

        manager = CAManager()
        try:
            with lifecycle_lock(0.0):
                result = manager.inject_ca_into_zygote(serial=serial)
        except AppStartError:
            # Not fatal: the method works, HTTPS shows as a problem.
            return True, "CA not installed: an app start is running, try again"
        if result.success:
            path = manager._sandroid_ca_path()
            if path is not None:
                try:
                    manager.bypass_chrome_ct(path)
                except Exception:
                    logger.debug("Chrome CT bypass failed", exc_info=True)
            return True, "CA installed"
        if getattr(result, "restart_required", False):
            return True, (
                "CA not installed without a restart: Ctrl+N in the Network tab "
                "offers it"
            )
        return True, f"CA not installed: {result.message}"

    @staticmethod
    def _prepare_guard(serial, addr: str) -> tuple[bool, str]:
        from sandroid.core.device_guard import Endpoint, get_device_guard

        endpoint = Endpoint.parse(addr)
        if endpoint is None:
            return False, f"invalid proxy address {addr!r}"
        if endpoint.loopback:
            ok, msg = _ensure_reverse(endpoint.port)
            if not ok:
                return False, msg
        view = get_device_guard().prepare(serial, endpoint, kill_switch=True, ours=True)
        if not view.kill_switch:
            return False, f"Kill switch not applied ({view.detail or 'see the log'})"
        return True, "Kill switch on"

    @staticmethod
    def _set_device_proxy(serial, addr: str) -> tuple[bool, str]:
        from sandroid.core.proxy_manager import ProxyConfig, ProxyManager
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        ok, msg = ProxyManager().set_proxy(ProxyConfig.from_string(addr))
        if ok:
            get_mitmproxy_service().note_device_proxy(addr, serial)
        return ok, msg

    @staticmethod
    def _clear_device_proxy(serial) -> tuple[bool, str]:
        from sandroid.core.proxy_manager import ProxyManager, _reverse_registered
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        svc = get_mitmproxy_service()
        ok, msg = ProxyManager().unset_proxy()
        if ok:
            svc.note_device_proxy(None)
            port = svc.state.proxy_port
            try:
                from sandroid.core.adb import Adb

                if _reverse_registered(port):
                    Adb.reverse_remove(f"tcp:{port}")
            except Exception:
                pass
        return ok, msg

    @staticmethod
    def _enable_lane(_serial, pkg: str) -> tuple[bool, str]:
        from sandroid.core.proxy_manager import get_focus_manager

        return get_focus_manager().enable_focus(pkg)

    @staticmethod
    def _disable_lane(_serial, pkg: str) -> tuple[bool, str]:
        from sandroid.core.proxy_manager import get_focus_manager

        return get_focus_manager().disable_focus(pkg)

    @staticmethod
    def _stop_fritap(_serial) -> tuple[bool, str]:
        stop = _fritap_api("stop_fritap")
        try:
            if stop is not None:
                stop()
            else:
                from sandroid.services import get_task_service

                get_task_service().stop("fritap")
        except Exception as exc:
            return False, f"friTap did not stop: {exc}"
        return True, "friTap stopped"

    @staticmethod
    def _start_fritap_keys(serial, pkg: str) -> tuple[bool, str]:
        start = _fritap_api("start_fritap_keys")
        if start is None:
            return False, KEYS_ONLY_UNAVAILABLE
        result = start(package=pkg, serial=serial)
        try:
            ok, message = result[0], result[1]
        except Exception:
            ok, message = bool(result), ""
        if ok:
            return True, message or f"friTap writing TLS keys of {pkg}"
        reason = getattr(result, "reason", None)
        return False, FRITAP_REASONS.get(
            reason or "", message or "friTap did not start"
        )

    @staticmethod
    def _pinning(_serial, on: bool) -> tuple[bool, str]:
        from sandroid.analysis.detection_bypass import get_bypass_service
        from sandroid.services.app_start import AppStartError, lifecycle_lock

        svc = get_bypass_service()
        try:
            with lifecycle_lock(0.0):
                if on:
                    return svc.start("ssl")
                svc.stop("ssl")
                return True, "pinning bypass off"
        except AppStartError:
            return False, "pinning bypass busy (an app start is running), try again"


def _ensure_reverse(port: int) -> tuple[bool, str]:
    from sandroid.core.adb import Adb
    from sandroid.core.proxy_manager import _reverse_registered

    if _reverse_registered(port):
        return True, ""
    try:
        Adb.reverse(f"tcp:{port}", f"tcp:{port}")
    except Exception as exc:
        return False, f"adb reverse failed: {exc}"
    return True, ""


@dataclass
class ApplyResult:
    """Outcome of :meth:`NetworkMethodService.apply`."""

    ok: bool
    message: str
    #: External pieces would be replaced: nothing changed; ask, then apply
    #: again with ``replace_external=True``.
    confirm: str = ""
    done: list[str] = field(default_factory=list)
    view: MethodView | None = None


def execute_plan(
    plan: ApplyPlan, actions: Actions, serial: str | None
) -> tuple[bool, list[str], str]:
    """Run *plan* in order; stop at the first failing step.

    Returns:
        ``(ok, messages of the steps run, the failure or "")``.
    """
    done: list[str] = []
    for step in plan.steps:
        try:
            ok, msg = actions.run(step, serial)
        except Exception as exc:
            logger.warning("Network method step %s failed: %s", step[0], exc)
            ok, msg = False, str(exc)
        logger.info("Network method step %s: %s", step[0], msg)
        if not ok:
            return False, done, f"{step[0].replace('_', ' ')}: {msg}"
        if msg:
            done.append(msg)
    return True, done, ""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

#: STATE_CHANGED kinds the method follows.
_FOLLOWED = (
    "device_proxy",
    "app_proxies",
    "proxy_infra",
    "proxy_ca",
    "spotlight_app",
    "network_guard",
)
#: TaskService tasks the method follows.
_TASKS = ("bypass", "fritap")


class NetworkMethodService:
    """Snapshot gathering, derivation, apply, events (one per process)."""

    def __init__(self, actions: Actions | None = None) -> None:
        self._actions = actions or ServiceActions()
        self._lock = threading.Lock()
        self._apply_lock = threading.Lock()
        self._snapshot = MethodSnapshot()
        self._view = derive_method(self._snapshot)
        self._ca = "unknown"
        self._busy = False
        self._again = False
        self._again_ca = False
        self._subscribed = False
        self._closed = False

    # -- cached reads (UI thread) -------------------------------------------

    def view_cached(self) -> MethodView:
        return self._view

    def snapshot_cached(self) -> MethodSnapshot:
        return self._snapshot

    # -- gathering ----------------------------------------------------------

    def gather(
        self, *, with_ca: bool = False, serial: str | None = None
    ) -> MethodSnapshot:
        """Read everything the method needs (blocking: one or two adb calls)."""
        from sandroid.core.adb import Adb
        from sandroid.core.device_guard import get_device_guard
        from sandroid.core.proxy_manager import (
            classify_device_proxy,
            get_focus_manager,
            resolve_proxy_host_ip,
        )
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        serial = serial or Adb.get_target_device()
        mitm = get_mitmproxy_service()
        port = mitm.state.proxy_port
        guard = get_device_guard()
        view = guard.refresh(serial)
        endpoint = view.endpoint
        if not view.checked:
            endpoint = _read_device_proxy(serial)
        device, addr = "none", ""
        if endpoint is not None:
            addr = endpoint.address
            with Adb.targeting(serial):
                ours = classify_device_proxy(endpoint.ip, endpoint.port, port) == "ours"
            device = "ours" if ours else "external"
        try:
            our_addr = f"{resolve_proxy_host_ip()}:{port}"
        except Exception:
            our_addr = ""
        focus = get_focus_manager()
        lanes = focus.app_proxies_cached()
        health = focus.lane_health_cached(serial)
        lane_problems = {pkg: h.label for pkg, h in health.items() if not h.ok}
        if with_ca:
            self._ca = _read_ca(serial)
        spotlight = _spotlight()
        fritap, fritap_on_spot = _fritap_state(spotlight)
        try:
            from sandroid.config import get_config

            quic = bool(get_config().focus.block_quic)
        except Exception:
            quic = True
        return MethodSnapshot(
            spotlight=spotlight,
            mitm_running=mitm.is_running(),
            device_proxy=device,
            device_addr=addr,
            our_addr=our_addr,
            kill_switch=view.kill_switch,
            refused=view.refused,
            attribution=view.attribution,
            named_apps=view.named_apps,
            lanes=lanes,
            lane_problems=lane_problems,
            ca=self._ca,
            pinning=_pinning_state(),
            fritap=fritap,
            fritap_on_spotlight=fritap_on_spot,
            quic_block=quic,
            keys_only_available=keys_only_available(),
        )

    def refresh_now(self, *, with_ca: bool = False) -> MethodView:
        """Gather and derive now (blocking); publishes the change."""
        snapshot = self.gather(with_ca=with_ca)
        return self._store(snapshot)

    def _store(self, snapshot: MethodSnapshot) -> MethodView:
        view = derive_method(snapshot)
        with self._lock:
            changed = view != self._view or snapshot != self._snapshot
            self._snapshot = snapshot
            self._view = view
        if changed:
            _publish({"change_type": "network_method", "method": view.preset})
        return view

    def refresh(self, *, with_ca: bool = False) -> None:
        """Re-derive on a worker (one at a time; a request meanwhile re-runs)."""
        if self._closed:
            return
        with self._lock:
            if self._busy:
                self._again = True
                self._again_ca = self._again_ca or with_ca
                return
            self._busy = True

        def _run() -> None:
            ca = with_ca
            while not self._closed:
                try:
                    self.refresh_now(with_ca=ca)
                except Exception:
                    logger.debug("network method refresh failed", exc_info=True)
                with self._lock:
                    if not self._again:
                        self._busy = False
                        return
                    self._again = False
                    ca = self._again_ca
                    self._again_ca = False
            with self._lock:
                self._busy = False

        threading.Thread(target=_run, name="network-method", daemon=True).start()

    def note_ca(self, installed: bool | None) -> None:
        """A CA change with a known outcome (``proxy_ca`` event)."""
        if installed is not None:
            self._ca = "installed" if installed else "missing"

    # -- apply ----------------------------------------------------------------

    def apply(
        self,
        preset: str,
        *,
        defeat_pinning: bool | None = None,
        replace_external: bool = False,
        serial: str | None = None,
    ) -> ApplyResult:
        """Apply a preset (blocking; worker threads / AI tools only)."""
        from sandroid.core.adb import Adb

        serial = serial or Adb.get_target_device()
        if not self._apply_lock.acquire(blocking=False):
            return ApplyResult(False, "Another Network method change is running")
        try:
            snapshot = self.gather(with_ca=True, serial=serial)
            plan = plan_apply(
                preset,
                snapshot,
                defeat_pinning=defeat_pinning,
                replace_external=replace_external,
            )
            if plan.error:
                return ApplyResult(False, plan.error, view=self._store(snapshot))
            if plan.confirm:
                return ApplyResult(
                    False,
                    plan.confirm,
                    confirm=plan.confirm,
                    view=self._store(snapshot),
                )
            ok, done, failure = execute_plan(plan, self._actions, serial)
            view = self.refresh_now(
                with_ca=any(s[0] == "inject_ca" for s in plan.steps)
            )
        finally:
            self._apply_lock.release()
        if not ok:
            return ApplyResult(
                False, f"{LABELS[preset]} stopped at {failure}", done=done, view=view
            )
        message = f"Network method: {view.name}"
        if view.problems:
            message += ". " + _sentence(view.problems)
        return ApplyResult(True, message, done=done, view=view)

    # -- events ---------------------------------------------------------------

    def subscribe(self) -> None:
        """Follow the state events (idempotent)."""
        if self._subscribed:
            return
        self._subscribed = True
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()
            bus.subscribe(EventType.STATE_CHANGED, self._on_state)
            bus.subscribe(EventType.TASK_STARTED, self._on_task)
            bus.subscribe(EventType.TASK_STOPPED, self._on_task)
            bus.subscribe(EventType.TASK_UPDATED, self._on_task)
        except Exception:
            logger.debug("network method subscription failed", exc_info=True)
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            # TODO(bypass-state-listener): app-lens adds add_state_listener;
            # until then the TaskService "bypass" events cover live changes
            # (arm-only changes show on the next refresh).
            add = getattr(get_bypass_service(), "add_state_listener", None)
            if callable(add):
                add(self._on_bypass_state)
        except Exception:
            logger.debug("bypass state listener not added", exc_info=True)
        try:
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            get_mitmproxy_service().add_listener(self._on_mitm_line)
        except Exception:
            logger.debug("mitmproxy listener not added", exc_info=True)

    def unsubscribe(self) -> None:
        """Stop following the events (tests; idempotent)."""
        if not self._subscribed:
            return
        self._subscribed = False
        self._closed = True
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()
            bus.unsubscribe(EventType.STATE_CHANGED, self._on_state)
            for kind in (
                EventType.TASK_STARTED,
                EventType.TASK_STOPPED,
                EventType.TASK_UPDATED,
            ):
                bus.unsubscribe(kind, self._on_task)
        except Exception:
            pass
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            remove = getattr(get_bypass_service(), "remove_state_listener", None)
            if callable(remove):
                remove(self._on_bypass_state)
        except Exception:
            pass
        try:
            from sandroid.services.mitmproxy_service import peek_mitmproxy_service

            service = peek_mitmproxy_service()
            if service is not None:
                service.remove_listener(self._on_mitm_line)
        except Exception:
            pass

    def _on_state(self, event) -> None:
        data = getattr(event, "data", None) or {}
        kind = data.get("change_type")
        if kind == "proxy_ca":
            self.note_ca(data.get("installed"))
        if kind in _FOLLOWED or data.get("component") == "proxy":
            self.refresh()

    def _on_task(self, event) -> None:
        data = getattr(event, "data", None) or {}
        if data.get("task_name") in _TASKS:
            self.refresh()

    def _on_bypass_state(self) -> None:
        # Runs on the changing thread, maybe under the service's lock: only
        # schedule (the worker reads on_categories()).
        self.refresh()

    def _on_mitm_line(self, line: str) -> None:
        if line.startswith("[INFO]") and (
            "mitmweb started" in line or "mitmweb stopped" in line or "exited" in line
        ):
            self.refresh()


def _publish(data: dict) -> None:
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(type=EventType.STATE_CHANGED, data=data, source="network_method")
        )
    except Exception:
        logger.debug("network method publish failed", exc_info=True)


def _spotlight() -> str | None:
    try:
        from sandroid.services import get_spotlight_service

        return get_spotlight_service().get_effective_package()
    except Exception:
        return None


def _pinning_state() -> str:
    try:
        from sandroid.analysis.detection_bypass import get_bypass_service

        svc = get_bypass_service()
        if svc.is_active("ssl"):
            return "on"
        if "ssl" in svc.on_categories():
            return "armed"
    except Exception:
        pass
    return "off"


def _read_device_proxy(serial: str | None):
    from sandroid.core.adb import Adb
    from sandroid.core.device_guard import Endpoint
    from sandroid.core.proxy_manager import ProxyManager, ProxyStatus

    try:
        with Adb.targeting(serial):
            status, cfg = ProxyManager().get_proxy_settings()
    except Exception:
        return None
    if status != ProxyStatus.SET or cfg is None:
        return None
    return Endpoint.parse(cfg.address)


def _read_ca(serial: str | None) -> str:
    try:
        from sandroid.core.proxy_manager import CAManager

        status = CAManager().check_zygote_injection_status(serial=serial)
    except Exception:
        return "unknown"
    if status.injected:
        return "installed"
    if status.verdict in ("", "unknown"):
        return "unknown"
    return "missing"


_INSTANCE: NetworkMethodService | None = None
_INSTANCE_LOCK = threading.Lock()


def get_network_method_service() -> NetworkMethodService:
    """The process-wide service (subscribed to the state events)."""
    global _INSTANCE
    if _INSTANCE is None:
        with _INSTANCE_LOCK:
            if _INSTANCE is None:
                service = NetworkMethodService()
                service.subscribe()
                _INSTANCE = service
    return _INSTANCE


def peek_network_method_service() -> NetworkMethodService | None:
    return _INSTANCE


__all__ = [
    "CUSTOM",
    "KEYS_ONLY",
    "LABELS",
    "OFF",
    "PRESETS",
    "THIS_APP",
    "WHOLE_DEVICE",
    "ApplyPlan",
    "ApplyResult",
    "MethodSnapshot",
    "MethodView",
    "NetworkMethodService",
    "derive_method",
    "execute_plan",
    "get_network_method_service",
    "plan_apply",
]
