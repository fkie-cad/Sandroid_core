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
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

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

#: Shown if friTap has no non-interactive keys-only start (older builds).
KEYS_ONLY_UNAVAILABLE = "needs friTap support"

#: friTap refusal reasons (``StartResult.reason``) in plain words.
FRITAP_REASONS = {
    "not_selected": "pick a spotlight app first",
    "other_device": "the spotlight app is on another device",
    "busy": "another start is running, try again",
    "needs_consent": "needs consent to restart the app",
    "declined": "the restart of the app was declined",
}

#: Steps that use Frida (friTap, the bypass scripts, the app start with its
#: spawn bundle). They run on the SELECTED device's Frida session only, so
#: they never run inside ``Adb.targeting`` and a preset needing them is
#: refused for another device.
FRIDA_STEPS = frozenset({"start_fritap_keys", "stop_fritap", "pinning", "start_app"})


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
    #: The Kill switch also covers IPv6 (False: no ip6tables on the device).
    ks_ipv6: bool = True
    refused: int = 0
    #: "off" | "on" | "partial" | "failed" | "external" | "unavailable"
    attribution: str = "off"
    named_apps: int = 0
    #: Apps the identity relay does not name yet (installed afterwards).
    unnamed_apps: int = 0
    #: "relay_down" | "jump_missing" | "" (see GuardView.naming_problem).
    naming_problem: str = ""
    #: Android users the Kill switch does not cover yet.
    uncovered_users: tuple[int, ...] = ()
    #: package -> "ours" | "http://ip:port"
    lanes: dict[str, str] = field(default_factory=dict)
    #: package -> health label, only lanes that pass no traffic.
    lane_problems: dict[str, str] = field(default_factory=dict)
    #: "installed" | "missing" | "unknown"
    ca: str = "unknown"
    #: "on" (live on the spotlight app) | "set" (for its next start) | "off"
    pinning: str = "off"
    fritap: bool = False
    fritap_on_spotlight: bool = False
    #: The running friTap was started by hand (``h``: its own settings,
    #: maybe a pcap), not by the Network method.
    fritap_by_hand: bool = False
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
    if s.pinning == "set":
        return "pinning bypass set for the next app start"
    return "pinning not bypassed"


def _ca_problem(s: MethodSnapshot) -> list[str]:
    if s.ca == "missing":
        return ["CA not installed: HTTPS cannot be read"]
    return []


def _naming_problems(s: MethodSnapshot) -> list[str]:
    """App naming of OUR device proxy, when it is not complete."""
    if s.device_proxy != "ours":
        return []
    if s.attribution == "partial":
        count = s.unnamed_apps
        return [f"{count} app{'s' if count != 1 else ''} not named yet (repairing)"]
    if s.naming_problem == "relay_down":
        effect = (
            "apps have no network meanwhile"
            if s.kill_switch
            else "apps may go direct past Mitmproxy meanwhile"
        )
        return [
            f"device proxy connections refused: identity relay down, repairing "
            f"({effect})"
        ]
    if s.naming_problem == "jump_missing":
        return ["apps not named (the proxy-port rule is missing, repairing)"]
    if s.attribution in ("failed", "unavailable"):
        return ["apps not named (identity relay not running)"]
    return []


def _kill_switch_problems(s: MethodSnapshot) -> list[str]:
    problems = []
    if s.kill_switch and s.uncovered_users:
        users = ", ".join(str(u) for u in s.uncovered_users)
        problems.append(f"not covered: Android user {users} (repairing)")
    if s.kill_switch and not s.ks_ipv6:
        problems.append("Kill switch covers IPv4 only (no ip6tables on the device)")
    return problems


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
            problems=(
                "Kill switch without a device proxy: apps have no network "
                "(Off removes it)",
            ),
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
        refused = "direct traffic refused"
        if s.uncovered_users:
            refused += " for the covered users"
        covered.append(f"{refused} ({s.refused})" if s.refused else refused)
        problems: list[str] = []
        if s.attribution == "on":
            covered.append("apps named")
        problems += _naming_problems(s)
        if not s.mitm_running:
            problems.insert(
                0, "Mitmproxy stopped: app traffic is blocked until it runs again"
            )
        problems += _kill_switch_problems(s)
        problems += _ca_problem(s)
        notes = [_pinning_note(s)] if spot else []
        if s.attribution == "on":
            # SDK runtime processes (UID 20000+) are refused by the Kill
            # switch but get no relay identity of their own.
            notes.insert(0, "SDK runtime processes not named")
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
    return MethodView(
        CUSTOM,
        covered=tuple(_custom_pieces(s)),
        problems=tuple(_naming_problems(s) + _kill_switch_problems(s)),
    )


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
    to be set), ``("set_device_proxy", addr)``, ``("own_device_proxy",
    addr)`` (our proxy is already set: Sandroid takes it over, so quit
    clears it), ``("clear_device_proxy",)``, ``("kill_switch_off",)`` (a Kill
    switch left without its proxy), ``("enable_lane", pkg)``,
    ``("disable_lane", pkg)``, ``("stop_fritap",)``, ``("start_app",)``,
    ``("start_fritap_keys", pkg)``, ``("pinning", bool)``.

    Replacing something the analyst set up outside the Network method (an
    external device proxy, an external App Proxy upstream, a friTap started
    by hand) needs ``replace_external``; without it the plan only carries the
    confirmation text.
    """
    if preset not in PRESETS:
        return ApplyPlan(error=f"Unknown Network method {preset!r}")
    spot = s.spotlight
    if preset in (THIS_APP, KEYS_ONLY) and not spot:
        return ApplyPlan(error="Pick a spotlight app first")
    if preset == KEYS_ONLY and not s.keys_only_available:
        return ApplyPlan(error=f"This app, keys only {KEYS_ONLY_UNAVAILABLE}")
    steps: list[tuple] = []
    pin = (
        [("pinning", defeat_pinning)]
        if defeat_pinning is not None and spot and preset != OFF
        else []
    )
    # A Kill switch without a device proxy takes every app offline; the
    # presets without a device proxy remove it (after the proxy is gone).
    ks_off = [("kill_switch_off",)] if s.kill_switch else []
    if preset == WHOLE_DEVICE:
        addr = s.device_addr if s.device_proxy == "ours" else s.our_addr
        if not s.mitm_running:
            steps.append(("start_mitm",))
        if s.ca != "installed":
            steps.append(("inject_ca",))
        steps.append(("prepare_guard", addr))
        if s.device_proxy == "ours" and s.device_addr == addr:
            steps.append(("own_device_proxy", addr))
        else:
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
        steps += ks_off
        if s.fritap:
            steps.append(("stop_fritap",))
        steps += pin
    elif preset == KEYS_ONLY:
        unroute = []
        if s.device_proxy != "none":
            unroute.append(("clear_device_proxy",))
        unroute += ks_off
        unroute += [("disable_lane", pkg) for pkg in sorted(s.lanes)]
        if s.fritap and not s.fritap_on_spotlight:
            steps.append(("stop_fritap",))
        if defeat_pinning and not s.fritap_on_spotlight:
            # A stopped app must start WITH the bypass (its pinning checks
            # run at startup): set it first, take the proxy away (its first
            # requests must not go through Mitmproxy), start the app with
            # the bypass in the spawn bundle, then friTap attaches.
            steps += pin + unroute + [("start_app",)]
            pin, unroute = [], []
        steps.append(("start_fritap_keys", spot))
        steps += unroute
        steps += pin
    else:  # OFF
        if s.device_proxy != "none":
            steps.append(("clear_device_proxy",))
        steps += ks_off
        steps += [("disable_lane", pkg) for pkg in sorted(s.lanes)]
        if s.fritap:
            steps.append(("stop_fritap",))
    external = _external_pieces(s)
    stops_hand_fritap = s.fritap_by_hand and ("stop_fritap",) in steps
    if (external or stops_hand_fritap) and not replace_external:
        target = LABELS[preset]
        parts = []
        if external:
            parts.append(
                f"{'; '.join(external).capitalize()}. Applying {target} replaces that."
            )
        if stops_hand_fritap:
            parts.append(
                f"friTap was started by hand (its own settings, maybe a pcap); "
                f"applying {target} stops it."
            )
        return ApplyPlan(confirm=" ".join(parts) + " Continue?")
    return ApplyPlan(steps=steps)


# ---------------------------------------------------------------------------
# friTap (app-lens: sandroid.analysis.fritap)
# ---------------------------------------------------------------------------


def keys_only_available() -> bool:
    """FriTap has its non-interactive keys-only start (always on this build)."""
    from sandroid.analysis import fritap

    return callable(getattr(fritap, "start_fritap_keys", None))


def _fritap_state(spotlight: str | None) -> tuple[bool, bool]:
    """``(friTap running, on the spotlight app)`` (in-process reads)."""
    try:
        from sandroid.analysis.fritap import fritap_running

        running = fritap_running()
        return running, running and bool(spotlight) and fritap_running(spotlight)
    except Exception:
        logger.debug("fritap_running failed", exc_info=True)
        return False, False


#: ``id()`` of the friTap instance the Network method started (keys only).
_OUR_FRITAP: int | None = None


def _fritap_instance() -> Any:
    try:
        from sandroid.services import get_task_service

        task = get_task_service().get_task("fritap")
    except Exception:
        return None
    return getattr(task, "instance", None) if task is not None else None


def _note_our_fritap() -> None:
    global _OUR_FRITAP
    instance = _fritap_instance()
    _OUR_FRITAP = id(instance) if instance is not None else None


def _fritap_by_hand() -> bool:
    """A friTap runs that the Network method did not start (``h``)."""
    instance = _fritap_instance()
    return instance is not None and id(instance) != _OUR_FRITAP


def _selected_device() -> str | None:
    """The device the user selected (never a thread's ``Adb.targeting`` pin)."""
    from sandroid.core.adb import Adb

    return Adb._target_device


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
        if name in FRIDA_STEPS:
            # friTap and the bypass scripts run on the SELECTED device's
            # Frida session: a pin here would only fool their device checks
            # (the apply refuses them for another device beforehand).
            return handler(serial, *step[1:])
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
    def _own_device_proxy(serial, addr: str) -> tuple[bool, str]:
        """Our proxy is already set (e.g. left by an earlier session): take
        it over, so Mitmproxy stop keeps it behind the Kill switch and quit
        clears it together with the Kill switch.
        """
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        get_mitmproxy_service().note_device_proxy(addr, serial)
        return True, ""

    @staticmethod
    def _kill_switch_off(serial) -> tuple[bool, str]:
        from sandroid.core.device_guard import get_device_guard

        return get_device_guard().set_kill_switch(False, serial)

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
        from sandroid.analysis.fritap import fritap_running, stop_fritap

        by_hand = _fritap_by_hand()
        stop_fritap()
        if fritap_running():
            return False, "friTap did not stop"
        if by_hand:
            return True, "friTap (started by hand) stopped"
        return True, "friTap stopped"

    @staticmethod
    def _start_app(_serial) -> tuple[bool, str]:
        """Start the STOPPED spotlight app with the set bypasses (spawn
        bundle). A running app is left alone (friTap attaches to it).
        """
        from sandroid.services import app_start

        package = _spotlight()
        if not package:
            return False, "no spotlight app"
        liveness, _pid = app_start.probe_liveness(package)
        if liveness != app_start.Liveness.NOT_RUNNING:
            return True, ""
        result = app_start.start_app()
        try:
            ok, message = result[0], result[1]
        except Exception:
            ok, message = bool(result), ""
        if ok:
            return True, message or f"{package} started with the pinning bypass"
        return False, message or f"{package} did not start"

    @staticmethod
    def _start_fritap_keys(serial, pkg: str) -> tuple[bool, str]:
        from sandroid.analysis.fritap import start_fritap_keys

        before = _fritap_instance()
        result = start_fritap_keys(package=pkg, serial=serial)
        try:
            ok, message = result[0], result[1]
        except Exception:
            ok, message = bool(result), ""
        if ok:
            after = _fritap_instance()
            if after is not None and after is not before:
                _note_our_fritap()  # a new friTap: the Network method's own
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


_SYMBOLS = {
    "\u2192": "to",  # right arrow
    "\u2190": "from",
    "\u2014": "-",  # em dash
    "\u2013": "-",
    "\u2423": "Space",  # open box (the Space key)
    "\u2026": "...",
}


def plain_words(text: str) -> str:
    """A step message from another service in plain words (no symbols, no
    "armed"): it reaches the toasts and the AI's ``steps``.
    """
    import re

    for symbol, word in _SYMBOLS.items():
        text = text.replace(symbol, word)
    text = re.sub(r"\barmed\b", "set for the next app start", text)
    text = re.sub(r"[\u2190-\u21ff\u2500-\u27bf\u2b00-\u2bff]", "", text)
    return re.sub(r"\s{2,}", " ", text).strip()


def execute_plan(
    plan: ApplyPlan,
    actions: Actions,
    serial: str | None,
    ran: list[tuple] | None = None,
    stop: Any = None,
) -> tuple[bool, list[str], str]:
    """Run *plan* in order; stop at the first failing step.

    Args:
        ran: Filled with the steps that succeeded, in order.
        stop: Callable; True between two steps ends the run (quit).

    Returns:
        ``(ok, messages of the steps run, the failure or "")``.
    """
    done: list[str] = []
    for step in plan.steps:
        if stop is not None and stop():
            return False, done, "stopped: Sandroid is quitting"
        try:
            ok, msg = actions.run(step, serial)
        except Exception as exc:
            logger.warning("Network method step %s failed: %s", step[0], exc)
            ok, msg = False, str(exc)
        logger.info("Network method step %s: %s", step[0], msg)
        if not ok:
            return False, done, f"{step[0].replace('_', ' ')}: {plain_words(msg)}"
        if ran is not None:
            ran.append(step)
        if msg:
            done.append(plain_words(msg))
    return True, done, ""


def needs_guard_rollback(plan: ApplyPlan, ran: list[tuple]) -> bool:
    """A failed Whole device left a Kill switch for a proxy never set (pure).

    ``prepare_guard`` (ran or failed half-way) points the Kill switch at the
    proxy about to be set; when ``set_device_proxy`` then did not succeed,
    the Kill switch allows a proxy the device does not use: every app would
    be offline.
    """
    names = [step[0] for step in plan.steps]
    if "prepare_guard" not in names or "set_device_proxy" not in names:
        return False
    return "set_device_proxy" not in [step[0] for step in ran]


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
        #: serial -> "installed" | "missing" | "unknown" (CA per device).
        self._ca: dict[str | None, str] = {}
        #: Set on quit: an apply stops between two steps.
        self._abort = threading.Event()
        self._health: threading.Thread | None = None
        self._busy = False
        self._again = False
        self._again_ca = False
        self._subscribed = False
        self._closed = False
        self._unnamed_at = -1e9

    # -- cached reads (UI thread) -------------------------------------------

    def view_cached(self) -> MethodView:
        return self._view

    def snapshot_cached(self) -> MethodSnapshot:
        return self._snapshot

    # -- gathering ----------------------------------------------------------

    def gather(
        self,
        *,
        with_ca: bool = False,
        serial: str | None = None,
        repair: bool = True,
    ) -> MethodSnapshot:
        """Read everything the method needs (blocking: one or two adb calls).

        With *repair* a broken app naming of our device proxy is repaired on
        the way (the guard's refresh; at most every few seconds).
        """
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
        view = guard.refresh(serial, repair=repair)
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
        lanes = focus.app_proxies_cached(serial)
        health = focus.lane_health_cached(serial)
        lane_problems = {pkg: h.label for pkg, h in health.items() if not h.ok}
        if with_ca:
            self._ca[serial] = _read_ca(serial)
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
            ks_ipv6=view.ipv6,
            refused=view.refused,
            attribution=view.attribution,
            named_apps=view.named_apps,
            unnamed_apps=view.unnamed_apps,
            naming_problem=view.naming_problem,
            uncovered_users=view.uncovered_users,
            lanes=lanes,
            lane_problems=lane_problems,
            ca=self._ca.get(serial, "unknown"),
            pinning=_pinning_state(spotlight),
            fritap=fritap,
            fritap_on_spotlight=fritap_on_spot,
            fritap_by_hand=fritap and _fritap_by_hand(),
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
        self._ensure_health(snapshot)
        return view

    #: Seconds between two health checks while our device proxy names apps.
    HEALTH_S = 15.0

    @staticmethod
    def _needs_health(snapshot: MethodSnapshot) -> bool:
        return snapshot.device_proxy == "ours" and (
            snapshot.kill_switch or snapshot.attribution in ("on", "partial", "failed")
        )

    def _ensure_health(self, snapshot: MethodSnapshot) -> None:
        """While our device proxy is on (Whole device), re-check it every
        :attr:`HEALTH_S` seconds on a worker: a dead relay sends no flow and
        no event, and the user may be on another tab.
        """
        if not self._subscribed or self._closed or not self._needs_health(snapshot):
            return  # only the process-wide (subscribed) service checks
        thread = self._health
        if thread is not None and thread.is_alive():
            return

        def _loop() -> None:
            while not self._abort.wait(self.HEALTH_S):
                if self._closed or not self._needs_health(self._snapshot):
                    return
                self.refresh()

        self._health = threading.Thread(
            target=_loop, name="network-method-health", daemon=True
        )
        self._health.start()

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

    def note_ca(self, installed: bool | None, serial: str | None = None) -> None:
        """A CA change with a known outcome on *serial* (``proxy_ca`` event)."""
        if installed is not None:
            self._ca[serial] = "installed" if installed else "missing"

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
        if self._closed:
            return ApplyResult(False, "Sandroid is quitting")
        if not self._apply_lock.acquire(blocking=False):
            return ApplyResult(False, "Another Network method change is running")
        try:
            snapshot = self.gather(with_ca=True, serial=serial, repair=False)
            plan = plan_apply(
                preset,
                snapshot,
                defeat_pinning=defeat_pinning,
                replace_external=replace_external,
            )
            if plan.error:
                return ApplyResult(
                    False, plan.error, view=self._view_of(snapshot, serial)
                )
            if plan.confirm:
                return ApplyResult(
                    False,
                    plan.confirm,
                    confirm=plan.confirm,
                    view=self._view_of(snapshot, serial),
                )
            selected = _selected_device()
            frida = sorted({step[0] for step in plan.steps} & FRIDA_STEPS)
            if frida and serial and selected and serial != selected:
                return ApplyResult(
                    False,
                    f"{LABELS[preset]} needs friTap or the pinning bypass, which "
                    f"run on the selected device only: select {serial} first",
                    view=self._view_of(snapshot, serial),
                )
            ran: list[tuple] = []
            ok, done, failure = execute_plan(
                plan, self._actions, serial, ran, stop=self._abort.is_set
            )
            if (
                not ok
                and not self._abort.is_set()  # quitting: the teardown removes it
                and needs_guard_rollback(plan, ran)
            ):
                # Never leave apps offline behind a Kill switch for a proxy
                # that did not get set: back to what the device really has.
                done.append(self._rollback_guard(serial, snapshot.kill_switch))
            after = self.gather(
                with_ca=any(s[0] == "inject_ca" for s in plan.steps),
                serial=serial,
                repair=False,
            )
            view = self._view_of(after, serial)
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

    def _view_of(self, snapshot: MethodSnapshot, serial: str | None) -> MethodView:
        """The method of *serial*: kept (and shown) only for the selected
        device, never mixed into the selected device's line.
        """
        selected = _selected_device()
        if selected is None or serial is None or serial == selected:
            return self._store(snapshot)
        return derive_method(snapshot)

    def close(self, timeout: float = 3.0) -> bool:
        """Quit: no new refresh, repair or health check, an apply stops
        between two steps; waits up to *timeout* for one in flight.

        Returns:
            True when no apply runs any more.
        """
        self._abort.set()
        self.unsubscribe()
        self._closed = True
        if self._apply_lock.acquire(timeout=max(0.0, timeout)):
            self._apply_lock.release()
            return True
        logger.warning("Network method change still running at quit")
        return False

    @staticmethod
    def _rollback_guard(serial: str | None, kill_switch_before: bool) -> str:
        from sandroid.core.device_guard import get_device_guard

        try:
            view = get_device_guard().rollback_prepare(serial, kill_switch_before)
        except Exception as exc:
            logger.error("Kill switch rollback on %s failed: %s", serial, exc)
            return f"Kill switch rollback failed: {exc}"
        if view.kill_switch:
            return "Kill switch kept on the device's proxy"
        return "Kill switch removed again (the proxy was not set)"

    # -- events ---------------------------------------------------------------

    def subscribe(self) -> None:
        """Follow the state events (idempotent)."""
        if self._subscribed:
            return
        self._subscribed = True
        try:
            # A leftover Kill switch (crash, a quit that timed out) is checked
            # on the next device attach too, not only on a snapshot load.
            from sandroid.services.proxy_restore import install_device_prepared_hook

            install_device_prepared_hook()
        except Exception:
            logger.debug("proxy restore hook not installed", exc_info=True)
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

            # Armed-only changes publish nothing else (TaskService events
            # cover live ones).
            get_bypass_service().add_state_listener(self._on_bypass_state)
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

            get_bypass_service().remove_state_listener(self._on_bypass_state)
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
            serial = data.get("serial")
            if serial is None:
                from sandroid.core.adb import Adb

                serial = Adb.get_target_device()
            self.note_ca(data.get("installed"), serial)
        if kind in _FOLLOWED or data.get("component") == "proxy":
            self.refresh()

    def _on_task(self, event) -> None:
        data = getattr(event, "data", None) or {}
        if data.get("task_name") in _TASKS:
            self.refresh()

    def _on_bypass_state(self) -> None:
        # Runs on the changing thread -- a worker or the UI thread itself,
        # maybe under the bypass service's lock: only schedule a worker
        # (it reads on_categories()); never marshal or block here.
        self.refresh()

    #: Seconds between two refreshes triggered by unnamed device-proxy flows.
    UNNAMED_REFRESH_S = 30.0

    def _on_mitm_line(self, line: str) -> None:
        if line.startswith("[INFO]") and (
            "mitmweb started" in line or "mitmweb stopped" in line or "exited" in line
        ):
            self.refresh()
        elif line.startswith("[FLOW]|") and self._unnamed_device_flow(line):
            # Maybe an app installed after "Whole device" (no relay identity
            # yet): the refresh re-reads packages.list and repairs the naming.
            now = time.monotonic()
            if now - self._unnamed_at >= self.UNNAMED_REFRESH_S:
                self._unnamed_at = now
                self.refresh()

    def _unnamed_device_flow(self, line: str) -> bool:
        snap = self._snapshot
        if snap.device_proxy != "ours" or snap.attribution not in ("on", "partial"):
            return False
        parts = line.split("|")
        return len(parts) >= 9 and parts[8].strip() == "device" and not parts[7]


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


def _pinning_state(spotlight: str | None) -> str:
    """The SSL pinning bypass for *spotlight*: live on it, set for its next
    start, or off. Another app's live bypass does not count.
    """
    if not spotlight:
        return "off"
    try:
        from sandroid.analysis.detection_bypass import get_bypass_service

        svc = get_bypass_service()
        if svc.target_app("ssl") == spotlight:
            return "on"
        if "ssl" in svc.carried_categories(spotlight):
            return "set"
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
