"""Network method: derived name, apply plans, Mitmproxy stop, restore, AI tools.

No device: the method is derived from hand-built snapshots, plans are pure,
and the executor runs against a recorder.
"""

from __future__ import annotations

import re
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sandroid.services import network_method as nm

SPOT = "de.fkie.canary"
OUR = "10.0.2.2:8080"

BASE = nm.MethodSnapshot(
    spotlight=SPOT,
    mitm_running=True,
    our_addr=OUR,
    ca="installed",
    keys_only_available=True,
)
WHOLE = replace(
    BASE,
    device_proxy="ours",
    device_addr=OUR,
    kill_switch=True,
    attribution="on",
    named_apps=200,
)
THIS = replace(BASE, lanes={SPOT: "ours"})
KEYS = replace(BASE, fritap=True, fritap_on_spotlight=True)

_GLYPHS = re.compile(r"[←-⇿─-➿⬀-⯿○●✓✗]")


# -- derived method ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("snapshot", "preset", "app"),
    [
        (BASE, nm.OFF, None),
        (replace(BASE, mitm_running=False, ca="missing"), nm.OFF, None),
        (WHOLE, nm.WHOLE_DEVICE, None),
        (THIS, nm.THIS_APP, SPOT),
        (KEYS, nm.KEYS_ONLY, SPOT),
    ],
)
def test_presets(snapshot, preset, app):
    view = nm.derive_method(snapshot)
    assert view.preset == preset
    assert view.app == app
    assert not view.problems


@pytest.mark.parametrize(
    "snapshot",
    [
        replace(WHOLE, kill_switch=False),  # our proxy, Kill switch off by hand
        replace(WHOLE, device_proxy="external", device_addr="192.168.1.5:8081"),
        replace(BASE, device_proxy="external", device_addr="192.168.1.5:8081"),
        replace(WHOLE, lanes={SPOT: "ours"}),  # device proxy + lane
        replace(BASE, lanes={"com.other": "ours"}),  # lane not on spotlight
        replace(BASE, lanes={SPOT: "ours", "com.other": "ours"}),
        replace(BASE, lanes={SPOT: "http://192.168.1.5:8081"}),  # external lane
        replace(THIS, fritap=True, fritap_on_spotlight=True),  # friTap + proxy
        replace(BASE, fritap=True, fritap_on_spotlight=False),  # friTap elsewhere
        replace(THIS, spotlight="com.new.app"),  # spotlight moved on
    ],
)
def test_custom_lists_what_is_on(snapshot):
    view = nm.derive_method(snapshot)
    assert view.preset == nm.CUSTOM
    assert view.covered  # "with what is on"
    assert "Custom" in view.line()


def test_qualities_are_problems_not_custom():
    view = nm.derive_method(
        replace(WHOLE, mitm_running=False, ca="missing", attribution="failed")
    )
    assert view.preset == nm.WHOLE_DEVICE
    assert view.problems[0].startswith("Mitmproxy stopped: app traffic is blocked")
    assert any("CA not installed" in p for p in view.problems)
    assert any("apps not named" in p for p in view.problems)
    lane_down = nm.derive_method(
        replace(THIS, lane_problems={SPOT: "waiting for mitmproxy"}, quic_block=False)
    )
    assert lane_down.preset == nm.THIS_APP
    assert lane_down.problems == ("App Proxy waiting for mitmproxy",)
    assert "QUIC not blocked" in lane_down.notes


@pytest.mark.parametrize(
    "snapshot",
    [
        # N3-B3: device proxy + Kill switch + App Proxy, Mitmproxy killed.
        replace(WHOLE, lanes={SPOT: "ours"}, mitm_running=False),
        replace(WHOLE, kill_switch=False, mitm_running=False),
        replace(BASE, lanes={"com.other": "ours"}, mitm_running=False),
    ],
)
def test_custom_needing_mitmproxy_shows_it_stopped(snapshot):
    view = nm.derive_method(snapshot)
    assert view.preset == nm.CUSTOM
    assert view.problems[0].startswith("Mitmproxy stopped: app traffic is blocked")


def test_custom_without_mitmproxy_pieces_has_no_stopped_problem():
    external = replace(
        BASE,
        device_proxy="external",
        device_addr="192.168.1.5:8081",
        mitm_running=False,
    )
    assert not nm.derive_method(external).problems


def test_kill_switch_without_proxy_is_a_problem():
    view = nm.derive_method(replace(BASE, kill_switch=True))
    assert view.preset == nm.CUSTOM
    assert "Kill switch without a device proxy" in view.problems[0]


def test_pinning_notes():
    assert "pinning not bypassed" in nm.derive_method(WHOLE).notes
    assert "pinning bypassed" in nm.derive_method(replace(THIS, pinning="on")).notes
    later = nm.derive_method(replace(THIS, pinning="set")).line()
    assert "pinning bypass set for the next app start" in later
    assert " arm" not in later


def test_status_line_words_and_colours_only():
    view = nm.derive_method(replace(WHOLE, refused=12, mitm_running=False))
    line = view.line()
    assert line.startswith("Network method: Whole device.")
    assert "direct traffic refused (12)" in line
    markup = view.markup("#0f0", "#ff0", "#f00", "#888")
    assert "[#f00]" in markup  # a problem: error colour
    for text in (line, markup, nm.derive_method(THIS).line()):
        assert not _GLYPHS.search(text)
        assert "Capture" not in text
        assert "mitmweb" not in text
        assert " arm" not in text.replace("armed", "")


# -- apply plans ---------------------------------------------------------------------


def _names(plan):
    return [step[0] for step in plan.steps]


def test_whole_device_plan_is_fail_closed():
    snap = replace(BASE, mitm_running=False, ca="missing", lanes={"x.y": "ours"})
    plan = nm.plan_apply(nm.WHOLE_DEVICE, snap, defeat_pinning=True)
    assert _names(plan) == [
        "start_mitm",
        "inject_ca",
        "prepare_guard",  # Kill switch + app naming BEFORE the proxy points at us
        "set_device_proxy",
        "disable_lane",
        "pinning",
    ]
    assert plan.steps[2] == ("prepare_guard", OUR)
    assert plan.steps[3] == ("set_device_proxy", OUR)


def test_reselecting_the_active_preset_repairs_it():
    plan = nm.plan_apply(nm.WHOLE_DEVICE, WHOLE)
    # re-check, and take over our proxy (quit clears it with the Kill switch)
    assert plan.steps == [("prepare_guard", OUR), ("own_device_proxy", OUR)]
    assert _names(nm.plan_apply(nm.THIS_APP, THIS)) == ["enable_lane"]


def test_external_proxy_needs_a_confirmation():
    snap = replace(BASE, device_proxy="external", device_addr="192.168.1.5:8081")
    for preset in (nm.WHOLE_DEVICE, nm.THIS_APP, nm.OFF):
        plan = nm.plan_apply(preset, snap)
        assert plan.confirm
        assert "192.168.1.5:8081" in plan.confirm
        assert plan.steps == []
    plan = nm.plan_apply(nm.OFF, snap, replace_external=True)
    assert plan.steps == [("clear_device_proxy",)]
    lane = replace(BASE, lanes={SPOT: "http://192.168.1.5:8081"})
    assert nm.plan_apply(nm.THIS_APP, lane).confirm
    plan = nm.plan_apply(nm.THIS_APP, lane, replace_external=True)
    assert plan.steps[:2] == [("disable_lane", SPOT), ("enable_lane", SPOT)]


def test_off_switches_off_only_sandroid_pieces():
    snap = replace(WHOLE, fritap=True, pinning="on")
    plan = nm.plan_apply(nm.OFF, snap, defeat_pinning=False)
    assert _names(plan) == ["clear_device_proxy", "kill_switch_off", "stop_fritap"]
    # Off leaves Mitmproxy, the CA and pinning alone (they route nothing).
    assert "inject_ca" not in _names(plan)
    assert "pinning" not in _names(plan)


def test_this_app_lane_goes_in_before_the_device_proxy_goes():
    plan = nm.plan_apply(nm.THIS_APP, replace(WHOLE, lanes={"x.y": "ours"}))
    names = _names(plan)
    assert names.index("enable_lane") < names.index("clear_device_proxy")
    assert ("disable_lane", "x.y") in plan.steps


def test_spotlight_and_friTap_preconditions():
    assert nm.plan_apply(nm.THIS_APP, replace(BASE, spotlight=None)).error
    off = nm.plan_apply(nm.KEYS_ONLY, replace(BASE, keys_only_available=False))
    assert "needs friTap support" in off.error
    plan = nm.plan_apply(nm.KEYS_ONLY, replace(WHOLE, fritap=False))
    assert _names(plan) == [
        "start_fritap_keys",
        "clear_device_proxy",
        "kill_switch_off",
    ]
    assert nm.plan_apply("custom", BASE).error


def test_execute_stops_at_the_first_failure():
    class Fake:
        def __init__(self):
            self.ran = []

        def run(self, step, serial):
            self.ran.append(step[0])
            return (step[0] != "prepare_guard", f"{step[0]} done")

    fake = Fake()
    ok, done, failure = nm.execute_plan(
        nm.plan_apply(nm.WHOLE_DEVICE, BASE), fake, "emulator-5570"
    )
    assert not ok
    assert fake.ran == ["prepare_guard"]
    assert failure.startswith("prepare guard")
    assert done == []


class _Recorder:
    def __init__(self):
        self.steps = []

    def run(self, step, serial):
        self.steps.append(step)
        return True, ""


def _service(monkeypatch, snapshot):
    rec = _Recorder()
    service = nm.NetworkMethodService(actions=rec)
    monkeypatch.setattr(service, "gather", lambda **kw: snapshot)
    monkeypatch.setattr(
        "sandroid.core.adb.Adb.get_target_device", staticmethod(lambda: "emulator-5570")
    )
    return service, rec


def test_service_apply_confirm_path_changes_nothing(monkeypatch):
    snap = replace(BASE, device_proxy="external", device_addr="192.168.1.5:8081")
    service, rec = _service(monkeypatch, snap)
    result = service.apply(nm.WHOLE_DEVICE)
    assert not result.ok
    assert result.confirm
    assert rec.steps == []
    assert service.view_cached().preset == nm.CUSTOM
    result = service.apply(nm.WHOLE_DEVICE, replace_external=True)
    assert result.ok
    assert [s[0] for s in rec.steps][:2] == ["prepare_guard", "set_device_proxy"]


def test_service_publishes_on_change(monkeypatch):
    from sandroid.core.events import EventBus, EventType

    service, _ = _service(monkeypatch, WHOLE)
    seen = []

    def handler(event):
        seen.append(event.data.get("change_type"))

    EventBus.get().subscribe(EventType.STATE_CHANGED, handler)
    try:
        service.refresh_now()
        service.refresh_now()  # unchanged: no second event
    finally:
        EventBus.get().unsubscribe(EventType.STATE_CHANGED, handler)
    assert seen == ["network_method"]


def test_fritap_reason_words():
    assert nm.FRITAP_REASONS["needs_consent"] == "needs consent to restart the app"
    assert "another start" in nm.FRITAP_REASONS["busy"]


def test_keys_only_uses_the_fritap_api(monkeypatch):
    from sandroid.analysis import fritap

    assert nm.keys_only_available()
    calls = []

    class Result(tuple):
        __slots__ = ()
        reason = "needs_consent"

    monkeypatch.setattr(
        fritap,
        "start_fritap_keys",
        lambda package=None, serial=None: (
            calls.append((package, serial)) or Result((False, "consent"))
        ),
    )
    ok, msg = nm.ServiceActions()._start_fritap_keys("emulator-5570", SPOT)
    assert calls == [(SPOT, "emulator-5570")]
    assert not ok
    assert msg == "needs consent to restart the app"
    monkeypatch.setattr(
        fritap, "fritap_running", lambda package=None: package in (None, SPOT)
    )
    assert nm._fritap_state(SPOT) == (True, True)
    assert nm._fritap_state("com.other") == (True, False)


def test_service_follows_bypass_state_listener(monkeypatch):
    from sandroid.analysis import detection_bypass

    added, removed = [], []
    fake = type(
        "B",
        (),
        {
            "add_state_listener": lambda self, cb: added.append(cb),
            "remove_state_listener": lambda self, cb: removed.append(cb),
        },
    )()
    monkeypatch.setattr(detection_bypass, "get_bypass_service", lambda: fake)
    service = nm.NetworkMethodService(actions=None)
    service.subscribe()
    assert added == [service._on_bypass_state]
    service.unsubscribe()
    assert removed == [service._on_bypass_state]


# -- Mitmproxy stop / restore / quit -------------------------------------------------


@pytest.fixture
def guard_on(monkeypatch):
    from sandroid.core import device_guard as dg

    guard = dg.DeviceGuard()
    guard._wanted["emulator-5570"] = dg._Wanted(kill_switch=True)
    monkeypatch.setattr(dg, "_INSTANCE", guard)
    return guard


def test_mitmproxy_stop_keeps_proxy_and_kill_switch(monkeypatch, guard_on):
    import threading

    from sandroid.services import mitmproxy_service as ms

    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._owned_device_proxy = OUR
    svc._owned_device_proxy_serial = "emulator-5570"
    svc._lock = threading.RLock()
    lines = []

    def emit(line):
        lines.append(line)
        svc._proc = None  # only the release decision is under test

    svc._listeners = [emit]
    released = []

    def release():
        released.append(1)
        svc._proc = None

    monkeypatch.setattr(svc, "release_device_proxy", release)
    svc._proc = object()
    svc.stop()
    assert released == []
    assert any("Kill switch stay" in line for line in lines)
    guard_on._wanted["emulator-5570"].kill_switch = False
    svc._proc = object()
    svc.stop()
    assert released == [1]


def test_snapshot_load_reapplies_the_proxy_behind_the_kill_switch(
    monkeypatch, guard_on
):
    """Mitmproxy stopped + Kill switch: the proxy is put back (traffic fails,
    nothing leaks), with the guard prepared before the proxy is set.
    """
    from sandroid.core import proxy_manager
    from sandroid.services import mitmproxy_service as ms

    order = []

    class PM:
        current = ""

        def get_proxy_settings(self):
            if not self.current:
                return proxy_manager.ProxyStatus.NOT_SET, None
            return (
                proxy_manager.ProxyStatus.SET,
                proxy_manager.ProxyConfig.from_string(self.current),
            )

        def set_proxy(self, config):
            order.append("set_proxy")
            PM.current = config.address
            return True, "ok"

    monkeypatch.setattr(proxy_manager, "ProxyManager", PM)
    monkeypatch.setattr(
        guard_on, "prepare", lambda *a, **k: order.append("prepare_guard")
    )
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._owned_device_proxy = OUR
    svc._owned_device_proxy_serial = "emulator-5570"
    svc._proc = None
    import threading

    svc._lock = threading.RLock()
    assert svc.reapply_device_proxy("emulator-5570") == "restored"
    assert order == ["prepare_guard", "set_proxy"]


def test_restore_checks_the_guard_after_a_load(monkeypatch):
    from sandroid.core import device_guard as dg
    from sandroid.services import proxy_restore as pr

    seen = []

    class Guard:
        def has_state(self, serial):
            return False

        def view_cached(self, serial):
            return dg.GuardView(kill_switch=True)

        def reconcile(self, serial, cause):
            seen.append((serial, cause))
            return dg.GuardView()

    monkeypatch.setattr(dg, "_INSTANCE", Guard())
    monkeypatch.setattr(pr, "_restore_lanes", lambda s, c: [])
    monkeypatch.setattr(pr, "_restore_ca", lambda s: "none")
    report = pr.restore_proxy_infra(
        "emulator-5570", "snapshot-load", device_proxy=False
    )
    assert seen == [("emulator-5570", "snapshot-load")]
    assert report.guard == "Kill switch removed (no device proxy)"
    # A re-attach checks for a leftover too (crash, a quit that timed out).
    seen.clear()
    pr.restore_proxy_infra("emulator-5570", "reconnect", device_proxy=False)
    assert seen == [("emulator-5570", "reconnect")]


def test_attach_with_nothing_set_up_still_removes_a_leftover(monkeypatch):
    """N2: the device-prepared hook checks for a leftover Kill switch even
    when this session set nothing up (and restores nothing else).
    """
    from sandroid.core import device_guard as dg
    from sandroid.services import proxy_restore as pr

    seen = []

    class Guard:
        def has_state(self, serial):
            return False

        def view_cached(self, serial):
            return dg.GuardView(kill_switch=True)

        def reconcile(self, serial, cause):
            seen.append((serial, cause))
            return dg.GuardView()

    monkeypatch.setattr(dg, "_INSTANCE", Guard())
    monkeypatch.setattr(pr, "_anything_desired", lambda serial: False)
    monkeypatch.setattr(
        pr,
        "restore_proxy_infra",
        lambda *a, **k: pytest.fail("nothing to restore: only the leftover check"),
    )
    pr._device_prepared_hook("emulator-5570", False)
    assert seen == [("emulator-5570", "reconnect")]


def test_quit_dialog_names_the_kill_switch(guard_on):
    from sandroid.tui.controllers.quit_controller import QuitController

    assert any("Kill switch" in note for note in QuitController._quit_notes())


# -- AI tools ------------------------------------------------------------------------


def test_ai_set_network_method_passes_the_confirmation(monkeypatch):
    from sandroid.ai.tools import session_control as sc

    calls = []

    class Svc:
        def apply(self, method, **kw):
            calls.append((method, kw))
            return nm.ApplyResult(
                False, "replace?", confirm="replace?", view=nm.derive_method(BASE)
            )

    monkeypatch.setattr(nm, "get_network_method_service", lambda: Svc())
    out = sc.set_network_method("whole_device")
    assert out["needs_confirmation"] is True
    assert out["success"] is False
    assert calls == [
        ("whole_device", {"defeat_pinning": None, "replace_external": False})
    ]
    from sandroid.ai.errors import ToolExecutionError

    with pytest.raises(ToolExecutionError):
        sc.set_network_method("custom")


def test_ai_tools_are_registered_with_their_risk():
    import sandroid.ai.tools
    from sandroid.ai.tools.registry import RiskTier, get_tool_registry

    registry = get_tool_registry()
    risks = {
        name: registry.get_spec(name).risk
        for name in (
            "get_network_method",
            "set_network_method",
            "get_kill_switch",
            "set_kill_switch",
        )
    }
    assert risks == {
        "get_network_method": RiskTier.READ_ONLY,
        "set_network_method": RiskTier.CONSEQUENTIAL,
        "get_kill_switch": RiskTier.READ_ONLY,
        "set_kill_switch": RiskTier.CONSEQUENTIAL,
    }


# -- review fixes (NETMETHOD-FIX-LIST) ---------------------------------------------


def _spec(name):
    import sandroid.ai.tools
    from sandroid.ai.tools.registry import get_tool_registry

    return get_tool_registry().get_spec(name)


def _remembered(name, args):
    """The rule "Yes, don't ask again" would save, parsed (None: none)."""
    from sandroid.ai.tool_permissions import PermissionRule, suggest_rule

    spec = _spec(name)
    text = suggest_rule(
        name,
        args,
        permission_key=spec.permission_key,
        can_remember_choice=spec.can_remember_choice,
    )
    return PermissionRule.parse(text) if text else None


def test_remembered_method_never_covers_replacing_an_external_proxy():
    """N1: a remembered whole_device approval does not auto-approve
    replace_external=true (the real permission ``matches``), and a call
    without the argument cannot be remembered at all.
    """
    name = "set_network_method"
    rule = _remembered(name, {"method": "whole_device", "replace_external": False})
    assert rule is not None
    assert rule.matches(name, {"method": "whole_device", "replace_external": False})
    assert not rule.matches(name, {"method": "whole_device", "replace_external": True})
    assert not rule.matches(name, {"method": "whole_device"})
    assert _remembered(name, {"method": "whole_device"}) is None


def test_store_asks_again_for_replace_external(tmp_path):
    """N1 end to end through the permission store's resolution."""
    from sandroid.ai.tool_permissions import ToolPermissionStore
    from sandroid.ai.tools.registry import RiskTier

    spec = _spec("set_network_method")
    store = ToolPermissionStore(tmp_path / "perm.toml")
    store.add_allow_rule(
        str(
            _remembered(
                spec.name, {"method": "whole_device", "replace_external": False}
            )
        )
    )

    def resolve(args):
        return store.resolve(
            spec.name,
            RiskTier.CONSEQUENTIAL,
            args,
            permission_key=spec.permission_key,
            can_remember_choice=spec.can_remember_choice,
        ).outcome

    assert resolve({"method": "whole_device", "replace_external": False}) == "allow"
    assert resolve({"method": "whole_device", "replace_external": True}) == "ask"


def test_kill_switch_and_its_removal_are_never_remembered(monkeypatch):
    """N1: set_kill_switch is a fresh confirmation every time, and the
    rememberable clear_device_proxy refuses while the Kill switch is on
    (clearing the proxy would remove it).
    """
    from sandroid.ai.tools import session_control as sc
    from sandroid.core import device_guard as dg

    assert _remembered("set_kill_switch", {"enabled": False}) is None
    assert _remembered("set_kill_switch", {"enabled": True}) is None

    cleared = []
    monkeypatch.setattr(
        "sandroid.services.get_proxy_service",
        lambda: SimpleNamespace(clear_proxy=lambda: cleared.append(1) or True),
    )
    guard = dg.DeviceGuard()
    monkeypatch.setattr(dg, "_INSTANCE", guard)
    monkeypatch.setattr(dg.Adb, "get_target_device", staticmethod(lambda: "emu-1"))
    guard._wanted["emu-1"] = dg._Wanted(kill_switch=True)
    out = sc.clear_device_proxy()
    assert out["success"] is False
    assert out["needs_confirmation"] is True
    assert "set_kill_switch" in out["message"]
    assert cleared == []
    # A Kill switch seen on the device (adopted leftover) counts too.
    guard._wanted["emu-1"] = dg._Wanted(kill_switch=False)
    monkeypatch.setattr(
        guard, "refresh", lambda serial, **kw: dg.GuardView(kill_switch=True)
    )
    assert sc.clear_device_proxy()["success"] is False
    assert cleared == []


def test_presets_without_a_proxy_remove_an_orphaned_kill_switch():
    """N2: a Kill switch whose device proxy is gone (all apps offline): Off,
    This app and keys only remove it.
    """
    orphan = replace(BASE, kill_switch=True)
    assert nm.plan_apply(nm.OFF, orphan).steps == [("kill_switch_off",)]
    this_app = nm.plan_apply(nm.THIS_APP, orphan).steps
    assert this_app.index(("enable_lane", SPOT)) < this_app.index(("kill_switch_off",))
    assert ("kill_switch_off",) in nm.plan_apply(nm.KEYS_ONLY, orphan).steps
    assert "Off removes it" in nm.derive_method(orphan).problems[0]
    # Nothing to remove: no step.
    assert nm.plan_apply(nm.OFF, BASE).steps == []


class _Failing:
    """Fake actions: *fail* step fails, the rest succeed; records the steps."""

    def __init__(self, fail):
        self.fail = fail
        self.steps = []

    def run(self, step, serial):
        self.steps.append(step)
        return (
            step[0] != self.fail,
            f"{step[0]} {'failed' if step[0] == self.fail else 'done'}",
        )


def test_failed_whole_device_rolls_the_kill_switch_back(monkeypatch):
    """N2: prepare_guard installed the Kill switch, then the proxy was not
    set: the Kill switch goes back to what it was (never apps offline).
    """
    from sandroid.core import device_guard as dg

    rolled = []

    class Guard:
        def rollback_prepare(self, serial, kill_switch):
            rolled.append((serial, kill_switch))
            return dg.GuardView()

    monkeypatch.setattr(dg, "_INSTANCE", Guard())
    for fail, expected in (
        ("set_device_proxy", [("emulator-5570", False)]),
        ("prepare_guard", [("emulator-5570", False)]),
        ("disable_lane", []),  # the proxy is set: the Kill switch is right
    ):
        rolled.clear()
        snap = replace(BASE, lanes={"x.y": "ours"})
        service = nm.NetworkMethodService(actions=_Failing(fail))
        monkeypatch.setattr(service, "gather", lambda snap=snap, **kw: snap)
        monkeypatch.setattr(
            "sandroid.core.adb.Adb.get_target_device",
            staticmethod(lambda: "emulator-5570"),
        )
        result = service.apply(nm.WHOLE_DEVICE)
        assert not result.ok
        assert rolled == expected, fail
        if expected:
            assert "Kill switch removed again" in " ".join(result.done)
    # A Kill switch that was on before stays on (on the real proxy).
    rolled.clear()
    snap = replace(
        BASE, kill_switch=True, device_proxy="external", device_addr="1.2.3.4:8"
    )
    service = nm.NetworkMethodService(actions=_Failing("set_device_proxy"))
    monkeypatch.setattr(service, "gather", lambda **kw: snap)
    service.apply(nm.WHOLE_DEVICE, replace_external=True)
    assert rolled == [("emulator-5570", True)]


def test_whole_device_takes_over_our_existing_proxy(monkeypatch):
    """N8: our proxy is already set (an earlier session): Whole device takes
    ownership, so Mitmproxy stop keeps it and quit clears it.
    """
    from sandroid.services import mitmproxy_service as ms

    noted = []
    monkeypatch.setattr(
        ms,
        "get_mitmproxy_service",
        lambda: SimpleNamespace(
            note_device_proxy=lambda a, s=None: noted.append((a, s))
        ),
    )
    snap = replace(WHOLE, kill_switch=False)
    plan = nm.plan_apply(nm.WHOLE_DEVICE, snap)
    assert plan.steps[-1] == ("own_device_proxy", OUR)
    assert "set_device_proxy" not in _names(plan)
    assert nm.ServiceActions().run(("own_device_proxy", OUR), "emu-1") == (True, "")
    assert noted == [(OUR, "emu-1")]


def test_frida_steps_never_run_pinned(monkeypatch):
    """N9: friTap and the bypass run on the SELECTED device's Frida session:
    their steps are never inside Adb.targeting (which only fools their
    device check); proxy steps stay pinned.
    """
    from sandroid.core.adb import Adb

    seen = {}
    actions = nm.ServiceActions()
    names = ("pinning", "stop_fritap", "start_fritap_keys", "start_app")
    for name in (*names, "clear_device_proxy"):

        def record(serial, *args, name=name):
            seen[name] = Adb.get_target_device()
            return True, ""

        monkeypatch.setattr(actions, f"_{name}", record)
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    for step in (
        ("pinning", True),
        ("stop_fritap",),
        ("start_fritap_keys", SPOT),
        ("start_app",),
        ("clear_device_proxy",),
    ):
        actions.run(step, "emulator-5570")
    assert {name: seen[name] for name in names} == dict.fromkeys(names, "emulator-5554")
    assert seen["clear_device_proxy"] == "emulator-5570"


def test_frida_presets_are_refused_for_another_device(monkeypatch):
    """N9: keys only / pinning on a serial that is not the selected device
    is refused in plain words; proxy-only presets still run there.
    """
    from sandroid.core.adb import Adb

    rec = _Recorder()
    service = nm.NetworkMethodService(actions=rec)
    monkeypatch.setattr(
        service, "gather", lambda **kw: replace(WHOLE, kill_switch=False)
    )
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    result = service.apply(nm.KEYS_ONLY, serial="emulator-5570")
    assert not result.ok
    assert "selected device" in result.message
    assert "emulator-5570" in result.message
    assert rec.steps == []
    result = service.apply(nm.WHOLE_DEVICE, defeat_pinning=True, serial="emulator-5570")
    assert not result.ok
    assert rec.steps == []
    assert service.apply(nm.OFF, serial="emulator-5570").ok
    assert rec.steps  # proxy steps only: allowed on another device


def test_pinning_state_is_per_spotlight_app(monkeypatch):
    """N16: another app's live SSL bypass does not show as "on" for the new
    spotlight app; one set for its next start shows as "set".
    """
    from sandroid.analysis import detection_bypass

    fake = SimpleNamespace(
        target_app=lambda cat: "com.previous",
        carried_categories=lambda pkg: {"ssl"} if pkg == "com.previous" else set(),
    )
    monkeypatch.setattr(detection_bypass, "get_bypass_service", lambda: fake)
    assert nm._pinning_state("com.previous") == "on"
    assert nm._pinning_state(SPOT) == "off"
    fake.carried_categories = lambda pkg: {"ssl"}
    assert nm._pinning_state(SPOT) == "set"
    assert nm._pinning_state(None) == "off"


def test_keys_only_with_pinning_starts_a_stopped_app_with_the_bypass():
    """N17: pinning first (set for the start), the app start with the bypass
    in its spawn bundle, then friTap attaches to the running app.
    """
    plan = nm.plan_apply(nm.KEYS_ONLY, BASE, defeat_pinning=True)
    assert _names(plan)[:3] == ["pinning", "start_app", "start_fritap_keys"]
    # friTap already on the app: no start, pinning applies live.
    plan = nm.plan_apply(nm.KEYS_ONLY, KEYS, defeat_pinning=True)
    assert "start_app" not in _names(plan)
    assert _names(plan)[-1] == "pinning"


def test_start_app_step_leaves_a_running_app_alone(monkeypatch):
    from sandroid.services import app_start

    started = []
    monkeypatch.setattr(nm, "_spotlight", lambda: SPOT)
    monkeypatch.setattr(
        app_start, "start_app", lambda: started.append(1) or (True, "started")
    )
    monkeypatch.setattr(
        app_start, "probe_liveness", lambda pkg: (app_start.Liveness.RUNNING, 42)
    )
    assert nm.ServiceActions._start_app(None) == (True, "")
    assert started == []
    monkeypatch.setattr(
        app_start, "probe_liveness", lambda pkg: (app_start.Liveness.NOT_RUNNING, None)
    )
    assert nm.ServiceActions._start_app(None) == (True, "started")
    assert started == [1]


def test_fritap_started_by_hand_needs_a_confirmation():
    """N18: a full friTap the user started (h) is not silently stopped."""
    snap = replace(WHOLE, fritap=True, fritap_by_hand=True)
    plan = nm.plan_apply(nm.OFF, snap)
    assert plan.steps == []
    assert "friTap was started by hand" in plan.confirm
    plan = nm.plan_apply(nm.OFF, snap, replace_external=True)
    assert ("stop_fritap",) in plan.steps
    # The Network method's own keys-only friTap: no question.
    assert not nm.plan_apply(nm.OFF, replace(snap, fritap_by_hand=False)).confirm


def test_confirmation_words_name_what_is_replaced():
    """N3-B4: friTap gets its own title, buttons and declined toast, not
    "Replace the external proxy?" / "External proxy kept".
    """
    fritap = nm.plan_apply(nm.OFF, replace(KEYS, fritap_by_hand=True))
    assert fritap.confirm_title == "Stop friTap?"
    assert (fritap.confirm_yes, fritap.confirm_no) == ("Stop friTap", "Keep")
    assert "proxy" not in fritap.confirm_kept.lower()
    ext = replace(BASE, device_proxy="external", device_addr="192.168.1.5:8081")
    proxy = nm.plan_apply(nm.WHOLE_DEVICE, ext)
    assert proxy.confirm_title == "Replace the external proxy?"
    assert proxy.confirm_yes == "Replace"
    assert proxy.confirm_kept.startswith("External proxy kept")
    both = nm.plan_apply(nm.OFF, replace(ext, fritap=True, fritap_by_hand=True))
    assert both.confirm_title == "Replace the external proxy and stop friTap?"
    assert both.confirm_yes == "Continue"


def test_tui_confirm_uses_the_plan_words(monkeypatch):
    from sandroid.tui.modals import proxy_modal

    result = nm.ApplyResult(
        False,
        "x",
        confirm="friTap was started by hand. Continue?",
        confirm_title="Stop friTap?",
        confirm_yes="Stop friTap",
        confirm_no="Keep",
        confirm_kept="friTap keeps running; nothing changed",
    )
    monkeypatch.setattr(
        proxy_modal,
        "_method_service",
        lambda: SimpleNamespace(apply=lambda *a, **k: result),
    )
    pushed, toasts = [], []

    class _App:
        def notify(self, message, **_kw):
            toasts.append(message)

        def call_from_thread(self, fn, *args):
            fn(*args)

        def push_screen(self, screen, callback):
            pushed.append(screen)
            callback(False)

    import threading

    monkeypatch.setattr(threading.Thread, "start", lambda self: self.run())
    proxy_modal.run_method_apply(_App(), nm.OFF, None)
    modal = pushed[0]
    assert modal.title_text == "Stop friTap?"
    assert (modal.yes_label, modal.no_label) == ("Stop friTap", "Keep")
    assert toasts[-1] == "friTap keeps running; nothing changed"


def test_stop_step_names_a_by_hand_fritap(monkeypatch):
    from sandroid.analysis import fritap

    instance = object()
    monkeypatch.setattr(nm, "_fritap_instance", lambda: instance)
    monkeypatch.setattr(nm, "_OUR_FRITAP", None)
    monkeypatch.setattr(fritap, "stop_fritap", lambda: True)
    monkeypatch.setattr(fritap, "fritap_running", lambda package=None: False)
    assert nm.ServiceActions._stop_fritap(None) == (
        True,
        "friTap (started by hand) stopped",
    )
    monkeypatch.setattr(nm, "_OUR_FRITAP", id(instance))
    assert nm.ServiceActions._stop_fritap(None) == (True, "friTap stopped")


def test_status_line_never_claims_apps_named_when_some_are_not():
    """N3/N21/N12/N19: the line in words for partial or broken naming, a
    dead relay without the Kill switch, IPv4-only Kill switch, SDK runtime.
    """
    partial = nm.derive_method(replace(WHOLE, attribution="partial", unnamed_apps=2))
    assert "apps named" not in partial.covered
    assert "2 apps not named yet (repairing)" in partial.problems
    failed = nm.derive_method(replace(WHOLE, attribution="failed"))
    assert "apps not named (identity relay not running)" in failed.problems
    direct = nm.derive_method(
        replace(
            WHOLE, kill_switch=False, attribution="failed", naming_problem="relay_down"
        )
    )
    assert direct.preset == nm.CUSTOM
    assert any("go direct past Mitmproxy" in p for p in direct.problems)
    v4 = nm.derive_method(replace(WHOLE, ks_ipv6=False))
    assert "Kill switch covers IPv4 only (no ip6tables on the device)" in v4.problems
    ok = nm.derive_method(WHOLE)
    assert "apps named" in ok.covered
    assert "SDK runtime processes not named" in ok.notes
    for view in (partial, failed, direct, v4, ok):
        assert not _GLYPHS.search(view.line())
        assert " arm" not in view.line()


def test_restore_registers_the_reverse_before_the_proxy(monkeypatch, guard_on):
    """N15: for a 127.0.0.1 proxy the adb reverse goes in before the proxy
    write (whose guard check would else read it as someone else's proxy and
    stop the relay for a moment).
    """
    import threading

    from sandroid.core import proxy_manager
    from sandroid.core.adb import Adb
    from sandroid.services import mitmproxy_service as ms

    order = []

    class PM:
        def get_proxy_settings(self):
            return proxy_manager.ProxyStatus.NOT_SET, None

        def set_proxy(self, config):
            order.append("set_proxy")
            return True, "ok"

    monkeypatch.setattr(proxy_manager, "ProxyManager", PM)
    monkeypatch.setattr(proxy_manager, "_reverse_registered", lambda port: False)
    monkeypatch.setattr(
        Adb, "reverse", staticmethod(lambda *a, **k: order.append("reverse"))
    )
    monkeypatch.setattr(guard_on, "prepare", lambda *a, **k: order.append("prepare"))
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._owned_device_proxy = "127.0.0.1:8080"
    svc._owned_device_proxy_serial = "emulator-5570"
    svc._proc = None
    svc._lock = threading.RLock()
    assert svc.reapply_device_proxy("emulator-5570") == "restored"
    assert order == ["reverse", "prepare", "set_proxy"]


def test_mitmproxy_shutdown_never_waits_long_for_the_guard(monkeypatch):
    """N10: a quit teardown that is still running (abandoned after its time
    box) must not block Mitmproxy's own shutdown: it waits a bounded time.
    """
    import threading

    from sandroid.core import device_guard as dg
    from sandroid.services import mitmproxy_service as ms

    calls = []

    class Guard:
        def begin_shutdown(self):
            calls.append("closing")

        def serials_with_state(self):
            return ["emulator-5570"]

        def teardown(self, serial, **kw):
            calls.append((serial, kw))
            return False

    monkeypatch.setattr(dg, "_INSTANCE", Guard())
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._proc = None
    svc._lock = threading.RLock()
    monkeypatch.setattr(svc, "release_device_proxy", lambda *a, **k: False)
    svc.shutdown(timeout=0.1)
    assert calls == ["closing", ("emulator-5570", {"lock_timeout": 1.0})]


def test_app_proxy_lanes_are_read_per_device():
    """N14: a lane on device A must not make device B show Custom (and B's
    "Whole device" must not try to remove it).
    """
    import threading

    from sandroid.core import proxy_manager as pm

    focus = pm.FocusManager.__new__(pm.FocusManager)
    focus._lock = threading.RLock()
    focus._lanes = {0: "com.a", 1: "com.b"}
    focus._lane_targets = {}
    focus._lane_serials = {0: "emulator-5570", 1: "emulator-5572"}
    focus._routes_cache = {}
    assert focus.app_proxies_cached() == {"com.a": "ours", "com.b": "ours"}
    assert focus.app_proxies_cached("emulator-5570") == {"com.a": "ours"}
    assert focus.app_proxies_cached("emulator-9999") == {}


def test_unnamed_device_flow_triggers_a_throttled_refresh(monkeypatch):
    """N3: a device-proxy flow without a name while apps are named (an app
    installed later) re-reads the app list soon, at most every 30 s.
    """
    service = nm.NetworkMethodService(actions=None)
    service._store(WHOLE)
    kicked = []
    monkeypatch.setattr(service, "refresh", lambda **kw: kicked.append(1))
    line = "[FLOW]|12:00:00|HTTPS/1.1|200|GET|example.org/|1 KB||device"
    service._on_mitm_line(line)
    service._on_mitm_line(line)
    assert kicked == [1]
    named = "[FLOW]|12:00:00|HTTPS/1.1|200|GET|example.org/|1 KB|a.b|device"
    lane = "[FLOW]|12:00:00|HTTPS/1.1|200|GET|example.org/|1 KB||app-proxy"
    service._unnamed_at = -1e9
    service._on_mitm_line(named)
    service._on_mitm_line(lane)
    assert kicked == [1]


# -- re-E2E fixes (e2e-netmethod-2.md) ---------------------------------------------


def test_quit_during_an_apply_leaves_nothing_behind(monkeypatch):
    """B1: quit while Whole device is half way: the apply stops between two
    steps, the guard refuses every install once its teardown started, and
    a refresh worker never relaunches the relay afterwards.
    """
    import threading

    from sandroid.core import device_guard as dg
    from sandroid.tui.controllers import quit_controller as qc

    guard = dg.DeviceGuard()
    installs = []
    monkeypatch.setattr(dg, "_INSTANCE", guard)
    monkeypatch.setattr(
        guard,
        "_apply_locked",
        lambda serial, endpoint, ours, obs: installs.append(serial) or dg.GuardView(),
    )
    monkeypatch.setattr(guard, "_root", lambda serial: True)
    monkeypatch.setattr(guard, "_publish", staticmethod(lambda serial: None))
    removed = []
    monkeypatch.setattr(
        guard, "_observe", lambda serial, uids: dg.parse_guard_observation("rc=0")
    )
    monkeypatch.setattr(guard, "_run", lambda serial, cmds: removed.extend(cmds) or [])

    in_step = threading.Event()
    release = threading.Event()
    ran = []

    class Actions:
        def run(self, step, serial):
            ran.append(step[0])
            if step[0] == "prepare_guard":
                guard.prepare(
                    serial,
                    dg.Endpoint("10.0.2.2", 8080),
                    kill_switch=True,
                )
                in_step.set()
                release.wait(5)
            if step[0] == "set_device_proxy":
                # The proxy write's follow-up: refused once quitting.
                guard.after_device_proxy_write(serial, "10.0.2.2:8080")
            return True, step[0]

    service = nm.NetworkMethodService(actions=Actions())
    monkeypatch.setattr(service, "gather", lambda **kw: BASE)
    monkeypatch.setattr(nm, "_INSTANCE", service)
    monkeypatch.setattr(
        "sandroid.core.adb.Adb.get_target_device",
        staticmethod(lambda: "emulator-5570"),
    )
    results = []
    worker = threading.Thread(
        target=lambda: results.append(service.apply(nm.WHOLE_DEVICE))
    )
    worker.start()
    assert in_step.wait(5)
    installs.clear()  # prepare_guard ran before the quit
    quitter = threading.Thread(target=lambda: qc.shutdown_network(timeout=2.0))
    quitter.start()
    for _ in range(100):
        if guard.closing or service._abort.is_set():
            break
        threading.Event().wait(0.01)
    release.set()
    worker.join(5)
    quitter.join(10)
    assert results
    assert not results[0].ok
    assert "set_device_proxy" not in ran  # stopped between steps
    assert installs == []  # nothing installed after the quit started
    assert guard.closing
    # A refresh worker after the quit: no repair, no relay launch.
    assert service.apply(nm.WHOLE_DEVICE).message == "Sandroid is quitting"
    guard._named_for["emulator-5570"] = dg.Endpoint("10.0.2.2", 8080)
    monkeypatch.setattr(
        guard,
        "_observe",
        lambda serial, uids: dg.parse_guard_observation(
            "DP -A sandroid_dp -p tcp -m owner --uid-owner 10215 -j REDIRECT "
            "--to-ports 61000\nPROXY 10.0.2.2:8080\nrc=0"
        ),
    )
    guard.refresh("emulator-5570", repair=True)
    assert installs == []


def test_guard_refuses_installs_once_closing(monkeypatch):
    from sandroid.core import device_guard as dg

    guard = dg.DeviceGuard()
    monkeypatch.setattr(
        guard, "_apply_locked", lambda *a: pytest.fail("installed while quitting")
    )
    guard.begin_shutdown()
    guard.prepare("emu-1", dg.Endpoint("10.0.2.2", 8080), kill_switch=True)
    guard.after_device_proxy_write("emu-1", "10.0.2.2:8080")
    ok, _msg = guard.set_kill_switch(False, "emu-1")
    assert guard.view_cached("emu-1") == dg.GuardView()


def test_new_android_user_is_reported_and_covered():
    """B2: a user created after Whole device: the line says it is not
    covered (no plain "direct traffic refused"), and the repair adds it.
    """
    snap = replace(WHOLE, uncovered_users=(11,))
    view = nm.derive_method(snap)
    assert "not covered: Android user 11 (repairing)" in view.problems
    assert "direct traffic refused" not in view.covered
    assert "direct traffic refused for the covered users" in view.covered


def test_remembering_replace_external_is_impossible(tmp_path):
    """B3 with the real permission store: (a) no "don't ask again" for
    replace_external=true and no allow rule covers it; (b) a rule on
    ``method`` only (the old suggestion, or written by hand) never matches a
    multi-key tool.
    """
    from sandroid.ai.tool_permissions import ToolPermissionStore
    from sandroid.ai.tools.registry import RiskTier

    spec = _spec("set_network_method")
    true_args = {"method": "whole_device", "replace_external": True}
    false_args = {"method": "whole_device", "replace_external": False}
    assert _remembered(spec.name, true_args) is None
    store = ToolPermissionStore(tmp_path / "perm.toml")

    def resolve(args):
        return store.resolve(
            spec.name,
            RiskTier.CONSEQUENTIAL,
            args,
            permission_key=spec.permission_key,
            can_remember_choice=spec.can_remember_choice,
        )

    assert resolve(true_args).suggested_rule is None
    store.add_allow_rule(
        "set_network_method(method=whole_device, replace_external=true)"
    )
    store.add_allow_rule("set_network_method(method=whole_device)")
    assert resolve(true_args).outcome == "ask"
    assert resolve(false_args).outcome == "ask"  # the method-only rule is void
    store.add_allow_rule(
        "set_network_method(method=whole_device, replace_external=false)"
    )
    assert resolve(false_args).outcome == "allow"
    assert resolve(true_args).outcome == "ask"


def test_dead_relay_shows_its_real_effect():
    """B4: a dead relay refuses every proxy connection; a missing jump only
    leaves apps unnamed: the line says which.
    """
    down = nm.derive_method(
        replace(WHOLE, attribution="failed", naming_problem="relay_down")
    )
    assert (
        "device proxy connections refused: identity relay down, repairing "
        "(apps have no network meanwhile)" in down.problems
    )
    jump = nm.derive_method(
        replace(WHOLE, attribution="failed", naming_problem="jump_missing")
    )
    assert "apps not named (the proxy-port rule is missing, repairing)" in (
        jump.problems
    )


def test_health_check_runs_only_while_our_proxy_is_on(monkeypatch):
    """B4: the subscribed service re-checks every HEALTH_S on a worker while
    Whole device is on, so a dead relay is repaired on any tab.
    """
    import threading

    service = nm.NetworkMethodService(actions=None)
    service._subscribed = True
    monkeypatch.setattr(service, "HEALTH_S", 0.01)
    kicked = threading.Event()
    monkeypatch.setattr(service, "refresh", lambda **kw: kicked.set())
    service._store(BASE)
    assert service._health is None  # Off: no checks
    service._store(WHOLE)
    assert kicked.wait(2)
    service._abort.set()
    service._health.join(2)
    assert not service._health.is_alive()


def test_apply_on_another_device_reports_that_device(monkeypatch):
    """B5: apply(serial=X) returns X's method and never replaces the selected
    device's line; the CA state is kept per device.
    """
    from sandroid.core.adb import Adb

    rec = _Recorder()
    service = nm.NetworkMethodService(actions=rec)
    service._store(WHOLE)
    other = replace(BASE)
    monkeypatch.setattr(service, "gather", lambda **kw: other)
    monkeypatch.setattr(Adb, "_target_device", "emulator-5570")
    result = service.apply(nm.OFF, serial="emulator-5572")
    assert result.view.preset == nm.OFF
    assert result.message == "Network method: Off"
    assert service.view_cached().preset == nm.WHOLE_DEVICE  # 5570 untouched
    service.note_ca(False, "emulator-5572")
    service.note_ca(True, "emulator-5570")
    assert service._ca == {"emulator-5572": "missing", "emulator-5570": "installed"}


def test_step_messages_reach_the_ai_in_plain_words():
    """O1: messages from other services lose their symbols and "armed"."""
    text = nm.plain_words(
        "SSL Pinning Bypass (experimental) armed \u2014 \u2423 starts de.fkie.x with it"
    )
    assert "armed" not in text
    assert text == (
        "SSL Pinning Bypass (experimental) set for the next app start - Space "
        "starts de.fkie.x with it"
    )
    assert nm.plain_words("App proxy \u2192 com.x (lane 0)") == (
        "App proxy to com.x (lane 0)"
    )

    class Actions:
        def run(self, step, serial):
            return True, "App proxy \u2192 com.x"

    _ok, done, _ = nm.execute_plan(nm.ApplyPlan(steps=[("x",)]), Actions(), None)
    assert done == ["App proxy to com.x"]


def test_keys_only_takes_the_proxy_away_before_the_app_starts():
    """O2: the app's first requests must not go through Mitmproxy."""
    plan = nm.plan_apply(nm.KEYS_ONLY, WHOLE, defeat_pinning=True)
    names = _names(plan)
    assert names.index("clear_device_proxy") < names.index("start_app")
    assert names.index("kill_switch_off") < names.index("start_app")
    assert names[-1] == "start_fritap_keys"
