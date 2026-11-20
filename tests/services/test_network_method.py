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


def test_kill_switch_without_proxy_is_a_problem():
    view = nm.derive_method(replace(BASE, kill_switch=True))
    assert view.preset == nm.CUSTOM
    assert "Kill switch without a device proxy" in view.problems[0]


def test_pinning_notes():
    assert "pinning not bypassed" in nm.derive_method(WHOLE).notes
    assert "pinning bypassed" in nm.derive_method(replace(THIS, pinning="on")).notes
    armed = nm.derive_method(replace(THIS, pinning="armed")).line()
    assert "pinning bypass armed" in armed


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
    assert plan.steps == [("prepare_guard", OUR)]  # re-check, nothing else
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
    assert _names(plan) == ["clear_device_proxy", "stop_fritap"]
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
    assert _names(plan) == ["start_fritap_keys", "clear_device_proxy"]
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


def test_keys_only_is_disabled_without_the_fritap_api(monkeypatch):
    from sandroid.analysis import fritap

    monkeypatch.delattr(fritap, "start_fritap_keys", raising=False)
    assert not nm.keys_only_available()
    monkeypatch.setattr(
        fritap, "start_fritap_keys", lambda **kw: (True, "ok"), raising=False
    )
    assert nm.keys_only_available()


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
    # Not a load and nothing set up: no device read at all.
    seen.clear()
    pr.restore_proxy_infra("emulator-5570", "reconnect", device_proxy=False)
    assert seen == []


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
