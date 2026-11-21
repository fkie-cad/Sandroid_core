"""The device-actions registry (``services/device_actions.py``) with a stub adb.

Every action is validated before any adb call, pinned to one serial, sends
the exact adb / emulator-console commands asserted here and writes one
``action`` line on the session timeline. Nothing reaches a device: the adb
layer is replaced by a recorder.
"""

from __future__ import annotations

import itertools
import threading
from datetime import datetime
from types import SimpleNamespace

import pytest

from sandroid.core import timeline
from sandroid.core.adb import Adb
from sandroid.services import device_actions as da

EMU = "emulator-5562"
PHONE = "R58M12345"

#: Every session-timeline line of the running test.
_CAPTURED: list[dict] = []


@pytest.fixture(autouse=True)
def _timeline_capture():
    _CAPTURED.clear()
    with timeline.capture():
        timeline.get_timeline()._capture_out = _CAPTURED
        yield
    da.stop_jobs()
    da._LAST_CALL.clear()


@pytest.fixture
def adb(monkeypatch):
    """Record ``(command, serial)`` of every adb call.

    ``.replies`` maps a command prefix to ``(stdout, stderr)`` or to a
    list of them (one per call, the last repeats); default: ``OK``.
    """
    calls: list[tuple[str, str | None]] = []
    replies: dict[str, object] = {}

    def fake_send(command, serial=None, timeout=30):
        calls.append((command, serial))
        for prefix, reply in replies.items():
            if command.startswith(prefix):
                if isinstance(reply, list):
                    return reply.pop(0) if len(reply) > 1 else reply[0]
                return reply
        return "OK\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    monkeypatch.setattr(da, "_sleep", lambda s: None)
    return SimpleNamespace(
        calls=calls,
        replies=replies,
        commands=lambda: [c for c, _s in calls],
    )


def _action_lines() -> list[dict]:
    return [line for line in _CAPTURED if line["src"] == "action"]


# -- the registry ------------------------------------------------------------


def test_registry_lists_every_planned_action_with_plain_titles():
    ids = [a.id for a in da.list_actions()]
    assert ids == [
        "sms.receive",
        "call.incoming",
        "call.accept",
        "call.hangup",
        "call.outgoing",
        "gps.fix",
        "gps.route",
        "time.jump",
        "time.reset",
        "power.battery",
        "power.charging",
        "power.ac",
        "net.wifi",
        "net.data",
        "net.airplane",
        "net.profile",
    ]
    for action in da.list_actions():
        assert action.title
        assert action.group
        assert action.help
        for text in (action.title, action.help, *(p.label for p in action.params)):
            for glyph in ("✓", "✗", "▸", "⇧", "␣", "⏎", "←", "→", "•"):
                assert glyph not in text
        described = action.describe()
        assert described["id"] == action.id
        assert [p["name"] for p in described["params"]] == [
            p.name for p in action.params
        ]


def test_physical_device_actions_are_the_non_emulator_ones():
    allowed = {a.id for a in da.list_actions() if not a.emulator_only}
    assert allowed == {
        "call.hangup",
        "call.outgoing",
        "time.jump",
        "time.reset",
        "net.wifi",
        "net.data",
        "net.airplane",
    }


# -- SMS ---------------------------------------------------------------------


def test_sms_from_a_letter_sender_sends_the_exact_console_command(adb):
    result = da.run_action(
        "sms.receive", EMU, {"sender": "DHL", "text": "Ihr Paket kommt heute"}
    )

    assert result.ok, result
    assert result.message == 'SMS received from DHL: "Ihr Paket kommt heute"'
    assert adb.calls == [("emu sms send DHL Ihr Paket kommt heute", EMU)]
    (line,) = _action_lines()
    assert line["kind"] == "sms-receive"
    assert line["summary"] == result.message
    assert line["dev"] == EMU
    assert line["actor"] == "user"
    assert line["level"] == "info"
    assert line["data"]["params"] == {"sender": "DHL", "text": "Ihr Paket kommt heute"}
    assert line["data"]["sender_type"] == "alphanumeric"
    assert line["data"]["commands"] == ["emu sms send DHL Ihr Paket kommt heute"]


def test_sms_number_sender_is_normalised_and_text_whitespace_collapsed(adb):
    result = da.run_action(
        "sms.receive", EMU, {"sender": "+49 151 123-456", "text": "Code\n  123456 "}
    )
    assert result.ok
    assert adb.commands() == ["emu sms send +49151123456 Code 123456"]
    assert _action_lines()[0]["data"]["sender_type"] == "number"


@pytest.mark.parametrize(
    ("sender", "reason"),
    [
        ("Shop24", "letters and digits mixed"),
        ("O2", "letters and digits mixed"),
        ("Sparkasse-Info", "letters only"),
        ("Pay Pal", "letters only"),
        ("ABCDEFGHIJKL", "at most 11 letters"),
        ("", "enter a value"),
    ],
)
def test_bad_sms_senders_are_refused_before_any_adb_call(adb, sender, reason):
    result = da.run_action("sms.receive", EMU, {"sender": sender, "text": "hi"})
    assert not result.ok
    assert result.refused
    assert reason in result.message
    assert adb.calls == []
    assert _action_lines() == []


def test_sms_text_limits(adb):
    assert da.run_action("sms.receive", EMU, {"sender": "DHL", "text": "  "}).refused
    long = "x" * (da.SMS_TEXT_MAX + 1)
    assert da.run_action("sms.receive", EMU, {"sender": "DHL", "text": long}).refused
    assert adb.calls == []


def test_a_console_ko_is_a_failure_with_a_warning_line(adb):
    adb.replies["emu "] = ("KO: bad phone number format\n", "")
    result = da.run_action("sms.receive", EMU, {"sender": "DHL", "text": "x"})
    assert not result.ok
    assert not result.refused
    assert result.message == "bad phone number format"
    (line,) = _action_lines()
    assert line["level"] == "warn"
    assert line["summary"] == "Receive an SMS failed: bad phone number format"
    assert line["data"]["ok"] is False


def test_no_console_answer_is_a_failure(adb):
    adb.replies["emu "] = ("", "error: device offline")
    result = da.run_action("power.battery", EMU, {"level": 20})
    assert not result.ok
    assert "device offline" in result.message


# -- devices, unknown input ------------------------------------------------------


def test_emulator_only_actions_are_refused_on_a_physical_device(adb):
    result = da.run_action("sms.receive", PHONE, {"sender": "DHL", "text": "x"})
    assert result.refused
    assert result.message == f"Receive an SMS works on an emulator only, not on {PHONE}"
    assert adb.calls == []


def test_unknown_action_parameter_or_device_is_refused(adb):
    assert da.run_action("sms.nope", EMU, {}).message == "Unknown action: sms.nope"
    result = da.run_action("net.wifi", EMU, {"on": True, "speed": 3})
    assert result.message == "Unknown parameter: speed"
    assert da.run_action("net.wifi", None, {"on": True}).message == (
        "No device selected"
    )
    assert adb.calls == []


# -- calls -------------------------------------------------------------------


def test_incoming_call_then_accept_uses_the_last_number(adb):
    assert da.run_action("call.incoming", EMU, {"number": "+49 30 123456"}).ok
    accepted = da.run_action("call.accept", EMU, {})
    assert accepted.ok
    assert accepted.message == "Call from +4930123456 accepted"
    assert adb.commands() == ["emu gsm call +4930123456", "emu gsm accept +4930123456"]
    kinds = [line["kind"] for line in _action_lines()]
    assert kinds == ["call-incoming", "call-accept"]
    assert _action_lines()[0]["summary"] == "Incoming call from +4930123456"


def test_accept_without_a_known_call_asks_for_the_number(adb):
    result = da.run_action("call.accept", EMU, {})
    assert result.refused
    assert "number of the ringing call" in result.message
    assert adb.calls == []


def test_letters_are_not_a_caller_number(adb):
    result = da.run_action("call.incoming", EMU, {"number": "DHL"})
    assert result.refused
    assert adb.calls == []


def test_hangup_presses_end_call_and_checks_the_call_ended(adb):
    adb.replies["shell 'dumpsys telephony.registry'"] = [
        ("  mCallState=2\n  mCallState=0\n", ""),
        ("  mCallState=0\n", ""),
    ]
    adb.replies["shell 'input keyevent"] = ("", "")
    result = da.run_action("call.hangup", PHONE, {})
    assert result.ok, result
    assert result.message == "Call ended"
    assert adb.commands() == [
        "shell 'dumpsys telephony.registry'",
        "shell 'input keyevent KEYCODE_ENDCALL'",
        "shell 'dumpsys telephony.registry'",
    ]
    assert {serial for _c, serial in adb.calls} == {PHONE}


def test_hangup_without_a_call_sends_no_key(adb):
    adb.replies["shell 'dumpsys"] = ("  mCallState=0\n", "")
    result = da.run_action("call.hangup", EMU, {})
    assert not result.ok
    assert result.message == "no call to hang up"
    assert all("keyevent" not in c for c in adb.commands())


def test_outgoing_call_starts_the_call_intent(adb):
    adb.replies["shell 'am start"] = ("Starting: Intent { act=... }\n", "")
    result = da.run_action("call.outgoing", PHONE, {"number": "+4989111222"})
    assert result.ok
    assert result.message == "Outgoing call to +4989111222"
    assert adb.commands() == [
        "shell 'am start -a android.intent.action.CALL -d tel:+4989111222'",
        "shell 'dumpsys telephony.registry'",
    ]


def test_outgoing_call_still_on_after_the_settle_is_a_success(adb):
    adb.replies["shell 'am start"] = ("Starting: Intent { act=... }\n", "")
    adb.replies["shell 'dumpsys"] = ("  mCallState=2\n", "")
    result = da.run_action("call.outgoing", PHONE, {"number": "+4989111222"})
    assert result.ok, result


def test_outgoing_call_ended_by_the_network_is_a_failure(adb):
    """N5-B1: the modem drops the call within a second; say so."""
    adb.replies["shell 'am start"] = ("Starting: Intent { act=... }\n", "")
    adb.replies["shell 'dumpsys"] = ("  mCallState=0\n", "")
    result = da.run_action("call.outgoing", PHONE, {"number": "+4989111222"})
    assert not result.ok
    assert not result.refused
    assert result.message == "call ended by the network"
    assert adb.commands().count("shell 'dumpsys telephony.registry'") == 2
    assert _action_lines()[-1]["data"]["ok"] is False


def test_outgoing_call_that_starts_slowly_is_a_success(adb):
    adb.replies["shell 'am start"] = ("Starting: Intent { act=... }\n", "")
    adb.replies["shell 'dumpsys"] = [("  mCallState=0\n", ""), ("  mCallState=2\n", "")]
    result = da.run_action("call.outgoing", PHONE, {"number": "+4989111222"})
    assert result.ok, result


# -- location -----------------------------------------------------------------


def test_gps_fix_sends_longitude_first(adb):
    result = da.run_action("gps.fix", EMU, {"latitude": "52.52", "longitude": "13.405"})
    assert result.ok
    assert adb.commands() == ["emu geo fix 13.405000 52.520000"]
    assert result.message == "GPS set to 52.52000, 13.40500"


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ({"latitude": "91", "longitude": "0"}, "Latitude: between -90 and 90"),
        ({"latitude": "0", "longitude": "-181"}, "Longitude: between -180 and 180"),
        ({"latitude": "abc", "longitude": "0"}, "Latitude: a number"),
    ],
)
def test_gps_fix_validation(adb, params, reason):
    result = da.run_action("gps.fix", EMU, params)
    assert result.refused
    assert result.message == reason


def test_route_fixes_follow_the_points_at_the_speed():
    points = [(52.5219, 13.4132), (52.5163, 13.3777)]
    fixes = da.route_fixes(points, speed_kmh=36.0, interval_s=1.0)  # 10 m per fix
    assert fixes[0] == points[0]
    assert fixes[-1] == points[-1]
    total = da._distance_m(*points)
    assert len(fixes) == pytest.approx(total / 10 + 2, abs=2)
    gaps = [da._distance_m(a, b) for a, b in itertools.pairwise(fixes[:-1])]
    assert all(g == pytest.approx(10.0, abs=0.5) for g in gaps)


def test_custom_route_needs_points(adb):
    result = da.run_action("gps.route", EMU, {"route": "custom"})
    assert result.refused
    assert "Points" in result.message
    bad = da.run_action("gps.route", EMU, {"route": "custom", "points": "52.5,13.4"})
    assert bad.refused
    assert "at least two" in bad.message


def test_gps_route_runs_in_the_background_to_the_end(adb, monkeypatch):
    monkeypatch.setattr(da, "_wait", lambda event, seconds: event.is_set())
    result = da.run_action(
        "gps.route",
        EMU,
        {"route": "custom", "points": "52.5200,13.4000; 52.5200,13.4010",
         "speed_kmh": "36", "interval_s": "1"},
    )  # fmt: skip
    assert result.ok, result
    assert result.job
    job_thread = next(
        (t for t in threading.enumerate() if t.name == f"device-action-{result.job}"),
        None,
    )
    if job_thread is not None:
        job_thread.join(5)
    assert da.running_jobs() == []
    fixes = [c for c in adb.commands() if c.startswith("emu geo fix")]
    assert fixes[0] == "emu geo fix 13.400000 52.520000"
    assert fixes[-1] == "emu geo fix 13.401000 52.520000"
    assert len(fixes) == result.data["fixes"]
    summaries = [line["summary"] for line in _action_lines()]
    assert summaries[0].startswith("GPS route started: custom route, 0.1 km")
    assert summaries[-1] == "GPS route finished: custom route"
    assert _action_lines()[-1]["data"]["status"] == "finished"


def test_a_route_can_be_stopped_and_a_fix_stops_it(adb):
    result = da.run_action(
        "gps.route", EMU, {"route": "berlin-walk", "interval_s": "60"}
    )
    assert result.ok
    (job,) = da.running_jobs(EMU)
    assert job.action == "gps.route"
    assert job.title.startswith("GPS route Berlin walk")
    assert job.progress == f"fix 1 of {result.data['fixes']}"

    fixed = da.run_action("gps.fix", EMU, {"latitude": "1", "longitude": "2"})
    assert fixed.ok
    assert fixed.message.endswith("(the running route was stopped)")
    assert da.running_jobs() == []
    assert job.status == "stopped"
    stopped = [ln for ln in _action_lines() if ln["data"].get("status") == "stopped"]
    assert stopped[0]["summary"].startswith("GPS route stopped: Berlin walk")
    assert not da.stop_job(job.id)  # already gone


# -- time --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("+2h", 7200), ("-30m", -1800), ("+1d 6h", 108000), ("90s", 90),
     ("1h30min", 5400), ("-0.5h", -1800)],
)  # fmt: skip
def test_duration_parsing(text, seconds):
    assert da.duration(text) == seconds


@pytest.mark.parametrize("text", ["2", "+2x", "h", "+0h", "+4000d"])
def test_bad_durations_are_refused(text):
    with pytest.raises(da.ActionError):
        da.duration(text)


def test_format_delta():
    assert da.format_delta(7200) == "+2 h"
    assert da.format_delta(-5400) == "-1 h 30 min"
    assert da.format_delta(3 * 86400 + 60) == "+3 d 1 min"
    assert da.format_delta(45) == "+45 s"


def test_time_jump_goes_through_the_device_clock(adb, monkeypatch):
    from sandroid.core import device_clock

    seen: list[dict] = []

    def fake_move(serial, **kw):
        seen.append({"serial": serial, **kw})
        return {"ok": True, "moved_s": 7200.0, "actual_moved_s": 7200.004,
                "set_by": "time_detector", "error": None}  # fmt: skip

    monkeypatch.setattr(device_clock, "move_wall_clock", fake_move)
    result = da.run_action("time.jump", PHONE, {"delta": "+2h"})
    assert result.ok
    assert seen == [{"serial": PHONE, "delta_s": 7200.0}]
    assert result.message.startswith("Device time moved +2 h")
    (line,) = _action_lines()
    assert line["kind"] == "time-jump"
    assert line["data"]["set_by"] == "time_detector"


def test_time_jump_to_a_date_uses_the_device_zone(adb, monkeypatch):
    from sandroid.core import device_clock

    seen: list[dict] = []
    monkeypatch.setattr(
        device_clock,
        "move_wall_clock",
        lambda serial, **kw: seen.append(kw)
        or {"ok": True, "moved_s": 60.0, "actual_moved_s": 60.0, "set_by": "date"},
    )
    adb.replies["shell 'getprop persist.sys.timezone'"] = ("Europe/Berlin\n", "")
    assert da.run_action("time.jump", EMU, {"to": "2026-12-24 18:00"}).ok
    expected = datetime.fromisoformat("2026-12-24T18:00:00+01:00").timestamp()
    assert seen == [{"to_epoch": expected}]
    # An explicit offset wins over the device zone.
    assert da.run_action("time.jump", EMU, {"to": "2026-12-24T18:00:00+00:00"}).ok
    assert seen[-1] == {
        "to_epoch": datetime.fromisoformat("2026-12-24T18:00:00+00:00").timestamp()
    }


@pytest.mark.parametrize(
    "params",
    [{}, {"delta": "+1h", "to": "2026-12-24 18:00"}, {"to": "24.12.2026"},
     {"to": "1999-01-01 00:00"}],
)  # fmt: skip
def test_time_jump_needs_exactly_one_valid_target(adb, params):
    result = da.run_action("time.jump", EMU, params)
    assert result.refused
    assert adb.calls == []


def test_a_failed_time_jump_is_reported(adb, monkeypatch):
    from sandroid.core import device_clock

    monkeypatch.setattr(
        device_clock,
        "move_wall_clock",
        lambda serial, **kw: {"ok": False, "error": "the device did not answer"},
    )
    result = da.run_action("time.jump", EMU, {"delta": "-1h"})
    assert not result.ok
    assert result.message == "the device did not answer"
    assert _action_lines()[0]["summary"] == (
        "Move the device time failed: the device did not answer"
    )


def test_time_reset_goes_through_the_device_clock(adb, monkeypatch):
    from sandroid.core import device_clock

    monkeypatch.setattr(
        device_clock,
        "reset_wall_clock",
        lambda serial: {"ok": True, "was_held": True, "line": None, "error": None},
    )
    result = da.run_action("time.reset", EMU, {})
    assert result.ok
    assert result.message == "Device time back to real time"


# -- power and network -------------------------------------------------------------


def test_power_actions_send_the_console_commands(adb):
    assert da.run_action("power.battery", EMU, {"level": "15"}).ok
    assert da.run_action("power.charging", EMU, {"on": "on"}).ok
    assert da.run_action("power.charging", EMU, {"on": False}).ok
    assert da.run_action("power.ac", EMU, {"on": "off"}).ok
    assert adb.commands() == [
        "emu power capacity 15",
        "emu power ac on",
        "emu power status charging",
        "emu power ac off",
        "emu power status discharging",
        "emu power ac off",
    ]


@pytest.mark.parametrize("level", ["101", "-1", "50.5", "half"])
def test_battery_level_validation(adb, level):
    assert da.run_action("power.battery", EMU, {"level": level}).refused
    assert adb.calls == []


def test_network_toggles_use_svc_and_connectivity(adb):
    adb.replies["shell "] = ("", "")
    assert da.run_action("net.wifi", PHONE, {"on": "off"}).message == "Wi-Fi off"
    assert da.run_action("net.data", PHONE, {"on": True}).message == "Mobile data on"
    airplane = da.run_action("net.airplane", PHONE, {"on": "yes"})
    assert airplane.message == "Airplane mode on"
    assert adb.commands() == [
        "shell 'svc wifi disable'",
        "shell 'svc data enable'",
        "shell 'cmd connectivity airplane-mode enable'",
    ]


def test_a_shell_error_is_a_failure(adb):
    adb.replies["shell "] = ("cmd: Unknown command: airplane-mode\n", "")
    result = da.run_action("net.airplane", EMU, {"on": True})
    assert not result.ok
    assert "Unknown command" in result.message


def test_network_profile_sets_speed_and_delay(adb):
    result = da.run_action("net.profile", EMU, {"profile": "3g"})
    assert result.ok
    assert result.message == "Network profile: 3G (UMTS)"
    assert adb.commands() == ["emu network speed umts", "emu network delay umts"]
    assert da.run_action("net.profile", EMU, {"profile": "5g"}).refused


def test_bool_parameters_accept_words(adb):
    for word in ("maybe", "2"):
        assert da.run_action("net.wifi", EMU, {"on": word}).refused


# -- headless API ------------------------------------------------------------------


def test_the_headless_handler_runs_lists_and_stops_actions(adb):
    import asyncio

    from sandroid.api.handlers.device_handler import DeviceHandler

    handler = DeviceHandler(api=None)
    listed = asyncio.run(handler.list_device_actions())
    assert listed.success
    assert [a["id"] for a in listed.data["actions"]][:2] == [
        "sms.receive",
        "call.incoming",
    ]

    ran = asyncio.run(
        handler.run_device_action("power.battery", {"level": 15}, serial=EMU)
    )
    assert ran.success
    assert ran.message == "Battery set to 15%"
    assert ran.data["serial"] == EMU
    assert adb.calls == [("emu power capacity 15", EMU)]

    refused = asyncio.run(
        handler.run_device_action("sms.receive", {"sender": "O2", "text": "x"}, EMU)
    )
    assert not refused.success
    assert refused.data["refused"] is True

    stopped = asyncio.run(handler.stop_device_action("job-999"))
    assert not stopped.success
