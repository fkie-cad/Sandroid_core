"""Tests for Player's explicit-recording-path wiring (features/player.py).

The device-switch recording bug came from re-deriving the recording path from
the process-global ``RAW_RESULTS_PATH`` at read time. Player now takes an
explicit ``recording_path`` (ctor and/or ``perform`` arg); these tests assert
it reads that path directly, that the process global is never consulted for
the recording (the ``os`` module is no longer even imported by ``player``),
that the ``perform`` arg overrides the ctor value, that supplying no path at
all raises a clear ``RuntimeError`` instead of silently falling back to the
env, and that a missing file still raises the clear ``RuntimeError``.

``Adb.send_adb_command`` and the two ``Toolbox`` action-window helpers are
stubbed so the test needs no device.
"""

from __future__ import annotations

import pytest

import sandroid.features.player as player_module
from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox
from sandroid.features.player import Player


@pytest.fixture
def _neutralize_toolbox(monkeypatch):
    """Stub the device-touching Toolbox action-window calls to no-ops."""
    monkeypatch.setattr(Toolbox, "set_action_time", staticmethod(lambda: None))
    monkeypatch.setattr(
        Toolbox, "set_action_duration", staticmethod(lambda seconds: None)
    )


@pytest.fixture
def sent(monkeypatch):
    """Capture every ``Adb.send_adb_command`` call (no device needed)."""
    calls: list[str] = []

    def _record(cmd):
        calls.append(cmd)

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(_record))
    return calls


def _write_recording(path, *lines: str) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def test_perform_reads_explicit_path_and_never_touches_env(
    tmp_path, sent, _neutralize_toolbox
):
    recording = tmp_path / "recording.txt"
    _write_recording(
        recording,
        "1000 /dev/input/event3 3 57 100",
        "1000 /dev/input/event3 1 330 1",
    )

    # The recording path can no longer be derived from the process global:
    # ``player`` does not import ``os`` at all, so the bug class is gone by
    # construction, not merely bypassed.
    assert not hasattr(player_module, "os")

    Player(recording_path=str(recording)).perform()

    assert sent == [
        "shell sendevent /dev/input/event3 3 57 100",
        "shell sendevent /dev/input/event3 1 330 1",
    ]


def test_perform_arg_overrides_ctor_path(tmp_path, sent, _neutralize_toolbox):
    ctor_file = tmp_path / "ctor.txt"
    _write_recording(ctor_file, "1 ctordev 1 1 1")
    override_file = tmp_path / "override.txt"
    _write_recording(override_file, "2 overridedev 2 2 2")

    Player(recording_path=str(ctor_file)).perform(recording_path=str(override_file))

    assert sent == ["shell sendevent overridedev 2 2 2"]


def test_no_path_raises_runtime_error(sent, _neutralize_toolbox):
    # No path on ctor or perform: must fail loudly rather than silently
    # falling back to RAW_RESULTS_PATH (the orphaning bug this design removes).
    with pytest.raises(RuntimeError, match="no recording path"):
        Player().perform()

    assert sent == []


def test_missing_recording_raises_runtime_error(tmp_path, sent, _neutralize_toolbox):
    missing = tmp_path / "does_not_exist.txt"

    with pytest.raises(RuntimeError, match="Recording file not found"):
        Player(recording_path=str(missing)).perform()


def _events():
    """The same five events: device seconds, type, code, value (hex/unsigned)."""
    return [
        (26404.737324, 3, 0x39, 0),
        (26404.737324, 3, 0x35, 0x238D),
        (26404.737324, 0, 0, 0),
        (26404.763419, 3, 0x39, 0xFFFFFFFF),
        (26404.763419, 0, 0, 0),
    ]


def test_getevent_and_legacy_recordings_replay_identically(
    tmp_path, sent, _neutralize_toolbox, monkeypatch
):
    """``recording.getevent.txt`` (raw ``getevent -t``) and a legacy
    ``recording.txt`` of the same events give the same sendevent calls and
    the same waits (the legacy recorder converted hex with ``int(x, 16)``).
    """
    new = tmp_path / "recording.getevent.txt"
    _write_recording(
        new,
        *(
            f"[{t:15.6f}] /dev/input/event1: {a:04x} {b:04x} {c:08x}"
            for t, a, b, c in _events()
        ),
    )
    legacy = tmp_path / "recording.txt"
    _write_recording(
        legacy,
        *(
            f"{round(t * 1000)} /dev/input/event1 {a} {b} {c}"
            for t, a, b, c in _events()
        ),
    )
    waits: list[float] = []
    monkeypatch.setattr(player_module._cancel_event, "wait", waits.append)

    Player(recording_path=str(new)).perform()
    sent_new, waits_new = list(sent), list(waits)
    sent.clear()
    waits.clear()
    Player(recording_path=str(legacy)).perform()

    assert sent_new == sent
    assert sent_new[3] == "shell sendevent /dev/input/event1 3 57 4294967295"
    assert [round(w, 3) for w in waits_new] == [round(w, 3) for w in waits] == [0.026]


def test_store_line_re_matches_both_formats():
    """``cli.resolve_recording`` validates lines with ``STORE_LINE_RE.match``."""
    assert Player.STORE_LINE_RE.match(
        "[   26404.737324] /dev/input/event1: 0003 0039 ffffffff"
    )
    assert Player.STORE_LINE_RE.match("1700000000000 /dev/input/event1 3 57 0")
    assert not Player.STORE_LINE_RE.match("add device 1: /dev/input/event0")
    assert player_module.parse_store_line(
        "[ 1.500000] /dev/input/event2: 0001 009e 00000001"
    ) == (
        1500.0,
        "/dev/input/event2",
        "1",
        "158",
        "1",
    )


# ---------------------------------------------------------------------------
# device time after a snapshot load (E2E crash: SystemExit on the Play worker)
# ---------------------------------------------------------------------------


def test_action_window_service_raises_device_time_error_not_systemexit():
    from unittest.mock import MagicMock

    from sandroid.core.exceptions import DeviceTimeError
    from sandroid.services.action_window_service import ActionWindowService

    adb = MagicMock()
    adb.send_adb_command.return_value = ("", "adb: device still authorizing")
    service = ActionWindowService(adb=adb)
    with pytest.raises(DeviceTimeError, match="authorizing"):
        service.set_action_time_from_device()
    assert issubclass(DeviceTimeError, RuntimeError)
    adb.send_adb_command.return_value = ("not a number\n", "")
    with pytest.raises(DeviceTimeError):
        service.set_action_time_from_device()
    adb.send_adb_command.return_value = ("1700000000\n", "")
    assert service.set_action_time_from_device() == 1700000000


class _FlakyClock:
    """``set_action_time`` failing ``fails`` times, like adb right after a
    snapshot load ("device still authorizing").
    """

    def __init__(self, fails: int) -> None:
        self.fails = fails
        self.calls = 0

    def set_action_time(self) -> None:
        from sandroid.core.exceptions import DeviceTimeError

        self.calls += 1
        if self.calls <= self.fails:
            raise DeviceTimeError("adb: device still authorizing")


@pytest.fixture
def _fast_retry(monkeypatch):
    monkeypatch.setattr(player_module, "ACTION_TIME_RETRY_S", 0.01)
    Player.clear_cancel()
    yield
    Player.clear_cancel()


def test_device_time_is_retried_after_a_snapshot_load(_fast_retry):
    clock = _FlakyClock(fails=2)
    player_module.set_action_time_after_load(clock)
    assert clock.calls == 3


def test_play_aborts_cleanly_when_the_device_time_stays_unreadable(
    tmp_path, sent, monkeypatch, _fast_retry
):
    from sandroid.analysis.engine import FatalStepError

    clock = _FlakyClock(fails=99)
    monkeypatch.setattr(Toolbox, "set_action_time", clock.set_action_time)
    recording = tmp_path / "recording.txt"
    _write_recording(recording, "1000 /dev/input/event3 3 57 100")
    with pytest.raises(FatalStepError, match="Device not ready"):
        Player(recording_path=str(recording)).perform()
    assert clock.calls == player_module.ACTION_TIME_ATTEMPTS
    assert sent == []  # no input replayed against an unknown window


def test_a_cancel_stops_the_device_time_retries(monkeypatch, _fast_retry):
    from sandroid.analysis.engine import FatalStepError

    monkeypatch.setattr(player_module, "ACTION_TIME_RETRY_S", 5.0)
    clock = _FlakyClock(fails=99)
    Player.cancel_all()
    with pytest.raises(FatalStepError, match="cancelled"):
        player_module.set_action_time_after_load(clock)
    assert clock.calls == 1
