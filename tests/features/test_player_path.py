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
