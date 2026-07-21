"""Headless Textual Pilot tests for Watchlist auto-mode (WatchlistView).

No physical device / real adb needed. Two class-level seams get
monkeypatched exactly like tests/tui/test_watchlist_view.py monkeypatches
``FileExtractionService.pull_file``:

- ``WatchlistView._stat_command`` -- the one method wrapping the batched
  ``adb shell stat ...`` call, so canned ``(stdout, stderr)`` tuples can
  drive the debounce/backoff/offline-pause state machine deterministically.
- ``WatchlistView._device_manager`` -- the one method wrapping
  ``DeviceService.get_device_manager()``, replaced with a fake exposing
  ``on_device_change``/``fire`` so a reconnect can be simulated without
  touching the real (process-wide) DeviceManager singleton.

``WatchlistView._is_watchlist_visible`` is also monkeypatched to ``True`` in
most tests: the minimal harness below mounts a bare ``WatchlistView`` (no
surrounding ``FilesPanel``/``MainScreen`` scaffold, matching
test_watchlist_view.py's own harness), so the real visibility check (which
looks for ``#tool-body``/``#files-body`` ContentSwitchers) would otherwise
always report "hidden" and no tick would ever do real work.
"""

from __future__ import annotations

import time

import pytest
from textual.app import App, ComposeResult

from sandroid.services import get_forensic_service
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)
from sandroid.tui.widgets import watchlist_view as wv_module
from sandroid.tui.widgets.watchlist_view import RowState, WatchlistView


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _clean_spotlight_files():
    """Guard the real ForensicService singleton against cross-test leakage."""
    svc = get_forensic_service()
    svc._spotlight_files.clear()
    yield
    svc._spotlight_files.clear()


PATH_A = "/data/data/com.app/config_a"
PATH_B = "/data/data/com.app/config_b"


def _stat_line(path: str, mtime: int, size: int) -> str:
    return f"{path} {mtime} {size}"


class _FakeDeviceManager:
    """Records ``on_device_change`` subscribers; ``fire`` invokes them all."""

    def __init__(self) -> None:
        self.callbacks: list = []

    def on_device_change(self, callback) -> None:
        self.callbacks.append(callback)

    def fire(self, device) -> None:
        for cb in list(self.callbacks):
            cb(device)


class _FakeExpandAdb:
    """Fake AdbProtocol for wildcard pattern expansion (find/ls only)."""

    def __init__(self, matches: list[str]):
        self.matches = list(matches)
        self.calls = 0

    def send_adb_command(self, cmd: str) -> tuple[str, str]:
        self.calls += 1
        return "\n".join(self.matches), ""


def _fake_pull_file(content_by_remote_path: dict[str, str]):
    """Class-level FileExtractionService.pull_file replacement (mirrors
    test_watchlist_view.py's helper of the same name).
    """

    def _pull(self, remote_path, local_path, compute_hash=False):
        from pathlib import Path

        if remote_path not in content_by_remote_path:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="no such file on (fake) device",
            )
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(
            content_by_remote_path[remote_path], encoding="utf-8"
        )
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    return _pull


class _WatchlistHarness(App):
    """Minimal single-widget host app for WatchlistView (mirrors
    test_watchlist_view.py's harness of the same name).
    """

    def compose(self) -> ComposeResult:
        yield WatchlistView(id="files-watchlist")


async def _wait_for(pilot, predicate, timeout: float = 3.0) -> None:
    """Poll ``predicate`` with real pauses until true or timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition was not met within timeout"


# ---------------------------------------------------------------------------
# Pure unit tests: no App/Pilot needed at all.
# ---------------------------------------------------------------------------


class TestParseStatOutput:
    def test_basic_two_paths(self):
        stdout = _stat_line(PATH_A, 1700000000, 42) + "\n" + _stat_line(PATH_B, 1, 2)
        parsed = WatchlistView._parse_stat_output(stdout)
        assert parsed == {PATH_A: (1700000000, 42), PATH_B: (1, 2)}

    def test_path_containing_spaces_is_not_shredded(self):
        path = "/sdcard/My Documents/notes.txt"
        stdout = _stat_line(path, 100, 5)
        parsed = WatchlistView._parse_stat_output(stdout)
        assert parsed == {path: (100, 5)}

    def test_blank_and_malformed_lines_are_skipped(self):
        stdout = "\n".join(
            [
                "",
                "garbage line with only one token",
                _stat_line(PATH_A, 10, 1),
                "not-a-number-mtime not-a-number-size extra",
            ]
        )
        parsed = WatchlistView._parse_stat_output(stdout)
        assert parsed == {PATH_A: (10, 1)}

    def test_empty_stdout_yields_empty_dict(self):
        assert WatchlistView._parse_stat_output("") == {}
        assert WatchlistView._parse_stat_output(None) == {}


class TestLooksLikeDeviceError:
    @pytest.mark.parametrize(
        "stderr",
        [
            "error: device offline",
            "error: no devices/emulators found",
            "adb: device not found",
            "Command timed out after 30 seconds",
            "adb: closed",
        ],
    )
    def test_matches_known_device_error_text(self, stderr):
        assert WatchlistView._looks_like_device_error(stderr) is True

    def test_plain_per_path_stat_error_does_not_match(self):
        stderr = f"stat: can't stat '{PATH_A}': No such file or directory"
        assert WatchlistView._looks_like_device_error(stderr) is False

    def test_empty_stderr_does_not_match(self):
        assert WatchlistView._looks_like_device_error("") is False
        assert WatchlistView._looks_like_device_error(None) is False


# ---------------------------------------------------------------------------
# _evaluate_auto_pull: debounce + rate-limit decision logic (bare instance,
# no mount needed -- _start_pull is monkeypatched to a recording stub so
# these stay tightly scoped to the decision logic itself).
# ---------------------------------------------------------------------------


class TestEvaluateAutoPull:
    def _view_with_row(self, monkeypatch, *, last_pulled=None):
        view = WatchlistView()
        view._rows[PATH_A] = wv_module._RowInfo(path=PATH_A, last_pulled=last_pulled)
        calls: list[list[str]] = []
        monkeypatch.setattr(view, "_start_pull", calls.append)
        return view, view._rows[PATH_A], calls

    def test_first_ever_tick_marks_settling_without_pulling(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch)
        view._evaluate_auto_pull(row, None, (100, 10))
        assert row.state == RowState.SETTLING
        assert calls == []

    def test_unstable_across_ticks_marks_settling_without_pulling(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch)
        # previously_seen != new_sig -- still changing, not stable yet.
        view._evaluate_auto_pull(row, (90, 9), (100, 10))
        assert row.state == RowState.SETTLING
        assert calls == []

    def test_stable_but_rate_limited_marks_settling_without_pulling(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch)
        view._last_auto_pull_at[PATH_A] = time.monotonic()  # "just pulled"
        view._evaluate_auto_pull(row, (100, 10), (100, 10))
        assert row.state == RowState.SETTLING
        assert calls == []

    def test_stable_and_rate_ok_triggers_pull(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch)
        view._evaluate_auto_pull(row, (100, 10), (100, 10))
        assert calls == [[PATH_A]]
        assert PATH_A in view._auto_pull_inflight
        assert view._last_auto_pull_at[PATH_A] > 0

    def test_matches_last_pulled_is_a_noop(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch, last_pulled=(100, 10))
        view._evaluate_auto_pull(row, (100, 10), (100, 10))
        assert calls == []
        assert row.state == RowState.NEVER_PULLED  # untouched

    def test_already_inflight_does_not_re_trigger(self, monkeypatch):
        view, row, calls = self._view_with_row(monkeypatch)
        view._auto_pull_inflight.add(PATH_A)
        view._evaluate_auto_pull(row, (100, 10), (100, 10))
        assert calls == []


# ---------------------------------------------------------------------------
# _apply_auto_tick_result: batch outcome application (bare instance; only
# needs _auto_enabled=True, no timers/mount required since _cancel_* are
# no-ops when no timer was ever started).
# ---------------------------------------------------------------------------


class TestApplyAutoTickResult:
    @staticmethod
    def _bare_view(monkeypatch) -> WatchlistView:
        """A WatchlistView with no App/mount -- _reschedule_auto_timer is
        stubbed out since it calls Widget.set_interval, which requires a
        running asyncio event loop these plain synchronous tests don't have.
        """
        view = WatchlistView()
        monkeypatch.setattr(view, "_reschedule_auto_timer", lambda: None)
        return view

    def test_per_path_failure_isolated_does_not_pause(self, monkeypatch):
        view = self._bare_view(monkeypatch)
        view._auto_enabled = True
        view._rows[PATH_A] = wv_module._RowInfo(path=PATH_A)
        view._rows[PATH_B] = wv_module._RowInfo(path=PATH_B)
        monkeypatch.setattr(view, "_evaluate_auto_pull", lambda *a, **k: None)

        stdout = _stat_line(PATH_B, 100, 10)  # PATH_A missing -> per-path error
        stderr = f"stat: can't stat '{PATH_A}': No such file or directory"
        view._apply_auto_tick_result([PATH_A, PATH_B], stdout, stderr)

        assert view._rows[PATH_A].state == RowState.ERROR
        assert PATH_A in view._rows[PATH_A].detail or view._rows[PATH_A].detail
        assert view._rows[PATH_B].state != RowState.ERROR
        assert view._auto_paused_reason is None

    def test_full_batch_device_error_pauses(self, monkeypatch):
        view = self._bare_view(monkeypatch)
        view._auto_enabled = True
        view._rows[PATH_A] = wv_module._RowInfo(path=PATH_A)

        view._apply_auto_tick_result([PATH_A], "", "error: device offline")

        assert view._auto_paused_reason == "device offline"

    def test_full_batch_generic_stat_errors_do_not_pause(self, monkeypatch):
        """All paths individually erroring (e.g. permission denied on every
        one) must NOT be misread as a device-offline pause -- only stderr
        text that actually looks like a dead device does.
        """
        view = self._bare_view(monkeypatch)
        view._auto_enabled = True
        view._rows[PATH_A] = wv_module._RowInfo(path=PATH_A)

        stderr = f"stat: can't stat '{PATH_A}': Permission denied"
        view._apply_auto_tick_result([PATH_A], "", stderr)

        assert view._auto_paused_reason is None
        assert view._rows[PATH_A].state == RowState.ERROR

    def test_toggled_off_mid_flight_is_ignored(self, monkeypatch):
        view = self._bare_view(monkeypatch)
        view._auto_enabled = False  # toggled off while the batch was in flight
        view._auto_tick_inflight = True
        view._rows[PATH_A] = wv_module._RowInfo(path=PATH_A)

        view._apply_auto_tick_result([PATH_A], _stat_line(PATH_A, 1, 1), "")

        assert view._auto_tick_inflight is False  # still must clear
        assert view._rows[PATH_A].state == RowState.NEVER_PULLED  # untouched

    def test_advances_backoff_on_no_change_and_resets_on_change(self, monkeypatch):
        view = WatchlistView()
        view._auto_enabled = True
        view._rows[PATH_A] = wv_module._RowInfo(
            path=PATH_A, last_pulled=(100, 10), last_seen=(100, 10)
        )
        reschedules: list[int] = []
        monkeypatch.setattr(
            view,
            "_reschedule_auto_timer",
            lambda: reschedules.append(view._auto_backoff_idx),
        )

        # No change -> backoff advances step by step, capped at the last step.
        for expected_idx in (1, 2, 3, 3):
            view._apply_auto_tick_result([PATH_A], _stat_line(PATH_A, 100, 10), "")
            assert view._auto_backoff_idx == expected_idx

        # A real change resets backoff to 0.
        view._apply_auto_tick_result([PATH_A], _stat_line(PATH_A, 200, 20), "")
        assert view._auto_backoff_idx == 0


# ---------------------------------------------------------------------------
# Pilot-based tests: toggle, full tick wiring, offline pause + auto-resume,
# wildcard re-expansion. A real mounted App is needed here because
# _reschedule_auto_timer/_reschedule_wildcard_timer call Widget.set_interval,
# which requires a running asyncio event loop.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_toggle_auto_updates_state_and_badge(monkeypatch):
    fake_manager = _FakeDeviceManager()
    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(lambda: fake_manager)
    )

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view._auto_enabled is False
        assert "off" in view._auto_badge()

        view.action_toggle_auto()
        await pilot.pause()
        assert view._auto_enabled is True
        assert "on" in view._auto_badge()
        assert fake_manager.callbacks  # subscribed exactly once

        view.action_toggle_auto()
        await pilot.pause()
        assert view._auto_enabled is False
        assert "off" in view._auto_badge()

        # Toggling on again must NOT grow the subscriber list further.
        view.action_toggle_auto()
        await pilot.pause()
        assert len(fake_manager.callbacks) == 1


@pytest.mark.asyncio
async def test_auto_tick_end_to_end_reaches_baseline_then_unchanged_then_changed(
    monkeypatch,
):
    """Full lifecycle against a path with an existing manual baseline:
    tick 1 (first-ever observation) settles, tick 2 (stable + rate ok, once
    the min interval is shrunk for the test) triggers a real pull that
    matches the existing baseline (-> UNCHANGED), then a genuine on-device
    content change is detected and, once stable again, pulled and diffed
    (-> CHANGED).
    """
    monkeypatch.setattr(wv_module, "_AUTO_PULL_MIN_INTERVAL", 0.0)
    fake_manager = _FakeDeviceManager()
    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(lambda: fake_manager)
    )

    content = {PATH_A: "line one\n"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        monkeypatch.setattr(view, "_is_watchlist_visible", lambda: True)

        # Seed a baseline the way a manual pull would (first pull is always
        # BASELINE_ONLY, never CHANGED/UNCHANGED).
        view._start_pull([PATH_A])
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY
        )

        stat_calls: list[list[str]] = []

        def fake_stat(paths):
            stat_calls.append(list(paths))
            return _stat_line(PATH_A, 100, 10), ""

        monkeypatch.setattr(WatchlistView, "_stat_command", staticmethod(fake_stat))

        view._start_auto_mode()

        # Tick 1: first-ever observation -> settling, no pull yet.
        view._auto_tick()
        await _wait_for(pilot, lambda: view._rows[PATH_A].last_seen == (100, 10))
        assert view._rows[PATH_A].state == RowState.SETTLING

        # Tick 2: stable signature + (shrunk) rate limit satisfied -> pulls,
        # content still matches the baseline -> UNCHANGED.
        view._auto_tick()
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.UNCHANGED)
        assert view._rows[PATH_A].last_pulled == (100, 10)

        # Device-side content changes.
        content[PATH_A] = "line one\nline two\n"

        def fake_stat_changed(paths):
            stat_calls.append(list(paths))
            return _stat_line(PATH_A, 200, 20), ""

        monkeypatch.setattr(
            WatchlistView, "_stat_command", staticmethod(fake_stat_changed)
        )

        # Tick 3: new signature differs from the previous tick -> settling.
        view._auto_tick()
        await _wait_for(pilot, lambda: view._rows[PATH_A].last_seen == (200, 20))
        assert view._rows[PATH_A].state == RowState.SETTLING

        # Tick 4: stable again -> triggers the real pull+diff -> CHANGED.
        view._auto_tick()
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.CHANGED)
        assert "line two" in (view._rows[PATH_A].diff_text or "")


@pytest.mark.asyncio
async def test_offline_pause_and_device_reconnect_auto_resume(monkeypatch):
    fake_manager = _FakeDeviceManager()
    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(lambda: fake_manager)
    )
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        monkeypatch.setattr(view, "_is_watchlist_visible", lambda: True)

        def fake_stat_offline(paths):
            return "", "error: device offline"

        monkeypatch.setattr(
            WatchlistView, "_stat_command", staticmethod(fake_stat_offline)
        )

        view._start_auto_mode()
        view._auto_tick()
        await _wait_for(pilot, lambda: view._auto_paused_reason == "device offline")
        assert view._auto_timer is None  # timer torn down while paused
        assert "device offline" in view._auto_badge()

        # Device comes back -- DeviceManager fires with a real (fake) device.
        fake_manager.fire(object())
        await pilot.pause()

        assert view._auto_paused_reason is None
        assert view._auto_backoff_idx == 0
        assert view._auto_timer is not None  # resumed

        # A disconnect signal (None) while NOT paused must be a no-op.
        fake_manager.fire(None)
        await pilot.pause()
        assert view._auto_paused_reason is None
        assert view._auto_enabled is True


@pytest.mark.asyncio
async def test_wildcard_reexpansion_picks_up_new_matches(monkeypatch):
    pattern = "/data/data/com.app/logs/*"
    fake_adb = _FakeExpandAdb([f"{pattern[:-2]}/a.log"])
    monkeypatch.setattr(WatchlistView, "_adb", staticmethod(lambda: fake_adb))
    fake_manager = _FakeDeviceManager()
    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(lambda: fake_manager)
    )

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        monkeypatch.setattr(view, "_is_watchlist_visible", lambda: True)

        view._add_path(pattern)
        await pilot.pause()
        assert pattern in view._watched_patterns
        assert f"{pattern[:-2]}/a.log" in view._rows

        # A new file appears matching the same pattern.
        fake_adb.matches.append(f"{pattern[:-2]}/b.log")

        view._start_auto_mode()
        view._wildcard_tick()
        await _wait_for(pilot, lambda: f"{pattern[:-2]}/b.log" in view._rows)


@pytest.mark.asyncio
async def test_wildcard_tick_noop_without_patterns(monkeypatch):
    """No watched patterns -> the wildcard tick must not touch adb at all."""
    calls: list[str] = []

    class _CountingAdb:
        def send_adb_command(self, cmd):
            calls.append(cmd)
            return "", ""

    monkeypatch.setattr(WatchlistView, "_adb", staticmethod(_CountingAdb))
    fake_manager = _FakeDeviceManager()
    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(lambda: fake_manager)
    )
    get_forensic_service().add_spotlight_file(PATH_A)  # a plain, non-pattern path

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        monkeypatch.setattr(view, "_is_watchlist_visible", lambda: True)

        view._start_auto_mode()
        view._wildcard_tick()
        await pilot.pause()

        assert calls == []
