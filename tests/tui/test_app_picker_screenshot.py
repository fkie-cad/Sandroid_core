"""Regressions: stale app picker, invisible filter text, screenshot messages.

* The app picker (``C`` / proxy) showed the session cache filled before an
  app was installed outside Sandroid (Firefox via adb) -- it now opens on the
  cache, refreshes in the background, refreshes on Ctrl+R and marks running
  apps.
* Typing in the picker's filter showed nothing: the modal sweep made the
  Input compact (1 row) while the app stylesheet's ``#filter-input`` border
  outranked compact's ``border: none !important`` (app CSS beats every
  widget DEFAULT_CSS), leaving no text row.
* Esc in the Screenshot dialog reported "Screenshot result is None"; a
  successful capture said nothing about where the file went.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pilot_helpers import settle, until
from textual.app import App
from textual.widgets import Input, OptionList

from sandroid.services.app_selection_service import AppSelectionService
from sandroid.tui.modals.app_selection_modal import AppSelectionModal
from sandroid.tui.modals.base import ForensicModal
from sandroid.tui.modals.selection_modal import SelectionModal

TUI_DIR = Path(__file__).resolve().parents[2] / "src" / "sandroid" / "tui"
STYLESHEETS = [TUI_DIR / "styles.tcss", *sorted((TUI_DIR / "themes").glob("*.tcss"))]

OLD = [
    {"package_name": "org.wikipedia", "install_date": "2026-11-10 09:00:00"},
    {"package_name": "com.ebay.mobile", "install_date": "2026-10-01 12:00:00"},
]
FIREFOX = {"package_name": "org.mozilla.firefox", "install_date": "2026-11-18 10:30:52"}


class _FakeAdb:
    """Device with three user apps; Firefox installed after the cache filled."""

    def __init__(self) -> None:
        self.packages = ["org.wikipedia", "com.ebay.mobile", "org.mozilla.firefox"]
        self.dates = {p["package_name"]: p["install_date"] for p in [*OLD, FIREFOX]}
        self.commands: list[str] = []
        self.running = ["org.mozilla.firefox", "org.mozilla.firefox:tab3", "init"]

    def get_installed_packages(self, user_only: bool = False) -> list[dict]:
        return [dict(p) for p in OLD]  # the stale first enumeration

    def send_adb_command(self, command: str) -> tuple[str, str]:
        self.commands.append(command)
        if command.startswith("shell pm list packages"):
            return "".join(f"package:{p}\n" for p in self.packages), ""
        if command.startswith("shell dumpsys package"):
            name = command.split()[3]
            return f"    firstInstallTime={self.dates[name]}\n", ""
        return "", ""

    def list_processes(self) -> list[dict]:
        return [{"pid": i, "user": "u0", "name": n} for i, n in enumerate(self.running)]


def _names(packages: list[dict]) -> list[str]:
    return [p["package_name"] for p in packages]


# --------------------------------------------------------------------------
# Service: refresh past the session cache
# --------------------------------------------------------------------------


def test_refresh_finds_app_installed_after_cache_newest_first() -> None:
    adb = _FakeAdb()
    svc = AppSelectionService(adb=adb)
    assert _names(svc.get_installed_packages()) == ["org.wikipedia", "com.ebay.mobile"]
    # Plain calls keep serving the (stale) cache ...
    assert "org.mozilla.firefox" not in _names(svc.get_installed_packages())

    fresh = svc.get_installed_packages(refresh=True)

    assert _names(fresh) == ["org.mozilla.firefox", "org.wikipedia", "com.ebay.mobile"]
    assert fresh[0]["install_date"] == "2026-11-18 10:30:52"
    # ... only the new package cost a dumpsys; known dates came from the cache.
    dumpsys = [c for c in adb.commands if "dumpsys" in c]
    assert dumpsys == [
        "shell dumpsys package org.mozilla.firefox | grep firstInstallTime"
    ]
    # The cache now holds the fresh list, removals included.
    adb.packages.remove("com.ebay.mobile")
    assert _names(svc.get_installed_packages(refresh=True)) == [
        "org.mozilla.firefox",
        "org.wikipedia",
    ]
    assert _names(svc.get_installed_packages()) == [
        "org.mozilla.firefox",
        "org.wikipedia",
    ]


def test_refresh_keeps_cache_when_device_unreadable() -> None:
    adb = _FakeAdb()
    svc = AppSelectionService(adb=adb)
    svc.get_installed_packages()
    adb.send_adb_command = lambda command: ("", "error: no devices/emulators found")
    assert _names(svc.get_installed_packages(refresh=True)) == [
        "org.wikipedia",
        "com.ebay.mobile",
    ]


def test_running_apps_are_marked_including_subprocess_names() -> None:
    svc = AppSelectionService(adb=_FakeAdb())
    marked = svc.mark_running([dict(FIREFOX), *OLD])
    assert [p["running"] for p in marked] == [True, False, False]


def test_picker_loaders_open_on_cache_then_load_fresh_and_running() -> None:
    adb = _FakeAdb()
    svc = AppSelectionService(adb=adb)
    assert svc.picker_loaders()["packages"] == []  # first use: spinner + load

    svc.get_installed_packages()
    kwargs = svc.picker_loaders()
    assert _names(kwargs["packages"]) == ["org.wikipedia", "com.ebay.mobile"]
    fresh = kwargs["package_loader"](False)
    assert _names(fresh)[0] == "org.mozilla.firefox"
    assert fresh[0]["running"] is True
    assert _names(kwargs["initial_loader"]())[0] == "org.mozilla.firefox"


# --------------------------------------------------------------------------
# Modal: background refresh, Ctrl+R, running marker
# --------------------------------------------------------------------------


class _Host(App):
    def __init__(self, screen, css_path=None) -> None:
        super().__init__(css_path=css_path)
        self._modal = screen

    def on_mount(self) -> None:
        self.push_screen(self._modal)


def _row_texts(modal: AppSelectionModal) -> list[str]:
    app_list = modal.query_one("#app-list", OptionList)
    return [
        str(app_list.get_option_at_index(i).prompt)
        for i in range(app_list.option_count)
    ]


async def test_picker_shows_cache_then_refreshes_in_background() -> None:
    svc = AppSelectionService(adb=_FakeAdb())
    svc.get_installed_packages()
    modal = AppSelectionModal(**svc.picker_loaders())
    async with _Host(modal).run_test(size=(120, 40)) as pilot:
        await until(pilot, lambda: len(modal.filtered_packages) == 3)
        rows = _row_texts(modal)
        assert "org.mozilla.firefox" in rows[0]
        assert rows[0].startswith("● ")  # running
        assert not rows[1].startswith("●")
        assert "2026-11-18 10:30:52" in rows[0]
        # The cursor follows the newest app, not the old top row.
        assert modal.query_one("#app-list", OptionList).highlighted == 0


async def test_ctrl_r_refreshes_and_keeps_filter() -> None:
    calls: list[bool] = []
    packages = [dict(p) for p in OLD]

    def loader(include_system: bool) -> list[dict]:
        calls.append(include_system)
        return [dict(FIREFOX), *packages]

    modal = AppSelectionModal(packages=list(packages), package_loader=loader)
    async with _Host(modal).run_test(size=(120, 40)) as pilot:
        await settle(pilot)
        assert calls == []  # no initial_loader: no automatic refresh
        await pilot.press("o", "r", "g")
        await pilot.press("ctrl+r")
        await until(
            pilot, lambda: calls == [False] and len(modal.filtered_packages) == 2
        )
        assert modal.query_one("#filter-input", Input).value == "org"
        assert _names(modal.filtered_packages) == [
            "org.mozilla.firefox",
            "org.wikipedia",
        ]


async def test_typing_during_the_open_refresh_keeps_the_filter() -> None:
    """E2E L9: text typed while the title said "(refreshing…)" was lost."""
    import threading

    release = threading.Event()

    def loader(include_system: bool) -> list[dict]:
        release.wait(10)
        return [dict(FIREFOX), *OLD]

    modal = AppSelectionModal(
        packages=[dict(p) for p in OLD],
        package_loader=loader,
        initial_loader=lambda on_status=None: loader(False),
    )
    async with _Host(modal).run_test(size=(120, 40)) as pilot:
        await until(
            pilot, lambda: "refreshing" in str(modal.query_one(".modal-title").render())
        )
        await pilot.press("f", "i", "r")
        release.set()
        await until(pilot, lambda: len(modal.all_packages) == 3)
        assert modal.query_one("#filter-input", Input).value == "fir"
        assert _names(modal.filtered_packages) == ["org.mozilla.firefox"]


async def test_ctrl_s_system_apps_keeps_the_filter() -> None:
    """N6-B5: Ctrl+S (system apps) cleared the filter, also text typed while
    the list reloaded.
    """
    import threading

    release = threading.Event()
    settings = {"package_name": "com.android.settings", "install_date": "x"}

    def loader(include_system: bool) -> list[dict]:
        release.wait(10)
        return [dict(settings), *OLD] if include_system else list(OLD)

    modal = AppSelectionModal(packages=[dict(p) for p in OLD], package_loader=loader)
    async with _Host(modal).run_test(size=(120, 40)) as pilot:
        await settle(pilot)
        await pilot.press("s", "e", "t")
        await pilot.press("ctrl+s")
        await pilot.press("t")  # typed during the reload
        release.set()
        await until(pilot, lambda: len(modal.all_packages) == 3)
        await settle(pilot)
        assert modal.query_one("#filter-input", Input).value == "sett"
        assert _names(modal.filtered_packages) == ["com.android.settings"]


def test_adb_commands_never_read_the_terminal(monkeypatch) -> None:
    """E2E L9 root cause: ``adb shell`` forwards its stdin to the device. With
    the TUI's terminal as stdin it consumed keys typed while the picker's
    refresh ran its adb commands, so they never reached the filter.
    """
    import subprocess

    from sandroid.core import adb as adb_mod
    from sandroid.core.adb import Adb

    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(kwargs.get("stdin"))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(adb_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(Adb, "ADB_PATH", "/x/adb")
    Adb.send_adb_command("shell pm list packages -3")
    Adb.send_adb_exec_out_command("cat /x")
    assert seen == [subprocess.DEVNULL, subprocess.DEVNULL]


# --------------------------------------------------------------------------
# Filter text is visible (every stylesheet)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("css", STYLESHEETS, ids=lambda p: p.stem)
async def test_app_picker_filter_shows_typed_text(css: Path) -> None:
    modal = AppSelectionModal(packages=[dict(FIREFOX), *OLD])
    async with _Host(modal, css_path=css).run_test(size=(120, 40)) as pilot:
        await settle(pilot)
        field = modal.query_one("#filter-input", Input)
        await pilot.press("f", "i", "r")
        await pilot.pause()
        assert field.value == "fir"
        assert field.content_region.height == 1  # a real text row
        assert _names(modal.filtered_packages) == ["org.mozilla.firefox"]


@pytest.mark.parametrize("css", STYLESHEETS, ids=lambda p: p.stem)
async def test_selection_modal_filter_has_a_text_row(css: Path) -> None:
    modal = SelectionModal(title="Pick", options=["alpha", "beta"])
    async with _Host(modal, css_path=css).run_test(size=(120, 40)) as pilot:
        await settle(pilot)
        assert modal.query_one("#filter-input", Input).content_region.height == 1


class _CompactProbe(ForensicModal[None]):
    """A swept (compact) Input carrying a themed, bordered ID."""

    def compose(self):
        yield Input(id="filter-input")


@pytest.mark.parametrize("css", STYLESHEETS, ids=lambda p: p.stem)
async def test_compact_inputs_stay_borderless_under_app_css(css: Path) -> None:
    modal = _CompactProbe()
    async with _Host(modal, css_path=css).run_test(size=(80, 20)) as pilot:
        await settle(pilot)
        field = modal.query_one(Input)
        assert field.compact
        assert field.content_region.height == 1


# --------------------------------------------------------------------------
# Screenshot
# --------------------------------------------------------------------------


def _controller(log: list[tuple[str, str]], result):
    from sandroid.tui.controllers.screenshot_controller import ScreenshotController

    return ScreenshotController(
        log_info=lambda m: log.append(("info", m)),
        log_error=lambda m: log.append(("error", m)),
        log_success=lambda m: log.append(("success", m)),
        push_modal=lambda modal, cb: cb(result),
    )


def test_escape_in_screenshot_dialog_is_a_cancel_not_an_error() -> None:
    log: list[tuple[str, str]] = []
    _controller(log, None).show_screenshot_modal()
    assert log == [("info", "Screenshot cancelled")]


def test_screenshot_success_says_where_it_was_saved(monkeypatch) -> None:
    from sandroid.tui.modals import ScreenshotResult

    class _Svc:
        def take_screenshot(self, filename):
            return f"/results/screenshots/{filename}.png"

    monkeypatch.setattr("sandroid.services.get_emulator_service", lambda: _Svc())
    log: list[tuple[str, str]] = []
    _controller(
        log, ScreenshotResult(cancelled=False, filename="x")
    ).show_screenshot_modal()
    assert log == [("success", "Screenshot saved to /results/screenshots/x.png")]


class _ShotAdb:
    """Console answers OK (as it does) but writes nothing; screencap works."""

    def __init__(self, console_writes: bool = False) -> None:
        self.console_writes = console_writes
        self.commands: list[str] = []

    def send_telnet_command(self, command: str) -> tuple[str, str]:
        self.commands.append(f"emu {command}")
        if self.console_writes:
            Path(command.split()[-1]).write_bytes(b"\x89PNG console")
        return "OK", ""

    def send_adb_command(self, command: str) -> tuple[str, str]:
        self.commands.append(command)
        if command.startswith("pull "):
            local = command.split(" ", 2)[2].strip("'\"")
            Path(local).write_bytes(b"\x89PNG screencap")
        return "", ""


def _emulator_service(adb, tmp_path: Path, monkeypatch, rel: str = "raw"):
    from sandroid.services.emulator_service import EmulatorService

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RAW_RESULTS_PATH", rel)  # relative on purpose
    return EmulatorService(adb=adb)


def test_screenshot_path_is_absolute_for_the_emulator_console(
    tmp_path, monkeypatch
) -> None:
    adb = _ShotAdb(console_writes=True)
    path = _emulator_service(adb, tmp_path, monkeypatch).take_screenshot("shot")
    expected = str(tmp_path.resolve() / "raw" / "screenshots" / "shot.png")
    assert os.path.realpath(path) == expected
    assert adb.commands[0].split()[-1] == path
    assert Path(path).is_absolute()
    assert not any("screencap" in c for c in adb.commands)


def test_screenshot_falls_back_to_screencap_when_console_writes_nothing(
    tmp_path, monkeypatch
) -> None:
    adb = _ShotAdb(console_writes=False)
    svc = _emulator_service(adb, tmp_path, monkeypatch)
    # A stale file of the same name must not count as this capture.
    target = tmp_path / "raw" / "screenshots" / "shot.png"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old")
    os.utime(target, (1, 1))

    path = svc.take_screenshot("shot")

    assert path
    assert Path(path).read_bytes() == b"\x89PNG screencap"
    assert any(c.startswith("shell screencap -p ") for c in adb.commands)


def test_screenshot_returns_none_when_nothing_is_captured(
    tmp_path, monkeypatch
) -> None:
    adb = _ShotAdb(console_writes=False)
    adb.send_adb_command = lambda command: ("", "error: no devices/emulators found")
    assert _emulator_service(adb, tmp_path, monkeypatch).take_screenshot("x") is None
