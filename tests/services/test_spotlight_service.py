"""SpotlightService is the single source of truth for the spotlight app.

Covers the canonical state (one selection, no spawn/attach mode), the
callers that used to read the removed legacy Toolbox state, and source
guards that keep the legacy state and the old mode API from coming back.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.services.spotlight_service import SpotlightService

_SRC = Path(__file__).resolve().parents[2] / "src"

A = "com.example.alpha"
B = "com.example.bravo"


class _FakeJobManager:
    def __init__(self, pid: int = 4321) -> None:
        self.pid = pid

    def spawn_paused(self, package_name: str) -> int:
        return self.pid


# -- canonical state ----------------------------------------------------------


def test_set_app_replaces_the_selection():
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=99)

    svc.set_app(B)

    assert svc.get_effective_package() == B
    assert svc.get_app_tuple() == (B, "")
    assert svc.get_pid() is None
    assert svc.get_activity_name() is None


def test_set_app_of_the_same_package_keeps_pid_and_activity():
    """A re-pick of the running app (⇧C, AI) keeps its PID and activity."""
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.set_app(A)

    assert svc.get_pid() == 1
    assert svc.get_activity_name() == ".Main"
    svc.set_pid(2)
    assert svc.get_app().pid == 2


def test_set_app_with_an_explicit_none_pid_clears_it():
    """⇧C after a lookup that found nothing: the stale PID must go."""
    svc = SpotlightService()
    svc.set_app(A, pid=1)

    svc.set_app(A, pid=None)

    assert svc.get_pid() is None


def test_set_app_still_validates_the_package():
    with pytest.raises(ValueError):
        SpotlightService().set_app("com.x;id")


def test_spawn_app_paused_of_another_package_replaces_the_selection(monkeypatch):
    monkeypatch.setattr(SpotlightService, "_spawn_listeners", [])
    svc = SpotlightService(job_manager_factory=_FakeJobManager)
    svc.set_app(A, pid=1)

    _jm, pid = svc.spawn_app_paused(B)

    assert pid == 4321
    assert svc.get_effective_package() == B
    assert svc.get_pid() is None


def test_spawn_app_paused_of_the_same_package_drops_the_old_pid(monkeypatch):
    """A fresh spawn of the selected app: the old process's PID is stale."""
    monkeypatch.setattr(SpotlightService, "_spawn_listeners", [])
    svc = SpotlightService(job_manager_factory=_FakeJobManager)
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.spawn_app_paused(A)

    assert svc.get_effective_package() == A
    assert svc.get_pid() is None
    assert svc.get_activity_name() == ".Main"


class _PausedJM:
    def __init__(self, package_name, paused=True):
        self.package_name = package_name
        self._paused = paused

    def is_paused(self):
        return self._paused


def test_is_app_paused_is_scoped_to_the_spotlight_package():
    svc = SpotlightService(job_manager_factory=lambda: _PausedJM(B))
    svc.set_app(A, pid=1)
    assert svc.is_app_paused() is False

    svc = SpotlightService(job_manager_factory=lambda: _PausedJM(A))
    svc.set_app(A, pid=1)
    assert svc.is_app_paused() is True


@pytest.mark.parametrize(
    ("pid", "paused", "restarting", "state"),
    [
        (7, False, False, "running"),
        (7, True, False, "paused"),
        (None, True, False, "paused"),  # a held spawn pidof cannot name yet
        (None, False, False, "not_running"),
        (None, False, True, "restarting"),
    ],
)
def test_run_state(pid, paused, restarting, state):
    svc = SpotlightService(job_manager_factory=lambda: _PausedJM(A, paused))
    svc.set_app(A, pid=pid)
    if restarting:
        svc._restarting = A

    assert svc.get_run_state() == state


def test_reset_clears_everything():
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.reset()

    assert svc.has_app() is False
    assert svc.get_effective_package() is None
    assert svc.get_app() is None
    assert svc.get_pid() is None


def test_state_dict_reports_the_run_state_not_a_mode():
    svc = SpotlightService(job_manager_factory=lambda: _PausedJM(A, False))
    svc.set_app(A, pid=3)

    state = svc.get_state_dict()

    assert set(state) == {
        "has_app",
        "package_name",
        "activity_name",
        "pid",
        "state",
        "running",
        "paused",
        "set_at",
    }
    assert state["package_name"] == A
    assert state["state"] == "running"
    assert state["running"] is True
    assert state["paused"] is False


# -- callers with a selected app that is not running ----------------------------


@pytest.fixture
def spawn_spotlight(monkeypatch) -> SpotlightService:
    """A fresh service with a selected (not running) app, as the singleton."""
    svc = SpotlightService()
    svc.set_app("org.wikipedia")
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    return svc


def test_monitor_command_offers_pid_mode_for_a_spawn_mode_app(
    monkeypatch, spawn_spotlight
):
    from sandroid.commands.base import CommandContext
    from sandroid.commands.monitoring_commands import MonitorCommand
    from sandroid.core.fsmon import FSMon

    monkeypatch.setattr(FSMon, "check_and_install_fsmon", staticmethod(lambda: None))
    offered: list = []

    def request_selection(title: str, options: list, message: str = "") -> None:
        offered.extend(options)  # and answer None: Esc, do not start

    ctx = CommandContext(
        is_tui_mode=True,
        spotlight_service=spawn_spotlight,
        adb=SimpleNamespace(get_pid_for_package_name=lambda package: 4242),
        request_selection=request_selection,
    )

    result = asyncio.run(MonitorCommand().start_task(ctx))

    assert result.error == "cancelled"
    assert offered[0] == "Monitor by PID (4242 - org.wikipedia)"


def test_ai_context_reads_the_watchlist_from_forensic_service(monkeypatch):
    from sandroid.ai import context

    monkeypatch.setattr(
        services,
        "get_forensic_service",
        lambda: SimpleNamespace(get_spotlight_files=lambda: ["/sdcard/a.db"]),
    )

    assert context._describe_spotlight_files() == (
        "Spotlight files being watched: /sdcard/a.db"
    )


def test_fritap_gather_points_at_start_and_stop():
    from sandroid.analysis.fritap import FriTap

    fritap = FriTap.__new__(FriTap)  # gather() must not need any state
    with pytest.raises(NotImplementedError, match=r"start\(\).*stop\(\)"):
        fritap.gather()


def test_headless_security_run_after_a_malware_run_analyses_its_own_app(
    monkeypatch, tmp_path
):
    """Malware run on A (spawn mode), then security run on B: B is analysed."""
    from sandroid.analysis import static_analysis
    from sandroid.api.analysis_runners import run_security_analysis

    svc = SpotlightService()
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(static_analysis, "asam", SimpleNamespace())
    sent: list[str] = []

    def send(self, command):
        sent.append(command)
        return "", "error: stop here"

    monkeypatch.setattr(static_analysis.StaticAnalysis, "_send_adb_command", send)
    monkeypatch.chdir(tmp_path)

    svc.set_app(A)  # what run_malware_analysis does
    asyncio.run(run_security_analysis(adb=None, toolbox=None, apk_path=B))

    assert sent[0] == f"shell pm path {B}"
    assert svc.get_effective_package() == B


# -- guard ---------------------------------------------------------------------

_LEGACY_NAMES = re.compile(
    r"get_spotlight_application|set_spotlight_application|_spotlight_application\b"
    r"|_spotlight_application_pid|spotlight_spawn_application"
    r"|auto_resume_after_spawn|get_application_pid|\.get_application\("
    r"|reset_application\(|(get|set)_spawn_application\("
    r"|get_spotlighted_app_data_path"
)


def test_no_source_file_uses_the_legacy_spotlight_state():
    offenders = [
        f"{path.relative_to(_SRC)}:{n}"
        for path in _SRC.rglob("*.py")
        for n, line in enumerate(path.read_text("utf-8").splitlines(), 1)
        if _LEGACY_NAMES.search(line)
    ]
    assert not offenders, offenders


#: The spawn/attach mode API is gone (no shims): nothing in src/ may use it.
_REMOVED_MODE_NAMES = re.compile(
    r"\bset_spawn_app\(|\bis_spawn_mode\(|\bget_spawn_package\(|\bset_spawn_mode\("
    r"|\b(get|set)_auto_resume\(|\bget_effective_mode\(|get_spawn_mode_string"
    r"|SpawnModeModal|SpotlightSelectionUI|ensure_(spotlight_)?app_for_tools"
    r"|\bspawn_app_paused\(.*auto_resume|\bspawn_mode_modal\b"
    r"|\bspotlight_selection_ui\b"
)


def test_no_source_file_uses_the_removed_mode_api():
    offenders = [
        f"{path.relative_to(_SRC).as_posix()}:{n}"
        for path in _SRC.rglob("*.py")
        for n, line in enumerate(path.read_text("utf-8").splitlines(), 1)
        if _REMOVED_MODE_NAMES.search(line)
    ]
    assert not offenders, offenders


def test_spotlight_app_and_its_event_have_no_mode():
    from sandroid.services.spotlight_service import SpotlightApp

    assert "mode" not in SpotlightApp.__dataclass_fields__
    events: list = []
    svc = SpotlightService(event_bus=SimpleNamespace(publish=events.append))
    svc.set_app(A)
    svc.reset()
    assert events
    assert all("mode" not in e.data for e in events)
    for gone in ("set_spawn_app", "is_spawn_mode", "get_effective_mode"):
        assert not hasattr(svc, gone)
