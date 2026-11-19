"""SpotlightService is the single source of truth for the spotlight app.

Covers the canonical state (attach vs spawn selection stay consistent), the
callers that used to read the removed legacy Toolbox state, and a source
guard that keeps that legacy state from coming back.
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


def test_set_app_after_spawn_app_leaves_spawn_mode():
    svc = SpotlightService()
    svc.set_spawn_app(A, auto_resume=False)
    svc.set_pid(99)

    svc.set_app(B)

    assert svc.get_effective_package() == B
    assert svc.get_app_tuple() == (B, "")
    assert svc.is_spawn_mode() is False
    assert svc.get_spawn_package() is None
    assert svc.get_auto_resume() is True
    assert svc.get_pid() is None


def test_spawn_app_of_another_package_drops_the_attach_record():
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.set_spawn_app(B)

    assert svc.get_effective_package() == B
    assert svc.get_pid() is None
    assert svc.get_activity_name() is None
    assert svc.get_app() is None


def test_spawn_app_of_the_same_package_keeps_it_with_its_pid():
    """⇧C re-pick of the attached app keeps its PID, so Space re-checks it."""
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.set_spawn_app(A)

    assert svc.get_effective_package() == A
    assert svc.is_spawn_mode() is True
    assert svc.get_pid() == 1
    assert svc.get_activity_name() == ".Main"
    svc.set_pid(2)
    assert svc.get_pid() == 2
    assert svc.get_app().pid == 2


def test_spawn_app_paused_uses_the_same_selection_rules(monkeypatch):
    monkeypatch.setattr(SpotlightService, "_spawn_listeners", [])
    svc = SpotlightService(job_manager_factory=_FakeJobManager)
    svc.set_app(A, pid=1)

    _jm, pid = svc.spawn_app_paused(B)

    assert pid == 4321
    assert svc.get_effective_package() == B
    assert svc.is_spawn_mode() is True
    assert svc.get_auto_resume() is False
    assert svc.get_app() is None
    assert svc.get_pid() is None


def test_spawn_app_paused_of_the_same_package_drops_the_old_pid(monkeypatch):
    """A fresh spawn of the attached app: the old process's PID is stale."""
    monkeypatch.setattr(SpotlightService, "_spawn_listeners", [])
    svc = SpotlightService(job_manager_factory=_FakeJobManager)
    svc.set_app(A, activity_name=".Main", pid=1)

    svc.spawn_app_paused(A)

    assert svc.get_effective_package() == A
    assert svc.get_pid() is None
    assert svc.get_activity_name() == ".Main"


def test_pid_getters_ignore_an_attach_record_of_another_package():
    """Defence in depth: a stale attach record never answers for the target."""
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)
    svc.set_spawn_mode(True)
    svc._spawn_package = B  # a state no public path produces any more

    assert svc.get_pid() is None
    assert svc.get_activity_name() is None
    svc.set_pid(7)
    assert svc.get_pid() == 7
    assert svc.get_app().pid == 1  # B's PID is not written into A's record


def test_reset_clears_everything():
    svc = SpotlightService()
    svc.set_app(A, activity_name=".Main", pid=1)
    svc.set_spawn_app(B, auto_resume=False)
    svc.set_pid(3)

    svc.reset()

    assert svc.has_app() is False
    assert svc.get_effective_package() is None
    assert svc.get_app() is None
    assert svc.get_pid() is None
    assert svc.is_spawn_mode() is False
    assert svc.get_spawn_package() is None
    assert svc.get_auto_resume() is True


def test_state_dict_has_no_legacy_keys():
    svc = SpotlightService()
    svc.set_spawn_app(A)

    state = svc.get_state_dict()

    assert set(state) == {
        "has_app",
        "package_name",
        "activity_name",
        "pid",
        "mode",
        "spawn_mode",
        "spawn_package",
        "auto_resume",
        "set_at",
    }
    assert state["package_name"] == A


# -- callers in spawn mode ------------------------------------------------------


@pytest.fixture
def spawn_spotlight(monkeypatch) -> SpotlightService:
    """A fresh service in spawn mode, installed as the process singleton."""
    svc = SpotlightService()
    svc.set_spawn_app("org.wikipedia")
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    return svc


def test_recording_hint_sees_a_spawn_mode_app(monkeypatch, spawn_spotlight):
    from sandroid.tui.modals import recording_modal

    monkeypatch.setattr(
        "sandroid.config.get_config",
        lambda: SimpleNamespace(
            analysis=SimpleNamespace(network_reset_after_snapshot="off")
        ),
    )
    monkeypatch.setattr(
        recording_modal.Adb,
        "get_focused_app",
        classmethod(lambda cls, max_retries=3: ("org.wikipedia", ".Main")),
    )

    hint = recording_modal.foreground_app_hint()

    assert hint is not None
    assert "org.wikipedia" in hint


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

    svc.set_spawn_app(A, auto_resume=True)  # what run_malware_analysis does
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
