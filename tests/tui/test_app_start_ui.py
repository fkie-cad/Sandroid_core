"""Where the app-selection rule asks the user (App lens, Objection).

⇧P on a running app and a start-time bypass toggled on a running app ask
before any restart; No keeps the app. Objection defaults to attach for a
running app and warns while spawn (which restarts it) is selected. Waits are
by condition (no fixed sleeps).
"""

from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace

import pytest
from pilot_helpers import settle, until
from rich.text import Text
from textual.app import App

from sandroid import services
from sandroid.services import app_start
from sandroid.services.spotlight_service import SpotlightService
from sandroid.tui.modals.confirm_modal import ConfirmModal
from sandroid.tui.themes import lens_palette
from sandroid.tui.widgets import app_lens
from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

PKG = "org.wikipedia"


class _Harness(App):
    def compose(self):
        yield SpotlightPanel(id="spotlight")


def _panel_env(monkeypatch, *, pid=77, tools=()):
    svc = SpotlightService(job_manager_factory=lambda: None)
    svc.set_app(PKG, pid=pid)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(app_start, "app_tools", lambda package: tuple(tools))
    monkeypatch.setattr(app_lens.AppLensSections, "track", lambda *a, **k: None)
    monkeypatch.setattr(SpotlightPanel, "_poll_running_state", lambda self: None)
    ran: list[str] = []
    monkeypatch.setattr(
        SpotlightPanel,
        "_run_frida_action",
        lambda self, work, label, feature: ran.append(label),
    )
    return svc, ran


async def test_shift_p_on_a_running_app_asks_and_no_keeps_it(monkeypatch):
    _svc, ran = _panel_env(monkeypatch, tools=("Dexray-Intercept", "FriTap"))
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda pkg, frida_fallback=False: (app_start.Liveness.RUNNING, 77),
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(SpotlightPanel)
        panel.action_start_paused()
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        modal = app.screen
        assert modal.title_text == f"Restart {PKG} paused?"
        assert "(pid 77)" in modal.message_text
        assert modal.message_text.endswith("This stops: Dexray-Intercept, FriTap.")
        assert modal.guard_typing is True
        await pilot.press("n")
        await until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert ran == []  # kept running


async def test_shift_p_on_a_stopped_app_starts_paused_without_asking(monkeypatch):
    _svc, ran = _panel_env(monkeypatch, pid=None)
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda pkg, frida_fallback=False: (app_start.Liveness.NOT_RUNNING, None),
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one(SpotlightPanel).action_start_paused()
        await until(pilot, lambda: ran == ["start-paused"])
        assert not isinstance(app.screen, ConfirmModal)


class _EmulatorBypass:
    """BypassService double: toggling the emulator category goes live."""

    def __init__(self):
        self.on: set[str] = set()

    def on_categories(self):
        return sorted(self.on)

    def toggle(self, category):
        self.on.add(category)
        return True, "Emulator (exp.) active"

    def is_active(self, category):
        return category in self.on

    def applies_at_spawn(self, category):
        return category == "emulator"

    def display_name(self, category):
        return "Emulator (exp.)"


async def test_b_emulator_on_a_running_app_offers_a_restart(monkeypatch):
    """The b toggle → worker → _post → restart offer, listing the tools."""
    _svc, ran = _panel_env(monkeypatch, tools=("FriTap",))
    bypass = _EmulatorBypass()
    monkeypatch.setattr(SpotlightPanel, "_bypass", staticmethod(lambda: bypass))
    monkeypatch.setattr(
        SpotlightPanel, "_frida_server_running", staticmethod(lambda: True)
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        panel.action_toggle_bypass("emulator")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        assert app.screen.title_text == f"Restart {PKG} now?"
        assert app.screen.yes_label == "Restart"
        assert app.screen.no_label == "Keep running"
        assert app.screen.message_text.endswith("This stops: FriTap.")
        await pilot.press("n")
        await until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert ran == []


def test_header_shows_the_run_state_and_no_mode(monkeypatch):
    svc, _ran = _panel_env(monkeypatch)
    panel = SpotlightPanel()

    def plain() -> str:
        return Text.from_markup(panel._render_header()).plain

    assert plain().startswith(f"● running pid 77  {PKG}")
    assert "spawn" not in plain()
    svc.set_pid(None)
    assert plain().startswith(f"○ not running  Space starts  {PKG}")
    svc.reset()
    header = panel._render_header()
    assert "use the foreground app" in header
    assert "pick an app…" in header


async def test_objection_warns_while_spawn_would_restart_the_app() -> None:
    from sandroid.tui.modals.objection_modal import ObjectionModal

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(
                ObjectionModal(
                    package_name=PKG, initial_spawn_mode=False, running_pid=77
                )
            )

    app = Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await until(pilot, lambda: isinstance(app.screen, ObjectionModal))
        modal = app.screen
        assert modal.config.spawn_mode is False  # running: attach by default
        assert modal._warning_text() == ""
        await pilot.press("s")
        assert modal.config.spawn_mode is True
        assert "Restarts the running app (pid 77)" in modal._warning_text()
        assert "Enter confirms" in modal._warning_text()


_AM_HELD = """\
ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)
  *APP* UID 10219 ProcessRecord{9075a3 8735:org.mozilla.firefox/u0a219}
    user #0 uid=10219 gids={50219, 20219, 9997}
    pid=8735 starting=true lastPss=0.00
    thread=null
  PID mappings:
    PID #8735: ProcessRecord{9075a3 8735:org.mozilla.firefox/u0a219}
"""

_AM_RESUMED = """\
  *APP* UID 10219 ProcessRecord{1a2b3c 9001:org.mozilla.firefox:tab/u0a219}
    thread=android.app.IApplicationThread$Stub$Proxy@6f1be70
  *APP* UID 10219 ProcessRecord{9075a3 8735:org.mozilla.firefox/u0a219}
    pid=8735
    thread=android.app.IApplicationThread$Stub$Proxy@c72926e
"""


def test_a_held_spawn_is_not_taken_for_a_resumed_app() -> None:
    """Device fact (API 35, frida 17): a held spawn reads ``State S`` and
    ``TracerPid 0`` in /proc like a running app; only ActivityManager's
    ``thread=null`` tells them apart. The old /proc self-heal cleared the
    paused flag ~2 s after ⇧P, so Space said "already running" and Android
    killed the app at its 10 s start timeout.
    """
    parse = SpotlightPanel._parse_am_process_attached
    assert parse(_AM_HELD, 8735) is False
    assert parse(_AM_RESUMED, 8735) is True
    # Another process of the same package being attached says nothing about ours.
    assert parse(_AM_RESUMED.replace(" 8735:", " 8800:"), 8735) is False
    assert parse("", 8735) is False


def test_am_parser_matches_whole_pids_and_record_boundaries() -> None:
    parse = SpotlightPanel._parse_am_process_attached
    # " 873:" must not match the " 8735:" record (and vice versa).
    collide = (
        "  *APP* UID 10219 ProcessRecord{9075a3 8735:org.mozilla.firefox/u0a219}\n"
        "    thread=android.app.IApplicationThread$Stub$Proxy@c72926e\n"
        "  *APP* UID 10220 ProcessRecord{11aa22 873:org.example/u0a220}\n"
        "    thread=null\n"
    )
    assert parse(collide, 873) is False
    assert parse(collide, 8735) is True
    # thread=null with trailing detail is still unattached.
    assert parse(collide.replace("thread=null", "thread=null pid=873"), 873) is False
    # *PERS*, isolated and sandboxed records end ours: their thread= is theirs.
    for header in (
        "  *PERS* UID 1000 ProcessRecord{55ee66 700:system/1000}",
        "  Isolated #0: ProcessRecord{77ff88 701:org.example:sandboxed/u0i5}",
        "  *APP* UID 99001 ProcessRecord{99aa00 702:org.example:privileged_process0/u0i9}",
    ):
        dump = (
            "  *APP* UID 10220 ProcessRecord{11aa22 873:org.example/u0a220}\n"
            "    pid=873 starting=true\n"
            f"{header}\n"
            "    thread=android.app.IApplicationThread$Stub$Proxy@1\n"
        )
        assert parse(dump, 873) is False, header


def test_a_record_sub_header_does_not_end_the_record() -> None:
    """AOSP prints ``processInfo:`` (indent 4) before ``thread=`` for apps
    that declare ``<processes>``; it is part of the record, not a title.
    """
    dump = (
        "  *APP* UID 10219 ProcessRecord{9075a3 8735:org.mozilla.firefox/u0a219}\n"
        "    processInfo:\n"
        "      name=org.mozilla.firefox\n"
        "    thread=android.app.IApplicationThread$Stub$Proxy@c72926e\n"
        "  PID mappings:\n"
    )
    assert SpotlightPanel._parse_am_process_attached(dump, 8735) is True


# -- the action watchdog and the pre-start step ----------------------------------


class _SlowFuture:
    """Done at ``done_at`` on a fake clock; every wait advances the clock."""

    def __init__(self, clock, done_at: float) -> None:
        self.clock, self.done_at = clock, done_at

    def result(self, timeout: float):
        self.clock.now += timeout
        if self.clock.now >= self.done_at:
            return True, "Spawned"
        raise concurrent.futures.TimeoutError


def test_the_watchdog_does_not_count_a_pre_start_step(monkeypatch):
    """A 5-minute dialog + framework restart, then a 60 s spawn: no timeout."""
    from sandroid.tui.widgets import spotlight_panel as sp

    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(sp, "time", SimpleNamespace(monotonic=lambda: clock.now))
    panel = SimpleNamespace(_ACTION_TIMEOUT=90.0)
    monkeypatch.setattr(app_start, "pre_start_running", lambda: clock.now < 300)

    result = SpotlightPanel._await_action(panel, _SlowFuture(clock, 360))

    assert result == (True, "Spawned")

    clock.now = 0.0  # without a pre-start step the watchdog trips at 90 s
    monkeypatch.setattr(app_start, "pre_start_running", lambda: False)
    with pytest.raises(concurrent.futures.TimeoutError):
        SpotlightPanel._await_action(panel, _SlowFuture(clock, 360))
    assert clock.now == pytest.approx(90.0)


# -- ⇧K keeps the armed bypasses; Stop all, ⇧X and a new app clear them --------


def _bypass_env(monkeypatch, *, armed=(), active=(), tasks=()):
    """A real BypassService (no Frida) and fake tasks, adb and JobManager."""
    from sandroid.analysis import detection_bypass as db
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox
    from sandroid.tui.widgets import spotlight_panel as sp

    state = SimpleNamespace(stopped=[], killed=[], notes=[], resets=[])
    fake_tasks = SimpleNamespace(
        get_running_tasks=lambda: list(tasks),
        stop=lambda name: state.stopped.append(name) or True,
        is_running=lambda name: False,
        unregister=lambda name: None,
    )
    monkeypatch.setattr(services, "get_task_service", lambda: fake_tasks)
    monkeypatch.setattr(db, "get_task_service", lambda: fake_tasks)
    bypass = db.BypassService()
    bypass._armed, bypass._active = set(armed), set(active)
    bypass._app_package = PKG if active else None
    monkeypatch.setattr(db, "_INSTANCE", bypass)
    monkeypatch.setattr(Adb, "force_stop", staticmethod(state.killed.append))
    monkeypatch.setattr(
        Toolbox,
        "get_frida_job_manager",
        staticmethod(
            lambda: SimpleNamespace(reset_session=lambda: state.resets.append(1))
        ),
    )
    real_time = sp.time
    monkeypatch.setattr(
        sp, "time", SimpleNamespace(sleep=lambda s: None, monotonic=real_time.monotonic)
    )
    monkeypatch.setattr(
        SpotlightPanel,
        "_notify",
        lambda self, message, severity="information": state.notes.append(message),
    )
    state.bypass = bypass
    return state


async def test_shift_k_keeps_every_bypass_that_was_on_armed(monkeypatch):
    svc, _ran = _panel_env(monkeypatch)
    tasks = (
        SimpleNamespace(name="fritap", app_name=PKG, display_name="FriTap"),
        SimpleNamespace(name="bypass", app_name=PKG, display_name="Bypass"),
    )
    # root was armed; ssl was only active (Ctrl+P on the running app).
    env = _bypass_env(monkeypatch, armed={"root"}, active={"ssl"}, tasks=tasks)
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(SpotlightPanel)
        panel.action_kill_app()
        modal = await until(
            pilot, lambda: isinstance(app.screen, ConfirmModal) and app.screen
        )
        modal._opened_at -= modal.ARM_SECONDS  # read, not typed ahead
        await pilot.press("y")
        await until(pilot, lambda: env.notes)

    assert env.notes == [
        f"Killed {PKG} — bypass ssl, root stay armed; Space starts with them"
    ]
    assert env.killed == [PKG]
    assert env.stopped == ["fritap"]  # the bypass task is not stopped
    assert sorted(env.bypass.armed_categories()) == ["root", "ssl"]
    assert env.bypass.active_categories() == []
    assert env.resets == [1]
    assert svc.get_pid() is None


async def test_shift_k_arms_live_bypasses_before_the_kill(monkeypatch):
    """The liveness poll may drop the active set as soon as the app dies."""
    from sandroid.core.adb import Adb

    _panel_env(monkeypatch)
    env = _bypass_env(monkeypatch, active={"ssl"})

    def _kill(pkg):
        env.killed.append(pkg)
        env.bypass._active.clear()  # the poll saw the dead process

    monkeypatch.setattr(Adb, "force_stop", staticmethod(_kill))
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(SpotlightPanel)
        panel.action_kill_app()
        modal = await until(
            pilot, lambda: isinstance(app.screen, ConfirmModal) and app.screen
        )
        modal._opened_at -= modal.ARM_SECONDS
        await pilot.press("y")
        await until(pilot, lambda: env.notes)

    assert env.bypass.armed_categories() == ["ssl"]


async def test_shift_k_without_bypasses_says_killed(monkeypatch):
    _panel_env(monkeypatch)
    env = _bypass_env(monkeypatch)
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        await settle(pilot)
        ok, msg = app.query_one(SpotlightPanel)._work_kill()
    assert (ok, msg) == (True, f"Killed {PKG}")
    assert env.bypass.armed_categories() == []


async def test_stop_all_clears_the_armed_set(monkeypatch):
    _panel_env(monkeypatch)
    env = _bypass_env(monkeypatch, armed={"root"}, active={"ssl"})
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one(SpotlightPanel).action_stop_all()
        await until(pilot, lambda: env.notes)
    assert env.notes == ["Stopped 1 item(s)"]
    assert env.bypass.armed_categories() == []
    assert env.killed == []  # the app keeps running


async def test_shift_x_and_another_app_disarm(monkeypatch):
    svc, _ran = _panel_env(monkeypatch)
    env = _bypass_env(monkeypatch, armed={"ssl", "root"})
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        await settle(pilot)
        svc.set_app(PKG)  # a re-pick of the same app keeps them
        assert sorted(env.bypass.armed_categories()) == ["root", "ssl"]
        app.query_one(SpotlightPanel).action_clear_spotlight()  # ⇧X
        assert env.bypass.armed_categories() == []

        env.bypass._armed = {"ssl"}
        svc.set_app(PKG)
        svc.set_app("org.example.other")  # another app: armed was per-app
        assert env.bypass.armed_categories() == []


# -- the identity profile notice ------------------------------------------------------


class _Identity:
    """IdentityService double: applied_state + the status listener."""

    def __init__(self, state: str | None, profile: str = "mara-de") -> None:
        self.state = state
        self.listeners: list = []
        self._config = SimpleNamespace(profile=profile)

    def applied_state(self, package, serial=None):
        return self.state

    def config(self):
        return self._config

    def add_status_listener(self, cb):
        self.listeners.append(cb)

    def remove_status_listener(self, cb):
        self.listeners.remove(cb)

    def fire(self):
        """A plan/apply/verify finished (listeners run on a worker thread)."""
        import threading

        for cb in list(self.listeners):
            threading.Thread(target=cb, args=([],)).start()


def _identity_env(monkeypatch, state, *, pid=77):
    from sandroid.services import identity

    svc, _ran = _panel_env(monkeypatch, pid=pid)
    fake = _Identity(state)
    monkeypatch.setattr(identity, "get_identity_service", lambda: fake)
    return svc, fake


def _body(app) -> str:
    return str(app.query_one("#spotlight-body").content)


FULL = (
    "Identity profile 'mara-de' not applied to this app — it started before the "
    "profile. Shift+R restarts it with the profile; Space in the Identity lens applies "
    "the live values without a restart."
)
SHORT = "Identity profile 'mara-de' not applied to this app — Shift+R restarts it with "


async def test_identity_notice_comes_and_goes_with_the_applied_state(monkeypatch):
    _svc, fake = _identity_env(monkeypatch, "not_applied")
    app = _Harness()
    async with app.run_test(size=(240, 30)) as pilot:
        await settle(pilot)
        assert "Identity profile" not in _body(app)  # nothing read yet
        fake.fire()
        await until(pilot, lambda: FULL in _body(app))
        panel = app.query_one(SpotlightPanel)
        assert f"[{lens_palette().warn}]" in panel._render_body()

        fake.state = "applied"  # e.g. Space in the Identity lens
        fake.fire()
        await until(pilot, lambda: "Identity profile" not in _body(app))
    assert fake.listeners == []  # unmount unsubscribed


async def test_identity_notice_is_short_on_a_narrow_lens_and_polled(monkeypatch):
    from sandroid.core.adb import Adb

    _svc, _fake = _identity_env(monkeypatch, "not_applied")
    monkeypatch.setattr(
        Adb, "get_pid_for_package_name", staticmethod(lambda *a, **k: 77)
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        panel.run_worker(lambda: panel._poll_worker(PKG), thread=True)
        await until(pilot, lambda: SHORT in _body(app))
        assert FULL not in _body(app)


@pytest.mark.parametrize(("state", "pid"), [(None, 77), ("not_applied", None)])
async def test_no_identity_notice_when_off_or_not_running(monkeypatch, state, pid):
    """Mode off: no line. A stopped app: the pre-start step covers it."""
    _svc, _fake = _identity_env(monkeypatch, state, pid=pid)
    app = _Harness()
    async with app.run_test(size=(240, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        panel._on_identity_status([])  # on the UI thread: repaints inline
        await settle(pilot)
        expected = (PKG, "mara-de") if state else None
        assert panel._identity_gap == expected
        assert "Identity profile" not in _body(app)


# -- fix round: Objection's spawn and the pre-start progress line ------------------


class _ObjectionApp:
    """Just what SandroidTUI._start_objection uses."""

    def __init__(self):
        self.pushed: list = []
        self.notes: list = []

    def push_screen(self, screen):
        self.pushed.append(screen)

    def notify(self, message, severity="information"):
        self.notes.append((message, severity))

    def call_from_thread(self, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def run_worker(self, fn, **kwargs):
        import threading

        self.worker_kwargs = kwargs
        t = threading.Thread(target=fn)
        t.start()
        t.join(5)


@pytest.mark.parametrize("fails", [False, True])
def test_objection_spawn_runs_the_pre_start_step_first(monkeypatch, fails):
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.modals import objection_modal

    calls: list = []

    def prepare(pkg, tool, **kw):
        calls.append((pkg, tool))
        if fails:
            raise app_start.AppStartError(f"{pkg} not started — x not applied")
        return True

    monkeypatch.setattr(app_start, "prepare_launch", prepare)
    monkeypatch.setattr(
        objection_modal, "build_objection_command", lambda pkg, cfg: ["objection"]
    )
    fake = _ObjectionApp()

    SandroidTUI._start_objection(fake, PKG, SimpleNamespace(spawn_mode=True))

    assert calls == [(PKG, "Objection")]
    if fails:
        assert fake.pushed == []
        assert fake.notes == [
            (f"Objection not started: {PKG} not started — x not applied", "error")
        ]
    else:
        assert len(fake.pushed) == 1

    calls.clear()
    fake.pushed.clear()
    SandroidTUI._start_objection(fake, PKG, SimpleNamespace(spawn_mode=False))
    assert calls == []  # attach: no pre-start step
    assert len(fake.pushed) == 1


def test_objection_spawn_does_not_restart_an_app_that_came_up(monkeypatch):
    """prepare_launch() False: the app runs now, a spawn would restart it."""
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.modals import objection_modal

    seen: list = []
    monkeypatch.setattr(
        app_start,
        "prepare_launch",
        lambda pkg, tool, **kw: seen.append(kw.get("restart")) or False,
    )
    monkeypatch.setattr(
        objection_modal, "build_objection_command", lambda pkg, cfg: ["objection"]
    )
    fake = _ObjectionApp()

    SandroidTUI._start_objection(fake, PKG, SimpleNamespace(spawn_mode=True))

    assert fake.pushed == []
    assert fake.notes == [
        (
            f"Objection not started: {PKG} is running now; "
            "open Objection again to attach",
            "warning",
        )
    ]
    assert seen == [False]  # the dialog showed it not running: no consent

    seen.clear()
    fake.notes.clear()
    SandroidTUI._start_objection(
        fake, PKG, SimpleNamespace(spawn_mode=True), restart=True
    )
    assert seen == [True]  # spawn on a running app: the user agreed


async def test_the_header_says_what_the_pre_start_step_does(monkeypatch):
    import threading

    _panel_env(monkeypatch, pid=None)
    text = (
        "Applying identity profile 'mara-de' (ssaid) — the Android framework "
        "restarts; this can take a few minutes"
    )

    def header() -> str:
        return str(app.query_one("#spotlight-header").content)

    short = "Applying identity profile 'mara-de', framework restarts"
    app = _Harness()
    async with app.run_test(size=(240, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        timer = panel._poll_timer
        stops: list = []
        stop = timer.stop
        timer.stop = lambda: stops.append(1) or stop()
        assert "not running" in header()
        t = threading.Thread(target=app_start._set_status, args=((PKG, text, short),))
        t.start()
        await until(pilot, lambda: text in header())
        assert "not running" not in header()
        assert "Space starts" not in header()
        t = threading.Thread(target=app_start._set_status, args=(None,))
        t.start()
        await until(pilot, lambda: "not running" in header())
        # The status listener never touches the running-state poll.
        assert panel._poll_timer is timer
        assert stops == []
    assert stops == [1]  # unmount stops it
    assert panel._poll_timer is None
    assert app_start._STATUS_LISTENERS == []  # unmount unsubscribed


async def test_the_progress_line_is_short_on_a_narrow_lens(monkeypatch):
    _panel_env(monkeypatch, pid=None)
    text = (
        "Applying identity profile 'mara-de' (ssaid) — the Android framework "
        "restarts; this can take a few minutes"
    )
    short = "Applying identity profile 'mara-de', framework restarts"
    app = _Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await settle(pilot)
        app_start._set_status((PKG, text, short))  # UI thread: repaints inline
        try:
            await settle(pilot)
            header = str(app.query_one("#spotlight-header").content)
            assert short in header
            assert text not in header
        finally:
            app_start._set_status(None)


def test_an_unexpected_objection_pre_start_error_is_shown(monkeypatch):
    from sandroid.tui.app import SandroidTUI

    def prepare(pkg, tool, **kw):
        raise RuntimeError("adb gone")

    monkeypatch.setattr(app_start, "prepare_launch", prepare)
    fake = _ObjectionApp()

    SandroidTUI._start_objection(fake, PKG, SimpleNamespace(spawn_mode=True))

    assert fake.pushed == []
    assert fake.notes == [("Objection not started: adb gone", "error")]
    assert fake.worker_kwargs["exit_on_error"] is False
