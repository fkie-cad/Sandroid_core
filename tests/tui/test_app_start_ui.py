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
from textual.screen import Screen

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
    from sandroid.tui.themes import lens_palette

    # Not running is muted (lens dim), not red.
    assert panel._render_header().startswith(f"[{lens_palette().dim}]○ not running[/]")
    svc.reset()
    header = panel._render_header()
    assert header.startswith(f"[{lens_palette().dim}]○ no app[/]")  # muted
    assert "use the foreground app" in header
    assert "pick an app…" in header


async def test_apk_sources_not_found_is_muted_and_failed_is_red() -> None:
    from textual.widgets import Label

    from sandroid.tui.modals.apk_install_modal import APKInstallModal

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(APKInstallModal())

    app = Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await until(pilot, lambda: isinstance(app.screen, APKInstallModal))
        modal = app.screen
        modal._update_source_status("fdroid", "not_found")
        modal._update_source_status("apkpure", "error")
        modal._update_source_status("aptoide", "done")
        await settle(pilot)

        def label(widget_id: str) -> Label:
            return modal.query_one(f"#{widget_id}", Label)

        fdroid, apkpure = label("source-fdroid"), label("source-apkpure")
        assert str(fdroid.render()) == "F-Droid ○ not found"
        assert not fdroid.has_class("error")
        assert str(apkpure.render()) == "APKPure failed"
        assert apkpure.has_class("error")
        assert str(label("source-aptoide").render()) == "Aptoide ● found"
        modal._update_source_status("apkpure", "not_found")  # a retry answers
        assert not apkpure.has_class("error")


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
        self.personas: dict = {}  # serial -> persona profile id
        self.asked: list = []

    def applied_state(self, package, serial=None):
        self.asked.append(("applied_state", package, serial))
        return self.state

    def config(self):
        return self._config

    def profile_id_for(self, serial):
        self.asked.append(("profile_id_for", serial))
        return self.personas.get(serial, self._config.profile)

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


async def test_identity_notice_names_the_persona_of_the_device(monkeypatch):
    """A persona emulator runs its own profile: the banner names that one,
    not the active profile of the config.
    """
    from sandroid.core.adb import Adb

    _svc, fake = _identity_env(monkeypatch, "not_applied")
    fake.personas["emulator-5558"] = "lena-fr"
    monkeypatch.setattr(Adb, "_target_device", "emulator-5558")
    app = _Harness()
    async with app.run_test(size=(240, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        panel._on_identity_status([])
        await settle(pilot)
        assert panel._identity_gap == (PKG, "lena-fr")
        assert ("profile_id_for", "emulator-5558") in fake.asked
        assert ("applied_state", PKG, "emulator-5558") in fake.asked
        assert "Identity profile 'lena-fr' not applied" in _body(app)
        assert "mara-de" not in _body(app)


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


# -- other apps with hooks: the "hooks running" row and the Shift+H list ----------

OTHER = "org.mozilla.firefox"
THIRD = "com.example.app"


def _hooks(*apps):
    from sandroid.tui.widgets.spotlight_panel import AppHooks

    return [AppHooks(*a) if isinstance(a, tuple) else a for a in apps]


def test_collect_app_hooks_merges_bypass_tools_and_objection():
    from datetime import datetime

    from sandroid.analysis.detection_bypass import HookedApp
    from sandroid.tui.widgets.spotlight_panel import collect_app_hooks

    bypass = SimpleNamespace(
        hooked_apps=lambda: [
            HookedApp(PKG, 77, ("ssl",), 200.0, False),
            HookedApp(OTHER, 88, ("ssl", "root", "frida"), 100.0, True),
        ]
    )
    task = SimpleNamespace
    tasks = SimpleNamespace(
        get_running_tasks=lambda: [
            task(name="bypass", app_name=PKG, display_name="Bypass", target_pid=77),
            task(name=f"bypass:{OTHER}", app_name=OTHER, display_name="Bypass"),
            task(name="monitor", app_name=THIRD, display_name="File monitor"),
            task(
                name="fritap",
                app_name=THIRD,
                display_name="friTap",
                target_pid=99,
                started_at=datetime.fromtimestamp(300.0),
            ),
            task(name="network", app_name=None, display_name="Network"),
        ]
    )
    objection = SimpleNamespace(get_session=lambda: SimpleNamespace(package_name=OTHER))

    apps = collect_app_hooks(bypass, tasks, objection)

    assert [a.package for a in apps] == [OTHER, PKG, THIRD]  # oldest first
    by = {a.package: a for a in apps}
    assert by[OTHER].summary() == "3 bypasses, Objection"
    assert by[PKG].summary() == "1 bypass"
    assert by[THIRD].summary() == "friTap"
    assert by[THIRD].pid == 99
    assert (
        collect_app_hooks(
            SimpleNamespace(hooked_apps=list),
            SimpleNamespace(get_running_tasks=list),
            SimpleNamespace(get_session=lambda: None),
        )
        == []
    )


def test_hooks_running_line_lists_every_app_when_others_have_hooks():
    from sandroid.tui.widgets.spotlight_panel import hooks_running_line, others_note

    def plain(markup):
        return Text.from_markup(markup).plain

    # 0 apps, and only the selected app: no row (the "hooks" row covers it).
    assert hooks_running_line([], PKG, 100) == ""
    assert hooks_running_line(_hooks((PKG, 77, ("ssl",))), PKG, 100) == ""
    # 1 other app.
    line = plain(hooks_running_line(_hooks((OTHER, 88, ("ssl", "root"))), PKG, 100))
    assert line == f"{OTHER} (2 bypasses)"
    # Several: the selected app first, then the others.
    apps = _hooks((OTHER, 88, ("ssl", "root", "frida")), (PKG, 77, ("ssl",)))
    line = plain(hooks_running_line(apps, PKG, 100, "Shift+H list"))
    assert line == f"{PKG} (1 bypass) · {OTHER} (3 bypasses)   Shift+H list"
    # Narrow: what does not fit becomes "N more", the hint goes first.
    apps = _hooks(
        (OTHER, 88, ("ssl",)), (THIRD, 99, (), ("friTap",)), (PKG, 77, ("ssl",))
    )
    line = plain(hooks_running_line(apps, PKG, 45, "Shift+H list"))
    assert line == f"{PKG} (1 bypass) · 2 more"
    assert others_note(1) == "1 other app has hooks"
    assert others_note(3) == "3 other apps have hooks"


def test_an_unfinished_unload_stays_listed_with_its_state():
    """An unload that timed out is never "No other app has hooks now"."""
    from sandroid.analysis.detection_bypass import HookedApp
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets.spotlight_panel import (
        collect_app_hooks,
        hooks_inspector,
        hooks_running_line,
    )

    c = lens_palette()
    bypass = SimpleNamespace(
        hooked_apps=lambda: [
            HookedApp(OTHER, 88, ("ssl",), 100.0, True, "failed", True)
        ]
    )
    apps = collect_app_hooks(
        bypass,
        SimpleNamespace(get_running_tasks=list),
        SimpleNamespace(get_session=lambda: None),
    )
    assert apps[0].unload == "failed"
    assert apps[0].hooks_off
    content, _rows = hooks_inspector(apps, PKG, OTHER)
    body = content.sections[0][1]
    assert "No other app has hooks" not in body.plain
    assert "unload failed" in body.plain
    assert "restart the app to clear them" in body.plain
    assert "hooks off but loaded" in body.plain
    # The failure is a red word.
    start = body.plain.index("unload failed")
    assert any(
        span.start <= start < span.end and str(span.style) == c.bad
        for span in body.spans
    )
    line = hooks_running_line(apps, PKG, 100)
    assert f"[{c.bad}]unload failed[/]" in line
    assert Text.from_markup(line).plain == f"{OTHER} (1 bypass) unload failed"
    unloading = _hooks((OTHER, 88, ("ssl",), (), None, "unloading"))
    assert f"[{c.warn}]◌ unloading[/]" in hooks_running_line(unloading, PKG, 100)


def test_work_unload_passes_on_why_the_bypass_unload_failed(monkeypatch):
    from sandroid.analysis.detection_bypass import HookedApp

    why = (
        f"Could not unload the bypass hooks in {OTHER}: they are switched "
        "off but still loaded (an app thread is inside a hooked call). "
        "Restart the app to clear them."
    )
    bypass = SimpleNamespace(
        hooked_apps=lambda: [HookedApp(OTHER, 88, ("ssl",), 1.0, True)],
        unload_app=lambda package: (False, why),
    )
    monkeypatch.setattr(SpotlightPanel, "_bypass", staticmethod(lambda: bypass))
    monkeypatch.setattr(
        SpotlightPanel,
        "_tasks",
        staticmethod(lambda: SimpleNamespace(get_running_tasks=list)),
    )
    from sandroid import services

    monkeypatch.setattr(
        services,
        "get_objection_service",
        lambda: SimpleNamespace(get_session=lambda: None),
    )
    ok, msg = SpotlightPanel._work_unload(
        SimpleNamespace(_bypass=SpotlightPanel._bypass, _tasks=SpotlightPanel._tasks),
        OTHER,
    )
    assert ok is False
    assert msg == why


def test_header_note_about_other_apps_hooks_is_muted(monkeypatch):
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets import spotlight_panel as sp

    _panel_env(monkeypatch)
    apps = _hooks((OTHER, 88, ("ssl",)), (PKG, 77, ("ssl",)))
    monkeypatch.setattr(sp, "collect_app_hooks", lambda: list(apps))
    header = SpotlightPanel()._render_header()
    c = lens_palette()
    # Secondary header text: the lens' muted token, not the warning colour.
    assert f"[{c.dim}]1 other app has hooks[/]" in header
    assert f"[{c.warn}]1 other app" not in header


class _InspScreen(Screen):
    """Just the Inspector API of MainScreen the panel uses."""

    def __init__(self):
        super().__init__()
        self.inspector_is_open = False
        self.inspector_content = None

    def compose(self):
        yield SpotlightPanel(id="spotlight")

    def open_inspector(self, content):
        self.inspector_content = content
        self.inspector_is_open = True

    def update_inspector(self, content):
        if self.inspector_is_open:
            self.inspector_content = content

    def set_lens_caption(self, *a, **k):
        pass


class _InspHarness(App):
    def on_mount(self):
        self.push_screen(_InspScreen())


class _HooksBypass:
    """BypassService double for the hooks list (unload records the app)."""

    def __init__(self):
        self.unloaded: list[str] = []
        self.apps: list = []

    def hooked_apps(self):
        return list(self.apps)

    def unload_app(self, package):
        self.unloaded.append(package)
        self.apps = [a for a in self.apps if a.package != package]
        return True, f"Unloaded the bypass hooks in {package}"

    def on_categories(self):
        return []

    def _plain_name(self, category):
        return {"ssl": "SSL Pinning Bypass", "root": "Root Detection Bypass"}.get(
            category, category
        )

    def add_state_listener(self, cb):
        pass

    def remove_state_listener(self, cb):
        pass

    def prune_parked(self):
        return []


def _hooks_env(monkeypatch, apps):
    from sandroid.analysis.detection_bypass import HookedApp
    from sandroid.tui.widgets import spotlight_panel as sp

    svc, _ran = _panel_env(monkeypatch)
    bypass = _HooksBypass()
    bypass.apps = [
        HookedApp(pkg, pid, cats, 1000.0 + i, pkg != PKG)
        for i, (pkg, pid, cats) in enumerate(apps)
    ]
    monkeypatch.setattr(SpotlightPanel, "_bypass", staticmethod(lambda: bypass))
    tasks = SimpleNamespace(
        running=[],
        stopped=[],
        get_running_tasks=lambda: list(tasks.running),
        stop=lambda name: tasks.stopped.append(name) or True,
    )
    monkeypatch.setattr(SpotlightPanel, "_tasks", staticmethod(lambda: tasks))
    real = sp.collect_app_hooks
    no_objection = SimpleNamespace(get_session=lambda: None)
    monkeypatch.setattr(
        sp, "collect_app_hooks", lambda: real(bypass, tasks, no_objection)
    )
    return svc, bypass, tasks


def _header(app) -> str:
    return Text.from_markup(str(app.query_one("#spotlight-header").content)).plain


def _plain_body(app) -> str:
    return Text.from_markup(_body(app)).plain


async def test_overview_row_and_header_follow_the_other_apps(monkeypatch):
    _svc, bypass, tasks = _hooks_env(monkeypatch, [(PKG, 77, ("ssl",))])
    app = _Harness()
    async with app.run_test(size=(200, 30)) as pilot:
        await settle(pilot)
        panel = app.query_one(SpotlightPanel)
        # Only the selected app has hooks: no row, no header note.
        assert "hooks running" not in _plain_body(app)
        assert "other app" not in _header(app)

        from sandroid.analysis.detection_bypass import HookedApp

        bypass.apps.append(HookedApp(OTHER, 88, ("ssl", "root"), 900.0, True))
        panel._repaint_text()
        await settle(pilot)
        assert "1 other app has hooks" in _header(app)
        body = _plain_body(app)
        assert f"hooks running  {PKG} (1 bypass) · {OTHER} (2 bypasses)" in body
        assert "Shift+H list" in body

        tasks.running.append(
            SimpleNamespace(name="fritap", app_name=THIRD, display_name="friTap")
        )
        panel._repaint_text()
        await settle(pilot)
        assert "2 other apps have hooks" in _header(app)
        assert f"{THIRD} (friTap)" in _plain_body(app)


async def test_shift_h_lists_the_other_apps_and_star_selects_one(monkeypatch):
    svc, bypass, _tasks = _hooks_env(
        monkeypatch,
        [(PKG, 77, ("ssl",)), (OTHER, 88, ("ssl", "root")), (THIRD, 99, ("ssl",))],
    )
    app = _InspHarness()
    async with app.run_test(size=(160, 30)) as pilot:
        await settle(pilot)
        screen = app.screen
        panel = screen.query_one(SpotlightPanel)
        panel.focus()
        await pilot.press("H")
        await settle(pilot)
        content = screen.inspector_content
        assert screen.inspector_is_open
        assert content.key == (app_lens.LENS_ID, "hooks")
        assert content.title == "Hooks in other apps"
        body = content.sections[0][1].plain
        assert OTHER in body
        assert THIRD in body
        assert PKG not in body
        assert "SSL Pinning Bypass, Root Detection Bypass" in body
        assert "loaded" in body
        assert "since" in body
        assert content.footer == "{ } pick · * switch to it · Shift+U unload"
        assert panel._hooks_pick == OTHER  # the oldest first
        # } picks the next app, { goes back (wrapping).
        content.keys["right_curly_bracket"](None)
        assert panel._hooks_pick == THIRD
        content.keys["left_curly_bracket"](None)
        assert panel._hooks_pick == OTHER
        # A click on an app's lines picks it.
        rows = panel._hooks_rows
        assert screen.inspector_content.click(None, rows[1][0] + 1) is True
        assert panel._hooks_pick == THIRD
        # * selects it; the app left keeps its hooks and shows in the list.
        screen.inspector_content.keys["asterisk"](None)
        await settle(pilot)
        assert svc.get_effective_package() == THIRD
        assert svc.get_pid() == 99
        assert bypass.unloaded == []
        body = screen.inspector_content.sections[0][1].plain
        assert PKG in body
        assert THIRD not in body.split("\n")[0]


async def test_header_click_opens_the_list(monkeypatch):
    _hooks_env(monkeypatch, [(PKG, 77, ()), (OTHER, 88, ("ssl",))])
    app = _InspHarness()
    async with app.run_test(size=(160, 30)) as pilot:
        await settle(pilot)
        await pilot.click("#spotlight-header")
        await settle(pilot)
        assert app.screen.inspector_content.key == (app_lens.LENS_ID, "hooks")


async def test_shift_u_unloads_the_picked_app_after_a_confirmation(monkeypatch):
    _svc, bypass, tasks = _hooks_env(
        monkeypatch, [(PKG, 77, ("ssl",)), (OTHER, 88, ("ssl", "root"))]
    )
    tasks.running.append(
        SimpleNamespace(name="fritap", app_name=OTHER, display_name="friTap")
    )
    tasks.running.append(
        SimpleNamespace(name="dexray", app_name=PKG, display_name="Dexray")
    )
    app = _InspHarness()
    async with app.run_test(size=(160, 30)) as pilot:
        await settle(pilot)
        panel = app.screen.query_one(SpotlightPanel)
        panel.focus()
        # Without the list open, U only says how to get there.
        notes: list = []
        monkeypatch.setattr(
            panel, "_notify", lambda m, s="information": notes.append(m)
        )
        await pilot.press("U")
        await settle(pilot)
        assert notes
        assert "Shift+H" in notes[-1]
        await pilot.press("H")
        await settle(pilot)
        await pilot.press("U")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        modal = app.screen
        assert modal.title_text == f"Unload the hooks in {OTHER}?"
        assert "SSL Pinning Bypass, Root Detection Bypass; friTap" in (
            modal.message_text
        )
        assert "keeps running" in modal.message_text
        await pilot.press("n")  # No keeps them
        await until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert bypass.unloaded == []
        assert tasks.stopped == []

        await pilot.press("U")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.pause(0.5)  # past the typing guard
        await pilot.press("y")
        await until(pilot, lambda: bypass.unloaded == [OTHER])
        await until(pilot, lambda: tasks.stopped == ["fritap"])  # not PKG's
        await until(pilot, lambda: any("Unloaded" in n for n in notes))
