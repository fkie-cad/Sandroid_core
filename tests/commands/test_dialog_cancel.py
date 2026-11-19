"""Commands that ask through a dialog: Esc cancels, an answer is used.

``ctx.request_input`` / ``ctx.request_selection`` are synchronous (they block
the command's worker thread until the dialog closes) and return ``None`` on
Esc / Cancel. Commands used to ``await`` them -- which raised for every
answer -- and several passed keyword arguments the functions do not take
(``prompt=``, ``placeholder=``). The fakes here have the real signatures, so
a wrong keyword fails the test as it failed in the TUI.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sandroid.commands.base import CommandContext


def _input(answer):
    def request_input(title: str, message: str = "", default: str = ""):
        return answer

    return request_input


def _selection(pick):
    """``pick(options)`` -> the answer (None = Esc)."""

    def request_selection(title: str, options: list, message: str = ""):
        return pick(options)

    return request_selection


def _ctx(**kwargs) -> CommandContext:
    return CommandContext(is_tui_mode=True, **kwargs)


# -- network: Proxy Configuration ------------------------------------------------


def test_proxy_prompt_esc_cancels_and_an_address_is_set(monkeypatch):
    from sandroid.commands.network_commands import ProxyConfigCommand
    from sandroid.core import proxy_manager

    calls: list = []

    class _Manager:
        def get_proxy_settings(self):
            return proxy_manager.ProxyStatus.NOT_SET, None

        def get_default_config(self):
            return proxy_manager.ProxyConfig.from_string("10.0.2.2:8080")

        def set_proxy(self, config):
            calls.append(("set", config.address))
            return True, "set"

        def unset_proxy(self):
            calls.append(("unset",))
            return True, "unset"

    monkeypatch.setattr(proxy_manager, "ProxyManager", _Manager)
    command = ProxyConfigCommand()
    result = asyncio.run(command._handle_console_mode(_ctx(request_input=_input(None))))
    assert result.error == "cancelled"
    assert calls == []
    ctx = _ctx(request_input=_input("10.0.2.2:8081"))
    result = asyncio.run(command._handle_console_mode(ctx))
    assert result.success
    assert calls == [("set", "10.0.2.2:8081")]


# -- device: Select Device -------------------------------------------------------


def test_device_selection_esc_cancels_and_a_pick_switches(monkeypatch):
    from sandroid import services
    from sandroid.commands.device_commands import DeviceSelectorCommand

    switched: list[str] = []
    devices = [
        SimpleNamespace(serial="emulator-5554", name="A"),
        SimpleNamespace(serial="emulator-5556", name="B"),
    ]
    service = SimpleNamespace(
        get_connected_devices=lambda: devices,
        set_active_device=switched.append,
    )
    monkeypatch.setattr(services, "get_device_service", lambda: service)
    command = DeviceSelectorCommand()
    result = asyncio.run(
        command.execute(_ctx(request_selection=_selection(lambda o: None)))
    )
    assert result.error == "cancelled"
    assert switched == []
    ctx = _ctx(request_selection=_selection(lambda options: options[1]))
    result = asyncio.run(command.execute(ctx))
    assert result.success
    assert switched == ["emulator-5556"]


# -- forensic: add / remove spotlight file, pull all -----------------------------


def test_spotlight_file_dialogs_cancel_on_esc_and_use_the_answer(monkeypatch):
    from sandroid.commands import forensic_commands as fc

    added: list[str] = []
    files = ["/data/data/a/x.db", "/data/data/a/y.xml"]
    forensic = SimpleNamespace(
        add_spotlight_file=lambda path: added.append(path) or True,
        get_spotlight_files=lambda: list(files),
    )
    add = fc.AddSpotlightFileCommand()
    result = asyncio.run(
        add.execute(_ctx(forensic_service=forensic, request_input=_input(None)))
    )
    assert result.error == "cancelled"
    assert added == []

    remove = fc.RemoveSpotlightFileCommand()
    esc = _ctx(request_selection=_selection(lambda o: None))
    assert asyncio.run(remove._select_file_to_remove(esc, files)) is None
    second = _ctx(request_selection=_selection(lambda options: options[1]))
    assert asyncio.run(remove._select_file_to_remove(second, files)) == files[1]

    pulled: list = []
    from sandroid import services

    monkeypatch.setattr(
        services,
        "get_file_extraction_service",
        lambda: SimpleNamespace(
            pull_spotlight_files=lambda **kw: pulled.append(kw) or []
        ),
    )
    pull = fc.PullAllSpotlightFilesCommand()
    result = asyncio.run(
        pull.execute(_ctx(forensic_service=forensic, request_input=_input(None)))
    )
    assert result.error == "cancelled"
    assert pulled == []
    asyncio.run(
        pull.execute(_ctx(forensic_service=forensic, request_input=_input("before")))
    )
    assert pulled == [{"files": files, "description": "before"}]


# -- monitoring: Monitoring Mode ---------------------------------------------------


def test_monitor_mode_esc_does_not_start_and_path_is_honoured(monkeypatch):
    from sandroid.commands.monitoring_commands import MonitorCommand
    from sandroid.core.fsmon import FSMon

    started: list = []
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", staticmethod(lambda: None))
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_pid",
        staticmethod(lambda pid, path: started.append(("pid", pid)) or None),
    )
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_path",
        staticmethod(lambda path: started.append(("path", path)) or None),
    )
    spotlight = SimpleNamespace(
        has_app=lambda: True,
        get_effective_package=lambda: "com.example.fit",
    )
    adb = SimpleNamespace(get_pid_for_package_name=lambda package: 4242)

    def ctx(pick):
        return _ctx(
            spotlight_service=spotlight, adb=adb, request_selection=_selection(pick)
        )

    command = MonitorCommand()
    result = asyncio.run(command.start_task(ctx(lambda o: None)))
    assert result.error == "cancelled"
    assert started == []
    asyncio.run(command.start_task(ctx(lambda options: options[1])))
    assert [kind for kind, _ in started] == ["path"]
