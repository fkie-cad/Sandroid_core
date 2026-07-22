"""Unit tests for sandroid.ai.context.build_ambient_block.

Every `_describe_*` helper does its `from sandroid.services import ...` (or
`from sandroid.core.toolbox import Toolbox`, or
`from sandroid.core.proxy_manager import get_focus_manager`) lazily, inside
its own body -- see context.py's module docstring -- so tests monkeypatch the
accessor function/classmethod on the module it actually lives on
(``sandroid.services``, ``sandroid.services.mitmproxy_service``,
``sandroid.core.toolbox.Toolbox``, ``sandroid.core.proxy_manager``), the same
style ``test_loop.py`` uses for ``loop_module.get_tool_registry``.
"""

from types import SimpleNamespace

from sandroid import services
from sandroid.ai import context
from sandroid.core import proxy_manager
from sandroid.core.toolbox import Toolbox
from sandroid.services import mitmproxy_service


def _raise(*_args, **_kwargs):
    raise RuntimeError("service unavailable")


# -- build_ambient_block: top-level guarantees ------------------------------


def test_block_always_starts_with_the_header():
    assert context.build_ambient_block().startswith(context._HEADER)


def test_block_is_header_only_when_every_real_source_raises(monkeypatch):
    monkeypatch.setattr(services, "get_spotlight_service", _raise)
    monkeypatch.setattr(services, "get_task_service", _raise)
    monkeypatch.setattr(services, "get_frida_session_service", _raise)
    monkeypatch.setattr(services, "get_configuration_service", _raise)
    monkeypatch.setattr(services, "get_emulator_service", _raise)
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", _raise)
    monkeypatch.setattr(Toolbox, "get_device_manager", staticmethod(_raise))
    monkeypatch.setattr(proxy_manager, "get_focus_manager", _raise)

    block = context.build_ambient_block()

    assert isinstance(block, str)
    assert block  # never empty, even in the total-failure case
    assert block == context._HEADER


def test_a_raising_source_does_not_propagate_and_others_still_render(monkeypatch):
    """Direct test of build_ambient_block's own per-call guard: even a
    describer that raises with no internal try/except of its own (as if one
    slipped through review, or was swapped out, without the isolation every
    real helper has) must not take down the rest of the block.
    """

    def boom():
        raise RuntimeError("kaboom")

    def ok_one():
        return "first ok line"

    def ok_two():
        return "second ok line"

    monkeypatch.setattr(context, "_DESCRIBERS", (ok_one, boom, ok_two))

    block = context.build_ambient_block()

    assert context._HEADER in block
    assert "first ok line" in block
    assert "second ok line" in block


def test_block_renders_an_explicit_negative_line_when_a_fact_is_false(monkeypatch):
    """Boolean yes/no facts (recording, mitmproxy, Frida session) must always
    render an explicit line stating current state, even when false --
    omitting the line when the answer is "no" gives the model nothing to
    answer a direct "is X running?" question from, and it falls back to
    guessing via an unrelated tool (the observed live bug this guards
    against). Contrast the list/optional-value sources, which still omit
    when empty/absent -- see test_block_is_header_only_when_every_real_source_raises.
    """
    monkeypatch.setattr(
        services,
        "get_emulator_service",
        lambda: SimpleNamespace(is_recording=lambda: False),
    )
    monkeypatch.setattr(
        mitmproxy_service,
        "get_mitmproxy_service",
        lambda: SimpleNamespace(is_running=lambda: False),
    )
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(has_active_session=lambda: False),
    )

    block = context.build_ambient_block()

    assert "Screen recording is not currently active." in block
    assert "Mitmproxy is not running." in block
    assert "No active Frida session is attached." in block


# -- _describe_background_tasks: the "chat" self-listing bug ---------------


def test_chat_task_is_filtered_but_other_tasks_are_not(monkeypatch):
    tasks = [
        SimpleNamespace(name="chat", display_name="AI Chat"),
        SimpleNamespace(name="fritap", display_name="FriTap"),
    ]
    monkeypatch.setattr(
        services,
        "get_task_service",
        lambda: SimpleNamespace(get_running_tasks=lambda: tasks),
    )

    line = context._describe_background_tasks()

    assert line is not None
    assert "FriTap" in line
    assert "AI Chat" not in line


def test_background_tasks_line_omitted_when_only_chat_is_running(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_task_service",
        lambda: SimpleNamespace(
            get_running_tasks=lambda: [
                SimpleNamespace(name="chat", display_name="AI Chat")
            ]
        ),
    )

    assert context._describe_background_tasks() is None


def test_background_tasks_line_omitted_when_none_running(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_task_service",
        lambda: SimpleNamespace(get_running_tasks=list),
    )

    assert context._describe_background_tasks() is None


def test_background_tasks_helper_raising_is_swallowed(monkeypatch):
    monkeypatch.setattr(services, "get_task_service", _raise)

    assert context._describe_background_tasks() is None


# -- _describe_spotlight_app -------------------------------------------------


def test_spotlight_app_renders_explicit_absence_when_no_effective_package(
    monkeypatch,
):
    """Deliberate exception to the module's "omit absent facts" rule: unlike
    security/countermeasure state, spotlight-app selection is a directly
    user-askable, non-sensitive fact, so absence must be stated explicitly
    rather than omitted -- otherwise the model has nothing to answer
    "what's the current spotlight app?" from and falls back to guessing via
    an unrelated tool (see the observed live bug this test guards against).
    """
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(
            get_effective_package=lambda: None,
            get_effective_mode=lambda: SimpleNamespace(value="attach"),
            get_pid=lambda: None,
        ),
    )

    line = context._describe_spotlight_app()

    assert line is not None
    assert "none currently selected" in line.lower()
    # Must not be phrased as a bare negative claim about some other fact --
    # it should be clearly about the spotlight app specifically.
    assert "spotlight" in line.lower()


def test_spotlight_app_renders_package_mode_and_pid(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(
            get_effective_package=lambda: "com.example.target",
            get_effective_mode=lambda: SimpleNamespace(value="spawn"),
            get_pid=lambda: 1234,
        ),
    )

    line = context._describe_spotlight_app()

    assert line is not None
    assert "com.example.target" in line
    assert "spawn" in line
    assert "1234" in line


# -- _describe_active_device --------------------------------------------------


def test_active_device_none_when_no_device_connected(monkeypatch):
    monkeypatch.setattr(
        Toolbox,
        "get_device_manager",
        staticmethod(lambda: SimpleNamespace(active_device=None)),
    )

    assert context._describe_active_device() is None


def test_active_device_renders_serial_only_when_details_are_blank(monkeypatch):
    """Device.model/android_version/api_level default to ""/""/0 (never
    None) -- the description must degrade gracefully to just the serial
    rather than rendering empty parens or "API 0".
    """
    device = SimpleNamespace(
        serial="emulator-5554", model="", android_version="", api_level=0
    )
    monkeypatch.setattr(
        Toolbox,
        "get_device_manager",
        staticmethod(lambda: SimpleNamespace(active_device=device)),
    )

    line = context._describe_active_device()

    assert line is not None
    assert "emulator-5554" in line
    assert "(" not in line


def test_active_device_renders_full_detail_when_populated(monkeypatch):
    device = SimpleNamespace(
        serial="emulator-5554",
        model="Pixel 6",
        android_version="14",
        api_level=34,
    )
    monkeypatch.setattr(
        Toolbox,
        "get_device_manager",
        staticmethod(lambda: SimpleNamespace(active_device=device)),
    )

    line = context._describe_active_device()

    assert line is not None
    assert "emulator-5554" in line
    assert "Pixel 6" in line
    assert "14" in line
    assert "34" in line


# -- _describe_frida_session --------------------------------------------------


def test_frida_session_renders_explicit_state_either_way(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(has_active_session=lambda: False),
    )
    line = context._describe_frida_session()
    assert line is not None
    assert line == "No active Frida session is attached."

    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(has_active_session=lambda: True),
    )
    line = context._describe_frida_session()
    assert line is not None
    assert line == "An active Frida session is attached."


# -- _describe_results_path --------------------------------------------------


def test_results_path_none_when_falsy(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(get_results_path=lambda: ""),
    )
    assert context._describe_results_path() is None


def test_results_path_renders_when_present(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(get_results_path=lambda: "results/session-1"),
    )
    line = context._describe_results_path()
    assert line is not None
    assert "results/session-1" in line


# -- _describe_spotlight_files -------------------------------------------------


def test_spotlight_files_none_when_empty(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_spotlight_files=list),
    )
    assert context._describe_spotlight_files() is None


def test_spotlight_files_renders_and_does_not_mutate_the_list(monkeypatch):
    files = ["/data/data/com.example/shared_prefs/a.xml", "/sdcard/b.db"]
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_spotlight_files=lambda: files),
    )

    line = context._describe_spotlight_files()

    assert line is not None
    assert "a.xml" in line
    assert "b.db" in line
    assert files == [
        "/data/data/com.example/shared_prefs/a.xml",
        "/sdcard/b.db",
    ]


# -- _describe_recording ------------------------------------------------------


def test_recording_renders_explicit_state_either_way(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_emulator_service",
        lambda: SimpleNamespace(is_recording=lambda: False),
    )
    line = context._describe_recording()
    assert line is not None
    assert line == "Screen recording is not currently active."

    monkeypatch.setattr(
        services,
        "get_emulator_service",
        lambda: SimpleNamespace(is_recording=lambda: True),
    )
    line = context._describe_recording()
    assert line is not None
    assert line == "Screen recording is currently active."


# -- _describe_mitmproxy -------------------------------------------------------


def test_mitmproxy_renders_explicit_state_either_way(monkeypatch):
    monkeypatch.setattr(
        mitmproxy_service,
        "get_mitmproxy_service",
        lambda: SimpleNamespace(is_running=lambda: False),
    )
    line = context._describe_mitmproxy()
    assert line is not None
    assert line == "Mitmproxy is not running."

    monkeypatch.setattr(
        mitmproxy_service,
        "get_mitmproxy_service",
        lambda: SimpleNamespace(is_running=lambda: True),
    )
    line = context._describe_mitmproxy()
    assert line is not None
    assert line == "Mitmproxy is running."


# -- _describe_app_proxies -----------------------------------------------------


def test_app_proxies_renders_explicit_none_line_when_empty(monkeypatch):
    """Deliberate exception to the module's "omit when absent" rule for
    list-shaped facts -- unlike _describe_spotlight_files, this always
    renders, even with no active lanes, since app_filter on
    get_captured_flows is only useful if the model already knows which
    packages exist to filter by.
    """
    monkeypatch.setattr(
        proxy_manager,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_nonblocking=dict),
    )

    line = context._describe_app_proxies()

    assert line == "App proxies: none currently active."


def test_app_proxies_renders_active_lane_pkg_and_target_pairs(monkeypatch):
    monkeypatch.setattr(
        proxy_manager,
        "get_focus_manager",
        lambda: SimpleNamespace(
            app_proxies_nonblocking=lambda: {
                "com.example.app": "ours",
                "com.other.app": "http://127.0.0.1:8888",
            }
        ),
    )

    line = context._describe_app_proxies()

    assert line is not None
    assert "com.example.app -> ours" in line
    assert "com.other.app -> http://127.0.0.1:8888" in line


def test_app_proxies_degrades_to_none_on_lock_contention(monkeypatch):
    """app_proxies_nonblocking() returning None (lock contention) must
    degrade to None, not render a misleading "none active" line.
    """
    monkeypatch.setattr(
        proxy_manager,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_nonblocking=lambda: None),
    )

    assert context._describe_app_proxies() is None


def test_app_proxies_degrades_to_none_on_error(monkeypatch):
    monkeypatch.setattr(proxy_manager, "get_focus_manager", _raise)

    assert context._describe_app_proxies() is None
