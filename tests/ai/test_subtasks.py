"""Unit tests for sandroid.ai.subtasks.SubtaskManager and the spawn tools.

Reuses test_loop.py's scripted-turn pattern: a hand-written FakeOpenAIClient
(or a gated blocking variant) is injected via ``SubtaskManager.configure``'s
``client_factory``, so no real network / OpenAIClient is involved. Subtasks run
on real daemon threads, but every wait is deterministic -- a ``threading.Event``
the subtask's ``on_complete`` sets, or a gate the fake client blocks on -- never
a sleep/poll race.
"""

import threading

import pytest

import sandroid.ai  # side-effect: populate the tool registry (spawn + natives)
import sandroid.ai.arbiter as arbiter_module
import sandroid.ai.loop as loop_module
import sandroid.ai.subtasks as subtasks_module
import sandroid.ai.tool_permissions as tool_permissions_module
import sandroid.ai.tools.registry as registry_module
from sandroid.ai.arbiter import Conflict, DeviceResourceArbiter, ResourceId
from sandroid.ai.subtasks import (
    _SPAWN_TOOL_NAMES,
    READ_ONLY_SUBTASK_TOOLS,
    SubtaskManager,
    get_subtask_manager,
    should_reenter,
)
from sandroid.ai.tool_permissions import ToolPermissionStore
from sandroid.ai.tools.registry import (
    RiskTier,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
)


class FakeOpenAIClient:
    """Replays one scripted event list per call to .chat(), in order."""

    def __init__(self, scripted_calls):
        self._scripted_calls = list(scripted_calls)
        self.calls = []

    def chat(self, messages, tools=None, stream=True):
        self.calls.append((list(messages), tools))
        events = self._scripted_calls.pop(0)
        return iter(events)


class _GatedClient:
    """A client whose .chat() blocks on ``gate`` before yielding, and sets
    ``started`` once it is inside .chat() -- lets a test observe the subtask
    while it is genuinely mid-flight, then release it deterministically.
    """

    def __init__(self, started, gate):
        self._started = started
        self._gate = gate

    def chat(self, messages, tools=None, stream=True):
        self._started.set()
        self._gate.wait(timeout=5)
        return iter([{"type": "text_delta", "content": "done"}, {"type": "done"}])


def _single_tool_call_then_text(tool_name, final_text="done", call_id="call_1"):
    """Two scripted .chat() rounds: one tool call, then a plain-text reply."""
    return [
        [
            {
                "type": "tool_call_delta",
                "index": 0,
                "id": call_id,
                "name": tool_name,
                "arguments_fragment": "{}",
            },
            {"type": "done"},
        ],
        [{"type": "text_delta", "content": final_text}, {"type": "done"}],
    ]


@pytest.fixture
def manager(monkeypatch):
    """A fresh SubtaskManager as the process-wide singleton, torn down after."""
    instance = SubtaskManager()
    monkeypatch.setattr(subtasks_module, "_subtask_manager", instance)
    yield instance
    instance.stop_all()


@pytest.fixture
def arbiter(monkeypatch):
    """A fresh DeviceResourceArbiter as the process-wide singleton.

    Both loop._dispatch_one and subtasks call ``get_arbiter()`` (which reads
    ``arbiter_module._arbiter``), so patching that global isolates each test.
    """
    instance = DeviceResourceArbiter()
    monkeypatch.setattr(arbiter_module, "_arbiter", instance)
    return instance


@pytest.fixture
def test_registry(monkeypatch):
    """A fresh ToolRegistry as the singleton (empty of the real native tools).

    Both loop.py and subtasks.py call the ``get_tool_registry()`` function,
    which reads ``registry_module._tool_registry`` -- patching that global
    redirects both to this fresh instance.
    """
    registry = ToolRegistry()
    monkeypatch.setattr(registry_module, "_tool_registry", registry)
    return registry


@pytest.fixture
def permission_store(tmp_path, monkeypatch):
    """A fresh ToolPermissionStore backed by a temp file (mirrors test_loop)."""
    instance = ToolPermissionStore(path=tmp_path / "ai_tool_permissions.toml")
    monkeypatch.setattr(tool_permissions_module, "_tool_permission_store", None)
    monkeypatch.setattr(
        tool_permissions_module, "get_tool_permission_store", lambda: instance
    )
    monkeypatch.setattr(loop_module, "get_tool_permission_store", lambda: instance)
    return instance


# -- basic lifecycle ---------------------------------------------------------


def test_read_only_spawn_returns_started_then_reports_completion(manager, arbiter):
    done = threading.Event()
    client = FakeOpenAIClient(
        [[{"type": "text_delta", "content": "my findings"}, {"type": "done"}]]
    )
    manager.configure(
        client_factory=lambda: client, epoch_probe=lambda: 7, on_complete=done.set
    )

    res = manager.spawn(
        "investigate the foreground app", privileged=False, title="probe"
    )

    assert res["status"] == "started"
    assert res["subtask_id"]
    assert done.wait(timeout=5), "on_complete must fire when the subtask finishes"

    records = manager.take_all_completed()
    assert len(records) == 1
    rec = records[0]
    assert rec.result == "my findings"
    assert rec.epoch == 7
    assert rec.privileged is False
    assert rec.label == "probe"
    assert rec.subtask_id == res["subtask_id"]

    # Draining is exhaustive: a second drain yields nothing.
    assert manager.take_all_completed() == []


def test_get_subtask_manager_is_a_singleton():
    assert get_subtask_manager() is get_subtask_manager()


def test_should_reenter_matches_only_on_equal_epoch():
    assert should_reenter(3, 3) is True
    assert should_reenter(3, 4) is False


# -- tool views --------------------------------------------------------------


def test_read_only_subset_excludes_disallowed_and_spawn_tools():
    for name in (
        "take_screenshot",
        "list_snapshots",
        "check_frida_server_status",
        "spawn_subtask",
        "spawn_privileged_subtask",
    ):
        assert name not in READ_ONLY_SUBTASK_TOOLS


def test_privileged_subset_is_all_registered_minus_the_two_spawn_tools():
    all_names = set(get_tool_registry().names())
    # Sanity: the spawn tools really are registered on the live singleton.
    assert _SPAWN_TOOL_NAMES.issubset(all_names)

    priv = set(SubtaskManager._privileged_tool_names())
    assert priv == all_names - _SPAWN_TOOL_NAMES


def test_no_subtask_view_can_nest_a_subtask():
    """Neither tool view offers a spawn tool, so loop.allowed_names refuses one."""
    assert _SPAWN_TOOL_NAMES.isdisjoint(READ_ONLY_SUBTASK_TOOLS)
    priv = set(SubtaskManager._privileged_tool_names())
    assert _SPAWN_TOOL_NAMES.isdisjoint(priv)


# -- privileged behaviour ----------------------------------------------------


def test_privileged_subtask_blanket_auto_approves_a_consequential_tool(
    manager, arbiter, test_registry, permission_store
):
    ran = []

    def dangerous_tool(**kwargs):
        ran.append(True)
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="dangerous_tool",
            description="A consequential tool that needs confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=dangerous_tool,
            risk=RiskTier.CONSEQUENTIAL,
        )
    )

    done = threading.Event()
    client = FakeOpenAIClient(_single_tool_call_then_text("dangerous_tool"))
    manager.configure(
        client_factory=lambda: client, epoch_probe=lambda: 0, on_complete=done.set
    )

    res = manager.spawn("run the dangerous tool", privileged=True)
    assert res["status"] == "started"
    assert done.wait(timeout=5)

    assert ran == [True], "blanket auto-approve must actually run the tool"

    records = manager.take_all_completed()
    assert len(records) == 1
    assert records[0].privileged is True
    assert records[0].result == "done"

    # A blanket "once" approval must persist nothing to the permission store.
    assert not permission_store.is_allowed("dangerous_tool")
    assert not permission_store.is_never("dangerous_tool")


def test_only_one_privileged_subtask_at_a_time_read_only_uncapped(manager, arbiter):
    started = threading.Event()
    gate = threading.Event()
    manager.configure(client_factory=lambda: _GatedClient(started, gate))

    first = manager.spawn("privileged work", privileged=True)
    assert first["status"] == "started"
    assert started.wait(timeout=5), "the first privileged subtask must be live"

    second = manager.spawn("more privileged work", privileged=True)
    assert second["status"] == "refused"
    assert "already running" in second["error"]

    # Read-only subtasks are uncapped even while a privileged one runs.
    read_only = manager.spawn("read-only work", privileged=False)
    assert read_only["status"] == "started"

    gate.set()  # release both blocked subtasks so teardown joins cleanly


# -- arbiter integration -----------------------------------------------------


def test_live_subtask_blocks_world_claim_then_frees_it_on_completion(manager, arbiter):
    started = threading.Event()
    gate = threading.Event()
    done = threading.Event()
    manager.configure(
        client_factory=lambda: _GatedClient(started, gate), on_complete=done.set
    )

    res = manager.spawn("investigate", privileged=False)
    sid = res["subtask_id"]
    assert started.wait(timeout=5)

    # A live subtask is a distinct owner; an orchestrator WORLD op conflicts.
    claimed = arbiter.claim("orchestrator", frozenset({ResourceId.WORLD}))
    assert isinstance(claimed, Conflict)
    assert sid in manager.active_owner_ids()

    gate.set()
    assert done.wait(timeout=5)

    # forget_subtask (in the run's finally) drops it as a live owner.
    assert sid not in manager.active_owner_ids()
    claimed_again = arbiter.claim("orchestrator", frozenset({ResourceId.WORLD}))
    assert not isinstance(claimed_again, Conflict)


# -- cancellation ------------------------------------------------------------


def test_cancelled_subtask_flags_its_completion_record(manager, arbiter):
    started = threading.Event()
    gate = threading.Event()
    done = threading.Event()
    manager.configure(
        client_factory=lambda: _GatedClient(started, gate), on_complete=done.set
    )

    res = manager.spawn("investigate", privileged=False)
    sid = res["subtask_id"]
    assert started.wait(timeout=5)

    # The analyst cancels the running subtask (via the status bar).
    assert manager.cancel(sid) is True

    # Let the gated turn unwind so the run's finally enqueues the record.
    gate.set()
    assert done.wait(timeout=5)

    records = manager.take_all_completed()
    assert len(records) == 1
    assert records[0].subtask_id == sid
    # The record is flagged so the panel skips re-entering it as a turn.
    assert records[0].cancelled is True


def test_cancel_returns_false_for_an_unknown_subtask(manager, arbiter):
    manager.configure(
        client_factory=lambda: _GatedClient(threading.Event(), threading.Event())
    )
    assert manager.cancel("does-not-exist") is False


# -- stop_all ----------------------------------------------------------------


def test_stop_all_sets_cancels_and_returns_promptly(manager, arbiter):
    started = threading.Event()
    gate = threading.Event()
    manager.configure(client_factory=lambda: _GatedClient(started, gate))

    manager.spawn("work", privileged=False)
    assert started.wait(timeout=5)

    with manager._lock:
        cancel_event = next(iter(manager._cancels.values()))

    stopper = threading.Thread(target=manager.stop_all)
    stopper.start()

    # stop_all sets every cancel Event before joining -- observable without
    # any sleep by waiting on the Event itself.
    assert cancel_event.wait(timeout=5)

    # Release the blocked turn so the (bounded) join can complete.
    gate.set()
    stopper.join(timeout=5)
    assert not stopper.is_alive(), "stop_all must return promptly, never hang"
