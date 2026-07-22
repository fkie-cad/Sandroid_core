"""Async subtasks: fire-and-forget autonomous agent turns.

A *subtask* is another :func:`sandroid.ai.loop.run_agent_turn` call, but --
unlike the old synchronous "agent-as-tool" subagents this replaces -- it runs
on its own daemon thread and returns to the orchestrator *immediately* with a
handle, not a result. The orchestrator keeps talking to the analyst while the
subtask works in the background; when the subtask finishes, its result is
enqueued as a :class:`CompletionRecord` and a one-shot ``on_complete`` callback
lets the UI splice it back into the conversation as a follow-up message.

Two flavours, both exposed to the orchestrator as tools:

- ``spawn_subtask`` -- a READ-ONLY investigation. Its tool view is the fixed
  :data:`READ_ONLY_SUBTASK_TOOLS` allow-list (every tool in it is a verified
  read-only query), so it never hits the approval gate and is uncapped: any
  number may run concurrently.
- ``spawn_privileged_subtask`` -- FULL device access. It sees every registered
  tool (minus the two spawn tools -- subtasks cannot nest) and runs with a
  blanket auto-approve, so it executes consequential tools without further
  confirmation. Because that is dangerous, the analyst must approve the spawn
  itself (the tool is ``CONSEQUENTIAL``), and at most ONE privileged subtask
  may run at a time.

Resource safety is handled by the arbiter (:mod:`sandroid.ai.arbiter`): each
subtask is a distinct owner id, registered via ``note_subtask`` *before* its
thread starts (so an orchestrator ``WORLD`` op cannot slip in before the
subtask is a live owner) and torn down via ``forget_subtask`` in the run's
``finally`` (which also releases any leases it still held).

The daemon-thread / cancel-Event / bounded-join lifecycle deliberately mirrors
:mod:`sandroid.core.adb_device_monitor`: never an unbounded join (a subtask may
be blocked in a slow ADB call or on the telnet-console mutex; daemon threads
die with the process anyway).
"""

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass

from sandroid.ai.arbiter import get_arbiter
from sandroid.ai.client import OpenAIClient
from sandroid.ai.context import build_ambient_block
from sandroid.ai.loop import run_agent_turn
from sandroid.ai.prompts import SUBTASK_SYSTEM_PROMPT
from sandroid.ai.tools.registry import RiskTier, get_tool_registry, sandroid_tool

logger = logging.getLogger(__name__)

#: The fixed tool allow-list a READ-ONLY subtask sees. Every entry is a
#: verified ``RiskTier.READ_ONLY`` query, so a read-only subtask never reaches
#: the approval gate. Deliberately EXCLUDES ``take_screenshot``,
#: ``list_snapshots``, ``check_frida_server_status``, every mutating tool, and
#: both spawn tools (subtasks cannot nest).
READ_ONLY_SUBTASK_TOOLS: frozenset[str] = frozenset(
    {
        "get_foreground_app",
        "is_package_installed",
        "list_installed_packages",
        "get_package_pid",
        "get_package_details",
        "list_exported_components",
        "get_build_and_patch_info",
        "check_root_and_magisk",
        "get_selinux_status",
        "get_spotlight_app",
        "get_mitmproxy_status",
        "get_device_proxy_status",
        "get_running_frida_jobs",
        "check_hook_conflicts",
        "list_host_dir",
        "read_host_file",
        "list_allowed_host_paths",
        "list_connections",
        "get_network_info",
        "list_processes",
        "get_process_detail",
        "list_services",
        "get_activity_stack",
    }
)

#: The spawn tools' own names -- excluded from every subtask's tool view so a
#: subtask can never spawn a nested subtask.
_SPAWN_TOOL_NAMES = frozenset({"spawn_subtask", "spawn_privileged_subtask"})

#: Cap on tool-calling round-trips within a single subtask turn -- higher than
#: the orchestrator's default since an autonomous investigation legitimately
#: chains many read/inspect calls before it can summarize.
_SUBTASK_MAX_ITERATIONS = 25


@dataclass(frozen=True)
class CompletionRecord:
    """A finished subtask's result, queued for the orchestrator to pick up.

    Attributes:
        subtask_id: The subtask's short opaque id (also its arbiter owner id).
        label: Human-readable label shown in the UI.
        privileged: Whether this was a full-access (vs read-only) subtask.
        result: The subtask's final summary text (or a JSON ``{"error": ...}``
            string if the subtask crashed).
        epoch: The conversation epoch captured at spawn time. Used by
            :func:`should_reenter` so a result from a subtask spawned in a
            since-cleared conversation is discarded rather than spliced into
            an unrelated one.
    """

    subtask_id: str
    label: str
    privileged: bool
    result: str
    epoch: int
    #: True if the subtask was explicitly cancelled by the analyst (via the
    #: status bar). A cancelled subtask still enqueues a record so its lease is
    #: freed and the UI updates, but the orchestrator does not re-enter its
    #: (partial/empty) result as a follow-up turn.
    cancelled: bool = False


def should_reenter(record_epoch: int, current_epoch: int) -> bool:
    """Whether a completed subtask's result still belongs to the live conversation.

    A subtask outlives the turn that spawned it, and the analyst may clear the
    conversation (bumping its epoch) before the subtask finishes. Its result
    should only be spliced back in when the conversation it was spawned into is
    still the current one.

    Args:
        record_epoch: The epoch captured on the :class:`CompletionRecord`.
        current_epoch: The conversation's current epoch.

    Returns:
        ``True`` iff the two epochs match.
    """
    return record_epoch == current_epoch


def _default_client_factory() -> OpenAIClient:
    """Build an :class:`OpenAIClient` from ``Toolbox.config.ai`` (lazy import).

    The default so the manager is usable even before a ChatPanel configures it
    with its own client factory. Mirrors ``chat_panel.py``'s config read.
    """
    from sandroid.core.toolbox import Toolbox

    ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
    base_url = getattr(ai_cfg, "base_url", None)
    api_key = getattr(ai_cfg, "api_key", None)
    model = getattr(ai_cfg, "model", None)
    if not (base_url and api_key and model):
        raise RuntimeError(
            "AI backend is not configured (set config.ai.base_url/api_key/model)"
        )
    return OpenAIClient(base_url, api_key, model)


class SubtaskManager:
    """Owns the lifecycle of every running subtask.

    Thread-safe: all mutable state (the thread/cancel/running maps and the
    completed-record queue) is guarded by ``self._lock``, taken only for short,
    non-blocking critical sections. A subtask runs on its own daemon thread;
    the manager never blocks a caller waiting for one to finish.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._cancels: dict[str, threading.Event] = {}
        #: id -> {"label", "privileged", "started_at" (monotonic), "last_activity"}
        self._running: dict[str, dict] = {}
        #: Finished-but-not-yet-collected results, drained by take_all_completed.
        self._completed: list[CompletionRecord] = []
        #: Subtask ids the analyst explicitly cancelled, so their completion
        #: record is flagged ``cancelled`` (and not re-entered as a turn).
        self._cancelled: set[str] = set()

        # Injectable collaborators -- overridable via configure(), but usable
        # as-is (defaults below) before a ChatPanel wires it up.
        self._client_factory = _default_client_factory
        self._epoch_probe = lambda: 0
        self._on_complete = lambda: None

    def configure(
        self,
        *,
        client_factory=None,
        epoch_probe=None,
        on_complete=None,
    ) -> None:
        """Override any of the injectable collaborators (leaving the rest).

        Args:
            client_factory: ``() -> OpenAIClient`` used to build each subtask's
                backend client. Defaults to :func:`_default_client_factory`.
            epoch_probe: ``() -> int`` returning the current conversation epoch,
                captured at spawn and carried on the :class:`CompletionRecord`
                (see :func:`should_reenter`). Defaults to ``lambda: 0``.
            on_complete: ``() -> None`` fired (on the subtask thread) after each
                subtask finishes and its record is enqueued -- the UI's signal
                to drain :meth:`take_all_completed`. Defaults to a no-op.
        """
        if client_factory is not None:
            self._client_factory = client_factory
        if epoch_probe is not None:
            self._epoch_probe = epoch_probe
        if on_complete is not None:
            self._on_complete = on_complete

    def spawn(self, prompt: str, *, privileged: bool, title: str | None = None) -> dict:
        """Start a subtask on a background thread; return immediately.

        Args:
            prompt: The subtask's fully self-contained task. It does NOT see the
                orchestrator's conversation.
            privileged: ``True`` for a full-access subtask (capped at one at a
                time, blanket auto-approve), ``False`` for a read-only one
                (uncapped, sees only :data:`READ_ONLY_SUBTASK_TOOLS`).
            title: Optional short label for the UI.

        Returns:
            ``{"status": "started", "subtask_id": ...}`` on success, or
            ``{"status": "refused", "error": ...}`` when the one-privileged cap
            is already reached.
        """
        subtask_id = uuid.uuid4().hex[:8]
        epoch = self._epoch_probe()
        label = title or ("privileged subtask" if privileged else "subtask")
        cancel = threading.Event()

        with self._lock:
            if privileged and any(
                info["privileged"] for info in self._running.values()
            ):
                return {
                    "status": "refused",
                    "error": (
                        "a privileged subtask is already running; wait for it "
                        "to finish or cancel it before starting another"
                    ),
                }
            self._cancels[subtask_id] = cancel
            self._running[subtask_id] = {
                "label": label,
                "privileged": privileged,
                "started_at": time.monotonic(),
                "last_activity": None,
            }

        # Register the subtask as a live owner BEFORE its thread starts, so an
        # orchestrator WORLD op cannot slip through between here and the first
        # tool the subtask claims.
        get_arbiter().note_subtask(subtask_id)

        thread = threading.Thread(
            target=self._run,
            args=(subtask_id, prompt, privileged, epoch, label, cancel),
            name=f"subtask-{subtask_id}",
            daemon=True,
        )
        with self._lock:
            self._threads[subtask_id] = thread
        thread.start()

        return {"status": "started", "subtask_id": subtask_id}

    @staticmethod
    def _privileged_tool_names() -> list[str]:
        """Every currently-registered tool name minus the two spawn tools.

        Computed at run time (not import time) so MCP tools bridged in after
        this module imported are included, and so a subtask can never nest.
        """
        return [n for n in get_tool_registry().names() if n not in _SPAWN_TOOL_NAMES]

    def _run(
        self,
        subtask_id: str,
        prompt: str,
        privileged: bool,
        epoch: int,
        label: str,
        cancel: threading.Event,
    ) -> None:
        """The subtask's body, run on its own daemon thread.

        A crash anywhere here is turned into a JSON ``{"error": ...}`` result
        rather than silently dying -- a subtask must always report *something*
        back. The ``finally`` unconditionally tears down the owner (releasing
        leases), the background-task entry, and the in-memory maps, enqueues the
        :class:`CompletionRecord`, and fires ``on_complete``.
        """
        from sandroid.core.toolbox import Toolbox

        task_name = f"chat-subtask-{subtask_id}"
        result = ""
        try:
            try:
                Toolbox.register_background_task(
                    name=task_name,
                    display_name=("⚠ " if privileged else "") + label,
                    instance=cancel,
                    stop_callback=cancel.set,
                    started_by="chat",
                )
            except Exception:
                logger.debug(
                    "Failed to register subtask background task", exc_info=True
                )

            client = self._client_factory()
            tools_names = (
                self._privileged_tool_names()
                if privileged
                else list(READ_ONLY_SUBTASK_TOOLS)
            )
            messages = [
                {
                    "role": "system",
                    "content": f"{SUBTASK_SYSTEM_PROMPT}\n\n{build_ambient_block()}",
                },
                {"role": "user", "content": prompt},
            ]
            # Privileged subtasks blanket-auto-approve every consequential tool
            # (the analyst already approved the spawn itself); read-only
            # subtasks never reach the approval gate, so they need no callback.
            approve = (lambda spec, args: "once") if privileged else None

            def on_event(event: dict) -> None:
                try:
                    if event.get("type") == "tool_call_done":
                        with self._lock:
                            info = self._running.get(subtask_id)
                            if info is not None:
                                info["last_activity"] = event.get("name")
                except Exception:
                    pass

            result = run_agent_turn(
                messages,
                get_tool_registry().subset(tools_names),
                client,
                cancel,
                on_event=on_event,
                approve=approve,
                owner_id=subtask_id,
                max_iterations=_SUBTASK_MAX_ITERATIONS,
            )
        except Exception as exc:
            logger.debug("Subtask %s crashed: %s", subtask_id, exc, exc_info=True)
            result = json.dumps({"error": str(exc)})
        finally:
            get_arbiter().forget_subtask(subtask_id)
            try:
                Toolbox.unregister_background_task(task_name)
            except Exception:
                logger.debug(
                    "Failed to unregister subtask background task", exc_info=True
                )
            with self._lock:
                self._running.pop(subtask_id, None)
                self._cancels.pop(subtask_id, None)
                self._threads.pop(subtask_id, None)
                was_cancelled = subtask_id in self._cancelled
                self._cancelled.discard(subtask_id)
                self._completed.append(
                    CompletionRecord(
                        subtask_id=subtask_id,
                        label=label,
                        privileged=privileged,
                        result=result or "",
                        epoch=epoch,
                        cancelled=was_cancelled,
                    )
                )
            try:
                self._on_complete()
            except Exception:
                logger.debug("Subtask on_complete callback raised", exc_info=True)

    def take_all_completed(self) -> list[CompletionRecord]:
        """Atomically drain and return every queued :class:`CompletionRecord`.

        Callers concatenate the returned records into the conversation; the
        queue is left empty, so nothing is ever collected twice or lost.
        """
        with self._lock:
            drained = list(self._completed)
            self._completed.clear()
        return drained

    def active_owner_ids(self) -> set[str]:
        """The set of currently-running subtask ids (for arbiter reconcile)."""
        with self._lock:
            return set(self._running.keys())

    def running(self) -> list[dict]:
        """A UI snapshot of the running subtasks, newest first.

        Each entry: ``subtask_id``, ``label``, ``privileged``, ``elapsed``
        (seconds, from a monotonic clock) and ``last_activity`` (the name of the
        most recent tool it called, or ``None``).
        """
        now = time.monotonic()
        with self._lock:
            ordered = sorted(
                self._running.items(),
                key=lambda kv: kv[1]["started_at"],
                reverse=True,
            )
            return [
                {
                    "subtask_id": sid,
                    "label": info["label"],
                    "privileged": info["privileged"],
                    "elapsed": now - info["started_at"],
                    "last_activity": info["last_activity"],
                }
                for sid, info in ordered
            ]

    def cancel(self, subtask_id: str) -> bool:
        """Signal a single subtask to stop.

        Args:
            subtask_id: The subtask to cancel.

        Returns:
            ``True`` if a matching running subtask's cancel Event was set,
            ``False`` if no such subtask is running.
        """
        with self._lock:
            event = self._cancels.get(subtask_id)
            if event is None:
                return False
            self._cancelled.add(subtask_id)
        event.set()
        return True

    def stop_all(self) -> None:
        """Signal every subtask to stop, then join each with a SHORT timeout.

        Never an unbounded join: a subtask may be blocked in a slow ADB call or
        on the telnet-console mutex, and daemon threads die with the process
        anyway. Mirrors :meth:`adb_device_monitor.AdbDeviceMonitor.stop`.
        """
        with self._lock:
            events = list(self._cancels.values())
            threads = list(self._threads.values())
        for event in events:
            event.set()
        for thread in threads:
            thread.join(timeout=2.0)


_subtask_manager: SubtaskManager | None = None


def get_subtask_manager() -> SubtaskManager:
    """Get or create the :class:`SubtaskManager` singleton.

    Mirrors :func:`sandroid.ai.arbiter.get_arbiter` and
    :func:`sandroid.ai.tools.registry.get_tool_registry`.
    """
    global _subtask_manager
    if _subtask_manager is None:
        _subtask_manager = SubtaskManager()
    return _subtask_manager


@sandroid_tool(
    name="spawn_subtask",
    description=(
        "Delegate a focused, READ-ONLY investigation to an autonomous subtask "
        "that runs in the background and reports its findings back to you "
        "automatically. Give it a fully self-contained prompt -- it does NOT "
        "see this conversation. Safe and needs no confirmation; several may "
        "run at once."
    ),
    parameters={
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": (
                    "The fully self-contained task for the subtask. It cannot "
                    "see this conversation, so include everything it needs."
                ),
            },
            "title": {
                "type": "string",
                "description": "Optional short label for the subtask, shown in the UI.",
            },
        },
        "required": ["prompt"],
    },
    risk=RiskTier.READ_ONLY,
    category="subtask",
)
def spawn_subtask(prompt: str, title: str | None = None) -> dict:
    """Spawn a read-only background subtask. See the tool description."""
    return get_subtask_manager().spawn(prompt, privileged=False, title=title)


@sandroid_tool(
    name="spawn_privileged_subtask",
    description=(
        "Runs a FULL-ACCESS subtask that autonomously executes ALL tools "
        "(proxy/frida/snapshots/app changes) with no confirmation; may disrupt "
        "the emulator."
    ),
    parameters={
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": (
                    "The fully self-contained task for the subtask. It cannot "
                    "see this conversation, so include everything it needs. "
                    "Keep it tight and specific."
                ),
            },
            "title": {
                "type": "string",
                "description": "Optional short label for the subtask, shown in the UI.",
            },
        },
        "required": ["prompt"],
    },
    risk=RiskTier.CONSEQUENTIAL,
    can_remember_choice=False,
    category="subtask",
)
def spawn_privileged_subtask(prompt: str, title: str | None = None) -> dict:
    """Spawn a full-access background subtask. See the tool description."""
    return get_subtask_manager().spawn(prompt, privileged=True, title=title)
