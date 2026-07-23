"""AI-chat tools for Sandroid's record/replay (getevent/sendevent) workflow.

Importing this module registers all seven tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). ``category="recording"``.

Like :mod:`sandroid.ai.tools.monitor_control`, these dispatch to the
TUI-only :class:`~sandroid.tui.controllers.recording_controller.RecordingController`
(constructed once in ``app.py``, never a singleton) via the
:mod:`sandroid.tui.controller_registry` seam, rather than duplicating its
orchestration (snapshotting, ``AnalysisEngine`` wiring, run-history
persistence) into a parallel service layer.

There is deliberately no ``RecordingModal`` in this flow: the AI is expected
to have already asked the analyst for a run *label* in chat before calling
``start_device_recording``, and tells them in chat when to perform the
action and when to stop -- the modal's job is replaced by the chat turn
itself. Record and replay are separate tool calls, never auto-chained in
code -- the LLM decides when to call ``start_replay`` after being told
"I'm done" (by default right after stopping, but it can wait if asked to).

- ``start_device_recording``, ``stop_device_recording`` --
  ``RiskTier.REVERSIBLE``, claiming/releasing
  :attr:`~sandroid.ai.arbiter.ResourceId.INPUT_RECORDING` respectively (a
  still-running recording naturally blocks a second AI owner from starting
  another one).
- ``start_replay`` -- ``RiskTier.CONSEQUENTIAL`` (same tier as
  ``load_snapshot``, since replay reverts the emulator snapshot). Claims
  :attr:`~sandroid.ai.arbiter.ResourceId.WORLD` but declares
  ``releases=frozenset()`` -- deliberately NOT auto-released when this tool
  call itself returns, since the actual replay (including every repeat's
  snapshot revert) runs on a detached background worker that outlives the
  synchronous dispatch. See :meth:`~sandroid.tui.controllers.recording_controller.RecordingController._release_replay_world_lease`
  for the other half of this deferred-release pattern.

  This deferred-release pattern is only airtight when ``start_replay`` is
  called by the ORCHESTRATOR's own turn, whose owner id is never subject to
  ``sandroid.ai.subtasks.SubtaskManager._run``'s ``finally``, which calls
  ``get_arbiter().forget_subtask(subtask_id)`` the moment a *subtask's* own
  (synchronous) ``run_agent_turn`` call returns and unconditionally releases
  EVERY lease that subtask still holds via ``_release_all_locked``,
  immediately (not merely as a periodic ``reconcile()`` backstop). A
  privileged subtask that called ``start_replay`` and then ended its own turn
  shortly after (e.g. reporting "replay kicked off, done") would have its
  ``WORLD`` lease force-released while the detached replay worker was very
  likely still mid-flight. Closed by excluding ``start_replay`` from
  ``SubtaskManager._privileged_tool_names()`` (see
  ``sandroid.ai.subtasks._ASYNC_LEASE_TOOL_NAMES``) rather than leaving the
  race live -- only the orchestrator can call this tool.
- ``get_recording_status``, ``get_replay_status``, ``list_recent_runs``,
  ``get_run_detail`` -- all ``RiskTier.READ_ONLY``, no resource claimed.
"""

from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

#: Floor on `get_run_detail`'s `max_diff_chars` -- just guards against a
#: degenerate zero/negative value, unlike `ai/tools/flow_query.py`'s
#: `_MAX_LIMIT` (a real hard ceiling): there is no upper cap here, mirroring
#: `get_flow_detail`'s own `max_body_bytes`, which similarly only
#: *further*-truncates an already-capped value with no enforced floor.
_MIN_MAX_DIFF_CHARS = 1


def _require_recording_controller() -> Any:
    """Return the registered ``RecordingController``, or raise.

    Mirrors :func:`sandroid.ai.tools.monitor_control._require_monitor_controller`
    -- shouldn't happen in practice, but keeps every tool function honest
    about the dependency.
    """
    from sandroid.tui.controller_registry import get_recording_controller

    controller = get_recording_controller()
    if controller is None:
        raise ToolExecutionError("Recording controller is not available")
    return controller


@sandroid_tool(
    name="start_device_recording",
    description=(
        "Start recording device input events (getevent) for later replay. "
        "Creates a snapshot first so replay can restore this exact starting "
        "state. The analyst should already have been asked for a run label "
        "in chat before calling this -- there is no separate naming modal."
    ),
    parameters={
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "description": "Human-readable name for this run.",
            },
            "number_of_runs": {
                "type": "integer",
                "description": "Replay-repeat count seeded for a later replay.",
                "default": 2,
            },
            "noise_filter": {
                "type": "boolean",
                "description": (
                    "Dry-run noise-filter toggle seeded for a later replay."
                ),
                "default": True,
            },
        },
        "required": ["label"],
    },
    risk=RiskTier.REVERSIBLE,
    category="recording",
    resources=frozenset({ResourceId.INPUT_RECORDING}),
)
def start_device_recording(
    label: str, number_of_runs: int = 2, noise_filter: bool = True
) -> dict[str, Any]:
    """Start a device input-event recording.

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.start_recording_chat`.

    Returns:
        ``{"success": False, "message": str}`` if a recording is already in
        progress, the pre-recording snapshot failed, or the recorder failed
        to start; ``{"success": True, "label": str}`` once recording has
        actually started.
    """
    controller = _require_recording_controller()
    return controller.start_recording_chat(label, number_of_runs, noise_filter)


@sandroid_tool(
    name="stop_device_recording",
    description="Stop the in-progress device input-event recording.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="recording",
    releases=frozenset({ResourceId.INPUT_RECORDING}),
)
def stop_device_recording() -> dict[str, Any]:
    """Stop the current recording.

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.stop_recording_chat`.
    Does NOT auto-chain into replay -- call ``start_replay`` separately.

    Returns:
        ``{"success": False, "message": str}`` if nothing was recording,
        else ``{"success": True, "event_count": int, "duration": float,
        "label": str | None}``.
    """
    controller = _require_recording_controller()
    return controller.stop_recording_chat()


@sandroid_tool(
    name="start_replay",
    description=(
        "Replay the most recently recorded input events against a freshly "
        "reverted emulator snapshot, then diff the filesystem before/after. "
        "This reverts device state (same as load_snapshot) and runs in the "
        "background -- poll get_replay_status for completion, then "
        "list_recent_runs/get_run_detail for results."
    ),
    parameters={
        "type": "object",
        "properties": {
            "number_of_runs": {
                "type": "integer",
                "description": (
                    "Override the seeded replay-repeat count for this "
                    "replay (and future ones, until the next recording). "
                    "Omit to keep the current seed."
                ),
            },
            "include_dry_run": {
                "type": "boolean",
                "description": (
                    "Override the seeded dry-run noise-filter toggle. Omit "
                    "to keep the current seed."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="recording",
    resources=frozenset({ResourceId.WORLD}),
    # Deliberately empty -- NOT released at dispatch-return time. See the
    # module docstring and RecordingController._release_replay_world_lease.
    releases=frozenset(),
)
def start_replay(
    number_of_runs: int | None = None, include_dry_run: bool | None = None
) -> dict[str, Any]:
    """Kick off a replay of the current recording.

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.start_playback_chat`.

    Captures this call's resource-arbiter owner id (from
    ``sandroid.ai.loop._current_owner_id``, the same ``ContextVar`` the loop
    itself reads before claiming resources -- the identical pattern
    ``session_control.enable_app_proxy`` uses to capture an owner id for a
    later-attributed release) and passes it through so
    ``RecordingController`` can release the ``WORLD`` lease claimed above
    itself, once the detached replay worker actually finishes -- this
    dispatch returns almost immediately, long before that happens.

    Args:
        number_of_runs: Replay-repeat count override, or ``None`` to keep
            the seed from the last ``start_device_recording`` call.
        include_dry_run: Dry-run/noise-filter toggle override (renamed from
            the controller's own ``noise_filter`` for a clearer tool-facing
            name), or ``None`` to keep the seed.

    Returns:
        ``{"success": False, "message": str}`` if there is no recording to
        replay, or one is still in progress; otherwise ``{"success": True,
        "number_of_runs": int, "noise_filter": bool}`` once the replay
        worker has been kicked off.
    """
    from sandroid.ai.loop import _current_owner_id

    controller = _require_recording_controller()
    owner = _current_owner_id.get()
    return controller.start_playback_chat(
        number_of_runs=number_of_runs,
        noise_filter=include_dry_run,
        owner_id=owner,
    )


@sandroid_tool(
    name="get_recording_status",
    description="Get the current device input-event recording's status.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="recording",
)
def get_recording_status() -> dict[str, Any]:
    """Return the current (or most recently completed) recording's status.

    Real integration point: ``TaskService.get_task("recording")`` plus
    :attr:`~sandroid.tui.controllers.recording_controller.RecordingController.current_recording_label`.

    Returns:
        ``{"recording": bool, "label": str | None, "event_count": int,
        "elapsed_seconds": float}``. ``event_count``/``elapsed_seconds`` are
        ``0`` when nothing is currently recording.
    """
    from sandroid.services import get_task_service

    controller = _require_recording_controller()
    recording = controller.is_recording()
    wrapper = None
    if recording:
        task = get_task_service().get_task("recording")
        wrapper = getattr(task, "instance", None)
    return {
        "recording": recording,
        "label": controller.current_recording_label,
        "event_count": getattr(wrapper, "event_count", 0) if wrapper else 0,
        "elapsed_seconds": getattr(wrapper, "elapsed_seconds", 0) if wrapper else 0,
    }


@sandroid_tool(
    name="get_replay_status",
    description="Check whether a replay (started via start_replay) is still running.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="recording",
)
def get_replay_status() -> dict[str, Any]:
    """Return whether a replay is currently in progress.

    Real integration point:
    :attr:`~sandroid.tui.controllers.recording_controller.RecordingController.is_replaying`
    -- backed by a dedicated controller-level flag, NOT
    ``TaskService.is_running("playback_analysis")`` (confirmed always
    False: that name is only ever a Textual ``run_worker`` name, never
    registered with ``TaskService``).

    Returns:
        ``{"replaying": bool}``.
    """
    controller = _require_recording_controller()
    return {"replaying": controller.is_replaying}


@sandroid_tool(
    name="list_recent_runs",
    description=(
        "List past record->replay analysis runs for the current device, "
        "newest first (label, timing, changed/new/deleted file counts). "
        "Use get_run_detail with a run's 'run_id' for the full diffs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Max runs to return. Default 20.",
                "default": 20,
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="recording",
)
def list_recent_runs(limit: int = 20) -> dict[str, Any]:
    """List lightweight per-run summaries, newest-first.

    Real integration point: :func:`sandroid.core.run_history.load_index`,
    scoped to the currently active device (mirrors
    ``tui/widgets/diffs_view.py``'s own ``_current_device_name`` fallback).
    Already newest-first upstream; sliced client-side here since no
    pagination exists in ``run_history`` itself today.

    Returns:
        ``{"runs": [...], "count": int, "total_available": int}``.
    """
    from sandroid.core import run_history
    from sandroid.core.toolbox import Toolbox

    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ToolExecutionError(f"limit must be an integer, got {limit!r}") from exc
    limit = max(1, limit)

    try:
        device_name = Toolbox.device_name
    except Exception:
        device_name = None
    device_name = device_name or "unknown"

    entries = run_history.load_index(device_name=device_name)
    sliced = entries[:limit]
    return {
        "runs": sliced,
        "count": len(sliced),
        "total_available": len(entries),
    }


@sandroid_tool(
    name="get_run_detail",
    description=(
        "Get one record->replay run's full detail, including per-file diff "
        "text. Use the 'run_id' field from list_recent_runs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "run_id": {
                "type": "string",
                "description": "The run's 'run_id', from list_recent_runs.",
            },
            "max_diff_chars": {
                "type": "integer",
                "description": (
                    "Truncate each changed file's diff text to at most "
                    "this many characters. Default 20000."
                ),
                "default": 20000,
            },
        },
        "required": ["run_id"],
    },
    risk=RiskTier.READ_ONLY,
    category="recording",
)
def get_run_detail(run_id: str, max_diff_chars: int = 20000) -> dict[str, Any]:
    """Drill down into one run's full changed/new/deleted-file detail.

    Real integration point: :func:`sandroid.core.run_history.load_run`.

    ``changed_files`` entries in the raw ``RunRecord`` are either
    ``{path: [diff_lines]}`` (a *list* of individual diff lines) or a bare
    ``str`` path (undiffable files) -- see that dataclass's own docstring.
    For readability (and to apply truncation at all) each dict entry's line
    list is joined into a single newline-joined string here, then capped at
    *max_diff_chars* -- same truncation convention as ``get_flow_detail``'s
    ``max_body_bytes``. Bare-``str`` (undiffable) entries pass through
    unchanged.

    Raises:
        ToolExecutionError: *run_id* is unknown or its run file is corrupt.

    Returns:
        The run's full ``RunRecord`` dict (``to_dict()`` shape), with
        ``changed_files``' diff text truncated as above, plus one added
        ``"diff_truncated": bool`` field (true if any file's diff was cut).
    """
    from sandroid.core import run_history

    try:
        max_diff_chars = int(max_diff_chars)
    except (TypeError, ValueError) as exc:
        raise ToolExecutionError(
            f"max_diff_chars must be an integer, got {max_diff_chars!r}"
        ) from exc
    max_diff_chars = max(_MIN_MAX_DIFF_CHARS, max_diff_chars)

    try:
        record = run_history.load_run(run_id)
    except run_history.RunHistoryError as exc:
        raise ToolExecutionError(str(exc)) from exc

    data = record.to_dict()
    truncated_any = False
    rewritten: list[Any] = []
    for entry in data.get("changed_files") or []:
        if isinstance(entry, dict):
            new_entry: dict[str, str] = {}
            for path, lines in entry.items():
                text = "\n".join(lines) if isinstance(lines, list) else str(lines)
                if len(text) > max_diff_chars:
                    omitted = len(text) - max_diff_chars
                    text = (
                        text[:max_diff_chars]
                        + f"\n... [truncated, {omitted} more characters]"
                    )
                    truncated_any = True
                new_entry[path] = text
            rewritten.append(new_entry)
        else:
            rewritten.append(entry)
    data["changed_files"] = rewritten
    data["diff_truncated"] = truncated_any
    return data
