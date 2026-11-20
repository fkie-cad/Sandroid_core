"""AI-chat tools for Sandroid's Rewind workflow (record, review, rewind).

Importing this module registers all eight tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). ``category="recording"``.

Like :mod:`sandroid.ai.tools.monitor_control`, these dispatch to the
TUI-only :class:`~sandroid.tui.controllers.recording_controller.RecordingController`
(constructed once in ``app.py``, never a singleton) via the
:mod:`sandroid.tui.controller_registry` seam, rather than duplicating its
orchestration (start points, the Review list, run-history persistence)
into a parallel service layer (see :mod:`sandroid.core.rewind`).

The AI tells the analyst in chat when to do the action and when it is done;
``stop_device_recording`` returns the Review list, ``start_replay`` selects
files and rewinds (optionally replaying), and ``get_recording_changes``
reads the results. The old batch replay (replay count, dry run, noise
filter) is gone: its parameters are ignored (recording) or rejected
(``start_replay``).

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
  called by the ORCHESTRATOR's own turn. A subagent's owner id is
  forgotten (``get_arbiter().forget_subtask``) the moment its run ends,
  which releases EVERY lease it still holds, so a subagent that started a
  replay and finished shortly after would have its ``WORLD`` lease
  force-released while the detached replay worker was still mid-flight.
  Closed by excluding ``start_replay`` from every subagent profile
  (``sandroid.ai.agents.ASYNC_LEASE_TOOL_NAMES``) -- only the orchestrator
  can call this tool.
- ``get_recording_status``, ``get_replay_status``, ``get_recording_changes``,
  ``list_recent_runs``, ``get_run_detail`` -- all ``RiskTier.READ_ONLY``, no
  resource claimed.
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


_BATCH_REMOVED = (
    "the batch replay was removed; call start_replay without counts "
    "(it rewinds to the start point once, optionally replaying the steps)"
)


@sandroid_tool(
    name="start_device_recording",
    description=(
        "Rewind, step 1: save a start point (emulator snapshot) and start "
        "recording the analyst's input on the selected app. Tell the analyst "
        "to do the action, then call stop_device_recording. The recording "
        "is named 'Recording HH:MM' unless a label is given. "
        "number_of_runs/noise_filter are accepted but ignored (the batch "
        "replay was removed)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "description": "Optional name of the recording.",
            },
            "number_of_runs": {
                "type": "integer",
                "description": "Ignored (the batch replay was removed).",
            },
            "noise_filter": {
                "type": "boolean",
                "description": "Ignored (the batch replay was removed).",
            },
        },
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="recording",
    resources=frozenset({ResourceId.INPUT_RECORDING}),
)
def start_device_recording(
    label: str | None = None,
    number_of_runs: int | None = None,
    noise_filter: bool | None = None,
) -> dict[str, Any]:
    """Save a start point and start recording (blocking, about 5 s).

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.start_recording_chat`.

    Returns:
        ``{"success": False, "message": str}`` (no app selected, no device,
        the start point could not be saved, ...) or ``{"success": True,
        "rec_id", "name", "start_point"}``; ``ignored`` lists old batch
        parameters that were passed.
    """
    controller = _require_recording_controller()
    result = dict(controller.start_recording_chat(label))
    ignored = [
        name
        for name, value in (
            ("number_of_runs", number_of_runs),
            ("noise_filter", noise_filter),
        )
        if value is not None
    ]
    if ignored:
        result["ignored"] = ignored
        result["note"] = "number_of_runs and noise_filter are ignored now."
    return result


@sandroid_tool(
    name="stop_device_recording",
    description=(
        "Rewind, step 2: stop the recording. Returns the Review list: the "
        "files that changed (new/changed/deleted) and the requests seen. "
        "Pass the files to compare to start_replay."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="recording",
    releases=frozenset({ResourceId.INPUT_RECORDING}),
)
def stop_device_recording() -> dict[str, Any]:
    """Stop the current recording and return the Review list.

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.stop_recording_chat`.
    Does NOT rewind: call ``start_replay`` separately.
    """
    controller = _require_recording_controller()
    return controller.stop_recording_chat()


@sandroid_tool(
    name="start_replay",
    description=(
        "Rewind, step 3: select files (they are watched and their current "
        "version is saved as After), then go back to the start point and "
        "save Before. With replay=true (default) the recorded steps are "
        "repeated and After (replay) is saved; the device ends after the "
        "action. With replay=false the device stays at the start point. "
        "This reverts device state (like load_snapshot) and runs in the "
        "background: poll get_replay_status, then get_recording_changes."
    ),
    parameters={
        "type": "object",
        "properties": {
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Device paths from the Review list to select (watch). "
                    "Omit to keep the current selection."
                ),
            },
            "replay": {
                "type": "boolean",
                "description": "Repeat the recorded steps after the rewind.",
                "default": True,
            },
            "number_of_runs": {
                "type": "integer",
                "description": "Removed; any value above 1 is rejected.",
            },
            "include_dry_run": {
                "type": "boolean",
                "description": "Removed; true is rejected.",
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
    paths: list[str] | None = None,
    replay: bool = True,
    number_of_runs: int | None = None,
    include_dry_run: bool | None = None,
) -> dict[str, Any]:
    """Select ``paths`` and start Rewind (+ Replay) of the current recording.

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.start_rewind_chat`.
    The ``WORLD`` lease claimed for this call is released by the controller
    once the detached rewind worker finishes.

    Raises:
        ToolExecutionError: an old batch parameter was used
            (``number_of_runs > 1`` or ``include_dry_run=True``).
    """
    from sandroid.ai.loop import _current_owner_id

    if (number_of_runs is not None and int(number_of_runs) > 1) or include_dry_run:
        raise ToolExecutionError(_BATCH_REMOVED)
    if paths is not None and (
        not isinstance(paths, list) or not all(isinstance(p, str) for p in paths)
    ):
        raise ToolExecutionError("paths must be a list of device paths")
    controller = _require_recording_controller()
    owner = _current_owner_id.get()
    return controller.start_rewind_chat(
        paths=paths, replay=bool(replay), owner_id=owner
    )


@sandroid_tool(
    name="get_recording_changes",
    description=(
        "Read the current recording's Review list (changed files, requests, "
        "what is selected) and, after a rewind, each selected file's "
        "'What your action changed' and its verdict, compared field by field "
        "(or byte for byte): 'same change in the replay', 'differs only in "
        "volatile fields' (each in 'volatile_fields' with both values and the "
        "rule: time of its own run, same distance from its run, freshly "
        "generated ID), 'replay changed it differently' (see "
        "'only_in_your_run' / 'only_in_the_replay') or 'replay did not "
        "change it'."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="recording",
)
def get_recording_changes() -> dict[str, Any]:
    """The Review list and the latest results (read-only).

    Real integration point:
    :meth:`~sandroid.tui.controllers.recording_controller.RecordingController.review_dict`.
    """
    controller = _require_recording_controller()
    return controller.review_dict()


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
    description=("Check whether a rewind (started via start_replay) is still running."),
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
        "List past runs (Rewind runs and command-line analyses) for the "
        "current device, "
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
        "Get one run's full detail: per-file text (for a Rewind: 'What your "
        "action changed' and the replay result), 'verdicts' per file, and "
        "'rewind' (steps, compared requests, requests per run, 'volatile' "
        "fields per file with both values and their rule). Use the "
        "'run_id' field from list_recent_runs."
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
    from sandroid.core import file_diff, run_history

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
                # Runs recorded before diffs were stored as plain text carry
                # Rich markup in their SQLite lines: hand the model plain text.
                text = (
                    "\n".join(str(file_diff.plain_diff_line(x)) for x in lines)
                    if isinstance(lines, list)
                    else str(file_diff.plain_diff_line(lines))
                )
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
