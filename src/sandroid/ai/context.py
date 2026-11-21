"""Ambient context: a cheap, per-turn snapshot of live Sandroid state.

The AI chat loop otherwise has zero automatic awareness of device/session
state -- it only learns about the emulator, the spotlighted app, or what's
running if it explicitly calls a tool. :func:`build_ambient_block` assembles
a short, human-readable text block from several cheap, in-memory-only state
sources so the model always knows what it's looking at without spending a
tool call to ask.

Design rules (see each ``_describe_*`` helper below):

- **Cheap only**: every source is an in-memory attribute read -- no ADB, no
  Frida, no telnet on the per-turn hot path. This is why, e.g.,
  ``get_results_path()`` is used instead of ``get_screenshots_path()``/
  ``get_spotlight_files_path()`` (which do real ``os.makedirs()`` I/O), and
  why the emulator's live foreground app and the snapshot list are
  deliberately *not* sources here (the former needs a slow ``dumpsys
  window`` call, the latter shells out over the emulator's telnet console
  with no caching).
- **Built once per user turn**: :class:`sandroid.ai.session.AgentSession`
  builds it fresh for every analyst message and inserts it right before that
  message (kept in the request history for a stable prefix, persisted as an
  ``ambient`` record, never sent to the timeline).
- **Explicit state for boolean facts**: for a fact that's a direct yes/no
  question a user can ask ("is mitmproxy running?", "is a Frida session
  attached?", "is it recording?", "what's the current spotlight app?"), the
  helper always renders a line stating the current state, whichever way it
  is -- never ``None`` for a healthy read. Omitting the line when the answer
  is "no" gives the model nothing to answer from, and it falls back to
  guessing via an unrelated tool instead of reading the block (this is an
  observed live bug: asked "is mitmproxy running", the model called an
  unrelated placeholder tool instead of just saying "no" from this block).
  ``_describe_spotlight_app``, ``_describe_mitmproxy``,
  ``_describe_frida_session``, and ``_describe_recording`` all follow this
  rule.
- **Omit when absent, for list/optional-value facts**: sources that aren't a
  single boolean yes/no fact still return ``None`` and get omitted when
  empty/absent -- ``_describe_background_tasks`` (a list of tasks),
  ``_describe_spotlight_files`` (a list of watched files),
  ``_describe_active_device`` (no device connected is a common idle state),
  and ``_describe_results_path`` (not configured).
- **Isolated failure**: every helper is wrapped in its own broad
  ``try/except`` so one unavailable/misbehaving service degrades only its
  own line, never the whole block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_HEADER = "Live Sandroid state (auto-refreshed each turn):"


def _describe_spotlight_app() -> str | None:
    """Describe the analyst's chosen investigation target, if any.

    Deliberately the *spotlight* app (the analyst's chosen target), not the
    emulator's live foreground app -- the latter isn't what the analyst is
    investigating and would need a slow ``dumpsys window`` call anyway.

    Like ``_describe_mitmproxy``, ``_describe_frida_session``, and
    ``_describe_recording``, this renders an explicit line stating the
    current state either way rather than omitting when the fact is absent:
    spotlight-app selection is a directly user-askable fact ("what's the
    current spotlight app?"), and staying silent when none is selected gives
    the model nothing to answer from, so it falls back to guessing via an
    unrelated tool instead of answering directly. See the module docstring.
    """
    try:
        from sandroid.services import get_spotlight_service

        service = get_spotlight_service()
        package = service.get_effective_package()
        if not package:
            return "Spotlight app: none currently selected."

        state = service.get_run_state()
        pid = service.get_pid()
        if state in ("running", "paused") and pid:
            detail = f"{package} ({state}, pid {pid})"
        elif state == "paused":
            detail = f"{package} (paused)"
        elif state == "restarting":
            detail = f"{package} (restarting)"
        else:
            detail = f"{package} (not running)"
        return f"Spotlight app (the analyst's chosen investigation target): {detail}"
    except Exception:
        return None


def _describe_active_device() -> str | None:
    """Describe the currently active device, if one is connected."""
    try:
        from sandroid.core.toolbox import Toolbox

        device = Toolbox.get_device_manager().active_device
        if device is None:
            return None

        details = []
        if device.model:
            details.append(device.model)
        if device.android_version:
            details.append(f"Android {device.android_version}")
        if device.api_level:
            details.append(f"API {device.api_level}")

        if details:
            return f"Active device: {device.serial} ({', '.join(details)})"
        return f"Active device: {device.serial}"
    except Exception:
        return None


def _describe_background_tasks() -> str | None:
    """Describe running background tasks, excluding the chat turn itself.

    The chat turn registers itself under the ``"chat"`` background task
    before this block is built, so it must be filtered out here -- otherwise
    the model would see itself listed as a running task every single turn.
    """
    try:
        from sandroid.services import get_task_service

        tasks = get_task_service().get_running_tasks()
        names = [task.display_name for task in tasks if task.name != "chat"]
        if not names:
            return None
        return "Running background tasks: " + ", ".join(names)
    except Exception:
        return None


def _describe_frida_session() -> str | None:
    """Describe whether a Frida session is currently attached."""
    try:
        from sandroid.services import get_frida_session_service

        if get_frida_session_service().has_active_session():
            return "An active Frida session is attached."
        return "No active Frida session is attached."
    except Exception:
        return None


def _describe_results_path() -> str | None:
    """Describe the current results path, if configured."""
    try:
        from sandroid.services import get_configuration_service

        path = get_configuration_service().get_results_path()
        if not path:
            return None
        return f"Results path: {path}"
    except Exception:
        return None


def _describe_recording() -> str | None:
    """Describe whether screen recording is currently active."""
    try:
        from sandroid.services import get_emulator_service

        if get_emulator_service().is_recording():
            return "Screen recording is currently active."
        return "Screen recording is not currently active."
    except Exception:
        return None


def _describe_spotlight_files() -> str | None:
    """Describe the spotlight file watchlist, if non-empty.

    The list returned by ``get_spotlight_files()`` is treated as read-only
    here -- it is only read/joined, never mutated.
    """
    try:
        from sandroid.services import get_forensic_service

        files = get_forensic_service().get_spotlight_files()
        if not files:
            return None
        return "Spotlight files being watched: " + ", ".join(str(f) for f in files)
    except Exception:
        return None


def _describe_mitmproxy() -> str | None:
    """Describe whether mitmproxy is currently running."""
    try:
        from sandroid.services.mitmproxy_service import get_mitmproxy_service

        if get_mitmproxy_service().is_running():
            return "Mitmproxy is running."
        return "Mitmproxy is not running."
    except Exception:
        return None


def _describe_app_proxies() -> str | None:
    """Describe which apps currently have their own proxy lane, if any.

    Deliberate, explicit exception to this module's "omit when absent" rule
    for list-shaped facts: the app_filter param on get_captured_flows is
    only useful if the model already knows what packages exist to filter
    by, so this always renders (even when empty), like the boolean-fact
    describers, rather than omitting like _describe_spotlight_files does.
    Uses the non-blocking read so a slow concurrent FocusManager mutation
    can never stall ambient-context building -- returns None on lock
    contention, consistent with this module's isolated-failure rule.
    """
    try:
        from sandroid.core.proxy_manager import get_focus_manager

        manager = get_focus_manager()
        apps = manager.app_proxies_nonblocking()
        if apps is None:
            return None
        if not apps:
            return "App proxies: none currently active."
        reader = getattr(manager, "lane_health_nonblocking", None)
        health = (reader() if reader is not None else None) or {}
        parts = []
        for pkg, target in apps.items():
            lane = health.get(pkg)
            state = f" ({lane.label})" if lane is not None and not lane.ok else ""
            parts.append(f"{pkg} -> {target}{state}")
        return "App proxies active: " + ", ".join(parts)
    except Exception:
        return None


def _describe_lens_highlights() -> str | None:
    """Describe the AI highlight sets of the Network/Files lenses, if any.

    In-memory read of the highlight store (no files, no device). Omitted when
    there is no set.
    """
    try:
        from sandroid.services.row_highlights import get_row_highlights

        store = get_row_highlights()
        sets = store.sets()
        if not sets:
            return None
        parts = []
        for hs in sets:
            mode = "filter" if store.filter_set(hs.lens) == hs.id else "highlight"
            state = {"scanning": ", scanning", "partial": ", partial"}.get(hs.state, "")
            unjudged = store.not_judged_in_view(hs.id)
            if unjudged:
                state += f", {unjudged} not judged (hidden when it was made)"
            parts.append(
                f'{hs.lens.capitalize()} "{hs.label}" {mode} {hs.count}{state} ({hs.id})'
            )
        return "Lens highlights: " + "; ".join(parts) + "."
    except Exception:
        return None


#: The analyst's lens as of their last message (:func:`capture_lens_state`):
#: ``{"lens": "Files", "selected": "/data/...", "filter": "prefs"}``.
_lens_state: dict[str, str] | None = None
#: Characters of a selected row key / filter in the ambient line.
_LENS_FIELD_CAP = 120
#: Lens methods that return the cursor row's key (the lenses differ).
_KEY_METHODS = ("cursor_key", "current_key", "_cursor_key")


def _lens_cursor_key(widget: object) -> str | None:
    """The cursor row key of a lens body (or of its first child that has one)."""
    candidates = [widget]
    walk = getattr(widget, "walk_children", None)
    if callable(walk):
        try:
            candidates.extend(walk())
        except Exception:
            pass
    for node in candidates[:200]:
        for name in _KEY_METHODS:
            method = getattr(node, name, None)
            if not callable(method):
                continue
            try:
                key = method()
            except Exception:
                continue
            if isinstance(key, str) and key:
                return key
    return None


def _lens_filter(widget: object) -> str | None:
    for name in ("_filter", "_filter_text"):
        value = getattr(widget, name, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def capture_lens_state(app: object | None = None) -> None:
    """Snapshot the open lens, its cursor row and its ``/`` filter (N2-B1).

    Call on the UI thread (``AgentSession.submit_user_message`` from the
    chat panel): it reads widgets. Off the UI thread, without an app or on
    any failure it keeps the last snapshot.
    """
    global _lens_state
    try:
        if app is None:
            from sandroid.tui.utils.ui_thread import in_app_context

            if not in_app_context():
                return
            from textual._context import active_app

            app = active_app.get()
        from sandroid.tui.widgets.lens_shell import LENS_BY_ID

        screen = next(
            (
                s
                for s in reversed(getattr(app, "screen_stack", []))
                if isinstance(getattr(s, "active_lens", None), str)
            ),
            None,
        )
        if screen is None:
            return
        spec = LENS_BY_ID.get(screen.active_lens)
        state = {"lens": spec.label if spec else str(screen.active_lens)}
        widget = screen.lens_widget()
        if widget is not None:
            key = _lens_cursor_key(widget)
            if key:
                state["selected"] = key
            text = _lens_filter(widget)
            if text:
                state["filter"] = text
        _lens_state = state
    except Exception:
        return


def _clip(text: str) -> str:
    text = " ".join(str(text).split())
    if len(text) <= _LENS_FIELD_CAP:
        return text
    return text[: _LENS_FIELD_CAP - 1] + "…"


def _describe_active_lens() -> str | None:
    """Which lens the analyst has open, its selected row and ``/`` filter.

    From the snapshot taken when the analyst sent the message (in memory).
    Omitted when unknown (no TUI). Masked with ``ai.mask_sensitive`` on (a
    row key can be a URL with a token).
    """
    try:
        state = _lens_state
        if not state:
            return None
        line = f"Open lens: {state['lens']}"
        extras = []
        if state.get("selected"):
            extras.append(f"selected row {_clip(state['selected'])}")
        if state.get("filter"):
            extras.append(f'filter "{_clip(state["filter"])}"')
        if extras:
            line += " (" + "; ".join(extras) + ")"
        line += "."
        from sandroid.ai.row_classifier import mask_enabled, mask_text

        return mask_text(line) if mask_enabled() else line
    except Exception:
        return None


# One helper per cheap, in-memory state source -- see the module docstring
# for the rules every helper follows.
_DESCRIBERS: tuple[Callable[[], str | None], ...] = (
    _describe_active_lens,
    _describe_spotlight_app,
    _describe_active_device,
    _describe_background_tasks,
    _describe_frida_session,
    _describe_results_path,
    _describe_recording,
    _describe_spotlight_files,
    _describe_mitmproxy,
    _describe_app_proxies,
    _describe_lens_highlights,
)


def build_ambient_block() -> str:
    """Build a short, human-readable block of live Sandroid state.

    Combines every non-``None`` ``_describe_*()`` helper output under a
    short header, one line each. Each helper already wraps its own body in a
    broad ``try/except`` (see the module docstring), and the call here is
    additionally guarded so that even a helper replaced or misbehaving in a
    way that bypasses its own guard can never take down the whole block.

    Returns:
        A non-empty string: the header alone if every source is
        absent/unavailable, or the header plus one line per available fact.
        Always safe to use verbatim as a system-message ``content``.
    """
    lines = [_HEADER]
    for describe in _DESCRIBERS:
        try:
            line = describe()
        except Exception:
            line = None
        if line:
            lines.append(f"- {line}")
    return "\n".join(lines)
