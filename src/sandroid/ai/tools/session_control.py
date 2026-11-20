"""Session-control tools for the Sandroid AI chat: spotlight + mitmproxy/proxy.

Three related groups of real, service-backed tools (no ``"note": "SAMPLE
DATA"`` markers -- every tool here dispatches to a genuinely existing
Sandroid service):

- **Spotlight app selection** (``category="spotlight"``): ``set_spotlight_app``
  (``RiskTier.REVERSIBLE``), ``get_spotlight_app`` (``RiskTier.READ_ONLY``)
  and ``start_spotlight_app`` (``RiskTier.CONSEQUENTIAL``, asks every call),
  backed by :class:`~sandroid.services.spotlight_service.SpotlightService`
  and :mod:`sandroid.services.app_start`.
- **Mitmproxy lifecycle + device-proxy routing**
  (``category="network_control"``): ``start_mitmproxy``
  (``RiskTier.CONSEQUENTIAL``), ``stop_mitmproxy``, ``set_device_proxy``,
  ``clear_device_proxy`` (all ``RiskTier.REVERSIBLE``), and
  ``get_mitmproxy_status``/``get_device_proxy_status``
  (``RiskTier.READ_ONLY``), backed by
  :class:`~sandroid.services.mitmproxy_service.MitmproxyService`,
  :class:`~sandroid.services.proxy_service.ProxyService`, and
  :class:`~sandroid.core.proxy_manager.ProxyManager`.
- **App Proxies / Focus lanes** (``category="network_control"``):
  ``enable_app_proxy``, ``disable_app_proxy``, ``set_app_proxy_quic_blocking``
  (all ``RiskTier.REVERSIBLE``) and ``get_app_proxy_status``
  (``RiskTier.READ_ONLY``), backed by
  :class:`~sandroid.core.proxy_manager.FocusManager`. ``disable_app_proxy``'s
  default (no-``package``) call scopes its teardown to lanes *this* AI
  caller itself enabled, tracked in the module-level
  ``_app_proxy_owner_by_package`` map -- see that function's docstring.

Importing this module registers all thirteen tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). Every tool here defaults
``can_remember_choice=True`` except ``enable_app_proxy``
(``can_remember_choice=False`` -- its ``target`` argument can point a lane at
an arbitrary, unreviewed external host, the same argument-dependent-risk
reason ``install_frida_server``/``load_snapshot`` use, see
:mod:`sandroid.ai.tools.environment_control`) and ``start_spotlight_app``
(``can_remember_choice=False`` -- ``fresh=true`` kills a running app, so the
analyst approves every call); every other tool's risk does
not vary meaningfully by argument, so a remembered allow/deny choice is safe
to reuse across future calls.
"""

import time
from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._shared import validate_package_name
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb_utils import is_valid_package_name

#: How long to let mitmweb settle after a successful ``start()`` before
#: trusting ``is_running()``. Found via E2E testing: a successful spawn can
#: still crash within about a second (e.g. the configured port is already
#: bound by an unrelated process), and an immediate ``is_running()`` check
#: can read ``True`` right before that crash lands.
_MITMPROXY_SETTLE_S = 0.5

# =============================================================================
# Spotlight app selection
# =============================================================================


def _curated_spotlight_state(service: Any) -> dict[str, Any]:
    """Curate ``SpotlightService.get_state_dict()`` down to the AI-facing shape.

    Shared by :func:`set_spotlight_app` and :func:`get_spotlight_app`.

    Args:
        service: A :class:`~sandroid.services.spotlight_service.SpotlightService`
            instance (or test double exposing ``get_state_dict``).

    Returns:
        ``{"has_app": bool, "package_name": str | None,
        "activity_name": str | None, "pid": int | None, "state": str,
        "running": bool, "paused": bool, "set_at": str | None}``. ``state``
        is ``"running"``, ``"paused"``, ``"not_running"`` or
        ``"restarting"`` (cached; no device round trip).
    """
    raw = service.get_state_dict()
    return {
        "has_app": raw["has_app"],
        "package_name": raw["package_name"],
        "activity_name": raw["activity_name"],
        "pid": raw["pid"],
        "state": raw.get("state", "not_running"),
        "running": bool(raw.get("running", False)),
        "paused": bool(raw.get("paused", False)),
        "set_at": raw["set_at"],
    }


@sandroid_tool(
    name="set_spotlight_app",
    description=(
        "Select the investigation target app (the 'spotlight' app). This only "
        "selects it: nothing is started or restarted. Frida tools later "
        "attach to it when it runs and start it when it does not; use "
        "start_spotlight_app to start, resume or restart it."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": (
                    "Fully qualified package name to spotlight "
                    "(e.g. 'com.example.app')."
                ),
            },
            "activity_name": {
                "type": "string",
                "description": "Optional activity name to record with the package.",
            },
        },
        "required": ["package_name"],
    },
    risk=RiskTier.REVERSIBLE,
    category="spotlight",
    can_remember_choice=True,
    resources=frozenset({ResourceId.SPOTLIGHT}),
    releases=frozenset({ResourceId.SPOTLIGHT}),
)
def set_spotlight_app(
    package_name: str,
    mode: str | None = None,
    activity_name: str | None = None,
) -> dict[str, Any]:
    """Select the spotlight (investigation-target) app.

    Real integration point:
    :meth:`sandroid.services.spotlight_service.SpotlightService.set_app`.
    The spotlight has no spawn/attach mode any more; ``mode`` is no longer in
    the schema but still accepted (and ignored) so old transcripts dispatch.

    Args:
        package_name: Fully qualified package name to spotlight.
        mode: Deprecated, ignored.
        activity_name: Optional activity name.

    Returns:
        The same curated dict shape as :func:`get_spotlight_app` (see
        :func:`_curated_spotlight_state`), reflecting the just-applied state.

    Raises:
        ToolExecutionError: *package_name* is not a valid Android package name.
    """
    package_name = validate_package_name(package_name)

    # Lazy import (matches the convention in `ai/tools/_shared.py` and
    # `ai/tools/device_query.py`): keeps this module import-cheap and lets
    # tests monkeypatch `get_spotlight_service` on the module it lives on.
    from sandroid.services import get_spotlight_service

    service = get_spotlight_service()
    service.set_app(package_name, activity_name=activity_name)
    return _curated_spotlight_state(service)


@sandroid_tool(
    name="get_spotlight_app",
    description=(
        "Get the current spotlight (investigation-target) app: package name, "
        "run state (running/paused/not_running/restarting), pid, activity "
        "name, and when it was selected."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="spotlight",
)
def get_spotlight_app() -> dict[str, Any]:
    """Return the curated spotlight app state.

    Real integration point:
    :meth:`sandroid.services.spotlight_service.SpotlightService.get_state_dict`
    (see :func:`_curated_spotlight_state` for the field curation).

    Returns:
        ``{"has_app", "package_name", "activity_name", "pid", "state",
        "running", "paused", "set_at"}``.
    """
    from sandroid.services import get_spotlight_service

    return _curated_spotlight_state(get_spotlight_service())


def _in_subtask() -> bool:
    """True unless the current tool call runs in the orchestrator's turn.

    A subagent (``spawn_agent``) runs with its own run context, whose agent
    id is not the orchestrator's. Fails closed: when the run context or the
    owner cannot be read, the call counts as a subagent's. A call outside
    any AI turn (direct call, test) is allowed.
    """
    try:
        from sandroid.ai.loop import (
            ORCHESTRATOR_ID,
            _current_owner_id,
            current_run_context,
        )

        ctx = current_run_context()
        owner = _current_owner_id.get()
    except Exception:
        return True
    if ctx is not None:
        return getattr(ctx, "agent_id", None) != ORCHESTRATOR_ID
    if owner is None:
        return False  # not an AI turn (direct call, test)
    return owner != ORCHESTRATOR_ID


@sandroid_tool(
    name="start_spotlight_app",
    description=(
        "Start, resume or restart the spotlight app with the armed bypasses. "
        "fresh=true RESTARTS a running app (force-stop + spawn) and STOPS the "
        "tools running on it (friTap, Dexray, ...; armed bypasses are "
        "re-applied); without it a running app is left alone. paused=true holds the new process paused "
        "until resumed (Android ends the hold after about 10 s). The analyst "
        "approves every call."
    ),
    parameters={
        "type": "object",
        "properties": {
            "fresh": {
                "type": "boolean",
                "description": (
                    "Restart the app even if it runs (kills the running "
                    "process). Default false."
                ),
                "default": False,
            },
            "paused": {
                "type": "boolean",
                "description": (
                    "Keep the started process paused (hooks loaded, app not "
                    "running yet). Default false."
                ),
                "default": False,
            },
        },
        "required": [],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="spotlight",
    can_remember_choice=False,
    resources=frozenset({ResourceId.FRIDA_SERVER}),
)
def start_spotlight_app(fresh: bool = False, paused: bool = False) -> dict[str, Any]:
    """Start / resume / restart the spotlight app (the Space / ⇧P / ⇧R paths).

    Real integration points: :func:`sandroid.services.app_start.start_app`,
    :func:`~sandroid.services.app_start.restart_app` and
    :func:`~sandroid.services.app_start.resume_app` -- the same code the App
    lens keys run. The approval gate is the consent for ``fresh``. The tool
    is orchestrator-only: a subagent is refused, so an operator agent cannot
    restart the app in two steps (``kill_process``, then this).

    Args:
        fresh: Restart a running app.
        paused: Hold the new process paused.

    Returns:
        ``{"started": bool, "running": bool, "paused": bool,
        "pid": int | None, "message": str}``.

    Raises:
        ToolExecutionError: No spotlight app is selected, or the call runs
            inside a subagent.
    """
    from sandroid.services import app_start, get_spotlight_service

    if _in_subtask():
        # Orchestrator-only (like start_replay): a subagent could otherwise
        # restart the app in two steps (kill_process, then this).
        raise ToolExecutionError(
            "start_spotlight_app is not allowed inside a subagent (starting "
            "the app is not a subtask a subagent may do); ask the "
            "orchestrator/analyst to start the app"
        )
    service = get_spotlight_service()
    package = service.get_effective_package()
    if not package:
        raise ToolExecutionError(
            "no spotlight app selected; call set_spotlight_app first"
        )
    liveness, pid = app_start.probe_liveness(package, frida_fallback=True)
    held = bool(service.is_app_paused())
    if liveness == app_start.Liveness.UNKNOWN and not held:
        return _start_result(
            False, service, f"could not tell whether {package} is running"
        )
    running = pid is not None or held
    if held and not fresh:
        if paused:
            return _start_result(False, service, f"{package} is already paused")
        ok, msg = app_start.resume_app()
        return _start_result(ok, service, msg)
    if running and not fresh:
        return _start_result(
            False,
            service,
            f"{package} is already running (pid {pid}); pass fresh=true to restart it",
        )
    if running:
        ok, msg = app_start.restart_app(paused=paused)
    else:
        ok, msg = app_start.start_app(paused=paused)
    return _start_result(ok, service, msg)


def _start_result(started: bool, service: Any, message: str) -> dict[str, Any]:
    state = service.get_run_state()
    return {
        "started": bool(started),
        "running": state in ("running", "paused"),
        "paused": state == "paused",
        "pid": service.get_pid(),
        "message": message,
    }


# =============================================================================
# Mitmproxy lifecycle
# =============================================================================


def _resolve_mitmproxy_start_ports(
    proxy_port: int | None, web_port: int | None
) -> tuple[int, int, str]:
    """Resolve concrete ``(proxy_port, web_port, web_host)`` for ``start()``.

    Mirrors :meth:`~sandroid.services.mitmproxy_service.MitmproxyService.start`'s
    own override-on-default config read, but resolves ``proxy_port`` and
    ``web_port`` independently rather than all-or-nothing. That method only
    reads config when the caller passed the exact sentinel defaults for ALL
    THREE of ``proxy_port``/``web_port``/``web_host`` -- so a caller
    forwarding just one explicit port while leaving the other at its Python
    default parameter value would silently skip the config read for BOTH,
    reverting the port the caller did *not* ask to override back to the
    hardcoded default (8080/8081) instead of the user's configured value.
    Resolving each argument independently here -- and always calling
    ``start()`` with three concrete keyword values -- avoids that trap.

    ``web_host`` is not exposed as a tool parameter at all (only the two
    ports are meaningful to override for a port-conflict retry), so it is
    always sourced from config when available.

    Args:
        proxy_port: Caller-supplied proxy port, or ``None`` to read config.
        web_port: Caller-supplied web port, or ``None`` to read config.

    Returns:
        ``(proxy_port, web_port, web_host)`` -- three concrete, non-``None``
        values: whichever the caller passed explicitly, else the
        config-resolved value, else ``MitmproxyService.start()``'s own
        hardcoded defaults (``8080``/``8081``/``"127.0.0.1"``) if
        ``get_config()`` itself raises or is unavailable -- mirroring the
        defensive ``try/except`` around that same read in
        ``mitmproxy_service.py``.
    """
    resolved_proxy_port = proxy_port
    resolved_web_port = web_port
    web_host = None
    try:
        from sandroid.config import get_config

        cfg = get_config().mitmproxy
        if resolved_proxy_port is None:
            resolved_proxy_port = cfg.proxy_port
        if resolved_web_port is None:
            resolved_web_port = cfg.web_port
        web_host = cfg.web_host
    except Exception:
        pass

    return (
        resolved_proxy_port if resolved_proxy_port is not None else 8080,
        resolved_web_port if resolved_web_port is not None else 8081,
        web_host if web_host is not None else "127.0.0.1",
    )


@sandroid_tool(
    name="start_mitmproxy",
    description=(
        "Start the embedded mitmweb (mitmproxy) subprocess used for traffic "
        "interception. Omit proxy_port/web_port to use the configured ports "
        "(default behavior). If a previous call failed because a port was "
        "already in use -- a common, ordinary conflict (e.g. Docker Desktop "
        "often binds 8080) -- retry this tool with different "
        "proxy_port/web_port values; retrying the identical call will never "
        "succeed."
    ),
    parameters={
        "type": "object",
        "properties": {
            "proxy_port": {
                "type": "integer",
                "description": (
                    "TCP port for the intercepting HTTP(S) proxy. Omit to "
                    "use the port from config. After a 'port already in "
                    "use' failure, retry with a different port (e.g. 8082)."
                ),
            },
            "web_port": {
                "type": "integer",
                "description": (
                    "TCP port for mitmweb's web UI. Omit to use the port "
                    "from config. After a 'port already in use' failure, "
                    "retry with a different port (e.g. 8090)."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="network_control",
    can_remember_choice=True,
    resources=frozenset({ResourceId.MITMPROXY}),
)
def start_mitmproxy(
    proxy_port: int | None = None, web_port: int | None = None
) -> dict[str, Any]:
    """Start the mitmweb subprocess, optionally overriding its ports.

    Real integration point:
    :meth:`sandroid.services.mitmproxy_service.MitmproxyService.start`,
    always called with three concrete keyword arguments (``proxy_port``,
    ``web_port``, ``web_host``) resolved by
    :func:`_resolve_mitmproxy_start_ports` -- never with bare defaults, and
    never relying on ``start()``'s own all-or-nothing sentinel-matching
    heuristic to decide whether to read config (see that helper's docstring
    for why). Omitting both ``proxy_port`` and ``web_port`` reproduces
    exactly today's default behavior: both ports (and ``web_host``) come
    from config. Never raises.

    A result of ``started=False`` together with ``running=True`` and
    ``error="already running"`` is a benign no-op (mitmproxy was already
    up), not a real failure -- treat ``running`` as ground truth, not
    ``started``. On a successful start, this waits
    :data:`_MITMPROXY_SETTLE_S` before reading ``running`` -- found via E2E
    testing that mitmweb can crash shortly after a successful spawn (e.g. its
    configured port is already bound by another process), and an immediate
    check can read ``running=True`` moments before that crash lands. The
    synthesized error for that case explicitly names ``proxy_port``/
    ``web_port`` as the retry levers, so the calling model knows what to
    change instead of blindly retrying the identical call (the real-world
    failure mode this tool exists to fix).

    Args:
        proxy_port: TCP port for the HTTP(S) proxy. Omit to read from
            config.
        web_port: TCP port for mitmweb's web UI. Omit to read from config.

    Returns:
        ``{"started": bool, "running": bool, "proxy_port": int,
        "web_port": int, "web_host": str, "error": str | None}``. ``error``
        is meaningful (non-``None``) whenever ``started`` is ``False`` OR
        ``running`` is ``False`` -- the latter covers the settle-detected
        post-start crash case (``started=True`` but the process died before
        settling), with a synthesized message (naming the actual ports used
        and suggesting a ``proxy_port``/``web_port`` retry) if the service
        itself never recorded one.
    """
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    service = get_mitmproxy_service()
    resolved_proxy_port, resolved_web_port, web_host = _resolve_mitmproxy_start_ports(
        proxy_port, web_port
    )
    started = service.start(
        proxy_port=resolved_proxy_port,
        web_port=resolved_web_port,
        web_host=web_host,
    )
    if started:
        time.sleep(_MITMPROXY_SETTLE_S)
    running = service.is_running()
    error = service.state.last_error
    if started and not running and not error:
        error = (
            "mitmweb exited shortly after starting -- port "
            f"{service.state.proxy_port}/{service.state.web_port} may "
            "already be in use by another process. Retry start_mitmproxy "
            "with different proxy_port/web_port values."
        )
    return {
        "started": started,
        "running": running,
        "proxy_port": service.state.proxy_port,
        "web_port": service.state.web_port,
        "web_host": service.state.web_host,
        "error": error if (not started or not running) else None,
    }


@sandroid_tool(
    name="stop_mitmproxy",
    description="Stop the embedded mitmweb (mitmproxy) subprocess, if running.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="network_control",
    can_remember_choice=True,
    resources=frozenset({ResourceId.MITMPROXY}),
    releases=frozenset({ResourceId.MITMPROXY}),
)
def stop_mitmproxy() -> dict[str, Any]:
    """Stop the mitmweb subprocess if it is running.

    Real integration point:
    :meth:`sandroid.services.mitmproxy_service.MitmproxyService.stop`. Blocks
    up to the service's internal 3s default timeout while it terminates the
    subprocess -- existing, accepted behavior elsewhere in this codebase, no
    special handling needed here. Never raises; idempotent when nothing was
    running.

    Returns:
        ``{"stopped": bool, "was_running": bool}``. ``stopped`` reflects
        whether mitmweb is confirmed not running after the call; not running
        beforehand still returns ``stopped=True``.
    """
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    service = get_mitmproxy_service()
    was_running = service.is_running()
    service.stop()
    return {"stopped": not service.is_running(), "was_running": was_running}


@sandroid_tool(
    name="get_mitmproxy_status",
    description=(
        "Get the embedded mitmproxy subprocess's current status: running "
        "state, ports, pid, and flow/TLS-failure counters."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="network_control",
)
def get_mitmproxy_status() -> dict[str, Any]:
    """Return mitmweb's current status.

    Real integration point:
    :meth:`sandroid.services.mitmproxy_service.MitmproxyService.is_running`
    for the ``running`` field -- deliberately NOT ``state.running``, which
    can go stale if mitmweb crashes independently of a ``stop()`` call.
    Every other field is read straight from ``service.state``. Does not call
    ``capture_view()`` (that does a separate, blocking device read reserved
    for :func:`get_device_proxy_status`).

    Returns:
        ``{"running": bool, "proxy_port": int, "web_port": int,
        "web_host": str, "pid": int | None, "flows_seen": int,
        "tls_failures": int, "flow_errors": int, "last_error": str | None}``.
    """
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    service = get_mitmproxy_service()
    state = service.state
    return {
        "running": service.is_running(),
        "proxy_port": state.proxy_port,
        "web_port": state.web_port,
        "web_host": state.web_host,
        "pid": state.pid,
        "flows_seen": state.flows_seen,
        "tls_failures": state.tls_failures,
        "flow_errors": state.flow_errors,
        "last_error": state.last_error,
    }


# =============================================================================
# Device proxy routing
# =============================================================================


@sandroid_tool(
    name="set_device_proxy",
    description=(
        "Point the device's global HTTP proxy at our mitmproxy instance. "
        "Does NOT set up an adb-reverse tunnel (a separate TUI-only "
        "convenience) -- start mitmproxy first so the resolved port is "
        "actually listening."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="network_control",
    can_remember_choice=True,
    resources=frozenset({ResourceId.DEVICE_PROXY}),
)
def set_device_proxy() -> dict[str, Any]:
    """Route the device's global HTTP proxy to our mitmproxy instance.

    Real integration points: :func:`sandroid.core.proxy_manager.resolve_proxy_host_ip`
    (emulator-aware host resolution),
    :meth:`sandroid.core.proxy_manager.ProxyManager.get_proxy_settings` +
    :func:`sandroid.core.proxy_manager.classify_device_proxy` (previous-state
    check), and :meth:`sandroid.services.proxy_service.ProxyService.set_proxy`
    -- replicating the exact orchestration
    ``tui/widgets/mitmproxy_panel.py::_set_device_proxy`` uses, rather than
    calling ``ProxyService.set_proxy`` bare. Never raises.

    This does **not** manage any ``adb reverse`` tunnel -- that is a separate
    TUI-only convenience, out of scope for this tool. ``proxy_port`` is the
    configured port while mitmproxy is stopped and the live port while it
    runs; prefer starting mitmproxy first so something is listening. The
    address is recorded on the mitmproxy service so Sandroid clears it again
    on stop / exit (only if it still points at us).

    Returns:
        ``{"success": bool, "host_ip": str, "port": int,
        "overwrote_foreign_proxy": bool, "previous_proxy": str | None}``.
        ``overwrote_foreign_proxy`` is ``True`` iff a proxy other than ours
        was set on the device beforehand; ``previous_proxy`` is that
        previous ``"ip:port"`` address, or ``None`` if none was set (or the
        device read failed).
    """
    from sandroid.core.proxy_manager import (
        ProxyManager,
        ProxyStatus,
        classify_device_proxy,
        resolve_proxy_host_ip,
    )
    from sandroid.services import get_proxy_service
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    proxy_port = get_mitmproxy_service().state.proxy_port
    host_ip = resolve_proxy_host_ip()

    previous_state = "none"
    previous_addr = None
    status, cfg = ProxyManager().get_proxy_settings()
    if status == ProxyStatus.SET and cfg is not None:
        previous_state = classify_device_proxy(cfg.ip, cfg.port, proxy_port)
        previous_addr = cfg.address
    # ProxyStatus.ERROR falls through to "none"/None, same as NOT_SET.

    success = get_proxy_service().set_proxy(host_ip, str(proxy_port))
    if success:
        get_mitmproxy_service().note_device_proxy(f"{host_ip}:{proxy_port}")

    return {
        "success": success,
        "host_ip": host_ip,
        "port": proxy_port,
        "overwrote_foreign_proxy": previous_state == "other",
        "previous_proxy": previous_addr,
    }


@sandroid_tool(
    name="clear_device_proxy",
    description=(
        "Clear the device's global HTTP proxy setting. Does NOT tear down "
        "any adb-reverse tunnel (a separate TUI-only convenience)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="network_control",
    can_remember_choice=True,
    resources=frozenset({ResourceId.DEVICE_PROXY}),
    releases=frozenset({ResourceId.DEVICE_PROXY}),
)
def clear_device_proxy() -> dict[str, Any]:
    """Clear the device's global HTTP proxy setting.

    Real integration point:
    :meth:`sandroid.services.proxy_service.ProxyService.clear_proxy`. Does
    not manage any ``adb reverse`` tunnel -- that is a separate TUI-only
    convenience, out of scope for this tool.

    Returns:
        ``{"success": bool}``.
    """
    from sandroid.services import get_proxy_service
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    success = get_proxy_service().clear_proxy()
    if success:
        get_mitmproxy_service().note_device_proxy(None)
    return {"success": success}


@sandroid_tool(
    name="get_device_proxy_status",
    description=(
        "Get the device's global HTTP proxy state: whether it points at our "
        "mitmproxy ('ours'), some other proxy ('other'), or is unset "
        "('none')."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="network_control",
)
def get_device_proxy_status() -> dict[str, Any]:
    """Return the device's global HTTP proxy classification.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.ProxyManager.get_proxy_settings` +
    :func:`sandroid.core.proxy_manager.classify_device_proxy`. Both
    ``ProxyStatus.NOT_SET`` and ``ProxyStatus.ERROR`` (an internal ADB-read
    failure) fold into ``"state": "none"`` -- no separate error path. Uses
    the classifier's own raw vocabulary (``"other"``), not
    ``MitmproxyService.capture_view()``'s relabeled ``"external"`` -- the two
    already disagree elsewhere in this codebase; this tool does not add a
    third variant.

    Returns:
        ``{"state": "ours" | "other" | "none", "addr": str,
        "mitmproxy_proxy_port": int}``. ``addr`` is ``""`` when
        ``state == "none"``.
    """
    from sandroid.core.proxy_manager import (
        ProxyManager,
        ProxyStatus,
        classify_device_proxy,
    )
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    proxy_port = get_mitmproxy_service().state.proxy_port
    status, cfg = ProxyManager().get_proxy_settings()
    if status == ProxyStatus.SET and cfg is not None:
        state = classify_device_proxy(cfg.ip, cfg.port, proxy_port)
        addr = cfg.address
    else:
        state = "none"
        addr = ""

    return {"state": state, "addr": addr, "mitmproxy_proxy_port": proxy_port}


# =============================================================================
# App proxies (Focus lanes)
# =============================================================================

#: AI-tools-layer-only bookkeeping: which owner (the orchestrator, or a
#: subagent id -- see ``sandroid.ai.loop._current_owner_id``) enabled each
#: app-proxy lane via :func:`enable_app_proxy`. ``FocusManager`` itself has no
#: ownership concept and gains none for this -- a lane created via the TUI
#: (not through this tool) correctly has no entry here, so it is never
#: touched by :func:`disable_app_proxy`'s default (unscoped) teardown.
_app_proxy_owner_by_package: dict[str, str] = {}


def _owns_lane(package: str, owner: str | None) -> bool:
    """Whether ``owner`` is the caller that enabled ``package``'s lane.

    A missing ownership entry (``None``) must never be reported as owned by
    a caller with no owner context (``owner is None`` too) -- that would
    misreport a TUI-created (or otherwise untracked) lane as
    ``owned_by_caller``.
    """
    lane_owner = _app_proxy_owner_by_package.get(package)
    return lane_owner is not None and lane_owner == owner


@sandroid_tool(
    name="enable_app_proxy",
    description=(
        "Route a single app's traffic through its own proxy lane, leaving "
        "every other app untouched. Requires root. Omit 'package' to use "
        "the spotlight app. Omit 'target' to route to our own mitmproxy "
        "(default); pass an external 'http://host:port' to route to "
        "Burp/ZAP instead."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package": {
                "type": "string",
                "description": (
                    "Package to route through its own proxy lane. Omit to "
                    "use the current spotlight app."
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Upstream to route this app's traffic to. Omit to route "
                    "to our own mitmproxy (default); pass 'http://host:port' "
                    "to route to an external proxy (Burp/ZAP) instead."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="network_control",
    can_remember_choice=False,
    resources=frozenset({ResourceId.FOCUS}),
)
def enable_app_proxy(
    package: str | None = None, target: str | None = None
) -> dict[str, Any]:
    """Assign an app-proxy lane to ``package`` (or the current spotlight app).

    Real integration point:
    :meth:`sandroid.core.proxy_manager.FocusManager.enable_focus`. Never
    raises; failure surfaces as ``success=False`` with an explanatory
    ``message`` (e.g. no spotlight app set, pool exhausted, root/gost/
    reachability failures).

    On success, records this call's resource-arbiter owner id (read from
    ``sandroid.ai.loop._current_owner_id``, the same ``ContextVar`` the loop
    itself reads before claiming arbiter resources) against the resolved
    package in the module-level ``_app_proxy_owner_by_package`` map, so a
    later unscoped :func:`disable_app_proxy` call only tears down lanes THIS
    owner itself enabled. A caller with no owner context (``None`` -- a
    non-chat caller, or a test) is never recorded, matching
    :func:`disable_app_proxy`'s own fallback-to-blanket behavior in that case.

    Two things are deliberately checked/resolved *before* calling
    ``enable_focus``, not after, closing two related gaps a verification
    pass found in an earlier draft:

    - The spotlight-app fallback is resolved exactly once, right here, and
      that same resolved value is passed through as ``enable_focus``'s own
      ``package`` argument (instead of passing ``None`` through and letting
      ``enable_focus`` resolve it internally, then separately re-querying
      the spotlight app afterward for this function's own return value).
      Two independent resolutions could observe two different spotlight
      apps if the spotlight changed in between -- a real race in this
      codebase's concurrent-subagent architecture -- which would attribute
      ownership to the wrong package below.
    - Whether the package already had a live lane is checked *before*
      calling ``enable_focus``, so ownership is only ever recorded for a
      lane this call actually just created. ``enable_focus`` is idempotent
      (a re-call for an already-proxied package is a harmless
      ``(True, "... already proxied")`` no-op) -- recording ownership
      unconditionally on any ``ok=True`` would let this call silently
      "adopt" a lane a *different* owner (another subagent, or the TUI)
      created earlier, letting this owner's later unscoped
      :func:`disable_app_proxy` tear it down. That is exactly the failure
      the ownership map exists to prevent, just reached via a different
      path than the one it was originally built for.

    Args:
        package: Target package, or None to use the spotlight app.
        target: Lane upstream -- None routes to our mitmproxy (default); an
            ``http://host:port`` string routes to an external HTTP proxy.

    Returns:
        ``{"success": bool, "message": str, "package": str | None,
        "target": str | None, "lane_socks_port": int | None}``. ``package``
        is the resolved package name (accounting for the spotlight-app
        fallback), not necessarily the raw argument. ``lane_socks_port`` is
        the lane's host SOCKS5 port (from ``FocusManager.lane_for``),
        populated only on success -- named "lane_socks_port" rather than
        "lane" because ``lane_for()`` returns a port number, not
        ``FocusManager``'s internal 0-based lane index.
    """
    from sandroid.ai.loop import _current_owner_id
    from sandroid.core.proxy_manager import get_focus_manager
    from sandroid.services import get_spotlight_service

    manager = get_focus_manager()

    effective_package = package
    if effective_package is None:
        try:
            effective_package = get_spotlight_service().get_effective_package()
        except Exception:
            effective_package = None
    if effective_package and not is_valid_package_name(effective_package):
        return {
            "success": False,
            "message": f"Invalid package name {effective_package!r}.",
            "package": effective_package,
            "target": target,
            "lane_socks_port": None,
        }

    already_active = bool(effective_package) and (
        manager.lane_for(effective_package) is not None
    )

    ok, message = manager.enable_focus(effective_package, target)

    lane_socks_port = None
    if ok and effective_package:
        lane_socks_port = manager.lane_for(effective_package)
        if not already_active:
            owner = _current_owner_id.get()
            if owner is not None:
                _app_proxy_owner_by_package[effective_package] = owner

    result = {
        "success": ok,
        "message": message,
        "package": effective_package,
        "target": target,
        "lane_socks_port": lane_socks_port,
    }
    health = _lane_health_words(manager).get(effective_package or "")
    if health is not None:
        # "active", "waiting for mitmproxy" (the app has no network until
        # mitmproxy runs), "mitmproxy unreachable ..." or "failed: <why>".
        result["health"] = health
    return result


def _lane_health_words(manager: Any) -> dict[str, str]:
    """``{package: health label}`` of the lanes, if the manager reports it."""
    reader = getattr(manager, "lane_health_nonblocking", None)
    if reader is None:
        return {}
    try:
        health = reader(timeout=1.0)
    except Exception:
        return {}
    return {pkg: h.label for pkg, h in (health or {}).items()}


@sandroid_tool(
    name="disable_app_proxy",
    description=(
        "Remove an app's proxy lane. Omit 'package' to free every lane THIS "
        "task itself enabled (not lanes other tasks or the TUI set up). "
        "Pass force=true to instead free every lane on the device, "
        "regardless of who enabled it."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package": {
                "type": "string",
                "description": (
                    "Package whose proxy lane to remove. Omit to free every "
                    "lane this task itself enabled (see 'force')."
                ),
            },
            "force": {
                "type": "boolean",
                "description": (
                    "Only meaningful when 'package' is omitted: free every "
                    "live lane on the device regardless of who enabled it, "
                    "including other tasks or the TUI. Defaults to false."
                ),
                "default": False,
            },
        },
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="network_control",
    resources=frozenset({ResourceId.FOCUS}),
    releases=frozenset({ResourceId.FOCUS}),
)
def disable_app_proxy(
    package: str | None = None, force: bool = False
) -> dict[str, Any]:
    """Free one app-proxy lane, or this owner's lanes, or every live lane.

    Real integration point:
    :meth:`sandroid.core.proxy_manager.FocusManager.disable_focus`. Three
    behaviors -- this scoping exists because ``ResourceId.FOCUS`` is one
    coarse lease covering ALL lanes, so an unscoped blanket disable could
    otherwise tear down a lane a *different* concurrent owner (another
    subagent, or the TUI) is still using:

    - ``package`` given: unchanged, always allowed -- calls
      ``disable_focus(package)`` and clears that package's ownership entry
      if present. Returns ``scope="one"``.
    - ``package=None``, ``force=False`` (the default), and this call has an
      owner context (``sandroid.ai.loop._current_owner_id`` is not
      ``None``): frees only the lanes ``_app_proxy_owner_by_package``
      attributes to the calling owner, one ``disable_focus(pkg)`` call per
      lane, and clears each from the ownership map. Returns ``scope="own"``.
    - ``package=None`` and (``force=True`` OR no owner context is
      available): falls back to the original blanket ``disable_focus(None)``
      behavior, clearing the whole ownership map. Returns ``scope="all"``.

    Args:
        package: Package to unfocus, or None (see behavior above).
        force: Only meaningful when ``package`` is None -- free every lane
            regardless of ownership.

    Returns:
        ``{"success": bool, "message": str, "package": str | None,
        "scope": "one" | "own" | "all"}``, plus ``"freed": list[str]`` (the
        packages actually freed) when ``scope == "own"``.
    """
    from sandroid.ai.loop import _current_owner_id
    from sandroid.core.proxy_manager import get_focus_manager

    manager = get_focus_manager()

    if package is not None:
        ok, message = manager.disable_focus(package)
        _app_proxy_owner_by_package.pop(package, None)
        return {
            "success": ok,
            "message": message,
            "package": package,
            "scope": "one",
        }

    owner = _current_owner_id.get()
    if not force and owner is not None:
        own_packages = [
            pkg
            for pkg, pkg_owner in _app_proxy_owner_by_package.items()
            if pkg_owner == owner
        ]
        success = True
        messages = []
        for pkg in own_packages:
            ok, message = manager.disable_focus(pkg)
            success = success and ok
            messages.append(message)
            _app_proxy_owner_by_package.pop(pkg, None)
        return {
            "success": success,
            "message": (
                "; ".join(messages) if messages else "No app proxies owned by this task"
            ),
            "package": None,
            "scope": "own",
            "freed": own_packages,
        }

    ok, message = manager.disable_focus(None)
    _app_proxy_owner_by_package.clear()
    return {
        "success": ok,
        "message": message,
        "package": None,
        "scope": "all",
    }


@sandroid_tool(
    name="get_app_proxy_status",
    description=(
        "List which apps have their own proxy lane, where each routes, and "
        "free lane count."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="network_control",
)
def get_app_proxy_status() -> dict[str, Any]:
    """Return every live app-proxy lane plus pool capacity.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.FocusManager.app_proxies` and
    ``get_config().mitmproxy.focus_lanes`` for the pool size (despite the
    name, lane count lives on ``MitmproxyConfig``, not ``FocusConfig``).

    Returns:
        ``{"active": bool, "apps": {package: {"target": str,
        "owned_by_caller": bool}}, "lanes_used": int, "lanes_total": int,
        "lanes_free": int}``. ``owned_by_caller`` is True iff the calling
        owner (``sandroid.ai.loop._current_owner_id``) is the one that
        enabled that app's lane via :func:`enable_app_proxy` -- a lane
        enabled by a different owner, or created via the TUI, reports False.
    """
    from sandroid.ai.loop import _current_owner_id
    from sandroid.config import get_config
    from sandroid.core.proxy_manager import get_focus_manager

    manager = get_focus_manager()
    apps = manager.app_proxies()
    health = _lane_health_words(manager)
    owner = _current_owner_id.get()
    lanes_total = int(get_config().mitmproxy.focus_lanes)
    lanes_used = len(apps)

    return {
        "active": lanes_used > 0,
        "apps": {
            pkg: {
                "target": target,
                "owned_by_caller": _owns_lane(pkg, owner),
                **({"health": health[pkg]} if pkg in health else {}),
            }
            for pkg, target in apps.items()
        },
        "lanes_used": lanes_used,
        "lanes_total": lanes_total,
        "lanes_free": max(0, lanes_total - lanes_used),
    }


@sandroid_tool(
    name="set_app_proxy_quic_blocking",
    description=(
        "Turn UDP/443 (QUIC/HTTP-3) blocking on/off for App-Proxy lanes, "
        "forcing QUIC-only apps to fall back to interceptable TCP/TLS."
    ),
    parameters={
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": (
                    "True to REJECT UDP/443 on app-proxy lanes, False to allow it."
                ),
            },
        },
        "required": ["enabled"],
    },
    risk=RiskTier.REVERSIBLE,
    category="network_control",
)
def set_app_proxy_quic_blocking(enabled: bool) -> dict[str, Any]:
    """Persist and apply the App-Proxy QUIC-blocking setting.

    Real integration points: ``get_config().focus.block_quic`` and
    :meth:`sandroid.core.proxy_manager.FocusManager.set_quic_blocking`.
    Persists the config value BEFORE calling the manager -- mirrors
    ``proxy_modal.py``'s own commit order, so lanes enabled *after* this call
    also pick up the new setting, not just already-live ones.

    Args:
        enabled: True to REJECT UDP/443 on app-proxy lanes, False to allow it.

    Returns:
        ``{"success": True, "enabled": bool}``.
    """
    from sandroid.config import get_config
    from sandroid.core.proxy_manager import get_focus_manager

    get_config().focus.block_quic = enabled
    get_focus_manager().set_quic_blocking(enabled)

    return {"success": True, "enabled": enabled}
