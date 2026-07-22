"""Session-control tools for the Sandroid AI chat: spotlight + mitmproxy/proxy.

Two related groups of real, service-backed tools (no ``"note": "SAMPLE DATA"``
markers -- every tool here dispatches to a genuinely existing Sandroid service):

- **Spotlight app selection** (``category="spotlight"``): ``set_spotlight_app``
  (``RiskTier.REVERSIBLE``) and ``get_spotlight_app`` (``RiskTier.READ_ONLY``),
  backed by :class:`~sandroid.services.spotlight_service.SpotlightService`.
- **Mitmproxy lifecycle + device-proxy routing**
  (``category="network_control"``): ``start_mitmproxy``
  (``RiskTier.CONSEQUENTIAL``), ``stop_mitmproxy``, ``set_device_proxy``,
  ``clear_device_proxy`` (all ``RiskTier.REVERSIBLE``), and
  ``get_mitmproxy_status``/``get_device_proxy_status``
  (``RiskTier.READ_ONLY``), backed by
  :class:`~sandroid.services.mitmproxy_service.MitmproxyService`,
  :class:`~sandroid.services.proxy_service.ProxyService`, and
  :class:`~sandroid.core.proxy_manager.ProxyManager`.

Importing this module registers all eight tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). Every tool here defaults
``can_remember_choice=True`` -- none of the eight have risk that varies
meaningfully by argument the way e.g. ``install_frida_server`` or
``load_snapshot`` do (see :mod:`sandroid.ai.tools.environment_control`), so a
remembered allow/deny choice is safe to reuse across future calls.
"""

import time
from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.enums import SpawnMode

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

    Shared by :func:`set_spotlight_app` and :func:`get_spotlight_app` so the
    field curation + ``SpawnMode`` -> ``str`` normalization lives in one
    place. Excludes every legacy/internal field the raw dict also carries
    (``spotlight_application``, ``spotlight_application_pid``,
    ``spotlight_spawn_application``, ``auto_resume_after_spawn``,
    ``spotlight_files``, ``spotlight_pull_one``, ``spotlight_pull_two``,
    ``spawn_package``).

    Args:
        service: A :class:`~sandroid.services.spotlight_service.SpotlightService`
            instance (or test double exposing ``get_state_dict``).

    Returns:
        ``{"has_app": bool, "package_name": str | None,
        "activity_name": str | None, "pid": int | None, "mode": str,
        "spawn_mode": bool, "auto_resume": bool, "set_at": str | None}``.
        ``mode`` is always a plain string -- the raw dict's ``"mode"`` field is
        a :class:`~sandroid.core.enums.SpawnMode` instance, normalized here to
        ``.value`` explicitly (not relied upon incidentally via
        ``SpawnMode``'s ``str`` subclassing).
    """
    raw = service.get_state_dict()
    mode = raw["mode"]
    mode_value = mode.value if isinstance(mode, SpawnMode) else mode
    spawn_mode = raw["spawn_mode"]
    # get_state_dict()'s "set_at" is only ever populated from attach-mode
    # state (SpotlightService never timestamps a spawn selection) -- so in
    # spawn mode it can carry a stale timestamp left over from a *previous*
    # attach call. Found via E2E testing. Report None instead of a
    # misleading leftover value.
    set_at = None if spawn_mode else raw["set_at"]
    return {
        "has_app": raw["has_app"],
        "package_name": raw["package_name"],
        "activity_name": raw["activity_name"],
        "pid": raw["pid"],
        "mode": mode_value,
        "spawn_mode": spawn_mode,
        "auto_resume": raw["auto_resume"],
        "set_at": set_at,
    }


@sandroid_tool(
    name="set_spotlight_app",
    description=(
        "Select the investigation target app (the 'spotlight' app). Use "
        "mode='attach' to connect to an already-running instance, or "
        "mode='spawn' to launch the app fresh next time a Frida tool is "
        "started (hooks attach from process start)."
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
            "mode": {
                "type": "string",
                "enum": ["attach", "spawn"],
                "description": (
                    "'attach' connects to an already-running instance of the "
                    "app. 'spawn' configures the app to be launched fresh "
                    "(Frida-instrumented from the start) the next time a "
                    "tool spawns it. Defaults to 'attach'."
                ),
                "default": "attach",
            },
            "activity_name": {
                "type": "string",
                "description": (
                    "Optional activity name to record alongside the package. "
                    "Only meaningful in attach mode; ignored in spawn mode."
                ),
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
    mode: str = "attach",
    activity_name: str | None = None,
) -> dict[str, Any]:
    """Select the spotlight (investigation-target) app, attach or spawn mode.

    Real integration points:
    :meth:`sandroid.services.spotlight_service.SpotlightService.set_app`,
    :meth:`~sandroid.services.spotlight_service.SpotlightService.set_spawn_app`,
    and :meth:`~sandroid.services.spotlight_service.SpotlightService.set_spawn_mode`.

    ``mode`` is validated before the spotlight service is even looked up, so
    an invalid value never touches service state. ``mode="spawn"`` calls
    ``set_spawn_app(package_name)`` directly -- never ``set_app(...,
    mode="spawn")``, which only tags a display field and does not set the
    internal spawn-target state ``get_effective_package()``/
    ``get_effective_mode()`` actually read. ``mode="attach"`` calls
    ``set_app(package_name, activity_name=activity_name,
    mode=SpawnMode.ATTACH)`` **and then** ``set_spawn_mode(False)`` -- the
    second call is required to clear any stale prior spawn-mode state
    (``set_app`` never touches it on its own), mirroring every real caller in
    this codebase (e.g. ``spotlight_selection_ui.py``'s attach handlers).

    Args:
        package_name: Fully qualified package name to spotlight.
        mode: ``"attach"`` (default) or ``"spawn"``.
        activity_name: Optional activity name, attach mode only.

    Returns:
        The same curated dict shape as :func:`get_spotlight_app` (see
        :func:`_curated_spotlight_state`), reflecting the just-applied state.

    Raises:
        ToolExecutionError: ``mode`` is neither ``"attach"`` nor ``"spawn"``.
    """
    if mode not in ("attach", "spawn"):
        raise ToolExecutionError(f"invalid mode {mode!r}: must be 'attach' or 'spawn'")

    # Lazy import (matches the convention in `ai/tools/_shared.py` and
    # `ai/tools/device_query.py`): keeps this module import-cheap and lets
    # tests monkeypatch `get_spotlight_service` on the module it lives on.
    from sandroid.services import get_spotlight_service

    service = get_spotlight_service()
    if mode == "spawn":
        service.set_spawn_app(package_name)
    else:
        service.set_app(
            package_name, activity_name=activity_name, mode=SpawnMode.ATTACH
        )
        service.set_spawn_mode(False)

    return _curated_spotlight_state(service)


@sandroid_tool(
    name="get_spotlight_app",
    description=(
        "Get the current spotlight (investigation-target) app: package name, "
        "mode, pid, activity name, auto-resume setting, and when it was set."
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

    This adds ``activity_name``, ``auto_resume``, and ``set_at`` beyond what
    the ambient-context block
    (:func:`sandroid.ai.context._describe_spotlight_app`) already surfaces
    every turn (just package name, mode, and pid) -- so calling this tool is
    not pure duplication of what the model already sees.

    Returns:
        ``{"has_app": bool, "package_name": str | None,
        "activity_name": str | None, "pid": int | None, "mode": str,
        "spawn_mode": bool, "auto_resume": bool, "set_at": str | None}``.
    """
    from sandroid.services import get_spotlight_service

    return _curated_spotlight_state(get_spotlight_service())


# =============================================================================
# Mitmproxy lifecycle
# =============================================================================


@sandroid_tool(
    name="start_mitmproxy",
    description=(
        "Start the embedded mitmweb (mitmproxy) subprocess used for traffic "
        "interception. Ports are read from config, not passed explicitly."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.CONSEQUENTIAL,
    category="network_control",
    can_remember_choice=True,
    resources=frozenset({ResourceId.MITMPROXY}),
)
def start_mitmproxy() -> dict[str, Any]:
    """Start the mitmweb subprocess with config-file ports.

    Real integration point:
    :meth:`sandroid.services.mitmproxy_service.MitmproxyService.start`,
    called with no arguments so it reads proxy/web ports from config rather
    than falling back to hardcoded defaults. Never raises.

    A result of ``started=False`` together with ``running=True`` and
    ``error="already running"`` is a benign no-op (mitmproxy was already
    up), not a real failure -- treat ``running`` as ground truth, not
    ``started``. On a successful start, this waits
    :data:`_MITMPROXY_SETTLE_S` before reading ``running`` -- found via E2E
    testing that mitmweb can crash shortly after a successful spawn (e.g. its
    configured port is already bound by another process), and an immediate
    check can read ``running=True`` moments before that crash lands.

    Returns:
        ``{"started": bool, "running": bool, "proxy_port": int,
        "web_port": int, "web_host": str, "error": str | None}``. ``error``
        is meaningful (non-``None``) whenever ``started`` is ``False`` OR
        ``running`` is ``False`` -- the latter covers the settle-detected
        post-start crash case (``started=True`` but the process died before
        settling), with a synthesized message if the service itself never
        recorded one.
    """
    from sandroid.services.mitmproxy_service import get_mitmproxy_service

    service = get_mitmproxy_service()
    started = service.start()
    if started:
        time.sleep(_MITMPROXY_SETTLE_S)
    running = service.is_running()
    error = service.state.last_error
    if started and not running and not error:
        error = (
            "mitmweb exited shortly after starting -- port "
            f"{service.state.proxy_port}/{service.state.web_port} may "
            "already be in use by another process"
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
        "tls_failures": int, "last_error": str | None}``.
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
    TUI-only convenience, out of scope for this tool. Also note:
    ``proxy_port`` defaults to ``8080`` until :func:`start_mitmproxy` has
    actually run once (config-file ports are not loaded until then) --
    calling this before starting mitmproxy can point the device at a port
    nothing is listening on. This mirrors the existing TUI panel's own
    behavior, not a regression, but prefer starting mitmproxy first.

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

    return {"success": get_proxy_service().clear_proxy()}


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
