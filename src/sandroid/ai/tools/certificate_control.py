"""CA certificate detection, push, install and removal tools for the AI chat.

Backed entirely by :class:`~sandroid.core.proxy_manager.CAManager` -- plain
ADB shell commands and one root device script that mounts the CA into the
trust store of every mount namespace. The install restarts nothing: running
apps, Zygote, system_server and frida-server keep their PIDs, and no Frida
session or script is touched. A Zygote restart (the fallback for devices the
no-restart path cannot handle) is never reachable from these tools: it kills
every app and needs the user's confirmation in the TUI. Every tool here is
tagged ``category="frida"`` purely as a chat-facing grouping choice (CA
certificates and SSL interception are, from an analyst's point of view, part
of the same "get HTTPS traffic decrypted" workflow as SSL-unpin); the
category has no effect on dispatch, permissions, or the
:class:`~sandroid.ai.arbiter.DeviceResourceArbiter`.

Importing this module registers all six tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator): ``list_detected_ca_certificates``
(``RiskTier.READ_ONLY``), ``push_ca_certificate`` (``REVERSIBLE``),
``check_ca_injection_status`` (``READ_ONLY``), ``enable_adb_root``
(``CONSEQUENTIAL``), ``inject_ca_certificate`` (``CONSEQUENTIAL``),
``remove_ca_certificate`` (``CONSEQUENTIAL``).
"""

from pathlib import Path
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._host_paths import resolve_confined_host_path
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

_SOURCE_PARAM_SCHEMA = {
    "type": "string",
    "enum": ["mitmproxy", "http_toolkit", "burp_suite", "custom"],
    "description": (
        "Which CA certificate to use. 'mitmproxy'/'http_toolkit'/"
        "'burp_suite' auto-detect that tool's default certificate location "
        "on this host (see list_detected_ca_certificates for what was "
        "found); 'custom' requires custom_path."
    ),
    "default": "mitmproxy",
}

_CUSTOM_PATH_PARAM_SCHEMA = {
    "type": "string",
    "description": (
        "Host filesystem path to a certificate file. Required when "
        "source='custom'; ignored for every other source. Must resolve "
        "inside one of the AI's allowed host roots -- see "
        "list_allowed_host_paths."
    ),
}


def _get_ca_manager() -> Any:
    """Construct a fresh ``CAManager`` instance.

    Real integration point: :class:`sandroid.core.proxy_manager.CAManager`.
    Lazily imported here (matching this package's convention for every other
    manager/service lookup) so tests can monkeypatch this helper directly.

    Unlike Frida-server access
    (:func:`sandroid.ai.tools.environment_control._get_frida_manager`),
    there is no process-wide shared-instance getter for ``CAManager``
    anywhere in the codebase -- the TUI itself constructs a fresh
    ``CAManager()`` per handler (see e.g. ``tui/widgets/mitmproxy_panel.py``),
    so this mirrors that existing pattern rather than inventing a new
    shared-instance one.

    Returns:
        A new ``CAManager`` instance.
    """
    from sandroid.core.proxy_manager import CAManager

    return CAManager()


def _resolve_ca_source_path(source: str, custom_path: str | None) -> Path:
    """Resolve a CA ``source`` selector to a real local certificate path.

    ``'custom'`` routes through :func:`resolve_confined_host_path` -- the
    same host-path allowlist confinement every other host-touching AI tool
    uses (see :mod:`sandroid.ai.tools._host_paths`) -- so a model-supplied
    path outside the configured roots is rejected before any filesystem
    access happens. Every other source is matched against
    :meth:`~sandroid.core.proxy_manager.CAManager.detect_ca_certificates`'s
    results by ``CAInfo.source`` (a
    :class:`~sandroid.core.proxy_manager.CASource` enum whose ``.value`` is
    exactly this module's ``source`` strings).

    Args:
        source: One of ``"mitmproxy"``, ``"http_toolkit"``, ``"burp_suite"``,
            ``"custom"``.
        custom_path: Host path to use when ``source == "custom"``. Ignored
            for every other source.

    Returns:
        The resolved local certificate :class:`~pathlib.Path`.

    Raises:
        ToolExecutionError: ``source == "custom"`` and ``custom_path`` is
            missing, or it falls outside every allowed host root; or no
            certificate for the requested ``source`` was detected on this
            host.
    """
    if source == "custom":
        if not custom_path:
            raise ToolExecutionError("custom_path is required when source='custom'")
        return resolve_confined_host_path(custom_path)

    manager = _get_ca_manager()
    for info in manager.detect_ca_certificates():
        if info.source.value == source:
            return info.path

    raise ToolExecutionError(
        f"no {source!r} CA certificate detected on this host -- call "
        "list_detected_ca_certificates to see what's available, or pass "
        "source='custom' with an explicit custom_path"
    )


@sandroid_tool(
    name="list_detected_ca_certificates",
    description=(
        "List CA certificates auto-detected on this host from known "
        "interception-tool locations (mitmproxy, HTTP Toolkit, Burp Suite)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="frida",
)
def list_detected_ca_certificates() -> dict[str, Any]:
    """List CA certificates auto-detected on well-known host paths.

    Real integration point:
    :meth:`sandroid.core.proxy_manager.CAManager.detect_ca_certificates`.
    Never raises -- a source whose certificate file isn't present at any of
    its known locations is simply absent from the result, not an error.

    Returns:
        ``{"certificates": [...], "count": int}`` -- each certificate entry
        is ``{"source": str, "path": str, "display_name": str,
        "exists": bool}``.
    """
    manager = _get_ca_manager()
    certs = manager.detect_ca_certificates()
    return {
        "certificates": [
            {
                "source": info.source.value,
                "path": str(info.path),
                "display_name": info.display_name,
                "exists": info.exists,
            }
            for info in certs
        ],
        "count": len(certs),
    }


@sandroid_tool(
    name="push_ca_certificate",
    description=(
        "Push a CA certificate to the device's temp directory (converted to "
        "DER format), staging it for inspection or manual install. Does NOT "
        "inject it into the system trust store -- see inject_ca_certificate "
        "for that."
    ),
    parameters={
        "type": "object",
        "properties": {
            "source": _SOURCE_PARAM_SCHEMA,
            "custom_path": _CUSTOM_PATH_PARAM_SCHEMA,
        },
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="frida",
)
def push_ca_certificate(
    source: str = "mitmproxy", custom_path: str | None = None
) -> dict[str, Any]:
    """Push a CA certificate to the device's temp directory in DER format.

    Real integration point:
    :meth:`sandroid.core.proxy_manager.CAManager.push_cert_to_device`, which
    converts a PEM/CRT input to DER before pushing -- Android's temp staging
    path expects DER here (see :func:`inject_ca_certificate`'s docstring for
    why system-store injection needs a *different*, PEM-producing push).

    Args:
        source: Which CA certificate to push -- ``"mitmproxy"``,
            ``"http_toolkit"``, ``"burp_suite"`` auto-detect that tool's
            default certificate location on this host; ``"custom"`` requires
            ``custom_path``. Defaults to ``"mitmproxy"``.
        custom_path: Host path to a certificate file, required when
            ``source == "custom"``. Resolved through
            :func:`~sandroid.ai.tools._host_paths.resolve_confined_host_path`.

    Returns:
        ``{"success": bool, "message": str, "path": str}`` -- ``path`` is
        the resolved local certificate path that was pushed.

    Raises:
        ToolExecutionError: ``source``/``custom_path`` could not be resolved
            to a real local path (see :func:`_resolve_ca_source_path`).
    """
    path = _resolve_ca_source_path(source, custom_path)
    manager = _get_ca_manager()
    success, message = manager.push_cert_to_device(path)
    return {"success": success, "message": message, "path": str(path)}


@sandroid_tool(
    name="check_ca_injection_status",
    description=(
        "Check whether Sandroid's mitmproxy CA is trusted system-wide: read "
        "inside Zygote's, system_server's and the running apps' mount "
        "namespaces (verdict injected / partial / other_ca / absent)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="frida",
)
def check_ca_injection_status() -> dict[str, Any]:
    """Report the CA status in Zygote's namespace plus the trust store used.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.CAManager.check_zygote_injection_status`
    (one root device script reading the CA file inside the namespaces of the
    Zygotes, system_server and every app namespace -- never the adb shell's
    own namespace) and
    :meth:`~sandroid.core.proxy_manager.CAManager.determine_injection_strategy`.

    Returns:
        ``{"injected": bool, "verdict": str, "cert_hash": str | None,
        "zygote_pid": int | None, "zygote64_pid": int | None,
        "namespaces_lacking": int, "message": str | None,
        "recommended_strategy": str, "api_level": int | None}``.
        ``verdict`` is ``injected`` (everywhere), ``partial`` (new apps trust
        it, some running ones not: inject again), ``other_ca`` (another CA
        under the same name: inject again to replace it), ``absent`` or
        ``unknown``.
    """
    manager = _get_ca_manager()
    zygote_status = manager.check_zygote_injection_status()
    strategy, api_level = manager.determine_injection_strategy()
    return {
        "injected": zygote_status.injected,
        "verdict": getattr(zygote_status, "verdict", ""),
        "cert_hash": zygote_status.cert_hash,
        "zygote_pid": zygote_status.zygote_pid,
        "zygote64_pid": zygote_status.zygote64_pid,
        "namespaces_lacking": getattr(zygote_status, "lacking", 0),
        "message": zygote_status.error_message,
        "recommended_strategy": strategy.value,
        "api_level": api_level,
    }


@sandroid_tool(
    name="enable_adb_root",
    description=(
        "Restart adbd as root ('adb root'). Required before CA injection on "
        "a device that is not already root-enabled. This grants root to "
        "every subsequent ADB command on this device, not just certificate "
        "injection."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.CONSEQUENTIAL,
    category="frida",
)
def enable_adb_root() -> dict[str, Any]:
    """Enable ADB root access on the device.

    Real integration point:
    :meth:`sandroid.core.proxy_manager.CAManager.enable_adb_root` -- runs
    ``adb root`` then verifies via ``adb shell id``. Never raises; a device
    that does not support root (or is not itself rooted) reports a clean
    failure message rather than an exception.

    ``RiskTier.CONSEQUENTIAL`` with its own confirmation dialog, separate
    from :func:`inject_ca_certificate`'s -- root affects every subsequent
    ADB command's privilege on this device, a broader and independently
    reviewable grant than the certificate injection that prompted it.

    Returns:
        ``{"success": bool, "message": str}``.
    """
    manager = _get_ca_manager()
    success, message = manager.enable_adb_root()
    return {"success": success, "message": message}


@sandroid_tool(
    name="inject_ca_certificate",
    description=(
        "Make a CA certificate trusted system-wide WITHOUT restarting "
        "anything (running apps, Zygote and frida-server keep running; "
        "running apps trust it at once), then bypass Chrome's Certificate "
        "Transparency enforcement for it. Idempotent; replaces another CA "
        "with the same name (rotation). Requires root; if the device is not "
        "yet root-enabled, this reports needs_root=true -- call "
        "enable_adb_root first, then retry. If the device needs a Zygote "
        "restart instead, this reports restart_required=true and does "
        "nothing: only the user can approve that, in the TUI (Ctrl+N)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "source": _SOURCE_PARAM_SCHEMA,
            "custom_path": _CUSTOM_PATH_PARAM_SCHEMA,
        },
        "required": [],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="frida",
    can_remember_choice=False,
)
def inject_ca_certificate(
    source: str = "mitmproxy", custom_path: str | None = None
) -> dict[str, Any]:
    """Install a CA in the system trust store (no restart), then bypass CT.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.CAManager.inject_ca_into_zygote` (the
    no-restart install: a shared tmpfs in init's namespace, bound into every
    Zygote first and then every running app's namespace) and, on success,
    :meth:`~sandroid.core.proxy_manager.CAManager.bypass_chrome_ct` -- the
    same two calls, in the same order, as the TUI's Ctrl+N.

    No WORLD lease: the install kills nothing and touches no Frida state, so
    it cannot invalidate another task's device work. It never restarts
    Zygote; when the device needs that (``restart_required``), the tool
    returns and the user decides in the TUI.

    ``source`` is always resolved to a real local certificate path via
    :func:`_resolve_ca_source_path`; the manager re-encodes it as PEM, pushes
    it and checks the result by SHA-256 inside Zygote's namespace.

    ``needs_root`` is reported, never auto-chained: auto-chaining would mean
    one approved ``CONSEQUENTIAL`` call silently also grants root over every
    later ADB command -- the model calls ``enable_adb_root`` itself (its own
    approval), then retries.

    ``can_remember_choice=False`` -- which certificate gets trusted
    system-wide varies with ``source``/``custom_path``.

    Args:
        source: ``"mitmproxy"``, ``"http_toolkit"``, ``"burp_suite"`` (that
            tool's default certificate on this host) or ``"custom"``
            (requires ``custom_path``). Defaults to ``"mitmproxy"``.
        custom_path: Host path to a certificate file, required when
            ``source == "custom"``. Resolved through
            :func:`~sandroid.ai.tools._host_paths.resolve_confined_host_path`.

    Returns:
        ``{"success": bool, "message": str, "needs_root": bool,
        "restart_required": bool, "verdict": str | None,
        "strategy": str | None, "api_level": int | None,
        "chrome_ct_bypass": {"success": bool, "message": str} | None}``.

    Raises:
        ToolExecutionError: ``source``/``custom_path`` could not be resolved
            to a real local path (see :func:`_resolve_ca_source_path`).
    """
    path = _resolve_ca_source_path(source, custom_path)
    manager = _get_ca_manager()
    result = manager.inject_ca_into_zygote(cert_path=path)

    chrome_ct_bypass = None
    if result.success:
        ct_success, ct_message = manager.bypass_chrome_ct(path)
        chrome_ct_bypass = {"success": ct_success, "message": ct_message}

    restart_required = bool(getattr(result, "restart_required", False))
    message = result.message
    if restart_required:
        message += (
            " -- a Zygote restart would install it, but that kills every app; "
            "ask the user to install it from the TUI (Ctrl+N in the Network "
            "lens), which asks before restarting"
        )
    return {
        "success": result.success,
        "message": message,
        "needs_root": result.needs_root,
        "restart_required": restart_required,
        "verdict": getattr(result, "verdict", None),
        "strategy": result.strategy.value if result.strategy else None,
        "api_level": result.api_level,
        "chrome_ct_bypass": chrome_ct_bypass,
    }


@sandroid_tool(
    name="remove_ca_certificate",
    description=(
        "Remove Sandroid's CA from the system trust store in every namespace "
        "(no restart). New apps stop trusting it at once; apps that are "
        "already running keep the old trust until they restart. HTTPS "
        "interception stops working after this."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.CONSEQUENTIAL,
    category="frida",
)
def remove_ca_certificate() -> dict[str, Any]:
    """Uninstall the CA (every swept namespace, init's mounts) and forget it.

    Real integration point:
    :meth:`sandroid.core.proxy_manager.CAManager.uninject_ca`. Also clears
    the re-inject intent, so a later snapshot load does not put it back.

    Returns:
        ``{"success": bool, "message": str}``; the message says that running
        apps keep the old trust until they restart.
    """
    manager = _get_ca_manager()
    success, message = manager.uninject_ca()
    return {"success": success, "message": message}
