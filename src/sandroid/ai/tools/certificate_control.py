"""CA certificate detection, push, and Zygote-injection tools for the AI chat.

Backed entirely by :class:`~sandroid.core.proxy_manager.CAManager` -- plain
ADB shell commands, OpenSSL subprocess calls, and Zygote mount-namespace
manipulation (root-gated). **None** of the five tools in this module touch
``AndroidFridaManager.FridaManager``, frida-server, or any Frida script --
unlike the real Frida-lifecycle tools in
:mod:`sandroid.ai.tools.environment_control`, every tool here is tagged
``category="frida"`` purely as a chat-facing grouping choice (CA certificates
and SSL interception are, from an analyst's point of view, part of the same
"get HTTPS traffic decrypted" workflow as SSL-unpin). This costs nothing
mechanically: :class:`~sandroid.ai.tools.registry.ToolSpec.category` is a
free-form display/filter label with zero effect on dispatch, permissions, or
the :class:`~sandroid.ai.arbiter.DeviceResourceArbiter` (see ``ToolSpec``'s
docstring in :mod:`sandroid.ai.tools.registry`).

Importing this module registers all five tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator): ``list_detected_ca_certificates``
(``RiskTier.READ_ONLY``), ``push_ca_certificate`` (``REVERSIBLE``),
``check_ca_injection_status`` (``READ_ONLY``), ``enable_adb_root``
(``CONSEQUENTIAL``), ``inject_ca_certificate`` (``CONSEQUENTIAL``).
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
        "Check whether a CA certificate is currently injected into "
        "Zygote's mount namespace (system-wide trust), and the injection "
        "strategy recommended for this device's Android version."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="frida",
)
def check_ca_injection_status() -> dict[str, Any]:
    """Report Zygote CA injection status plus the recommended strategy.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.CAManager.check_zygote_injection_status`
    (verifies by actually looking inside Zygote's mount namespace via
    ``nsenter``, not just checking the staging path) and
    :meth:`~sandroid.core.proxy_manager.CAManager.determine_injection_strategy`.
    Neither raises on its own -- every ADB/nsenter call inside them is
    individually try/except-guarded.

    Returns:
        ``{"injected": bool, "cert_hash": str | None,
        "zygote_pid": int | None, "zygote64_pid": int | None,
        "recommended_strategy": str, "api_level": int | None}``.
    """
    manager = _get_ca_manager()
    zygote_status = manager.check_zygote_injection_status()
    strategy, api_level = manager.determine_injection_strategy()
    return {
        "injected": zygote_status.injected,
        "cert_hash": zygote_status.cert_hash,
        "zygote_pid": zygote_status.zygote_pid,
        "zygote64_pid": zygote_status.zygote64_pid,
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
        "Inject a CA certificate into Zygote's mount namespace for "
        "system-wide trust, then bypass Chrome's Certificate Transparency "
        "enforcement for it. Restarts Zygote -- every running app briefly "
        "closes. Requires root; if the device is not yet root-enabled, this "
        "reports needs_root=true instead of injecting -- call enable_adb_root "
        "first, then retry this tool."
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
    """Inject a CA certificate into Zygote's mount namespace, then bypass CT.

    Real integration points:
    :meth:`sandroid.core.proxy_manager.CAManager.inject_ca_into_zygote` and,
    on success, :meth:`~sandroid.core.proxy_manager.CAManager.bypass_chrome_ct`
    -- mirrors ``tui/widgets/mitmproxy_panel.py``'s ``_apply_inject_result``,
    which chains the same two calls in the same order after a successful
    TUI-driven injection.

    ``source`` defaults to ``"mitmproxy"`` (never optional/``None``) and is
    always resolved to a real local :class:`~pathlib.Path` via
    :func:`_resolve_ca_source_path` before being passed through as
    ``inject_ca_into_zygote(cert_path=path)`` -- this tool never calls it
    with ``cert_path=None``. That no-argument mode is real in the underlying
    manager (it means "use whatever is already staged on the device"), but
    it is a trap for an AI tool specifically: the default staging push
    (``push_cert_to_device``, used by :func:`push_ca_certificate`) converts
    the certificate to **DER** before pushing it, while
    ``inject_ca_into_zygote(cert_path=None)`` never re-pushes -- it goes
    straight to ``_get_cert_hash_from_device()``, which pulls the on-device
    file to a hardcoded local ``sandroid-device-cert.pem`` and infers
    ``-inform PEM`` purely from that hardcoded ``.pem`` suffix, not the
    actual bytes on disk. Against a DER-format on-device file, OpenSSL's PEM
    parse fails, ``cert_hash`` comes back ``None``, and the call fails with a
    misleading "could not determine certificate hash" instead of the real
    cause. Passing a real ``cert_path`` sidesteps this entirely:
    ``inject_ca_into_zygote`` re-pushes it in PEM form internally via
    ``push_cert_for_injection`` (step 2 of its own implementation, run
    *before* it ever computes a hash) whenever ``cert_path`` is truthy and
    exists -- exactly what the TUI's own ``_do_inject_ca`` relies on, and
    exactly why this tool never needs to call ``push_cert_for_injection``
    itself.

    ``needs_root`` is reported, never auto-chained: if
    ``InjectionResult.needs_root`` is ``True``, this returns immediately
    without calling :func:`enable_adb_root` itself. Auto-chaining would mean
    one approved ``CONSEQUENTIAL`` call silently also grants a second,
    broader capability (root over every subsequent ADB command) that the
    human never separately reviewed -- the model is expected to see
    ``needs_root: true``, call ``enable_adb_root`` itself (its own
    ``CONSEQUENTIAL`` approval), then re-invoke this tool.

    ``can_remember_choice=False`` -- which certificate gets trusted
    system-wide varies with ``source``/``custom_path``, so an "allow
    always" choice made for one call must not silently cover a different
    certificate on a later call.

    Args:
        source: Which CA certificate to inject -- ``"mitmproxy"``,
            ``"http_toolkit"``, ``"burp_suite"`` auto-detect that tool's
            default certificate location on this host; ``"custom"`` requires
            ``custom_path``. Defaults to ``"mitmproxy"``.
        custom_path: Host path to a certificate file, required when
            ``source == "custom"``. Resolved through
            :func:`~sandroid.ai.tools._host_paths.resolve_confined_host_path`.

    Returns:
        ``{"success": bool, "message": str, "needs_root": bool,
        "strategy": str | None, "api_level": int | None,
        "chrome_ct_bypass": {"success": bool, "message": str} | None}`` --
        ``chrome_ct_bypass`` is ``None`` whenever injection itself did not
        succeed (it is never attempted in that case).

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

    return {
        "success": result.success,
        "message": result.message,
        "needs_root": result.needs_root,
        "strategy": result.strategy.value if result.strategy else None,
        "api_level": result.api_level,
        "chrome_ct_bypass": chrome_ct_bypass,
    }
