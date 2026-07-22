"""Frida-server lifecycle and screen-capture/snapshot tools for the AI chat.

Importing this module registers all ten tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator).

Two categories:

- ``category="frida"`` (4 tools): ``check_frida_server_status``,
  ``start_frida_server``, ``stop_frida_server``, ``install_frida_server`` --
  ``RiskTier.READ_ONLY``/``REVERSIBLE``/``REVERSIBLE``/``CONSEQUENTIAL``
  respectively, all dispatching through the real installed
  ``AndroidFridaManager.FridaManager`` instance shared with the rest of the
  app via :meth:`sandroid.services.frida_session_service.FridaSessionService.get_frida_manager`.
  ``install_frida_server`` has ``can_remember_choice=False`` -- its risk
  varies with the (optional) ``version`` argument and device state, so an
  "allow always" choice must not be persisted.
- ``category="capture"`` (6 tools): ``take_screenshot``,
  ``start_screen_recording``, ``stop_screen_recording``, ``create_snapshot``,
  ``load_snapshot``, ``list_snapshots`` -- ``RiskTier.READ_ONLY``/
  ``REVERSIBLE``/``REVERSIBLE``/``REVERSIBLE``/``CONSEQUENTIAL``/
  ``READ_ONLY`` respectively, all dispatching through
  :class:`sandroid.services.emulator_service.EmulatorService` via
  :func:`sandroid.services.get_emulator_service`. ``load_snapshot`` has
  ``can_remember_choice=False`` -- restoring an arbitrary named snapshot can
  discard current device state, and that risk depends on which snapshot is
  named, not just the tool's identity. Screenshot/snapshot operations only
  work against the emulator's telnet console (not a real physical device);
  screen recording is real ``adb shell screenrecord`` and works on physical
  devices too -- see each tool's docstring for which applies.
"""

import os
import time
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

#: How long to poll for frida-server to actually exit after
#: ``stop_frida_server()`` returns, before concluding the stop failed. Found
#: via E2E testing against a real device: the kill takes ~1-2s to land, so an
#: immediate ``is_frida_server_running()`` check produces a false failure.
_STOP_FRIDA_SETTLE_TIMEOUT_S = 3.0
_STOP_FRIDA_POLL_INTERVAL_S = 0.5


def _get_frida_manager() -> Any:
    """Get the shared ``AndroidFridaManager.FridaManager`` instance.

    Real integration point:
    :meth:`sandroid.services.frida_session_service.FridaSessionService.get_frida_manager`
    (lazily imported here so tests can monkeypatch
    ``sandroid.services.get_frida_session_service`` directly, mirroring the
    convention in :mod:`sandroid.ai.tools.device_query`).

    ``FridaManager()`` construction itself is what can fail (e.g. no device
    connected) -- not just individual operations on an already-constructed
    instance -- so every one of the four Frida tools in this module,
    including the read-only status check, goes through this helper.

    Returns:
        The shared ``FridaManager`` instance.

    Raises:
        ToolExecutionError: Construction/retrieval failed for any reason.
            Caught broadly (``except Exception``, not narrowly
            ``(RuntimeError, ImportError)``) -- ``get_frida_manager()`` itself
            only re-raises those two, but this helper is the one place meant
            to guarantee a clean conversion regardless of what the underlying
            ``ADB.find()`` construction path might surface.
    """
    from sandroid.services import get_frida_session_service

    try:
        return get_frida_session_service().get_frida_manager()
    except Exception as exc:
        raise ToolExecutionError(str(exc)) from exc


@sandroid_tool(
    name="check_frida_server_status",
    description=(
        "Check whether frida-server is currently running on the device, and "
        "which frida-server version (if any) is installed there."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="frida",
)
def check_frida_server_status() -> dict[str, Any]:
    """Report frida-server's running state and installed version.

    Real integration point: ``AndroidFridaManager.FridaManager.is_frida_server_running``
    and ``.get_installed_server_version`` (both safe -- neither raises on its
    own; the manager's own *construction*, done in :func:`_get_frida_manager`,
    is the part that can fail, e.g. when no device is connected).

    Returns:
        ``{"running": bool, "installed_version": str | None}``.

    Raises:
        ToolExecutionError: The Frida manager could not be constructed/
            retrieved (see :func:`_get_frida_manager`).
    """
    manager = _get_frida_manager()
    return {
        "running": manager.is_frida_server_running(),
        "installed_version": manager.get_installed_server_version(),
    }


@sandroid_tool(
    name="start_frida_server",
    description=(
        "Start the installed frida-server binary on the device. Requires "
        "root and a frida-server binary already installed on the device."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="frida",
)
def start_frida_server() -> dict[str, Any]:
    """Start frida-server on the device.

    Real integration point: ``AndroidFridaManager.FridaManager.run_frida_server``.
    Never raises on its own -- it returns ``False`` on a non-rooted device or
    any other failure, and can block up to roughly 16 seconds while it waits
    for the server process to come up.

    Returns:
        ``{"started": bool}``, plus a ``"hint"`` field when ``started`` is
        ``False`` (the device may not be rooted, or frida-server may not be
        installed).

    Raises:
        ToolExecutionError: The Frida manager could not be constructed/
            retrieved (see :func:`_get_frida_manager`).
    """
    manager = _get_frida_manager()
    started = manager.run_frida_server()
    if started:
        return {"started": True}
    return {
        "started": False,
        "hint": (
            "frida-server did not start -- the device may not be rooted, or "
            "no frida-server binary is installed (see install_frida_server)"
        ),
    }


@sandroid_tool(
    name="stop_frida_server",
    description="Stop a currently running frida-server process on the device.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="frida",
)
def stop_frida_server() -> dict[str, Any]:
    """Stop frida-server on the device, pre/post-checking its running state.

    Real integration point: ``AndroidFridaManager.FridaManager.stop_frida_server``.
    That real method gives no success/failure signal at all (it returns
    ``None``) and, on a non-rooted device, silently no-ops (logs a warning,
    raises nothing). This wrapper therefore checks
    ``is_frida_server_running()`` both before and after calling it, so the
    model gets an honest answer instead of a bare "done". The kill takes
    roughly 1-2 seconds to actually land on-device (confirmed via live
    testing), so the post-check polls for up to
    :data:`_STOP_FRIDA_SETTLE_TIMEOUT_S` seconds rather than checking once
    immediately -- an immediate single check produced false "may not be
    rooted" failures on a device that was, in fact, rooted and did stop.

    Returns:
        ``{"stopped": False, "was_running": False}`` if frida-server was not
        running to begin with (the manager's ``stop_frida_server`` is never
        called in this case).
        ``{"stopped": False, "was_running": True, "error": str}`` if the stop
        call itself raised, or if frida-server still appears to be running
        afterwards (most likely a non-rooted device silently no-oping).
        ``{"stopped": True, "was_running": True}`` on a confirmed stop.

    Raises:
        ToolExecutionError: The Frida manager could not be constructed/
            retrieved (see :func:`_get_frida_manager`).
    """
    manager = _get_frida_manager()
    was_running = manager.is_frida_server_running()
    if not was_running:
        return {"stopped": False, "was_running": False}

    try:
        manager.stop_frida_server()
    except Exception as exc:
        return {"stopped": False, "was_running": True, "error": str(exc)}

    deadline = time.monotonic() + _STOP_FRIDA_SETTLE_TIMEOUT_S
    still_running = manager.is_frida_server_running()
    while still_running and time.monotonic() < deadline:
        time.sleep(_STOP_FRIDA_POLL_INTERVAL_S)
        still_running = manager.is_frida_server_running()

    if still_running:
        return {
            "stopped": False,
            "was_running": True,
            "error": (
                "stop command sent but frida-server still appears to be "
                "running -- the device may not be rooted (stop_frida_server "
                "silently no-ops on non-rooted devices)"
            ),
        }
    return {"stopped": True, "was_running": True}


@sandroid_tool(
    name="install_frida_server",
    description=(
        "Download and install a frida-server binary onto the device. "
        "Requires root. Optionally pin a specific frida-server version; "
        "omit to install the version matching the local frida Python "
        "package."
    ),
    parameters={
        "type": "object",
        "properties": {
            "version": {
                "type": "string",
                "description": (
                    "Specific frida-server version to install (e.g. "
                    "'16.1.4'). Omit to install the version matching the "
                    "locally installed frida Python package."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="frida",
    can_remember_choice=False,
)
def install_frida_server(version: str | None = None) -> dict[str, Any]:
    """Download and install a frida-server binary on the device.

    Real integration point: ``AndroidFridaManager.FridaManager.install_frida_server``.
    On success, the real method returns bare ``True`` -- never the version
    that got installed -- so this wrapper calls
    ``get_installed_server_version()`` afterwards and reports that, rather
    than echoing back the input ``version`` argument (which is often
    ``None``/"latest" and would misleadingly imply the tool doesn't actually
    know what got installed). The whole call is wrapped in one broad
    ``except Exception`` since the real method raises a documented
    ``RuntimeError`` on a non-rooted device *and* can raise other,
    undocumented exceptions (network/download/extraction failures) that
    aren't individually caught inside the library.

    Args:
        version: Specific frida-server version to install, or ``None`` to
            install the version matching the local ``frida`` Python package.

    Returns:
        ``{"installed": True, "version": str | None}`` on success (``version``
        is whatever ``get_installed_server_version()`` reports afterwards).
        ``{"installed": False, "error": str}`` on any failure, including a
        non-rooted device.

    Raises:
        ToolExecutionError: The Frida manager could not be constructed/
            retrieved (see :func:`_get_frida_manager`).
    """
    manager = _get_frida_manager()
    try:
        manager.install_frida_server(version=version)
    except Exception as exc:
        return {"installed": False, "error": str(exc)}
    return {"installed": True, "version": manager.get_installed_server_version()}


@sandroid_tool(
    name="take_screenshot",
    description=(
        "Take a screenshot of the device screen. Emulator-only -- this uses "
        "the AVD's telnet console and does not work against a real physical "
        "device."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="capture",
)
def take_screenshot() -> dict[str, str]:
    """Capture a screenshot via the emulator's telnet console.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.take_screenshot`.
    Emulator-telnet-console-only -- does **not** work against a real physical
    device.

    The underlying telnet command resolves its output path against the
    emulator (QEMU) process's own working directory, not the caller's.
    ``EmulatorService.take_screenshot()`` builds that output path by joining
    a *relative* screenshots directory (from
    ``ConfigurationService.get_raw_results_path()``, never made absolute)
    with the filename -- confirmed via E2E testing that this silently fails
    to write anywhere while the telnet console still reports success and the
    service still returns a path. This wrapper sidesteps the bug rather than
    just detecting it: it passes an explicit *absolute* ``filename``, and
    since ``os.path.join()`` discards a relative first argument once the
    second argument is absolute, the buggy relative directory never survives
    into the final path the service actually uses. The
    ``os.path.exists()`` check below is kept as a defense-in-depth guard
    (e.g. against a genuinely disconnected emulator), not the primary fix.

    Returns:
        ``{"path": str}`` -- local path to the saved screenshot file, verified
        to exist.

    Raises:
        ToolExecutionError: The screenshot failed (``take_screenshot``
            returned ``None``), or it returned a path but no file was
            actually written there -- both most likely mean this isn't
            running against a properly-attached AVD emulator.
    """
    from sandroid.services import get_configuration_service, get_emulator_service

    screenshots_dir = os.path.abspath(
        os.path.join(get_configuration_service().get_raw_results_path(), "screenshots")
    )
    os.makedirs(screenshots_dir, exist_ok=True)
    filename = os.path.join(
        screenshots_dir, f"screenshot_{time.strftime('%Y-%m-%d_%H-%M-%S')}.png"
    )

    path = get_emulator_service().take_screenshot(filename=filename)
    if path is None or not os.path.exists(path):
        raise ToolExecutionError(
            "screenshot failed -- take_screenshot only works against the "
            "emulator's telnet console, not a real physical device; check "
            "that an AVD emulator is running and that Sandroid can write to "
            "its screenshots directory"
        )
    return {"path": path}


@sandroid_tool(
    name="start_screen_recording",
    description=(
        "Start recording the device screen via 'adb shell screenrecord'. "
        "Works on both the emulator and a real physical device."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="capture",
)
def start_screen_recording() -> dict[str, Any]:
    """Start a real ``adb shell screenrecord``-backed screen recording.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.start_recording`.
    Backed by real ``adb shell screenrecord`` -- works on a real physical
    device as well as the emulator.

    Returns:
        ``{"started": True, "path": str}`` on success -- ``path`` is the
        pending local path the recording will be pulled to when stopped
        (read via ``get_recording_file()`` immediately after ``start_recording``
        returns ``True``, which is safe since that path is already decided).
        ``{"started": False, "message": "a recording is already active"}``
        if a recording was already in progress.
    """
    from sandroid.services import get_emulator_service

    service = get_emulator_service()
    started = service.start_recording()
    if not started:
        return {"started": False, "message": "a recording is already active"}
    return {"started": True, "path": service.get_recording_file()}


@sandroid_tool(
    name="stop_screen_recording",
    description="Stop the currently active screen recording and pull it from the device.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="capture",
)
def stop_screen_recording() -> dict[str, Any]:
    """Stop the active screen recording and pull the file off the device.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.stop_recording`.
    Checks ``is_recording()`` *before* calling ``stop_recording()``, because
    ``stop_recording()``'s own ``None`` return can't otherwise distinguish
    "nothing was recording" from "the pull from the device failed".

    A pulled file that exists but is exactly 0 bytes is treated as a failure,
    not a success -- found via E2E testing that a race in the underlying
    service (a stop issued shortly after start can have its background
    kill/pull thread's ``join()`` time out, after which the service still
    proceeds to pull the file) can produce an empty ``.webm``. This wrapper
    can't fix that race (it lives entirely inside
    ``EmulatorService.stop_recording()``'s threading), but it can avoid
    reporting a hollow "success".

    Returns:
        ``{"stopped": True, "path": str}`` on success (file confirmed
        non-empty).
        ``{"stopped": False, "message": "no screen recording was active"}``
        if nothing was recording.
        ``{"stopped": False, "message": "recording was active but pulling "
        "the file from the device failed"}`` if a recording was active but
        the pull failed.
        ``{"stopped": False, "message": "..."}`` mentioning an empty file if
        a path was pulled but it has zero bytes.
    """
    from sandroid.services import get_emulator_service

    service = get_emulator_service()
    was_recording = service.is_recording()
    path = service.stop_recording()
    if path is not None:
        if os.path.getsize(path) == 0:
            return {
                "stopped": False,
                "message": (
                    "recording was pulled but the file is empty (0 bytes) -- "
                    "this can happen when stop is called very shortly after "
                    "start; try recording for a few seconds longer"
                ),
            }
        return {"stopped": True, "path": path}
    if not was_recording:
        return {"stopped": False, "message": "no screen recording was active"}
    return {
        "stopped": False,
        "message": "recording was active but pulling the file from the device failed",
    }


@sandroid_tool(
    name="create_snapshot",
    description=(
        "Create a named emulator snapshot of the current device state. "
        "Emulator-only -- this uses the AVD's telnet console and does not "
        "work against a real physical device."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name to give the new snapshot.",
            },
        },
        "required": ["name"],
    },
    risk=RiskTier.REVERSIBLE,
    category="capture",
)
def create_snapshot(name: str) -> dict[str, Any]:
    """Create a named emulator snapshot via the telnet console.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.create_snapshot`.
    Emulator-telnet-console-only -- does **not** work against a real physical
    device.

    Args:
        name: Name to give the new snapshot.

    Returns:
        ``{"created": bool, "name": str}``.
    """
    from sandroid.services import get_emulator_service

    created = get_emulator_service().create_snapshot(name)
    return {"created": created, "name": name}


@sandroid_tool(
    name="load_snapshot",
    description=(
        "Restore the emulator to a previously created named snapshot, "
        "discarding current device state. Emulator-only -- this uses the "
        "AVD's telnet console and does not work against a real physical "
        "device."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name of the snapshot to load.",
            },
        },
        "required": ["name"],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="capture",
    can_remember_choice=False,
)
def load_snapshot(name: str) -> dict[str, Any]:
    """Restore the emulator to a previously created named snapshot.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.load_snapshot`.
    Emulator-telnet-console-only -- does **not** work against a real physical
    device. On the success path, the underlying service call blocks an extra
    ~2 seconds internally to let the emulator settle -- no extra
    sleep/timeout handling is needed here.

    Args:
        name: Name of the snapshot to load.

    Returns:
        ``{"loaded": bool, "name": str}``.
    """
    from sandroid.services import get_emulator_service

    loaded = get_emulator_service().load_snapshot(name)
    return {"loaded": loaded, "name": name}


@sandroid_tool(
    name="list_snapshots",
    description=(
        "List available emulator snapshots. Emulator-only -- this uses the "
        "AVD's telnet console and does not work against a real physical "
        "device."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="capture",
)
def list_snapshots() -> dict[str, Any]:
    """List available emulator snapshots.

    Real integration point:
    :meth:`sandroid.services.emulator_service.EmulatorService.list_snapshots`,
    which returns a list of ``SnapshotInfo`` dataclass instances -- converted
    here into plain dicts for JSON-tool-result serialization.
    Emulator-telnet-console-only -- does **not** work against a real physical
    device.

    Returns:
        ``{"snapshots": [{"name": str, "date": str}, ...], "count": int}``.
    """
    from sandroid.services import get_emulator_service

    snapshots = get_emulator_service().list_snapshots()
    return {
        "snapshots": [{"name": s.name, "date": s.date} for s in snapshots],
        "count": len(snapshots),
    }
