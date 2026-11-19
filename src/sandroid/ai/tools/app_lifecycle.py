"""Real, ADB-backed app lifecycle tools for the Sandroid AI chat.

Importing this module registers all three tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All tools in this module share
``category="app_lifecycle"``:

- ``install_apk`` -- ``RiskTier.CONSEQUENTIAL``, ``can_remember_choice=False``.
  Installing an arbitrary host APK onto the device is exactly the kind of
  argument-dependent risk that rule exists for.
- ``uninstall_apk`` -- ``RiskTier.CONSEQUENTIAL``, ``can_remember_choice=False``.
  Corrected during review to match ``install_apk``'s own stated risk rule --
  *which* package gets removed is exactly the argument-dependent risk an
  "allow always" choice must not paper over.
- ``launch_app`` -- ``RiskTier.REVERSIBLE``, ``can_remember_choice=True``.
  Launching an app is easily undone (force-stop/relaunch), so persisting an
  "allow always" choice is fine.

``package_name`` is a required argument on all three tools here -- unlike
the read-only tools in :mod:`sandroid.ai.tools.app_query`, there is no
spotlight-app fallback: silently defaulting the target of a destructive
action (install/uninstall/launch) would be the wrong kind of implicit.

Host-path confinement: ``install_apk``'s ``apk_path`` argument is resolved
through :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path`
before it ever reaches ADB -- installing an APK uploads a host file's bytes
to the device, the same threat class ``push_path`` (see
:mod:`sandroid.ai.tools.file_transfer`) guards, so it is confined
identically (a bare filename resolves against the AI data-share folder;
anything else must fall within an allowed host root -- see
``list_allowed_host_paths`` in :mod:`sandroid.ai.tools.host_files`).

Injection hardening: :meth:`sandroid.core.adb.Adb.uninstall_apk`,
``.launch_app`` and ``.force_stop`` quote ``package_name``/``activity_name``
for both the device and the host shell themselves
(:func:`sandroid.core.adb_utils.device_shell_arg`), so the tools pass the raw
values. Every tool accepting a ``package_name`` here additionally validates
it against Android's package-identifier format via
:func:`sandroid.ai.tools._shared.validate_package_name` before it is used
anywhere (it also reaches non-shell argv lists and host paths).

**``install_apk``'s ``apk_path`` is deliberately never ``shlex.quote()``-d**
(review-caught bug, fixed here): :meth:`sandroid.core.adb.Adb.install_apk`
internally both (a) sends a shell command built via unquoted f-string
interpolation *and* (b) calls ``extract_package_name_with_aapt`` with the
very same string as a literal ``argv`` element in a non-shell
``subprocess.run([...])`` call. Quoting ``apk_path`` would make (a) safe but
would corrupt (b) -- the literal quote characters ``shlex.quote()`` adds
become part of the path ``aapt`` is asked to open, so a quoted
space-containing filename makes ``aapt`` silently fail to find the real
file, and ``install_apk`` returns ``package_name: None`` even though the
install itself succeeded. Instead, :func:`_reject_shell_metacharacters`
validates the *resolved* path (already confined to an allowed host root, so
its directory portion is never attacker-chosen) contains none of the
characters a shell would treat specially, then the raw, unquoted string is
passed on -- this keeps both of ``Adb.install_apk``'s internal calls
correct, since there is nothing hazardous left in the string for either of
them to mishandle.
"""

from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._host_paths import resolve_confined_host_path
from sandroid.ai.tools._shared import validate_package_name
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb
from sandroid.core.exceptions import APKInstallError

#: Shell metacharacters ``install_apk`` rejects in a resolved ``apk_path``
#: before passing it on, unquoted, to :meth:`sandroid.core.adb.Adb.install_apk`
#: (see the module docstring for why that call site cannot ``shlex.quote()``
#: the path). Deliberately does *not* reject spaces -- a space-containing
#: filename is the exact case this fix targets keeping working end to end.
_SHELL_METACHARACTERS = frozenset(";`$|&#\n\r")


def _reject_shell_metacharacters(path_str: str) -> None:
    """Raise if *path_str* contains a character a shell would treat specially.

    Args:
        path_str: A resolved, confined host path (see
            :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path`)
            about to be passed on, unquoted, to ``Adb.install_apk``.

    Raises:
        ToolExecutionError: *path_str* contains one or more characters from
            :data:`_SHELL_METACHARACTERS`.
    """
    found = sorted({char for char in path_str if char in _SHELL_METACHARACTERS})
    if found:
        raise ToolExecutionError(
            f"apk_path contains disallowed character(s) {''.join(found)!r}"
        )


@sandroid_tool(
    name="install_apk",
    description=(
        "Install an APK file from the host filesystem onto the device. The "
        "path must resolve within an allowed host directory -- a bare "
        "filename is resolved against the AI data-share folder; call "
        "list_allowed_host_paths to see what else is reachable."
    ),
    parameters={
        "type": "object",
        "properties": {
            "apk_path": {
                "type": "string",
                "description": (
                    "Path to the APK file to install. A bare filename (e.g. "
                    "'app.apk') is resolved against the AI data-share "
                    "folder; an absolute path must fall within an allowed "
                    "host root."
                ),
            },
        },
        "required": ["apk_path"],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="app_lifecycle",
    can_remember_choice=False,
)
def install_apk(apk_path: str) -> dict[str, Any]:
    """Install a host APK file onto the device.

    Real integration point: :meth:`sandroid.core.adb.Adb.install_apk`.
    *apk_path* is resolved through
    :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path` before
    it ever reaches ADB, then validated (not quoted -- see the module
    docstring's ``install_apk`` section for why) via
    :func:`_reject_shell_metacharacters` before its raw ``str()`` form is
    passed on.

    Args:
        apk_path: Path to the APK file on the host, resolved through the
            confined host-path allowlist.

    Returns:
        ``{"installed": True, "package_name": str | None}`` -- ``package_name``
        can be ``None`` if ``aapt`` could not determine it (see
        ``Adb.install_apk``'s own docstring).

    Raises:
        ToolExecutionError: *apk_path* falls outside every allowed host
            directory (raised by ``resolve_confined_host_path``), the
            resolved path contains a shell metacharacter (raised by
            :func:`_reject_shell_metacharacters`), or the installation
            itself failed (wraps ``APKInstallError``).
    """
    resolved_path = resolve_confined_host_path(apk_path)
    resolved_str = str(resolved_path)
    _reject_shell_metacharacters(resolved_str)
    try:
        package_name = Adb.install_apk(resolved_str)
    except APKInstallError as exc:
        raise ToolExecutionError(str(exc)) from exc
    return {"installed": True, "package_name": package_name}


@sandroid_tool(
    name="uninstall_apk",
    description=(
        "Uninstall a package from the device by its package name. "
        "Removes the app and its data; a no-op (reported as success) if "
        "the package is not installed. Requires package_name explicitly -- "
        "there is no spotlight-app fallback for this destructive action."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": (
                    "Fully qualified package name to uninstall (e.g. "
                    "'com.example.app'). Required -- unlike the read-only "
                    "app-query tools, there is no spotlight-app fallback "
                    "for a destructive action like this."
                ),
            },
        },
        "required": ["package_name"],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="app_lifecycle",
    can_remember_choice=False,
)
def uninstall_apk(package_name: str) -> dict[str, Any]:
    """Uninstall a package from the device.

    Real integration point: :meth:`sandroid.core.adb.Adb.uninstall_apk`.
    ``package_name`` is validated via
    :func:`sandroid.ai.tools._shared.validate_package_name`; the core
    function quotes it for the device and host shell.

    ``can_remember_choice=False``: *which* package gets removed is exactly
    the argument-dependent risk that rule exists for (matching
    ``install_apk``'s own stated risk rule -- corrected during review to be
    consistent with it).

    Args:
        package_name: Fully qualified package name to uninstall.

    Returns:
        ``{"uninstalled": bool, "package_name": str}``. ``uninstalled`` is
        ``True`` if the package was removed or was already not installed
        (matches ``Adb.uninstall_apk``'s own success semantics), ``False`` if
        an error occurred.

    Raises:
        ToolExecutionError: *package_name* does not match Android's package
            identifier format.
    """
    package_name = validate_package_name(package_name)
    uninstalled = Adb.uninstall_apk(package_name)
    return {"uninstalled": uninstalled, "package_name": package_name}


@sandroid_tool(
    name="launch_app",
    description=(
        "Launch an app on the device. Uses the given activity if provided, "
        "otherwise falls back to the app's default launcher intent. A first "
        "launch may run a pre-start step first (e.g. an identity profile "
        "with an Android framework restart, after the analyst confirms); "
        "that can take minutes."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": (
                    "Fully qualified package name to launch (e.g. "
                    "'com.example.app'). Required -- unlike the read-only "
                    "app-query tools, there is no spotlight-app fallback."
                ),
            },
            "activity_name": {
                "type": "string",
                "description": (
                    "Optional launchable activity (short, e.g. "
                    "'.MainActivity', or fully-qualified). Omit to launch "
                    "via the app's default launcher intent instead."
                ),
            },
        },
        "required": ["package_name"],
    },
    risk=RiskTier.REVERSIBLE,
    category="app_lifecycle",
    can_remember_choice=True,
)
def launch_app(package_name: str, activity_name: str | None = None) -> dict[str, Any]:
    """Launch an app on the device, optionally targeting a specific activity.

    Real integration point: :meth:`sandroid.core.adb.Adb.launch_app`.
    ``package_name`` is validated via
    :func:`sandroid.ai.tools._shared.validate_package_name`. The core
    function quotes ``package_name``/``activity_name`` for the device and
    host shell.

    A first launch (the app is not running) runs the pre-spawn hooks first
    (:func:`sandroid.services.app_start.prepare_launch`, e.g. the identity
    profile; one that stops every app asks the analyst, and the step may
    take minutes). With a pre-start step to run: busy, an adb error, a
    failed or declined step mean not launched. Without one the launch is as
    it always was (no lifecycle lock, no liveness probe).

    Args:
        package_name: Fully qualified package name to launch.
        activity_name: Optional launchable activity (short, e.g.
            ``.MainActivity``, or fully-qualified). ``None`` launches via the
            app's default launcher intent instead.

    Returns:
        ``{"launched": bool, "package_name": str, "activity_name": str | None,
        "message": str}``.

    Raises:
        ToolExecutionError: *package_name* does not match Android's package
            identifier format.
    """
    from sandroid.services.app_start import AppStartError, prepare_launch

    package_name = validate_package_name(package_name)
    try:
        prepare_launch(package_name, package_name)
        # Adb.launch_app quotes both values for the device and host shell.
        success, message = Adb.launch_app(package_name, activity_name or None)
    except AppStartError as exc:
        success, message = False, str(exc)
    return {
        "launched": success,
        "package_name": package_name,
        "activity_name": activity_name,
        "message": message,
    }
