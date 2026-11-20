"""Shared helpers for native Sandroid AI tool modules.

Leading-underscore name is deliberate: unlike :mod:`sandroid.ai.tools.app_query`
or :mod:`sandroid.ai.tools.device_query`, this module registers no tools of
its own and has no import-time side effects worth relying on -- it's a plain
helper library other tool modules import from.
"""

from sandroid.ai.errors import ToolExecutionError
from sandroid.core.adb_utils import PACKAGE_NAME_RE, is_valid_package_name

# Re-exported: the parser lives in the UI-shared service layer.
from sandroid.services.app_info_service import parse_pm_path_output

__all__ = [
    "PACKAGE_NAME_PARAM",
    "parse_pm_path_output",
    "resolve_package_name",
    "start_refusal",
    "validate_package_name",
]

#: Android's real package-identifier format: two or more dot-separated
#: segments, each segment starting with a letter and containing only
#: letters/digits/underscore (mirrors the JLS package-name grammar Android
#: itself enforces for ``AndroidManifest.xml``'s ``package`` attribute).
#: Deliberately stricter than "no shell metacharacters" -- a single shared
#: allowlist regex is validated once, at the point of entry, rather than
#: trying to quote a package_name correctly for every different embedding
#: context it might later reach (shell=True command string, non-shell argv
#: list, plain Path operation) -- see file_transfer.py's module docstring
#: for the review finding that motivated this.
#: (Defined in :mod:`sandroid.core.adb_utils` so core sinks share it.)
_PACKAGE_NAME_RE = PACKAGE_NAME_RE

#: Shared JSON Schema fragment for an optional ``package_name`` tool
#: parameter, used by every tool that accepts one (see
#: :func:`resolve_package_name` for the matching fallback behavior).
PACKAGE_NAME_PARAM = {
    "type": "string",
    "description": (
        "Fully qualified package name (e.g. 'com.example.app'). Omit to use "
        "the analyst's current spotlight app."
    ),
}


def resolve_package_name(package_name: str | None) -> str:
    """Resolve a tool's optional ``package_name`` argument to a concrete value.

    Every tool that accepts an optional ``package_name`` argument (so the
    analyst can omit it and mean "the app I'm currently looking at") should
    route through this helper rather than reimplementing the fallback.

    Args:
        package_name: Package name explicitly passed to a tool call, or
            ``None``/empty string if the caller wants the current spotlight
            app used instead.

    Returns:
        A concrete, non-empty package name.

    Raises:
        ToolExecutionError: *package_name* was not given and no spotlight
            app is currently selected.
    """
    if package_name:
        return validate_package_name(package_name)

    # Lazy import (matches the convention in ai/context.py's `_describe_*`
    # helpers): keeps this module import-cheap and lets tests monkeypatch
    # `get_spotlight_service` on the module it actually lives on.
    from sandroid.services import get_spotlight_service

    effective = get_spotlight_service().get_effective_package()
    if effective:
        # Validated too: the spotlight package can come from a restored
        # session/config, and every caller embeds it in an adb command.
        return validate_package_name(effective)

    raise ToolExecutionError(
        "no package_name given and no spotlight app is currently selected"
    )


def validate_package_name(name: str) -> str:
    """Validate a package_name against Android's real package-identifier format.

    This is a hardening measure distinct from ``shlex.quote()``: a single
    caller-supplied ``package_name`` string can reach a ``shell=True``
    command string, a non-shell argv-list ``subprocess.run([...])`` call,
    *and* a plain Python ``Path``/filesystem operation, all from one call
    site (see :mod:`sandroid.ai.tools.file_transfer`'s module docstring).
    ``shlex.quote()`` only protects the first of those -- it does nothing
    for (and can actively corrupt) the other two. Validating the string
    against a safe format up front, before it reaches *any* of those
    contexts, is the fix that actually covers all three.

    Args:
        name: The package name to validate, e.g. ``'com.example.app'``.

    Returns:
        *name*, unchanged, if it matches Android's package-identifier
        format.

    Raises:
        ToolExecutionError: *name* does not match Android's package-name
            format (two or more dot-separated segments, each starting with
            a letter and containing only letters/digits/underscore).
    """
    if not is_valid_package_name(name):
        raise ToolExecutionError(
            f"invalid package_name {name!r}: must match Android's package "
            "identifier format (e.g. 'com.example.app')"
        )
    return name


#: ``app_start`` refusal reasons (``StartResult.reason`` /
#: ``AppStartError.reason``) -> ``(tool error code, words, retryable)``.
START_REFUSALS: dict[str, tuple[str, str, bool]] = {
    "needs_consent": (
        "needs_confirmation",
        "needs the analyst's confirmation in the Sandroid TUI (it restarts "
        "the Android framework, every running app stops); ask the analyst — "
        "it can't be applied without the dialog",
        False,
    ),
    "declined": (
        "declined_by_analyst",
        "the analyst declined; don't retry unless asked",
        False,
    ),
    "busy": (
        "busy",
        "another app start is running; wait until it has finished "
        "(get_spotlight_app shows it) before trying once more",
        True,
    ),
}


def start_refusal(reason: str | None, package: str, detail: str | None = None):
    """The ``ToolError`` for an app start refused with *reason*, or None.

    *reason* is ``app_start``'s refusal reason (``needs_consent``,
    ``declined``, ``busy``); any other value (None included) is an ordinary
    failure the tool reports as before. *detail* is app_start's own message.
    """
    entry = START_REFUSALS.get(reason or "")
    if entry is None:
        return None
    from sandroid.ai.tools.registry import ToolError

    code, words, retryable = entry
    if reason == "needs_consent":
        # app_start's own text tells API callers to "pass fresh=True"; the
        # AI tools never turn fresh into consent, so it would only mislead.
        detail = None
    return ToolError(
        code,
        f"{package} not started: {words}",
        retryable=retryable,
        details={"detail": detail} if detail else None,
    )
