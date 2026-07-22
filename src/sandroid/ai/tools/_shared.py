"""Shared helpers for native Sandroid AI tool modules.

Leading-underscore name is deliberate: unlike :mod:`sandroid.ai.tools.app_query`
or :mod:`sandroid.ai.tools.device_query`, this module registers no tools of
its own and has no import-time side effects worth relying on -- it's a plain
helper library other tool modules import from.
"""

import re

from sandroid.ai.errors import ToolExecutionError

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
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

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


def parse_pm_path_output(stdout: str) -> list[str]:
    """Parse ``pm path <pkg>`` output into a list of on-device APK paths.

    Real output is one ``package:/absolute/path/to/*.apk`` line per APK
    (``base.apk`` plus any installed splits) -- verified against a live
    emulator across several multi-split apps (Microsoft Edge, Snapchat,
    Telegram, Uber all install ``base.apk`` + several ``split_*.apk``).

    Args:
        stdout: Raw stdout from ``adb shell pm path <pkg>``.

    Returns:
        A list of on-device APK paths, in the order ``pm path`` printed
        them. Empty if *stdout* has no ``package:`` lines (e.g. the package
        is not installed).
    """
    paths = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:") :])
    return paths


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
        return package_name

    # Lazy import (matches the convention in ai/context.py's `_describe_*`
    # helpers): keeps this module import-cheap and lets tests monkeypatch
    # `get_spotlight_service` on the module it actually lives on.
    from sandroid.services import get_spotlight_service

    effective = get_spotlight_service().get_effective_package()
    if effective:
        return effective

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
    if not name or not _PACKAGE_NAME_RE.match(name):
        raise ToolExecutionError(
            f"invalid package_name {name!r}: must match Android's package "
            "identifier format (e.g. 'com.example.app')"
        )
    return name
