"""Shared helpers for native Sandroid AI tool modules.

Leading-underscore name is deliberate: unlike :mod:`sandroid.ai.tools.app_query`
or :mod:`sandroid.ai.tools.device_query`, this module registers no tools of
its own and has no import-time side effects worth relying on -- it's a plain
helper library other tool modules import from.
"""

from sandroid.ai.errors import ToolExecutionError


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
