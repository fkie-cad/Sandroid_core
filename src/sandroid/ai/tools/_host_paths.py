"""Host filesystem path confinement for the AI's file-touching tools.

Leading-underscore name is deliberate, mirroring
:mod:`sandroid.ai.tools._shared`: this module registers no tools of its own
and has no import-time side effects worth relying on -- it's the one helper
every host-touching tool (``host_files.py``, ``file_transfer.py``,
``app_lifecycle.py``'s ``install_apk``) depends on.

No confinement of any kind existed before this module: the destination for
host-writing tools was always tool-computed from config, and
``FileExtractionService.pull_file``'s host destination had zero validation.
The design (settled with the user, see the plan's "Host filesystem access
design" section) is hard confinement to an explicit allowlist of roots --
anything outside is always rejected, with no per-call approval escape hatch
(a dynamic per-call risk mechanism the tool registry doesn't have today).
"""

from pathlib import Path
from typing import Any

from sandroid.ai.errors import ToolExecutionError


def _allowed_roots() -> list[dict[str, Any]]:
    """Every host root an AI file tool may resolve into, with availability.

    Recomputed on every call rather than cached: the session/device can
    change mid-chat (e.g. via ``ConfigurationService.switch_device``), so a
    cached list could go stale and either wrongly permit a path that
    belonged to a previous session or wrongly reject one that belongs to the
    new one.

    Each root's computation is wrapped in its own ``try``/``except`` so one
    bad config entry (an unreadable ``ai.extra_host_paths`` entry, a session
    that hasn't started yet, ...) can't crash every other root -- and
    therefore every host-file tool -- along with it.

    Returns:
        A list of ``{"label": str, "path": Path | None, "available": bool,
        "reason": str | None}`` dicts, in this order: ``ai_data_share``
        (always attempted first -- see :func:`resolve_confined_host_path`,
        which anchors bare relative paths against it), ``session_results``,
        ``session_raw_results``, ``cache`` (only appended if configured),
        then one ``extra`` entry per configured
        ``ai.extra_host_paths`` entry. When a root's computation raised,
        that entry has ``path=None``, ``available=False``, and ``reason``
        set to ``str(exc)``.
    """
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import get_configuration_service

    roots: list[dict[str, Any]] = []

    ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
    try:
        share = (
            getattr(ai_cfg, "data_share_path", None)
            or Path("~/Sandroid/ai_share/").expanduser()
        )
        # Always available, unlike the session-scoped dirs below.
        share.mkdir(parents=True, exist_ok=True)
        roots.append(
            {
                "label": "ai_data_share",
                "path": share.resolve(),
                "available": True,
                "reason": None,
            }
        )
    except Exception as exc:
        roots.append(
            {
                "label": "ai_data_share",
                "path": None,
                "available": False,
                "reason": str(exc),
            }
        )

    cfg_service = get_configuration_service()
    for label, getter in (
        ("session_results", cfg_service.get_results_path),
        ("session_raw_results", cfg_service.get_raw_results_path),
    ):
        try:
            p = Path(getter()).expanduser().resolve()
            roots.append(
                {
                    "label": label,
                    "path": p,
                    "available": p.exists(),
                    "reason": None if p.exists() else "no analysis session started yet",
                }
            )
        except Exception as exc:
            roots.append(
                {"label": label, "path": None, "available": False, "reason": str(exc)}
            )

    try:
        paths_cfg = getattr(getattr(Toolbox, "config", None), "paths", None)
        cache_path = getattr(paths_cfg, "cache_path", None)
        if cache_path:
            roots.append(
                {
                    "label": "cache",
                    "path": Path(cache_path).expanduser().resolve(),
                    "available": True,
                    "reason": None,
                }
            )
    except Exception as exc:
        roots.append(
            {"label": "cache", "path": None, "available": False, "reason": str(exc)}
        )

    for extra in getattr(ai_cfg, "extra_host_paths", None) or []:
        try:
            p = Path(extra).expanduser().resolve()
            roots.append(
                {
                    "label": "extra",
                    "path": p,
                    "available": p.exists(),
                    "reason": None if p.exists() else "configured but does not exist",
                }
            )
        except Exception as exc:
            roots.append(
                {"label": "extra", "path": None, "available": False, "reason": str(exc)}
            )

    return roots


def resolve_confined_host_path(user_path: str) -> Path:
    """Resolve *user_path* against the allowed roots, or raise.

    A bare relative path is anchored against ``ai_data_share`` (the
    always-on default), not the session results dir -- the latter may not
    exist yet if no analysis session has been started. Symlinks are fully
    resolved (``Path.resolve()``) before the allowlist check, so a symlink
    inside an allowed root that points outside it is correctly rejected
    rather than let through on the strength of its containing directory.

    Args:
        user_path: A path as supplied by the model -- either absolute, or
            relative to ``ai_data_share``.

    Returns:
        The resolved, confined, absolute :class:`~pathlib.Path`.

    Raises:
        ToolExecutionError: *user_path* is empty, no host root is currently
            available at all, or the resolved path falls outside every
            available root.
    """
    if not user_path:
        raise ToolExecutionError("path must not be empty")

    roots = _allowed_roots()
    available = [r for r in roots if r["available"]]
    if not available:
        raise ToolExecutionError(
            "no host paths are currently accessible to the AI -- "
            "call list_allowed_host_paths for details"
        )

    candidate = Path(user_path).expanduser()
    if not candidate.is_absolute():
        anchor = next(
            (r["path"] for r in available if r["label"] == "ai_data_share"),
            available[0]["path"],
        )
        candidate = anchor / candidate
    resolved = candidate.resolve(strict=False)

    for root in available:
        if resolved == root["path"] or resolved.is_relative_to(root["path"]):
            return resolved

    listing = ", ".join(f"{r['label']}={r['path']}" for r in available)
    raise ToolExecutionError(
        f"path {user_path!r} is outside every allowed host directory "
        f"({listing}) -- refusing to access it. Call list_allowed_host_paths "
        "to see what's currently reachable, or add a root to ai.extra_host_paths."
    )
