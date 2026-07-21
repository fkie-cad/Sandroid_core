"""Persisted per-tool allow/never/ask policy for the AI tool-calling gate.

Every AI tool carries a :class:`~sandroid.ai.tools.registry.RiskTier` (see
:mod:`sandroid.ai.tools.registry`) that has existed since the tool-calling
loop's first commit but was never enforced. This module is the gate: a small
on-disk store of per-tool-name decisions (``"allowed"`` / ``"never"``),
resolved against a tool's risk tier to decide whether a given call may run
immediately, must be refused outright, or needs to ask the user first.

The store persists to ``~/.config/sandroid/ai_tool_permissions.toml`` (TOML,
matching the format ``~/.config/sandroid/sandroid.toml`` already uses --
see :mod:`sandroid.config.loader`), keyed by tool *name*, not by arguments.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Literal

from sandroid.ai.tools.registry import RiskTier

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import tomli_w

logger = logging.getLogger(__name__)

#: The three outcomes `resolve_tool_policy` can return for a pending tool call.
ToolPolicy = Literal["allowed", "never", "ask"]


def _default_permissions_path() -> Path:
    """Default location of the persisted tool-permissions file.

    Follows the same XDG-preferring config-dir snippet already duplicated by
    ``ConfigLoader._preferred_user_config_dir()`` (see
    :mod:`sandroid.config.loader`) and ``SandroidTUI._get_user_config_dir()``
    (see :mod:`sandroid.tui.app`) -- no shared helper exists to import, and
    the codebase already tolerates this small snippet being duplicated
    rather than factored out.

    Returns:
        ``~/.config/sandroid/ai_tool_permissions.toml``, or under
        ``$XDG_CONFIG_HOME/sandroid`` if that environment variable is set.
    """
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        config_dir = Path(xdg_config_home) / "sandroid"
    else:
        config_dir = Path.home() / ".config" / "sandroid"
    return config_dir / "ai_tool_permissions.toml"


class ToolPermissionStore:
    """Loads/saves the persisted allow/never sets of tool names.

    Thread safety: mirrors :class:`~sandroid.ai.tools.registry.ToolRegistry`
    -- no locking, low-contention assumption (decisions are made one at a
    time from the UI thread's approval flow).
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the store, loading any existing file.

        Args:
            path: Explicit path to the permissions TOML file. Defaults to
                the real config-dir location (see
                :func:`_default_permissions_path`); tests should pass a
                temp path instead.
        """
        self._path = path if path is not None else _default_permissions_path()
        self._allowed: set[str] = set()
        self._never: set[str] = set()
        self._load()

    def _load(self) -> None:
        """Load ``{"allowed": [...], "never": [...]}`` from disk, if present.

        A missing file just starts empty (first run). A present-but-unreadable
        or corrupt file is logged and also starts empty, rather than crashing
        -- the gate must never take down the chat feature over a bad on-disk
        state file.
        """
        if not self._path.exists():
            return
        try:
            with open(self._path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            logger.warning(
                "Failed to load tool permissions from %s: %s", self._path, exc
            )
            return
        self._allowed = set(data.get("allowed", []))
        self._never = set(data.get("never", []))

    def _save(self) -> None:
        """Re-write the permissions file from the current in-memory sets.

        Wrapped in ``try/except OSError`` that logs and continues on
        failure -- matching ``tui/app.py``'s first-run marker file precedent
        (plain write, log and continue), the only atomic-write/locking
        precedent in this codebase for a small state file like this one.
        """
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "wb") as f:
                tomli_w.dump(
                    {
                        "allowed": sorted(self._allowed),
                        "never": sorted(self._never),
                    },
                    f,
                )
        except OSError as exc:
            logger.warning("Failed to save tool permissions to %s: %s", self._path, exc)

    def is_allowed(self, name: str) -> bool:
        """Return whether ``name`` has a persisted "allow always" decision."""
        return name in self._allowed

    def is_never(self, name: str) -> bool:
        """Return whether ``name`` has a persisted "never" decision."""
        return name in self._never

    def mark_allowed(self, name: str) -> None:
        """Persist an "allow always" decision for ``name``.

        Removes any conflicting "never" entry for the same name -- a tool
        can only ever have one current decision -- and immediately re-writes
        the file.
        """
        self._never.discard(name)
        self._allowed.add(name)
        self._save()

    def mark_never(self, name: str) -> None:
        """Persist a "never" decision for ``name``.

        Removes any conflicting "allowed" entry for the same name and
        immediately re-writes the file.
        """
        self._allowed.discard(name)
        self._never.add(name)
        self._save()


_tool_permission_store: ToolPermissionStore | None = None


def get_tool_permission_store() -> ToolPermissionStore:
    """Get or create the :class:`ToolPermissionStore` singleton.

    Returns:
        The process-wide store, backed by the real config-dir file (same
        shape as :func:`sandroid.ai.tools.registry.get_tool_registry`).
    """
    global _tool_permission_store
    if _tool_permission_store is None:
        _tool_permission_store = ToolPermissionStore()
    return _tool_permission_store


def resolve_tool_policy(
    name: str, risk: RiskTier, can_remember_choice: bool = True
) -> ToolPolicy:
    """Resolve whether a pending tool call may run, must be refused, or asks.

    Resolution order (each step is final -- later steps are only reached if
    an earlier one doesn't already decide):

    1. ``risk == RiskTier.NOT_EXPOSED`` always returns ``"never"``, regardless
       of anything in the store. Defense in depth: these tools shouldn't be
       schema-listed for the model at all, but the gate itself must never
       blindly trust that invariant.
    2. ``can_remember_choice is False`` always returns ``"ask"``, **without
       even consulting the store**. A stale "allowed" entry for this tool
       name (written before this flag existed on it, or by a future bug)
       must never silently bypass re-asking for a tool whose risk lives in
       its *arguments* rather than its identity.
    3. Otherwise, consult the store: an explicit ``is_never``/``is_allowed``
       entry wins (checked in that order, so a corrupted file that somehow
       has a name in both sets fails closed); absent from the store, fall
       back to ``"allowed"`` for ``RiskTier.READ_ONLY`` or ``"ask"`` for
       anything else.

    Args:
        name: Tool name to resolve a policy for.
        risk: The tool's :class:`~sandroid.ai.tools.registry.RiskTier`.
        can_remember_choice: Whether this tool's decisions may be persisted
            and reused, see
            :attr:`~sandroid.ai.tools.registry.ToolSpec.can_remember_choice`.

    Returns:
        ``"allowed"`` to run without prompting, ``"never"`` to refuse
        outright, or ``"ask"`` to prompt the user before running.
    """
    if risk == RiskTier.NOT_EXPOSED:
        return "never"
    if not can_remember_choice:
        return "ask"

    store = get_tool_permission_store()
    if store.is_never(name):
        return "never"
    if store.is_allowed(name):
        return "allowed"
    return "allowed" if risk == RiskTier.READ_ONLY else "ask"
