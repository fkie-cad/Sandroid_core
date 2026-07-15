"""Dexray (dexray-intercept) configuration service for Sandroid.

Holds the *armed* hook + AppProfiler configuration that the TUI "DEXray" tab
collects, so the panel can drive a ``MalwareMonitor`` start **without** the
legacy interactive (Rich / Textual-modal) configuration prompt.

This is an additive bridge. When the panel arms a configuration and marks it
``configured_from_panel``, ``MalwareMonitor.start_monitoring`` consults this
service (via ``_apply_panel_config_if_present``) and skips the interactive
prompt. The flag is **one-shot** — cleared the instant the monitor consumes it
— so a terminal/headless ``m``/``k`` invocation always falls back to the
existing interactive flow. Nothing in the interactive path is removed.

Thread safety:
    The panel mutates configuration on the Textual UI thread; the command
    reads it on a worker thread (``MalwareMonitorCommand`` runs with
    ``is_blocking_io=True``). All reads/writes are guarded by an ``RLock``,
    and ``consume_panel_config`` returns **copies** so a live monitoring run
    owns its own snapshot and later panel toggles cannot mutate it.

Usage:
    from sandroid.services import get_dexray_config_service

    svc = get_dexray_config_service()

    # Panel (UI thread): render + toggle.
    cfg = svc.hook_configuration            # a HookConfiguration
    cfg.toggle_group("network")
    svc.toggle_profiler_setting("enable_fritap")
    svc.mark_configured()                   # arm before Start

    # Command (worker thread): consume once, then fall back if None.
    armed = svc.consume_panel_config()
    if armed is not None:
        hook_config, profiler_settings = armed
"""

import logging
import threading
from typing import Any

from sandroid.analysis.hook_config import HookConfiguration

logger = logging.getLogger(__name__)

# Canonical AppProfiler settings + defaults. Mirrors
# ``MalwareMonitor.profiler_settings`` and ``AppProfilerConfigUI`` so a config
# armed here is shape-compatible with what the interactive path produces.
_DEFAULT_PROFILER_SETTINGS: dict[str, Any] = {
    "enable_stacktrace": False,
    "deactivate_unlink": False,
    "enable_fritap": False,
    "fritap_output_dir": "fritap_output",
    "custom_scripts": [],
}


class DexrayConfigService:
    """Process-wide store for the DEXray tab's armed dexray-intercept config.

    Wraps a :class:`HookConfiguration` (the single source of truth for hook
    group/enable state, reused for its thread-safe group toggle logic) plus the
    AppProfiler ``profiler_settings`` dict and a one-shot "configured from
    panel" intent flag.
    """

    def __init__(self) -> None:
        """Initialise with default hooks + settings and the flag cleared."""
        self._lock = threading.RLock()
        self._hooks = HookConfiguration()
        self._profiler_settings: dict[str, Any] = self._fresh_profiler_settings()
        self._configured_from_panel = False

    @staticmethod
    def _fresh_profiler_settings() -> dict[str, Any]:
        """Return a fresh defaults dict (with its own ``custom_scripts`` list)."""
        settings = dict(_DEFAULT_PROFILER_SETTINGS)
        settings["custom_scripts"] = []
        return settings

    # =========================================================================
    # Panel-facing API (Textual UI thread)
    # =========================================================================

    @property
    def hook_configuration(self) -> HookConfiguration:
        """The wrapped :class:`HookConfiguration` (toggle + render source).

        Returned by reference on purpose: the panel reads ``get_group_status``/
        ``is_group_enabled``/``get_config`` and mutates via ``toggle_group``/
        ``toggle`` — all of which are internally lock-protected.
        """
        return self._hooks

    def get_profiler_setting(self, key: str) -> Any:
        """Return a single AppProfiler setting value (or None if unknown)."""
        with self._lock:
            return self._profiler_settings.get(key)

    def set_profiler_setting(self, key: str, value: Any) -> None:
        """Set a single AppProfiler setting. Unknown keys are ignored."""
        with self._lock:
            if key in self._profiler_settings:
                self._profiler_settings[key] = value
            else:
                logger.warning("Unknown dexray profiler setting: %s", key)

    def toggle_profiler_setting(self, key: str) -> bool:
        """Toggle a boolean AppProfiler setting and return its new value.

        Returns False (and logs) if the key is unknown or non-boolean.
        """
        with self._lock:
            current = self._profiler_settings.get(key)
            if not isinstance(current, bool):
                logger.warning("Cannot toggle non-boolean dexray setting: %s", key)
                return False
            self._profiler_settings[key] = not current
            return self._profiler_settings[key]

    def mark_configured(self) -> None:
        """Arm the panel config so the next monitor start consumes it.

        One-shot: cleared by :meth:`consume_panel_config`.
        """
        with self._lock:
            self._configured_from_panel = True

    def reset(self) -> None:
        """Reset hooks + settings to defaults and clear the armed flag."""
        with self._lock:
            self._hooks.reset_to_defaults()
            self._profiler_settings = self._fresh_profiler_settings()
            self._configured_from_panel = False
        logger.debug("DexrayConfigService reset to defaults")

    # =========================================================================
    # Command-facing API (worker thread)
    # =========================================================================

    def is_configured_from_panel(self) -> bool:
        """Whether a panel config is currently armed (does not consume it)."""
        with self._lock:
            return self._configured_from_panel

    def consume_panel_config(self) -> tuple[dict[str, bool], dict[str, Any]] | None:
        """Atomically read the armed config and clear the flag (one-shot).

        Returns:
            ``(hook_config_copy, profiler_settings_copy)`` if a panel config was
            armed, otherwise ``None``. The returned dicts are independent copies
            (including a fresh ``custom_scripts`` list) so the caller owns its
            own snapshot for the lifetime of the run.
        """
        with self._lock:
            if not self._configured_from_panel:
                return None
            self._configured_from_panel = False  # one-shot
            return self._hooks.get_config(), self._snapshot_profiler_settings()

    def _snapshot_profiler_settings(self) -> dict[str, Any]:
        """Return a copy of profiler settings with an independent list."""
        snapshot = dict(self._profiler_settings)
        snapshot["custom_scripts"] = list(self._profiler_settings.get("custom_scripts", []))
        return snapshot

    def get_state_dict(self) -> dict[str, Any]:
        """Return a debug snapshot of the service state."""
        with self._lock:
            return {
                "enabled_hooks": self._hooks.get_enabled_count(),
                "group_status": self._hooks.get_group_status(),
                "profiler_settings": self._snapshot_profiler_settings(),
                "configured_from_panel": self._configured_from_panel,
            }


__all__ = [
    "DexrayConfigService",
]
