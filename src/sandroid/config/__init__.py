"""Configuration management for Sandroid."""

from pathlib import Path
from typing import Any

from .loader import ConfigLoader
from .schema import SandroidConfig

# Cached config instance for singleton access
_config_instance: SandroidConfig | None = None
# Explicit file the live config was loaded from (``sandroid --config FILE``).
_config_source: Path | None = None


def get_config() -> SandroidConfig:
    """Get the Sandroid configuration singleton.

    Loads config from sandroid.toml (or defaults) on first call,
    then returns the cached instance on subsequent calls.

    Returns:
        SandroidConfig instance with all settings
    """
    global _config_instance
    if _config_instance is None:
        loader = ConfigLoader()
        try:
            _config_instance = loader.load()
        except Exception:
            # Fall back to defaults if config loading fails
            _config_instance = SandroidConfig()
    return _config_instance


def set_config(
    config: SandroidConfig | None, source_file: str | Path | None = None
) -> None:
    """Install ``config`` as the process-wide singleton returned by get_config().

    The CLI calls this after loading the config with ``--config`` /
    ``--environment`` / CLI overrides, so code that uses ``get_config()``
    (run history, run bundles, ...) sees the same settings, e.g. the same
    ``paths.results_path``.

    Args:
        config: The config to install (``None`` clears the singleton).
        source_file: The explicit ``--config`` file the config was loaded
            from, if any. ``update_config()`` persists changes there instead
            of to an auto-discovered file.
    """
    global _config_instance, _config_source
    _config_instance = config
    _config_source = Path(source_file).expanduser() if source_file else None


def get_config_source() -> Path | None:
    """Return the explicit config file the live config came from (or None)."""
    return _config_source


def reset_config_cache() -> None:
    """Reset the cached config instance.

    Forces a fresh load from the auto-discovered files on the next
    get_config() call. Note that this DROPS any ``--config`` /
    ``--environment`` / CLI overrides the CLI installed via set_config(), so
    runtime code that changes settings should use update_config() instead.
    """
    global _config_instance, _config_source
    _config_instance = None
    _config_source = None


class ConfigUpdateError(ValueError):
    """Raised by update_config() when the requested changes are invalid."""


def update_config(
    updates: dict[str, Any], persist: bool = True
) -> tuple[SandroidConfig, Path | None]:
    """Validate and apply dotted-key changes to the live config, then persist.

    Unlike re-loading the config from disk, this keeps everything the live
    singleton was built from (``--config``, ``--environment``, CLI flag
    overrides) intact: the changes are validated against the *whole* live
    config, applied to it in place, and only the changed keys are written
    to the config file actually in use (the ``--config`` file if one was
    given, otherwise the first discovered config file, otherwise the user
    config file). Nothing else -- no defaults, no CLI overrides, no
    environment values -- is copied into the file.

    Args:
        updates: Mapping of ``"section.field"`` (or top-level ``"field"``)
            keys to new values. Unknown keys are ignored.
        persist: Write the changes to the config file (default True).

    Returns:
        ``(live_config, saved_path)``; ``saved_path`` is None if not persisted.

    Raises:
        ConfigUpdateError: If the resulting configuration is invalid. Neither
            the live config nor any file is modified in that case.
    """
    from pydantic import ValidationError

    live = get_config()
    candidate_dict = live.model_dump()
    applied: list[tuple[str, ...]] = []
    for key, value in updates.items():
        parts = tuple(key.split("."))
        if len(parts) == 1:
            if parts[0] not in type(live).model_fields:
                continue
            candidate_dict[parts[0]] = value
        elif len(parts) == 2:
            section = getattr(live, parts[0], None)
            if section is None or parts[1] not in type(section).model_fields:
                continue
            candidate_dict[parts[0]][parts[1]] = value
        else:
            continue
        applied.append(parts)

    try:
        candidate = SandroidConfig(**candidate_dict)
    except ValidationError as e:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in e.errors()
        )
        raise ConfigUpdateError(f"Invalid setting -- {details}") from e

    def _owner(model: Any, parts: tuple[str, ...]) -> Any:
        return model if len(parts) == 1 else getattr(model, parts[0])

    saved_path: Path | None = None
    if persist and applied:
        serialised = {}
        for parts in applied:
            owner = _owner(candidate, parts)
            dumped = owner.model_dump(mode="json", include={parts[-1]})
            serialised[".".join(parts)] = dumped.get(parts[-1])
        loader = ConfigLoader()
        target = loader.resolve_save_target(_config_source)
        saved_path = loader.update_file_keys(target, serialised)

    # Apply validated (coerced) values to the live object in place, so every
    # holder of the singleton (Toolbox.config, the TUI, services) sees them.
    for parts in applied:
        setattr(
            _owner(live, parts),
            parts[-1],
            getattr(_owner(candidate, parts), parts[-1]),
        )
    return live, saved_path


__all__ = [
    "ConfigLoader",
    "ConfigUpdateError",
    "SandroidConfig",
    "get_config",
    "get_config_source",
    "reset_config_cache",
    "set_config",
    "update_config",
]
