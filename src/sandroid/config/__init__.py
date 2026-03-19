"""Configuration management for Sandroid."""

from .loader import ConfigLoader
from .schema import SandroidConfig

# Cached config instance for singleton access
_config_instance: SandroidConfig | None = None


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


def reset_config_cache() -> None:
    """Reset the cached config instance.

    Call this after saving config changes to force a fresh load
    on the next get_config() call.
    """
    global _config_instance
    _config_instance = None


__all__ = ["ConfigLoader", "SandroidConfig", "get_config", "reset_config_cache"]
