"""Configuration loader for Sandroid with support for multiple formats and XDG directories."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from platformdirs import site_config_dir, user_config_dir

from .schema import SandroidConfig

# Handle tomli import for Python < 3.11
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import tomli_w


class ConfigLoader:
    """Loads and manages Sandroid configuration from multiple sources."""

    def __init__(self, app_name: str = "sandroid"):
        """Initialize the config loader.

        Args:
            app_name: Application name for config directory lookup
        """
        self.app_name = app_name
        self._config_dirs = self._get_config_directories()
        self._config_files = self._discover_config_files()

    def _get_config_directories(self) -> list[Path]:
        """Get configuration directories following XDG specification."""
        dirs = []

        # User config directory (highest priority)
        user_dir = Path(user_config_dir(self.app_name))
        dirs.append(user_dir)

        # Additional user directories from XDG_CONFIG_DIRS
        xdg_config_dirs = os.environ.get("XDG_CONFIG_DIRS", "")
        if xdg_config_dirs:
            for config_dir in xdg_config_dirs.split(":"):
                if config_dir.strip():
                    dirs.append(Path(config_dir.strip()) / self.app_name)

        # System config directory (lowest priority)
        system_dir = Path(site_config_dir(self.app_name))
        dirs.append(system_dir)

        # Current working directory (for development)
        current_dir = Path.cwd()
        dirs.insert(0, current_dir)  # Highest priority for development

        return dirs

    def _discover_config_files(self) -> list[Path]:
        """Discover configuration files in order of preference."""
        config_files = []
        config_names = ["sandroid", "config"]
        extensions = [".yaml", ".yml", ".toml", ".json"]  # Prioritize YAML

        for config_dir in self._config_dirs:
            for name in config_names:
                for ext in extensions:
                    config_file = config_dir / f"{name}{ext}"
                    if config_file.exists() and config_file.is_file():
                        config_files.append(config_file)

        return config_files

    def _load_toml(self, path: Path) -> dict[str, Any]:
        """Load TOML configuration file."""
        with open(path, "rb") as f:
            return tomllib.load(f)

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        """Load YAML configuration file."""
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _load_json(self, path: Path) -> dict[str, Any]:
        """Load JSON configuration file."""
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _load_file(self, path: Path) -> dict[str, Any]:
        """Load configuration file based on extension."""
        suffix = path.suffix.lower()

        if suffix == ".toml":
            return self._load_toml(path)
        if suffix in [".yaml", ".yml"]:
            return self._load_yaml(path)
        if suffix == ".json":
            return self._load_json(path)
        raise ValueError(f"Unsupported configuration file format: {suffix}")

    def _merge_configs(
        self, base: dict[str, Any], override: dict[str, Any]
    ) -> dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def load_environment_vars(self) -> dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        prefix = "SANDROID_"

        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Remove prefix and convert to lowercase
                config_key = key[len(prefix) :].lower()

                # Handle nested configuration with double underscore
                if "__" in config_key:
                    parts = config_key.split("__")
                    current = config
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = self._parse_env_value(value)
                else:
                    config[config_key] = self._parse_env_value(value)

        return config

    def _parse_env_value(self, value: str) -> str | int | float | bool:
        """Parse environment variable value to appropriate type."""
        # Boolean values
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # Numeric values
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def load(
        self,
        config_file: str | Path | None = None,
        environment: str | None = None,
        cli_overrides: dict[str, Any] | None = None,
    ) -> SandroidConfig:
        """Load configuration from all sources.

        Args:
            config_file: Explicit configuration file path
            environment: Environment name for environment-specific config
            cli_overrides: Command-line argument overrides

        Returns:
            Loaded and validated Sandroid configuration

        Raises:
            FileNotFoundError: If explicit config file is specified but not found
            ValueError: If configuration is invalid
        """
        # Start with empty config
        merged_config = {}

        # 1. Load from discovered config files (lowest priority)
        for config_path in reversed(self._config_files):  # Reverse for correct priority
            try:
                file_config = self._load_file(config_path)
                merged_config = self._merge_configs(merged_config, file_config)
            except Exception as e:
                # Log warning but don't fail
                print(f"Warning: Failed to load config from {config_path}: {e}")

        # 2. Load explicit config file if provided
        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")

            try:
                explicit_config = self._load_file(config_path)
                merged_config = self._merge_configs(merged_config, explicit_config)
            except Exception as e:
                raise ValueError(
                    f"Failed to load configuration from {config_path}: {e}"
                )

        # 3. Load environment-specific config if environment is specified
        if environment:
            for config_dir in self._config_dirs:
                env_config_path = config_dir / f"{environment}.toml"
                if env_config_path.exists():
                    try:
                        env_config = self._load_file(env_config_path)
                        merged_config = self._merge_configs(merged_config, env_config)
                    except Exception as e:
                        print(
                            f"Warning: Failed to load environment config from {env_config_path}: {e}"
                        )

        # 4. Load environment variables (higher priority)
        env_config = self.load_environment_vars()
        if env_config:
            merged_config = self._merge_configs(merged_config, env_config)

        # 5. Apply CLI overrides (highest priority)
        if cli_overrides:
            merged_config = self._merge_configs(merged_config, cli_overrides)

        # Validate and create config object
        try:
            config = SandroidConfig(**merged_config)
            config.create_directories()  # Ensure directories exist
            return config
        except Exception as e:
            raise ValueError(f"Invalid configuration: {e}")

    def save_config(
        self,
        config: SandroidConfig,
        config_file: str | Path | None = None,
        format: str = "yaml",
    ) -> Path:
        """Save configuration to file.

        Args:
            config: Configuration to save
            config_file: Target file path (defaults to user config dir)
            format: Output format ('toml', 'yaml', 'json')

        Returns:
            Path where configuration was saved
        """
        if config_file is None:
            user_dir = Path(user_config_dir(self.app_name))
            user_dir.mkdir(parents=True, exist_ok=True)
            config_file = user_dir / f"sandroid.{format}"
        else:
            config_file = Path(config_file)
            config_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict with proper enum serialization
        # Using JSON serialization ensures enums are converted to their values
        config_dict = json.loads(config.model_dump_json(exclude_unset=True))

        # Save based on format
        if format == "toml":
            with open(config_file, "wb") as f:
                tomli_w.dump(config_dict, f)
        elif format in ["yaml", "yml"]:
            with open(config_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(
                    config_dict, f, default_flow_style=False, sort_keys=False
                )
        elif format == "json":
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config_dict, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return config_file

    def create_default_config(self, config_file: str | Path | None = None) -> Path:
        """Create a default configuration file.

        Args:
            config_file: Target file path (defaults to user config dir)

        Returns:
            Path where default configuration was created
        """
        default_config = SandroidConfig()
        return self.save_config(default_config, config_file)
