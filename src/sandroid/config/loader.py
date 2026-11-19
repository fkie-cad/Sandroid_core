"""Configuration loader for Sandroid with support for multiple formats and XDG directories."""

import contextlib
import json
import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any

import tomli_w
import yaml
from platformdirs import site_config_dir, user_config_dir
from pydantic import ValidationError

from .schema import SandroidConfig


def atomic_write_bytes(
    path: str | Path,
    data: bytes,
    *,
    new_mode: int = 0o600,
    mode: int | None = None,
) -> None:
    """Replace ``path`` with ``data`` atomically (temp file + ``os.replace``).

    An existing file keeps its permission bits; a new file gets ``new_mode``
    (owner-only by default: config files may hold credentials). ``mode``
    forces the bits either way. The parent directory is created when
    missing.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        try:
            mode = path.stat().st_mode & 0o7777
        except FileNotFoundError:
            mode = new_mode
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).chmod(mode)
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


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

    def _preferred_user_config_dir(self) -> Path:
        """Preferred user config directory (XDG ``~/.config/<app>``).

        This is the directory ``load()`` searches first and that the docs point
        users to. ``save_config()`` writes here by default rather than the
        platformdirs location (``~/Library/Application Support`` on macOS),
        which ``load()`` only treats as a fallback.
        """
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config_home:
            return Path(xdg_config_home) / self.app_name
        # Default to ~/.config/<app> on all platforms (including macOS)
        return Path.home() / ".config" / self.app_name

    def _get_config_directories(self) -> list[Path]:
        """Get configuration directories following XDG specification.

        On macOS, we prefer ~/.config/sandroid over ~/Library/Application Support
        for consistency with Linux and user expectations.
        """
        dirs = []

        # User config directory - prefer XDG style (~/.config/sandroid) on all
        # platforms. This is more consistent and expected by users.
        user_dir = self._preferred_user_config_dir()
        dirs.append(user_dir)

        # Also check platformdirs location as fallback (e.g., ~/Library/Application Support on macOS)
        platform_user_dir = Path(user_config_dir(self.app_name))
        if platform_user_dir != user_dir:
            dirs.append(platform_user_dir)

        # Additional user directories from XDG_CONFIG_DIRS
        xdg_config_dirs = os.environ.get("XDG_CONFIG_DIRS", "")
        if xdg_config_dirs:
            for config_dir in xdg_config_dirs.split(os.pathsep):
                if config_dir.strip():
                    dirs.append(Path(config_dir.strip()) / self.app_name)

        # System config directory (lowest priority)
        system_dir = Path(site_config_dir(self.app_name))
        dirs.append(system_dir)

        # Current working directory (for development)
        current_dir = Path.cwd()
        dirs.insert(0, current_dir)  # Highest priority for development

        return dirs

    # In the current working directory only ``sandroid.{toml,yaml,yml}`` are
    # picked up: ``sandroid.json`` is the default analysis *result* file
    # (``sandroid -f``) and ``config.*`` is far too generic a name -- loading
    # (and, worse, saving settings into) either would clobber unrelated data.
    _CWD_CONFIG_NAMES = ("sandroid.toml", "sandroid.yaml", "sandroid.yml")
    _CONFIG_NAMES = ("sandroid", "config")
    _CONFIG_EXTENSIONS = (".toml", ".yaml", ".yml", ".json")  # TOML is default

    def _discover_config_files(self) -> list[Path]:
        """Discover configuration files in order of preference."""
        config_files = []

        # _config_dirs[0] is the current working directory (see
        # _get_config_directories); the rest are XDG/platform/system dirs.
        for index, config_dir in enumerate(self._config_dirs):
            for name in self._CONFIG_NAMES:
                for ext in self._CONFIG_EXTENSIONS:
                    filename = f"{name}{ext}"
                    if index == 0 and filename not in self._CWD_CONFIG_NAMES:
                        continue
                    config_file = config_dir / filename
                    if config_file.exists() and config_file.is_file():
                        config_files.append(config_file)

        return config_files

    def _is_recognised_config(self, path: Path) -> bool:
        """True if ``path`` is a file name/location discovery treats as config."""
        path = Path(path)
        if path.parent == self._config_dirs[0] and path.name in self._CWD_CONFIG_NAMES:
            return True
        return (
            path.stem in self._CONFIG_NAMES
            and path.suffix in self._CONFIG_EXTENSIONS
            and path.parent in self._config_dirs[1:]
        )

    def resolve_save_target(self, explicit: str | Path | None = None) -> Path:
        """Return the config file that settings changes should be written to.

        Order: the explicit (``--config``) file, else the highest-priority
        discovered config file, else ``~/.config/sandroid/sandroid.toml``.
        Never a file that discovery would not load as a config.
        """
        if explicit is not None:
            return Path(explicit)
        for candidate in self._config_files:
            if self._is_recognised_config(candidate):
                return candidate
        return self._preferred_user_config_dir() / "sandroid.toml"

    def update_file_keys(self, path: str | Path, updates: dict[str, Any]) -> Path:
        """Write dotted-key ``updates`` into the config file at ``path``.

        Only the given keys are touched: the file's existing content is kept
        as-is (no defaults are added), sections missing from a minimal file
        are created. A ``None`` value removes the key (TOML has no null).
        Values must already be JSON-serialisable.
        """
        path = Path(path)
        data: dict[str, Any] = self._load_file(path) if path.exists() else {}
        for key, value in updates.items():
            parts = key.split(".")
            current = data
            for part in parts[:-1]:
                if not isinstance(current.get(part), dict):
                    current[part] = {}
                current = current[part]
            if value is None:
                current.pop(parts[-1], None)
            else:
                current[parts[-1]] = value

        fmt = self._suffix_to_format(path)
        if fmt == "toml":
            payload = tomli_w.dumps(data).encode("utf-8")
        elif fmt == "yaml":
            payload = yaml.safe_dump(
                data, default_flow_style=False, sort_keys=False
            ).encode("utf-8")
        else:
            payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        atomic_write_bytes(path, payload)
        return path

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
        if suffix in (".yaml", ".yml"):
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
        except ValidationError as e:
            errors = []
            for error in e.errors():
                loc = " -> ".join(str(loc_part) for loc_part in error["loc"])
                msg = error["msg"]
                errors.append(f"  {loc}: {msg}")
            error_text = "\n".join(errors)
            raise ValueError(
                f"Invalid configuration in sandroid.toml:\n{error_text}\n\n"
                f"Run 'sandroid-config show' to see valid options."
            ) from e
        except Exception as e:
            raise ValueError(f"Invalid configuration: {e}") from e

    @staticmethod
    def _redact_secrets(config_dict: dict) -> dict:
        """Redact known secret fields from a config dict, for display only.

        Mutates and returns config_dict. Never called on the path that
        actually persists a config file — only from the
        ``sandroid-config show`` display helper, which discards its temp
        file immediately after reading it back.
        """
        ai_section = config_dict.get("ai")
        if isinstance(ai_section, dict) and ai_section.get("api_key"):
            ai_section["api_key"] = "***REDACTED***"

        credentials = config_dict.get("credentials")
        if isinstance(credentials, dict):
            custom_keys = credentials.get("custom_api_keys")
            if isinstance(custom_keys, dict) and custom_keys:
                credentials["custom_api_keys"] = dict.fromkeys(
                    custom_keys, "***REDACTED***"
                )
        return config_dict

    @staticmethod
    def _drop_env_only_secrets(config_dict: dict) -> dict:
        """Never persist a secret that was supplied via an environment variable.

        ``load()`` merges ``SANDROID_*`` env vars into the config, so any
        load-modify-save flow (``sandroid-config theme set``, the TUI help
        screen, ...) would otherwise copy ``SANDROID_AI__API_KEY`` into the
        config file in plaintext.
        """
        env_key = (os.environ.get("SANDROID_AI__API_KEY") or "").strip()
        ai_section = config_dict.get("ai")
        if env_key and isinstance(ai_section, dict):
            if str(ai_section.get("api_key") or "").strip() == env_key:
                ai_section.pop("api_key", None)
        return config_dict

    def save_config(
        self,
        config: SandroidConfig,
        config_file: str | Path | None = None,
        format: str = "toml",
        redact_secrets: bool = False,
    ) -> Path:
        """Save configuration to file.

        Args:
            config: Configuration to save
            config_file: Target file path (defaults to ~/.config/sandroid/)
            format: Output format ('toml', 'yaml', 'json'). Default is 'toml'.
            redact_secrets: If True, replace known secret field values
                (``ai.api_key``, ``credentials.custom_api_keys``) with a
                redacted placeholder before writing. Intended only for
                display-purposes callers (e.g. ``sandroid-config show``) —
                never set this when persisting a real configuration file.

        Returns:
            Path where configuration was saved
        """
        if config_file is None:
            # Write to the preferred XDG dir (~/.config/sandroid) — the location
            # load() searches first and the docs document — not the platformdirs
            # path, which load() only treats as a fallback.
            user_dir = self._preferred_user_config_dir()
            user_dir.mkdir(parents=True, exist_ok=True)
            config_file = user_dir / f"sandroid.{format}"
        else:
            config_file = Path(config_file)
            config_file.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict with proper enum serialization
        # Using JSON serialization ensures enums are converted to their values
        # For TOML, we must exclude None values since TOML has no null representation
        if format == "toml":
            config_dict = json.loads(
                config.model_dump_json(exclude_unset=True, exclude_none=True)
            )
        else:
            # JSON and YAML support null/None values
            config_dict = json.loads(config.model_dump_json(exclude_unset=True))

        if redact_secrets:
            config_dict = self._redact_secrets(config_dict)
        else:
            config_dict = self._drop_env_only_secrets(config_dict)

        # Save based on format
        if format == "toml":
            with open(config_file, "wb") as f:
                tomli_w.dump(config_dict, f)
        elif format in ("yaml", "yml"):
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

    @staticmethod
    def _suffix_to_format(path: Path | None) -> str:
        """Map a file suffix to a config format string."""
        if path is not None:
            suffix = path.suffix
            if suffix in (".yaml", ".yml"):
                return "yaml"
            if suffix == ".json":
                return "json"
        return "toml"

    def detect_and_save(
        self, config: SandroidConfig, config_path: str | Path | None = None
    ) -> Path:
        """Detect existing config format and save.

        Without ``config_path`` this writes to the highest-priority discovered
        *recognised* config file (see ``resolve_save_target``), falling back
        to the user config dir -- never to an arbitrary file such as an
        analysis result ``sandroid.json`` in the working directory.
        """
        target = self.resolve_save_target(config_path)
        return self.save_config(config, target, self._suffix_to_format(target))

    #: ``(section, key)`` pairs that are never written by
    #: :meth:`load_and_update_section`; ``"*"`` covers a whole section.
    _NEVER_PERSISTED = frozenset({("ai", "api_key"), ("credentials", "*")})

    @classmethod
    def _is_secret_key(cls, section: str, key: str) -> bool:
        return (section, key) in cls._NEVER_PERSISTED or (
            section,
            "*",
        ) in cls._NEVER_PERSISTED

    def load_and_update_section(
        self, section: str, updates: dict[str, Any]
    ) -> tuple[SandroidConfig, Path]:
        """Validate ``section`` updates and write only those keys to disk.

        The updates are validated against the whole merged configuration
        (files, environment), but only ``section.<key>`` for each key in
        ``updates`` is written into the save target (see
        :meth:`resolve_save_target`): the file keeps its own content and
        permissions, and nothing else -- no defaults, no other sections, no
        values that came from environment variables or other files -- is
        copied into it. Secrets (``ai.api_key``, ``credentials.*``) are
        never written this way.

        Returns:
            ``(updated merged config, path written)``.

        Raises:
            ValueError: A secret key, a key the section does not have, or an
                invalid value. Nothing is written in that case.
        """
        for key in updates:
            if self._is_secret_key(section, key):
                raise ValueError(f"refusing to persist the secret {section}.{key}")
        try:
            current_config = self.load()
        except FileNotFoundError:
            current_config = SandroidConfig()

        section_model = getattr(current_config, section, None)
        if section not in SandroidConfig.model_fields or not hasattr(
            section_model, "model_fields"
        ):
            raise ValueError(f"unknown config section {section!r}")
        unknown = [
            key for key in updates if key not in type(section_model).model_fields
        ]
        if unknown:
            raise ValueError(f"unknown {section} keys: {', '.join(unknown)}")
        config_dict = current_config.model_dump()
        config_dict[section].update(updates)

        updated_config = SandroidConfig(**config_dict)
        section_model = getattr(updated_config, section)
        serialised = {
            f"{section}.{key}": section_model.model_dump(
                mode="json", include={key}
            ).get(key)
            for key in updates
        }
        saved_path = self.update_file_keys(self.resolve_save_target(), serialised)
        return updated_config, saved_path

    def create_default_config(self, config_file: str | Path | None = None) -> Path:
        """Create a default configuration file.

        Args:
            config_file: Target file path (defaults to user config dir)

        Returns:
            Path where default configuration was created
        """
        default_config = SandroidConfig()
        return self.save_config(default_config, config_file)
