"""Configuration schema for Sandroid using Pydantic."""

import re
import shutil
import tempfile
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator, validator

#: Default of ``ai.mask_sensitive``: whether the AI's timeline reads see the
#: content of sensitive lines (typed text, TLS keys) masked. One constant:
#: flip it here to change the default.
AI_MASK_SENSITIVE_DEFAULT = False


def get_secure_temp_dir() -> Path:
    """Get a secure temporary directory for Sandroid."""
    return Path(tempfile.gettempdir()) / "sandroid"


class LogLevel(str, Enum):
    """Supported log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EmulatorConfig(BaseModel):
    """Emulator-specific configuration."""

    device_name: str = Field(
        default="Pixel_6_Pro_API_31", description="Android Virtual Device name"
    )
    serial: str | None = Field(
        default=None,
        description=(
            "ADB serial of the device to use (e.g. emulator-5556). Overrides "
            "automatic selection; --serial and ANDROID_SERIAL also work."
        ),
    )
    android_emulator_path: Path | None = Field(
        default=None,
        description="Path to Android emulator executable (auto-detected if not provided)",
    )
    sdk_path: Path | None = Field(
        default=None, description="Path to Android SDK (auto-detected if not provided)"
    )
    adb_path: Path | None = Field(
        default=None,
        description="Path to ADB executable (auto-detected if not provided)",
    )
    avd_home: Path | None = Field(
        default=None,
        description="Android AVD home directory (auto-detected if not provided)",
    )
    selected_avd: str | None = Field(
        default=None,
        description="AVD name to use for Sandroid analysis",
    )
    avd_headless: bool = Field(
        default=False,
        description="Start AVD in headless mode (no UI)",
    )
    avd_auto_start: bool = Field(
        default=False,
        description="Automatically start AVD when needed",
    )
    max_host_memory_gb: float = Field(
        default=10.0,
        ge=0,
        description=(
            "Host memory limit (GB) for the active emulator's qemu process: "
            "physical footprint on macOS, resident memory elsewhere. The "
            "enforced limit is never below the AVD's RAM + 4 GB (2 x RAM + "
            "4 GB when measuring resident memory). Above it on two readings "
            "the emulator is stopped to protect the host (see "
            "memory_guard_action). 0 disables the guard."
        ),
    )
    memory_guard_action: Literal["kill", "warn"] = Field(
        default="kill",
        description="What to do when max_host_memory_gb is exceeded: kill or warn",
    )
    sync_clock_after_snapshot: bool = Field(
        default=True,
        description=(
            "After every snapshot load, set the device wall clock to host "
            "time (root `date`) when it is more than 1 s off. The offset "
            "before and after is recorded in the session timeline either "
            "way; off keeps the snapshot's frozen clock."
        ),
    )

    @validator("android_emulator_path", "sdk_path", "adb_path", "avd_home", pre=True)
    def expand_user_path(cls, v):
        """Expand user path if it's a string or Path."""
        if isinstance(v, (str, Path)):
            return Path(str(v)).expanduser()
        return v

    def validate_android_environment(self) -> dict[str, bool]:
        """Validate Android development environment setup.

        Returns:
            Dict mapping tool names to their availability status
        """

        def _is_available(configured_path: Path | None, fallback_name: str) -> bool:
            """Check if a tool is available via configured path or system PATH."""
            if configured_path and configured_path.exists():
                return True
            return shutil.which(fallback_name) is not None

        status = {
            "adb": _is_available(self.adb_path, "adb"),
            "emulator": _is_available(self.android_emulator_path, "emulator"),
            "sdk": bool(self.sdk_path and self.sdk_path.exists()),
        }

        # Check AVD home with fallback to default location
        if self.avd_home and self.avd_home.exists():
            status["avd_home"] = True
        else:
            default_avd = Path("~/.android/avd").expanduser()
            status["avd_home"] = default_avd.exists()

        return status


class FridaConfig(BaseModel):
    """Frida-specific configuration."""

    server_auto_start: bool = Field(
        default=True, description="Automatically start Frida server if not running"
    )
    server_port: int = Field(default=27042, description="Frida server port")
    spawn_timeout: int = Field(
        default=30, description="Timeout for spawning processes (seconds)"
    )
    server_version: str = Field(
        default="host",
        description=(
            "Frida-server version to install. 'host' matches the installed "
            "frida Python package (frida.__version__), 'latest' grabs the "
            "newest from GitHub, or specify an explicit version like '17.9.11'. "
            "Legacy 'auto' is accepted as an alias for 'host'."
        ),
    )
    spawn_attempts: int = Field(
        default=4,
        ge=1,
        le=10,
        description=(
            "Max spawn-freeze attempts before failing loud (spawn-reliability ladder)"
        ),
    )
    spawn_splash_window: float = Field(
        default=5.0,
        ge=0.0,
        description=(
            "Seconds to poll the spawned PID for liveness after resume "
            "(crash-relaunch detection)"
        ),
    )
    spawn_retry_sleep: float = Field(
        default=0.6,
        ge=0.0,
        description="Seconds to sleep between spawn re-attempts",
    )


class NetworkConfig(BaseModel):
    """Network analysis configuration."""

    capture_interface: str | None = Field(
        default=None,
        description="Network interface to capture (auto-detected if not provided)",
    )
    pcap_buffer_size: int = Field(
        default=65536, description="PCAP capture buffer size in bytes"
    )
    connection_timeout: int = Field(
        default=30, description="Network connection timeout (seconds)"
    )


class PathConfig(BaseModel):
    """Path configuration for output and temporary files."""

    results_path: Path = Field(
        default=Path("./results/"), description="Directory for analysis results"
    )
    raw_results_path: Path = Field(
        default=Path("./results/raw/"), description="Directory for raw analysis data"
    )
    temp_path: Path = Field(
        default_factory=get_secure_temp_dir, description="Directory for temporary files"
    )
    cache_path: Path = Field(
        default=Path("~/.cache/sandroid/").expanduser(),
        description="Directory for cache files",
    )
    apk_cache_path: Path = Field(
        default=Path("~/.cache/sandroid/apk_cache/").expanduser(),
        description="Shared APK static-facts cache (may be a team share)",
    )

    @validator("*", pre=True)
    def expand_user_path(cls, v):
        """Expand user path if it's a string."""
        if isinstance(v, (str, Path)):
            return Path(v).expanduser()
        return v


class AnalysisConfig(BaseModel):
    """Analysis-specific configuration."""

    number_of_runs: int = Field(
        default=2, ge=2, description="Minimum number of analysis runs"
    )
    insight_offline: bool = Field(
        default=True,
        description="Run Dexray Insight without network lookups (Exodus, updates)",
    )
    avoid_strong_noise_filter: bool = Field(
        default=False, description="Disable strong noise filtering (dry run)"
    )
    system_noise_filter: bool = Field(
        default=True,
        description=(
            "Hide well-known Android/GMS background files (curated list in "
            "sandroid.analysis.filters). Hidden files stay in the result JSON "
            "under Other Data -> Filtered Noise; set false to show everything"
        ),
    )
    noise_patterns: list[str] = Field(
        default_factory=list,
        description="Extra fnmatch globs treated as system noise",
    )
    protected_packages: list[str] = Field(
        default_factory=list,
        description=(
            "Packages whose files are never filtered as noise (the spotlight "
            "app always is)"
        ),
    )
    hash_files: bool = Field(
        default=False, description="Generate MD5 hashes of changed/new files"
    )
    capture_processes: bool = Field(
        default=True, description="Capture active processes during analysis run"
    )
    capture_sockets: bool = Field(
        default=False, description="Capture listening sockets during analysis run"
    )
    capture_network: bool = Field(
        default=False, description="Capture network traffic during analysis run"
    )
    show_deleted_files: bool = Field(
        default=False, description="Perform full filesystem checks for deleted files"
    )
    replay_settle_seconds: int = Field(
        default=8,
        ge=0,
        le=600,
        description=(
            "Seconds to keep capturing after each replay so late network "
            "responses and writes land in the run (the dry run waits the "
            "same extra time); 0 = window ends with the replay"
        ),
    )
    network_reset_after_snapshot: str = Field(
        default="airplane",
        pattern=r"^(airplane|svc|off)$",
        description=(
            "Cycle the device network after every snapshot load before an "
            "action run or the dry run, so connections restored from the "
            "snapshot fail fast and the app reconnects (airplane = airplane "
            "mode on/off, svc = svc wifi/data off/on, off = keep the network)"
        ),
    )
    list_apks: bool = Field(default=False, description="List all APKs and their hashes")
    degrade_network: bool = Field(
        default=False, description="Simulate UMTS/3G connection speeds"
    )
    default_view: str = Field(
        default="forensic",
        description="Default view mode for interactive menu (forensic, malware, or security)",
        pattern=r"^(forensic|malware|security)$",
    )

    @model_validator(mode="before")
    @classmethod
    def _backfill_legacy_capture_keys(cls, data):
        """Back-fill legacy ``monitor_*`` keys onto their ``capture_*`` names.

        The automated-analysis-run artifact toggles were renamed from
        ``monitor_*`` to ``capture_*`` (ending the name collision with the live
        FS Monitor). Sub-models default to ``extra="ignore"``, so without this a
        legacy ``monitor_processes`` (etc.) would be silently dropped. Copy each
        legacy key to its new name only when the new key isn't already present.
        """
        if isinstance(data, dict):
            aliases = {
                "monitor_processes": "capture_processes",
                "monitor_sockets": "capture_sockets",
                "monitor_network": "capture_network",
            }
            for old, new in aliases.items():
                if old in data and new not in data:
                    data[new] = data[old]
        return data


class TrigDroidConfig(BaseModel):
    """TrigDroid malware trigger configuration."""

    enabled: bool = Field(
        default=False, description="Enable TrigDroid malware triggers"
    )
    package_name: str | None = Field(
        default=None, description="Target package name for triggers"
    )
    config_mode: str | None = Field(
        default=None,
        pattern=r"^[ID]$",
        description="Configuration mode: I (interactive) or D (default)",
    )


class AIConfig(BaseModel):
    """Chat/agent LLM connection config (EXPERIMENTAL feature, off by default).

    The connection fields (``base_url``/``api_key``/``model``) have no
    defaults — the AI Chat stays disabled until all three are explicitly set.
    Only a local (loopback) endpoint is accepted unless ``allow_remote`` is
    turned on, because tool results carry device and app data to the model
    (see :mod:`sandroid.ai.safety`). The behavior toggles below do have
    defaults since they're just chat-UI presentation preferences.
    """

    base_url: str | None = Field(
        default=None,
        description=(
            "EXPERIMENTAL. OpenAI-compatible chat-completions base URL. Device "
            "and app data is sent here. A local server is recommended, e.g. "
            "http://localhost:11434/v1 (Ollama) or http://localhost:8000/v1 "
            "(vLLM). No default: AI Chat is off until this is set."
        ),
    )
    api_key: str | None = Field(
        default=None,
        # Never include the key in repr()/str() of the config (logs, tracebacks).
        repr=False,
        description=(
            "API key for the endpoint. Prefer the SANDROID_AI__API_KEY "
            "environment variable: a key in a config file is stored in "
            "plaintext. Local servers that ignore keys accept any value."
        ),
    )
    model: str | None = Field(default=None, description="Model name to request")
    allow_remote: bool = Field(
        default=False,
        description=(
            "Allow a non-local ai.base_url. Off (default) = only loopback "
            "endpoints (localhost/127.0.0.1/::1) are used, so device and app "
            "data never leaves this machine. Set to true only if you accept "
            "sending case data to that remote service."
        ),
    )
    show_verbose_thinking: bool = Field(
        default=False,
        description=(
            "Show the model's full reasoning/thinking text in the Chat "
            "transcript. Off (default) collapses it into a single "
            "'Thought for Ns' line once the reasoning phase ends."
        ),
    )
    show_chat_mascot: bool = Field(
        default=True,
        description="Show the small animated ASCII mascot in the Chat panel.",
    )
    data_share_path: Path = Field(
        default=Path("~/Sandroid/ai_share/").expanduser(),
        description=(
            "Always-available host directory for the AI's file tools. Bare "
            "relative paths given to list_host_dir/read_host_file/push_path/"
            "install_apk are resolved against this directory -- drop a file "
            "here (e.g. an APK to install) and the AI can reach it by "
            "filename alone. Created automatically if missing."
        ),
    )
    extra_host_paths: list[Path] = Field(
        default_factory=list,
        description=(
            "Additional host roots the AI's file tools may access, beyond "
            "data_share_path and the current session's results/raw-results/"
            "cache directories. Empty by default."
        ),
    )

    mask_sensitive: bool = Field(
        default=AI_MASK_SENSITIVE_DEFAULT,
        description=(
            "Mask the content of sensitive session-timeline lines (typed "
            "text, TLS keys) in what the AI reads."
        ),
    )

    @validator("data_share_path", pre=True)
    def expand_data_share_path(cls, v):
        """Expand user path for the AI data-share directory."""
        if isinstance(v, (str, Path)):
            return Path(str(v)).expanduser()
        return v

    @validator("extra_host_paths", pre=True, each_item=True)
    def expand_extra_host_paths(cls, v):
        """Expand user path for each configured extra host root."""
        if isinstance(v, (str, Path)):
            return Path(str(v)).expanduser()
        return v


class MCPServerConfig(BaseModel):
    """A single MCP server connection Sandroid can consume tools from."""

    name: str
    transport: str = "stdio"  # "stdio" | "sse"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None  # for "sse" transport
    enabled: bool = True


class MCPConfig(BaseModel):
    """MCP (Model Context Protocol) client configuration."""

    # Empty by default: no MCP server (and no subprocess) unless explicitly
    # configured. The bundled ``sandroid.ai.mcp_demo_server`` is a test
    # fixture that returns FAKE data and must be opted into explicitly.
    servers: list[MCPServerConfig] = Field(
        default_factory=list,
        description=(
            "External MCP tool servers for the (experimental) AI Chat. "
            "Empty by default; only used when AI Chat is configured."
        ),
    )


class ReportConfig(BaseModel):
    """Report generation configuration."""

    generate_pdf: bool = Field(default=False, description="Generate PDF report")
    include_screenshots: bool = Field(
        default=True, description="Include screenshots in reports"
    )
    template_path: Path | None = Field(
        default=None, description="Custom report template path"
    )
    effects_window_s: float = Field(
        default=2.0,
        ge=0.0,
        le=60.0,
        description=(
            "Seconds after an input in which file/network lines count as its "
            "effects in the report transcript"
        ),
    )
    shot_triggers: list[str] = Field(
        default_factory=lambda: [
            "before_tap",
            "after_tap",
            "screen_change",
            "label",
            "manual",
        ],
        description="Screenshot triggers shown in the report",
    )
    formats: list[str] = Field(
        default_factory=lambda: ["pdf", "md"],
        description="Report formats written besides report.json (pdf, md)",
    )


class ThemeConfig(BaseModel):
    """Theme/appearance configuration for terminal output."""

    preset: str = Field(
        default="default",
        description="Theme preset: default, dark, light, high_contrast",
    )

    @validator("preset")
    def validate_preset(cls, v):
        """Validate that preset is a known theme name."""
        valid_presets = {"default", "dark", "light", "high_contrast"}
        if v.lower() not in valid_presets:
            raise ValueError(
                f"Invalid theme preset: {v}. Must be one of: {', '.join(valid_presets)}"
            )
        return v.lower()


#: OS paths the Files lens hides by default (never the app's own data;
#: ``/data/local/tmp/`` is deliberately not one -- malware drops files there).
FILES_OS_PREFIXES: tuple[str, ...] = (
    "/proc/",
    "/sys/",
    "/dev/",
    "/system/",
    "/apex/",
    "/vendor/",
    "/product/",
    "/data/dalvik-cache/",
    "/data/misc/",
    "/data/system/",
    "/data/app/",
)

#: Rule kinds/actions of ``tui.files_noise_rules``.
FILES_RULE_KINDS: tuple[str, ...] = ("prefix", "segment", "suffix", "glob")
FILES_RULE_ACTIONS: tuple[str, ...] = ("hide", "group")


def default_files_noise_rules() -> list[dict]:
    """Default ``tui.files_noise_rules``: hide OS paths, group cache folders."""
    rules: list[dict] = [
        {"action": "hide", "kind": "prefix", "pattern": p, "enabled": True}
        for p in FILES_OS_PREFIXES
    ]
    for segment in ("cache", "code_cache"):
        rules.append(
            {"action": "group", "kind": "segment", "pattern": segment, "enabled": True}
        )
    return rules


class TUIConfig(BaseModel):
    """TUI (Terminal User Interface) configuration."""

    custom_css_path: Path | None = Field(
        default=None,
        description="Path to custom CSS file for TUI styling. If not set, uses default styles.",
    )
    theme: str = Field(
        default="default",
        description="TUI theme: default, dark, light, high_contrast, cyberpunk, nord, dracula, solarized, graphite, deep_sea, evergreen",
    )
    show_theme_indicator: bool = Field(
        default=False,
        description="Show current theme name in status bar. Disabled by default.",
    )
    logo_color: str | None = Field(
        default=None,
        description="Custom logo color (hex, e.g., '#00ff00'). Overrides theme's logo color.",
    )
    logo_text_color: str | None = Field(
        default=None,
        description="Custom 'Sandroid' text color in logo (hex, e.g., '#ffffff'). Overrides theme.",
    )
    immediate_exit_on_ctrl_c: bool = Field(
        default=False,
        description="If True, Ctrl+C exits immediately. If False (default), shows quit confirmation dialog.",
    )
    monitor_buffer_interval: float = Field(
        default=0.15,
        ge=0.0,
        le=5.0,
        description="Monitor output buffer flush interval in seconds. "
        "Lower values = faster display, higher CPU. 0 = near-realtime.",
    )
    monitor_max_lines: int = Field(
        default=500,
        ge=50,
        le=10000,
        description="Maximum lines kept in Monitor observer log. "
        "Higher values use more memory but allow scrolling back further.",
    )
    monitor_event_visibility: dict[str, str] = Field(
        default_factory=lambda: {
            "create": "always",
            "modify": "always",
            "delete": "always",
            "rename": "always",
            "attrs": "always",
            "noise": "verbose",
        },
        description="Per-category Monitor visibility: 'always', 'verbose', or 'never'. "
        "Categories: create, modify, delete, rename, attrs, noise (monitor OPEN/CLOSE).",
    )
    monitor_backend: str = Field(
        default="kprobe",
        description="Filesystem monitor backend: 'kprobe' (kernel tracefs "
        "kprobes; prefer kprobe, auto-fall-back to fsmon when the kernel lacks "
        "support) or 'fsmon' (the fsmon binary).",
    )
    auto_pull_on_change: bool = Field(
        default=True,
        description="Files lens: pull a watched (★) file automatically when "
        "the file monitor sees a write to it (debounced ~1.5 s; a database "
        "and its -wal/-journal are one group). Needs the monitor running.",
    )
    monitor_follow_app: bool = Field(
        default=True,
        description="File monitor, App mode: follow the APP, not one PID -- "
        "every process of the app (its UID, or named <pkg> / <pkg>:<sub>), "
        "also ones that start or restart while the monitor runs (kprobe "
        "backend). Off: only the PID running at start and its children; the "
        "Files lens says 'monitor blind' once it is gone. Default for the "
        "checkbox in the monitor dialog.",
    )
    files_noise_rules: list[dict] = Field(
        default_factory=default_files_noise_rules,
        description="Files lens path rules, in order: {action: hide|group, "
        "kind: prefix|segment|suffix|glob, pattern, enabled}. 'hide' drops "
        "matching rows (N shows them), 'group' collapses them into one row "
        "per folder. Edited live from the Files lens (R).",
    )
    keybindings: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Override keys: maps a binding id (the MenuController action name) to "
            "a key string, e.g. {'proxy': 'ctrl+y'}. Edited by the in-app ? "
            "keybinding editor or by hand."
        ),
    )
    snapshot_slots: dict[str, dict[str, str]] = Field(
        default_factory=dict,
        description=(
            "Per-AVD snapshot slot memory: maps an AVD name to a slot table "
            "{slot_number: snapshot_tag}, e.g. "
            "{'Pixel_6_API_33': {'1': 'clean-boot', '3': 'post-install'}}. "
            "Edited via the snapshot picker (key S)."
        ),
    )
    snapshot_save_mode: str = Field(
        default="ask",
        description="Save to an occupied slot: 'ask' (prompt), 'overwrite' "
        "(re-save in place), 'fresh' (new timestamped snapshot + re-point).",
    )

    @validator("snapshot_save_mode")
    def validate_snapshot_save_mode(cls, v):
        """Validate snapshot save mode setting."""
        valid = {"ask", "overwrite", "fresh"}
        if v not in valid:
            raise ValueError(
                f"Invalid snapshot_save_mode: {v}. Must be one of: "
                f"{', '.join(sorted(valid))}"
            )
        return v

    @validator("monitor_event_visibility")
    def validate_monitor_event_visibility(cls, v):
        """Validate Monitor per-category visibility modes."""
        valid = {"always", "verbose", "never"}
        for category, mode in v.items():
            if mode not in valid:
                raise ValueError(
                    f"Invalid monitor_event_visibility mode for '{category}': {mode}. "
                    f"Must be one of: {', '.join(sorted(valid))}"
                )
        return v

    @validator("files_noise_rules")
    def validate_files_noise_rules(cls, v):
        """Each rule: a known action and kind, a non-empty pattern."""
        cleaned: list[dict] = []
        for rule in v:
            if not isinstance(rule, dict):
                raise ValueError(f"Invalid files_noise_rules entry: {rule!r}")  # noqa: TRY004
            action = rule.get("action", "hide")
            kind = rule.get("kind")
            pattern = rule.get("pattern")
            if action not in FILES_RULE_ACTIONS:
                raise ValueError(
                    f"Invalid files_noise_rules action: {action!r}. Must be one "
                    f"of: {', '.join(FILES_RULE_ACTIONS)}"
                )
            if kind not in FILES_RULE_KINDS:
                raise ValueError(
                    f"Invalid files_noise_rules kind: {kind!r}. Must be one of: "
                    f"{', '.join(FILES_RULE_KINDS)}"
                )
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("files_noise_rules: every rule needs a pattern")
            cleaned.append(
                {
                    "action": action,
                    "kind": kind,
                    "pattern": pattern,
                    "enabled": bool(rule.get("enabled", True)),
                }
            )
        return cleaned

    @validator("monitor_backend")
    def validate_monitor_backend(cls, v):
        """Validate filesystem monitor backend setting.

        The legacy ``"auto"`` value is normalized to ``"kprobe"`` before the
        membership check (a transform-in-validator, like ``validate_theme``),
        so existing configs self-heal to the two-way selector on load.
        """
        if v == "auto":
            v = "kprobe"
        valid = {"fsmon", "kprobe"}
        if v not in valid:
            raise ValueError(
                f"Invalid monitor_backend: {v}. Must be one of: "
                f"{', '.join(sorted(valid))}"
            )
        return v

    @model_validator(mode="before")
    @classmethod
    def _backfill_legacy_monitor_keys(cls, data):
        """Back-fill legacy ``fsmon_*`` config keys onto their ``monitor_*`` names.

        The generic monitoring layer was renamed from ``fsmon_*`` to
        ``monitor_*``; an existing config file may still carry the old keys.
        Sub-models default to ``extra="ignore"``, so without this a legacy
        ``fsmon_buffer_interval`` (etc.) would be silently dropped. Copy each
        legacy key to its new name only when the new key isn't already present.
        """
        if isinstance(data, dict):
            aliases = {
                "fsmon_buffer_interval": "monitor_buffer_interval",
                "fsmon_max_lines": "monitor_max_lines",
                "fsmon_event_visibility": "monitor_event_visibility",
            }
            for old, new in aliases.items():
                if old in data and new not in data:
                    data[new] = data[old]
        return data

    @validator("custom_css_path", pre=True)
    def expand_css_path(cls, v):
        """Expand user path for custom CSS file."""
        if isinstance(v, (str, Path)) and v:
            return Path(str(v)).expanduser()
        return v

    @validator("theme")
    def validate_theme(cls, v):
        """Validate that theme is a known TUI theme name."""
        valid_themes = {
            "default",
            "dark",
            "light",
            "high_contrast",
            "cyberpunk",
            "nord",
            "dracula",
            "solarized",
            "graphite",
            "deep_sea",
            "evergreen",
        }
        if v.lower() not in valid_themes:
            raise ValueError(
                f"Invalid TUI theme: {v}. Must be one of: {', '.join(sorted(valid_themes))}"
            )
        return v.lower()

    @validator("logo_color", "logo_text_color", pre=True)
    def validate_hex_color(cls, v):
        """Validate hex color format."""
        if v is None:
            return v
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            # Accept hex colors with or without #
            if not v.startswith("#"):
                v = f"#{v}"
            # Validate hex format (3, 4, 6, or 8 characters after #)
            hex_part = v[1:]
            if len(hex_part) not in (3, 4, 6, 8):
                raise ValueError(
                    f"Invalid hex color: {v}. Use format like '#00ff00' or '#fff'"
                )
            try:
                int(hex_part, 16)
            except ValueError:
                raise ValueError(
                    f"Invalid hex color: {v}. Contains non-hex characters"
                ) from None
            return v
        return v


#: Timeline sources the policy can never turn off (mirrors
#: ``sandroid.core.timeline.ALWAYS_ON``).
TIMELINE_ALWAYS_ON = frozenset(
    {"label", "sandroid", "clock", "snapshot", "device", "run"}
)
_SRC_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,15}\.([a-z][a-z0-9_-]{0,23}|\*)$")


class TimelineConfig(BaseModel):
    """The session timeline (``timeline.jsonl`` per device folder): what is
    written, counted or left out, and how readers mask sensitive lines.
    """

    sources: dict[str, bool] = Field(
        default_factory=lambda: {
            "files": True,
            "monitor": True,
            "net": True,
            "input": True,
            "screen": True,
            "shot": True,
        },
        description=(
            "Per-source switch (off = not written). label, sandroid, clock, "
            "snapshot, device and run are always on."
        ),
    )
    kinds_off: list[str] = Field(
        default_factory=list,
        description='Line kinds not written: "src.kind" or "src.*"',
    )
    count_only: list[str] = Field(
        default_factory=lambda: ["files.open", "files.close"],
        description='Line kinds only counted ("<src>/count" lines): "src.kind"',
    )
    files_attrs: Literal["app_dirs", "lines", "counts"] = Field(
        default="app_dirs",
        description=(
            "files.attrs: a line inside the analysed app's data dirs and a "
            "count elsewhere (app_dirs), always a line, or always a count"
        ),
    )
    files_modify_coalesce_ms: int = Field(
        default=1000,
        ge=0,
        le=60_000,
        description="files.modify lines per (path, pid) within this window are "
        "merged into one (0 = off)",
    )
    count_window_s: float = Field(
        default=5.0, ge=1.0, le=60.0, description="Seconds per count line"
    )
    queue_max: int = Field(
        default=10_000,
        ge=1_000,
        le=1_000_000,
        description="Bulk lines queued per device before they are dropped",
    )
    clock_every_s: int = Field(
        default=60,
        ge=0,
        le=3_600,
        description="Seconds between periodic device-clock samples (0 = off)",
    )
    mask_sensitive: bool = Field(
        default=False,
        description=(
            "Mask sensitive lines (typed text, TLS keys) in the lens, the "
            "Inspector, exports and reports"
        ),
    )

    @field_validator("sources")
    @classmethod
    def _sources_keep_always_on(cls, v: dict[str, bool]) -> dict[str, bool]:
        """Always-on sources cannot be switched off (dropped from the map)."""
        return {k: bool(on) for k, on in v.items() if k not in TIMELINE_ALWAYS_ON}

    @field_validator("kinds_off", "count_only")
    @classmethod
    def _src_kinds(cls, v: list[str]) -> list[str]:
        """``src.kind`` / ``src.*`` entries; always-on sources are ignored."""
        out = []
        for entry in v:
            entry = str(entry).strip()
            if not _SRC_KIND_RE.match(entry):
                raise ValueError(f'"{entry}" is not "src.kind" or "src.*"')
            if entry.split(".", 1)[0] in TIMELINE_ALWAYS_ON or entry in out:
                continue
            out.append(entry)
        return out


class TrackingConfig(BaseModel):
    """Tracking: the interaction transcript (taps, text, screens, shots)."""

    helper_mode: Literal["full", "invisible", "off"] = Field(
        default="full",
        description=(
            "UI helper: full (accessibility events, element lookup; "
            "detectable), invisible (screenshots only), off"
        ),
    )
    auto_on_record: bool = Field(
        default=True, description="Start Tracking with a recording"
    )
    shot_before_tap: bool = Field(default=True, description="Screenshot at touch-down")
    shot_screen_change: bool = Field(
        default=True, description="Screenshot when the screen changes"
    )
    shot_after_tap: bool = Field(
        default=False, description="Screenshot once the screen settled after a tap"
    )
    shot_label: bool = Field(default=False, description="Screenshot at every label")
    settle_interval_ms: int = Field(default=300, ge=100, le=2_000)
    settle_max_ms: int = Field(default=2_000, ge=300, le=10_000)
    capture_text: bool = Field(default=True, description="Record typed text")
    text_idle_ms: int = Field(default=1_500, ge=200, le=10_000)
    long_press_ms: int = Field(default=500, ge=200, le=3_000)
    swipe_slop_px: int = Field(default=24, ge=4, le=200)
    logcat_screen_backup: bool = Field(
        default=True, description="Activity changes from logcat as a backup"
    )


class MVTConfig(BaseModel):
    """Mobile Verification Toolkit (MVT) integration configuration.

    MVT is a forensic tool for analyzing mobile devices to detect signs of
    compromise. It uses STIX2 IOC (Indicators of Compromise) files.
    """

    enabled: bool = Field(
        default=False,
        description="Enable MVT forensic evidence scanning",
    )
    ioc_path: Path | None = Field(
        default=None,
        description="Path to STIX2 IOC file or directory containing IOC files",
    )
    ioc_url: str | None = Field(
        default=None,
        description="URL to download STIX2 IOC files (e.g., from Amnesty International)",
    )
    auto_update_iocs: bool = Field(
        default=False,
        description="Automatically update IOC files from URL before scanning",
    )
    scan_sms: bool = Field(
        default=True,
        description="Scan SMS messages for IOC matches",
    )
    scan_calls: bool = Field(
        default=True,
        description="Scan call logs for IOC matches",
    )
    scan_apps: bool = Field(
        default=True,
        description="Scan installed applications for IOC matches",
    )
    scan_files: bool = Field(
        default=True,
        description="Scan filesystem for IOC matches",
    )
    output_format: str = Field(
        default="json",
        description="Output format for MVT results (json, csv, or both)",
        pattern=r"^(json|csv|both)$",
    )
    remember_ioc_choice: bool = Field(
        default=False,
        description="Remember IOC source preference (skip choice modal)",
    )

    @validator("ioc_path", pre=True)
    def expand_ioc_path(cls, v):
        """Expand user path for IOC file/directory."""
        if isinstance(v, (str, Path)) and v:
            return Path(str(v)).expanduser()
        return v

    @validator("ioc_url", pre=True)
    def validate_ioc_url(cls, v):
        """Validate IOC URL format."""
        if v is None:
            return v
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            if not v.startswith(("http://", "https://")):
                raise ValueError("IOC URL must start with http:// or https://")
        return v


class FocusConfig(BaseModel):
    """Per-app proxy ("App Proxies") lane configuration.

    Each app proxy scopes traffic for one app by redirecting it (by Linux UID,
    via an iptables ``owner`` match REDIRECT) into its own on-device ``gost``
    redirector. gost's ``red://`` listener reads ``SO_ORIGINAL_DST`` and
    forwards to the lane's upstream — either our mitmproxy SOCKS5 port (the
    default) or an external HTTP proxy (Burp/ZAP). For our-mitmproxy lanes the
    arrival SOCKS port *is* the app identity used to label flows.

    The gost binary is downloaded at runtime, cached, and sha256-verified
    (mirrors the frida-server pattern); it is not bundled in the wheel. The
    release ships ``.tar.gz`` assets, so the download path extracts the ``gost``
    member and verifies the **extracted ELF** sha256 (see ``gost_assets``).
    """

    redirect_base: int = Field(
        default=60080,
        description="Base on-device REDIRECT port for app-proxy lanes",
    )
    gost_binary_dst: str = Field(
        default="/data/local/tmp/gost",
        description="On-device path for the gost binary",
    )
    host_ip_override: str = Field(
        default="",
        description=(
            "Force the host IP our-mitmproxy lanes forward to "
            "(blank = auto, 10.0.2.2 on emulator)"
        ),
    )
    block_quic: bool = Field(
        default=True,
        description="REJECT UDP/443 (QUIC) for proxied apps so they fall back to "
        "interceptable TCP/TLS. Off = QUIC bypasses the app proxy.",
    )
    gost_version: str = Field(
        default="v3.2.6",
        description="gost release tag whose assets are downloaded",
    )
    sidecar_path: str = Field(
        default="~/.cache/sandroid/focus_lanes.json",
        description=(
            "Path to the lane→app sidecar map (consumers must expanduser() it)"
        ),
    )
    gost_assets: dict[str, dict[str, str]] = Field(
        default_factory=lambda: {
            "arm64": {
                "url": "https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_arm64.tar.gz",
                "sha256": "343c3e003996ca0437b9cc47dd1500cd0475ba09f5a5f17e50851854e06a1ca7",
            },
            "arm": {
                "url": "https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_armv7.tar.gz",
                "sha256": "ad5b0979f452b07c23e90d566c632b0ffe228ef0e1021085e8c4e2f164824151",
            },
            "x86": {
                "url": "https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_386.tar.gz",
                "sha256": "c4c4156acda43caa2ccc71ccf025662699cdea05ae9e6e763c07588d893bfb45",
            },
            "x86_64": {
                "url": "https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_amd64.tar.gz",
                "sha256": "a2aea24efb4597b5f57b35b8e1bbcc59f439b80723854d4371f6828b46682ffb",
            },
        },
        description=(
            "Per-ABI gost download URLs and sha256 checksums. NOTE: assets are "
            ".tar.gz archives; the sha256 is of the EXTRACTED `gost` ELF, not "
            "the tarball (the download path extracts before checksumming)."
        ),
    )

    # ── DEPRECATED (ipt2socks era) ────────────────────────────────────
    # Retained so existing configs still validate after the gost migration.
    # No longer read by FocusManager; safe to remove once all configs are
    # regenerated. See gost_binary_dst/gost_version/gost_assets above.
    binary_dst: str = Field(
        default="/data/local/tmp/ipt2socks",
        description="DEPRECATED (ipt2socks): superseded by gost_binary_dst",
    )
    ipt2socks_version: str = Field(
        default="v1.1.4",
        description="DEPRECATED (ipt2socks): superseded by gost_version",
    )
    ipt2socks_assets: dict[str, dict[str, str]] = Field(
        default_factory=dict,
        description="DEPRECATED (ipt2socks): superseded by gost_assets",
    )


class MitmproxyConfig(BaseModel):
    """mitmproxy (mitmweb) integration configuration.

    Controls the embedded mitmweb subprocess used for network interception
    and the user-supplied addon scripts loaded into it.
    """

    proxy_port: int = Field(
        default=8080, description="Listen port for the mitmproxy HTTP proxy"
    )
    listen_host: str = Field(
        default="127.0.0.1",
        description=(
            "Bind address for the proxy and app-proxy SOCKS listeners. "
            "127.0.0.1 keeps intercepted traffic off the LAN and is enough "
            "for emulators (10.0.2.2 is the host loopback) and for USB "
            "devices routed via adb reverse. Set 0.0.0.0 (all interfaces) "
            "only for a physical device that reaches the host over Wi-Fi."
        ),
    )
    auto_device_proxy: bool = Field(
        default=False,
        description=(
            "Also point the device's global http_proxy at mitmproxy when it "
            "is started with Enter in the Network lens (off: start touches "
            "nothing on the device; use Ctrl+D). Sandroid clears the device "
            "proxy it set when mitmproxy stops and when Sandroid exits."
        ),
    )
    web_port: int = Field(default=8081, description="Port for the mitmweb web UI")
    web_host: str = Field(
        default="127.0.0.1", description="Bind host for the mitmweb web UI"
    )
    addons_dir: Path = Field(
        default=Path("~/.config/sandroid/mitm_addons/").expanduser(),
        description="Directory scanned for user-supplied mitmproxy addons",
    )
    enabled_addons: list[str] = Field(
        default_factory=list,
        description=("Resolved absolute path strings of addons to load into mitmweb"),
    )
    capture_scope: str = Field(
        default="none",
        description=(
            "DEPRECATED: vestigial mode field. The proxy UI now derives display "
            "and control from ground truth (device http_proxy + live app-proxy "
            "lanes), not this stored mode. Kept (with its validator) so existing "
            "configs validate; no longer drives behavior."
        ),
    )
    socks_base: int = Field(
        default=8082,
        description="Base host SOCKS5 port for our-mitmproxy app-proxy lanes",
    )
    focus_lanes: int = Field(
        default=5,
        description=(
            "Number of app-proxy lanes (each = 1 on-device redirector + 1 "
            "mitmproxy SOCKS port for our-mitmproxy lanes)"
        ),
    )
    flow_log_enabled: bool = Field(
        default=True,
        description=(
            "Write every captured flow to a structured, queryable log under "
            "the session's raw-results directory (mitm_flows/), so the AI "
            "chat's get_captured_flows/get_flow_detail tools can read what "
            "was intercepted. Disable to skip this bookkeeping entirely."
        ),
    )
    max_stored_flows: int = Field(
        default=5000,
        ge=100,
        le=100000,
        description=(
            "Maximum number of flow records kept in the structured flow "
            "log. Once exceeded, the oldest records (and their detail "
            "files) are dropped to make room for new ones."
        ),
    )
    max_captured_body_bytes: int = Field(
        default=65536,
        ge=0,
        le=1048576,
        description=(
            "Maximum request/response body size, in bytes, captured per "
            "side into a flow's detail file. Capped once at capture time -- "
            "raising this later cannot recover bodies already truncated "
            "under a smaller value."
        ),
    )

    @validator("addons_dir", pre=True)
    def expand_addons_dir(cls, v):
        """Expand user path/env for the addons directory."""
        if isinstance(v, (str, Path)) and v:
            return Path(str(v)).expanduser()
        return v

    @validator("capture_scope", pre=True)
    def validate_capture_scope(cls, v):
        """Lowercase and restrict the capture mechanism to the known values.

        Legacy ``"off"`` is deliberately migrated to ``"none"`` (the unarmed
        status) rather than falling through the catch-all.
        """
        if isinstance(v, str):
            v = v.strip().lower()
        if v == "off":
            return "none"
        if v not in {"none", "device", "focus"}:
            return "none"
        return v

    @validator("focus_lanes", pre=True)
    def clamp_focus_lanes(cls, v):
        """Clamp the lane-pool size to a sane 1..16 range.

        Runs ``pre`` so a non-integer config value (e.g. a hand-edited
        ``focus_lanes: "x"``) falls back to the default instead of raising a
        ValidationError that would crash config load.
        """
        try:
            v = int(v)
        except (TypeError, ValueError):
            return 5
        return max(1, min(16, v))


class DevicePathsConfig(BaseModel):
    """Android device filesystem paths.

    These paths are used when interacting with the Android device/emulator
    filesystem. Override in sandroid.toml to match non-standard setups.

        [device_paths]
        frida_install_dir = "/data/local/tmp/"
        default_monitor_path = "/data/"
    """

    frida_install_dir: str = Field(
        default="/data/local/tmp/",
        description="Directory on device where Frida server is installed",
    )
    fsmon_binary_base: str = Field(
        default="/data/local/tmp/fsmon-{arch}",
        description="FSMon binary path template ({arch} replaced at runtime)",
    )
    default_monitor_path: str = Field(
        default="/data/",
        description="Default filesystem path for filesystem monitoring",
    )
    scan_directories: list[str] = Field(
        default=["/data", "/storage", "/sdcard"],
        description="Directories to scan for forensic file change detection",
    )
    app_data_paths: list[str] = Field(
        default=[
            "/data/data/{package}",
            "/data/user/0/{package}",
            "/sdcard/Android/data/{package}",
        ],
        description="App data path templates ({package} replaced at runtime)",
    )
    device_cert_path: str = Field(
        default="/data/local/tmp/cert-der.crt",
        description="Temporary certificate path on device for CA injection",
    )
    system_ca_path: str = Field(
        default="/system/etc/security/cacerts",
        description="System CA certificate directory on device",
    )
    apex_ca_path: str = Field(
        default="/apex/com.android.conscrypt/cacerts",
        description="APEX CA certificate directory on device (Android 14+)",
    )
    spotlight_data_path: str = Field(
        default="/data/data/{app}",
        description="Spotlight app data path template ({app} replaced at runtime)",
    )
    pidof_binary: str = Field(
        default="/system/bin/pidof",
        description="Path to pidof binary on device",
    )
    killall_binary: str = Field(
        default="/system/bin/killall",
        description="Path to killall binary on device",
    )

    @validator(
        "frida_install_dir",
        "fsmon_binary_base",
        "default_monitor_path",
        "device_cert_path",
        "system_ca_path",
        "apex_ca_path",
        "spotlight_data_path",
        "pidof_binary",
        "killall_binary",
    )
    def validate_non_empty_path(cls, v):
        """Validate that path strings are non-empty."""
        if not v or not v.strip():
            raise ValueError("Device path cannot be empty")
        return v


class ExternalURLsConfig(BaseModel):
    """External service URLs for downloads and API calls.

    Override these if using internal mirrors or alternative sources.

        [external_urls]
        frida_releases_url = "https://github.com/frida/frida/releases"
    """

    frida_releases_url: str = Field(
        default="https://github.com/frida/frida/releases",
        description="Frida GitHub releases base URL",
    )
    frida_api_url: str = Field(
        default="https://api.github.com/repos/frida/frida/releases/",
        description="Frida GitHub API URL for version lookups",
    )
    frida_download_url: str = Field(
        default="https://github.com/frida/frida/releases/download/",
        description="Frida server binary download base URL",
    )
    fsmon_urls: dict[str, str] = Field(
        default={
            "arm64": "https://github.com/nowsecure/fsmon/releases/download/1.8.6/fsmon-android-arm64",
            "arm": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-arm",
            "x86": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86",
            "x86_64": "https://github.com/nowsecure/fsmon/releases/download/1.8.4/fsmon-and-x86_64",
        },
        description="FSMon binary download URLs per architecture",
    )
    mvt_github_base: str = Field(
        default="https://raw.githubusercontent.com/mvt-project/mvt/main/",
        description="MVT GitHub raw content base URL for IOC downloads",
    )
    stalkerware_ioc_url: str = Field(
        default="https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2",
        description="Stalkerware indicators STIX2 file URL",
    )
    apkpure_base_url: str = Field(
        default="https://apkpure.com",
        description="APKPure base URL for APK downloads",
    )
    apkpure_api_url: str = Field(
        default="https://api.apkpure.com",
        description="APKPure API base URL",
    )
    fdroid_base_url: str = Field(
        default="https://f-droid.org",
        description="F-Droid base URL",
    )
    fdroid_search_url: str = Field(
        default="https://search.f-droid.org/api/search_apps",
        description="F-Droid app search API URL",
    )
    fdroid_package_api_url: str = Field(
        default="https://f-droid.org/api/v1/packages",
        description="F-Droid package API URL",
    )
    fdroid_repo_url: str = Field(
        default="https://f-droid.org/repo",
        description="F-Droid repository base URL",
    )
    aptoide_api_url: str = Field(
        default="https://ws75.aptoide.com/api/7",
        description="Aptoide API base URL",
    )
    aptoide_meta_url: str = Field(
        default="https://ws2.aptoide.com/api/7",
        description="Aptoide metadata API URL",
    )
    apksfull_base_url: str = Field(
        default="https://apksfull.com",
        description="APKsFull base URL for APK downloads",
    )

    @validator(
        "frida_releases_url",
        "frida_api_url",
        "frida_download_url",
        "mvt_github_base",
        "stalkerware_ioc_url",
        "apkpure_base_url",
        "apkpure_api_url",
        "fdroid_base_url",
        "fdroid_search_url",
        "fdroid_package_api_url",
        "fdroid_repo_url",
        "aptoide_api_url",
        "aptoide_meta_url",
        "apksfull_base_url",
    )
    def validate_url_format(cls, v):
        """Validate that URL strings start with http:// or https://."""
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"URL must start with http:// or https://, got: {v}")
        return v


class DisplayConfig(BaseModel):
    """Display and formatting constants.

    Customize output formatting widths, cutoffs, and limits.

        [display]
        section_width = 60
        line_length_cutoff = 150
    """

    section_width: int = Field(
        default=60,
        ge=20,
        le=200,
        description="Width of section headers/footers in character output",
    )
    line_length_cutoff: int = Field(
        default=150,
        ge=50,
        le=1000,
        description="Maximum characters per line before truncation",
    )
    line_number_cutoff: int = Field(
        default=50,
        ge=10,
        le=10000,
        description="Maximum lines before truncation",
    )
    section_separator_width: int = Field(
        default=108,
        ge=20,
        le=200,
        description="Width of section separator lines in analysis output",
    )
    box_width: int = Field(
        default=60,
        ge=30,
        le=200,
        description="Width of info boxes in analysis output",
    )
    spotlight_box_width: int = Field(
        default=70,
        ge=30,
        le=200,
        description="Width of spotlight info box",
    )
    file_path_max_length: int = Field(
        default=80,
        ge=30,
        le=500,
        description="Max display length for file paths before middle-truncation",
    )
    timestamp_highlight_margin: int = Field(
        default=100,
        ge=0,
        le=1000,
        description="Margin (seconds) around action time for timestamp highlighting",
    )
    fridump_max_size: int = Field(
        default=20971520,
        ge=1048576,
        description="Maximum memory region size for Fridump (bytes, default 20MB)",
    )
    apk_search_limit: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum number of APK search results to display",
    )


class TimeoutConfig(BaseModel):
    """Timeout configuration for various operations.

    All values are in seconds. These can be overridden in sandroid.toml:

        [timeouts]
        adb_command = 45
        frida_download = 600
    """

    adb_command: int = Field(
        default=30, description="Timeout for ADB shell commands (seconds)"
    )
    adb_pull: int = Field(default=60, description="Timeout for ADB file pull (seconds)")
    adb_pull_large: int = Field(
        default=180, description="Timeout for large file pulls like APKs (seconds)"
    )
    adb_push: int = Field(
        default=120, description="Timeout for ADB file push (seconds)"
    )
    network_download: int = Field(
        default=120, description="Timeout for network file downloads (seconds)"
    )
    frida_download: int = Field(
        default=300, description="Timeout for Frida server download (seconds)"
    )
    api_call: int = Field(default=10, description="Timeout for API calls (seconds)")
    subprocess: int = Field(
        default=60, description="Default subprocess timeout (seconds)"
    )


class CredentialsConfig(BaseModel):
    """Secure credentials configuration."""

    custom_api_keys: dict[str, str] = Field(
        default_factory=dict, description="Additional API keys for custom integrations"
    )

    class Config:
        """Pydantic configuration for credentials."""

        # Hide sensitive fields in string representation
        repr = False


class SandroidConfig(BaseModel):
    """Main Sandroid configuration."""

    # Core settings
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    output_file: Path = Field(
        default=Path("sandroid.json"), description="Output file for analysis results"
    )
    whitelist_file: Path | None = Field(
        default=None,
        description="Path to file containing paths to exclude from analysis",
    )

    # Component configurations
    emulator: EmulatorConfig = Field(default_factory=EmulatorConfig)
    frida: FridaConfig = Field(default_factory=FridaConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    trigdroid: TrigDroidConfig = Field(default_factory=TrigDroidConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    theme: ThemeConfig = Field(default_factory=ThemeConfig)
    tui: TUIConfig = Field(default_factory=TUIConfig)
    timeline: TimelineConfig = Field(default_factory=TimelineConfig)
    tracking: TrackingConfig = Field(default_factory=TrackingConfig)
    mvt: MVTConfig = Field(default_factory=MVTConfig)
    mitmproxy: MitmproxyConfig = Field(default_factory=MitmproxyConfig)
    focus: FocusConfig = Field(default_factory=FocusConfig)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    device_paths: DevicePathsConfig = Field(default_factory=DevicePathsConfig)
    external_urls: ExternalURLsConfig = Field(default_factory=ExternalURLsConfig)
    display: DisplayConfig = Field(default_factory=DisplayConfig)

    # Environment-specific overrides
    environment: str = Field(
        default="production",
        description="Environment name (development, testing, production)",
    )

    # Custom settings (for user extensions)
    custom: dict[str, str | int | bool | float] = Field(
        default_factory=dict, description="Custom configuration values"
    )

    class Config:
        """Pydantic configuration."""

        env_prefix = "SANDROID_"
        env_nested_delimiter = "__"
        case_sensitive = False
        validate_assignment = True
        extra = "allow"  # Allow additional fields for extensibility

    @validator("whitelist_file", pre=True)
    def expand_whitelist_path(cls, v):
        """Expand user path for whitelist file."""
        if isinstance(v, (str, Path)) and v:
            return Path(v).expanduser()
        return v

    def create_directories(self) -> None:
        """Create necessary directories."""
        for path in [
            self.paths.results_path,
            self.paths.raw_results_path,
            self.paths.temp_path,
            self.paths.cache_path,
        ]:
            path.mkdir(parents=True, exist_ok=True)
