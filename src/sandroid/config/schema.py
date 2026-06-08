"""Configuration schema for Sandroid using Pydantic."""

import shutil
import tempfile
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, validator


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
    avoid_strong_noise_filter: bool = Field(
        default=False, description="Disable strong noise filtering (dry run)"
    )
    screenshot_interval: int | None = Field(
        default=None, ge=1, description="Screenshot interval in seconds"
    )
    hash_files: bool = Field(
        default=False, description="Generate MD5 hashes of changed/new files"
    )
    monitor_processes: bool = Field(
        default=True, description="Monitor active processes during analysis"
    )
    monitor_sockets: bool = Field(
        default=False, description="Monitor listening sockets"
    )
    monitor_network: bool = Field(default=False, description="Capture network traffic")
    show_deleted_files: bool = Field(
        default=False, description="Perform full filesystem checks for deleted files"
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
    """AI processing configuration."""

    enabled: bool = Field(default=False, description="Enable AI-powered analysis")
    provider: str = Field(default="google-genai", description="AI provider to use")
    api_key: str | None = Field(
        default=None,
        description="AI service API key (use environment variable or credentials section)",
    )
    model: str = Field(default="gemini-pro", description="AI model to use")


class ReportConfig(BaseModel):
    """Report generation configuration."""

    generate_pdf: bool = Field(default=False, description="Generate PDF report")
    include_screenshots: bool = Field(
        default=True, description="Include screenshots in reports"
    )
    template_path: Path | None = Field(
        default=None, description="Custom report template path"
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


class TUIConfig(BaseModel):
    """TUI (Terminal User Interface) configuration."""

    custom_css_path: Path | None = Field(
        default=None,
        description="Path to custom CSS file for TUI styling. If not set, uses default styles.",
    )
    theme: str = Field(
        default="default",
        description="TUI theme: default, dark, light, high_contrast, cyberpunk, nord, dracula, solarized",
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
    fsmon_display_mode: str = Field(
        default="ask",
        description="FSMon output display: 'ask' (prompt), 'observer' (modal), 'background' (activity log)",
    )

    @validator("fsmon_display_mode")
    def validate_fsmon_display_mode(cls, v):
        """Validate FSMon display mode setting."""
        valid = {"ask", "observer", "background"}
        if v not in valid:
            raise ValueError(
                f"Invalid fsmon_display_mode: {v}. Must be one of: {', '.join(sorted(valid))}"
            )
        return v

    fsmon_buffer_interval: float = Field(
        default=0.15,
        ge=0.0,
        le=5.0,
        description="FSMon output buffer flush interval in seconds. "
        "Lower values = faster display, higher CPU. 0 = near-realtime.",
    )
    fsmon_max_lines: int = Field(
        default=500,
        ge=50,
        le=10000,
        description="Maximum lines kept in FSMon observer log. "
        "Higher values use more memory but allow scrolling back further.",
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
            "Edited via the Snapshots tab (assign/save to slot)."
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


class MitmproxyConfig(BaseModel):
    """mitmproxy (mitmweb) integration configuration.

    Controls the embedded mitmweb subprocess used for network interception
    and the user-supplied addon scripts loaded into it.
    """

    proxy_port: int = Field(
        default=8080, description="Listen port for the mitmproxy HTTP proxy"
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

    @validator("addons_dir", pre=True)
    def expand_addons_dir(cls, v):
        """Expand user path/env for the addons directory."""
        if isinstance(v, (str, Path)) and v:
            return Path(str(v)).expanduser()
        return v


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
        description="Default filesystem path for FSMon monitoring",
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

    google_genai_api_key: str | None = Field(
        default=None, description="Google Generative AI API key"
    )
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
    report: ReportConfig = Field(default_factory=ReportConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    theme: ThemeConfig = Field(default_factory=ThemeConfig)
    tui: TUIConfig = Field(default_factory=TUIConfig)
    mvt: MVTConfig = Field(default_factory=MVTConfig)
    mitmproxy: MitmproxyConfig = Field(default_factory=MitmproxyConfig)
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
