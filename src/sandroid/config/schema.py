"""Configuration schema for Sandroid using Pydantic."""

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
    android_emulator_path: Path = Field(
        default=Path("~/Android/Sdk/emulator/emulator").expanduser(),
        description="Path to Android emulator executable",
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
        if isinstance(v, (str, Path)) and v is not None:
            return Path(str(v)).expanduser()
        return v

    def validate_android_environment(self) -> dict[str, bool]:
        """Validate Android development environment setup.

        Returns:
            Dict mapping tool names to their availability status
        """
        status = {}

        # Check ADB
        if self.adb_path and self.adb_path.exists():
            status["adb"] = True
        else:
            # Try to find adb in PATH
            import shutil

            adb_in_path = shutil.which("adb")
            status["adb"] = adb_in_path is not None

        # Check emulator
        if self.android_emulator_path and self.android_emulator_path.exists():
            status["emulator"] = True
        else:
            # Try to find emulator in PATH
            import shutil

            emulator_in_path = shutil.which("emulator")
            status["emulator"] = emulator_in_path is not None

        # Check SDK
        if self.sdk_path and self.sdk_path.exists():
            status["sdk"] = True
        else:
            status["sdk"] = False

        # Check AVD home
        if self.avd_home and self.avd_home.exists():
            status["avd_home"] = True
        else:
            # Check default AVD location
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
