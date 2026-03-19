"""CLI mode dispatchers for Sandroid.

Each module handles a specific execution mode:
- interactive: TUI and Rich-based interactive menus
- analysis: Automated forensic analysis workflow
- fritap: Headless FriTap SSL/TLS key extraction
- dexray: Headless dexray-intercept malware monitoring
- network: Headless network capture
- headless: Headless/batch API-based analysis
- helpers: Shared utilities (logging setup, CLI override builder)
"""

from .analysis import run_analysis
from .device_settings import run_device_settings_headless
from .dexray import run_dexray_headless
from .fridump import run_fridump_headless
from .fritap import run_fritap_headless
from .headless import run_headless_analysis
from .helpers import build_cli_overrides, setup_logging
from .interactive import start_interactive_mode
from .network import run_network_headless

__all__ = [
    "build_cli_overrides",
    "run_analysis",
    "run_device_settings_headless",
    "run_dexray_headless",
    "run_fridump_headless",
    "run_fritap_headless",
    "run_headless_analysis",
    "run_network_headless",
    "setup_logging",
    "start_interactive_mode",
]
