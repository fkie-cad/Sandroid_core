"""Sandroid API Layer.

This package provides UI-agnostic interfaces for Sandroid operations,
enabling multiple UI implementations (TUI, REST API, headless) to share
the same core functionality.

Usage:
    # Abstract interface usage
    from sandroid.api import SandroidAPI, CommandResult, MenuState

    # Headless API usage (recommended for programmatic access)
    from sandroid.api import SandroidHeadlessAPI, AnalysisMode

    async def main():
        api = SandroidHeadlessAPI()
        await api.initialize()

        # Run malware analysis
        results = await api.run_analysis(
            AnalysisMode.MALWARE,
            package="com.example.app",
            runs=3,
            capture_network=True,
        )

        await api.shutdown()

    # Batch processing
    from sandroid.api import batch_analyze

    results = await batch_analyze(
        packages=["com.app1", "com.app2"],
        mode=AnalysisMode.MALWARE,
        output_dir="results/",
    )
"""

from .headless import SandroidHeadlessAPI, batch_analyze
from .interfaces import (
    AnalysisConfig,
    AnalysisMode,
    AnalysisState,
    AnalysisStateEnum,
    CommandResult,
    MenuItem,
    MenuState,
    SandroidAPI,
)

__all__ = [
    # Data classes
    "AnalysisConfig",
    "AnalysisMode",
    "AnalysisState",
    "AnalysisStateEnum",
    "CommandResult",
    "MenuItem",
    "MenuState",
    # Abstract interface
    "SandroidAPI",
    # Concrete implementation
    "SandroidHeadlessAPI",
    # Utilities
    "batch_analyze",
]
