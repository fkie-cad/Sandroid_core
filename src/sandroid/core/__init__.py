"""Sandroid Core Module

This package contains the core utilities for Sandroid analysis framework.
Previously located in src/utils/, these modules have been migrated here
for better packaging and pip installation support.

Key modules:
- toolbox: Central orchestrator and utility functions
- adb: Android Debug Bridge interface
- adb_utils: ADB error handling and stderr filtering utilities
- actionQ: Action queue management system
- frida_manager: Frida instrumentation management
- emulator: Android emulator control
- AI_processing: AI-powered analysis features
"""

# Core analysis components
from .adb import Adb

# Toolbox excluded from __init__ to prevent circular imports (import directly: from sandroid.core.toolbox import Toolbox)
# ADB utilities for error handling
from .adb_utils import (
    ADB_ERROR_INDICATORS,
    BENIGN_ADB_PATTERNS,
    format_adb_error,
    is_adb_error_actionable,
    log_adb_result,
)

# ActionQ excluded from __init__ to prevent circular imports (import directly when needed)

# AI_processing and frida_manager are imported directly when needed:
#   from sandroid.core.AI_processing import AIProcessing
#   from sandroid.core.frida_manager import FridaManager

__all__ = [
    "ADB_ERROR_INDICATORS",
    "BENIGN_ADB_PATTERNS",
    "Adb",
    "format_adb_error",
    # Toolbox excluded due to circular import (import directly: from sandroid.core.toolbox import Toolbox)
    # ADB utilities
    "is_adb_error_actionable",
    "log_adb_result",
    # ActionQ excluded due to circular import (import directly: from .actionQ import ActionQ)
]
