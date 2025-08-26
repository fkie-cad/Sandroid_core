"""Sandroid Core Module

This package contains the core utilities for Sandroid analysis framework.
Previously located in src/utils/, these modules have been migrated here
for better packaging and pip installation support.

Key modules:
- toolbox: Central orchestrator and utility functions
- adb: Android Debug Bridge interface
- actionQ: Action queue management system
- frida_manager: Frida instrumentation management
- emulator: Android emulator control
- AI_processing: AI-powered analysis features
"""

# Core analysis components
from .adb import Adb
from .toolbox import Toolbox

# ActionQ excluded from __init__ to prevent circular imports (import directly when needed)

# Optional imports that may have dependencies
try:
    from .AI_processing import *
except ImportError:
    # AI functionality not available
    pass

try:
    from .frida_manager import *
except ImportError:
    # Frida functionality not available
    pass

__all__ = [
    "Adb",
    "Toolbox",
    # ActionQ excluded due to circular import (import directly: from .actionQ import ActionQ)
]
