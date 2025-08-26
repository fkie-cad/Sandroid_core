"""Sandroid Features Module

This package contains the functionality components for Sandroid.
Previously located in src/functionality/, these modules have been migrated here
for better packaging and pip installation support.

Key modules:
- functionality: Base class for functionality operations
- screenshot: Screenshot capture functionality
- recorder: Action recording functionality
- player: Action replay functionality
- trigdroid: TrigDroid malware trigger functionality
"""

# Core feature components
from .functionality import Functionality
from .player import Player

# Screenshot temporarily excluded due to Toolbox.args initialization dependency
from .recorder import Recorder
from .trigdroid import Trigdroid

__all__ = [
    "Functionality",
    "Player",
    "Recorder",
    "Trigdroid",
]
