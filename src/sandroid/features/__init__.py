"""Sandroid Features Module.

Provides functionality components: screenshot capture, event recording/replay,
and TrigDroid malware trigger analysis.
"""

from .functionality import Functionality
from .player import Player
from .recorder import Recorder
from .trigdroid import Trigdroid

__all__ = [
    "Functionality",
    "Player",
    "Recorder",
    "Trigdroid",
]
