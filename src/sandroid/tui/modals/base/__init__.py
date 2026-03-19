"""Sandroid modal base classes and components.

Core classes:
    SandroidModal: Base class for ALL Sandroid modals with keyboard navigation
    KeyHintFooter: Dynamic keyboard hint widget

Themed modals:
    ForensicModal: Blue theme for forensic/analysis operations
    FridaModal: Green theme for Frida-related operations
    DangerModal: Red theme for dangerous/destructive actions
    ExtractionModal: Violet theme for extraction/export operations

Example:
    from sandroid.tui.modals.base import DangerModal

    class QuitConfirmModal(DangerModal[bool]):
        ...
"""

from .key_hint_footer import KeyHintFooter
from .sandroid_modal import SandroidModal
from .themed_modals import (
    DangerModal,
    ExtractionModal,
    ForensicModal,
    FridaModal,
)

__all__ = [
    "DangerModal",
    "ExtractionModal",
    "ForensicModal",
    "FridaModal",
    "KeyHintFooter",
    "SandroidModal",
]
