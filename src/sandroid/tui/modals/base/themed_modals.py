"""Themed modal subclasses for Sandroid TUI.

This module provides semantic themed modals for different operation categories:
- ForensicModal: Blue theme for analysis and forensic operations (default)
- FridaModal: Green theme for Frida-related operations
- DangerModal: Red theme for dangerous/destructive actions
- ExtractionModal: Violet theme for extraction and export operations

Usage:
    from sandroid.tui.modals.base import ForensicModal, DangerModal

    class QuitConfirmModal(DangerModal[bool]):
        '''Inherits red theme styling automatically.'''
        ...

    class AnalysisModal(ForensicModal[dict]):
        '''Inherits blue theme styling automatically.'''
        ...
"""

from __future__ import annotations

from typing import Generic, TypeVar

from .sandroid_modal import SandroidModal

T = TypeVar("T")


class ForensicModal(SandroidModal[T], Generic[T]):
    """Base class for forensic/analysis modals.

    Uses Forensic Blue theme color ($primary) for borders and titles.
    This is the default theme color for general information modals.

    Categories using this base:
    - Device selection, snapshot management
    - Analysis results, MVT results
    - Generic input, selection, confirmation modals
    """

    DEFAULT_CSS = """
    ForensicModal .modal-container {
        border: solid $primary;
    }

    ForensicModal .modal-title {
        color: $primary;
    }
    """


class FridaModal(SandroidModal[T], Generic[T]):
    """Base class for Frida-related modals.

    Uses Frida Green theme color ($success) for borders and titles.
    Frida operations are "success-oriented" actions.

    Categories using this base:
    - Frida server installation
    - Objection configuration
    - FSMon, Spotlight file browser
    - Tool selection for Frida tools
    """

    DEFAULT_CSS = """
    FridaModal .modal-container {
        border: solid $success;
    }

    FridaModal .modal-title {
        color: $success;
    }

    /* Use hardcoded white for reliable contrast on colored backgrounds */
    FridaModal Button.-primary {
        background: $success;
        color: #ffffff;
    }

    /* Use darken variant on hover to maintain contrast with white text */
    FridaModal Button.-primary:hover {
        background: $success-darken-1;
        color: #ffffff;
    }

    /* Override specificity for Textual's internal Button classes */
    FridaModal .button-row Button.-style-default.-primary,
    FridaModal .button-row Button.-style-default.-primary:hover,
    FridaModal .button-row Button.-style-default.-primary:focus {
        background: $success;
        color: #ffffff;
    }

    FridaModal .button-row Button.-style-default.-primary:hover {
        background: $success-darken-1;
        color: #ffffff;
    }
    """


class DangerModal(SandroidModal[T], Generic[T]):
    """Base class for dangerous/destructive action modals.

    Uses Danger Red theme color ($error) for borders and titles.
    Quit confirmation, delete operations, error displays.

    Categories using this base:
    - Quit confirmation
    - Device switch warnings
    - APK install warnings
    """

    DEFAULT_CSS = """
    DangerModal .modal-container {
        border: solid $error;
    }

    DangerModal .modal-title {
        color: $error;
    }

    /* Use hardcoded white for reliable contrast on colored backgrounds */
    DangerModal Button.-primary {
        background: $error;
        color: #ffffff;
    }

    /* Use darken variant on hover to maintain contrast with white text */
    DangerModal Button.-primary:hover {
        background: $error-darken-1;
        color: #ffffff;
    }

    /* Override specificity for Textual's internal Button classes */
    DangerModal .button-row Button.-style-default.-primary,
    DangerModal .button-row Button.-style-default.-primary:hover,
    DangerModal .button-row Button.-style-default.-primary:focus {
        background: $error;
        color: #ffffff;
    }

    DangerModal .button-row Button.-style-default.-primary:hover {
        background: $error-darken-1;
        color: #ffffff;
    }
    """


class ExtractionModal(SandroidModal[T], Generic[T]):
    """Base class for extraction/export modals.

    Uses Extraction Violet theme color ($accent) for borders and titles.
    APK extraction, export operations, file pulls.

    Categories using this base:
    - Export modal for action export
    - Folder selection for extraction
    - APK selection/installation
    - Forensic APK management
    """

    DEFAULT_CSS = """
    ExtractionModal .modal-container {
        border: solid $accent;
    }

    ExtractionModal .modal-title {
        color: $accent;
    }

    /* Use hardcoded white for reliable contrast on colored backgrounds */
    ExtractionModal Button.-primary {
        background: $accent;
        color: #ffffff;
    }

    /* Use darken variant on hover to maintain contrast with white text */
    ExtractionModal Button.-primary:hover {
        background: $accent-darken-1;
        color: #ffffff;
    }

    /* Override specificity for Textual's internal Button classes */
    ExtractionModal .button-row Button.-style-default.-primary,
    ExtractionModal .button-row Button.-style-default.-primary:hover,
    ExtractionModal .button-row Button.-style-default.-primary:focus {
        background: $accent;
        color: #ffffff;
    }

    ExtractionModal .button-row Button.-style-default.-primary:hover {
        background: $accent-darken-1;
        color: #ffffff;
    }
    """
