"""Spotlight Controller for TUI.

This controller manages spotlight files operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Add/remove files to spotlight monitoring
- Pull spotlight files to local disk
- View and manage spotlight file list

Usage:
    from sandroid.tui.controllers import SpotlightController

    controller = SpotlightController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
    )

    controller.add_file("/data/data/com.example.app/databases/app.db")
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SpotlightFilesAction:
    """Action from spotlight files modal."""

    action: str  # "add", "remove", "pull", "pull_all", "close"
    file_path: str | None = None
    pull_all: bool = False


class SpotlightController:
    """Controller for spotlight files operations.

    This controller handles all spotlight file-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of spotlight logic from UI rendering
    - Reusable spotlight management across different UI modes

    Example:
        controller = SpotlightController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
        )

        controller.add_file("/data/data/com.example.app/databases/app.db")
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        get_current_view: Callable[[], str] | None = None,
    ):
        """Initialize SpotlightController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            get_current_view: Callback to get current view mode
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._get_current_view = get_current_view

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_forensic_service(self) -> Any:
        """Get forensic service instance."""
        from sandroid.services import get_forensic_service

        return get_forensic_service()

    def _get_file_extraction_service(self) -> Any:
        """Get file extraction service instance."""
        from sandroid.services import get_file_extraction_service

        return get_file_extraction_service()

    # =========================================================================
    # Spotlight Status
    # =========================================================================

    def get_spotlight_files(self) -> list[str]:
        """Get list of spotlight files.

        Returns:
            List of file paths in spotlight
        """
        try:
            return self._get_forensic_service().get_spotlight_files()
        except Exception as e:
            logger.error(f"Error getting spotlight files: {e}")
            return []

    # =========================================================================
    # Spotlight Operations
    # =========================================================================

    def add_file(self, file_path: str) -> bool:
        """Add file to spotlight.

        Args:
            file_path: Path to file to add

        Returns:
            True if file was added
        """
        try:
            added = self._get_forensic_service().add_spotlight_file(file_path)
            if added:
                self._log_info(f"Added file to spotlight: {file_path}")
                return True
            self._log_warning(f"File already in spotlight or invalid: {file_path}")
            return False
        except Exception as e:
            self._log_error(f"Failed to add file: {e}")
            return False

    def remove_file(self, file_path: str) -> bool:
        """Remove file from spotlight.

        Args:
            file_path: Path to file to remove

        Returns:
            True if file was removed
        """
        try:
            self._get_forensic_service().remove_spotlight_file(file_path)
            self._log_info(f"Removed from spotlight: {file_path}")
            return True
        except Exception as e:
            self._log_error(f"Failed to remove file: {e}")
            return False

    def pull_files(self, specific_file: str | None = None) -> bool:
        """Pull spotlight files to local disk.

        Args:
            specific_file: Specific file to pull, or None for all files

        Returns:
            True if files were pulled successfully
        """
        try:
            files = self._get_forensic_service().get_spotlight_files()
            if not files:
                self._log_warning("No spotlight files to pull")
                return False

            if specific_file:
                if specific_file in files:
                    files = [specific_file]
                else:
                    self._log_warning(f"File not in spotlight list: {specific_file}")
                    return False

            self._log_info(f"Pulling {len(files)} spotlight file(s)...")

            results = self._get_file_extraction_service().pull_spotlight_files(files)
            successful = sum(1 for r in results if r.success)
            self._log_success(
                f"Pulled {successful}/{len(results)} file(s) to results folder"
            )
            return successful > 0

        except Exception as e:
            self._log_error(f"Error pulling spotlight files: {e}")
            return False


__all__ = [
    "SpotlightController",
    "SpotlightFilesAction",
]
