"""Forensic Controller for TUI.

This controller manages forensic scanning orchestration, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- IOC configuration management
- Forensic scan execution
- Scan progress tracking
- Result presentation

Usage:
    from sandroid.tui.controllers import ForensicController

    controller = ForensicController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
    )

    # Run forensic evidence scan
    controller.run_forensic_evidence_scan()
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sandroid.core.enums import ViewMode

logger = logging.getLogger(__name__)


@dataclass
class ScanProgress:
    """Progress update from a forensic scan."""

    stage: str
    current: int
    total: int
    message: str = ""


@dataclass
class ScanResult:
    """Result of a forensic scan."""

    success: bool
    detections: list[dict[str, Any]]
    total_scanned: int
    scan_duration_seconds: float
    error: str | None = None


class ForensicController:
    """Controller for forensic scanning orchestration.

    This controller handles forensic evidence scanning operations,
    decoupled from the TUI layer through callback injection.

    Thread Safety:
        Scan operations run in background threads with progress callbacks.
        UI updates should be dispatched to the main thread.

    Example:
        controller = ForensicController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
        )

        # Check if scan can run
        if controller.can_run_forensic_scan():
            controller.run_forensic_evidence_scan()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        update_progress: Callable[[ScanProgress], None] | None = None,
        on_scan_complete: Callable[[ScanResult], None] | None = None,
        toolbox: Any | None = None,
    ):
        """Initialize ForensicController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            update_progress: Callback for scan progress updates
            on_scan_complete: Callback when scan completes
            toolbox: Optional Toolbox reference
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._push_modal = push_modal
        self._update_progress = update_progress
        self._on_scan_complete = on_scan_complete
        self._toolbox = toolbox
        self._scan_in_progress = False

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_toolbox(self) -> Any:
        """Get Toolbox reference."""
        if self._toolbox:
            return self._toolbox
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    # =========================================================================
    # Scan Prerequisites
    # =========================================================================

    def can_run_forensic_scan(
        self, view: str | ViewMode = ViewMode.FORENSIC
    ) -> tuple[bool, str]:
        """Check if forensic scan can run.

        Args:
            view: Current view name or ViewMode enum (retained for caller
                compatibility; no longer used now that view modes are removed).

        Returns:
            Tuple of (can_run, reason_if_not)
        """
        # Check device type
        toolbox = self._get_toolbox()
        if toolbox.is_emulator_device():
            return (
                False,
                "Forensic Evidence scan is disabled on emulators. "
                "Connect a physical device for real forensic analysis.",
            )

        # Check if scan already in progress
        if self._scan_in_progress:
            return False, "A forensic scan is already in progress."

        return True, ""

    def is_scan_in_progress(self) -> bool:
        """Check if a scan is currently running.

        Returns:
            True if scan is in progress
        """
        return self._scan_in_progress

    def has_ioc_configured(self) -> bool:
        """Check if IOC (Indicators of Compromise) are configured.

        Returns:
            True if IOCs are available for scanning
        """
        try:
            from sandroid.core.forensic_evidence import ForensicEvidence

            fe = ForensicEvidence.get()
            return fe.is_configured()
        except Exception as e:
            logger.debug(f"Error checking IOC configuration: {e}")
            return False

    def has_cached_iocs(self) -> dict[str, Any] | None:
        """Check for cached IOCs.

        Returns:
            Cached IOC info dict if available, None otherwise
        """
        try:
            from sandroid.core.ioc_downloader import IOCDownloader

            downloader = IOCDownloader()
            return downloader.get_cached_iocs_info()
        except Exception as e:
            logger.debug(f"Error checking cached IOCs: {e}")
            return None

    def has_remembered_ioc_choice(self) -> bool:
        """Check if user has saved IOC choice preference.

        Returns:
            True if user chose to remember IOC preference
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return bool(config.mvt.remember_ioc_choice and config.mvt.ioc_path)
        except Exception:
            return False

    # =========================================================================
    # IOC Configuration
    # =========================================================================

    def save_ioc_config(
        self,
        ioc_path: str | None = None,
        ioc_url: str | None = None,
        remember_choice: bool = False,
    ) -> bool:
        """Save IOC configuration.

        Args:
            ioc_path: Local path to IOC files
            ioc_url: URL to download IOCs from
            remember_choice: Whether to remember this choice

        Returns:
            True if saved successfully
        """
        try:
            updates: dict[str, Any] = {}
            if ioc_path:
                updates["ioc_path"] = ioc_path
            if ioc_url:
                updates["ioc_url"] = ioc_url
            if remember_choice:
                updates["remember_ioc_choice"] = True

            self._load_and_update_mvt_config(updates)
            self._log_info("IOC configuration saved")
            return True

        except Exception as e:
            logger.error(f"Failed to save IOC config: {e}")
            return False

    def reset_forensic_evidence(self) -> None:
        """Reset ForensicEvidence to reload configuration."""
        try:
            from sandroid.core.forensic_evidence import ForensicEvidence

            ForensicEvidence.reset()
        except Exception as e:
            logger.debug(f"Error resetting ForensicEvidence: {e}")

    # =========================================================================
    # Scan Execution
    # =========================================================================

    def run_forensic_evidence_scan(
        self,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        completion_callback: Callable[[ScanResult], None] | None = None,
    ) -> bool:
        """Run forensic evidence scan in background.

        Args:
            progress_callback: Called with progress updates
            completion_callback: Called when scan completes

        Returns:
            True if scan was started successfully
        """
        if self._scan_in_progress:
            self._log_warning("A scan is already in progress")
            return False

        self._scan_in_progress = True
        progress_cb = progress_callback or self._update_progress
        complete_cb = completion_callback or self._on_scan_complete

        def run_scan():
            import time

            start_time = time.time()

            try:
                from sandroid.core.forensic_evidence import ForensicEvidence

                fe = ForensicEvidence.get()

                # Report progress
                if progress_cb:
                    progress_cb(
                        ScanProgress(
                            stage="initializing",
                            current=0,
                            total=100,
                            message="Initializing forensic scan...",
                        )
                    )

                # Run the scan with progress tracking
                def fe_progress(progress):
                    if progress_cb:
                        progress_cb(
                            ScanProgress(
                                stage=progress.stage,
                                current=progress.current,
                                total=progress.total,
                                message=progress.message,
                            )
                        )

                results = fe.run_scan(progress_callback=fe_progress)

                duration = time.time() - start_time

                scan_result = ScanResult(
                    success=True,
                    detections=results.get("detections", []),
                    total_scanned=results.get("total_scanned", 0),
                    scan_duration_seconds=duration,
                )

                if complete_cb:
                    complete_cb(scan_result)

            except Exception as e:
                logger.exception(f"Forensic scan failed: {e}")
                duration = time.time() - start_time

                scan_result = ScanResult(
                    success=False,
                    detections=[],
                    total_scanned=0,
                    scan_duration_seconds=duration,
                    error=str(e),
                )

                if complete_cb:
                    complete_cb(scan_result)

            finally:
                self._scan_in_progress = False

        # Run in background thread
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        self._log_info("Forensic evidence scan started")
        return True

    def cancel_scan(self) -> bool:
        """Cancel running scan if possible.

        Returns:
            True if scan was cancelled
        """
        if not self._scan_in_progress:
            return False

        # Note: Actual cancellation would need to be implemented
        # in ForensicEvidence class with cooperative cancellation
        self._log_warning("Scan cancellation requested (may not stop immediately)")
        return True

    # =========================================================================
    # Full Workflow Methods (for TUI integration)
    # =========================================================================

    def show_forensic_evidence_modal(
        self,
        get_current_view: Callable[[], str],
        run_worker: Callable,
        call_from_thread: Callable,
        force_ui_refresh: Callable,
        on_mvt_result: Callable,
    ) -> bool:
        """Show forensic evidence modal workflow.

        This orchestrates the full forensic evidence scan workflow:
        1. Check prerequisites (view, device type)
        2. Check for cached IOCs or remembered preferences
        3. Show appropriate modal (IOC choice, IOC setup)
        4. Run scan with progress modal
        5. Show results

        Args:
            get_current_view: Callback to get current view
            run_worker: Callback to run background worker
            call_from_thread: Callback to execute on main thread
            force_ui_refresh: Callback to refresh UI
            on_mvt_result: Callback for MVT result actions

        Returns:
            True if workflow was started
        """
        from sandroid.core.forensic_evidence import ForensicEvidence
        from sandroid.tui.modals import (
            IOCChoiceModal,
            IOCSetupModal,
        )

        # Check prerequisites
        current_view = get_current_view()
        can_run, reason = self.can_run_forensic_scan(current_view)
        if not can_run:
            self._log_warning(reason)
            return False

        # Check for remembered choice
        if self.has_remembered_ioc_choice():
            self._run_forensic_scan_workflow(
                run_worker, call_from_thread, force_ui_refresh, on_mvt_result
            )
            return True

        # Check for cached IOCs
        cached_info = self.has_cached_iocs()

        # Setup modal callback
        def on_ioc_setup(setup_result) -> None:
            if setup_result.cancelled:
                return

            # Save configuration
            self._save_ioc_config_from_setup(setup_result)

            # Reset and run scan
            self.reset_forensic_evidence()
            self._run_forensic_scan_workflow(
                run_worker, call_from_thread, force_ui_refresh, on_mvt_result
            )

        if cached_info is None:
            # No cached IOCs - go directly to IOC setup modal
            if self._push_modal:
                self._push_modal(IOCSetupModal(), on_ioc_setup)
            return True

        # Show IOC choice modal
        def on_ioc_choice(result) -> None:
            if result.cancelled:
                return

            # Save preference if user checked "remember"
            if result.remember_choice:
                self._save_ioc_preference(result.use_cached)

            if result.use_cached:
                # Use cached IOCs - ensure ForensicEvidence is configured
                fe = ForensicEvidence.get()
                if not fe.is_configured():
                    self._save_cached_ioc_path(cached_info.get("path"))
                    self.reset_forensic_evidence()
                self._run_forensic_scan_workflow(
                    run_worker, call_from_thread, force_ui_refresh, on_mvt_result
                )
            # Configure new IOCs
            elif self._push_modal:
                self._push_modal(IOCSetupModal(), on_ioc_setup)

        if self._push_modal:
            self._push_modal(IOCChoiceModal(cached_info=cached_info), on_ioc_choice)
        return True

    def _load_and_update_mvt_config(self, updates: dict[str, Any]) -> bool:
        """Load config, apply MVT section updates, and save.

        Args:
            updates: Key-value pairs to set under config_dict["mvt"].

        Returns:
            True if config was saved successfully.
        """
        from sandroid.config.loader import ConfigLoader

        loader = ConfigLoader()
        loader.load_and_update_section("mvt", updates)
        return True

    def _save_ioc_config_from_setup(self, setup_result) -> None:
        """Save IOC configuration from setup modal result.

        Args:
            setup_result: IOCSetupResult from setup modal
        """
        try:
            updates: dict[str, Any] = {"enabled": True}

            if setup_result.source_type == "path":
                updates["ioc_path"] = setup_result.value
            elif setup_result.source_type == "url":
                from sandroid.core.ioc_downloader import IOCDownloader

                downloader = IOCDownloader()
                downloaded_path = downloader.download_from_url(setup_result.value)
                if downloaded_path:
                    updates["ioc_path"] = str(downloaded_path)
                updates["ioc_url"] = setup_result.value
                updates["auto_update_iocs"] = setup_result.auto_update
                if not downloaded_path:
                    self._log_warning(
                        "Failed to download IOC file, URL saved for retry"
                    )
            elif setup_result.source_type == "mvt_download":
                from sandroid.core.ioc_downloader import IOCDownloader

                downloader = IOCDownloader()
                ioc_path = downloader.download_mvt_iocs()
                if ioc_path:
                    updates["ioc_path"] = str(ioc_path)
                    self._log_info(f"Downloaded MVT IOCs to: {ioc_path}")
                else:
                    self._log_error("Failed to download MVT IOCs")
                    return

            self._load_and_update_mvt_config(updates)
            self._log_info("IOC configuration saved")

        except Exception as e:
            self._log_error(f"Failed to save IOC config: {e}")

    def _save_ioc_preference(self, use_cached: bool) -> None:
        """Save IOC source preference to config.

        Args:
            use_cached: Whether user prefers to use cached IOCs
        """
        try:
            self._load_and_update_mvt_config({"remember_ioc_choice": True})
            self._log_info("IOC preference saved")
        except Exception as e:
            logger.debug(f"Failed to save IOC preference: {e}")

    def _save_cached_ioc_path(self, cached_path: str) -> None:
        """Save cached IOC path to config.

        Args:
            cached_path: Path to cached IOCs
        """
        try:
            self._load_and_update_mvt_config({"enabled": True, "ioc_path": cached_path})
        except Exception as e:
            logger.debug(f"Failed to save cached IOC path: {e}")

    def _run_forensic_scan_workflow(
        self,
        run_worker: Callable,
        call_from_thread: Callable,
        force_ui_refresh: Callable,
        on_mvt_result: Callable,
    ) -> None:
        """Run the forensic evidence scan with progress modal.

        Args:
            run_worker: Callback to run background worker
            call_from_thread: Callback to execute on main thread
            force_ui_refresh: Callback to refresh UI
            on_mvt_result: Callback for MVT result actions
        """
        from sandroid.core.forensic_evidence import ForensicEvidence
        from sandroid.core.forensic_evidence import ScanProgress as FEScanProgress
        from sandroid.tui.modals import MVTResultsModal, ScanProgressModal

        fe = ForensicEvidence.get()

        self._log_info("Starting forensic evidence scan...")

        # Load IOCs
        if not fe.load_iocs():
            self._log_error("Failed to load IOC indicators")
            return

        self._log_info(f"Loaded {fe.total_indicators} IOC indicators")

        # Create progress modal
        progress_modal = ScanProgressModal()
        scan_results = []

        def run_scan_with_progress():
            """Run the scan in a worker thread with progress updates."""

            def progress_callback(progress: FEScanProgress):
                if progress_modal.cancelled:
                    return

                call_from_thread(
                    progress_modal.update_progress,
                    scan_type=progress.scan_type,
                    current=progress.current,
                    total=progress.total,
                    item=progress.item,
                    message=progress.message,
                )

            results = fe.run_scan(progress_callback=progress_callback)
            scan_results.extend(results)

            if not progress_modal.cancelled:
                call_from_thread(progress_modal.mark_complete)

        def on_progress_modal_result(result):
            """Handle progress modal completion."""
            if result and result.cancelled:
                self._log_warning("Forensic scan cancelled by user")
                return

            if scan_results:
                total_matches = sum(len(r.matches) for r in scan_results)
                if total_matches > 0:
                    self._log_warning(
                        f"Forensic scan complete: {total_matches} potential IOC matches found!"
                    )
                else:
                    self._log_info(
                        "Forensic scan complete: No indicators of compromise found"
                    )

                def handle_mvt_result(mvt_result) -> None:
                    if mvt_result is None or mvt_result.action == "close":
                        return
                    on_mvt_result(mvt_result)

                if self._push_modal:
                    self._push_modal(
                        MVTResultsModal(results=scan_results), handle_mvt_result
                    )

        # Show progress modal and start scan
        if self._push_modal:
            self._push_modal(progress_modal, on_progress_modal_result)

        # Run scan in background worker
        run_worker(
            run_scan_with_progress,
            name="forensic_scan",
            exclusive=False,
            thread=True,
        )


__all__ = [
    "ForensicController",
    "ScanProgress",
    "ScanResult",
]
