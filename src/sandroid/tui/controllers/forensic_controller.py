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


class _ScanAborted(BaseException):
    """Unwinds a running forensic scan when the user requests cancellation.

    Subclasses ``BaseException`` (not ``Exception``) deliberately: the scan
    strategies wrap their per-item loops in ``except Exception``, so a plain
    exception raised from the progress callback would be swallowed and the scan
    would keep going. ``BaseException`` bypasses those handlers and unwinds the
    strategy cleanly, so cancellation actually stops the work in progress.
    """


# Run the scan one stage at a time (each dict enables exactly one strategy via
# ForensicEvidence.run_scan's flags). Lets the inline runner check for cancel
# between stages and keep results from the stages that already finished.
_SCAN_STAGES = (
    {"scan_apps": True, "scan_sms": False, "scan_calls": False, "scan_files": False},
    {"scan_apps": False, "scan_sms": True, "scan_calls": False, "scan_files": False},
    {"scan_apps": False, "scan_sms": False, "scan_calls": True, "scan_files": False},
    {"scan_apps": False, "scan_sms": False, "scan_calls": False, "scan_files": True},
)


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
        # Set by cancel_scan(); checked by the inline-scan progress callback so a
        # running scan stops feeding the UI. Best-effort: the in-flight strategy
        # still finishes (the engine has no mid-strategy cancellation).
        self._cancel_event = threading.Event()

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
        """Request cancellation of a running scan (cooperative, best-effort).

        Sets the cancel event so the inline-scan progress callback stops feeding
        the UI and the completion is reported as cancelled. The engine has no
        mid-strategy cancellation, so the currently-running scan stage still
        finishes before the scan thread exits.

        Returns:
            True if a scan was in progress and cancellation was requested.
        """
        if not self._scan_in_progress:
            return False

        self._cancel_event.set()
        self._log_warning("Scan cancellation requested (may not stop immediately)")
        return True

    def run_forensic_scan_inline(
        self,
        run_worker: Callable,
        call_from_thread: Callable,
        on_progress: Callable,
        on_complete: Callable,
        on_error: Callable,
    ) -> bool:
        """Run a forensic scan, streaming progress to in-tab callbacks (no modals).

        This is the non-modal sibling of ``_run_forensic_scan_workflow``: it
        loads IOCs and runs ``ForensicEvidence.run_scan`` on a worker thread, but
        routes progress/results to the Forensic panel instead of
        ``ScanProgressModal`` / ``MVTResultsModal``.

        Thread-safety: ``ForensicEvidence.run_scan``'s progress callback fires on
        the scan worker thread, so ``on_progress`` / ``on_complete`` / ``on_error``
        are marshalled onto the Textual main thread via ``call_from_thread`` (the
        same proven path the modal workflow uses). The scan worker is the only
        producer thread, so ``call_from_thread`` here never deadlocks.

        Args:
            run_worker: App.run_worker (used with thread=True).
            call_from_thread: App.call_from_thread (worker -> main marshaller).
            on_progress: Called (main thread) with a core ``ScanProgress``.
            on_complete: Called (main thread) with (results, cancelled).
            on_error: Called (main thread) with an error message string.

        Returns:
            True if the scan was started.
        """
        can_run, reason = self.can_run_forensic_scan()
        if not can_run:
            self._log_warning(reason)
            on_error(reason)
            return False

        from sandroid.core.forensic_evidence import ForensicEvidence

        fe = ForensicEvidence.get()
        if not fe.load_iocs():
            msg = "Failed to load IOC indicators"
            self._log_error(msg)
            on_error(msg)
            return False

        self._scan_in_progress = True
        self._cancel_event.clear()
        self._log_info(f"Loaded {fe.total_indicators} IOC indicators")

        def progress_callback(progress) -> None:
            # Cancellation is cooperative: raise out of the scan so the running
            # strategy (e.g. the long FILES hashing loop) actually stops instead
            # of merely going quiet. _ScanAborted subclasses BaseException so the
            # strategies' ``except Exception`` blocks do not swallow it.
            if self._cancel_event.is_set():
                raise _ScanAborted
            call_from_thread(on_progress, progress)

        def work() -> None:
            results: list = []
            aborted = False
            error: str | None = None
            try:
                # Run one stage at a time (via run_scan's per-stage flags) so a
                # cancel is honoured between stages AND mid-stage, while matches
                # already found in completed stages are preserved.
                for flags in _SCAN_STAGES:
                    if self._cancel_event.is_set():
                        aborted = True
                        break
                    try:
                        results.extend(
                            fe.run_scan(progress_callback=progress_callback, **flags)
                        )
                    except _ScanAborted:
                        aborted = True
                        break
            except Exception as exc:
                logger.exception(f"Inline forensic scan failed: {exc}")
                error = str(exc)
            finally:
                # Clear the guard BEFORE delivering the outcome so the panel
                # renders the completed state (not a stuck "scanning" header).
                self._scan_in_progress = False

            if error is not None:
                try:
                    call_from_thread(on_error, error)
                except Exception:
                    pass
            else:
                cancelled = aborted or self._cancel_event.is_set()
                call_from_thread(on_complete, results, cancelled)

        run_worker(work, name="forensic_scan_inline", exclusive=False, thread=True)
        self._log_info("Forensic evidence scan started")
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

        # Present the IOC choice/setup modals, then run the scan once a usable
        # IOC source is selected. The modal routing is shared with the Forensic
        # tab's "configure" action via _present_ioc_config.
        self._present_ioc_config(
            push_modal=self._push_modal,
            then=lambda: self._run_forensic_scan_workflow(
                run_worker, call_from_thread, force_ui_refresh, on_mvt_result
            ),
        )
        return True

    def configure_iocs_only(self, push_modal: Callable, on_done: Callable) -> None:
        """Show the IOC choice/setup modals WITHOUT starting a scan.

        Used by the Forensic tab's "configure" (c) action so an analyst can
        inspect or switch the IOC source independently of running a scan.
        ``on_done`` runs (main thread) only after a usable IOC source has been
        selected/saved — never on cancel.

        Args:
            push_modal: Callback to push a modal screen with a result callback.
            on_done: Called after IOCs are configured (e.g. refresh the header).
        """
        self._present_ioc_config(push_modal=push_modal, then=on_done)

    def _present_ioc_config(self, push_modal: Callable, then: Callable) -> None:
        """Drive the IOC choice/setup modal flow, then call ``then``.

        Shared by ``show_forensic_evidence_modal`` (then = run the scan) and
        ``configure_iocs_only`` (then = refresh the panel). ``then`` is invoked
        only after the user selects cached IOCs or saves a new source; it is
        never called when the user cancels.
        """
        from sandroid.core.forensic_evidence import ForensicEvidence
        from sandroid.tui.modals import IOCChoiceModal, IOCSetupModal

        if not push_modal:
            return

        cached_info = self.has_cached_iocs()

        def on_ioc_setup(setup_result) -> None:
            if setup_result.cancelled:
                return
            self._save_ioc_config_from_setup(setup_result)
            self.reset_forensic_evidence()
            then()

        if cached_info is None:
            # No cached IOCs - go directly to IOC setup modal.
            push_modal(IOCSetupModal(), on_ioc_setup)
            return

        def on_ioc_choice(result) -> None:
            if result.cancelled:
                return
            if result.remember_choice:
                self._save_ioc_preference(result.use_cached)
            if result.use_cached:
                # Use cached IOCs - ensure ForensicEvidence is configured.
                fe = ForensicEvidence.get()
                if not fe.is_configured():
                    self._save_cached_ioc_path(cached_info.get("path"))
                    self.reset_forensic_evidence()
                then()
            else:
                push_modal(IOCSetupModal(), on_ioc_setup)

        push_modal(IOCChoiceModal(cached_info=cached_info), on_ioc_choice)

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
                # Absolutize relative paths now (CWD is correct at save time) so
                # the scan still finds the IOCs if the working dir later changes.
                from pathlib import Path

                raw = Path(str(setup_result.value)).expanduser()
                try:
                    if raw.exists():
                        raw = raw.resolve()
                except OSError:
                    pass
                updates["ioc_path"] = str(raw)
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
