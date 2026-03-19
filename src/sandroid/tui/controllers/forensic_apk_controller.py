"""Forensic APK Controller for TUI.

This controller manages forensic APK operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Handle MVT scan results
- Pull APKs from device
- Manage forensic APK collection
- Install forensic APKs to device

Usage:
    from sandroid.tui.controllers import ForensicAPKController

    controller = ForensicAPKController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        force_ui_refresh=app._force_ui_refresh,
    )

    # Handle MVT result action
    controller.handle_mvt_result(result)
"""

import datetime
import hashlib
import logging
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sandroid.core.enums import ViewMode

logger = logging.getLogger(__name__)


@dataclass
class ForensicAPK:
    """Represents a forensic APK pulled from device."""

    package_name: str
    local_path: str
    md5_hash: str
    severity: str
    ioc_matches: list[dict[str, Any]]


@dataclass
class MVTResult:
    """Result action from MVT results modal.

    Note: This is a simplified representation. The actual modal uses
    MVTResultsAction from sandroid.tui.modals which contains IOCMatch objects.
    """

    action: str  # "close", "pull_all", "select"
    matched_packages: list[str] = None
    matches_by_package: dict[str, list[Any]] = None  # List of IOCMatch objects


class ForensicAPKController:
    """Controller for forensic APK operations.

    This controller handles all forensic APK-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of forensic APK logic from UI rendering
    - Reusable forensic APK management across different UI modes

    Example:
        controller = ForensicAPKController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            force_ui_refresh=lambda: None,
        )

        # Handle MVT result
        controller.handle_mvt_result(mvt_result)
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        get_current_view: Callable[[], str] | None = None,
        scroll_to_bottom: Callable[[], None] | None = None,
        toolbox: Any | None = None,
    ):
        """Initialize ForensicAPKController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            force_ui_refresh: Callback to force UI refresh after state changes
            get_current_view: Callback to get current view mode
            scroll_to_bottom: Callback to scroll activity log to bottom
            toolbox: Optional Toolbox reference
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._force_ui_refresh = force_ui_refresh
        self._get_current_view = get_current_view
        self._scroll_to_bottom = scroll_to_bottom
        self._toolbox = toolbox

        # Session state for warned flags
        self._install_warning_shown = False

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
    # MVT Result Handling
    # =========================================================================

    def handle_mvt_result(self, result) -> None:
        """Handle MVT results modal action.

        Routes to appropriate handler based on action type.

        Args:
            result: MVTResultsAction from modal (has action, matched_packages, matches_by_package)
        """
        if result is None or result.action == "close":
            return

        if result.action == "pull_all":
            # Pull all packages with IOC matches
            packages = result.matched_packages or []
            matches_by_package = result.matches_by_package or {}
            self._pull_apks(packages, matches_by_package)

        elif result.action == "select":
            # Show APK selection modal first
            self._show_apk_selection(
                result.matched_packages or [],
                result.matches_by_package or {},
            )

    def _show_apk_selection(
        self, packages: list[str], matches_by_package: dict[str, list[Any]]
    ) -> None:
        """Show APK selection modal for user to choose packages to pull.

        Args:
            packages: List of package names to show
            matches_by_package: Dict mapping package name to IOCMatch objects
        """
        from sandroid.tui.modals import APKSelectionModal

        if not self._push_modal:
            self._log_error("Cannot show selection modal - push_modal not configured")
            return

        def on_selection(sel_result) -> None:
            """Handle APK selection result."""
            if sel_result.cancelled:
                return
            self._pull_apks(sel_result.selected_packages, sel_result.matches_by_package)

        self._push_modal(
            APKSelectionModal(packages=packages, matches_by_package=matches_by_package),
            on_selection,
        )

    def _pull_apks(
        self, packages: list[str], matches_by_package: dict[str, list[Any]]
    ) -> None:
        """Initiate APK pull workflow.

        Shows folder selection then pulls APKs.

        Args:
            packages: List of packages to pull
            matches_by_package: Dict mapping package name to IOCMatch objects
        """
        from sandroid.tui.modals import (
            FolderSelectModal,
            get_default_forensic_apks_folder,
        )

        if not packages:
            self._log_warning("No packages selected for pull")
            return

        if not self._push_modal:
            self._log_error("Cannot show folder modal - push_modal not configured")
            return

        default_folder = get_default_forensic_apks_folder()

        def on_folder_selected(folder_result) -> None:
            """Handle folder selection result."""
            if folder_result.cancelled:
                return
            self._execute_apk_pull(
                packages, matches_by_package, folder_result.folder_path
            )

        self._push_modal(
            FolderSelectModal(
                title="Select Download Folder",
                description=f"Choose where to save {len(packages)} forensic APKs.",
                default_path=default_folder,
            ),
            on_folder_selected,
        )

    def _execute_apk_pull(
        self,
        packages: list[str],
        matches_by_package: dict[str, list[Any]],
        output_folder: str,
    ) -> int:
        """Execute APK pull operation.

        Uses the Adb class for ADB commands and creates proper ForensicAPK records.

        Args:
            packages: List of packages to pull
            matches_by_package: Dict mapping package name to IOCMatch objects
            output_folder: Destination folder

        Returns:
            Number of APKs successfully pulled
        """
        from pathlib import Path

        from sandroid.core.adb import Adb
        from sandroid.core.device_manager import DeviceManager
        from sandroid.core.toolbox import ForensicAPK, Toolbox

        os.makedirs(output_folder, exist_ok=True)
        dm = DeviceManager.get()
        device = dm.active_device

        self._log_info(f"Pulling {len(packages)} APKs to {output_folder}...")

        pulled_count = 0
        total_packages = len(packages)

        for idx, pkg in enumerate(packages, 1):
            try:
                # Show progress for each APK being pulled
                self._log_info(f"[{idx}/{total_packages}] Pulling: {pkg}...")

                # Get APK path on device
                result, stderr = Adb.send_adb_command(f"shell pm path {pkg}")
                if stderr:
                    logger.warning(f"ADB pm path warning for '{pkg}': {stderr}")
                if not result or "package:" not in result:
                    self._log_warning(f"Could not find APK path for {pkg}")
                    continue

                # Parse path (format: "package:/data/app/...")
                apk_path = result.strip().replace("package:", "")

                # Pull APK
                output_path = Path(output_folder) / f"{pkg}.apk"
                _pull_result, pull_err = Adb.send_adb_command(
                    f"pull '{apk_path}' '{output_path}'"
                )

                if pull_err and "error" in pull_err.lower():
                    self._log_error(f"Failed to pull {pkg}: {pull_err}")
                    continue

                # Calculate hash
                file_hash = ""
                if output_path.exists():
                    file_hash = self._calculate_md5(str(output_path))

                # Get severity from matches
                matches = matches_by_package.get(pkg, [])
                severity = self._extract_severity_from_ioc_matches(matches)

                # Create ForensicAPK record
                forensic_apk = ForensicAPK(
                    package_name=pkg,
                    source_device=device.serial if device else "",
                    source_device_name=device.display_name if device else "Unknown",
                    local_path=str(output_path),
                    pull_timestamp=datetime.datetime.now(),
                    ioc_matches=[
                        m.indicator_value
                        for m in matches
                        if hasattr(m, "indicator_value")
                    ],
                    severity=severity,
                    file_hash=file_hash,
                )

                # Add to session state
                Toolbox.add_forensic_apk(forensic_apk)
                pulled_count += 1

                # Log with forensic indicator
                device_name = device.display_name if device else "Unknown"
                self._log_success(f"Tracked forensic APK: {pkg} from {device_name}")

            except Exception as e:
                self._log_error(f"Error pulling {pkg}: {e}")
                logger.exception(f"Error pulling APK {pkg}")

        self._log_info(f"Successfully pulled {pulled_count}/{total_packages} APKs")

        # Force UI refresh after pulling APKs
        if pulled_count > 0 and self._force_ui_refresh:
            self._force_ui_refresh()

        return pulled_count

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of file.

        Args:
            file_path: Path to file

        Returns:
            MD5 hash string
        """
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating MD5: {e}")
            return "error"

    def _extract_severity_from_ioc_matches(self, matches: list[Any]) -> str:
        """Extract highest severity from IOCMatch objects.

        Args:
            matches: List of IOCMatch objects

        Returns:
            Severity string (critical, high, medium, low)
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        severity = "medium"

        for match in matches:
            # IOCMatch objects have severity attribute (MatchSeverity enum)
            if hasattr(match, "severity"):
                match_sev = (
                    match.severity.value
                    if hasattr(match.severity, "value")
                    else str(match.severity)
                )
                if severity_order.get(match_sev, 99) < severity_order.get(severity, 99):
                    severity = match_sev

        return severity

    # =========================================================================
    # Forensic APK Management
    # =========================================================================

    def get_forensic_apks(self) -> list[ForensicAPK]:
        """Get list of forensic APKs in session.

        Returns:
            List of ForensicAPK objects
        """
        toolbox = self._get_toolbox()
        return toolbox.get_forensic_apks()

    def has_forensic_apks(self) -> bool:
        """Check if there are any forensic APKs.

        Returns:
            True if forensic APKs exist
        """
        return len(self.get_forensic_apks()) > 0

    def handle_shift_g(self) -> bool:
        """Handle Shift+G key press.

        In FORENSIC view, opens forensic APK manager.
        In other views, scrolls to bottom.

        Returns:
            True if action was handled
        """
        if self._get_current_view:
            current_view = self._get_current_view()
            if current_view in (ViewMode.FORENSIC, ViewMode.FORENSIC.value):
                return self.show_forensic_apk_modal()

        # Not in forensic view - scroll to bottom
        if self._scroll_to_bottom:
            self._scroll_to_bottom()
            return True

        return False

    def show_forensic_apk_modal(self) -> bool:
        """Show forensic APK management modal.

        Returns:
            True if modal was shown
        """
        from sandroid.tui.modals import ForensicAPKModal

        forensic_apks = self.get_forensic_apks()

        if not forensic_apks:
            self._log_warning(
                "No forensic APKs available. Run a forensic scan first (F key)."
            )
            return False

        if not self._push_modal:
            self._log_error("Cannot show modal - push_modal not configured")
            return False

        def on_modal_result(result) -> None:
            if result is None:
                return

            if result.action == "install":
                self._handle_install_action(result.apk)
            elif result.action == "delete":
                self._handle_delete_action(result.apk)

        self._push_modal(ForensicAPKModal(apks=forensic_apks), on_modal_result)
        return True

    def _handle_install_action(self, apk: ForensicAPK) -> None:
        """Handle install action from modal.

        Shows warning if not previously shown, then installs.

        Args:
            apk: ForensicAPK to install
        """
        from sandroid.tui.modals import WarningModal

        if not self._install_warning_shown:
            # Show warning first
            def on_warning_result(result) -> None:
                if result.proceed:
                    if result.dont_show_again:
                        self._install_warning_shown = True
                    self._install_forensic_apk(apk)

            if self._push_modal:
                self._push_modal(
                    WarningModal(
                        title="Security Warning",
                        message="Installing this APK may compromise device security. "
                        "Only proceed if you understand the risks.",
                    ),
                    on_warning_result,
                )
        else:
            self._install_forensic_apk(apk)

    def _handle_delete_action(self, apk: ForensicAPK) -> None:
        """Handle delete action from modal.

        Args:
            apk: ForensicAPK to delete from session
        """
        toolbox = self._get_toolbox()
        toolbox.remove_forensic_apk(apk.package_name)
        self._log_info(f"Removed {apk.package_name} from forensic APKs")

        if self._force_ui_refresh:
            self._force_ui_refresh()

    def _install_forensic_apk(self, apk: ForensicAPK) -> bool:
        """Install forensic APK to device.

        Args:
            apk: ForensicAPK to install

        Returns:
            True if installation was successful
        """
        if not os.path.exists(apk.local_path):
            self._log_error(f"APK file not found: {apk.local_path}")
            return False

        try:
            self._log_info(
                f"Installing {apk.package_name}... (this may take up to 2 minutes)"
            )

            result = subprocess.run(
                ["adb", "install", "-r", apk.local_path],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0 and "Success" in result.stdout:
                self._log_success(f"Installed {apk.package_name}")
                return True
            error_msg = result.stderr or result.stdout
            self._log_error(f"Install failed: {error_msg}")
            return False

        except subprocess.TimeoutExpired:
            self._log_error(
                f"Installation of {apk.package_name} timed out after 120 seconds"
            )
            return False
        except Exception as e:
            self._log_error(f"Installation error: {e}")
            return False


__all__ = [
    "ForensicAPK",
    "ForensicAPKController",
    "MVTResult",
]
