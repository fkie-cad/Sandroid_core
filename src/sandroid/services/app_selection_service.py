"""App Selection Service for Sandroid.

This service handles application listing, filtering, and interactive selection.
Extracted from Toolbox class to follow Single Responsibility Principle.

Supports both CLI and TUI modes through callback-based UI interaction,
allowing the service to be tested independently of the UI.

Usage:
    from sandroid.services import get_app_selection_service
    from sandroid.services.app_selection_service import AppSelectionService

    # Get service
    app_selection = get_app_selection_service()

    # Get installed packages
    packages = app_selection.get_installed_packages()

    # Filter packages
    filtered = app_selection.filter_packages("chrome", packages)

    # Get package info
    info = app_selection.get_package_info("com.android.chrome")

    # Interactive selection (CLI mode)
    selected = app_selection.select_app_with_fuzzy_search()

    # With dependency injection for testing
    mock_adb = Mock()
    service = AppSelectionService(adb=mock_adb)
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from sandroid.services.app_selection_flows import (
    CLISelectionFlow,
    FuzzyFilterOperation,
    resolve_package_list,
)
from sandroid.services.app_selection_parsers import PackageInfoParser, get_parser
from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


def _package_sort_key(pkg: dict[str, Any]) -> tuple[str, str]:
    """Sort key for ordering packages by install date (newest first), then name."""
    return (pkg.get("install_date") or "", pkg.get("package_name", ""))


# ===========================================================================
# Protocols for Dependency Injection
# ===========================================================================


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def get_installed_packages(user_only: bool = False) -> list[dict[str, Any]]:
        """Get installed packages from device."""
        ...

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return (stdout, stderr)."""
        ...


class UICallbackProtocol(Protocol):
    """Protocol for UI callback functions used in interactive selection."""

    def __call__(
        self,
        packages: list[dict[str, Any]],
        title: str,
        default_package: str | None,
        show_fuzzy_option: bool,
    ) -> str | None:
        """Display packages and get user selection.

        Args:
            packages: List of package dictionaries
            title: Title for the selection dialog
            default_package: Package to highlight/suggest
            show_fuzzy_option: Whether to show fuzzy search option

        Returns:
            Selected package name, or None if cancelled
        """
        ...


# ===========================================================================
# Data Classes
# ===========================================================================


@dataclass
class PackageInfo:
    """Information about an installed package.

    Attributes:
        package_name: Android package name (e.g., "com.example.app")
        install_date: First installation timestamp
        is_user_app: Whether this is a user-installed app (not system)
        version_name: Version name string
        version_code: Version code integer
        target_sdk: Target SDK version
        min_sdk: Minimum SDK version
        apk_path: Path to APK on device
        data_dir: Path to app data directory
    """

    package_name: str
    install_date: str | None = None
    is_user_app: bool = True
    version_name: str | None = None
    version_code: int | None = None
    target_sdk: int | None = None
    min_sdk: int | None = None
    apk_path: str | None = None
    data_dir: str | None = None


@dataclass
class SelectionResult:
    """Result of an app selection operation.

    Attributes:
        package_name: Selected package name, or None if cancelled
        cancelled: Whether the selection was cancelled
        filter_applied: The filter that was applied (if any)
        show_system: Whether system apps were included
    """

    package_name: str | None = None
    cancelled: bool = False
    filter_applied: str | None = None
    show_system: bool = False


# ===========================================================================
# Service Implementation
# ===========================================================================


class AppSelectionService:
    """Service for listing, filtering, and selecting Android applications.

    This service extracts app selection logic from Toolbox, providing:
    - Package listing with filtering options
    - Fuzzy search filtering
    - Interactive selection with CLI/TUI support
    - Package info retrieval

    Thread Safety:
        Operations are thread-safe for basic get operations.

    Example:
        service = AppSelectionService()

        # List user-installed apps
        packages = service.get_installed_packages(user_only=True)

        # Filter packages
        matches = service.filter_packages("chrome", packages)

        # Get detailed info
        info = service.get_package_info("com.android.chrome")
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize the AppSelectionService.

        Args:
            adb: Optional ADB interface for dependency injection.
                 If not provided, uses the global Adb class.
            event_bus: Optional EventBus for publishing state change events.
        """
        self._adb = adb
        self._event_bus = event_bus
        self._logger = logger
        self._fuzzy_op = FuzzyFilterOperation()
        self._parser: PackageInfoParser = get_parser()
        self._package_cache: dict[bool, list[dict[str, Any]]] = {}

    @property
    def _has_fuzzy(self) -> bool | None:
        """Proxy that reads from the FuzzyFilterOperation.

        Kept for backward compatibility — tests may read/write this attribute.
        """
        return self._fuzzy_op._has_fuzzy

    @_has_fuzzy.setter
    def _has_fuzzy(self, value: bool | None) -> None:
        """Proxy that writes to the FuzzyFilterOperation."""
        self._fuzzy_op._has_fuzzy = value

    # =========================================================================
    # ADB Access (with DI fallback)
    # =========================================================================

    def _get_adb(self) -> AdbProtocol:
        """Get the ADB interface.

        Returns injected ADB if available, otherwise falls back to global Adb.

        Returns:
            ADB interface
        """
        if self._adb is not None:
            return self._adb

        # Fallback to global Adb class
        from sandroid.core.adb import Adb

        return Adb

    # =========================================================================
    # Package Listing
    # =========================================================================

    def get_installed_packages(
        self,
        user_only: bool = True,
        sort_by_date: bool = True,
    ) -> list[dict[str, Any]]:
        """Get list of installed packages from the device.

        Args:
            user_only: If True, only return user-installed apps (not system apps)
            sort_by_date: If True, sort packages by install date (newest first)

        Returns:
            List of package dictionaries with keys:
            - package_name: str
            - install_date: str or None
            - is_user_app: bool
        """
        # Check session-scoped cache
        if user_only in self._package_cache:
            cached = list(self._package_cache[user_only])
            self._logger.debug(f"Cache hit: {len(cached)} packages")
            if sort_by_date:
                cached.sort(key=_package_sort_key, reverse=True)
            return cached

        adb = self._get_adb()
        self._logger.info(
            f"Fetching {'user-installed' if user_only else 'all'} packages..."
        )

        try:
            packages = adb.get_installed_packages(user_only=user_only)

            # Store a copy in session cache (avoid mutation by callers)
            self._package_cache[user_only] = list(packages) if packages else []

            if not packages:
                self._logger.debug("No packages found on device")
                return []

            if sort_by_date:
                packages.sort(key=_package_sort_key, reverse=True)

            self._logger.info(f"Found {len(packages)} packages")
            return packages

        except (OSError, RuntimeError, AttributeError, TypeError, IndexError) as e:
            self._logger.error(f"Error fetching packages: {e}")
            return []

    def get_package_names(
        self,
        user_only: bool = True,
    ) -> list[str]:
        """Get list of installed package names only.

        Convenience method that returns just the package names.

        Args:
            user_only: If True, only return user-installed apps

        Returns:
            List of package name strings
        """
        packages = self.get_installed_packages(user_only=user_only, sort_by_date=False)
        return [p.get("package_name", "") for p in packages if p.get("package_name")]

    def get_installed_packages_with_fallback(
        self,
        prefer_user_only: bool = True,
        sort_by_date: bool = True,
        on_status: Callable[[str], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Get installed packages with automatic fallback to all packages.

        If prefer_user_only is True and no user packages are found,
        automatically falls back to fetching all packages (including system).

        Args:
            prefer_user_only: If True, try user-only first, then fall back to all.
            sort_by_date: If True, sort packages by install date (newest first).
            on_status: Optional callback for live progress updates.

        Returns:
            List of package dictionaries.
        """
        if on_status:
            on_status("Enumerating user-installed apps on device...")
        packages = self.get_installed_packages(
            user_only=prefer_user_only, sort_by_date=sort_by_date
        )
        if packages or not prefer_user_only:
            return packages
        # Fallback to all packages
        if on_status:
            on_status("No user apps found. Checking all installed apps...")
        self._logger.info("No user apps found, falling back to all packages")
        all_pkgs = self.get_installed_packages(
            user_only=False, sort_by_date=sort_by_date
        )
        if not all_pkgs:
            self._logger.warning("No packages found on device (user or system)")
        return all_pkgs

    def flush_package_cache(self) -> None:
        """Clear all cached package data. Called from settings by the user."""
        self._package_cache.clear()
        self._logger.info("Package cache flushed")

    def add_package_to_cache(self, package_name: str) -> None:
        """Add a newly installed package to all existing caches.

        Called after APK installation to update cache without full re-fetch.
        """
        new_entry: dict[str, Any] = {"package_name": package_name, "install_date": None}
        try:
            adb = self._get_adb()
            output, _ = adb.send_adb_command(
                f"shell dumpsys package {package_name} | grep firstInstallTime"
            )
            parsed = self._parser.parse(output)
            if parsed.get("install_date"):
                new_entry["install_date"] = parsed["install_date"]
        except (
            OSError,
            ValueError,
            KeyError,
            AttributeError,
            TypeError,
            IndexError,
        ) as exc:
            self._logger.debug(
                f"Could not fetch install date for {package_name}: {exc}"
            )

        for key in list(self._package_cache.keys()):
            existing_names = {p.get("package_name") for p in self._package_cache[key]}
            if package_name not in existing_names:
                self._package_cache[key].append(new_entry)
                self._logger.debug(f"Added {package_name} to cache[user_only={key}]")

    # =========================================================================
    # Package Filtering
    # =========================================================================

    def filter_packages(
        self,
        query: str,
        packages: list[dict[str, Any]] | None = None,
        min_score: int = 50,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Filter packages using fuzzy string matching.

        Uses the thefuzz library for fuzzy matching. Falls back to simple
        substring matching if thefuzz is not available.

        Args:
            query: Search query string
            packages: List of packages to filter (fetches if None)
            min_score: Minimum fuzzy match score (0-100)
            limit: Maximum number of results to return

        Returns:
            List of matching packages, sorted by relevance
        """
        if not query:
            return packages if packages else []

        if packages is None:
            packages = self.get_installed_packages()

        if not packages:
            return []

        return self._fuzzy_op.filter_packages(query, packages, min_score, limit)

    def filter_package_names(
        self,
        query: str,
        packages: list[str],
        min_score: int = 50,
        limit: int = 20,
    ) -> list[str]:
        """Filter package name strings using fuzzy matching.

        Simpler version that works with just package names.

        Args:
            query: Search query string
            packages: List of package name strings
            min_score: Minimum fuzzy match score (0-100)
            limit: Maximum number of results

        Returns:
            List of matching package names
        """
        if not query or not packages:
            return packages[:limit] if packages else []

        return self._fuzzy_op.filter_names(query, packages, min_score, limit)

    def _check_fuzzy_available(self) -> bool:
        """Check if fuzzy matching library is available.

        Caches the result for efficiency.

        Returns:
            True if thefuzz is available
        """
        return self._fuzzy_op.is_available()

    def _fuzzy_filter(
        self,
        query: str,
        packages: list[dict[str, Any]],
        min_score: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Delegate to FuzzyFilterOperation (kept for backward compatibility)."""
        return self._fuzzy_op._fuzzy_filter(query, packages, min_score, limit)

    def _simple_filter(
        self,
        query: str,
        packages: list[dict[str, Any]],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Delegate to FuzzyFilterOperation (kept for backward compatibility)."""
        return self._fuzzy_op._simple_filter(query, packages, limit)

    # =========================================================================
    # Package Information
    # =========================================================================

    def get_package_info(self, package_name: str) -> PackageInfo | None:
        """Get detailed information about a package.

        Args:
            package_name: Android package name

        Returns:
            PackageInfo object with package details, or None if not found
        """
        adb = self._get_adb()

        try:
            # Get package dump
            output, error = adb.send_adb_command(
                f"shell dumpsys package {package_name}"
            )

            if error or "Unable to find package" in output:
                self._logger.warning(f"Package not found: {package_name}")
                return None

            # Parse package info using the unified parser
            info = PackageInfo(package_name=package_name)
            parsed = self._parser.parse(output)

            # Apply parsed values to the dataclass
            for field_name, value in parsed.items():
                setattr(info, field_name, value)

            # Check if system app
            info.is_user_app = self._parser.is_user_app(output)

            return info

        except (
            OSError,
            ValueError,
            KeyError,
            AttributeError,
            TypeError,
            IndexError,
        ) as e:
            self._logger.error(f"Error getting package info for {package_name}: {e}")
            return None

    def package_exists(self, package_name: str) -> bool:
        """Check if a package is installed on the device.

        Args:
            package_name: Android package name to check

        Returns:
            True if the package is installed
        """
        adb = self._get_adb()

        try:
            output, error = adb.send_adb_command(f"shell pm path {package_name}")
            return not error and "package:" in output

        except (OSError, RuntimeError, AttributeError, TypeError, IndexError) as e:
            self._logger.error(f"Error checking package existence: {e}")
            return False

    # =========================================================================
    # Interactive Selection
    # =========================================================================

    def select_app_with_fuzzy_search(
        self,
        packages: list[str] | None = None,
        title: str = "Select Application",
        recently_installed_package: str | None = None,
        ui_callback: UICallbackProtocol | None = None,
        show_system: bool = False,
    ) -> str | None:
        """Interactive app selection with fuzzy search capability.

        This method supports both CLI and TUI modes through callbacks.
        For CLI mode, it provides a Rich-based interactive selection.
        For TUI mode, it can use a custom callback or the default TUI modal.

        Args:
            packages: Optional list of package names to select from.
                     If None, fetches installed packages.
            title: Title for the selection dialog
            recently_installed_package: Package to highlight/suggest
            ui_callback: Optional callback for custom UI interaction
            show_system: Whether to include system apps

        Returns:
            Selected package name, or None if cancelled
        """
        # Check for TUI mode
        from sandroid.core.ui_request_bus import UIRequestBus

        bus = UIRequestBus.get()
        if bus.has_active_handler():
            return self._select_app_tui(
                packages=packages,
                title=title,
                recently_installed_package=recently_installed_package,
                show_system=show_system,
            )

        # Use custom UI callback if provided
        if ui_callback is not None:
            pkg_list = self._prepare_packages_for_ui(packages, show_system)
            return ui_callback(
                packages=pkg_list,
                title=title,
                default_package=recently_installed_package,
                show_fuzzy_option=self._check_fuzzy_available(),
            )

        # Fall back to CLI selection
        return self._select_app_cli(
            packages=packages,
            title=title,
            recently_installed_package=recently_installed_package,
            show_system=show_system,
        )

    def _prepare_packages_for_ui(
        self,
        packages: list[str] | None,
        show_system: bool,
    ) -> list[dict[str, Any]]:
        """Prepare package list for UI display.

        Args:
            packages: Optional package name list
            show_system: Whether to include system apps

        Returns:
            List of package dictionaries
        """
        if packages is not None:
            # Convert string list to dict format
            return [{"package_name": p, "install_date": None} for p in packages]

        return self.get_installed_packages(user_only=not show_system)

    def _select_app_tui(
        self,
        packages: list[str] | None,
        title: str,
        recently_installed_package: str | None,
        show_system: bool,
    ) -> str | None:
        """Select app using TUI modal.

        Args:
            packages: Optional package list
            title: Dialog title
            recently_installed_package: Package to suggest
            show_system: Include system apps

        Returns:
            Selected package name or None
        """
        try:
            from sandroid.core.ui_request_bus import request_modal, show_warning
            from sandroid.tui.modals.app_selection_modal import AppSelectionModal

            def load_packages(include_system: bool) -> list:
                return self.get_installed_packages_with_fallback(
                    prefer_user_only=not include_system
                )

            # Build initial loader that resolves packages with fallback logic
            def initial_loader(on_status=None) -> list:
                return self.get_installed_packages_with_fallback(
                    prefer_user_only=not show_system,
                    on_status=on_status,
                )

            default_package = recently_installed_package

            # Show modal immediately with empty list; packages load async inside
            result = request_modal(
                AppSelectionModal,
                title=title,
                packages=[],
                default_package=default_package,
                package_loader=load_packages,
                include_system_apps=show_system,
                initial_loader=initial_loader,
            )

            if result is None or result.cancelled:
                self._logger.info("Selection cancelled")
                return None

            self._logger.info(f"Selected: {result.package_name}")
            return result.package_name

        except Exception as e:
            self._logger.error(f"Error during TUI app selection: {e}")
            return None

    def _select_app_cli(
        self,
        packages: list[str] | None,
        title: str,
        recently_installed_package: str | None,
        show_system: bool,
    ) -> str | None:
        """Select app using CLI interactive selection.

        Delegates to CLISelectionFlow for the actual interaction.

        Args:
            packages: Optional package list
            title: Dialog title
            recently_installed_package: Package to suggest
            show_system: Include system apps

        Returns:
            Selected package name or None
        """
        pkg_list, show_system = resolve_package_list(
            packages,
            show_system,
            self._prepare_packages_for_ui,
        )

        flow = CLISelectionFlow(
            fuzzy_op=self._fuzzy_op,
            filter_packages_fn=self.filter_packages,
        )
        return flow.run(pkg_list, show_system, recently_installed_package)

    def _safe_input(self, prompt: str) -> str:
        """Safe input that handles EOFError.

        Args:
            prompt: Input prompt

        Returns:
            User input string
        """
        try:
            return input(prompt)
        except EOFError:
            return ""


__all__ = [
    "AdbProtocol",
    "AppSelectionService",
    "PackageInfo",
    "SelectionResult",
    "UICallbackProtocol",
]
