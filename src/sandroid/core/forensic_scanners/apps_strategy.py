"""Strategy for scanning installed applications against IOC indicators."""

import logging
import time
from typing import TYPE_CHECKING

from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    ScanType,
)

from .base_strategy import BaseScanStrategy

if TYPE_CHECKING:
    from sandroid.core.forensic_evidence import IOCLoader, ProgressCallback

logger = logging.getLogger(__name__)


class AppsScanStrategy(BaseScanStrategy):
    """Scan strategy for installed applications.

    Checks installed Android packages against IOC package name indicators
    using smart matching logic to avoid false positives on Android package names.
    """

    @property
    def scan_type(self) -> ScanType:
        """Return the scan type this strategy handles."""
        return ScanType.APPS

    def scan(
        self,
        ioc_loader: "IOCLoader",
        progress_callback: "ProgressCallback" = None,
    ) -> ScanResult:
        """Scan installed applications against IOC indicators.

        Args:
            ioc_loader: Loaded IOCLoader instance with indicators
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any package matches
        """
        from sandroid.core.adb import Adb

        start_time = time.time()
        result = self._create_result()

        try:
            # Report starting
            self._report_progress(
                progress_callback,
                current=0,
                total=0,
                message="Getting installed packages...",
            )

            # Get list of installed packages
            stdout, _stderr = Adb.send_adb_command("shell pm list packages")

            if stdout:
                packages = self._parse_package_list(stdout)
                result.scanned_items = len(packages)
                total_checks = len(packages)

                # Check against IOC packages
                self._check_packages_against_iocs(
                    packages=packages,
                    ioc_loader=ioc_loader,
                    result=result,
                    total_checks=total_checks,
                    progress_callback=progress_callback,
                )

        except Exception as e:
            result.errors.append(f"App scan error: {e!s}")
            logger.error(f"Error scanning apps: {e}")

        result.scan_duration = time.time() - start_time
        return result

    def _parse_package_list(self, stdout: str) -> list[str]:
        """Parse package list from pm list packages output.

        Args:
            stdout: Raw output from 'pm list packages' command

        Returns:
            List of package names
        """
        packages = []
        for line in stdout.strip().split("\n"):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return packages

    def _check_packages_against_iocs(
        self,
        packages: list[str],
        ioc_loader: "IOCLoader",
        result: ScanResult,
        total_checks: int,
        progress_callback: "ProgressCallback",
    ) -> None:
        """Check packages against IOC indicators.

        Args:
            packages: List of installed package names
            ioc_loader: IOCLoader with package indicators
            result: ScanResult to append matches to
            total_checks: Total number of packages for progress reporting
            progress_callback: Optional progress callback
        """
        for ioc in ioc_loader.packages:
            ioc_value = ioc["value"].lower()

            for idx, pkg in enumerate(packages):
                # Report progress every 50 packages
                if progress_callback and idx % 50 == 0:
                    self._report_progress(
                        progress_callback,
                        current=idx + 1,
                        total=total_checks,
                        item=pkg[:40],
                        message=f"Checking {idx + 1}/{total_checks} packages",
                    )

                if self._is_package_match(ioc_value, pkg.lower()):
                    result.matches.append(
                        IOCMatch(
                            indicator_type="package",
                            indicator_value=ioc["value"],
                            matched_data=pkg,
                            source="installed_apps",
                            severity=MatchSeverity.HIGH,
                            description=ioc.get("description", ""),
                        )
                    )

    def _is_package_match(self, ioc_value: str, pkg_lower: str) -> bool:
        """Determine if IOC value matches a package name using smart matching.

        Smart matching logic for Android packages to avoid false positives:
        - For full package names (contain dots): require exact match
        - For simple names: match against significant package segments

        Args:
            ioc_value: Lowercase IOC indicator value
            pkg_lower: Lowercase package name

        Returns:
            True if the IOC matches the package
        """
        if "." in ioc_value:
            # IOC looks like a full package name - exact match only
            return ioc_value == pkg_lower

        if "." not in pkg_lower:
            # Both IOC and package are simple names - exact match
            return ioc_value == pkg_lower

        # IOC is simple name, package is full Android name
        # Only match if IOC equals a "significant" segment:
        # - First segment after standard prefixes (com, org, net, etc.)
        # - Or if package starts with IOC as first segment
        pkg_segments = pkg_lower.split(".")
        standard_prefixes = {"com", "org", "net", "io", "de", "uk", "ru", "cn"}

        # Find the first "significant" segment
        significant_idx = 0
        for i, seg in enumerate(pkg_segments):
            if seg not in standard_prefixes:
                significant_idx = i
                break

        # Match if IOC equals the significant segment
        if significant_idx < len(pkg_segments):
            return ioc_value == pkg_segments[significant_idx]

        return False


__all__ = ["AppsScanStrategy"]
