"""SMS scan strategy for checking SMS messages against IOC indicators."""

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandroid.core.forensic_evidence import IOCLoader, ProgressCallback

from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    ScanType,
)

from .base_strategy import BaseScanStrategy

logger = logging.getLogger(__name__)


class SMSScanStrategy(BaseScanStrategy):
    """Strategy for scanning SMS messages against IOC indicators.

    Scans SMS inbox for phone numbers, URLs, and domains that match
    loaded IOC indicators. Requires root or specific permissions on device.
    """

    @property
    def scan_type(self) -> ScanType:
        return ScanType.SMS

    def scan(
        self,
        ioc_loader: "IOCLoader",
        progress_callback: "ProgressCallback" = None,
    ) -> ScanResult:
        """Scan SMS messages against IOC indicators.

        Args:
            ioc_loader: Loaded IOCLoader instance with indicators
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any SMS matches found
        """
        from sandroid.core.adb import Adb

        start_time = time.time()
        result = self._create_result()

        self._report_progress(progress_callback, 0, 0, "", "Reading SMS messages...")

        try:
            # No --projection (see CallsScanStrategy): the `content` tool's
            # projection parsing is version-dependent and rejected the
            # comma-joined columns as one invalid column. We substring-match the
            # whole row, so query all columns and parse line by line.
            stdout, _stderr = Adb.send_adb_command(
                "shell content query --uri content://sms/inbox"
            )

            if stdout and "Error" not in stdout:
                sms_count = 0
                for line in stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    sms_count += 1

                    # Check phone numbers
                    matches = self._check_phone_numbers(line, ioc_loader)
                    result.matches.extend(matches)

                    # Check URLs
                    matches = self._check_urls(line, ioc_loader)
                    result.matches.extend(matches)

                    # Check domains
                    matches = self._check_domains(line, ioc_loader)
                    result.matches.extend(matches)

                result.scanned_items = sms_count
            else:
                result.errors.append("Could not access SMS database (may require root)")

        except Exception as e:
            result.errors.append(f"SMS scan error: {e!s}")
            logger.error(f"Error scanning SMS: {e}")

        result.scan_duration = time.time() - start_time
        return result

    def _check_phone_numbers(
        self,
        line: str,
        ioc_loader: "IOCLoader",
    ) -> list[IOCMatch]:
        """Check SMS line for phone number IOC matches.

        Args:
            line: SMS content line to check
            ioc_loader: Loaded IOCLoader instance

        Returns:
            List of IOCMatch objects for any matches found
        """
        matches = []
        for ioc in ioc_loader.phone_numbers:
            if ioc["value"] in line:
                matches.append(
                    IOCMatch(
                        indicator_type="phone_number",
                        indicator_value=ioc["value"],
                        matched_data=line[:100],  # Truncate for privacy
                        source="sms",
                        severity=MatchSeverity.HIGH,
                        description=ioc.get("description", ""),
                    )
                )
        return matches

    def _check_urls(
        self,
        line: str,
        ioc_loader: "IOCLoader",
    ) -> list[IOCMatch]:
        """Check SMS line for URL IOC matches.

        Args:
            line: SMS content line to check
            ioc_loader: Loaded IOCLoader instance

        Returns:
            List of IOCMatch objects for any matches found
        """
        matches = []
        for ioc in ioc_loader.urls:
            if ioc["value"] in line:
                matches.append(
                    IOCMatch(
                        indicator_type="url",
                        indicator_value=ioc["value"],
                        matched_data=line[:100],
                        source="sms",
                        severity=MatchSeverity.CRITICAL,
                        description=ioc.get("description", ""),
                    )
                )
        return matches

    def _check_domains(
        self,
        line: str,
        ioc_loader: "IOCLoader",
    ) -> list[IOCMatch]:
        """Check SMS line for domain IOC matches.

        Args:
            line: SMS content line to check
            ioc_loader: Loaded IOCLoader instance

        Returns:
            List of IOCMatch objects for any matches found
        """
        matches = []
        for ioc in ioc_loader.domains:
            if ioc["value"] in line:
                matches.append(
                    IOCMatch(
                        indicator_type="domain",
                        indicator_value=ioc["value"],
                        matched_data=line[:100],
                        source="sms",
                        severity=MatchSeverity.HIGH,
                        description=ioc.get("description", ""),
                    )
                )
        return matches


__all__ = ["SMSScanStrategy"]
