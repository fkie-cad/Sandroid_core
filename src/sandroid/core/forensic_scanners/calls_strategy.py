"""Calls scan strategy for call log IOC detection."""

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


class CallsScanStrategy(BaseScanStrategy):
    """Strategy for scanning call logs against phone number IOCs."""

    @property
    def scan_type(self) -> ScanType:
        return ScanType.CALLS

    def scan(
        self,
        ioc_loader: "IOCLoader",
        progress_callback: "ProgressCallback" = None,
    ) -> ScanResult:
        """Scan call logs against IOC indicators.

        Args:
            ioc_loader: Loaded IOCLoader instance with indicators
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any call log matches
        """
        from sandroid.core.adb import Adb

        start_time = time.time()
        result = self._create_result()

        self._report_progress(progress_callback, 0, 0, "", "Reading call logs...")

        try:
            stdout, _stderr = Adb.send_adb_command(
                "shell content query --uri content://call_log/calls --projection number,date,type"
            )

            if stdout and "Error" not in stdout:
                call_count = 0
                for line in stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    call_count += 1

                    for ioc in ioc_loader.phone_numbers:
                        if ioc["value"] in line:
                            result.matches.append(
                                IOCMatch(
                                    indicator_type="phone_number",
                                    indicator_value=ioc["value"],
                                    matched_data=line[:100],
                                    source="call_log",
                                    severity=MatchSeverity.HIGH,
                                    description=ioc.get("description", ""),
                                )
                            )

                result.scanned_items = call_count
            else:
                result.errors.append(
                    "Could not access call log (may require permissions)"
                )

        except Exception as e:
            result.errors.append(f"Call log scan error: {e!s}")
            logger.error(f"Error scanning call log: {e}")

        result.scan_duration = time.time() - start_time
        return result


__all__ = ["CallsScanStrategy"]
