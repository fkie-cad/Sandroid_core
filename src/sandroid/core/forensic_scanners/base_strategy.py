"""Base strategy for forensic scan operations."""

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandroid.core.forensic_evidence import IOCLoader, ProgressCallback, ScanResult

from sandroid.core.forensic_evidence import (
    ScanProgress,
    ScanResult,
    ScanType,
)

logger = logging.getLogger(__name__)


class BaseScanStrategy(ABC):
    """Abstract base class for forensic scan strategies.

    Implements the Strategy pattern for different types of forensic scans.
    Each concrete strategy handles a specific scan type (APPS, SMS, CALLS, FILES).
    """

    @property
    @abstractmethod
    def scan_type(self) -> ScanType:
        """Return the scan type this strategy handles."""
        ...

    @abstractmethod
    def scan(
        self, ioc_loader: "IOCLoader", progress_callback: "ProgressCallback" = None
    ) -> ScanResult:
        """Execute the scan strategy.

        Args:
            ioc_loader: Loaded IOCLoader instance with indicators
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any matches found
        """
        ...

    def _get_device_serial(self) -> str:
        """Get current device serial from DeviceManager."""
        try:
            from sandroid.core.device_manager import DeviceManager

            dm = DeviceManager.get()
            if dm.active_device:
                return dm.active_device.serial
        except Exception:
            pass
        return ""

    def _create_result(self) -> ScanResult:
        """Create an initialized ScanResult for this strategy's scan type."""
        result = ScanResult(scan_type=self.scan_type)
        result.device_serial = self._get_device_serial()
        return result

    def _report_progress(
        self,
        progress_callback: "ProgressCallback",
        current: int,
        total: int,
        item: str = "",
        message: str = "",
    ) -> None:
        """Report progress through callback if provided."""
        if progress_callback:
            progress_callback(
                ScanProgress(
                    scan_type=self.scan_type.name,
                    current=current,
                    total=total,
                    item=item,
                    message=message,
                )
            )


__all__ = ["BaseScanStrategy"]
