"""Forensic Evidence module for MVT (Mobile Verification Toolkit) integration.

This module provides forensic scanning capabilities using STIX2 IOC files
to detect signs of compromise on Android devices.
"""

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Types of forensic scans available."""

    SMS = auto()
    CALLS = auto()
    APPS = auto()
    FILES = auto()
    ALL = auto()


class MatchSeverity(Enum):
    """Severity levels for IOC matches."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IOCMatch:
    """Represents a single IOC match found during scanning.

    Attributes:
        indicator_type: Type of indicator (e.g., domain, hash, package)
        indicator_value: The matched indicator value
        matched_data: The data from the device that matched
        source: Where the match was found (e.g., SMS, app list)
        severity: Severity level of the match
        description: Human-readable description of the indicator
        reference: Optional reference URL for more information
        timestamp: When the match was found
    """

    indicator_type: str
    indicator_value: str
    matched_data: str
    source: str
    severity: MatchSeverity = MatchSeverity.MEDIUM
    description: str = ""
    reference: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert match to dictionary for serialization."""
        return {
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "matched_data": self.matched_data,
            "source": self.source,
            "severity": self.severity.value,
            "description": self.description,
            "reference": self.reference,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """Results from a forensic evidence scan.

    Attributes:
        scan_type: Type of scan performed
        matches: List of IOC matches found
        scanned_items: Number of items scanned
        scan_duration: Duration of scan in seconds
        device_serial: Serial of scanned device
        timestamp: When the scan started
        errors: Any errors encountered during scanning
    """

    scan_type: ScanType
    matches: list[IOCMatch] = field(default_factory=list)
    scanned_items: int = 0
    scan_duration: float = 0.0
    device_serial: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    errors: list[str] = field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        """Check if any matches were found."""
        return len(self.matches) > 0

    @property
    def critical_matches(self) -> list[IOCMatch]:
        """Get only critical severity matches."""
        return [m for m in self.matches if m.severity == MatchSeverity.CRITICAL]

    @property
    def high_matches(self) -> list[IOCMatch]:
        """Get high severity matches."""
        return [m for m in self.matches if m.severity == MatchSeverity.HIGH]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "scan_type": self.scan_type.name,
            "matches": [m.to_dict() for m in self.matches],
            "scanned_items": self.scanned_items,
            "scan_duration": self.scan_duration,
            "device_serial": self.device_serial,
            "timestamp": self.timestamp.isoformat(),
            "errors": self.errors,
            "summary": {
                "total_matches": len(self.matches),
                "critical": len(self.critical_matches),
                "high": len(self.high_matches),
            },
        }


class IOCLoader:
    """Loads and parses STIX2 IOC files."""

    def __init__(self, ioc_path: Path | str | None = None):
        """Initialize IOC loader.

        Args:
            ioc_path: Path to IOC file or directory
        """
        self.ioc_path = Path(ioc_path) if ioc_path else None
        self._indicators: dict[str, list[dict[str, Any]]] = {
            "domains": [],
            "urls": [],
            "hashes": [],
            "packages": [],
            "phone_numbers": [],
            "emails": [],
            "patterns": [],
        }
        self._loaded = False

    def load(self) -> bool:
        """Load IOC indicators from configured path.

        Returns:
            True if IOCs were loaded successfully
        """
        if not self.ioc_path:
            logger.warning("No IOC path configured")
            return False

        if not self.ioc_path.exists():
            logger.error(f"IOC path does not exist: {self.ioc_path}")
            return False

        try:
            if self.ioc_path.is_file():
                self._load_file(self.ioc_path)
            else:
                # Load both .json and .stix2 files (MVT uses .stix2 extension)
                for pattern in ["*.json", "*.stix2"]:
                    for f in self.ioc_path.glob(pattern):
                        self._load_file(f)

            self._loaded = True
            logger.info(
                f"Loaded IOCs: {sum(len(v) for v in self._indicators.values())} indicators"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load IOCs: {e}")
            return False

    def _load_file(self, path: Path) -> None:
        """Load indicators from a single IOC file.

        Args:
            path: Path to the IOC file
        """
        try:
            with open(path) as f:
                data = json.load(f)

            # Handle STIX2 bundle format
            if isinstance(data, dict):
                if "objects" in data:
                    objects = data["objects"]
                else:
                    objects = [data]
            elif isinstance(data, list):
                objects = data
            else:
                logger.warning(f"Unknown IOC format in {path}")
                return

            for obj in objects:
                self._parse_stix_object(obj)

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {path}: {e}")
        except Exception as e:
            logger.warning(f"Error loading {path}: {e}")

    def _parse_stix_object(self, obj: dict[str, Any]) -> None:
        """Parse a STIX2 object and extract indicators.

        Args:
            obj: STIX2 object dictionary
        """
        if not isinstance(obj, dict):
            return

        obj_type = obj.get("type", "")

        # Handle indicator objects
        if obj_type == "indicator":
            pattern = obj.get("pattern", "")
            description = obj.get("description", "")
            name = obj.get("name", "")

            # Parse STIX pattern for different indicator types
            self._extract_from_pattern(pattern, description or name)

        # Handle direct indicator values (simplified format)
        elif obj_type in ("domain-name", "domain"):
            value = obj.get("value", obj.get("domain", ""))
            if value:
                self._indicators["domains"].append(
                    {
                        "value": value,
                        "description": obj.get("description", ""),
                    }
                )

        elif obj_type == "url":
            value = obj.get("value", obj.get("url", ""))
            if value:
                self._indicators["urls"].append(
                    {
                        "value": value,
                        "description": obj.get("description", ""),
                    }
                )

        elif obj_type in ("file", "hash"):
            hashes = obj.get("hashes", {})
            for hash_type, hash_value in hashes.items():
                self._indicators["hashes"].append(
                    {
                        "value": hash_value,
                        "type": hash_type,
                        "description": obj.get("description", ""),
                    }
                )

        elif obj_type == "software":
            name = obj.get("name", "")
            if name:
                self._indicators["packages"].append(
                    {
                        "value": name,
                        "description": obj.get("description", ""),
                    }
                )

    def _extract_from_pattern(self, pattern: str, description: str) -> None:
        """Extract indicator values from STIX pattern.

        Args:
            pattern: STIX2 pattern string
            description: Description for the indicator
        """
        if not pattern:
            return

        # Domain patterns
        domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if domain_match:
            self._indicators["domains"].append(
                {
                    "value": domain_match.group(1),
                    "description": description,
                }
            )

        # URL patterns
        url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
        if url_match:
            self._indicators["urls"].append(
                {
                    "value": url_match.group(1),
                    "description": description,
                }
            )

        # File hash patterns
        hash_matches = re.findall(
            r"file:hashes\.'?(MD5|SHA-1|SHA-256|SHA256)'?\s*=\s*'([^']+)'",
            pattern,
            re.IGNORECASE,
        )
        for hash_type, hash_value in hash_matches:
            self._indicators["hashes"].append(
                {
                    "value": hash_value,
                    "type": hash_type,
                    "description": description,
                }
            )

        # Process name (package) patterns
        process_match = re.search(r"process:name\s*=\s*'([^']+)'", pattern)
        if process_match:
            self._indicators["packages"].append(
                {
                    "value": process_match.group(1),
                    "description": description,
                }
            )

        # Phone number patterns (custom)
        phone_match = re.search(r"phone-number:value\s*=\s*'([^']+)'", pattern)
        if phone_match:
            self._indicators["phone_numbers"].append(
                {
                    "value": phone_match.group(1),
                    "description": description,
                }
            )

        # Email patterns (custom)
        email_match = re.search(r"email-addr:value\s*=\s*'([^']+)'", pattern)
        if email_match:
            self._indicators["emails"].append(
                {
                    "value": email_match.group(1),
                    "description": description,
                }
            )

    @property
    def domains(self) -> list[dict[str, Any]]:
        """Get loaded domain indicators."""
        return self._indicators["domains"]

    @property
    def urls(self) -> list[dict[str, Any]]:
        """Get loaded URL indicators."""
        return self._indicators["urls"]

    @property
    def hashes(self) -> list[dict[str, Any]]:
        """Get loaded hash indicators."""
        return self._indicators["hashes"]

    @property
    def packages(self) -> list[dict[str, Any]]:
        """Get loaded package name indicators."""
        return self._indicators["packages"]

    @property
    def phone_numbers(self) -> list[dict[str, Any]]:
        """Get loaded phone number indicators."""
        return self._indicators["phone_numbers"]

    @property
    def emails(self) -> list[dict[str, Any]]:
        """Get loaded email indicators."""
        return self._indicators["emails"]

    @property
    def total_indicators(self) -> int:
        """Get total number of loaded indicators."""
        return sum(len(v) for v in self._indicators.values())

    @property
    def is_loaded(self) -> bool:
        """Check if IOCs have been loaded."""
        return self._loaded


class ScanProgress:
    """Progress information for scan operations."""

    def __init__(
        self,
        scan_type: str,
        current: int,
        total: int,
        item: str = "",
        message: str = "",
    ):
        """Initialize scan progress.

        Args:
            scan_type: Type of scan (APPS, SMS, CALLS, FILES)
            current: Current item number (1-based)
            total: Total items to scan
            item: Current item being scanned (e.g., package name)
            message: Optional status message
        """
        self.scan_type = scan_type
        self.current = current
        self.total = total
        self.item = item
        self.message = message
        self.percentage = (current / total * 100) if total > 0 else 0


# Type alias for progress callback
ProgressCallback = Callable[[ScanProgress], None] | None


class ForensicScanner:
    """Performs forensic scans on Android devices using IOC indicators.

    This class uses the Strategy pattern for scan implementations.
    Individual scan methods delegate to strategy classes for better
    testability and separation of concerns.
    """

    def __init__(self, ioc_loader: IOCLoader):
        """Initialize forensic scanner.

        Args:
            ioc_loader: Loaded IOCLoader instance
        """
        self.ioc_loader = ioc_loader
        self._results: list[ScanResult] = []
        self._strategies = self._init_strategies()

    def _init_strategies(self) -> dict:
        """Initialize scan strategies.

        Returns:
            Dictionary mapping ScanType to strategy instance
        """
        from .forensic_scanners import (
            AppsScanStrategy,
            CallsScanStrategy,
            FilesScanStrategy,
            SMSScanStrategy,
        )

        return {
            ScanType.APPS: AppsScanStrategy(),
            ScanType.SMS: SMSScanStrategy(),
            ScanType.CALLS: CallsScanStrategy(),
            ScanType.FILES: FilesScanStrategy(),
        }

    def _run_strategy(
        self,
        scan_type: ScanType,
        progress_callback: ProgressCallback = None,
    ) -> ScanResult:
        """Run a scan using the appropriate strategy.

        Args:
            scan_type: Type of scan to run
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult from the strategy
        """
        strategy = self._strategies.get(scan_type)
        if not strategy:
            result = ScanResult(scan_type=scan_type)
            result.errors.append(f"No strategy found for scan type: {scan_type}")
            return result

        result = strategy.scan(self.ioc_loader, progress_callback)
        self._results.append(result)
        return result

    def scan_apps(self, progress_callback: ProgressCallback = None) -> ScanResult:
        """Scan installed applications against IOC indicators.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any package matches
        """
        return self._run_strategy(ScanType.APPS, progress_callback)

    def scan_sms(self, progress_callback: ProgressCallback = None) -> ScanResult:
        """Scan SMS messages against IOC indicators.

        Note: Requires root or specific permissions on device.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any SMS matches
        """
        return self._run_strategy(ScanType.SMS, progress_callback)

    def scan_calls(self, progress_callback: ProgressCallback = None) -> ScanResult:
        """Scan call logs against IOC indicators.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any call log matches
        """
        return self._run_strategy(ScanType.CALLS, progress_callback)

    def scan_files(self, progress_callback: ProgressCallback = None) -> ScanResult:
        """Scan installed APKs for IOC hash matches.

        Uses 'pm path' to get APK paths (works on non-rooted devices),
        then calculates hashes and compares against IOC indicators.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with any file/hash matches
        """
        return self._run_strategy(ScanType.FILES, progress_callback)

    def scan_all(self, progress_callback: ProgressCallback = None) -> list[ScanResult]:
        """Run all available scans.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            List of ScanResult objects for each scan type
        """
        results = []
        results.append(self.scan_apps(progress_callback))
        results.append(self.scan_sms(progress_callback))
        results.append(self.scan_calls(progress_callback))
        results.append(self.scan_files(progress_callback))
        return results

    @property
    def all_results(self) -> list[ScanResult]:
        """Get all scan results."""
        return self._results

    @property
    def all_matches(self) -> list[IOCMatch]:
        """Get all matches from all scans."""
        matches = []
        for result in self._results:
            matches.extend(result.matches)
        return matches

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all scan results.

        Returns:
            Dictionary with scan summary
        """
        total_matches = sum(len(r.matches) for r in self._results)
        critical = sum(len(r.critical_matches) for r in self._results)
        high = sum(len(r.high_matches) for r in self._results)

        return {
            "total_scans": len(self._results),
            "total_matches": total_matches,
            "critical_matches": critical,
            "high_matches": high,
            "scans": [r.to_dict() for r in self._results],
        }


class ForensicEvidence:
    """Main interface for forensic evidence scanning.

    This class provides a high-level interface for running MVT-style
    forensic scans on Android devices.
    """

    _instance: "ForensicEvidence | None" = None

    def __init__(self):
        """Initialize ForensicEvidence."""
        self._ioc_loader: IOCLoader | None = None
        self._scanner: ForensicScanner | None = None
        self._config = None

    @classmethod
    def get(cls) -> "ForensicEvidence":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton instance."""
        cls._instance = None

    def _load_config(self):
        """Load MVT configuration."""
        if self._config is None:
            try:
                from sandroid.config.loader import ConfigLoader

                loader = ConfigLoader()
                config = loader.load()
                self._config = config.mvt
            except Exception as e:
                logger.warning(f"Could not load config: {e}")
                self._config = None

    def is_configured(self) -> bool:
        """Check if MVT/IOC is properly configured.

        Returns:
            True if IOC path is configured and exists
        """
        self._load_config()
        if not self._config:
            return False

        if not self._config.enabled:
            return False

        if self._config.ioc_path and Path(self._config.ioc_path).exists():
            return True

        return False

    def get_ioc_path(self) -> Path | None:
        """Get configured IOC path.

        Returns:
            Path to IOC file/directory or None
        """
        self._load_config()
        if self._config and self._config.ioc_path:
            return Path(self._config.ioc_path)
        return None

    def load_iocs(self, ioc_path: Path | str | None = None) -> bool:
        """Load IOC indicators.

        Args:
            ioc_path: Optional path override (uses config if not provided)

        Returns:
            True if IOCs loaded successfully
        """
        if ioc_path is None:
            self._load_config()
            if self._config and self._config.ioc_path:
                ioc_path = self._config.ioc_path

        if not ioc_path:
            logger.error("No IOC path provided or configured")
            return False

        self._ioc_loader = IOCLoader(ioc_path)
        if self._ioc_loader.load():
            self._scanner = ForensicScanner(self._ioc_loader)
            return True
        return False

    def run_scan(
        self,
        scan_apps: bool = True,
        scan_sms: bool = True,
        scan_calls: bool = True,
        scan_files: bool = True,
        progress_callback: ProgressCallback = None,
    ) -> list[ScanResult]:
        """Run forensic scans based on configuration.

        Args:
            scan_apps: Scan installed applications
            scan_sms: Scan SMS messages
            scan_calls: Scan call logs
            scan_files: Scan filesystem
            progress_callback: Optional callback for progress updates

        Returns:
            List of ScanResult objects
        """
        if not self._scanner:
            if not self.load_iocs():
                logger.error("Cannot run scan - IOCs not loaded")
                return []

        results = []

        if scan_apps:
            results.append(self._scanner.scan_apps(progress_callback))
        if scan_sms:
            results.append(self._scanner.scan_sms(progress_callback))
        if scan_calls:
            results.append(self._scanner.scan_calls(progress_callback))
        if scan_files:
            results.append(self._scanner.scan_files(progress_callback))

        return results

    def get_summary(self) -> dict[str, Any]:
        """Get summary of scan results.

        Returns:
            Dictionary with scan summary
        """
        if not self._scanner:
            return {"error": "No scans have been run"}
        return self._scanner.get_summary()

    @property
    def total_indicators(self) -> int:
        """Get number of loaded IOC indicators."""
        if self._ioc_loader:
            return self._ioc_loader.total_indicators
        return 0

    @property
    def all_matches(self) -> list[IOCMatch]:
        """Get all matches from scans."""
        if self._scanner:
            return self._scanner.all_matches
        return []
