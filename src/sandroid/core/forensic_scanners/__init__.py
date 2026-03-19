"""Forensic scan strategies module.

This module implements the Strategy pattern for forensic scans,
allowing pluggable scan implementations for different data sources.

Strategies:
    - AppsScanStrategy: Scans installed packages against IOC package names
    - SMSScanStrategy: Scans SMS messages for phone numbers, URLs, domains
    - CallsScanStrategy: Scans call logs for phone number IOCs
    - FilesScanStrategy: Scans APK files for hash IOCs

Usage:
    from sandroid.core.forensic_scanners import (
        BaseScanStrategy,
        AppsScanStrategy,
        SMSScanStrategy,
        CallsScanStrategy,
        FilesScanStrategy,
    )

    # Create strategy
    strategy = AppsScanStrategy()

    # Run scan
    result = strategy.scan(ioc_loader, progress_callback)
"""

from .apps_strategy import AppsScanStrategy
from .base_strategy import BaseScanStrategy
from .calls_strategy import CallsScanStrategy
from .files_strategy import FilesScanStrategy
from .sms_strategy import SMSScanStrategy

__all__ = [
    "AppsScanStrategy",
    "BaseScanStrategy",
    "CallsScanStrategy",
    "FilesScanStrategy",
    "SMSScanStrategy",
]
