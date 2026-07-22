"""Sandroid Analysis Module

This package contains the data gathering and analysis components for Sandroid.

Key modules:
- base_di: DI-enabled base class for data-gathering implementations
- changedfiles: Detects modified files during analysis
- newfiles: Identifies newly created files
- deletedfiles: Tracks deleted files (with --show_deleted flag)
- processes: Monitors running processes
- network: Captures network traffic
- static_analysis: Performs static APK analysis
- trigdroid_bypass: Unified bypass hooks for app protections
- interfaces: Segregated interfaces following ISP

Base Classes:
    DataGatherBase: DI-enabled base class for testability

Interfaces:
    DataGatherer: Core data collection interface
    DataProvider: Data retrieval interface
    Formattable: Optional formatting interface
    DataGatherModule: Composite interface for full functionality
"""

# Core analysis components
# Modern DI-enabled base class
from .base_di import (
    AdbProtocol,
    ConfigProtocol,
    DataGatherBase,
    DataGatherDI,  # Alias for DataGatherBase
    ForensicServiceProtocol,
)
from .changedfiles import ChangedFiles
from .deletedfiles import DeletedFiles

# Segregated interfaces
from .interfaces import (
    CanGather,
    DataGatherer,
    DataGatherModule,
    DataProvider,
    Formattable,
    HasData,
    LegacyDataGatherAdapter,
)
from .network import Network
from .newfiles import NewFiles
from .processes import Processes
from .trigdroid_bypass import TrigDroidBypass

__all__ = [
    # Protocols for dependency injection
    "AdbProtocol",
    "CanGather",
    # Analysis modules
    "ChangedFiles",
    "ConfigProtocol",
    # DI-enabled base class
    "DataGatherBase",
    "DataGatherDI",
    "DataGatherModule",
    # Segregated interfaces
    "DataGatherer",
    "DataProvider",
    "DeletedFiles",
    "ForensicServiceProtocol",
    "Formattable",
    "HasData",
    "LegacyDataGatherAdapter",
    "Network",
    "NewFiles",
    "Processes",
    "TrigDroidBypass",
]
