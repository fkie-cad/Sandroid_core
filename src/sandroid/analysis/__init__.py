"""Sandroid Analysis Module

This package contains the data gathering and analysis components for Sandroid.
Previously located in src/datagather/, these modules have been migrated here
for better packaging and pip installation support.

Key modules:
- datagather: Base class for data gathering operations
- changedfiles: Detects modified files during analysis
- newfiles: Identifies newly created files
- deletedfiles: Tracks deleted files (with --show_deleted flag)
- processes: Monitors running processes
- network: Captures network traffic
- static_analysis: Performs static APK analysis
"""

# Core analysis components
from .changedfiles import ChangedFiles
from .datagather import DataGather
from .deletedfiles import DeletedFiles
from .network import Network
from .newfiles import NewFiles
from .processes import Processes

__all__ = [
    "ChangedFiles",
    "DataGather",
    "DeletedFiles",
    "Network",
    "NewFiles",
    "Processes",
]
