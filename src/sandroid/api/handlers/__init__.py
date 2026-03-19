"""Handler modules for the Sandroid Headless API.

Each handler encapsulates a coherent group of API operations,
keeping the main HeadlessAPI class as a thin facade.
"""

from .app_handler import AppHandler
from .device_handler import DeviceHandler
from .forensic_handler import ForensicHandler
from .monitoring_handler import MonitoringHandler
from .task_handler import TaskHandler

__all__ = [
    "AppHandler",
    "DeviceHandler",
    "ForensicHandler",
    "MonitoringHandler",
    "TaskHandler",
]
