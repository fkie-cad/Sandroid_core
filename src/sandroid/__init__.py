"""Sandroid: A framework for extracting forensic artifacts from Android Virtual Devices."""

__version__ = "1.0.0"
__author__ = "Fraunhofer FKIE"
__email__ = "contact@fkie.fraunhofer.de"
__description__ = "A framework for extracting forensic artifacts from Android Virtual Devices (AVD)"

from .config.schema import SandroidConfig
from .config.loader import ConfigLoader

__all__ = ["SandroidConfig", "ConfigLoader"]