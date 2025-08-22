"""Sandroid: An Android sandbox for automated Forensic, Malware, and Security Analysis."""

from ._about import __version__, __authors__, __author__, __email__, __description__

from .config.schema import SandroidConfig
from .config.loader import ConfigLoader

__all__ = ["SandroidConfig", "ConfigLoader"]