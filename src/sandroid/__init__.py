"""Sandroid: An Android sandbox for automated Forensic, Malware, and Security Analysis."""

from .__about import __author__, __authors__, __description__, __email__, __version__
from .config.loader import ConfigLoader
from .config.schema import SandroidConfig

__all__ = ["ConfigLoader", "SandroidConfig"]
