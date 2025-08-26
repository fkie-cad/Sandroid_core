"""Legacy compatibility alias for toolbox.py

This module provides backward compatibility for existing code that imports
from src.utils.toolbox. All functionality has been migrated to sandroid.core.toolbox
but this alias ensures legacy imports continue to work.

Usage:
    from src.utils.toolbox import Toolbox  # Still works!
    from sandroid.core.toolbox import Toolbox  # New way
"""

# Import everything from the new location and re-export it
from sandroid.core.toolbox import *
