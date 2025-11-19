"""Progress bar utilities for long-running operations.

Provides a simple, reusable progress indicator for terminal output.
"""

import sys
from typing import Optional


class ProgressBar:
    """Simple progress bar for terminal output.

    Provides visual feedback for long-running operations without external dependencies.
    Falls back gracefully if tqdm is not available.
    """

    def __init__(self, total: int, desc: str = "Processing", unit: str = "items"):
        """Initialize progress bar.

        Args:
            total: Total number of items to process
            desc: Description to show before the progress bar
            unit: Unit name for items (e.g., "pages", "files", "items")
        """
        self.total = total
        self.desc = desc
        self.unit = unit
        self.current = 0
        self.bar = None

        # Try to use tqdm if available (nicer output)
        try:
            from tqdm import tqdm

            self.bar = tqdm(total=total, desc=desc, unit=unit, leave=True)
            self.use_tqdm = True
        except ImportError:
            # Fallback to simple custom progress
            self.use_tqdm = False
            self._print_progress()

    def update(self, n: int = 1):
        """Update progress by n items.

        Args:
            n: Number of items to increment (default: 1)
        """
        self.current += n

        if self.use_tqdm and self.bar:
            self.bar.update(n)
        else:
            self._print_progress()

    def close(self):
        """Close the progress bar."""
        if self.use_tqdm and self.bar:
            self.bar.close()
        else:
            # Print final newline for custom progress
            sys.stdout.write("\n")
            sys.stdout.flush()

    def _print_progress(self):
        """Print simple progress bar (fallback when tqdm not available)."""
        if self.total == 0:
            percent = 100
        else:
            percent = int((self.current / self.total) * 100)

        # Create simple bar: [####......] 40%
        bar_length = 30
        filled = int((percent / 100) * bar_length)
        bar = "#" * filled + "." * (bar_length - filled)

        # Print with carriage return to update same line
        sys.stdout.write(
            f"\r{self.desc}: [{bar}] {percent}% ({self.current}/{self.total} {self.unit})"
        )
        sys.stdout.flush()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


def create_progress_bar(
    total: int, desc: str = "Processing", unit: str = "items"
) -> ProgressBar | None:
    """Create a progress bar if total > 0.

    Args:
        total: Total number of items
        desc: Description text
        unit: Unit name

    Returns:
        ProgressBar instance or None if total is 0
    """
    if total > 0:
        return ProgressBar(total, desc, unit)
    return None
