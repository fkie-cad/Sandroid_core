"""Spotlight memory tracking module for detecting memory changes.

This module implements differential memory tracking: it captures a baseline
snapshot of dirty (writable) memory pages before an action, then compares
against a post-action snapshot to identify which pages changed.
"""

import json
import os
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import List, Optional

from sandroid.core.memorytracker import (
    FridaMemoryTracker,
    MemoryPage,
    MemorySnapshot,
    MemoryTracker,
)
from sandroid.core.progress import ProgressBar
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

logger = getLogger(__name__)


class Bcolors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class SpotlightMemory(DataGather):
    """Tracks memory changes in spotlight application.

    This module uses a MemoryTracker backend (default: Frida) to:
    1. Create baseline snapshot before action execution
    2. Create post-action snapshot after action completes
    3. Compare snapshots to identify changed (dirty) pages
    4. Dump only the changed pages to disk
    5. Generate analysis report

    The module focuses on writable memory pages (rw-) as these are
    most likely to contain interesting behavioral changes.
    """

    def __init__(self, tracker: MemoryTracker | None = None):
        """Initialize spotlight memory tracking.

        Args:
            tracker: Memory tracker backend (defaults to FridaMemoryTracker)
        """
        self.tracker = tracker
        self.baseline_snapshot: MemorySnapshot | None = None
        self.current_snapshot: MemorySnapshot | None = None
        self.changed_pages: list[MemoryPage] = []
        self.dump_directory: Path | None = None
        self.metadata = {}

        # Configuration from Toolbox (will be set during gather())
        self.target_permissions = "rw-"  # Focus on writable pages
        self.custom_regions: list[str] | None = None
        self.capture_baseline_dumps = False  # Only checksums by default

    def gather(self):
        """Create baseline memory snapshot before action.

        This method is called BEFORE the action executes. It:
        1. Gets the spotlight application session
        2. Attaches memory tracker to the process
        3. Creates baseline snapshot with checksums
        """
        logger.info("Creating baseline memory snapshot for spotlight application")

        try:
            # Get spotlight application session
            session, mode, app_info = Toolbox.get_frida_session_for_spotlight()
            pid = app_info["pid"]
            package_name = app_info["package_name"]

            logger.info(
                f"Tracking memory for {package_name} (PID: {pid}) in {mode.upper()} mode"
            )

            # Initialize tracker if not provided
            if self.tracker is None:
                self.tracker = FridaMemoryTracker(session=session)

            # Attach to process
            if not self.tracker.attach(pid, package_name):
                logger.error("Failed to attach memory tracker")
                return

            # Get configuration from Toolbox args if available
            args = getattr(Toolbox, "args", None)
            if args:
                self.target_permissions = getattr(args, "memory_permissions", "rw-")
                self.custom_regions = getattr(args, "memory_regions", None)
                self.capture_baseline_dumps = getattr(
                    args, "memory_baseline_dumps", False
                )

            # Create baseline snapshot
            logger.info(
                f"Creating baseline snapshot with permissions: {self.target_permissions}"
            )
            if self.custom_regions:
                logger.info(f"Filtering to regions: {self.custom_regions}")

            self.baseline_snapshot = self.tracker.create_snapshot(
                target_permissions=self.target_permissions,
                regions=self.custom_regions,
                compute_checksums=True,
            )

            # Store metadata
            self.metadata = {
                "package": package_name,
                "pid": pid,
                "mode": mode,
                "baseline_timestamp": self.baseline_snapshot.timestamp.isoformat(),
                "target_permissions": self.target_permissions,
                "custom_regions": self.custom_regions or [],
                "total_baseline_pages": len(self.baseline_snapshot.pages),
                "baseline_size_mb": self.baseline_snapshot.total_size / 1024 / 1024,
            }

            logger.info(
                f"Baseline snapshot created: {len(self.baseline_snapshot.pages)} pages "
                f"({self.metadata['baseline_size_mb']:.2f} MB)"
            )

        except Exception as e:
            logger.error(f"Failed to create baseline snapshot: {e}", exc_info=True)

    def return_data(self):
        """Create post-action snapshot, compare, and dump changed pages.

        This method is called AFTER the action executes. It:
        1. Creates current snapshot
        2. Compares with baseline to find changed pages
        3. Dumps changed pages to disk
        4. Generates metadata and summary
        5. Detaches from process

        Returns:
            Dictionary with memory tracking results
        """
        if not self.baseline_snapshot or not self.tracker:
            logger.warning("No baseline snapshot available, skipping memory comparison")
            return {"SpotlightMemory": {"error": "No baseline snapshot"}}

        try:
            logger.info("Creating post-action memory snapshot")

            # Create current snapshot
            self.current_snapshot = self.tracker.create_snapshot(
                target_permissions=self.target_permissions,
                regions=self.custom_regions,
                compute_checksums=True,
            )

            # Compare snapshots
            logger.info("Comparing snapshots to detect changed pages")
            self.changed_pages = self.tracker.compare_snapshots(
                self.baseline_snapshot, self.current_snapshot
            )

            # Update metadata
            self.metadata.update(
                {
                    "current_timestamp": self.current_snapshot.timestamp.isoformat(),
                    "total_current_pages": len(self.current_snapshot.pages),
                    "current_size_mb": self.current_snapshot.total_size / 1024 / 1024,
                    "changed_pages": len(self.changed_pages),
                    "changed_size_mb": sum(p.size for p in self.changed_pages)
                    / 1024
                    / 1024,
                }
            )

            logger.info(
                f"Detected {len(self.changed_pages)} changed pages out of "
                f"{len(self.current_snapshot.pages)} total pages"
            )

            # Dump changed pages
            if self.changed_pages:
                self._dump_changed_pages()
            else:
                logger.info("No changed pages detected, skipping dumps")

            # Save metadata
            self._save_metadata()

            # Detach tracker
            self.tracker.detach()

            # Return results
            return {
                "SpotlightMemory": {
                    "package": self.metadata["package"],
                    "pid": self.metadata["pid"],
                    "mode": self.metadata["mode"],
                    "baseline_pages": self.metadata["total_baseline_pages"],
                    "changed_pages": len(self.changed_pages),
                    "changed_size_mb": self.metadata.get("changed_size_mb", 0),
                    "dump_directory": str(self.dump_directory)
                    if self.dump_directory
                    else None,
                    "changed_page_addresses": [
                        p.base_address for p in self.changed_pages
                    ],
                }
            }

        except Exception as e:
            logger.error(f"Failed to process memory changes: {e}", exc_info=True)
            if self.tracker:
                self.tracker.detach()
            return {"SpotlightMemory": {"error": str(e)}}

    def pretty_print(self):
        """Return formatted string of memory tracking results.

        Returns:
            Formatted string with memory change statistics and details
        """
        result = (
            Bcolors.HEADER
            + Bcolors.BOLD
            + "\n—————————————————SPOTLIGHT MEMORY (Changed Dirty Pages)———————————————————————————\n"
            + Bcolors.ENDC
            + Bcolors.HEADER
        )

        if not self.baseline_snapshot:
            result += "No baseline snapshot available\n"
        elif not self.changed_pages:
            result += "No memory changes detected\n"
        else:
            # Summary
            result += (
                f"{Bcolors.OKGREEN}Package:{Bcolors.ENDC} {self.metadata['package']}\n"
            )
            result += f"{Bcolors.OKGREEN}PID:{Bcolors.ENDC} {self.metadata['pid']}\n"
            result += f"{Bcolors.OKGREEN}Mode:{Bcolors.ENDC} {self.metadata['mode'].upper()}\n"
            result += f"{Bcolors.OKGREEN}Baseline Pages:{Bcolors.ENDC} {self.metadata['total_baseline_pages']}\n"
            result += f"{Bcolors.OKGREEN}Changed Pages:{Bcolors.ENDC} {len(self.changed_pages)}\n"
            result += f"{Bcolors.OKGREEN}Changed Size:{Bcolors.ENDC} {self.metadata.get('changed_size_mb', 0):.2f} MB\n"

            if self.dump_directory:
                result += (
                    f"{Bcolors.OKGREEN}Dumps:{Bcolors.ENDC} {self.dump_directory}\n"
                )

            result += "\n"

            # List changed pages
            result += f"{Bcolors.OKBLUE}Changed Pages:{Bcolors.ENDC}\n"
            for page in self.changed_pages[:20]:  # Limit to first 20
                size_kb = page.size / 1024
                result += (
                    f"  {page.base_address} ({size_kb:.1f} KB) "
                    f"[{page.protection}] {page.module}\n"
                )

            if len(self.changed_pages) > 20:
                result += f"  ... and {len(self.changed_pages) - 20} more\n"

        result += (
            Bcolors.BOLD
            + "———————————————————————————————————————————————————————————————————————————————————\n"
            + Bcolors.ENDC
        )

        return result

    def _dump_changed_pages(self):
        """Dump all changed pages to disk."""
        # Create dump directory
        package_name = self.metadata["package"].replace(".", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Use Sandroid session results directory (includes session timestamp)
        # RESULTS_PATH is set by Toolbox.init_files() as "results/{session_timestamp}/"
        results_path = os.getenv("RESULTS_PATH", os.getcwd())
        self.dump_directory = (
            Path(results_path) / "memtracking" / package_name / f"event_{timestamp}"
        )
        self.dump_directory.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Dumping {len(self.changed_pages)} changed pages to {self.dump_directory}"
        )

        # Dump each changed page
        dumped_count = 0
        with ProgressBar(
            len(self.changed_pages), desc="Dumping pages", unit="pages"
        ) as progress:
            for page in self.changed_pages:
                # Generate filename from address
                filename = f"{page.base_address.replace('0x', '')}_dump.data"
                output_path = self.dump_directory / filename

                if self.tracker.dump_page(page, output_path):
                    page.dump_file = str(output_path)
                    dumped_count += 1
                else:
                    logger.warning(f"Failed to dump page {page.base_address}")
                progress.update(1)

        logger.info(
            f"Successfully dumped {dumped_count}/{len(self.changed_pages)} pages"
        )

        # Create diff summary
        self._create_diff_summary()

    def _create_diff_summary(self):
        """Create human-readable diff summary file."""
        if not self.dump_directory:
            return

        summary_path = self.dump_directory / "diff_summary.txt"

        try:
            with open(summary_path, "w") as f:
                f.write("=" * 80 + "\n")
                f.write("Sandroid Spotlight Memory - Diff Summary\n")
                f.write("=" * 80 + "\n\n")

                f.write(f"Package: {self.metadata['package']}\n")
                f.write(f"PID: {self.metadata['pid']}\n")
                f.write(f"Mode: {self.metadata['mode'].upper()}\n")
                f.write(f"Baseline Time: {self.metadata['baseline_timestamp']}\n")
                f.write(
                    f"Current Time: {self.metadata.get('current_timestamp', 'N/A')}\n"
                )
                f.write(f"Target Permissions: {self.target_permissions}\n")
                f.write("\n")

                f.write(
                    f"Total Baseline Pages: {self.metadata['total_baseline_pages']}\n"
                )
                f.write(
                    f"Total Current Pages: {self.metadata.get('total_current_pages', 0)}\n"
                )
                f.write(f"Changed Pages: {len(self.changed_pages)}\n")
                f.write(
                    f"Changed Size: {self.metadata.get('changed_size_mb', 0):.2f} MB\n"
                )
                f.write("\n")

                f.write("=" * 80 + "\n")
                f.write("Changed Pages Details\n")
                f.write("=" * 80 + "\n\n")

                for page in self.changed_pages:
                    f.write(f"Address: {page.base_address}\n")
                    f.write(f"  Size: {page.size} bytes ({page.size / 1024:.2f} KB)\n")
                    f.write(f"  Protection: {page.protection}\n")
                    f.write(f"  Module: {page.module}\n")
                    f.write(f"  Checksum: {page.checksum}\n")
                    if page.dump_file:
                        f.write(f"  Dump: {os.path.basename(page.dump_file)}\n")
                    f.write("\n")

                f.write("=" * 80 + "\n")

            logger.info(f"Created diff summary: {summary_path}")

        except Exception as e:
            logger.error(f"Failed to create diff summary: {e}")

    def _save_metadata(self):
        """Save metadata and changed pages information to JSON."""
        if not self.dump_directory:
            return

        try:
            # Ensure parent directory exists
            self.dump_directory.parent.mkdir(parents=True, exist_ok=True)

            # Save baseline snapshot (at package level, not event level)
            baseline_path = self.dump_directory.parent / "baseline_snapshot.json"
            with open(baseline_path, "w") as f:
                json.dump(self.baseline_snapshot.model_dump(), f, indent=2, default=str)

            # Save changed pages (in event-specific directory)
            changed_pages_path = self.dump_directory / "changed_pages.json"
            changed_pages_data = {
                "metadata": self.metadata,
                "changed_pages": [page.model_dump() for page in self.changed_pages],
            }
            with open(changed_pages_path, "w") as f:
                json.dump(changed_pages_data, f, indent=2, default=str)

            # Save overall metadata (at package level)
            metadata_path = self.dump_directory.parent / "metadata.json"
            with open(metadata_path, "w") as f:
                json.dump(self.metadata, f, indent=2, default=str)

            logger.info(f"Saved metadata to {metadata_path}")

        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
