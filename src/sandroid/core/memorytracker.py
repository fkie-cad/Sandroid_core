"""Abstract memory tracking interface with concrete implementations.

This module provides a technology-agnostic interface for tracking process memory changes,
with support for multiple backend implementations (Frida, process_vm_readv, kernel features).
"""

import logging
import zlib
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field

from .progress import ProgressBar

logger = logging.getLogger(__name__)


class MemoryPage(BaseModel):
    """Represents a single memory page with tracking metadata.

    Attributes:
        base_address: Hexadecimal string of page base address (e.g., "0x12345000")
        size: Page size in bytes
        protection: Memory protection flags (e.g., "rw-", "r-x", "rwx")
        checksum: CRC32 checksum of page content as hexadecimal string
        module: Associated module/library name (e.g., "libnative.so", "heap")
        changed: Whether this page changed between snapshots
        dump_file: Path to dump file for this page (if dumped)
    """

    base_address: str = Field(..., description="Hexadecimal address of page base")
    size: int = Field(..., gt=0, description="Page size in bytes")
    protection: str = Field(..., description="Memory protection flags")
    checksum: str = Field(default="", description="CRC32 checksum (hex)")
    module: str = Field(default="", description="Associated module name")
    changed: bool = Field(default=False, description="Changed since baseline")
    dump_file: str = Field(default="", description="Path to dump file")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "base_address": "0x12345000",
                "size": 4096,
                "protection": "rw-",
                "checksum": "abc12345",
                "module": "libnative.so",
                "changed": False,
                "dump_file": "",
            }
        }


class MemorySnapshot(BaseModel):
    """Container for memory state at a specific point in time.

    Attributes:
        timestamp: When the snapshot was created
        pages: List of memory pages in this snapshot
        pid: Process ID that was tracked
        package_name: Android package name
        total_size: Total memory size covered by snapshot (bytes)
        backend: Tracker backend used (e.g., "frida", "process_vm_readv")
    """

    timestamp: datetime = Field(default_factory=datetime.now)
    pages: list[MemoryPage] = Field(default_factory=list)
    pid: int = Field(..., gt=0)
    package_name: str = Field(...)
    total_size: int = Field(default=0, ge=0, description="Total memory size in bytes")
    backend: str = Field(default="frida", description="Tracker backend name")

    def __init__(self, **data):
        """Initialize snapshot and calculate total size."""
        super().__init__(**data)
        if self.total_size == 0 and self.pages:
            self.total_size = sum(page.size for page in self.pages)

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class MemoryTracker(ABC):
    """Abstract base class for memory tracking implementations.

    This interface allows swapping between different tracking backends
    (Frida, process_vm_readv, kernel features) without changing
    higher-level code.

    Concrete implementations must provide methods for:
    - Attaching to a process
    - Enumerating memory pages (especially dirty/writable ones)
    - Creating snapshots with checksums
    - Comparing snapshots to detect changes
    - Dumping specific memory pages
    - Detaching from the process
    """

    def __init__(self):
        """Initialize the memory tracker."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.attached = False
        self.pid: int | None = None
        self.package_name: str | None = None

    @abstractmethod
    def attach(self, pid: int, package_name: str = "") -> bool:
        """Attach to a process for memory tracking.

        Args:
            pid: Process ID to attach to
            package_name: Android package name (for metadata)

        Returns:
            True if successfully attached, False otherwise
        """

    @abstractmethod
    def enumerate_dirty_pages(
        self, target_permissions: str = "rw-", regions: list[str] | None = None
    ) -> list[MemoryPage]:
        """Enumerate writable/dirty pages in process memory.

        Focus on pages that can be modified (dirty pages) as they are
        most relevant for behavioral analysis.

        Args:
            target_permissions: Permission filter (e.g., "rw-", "rwx")
            regions: Optional list of address ranges to filter (e.g., ["0x12345000-0x12350000"])

        Returns:
            List of MemoryPage objects matching criteria
        """

    @abstractmethod
    def create_snapshot(
        self,
        target_permissions: str = "rw-",
        regions: list[str] | None = None,
        compute_checksums: bool = True,
    ) -> MemorySnapshot:
        """Create memory state snapshot.

        By default, only computes checksums without dumping full pages
        to reduce overhead. Full dumps can be created later for changed pages.

        Args:
            target_permissions: Permission filter for pages to include
            regions: Optional address ranges to monitor
            compute_checksums: Whether to compute page checksums (default: True)

        Returns:
            MemorySnapshot object with page metadata and checksums
        """

    @abstractmethod
    def compare_snapshots(
        self, baseline: MemorySnapshot, current: MemorySnapshot
    ) -> list[MemoryPage]:
        """Compare two snapshots and identify changed pages.

        Compares checksums between baseline and current snapshots to
        detect which pages have been modified.

        Args:
            baseline: Earlier snapshot to compare against
            current: Current snapshot

        Returns:
            List of MemoryPage objects that changed (with changed=True)
        """

    @abstractmethod
    def dump_page(self, page: MemoryPage, output_path: Path) -> bool:
        """Dump a specific memory page to file.

        Args:
            page: MemoryPage object to dump
            output_path: Path where dump file should be written

        Returns:
            True if successfully dumped, False otherwise
        """

    @abstractmethod
    def detach(self) -> bool:
        """Detach from the process.

        Returns:
            True if successfully detached, False otherwise
        """

    @staticmethod
    def compute_checksum(data: bytes, algorithm: str = "crc32") -> str:
        """Compute checksum of memory data.

        Uses CRC32 by default for speed (not cryptographic security).

        Args:
            data: Memory content as bytes
            algorithm: Checksum algorithm ("crc32" only for now)

        Returns:
            Checksum as hexadecimal string
        """
        if algorithm == "crc32":
            checksum = zlib.crc32(data) & 0xFFFFFFFF
            return f"{checksum:08x}"
        raise ValueError(f"Unsupported checksum algorithm: {algorithm}")

    @staticmethod
    def parse_region(region_str: str) -> tuple[int, int]:
        """Parse address range string into start and end addresses.

        Args:
            region_str: Address range like "0x12345000-0x12350000"

        Returns:
            Tuple of (start_address, end_address) as integers

        Raises:
            ValueError: If region string format is invalid
        """
        try:
            start, end = region_str.split("-")
            start_addr = int(start.strip(), 16)
            end_addr = int(end.strip(), 16)
            if start_addr >= end_addr:
                raise ValueError(f"Invalid region: start >= end in {region_str}")
            return start_addr, end_addr
        except Exception as e:
            raise ValueError(f"Invalid region format '{region_str}': {e}") from e

    @staticmethod
    def address_in_regions(address: int, regions: list[str] | None = None) -> bool:
        """Check if an address falls within specified regions.

        Args:
            address: Memory address to check
            regions: List of region strings (e.g., ["0x12345000-0x12350000"])

        Returns:
            True if address is in any region, or if regions is None/empty
        """
        if not regions:
            return True

        for region in regions:
            start, end = MemoryTracker.parse_region(region)
            if start <= address < end:
                return True
        return False


# Frida script for memory enumeration and checksumming
FRIDA_MEMORY_SCRIPT = """
'use strict';

// Maximum size for a single memory read (20MB)
const MAX_SIZE = 20971520;

// CRC32 lookup table for fast checksum computation
const CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 0; j < 8; j++) {
            crc = (crc & 1) ? (0xEDB88320 ^ (crc >>> 1)) : (crc >>> 1);
        }
        table[i] = crc;
    }
    return table;
})();

/**
 * Compute CRC32 checksum of byte array
 */
function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.byteLength; i++) {
        const byte = data[i];
        const tableIndex = (crc ^ byte) & 0xFF;
        crc = (crc >>> 8) ^ CRC32_TABLE[tableIndex];
    }
    return ((crc ^ 0xFFFFFFFF) >>> 0);
}

/**
 * Convert CRC32 value to hex string
 */
function crc32ToHex(crc) {
    return ('00000000' + crc.toString(16)).slice(-8);
}

rpc.exports = {
    /**
     * Enumerate memory ranges with optional permission filter
     * Returns array of {base, size, protection, file} objects
     */
    enumerateRanges: function(prot) {
        const ranges = Process.enumerateRanges(prot || 'rw-');
        return ranges.map(range => ({
            base: range.base.toString(),
            size: range.size,
            protection: range.protection,
            file: range.file ? range.file.path : ''
        }));
    },

    /**
     * Enumerate ranges and compute checksums
     * More efficient than separate enumerate + checksum calls
     */
    enumerateRangesWithChecksums: function(prot) {
        const ranges = Process.enumerateRanges(prot || 'rw-');
        const results = [];

        for (const range of ranges) {
            try {
                // Skip very large regions to avoid timeout
                if (range.size > MAX_SIZE) {
                    results.push({
                        base: range.base.toString(),
                        size: range.size,
                        protection: range.protection,
                        file: range.file ? range.file.path : '',
                        checksum: 'too_large',
                        error: null
                    });
                    continue;
                }

                // Read memory and compute checksum
                const data = range.base.readByteArray(range.size);
                if (data) {
                    const checksum = crc32(new Uint8Array(data));
                    results.push({
                        base: range.base.toString(),
                        size: range.size,
                        protection: range.protection,
                        file: range.file ? range.file.path : '',
                        checksum: crc32ToHex(checksum),
                        error: null
                    });
                } else {
                    results.push({
                        base: range.base.toString(),
                        size: range.size,
                        protection: range.protection,
                        file: range.file ? range.file.path : '',
                        checksum: 'read_failed',
                        error: 'Memory read returned null'
                    });
                }
            } catch (e) {
                results.push({
                    base: range.base.toString(),
                    size: range.size,
                    protection: range.protection,
                    file: range.file ? range.file.path : '',
                    checksum: 'error',
                    error: e.message
                });
            }
        }

        return results;
    },

    /**
     * Read memory at specific address
     */
    readMemory: function(address, size) {
        try {
            return ptr(address).readByteArray(size);
        } catch (e) {
            throw new Error('Memory read failed at ' + address + ': ' + e.message);
        }
    },

    /**
     * Compute checksum of memory region without reading all data
     */
    checksumMemory: function(address, size) {
        try {
            if (size > MAX_SIZE) {
                return 'too_large';
            }
            const data = ptr(address).readByteArray(size);
            if (!data) {
                return 'read_failed';
            }
            const checksum = crc32(new Uint8Array(data));
            return crc32ToHex(checksum);
        } catch (e) {
            return 'error:' + e.message;
        }
    }
};
"""


class FridaMemoryTracker(MemoryTracker):
    """Frida-based implementation of memory tracking.

    Uses Frida's Process.enumerateRanges() and Memory API to track
    memory changes. Fast and cross-platform, but requires Frida server.

    Advantages:
        - Cross-platform (works on any Android version)
        - No kernel modifications needed
        - Integrates with existing Sandroid Frida infrastructure

    Disadvantages:
        - Requires Frida server to be running
        - Slightly higher overhead than native syscalls
    """

    def __init__(self, session=None):
        """Initialize Frida memory tracker.

        Args:
            session: Existing Frida session to reuse (optional)
        """
        super().__init__()
        self.session = session
        self.script = None
        self.agent = None
        self._external_session = session is not None

    def attach(self, pid: int, package_name: str = "") -> bool:
        """Attach to process via Frida.

        Args:
            pid: Process ID to attach to
            package_name: Android package name (for metadata)

        Returns:
            True if successfully attached
        """
        try:
            # Use provided session or create new one
            if not self.session:
                import frida

                self.session = frida.get_usb_device().attach(pid)
                self.logger.info(f"Attached to process {pid}")
            else:
                self.logger.debug(f"Using existing Frida session for PID {pid}")

            # Load memory tracking script
            self.script = self.session.create_script(FRIDA_MEMORY_SCRIPT)
            self.script.load()
            self.agent = self.script.exports_sync

            self.attached = True
            self.pid = pid
            self.package_name = package_name or f"pid_{pid}"

            self.logger.info(
                f"FridaMemoryTracker attached to {self.package_name} (PID: {pid})"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to attach to process {pid}: {e}")
            return False

    def enumerate_dirty_pages(
        self, target_permissions: str = "rw-", regions: list[str] | None = None
    ) -> list[MemoryPage]:
        """Enumerate writable/dirty pages.

        Args:
            target_permissions: Permission filter (default: "rw-" for writable pages)
            regions: Optional address ranges to filter

        Returns:
            List of MemoryPage objects
        """
        if not self.attached or not self.agent:
            self.logger.error("Not attached to any process")
            return []

        try:
            # Get ranges from Frida
            ranges = self.agent.enumerate_ranges(target_permissions)

            # Convert to MemoryPage objects
            pages = []
            for range_data in ranges:
                base_addr = range_data["base"]
                base_int = (
                    int(base_addr, 16) if isinstance(base_addr, str) else int(base_addr)
                )

                # Filter by regions if specified
                if not self.address_in_regions(base_int, regions):
                    continue

                # Extract module name from file path
                file_path = range_data.get("file", "")
                module = Path(file_path).name if file_path else "[anon]"

                page = MemoryPage(
                    base_address=base_addr
                    if isinstance(base_addr, str)
                    else f"0x{base_int:x}",
                    size=range_data["size"],
                    protection=range_data["protection"],
                    module=module,
                )
                pages.append(page)

            self.logger.info(
                f"Enumerated {len(pages)} dirty pages with permissions '{target_permissions}'"
            )
            return pages

        except Exception as e:
            self.logger.error(f"Failed to enumerate dirty pages: {e}")
            return []

    def create_snapshot(
        self,
        target_permissions: str = "rw-",
        regions: list[str] | None = None,
        compute_checksums: bool = True,
    ) -> MemorySnapshot:
        """Create memory snapshot with checksums.

        Args:
            target_permissions: Permission filter
            regions: Optional address ranges
            compute_checksums: Whether to compute checksums (default: True)

        Returns:
            MemorySnapshot object
        """
        if not self.attached or not self.agent:
            raise RuntimeError("Not attached to any process")

        try:
            pages = []

            if compute_checksums:
                # Use optimized single-call enumeration with checksums
                self.logger.info("Creating snapshot with checksums...")
                ranges = self.agent.enumerate_ranges_with_checksums(target_permissions)

                with ProgressBar(
                    len(ranges), desc="Processing pages", unit="pages"
                ) as progress:
                    for range_data in ranges:
                        base_addr = range_data["base"]
                        base_int = (
                            int(base_addr, 16)
                            if isinstance(base_addr, str)
                            else int(base_addr)
                        )

                        # Filter by regions
                        if not self.address_in_regions(base_int, regions):
                            progress.update(1)
                            continue

                        # Extract module name
                        file_path = range_data.get("file", "")
                        module = Path(file_path).name if file_path else "[anon]"

                        # Get checksum (may be error string)
                        checksum = range_data.get("checksum", "")
                        if checksum.startswith("error"):
                            self.logger.debug(
                                f"Checksum error for {base_addr}: {range_data.get('error')}"
                            )

                        page = MemoryPage(
                            base_address=base_addr
                            if isinstance(base_addr, str)
                            else f"0x{base_int:x}",
                            size=range_data["size"],
                            protection=range_data["protection"],
                            module=module,
                            checksum=checksum,
                        )
                        pages.append(page)
                        progress.update(1)

            else:
                # Just enumerate without checksums
                pages = self.enumerate_dirty_pages(target_permissions, regions)

            snapshot = MemorySnapshot(
                pid=self.pid,
                package_name=self.package_name,
                pages=pages,
                backend="frida",
            )

            self.logger.info(
                f"Created snapshot with {len(pages)} pages "
                f"(total: {snapshot.total_size / 1024 / 1024:.2f} MB)"
            )
            return snapshot

        except Exception as e:
            self.logger.error(f"Failed to create snapshot: {e}")
            raise

    def compare_snapshots(
        self, baseline: MemorySnapshot, current: MemorySnapshot
    ) -> list[MemoryPage]:
        """Compare snapshots and identify changed pages.

        Args:
            baseline: Baseline snapshot
            current: Current snapshot

        Returns:
            List of changed MemoryPage objects (with changed=True)
        """
        # Build lookup dict for baseline checksums
        baseline_dict = {page.base_address: page.checksum for page in baseline.pages}

        changed_pages = []

        for current_page in current.pages:
            base_addr = current_page.base_address
            baseline_checksum = baseline_dict.get(base_addr)

            # Page is changed if:
            # 1. It didn't exist in baseline (new page)
            # 2. Checksum differs from baseline
            if baseline_checksum is None:
                # New page
                current_page.changed = True
                changed_pages.append(current_page)
                self.logger.debug(f"New page detected: {base_addr}")
            elif (
                current_page.checksum != baseline_checksum
                and current_page.checksum not in ["error", "too_large", "read_failed"]
                and baseline_checksum not in ["error", "too_large", "read_failed"]
            ):
                # Changed page
                current_page.changed = True
                changed_pages.append(current_page)
                self.logger.debug(
                    f"Changed page: {base_addr} ({baseline_checksum} -> {current_page.checksum})"
                )

        self.logger.info(
            f"Detected {len(changed_pages)} changed pages out of {len(current.pages)} total"
        )
        return changed_pages

    def dump_page(self, page: MemoryPage, output_path: Path) -> bool:
        """Dump specific memory page to file.

        Args:
            page: MemoryPage to dump
            output_path: Output file path

        Returns:
            True if successful
        """
        if not self.attached or not self.agent:
            self.logger.error("Not attached to any process")
            return False

        try:
            # Read memory content
            address = page.base_address
            size = page.size

            self.logger.debug(f"Dumping page {address} ({size} bytes) to {output_path}")
            data = self.agent.read_memory(address, size)

            if not data:
                self.logger.error(f"Failed to read memory at {address}")
                return False

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(bytes(data))

            self.logger.debug(f"Successfully dumped {size} bytes to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to dump page {page.base_address}: {e}")
            return False

    def detach(self) -> bool:
        """Detach from process.

        Returns:
            True if successful
        """
        try:
            if self.script:
                self.script.unload()
                self.script = None

            # Only detach session if we created it
            if self.session and not self._external_session:
                self.session.detach()
                self.session = None

            self.attached = False
            self.agent = None
            self.logger.info("Detached from process")
            return True

        except Exception as e:
            self.logger.error(f"Error during detach: {e}")
            return False
