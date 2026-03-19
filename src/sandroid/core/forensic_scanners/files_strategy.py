"""Files scan strategy for hash-based APK detection."""

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandroid.core.forensic_evidence import IOCLoader, ProgressCallback

from sandroid.core.adb_utils import is_adb_error_actionable, log_adb_result
from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    ScanType,
)

from .base_strategy import BaseScanStrategy

logger = logging.getLogger(__name__)


class FilesScanStrategy(BaseScanStrategy):
    """Strategy for scanning APK files against hash IOCs."""

    @property
    def scan_type(self) -> ScanType:
        return ScanType.FILES

    def scan(
        self,
        ioc_loader: "IOCLoader",
        progress_callback: "ProgressCallback" = None,
    ) -> ScanResult:
        from sandroid.core.adb import Adb

        start_time = time.time()
        result = self._create_result()

        # Early exit if no hash IOCs
        if not ioc_loader.hashes:
            self._report_progress(
                progress_callback, 0, 0, "", "No hash IOCs to check, skipping..."
            )
            result.scan_duration = time.time() - start_time
            return result

        self._report_progress(
            progress_callback, 0, 0, "", "Getting installed packages..."
        )

        try:
            stdout, stderr = Adb.send_adb_command("shell pm list packages")
            log_adb_result("shell pm list packages", stdout, stderr)
            if stderr and is_adb_error_actionable(stderr):
                logger.warning(f"ADB command warning (pm list packages): {stderr}")

            if stdout:
                packages = self._parse_packages(stdout)
                total_to_scan = len(packages)
                result.scanned_items = total_to_scan

                self._report_progress(
                    progress_callback,
                    0,
                    total_to_scan,
                    "",
                    f"Scanning {total_to_scan} APKs for hash matches...",
                )

                sha256_iocs = [
                    i
                    for i in ioc_loader.hashes
                    if i.get("type", "").upper() in ("SHA-256", "SHA256")
                ]

                for idx, pkg in enumerate(packages):
                    self._report_progress(
                        progress_callback,
                        idx + 1,
                        total_to_scan,
                        pkg[:40],
                        f"Hashing APK {idx + 1}/{total_to_scan}",
                    )

                    matches = self._scan_package(pkg, ioc_loader, sha256_iocs)
                    result.matches.extend(matches)

        except Exception as e:
            result.errors.append(f"File scan error: {e!s}")
            logger.error(f"Error scanning files: {e}")

        result.scan_duration = time.time() - start_time
        return result

    def _parse_packages(self, stdout: str) -> list[str]:
        """Parse package list from pm output."""
        packages = []
        for line in stdout.strip().split("\n"):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return packages

    def _scan_package(
        self,
        pkg: str,
        ioc_loader: "IOCLoader",
        sha256_iocs: list,
    ) -> list[IOCMatch]:
        """Scan a single package for hash matches."""
        from sandroid.core.adb import Adb

        matches = []

        try:
            # Get APK path
            path_stdout, path_stderr = Adb.send_adb_command(f"shell pm path {pkg}")
            log_adb_result(f"shell pm path {pkg}", path_stdout, path_stderr)
            if path_stderr and is_adb_error_actionable(path_stderr):
                logger.warning(f"ADB command warning (pm path {pkg}): {path_stderr}")
            if not path_stdout or "package:" not in path_stdout:
                return matches

            apk_path = path_stdout.strip().replace("package:", "")

            # Check MD5
            hash_stdout, hash_stderr = Adb.send_adb_command(
                f"shell md5sum '{apk_path}'"
            )
            log_adb_result(f"shell md5sum '{apk_path}'", hash_stdout, hash_stderr)
            if hash_stderr and is_adb_error_actionable(hash_stderr):
                logger.warning(
                    f"ADB command warning (md5sum {apk_path}): {hash_stderr}"
                )
            if hash_stdout and not hash_stdout.startswith("md5sum:"):
                parts = hash_stdout.split()
                if parts:
                    file_md5 = parts[0].strip().lower()

                    for ioc in ioc_loader.hashes:
                        ioc_value = ioc["value"].lower()
                        ioc_type = ioc.get("type", "").upper()

                        if ioc_type in ("MD5", "") and file_md5 == ioc_value:
                            matches.append(
                                IOCMatch(
                                    indicator_type="file_hash",
                                    indicator_value=ioc["value"],
                                    matched_data=f"{pkg} ({apk_path})",
                                    source="apk_hash",
                                    severity=MatchSeverity.CRITICAL,
                                    description=ioc.get(
                                        "description", f"MD5 hash match for {pkg}"
                                    ),
                                )
                            )
                            logger.info(f"Hash IOC match: {pkg} matches MD5 {ioc['value']}")

            # Check SHA-256 if we have SHA-256 IOCs
            if sha256_iocs:
                sha_stdout, sha_stderr = Adb.send_adb_command(
                    f"shell sha256sum '{apk_path}'"
                )
                log_adb_result(f"shell sha256sum '{apk_path}'", sha_stdout, sha_stderr)
                if sha_stderr and is_adb_error_actionable(sha_stderr):
                    logger.warning(
                        f"ADB command warning (sha256sum {apk_path}): {sha_stderr}"
                    )
                if sha_stdout and not sha_stdout.startswith("sha256sum:"):
                    sha_parts = sha_stdout.split()
                    if sha_parts:
                        file_sha256 = sha_parts[0].strip().lower()

                        for ioc in sha256_iocs:
                            if file_sha256 == ioc["value"].lower():
                                matches.append(
                                    IOCMatch(
                                        indicator_type="file_hash",
                                        indicator_value=ioc["value"],
                                        matched_data=f"{pkg} ({apk_path})",
                                        source="apk_hash",
                                        severity=MatchSeverity.CRITICAL,
                                        description=ioc.get(
                                            "description", f"SHA-256 hash match for {pkg}"
                                        ),
                                    )
                                )
                                logger.info(
                                    f"Hash IOC match: {pkg} matches SHA-256 {ioc['value']}"
                                )

        except Exception as e:
            logger.debug(f"Error checking hash for {pkg}: {e}")

        return matches


__all__ = ["FilesScanStrategy"]
