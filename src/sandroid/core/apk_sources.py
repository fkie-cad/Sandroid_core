"""APK source providers for searching and downloading Android apps.

This module provides a unified interface for searching multiple APK repositories
including APKPure, F-Droid, and Aptoide.
"""

from __future__ import annotations

import logging
import os
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

import requests

from .adb import Adb
from .exceptions import APKInstallError, APKNetworkError, APKNotFoundError

ProgressCallback = Callable[[int, int], None] | None  # (bytes_downloaded, total_bytes)
SearchProgressCallback = Callable[[str, str], None] | None  # (source_name, status)

# Sentinel value signaling transition from download to ADB install phase
PROGRESS_INSTALL_PHASE = (-1, -1)

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


def _get_external_url(field: str, default: str) -> str:
    """Read an external URL from config with fallback.

    Args:
        field: Field name on ExternalURLsConfig
        default: Fallback value if config unavailable

    Returns:
        The configured value or the default.
    """
    try:
        if get_config is not None:
            return getattr(get_config().external_urls, field, default)
    except Exception:
        pass
    return default


@dataclass
class APKVersion:
    """Represents an available APK version."""

    id: str  # Unique identifier for this version
    name: str  # App name
    package_name: str  # Package name (e.g., org.mozilla.firefox)
    version: str  # Version string (e.g., "120.0.1")
    version_code: int | None = None  # Android version code
    size: int | None = None  # Size in bytes
    download_url: str | None = None  # Direct download URL if available
    source: str = ""  # Source name (apkpure, fdroid, aptoide)
    added_date: str = ""  # Date added/updated

    def __str__(self) -> str:
        return f"[{self.version}] {self.name}"


class APKSource(ABC):
    """Abstract base class for APK source providers."""

    name: str = "unknown"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    @abstractmethod
    def search(self, query: str, limit: int = 10) -> list[APKVersion]:
        """Search for APKs matching the query.

        Args:
            query: Package name or app name to search for
            limit: Maximum number of results

        Returns:
            List of APKVersion objects

        Raises:
            APKNotFoundError: If no results found
            APKNetworkError: If network error occurs
        """

    @abstractmethod
    def download(
        self,
        version: APKVersion,
        dest_path: str,
        progress_callback: ProgressCallback = None,
    ) -> str:
        """Download an APK version.

        Args:
            version: APKVersion to download
            dest_path: Directory to save the APK

        Returns:
            Path to downloaded APK file

        Raises:
            APKInstallError: If download fails
        """

    def _download_file(
        self,
        response: requests.Response,
        file_path: str,
        progress_callback: ProgressCallback = None,
    ) -> str:
        """Download a streaming response to a file with optional progress reporting.

        Args:
            response: Streaming requests Response object
            file_path: Destination file path
            progress_callback: Optional callback receiving (bytes_downloaded, total_bytes)

        Returns:
            The file_path written to
        """
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback:
                    progress_callback(downloaded, total_size)
        return file_path

    def install(
        self, version: APKVersion, progress_callback: ProgressCallback = None
    ) -> str:
        """Download and install an APK version.

        Args:
            version: APKVersion to install
            progress_callback: Optional callback for download progress

        Returns:
            Package name of installed app
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = self.download(
                version, temp_dir, progress_callback=progress_callback
            )
            logger.info(f"Installing {version.name}...")
            if progress_callback:
                progress_callback(*PROGRESS_INSTALL_PHASE)
            result = Adb.install_apk(apk_path)
            return result or version.package_name


class APKPureSource(APKSource):
    """APKPure.com source provider.

    APKPure has a large catalog and provides direct download links.
    """

    name = "apkpure"
    _DEFAULT_BASE_URL = "https://apkpure.com"
    _DEFAULT_API_URL = "https://api.apkpure.com"

    @classmethod
    def _get_base_url(cls) -> str:
        """Get APKPure base URL from config with fallback."""
        return _get_external_url("apkpure_base_url", cls._DEFAULT_BASE_URL)

    @classmethod
    def _get_api_url(cls) -> str:
        """Get APKPure API URL from config with fallback."""
        return _get_external_url("apkpure_api_url", cls._DEFAULT_API_URL)

    # Keep class-level aliases for backwards compatibility
    base_url = _DEFAULT_BASE_URL
    api_url = _DEFAULT_API_URL

    def search(self, query: str, limit: int = 10) -> list[APKVersion]:
        """Search APKPure for apps."""
        # APKPure search API
        api_url = self._get_api_url()
        search_url = f"{api_url}/v3/search_suggestion"
        params = {"key": query, "limit": limit}

        try:
            response = requests.get(
                search_url, params=params, headers=self.headers, timeout=10
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"APKPure search failed: {e}")
            raise APKNetworkError(f"APKPure search failed: {e}", e)

        results = []
        suggestions = data.get("data", []) or []

        for item in suggestions[:limit]:
            pkg = item.get("package_name", "")
            if not pkg:
                continue

            version = APKVersion(
                id=pkg,
                name=item.get("title", pkg),
                package_name=pkg,
                version=item.get("version", ""),
                source=self.name,
            )
            results.append(version)

        if not results:
            raise APKNotFoundError(query, f"No results on {self.name}")

        return results

    def _get_download_info(self, package_name: str) -> dict:
        """Get download information for a package."""
        # APKPure download API
        api_url = self._get_api_url()
        download_url = f"{api_url}/v3/get_app_download"
        params = {"package_name": package_name}

        try:
            response = requests.get(
                download_url, params=params, headers=self.headers, timeout=10
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except requests.exceptions.RequestException as e:
            raise APKNetworkError(f"Failed to get download info: {e}", e)

    def download(
        self,
        version: APKVersion,
        dest_path: str,
        progress_callback: ProgressCallback = None,
    ) -> str:
        """Download APK from APKPure."""
        try:
            info = self._get_download_info(version.package_name)
            download_url = info.get("download_url") or info.get("url")

            if not download_url:
                raise APKInstallError(version.name, "No download URL available")

            file_name = f"{version.package_name}.apk"
            file_path = os.path.join(dest_path, file_name)

            logger.info(f"Downloading {version.name} from APKPure...")
            response = requests.get(
                download_url, headers=self.headers, timeout=300, stream=True
            )
            response.raise_for_status()

            return self._download_file(response, file_path, progress_callback)

        except requests.exceptions.RequestException as e:
            raise APKInstallError(version.name, f"Download failed: {e}")


class FDroidSource(APKSource):
    """F-Droid source provider.

    F-Droid hosts free and open source Android apps.
    Uses:
    - Search API: https://search.f-droid.org/api/search_apps
    - Package API: https://f-droid.org/api/v1/packages/<package>
    - Download: https://f-droid.org/repo/<package>_<versioncode>.apk
    """

    name = "fdroid"
    _DEFAULT_BASE_URL = "https://f-droid.org"
    _DEFAULT_SEARCH_URL = "https://search.f-droid.org/api/search_apps"
    _DEFAULT_PACKAGE_API_URL = "https://f-droid.org/api/v1/packages"
    _DEFAULT_REPO_URL = "https://f-droid.org/repo"

    @classmethod
    def _get_base_url(cls) -> str:
        """Get F-Droid base URL from config with fallback."""
        return _get_external_url("fdroid_base_url", cls._DEFAULT_BASE_URL)

    @classmethod
    def _get_search_url(cls) -> str:
        """Get F-Droid search URL from config with fallback."""
        return _get_external_url("fdroid_search_url", cls._DEFAULT_SEARCH_URL)

    @classmethod
    def _get_package_api_url(cls) -> str:
        """Get F-Droid package API URL from config with fallback."""
        return _get_external_url("fdroid_package_api_url", cls._DEFAULT_PACKAGE_API_URL)

    @classmethod
    def _get_repo_url(cls) -> str:
        """Get F-Droid repo URL from config with fallback."""
        return _get_external_url("fdroid_repo_url", cls._DEFAULT_REPO_URL)

    # Keep class-level aliases for backwards compatibility
    base_url = _DEFAULT_BASE_URL
    search_url = _DEFAULT_SEARCH_URL
    package_api_url = _DEFAULT_PACKAGE_API_URL
    repo_url = _DEFAULT_REPO_URL

    def _get_package_info(self, package_name: str) -> dict:
        """Get package info including versions from F-Droid API."""
        pkg_api_url = self._get_package_api_url()
        url = f"{pkg_api_url}/{package_name}"
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"F-Droid package info failed for {package_name}: {e}")
            return {}

    def search(self, query: str, limit: int = 10) -> list[APKVersion]:
        """Search F-Droid for apps using the search API."""
        results = []

        # Check if query looks like a package name
        is_package_name = "." in query and " " not in query

        if is_package_name:
            # Direct package lookup
            repo_url = self._get_repo_url()
            pkg_info = self._get_package_info(query)
            if pkg_info and pkg_info.get("packages"):
                packages = pkg_info.get("packages", [])
                for pkg in packages[:limit]:
                    version_code = pkg.get("versionCode")
                    version_name = pkg.get("versionName", "")
                    # Download URL: <package>_<versioncode>.apk
                    download_url = f"{repo_url}/{query}_{version_code}.apk"

                    version = APKVersion(
                        id=f"{query}:{version_code}",
                        name=query.rsplit(".", maxsplit=1)[-1]
                        .replace("_", " ")
                        .title(),
                        package_name=query,
                        version=version_name,
                        version_code=version_code,
                        download_url=download_url,
                        source=self.name,
                    )
                    results.append(version)
        else:
            # Use search API for name searches
            fdroid_search_url = self._get_search_url()
            fdroid_repo_url = self._get_repo_url()
            try:
                response = requests.get(
                    fdroid_search_url,
                    params={"q": query},
                    headers=self.headers,
                    timeout=15,
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                logger.debug(f"F-Droid search failed: {e}")
                raise APKNetworkError(f"F-Droid search failed: {e}", e)

            apps = data.get("apps", []) or []

            for app in apps[:limit]:
                app_name = app.get("name", "")
                app_url = app.get("url", "")

                # Extract package name from URL
                # URL format: https://f-droid.org/en/packages/<package_name>
                if "/packages/" in app_url:
                    pkg_name = app_url.split("/packages/")[-1].rstrip("/")
                else:
                    continue

                # Get version info for this package
                pkg_info = self._get_package_info(pkg_name)
                if not pkg_info or not pkg_info.get("packages"):
                    continue

                # Get the latest (first) version
                latest = pkg_info["packages"][0]
                version_code = latest.get("versionCode")
                version_name = latest.get("versionName", "")
                download_url = f"{fdroid_repo_url}/{pkg_name}_{version_code}.apk"

                version = APKVersion(
                    id=f"{pkg_name}:{version_code}",
                    name=app_name,
                    package_name=pkg_name,
                    version=version_name,
                    version_code=version_code,
                    download_url=download_url,
                    source=self.name,
                )
                results.append(version)

        if not results:
            raise APKNotFoundError(query, f"No results on {self.name}")

        return results

    def download(
        self,
        version: APKVersion,
        dest_path: str,
        progress_callback: ProgressCallback = None,
    ) -> str:
        """Download APK from F-Droid."""
        if not version.download_url:
            raise APKInstallError(version.name, "No download URL available")

        try:
            file_name = f"{version.package_name}.apk"
            file_path = os.path.join(dest_path, file_name)

            logger.info(
                f"Downloading {version.name} [{version.version}] from F-Droid..."
            )
            logger.info(f"Download URL: {version.download_url}")
            response = requests.get(
                version.download_url, headers=self.headers, timeout=300, stream=True
            )
            response.raise_for_status()

            # Log file size if available
            content_length = response.headers.get("content-length")
            if content_length:
                logger.info(
                    f"Download size: {int(content_length) / 1024 / 1024:.1f} MB"
                )

            self._download_file(response, file_path, progress_callback)

            logger.info(f"Downloaded to: {file_path}")
            return file_path

        except requests.exceptions.RequestException as e:
            raise APKInstallError(version.name, f"Download failed: {e}")


class AptoideSource(APKSource):
    """Aptoide source provider (legacy, kept for compatibility)."""

    name = "aptoide"
    _DEFAULT_API_URL = "https://ws75.aptoide.com/api/7"
    _DEFAULT_META_URL = "https://ws2.aptoide.com/api/7"

    @classmethod
    def _get_api_url(cls) -> str:
        """Get Aptoide API URL from config with fallback."""
        return _get_external_url("aptoide_api_url", cls._DEFAULT_API_URL)

    @classmethod
    def _get_meta_url(cls) -> str:
        """Get Aptoide metadata API URL from config with fallback."""
        return _get_external_url("aptoide_meta_url", cls._DEFAULT_META_URL)

    # Keep class-level aliases for backwards compatibility
    api_url = _DEFAULT_API_URL
    meta_url = _DEFAULT_META_URL

    def search(self, query: str, limit: int = 10) -> list[APKVersion]:
        """Search Aptoide for apps."""
        aptoide_api_url = self._get_api_url()
        version_url = (
            f"{aptoide_api_url}/app/getVersions/package_name={query}/limit={limit}"
        )

        try:
            response = requests.get(version_url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"Aptoide search failed: {e}")
            raise APKNetworkError(f"Aptoide search failed: {e}", e)

        results = []
        versions = data.get("list", []) or []

        for item in versions[:limit]:
            app_id = item.get("id")
            if not app_id:
                continue

            file_info = item.get("file", {})
            version = APKVersion(
                id=str(app_id),
                name=item.get("name", query),
                package_name=item.get("package", query),
                version=file_info.get("vername", ""),
                version_code=file_info.get("vercode"),
                size=item.get("size"),
                source=self.name,
                added_date=item.get("added", ""),
            )
            results.append(version)

        if not results:
            raise APKNotFoundError(query, f"No results on {self.name}")

        return results

    def _get_app_info(self, app_id: str) -> dict:
        """Get detailed app info including download URL."""
        aptoide_meta_url = self._get_meta_url()
        info_url = f"{aptoide_meta_url}/app/getMeta/app_id={app_id}"

        try:
            response = requests.get(info_url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json().get("data", {})
        except requests.exceptions.RequestException as e:
            raise APKNetworkError(f"Failed to get app info: {e}", e)

    def download(
        self,
        version: APKVersion,
        dest_path: str,
        progress_callback: ProgressCallback = None,
    ) -> str:
        """Download APK from Aptoide.

        Note: Aptoide APKs may have architecture compatibility issues.
        Some older versions only support armeabi-v7a, not arm64-v8a.
        If installation fails with INSTALL_FAILED_NO_MATCHING_ABIS,
        try using F-Droid instead which has more recent builds.
        """
        try:
            info = self._get_app_info(version.id)
            download_url = info.get("file", {}).get("path")

            if not download_url:
                raise APKInstallError(version.name, "No download URL available")

            file_name = f"{version.package_name}.apk"
            file_path = os.path.join(dest_path, file_name)

            logger.info(
                f"Downloading {version.name} [{version.version}] from Aptoide..."
            )
            logger.info(f"Download URL: {download_url}")
            logger.warning(
                "Note: Aptoide APKs may not be compatible with arm64-v8a devices. "
                "If installation fails, try F-Droid instead."
            )
            response = requests.get(
                download_url, headers=self.headers, timeout=300, stream=True
            )
            response.raise_for_status()

            # Log file size if available
            content_length = response.headers.get("content-length")
            if content_length:
                logger.info(
                    f"Download size: {int(content_length) / 1024 / 1024:.1f} MB"
                )

            self._download_file(response, file_path, progress_callback)

            logger.info(f"Downloaded to: {file_path}")
            return file_path

        except requests.exceptions.RequestException as e:
            raise APKInstallError(version.name, f"Download failed: {e}")


class APKSearcher:
    """Unified APK search across multiple sources.

    Tries multiple sources in order of preference and combines results.
    F-Droid is preferred as it has better arm64 compatibility.
    """

    def __init__(self):
        # Sources in order of preference
        # F-Droid first: open source, arm64 compatible, reliable
        # APKPure second: large catalog (but API often blocked)
        # Aptoide last: legacy, often has only 32-bit APKs
        self.sources: list[APKSource] = [
            FDroidSource(),
            APKPureSource(),
            AptoideSource(),
        ]

    def search(
        self,
        query: str,
        limit: int = 10,
        search_progress_callback: SearchProgressCallback = None,
    ) -> list[APKVersion]:
        """Search all sources for APKs.

        Args:
            query: Package name or app name to search for
            limit: Maximum results per source
            search_progress_callback: Optional callback for search progress

        Returns:
            Combined list of APKVersion objects from all sources

        Raises:
            APKNotFoundError: If no results found in any source
        """
        all_results: list[APKVersion] = []
        errors: list[str] = []

        # Check if query looks like a package name
        is_package_name = "." in query and " " not in query

        for source in self.sources:
            try:
                logger.debug(f"Searching {source.name} for: {query}")
                if search_progress_callback:
                    search_progress_callback(source.name, "searching")
                results = source.search(query, limit=limit)
                all_results.extend(results)
                logger.info(f"Found {len(results)} results on {source.name}")
                if search_progress_callback:
                    search_progress_callback(source.name, "done")
            except APKNotFoundError as e:
                errors.append(f"{source.name}: not found")
                logger.debug(f"No results on {source.name}: {e}")
                if search_progress_callback:
                    search_progress_callback(source.name, "not_found")
            except APKNetworkError as e:
                errors.append(f"{source.name}: network error")
                logger.debug(f"Network error on {source.name}: {e}")
                if search_progress_callback:
                    search_progress_callback(source.name, "error")
            except Exception as e:
                errors.append(f"{source.name}: {e!s}")
                logger.warning(f"Error searching {source.name}: {e}")
                if search_progress_callback:
                    search_progress_callback(source.name, "error")

        if not all_results:
            # Check if query looks like it needs the package name format
            has_dots = "." in query
            tip = (
                "Try searching for specific apps by package name"
                if not has_dots
                else "Check the package name spelling"
            )
            raise APKNotFoundError(
                query,
                f"No APK found for '{query}'.\n"
                f"Tip: {tip}\n"
                f"Example: org.mozilla.firefox",
            )

        # Deduplicate by unique ID (package + version + source), keeping different versions
        seen_ids: set[str] = set()
        unique_results: list[APKVersion] = []
        for result in all_results:
            # Create unique key from package name, version, and source
            unique_key = f"{result.package_name}:{result.version}:{result.source}"
            if unique_key not in seen_ids:
                seen_ids.add(unique_key)
                unique_results.append(result)

        return unique_results[:limit]

    def search_single_source(
        self, query: str, source_name: str, limit: int = 10
    ) -> list[APKVersion]:
        """Search a specific source only.

        Args:
            query: Package name or app name
            source_name: Source name (apkpure, fdroid, aptoide)
            limit: Maximum results

        Returns:
            List of APKVersion objects
        """
        for source in self.sources:
            if source.name == source_name:
                return source.search(query, limit)

        raise ValueError(f"Unknown source: {source_name}")

    def get_source(self, source_name: str) -> APKSource:
        """Get a source by name."""
        for source in self.sources:
            if source.name == source_name:
                return source
        raise ValueError(f"Unknown source: {source_name}")

    def install(
        self, version: APKVersion, progress_callback: ProgressCallback = None
    ) -> str:
        """Install an APK version using its source.

        Args:
            version: APKVersion to install
            progress_callback: Optional callback for download progress

        Returns:
            Package name of installed app
        """
        source = self.get_source(version.source)
        return source.install(version, progress_callback=progress_callback)
