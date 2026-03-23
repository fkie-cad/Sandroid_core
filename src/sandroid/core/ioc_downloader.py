"""IOC Downloader utility for MVT indicators.

Provides downloading of IOC (Indicators of Compromise) files from:
1. MVT tool (mvt-android download-iocs command)
2. Direct GitHub download (fallback if MVT not installed)
3. Custom URL download
"""

import logging
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


def _create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context with proper certificate handling.

    Tries to use certifi certificates first, then falls back to system defaults.
    """
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        return context
    except ImportError:
        pass

    # Try to create context with system certificates
    context = ssl.create_default_context()

    # On macOS, try to load certificates from common locations
    macos_cert_paths = [
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/usr/local/etc/openssl@1.1/cert.pem",
        "/opt/homebrew/etc/openssl@3/cert.pem",
        "/opt/homebrew/etc/openssl/cert.pem",
    ]

    for cert_path in macos_cert_paths:
        if os.path.exists(cert_path):
            try:
                context.load_verify_locations(cert_path)
                return context
            except ssl.SSLError:
                continue

    return context


class IOCDownloader:
    """Downloads and manages IOC files for forensic scanning.

    Supports three download methods:
    - MVT command: Uses mvt-android download-iocs
    - GitHub fallback: Downloads from MVT's GitHub repository
    - Custom URL: Downloads from any URL (for stalkerware indicators, etc.)
    """

    CACHE_DIR = Path.home() / ".cache" / "sandroid" / "iocs"

    # Default MVT GitHub base URL (kept as fallback)
    _DEFAULT_MVT_GITHUB_BASE = "https://raw.githubusercontent.com/mvt-project/mvt/main/"
    MVT_IOC_FILES = [
        "mvt/android/data/androidspy.stix2",
        "mvt/android/data/malware.stix2",
        "mvt/android/data/pegasus.stix2",
        "mvt/android/data/spyware.stix2",
    ]

    @classmethod
    def _get_mvt_github_base(cls) -> str:
        """Get MVT GitHub base URL from config with fallback.

        Returns:
            MVT GitHub raw content base URL.
        """
        try:
            if get_config is not None:
                return get_config().external_urls.mvt_github_base
        except Exception:
            pass
        return cls._DEFAULT_MVT_GITHUB_BASE

    # Keep class-level alias for backwards compatibility
    MVT_GITHUB_BASE = _DEFAULT_MVT_GITHUB_BASE

    def __init__(self):
        """Initialize the IOC downloader."""
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists."""
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def download_mvt_iocs(self) -> Path | None:
        """Download MVT IOCs using mvt-android or GitHub fallback.

        Tries mvt-android download-iocs first. If not installed or fails,
        falls back to downloading directly from MVT's GitHub repository.

        Returns:
            Path to IOC directory on success, None on failure
        """
        # Try mvt-android command first
        ioc_path = self._try_mvt_command()
        if ioc_path:
            logger.info(f"Downloaded MVT IOCs via mvt-android to: {ioc_path}")
            return ioc_path

        # Fallback to GitHub download
        logger.info("mvt-android not available, downloading from GitHub...")
        ioc_path = self._download_from_github()
        if ioc_path:
            logger.info(f"Downloaded MVT IOCs from GitHub to: {ioc_path}")
            return ioc_path

        logger.error("Failed to download MVT IOCs")
        return None

    def download_from_url(self, url: str) -> Path | None:
        """Download IOC file from a custom URL.

        Args:
            url: URL to STIX2 IOC file

        Returns:
            Path to downloaded file on success, None on failure
        """
        try:
            # Generate filename from URL
            filename = url.rsplit("/", maxsplit=1)[-1]
            if not filename.endswith((".stix2", ".json")):
                filename = "custom_iocs.stix2"

            output_path = self.CACHE_DIR / filename

            logger.info(f"Downloading IOC file from: {url}")

            ssl_context = _create_ssl_context()
            with urlopen(url, timeout=30, context=ssl_context) as response:  # nosec B310
                content = response.read()

            output_path.write_bytes(content)
            logger.info(f"Downloaded IOC file to: {output_path}")
            return output_path

        except URLError as e:
            logger.error(f"Failed to download IOC from URL: {e}")
            return None
        except Exception as e:
            logger.error(f"Error downloading IOC file: {e}")
            return None

    def _find_mvt_android(self) -> str | None:
        """Find mvt-android executable.

        Checks PATH and common virtual environment locations.

        Returns:
            Path to mvt-android if found, None otherwise
        """
        # First check PATH
        mvt_path = shutil.which("mvt-android")
        if mvt_path:
            return mvt_path

        # Check common virtual environment locations
        venv_bin = Path(sys.executable).parent
        mvt_in_venv = venv_bin / "mvt-android"
        if mvt_in_venv.exists():
            return str(mvt_in_venv)

        # Check user's local bin
        user_local_bin = Path.home() / ".local" / "bin" / "mvt-android"
        if user_local_bin.exists():
            return str(user_local_bin)

        return None

    def _get_mvt_indicators_folder(self) -> Path:
        """Get the MVT indicators folder path.

        Returns:
            Path to MVT's default indicators folder
        """
        # Try to get from MVT module
        try:
            from mvt.common.updates import MVT_INDICATORS_FOLDER

            return Path(MVT_INDICATORS_FOLDER)
        except ImportError:
            pass

        # Fallback: use platform-specific Application Support folder
        if sys.platform == "darwin":
            return (
                Path.home() / "Library" / "Application Support" / "mvt" / "indicators"
            )
        if sys.platform == "win32":
            return Path(os.environ.get("APPDATA", "")) / "mvt" / "indicators"
        return Path.home() / ".local" / "share" / "mvt" / "indicators"

    def _try_mvt_command(self) -> Path | None:
        """Try to run mvt-android download-iocs command.

        Returns:
            Path to IOC directory if successful, None otherwise
        """
        # Check if mvt-android is installed
        mvt_android = self._find_mvt_android()
        if not mvt_android:
            logger.debug("mvt-android not found in PATH or common locations")
            return None

        try:
            # MVT downloads to its default indicators folder
            mvt_ioc_dir = self._get_mvt_indicators_folder()

            logger.debug(f"Running mvt-android from: {mvt_android}")
            result = subprocess.run(
                [mvt_android, "download-iocs"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                # Check if files were downloaded
                if mvt_ioc_dir.exists():
                    stix_files = list(mvt_ioc_dir.glob("*.stix2"))
                    if stix_files:
                        return mvt_ioc_dir
                logger.warning("mvt-android ran but no IOC files found")
                return None

            logger.debug(f"mvt-android failed: {result.stderr}")
            return None

        except subprocess.TimeoutExpired:
            logger.warning("mvt-android download timed out")
            return None
        except Exception as e:
            logger.debug(f"mvt-android command failed: {e}")
            return None

    def _download_from_github(self) -> Path | None:
        """Download IOC files directly from MVT's GitHub repository.

        Returns:
            Path to IOC directory if successful, None otherwise
        """
        github_ioc_dir = self.CACHE_DIR / "github_mvt"
        github_ioc_dir.mkdir(parents=True, exist_ok=True)

        downloaded_files = []
        ssl_context = _create_ssl_context()
        mvt_base = self._get_mvt_github_base()

        for ioc_file in self.MVT_IOC_FILES:
            url = f"{mvt_base}{ioc_file}"
            filename = ioc_file.split("/")[-1]
            output_path = github_ioc_dir / filename

            try:
                logger.debug(f"Downloading {filename}...")
                with urlopen(url, timeout=30, context=ssl_context) as response:  # nosec B310
                    content = response.read()

                output_path.write_bytes(content)
                downloaded_files.append(output_path)
                logger.debug(f"Downloaded: {filename}")

            except Exception as e:
                logger.warning(f"Failed to download {filename}: {e}")
                continue

        if downloaded_files:
            logger.info(f"Downloaded {len(downloaded_files)} IOC files from GitHub")
            return github_ioc_dir

        return None

    def get_cached_iocs(self) -> Path | None:
        """Get path to cached IOCs if they exist.

        Returns:
            Path to IOC directory/file if cached, None otherwise
        """
        # Check MVT's default indicators folder first
        mvt_indicators = self._get_mvt_indicators_folder()
        if mvt_indicators.exists() and list(mvt_indicators.glob("*.stix2")):
            return mvt_indicators

        # Check for our cache's mvt downloaded IOCs
        mvt_dir = self.CACHE_DIR / "mvt"
        if mvt_dir.exists() and list(mvt_dir.glob("*.stix2")):
            return mvt_dir

        # Check for GitHub downloaded IOCs
        github_dir = self.CACHE_DIR / "github_mvt"
        if github_dir.exists() and list(github_dir.glob("*.stix2")):
            return github_dir

        # Check for any STIX2 files in cache root
        stix_files = list(self.CACHE_DIR.glob("*.stix2"))
        if stix_files:
            return self.CACHE_DIR

        return None

    def get_cached_iocs_info(self) -> dict | None:
        """Get information about cached IOCs.

        Returns:
            Dict with 'path', 'file_count', 'indicator_count' or None if no cache
        """
        cached_path = self.get_cached_iocs()
        if not cached_path:
            return None

        try:
            # Count STIX2 files
            if cached_path.is_dir():
                stix_files = list(cached_path.glob("*.stix2"))
            else:
                stix_files = [cached_path] if cached_path.suffix == ".stix2" else []

            if not stix_files:
                return None

            # Count indicators by parsing STIX2 files
            indicator_count = 0
            for stix_file in stix_files:
                try:
                    import json

                    with open(stix_file, encoding="utf-8") as f:
                        data = json.load(f)
                        # STIX2 bundles have "objects" array
                        if isinstance(data, dict) and "objects" in data:
                            indicator_count += len(data["objects"])
                        elif isinstance(data, list):
                            indicator_count += len(data)
                except Exception:
                    # If we can't parse, just count files
                    pass

            return {
                "path": str(cached_path),
                "file_count": len(stix_files),
                "indicator_count": indicator_count,
            }

        except Exception as e:
            logger.debug(f"Error getting cached IOC info: {e}")
            return None

    def clear_cache(self) -> None:
        """Clear all cached IOC files."""
        if self.CACHE_DIR.exists():
            shutil.rmtree(self.CACHE_DIR)
            self._ensure_cache_dir()
            logger.info("IOC cache cleared")
