import os
import re
import subprocess
import tempfile
from logging import getLogger

import requests
from bs4 import BeautifulSoup as BS
from tqdm import tqdm

from sandroid.services import get_ui_service

from .adb import Adb
from .console import SandroidConsole
from .exceptions import (
    APKInstallError,
    APKNetworkError,
    APKNotFoundError,
    APKVersionNotFoundError,
)

try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = getLogger(__name__)


def _get_display_value(field: str, default):
    """Read a display config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().display, field, default)
    except Exception:
        pass
    return default


def _get_external_url(field: str, default: str) -> str:
    """Read an external URL config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().external_urls, field, default)
    except Exception:
        pass
    return default


# parts taken and adapted from https://github.com/jayluxferro/APK-Downloader/blob/main/apk-downloader.py
# parts taken and adapted from https://github.com/09u2h4n/PyAPKDownloader


class ApkDownloaderTools:
    def __init__(self) -> None:
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
        }

    def download_w_progress_bar(self, url: str, file_path):
        with requests.get(
            url=url, stream=True, headers=self.headers, timeout=30
        ) as response:
            total_size_header = response.headers.get("content-length")
            if total_size_header is None:
                return None
            try:
                total_size = int(total_size_header)
            except ValueError:
                return None
            chunk_size = 1024
            progress_bar = tqdm(total=total_size, unit="B", unit_scale=True)

            full_path = os.path.join(file_path, url.rsplit("/", maxsplit=1)[-1])
            with open(full_path, "wb") as f:
                logger.info(f"Downloading to {full_path}")
                for data in response.iter_content(chunk_size=chunk_size):
                    progress_bar.update(len(data))
                    f.write(data)
            progress_bar.close()

        return full_path


class ApkDownloader:
    _DEFAULT_APTOIDE_API_URL = "https://ws75.aptoide.com/api/7"
    _DEFAULT_APTOIDE_META_URL = "https://ws2.aptoide.com/api/7"

    def __init__(self) -> None:
        aptoide_api = _get_external_url(
            "aptoide_api_url", self._DEFAULT_APTOIDE_API_URL
        )
        aptoide_meta = _get_external_url(
            "aptoide_meta_url", self._DEFAULT_APTOIDE_META_URL
        )
        self.aptoide_web_api_base_url_get_versions = f"{aptoide_api}/app/getVersions/"
        self.aptoide_web_api_base_url_get_meta = f"{aptoide_meta}/app/getMeta/"
        self.headers = ApkDownloaderTools().headers

    def search_for_name(self, package_name, wanted_version=None, limit=10):
        version_url = f"{self.aptoide_web_api_base_url_get_versions}package_name={package_name}/limit={limit}"
        try:
            v_res = requests.get(url=version_url, headers=self.headers, timeout=10)
            v_res.raise_for_status()  # Raise an exception for bad HTTP status codes
            response_data = v_res.json()

            if "list" not in response_data:
                logger.error(
                    f"Unexpected API response format for package '{package_name}': {response_data}"
                )
                raise ValueError("API returned unexpected format - no 'list' key found")

            json_data_list = response_data["list"]
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error while searching for '{package_name}': {e}")
            raise
        except ValueError as e:
            logger.error(f"JSON parsing error or invalid response format: {e}")
            raise
        except KeyError as e:
            logger.error(f"Missing expected key in API response: {e}")
            raise

        if json_data_list == []:
            logger.error(f"{package_name} could not be found.")
            raise APKNotFoundError(package_name)
        logger.info(f"Displaying search results for {package_name}")
        for json_data in json_data_list:
            print(
                f"[{json_data['file']['vername']}] {json_data['name']} ({json_data['added']})"
            )

        # Ask for user input to select a version
        logger.info(
            "Enter the version string to select (press ENTER for the latest version): "
        )
        version_input = get_ui_service().safe_input()

        if version_input == "":
            # Select the latest version
            json_data = json_data_list[0]
            app_id = json_data["id"]
        else:
            # Select the specified version
            app_id = None
            for json_data in json_data_list:
                app_version = json_data["file"]["vername"]
                if version_input == app_version:
                    app_id = json_data["id"]
                    break

            if app_id is None:
                available = [j["file"]["vername"] for j in json_data_list]
                raise APKVersionNotFoundError(package_name, version_input, available)

        # Continue with the selected app_id
        logger.info(f"Selected version: {json_data['file']['vername']} (ID: {app_id})")

        return app_id

    def __get_app_infos_by_app_id(self, app_id: str):
        app_info_url = f"{self.aptoide_web_api_base_url_get_meta}app_id={app_id}"
        i_res = requests.get(url=app_info_url, headers=self.headers, timeout=10)
        app_info_json = i_res.json()

        app_size = app_info_json["data"]["size"]
        app_version = app_info_json["data"]["file"]["vername"]
        app_download_url = app_info_json["data"]["file"]["path"]
        app_ext = app_download_url.split(".")[1]
        app_name = app_info_json["data"]["name"]
        app_fullname = f"{app_name} {app_version}.{app_ext}"

        return {
            "app_size": app_size,
            "app_version": app_version,
            "app_download_url": app_download_url,
            "app_ext": app_ext,
            "app_name": app_name,
            "app_fullname": app_fullname,
        }

    def download_by_app_id(self, app_id, file_path):
        app_infos = self.__get_app_infos_by_app_id(app_id)
        d_url = app_infos["app_download_url"]
        app_size = app_infos["app_size"]
        app_ext = app_infos["app_ext"]
        app_version = app_infos["app_version"]
        app_full_name = app_infos["app_fullname"]

        return ApkDownloaderTools().download_w_progress_bar(d_url, file_path)

    def install_app_id(self, app_id):
        """Downloads and installs a specific version of an APK.

        :param version: The version details of the APK.
        :type version: dict
        """
        with tempfile.TemporaryDirectory() as dir:
            file_path = self.download_by_app_id(app_id, dir)
            if file_path:
                logger.info(f"Installing {file_path}")
                Adb.install_apk(file_path)

    def install_app_id_simple(self, app_id) -> str:
        """Downloads and installs APK without progress bar (TUI-friendly).

        This method is designed for use in async/TUI contexts where tqdm
        progress bars cause issues with file descriptors.

        Args:
            app_id: The Aptoide app ID to install

        Returns:
            Package name of installed app

        Raises:
            APKInstallError: If download or installation fails
        """
        app_infos = self.__get_app_infos_by_app_id(app_id)
        download_url = app_infos["app_download_url"]
        app_name = app_infos.get("app_name", "Unknown")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Download without tqdm (simpler, works in async contexts)
            file_name = download_url.split("/")[-1]
            file_path = os.path.join(temp_dir, file_name)

            logger.info(f"Downloading {app_name}...")
            try:
                response = requests.get(
                    download_url,
                    headers=ApkDownloaderTools().headers,
                    timeout=120,
                    stream=True,
                )
                response.raise_for_status()

                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

            except requests.exceptions.RequestException as e:
                raise APKInstallError(app_name, f"Download failed: {e}")

            if not os.path.exists(file_path):
                raise APKInstallError(app_name, "Download failed - file not created")

            logger.info(f"Installing {app_name}...")
            result = Adb.install_apk(file_path)
            return result or app_name

    def get_versions_only(self, package_name: str, limit: int = 10) -> list[dict]:
        """Get available versions without interactive prompts.

        For use by TUI modal to display version selection.

        Args:
            package_name: Package name to search for
            limit: Maximum number of versions to return

        Returns:
            List of version dictionaries with keys:
                - id: App ID for installation
                - name: App name
                - file.vername: Version string
                - added: Date added

        Raises:
            APKNotFoundError: If package not found
            APKNetworkError: If network request fails
        """
        version_url = f"{self.aptoide_web_api_base_url_get_versions}package_name={package_name}/limit={limit}"

        try:
            v_res = requests.get(url=version_url, headers=self.headers, timeout=10)
            v_res.raise_for_status()
            response_data = v_res.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error while searching for '{package_name}': {e}")
            raise APKNetworkError(f"Network error searching for '{package_name}'", e)

        if "list" not in response_data:
            logger.error(f"Unexpected API response for '{package_name}'")
            raise APKNotFoundError(package_name, "API returned unexpected format")

        json_data_list = response_data["list"]

        if not json_data_list:
            raise APKNotFoundError(package_name)

        return json_data_list


class ApkDownloader_Old:
    """Handles APK downloading and installation from apksfull.com.

    **Attributes:**
        base_url (str): Base URL for the APK site.
        version_url (str): URL for fetching APK versions.
        download_url (str): URL for downloading APKs.
        search_url (str): URL for searching APKs.
        logger (Logger): Logger instance for APKDownloader operations.
        headers (dict): HTTP headers for requests.
    """

    _DEFAULT_BASE_URL = "https://apksfull.com"
    _DEFAULT_APK_SEARCH_LIMIT = 5

    @classmethod
    def _get_base_url(cls) -> str:
        """Get base URL from config with fallback."""
        return _get_external_url("apksfull_base_url", cls._DEFAULT_BASE_URL)

    @classmethod
    def _get_search_limit(cls) -> int:
        """Get APK search result limit from config with fallback."""
        return _get_display_value("apk_search_limit", cls._DEFAULT_APK_SEARCH_LIMIT)

    @classmethod
    def _get_urls(cls) -> dict[str, str]:
        """Get all derived URLs from base URL."""
        base = cls._get_base_url()
        return {
            "base": base,
            "version": f"{base}/version/",
            "download": f"{base}/dl/",
            "search": f"{base}/search/",
        }

    # Keep class-level attrs for backwards compatibility with headers
    base_url = _DEFAULT_BASE_URL
    version_url = f"{base_url}/version/"
    download_url = f"{base_url}/dl/"
    search_url = f"{base_url}/search/"

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": f"{base_url}",
        "`Referer": f"{search_url}",
        "Connection": "keep-alive",
    }

    def download_file(data):
        """Downloads the APK file using wget.

        :param data: Dictionary containing the download link.
        :type data: dict
        """
        global bundle_identifier, app_version
        print("[+] Downloading...")
        try:
            subprocess.call(
                [
                    "wget",
                    data["download_link"],
                    "-O",
                    f"{bundle_identifier}-{app_version}.apk",
                ]
            )
        except OSError as e:
            logger.error(f"Failed to start wget process: {e}")
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error running wget: {e}")

    @classmethod
    def search_for_name(cls, name):
        """Searches for APKs online by name.

        :param name: The name of the APK to search for.
        :type name: str
        :returns: A list of search results.
        :rtype: list of dict
        """
        urls = cls._get_urls()
        res = requests.get(
            f"{urls['search']}/{name}",
            headers=cls.headers,
            allow_redirects=True,
            timeout=10,
        )
        if res.status_code != 200:
            print("ERROR")

        web_data = BS(res.content, "html.parser")
        links = web_data.findAll("a")

        # take top hits from config (default 5)
        TOP_HITS = cls._get_search_limit()
        counter = 0
        search_results = []

        for link in links:
            if counter >= TOP_HITS:
                break
            title = link.get("title")

            # only consider links for APKs
            if not title:
                continue
            title_parts = title.split()
            if not title_parts or title_parts[0] != "download":
                continue

            last_p = link.find_all("p")[-1]
            last_span = last_p.find_all("span")[-1]
            version_number = last_span.text
            href = f"{urls['base']}{link.get('href')}"
            package_name = href.rsplit("/", maxsplit=1)[-1]
            title = " ".join(title.split()[1:])

            result = {
                "title": title,
                "package_name": package_name,
                "version": version_number,
                "href": href,
            }

            search_results.append(result)

            counter += 1

        return search_results

    @classmethod
    def display_search_results_menu(cls, search_results):
        """Displays the search results in a formatted menu.

        :param search_results: List of search results.
        :type search_results: list of dict
        """
        console = SandroidConsole.get()
        console.print("[bold]+++ Search Results +++[/bold]")
        for i, result in enumerate(search_results):
            console.print(
                f"    \\[{i}] {result['title']} {result['version']} ([accent]{result['package_name']}[/accent])"
            )

    @classmethod
    def get_versions(cls, result):
        """Retrieves available versions for a given APK.

        :param result: The search result containing the package name.
        :type result: dict
        :returns: A list of available versions.
        :rtype: list of dict
        """
        urls = cls._get_urls()
        apk_url = f"{urls['version']}{result['package_name']}"

        res = requests.get(
            apk_url, headers=cls.headers, allow_redirects=True, timeout=30
        )
        if res.status_code != 200:
            print("ERROR")

        web_data = BS(res.content, "html.parser")
        rows = web_data.findAll("tr")
        versions = []

        TOP_HITS = cls._get_search_limit()
        counter = 0

        for row in rows:
            if counter >= TOP_HITS:
                break

            link = row.find("a")
            # no href => probably first row without links
            try:
                _link = link.get("href")
            except AttributeError:
                logger.debug("Row has no link element, skipping")
                continue

            if _link.find("/download/") != -1:
                cols = row.find_all("td")
                arch = cols[1].text
                updated = cols[3].text

                _version = link.text.strip()
                _title = " ".join(link.get("title").split(" ")[1:-1])
                versions.append(
                    {
                        "url": f"{urls['base']}{_link}",
                        "version": _version,
                        "package_name": result["package_name"],
                        "arch": arch,
                        "updated": updated,
                    }
                )

                counter += 1

        return versions

    @classmethod
    def display_versions(cls, versions):
        """Displays the available versions in a formatted menu.

        :param versions: List of available versions.
        :type versions: list of dict
        """
        console = SandroidConsole.get()
        console.print(
            f"[bold]+++ Versions for {versions[0]['package_name']} +++[/bold]"
        )
        for i, version in enumerate(versions):
            console.print(
                f"    \\[{i}] {version['version']} {version['arch']} ([secondary]{version['updated']}[/secondary])"
            )

    @classmethod
    def get_real_download_url(cls, version_url):
        """Retrieves the real download URL for a given APK version.

        :param version_url: The URL of the APK version.
        :type version_url: str
        :returns: The real download URL if available, None otherwise.
        :rtype: str or None
        """
        res = requests.get(
            version_url, headers=cls.headers, allow_redirects=True, timeout=10
        )
        if res.status_code != 200:
            return None

        web_data = BS(res.content, "html.parser").findAll("script")

        token = re.findall("token','([^']+)", web_data[-2].contents[0])[0]

        payload = {"token": token}

        res = requests.post(
            cls.download_url, data=payload, headers=cls.headers, timeout=10
        )
        if res.status_code != 200:
            return None

        data = res.json()
        if data["status"] is True:
            return data["download_link"]
        return None

    @classmethod
    def download_version(cls, version, path):
        """Downloads a specific version of an APK to a given path.

        :param version: The version details of the APK.
        :type version: dict
        :param path: The path to save the downloaded APK.
        :type path: str
        :returns: The file path of the downloaded APK.
        :rtype: str or None
        """
        version_url = version["url"]
        download_url = cls.get_real_download_url(version_url)
        file_name = f"{version['package_name']}-{version['version']}.apk"

        if not download_url:
            cls.logger.error("Could not get download URL for APK")
            return None

        with open(f"{path}/{file_name}", "wb") as fsb:
            cls.logger.info(f"Downloading {version['package_name']} to {path}")
            res = requests.get(download_url, timeout=30)
            fsb.write(res.content)

        return f"{path}/{file_name}"
