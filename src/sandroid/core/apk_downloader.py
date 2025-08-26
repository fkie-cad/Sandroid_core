import os
import re
import subprocess
import tempfile
from logging import getLogger

import click
import requests
from bs4 import BeautifulSoup as BS
from colorama import Fore, Style
from tqdm import tqdm

from .adb import Adb

logger = getLogger(__name__)


# parts taken and adapted from https://github.com/jayluxferro/APK-Downloader/blob/main/apk-downloader.py
# parts taken and adapted from https://github.com/09u2h4n/PyAPKDownloader


class ApkDownloaderTools:
    def __init__(self) -> None:
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
        }

    def download_w_progress_bar(self, url: str, file_path):
        response = requests.get(url=url, stream=True, headers=self.headers, timeout=30)
        try:
            total_size = int(response.headers.get("content-length"))
        except ValueError:
            pass
        if total_size is None:
            return None
        chunk_size = 1024
        progress_bar = tqdm(total=total_size, unit="B", unit_scale=True)

        full_path = os.path.join(file_path, url.split("/")[-1])
        with open(full_path, "wb") as f:
            logger.info(f"Downloading to {full_path}")
            for data in response.iter_content(chunk_size=chunk_size):
                progress_bar.update(len(data))
                f.write(data)
        progress_bar.close()

        return full_path


class ApkDownloader:
    def __init__(self) -> None:
        self.aptoide_web_api_base_url_get_versions = (
            "https://ws75.aptoide.com/api/7/app/getVersions/"
        )
        self.aptoide_web_api_base_url_get_meta = (
            "https://ws2.aptoide.com/api/7/app/getMeta/"
        )
        self.headers = ApkDownloaderTools().headers

    def search_for_name(self, package_name, wanted_version=None, limit=10):
        version_url = f"{self.aptoide_web_api_base_url_get_versions}package_name={package_name}/limit={limit}"
        v_res = requests.get(url=version_url, headers=self.headers, timeout=10)
        json_data_list = v_res.json()["list"]

        if json_data_list == []:
            logger.error(f"{package_name} could not be found.")
            exit()
        else:
            logger.info(f"Displaying search results for {package_name}")
            for json_data in json_data_list:
                print(
                    f"[{json_data['file']['vername']}] {json_data['name']} ({json_data['added']})"
                )

        # Ask for user input to select a version
        logger.info(
            "Enter the version string to select (press ENTER for the latest version): "
        )
        version_input = input()

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
                logger.error(f"Version {version_input} could not be found.")
                exit()

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
        print(app_infos)
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
            print(file_path)
            if file_path:
                logger.info(f"Installing {file_path}")
                Adb.install_apk(file_path)


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

    base_url = "https://apksfull.com"
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
        subprocess.call(
            [
                "wget",
                data["download_link"],
                "-O",
                f"{bundle_identifier}-{app_version}.apk",
            ]
        )

    @classmethod
    def search_for_name(cls, name):
        """Searches for APKs online by name.

        :param name: The name of the APK to search for.
        :type name: str
        :returns: A list of search results.
        :rtype: list of dict
        """
        res = requests.get(
            f"{cls.search_url}/{name}",
            headers=cls.headers,
            allow_redirects=True,
            timeout=10,
        )
        if res.status_code != 200:
            print("ERROR")

        web_data = BS(res.content, "html.parser")
        links = web_data.findAll("a")

        # take top 5 hits of the links
        TOP_HITS = 5
        counter = 0
        search_results = []

        for link in links:
            if counter >= TOP_HITS:
                break
            title = link.get("title")

            # only consider links for APKs
            if not title or title.split()[0] != "download":
                continue

            last_p = link.find_all("p")[-1]
            last_span = last_p.find_all("span")[-1]
            version_number = last_span.text
            href = f"{cls.base_url}{link.get('href')}"
            package_name = href.split("/")[-1]
            title = " ".join(title.split()[1:])

            # print(f"{title} {version_number} {href}")
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
        display_string = f"""{Style.BRIGHT}+++ Search Results +++{Style.RESET_ALL}\n"""
        for i, result in enumerate(search_results):
            display_string += f"    [{i}] {result['title']} {result['version']} ({Fore.YELLOW}{result['package_name']}{Fore.RESET})\n"

        click.echo(display_string)

    @classmethod
    def get_versions(cls, result):
        """Retrieves available versions for a given APK.

        :param result: The search result containing the package name.
        :type result: dict
        :returns: A list of available versions.
        :rtype: list of dict
        """
        apk_url = f"{cls.version_url}{result['package_name']}"

        res = requests.get(
            apk_url, headers=cls.headers, allow_redirects=True, timeout=30
        )
        if res.status_code != 200:
            print("ERROR")

        web_data = BS(res.content, "html.parser")
        rows = web_data.findAll("tr")
        versions = []

        TOP_HITS = 5
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
                        "url": f"{cls.base_url}{_link}",
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
        display_string = f"""{Style.BRIGHT}+++ Versions for {versions[0]["package_name"]} +++{Style.RESET_ALL}\n"""
        for i, version in enumerate(versions):
            display_string += f"    [{i}] {version['version']} {version['arch']} ({Fore.LIGHTMAGENTA_EX}{version['updated']}{Fore.RESET})\n"

        click.echo(display_string)

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
        if data["status"] == True:
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
