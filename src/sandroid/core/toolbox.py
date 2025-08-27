# Standard library imports
import argparse
import datetime
import fnmatch
import hashlib
import logging
import os
import re
import shutil
import subprocess
import threading
import time

# Third-party imports
import click
import dateutil.parser as dp

# Local imports
from AndroidFridaManager import FridaManager, JobManager
from colorama import Fore, Style

# Updated to use migrated modules within same package
from .adb import Adb
from .CustomLoggerFormatter import CustomFormatter
from .emulator import Emulator


class Toolbox:
    """A static class providing various utility functions for forensic analysis on an Android Virtual Device (AVD)."""

    action_time = 0
    already_looked_at_filesystem_for_this_action_time = False
    action_duration = 0
    changed_files_cache = {}
    _timestamps_shadow_dict_list = []
    noise_files = {}
    baseline = {}
    noise_processes = []
    other_output_data_collector = {}
    file_paths_whitelist = None
    _is_dry_run = False
    _run_counter = 0
    _spotlight_application = None
    _spotlight_application_pid = None
    logger = None
    args = None
    frida_manager = None
    _frida_job_manager = None
    malware_monitor_running = False
    _spotlight_files = []
    _network_capture_running = False
    _network_capture_file = None
    _screen_recording_running = False
    _screen_recording_file = None
    _spotlight_pull_one = None
    _spotlight_pull_two = None
    _screen_recording_running = False

    # replace these with your own values
    # TODO: Shouldn't be hardcoded
    device_name = "Pixel_6_Pro_API_31"
    android_emulator_path = "~/Android/Sdk/emulator/emulator"

    def __new__(cls):
        raise TypeError("This is a static class and cannot be instantiated.")

    @classmethod
    def init(cls):
        """Initializes the Toolbox class by parsing command-line arguments and setting up the logger and Frida manager."""
        cls.init_files()

        parser = argparse.ArgumentParser(
            description="Find forensic artefacts for any action on an AVD"
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            metavar="FILENAME",
            help="Save output to the specified file, default is sandroid.json",
            default=f"{os.getenv('RESULTS_PATH')}sandroid.json",
        )
        parser.add_argument(
            "-ll",
            "--loglevel",
            type=str,
            metavar="LOGLEVEL",
            help="Set the log level. The logging file sandroid.log will always contain an expanded DEBUG level log.",
            default="INFO",
        )
        parser.add_argument(
            "-n",
            "--number_of_runs",
            type=int,
            metavar="NUMBER",
            help="Run action n times (Minimum and default is 2)",
            default=2,
        )
        parser.add_argument(
            "--avoid_strong_noise_filter",
            action="store_true",
            help='Don\'t use a "Dry Run". This will catch more noise and disable intra file noise detection.',
        )
        parser.add_argument(
            "--network",
            action="store_true",
            help="Capture traffic and show connections. Connections are not necessarily in chronological order. Each connection will only show up once, even if it was made multiple times. For better results, \033[4m it is recommended to use at least -n 3 \033[0m and to leave the strong noise filter on",
        )
        parser.add_argument(
            "-d",
            "--show_deleted",
            action="store_true",
            help="Perform additional full filesystem checks to reveal deleted files",
        )
        parser.add_argument(
            "--no-processes",
            action="store_false",
            dest="processes",
            help="Do not monitor active processes during the action",
        )
        parser.add_argument(
            "--sockets",
            action="store_true",
            dest="sockets",
            help="Monitor listening sockets during the action",
        )
        parser.add_argument(
            "--screenshot",
            type=int,
            metavar="INTERVAL",
            help="Take a screenshot each INTERVAL seconds",
            default=0,
        )
        parser.add_argument(
            "--trigdroid",
            type=str,
            metavar="PACKAGE NAME",
            help="Use the TrigDroid(tm) tool to execute malware triggers in package PACKAGE NAME",
        )
        parser.add_argument(
            "--trigdroid_ccf",
            type=str,
            metavar="{I,D}",
            help="Use the TrigDroid(tm) CCF utility to create a Trigdroid config file. I for interactive mode, D to create the default config file",
        )
        parser.add_argument(
            "--hash",
            action="store_true",
            help="Create before/after md5 hashes of all changed and new files and save them to hashes.json",
        )
        parser.add_argument(
            "--apk",
            action="store_true",
            help="List all APKs from the emulator and their hashes in the output file",
        )
        parser.add_argument(
            "--degrade_network",
            action="store_true",
            help="Lower the emulators network speed and network latency to simulate and 'UMTS/3G' connection. For more fine grained control, use the emulator console",
        )
        parser.add_argument(
            "--whitelist",
            type=str,
            metavar="FILE",
            help="Entries in the whitelist will be excluded from any outputs. Separate paths by commas, wildcards are supported",
        )
        parser.add_argument(
            "--iterative",
            action="store_true",
            help="Enable iterative analysis of new apk files",
        )
        parser.add_argument(
            "--report",
            action="store_true",
            default=True,
            help="Enable generation of a report file(pdf)",
        )
        parser.add_argument(
            "--ai",
            action="store_true",
            default=False,
            help="Use AI to summarize the action and generate a report",
        )

        cls.args = parser.parse_args()
        if cls.logger is None:
            cls.initialize_logger()
        if cls.frida_manager is None:
            cls.frida_manager = FridaManager(
                verbose=True, frida_install_dst="/data/local/tmp/"
            )

        cls.scan_directories = ["/data", "/storage", "/sdcard"]

    @classmethod
    def init_files(cls):
        """**Initializes** the necessary folders and files for the Sandroid program."""
        os.environ["RESULTS_PATH"] = (
            f"results/{datetime.datetime.now().strftime('%Y.%m.%d_%H:%M:%S')}/"
        )
        os.environ["RAW_RESULTS_PATH"] = f"{os.getenv('RESULTS_PATH')}raw/"

        folders_for_raw = [
            "first_pull",
            "second_pull",
            "noise_pull",
            "new_pull",
            "network_trace_pull",
            "screenshots",
            "spotlight_files",
        ]
        folders_for_result = ["spotlight_files"]
        base_folder_raw = os.getenv("RAW_RESULTS_PATH")
        base_folder = os.getenv("RESULTS_PATH")

        for folder in folders_for_raw:
            folder_path = os.path.join(base_folder_raw, folder)
            if os.path.isdir(folder_path):
                shutil.rmtree(folder_path)
            os.makedirs(folder_path)

        for folder in folders_for_result:
            folder_path = os.path.join(base_folder, folder)
            if os.path.isdir(folder_path):
                shutil.rmtree(folder_path)
            os.makedirs(folder_path)

        with open(f"{base_folder_raw}sandroid.log", "w"):
            pass

    @classmethod
    def check_setup(cls):
        """Ensures the setup is correct by checking adb, root access, and SELinux permissive mode."""
        stdout, stderr = Adb.send_adb_command("shell ls /data")
        if "not found" in stderr:
            cls.logger.critical("Could not find adb")
            exit(1)

        if "no devices/emulators found" in stderr:
            cls.logger.critical("There is no emulator running")
            cls.logger.info("Detecting available AVDs...")
            available_emulators = Emulator.list_available_avds()

            if available_emulators:
                # Build formatted emulator list
                emulator_list = ""
                for idx, emulator in enumerate(available_emulators, 1):
                    emulator_list += f"{Fore.CYAN}[{Fore.YELLOW}{idx}{Fore.CYAN}] {Fore.GREEN}{emulator}{Fore.RESET}\n"

                # Display emulators in a nice ASCII box
                formatted_box = cls._create_ascii_box(
                    emulator_list.strip(),
                    f"{Fore.MAGENTA}Available Emulators{Fore.RESET}",
                )
                print(f"\n{formatted_box}")

                # Ask user to select an emulator
                selected_idx = 0
                try:
                    while selected_idx < 1 or selected_idx > len(available_emulators):
                        try:
                            selected_idx = int(
                                input(
                                    f"\n{Fore.CYAN}Select an emulator to start ({Fore.YELLOW}1{Fore.CYAN}-{Fore.YELLOW}{len(available_emulators)}{Fore.CYAN}): {Style.RESET_ALL}"
                                )
                            )
                            if selected_idx < 1 or selected_idx > len(
                                available_emulators
                            ):
                                print(
                                    f"{Fore.RED}Please enter a number between {Fore.YELLOW}1{Fore.RED} and {Fore.YELLOW}{len(available_emulators)}{Style.RESET_ALL}"
                                )
                        except ValueError:
                            print(
                                f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}"
                            )
                except KeyboardInterrupt:
                    print(
                        f"\n{Fore.YELLOW}Emulator selection cancelled by user. Exiting...{Style.RESET_ALL}"
                    )
                    exit(0)

                # Store the selected emulator name
                selected_emulator = available_emulators[selected_idx - 1]
                # Update the device name with selected emulator
                cls.device_name = selected_emulator
                cls.logger.info(
                    f"Starting emulator {Fore.GREEN}{selected_emulator}{Style.RESET_ALL}..."
                )

                if Emulator.start_avd(selected_emulator):
                    cls.logger.info(
                        f"Emulator '{Fore.GREEN}{selected_emulator}{Style.RESET_ALL}' started successfully. Continuing setup..."
                    )
                    # Re-check connection after starting
                    stdout_check, stderr_check = Adb.send_adb_command("shell ls /data")
                    if "no devices/emulators found" in stderr_check:
                        cls.logger.critical(
                            "Emulator started but ADB connection failed. Please check manually."
                        )
                        exit(1)
                    # Proceed with the rest of the setup if connection is now okay
                else:
                    cls.logger.critical(
                        f"Failed to start emulator '{selected_emulator}'. Please start it manually and rerun."
                    )
            else:
                cls.logger.critical("No available emulators found.")
                exit(1)

        if "Permission denied" in stderr:
            cls.logger.warning(
                "Android Debug Bridge returned Permission denied, restarting adbd as root"
            )
            Adb.send_adb_command("root")
            time.sleep(2)

        # Ensure adb root is enabled
        stdout, stderr = Adb.send_adb_command("root")
        if "adbd cannot run as root" in stderr:
            cls.logger.critical(
                "Device does not support adb root. Please ensure the device is rooted."
            )
            exit(1)
        cls.logger.info("adb root enabled successfully.")

        # Ensure SELinux is set to permissive mode
        stdout, stderr = Adb.send_adb_command("shell setenforce 0")
        if stderr:
            cls.logger.warning(
                f"Failed to set SELinux to permissive mode: {stderr.strip()}"
            )
        else:
            cls.logger.info("SELinux set to permissive mode.")

        # Check for sqldiff binary
        cls.check_sqldiff_binary()

        # Check for objection binary
        cls.check_objection_binary()

    @classmethod
    def check_sqldiff_binary(cls):
        """Checks if the sqldiff binary is available in the system PATH.

        This binary is used for comparing SQLite databases. If it's missing,
        database comparison functionality will be limited.

        :returns: True if the sqldiff binary is available, False otherwise.
        :rtype: bool
        """
        sqldiff_available = shutil.which("sqldiff") is not None

        if not sqldiff_available:
            cls.logger.info(
                "The 'sqldiff' binary was not found in PATH. "
                "Database comparison functionality will be limited. "
                "Please install sqlite3 tools to enable full database diffing."
            )

        return sqldiff_available

    @classmethod
    def check_objection_binary(cls):
        """Checks if the objection command-line tool is available in the system PATH.

        This tool is used for interactive exploration of mobile applications via Frida.

        :returns: True if objection is available, False otherwise.
        :rtype: bool
        """
        objection_available = shutil.which("objection") is not None

        if not objection_available:
            cls.logger.warning(
                "The 'objection' tool was not found in PATH. "
                "Interactive application exploration will be limited. "
                "Please install objection using 'pip install objection'."
            )

        return objection_available

    @classmethod
    def initialize_logger(cls):
        if cls.logger is None:
            cls.logger = logging.getLogger()
            cls.logger.setLevel(cls.args.loglevel)

            # Check if the logger already has handlers
            if not cls.logger.handlers:
                file_formatter = logging.Formatter(
                    "%(asctime)s~%(levelname)s~%(message)s~module:%(module)s~function:%(funcName)s~args:%(args)s"
                )

                file_handler = logging.FileHandler(
                    f"{os.getenv('RAW_RESULTS_PATH')}sandroid.log"
                )
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(file_formatter)

                console_handler = logging.StreamHandler()
                console_handler.setLevel(cls.args.loglevel)
                console_handler.setFormatter(CustomFormatter())

                cls.logger.addHandler(file_handler)
                cls.logger.addHandler(console_handler)

    @classmethod
    def create_snapshot(cls, name):
        """Creates a snapshot of the AVD.

        :param name: The name of the snapshot.
        :type name: str
        """
        cls.logger.info(
            f"Creating snapshot: {Fore.GREEN}{name.decode('utf-8')}{Style.RESET_ALL}"
        )
        Adb.send_telnet_command(b"avd snapshot save " + name)

    @classmethod
    def load_snapshot(cls, name):
        """Loads a snapshot of the AVD.

        .. warning::
            Make sure the snapshot you are trying to load has been created first, this function has no error handling for that case.

        :param name: The name of the snapshot.
        :type name: str
        """
        cls.logger.info(
            f"Loading snapshot: {Fore.GREEN}{name.decode('utf-8')}{Style.RESET_ALL}"
        )
        Adb.send_telnet_command(b"avd snapshot load " + name)
        time.sleep(2)

    @classmethod
    def fetch_changed_files(cls, fetch_all=False):
        """Returns a dictionary of file paths and change times of all files that were changed between action_time and action_time + action_duration.

        The function uses a caching system to only list the file system after a new action, but this is not relevant for the caller.

        :param fetch_all: Whether to fetch all changed files or only those within the action time range.
        :type fetch_all: bool
        :returns: Dictionary of changed files and their change times while the action took place.
        :rtype: dict
        """
        if cls.already_looked_at_filesystem_for_this_action_time and not fetch_all:
            cls.logger.debug("Reading filesystem timestamps from cache")
            return cls.changed_files_cache
        return cls._fetch_changed_files(fetch_all)

    @classmethod
    def print_emulator_information(cls):
        """Prints information about the emulator, including network interfaces, snapshots, date, locale, Android version, and API level."""
        emulator_id = Adb.get_current_avd_name()
        emulator_path = Adb.get_current_avd_path()
        device_time = Adb.get_device_time()
        device_locale = Adb.get_device_locale()
        android_info = Adb.get_android_version_and_api_level()
        network_info = Adb.get_network_info()
        snapshots = Adb.get_avd_snapshots()

        # Build information string with colorful formatting
        info_text = f"{Fore.CYAN}Emulator ID:{Fore.RESET} {Fore.GREEN}{emulator_id}{Fore.RESET}\n"
        info_text += f"{Fore.CYAN}Emulator Path:{Fore.RESET} {Fore.GREEN}{emulator_path}{Fore.RESET}\n"
        info_text += f"{Fore.CYAN}Device Time:{Fore.RESET} {Fore.GREEN}{device_time}{Fore.RESET}\n"
        info_text += f"{Fore.CYAN}Device Locale:{Fore.RESET} {Fore.GREEN}{device_locale}{Fore.RESET}\n"
        info_text += f"{Fore.CYAN}Android Version & API Level:{Fore.RESET} {Fore.GREEN}{android_info.get('android_version', 'Unknown')} (API {android_info.get('api_level', 'Unknown')}){Fore.RESET}\n\n"

        # Add network interfaces section
        info_text += f"{Fore.YELLOW}Network Interfaces:{Fore.RESET}\n"
        for interface, ip in network_info:
            info_text += f"{Fore.CYAN}Interface:{Fore.RESET} {Fore.GREEN}{interface}{Fore.RESET} ({Fore.BLUE}{ip}{Fore.RESET})\n"

        # Add snapshots section if available
        if snapshots:
            info_text += f"\n{Fore.YELLOW}Available Snapshots:{Fore.RESET}\n"
            for snapshot in snapshots:
                # Switch order to put date first for better alignment
                info_text += f"{Fore.GREEN}{snapshot['date']}{Fore.RESET} - {Fore.CYAN}{snapshot['tag']}{Fore.RESET}\n"

        # Use the ASCII box format and print it
        formatted_output = cls._create_ascii_box(
            info_text.strip(), f"{Fore.MAGENTA}Emulator Information{Fore.RESET}"
        )
        click.echo(formatted_output)

    @classmethod
    def _fetch_changed_files(cls, fetch_all=False):
        """Fetches changed files from the AVD filesystem.

        .. warning::
            Not meant to be called directly, only through fetch_changed_files()

        :param fetch_all: Whether to fetch all changed files or only those within the action time range.
        :type fetch_all: bool
        :returns: Dictionary of changed files and their change times while the action took place.
        :rtype: dict
        """
        time_pattern = re.compile(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
        dir_pattern = re.compile(r"/.*:$")

        cls.logger.info("Reading filesystem timestamps")
        # Right now only /data is scanned, if you want to scan more, remove "data" from command to pull everything or replace "data" with the line below to scan everything except dev, proc and data_mirror
        # acct bin config etc linkerconfig mnt oem product storage system_ext adb_keys bugreports d debug_ramdisk init lost+found odm postinstall sdcard sys vendor apex cache data init.environ.rc metadata odm_dlkm second_stage_resources system vendor_dlkm
        # "data/user/0/" is always ignored, because it's a duplicate of "data/data"
        # filesystem, errors = Adb.send_adb_command("shell ls /data -ltRAp --full-time")
        filesystem, errors = Adb.send_adb_command(
            "shell ls {} -ltRAp --full-time".format(" ".join(cls.scan_directories))
        )
        if errors != "":
            cls.logger.error("Errors from the subprocess on the phone: " + errors)

        changedFiles = {}
        currentDir = ""
        newestchange = 0
        for line in filesystem.splitlines():
            match = time_pattern.search(line)

            if match is None:  # Line has no time (aka is not a file)
                match = dir_pattern.search(line)
                if match is not None:  # Line is the directory
                    currentDir = match.string[0:-1] + "/"
            else:  # Line has the correct timestamp
                if line[-1] == "/":  # entry is a directory
                    continue
                if " -> " in line:  # entry is a symlink
                    continue
                words = line.split(" ")
                words = list(filter(None, words))
                filename = words[8]
                timestamp = words[5] + " " + words[6] + " " + words[7]
                try:
                    parsed_ts = dp.parse(timestamp)
                except (ValueError, TypeError) as e:
                    cls.logger.debug(f"Could not parse timestamp '{timestamp}': {e}")
                    continue
                secondsTimestamp = int(round(parsed_ts.timestamp()))
                newestchange = max(newestchange, secondsTimestamp)
                if (
                    cls.action_time
                    <= secondsTimestamp
                    <= cls.action_time + cls.action_duration
                ) or fetch_all:
                    changedFiles.update({currentDir + filename: secondsTimestamp})
                    cls.add_to_shadow_ts_list(
                        currentDir, filename, secondsTimestamp, fetch_all=fetch_all
                    )
                    if filename.endswith(
                        ".db-wal"
                    ):  # Make sure db files that use write ahead logging are also added to list
                        changedFiles.update(
                            {currentDir + filename[0:-4]: secondsTimestamp}
                        )

        returnThis = {}
        for changedFile, changedTime in reversed(changedFiles.items()):
            if not changedFile.startswith("/data/user/0/"):
                returnThis.update({changedFile: changedTime})
        if not fetch_all:
            cls.changed_files_cache = returnThis
            cls.already_looked_at_filesystem_for_this_action_time = True
        return returnThis

    @classmethod
    def add_to_shadow_ts_list(
        cls, currentDir, filename, secondsTimestamp, color="#1A535C", fetch_all=False
    ):
        """Adds a file change entry to the shadow timestamp list. This list is meant for the timeline generation later on.

        :param currentDir: The current directory of the file.
        :type currentDir: str
        :param filename: The name of the file.
        :type filename: str
        :param secondsTimestamp: The change time of the file in seconds.
        :type secondsTimestamp: int
        :param color: Color for the entry in the timeline, set to #1A535C by default
        :param fetch_all: Whether this call was made during a fetch_all or normal run.
        :type fetch_all: bool
        """
        if fetch_all:
            return
        entry = {
            "id": currentDir + filename,
            "name": filename,
            "action_base_time": cls.action_time,
            "file_change_time": secondsTimestamp,
            "seconds_after_start": secondsTimestamp - cls.action_time,
            "timeline_color": color,
        }
        cls._timestamps_shadow_dict_list.append(entry)

    @classmethod
    def set_action_time(cls):
        """Sets the action time by fetching the current time from the emulator."""
        cls.already_looked_at_filesystem_for_this_action_time = False
        output, error = Adb.send_adb_command("shell date +%s")
        if error:
            cls.logger.critical("Could not grab time from emulator: " + error.strip())
            exit(1)
        cls.action_time = int(output)

    @classmethod
    def set_action_duration(cls, seconds):
        """Sets the action duration.

        :param seconds: The duration of the action in seconds.
        :type seconds: int
        """
        if cls.action_duration == 0:
            cls.action_duration = seconds

    @classmethod
    def get_action_time(cls):
        """Returns the action time. Relative to the emulator, so not necessarily the actual time during which the action took place.

        :returns: The action time.
        :rtype: int
        """
        return cls.action_time

    @classmethod
    def get_action_duration(cls):
        """Returns the action duration.

        :returns: The action duration.
        :rtype: int
        """
        return cls.action_duration

    @classmethod
    def started_dry_run(cls):
        """Marks the start of a dry run."""
        cls._is_dry_run = True

    @classmethod
    def is_dry_run(cls):
        """Checks if a dry run is in progress.

        :returns: True if a dry run is in progress, False otherwise.
        :rtype: bool
        """
        return cls._is_dry_run

    @classmethod
    def get_run_counter(cls):
        """Returns the run counter.

        :returns: The run counter.
        :rtype: int
        """
        return cls._run_counter

    @classmethod
    def increase_run_counter(cls):
        """Increases the run counter by one."""
        cls._run_counter += 1

    @classmethod
    def get_spotlight_application(cls):
        """Returns the spotlight application.

        If no application was previously set using set_spotlight_application, the currently running application will be returned.
        This does NOT implicitly set the spotlight application.

        :returns: A tuple containing the package name and activity name of the focused app..
        :rtype: tuple
        """
        if cls._spotlight_application == None:
            return None
        return cls._spotlight_application

    @classmethod
    def set_spotlight_application(cls, spotlight_application):
        """Sets the spotlight application.

        :param spotlight_application: The spotlight application. Obtain with Adb.get_focussed_app()
        """
        logging.info(f"Setting spotlight application to {spotlight_application}")
        cls._spotlight_application = spotlight_application

    @classmethod
    def get_spotlight_application_pid(cls):
        """Returns the PID of the spotlight application.

        :returns: The PID of the spotlight application.
        :rtype: int
        """
        return cls._spotlight_application_pid

    @classmethod
    def set_spotlight_application_pid(cls, spotlight_application_pid):
        """Sets the PID of the spotlight application.

        :param spotlight_application_pid: The PID of the spotlight application.
        :type spotlight_application_pid: int
        """
        cls._spotlight_application_pid = spotlight_application_pid

    @classmethod
    def reset_spotlight_application(cls):
        """Resets the spotlight application and its PID to None.
        Used when the spotlight application may have been closed or monitoring is ended.
        """
        cls._spotlight_application = None
        cls._spotlight_application_pid = None
        cls.logger.info("Spotlight application information has been reset.")

    @classmethod
    def get_spotlighted_app_data_path(cls):
        """Returns the /data/data/<spotlight_application> path if a spotlight app is set.
        Otherwise, returns None and logs a warning.
        """
        if not cls._spotlight_application:
            cls.logger.warning("No spotlight application is set.")
            return None

        return f"/data/data/{cls._spotlight_application[0]}"

    @classmethod
    def set_network_capture_path(cls, path):
        """Sets the network capture file path.

        :param path: The path to the network capture file.
        :type path: str
        """
        cls._network_capture_file = path

    @classmethod
    def get_spotlight_files(cls):
        """Returns the list of spotlight files.

        :returns: The list of spotlight file paths.
        :rtype: list
        """
        return cls._spotlight_files

    @classmethod
    def add_spotlight_file(cls, file_path):
        """Adds a file to the spotlight files list for monitoring.
        Supports wildcards (*) to add multiple files matching a pattern.

        :param file_path: Path to the file or pattern to add
        :type file_path: str
        :return: True if the file(s) were added, False otherwise
        :rtype: bool
        """
        if not file_path:
            cls.logger.warning("Cannot add empty file path to spotlight files")
            return False

        # Check if the path contains a wildcard
        if "*" in file_path:
            added_count = 0
            is_recursive = file_path.endswith("/*")

            # For recursive directory traversal, remove the trailing /*
            search_path = file_path[:-2] if is_recursive else file_path
            parent_dir = os.path.dirname(search_path)

            # Use find for recursive search, ls -A for simple pattern matching including hidden files
            if is_recursive:
                cmd = f"shell find {search_path} -type f"
            else:
                cmd = f"shell ls -1A {search_path}"

            stdout, stderr = Adb.send_adb_command(cmd)

            if stderr:
                cls.logger.error(f"Error listing files: {stderr}")
                return False

            # Process each matching file
            for matched_file in stdout.strip().split("\n"):
                if not matched_file or matched_file.isspace():
                    continue

                # Skip WAL and journal files
                if matched_file.endswith("-wal") or matched_file.endswith("-journal"):
                    cls.logger.debug(f"Skipping WAL or journal file: {matched_file}")
                    continue

                # For recursive search, check if file matches the pattern
                if is_recursive:
                    # Skip directories, only add files
                    if matched_file.endswith("/"):
                        continue
                    # Only add files if recursive
                    cls._add_single_spotlight_file(matched_file.strip())
                    added_count += 1
                else:
                    # For pattern search, add all matches
                    cls._add_single_spotlight_file(matched_file.strip())
                    added_count += 1

            cls.logger.info(
                f"Added {added_count} files matching pattern '{file_path}' to spotlight files"
            )
            return added_count > 0
        # Original single file handling
        return cls._add_single_spotlight_file(file_path)

    @classmethod
    def _add_single_spotlight_file(cls, file_path):
        """Helper method to add a single file to spotlight files.

        :param file_path: Path to the file to add
        :type file_path: str
        :return: True if the file was added, False otherwise
        :rtype: bool
        """
        # Don't add WAL and journal files directly
        if file_path.endswith("-wal") or file_path.endswith("-journal"):
            return False

        # Check if the file is already in the list
        if file_path in cls._spotlight_files:
            cls.logger.info(f"File '{file_path}' is already in spotlight files")
            return False

        # Add file to the list
        cls._spotlight_files.append(file_path)
        cls.logger.info(f"Added '{file_path}' to spotlight files")
        return True

    @classmethod
    def remove_spotlight_file(cls, file_path=None):
        """Removes a file from the spotlight files list. If only one file exists, it removes that file.

        :param file_path: The path to the spotlight file to remove. If None, removes the only file if one exists.
        :type file_path: str
        """
        if len(cls._spotlight_files) == 1 and file_path is None:
            removed_file = cls._spotlight_files.pop()
            cls.logger.info(f"Removed the only spotlight file: {removed_file}")
        elif file_path and file_path in cls._spotlight_files:
            cls._spotlight_files.remove(file_path)
            cls.logger.info(f"Removed spotlight file: {file_path}")
        else:
            cls.logger.warning(
                "File not found in spotlight files or no file specified."
            )

    @classmethod
    # pulls file_to_pull from emulator and puts it in the folder Data/[number]_pull
    def pull_file(cls, number, file_to_pull):
        """Pulls a file from the emulator and saves it to the specified directory,
        preserving the complete directory structure.

        :param number: The pull id, used as the folder name. Usually "first", "second", "noise", "network"...
        :type number: str
        :param file_to_pull: The file to pull from the emulator.
        :type file_to_pull: str
        """
        # Create the target directory structure if it doesn't exist
        target_dir = os.path.join(
            f"{os.getenv('RAW_RESULTS_PATH')}{number}_pull",
            os.path.dirname(file_to_pull.lstrip("/")),
        )
        os.makedirs(target_dir, exist_ok=True)

        # Pull the file while preserving its path
        output, error = Adb.send_adb_command(
            "pull "
            + file_to_pull
            + " "
            + os.path.join(
                f"{os.getenv('RAW_RESULTS_PATH')}{number}_pull",
                file_to_pull.lstrip("/"),
            )
        )

        if "failed to stat remote object" in str(
            output
        ) or "failed to stat remote object" in str(error):
            cls.logger.warning(
                "File likely deleted before it could be pulled: " + file_to_pull
            )
        if "Permission denied" in str(output) or "Permission denied" in str(error):
            cls.logger.error(
                "Permissions Error: Could not pull "
                + file_to_pull
                + " from device. This is not technically critical but will lead to incomplete results."
            )

    @classmethod
    def pull_spotlight_files(cls, description=None):
        """Pulls all spotlight files from the device to the 'spotlight_files' directory.
        Creates a timestamped subdirectory for each pull operation.

        If multiple spotlight files are set, recreates their directory hierarchy.
        For .db files, also pulls the associated WAL and journal files.

        :param description: A short description of the action performed before the pull.
        :type description: str or None
        """
        if not cls._spotlight_files:
            cls.logger.warning("No spotlight files are set.")
            return False

        # Create or empty the spotlight_files directory
        spotlight_dir = os.getenv("RESULTS_PATH") + "spotlight_files"
        if not os.path.exists(spotlight_dir):
            os.makedirs(spotlight_dir)

        # Create a timestamped subdirectory with optional description
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        if description:
            pull_dir = os.path.join(
                spotlight_dir, f"{timestamp}_{description.replace(' ', '_')}"
            )
        else:
            pull_dir = os.path.join(spotlight_dir, timestamp)
        os.makedirs(pull_dir, exist_ok=True)

        cls.logger.info(f"Pulling spotlight files to {pull_dir}")

        # Process each spotlight file
        for file_path in cls._spotlight_files:
            # Skip files that are already handled as part of .db files
            if file_path.endswith(("-wal", "-journal")):
                continue

            # Set up the target path
            if len(cls._spotlight_files) > 1:
                # Preserve hierarchy for multiple files
                target_dir = os.path.join(
                    pull_dir, os.path.dirname(file_path).lstrip("/")
                )
                os.makedirs(target_dir, exist_ok=True)
                target = os.path.join(pull_dir, file_path.lstrip("/"))
            else:
                # Single file goes flat in the directory
                target = os.path.join(pull_dir, os.path.basename(file_path))

            # Pull the file from the device
            output, error = Adb.send_adb_command(f"pull {file_path} {target}")

            if "failed to stat remote object" in str(
                output
            ) or "failed to stat remote object" in str(error):
                cls.logger.warning(f"File not found on device: {file_path}")
            elif "Permission denied" in str(output):
                cls.logger.error(f"Permission denied when pulling {file_path}")
            else:
                cls.logger.info(f"Pulled {file_path} to {target}")

            # For .db files, also pull WAL and journal files if they exist
            if file_path.endswith(".db"):
                wal_file = file_path + "-wal"
                journal_file = file_path + "-journal"

                # Pull the WAL file
                wal_target = target + "-wal"
                output, error = Adb.send_adb_command(f"pull {wal_file} {wal_target}")
                if (
                    "failed to stat remote object" not in str(output)
                    and "Permission denied" not in str(output)
                    and "failed to stat remote object" not in str(error)
                    and "Permission denied" not in str(error)
                ):
                    cls.logger.info(f"Pulled WAL file: {wal_file}")

                # Pull the journal file
                journal_target = target + "-journal"
                output, error = Adb.send_adb_command(
                    f"pull {journal_file} {journal_target}"
                )
                if (
                    "failed to stat remote object" not in str(output)
                    and "Permission denied" not in str(output)
                    and "failed to stat remote object" not in str(error)
                    and "Permission denied" not in str(error)
                ):
                    cls.logger.info(f"Pulled journal file: {journal_file}")

        cls.logger.info(f"All spotlight files pulled to {pull_dir}")
        return True

    @classmethod
    def highlight_timestamps(cls, s, restColor):
        """Highlights timestamps in the given string.

        :param s: The input string.
        :type s: str
        :param restColor: The color the string should return to after the highlight.
        :type restColor: str
        :returns: The string with highlighted timestamps.
        :rtype: str
        """
        highlight_list = []
        for i in range(
            cls.action_time - 100, cls.action_time + cls.action_duration + 100
        ):
            highlight_list.append(str(i))
        highlight_str = r"\b(?:" + "|".join(highlight_list) + r")"
        text_highlight = re.sub(highlight_str, r"\033[93m\g<0>\033[m" + restColor, s)
        return text_highlight

    @classmethod
    def truncate(cls, input_string, line_length_cutoff=150, line_number_cutoff=50):
        """Truncates the input string to a specific length.

        :param input_string: The input string.
        :type input_string: str
        :returns: The truncated string.
        :rtype: str
        """
        output = ""
        cutoff = 150
        line_number_cutoff = 50
        for line in input_string.splitlines()[0:line_number_cutoff]:
            output = output + line[0:cutoff]
            if len(line) > cutoff + 1:
                output = output + "[...]"
            output = output + "\n"
        output = output[:-1]  # remove one newline from end

        if input_string.count("\n") > line_number_cutoff:
            number_of_cut_lines = input_string.count("\n") - line_number_cutoff
            output = (
                output
                + "\n\t["
                + str(number_of_cut_lines)
                + " lines have been cut here for brevity]"
            )

        return output

    # TODO: seperate emulator stuff like snapshots from toolbox
    @classmethod
    def restart_emulator(cls):
        """Restarts the Android emulator."""
        cls.logger.info("Trying to shut down Emulator")
        stdout, stderr = Adb.send_telnet_command(b"kill")
        if stderr:
            cls.logger.warning(
                "Emulator " + cls.device_name + " was not running, starting now"
            )
            subprocess.Popen(
                [
                    f"{cls.android_emulator_path} @ {cls.device_name} -feature -Vulkan -gpu host"
                ],
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(5)
        cls.logger.info("Starting Emulator")
        subprocess.Popen(
            [
                f"{cls.android_emulator_path} @ {cls.device_name} -feature -Vulkan -gpu host"
            ],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(5)

    @classmethod
    def get_proxy_settings(cls):
        """Gets the current HTTP proxy settings from the device.

        :returns: The current HTTP proxy settings as a string or "Not set" if no proxy is configured.
        :rtype: str
        """
        stdout, stderr = Adb.send_adb_command("shell settings get global http_proxy")

        if stdout and stdout.strip() and stdout.strip() not in ["", ":0", "null"]:
            return stdout.strip()
        return "Not set"

    @classmethod
    def set_unset_proxy(cls):
        """Toggles the network proxy on the emulator.
        If a proxy is currently set, it will be removed.
        If no proxy is set, the user will be prompted to configure one.
        """
        current_proxy = cls.get_proxy_settings()
        if current_proxy != "Not set":
            cls.logger.info(f"Current proxy is set to: {current_proxy}")
            stdout, stderr = Adb.send_adb_command(
                "shell settings put global http_proxy :0"
            )
            if not stderr:
                cls.logger.info("Proxy unset successfully.")
            else:
                cls.logger.error(f"Failed to unset proxy: {stderr}")
            return

        # Get the host IP address
        host_ip = cls.get_host_ip()
        cls.logger.info(f"Enter proxy IP (default: {host_ip})")
        proxy_ip = input().strip() or host_ip
        cls.logger.info("Enter proxy port (default: 8080)")
        proxy_port = input().strip() or "8080"

        stdout, stderr = Adb.send_adb_command(
            f"shell settings put global http_proxy {proxy_ip}:{proxy_port}"
        )
        if not stderr:
            cls.logger.info(f"Proxy set to {proxy_ip}:{proxy_port}")
        else:
            cls.logger.error(f"Failed to set proxy: {stderr}")

    @classmethod
    def get_host_ip(cls):
        """Gets the host's IP address.
        Uses a more robust method that works on macOS, Linux, and Windows.

        :returns: The host's IP address or "127.0.0.1" if no suitable IP is found.
        :rtype: str
        """
        import socket

        # First attempt - Create a socket connection to an external server
        # This doesn't actually establish a connection but helps determine which interface would be used
        try:
            # Use Google's DNS server as a reference point
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            host_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return host_ip
        except (OSError, IndexError):
            cls.logger.debug("Failed to get IP by connecting to external server")

        # Second attempt - Try using hostname
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
            # Check if we got a loopback address
            if not host_ip.startswith("127."):
                return host_ip
        except socket.gaierror:
            cls.logger.debug("Failed to get IP from hostname")

        # Third attempt - Try getting all addresses and find a suitable one
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if not ip.startswith("127."):
                    return ip
        except socket.gaierror:
            cls.logger.debug("Failed to get IP from hostname extended lookup")

        # Fallback to localhost if all else fails
        cls.logger.warning("Could not determine host IP, using localhost (127.0.0.1)")
        return "127.0.0.1"

    @classmethod
    def take_screenshot(cls, filename=None):
        """Takes a screenshot of the Android device using telnet commands.

        :param filename: Optional custom filename, otherwise a timestamped name is used
        :type filename: str
        :returns: Path to the saved screenshot file
        :rtype: str
        """
        # Create screenshots directory if it doesn't exist
        screenshots_dir = "screenshots"
        if not os.path.exists(screenshots_dir):
            os.makedirs(screenshots_dir)

        # Generate a timestamped filename if none is provided
        if filename is None:
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"{screenshots_dir}/screenshot_{timestamp}.png"
        else:
            filename = f"{screenshots_dir}/{filename}"

        # Take the screenshot using the telnet command
        cls.logger.info(f"Taking screenshot: {Fore.GREEN}{filename}{Style.RESET_ALL}")

        # Use the specified telnet command
        stdout, stderr = Adb.send_telnet_command(f"screenrecord screenshot {filename}")

        if stderr:
            cls.logger.error(f"Failed to capture screenshot: {stderr}")
            return None

        cls.logger.info(f"Screenshot saved to {Fore.GREEN}{filename}{Style.RESET_ALL}")
        return filename

    @classmethod
    def start_screen_recording(cls, filename=None):
        """Starts screen recording using the Android emulator's screenrecord command.

        :param filename: Optional custom filename, otherwise a timestamped name is used
        :type filename: str
        :returns: True if recording started successfully, False otherwise
        :rtype: bool
        """
        if cls._screen_recording_running:
            cls.logger.warning("Screen recording is already running")
            return False

        # Create screenrecords directory if it doesn't exist
        recording_dir = "screenrecords"
        if not os.path.exists(recording_dir):
            os.makedirs(recording_dir)

        # Generate a timestamped filename if none is provided
        if filename is None:
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"screenrecord_{timestamp}.webm"
        # Ensure filename has .webm extension
        elif not filename.endswith(".webm"):
            filename += ".webm"

        # Set the full path
        cls._screen_recording_file = os.path.join(recording_dir, filename)

        # Start recording using telnet command
        stdout, stderr = Adb.send_telnet_command(
            f"screenrecord start {cls._screen_recording_file}"
        )

        if stderr:
            cls.logger.error(f"Failed to start screen recording: {stderr}")
            cls._screen_recording_file = None
            return False

        cls._screen_recording_running = True
        cls.logger.info(
            f"Started screen recording to {Fore.GREEN}{cls._screen_recording_file}{Style.RESET_ALL}"
        )
        return True

    @classmethod
    def stop_screen_recording(cls):
        """Stops the current screen recording.

        :returns: True if recording stopped successfully, False otherwise
        :rtype: bool
        """
        if not cls._screen_recording_running:
            cls.logger.warning("No screen recording is currently running")
            return False

        # Stop recording using telnet command
        stdout, stderr = Adb.send_telnet_command("screenrecord stop")

        if stderr:
            cls.logger.error(f"Failed to stop screen recording: {stderr}")
            return False

        cls.logger.info(
            f"Screen recording saved to {Fore.GREEN}{cls._screen_recording_file}{Style.RESET_ALL}"
        )
        cls._screen_recording_running = False
        return True

    @classmethod
    def print_interactive_menu(cls):
        """Prints the interactive main menu."""
        is_frida_running = cls.frida_manager.is_frida_server_running()
        if is_frida_running:
            frida_server_string = f"{Fore.GREEN}Running{Fore.RESET}"
        else:
            frida_server_string = f"{Fore.RED}Not running{Fore.RESET}"
        frida_server_string = f"Frida Server: [{frida_server_string}]"

        # Get and format the proxy settings
        proxy_settings = cls.get_proxy_settings()
        if proxy_settings == "Not set":
            proxy_string = f"{Fore.RED}Not set{Fore.RESET}"
        else:
            proxy_string = f"{Fore.GREEN}{proxy_settings}{Fore.RESET}"
        proxy_string = f"HTTP Proxy: [{proxy_string}]"

        spotlight_application = cls._spotlight_application
        if spotlight_application:
            spotlight_application_string = f"{Fore.YELLOW}{spotlight_application[0]}, PID: {cls._spotlight_application_pid}{Fore.RESET}"
        else:
            spotlight_application_string = f"{Fore.RED}Not set{Fore.RESET}"
        spotlight_application_string = (
            f"Spotlight Application: [{spotlight_application_string}]"
        )

        # Filter spotlight files to exclude internal WAL and journal files
        spotlight_files = [
            file
            for file in cls._spotlight_files
            if not (file.endswith("-wal") or file.endswith("-journal"))
        ]

        if not spotlight_files:
            spotlight_files_string = f"{Fore.RED}Not set{Fore.RESET}"
        elif len(spotlight_files) == 1:
            spotlight_files_string = f"{Fore.YELLOW}{spotlight_files[0]}{Fore.RESET}"
        else:
            # Only show the count for multiple files
            spotlight_files_string = (
                f"{Fore.YELLOW}{len(spotlight_files)} files set{Fore.RESET}"
            )

        spotlight_files_string = f"Spotlight Files: [{spotlight_files_string}]"

        if cls.malware_monitor_running == False:
            malware_monitor_string = f"* start android {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}m{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}alware monitor (dexray-intercept) on spotlight app"
        else:
            malware_monitor_string = f"* stop android {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}m{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}alware monitor (dexray-intercept) on {spotlight_application}"

        # Network capture menu text changes based on capture status
        if cls._network_capture_running:
            network_capture_string = f"* stop {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}w{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}riting network capture file ({Fore.YELLOW}{os.path.basename(cls._network_capture_file)}{Fore.RESET})"
        else:
            network_capture_string = f"* {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}w{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}rite network capture file"

        # Screen recording menu text changes based on recording status
        if cls._screen_recording_running:
            screen_recording_string = f"* stop {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}g{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}rabbing video of screen ({Fore.YELLOW}{os.path.basename(cls._screen_recording_file)}{Fore.RESET})"
        else:
            screen_recording_string = f"* {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}g{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}rab video of screen"

        click.echo(
            cls._create_ascii_box(
                f"""{frida_server_string}
{proxy_string}
{spotlight_application_string}
{spotlight_files_string}

    {Fore.CYAN}=== Action Recording & Playback ==={Fore.RESET}
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}r{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ecord an action
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}p{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}lay the currently loaded action
    * e{Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}x{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}port currently loaded action
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}i{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}mport action

    {Fore.CYAN}=== Spotlight Application ==={Fore.RESET}
    * set {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}c{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}urrent app in focus as spotlight app
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}a{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}nalyze spotlight app with dexray-insight
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}d{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ump memory of spotlight app (using fridump)
    {malware_monitor_string}
    * start o{Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}b{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}jection interactive shell for spotlight app
    * run {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}t{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}rigdroid malware triggers

    {Fore.CYAN}=== Spotlight Files ==={Fore.RESET}
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}l{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ist/add spotlight file
    * remo{Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}v{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}e spotlight file
    * p{Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}u{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ll spotlight files
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}o{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}bserve file system changes (fsmon)

    {Fore.CYAN}=== Emulator Management ==={Fore.RESET}
    * show {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}e{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}mulator information
    * keys {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}1-8{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} create snapshots, key {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}0{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} lists/loads snapshots
    * take {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}s{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}creenshot of device
    {screen_recording_string}
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}n{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ew APK installation
    * run/install {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}f{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}rida server

    {Fore.CYAN}=== Network Management ==={Fore.RESET}
    * set/unset network prox{Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}y{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}
    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}h{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}ook encryption routines with friTap
    {network_capture_string}


    * {Fore.LIGHTMAGENTA_EX}[{Style.BRIGHT}q{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Fore.RESET}uit""",
                "Sandroid Interactive Menu",
            )
        )

    @classmethod
    def _create_ascii_box(cls, text: str, title: str) -> str:
        """Creates an ASCII box with a title.

        :param text: The text to be enclosed in the ASCII box.
        :type text: str
        :param title: The title of the ASCII box.
        :type title: str
        :returns: The formatted ASCII box.
        :rtype: str
        """
        lines = text.splitlines()

        # Strip ANSI color codes for length calculation with a more comprehensive regex
        def strip_ansi(line):
            # This improved regex pattern catches more ANSI escape codes
            return re.sub(
                r"\x1b(?:\[[0-9;]*[a-zA-Z]|\][0-9;]*[a-zA-Z]|[()][A-Z]|[@-Z])", "", line
            )

        # Calculate the actual visible width of each line
        visible_lengths = [len(strip_ansi(line)) for line in lines]
        max_length = max(visible_lengths) + 4

        # Create the top border with the title in the center
        stripped_title = strip_ansi(title)
        title_padding = (max_length - len(stripped_title)) // 2
        top_border = f"┌{'─' * max_length}┐\n│{' ' * title_padding}{title}{' ' * (max_length - len(stripped_title) - title_padding)}│\n├{'─' * max_length}┤\n"

        # Create the middle section with correct padding
        middle_text = ""
        for i, line in enumerate(lines):
            visible_length = len(strip_ansi(line))
            padding = max_length - visible_length
            middle_text += f"│{line}{' ' * padding}│"
            if i < len(lines) - 1:
                middle_text += "\n"

        # Create the bottom border
        bottom_border = f"\n└{'─' * max_length}┘"

        return f"{top_border}{middle_text}{bottom_border}"

    @classmethod
    def wrap_up(
        cls,
    ):  # Closing routing to handle anything that needs to be done right before the program finishes
        """Closing routine to handle tasks that need to be done right before the program finishes.

        Runs before the final results are written to the output file.
        """
        if cls.args.hash:
            cls.calculate_hashes()
        if cls.args.apk:
            cls.pull_and_hash_apks()
        cls.submit_other_data("Timeline Data", cls._timestamps_shadow_dict_list)

    @classmethod
    def calculate_hashes(cls):
        """Calculates MD5 hashes for new and changed files."""
        cls.logger.info("Calculating Hashes")

        base_folder = os.getenv("RAW_RESULTS_PATH")
        hashes = {}
        new_file_hashes = {}  # path : hash
        change_file_hashes = {}  # path : [old_hash, new_hash]
        # hashes['Disclaimer'] = "If either the old or new version are not available, that hash will show as 'n/a', if a changed file could never be pulled, it will not have an entry at all. This is a list of hashes of all files that were pulled, so it can also contain extra entries that got removed as noise. For the complete list of all non-noise changed files, check the output file (default sandroid.json)"

        for file in os.listdir(f"{base_folder}new_pull"):
            if file in os.listdir(f"{base_folder}noise_pull"):
                continue
            f = open(f"{base_folder}new_pull/" + file, mode="rb")
            data = f.read()
            f.close()

            cls.logger.debug("Hashing " + file)
            new_file_hashes[file] = hashlib.md5(data).hexdigest()
        for file in os.listdir(f"{base_folder}first_pull"):
            if file in os.listdir(f"{base_folder}noise_pull"):
                continue
            f = open(f"{base_folder}first_pull/" + file, mode="rb")
            data = f.read()
            f.close()

            cls.logger.debug("Hashing old version of " + file)
            change_file_hashes[file] = [hashlib.md5(data).hexdigest(), "n/a"]
        for file in os.listdir(f"{base_folder}second_pull"):
            if file in os.listdir(f"{base_folder}noise_pull"):
                continue
            f = open(f"{base_folder}second_pull/" + file, mode="rb")
            data = f.read()
            f.close()

            cls.logger.debug("Hashing new version of " + file)
            if file in change_file_hashes:
                change_file_hashes[file][1] = hashlib.md5(data).hexdigest()
            else:
                change_file_hashes[file] = ["n/a", hashlib.md5(data).hexdigest()]

        hashes["new_file_hashes"] = new_file_hashes
        hashes["changed_file_hashes(old,new)"] = change_file_hashes

        # f = open('hashes.json', mode='w')
        # f.write(json.dumps(hashes, indent = 4))
        cls.submit_other_data("Artifact Hashes", hashes)

    @classmethod
    def pull_and_hash_apks(cls):
        """Pulls APKs from the emulator, calculates their hashes and submits them into the output file.

        Pulled files are deleted again after their hash has been calculated.
        """
        cls.logger.info("Pulling and hashing APKs")

        base_folder = os.getenv("RAW_RESULTS_PATH")
        list_of_all_packages = []
        names_and_hashes = []
        stdout, stderr = Adb.send_adb_command("shell pm list packages")
        for package in stdout.split("\n"):
            if not package == "":
                list_of_all_packages.append(package[8:])

        # For each package: pull it, get its hash, delete it.
        for package in list_of_all_packages:
            package_path, stderr = Adb.send_adb_command("shell pm path " + package)
            package_path = package_path[8:-1]
            Adb.send_adb_command(f"pull {package_path} {base_folder}{package}.apk")

            if os.path.exists(f"{base_folder}{package}.apk"):
                f = open(f"{base_folder}{package}.apk", mode="rb")
                data = f.read()
                f.close()
                cls.logger.debug("Hashing apk " + package)
                names_and_hashes.append(
                    package + ": " + str(hashlib.md5(data).hexdigest())
                )

                os.remove(f"{base_folder}{package}.apk")
            else:
                cls.logger.error(
                    "Something went wrong looking for a package: " + package
                )
                names_and_hashes.append(package + ": n/a")
        cls.submit_other_data("APK Hashes", names_and_hashes)
        """
        with open(cls.args.file,'r+') as file:
            file_data = json.load(file)
            file_data["APK Hashes"] = names_and_hashes
            file.seek(0)
            json.dump(file_data, file, indent = 4)
        """

    @classmethod
    def exclude_whitelist(cls, file_paths):
        """Excludes file paths that match patterns in the whitelist.

        :param file_paths: List of file paths to be filtered.
        :type file_paths: list
        :returns: Filtered list of file paths.
        :rtype: list
        """
        if cls.args.whitelist:
            before_len = len(file_paths)
            if cls.file_paths_whitelist is None:
                with open(cls.args.whitelist) as f:
                    cls.file_paths_whitelist = "".join(f.read()).split(",")
            file_paths = [
                fp
                for fp in file_paths
                if not any(
                    fnmatch.fnmatch(fp, pattern) for pattern in cls.file_paths_whitelist
                )
            ]
            cls.logger.info("My list is: " + str(cls.file_paths_whitelist))
            after_len = len(file_paths)
            cls.logger.debug(
                "Filtered out "
                + str(before_len - after_len)
                + " paths because of whitelist"
            )
        return file_paths

    @classmethod
    def submit_other_data(cls, identifier, data):
        """Submits additional data to the 'other' section of the output file.

        Multiple datasets can be added under the same name, they will be appended to the same field in the result file.

        :param identifier: The type of data being submitted.
        :type identifier: str
        :param data: The data to be submitted.
        :type data: any
        """
        cls.logger.debug(f'Submitting Data of type {identifier} into "other" section')
        if identifier not in cls.other_output_data_collector:
            # If the identifier is not in the dictionary, add it with the data
            cls.other_output_data_collector[identifier] = [data]
        else:
            # If the identifier is already in the dictionary, append the data to its entry
            cls.other_output_data_collector[identifier].append(data)

    @classmethod
    def get_frida_job_manager(cls):
        """Returns the Frida job manager instance.

        :returns: The Frida job manager instance.
        :rtype: JobManager
        """
        if cls._frida_job_manager == None:
            cls._frida_job_manager = JobManager()

        return cls._frida_job_manager

    @classmethod
    def export_action(cls, snapshot_name="tmp"):
        cls.logger.debug(f'exporting snapshot "{snapshot_name}"')
        snapshot_path = f"{os.path.expanduser('~')}/.android/avd/{cls.device_name}.avd/snapshots/tmp"

        if not os.path.exists(f"{os.getenv('RAW_RESULTS_PATH')}recording.txt"):
            cls.logger.error("No recording currently loaded")
            return
        if not os.path.exists(snapshot_path):
            cls.logger.error(
                "No snapshot exists, a snapshot has to be part of the export"
            )
            return

        action_name = input("Name your action for export: ")

        if os.path.exists(f"{action_name}.action"):
            cls.logger.error(
                "An action with this name already exist, choose a different name"
            )
            return

        shutil.copytree(snapshot_path, action_name)
        shutil.copy(f"{os.getenv('RAW_RESULTS_PATH')}recording.txt", action_name)
        shutil.make_archive(action_name, "zip", action_name)
        os.rename(f"{action_name}.zip", f"{action_name}.action")
        shutil.rmtree(action_name)

        cls.logger.info("Action sucessfully exported.")

    @classmethod
    def toggle_screen_record(cls):
        """Starts screen recording on the emulator if not already running, or stops it if it is running."""
        if not cls._screen_recording_running:
            cls.logger.info("Starting screen recording")
            recorder = threading.Thread(target=cls._screenrecorder_thread, daemon=True)
            recorder.start()
        else:
            cls.logger.info("Stopping screen recording")
            cls._screen_recording_running = False
            time.sleep(1)
            cls.logger.debug("Pulling screen recording file from device")
            Adb.send_adb_command(
                f"pull sdcard/screenrecord.webm {os.getenv('RAW_RESULTS_PATH')}recording.webm"
            )

    @classmethod
    def _screenrecorder_thread(cls):
        """Thread function to handle screen recording.
        This starts the ADB screenrecord command and manages it until stopped.
        """
        cls._screen_recording_running = True

        try:
            device_path = "sdcard/screenrecord.webm"

            # Start the ADB screenrecord command as a subprocess
            cls._screen_recording_process = subprocess.Popen(
                ["adb", "shell", "screenrecord", device_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            cls.logger.debug(f"Started screen recording to device: {device_path}")

            # Wait for the recording to be stopped
            total_wait_time = 0
            while (
                cls._screen_recording_running
                and cls._screen_recording_process.poll() is None
            ):
                time.sleep(0.5)
                total_wait_time += 0.5
                if total_wait_time > 178:
                    cls.logger.warning(
                        "Maximum screen recording duration reached, stopping recording"
                    )
                    cls._screen_recording_running = False

            # Stop the recording if it's still running
            if cls._screen_recording_process.poll() is None:
                import signal

                try:
                    # Send SIGINT (Ctrl+C equivalent) to stop recording gracefully
                    cls._screen_recording_process.send_signal(signal.SIGINT)
                    cls._screen_recording_process.wait(timeout=5)
                    cls.logger.info("Screen recording stopped gracefully")
                except subprocess.TimeoutExpired:
                    # Force terminate if graceful stop fails
                    cls.logger.warning("Graceful stop failed, force terminating")
                    cls._screen_recording_process.terminate()
                    cls._screen_recording_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # Last resort - kill the process
                    cls.logger.warning("Terminate failed, killing process")
                    cls._screen_recording_process.kill()
                    cls._screen_recording_process.wait()

        except Exception as e:
            cls.logger.error(f"Error in screen recording thread: {e}")
        finally:
            cls._screen_recording_running = False
            cls._screen_recording_process = None
