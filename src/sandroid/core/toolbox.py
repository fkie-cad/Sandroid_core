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
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from wcwidth import wcswidth

# Platform-specific imports for stdin flushing
try:
    import fcntl
    import termios

    TERMIOS_AVAILABLE = True
except ImportError:
    TERMIOS_AVAILABLE = False

try:
    import msvcrt

    MSVCRT_AVAILABLE = True
except ImportError:
    MSVCRT_AVAILABLE = False

# Third-party imports
import click
import dateutil.parser as dp

# Local imports
from AndroidFridaManager import FridaManager, JobManager

# Updated to use migrated modules within same package
from .adb import Adb
from .console import SandroidConsole
from .CustomLoggerFormatter import CustomFormatter
from .emulator import Emulator
from .file_diff import is_sqlite_file


@dataclass
class BackgroundTask:
    """Represents a running background task."""

    name: str  # e.g., "fritap", "dexray-intercept", "network"
    display_name: str  # e.g., "FriTap", "Dexray-Intercept"
    instance: object  # The actual tool instance
    stop_callback: Callable  # Function to call when stopping
    started_at: datetime.datetime  # When the task started
    started_by: str | None = None  # Which task started this one (for dependencies)
    app_name: str | None = None  # Target application package name (if applicable)
    target_pid: int | None = None  # Target process PID (if applicable)


class Toolbox:
    """A static class providing various utility functions for forensic, malware and securty analysis on an Android Virtual Device (AVD)."""

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

    # Spawn mode variables
    _spawn_mode = False
    _spotlight_spawn_application = None
    _auto_resume_after_spawn = True  # Auto-resume by default

    # View mode variables
    _current_view = "forensic"  # Default view: forensic, malware, or security
    _view_cycle = ["forensic", "malware", "security"]  # Cycle order

    # Tool usage tracking for exit summary
    _tools_used: dict = {}  # {"tool_name": {"used": True, "files": [...]}}

    # Background task management
    _background_tasks: dict[str, BackgroundTask] = {}

    # Background task output buffering for menu display
    _background_output_buffer: list[
        tuple[str, str, str]
    ] = []  # [(timestamp, task_name, message)]
    _background_output_max_lines: int = 50

    # replace these with your own values
    # TODO: Shouldn't be hardcoded
    device_name = "Pixel_6_Pro_API_31"
    android_emulator_path = "~/Android/Sdk/emulator/emulator"

    def __new__(cls):
        raise TypeError("This is a static class and cannot be instantiated.")

    @classmethod
    def safe_input(cls, prompt: str = "") -> str:
        """Safely read input from stdin with buffer flushing to prevent input swallowing issues.

        This method addresses buffering problems that occur when multiple interactive programs
        (e.g., Claude Code, then sandroid) run in the same terminal session. It flushes any
        pending stdin input before reading, which prevents leftover buffered data from being
        consumed or terminal state issues from causing input to be lost.

        Args:
            prompt: Optional prompt string to display before reading input

        Returns:
            The user's input as a string (stripped of leading/trailing whitespace)

        Note:
            Works cross-platform (Linux, macOS, Windows) and handles non-TTY cases gracefully.
        """
        # Only attempt flushing if stdin is a TTY (interactive terminal)
        if sys.stdin.isatty():
            try:
                # Unix-like systems (Linux, macOS)
                if TERMIOS_AVAILABLE:
                    # Flush the input buffer
                    termios.tcflush(sys.stdin, termios.TCIFLUSH)

                # Windows systems
                elif MSVCRT_AVAILABLE:
                    # Flush Windows console input buffer
                    while msvcrt.kbhit():
                        msvcrt.getch()

            except Exception as e:
                # Log but don't fail - just proceed with regular input
                if cls.logger:
                    cls.logger.debug(f"Could not flush stdin buffer: {e}")

        # Display prompt if provided
        if prompt:
            print(prompt, end="", flush=True)

        # Read input normally
        try:
            return input().strip()
        except EOFError:
            # Handle EOF gracefully (e.g., when input is redirected)
            return ""

    @classmethod
    def buffer_background_output(cls, task_name: str, message: str) -> None:
        """Buffer output from a background task for display in menu.

        Args:
            task_name: Name of the background task producing the output
            message: The message/output to buffer
        """
        import datetime

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        cls._background_output_buffer.append((timestamp, task_name, message))
        # Keep only the most recent lines
        if len(cls._background_output_buffer) > cls._background_output_max_lines:
            cls._background_output_buffer = cls._background_output_buffer[
                -cls._background_output_max_lines :
            ]

        # Emit event for task output
        try:
            from sandroid.core.events import Event, EventBus, EventType

            EventBus.get().publish(
                Event(
                    type=EventType.TASK_OUTPUT,
                    data={
                        "task_name": task_name,
                        "message": message,
                        "timestamp": timestamp,
                    },
                    source=task_name,
                )
            )
        except ImportError:
            pass  # Events module not available

    @classmethod
    def get_recent_background_output(cls, count: int = 5) -> list[tuple[str, str, str]]:
        """Get the most recent background output lines.

        Args:
            count: Number of recent lines to return (default: 5)

        Returns:
            List of (timestamp, task_name, message) tuples
        """
        return cls._background_output_buffer[-count:]

    @classmethod
    def clear_background_output_buffer(cls) -> None:
        """Clear the background output buffer."""
        cls._background_output_buffer = []

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
        parser.add_argument(
            "--debug",
            action="store_true",
            default=False,
            help="Enable debug/verbose mode (shows detailed hook installation and internal messages from dexray-intercept)",
        )

        # Only parse args if not already set by modern CLI (click-based)
        # When running via `sandroid -i`, cli.py sets Toolbox.args before calling init()
        if cls.args is None:
            cls.args = parser.parse_args()
        else:
            # Args were already set by the modern CLI - don't parse again
            # This avoids argparse failing on click-only options like -i/--interactive
            pass
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
            f"results/{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}/"
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

        # Create tool-specific folders at results root (sibling to raw/, like dexray_intercept/)
        tool_folders = ["fritap", "dexray_insight"]
        for folder in tool_folders:
            folder_path = os.path.join(base_folder, folder)
            if not os.path.exists(folder_path):
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
                from rich.panel import Panel

                console = SandroidConsole.get()

                # Build formatted emulator list
                emulator_list = ""
                for idx, emulator in enumerate(available_emulators, 1):
                    emulator_list += f"[primary]\\[[/primary][warning]{idx}[/warning][primary]][/primary] [success]{emulator}[/success]\n"

                # Display emulators in a Rich Panel
                panel = Panel(
                    emulator_list.strip(),
                    title="[accent]Available Emulators[/accent]",
                    border_style="cyan",
                    expand=False,
                )
                console.print()
                console.print(panel)

                # Ask user to select an emulator
                selected_idx = 0
                try:
                    while selected_idx < 1 or selected_idx > len(available_emulators):
                        try:
                            selected_idx = int(
                                cls.safe_input(
                                    f"\nSelect an emulator to start (1-{len(available_emulators)}): "
                                )
                            )
                            if selected_idx < 1 or selected_idx > len(
                                available_emulators
                            ):
                                console.print(
                                    f"[error]Please enter a number between [warning]1[/warning] and [warning]{len(available_emulators)}[/warning][/error]"
                                )
                        except ValueError:
                            console.print("[error]Please enter a valid number[/error]")
                except KeyboardInterrupt:
                    console.print(
                        "\n[warning]Emulator selection cancelled by user. Exiting...[/warning]"
                    )
                    exit(0)

                # Store the selected emulator name
                selected_emulator = available_emulators[selected_idx - 1]
                # Update the device name with selected emulator
                cls.device_name = selected_emulator
                cls.logger.info(f"Starting emulator {selected_emulator}...")

                if Emulator.start_avd(selected_emulator):
                    cls.logger.info(
                        f"Emulator '{selected_emulator}' started successfully. Continuing setup..."
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
        SandroidConsole.add_startup_message(
            "[info]adb root enabled successfully.[/info]"
        )

        # Ensure SELinux is set to permissive mode
        stdout, stderr = Adb.send_adb_command("shell setenforce 0")
        if stderr:
            cls.logger.warning(
                f"Failed to set SELinux to permissive mode: {stderr.strip()}"
            )
            SandroidConsole.add_startup_message(
                f"[warning]Failed to set SELinux to permissive mode: {stderr.strip()}[/warning]"
            )
        else:
            cls.logger.info("SELinux set to permissive mode.")
            SandroidConsole.add_startup_message(
                "[info]SELinux set to permissive mode.[/info]"
            )

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
            msg = (
                "The 'sqldiff' binary was not found in PATH. "
                "Database comparison functionality will be limited. "
                "Please install sqlite3 tools to enable full database diffing."
            )
            cls.logger.info(msg)
            SandroidConsole.add_startup_message(f"[info]{msg}[/info]")

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
            msg = (
                "The 'objection' tool was not found in PATH. "
                "Interactive application exploration will be limited. "
                "Please install objection using 'pip install objection'."
            )
            cls.logger.warning(msg)
            SandroidConsole.add_startup_message(f"[warning]{msg}[/warning]")

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
        cls.logger.info(f"Creating snapshot: {name.decode('utf-8')}")
        Adb.send_telnet_command(b"avd snapshot save " + name)

    @classmethod
    def load_snapshot(cls, name):
        """Loads a snapshot of the AVD.

        .. warning::
            Make sure the snapshot you are trying to load has been created first, this function has no error handling for that case.

        :param name: The name of the snapshot.
        :type name: str
        """
        cls.logger.info(f"Loading snapshot: {name.decode('utf-8')}")
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
        from rich.panel import Panel

        console = SandroidConsole.get()

        emulator_id = Adb.get_current_avd_name()
        emulator_path = Adb.get_current_avd_path()
        device_time = Adb.get_device_time()
        device_locale = Adb.get_device_locale()
        android_info = Adb.get_android_version_and_api_level()
        network_info = Adb.get_network_info()
        snapshots = Adb.get_avd_snapshots()

        # Build information string with Rich markup
        info_text = (
            f"[primary]Emulator ID:[/primary] [success]{emulator_id}[/success]\n"
        )
        info_text += (
            f"[primary]Emulator Path:[/primary] [success]{emulator_path}[/success]\n"
        )
        info_text += (
            f"[primary]Device Time:[/primary] [success]{device_time}[/success]\n"
        )
        info_text += (
            f"[primary]Device Locale:[/primary] [success]{device_locale}[/success]\n"
        )
        info_text += f"[primary]Android Version & API Level:[/primary] [success]{android_info.get('android_version', 'Unknown')} (API {android_info.get('api_level', 'Unknown')})[/success]\n\n"

        # Add network interfaces section
        info_text += "[warning]Network Interfaces:[/warning]\n"
        for interface, ip in network_info:
            info_text += f"[primary]Interface:[/primary] [success]{interface}[/success] ([info]{ip}[/info])\n"

        # Add snapshots section if available
        if snapshots:
            info_text += "\n[warning]Available Snapshots:[/warning]\n"
            for snapshot in snapshots:
                # Switch order to put date first for better alignment
                info_text += f"[success]{snapshot['date']}[/success] - [primary]{snapshot['tag']}[/primary]\n"

        # Display in Rich Panel
        panel = Panel(
            info_text.strip(),
            title="[accent]Emulator Information[/accent]",
            border_style="cyan",
            expand=False,
        )
        console.print(panel)

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
                    # Make sure parent db files are added when WAL or journal files change
                    if filename.endswith("-wal"):
                        changedFiles.update(
                            {currentDir + filename[0:-4]: secondsTimestamp}
                        )
                    elif filename.endswith("-journal"):
                        changedFiles.update(
                            {currentDir + filename[0:-8]: secondsTimestamp}
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
        cls._spawn_mode = False
        cls._spotlight_spawn_application = None
        cls.logger.info("Spotlight application information has been reset.")

    @classmethod
    def set_spawn_mode(cls, enabled):
        """Sets whether spawn mode is enabled.

        :param enabled: True to enable spawn mode, False for attach mode.
        :type enabled: bool
        """
        cls._spawn_mode = enabled
        mode_str = "SPAWN" if enabled else "ATTACH"
        cls.logger.info(f"Spotlight mode set to: {mode_str}")

    @classmethod
    def is_spawn_mode(cls):
        """Returns whether spawn mode is currently enabled.

        :returns: True if spawn mode is enabled, False otherwise.
        :rtype: bool
        """
        return cls._spawn_mode

    @classmethod
    def set_spotlight_spawn_application(cls, package_name):
        """Sets the application to be spawned when using Frida-based tools.

        :param package_name: The package name of the app to spawn.
        :type package_name: str
        """
        cls._spotlight_spawn_application = package_name
        cls._spawn_mode = True
        cls.logger.info(f"Spotlight spawn application set to: {package_name}")

    @classmethod
    def get_spotlight_spawn_application(cls):
        """Returns the package name of the app to be spawned.

        :returns: The package name of the spawn app, or None if not set.
        :rtype: str or None
        """
        return cls._spotlight_spawn_application

    @classmethod
    def set_auto_resume_after_spawn(cls, enabled):
        """Sets whether spawned apps should be auto-resumed.

        :param enabled: True to auto-resume, False to leave paused.
        :type enabled: bool
        """
        cls._auto_resume_after_spawn = enabled
        cls.logger.info(f"Auto-resume after spawn: {enabled}")

    @classmethod
    def get_auto_resume_after_spawn(cls):
        """Returns whether auto-resume after spawn is enabled.

        :returns: True if auto-resume is enabled, False otherwise.
        :rtype: bool
        """
        return cls._auto_resume_after_spawn

    @classmethod
    def resume_spawned_process_after_hooks(cls, device, pid):
        """Resume a spawned process after hooks have been installed.

        This includes the required 1-second sleep to prevent Java.perform from silently failing.

        :param device: Frida device object
        :type device: frida.core.Device
        :param pid: Process ID to resume
        :type pid: int
        """
        import time

        if cls._auto_resume_after_spawn:
            cls.logger.debug(f"Resuming spawned process {pid} after hook installation")
            device.resume(pid)
            time.sleep(1)  # CRITICAL: Prevents Java.perform from silently failing
            cls.logger.debug("Process resumed and stabilized")
        else:
            cls.logger.info(
                f"Process {pid} remains PAUSED (auto-resume disabled). "
                "Resume manually when ready."
            )

    @classmethod
    def get_frida_session_for_spotlight(cls):
        """Returns appropriate Frida session based on current mode (spawn/attach).

        This is the unified abstraction layer for all Frida-based tools.

        :returns: A tuple of (session, mode, app_info) where:
            - session: Frida session object
            - mode: "spawn" or "attach"
            - app_info: dict with package_name, pid, mode, etc.
        :rtype: tuple
        :raises: Exception if Frida setup fails
        """
        import frida

        try:
            device = frida.get_usb_device()

            if cls._spawn_mode and cls._spotlight_spawn_application:
                # SPAWN MODE
                cls.logger.info(
                    f"Spawning application: {cls._spotlight_spawn_application}"
                )

                # Spawn the application (starts paused)
                pid = device.spawn([cls._spotlight_spawn_application])
                cls.logger.debug(f"Spawned process with PID: {pid}")

                # Attach to the spawned process
                session = device.attach(pid)
                cls.logger.debug("Attached to spawned process")

                # Don't resume yet - let the caller resume AFTER installing hooks
                cls.logger.debug(
                    f"Process spawned and attached but PAUSED. "
                    f"Will be resumed after hooks are installed (auto-resume: {cls._auto_resume_after_spawn})"
                )

                app_info = {
                    "package_name": cls._spotlight_spawn_application,
                    "pid": pid,
                    "mode": "spawn",
                    "device": device,
                }

                cls.logger.info(
                    f"Successfully spawned and attached to {cls._spotlight_spawn_application} "
                    f"(PID: {pid})"
                )

                return session, "spawn", app_info

            # ATTACH MODE (existing behavior)
            if not cls._spotlight_application:
                raise ValueError(
                    "No spotlight application set. Press 'c' to set current app or 'C' to select spawn app."
                )

            package_name = cls._spotlight_application[0]
            cls.logger.info(f"Attaching to running application: {package_name}")

            # Get PID if not already set
            if not cls._spotlight_application_pid:
                from .adb import Adb

                pid = Adb.get_pid_for_package_name(package_name)
                if not pid:
                    raise ValueError(
                        f"Application {package_name} is not running. "
                        f"Start it first or use spawn mode (Shift+C)."
                    )
                cls._spotlight_application_pid = pid
            else:
                pid = cls._spotlight_application_pid

            # Attach to running process using PID (not package name)
            # Using PID is more reliable than package name
            cls.logger.debug(f"Attaching to {package_name} with PID {pid}")
            session = device.attach(pid)
            cls.logger.debug(f"Attached to running process (PID: {pid})")

            app_info = {
                "package_name": package_name,
                "pid": pid,
                "mode": "attach",
                "device": device,
            }

            cls.logger.info(f"Successfully attached to {package_name} (PID: {pid})")

            return session, "attach", app_info

        except frida.ProcessNotFoundError as e:
            cls.logger.error(f"Process not found: {e}")
            raise
        except frida.ServerNotRunningError:
            cls.logger.error("Frida server is not running. Press 'f' to start it.")
            raise
        except Exception as e:
            error_msg = str(e).lower()

            # Handle specific "front-door activity" error in spawn mode
            if "front-door" in error_msg or "unable to find" in error_msg:
                cls.logger.error(f"Error setting up Frida session: {e}")
                cls.logger.error("")
                cls.logger.error("This error typically occurs when:")
                cls.logger.error("  1. The app has no launchable main activity")
                cls.logger.error("  2. The package name is incorrect")
                cls.logger.error("  3. The app cannot be launched directly")
                cls.logger.error("")
                cls.logger.error("Suggestions:")
                cls.logger.error("  - Verify the package name is correct")
                cls.logger.error(
                    "  - Try using ATTACH mode instead (press 'c' after launching the app manually)"
                )
                cls.logger.error("  - Check if the app appears in the launcher")
                cls.logger.error("  - For system services, use attach mode only")
            else:
                cls.logger.error(f"Error setting up Frida session: {e}")
            raise

    @classmethod
    def ensure_spotlight_app_for_tools(cls, tool_name: str = "this tool") -> bool:
        """Ensure a spotlight app is set, prompting user to select if not.

        This is the unified entry point for tools that require a spotlight application.
        Shows a nice UI asking user to choose ATTACH or SPAWN mode if no app is set.

        Args:
            tool_name: Name of the tool requiring spotlight (for display)

        Returns:
            True if spotlight is now set, False if user cancelled
        """
        from .adb import Adb

        console = SandroidConsole.get()

        # Check if spotlight is already set
        spotlight_set = cls._spotlight_application is not None or (
            cls._spawn_mode and cls._spotlight_spawn_application is not None
        )

        if spotlight_set:
            return True

        # No spotlight set - prompt user
        BOX_WIDTH = 70

        def _box_line(content: str, align: str = "center") -> str:
            """Create a box line with proper alignment accounting for Rich markup."""
            import re

            PLACEHOLDER = "\x00LBRACKET\x00"
            temp = content.replace("\\[", PLACEHOLDER)
            RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
            visual_text = RICH_MARKUP_RE.sub("", temp)
            visual_text = visual_text.replace(PLACEHOLDER, "[")
            visual_len = len(visual_text)

            if align == "center":
                left_pad = (BOX_WIDTH - visual_len) // 2
                right_pad = BOX_WIDTH - visual_len - left_pad
            else:  # left align
                left_pad = 2
                right_pad = BOX_WIDTH - visual_len - left_pad

            return f"[primary]║[/primary]{' ' * left_pad}{content}{' ' * right_pad}[primary]║[/primary]"

        console.print()
        console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
        console.print(
            _box_line(f"[bold]Spotlight Application Required for {tool_name}[/bold]")
        )
        console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
        console.print(
            _box_line("[accent]Choose how to target the application:[/accent]")
        )
        console.print(_box_line(""))
        console.print(
            _box_line(
                "[warning]\\[A][/warning] ATTACH mode - Hook into currently running app",
                align="left",
            )
        )
        console.print(
            _box_line(
                "    [dim]Use if app is already open on device[/dim]", align="left"
            )
        )
        console.print(_box_line(""))
        console.print(
            _box_line(
                "[warning]\\[S][/warning] SPAWN mode - Launch app fresh with hooks",
                align="left",
            )
        )
        console.print(
            _box_line(
                "    [dim]Use for clean analysis from app startup[/dim]", align="left"
            )
        )
        console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
        console.print(
            _box_line(
                "[success]\\[A/S][/success] Select mode    [error]\\[Esc/Q][/error] Cancel",
                align="left",
            )
        )
        console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")

        console.print("\n[success]► Select mode:[/success] ", end="")

        try:
            choice = click.getchar().lower()
            console.print(f"[accent]{choice}[/accent]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[warning]Cancelled[/warning]")
            return False

        if choice in ("\x1b", "q"):  # ESC or Q
            console.print("[warning]Cancelled[/warning]")
            return False
        if choice == "a":
            # ATTACH MODE - use currently focused app
            focused_app = Adb.get_focused_app()
            if not focused_app:
                console.print(
                    "[error]No app is currently focused on the device.[/error]"
                )
                console.print(
                    "[warning]Please open an app on the device and try again.[/warning]"
                )
                return False

            cls.set_spotlight_application(focused_app)
            spotlight_name = cls.get_spotlight_application()[0]
            spotlight_pid = Adb.get_pid_for_package_name(spotlight_name)

            if not spotlight_pid:
                console.print(f"[error]Could not get PID for {spotlight_name}[/error]")
                return False

            cls.set_spotlight_application_pid(spotlight_pid)
            cls.set_spawn_mode(False)

            console.print("\n[success]✓ Spotlight set in ATTACH mode:[/success]")
            console.print(f"  Package: [warning]{spotlight_name}[/warning]")
            console.print(f"  PID: [warning]{spotlight_pid}[/warning]")
            return True

        if choice == "s":
            # SPAWN MODE - select app with fuzzy search
            console.print("\n[primary]Select an application to spawn...[/primary]")

            selected_package = cls.select_app_with_fuzzy_search()
            if not selected_package:
                console.print("[warning]No app selected[/warning]")
                return False

            cls.set_spotlight_spawn_application(selected_package)

            # Ask about auto-resume
            console.print("\n[primary]Auto-resume spawned app?[/primary]")
            console.print(
                "[accent]\\[Y][/accent] = App starts immediately after spawn (recommended)"
            )
            console.print("[accent]\\[N][/accent] = App stays paused, resume manually")
            console.print("\n[success]► Press y or n (Enter = yes):[/success] ", end="")

            try:
                resume_choice = click.getchar().lower()
                console.print(f"[accent]{resume_choice}[/accent]")
            except (KeyboardInterrupt, EOFError):
                resume_choice = "y"

            cls.set_auto_resume_after_spawn(resume_choice != "n")

            resume_status = "enabled" if resume_choice != "n" else "disabled"
            console.print("\n[success]✓ Spotlight set in SPAWN mode:[/success]")
            console.print(f"  Package: [warning]{selected_package}[/warning]")
            console.print(f"  Auto-resume: [warning]{resume_status}[/warning]")
            return True

        console.print(f"[error]Invalid choice: {choice}[/error]")
        return False

    @classmethod
    def select_app_with_fuzzy_search(cls, recently_installed_package=None):
        """Interactive app selection with fuzzy search capability.

        Displays user-installed apps by default and allows user to filter them with fuzzy search.
        Offers option to show all apps (including system apps).

        :param recently_installed_package: Package name of a recently installed app to highlight/suggest.
        :type recently_installed_package: str or None
        :returns: Selected package name, or None if cancelled.
        :rtype: str or None
        """
        from .adb import Adb

        try:
            # Try to import fuzzy search library
            try:
                from thefuzz import fuzz, process

                has_fuzzy = True
            except ImportError:
                cls.logger.warning(
                    "thefuzz library not installed. Install with: pip install thefuzz"
                )
                cls.logger.info("Falling back to simple numbered selection")
                has_fuzzy = False

            # Get Rich console
            console = SandroidConsole.get()

            # Suggest recently installed app first if provided
            if recently_installed_package:
                console.print(
                    "\n[menu.section]=== Recently Installed App ===[/menu.section]"
                )
                console.print(
                    f"[warning]\\[0][/warning] [success]{recently_installed_package}[/success] "
                    f"[primary](Just installed)[/primary]"
                )
                console.print(
                    "\n[warning]Press 0 to use this app, or press ENTER to see all apps:[/warning]"
                )

                try:
                    char = click.getchar()
                    if char == "0":
                        cls.logger.info(
                            f"Selected recently installed app: {recently_installed_package}"
                        )
                        return recently_installed_package
                except (KeyboardInterrupt, EOFError):
                    pass  # Continue to app list

            # Ask if user wants to see all apps or just user-installed
            console.print("\n[menu.section]=== App Filter ===[/menu.section]")
            console.print(
                "[warning]\\[1][/warning] Show only user-installed apps (recommended)"
            )
            console.print(
                "[warning]\\[2][/warning] Show all apps (including system apps)"
            )
            console.print(
                "\n[warning]Select filter (press 1 or 2, default is 1):[/warning]"
            )

            try:
                char = click.getchar()
                show_all = char == "2"
            except (KeyboardInterrupt, EOFError):
                show_all = False  # Default to user-installed only

            # Get installed packages based on filter
            cls.logger.info("Fetching installed applications...")
            packages = Adb.get_installed_packages(user_only=not show_all)

            if not packages:
                cls.logger.error("No packages found on device")
                return None

            # Sort by install date (newest first), then by package name
            packages.sort(
                key=lambda x: (x.get("install_date") or "", x["package_name"]),
                reverse=True,
            )

            # Start with all packages (show apps first, then allow filtering)
            filtered_packages = packages

            # Display filtered packages
            app_type = "User-Installed" if not show_all else "All"
            console.print(
                f"\n[menu.section]=== {app_type} Applications ({len(filtered_packages)}) ===[/menu.section]"
            )

            for idx, pkg in enumerate(filtered_packages, 1):
                install_date = pkg.get("install_date", "Unknown")
                # Truncate long package names for display
                pkg_name = pkg["package_name"]
                if len(pkg_name) > 50:
                    pkg_name = pkg_name[:47] + "..."

                # Show app type indicator if showing all apps
                type_indicator = ""
                if show_all and pkg.get("is_user_app", False):
                    type_indicator = " [info]\\[USER][/info]"

                console.print(
                    f"[warning]{idx:3d}.[/warning] "
                    f"[success]{pkg_name:50s}[/success]"
                    f"{type_indicator} "
                    f"[primary]\\[{install_date}][/primary]"
                )

                # Add pagination for long lists
                if idx % 20 == 0 and idx < len(filtered_packages):
                    response = cls.safe_input(
                        "\nPress ENTER to see more, or type a number to select: "
                    )
                    if response.isdigit():
                        selected_idx = int(response)
                        if 1 <= selected_idx <= len(filtered_packages):
                            return filtered_packages[selected_idx - 1]["package_name"]

            # Special handling for single app - auto-select with Enter
            if len(filtered_packages) == 1:
                console.print(
                    "\n[success]Press Enter to select this app, or 'q' to cancel:[/success] ",
                    end="",
                )
                choice = cls.safe_input("")
                if choice.lower() != "q":
                    return filtered_packages[0]["package_name"]
                cls.logger.info("Selection cancelled")
                return None

            # Get user selection (with optional fuzzy filtering)
            while True:
                try:
                    # Build prompt based on fuzzy search availability
                    if has_fuzzy and filtered_packages == packages:
                        prompt = f"\nEnter number (1-{len(filtered_packages)}), 'f' to filter, or 'q' to cancel: "
                    else:
                        prompt = f"\nEnter number (1-{len(filtered_packages)}) or 'q' to cancel: "

                    selection_input = cls.safe_input(prompt)

                    if selection_input.lower() == "q":
                        cls.logger.info("Selection cancelled")
                        return None

                    # Fuzzy search filter option
                    if selection_input.lower() == "f" and has_fuzzy:
                        console.print(
                            "\n[menu.section]=== Fuzzy Search Filter ===[/menu.section]"
                        )
                        search_term = cls.safe_input(
                            "Enter search term (or press ENTER to show all): "
                        )

                        if search_term:
                            # Perform fuzzy matching
                            package_names = [p["package_name"] for p in packages]
                            matches = process.extract(
                                search_term,
                                package_names,
                                scorer=fuzz.partial_ratio,
                                limit=20,
                            )

                            # Filter packages based on matches
                            filtered_packages = [
                                p
                                for p in packages
                                if p["package_name"]
                                in [m[0] for m in matches if m[1] > 50]
                            ]

                            if not filtered_packages:
                                cls.logger.warning(
                                    f"No matches found for '{search_term}'. Showing all apps."
                                )
                                filtered_packages = packages
                        else:
                            filtered_packages = packages

                        # Re-display filtered packages
                        app_type = "User-Installed" if not show_all else "All"
                        console.print(
                            f"\n[menu.section]=== {app_type} Applications ({len(filtered_packages)}) ===[/menu.section]"
                        )

                        for idx, pkg in enumerate(filtered_packages, 1):
                            install_date = pkg.get("install_date", "Unknown")
                            pkg_name = pkg["package_name"]
                            if len(pkg_name) > 50:
                                pkg_name = pkg_name[:47] + "..."

                            type_indicator = ""
                            if show_all and pkg.get("is_user_app", False):
                                type_indicator = " [info]\\[USER][/info]"

                            console.print(
                                f"[warning]{idx:3d}.[/warning] "
                                f"[success]{pkg_name:50s}[/success]"
                                f"{type_indicator} "
                                f"[primary]\\[{install_date}][/primary]"
                            )
                        continue  # Go back to selection prompt

                    selected_idx = int(selection_input)

                    if 1 <= selected_idx <= len(filtered_packages):
                        selected_package = filtered_packages[selected_idx - 1][
                            "package_name"
                        ]
                        cls.logger.info(f"Selected: {selected_package}")
                        return selected_package
                    console.print(
                        f"[error]Invalid number. Please enter 1-{len(filtered_packages)}[/error]"
                    )
                except ValueError:
                    if has_fuzzy and filtered_packages == packages:
                        console.print(
                            "[error]Invalid input. Please enter a number, 'f' to filter, or 'q'[/error]"
                        )
                    else:
                        console.print(
                            "[error]Invalid input. Please enter a number or 'q'[/error]"
                        )
                except KeyboardInterrupt:
                    cls.logger.info("\nSelection cancelled by user")
                    return None

        except Exception as e:
            cls.logger.error(f"Error during app selection: {e}")
            return None

    @classmethod
    def get_spotlighted_app_data_path(cls):
        """Returns the /data/data/<spotlight_application> path if a spotlight app is set.
        Otherwise, returns None and logs a warning.
        """
        if cls._spawn_mode and cls._spotlight_spawn_application:
            return f"/data/data/{cls._spotlight_spawn_application}"
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

            # For SQLite database files, also pull WAL and journal files if they exist
            if is_sqlite_file(target):
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
                start_new_session=True,
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
            start_new_session=True,
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
    def get_current_view(cls):
        """Gets the current view mode.

        :returns: The current view mode (forensic, malware, or security).
        :rtype: str
        """
        return cls._current_view

    @classmethod
    def set_current_view(cls, view):
        """Sets the current view mode.

        :param view: The view mode to set (forensic, malware, or security).
        :type view: str
        """
        if view in cls._view_cycle:
            cls._current_view = view
            if cls.logger:
                cls.logger.info(f"View changed to: {view.upper()}")
        elif cls.logger:
            cls.logger.warning(
                f"Invalid view mode: {view}. Valid modes are: {', '.join(cls._view_cycle)}"
            )

    @classmethod
    def cycle_view(cls):
        """Cycles to the next view mode in the cycle order."""
        current_index = cls._view_cycle.index(cls._current_view)
        next_index = (current_index + 1) % len(cls._view_cycle)
        cls._current_view = cls._view_cycle[next_index]
        if cls.logger:
            cls.logger.info(f"View changed to: {cls._current_view.upper()}")
        return cls._current_view

    @classmethod
    def show_blocking_warning(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Display a warning modal that requires user acknowledgment.

        This creates a blocking dialog box that overlays the terminal and requires
        the user to press Enter to continue. Useful for important warnings that
        should not be missed.

        :param title: The title of the warning dialog
        :type title: str
        :param message: The warning message to display
        :type message: str
        :param action_hint: Optional hint about what action to take (e.g., "Press [f] to start Frida")
        :type action_hint: str
        :param action_key: Optional key that can dismiss modal and trigger the suggested action
        :type action_key: str
        :return: None if Enter pressed, or the action_key if that was pressed
        :rtype: str or None
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text

            # Build message with optional action hint using Rich markup
            console = Console()

            # Create text object for proper formatting
            text = Text()
            text.append(message)

            if action_hint:
                text.append("\n\n")
                text.append(action_hint, style="cyan bold")

            text.append("\n\n")
            text.append("Press Enter to continue...", style="yellow")

            panel = Panel(
                text,
                title=f"! {title}",
                border_style="yellow bold",
                padding=(1, 2),
                expand=False,
            )

            print()  # Add spacing before panel
            console.print(panel)
            print()  # Add spacing after panel

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

        except ImportError:
            # Fallback to ASCII box if Rich is not available
            box_content = f"{message}\n"
            if action_hint:
                box_content += f"\n{action_hint}\n"
            box_content += "\nPress Enter to continue..."

            print()
            print(cls._create_ascii_box(box_content, f"WARNING: {title}"))

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

    @classmethod
    def show_blocking_error(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Display an error modal that requires user acknowledgment.

        Similar to show_blocking_warning but styled for errors with red border.

        :param title: The title of the error dialog
        :type title: str
        :param message: The error message to display
        :type message: str
        :param action_hint: Optional hint about what action to take
        :type action_hint: str
        :param action_key: Optional key that can dismiss modal and trigger the suggested action
        :type action_key: str
        :return: None if Enter pressed, or the action_key if that was pressed
        :rtype: str or None
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text

            # Build message with optional action hint using Rich markup
            console = Console()

            # Create text object for proper formatting
            text = Text()
            text.append(message)

            if action_hint:
                text.append("\n\n")
                text.append(action_hint, style="cyan bold")

            text.append("\n\n")
            text.append("Press Enter to continue...", style="red")

            panel = Panel(
                text,
                title=f"✗ {title}",
                border_style="red bold",
                padding=(1, 2),
                expand=False,
            )

            print()  # Add spacing before panel
            console.print(panel)
            print()  # Add spacing after panel

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

        except ImportError:
            # Fallback to ASCII box if Rich is not available
            box_content = f"{message}\n"
            if action_hint:
                box_content += f"\n{action_hint}\n"
            box_content += "\nPress Enter to continue..."

            print()
            print(cls._create_ascii_box(box_content, f"ERROR: {title}"))

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

    @classmethod
    def show_blocking_info(
        cls, title: str, message: str, action_hint: str = None, action_key: str = None
    ):
        """Display an info modal that requires user acknowledgment.

        Similar to show_blocking_warning but styled for informational messages with cyan border.

        :param title: The title of the info dialog
        :type title: str
        :param message: The info message to display
        :type message: str
        :param action_hint: Optional hint about what action to take
        :type action_hint: str
        :param action_key: Optional key that can dismiss modal and trigger the suggested action
        :type action_key: str
        :return: None if Enter pressed, or the action_key if that was pressed
        :rtype: str or None
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text

            # Build message with optional action hint using Rich markup
            console = Console()

            # Create text object for proper formatting
            text = Text()
            text.append(message)

            if action_hint:
                text.append("\n\n")
                text.append(action_hint, style="cyan bold")

            text.append("\n\n")
            text.append("Press Enter to continue...", style="cyan")

            panel = Panel(
                text,
                title=f"[i] {title}",
                border_style="cyan bold",
                padding=(1, 2),
                expand=False,
            )

            print()  # Add spacing before panel
            console.print(panel)
            print()  # Add spacing after panel

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

        except ImportError:
            # Fallback to ASCII box if Rich is not available
            box_content = f"{message}\n"
            if action_hint:
                box_content += f"\n{action_hint}\n"
            box_content += "\nPress Enter to continue..."

            print()
            print(cls._create_ascii_box(box_content, f"INFO: {title}"))

            # Wait for Enter key or action key
            import click

            while True:
                key = click.getchar()
                if key in ("\r", "\n"):  # Enter key
                    return None
                if action_key and key == action_key:
                    return action_key
                # Ignore all other keys

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
        proxy_ip = cls.safe_input() or host_ip
        cls.logger.info("Enter proxy port (default: 8080)")
        proxy_port = cls.safe_input() or "8080"

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
        cls.logger.info(f"Taking screenshot: {filename}")

        # Use the specified telnet command
        stdout, stderr = Adb.send_telnet_command(f"screenrecord screenshot {filename}")

        if stderr:
            cls.logger.error(f"Failed to capture screenshot: {stderr}")
            return None

        cls.logger.info(f"Screenshot saved to {filename}")

        # Register tool usage for exit summary
        cls.mark_tool_used("screenshots", files=[filename])

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
        cls.logger.info(f"Started screen recording to {cls._screen_recording_file}")
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

        cls.logger.info(f"Screen recording saved to {cls._screen_recording_file}")
        cls._screen_recording_running = False
        return True

    @classmethod
    def print_interactive_menu(cls):
        """Prints the interactive main menu with view-based filtering."""
        from rich.panel import Panel

        console = SandroidConsole.get()

        # Clear screen and show logo at top, so menu stays at top and logs appear below
        SandroidConsole.clear()
        SandroidConsole.print_logo()
        console.print()  # Add blank line after logo

        # Get current view
        current_view = cls._current_view
        view_display = current_view.upper()

        # Frida server status
        is_frida_running = cls.frida_manager.is_frida_server_running()
        if is_frida_running:
            frida_server_string = "[status.running]Running[/status.running]"
        else:
            frida_server_string = "[status.stopped]Not running[/status.stopped]"
        frida_server_string = f"Frida Server: [{frida_server_string}]"

        # Proxy settings (shown in all views)
        proxy_settings = cls.get_proxy_settings()
        if proxy_settings == "Not set":
            proxy_string = "[status.stopped]Not set[/status.stopped]"
        else:
            proxy_string = f"[success]{proxy_settings}[/success]"

        # Add adjustment note if not in a view where it can be modified
        if current_view == "security":
            proxy_string = f"HTTP Proxy: [{proxy_string}] [warning](adjust in forensic/malware view)[/warning]"
        else:
            proxy_string = f"HTTP Proxy: [{proxy_string}]"

        # Spotlight application (shown in all views)
        if cls._spawn_mode and cls._spotlight_spawn_application:
            # SPAWN MODE
            spotlight_application_string = (
                f"[warning]{cls._spotlight_spawn_application}[/warning]"
            )
            if cls._auto_resume_after_spawn:
                spotlight_application_string += " [success](auto-resume)[/success]"
            else:
                spotlight_application_string += " [warning](manual resume)[/warning]"
            spotlight_application_string = f"Spotlight Application: [{spotlight_application_string}] [mode.spawn]\\[SPAWN MODE][/mode.spawn]"
        elif cls._spotlight_application:
            # ATTACH MODE
            spotlight_application_string = f"Spotlight Application: [[warning]{cls._spotlight_application[0]}, PID: {cls._spotlight_application_pid}[/warning]] [mode.attach]\\[ATTACH MODE][/mode.attach]"
        else:
            spotlight_application_string = (
                "Spotlight Application: [[status.stopped]Not set[/status.stopped]]"
            )

        # Spotlight files (shown in all views)
        spotlight_files = [
            file
            for file in cls._spotlight_files
            if not (file.endswith("-wal") or file.endswith("-journal"))
        ]

        if not spotlight_files:
            spotlight_files_display = "[status.stopped]Not set[/status.stopped]"
        elif len(spotlight_files) == 1:
            spotlight_files_display = f"[warning]{spotlight_files[0]}[/warning]"
        else:
            spotlight_files_display = (
                f"[warning]{len(spotlight_files)} files set[/warning]"
            )

        # Add adjustment note if not in forensic view
        if current_view == "forensic":
            spotlight_files_string = f"Spotlight Files: [{spotlight_files_display}]"
        else:
            spotlight_files_string = f"Spotlight Files: [{spotlight_files_display}] [warning](adjust in forensic view)[/warning]"

        # Background tasks status
        bg_tasks_status = cls.get_background_tasks_status_string()
        background_tasks_string = ""
        if bg_tasks_status:
            background_tasks_string = f"Background Tasks: {bg_tasks_status}"

        # Mode indicator for Frida-based tools
        mode_indicator = ""
        if cls._spawn_mode:
            mode_indicator = " [mode.spawn]\\[SPAWN][/mode.spawn]"
        elif cls._spotlight_application:
            mode_indicator = " [mode.attach]\\[ATTACH][/mode.attach]"

        # Build menu content based on view
        menu_content = []

        # Header with status info (always shown in all views)
        menu_content.append(f"{frida_server_string}")
        menu_content.append(proxy_string)
        menu_content.append(spotlight_application_string)
        menu_content.append(spotlight_files_string)
        if background_tasks_string:
            menu_content.append(background_tasks_string)
        menu_content.append("")  # Blank line

        # === FORENSIC VIEW ===
        if current_view == "forensic":
            # Action Recording & Playback
            menu_content.extend(
                [
                    "    [menu.section]=== Action Recording & Playback ===[/menu.section]",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]r[/menu.key][menu.key.bracket]][/menu.key.bracket]ecord an action",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]p[/menu.key][menu.key.bracket]][/menu.key.bracket]lay the currently loaded action",
                    "    * e[menu.key.bracket]\\[[/menu.key.bracket][menu.key]x[/menu.key][menu.key.bracket]][/menu.key.bracket]port currently loaded action",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]i[/menu.key][menu.key.bracket]][/menu.key.bracket]mport action",
                    "",
                ]
            )

            # Spotlight Application
            menu_content.extend(
                [
                    "    [menu.section]=== Spotlight Application ===[/menu.section]",
                    "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
                    "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
                    f"    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]d[/menu.key][menu.key.bracket]][/menu.key.bracket]ump memory of spotlight app{mode_indicator}",
                    "",
                ]
            )

            # Spotlight Files
            menu_content.extend(
                [
                    "    [menu.section]=== Spotlight Files ===[/menu.section]",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]l[/menu.key][menu.key.bracket]][/menu.key.bracket]ist/add spotlight file",
                    "    * remo[menu.key.bracket]\\[[/menu.key.bracket][menu.key]v[/menu.key][menu.key.bracket]][/menu.key.bracket]e spotlight file",
                    "    * p[menu.key.bracket]\\[[/menu.key.bracket][menu.key]u[/menu.key][menu.key.bracket]][/menu.key.bracket]ll spotlight files",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]o[/menu.key][menu.key.bracket]][/menu.key.bracket]bserve file system changes (fsmon)",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]space[/menu.key][menu.key.bracket]][/menu.key.bracket] pull spotlight DB file",
                    "",
                ]
            )

            # Emulator Management
            screen_recording_string = ""
            if cls._screen_recording_running:
                screen_recording_string = f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rabbing video of screen ([warning]{os.path.basename(cls._screen_recording_file)}[/warning])"
            else:
                screen_recording_string = "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rab video of screen"

            menu_content.extend(
                [
                    "    [menu.section]=== Emulator Management ===[/menu.section]",
                    "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information",
                    "    * keys [menu.key.bracket]\\[[/menu.key.bracket][menu.key]1-8[/menu.key][menu.key.bracket]][/menu.key.bracket] create snapshots, key [menu.key.bracket]\\[[/menu.key.bracket][menu.key]0[/menu.key][menu.key.bracket]][/menu.key.bracket] lists/loads snapshots",
                    "    * take [menu.key.bracket]\\[[/menu.key.bracket][menu.key]s[/menu.key][menu.key.bracket]][/menu.key.bracket]creenshot of device",
                    f"    {screen_recording_string}",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                    "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                    "",
                ]
            )

            # Network Management (no friTap in forensic view)
            network_capture_string = ""
            if cls._network_capture_running:
                network_capture_string = f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]riting network capture file ([warning]{os.path.basename(cls._network_capture_file)}[/warning])"
            else:
                network_capture_string = "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]rite network capture file"

            menu_content.extend(
                [
                    "    [menu.section]=== Network Management ===[/menu.section]",
                    "    * set/unset network prox[menu.key.bracket]\\[[/menu.key.bracket][menu.key]y[/menu.key][menu.key.bracket]][/menu.key.bracket]",
                    f"    {network_capture_string}",
                    "",
                ]
            )

        # === MALWARE ANALYSIS VIEW ===
        elif current_view == "malware":
            # Action Recording & Playback
            menu_content.extend(
                [
                    "    [menu.section]=== Action Recording & Playback ===[/menu.section]",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]r[/menu.key][menu.key.bracket]][/menu.key.bracket]ecord an action",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]p[/menu.key][menu.key.bracket]][/menu.key.bracket]lay the currently loaded action",
                    "    * e[menu.key.bracket]\\[[/menu.key.bracket][menu.key]x[/menu.key][menu.key.bracket]][/menu.key.bracket]port currently loaded action",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]i[/menu.key][menu.key.bracket]][/menu.key.bracket]mport action",
                    "",
                ]
            )

            # Spotlight Application (malware-specific tools)
            malware_monitor_string = ""
            hook_config_string = ""
            if cls.is_task_running("dexray-intercept"):
                dexray_task = cls.get_task("dexray-intercept")
                # Show app name in [warning] color for consistency with filenames
                current_app = (
                    dexray_task.app_name
                    if dexray_task and dexray_task.app_name
                    else "app"
                )
                malware_monitor_string = f"* stop android [menu.key.bracket]\\[[/menu.key.bracket][menu.key]m[/menu.key][menu.key.bracket]][/menu.key.bracket]alware monitor (dexray-intercept) on [warning]{current_app}[/warning]"
                # Show option to reconfigure hooks while running
                hook_config_string = "    * reconfigure hoo[menu.key.bracket]\\[[/menu.key.bracket][menu.key]k[/menu.key][menu.key.bracket]][/menu.key.bracket]s (stops, reconfigures, restarts)"
            else:
                malware_monitor_string = f"* start android [menu.key.bracket]\\[[/menu.key.bracket][menu.key]m[/menu.key][menu.key.bracket]][/menu.key.bracket]alware monitor (dexray-intercept){mode_indicator}"

            menu_items = [
                "    [menu.section]=== Spotlight Application ===[/menu.section]",
                "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
                "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
                f"    {malware_monitor_string}",
            ]
            # Add hook config option only when dexray-intercept is running
            if hook_config_string:
                menu_items.append(hook_config_string)
            menu_items.extend(
                [
                    f"    * start o[menu.key.bracket]\\[[/menu.key.bracket][menu.key]b[/menu.key][menu.key.bracket]][/menu.key.bracket]jection interactive shell{mode_indicator}",
                    "    * run [menu.key.bracket]\\[[/menu.key.bracket][menu.key]t[/menu.key][menu.key.bracket]][/menu.key.bracket]rigdroid malware triggers",
                    "",
                ]
            )
            menu_content.extend(menu_items)

            # Emulator Management
            screen_recording_string = ""
            if cls._screen_recording_running:
                screen_recording_string = f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rabbing video of screen ([warning]{os.path.basename(cls._screen_recording_file)}[/warning])"
            else:
                screen_recording_string = "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]g[/menu.key][menu.key.bracket]][/menu.key.bracket]rab video of screen"

            menu_content.extend(
                [
                    "    [menu.section]=== Emulator Management ===[/menu.section]",
                    "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information",
                    "    * keys [menu.key.bracket]\\[[/menu.key.bracket][menu.key]1-8[/menu.key][menu.key.bracket]][/menu.key.bracket] create snapshots, key [menu.key.bracket]\\[[/menu.key.bracket][menu.key]0[/menu.key][menu.key.bracket]][/menu.key.bracket] lists/loads snapshots",
                    "    * take [menu.key.bracket]\\[[/menu.key.bracket][menu.key]s[/menu.key][menu.key.bracket]][/menu.key.bracket]creenshot of device",
                    f"    {screen_recording_string}",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                    "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                    "",
                ]
            )

            # Network Management (includes friTap)
            network_capture_string = ""
            if cls._network_capture_running:
                network_capture_string = f"* stop [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]riting network capture file ([warning]{os.path.basename(cls._network_capture_file)}[/warning])"
            else:
                network_capture_string = "* [menu.key.bracket]\\[[/menu.key.bracket][menu.key]w[/menu.key][menu.key.bracket]][/menu.key.bracket]rite network capture file"

            # FriTap menu item with toggle state
            if cls.is_task_running("fritap"):
                fritap_task = cls.get_task("fritap")
                # Show app name in [warning] color for consistency with filenames
                fritap_app = (
                    fritap_task.app_name
                    if fritap_task and fritap_task.app_name
                    else "app"
                )
                fritap_string = f"* stop friTap [menu.key.bracket]\\[[/menu.key.bracket][menu.key]h[/menu.key][menu.key.bracket]][/menu.key.bracket]ooking on [warning]{fritap_app}[/warning]"
            else:
                fritap_string = f"* start friTap [menu.key.bracket]\\[[/menu.key.bracket][menu.key]h[/menu.key][menu.key.bracket]][/menu.key.bracket]ooking{mode_indicator}"

            menu_content.extend(
                [
                    "    [menu.section]=== Network Management ===[/menu.section]",
                    "    * set/unset network prox[menu.key.bracket]\\[[/menu.key.bracket][menu.key]y[/menu.key][menu.key.bracket]][/menu.key.bracket]",
                    f"    {fritap_string}",
                    f"    {network_capture_string}",
                    "",
                ]
            )

        # === SECURITY VIEW ===
        elif current_view == "security":
            # Minimal view - only static analysis and basic controls
            menu_content.extend(
                [
                    "    [menu.section]=== Application Management ===[/menu.section]",
                    "    * set [menu.key.bracket]\\[[/menu.key.bracket][menu.key]c[/menu.key][menu.key.bracket]][/menu.key.bracket]urrent app in focus as spotlight app [mode.attach]\\[ATTACH MODE][/mode.attach]",
                    "    * select app with [menu.key.bracket]\\[[/menu.key.bracket][menu.key]Shift+C[/menu.key][menu.key.bracket]][/menu.key.bracket] for spawning [mode.spawn]\\[SPAWN MODE][/mode.spawn]",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]n[/menu.key][menu.key.bracket]][/menu.key.bracket]ew APK installation",
                    "",
                    "    [menu.section]=== Static Analysis ===[/menu.section]",
                    "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]a[/menu.key][menu.key.bracket]][/menu.key.bracket]nalyze spotlight app with dexray-insight",
                    "",
                    "    [menu.section]=== System ===[/menu.section]",
                    "    * show [menu.key.bracket]\\[[/menu.key.bracket][menu.key]e[/menu.key][menu.key.bracket]][/menu.key.bracket]mulator information",
                    "    * run/install [menu.key.bracket]\\[[/menu.key.bracket][menu.key]f[/menu.key][menu.key.bracket]][/menu.key.bracket]rida server",
                    "",
                ]
            )

        # Background Activity Section (shown if there are background tasks or recent output)
        recent_output = cls.get_recent_background_output(5)  # Show last 5 messages
        if recent_output or cls._background_tasks:
            menu_content.append("")
            menu_content.append(
                "    [menu.section]=== Background Activity ===[/menu.section]"
            )
            if recent_output:
                for timestamp, task_name, msg in recent_output:
                    # Truncate long messages to fit in menu
                    display_msg = msg[:65] + "..." if len(msg) > 65 else msg
                    # Escape any brackets in the message to prevent Rich markup issues
                    display_msg = display_msg.replace("[", "\\[").replace("]", "\\]")
                    menu_content.append(
                        f"    [dim]{timestamp}[/dim] [accent]{task_name}:[/accent] {display_msg}"
                    )
                # Show hint for more output
                total_buffered = len(cls._background_output_buffer)
                if total_buffered > 5:
                    menu_content.append(
                        f"    [dim]... {total_buffered - 5} more messages buffered[/dim]"
                    )
            else:
                # Show that tasks are running but no output yet
                running_tasks = ", ".join(cls._background_tasks.keys())
                menu_content.append(
                    f"    [dim]Tasks running: {running_tasks} (no output yet)[/dim]"
                )

        # Footer (common to all views)
        menu_content.extend(
            [
                "",
                "    [dim]💡 Tip: Press the same key again to stop/toggle active background processes[/dim]",
                "    * [menu.key.bracket]\\[[/menu.key.bracket][menu.key]TAB[/menu.key][menu.key.bracket]][/menu.key.bracket] switch view  |  [menu.key.bracket]\\[[/menu.key.bracket][menu.key]q[/menu.key][menu.key.bracket]][/menu.key.bracket]uit",
            ]
        )

        # Create the menu with view-specific title using custom bordered box
        # Title with VIEW in a unique color (yellow)
        title = f"Sandroid Interactive Menu - [bold yellow]{view_display} VIEW[/bold yellow]"
        content = "\n".join(menu_content)

        # Create the bordered box
        box_output = cls._create_colored_box(content, title, border_color="cyan")
        console.print(box_output)

        # Print any buffered startup messages below the menu
        SandroidConsole.print_startup_messages()

    @classmethod
    def _create_colored_box(
        cls, text: str, title: str, border_color: str = "cyan"
    ) -> str:
        """Creates a bordered box with colored borders and a title section.

        The title gets its own row with a separator line below it.

        :param text: The text to be enclosed in the box.
        :type text: str
        :param title: The title of the box (can include Rich markup).
        :type title: str
        :param border_color: Color for the box borders.
        :type border_color: str
        :returns: The formatted box with Rich color markup.
        :rtype: str
        """
        ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

        def strip_rich_markup(s: str) -> str:
            """Strip Rich markup tags but preserve escaped brackets as visible text."""
            # First, replace escaped brackets \[ with a placeholder
            PLACEHOLDER = "\x00LBRACKET\x00"
            s = s.replace("\\[", PLACEHOLDER)

            # Now strip actual Rich markup tags [tag]...[/tag]
            # Match tags like [bold], [red], [/bold], [menu.key], [bold yellow], etc.
            # Tags can contain: letters, numbers, dots, underscores, slashes, hashes, spaces
            RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
            s = RICH_MARKUP_RE.sub("", s)

            # Restore escaped brackets as literal [ characters
            s = s.replace(PLACEHOLDER, "[")
            return s

        def strip_formatting(s: str) -> str:
            s = ANSI_RE.sub("", s)
            s = strip_rich_markup(s)
            return s

        def cell_width(s: str) -> int:
            w = wcswidth(s)
            return 0 if w < 0 else w

        # Prepare content lines
        raw_lines = text.splitlines()
        stripped_lines = [strip_formatting(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [cell_width(ln) for ln in stripped_lines]

        # Calculate title width (without formatting)
        stripped_title = strip_formatting(title)
        title_w = cell_width(stripped_title)

        # Inner width is max of content width and title width, plus padding
        content_max_width = max(visible_widths) if visible_widths else 0
        inner_width = max(content_max_width, title_w) + 4  # padding on both sides

        # Build the box with colored borders
        bc = border_color  # shorthand

        # Title padding
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        # Top border and title section
        top = (
            f"[{bc}]┌{'─' * inner_width}┐[/{bc}]\n"
            f"[{bc}]│[/{bc}]{' ' * pad_left}{title}{' ' * pad_right}[{bc}]│[/{bc}]\n"
            f"[{bc}]├{'─' * inner_width}┤[/{bc}]\n"
        )

        # Body lines with colored borders
        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = inner_width - cell_width(stripped)
            pad = max(pad, 0)
            body_parts.append(f"[{bc}]│[/{bc}]{raw}{' ' * pad}[{bc}]│[/{bc}]")
        body = "\n".join(body_parts)

        # Bottom border
        bottom = f"\n[{bc}]└{'─' * inner_width}┘[/{bc}]"

        return f"{top}{body}{bottom}"

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
        ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

        def strip_ansi(s: str) -> str:
            return ANSI_RE.sub("", s)

        # Prepare lines, but compute visible width using wcswidth()
        raw_lines = text.splitlines()
        stripped_lines = [strip_ansi(ln).expandtabs(4) for ln in raw_lines]

        # Display width in terminal cells (handles emoji, combining marks, etc.)
        def cell_width(s: str) -> int:
            # wcswidth returns -1 if it encounters a nonprintable; treat as 0
            w = wcswidth(s)
            return 0 if w < 0 else w

        visible_widths = [cell_width(ln) for ln in stripped_lines]
        inner_width = (max(visible_widths) if visible_widths else 0) + 2  # your padding

        # Title line (measure width without ANSI, but print the original)
        stripped_title = strip_ansi(title)
        title_w = cell_width(stripped_title)
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        top = (
            f"┌{'─' * inner_width}┐\n"
            f"│{' ' * pad_left}{title}{' ' * pad_right}│\n"
            f"├{'─' * inner_width}┤\n"
        )

        # Body lines: pad by display width, not codepoint length
        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = inner_width - cell_width(stripped)
            pad = max(pad, 0)
            body_parts.append(f"│{raw}{' ' * pad}│")
        body = "\n".join(body_parts)

        bottom = f"\n└{'─' * inner_width}┘"
        return f"{top}{body}{bottom}"

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
    def mark_tool_used(cls, tool_name: str, files: list = None):
        """Mark a tool as used and optionally track its output files.

        Args:
            tool_name: Name of the tool (e.g., 'fritap', 'network', 'dexray-intercept')
            files: Optional list of file paths generated by this tool
        """
        if tool_name not in cls._tools_used:
            cls._tools_used[tool_name] = {"used": True, "files": []}
        if files:
            cls._tools_used[tool_name]["files"].extend(files)

    @classmethod
    def get_tools_used(cls) -> dict:
        """Return dictionary of tools used during this session.

        Returns:
            Dictionary mapping tool names to their usage info and generated files
        """
        return cls._tools_used

    # ==================== Background Task Management ====================

    @classmethod
    def register_background_task(
        cls,
        name: str,
        display_name: str,
        instance: object,
        stop_callback: Callable,
        started_by: str = None,
        app_name: str = None,
        target_pid: int = None,
    ):
        """Register a new background task.

        Args:
            name: Internal task identifier (e.g., "fritap", "dexray-intercept")
            display_name: User-friendly name (e.g., "FriTap", "Dexray-Intercept")
            instance: The actual tool instance
            stop_callback: Function to call when stopping the task
            started_by: Name of task that started this one (for dependency tracking)
            app_name: Target application package name (if applicable)
            target_pid: Target process PID (if applicable)
        """
        cls._background_tasks[name] = BackgroundTask(
            name=name,
            display_name=display_name,
            instance=instance,
            stop_callback=stop_callback,
            started_at=datetime.datetime.now(),
            started_by=started_by,
            app_name=app_name,
            target_pid=target_pid,
        )
        cls.logger.info(f"Background task '{display_name}' registered")

        # Emit event for task started
        try:
            from sandroid.core.events import Event, EventBus, EventType

            EventBus.get().publish(
                Event(
                    type=EventType.TASK_STARTED,
                    data={
                        "name": name,
                        "display_name": display_name,
                        "app_name": app_name,
                        "target_pid": target_pid,
                    },
                    source="toolbox",
                )
            )
        except ImportError:
            pass  # Events module not available

    @classmethod
    def unregister_background_task(cls, name: str):
        """Remove a task from tracking (after it's stopped).

        Args:
            name: Internal task identifier to remove
        """
        if name in cls._background_tasks:
            task = cls._background_tasks[name]
            del cls._background_tasks[name]
            cls.logger.info(f"Background task '{task.display_name}' unregistered")

            # Emit event for task stopped
            try:
                from sandroid.core.events import Event, EventBus, EventType

                EventBus.get().publish(
                    Event(
                        type=EventType.TASK_STOPPED,
                        data={
                            "name": name,
                            "display_name": task.display_name,
                            "app_name": task.app_name,
                        },
                        source="toolbox",
                    )
                )
            except ImportError:
                pass  # Events module not available

    @classmethod
    def is_task_running(cls, name: str) -> bool:
        """Check if a specific task is running.

        Args:
            name: Internal task identifier

        Returns:
            True if the task is currently running
        """
        return name in cls._background_tasks

    @classmethod
    def get_running_tasks(cls) -> list[str]:
        """Get list of all running task names.

        Returns:
            List of internal task identifiers for all running tasks
        """
        return list(cls._background_tasks.keys())

    @classmethod
    def get_task(cls, name: str) -> BackgroundTask | None:
        """Get a specific background task by name.

        Args:
            name: Internal task identifier

        Returns:
            BackgroundTask instance or None if not found
        """
        return cls._background_tasks.get(name)

    @classmethod
    def get_tasks_started_by(cls, parent_name: str) -> list[str]:
        """Get tasks that were started by a specific parent task.

        Args:
            parent_name: Name of the parent task

        Returns:
            List of task names that were started by the parent
        """
        return [
            name
            for name, task in cls._background_tasks.items()
            if task.started_by == parent_name
        ]

    @classmethod
    def stop_task(cls, name: str) -> bool:
        """Stop a single task without prompting for dependencies.

        Args:
            name: Internal task identifier

        Returns:
            True if task was stopped successfully
        """
        if name not in cls._background_tasks:
            return False

        task = cls._background_tasks[name]
        console = SandroidConsole.get()

        try:
            task.stop_callback()
            console.print(f"[success]✓ {task.display_name} stopped[/success]")
        except Exception as e:
            cls.logger.error(f"Error stopping {task.display_name}: {e}")

        cls.unregister_background_task(name)
        return True

    @classmethod
    def stop_task_with_prompt(cls, name: str) -> bool:
        """Stop a task and prompt for dependent tasks.

        Args:
            name: Internal task identifier

        Returns:
            True if task was stopped, False if not found
        """
        if name not in cls._background_tasks:
            return False

        task = cls._background_tasks[name]
        console = SandroidConsole.get()

        # Find tasks started by this one
        dependent_tasks = cls.get_tasks_started_by(name)

        # Stop the main task
        try:
            task.stop_callback()
        except Exception as e:
            cls.logger.error(f"Error stopping {task.display_name}: {e}")

        cls.unregister_background_task(name)
        console.print(f"[success]✓ {task.display_name} stopped[/success]")

        # Prompt for dependent tasks
        if dependent_tasks:
            for dep_name in dependent_tasks:
                dep_task = cls._background_tasks.get(dep_name)
                if dep_task:
                    console.print(
                        f"\n[warning]{dep_task.display_name} was started with {task.display_name}.[/warning]"
                    )
                    console.print(
                        f"Stop {dep_task.display_name} too? [primary]\\[Y/n][/primary] ",
                        end="",
                    )

                    choice = click.getchar().lower()
                    console.print(choice)

                    if choice != "n":
                        try:
                            dep_task.stop_callback()
                            cls.unregister_background_task(dep_name)
                            console.print(
                                f"[success]✓ {dep_task.display_name} stopped[/success]"
                            )
                        except Exception as e:
                            cls.logger.error(
                                f"Error stopping {dep_task.display_name}: {e}"
                            )

        return True

    @classmethod
    def stop_all_background_tasks(cls):
        """Stop all running background tasks. Used during cleanup/exit."""
        console = SandroidConsole.get()
        tasks_to_stop = list(cls._background_tasks.keys())

        for name in tasks_to_stop:
            task = cls._background_tasks.get(name)
            if task:
                try:
                    task.stop_callback()
                    console.print(f"[success]✓ {task.display_name} stopped[/success]")
                except Exception as e:
                    cls.logger.error(f"Error stopping {task.display_name}: {e}")
                cls.unregister_background_task(name)

    @classmethod
    def get_background_tasks_status_string(cls) -> str:
        """Get a formatted string showing running background tasks for menu display.

        Returns:
            Formatted string like "● FriTap (PID: 12345) | ● Network Capture" or empty string
        """
        if not cls._background_tasks:
            return ""

        task_parts = []
        for name in cls._background_tasks:
            task = cls._background_tasks[name]
            # Show PID in consistent [warning] color (same as filenames)
            if task.target_pid:
                task_parts.append(
                    f"[success]●[/success] {task.display_name} ([warning]{task.target_pid}[/warning])"
                )
            else:
                task_parts.append(f"[success]●[/success] {task.display_name}")

        return " | ".join(task_parts)

    # ==================== End Background Task Management ====================

    @classmethod
    def print_exit_summary(cls):
        """Print summary of results folder and generated files on exit."""
        console = SandroidConsole.get()
        results_path = os.getenv("RESULTS_PATH", "results/")

        console.print()
        console.print("[bold cyan]═══ Sandroid Session Complete ═══[/bold cyan]")
        console.print()
        console.print(
            f"[success]Results saved to:[/success] [bold]{results_path}[/bold]"
        )

        # List tool-specific files
        if cls._tools_used:
            console.print()
            console.print("[info]Generated files by tool:[/info]")
            for tool_name, tool_info in cls._tools_used.items():
                if tool_info.get("files"):
                    console.print(f"  [accent]{tool_name}:[/accent]")
                    for file_path in tool_info["files"]:
                        # Show relative path from results folder
                        if file_path and os.path.exists(file_path):
                            rel_path = os.path.relpath(file_path, results_path)
                            console.print(f"    • {rel_path}")

        console.print()

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

        action_name = cls.safe_input("Name your action for export: ")

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
                stdin=subprocess.DEVNULL,  # Prevent consuming terminal input
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
