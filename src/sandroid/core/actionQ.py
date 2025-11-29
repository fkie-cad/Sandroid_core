import json
import os
import subprocess
import time
import warnings
from dataclasses import asdict, is_dataclass

import click

warnings.filterwarnings("ignore", category=ResourceWarning)  # it is what it is

from logging import getLogger


def _json_encoder(obj):
    """Custom JSON encoder for non-serializable objects like NetworkEvent."""
    # Handle Pydantic models (v2)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    # Handle Pydantic models (v1)
    if hasattr(obj, "dict"):
        return obj.dict()
    # Handle dataclasses
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    # Handle objects with __dict__
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    # Handle datetime
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    # Handle bytes
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    # Handle sets
    if isinstance(obj, set):
        return list(obj)
    # Fallback to string representation
    return str(obj)


from sandroid.analysis.changedfiles import ChangedFiles
from sandroid.analysis.datagather import DataGather
from sandroid.analysis.deletedfiles import DeletedFiles
from sandroid.analysis.fritap import FriTap
from sandroid.analysis.malwaremonitor import MalwareMonitor
from sandroid.analysis.network import Network
from sandroid.analysis.newfiles import NewFiles
from sandroid.analysis.processes import Processes
from sandroid.analysis.sockets import Sockets
from sandroid.analysis.static_analysis import StaticAnalysis
from sandroid.features.functionality import Functionality
from sandroid.features.player import Player
from sandroid.features.recorder import Recorder

# Screenshot temporarily excluded due to Toolbox.args initialization dependency
from sandroid.features.trigdroid import Trigdroid

from .adb import Adb
from .apk_downloader import ApkDownloader
from .console import SandroidConsole
from .file_diff import is_sqlite_file
from .fridump import Fridump
from .fsmon import FSMon
from .toolbox import Toolbox


class ActionQ:
    """Manages the action queue for various tasks and functionalities.

    The idea of the action queue is to assemble the complex list of actions that need to be executed beforehand.
    This provides a big picture view and a simple main function that simply steps through the queue.
    """

    index = 0
    q = []
    finished = False
    recently_installed_package = None  # Track the last installed package for spawn mode

    logger = getLogger(__name__)
    photographer = None
    malwaremonitor = None

    def assembleQ(self):
        """Assembles the initial action queue based on provided arguments."""
        args = Toolbox.args

        if args.trigdroid_ccf:
            Trigdroid().run_ccf()

        if args.screenshot:
            # Lazy import to avoid initialization issues
            from sandroid.features.screenshot import Screenshot

            self.photographer = Screenshot()
            self.q.append(self.photographer)

        if args.trigdroid:
            action = Trigdroid()

        if args.degrade_network:
            Adb.send_telnet_command("network delay umts")
            Adb.send_telnet_command("network speed umts")
        else:
            Adb.send_telnet_command("network delay none")
            Adb.send_telnet_command("network speed full")

        self.logger.debug("Our schedule for today: " + self.print_q())

        self.q.append("interactive")

    def assembleQ_for_runs(self, action):
        """Assembles an action queue for a given action.

        The action will be performed multiple times according to the number of runs command line parameter and different attributes on the emulator will be measured
        Usually the action will be a Player object, meaning the recorded inputs of the user are replayed and investigated.

        .. note::
        Those actions will not yet be performed, just queued.

        :param action: The action to be performed and investigated.
        :type action: Functionality
        """
        args = Toolbox.args

        changed_files_object = ChangedFiles()
        new_files_object = NewFiles()
        if args.network:
            network_object = Network()
        if args.show_deleted:
            deleted_files_object = DeletedFiles()
        if args.processes:
            processes_object = Processes()
        if args.sockets:
            sockets_object = Sockets()

        # pre-workout routine
        self.q.append("load_snapshot")
        self.q.append("baseline")

        # assemble first run
        self.q.append(action)  # or action?
        # create datagather objects
        self.q.append(changed_files_object)
        self.q.append(new_files_object)

        if args.show_deleted:
            self.q.append(deleted_files_object)

        self.q.append(
            "load_snapshot"
        )  # load snapshot BEFORE the pull only in the first run. This will give us a "pre action" version of the files and allow for intra file change detection
        self.q.append("pull0")

        # assemble runs in between
        for run_number in range(1, args.number_of_runs):
            if args.network:
                self.q.append(
                    network_object
                )  # Network runs during action, so is started just before
            if args.processes:
                self.q.append(processes_object)
            if args.sockets:
                self.q.append(sockets_object)

            self.q.append(action)
            self.q.append(changed_files_object)
            self.q.append(new_files_object)

            if args.show_deleted:
                self.q.append(deleted_files_object)

            if run_number == 1:
                self.q.append("pull" + str(run_number))

            self.q.append("load_snapshot")

        # assemble dry run
        if not args.avoid_strong_noise_filter:
            self.q.append("init_dry_run")

            if args.network:
                self.q.append(
                    network_object
                )  # Network runs during action, so is started just before
            if args.processes:
                self.q.append(processes_object)
            if args.sockets:
                self.q.append(sockets_object)

            self.q.append("dry_run_sleep")
            self.q.append(changed_files_object)

            self.q.append("pull_dry_run")

        self.logger.debug("Our schedule for today: " + self.print_q())

    def do_next(self):
        """Executes the next action in the queue."""
        if self.index >= len(self.q):
            self.finished = True
            return
        action = self.q[self.index]
        self.index = self.index + 1

        if isinstance(action, Functionality):
            action.perform()
        if isinstance(action, DataGather):
            action.gather()
        if isinstance(action, str):
            match action:
                case "baseline":
                    Toolbox.baseline = Toolbox.fetch_changed_files(fetch_all=True)
                case "create_snapshot":
                    Toolbox.create_snapshot(b"tmp")
                case "load_snapshot":
                    Toolbox.load_snapshot(b"tmp")
                case "create_snapshot_master":
                    Toolbox.create_snapshot(b"master")
                case "load_snapshot_master":
                    Toolbox.load_snapshot(b"master")
                case "reboot":
                    Toolbox.restart_emulator()
                case "pull0":
                    changed_files = Toolbox.fetch_changed_files()
                    for file in changed_files:
                        if file in Toolbox.baseline:
                            Toolbox.pull_file("first", file)
                case "pull1":
                    changed_files = Toolbox.fetch_changed_files()
                    for file in changed_files:
                        if file in Toolbox.baseline:
                            Toolbox.pull_file("second", file)
                case "new_run":
                    self.logger.info(f"Starting run #{Toolbox.get_run_counter()}")
                case "init_dry_run":
                    self.logger.info(
                        "Measuring noise in dry run for "
                        + str(Toolbox.action_duration)
                        + " seconds"
                    )
                    Toolbox.started_dry_run()
                    Toolbox.set_action_time()
                case "dry_run_sleep":
                    # wait for action duration to complete
                    self.logger.debug("Entering sleep")
                    time.sleep(Toolbox.action_duration)
                    self.logger.debug("Waking up")
                case "pull_dry_run":
                    changed_files = Toolbox.fetch_changed_files()
                    for file in changed_files:
                        Toolbox.pull_file("noise", file)
                case "interactive":
                    Toolbox.print_interactive_menu()
                    try:
                        char = click.getchar()
                        self.parse_interactive_char(char)
                    except KeyboardInterrupt:
                        console = SandroidConsole.get()
                        console.print("\n[warning]Ctrl+C detected[/warning]")

                        # Check if there are any background tasks running
                        has_background_tasks = bool(Toolbox._background_tasks)
                        has_network_capture = Toolbox._network_capture_running
                        has_screen_recording = Toolbox._screen_recording_running

                        if (
                            has_background_tasks
                            or has_network_capture
                            or has_screen_recording
                        ):
                            console.print(
                                "[accent]Stop background tasks? [Y/n] (Ctrl+C again to exit):[/accent] ",
                                end="",
                            )
                            try:
                                choice = click.getchar().lower()
                                console.print(choice)

                                if choice != "n":
                                    # Stop all registered background tasks
                                    if has_background_tasks:
                                        console.print(
                                            "[accent]Stopping background tasks...[/accent]"
                                        )
                                        Toolbox.stop_all_background_tasks()
                                        console.print(
                                            "[success]✓ Background tasks stopped[/success]"
                                        )

                                    # Stop network capture if running
                                    if has_network_capture:
                                        try:
                                            console.print(
                                                "[accent]Stopping network capture...[/accent]"
                                            )
                                            if Adb.stop_network_capture():
                                                Toolbox._network_capture_running = False
                                                Toolbox.set_network_capture_path(None)
                                                console.print(
                                                    "[success]✓ Network capture stopped[/success]"
                                                )
                                        except Exception as e:
                                            console.print(
                                                f"[error]✗ Error stopping network capture: {e}[/error]"
                                            )

                                    # Stop screen recording if running
                                    if has_screen_recording:
                                        try:
                                            console.print(
                                                "[accent]Stopping screen recording...[/accent]"
                                            )
                                            Toolbox.stop_screen_recording()
                                            console.print(
                                                "[success]✓ Screen recording stopped[/success]"
                                            )
                                        except Exception as e:
                                            console.print(
                                                f"[error]✗ Error stopping screen recording: {e}[/error]"
                                            )

                                # Return to menu
                                console.print(
                                    "\n[success]Returning to menu...[/success]"
                                )
                                self.q.append("interactive")

                            except KeyboardInterrupt:
                                # Double Ctrl+C = force exit
                                console.print(
                                    "\n[warning]Force exit requested[/warning]"
                                )
                                self.finished = True
                        else:
                            # No background tasks - ask if user wants to exit
                            console.print(
                                "[accent]Exit Sandroid? [Y/n]:[/accent] ", end=""
                            )
                            try:
                                choice = click.getchar().lower()
                                console.print(choice)
                                if choice != "n":
                                    console.print("[success]Exiting...[/success]")
                                    self.finished = True
                                else:
                                    console.print(
                                        "[success]Returning to menu...[/success]"
                                    )
                                    self.q.append("interactive")
                            except KeyboardInterrupt:
                                # Double Ctrl+C = force exit
                                console.print("\n[warning]Force exit[/warning]")
                                self.finished = True
                case _:
                    self.logger.critical("Unknown action in Action Queue: " + action)
                    exit(1)

        self.update_photographer()

        if (
            not isinstance(action, Functionality)
            and not isinstance(action, DataGather)
            and not isinstance(action, str)
        ):
            self.logger.critical(
                "Unable to parse action in Action Queue: " + str(action)
            )
            exit(1)

    def get_pretty_print(self):
        """Returns a pretty-printed string of the results from the data gatherers.

        :returns: Pretty-printed results.
        :rtype: str
        """
        result = ""
        already_looked_at_these = []
        for q_entry in self.q:
            if (
                isinstance(q_entry, DataGather)
                and q_entry not in already_looked_at_these
            ):
                result = result + q_entry.pretty_print()
                already_looked_at_these.append(q_entry)
        return result

    def get_data(self):
        """Collects and returns data from the action queue.

        :returns: Collected data in JSON format.
        :rtype: str
        """
        data = {
            "Device Name": Toolbox.device_name,
            "Emulator relative action timestamp": Toolbox.get_action_time(),
            "Action Duration": Toolbox.get_action_duration(),
        }

        data.update({"Other Data": Toolbox.other_output_data_collector})

        already_looked_at_these = []
        for q_entry in self.q:
            if (
                isinstance(q_entry, DataGather)
                and q_entry not in already_looked_at_these
            ):
                data.update(q_entry.return_data())
                already_looked_at_these.append(q_entry)
        return json.dumps(data, indent=4, default=_json_encoder)

    def update_photographer(self):
        """Updates the screenshot utility with the current action.

        This allows screenshots to be labeled with the current action
        """
        if Toolbox.args.screenshot:
            if self.index >= len(self.q):
                self.photographer.stop()
                return
            if isinstance(self.q[self.index], str):
                current_action = self.q[self.index]
            else:
                current_action = type(self.q[self.index]).__name__

            self.photographer.set_action(current_action)

    def parse_interactive_char(self, char):
        """Parses and handles interactive character input from the menu.

        :param char: The character input from the user.
        :type char: str
        """
        if Toolbox.args.loglevel != "DEBUG":
            os.system(  # nosec S605 # Safe terminal clear command
                "cls" if os.name == "nt" else "clear"
            )  # Just to keep everything nice and clean

        # Check if char is a digit between 0-8
        if char.isdigit() and 0 <= int(char) <= 8:
            if char == "0":  # Show available snapshots
                snapshots = Adb.get_avd_snapshots()
                if snapshots:
                    # Create formatted list of snapshots
                    console = SandroidConsole.get()
                    snapshot_list = ""
                    for idx, snapshot in enumerate(snapshots, 1):
                        snapshot_list += f"[success]{snapshot['date']}[/success] - [primary]{snapshot['tag']}[/primary]\n"

                    # Display snapshots in a Rich panel
                    console.print()
                    SandroidConsole.print_panel(
                        snapshot_list.strip(), title="Available Snapshots"
                    )

                    # Ask user to select a snapshot
                    selected_idx = 0
                    try:
                        while selected_idx < 1 or selected_idx > len(snapshots):
                            try:
                                console.print(
                                    f"[primary]Select a snapshot to load ([accent]1[/accent]-[accent]{len(snapshots)}[/accent]): [/primary]",
                                    end="",
                                )
                                char = click.getchar()
                                if char.isdigit():
                                    selected_idx = int(char)
                                else:
                                    selected_idx = 0  # Invalid input
                                if selected_idx < 1 or selected_idx > len(snapshots):
                                    console.print(
                                        f"[error]Please enter a number between [accent]1[/accent] and [accent]{len(snapshots)}[/accent][/error]"
                                    )
                            except ValueError:
                                console.print(
                                    "[error]Please enter a valid number[/error]"
                                )
                    except KeyboardInterrupt:
                        console.print(
                            "\n[warning]Snapshot selection cancelled by user.[/warning]"
                        )
                        self.q.append("interactive")
                        return

                    # Load selected snapshot
                    selected_snapshot = snapshots[selected_idx - 1]["tag"]
                    # Add load snapshot command to the queue
                    Toolbox.load_snapshot(selected_snapshot.encode())
                else:
                    self.logger.warning("No snapshots available.")

                self.q.append("interactive")
                return
            # Keys 1-8 for creating snapshots
            # Prompt for snapshot name
            console = SandroidConsole.get()
            try:
                console.print(
                    "[primary]Enter snapshot name (or press Enter for timestamp): [/primary]",
                    end="",
                )
                snapshot_name = Toolbox.safe_input()
                if not snapshot_name:
                    from datetime import datetime

                    snapshot_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

                # Create snapshot
                Toolbox.create_snapshot(snapshot_name.encode())
            except KeyboardInterrupt:
                console.print(
                    "\n[warning]Snapshot creation cancelled by user.[/warning]"
                )

            self.q.append("interactive")
            return

        # Handle TAB key for view switching
        if char == "\t":  # TAB key
            Toolbox.cycle_view()
            self.q.append("interactive")
            return

        # Validate key based on current view
        current_view = Toolbox.get_current_view()

        # Define allowed keys for each view
        forensic_keys = {
            "r",
            "p",
            "x",
            "i",
            "c",
            "C",
            "d",
            "l",
            "v",
            "u",
            "o",
            " ",
            "e",
            "s",
            "g",
            "n",
            "f",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "y",
            "w",
            "q",
        }
        malware_keys = {
            "r",
            "p",
            "x",
            "i",
            "c",
            "C",
            "M",
            "m",
            "b",
            "t",
            "k",
            "e",
            "s",
            "g",
            "n",
            "f",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "y",
            "w",
            "h",
            "q",
        }
        security_keys = {"c", "C", "n", "a", "e", "f", "q"}

        # Check if key is valid for current view
        valid_keys = []
        if current_view == "forensic":
            valid_keys = forensic_keys
        elif current_view == "malware":
            valid_keys = malware_keys
        elif current_view == "security":
            valid_keys = security_keys

        if char not in valid_keys:
            Toolbox.show_blocking_warning(
                title="Key Not Available",
                message=f"Key '{char}' is not available in {current_view.upper()} view.",
                action_hint="Press TAB to switch between views: Forensic → Malware → Security",
            )
            self.q.append("interactive")
            return

        # Original match/case statement continues here
        match char:
            case " ":
                # Check if a spotlight file is set
                spotlight_files = Toolbox.get_spotlight_files()
                if not spotlight_files or len(spotlight_files) != 1:
                    self.logger.warning(
                        "Exactly one spotlight file must be set to use this functionality."
                    )
                    self.q.append("interactive")
                    return

                spotlight_file = spotlight_files[0]
                print(spotlight_file)
                wal_file = spotlight_file + "-wal"
                journal_file = spotlight_file + "-journal"

                target_dir = os.getenv("RESULTS_PATH") + "spotlight_files"

                # If the spotlight file path changed, reset previous pulls
                if (
                    hasattr(Toolbox, "_spotlight_last_file")
                    and Toolbox._spotlight_last_file != spotlight_file
                ):
                    self.logger.info(
                        "Spotlight file changed. Resetting previous versions."
                    )
                    Toolbox._spotlight_pull_one = None
                    Toolbox._spotlight_pull_two = None

                Toolbox._spotlight_last_file = spotlight_file

                # Rotate the versions
                if Toolbox._spotlight_pull_one and Toolbox._spotlight_pull_two:
                    Toolbox._spotlight_pull_one = Toolbox._spotlight_pull_two
                    Toolbox._spotlight_pull_two = None

                # Generate timestamp
                timestamp = str(int(time.time()))

                # Determine target path
                if not Toolbox._spotlight_pull_one:
                    target_path = os.path.join(
                        target_dir, f"{os.path.basename(spotlight_file)}_{timestamp}"
                    )
                    Toolbox._spotlight_pull_one = target_path
                else:
                    target_path = os.path.join(
                        target_dir, f"{os.path.basename(spotlight_file)}_{timestamp}"
                    )
                    Toolbox._spotlight_pull_two = target_path

                # Pull the file from the device
                output, error = Adb.send_adb_command(
                    f"pull {spotlight_file} {target_path}"
                )

                if "failed to stat remote object" in str(
                    output
                ) or "failed to stat remote object" in str(error):
                    Toolbox.show_blocking_warning(
                        title="File Not Found",
                        message=f"The spotlight file does not exist on the device:\n{spotlight_file}",
                        action_hint="Check if the file path is correct or if the app has created the file yet",
                    )
                elif "Permission denied" in str(output):
                    Toolbox.show_blocking_error(
                        title="Permission Denied",
                        message=f"Cannot pull file due to permission restrictions:\n{spotlight_file}",
                        action_hint="The file may be in a protected directory. Try running as root or accessing a different location.",
                    )
                else:
                    self.logger.info(f"Pulled {spotlight_file} to {target_path}")

                # For SQLite database files, also pull WAL and journal files if they exist
                if is_sqlite_file(target_path):
                    # Pull the WAL file
                    wal_target = target_path + "-wal"
                    output, error = Adb.send_adb_command(
                        f"pull {wal_file} {wal_target}"
                    )
                    if (
                        "failed to stat remote object" not in str(output)
                        and "Permission denied" not in str(output)
                        and "failed to stat remote object" not in str(error)
                        and "Permission denied" not in str(error)
                    ):
                        self.logger.info(f"Pulled WAL file: {wal_file}")

                    # Pull the journal file
                    journal_target = target_path + "-journal"
                    output, error = Adb.send_adb_command(
                        f"pull {journal_file} {journal_target}"
                    )
                    if (
                        "failed to stat remote object" not in str(output)
                        and "Permission denied" not in str(output)
                        and "failed to stat remote object" not in str(error)
                        and "Permission denied" not in str(error)
                    ):
                        self.logger.info(f"Pulled journal file: {journal_file}")
                        self.logger.info(
                            f"Pull completed for {spotlight_file} and its associated files."
                        )

                if Toolbox._spotlight_pull_one and Toolbox._spotlight_pull_two:
                    # Perform diff
                    from .file_diff import db_diff

                    self.logger.info(
                        f"Performing diff on spotlight files using paths {Toolbox._spotlight_pull_one} and {Toolbox._spotlight_pull_two}"
                    )
                    diff_result = db_diff(
                        Toolbox._spotlight_pull_one, Toolbox._spotlight_pull_two
                    )
                    self.logger.info("Diff result:")
                    print(diff_result)

                self.q.append("interactive")
                return

            case "s":
                try:
                    self.logger.info(
                        "Enter filename for screenshot (or press ENTER for timestamp):"
                    )
                    filename = Toolbox.safe_input()
                    Toolbox.take_screenshot(filename if filename else None)
                except KeyboardInterrupt:
                    self.logger.info("\nScreenshot cancelled")
                self.q.append("interactive")
            case "g":
                if Toolbox._screen_recording_running:
                    # Stop the recording
                    if Toolbox.stop_screen_recording():
                        self.logger.info("Screen recording stopped successfully")
                    else:
                        self.logger.error("Failed to stop screen recording")
                else:
                    # Ask for a filename
                    try:
                        self.logger.info(
                            "Enter filename for screen recording (or press ENTER for timestamp):"
                        )
                        filename = Toolbox.safe_input()

                        # Start the recording
                        if Toolbox.start_screen_recording(
                            filename if filename else None
                        ):
                            self.logger.info("Press 'g' again to stop the recording")
                        else:
                            self.logger.error("Failed to start screen recording")

                    except KeyboardInterrupt:
                        self.logger.info("\nScreen recording cancelled")

                self.q.append("interactive")
            case "r":
                self.q.append("create_snapshot")
                self.q.append(Recorder())
                self.q.append("interactive")
            case "p":
                self.assembleQ_for_runs(Player())
            case "t":
                self.q.append("create_snapshot")
                trigdroid_object = Trigdroid()
                self.assembleQ_for_runs(trigdroid_object)
            case "f":
                if not Toolbox.frida_manager.is_frida_server_running():
                    try:
                        Toolbox.frida_manager.install_frida_server()
                        Toolbox.frida_manager.run_frida_server()
                        self.q.append("interactive")
                    except Exception as e:
                        self.logger.error(f"Error starting frida server: {e!s}")
                        self.q.append("interactive")
                else:
                    Toolbox.show_blocking_info(
                        title="Frida Already Running",
                        message="Frida server is already running on the device.",
                        action_hint="No action needed - Frida is ready to use",
                    )
                    self.q.append("interactive")
            case "n":  # New APK installation
                try:
                    self.logger.info("Enter file path of APK or search term:")
                    apk = Toolbox.safe_input()

                    installed_package = None  # Track the installed package name

                    # Expand user path (~) and convert to absolute path
                    expanded_apk_path = os.path.abspath(os.path.expanduser(apk))

                    if os.path.isfile(expanded_apk_path):
                        self.logger.info(f"Found local APK file: {expanded_apk_path}")
                        installed_package = Adb.install_apk(expanded_apk_path)
                        if installed_package:
                            self.logger.info(
                                f"APK installation completed successfully: {installed_package}"
                            )
                        else:
                            self.logger.info(
                                "APK installation completed, but package name could not be determined"
                            )
                    else:
                        self.logger.info(
                            f"The path '{apk}' is not a valid file. Searching online for package."
                        )
                        try:
                            app_id = ApkDownloader().search_for_name(apk)
                            ApkDownloader().install_app_id(app_id)
                            installed_package = app_id  # Online installers typically return package name
                            self.logger.info(
                                "Online APK installation completed successfully"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"Online APK search/installation failed: {e}"
                            )
                            self.logger.info(
                                "Please check the search term or try a different APK"
                            )

                    # Offer to set as spotlight spawn app
                    if installed_package:
                        # Store as recently installed for later use
                        ActionQ.recently_installed_package = installed_package
                        console = SandroidConsole.get()

                        console.print(
                            f"\n[success]✓ Successfully installed: [accent]{installed_package}[/accent][/success]"
                        )
                        console.print(
                            "\n[primary]Would you like to set this app for spawning?[/primary]"
                        )
                        console.print(
                            "[accent]\\[y][/accent] = Yes, set as spotlight spawn app"
                        )
                        console.print("[accent]\\[n][/accent] = No, return to menu")

                        try:
                            choice = click.getchar().lower()
                            if choice == "y":
                                Toolbox.set_spotlight_spawn_application(
                                    installed_package
                                )

                                # Ask about auto-resume
                                console.print(
                                    "\n[primary]Auto-resume spawned app?[/primary]"
                                )
                                console.print(
                                    "[accent]\\[y][/accent] = App starts immediately after spawn (recommended, default)"
                                )
                                console.print(
                                    "[accent]\\[n][/accent] = App stays paused, resume manually"
                                )
                                console.print(
                                    "\n[success]► Press y or n (Enter = yes):[/success] ",
                                    end="",
                                )

                                resume_choice = click.getchar().lower()
                                # Default to 'y' if Enter is pressed
                                Toolbox.set_auto_resume_after_spawn(
                                    resume_choice
                                    != "n"  # Anything except 'n' means yes (including Enter)
                                )

                                resume_status = (
                                    "enabled" if resume_choice != "n" else "disabled"
                                )
                                console.print(
                                    f"\n[success]✓ Spotlight app configured:[/success]\n"
                                    f"  Package: [accent]{installed_package}[/accent]\n"
                                    f"  Mode: [primary]SPAWN[/primary]\n"
                                    f"  Auto-resume: [accent]{resume_status}[/accent]\n"
                                )
                            else:
                                self.logger.info("Returning to menu...")
                        except (KeyboardInterrupt, EOFError):
                            self.logger.info("\nReturning to menu...")

                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                except Exception as e:
                    self.logger.error(
                        f"APK installation failed with unexpected error: {e}"
                    )
                    self.logger.info("Please check the file path or try again")
                self.q.append("interactive")
            case "c":
                # ATTACH MODE: Set currently focused app as spotlight (existing behavior)
                Toolbox.set_spotlight_application(Adb.get_focused_app())
                spotlight_application_name = Toolbox.get_spotlight_application()[0]
                spotlight_application_pid = Adb.get_pid_for_package_name(
                    spotlight_application_name
                )
                Toolbox.set_spotlight_application_pid(spotlight_application_pid)
                Toolbox.set_spawn_mode(False)  # Ensure attach mode
                console = SandroidConsole.get()
                console.print(
                    f"[success]Spotlight app set in ATTACH mode: {spotlight_application_name}[/success]"
                )
                self.q.append("interactive")
            case "C":
                # SPAWN MODE: Select app to spawn with fuzzy search
                console = SandroidConsole.get()
                try:
                    console.print(
                        "\n[menu.section]=== Spawn Mode Selection ===[/menu.section]"
                    )
                    console.print(
                        "Select an application to spawn when using Frida-based tools.\n"
                        "The app will be launched fresh with hooks active from the start.\n"
                    )

                    # Use fuzzy search to select app (with recently installed as default)
                    selected_package = Toolbox.select_app_with_fuzzy_search(
                        recently_installed_package=ActionQ.recently_installed_package
                    )

                    if selected_package:
                        Toolbox.set_spotlight_spawn_application(selected_package)

                        # Ask about auto-resume preference with clear prompt
                        console.print(
                            "\n[menu.section]=== Auto-Resume Configuration ===[/menu.section]"
                        )
                        console.print(
                            "[accent]\\[y][/accent] = App starts immediately after spawn (recommended, default)"
                        )
                        console.print(
                            "[accent]\\[n][/accent] = App stays paused, resume manually"
                        )
                        console.print(
                            "\n[success]► Press y or n (Enter = yes):[/success] ",
                            end="",
                        )

                        resume_choice = click.getchar().lower()
                        console.print(
                            f"[accent]{resume_choice}[/accent]"
                        )  # Echo the choice
                        # Default to 'y' if Enter is pressed
                        Toolbox.set_auto_resume_after_spawn(resume_choice != "n")

                        resume_status = (
                            "enabled" if resume_choice != "n" else "disabled"
                        )
                        console.print(
                            f"\n[success]✓ Spotlight app configured:[/success]\n"
                            f"  Package: [accent]{selected_package}[/accent]\n"
                            f"  Mode: [primary]SPAWN[/primary]\n"
                            f"  Auto-resume: [accent]{resume_status}[/accent]\n"
                        )
                    else:
                        self.logger.info("Spawn mode selection cancelled")

                except KeyboardInterrupt:
                    self.logger.info("\nSpawn mode selection cancelled by user")
                except Exception as e:
                    self.logger.error(f"Error setting spawn mode: {e}")

                self.q.append("interactive")
            case "a":
                try:
                    # Check if spotlight app is set
                    spotlight_app = Toolbox.get_spotlight_application()
                    if spotlight_app is None:
                        if Toolbox._spawn_mode and Toolbox._spotlight_spawn_application:
                            package_name = Toolbox._spotlight_spawn_application
                        else:
                            Toolbox.show_blocking_error(
                                title="Spotlight App Required",
                                message="You need to set a spotlight application before running static analysis.",
                                action_hint="Press [c] for ATTACH mode or [Shift+C] for SPAWN mode",
                            )
                            self.q.append("interactive")
                            return
                    else:
                        package_name = spotlight_app[0]

                    # Get the APK path from the device
                    self.logger.info(f"Pulling APK for {package_name}...")
                    stdout, stderr = Adb.send_adb_command(
                        f"shell pm path {package_name}"
                    )

                    if not stdout or "package:" not in stdout:
                        self.logger.error(f"Could not find APK path for {package_name}")
                        self.q.append("interactive")
                        return

                    # Extract the APK path (format is "package:/path/to/apk")
                    apk_path = stdout.strip().replace("package:", "")

                    # Pull the APK to a temporary location
                    import tempfile

                    temp_dir = tempfile.gettempdir()
                    local_apk_path = os.path.join(temp_dir, f"{package_name}.apk")

                    self.logger.info("Downloading APK from device...")
                    stdout, stderr = Adb.send_adb_command(
                        f"pull {apk_path} {local_apk_path}"
                    )

                    if stderr and "error" in stderr.lower():
                        self.logger.error(f"Failed to pull APK: {stderr}")
                        self.q.append("interactive")
                        return

                    self.logger.info(f"APK saved to: {local_apk_path}")

                    # Run static analysis with interactive menu
                    static_analysis = StaticAnalysis()
                    if not static_analysis.gather(interactive=True):
                        # User cancelled from interactive menu
                        self.q.append("interactive")
                        return
                    # static_analysis.pretty_print()
                    # Toolbox.submit_other_data("static_analysis", static_analysis.return_data())

                except Exception as e:
                    self.logger.error(f"Error during static analysis: {e}")

                self.q.append("interactive")
            case "m":
                try:
                    if Toolbox.is_task_running("dexray-intercept"):
                        # STOP Dexray-Intercept
                        Toolbox.stop_task_with_prompt("dexray-intercept")

                        # Collect results if available
                        if (
                            self.malwaremonitor
                            and self.malwaremonitor.has_new_results()
                        ):
                            Toolbox.submit_other_data(
                                "Dexray Intercept",
                                self.malwaremonitor.return_data(),
                            )

                        # Reset spotlight app info as the app may have been closed
                        Toolbox.reset_spotlight_application()
                    else:
                        # START Dexray-Intercept
                        # Ensure spotlight app is set (prompts user if not)
                        if not Toolbox.ensure_spotlight_app_for_tools(
                            "Dexray-Intercept"
                        ):
                            self.q.append("interactive")
                            return

                        check_frida = self.check_frida_and_spotlight()
                        if not check_frida:
                            self.q.append("interactive")
                            return

                        spotlight_application_pid, spotlight_application_name = (
                            check_frida
                        )

                        # Get debug mode from Toolbox args (set by CLI --debug flag)
                        debug_mode = getattr(Toolbox.args, "debug", False)

                        self.malwaremonitor = MalwareMonitor(
                            path_filters=Toolbox.get_spotlight_files(),
                            debug_mode=debug_mode,
                        )

                        # Start monitoring (non-blocking)
                        if self.malwaremonitor.start_monitoring():
                            # Register as background task with PID
                            Toolbox.register_background_task(
                                name="dexray-intercept",
                                display_name="Dexray-Intercept",
                                instance=self.malwaremonitor,
                                stop_callback=self.malwaremonitor.stop_monitoring,
                                app_name=spotlight_application_name,
                                target_pid=spotlight_application_pid,
                            )

                            self.logger.info(
                                "Dexray-Intercept started in background. Press 'm' again to stop."
                            )
                        # else: user cancelled from interactive menu

                except Exception as e:
                    self.logger.error(f"Error managing Dexray-Intercept: {e}")

                self.q.append("interactive")  # Always return to menu
            case "k":
                # Reconfigure hooks (only available when dexray-intercept is running)
                try:
                    if Toolbox.is_task_running("dexray-intercept"):
                        console = SandroidConsole.get()
                        console.print(
                            "\n[primary]Reconfiguring dexray-intercept hooks...[/primary]"
                        )

                        # Get current malwaremonitor instance
                        dexray_task = Toolbox.get_task("dexray-intercept")
                        if dexray_task and dexray_task.instance:
                            current_monitor = dexray_task.instance
                            current_app = dexray_task.app_name

                            # Stop current monitoring (use stop_task for silent stop)
                            console.print(
                                "[accent]Stopping current monitoring...[/accent]"
                            )
                            Toolbox.stop_task("dexray-intercept")

                            # Get debug mode from Toolbox args
                            debug_mode = getattr(Toolbox.args, "debug", False)

                            # Create new malwaremonitor with interactive config
                            console.print(
                                "[accent]Please configure new hook settings...[/accent]"
                            )
                            self.malwaremonitor = MalwareMonitor(
                                path_filters=Toolbox.get_spotlight_files(),
                                debug_mode=debug_mode,
                            )

                            # Start monitoring (will show config menu)
                            if self.malwaremonitor.start_monitoring():
                                # Get spotlight info for registration
                                check_frida = self.check_frida_and_spotlight()
                                if check_frida:
                                    (
                                        spotlight_application_pid,
                                        spotlight_application_name,
                                    ) = check_frida

                                    # Register as background task
                                    Toolbox.register_background_task(
                                        name="dexray-intercept",
                                        display_name="Dexray-Intercept",
                                        instance=self.malwaremonitor,
                                        stop_callback=self.malwaremonitor.stop_monitoring,
                                        app_name=spotlight_application_name,
                                        target_pid=spotlight_application_pid,
                                    )
                                    console.print(
                                        "[success]Hooks reconfigured and monitoring restarted.[/success]"
                                    )
                                else:
                                    console.print(
                                        "[error]Failed to get spotlight app info.[/error]"
                                    )
                    else:
                        console = SandroidConsole.get()
                        console.print(
                            "[warning]Dexray-intercept is not running. Start it first with 'm'.[/warning]"
                        )

                except Exception as e:
                    self.logger.error(f"Error reconfiguring hooks: {e}")

                self.q.append("interactive")
            case "h":
                try:
                    if Toolbox.is_task_running("fritap"):
                        # STOP FriTap with dependency prompt
                        Toolbox.stop_task_with_prompt("fritap")
                        # Reset spotlight app info if spawned
                        if Toolbox.is_spawn_mode():
                            Toolbox.reset_spotlight_application()
                    else:
                        # START FriTap
                        # Check Frida is running
                        if not Toolbox.frida_manager.is_frida_server_running():
                            result = Toolbox.show_blocking_warning(
                                title="Frida Server Required",
                                message="No Frida server is running. This feature requires Frida to be installed and running.",
                                action_hint="Press [f] to install and start Frida server",
                                action_key="f",
                            )
                            if result == "f":
                                # User pressed 'f' - install and start Frida
                                try:
                                    Toolbox.frida_manager.install_frida_server()
                                    Toolbox.frida_manager.run_frida_server()
                                    # Don't return - let the feature continue to execute
                                except Exception as e:
                                    self.logger.error(
                                        f"Error starting frida server: {e!s}"
                                    )
                                    self.q.append("interactive")
                                    return
                            else:
                                # User pressed Enter - return to menu
                                self.q.append("interactive")
                                return

                        # Ensure spotlight app is set (prompts user if not)
                        if not Toolbox.ensure_spotlight_app_for_tools("FriTap"):
                            self.q.append("interactive")
                            return

                        # FriTap now handles both spawn/attach internally with interactive menu
                        fritap = FriTap()  # No args needed, uses unified session getter
                        if fritap.start(interactive=True):
                            self.logger.info(
                                "FriTap started in background. Press 'h' again to stop."
                            )
                        # else: user cancelled from interactive menu

                except Exception as e:
                    self.logger.error(f"Error managing FriTap: {e!s}")

                self.q.append("interactive")  # Always return to menu
            case "d":
                try:
                    # Check Frida is running
                    if not Toolbox.frida_manager.is_frida_server_running():
                        result = Toolbox.show_blocking_warning(
                            title="Frida Server Required",
                            message="No Frida server is running. This feature requires Frida to be installed and running.",
                            action_hint="Press [f] to install and start Frida server",
                            action_key="f",
                        )
                        if result == "f":
                            # User pressed 'f' - install and start Frida
                            try:
                                Toolbox.frida_manager.install_frida_server()
                                Toolbox.frida_manager.run_frida_server()
                                # Don't return - let the feature continue to execute
                            except Exception as e:
                                self.logger.error(f"Error starting frida server: {e!s}")
                                self.q.append("interactive")
                                return
                        else:
                            # User pressed Enter - return to menu
                            self.q.append("interactive")
                            return

                    # Fridump now handles both spawn/attach internally
                    Fridump.dump_memory()  # Uses unified session getter

                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                except Exception as e:
                    self.logger.error(f"Error during memory dump: {e}")
                self.q.append("interactive")

            case "o":
                try:
                    FSMon.check_and_install_fsmon()

                    # Get spotlight info (works with both spawn and attach modes)
                    spotlight_data_path = Toolbox.get_spotlighted_app_data_path()
                    process = None

                    # Try to get PID from current spotlight settings
                    console = SandroidConsole.get()
                    if Toolbox.is_spawn_mode():
                        # In spawn mode, app may not be running yet
                        spawn_app = Toolbox.get_spotlight_spawn_application()
                        if spawn_app:
                            console.print(
                                f"[warning]Spawn mode active for {spawn_app}.[/warning]"
                            )
                            click.echo(
                                "FSMon requires a running process. Options:\n"
                                "  1. Press ENTER to monitor app's data directory\n"
                                "  2. Enter a custom path to monitor"
                            )
                            user_input = Toolbox.safe_input()

                            if user_input:
                                process = FSMon.run_fsmon_by_path(user_input)
                            elif spotlight_data_path:
                                process = FSMon.run_fsmon_by_path(spotlight_data_path)
                            else:
                                self.logger.warning("No valid path available.")
                                self.q.append("interactive")
                                return
                        else:
                            self.logger.info(
                                "No spotlight app set. Enter a path to monitor:"
                            )
                            user_input = Toolbox.safe_input()
                            if user_input:
                                process = FSMon.run_fsmon_by_path(user_input)
                            else:
                                self.logger.warning("No path specified.")
                                self.q.append("interactive")
                                return
                    else:
                        # Attach mode or no mode - try to get PID
                        spotlight_application_pid = (
                            Toolbox.get_spotlight_application_pid()
                        )

                        if spotlight_application_pid:
                            mode_str = (
                                "[success]\\[ATTACH MODE][/success]"
                                if Toolbox.get_spotlight_application()
                                else ""
                            )
                            console.print(
                                f"Press ENTER to monitor spotlight app {mode_str} (PID: {spotlight_application_pid}) or enter a path to monitor:"
                            )
                            user_input = Toolbox.safe_input()

                            if user_input:
                                process = FSMon.run_fsmon_by_path(user_input)
                            else:
                                process = FSMon.run_fsmon_by_pid(
                                    spotlight_application_pid
                                )
                        else:
                            self.logger.info(
                                "No spotlight app is set. Enter a path to monitor:"
                            )
                            user_input = Toolbox.safe_input()

                            if user_input:
                                process = FSMon.run_fsmon_by_path(user_input)
                            else:
                                self.logger.warning(
                                    "No path specified and no spotlight app available."
                                )
                                self.q.append("interactive")
                                return

                    if process is None:
                        self.logger.warning("Failed to start FSMon monitoring.")
                        self.q.append("interactive")
                        return

                    # Determine what we're monitoring for log message
                    if "user_input" in locals() and user_input:
                        monitor_target = f"path {user_input}"
                    elif (
                        "spotlight_application_pid" in locals()
                        and spotlight_application_pid
                    ):
                        monitor_target = f"PID {spotlight_application_pid}"
                    else:
                        monitor_target = f"path {spotlight_data_path}"

                    self.logger.info(
                        f"Now fsmon output for {monitor_target} follows. End with CTRL-C"
                    )

                    while True:
                        pass
                except KeyboardInterrupt:
                    self.logger.info("\nCTRL-C detected. Stopping FSMon monitoring.")
                    if "process" in locals() and process is not None:
                        process.terminate()
                        self.logger.info("FSMon process terminated.")
                self.q.append("interactive")

            case "e":
                Toolbox.print_emulator_information()
                self.q.append("interactive")
            case "x":
                try:
                    Toolbox.export_action()
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "i":
                try:
                    self.logger.info("Feature not yet implemented: Import action")
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "q":
                self.finished = True
            case "l":
                try:
                    spotlight_files = Toolbox.get_spotlight_files()
                    if len(spotlight_files) > 1:
                        self.logger.info("Current spotlight files:")
                        for i, file_path in enumerate(spotlight_files):
                            self.logger.info(f"{i + 1}. {file_path}")
                    self.logger.info(
                        "Enter the file path to add as a spotlight file (or press ENTER to skip):"
                    )
                    file_path = Toolbox.safe_input()
                    if file_path:
                        if file_path.endswith("-wal") or file_path.endswith("-journal"):
                            self.logger.warning(
                                "WAL and journal files are handled automatically with their DB file. Not adding directly."
                            )
                        else:
                            Toolbox.add_spotlight_file(file_path)
                    else:
                        self.logger.warning("File path cannot be empty. No file added.")
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "v":
                try:
                    spotlight_files = Toolbox.get_spotlight_files()
                    if not spotlight_files:
                        self.logger.warning("No spotlight files to remove.")
                    elif len(spotlight_files) == 1:
                        Toolbox.remove_spotlight_file()
                    else:
                        self.logger.info("Current spotlight files:")
                        for i, file_path in enumerate(spotlight_files):
                            self.logger.info(f"{i + 1}. {file_path}")

                        self.logger.info(
                            "Enter the file path to remove from spotlight files:"
                        )
                        file_path = Toolbox.safe_input()
                        Toolbox.remove_spotlight_file(file_path)
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "u":
                try:
                    self.logger.info(
                        "Enter a short description of the action performed (or press ENTER to skip):"
                    )
                    description = Toolbox.safe_input()

                    success = Toolbox.pull_spotlight_files(
                        description=description if description else None
                    )
                    if success:
                        self.logger.info("Spotlight files pulled successfully.")
                    else:
                        self.logger.warning("Failed to pull spotlight files.")
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "y":
                try:
                    Toolbox.set_unset_proxy()
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")

            case "b":
                try:
                    # Check Frida is running
                    if not Toolbox.frida_manager.is_frida_server_running():
                        result = Toolbox.show_blocking_warning(
                            title="Frida Server Required",
                            message="No Frida server is running. This feature requires Frida to be installed and running.",
                            action_hint="Press [f] to install and start Frida server",
                            action_key="f",
                        )
                        if result == "f":
                            # User pressed 'f' - install and start Frida
                            try:
                                Toolbox.frida_manager.install_frida_server()
                                Toolbox.frida_manager.run_frida_server()
                                # Don't return - let the feature continue to execute
                            except Exception as e:
                                self.logger.error(f"Error starting frida server: {e!s}")
                                self.q.append("interactive")
                                return
                        else:
                            # User pressed Enter - return to menu
                            self.q.append("interactive")
                            return

                    # Ensure spotlight app is set (prompts user if not)
                    if not Toolbox.ensure_spotlight_app_for_tools("Objection"):
                        self.q.append("interactive")
                        return

                    # Get session info using unified getter
                    try:
                        session, mode, app_info = (
                            Toolbox.get_frida_session_for_spotlight()
                        )
                        package_name = app_info["package_name"]
                        pid = app_info["pid"]

                        self.logger.info(
                            f"Launching objection interactive shell in {mode.upper()} mode for {package_name}"
                        )

                        # Build objection command based on mode
                        if mode == "spawn":
                            # For spawn mode, objection can handle spawning itself
                            cmd = [
                                "objection",
                                "-g",
                                package_name,
                                "explore",
                                "--startup-command",
                                "android hooking watch class_method *.*",  # Example startup hook
                            ]
                            self.logger.info(
                                f"Note: Objection will spawn a fresh instance of {package_name}"
                            )
                        else:
                            # Attach mode (existing behavior)
                            cmd = [
                                "objection",
                                "--gadget",
                                str(pid),
                                "explore",
                            ]

                        self.logger.info(f"Running command: {' '.join(cmd)}")

                        process = subprocess.Popen(
                            cmd,
                            stdin=subprocess.DEVNULL,  # Prevent consuming terminal input
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )  # nosec S603 # Launching objection security tool
                        process.communicate()

                        self.logger.info("Objection session ended")

                        # Reset spotlight if spawned
                        if mode == "spawn":
                            Toolbox.reset_spotlight_application()

                    except Exception as e:
                        self.logger.error(f"Error getting spotlight session: {e}")

                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                except Exception as e:
                    self.logger.error(f"Error launching objection: {e!s}")
                self.q.append("interactive")
            case "w":
                try:
                    # If a capture is already running, stop it
                    if Toolbox._network_capture_running or Toolbox.is_task_running(
                        "network"
                    ):
                        self.logger.info(
                            f"Stopping network capture: {Toolbox._network_capture_file}"
                        )

                        # If network was registered as background task, stop via that mechanism
                        if Toolbox.is_task_running("network"):
                            Toolbox.stop_task("network")
                        elif Adb.stop_network_capture():
                            self.logger.info("Network capture stopped successfully")
                            Toolbox._network_capture_running = False
                            Toolbox.set_network_capture_path(None)
                        else:
                            self.logger.error("Failed to stop network capture")
                    else:
                        # Ask for destination path
                        self.logger.info(
                            "Enter path for the network capture file (or press ENTER for default):"
                        )
                        user_path = Toolbox.safe_input()

                        # Generate a default filename with timestamp if none provided
                        if not user_path:
                            timestamp = time.strftime("%Y%m%d-%H%M%S")
                            user_path = f"{timestamp}.pcap"
                            self.logger.info(f"Using default filename: {user_path}")

                        # Ensure file has .pcap extension
                        if not user_path.endswith(".pcap"):
                            user_path += ".pcap"

                        # Create network_captures directory if it doesn't exist
                        network_captures_dir = os.path.join(
                            os.getcwd(), "network_captures"
                        )
                        if not os.path.exists(network_captures_dir):
                            os.makedirs(network_captures_dir)
                            self.logger.info(
                                f"Created directory: {network_captures_dir}"
                            )

                        # Combine path and filename
                        user_path = os.path.join(
                            network_captures_dir, os.path.basename(user_path)
                        )
                        self.logger.info(
                            f"Network capture will be saved to: {user_path}"
                        )
                        # Start the capture
                        if Adb.start_network_capture(user_path):
                            Toolbox._network_capture_running = True
                            Toolbox.set_network_capture_path(user_path)
                            self.logger.info(f"Network capture started: {user_path}")
                            self.logger.info("Press 'w' again to stop the capture")
                        else:
                            self.logger.error("Failed to start network capture")

                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case _:
                print(f"Invalid key: {char}.")
                self.q.append("interactive")

    def print_q(self):
        """Returns a string representation of the action queue.

        :returns: String representation of the action queue.
        :rtype: str
        """
        result = ""
        for i in range(len(self.q)):
            if isinstance(self.q[i], str):
                result += self.q[i]
            else:
                result += type(self.q[i]).__name__
            result += ", "
        return result[:-2]

    def check_frida_and_spotlight(self):
        """Checks if the frida server is running and if a spotlight application is set.
        Appends 'interactive' and returns None if the check fails.
        Returns (PID, app_name) if successful (for attach mode) or (None, package_name) for spawn mode.
        """
        # Check if the frida server is running
        if not Toolbox.frida_manager.is_frida_server_running():
            result = Toolbox.show_blocking_warning(
                title="Frida Server Required",
                message="No Frida server is running. This feature requires Frida to be installed and running.",
                action_hint="Press [f] to install and start Frida server",
                action_key="f",
            )
            if result == "f":
                # User pressed 'f' - install and start Frida
                try:
                    Toolbox.frida_manager.install_frida_server()
                    Toolbox.frida_manager.run_frida_server()
                    # Continue with the check - don't return None
                except Exception as e:
                    self.logger.error(f"Error starting frida server: {e!s}")
                    self.q.append("interactive")
                    return None
            else:
                # User pressed Enter - return to menu
                self.q.append("interactive")
                return None

        # Check for spawn mode first
        if Toolbox.is_spawn_mode():
            spawn_app = Toolbox.get_spotlight_spawn_application()
            if spawn_app:
                # Spawn mode is set with an app
                return (None, spawn_app)
            Toolbox.show_blocking_warning(
                title="Spotlight App Required",
                message="Spawn mode is enabled but no spawn application is set.",
                action_hint="Press [Shift+C] to set a spawn application",
            )
            self.q.append("interactive")
            return None

        # Check for attach mode
        spotlight_application = Toolbox.get_spotlight_application()

        if not spotlight_application:
            Toolbox.show_blocking_info(
                title="Auto-selecting Spotlight App",
                message="No spotlight application was set. Automatically using the currently focused app.",
                action_hint="To manually select an app, press [c] for ATTACH mode or [Shift+C] for SPAWN mode",
            )
            Toolbox.set_spotlight_application(Adb.get_focused_app())
            spotlight_application_name = Toolbox.get_spotlight_application()[0]
            spotlight_application_pid = Adb.get_pid_for_package_name(
                spotlight_application_name
            )
            Toolbox.set_spotlight_application_pid(spotlight_application_pid)

        # Check if a spotlight application is set
        try:
            spotlight_application_pid = Toolbox.get_spotlight_application_pid()
            spotlight_application_name = Toolbox.get_spotlight_application()[0]
        except:
            self.q.append("interactive")
            return None

        return (spotlight_application_pid, spotlight_application_name)
