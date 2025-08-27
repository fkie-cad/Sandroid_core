import json
import os
import subprocess
import time
import warnings

import click
from colorama import Fore, Style

warnings.filterwarnings("ignore", category=ResourceWarning)  # it is what it is

from logging import getLogger

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
                        self.logger.info("Exiting program...")
                        self.finished = True
                        exit(0)
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
        return json.dumps(data, indent=4)

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
                    snapshot_list = ""
                    for idx, snapshot in enumerate(snapshots, 1):
                        snapshot_list += f"{Fore.GREEN}{snapshot['date']}{Fore.RESET} - {Fore.CYAN}{snapshot['tag']}{Fore.RESET}\n"

                    # Display snapshots in a nice ASCII box
                    formatted_box = Toolbox._create_ascii_box(
                        snapshot_list.strip(),
                        f"{Fore.MAGENTA}Available Snapshots{Fore.RESET}",
                    )
                    print(f"\n{formatted_box}")

                    # Ask user to select a snapshot
                    selected_idx = 0
                    try:
                        while selected_idx < 1 or selected_idx > len(snapshots):
                            try:
                                self.logger.info(
                                    f"{Fore.CYAN}Select a snapshot to load ({Fore.YELLOW}1{Fore.CYAN}-{Fore.YELLOW}{len(snapshots)}{Fore.CYAN}): {Style.RESET_ALL}"
                                )
                                char = click.getchar()
                                if char.isdigit():
                                    selected_idx = int(char)
                                else:
                                    selected_idx = 0  # Invalid input
                                if selected_idx < 1 or selected_idx > len(snapshots):
                                    self.logger.info(
                                        f"{Fore.RED}Please enter a number between {Fore.YELLOW}1{Fore.RED} and {Fore.YELLOW}{len(snapshots)}{Style.RESET_ALL}"
                                    )
                            except ValueError:
                                self.logger.info(
                                    f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}"
                                )
                    except KeyboardInterrupt:
                        self.logger.info(
                            f"\n{Fore.YELLOW}Snapshot selection cancelled by user.{Style.RESET_ALL}"
                        )
                        self.q.append("interactive")
                        return

                    # Load selected snapshot
                    selected_snapshot = snapshots[selected_idx - 1]["tag"]
                    # Add load snapshot command to the queue
                    Toolbox.load_snapshot(selected_snapshot.encode())
                else:
                    self.logger.warning(
                        f"{Fore.RED}No snapshots available.{Style.RESET_ALL}"
                    )

                self.q.append("interactive")
                return
            # Keys 1-8 for creating snapshots
            # Prompt for snapshot name
            try:
                self.logger.info(
                    f"{Fore.CYAN}Enter snapshot name (or press Enter for timestamp): {Style.RESET_ALL}"
                )
                snapshot_name = input()
                if not snapshot_name:
                    from datetime import datetime

                    snapshot_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

                # Create snapshot
                Toolbox.create_snapshot(snapshot_name.encode())
            except KeyboardInterrupt:
                self.logger.info(
                    f"\n{Fore.YELLOW}Snapshot creation cancelled by user.{Style.RESET_ALL}"
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
                    self.logger.warning(f"File not found on device: {spotlight_file}")
                elif "Permission denied" in str(output):
                    self.logger.error(
                        f"Permission denied when pulling {spotlight_file}"
                    )
                else:
                    self.logger.info(f"Pulled {spotlight_file} to {target_path}")

                # For .db files, also pull WAL and journal files if they exist
                if spotlight_file.endswith(".db") or True:
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
                    filename = input().strip()
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
                        filename = input().strip()

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
                    Toolbox.frida_manager.install_frida_server()
                    Toolbox.frida_manager.run_frida_server()
                self.q.append("interactive")
            case "n":  # New APK installation
                try:
                    self.logger.info("Enter file path of APK or search term:")
                    apk = input().strip()
                    if os.path.isfile(apk):
                        Adb.install_apk(apk)
                    else:
                        self.logger.info(
                            "The path provided is not a valid file. Searching online."
                        )
                        app_id = ApkDownloader().search_for_name(apk)
                        ApkDownloader().install_app_id(app_id)
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "c":
                Toolbox.set_spotlight_application(Adb.get_focused_app())
                spotlight_application_name = Toolbox.get_spotlight_application()[0]
                spotlight_application_pid = Adb.get_pid_for_package_name(
                    spotlight_application_name
                )
                Toolbox.set_spotlight_application_pid(spotlight_application_pid)
                self.q.append("interactive")
            case "a":
                try:
                    apk_name = Toolbox.get_spotlight_application()[0]
                except:
                    self.logger.warning("Spotlight app has to be set first.")
                    self.q.append("interactive")
                    return
                asam = StaticAnalysis()
                asam.gather()
                # asam.pretty_print()
                # Toolbox.submit_other_data("asam", asam.return_data())
                self.q.append("interactive")
            case "m":
                check_frida = self.check_frida_and_spotlight()
                if not check_frida:
                    self.q.append("interactive")
                    return

                spotlight_application_pid, spotlight_application_name = check_frida

                self.logger.info(
                    "Now the dexray-intercept output follows. End with CTRC-C"
                )
                if self.malwaremonitor == None:
                    self.malwaremonitor = MalwareMonitor(
                        path_filters=Toolbox.get_spotlight_files()
                    )
                self.malwaremonitor.gather()

                if self.malwaremonitor.has_new_results():
                    Toolbox.submit_other_data(
                        "Dexray Intercept",
                        self.malwaremonitor.return_data(),
                    )

                try:
                    self.logger.info(
                        "Malware monitoring in progress... Press CTRL+C to stop"
                    )
                    while True:
                        time.sleep(0.5)  # Sleep to reduce CPU usage
                except KeyboardInterrupt:
                    self.logger.info("CTRL-C detected. Stopping malware monitoring.")
                    self.malwaremonitor.gather()
                    # Reset spotlight app info as the app may have been closed
                    Toolbox.reset_spotlight_application()
                self.q.append("interactive")
            case "h":
                try:
                    check_frida = self.check_frida_and_spotlight()
                    if not check_frida:
                        self.q.append("interactive")
                        return

                    spotlight_application_pid, spotlight_application_name = check_frida

                    self.logger.info("Now fritap output follows. End with CTRC-C")
                    fritap = FriTap(spotlight_application_pid)
                    fritap.start()

                    try:
                        self.logger.info(
                            "FriTap monitoring in progress... Press CTRL+C to stop"
                        )
                        while True:
                            time.sleep(0.5)  # Sleep to reduce CPU usage
                    except KeyboardInterrupt:
                        self.logger.info("CTRL-C detected. Stopping FriTap monitoring.")
                        fritap.stop()
                        # Reset spotlight app info as the app may have been closed
                        Toolbox.reset_spotlight_application()
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "d":
                try:
                    check_frida = self.check_frida_and_spotlight()
                    if not check_frida:
                        return

                    spotlight_application_pid, spotlight_application_name = check_frida

                    if spotlight_application_pid:
                        Fridump.dump_memory(
                            spotlight_application_pid, spotlight_application_name
                        )
                    else:
                        self.logger.warning("Spotlight app has to be set first.")
                        self.q.append("interactive")
                        return
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")

            case "o":
                try:
                    FSMon.check_and_install_fsmon()

                    spotlight_data_path = Toolbox.get_spotlighted_app_data_path()
                    spotlight_application_pid = Toolbox.get_spotlight_application_pid()
                    process = None

                    if spotlight_application_pid:
                        self.logger.info(
                            f"Press ENTER to monitor spotlight app (PID: {spotlight_application_pid}) or enter a path to monitor:"
                        )
                        user_input = input().strip()

                        if user_input:
                            process = FSMon.run_fsmon_by_path(user_input)
                        else:
                            process = FSMon.run_fsmon_by_pid(spotlight_application_pid)
                    else:
                        self.logger.info(
                            "No spotlight app is set. Enter a path to monitor:"
                        )
                        user_input = input().strip()

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

                    if user_input:
                        self.logger.info(
                            f"Now fsmon output for path {user_input} follows. End with CTRL-C"
                        )
                    else:
                        self.logger.info(
                            f"Now fsmon output for PID {spotlight_application_pid} follows. End with CTRL-C"
                        )

                    try:
                        while True:
                            pass
                    except KeyboardInterrupt:
                        process.terminate()
                        self.logger.info("CTRL-C detected. Exiting fsmon loop.")
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
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
                    file_path = input().strip()
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
                        file_path = input().strip()
                        Toolbox.remove_spotlight_file(file_path)
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "u":
                try:
                    self.logger.info(
                        "Enter a short description of the action performed (or press ENTER to skip):"
                    )
                    description = input().strip()

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
                    check_frida = self.check_frida_and_spotlight()
                    if not check_frida:
                        return

                    spotlight_application_pid, spotlight_application_name = check_frida

                    self.logger.info(
                        f"Launching objection interactive shell for {spotlight_application_name}"
                    )

                    try:
                        cmd = [
                            "objection",
                            "--gadget",
                            str(spotlight_application_pid),
                            "explore",
                        ]
                        self.logger.info(f"Running command: {' '.join(cmd)}")

                        process = subprocess.Popen(cmd)  # nosec S603 # Launching objection security tool
                        process.communicate()

                        self.logger.info("Objection session ended")
                    except Exception as e:
                        self.logger.error(f"Error launching objection: {e!s}")
                except KeyboardInterrupt:
                    self.logger.info("\nOperation cancelled")
                self.q.append("interactive")
            case "w":
                try:
                    # If a capture is already running, stop it
                    if Toolbox._network_capture_running:
                        self.logger.info(
                            f"Stopping network capture: {Toolbox._network_capture_file}"
                        )
                        if Adb.stop_network_capture():
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
                        user_path = input().strip()

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
        Returns (PID, app_name) if successful.
        """
        # Check if the frida server is running
        if not Toolbox.frida_manager.is_frida_server_running():
            self.logger.warning(
                "No frida server is running. Please start or install it first."
            )
            self.q.append("interactive")
            return None

        spotlight_application = Toolbox.get_spotlight_application()

        if not spotlight_application:
            self.logger.warning(
                "No spotlight application is set. Using the currently focused app."
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
