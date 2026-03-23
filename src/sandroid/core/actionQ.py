import json
import os
import time
import warnings

import click

warnings.filterwarnings("ignore", category=ResourceWarning)  # it is what it is

from logging import getLogger

from sandroid.analysis.changedfiles import ChangedFiles
from sandroid.analysis.datagather import DataGather
from sandroid.analysis.deletedfiles import DeletedFiles
from sandroid.analysis.network import Network
from sandroid.analysis.newfiles import NewFiles
from sandroid.analysis.processes import Processes
from sandroid.analysis.sockets import Sockets
from sandroid.core.json_utils import json_encoder as _json_encoder
from sandroid.features.functionality import Functionality

# Screenshot temporarily excluded due to Toolbox.args initialization dependency
from sandroid.features.trigdroid import Trigdroid
from sandroid.services import (
    get_emulator_service,
    get_forensic_service,
    get_frida_session_service,
    get_network_capture_service,
    get_spotlight_service,
    get_task_service,
    get_ui_service,
)

from .adb import Adb
from .console import SandroidConsole


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
        from .toolbox import Toolbox

        args = Toolbox.args

        if args.trigdroid_ccf:
            Trigdroid().run_ccf()

        if args.screenshot:
            # Lazy import to avoid initialization issues
            from sandroid.features.screenshot import Screenshot

            self.photographer = Screenshot()
            self.q.append(self.photographer)

        if args.trigdroid:
            # Initialize SpotlightService with the package from CLI args
            spotlight = get_spotlight_service()
            spotlight.set_spawn_app(args.trigdroid, auto_resume=True)
            self.logger.info(
                f"SpotlightService initialized with package: {args.trigdroid}"
            )

            # Create Trigdroid action and queue it with full analysis pipeline
            action = Trigdroid()

            # Create snapshot first (required by assembleQ_for_runs)
            self.q.append("create_snapshot")

            # Queue the full analysis pipeline
            self.assembleQ_for_runs(action)

            # Remove the "interactive" item that assembleQ_for_runs adds
            # since we're running in automated CLI mode
            if self.q and self.q[-1] == "interactive":
                self.q.pop()

        if args.degrade_network:
            Adb.send_telnet_command("network delay umts")
            Adb.send_telnet_command("network speed umts")
        else:
            Adb.send_telnet_command("network delay none")
            Adb.send_telnet_command("network speed full")

        self.logger.debug("Our schedule for today: " + self.print_q())

        # NOTE: "interactive" is NOT appended here.
        # - Rich mode adds it via _start_rich_interactive_mode()
        # - TUI mode has its own event loop
        # - Automated analysis should NOT have interactive menu

    def assembleQ_for_runs(self, action):
        """Assembles an action queue for a given action.

        The action will be performed multiple times according to the number of runs command line parameter and different attributes on the emulator will be measured
        Usually the action will be a Player object, meaning the recorded inputs of the user are replayed and investigated.

        .. note::
        Those actions will not yet be performed, just queued.

        :param action: The action to be performed and investigated.
        :type action: Functionality
        """
        from .toolbox import Toolbox

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

        # Save results and return to interactive menu after playback
        self.q.append("save_results")
        self.q.append("interactive")

        self.logger.debug("Our schedule for today: " + self.print_q())

    def do_next(self):
        """Executes the next action in the queue."""
        from .toolbox import Toolbox

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
                    from sandroid.services import get_forensic_service

                    forensic = get_forensic_service()
                    forensic.set_baseline(Toolbox.fetch_changed_files(fetch_all=True))
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
                    from sandroid.services import get_forensic_service

                    forensic = get_forensic_service()
                    baseline = forensic.get_baseline()
                    changed_files = Toolbox.fetch_changed_files()
                    for file in changed_files:
                        if file in baseline:
                            Toolbox.pull_file("first", file)
                case "pull1":
                    from sandroid.services import get_forensic_service

                    forensic = get_forensic_service()
                    baseline = forensic.get_baseline()
                    changed_files = Toolbox.fetch_changed_files()
                    for file in changed_files:
                        if file in baseline:
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
                case "save_results":
                    self._save_analysis_results()
                case "interactive":
                    Toolbox.print_interactive_menu()
                    try:
                        char = click.getchar()
                        self.parse_interactive_char(char)
                    except KeyboardInterrupt:
                        console = SandroidConsole.get()
                        console.print("\n[warning]Ctrl+C detected[/warning]")

                        # Check if there are any background tasks running
                        has_background_tasks = bool(get_task_service().get_running())
                        has_network_capture = (
                            get_network_capture_service().is_capturing()
                        )
                        has_screen_recording = get_emulator_service().is_recording()

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
                                        get_task_service().stop_all()
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
                                                get_network_capture_service().stop_capture()
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
                                            get_emulator_service().stop_recording()
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
        from .toolbox import Toolbox

        forensic_service = get_forensic_service()
        data = {
            "Device Name": Toolbox.device_name,
            "Emulator relative action timestamp": forensic_service.get_action_time(),
            "Action Duration": forensic_service.get_action_duration(),
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

    def _save_analysis_results(self):
        """Save current analysis results to output file.

        This is called at the end of playback analysis to save results
        and show a summary before returning to the interactive menu.
        """
        from .toolbox import Toolbox

        try:
            Toolbox.wrap_up()

            # Determine output path
            results_path = os.getenv("RESULTS_PATH", "./")
            output_file = getattr(Toolbox.args, "file", "sandroid.json")
            output_path = os.path.join(results_path, output_file)

            # Ensure directory exists
            os.makedirs(
                os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
                exist_ok=True,
            )

            # Write results
            with open(output_path, "w", encoding="utf-8") as fd:
                fd.write(self.get_data())

            self.logger.info(f"Results saved to: {output_path}")

            # Show summary in Rich mode
            console = SandroidConsole.get()
            console.print("\n[bold #58a6ff]═══ Analysis Summary ═══[/bold #58a6ff]\n")
            console.print(self.get_pretty_print())
            console.print(
                f"\n[success]✓ Results saved to:[/success] [accent]{output_path}[/accent]\n"
            )

            # Pause for user to review
            console.print("[dim]Press any key to return to menu...[/dim]")
            try:
                import click

                click.getchar()
            except (KeyboardInterrupt, EOFError):
                pass

        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def update_photographer(self):
        """Updates the screenshot utility with the current action.

        This allows screenshots to be labeled with the current action
        """
        from .toolbox import Toolbox

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
        # Check if TUI mode is active (skip screen clear and use modals instead of Rich prompts)
        from sandroid.core.ui_request_bus import (
            UIRequestBus,
        )

        from .toolbox import Toolbox

        bus = UIRequestBus.get()
        is_tui_mode = bus.has_active_handler()

        # Only clear screen in Rich mode (TUI manages its own display)
        if not is_tui_mode and Toolbox.args.loglevel != "DEBUG":
            os.system(  # nosec S605 # Safe terminal clear command
                "cls" if os.name == "nt" else "clear"
            )  # Just to keep everything nice and clean

        # Check if char is a digit between 0-8 (Snapshot handling)
        # Delegate to command system for snapshot operations
        if char.isdigit() and 0 <= int(char) <= 8:
            self._execute_snapshot_command(char)
            self.q.append("interactive")
            return

        # Handle TAB key for view switching
        if char == "\t":  # TAB key
            get_ui_service().cycle_view()
            self.q.append("interactive")
            return

        # Import MenuController for key validation and help
        from sandroid.core.menu_controller import MenuController

        # Handle '?' key for help overlay (Rich mode only)
        # TUI mode has its own help screen that's triggered by the app bindings
        if char == "?":
            if is_tui_mode:
                # TUI handles help via its own help screen - just return to interactive
                self.q.append("interactive")
                return

            # Rich mode: Show help using console
            console = SandroidConsole.get()
            controller = MenuController.get()
            current_view = get_ui_service().get_current_view()

            # Print help text using Rich formatting
            help_text = controller.get_help_text(current_view)
            console.print()
            console.print(help_text)
            console.print()
            console.print("[dim]Press any key to return to menu...[/dim]")

            # Wait for key press
            try:
                click.getchar()
            except (KeyboardInterrupt, EOFError):
                pass

            self.q.append("interactive")
            return

        # Validate key based on current view using MenuController
        current_view = get_ui_service().get_current_view()
        controller = MenuController.get()

        # Get action for this key in the current view
        action = controller.get_action_by_key(char, current_view)

        # Special case: 'q' is always valid (quit)
        if char == "q":
            pass  # Allow quit in all views
        elif action is None:
            # Key not found in current view
            get_ui_service().show_blocking_warning(
                title="Key Not Available",
                message=f"Key '{char}' is not available in {current_view.upper()} view.",
                action_hint="Press TAB to switch between views: Forensic → Malware → Security\nPress ? for help or Ctrl+P for command palette",
            )
            self.q.append("interactive")
            return

        # === COMMAND SYSTEM DISPATCH ===
        # Route to new command system if a handler is registered
        # This allows gradual migration while preserving backward compatibility
        from sandroid.core.actionq_commands import (
            execute_command_from_actionq,
            is_command_key,
        )

        if is_command_key(char):
            result = execute_command_from_actionq(self, char)
            if result.should_return_to_menu:
                self.q.append("interactive")
            return

        # === LEGACY FALLBACK ===
        # NOTE: All command keys are now handled by the command system above.
        # This fallback handles any keys that weren't caught by:
        # 1. Special keys (digits 0-8, TAB, ?)
        # 2. Command keys (handled by CommandRegistry)
        # 3. View-based key validation (shows "Key Not Available" warning)
        #
        # If we reach here, it's an unexpected key that passed view validation
        # but isn't in the command system - this shouldn't normally happen.
        self.logger.warning(
            f"Unhandled key '{char}' reached legacy fallback - this shouldn't happen"
        )
        self.q.append("interactive")
        return

    def _execute_snapshot_command(self, char: str) -> None:
        """Execute snapshot command through the command system.

        Delegates snapshot operations (list/load for '0', create for '1'-'8')
        to the SnapshotCommands in the command registry.

        :param char: The digit character ('0'-'8')
        :type char: str
        """
        from .toolbox import Toolbox

        try:
            from sandroid.commands import CommandRegistry
            from sandroid.commands.context_factory import create_context_from_actionq

            # Create command context
            ctx = create_context_from_actionq(action_queue=self, toolbox=Toolbox)

            # Get registry and execute
            registry = CommandRegistry.get()
            if not registry.has(char):
                # Initialize commands if not already done
                registry.initialize_default_commands()

            if registry.has(char):
                # Execute synchronously (async wrapper)
                result = registry.execute_sync(char, ctx)
                if not result.success:
                    self.logger.warning(f"Snapshot command failed: {result.message}")
            else:
                self.logger.warning(f"No snapshot command registered for key '{char}'")
        except Exception as e:
            self.logger.error(f"Error executing snapshot command: {e}")

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
        # Get FridaManager from FridaSessionService
        frida_service = get_frida_session_service()
        frida_manager = frida_service.get_frida_manager()

        # Check if the frida server is running
        if not frida_manager.is_frida_server_running():
            result = get_ui_service().show_blocking_warning(
                title="Frida Server Required",
                message="No Frida server is running. This feature requires Frida to be installed and running.",
                action_hint="Press [f] to install and start Frida server",
                action_key="f",
            )
            if result == "f":
                # User pressed 'f' - install and start Frida
                try:
                    frida_manager.install_frida_server()
                    frida_manager.run_frida_server()
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
        spotlight = get_spotlight_service()
        if spotlight.is_spawn_mode():
            spawn_app = spotlight.get_spawn_package()
            if spawn_app:
                # Spawn mode is set with an app
                return (None, spawn_app)
            get_ui_service().show_blocking_warning(
                title="Spotlight App Required",
                message="Spawn mode is enabled but no spawn application is set.",
                action_hint="Press [Shift+C] to set a spawn application",
            )
            self.q.append("interactive")
            return None

        # Check for attach mode
        spotlight_application = spotlight.get_app_tuple()

        if not spotlight_application:
            get_ui_service().show_blocking_info(
                title="Auto-selecting Spotlight App",
                message="No spotlight application was set. Automatically using the currently focused app.",
                action_hint="To manually select an app, press [c] for ATTACH mode or [Shift+C] for SPAWN mode",
            )
            spotlight.set_app_from_tuple(Adb.get_focused_app())
            spotlight_application_name = spotlight.get_app_tuple()[0]
            spotlight_application_pid = Adb.get_pid_for_package_name(
                spotlight_application_name
            )
            spotlight.set_pid(spotlight_application_pid)

        # Check if a spotlight application is set
        try:
            spotlight_application_pid = spotlight.get_pid()
            spotlight_application_name = spotlight.get_app_tuple()[0]
        except Exception:
            self.q.append("interactive")
            return None

        return (spotlight_application_pid, spotlight_application_name)
