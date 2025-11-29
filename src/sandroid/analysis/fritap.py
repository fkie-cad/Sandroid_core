import logging
import os

import click
from friTap import SSL_Logger

from sandroid.core.console import SandroidConsole
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

logger = logging.getLogger(__name__)


# Set up dedicated fritap log file
def _setup_fritap_logging():
    """Set up dedicated file logging for friTap in the fritap results folder."""
    fritap_logger = logging.getLogger("friTap")

    # Check if we already have a file handler to avoid duplicates
    has_file_handler = any(
        isinstance(handler, logging.FileHandler) for handler in fritap_logger.handlers
    )

    if not has_file_handler and os.getenv("RESULTS_PATH"):
        fritap_dir = f"{os.getenv('RESULTS_PATH')}fritap/"
        log_path = f"{fritap_dir}fritap.log"
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s~%(levelname)s~%(message)s~module:%(module)s~function:%(funcName)s"
        )
        file_handler.setFormatter(file_formatter)
        fritap_logger.addHandler(file_handler)
        fritap_logger.setLevel(logging.DEBUG)

        logger.info(f"FriTap logs will be saved to {log_path}")


class FriTap(DataGather):
    def __init__(self):
        """Initialize FriTap without process_id - will get session info when starting."""
        self.last_results = {}
        self.job_manager = Toolbox.get_frida_job_manager()
        self.process_id = None
        self.app_package = None
        self.mode = None
        self.ssl_log = None
        self.frida_script_path = None

        # Set up dedicated fritap logging
        _setup_fritap_logging()

    def _setup_session(self, config: dict = None):
        """Set up FriTap session using unified Frida session getter.

        Args:
            config: Optional configuration dict from interactive menu
        """
        # Use unified session getter (supports both spawn and attach modes)
        session, mode, app_info = Toolbox.get_frida_session_for_spotlight()

        self.process_id = app_info["pid"]
        self.app_package = app_info["package_name"]
        self.mode = mode
        self.frida_device = app_info["device"]  # Store device for resume after hooks

        # Use config or defaults
        output_keylog = config.get("output_keylog", True) if config else True
        output_json = config.get("output_json", True) if config else True

        # Use fritap folder at results root (sibling to raw/, like dexray_intercept/)
        fritap_dir = f"{os.getenv('RESULTS_PATH', '')}fritap/"
        self.keylog_path = f"{fritap_dir}fritap_keylog.log" if output_keylog else None
        self.json_output_path = (
            f"{fritap_dir}fritap_output.json" if output_json else None
        )
        self.log_path = f"{fritap_dir}fritap.log"

        # Initialize SSL_Logger with the obtained process ID
        # Note: verbose and debug_output are disabled to prevent terminal interference
        # All output goes to log files in the fritap directory
        self.ssl_log = SSL_Logger(
            self.process_id,
            verbose=False,  # Disable verbose output to prevent terminal noise
            keylog=self.keylog_path,  # Path to save SSL key log in results folder
            debug_output=False,  # Disable debug output to prevent terminal noise
            json_output=self.json_output_path,  # Path to save JSON output in results folder
        )

        # Get the Frida script path from SSL_Logger
        self.frida_script_path = self.ssl_log.get_fritap_frida_script_path()

        # Set up the Frida session in the JobManager
        # Note: We already spawned/attached via get_frida_session_for_spotlight()
        should_spawn = mode == "spawn"
        self.job_manager.setup_frida_session(
            self.process_id,
            self.ssl_log.on_fritap_message,
            should_spawn=False,  # Already spawned/attached
        )

        logger.info(
            f"FriTap initialized in {mode.upper()} mode for {self.app_package} (PID: {self.process_id})"
        )

    def _interactive_configuration(self) -> dict | None:
        """Interactive configuration menu for FriTap options.

        Returns:
            Configuration dict if user confirms, None if cancelled
        """
        import re

        console = SandroidConsole.get()

        # Box width (inner content width)
        BOX_WIDTH = 60

        def _box_line(content: str, align: str = "center") -> str:
            """Create a box line with proper alignment accounting for Rich markup."""
            # Strip Rich markup to calculate visual width
            PLACEHOLDER = "\x00LBRACKET\x00"
            temp = content.replace("\\[", PLACEHOLDER)
            RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
            visual_text = RICH_MARKUP_RE.sub("", temp)
            visual_text = visual_text.replace(PLACEHOLDER, "[")
            visual_len = len(visual_text)

            # Calculate padding
            if align == "center":
                left_pad = (BOX_WIDTH - visual_len) // 2
                right_pad = BOX_WIDTH - visual_len - left_pad
            else:  # left align
                left_pad = 1
                right_pad = BOX_WIDTH - visual_len - left_pad

            return f"[primary]║[/primary]{' ' * left_pad}{content}{' ' * right_pad}[primary]║[/primary]"

        # Default settings
        settings = {
            "enable_network_capture": False,
            "output_keylog": True,
            "output_json": True,
        }

        # Check if network capture is already running
        network_already_running = Toolbox._network_capture_running

        while True:
            console.clear()

            # Draw configuration box
            console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
            console.print(_box_line("[bold]FriTap Configuration[/bold]"))
            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")

            # Network capture option
            if network_already_running:
                net_status = "[success]● Running[/success]"
                net_note = "(already active)"
            elif settings["enable_network_capture"]:
                net_status = "[success]● Enabled[/success]"
                net_note = "(will start tcpdump)"
            else:
                net_status = "[error]○ Disabled[/error]"
                net_note = ""
            console.print(
                _box_line(
                    f"[accent]\\[N][/accent] Network Capture: {net_status} {net_note}",
                    align="left",
                )
            )

            # Output format options
            keylog_status = (
                "[success]●[/success]"
                if settings["output_keylog"]
                else "[error]○[/error]"
            )
            json_status = (
                "[success]●[/success]"
                if settings["output_json"]
                else "[error]○[/error]"
            )
            console.print(
                _box_line(
                    f"[accent]\\[K][/accent] Keylog Output:   {keylog_status} (SSLKEYLOGFILE format)",
                    align="left",
                )
            )
            console.print(
                _box_line(
                    f"[accent]\\[J][/accent] JSON Output:     {json_status} (structured data)",
                    align="left",
                )
            )

            console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
            console.print(
                _box_line(
                    "[success]\\[Enter][/success] Start FriTap    [warning]\\[Esc/Q][/warning] Cancel",
                    align="left",
                )
            )
            console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")

            # Get user input
            try:
                choice = click.getchar().lower()
            except (KeyboardInterrupt, EOFError):
                return None

            if choice in ("\r", "\n"):  # Enter - start
                return settings
            if choice in ("\x1b", "q"):  # Escape or Q - cancel
                return None
            if choice == "n" and not network_already_running:
                settings["enable_network_capture"] = not settings[
                    "enable_network_capture"
                ]
            elif choice == "k":
                settings["output_keylog"] = not settings["output_keylog"]
            elif choice == "j":
                settings["output_json"] = not settings["output_json"]

    def start(self, interactive: bool = True) -> bool:
        """Start FriTap monitoring.

        Args:
            interactive: If True, show interactive configuration menu first

        Returns:
            True if started successfully, False if cancelled
        """
        config = None
        network_instance = None
        network_started = False

        if interactive:
            config = self._interactive_configuration()
            if config is None:
                logger.info("FriTap configuration cancelled")
                return False

        try:
            # Set up session FIRST (before starting network) to fail fast
            if self.process_id is None:
                self._setup_session(config)

            # Now start network capture if requested (after session setup succeeded)
            if (
                config
                and config.get("enable_network_capture")
                and not Toolbox._network_capture_running
            ):
                # Set long action duration for FriTap sessions (1 hour)
                Toolbox.action_duration = 3600
                from sandroid.analysis.network import Network

                network_instance = Network()
                network_instance.gather()  # This starts tcpdump capture
                network_started = True
                logger.info("Network capture started for FriTap")

                # Register network as background task (started by fritap)
                Toolbox.register_background_task(
                    name="network",
                    display_name="Network Capture",
                    instance=network_instance,
                    stop_callback=network_instance.stop,
                    started_by="fritap",
                )

            # Start the job with a custom hooking handler
            self.job_id = self.job_manager.start_job(
                self.frida_script_path,
                custom_hooking_handler_name=self.ssl_log.on_fritap_message,
            )

            # Resume spawned process now that hooks are installed
            if self.mode == "spawn":
                Toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            # Register tool usage and files for exit summary
            files = [self.log_path]
            if self.keylog_path:
                files.append(self.keylog_path)
            if self.json_output_path:
                files.append(self.json_output_path)
            Toolbox.mark_tool_used("fritap", files=files)

            # Register FriTap as background task with PID
            Toolbox.register_background_task(
                name="fritap",
                display_name="FriTap",
                instance=self,
                stop_callback=self.stop,
                app_name=self.app_package,
                target_pid=self.process_id,
            )

            logger.info(
                f"FriTap job started with ID: {self.job_id} in {self.mode.upper()} mode for {self.app_package}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start FriTap: {e}")
            # Clean up network capture if we started it
            if network_started and network_instance:
                logger.info("Cleaning up network capture due to FriTap startup failure")
                try:
                    network_instance.stop()
                    if Toolbox.is_task_running("network"):
                        Toolbox.unregister_background_task("network")
                except Exception as cleanup_error:
                    logger.warning(f"Error during network cleanup: {cleanup_error}")
            raise  # Re-raise so the caller knows it failed

    def stop(self):
        """Stop FriTap monitoring and finalize outputs."""
        # Finalize JSON output before stopping
        if self.ssl_log:
            if hasattr(self.ssl_log, "_finalize_json_output"):
                try:
                    self.ssl_log._finalize_json_output()
                    logger.info("FriTap JSON output finalized")
                except Exception as e:
                    logger.warning(f"Error finalizing JSON output: {e}")

        # Stop the Frida job
        if self.app_package:
            self.job_manager.stop_app_with_closing_frida(self.app_package)

    def gather(self):
        """Gather data from the monitored application.

        .. warning::
            Context dependent behavior: Calling this method acts as a toggle, it starts or stops the monitoring process based on the current state.
        """
        if self.running:
            self.job_manager.stop_app_with_closing_frida(self.app_package)
            self.last_output = self.profiler.get_profiling_log_as_JSON()
            self.running = False
            Toolbox.malware_monitor_running = False
            self.has_new_results = True
        elif not self.running:
            self.app_package, _ = Toolbox.get_spotlight_application()
            # self.logger.warning("Next: Setup Frida Session")
            self.job_manager.setup_frida_session(
                self.app_package, self.profiler.on_appProfiling_message
            )
            # self.logger.warning("Next: start job")
            job = self.job_manager.start_job(
                self.frida_script_path,
                custom_hooking_handler_name=self.profiler.on_appProfiling_message,
            )

            # Resume spawned process now that hooks are installed (if in spawn mode)
            if (
                hasattr(self, "mode")
                and self.mode == "spawn"
                and hasattr(self, "frida_device")
                and hasattr(self, "process_id")
            ):
                Toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            self.running = True
            Toolbox.malware_monitor_running = True

    def has_new_results(self):
        """Check if there are new results available.

        :returns: True if there are new results, False otherwise.
        :rtype: bool
        """
        if self.running:
            return False
        return self.has_new_results

    def return_data(self):
        """Return the last profiling data.

        This method returns the last profiling data and resets the new results flag.

        :returns: The last profiling data in JSON format.
        :rtype: str
        """
        self.has_new_results = False
        return self.last_output

    def pretty_print(self):
        """Not implemented"""
