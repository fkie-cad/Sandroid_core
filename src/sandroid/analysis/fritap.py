import logging
import os

from friTap import SSL_Logger

from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

logger = logging.getLogger(__name__)

# Set up dedicated fritap log file
def _setup_fritap_logging():
    """Set up dedicated file logging for friTap in the Sandroid results folder."""
    fritap_logger = logging.getLogger('friTap')

    # Check if we already have a file handler to avoid duplicates
    has_file_handler = any(
        isinstance(handler, logging.FileHandler)
        for handler in fritap_logger.handlers
    )

    if not has_file_handler and os.getenv('RAW_RESULTS_PATH'):
        file_handler = logging.FileHandler(
            f"{os.getenv('RAW_RESULTS_PATH')}fritap.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s~%(levelname)s~%(message)s~module:%(module)s~function:%(funcName)s"
        )
        file_handler.setFormatter(file_formatter)
        fritap_logger.addHandler(file_handler)
        fritap_logger.setLevel(logging.DEBUG)

        logger.info(f"FriTap logs will be saved to {os.getenv('RAW_RESULTS_PATH')}fritap.log")


class FriTap(DataGather):
    def __init__(self, process_id):
        self.last_results = {}
        self.job_manager = Toolbox.get_frida_job_manager()
        self.process_id = process_id

        # Set up dedicated fritap logging
        _setup_fritap_logging()

        # Initialize SSL_Logger with optional arguments
        keylog_path = f"{os.getenv('RAW_RESULTS_PATH', '')}fritap_keylog.log"
        json_output_path = f"{os.getenv('RAW_RESULTS_PATH', '')}fritap_output.json"
        self.ssl_log = SSL_Logger(
            self.process_id,
            verbose=True,  # Enable verbose output
            keylog=keylog_path,  # Path to save SSL key log in results folder
            debug_output=True,  # Enable debug output
            json_output=json_output_path,  # Path to save JSON output in results folder
        )

        # Get the Frida script path from SSL_Logger
        self.frida_script_path = self.ssl_log.get_fritap_frida_script_path()

        # Set up the Frida session in the JobManager
        self.job_manager.setup_frida_session(
            self.process_id,
            self.ssl_log.on_fritap_message,
            should_spawn=False,  # Do not spawn the process
        )

    def start(self):
        # Start the job with a custom hooking handler
        self.job_id = self.job_manager.start_job(
            self.frida_script_path,
            custom_hooking_handler_name=self.ssl_log.on_fritap_message,
        )
        self.app_package, _ = Toolbox.get_spotlight_application()
        logger.info(f"Job started with ID: {self.job_id}")

    def stop(self):
        # self.job_manager.stop_job_with_id(self.job_id)
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
