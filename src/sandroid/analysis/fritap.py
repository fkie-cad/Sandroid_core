from logging import getLogger

from friTap import SSL_Logger

from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

logger = getLogger(__name__)


class FriTap(DataGather):
    def __init__(self, process_id):
        self.last_results = {}
        self.job_manager = Toolbox.get_frida_job_manager()
        self.process_id = process_id

        # Initialize SSL_Logger with optional arguments
        self.ssl_log = SSL_Logger(
            self.process_id,
            verbose=True,  # Enable verbose output
            keylog="keylog.log",  # Path to save SSL key log
            debug_output=True,  # Enable debug output
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
