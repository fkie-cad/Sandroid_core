import time
from logging import getLogger

from sandroid.core.toolbox import Toolbox

from .functionality import Functionality

try:
    from trigdroid import TestConfiguration, TrigDroidAPI, quick_test
except ImportError:
    logger = getLogger(__name__)
    logger.warning(
        "TrigDroid package not installed. TrigDroid functionality will be disabled."
    )
    TrigDroidAPI = None
    TestConfiguration = None
    quick_test = None

logger = getLogger(__name__)


class Trigdroid(Functionality):
    """Wrapper for the Trigdroid Tool to integrate it into Sandroid

    **Attributes:**
        logger (Logger): Logger instance for Trigdroid.
        did_dummy_round (bool): Indicates if a dummy round was performed.
    """

    did_dummy_round = False

    def perform(self):
        """Executes the main functionality of Trigdroid."""
        logger.warning("Trigdroid dry run is disabled at the moment")
        package_under_test = Toolbox.get_spotlight_application()[0]

        if self.did_dummy_round:
            logger.info("Starting Trigdroid with specified package")
            self.run_trigdroid(package_under_test)
        else:
            logger.info("Starting Trigdroid without package to measure noise")
            self.run_trigdroid("no_package")
            self.did_dummy_round = True
            changed_files = Toolbox.fetch_changed_files()
            Toolbox.noise_files.update(
                changed_files
            )  # registering files that changed in the dummy round as noise. This kind of goes against the Functionality/Datagather structural distinction, but oh well, it's an exception.

    def run_ccf(self):
        """Runs the Trigdroid CCF utility."""
        if TrigDroidAPI is None:
            logger.error("TrigDroid package not available. Cannot run CCF utility.")
            return

        if Toolbox.args.trigdroid_ccf:
            logger.info("Starting Trigdroid CCF utility")
            try:
                with TrigDroidAPI() as trigdroid:
                    config = TestConfiguration()
                    if Toolbox.args.trigdroid_ccf == "I":
                        # Interactive mode - would need implementation
                        logger.info(
                            "Interactive CCF mode not yet implemented with new API"
                        )
                    elif Toolbox.args.trigdroid_ccf == "D":
                        # Default config file creation
                        logger.info("Creating default TrigDroid configuration")
                        # This would create config.yml - implementation depends on TrigDroid API
                exit(0)
            except Exception as e:
                logger.error(f"TrigDroid CCF utility failed: {e}")
                exit(1)
        logger.warning(
            "somehow Trigdroid.run_ccf() was called without trigdroid_ccf command line option"
        )

    def run_trigdroid(self, package_name):
        """Runs the Trigdroid with the specified package name using the new API.

        .. warning::
            Uses TestConfiguration for setup. Config file support depends on new API capabilities.

        :param package_name: The name of the package to be tested.
        :type package_name: str
        """
        if TrigDroidAPI is None:
            logger.error("TrigDroid package not available. Cannot run analysis.")
            return

        if package_name == "no_package":
            logger.info(
                "Running TrigDroid noise detection round without specific package"
            )
            package_name = None

        logger.debug(f"TrigDroid analyzing package: {package_name}")
        Toolbox.set_action_time()
        start_time = time.perf_counter()

        try:
            if package_name is None:
                # Dummy/noise run - use minimal configuration
                result = quick_test(
                    "com.android.settings"
                )  # Use a system app for noise detection
                logger.info("TrigDroid noise detection completed")
            else:
                # Real analysis run
                config = TestConfiguration(
                    package=package_name,
                    acceleration=8,  # Default acceleration
                    sensors=["accelerometer", "gyroscope"],  # Common sensors
                    frida_hooks=True,
                )

                with TrigDroidAPI() as trigdroid:
                    trigdroid.configure(config)
                    result = trigdroid.run_tests()

                    if result.success:
                        logger.info(
                            f"TrigDroid analysis completed successfully for {package_name}"
                        )
                        # Store results in Toolbox for later retrieval
                        Toolbox.submit_other_data(
                            "TrigDroid Results",
                            {
                                "package": package_name,
                                "success": result.success,
                                "triggers_activated": getattr(
                                    result, "triggers_activated", 0
                                ),
                                "analysis_data": getattr(result, "data", {}),
                            },
                        )
                    else:
                        logger.warning(
                            f"TrigDroid analysis had issues for {package_name}"
                        )

        except Exception as e:
            logger.error(f"TrigDroid analysis failed: {e}")
        finally:
            end_time = time.perf_counter()
            Toolbox.set_action_duration(int(end_time - start_time))

    def overide_package(self, new_name):
        """Overrides the package name with a new name.

        :param new_name: The new package name.
        :type new_name: str
        """
        self.override_package_name = new_name
        self.package_name_overridden = True
