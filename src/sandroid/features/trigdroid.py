import sys
import time
from logging import getLogger

from sandroid.core.toolbox import Toolbox
from sandroid.services import get_spotlight_service

from .functionality import Functionality

try:
    from trigdroid import TestConfiguration, TrigDroidAPI, quick_test
except ImportError:
    _import_logger = getLogger(__name__)
    _import_logger.warning(
        "TrigDroid package not installed. TrigDroid functionality will be disabled."
    )
    TrigDroidAPI = None
    TestConfiguration = None
    quick_test = None

logger = getLogger(__name__)

# System app used for noise-detection runs
_NOISE_DETECTION_APP = "com.android.settings"


class Trigdroid(Functionality):
    """Wrapper for the TrigDroid automated malware trigger tool.

    Integrates TrigDroid into Sandroid by managing noise-detection rounds,
    bypass configuration, and result submission.

    Attributes:
        did_dummy_round: Whether a noise-detection round has already been performed.
    """

    did_dummy_round: bool = False

    def perform(self) -> None:
        """Execute TrigDroid analysis.

        On the first call, performs a noise-detection round without a target package.
        On subsequent calls, runs the real analysis against the spotlight application.
        """
        logger.warning("Trigdroid dry run is disabled at the moment")
        package_under_test = get_spotlight_service().get_app_tuple()[0]

        if self.did_dummy_round:
            logger.info("Starting Trigdroid with specified package")
            self.run_trigdroid(package_under_test)
        else:
            logger.info("Starting Trigdroid without package to measure noise")
            self.run_trigdroid("no_package")
            self.did_dummy_round = True
            changed_files = Toolbox.fetch_changed_files()
            # Register files changed during noise round so they can be filtered later
            Toolbox.noise_files.update(changed_files)

    def run_ccf(self) -> None:
        """Run the TrigDroid CCF (Config Creation Flow) utility.

        Exits the process after completion (exit code 0 on success, 1 on error).
        """
        if TrigDroidAPI is None:
            logger.error("TrigDroid package not available. Cannot run CCF utility.")
            return

        if not Toolbox.args.trigdroid_ccf:
            logger.warning(
                "somehow Trigdroid.run_ccf() was called without trigdroid_ccf command line option"
            )
            return

        logger.info("Starting Trigdroid CCF utility")
        try:
            with TrigDroidAPI() as trigdroid:
                config = TestConfiguration()
                if Toolbox.args.trigdroid_ccf == "I":
                    logger.info("Interactive CCF mode not yet implemented with new API")
                elif Toolbox.args.trigdroid_ccf == "D":
                    logger.info("Creating default TrigDroid configuration")
            sys.exit(0)
        except Exception as e:
            logger.error(f"TrigDroid CCF utility failed: {e}")
            sys.exit(1)

    def run_trigdroid(self, package_name: str) -> None:
        """Run TrigDroid analysis for the given package.

        Args:
            package_name: Android package name to analyze, or ``"no_package"``
                for a noise-detection round.
        """
        if TrigDroidAPI is None:
            logger.error("TrigDroid package not available. Cannot run analysis.")
            return

        is_noise_round = package_name == "no_package"
        if is_noise_round:
            logger.info(
                "Running TrigDroid noise detection round without specific package"
            )
            package_name = None

        logger.debug(f"TrigDroid analyzing package: {package_name}")
        Toolbox.set_action_time()
        start_time = time.perf_counter()

        bypass_config = Toolbox.trigdroid_bypass_config
        spawn_mode = Toolbox.trigdroid_spawn_mode
        auto_resume = Toolbox.trigdroid_auto_resume

        self._log_enabled_bypasses(bypass_config)

        try:
            if is_noise_round:
                quick_test(_NOISE_DETECTION_APP)
                logger.info("TrigDroid noise detection completed")
            else:
                self._run_real_analysis(
                    package_name, bypass_config, spawn_mode, auto_resume
                )
        except Exception as e:
            logger.error(f"TrigDroid analysis failed: {e}")
        finally:
            elapsed = int(time.perf_counter() - start_time)
            Toolbox.set_action_duration(elapsed)
            Toolbox.trigdroid_bypass_config = None

    def override_package(self, new_name: str) -> None:
        """Override the target package name.

        Args:
            new_name: The new package name.
        """
        self.override_package_name = new_name
        self.package_name_overridden = True

    # Keep the old misspelled name as an alias for backward compatibility
    overide_package = override_package

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _log_enabled_bypasses(self, bypass_config: dict | None) -> None:
        """Log which bypass hooks are enabled, if any."""
        if not bypass_config:
            return
        enabled = [name for name, cfg in bypass_config.items() if cfg.get("enabled")]
        if enabled:
            logger.info(f"TrigDroid bypass hooks enabled: {', '.join(enabled)}")

    def _run_real_analysis(
        self,
        package_name: str,
        bypass_config: dict | None,
        spawn_mode: bool,
        auto_resume: bool,
    ) -> None:
        """Execute TrigDroid analysis with full configuration.

        Args:
            package_name: Target Android package.
            bypass_config: Optional bypass hook configuration dict.
            spawn_mode: Whether to use spawn mode.
            auto_resume: Whether to auto-resume after instrumentation.
        """
        config_kwargs = {
            "package": package_name,
            "acceleration": 8,
            "sensors": ["accelerometer", "gyroscope"],
            "frida_hooks": True,
            "spawn_mode": spawn_mode,
            "auto_resume": auto_resume,
        }

        if bypass_config:
            config_kwargs["bypass_config"] = bypass_config

        config = TestConfiguration(**config_kwargs)

        with TrigDroidAPI() as trigdroid:
            trigdroid.configure(config)
            result = trigdroid.run_tests()

            if result.success:
                logger.info(
                    f"TrigDroid analysis completed successfully for {package_name}"
                )
                Toolbox.submit_other_data(
                    "TrigDroid Results",
                    {
                        "package": package_name,
                        "success": result.success,
                        "triggers_activated": getattr(result, "triggers_activated", 0),
                        "analysis_data": getattr(result, "data", {}),
                        "bypasses_enabled": [
                            name
                            for name, cfg in (bypass_config or {}).items()
                            if cfg.get("enabled")
                        ],
                    },
                )
            else:
                logger.warning(f"TrigDroid analysis had issues for {package_name}")
