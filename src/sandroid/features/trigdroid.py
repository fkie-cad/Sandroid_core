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
    the spawn/resume mode, and result submission.

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

        # Detection bypasses come only from BypassService (the TUI's ``b``
        # chord), so the trigger run passes TrigDroid no bypass_config.
        spawn_mode = Toolbox.trigdroid_spawn_mode
        auto_resume = Toolbox.trigdroid_auto_resume

        try:
            if is_noise_round:
                quick_test(_NOISE_DETECTION_APP)
                logger.info("TrigDroid noise detection completed")
            else:
                spawn_mode = self._resolve_spawn(package_name, spawn_mode)
                if spawn_mode is None:
                    return
                self._run_real_analysis(package_name, spawn_mode, auto_resume)
        except Exception as e:
            logger.error(f"TrigDroid analysis failed: {e}")
        finally:
            elapsed = int(time.perf_counter() - start_time)
            Toolbox.set_action_duration(elapsed)

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

    @staticmethod
    def _resolve_spawn(package_name: str, spawn_mode: bool) -> bool | None:
        """Spawn or attach, by the one start rule (never a restart).

        A running app is attached to; a stopped one is spawned (when
        ``spawn_mode`` allows it). TrigDroid spawns through its own Frida
        session, outside Sandroid's JobManager, so it cannot restart a
        running app cleanly (stop the other tools, re-apply the armed
        bypasses): with the config's ``fresh`` flag on a running app it
        refuses and asks for a restart first.

        Returns:
            TrigDroid's ``spawn_mode`` for this run, or None to abort.
        """
        from sandroid.services import get_trigdroid_config_service
        from sandroid.services.app_start import StartAction, resolve_start

        fresh = bool(getattr(get_trigdroid_config_service(), "fresh", False))
        decision = resolve_start(package_name, tool="TrigDroid", java_agent=True)
        action = decision.action
        if action == StartAction.REFUSE:
            logger.error(f"TrigDroid not started: {decision.reason}")
            return None
        if action == StartAction.SPAWN:
            if not spawn_mode:
                logger.error(f"TrigDroid not started: {package_name} is not running")
                return None
            return True
        if fresh:
            logger.error(
                f"TrigDroid not started: {package_name} is running and TrigDroid "
                "cannot restart it itself — restart the app with ⇧R (headless: "
                "stop it first), then run TrigDroid."
            )
            return None
        return False

    def _run_real_analysis(
        self,
        package_name: str,
        spawn_mode: bool,
        auto_resume: bool,
    ) -> None:
        """Execute TrigDroid analysis with full configuration.

        Args:
            package_name: Target Android package.
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
                    },
                )
            else:
                logger.warning(f"TrigDroid analysis had issues for {package_name}")
