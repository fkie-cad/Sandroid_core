"""TrigDroid Bypass - Unified bypass hooks for Android app analysis.

This module provides a JobManager-integrated bypass system for common app
protections including SSL pinning, root detection, Frida detection, emulator
detection, and debug detection.

The bypass hooks use RPC-based runtime controls, allowing selective enabling
of individual bypass categories without needing multiple pre-compiled scripts.

For authorized security testing and research purposes only.
"""

import logging
import os

from sandroid.core.enums import SpawnMode
from sandroid.core.events import Event, EventBus, EventType
from sandroid.core.toolbox import Toolbox
from sandroid.services import (
    get_spotlight_service,
    get_task_service,
    get_tool_usage_service,
)

logger = logging.getLogger(__name__)

# TrigDroid bypass hooks registry - for conflict detection
# This lists the major hook targets that may conflict with other Frida tools
TRIGDROID_BYPASS_HOOKS = [
    # SSL Unpinning hooks
    "javax.net.ssl.SSLContext.init",
    "javax.net.ssl.HttpsURLConnection.setHostnameVerifier",
    "javax.net.ssl.HttpsURLConnection.setSSLSocketFactory",
    "okhttp3.CertificatePinner.check",
    "com.android.okhttp.CertificatePinner.check",
    "android.webkit.WebViewClient.onReceivedSslError",
    "com.android.org.conscrypt.TrustManagerImpl.verifyChain",
    # Root detection hooks
    "java.io.File.exists",
    "java.io.File.length",
    "java.io.FileInputStream.<init>",
    "java.lang.Runtime.exec",
    "java.lang.ProcessBuilder.command",
    "android.app.ApplicationPackageManager.getPackageInfo",
    "android.app.ApplicationPackageManager.getInstalledPackages",
    # Frida detection hooks
    "java.net.Socket.connect",
    "java.io.BufferedReader.readLine",  # Also used by debug detection
    # Emulator detection hooks
    "android.os.Build.getSerial",
    "android.telephony.TelephonyManager.getDeviceId",
    "android.telephony.TelephonyManager.getSubscriberId",
    # Debug detection hooks
    "android.os.Debug.isDebuggerConnected",
    "android.os.Debug.waitingForDebugger",
    "android.content.pm.PackageManager.getApplicationInfo",
]


class EventBusHandler(logging.Handler):
    """Logging handler that forwards messages to the EventBus for TUI display."""

    def __init__(self, task_name: str = "TrigDroid Bypass"):
        super().__init__()
        self.task_name = task_name
        self._event_bus = None

    @property
    def event_bus(self):
        """Lazy load EventBus to avoid circular imports."""
        if self._event_bus is None:
            self._event_bus = EventBus.get()
        return self._event_bus

    def emit(self, record: logging.LogRecord):
        """Emit a log record to the EventBus."""
        try:
            msg = self.format(record)
            if record.levelno >= logging.ERROR:
                msg = f"[error]{msg}[/error]"
            elif record.levelno >= logging.WARNING:
                msg = f"[warning]{msg}[/warning]"
            self.event_bus.publish(
                Event(
                    type=EventType.TASK_OUTPUT,
                    data={
                        "task_name": self.task_name,
                        "message": msg,
                    },
                    source="trigdroid_bypass",
                )
            )
        except Exception:
            pass


class TrigDroidBypass:
    """TrigDroid bypass hooks as a JobManager-integrated tool.

    This class provides unified bypass hooks for common app protections.
    It uses a single RPC-controlled Frida script to enable/disable
    individual bypass categories at runtime.

    Usage:
        bypass = TrigDroidBypass()
        bypass.start(config={
            'ssl_unpinning': True,
            'root_detection': True,
            'emulator_detection': {'device_profile': 'pixel_6_pro'},
        })
        # ... run tests ...
        bypass.stop()

    For use with objection, the compiled script can be loaded via:
        objection -g com.example.app explore -s trigdroid_bypass_bundle.js

    Build the script with:
        cd Sandroid_TrigDroid/frida_hooks && npm run build:bypass
    """

    # Try bundled version first, then fall back to tsc-compiled version
    SCRIPT_FILENAMES = ["trigdroid_bypass_bundle.js", "trigdroid_bypass_rpc.js"]
    HOOKS_REGISTRY = TRIGDROID_BYPASS_HOOKS

    def __init__(self):
        """Initialize TrigDroidBypass."""
        self.job_manager = Toolbox.get_frida_job_manager()
        self.job_id = None
        self.script = None
        self.process_id = None
        self.app_package = None
        self.mode = None
        self.frida_device = None
        self.enabled_bypasses = {}
        self.show_in_activity_log = False
        self._activity_log_handler = None
        self._script_path = self._find_script_path()

    def _find_script_path(self) -> str | None:
        """Find the compiled bypass script path.

        Uses TrigDroid's Python API to locate the script, with fallback
        to manual path search for development environments.

        Returns:
            Path to the compiled script, or None if not found.
        """
        # Try TrigDroid's Python API first (preferred method)
        try:
            from trigdroid import get_bypass_script_path

            path = get_bypass_script_path()
            if path:
                logger.debug(f"Found bypass script via trigdroid API: {path}")
                return path
        except ImportError:
            logger.debug("TrigDroid package not available, using fallback path search")

        # Fallback: manual path search for development environments
        base_dirs = [
            # Development path (from TrigDroid source)
            os.path.expanduser(
                "~/Documents/projekte/sandroid/github/Sandroid_TrigDroid/src/trigdroid/scripts"
            ),
            os.path.expanduser(
                "~/Documents/projekte/sandroid/github/Sandroid_TrigDroid/frida_hooks/dist"
            ),
            # TRIGDROID_SCRIPTS_PATH environment variable
        ]

        env_path = os.environ.get("TRIGDROID_SCRIPTS_PATH")
        if env_path:
            base_dirs.insert(0, env_path)

        # Try each filename in each directory
        for base_dir in base_dirs:
            for filename in self.SCRIPT_FILENAMES:
                path = os.path.join(base_dir, filename)
                if os.path.exists(path):
                    logger.debug(f"Found bypass script at: {path}")
                    return path

        logger.warning(
            "TrigDroid bypass script not found. Install trigdroid package or "
            "run 'npm run build:bypass' in TrigDroid frida_hooks directory."
        )
        return None

    def _setup_activity_log(self):
        """Set up activity log handler for bypass messages."""
        if self._activity_log_handler is not None:
            return

        self._activity_log_handler = EventBusHandler(task_name="TrigDroid Bypass")
        self._activity_log_handler.setLevel(logging.INFO)
        self._activity_log_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(self._activity_log_handler)

    def _remove_activity_log(self):
        """Remove activity log handler."""
        if self._activity_log_handler is not None:
            logger.removeHandler(self._activity_log_handler)
            self._activity_log_handler = None

    def _message_handler(self, message, data):
        """Handle messages from the Frida script.

        Args:
            message: Frida message object
            data: Optional binary data
        """
        msg_type = message.get("type", "")

        if msg_type == "send":
            payload = message.get("payload", "")
            if isinstance(payload, str):
                # Parse message type
                if payload.startswith("INFO:"):
                    logger.info(f"[Bypass] {payload[5:].strip()}")
                elif payload.startswith("DEBUG:"):
                    logger.debug(f"[Bypass] {payload[6:].strip()}")
                elif payload.startswith("#changelog"):
                    # Changelog entry - log as info
                    logger.info(f"[Bypass Change] {payload}")
                else:
                    logger.info(f"[Bypass] {payload}")

                # Forward to activity log if enabled
                if self.show_in_activity_log:
                    try:
                        EventBus.get().publish(
                            Event(
                                type=EventType.TASK_OUTPUT,
                                data={
                                    "task_name": "TrigDroid Bypass",
                                    "message": payload,
                                },
                                source="trigdroid_bypass",
                            )
                        )
                    except Exception:
                        pass

        elif msg_type == "error":
            error_msg = message.get("description", str(message))
            logger.error(f"[Bypass Error] {error_msg}")

    def _setup_session(self, config: dict = None):
        """Set up Frida session following JobManager pattern.

        This method avoids creating a duplicate Frida session by checking
        if one already exists in JobManager, enabling parallel tool support.

        Args:
            config: Optional configuration dict

        Raises:
            ValueError: If no spotlight app is selected or app not running in attach mode
        """
        from sandroid.core.adb import Adb

        # Get app info from SpotlightService directly (NOT from get_session_for_spotlight!)
        spotlight = get_spotlight_service()
        app_tuple = spotlight.get_app_tuple()
        if not app_tuple:
            raise ValueError(
                "No spotlight app selected. Press 'c' to select an app first."
            )

        self.app_package = app_tuple[0]
        self.process_id = spotlight.get_pid()
        self.mode = "spawn" if spotlight.is_spawn_mode() else "attach"
        should_spawn = spotlight.is_spawn_mode()

        # For attach mode, ensure we have a PID
        if not should_spawn and not self.process_id:
            self.process_id = Adb.get_pid_for_package_name(self.app_package)
            if not self.process_id:
                raise ValueError(
                    f"App {self.app_package} not running. Start it or use spawn mode."
                )

        self.show_in_activity_log = (
            config.get("show_in_activity_log", False) if config else False
        )

        if self.show_in_activity_log:
            self._setup_activity_log()

        # CRITICAL: Only set up session if JobManager doesn't have one
        # This enables parallel tool support (TrigDroid + FriTap + DexRay)
        if not self.job_manager.has_active_session():
            logger.debug("No existing Frida session - setting up new session")
            target = self.app_package if should_spawn else self.process_id
            self.job_manager.setup_frida_session(
                target,
                self._message_handler,
                should_spawn=should_spawn,
            )
            if should_spawn:
                session_info = self.job_manager.get_session_info()
                if session_info and session_info.get("pid"):
                    self.process_id = session_info["pid"]
        else:
            logger.debug("Reusing existing Frida session from another tool")
            # In reuse mode, get PID from existing session if we don't have it
            if not self.process_id:
                session_info = self.job_manager.get_session_info()
                if session_info and session_info.get("pid"):
                    self.process_id = session_info["pid"]

        # Get Frida device for resume operations
        if Toolbox.frida_manager:
            self.frida_device = Toolbox.frida_manager.get_frida_device()
        else:
            # Fallback: get device directly via frida
            import frida

            self.frida_device = frida.get_usb_device()

        logger.info(
            f"TrigDroid Bypass initialized in {self.mode.upper()} mode for {self.app_package} (PID: {self.process_id})"
        )

    def start(self, config: dict = None, interactive: bool = False) -> bool:
        """Start TrigDroid bypass hooks.

        Args:
            config: Bypass configuration dict with keys:
                - ssl_unpinning: bool or dict with SSLUnpinningConfig options
                - root_detection: bool or dict with RootDetectionConfig options
                - frida_detection: bool or dict with FridaDetectionConfig options
                - emulator_detection: bool or dict with EmulatorDetectionConfig options
                - debug_detection: bool or dict with DebugDetectionConfig options
                - show_in_activity_log: bool - Show output in TUI activity log
            interactive: If True, show interactive configuration (uses TrigDroidModal)

        Returns:
            True if started successfully, False otherwise.
        """
        if self._script_path is None:
            logger.error(
                "TrigDroid bypass script not found. "
                "Run 'npm run build:bypass' in the TrigDroid frida_hooks directory."
            )
            return False

        config = config or {}

        try:
            # Set up session if not already done
            if self.process_id is None:
                self._setup_session(config)

            # Check for hook conflicts
            conflicts = Toolbox.check_frida_hook_conflicts(self.HOOKS_REGISTRY)
            if conflicts:
                conflict_details = ", ".join(
                    f"{hook} (job: {job_id[:8]}...)"
                    for hook, job_id in conflicts.items()
                )
                logger.warning(
                    f"TrigDroid Bypass may conflict with existing hooks: {conflict_details}"
                )

            # Start the job
            job = self.job_manager.start_job(
                self._script_path,
                custom_hooking_handler_name=self._message_handler,
                job_type="trigdroid_bypass",
                display_name="TrigDroid Bypass",
                hooks_registry=self.HOOKS_REGISTRY,
                priority=5,  # Lower priority than FriTap
            )

            self.job_id = job.get_id() if job else None
            self.script = job.get_script_of_job() if job else None

            if self.job_id:
                Toolbox.register_frida_hooks(self.job_id, self.HOOKS_REGISTRY)

            # Enable bypasses via RPC
            if self.script:
                self._enable_bypasses(config)

            # Resume spawned process now that hooks are installed
            if self.mode == SpawnMode.SPAWN or self.mode == SpawnMode.SPAWN.value:
                Toolbox.resume_spawned_process_after_hooks(
                    self.frida_device, self.process_id
                )

            # Register as background task
            get_task_service().register(
                name="trigdroid_bypass",
                display_name="TrigDroid Bypass",
                instance=self,
                stop_callback=self.stop,
                app_name=self.app_package,
                target_pid=self.process_id,
            )

            # Mark tool as used
            get_tool_usage_service().mark_used("trigdroid_bypass", files=[])

            logger.info(f"TrigDroid Bypass job started with ID: {self.job_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to start TrigDroid Bypass: {e}")
            return False

    def _enable_bypasses(self, config: dict):
        """Enable bypass hooks via RPC based on configuration.

        Args:
            config: Bypass configuration dict
        """
        if not self.script:
            logger.error("No script available for RPC calls")
            return

        try:
            # Prepare batch configuration
            batch_config = {}

            if config.get("ssl_unpinning"):
                ssl_config = (
                    config["ssl_unpinning"]
                    if isinstance(config["ssl_unpinning"], dict)
                    else {}
                )
                batch_config["ssl"] = ssl_config or True
                self.enabled_bypasses["ssl_unpinning"] = True

            if config.get("root_detection"):
                root_config = (
                    config["root_detection"]
                    if isinstance(config["root_detection"], dict)
                    else {}
                )
                batch_config["root"] = root_config or True
                self.enabled_bypasses["root_detection"] = True

            if config.get("frida_detection"):
                frida_config = (
                    config["frida_detection"]
                    if isinstance(config["frida_detection"], dict)
                    else {}
                )
                batch_config["frida"] = frida_config or True
                self.enabled_bypasses["frida_detection"] = True

            if config.get("emulator_detection"):
                emu_config = (
                    config["emulator_detection"]
                    if isinstance(config["emulator_detection"], dict)
                    else {}
                )
                batch_config["emulator"] = emu_config or True
                self.enabled_bypasses["emulator_detection"] = True

            if config.get("debug_detection"):
                debug_config = (
                    config["debug_detection"]
                    if isinstance(config["debug_detection"], dict)
                    else {}
                )
                batch_config["debug"] = debug_config or True
                self.enabled_bypasses["debug_detection"] = True

            # Call batch enable via RPC
            if batch_config:
                results = self.script.exports_sync.enableBypasses(batch_config)
                for result in results:
                    status = result.get("status", "unknown")
                    bypass_type = result.get("type", "unknown")
                    if status == "enabled":
                        logger.info(f"Enabled {bypass_type} bypass")
                    elif status == "error":
                        logger.error(
                            f"Failed to enable {bypass_type}: {result.get('message')}"
                        )

        except Exception as e:
            logger.error(f"Failed to enable bypasses via RPC: {e}")

    def enable_ssl_unpinning(self, config: dict = None) -> bool:
        """Enable SSL unpinning bypass at runtime.

        Args:
            config: Optional SSL unpinning configuration

        Returns:
            True if enabled successfully
        """
        if not self.script:
            logger.error("Script not loaded - call start() first")
            return False

        try:
            result = self.script.exports_sync.enableSSLUnpinning(config or {})
            if result.get("status") == "enabled":
                self.enabled_bypasses["ssl_unpinning"] = True
                logger.info("SSL unpinning bypass enabled")
                return True
            if result.get("status") == "already_enabled":
                logger.info("SSL unpinning bypass already enabled")
                return True
            logger.error(f"Failed to enable SSL unpinning: {result.get('message')}")
            return False
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            return False

    def enable_root_bypass(self, config: dict = None) -> bool:
        """Enable root detection bypass at runtime.

        Args:
            config: Optional root detection bypass configuration

        Returns:
            True if enabled successfully
        """
        if not self.script:
            logger.error("Script not loaded - call start() first")
            return False

        try:
            result = self.script.exports_sync.enableRootBypass(config or {})
            if result.get("status") == "enabled":
                self.enabled_bypasses["root_detection"] = True
                logger.info("Root detection bypass enabled")
                return True
            if result.get("status") == "already_enabled":
                logger.info("Root detection bypass already enabled")
                return True
            logger.error(f"Failed to enable root bypass: {result.get('message')}")
            return False
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            return False

    def enable_frida_bypass(self, config: dict = None) -> bool:
        """Enable Frida detection bypass at runtime.

        NOTE: For best results, this should be enabled in SPAWN mode.

        Args:
            config: Optional Frida detection bypass configuration

        Returns:
            True if enabled successfully
        """
        if not self.script:
            logger.error("Script not loaded - call start() first")
            return False

        if self.mode != SpawnMode.SPAWN and self.mode != SpawnMode.SPAWN.value:
            logger.warning(
                "Frida bypass works best in SPAWN mode. "
                "Some detection methods may trigger before hooks are installed."
            )

        try:
            result = self.script.exports_sync.enableFridaBypass(config or {})
            if result.get("status") == "enabled":
                self.enabled_bypasses["frida_detection"] = True
                logger.info("Frida detection bypass enabled")
                return True
            if result.get("status") == "already_enabled":
                logger.info("Frida detection bypass already enabled")
                return True
            logger.error(f"Failed to enable Frida bypass: {result.get('message')}")
            return False
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            return False

    def enable_emulator_bypass(self, config: dict = None) -> bool:
        """Enable emulator detection bypass at runtime.

        Args:
            config: Optional emulator detection bypass configuration
                    Can include 'device_profile' key with values like
                    'pixel_4_xl', 'pixel_6_pro', 'samsung_s21', etc.

        Returns:
            True if enabled successfully
        """
        if not self.script:
            logger.error("Script not loaded - call start() first")
            return False

        try:
            result = self.script.exports_sync.enableEmulatorBypass(config or {})
            if result.get("status") == "enabled":
                self.enabled_bypasses["emulator_detection"] = True
                logger.info("Emulator detection bypass enabled")
                return True
            if result.get("status") == "already_enabled":
                logger.info("Emulator detection bypass already enabled")
                return True
            logger.error(f"Failed to enable emulator bypass: {result.get('message')}")
            return False
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            return False

    def enable_debug_bypass(self, config: dict = None) -> bool:
        """Enable debug detection bypass at runtime.

        Args:
            config: Optional debug detection bypass configuration

        Returns:
            True if enabled successfully
        """
        if not self.script:
            logger.error("Script not loaded - call start() first")
            return False

        try:
            result = self.script.exports_sync.enableDebugBypass(config or {})
            if result.get("status") == "enabled":
                self.enabled_bypasses["debug_detection"] = True
                logger.info("Debug detection bypass enabled")
                return True
            if result.get("status") == "already_enabled":
                logger.info("Debug detection bypass already enabled")
                return True
            logger.error(f"Failed to enable debug bypass: {result.get('message')}")
            return False
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            return False

    def get_status(self) -> dict:
        """Get status of all bypass hooks.

        Returns:
            Dict with bypass status information
        """
        if not self.script:
            return {
                "loaded": False,
                "enabled_bypasses": {},
            }

        try:
            rpc_status = self.script.exports_sync.getStatus()
            return {
                "loaded": True,
                "job_id": self.job_id,
                "app_package": self.app_package,
                "process_id": self.process_id,
                "mode": self.mode,
                "rpc_status": rpc_status,
                "enabled_bypasses": self.enabled_bypasses,
            }
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return {
                "loaded": True,
                "error": str(e),
                "enabled_bypasses": self.enabled_bypasses,
            }

    def stop(self):
        """Stop TrigDroid bypass hooks.

        Note: This stops Frida hooks but keeps the target app running.
        """
        self._remove_activity_log()

        if self.job_id:
            # Unregister hooks
            Toolbox.unregister_frida_hooks(self.job_id)

            # Stop the job
            try:
                self.job_manager.stop_job_with_id(self.job_id)
                logger.info("TrigDroid Bypass stopped (app still running)")
            except Exception as e:
                logger.warning(f"Error stopping TrigDroid Bypass job: {e}")

        self.script = None
        self.job_id = None
        self.enabled_bypasses = {}

    @staticmethod
    def get_script_path_for_objection() -> str | None:
        """Get the path to the compiled bypass script for use with objection.

        This method finds the compiled trigdroid_bypass_bundle.js file that can
        be loaded into objection using the -s flag:
            objection -g com.example.app explore -s <path>

        Prefers using TrigDroid's Python API for installed packages.

        Returns:
            Path to the compiled script, or None if not found.
        """
        # Try TrigDroid's Python API first (preferred method)
        try:
            from trigdroid import get_bypass_script_path

            path = get_bypass_script_path()
            if path:
                return path
        except ImportError:
            pass

        # Fallback: create instance and use its path finder
        bypass = TrigDroidBypass()
        return bypass._script_path
