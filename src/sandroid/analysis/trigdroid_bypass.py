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

import frida

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
        # Categories delegated to the native BypassService (so stop() can tear
        # down exactly what this instance enabled).
        self._delegated_categories: set[str] = set()
        self._script_path = self._find_script_path()

    @staticmethod
    def _bypass_service():
        """Lazy accessor for the process-wide BypassService singleton."""
        from sandroid.analysis.detection_bypass import get_bypass_service

        return get_bypass_service()

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

    def _message_handler(self, job, message, data):
        """Handle messages from the Frida (RPC bundle) script.

        ``Job.wrap_custom_hooking_handler_with_job_id`` always invokes the
        handler as ``handler(job, message, data)`` — this 4-arg signature
        matches it (B2 fix; the old 3-arg form raised TypeError at runtime).

        Args:
            job: The originating Job instance.
            message: Frida message object.
            data: Optional binary data.
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

        The common bypass categories (ssl/root/frida/debug) run through the
        native :class:`BypassService` and need NO external trigdroid bundle —
        this is what makes Sandroid self-sufficient for interception. Only
        ``emulator_detection`` still uses TrigDroid's compiled RPC
        device-profile bundle (there is no coherent native equivalent).

        Args:
            config: Bypass configuration dict with keys:
                - ssl_unpinning / root_detection / frida_detection /
                  debug_detection: truthy to enable (native BypassService)
                - emulator_detection: truthy to enable (RPC bundle)
                - show_in_activity_log: bool - Show output in TUI activity log
            interactive: Unused (kept for API compatibility).

        Returns:
            True if at least one bypass category was enabled.
        """
        config = config or {}

        self.show_in_activity_log = config.get("show_in_activity_log", False)
        if self.show_in_activity_log:
            self._setup_activity_log()

        # Reflect the spotlight target for the coordinator task display.
        spotlight = get_spotlight_service()
        app_tuple = spotlight.get_app_tuple()
        if app_tuple:
            self.app_package = app_tuple[0]
            self.process_id = spotlight.get_pid()
            self.mode = "spawn" if spotlight.is_spawn_mode() else "attach"

        try:
            any_enabled = False

            # Native categories — self-contained via BypassService, applied as
            # ONE bundle op (start_many) so we don't trigger N sequential
            # rebuilds (each rebuild could otherwise blink the others off).
            native_map = {
                "ssl_unpinning": "ssl",
                "root_detection": "root",
                "frida_detection": "frida",
                "debug_detection": "debug",
            }
            requested = [cat for key, cat in native_map.items() if config.get(key)]
            if requested:
                svc = self._bypass_service()
                # Frida bypass works best in spawn mode (advisory).
                if "frida" in requested and self.mode not in (
                    SpawnMode.SPAWN,
                    SpawnMode.SPAWN.value,
                ):
                    logger.warning(
                        "Frida bypass works best in SPAWN mode. Some detection "
                        "methods may trigger before hooks are installed."
                    )
                svc.start_many(requested)
                for key, cat in native_map.items():
                    if config.get(key) and svc.is_active(cat):
                        self.enabled_bypasses[key] = True
                        self._delegated_categories.add(cat)
                        any_enabled = True

            # Emulator — still needs TrigDroid's RPC device-profile bundle.
            if config.get("emulator_detection") and self._start_emulator_rpc(config):
                any_enabled = True

            if not any_enabled:
                logger.error("TrigDroid Bypass: no bypass categories enabled")
                return False

            # Coordinator task so the TUI toggle (is_running / stop) works even
            # though the actual jobs are owned by BypassService managers.
            get_task_service().register(
                name="trigdroid_bypass",
                display_name="TrigDroid Bypass",
                instance=self,
                stop_callback=self.stop,
                app_name=self.app_package,
                target_pid=self.process_id,
            )
            get_tool_usage_service().mark_used("trigdroid_bypass", files=[])

            logger.info("TrigDroid Bypass started")
            return True

        except Exception as e:
            logger.error(f"Failed to start TrigDroid Bypass: {e}")
            return False

    def _start_emulator_rpc(self, config: dict) -> bool:
        """Load the RPC bundle and enable emulator-detection bypass.

        Emulator spoofing has no native manager (incoherent field spoofing
        gives false confidence), so it stays on TrigDroid's compiled bundle.

        Returns:
            True if the emulator bypass job loaded.
        """
        if self._script_path is None:
            logger.error(
                "Emulator detection bypass requires the TrigDroid bundle "
                "(install the trigdroid package or run 'npm run build:bypass'). "
                "Other bypass categories run natively without it."
            )
            return False

        try:
            created = not self.job_manager.has_active_session()
            self._setup_session(config)

            conflicts = Toolbox.check_frida_hook_conflicts(self.HOOKS_REGISTRY)
            if conflicts:
                conflict_details = ", ".join(
                    f"{hook} (job: {job_id[:8]}...)"
                    for hook, job_id in conflicts.items()
                )
                logger.warning(
                    f"TrigDroid Bypass may conflict with existing hooks: "
                    f"{conflict_details}"
                )

            job = self.job_manager.start_job(
                self._script_path,
                custom_hooking_handler_name=self._message_handler,
                job_type="trigdroid_bypass",
                display_name="TrigDroid Bypass (emulator)",
                hooks_registry=self.HOOKS_REGISTRY,
                priority=5,
            )
            self.job_id = job.get_id() if job else None
            self.script = job.get_script_of_job() if job else None
            if self.job_id:
                Toolbox.register_frida_hooks(self.job_id, self.HOOKS_REGISTRY)

            if self.script:
                emu_config = (
                    config["emulator_detection"]
                    if isinstance(config["emulator_detection"], dict)
                    else {}
                )
                self.enable_emulator_bypass(emu_config)

            # Resume gate: only resume a process we created that is still
            # paused (mirrors BypassManagerBase; avoids double-resume).
            if created and self.job_manager.is_paused():
                try:
                    Toolbox.resume_spawned_process_after_hooks(
                        self.frida_device, self.process_id
                    )
                except (frida.ProcessNotFoundError, frida.InvalidOperationError) as exc:
                    logger.warning(f"Emulator bypass resume skipped: {exc}")

            return self.job_id is not None

        except Exception as e:
            logger.error(f"Failed to start emulator RPC bypass: {e}")
            return False

    def _delegate_to_bypass_service(
        self, category: str, enabled_key: str, label: str
    ) -> bool:
        """Enable a native bypass category via the BypassService.

        Self-contained — no RPC bundle required (that's the point: Sandroid
        intercepts hardened apps without the external trigdroid package).

        Args:
            category: BypassService category key ("ssl", "root", "frida", "debug").
            enabled_key: Key recorded in ``self.enabled_bypasses``.
            label: Human-readable label for log messages.

        Returns:
            True if the bypass is now active.
        """
        try:
            svc = self._bypass_service()
            if svc.is_active(category):
                logger.info(f"{label} already active")
                self.enabled_bypasses[enabled_key] = True
                self._delegated_categories.add(category)
                return True

            success, msg = svc.start(category, on_message=None)
            if success:
                self.enabled_bypasses[enabled_key] = True
                self._delegated_categories.add(category)
                logger.info(f"{label} enabled: {msg}")
                return True
            logger.error(f"Failed to enable {label}: {msg}")
            return False
        except Exception as e:
            logger.error(f"{label} failed: {e}")
            return False

    def enable_ssl_unpinning(self, config: dict = None) -> bool:
        """Enable SSL unpinning via the native BypassService ("ssl")."""
        return self._delegate_to_bypass_service(
            "ssl", "ssl_unpinning", "SSL unpinning bypass"
        )

    def enable_root_bypass(self, config: dict = None) -> bool:
        """Enable root detection bypass via the native BypassService ("root")."""
        return self._delegate_to_bypass_service(
            "root", "root_detection", "Root detection bypass"
        )

    def enable_frida_bypass(self, config: dict = None) -> bool:
        """Enable Frida detection bypass via the native BypassService ("frida").

        NOTE: For best results, this should be enabled in SPAWN mode so the
        anti-anti-Frida hooks install before the app starts running.
        """
        if self.mode != SpawnMode.SPAWN and self.mode != SpawnMode.SPAWN.value:
            logger.warning(
                "Frida bypass works best in SPAWN mode. "
                "Some detection methods may trigger before hooks are installed."
            )
        return self._delegate_to_bypass_service(
            "frida", "frida_detection", "Frida detection bypass"
        )

    def enable_debug_bypass(self, config: dict = None) -> bool:
        """Enable debug detection bypass via the native BypassService ("debug")."""
        return self._delegate_to_bypass_service(
            "debug", "debug_detection", "Debug detection bypass"
        )

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

    def get_status(self) -> dict:
        """Get status of all bypass hooks.

        Reports both the RPC bundle state (if loaded, used by emulator
        profiles) and the live state of any categories delegated to the
        native BypassService.

        Returns:
            Dict with bypass status information
        """
        svc = self._bypass_service()
        status = {
            "loaded": self.script is not None,
            "job_id": self.job_id,
            "app_package": self.app_package,
            "process_id": self.process_id,
            "mode": self.mode,
            "enabled_bypasses": self.enabled_bypasses,
            "delegated_bypasses": {
                cat: svc.is_active(cat)
                for cat in sorted(self._delegated_categories)
            },
        }
        if self.script:
            try:
                status["rpc_status"] = self.script.exports_sync.getStatus()
            except Exception as e:
                logger.error(f"Failed to get RPC status: {e}")
                status["error"] = str(e)
        return status

    def stop(self):
        """Stop TrigDroid bypass hooks.

        Note: This stops Frida hooks but keeps the target app running.
        """
        self._remove_activity_log()

        # Tear down native bypasses this instance delegated to BypassService.
        if self._delegated_categories:
            svc = self._bypass_service()
            for category in list(self._delegated_categories):
                try:
                    svc.stop(category)
                except Exception as e:
                    logger.warning(
                        f"Error stopping delegated {category} bypass: {e}"
                    )
            self._delegated_categories.clear()

        if self.job_id:
            Toolbox.unregister_frida_hooks(self.job_id)
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
