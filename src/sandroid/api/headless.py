"""Sandroid Headless API Implementation.

This module provides the complete implementation of SandroidAPI for headless
(non-interactive) usage. It enables programmatic access to all Sandroid
capabilities including forensic analysis, malware analysis, and security scanning.

Usage:
    from sandroid.api import SandroidHeadlessAPI, AnalysisMode

    async def main():
        api = SandroidHeadlessAPI()
        await api.initialize()

        # Run malware analysis
        results = await api.run_analysis(
            AnalysisMode.MALWARE,
            package="com.example.app",
            runs=3,
            capture_network=True,
        )

        print(json.dumps(results, indent=2))
        await api.shutdown()

    asyncio.run(main())
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .analysis_runners import (
    run_forensic_analysis,
    run_malware_analysis,
    run_security_analysis,
)
from .batch import batch_analyze
from .decorators import require_initialized
from .fritap_controller import HeadlessFriTapController
from .handlers import (
    AppHandler,
    DeviceHandler,
    ForensicHandler,
    MonitoringHandler,
    TaskHandler,
)
from .interfaces import (
    AnalysisConfig,
    AnalysisMode,
    AnalysisState,
    AnalysisStateEnum,
    CommandResult,
    MenuItem,
    MenuState,
    SandroidAPI,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sandroid.config import SandroidConfig
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

logger = logging.getLogger(__name__)

# Re-export for backwards compatibility
__all__ = ["SandroidHeadlessAPI", "batch_analyze"]


class SandroidHeadlessAPI(SandroidAPI):
    """Complete SandroidAPI implementation for headless usage.

    This class implements all 21 abstract methods from SandroidAPI, providing
    full programmatic access to Sandroid's capabilities without requiring
    the interactive TUI or Rich menu.

    The API supports three primary analysis modes:
    - FORENSIC: File system change detection, spotlight tracking, evidence collection
    - MALWARE: TrigDroid automated triggers, behavioral monitoring, network capture
    - SECURITY: Static APK analysis, vulnerability scanning

    Thread Safety:
        This implementation is designed for single-threaded async usage.
        For concurrent access, use appropriate synchronization.

    Attributes:
        config: Sandroid configuration instance
        adb: ADB interface for device communication
        toolbox: Core utility class reference
        _state: Current analysis state
        _spotlight_app: Currently targeted application

    Example:
        >>> api = SandroidHeadlessAPI()
        >>> await api.initialize()
        >>> result = await api.run_analysis(AnalysisMode.MALWARE, package="com.app")
        >>> await api.shutdown()
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        """Initialize the headless API.

        Args:
            config_path: Optional path to configuration file. If not provided,
                uses the standard config loading mechanism.
        """
        self._config_path = config_path
        self._config: SandroidConfig | None = None
        self._adb: Adb | None = None
        self._toolbox: type[Toolbox] | None = None
        self._state = AnalysisStateEnum.IDLE
        self._spotlight_app: str | None = None
        self._initialized = False
        self._event_handlers: list[Callable[[Any], None]] = []
        self._typed_handlers: dict[type, list[Callable[[Any], None]]] = {}
        self._analysis_start_time: datetime | None = None
        self._current_run = 0
        self._total_runs = 0

        # Lazily created on first use via property
        self._fritap_controller: HeadlessFriTapController | None = None

        # Handler delegates
        self._monitoring_handler = MonitoringHandler(self)
        self._device_handler = DeviceHandler(self)
        self._app_handler = AppHandler(self)
        self._task_handler = TaskHandler(self)
        self._forensic_handler = ForensicHandler(self)

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def config(self) -> SandroidConfig:
        """Get the configuration instance."""
        if self._config is None:
            raise RuntimeError("API not initialized. Call initialize() first.")
        return self._config

    @property
    def adb(self) -> Adb:
        """Get the ADB interface."""
        if self._adb is None:
            raise RuntimeError("API not initialized. Call initialize() first.")
        return self._adb

    @property
    def toolbox(self) -> type[Toolbox]:
        """Get the Toolbox class."""
        if self._toolbox is None:
            raise RuntimeError("API not initialized. Call initialize() first.")
        return self._toolbox

    @property
    def _fritap(self) -> HeadlessFriTapController:
        """Lazily create and return the FriTap controller."""
        if self._fritap_controller is None:
            self._fritap_controller = HeadlessFriTapController(
                adb=self._adb,
                get_spotlight_app=lambda: self._spotlight_app,
                set_spotlight_app=self._set_spotlight_app_name,
            )
        return self._fritap_controller

    def _set_spotlight_app_name(self, package: str) -> None:
        """Internal setter for spotlight app name used by FriTap controller."""
        self._spotlight_app = package

    # =========================================================================
    # Lifecycle (implements SandroidAPI)
    # =========================================================================

    async def initialize(self) -> CommandResult:
        """Initialize the API and connect to services.

        This method:
        1. Loads configuration from file or defaults
        2. Initializes ADB and Toolbox
        3. Validates environment (ADB, device connection)
        4. Sets up session folder and logging

        Returns:
            CommandResult indicating success or failure with details
        """
        try:
            # Load configuration
            from sandroid.config import ConfigLoader

            loader = ConfigLoader()
            if self._config_path:
                self._config = loader.load(config_file=str(self._config_path))
            else:
                self._config = loader.load()

            # Import and initialize core components
            from sandroid.core.adb import Adb
            from sandroid.core.toolbox import Toolbox

            # Set config on Toolbox (required for initialization)
            Toolbox.config = self._config

            # Initialize ADB first (required by Toolbox)
            Adb.init()
            self._adb = Adb

            # Initialize Toolbox
            Toolbox.init()

            # Initialize session files
            Toolbox.init_files()

            self._toolbox = Toolbox
            self._initialized = True

            # Reset FriTap controller so it picks up the new ADB
            self._fritap_controller = None

            # Validate environment
            from sandroid.services import get_setup_service

            setup_result = get_setup_service().check_critical_setup()
            if not setup_result.success:
                return CommandResult(
                    success=False,
                    message="Environment validation failed",
                    error="; ".join(setup_result.errors),
                )

            logger.info("Headless API initialized successfully")
            return CommandResult(
                success=True,
                message="Headless API initialized",
                data={
                    "config_file": (
                        str(self._config_path) if self._config_path else "default"
                    ),
                    "device_connected": await self.is_device_connected(),
                },
            )

        except Exception as e:
            logger.exception("Failed to initialize headless API")
            return CommandResult(
                success=False,
                message="Initialization failed",
                error=str(e),
            )

    async def shutdown(self) -> CommandResult:
        """Shutdown the API and cleanup resources.

        Stops all background tasks and releases resources.

        Returns:
            CommandResult indicating success
        """
        try:
            from sandroid.services import get_task_service

            # Stop all background tasks
            get_task_service().stop_all()

            # Wrap up Toolbox operations
            if self._toolbox:
                self._toolbox.wrap_up()

            self._initialized = False
            self._state = AnalysisStateEnum.IDLE

            logger.info("Headless API shutdown complete")
            return CommandResult(success=True, message="Shutdown complete")

        except Exception as e:
            logger.exception("Error during shutdown")
            return CommandResult(
                success=False,
                message="Shutdown error",
                error=str(e),
            )

    # =========================================================================
    # Extended Analysis Methods (headless-specific)
    # =========================================================================

    @require_initialized
    async def run_analysis(
        self,
        mode: AnalysisMode,
        package: str | None = None,
        runs: int = 2,
        capture_network: bool = False,
        compute_hashes: bool = False,
        track_deleted: bool = False,
        apk_path: str | None = None,
        output_file: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run analysis in the specified mode.

        This is the primary method for headless analysis. It configures and
        executes the appropriate analysis pipeline based on the mode.

        Args:
            mode: Analysis mode (FORENSIC, MALWARE, or SECURITY)
            package: Target package name (required for MALWARE mode)
            runs: Number of analysis runs (minimum 2 for noise detection)
            capture_network: Enable network traffic capture
            compute_hashes: Compute MD5 hashes for changed files
            track_deleted: Track deleted files during analysis
            apk_path: Path to APK file (required for SECURITY mode)
            output_file: Optional output file path for results
            **kwargs: Additional mode-specific options

        Returns:
            JSON-serializable dictionary with analysis results

        Raises:
            ValueError: If required parameters are missing for the mode
            RuntimeError: If API not initialized
        """
        self._state = AnalysisStateEnum.RUNNING
        self._analysis_start_time = datetime.now()
        self._current_run = 0
        self._total_runs = runs

        def _set_current_run(run: int) -> None:
            self._current_run = run

        try:
            if mode == AnalysisMode.MALWARE:
                if not package:
                    raise ValueError("Package name required for malware analysis")
                results = await run_malware_analysis(
                    toolbox=self._toolbox,
                    package=package,
                    runs=runs,
                    capture_network=capture_network,
                    compute_hashes=compute_hashes,
                    current_run_setter=_set_current_run,
                    **kwargs,
                )
            elif mode == AnalysisMode.FORENSIC:
                results = await run_forensic_analysis(
                    toolbox=self._toolbox,
                    runs=runs,
                    track_deleted=track_deleted,
                    compute_hashes=compute_hashes,
                    current_run_setter=_set_current_run,
                    **kwargs,
                )
            elif mode == AnalysisMode.SECURITY:
                if not apk_path:
                    raise ValueError("APK path required for security analysis")
                results = await run_security_analysis(
                    adb=self._adb,
                    toolbox=self._toolbox,
                    apk_path=apk_path,
                    **kwargs,
                )
            else:
                raise ValueError(f"Unknown analysis mode: {mode}")

            self._state = AnalysisStateEnum.COMPLETED

            # Save results if output file specified
            if output_file:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, default=str)
                logger.info(f"Results saved to: {output_path}")

            return results

        except Exception as e:
            self._state = AnalysisStateEnum.ERROR
            logger.exception(f"Analysis failed: {e}")
            raise

    @require_initialized
    async def run_headless_network(
        self,
        duration: int = 60,
        with_fritap: bool = False,
        fritap_package: str | None = None,
    ) -> dict[str, Any]:
        """Run headless network capture with optional FriTap integration.

        Args:
            duration: Capture duration in seconds (minimum 5, default 60).
            with_fritap: Whether to enable FriTap SSL keylog during capture.
            fritap_package: Target package name for FriTap.

        Returns:
            Dictionary with network capture and analysis results.

        Raises:
            RuntimeError: If the API has not been initialized.
            ValueError: If with_fritap is True but fritap_package is None.
        """
        return await self._fritap.run_network_capture(
            duration=duration,
            with_fritap=with_fritap,
            fritap_package=fritap_package,
            device_name=getattr(self._toolbox, "device_name", "unknown"),
        )

    # =========================================================================
    # Menu State (implements SandroidAPI)
    # =========================================================================

    async def get_menu_state(self) -> MenuState:
        """Get the current menu state.

        Returns:
            MenuState with available items and current context
        """
        from sandroid.services import get_task_service

        items = await self.get_available_commands()
        running_tasks = get_task_service().get_running()

        return MenuState(
            items=items,
            spotlight_app=self._spotlight_app,
            running_tasks=running_tasks,
            analysis_state=self._state,
        )

    async def get_available_commands(self) -> list[MenuItem]:
        """Get list of available commands.

        Returns:
            List of MenuItem objects representing available commands
        """
        from sandroid.commands import CommandRegistry
        from sandroid.services import get_ui_service

        registry = CommandRegistry.get()
        if not registry._initialized:
            registry.initialize_default_commands()

        current_view = get_ui_service().get_current_view()
        commands = registry.get_by_view(current_view)

        return [
            MenuItem(
                key=cmd.key,
                name=cmd.name,
                description=cmd.description,
                enabled=True,
                category=cmd.category,
            )
            for cmd in commands
        ]

    # =========================================================================
    # Command Execution (implements SandroidAPI)
    # =========================================================================

    async def execute_command(self, command_key: str) -> CommandResult:
        """Execute a command by its keyboard shortcut.

        Args:
            command_key: Single character command key (e.g., 's' for screenshot)

        Returns:
            CommandResult with success status and any data
        """
        from sandroid.commands import CommandRegistry
        from sandroid.commands.context_factory import create_context_with_toolbox

        registry = CommandRegistry.get()
        if not registry.has(command_key):
            return CommandResult(
                success=False,
                message=f"Command '{command_key}' not found",
            )

        ctx = create_context_with_toolbox(self._toolbox)
        result = await registry.execute(command_key, ctx)

        return CommandResult(
            success=result.success,
            message=result.message,
            data=result.data,
            error=result.error if hasattr(result, "error") else None,
        )

    async def can_execute_command(self, command_key: str) -> tuple[bool, str]:
        """Check if a command can be executed.

        Args:
            command_key: Single character command key

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        from sandroid.commands import CommandRegistry
        from sandroid.commands.context_factory import create_context_with_toolbox

        registry = CommandRegistry.get()
        if not registry.has(command_key):
            return False, f"Command '{command_key}' not found"

        handler = registry.get_handler(command_key)
        if handler and hasattr(handler, "can_execute"):
            ctx = create_context_with_toolbox(self._toolbox)
            can_exec, reason = handler.can_execute(ctx)
            return can_exec, reason

        return True, ""

    # =========================================================================
    # Analysis Control (implements SandroidAPI)
    # =========================================================================

    async def get_analysis_state(self) -> AnalysisState:
        """Get the current analysis state.

        Returns:
            AnalysisState with current progress and status
        """
        from sandroid.services import get_forensic_service

        forensic = get_forensic_service()

        return AnalysisState(
            state=self._state,
            run_number=self._current_run,
            total_runs=self._total_runs,
            progress_message=f"Run {self._current_run}/{self._total_runs}",
            started_at=self._analysis_start_time,
            spotlight_app=self._spotlight_app,
            changed_files_count=len(forensic.get_changed_files_cache() or {}),
        )

    async def start_analysis(self, config: AnalysisConfig) -> CommandResult:
        """Start an analysis run with the given configuration.

        Args:
            config: Analysis configuration

        Returns:
            CommandResult indicating success/failure
        """
        if self._state == AnalysisStateEnum.RUNNING:
            return CommandResult(
                success=False,
                message="Analysis already running",
            )

        try:
            mode = AnalysisMode.FORENSIC

            await self.run_analysis(
                mode=mode,
                runs=config.number_of_runs,
                capture_network=config.monitor_network,
                compute_hashes=config.hash_files,
                track_deleted=config.show_deleted,
            )

            return CommandResult(success=True, message="Analysis started")

        except Exception as e:
            return CommandResult(
                success=False,
                message="Failed to start analysis",
                error=str(e),
            )

    async def stop_analysis(self) -> CommandResult:
        """Stop the current analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        if self._state != AnalysisStateEnum.RUNNING:
            return CommandResult(
                success=False,
                message="No analysis running",
            )

        self._state = AnalysisStateEnum.IDLE
        return CommandResult(success=True, message="Analysis stopped")

    async def pause_analysis(self) -> CommandResult:
        """Pause the current analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        if self._state != AnalysisStateEnum.RUNNING:
            return CommandResult(
                success=False,
                message="No analysis running to pause",
            )

        self._state = AnalysisStateEnum.PAUSED
        return CommandResult(success=True, message="Analysis paused")

    async def resume_analysis(self) -> CommandResult:
        """Resume a paused analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        if self._state != AnalysisStateEnum.PAUSED:
            return CommandResult(
                success=False,
                message="No paused analysis to resume",
            )

        self._state = AnalysisStateEnum.RUNNING
        return CommandResult(success=True, message="Analysis resumed")

    # =========================================================================
    # Spotlight App Management (delegates to AppHandler)
    # =========================================================================

    async def get_spotlight_app(self) -> str | None:
        """Get the current spotlight application package name."""
        return await self._app_handler.get_spotlight_app()

    async def set_spotlight_app(
        self,
        package_name: str,
        mode: str = "attach",
    ) -> CommandResult:
        """Set the spotlight application."""
        return await self._app_handler.set_spotlight_app(package_name, mode)

    async def get_installed_apps(self) -> list[str]:
        """Get list of installed applications on device."""
        return await self._app_handler.get_installed_apps()

    # =========================================================================
    # FriTap Control (delegates to HeadlessFriTapController)
    # =========================================================================

    @require_initialized
    async def start_fritap(
        self,
        package: str | None = None,
        verbose: bool = False,
        keylog_output: str | None = None,
        json_output: str | None = None,
    ) -> CommandResult:
        """Start FriTap SSL/TLS key extraction (non-blocking)."""
        return await self._fritap.start(
            package=package,
            verbose=verbose,
            keylog_output=keylog_output,
            json_output=json_output,
        )

    async def stop_fritap(self, timeout: float = 5.0) -> CommandResult:
        """Stop FriTap SSL/TLS key extraction."""
        return await self._fritap.stop(timeout=timeout)

    async def is_fritap_running(self) -> bool:
        """Check if FriTap is currently running."""
        return await self._fritap.is_running()

    # =========================================================================
    # Malware Monitor (delegates to MonitoringHandler)
    # =========================================================================

    @require_initialized
    async def start_malware_monitor(
        self,
        package: str | None = None,
        hook_config: dict[str, bool] | None = None,
        enable_fritap: bool = False,
        enable_stacktrace: bool = False,
    ) -> CommandResult:
        """Start the dexray-intercept malware monitor (non-blocking)."""
        return await self._monitoring_handler.start_malware_monitor(
            package=package,
            hook_config=hook_config,
            enable_fritap=enable_fritap,
            enable_stacktrace=enable_stacktrace,
        )

    @require_initialized
    async def stop_malware_monitor(self) -> CommandResult:
        """Stop the running dexray-intercept malware monitor."""
        return await self._monitoring_handler.stop_malware_monitor()

    # =========================================================================
    # Device Operations (delegates to DeviceHandler)
    # =========================================================================

    @require_initialized
    async def set_proxy(self, ip: str, port: str) -> CommandResult:
        """Set HTTP proxy on the connected device."""
        return await self._device_handler.set_proxy(ip, port)

    @require_initialized
    async def clear_proxy(self) -> CommandResult:
        """Clear HTTP proxy settings on the device."""
        return await self._device_handler.clear_proxy()

    @require_initialized
    async def get_proxy_settings(self) -> CommandResult:
        """Get current HTTP proxy settings from the device."""
        return await self._device_handler.get_proxy_settings()

    @require_initialized
    async def install_apk(
        self, apk_path: str, set_as_spotlight: bool = False
    ) -> CommandResult:
        """Install an APK on the connected device."""
        return await self._app_handler.install_apk(apk_path, set_as_spotlight)

    @require_initialized
    async def configure_device_settings(
        self,
        settings: dict[str, Any] | None = None,
        preset: str | None = None,
        settings_file: str | None = None,
    ) -> CommandResult:
        """Configure device environment settings."""
        return await self._device_handler.configure_device_settings(
            settings=settings, preset=preset, settings_file=settings_file
        )

    @require_initialized
    async def take_screenshot(self, filename: str | None = None) -> CommandResult:
        """Take a screenshot of the device screen."""
        return await self._device_handler.take_screenshot(filename)

    @require_initialized
    async def create_snapshot(self, name: str | None = None) -> CommandResult:
        """Create an emulator snapshot."""
        return await self._device_handler.create_snapshot(name)

    @require_initialized
    async def load_snapshot(self, name: str) -> CommandResult:
        """Load an emulator snapshot."""
        return await self._device_handler.load_snapshot(name)

    @require_initialized
    async def list_snapshots(self) -> CommandResult:
        """List available emulator snapshots."""
        return await self._device_handler.list_snapshots()

    # =========================================================================
    # Screen Recording, Monitor, Action Import/Export (delegates to handlers)
    # =========================================================================

    @require_initialized
    async def start_screen_recording(
        self, filename: str | None = None
    ) -> CommandResult:
        """Start screen recording on the device."""
        return await self._device_handler.start_screen_recording(filename)

    @require_initialized
    async def stop_screen_recording(self) -> CommandResult:
        """Stop screen recording on the device."""
        return await self._device_handler.stop_screen_recording()

    @require_initialized
    async def start_monitor(
        self, mode: str = "auto", path: str | None = None
    ) -> CommandResult:
        """Start Monitor filesystem monitoring."""
        return await self._monitoring_handler.start_monitor(mode=mode, path=path)

    @require_initialized
    async def stop_monitor(self) -> CommandResult:
        """Stop Monitor filesystem monitoring."""
        return await self._monitoring_handler.stop_monitor()

    @require_initialized
    async def import_action(self, file_path: str) -> CommandResult:
        """Import an action recording file."""
        return await self._forensic_handler.import_action(file_path)

    @require_initialized
    async def export_results(self, filename: str | None = None) -> CommandResult:
        """Export analysis results to a file."""
        return await self._forensic_handler.export_results(filename)

    # =========================================================================
    # Network Capture (delegates to MonitoringHandler)
    # =========================================================================

    @require_initialized
    async def start_network_capture(
        self, output_file: str | None = None
    ) -> CommandResult:
        """Start network traffic capture on the device."""
        return await self._monitoring_handler.start_network_capture(output_file)

    @require_initialized
    async def stop_network_capture(self) -> CommandResult:
        """Stop network traffic capture and pull the PCAP file."""
        return await self._monitoring_handler.stop_network_capture()

    # =========================================================================
    # Background Tasks (delegates to TaskHandler)
    # =========================================================================

    async def get_running_tasks(self) -> dict[str, dict[str, Any]]:
        """Get status of all running background tasks."""
        return await self._task_handler.get_running_tasks()

    async def stop_task(self, task_name: str) -> CommandResult:
        """Stop a specific background task."""
        return await self._task_handler.stop_task(task_name)

    async def stop_all_tasks(self) -> CommandResult:
        """Stop all running background tasks."""
        return await self._task_handler.stop_all_tasks()

    # =========================================================================
    # Forensic Operations (delegates to ForensicHandler)
    # =========================================================================

    async def get_spotlight_files(self) -> list[str]:
        """Get list of spotlight files being tracked."""
        return await self._forensic_handler.get_spotlight_files()

    async def add_spotlight_file(self, file_path: str) -> CommandResult:
        """Add a file to spotlight tracking."""
        return await self._forensic_handler.add_spotlight_file(file_path)

    async def remove_spotlight_file(self, file_path: str) -> CommandResult:
        """Remove a file from spotlight tracking."""
        return await self._forensic_handler.remove_spotlight_file(file_path)

    async def pull_spotlight_files(self) -> CommandResult:
        """Pull all spotlight files from device."""
        return await self._forensic_handler.pull_spotlight_files()

    # =========================================================================
    # Event Subscription (implements SandroidAPI)
    # =========================================================================

    def subscribe_events(
        self,
        handler: Callable[[Any], None],
    ) -> Callable[[], None]:
        """Subscribe to all events.

        Args:
            handler: Function to call when events occur

        Returns:
            Unsubscribe function to call when done
        """
        self._event_handlers.append(handler)

        # Also subscribe to EventBus if available
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            bus.subscribe_all(handler)
        except (ImportError, RuntimeError):
            pass

        def unsubscribe() -> None:
            if handler in self._event_handlers:
                self._event_handlers.remove(handler)
            try:
                from sandroid.core.events import EventBus

                bus = EventBus.get()
                bus.unsubscribe_all(handler)
            except (ImportError, RuntimeError):
                pass

        return unsubscribe

    def subscribe_event_type(
        self,
        event_type: type,
        handler: Callable[[Any], None],
    ) -> Callable[[], None]:
        """Subscribe to specific event type.

        Args:
            event_type: Type of events to receive
            handler: Function to call when events occur

        Returns:
            Unsubscribe function to call when done
        """
        if event_type not in self._typed_handlers:
            self._typed_handlers[event_type] = []
        self._typed_handlers[event_type].append(handler)

        # Also subscribe to EventBus if available
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            bus.subscribe(event_type, handler)
        except (ImportError, RuntimeError):
            pass

        def unsubscribe() -> None:
            if event_type in self._typed_handlers:
                if handler in self._typed_handlers[event_type]:
                    self._typed_handlers[event_type].remove(handler)
            try:
                from sandroid.core.events import EventBus

                bus = EventBus.get()
                bus.unsubscribe(event_type, handler)
            except (ImportError, RuntimeError):
                pass

        return unsubscribe

    # =========================================================================
    # Device Information (implements SandroidAPI)
    # =========================================================================

    async def get_device_info(self) -> dict[str, Any]:
        """Get information about the connected device."""
        from sandroid.services import get_device_service

        device_service = get_device_service()
        return device_service.get_device_info()

    async def is_device_connected(self) -> bool:
        """Check if a device is connected."""
        from sandroid.services import get_device_service

        device_service = get_device_service()
        return device_service.has_active_device()
