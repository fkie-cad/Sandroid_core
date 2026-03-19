"""Network commands for FriTap, proxy, and network capture."""

import logging

from sandroid.services import (
    get_network_capture_service,
    get_spotlight_service,
    get_task_service,
    get_ui_service,
)

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
    RequiresSpotlightApp,
    ToggleCommand,
)

logger = logging.getLogger(__name__)


class FriTapCommand(ToggleCommand, RequiresSpotlightApp):
    """Command to start/stop FriTap SSL/TLS interception.

    FriTap intercepts SSL/TLS traffic from the spotlight application,
    capturing encrypted network communications for analysis. It provides:
    - SSL/TLS key extraction (SSLKEYLOGFILE format)
    - Connection data logging (source/dest IPs, ports, data)
    - JSON output for structured analysis

    This is a toggle command - pressing the key starts FriTap if not running,
    or stops it if already running.

    Note: is_blocking_io=True because Frida's attach/spawn operations conflict
    with asyncio.run() when called from TUI worker threads. This ensures the
    same execution path as CLI mode.
    """

    key = "h"
    name = "FriTap"
    description = "Start/stop FriTap SSL/TLS interception"
    category = CommandCategory.NETWORK
    views = ["forensic", "malware", "security"]

    # Frida operations conflict with asyncio.run() - use blocking execution path
    is_blocking_io = True

    def execute_blocking(self, ctx: CommandContext) -> CommandResult:
        """Execute FriTap command synchronously (blocking I/O path).

        This method is called directly from worker threads without asyncio.run()
        to avoid conflicts with Frida's internal threading model.
        """
        if self.is_task_running(ctx):
            return self._stop_fritap(ctx)
        return self._start_fritap(ctx)

    def get_task_name(self) -> str:
        """Get the task identifier for FriTap."""
        return "fritap"

    def is_task_running(self, ctx: CommandContext) -> bool:
        """Check if FriTap is currently running.

        Checks TaskService first, then falls back to FridaSessionService
        to detect running FriTap even if registration failed.
        """
        # Check context TaskService, then global TaskService
        if ctx.task_service and ctx.task_service.is_running("fritap"):
            return True

        if get_task_service().is_running("fritap"):
            return True

        # Fallback: Check FridaSessionService for active FriTap jobs
        try:
            from sandroid.services import get_frida_session_service

            frida_service = get_frida_session_service()
            if frida_service.has_active_session():
                for job_info in frida_service.get_running_jobs():
                    if job_info.get("job_type") == "fritap":
                        return True
        except Exception as e:
            logger.debug(f"FridaSessionService check failed: {e}")

        return False

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check preconditions for FriTap execution.

        When starting FriTap, requires:
        - Task service available
        - A spotlight app to be selected
        - Frida server to be running

        When stopping, only needs task service.
        """
        valid, msg = self._validate_task_service(ctx)
        if not valid:
            return (False, msg)

        # If already running, can always stop
        if self.is_task_running(ctx):
            return True, ""

        # Check spotlight app requirement for starting
        can_exec, reason = RequiresSpotlightApp.can_execute(self, ctx)
        if not can_exec:
            return can_exec, reason

        # Check Frida server is running
        if ctx.toolbox and hasattr(ctx.toolbox, "frida_manager"):
            if not ctx.toolbox.frida_manager.is_frida_server_running():
                return (
                    False,
                    "Frida server not running. Press 'f' to start Frida first.",
                )

        return True, ""

    def _start_fritap(self, ctx: CommandContext) -> CommandResult:
        """Start FriTap SSL/TLS interception.

        Creates a FriTap instance, shows configuration dialog,
        and starts interception on the spotlight application.
        This method is shared between sync and async execution paths.
        """
        try:
            from sandroid.analysis.fritap import FriTap

            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            app_info = get_spotlight_service().get_app_tuple()
            app_name = app_info[0] if app_info else "unknown"
            logger.info(f"Starting FriTap for {app_name}")

            fritap = FriTap()
            success = fritap.start(interactive=True)

            if not success:
                return CommandResult(
                    success=False,
                    message="FriTap startup cancelled or failed",
                    error="User cancelled configuration or startup error occurred",
                )

            # Register with task_service
            task_service = ctx.task_service or get_task_service()
            try:
                task_service.register(
                    name="fritap",
                    display_name="FriTap",
                    instance=fritap,
                    stop_callback=fritap.stop,
                    app_name=fritap.app_package,
                    target_pid=fritap.process_id,
                )
                logger.debug(
                    f"FriTap registered with TaskService (pid={fritap.process_id})"
                )
            except Exception as e:
                logger.error(
                    f"Failed to register FriTap with TaskService: {e}. "
                    f"FriTap is running (job_id={fritap.job_id}) but menu state may be incorrect."
                )

            # Collect output file paths
            output_files = [
                path
                for attr in ("keylog_path", "json_output_path", "log_path")
                if (path := getattr(fritap, attr, None))
            ]

            return CommandResult(
                success=True,
                message=f"FriTap started for {fritap.app_package} (PID: {fritap.process_id})",
                data={
                    "app_package": fritap.app_package,
                    "pid": fritap.process_id,
                    "mode": fritap.mode,
                    "output_files": output_files,
                    "action": "started",
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import FriTap: {e}")
            return CommandResult(
                success=False,
                message="FriTap module not available",
                error=f"Import error: {e}. Is friTap installed?",
            )
        except Exception as e:
            logger.exception("Error starting FriTap")
            return CommandResult(
                success=False,
                message=f"FriTap startup failed: {e!s}",
                error=str(e),
            )

    def _stop_fritap(self, ctx: CommandContext) -> CommandResult:
        """Stop FriTap SSL/TLS interception.

        Uses dual-path cleanup: TaskService for registered tasks,
        JobManager directly for unregistered/orphaned sessions.
        This method is shared between sync and async execution paths.
        """
        try:
            # Path 1: Try TaskService first
            task_service = ctx.task_service or get_task_service()
            if task_service.is_running("fritap"):
                task_service.stop("fritap")
                logger.info("FriTap stopped via TaskService")
                return CommandResult(
                    success=True,
                    message="FriTap stopped",
                    data={"action": "stopped"},
                )

            # Path 2: Fallback to JobManager for orphaned sessions
            from sandroid.services import get_frida_session_service

            frida_service = get_frida_session_service()

            if frida_service.has_active_session():
                job_manager = frida_service.get_job_manager()
                stopped_any = False

                for job_info in frida_service.get_running_jobs():
                    if job_info.get("job_type") == "fritap":
                        job_id = job_info.get("job_id")
                        if job_id:
                            logger.info(f"Stopping orphaned FriTap job {job_id[:8]}...")
                            try:
                                job_manager.stop_job_with_id(job_id, timeout=3.0)
                                stopped_any = True
                            except Exception as e:
                                logger.warning(f"Error stopping job {job_id}: {e}")

                if stopped_any:
                    # Detach if no other jobs remain
                    if not frida_service.get_running_jobs():
                        try:
                            job_manager.detach_from_app(timeout=2.0)
                        except Exception:
                            pass
                    return CommandResult(
                        success=True,
                        message="FriTap stopped",
                        data={"action": "stopped"},
                    )

            return CommandResult(
                success=False,
                message="FriTap is not running",
                error="No active FriTap session found",
            )

        except Exception as e:
            logger.exception("Error stopping FriTap")
            return CommandResult(
                success=False,
                message=f"Error stopping FriTap: {e!s}",
                error=str(e),
            )

    async def start_task(self, ctx: CommandContext) -> CommandResult:
        """Start FriTap SSL/TLS interception (async wrapper)."""
        return self._start_fritap(ctx)

    async def stop_task(self, ctx: CommandContext) -> CommandResult:
        """Stop FriTap SSL/TLS interception (async wrapper)."""
        return self._stop_fritap(ctx)


class ProxyConfigCommand(CommandHandler):
    """Command to configure device proxy settings.

    Opens a configuration dialog for:
    - Setting/unsetting HTTP proxy on the device
    - Managing CA certificates for SSL interception
    - Zygote CA injection for system-wide SSL trust

    In TUI mode, opens a modal dialog with full configuration options.
    In console mode, uses interactive prompts.
    """

    key = "y"
    name = "Proxy Configuration"
    description = "Configure device proxy settings"
    category = CommandCategory.NETWORK
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute proxy configuration.

        Opens proxy configuration modal in TUI mode or uses
        console prompts otherwise.
        """
        try:
            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            # Check if TUI mode with UI bus available
            if ctx.is_tui_mode and ctx.ui_bus:
                return await self._handle_tui_mode(ctx)
            return await self._handle_console_mode(ctx)

        except ImportError as e:
            logger.error(f"Failed to import proxy manager: {e}")
            return CommandResult(
                success=False,
                message="Proxy manager not available",
                error=f"Import error: {e}",
            )
        except Exception as e:
            logger.exception("Error in proxy configuration")
            return CommandResult(
                success=False,
                message=f"Proxy configuration failed: {e!s}",
                error=str(e),
            )

    async def _handle_tui_mode(self, ctx: CommandContext) -> CommandResult:
        """Handle proxy configuration in TUI mode using modal.

        Shows the ProxyModal for full configuration options including
        CA certificate management and Zygote injection.
        """
        try:
            # Try to get the TUI app and push modal
            if hasattr(ctx.ui_bus, "request_proxy_config"):
                result = await ctx.ui_bus.request_proxy_config()

                if result and not result.cancelled:
                    if result.action == "set_proxy" and result.proxy_config:
                        return CommandResult(
                            success=True,
                            message=f"Proxy set to {result.proxy_config.address}",
                            data={
                                "action": "set_proxy",
                                "proxy_address": result.proxy_config.address,
                            },
                        )
                    if result.action == "unset_proxy":
                        return CommandResult(
                            success=True,
                            message="Proxy cleared",
                            data={"action": "unset_proxy"},
                        )
                    if result.action == "inject_ca":
                        return CommandResult(
                            success=True,
                            message="CA certificate injected into Zygote",
                            data={
                                "action": "inject_ca",
                                "ca_path": str(result.ca_path),
                            },
                        )
                    if result.action == "push_ca":
                        return CommandResult(
                            success=True,
                            message="CA certificate pushed to device",
                            data={"action": "push_ca", "ca_path": str(result.ca_path)},
                        )

                return CommandResult(
                    success=True,
                    message="Proxy configuration cancelled",
                    data={"action": "cancelled"},
                )

            # If direct modal support isn't available, try showing warning
            get_ui_service().show_blocking_info(
                title="Proxy Configuration",
                message="Please use the proxy configuration in the TUI interface.",
                action_hint="Press 'y' in the TUI to configure proxy",
            )

            return CommandResult(
                success=True,
                message="Proxy configuration not available in this context",
                data={"action": "not_available"},
            )

        except Exception as e:
            logger.exception("Error showing proxy modal")
            return CommandResult(
                success=False,
                message=f"Error showing proxy configuration: {e!s}",
                error=str(e),
            )

    async def _handle_console_mode(self, ctx: CommandContext) -> CommandResult:
        """Handle proxy configuration in console mode.

        Uses interactive prompts to configure proxy settings.
        """
        from sandroid.core.proxy_manager import ProxyConfig, ProxyManager, ProxyStatus

        proxy_manager = ProxyManager()

        # Get current status
        status, current_config = proxy_manager.get_proxy_settings()

        # Show current status
        if status == ProxyStatus.SET and current_config:
            logger.info(f"Current proxy: {current_config.address}")
        else:
            logger.info("No proxy currently configured")

        # Get user input for new proxy
        try:
            default_config = proxy_manager.get_default_config()

            if ctx.request_input:
                user_input = await ctx.request_input(
                    title="Proxy Configuration",
                    prompt="Enter proxy address (IP:PORT) or leave blank to clear:",
                    placeholder=f"{default_config.ip}:{default_config.port}",
                )
            else:
                user_input = ctx.toolbox.safe_input(
                    f"Enter proxy address (IP:PORT) or leave blank to clear [{default_config.address}]: "
                )

            # Handle empty input
            if user_input is None:
                return CommandResult(
                    success=True,
                    message="Proxy configuration cancelled",
                    data={"action": "cancelled"},
                )

            user_input = user_input.strip()

            if not user_input:
                # Clear proxy
                success, message = proxy_manager.unset_proxy()
                return CommandResult(
                    success=success,
                    message=message,
                    data={"action": "unset_proxy"},
                )

            # Set new proxy
            try:
                new_config = ProxyConfig.from_string(user_input)
                success, message = proxy_manager.set_proxy(new_config)
                return CommandResult(
                    success=success,
                    message=message,
                    data={"action": "set_proxy", "proxy_address": new_config.address},
                )
            except ValueError as e:
                return CommandResult(
                    success=False,
                    message=f"Invalid proxy format: {e}",
                    error=str(e),
                )

        except Exception as e:
            logger.exception("Error getting proxy input")
            return CommandResult(
                success=False,
                message=f"Error during proxy configuration: {e!s}",
                error=str(e),
            )


class NetworkCaptureCommand(ToggleCommand):
    """Command to start/stop tcpdump network capture.

    Captures network traffic from the emulator using tcpdump via
    the emulator's network capture feature. Creates pcap files
    in the results directory for analysis.

    This is a toggle command - pressing the key starts capture if not running,
    or stops it if already running.
    """

    key = "w"
    name = "Network Capture"
    description = "Start/stop tcpdump network capture"
    category = CommandCategory.NETWORK
    views = ["forensic", "malware"]

    def get_task_name(self) -> str:
        """Get the task identifier for network capture."""
        return "network"

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check preconditions for network capture.

        Requires task_service for task registration and toolbox for network operations.
        """
        # Validate task_service
        valid, msg = self._validate_task_service(ctx)
        if not valid:
            return (False, msg)

        # Validate toolbox for network capture
        if not ctx.toolbox:
            return (False, "Toolbox not available")

        return (True, "")

    def is_task_running(self, ctx: CommandContext) -> bool:
        """Check if network capture is currently running."""
        if ctx.task_service and ctx.task_service.is_running("network"):
            return True
        # Fall back to NetworkCaptureService for backwards compatibility
        return get_network_capture_service().is_capturing()

    async def start_task(self, ctx: CommandContext) -> CommandResult:
        """Start network capture using tcpdump.

        Creates a Network instance and starts packet capture.
        The capture runs in a background thread until stopped.
        """
        try:
            from sandroid.analysis.network import Network

            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            # Create Network instance
            network = Network()

            # Get expected capture file path BEFORE starting
            capture_file = network.get_expected_capture_path()
            logger.info(f"Starting network capture to: {capture_file}")

            # Start capture (runs in background thread)
            network.gather()

            # Register with task_service
            task_service = ctx.task_service or get_task_service()
            task_service.register(
                name="network",
                display_name="Network Capture",
                instance=network,
                stop_callback=network.stop,
            )

            return CommandResult(
                success=True,
                message=f"Network capture started.\nSaving to: {capture_file}\nPress 'w' again to stop.",
                data={
                    "action": "started",
                    "capture_file": capture_file,
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import Network: {e}")
            return CommandResult(
                success=False,
                message="Network capture module not available",
                error=f"Import error: {e}. Is scapy installed?",
            )
        except Exception as e:
            logger.exception("Error starting network capture")
            return CommandResult(
                success=False,
                message=f"Network capture failed: {e!s}",
                error=str(e),
            )

    async def stop_task(self, ctx: CommandContext) -> CommandResult:
        """Stop network capture.

        Stops the tcpdump capture and saves the pcap file.
        """
        try:
            # Get capture file before stopping (for message)
            capture_file = get_network_capture_service().get_capture_file()

            task_service = ctx.task_service or get_task_service()
            if task_service.is_running("network"):
                task_service.stop("network")
                return CommandResult(
                    success=True,
                    message=f"Network capture stopped.\nSaved to: {capture_file or 'unknown'}",
                    data={
                        "action": "stopped",
                        "capture_file": capture_file,
                    },
                )

            # Try direct service check as last resort
            if get_network_capture_service().is_capturing():
                # Try to get the network instance from background tasks
                task = task_service.get_task("network")
                if (
                    task
                    and hasattr(task, "instance")
                    and hasattr(task.instance, "stop")
                ):
                    task.instance.stop()
                    task_service.unregister("network")
                    return CommandResult(
                        success=True,
                        message="Network capture stopped",
                        data={"action": "stopped", "capture_file": capture_file},
                    )

            return CommandResult(
                success=False,
                message="Could not stop network capture",
                error="Network capture task not found",
            )

        except Exception as e:
            logger.exception("Error stopping network capture")
            return CommandResult(
                success=False,
                message=f"Error stopping network capture: {e!s}",
                error=str(e),
            )


def register_commands(registry) -> None:
    """Register all network commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(FriTapCommand())
    registry.register(ProxyConfigCommand())
    registry.register(NetworkCaptureCommand())
