"""FriTap controller for the Sandroid Headless API.

Encapsulates all FriTap SSL/TLS key extraction operations including
starting, stopping, and status checking of FriTap sessions.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import TYPE_CHECKING, Any

from .interfaces import CommandResult

if TYPE_CHECKING:
    from collections.abc import Callable

    from sandroid.core.adb import Adb

logger = logging.getLogger(__name__)


class HeadlessFriTapController:
    """Manages FriTap lifecycle for headless API usage.

    This controller handles starting and stopping FriTap SSL/TLS key
    extraction sessions, including spotlight app configuration, task
    registration, and graceful shutdown with timeout support.

    Args:
        adb: ADB interface for device communication.
        get_spotlight_app: Callback returning the current spotlight app name.
        set_spotlight_app: Callback to update the current spotlight app name.

    Example::

        controller = HeadlessFriTapController(
            adb=adb_instance,
            get_spotlight_app=lambda: self._spotlight_app,
            set_spotlight_app=lambda pkg: setattr(self, '_spotlight_app', pkg),
        )
        result = await controller.start(package="com.example.app")
    """

    def __init__(
        self,
        adb: Adb | None,
        get_spotlight_app: Callable[[], str | None] | None = None,
        set_spotlight_app: Callable[[str], None] | None = None,
    ) -> None:
        self._adb = adb
        self._get_spotlight_app = get_spotlight_app
        self._set_spotlight_app = set_spotlight_app

    async def start(
        self,
        package: str | None = None,
        verbose: bool = False,
        keylog_output: str | None = None,
        json_output: str | None = None,
    ) -> CommandResult:
        """Start FriTap SSL/TLS key extraction (non-blocking).

        FriTap intercepts SSL/TLS traffic from the target application,
        capturing encryption keys for traffic decryption. Runs until
        stop() or API shutdown is called.

        This method returns immediately after starting the FriTap job.
        Hook loading happens asynchronously in a background thread.

        Note:
            First-time Frida attach can be slow (15-30s) due to JIT
            compilation and caching. Subsequent runs are fast (~3s).

        Args:
            package: Target package name. If None, uses current spotlight app.
            verbose: Enable verbose logging output.
            keylog_output: Path for SSLKEYLOGFILE output (optional).
            json_output: Path for JSON traffic log (optional).

        Returns:
            CommandResult with success status and output file paths.
            Note: Success means job was started, not that hooks are loaded.
        """
        try:
            from sandroid.analysis.fritap import FriTap
            from sandroid.services import get_spotlight_service, get_task_service

            # Set spotlight app if specified
            if package:
                spotlight = get_spotlight_service()

                # Check if app is already running - use attach mode if so
                pid = self._adb.get_pid_for_package_name(package) if self._adb else None

                if pid:
                    # App is running - use attach mode
                    logger.info(
                        f"App {package} is running (PID: {pid}), using attach mode"
                    )
                    spotlight.set_app(package, pid=pid)
                else:
                    # App not running - use spawn mode
                    logger.info(f"App {package} not running, using spawn mode")
                    spotlight.set_spawn_app(package, auto_resume=True)

                if self._set_spotlight_app:
                    self._set_spotlight_app(package)

            # Check spotlight is set
            effective_package = get_spotlight_service().get_effective_package()
            if not effective_package:
                return CommandResult(
                    success=False,
                    message="No target application specified",
                    error="Provide package parameter or set spotlight app first",
                )

            logger.info(f"Starting FriTap for {effective_package}")

            # Create and start FriTap
            fritap = FriTap()

            # Configure output paths if provided
            if keylog_output:
                fritap.keylog_path = keylog_output
            if json_output:
                fritap.json_output_path = json_output

            # Start in non-interactive mode for headless
            success = fritap.start(interactive=False)

            if not success:
                return CommandResult(
                    success=False,
                    message="FriTap startup failed",
                    error="Could not start FriTap - check Frida server is running",
                )

            # Register with TaskService
            task_service = get_task_service()
            try:
                task_service.register(
                    name="fritap",
                    display_name="FriTap",
                    instance=fritap,
                    stop_callback=fritap.stop,
                    app_name=fritap.app_package,
                    target_pid=fritap.process_id,
                )
            except Exception as e:
                logger.warning(f"FriTap task registration failed: {e}")

            # Collect output paths
            output_files = []
            if hasattr(fritap, "keylog_path") and fritap.keylog_path:
                output_files.append(str(fritap.keylog_path))
            if hasattr(fritap, "json_output_path") and fritap.json_output_path:
                output_files.append(str(fritap.json_output_path))

            return CommandResult(
                success=True,
                message=(
                    f"FriTap job started for {fritap.app_package} "
                    f"(PID: {fritap.process_id}) - hooks loading in background"
                ),
                data={
                    "app_package": fritap.app_package,
                    "pid": fritap.process_id,
                    "mode": fritap.mode,
                    "output_files": output_files,
                },
            )

        except ImportError as e:
            return CommandResult(
                success=False,
                message="FriTap not available",
                error=f"Import error: {e}. Is friTap installed?",
            )
        except Exception as e:
            logger.exception("Error starting FriTap")
            return CommandResult(
                success=False,
                message=f"FriTap error: {e}",
                error=str(e),
            )

    async def stop(self, timeout: float = 5.0) -> CommandResult:
        """Stop FriTap SSL/TLS key extraction.

        Stops FriTap gracefully and returns information about captured data.
        Uses timeout to prevent hanging if Frida connection is broken.

        Args:
            timeout: Maximum time in seconds to wait for stop (default: 5.0)

        Returns:
            CommandResult with success status and output file paths.
        """

        def _stop_fritap_sync() -> tuple[bool, list[str]]:
            """Synchronous stop helper that runs in a thread."""
            from sandroid.services import (
                get_frida_session_service,
                get_task_service,
            )

            task_service = get_task_service()
            stopped = False
            output_files: list[str] = []

            # Try TaskService first
            if task_service.is_running("fritap"):
                task = task_service.get_task("fritap")
                if task and hasattr(task, "instance"):
                    fritap = task.instance
                    if hasattr(fritap, "keylog_path") and fritap.keylog_path:
                        output_files.append(str(fritap.keylog_path))
                    if hasattr(fritap, "json_output_path") and fritap.json_output_path:
                        output_files.append(str(fritap.json_output_path))

                try:
                    task_service.stop("fritap")
                    stopped = True
                    logger.info("FriTap stopped via TaskService")
                except Exception as e:
                    logger.warning(f"TaskService stop failed: {e}")

            # Fallback: Check FridaSessionService for orphaned jobs
            if not stopped:
                try:
                    frida_service = get_frida_session_service()
                    if frida_service.has_active_session():
                        for job_info in frida_service.get_running_jobs():
                            if job_info.get("job_type") == "fritap":
                                job_id = job_info.get("job_id")
                                if job_id:
                                    try:
                                        job_manager = frida_service.get_job_manager()
                                        job_manager.stop_job_with_id(
                                            job_id, timeout=2.0
                                        )
                                        stopped = True
                                        logger.info(
                                            f"FriTap stopped via JobManager "
                                            f"(job_id={job_id[:8]})"
                                        )
                                    except Exception as e:
                                        logger.warning(f"JobManager stop failed: {e}")
                                        # Force unregister even if stop failed
                                        stopped = True
                except Exception as e:
                    logger.warning(f"FridaSessionService check failed: {e}")

            return stopped, output_files

        try:
            # Run stop in a thread with timeout to prevent hanging
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_stop_fritap_sync)
                try:
                    stopped, output_files = future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    logger.warning(
                        f"FriTap stop timed out after {timeout}s - force stopping"
                    )
                    # Force cleanup - the connection is likely broken
                    stopped = True
                    output_files = []

            if stopped:
                return CommandResult(
                    success=True,
                    message="FriTap stopped",
                    data={"output_files": output_files},
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
                message=f"Error stopping FriTap: {e}",
                error=str(e),
            )

    async def is_running(self) -> bool:
        """Check if FriTap is currently running.

        Returns:
            True if FriTap is active, False otherwise.
        """
        try:
            from sandroid.services import (
                get_frida_session_service,
                get_task_service,
            )

            # Check TaskService
            if get_task_service().is_running("fritap"):
                return True

            # Check FridaSessionService for unregistered jobs
            frida_service = get_frida_session_service()
            if frida_service.has_active_session():
                for job_info in frida_service.get_running_jobs():
                    if job_info.get("job_type") == "fritap":
                        return True

            return False
        except Exception:  # Best-effort check; any failure means "not running"
            return False

    async def _try_start_fritap(self, package: str) -> tuple[bool, dict[str, Any]]:
        """Attempt to start FriTap and return status info.

        Args:
            package: Target package name for FriTap.

        Returns:
            Tuple of (started_successfully, fritap_status_dict).
        """
        try:
            result = await self.start(package=package)
            if result.success:
                return True, {
                    "enabled": True,
                    "package": package,
                    "status": "running",
                }
            return False, {
                "enabled": False,
                "package": package,
                "status": "failed",
                "error": result.error or result.message,
            }
        except Exception as e:
            logger.warning(f"FriTap start failed: {e}")
            return False, {
                "enabled": False,
                "package": package,
                "status": "error",
                "error": str(e),
            }

    async def _stop_fritap_if_started(self, started: bool) -> None:
        """Stop FriTap session if it was started, suppressing errors.

        Args:
            started: Whether a FriTap session was started.
        """
        if not started:
            return
        try:
            await self.stop()
        except Exception as e:
            logger.warning(f"FriTap stop error: {e}")

    async def run_network_capture(
        self,
        duration: int = 60,
        with_fritap: bool = False,
        fritap_package: str | None = None,
        device_name: str = "unknown",
    ) -> dict[str, Any]:
        """Run network capture with optional FriTap integration.

        Captures network traffic for the specified duration, analyzes the
        resulting PCAP file, and returns structured results including DNS
        queries, TCP connections, and byte-level IP analysis.

        Optionally combines the capture with FriTap SSL/TLS key extraction
        for a specified package, enabling decryption of captured traffic.

        Args:
            duration: Capture duration in seconds (minimum 5, default 60).
            with_fritap: Whether to enable FriTap SSL keylog during capture.
            fritap_package: Target package name for FriTap. Required when
                with_fritap is True.
            device_name: Name of the connected device for result metadata.

        Returns:
            Dictionary with network capture and analysis results.

        Raises:
            ValueError: If with_fritap is True but fritap_package is None.
        """
        import asyncio
        from datetime import datetime

        if with_fritap and not fritap_package:
            raise ValueError("fritap_package is required when with_fritap is True")

        from sandroid.analysis.network import Network

        results: dict[str, Any] = {
            "analysis_type": "network",
            "capture_duration_seconds": duration,
            "timestamp": datetime.now().isoformat(),
            "device_name": device_name,
        }

        # Start FriTap if requested
        fritap_started = False
        if with_fritap and fritap_package:
            fritap_started, fritap_info = await self._try_start_fritap(fritap_package)
            results["fritap"] = fritap_info
            if fritap_started:
                await asyncio.sleep(3)

        # Run network capture
        network = Network()
        try:
            pcap_path = network.gather_for_duration(duration)
        except Exception as e:
            logger.error(f"Network capture failed: {e}")
            results["capture_error"] = str(e)
            await self._stop_fritap_if_started(fritap_started)
            return results

        # Analyze captured PCAP
        if pcap_path:
            try:
                analysis = network.analyze_pcap(pcap_path)
                results.update(analysis)
            except Exception as e:
                logger.error(f"PCAP analysis failed: {e}")
                results["analysis_error"] = str(e)
                results["pcap_file"] = pcap_path
        else:
            results["capture_error"] = "No PCAP file generated"

        await self._stop_fritap_if_started(fritap_started)

        return results
