"""Monitoring handler — Monitor, malware monitor, network capture."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sandroid.api.helpers import resolve_target_package, safe_command
from sandroid.api.interfaces import CommandResult

if TYPE_CHECKING:
    from sandroid.api.headless import SandroidHeadlessAPI

logger = logging.getLogger(__name__)


class MonitoringHandler:
    """Handles Monitor, malware monitor, and network capture operations."""

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api

    # -- Malware Monitor (Dexray-Intercept) ----------------------------------

    @safe_command("Failed to start malware monitor")
    async def start_malware_monitor(
        self,
        package: str | None = None,
        hook_config: dict[str, bool] | None = None,
        enable_fritap: bool = False,
        enable_stacktrace: bool = False,
    ) -> CommandResult:
        """Start the dexray-intercept malware monitor (non-blocking)."""
        from sandroid.analysis.malwaremonitor import MalwareMonitor
        from sandroid.services import get_spotlight_service

        target_package = package or self._api._spotlight_app
        if not target_package:
            spotlight = get_spotlight_service()
            target_package = spotlight.get_effective_package()
        if not target_package:
            return CommandResult(
                success=False,
                message="No target package specified",
                error="Provide a package name or set a spotlight app first",
            )

        if not self._api._spotlight_app:
            await self._api.set_spotlight_app(target_package)

        if (
            hasattr(self._api, "_malware_monitor")
            and self._api._malware_monitor
            and self._api._malware_monitor.running
        ):
            return CommandResult(
                success=False,
                message="Malware monitor is already running",
                error="Stop the current monitor before starting a new one",
            )

        monitor = MalwareMonitor(
            enable_fritap=enable_fritap,
            enable_full_stacktrace=enable_stacktrace,
        )

        if not monitor.available:
            return CommandResult(
                success=False,
                message="dexray-intercept package not installed",
                error="Install dexray-intercept: pip install dexray-intercept",
            )

        if hook_config:
            monitor.hook_config.update(hook_config)

        success = monitor.start_monitoring()

        if not success:
            return CommandResult(
                success=False,
                message="Failed to start malware monitor",
                error="MalwareMonitor.start_monitoring() returned False",
            )

        self._api._malware_monitor = monitor

        return CommandResult(
            success=True,
            message=f"Malware monitor started for {monitor.app_package}",
            data={
                "package": monitor.app_package,
                "enabled_hooks": [k for k, v in monitor.hook_config.items() if v],
                "fritap_enabled": enable_fritap,
            },
        )

    @safe_command("Failed to stop malware monitor")
    async def stop_malware_monitor(self) -> CommandResult:
        """Stop the running dexray-intercept malware monitor."""
        monitor = getattr(self._api, "_malware_monitor", None)
        if not monitor or not monitor.running:
            return CommandResult(
                success=False,
                message="Malware monitor is not running",
            )

        monitor.stop_monitoring()
        results = monitor.return_data()

        self._api._malware_monitor = None

        return CommandResult(
            success=True,
            message="Malware monitor stopped",
            data={
                "results": results,
                "package": monitor.app_package,
            },
        )

    # -- Monitor ---------------------------------------------------------------

    @safe_command("Failed to start Monitor")
    async def start_monitor(
        self, mode: str = "auto", path: str | None = None
    ) -> CommandResult:
        """Start Monitor filesystem monitoring."""
        from sandroid.core.fsmon import FSMon
        from sandroid.services import get_spotlight_service, get_task_service

        task_service = get_task_service()
        if task_service.is_running("monitor"):
            return CommandResult(
                success=False,
                message="Monitor is already running",
                error="Stop the current Monitor before starting a new one",
            )

        FSMon.check_and_install_fsmon()

        monitor_path = path or "/data/"
        target_pid = None
        app_name = None

        if mode in ("auto", "pid"):
            spotlight = get_spotlight_service()
            app_tuple = spotlight.get_app_tuple()
            if app_tuple and app_tuple[0]:
                app_name = app_tuple[0]
                pid = self._api._adb.get_pid_for_package_name(app_name)
                if pid:
                    target_pid = pid

        if mode == "pid" and not target_pid:
            return CommandResult(
                success=False,
                message="No running spotlight app found for PID monitoring",
                error="Set a spotlight app that is running on the device",
            )

        if target_pid:
            monitor_process = FSMon.run_fsmon_by_pid(target_pid, monitor_path)
        else:
            monitor_process = FSMon.run_fsmon_by_path(monitor_path)

        if monitor_process is None:
            return CommandResult(
                success=False,
                message="Failed to start Monitor process",
            )

        def stop_monitor():
            try:
                if monitor_process.poll() is None:
                    monitor_process.terminate()
                    try:
                        monitor_process.wait(timeout=5)
                    except Exception:
                        monitor_process.kill()
            except Exception as e:
                logger.error(f"Error stopping Monitor: {e}")

        task_service.register(
            name="monitor",
            display_name="Monitor",
            instance=monitor_process,
            stop_callback=stop_monitor,
            app_name=app_name,
            target_pid=target_pid,
        )

        message = (
            f"Monitor started monitoring PID {target_pid} ({app_name})"
            if target_pid
            else f"Monitor started monitoring path: {monitor_path}"
        )
        return CommandResult(
            success=True,
            message=message,
            data={
                "monitor_path": monitor_path,
                "target_pid": target_pid,
                "app_name": app_name,
            },
        )

    @safe_command("Failed to stop Monitor")
    async def stop_monitor(self) -> CommandResult:
        """Stop Monitor filesystem monitoring."""
        from sandroid.services import get_task_service

        task_service = get_task_service()
        if not task_service.is_running("monitor"):
            return CommandResult(success=False, message="Monitor is not running")

        task_service.stop("monitor")
        return CommandResult(success=True, message="Monitor stopped")

    # -- Network Capture -----------------------------------------------------

    @safe_command("Failed to start network capture")
    async def start_network_capture(
        self, output_file: str | None = None
    ) -> CommandResult:
        """Start network traffic capture on the device."""
        from sandroid.services import get_task_service

        task_service = get_task_service()
        if task_service.is_running("network_capture"):
            return CommandResult(
                success=False,
                message="Network capture is already running",
            )

        import os
        from datetime import datetime

        if not output_file:
            raw_path = os.getenv("RAW_RESULTS_PATH", ".")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(raw_path, f"capture_{timestamp}.pcap")

        _stdout, stderr = self._api._adb.send_adb_command(
            "shell tcpdump -i any -w /sdcard/capture.pcap &"
        )

        if stderr and "error" in stderr.lower():
            return CommandResult(
                success=False,
                message="Failed to start network capture",
                error=stderr,
            )

        return CommandResult(
            success=True,
            message="Network capture started",
            data={"output_file": output_file},
        )

    @safe_command("Failed to stop network capture")
    async def stop_network_capture(self) -> CommandResult:
        """Stop network traffic capture and pull the PCAP file."""
        import os

        self._api._adb.send_adb_command("shell pkill tcpdump")

        raw_path = os.getenv("RAW_RESULTS_PATH", ".")
        local_path = os.path.join(raw_path, "capture.pcap")

        self._api._adb.send_adb_command(f"pull /sdcard/capture.pcap {local_path}")
        self._api._adb.send_adb_command("shell rm /sdcard/capture.pcap")

        return CommandResult(
            success=True,
            message="Network capture stopped",
            data={"pcap_path": local_path},
        )
