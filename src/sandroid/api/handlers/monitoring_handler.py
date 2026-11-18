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

    #: Device-side pcap written by :meth:`start_network_capture`.
    _DEVICE_PCAP = "/sdcard/sandroid_capture.pcap"

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api
        # {"pid", "device_path", "output_file"} of the capture we started.
        self._capture: dict[str, Any] | None = None

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
            # e.g. Dexray's bypass group refused next to Bypass (b) categories
            reason = getattr(monitor, "last_error", None)
            return CommandResult(
                success=False,
                message=(
                    f"Failed to start malware monitor: {reason}"
                    if reason
                    else "Failed to start malware monitor"
                ),
                error=reason or "MalwareMonitor.start_monitoring() returned False",
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

        if self._capture is not None:
            return CommandResult(
                success=False,
                message="Network capture is already running",
                data={"pid": self._capture["pid"]},
            )

        import asyncio
        import os
        import shlex
        from datetime import datetime

        from sandroid.core.adb_utils import device_shell_command

        if not output_file:
            raw_path = os.getenv("RAW_RESULTS_PATH", ".")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(raw_path, f"capture_{timestamp}.pcap")

        adb = self._api._adb
        # Detach tcpdump ON THE DEVICE and print its PID. (A host-side
        # trailing ``&`` backgrounded nothing: the host shell kept adb
        # attached, so the call blocked until the 30 s timeout.)
        device_pcap = self._DEVICE_PCAP
        stdout, stderr = adb.send_adb_command(
            device_shell_command(
                f"nohup tcpdump -i any -w {shlex.quote(device_pcap)} "
                "</dev/null >/dev/null 2>&1 & echo $!"
            )
        )
        lines = (stdout or "").strip().splitlines()
        pid = int(lines[-1]) if lines and lines[-1].strip().isdigit() else None
        if pid is None:
            return CommandResult(
                success=False,
                message="Failed to start network capture",
                error=stderr or stdout or "no tcpdump PID returned",
            )

        # tcpdump exits at once when it is missing or lacks permissions.
        await asyncio.sleep(0.5)
        alive, _ = adb.send_adb_command(
            device_shell_command(f"kill -0 {pid} 2>/dev/null && echo RUNNING")
        )
        if "RUNNING" not in (alive or ""):
            return CommandResult(
                success=False,
                message="Failed to start network capture",
                error=f"tcpdump (pid {pid}) exited immediately: {stderr}".strip(),
            )

        self._capture = {
            "pid": pid,
            "device_path": device_pcap,
            "output_file": output_file,
        }
        return CommandResult(
            success=True,
            message="Network capture started",
            data={"output_file": output_file, "pid": pid},
        )

    @safe_command("Failed to stop network capture")
    async def stop_network_capture(self) -> CommandResult:
        """Stop the capture started by :meth:`start_network_capture`.

        Signals exactly that tcpdump PID (never a blanket ``pkill``, which
        also killed other tcpdump instances, e.g. the analysis capture) and
        pulls the PCAP to the ``output_file`` chosen at start.
        """
        import asyncio
        import os

        from sandroid.core.adb_utils import (
            device_shell_arg,
            device_shell_command,
            quote_host_arg,
        )

        capture = self._capture
        if capture is None:
            return CommandResult(
                success=False, message="No network capture started by this API"
            )
        self._capture = None
        adb = self._api._adb
        pid = int(capture["pid"])

        # SIGTERM (tcpdump flushes and closes the pcap on it; SIGINT may be
        # ignored by a background job), then wait for that PID to exit.
        adb.send_adb_command(f"shell kill {pid}")
        for _ in range(10):
            await asyncio.sleep(0.3)
            alive, _ = adb.send_adb_command(
                device_shell_command(f"kill -0 {pid} 2>/dev/null && echo RUNNING")
            )
            if "RUNNING" not in (alive or ""):
                break

        local_path = capture["output_file"]
        parent = os.path.dirname(os.path.abspath(local_path))
        os.makedirs(parent, exist_ok=True)
        device_path = capture["device_path"]
        _out, err = adb.send_adb_command(
            f"pull {quote_host_arg(device_path)} {quote_host_arg(local_path)}"
        )
        adb.send_adb_command(f"shell rm -f {device_shell_arg(device_path)}")
        if err and "error" in err.lower():
            return CommandResult(
                success=False,
                message="Failed to pull network capture",
                error=err,
                data={"pcap_path": local_path},
            )

        return CommandResult(
            success=True,
            message="Network capture stopped",
            data={"pcap_path": local_path},
        )
