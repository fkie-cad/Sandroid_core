"""Headless Fridump mode dispatcher for Sandroid.

Runs Fridump memory dumping in headless mode as a one-shot operation.
"""

import logging
import os
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.core.enums import SpawnMode

logger = logging.getLogger(__name__)


def run_fridump_headless(
    sandroid_config: SandroidConfig,
    active_logger: logging.Logger,
    package: str,
) -> None:
    """Run Fridump memory dump in headless mode.

    Dumps the memory of the target package and exits. Unlike FriTap/dexray,
    this is a one-shot operation — dump, report results, exit.

    Args:
        sandroid_config: Loaded Sandroid configuration.
        active_logger: Configured logger instance.
        package: Target package name to dump memory from.

    Raises:
        SystemExit: On initialization or dump failure.
    """
    console = SandroidConsole.get()

    try:
        from sandroid.core.adb import Adb
        from sandroid.core.fridump import Fridump
        from sandroid.core.initializer import initialize_core
        from sandroid.services import get_frida_session_service, get_spotlight_service
    except ImportError as e:
        console.print(f"[error]Missing dependency: {e}[/error]")
        console.print(
            "[warning]Ensure Frida is installed: pip install frida frida-tools[/warning]"
        )
        sys.exit(1)

    initialize_core(sandroid_config)

    # Check Frida server is running
    frida_manager = get_frida_session_service().get_frida_manager()
    if not frida_manager.is_frida_server_running():
        console.print("[error]Frida server is not running on the device.[/error]")
        console.print(
            "[warning]Start it with: adb push frida-server /data/local/tmp/ && "
            "adb shell '/data/local/tmp/frida-server &'[/warning]"
        )
        sys.exit(1)

    # Detect whether to attach or spawn
    spotlight = get_spotlight_service()
    pid = Adb.get_pid_for_package_name(package)
    mode: SpawnMode
    if pid:
        logger.info(f"App {package} is running (PID: {pid}), using attach mode")
        console.print(f"[accent]Attaching to {package} (PID: {pid})[/accent]")
        spotlight.set_app(package, pid=pid)
        mode = SpawnMode.ATTACH
    else:
        logger.info(f"App {package} not running, using spawn mode")
        console.print(f"[accent]App {package} not running, using spawn mode[/accent]")
        spotlight.set_spawn_app(package, auto_resume=True)
        mode = SpawnMode.SPAWN

    try:
        console.print(f"[accent]Starting memory dump for: {package}[/accent]")
        Fridump.dump_memory(pid=pid, process_name=package, mode=mode)

        # Report results
        dump_dir = Fridump.get_output_directory(package)
        if os.path.isdir(dump_dir):
            file_count = sum(
                1
                for f in os.listdir(dump_dir)
                if os.path.isfile(os.path.join(dump_dir, f))
            )
            console.print(
                f"[success]Memory dump complete: {file_count} file(s) "
                f"saved to {dump_dir}[/success]"
            )
        else:
            console.print(
                "[warning]Dump completed but no output directory found.[/warning]"
            )

    except KeyboardInterrupt:
        console.print("\n[warning]Dump interrupted by user.[/warning]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[error]Fridump error: {e}[/error]")
        logger.exception("Fridump headless error")
        sys.exit(1)
