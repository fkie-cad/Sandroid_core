"""Headless network capture mode dispatcher for Sandroid.

Runs network traffic capture with optional FriTap integration in headless mode.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.services import get_task_service

logger = logging.getLogger(__name__)


def run_network_headless(
    sandroid_config: SandroidConfig,
    active_logger: logging.Logger,
    duration: int,
    with_fritap: str | None,
    output_file: str | None,
) -> None:
    """Run headless network capture with optional FriTap integration.

    Captures network traffic for the specified duration, analyzes the resulting
    PCAP file, and outputs structured JSON results. Optionally combines capture
    with FriTap SSL/TLS key extraction for a specified package.

    Args:
        sandroid_config: Loaded Sandroid configuration.
        active_logger: Configured logger instance.
        duration: Capture duration in seconds (minimum 5).
        with_fritap: Optional package name for FriTap SSL keylog integration.
        output_file: Optional output file path for JSON results.

    Raises:
        SystemExit: On initialization failure or if device is not an emulator.
    """
    from sandroid.api.headless import SandroidHeadlessAPI
    from sandroid.core.adb import Adb
    from sandroid.core.initializer import EscalatingSignalHandler, initialize_core
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import get_device_service

    console = SandroidConsole.get()
    initialize_core(sandroid_config)

    # Pre-check: emulator-only mode
    try:
        if not get_device_service().is_emulator_device():
            console.print(
                "[error]Error: Headless network capture requires an emulator device.[/error]"
            )
            console.print(
                "[warning]Physical devices are not supported for headless network capture. "
                "Please start an Android Virtual Device (AVD) and try again.[/warning]"
            )
            sys.exit(1)
    except Exception as e:
        logger.warning(f"Emulator pre-check could not be completed: {e}")

    signal_handler = EscalatingSignalHandler(
        console=console,
        first_message="Received interrupt, stopping capture...",
    )
    signal_handler.install()

    try:
        console.print(
            f"[accent]Starting headless network capture for {duration}s...[/accent]"
        )
        if with_fritap:
            console.print(f"[dim]FriTap SSL keylog enabled for: {with_fritap}[/dim]")

        api = SandroidHeadlessAPI(config_path=None)
        api._config = sandroid_config
        api._initialized = True
        api._toolbox = Toolbox
        api._adb = Adb

        results = asyncio.run(
            api.run_headless_network(
                duration=duration,
                with_fritap=bool(with_fritap),
                fritap_package=with_fritap,
            )
        )

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"[success]Results saved to: {output_file}[/success]")
        else:
            print(json.dumps(results, indent=2, default=str))

        console.print(
            "[success]Headless network capture completed successfully[/success]"
        )

    except KeyboardInterrupt:
        console.print("[warning]Capture interrupted by user[/warning]")
    except Exception as e:
        console.print(f"[error]Network capture failed: {e}[/error]")
        logger.exception("Headless network capture error")
        sys.exit(1)
    finally:
        get_task_service().stop_all()
