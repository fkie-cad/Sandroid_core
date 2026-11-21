"""CLI entry point for the Sandroid Headless API.

Usage:
    python -m sandroid.api [-s SERIAL] [-c CONFIG] <package_name> [mode]

Examples:
    python -m sandroid.api com.example.app
    python -m sandroid.api -s emulator-5556 com.example.app malware
    python -m sandroid.api com.example.app forensic
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .headless import SandroidHeadlessAPI
from .interfaces import AnalysisMode

_MODES = [m.value for m in AnalysisMode]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sandroid.api",
        description=(
            "Run one headless Sandroid analysis of PACKAGE and print the "
            "results as JSON. Exits non-zero when initialization or the "
            "analysis fails."
        ),
    )
    parser.add_argument("package", help="Target app package (e.g. com.example.app)")
    parser.add_argument(
        "mode",
        nargs="?",
        default=AnalysisMode.MALWARE.value,
        choices=_MODES,
        help="Analysis mode (default: malware)",
    )
    parser.add_argument(
        "-s",
        "--serial",
        metavar="SERIAL",
        help=(
            "ADB serial of the device to use (e.g. emulator-5556). Default: "
            "config emulator.serial, then $ANDROID_SERIAL, then the only "
            "connected device."
        ),
    )
    parser.add_argument("-c", "--config", metavar="PATH", help="Configuration file")
    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for headless API (exit 0 on success, 1 on failure)."""
    args = _parser().parse_args(argv)
    mode = AnalysisMode(args.mode)

    config = None
    if args.serial or args.config:
        from sandroid.config import ConfigLoader

        try:
            config = ConfigLoader().load(config_file=args.config)
        except Exception as e:
            print(f"Could not load the configuration: {e}", file=sys.stderr)
            sys.exit(1)
        if args.serial:
            # --serial wins over config emulator.serial and $ANDROID_SERIAL.
            config.emulator.serial = args.serial

    async def run() -> int:
        api = SandroidHeadlessAPI(config=config)
        result = await api.initialize()

        if not result.success:
            print(
                f"Initialization failed: {result.message}: {result.error}",
                file=sys.stderr,
            )
            await api.shutdown()
            return 1

        try:
            results = await api.run_analysis(
                mode=mode,
                package=args.package,
                runs=2,
                capture_network=True,
            )
        except Exception as e:
            print(f"Analysis failed: {e}", file=sys.stderr)
            return 1
        finally:
            await api.shutdown()
        print(json.dumps(results, indent=2, default=str))
        failed = isinstance(results, dict) and results.get("success") is False
        return 1 if failed else 0

    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
