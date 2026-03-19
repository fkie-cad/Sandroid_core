"""CLI entry point for the Sandroid Headless API.

Usage:
    python -m sandroid.api <package_name> [mode]

Examples:
    python -m sandroid.api com.example.app
    python -m sandroid.api com.example.app malware
    python -m sandroid.api com.example.app forensic
"""

from __future__ import annotations

import asyncio
import json
import sys

from .headless import SandroidHeadlessAPI
from .interfaces import AnalysisMode


def main() -> None:
    """CLI entry point for headless API."""
    if len(sys.argv) < 2:
        print("Usage: python -m sandroid.api <package_name> [mode]")
        print("Modes: forensic, malware, security")
        sys.exit(1)

    package = sys.argv[1]
    mode_str = sys.argv[2] if len(sys.argv) > 2 else "malware"

    try:
        mode = AnalysisMode(mode_str)
    except ValueError:
        print(f"Invalid mode: {mode_str}. Use: forensic, malware, or security")
        sys.exit(1)

    async def run() -> None:
        api = SandroidHeadlessAPI()
        result = await api.initialize()

        if not result.success:
            print(f"Initialization failed: {result.error}")
            sys.exit(1)

        try:
            results = await api.run_analysis(
                mode=mode,
                package=package,
                runs=2,
                capture_network=True,
            )
            print(json.dumps(results, indent=2, default=str))
        finally:
            await api.shutdown()

    asyncio.run(run())


if __name__ == "__main__":
    main()
