"""Batch processing utility for the Sandroid Headless API.

Provides functions for analyzing multiple APK packages in sequence
using a single API instance.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .interfaces import AnalysisMode

logger = logging.getLogger(__name__)


async def batch_analyze(
    packages: list[str],
    mode: AnalysisMode = AnalysisMode.MALWARE,
    runs: int = 2,
    capture_network: bool = False,
    output_dir: str = "results",
    config_path: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Analyze multiple packages in batch.

    This utility function creates a single API instance and runs analysis
    on multiple packages sequentially, collecting results for each.

    Args:
        packages: List of package names to analyze.
        mode: Analysis mode to use for all packages.
        runs: Number of analysis runs per package.
        capture_network: Enable network capture.
        output_dir: Directory for individual result files.
        config_path: Optional path to configuration file.

    Returns:
        Dictionary mapping package names to their analysis results or errors.

    Example::

        results = await batch_analyze(
            packages=["com.app1", "com.app2", "com.app3"],
            mode=AnalysisMode.MALWARE,
            runs=3,
            output_dir="batch_results/",
        )
        for pkg, result in results.items():
            print(f"{pkg}: {result.get('status')}")
    """
    from .headless import SandroidHeadlessAPI

    api = SandroidHeadlessAPI(config_path=config_path)
    init_result = await api.initialize()

    if not init_result.success:
        return {
            pkg: {"status": "error", "error": init_result.error} for pkg in packages
        }

    results: dict[str, dict[str, Any]] = {}
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for package in packages:
        logger.info(f"Analyzing package: {package}")
        try:
            result = await api.run_analysis(
                mode=mode,
                package=package,
                runs=runs,
                capture_network=capture_network,
            )
            results[package] = {"status": "success", "data": result}

            # Save individual result
            pkg_file = output_path / f"{package.replace('.', '_')}.json"
            with open(pkg_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"Results saved to: {pkg_file}")

        except Exception as e:
            logger.error(f"Analysis failed for {package}: {e}")
            results[package] = {"status": "error", "error": str(e)}

    await api.shutdown()
    return results
