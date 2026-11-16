"""Batch processing utility for the Sandroid Headless API.

Provides functions for analyzing multiple APK packages in sequence
using a single API instance.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .interfaces import AnalysisMode

if TYPE_CHECKING:
    from sandroid.config import SandroidConfig

logger = logging.getLogger(__name__)

_UNTRACKED = object()


def package_result_dir(root: str | os.PathLike[str], package: str) -> Path:
    """Create and return a fresh, unique result folder for one batch package.

    ``<root>/<package>`` -- or ``<package>_2``, ``_3`` ... if that already
    exists (the same package twice in one batch, or a second batch in the
    same second), so no two runs ever share a folder.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", package).strip(".") or "package"
    base = Path(root)
    base.mkdir(parents=True, exist_ok=True)
    n = 1
    while True:
        candidate = base / (safe if n == 1 else f"{safe}_{n}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            n += 1


async def batch_analyze(
    packages: list[str],
    mode: AnalysisMode = AnalysisMode.MALWARE,
    runs: int = 2,
    capture_network: bool | None = None,
    output_dir: str = "results",
    config_path: str | None = None,
    config: SandroidConfig | None = None,
) -> dict[str, dict[str, Any]]:
    """Analyze multiple packages in batch.

    This utility function creates a single API instance and runs analysis
    on multiple packages sequentially, collecting results for each.

    Args:
        packages: List of package names to analyze.
        mode: Analysis mode to use for all packages.
        runs: Number of analysis runs per package.
        capture_network: Enable network capture (None: config ``analysis``).
        output_dir: Directory for individual result files.
        config_path: Optional path to configuration file.
        config: Optional already-loaded configuration (takes precedence over
            ``config_path``; avoids reloading and losing CLI overrides).

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

    api = SandroidHeadlessAPI(config_path=config_path, config=config)
    init_result = await api.initialize()

    if not init_result.success:
        return {
            pkg: {"status": "error", "error": init_result.error} for pkg in packages
        }

    results: dict[str, dict[str, Any]] = {}
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    session_root = Path(
        os.environ.get("SESSION_PATH")
        or str(getattr(getattr(config, "paths", None), "results_path", "") or "")
        or output_dir
    )

    for package in packages:
        logger.info(f"Analyzing package: {package}")
        try:
            # SECURITY mode takes the target as apk_path (local .apk file or
            # installed package name), the other modes as package.
            target_kw: dict[str, Any] = (
                {"apk_path": package}
                if mode == AnalysisMode.SECURITY
                else {"package": package}
            )
            if mode != AnalysisMode.SECURITY:
                # Every package gets its own result folder (own raw pulls,
                # results JSON, PDF and evidence manifest) instead of all
                # packages overwriting one session folder.
                target_kw["result_dir"] = str(package_result_dir(session_root, package))
            result = await api.run_analysis(
                mode=mode,
                runs=runs,
                capture_network=capture_network,
                **target_kw,
            )
            results[package] = {"status": "success", "data": result}
            if "result_dir" in target_kw:
                results[package]["result_dir"] = target_kw["result_dir"]
            doc_errors: list[str] = []
            doc = getattr(api, "last_run_documentation", _UNTRACKED)
            if mode != AnalysisMode.SECURITY and doc is not _UNTRACKED:
                if doc is None:
                    doc_errors.append(
                        "results JSON / evidence documentation not written"
                    )
                elif doc.errors:
                    doc_errors.extend(doc.errors)
            run_errors = result.get("Run Errors") if isinstance(result, dict) else None
            if isinstance(run_errors, dict) and run_errors:
                doc_errors.append(
                    f"run {run_errors.get('status', 'completed with errors')}: "
                    + (
                        str(run_errors.get("fatal"))
                        if run_errors.get("fatal")
                        else f"{len(run_errors.get('steps') or [])} step error(s)"
                    )
                )
            if doc_errors:
                results[package]["documentation_errors"] = doc_errors

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
