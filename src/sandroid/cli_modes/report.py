"""``sandroid --report-from DIR``: offline PDF (re)generation.

Works without a configuration or a device: it only reads the results folder.
Every invocation is appended to ``<DIR>/sandroid_report.log`` (manifest
verification result, PDF and manifest hashes) so the regeneration itself is
documented next to the evidence.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sandroid.core.console import SandroidConsole

REPORT_LOG_NAME = "sandroid_report.log"


def run_report_from(result_dir: str) -> int:
    """Regenerate the PDF report for ``result_dir``.

    Args:
        result_dir: Existing Sandroid results folder.

    Returns:
        Process exit code: 0 on success, 1 on error, 2 if the existing
        evidence manifest did not verify (the PDF is still written).
    """
    from sandroid.core.run_report import report_from_folder

    console = SandroidConsole.get()
    root = Path(result_dir)
    handler = logging.FileHandler(root / REPORT_LOG_NAME, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    sandroid_logger = logging.getLogger("sandroid")
    sandroid_logger.addHandler(handler)
    previous_level = sandroid_logger.level
    if sandroid_logger.getEffectiveLevel() > logging.INFO:
        sandroid_logger.setLevel(logging.INFO)
    try:
        sandroid_logger.info("Report regeneration requested for %s", root.resolve())
        outcome = report_from_folder(root)
    except Exception as exc:
        sandroid_logger.error("Report regeneration failed: %s", exc, exc_info=True)
        console.print(f"[error]Report generation failed: {exc}[/error]")
        return 1
    finally:
        sandroid_logger.removeHandler(handler)
        handler.close()
        sandroid_logger.setLevel(previous_level)

    console.print(f"[success]PDF report written: {outcome.pdf}[/success]")
    check = outcome.check
    if not check.present:
        console.print("[warning]No evidence manifest existed; a new one was written.[/warning]")
    elif check.ok:
        console.print("[success]Existing evidence manifest verified OK.[/success]")
    else:
        console.print(
            "[error]Evidence manifest verification FAILED "
            f"({len(check.mismatched)} modified, {len(check.missing)} missing). "
            "The manifest was left unchanged.[/error]"
        )
        for rel in check.mismatched[:20]:
            console.print(f"  modified: {rel}")
        for rel in check.missing[:20]:
            console.print(f"  missing:  {rel}")
        return 2
    if outcome.manifest is not None:
        console.print(
            f"Manifest: {outcome.manifest.sha256sums_path} "
            f"(SHA-256 {outcome.manifest.sha256sums_sha256})"
        )
    return 0
