"""``sandroid --report-from DIR``: offline PDF (re)generation.

Works without a configuration or a device: it only reads the results folder.
The evidence rules are those of :func:`sandroid.core.run_report.report_from_folder`:
the manifest is verified first, nothing is written on a mismatch, existing
files are never overwritten (the PDF gets a ``_regenerated_<UTC>`` name) and
the new PDF is recorded in an addendum manifest.

After a successful verification the invocation is appended to
``<DIR>/sandroid_report.log`` (verification result, PDF and addendum hashes)
so the regeneration itself is documented next to the evidence. On a failed
verification the log is only shown on the console.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sandroid.core.console import SandroidConsole

REPORT_LOG_NAME = "sandroid_report.log"

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class _BufferHandler(logging.Handler):
    """Keeps records in memory until it is known whether we may write."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _append_log(root: Path, records: list[logging.LogRecord]) -> None:
    handler = logging.FileHandler(root / REPORT_LOG_NAME, encoding="utf-8")
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    try:
        for record in records:
            handler.handle(record)
    finally:
        handler.close()


def run_report_from(result_dir: str) -> int:
    """Regenerate the PDF report for ``result_dir``.

    Args:
        result_dir: Existing Sandroid results folder.

    Returns:
        Process exit code: 0 on success, 1 on error, 2 if the existing
        evidence manifest did not verify (nothing is written in that case).
    """
    from sandroid.core.run_report import (
        SHA256SUMS_NAME,
        EvidenceVerificationError,
        report_from_folder,
    )

    console = SandroidConsole.get()
    root = Path(result_dir)
    buffer = _BufferHandler()
    sandroid_logger = logging.getLogger("sandroid")
    sandroid_logger.addHandler(buffer)
    previous_level = sandroid_logger.level
    if sandroid_logger.getEffectiveLevel() > logging.INFO:
        sandroid_logger.setLevel(logging.INFO)
    write_log = root.is_dir()
    try:
        sandroid_logger.info("Report regeneration requested for %s", root.resolve())
        outcome = report_from_folder(root)
    except EvidenceVerificationError as exc:
        write_log = False  # never write into a folder that failed verification
        console.print(f"[error]{exc}[/error]")
        for rel in exc.check.mismatched[:20]:
            console.print(f"  modified: {rel}")
        for rel in exc.check.missing[:20]:
            console.print(f"  missing:  {rel}")
        return 2
    except Exception as exc:
        sandroid_logger.error("Report regeneration failed: %s", exc, exc_info=True)
        console.print(f"[error]Report generation failed: {exc}[/error]")
        return 1
    finally:
        sandroid_logger.removeHandler(buffer)
        sandroid_logger.setLevel(previous_level)
        if write_log:
            try:
                _append_log(root, buffer.records)
            except OSError as exc:
                console.print(f"[warning]Could not write {REPORT_LOG_NAME}: {exc}[/warning]")

    check = outcome.check
    if check.present:
        console.print(
            f"[success]Existing evidence manifest verified OK "
            f"({SHA256SUMS_NAME}, nothing was modified).[/success]"
        )
    else:
        console.print("[warning]No evidence manifest existed; a new one was written.[/warning]")
    console.print(f"[success]PDF report written: {outcome.pdf}[/success]")
    if outcome.addendum is not None:
        console.print(
            f"Recorded in addendum manifest: {outcome.addendum} "
            f"(SHA-256 {outcome.addendum_sha256})"
        )
    if outcome.manifest is not None:
        console.print(
            f"Manifest: {outcome.manifest.sha256sums_path} "
            f"(SHA-256 {outcome.manifest.sha256sums_sha256})"
        )
    return 0
