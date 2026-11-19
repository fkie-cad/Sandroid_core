"""``sandroid --report-from DIR``: offline report (re)generation.

Works without a configuration or a device: it only reads the results folder
(its results JSON, ``timeline_seal.json`` and the sealed prefix of the session
timeline it names, or the previous ``report.json``). The evidence rules are
those of :func:`sandroid.core.run_report.report_from_folder`: the manifest is
verified first, nothing is written on a mismatch, existing files are never
overwritten (the new files are named ``report_regenerated_<UTC>.{json,md,pdf}``)
and the new files are recorded in an addendum manifest.

After a successful verification the invocation is appended to
``<DIR>/sandroid_report.log`` (verification result, report and addendum
hashes) so the regeneration itself is documented next to the evidence. On a
failed verification the log is only shown on the console.
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


def _plain(console, text: str, style: str | None = None) -> None:
    """Print verbatim (no markup, no wrapping) so paths stay parseable."""
    console.print(text, style=style, soft_wrap=True, markup=False, highlight=False)


def run_report_from(result_dir: str) -> int:
    """Regenerate the report (JSON, Markdown, PDF) for ``result_dir``.

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
        _plain(console, str(exc), "error")
        for rel in exc.check.mismatched[:20]:
            _plain(console, f"  modified: {rel}")
        for rel in exc.check.missing[:20]:
            _plain(console, f"  missing:  {rel}")
        return 2
    except Exception as exc:
        sandroid_logger.error("Report regeneration failed: %s", exc, exc_info=True)
        _plain(console, f"Report generation failed: {exc}", "error")
        return 1
    finally:
        sandroid_logger.removeHandler(buffer)
        sandroid_logger.setLevel(previous_level)
        if write_log:
            try:
                _append_log(root, buffer.records)
            except OSError as exc:
                console.print(
                    f"[warning]Could not write {REPORT_LOG_NAME}: {exc}[/warning]"
                )

    check = outcome.check
    if check.present:
        console.print(
            f"[success]Existing evidence manifest verified OK "
            f"({SHA256SUMS_NAME}, nothing was modified).[/success]"
        )
    elif outcome.addendum is not None:
        console.print(
            f"[warning]{SHA256SUMS_NAME} could not be verified (none present); "
            "the new report is recorded in an addendum manifest.[/warning]"
        )
    else:
        console.print(
            "[warning]No evidence manifest existed; a new one was written.[/warning]"
        )
    if outcome.timeline_note:
        _plain(
            console,
            f"{outcome.timeline_note}; the transcript was not re-derived from it.",
            "warning",
        )
    if outcome.report_json is not None:
        _plain(console, f"Report written: {outcome.report_json}", "success")
    if outcome.markdown is not None:
        _plain(console, f"Markdown written: {outcome.markdown}", "success")
    _plain(console, f"PDF report written: {outcome.pdf}", "success")
    if outcome.addendum is not None:
        _plain(
            console,
            f"Recorded in addendum manifest: {outcome.addendum} "
            f"(SHA-256 {outcome.addendum_sha256})",
        )
    if outcome.manifest is not None:
        _plain(
            console,
            f"Manifest: {outcome.manifest.sha256sums_path} "
            f"(SHA-256 {outcome.manifest.sha256sums_sha256})",
        )
    return 0
