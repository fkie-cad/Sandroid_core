"""Forensic handler — spotlight file tracking, import/export."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sandroid.api.helpers import safe_command
from sandroid.api.interfaces import CommandResult

if TYPE_CHECKING:
    from sandroid.api.headless import SandroidHeadlessAPI

logger = logging.getLogger(__name__)


class ForensicHandler:
    """Handles forensic operations: spotlight files, import/export."""

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api

    async def get_spotlight_files(self) -> list[str]:
        """Get list of spotlight files being tracked."""
        from sandroid.services import get_forensic_service

        forensic = get_forensic_service()
        return list(forensic.get_spotlight_files())

    async def add_spotlight_file(self, file_path: str) -> CommandResult:
        """Add a file to spotlight tracking."""
        from sandroid.services import get_forensic_service

        try:
            forensic = get_forensic_service()
            forensic.add_spotlight_file(file_path)
            return CommandResult(
                success=True,
                message=f"Added spotlight file: {file_path}",
            )
        except Exception as e:
            return CommandResult(
                success=False,
                message="Failed to add spotlight file",
                error=str(e),
            )

    async def remove_spotlight_file(self, file_path: str) -> CommandResult:
        """Remove a file from spotlight tracking."""
        from sandroid.services import get_forensic_service

        try:
            forensic = get_forensic_service()
            forensic.remove_spotlight_file(file_path)
            return CommandResult(
                success=True,
                message=f"Removed spotlight file: {file_path}",
            )
        except Exception as e:
            return CommandResult(
                success=False,
                message="Failed to remove spotlight file",
                error=str(e),
            )

    async def pull_spotlight_files(self) -> CommandResult:
        """Pull all spotlight files from device."""
        from sandroid.services import get_file_extraction_service

        try:
            extraction = get_file_extraction_service()
            pulled_files = extraction.pull_spotlight_files()
            return CommandResult(
                success=True,
                message=f"Pulled {len(pulled_files)} spotlight files",
                data={"files": pulled_files},
            )
        except Exception as e:
            return CommandResult(
                success=False,
                message="Failed to pull spotlight files",
                error=str(e),
            )

    @safe_command("Failed to import action")
    async def import_action(self, file_path: str) -> CommandResult:
        """Import an action recording file."""
        import json
        from pathlib import Path

        path = Path(file_path)
        if not path.exists():
            return CommandResult(
                success=False,
                message=f"Action file not found: {file_path}",
                error="File does not exist",
            )

        with open(path, encoding="utf-8") as f:
            action_data = json.load(f)

        return CommandResult(
            success=True,
            message=f"Action imported from: {path.name}",
            data={
                "file": str(path),
                "actions": len(action_data) if isinstance(action_data, list) else 1,
            },
        )

    @safe_command("Failed to export results")
    async def export_results(self, filename: str | None = None) -> CommandResult:
        """Export analysis results to a file."""
        import json
        import os
        from datetime import datetime

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_results_{timestamp}.json"

        results_path = os.getenv("RESULTS_PATH", ".")
        output_path = os.path.join(results_path, filename)

        from sandroid.services import get_forensic_service

        forensic = get_forensic_service()
        changed_files = forensic.get_changed_files_cache() or {}

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"changed_files": changed_files}, f, indent=2, default=str)

        return CommandResult(
            success=True,
            message=f"Results exported to: {output_path}",
            data={"path": output_path},
        )
