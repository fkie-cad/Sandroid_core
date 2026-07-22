"""IO commands for import/export of results."""

import json
import logging
import os
from datetime import datetime

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class ExportResultsCommand(CommandHandler):
    """Command handler for exporting analysis results to file."""

    key = "x"
    name = "Export Results"
    description = "Export analysis results to file"
    category = CommandCategory.IO
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if export command can be executed.

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if ctx.action_queue is None:
            return (False, "Action queue not available")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute results export.

        If toolbox has export_results(), use that. Otherwise, save
        current results to JSON in RESULTS_PATH.

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure
        """
        # Early validation: check action_queue is available
        if ctx.action_queue is None:
            return CommandResult(
                success=False,
                message="Action queue not available",
                error="No action queue in context",
            )

        # Try toolbox's export_results method first
        if ctx.toolbox and hasattr(ctx.toolbox, "export_results"):
            try:
                result = ctx.toolbox.export_results()
                if result:
                    return CommandResult(
                        success=True,
                        message=f"Results exported: {result}",
                        data={"export_path": result},
                    )
            except Exception as e:
                logger.warning(
                    f"Toolbox export_results failed: {e}, falling back to manual export"
                )

        # Fallback: manual JSON export
        return await self._export_to_json(ctx)

    async def _export_to_json(self, ctx: CommandContext) -> CommandResult:
        """Export results to JSON file.

        Args:
            ctx: Command context

        Returns:
            CommandResult for the export operation
        """
        # Get results path from context or environment
        results_path = ctx.get_results_path()

        # Generate default filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"sandroid_export_{timestamp}.json"

        # Get optional filename from user
        filename: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                filename = await ctx.request_input(
                    title="Export Results",
                    message="Enter filename (leave blank for default):",
                    default=default_filename,
                )
            elif ctx.toolbox and hasattr(ctx.toolbox, "safe_input"):
                logger.info(f"Enter export filename (default: {default_filename}):")
                filename = ctx.toolbox.safe_input("Filename: ")
        except Exception as e:
            logger.warning(f"Error getting filename input: {e}")

        # Use default if empty
        if not filename or filename.strip() == "":
            filename = default_filename

        # Ensure .json extension
        if not filename.endswith(".json"):
            filename += ".json"

        # Build full path
        output_path = os.path.join(results_path, filename)

        # Ensure directory exists
        os.makedirs(
            os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
            exist_ok=True,
        )

        try:
            # Collect data to export
            export_data = self._collect_export_data(ctx)

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=4, default=str)

            logger.info(f"Results exported to: {output_path}")
            return CommandResult(
                success=True,
                message=f"Results exported to: {output_path}",
                data={"export_path": output_path, "entries": len(export_data)},
            )

        except Exception as e:
            logger.exception("Error exporting results")
            return CommandResult(
                success=False, message=f"Export failed: {e!s}", error=str(e)
            )

    def _collect_export_data(self, ctx: CommandContext) -> dict:
        """Collect data to export from available sources.

        Results no longer live on ``forensic_service`` as a bulk blob (it has
        no ``get_results()`` -- that was always a dead ``hasattr`` check, even
        before the ``AnalysisEngine`` refactor); the durable record of each
        completed Record->Play analysis is the current device's most recent
        entry in ``run_history`` (what the Files -> Diffs panel reads), so
        that is what gets exported here, alongside a snapshot of live
        forensic-service state.

        Args:
            ctx: Command context

        Returns:
            Dictionary containing exportable data
        """
        export_data = {"export_timestamp": datetime.now().isoformat(), "version": "2.0"}

        if ctx.forensic_service and hasattr(ctx.forensic_service, "get_state_dict"):
            try:
                export_data["forensic_state"] = ctx.forensic_service.get_state_dict()
            except Exception as e:
                logger.warning(f"Could not get forensic service state: {e}")

        try:
            from sandroid.core import run_history

            device_name = getattr(ctx.toolbox, "device_name", None)
            index = run_history.load_index(device_name=device_name)
            if index:
                latest_run_id = index[0]["run_id"]
                record = run_history.load_run(latest_run_id)
                export_data["latest_run"] = record.to_dict()
        except Exception as e:
            logger.warning(f"Could not get latest run_history entry: {e}")

        return export_data


class ImportResultsCommand(CommandHandler):
    """Command handler for importing previously saved results."""

    key = "i"
    name = "Import Results"
    description = "Import previously saved results"
    category = CommandCategory.IO
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if import command can be executed.

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if ctx.action_queue is None:
            return (False, "Action queue not available")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute results import.

        If toolbox has import_results(), use that. Otherwise, prompt
        for file path and load JSON.

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure
        """
        # Early validation: check action_queue is available
        if ctx.action_queue is None:
            return CommandResult(
                success=False,
                message="Action queue not available",
                error="No action queue in context",
            )

        # Try toolbox's import_results method first
        if ctx.toolbox and hasattr(ctx.toolbox, "import_results"):
            try:
                # Get file path from user first
                file_path = await self._get_import_path(ctx)
                if not file_path:
                    return CommandResult(
                        success=False,
                        message="Import cancelled - no file selected",
                        error="No file path provided",
                    )

                result = ctx.toolbox.import_results(file_path)
                if result:
                    return CommandResult(
                        success=True,
                        message=f"Results imported from: {file_path}",
                        data={"import_path": file_path},
                    )
            except Exception as e:
                logger.warning(
                    f"Toolbox import_results failed: {e}, falling back to manual import"
                )

        # Fallback: manual JSON import
        return await self._import_from_json(ctx)

    async def _get_import_path(self, ctx: CommandContext) -> str | None:
        """Get import file path from user.

        Args:
            ctx: Command context

        Returns:
            File path string or None if cancelled
        """
        # Get results path for placeholder
        results_path = ctx.get_results_path()
        default_path = os.path.join(results_path, "sandroid.json")

        file_path: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                file_path = await ctx.request_input(
                    title="Import Results",
                    message="Enter path to results file:",
                    default=default_path,
                )
            elif ctx.toolbox and hasattr(ctx.toolbox, "safe_input"):
                logger.info(f"Enter path to import (default: {default_path}):")
                file_path = ctx.toolbox.safe_input("File path: ")
        except Exception as e:
            logger.warning(f"Error getting file path input: {e}")

        # Use default if empty
        if not file_path or file_path.strip() == "":
            file_path = default_path

        return file_path

    async def _import_from_json(self, ctx: CommandContext) -> CommandResult:
        """Import results from JSON file.

        Args:
            ctx: Command context

        Returns:
            CommandResult for the import operation
        """
        # Get file path from user
        file_path = await self._get_import_path(ctx)

        if not file_path:
            return CommandResult(
                success=False,
                message="Import cancelled - no file selected",
                error="No file path provided",
            )

        # Validate file exists
        if not os.path.exists(file_path):
            return CommandResult(
                success=False,
                message=f"File not found: {file_path}",
                error="File does not exist",
            )

        try:
            # Read and parse JSON
            with open(file_path, encoding="utf-8") as f:
                import_data = json.load(f)

            # Apply imported data where possible
            entries_count = self._apply_import_data(ctx, import_data)

            logger.info(f"Results imported from: {file_path}")
            return CommandResult(
                success=True,
                message=f"Results imported from: {file_path}",
                data={
                    "import_path": file_path,
                    "entries": entries_count,
                    "data": import_data,
                },
            )

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file: {e}")
            return CommandResult(
                success=False, message=f"Invalid JSON format: {e!s}", error=str(e)
            )
        except Exception as e:
            logger.exception("Error importing results")
            return CommandResult(
                success=False, message=f"Import failed: {e!s}", error=str(e)
            )

    def _apply_import_data(self, ctx: CommandContext, data: dict) -> int:
        """Apply/recognize imported data.

        ``"latest_run"`` (a ``run_history`` ``RunRecord``) and
        ``"forensic_state"`` (a forensic-service state snapshot) are
        historical/read-only -- there is no live, mutable "current results"
        to restore them into (that concept left with the legacy ``ActionQ``
        engine) -- so they are counted as recognized rather than restored.
        ``"forensic_results"``/``set_results`` is kept for forward
        compatibility with any future bulk-restore API; it is currently
        always a no-op since ``forensic_service`` has no such method.

        Args:
            ctx: Command context
            data: Imported data dictionary

        Returns:
            Number of entries recognized/applied
        """
        entries = 0

        # If forensic service is available, try to restore forensic results
        if ctx.forensic_service and hasattr(ctx.forensic_service, "set_results"):
            if "forensic_results" in data:
                try:
                    ctx.forensic_service.set_results(data["forensic_results"])
                    entries += 1
                except Exception as e:
                    logger.warning(f"Could not restore forensic results: {e}")

        # run_history/forensic-state snapshots are historical -- recognize
        # them rather than pretending to restore into a live session.
        if "latest_run" in data:
            entries += 1
        if "forensic_state" in data:
            entries += 1

        # Count top-level entries if no specific restoration happened
        if entries == 0:
            entries = len(data)

        return entries


def register_commands(registry) -> None:
    """Register all IO commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(ExportResultsCommand())
    registry.register(ImportResultsCommand())
