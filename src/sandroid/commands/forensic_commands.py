"""Forensic commands for spotlight file management.

This module provides command handlers for managing spotlight files - files
that are specifically tracked during forensic analysis. Spotlight files
are pulled from the device at key points to capture their state.

Commands:
    - PullSpotlightFileCommand: Pull currently selected spotlight file
    - AddSpotlightFileCommand: Add a file to spotlight tracking
    - RemoveSpotlightFileCommand: Remove a file from spotlight tracking
    - PullAllSpotlightFilesCommand: Pull all spotlight files at once
"""

import logging
import os
import time

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


def _is_sqlite_file(file_path: str) -> bool:
    """Check if a file is a SQLite database by reading its magic header.

    Args:
        file_path: Path to the file to check

    Returns:
        True if the file is a SQLite database
    """
    try:
        # Import from the core module if available
        from sandroid.core.file_diff import is_sqlite_file

        return is_sqlite_file(file_path)
    except ImportError:
        # Fallback implementation
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                return header.startswith(b"SQLite format 3\x00")
        except OSError:
            return False


def _get_adb():
    """Get the ADB class, handling import errors gracefully."""
    try:
        from sandroid.core.adb import Adb

        return Adb
    except ImportError:
        logger.error("Could not import ADB module")
        return None


def _adb_pull_has_error(output: str, error: str) -> bool:
    """Check if an ADB pull command output indicates an error.

    Args:
        output: stdout from the ADB command
        error: stderr from the ADB command

    Returns:
        True if the output indicates an error (file not found or permission denied)
    """
    from sandroid.core.adb_utils import detect_adb_pull_error

    return detect_adb_pull_error(output, error) is not None


class PullSpotlightFileCommand(CommandHandler):
    """Command handler for pulling the current spotlight file from device.

    This command pulls the currently selected spotlight file and optionally
    performs a diff between the previous version and the newly pulled version.
    For SQLite files, it also pulls the -wal and -journal files.

    The target directory is: RESULTS_PATH/spotlight_files/<timestamp>/
    """

    key = " "
    name = "Pull Spotlight File"
    description = "Pull the current spotlight file from device and diff"
    category = CommandCategory.FORENSIC
    views = ["forensic"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if spotlight files exist to pull.

        Args:
            ctx: Command context with forensic service access

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # First validate forensic_service
        valid, msg = self._validate_forensic_service(ctx)
        if not valid:
            return (False, msg)

        # Then check if spotlight files exist
        spotlight_files = ctx.forensic_service.get_spotlight_files()
        if not spotlight_files:
            return (
                False,
                "No spotlight files are set. Use 'l' to add a spotlight file first.",
            )

        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the pull spotlight file command.

        Args:
            ctx: Command context with toolbox and ADB access

        Returns:
            CommandResult indicating success/failure with pulled file info
        """
        # Get spotlight files from forensic service
        spotlight_files: list[str] = []

        if ctx.forensic_service:
            spotlight_files = ctx.forensic_service.get_spotlight_files()

        if not spotlight_files:
            return CommandResult(
                success=False,
                message="No spotlight files are set. Use 'l' to add a spotlight file first.",
                error="No spotlight files configured",
            )

        if len(spotlight_files) != 1:
            return CommandResult(
                success=False,
                message=f"Expected exactly 1 spotlight file, but {len(spotlight_files)} are set. "
                "Use 'u' to pull all files or 'v' to remove some files first.",
                error=f"Multiple spotlight files: {len(spotlight_files)}",
            )

        file_to_pull = spotlight_files[0]
        Adb = _get_adb()

        if Adb is None:
            return CommandResult(
                success=False,
                message="ADB module not available",
                error="Could not import ADB",
            )

        # Create the spotlight_files directory if it doesn't exist
        results_path = ctx.get_results_path()
        spotlight_dir = os.path.join(results_path, "spotlight_files")
        os.makedirs(spotlight_dir, exist_ok=True)

        # Create a timestamped subdirectory
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        pull_dir = os.path.join(spotlight_dir, timestamp)
        os.makedirs(pull_dir, exist_ok=True)

        # Determine target path
        target_filename = os.path.basename(file_to_pull)
        target = os.path.join(pull_dir, target_filename)

        logger.info(f"Pulling spotlight file: {file_to_pull} -> {target}")

        # Pull the main file
        output, error = Adb.send_adb_command(f"pull {file_to_pull} {target}")

        # Check for errors
        combined_output = str(output) + str(error)
        if "failed to stat remote object" in combined_output:
            return CommandResult(
                success=False,
                message=f"File not found on device: {file_to_pull}",
                error="File does not exist on device",
            )

        if "Permission denied" in combined_output:
            return CommandResult(
                success=False,
                message=f"Permission denied when pulling: {file_to_pull}",
                error="ADB permission denied",
            )

        if error and "error" in error.lower():
            return CommandResult(
                success=False, message=f"Failed to pull file: {error}", error=str(error)
            )

        pulled_files = [target]

        # For SQLite files, also pull WAL and journal files
        if os.path.exists(target) and _is_sqlite_file(target):
            logger.info("Detected SQLite file, pulling associated files")

            for suffix in ("-wal", "-journal"):
                companion_source = file_to_pull + suffix
                companion_target = target + suffix
                comp_output, comp_error = Adb.send_adb_command(
                    f"pull {companion_source} {companion_target}"
                )
                if not _adb_pull_has_error(comp_output, comp_error):
                    logger.info(f"Pulled {suffix} file: {companion_source}")
                    pulled_files.append(companion_target)

        # Check for previous pulls to perform diff
        previous_pulls = self._find_previous_pulls(
            spotlight_dir, timestamp, target_filename
        )
        diff_result = None

        if previous_pulls:
            latest_previous = previous_pulls[-1]
            diff_result = self._perform_diff(latest_previous, target)

        message = f"Pulled {target_filename} to {pull_dir}"
        if len(pulled_files) > 1:
            message += f" ({len(pulled_files)} files including WAL/journal)"
        if diff_result:
            message += f"\n{diff_result}"

        return CommandResult(
            success=True,
            message=message,
            data={
                "target_path": target,
                "pulled_files": pulled_files,
                "source_file": file_to_pull,
                "pull_directory": pull_dir,
                "diff_result": diff_result,
            },
        )

    def _find_previous_pulls(
        self, spotlight_dir: str, current_timestamp: str, filename: str
    ) -> list[str]:
        """Find previous versions of the pulled file.

        Args:
            spotlight_dir: Base spotlight directory
            current_timestamp: Current pull timestamp to exclude
            filename: Filename to look for

        Returns:
            List of paths to previous versions, sorted by timestamp
        """
        previous = []

        try:
            for entry in os.listdir(spotlight_dir):
                if entry == current_timestamp:
                    continue

                entry_path = os.path.join(spotlight_dir, entry)
                if os.path.isdir(entry_path):
                    file_path = os.path.join(entry_path, filename)
                    if os.path.exists(file_path):
                        previous.append(file_path)

            # Sort by directory name (timestamp)
            previous.sort()
        except OSError as e:
            logger.warning(f"Error scanning previous pulls: {e}")

        return previous

    def _perform_diff(self, old_file: str, new_file: str) -> str | None:
        """Perform a diff between two files.

        For SQLite files, uses sqldiff if available. Otherwise, reports
        if files are identical or different.

        Args:
            old_file: Path to the old version
            new_file: Path to the new version

        Returns:
            Diff result string or None if diff not possible
        """
        import subprocess

        try:
            # Check if both files are SQLite
            if _is_sqlite_file(old_file) and _is_sqlite_file(new_file):
                # Try using sqldiff
                try:
                    result = subprocess.run(
                        ["sqldiff", old_file, new_file],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode == 0:
                        if result.stdout.strip():
                            lines = result.stdout.strip().split("\n")
                            return f"SQLite diff: {len(lines)} changes detected"
                        return "SQLite diff: No changes detected"
                except FileNotFoundError:
                    logger.debug("sqldiff not available, using basic comparison")
                except subprocess.TimeoutExpired:
                    logger.warning("sqldiff timed out")

            # Basic file comparison
            import filecmp

            if filecmp.cmp(old_file, new_file, shallow=False):
                return "Diff: Files are identical"
            # Get file sizes for basic comparison
            old_size = os.path.getsize(old_file)
            new_size = os.path.getsize(new_file)
            size_diff = new_size - old_size
            sign = "+" if size_diff >= 0 else ""
            return f"Diff: Files differ (size change: {sign}{size_diff} bytes)"

        except Exception as e:
            logger.warning(f"Error performing diff: {e}")
            return None


class AddSpotlightFileCommand(CommandHandler):
    """Command handler for adding a file to spotlight tracking.

    This command prompts the user for a file path and adds it to the
    list of files being tracked for forensic analysis. Supports wildcards
    for adding multiple files at once.
    """

    key = "l"
    name = "Add Spotlight File"
    description = "Add a file to spotlight tracking"
    category = CommandCategory.FORENSIC
    views = ["forensic"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if forensic service is available.

        Args:
            ctx: Command context with forensic service access

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        return self._validate_forensic_service(ctx)

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the add spotlight file command.

        Args:
            ctx: Command context with input capabilities

        Returns:
            CommandResult indicating success/failure
        """
        # Get the file path from user
        file_path: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                # TUI mode - use async input modal
                file_path = await ctx.request_input(
                    title="Add Spotlight File",
                    prompt="Enter file path on device (supports wildcards):",
                    placeholder="/data/data/com.app/databases/*.db",
                )
            elif ctx.toolbox and hasattr(ctx.toolbox, "safe_input"):
                # Rich console mode - use safe_input
                logger.info("Enter file path to add to spotlight tracking:")
                file_path = ctx.toolbox.safe_input("File path: ")
            else:
                return CommandResult(
                    success=False,
                    message="No input method available",
                    error="Cannot prompt for input",
                )
        except Exception as e:
            logger.warning(f"Error getting file path input: {e}")
            return CommandResult(
                success=False, message=f"Error getting input: {e!s}", error=str(e)
            )

        # Check if input was cancelled or empty
        if file_path is None:
            return CommandResult(
                success=False, message="Input cancelled", error="User cancelled input"
            )

        file_path = file_path.strip()
        if not file_path:
            return CommandResult(
                success=False, message="No file path provided", error="Empty file path"
            )

        # Add the file to spotlight tracking
        success = False
        added_count = 0

        try:
            if ctx.forensic_service:
                success = ctx.forensic_service.add_spotlight_file(file_path)
                added_count = 1 if success else 0
            else:
                return CommandResult(
                    success=False,
                    message="Forensic service not available",
                    error="No service to add spotlight file",
                )
        except Exception as e:
            logger.exception("Error adding spotlight file")
            return CommandResult(
                success=False, message=f"Error adding file: {e!s}", error=str(e)
            )

        if success:
            # Get current list of spotlight files
            current_files = []
            if ctx.forensic_service:
                current_files = ctx.forensic_service.get_spotlight_files()

            return CommandResult(
                success=True,
                message=f"Added '{file_path}' to spotlight tracking. "
                f"Now tracking {len(current_files)} file(s).",
                data={
                    "added_path": file_path,
                    "total_files": len(current_files),
                    "spotlight_files": current_files,
                },
            )
        return CommandResult(
            success=False,
            message=f"Could not add '{file_path}' to spotlight. "
            "It may already be tracked or is invalid.",
            error="add_spotlight_file returned False",
        )


class RemoveSpotlightFileCommand(CommandHandler):
    """Command handler for removing a file from spotlight tracking.

    This command shows the current list of spotlight files and lets
    the user select which one to remove.
    """

    key = "v"
    name = "Remove Spotlight File"
    description = "Remove a file from spotlight tracking"
    category = CommandCategory.FORENSIC
    views = ["forensic"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if spotlight files exist to remove.

        Args:
            ctx: Command context with forensic service access

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # First validate forensic_service
        valid, msg = self._validate_forensic_service(ctx)
        if not valid:
            return (False, msg)

        # Then check if spotlight files exist to remove
        spotlight_files = ctx.forensic_service.get_spotlight_files()
        if not spotlight_files:
            return (False, "No spotlight files are currently being tracked.")

        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the remove spotlight file command.

        Args:
            ctx: Command context with selection capabilities

        Returns:
            CommandResult indicating success/failure
        """
        # Get current spotlight files
        spotlight_files: list[str] = []

        if ctx.forensic_service:
            spotlight_files = ctx.forensic_service.get_spotlight_files()

        if not spotlight_files:
            return CommandResult(
                success=False,
                message="No spotlight files are currently being tracked.",
                error="No spotlight files to remove",
            )

        # If only one file, remove it directly
        if len(spotlight_files) == 1:
            file_to_remove = spotlight_files[0]
        else:
            # Let user select which file to remove
            file_to_remove = await self._select_file_to_remove(ctx, spotlight_files)

        if file_to_remove is None:
            return CommandResult(
                success=False,
                message="No file selected for removal",
                error="Selection cancelled or failed",
            )

        # Remove the file from tracking
        success = False
        try:
            if ctx.forensic_service:
                success = ctx.forensic_service.remove_spotlight_file(file_to_remove)
            else:
                return CommandResult(
                    success=False,
                    message="Forensic service not available",
                    error="No service to remove spotlight file",
                )
        except Exception as e:
            logger.exception("Error removing spotlight file")
            return CommandResult(
                success=False, message=f"Error removing file: {e!s}", error=str(e)
            )

        if success:
            # Get remaining files
            remaining_files = []
            if ctx.forensic_service:
                remaining_files = ctx.forensic_service.get_spotlight_files()

            return CommandResult(
                success=True,
                message=f"Removed '{file_to_remove}' from spotlight tracking. "
                f"Now tracking {len(remaining_files)} file(s).",
                data={
                    "removed_path": file_to_remove,
                    "remaining_files": remaining_files,
                    "remaining_count": len(remaining_files),
                },
            )
        return CommandResult(
            success=False,
            message=f"Could not remove '{file_to_remove}' from spotlight.",
            error="remove_spotlight_file returned False",
        )

    async def _select_file_to_remove(
        self, ctx: CommandContext, files: list[str]
    ) -> str | None:
        """Prompt user to select a file to remove.

        Args:
            ctx: Command context
            files: List of current spotlight files

        Returns:
            Selected file path or None if cancelled
        """
        try:
            if ctx.is_tui_mode and ctx.request_selection:
                # TUI mode - use selection modal
                # Format options with indices for clarity
                options = [f"[{i + 1}] {f}" for i, f in enumerate(files)]
                selected = await ctx.request_selection(
                    title="Remove Spotlight File",
                    prompt="Select file to remove:",
                    options=options,
                )
                if selected is not None and 0 <= selected < len(files):
                    return files[selected]
            elif ctx.toolbox and hasattr(ctx.toolbox, "safe_input"):
                # Console mode - show numbered list
                logger.info("Current spotlight files:")
                for i, f in enumerate(files):
                    logger.info(f"  [{i + 1}] {f}")
                logger.info("\nEnter number to remove (or 0 to cancel):")

                choice = ctx.toolbox.safe_input("Choice: ")
                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(files):
                        return files[choice_num - 1]
                except (ValueError, TypeError):
                    pass

            return None
        except Exception as e:
            logger.warning(f"Error during file selection: {e}")
            return None


class PullAllSpotlightFilesCommand(CommandHandler):
    """Command handler for pulling all spotlight files at once.

    This command pulls all configured spotlight files from the device
    to a timestamped subdirectory, preserving directory hierarchy for
    multiple files.
    """

    key = "u"
    name = "Pull All Spotlight Files"
    description = "Pull all spotlight files from device"
    category = CommandCategory.FORENSIC
    views = ["forensic"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if spotlight files exist to pull.

        Args:
            ctx: Command context with forensic service access

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # First validate forensic_service
        valid, msg = self._validate_forensic_service(ctx)
        if not valid:
            return (False, msg)

        # Then check if spotlight files exist
        spotlight_files = ctx.forensic_service.get_spotlight_files()
        if not spotlight_files:
            return (
                False,
                "No spotlight files are set. Use 'l' to add spotlight files first.",
            )

        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the pull all spotlight files command.

        Args:
            ctx: Command context with toolbox access

        Returns:
            CommandResult indicating success/failure
        """
        # Get current spotlight files count first
        spotlight_files: list[str] = []

        if ctx.forensic_service:
            spotlight_files = ctx.forensic_service.get_spotlight_files()

        if not spotlight_files:
            return CommandResult(
                success=False,
                message="No spotlight files are set. Use 'l' to add spotlight files first.",
                error="No spotlight files configured",
            )

        # Prompt for optional description
        description: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                description = await ctx.request_input(
                    title="Pull Description",
                    prompt="Enter optional description for this pull (leave blank for none):",
                    placeholder="before_trigger",
                )
            elif ctx.toolbox and hasattr(ctx.toolbox, "safe_input"):
                logger.info(
                    "Enter optional description for this pull (leave blank for none):"
                )
                description = ctx.toolbox.safe_input("Description: ")
        except Exception as e:
            logger.warning(f"Error getting description: {e}")
            # Continue without description

        # Clean up empty description
        if description and not description.strip():
            description = None

        # Use FileExtractionService to pull files
        try:
            from sandroid.services import get_file_extraction_service

            extraction_service = get_file_extraction_service()
            results = extraction_service.pull_spotlight_files(
                files=spotlight_files, description=description
            )

            successful = sum(1 for r in results if r.success)

            if successful > 0:
                # Get the directory where files were pulled
                results_path = ctx.get_results_path()
                spotlight_dir = os.path.join(results_path, "spotlight_files")

                return CommandResult(
                    success=True,
                    message=f"Pulled {successful}/{len(spotlight_files)} spotlight file(s) to {spotlight_dir}",
                    data={
                        "files_pulled": spotlight_files,
                        "count": successful,
                        "total": len(spotlight_files),
                        "description": description,
                        "target_directory": spotlight_dir,
                        "results": [
                            {
                                "source": r.source_path,
                                "local": r.local_path,
                                "success": r.success,
                                "error": r.error,
                            }
                            for r in results
                        ],
                    },
                )
            return CommandResult(
                success=False,
                message="Failed to pull spotlight files",
                error="No files were successfully pulled",
            )

        except Exception as e:
            logger.exception("Error pulling spotlight files")
            return CommandResult(
                success=False, message=f"Error pulling files: {e!s}", error=str(e)
            )


def register_commands(registry) -> None:
    """Register all forensic commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(PullSpotlightFileCommand())
    registry.register(AddSpotlightFileCommand())
    registry.register(RemoveSpotlightFileCommand())
    registry.register(PullAllSpotlightFilesCommand())
