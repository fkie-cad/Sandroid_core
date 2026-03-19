"""Analysis commands for static analysis and forensic scan."""

import logging

from sandroid.services import get_spotlight_service

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
)

logger = logging.getLogger(__name__)


class StaticAnalysisCommand(CommandHandler):
    """Command to perform static analysis on an APK.

    Uses dexray-insight (formerly ASAM) to perform comprehensive static
    analysis on the spotlight application's APK file, including:
    - Manifest analysis
    - Permission analysis
    - Security vulnerability scanning
    - Code analysis
    """

    key = "a"
    name = "Static Analysis"
    description = "Perform static analysis on APK"
    category = CommandCategory.ANALYSIS
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check that dexray-insight is available and a spotlight app is set.

        Args:
            ctx: Command context with current state

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        from sandroid.core.toolbox import Toolbox

        # Check dexray-insight availability first
        if not Toolbox.is_dexray_insight_available():
            return (
                False,
                "dexray-insight package not installed.\n\n"
                "Install with: pip install dexray-insight\n\n"
                "This optional dependency provides static APK analysis capabilities.",
            )

        # Check context-injected spotlight_service first, fall back to singleton
        if ctx.spotlight_service:
            if not ctx.spotlight_service.has_app():
                return (
                    False,
                    "No spotlight app selected. Press 'c' to select an app first.",
                )
            return True, ""

        # Fallback to singleton (for backwards compatibility)
        app = get_spotlight_service().get_app_tuple()
        if not app or app[0] is None:
            return False, "No spotlight app selected. Press 'c' to select an app first."
        return True, ""

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute static analysis on the spotlight application.

        Args:
            ctx: Command context with access to toolbox and services

        Returns:
            CommandResult indicating success/failure of the analysis
        """
        try:
            from sandroid.analysis.static_analysis import StaticAnalysis

            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            # Get spotlight app info for logging - use context if available
            if ctx.spotlight_service:
                app_info = ctx.spotlight_service.get_app_tuple()
            else:
                app_info = get_spotlight_service().get_app_tuple()
            app_name = app_info[0] if app_info else "unknown"

            logger.info(f"Starting static analysis for {app_name}")

            # Create static analysis instance and run
            static_analysis = StaticAnalysis()

            # Run gather which performs the analysis (interactive=True for config dialog)
            success = static_analysis.gather(interactive=True)

            if not success:
                return CommandResult(
                    success=False,
                    message="Static analysis cancelled or failed",
                    error="Analysis was cancelled by user or encountered an error",
                )

            # Get results
            results = static_analysis.return_data()

            # Check for errors in results
            if results and app_name in results:
                app_results = results[app_name]
                if "error" in app_results:
                    return CommandResult(
                        success=False,
                        message=f"Static analysis error: {app_results['error']}",
                        error=app_results["error"],
                        data=results,
                    )

            logger.info(f"Static analysis completed for {app_name}")

            return CommandResult(
                success=True,
                message=f"Static analysis completed for {app_name}",
                data=results,
            )

        except ImportError as e:
            logger.error(f"Failed to import StaticAnalysis: {e}")
            return CommandResult(
                success=False,
                message="Static analysis module not available",
                error=f"Import error: {e}",
            )
        except Exception as e:
            logger.exception("Error during static analysis")
            return CommandResult(
                success=False, message=f"Static analysis failed: {e!s}", error=str(e)
            )


class ForensicEvidenceScanCommand(CommandHandler):
    """Command to run forensic evidence scan using MVT-style IOC matching.

    Scans the device for indicators of compromise (IOCs) using STIX2
    indicator files. Checks:
    - Installed applications against known malicious packages
    - SMS messages for suspicious URLs, domains, and phone numbers
    - Call logs for suspicious phone numbers
    - APK file hashes against known malware hashes
    """

    key = "F"
    name = "Forensic Evidence Scan"
    description = "Run forensic evidence scan"
    category = CommandCategory.ANALYSIS
    views = ["forensic"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute forensic evidence scan on the device.

        Args:
            ctx: Command context with access to toolbox and services

        Returns:
            CommandResult indicating success/failure of the scan
        """
        try:
            from sandroid.core.forensic_evidence import ForensicEvidence

            logger.info("Starting forensic evidence scan")

            # Get ForensicEvidence singleton
            forensic = ForensicEvidence.get()

            # Check if configured
            if not forensic.is_configured():
                return CommandResult(
                    success=False,
                    message="Forensic evidence scan not configured",
                    error="No IOC path configured. Configure MVT settings in sandroid.toml.",
                )

            # Load IOCs if not already loaded
            if not forensic.load_iocs():
                return CommandResult(
                    success=False,
                    message="Failed to load IOC indicators",
                    error="Could not load STIX2 IOC files from configured path",
                )

            logger.info(f"Loaded {forensic.total_indicators} IOC indicators")

            # Define progress callback for logging
            def progress_callback(progress):
                if progress.message:
                    logger.debug(f"Scan progress: {progress.message}")

            # Run all scans
            results = forensic.run_scan(
                scan_apps=True,
                scan_sms=True,
                scan_calls=True,
                scan_files=True,
                progress_callback=progress_callback,
            )

            # Get summary
            summary = forensic.get_summary()

            # Count matches
            total_matches = summary.get("total_matches", 0)
            critical_matches = summary.get("critical_matches", 0)

            if total_matches > 0:
                message = f"Forensic scan complete: {total_matches} matches found"
                if critical_matches > 0:
                    message += f" ({critical_matches} CRITICAL)"
                logger.warning(message)
            else:
                message = "Forensic scan complete: No IOC matches found"
                logger.info(message)

            return CommandResult(
                success=True,
                message=message,
                data={
                    "summary": summary,
                    "total_indicators": forensic.total_indicators,
                    "matches": [m.to_dict() for m in forensic.all_matches],
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import ForensicEvidence: {e}")
            return CommandResult(
                success=False,
                message="Forensic evidence module not available",
                error=f"Import error: {e}",
            )
        except Exception as e:
            logger.exception("Error during forensic evidence scan")
            return CommandResult(
                success=False, message=f"Forensic scan failed: {e!s}", error=str(e)
            )


class ManageForensicApksCommand(CommandHandler):
    """Command to manage forensic APKs pulled from devices.

    Provides interface to view, install, and manage APKs that were
    pulled from devices after matching IOC indicators during forensic
    scanning.
    """

    key = "G"
    name = "Manage Forensic APKs"
    description = "View and install pulled forensic evidence APKs"
    category = CommandCategory.ANALYSIS
    views = ["forensic"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if forensic APKs are available.

        Args:
            ctx: Command context with current state

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        try:
            from sandroid.services import get_forensic_apk_service

            apk_service = get_forensic_apk_service()
            apks = apk_service.get_all()

            if not apks:
                return (
                    False,
                    "No forensic APKs found. Run MVT scan first or pull APKs manually.",
                )
            return True, ""
        except Exception as e:
            logger.debug(f"Error checking forensic APKs: {e}")
            return False, "Forensic APK service not available"

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Open forensic APK management interface.

        In TUI mode, opens the ForensicAPKModal.
        In CLI mode, lists available forensic APKs.

        Args:
            ctx: Command context with access to toolbox and services

        Returns:
            CommandResult indicating success/failure
        """
        try:
            from sandroid.services import get_forensic_apk_service

            apk_service = get_forensic_apk_service()
            apks = apk_service.get_all()

            if not apks:
                return CommandResult(
                    success=False,
                    message="No forensic APKs available",
                    error="No APKs have been pulled from devices",
                )

            # TUI mode - request modal via UI bus
            if ctx.is_tui_mode and ctx.ui_bus:
                logger.info(
                    f"Opening forensic APK manager ({len(apks)} APKs available)"
                )

                # Request TUI to show the modal
                await ctx.ui_bus.request_modal("forensic_apk_modal")

                return CommandResult(
                    success=True,
                    message=f"Forensic APK manager opened ({len(apks)} APKs)",
                    data={"apk_count": len(apks)},
                )

            # CLI mode - list APKs
            logger.info(f"Forensic APKs available: {len(apks)}")

            # Group by source device
            by_device: dict[str, list] = {}
            for apk in apks:
                device = apk.source_device_name or apk.source_device
                if device not in by_device:
                    by_device[device] = []
                by_device[device].append(apk)

            # Build summary
            summary_lines = [f"\nForensic APKs ({len(apks)} total):"]
            for device, device_apks in by_device.items():
                summary_lines.append(f"\n  From {device}:")
                for apk in device_apks:
                    severity_marker = (
                        "[!]" if apk.severity in ("critical", "high") else "   "
                    )
                    summary_lines.append(
                        f"    {severity_marker} {apk.package_name} ({apk.severity})"
                    )

            summary = "\n".join(summary_lines)
            logger.info(summary)

            return CommandResult(
                success=True,
                message=f"Listed {len(apks)} forensic APKs",
                data={
                    "apk_count": len(apks),
                    "by_device": {
                        k: [a.to_dict() for a in v] for k, v in by_device.items()
                    },
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import forensic APK service: {e}")
            return CommandResult(
                success=False,
                message="Forensic APK service not available",
                error=f"Import error: {e}",
            )
        except Exception as e:
            logger.exception("Error managing forensic APKs")
            return CommandResult(
                success=False,
                message=f"Failed to manage forensic APKs: {e!s}",
                error=str(e),
            )


def register_commands(registry) -> None:
    """Register all analysis commands.

    Args:
        registry: The CommandRegistry to register commands with
    """
    registry.register(StaticAnalysisCommand())
    registry.register(ForensicEvidenceScanCommand())
    registry.register(ManageForensicApksCommand())
