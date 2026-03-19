"""Background work tracker for detecting untracked threads and processes.

This module provides diagnostics and cleanup for background work that
isn't properly registered with TaskService. It helps identify bugs
where tasks aren't properly tracked.

Usage:
    from sandroid.core.background_tracker import get_background_tracker

    # Detect untracked work
    tracker = get_background_tracker()
    report = tracker.detect_untracked_work()

    if report.has_untracked_work:
        print(report.format_report())
        cleaned = tracker.force_cleanup(report)
"""

import logging
import os
import signal
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Known Sandroid thread name patterns (threads we expect)
KNOWN_THREAD_PATTERNS = {
    "MainThread",
    "Dummy-",  # Textual internal
    "asyncio",
    "ThreadPoolExecutor",
    "AnyIO",
    "concurrent",
}

# Thread patterns that indicate Sandroid work
SANDROID_THREAD_PATTERNS = {
    "network": "Network Capture",
    "screenshot": "Screenshot",
    "screenrecord": "Screen Recording",
    "frida": "Frida Session",
    "fsmon": "File Monitor",
    "forensic": "Forensic Scan",
    "emulator": "Emulator",
    "recording": "Screen Recording",
    "capture": "Network Capture",
}


@dataclass
class UntrackedWork:
    """Represents untracked background work."""

    work_type: str  # "thread", "process", "frida_job"
    name: str
    details: str
    identifier: Any = None  # Thread object, PID, or job_id


@dataclass
class BackgroundWorkReport:
    """Report of all detected untracked background work."""

    untracked_threads: list[UntrackedWork] = field(default_factory=list)
    untracked_processes: list[UntrackedWork] = field(default_factory=list)
    untracked_frida_jobs: list[UntrackedWork] = field(default_factory=list)

    @property
    def has_untracked_work(self) -> bool:
        """Check if any untracked work was detected."""
        return bool(
            self.untracked_threads
            or self.untracked_processes
            or self.untracked_frida_jobs
        )

    @property
    def total_count(self) -> int:
        """Get total count of untracked work items."""
        return (
            len(self.untracked_threads)
            + len(self.untracked_processes)
            + len(self.untracked_frida_jobs)
        )

    def format_report(self) -> str:
        """Format report for user notification."""
        if not self.has_untracked_work:
            return ""

        lines = [f"Detected {self.total_count} untracked background task(s):"]

        for work in self.untracked_threads:
            lines.append(f"  - Thread: {work.name} ({work.details})")

        for work in self.untracked_processes:
            lines.append(f"  - Process: {work.name} (PID: {work.details})")

        for work in self.untracked_frida_jobs:
            lines.append(f"  - Frida Job: {work.name} ({work.details})")

        lines.append("")
        lines.append("These tasks were not properly registered with TaskService.")
        lines.append("Please report this as a bug for investigation.")

        return "\n".join(lines)


class BackgroundWorkTracker:
    """Tracks and cleans up untracked background work.

    This class detects threads, processes, and Frida jobs that are
    running but not registered with TaskService. It helps identify
    bugs where tasks aren't properly tracked.
    """

    def __init__(self):
        """Initialize the BackgroundWorkTracker."""
        self._main_thread_id = threading.main_thread().ident

    def has_untracked_frida_jobs(self) -> bool:
        """Quick check for untracked Frida jobs.

        This is a fast method for checking if there are untracked Frida jobs
        without generating a full report. Useful for quit flow checks.

        Returns:
            True if untracked Frida jobs exist, False otherwise.
        """
        try:
            from sandroid.services import get_frida_session_service, get_task_service

            frida_service = get_frida_session_service()

            if not frida_service.has_active_session():
                return False

            running_jobs = frida_service.get_running_jobs()
            if not running_jobs:
                return False

            task_service = get_task_service()
            registered_tasks = task_service.get_running()

            # Map job types to expected task names
            job_to_task = {
                "fritap": "fritap",
                "dexray": "dexray-intercept",
                "trigdroid": "trigdroid",
            }

            for job_info in running_jobs:
                job_type = job_info.get("job_type", "unknown")
                expected_task = job_to_task.get(job_type, job_type)
                if expected_task not in registered_tasks:
                    return True

            return False
        except Exception as e:
            logger.debug(f"Error checking for untracked Frida jobs: {e}")
            return False

    def detect_untracked_work(self) -> BackgroundWorkReport:
        """Detect all untracked background work.

        Returns:
            BackgroundWorkReport with details of untracked work.
        """
        report = BackgroundWorkReport()

        # 1. Detect untracked threads
        report.untracked_threads = self._detect_untracked_threads()

        # 2. Detect untracked child processes
        report.untracked_processes = self._detect_untracked_processes()

        # 3. Detect untracked Frida jobs
        report.untracked_frida_jobs = self._detect_untracked_frida_jobs()

        return report

    def _detect_untracked_threads(self) -> list[UntrackedWork]:
        """Detect Sandroid threads not registered with TaskService."""
        untracked = []

        try:
            from sandroid.services import get_task_service

            task_service = get_task_service()
            registered_tasks = task_service.get_running()
        except Exception:
            registered_tasks = []

        for thread in threading.enumerate():
            # Skip main thread
            if thread.ident == self._main_thread_id:
                continue

            # Skip known system threads
            thread_name = thread.name or ""
            if any(pattern in thread_name for pattern in KNOWN_THREAD_PATTERNS):
                continue

            # Check if this looks like a Sandroid thread
            sandroid_type = None
            for pattern, type_name in SANDROID_THREAD_PATTERNS.items():
                if pattern in thread_name.lower():
                    sandroid_type = type_name
                    break

            if sandroid_type and thread.is_alive():
                # Check if registered
                task_name = thread_name.lower().replace("thread", "").strip()
                if task_name not in registered_tasks:
                    untracked.append(
                        UntrackedWork(
                            work_type="thread",
                            name=sandroid_type,
                            details=f"Thread: {thread_name}, daemon={thread.daemon}",
                            identifier=thread,
                        )
                    )

        return untracked

    def _detect_untracked_processes(self) -> list[UntrackedWork]:
        """Detect child processes not tracked by Sandroid."""
        untracked = []

        try:
            import psutil

            main_process = psutil.Process()
            children = main_process.children(recursive=True)

            for child in children:
                try:
                    cmd = " ".join(child.cmdline())
                    name = child.name()

                    # Identify process type
                    if "adb" in name.lower() or "adb" in cmd.lower():
                        proc_type = "ADB Command"
                    elif "emulator" in name.lower():
                        proc_type = "Emulator"
                    elif "frida" in name.lower():
                        proc_type = "Frida Server"
                    elif "tcpdump" in name.lower():
                        proc_type = "Network Capture"
                    else:
                        continue  # Skip unknown processes

                    untracked.append(
                        UntrackedWork(
                            work_type="process",
                            name=proc_type,
                            details=str(child.pid),
                            identifier=child.pid,
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            # psutil not available, skip process detection
            logger.debug("psutil not available, skipping process detection")
        except Exception as e:
            logger.debug(f"Error detecting processes: {e}")

        return untracked

    def _detect_untracked_frida_jobs(self) -> list[UntrackedWork]:
        """Detect Frida jobs not registered with TaskService."""
        untracked = []

        try:
            from sandroid.services import get_frida_session_service, get_task_service

            frida_service = get_frida_session_service()
            task_service = get_task_service()

            if not frida_service.has_active_session():
                return untracked

            running_jobs = frida_service.get_running_jobs()
            registered_tasks = task_service.get_running()

            # Map job types to task names
            job_to_task = {
                "fritap": "fritap",
                "dexray": "dexray-intercept",
                "trigdroid": "trigdroid",
            }

            for job_info in running_jobs:
                job_type = job_info.get("job_type", "unknown")
                job_id = job_info.get("job_id", "unknown")

                expected_task = job_to_task.get(job_type, job_type)
                if expected_task not in registered_tasks:
                    untracked.append(
                        UntrackedWork(
                            work_type="frida_job",
                            name=job_info.get("display_name", job_type),
                            details=f"job_id={job_id[:8]}..."
                            if len(job_id) > 8
                            else f"job_id={job_id}",
                            identifier=job_id,
                        )
                    )
        except Exception as e:
            logger.debug(f"Error detecting Frida jobs: {e}")

        return untracked

    def force_cleanup(self, report: BackgroundWorkReport) -> list[str]:
        """Forcefully clean up untracked background work.

        Args:
            report: BackgroundWorkReport from detect_untracked_work()

        Returns:
            List of cleaned up item descriptions.
        """
        cleaned = []

        # 1. Stop untracked Frida jobs first (graceful)
        for work in report.untracked_frida_jobs:
            try:
                from sandroid.services import get_frida_session_service

                frida_service = get_frida_session_service()
                job_manager = frida_service.get_job_manager()

                job_manager.stop_job_with_id(work.identifier, timeout=2.0)
                cleaned.append(f"Stopped Frida job: {work.name}")
                logger.warning(f"Force-stopped untracked Frida job: {work.name}")
            except Exception as e:
                logger.debug(f"Error stopping Frida job {work.name}: {e}")

        # 2. Kill untracked processes
        for work in report.untracked_processes:
            try:
                pid = work.identifier
                os.kill(pid, signal.SIGTERM)
                cleaned.append(f"Killed process: {work.name} (PID: {pid})")
                logger.warning(
                    f"Force-killed untracked process: {work.name} (PID: {pid})"
                )
            except (ProcessLookupError, PermissionError) as e:
                logger.debug(f"Error killing process {work.name}: {e}")

        # 3. Note: Can't directly kill threads, but we log them
        for work in report.untracked_threads:
            # Daemon threads will die with main process
            # Non-daemon threads we can only log
            thread = work.identifier
            if thread and not thread.daemon:
                cleaned.append(f"WARNING: Non-daemon thread still alive: {work.name}")
                logger.warning(f"Untracked non-daemon thread: {work.name}")
            else:
                cleaned.append(f"Daemon thread will exit: {work.name}")

        return cleaned


# Singleton instance
_tracker: BackgroundWorkTracker | None = None


def get_background_tracker() -> BackgroundWorkTracker:
    """Get the singleton BackgroundWorkTracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = BackgroundWorkTracker()
    return _tracker


__all__ = [
    "BackgroundWorkReport",
    "BackgroundWorkTracker",
    "UntrackedWork",
    "get_background_tracker",
]
