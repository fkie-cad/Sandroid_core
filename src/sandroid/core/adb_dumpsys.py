"""ADB ``dumpsys activity`` parsing.

Provides functions that query the Activity Manager's own diagnostic dumps
(``dumpsys activity services`` / ``dumpsys activity activities``) rather than
a system property or shell command. All functions accept a *send_command*
callable so they can be mixed into the ``Adb`` class without circular
imports, matching the convention in :mod:`adb_queries`/:mod:`adb_process`.

.. warning::
    Unlike :func:`sandroid.core.adb_packages.get_focused_app`'s proven
    ``dumpsys window`` regex, neither parser below has an existing verified
    precedent in this codebase (confirmed via grep) -- real ``dumpsys
    activity`` output varies across Android versions and OEM skins. Treat
    both as needing a live-device/emulator smoke-test pass, and back any new
    unit tests with captured real ``dumpsys`` output rather than
    hand-written fixtures.
"""

from __future__ import annotations

import re
import shlex
from logging import getLogger
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)

_SERVICE_RECORD_RE = re.compile(
    r"^\s*\*\s*ServiceRecord\{(?P<record_id>\S+)\s+(?P<user>u\d+)\s+"
    r"(?P<component>[^}]+)\}\s*$"
)
_SERVICE_PROCESS_RE = re.compile(r"ProcessRecord\{\S+\s+(?P<pid>\d+):(?P<proc>\S+)\}")

_TASK_RECORD_RE = re.compile(
    r"TaskRecord\{\S+\s+#(?P<task_id>\d+)(?:\s+A=(?P<affinity>\S+))?"
)
# The canonical per-task activity listing. ``dumpsys activity activities``
# prints each activity's record exactly once as a ``* Hist #N:`` line under
# its owning task, but echoes that same ActivityRecord across many summary
# lines elsewhere in the dump (mResumedActivity, mLastPausedActivity,
# mFocusedApp/mFocusedActivity, "Resumed:", the "Application tokens in top
# down Z order" section, ...). Anchoring on the ``Hist #N:`` prefix restricts
# parsing to that one authoritative listing so the echoes are not re-counted
# -- a device that emits 18 ActivityRecord lines for 4 real activities (one
# launcher task echoed 9 times, measured live) would otherwise yield 18.
_HIST_ACTIVITY_RE = re.compile(
    r"(?:\*\s*)?Hist\s+#\d+:\s*"
    r"ActivityRecord\{\S+\s+(?P<user>u\d+)\s+(?P<component>\S+)\s+t(?P<task_id>\d+)\}"
)


def list_services(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str | None = None,
) -> list[dict[str, Any]]:
    """List running Android services via ``dumpsys activity services``.

    Runs device-wide (no filter) when *package_name* is omitted, or scoped
    to one package (``dumpsys activity services <pkg>``, shlex-quoted) when
    given -- both forms emit the same ``ServiceRecord{...}`` block format,
    just narrowed to fewer blocks.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_name: Optional package to filter to. Omit to list every
            running service on the device.

    Returns:
        A list of dicts, each with keys ``'record_id'``, ``'user'``,
        ``'component'`` (``pkg/.Class``), ``'package_name'``, ``'pid'``
        (int or None), and ``'process_name'`` (or None). Empty if no
        services matched or the dump could not be parsed.
    """
    if package_name:
        command = f"shell dumpsys activity services {shlex.quote(package_name)}"
    else:
        command = "shell dumpsys activity services"

    stdout, stderr = send_command(command)
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"dumpsys activity services warning: {stderr}")
    if not stdout:
        return []

    services: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line in stdout.splitlines():
        match = _SERVICE_RECORD_RE.match(line)
        if match:
            if current is not None:
                services.append(current)
            component = match.group("component").strip()
            current = {
                "record_id": match.group("record_id"),
                "user": match.group("user"),
                "component": component,
                "package_name": component.split("/", 1)[0],
                "pid": None,
                "process_name": None,
            }
            continue

        if current is None:
            continue

        stripped = line.strip()
        if stripped.startswith("packageName="):
            current["package_name"] = stripped[len("packageName=") :]
        elif stripped.startswith("processName="):
            current["process_name"] = stripped[len("processName=") :]
        elif stripped.startswith("app="):
            proc_match = _SERVICE_PROCESS_RE.search(stripped)
            if proc_match:
                current["pid"] = int(proc_match.group("pid"))
                if not current.get("process_name"):
                    current["process_name"] = proc_match.group("proc")

    if current is not None:
        services.append(current)

    return services


def get_activity_stack(
    send_command: Callable[[str], tuple[str, str]],
) -> list[dict[str, Any]]:
    """Get the device's activity task stack via ``dumpsys activity activities``.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).

    Returns:
        A list of task dicts (in the order first encountered in the dump),
        each with keys ``'task_id'`` (int), ``'affinity'`` (str or None),
        and ``'activities'`` -- a list of ``{'component': str, 'user':
        str}`` dicts belonging to that task. Empty if the dump could not be
        parsed.
    """
    stdout, stderr = send_command("shell dumpsys activity activities")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"dumpsys activity activities warning: {stderr}")
    if not stdout:
        return []

    tasks: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def _task_entry(task_id: str) -> dict[str, Any]:
        if task_id not in tasks:
            tasks[task_id] = {
                "task_id": int(task_id),
                "affinity": None,
                "activities": [],
            }
            order.append(task_id)
        return tasks[task_id]

    for line in stdout.splitlines():
        task_match = _TASK_RECORD_RE.search(line)
        if task_match:
            task_id = task_match.group("task_id")
            entry = _task_entry(task_id)
            affinity = task_match.group("affinity")
            if affinity:
                entry["affinity"] = affinity
            continue

        activity_match = _HIST_ACTIVITY_RE.search(line)
        if activity_match:
            task_id = activity_match.group("task_id")
            entry = _task_entry(task_id)
            entry["activities"].append(
                {
                    "component": activity_match.group("component"),
                    "user": activity_match.group("user"),
                }
            )

    return [tasks[task_id] for task_id in order]
