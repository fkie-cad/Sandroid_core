"""ADB process identification.

Provides functions for finding the PID of a running Android package,
with multiple fallback strategies.
"""

from __future__ import annotations

import time
from logging import getLogger
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)

#: Signals `kill_pid` is allowed to send. Both `kill_pid` and its internal
#: liveness probe interpolate `signal` directly into a shell command string,
#: so this allowlist (checked before either is built) is what keeps that
#: interpolation safe rather than `shlex.quote()` -- the value must be one of
#: these exact tokens, not merely quoted.
_ALLOWED_SIGNALS = {"TERM", "KILL", "HUP", "INT"}


# ---------------------------------------------------------------------------
# Individual PID-lookup strategies
# ---------------------------------------------------------------------------


def _try_pidof(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 1: Use the ``pidof`` shell command (fast, not always available).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    output, stderr = send_command(f"shell pidof {package_name}")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"pidof command warning for {package_name}: {stderr}")
    logger.debug(f"pidof output: '{output}', stderr: '{stderr}'")

    if output and output.strip():
        try:
            pid = int(output.strip().split()[0])
            logger.debug(f"Found PID {pid} for {package_name} via pidof")
            return pid
        except (ValueError, IndexError) as e:
            logger.debug(f"pidof parsing failed: {e}")
    return None


def _try_ps_a(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 2: Parse ``ps -A`` output (more reliable across versions).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(f"Trying ps -A fallback for {package_name}")
    output, _stderr = send_command("shell ps -A")
    logger.debug(f"ps -A output length: {len(output) if output else 0} chars")

    if output:
        for line in output.strip().split("\n"):
            if package_name in line:
                logger.debug(f"Found matching line: '{line}'")
                parts = line.split()
                logger.debug(f"Line parts: {parts}")
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        logger.debug(f"Found PID {pid} for {package_name} via ps -A")
                        return pid
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse PID from parts: {e}")
                        continue
    return None


def _try_ps_o(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 3: Parse ``ps -o PID,NAME`` output (alternative format).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(f"Trying ps -o PID,NAME fallback for {package_name}")
    output, _stderr = send_command("shell ps -o PID,NAME")

    if output:
        for line in output.strip().split("\n"):
            if package_name in line:
                logger.debug(f"Found matching line in ps -o: '{line}'")
                parts = line.split()
                if len(parts) >= 1:
                    try:
                        pid = int(parts[0])
                        logger.debug(f"Found PID {pid} for {package_name} via ps -o")
                        return pid
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse PID from ps -o: {e}")
                        continue
    return None


def _try_frida(package_name: str) -> int | None:
    """Strategy 4: Use Frida's ``enumerate_processes`` (last resort).

    Args:
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(
        f"All ADB methods failed, trying Frida as last resort for {package_name}"
    )
    try:
        import frida

        device = frida.get_usb_device()
        processes = device.enumerate_processes()
        for proc in processes:
            if proc.name == package_name or package_name in proc.name:
                logger.info(
                    f"Found PID {proc.pid} for {package_name} via Frida (last resort)"
                )
                return proc.pid
        logger.debug(f"Frida didn't find process {package_name}")
    except Exception as e:
        logger.debug(f"Frida PID lookup failed: {e}")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_pid_for_package_name(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
    use_frida_fallback: bool = True,
    quiet: bool = False,
) -> int | None:
    """Get the process ID (PID) for a given package name.

    Tries multiple methods in order of preference:

    1. ``pidof`` command -- fast and standard on most Android versions
    2. ``ps -A`` command -- more compatible across Android versions
    3. ``ps -o PID,NAME`` -- alternative format for some Android versions
    4. Frida ``enumerate_processes`` -- last resort, requires Frida

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_name: The fully qualified package name.
        use_frida_fallback: When True (default), fall back to Frida's
            ``enumerate_processes`` if the ADB strategies all fail. Set to
            False for latency-sensitive hot paths (e.g. a periodic
            running-state poll) where the Frida round-trip is too heavy.
        quiet: When True, a final miss is logged at debug instead of warning.
            Set this for paths where "not running" is an expected, frequent
            outcome (e.g. the running-state poll on a stopped app) so the log
            isn't spammed with misleading warnings.

    Returns:
        The process ID if found, *None* otherwise.
    """
    strategies = [
        lambda: _try_pidof(send_command, package_name),
        lambda: _try_ps_a(send_command, package_name),
        lambda: _try_ps_o(send_command, package_name),
    ]
    if use_frida_fallback:
        strategies.append(lambda: _try_frida(package_name))

    for strategy in strategies:
        pid = strategy()
        if pid is not None:
            return pid

    if quiet:
        logger.debug(f"No PID for package {package_name} (not running)")
    else:
        logger.warning(
            f"Could not find PID for package {package_name} using any method"
        )
    return None


def list_processes(
    send_command: Callable[[str], tuple[str, str]],
    package_filter: str | None = None,
) -> list[dict[str, str | int]]:
    """List running processes on the device via ``ps -A``.

    Generalizes :func:`_try_ps_a`'s parsing of the full ``ps -A`` output --
    that helper already parses every process line before filtering down to
    one package; this drops the filter (or narrows it to a substring match)
    and returns the parsed rows directly instead of a single PID.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_filter: Optional substring to match against each process
            name. Omit to list every running process on the device.

    Returns:
        A list of dicts, each with keys ``'pid'`` (int), ``'user'`` (str),
        and ``'name'`` (str). Lines that don't parse as a process row
        (notably the ``ps -A`` header line, where the PID column fails
        ``int()``) are silently skipped.
    """
    output, stderr = send_command("shell ps -A")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"ps -A warning: {stderr}")

    processes: list[dict[str, str | int]] = []
    if not output:
        return processes

    for line in output.strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue

        name = parts[-1]
        if package_filter and package_filter not in name:
            continue

        processes.append({"pid": pid, "user": parts[0], "name": name})

    return processes


def get_process_detail(
    send_command: Callable[[str], tuple[str, str]],
    pid: int,
) -> dict[str, Any] | None:
    """Get detailed process info from ``/proc/<pid>``.

    Parses ``/proc/<pid>/status`` for Name/State/PPid/Threads/Uid/VmRSS/
    VmSize, plus an open-file-descriptor count (``ls /proc/<pid>/fd | wc -l``)
    and a memory-map region count (``wc -l /proc/<pid>/maps``).

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        pid: The process ID to inspect.

    Returns:
        A dict with keys ``'pid'``, ``'name'``, ``'state'``, ``'ppid'``,
        ``'threads'``, ``'uid'``, ``'uid_map'``, ``'gid'``, ``'gid_map'``,
        ``'vm_rss_kb'``, ``'vm_size_kb'``, ``'fd_count'``,
        ``'map_region_count'``, or *None* if the process is gone or
        ``/proc/<pid>/status`` is otherwise unreadable.

        ``/proc/<pid>/status`` prints ``Uid``/``Gid`` as four
        whitespace-separated values (real, effective, saved-set,
        filesystem). ``'uid'``/``'gid'`` expose the real id as an ``int``;
        ``'uid_map'``/``'gid_map'`` carry all four keyed by ``'real'``,
        ``'effective'``, ``'saved'``, ``'fs'`` (each ``None`` if the line was
        missing or unparseable).
    """
    status_out, status_err = send_command(f"shell cat /proc/{pid}/status")
    if not status_out or not status_out.strip():
        logger.debug(
            f"get_process_detail: /proc/{pid}/status unreadable ({status_err})"
        )
        return None

    fields: dict[str, str] = {}
    for line in status_out.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()

    if "Name" not in fields:
        return None

    fd_out, _fd_err = send_command(f"shell ls /proc/{pid}/fd | wc -l")
    maps_out, _maps_err = send_command(f"shell wc -l /proc/{pid}/maps")

    def _leading_int(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value.strip().split()[0])
        except (ValueError, IndexError):
            return None

    def _id_set(value: str | None) -> tuple[int | None, dict[str, int] | None]:
        """Parse a ``/proc/<pid>/status`` Uid/Gid line.

        Those lines are printed as four whitespace-separated ids -- real,
        effective, saved-set, filesystem. Returns the real id (first field)
        plus a map of all four, or ``(None, None)`` if none parsed.
        """
        if not value:
            return None, None
        labels = ("real", "effective", "saved", "fs")
        id_map: dict[str, int] = {}
        for label, token in zip(labels, value.split(), strict=False):
            try:
                id_map[label] = int(token)
            except ValueError:
                break
        if not id_map:
            return None, None
        return id_map["real"], id_map

    uid, uid_map = _id_set(fields.get("Uid"))
    gid, gid_map = _id_set(fields.get("Gid"))

    return {
        "pid": pid,
        "name": fields.get("Name"),
        "state": fields.get("State"),
        "ppid": _leading_int(fields.get("PPid")),
        "threads": _leading_int(fields.get("Threads")),
        "uid": uid,
        "uid_map": uid_map,
        "gid": gid,
        "gid_map": gid_map,
        "vm_rss_kb": _leading_int(fields.get("VmRSS")),
        "vm_size_kb": _leading_int(fields.get("VmSize")),
        "fd_count": _leading_int(fd_out),
        "map_region_count": _leading_int(maps_out),
    }


def kill_pid(
    send_command: Callable[[str], tuple[str, str]],
    send_root_shell: Callable[[str], tuple[str, str]],
    pid: int,
    signal: str = "TERM",
) -> tuple[bool, bool]:
    """Send a signal to a process, retrying as root if it doesn't die.

    Sends the signal via a plain (non-root) shell first; if the process is
    still alive after a settle-timeout poll, retries once via
    :meth:`Adb.send_root_shell` (the established ``su 0 <command>``
    primitive already reused elsewhere for this "run one root command via
    ADB" need -- see ``services/device_settings_service.py``). A single
    immediate re-probe right after sending the signal is not reliable
    (SIGTERM isn't instantaneous, especially for ART/Zygote-forked app
    processes), so both attempts are followed by a poll loop rather than one
    check.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        send_root_shell: Callable matching :meth:`Adb.send_root_shell` --
            runs a shell command as root via ``su 0``.
        pid: The target process ID. Coerced with ``int()``.
        signal: Signal name to send. Must be one of ``_ALLOWED_SIGNALS``
            (``'TERM'``, ``'KILL'``, ``'HUP'``, ``'INT'``) -- both this
            value and *pid* are interpolated directly into a shell command
            string, so validating them up front (rather than merely quoting)
            is what keeps that interpolation safe.

    Returns:
        A tuple of ``(killed, used_root)``: ``killed`` is True once the
        process is confirmed gone via the settle-timeout poll, ``used_root``
        is True if the root-shell retry was needed to get there.

    Raises:
        ValueError: *pid* is not coercible to ``int``, or *signal* is not
            one of ``_ALLOWED_SIGNALS``.
    """
    pid = int(pid)
    if signal not in _ALLOWED_SIGNALS:
        raise ValueError(
            f"unsupported signal {signal!r}, must be one of "
            f"{sorted(_ALLOWED_SIGNALS)}"
        )

    def _alive() -> bool:
        out, err = send_command(f"shell kill -0 {pid}")
        combined = f"{out or ''} {err or ''}".lower()
        return "no such process" not in combined

    def _settled_dead(timeout_s: float = 2.0, interval_s: float = 0.3) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not _alive():
                return True
            time.sleep(interval_s)
        return not _alive()

    send_command(f"shell kill -s {signal} {pid}")
    if _settled_dead():
        return True, False

    send_root_shell(f"kill -s {signal} {pid}")
    return _settled_dead(), True
