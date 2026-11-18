"""Emulator launch flags and host-memory guard.

Background: with guest Vulkan enabled, the Android emulator renders through
SwiftShader (software Vulkan) and leaks host colour buffers on every snapshot
load ("on load, stale colorbuffers: N" in the emulator log). Sandroid loads a
snapshot for every replay and dry run, so a long session can grow
``qemu-system-*`` to tens of GB and exhaust the host's memory.

This module provides

* :data:`SAFE_EMULATOR_ARGS` / :func:`emulator_launch_args` -- the flags every
  Sandroid-launched emulator uses (guest Vulkan off, host GPU), and
* :class:`EmulatorMemoryGuard` -- a daemon thread that watches the qemu process
  behind the active ADB serial and stops the emulator once its host memory
  stays above the limit (see :func:`effective_limit_bytes`). It also warns
  once when the emulator was started *without* ``-feature -Vulkan`` (e.g. by
  hand).

What is measured (:func:`measure_host_memory`): on macOS the *physical
footprint* reported by ``footprint -p <pid>`` (dirty memory, what the leak
grows), elsewhere -- or when ``footprint`` is unavailable -- the resident set
size. macOS RSS is not usable on its own: it also counts resident guest-RAM
pages a second time, so a healthy 8 GB AVD read 8.5-15.0 GB RSS while its
footprint was 6.5-9.3 GB.

macOS has no cgroups, so polling is the only portable way to cap the process.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Flags Sandroid passes to every emulator it launches.
SAFE_EMULATOR_ARGS: list[str] = ["-feature", "-Vulkan"]

_GB = 1024**3


def emulator_launch_args(*, headless: bool = False) -> list[str]:
    """Return the safe emulator flags (Vulkan off + GPU mode).

    Windowed emulators use the host GPU for GLES. Headless emulators fall
    back to software GLES (``swiftshader_indirect``); with guest Vulkan
    disabled that path does not leak.
    """
    gpu = "swiftshader_indirect" if headless else "host"
    return [*SAFE_EMULATOR_ARGS, "-gpu", gpu]


def vulkan_disabled(cmdline: list[str]) -> bool:
    """True if an emulator command line disables guest Vulkan."""
    for i, arg in enumerate(cmdline[:-1]):
        if arg == "-feature" and "-Vulkan" in cmdline[i + 1].split(","):
            return True
    return False


def console_port(cmdline: list[str]) -> int | None:
    """Explicit console port of an emulator command line (``-port N``).

    Returns ``None`` when the command line has no ``-port``/``-ports``: the
    emulator then auto-assigns the first free even port from 5554, so the
    port cannot be derived from the command line (Sandroid itself never
    passes ``-port``).
    """
    for i, arg in enumerate(cmdline[:-1]):
        if arg in ("-port", "-ports"):
            try:
                return int(cmdline[i + 1].split(",")[0])
            except ValueError:
                return None
    return None


def _proc_listens_on(proc: Any, port: int) -> bool | None:
    """True/False if *proc* has a TCP LISTEN socket on *port*; None if unknown."""
    getter = getattr(proc, "net_connections", None) or getattr(
        proc, "connections", None
    )
    if getter is None:
        return None
    try:
        conns = getter(kind="tcp")
    except Exception:  # AccessDenied, NoSuchProcess, ...
        return None
    for conn in conns:
        laddr = getattr(conn, "laddr", None)
        if (
            laddr
            and getattr(laddr, "port", None) == port
            and getattr(conn, "status", "") == "LISTEN"
        ):
            return True
    return False


def _lsof_listener_pids(port: int) -> set[int] | None:
    """PIDs with a TCP LISTEN socket on *port* via ``lsof``; None if unknown."""
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        return None
    if result.returncode not in (0, 1):  # 1 == no matching socket
        return None
    return {int(tok) for tok in result.stdout.split() if tok.isdigit()}


#: Serials we already warned about (could not identify their qemu process).
_unidentified_serials: set[str] = set()


def _warn_unidentified(serial: str, reason: str) -> None:
    if serial in _unidentified_serials:
        return
    _unidentified_serials.add(serial)
    logger.warning(
        "Emulator memory guard: cannot identify the qemu process behind %s "
        "(%s); it is not monitored and will never be stopped by the guard.",
        serial,
        reason,
    )


def find_emulator_process(serial: str | None) -> Any | None:
    """Return the ``psutil.Process`` of the qemu behind ``emulator-<port>``.

    Matching, most reliable first:

    1. a qemu started with an explicit ``-port <port>``;
    2. the qemu that owns the TCP LISTEN socket on the console port (per
       process via psutil, falling back to ``lsof`` where psutil is denied);
    3. the only running qemu without ``-port`` when no socket information is
       available at all.

    Anything else is ambiguous: ``None`` is returned (and a warning logged
    once per serial) so the guard never measures or kills the wrong
    emulator -- e.g. the analyst's own AVD on another auto-assigned port.

    Returns ``None`` for non-emulator serials, when psutil is unavailable or
    no unique matching process is found.
    """
    if not serial:
        return None
    match = re.fullmatch(r"emulator-(\d+)", serial)
    if not match:
        return None
    port = int(match.group(1))
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a core dependency
        return None
    implicit: list[Any] = []
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = proc.info.get("name") or ""
            cmdline = proc.info.get("cmdline") or []
        except Exception:
            continue
        if not name.startswith("qemu-system") or not cmdline:
            continue
        explicit = console_port(cmdline)
        if explicit == port:
            return proc
        if explicit is None:
            implicit.append(proc)
    if not implicit:
        return None

    unknown: list[Any] = []
    for proc in implicit:
        listening = _proc_listens_on(proc, port)
        if listening:
            return proc
        if listening is None:
            unknown.append(proc)
    if not unknown:
        return None  # every candidate answered: none owns this console port

    pids = _lsof_listener_pids(port)
    if pids is not None:
        owners = [p for p in unknown if p.pid in pids]
        if len(owners) == 1:
            return owners[0]
        if not owners:
            return None
    elif len(implicit) == 1:
        return implicit[0]
    _warn_unidentified(
        serial, f"{len(implicit)} emulators without -port, console owner unknown"
    )
    return None


# -- measuring ---------------------------------------------------------------

_UNIT_BYTES = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": _GB, "TB": 1024**4}


def parse_footprint_output(text: str) -> int | None:
    """Bytes from ``footprint -p`` output ("... Footprint: 6434 MB (16384 ...").

    Returns ``None`` when the output has no ``Footprint:`` figure.
    """
    match = re.search(r"Footprint:\s*([\d.]+)\s*([KMGT]?B)\b", text or "")
    if not match:
        return None
    try:
        return int(float(match.group(1)) * _UNIT_BYTES[match.group(2)])
    except (KeyError, ValueError):
        return None


def footprint_bytes(pid: int) -> int | None:
    """Physical footprint of *pid* via macOS ``footprint``; None if unavailable.

    ``psutil.Process.memory_full_info()`` needs task_for_pid (AccessDenied
    for the user's own qemu) and the kernel's ``ri_phys_footprint`` ledger
    (``proc_pid_rusage``, Activity Monitor's "Memory") read 12.3 GB on the
    same healthy 8 GB AVD -- both unusable here, hence the subprocess
    (~0.4 s CPU per call).
    """
    if sys.platform != "darwin":
        return None
    exe = shutil.which("footprint") or (
        "/usr/bin/footprint" if os.path.exists("/usr/bin/footprint") else None
    )
    if exe is None:
        return None
    try:
        result = subprocess.run(
            [exe, "-p", str(int(pid))],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        return None
    return parse_footprint_output(result.stdout)


def measure_host_memory(proc: Any) -> tuple[int, str] | None:
    """``(bytes, metric)`` for an emulator process; None if it is gone.

    ``metric`` is ``"footprint"`` (macOS physical footprint) or ``"rss"``.
    """
    value = footprint_bytes(proc.pid)
    if value:
        return value, "footprint"
    try:
        return int(proc.memory_info().rss), "rss"
    except Exception:
        return None


# -- the guest's RAM -----------------------------------------------------------

#: Headroom over the guest RAM for qemu itself (GPU buffers, caches). A
#: healthy 8 GB AVD measured at most 9.3 GB footprint (guest + 1.3 GB), even
#: after two snapshot loads.
GUEST_RAM_MARGIN_GB = 4.0


def parse_ram_size(value: str) -> int | None:
    """Bytes of an ``hw.ramSize`` / ``-memory`` value (MB unless suffixed)."""
    match = re.fullmatch(
        r"\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*", str(value or ""), re.IGNORECASE
    )
    if not match:
        return None
    unit = match.group(2).upper() or "M"
    return int(float(match.group(1)) * _UNIT_BYTES[unit + "B"]) or None


def _avd_dir(name: str) -> Path | None:
    """Directory of AVD *name* (honours ``ANDROID_AVD_HOME`` and ``path=``)."""
    try:
        from sandroid.config.android_env import find_existing_avd_home

        home = find_existing_avd_home()
    except Exception:
        home = None
    home = home or Path("~/.android/avd").expanduser()
    try:
        for line in (home / f"{name}.ini").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "path" and Path(value.strip()).is_dir():
                return Path(value.strip())
    except OSError:
        pass
    default = home / f"{name}.avd"
    return default if default.is_dir() else None


def guest_ram_bytes(cmdline: list[str]) -> int | None:
    """Guest RAM of an emulator: ``-memory`` or the AVD's ``hw.ramSize``.

    ``hardware-qemu.ini`` (what the running emulator resolved) wins over
    ``config.ini``. Returns ``None`` when neither can be read.
    """
    avd = None
    for i, arg in enumerate(cmdline[:-1]):
        if arg == "-memory":
            size = parse_ram_size(cmdline[i + 1])
            if size:
                return size
        elif arg == "-avd":
            avd = cmdline[i + 1]
    if not avd:
        return None
    avd_dir = _avd_dir(avd)
    if avd_dir is None:
        return None
    for name in ("hardware-qemu.ini", "config.ini"):
        try:
            text = (avd_dir / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "hw.ramSize":
                size = parse_ram_size(value)
                if size:
                    return size
    return None


def effective_limit_bytes(
    configured: int, guest_ram: int | None, metric: str = "footprint"
) -> int:
    """The limit the guard enforces: never below what a healthy AVD needs.

    ``max(emulator.max_host_memory_gb, guest RAM + 4 GB)`` for the macOS
    footprint. RSS (Linux, or macOS without ``footprint``) can count the
    guest RAM twice on macOS (15.0 GB RSS on a healthy 8 GB AVD), so the RSS
    floor is ``2 x guest RAM + 4 GB``. A configured limit of 0 disables the
    guard; an unknown guest RAM leaves the configured limit as is.
    """
    if configured <= 0 or not guest_ram:
        return configured
    factor = 1 if metric == "footprint" else 2
    floor = factor * guest_ram + int(GUEST_RAM_MARGIN_GB * _GB)
    return max(configured, floor)


class EmulatorMemoryGuard:
    """Watch the active emulator's host memory and stop it above a limit."""

    def __init__(
        self,
        serial_getter: Callable[[], str | None],
        *,
        limit_gb: float = 10.0,
        action: str = "kill",
        interval: float = 10.0,
        confirm_delay: float | None = None,
        adb_path_getter: Callable[[], str] | None = None,
        notify: Callable[[str, int], None] | None = None,
    ) -> None:
        self._serial_getter = serial_getter
        #: The configured limit (emulator.max_host_memory_gb); the enforced
        #: one is scaled by the guest RAM, see effective_limit_bytes().
        self.limit_bytes = int(limit_gb * _GB)
        self.action = action
        self.interval = interval
        #: Pause before the confirming re-measurement of an over-limit reading.
        self.confirm_delay = interval if confirm_delay is None else confirm_delay
        self._adb_path_getter = adb_path_getter or (lambda: "adb")
        self._notify = notify or (lambda msg, level: logger.log(level, msg))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._warned_pids: set[int] = set()
        self._near_limit_pids: set[int] = set()
        self._guest_ram: dict[int, int | None] = {}

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="sandroid-emulator-memguard", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.check_once()
            except Exception:  # never let the guard die silently
                logger.debug("emulator memory guard check failed", exc_info=True)

    # -- one poll ----------------------------------------------------------
    def check_once(self) -> str | None:
        """Run one check. Returns "warned", "killed", "over-limit" or None."""
        serial = self._serial_getter()
        proc = find_emulator_process(serial)
        if proc is None:
            return None
        try:
            cmdline = proc.cmdline()
        except Exception:
            return None
        measured = measure_host_memory(proc)
        if measured is None:
            return None
        used, metric = measured

        if proc.pid not in self._warned_pids and not vulkan_disabled(cmdline):
            self._warned_pids.add(proc.pid)
            self._notify(
                f"Emulator {serial} was started without '-feature -Vulkan'. "
                "Snapshot loads then leak host memory (SwiftShader Vulkan). "
                "Restart it with: emulator -avd <AVD> -feature -Vulkan -gpu host",
                logging.WARNING,
            )

        if self.limit_bytes <= 0:
            return None
        if proc.pid not in self._guest_ram:
            self._guest_ram[proc.pid] = guest_ram_bytes(cmdline)
        guest = self._guest_ram[proc.pid]
        limit = effective_limit_bytes(self.limit_bytes, guest, metric)
        if used >= 0.75 * limit and proc.pid not in self._near_limit_pids:
            self._near_limit_pids.add(proc.pid)
            self._notify(
                f"Emulator {serial} uses {used / _GB:.1f} GB host memory "
                f"({metric}; {self._limit_text(limit, guest, metric)}).",
                logging.WARNING,
            )
        if used < limit:
            return None

        # Confirm before acting: a single reading (start-up, snapshot load)
        # must not stop the emulator.
        if self._stop.wait(self.confirm_delay):
            return None
        confirmed = measure_host_memory(proc)
        if confirmed is None:
            return None
        used, metric = confirmed
        limit = effective_limit_bytes(self.limit_bytes, guest, metric)
        if used < limit:
            logger.info(
                "Emulator %s host memory back to %.1f GB (%s) on re-check; "
                "not over the %.0f GB limit",
                serial,
                used / _GB,
                metric,
                limit / _GB,
            )
            return None

        msg = (
            f"Emulator {serial} uses {used / _GB:.1f} GB host memory ({metric}), "
            f"above its limit on two readings ({self._limit_text(limit, guest, metric)})."
        )
        if self.action != "kill":
            self._notify(msg, logging.ERROR)
            return "over-limit"
        self._notify(
            msg + " Shutting the emulator down to protect the host.", logging.ERROR
        )
        self._shutdown(serial, proc)
        return "killed"

    def _limit_text(self, limit: int, guest: int | None, metric: str) -> str:
        configured = f"emulator.max_host_memory_gb = {self.limit_bytes / _GB:g}"
        if limit == self.limit_bytes or not guest:
            return f"limit {limit / _GB:.0f} GB, {configured}"
        times = "" if metric == "footprint" else "2 x "
        return (
            f"limit {limit / _GB:.0f} GB = {times}{guest / _GB:g} GB guest RAM "
            f"+ {GUEST_RAM_MARGIN_GB:g} GB, above {configured}"
        )

    def _shutdown(self, serial: str | None, proc: Any) -> None:
        try:
            subprocess.run(
                [self._adb_path_getter(), "-s", str(serial), "emu", "kill"],
                capture_output=True,
                timeout=10,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            logger.debug("adb emu kill failed", exc_info=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not proc.is_running():
                return
            time.sleep(0.5)
        try:
            proc.kill()
        except Exception:
            logger.debug("killing qemu failed", exc_info=True)


_guard: EmulatorMemoryGuard | None = None
_guard_lock = threading.Lock()


def start_memory_guard(config: Any) -> EmulatorMemoryGuard | None:
    """Start (once per process) the guard configured by ``config.emulator``."""
    global _guard
    emulator_cfg = getattr(config, "emulator", None)
    limit = float(getattr(emulator_cfg, "max_host_memory_gb", 10.0) or 0)
    action = str(getattr(emulator_cfg, "memory_guard_action", "kill") or "kill")
    with _guard_lock:
        if _guard is not None:
            _guard.limit_bytes = int(limit * _GB)
            _guard.action = action
            return _guard
        from sandroid.core.adb import Adb

        def _serial() -> str | None:
            try:
                return Adb.get_target_device()
            except Exception:
                return None

        _guard = EmulatorMemoryGuard(
            _serial,
            limit_gb=limit,
            action=action,
            adb_path_getter=lambda: Adb.ADB_PATH or "adb",
        )
        _guard.start()
        return _guard
