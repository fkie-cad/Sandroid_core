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
  behind the active ADB serial and stops the emulator once its resident memory
  exceeds ``emulator.max_host_memory_gb``. It also warns once when the
  emulator was started *without* ``-feature -Vulkan`` (e.g. by hand).

macOS has no cgroups, so polling is the only portable way to cap the process.
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Flags Sandroid passes to every emulator it launches.
SAFE_EMULATOR_ARGS: list[str] = ["-feature", "-Vulkan"]

_DEFAULT_CONSOLE_PORT = 5554
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


def console_port(cmdline: list[str]) -> int:
    """Console port of an emulator command line (``-port N``, default 5554)."""
    for i, arg in enumerate(cmdline[:-1]):
        if arg in ("-port", "-ports"):
            try:
                return int(cmdline[i + 1].split(",")[0])
            except ValueError:
                break
    return _DEFAULT_CONSOLE_PORT


def find_emulator_process(serial: str | None) -> Any | None:
    """Return the ``psutil.Process`` of the qemu behind ``emulator-<port>``.

    Returns ``None`` for non-emulator serials, when psutil is unavailable or
    no matching process is found.
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
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = proc.info.get("name") or ""
            cmdline = proc.info.get("cmdline") or []
        except Exception:
            continue
        if not name.startswith("qemu-system") or not cmdline:
            continue
        if console_port(cmdline) == port:
            return proc
    return None


class EmulatorMemoryGuard:
    """Watch the active emulator's host memory and stop it above a limit."""

    def __init__(
        self,
        serial_getter: Callable[[], str | None],
        *,
        limit_gb: float = 10.0,
        action: str = "kill",
        interval: float = 5.0,
        adb_path_getter: Callable[[], str] | None = None,
        notify: Callable[[str, int], None] | None = None,
    ) -> None:
        self._serial_getter = serial_getter
        self.limit_bytes = int(limit_gb * _GB)
        self.action = action
        self.interval = interval
        self._adb_path_getter = adb_path_getter or (lambda: "adb")
        self._notify = notify or (lambda msg, level: logger.log(level, msg))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._warned_pids: set[int] = set()
        self._near_limit_pids: set[int] = set()

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
            rss = proc.memory_info().rss
        except Exception:
            return None

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
        if rss >= 0.75 * self.limit_bytes and proc.pid not in self._near_limit_pids:
            self._near_limit_pids.add(proc.pid)
            self._notify(
                f"Emulator {serial} uses {rss / _GB:.1f} GB host memory "
                f"(limit {self.limit_bytes / _GB:.0f} GB, emulator.max_host_memory_gb).",
                logging.WARNING,
            )
        if rss < self.limit_bytes:
            return None

        msg = (
            f"Emulator {serial} uses {rss / _GB:.1f} GB host memory, above the "
            f"{self.limit_bytes / _GB:.0f} GB limit (emulator.max_host_memory_gb)."
        )
        if self.action != "kill":
            self._notify(msg, logging.ERROR)
            return "over-limit"
        self._notify(msg + " Shutting the emulator down to protect the host.", logging.ERROR)
        self._shutdown(serial, proc)
        return "killed"

    def _shutdown(self, serial: str | None, proc: Any) -> None:
        try:
            subprocess.run(
                [self._adb_path_getter(), "-s", str(serial), "emu", "kill"],
                capture_output=True,
                timeout=10,
                check=False,
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
