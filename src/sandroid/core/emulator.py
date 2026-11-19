"""The emulator / AVD backend: discovery, catalogue, launch and lifecycle.

Every place in Sandroid that finds the SDK, lists AVDs, starts, stops or
restarts an emulator goes through this module:

* **Discovery** (config-aware): :func:`sdk_root`, :func:`emulator_binary`,
  :func:`adb_binary`, :func:`avd_home`, :func:`avd_dir`, :func:`emulator_env`.
* **Catalogue**: :func:`list_avds`, :func:`avd_info`, :func:`avd_snapshots`,
  :func:`rename_avd`, :func:`avd_name_of`.
* **Launch** (one path): :class:`AvdLaunchOptions`,
  :func:`build_emulator_command`, :func:`free_console_port`,
  :func:`launch_avd` -> :class:`EmulatorLaunch` (kept in a registry, see
  :func:`get_launch` / :func:`booting_serials`). Every launch passes an
  explicit ``-port`` so the adb serial (``emulator-<port>``) is known before
  the emulator even starts.
* **Lifecycle**: :func:`boot_state`, :func:`wait_until_ready`,
  :func:`stop_emulator` (per-serial ``emu kill``, never ``pkill``),
  :func:`restart_emulator` (same AVD, same port), :func:`ensure_avd_running`.
* **Remembered launch options** (``devices.json`` in the user config dir):
  :func:`load_launch_prefs`, :func:`remembered_options`,
  :func:`remember_launch`.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from sandroid.core.exceptions import EmulatorLaunchError

if TYPE_CHECKING:
    from collections.abc import Callable

logger = getLogger(__name__)

# Keywords indicating emulator startup failure in stderr output
EMULATOR_ERROR_KEYWORDS = ("PANIC", "ERROR", "WARNING", "Fatal")
_STARTUP_GRACE_PERIOD = 3


#: Where detached emulators write their stdout/stderr (one file per AVD).
EMULATOR_LOG_DIR = Path("~/.cache/sandroid/emulator").expanduser()

#: Console ports Sandroid launches on. adb auto-discovers emulators on the
#: console/adb port pairs 5554/5555 ... 5584/5585 only, so a launch outside
#: this range would never show up in ``adb devices``.
CONSOLE_PORT_MIN = 5554
CONSOLE_PORT_MAX = 5584

#: Seconds :func:`wait_until_ready` waits by default.
DEFAULT_BOOT_TIMEOUT = 240.0

#: A launch older than this is no longer reported as booting even if nobody
#: confirmed it ready, so auto-selection is never blocked forever by a launch
#: whose waiter died.
BOOTING_MAX_AGE = 600.0

#: Timeout of every adb call made from this module.
_ADB_TIMEOUT = 10.0

BootMode = Literal["normal", "cold", "snapshot", "wipe"]
BootState = Literal["absent", "offline", "booting", "ready"]


def _adb(adb: Any) -> Any:
    """Return *adb*, or the global :class:`~sandroid.core.adb.Adb` class."""
    if adb is not None:
        return adb
    from sandroid.core.adb import Adb

    return Adb


def _config_emulator() -> Any:
    """The ``emulator`` config section, or ``None`` when unavailable."""
    try:
        from sandroid.config import get_config

        return get_config().emulator
    except Exception:
        return None


def _config_path(key: str) -> Path | None:
    value = getattr(_config_emulator(), key, None)
    return Path(value).expanduser() if value else None


def _adb_call(adb: Any, command: str, serial: str) -> str:
    """Return stdout of one adb command with a short timeout ("" on any failure).

    Falls back to a call without ``timeout`` for adb doubles that lack it.
    """
    try:
        try:
            out, _err = adb.send_adb_command(
                command, serial=serial, timeout=_ADB_TIMEOUT
            )
        except TypeError:
            out, _err = adb.send_adb_command(command, serial=serial)
    except Exception:
        return ""
    return out or ""


# ---------------------------------------------------------------------------
# Spawning
# ---------------------------------------------------------------------------


def emulator_log_path(avd_name: str) -> Path:
    """Return the log file a detached emulator for *avd_name* writes to."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", avd_name or "") or "emulator"
    return EMULATOR_LOG_DIR / f"{safe}.log"


def spawn_emulator(
    command: list[str], avd_name: str, env: dict[str, str] | None = None
) -> tuple[subprocess.Popen, Path | None]:
    """Start a detached emulator whose output goes to a log file.

    The emulator outlives the call (``start_new_session=True``), so its
    output must never go to a pipe nobody drains: once the ~64 KiB pipe
    buffer fills the emulator blocks on its next log write. stdout and
    stderr are written to :func:`emulator_log_path` instead (truncated per
    launch), or discarded if the log file cannot be created.

    Returns:
        ``(process, log_path)``; ``log_path`` is ``None`` when output is
        discarded.

    Raises:
        OSError / subprocess.SubprocessError: The process could not start.
    """
    log_path: Path | None = emulator_log_path(avd_name)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        sink = open(log_path, "wb")
    except OSError:
        log_path, sink = None, None
    try:
        process = subprocess.Popen(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sink if sink is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if sink is not None else subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        if sink is not None:
            sink.close()  # the child keeps its own descriptor
    return process, log_path


def check_emulator_startup(
    process: subprocess.Popen, log_path: str | Path | None = None
) -> tuple[bool, str]:
    """Check whether an emulator process survived initial startup.

    Waits briefly, then checks if the process is still running.
    If it exited, reads its output and filters for error keywords.

    Args:
        process: The emulator Popen process.
        log_path: Log file the process writes to (see :func:`spawn_emulator`).
            Without it, ``process.stderr`` is read if it is a pipe.

    Returns:
        Tuple of (success, error_message). On success error_message is empty.
    """
    time.sleep(_STARTUP_GRACE_PERIOD)
    exit_code = process.poll()
    if exit_code is None:
        return True, ""

    stderr_output = ""
    try:
        if log_path is not None:
            stderr_output = Path(log_path).read_bytes().decode(errors="replace")
        elif process.stderr is not None:
            stderr_output = process.stderr.read().decode(errors="replace")
    except OSError:
        pass
    error_lines = [
        line
        for line in stderr_output.strip().splitlines()
        if any(kw in line for kw in EMULATOR_ERROR_KEYWORDS)
    ]
    error_msg = "; ".join(error_lines) if error_lines else f"exit code {exit_code}"
    return False, error_msg


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _exe(name: str) -> str:
    return f"{name}.exe" if platform.system().lower().startswith("win") else name


def looks_like_sdk(path: str | Path) -> bool:
    """Check if the given path looks like a valid Android SDK root."""
    path = Path(path)
    if not path.is_dir():
        return False
    return any((path / c).is_dir() for c in ("platform-tools", "cmdline-tools"))


def _default_sdk_candidates() -> list[Path]:
    system = platform.system().lower()
    if system == "darwin":
        return [
            Path("~/Library/Android/sdk").expanduser(),
            Path("~/Library/Android").expanduser(),
        ]
    if system == "linux":
        return [
            Path("~/Android/Sdk").expanduser(),
            Path("~/Android/sdk").expanduser(),
            Path("~/android-sdk").expanduser(),
        ]
    if system.startswith("win"):
        return [
            Path(os.environ[var]) / "Android" / "Sdk"
            for var in ("LOCALAPPDATA", "APPDATA")
            if os.environ.get(var)
        ]
    return []


def sdk_root() -> Path | None:
    """The Android SDK root.

    Order: config ``emulator.sdk_path`` -> ``ANDROID_SDK_ROOT`` /
    ``ANDROID_HOME`` -> ``sdkmanager`` on PATH -> per-OS default locations.
    """
    configured = _config_path("sdk_path")
    if configured and configured.is_dir():
        return configured
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(var)
        if value and looks_like_sdk(value):
            return Path(value)
    manager = shutil.which("sdkmanager") or shutil.which("sdkmanager.bat")
    if manager:
        candidate = Path(manager).parent.parent.parent
        if looks_like_sdk(candidate):
            return candidate
    for candidate in _default_sdk_candidates():
        for path in (candidate, candidate / "sdk"):
            if looks_like_sdk(path):
                return path
    return None


def _is_executable(path: Path | None) -> bool:
    return path is not None and path.is_file() and os.access(path, os.X_OK)


def emulator_binary() -> Path | None:
    """The emulator executable.

    Order: config ``emulator.android_emulator_path`` ->
    ``<sdk>/emulator/emulator`` -> ``emulator`` on PATH (last: an
    ``emulator`` on PATH is often the obsolete ``tools/emulator`` wrapper).
    """
    configured = _config_path("android_emulator_path")
    if _is_executable(configured):
        return configured
    root = sdk_root()
    if root is not None:
        candidate = root / "emulator" / _exe("emulator")
        if _is_executable(candidate):
            return candidate
    found = shutil.which("emulator")
    return Path(found) if found else None


def adb_binary() -> Path | None:
    """The adb executable.

    Order: config ``emulator.adb_path`` -> ``adb`` on PATH ->
    ``<sdk>/platform-tools/adb``. PATH wins over the SDK so Sandroid talks
    to the same adb (server version) the user runs by hand.
    """
    configured = _config_path("adb_path")
    if _is_executable(configured):
        return configured
    found = shutil.which("adb")
    if found:
        return Path(found)
    root = sdk_root()
    if root is not None:
        candidate = root / "platform-tools" / _exe("adb")
        if _is_executable(candidate):
            return candidate
    return None


def avd_home() -> Path | None:
    """The directory holding ``<name>.ini`` / ``<name>.avd`` (if it exists).

    Order: config ``emulator.avd_home`` -> ``ANDROID_AVD_HOME`` ->
    ``ANDROID_EMULATOR_HOME/avd`` -> ``ANDROID_USER_HOME/avd`` ->
    ``~/.android/avd``; the first existing directory wins.
    """
    candidates: list[Path] = []
    configured = _config_path("avd_home")
    if configured:
        candidates.append(configured)
    if os.environ.get("ANDROID_AVD_HOME"):
        candidates.append(Path(os.environ["ANDROID_AVD_HOME"]).expanduser())
    for var in ("ANDROID_EMULATOR_HOME", "ANDROID_USER_HOME"):
        if os.environ.get(var):
            candidates.append(Path(os.environ[var]).expanduser() / "avd")
    candidates.append(Path("~/.android/avd").expanduser())
    return next((c for c in candidates if c.is_dir()), None)


def _read_ini(path: Path) -> dict[str, str]:
    """``key=value`` lines of an AVD ini file ({} when unreadable)."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def avd_dir(name: str) -> Path | None:
    """Directory of AVD *name*, or ``None`` if it cannot be found.

    Honours the ``path=`` (absolute) and then ``path.rel=`` (relative to the
    Android user home, i.e. the parent of the AVD home) entries of
    ``<name>.ini`` before falling back to ``<avd home>/<name>.avd``.
    """
    home = avd_home()
    if home is None:
        return None
    ini = _read_ini(home / f"{name}.ini")
    if ini.get("path") and Path(ini["path"]).is_dir():
        return Path(ini["path"])
    rel = ini.get("path.rel")
    if rel:
        for base in (home.parent, home):
            if (base / rel).is_dir():
                return base / rel
    default = home / f"{name}.avd"
    return default if default.is_dir() else None


def emulator_env() -> dict[str, str]:
    """Environment for emulator processes: the SDK root and AVD home the
    rest of Sandroid resolved, so the emulator sees the same AVDs.
    """
    env = os.environ.copy()
    root = sdk_root()
    if root is not None:
        env["ANDROID_SDK_ROOT"] = str(root)
        env["ANDROID_HOME"] = str(root)
    home = avd_home()
    if home is not None:
        env["ANDROID_AVD_HOME"] = str(home)
    return env


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

#: API level -> Android version (display only).
API_TO_ANDROID_VERSION = {
    36: "16",
    35: "15",
    34: "14",
    33: "13",
    32: "12L",
    31: "12",
    30: "11",
    29: "10",
    28: "9 (Pie)",
    27: "8.1 (Oreo)",
    26: "8.0 (Oreo)",
    25: "7.1 (Nougat)",
    24: "7.0 (Nougat)",
    23: "6.0 (Marshmallow)",
    22: "5.1 (Lollipop)",
    21: "5.0 (Lollipop)",
}


def list_avds(timeout: float = 15.0, *, binary: str | Path | None = None) -> list[str]:
    """Names of the installed AVDs (``emulator -list-avds``).

    Args:
        timeout: Seconds before giving up.
        binary: Emulator executable (default: :func:`emulator_binary`).

    Returns:
        AVD names; ``[]`` when the emulator is missing, fails or times out.
    """
    binary = binary or emulator_binary()
    if not binary:
        return []
    try:
        result = subprocess.run(
            [str(binary), "-list-avds"],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            stdin=subprocess.DEVNULL,
            env=emulator_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"'emulator -list-avds' timed out after {timeout:g}s")
        return []
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Could not list AVDs: {e}")
        return []
    if result.returncode != 0:
        return []
    names = []
    for line in (result.stdout or "").splitlines():
        name = line.strip()
        # Newer emulators print "INFO    | ..." diagnostics on stdout.
        if not name or "|" in name or name.startswith(("INFO", "WARNING", "ERROR")):
            continue
        names.append(name)
    return names


@dataclass(frozen=True)
class AvdInfo:
    """Static facts about an installed AVD (read from its ini files).

    Attributes:
        name: AVD name.
        api_level: Android API level, ``None`` if unknown.
        android_version: Display version ("14"), "Unknown" if unknown.
        tag: System image tag (``google_apis``, ``google_apis_playstore``...).
        abi: Image ABI (``arm64-v8a``, ``x86_64``...).
        device_name: Hardware profile (``hw.device.name``).
        path: The AVD directory, ``None`` if missing.
        snapshot_count: Number of saved snapshots.
    """

    name: str
    api_level: int | None = None
    android_version: str = "Unknown"
    tag: str = ""
    abi: str = ""
    device_name: str = ""
    path: Path | None = None
    snapshot_count: int = 0


def avd_info(name: str) -> AvdInfo:
    """Read :class:`AvdInfo` for AVD *name* from ``<name>.ini`` + config.ini."""
    home = avd_home()
    ini = _read_ini(home / f"{name}.ini") if home else {}
    directory = avd_dir(name)
    config = _read_ini(directory / "config.ini") if directory else {}

    api: int | None = None
    sysdir = config.get("image.sysdir.1", "")
    sys_parts = [p for p in re.split(r"[\\/]", sysdir) if p]
    match = re.search(r"android-(\d+)", sysdir)
    if match:
        api = int(match.group(1))
    else:
        match = re.fullmatch(r"android-(\d+)", ini.get("target", ""))
        if match:
            api = int(match.group(1))

    tag = config.get("tag.id", "")
    if not tag and len(sys_parts) >= 2 and not sys_parts[-2].startswith("android-"):
        tag = sys_parts[-2]
    abi = config.get("abi.type", "") or (sys_parts[-1] if sys_parts else "")

    return AvdInfo(
        name=name,
        api_level=api,
        android_version=(
            API_TO_ANDROID_VERSION.get(api, f"API {api}") if api else "Unknown"
        ),
        tag=tag,
        abi=abi,
        device_name=config.get("hw.device.name", ""),
        path=directory,
        snapshot_count=len(avd_snapshots(name)) if directory else 0,
    )


@dataclass
class AvdSnapshot:
    """A snapshot saved in an AVD directory.

    Attributes:
        name: Snapshot folder name (e.g. ``default_boot``).
        path: Full path to the snapshot directory.
        size_mb: Approximate size (``ram.bin``).
        modified_date: Last modified date ("YYYY-MM-DD HH:MM").
        mtime: Raw modification timestamp for sorting (0.0 if unknown).
    """

    name: str
    path: Path
    size_mb: float
    modified_date: str
    mtime: float = 0.0


def avd_snapshots(name: str) -> list[AvdSnapshot]:
    """Snapshots of AVD *name* read from disk (works while it is stopped).

    Returns:
        ``default_boot`` first, then newest first.
    """
    directory = avd_dir(name)
    if directory is None or not (directory / "snapshots").is_dir():
        return []
    snapshots: list[AvdSnapshot] = []
    for path in (directory / "snapshots").iterdir():
        if not path.is_dir():
            continue
        if not ((path / "snapshot.pb").exists() or (path / "hardware.ini").exists()):
            continue
        size_mb = 0.0
        try:
            size_mb = (path / "ram.bin").stat().st_size / (1024 * 1024)
        except OSError:
            pass
        mtime, modified = 0.0, "Unknown"
        try:
            mtime = path.stat().st_mtime
            modified = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            pass
        snapshots.append(AvdSnapshot(path.name, path, size_mb, modified, mtime))
    snapshots.sort(key=lambda s: (s.name != "default_boot", -s.mtime))
    return snapshots


_AVD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


#: Lock files that exist whether or not the AVD runs (the emulator only
#: ``flock``s it), so their presence says nothing.
_PERSISTENT_LOCKS = frozenset({"multiinstance.lock"})


def _stale_lock(path: Path) -> bool:
    """True if lock *path* names a process that no longer exists.

    The emulator writes its PID into ``hardware-qemu.ini.lock`` (a file on
    POSIX, a directory with a ``pid`` file on Windows). Anything unreadable
    or not a PID counts as a live lock. Windows is never checked:
    ``os.kill(pid, 0)`` would terminate the process there.
    """
    if os.name == "nt":
        return False
    target = path / "pid" if path.is_dir() else path
    try:
        text = target.read_text(encoding="utf-8", errors="ignore").strip()[:32]
    except OSError:
        return False
    if not text.isdigit() or int(text) <= 0:
        return False
    try:
        os.kill(int(text), 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def avd_lock_files(name: str) -> list[Path]:
    """Lock files a running emulator holds in AVD *name*'s directory.

    Every ``*.lock`` entry (file or directory) counts except
    ``multiinstance.lock``, which stays behind after a clean exit, and locks
    naming a dead PID (left by a crash). Non-empty means some emulator --
    possibly another session's, or one adb does not list -- runs this AVD.
    """
    directory = avd_dir(name)
    if directory is None:
        return []
    try:
        entries = list(directory.glob("*.lock"))
    except OSError:
        return []
    return sorted(
        path
        for path in entries
        if path.name not in _PERSISTENT_LOCKS and not _stale_lock(path)
    )


def rename_avd(old_name: str, new_name: str) -> tuple[bool, str]:
    """Rename a stopped AVD.

    Renames ``<old>.ini`` and, when the AVD lives in the AVD home as
    ``<old>.avd``, that directory too (rewriting ``path=``/``path.rel=``).
    An AVD redirected elsewhere keeps its directory. Remembered launch
    options move to the new name. Refused while the AVD runs (our launch is
    alive, or its directory holds emulator lock files).

    Returns:
        ``(success, message)``.
    """
    with _LAUNCH_LOCK:
        ours = [x for x in _LAUNCHES.values() if x.avd == old_name and x.alive]
    if ours:
        return False, f"AVD '{old_name}' is running as {ours[0].serial}; stop it first"
    locks = avd_lock_files(old_name)
    if locks:
        names = ", ".join(path.name for path in locks)
        return (
            False,
            f"AVD '{old_name}' is in use by an emulator ({names}); stop it first",
        )
    home = avd_home()
    if home is None:
        return False, "AVD home directory not found"
    old_ini, new_ini = home / f"{old_name}.ini", home / f"{new_name}.ini"
    if not old_ini.exists():
        return False, f"AVD '{old_name}' not found (missing .ini file)"
    directory = avd_dir(old_name)
    if directory is None:
        return False, f"AVD '{old_name}' not found (missing .avd directory)"
    new_dir = home / f"{new_name}.avd"
    if new_ini.exists() or new_dir.exists():
        return False, f"AVD '{new_name}' already exists"
    if not _AVD_NAME_RE.match(new_name or ""):
        return (
            False,
            "Invalid AVD name. Use letters, numbers, dots, underscores and "
            "hyphens. Must start with a letter.",
        )
    try:
        content = old_ini.read_text(encoding="utf-8")
        if directory == home / f"{old_name}.avd":
            directory.rename(new_dir)
            lines = [
                _retarget_ini_line(line, old_name, new_name, new_dir)
                for line in content.splitlines()
            ]
            content = "\n".join(lines) + "\n"
        new_ini.write_text(content, encoding="utf-8")
        old_ini.unlink()
    except PermissionError:
        return False, "Permission denied. Make sure the AVD is not running."
    except OSError as e:
        return False, f"Error renaming AVD: {e}"
    _move_prefs(old_name, new_name)
    return True, f"Successfully renamed '{old_name}' to '{new_name}'"


def _retarget_ini_line(line: str, old: str, new: str, new_dir: Path) -> str:
    key = line.partition("=")[0].strip()
    if key == "path":
        return f"path={new_dir}"
    if key == "path.rel":
        return line.replace(f"{old}.avd", f"{new}.avd")
    return line


def avd_name_of(serial: str, adb: Any = None) -> str | None:
    """AVD name of the running emulator *serial*.

    Our own (live) launch record first, then the ``ro.boot.qemu.avd_name`` /
    ``ro.kernel.qemu.avd_name`` property (one adb round-trip), then the
    console's ``emu avd name``. Every adb call has a short timeout.
    """
    launch = get_launch(serial)
    if launch is not None and launch.alive:
        return launch.avd
    adb = _adb(adb)
    for prop in ("ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name"):
        name = _adb_call(adb, f"shell getprop {prop}", serial).strip()
        if name:
            return name
    for line in _adb_call(adb, "emu avd name", serial).splitlines():
        line = line.strip()
        if line and line != "OK" and not line.startswith("KO"):
            return line
    return None


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AvdLaunchOptions:
    """How to launch an AVD.

    Attributes:
        headless: No window (``-no-window -no-boot-anim``, software GLES).
        boot: ``normal`` (quick-boot snapshot), ``cold`` (no snapshot load),
            ``snapshot`` (load *snapshot*), ``wipe`` (factory reset).
        snapshot: Snapshot name for ``boot="snapshot"``.
        extra_args: Further emulator arguments.
    """

    headless: bool = False
    boot: BootMode = "normal"
    snapshot: str | None = None
    extra_args: tuple[str, ...] = ()


def build_emulator_command(
    binary: str | Path, avd: str, port: int, opts: AvdLaunchOptions
) -> list[str]:
    """The emulator argv of one launch (pure)."""
    from sandroid.core.emulator_guard import emulator_launch_args

    command = [str(binary), "-avd", avd, "-port", str(port)]
    # Guest Vulkan off in every mode: SwiftShader Vulkan leaks host memory on
    # every snapshot load (see core/emulator_guard.py).
    command += emulator_launch_args(headless=opts.headless)
    if opts.headless:
        command += ["-no-window", "-no-boot-anim"]
    if opts.boot == "cold":
        command.append("-no-snapshot-load")
    elif opts.boot == "wipe":
        command.append("-wipe-data")
    elif opts.boot == "snapshot" and opts.snapshot:
        command += ["-snapshot", opts.snapshot]
    command += list(opts.extra_args)
    return command


def _port_bindable(port: int) -> bool:
    """True if nothing listens on ``127.0.0.1:<port>``.

    ``SO_REUSEADDR`` (POSIX only) lets the bind ignore sockets in TIME_WAIT:
    right after ``emu kill`` the old console/adb connections linger there for
    30-60 s although the port is free for a new emulator. On Windows the
    option would let us bind a port that is really in use, so it stays off.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _ports_free(port: int) -> bool:
    """True if the console port and its adb port (+1) are both bindable."""
    return _port_bindable(port) and _port_bindable(port + 1)


def free_console_port(taken: set[int]) -> int:
    """First free even console port in 5554-5584.

    Args:
        taken: Console ports to skip (listed / launched emulators).

    Raises:
        EmulatorLaunchError: All 16 ports are in use.
    """
    for port in range(CONSOLE_PORT_MIN, CONSOLE_PORT_MAX + 1, 2):
        if port not in taken and _ports_free(port):
            return port
    raise EmulatorLaunchError(
        f"No free emulator console port in {CONSOLE_PORT_MIN}-{CONSOLE_PORT_MAX} "
        "(adb only discovers emulators there); stop an emulator first."
    )


def serial_port(serial: str) -> int | None:
    """Console port of an ``emulator-<port>`` serial (``None`` otherwise)."""
    match = re.fullmatch(r"emulator-(\d+)", serial or "")
    return int(match.group(1)) if match else None


@dataclass
class EmulatorLaunch:
    """An emulator Sandroid started (kept in the launch registry).

    Attributes:
        avd: AVD name.
        serial: adb serial (``emulator-<port>``).
        port: Console port.
        options: The options it was launched with.
        process: The emulator process.
        log_path: Its log file (``None`` when output is discarded).
        started_at: ``time.monotonic()`` of the launch.
        ready: True once its boot completed (see :func:`boot_state`).
        cancel: Set when this launch was stopped or restarted: whoever waits
            for its boot gives up quietly (a restart's new launch on the same
            port has its own event).
    """

    avd: str
    serial: str
    port: int
    options: AvdLaunchOptions
    process: Any
    log_path: Path | None
    started_at: float
    ready: bool = False
    cancel: threading.Event = field(
        default_factory=threading.Event, compare=False, repr=False
    )

    @property
    def alive(self) -> bool:
        """True while the emulator process runs."""
        try:
            return self.process is not None and self.process.poll() is None
        except Exception:
            return False


_LAUNCHES: dict[str, EmulatorLaunch] = {}
_LAUNCH_LOCK = threading.RLock()
#: Console ports chosen by a launch whose process is not registered yet
#: (guarded by ``_LAUNCH_LOCK``): two near-simultaneous launches never pick
#: the same port.
_RESERVED_PORTS: set[int] = set()
#: AVDs a :func:`launch_avd` call is starting right now (``_LAUNCH_LOCK``).
_STARTING_AVDS: set[str] = set()


def get_launch(serial: str) -> EmulatorLaunch | None:
    """The launch record of *serial*, if Sandroid started it."""
    with _LAUNCH_LOCK:
        return _LAUNCHES.get(serial)


def launches() -> list[EmulatorLaunch]:
    """All launch records (live, booting, ready and crashed ones)."""
    with _LAUNCH_LOCK:
        return list(_LAUNCHES.values())


def booting_serials() -> list[str]:
    """Serials of our launches still booting (alive, not yet ready)."""
    now = time.monotonic()
    with _LAUNCH_LOCK:
        return [
            serial
            for serial, launch in _LAUNCHES.items()
            if not launch.ready
            and launch.alive
            and now - launch.started_at < BOOTING_MAX_AGE
        ]


def _forget_launch(serial: str) -> None:
    with _LAUNCH_LOCK:
        _LAUNCHES.pop(serial, None)


def mark_ready(serial: str) -> None:
    """Record that our launch of *serial* finished booting.

    Called by :func:`boot_state` and by the Devices screen once its probe
    sees ``sys.boot_completed=1``, so a launch never stays "booting" (and
    excluded from auto-selection) only because its boot waiter gave up.
    """
    with _LAUNCH_LOCK:
        launch = _LAUNCHES.get(serial)
        if launch is not None:
            launch.ready = True


def _list_entries(adb: Any) -> list | None:
    """``adb devices -l`` entries, or ``None`` when adb itself failed."""
    from sandroid.core.device import parse_adb_devices

    out = _adb_call(adb, "devices -l", "")
    if "list of devices" not in out.lower():
        return None
    return parse_adb_devices(out)


def _listed_ports(adb: Any) -> set[int]:
    """Console ports of the emulators ``adb devices`` lists."""
    return {
        port
        for entry in _list_entries(adb) or []
        if (port := serial_port(entry.serial)) is not None
    }


def _our_ports() -> set[int]:
    """Ports of our live launches and reserved ports (hold ``_LAUNCH_LOCK``)."""
    return {
        launch.port for launch in _LAUNCHES.values() if launch.alive
    } | _RESERVED_PORTS


def _reserve_port(taken: set[int], port: int | None) -> int:
    """Choose (or claim *port*) and reserve it, under the registry lock.

    Raises:
        EmulatorLaunchError: *port* is already reserved / used by our live
            launch, or no port is free.
    """
    with _LAUNCH_LOCK:
        ours = _our_ports()
        if port is not None:
            if port in ours:
                raise EmulatorLaunchError(
                    f"Console port {port} is already used by another launch"
                )
            chosen = port
        else:
            chosen = free_console_port(taken | ours)
        _RESERVED_PORTS.add(chosen)
        return chosen


def _release_port(port: int) -> None:
    with _LAUNCH_LOCK:
        _RESERVED_PORTS.discard(port)


def launch_avd(
    avd: str,
    options: AvdLaunchOptions | None = None,
    *,
    port: int | None = None,
    adb: Any = None,
) -> EmulatorLaunch:
    """Start AVD *avd* on an explicit console port (blocks ~3 s).

    The emulator is detached and logs to :func:`emulator_log_path`. Returns
    once the process survived its first seconds; the boot continues in the
    background (see :func:`wait_until_ready`). If the automatically chosen
    port was grabbed in the meantime, retries once on the next free port.

    Args:
        avd: AVD name.
        options: Launch options (default: :class:`AvdLaunchOptions`).
        port: Console port; ``None`` picks :func:`free_console_port`.
        adb: adb interface (default: the global ``Adb``).

    Returns:
        The registered :class:`EmulatorLaunch` (``serial`` is
        ``emulator-<port>``).

    Raises:
        EmulatorLaunchError: No emulator binary / free port, our launch of
            *avd* is still running, the process could not start, or it
            crashed during startup (the message names the log file).
    """
    opts = options or AvdLaunchOptions()
    if not avd:
        raise EmulatorLaunchError("No AVD name given")
    binary = emulator_binary()
    if binary is None:
        raise EmulatorLaunchError(
            "Emulator executable not found (set emulator.android_emulator_path "
            "or ANDROID_SDK_ROOT)"
        )
    with _LAUNCH_LOCK:
        running = next(
            (x for x in _LAUNCHES.values() if x.avd == avd and x.alive), None
        )
        if running is not None:
            raise EmulatorLaunchError(
                f"AVD '{avd}' is already running as {running.serial}"
            )
        if avd in _STARTING_AVDS:
            raise EmulatorLaunchError(f"AVD '{avd}' is already being started")
        _STARTING_AVDS.add(avd)
    try:
        return _launch_reserved(avd, opts, binary, _adb(adb), port)
    finally:
        with _LAUNCH_LOCK:
            _STARTING_AVDS.discard(avd)


def _launch_reserved(
    avd: str, opts: AvdLaunchOptions, binary: Path, adb: Any, port: int | None
) -> EmulatorLaunch:
    """:func:`launch_avd` once *avd* is marked as starting."""
    explicit = port is not None
    taken = _listed_ports(adb)
    chosen = _reserve_port(taken, port)
    try:
        for attempt in (1, 2):
            launch = _spawn_launch(binary, avd, chosen, opts)
            ok, error = check_emulator_startup(launch.process, launch.log_path)
            if ok:
                logger.info(
                    f"Emulator '{avd}' is booting as {launch.serial} "
                    f"(PID {getattr(launch.process, 'pid', '?')}, "
                    f"log {launch.log_path})"
                )
                return launch
            _forget_launch(launch.serial)
            if attempt == 1 and not explicit and not _ports_free(chosen):
                logger.warning(
                    f"Console port {chosen} was taken during startup; retrying"
                )
                taken.add(chosen)
                _release_port(chosen)
                chosen = _reserve_port(taken, None)
                continue
            log_path = launch.log_path
            raise EmulatorLaunchError(
                f"Emulator '{avd}' crashed during startup: {error}"
                + (f" (log: {log_path})" if log_path else ""),
                log_path=log_path,
            )
        raise AssertionError("unreachable")  # pragma: no cover
    finally:
        _release_port(chosen)


def _spawn_launch(
    binary: Path, avd: str, port: int, opts: AvdLaunchOptions
) -> EmulatorLaunch:
    """Start the emulator process and register its launch record."""
    command = build_emulator_command(binary, avd, port, opts)
    logger.info(f"Starting emulator '{avd}': {' '.join(command)}")
    try:
        process, log_path = spawn_emulator(command, avd, emulator_env())
    except (OSError, subprocess.SubprocessError) as e:
        raise EmulatorLaunchError(f"Could not start emulator '{avd}': {e}") from e
    launch = EmulatorLaunch(
        avd=avd,
        serial=f"emulator-{port}",
        port=port,
        options=opts,
        process=process,
        log_path=log_path,
        started_at=time.monotonic(),
    )
    with _LAUNCH_LOCK:
        _LAUNCHES[launch.serial] = launch
    return launch


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def boot_state(serial: str, adb: Any = None) -> BootState:
    """Where emulator/device *serial* is in its boot.

    Returns:
        ``absent`` (not listed by adb), ``offline`` (listed but not in state
        ``device``, or adb failed), ``booting`` (online, not yet ready) or
        ``ready`` (``sys.boot_completed=1`` AND ``pm path android`` works).
    """
    adb = _adb(adb)
    entries = _list_entries(adb)
    if entries is None:
        return "offline"
    entry = next((e for e in entries if e.serial == serial), None)
    if entry is None:
        return "absent"
    if entry.state != "device":
        return "offline"
    if _adb_call(adb, "shell getprop sys.boot_completed", serial).strip() != "1":
        return "booting"
    if "package:" not in _adb_call(adb, "shell pm path android", serial):
        return "booting"
    mark_ready(serial)
    return "ready"


def _cancelled(cancel: Any) -> bool:
    if cancel is None:
        return False
    is_set = getattr(cancel, "is_set", None)
    try:
        return bool(is_set() if callable(is_set) else cancel())
    except Exception:
        return False


def wait_until_ready(
    serial: str,
    timeout: float = DEFAULT_BOOT_TIMEOUT,
    on_progress: Callable[[BootState, float], None] | None = None,
    cancel: Any = None,
    *,
    adb: Any = None,
    interval: float = 2.0,
) -> bool:
    """Poll :func:`boot_state` until *serial* is ready.

    Args:
        serial: adb serial.
        timeout: Seconds to wait.
        on_progress: Called with ``(state, elapsed_seconds)`` after each poll.
        cancel: ``threading.Event`` (or a callable returning True) that
            aborts the wait.
        adb: adb interface (default: the global ``Adb``).
        interval: Seconds between polls.

    Returns:
        True once ready; False on timeout, cancel, or when our launch of
        *serial* died.
    """
    adb = _adb(adb)
    start = time.monotonic()
    while True:
        if _cancelled(cancel):
            return False
        state = boot_state(serial, adb)
        elapsed = time.monotonic() - start
        if on_progress is not None:
            try:
                on_progress(state, elapsed)
            except Exception:
                logger.debug("boot progress callback failed", exc_info=True)
        if state == "ready":
            return True
        launch = get_launch(serial)
        if launch is not None and not launch.alive:
            logger.warning(
                f"Emulator {serial} exited while booting (log: {launch.log_path})"
            )
            return False
        if elapsed >= timeout:
            return False
        time.sleep(interval)


def _console_kill(adb: Any, serial: str) -> bool:
    """``adb -s <serial> emu kill``; False if adb or the console refused."""
    try:
        out, err = adb.send_telnet_command("kill", serial=serial)
    except Exception as e:
        logger.debug(f"emu kill {serial} failed: {e}")
        return False
    text = f"{out or ''}\n{err or ''}".lower()
    failed = "error" in text or "not found" in text or "\nko" in f"\n{text}"
    if failed:
        logger.debug(f"emu kill {serial} failed: {' '.join(text.split())}")
    return not failed


def _terminate(process: Any, grace: float = 10.0) -> None:
    """Terminate our emulator *process*: SIGTERM, wait *grace* s, then kill."""
    try:
        process.terminate()
    except Exception:
        logger.debug("terminate failed", exc_info=True)
    try:
        process.wait(timeout=grace)
        return
    except Exception:
        pass
    try:
        process.kill()
        process.wait(timeout=5.0)
    except Exception:
        logger.warning(f"Emulator process {getattr(process, 'pid', '?')} did not exit")


def stop_emulator(serial: str, adb: Any = None, timeout: float = 30.0) -> bool:
    """Stop emulator *serial* via its console (``adb -s <serial> emu kill``).

    Never kills processes by name: other sessions' emulators stay untouched.
    Our own launch is also stopped while adb cannot reach its console yet
    (not listed, or ``emu kill`` refused): its process is terminated, so a
    stop during the early boot really stops it. Whoever waits for the boot
    of our launch gives up (its ``cancel`` event is set).

    Returns:
        True once *serial* left ``adb devices`` (and our process, if it was
        terminated, exited) within *timeout*.
    """
    if serial_port(serial) is None:
        logger.warning(f"{serial} is not an emulator; not stopping it")
        return False
    adb = _adb(adb)
    launch = get_launch(serial)
    if launch is not None:
        launch.cancel.set()
    entries = _list_entries(adb)
    listed = entries is not None and any(e.serial == serial for e in entries)
    killed = _console_kill(adb, serial)
    if launch is not None and launch.alive and not (killed and listed):
        logger.info(
            f"Emulator {serial} is not reachable over its console yet; "
            f"terminating our process (PID {getattr(launch.process, 'pid', '?')})"
        )
        _terminate(launch.process)
    deadline = time.monotonic() + timeout
    while True:
        entries = _list_entries(adb)
        if entries is not None and all(e.serial != serial for e in entries):
            _forget_launch(serial)
            return True
        if time.monotonic() >= deadline:
            logger.warning(f"Emulator {serial} still listed {timeout:g}s after kill")
            return False
        time.sleep(1.0)


def restart_emulator(
    serial: str, options: AvdLaunchOptions | None = None, adb: Any = None
) -> EmulatorLaunch:
    """Stop emulator *serial* and start the same AVD on the same port.

    The AVD name is resolved BEFORE the kill. Options default to the launch
    record, then the remembered options; ``wipe`` becomes ``normal`` (a
    restart never factory-resets). Same port -> same serial, so the session
    reconnects to it. Does not wait for the boot (see
    :func:`wait_until_ready`).

    Raises:
        EmulatorLaunchError: Not an emulator, AVD unknown, it did not stop,
            its port stayed busy, or the relaunch failed.
    """
    port = serial_port(serial)
    if port is None:
        raise EmulatorLaunchError(f"{serial} is not an emulator")
    adb = _adb(adb)
    avd = avd_name_of(serial, adb)
    if not avd:
        raise EmulatorLaunchError(f"Could not determine the AVD of {serial}")
    if options is None:
        launch = get_launch(serial)
        options = launch.options if launch is not None else remembered_options(avd)
    if options.boot == "wipe":
        options = replace(options, boot="normal")
    if not stop_emulator(serial, adb):
        raise EmulatorLaunchError(f"Emulator {serial} did not stop")
    # Bindable ignores TIME_WAIT (see _port_bindable): this only waits for
    # the old emulator to really let go of its ports.
    deadline = time.monotonic() + 15.0
    while not _ports_free(port):
        if time.monotonic() >= deadline:
            raise EmulatorLaunchError(f"Console port {port} is still in use")
        time.sleep(0.5)
    return launch_avd(avd, options, port=port, adb=adb)


def ensure_avd_running(
    avd: str,
    *,
    timeout: float = DEFAULT_BOOT_TIMEOUT,
    on_progress: Callable[[BootState, float], None] | None = None,
    options: AvdLaunchOptions | None = None,
    adb: Any = None,
) -> str:
    """Serial of a ready emulator running AVD *avd*, starting it if needed.

    Reuses an emulator of that AVD that is already running (any session's;
    only online ones -- an offline emulator cannot be asked for its AVD);
    otherwise launches it with *options* (default: the remembered options),
    remembers them and waits for the boot.

    Raises:
        EmulatorLaunchError: The launch failed or it did not boot in time.
    """
    adb = _adb(adb)
    for entry in _list_entries(adb) or []:
        if serial_port(entry.serial) is None or entry.state != "device":
            continue
        if avd_name_of(entry.serial, adb) != avd:
            continue
        if wait_until_ready(entry.serial, timeout, on_progress, adb=adb):
            return entry.serial
        raise EmulatorLaunchError(
            f"Emulator {entry.serial} ({avd}) did not become ready within "
            f"{timeout:g}s"
        )
    launch = launch_avd(avd, options or remembered_options(avd), adb=adb)
    remember_launch(avd, launch.options)
    if not wait_until_ready(launch.serial, timeout, on_progress, adb=adb):
        raise EmulatorLaunchError(
            f"Emulator '{avd}' ({launch.serial}) did not become ready within "
            f"{timeout:g}s" + (f" (log: {launch.log_path})" if launch.log_path else ""),
            log_path=launch.log_path,
        )
    return launch.serial


# ---------------------------------------------------------------------------
# Remembered launch options
# ---------------------------------------------------------------------------

_PREFS_SCHEMA = 1
_PREFS_LOCK = threading.RLock()


def _prefs_path() -> Path:
    """``devices.json`` in Sandroid's per-user dir (``$XDG_CONFIG_HOME``)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sandroid" / "devices.json"


def _empty_prefs() -> dict[str, Any]:
    return {"schema_version": _PREFS_SCHEMA, "last_avd": None, "avds": {}}


def load_launch_prefs() -> dict[str, Any]:
    """The remembered launch preferences.

    Returns:
        ``{"schema_version": 1, "last_avd": str | None, "avds": {name:
        {"headless": bool, "boot": str, "snapshot": str | None}}}``; the
        empty document when the file is missing or unreadable.
    """
    try:
        data = json.loads(_prefs_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty_prefs()
    prefs = _empty_prefs()
    if not isinstance(data, dict) or not isinstance(data.get("avds"), dict):
        return prefs
    if isinstance(data.get("last_avd"), str):
        prefs["last_avd"] = data["last_avd"]
    prefs["avds"] = {k: v for k, v in data["avds"].items() if isinstance(v, dict)}
    return prefs


def _save_prefs(prefs: dict[str, Any]) -> None:
    path = _prefs_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(prefs, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError as e:
        logger.warning(f"Could not save launch options to {path}: {e}")


def options_from_prefs(prefs: dict[str, Any], name: str) -> AvdLaunchOptions:
    """Launch options remembered for AVD *name* in *prefs* (never ``wipe``).

    Args:
        prefs: A document as returned by :func:`load_launch_prefs`.
        name: AVD name.

    Returns:
        The remembered options; for an AVD launched never before: normal
        boot, headless per config ``emulator.avd_headless``.
    """
    entry = (prefs.get("avds") or {}).get(name)
    if not isinstance(entry, dict):
        return AvdLaunchOptions(
            headless=bool(getattr(_config_emulator(), "avd_headless", False))
        )
    boot = entry.get("boot", "normal")
    snapshot = entry.get("snapshot") or None
    if boot not in ("normal", "cold", "snapshot") or (
        boot == "snapshot" and not snapshot
    ):
        boot = "normal"
    return AvdLaunchOptions(
        headless=bool(entry.get("headless", False)),
        boot=boot,
        snapshot=snapshot if boot == "snapshot" else None,
    )


def remembered_options(name: str) -> AvdLaunchOptions:
    """Launch options last used for AVD *name* (never ``wipe``).

    First launch: normal boot, headless per config ``emulator.avd_headless``.
    """
    return options_from_prefs(load_launch_prefs(), name)


def remember_launch(
    name: str, opts: AvdLaunchOptions, *, make_last: bool = True
) -> None:
    """Persist *opts* for AVD *name* and make it the last-used AVD.

    A ``wipe`` is stored as ``normal``: a factory reset is never repeated by
    accident. Write errors are logged, not raised.

    Args:
        name: AVD name.
        opts: The options to remember.
        make_last: Also make *name* the last-used AVD (False when only an
            option is changed, e.g. the headless toggle in the Devices screen).
    """
    boot = "normal" if opts.boot == "wipe" else opts.boot
    snapshot = opts.snapshot if boot == "snapshot" else None
    if boot == "snapshot" and not snapshot:
        boot = "normal"
    with _PREFS_LOCK:
        prefs = load_launch_prefs()
        if make_last:
            prefs["last_avd"] = name
        prefs["avds"][name] = {
            "headless": bool(opts.headless),
            "boot": boot,
            "snapshot": snapshot,
        }
        _save_prefs(prefs)


def _move_prefs(old: str, new: str) -> None:
    """Carry remembered options of a renamed AVD over to its new name."""
    with _PREFS_LOCK:
        if not _prefs_path().exists():
            return
        prefs = load_launch_prefs()
        entry = prefs["avds"].pop(old, None)
        if entry is not None:
            prefs["avds"][new] = entry
        if prefs["last_avd"] == old:
            prefs["last_avd"] = new
        _save_prefs(prefs)


__all__ = [
    "API_TO_ANDROID_VERSION",
    "AvdInfo",
    "AvdLaunchOptions",
    "AvdSnapshot",
    "EmulatorLaunch",
    "EmulatorLaunchError",
    "adb_binary",
    "avd_dir",
    "avd_home",
    "avd_info",
    "avd_name_of",
    "avd_snapshots",
    "boot_state",
    "booting_serials",
    "build_emulator_command",
    "check_emulator_startup",
    "emulator_binary",
    "emulator_env",
    "emulator_log_path",
    "ensure_avd_running",
    "free_console_port",
    "get_launch",
    "launch_avd",
    "launches",
    "list_avds",
    "load_launch_prefs",
    "looks_like_sdk",
    "options_from_prefs",
    "remember_launch",
    "remembered_options",
    "rename_avd",
    "restart_emulator",
    "sdk_root",
    "serial_port",
    "spawn_emulator",
    "stop_emulator",
    "wait_until_ready",
]
