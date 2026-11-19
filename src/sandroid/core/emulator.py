"""The emulator / AVD backend: discovery, catalogue, launch and lifecycle.

Every place in Sandroid that finds the SDK, lists AVDs, starts, stops or
restarts an emulator goes through this module:

* **Discovery** (config-aware): :func:`sdk_root`, :func:`emulator_binary`,
  :func:`adb_binary`, :func:`avd_home`, :func:`avd_dir`, :func:`emulator_env`.
* **Catalogue**: :func:`list_avds`, :func:`avd_info`, :func:`avd_snapshots`,
  :func:`rename_avd`, :func:`avd_name_of`.
* **Launch** (one path): :class:`AvdLaunchOptions`,
  :func:`build_emulator_command`, :func:`free_console_port`,
  :func:`preferred_console_port` (pinned serial's port, else the AVD's
  last port, else the first free one), :func:`launch_avd` ->
  :class:`EmulatorLaunch` (kept in a registry, see
  :func:`get_launch` / :func:`booting_serials`). Every launch passes an
  explicit ``-port`` so the adb serial (``emulator-<port>``) is known before
  the emulator even starts.
* **Lifecycle**: :func:`boot_state`, :func:`wait_until_ready`,
  :func:`stop_emulator` (per-serial ``emu kill``, never ``pkill``),
  :func:`restart_emulator` (same AVD, same port), :func:`ensure_avd_running`.
* **Launch hooks**: :func:`register_pre_launch_hook` (run before every
  emulator process Sandroid spawns, after its port is chosen; may return
  extra emulator arguments and patch files under the AVD directory) and
  :func:`register_post_stop_hook` (run once that emulator has exited, to
  restore what pre-launch patched), both called with a
  :class:`LaunchContext`. Hooks run on the backend's worker paths, never on
  the Textual UI thread. Emulators Sandroid did not launch get no post-stop
  hooks. A further hook kind (e.g. a ``post_ready`` hook called with the
  serial after :func:`wait_until_ready` succeeded and after Sandroid's own
  attach steps) is added as one more key in ``_HOOKS`` plus a
  register/unregister pair and one invocation site.
* **Remembered launch options** (``devices.json`` in the user config dir):
  :func:`load_launch_prefs`, :func:`remembered_options`,
  :func:`remember_launch`.
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import Any, Literal

from sandroid.core.exceptions import EmulatorLaunchError

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

BootMode = Literal["normal", "cold", "snapshot"]
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
        snapshots: Their names (``default_boot`` first, then newest first).
    """

    name: str
    api_level: int | None = None
    android_version: str = "Unknown"
    tag: str = ""
    abi: str = ""
    device_name: str = ""
    path: Path | None = None
    snapshot_count: int = 0
    snapshots: tuple[str, ...] = ()


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
    snapshots = avd_snapshots(name) if directory else []

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
        snapshot_count=len(snapshots),
        snapshots=tuple(s.name for s in snapshots),
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
        ours = [
            x
            for x in [*_LAUNCHES.values(), *_UNFINISHED]
            if x.avd == old_name and x.alive
        ]
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

    Our own (live) launch record first, then the emulator console's
    ``adb -s <serial> emu avd name`` -- what the emulator itself reports; it
    answers before the boot completed and runs nothing inside the guest.
    Only when the console gives no name: the ``ro.boot.qemu.avd_name`` /
    ``ro.kernel.qemu.avd_name`` properties. Every adb call is scoped to
    *serial* and has a short timeout.
    """
    launch = get_launch(serial)
    if launch is not None and launch.alive:
        return launch.avd
    adb = _adb(adb)
    for line in _adb_call(adb, "emu avd name", serial).splitlines():
        line = line.strip()
        if (
            line
            and line != "OK"
            and not line.startswith("KO")
            and not line.lower().startswith("error")
        ):
            return line
    for prop in ("ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name"):
        name = _adb_call(adb, f"shell getprop {prop}", serial).strip()
        if name:
            return name
    return None


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AvdLaunchOptions:
    """How to launch an AVD.

    Attributes:
        headless: No window (``-no-window -no-boot-anim``, software GLES).
        boot: ``normal`` (quick boot from the AVD's quick-boot snapshot),
            ``cold`` (no snapshot load) or ``snapshot`` (load *snapshot*).
        snapshot: Snapshot name for ``boot="snapshot"``.
        save_on_exit: Let the emulator save its state when it shuts down
            (its default). False adds ``-no-snapshot-save``: every boot
            starts from the same state.
        wipe_once: Factory-reset this launch (``-wipe-data``). Never
            remembered and never repeated by a restart.
        extra_args: Further emulator arguments.

    ``boot="wipe"`` (the old way to ask for a factory reset) is accepted and
    becomes ``boot="normal", wipe_once=True``.
    """

    headless: bool = False
    boot: BootMode = "normal"
    snapshot: str | None = None
    save_on_exit: bool = False
    wipe_once: bool = False
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.boot == "wipe":  # type: ignore[comparison-overlap]
            object.__setattr__(self, "boot", "normal")
            object.__setattr__(self, "wipe_once", True)


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
    elif opts.boot == "snapshot" and opts.snapshot:
        command += ["-snapshot", opts.snapshot]
    if opts.wipe_once:
        command.append("-wipe-data")
    if not opts.save_on_exit:
        command.append("-no-snapshot-save")
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


#: Why :func:`preferred_console_port` chose a port.
PortReason = Literal["pinned", "last used", "auto"]


def pinned_serial() -> str | None:
    """The serial this session is pinned to, if any.

    ``--serial`` (``DeviceManager.set_preferred_serial``), then config
    ``emulator.serial``, then ``$ANDROID_SERIAL``.
    """
    try:
        from sandroid.core.device_manager import DeviceManager

        explicit = DeviceManager._preferred_serial
    except Exception:
        explicit = None
    configured = getattr(_config_emulator(), "serial", None)
    return (
        explicit
        or (configured if isinstance(configured, str) else None)
        or os.environ.get("ANDROID_SERIAL")
        or None
    )


def _usable_console_port(port: int | None) -> bool:
    """An even console port adb auto-discovers (5554-5584)."""
    return (
        port is not None
        and CONSOLE_PORT_MIN <= port <= CONSOLE_PORT_MAX
        and port % 2 == 0
    )


def remembered_port(name: str, prefs: dict[str, Any] | None = None) -> int | None:
    """Console port AVD *name* last ran on (``devices.json``), if known."""
    prefs = load_launch_prefs() if prefs is None else prefs
    entry = (prefs.get("avds") or {}).get(name)
    port = entry.get("port") if isinstance(entry, dict) else None
    return port if isinstance(port, int) and _usable_console_port(port) else None


def preferred_console_port(
    avd: str,
    taken: set[int],
    *,
    pinned: str | None = None,
    prefs: dict[str, Any] | None = None,
) -> tuple[int, PortReason]:
    """The console port a launch of *avd* uses (every launch path).

    In a shared lab every session owns one console port, so a launch must
    not grab the first free port when it has a better one:

    1. **pinned**: the session is pinned to ``emulator-<N>`` (see
       :func:`pinned_serial`), no listed emulator uses it and N is free.
    2. **last used**: the port *avd* last ran on, if free.
    3. **auto**: :func:`free_console_port`.

    Args:
        avd: AVD name.
        taken: Console ports to skip (listed emulators, our launches).
        pinned: Pinned serial (default: :func:`pinned_serial`).
        prefs: Launch prefs (default: :func:`load_launch_prefs`).

    Returns:
        ``(port, reason)``.

    Raises:
        EmulatorLaunchError: No port is free.
    """
    pinned = pinned_serial() if pinned is None else pinned
    port = serial_port(pinned or "")
    if _usable_console_port(port) and port not in taken and _ports_free(port):
        return port, "pinned"
    last = remembered_port(avd, prefs)
    if last is not None and last not in taken and _ports_free(last):
        return last, "last used"
    return free_console_port(taken), "auto"


# ---------------------------------------------------------------------------
# Launch hooks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchContext:
    """What a launch hook knows about one emulator launch.

    Post-stop hooks get the same object the launch's pre-launch hooks got.

    Attributes:
        avd: AVD name.
        avd_dir: The AVD's directory (:func:`avd_dir`, honouring the ini's
            ``path=`` / ``path.rel=`` redirect); when it cannot be resolved,
            the default ``<avd home>/<avd>.avd`` (which may not exist).
        port: Console port of the launch (the serial is
            ``emulator-<port>``); always set for Sandroid's launches.
        options: The launch options, without arguments added by hooks.
    """

    avd: str
    avd_dir: Path
    port: int | None
    options: AvdLaunchOptions


#: Called before an emulator process starts; returns extra emulator
#: arguments (appended after ``options.extra_args``, never remembered) and
#: may patch files under ``context.avd_dir``.
PreLaunchHook = Callable[[LaunchContext], tuple[str, ...]]
#: Called once that emulator has exited; restores what pre-launch patched.
PostStopHook = Callable[[LaunchContext], None]

#: Registered hooks per kind, in registration order (guarded by
#: ``_HOOK_LOCK``). Invocations iterate a snapshot taken under the lock.
_HOOKS: dict[str, list[Callable[..., Any]]] = {"pre_launch": [], "post_stop": []}
_HOOK_LOCK = threading.Lock()


def _register_hook(kind: str, hook: Callable[..., Any]) -> None:
    if not callable(hook):
        raise TypeError(f"{kind} hook must be callable, got {hook!r}")
    with _HOOK_LOCK:
        if hook not in _HOOKS[kind]:
            _HOOKS[kind].append(hook)


def _unregister_hook(kind: str, hook: Callable[..., Any]) -> None:
    with _HOOK_LOCK:
        if hook in _HOOKS[kind]:
            _HOOKS[kind].remove(hook)


def _hook_snapshot(kind: str) -> list[Callable[..., Any]]:
    with _HOOK_LOCK:
        return list(_HOOKS[kind])


def register_pre_launch_hook(hook: PreLaunchHook) -> None:
    """Run *hook* before every emulator process Sandroid starts.

    It runs on every launch path (:func:`launch_avd`,
    :func:`restart_emulator`, :func:`ensure_avd_running`) after the console
    port was chosen and before the process is spawned, off the UI thread.
    It returns extra emulator arguments (appended to the command after
    ``options.extra_args``; never stored in ``devices.json``) and may patch
    files under ``context.avd_dir``. Hooks run in registration order;
    registering the same callable again does nothing.

    If a hook raises, the launch fails closed: no process is started, the
    port is released, the post-stop hooks run (best effort, so partial
    patches are restored) and :class:`EmulatorLaunchError` names the hook.

    Args:
        hook: ``hook(context) -> tuple[str, ...]``.

    Raises:
        TypeError: *hook* is not callable.
    """
    _register_hook("pre_launch", hook)


def unregister_pre_launch_hook(hook: PreLaunchHook) -> None:
    """Remove a pre-launch hook (no-op if it is not registered)."""
    _unregister_hook("pre_launch", hook)


def register_post_stop_hook(hook: PostStopHook) -> None:
    """Run *hook* once an emulator Sandroid launched has exited.

    Called with the launch's :class:`LaunchContext` (the one its pre-launch
    hooks saw) after the emulator actually exited: on
    :func:`stop_emulator`, on :func:`restart_emulator` (before the
    relaunch's pre-launch hooks), when a launch crashes during startup or
    its pre-launch failed, and best effort when our emulator died on its own
    (noticed by :func:`wait_until_ready` or :func:`reap_exited_launches`:
    the next :func:`launch_avd`, the TUI's device poll, interpreter exit).
    At most once per launch, off the UI thread, and always finished before
    a later pre-launch for the same AVD starts. Exceptions are logged and
    swallowed; they never block a stop or restart. Hooks must tolerate a
    launch with nothing to restore.

    An emulator still running when Sandroid exits keeps running (detached)
    with its patches: post-stop runs only for launches Sandroid saw exit.
    Pre-launch hooks must therefore tolerate leftover state from an earlier
    session.

    Emulators Sandroid did not launch (no launch record) get no post-stop
    hooks, although :func:`stop_emulator` stops them.

    Args:
        hook: ``hook(context) -> None``.

    Raises:
        TypeError: *hook* is not callable.
    """
    _register_hook("post_stop", hook)


def unregister_post_stop_hook(hook: PostStopHook) -> None:
    """Remove a post-stop hook (no-op if it is not registered)."""
    _unregister_hook("post_stop", hook)


def _hook_name(hook: Callable[..., Any]) -> str:
    name = getattr(hook, "__qualname__", None) or getattr(hook, "__name__", None)
    if not name:
        return repr(hook)
    module = getattr(hook, "__module__", None)
    return f"{module}.{name}" if module else name


def _launch_context(avd: str, port: int, opts: AvdLaunchOptions) -> LaunchContext:
    directory = avd_dir(avd)
    if directory is None:
        home = avd_home() or Path("~/.android/avd").expanduser()
        directory = home / f"{avd}.avd"
    return LaunchContext(avd=avd, avd_dir=directory, port=port, options=opts)


def _hook_args(value: Any) -> tuple[str, ...]:
    """Validate what a pre-launch hook returned (``None`` means none)."""
    if value is None:
        return ()
    if isinstance(value, (tuple, list)) and all(isinstance(a, str) for a in value):
        return tuple(value)
    raise TypeError(f"expected a tuple of str, got {value!r}")


def _run_pre_launch_hooks(context: LaunchContext) -> tuple[str, ...]:
    """Extra emulator arguments of all pre-launch hooks (fails closed).

    Raises:
        EmulatorLaunchError: A hook raised or returned something other
            than a tuple of strings; the post-stop hooks have run.
    """
    args: list[str] = []
    for hook in _hook_snapshot("pre_launch"):
        try:
            args += _hook_args(hook(context))
        except Exception as e:
            name = _hook_name(hook)
            logger.error(
                f"Pre-launch hook {name} failed for AVD '{context.avd}': "
                f"{type(e).__name__}: {e}; not starting it"
            )
            _run_post_stop_hooks(context)
            raise EmulatorLaunchError(
                f"Pre-launch hook {name} failed for AVD '{context.avd}': "
                f"{type(e).__name__}: {e}"
            ) from e
    return tuple(args)


def _run_post_stop_hooks(context: LaunchContext) -> None:
    """Run every post-stop hook; errors are logged, never raised."""
    for hook in _hook_snapshot("post_stop"):
        try:
            hook(context)
        except Exception:
            logger.warning(
                f"Post-stop hook {_hook_name(hook)} failed for AVD '{context.avd}'",
                exc_info=True,
            )


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
        context: What its launch hooks saw (post-stop gets the same).
        hook_args: Emulator arguments its pre-launch hooks added.
        post_stop_claimed: True once a thread started its post-stop hooks
            (they run at most once; only after its process exited).
        post_stop_finished: Set once its post-stop hooks have finished
            (also when one raised); wait on it before patching its AVD again.
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
    context: LaunchContext | None = field(default=None, compare=False)
    hook_args: tuple[str, ...] = ()
    post_stop_claimed: bool = field(
        default=False, init=False, compare=False, repr=False
    )
    post_stop_finished: threading.Event = field(
        default_factory=threading.Event, init=False, compare=False, repr=False
    )

    @property
    def post_stop_done(self) -> bool:
        """True once its process exited and its post-stop hooks finished."""
        return self.post_stop_finished.is_set()

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
#: Launches dropped from ``_LAUNCHES`` (left adb, or crashed during startup)
#: whose post-stop hooks have not finished yet: the process is still exiting
#: (e.g. saving its snapshot) or the hooks are running (``_LAUNCH_LOCK``).
#: An alive one still blocks a new launch of its AVD.
_UNFINISHED: list[EmulatorLaunch] = []
#: Seconds a launch waits for an earlier launch's post-stop hooks (run by
#: another thread) to finish before its own pre-launch hooks; then it fails.
POST_STOP_WAIT = 60.0
#: Seconds :func:`restart_emulator` waits for the old process to exit after
#: it left adb (``save_on_exit`` launches write their snapshot first).
RESTART_EXIT_WAIT = 15.0
RESTART_EXIT_WAIT_SAVING = 60.0


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
    """Drop *serial*'s record; one whose post-stop is due moves (atomically)
    to ``_UNFINISHED``, so it is never in neither registry.
    """
    with _LAUNCH_LOCK:
        launch = _LAUNCHES.pop(serial, None)
        if launch is not None:
            _keep_unfinished(launch)


def _keep_unfinished(launch: EmulatorLaunch) -> None:
    """Track *launch* in ``_UNFINISHED`` until its post-stop finished."""
    with _LAUNCH_LOCK:
        if launch.post_stop_done or any(x is launch for x in _UNFINISHED):
            return
        _UNFINISHED.append(launch)


def _shutting_down(avd: str) -> EmulatorLaunch | None:
    """Our forgotten launch of *avd* whose process still runs."""
    with _LAUNCH_LOCK:
        return next((x for x in _UNFINISHED if x.avd == avd and x.alive), None)


def _finish_launch(launch: EmulatorLaunch) -> bool:
    """Run the post-stop hooks of *launch* (it exited); at most once.

    Only call it once the process exited. The first caller claims the hooks
    and runs them; a later or concurrent caller returns at once -- wait on
    ``launch.post_stop_finished`` (see :func:`_await_post_stop`) to know
    they finished. Never runs hooks under ``_LAUNCH_LOCK``.

    Returns:
        True if this call ran them.
    """
    with _LAUNCH_LOCK:
        if launch.post_stop_claimed:
            return False
        launch.post_stop_claimed = True
    try:
        if launch.context is not None:
            _run_post_stop_hooks(launch.context)
    finally:
        with _LAUNCH_LOCK:
            _UNFINISHED[:] = [x for x in _UNFINISHED if x is not launch]
        launch.post_stop_finished.set()
    return True


def _await_post_stop(launch: EmulatorLaunch, timeout: float | None = None) -> None:
    """Finish *launch* (exited) and wait until its post-stop hooks finished.

    Another thread may be running them (a poll's reap, a boot waiter); a
    pre-launch for the same AVD must not start before they are done.

    Raises:
        EmulatorLaunchError: They are still running after *timeout* s
            (default :data:`POST_STOP_WAIT`); fails closed.
    """
    _finish_launch(launch)
    wait = POST_STOP_WAIT if timeout is None else timeout
    if not launch.post_stop_finished.wait(wait):
        raise EmulatorLaunchError(
            f"The post-stop hooks of the previous launch of AVD '{launch.avd}' "
            f"({launch.serial}) are still running after {wait:g}s; not "
            "starting it again until they finished restoring it -- try again "
            "shortly"
        )


def _await_avd_post_stops(avd: str) -> None:
    """Wait for the post-stop hooks of every exited launch of *avd*.

    Raises:
        EmulatorLaunchError: See :func:`_await_post_stop`.
    """
    with _LAUNCH_LOCK:
        due = [
            x
            for x in [*_LAUNCHES.values(), *_UNFINISHED]
            if x.avd == avd and not x.post_stop_done and not x.alive
        ]
    deadline = time.monotonic() + POST_STOP_WAIT
    for launch in due:
        _await_post_stop(launch, max(0.0, deadline - time.monotonic()))


def _wait_exit(process: Any, timeout: float) -> None:
    """Wait up to *timeout* s for *process* to exit (errors ignored)."""
    try:
        process.wait(timeout=timeout)
    except Exception:
        pass


def reap_exited_launches() -> list[EmulatorLaunch]:
    """Run the post-stop hooks of our launches whose process has exited.

    Best effort for emulators that died on their own (crash, closed
    window) or exited after they left adb: their post-stop hooks have not
    run yet. Called by :func:`launch_avd` before every launch, by the TUI's
    device poll worker and at interpreter exit; may be called by any worker
    thread (never the UI thread: hooks may block). Emulators still running
    are left alone (they are detached and keep running after Sandroid
    exits, with their patches).

    Returns:
        The launches whose post-stop hooks this call ran (hooks another
        thread is running are not waited for).
    """
    with _LAUNCH_LOCK:
        due = [
            x
            for x in [*_LAUNCHES.values(), *_UNFINISHED]
            if not x.post_stop_claimed and not x.alive
        ]
    return [launch for launch in due if _finish_launch(launch)]


def _reap_at_exit() -> None:
    """``atexit``: run post-stop hooks of launches that exited (best effort)."""
    try:
        reap_exited_launches()
    except Exception:
        logger.debug("reaping exited emulator launches at exit failed", exc_info=True)


atexit.register(_reap_at_exit)


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


def _reserve_port(
    taken: set[int], port: int | None, avd: str | None = None
) -> tuple[int, PortReason | Literal["explicit"]]:
    """Choose (or claim *port*) and reserve it, under the registry lock.

    With *avd* the choice follows :func:`preferred_console_port` (pinned,
    then last-used port); without it, the first free port.

    Returns:
        ``(port, reason)``; reason is ``"explicit"`` for a given *port*.

    Raises:
        EmulatorLaunchError: *port* is already reserved / used by our live
            launch, or no port is free.
    """
    with _LAUNCH_LOCK:
        ours = _our_ports()
        reason: PortReason | Literal["explicit"]
        if port is not None:
            if port in ours:
                raise EmulatorLaunchError(
                    f"Console port {port} is already used by another launch"
                )
            chosen, reason = port, "explicit"
        elif avd is not None:
            chosen, reason = preferred_console_port(avd, taken | ours)
            logger.info(f"Console port {chosen} for '{avd}' ({reason})")
        else:
            chosen, reason = free_console_port(taken | ours), "auto"
        _RESERVED_PORTS.add(chosen)
        return chosen, reason


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
    background (see :func:`wait_until_ready`). If an ``auto`` port was
    grabbed in the meantime, retries once on the next free port; a pinned or
    last-used port is never swapped for an arbitrary one (the launch fails).
    The pre-launch hooks (:func:`register_pre_launch_hook`) run before each
    spawned process, once its port is known.

    Args:
        avd: AVD name.
        options: Launch options (default: :class:`AvdLaunchOptions`).
        port: Console port; ``None`` picks :func:`preferred_console_port`
            (the pinned serial's port, else the AVD's last port, else the
            first free one).
        adb: adb interface (default: the global ``Adb``).

    Returns:
        The registered :class:`EmulatorLaunch` (``serial`` is
        ``emulator-<port>``).

    Before the pre-launch hooks, the post-stop hooks of every earlier
    launch of *avd* that exited have finished (run here, or awaited when
    another thread is running them).

    Raises:
        EmulatorLaunchError: No emulator binary / free port, our launch of
            *avd* is still running or still shutting down, an earlier
            launch's post-stop hooks did not finish within
            :data:`POST_STOP_WAIT`, a pre-launch hook failed (named in the
            message), the process could not start, or it crashed during
            startup (the message names the log file).
    """
    opts = options or AvdLaunchOptions()
    if not avd:
        raise EmulatorLaunchError("No AVD name given")
    # An earlier launch that died unnoticed restores its patches before
    # this launch's pre-launch hooks patch again.
    reap_exited_launches()
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
        exiting = _shutting_down(avd)
        if exiting is not None:
            raise EmulatorLaunchError(
                f"AVD '{avd}' is still shutting down ({exiting.serial}, PID "
                f"{getattr(exiting.process, 'pid', '?')}; it may still be "
                "saving its snapshot); start it again once it has exited"
            )
        if avd in _STARTING_AVDS:
            raise EmulatorLaunchError(f"AVD '{avd}' is already being started")
        _STARTING_AVDS.add(avd)
    try:
        # Another thread (a poll's reap) may still be restoring an earlier
        # launch: never patch the AVD again before that has finished.
        _await_avd_post_stops(avd)
        launch = _launch_reserved(avd, opts, binary, _adb(adb), port)
    finally:
        with _LAUNCH_LOCK:
            _STARTING_AVDS.discard(avd)
    # Outside the "being started" window: a restart may follow at once.
    _remember_port(avd, launch.port)
    return launch


def _launch_reserved(
    avd: str, opts: AvdLaunchOptions, binary: Path, adb: Any, port: int | None
) -> EmulatorLaunch:
    """:func:`launch_avd` once *avd* is marked as starting."""
    taken = _listed_ports(adb)
    chosen, reason = _reserve_port(taken, port, avd)
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
            _await_post_stop(launch)  # it exited: restore before any retry
            log_path = launch.log_path
            if reason in ("pinned", "last used") and not _ports_free(chosen):
                # Never fall back to an arbitrary port: in a shared lab the
                # next free one may be another session's.
                hint = "free it or unpin" if reason == "pinned" else "free it"
                raise EmulatorLaunchError(
                    f"Console port {chosen} ({reason}) is taken — {hint}"
                    + (f" (log: {log_path})" if log_path else ""),
                    log_path=log_path,
                )
            if attempt == 1 and reason == "auto" and not _ports_free(chosen):
                logger.warning(
                    f"Console port {chosen} was taken during startup; retrying"
                )
                taken.add(chosen)
                _release_port(chosen)
                chosen, reason = _reserve_port(taken, None)
                continue
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
    """Run the pre-launch hooks, start the process, register the launch.

    The one place an emulator process is spawned, so every launch path runs
    the pre-launch hooks exactly once per process, with its real port. A
    dead earlier record on the same serial is finished (post-stop) first;
    a live one refuses the launch.
    """
    serial = f"emulator-{port}"
    with _LAUNCH_LOCK:
        previous = _LAUNCHES.get(serial)
        if previous is not None and previous.alive:
            raise EmulatorLaunchError(
                f"{serial} is still used by our launch of AVD '{previous.avd}'"
            )
        if previous is not None:
            _forget_launch(serial)
    if previous is not None:
        _await_post_stop(previous)
    context = _launch_context(avd, port, opts)
    hook_args = _run_pre_launch_hooks(context)
    process = None
    try:
        command = build_emulator_command(binary, avd, port, opts) + list(hook_args)
        logger.info(f"Starting emulator '{avd}': {' '.join(command)}")
        try:
            process, log_path = spawn_emulator(command, avd, emulator_env())
        except (OSError, subprocess.SubprocessError) as e:
            raise EmulatorLaunchError(f"Could not start emulator '{avd}': {e}") from e
        launch = EmulatorLaunch(
            avd=avd,
            serial=serial,
            port=port,
            options=opts,
            process=process,
            log_path=log_path,
            started_at=time.monotonic(),
            context=context,
            hook_args=hook_args,
        )
        with _LAUNCH_LOCK:
            displaced = _LAUNCHES.get(serial)
            if displaced is not None:  # pragma: no cover - port is reserved
                _forget_launch(serial)  # still finished by a later reap
            _LAUNCHES[serial] = launch
        return launch
    except BaseException:
        # Whatever failed after the pre-launch hooks: no process of ours
        # keeps running unregistered, and what they patched is restored.
        if process is not None:
            _terminate(process)
        _run_post_stop_hooks(context)
        raise


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
        *serial* died (its post-stop hooks then run).
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
            _finish_launch(launch)
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

    Once our launch has exited, its post-stop hooks run (when hooks are
    registered, the process is awaited within *timeout* after it left adb;
    if it is still exiting, it is kept as "shutting down" -- a new launch
    of its AVD is refused meanwhile -- and its hooks run when its exit is
    next noticed, see :func:`reap_exited_launches`). An emulator Sandroid
    did not launch is stopped the same way but gets no post-stop hooks.

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
            _forget_launch(serial)  # -> _UNFINISHED until post-stop finished
            if launch is not None:
                _settle_stopped(launch, max(2.0, deadline - time.monotonic()))
            return True
        if time.monotonic() >= deadline:
            logger.warning(f"Emulator {serial} still listed {timeout:g}s after kill")
            if launch is not None and not launch.alive:
                _finish_launch(launch)  # adb lags, but our process ended
            return False
        time.sleep(1.0)


def _settle_stopped(launch: EmulatorLaunch, wait: float) -> None:
    """*launch* left adb: run its post-stop hooks once its process exited.

    Waits up to *wait* seconds for the process (only when post-stop hooks
    are registered). Never finishes a launch whose process still runs, even
    without hooks (one registered meanwhile must not run before the exit):
    it stays in ``_UNFINISHED`` and is finished by
    :func:`reap_exited_launches`.
    """
    _keep_unfinished(launch)
    hooks = bool(_hook_snapshot("post_stop"))
    if hooks and launch.alive:
        _wait_exit(launch.process, wait)
    if launch.alive:
        if hooks:
            logger.info(
                f"Emulator {launch.serial} left adb but is still exiting; its "
                "post-stop hooks run once it has exited"
            )
        return
    _finish_launch(launch)


def restart_emulator(
    serial: str,
    options: AvdLaunchOptions | None = None,
    adb: Any = None,
    *,
    exit_timeout: float | None = None,
) -> EmulatorLaunch:
    """Stop emulator *serial* and start the same AVD on the same port.

    The AVD name is resolved BEFORE the kill. Options default to the launch
    record, then the remembered options; ``wipe_once`` is dropped (a
    restart never factory-resets). Same port -> same serial, so the session
    reconnects to it. Does not wait for the boot (see
    :func:`wait_until_ready`). Once it left adb, our old process is awaited
    (it may still be saving its snapshot); its post-stop hooks finish
    before the new launch's pre-launch hooks (via :func:`launch_avd`).

    Args:
        serial: The emulator to restart.
        options: Launch options of the relaunch (see above).
        adb: adb interface (default: the global ``Adb``).
        exit_timeout: Seconds to wait for the old process to exit and its
            port to be free after it left adb (default
            :data:`RESTART_EXIT_WAIT`, or :data:`RESTART_EXIT_WAIT_SAVING`
            when the old launch saves its state on exit).

    Raises:
        EmulatorLaunchError: Not an emulator, AVD unknown, it did not stop,
            its port stayed busy, our old process did not exit, or the
            relaunch failed.
    """
    port = serial_port(serial)
    if port is None:
        raise EmulatorLaunchError(f"{serial} is not an emulator")
    adb = _adb(adb)
    avd = avd_name_of(serial, adb)
    if not avd:
        raise EmulatorLaunchError(f"Could not determine the AVD of {serial}")
    old = get_launch(serial)
    if options is None:
        options = old.options if old is not None else remembered_options(avd)
    if options.wipe_once:
        options = replace(options, wipe_once=False)
    if not stop_emulator(serial, adb):
        raise EmulatorLaunchError(f"Emulator {serial} did not stop")
    # Bindable ignores TIME_WAIT (see _port_bindable): this only waits for
    # the old emulator to really let go of its ports -- and for our old
    # process to exit, so its post-stop hooks run before the relaunch's
    # pre-launch hooks (launch_avd refuses an AVD still shutting down).
    saving = (old.options if old is not None else options).save_on_exit
    if exit_timeout is None:
        exit_timeout = RESTART_EXIT_WAIT_SAVING if saving else RESTART_EXIT_WAIT
    deadline = time.monotonic() + exit_timeout
    while not _ports_free(port) or (old is not None and old.alive):
        if time.monotonic() >= deadline:
            if old is not None and old.alive:
                pid = getattr(old.process, "pid", "?")
                raise EmulatorLaunchError(
                    f"Emulator {serial} left adb but its process (PID {pid}) "
                    f"has not exited after {exit_timeout:g}s"
                    + (" -- it may still be saving its snapshot" if saving else "")
                    + "; start the AVD again once it has exited (or end that "
                    "process)"
                )
            raise EmulatorLaunchError(
                f"Console port {port} is still in use {exit_timeout:g}s after "
                f"{serial} stopped; start the AVD again once it is free"
            )
        time.sleep(0.5)
    return launch_avd(avd, options, port=port, adb=adb)


def _find_running_avd(avd: str, adb: Any) -> str | None:
    """Serial of the listed emulator running AVD *avd* (it is known to run).

    Asks as few emulators as possible -- in a shared lab the others belong
    to other sessions: our own launch (no adb call), then the pinned serial,
    then the serial of the AVD's last port. Only when none of those runs it
    are the remaining online emulators asked (logged).
    """
    with _LAUNCH_LOCK:
        ours = next((x for x in _LAUNCHES.values() if x.avd == avd and x.alive), None)
    if ours is not None:
        return ours.serial
    entries = _list_entries(adb) or []
    listed = {e.serial: e.state for e in entries if serial_port(e.serial)}
    candidates: list[str] = []
    pinned = pinned_serial()
    last = remembered_port(avd)
    for serial in (pinned, f"emulator-{last}" if last else None):
        if serial and serial in listed and serial not in candidates:
            candidates.append(serial)
    for serial in candidates:
        if avd_name_of(serial, adb) == avd:
            return serial
    others = [
        serial
        for serial, state in listed.items()
        if serial not in candidates and state == "device"
    ]
    if others:
        logger.info(
            f"AVD '{avd}' runs, but not as the pinned / last-used serial; "
            f"asking the other emulators: {', '.join(others)}"
        )
    for serial in others:
        if avd_name_of(serial, adb) == avd:
            return serial
    return None


def ensure_avd_running(
    avd: str,
    *,
    timeout: float = DEFAULT_BOOT_TIMEOUT,
    on_progress: Callable[[BootState, float], None] | None = None,
    options: AvdLaunchOptions | None = None,
    adb: Any = None,
) -> str:
    """Serial of a ready emulator running AVD *avd*, starting it if needed.

    Whether the AVD runs at all is decided without asking any emulator: our
    live launch, or emulator lock files in its directory
    (:func:`avd_lock_files`). Not running -> it is launched with *options*
    (default: the remembered options), which are remembered, and the boot
    is awaited. Running -> its serial is found by :func:`_find_running_avd`
    (our launch, the pinned serial, the AVD's last port; other sessions'
    emulators only as a last resort) and awaited; no pre-launch hook runs
    for a running AVD.

    Raises:
        EmulatorLaunchError: The launch failed, it did not boot in time, or
            the AVD runs but no listed online emulator reports it.
    """
    adb = _adb(adb)
    with _LAUNCH_LOCK:
        ours = any(x.avd == avd and x.alive for x in _LAUNCHES.values())
    locks = [] if ours else avd_lock_files(avd)
    if ours or locks:
        serial = _find_running_avd(avd, adb)
        if serial is None:
            names = ", ".join(path.name for path in locks)
            raise EmulatorLaunchError(
                f"AVD '{avd}' is already running ({names}), but no online "
                "emulator adb lists reports it (another adb server, or it is "
                "still starting); stop it or try again"
            )
        if wait_until_ready(serial, timeout, on_progress, adb=adb):
            return serial
        raise EmulatorLaunchError(
            f"Emulator {serial} ({avd}) did not become ready within {timeout:g}s"
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
        {"headless": bool, "boot": str, "snapshot": str | None,
        "save_on_exit": bool, "port": int}}}`` (``port``: the console port
        of its last launch); the empty document when the file is
        missing or unreadable. Older files (``boot: "wipe"``, no
        ``save_on_exit``) are read by :func:`options_from_prefs`.
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
    """Launch options remembered for AVD *name* in *prefs* (never a wipe).

    Args:
        prefs: A document as returned by :func:`load_launch_prefs`.
        name: AVD name.

    Returns:
        The remembered options; for an AVD launched never before: normal
        boot, no state saved on exit, headless per config
        ``emulator.avd_headless``. An old ``boot: "wipe"`` reads as a normal
        boot, a missing ``save_on_exit`` as False.
    """
    entry = (prefs.get("avds") or {}).get(name)
    if not isinstance(entry, dict) or not set(entry) - {"port"}:
        # No options remembered (at most the port of a launch is known).
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
        save_on_exit=entry.get("save_on_exit") is True,
    )


def remembered_options(name: str) -> AvdLaunchOptions:
    """Launch options last used for AVD *name* (never a wipe).

    First launch: normal boot, headless per config ``emulator.avd_headless``.
    """
    return options_from_prefs(load_launch_prefs(), name)


def remember_launch(
    name: str, opts: AvdLaunchOptions, *, make_last: bool = True
) -> None:
    """Persist *opts* for AVD *name* and make it the last-used AVD.

    ``wipe_once`` is never stored: a factory reset is never repeated by
    accident. Write errors are logged, not raised.

    Args:
        name: AVD name.
        opts: The options to remember.
        make_last: Also make *name* the last-used AVD (False when only an
            option is changed in the Devices screen).
    """
    boot = opts.boot
    snapshot = opts.snapshot if boot == "snapshot" else None
    if boot == "snapshot" and not snapshot:
        boot = "normal"
    with _PREFS_LOCK:
        prefs = load_launch_prefs()
        if make_last:
            prefs["last_avd"] = name
        entry = {
            "headless": bool(opts.headless),
            "boot": boot,
            "snapshot": snapshot,
            "save_on_exit": bool(opts.save_on_exit),
        }
        port = prefs["avds"].get(name, {}).get("port")
        if port is not None:
            entry["port"] = port
        prefs["avds"][name] = entry
        _save_prefs(prefs)


def _remember_port(name: str, port: int) -> None:
    """Persist the console port AVD *name* was just launched on.

    :func:`preferred_console_port` offers it again next time, so an AVD
    keeps its serial across launches. Its options stay as they are.
    """
    with _PREFS_LOCK:
        prefs = load_launch_prefs()
        entry = prefs["avds"].setdefault(name, {})
        if entry.get("port") == port:
            return
        entry["port"] = port
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
    "LaunchContext",
    "PostStopHook",
    "PreLaunchHook",
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
    "pinned_serial",
    "preferred_console_port",
    "reap_exited_launches",
    "register_post_stop_hook",
    "register_pre_launch_hook",
    "remember_launch",
    "remembered_options",
    "remembered_port",
    "rename_avd",
    "restart_emulator",
    "sdk_root",
    "serial_port",
    "spawn_emulator",
    "stop_emulator",
    "unregister_post_stop_hook",
    "unregister_pre_launch_hook",
    "wait_until_ready",
]
