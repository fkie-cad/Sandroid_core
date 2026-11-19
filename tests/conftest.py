"""Suite-wide test isolation for Sandroid.

The test suite must never act on a real Android device, emulator or host
process, even when a developer runs ``pytest`` with an emulator attached.
Several code paths reachable from tests (mounting the full TUI
``MainScreen``, building the AI ambient-context block, ...) shell out to
``adb`` -- e.g. ``adb shell su -c pkill -f /data/local/tmp/gost`` or
``iptables`` cleanup -- which would silently modify a connected device.

This conftest therefore installs, for every test:

* **A subprocess guard.** ``subprocess.Popen.__init__`` is wrapped (this also
  covers ``subprocess.run``/``check_output``/``call``, ``os.popen`` and
  ``asyncio.create_subprocess_*``). Any invocation of a device/host-control
  tool (``adb``, ``emulator``, ``frida*``, ``objection``, ``mitmdump``,
  ``pkill`` ...) is *recorded* and replaced by a harmless process that exits
  with status 1 and prints nothing -- the same behaviour as a missing/broken
  ``adb``, so code under test takes its normal error path. Tests that mock
  ``subprocess.run``/``Popen`` themselves are unaffected (their mock replaces
  the guarded callable).
* **A frida guard.** ``frida.get_usb_device``/``get_device``/... raise
  ``frida.InvalidOperationError`` instead of talking to the adb server.
* **A socket guard.** Connections to the adb server (5037), emulator
  console/adb ports (5554-5685) and frida-server (27042/27043) on the local
  host are refused.

Every blocked call is listed in the terminal summary. Set
``SANDROID_TESTS_STRICT_DEVICE=1`` to turn any blocked call into a test error
(useful to hunt down tests that forget to mock the device layer), and
``SANDROID_TESTS_BLOCKED_LOG=<file>`` to append blocked calls to a file.

Tests marked ``@pytest.mark.requires_device`` are skipped unless pytest is run
with ``--allow-device``; only those tests run without the guards.

Additionally the whole session runs with ``HOME``/XDG dirs pointing to a
temporary directory, ``ANDROID_HOME``/``ANDROID_SDK_ROOT`` pointing to a
nonexistent path, any ``SANDROID_*`` / AI-key environment variables removed,
and the working directory set to a temporary directory, so tests neither read
the developer's ``~/.config/sandroid`` nor leave ``./results`` behind.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

#: Executables (basename, case-insensitive, ``.exe`` stripped) that must never
#: really run from the test suite.
_BLOCKED_EXECUTABLES = frozenset(
    {
        "adb",
        "emulator",
        "emulator-headless",
        "avdmanager",
        "sdkmanager",
        "objection",
        "fritap",
        "mitmdump",
        "mitmweb",
        "mitmproxy",
        "pkill",
        "killall",
        "iptables",
        "ip6tables",
        "gost",
        "ipt2socks",
    }
)
_BLOCKED_PREFIXES = ("frida", "qemu-system")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"})

#: (port) -> reason; only enforced for loopback / unspecified hosts.
_BLOCKED_PORTS = {5037: "adb server", 27042: "frida-server", 27043: "frida-server"}
_BLOCKED_PORT_RANGE = range(5554, 5686)  # emulator console + adb ports
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "", "::"})

_FRIDA_DEVICE_FUNCS = (
    "get_usb_device",
    "get_remote_device",
    "get_local_device",
    "get_device",
    "get_device_matching",
    "get_device_manager",
    "enumerate_devices",
    "attach",
    "spawn",
    "resume",
    "kill",
)

# Environment variables that would leak the developer's setup into tests.
_ENV_DROP_RE = re.compile(
    r"^(SANDROID_.*|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|"
    r"GOOGLE_API_KEY|ANDROID_SERIAL|ANDROID_AVD_HOME|ANDROID_EMULATOR_HOME|"
    r"ANDROID_ADB_SERVER_PORT|ADB_SERVER_SOCKET)$"
)

_STRICT = os.environ.get("SANDROID_TESTS_STRICT_DEVICE", "") not in ("", "0")
_BLOCKED_LOG = os.environ.get("SANDROID_TESTS_BLOCKED_LOG")

#: All blocked calls of the session: (nodeid, kind, detail)
_blocked: list[tuple[str, str, str]] = []

_ORIG_POPEN_INIT = subprocess.Popen.__init__
_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex

_saved_env: dict[str, str | None] = {}
_saved_cwd: str | None = None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _is_blocked_name(token: str) -> bool:
    name = Path(str(token).strip("\"'")).name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name in _BLOCKED_EXECUTABLES or name.startswith(_BLOCKED_PREFIXES)


def _split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def _shell_command_is_blocked(command: str) -> bool:
    # Any token may start a command (``foo && adb ...``, ``x | pkill ...``),
    # so check every token's basename. False positives only make a host
    # command exit 1, which is harmless for the suite.
    return any(_is_blocked_name(tok) for tok in _split(command))


def _argv_is_blocked(args, executable, shell: bool) -> bool:
    if executable and _is_blocked_name(os.fspath(executable)):
        return True
    if isinstance(args, (str, bytes, os.PathLike)):
        cmd = os.fsdecode(args) if not isinstance(args, str) else args
        return _shell_command_is_blocked(cmd) if shell else _is_blocked_name(cmd)
    argv = [os.fsdecode(a) if not isinstance(a, str) else a for a in args]
    if not argv:
        return False
    if shell:
        return _shell_command_is_blocked(" ".join(argv))
    if _is_blocked_name(argv[0]):
        return True
    # ``sh -c "adb ..."`` style wrappers
    if Path(argv[0]).name.lower().removesuffix(".exe") in _SHELLS:
        return any(_shell_command_is_blocked(a) for a in argv[1:])
    return False


def _current_test() -> str:
    return os.environ.get("PYTEST_CURRENT_TEST", "<no test>").rsplit(" ", 1)[0]


def _record(kind: str, detail: str) -> None:
    entry = (_current_test(), kind, detail)
    _blocked.append(entry)
    if _BLOCKED_LOG:
        try:
            with open(_BLOCKED_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"[{entry[0]}] {kind}: {detail}\n")
        except OSError:
            pass


def _describe(args) -> str:
    if isinstance(args, (str, bytes, os.PathLike)):
        return os.fsdecode(args) if not isinstance(args, str) else args
    return " ".join(os.fsdecode(a) if not isinstance(a, str) else a for a in args)


# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------


def _guarded_popen_init(self, args, *pargs, **kwargs):
    shell = bool(kwargs.get("shell", False))
    if _argv_is_blocked(args, kwargs.get("executable"), shell):
        _record("subprocess", _describe(args)[:300])
        kwargs["executable"] = None
        args = "exit 1" if shell else [sys.executable, "-c", "raise SystemExit(1)"]
        if shell and os.name == "nt":
            args = "exit /b 1"
    return _ORIG_POPEN_INIT(self, args, *pargs, **kwargs)


def _blocked_address(address) -> str | None:
    if not isinstance(address, tuple) or len(address) < 2:
        return None
    host, port = str(address[0]).lower(), address[1]
    if host not in _LOCAL_HOSTS and not host.startswith("127."):
        return None
    if port in _BLOCKED_PORTS:
        return _BLOCKED_PORTS[port]
    if port in _BLOCKED_PORT_RANGE:
        return "emulator console/adb"
    return None


def _guarded_connect(self, address):
    reason = _blocked_address(address)
    if reason:
        _record("socket", f"connect {address!r} ({reason})")
        raise ConnectionRefusedError(f"blocked by tests/conftest.py: {reason}")
    return _ORIG_CONNECT(self, address)


def _guarded_connect_ex(self, address):
    reason = _blocked_address(address)
    if reason:
        _record("socket", f"connect_ex {address!r} ({reason})")
        return 111  # ECONNREFUSED
    return _ORIG_CONNECT_EX(self, address)


def _make_frida_blocker(frida_mod, name):
    def _blocked_frida_call(*args, **kwargs):
        _record("frida", f"frida.{name}{args!r}")
        raise frida_mod.InvalidOperationError(
            f"frida.{name}() blocked by tests/conftest.py (no device in tests)"
        )

    return _blocked_frida_call


# --------------------------------------------------------------------------
# pytest hooks / fixtures
# --------------------------------------------------------------------------


def pytest_addoption(parser):
    parser.addoption(
        "--allow-device",
        action="store_true",
        default=False,
        help="Run tests marked requires_device against a real device "
        "(those tests run without the device guard).",
    )


def pytest_configure(config):
    """Isolate HOME/XDG/Android SDK env before any test module is imported."""
    global _saved_cwd
    base = Path(tempfile.mkdtemp(prefix="sandroid-tests-"))
    home = base / "home"
    home.mkdir()
    (base / "cwd").mkdir()
    overrides = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "ANDROID_HOME": str(base / "no-android-sdk"),
        "ANDROID_SDK_ROOT": str(base / "no-android-sdk"),
    }
    for key in [k for k in os.environ if _ENV_DROP_RE.match(k)]:
        _saved_env.setdefault(key, os.environ.pop(key))
    for key, value in overrides.items():
        _saved_env.setdefault(key, os.environ.get(key))
        os.environ[key] = value
    config._sandroid_test_base = base  # type: ignore[attr-defined]
    global _real_tl
    from sandroid.core import timeline

    _real_tl = timeline


def pytest_unconfigure(config):
    for key, value in _saved_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _saved_env.clear()


@pytest.fixture(scope="session", autouse=True)
def _sandroid_tmp_cwd(request):
    """Run the session from a scratch directory (``./results`` etc. land there)."""
    base = getattr(request.config, "_sandroid_test_base", None)
    if base is None:  # pragma: no cover - configure hook always runs
        yield
        return
    old = os.getcwd()
    os.chdir(base / "cwd")
    try:
        yield base / "cwd"
    finally:
        os.chdir(old)


class _NoDeviceShell:
    """``device_clock.SHELL_FACTORY`` for the suite: there is no device."""

    def __init__(self, serial):
        from sandroid.core.device_clock import ShellDeadError

        raise ShellDeadError("no device in tests")


@pytest.fixture(scope="session", autouse=True)
def _no_device_clock():
    """Device clock samples (``core/device_clock.py``) run on background
    threads (device connect, the header's 60 s sample) that can outlive the
    test that started them and run adb inside a later test's subprocess
    mock. For the whole session they find no device; tests that need a
    clock install a fake shell with ``monkeypatch`` (restored to this).
    """
    from sandroid.core import device_clock

    saved = device_clock.SHELL_FACTORY, device_clock._default_send
    device_clock.SHELL_FACTORY = _NoDeviceShell
    device_clock._default_send = lambda serial: lambda command: ("", "")
    yield
    device_clock.SHELL_FACTORY, device_clock._default_send = saved


@pytest.fixture(autouse=True)
def _isolated_watchlist_dir(tmp_path, monkeypatch):
    """Give every test its own Files-lens watchlist + pulled-files directory.

    The watchlist lives in a stable per-user, per-device directory (it must
    survive restarts); tests point it at their own ``tmp_path`` instead --
    at ``spotlight_files/.watchlist`` below it, where it used to live under
    ``RESULTS_PATH``, so tests that look for ``index.json`` there still do.
    """
    monkeypatch.setenv(
        "SDROID_WATCHLIST_DIR", str(tmp_path / "spotlight_files" / ".watchlist")
    )
    # Pulled versions go to <session results>/files; keep them per test too.
    monkeypatch.setenv("SDROID_FILES_DIR", str(tmp_path / "session" / "files"))


#: The real session-timeline module, captured once in ``pytest_configure``
#: (importing sandroid any earlier would read the real HOME): WP2/WP5 tests
#: may install fakes in ``sys.modules`` for a while; the reset always hits
#: this module object, never a ``sys.modules`` lookup.
_real_tl: Any = None


@pytest.fixture(autouse=True)
def _reset_timeline():
    """Close and drop the session-timeline singleton after every test."""
    yield
    _real_tl.reset_for_tests()


@pytest.fixture
def timeline_sink(tmp_path):
    """A bound session timeline: ``(service, path of timeline.jsonl)``.

    ``"emulator-test"`` writes to ``tmp_path/session/dev`` (``files_root()``
    is ``tmp_path/session/files``, so :func:`timeline_folder` is
    ``tmp_path/session``).
    """
    service = _real_tl.get_timeline()
    folder = tmp_path / "session" / "dev"
    status = service.bind("emulator-test", folder)
    assert status.state == "open", status
    return service, folder / _real_tl.FILE_NAME


def pytest_collection_modifyitems(config, items):
    if config.getoption("--allow-device"):
        return
    skip = pytest.mark.skip(reason="requires a real device (run with --allow-device)")
    for item in items:
        if "requires_device" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _block_device_access(request, monkeypatch):
    """Prevent every test from reaching a real device, emulator or frida."""
    if request.config.getoption("--allow-device") and (
        "requires_device" in request.keywords
    ):
        yield
        return

    monkeypatch.setattr(subprocess.Popen, "__init__", _guarded_popen_init)
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    frida_mod = sys.modules.get("frida")
    if frida_mod is None:
        try:
            import frida as frida_mod
        except Exception:  # frida missing or broken: nothing to guard
            frida_mod = None
    if frida_mod is not None:
        for name in _FRIDA_DEVICE_FUNCS:
            if hasattr(frida_mod, name):
                monkeypatch.setattr(
                    frida_mod, name, _make_frida_blocker(frida_mod, name)
                )
    # The emulator memory guard watches real qemu processes on the host;
    # never start it from tests (tests/core/test_emulator_guard.py drives
    # EmulatorMemoryGuard.check_once directly).
    try:
        from sandroid.core import emulator_guard
    except Exception:
        emulator_guard = None
    if emulator_guard is not None:
        monkeypatch.setattr(emulator_guard, "start_memory_guard", lambda config: None)
    # On hosts without adb (CI runners) ``Adb.init`` calls ``exit(1)`` the
    # first time a widget asks the device anything. Give it a placeholder
    # path: the Popen guard above blocks every ``adb`` call anyway, so code
    # under test takes its normal "command failed" path.
    try:
        from sandroid.core.adb import Adb
    except Exception:
        Adb = None
    if Adb is not None and not Adb.ADB_PATH:
        monkeypatch.setattr(Adb, "ADB_PATH", "adb")

    start = len(_blocked)
    yield
    if _STRICT and len(_blocked) > start:
        calls = "\n  ".join(f"{k}: {d}" for _, k, d in _blocked[start:])
        pytest.fail(
            "test attempted real device access (SANDROID_TESTS_STRICT_DEVICE=1):"
            f"\n  {calls}",
            pytrace=False,
        )


def pytest_terminal_summary(terminalreporter):
    if not _blocked:
        terminalreporter.write_line(
            "sandroid device guard: no device/host-tool access attempted"
        )
        return
    tests = {nodeid for nodeid, _, _ in _blocked}
    terminalreporter.section("sandroid device guard")
    terminalreporter.write_line(
        f"blocked {len(_blocked)} device/host-tool call(s) from {len(tests)} "
        "test(s); none reached a real device. Mock the device layer in these "
        "tests (SANDROID_TESTS_STRICT_DEVICE=1 turns this into errors):"
    )
    for nodeid in sorted(tests):
        n = sum(1 for t, _, _ in _blocked if t == nodeid)
        terminalreporter.write_line(f"  {n:4d}  {nodeid}")
