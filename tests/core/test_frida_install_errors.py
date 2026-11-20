"""describe_frida_install_error: AndroidFridaManager >= 2.0.6 install failures.

The exceptions are produced by AFM's own verification helpers (not hand-written
strings) so a wording change upstream shows up here instead of silently
degrading the user-facing message to the generic fallback.
"""

from __future__ import annotations

import pytest
import requests
from AndroidFridaManager import FridaServerDownloadError, FridaServerVerificationError
from AndroidFridaManager.server_download import (
    ServerAsset,
    enforce_digest,
    release_asset_sha256,
)

from sandroid.core.frida_manager import (
    AFM_ALLOW_UNVERIFIED_ENV,
    describe_frida_install_error,
)

NAME = "frida-server-17.26.3-android-arm64.xz"


def _verification_error(sha256, reason=None) -> FridaServerVerificationError:
    asset = ServerAsset(NAME, "https://example.invalid/" + NAME, sha256, reason)
    with pytest.raises(FridaServerVerificationError) as info:
        enforce_digest(asset, "b" * 64, allow_unverified=False)
    return info.value


def test_env_var_name_matches_afm():
    from AndroidFridaManager.server_download import ALLOW_UNVERIFIED_ENV

    assert AFM_ALLOW_UNVERIFIED_ENV == ALLOW_UNVERIFIED_ENV


def test_digest_mismatch_never_suggests_the_override():
    msg = describe_frida_install_error(_verification_error("a" * 64))
    assert "SHA-256" in msg
    assert "nothing was installed" in msg
    assert AFM_ALLOW_UNVERIFIED_ENV not in msg


def test_rate_limited_metadata_lookup():
    exc = _verification_error(
        None,
        "release metadata unavailable (403 Client Error: rate limit exceeded "
        "for url: https://api.github.com/repos/frida/frida/releases/tags/17.26.3)",
    )
    msg = describe_frida_install_error(exc)
    assert "rate limit" in msg
    assert "try again later" in msg
    assert AFM_ALLOW_UNVERIFIED_ENV in msg


def test_offline_metadata_lookup():
    exc = _verification_error(
        None, "release metadata unavailable (Max retries exceeded, NameResolution)"
    )
    msg = describe_frida_install_error(exc)
    assert "could not be reached" in msg
    assert "rate limit" not in msg


def test_release_without_digest():
    exc = _verification_error(None, "GitHub publishes no sha256 digest for this asset")
    msg = describe_frida_install_error(exc)
    assert "no digest" in msg
    assert AFM_ALLOW_UNVERIFIED_ENV in msg


@pytest.mark.parametrize(
    "exc",
    [
        requests.ConnectionError("HTTPSConnectionPool(host='github.com'): boom"),
        requests.Timeout("read timed out"),
    ],
)
def test_offline_download(exc):
    msg = describe_frida_install_error(exc)
    assert "unreachable" in msg
    assert "HTTPSConnectionPool" not in msg


def test_offline_latest_lookup_is_unwrapped():
    # version="latest": AFM raises FridaServerDownloadError(...) from the
    # requests error (seen live with an unreachable proxy).
    try:
        try:
            raise requests.ConnectionError("HTTPSConnectionPool(...): ProxyError")
        except requests.ConnectionError as inner:
            raise FridaServerDownloadError(
                "Failed to fetch Frida release information: " + str(inner)
            ) from inner
    except FridaServerDownloadError as exc:
        msg = describe_frida_install_error(exc)
    assert "unreachable" in msg
    assert "HTTPSConnectionPool" not in msg


def test_rate_limited_latest_lookup():
    exc = FridaServerDownloadError(
        "Failed to fetch Frida release information: 403 Client Error: "
        "rate limit exceeded for url: https://api.github.com/..."
    )
    assert "rate limit" in describe_frida_install_error(exc)


def test_missing_asset_is_a_download_error():
    with pytest.raises(FridaServerDownloadError) as info:
        release_asset_sha256({"tag_name": "17.26.3", "assets": []}, NAME)
    msg = describe_frida_install_error(info.value)
    assert msg.startswith("Could not download frida-server:")
    assert NAME in msg


class _FM:
    def __init__(self, installed):
        self.installed = installed
        self.calls = []

    def get_installed_server_version(self):
        return self.installed

    def install_frida_server(self):
        self.calls.append("install")

    def run_frida_server(self):
        self.calls.append("run")
        return True


def test_ensure_started_skips_download_when_versions_match():
    import frida

    from sandroid.core.frida_manager import ensure_frida_server_started

    fm = _FM(frida.__version__)
    assert ensure_frida_server_started(fm) is True
    assert fm.calls == ["run"]


@pytest.mark.parametrize("installed", [None, "16.0.0"])
def test_ensure_started_installs_missing_or_mismatched_server(installed):
    from sandroid.core.frida_manager import ensure_frida_server_started

    fm = _FM(installed)
    assert ensure_frida_server_started(fm) is True
    assert fm.calls == ["install", "run"]


def test_auto_start_reads_config(monkeypatch):
    import types

    from sandroid.core import frida_manager

    cfg = types.SimpleNamespace(frida=types.SimpleNamespace(server_auto_start=False))
    monkeypatch.setattr(frida_manager, "get_config", lambda: cfg)
    assert frida_manager.frida_server_auto_start_enabled() is False
    cfg.frida.server_auto_start = True
    assert frida_manager.frida_server_auto_start_enabled() is True


def test_unrelated_errors_pass_through():
    exc = RuntimeError("Cannot install frida-server: device not rooted")
    assert describe_frida_install_error(exc) == str(exc)
    assert describe_frida_install_error(KeyError()) == "KeyError"


# --- frida.server_auto_start honoured at startup / headless; helper cleanup ---


class _Adb:
    def __init__(self, removed="3"):
        self.cmds = []
        self.removed = removed

    def root_shell(self, cmd, timeout=5):
        import types

        self.cmds.append(cmd)
        return types.SimpleNamespace(stdout=f"{self.removed}\n", stderr="")


class _ServerFM:
    def __init__(self, running=False, rooted=True, starts=True, version=None):
        import frida

        self.running = running
        self.is_device_rooted = rooted
        self.starts = starts
        self.version = version or frida.__version__
        self.adb = _Adb()
        self.frida_install_dst = "/data/local/tmp/"
        self.calls = []

    def is_frida_server_running(self):
        return self.running

    def get_installed_server_version(self):
        return self.version

    def install_frida_server(self):
        self.calls.append("install")

    def run_frida_server(self):
        self.calls.append("run")
        self.running = self.starts
        return self.starts


def _auto(monkeypatch, enabled=True):
    from sandroid.core import frida_manager

    monkeypatch.setattr(
        frida_manager, "frida_server_auto_start_enabled", lambda: enabled
    )
    return frida_manager


def test_auto_start_starts_server_and_cleans_helpers(monkeypatch):
    fm_mod = _auto(monkeypatch)
    fm = _ServerFM()
    assert fm_mod.auto_start_frida_server(fm) == (True, "frida-server started")
    assert fm.calls == ["run"]  # versions match: no download
    assert any("frida-helper-*.dex" in c and "rm -f" in c for c in fm.adb.cmds)


def test_auto_start_reports_reasons(monkeypatch):
    fm_mod = _auto(monkeypatch)
    ok, reason = fm_mod.auto_start_frida_server(_ServerFM(rooted=False))
    assert not ok
    assert "not rooted" in reason
    ok, reason = fm_mod.auto_start_frida_server(_ServerFM(starts=False))
    assert not ok
    assert "did not become ready" in reason

    fm_mod = _auto(monkeypatch, enabled=False)
    fm = _ServerFM()
    ok, reason = fm_mod.auto_start_frida_server(fm)
    assert not ok
    assert "disabled" in reason
    assert fm.calls == []
    # A running server is reported as running even with auto-start off.
    assert fm_mod.auto_start_frida_server(_ServerFM(running=True))[0] is True


def test_helper_cleanup_skipped_while_server_runs():
    from sandroid.core.frida_manager import cleanup_stale_frida_helpers

    fm = _ServerFM(running=True)
    assert cleanup_stale_frida_helpers(fm) == 0
    assert fm.adb.cmds == []
    fm = _ServerFM()
    assert cleanup_stale_frida_helpers(fm) == 3


def test_headless_ensure_frida_server_prints_reason(monkeypatch):
    from sandroid.core import frida_manager, initializer

    printed = []
    console = type("C", (), {"print": lambda self, m: printed.append(m)})()
    monkeypatch.setattr(
        frida_manager,
        "auto_start_frida_server",
        lambda: (False, "device is not rooted"),
    )
    monkeypatch.setattr(frida_manager, "frida_server_auto_start_enabled", lambda: True)
    assert initializer.ensure_frida_server(console) is False
    assert "device is not rooted" in printed[-1]
    monkeypatch.setattr(
        frida_manager, "auto_start_frida_server", lambda: (True, "frida-server started")
    )
    assert initializer.ensure_frida_server(console) is True


# --- Phase 5 N4: frida-server older than system_server (Zygote restart) ---


def _stat_line(pid: int, start_ticks: int) -> str:
    # /proc/<pid>/stat: "pid (comm) state ppid ..." -- field 22 is starttime.
    rest = ["S"] + ["0"] * 18 + [str(start_ticks)] + ["0"] * 10
    return f"{pid} (name with space) " + " ".join(rest) + "\n"


class _ProcAdb:
    def __init__(self, frida_start: int, system_start: int):
        self.cmds = []
        self.ticks = {"700": frida_start, "500": system_start}

    def root_shell(self, cmd, timeout=5):
        import types

        self.cmds.append(cmd)
        if cmd.startswith("ps -A"):
            out = (
                "  PID NAME\n"
                "  500 system_server\n"
                "  700 frida-server-17.2.0-android-arm64\n"
            )
        elif cmd.startswith("cat /proc/"):
            pid = cmd.split("/")[2]
            out = _stat_line(int(pid), self.ticks[pid])
        else:
            out = "0\n"
        return types.SimpleNamespace(stdout=out, stderr="")


class _RestartableFM(_ServerFM):
    def __init__(self, frida_start: int, system_start: int):
        super().__init__(running=True)
        self.adb = _ProcAdb(frida_start, system_start)

    def restart_frida_server_and_wait(self):
        self.calls.append("restart")
        return True


def test_stale_frida_server_is_detected_and_restarted_at_startup(monkeypatch):
    fm_mod = _auto(monkeypatch)
    resets = []
    monkeypatch.setattr(fm_mod, "reset_frida_handles", lambda: resets.append(1))

    fresh = _RestartableFM(frida_start=9000, system_start=5000)
    assert fm_mod.frida_server_is_stale(fresh) is False
    assert fm_mod.auto_start_frida_server(fresh) == (
        True,
        "frida-server already running",
    )
    assert fresh.calls == []

    stale = _RestartableFM(frida_start=5000, system_start=9000)
    assert fm_mod.frida_server_is_stale(stale) is True
    ok, reason = fm_mod.auto_start_frida_server(stale)
    assert ok
    assert "restarted" in reason
    assert stale.calls == ["restart"]
    assert resets == [1]


def test_dead_post_ca_restart_helper_is_gone():
    """The post-CA frida restart moved into the identity/proxy restart window.

    ``restart_frida_server_after_system_restart`` (and its private
    ``_wait_for_system_server`` poll) had no caller left; stale servers are
    handled by ``auto_start_frida_server``'s start-time check instead.
    """
    from sandroid.core import frida_manager as fm_mod

    assert not hasattr(fm_mod, "restart_frida_server_after_system_restart")
    assert not hasattr(fm_mod, "_wait_for_system_server")


# -- M6: frida-server relaunch took two zygote PIDs ------------------------


def _decoded(command: str) -> str:
    import base64

    return base64.b64decode(command.split()[1]).decode()


def _zpid(tmp_path, pidof_out: str, stats: dict[int, str]) -> str:
    """Run the launcher's ZPID snippet in a local sh with a fake pidof/proc."""
    import subprocess

    from sandroid.core.frida_manager import ZYGOTE_PID_SNIPPET

    proc = tmp_path / "proc"
    proc.mkdir(exist_ok=True)
    for pid, stat in stats.items():
        (proc / str(pid)).mkdir()
        (proc / str(pid) / "stat").write_text(stat)
    script = (
        f"pidof() {{ [ \"$1\" = zygote64 ] && echo '{pidof_out}'; }}\n"
        + ZYGOTE_PID_SNIPPET.replace("/proc/", f"{proc}/")
        + 'echo "[$ZPID]"\n'
    )
    out = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    return out.stdout.strip()


ZYGOTE_STATS = {
    744: "744 (zygote64) S 1 744 0 0 -1 4210944",
    13955: "13955 (zygote64) t 744 744 0 0 -1 4210944",
}


@pytest.mark.parametrize("pidof_out", ["744 13955", "13955 744", "744"])
def test_zygote_pid_picks_the_init_child_not_a_forked_app(tmp_path, pidof_out):
    """E2E M6: ``pidof zygote64`` said "744 13955" (13955: an app zygote had
    forked but not yet specialized); "/proc/744 13955/environ" broke the
    launch. Only zygote's own PID (parent: init) may be used.
    """
    assert _zpid(tmp_path, pidof_out, ZYGOTE_STATS) == "[744]"


def test_zygote_pid_falls_back_to_the_first_pid(tmp_path):
    # Unreadable /proc/<pid>/stat: still exactly one PID, never "a b".
    assert _zpid(tmp_path, "900 901", {}) == "[900]"
    assert _zpid(tmp_path, "", {}) == "[]"


def test_afm_launcher_is_patched_to_a_single_zygote_pid():
    from AndroidFridaManager import FridaManager as AfmFridaManager

    from sandroid.core.frida_manager import (
        ZYGOTE_PID_SNIPPET,
        fix_launcher_zygote_pid,
        install_zygote_pid_fix,
    )

    bin_path = "/data/local/tmp/frida-server"
    original = AfmFridaManager._build_frida_server_launcher
    fm = AfmFridaManager.__new__(AfmFridaManager)
    before = _decoded(original(fm, bin_path))
    assert "ZPID=$(pidof zygote64 || pidof zygote)\n" in before
    try:
        assert install_zygote_pid_fix()
        assert install_zygote_pid_fix()  # idempotent
        after = _decoded(fm._build_frida_server_launcher(bin_path))
    finally:
        AfmFridaManager._build_frida_server_launcher = original
        AfmFridaManager._sandroid_zygote_pid_fix = False
    assert ZYGOTE_PID_SNIPPET in after
    assert "ZPID=$(pidof" not in after
    # The rest of AFM's launcher is untouched.
    assert after.replace(ZYGOTE_PID_SNIPPET, "") == before.replace(
        "ZPID=$(pidof zygote64 || pidof zygote)\n", ""
    )
    # Unknown shapes pass through unchanged.
    assert fix_launcher_zygote_pid("frida-server &") == "frida-server &"


def test_frida_server_pid_parsing_never_matches_zygote():
    """The stop/kill path matches frida-server processes only."""
    from AndroidFridaManager import FridaManager as AfmFridaManager

    ps = (
        "  PID NAME\n"
        "  744 zygote64\n"
        "13955 zygote64\n"
        " 9117 org.mozilla.firefox\n"
        " 4321 /data/local/tmp/frida-server\n"
        " 4400 frida-server-17.27.0-android-arm64\n"
    )
    assert AfmFridaManager._parse_frida_server_pids(ps) == [4321, 4400]
