"""Unit tests for ``KprobeTracer`` (the kernel-tracefs kprobe monitor backend).

No device/adb/network involved: ``Adb.send_adb_command`` (every device shell
round-trip) and ``KprobeTracer._start_process`` (the streaming ``cat
trace_pipe`` Popen) are monkeypatched. Covers:

* ``kprobe_supported()`` -> False on each failure signature (no root / missing
  kallsyms symbol / bogus-symbol test-attach / offset-self-check mismatch) and
  True on success; per-serial memoization; no-memoize-on-inconclusive.
* Session setup command construction: idempotent self-clean BEFORE instance
  creation; probe-set install; per-mode filters (pid TID seeding + event-fork,
  path glob); the final streaming Popen is ``cat instances/sandroid_mon/
  trace_pipe``.
* Teardown order: the trace_pipe Popen is killed BEFORE the tracefs instance is
  removed (both at the wrapper level and inside ``KprobeTracer.teardown``).
"""

from __future__ import annotations

import subprocess
import threading
import time

import pytest

from sandroid.core.adb import Adb
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.tui.utils import MonitorProcessWrapper


@pytest.fixture(autouse=True)
def _clean_kprobe_state():
    """Guard KprobeTracer class-level state against cross-test leaks."""
    KprobeTracer._kprobe_cache.clear()
    KprobeTracer._tracefs = None
    KprobeTracer._orig_buffer_kb = None
    yield
    KprobeTracer._kprobe_cache.clear()
    KprobeTracer._tracefs = None
    KprobeTracer._orig_buffer_kb = None


@pytest.fixture(autouse=True)
def _clean_target_device():
    original = Adb._target_device
    yield
    Adb._target_device = original


# =============================================================================
# Scriptable fake Adb.send_adb_command
# =============================================================================


class _FakeShell:
    """Records every send_adb_command string and answers by substring rule.

    Rules are (predicate, (stdout, stderr)) tuples, checked in order; the first
    match wins. Defaults to ("", "").
    """

    def __init__(self, rules):
        self.commands: list[str] = []
        self._rules = rules

    def __call__(self, command: str):
        self.commands.append(command)
        for predicate, response in self._rules:
            if predicate(command):
                return response
        return ("", "")


def _install(monkeypatch, fake: _FakeShell) -> _FakeShell:
    monkeypatch.setattr(Adb, "send_adb_command", fake)
    return fake


# Reusable rule builders --------------------------------------------------

_SYMBOLS = KprobeTracer._REQUIRED_SYMBOLS


def _root_ok(cmd):
    return cmd == "root"


def _id_ok(cmd):
    return cmd == "shell id"


def _tracefs_probe(cmd):
    return "test -w" in cmd and "kprobe_events" in cmd


def _symbol_loop(cmd):
    return "for s in" in cmd and "/proc/kallsyms" in cmd


def _trace_read(cmd):
    # The check-instance snapshot read is ``cat .../trace`` -- now suffixed with
    # ``2>/dev/null`` to keep a failed read quiet, so match ``/trace'`` (bare) OR
    # ``/trace 2>`` (silenced). Still excludes ``/trace_pipe'`` and ``tracing_on``.
    return "cat " in cmd and ("/trace'" in cmd or "/trace 2>" in cmd)


def _make_success_fake(basename="sandroid_kpcheck", *, present_symbols=None):
    present = _SYMBOLS if present_symbols is None else present_symbols
    good_trace = (
        f"   sh-999   [000] ...1 1.1: kpck_dfo: (do_filp_open+0x0/0x1) "
        f'path="/data/local/tmp/{basename}"\n'
        f"   sh-999   [000] ...1 1.2: kpck_vw: (vfs_write+0x0/0x1) "
        f'name="{basename}"\n'
    )
    return _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root) gid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (_symbol_loop, ("\n".join(present), "")),
            (_trace_read, (good_trace, "")),
        ]
    )


# =============================================================================
# kprobe_supported() -- failure signatures + success
# =============================================================================


def test_kprobe_supported_true_on_full_success(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    _install(monkeypatch, _make_success_fake())
    assert KprobeTracer.kprobe_supported() is True
    assert KprobeTracer._kprobe_cache["emulator-5556"] is True


def test_kprobe_supported_false_when_no_root(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _FakeShell(
        [
            (_root_ok, ("adbd cannot run as root in production builds", "")),
            (_id_ok, ("uid=2000(shell)", "")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    # A real "can't grant root" verdict for this serial IS memoized.
    assert KprobeTracer._kprobe_cache["emulator-5556"] is False


def test_kprobe_supported_false_on_missing_symbol(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    # Drop one required symbol from the kallsyms loop output.
    partial = [s for s in _SYMBOLS if s != "do_renameat2"]
    _install(monkeypatch, _make_success_fake(present_symbols=partial))
    assert KprobeTracer.kprobe_supported() is False
    assert KprobeTracer._kprobe_cache["emulator-5556"] is False


def test_kprobe_supported_false_on_bogus_symbol_test_attach(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")

    def _install_probe(cmd):
        return "kpck" in cmd and ">>" in cmd

    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (_symbol_loop, ("\n".join(_SYMBOLS), "")),
            # The self-check probe install itself is rejected by trace_kprobe.
            (
                _install_probe,
                ("", "trace_kprobe: error: Invalid probed address or symbol"),
            ),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False


def test_kprobe_supported_false_on_offset_self_check_mismatch(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    # DEFINITIVE mismatch: the do_filp_open path canary (a KNOWN-GOOD offset)
    # fires and recovers the marker path -- proving the trigger + tracing +
    # snapshot read all worked -- but the dentry-offset name= is garbage (wrong
    # +0xb0/+0x28). That is a genuine wrong-offset verdict -> False AND memoized.
    bad_trace = (
        "   sh-999 [000] ...1 1.1: kpck_dfo: (do_filp_open+0x0/0x1) "
        'path="/data/local/tmp/sandroid_kpcheck"\n'
        '   sh-999 [000] ...1 1.2: kpck_vw: (vfs_write+0x0/0x1) name="\\xef\\xbf"\n'
    )
    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (_symbol_loop, ("\n".join(_SYMBOLS), "")),
            (_trace_read, (bad_trace, "")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    # A definitive wrong-offset verdict for this serial IS memoized.
    assert KprobeTracer._kprobe_cache["emulator-5556"] is False


def test_offset_self_check_disables_tracing_before_reading_trace(monkeypatch):
    """The fix: `cat .../trace` (the static snapshot) must be read only AFTER
    tracing_on is set back to 0. Reading it while tracing is on hangs on a live
    device (the no-filter check probe records the ambient write firehose so the
    snapshot never reaches EOF). Assert the issued command sequence disables
    tracing before the snapshot read -- and after the write trigger.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _install(monkeypatch, _make_success_fake())

    assert KprobeTracer.kprobe_supported() is True

    cmds = fake.commands
    inst = f"instances/{KprobeTracer._CHECK_INSTANCE}"
    # The snapshot read of the CHECK instance's `trace` (now suffixed 2>/dev/null).
    read_idx = next(
        i
        for i, c in enumerate(cmds)
        if "cat " in c and (f"{inst}/trace'" in c or f"{inst}/trace 2>" in c)
    )
    # The write trigger that must precede everything.
    trigger_idx = next(i for i, c in enumerate(cmds) if "echo sandroid_canary" in c)
    # The `echo 0 > .../tracing_on` that must sit between trigger and read. Both
    # this main-body disable and the post-read _cleanup one now carry
    # ``2>/dev/null``, so we identify it purely by position: the FIRST tracing-off
    # after the trigger is the main-body one (the up-front _cleanup runs before
    # the trigger; the other _cleanup runs after the read).
    tracing_off_idx = next(
        i
        for i, c in enumerate(cmds)
        if i > trigger_idx and "echo 0 >" in c and f"{inst}/tracing_on" in c
    )
    assert trigger_idx < tracing_off_idx < read_idx


def test_offset_self_check_writes_are_silenced(monkeypatch):
    """The eager preflight must be quiet: every check-instance write to
    filter/enable/tracing_on is guarded by ``[ -e path ] && echo ... 2>/dev/null``
    -- the SAME existence-guard idiom ``_cleanup``/``_self_clean``/``teardown``
    already use -- so a device that can't register the check probes (their
    ``events/kprobes/kpck_*`` dirs never appear under the instance) doesn't
    flood the activity log with ADB WARNINGs.

    A bare ``echo ... > missing/path 2>/dev/null`` does NOT suppress that
    failure: the shell's own redirect-open fails (ENOENT on the containing
    directory) BEFORE the trailing ``2>`` redirect is even set up, so the
    "can't create ... No such file or directory" diagnostic reaches the
    ORIGINAL stderr regardless -- this is the real, load-bearing fix (not
    just the ``2>/dev/null`` suffix, confirmed insufficient in isolation).
    The two probe-INSTALL lines keep their stderr (the bogus-symbol signature
    is read from it).
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _install(monkeypatch, _make_success_fake())
    assert KprobeTracer.kprobe_supported() is True

    inst = f"instances/{KprobeTracer._CHECK_INSTANCE}"
    filter_enable_tracing_writes = [
        c
        for c in fake.commands
        if inst in c
        and ("/filter" in c or "/enable" in c or "/tracing_on" in c)
        and "echo" in c
        and "-:kpck" not in c  # excludes the unrelated _cleanup probe-removal
    ]
    assert filter_enable_tracing_writes
    for c in filter_enable_tracing_writes:
        # Load-bearing: an existence guard on the SAME path being written,
        # not merely a trailing 2>/dev/null.
        assert "[ -e " in c, f"missing existence guard: {c}"
        assert "] && echo" in c, f"missing existence guard: {c}"
        assert "2>/dev/null" in c, f"missing secondary suppression: {c}"
    # The probe DEFINITION installs (echo "p:kpck_..." >> kprobe_events) must
    # NOT be silenced (the bogus-symbol signature is read from their stderr).
    # Matched by the literal probe-definition text, not just "kpck" + ">>" --
    # the (unrelated, pre-existing) cleanup's conditional probe-removal line
    # also contains both and legitimately carries its own "2>/dev/null" on the
    # `grep` redirect.
    installs = [
        c
        for c in fake.commands
        if ">>" in c and ("vfs_write name=" in c or "do_filp_open path=" in c)
    ]
    assert installs
    assert all("2>/dev/null" not in c for c in installs)


def test_kprobe_supported_inconclusive_self_check_not_memoized(monkeypatch):
    """An inconclusive self-check (empty/unreadable trace -- e.g. the snapshot
    read timed out or the trigger never landed, so NOT even the do_filp_open
    path canary recovered) returns False WITHOUT memoizing, so a later start
    re-checks once the device settles.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (_symbol_loop, ("\n".join(_SYMBOLS), "")),
            # No path canary and no name -> neither recovered -> inconclusive.
            (_trace_read, ("", "")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    assert "emulator-5556" not in KprobeTracer._kprobe_cache


def test_kprobe_supported_memoizes_per_serial(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _install(monkeypatch, _make_success_fake())

    assert KprobeTracer.kprobe_supported() is True
    n_after_first = len(fake.commands)
    # Second call served from cache -> no new device round-trips.
    assert KprobeTracer.kprobe_supported() is True
    assert len(fake.commands) == n_after_first


def test_kprobe_supported_serializes_concurrent_probes_for_same_serial(monkeypatch):
    """Two threads racing kprobe_supported() for the SAME unprobed serial must
    not both run the full device preflight concurrently (they'd collide on the
    SAME fixed on-device check-instance/probe names) -- the second thread
    should block on ``_probe_lock`` and then serve the first thread's memoized
    verdict instead of re-probing.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    monkeypatch.setattr(KprobeTracer, "_kprobe_cache", {})

    # Widen the race window: sleep briefly inside the symbol-loop step so a
    # second thread's call has time to reach (and block on) the lock while
    # the first is still mid-preflight.
    def _slow_symbol_loop(cmd):
        if _symbol_loop(cmd):
            time.sleep(0.05)
            return True
        return False

    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (
                _slow_symbol_loop,
                ("\n".join(KprobeTracer._REQUIRED_SYMBOLS), ""),
            ),
            (
                _trace_read,
                (
                    "   sh-999 [000] ...1 1.1: kpck_dfo: (do_filp_open+0x0/0x1) "
                    'path="/data/local/tmp/sandroid_kpcheck"\n'
                    "   sh-999 [000] ...1 1.2: kpck_vw: (vfs_write+0x0/0x1) "
                    'name="sandroid_kpcheck"\n',
                    "",
                ),
            ),
        ]
    )
    _install(monkeypatch, fake)

    results: list[bool] = []
    threads = [
        threading.Thread(target=lambda: results.append(KprobeTracer.kprobe_supported()))
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert results == [True, True]
    assert KprobeTracer._kprobe_cache["emulator-5556"] is True
    # Exactly one full preflight ran: the root-check command appears once,
    # not twice (the second thread's double-checked cache read short-circuits
    # before repeating any device round-trip).
    root_checks = [c for c in fake.commands if c == "root"]
    assert len(root_checks) == 1, (
        f"expected exactly one preflight run, got {len(root_checks)}: "
        f"{fake.commands}"
    )


def test_kprobe_supported_reprobes_for_a_different_serial(monkeypatch):
    fake = _install(monkeypatch, _make_success_fake())

    monkeypatch.setattr(Adb, "_target_device", "device-a")
    assert KprobeTracer.kprobe_supported() is True
    n_a = len(fake.commands)

    monkeypatch.setattr(Adb, "_target_device", "device-b")
    assert KprobeTracer.kprobe_supported() is True
    # A different serial re-probes rather than reusing device-a's cache.
    assert len(fake.commands) > n_a


def test_kprobe_supported_inconclusive_tracefs_not_memoized(monkeypatch):
    """Root OK but no writable tracefs reachable (could be transient adb) ->
    return False WITHOUT memoizing, so a later real probe re-checks.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            # test -w returns nothing for BOTH candidates -> tracefs None.
            (_tracefs_probe, ("", "")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    assert "emulator-5556" not in KprobeTracer._kprobe_cache


def test_kprobe_supported_transient_root_failure_not_memoized(monkeypatch):
    """Fix 4: a transient/timeout root failure (NOT the genuine "adbd cannot
    run as root" signal) is inconclusive -> return False WITHOUT memoizing, so
    a later start retries once adb recovers.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _FakeShell(
        [
            # `adb root` neither confirms nor denies (e.g. protocol fault), and
            # `shell id` doesn't show uid=0 -> inconclusive, must NOT memoize.
            (_root_ok, ("", "error: protocol fault")),
            (_id_ok, ("", "error: device offline")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    assert "emulator-5556" not in KprobeTracer._kprobe_cache


def test_kprobe_supported_root_exception_not_memoized(monkeypatch):
    """Fix 4: an exception during the root check (adb wedged) is inconclusive
    too -> False without memoizing.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")

    def _boom(command):
        raise RuntimeError("adb transport died")

    monkeypatch.setattr(Adb, "send_adb_command", _boom)
    assert KprobeTracer.kprobe_supported() is False
    assert "emulator-5556" not in KprobeTracer._kprobe_cache


# =============================================================================
# cached_availability() -- pure per-serial cache read, no probe/adb
# =============================================================================


def test_cached_availability_returns_cached_verdict_for_current_serial(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    KprobeTracer._kprobe_cache["emulator-5556"] = True
    assert KprobeTracer.cached_availability() is True

    KprobeTracer._kprobe_cache["emulator-5556"] = False
    assert KprobeTracer.cached_availability() is False


def test_cached_availability_none_when_serial_absent(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-9999")
    # Nothing memoized for this serial (even if another serial is cached).
    KprobeTracer._kprobe_cache["emulator-5556"] = True
    assert KprobeTracer.cached_availability() is None


def test_cached_availability_never_invokes_adb(monkeypatch):
    """It is a pure cache read -- it must not probe. Patch every adb entry point
    to raise and assert the read still succeeds (and returns the cached value).
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    KprobeTracer._kprobe_cache["emulator-5556"] = True

    def _boom(*args, **kwargs):
        raise AssertionError("cached_availability must not touch adb")

    monkeypatch.setattr(Adb, "send_adb_command", _boom)
    monkeypatch.setattr(KprobeTracer, "_root_status", classmethod(_boom))
    monkeypatch.setattr(KprobeTracer, "_resolve_tracefs", classmethod(_boom))

    assert KprobeTracer.cached_availability() is True


# =============================================================================
# Session setup -- command construction
# =============================================================================


def _capture_run(monkeypatch, *, extra_rules=None):
    """Wire a fake shell + capture the streaming Popen cmd for a run_* call."""
    sentinel = object()
    captured = {"stream_cmd": None}

    rules = list(extra_rules or [])
    # buffer_size_kb read (in _begin_session) returns the default to restore.

    def _buffer_read(cmd):
        return "cat " in cmd and "buffer_size_kb" in cmd

    def _task_list(cmd):
        return "ls /proc/" in cmd and "/task" in cmd

    rules.append((_buffer_read, ("7", "")))
    rules.append((_task_list, ("1234 1240 1241", "")))
    fake = _FakeShell(rules)
    monkeypatch.setattr(Adb, "send_adb_command", fake)

    def _fake_start(cls, cmd):
        captured["stream_cmd"] = cmd
        return sentinel

    monkeypatch.setattr(KprobeTracer, "_start_process", classmethod(_fake_start))
    # Pretend tracefs is already resolved so run_* doesn't probe for it.
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    return fake, captured, sentinel


def test_run_by_path_self_cleans_before_creating_instance(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, sentinel = _capture_run(monkeypatch)

    result = KprobeTracer.run_by_path("/data/data/com.example.app")
    assert result is sentinel

    cmds = fake.commands
    # Self-clean must precede instance creation: the self-clean rmdir of the
    # instance appears before the `mkdir -p` that (re)creates it. Match the
    # instance rmdir precisely -- "rmdir" is also a probe name, so a bare
    # "rmdir" substring would match the disable-events command too.
    rmdir_idx = next(
        i for i, c in enumerate(cmds) if "rmdir /sys/kernel/tracing/instances" in c
    )
    mkdir_idx = next(i for i, c in enumerate(cmds) if "mkdir -p" in c)
    assert rmdir_idx < mkdir_idx
    # Our probes are removed from kprobe_events during self-clean (before mkdir).
    remove_idx = next(i for i, c in enumerate(cmds) if "-:openat2" in c)
    assert remove_idx < mkdir_idx


def test_run_by_path_installs_probe_set_and_path_filter(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_path("/data/data/com.example.app")

    joined = "\n".join(fake.commands)
    # Path-mode probe set installed (everything EXCEPT the attr/xattr probes).
    for sym in (
        "do_sys_openat2",
        "do_mkdirat",
        "do_unlinkat",
        "do_renameat2",
        "vfs_write",
        "do_iter_write",
        "do_filp_open",
        "__fput",
    ):
        assert sym in joined, sym
    # Fix 2: pure PATH mode must NOT install the ATTRS/XATTR probes. They
    # capture only a basename (never a full path), so they can't be
    # path-glob-filtered and would otherwise emit device-wide ATTRS/XATTR rows
    # for any process. (The self-clean/teardown still reference them by the
    # short probe names nc/sx, but the kernel symbols only ever appear via an
    # INSTALL, so their absence proves the defs were never installed.)
    assert "notify_change" not in joined
    assert "vfs_setxattr" not in joined
    # In-kernel path glob on the scoped probes + do_filp_open correlation set.
    assert "/data/data/com.example.app/*" in joined
    assert "/events/kprobes/openat2/filter" in joined
    assert "/events/kprobes/dfo/filter" in joined
    # nc/sx are not ENABLED inside the instance (the self-clean still DISABLES
    # them idempotently with `echo 0`, but no `echo 1` enable is issued).
    assert not any(
        "echo 1 > " in c and "/events/kprobes/nc/enable" in c for c in fake.commands
    )
    assert not any(
        "echo 1 > " in c and "/events/kprobes/sx/enable" in c for c in fake.commands
    )
    # No PID scoping in path mode: no /proc/<pid>/task enumeration and no
    # event-fork (both are pid-mode-only). The only set_event_pid touch is the
    # self-clean's clearing write.
    assert not any("ls /proc/" in c for c in fake.commands)
    assert "options/event-fork" not in joined


def test_run_by_path_streams_the_instance_trace_pipe(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_path("/data/x")

    cmd = captured["stream_cmd"]
    assert cmd is not None
    assert cmd[-3:] == [
        "shell",
        "cat",
        "/sys/kernel/tracing/instances/sandroid_mon/trace_pipe",
    ]
    # Device targeting honored.
    assert "-s" in cmd
    assert "emulator-5556" in cmd


def test_run_by_pid_seeds_all_tids_and_enables_event_fork(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_pid(1234)

    joined = "\n".join(fake.commands)
    # All TIDs from /proc/<pid>/task/ seeded into set_event_pid.
    assert "ls /proc/1234/task" in joined
    seed = next(c for c in fake.commands if "set_event_pid" in c and "1240" in c)
    assert "1234 1240 1241" in seed
    # Whole child-tree following.
    assert "options/event-fork" in joined
    # Streams trace_pipe.
    assert captured["stream_cmd"][-1].endswith("/sandroid_mon/trace_pipe")


def test_run_by_pid_with_path_also_applies_path_glob(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_pid(1234, "/data/data/com.x")

    joined = "\n".join(fake.commands)
    assert "set_event_pid" in joined
    assert "/data/data/com.x/*" in joined


def test_run_by_path_single_path_has_no_or(monkeypatch):
    """A single path must produce a plain single-glob filter (no ``||``) --
    byte-identical to the pre-multi-path behaviour.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_path("/data/data/com.example.app")

    filter_cmds = [c for c in fake.commands if "/filter" in c]
    assert filter_cmds
    for cmd in filter_cmds:
        assert "||" not in cmd
        assert "/data/data/com.example.app/*" in cmd


def test_run_by_path_multi_path_ors_globs_per_field(monkeypatch):
    """A list of paths is OR'd (ftrace ``||``) into ONE filter per scoped field,
    each field name repeated once per glob (e.g. ``fname ~ "a/*" || fname ~
    "b/*"``).
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_path(["/data/data/com.x", "/sdcard/Download"])

    # The scoped fields (see _PATH_FILTER_FIELDS) each get one OR'd filter.
    for name, field in KprobeTracer._PATH_FILTER_FIELDS.items():
        cmd = next(c for c in fake.commands if f"/events/kprobes/{name}/filter" in c)
        # Both globs present, OR'd together, field repeated per glob.
        assert "/data/data/com.x/*" in cmd
        assert "/sdcard/Download/*" in cmd
        assert " || " in cmd
        assert cmd.count(f"{field} ~ ") == 2


def test_run_capture_all_has_no_pid_or_path_filter(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_capture_all()

    joined = "\n".join(fake.commands)
    # No pid seeding (no /proc/<pid>/task enumeration) and no per-mode filter.
    assert not any("ls /proc/" in c for c in fake.commands)
    assert "options/event-fork" not in joined
    assert "/filter" not in joined
    assert captured["stream_cmd"][-1].endswith("/sandroid_mon/trace_pipe")


def test_run_by_pid_keeps_attr_probes(monkeypatch):
    """Fix 2: PID mode keeps the ATTRS/XATTR probes (nc/sx) -- they're scoped by
    set_event_pid, so they don't leak device-wide.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_pid(1234)

    joined = "\n".join(fake.commands)
    assert "notify_change" in joined  # nc def installed
    assert "vfs_setxattr" in joined  # sx def installed
    assert any(
        "echo 1 > " in c and "/events/kprobes/nc/enable" in c for c in fake.commands
    )
    assert any(
        "echo 1 > " in c and "/events/kprobes/sx/enable" in c for c in fake.commands
    )


def test_run_capture_all_keeps_attr_probes(monkeypatch):
    """Fix 2: capture-all mode keeps the ATTRS/XATTR probes -- device-wide
    capture is the explicit intent.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_capture_all()

    joined = "\n".join(fake.commands)
    assert "notify_change" in joined
    assert "vfs_setxattr" in joined
    assert any(
        "echo 1 > " in c and "/events/kprobes/nc/enable" in c for c in fake.commands
    )
    assert any(
        "echo 1 > " in c and "/events/kprobes/sx/enable" in c for c in fake.commands
    )


# =============================================================================
# Teardown order -- Popen killed before instance removal
# =============================================================================


def test_teardown_removes_instance_last(monkeypatch):
    """Inside KprobeTracer.teardown: tracing off first, instance rmdir last
    (removing it while probes/pid/buffer still reference it would be wrong).
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake = _FakeShell([])
    monkeypatch.setattr(Adb, "send_adb_command", fake)
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    KprobeTracer._orig_buffer_kb = "7"

    KprobeTracer.teardown()

    cmds = fake.commands
    tracing_off_idx = next(
        i for i, c in enumerate(cmds) if "tracing_on" in c and "echo 0" in c
    )
    # Match the INSTANCE rmdir precisely -- "rmdir" is also a probe name.
    rmdir_idx = next(
        i for i, c in enumerate(cmds) if "rmdir /sys/kernel/tracing/instances" in c
    )
    pid_clear_idx = next(i for i, c in enumerate(cmds) if "set_event_pid" in c)
    probe_remove_idx = next(i for i, c in enumerate(cmds) if "-:openat2" in c)
    assert tracing_off_idx < rmdir_idx
    assert pid_clear_idx < rmdir_idx
    assert probe_remove_idx < rmdir_idx
    # Instance removal is the LAST tracefs operation.
    assert rmdir_idx == len(cmds) - 1
    # Buffer size restored before removal.
    assert any("buffer_size_kb" in c and "echo 7" in c for c in cmds)


def test_teardown_is_idempotent_and_swallows_errors(monkeypatch):
    def _boom(command):
        raise RuntimeError("adb is gone")

    monkeypatch.setattr(Adb, "send_adb_command", _boom)
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    # Must not raise even when every device command fails (adb already dead).
    KprobeTracer.teardown()
    KprobeTracer.teardown()


class _FakeProc:
    """Records terminate/kill/wait ordering into a shared event list."""

    def __init__(self, events, *, alive=True):
        self._events = events
        self._alive = alive
        self.returncode = None

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self._events.append("terminate")
        self._alive = False

    def kill(self):
        self._events.append("kill")
        self._alive = False

    def wait(self, timeout=None):
        self._events.append("wait")
        return 0


def test_wrapper_kills_popen_before_teardown(monkeypatch):
    """The wrapper's stop() must release the trace_pipe Popen (terminate/wait)
    BEFORE running teardown -- removing the tracefs instance while ``cat``
    still holds trace_pipe open would EBUSY.
    """
    events: list[str] = []
    proc = _FakeProc(events)

    def _teardown():
        events.append("teardown")

    wrapper = MonitorProcessWrapper(
        proc, config=object(), teardown=_teardown, translator=object()
    )
    wrapper.stop()

    assert "teardown" in events
    assert events.index("teardown") > events.index("terminate")
    # Idempotent: a second stop / natural-exit teardown does not re-run it.
    wrapper.run_teardown()
    assert events.count("teardown") == 1
