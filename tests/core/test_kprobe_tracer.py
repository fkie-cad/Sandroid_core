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
    KprobeTracer._orig_cmdlines = None
    KprobeTracer._write_scope = None
    yield
    KprobeTracer._kprobe_cache.clear()
    KprobeTracer._tracefs = None
    KprobeTracer._orig_buffer_kb = None
    KprobeTracer._orig_cmdlines = None
    KprobeTracer._write_scope = None


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
        f'name="{basename}" parent="tmp"\n'
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
                    'name="sandroid_kpcheck" parent="tmp"\n',
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
        f"expected exactly one preflight run, got {len(root_checks)}: {fake.commands}"
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
    """A single path without aliases produces a plain single-glob filter (no
    ``||``) -- byte-identical to the pre-multi-path behaviour.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_path("/data/local/tmp/work")

    filter_cmds = [c for c in fake.commands if "/filter" in c]
    assert filter_cmds
    for cmd in filter_cmds:
        assert "||" not in cmd
        assert "/data/local/tmp/work/*" in cmd


def test_run_by_path_multi_path_ors_globs_per_field(monkeypatch):
    """A list of paths is OR'd (ftrace ``||``) into ONE filter per scoped field,
    each field name repeated once per glob (e.g. ``fname ~ "a/*" || fname ~
    "b/*"``); every alias of each path gets its own glob.
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
        # data/data + user/0 + user_de/0; sdcard + storage/emulated/0 +
        # storage/self/primary.
        assert cmd.count(f"{field} ~ ") == 6


def test_app_data_root_also_watches_user0_and_user_de_aliases(monkeypatch):
    """H1: apps write via /data/user/0/<pkg> (getFilesDir()), and the probes
    match the path string, so the default /data/data/<pkg> target must also
    filter on /data/user/0/<pkg> (+ the app's /data/user_de/0/<pkg>).
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, captured, _ = _capture_run(monkeypatch)

    KprobeTracer.run_by_pid(1234, "/data/data/org.wikipedia")

    for name in KprobeTracer._PATH_FILTER_FIELDS:
        cmd = next(c for c in fake.commands if f"/events/kprobes/{name}/filter" in c)
        assert "/data/data/org.wikipedia/*" in cmd
        assert "/data/user/0/org.wikipedia/*" in cmd
        assert "/data/user_de/0/org.wikipedia/*" in cmd


def test_session_raises_and_restores_saved_cmdlines(monkeypatch):
    """M8: the comm cache is enlarged for the session (no ``<...>`` actors)
    and put back on teardown.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")

    def _cmdlines_read(cmd):
        return "cat " in cmd and "saved_cmdlines_size" in cmd

    fake, captured, _ = _capture_run(
        monkeypatch, extra_rules=[(_cmdlines_read, ("128", ""))]
    )
    KprobeTracer.run_by_path("/data/data/com.x")
    assert any(
        "saved_cmdlines_size" in c and f"echo {KprobeTracer._CMDLINES_SIZE}" in c
        for c in fake.commands
    )
    KprobeTracer.teardown()
    assert any("saved_cmdlines_size" in c and "echo 128 " in c for c in fake.commands)


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

    # M8 (round 2): the whole teardown is ONE adb round-trip (it was ~30,
    # 12-18 s per stop); the steps keep their order inside it.
    assert len(fake.commands) == 1
    (script,) = fake.commands
    tracing_off_idx = script.index("echo 0 > /sys/kernel/tracing/instances")
    # Match the INSTANCE rmdir precisely -- "rmdir" is also a probe name.
    rmdir_idx = script.index("rmdir /sys/kernel/tracing/instances")
    pid_clear_idx = script.index("set_event_pid")
    probe_remove_idx = script.index("-:openat2")
    buffer_idx = script.index("echo 7 > ")
    assert tracing_off_idx < rmdir_idx
    assert pid_clear_idx < rmdir_idx
    assert probe_remove_idx < rmdir_idx
    assert buffer_idx < rmdir_idx
    # Instance removal is the LAST tracefs operation.
    assert (
        script.rstrip("'")
        .rstrip()
        .endswith("rmdir /sys/kernel/tracing/instances/sandroid_mon 2>/dev/null")
    )


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


def test_device_path_helpers():
    """H1/H3/M5/M8 helpers in adb_utils."""
    from sandroid.core.adb_utils import (
        canonical_device_path,
        expand_monitor_paths,
        watch_path_problem,
    )

    assert canonical_device_path("/data/user/0/org.w/files//a/") == (
        "/data/data/org.w/files/a"
    )
    assert canonical_device_path("/storage/emulated/0/Download/x") == (
        "/sdcard/Download/x"
    )
    assert canonical_device_path("databases/") == "databases"
    assert canonical_device_path("/data/user/10/org.w/x") == "/data/user/10/org.w/x"
    assert expand_monitor_paths(["/data/user/0/org.w", "/data/data/org.w"]) == [
        "/data/data/org.w",
        "/data/user/0/org.w",
        "/data/user_de/0/org.w",
    ]
    assert expand_monitor_paths("/data/data/org.w/files") == [
        "/data/data/org.w/files",
        "/data/user/0/org.w/files",
    ]
    assert watch_path_problem("/data/data/org.w/my file.txt") is None
    assert watch_path_problem("/data/data/org.w/*.db") is None
    assert "absolute" in watch_path_problem("shared_prefs/x.xml")
    for bad in ("/x;touch y", "/x`id`", "/x$(id)", "/x|y", "/x&y"):
        assert "metacharacters" in watch_path_problem(bad)


# =============================================================================
# Write scope: dentry chains name writes through files opened before the start
# (recorded on emulator-5554, API 35, kernel 6.6.30, Firefox attached)
# =============================================================================

#: ``awk '{print $3, $4, $5}' /proc/1/mountinfo`` (the relevant lines).
RECORDED_MOUNTS = (
    "254:0 / /\n"
    "0:23 /user/0 /storage\n"
    "254:44 / /data\n"
    "254:44 /storage_area /data_mirror/storage_area\n"
    "254:44 /data /data/user/0\n"
    "0:80 / /mnt/user/0/emulated\n"
    "0:80 / /storage/emulated\n"
)
DATA_DEV = 266338348  # (254 << 20) | 44, as the probes print d_sb->s_dev
FUSE_DEV = 80
FF = "/data/data/org.mozilla.firefox"
#: The on-device vw filter for FF (read back from events/kprobes/.../filter).
RECORDED_FF_FILTER = (
    '(dev == 266338348 && (n1 == "org.mozilla.firefox" || '
    'n2 == "org.mozilla.firefox" || n3 == "org.mozilla.firefox" || '
    'n4 == "org.mozilla.firefox" || n5 == "org.mozilla.firefox" || '
    'n6 == "org.mozilla.firefox" || n7 == "org.mozilla.firefox" || n7 != "/"))'
)


def _ff_scope():
    from sandroid.core.kprobe_tracer import (
        build_write_scope,
        parse_mounts,
        scope_aliases,
    )

    return build_write_scope(scope_aliases(FF), parse_mounts(RECORDED_MOUNTS), {})


def test_write_probes_fetch_the_dentry_chain_within_the_tracefs_limit():
    """vw/diw carry dev + n0..n7; tracefs rejected a fetch expression one
    d_parent deeper than n7 ("Argument expression is too long", 67 chars)
    and accepted n7 (62).
    """
    defs = dict(zip(KprobeTracer._PROBE_NAMES, KprobeTracer._PROBE_DEFS, strict=True))
    for name in ("vw", "diw"):
        args = dict(a.split("=", 1) for a in defs[name].split()[2:])
        assert args["file"] == "$arg1:x64"
        assert args["dev"] == "+16(+104(+176($arg1))):u32"
        assert args["n0"] == "+0(+40(+176($arg1))):string"
        assert args["n7"] == (
            "+0(+40(+24(+24(+24(+24(+24(+24(+24(+176($arg1)))))))))):string"
        )
        assert all(len(v) <= 63 for v in args.values())
    for name in ("nc", "sx"):
        assert "n1=+0(+40(+24($arg2))):string" in defs[name]
        assert "dev=+16(+104($arg2)):u32" in defs[name]
    assert defs["dfor"] == "r:dfor do_filp_open file=$retval:x64 mode=+20($retval):x32"
    assert defs["mkdirr"] == "r:mkdirr do_mkdirat ret=$retval:s32"


def test_parse_mounts_and_kernel_dev():
    from sandroid.core.kprobe_tracer import kernel_dev, parse_mounts

    assert kernel_dev("254:44") == DATA_DEV
    assert kernel_dev("garbage") is None
    mounts = parse_mounts(RECORDED_MOUNTS + "0:99 /a\\040b /mnt/x\\040y\nbad line\n")
    assert (DATA_DEV, "/", "/data") in mounts
    assert (DATA_DEV, "/data", "/data/user/0") in mounts
    assert (99, "/a b", "/mnt/x y") in mounts


def test_write_scope_resolves_the_app_dir_on_the_data_filesystem():
    from sandroid.core.kprobe_tracer import WriteTarget, write_filter

    scope = _ff_scope()
    assert scope.complete
    # /data/user/0/<pkg> is a bind mount of /data/data: the same directory.
    assert scope.targets == (
        WriteTarget(FF, DATA_DEV, "/data/org.mozilla.firefox"),
        WriteTarget(
            "/data/user_de/0/org.mozilla.firefox",
            DATA_DEV,
            "/user_de/0/org.mozilla.firefox",
        ),
    )
    assert write_filter(scope) == RECORDED_FF_FILTER


def test_write_scope_follows_symlinks_and_nested_mounts():
    """/sdcard is a symlink to the FUSE mount; apps also reach Android/data on
    the lower filesystem (/data/media/0). A target containing a mount point
    covers that filesystem too.
    """
    from sandroid.core.kprobe_tracer import (
        WriteTarget,
        build_write_scope,
        parse_mounts,
        resolve_chain,
        scope_aliases,
        write_filter,
    )

    mounts = parse_mounts(RECORDED_MOUNTS)
    real = {
        "/sdcard": "/storage/emulated/0",
        "/storage/emulated/0": "/storage/emulated/0",
        "/storage/self/primary": "/storage/emulated/0",
    }
    scope = build_write_scope(scope_aliases("/sdcard"), mounts, real)
    assert WriteTarget("/sdcard", FUSE_DEV, "/0") in scope.targets
    assert WriteTarget("/sdcard", DATA_DEV, "/media/0") in scope.targets
    names = ["x.jpg", "Download", "0", "/", "/", "/", "/", "/"]
    assert resolve_chain(names, FUSE_DEV, scope) == "/sdcard/Download/x.jpg"
    lower = ["x.jpg", "Download", "0", "media", "/", "/", "/", "/"]
    assert resolve_chain(lower, DATA_DEV, scope) == "/sdcard/Download/x.jpg"
    expr = write_filter(scope)
    assert f'(dev == {FUSE_DEV} && (n1 == "0"' in expr
    assert f'(dev == {DATA_DEV} && (n1 == "0"' in expr

    # /storage (a tmpfs showing its /user/0) contains the FUSE mount, whose
    # whole filesystem is then in scope.
    wide = build_write_scope(scope_aliases("/storage"), mounts, {})
    assert WriteTarget("/storage", 23, "/user/0") in wide.targets
    assert WriteTarget("/storage/emulated", FUSE_DEV, "/") in wide.targets
    expr = write_filter(wide)
    assert expr.startswith(f'dev == {FUSE_DEV} || (dev == 23 && (n1 == "0"')


def test_resolve_chain_with_recorded_firefox_writes():
    from sandroid.core.kprobe_tracer import resolve_chain

    scope = _ff_scope()
    # files/places.sqlite-wal: opened at 10:56, long before any probe.
    wal = ["places.sqlite-wal", "files", "org.mozilla.firefox", "data"] + ["/"] * 4
    assert resolve_chain(wal, DATA_DEV, scope) == f"{FF}/files/places.sqlite-wal"
    # Same chain on another filesystem: not the target.
    assert resolve_chain(wal, 11, scope) is None
    # Sockets / eventfd / anonymous inodes / a /dev node: never a target.
    assert resolve_chain(["UNIX"] * 8, 8, scope) is None
    assert resolve_chain(["[eventfd]"] * 8, 15, scope) is None
    assert resolve_chain([""] * 8, 15, scope) is None
    assert resolve_chain(["goldfish_pipe_dprctd"] + ["/"] * 7, 6, scope) is None
    # Another app on the same filesystem.
    other = ["a.db", "databases", "com.other", "data"] + ["/"] * 4
    assert resolve_chain(other, DATA_DEV, scope) is None
    # The app directory itself is not a file under it.
    pkg_dir = ["org.mozilla.firefox", "data"] + ["/"] * 6
    assert resolve_chain(pkg_dir, DATA_DEV, scope) is None


def test_resolve_chain_longer_than_eight_names():
    """Cut chains: named when they still contain the app directory (or start
    inside the target's own path); the recorded IndexedDB file (9 deep below
    the package) is not -- the open-time map has to name it.
    """
    from sandroid.core.kprobe_tracer import resolve_chain

    scope = _ff_scope()
    six_deep = ["x", "e", "d", "c", "b", "a", "org.mozilla.firefox", "data"]
    assert resolve_chain(six_deep, DATA_DEV, scope) == f"{FF}/a/b/c/d/e/x"
    seven_deep = ["x", "f", "e", "d", "c", "b", "a", "org.mozilla.firefox"]
    assert resolve_chain(seven_deep, DATA_DEV, scope) == f"{FF}/a/b/c/d/e/f/x"
    idb = [
        "3870112724rsegmnoittet-es.sqlite-shm",
        "idb",
        "chrome",
        "permanent",
        "storage",
        "k3m7yjvw.default",
        "mozilla",
        "files",
    ]
    assert resolve_chain(idb, DATA_DEV, scope) is None


def test_guessed_scope_without_device_information():
    """Without the mount table the filesystem is unknown: /data/data/<pkg>
    chains still resolve by path components; a mount-point target (/data)
    stays unnamed instead of misnamed.
    """
    from sandroid.core.kprobe_tracer import (
        guess_write_scope,
        resolve_chain,
        write_filter,
    )

    wal = ["places.sqlite-wal", "files", "org.mozilla.firefox", "data"] + ["/"] * 4
    guessed = guess_write_scope(FF)
    assert resolve_chain(wal, DATA_DEV, guessed) == f"{FF}/files/places.sqlite-wal"
    assert resolve_chain(wal, None, guessed) == f"{FF}/files/places.sqlite-wal"
    assert write_filter(guessed) is None  # never filter in-kernel on a guess
    assert resolve_chain(wal, DATA_DEV, guess_write_scope("/data")) is None


def test_resolve_write_scope_is_one_adb_call_and_filters_the_write_probes(
    monkeypatch,
):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")

    def _scope_read(cmd):
        return "mountinfo" in cmd

    out = (
        RECORDED_MOUNTS
        + "--sandroid-scope--\n"
        + f"{FF}|{FF}\n"
        + "/data/user/0/org.mozilla.firefox|/data/user/0/org.mozilla.firefox\n"
        + "/data/user_de/0/org.mozilla.firefox|\n"
    )
    fake, _captured, _ = _capture_run(
        monkeypatch, extra_rules=[(_scope_read, (out, ""))]
    )
    scope = KprobeTracer.resolve_write_scope(FF)
    assert scope is not None
    assert scope.complete
    assert sum("mountinfo" in c for c in fake.commands) == 1
    assert "readlink -f" in fake.commands[-1]

    KprobeTracer.run_by_pid(1234, FF)
    for name in ("vw", "diw"):
        cmd = next(c for c in fake.commands if f"kprobes/{name}/filter" in c)
        assert RECORDED_FF_FILTER in cmd
    KprobeTracer.teardown()
    assert KprobeTracer._write_scope is None


def test_write_probes_stay_unfiltered_without_a_matching_scope(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, _captured, _ = _capture_run(monkeypatch)
    # No scope (mount table unreadable): unfiltered.
    assert KprobeTracer.resolve_write_scope(FF) is None
    KprobeTracer.run_by_path(FF)
    assert not any("kprobes/vw/filter" in c for c in fake.commands)
    # A scope resolved for other paths is not applied.
    KprobeTracer._write_scope = _ff_scope()
    KprobeTracer.run_by_path("/data/data/com.other")
    assert not any("kprobes/vw/filter" in c for c in fake.commands)


def test_kprobe_supported_false_when_the_parent_offset_is_wrong(monkeypatch):
    """The self-check also reads d_parent's name (the chain walks it)."""
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    trace = (
        "   sh-999 [000] ...1 1.1: kpck_dfo: (do_filp_open+0x0/0x1) "
        'path="/data/local/tmp/sandroid_kpcheck"\n'
        "   sh-999 [000] ...1 1.2: kpck_vw: (vfs_write+0x0/0x1) "
        'name="sandroid_kpcheck" parent="\\x01"\n'
    )
    fake = _FakeShell(
        [
            (_root_ok, ("restarting adbd as root", "")),
            (_id_ok, ("uid=0(root)", "")),
            (_tracefs_probe, ("OK", "")),
            (_symbol_loop, ("\n".join(_SYMBOLS), "")),
            (_trace_read, (trace, "")),
        ]
    )
    _install(monkeypatch, fake)
    assert KprobeTracer.kprobe_supported() is False
    vw_def = next(c for c in fake.commands if "p:kpck_vw" in c)
    assert "parent=+0(+40(+24(+176($arg1)))):string" in vw_def


# =============================================================================
# Follow the app: multi-process seeding, task_rename watch, set_event_pid
# adds, lost-event counters, process-table parsing (recorded device output)
# =============================================================================

from sandroid.core.kprobe_tracer import (
    android_comm,
    exit_filter,
    parse_add_output,
    parse_app_listing,
    parse_overruns,
    parse_process_exit,
    parse_task_rename,
    process_label,
    rename_filter,
)

FFX = "org.mozilla.firefox"

#: ``UID`` line + ``ps -A -o PID,UID,NAME`` + ``T`` lines, as the device
#: printed them for Firefox (5 processes; the sandboxed tabs run under
#: isolated UIDs, a fresh zygote child still shows ``zygote64``).
_REC_LISTING = """UID 10219
  PID   UID NAME
    1     0 init
  612     0 zygote64
 1290  1000 system_server
24310 10219 org.mozilla.firefox
24398 99012 org.mozilla.firefox:sandboxed_tab_17
24402 10219 org.mozilla.firefox:gpu_process
24455 99013 org.mozilla.firefox:sandboxed_tab_18
24470 10219 org.mozilla.firefox:crashhelper_service
24990 10220 com.other.app
T 24310 24310 24311 24312
"""

_REC_STATS = """entries: 12
overrun: 340
commit overrun: 7
bytes: 1234
oldest event ts:  9876.123456
now ts:  9880.654321
dropped events: 0
read events: 4321
entries: 3
overrun: 0
commit overrun: 0
bytes: 120
oldest event ts:  9876.2
now ts:  9880.6
dropped events: 2
read events: 99
"""

_REC_RENAME = (
    "           <...>-25983   [002] d..2.  9876.543210: task_rename: pid=25983 "
    "oldcomm=main newcomm=mozilla.firefox oom_score_adj=-1000"
)


def test_buffer_is_a_few_mb_per_cpu_not_64():
    """64 MB/CPU = 256 MB on a 4-CPU 2 GB AVD; a few MB absorbs a stall."""
    assert 1024 <= KprobeTracer._BUFFER_SIZE_KB <= 8192


def test_run_by_app_seeds_every_process_and_all_their_tids(monkeypatch):
    fake, captured, sentinel = _capture_run(
        monkeypatch,
        extra_rules=[
            (
                lambda c: "ls /proc/24310/task" in c,
                ("T 24310 24310 24311\nT 24402 24402 24403 24404\n", ""),
            )
        ],
    )
    assert KprobeTracer.run_by_app([24310, 24402], FF) is sentinel
    seed = next(c for c in fake.commands if "set_event_pid" in c and "24403" in c)
    assert "24310 24311 24402 24403 24404" in seed
    assert "> /sys/kernel/tracing/instances/sandroid_mon/set_event_pid" in seed
    assert any("options/event-fork" in c for c in fake.commands)
    assert KprobeTracer.last_seeded == {
        24310: [24310, 24311],
        24402: [24402, 24403, 24404],
    }
    # One adb round-trip lists every pid's tasks.
    assert sum("ls /proc/" in c for c in fake.commands) == 1


def test_run_by_app_before_the_app_runs_keeps_the_filter_armed(monkeypatch):
    """An EMPTY set_event_pid would record every task: pid 0 keeps it on."""
    fake, _captured, sentinel = _capture_run(monkeypatch)
    assert KprobeTracer.run_by_app([], FF) is sentinel
    seed = next(
        c for c in fake.commands if "> " in c and "set_event_pid" in c and "echo 0" in c
    )
    assert "instances/sandroid_mon/set_event_pid" in seed
    assert KprobeTracer.last_seeded == {}


def test_add_pids_appends_twice_and_measures_the_gap(monkeypatch):
    out = "T 25983 25983 25990 25991\nS 25983 987620\nU 9876.54\n"
    fake = _install(monkeypatch, _FakeShell([(lambda c: True, (out, ""))]))
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    result = KprobeTracer.add_pids([25983])
    (cmd,) = fake.commands
    sep = "/sys/kernel/tracing/instances/sandroid_mon/set_event_pid"
    # >> appends; > would clear the app's other processes first.
    assert cmd.count(f">> {sep}") == 2
    assert f"> {sep}" not in cmd.replace(f">> {sep}", "")
    assert "/proc/25983/stat" in cmd
    assert "/proc/uptime" in cmd
    assert result.tasks == {25983: [25983, 25990, 25991]}
    assert result.gap(25983) == pytest.approx(0.34, abs=1e-6)
    assert result.error is False


def test_add_pids_reports_a_refused_write():
    res = parse_add_output(
        "sh: echo: write error: Invalid argument\nT 5 5\nS 5 100\nU 2.0\n"
    )
    assert res.error is True
    assert res.gap(5) == pytest.approx(1.0)
    assert parse_add_output("U x\n").gap(5) is None


def test_list_app_processes_matches_uid_and_names():
    listing = parse_app_listing(_REC_LISTING, FFX)
    assert listing.ok is True
    assert listing.app_uid == 10219
    assert sorted(listing.processes) == [24310, 24398, 24402, 24455, 24470]
    assert listing.tasks == {24310: [24310, 24311, 24312]}
    # A zygote child that already took the app's UID but not its name yet.
    fresh = parse_app_listing(_REC_LISTING + "25983 10219 zygote64\n", FFX)
    assert 25983 in fresh.processes
    # The UID is learnt from the main process when /data/data is unreadable.
    no_uid = parse_app_listing(_REC_LISTING.replace("UID 10219\n", ""), FFX)
    assert no_uid.app_uid == 10219
    # An adb failure is no process table (never "everything exited").
    assert parse_app_listing("error: device offline", FFX).ok is False


def test_a_system_uid_is_never_matched():
    text = "UID 1000\n  PID   UID NAME\n 1290  1000 system_server\n"
    assert parse_app_listing(text, "com.android.settings").processes == {}


def test_list_app_processes_is_one_round_trip(monkeypatch):
    fake = _install(monkeypatch, _FakeShell([(lambda c: True, (_REC_LISTING, ""))]))
    listing = KprobeTracer.list_app_processes(FFX, [24310])
    (cmd,) = fake.commands
    assert "ps -A -o PID,UID,NAME" in cmd
    assert "stat -c %u /data/data/org.mozilla.firefox" in cmd
    assert "ls /proc/24310/task" in cmd
    assert len(listing.processes) == 5


def test_overrun_counters_are_summed_without_commit_overrun(monkeypatch):
    assert parse_overruns(_REC_STATS) == 342
    assert parse_overruns("") is None
    fake = _install(monkeypatch, _FakeShell([(lambda c: True, (_REC_STATS, ""))]))
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    assert KprobeTracer.read_lost_events() == 342
    assert "instances/sandroid_mon/per_cpu/cpu*/stats" in fake.commands[0]


def test_task_rename_lines_and_filter():
    assert parse_task_rename(_REC_RENAME) == (25983, "main", "mozilla.firefox")
    spaced = _REC_RENAME.replace("newcomm=mozilla.firefox", "newcomm=Binder 1")
    assert parse_task_rename(spaced) == (25983, "main", "Binder 1")
    assert parse_task_rename(" vw: (vfs_write+0x0) file=0x1") is None
    expr = rename_filter(FFX)
    # Android keeps the LAST 15 chars of a long dotted name as the comm.
    assert android_comm(FFX) == "mozilla.firefox"
    assert android_comm("com.x") == "com.x"
    assert 'oldcomm == "main"' in expr
    assert 'newcomm ~ "org.mozilla.fir*"' in expr
    assert 'newcomm == "mozilla.firefox"' in expr
    # A package name with filter syntax in it never reaches the kernel.
    assert "newcomm" not in rename_filter('x" || 1 == "1')


def test_process_labels():
    assert process_label(FFX, FFX) == "main"
    assert process_label(f"{FFX}:sandboxed_tab_17", FFX) == "tab_17"
    assert process_label(f"{FFX}:gpu_process", FFX) == "gpu_process"
    assert process_label(f"{FFX}:org.mozilla.gecko.Svc$tab3", FFX) == "tab3"
    assert process_label("com.shared.uid", FFX) == "com.shared.uid"


def test_rename_watch_uses_its_own_unscoped_instance(monkeypatch):
    captured = {}
    fake = _install(
        monkeypatch,
        _FakeShell(
            [
                (lambda c: "mkdir -p" in c and "sandroid_follow" in c, ("OK", "")),
                (lambda c: "/filter" in c, ("OK", "")),
            ]
        ),
    )
    monkeypatch.setattr(
        KprobeTracer,
        "_start_process",
        classmethod(lambda cls, cmd: captured.setdefault("cmd", cmd) and "proc"),
    )
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    assert KprobeTracer.start_rename_watch(FFX) == "proc"
    joined = "\n".join(fake.commands)
    inst = "/sys/kernel/tracing/instances/sandroid_follow"
    assert f"{inst}/events/task/task_rename/filter" in joined
    assert f"echo 1 > {inst}/events/task/task_rename/enable" in joined
    assert "set_event_pid" not in joined  # never PID-scoped
    assert captured["cmd"][-1] == f"{inst}/trace_pipe"
    assert any(f"echo 64 > {inst}/buffer_size_kb" in c for c in fake.commands)


def test_rename_watch_absent_tracepoint_means_poll_only(monkeypatch):
    fake = _install(monkeypatch, _FakeShell([]))
    monkeypatch.setattr(
        KprobeTracer,
        "_start_process",
        classmethod(lambda cls, cmd: pytest.fail("no stream without tracepoint")),
    )
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    assert KprobeTracer.start_rename_watch(FFX) is None
    assert any(
        "rmdir /sys/kernel/tracing/instances/sandroid_follow" in c
        for c in fake.commands
    )


def test_rename_watch_falls_back_when_the_filter_is_refused(monkeypatch):
    filters: list[str] = []

    def _filter(cmd):
        if "task_rename/filter" in cmd:
            filters.append(cmd)
            return len(filters) >= 2
        return False

    _install(
        monkeypatch,
        _FakeShell(
            [
                (lambda c: "mkdir -p" in c and "sandroid_follow" in c, ("OK", "")),
                (_filter, ("OK", "")),
                (
                    lambda c: "task_rename/filter" in c,
                    ("", "write error: Invalid argument"),
                ),
            ]
        ),
    )
    monkeypatch.setattr(KprobeTracer, "_start_process", classmethod(lambda cls, c: "p"))
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    assert KprobeTracer.start_rename_watch(FFX) == "p"
    assert len(filters) == 2
    assert "newcomm" in filters[0]
    assert "newcomm" not in filters[1]


def test_self_clean_also_removes_a_leaked_follow_instance(monkeypatch):
    fake, _captured, _ = _capture_run(monkeypatch)
    KprobeTracer.run_by_path("/data/x")
    assert any(
        "rmdir /sys/kernel/tracing/instances/sandroid_follow" in c
        for c in fake.commands
    )


# =============================================================================
# E2E round 2: TGID per line (M4), one-call teardown (M8), exit hint (L2)
# =============================================================================


def test_session_records_the_tgid_on_every_line(monkeypatch):
    """M4: threads born after the start carried only their TID."""
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    fake, _captured, _ = _capture_run(monkeypatch)
    KprobeTracer.run_by_app([4665])
    opt = "/instances/sandroid_mon/options/record-tgid"
    assert any(opt in c and "echo 1 > " in c for c in fake.commands)


def test_rename_watch_also_watches_the_main_threads_exit(monkeypatch):
    fake = _install(
        monkeypatch,
        _FakeShell(
            [(lambda c: "mkdir -p" in c and "sandroid_follow" in c, ("OK", ""))]
        ),
    )
    monkeypatch.setattr(KprobeTracer, "_start_process", classmethod(lambda cls, c: "p"))
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    assert KprobeTracer.start_rename_watch(FFX) == "p"
    (cmd,) = [c for c in fake.commands if "sched_process_exit/filter" in c]
    assert 'comm == "mozilla.firefox"' in cmd
    assert 'comm == "org.mozilla.fir"' in cmd
    # Enabled only once the filter was accepted (&&): never device-wide.
    assert cmd.index("/filter") < cmd.index("sched_process_exit/enable")
    assert " && echo 1 > " in cmd


def test_exit_filter_and_parse():
    assert exit_filter(None) is None
    assert exit_filter("bad pkg;rm") is None
    assert exit_filter("com.x") == 'comm == "com.x"'
    line = (
        "  mozilla.firefox-4665    [001] d..2. 9876.6: sched_process_exit: "
        "comm=mozilla.firefox pid=4665 prio=120"
    )
    assert parse_process_exit(line) == 4665
    assert parse_process_exit(_REC_RENAME) is None


def test_follow_instance_removal_is_one_adb_call(monkeypatch):
    fake = _install(monkeypatch, _FakeShell([]))
    KprobeTracer._tracefs = "/sys/kernel/tracing"
    KprobeTracer.stop_rename_watch()
    (cmd,) = fake.commands
    assert "task_rename/enable" in cmd
    assert "sched_process_exit/enable" in cmd
    assert cmd.index("tracing_on") < cmd.index("rmdir")
