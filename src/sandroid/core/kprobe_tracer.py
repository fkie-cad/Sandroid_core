r"""Kernel-tracefs kprobe filesystem-monitor backend.

``KprobeTracer`` is the second monitor backend (alongside the ``fsmon`` binary
driver in :mod:`sandroid.core.fsmon`). Where fsmon falls back to a broken
inotify ``-p`` filter on fanotify-less kernels, kprobes give genuine
kernel-verified per-PID attribution, whole child-process-tree following (ftrace
``event-fork``), path-scoped capture with reliable writes-under-a-path
(``struct file*`` correlation via ``do_filp_open``), and push **zero binaries**
to the device.

Mirrors ``FSMon``'s classmethod shape (``_build_adb_cmd`` / ``_start_process``
copied verbatim) so the controller can drive either backend identically. Root
is obtained via ``adb root`` + a ``shell id`` uid=0 verification (mirroring
``proxy_manager.enable_adb_root``) -- NEVER ``su``/``su 0`` (a non-functional
Magisk stub on the target AVDs).

All kprobe mechanisms here (probe defs, dentry offsets ``f_path.dentry +0xb0`` /
``d_name.name +0x28``, ``event-fork`` PID seeding, ``set_event_pid`` scoping,
per-instance ``trace_pipe`` streaming) were verified live on emulator-5556
(API 35, kernel 6.6.30) and emulator-5554 (API 36, kernel 6.6.66); offsets
matched exactly on both.

Documented caveats (not v1 blockers -- diff mode covers global completeness):
- Files opened BEFORE the monitor starts aren't in the ``file*`` map, so their
  writes are unattributed in *path* mode (a non-issue when the sandbox starts
  the monitor before launching the target app).
- On ``/sdcard`` the MediaProvider FUSE daemon co-writes the same paths in its
  own process; PID scoping will attribute those to the daemon, not the app.
- PID/tree scoping deliberately misses content-provider processes (e.g.
  contacts DB writes happen in ``android.process.acore``); diff mode covers it.

Shell-quoting note: device commands are single-quoted for the host shell (the
established ``proxy_manager._root_cmd`` idiom) and, where the payload must
survive the *device* shell too (probe defs contain ``$argN`` and parentheses,
filters contain double quotes), wrapped in device-side double quotes with
``$`` escaped to ``\\$`` and inner ``"`` escaped to ``\\"``. That way a literal
``$arg2`` / ``fname ~ "..."`` reaches ``kprobe_events`` / the filter file
instead of being expanded or stripped by either shell.
"""

from __future__ import annotations

import logging
import subprocess

from .adb import Adb

logger = logging.getLogger(__name__)


class KprobeTracer:
    """Kernel tracefs kprobe filesystem-monitor backend (mirrors ``FSMon``)."""

    logger = logging.getLogger(__name__)

    # Dedicated tracefs instance name for our session (isolated from any global
    # or foreign tracing). All probes are global (kprobe_events is not
    # per-instance) but only enabled/recorded inside this instance.
    _INSTANCE = "sandroid_mon"

    # Temp instance + probe names used only by the offset self-check preflight.
    _CHECK_INSTANCE = "sandroid_kpcheck"
    _CHECK_FILE = "/data/local/tmp/sandroid_kpcheck"

    # tracefs mount points to try, in order (writable-as-root probe picks one).
    _TRACEFS_CANDIDATES = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")

    # ~64 MB/CPU ring buffer for the dedicated instance (bumped from the tiny
    # default so bursty write storms don't overrun trace_pipe before the reader
    # drains them).
    _BUFFER_SIZE_KB = 65536

    # Kernel functions we attach to. If any is absent from /proc/kallsyms the
    # backend is unusable on this device.
    _REQUIRED_SYMBOLS = (
        "do_sys_openat2",
        "do_mkdirat",
        "do_unlinkat",
        "do_rmdir",
        "do_renameat2",
        "vfs_write",
        "do_iter_write",
        "do_filp_open",
        "__fput",
        "notify_change",
        "vfs_setxattr",
    )

    # trace_kprobe prints this when asked to probe a symbol/address it can't
    # resolve -- the "bogus symbol" test-attach signature.
    _BOGUS_SYMBOL_SIGNATURE = "Invalid probed address or symbol"

    # Verified probe set (do NOT edit the offsets/args -- confirmed live on two
    # kernels). ``name=+0(...)`` reads a null-terminated string at the innermost
    # dereferenced address; ``:ustring`` reads a userspace string. Names double
    # as the trace event names the translator keys on.
    #
    #   p:openat2 fname + flags   -> CREATE (O_CREAT 0x40) vs OPEN (noise)
    #   p:mkdir/unlink/rmdir/rename                metadata paths, emitted directly
    #   p:vw/diw                  vfs_write / do_iter_write, correlated via file*
    #   p:nc                      notify_change (attrs)
    #   p:sx                      vfs_setxattr (xattr)
    #   p:dfo (entry) / r:dfor    do_filp_open path + returned file* -> file* map
    #   p:fput                    __fput -> MANDATORY file* map invalidation
    _PROBE_DEFS = (
        "p:openat2 do_sys_openat2 fname=+0($arg2):ustring flags=+0($arg3):x64",
        "p:mkdir do_mkdirat name=+0(+0($arg2)):string",
        "p:unlink do_unlinkat name=+0(+0($arg2)):string",
        "p:rmdir do_rmdir name=+0(+0($arg2)):string",
        "p:rename do_renameat2 from=+0(+0($arg2)):string to=+0(+0($arg4)):string",
        "p:vw vfs_write file=$arg1:x64 count=$arg3:u64",
        "p:diw do_iter_write file=$arg1:x64",
        "p:nc notify_change dentry=+0(+0x28($arg2)):string ia_valid=+0($arg3):x32",
        "p:sx vfs_setxattr dentry=+0(+0x28($arg2)):string xname=+0($arg3):string",
        "p:dfo do_filp_open path=+0(+0($arg2)):string",
        "r:dfor do_filp_open file=$retval:x64",
        "p:fput __fput file=$arg1:x64",
    )

    # Event names (the ``NAME`` in ``p:NAME``/``r:NAME``) -- used for enable,
    # per-mode filters, and self-clean/teardown probe removal.
    _PROBE_NAMES = (
        "openat2",
        "mkdir",
        "unlink",
        "rmdir",
        "rename",
        "vw",
        "diw",
        "nc",
        "sx",
        "dfo",
        "dfor",
        "fput",
    )

    # ATTRS/XATTR probes (notify_change / vfs_setxattr) capture only a
    # *basename* (dentry name), never a full path -- so they are absent from
    # _PATH_FILTER_FIELDS and CANNOT be in-kernel path-glob-filtered. In pure
    # PATH mode they are therefore NOT installed/enabled: otherwise ANY
    # process's chmod/chown/truncate/utimes/setxattr device-wide would surface
    # as an ATTRS/XATTR row, violating the "nothing outside the path" contract.
    # They ARE kept in PID mode (scoped by set_event_pid) and in capture-all
    # mode (global capture is the intent).
    #
    # KNOWN LIMITATION: ATTRS/XATTR events are unavailable in pure path mode.
    # Use PID mode (or PID+path) or capture-all mode if you need them.
    _GLOBAL_ONLY_PROBES = ("nc", "sx")

    # Metadata probes whose path/name field is glob-filterable in path mode.
    _PATH_FILTER_FIELDS = {
        "openat2": "fname",
        "mkdir": "name",
        "unlink": "name",
        "rmdir": "name",
        "rename": "from",
        # The write-correlation set is scoped by filtering do_filp_open's path
        # (only files opened under the target land in the file* map).
        "dfo": "path",
    }

    # Per-device-serial memoization for kprobe_supported(), so switching the
    # active device (the 'D' key) never reuses a stale verdict. Inconclusive
    # probes (adb unreachable) are NOT memoized (mirrors FSMon._fanotify_cache).
    _kprobe_cache: dict[str, bool] = {}

    # Resolved tracefs mount + captured original buffer size, stored so an
    # idempotent teardown (which has no other state) can reach the right paths
    # and restore the buffer even when called standalone.
    _tracefs: str | None = None
    _orig_buffer_kb: str | None = None

    # =========================================================================
    # adb plumbing (mirrors FSMon)
    # =========================================================================

    @classmethod
    def _build_adb_cmd(cls, *args: str) -> list[str]:
        """Build an ADB command list, honoring the active target serial."""
        adb_path = Adb.ADB_PATH or "adb"
        cmd = [adb_path]
        serial = Adb.get_target_device()
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(args)
        return cmd

    @classmethod
    def _start_process(cls, cmd: list[str]) -> subprocess.Popen | None:
        """Start a streaming subprocess with line-buffered stdout (like FSMon)."""
        cls.logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            return subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as e:
            cls.logger.error(f"Failed to start kprobe trace_pipe reader: {e}")
            return None
        except subprocess.SubprocessError as e:
            cls.logger.error(f"Subprocess error starting kprobe reader: {e}")
            return None

    @classmethod
    def _shell(cls, device_cmd: str) -> str:
        """Run a single device shell command as root, returning combined output.

        Single-quotes the device command for the host shell (so host
        metacharacters aren't interpreted host-side) -- the established
        ``proxy_manager._root_cmd`` idiom for an ``adb root`` shell.
        """
        stdout, stderr = Adb.send_adb_command(f"shell '{device_cmd}'")
        return (stdout or "") + ("\n" + stderr if stderr else "")

    @staticmethod
    def _dq(payload: str) -> str:
        r"""Device-side double-quote a payload that must survive the device shell.

        Escapes ``$`` -> ``\\$`` (so ``$argN`` isn't expanded by the device
        shell) and ``"`` -> ``\\"`` (so inner double quotes survive), then wraps
        in device double quotes. Parentheses are literal inside double quotes.
        The whole device command is later single-quoted for the host shell by
        :meth:`_shell`, so this ``\\$`` / ``\\"`` reaches the device intact.
        """
        escaped = payload.replace("$", "\\$").replace('"', '\\"')
        return f'"{escaped}"'

    # =========================================================================
    # Root
    # =========================================================================

    @classmethod
    def _root_status(cls) -> str:
        """Enable adb root and classify the outcome into a tri-state.

        Mirrors ``proxy_manager.enable_adb_root`` but distinguishes a GENUINE
        "this device can't grant root" verdict from a merely transient/timeout
        adb failure, so ``kprobe_supported`` can apply the same
        no-memoize-on-inconclusive rule it already uses for the tracefs-None
        branch. Never uses ``su``/``su 0`` (a non-functional stub on the target
        AVDs).

        Returns:
            ``"root"`` -- the device shell is confirmed running as uid=0.
            ``"denied"`` -- adbd reported the genuine "adbd cannot run as root"
            signal (a real, memoizable verdict for this serial).
            ``"inconclusive"`` -- neither confirmed nor genuinely denied (e.g.
            an adb timeout/protocol fault, device offline, or an exception);
            indistinguishable from a transient failure, so the caller must NOT
            memoize it.
        """
        import time

        try:
            stdout, stderr = Adb.send_adb_command("root")
            combined = (stdout or "") + (stderr or "")
            if "adbd cannot run as root" in combined:
                return "denied"
            if "restarting" in combined.lower():
                time.sleep(0.5)
            stdout, _ = Adb.send_adb_command("shell id")
            return "root" if "uid=0" in (stdout or "") else "inconclusive"
        except Exception as e:
            cls.logger.warning(f"root status check failed: {e}")
            return "inconclusive"

    @classmethod
    def ensure_root(cls) -> bool:
        """Enable adb root and verify uid=0 (thin bool wrapper over _root_status).

        Never uses ``su``/``su 0`` (a non-functional stub on the target AVDs).

        Returns:
            True if the device shell is running as uid=0.
        """
        return cls._root_status() == "root"

    # =========================================================================
    # Capability preflight (run OFF the UI thread by the controller)
    # =========================================================================

    @classmethod
    def _resolve_tracefs(cls) -> str | None:
        """Return the first tracefs mount whose kprobe_events is writable as root."""
        for candidate in cls._TRACEFS_CANDIDATES:
            out = cls._shell(f"test -w {candidate}/kprobe_events && echo OK")
            if "OK" in out:
                return candidate
        return None

    @classmethod
    def _missing_symbols(cls, tracefs: str) -> list[str]:
        """Return the required kallsyms symbols NOT present on the device."""
        # A device-side loop echoes each symbol that IS present (device expands
        # the loop var $s itself -- do NOT escape it here).
        syms = " ".join(cls._REQUIRED_SYMBOLS)
        out = cls._shell(
            f"for s in {syms}; do grep -qw $s /proc/kallsyms && echo $s; done"
        )
        present = {tok.strip() for tok in out.split() if tok.strip()}
        return [s for s in cls._REQUIRED_SYMBOLS if s not in present]

    @classmethod
    def _offset_self_check(cls, tracefs: str) -> bool:
        """Validate the dentry offsets AND the do_filp_open write hot-path.

        Creates a known-named temp file, installs a temp ``vfs_write`` probe
        recovering the basename via ``f_path.dentry +0xb0`` / ``d_name.name
        +0x28`` AND a ``do_filp_open`` path-string canary, triggers a write,
        and confirms the recovered basename matches. A wrong offset yields
        garbage in ``name=`` / an empty capture, so a mismatch -> False.
        """
        events = f"{tracefs}/kprobe_events"
        inst = f"{tracefs}/instances/{cls._CHECK_INSTANCE}"
        basename = cls._CHECK_FILE.rsplit("/", 1)[-1]

        def _cleanup() -> None:
            cls._shell(f"echo 0 > {inst}/tracing_on 2>/dev/null")
            cls._shell(f"echo 0 > {inst}/events/kprobes/kpck_vw/enable 2>/dev/null")
            cls._shell(f"echo 0 > {inst}/events/kprobes/kpck_dfo/enable 2>/dev/null")
            cls._shell(f"rmdir {inst} 2>/dev/null")
            cls._shell(f"echo {cls._dq('-:kpck_vw')} >> {events} 2>/dev/null")
            cls._shell(f"echo {cls._dq('-:kpck_dfo')} >> {events} 2>/dev/null")
            cls._shell(f"rm -f {cls._CHECK_FILE} 2>/dev/null")

        _cleanup()  # scrub any leaked prior check

        vw_def = "p:kpck_vw vfs_write name=+0(+0x28(+0xb0($arg1))):string"
        dfo_def = "p:kpck_dfo do_filp_open path=+0(+0($arg2)):string"
        install_out = cls._shell(f"echo {cls._dq(vw_def)} >> {events}")
        install_out += cls._shell(f"echo {cls._dq(dfo_def)} >> {events}")
        if cls._BOGUS_SYMBOL_SIGNATURE in install_out:
            _cleanup()
            return False

        cls._shell(f"mkdir -p {inst}")
        cls._shell(f"echo 1 > {inst}/events/kprobes/kpck_vw/enable")
        cls._shell(f"echo 1 > {inst}/events/kprobes/kpck_dfo/enable")
        cls._shell(f"echo 1 > {inst}/tracing_on")
        # Trigger both do_filp_open (open path) and vfs_write (name) on the file.
        cls._shell(f"echo sandroid_canary > {cls._CHECK_FILE}")
        trace = cls._shell(f"cat {inst}/trace")
        _cleanup()

        # The vfs_write probe's name= field must recover the basename (proves
        # both +0xb0 and +0x28), and the do_filp_open canary must recover the
        # path (proves the write-attribution hot-path we actually depend on).
        name_ok = any(
            val.rstrip("/").rsplit("/", 1)[-1] == basename
            for val in _extract_field_values(trace, "name")
        )
        path_ok = any(basename in val for val in _extract_field_values(trace, "path"))
        return name_ok and path_ok

    @classmethod
    def kprobe_supported(cls) -> bool:
        """Preflight: True only if root + tracefs + symbols + offsets all pass.

        Memoized per device serial; inconclusive results (adb unreachable) are
        returned WITHOUT memoizing so a later real probe re-checks (mirrors
        ``FSMon.fanotify_supported``). MUST be run off the UI thread by the
        controller (several adb round-trips: kallsyms scan + test-attach +
        offset self-check).
        """
        serial = Adb.get_target_device() or ""
        if serial in cls._kprobe_cache:
            return cls._kprobe_cache[serial]

        # 1. Root. Only a GENUINE "device can't grant root" verdict is memoized
        # for this serial; a transient/timeout adb failure is inconclusive and
        # must NOT be cached (else a later start can never retry once adb
        # recovers) -- same no-memoize-on-inconclusive rule as the tracefs-None
        # branch below.
        status = cls._root_status()
        if status == "denied":
            cls._kprobe_cache[serial] = False
            return False
        if status != "root":
            return False

        # 2. Writable tracefs.
        tracefs = cls._resolve_tracefs()
        if tracefs is None:
            # No writable kprobe_events reachable. Could be a transient adb
            # failure -> inconclusive, do not memoize.
            return False
        cls._tracefs = tracefs

        # 3. Required kernel symbols present.
        missing = cls._missing_symbols(tracefs)
        if missing:
            cls.logger.info("kprobe unsupported: missing symbols %s", missing)
            cls._kprobe_cache[serial] = False
            return False

        # 4. Offset self-check (dentry offsets + write hot-path canary).
        try:
            ok = cls._offset_self_check(tracefs)
        except Exception:
            cls.logger.debug("kprobe offset self-check errored", exc_info=True)
            ok = False

        cls._kprobe_cache[serial] = ok
        return ok

    # =========================================================================
    # Session setup / teardown
    # =========================================================================

    @classmethod
    def _instance_dir(cls, tracefs: str) -> str:
        return f"{tracefs}/instances/{cls._INSTANCE}"

    @classmethod
    def _self_clean(cls, tracefs: str) -> None:
        """Idempotently scrub any pre-existing sandroid_mon session.

        Belt-and-suspenders so a leaked prior session (or the adb-already-dead
        teardown gap) can't wedge a fresh start. Safe when nothing exists
        (every command swallows its own "doesn't exist" error).
        """
        inst = cls._instance_dir(tracefs)
        events = f"{tracefs}/kprobe_events"
        cls._shell(f"echo 0 > {inst}/tracing_on 2>/dev/null")
        for name in cls._PROBE_NAMES:
            cls._shell(f"echo 0 > {inst}/events/kprobes/{name}/enable 2>/dev/null")
        cls._shell(f"echo > {inst}/set_event_pid 2>/dev/null")
        cls._shell(f"rmdir {inst} 2>/dev/null")
        # Remove our probes from the GLOBAL kprobe_events (must be disabled
        # everywhere first, done above).
        for name in cls._PROBE_NAMES:
            cls._shell(f"echo {cls._dq('-:' + name)} >> {events} 2>/dev/null")

    @classmethod
    def _active_probes(cls, mode: str) -> tuple[str, ...]:
        """Probe names to install+enable for a given scoping ``mode``.

        In pure ``"path"`` mode the ATTRS/XATTR probes (``nc``/``sx``) are
        OMITTED -- they capture only a basename and can't be path-glob-filtered,
        so keeping them would leak device-wide attribute/xattr rows (see
        ``_GLOBAL_ONLY_PROBES``). Every other mode (``"pid"``, capture-all)
        keeps the full set.
        """
        if mode == "path":
            return tuple(
                n for n in cls._PROBE_NAMES if n not in cls._GLOBAL_ONLY_PROBES
            )
        return cls._PROBE_NAMES

    @classmethod
    def _install_probes(cls, tracefs: str, probe_names: tuple[str, ...]) -> None:
        """Append the mode-appropriate probe set to the global kprobe_events."""
        events = f"{tracefs}/kprobe_events"
        for name, definition in zip(cls._PROBE_NAMES, cls._PROBE_DEFS, strict=True):
            if name in probe_names:
                cls._shell(f"echo {cls._dq(definition)} >> {events}")

    @classmethod
    def _enable_events(cls, tracefs: str, probe_names: tuple[str, ...]) -> None:
        """Enable each of the mode's events inside the dedicated instance."""
        inst = cls._instance_dir(tracefs)
        for name in probe_names:
            cls._shell(f"echo 1 > {inst}/events/kprobes/{name}/enable")

    @classmethod
    def _apply_path_filter(cls, tracefs: str, path: str) -> None:
        """Install an in-kernel ``field ~ "<path>/*"`` glob on the scoped probes."""
        inst = cls._instance_dir(tracefs)
        glob = f'{path.rstrip("/")}/*'
        for name, field in cls._PATH_FILTER_FIELDS.items():
            expr = f'{field} ~ "{glob}"'
            cls._shell(f"echo {cls._dq(expr)} > {inst}/events/kprobes/{name}/filter")

    @classmethod
    def _seed_pid_tree(cls, tracefs: str, pid: int) -> None:
        """Seed ALL TIDs of ``pid`` into set_event_pid + enable event-fork.

        set_event_pid scopes recording to those tasks; event-fork then
        auto-adds any child spawned by them (whole process tree, verified).
        """
        inst = cls._instance_dir(tracefs)
        out = cls._shell(f"ls /proc/{pid}/task")
        tids = [tok.strip() for tok in out.split() if tok.strip().isdigit()]
        if not tids:
            tids = [str(pid)]
        cls._shell(f"echo {cls._dq(' '.join(tids))} > {inst}/set_event_pid")
        cls._shell(f"echo 1 > {inst}/options/event-fork")

    @classmethod
    def _begin_session(cls, tracefs: str, probe_names: tuple[str, ...]) -> None:
        """Self-clean, create the instance, bump the buffer, install probes."""
        cls._self_clean(tracefs)
        inst = cls._instance_dir(tracefs)
        cls._shell(f"mkdir -p {inst}")
        # Capture the fresh instance's default buffer size so teardown can
        # restore it (belt-and-suspenders if the instance rmdir later fails).
        cls._orig_buffer_kb = cls._shell(f"cat {inst}/buffer_size_kb").strip() or None
        cls._shell(f"echo {cls._BUFFER_SIZE_KB} > {inst}/buffer_size_kb")
        cls._install_probes(tracefs, probe_names)

    @classmethod
    def _finish_session(
        cls, tracefs: str, probe_names: tuple[str, ...]
    ) -> subprocess.Popen | None:
        """Enable events, turn tracing on, and stream the instance trace_pipe."""
        cls._enable_events(tracefs, probe_names)
        inst = cls._instance_dir(tracefs)
        cls._shell(f"echo 1 > {inst}/tracing_on")
        cmd = cls._build_adb_cmd("shell", "cat", f"{inst}/trace_pipe")
        return cls._start_process(cmd)

    @classmethod
    def run_by_pid(cls, pid: int, path: str | None = None) -> subprocess.Popen | None:
        """Start kprobe tracing scoped to ``pid`` and its whole child tree.

        Optionally also constrains to files under ``path`` (a glob on the
        metadata + do_filp_open probes). PID mode keeps the FULL probe set --
        the ATTRS/XATTR probes (nc/sx) are scoped by ``set_event_pid`` here, so
        (unlike pure path mode) they don't leak device-wide.
        """
        tracefs = cls._tracefs or cls._resolve_tracefs()
        if tracefs is None:
            cls.logger.error("kprobe run_by_pid: no writable tracefs")
            return None
        cls._tracefs = tracefs
        probe_names = cls._active_probes("pid")
        cls._begin_session(tracefs, probe_names)
        cls._seed_pid_tree(tracefs, pid)
        if path:
            cls._apply_path_filter(tracefs, path)
        return cls._finish_session(tracefs, probe_names)

    @classmethod
    def run_by_path(cls, path: str) -> subprocess.Popen | None:
        """Start kprobe tracing scoped (in-kernel) to files under ``path``.

        Two path-mode caveats callers should know about:

        * ATTRS/XATTR events are UNAVAILABLE here -- the ``nc``/``sx`` probes
          capture only a basename, can't be path-glob-filtered, and are omitted
          to avoid leaking device-wide attribute/xattr rows (see
          ``_GLOBAL_ONLY_PROBES``). Use PID mode or capture-all for those.
        * WRITE FIREHOSE: writes (``vfs_write``/``do_iter_write``) and the
          ``do_filp_open``-return / ``__fput`` correlation lines can't be
          path-filtered in-kernel, so they fire system-wide. Under heavy system
          write load the kernel ring buffer can drop the sparse ``dfor``/``fput``
          control lines -- upstream of the Python deque, so the translator's
          translate-ahead-of-deque design can't recover them -- corrupting the
          file* map. The 64 MB/CPU buffer mitigates this. When a target PID is
          known, prefer ``run_by_pid(pid, path)`` (PID+path): ``set_event_pid``
          bounds the firehose to the target's task tree.
        """
        if not path:
            cls.logger.error("kprobe run_by_path: empty path")
            return None
        tracefs = cls._tracefs or cls._resolve_tracefs()
        if tracefs is None:
            cls.logger.error("kprobe run_by_path: no writable tracefs")
            return None
        cls._tracefs = tracefs
        probe_names = cls._active_probes("path")
        cls._begin_session(tracefs, probe_names)
        cls._apply_path_filter(tracefs, path)
        return cls._finish_session(tracefs, probe_names)

    @classmethod
    def run_capture_all(cls) -> subprocess.Popen | None:
        """Start kprobe tracing with no pid/path filter (global capture).

        Keeps the FULL probe set including ATTRS/XATTR -- device-wide capture
        is the explicit intent of this mode.
        """
        tracefs = cls._tracefs or cls._resolve_tracefs()
        if tracefs is None:
            cls.logger.error("kprobe run_capture_all: no writable tracefs")
            return None
        cls._tracefs = tracefs
        probe_names = cls._active_probes("all")
        cls._begin_session(tracefs, probe_names)
        return cls._finish_session(tracefs, probe_names)

    @classmethod
    def teardown(cls) -> None:
        """Idempotently tear the session down. Safe if adb/device is already gone.

        ORDER MATTERS: the caller (MonitorProcessWrapper.stop) kills the
        trace_pipe ``cat`` Popen FIRST -- removing the instance while ``cat``
        holds it open would EBUSY. This then: tracing off -> disable events ->
        clear set_event_pid -> restore buffer_size_kb -> remove probes ->
        remove the instance (last). Every step swallows its own error.
        """
        tracefs = cls._tracefs or cls._TRACEFS_CANDIDATES[0]
        inst = cls._instance_dir(tracefs)
        events = f"{tracefs}/kprobe_events"
        try:
            cls._shell(f"echo 0 > {inst}/tracing_on 2>/dev/null")
            for name in cls._PROBE_NAMES:
                cls._shell(f"echo 0 > {inst}/events/kprobes/{name}/enable 2>/dev/null")
            cls._shell(f"echo > {inst}/set_event_pid 2>/dev/null")
            if cls._orig_buffer_kb:
                cls._shell(
                    f"echo {cls._orig_buffer_kb} > {inst}/buffer_size_kb 2>/dev/null"
                )
            for name in cls._PROBE_NAMES:
                cls._shell(f"echo {cls._dq('-:' + name)} >> {events} 2>/dev/null")
            # Instance removal LAST (after the pipe is released + probes gone).
            cls._shell(f"rmdir {inst} 2>/dev/null")
        except Exception:
            cls.logger.debug("kprobe teardown swallowed an error", exc_info=True)
        finally:
            cls._orig_buffer_kb = None


def _extract_field_values(trace: str, field: str) -> list[str]:
    """Pull all ``field="..."`` string values out of raw trace output.

    Used by the offset self-check to read back the recovered basename/path.
    """
    values: list[str] = []
    token = field + '="'
    idx = 0
    while True:
        start = trace.find(token, idx)
        if start == -1:
            break
        start += len(token)
        end = trace.find('"', start)
        if end == -1:
            break
        values.append(trace[start:end])
        idx = end + 1
    return values
