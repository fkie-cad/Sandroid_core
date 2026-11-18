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

Naming writes through files opened BEFORE the monitor started (an attached
app's SQLite db and ``-wal``): ``vfs_write``/``do_iter_write`` only carry the
``struct file*``, and the ``file* -> path`` map is learned from
``do_filp_open`` at open time. So the write probes additionally fetch the
file's dentry chain -- ``f_path.dentry`` (+0xb0), then ``d_parent`` (+0x18)
seven times, each ``d_name.name`` (+0x28) as ``n0`` (the file) .. ``n7`` --
plus the filesystem's ``d_sb->s_dev`` (+0x68, +0x10) as ``dev``. A
filesystem root names itself ``/`` and is its own parent, so a chain that
reaches ``/`` is the file's complete path inside its filesystem; the
session's :class:`WriteScope` (``/proc/1/mountinfo`` + the targets'
real paths, read once at start) maps that onto the watched directory, e.g.
``places.sqlite-wal`` < ``files`` < ``org.mozilla.firefox`` < ``data`` <
``/`` on the /data filesystem is ``/data/data/org.mozilla.firefox/files/
places.sqlite-wal``. Eight names is the most tracefs accepts (a longer fetch
expression is rejected as "Argument expression is too long"); a deeper
chain is matched by the target's own path components (see
:func:`resolve_chain`). Verified live on emulator-5554 (API 35, 6.6.30)
against Firefox's pre-opened ``places.sqlite``/``-wal``.

Creation is the kernel's verdict too: ``r:dfor`` also reads the opened
file's ``f_mode`` (+0x14) -- ``FMODE_CREATED`` is set only when this open
created the file -- and ``r:mkdirr`` reports ``do_mkdirat``'s result, so an
``O_CREAT`` reopen or ``mkdir -p`` on an existing directory is no creation
without any scan of the targets.

Documented caveats (not v1 blockers -- diff mode covers global completeness):
- A write is named from the dentry chain when it is under a target; files
  more than seven directories below a target's filesystem root are named
  only if the chain still contains the target's directory, or from the
  open-time ``file*`` map.
- The probes see the path *string* a process passes in. Android reaches app
  data as ``/data/data/<pkg>`` AND ``/data/user/0/<pkg>`` (what
  ``getFilesDir()`` returns), so :meth:`_apply_path_filter` watches every
  alias (``adb_utils.expand_monitor_paths``). Relative names (``openat`` on a
  directory fd, ``cd dir && echo > f``, toybox ``rm -r``) don't match an
  absolute path filter: such creations and deletions are not reported (a
  deleted directory marks its known files deleted); writes to such files
  are, named by the write.
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
import re
import shlex
import subprocess
import threading
from dataclasses import dataclass
from dataclasses import field as dc_field

from .adb import Adb
from .adb_utils import (
    canonical_device_path,
    device_shell_command,
    expand_monitor_paths,
)

logger = logging.getLogger(__name__)

# Kernel struct offsets (arm64 GKI 6.6, verified live -- see module docstring).
_F_DENTRY = 0xB0  # struct file: f_path.dentry
_F_MODE = 0x14  # struct file: f_mode
_D_PARENT = 0x18  # struct dentry: d_parent
_D_NAME = 0x28  # struct dentry: d_name.name
_D_SB = 0x68  # struct dentry: d_sb
_S_DEV = 0x10  # struct super_block: s_dev

#: ``f_mode`` bit the kernel sets only when this open created the file.
FMODE_CREATED = 0x100000

#: Dentry names fetched per write (``n0`` = the file .. ``n7``). tracefs
#: rejects a longer fetch expression ("Argument expression is too long").
CHAIN_DEPTH = 8

#: ``kdev_t`` minor bits (``MKDEV(ma, mi) = ma << 20 | mi``).
_MINORBITS = 20


def _chain_args(dentry: str, first: int = 0) -> str:
    """``dev=`` + ``n<first>``..``n7`` fetch args for a dentry expression.

    Offsets are written in decimal: the fetch expression length is capped
    and ``+24(`` is shorter than ``+0x18(``.
    """
    args = [f"dev=+{_S_DEV}(+{_D_SB}({dentry})):u32"]
    for i in range(first, CHAIN_DEPTH):
        expr = dentry
        for _ in range(i):
            expr = f"+{_D_PARENT}({expr})"
        args.append(f"n{i}=+0(+{_D_NAME}({expr})):string")
    return " ".join(args)


_FILE_DENTRY = f"+{_F_DENTRY}($arg1)"


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

    # Ring buffer per CPU for the dedicated instance. trace_pipe is streamed
    # continuously, so the buffer only has to absorb a reader stall (adb
    # hiccup, host GC), not a whole session. A recorded line is ~230 bytes
    # (8 dentry names + dev/file/count; the binary entry is about the same
    # size). PID-scoped Firefox peaks around 2000 lines/s device-wide
    # (~0.5 MB/s); path mode's unfiltered dfor/fput correlation lines reach
    # ~10k lines/s (~2.3 MB/s). 4 MB/CPU holds ~18k lines per CPU: several
    # seconds of stall even if one CPU took the whole burst, 16 MB on a
    # 4-CPU AVD instead of the old 64 MB/CPU = 256 MB, which squeezed a 2 GB
    # device into LMK kills. An overrun is reported, not silent:
    # :meth:`read_lost_events` sums the per-CPU ``overrun`` counters.
    _BUFFER_SIZE_KB = 4096

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

    # Verified probe set (do NOT edit the offsets/args -- the path/name probes
    # were confirmed live on two kernels, the dentry chain, ``dev`` and
    # ``f_mode`` on 6.6.30). ``name=+0(...)`` reads a null-terminated string at the innermost
    # dereferenced address; ``:ustring`` reads a userspace string. Names double
    # as the trace event names the translator keys on.
    #
    #   p:openat2 fname + flags   -> O_CREAT opens are decided at dfor
    #   p:mkdir (entry) / r:mkdirr do_mkdirat path + result -> real creations only
    #   p:unlink/rmdir/rename     metadata paths, emitted directly
    #   p:vw/diw                  vfs_write / do_iter_write: file* + dentry chain
    #   p:nc                      notify_change (attrs) + dentry chain
    #   p:sx                      vfs_setxattr (xattr) + dentry chain
    #   p:dfo (entry) / r:dfor    do_filp_open path + returned file* (+ f_mode)
    #   p:fput                    __fput -> MANDATORY file* map invalidation
    _PROBE_DEFS = (
        "p:openat2 do_sys_openat2 fname=+0($arg2):ustring flags=+0($arg3):x64",
        "p:mkdir do_mkdirat name=+0(+0($arg2)):string",
        "r:mkdirr do_mkdirat ret=$retval:s32",
        "p:unlink do_unlinkat name=+0(+0($arg2)):string",
        "p:rmdir do_rmdir name=+0(+0($arg2)):string",
        "p:rename do_renameat2 from=+0(+0($arg2)):string to=+0(+0($arg4)):string",
        f"p:vw vfs_write file=$arg1:x64 count=$arg3:u64 {_chain_args(_FILE_DENTRY)}",
        f"p:diw do_iter_write file=$arg1:x64 {_chain_args(_FILE_DENTRY)}",
        "p:nc notify_change dentry=+0(+0x28($arg2)):string ia_valid=+0($arg3):x32 "
        + _chain_args("$arg2", first=1),
        "p:sx vfs_setxattr dentry=+0(+0x28($arg2)):string xname=+0($arg3):string "
        + _chain_args("$arg2", first=1),
        "p:dfo do_filp_open path=+0(+0($arg2)):string",
        f"r:dfor do_filp_open file=$retval:x64 mode=+{_F_MODE}($retval):x32",
        "p:fput __fput file=$arg1:x64",
    )

    # Event names (the ``NAME`` in ``p:NAME``/``r:NAME``) -- used for enable,
    # per-mode filters, and self-clean/teardown probe removal.
    _PROBE_NAMES = (
        "openat2",
        "mkdir",
        "mkdirr",
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

    # ATTRS/XATTR probes (notify_change / vfs_setxattr) capture a dentry
    # chain, never the path string -- so they are absent from
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

    # Serializes kprobe_supported() across its several independent callers
    # (app startup warm-up, device-change warm-up, Settings-tab warm-up, the
    # interactive select-probe, and _start_monitor's own preflight) -- without
    # it, two concurrent probes for the SAME serial would race on the SAME
    # fixed, non-namespaced on-device check-instance/probe names
    # (_CHECK_INSTANCE/_CHECK_FILE), each tearing down the other's in-flight
    # probes mid-check and risking a spurious verdict.
    _probe_lock = threading.Lock()

    # Resolved tracefs mount + captured original buffer size, stored so an
    # idempotent teardown (which has no other state) can reach the right paths
    # and restore the buffer even when called standalone.
    _tracefs: str | None = None
    _orig_buffer_kb: str | None = None
    _orig_cmdlines: str | None = None

    #: ftrace's comm cache (``saved_cmdlines_size``, default 128) is global and
    #: small: a busy app's threads overflow it and lines show ``<...>`` instead
    #: of the process name. Raised for the session, restored on teardown.
    _CMDLINES_SIZE = 4096

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

        The device command is passed as ONE host-quoted word
        (:func:`~sandroid.core.adb_utils.device_shell_command`), so host
        metacharacters are never interpreted host-side -- even when the
        command contains single quotes (e.g. from :meth:`_dq` or a
        user-supplied path).
        """
        stdout, stderr = Adb.send_adb_command(device_shell_command(device_cmd))
        return (stdout or "") + ("\n" + stderr if stderr else "")

    @staticmethod
    def _dq(payload: str) -> str:
        """Quote a payload as one literal word for the device shell.

        ``shlex.quote`` single-quotes it, so ``$argN``, inner double quotes,
        backticks and parentheses all reach ``echo`` verbatim (nothing is
        expanded on the device). :meth:`_shell` then quotes the whole device
        command for the host shell.
        """
        return shlex.quote(payload)

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
    def _offset_self_check(cls, tracefs: str) -> bool | None:
        """Validate the dentry offsets AND the do_filp_open write hot-path.

        Creates a known-named temp file, installs a temp ``vfs_write`` probe
        recovering the basename via ``f_path.dentry +0xb0`` / ``d_name.name
        +0x28`` AND a ``do_filp_open`` path-string canary, both scoped by an
        in-kernel filter to our one marker file, triggers a write, disables
        tracing, then reads the finite ``trace`` snapshot and confirms the
        recovered basename matches.

        Ordering is load-bearing: trigger the known write, THEN ``tracing_on=0``,
        THEN ``cat trace``, THEN parse. Reading ``cat trace`` while tracing is
        still on hangs on a live device -- the check probe records ambient
        device-wide writes (logd/adbd/system_server) so the snapshot never
        reaches EOF and the read blocks until the adb timeout. Disabling tracing
        first makes ``trace`` (the static snapshot file) return at EOF at once.
        The marker-scoped filter is defense in depth: even a race can't bury our
        one record under the ambient firehose.

        Returns:
            ``True``  -- offsets verified (basename AND path both recovered).
            ``False`` -- DEFINITIVE mismatch: the do_filp_open path canary (a
            KNOWN-GOOD offset) fired and recovered the marker path, proving the
            trigger + tracing + snapshot read all worked, yet the dentry-offset
            basename did not match -- a genuine wrong-offset verdict the caller
            memoizes. Also returned when the kernel rejects the check-probe
            attach outright (bogus-symbol signature -- a real capability fault).
            ``None``  -- INCONCLUSIVE: the check could not reach a verdict (empty
            or unreadable trace, the trigger/canary never landed, adb fault);
            the caller must NOT memoize so a later start re-checks.
        """
        events = f"{tracefs}/kprobe_events"
        inst = f"{tracefs}/instances/{cls._CHECK_INSTANCE}"
        basename = cls._CHECK_FILE.rsplit("/", 1)[-1]

        def _cleanup() -> None:
            # Guarded existence tests (see _self_clean): _cleanup runs once up
            # front to scrub a leaked prior check, when the sandroid_kpcheck
            # instance usually does NOT exist -- an unguarded `echo 0 > missing`
            # fails its redirect before `2>/dev/null` applies and warns.
            for probe in ("kpck_vw", "kpck_dfo"):
                enable = f"{inst}/events/kprobes/{probe}/enable"
                cls._shell(f"[ -e {enable} ] && echo 0 > {enable} 2>/dev/null")
            cls._shell(
                f"[ -e {inst}/tracing_on ] && echo 0 > {inst}/tracing_on 2>/dev/null"
            )
            cls._shell(f"[ -d {inst} ] && rmdir {inst} 2>/dev/null")
            for probe in ("kpck_vw", "kpck_dfo"):
                cls._shell(
                    f'grep -q "kprobes/{probe} " {events} 2>/dev/null '
                    f"&& echo {cls._dq('-:' + probe)} >> {events}"
                )
            cls._shell(f"rm -f {cls._CHECK_FILE} 2>/dev/null")

        _cleanup()  # scrub any leaked prior check

        # name = f_path.dentry->d_name.name; parent = d_parent's name (the
        # write probes' dentry chain depends on the d_parent offset too).
        vw_def = (
            "p:kpck_vw vfs_write name=+0(+0x28(+0xb0($arg1))):string "
            f"parent=+0(+{_D_NAME}(+{_D_PARENT}({_FILE_DENTRY}))):string"
        )
        dfo_def = "p:kpck_dfo do_filp_open path=+0(+0($arg2)):string"
        install_out = cls._shell(f"echo {cls._dq(vw_def)} >> {events}")
        install_out += cls._shell(f"echo {cls._dq(dfo_def)} >> {events}")
        if cls._BOGUS_SYMBOL_SIGNATURE in install_out:
            _cleanup()
            return False

        cls._shell(f"mkdir -p {inst}")
        # Every device write below to a path INSIDE the check instance is
        # guarded by ``[ -e path ] && echo ... 2>/dev/null`` -- the SAME
        # existence-guard idiom ``_cleanup``/``_self_clean``/``teardown`` already
        # use, and for the same documented reason (see ``_cleanup`` above): this
        # preflight runs eagerly (at startup + on device change), and on a
        # device where the check probes don't register -- so
        # ``events/kprobes/kpck_vw/`` etc. never appear under the instance --
        # a BARE ``echo ... > missing/path 2>/dev/null`` does NOT suppress the
        # failure. The shell's own redirect-open fails (ENOENT on the
        # containing directory) BEFORE the trailing ``2>`` redirect is even
        # set up, so the "can't create ... No such file or directory"
        # diagnostic reaches the ORIGINAL stderr regardless -- empirically
        # confirmed (unlike a spawned command's own stderr, e.g. ``cat``,
        # which IS 2>/dev/null-suppressible because its fd already points at
        # /dev/null before it runs). The existence guard is therefore load
        # -bearing, not just defense in depth; ``2>/dev/null`` is kept only as
        # a secondary guard against any OTHER write failure once the path is
        # confirmed present. The verdict is still derived purely from the
        # ``trace`` snapshot below, so silencing these writes cannot mask a
        # real result. (The two probe-install lines above deliberately KEEP
        # their stderr -- the bogus-symbol signature is read from it.)
        #
        # Scope BOTH check probes to our one marker file so the ambient
        # device-wide write firehose can never bury the record we look for
        # (belt-and-suspenders on top of the tracing-off-before-read fix).
        vw_filter = f'name ~ "*{basename}*"'
        dfo_filter = f'path ~ "*{basename}*"'
        vw_filter_path = f"{inst}/events/kprobes/kpck_vw/filter"
        dfo_filter_path = f"{inst}/events/kprobes/kpck_dfo/filter"
        vw_enable_path = f"{inst}/events/kprobes/kpck_vw/enable"
        dfo_enable_path = f"{inst}/events/kprobes/kpck_dfo/enable"
        tracing_on_path = f"{inst}/tracing_on"
        cls._shell(
            f"[ -e {vw_filter_path} ] && echo {cls._dq(vw_filter)} > "
            f"{vw_filter_path} 2>/dev/null"
        )
        cls._shell(
            f"[ -e {dfo_filter_path} ] && echo {cls._dq(dfo_filter)} > "
            f"{dfo_filter_path} 2>/dev/null"
        )
        cls._shell(f"[ -e {vw_enable_path} ] && echo 1 > {vw_enable_path} 2>/dev/null")
        cls._shell(
            f"[ -e {dfo_enable_path} ] && echo 1 > {dfo_enable_path} 2>/dev/null"
        )
        cls._shell(
            f"[ -e {tracing_on_path} ] && echo 1 > {tracing_on_path} 2>/dev/null"
        )
        # Trigger both do_filp_open (open path) and vfs_write (name) on the
        # file. This CREATES a new file under /data/local/tmp (always
        # writable on Android) -- no existence guard applies here.
        cls._shell(f"echo sandroid_canary > {cls._CHECK_FILE} 2>/dev/null")
        # Disable tracing BEFORE reading so `cat trace` (the static snapshot)
        # returns at EOF immediately instead of blocking on the live firehose.
        cls._shell(
            f"[ -e {tracing_on_path} ] && echo 0 > {tracing_on_path} 2>/dev/null"
        )
        # `cat`'s own "No such file" IS 2>/dev/null-suppressible (its stderr fd
        # is already redirected before it runs) -- no existence guard needed.
        trace = cls._shell(f"cat {inst}/trace 2>/dev/null")
        _cleanup()

        # The vfs_write probe's name= field must recover the basename (proves
        # both +0xb0 and +0x28) and parent= its directory (proves d_parent
        # +0x18, which the write probes' dentry chain walks), and the
        # do_filp_open canary must recover the path (the open-time hot-path).
        parent_name = cls._CHECK_FILE.rsplit("/", 2)[-2]
        name_ok = any(
            val.rstrip("/").rsplit("/", 1)[-1] == basename
            for val in _extract_field_values(trace, "name")
        ) and parent_name in _extract_field_values(trace, "parent")
        path_ok = any(basename in val for val in _extract_field_values(trace, "path"))
        if name_ok and path_ok:
            return True
        # do_filp_open's path uses a KNOWN-GOOD offset and fires on the very
        # open that precedes our write. If it recovered the marker path, the
        # trigger + tracing + snapshot read all demonstrably worked, so a
        # missing/garbage basename is a genuine dentry-offset MISMATCH
        # (memoizable False). If not even the path canary landed, the check
        # never reached a verdict (empty/unreadable trace, failed trigger, adb
        # fault) -> INCONCLUSIVE (None) -> caller must not memoize.
        return False if path_ok else None

    @classmethod
    def kprobe_supported(cls) -> bool:
        """Preflight: True only if root + tracefs + symbols + offsets all pass.

        Memoized per device serial; inconclusive results (adb unreachable) are
        returned WITHOUT memoizing so a later real probe re-checks (mirrors
        ``FSMon.fanotify_supported``). MUST be run off the UI thread by the
        controller (several adb round-trips: kallsyms scan + test-attach +
        offset self-check).

        Serialized by :attr:`_probe_lock` -- several independent callers
        (app startup, device-change, the Settings warm-up, the interactive
        select-probe, ``_start_monitor``'s own preflight) can invoke this for
        the same serial around the same time; without the lock, two
        concurrent runs would race on the SAME fixed on-device check-instance
        and could corrupt each other's verdict.
        """
        serial = Adb.get_target_device() or ""
        if serial in cls._kprobe_cache:
            return cls._kprobe_cache[serial]

        with cls._probe_lock:
            # Double-checked: another thread may have completed (and
            # memoized) a probe for this serial while we were waiting for the
            # lock -- serve its verdict instead of redundantly re-running the
            # whole preflight.
            if serial in cls._kprobe_cache:
                return cls._kprobe_cache[serial]

            # 1. Root. Only a GENUINE "device can't grant root" verdict is
            # memoized for this serial; a transient/timeout adb failure is
            # inconclusive and must NOT be cached (else a later start can
            # never retry once adb recovers) -- same no-memoize-on-inconclusive
            # rule as the tracefs-None branch below.
            status = cls._root_status()
            if status == "denied":
                cls._kprobe_cache[serial] = False
                return False
            if status != "root":
                return False

            # 2. Writable tracefs.
            tracefs = cls._resolve_tracefs()
            if tracefs is None:
                # No writable kprobe_events reachable. Could be a transient
                # adb failure -> inconclusive, do not memoize.
                return False
            cls._tracefs = tracefs

            # 3. Required kernel symbols present.
            missing = cls._missing_symbols(tracefs)
            if missing:
                cls.logger.info("kprobe unsupported: missing symbols %s", missing)
                cls._kprobe_cache[serial] = False
                return False

            # 4. Offset self-check (dentry offsets + write hot-path canary).
            # Tri-state: True/False are DEFINITIVE verdicts (memoized for this
            # serial); None is INCONCLUSIVE (the check couldn't run to a
            # verdict -- adb fault, failed trigger, empty/unreadable trace)
            # and is NOT memoized, so a later start re-checks once the device
            # settles (same no-memoize-on-inconclusive rule as the
            # root/tracefs branches above).
            try:
                result = cls._offset_self_check(tracefs)
            except Exception:
                cls.logger.debug("kprobe offset self-check errored", exc_info=True)
                result = None

            if result is None:
                return False
            cls._kprobe_cache[serial] = result
            return result

    @classmethod
    def cached_availability(cls) -> bool | None:
        """Return the memoized kprobe verdict for the CURRENT serial (no probe).

        A pure read of :attr:`_kprobe_cache` for the active target serial --
        NEVER runs ``adb``, never triggers a probe, so it is safe to call on the
        UI thread. The heavy :meth:`kprobe_supported` (which fills the cache)
        must be run off-thread; this only surfaces what it already learned.

        The verdict is per current serial: switching the active device (the
        ``D`` key) changes what this returns, and a serial never probed on (or
        only probed inconclusively) is absent from the cache.

        Returns:
            ``True``/``False`` -- the memoized definitive verdict for this
            serial. ``None`` -- this serial has never been probed to a
            definitive verdict (never probed, or every probe was inconclusive).
        """
        return cls._kprobe_cache.get(Adb.get_target_device() or "")

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
        # Every step is guarded by an on-device existence test. A bare
        # ``echo 0 > missing/file`` fails its redirect BEFORE a trailing
        # ``2>/dev/null`` can take effect (redirects apply left-to-right and the
        # shell aborts on the first failure), so on a clean device -- the common
        # case, since a normal stop removes the instance -- the old unguarded
        # form leaked a "can't create ..." to stderr and spammed a WARNING per
        # probe on EVERY start. Guarding means a clean device emits no stderr.
        cls._shell(f"[ -e {inst}/tracing_on ] && echo 0 > {inst}/tracing_on")
        for name in cls._PROBE_NAMES:
            enable = f"{inst}/events/kprobes/{name}/enable"
            cls._shell(f"[ -e {enable} ] && echo 0 > {enable}")
        cls._shell(f"[ -e {inst}/set_event_pid ] && echo > {inst}/set_event_pid")
        cls._shell(f"[ -d {inst} ] && rmdir {inst} 2>/dev/null")
        # Remove our probes from the GLOBAL kprobe_events, but only the ones
        # actually registered -- a ``-:name`` for an absent probe errors too.
        for name in cls._PROBE_NAMES:
            cls._shell(
                f'grep -q "kprobes/{name} " {events} 2>/dev/null '
                f"&& echo {cls._dq('-:' + name)} >> {events}"
            )
        cls._remove_follow_instance(tracefs)

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
    def _apply_path_filter(cls, tracefs: str, paths: str | list[str]) -> None:
        """Install an in-kernel ``field ~ "<path>/*"`` glob on the scoped probes.

        Accepts a single path or a list. Each path becomes one ``<p>/*`` glob;
        the per-field globs are OR'd with ftrace's ``||`` so a single filter
        matches files under ANY of the target paths. A single path yields a
        one-element join, i.e. exactly the old single-glob string (byte-for-byte)
        so nothing changes for the common single-path case.
        """
        inst = cls._instance_dir(tracefs)
        # Every alias of each target (/data/data/<pkg> also as
        # /data/user/0/<pkg>, plus the app's /data/user_de/0/<pkg>): the
        # probes match the path STRING a process passes, not the resolved path.
        path_list = expand_monitor_paths(paths)
        globs = [f"{p.rstrip('/')}/*" for p in path_list]
        for name, field in cls._PATH_FILTER_FIELDS.items():
            expr = " || ".join(f'{field} ~ "{g}"' for g in globs)
            cls._shell(f"echo {cls._dq(expr)} > {inst}/events/kprobes/{name}/filter")
        cls._apply_write_filter(tracefs, paths)

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

    #: Placeholder written to ``set_event_pid`` when an app session starts
    #: with none of the app's processes running: an EMPTY list written with
    #: ``>`` clears the filter (= record every task), a list holding only the
    #: idle task (pid 0, which never enters the probed syscalls) keeps the
    #: filter on and records nothing until the follower adds the app.
    _NO_PID = 0

    @classmethod
    def _seed_pids(cls, tracefs: str, pids: list[int]) -> dict[int, list[int]]:
        """Seed every TID of every ``pid`` + enable event-fork (app scope).

        ONE adb round-trip. With no pid the filter is armed with
        :attr:`_NO_PID` (see there). Returns ``{pid: [tids]}`` as written.
        """
        inst = cls._instance_dir(tracefs)
        sep = f"{inst}/set_event_pid"
        if not pids:
            cls._shell(f"echo {cls._NO_PID} > {sep}")
            cls._shell(f"echo 1 > {inst}/options/event-fork")
            return {}
        listing = "; ".join(
            f'echo "T {int(p)} $(ls /proc/{int(p)}/task 2>/dev/null | tr "\\n" " ")"'
            for p in pids
        )
        tasks = parse_task_lines(cls._shell(listing))
        tids: list[int] = []
        for p in pids:
            tids.extend(tasks.get(int(p)) or [int(p)])
        cls._shell(f"echo {cls._dq(' '.join(str(t) for t in tids))} > {sep}")
        cls._shell(f"echo 1 > {inst}/options/event-fork")
        return {int(p): tasks.get(int(p)) or [int(p)] for p in pids}

    #: The app's processes seeded by the last :meth:`run_by_app` (pid -> tids).
    last_seeded: dict[int, list[int]] = {}

    @classmethod
    def run_by_app(
        cls, pids: list[int], path: str | list[str] | None = None
    ) -> subprocess.Popen | None:
        """Start kprobe tracing scoped to ALL of an app's processes.

        Like :meth:`run_by_pid`, but seeds every process in ``pids`` (all
        their TIDs; event-fork follows their children). ``pids`` may be empty
        (the app is not running yet): the follower adds its processes as
        they start (:meth:`add_pids`). The seeded ``{pid: tids}`` is left in
        :attr:`last_seeded`.
        """
        tracefs = cls._tracefs or cls._resolve_tracefs()
        if tracefs is None:
            cls.logger.error("kprobe run_by_app: no writable tracefs")
            return None
        cls._tracefs = tracefs
        probe_names = cls._active_probes("pid")
        cls._begin_session(tracefs, probe_names)
        cls.last_seeded = cls._seed_pids(tracefs, list(pids))
        if path:
            cls._apply_path_filter(tracefs, path)
        return cls._finish_session(tracefs, probe_names)

    # =========================================================================
    # Follow the app: add processes, notice starts, count lost events
    # =========================================================================

    #: Separate small instance for ``task:task_rename`` (NOT pid-scoped).
    _FOLLOW_INSTANCE = "sandroid_follow"
    #: Its ring buffer per CPU: a handful of renames per app start.
    _FOLLOW_BUFFER_KB = 64

    @classmethod
    def _follow_dir(cls, tracefs: str) -> str:
        return f"{tracefs}/instances/{cls._FOLLOW_INSTANCE}"

    @classmethod
    def _remove_follow_instance(cls, tracefs: str) -> None:
        """Guarded, idempotent removal of the follow instance (ONE adb call)."""
        inst = cls._follow_dir(tracefs)
        steps = [f"[ -e {inst}/tracing_on ] && echo 0 > {inst}/tracing_on"]
        for ev in (
            f"{inst}/events/task/task_rename",
            f"{inst}/events/sched/sched_process_exit",
        ):
            steps.append(f"[ -e {ev}/enable ] && echo 0 > {ev}/enable")
        steps.append(f"[ -d {inst} ] && rmdir {inst} 2>/dev/null")
        cls._shell(" ; ".join(steps))

    @classmethod
    def start_rename_watch(cls, package: str) -> subprocess.Popen | None:
        """Stream ``task:task_rename`` for new app processes (or ``None``).

        A zygote child names itself (``SetThreadName``: "main" -> its nice
        name) right after it took the app's UID, so a rename is the
        earliest cheap sign of a new app process. Lives in its own instance
        (:attr:`_FOLLOW_INSTANCE`), not scoped by ``set_event_pid``, filtered
        in-kernel by :func:`rename_filter`; a filter the kernel rejects is
        retried simpler, then dropped (the follower verifies every pid via
        ``/proc`` anyway). ``None`` when the tracepoint is missing: the
        follower then relies on its poll alone.
        """
        tracefs = cls._tracefs or cls._resolve_tracefs()
        if tracefs is None:
            return None
        cls._tracefs = tracefs
        inst = cls._follow_dir(tracefs)
        ev = f"{inst}/events/task/task_rename"
        cls._remove_follow_instance(tracefs)
        out = cls._shell(f"mkdir -p {inst} && [ -e {ev}/enable ] && echo OK")
        if "OK" not in out:
            cls.logger.info("task_rename tracepoint unavailable: poll-only follow")
            cls._remove_follow_instance(tracefs)
            return None
        cls._shell(f"echo {cls._FOLLOW_BUFFER_KB} > {inst}/buffer_size_kb")
        for expr in (rename_filter(package), rename_filter(None), None):
            if expr is None:
                cls.logger.info("task_rename filter rejected: watching unfiltered")
                break
            res = cls._shell(f"echo {cls._dq(expr)} > {ev}/filter && echo OK")
            if "OK" in res and "rror" not in res and "nvalid" not in res:
                break
        # The app's main thread exiting (force-stop, crash, kill) wakes the
        # follower's poll at once instead of at its next slow tick. Only
        # with the in-kernel comm filter accepted: unfiltered, every thread
        # exit device-wide would wake it.
        exit_expr = exit_filter(package)
        if exit_expr:
            xev = f"{inst}/events/sched/sched_process_exit"
            cls._shell(
                f"[ -e {xev}/filter ] && echo {cls._dq(exit_expr)} > {xev}/filter"
                f" && echo 1 > {xev}/enable"
            )
        cls._shell(f"echo 1 > {ev}/enable && echo 1 > {inst}/tracing_on")
        return cls._start_process(
            cls._build_adb_cmd("shell", "cat", f"{inst}/trace_pipe")
        )

    @classmethod
    def stop_rename_watch(cls) -> None:
        """Remove the follow instance (after its ``cat`` was killed)."""
        tracefs = cls._tracefs or cls._TRACEFS_CANDIDATES[0]
        try:
            cls._remove_follow_instance(tracefs)
        except Exception:
            cls.logger.debug("follow instance removal failed", exc_info=True)

    @classmethod
    def list_app_processes(
        cls, package: str, tracked: list[int] | tuple[int, ...] = ()
    ) -> AppListing:
        """The app's UID and process table, plus TIDs of ``tracked`` pids.

        ONE adb round-trip; parsed by :func:`parse_app_listing`.
        """
        cmd = (
            f"echo UID $(stat -c %u /data/data/{shlex.quote(package)} 2>/dev/null); "
            "ps -A -o PID,UID,NAME 2>/dev/null"
        )
        for p in tracked:
            cmd += (
                f'; echo "T {int(p)} $(ls /proc/{int(p)}/task 2>/dev/null'
                ' | tr "\\n" " ")"'
            )
        return parse_app_listing(cls._shell(cmd), package)

    @classmethod
    def add_pids(cls, pids: list[int]) -> AddResult:
        """Append every TID of each pid to the monitor's ``set_event_pid``.

        ``>>`` appends (``>`` would clear the list first). Each pid's TIDs
        are listed and appended twice, so a thread spawned between the
        first listing and the write is caught by the second pass (once a
        thread is in the list, event-fork adds its children itself). Each
        pid's ``starttime`` and the uptime right after the writes give the
        gap between the process start and the moment it was followed.
        ONE adb round-trip; parsed by :func:`parse_add_output`.
        """
        tracefs = cls._tracefs or cls._TRACEFS_CANDIDATES[0]
        sep = f"{cls._instance_dir(tracefs)}/set_event_pid"
        parts = []
        for p in pids:
            p = int(p)
            ls = f'$(ls /proc/{p}/task 2>/dev/null | tr "\\n" " ")'
            parts.append(
                f't="{ls}"; [ -n "$t" ] && echo $t >> {sep}; '
                f't="{ls}"; [ -n "$t" ] && echo $t >> {sep}; '
                f'echo "T {p} $t"; '
                f"echo \"S {p} $(sed -e 's/^.*) //' /proc/{p}/stat 2>/dev/null"
                ' | cut -d" " -f20)"'
            )
        parts.append('echo "U $(cut -d" " -f1 /proc/uptime)"')
        return parse_add_output(cls._shell("; ".join(parts)))

    @classmethod
    def read_lost_events(cls) -> int | None:
        """Events the monitor instance's ring buffer lost (all CPUs).

        Sums ``overrun`` (oldest entries overwritten while the reader lagged)
        and ``dropped events`` from ``per_cpu/cpuN/stats``. ``None`` when
        the stats can't be read.
        """
        tracefs = cls._tracefs or cls._TRACEFS_CANDIDATES[0]
        inst = cls._instance_dir(tracefs)
        try:
            out = cls._shell(f"cat {inst}/per_cpu/cpu*/stats 2>/dev/null")
        except Exception:
            return None
        return parse_overruns(out)

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
        # Every line then carries the writer's TGID next to its thread id
        # ("comm-TID (  TGID) [cpu]"): a thread born after the session
        # started is attributed to its process without a /proc lookup. The
        # kernel fills its pid->tgid map at the next context switch, so a
        # line read before that shows "(-------)" (see KprobeStreamTranslator).
        tgid_opt = f"{inst}/options/record-tgid"
        cls._shell(f"[ -e {tgid_opt} ] && echo 1 > {tgid_opt}")
        cmdlines = f"{tracefs}/saved_cmdlines_size"
        if cls._orig_cmdlines is None:
            first = cls._shell(f"cat {cmdlines} 2>/dev/null").strip().split("\n")[0]
            cls._orig_cmdlines = first if first.isdigit() else None
        cls._shell(
            f"[ -e {cmdlines} ] && echo {cls._CMDLINES_SIZE} > {cmdlines} 2>/dev/null"
        )
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
    def run_by_pid(
        cls, pid: int, path: str | list[str] | None = None
    ) -> subprocess.Popen | None:
        """Start kprobe tracing scoped to ``pid`` and its whole child tree.

        Optionally also constrains to files under ``path`` (a glob on the
        metadata + do_filp_open probes). ``path`` may be a single path or a list
        of paths, which are OR'd into one per-field filter. PID mode keeps the
        FULL probe set -- the ATTRS/XATTR probes (nc/sx) are scoped by
        ``set_event_pid`` here, so (unlike pure path mode) they don't leak
        device-wide.
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
    def run_by_path(cls, path: str | list[str]) -> subprocess.Popen | None:
        """Start kprobe tracing scoped (in-kernel) to files under ``path``.

        ``path`` may be a single path or a list of paths; a list is OR'd into
        one per-field filter so files under ANY listed path are captured. An
        empty string or empty list is guarded (logged + ``None``).

        Two path-mode caveats callers should know about:

        * ATTRS/XATTR events are UNAVAILABLE here -- the ``nc``/``sx`` probes
          capture only a basename, can't be path-glob-filtered, and are omitted
          to avoid leaking device-wide attribute/xattr rows (see
          ``_GLOBAL_ONLY_PROBES``). Use PID mode or capture-all for those.
        * WRITE FIREHOSE: writes (``vfs_write``/``do_iter_write``) are only
          filtered by the targets' filesystem and directory name (with a
          resolved :class:`WriteScope`), after their dentry chain was fetched
          -- every write device-wide pays that fetch. The ``do_filp_open``
          -return / ``__fput`` correlation lines can't be filtered and fire
          system-wide; under heavy write load the kernel ring buffer can drop
          them (upstream of the Python deque) and corrupt the file* map --
          writes still carry their own name. Such losses are counted
          (:meth:`read_lost_events`) and shown. When a target PID is known, prefer ``run_by_pid(pid, path)``
          (PID+path): ``set_event_pid`` is checked before any fetch and bounds
          the firehose to the target's task tree.
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
            # ONE adb round-trip: the steps run in this order in one device
            # shell (``;`` -- a failed step never stops the next). As ~30
            # separate ``adb shell`` calls a stop took 12-18 s.
            # Guarded like _self_clean: in path mode nc/sx are never installed,
            # so their per-probe disable + `-:name` removal would otherwise warn
            # on every stop. Existence tests keep stderr clean.
            steps = [f"[ -e {inst}/tracing_on ] && echo 0 > {inst}/tracing_on"]
            for name in cls._PROBE_NAMES:
                enable = f"{inst}/events/kprobes/{name}/enable"
                steps.append(f"[ -e {enable} ] && echo 0 > {enable}")
            steps.append(f"[ -e {inst}/set_event_pid ] && echo > {inst}/set_event_pid")
            if cls._orig_buffer_kb:
                steps.append(
                    f"[ -e {inst}/buffer_size_kb ] "
                    f"&& echo {cls._orig_buffer_kb} > {inst}/buffer_size_kb"
                )
            for name in cls._PROBE_NAMES:
                steps.append(
                    f'grep -q "kprobes/{name} " {events} 2>/dev/null '
                    f"&& echo {cls._dq('-:' + name)} >> {events}"
                )
            if cls._orig_cmdlines:
                cmdlines = f"{tracefs}/saved_cmdlines_size"
                steps.append(
                    f"[ -e {cmdlines} ] && echo {cls._orig_cmdlines} > {cmdlines}"
                    " 2>/dev/null"
                )
            # Instance removal LAST (after the pipe is released + probes gone).
            # (The follow instance is removed by MonitorWatch.stop before
            # this runs, and by _self_clean on the next start if it leaked.)
            steps.append(f"[ -d {inst} ] && rmdir {inst} 2>/dev/null")
            cls._shell(" ; ".join(steps))
        except Exception:
            cls.logger.debug("kprobe teardown swallowed an error", exc_info=True)
        finally:
            cls._orig_buffer_kb = None
            cls._orig_cmdlines = None
            cls._write_scope = None
            cls.last_seeded = {}

    # =========================================================================
    # Write scope (names writes from the dentry chain; see module docstring)
    # =========================================================================

    #: Set by :meth:`resolve_write_scope` for the next session; the path
    #: filter adds the in-kernel write filter from it. Cleared on teardown.
    _write_scope: WriteScope | None = None

    _SCOPE_SEP = "--sandroid-scope--"

    @classmethod
    def resolve_write_scope(cls, paths: str | list[str] | None) -> WriteScope | None:
        """Read the mount table and the targets' real paths (ONE adb call).

        ``/proc/1/mountinfo`` says where each filesystem (``dev``) and which
        directory of it is mounted; ``readlink -f`` resolves symlinked
        targets (``/sdcard``). Run off the UI thread, before the session
        starts; the result is kept for :meth:`_apply_write_filter` and
        handed to the translator. ``None`` on any failure (the translator
        then matches chains by the targets' path components alone and the
        write probes stay unfiltered).
        """
        cls._write_scope = None
        pairs = scope_aliases(paths)
        if not pairs:
            return None
        quoted = " ".join(shlex.quote(alias) for alias, _ in pairs)
        cmd = (
            "awk '{print $3, $4, $5}' /proc/1/mountinfo 2>/dev/null; "
            f"echo {cls._SCOPE_SEP}; "
            f"for p in {quoted}; do "
            'echo "$p|$(readlink -f "$p" 2>/dev/null)"; done'
        )
        try:
            out = cls._shell(cmd)
        except Exception:
            cls.logger.debug("kprobe write-scope read failed", exc_info=True)
            return None
        head, sep, tail = out.partition(cls._SCOPE_SEP)
        mounts = parse_mounts(head)
        if not sep or not mounts:
            return None
        real: dict[str, str] = {}
        for line in tail.splitlines():
            alias, bar, resolved = line.strip().partition("|")
            if bar and resolved.startswith("/"):
                real[alias] = resolved
        scope = build_write_scope(pairs, mounts, real)
        cls._write_scope = scope
        return scope

    @classmethod
    def _apply_write_filter(cls, tracefs: str, paths: str | list[str]) -> None:
        """Scope vw/diw in-kernel by the targets' filesystem + directory name.

        Only with a complete :class:`WriteScope` resolved for exactly these
        paths -- otherwise the write probes stay unfiltered (the translator
        still matches every write against the targets). Drops socket, pipe
        and eventfd writes and writes to other filesystems before they reach
        the ring buffer. The filter runs after the fetch, so it saves buffer
        space, adb bandwidth and parsing, not the fetch itself.
        """
        scope = cls._write_scope
        if scope is None or scope.paths != tuple(scope_aliases(paths)):
            return
        expr = write_filter(scope)
        if not expr:
            return
        inst = cls._instance_dir(tracefs)
        for name in ("vw", "diw"):
            cls._shell(f"echo {cls._dq(expr)} > {inst}/events/kprobes/{name}/filter")


# =============================================================================
# Write scope: dentry chain -> watched path (pure, unit-tested)
# =============================================================================


@dataclass(frozen=True)
class WriteTarget:
    """One watched directory as the kernel sees it.

    ``path`` is the canonical device path rows are keyed by; ``fs_path`` is
    the same directory inside its filesystem (``dev``; ``None`` = unknown,
    any filesystem): ``/data/data/<pkg>`` is ``/data/<pkg>`` on the /data
    filesystem, ``/sdcard`` is ``/0`` on the FUSE one.
    """

    path: str
    dev: int | None
    fs_path: str


@dataclass(frozen=True)
class WriteScope:
    """Targets resolved for one session (see ``resolve_write_scope``)."""

    #: ``(alias, canonical path)`` pairs this scope was resolved for.
    paths: tuple[tuple[str, str], ...]
    targets: tuple[WriteTarget, ...]
    #: True when every alias resolved to a filesystem (the in-kernel write
    #: filter is only installed then).
    complete: bool = True
    mounts: tuple[tuple[int, str, str], ...] = dc_field(default=(), compare=False)


def kernel_dev(major_minor: str) -> int | None:
    """``"254:44"`` (mountinfo) -> the kernel's ``dev_t`` (``s_dev``)."""
    major, sep, minor = major_minor.partition(":")
    if not sep or not major.isdigit() or not minor.isdigit():
        return None
    return (int(major) << _MINORBITS) | int(minor)


def _unescape_mount(value: str) -> str:
    """Undo mountinfo's octal escapes (space, tab, newline, backslash)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def parse_mounts(text: str) -> list[tuple[int, str, str]]:
    """``"maj:min root mountpoint"`` lines -> ``[(dev, root, mountpoint)]``."""
    mounts: list[tuple[int, str, str]] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        dev = kernel_dev(parts[0])
        root, point = _unescape_mount(parts[1]), _unescape_mount(parts[2])
        if dev is None or not root.startswith("/") or not point.startswith("/"):
            continue
        mounts.append((dev, root, point))
    return mounts


def _under(path: str, base: str) -> bool:
    """``path`` is ``base`` or below it (component-wise)."""
    return base == "/" or path == base or path.startswith(base.rstrip("/") + "/")


def _rel(path: str, base: str) -> str:
    """``path`` relative to ``base`` (``""`` or starting with ``/``)."""
    return path if base == "/" else path[len(base.rstrip("/")) :]


def _join(base: str, rest: str) -> str:
    """``base`` + a relative part from :func:`_rel`."""
    if base == "/":
        return rest or "/"
    return base.rstrip("/") + rest


def scope_aliases(paths: str | list[str] | None) -> list[tuple[str, str]]:
    """``(alias to resolve, canonical path)`` for every name of the targets.

    Every alias the path filter watches, plus ``/data/media/0`` for
    ``/sdcard`` (the FUSE lower filesystem, which apps reach directly for
    ``Android/data``).
    """
    out: list[tuple[str, str]] = []
    for alias in expand_monitor_paths(paths or []):
        canonical = canonical_device_path(alias)
        pairs = [(alias.rstrip("/") or "/", canonical)]
        if _under(canonical, "/sdcard"):
            pairs.append(("/data/media/0" + _rel(canonical, "/sdcard"), canonical))
        for pair in pairs:
            if pair not in out:
                out.append(pair)
    return out


def _mount_of(
    path: str, mounts: list[tuple[int, str, str]]
) -> tuple[int, str, str] | None:
    """The mount ``path`` lies on (longest mount point; a later one wins)."""
    best = None
    for mount in mounts:
        if _under(path, mount[2]) and (best is None or len(mount[2]) >= len(best[2])):
            best = mount
    return best


def build_write_scope(
    pairs: list[tuple[str, str]],
    mounts: list[tuple[int, str, str]],
    real: dict[str, str],
) -> WriteScope:
    """Resolve each alias to ``(dev, fs_path)``; mounts inside it are added."""
    targets: list[WriteTarget] = []
    complete = True

    def add(target: WriteTarget) -> None:
        if target not in targets:
            targets.append(target)

    for alias, canonical in pairs:
        resolved = real.get(alias) or alias
        mount = _mount_of(resolved, mounts)
        if mount is None:
            complete = False
            continue
        dev, root, point = mount
        add(WriteTarget(canonical, dev, _join(root, _rel(resolved, point))))
        # A filesystem mounted inside the target (e.g. FUSE under /storage).
        for sub_dev, sub_root, sub_point in mounts:
            if sub_point != resolved and _under(sub_point, resolved):
                add(
                    WriteTarget(
                        _join(canonical, _rel(sub_point, resolved)), sub_dev, sub_root
                    )
                )
    return WriteScope(tuple(pairs), tuple(targets), complete, tuple(mounts))


def guess_write_scope(paths: str | list[str] | None) -> WriteScope:
    """A scope without device information (mount table unreadable, tests).

    The filesystem is unknown, so each target is tried as every tail of its
    path with at least two components (``/data/data/<pkg>`` as
    ``/data/data/<pkg>`` and ``/data/<pkg>``). A target that is a mount
    point itself (``/data``) can't be guessed and stays unnamed rather than
    misnamed.
    """
    pairs = scope_aliases(paths)
    targets: list[WriteTarget] = []
    for alias, canonical in pairs:
        parts = [p for p in alias.split("/") if p]
        for start in range(len(parts) - 1):
            target = WriteTarget(canonical, None, "/" + "/".join(parts[start:]))
            if target not in targets:
                targets.append(target)
    return WriteScope(tuple(pairs), tuple(targets), False)


def chain_names(fields: dict[str, str]) -> list[str] | None:
    """A trace line's dentry names, leaf first (``n0``/``dentry`` .. ``n7``)."""
    first = fields.get("n0", fields.get("dentry"))
    if first is None or "n1" not in fields:
        return None
    return [first] + [fields.get(f"n{i}", "") for i in range(1, CHAIN_DEPTH)]


def resolve_chain(
    names: list[str] | None, dev: int | None, scope: WriteScope | None
) -> str | None:
    """The watched path a dentry chain names, or ``None``.

    ``names`` is leaf first. A chain that reaches ``/`` (a filesystem root)
    is the complete path inside that filesystem and must lie below a
    target's ``fs_path`` on the same ``dev``. A chain cut after eight names
    is accepted when it contains the target's trailing path components
    (``.../data/<pkg>/...``) or begins inside them (``<pkg>/a/.../x``); the
    longest match wins.
    """
    if not names or scope is None or not scope.targets:
        return None
    comps: list[str] = []
    complete = False
    for name in names:
        if name == "/":
            complete = True
            break
        if not name or "/" in name:
            return None  # unreadable name / anonymous inode
        comps.append(name)
    if not comps:
        return None
    comps.reverse()
    candidates = [t for t in scope.targets if dev is None or t.dev in (None, dev)]
    if complete:
        fs_path = "/" + "/".join(comps)
        below = [
            t for t in candidates if _under(fs_path, t.fs_path) and fs_path != t.fs_path
        ]
        if not below:
            return None
        best = max(below, key=lambda t: len(t.fs_path))
        return canonical_device_path(_join(best.path, _rel(fs_path, best.fs_path)))
    found, found_len = None, 0
    for t in candidates:
        tail = [p for p in t.fs_path.split("/") if p]
        if not tail:
            continue  # a filesystem root: the depth can't be known
        # The whole tail inside the chain ...
        for i in range(len(comps) - len(tail)):
            if comps[i : i + len(tail)] == tail:
                if len(tail) > found_len:
                    rest = "/" + "/".join(comps[i + len(tail) :])
                    found, found_len = _join(t.path, rest), len(tail)
                break
        # ... or the chain starts inside it (cut within the target's path).
        weakest = 1 if t.dev is not None else 2
        for j in range(min(len(tail), len(comps) - 1), weakest - 1, -1):
            if comps[:j] == tail[-j:]:
                if j > found_len:
                    found, found_len = _join(t.path, "/" + "/".join(comps[j:])), j
                break
    return canonical_device_path(found) if found else None


def write_filter(scope: WriteScope, max_clauses: int = 16) -> str | None:
    """The in-kernel vw/diw filter for a complete scope (``None``: none).

    Per target filesystem: ``dev == D`` and, unless the target is that
    filesystem's root, one of ``n1``..``n7`` names the target's directory
    -- or the chain is longer than eight names (``n7 != "/"``), which the
    translator matches itself.
    """
    if not scope.complete or not scope.targets:
        return None
    whole: set[int] = set()
    named: dict[int, list[str]] = {}
    for t in scope.targets:
        if t.dev is None:
            return None
        leaf = t.fs_path.rstrip("/").rsplit("/", 1)[-1]
        if not leaf:
            whole.add(t.dev)
            continue
        if any(c in leaf for c in '"\\'):
            return None
        leaves = named.setdefault(t.dev, [])
        if leaf not in leaves:
            leaves.append(leaf)
    clauses = [f"dev == {d}" for d in sorted(whole)]
    for dev, leaves in named.items():
        if dev in whole:
            continue
        tests = [f'n{i} == "{leaf}"' for leaf in leaves for i in range(1, CHAIN_DEPTH)]
        tests.append(f'n{CHAIN_DEPTH - 1} != "/"')
        clauses.append(f"(dev == {dev} && ({' || '.join(tests)}))")
    if not clauses or len(clauses) > max_clauses:
        return None
    return " || ".join(clauses)


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


# =============================================================================
# Follow the app: process table, task_rename, set_event_pid adds, overruns
# (pure, unit-tested; the adb side is in KprobeTracer)
# =============================================================================

#: First UID of an app (``AID_APP_START``). A UID below it (system 1000,
#: shell 2000, ...) is shared with system processes and never matched.
APP_UID_MIN = 10000

#: ``USER_HZ`` of ``/proc/<pid>/stat`` times (100 on Android/arm64).
CLK_TCK = 100

#: Comm length the kernel keeps (``TASK_COMM_LEN`` - 1).
COMM_LEN = 15

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.]+$")


@dataclass(frozen=True)
class AppProcess:
    """One process of the followed app."""

    pid: int
    uid: int | None
    name: str


@dataclass
class AppListing:
    """Result of :meth:`KprobeTracer.list_app_processes`."""

    #: Owner UID of ``/data/data/<pkg>`` (the app's UID), if readable.
    app_uid: int | None = None
    #: The app's processes, by pid.
    processes: dict[int, AppProcess] = dc_field(default_factory=dict)
    #: ``pid -> tids`` of the pids asked for (missing: the pid is gone).
    tasks: dict[int, list[int]] = dc_field(default_factory=dict)
    #: False when the output didn't look like a process table (adb failure):
    #: never read as "every process exited".
    ok: bool = False


@dataclass
class AddResult:
    """Result of :meth:`KprobeTracer.add_pids`."""

    tasks: dict[int, list[int]] = dc_field(default_factory=dict)
    #: ``pid -> starttime`` in seconds since boot.
    started: dict[int, float] = dc_field(default_factory=dict)
    #: Seconds since boot right after the writes.
    uptime: float | None = None
    #: The kernel refused a ``set_event_pid`` write (the shell said so).
    error: bool = False

    def gap(self, pid: int) -> float | None:
        """Seconds between the process start and the write (None: unknown)."""
        start = self.started.get(pid)
        if start is None or self.uptime is None:
            return None
        return max(0.0, self.uptime - start)


def is_app_process(name: str, uid: int | None, package: str, app_uid: int | None):
    """True for a process of ``package``: its UID, or its name / ``name:sub``."""
    if name == package or name.startswith(package + ":"):
        return True
    return uid is not None and uid == app_uid and uid >= APP_UID_MIN


def parse_task_lines(text: str) -> dict[int, list[int]]:
    """``T <pid> <tid> <tid> ...`` lines -> ``{pid: [tids]}`` (empty: gone)."""
    out: dict[int, list[int]] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "T" or not parts[1].isdigit():
            continue
        tids = [int(t) for t in parts[2:] if t.isdigit()]
        if tids:
            out[int(parts[1])] = tids
    return out


def parse_app_listing(text: str, package: str) -> AppListing:
    """``UID <n>`` + ``ps -A -o PID,UID,NAME`` + ``T`` lines -> AppListing."""
    listing = AppListing()
    rows: list[AppProcess] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "UID" and len(parts) == 2 and parts[1].isdigit():
            listing.app_uid = int(parts[1])
            continue
        if parts[0] == "PID" and "NAME" in parts:
            listing.ok = True  # the ps header: the table was read
            continue
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            rows.append(AppProcess(int(parts[0]), int(parts[1]), " ".join(parts[2:])))
    listing.tasks = parse_task_lines(text)
    app_uid = listing.app_uid
    if app_uid is None:
        # Learn it from the main process when /data/data isn't readable.
        main = next((r for r in rows if r.name == package), None)
        app_uid = main.uid if main is not None else None
        listing.app_uid = app_uid
    for row in rows:
        if is_app_process(row.name, row.uid, package, app_uid):
            listing.processes[row.pid] = row
    return listing


def parse_add_output(text: str) -> AddResult:
    """``T``/``S``/``U`` lines of :meth:`KprobeTracer.add_pids` -> AddResult."""
    result = AddResult(tasks=parse_task_lines(text))
    lowered = (text or "").lower()
    result.error = any(
        sign in lowered
        for sign in ("write error", "can't create", "invalid argument", "denied")
    )
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "S" and parts[1].isdigit():
            if parts[2].isdigit():
                result.started[int(parts[1])] = int(parts[2]) / CLK_TCK
        elif len(parts) == 2 and parts[0] == "U":
            try:
                result.uptime = float(parts[1])
            except ValueError:
                pass
    return result


_OVERRUN_RE = re.compile(r"^(overrun|dropped events):\s*(\d+)\s*$", re.MULTILINE)


def parse_overruns(text: str) -> int | None:
    """Sum ``overrun:`` + ``dropped events:`` over ``per_cpu/cpuN/stats``.

    ``commit overrun:`` is a different counter (nested writers), not a
    reader-lag loss, and is not matched. ``None`` when no counter was found.
    """
    found = _OVERRUN_RE.findall(text or "")
    if not found:
        return None
    return sum(int(n) for _key, n in found)


def android_comm(name: str) -> str:
    """The comm Android gives a process named ``name`` (zygote rule).

    ``SetThreadName`` keeps the LAST 15 characters of a dotted name without
    ``@`` (``org.mozilla.firefox`` -> ``mozilla.firefox``), else the first.
    """
    if len(name) <= COMM_LEN or "@" in name or "." not in name:
        return name[:COMM_LEN]
    return name[-COMM_LEN:]


def rename_filter(package: str | None) -> str:
    """In-kernel filter for ``task:task_rename`` (new app processes).

    A zygote child renames itself from the zygote's comm (``main`` -- ART
    names the zygote's main thread so -- or ``zygote*``/``usap*``) to
    its nice name; the package's 15-char comm prefix and Android's actual
    (last-15) comm catch the main process of an app started any other way.
    ``package=None``: the zygote clauses only. Every match is only a
    candidate: the follower checks UID and name before adding it.
    """
    clauses = ['oldcomm == "main"', 'oldcomm ~ "zygote*"', 'oldcomm ~ "usap*"']
    if package and _PACKAGE_RE.match(package):
        prefix = f'newcomm ~ "{package[:COMM_LEN]}*"'
        exact = f'newcomm == "{android_comm(package)}"'
        for clause in (prefix, exact):
            if clause not in clauses:
                clauses.append(clause)
    return " || ".join(clauses)


def exit_filter(package: str | None) -> str | None:
    """In-kernel filter for ``sched:sched_process_exit`` of the app's main
    thread (its comm), or ``None`` when the package can't be filtered on.
    """
    if not package or not _PACKAGE_RE.match(package):
        return None
    clauses = [f'comm == "{android_comm(package)}"']
    prefix = f'comm == "{package[:COMM_LEN]}"'
    if prefix not in clauses:
        clauses.append(prefix)
    return " || ".join(clauses)


_EXIT_RE = re.compile(r"sched_process_exit:\s+comm=.*?\s+pid=(\d+)")


def parse_process_exit(line: str) -> int | None:
    """The pid (TID) of a ``sched_process_exit`` trace line, or None."""
    m = _EXIT_RE.search(line or "")
    return int(m.group(1)) if m else None


_RENAME_RE = re.compile(
    r"task_rename:\s+pid=(\d+)\s+oldcomm=(.*?)\s+newcomm=(.*?)"
    r"(?:\s+oom_score_adj=\S*)?\s*$"
)


def parse_task_rename(line: str) -> tuple[int, str, str] | None:
    """``(pid, oldcomm, newcomm)`` of a ``task_rename`` trace line."""
    m = _RENAME_RE.search(line or "")
    if m is None:
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def process_label(name: str, package: str) -> str:
    """Short name of an app process: ``main``, ``tab_17``, ``gpu``...

    ``<pkg>`` is ``main``; ``<pkg>:sandboxed_tab_17`` is ``tab_17`` (the
    ``sandboxed_`` prefix is dropped); a class-name suffix keeps its last
    part. Anything else (a process sharing the app's UID) keeps its name.
    """
    if name == package:
        return "main"
    if name.startswith(package + ":"):
        sub = name[len(package) + 1 :]
        sub = re.split(r"[.$]", sub)[-1] or sub
        if sub.startswith("sandboxed_"):
            sub = sub[len("sandboxed_") :]
        return sub or name
    return name
