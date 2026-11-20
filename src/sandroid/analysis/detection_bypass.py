"""Native detection-bypass managers for Android app analysis.

Sandroid ships self-contained Frida bypasses for the bypasses needed to
intercept and analyse hardened apps, so interception does not depend on an
external package or a pre-compiled frida bundle being present.

This module provides:

- :class:`BypassManagerBase` — data holder for one bypass: its Frida payload,
  hook registry, display name, and load-order priority. The lifecycle lives in
  :class:`BypassService`, which assembles all payloads into one persistent
  flag-gated script.
- :class:`FridaDetectionBypassManager` — anti-anti-Frida prelude (process
  self-kill suppression, ``/proc/*/maps`` filtering, frida-needle ``strstr``).
- :class:`RootDetectionBypassManager` — su/magisk path hiding, ``su`` exec
  blocking, root-app package hiding, ``release-keys`` build tags.
- :class:`DebugDetectionBypassManager` — ``Debug.isDebuggerConnected`` /
  ``waitingForDebugger`` and ``TracerPid`` filtering.
- :class:`IntegrityBypassManager` — PairIP license-check / Play gate.
- :class:`EmulatorDetectionBypassManager` — one coherent device profile for
  ``Build.*``, qemu/goldfish/ranchu property hiding, emulator file/pipe hiding
  and TelephonyManager fakes (ported from TrigDroid and Dexray Intercept).
- :class:`BypassService` — process-wide singleton that owns the armed/active
  category sets and one persistent flag-gated Frida script (toggled via the
  ``set_flags`` RPC — instant, gap-free, one Java bridge).

BypassService is the only source of bypasses in Sandroid (Dexray Intercept's
own bypass group is mutually exclusive with it). Hook sets marked "ported
from TrigDroid" come from the MIT-licensed TrigDroid project.

**EXPERIMENTAL.** All bypass categories (SSL unpinning incl. the native
cronet/BoringSSL and mbedTLS/MNS tiers, PairIP/integrity, root/Frida/debug/
emulator detection) are experimental, off by default, and only applied after an
explicit analyst toggle. Results must be verified; a bypass can silently miss.

For authorized security testing, forensic analysis, and research only.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import frida

from sandroid.core.toolbox import Toolbox
from sandroid.services import (
    get_spotlight_service,
    get_task_service,
    get_tool_usage_service,
)

logger = logging.getLogger(__name__)

# Max seconds to wait for a Frida script to finish loading (script.load runs
# on the Job's own thread; start_job returns before it completes). Generous to
# tolerate slow emulators loading large hook sets.
_READINESS_TIMEOUT = 15.0


@functools.lru_cache(maxsize=1)
def _java_bridge_prelude() -> str:
    """JS that defines global ``Java`` from frida_tools' version-matched bundle.

    frida 17 no longer auto-injects the global ``Java`` (and ``ObjC``) into the
    agent runtime, so every hook-set that references the bare global ``Java``
    throws ``ReferenceError: 'Java' is not defined``. We restore it by reusing
    the prebuilt ``frida_tools/bridges/java.js`` bundle — the exact one the
    frida REPL loads on v17, so it stays version-synced with the installed
    frida. Mirrors repl_agent.js. ``ObjC`` is intentionally NOT injected: the
    hook-sets are Android-only and reference only ``Java``.
    """
    try:
        from pathlib import Path

        import frida_tools

        src = (Path(frida_tools.__file__).parent / "bridges" / "java.js").read_text(
            "utf-8"
        )
        # java.js evaluates to `var bridge = (function () { ... })();`; scope it
        # in an IIFE and publish the result as the global `Java`.
        return (
            "(function () {\n"
            + src
            + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n"
            + "})();\n"
        )
    except Exception as exc:
        logger.warning(
            "Java bridge prelude unavailable (%s); hook-sets may fail on frida 17",
            exc,
        )
        return ""


#: Realm-top helpers every category may use (part of the merged script's
#: preamble). Frida 17 removed the static ``Module.findExportByName(lib, n)``
#: and the static ``Memory`` string read/write helpers: a hook
#: written against them throws inside its ``try`` and silently never
#: installs. Use these helpers and the NativePointer instance methods
#: (``p.readUtf8String()``, ``p.writeUtf8String(s)``) instead.
_PREAMBLE_HEAD_JS = r"""
// Lazy categories: every category body is registered here and only runs
// (installs its native and Java hooks) the first time its flag is on --
// baked in at load or flipped by setFlags. An SSL-only session installs only
// SSL's hooks; nothing a category does not need is in the process. Hooks
// stay installed (flag-gated) after a flag goes off; the emulator category
// removes its own (see FLAG_LISTENERS).
var CATEGORY_INSTALLERS = [];  // [category, installer], in priority order
var INSTALLED = {};
var INSTALL_FAILED = [];

function _installFailed(category, e) {
    if (INSTALL_FAILED.indexOf(category) === -1) INSTALL_FAILED.push(category);
    send({merge_error: category, error: '' + e});
}

// Java.perform bodies often run later (after resume on a paused spawn);
// while a category installs, wrap them so a throw inside one is recorded
// for that category too, not lost as an unhandled script error.
function _installCategory(category, installer) {
    if (INSTALLED[category]) return;
    INSTALLED[category] = true;
    var hasJava = typeof Java !== 'undefined' && Java !== null &&
        typeof Java.perform === 'function';
    var perform = hasJava ? Java.perform : null;
    if (hasJava) {
        try {
            Java.perform = function (fn) {
                return perform.call(Java, function () {
                    try {
                        return fn.apply(this, arguments);
                    } catch (e) {
                        _installFailed(category, e);
                    }
                });
            };
        } catch (e) {
            hasJava = false;
        }
    }
    try {
        installer();
    } catch (e) {
        _installFailed(category, e);
    } finally {
        if (hasJava) {
            try { Java.perform = perform; } catch (e) {}
        }
    }
}

function registerCategory(category, installer) {
    CATEGORY_INSTALLERS.push([category, installer]);
    if (FLAGS[category]) _installCategory(category, installer);
}

function _installEnabledCategories() {
    for (var i = 0; i < CATEGORY_INSTALLERS.length; i++) {
        var c = CATEGORY_INSTALLERS[i];
        if (FLAGS[c[0]]) _installCategory(c[0], c[1]);
    }
}

function _findExport(lib, name) {
    try {
        var m = Process.findModuleByName(lib);
        if (m === null) return null;
        return m.findExportByName(name);
    } catch (e) {
        return null;
    }
}
function _libcExport(name) { return _findExport('libc.so', name); }

"""

#: C fast path of the shared path hider (CModule; see the preamble's
#: ``hidePaths``). Compiled in the target by Frida's TinyCC.
_PATH_HIDER_C = r"""
/* Sandroid path hider: C fast path for the libc file probes.
 *
 * Every access/faccessat/fopen/stat/lstat/fstatat call lands here. Only a
 * path that a cheap, case-insensitive name check marks as a candidate for an
 * enabled hiding class calls into JS (sandroid_path_decide), which makes the
 * exact decision; every other call goes straight to the original without
 * touching the JS runtime. The real errno is handed back to the caller.
 */
#include <gum/guminterceptor.h>

#ifndef NULL
# define NULL ((void *) 0)
#endif

/* bit 1: root names on, bit 2: emulator names on (JS keeps it current). */
extern volatile int sandroid_path_flags;
extern int sandroid_path_decide (const char * path, void * return_address);
extern int * sandroid_errno (void);

extern int real_access (const char * path, int mode);
extern int real_faccessat (int dirfd, const char * path, int mode, int flags);
extern void * real_fopen (const char * path, const char * mode);
extern int real_stat (const char * path, void * st);
extern int real_lstat (const char * path, void * st);
extern int real_fstatat (int dirfd, const char * path, void * st, int flags);

static int
lower (int c)
{
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int
contains (const char * s, const char * needle)
{
  for (; *s != '\0'; s++)
  {
    const char * a = s;
    const char * b = needle;
    while (*b != '\0' && lower (*a) == *b)
    {
      a++;
      b++;
    }
    if (*b == '\0')
      return 1;
  }
  return 0;
}

static int
equals (const char * a, const char * b)
{
  while (*a != '\0' && *b != '\0' && lower (*a) == *b)
  {
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static const char *
base_name (const char * p)
{
  const char * b = p;
  for (; *p != '\0'; p++)
  {
    if (*p == '/')
      b = p + 1;
  }
  return b;
}

/* Superset of the root category's _looksLikeRootPath(). */
static int
root_candidate (const char * p)
{
  const char * b = base_name (p);
  return equals (b, "su") || equals (b, "busybox") || equals (b, "supersu") ||
      equals (b, "daemonsu") || contains (b, "magisk") ||
      contains (b, "superuser") || contains (p, "/data/adb/");
}

/* Superset of the emulator category's _isEmuPath(). */
static int
emu_candidate (const char * p)
{
  static const char * needles[] = {
    "qemu", "goldfish", "ranchu", "genyd", "vbox", "nox", "ttvm", "microvirt",
    "windroyed", "droid4x", "andy", "x86.prop", "android_x86", NULL
  };
  int i;
  for (i = 0; needles[i] != NULL; i++)
  {
    if (contains (p, needles[i]))
      return 1;
  }
  return 0;
}

static int
candidate (const char * p)
{
  int f = sandroid_path_flags;
  if (f == 0 || p == NULL)
    return 0;
  return ((f & 1) != 0 && root_candidate (p)) ||
      ((f & 2) != 0 && emu_candidate (p));
}

/* Ask JS; on "hide" the caller sees errno ENOENT. */
static int
hide (const char * p)
{
  GumInvocationContext * ic = gum_interceptor_get_current_invocation ();
  if (!sandroid_path_decide (p, gum_invocation_context_get_return_address (ic)))
    return 0;
  ic->system_error = 2;
  return 1;
}

/* The interceptor restores errno from system_error on return: copy the
 * original call's errno there, or every real failure reads as errno 0. */
static void
keep_errno (void)
{
  gum_interceptor_get_current_invocation ()->system_error = *sandroid_errno ();
}

int
replace_access (const char * path, int mode)
{
  int r;
  if (candidate (path) && hide (path))
    return -1;
  r = real_access (path, mode);
  keep_errno ();
  return r;
}

int
replace_faccessat (int dirfd, const char * path, int mode, int flags)
{
  int r;
  if (candidate (path) && hide (path))
    return -1;
  r = real_faccessat (dirfd, path, mode, flags);
  keep_errno ();
  return r;
}

void *
replace_fopen (const char * path, const char * mode)
{
  void * r;
  if (candidate (path) && hide (path))
    return NULL;
  r = real_fopen (path, mode);
  keep_errno ();
  return r;
}

int
replace_stat (const char * path, void * st)
{
  int r;
  if (candidate (path) && hide (path))
    return -1;
  r = real_stat (path, st);
  keep_errno ();
  return r;
}

int
replace_lstat (const char * path, void * st)
{
  int r;
  if (candidate (path) && hide (path))
    return -1;
  r = real_lstat (path, st);
  keep_errno ();
  return r;
}

int
replace_fstatat (int dirfd, const char * path, void * st, int flags)
{
  int r;
  if (candidate (path) && hide (path))
    return -1;
  r = real_fstatat (dirfd, path, st, flags);
  keep_errno ();
  return r;
}
"""

#: C fast path of the shared /proc filter (CModule attach listener; see the
#: preamble's ``filterProcFiles``).
_PROC_FILTER_C = r"""
/* Sandroid /proc filter: C fast path for the open family (attach listener).
 *
 * Only an open of this process's own /proc/{self,thread-self,<pid>}
 * [/task/<tid>]/{maps,smaps,status}, while a /proc filter is on, calls into
 * JS (sandroid_proc_swap) to answer with a filtered memfd; every other open
 * returns without touching the JS runtime.
 */
#include <gum/guminterceptor.h>

#ifndef NULL
# define NULL ((void *) 0)
#endif

extern volatile int sandroid_proc_flags;
extern volatile int sandroid_own_pid;
extern int sandroid_proc_swap (int fd, int kind, int oflags);

typedef struct _ProcState ProcState;
struct _ProcState
{
  int kind;
  int oflags;
};

static int
starts (const char * s, const char * prefix)
{
  while (*prefix != '\0')
  {
    if (*s != *prefix)
      return 0;
    s++;
    prefix++;
  }
  return 1;
}

static int
same (const char * a, const char * b)
{
  while (*a != '\0' && *a == *b)
  {
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

/* 1 maps, 2 smaps, 3 status, 0 anything else. */
static int
proc_kind (const char * p)
{
  int value = 0;
  int n = 0;
  if (p == NULL || !starts (p, "/proc/"))
    return 0;
  p += 6;
  if (starts (p, "self/"))
    p += 5;
  else if (starts (p, "thread-self/"))
    p += 12;
  else
  {
    while (*p >= '0' && *p <= '9')
    {
      value = value * 10 + (*p - '0');
      p++;
      n++;
    }
    if (n == 0 || *p != '/' || value != sandroid_own_pid)
      return 0;
    p++;
  }
  if (starts (p, "task/"))
  {
    p += 5;
    n = 0;
    while (*p >= '0' && *p <= '9')
    {
      p++;
      n++;
    }
    if (n == 0 || *p != '/')
      return 0;
    p++;
  }
  if (same (p, "maps"))
    return 1;
  if (same (p, "smaps"))
    return 2;
  if (same (p, "status"))
    return 3;
  return 0;
}

void
onEnter (GumInvocationContext * ic)
{
  ProcState * s = GUM_IC_GET_INVOCATION_DATA (ic, ProcState);
  int path_index = (int) (gsize) gum_invocation_context_get_listener_function_data (ic);
  s->kind = 0;
  if (sandroid_proc_flags == 0)
    return;
  s->kind = proc_kind (
      (const char *) gum_invocation_context_get_nth_argument (ic, path_index));
  if (s->kind != 0)
    s->oflags = (int) (gsize) gum_invocation_context_get_nth_argument (ic,
        path_index + 1);
}

void
onLeave (GumInvocationContext * ic)
{
  ProcState * s = GUM_IC_GET_INVOCATION_DATA (ic, ProcState);
  int fd;
  int swapped;
  if (s->kind == 0)
    return;
  fd = (int) (gsize) gum_invocation_context_get_return_value (ic);
  if (fd < 0)
    return;
  swapped = sandroid_proc_swap (fd, s->kind, s->oflags);
  if (swapped >= 0)
    gum_invocation_context_replace_return_value (ic, (gpointer) (gsize) swapped);
}
"""

_PREAMBLE_TAIL_JS = r"""
// Shared path hider: ONE Interceptor.replace per libc probe (access,
// faccessat, fopen, stat, lstat, fstatat; the 64 names are aliases on
// bionic) for every category that hides files (root, emulator). A hidden
// path gets -1 / NULL with errno = ENOENT, like a missing file, and the real
// call never runs (no leaked FILE*). Two categories cannot each replace the
// same export, hence the registry.
//
// Fast path: the replacements are C (PATH_HIDER_C, a CModule). stat and
// friends are among the hottest calls at ART boot, so a call only enters
// JS when a cheap name check marks the path as a candidate of an enabled
// class (bits in _pathFlags, kept current on every setFlags); all others go
// straight to the original. If the CModule cannot be built, the same
// replacements run in JS (checking FLAGS before touching the path).
// PATH_HIDER_MODE says which one is active ('cmodule' / 'js').
var PATH_HIDERS = [];  // {cat, test(path, returnAddress), cls}
var _pathHiderInstalled = false;
var _ENOENT = 2;
var PATH_HIDER_MODE = null;
var _pathFlags = null;  // int the C fast path reads
var _pathKeep = [];     // CModule + NativeCallbacks, kept alive

function _anyPathHiderOn() {
    for (var i = 0; i < PATH_HIDERS.length; i++) {
        if (FLAGS[PATH_HIDERS[i].cat]) return true;
    }
    return false;
}

function _pathHiderBits() {
    var bits = 0;
    for (var i = 0; i < PATH_HIDERS.length; i++) {
        if (FLAGS[PATH_HIDERS[i].cat]) bits |= PATH_HIDERS[i].cls;
    }
    return bits;
}

function _syncPathFlags() {
    if (_pathFlags !== null) _pathFlags.writeS32(_pathHiderBits());
}

function _hiddenBy(path, returnAddress) {
    for (var i = 0; i < PATH_HIDERS.length; i++) {
        var h = PATH_HIDERS[i];
        try {
            if (FLAGS[h.cat] && h.test(path, returnAddress)) return h.cat;
        } catch (e) {}
    }
    return null;
}

// Tolerant C-string read: never throws (a name cut mid-UTF-8 throws in
// readUtf8String on Frida 17).
function _readPath(p) {
    try { return p.readUtf8String(); } catch (e) {}
    try { return p.readCString(); } catch (e) {}
    return null;
}

var _pathProbeAddrs = {};  // one replacement per address (aliases share one)

// [export, return type, argument types, path argument, value when hidden]
var PATH_PROBES = [
    ['access', 'int', ['pointer', 'int'], 0, -1],
    ['faccessat', 'int', ['int', 'pointer', 'int', 'int'], 1, -1],
    ['fopen', 'pointer', ['pointer', 'pointer'], 0, NULL],
    ['stat', 'int', ['pointer', 'pointer'], 0, -1],
    ['lstat', 'int', ['pointer', 'pointer'], 0, -1],
    ['fstatat', 'int', ['int', 'pointer', 'pointer', 'int'], 1, -1],
    ['fopen64', 'pointer', ['pointer', 'pointer'], 0, NULL],
    ['stat64', 'int', ['pointer', 'pointer'], 0, -1],
    ['lstat64', 'int', ['pointer', 'pointer'], 0, -1],
    ['fstatat64', 'int', ['int', 'pointer', 'pointer', 'int'], 1, -1]
];

function _replacePathProbeJs(sym, retType, argTypes, pathIndex, failValue) {
    var addr = _libcExport(sym);
    if (addr === null || _pathProbeAddrs[addr.toString()]) return;
    _pathProbeAddrs[addr.toString()] = sym;
    // SystemFunction (not NativeFunction): its result carries the errno the
    // real call set, which the pass-through must hand back to the caller.
    var original = new SystemFunction(addr, retType, argTypes);
    Interceptor.replace(addr, new NativeCallback(function () {
        if (_anyPathHiderOn()) {
            var path = _readPath(arguments[pathIndex]);
            var cat = path === null ? null : _hiddenBy(path, this.returnAddress);
            if (cat !== null) {
                try { this.errno = _ENOENT; } catch (e) {}
                send({type: 'info', hook: cat + '-bypass:' + sym + '(' + path + ')'});
                return failValue;
            }
        }
        // A SystemFunction call from inside the replacement reaches the
        // original implementation, not this callback again. Without passing
        // its errno on, every real failure (ENOENT, EACCES) read as errno 0.
        var r = original.apply(null, arguments);
        this.errno = r.errno;
        return r.value;
    }, retType, argTypes));
}

// The C fast path for the base probes; throws when CModule is unavailable.
function _installPathHiderC() {
    if (typeof CModule === 'undefined') throw new Error('no CModule');
    var errnoFn = _libcExport('__errno');
    if (errnoFn === null) throw new Error('no __errno');
    var flags = Memory.alloc(4);
    var decide = new NativeCallback(function (pathPtr, returnAddress) {
        var path = _readPath(pathPtr);
        var cat = path === null ? null : _hiddenBy(path, returnAddress);
        if (cat === null) return 0;
        send({type: 'info', hook: cat + '-bypass:' + path});
        return 1;
    }, 'int', ['pointer', 'pointer']);
    var symbols = {
        sandroid_path_flags: flags,
        sandroid_path_decide: decide,
        sandroid_errno: errnoFn
    };
    var base = ['access', 'faccessat', 'fopen', 'stat', 'lstat', 'fstatat'];
    var addrs = {};
    base.forEach(function (sym) {
        var a = _libcExport(sym);
        if (a === null) throw new Error('no ' + sym);
        addrs[sym] = a;
        symbols['real_' + sym] = a;
    });
    var cm = new CModule(PATH_HIDER_C, symbols);
    _pathKeep.push(cm, decide);
    _pathFlags = flags;
    _syncPathFlags();
    base.forEach(function (sym) {
        Interceptor.replace(addrs[sym], cm['replace_' + sym]);
        _pathProbeAddrs[addrs[sym].toString()] = sym;
    });
}

function hidePaths(category, test, cls) {
    PATH_HIDERS.push({cat: category, test: test, cls: cls});
    if (_pathHiderInstalled) {
        _syncPathFlags();
        return;
    }
    _pathHiderInstalled = true;
    FLAG_LISTENERS.push(_syncPathFlags);
    try {
        _installPathHiderC();
        PATH_HIDER_MODE = 'cmodule';
    } catch (e) {
        PATH_HIDER_MODE = 'js';
        send({type: 'info', hook: 'path-hider:js-fallback', error: '' + e});
    }
    // Remaining probes (all of them in JS mode; distinct 64 aliases in C
    // mode -- on bionic they are the same address and skipped).
    PATH_PROBES.forEach(function (p) {
        try {
            _replacePathProbeJs(p[0], p[1], p[2], p[3], p[4]);
        } catch (e) {
            send({type: 'debug', hook: 'path-hider:' + p[0], error: e.message});
        }
    });
    send({type: 'info', hook: 'path-hider:' + PATH_HIDER_MODE});
}

// Shared /proc filter for the frida and debug categories. It replaces the old
// libc `read` hooks: an Interceptor.attach on `read` installed before resume
// crashed every paused spawn of a real app (SIGSEGV in perfetto_hprof_,
// API 35). Instead the open/openat that opens one of this process's own
// /proc/{self,thread-self,<pid>}[/task/<tid>]/{maps,smaps,status} files is
// answered with a memfd holding the filtered text (only when a filter
// changed something; otherwise the real fd, rewound, is kept). `read` is
// never hooked.
//
// Fast path: the open-family listener is C (PROC_FILTER_C); it only enters
// JS for those few files while a filter is on. JS fallback otherwise
// (PROC_FILTER_MODE). The text is streamed in 64 KiB chunks, decoded
// byte-wise (latin1: never throws, bytes survive exactly) and filtered line
// by line; a file over PROC_FILTER_MAX_BYTES passes through unfiltered (a
// missed hide, never a crash or an empty read). Any failure closes the memfd
// and rewinds the real fd, so the app always reads the real file at worst.
//
// Remaining tells of a swapped fd: readlink(/proc/self/fd/N) shows
// "/memfd:proc (deleted)", and fstat() shows a non-zero st_size and a tmpfs
// device where a /proc file has size 0. The memfd is close-on-exec only if
// the app opened the file with O_CLOEXEC.
var PROC_FILTERS = [];  // {cat, kinds, line(line, kind, state) -> line|null}
var _procFilterInstalled = false;
var PROC_FILTER_MODE = null;
var PROC_FILTER_MAX_BYTES = 8 * 1024 * 1024;
var _PROC_CHUNK = 64 * 1024;
var _PROC_KINDS = [null, 'maps', 'smaps', 'status'];
var _O_CLOEXEC = 0x80000;
var _MFD_CLOEXEC = 1;
var _EINTR = 4;
var _PROC_RE = /^\/proc\/(self|thread-self|\d+)(?:\/task\/\d+)?\/(maps|smaps|status)$/;
var _procIo = null;
var _procFlags = null;  // int the C fast path reads
var _procKeep = [];

function _procKind(path) {
    if (path === null || path.indexOf('/proc/') !== 0) return null;
    var m = _PROC_RE.exec(path);
    if (m === null) return null;
    if (/^\d+$/.test(m[1]) && parseInt(m[1], 10) !== Process.id) return null;
    return m[2];
}

function _anyProcFilterOn() {
    for (var i = 0; i < PROC_FILTERS.length; i++) {
        if (FLAGS[PROC_FILTERS[i].cat]) return true;
    }
    return false;
}

function _syncProcFlags() {
    if (_procFlags !== null) _procFlags.writeS32(_anyProcFilterOn() ? 1 : 0);
}

function _procFiltersFor(kind) {
    var out = [];
    for (var i = 0; i < PROC_FILTERS.length; i++) {
        var f = PROC_FILTERS[i];
        if (FLAGS[f.cat] && f.kinds.indexOf(kind) !== -1) out.push(f);
    }
    return out;
}

function _procNative() {
    if (_procIo !== null) return _procIo;
    var memfd = _libcExport('memfd_create');
    var syscall = _libcExport('syscall');
    var nr = {arm64: 279, x64: 319, arm: 385, ia32: 356}[Process.arch];
    _procIo = {
        read: new NativeFunction(_libcExport('read'), 'long', ['int', 'pointer', 'ulong']),
        // SystemFunction: a failed write's errno tells EINTR (retry) apart.
        write: new SystemFunction(_libcExport('write'), 'long', ['int', 'pointer', 'ulong']),
        lseek: new NativeFunction(_libcExport('lseek'), 'long', ['int', 'long', 'int']),
        close: new NativeFunction(_libcExport('close'), 'int', ['int']),
        memfd: memfd !== null
            ? new NativeFunction(memfd, 'int', ['pointer', 'uint'])
            : (syscall !== null && nr !== undefined
                ? (function (fn) {
                    return function (name, flags) { return fn(nr, name, flags); };
                })(new NativeFunction(syscall, 'long', ['long', 'pointer', 'uint']))
                : null)
    };
    return _procIo;
}

function _latin1(bytes) {
    var u = new Uint8Array(bytes);
    var s = '';
    for (var i = 0; i < u.length; i += 4096) {
        s += String.fromCharCode.apply(null, u.subarray(i, i + 4096));
    }
    return s;
}

// Write every byte of `text` (latin1, as decoded) to `fd`; retries partial
// writes and EINTR. False on any other failure.
function _procWriteAll(io, fd, text) {
    if (text.length === 0) return true;
    var u = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i++) u[i] = text.charCodeAt(i) & 0xff;
    var mem = Memory.alloc(u.length);
    mem.writeByteArray(u.buffer);
    var done = 0;
    var interrupted = 0;
    while (done < u.length) {
        var r = io.write(fd, mem.add(done), u.length - done);
        var n = Number(r.value);
        if (n > 0) {
            done += n;
        } else if (n < 0 && r.errno === _EINTR && ++interrupted < 100) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

// Filter complete lines; `last` is a final line without its newline.
function _procFilterLines(lines, kind, filters, state, last) {
    var out = '';
    var changed = false;
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        for (var j = 0; j < filters.length && line !== null; j++) {
            line = filters[j].line(line, kind, state);
        }
        if (line !== lines[i]) changed = true;
        if (line !== null) out += (last && i === lines.length - 1) ? line : line + '\n';
    }
    return {text: out, changed: changed};
}

// The filtered memfd for the just-opened /proc `fd`, or -1 to keep `fd`
// (always rewound to the start then).
function _procFilteredFd(fd, kind, filters, oflags) {
    var io = _procNative();
    if (io.memfd === null) return -1;
    var mfd = -1;
    var handed = false;
    try {
        var mfdFlags = (oflags & _O_CLOEXEC) ? _MFD_CLOEXEC : 0;
        mfd = Number(io.memfd(Memory.allocUtf8String('proc'), mfdFlags));
        if (mfd < 0) return -1;
        var buf = Memory.alloc(_PROC_CHUNK);
        var total = 0;
        var carry = '';
        var changed = false;
        var state = {};
        for (;;) {
            var n = Number(io.read(fd, buf, _PROC_CHUNK));
            if (n < 0) return -1;
            if (n === 0) break;
            total += n;
            if (total > PROC_FILTER_MAX_BYTES) return -1;  // missed hide
            var lines = (carry + _latin1(buf.readByteArray(n))).split('\n');
            carry = lines.pop();
            var part = _procFilterLines(lines, kind, filters, state, false);
            changed = changed || part.changed;
            if (!_procWriteAll(io, mfd, part.text)) return -1;
        }
        if (carry.length) {
            var tail = _procFilterLines([carry], kind, filters, state, true);
            changed = changed || tail.changed;
            if (!_procWriteAll(io, mfd, tail.text)) return -1;
        }
        if (!changed) return -1;
        io.lseek(mfd, 0, 0);  // SEEK_SET
        handed = true;
        return mfd;
    } catch (e) {
        return -1;
    } finally {
        if (handed) {
            io.close(fd);
        } else {
            if (mfd >= 0) io.close(mfd);
            io.lseek(fd, 0, 0);  // the caller reads the real file from the start
        }
    }
}

function _procSwap(fd, kind, oflags) {
    if (kind === null) return -1;
    var filters = _procFiltersFor(kind);
    if (filters.length === 0) return -1;
    try {
        return _procFilteredFd(fd, kind, filters, oflags);
    } catch (e) {
        return -1;
    }
}

// [export, path argument]; fortified callers use __open_2/__openat_2.
var PROC_OPENS = [['open', 0], ['openat', 1], ['__open_2', 0], ['__openat_2', 1]];

function _installProcFilterC() {
    if (typeof CModule === 'undefined') throw new Error('no CModule');
    var flags = Memory.alloc(4);
    var pid = Memory.alloc(4);
    pid.writeS32(Process.id);
    var swap = new NativeCallback(function (fd, kind, oflags) {
        return _procSwap(fd, _PROC_KINDS[kind] || null, oflags);
    }, 'int', ['int', 'int', 'int']);
    var cm = new CModule(PROC_FILTER_C, {
        sandroid_proc_flags: flags,
        sandroid_own_pid: pid,
        sandroid_proc_swap: swap
    });
    _procKeep.push(cm, swap);
    _procFlags = flags;
    _syncProcFlags();
    var seen = {};
    PROC_OPENS.forEach(function (e) {
        var addr = _libcExport(e[0]);
        if (addr === null || seen[addr.toString()]) return;
        seen[addr.toString()] = true;
        Interceptor.attach(addr, cm, ptr(e[1]));
    });
}

function _installProcFilterJs() {
    var seen = {};
    PROC_OPENS.forEach(function (e) {
        var addr = _libcExport(e[0]);
        if (addr === null || seen[addr.toString()]) return;
        seen[addr.toString()] = true;
        var pathIndex = e[1];
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._kind = null;
                    if (!_anyProcFilterOn()) return;  // flags before any work
                    var kind = _procKind(_readPath(args[pathIndex]));
                    if (kind !== null && _procFiltersFor(kind).length) {
                        this._kind = kind;
                        this._oflags = args[pathIndex + 1].toInt32();
                    }
                },
                onLeave: function (rv) {
                    if (this._kind === null) return;
                    var fd = rv.toInt32();
                    if (fd < 0) return;
                    var mfd = _procSwap(fd, this._kind, this._oflags);
                    if (mfd >= 0) rv.replace(ptr(mfd));
                }
            });
        } catch (err) {
            send({type: 'debug', hook: 'proc-filter:' + e[0], error: err.message});
        }
    });
}

function filterProcFiles(category, kinds, line) {
    PROC_FILTERS.push({cat: category, kinds: kinds, line: line});
    if (_procFilterInstalled) {
        _syncProcFlags();
        return;
    }
    _procFilterInstalled = true;
    FLAG_LISTENERS.push(_syncProcFlags);
    try {
        _installProcFilterC();
        PROC_FILTER_MODE = 'cmodule';
    } catch (e) {
        PROC_FILTER_MODE = 'js';
        send({type: 'info', hook: 'proc-filter:js-fallback', error: '' + e});
        _installProcFilterJs();
    }
    send({type: 'info', hook: 'proc-filter:' + PROC_FILTER_MODE});
}

// Frida's traces in /proc: maps/smaps entries of its agent and thread names.
var FRIDA_TOKENS = ['frida', 'gum-js-loop', 'gmain', 'gdbus', 'linjector', 'gadget'];

function _hasFridaToken(line) {
    for (var i = 0; i < FRIDA_TOKENS.length; i++) {
        if (line.indexOf(FRIDA_TOKENS[i]) !== -1) return true;
    }
    return false;
}

// Line filter (null drops the line). status: keep the Name: line (a status
// without one is a tell) and rename the thread; smaps: drop whole entries (a
// header line plus its attribute lines); maps: drop the line.
function hideFridaLine(line, kind, state) {
    if (kind === 'status') {
        return (line.indexOf('Name:') === 0 && _hasFridaToken(line)) ? 'Name:\tThread-2' : line;
    }
    if (kind === 'smaps') {
        if (/^[0-9a-f]+-[0-9a-f]+ /.test(line)) state.fridaSkip = _hasFridaToken(line);
        return state.fridaSkip ? null : line;
    }
    return _hasFridaToken(line) ? null : line;
}

function zeroTracerPidLine(line) {
    return /^TracerPid:[ \t]*\d+$/.test(line) ? 'TracerPid:\t0' : line;
}
"""

_PREAMBLE_HELPERS_JS = (
    _PREAMBLE_HEAD_JS
    + "var PATH_HIDER_C = "
    + json.dumps(_PATH_HIDER_C)
    + ";\nvar PROC_FILTER_C = "
    + json.dumps(_PROC_FILTER_C)
    + ";\n"
    + _PREAMBLE_TAIL_JS
)


# ---------------------------------------------------------------------------
# Spawn-reliability failure taxonomy
# ---------------------------------------------------------------------------

# Substrings (lowercased) that mark a wedged/crashed *frida-server* transport
# — the remedy is a server restart, not a bare re-spawn.
_DIRTY_MARKERS = (
    "restart frida-server",
    "connection is closed",
    "transporterror",
    "protocolerror",
    "transport",
    "timeout",
    "need gadget",
    "connection issue",
    # A spawn that yields no PID is the canonical symptom of a down/wedged
    # frida-server (apply_to_fresh_spawn emits "... (no PID — is frida-server
    # running?)"); route it to the server-restart remedy, not a bare re-spawn.
    "no pid",
    "is frida-server running",
    # After a snapshot load the cached frida device object is dead
    # ("device is gone"); a fresh device handle / server restart recovers.
    "device is gone",
    "device has been lost",
    "frida-server not running",
)

#: Shown instead of frida-core's "need Gadget to attach on jailed Android",
#: which means the client fell back to jailed mode: no frida-server answers.
FRIDA_SERVER_DOWN_MSG = "frida-server not running — reload snapshot or restart frida"


def frida_server_down(message: str | None) -> bool:
    """True if a spawn failure means frida-server is not running at all."""
    text = (message or "").lower()
    return "need gadget" in text or FRIDA_SERVER_DOWN_MSG.lower() in text


# Substrings that mark the *target process* dying (anti-Frida self-kill, hook
# load crash) — the remedy is a fresh re-spawn.
_CRASH_MARKERS = (
    "no longer exists",
    "processnotfound",
    "died during hook load",
    "crashed",
    "script destroyed",
)

# Substrings that mark a benign "already running" outcome — treat as success.
_BENIGN_MARKERS = (
    "already running",
    "invalidoperation",
)


def classify_spawn_failure(message: str | None, exc: Exception | None = None) -> str:
    """Classify a spawn failure into ``dirty`` / ``crash`` / ``benign`` / ``other``.

    The retry wrapper classifies the ``(False, msg)`` STRING returned by
    :meth:`BypassService.apply_to_fresh_spawn` — that method already converts
    the resume-path ``ProcessNotFoundError`` / ``InvalidOperationError`` to a
    string internally and never propagates a frida exception, so callers do not
    normally pass *exc*. The optional *exc* type fast-path is kept only for a
    hypothetical future re-raise and is forward-compatible with a gated-spawn
    variant.

    ORDERING IS LOAD-BEARING: ``dirty`` is checked BEFORE ``crash`` because
    AFM's ``TransportError`` message contains "may have crashed", yet the
    correct remedy there is a server restart, not a bare re-spawn.

    Args:
        message: The failure message string (typically the ``(False, msg)``
            second element). ``None`` is treated as empty.
        exc: Optional exception whose type seeds the classification when the
            message is inconclusive.

    Returns:
        One of ``"dirty"``, ``"crash"``, ``"benign"``, ``"other"``.
    """
    text = (message or "").lower()
    if exc is not None:
        # Type fast-path (forward-compat); the message scan below still wins
        # when it is conclusive, preserving the dirty-before-crash ordering.
        exc_name = type(exc).__name__.lower()
        text = f"{text} {exc_name}"

    # dirty BEFORE crash — see docstring.
    if any(m in text for m in _DIRTY_MARKERS):
        return "dirty"
    if any(m in text for m in _CRASH_MARKERS):
        return "crash"
    if any(m in text for m in _BENIGN_MARKERS):
        return "benign"
    return "other"


# ---------------------------------------------------------------------------
# Base manager
# ---------------------------------------------------------------------------


class BypassManagerBase:
    """Data holder describing one Frida-based detection bypass.

    The lifecycle (session setup, script assembly, resume, message handler,
    TaskService registration) now lives in :class:`BypassService`, which
    concatenates every payload into one persistent flag-gated script. Subclasses
    only declare the Frida payload, its hook registry, a display name, and a
    load-order priority — they are never instantiated as job owners anymore.

    Class attributes:

    - ``TOOL_NAME`` — internal identifier (legacy; kept for reference).
    - ``DISPLAY_NAME`` — human-readable name for UI and logs.
    - ``HOOKS_REGISTRY`` — logical hook identifiers (advisory conflict detection).
    - ``FRIDA_SCRIPT`` — the Frida JS payload.
    - ``PRIORITY`` — load order (lower installs earlier in the merged script,
      so the anti-anti-Frida prelude can land before root/debug/SSL).
    - ``APPLY_AT_SPAWN`` — True when the app reads what the bypass changes
      at startup (Build fields), so turning it on live is only complete after
      a restart; the toggle message says so.
    """

    TOOL_NAME: str = "bypass"
    DISPLAY_NAME: str = "Detection Bypass"
    HOOKS_REGISTRY: list[str] = []
    FRIDA_SCRIPT: str = ""
    PRIORITY: int = 10
    APPLY_AT_SPAWN: bool = False


# ---------------------------------------------------------------------------
# Frida detection bypass (anti-anti-Frida prelude)
# ---------------------------------------------------------------------------

_FRIDA_DETECTION_SCRIPT = r"""
'use strict';

// Anti-anti-Frida: suppress the most common detector tricks so later jobs
// (e.g. SSL unpinning) get a chance to run even on apps that try to SIGKILL
// on Frida presence. Deliberately does NOT hook Debug.isDebuggerConnected —
// that lives in the Debug detection bypass.

// Native: hide frida from this process's /proc maps/smaps/status (shared
// open/openat filter in the preamble -- no libc read hook).
(function () {
    try {
        filterProcFiles('frida', ['maps', 'smaps', 'status'], hideFridaLine);
        send({type: 'info', hook: 'frida-bypass:proc-filter'});
    } catch (e) {
        send({type: 'debug', hook: 'frida-bypass:proc-filter', error: e.message});
    }

    // Native: strstr scans for 'frida'/'gum' return NULL
    try {
        var strstr = _libcExport('strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function (args) {
                    this._block = false;
                    if (!FLAGS.frida) return;  // flag before any work
                    try {
                        var needle = args[1].readUtf8String();
                        this._block = needle && (
                            needle.indexOf('frida') !== -1 ||
                            needle.indexOf('gum-js') !== -1 ||
                            needle.indexOf('linjector') !== -1 ||
                            needle.indexOf('gadget') !== -1
                        );
                    } catch (e) { this._block = false; }
                },
                onLeave: function (rv) {
                    if (!FLAGS.frida) return;  // inert when frida bypass off
                    if (this._block) rv.replace(ptr(0));
                }
            });
            send({type: 'info', hook: 'frida-bypass:strstr-filter'});
        }
    } catch (e) {}

    // Native: log who calls exit/_exit/abort (visibility only, non-blocking —
    // blocking these can crash ART).
    ['_exit', 'exit', 'abort'].forEach(function (sym) {
        try {
            var p = _libcExport(sym);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function () {
                    if (!FLAGS.frida) return;  // inert when frida bypass off
                    send({type: 'info', hook: 'frida-bypass:lifecycle-' + sym});
                }
            });
        } catch (e) {}
    });
})();

// Java: suppress self-kill paths once the VM is ready
Java.perform(function () {
    try {
        var ProcessCls = Java.use('android.os.Process');
        var ownPid = ProcessCls.myPid();
        ProcessCls.killProcess.implementation = function (pid) {
            if (!FLAGS.frida) return this.killProcess(pid);
            if (pid === ownPid) {
                send({type: 'info', hook: 'frida-bypass:Process.killProcess(self)'});
                return;  // swallow
            }
            return this.killProcess(pid);
        };
    } catch (e) {}

    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exit.implementation = function (code) {
            if (!FLAGS.frida) return this.exit(code);
            send({type: 'info', hook: 'frida-bypass:Runtime.exit(' + code + ')'});
            // swallow
        };
    } catch (e) {}

    try {
        var SystemCls = Java.use('java.lang.System');
        SystemCls.exit.implementation = function (code) {
            if (!FLAGS.frida) return this.exit(code);
            send({type: 'info', hook: 'frida-bypass:System.exit(' + code + ')'});
            // swallow
        };
    } catch (e) {}

    send({type: 'ready', message: 'Frida detection bypass hooks loaded'});
});
"""

FRIDA_DETECTION_HOOKS = [
    "libc:open",
    "libc:openat",
    "libc:strstr",
    "libc:exit",
    "libc:_exit",
    "libc:abort",
    "android.os.Process.killProcess",
    "java.lang.Runtime.exit",
    "java.lang.System.exit",
]


class FridaDetectionBypassManager(BypassManagerBase):
    """Suppress common anti-Frida detection tricks (self-kill, proc scans)."""

    TOOL_NAME = "frida_detection_bypass"
    DISPLAY_NAME = "Frida Detection Bypass (experimental)"
    HOOKS_REGISTRY = FRIDA_DETECTION_HOOKS
    FRIDA_SCRIPT = _FRIDA_DETECTION_SCRIPT
    PRIORITY = 5  # installs first in the merged script (anti-anti-Frida prelude)


# ---------------------------------------------------------------------------
# Root detection bypass
# ---------------------------------------------------------------------------

_ROOT_DETECTION_SCRIPT = r"""
'use strict';

// --- Shared path matcher (script scope) -------------------------------------
// Hoisted out of Java.perform so the native libc hooks (access/faccessat/
// fopen) and the Java hooks below can both reuse the same root-path logic.

// Full paths that are root indicators on their own.
var SU_PATHS = [
    '/system/xbin/su', '/system/bin/su', '/sbin/su', '/su/bin/su',
    '/system/app/Superuser.apk', '/system/xbin/busybox',
    '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
    '/system/sd/xbin/su', '/system/bin/failsafe/su',
    '/data/adb/magisk', '/data/adb/modules', '/data/adb/su'
];
// Binaries that are root indicators when they are the *basename* of a path
// or a bare command token. Matched on path segments / exact tokens only —
// NEVER as a substring (so 'samsung', 'issue', 'consumer' do not match).
var SU_BINS = [
    'su', 'busybox', 'magisk', 'magiskhide', 'supersu', 'daemonsu'
];

function _basename(s) {
    var v = '' + s;
    var i = v.lastIndexOf('/');
    return i === -1 ? v : v.substring(i + 1);
}

function _isRootBin(token) {
    var t = ('' + token).toLowerCase();
    for (var i = 0; i < SU_BINS.length; i++) {
        if (t === SU_BINS[i]) return true;
    }
    return false;
}

// Path-shaped check: exact full-path match, or basename is a su binary,
// or it lives under a magisk dir.
function _looksLikeRootPath(s) {
    if (!s) return false;
    var v = '' + s;
    for (var i = 0; i < SU_PATHS.length; i++) {
        if (v === SU_PATHS[i]) return true;
    }
    if (v.indexOf('/data/adb/magisk') !== -1 ||
        v.indexOf('/data/adb/modules') !== -1) {
        return true;
    }
    return _isRootBin(_basename(v));
}

// Native: __system_property_get for ro.debuggable / ro.secure
(function () {
    try {
        var sysprop = _libcExport('__system_property_get');
        if (sysprop) {
            Interceptor.attach(sysprop, {
                onEnter: function (args) {
                    this._key = null;
                    if (!FLAGS.root) return;
                    try { this._key = args[0].readUtf8String(); }
                    catch (e) { this._key = null; }
                    this._out = args[1];
                },
                onLeave: function (rv) {
                    if (!FLAGS.root || this._key === null) return;
                    try {
                        // Only a present, revealing value changes. A device
                        // that does not set the property gives every app "",
                        // and a spoofed "0"/"1" there is itself the tell.
                        var cur = this._out.readUtf8String();
                        var want = null;
                        if (this._key === 'ro.debuggable' && cur === '1') want = '0';
                        else if (this._key === 'ro.secure' && cur === '0') want = '1';
                        if (want === null) return;
                        this._out.writeUtf8String(want);
                        rv.replace(ptr(1));
                        send({type: 'info', hook: 'root-bypass:prop:' + this._key});
                    } catch (e) {}
                }
            });
            send({type: 'info', hook: 'root-bypass:__system_property_get'});
        }
    } catch (e) {
        send({type: 'debug', hook: 'root-bypass:__system_property_get', error: e.message});
    }
})();

// Native: hide su/magisk/busybox paths from RootBeer's *native* probes.
// RootBeer (wrapped by JailMonkey in Doctolib's React Native build) checks the
// filesystem via libc access()/faccessat()/fopen() rather than java.io.File,
// so the Java File.exists hook never sees them. The shared path hider
// (preamble ``hidePaths``) answers a root path with -1/NULL + ENOENT without
// running the real call, and only reads the path while a hiding category is
// on, so this never throttles a Hermes app at boot. We deliberately do NOT
// hook open/openat (far too hot — fopen/access cover RootBeer's primitives).
try {
    hidePaths('root', function (path) { return _looksLikeRootPath(path); }, 1);
    send({type: 'info', hook: 'root-bypass:access/faccessat/fopen'});
} catch (e) {
    send({type: 'debug', hook: 'root-bypass:path-hider', error: e.message});
}

Java.perform(function () {
    // Command check: any whitespace-separated token is a su binary or a known
    // root path (covers 'su', 'which su', '/system/xbin/su -c id').
    function _cmdLooksLikeRoot(cmd) {
        var tokens = ('' + cmd).trim().split(/\s+/);
        for (var i = 0; i < tokens.length; i++) {
            if (_isRootBin(tokens[i]) || _looksLikeRootPath(tokens[i])) return true;
        }
        return false;
    }

    var IOException = Java.use('java.io.IOException');

    // File.exists — hide su/magisk/busybox paths. (We intentionally do NOT
    // hook the File constructor: redirecting paths there corrupts normal I/O
    // and risks infinite recursion. Detectors call File(path).exists().)
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            if (!FLAGS.root) return this.exists();
            try {
                var p = this.getAbsolutePath();
                if (_looksLikeRootPath(p)) {
                    send({type: 'info', hook: 'root-bypass:File.exists(' + p + ')'});
                    return false;
                }
            } catch (e) {}
            return this.exists();
        };
        send({type: 'info', hook: 'root-bypass:File.exists'});
    } catch (e) {}

    // Runtime.exec — block su / which su (String and String[] overloads)
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (!FLAGS.root) return this.exec(cmd);
            if (_cmdLooksLikeRoot(cmd)) {
                send({type: 'info', hook: 'root-bypass:Runtime.exec(' + cmd + ')'});
                throw IOException.$new('No such file or directory');
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            if (!FLAGS.root) return this.exec(cmds);
            var joined = '';
            for (var i = 0; i < cmds.length; i++) { joined += ' ' + cmds[i]; }
            if (_cmdLooksLikeRoot(joined)) {
                send({type: 'info', hook: 'root-bypass:Runtime.exec[](' + joined + ')'});
                throw IOException.$new('No such file or directory');
            }
            return this.exec(cmds);
        };
        send({type: 'info', hook: 'root-bypass:Runtime.exec'});
    } catch (e) {}

    // ProcessBuilder — block su / which
    try {
        var PB = Java.use('java.lang.ProcessBuilder');
        PB.start.implementation = function () {
            if (!FLAGS.root) return this.start();
            var joined = '' + this.command();
            if (_cmdLooksLikeRoot(joined)) {
                send({type: 'info', hook: 'root-bypass:ProcessBuilder.start(' + joined + ')'});
                throw IOException.$new('No such file or directory');
            }
            return this.start();
        };
        send({type: 'info', hook: 'root-bypass:ProcessBuilder.start'});
    } catch (e) {}

    // PackageManager — hide known root-management apps
    try {
        var ROOT_PKGS = [
            'com.topjohnwu.magisk', 'eu.chainfire.supersu',
            'com.koushikdutta.superuser', 'com.thirdparty.superuser',
            'com.noshufou.android.su', 'com.kingroot.kinguser',
            'com.kingo.root', 'com.zachspong.temprootremovejb',
            'com.ramdroid.appquarantine'
        ];
        function _isRootPkg(name) {
            var n = '' + name;
            for (var i = 0; i < ROOT_PKGS.length; i++) {
                if (n.indexOf(ROOT_PKGS[i]) !== -1) return true;
            }
            return false;
        }
        var APM = Java.use('android.app.ApplicationPackageManager');
        APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (!FLAGS.root) return this.getPackageInfo(pkg, flags);
            if (_isRootPkg(pkg)) {
                send({type: 'info', hook: 'root-bypass:getPackageInfo(' + pkg + ')'});
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
        send({type: 'info', hook: 'root-bypass:PackageManager'});
    } catch (e) {}

    // Build.TAGS -> release-keys. A field write, NOT a flag-gated method
    // body: it happens once, when the root category installs -- at load if
    // root is armed for the spawn, or on the live flip that first turns root
    // on. It is sticky for the session (turning root off does not restore the
    // real TAGS; the emulator category leaves TAGS alone on its own flip-off
    // while root is on). Acceptable fidelity caveat — TAGS is rarely the sole
    // root signal.
    try {
        if (FLAGS.root) {
            var Build = Java.use('android.os.Build');
            Build.TAGS.value = 'release-keys';
            send({type: 'info', hook: 'root-bypass:Build.TAGS=release-keys'});
        }
    } catch (e) {}

    // --- JailMonkey / RootBeer (React Native, e.g. Doctolib) ----------------
    // Each guarded so it is totally inert on apps that lack these classes:
    // a non-JailMonkey app simply skips the block on the Java.use throw.

    // JailMonkey: forcing isJailBroken() -> false alone clears Doctolib's
    // block screen (confirmed on-device). Hook the no-arg implementation.
    try {
        var RootedCheck = Java.use('com.gantix.JailMonkey.Rooted.RootedCheck');
        try {
            RootedCheck.isJailBroken.overload().implementation = function () {
                if (!FLAGS.root) return this.isJailBroken();
                send({type: 'info', hook: 'root-bypass:JailMonkey.isJailBroken'});
                return false;
            };
        } catch (e) {
            RootedCheck.isJailBroken.implementation = function () {
                if (!FLAGS.root) return this.isJailBroken();
                send({type: 'info', hook: 'root-bypass:JailMonkey.isJailBroken'});
                return false;
            };
        }
        send({type: 'info', hook: 'root-bypass:JailMonkey.RootedCheck'});
    } catch (e) {}

    // RootBeer (Java side): isRooted / isRootedWithoutBusyBoxCheck -> false.
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function () {
            if (!FLAGS.root) return this.isRooted();
            send({type: 'info', hook: 'root-bypass:RootBeer.isRooted'});
            return false;
        };
        send({type: 'info', hook: 'root-bypass:RootBeer.isRooted'});
    } catch (e) {}
    try {
        var RootBeer2 = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer2.isRootedWithoutBusyBoxCheck.implementation = function () {
            if (!FLAGS.root) return this.isRootedWithoutBusyBoxCheck();
            send({type: 'info', hook: 'root-bypass:RootBeer.isRootedWithoutBusyBoxCheck'});
            return false;
        };
        send({type: 'info', hook: 'root-bypass:RootBeer.isRootedWithoutBusyBoxCheck'});
    } catch (e) {}

    // RootBeerNative.checkForRoot returns an int; force 0 (not rooted).
    try {
        var RootBeerNative = Java.use('com.scottyab.rootbeer.RootBeerNative');
        RootBeerNative.checkForRoot.implementation = function () {
            if (!FLAGS.root) return this.checkForRoot.apply(this, arguments);
            send({type: 'info', hook: 'root-bypass:RootBeerNative.checkForRoot'});
            return 0;
        };
        send({type: 'info', hook: 'root-bypass:RootBeerNative.checkForRoot'});
    } catch (e) {}

    // --- Installed-app / running-service filtering --------------------------
    // RootBeer / JailMonkey also enumerate installed apps and running services
    // looking for root managers, Xposed, substrate, and frida-server. Filter
    // those entries out of the lists the app receives.
    var ROOT_APP_TOKENS = [
        'magisk', 'supersu', 'superuser', 'com.topjohnwu',
        'de.robv.android.xposed', 'com.saurik.substrate',
        'kingroot', 'kinguser'
    ];
    function _hasRootToken(name) {
        var n = ('' + name).toLowerCase();
        for (var i = 0; i < ROOT_APP_TOKENS.length; i++) {
            if (n.indexOf(ROOT_APP_TOKENS[i]) !== -1) return true;
        }
        return false;
    }

    try {
        var ArrayList = Java.use('java.util.ArrayList');
        var APM2 = Java.use('android.app.ApplicationPackageManager');

        APM2.getInstalledApplications.overload('int').implementation = function (flags) {
            if (!FLAGS.root) return this.getInstalledApplications(flags);
            var original = this.getInstalledApplications(flags);
            try {
                var kept = ArrayList.$new();
                var n = original.size();
                var removed = 0;
                for (var i = 0; i < n; i++) {
                    var info = original.get(i);
                    var pkg = '' + info.packageName.value;
                    if (_hasRootToken(pkg)) { removed++; continue; }
                    kept.add(info);
                }
                if (removed > 0) {
                    send({type: 'info', hook: 'root-bypass:getInstalledApplications(-' + removed + ')'});
                }
                return kept;
            } catch (e) {
                return original;
            }
        };

        APM2.getInstalledPackages.overload('int').implementation = function (flags) {
            if (!FLAGS.root) return this.getInstalledPackages(flags);
            var original = this.getInstalledPackages(flags);
            try {
                var kept = ArrayList.$new();
                var n = original.size();
                var removed = 0;
                for (var i = 0; i < n; i++) {
                    var info = original.get(i);
                    var pkg = '' + info.packageName.value;
                    if (_hasRootToken(pkg)) { removed++; continue; }
                    kept.add(info);
                }
                if (removed > 0) {
                    send({type: 'info', hook: 'root-bypass:getInstalledPackages(-' + removed + ')'});
                }
                return kept;
            } catch (e) {
                return original;
            }
        };
        send({type: 'info', hook: 'root-bypass:ApplicationPackageManager.installed'});
    } catch (e) {}

    // ActivityManager.getRunningServices: drop frida-server / magisk services
    // (defeats JailMonkey's checkFrida, which matches 'frida-server').
    try {
        var ArrayList2 = Java.use('java.util.ArrayList');
        var AM = Java.use('android.app.ActivityManager');
        AM.getRunningServices.overload('int').implementation = function (max) {
            if (!FLAGS.root) return this.getRunningServices(max);
            var original = this.getRunningServices(max);
            try {
                var kept = ArrayList2.$new();
                var n = original.size();
                var removed = 0;
                for (var i = 0; i < n; i++) {
                    var svc = original.get(i);
                    var probe = '';
                    try { probe += '' + svc.service.value; } catch (e) {}
                    try { probe += ' ' + svc.process.value; } catch (e) {}
                    var lower = probe.toLowerCase();
                    if (lower.indexOf('frida') !== -1 ||
                        lower.indexOf('magisk') !== -1) {
                        removed++;
                        continue;
                    }
                    kept.add(svc);
                }
                if (removed > 0) {
                    send({type: 'info', hook: 'root-bypass:getRunningServices(-' + removed + ')'});
                }
                return kept;
            } catch (e) {
                return original;
            }
        };
        send({type: 'info', hook: 'root-bypass:ActivityManager.getRunningServices'});
    } catch (e) {}

    // --- Settings flags (adb_enabled / development_settings_enabled = 0) -----
    // Some root/debug heuristics read these via Settings.Global / Settings.Secure.
    function _hookSettingsGetInt(clsName) {
        try {
            var Cls = Java.use(clsName);
            Cls.getInt.overload(
                'android.content.ContentResolver', 'java.lang.String'
            ).implementation = function (cr, key) {
                if (!FLAGS.root) return this.getInt(cr, key);
                var k = '' + key;
                if (k === 'adb_enabled' || k === 'development_settings_enabled') {
                    send({type: 'info', hook: 'root-bypass:Settings.getInt(' + k + ')'});
                    return 0;
                }
                return this.getInt(cr, key);
            };
            Cls.getInt.overload(
                'android.content.ContentResolver', 'java.lang.String', 'int'
            ).implementation = function (cr, key, def) {
                if (!FLAGS.root) return this.getInt(cr, key, def);
                var k = '' + key;
                if (k === 'adb_enabled' || k === 'development_settings_enabled') {
                    send({type: 'info', hook: 'root-bypass:Settings.getInt(' + k + ')'});
                    return 0;
                }
                return this.getInt(cr, key, def);
            };
            send({type: 'info', hook: 'root-bypass:' + clsName + '.getInt'});
        } catch (e) {}
    }
    _hookSettingsGetInt('android.provider.Settings$Global');
    _hookSettingsGetInt('android.provider.Settings$Secure');

    send({type: 'ready', message: 'Root detection bypass hooks loaded'});
});
"""

ROOT_DETECTION_HOOKS = [
    "java.io.File.exists",
    "java.io.File.<init>",
    "java.lang.Runtime.exec",
    "java.lang.ProcessBuilder.start",
    "android.app.ApplicationPackageManager.getPackageInfo",
    "android.os.Build.TAGS",
    "libc:__system_property_get",
    "libc:access",
    "libc:faccessat",
    "libc:fopen",
    "libc:stat",
    "libc:lstat",
    "libc:fstatat",
    "com.gantix.JailMonkey.Rooted.RootedCheck.isJailBroken",
    "com.scottyab.rootbeer.RootBeer.isRooted",
    "com.scottyab.rootbeer.RootBeerNative.checkForRoot",
    "android.app.ApplicationPackageManager.getInstalledApplications",
    "android.app.ActivityManager.getRunningServices",
    "android.provider.Settings.getInt",
]


class RootDetectionBypassManager(BypassManagerBase):
    """Hide root indicators (su paths, magisk, root apps, build tags)."""

    TOOL_NAME = "root_detection_bypass"
    DISPLAY_NAME = "Root Detection Bypass (experimental)"
    HOOKS_REGISTRY = ROOT_DETECTION_HOOKS
    FRIDA_SCRIPT = _ROOT_DETECTION_SCRIPT
    PRIORITY = 10


# ---------------------------------------------------------------------------
# Debug detection bypass
# ---------------------------------------------------------------------------

_DEBUG_DETECTION_SCRIPT = r"""
'use strict';

// Native: TracerPid reads 0 in this process's /proc status files, so
// ptrace-based debugger checks pass (shared open/openat filter in the
// preamble -- no libc read hook).
try {
    filterProcFiles('debug', ['status'], zeroTracerPidLine);
    send({type: 'info', hook: 'debug-bypass:tracerpid-filter'});
} catch (e) {
    send({type: 'debug', hook: 'debug-bypass:tracerpid-filter', error: e.message});
}

Java.perform(function () {
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            if (!FLAGS.debug) return this.isDebuggerConnected();
            send({type: 'info', hook: 'debug-bypass:Debug.isDebuggerConnected'});
            return false;
        };
        try {
            Debug.waitingForDebugger.implementation = function () {
                if (!FLAGS.debug) return this.waitingForDebugger();
                return false;
            };
        } catch (e) {}
        send({type: 'info', hook: 'debug-bypass:Debug'});
    } catch (e) {}

    send({type: 'ready', message: 'Debug detection bypass hooks loaded'});
});
"""

DEBUG_DETECTION_HOOKS = [
    "android.os.Debug.isDebuggerConnected",
    "android.os.Debug.waitingForDebugger",
    "libc:openat:tracerpid",
]


class DebugDetectionBypassManager(BypassManagerBase):
    """Defeat debugger-attached checks (isDebuggerConnected, TracerPid)."""

    TOOL_NAME = "debug_detection_bypass"
    DISPLAY_NAME = "Debug Detection Bypass (experimental)"
    HOOKS_REGISTRY = DEBUG_DETECTION_HOOKS
    FRIDA_SCRIPT = _DEBUG_DETECTION_SCRIPT
    PRIORITY = 10


# ---------------------------------------------------------------------------
# Google Play check bypass (PairIP licensing)
# ---------------------------------------------------------------------------

# Apps protected by Google Play App Signing ship the PairIP license-check
# wrapper (``com.pairip.licensecheck.*``). On a sideloaded / emulator install
# the on-device licensing service ("com.android.vending") cannot fulfil the
# license request, so ``LicenseClient.handleError`` fires with
# ``LicenseCheckException: Licensing service could not process request.`` and
# starts ``LicenseActivity``, which shows the blocking dialog "Something went
# wrong - Check that Google Play is enabled on your device ..." and then exits
# the app. This is NOT a ``GoogleApiAvailability`` /
# ``isGooglePlayServicesAvailable`` check (those SDK classes are usually
# absent) - the gate is purely PairIP's license verdict. Confirmed on-device
# against ``com.deepseek.chat``: swallowing ``LicenseClient.handleError`` alone
# drops the dialog and the real first screen renders. The ``LicenseActivity``
# neutralisers are belt-and-suspenders in case the error activity is already
# in flight.
_INTEGRITY_SCRIPT = r"""
'use strict';

// Flag-gated Google Play / PairIP license-check bypass. Every hook body early-
// checks FLAGS.integrity (a shared object from the combined-script preamble) and
// passes through to the original method when the integrity category is toggled off —
// so this single resident script can be armed/disarmed at runtime via the
// set_flags RPC with no reload and no gap. Each Java.use is wrapped in try/catch
// so an app lacking the PairIP classes simply skips the block (totally inert).

Java.perform(function () {
    // 1. Swallow the license-check failure at the source so it never starts the
    //    error-dialog activity nor schedules an app shutdown. This is the
    //    decisive hook (confirmed on-device).
    try {
        var LicenseClient = Java.use('com.pairip.licensecheck.LicenseClient');
        try {
            LicenseClient.handleError.implementation = function (ex) {
                if (!FLAGS.integrity) return this.handleError(ex);
                send({type: 'info', hook: 'integrity:LicenseClient.handleError(swallowed)'});
                // do nothing -> no error dialog, no shutdown
            };
        } catch (e) {}
        try {
            LicenseClient.startErrorDialogActivity.implementation = function () {
                if (!FLAGS.integrity) return this.startErrorDialogActivity();
                send({type: 'info', hook: 'integrity:LicenseClient.startErrorDialogActivity(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseClient.scheduleAppShutdown.implementation = function () {
                if (!FLAGS.integrity) return this.scheduleAppShutdown();
                send({type: 'info', hook: 'integrity:LicenseClient.scheduleAppShutdown(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseClient.retryOrThrow.overload(
                'com.pairip.licensecheck.LicenseCheckException'
            ).implementation = function (ex) {
                if (!FLAGS.integrity) return this.retryOrThrow(ex);
                send({type: 'info', hook: 'integrity:LicenseClient.retryOrThrow(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseClient.retryOrThrow.overload(
                'com.pairip.licensecheck.LicenseCheckException', 'boolean'
            ).implementation = function (ex, b) {
                if (!FLAGS.integrity) return this.retryOrThrow(ex, b);
                send({type: 'info', hook: 'integrity:LicenseClient.retryOrThrow2(swallowed)'});
            };
        } catch (e) {}
        send({type: 'info', hook: 'integrity:LicenseClient'});
    } catch (e) {
        send({type: 'debug', hook: 'integrity:LicenseClient', error: e.message});
    }

    // 2. Belt-and-suspenders: neutralise LicenseActivity's error/exit UI so even
    //    if the error activity is launched it never shows the dialog or closes
    //    the app. onStart -> finish() so the activity dismisses immediately.
    try {
        var LicenseActivity = Java.use('com.pairip.licensecheck.LicenseActivity');
        try {
            LicenseActivity.showErrorDialog.implementation = function () {
                if (!FLAGS.integrity) return this.showErrorDialog();
                send({type: 'info', hook: 'integrity:LicenseActivity.showErrorDialog(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.logAndShowErrorDialog.overload(
                'java.lang.String'
            ).implementation = function (s) {
                if (!FLAGS.integrity) return this.logAndShowErrorDialog(s);
                send({type: 'info', hook: 'integrity:LicenseActivity.logAndShowErrorDialog(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.logAndShowErrorDialog.overload(
                'java.lang.String', 'java.lang.Exception'
            ).implementation = function (s, ex) {
                if (!FLAGS.integrity) return this.logAndShowErrorDialog(s, ex);
                send({type: 'info', hook: 'integrity:LicenseActivity.logAndShowErrorDialog2(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.closeApp.implementation = function () {
                if (!FLAGS.integrity) return this.closeApp();
                send({type: 'info', hook: 'integrity:LicenseActivity.closeApp(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.exitApp.implementation = function () {
                if (!FLAGS.integrity) return this.exitApp();
                send({type: 'info', hook: 'integrity:LicenseActivity.exitApp(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.closeAllTasks.implementation = function () {
                if (!FLAGS.integrity) return this.closeAllTasks();
                send({type: 'info', hook: 'integrity:LicenseActivity.closeAllTasks(swallowed)'});
            };
        } catch (e) {}
        try {
            LicenseActivity.onStart.implementation = function () {
                if (!FLAGS.integrity) return this.onStart();
                send({type: 'info', hook: 'integrity:LicenseActivity.onStart->finish'});
                try { this.finish(); } catch (e) {}
            };
        } catch (e) {}
        send({type: 'info', hook: 'integrity:LicenseActivity'});
    } catch (e) {
        send({type: 'debug', hook: 'integrity:LicenseActivity', error: e.message});
    }

    // 3. Defensive: if an app DOES use the GMS availability SDK as part of its
    //    Play gate, force isGooglePlayServicesAvailable -> 0 (SUCCESS). Inert on
    //    apps lacking these classes (the common case, incl. deepseek).
    ['com.google.android.gms.common.GoogleApiAvailability',
     'com.google.android.gms.common.GoogleApiAvailabilityLight',
     'com.google.android.gms.common.GooglePlayServicesUtil'].forEach(function (clsName) {
        try {
            var C = Java.use(clsName);
            C.isGooglePlayServicesAvailable.overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        if (!FLAGS.integrity) return ov.apply(this, arguments);
                        send({type: 'info', hook: 'integrity:' + clsName + '.isGooglePlayServicesAvailable=0'});
                        return 0;  // ConnectionResult.SUCCESS
                    };
                } catch (e) {}
            });
        } catch (e) {}
    });

    send({type: 'ready', message: 'Integrity / attestation bypass hooks loaded'});
});
"""

INTEGRITY_HOOKS = [
    "com.pairip.licensecheck.LicenseClient.handleError",
    "com.pairip.licensecheck.LicenseClient.startErrorDialogActivity",
    "com.pairip.licensecheck.LicenseClient.scheduleAppShutdown",
    "com.pairip.licensecheck.LicenseClient.retryOrThrow",
    "com.pairip.licensecheck.LicenseActivity.showErrorDialog",
    "com.pairip.licensecheck.LicenseActivity.logAndShowErrorDialog",
    "com.pairip.licensecheck.LicenseActivity.onStart",
    "com.google.android.gms.common.GoogleApiAvailability.isGooglePlayServicesAvailable",
]


class IntegrityBypassManager(BypassManagerBase):
    """Bypass the Google Play / PairIP license check ("Something went wrong")."""

    TOOL_NAME = "integrity_bypass"
    DISPLAY_NAME = "Integrity / Attestation Bypass (experimental)"
    HOOKS_REGISTRY = INTEGRITY_HOOKS
    FRIDA_SCRIPT = _INTEGRITY_SCRIPT
    PRIORITY = 10


# ---------------------------------------------------------------------------
# Emulator detection bypass
# ---------------------------------------------------------------------------

# Ported from TrigDroid's emulator-detection hook set (trigdroid/scripts/hooks/
# emulator-detection.js: device profile -> Build.* fields, ro.* / qemu system
# properties via __system_property_get, Build.getSerial, TelephonyManager
# fakes) and Dexray Intercept's install_emulator_detection_bypass
# (profiling.js: emulator-valued Build.* fields, SystemProperties.get for
# ro.kernel.qemu / ro.product.model). Neither source hides emulator files, so
# the /dev/qemu_pipe, qemud socket and goldfish/ranchu file hiding is new,
# modelled on the root category's access/faccessat/fopen probes. Neither
# source fakes sensors or the battery, so this category does not either.
#
# Coherence instead of blind spoofing (the reason this category was missing):
#
# - Build.* is replaced as ONE device profile and only when at least one
#   identity field shows an emulator value, so a real device is never
#   relabelled and no half-spoofed mix is left behind. The Pixel is picked by
#   the device's real API level (one that really ran that Android version);
#   FINGERPRINT, DISPLAY, ro.build.flavor/display.id/description are built
#   from the device's own release / build ID / incremental; the hidden
#   Build.IS_EMULATOR is cleared. SUPPORTED_ABIS / cpu.abi stay real (faking
#   them breaks native library loading): x86_64 AVDs keep that tell.
# - Native property spoofing and file hiding only answer *app* callers: a
#   caller inside /system, /apex, /vendor, ..., updatable system code under
#   /data (WebView/Trichrome, GMS/GSF modules) or a non-file module (memfd,
#   e.g. the frida agent) keeps the truth, so the emulator's own graphics
#   stack (goldfish pipe, ro.kernel.qemu.gles, ro.hardware) keeps working in
#   the hooked process. Java's File I/O (libopenjdk/libjavacore) counts as an
#   app caller, which is how File.exists() probes are covered without a
#   second File.exists hook (the root category owns that one). The Java
#   SystemProperties.get hook has no caller filter and answers only a fixed
#   list of emulator-revealing keys; framework code in the process that reads
#   one of them sees the spoof too.
# - Device identifiers (IMEI, IMSI, ICCID, serial) call through first: where a
#   real non-privileged app gets a SecurityException (API 29+), so does this
#   one; only an entitled caller gets a (non-emulator) value.
#
# Nothing is hooked until the category is on: the hooks install the first
# time FLAGS.emulator is set -- baked in at load (the armed-then-Start path,
# before the app's first instruction) or flipped live via FLAG_LISTENERS --
# and the Java replacements and the property listener are removed again on
# flip-off. So SSL-only sessions carry none of them, and Dexray's
# telephony_hooks only collide while emulator is on (BypassService refuses
# that pairing). Build fields are static finals zygote set before the app
# existed, so they are written, not hooked, and restored on flip-off. Checks
# an app ran at startup are only fooled on the spawn path (APPLY_AT_SPAWN).
_EMULATOR_DETECTION_SCRIPT = r"""
'use strict';

// Device profiles, picked by the device's real API level so the claimed
// Pixel really shipped (or was updated to) that Android version: Pixel
// (sailfish) 7.1-10, Pixel 3 (blueline) 9-12, Pixel 4 XL (coral) 10-13,
// Pixel 8 Pro (husky) 14+. Below API 25 no profile is coherent; sailfish is
// the closest. Release / build ID / incremental always stay the device's own.
var EMU_PROFILES = [
    {maxSdk: 27, MODEL: 'Pixel', DEVICE: 'sailfish', BOARD: 'sailfish'},
    {maxSdk: 28, MODEL: 'Pixel 3', DEVICE: 'blueline', BOARD: 'blueline'},
    {maxSdk: 33, MODEL: 'Pixel 4 XL', DEVICE: 'coral', BOARD: 'coral'},
    {maxSdk: 9999, MODEL: 'Pixel 8 Pro', DEVICE: 'husky', BOARD: 'husky'}
];
// The active profile: every spoofed value, filled by _emuInitProfile().
var EMU_PROFILE = null;
// Pixel-style serial, for an app that is allowed to read the serial at all.
var EMU_SERIAL = '2B111FDH2004QG';
var EMU_BUILD_FIELDS = [
    'FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT',
    'HARDWARE', 'BOARD', 'TAGS', 'TYPE', 'DISPLAY'
];
// TAGS/TYPE/DISPLAY are replaced along with the identity fields but never
// decide whether this is an emulator (EMU_IDENTITY_PROPS does; a userdebug
// phone is no emulator).
// NOT spoofed: Build.SUPPORTED_ABIS / ro.product.cpu.abi*. Faking them would
// break native library loading. An x86_64 AVD therefore still shows an x86
// ABI (rare on phones) -- arm64 AVDs on Apple silicon do not have that tell.

// Identity properties that decide (once, for Build AND properties alike)
// whether this device is an emulator at all; tags/type never decide.
var EMU_IDENTITY_PROPS = [
    'ro.build.fingerprint', 'ro.product.model', 'ro.product.manufacturer',
    'ro.product.brand', 'ro.product.device', 'ro.product.name', 'ro.hardware',
    'ro.product.board'
];

// Fill EMU_PROFILE from the device's real API level / release / build ID.
// `real(key)` reads a real property ('' when unknown).
function _emuInitProfile(real) {
    var emulated = false;
    for (var k = 0; k < EMU_IDENTITY_PROPS.length; k++) {
        if (_emuValue(real(EMU_IDENTITY_PROPS[k]))) { emulated = true; break; }
    }
    var sdk = parseInt(real('ro.build.version.sdk'), 10);
    if (isNaN(sdk)) sdk = 9999;
    var base = EMU_PROFILES[EMU_PROFILES.length - 1];
    for (var i = 0; i < EMU_PROFILES.length; i++) {
        if (sdk <= EMU_PROFILES[i].maxSdk) { base = EMU_PROFILES[i]; break; }
    }
    var release = real('ro.build.version.release');
    var id = real('ro.build.id');
    var incremental = real('ro.build.version.incremental');
    var d = base.DEVICE;
    EMU_PROFILE = {
        emulated: emulated,
        MODEL: base.MODEL, MANUFACTURER: 'Google', BRAND: 'google',
        DEVICE: d, PRODUCT: d, HARDWARE: d, BOARD: base.BOARD,
        TAGS: 'release-keys', TYPE: 'user', DISPLAY: id,
        FINGERPRINT: 'google/' + d + '/' + d + ':' + release + '/' + id + '/' +
            incremental + ':user/release-keys',
        FLAVOR: d + '-user',
        DESCRIPTION: d + '-user ' + release + ' ' + id + ' ' + incremental +
            ' release-keys'
    };
}

// Real property values, read before any emulator listener is attached.
function _emuRealProp(key) {
    try {
        var addr = _libcExport('__system_property_get');
        if (addr === null) return '';
        var get = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
        var buf = Memory.alloc(92);  // PROP_VALUE_MAX
        get(Memory.allocUtf8String(key), buf);
        return buf.readUtf8String();
    } catch (e) {
        return '';
    }
}
// Value tokens that mark an emulator (TrigDroid's EMULATOR_INDICATORS +
// Dexray's emulatorIndicators + the current sdk_gphone/emu64 images).
var EMU_VALUE_TOKENS = [
    'generic', 'google_sdk', 'sdk_gphone', 'sdk_x86', 'sdk_google',
    'android sdk built for', 'emulator', 'emu64', 'genymotion', 'goldfish',
    'ranchu', 'vbox86'
];
var EMU_EXACT_VALUES = ['sdk', 'unknown'];
// Build tags/type of a debug image (emulator images are userdebug/dev-keys).
var EMU_DEBUG_VALUES = ['test-keys', 'dev-keys', 'userdebug', 'eng'];

function _emuValue(v) {
    if (v === null || v === undefined) return false;
    var s = ('' + v).toLowerCase();
    if (EMU_EXACT_VALUES.indexOf(s) !== -1) return true;
    for (var i = 0; i < EMU_VALUE_TOKENS.length; i++) {
        if (s.indexOf(EMU_VALUE_TOKENS[i]) !== -1) return true;
    }
    return false;
}

// --- emulator files / pipes ---------------------------------------------
var EMU_PATHS = [
    '/dev/qemu_pipe', '/dev/goldfish_pipe', '/dev/socket/qemud',
    '/dev/socket/genyd', '/dev/socket/baseband_genyd', '/sys/qemu_trace',
    '/system/bin/qemu-props', '/system/bin/qemud',
    '/system/lib/libc_malloc_debug_qemu.so',
    '/system/lib64/libc_malloc_debug_qemu.so',
    '/dev/vboxguest', '/dev/vboxuser', '/system/bin/nox-prop',
    '/system/bin/ttVM-prop', '/system/bin/microvirt-prop',
    '/system/bin/windroyed', '/system/lib/libdroid4x.so'
];
// Basename tokens: fstab.ranchu, init.goldfish.rc, ueventd.vbox86.rc, ...
var EMU_NAME_TOKENS = [
    'goldfish', 'ranchu', 'qemu', 'vbox86', 'ttvm_x86', 'android_x86', 'genyd'
];
var EMU_NAMES = [
    'fstab.nox', 'init.nox.rc', 'ueventd.nox.rc', 'fstab.andy',
    'ueventd.andy.rc', 'x86.prop'
];

function _isEmuPath(p) {
    if (!p) return false;
    var v = '' + p;
    if (EMU_PATHS.indexOf(v) !== -1) return true;
    var i = v.lastIndexOf('/');
    var base = (i === -1 ? v : v.substring(i + 1)).toLowerCase();
    if (EMU_NAMES.indexOf(base) !== -1) return true;
    for (var j = 0; j < EMU_NAME_TOKENS.length; j++) {
        if (base.indexOf(EMU_NAME_TOKENS[j]) !== -1) return true;
    }
    return false;
}

// --- caller scoping (see the Python comment above) ------------------------
var EMU_SYSTEM_PREFIXES = [
    '/system/', '/apex/', '/vendor/', '/product/', '/system_ext/', '/odm/'
];
// Updatable system code that lives under /data (app or GMS module dirs) and
// is loaded into the app process: WebView/Trichrome, Play services (incl.
// its dynamite modules), Google services framework.
var EMU_UPDATABLE_SYSTEM = [
    'webview', 'trichrome', 'com.google.android.gms', 'com.google.android.gsf'
];
var EMU_JAVA_IO_LIBS = ['libopenjdk.so', 'libjavacore.so'];

function _isAppCaller(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        // Anonymous / JIT / unpacked code: the app (packers unpack there).
        if (!m) return true;
        var p = '' + m.path;
        // Not a file on disk (memfd: the frida agent, ...): never the app.
        if (p.charAt(0) !== '/' || p.indexOf('memfd:') !== -1) return false;
        for (var i = 0; i < EMU_JAVA_IO_LIBS.length; i++) {
            if (p.indexOf('/' + EMU_JAVA_IO_LIBS[i]) !== -1) return true;
        }
        for (var j = 0; j < EMU_SYSTEM_PREFIXES.length; j++) {
            if (p.indexOf(EMU_SYSTEM_PREFIXES[j]) === 0) return false;
        }
        var pl = p.toLowerCase();
        for (var k = 0; k < EMU_UPDATABLE_SYSTEM.length; k++) {
            if (pl.indexOf(EMU_UPDATABLE_SYSTEM[k]) !== -1) return false;
        }
    } catch (e) {}
    return true;
}

// --- system properties ------------------------------------------------------
// The keys the Java SystemProperties.get hook answers. It has no caller
// filter (a Java stack walk per read is too costly), so framework Java code
// in the app process that reads one of these sees the spoof as well; the
// list is kept to keys that only reveal the emulator.
var EMU_JAVA_PROP_KEYS = [
    'ro.kernel.qemu', 'ro.kernel.qemu.gles', 'ro.boot.qemu',
    'ro.boot.qemu.avd_name', 'ro.kernel.android.qemud', 'init.svc.qemud',
    'init.svc.qemu-props', 'init.svc.goldfish-logcat', 'init.svc.goldfish-setup',
    'qemu.hw.mainkeys', 'qemu.sf.fake_camera', 'qemu.sf.lcd_density',
    'ro.hardware', 'ro.boot.hardware', 'ro.product.model',
    'ro.product.manufacturer', 'ro.product.brand', 'ro.product.device',
    'ro.product.name', 'ro.product.board', 'ro.build.product',
    'ro.build.fingerprint', 'ro.build.tags', 'ro.build.type',
    'ro.build.flavor', 'ro.build.display.id', 'ro.build.description',
    'ro.build.characteristics'
];

// Replacement for property `key` whose current value is `value`, or null to
// leave it alone. ro.debuggable / ro.secure stay with the root category.
function _spoofProp(key, value) {
    // Not an emulator (e.g. a userdebug phone): spoof no property, exactly as
    // _emuApplyBuild leaves Build alone, so Build.TAGS/TYPE and
    // ro.build.tags/type always agree.
    if (!key || EMU_PROFILE === null || !EMU_PROFILE.emulated) return null;
    var k = '' + key;
    var kl = k.toLowerCase();
    // qemu / goldfish / ranchu markers are unset on a real device.
    if (kl.indexOf('qemu') !== -1 || kl.indexOf('goldfish') !== -1 ||
        kl.indexOf('ranchu') !== -1) {
        return (value === null || value === '') ? null : '';
    }
    var dot = k.lastIndexOf('.');
    var leaf = dot === -1 ? k : k.substring(dot + 1);
    if (value !== null && EMU_DEBUG_VALUES.indexOf(('' + value).toLowerCase()) !== -1) {
        if (leaf === 'tags') return EMU_PROFILE.TAGS;
        if (leaf === 'type') return EMU_PROFILE.TYPE;
    }
    if (!_emuValue(value)) return null;
    if (k === 'ro.hardware' || k === 'ro.boot.hardware') return EMU_PROFILE.HARDWARE;
    if (k === 'ro.build.product') return EMU_PROFILE.PRODUCT;
    if (k === 'ro.build.characteristics') return 'nosdcard';
    if (k === 'ro.build.flavor') return EMU_PROFILE.FLAVOR;
    if (k === 'ro.build.display.id') return EMU_PROFILE.DISPLAY;
    if (k === 'ro.build.description') return EMU_PROFILE.DESCRIPTION;
    if (k.indexOf('ro.product.') === 0 || k.indexOf('ro.build.') === 0 ||
        k.indexOf('ro.vendor.') === 0 || k.indexOf('ro.system.') === 0 ||
        k.indexOf('ro.bootimage.') === 0 || k.indexOf('ro.odm.') === 0) {
        if (leaf === 'model') return EMU_PROFILE.MODEL;
        if (leaf === 'manufacturer') return EMU_PROFILE.MANUFACTURER;
        if (leaf === 'brand') return EMU_PROFILE.BRAND;
        if (leaf === 'device') return EMU_PROFILE.DEVICE;
        if (leaf === 'name') return EMU_PROFILE.PRODUCT;
        if (leaf === 'board') return EMU_PROFILE.BOARD;
        if (leaf === 'fingerprint') return EMU_PROFILE.FINGERPRINT;
    }
    return null;
}

// Everything below installs lazily, the first time FLAGS.emulator turns on
// (baked in at load, or a set_flags flip via FLAG_LISTENERS), and the Java
// replacements are reverted when it turns off. An SSL-only session never
// carries them, and Dexray's telephony_hooks (which replace the same
// TelephonyManager methods from a second script) only collide while the
// emulator category is on, which BypassService refuses.
var _emuInstalled = false;
var _emuPropListener = null;
var _emuPathsRegistered = false;
var _emuJavaHooks = [];  // replaced Java methods, reverted on flip-off

// Native: __system_property_get (TrigDroid's mapping). Stacks with the root
// category's listener on the same export; that one owns ro.debuggable /
// ro.secure, this one only the emulator keys.
function _emuInstallPropHook() {
    var propGet = _libcExport('__system_property_get');
    if (!propGet) return;
    _emuPropListener = Interceptor.attach(propGet, {
        onEnter: function (args) {
            this._out = null;
            if (!FLAGS.emulator) return;
            try {
                this._key = args[0].readUtf8String();
                this._out = args[1];
                this._ra = this.returnAddress;
            } catch (e) { this._out = null; }
        },
        onLeave: function (rv) {
            if (!FLAGS.emulator || !this._out) return;
            try {
                var cur = this._out.readUtf8String();
                var s = _spoofProp(this._key, cur);
                if (s === null || !_isAppCaller(this._ra)) return;
                this._out.writeUtf8String(s);
                rv.replace(ptr(s.length));
                send({type: 'info', hook: 'emulator-bypass:prop:' + this._key});
            } catch (e) {}
        }
    });
    send({type: 'info', hook: 'emulator-bypass:__system_property_get'});
}

// Build.* fields: one coherent device profile, written (not hooked).
var _emuBuildOriginal = null;

function _emuApplyBuild(on) {
    Java.perform(function () {
        var Build = Java.use('android.os.Build');
        if (on) {
            if (_emuBuildOriginal) return;
            var orig = {};
            EMU_BUILD_FIELDS.forEach(function (f) {
                try { orig[f] = '' + Build[f].value; } catch (e) {}
            });
            if (EMU_PROFILE === null || !EMU_PROFILE.DISPLAY) {
                // Native property read failed: take the real values from
                // Java instead (same keys, same emulator decision).
                var Version = Java.use('android.os.Build$VERSION');
                var fromBuild = {
                    'ro.build.fingerprint': 'FINGERPRINT', 'ro.product.model': 'MODEL',
                    'ro.product.manufacturer': 'MANUFACTURER',
                    'ro.product.brand': 'BRAND', 'ro.product.device': 'DEVICE',
                    'ro.product.name': 'PRODUCT', 'ro.hardware': 'HARDWARE',
                    'ro.product.board': 'BOARD', 'ro.build.id': 'ID'
                };
                _emuInitProfile(function (key) {
                    try {
                        if (key in fromBuild) return '' + Build[fromBuild[key]].value;
                        if (key === 'ro.build.version.sdk') return '' + Version.SDK_INT.value;
                        if (key === 'ro.build.version.release') {
                            return '' + Version.RELEASE.value;
                        }
                        if (key === 'ro.build.version.incremental') {
                            return '' + Version.INCREMENTAL.value;
                        }
                    } catch (e) {}
                    return '';
                });
            }
            if (!EMU_PROFILE.emulated) {
                send({type: 'info', hook: 'emulator-bypass:Build(no emulator values)'});
                return;
            }
            EMU_BUILD_FIELDS.forEach(function (f) {
                try { Build[f].value = EMU_PROFILE[f]; } catch (e) {}
            });
            // Hidden Build.IS_EMULATOR (ro.boot.qemu == "1"), where present.
            try {
                orig.IS_EMULATOR = Build.IS_EMULATOR.value;
                Build.IS_EMULATOR.value = false;
            } catch (e) {}
            _emuBuildOriginal = orig;
            send({type: 'info', hook: 'emulator-bypass:Build=' + EMU_PROFILE.MODEL});
        } else {
            if (!_emuBuildOriginal) return;
            var saved = _emuBuildOriginal;
            _emuBuildOriginal = null;
            EMU_BUILD_FIELDS.concat(['IS_EMULATOR']).forEach(function (f) {
                // TAGS is also the root category's (sticky) field.
                if (f === 'TAGS' && FLAGS.root) return;
                try {
                    if (f in saved) Build[f].value = saved[f];
                } catch (e) {}
            });
            send({type: 'info', hook: 'emulator-bypass:Build restored'});
        }
    });
}

function _emuHook(method, impl) {
    method.implementation = impl;
    _emuJavaHooks.push(method);
}

function _emuInstallJavaHooks() {
    // Build.getSerial (TrigDroid).
    try {
        var BuildCls = Java.use('android.os.Build');
        // Call through first: on API 29+ a normal app gets the real
        // SecurityException (as on a phone); only a caller entitled to the
        // serial gets one, and then a Pixel-style one.
        _emuHook(BuildCls.getSerial, function () {
            var real = this.getSerial();
            if (!FLAGS.emulator || real === null) return real;
            send({type: 'info', hook: 'emulator-bypass:Build.getSerial'});
            return EMU_SERIAL;
        });
    } catch (e) {}

    // SystemProperties.get (Dexray): Java-level reads skip __system_property_get
    // on current Android (they use __system_property_read_callback).
    try {
        var SP = Java.use('android.os.SystemProperties');
        _emuHook(SP.get.overload('java.lang.String'), function (key) {
            var v = this.get(key);
            if (!FLAGS.emulator || EMU_JAVA_PROP_KEYS.indexOf('' + key) === -1) return v;
            var s = _spoofProp(key, v);
            if (s === null) return v;
            send({type: 'info', hook: 'emulator-bypass:SystemProperties.get(' + key + ')'});
            return s;
        });
        _emuHook(SP.get.overload('java.lang.String', 'java.lang.String'), function (key, def) {
            var v = this.get(key, def);
            if (!FLAGS.emulator || EMU_JAVA_PROP_KEYS.indexOf('' + key) === -1) return v;
            var s = _spoofProp(key, v);
            if (s === null) return v;
            send({type: 'info', hook: 'emulator-bypass:SystemProperties.get(' + key + ')'});
            return s === '' ? def : s;
        });
        send({type: 'info', hook: 'emulator-bypass:SystemProperties.get'});
    } catch (e) {}

    // TelephonyManager (TrigDroid's bypassTelephonyChecks set). TrigDroid's
    // IMEI/IMSI/ICCID fakes were the emulator's OWN defaults
    // (358240051111110, 310260000000000, 89014103211118510720), so these are
    // other, checksum-valid values; line 1 is empty, as on many real SIMs
    // (the emulator answers 15555215554). Identifier getters call through
    // first: on API 29+ a normal app gets the real SecurityException.
    var TELEPHONY = [
        ['getDeviceId', [], '358813084172653', true],
        ['getDeviceId', ['int'], '358813084172653', true],
        ['getSubscriberId', [], '310260518374921', true],
        ['getLine1Number', [], '', true],
        ['getSimSerialNumber', [], '89012604173859201844', true],
        ['getNetworkOperatorName', [], 'T-Mobile', false],
        ['getNetworkOperator', [], '310260', false],
        ['getPhoneType', [], 1, false],   // PHONE_TYPE_GSM
        ['getSimState', [], 5, false]     // SIM_STATE_READY
    ];
    try {
        var TM = Java.use('android.telephony.TelephonyManager');
        TELEPHONY.forEach(function (row) {
            var name = row[0], sig = row[1], fake = row[2], callThrough = row[3];
            try {
                var m = TM[name].overload.apply(TM[name], sig);
                _emuHook(m, function () {
                    if (!FLAGS.emulator) return m.apply(this, arguments);
                    if (callThrough) {
                        // Throws where a real phone throws (permissions).
                        var real = m.apply(this, arguments);
                        if (real === null) return real;
                    }
                    send({type: 'info', hook: 'emulator-bypass:TelephonyManager.' + name});
                    return fake;
                });
            } catch (e) {}
        });
        send({type: 'info', hook: 'emulator-bypass:TelephonyManager'});
    } catch (e) {}

}

function _emuInstall() {
    if (_emuInstalled) return;
    _emuInstalled = true;
    if (EMU_PROFILE === null) _emuInitProfile(_emuRealProp);
    try { _emuInstallPropHook(); } catch (e) {
        send({type: 'debug', hook: 'emulator-bypass:__system_property_get', error: e.message});
    }
    // Emulator files and pipes go through the shared path hider (one
    // replacement per export, see preamble); registered once, flag-gated.
    if (!_emuPathsRegistered) {
        _emuPathsRegistered = true;
        try {
            hidePaths('emulator', function (path, returnAddress) {
                return _isEmuPath(path) && _isAppCaller(returnAddress);
            }, 2);
        } catch (e) {
            send({type: 'debug', hook: 'emulator-bypass:path-hider', error: e.message});
        }
    }
    Java.perform(_emuInstallJavaHooks);
    _emuApplyBuild(true);
}

function _emuUninstall() {
    if (!_emuInstalled) return;
    _emuInstalled = false;
    _emuApplyBuild(false);
    Java.perform(function () {
        _emuJavaHooks.forEach(function (m) {
            try { m.implementation = null; } catch (e) {}
        });
        _emuJavaHooks = [];
    });
    if (_emuPropListener !== null) {
        try { _emuPropListener.detach(); } catch (e) {}
        _emuPropListener = null;
    }
    send({type: 'info', hook: 'emulator-bypass:uninstalled'});
}

if (FLAGS.emulator) _emuInstall();
FLAG_LISTENERS.push(function (flags) {
    if (flags.emulator) _emuInstall(); else _emuUninstall();
});

send({type: 'ready', message: 'Emulator detection bypass ready (installs on enable)'});
"""

EMULATOR_DETECTION_HOOKS = [
    "android.os.Build.FINGERPRINT",
    "android.os.Build.MODEL",
    "android.os.Build.MANUFACTURER",
    "android.os.Build.BRAND",
    "android.os.Build.DEVICE",
    "android.os.Build.PRODUCT",
    "android.os.Build.HARDWARE",
    "android.os.Build.BOARD",
    "android.os.Build.TAGS",
    "android.os.Build.TYPE",
    "android.os.Build.DISPLAY",
    "android.os.Build.IS_EMULATOR",
    "android.os.Build.getSerial",
    "android.os.SystemProperties.get",
    "android.telephony.TelephonyManager.getDeviceId",
    "android.telephony.TelephonyManager.getSubscriberId",
    "android.telephony.TelephonyManager.getLine1Number",
    "android.telephony.TelephonyManager.getSimSerialNumber",
    "android.telephony.TelephonyManager.getNetworkOperatorName",
    "android.telephony.TelephonyManager.getNetworkOperator",
    "android.telephony.TelephonyManager.getPhoneType",
    "android.telephony.TelephonyManager.getSimState",
    # Native hooks shared with the root category: one path-hider replacement
    # per file probe, a stacked listener on __system_property_get (distinct
    # ids, like the debug category's ``libc:openat:tracerpid``).
    "libc:__system_property_get:emulator",
    "libc:access:emulator",
    "libc:faccessat:emulator",
    "libc:fopen:emulator",
    "libc:stat:emulator",
    "libc:lstat:emulator",
    "libc:fstatat:emulator",
]


class EmulatorDetectionBypassManager(BypassManagerBase):
    """Hide emulator markers (Build.*, qemu props, emulator files, telephony)."""

    TOOL_NAME = "emulator_detection_bypass"
    DISPLAY_NAME = "Emulator Detection Bypass (experimental)"
    HOOKS_REGISTRY = EMULATOR_DETECTION_HOOKS
    FRIDA_SCRIPT = _EMULATOR_DETECTION_SCRIPT
    PRIORITY = 8  # before root/debug (10): Build/props must be in place early
    APPLY_AT_SPAWN = True


# ---------------------------------------------------------------------------
# Bypass service (singleton owning all managers)
# ---------------------------------------------------------------------------

# Category keys are the stable identifiers used by the panel and
# MitmproxyService. "ssl" maps to SSLUnpinManager (imported lazily to
# avoid a circular import: ssl_unpin imports this module's base class).
#: Every bypass category is EXPERIMENTAL: hooks target specific library
#: versions/obfuscations and can silently miss (or crash) an app. All are OFF
#: by default (nothing is armed until the analyst toggles it) and every
#: user-facing name/message carries this tag.
EXPERIMENTAL_SUFFIX = " (experimental)"

#: Dexray Intercept's own bypass group (``bypass_hooks``: root/frida/
#: debugger/emulator/hook detection) never runs alongside these categories:
#: in experiments both together crashed apps (recursion in the File.exists
#: hooks). Either side refuses to start while the other is on, with this.
BYPASS_CONFLICT_CHOICE = (
    "choose one: Dexray's bypass group or the Bypass (b) categories"
)
#: Dexray's ``telephony_hooks`` replace the same TelephonyManager methods as
#: the emulator category, from a second script (the same two-bridge
#: double-replace that crashed File.exists), so that pair excludes too.
TELEPHONY_CONFLICT_CHOICE = (
    "choose one: Dexray's telephony hooks or the Emulator bypass (b 6)"
)
#: Owner name Dexray Intercept claims exclusivity under.
DEXRAY_BYPASS_OWNER = "Dexray Intercept"


@dataclass(frozen=True)
class _ExclusiveClaim:
    """Another bypass source holding some categories (see claim_exclusive)."""

    owner: str
    what: str
    categories: frozenset[str]
    choice: str
    is_alive: Callable[[], bool] | None
    resolve: str = ""


_CATEGORY_DISPLAY = {
    "ssl": "SSL Pinning Bypass",
    "frida": "Frida Detection Bypass",
    "root": "Root Detection Bypass",
    "debug": "Debug Detection Bypass",
    "integrity": "Integrity / Attestation Bypass",
    "emulator": "Emulator Detection Bypass",
}


def _notifies(method):
    """Notify the state listeners when ``method`` changed armed or active."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        before = self._state_key()
        try:
            return method(self, *args, **kwargs)
        finally:
            if self._state_key() != before:
                self._notify_state()

    return wrapper


class BypassService:
    """Owns the armed/active bypass categories and one flag-gated Frida script.

    Process-wide singleton so the bypass job survives TUI screen changes —
    Textual recreates widgets on screen change, so panel-local state would
    orphan the running job.

    **One persistent flag-gated script.** Instead of loading/unloading a script
    per category (a fresh ``script.load`` each time = a new frida-java-bridge on
    the contended JS thread, which is slow and causes a no-hooks gap on
    off-toggle), this assembles ONE combined script (preamble + every
    category's source, each hook body early-checking its ``FLAGS[category]``) and
    loads it once per session. Toggling a category is then an instant
    ``set_flags`` RPC — no reload, no gap, and exactly one Java bridge (so the
    paused-spawn #218 crash is moot: one combined script = one ``create_script``
    = one bridge, resumed after a single load).

    Reconciles ``_active`` from the categories whose IIFE loaded without a
    ``merge_error`` so :meth:`is_active` never reports a broken category active.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # In-flight guard for the *mutating* path (load / set_flags). Acquired
        # non-blocking at the top of set_active and released in a finally in the
        # SAME frame — never a flag an external watchdog resets, so an abandoned
        # worker can't wedge it forever. Distinct from _lock (which guards reads
        # so UI rendering stays responsive while a load is in flight).
        self._mutate_lock = threading.Lock()
        # One resident job + its loaded script + the temp file we own.
        self._job: Any = None
        self._script: Any = None
        self._temp_path: str | None = None
        # Category labels whose IIFE reported a merge_error at load (so they are
        # NOT counted active). Reset on every fresh load.
        self._merge_errors: set[str] = set()
        self._active: set[str] = set()
        self._app_package: str | None = None
        self._process_id: int | None = None
        # Categories the user has *armed* (intends to apply). Distinct from
        # active: a category can be armed while the app is stopped (applied on
        # the next Start/Restart) and active without being armed (started
        # directly, e.g. Ctrl+P SSL unpin). The panel renders armed | active.
        self._armed: set[str] = set()
        self._on_message: Callable[[Any], None] | None = None
        # Display string of the currently-registered TaskService entry (None
        # when unregistered), so _register_task can refresh a changed display
        # without re-registering identically every toggle.
        self._task_display: str | None = None
        # Other bypass sources holding categories (Dexray's bypass group or
        # telephony hooks), by claim token. While a claim covers a category,
        # it may not be armed or started. See claim_exclusive().
        self._claims: dict[str, _ExclusiveClaim] = {}
        # Categories the in-flight set_active (under _mutate_lock) turns on;
        # a claim on any of them waits for it, unrelated claims do not.
        self._mutating: frozenset[str] = frozenset()
        # Bumped by release_app: a load in flight when the selection moved
        # away from its app is discarded instead of stored (_ensure_loaded).
        self._release_gen = 0
        # Called after the armed or active set changed, see add_state_listener.
        self._state_listeners: list[Callable[[], None]] = []
        self._listeners_lock = threading.Lock()

    # -- state listeners ---------------------------------------------------

    def add_state_listener(self, cb: Callable[[], None]) -> None:
        """Call ``cb()`` after every change of the armed or active set.

        Runs on whichever thread made the change: a worker, or the UI thread
        itself (a new app selection disarms from UI code). Keep it short and
        non-blocking and post to the UI without assuming the thread (e.g.
        ``call_later`` / ``post_message``, or a dispatcher that runs inline
        on the UI thread; ``call_from_thread`` raises there). Read the new
        state with :meth:`on_categories` / :meth:`armed_categories` /
        :meth:`active_categories`. Errors are logged, not raised.
        """
        with self._listeners_lock:
            if cb not in self._state_listeners:
                self._state_listeners.append(cb)

    def remove_state_listener(self, cb: Callable[[], None]) -> None:
        with self._listeners_lock:
            if cb in self._state_listeners:
                self._state_listeners.remove(cb)

    def _state_key(self) -> tuple[frozenset[str], frozenset[str]]:
        with self._lock:
            return frozenset(self._armed), frozenset(self._active)

    def _notify_state(self) -> None:
        with self._listeners_lock:
            listeners = list(self._state_listeners)
        for cb in listeners:
            try:
                cb()
            except Exception:
                logger.debug("Bypass state listener failed", exc_info=True)

    # -- mutual exclusion with other bypass sources (Dexray) --------------

    def claim_exclusive(
        self,
        owner: str,
        *,
        what: str = "its bypass group",
        categories=None,
        choice: str = BYPASS_CONFLICT_CHOICE,
        is_alive: Callable[[], bool] | None = None,
        resolve: str = "",
    ) -> tuple[str | None, str]:
        """Claim bypass categories for another source (e.g. Dexray's group).

        Refused while any claimed category is armed or active, or while a
        bypass load turning one of them on is in flight. While the claim is held, arming or starting
        a claimed category is refused in turn. Arming checks under ``_lock``
        and a load checks while holding ``_mutate_lock``, so neither side can
        slip in between.

        Args:
            owner: User-facing name of the claiming source.
            what: What of the owner conflicts (``"its telephony hooks"``).
            categories: Categories claimed; None claims every category.
            choice: The "choose one: ..." sentence both refusals end with.
            is_alive: Optional liveness probe; a claim whose probe returns
                False (or raises) is dropped the next time it is checked
                (e.g. the owner's job died with the app).
            resolve: How the user frees the categories, appended to this
                side's refusal (``"stop Dexray Intercept (m) first"``).

        Returns:
            ``(token, message)``: the token releases this claim (and only this
            one) via :meth:`release_exclusive`; ``token`` is None when refused,
            and ``message`` says why.
        """
        cats = frozenset(self.categories() if categories is None else categories)
        with self._lock:
            on = [
                c
                for c in self._categories_by_priority(self._armed | self._active)
                if c in cats
            ]
            if not on and self._mutating & cats:
                return None, (
                    f"Not starting {owner} with {what}: a Bypass (b) change "
                    f"is in progress — {choice}."
                )
            if on:
                names = ", ".join(self._plain_name(c) for c in on)
                return None, (
                    f"Not starting {owner} with {what}: Bypass (b) has "
                    f"{names} on — {choice}; turn them off with b first."
                )
            token = uuid.uuid4().hex
            self._claims[token] = _ExclusiveClaim(
                owner, what, cats, choice, is_alive, resolve
            )
        return token, f"{owner} holds {', '.join(sorted(cats))}"

    def release_exclusive(self, token: str | None) -> None:
        """Release the claim ``token`` names (idempotent; others are kept)."""
        if token is None:
            return
        with self._lock:
            self._claims.pop(token, None)

    def exclusive_conflict(self, categories=None) -> str | None:
        """Why ``categories`` (default: any) cannot be armed/started, or None."""
        wanted = set(self.categories() if categories is None else categories)
        with self._lock:
            claims = list(self._claims.items())
        for token, claim in claims:
            if not claim.categories & wanted:
                continue
            if claim.is_alive is not None:
                try:
                    alive = bool(claim.is_alive())
                except Exception:
                    alive = False
                if not alive:
                    self.release_exclusive(token)
                    continue
            hint = f"; {claim.resolve}" if claim.resolve else ""
            return f"{claim.owner} is running with {claim.what} — {claim.choice}{hint}."
        return None

    # -- category metadata (data holders) ---------------------------------

    def _manager_class(self, category: str):
        if category == "ssl":
            from sandroid.analysis.ssl_unpin import SSLUnpinManager

            return SSLUnpinManager
        return {
            "frida": FridaDetectionBypassManager,
            "root": RootDetectionBypassManager,
            "debug": DebugDetectionBypassManager,
            "integrity": IntegrityBypassManager,
            "emulator": EmulatorDetectionBypassManager,
        }.get(category)

    def categories(self) -> list[str]:
        """All known category keys, in display order."""
        return ["ssl", "root", "frida", "debug", "integrity", "emulator"]

    def _plain_name(self, category: str) -> str:
        return _CATEGORY_DISPLAY.get(category, category)

    def display_name(self, category: str) -> str:
        """User-facing name, always tagged experimental (see module docstring)."""
        return _CATEGORY_DISPLAY.get(category, category) + EXPERIMENTAL_SUFFIX

    def _categories_by_priority(self, categories) -> list[str]:
        """Order categories by PRIORITY (lower first) for the merged order.

        Anti-anti-Frida (priority 5) must install before root/debug (10) and
        SSL (15) so a hardened app cannot detect un-bypassed Frida mid-load.
        Reads the class attribute only; never instantiates a manager.
        """

        def prio(cat: str) -> int:
            cls = self._manager_class(cat)
            return getattr(cls, "PRIORITY", 50) if cls else 50

        return sorted(categories, key=prio)

    def _frida_script(self, category: str) -> str:
        cls = self._manager_class(category)
        return getattr(cls, "FRIDA_SCRIPT", "") if cls else ""

    def _union_hooks(self, categories) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for cat in categories:
            cls = self._manager_class(cat)
            hooks = getattr(cls, "HOOKS_REGISTRY", []) if cls else []
            for hook in hooks:
                if hook not in seen:
                    seen.add(hook)
                    out.append(hook)
        return out

    def _flag_dict(self, target) -> dict[str, bool]:
        """Map a target category set to the full ``{category: bool}`` flag dict.

        Always carries every category key so the baked ``FLAGS`` object and
        every ``set_flags`` RPC are complete (the JS preamble's ``setFlags``
        merges, but a complete dict keeps state unambiguous).
        """
        target = set(target)
        return {cat: (cat in target) for cat in self.categories()}

    # -- single Frida message handler for the combined script -------------

    def _message_handler(self, job, message, data) -> None:
        """Log by the payload's ``hook`` prefix; record ``merge_error``.

        Forwards the raw payload to an optional ``on_message`` callback.
        ``Job.wrap_custom_hooking_handler_with_job_id`` invokes the handler as
        ``handler(job, message, data)``. Unlike the old bundle path (where AFM
        intercepted ``merge_error``), we load via ``start_job`` directly, so this
        handler must track failed-category labels itself for ``_active``
        reconciliation.
        """
        msg_type = message.get("type", "")
        if msg_type == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                if "merge_error" in payload:
                    label = payload.get("merge_error")
                    with self._lock:
                        self._merge_errors.add(label)
                    logger.warning(
                        "[Bypass] hook-set '%s' failed to load: %s",
                        label,
                        payload.get("error", ""),
                    )
                else:
                    ptype = payload.get("type", "")
                    hook = payload.get("hook", "")
                    if ptype == "info":
                        # The combined script installs the hooks of every
                        # category up front; FLAGS decide which act. So an
                        # install line is no sign the category is on (a
                        # Frida-only b 3 logged root/debug/SSL "Hooked:").
                        logger.debug(f"[Bypass] Hook installed: {hook}")
                    elif ptype == "ready":  # per category, see above
                        logger.debug(f"[Bypass] {payload.get('message', 'Ready')}")
                    elif ptype == "debug":
                        logger.debug(f"[Bypass] {hook}: {payload.get('error', '')}")
            cb = self._on_message
            if cb:
                try:
                    cb(payload)
                except Exception:
                    pass
        elif msg_type == "error":
            error_msg = message.get("description", str(message))
            logger.error(f"[Bypass] Error: {error_msg}")

    # -- session setup ----------------------------------------------------

    def _setup_session(self, *, paused: bool) -> bool:
        """Ensure a Frida session on the spotlight app, never starting it.

        Records :attr:`_app_package` / :attr:`_process_id` and surfaces the
        PID to the spotlight panel. Joins the JobManager's session on the app
        (the paused spawn of Start/⇧P/⇧R, or a live session of another tool)
        or attaches to the running PID. A stopped app is refused, never
        spawned (:func:`sandroid.services.app_start.resolve_start` with
        ``allow_spawn=False``), and a running one is never restarted.

        Returns:
            False (kept for callers: this never creates a spawn to resume).

        Raises:
            ValueError: No spotlight app, the app is not running, or Frida is
                busy (the message says why).
        """
        from sandroid.services.app_start import StartAction, open_session
        from sandroid.services.app_start import resolve_start as _resolve

        spotlight = get_spotlight_service()
        decision = _resolve(tool="Bypass", allow_spawn=False, java_agent=False)
        if decision.action not in (StartAction.JOIN, StartAction.ATTACH):
            raise ValueError(decision.reason or "Spotlight app not available")
        self._app_package = decision.package
        if decision.action == StartAction.ATTACH:
            logger.debug("Attaching the bypass to PID %s", decision.pid)
            open_session(decision, self._message_handler)
        else:
            logger.debug("Reusing the Frida session on PID %s", decision.pid)
        process_id = decision.pid
        self._process_id = process_id
        # Surface the resolved PID so the spotlight panel shows it (non-
        # publishing, so this does not retrigger a panel refresh loop).
        if process_id:
            spotlight.set_pid(process_id)
        return False

    # -- combined-script assembly -----------------------------------------

    def _assemble_source(self, initial_flags: dict[str, bool]) -> str:
        """Build the ONE combined, flag-gated bypass script.

        Layout (realm-top scope):

        - Preamble: ``'use strict';`` + ``var FLAGS = <json>;`` +
          ``var FLAG_LISTENERS = [];`` + ``rpc.exports`` (``setFlags`` merges a
          partial dict, calls every ``FLAG_LISTENERS`` entry with FLAGS -- for
          state a hook body cannot gate, like the emulator category's Build
          field writes -- and returns FLAGS; ``getFlags`` returns it).
          ``json.dumps`` is used everywhere — category names are never
          string-interpolated.
        - Each category source wrapped in a function handed to
          ``registerCategory`` (``var`` isolation), ordered by priority so the
          anti-anti-Frida prelude installs first. The function runs -- and the
          category's hooks install -- only once its flag is on (at load, or on
          the ``setFlags`` that turns it on); a throw is reported via
          ``send({merge_error: <label>})`` and ``installFailures()``.

        Category bodies read the shared ``FLAGS`` via closure over this
        realm-top declaration and must NOT re-declare ``var FLAGS``. Each source
        keeps its own leading ``'use strict';`` (a directive for its function).
        """
        # 'use strict' MUST stay first (it is only a directive at the very top).
        # The Java bridge prelude runs next so globalThis.Java exists before any
        # hook-set IIFE references it (frida 17 no longer auto-injects `Java`).
        # ObjC is intentionally omitted — the hook-sets are Android-only.
        preamble = (
            "'use strict';\n"
            + _java_bridge_prelude()
            + "var FLAGS = "
            + json.dumps(initial_flags)
            + ";\n"
            "var FLAG_LISTENERS = [];\n" + _PREAMBLE_HELPERS_JS + "rpc.exports = {\n"
            "    setFlags: function (f) {\n"
            "        if (f) {\n"
            "            for (var k in f) {\n"
            "                if (Object.prototype.hasOwnProperty.call(f, k)) {\n"
            "                    FLAGS[k] = !!f[k];\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "        _installEnabledCategories();\n"
            "        for (var i = 0; i < FLAG_LISTENERS.length; i++) {\n"
            "            try { FLAG_LISTENERS[i](FLAGS); } catch (e) {}\n"
            "        }\n"
            "        return FLAGS;\n"
            "    },\n"
            "    getFlags: function () { return FLAGS; },\n"
            "    installFailures: function () { return INSTALL_FAILED; }\n"
            "};\n"
        )
        parts = [preamble]
        for category in self._categories_by_priority(self.categories()):
            src = self._frida_script(category)
            if not src:
                continue
            label = json.dumps(category)
            parts.append(
                "registerCategory(" + label + ", function () {\n" + src + "\n});\n"
            )
        return "".join(parts)

    def _is_job_live(self, jm) -> bool:
        """True if the resident bypass job is loaded and its session alive.

        Checks ``job.state == "running"`` AND ``jm.has_active_session()`` AND
        that the job is still tracked — NOT merely ``_script is not None`` (the
        handle is not nulled on process death, so a stale non-None script would
        otherwise pass).
        """
        job = self._job
        if job is None or self._script is None:
            return False
        try:
            if getattr(self._script, "is_destroyed", False):
                return False
            if getattr(job, "state", None) != "running":
                return False
            if not jm.has_active_session():
                return False
            if job.get_id() not in getattr(jm, "jobs", {}):
                return False
        except Exception:
            return False
        return True

    def _ensure_loaded(
        self, *, paused: bool, initial_flags: dict[str, bool]
    ) -> tuple[bool, str, bool]:
        """Idempotently ensure the combined bypass script is loaded.

        Reuses a live job; otherwise resets stale state, ensures a session,
        assembles the combined source with ``initial_flags`` baked in, writes a
        temp file we own, loads it via a non-destructive ``start_job``, and gates
        readiness on ``job.wait_until_ready`` + ``state == "running"`` (NOT a
        ``get_script_of_job()`` non-None poll, which would race the load — the
        script handle is set in ``instrument()`` *before* ``script.load()``).

        Runs on a worker thread (Part 1), so the readiness wait never freezes the
        UI; ``start_job`` is non-destructive on timeout, so we clean up ourselves
        and report — no AFM-side cascade.

        Returns ``(ok, message, freshly_loaded)``. ``freshly_loaded`` is True
        when this call loaded a new script (so its baked ``FLAGS`` already match
        ``initial_flags`` and the caller can skip a redundant ``set_flags`` RPC —
        which also avoids an RPC on a still-paused spawn).
        """
        jm = Toolbox.get_frida_job_manager()
        with self._lock:
            if self._is_job_live(jm):
                return True, "Bypass script already loaded", False
            generation = self._release_gen

        # Not live — drop any stale handles/temp, then load fresh.
        self._reset_script_state()
        with self._lock:
            self._merge_errors = set()

        try:
            self._setup_session(paused=paused)
        except ValueError as exc:
            return False, str(exc), False

        source = self._assemble_source(initial_flags)
        path: str | None = None
        try:
            fd, path = tempfile.mkstemp(prefix="sandroid-bypass-", suffix=".js")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(source)
        except Exception as exc:
            self._unlink(path)  # unlink if mkstemp succeeded but write failed
            return False, f"Failed to write bypass script: {exc}", False

        union = self._union_hooks(self.categories())
        display = "Detection Bypass"
        try:
            job = jm.start_job(
                path,
                custom_hooking_handler_name=self._message_handler,
                job_type="bypass",
                display_name=display,
                hooks_registry=union,
                priority=5,
                auto_resume=False,
            )
        except Exception as exc:
            self._unlink(path)
            return False, f"Failed to start bypass job: {exc}", False
        if job is None:
            self._unlink(path)
            return False, "Failed to start bypass job (no Frida session)", False

        if not job.wait_until_ready(_READINESS_TIMEOUT) or job.state != "running":
            err = job.get_error() or "hooks did not load (timeout)"
            try:
                jm.stop_job_with_id(job.get_id())
            except Exception:
                pass
            self._unlink(path)
            return False, f"Bypass load failed: {err}", False

        script = job.get_script_of_job()
        if script is None:
            try:
                jm.stop_job_with_id(job.get_id())
            except Exception:
                pass
            self._unlink(path)
            return False, "Bypass load failed: script unavailable", False

        with self._lock:
            stale = self._release_gen != generation
            if not stale:
                self._job = job
                self._script = script
                self._temp_path = path
        if stale:
            # The selection left this app while it loaded: never keep a
            # script in an app that is no longer selected.
            try:
                jm.stop_job_with_id(job.get_id())
            except Exception:
                pass
            self._unlink(path)
            return False, "Bypass not loaded: the app selection changed", False

        return True, "Bypass script loaded", True

    # -- the single transition point --------------------------------------

    @_notifies
    def set_active(
        self,
        target,
        *,
        paused: bool,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Reconcile the *armed* flag set to ``target`` (the one entry point).

        Loads the combined script once (lazily) then flips the per-category
        ``FLAGS`` via the ``set_flags`` RPC — instant and gap-free, with exactly
        one Java bridge. No more per-toggle ``script.load``.

        Args:
            target: Desired set of active category keys.
            paused: True only on the paused-spawn load (bakes flags before the
                single resume). False for every live transition.
            on_message: Optional Frida payload callback. Stored *before* loading
                so the message handler closure can read it at message time.

        Returns:
            (success, message).
        """
        target = set(target)

        # In-flight guard: serialize the mutating path. Released in finally in
        # THIS frame so an abandoned worker can never wedge it (no watchdog
        # reset). Pure reads use _lock and stay responsive meanwhile.
        if not self._mutate_lock.acquire(blocking=False):
            return False, "Bypass change already in progress"
        try:
            # Published under _lock before the claim check: claim_exclusive
            # refuses a claim on any category in _mutating, so a Dexray claim
            # and this load cannot interleave (unrelated claims still can).
            with self._lock:
                self._mutating = frozenset(target)
            if target:
                conflict = self.exclusive_conflict(target)
                if conflict:
                    return False, conflict
            jm = Toolbox.get_frida_job_manager()
            with self._lock:
                if on_message is not None:
                    self._on_message = on_message
                # Early-return if nothing changes AND the script is still live.
                # Without the liveness check, a stale _active (app self-died
                # without Kill) would skip hook installation on the new process.
                if target == self._active and self._is_job_live(jm):
                    return True, "No bypass change"
                # Never load a live combined script while the session is still
                # paused unless this IS the paused-spawn load (paused=True):
                # a 2nd create_script on a paused spawn SIGSEGVs the agent
                # (#218). Flipping flags off (empty target) is always allowed.
                if target and not paused and jm.is_paused():
                    logger.warning("set_active(live) while session paused; skipping")
                    return False, ("Session paused — resume before changing hooks")

            # Empty target -> flip every flag off but keep the script resident
            # (instant re-enable). Explicit teardown is stop_all's job.
            if not target:
                with self._lock:
                    script = self._script if self._is_job_live(jm) else None
                if script is not None:
                    try:
                        script.exports_sync.set_flags(self._flag_dict(set()))
                    except Exception as exc:
                        logger.warning("[Bypass] set_flags(off) failed: %s", exc)
                        self._reset_script_state()
                        return True, "All bypasses off"
                with self._lock:
                    self._active = set()
                self._unregister_task()
                return True, "All bypasses off"

            # Ensure the combined script is loaded (bakes flags = target on a
            # fresh load; reuses an existing live job otherwise).
            flags = self._flag_dict(target)
            ok, msg, fresh = self._ensure_loaded(paused=paused, initial_flags=flags)
            if not ok:
                return False, msg

            # On a fresh load the baked FLAGS already equal `target`, so skip
            # the RPC — this also avoids a set_flags RPC on a still-paused
            # spawn. When reusing a live script, flip its flags to `target`.
            # On RPC failure (e.g. script destroyed by a process restart),
            # reload transparently — one automatic retry.
            if not fresh:
                with self._lock:
                    script = self._script
                if script is None:
                    return False, "Bypass script unavailable"
                try:
                    script.exports_sync.set_flags(flags)
                    self._note_install_failures(script)
                except Exception as exc:
                    logger.warning("[Bypass] set_flags failed: %s — reloading", exc)
                    self._reset_script_state()
                    ok2, msg2, _ = self._ensure_loaded(
                        paused=paused, initial_flags=flags
                    )
                    if not ok2:
                        return False, f"Bypass reload failed: {msg2}"

            return self._reconcile_and_register(target)
        finally:
            with self._lock:
                self._mutating = frozenset()
            self._mutate_lock.release()

    def _note_install_failures(self, script) -> None:
        """Count categories whose lazy install (on a live flip) threw.

        At load a failure arrives as a ``merge_error`` message while we wait
        for readiness; a category first turned on by ``set_flags`` installs
        inside that RPC, so ask the script instead of racing the message.
        """
        try:
            failed = script.exports_sync.install_failures() or []
        except Exception:
            return
        with self._lock:
            self._merge_errors.update(str(c) for c in failed)

    def _reconcile_and_register(self, target) -> tuple[bool, str]:
        """Reconcile ``_active`` against merge errors and update TaskService."""
        with self._lock:
            failed = set(self._merge_errors)
            self._active = target - failed
            active_now = set(self._active)

        if active_now:
            display = "Bypass (experimental): " + ", ".join(
                self._plain_name(c) for c in self._categories_by_priority(active_now)
            )
            self._register_task(display)
            return True, display
        self._unregister_task()
        return True, "All bypasses off"

    # -- armed set (user intent, independent of live state) ---------------

    def _arm(self, category: str) -> None:
        with self._lock:
            self._armed.add(category)

    def _arm_unless_claimed(self, category: str) -> str | None:
        """Arm ``category`` unless another source holds the bypasses.

        Check and arm happen under one lock acquisition, so a concurrent
        :meth:`claim_exclusive` sees either the armed category or nothing.

        Returns:
            None when armed, else the refusal message.
        """
        with self._lock:
            conflict = self.exclusive_conflict([category])
            if conflict:
                return conflict
            self._armed.add(category)
        return None

    def _disarm(self, category: str) -> None:
        with self._lock:
            self._armed.discard(category)

    def armed_categories(self) -> list[str]:
        """Categories the user has armed (intends to apply on Start)."""
        with self._lock:
            return list(self._armed)

    def _spotlight_running(self) -> bool:
        """True if the spotlight app has a live (non-paused) process."""
        try:
            sp = get_spotlight_service()
            return sp.get_pid() is not None and not sp.is_app_paused()
        except Exception:
            return False

    # -- public category controls -----------------------------------------

    def _arm_unless_live(self, categories) -> tuple[bool, str] | None:
        """Arm ``categories`` instead of loading them when the app is not live.

        Ctrl+P / the AI ``start_ssl_unpin`` never start or restart the app:
        a stopped app gets the categories armed (␣ starts it with them), a
        held paused spawn gets them on ␣ resume.

        Returns:
            ``(ok, message)`` when armed or refused, None when the app runs
            and the caller loads the categories live.
        """
        from sandroid.services.app_start import StartAction
        from sandroid.services.app_start import resolve_start as _resolve

        decision = _resolve(tool="Bypass", allow_spawn=False, java_agent=False)
        names = ", ".join(self.display_name(c) for c in categories)
        if decision.action == StartAction.JOIN and decision.paused:
            for cat in categories:
                self._arm(cat)
            return True, f"{names} armed — ␣ resume applies it"
        if decision.action == StartAction.REFUSE:
            if decision.code == "not_running":
                for cat in categories:
                    self._arm(cat)
                return True, f"{names} armed — ␣ starts {decision.package} with it"
            return False, decision.reason
        return None

    @_notifies
    def start(
        self,
        category: str,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Add one category live. Idempotent; arms only when not running."""
        cls = self._manager_class(category)
        if cls is None:
            return False, f"Unknown bypass category: {category}"
        conflict = self.exclusive_conflict([category])
        if conflict:
            return False, conflict
        with self._lock:
            if category in self._active:
                return True, f"{self.display_name(category)} already active"
            target = set(self._active) | {category}
        armed = self._arm_unless_live([category])
        if armed is not None:
            return armed
        return self.set_active(target, paused=False, on_message=on_message)

    @_notifies
    def start_many(
        self,
        categories,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Add several categories live in ONE set_flags op (no N reloads).

        Arms only when the app is not running (never starts it).
        """
        conflict = self.exclusive_conflict(categories)
        if conflict:
            return False, conflict
        with self._lock:
            target = set(self._active) | set(categories)
        armed = self._arm_unless_live(sorted(set(categories)))
        if armed is not None:
            return armed
        return self.set_active(target, paused=False, on_message=on_message)

    @_notifies
    def stop(self, category: str) -> bool:
        """Remove one category (and disarm it). Idempotent."""
        with self._lock:
            active = category in self._active
            self._armed.discard(category)
            if not active:
                return False
            target = set(self._active) - {category}
        self.set_active(target, paused=False)
        return True

    @_notifies
    def toggle(
        self,
        category: str,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Toggle a category against the armed | active set.

        - ON + running     -> arm and flip the flag on live (instant).
        - ON + not running  -> arm only; applied by the next Start/Restart.
        - OFF + active      -> flip the flag off (script stays resident) + disarm.
        - OFF + armed-only  -> disarm.

        Returns ``(now_on, message)``.
        """
        name = self.display_name(category)
        with self._lock:
            currently_on = category in self._armed or category in self._active

        if not currently_on:
            # Turning ON (arming counts: refused while Dexray holds bypasses).
            conflict = self._arm_unless_claimed(category)
            if conflict:
                return False, conflict
            if self._spotlight_running():
                with self._lock:
                    target = set(self._active) | {category}
                ok, msg = self.set_active(target, paused=False, on_message=on_message)
                if not ok:
                    self._disarm(category)
                    return False, msg
                if self.applies_at_spawn(category):
                    return True, (
                        f"{name} active — restart the app (⇧R) so checks it "
                        "ran at startup see it too"
                    )
                return True, f"{name} active"
            if self.is_paused_session():
                return True, f"{name} armed — ␣ resume applies it"
            return True, f"{name} armed — ␣ start applies it"

        # Turning OFF.
        self._disarm(category)
        with self._lock:
            active = category in self._active
            target = set(self._active) - {category}
        if active:
            self.set_active(target, paused=False)
        return False, f"{name} off"

    # -- queries ----------------------------------------------------------

    def applies_at_spawn(self, category: str) -> bool:
        """True if ``category`` only fully works from the app's start."""
        return bool(getattr(self._manager_class(category), "APPLY_AT_SPAWN", False))

    @_notifies
    def forget_process(self) -> None:
        """Drop the resident script and its process (keeps the armed set).

        For a restart or a dropped Frida session: the next load goes onto
        the new process from scratch.
        """
        self._reset_script_state()

    @_notifies
    def keep_armed_and_forget(self, package: str | None = None) -> list[str]:
        """Drop the resident script but keep its categories as intent (⇧K).

        The active categories join the armed set (also those turned on live
        without arming, e.g. Ctrl+P), then the script state is reset like
        :meth:`forget_process`. The next start applies them all.

        Args:
            package: The app being stopped; active categories hooked into
                another app (the selection changed since) are not kept.

        Returns:
            The armed categories, in display order.
        """
        # One lock hold for the union and the drop: a live toggle lands
        # either before (kept as armed) or after (a fresh load), never lost.
        with self._lock:
            if package is None or self._app_package == package:
                self._armed |= self._active
            armed = set(self._armed)
            job, path = self._take_script_locked()
        self._dispose_script(job, path)
        rank = {c: i for i, c in enumerate(self.categories())}
        return sorted(armed, key=lambda c: (rank.get(c, len(rank)), c))

    @_notifies
    def release_app(self, package: str) -> list[str]:
        """Unhook ``package`` when the live script is in it (selection left it).

        A new selection starts clean, so the app left behind loses its live
        bypass too, not only the armed set. The script handles are dropped
        at once (any start, toggle or attach after this loads fresh for the
        new app); the unload itself, which can take seconds, runs on a
        daemon thread.

        Returns:
            The categories that were live in ``package`` ([] when none).
        """
        with self._lock:
            # Always: a load for ``package`` still in flight is discarded.
            self._release_gen += 1
            if self._app_package != package or (self._job is None and not self._active):
                return []
            was = sorted(self._active)
            job, path = self._take_script_locked()
        # The task entry goes now (a late unregister could remove the new
        # app's); the slow job stop runs on a daemon thread.
        self._unregister_task()
        threading.Thread(
            target=self._stop_job_and_unlink,
            args=(job, path),
            name="bypass-release",
            daemon=True,
        ).start()
        return was

    def _stop_job_and_unlink(self, job: Any, path: str | None) -> None:
        if job is not None:
            try:
                Toolbox.get_frida_job_manager().stop_job_with_id(job.get_id())
            except Exception as exc:
                logger.warning("stop_job during release failed: %s", exc)
        self._unlink(path)

    @_notifies
    def disarm_all(self) -> list[str]:
        """Clear the armed set; the live script is left alone.

        Armed is intent for one app: a new spotlight selection starts clean.

        Returns:
            The categories that were armed.
        """
        with self._lock:
            cleared = sorted(self._armed)
            self._armed.clear()
        return cleared

    def is_active(self, category: str) -> bool:
        with self._lock:
            return category in self._active

    def target_app(self, category: str) -> str | None:
        with self._lock:
            return self._app_package if category in self._active else None

    def active_categories(self) -> list[str]:
        with self._lock:
            return list(self._active)

    def on_categories(self) -> list[str]:
        """Categories that are armed OR active (what the panel renders ON)."""
        with self._lock:
            return sorted(self._armed | self._active)

    @_notifies
    def arm_active(self, package: str) -> None:
        """Add the categories active on ``package`` to the armed set.

        Called before a force-stop: the liveness poll may clear the active
        set as soon as the process dies. Unloads nothing, so it cannot hang.
        """
        with self._lock:
            if self._app_package == package:
                self._armed |= self._active

    def carried_categories(self, package: str) -> set[str]:
        """What a restart of ``package`` re-applies: armed, plus active on it."""
        with self._lock:
            if self._app_package == package:
                return self._armed | self._active
            return set(self._armed)

    @_notifies
    def reconcile_liveness(self) -> list[str]:
        """Drop the active categories when their hooked process is gone.

        A Zygote restart (Ctrl+N), a crash or a force-stop kills the hooked
        process; "SSL unpin ✓" and "Hooks 1 · bypass ssl" used to stay for as
        long as Sandroid ran. Gone means: the Frida session detached or the
        script was destroyed (``_is_job_live``), or the spotlight app now runs
        under another PID. The armed set is kept, so the next Start/Restart
        re-applies the categories. Blocking only when it stops the dead job:
        call it off the UI thread.

        Returns:
            The categories that were dropped (empty while all is well, while
            nothing is active, or while a load is in flight).
        """
        with self._lock:
            active = sorted(self._active)
            job, pid, package = self._job, self._process_id, self._app_package
        if not active or job is None:
            return []
        if self._mutate_lock.locked():
            return []  # a load / set_flags is in flight: not our call now
        alive = True
        try:
            alive = self._is_job_live(Toolbox.get_frida_job_manager())
        except Exception:
            alive = True  # cannot tell: keep showing what we have
        if alive and pid is not None:
            try:
                current = get_spotlight_service().get_pid()
            except Exception:
                current = None
            if current is not None and current != pid:
                alive = False
        if alive:
            return []
        with self._lock:
            if self._job is not job:  # replaced meanwhile (a new load)
                return []
        names = ", ".join(self.display_name(c) for c in active)
        logger.warning(
            "[Bypass] %s (PID %s) is gone, so its hooks (%s) are no longer "
            "active. Start the app again to re-apply them (armed bypasses are "
            "applied on Start), or press Ctrl+P for SSL unpin.",
            package or "the hooked app",
            pid if pid is not None else "?",
            names,
        )
        self._reset_script_state()
        return active

    @_notifies
    def stop_all(self) -> list[str]:
        """Stop the resident bypass script for real and clear the armed set.

        This is the explicit "done" teardown: it stops the job, unlinks the temp
        file, and unregisters the task — distinct from a toggle-last-off, which
        keeps the script resident (flags all false) for instant re-enable.
        """
        with self._lock:
            stopped = list(self._active)
        self._reset_script_state()
        with self._lock:
            self._armed.clear()
        return stopped

    # -- orchestration ----------------------------------------------------

    @_notifies
    def apply_armed(
        self,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Apply every armed category live (attach path).

        The spotlight must already point at a running app. Idempotent via
        set_active's early-return.
        """
        with self._lock:
            armed = set(self._armed)
        if not armed:
            return True, "Attached (no bypasses armed)"
        ok, msg = self.set_active(armed, paused=False, on_message=on_message)
        if not ok:
            return False, msg
        return True, "Applied (experimental): " + ", ".join(
            self._plain_name(c) for c in self._categories_by_priority(armed)
        )

    @_notifies
    def apply_to_fresh_spawn(
        self,
        package: str,
        categories,
        on_message: Callable[[Any], None] | None = None,
        resume: bool = True,
    ) -> tuple[bool, str]:
        """Spawn ``package`` paused, load the combined script, then resume.

        Race-correct multi-bypass spawn path. MUST run on a worker thread — it
        blocks on the spawn and on the script load.

        On a paused spawn the bypasses load as ONE combined flag-gated script
        (one ``create_script`` = one Java bridge) before the single resume, so
        the #218 paused-spawn crash is moot. Flags are baked into ``FLAGS`` so
        the native hooks are armed at the first instruction; this defeats
        detectors computed before the UI (e.g. JailMonkey's ``isJailBroken`` at
        React-Native bridge init). Java hooks still land after ``Java.perform``
        regardless — same as before, no regression and no improvement there.

        Args:
            package: Package to spawn.
            categories: Bypass categories to load (typically the armed set).
            on_message: Optional Frida payload callback.
            resume: When False, leave the app paused with the full set loaded
                (the advanced Start-paused flow); Resume just resumes, since
                every hook is already installed.

        Returns:
            (success, message).
        """
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        cats = set(categories)
        if cats:
            conflict = self.exclusive_conflict(cats)
            if conflict:
                return False, conflict  # before spawning anything

        # A fresh spawn invalidates any prior job (it lives on a now dead/
        # replaced process). Clear script state up front so set_active loads
        # onto the new process from scratch and its no-change early-return can
        # never skip installing hooks — e.g. after the app self-died without a
        # Kill, leaving _active stale and equal to the armed set.
        self._reset_script_state()

        # 1. Spawn paused.
        jm, pid = spotlight.spawn_app_paused(package)
        if not pid or pid <= 0:
            reason = getattr(spotlight, "last_spawn_error", None)
            if isinstance(reason, str) and frida_server_down(reason):
                return False, f"{FRIDA_SERVER_DOWN_MSG} (spawn of {package})"
            return False, (
                f"Failed to spawn {package} (no PID — is frida-server running?)"
            )

        if not self.is_paused_session():
            logger.warning(
                "Expected a paused session after spawn_app_paused(%s); "
                "proceeding cautiously",
                package,
            )

        # 2. Surface the PID immediately -- publishing, so the header shows it
        #    now, not when the whole spawn (hooks, resume, splash check) ends.
        if not spotlight.announce_pid(pid, package):
            spotlight.set_pid(pid)

        # 3. Load every bypass as ONE merged script while paused (#218-safe).
        ok, msg = self.set_active(cats, paused=True, on_message=on_message)
        if not ok:
            self._teardown_failed_spawn(spotlight, package)
            return False, msg
        for category in cats:
            self._arm(category)  # keep intent so a later Restart re-applies it

        # 4. Start-paused: leave paused with the full set already loaded.
        if not resume:
            with self._lock:
                active_n = len(self._active)
            if not active_n:
                return True, f"Spawned (paused) {package} (no bypasses armed)"
            return True, (
                f"Spawned (paused) {package} with {active_n} bypass(es) (Resume to run)"
            )

        # 4'. Resume exactly once (we own this spawn), preserving the
        # anti-Frida self-kill diagnostic: resume_spawned_process_after_hooks
        # lets a ProcessNotFoundError propagate (resume_app would swallow it).
        try:
            Toolbox.resume_spawned_process_after_hooks(self._frida_device(), pid)
        except frida.ProcessNotFoundError:
            msg = (
                f"Process {pid} died during hook load — target likely has "
                "anti-Frida detection. Enable the Frida detection bypass first, "
                "or attach after the app is fully started instead of spawning."
            )
            logger.error(msg)
            self._teardown_failed_spawn(spotlight, package)
            return False, msg
        except frida.InvalidOperationError as exc:
            logger.info(
                "[Bypass] Process %s already running; skipping resume (%s)",
                pid,
                exc,
            )

        with self._lock:
            loaded = sorted(self._active)
        if loaded:
            return True, (
                f"Spawned {package} with {len(loaded)} experimental bypass(es): "
                + ", ".join(self._plain_name(c) for c in loaded)
            )
        return True, f"Spawned {package} (no bypasses armed)"

    @_notifies
    def apply_to_fresh_spawn_with_retry(
        self,
        package: str,
        categories,
        on_message: Callable[[Any], None] | None = None,
        resume: bool = True,
        spawn_fn: Callable[..., tuple[bool, str]] | None = None,
    ) -> tuple[bool, str]:
        """Spawn-reliability ladder around :meth:`apply_to_fresh_spawn`.

        Hardened apps (e.g. Meta AI ``com.facebook.stella``) crash off the
        splash on a fraction of cold spawns even with the JS hardening: the
        instrumented pid dies right after ``resume()`` and Android relaunches
        the app *uninstrumented*, which re-pins TLS. This re-spawns until the
        instrumented pid survives the splash window, recovering a wedged
        frida-server at most once along the way, and FAILS LOUD on exhaustion.

        It NEVER falls back to attach (which would lose the early SSL ctor
        hooks installed at the pre-init window) and NEVER silently degrades to a
        stock/uninstrumented launch — for a forensic tool a clear failure beats
        a quietly-unhooked capture.

        Always active: every Start/⇧P/⇧R spawn gets the ladder (attach is
        the separate ``apply_armed`` path). Callers check that the app is not
        running before calling (a spawn kills a running instance).

        Args:
            package: Package to spawn.
            categories: Bypass categories to load (typically the armed set).
            on_message: Optional Frida payload callback.
            resume: When False (Start-paused) the spawn is intentionally left
                frozen — no liveness poll, since the process is meant to stay
                paused.
            spawn_fn: Optional spawn callable returning ``(ok, msg)``
                (forward-compat for a future child-process / gated-spawn
                variant). Defaults to :meth:`apply_to_fresh_spawn`.

        Returns:
            (success, message). On exhaustion ``success`` is False and the
            message names the attempt count and preserves the anti-Frida
            diagnostic as the last error.
        """
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        do_spawn = spawn_fn or self.apply_to_fresh_spawn
        if categories:
            conflict = self.exclusive_conflict(categories)
            if conflict:
                return False, conflict  # not a spawn failure: no retry ladder

        attempts, splash_window, retry_sleep = 4, 5.0, 0.6
        try:
            from sandroid.config import get_config

            frida_cfg = get_config().frida
            attempts = int(getattr(frida_cfg, "spawn_attempts", attempts))
            splash_window = float(
                getattr(frida_cfg, "spawn_splash_window", splash_window)
            )
            retry_sleep = float(getattr(frida_cfg, "spawn_retry_sleep", retry_sleep))
        except Exception as exc:  # config unavailable — keep literal defaults
            logger.debug("[Bypass] spawn-retry config read failed (%s)", exc)

        restarted_server = False
        last_msg = ""

        for attempt in range(1, attempts + 1):
            ok, msg = do_spawn(package, categories, on_message, resume)
            last_msg = msg

            if not ok:
                klass = classify_spawn_failure(msg)
                if klass == "benign":
                    # "already running" — process is up with hooks; success.
                    return True, msg
                logger.warning(
                    "[Bypass] spawn attempt %d/%d for %s failed (%s): %s",
                    attempt,
                    attempts,
                    package,
                    klass,
                    msg,
                )
                self._teardown_failed_spawn(spotlight, package)
                if restarted_server and frida_server_down(msg):
                    # Still no server after the one restart: more attempts
                    # only repeat the same failure.
                    return False, f"{FRIDA_SERVER_DOWN_MSG} (spawn of {package})"
                if klass == "dirty" and not restarted_server:
                    logger.warning(
                        "[Bypass] frida-server looks wedged; restarting it "
                        "once before re-spawn"
                    )
                    ready = self._recover_frida_server()
                    restarted_server = True
                    if ready is False:
                        return False, (
                            f"{FRIDA_SERVER_DOWN_MSG} (its restart failed; "
                            f"spawn of {package}: {msg})"
                        )
                time.sleep(retry_sleep)
                continue

            # ok == True
            if not resume:
                # Start-paused: intentionally frozen, no liveness poll.
                return True, msg

            # Resume path: confirm the SPECIFIC spawned pid survived the splash.
            # MUST be pid-based — a relaunched uninstrumented process keeps the
            # SAME package, so a package-focused check would false-positive.
            try:
                pid = spotlight.get_pid()
            except Exception:
                pid = None

            if pid and pid > 0:
                device = self._frida_device()
                if self._poll_liveness(device, pid, splash_window):
                    return True, msg
                logger.warning(
                    "[Bypass] spawned pid %s for %s vanished within the splash "
                    "window (attempt %d/%d) — likely crashed and relaunched "
                    "uninstrumented; re-spawning",
                    pid,
                    package,
                    attempt,
                    attempts,
                )
                self._teardown_failed_spawn(spotlight, package)
                time.sleep(retry_sleep)
                continue

            # No pid to poll — can't confirm a crash, accept reported success.
            return True, msg

        # Exhausted every attempt — FAIL LOUD. Do not attach, do not degrade.
        self._teardown_failed_spawn(spotlight, package)
        return False, (
            f"Spawn-reliability: exhausted {attempts} attempts for {package}; "
            f"last: {last_msg}. Not falling back to attach (would lose the "
            f"early SSL hooks). {package} likely died during hook load — the "
            "target likely has anti-Frida detection. Enable the Frida "
            "detection bypass first, or attach after the app is fully started "
            "instead of spawning."
        )

    def _recover_frida_server(self) -> bool | None:
        """Restart a wedged frida-server and drop the stale device handle.

        Fires at most once per ladder run (the caller guards that). Uses the
        AFM recovery primitive, then invalidates the cached frida device so the
        next spawn resolves a fresh, ready one — the same pattern the TUI uses
        after a manual frida install/start.

        Returns:
            True/False whether the restarted server is ready, or None when
            no restart could be attempted (no frida manager, error).
        """
        ok: bool | None = None
        try:
            from sandroid.services import get_frida_session_service

            svc = get_frida_session_service()
            fm = svc.get_frida_manager()
            if fm is not None:
                ok = bool(fm.restart_frida_server_and_wait())
                logger.info("[Bypass] frida-server restart -> ready=%s", ok)
            try:
                svc.invalidate_frida_device_cache()
            except Exception:
                pass
        except Exception as exc:
            logger.warning("[Bypass] frida-server recovery failed: %s", exc)
        return ok

    def _poll_liveness(self, device: Any, pid: int, window: float) -> bool:
        """Poll the SPECIFIC spawned *pid* for liveness over *window* seconds.

        Returns True if the pid stays alive for the whole window (the
        instrumented process survived the splash). A pid that vanishes from
        ``enumerate_processes`` = crash-and-relaunch (the relaunch is
        uninstrumented) => return False.

        Guards (a good spawn must NEVER be failed by an inconclusive probe):

        - ``_frida_device()`` CAN return ``None`` on a worker thread without a
          pre-cached device, so ``device is None`` => accept (cannot confirm a
          crash, don't false-fail a reported-good spawn).
        - A transient transport/protocol hiccup raises from
          ``enumerate_processes`` — treat it as alive and keep polling (per the
          image-extractor reference). This is why the poll uses a direct,
          hiccup-tolerant enumerate rather than AFM's ``is_process_alive``,
          which (by design, for the one-shot dirty-server question) reports a
          transport error as *not alive* — wrong for a splash poll, where a
          momentary server blip must not tear down a good capture. Only a
          definitive ``ProcessNotFoundError`` or genuine absence from the list
          counts as a crash.
        """
        if device is None:
            # Cannot confirm a crash — don't false-fail a reported-good spawn.
            return True
        deadline = time.time() + max(0.0, window)
        while True:
            try:
                alive = any(p.pid == pid for p in device.enumerate_processes())
            except frida.ProcessNotFoundError:
                return False
            except Exception as exc:
                # Transient/transport hiccup — treat as alive (per reference).
                logger.debug("[Bypass] liveness probe hiccup for %s: %s", pid, exc)
                alive = True
            if not alive:
                return False
            if time.time() >= deadline:
                return True
            time.sleep(0.3)

    def is_paused_session(self) -> bool:
        """True if the job manager reports a paused (spawned) process."""
        try:
            return bool(Toolbox.get_frida_job_manager().is_paused())
        except Exception:
            return False

    # -- helpers ----------------------------------------------------------

    def _unlink(self, path: str | None) -> None:
        """Best-effort unlink of a temp script file we own."""
        if not path:
            return
        try:
            os.unlink(path)
        except OSError:
            pass

    def _reset_script_state(self) -> None:
        """Stop the resident job, unlink its temp, null handles (keeps armed).

        Used before a fresh load/spawn and as the explicit teardown so a stale
        ``_job`` / ``_active`` (e.g. from an app that self-died without a Kill)
        can't make ``set_active``'s no-change early-return skip installing hooks
        on the new process.
        """
        with self._lock:
            job, path = self._take_script_locked()
        self._dispose_script(job, path)

    def _take_script_locked(self) -> tuple[Any, str | None]:
        """Null the script state (caller holds ``_lock``); returns the job
        and temp path for :meth:`_dispose_script`.
        """
        job, path = self._job, self._temp_path
        self._job = None
        self._script = None
        self._temp_path = None
        self._active = set()
        self._merge_errors = set()
        return job, path

    def _dispose_script(self, job: Any, path: str | None) -> None:
        """Stop the taken job, unlink its temp, unregister the task."""
        if job is not None:
            try:
                Toolbox.get_frida_job_manager().stop_job_with_id(job.get_id())
            except Exception as exc:
                logger.warning("stop_job during reset failed: %s", exc)
        self._unlink(path)
        self._unregister_task()

    @staticmethod
    def _frida_device():
        if Toolbox.frida_manager:
            return Toolbox.frida_manager.get_frida_device()
        from sandroid.services.frida_device_manager import get_selected_frida_device

        return get_selected_frida_device()

    def _register_task(self, display: str) -> None:
        try:
            svc = get_task_service()
            if svc.is_running("bypass"):
                if self._task_display != display:
                    svc.update_display("bypass", display)
                    self._task_display = display
            else:
                svc.register(
                    name="bypass",
                    display_name=display,
                    instance=self,
                    stop_callback=self.stop_all,
                    app_name=self._app_package,
                    target_pid=self._process_id,
                )
                self._task_display = display
        except Exception:
            pass
        try:
            get_tool_usage_service().mark_used("bypass", files=[])
        except Exception:
            pass

    def _unregister_task(self) -> None:
        self._task_display = None
        try:
            get_task_service().unregister("bypass")
        except Exception:
            pass

    def _teardown_failed_spawn(self, spotlight: Any, package: str) -> None:
        """Stop the job, reset the session, and force-stop the spawn.

        Never leaves a half-instrumented app frozen on the device.
        """
        # Stops the job, unlinks the temp, nulls handles, unregisters the task.
        self._reset_script_state()
        try:
            Toolbox.get_frida_job_manager().reset_session()
        except Exception as exc:
            logger.warning("reset_session during teardown failed: %s", exc)
        try:
            from sandroid.core.adb import Adb

            Adb.force_stop(package)
        except Exception as exc:
            logger.warning("force_stop during teardown failed: %s", exc)
        try:
            # Publishing: the header/panel must stop showing the dead PID now,
            # not when the whole spawn ladder ends.
            spotlight.announce_pid(None, package)
        except Exception:
            try:
                spotlight.set_pid(None)
            except Exception:
                pass


_INSTANCE: BypassService | None = None
_INSTANCE_LOCK = threading.Lock()


def get_bypass_service() -> BypassService:
    """Module-level accessor for the singleton BypassService."""
    global _INSTANCE
    if _INSTANCE is None:
        with _INSTANCE_LOCK:
            if _INSTANCE is None:
                _INSTANCE = BypassService()
    return _INSTANCE
