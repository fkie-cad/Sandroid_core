"""Native detection-bypass managers for Android app analysis.

Sandroid ships self-contained Frida bypasses for the bypasses needed to
intercept and analyse hardened apps, so interception no longer depends on an
external ``trigdroid`` package or a pre-compiled frida bundle being present.

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

BypassService is the only source of bypasses in Sandroid (TrigDroid's bypass
wrapper is gone; Dexray Intercept's own bypass group is mutually exclusive
with it).

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
_PREAMBLE_HELPERS_JS = r"""
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

// Shared path hider: ONE Interceptor.replace per libc probe (access,
// faccessat, fopen, fopen64) for every category that hides files (root,
// emulator). A hidden path gets -1 / NULL with errno = ENOENT, like a missing
// file, and the real call never runs (no leaked FILE*). Two categories
// cannot each replace the same export, hence the registry.
var PATH_HIDERS = [];  // {cat, test(path, returnAddress)}
var _pathHiderInstalled = false;
var _ENOENT = 2;

function _anyPathHiderOn() {
    for (var i = 0; i < PATH_HIDERS.length; i++) {
        if (FLAGS[PATH_HIDERS[i].cat]) return true;
    }
    return false;
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

function _replacePathProbe(sym, retType, argTypes, pathIndex, failValue) {
    var addr = _libcExport(sym);
    if (addr === null) return;
    var original = new NativeFunction(addr, retType, argTypes);
    Interceptor.replace(addr, new NativeCallback(function () {
        if (_anyPathHiderOn()) {
            var path = null;
            try { path = arguments[pathIndex].readUtf8String(); } catch (e) {}
            var cat = path === null ? null : _hiddenBy(path, this.returnAddress);
            if (cat !== null) {
                try { this.errno = _ENOENT; } catch (e) {}
                send({type: 'info', hook: cat + '-bypass:' + sym + '(' + path + ')'});
                return failValue;
            }
        }
        // A NativeFunction call from inside the replacement reaches the
        // original implementation, not this callback again.
        return original.apply(null, arguments);
    }, retType, argTypes));
}

function hidePaths(category, test) {
    PATH_HIDERS.push({cat: category, test: test});
    if (_pathHiderInstalled) return;
    _pathHiderInstalled = true;
    var probes = [
        ['access', 'int', ['pointer', 'int'], 0, -1],
        ['faccessat', 'int', ['int', 'pointer', 'int', 'int'], 1, -1],
        ['fopen', 'pointer', ['pointer', 'pointer'], 0, NULL],
        ['fopen64', 'pointer', ['pointer', 'pointer'], 0, NULL]
    ];
    probes.forEach(function (p) {
        try {
            _replacePathProbe(p[0], p[1], p[2], p[3], p[4]);
        } catch (e) {
            send({type: 'debug', hook: 'path-hider:' + p[0], error: e.message});
        }
    });
}
"""


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
)

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

// Native: hide /proc/self/maps + /proc/<pid>/status from frida-name scans
(function () {
    var procFds = {};  // fd -> 1 if it's a /proc/{self,N}/maps|status read

    function _maybeTrack(pathPtr, fd) {
        try {
            var path = pathPtr.readUtf8String();
            if (!path) return;
            // Only newline-delimited text files. /cmdline is NUL-separated, so
            // readUtf8String would stop at argv[0] and writeUtf8String would
            // truncate the whole buffer — skip it.
            if (path.indexOf('/maps') !== -1 ||
                path.indexOf('/status') !== -1) {
                procFds[fd] = 1;
            }
        } catch (e) {}
    }

    try {
        var openat = _libcExport('openat');
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function (args) { this._path = args[1]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _maybeTrack(this._path, fd);
                }
            });
        }
        var openFn = _libcExport('open');
        if (openFn) {
            Interceptor.attach(openFn, {
                onEnter: function (args) { this._path = args[0]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _maybeTrack(this._path, fd);
                }
            });
        }
        var closeFn = _libcExport('close');
        if (closeFn) {
            Interceptor.attach(closeFn, {
                onEnter: function (args) { delete procFds[args[0].toInt32()]; }
            });
        }
        var readFn = _libcExport('read');
        if (readFn) {
            Interceptor.attach(readFn, {
                onEnter: function (args) {
                    this._fd = args[0].toInt32();
                    this._buf = args[1];
                },
                onLeave: function (rv) {
                    if (!FLAGS.frida) return;  // inert when frida bypass off
                    if (!(this._fd in procFds)) return;
                    var n = rv.toInt32();
                    if (n <= 0) return;
                    try {
                        var data = this._buf.readUtf8String(n);
                        if (!data) return;
                        var filtered = data.split('\n').filter(function (l) {
                            return l.indexOf('frida') === -1 &&
                                   l.indexOf('gum-js-loop') === -1 &&
                                   l.indexOf('gmain') === -1 &&
                                   l.indexOf('linjector') === -1 &&
                                   l.indexOf('gadget') === -1;
                        }).join('\n');
                        if (filtered.length !== data.length) {
                            this._buf.writeUtf8String(filtered);
                            rv.replace(ptr(filtered.length));
                        }
                    } catch (e) {}
                }
            });
        }
        send({type: 'info', hook: 'frida-bypass:proc-maps-filter'});
    } catch (e) {
        send({type: 'debug', hook: 'frida-bypass:proc-maps-filter', error: e.message});
    }

    // Native: strstr scans for 'frida'/'gum' return NULL
    try {
        var strstr = _libcExport('strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function (args) {
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
    "libc:read",
    "libc:close",
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
                    try { this._key = args[0].readUtf8String(); }
                    catch (e) { this._key = null; }
                    this._out = args[1];
                },
                onLeave: function (rv) {
                    if (!FLAGS.root) return;  // inert when root bypass off
                    try {
                        if (this._key === 'ro.debuggable') {
                            this._out.writeUtf8String('0');
                            rv.replace(ptr(1));
                            send({type: 'info', hook: 'root-bypass:prop:ro.debuggable'});
                        } else if (this._key === 'ro.secure') {
                            this._out.writeUtf8String('1');
                            rv.replace(ptr(1));
                            send({type: 'info', hook: 'root-bypass:prop:ro.secure'});
                        }
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
    hidePaths('root', function (path) { return _looksLikeRootPath(path); });
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

    // Build.TAGS -> release-keys. This is a field write performed once at load,
    // NOT a runtime-reversible method body — so flag-gating can only honour the
    // *baked* initial flag. If root is armed at load it is applied; it is sticky
    // for the session thereafter (toggling root off later won't restore the real
    // TAGS, and toggling root on later won't set them). Acceptable fidelity
    // caveat — TAGS is rarely the sole root signal.
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

// Native: filter 'TracerPid:' in /proc/self/status so ptrace-based debugger
// checks read 0. Registered under a distinct hook id from the Frida bypass's
// read filter; the Interceptor.attach stacks cleanly at runtime.
(function () {
    var statusFds = {};

    function _trackStatus(pathPtr, fd) {
        try {
            var path = pathPtr.readUtf8String();
            if (path && path.indexOf('/status') !== -1) statusFds[fd] = 1;
        } catch (e) {}
    }

    try {
        var openat = _libcExport('openat');
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function (args) { this._p = args[1]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _trackStatus(this._p, fd);
                }
            });
        }
        var closeFn = _libcExport('close');
        if (closeFn) {
            Interceptor.attach(closeFn, {
                onEnter: function (args) { delete statusFds[args[0].toInt32()]; }
            });
        }
        var readFn = _libcExport('read');
        if (readFn) {
            Interceptor.attach(readFn, {
                onEnter: function (args) {
                    this._fd = args[0].toInt32();
                    this._buf = args[1];
                },
                onLeave: function (rv) {
                    if (!FLAGS.debug) return;  // inert when debug bypass off
                    if (!(this._fd in statusFds)) return;
                    var n = rv.toInt32();
                    if (n <= 0) return;
                    try {
                        var data = this._buf.readUtf8String(n);
                        if (!data || data.indexOf('TracerPid:') === -1) return;
                        var filtered = data.replace(/TracerPid:\s*\d+/g, 'TracerPid:\t0');
                        if (filtered.length === data.length) return;
                        // Rewrite the buffer and shrink the reported byte count
                        // so the caller doesn't see stale trailing bytes.
                        this._buf.writeUtf8String(filtered);
                        rv.replace(ptr(filtered.length));
                        send({type: 'info', hook: 'debug-bypass:TracerPid=0'});
                    } catch (e) {}
                }
            });
        }
        send({type: 'info', hook: 'debug-bypass:tracerpid-filter'});
    } catch (e) {
        send({type: 'debug', hook: 'debug-bypass:tracerpid-filter', error: e.message});
    }
})();

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
    "libc:read:tracerpid",
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
# - Build.* is replaced as ONE device profile (Pixel 4 XL, TrigDroid's default)
#   and only when at least one field shows an emulator value, so a real device
#   is never relabelled and no half-spoofed mix is left behind. FINGERPRINT is
#   built from the device's own Build.VERSION.RELEASE / Build.ID /
#   VERSION.INCREMENTAL, so it agrees with the Android version the app sees.
# - Native property spoofing and file hiding only answer *app* callers: a
#   caller inside /system, /apex, /vendor, ... keeps the truth, so the
#   emulator's own graphics stack (goldfish pipe, ro.kernel.qemu.gles,
#   ro.hardware) keeps working inside the hooked process. Java's File I/O
#   (libopenjdk/libjavacore) counts as an app caller, which is how
#   File.exists() probes are covered without a second File.exists hook (one
#   Java method has one implementation; the root category owns that one).
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

var EMU_PROFILE = {
    MODEL: 'Pixel 4 XL', MANUFACTURER: 'Google', BRAND: 'google',
    DEVICE: 'coral', PRODUCT: 'coral', HARDWARE: 'coral', BOARD: 'coral',
    TAGS: 'release-keys', TYPE: 'user'
};
var EMU_BUILD_FIELDS = [
    'FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT',
    'HARDWARE', 'BOARD', 'TAGS', 'TYPE'
];
// Identity fields decide whether this is an emulator at all; TAGS/TYPE are
// replaced along with them but never decide (a userdebug phone is no emulator).
var EMU_IDENTITY_FIELDS = EMU_BUILD_FIELDS.filter(function (f) {
    return f !== 'TAGS' && f !== 'TYPE';
});
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
var EMU_JAVA_IO_LIBS = ['libopenjdk.so', 'libjavacore.so'];

function _isAppCaller(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        if (!m) return true;  // anonymous / JIT / unpacked code: the app
        var p = '' + m.path;
        for (var i = 0; i < EMU_JAVA_IO_LIBS.length; i++) {
            if (p.indexOf('/' + EMU_JAVA_IO_LIBS[i]) !== -1) return true;
        }
        for (var j = 0; j < EMU_SYSTEM_PREFIXES.length; j++) {
            if (p.indexOf(EMU_SYSTEM_PREFIXES[j]) === 0) return false;
        }
    } catch (e) {}
    return true;
}

// --- system properties ------------------------------------------------------
var _emuFingerprint = null;  // set once the Build profile is computed

function _profileFingerprint() {
    if (_emuFingerprint) return _emuFingerprint;
    return 'google/coral/coral:12/SP1A.210812.016.C1/7676683:user/release-keys';
}

// Replacement for property `key` whose current value is `value`, or null to
// leave it alone. ro.debuggable / ro.secure stay with the root category.
function _spoofProp(key, value) {
    if (!key) return null;
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
    if (k.indexOf('ro.product.') === 0 || k.indexOf('ro.build.') === 0 ||
        k.indexOf('ro.vendor.') === 0 || k.indexOf('ro.system.') === 0 ||
        k.indexOf('ro.bootimage.') === 0 || k.indexOf('ro.odm.') === 0) {
        if (leaf === 'model') return EMU_PROFILE.MODEL;
        if (leaf === 'manufacturer') return EMU_PROFILE.MANUFACTURER;
        if (leaf === 'brand') return EMU_PROFILE.BRAND;
        if (leaf === 'device') return EMU_PROFILE.DEVICE;
        if (leaf === 'name') return EMU_PROFILE.PRODUCT;
        if (leaf === 'board') return EMU_PROFILE.BOARD;
        if (leaf === 'fingerprint') return _profileFingerprint();
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
            var emulated = false;
            EMU_BUILD_FIELDS.forEach(function (f) {
                try {
                    var v = '' + Build[f].value;
                    orig[f] = v;
                    if (EMU_IDENTITY_FIELDS.indexOf(f) !== -1 && _emuValue(v)) {
                        emulated = true;
                    }
                } catch (e) {}
            });
            if (!emulated) {
                send({type: 'info', hook: 'emulator-bypass:Build(no emulator values)'});
                return;
            }
            try {
                var Version = Java.use('android.os.Build$VERSION');
                _emuFingerprint = 'google/coral/coral:' + Version.RELEASE.value +
                    '/' + Build.ID.value + '/' + Version.INCREMENTAL.value +
                    ':user/release-keys';
            } catch (e) {
                _emuFingerprint = _profileFingerprint();
            }
            EMU_BUILD_FIELDS.forEach(function (f) {
                try {
                    Build[f].value = f === 'FINGERPRINT' ? _emuFingerprint : EMU_PROFILE[f];
                } catch (e) {}
            });
            _emuBuildOriginal = orig;
            send({type: 'info', hook: 'emulator-bypass:Build=' + EMU_PROFILE.MODEL});
        } else {
            if (!_emuBuildOriginal) return;
            var saved = _emuBuildOriginal;
            _emuBuildOriginal = null;
            EMU_BUILD_FIELDS.forEach(function (f) {
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
        _emuHook(BuildCls.getSerial, function () {
            if (!FLAGS.emulator) return this.getSerial();
            send({type: 'info', hook: 'emulator-bypass:Build.getSerial'});
            return 'RF8M33XXXXX';
        });
    } catch (e) {}

    // SystemProperties.get (Dexray): Java-level reads skip __system_property_get
    // on current Android (they use __system_property_read_callback).
    try {
        var SP = Java.use('android.os.SystemProperties');
        _emuHook(SP.get.overload('java.lang.String'), function (key) {
            var v = this.get(key);
            if (!FLAGS.emulator) return v;
            var s = _spoofProp(key, v);
            if (s === null) return v;
            send({type: 'info', hook: 'emulator-bypass:SystemProperties.get(' + key + ')'});
            return s;
        });
        _emuHook(SP.get.overload('java.lang.String', 'java.lang.String'), function (key, def) {
            var v = this.get(key, def);
            if (!FLAGS.emulator) return v;
            var s = _spoofProp(key, v);
            if (s === null) return v;
            send({type: 'info', hook: 'emulator-bypass:SystemProperties.get(' + key + ')'});
            return s === '' ? def : s;
        });
        send({type: 'info', hook: 'emulator-bypass:SystemProperties.get'});
    } catch (e) {}

    // TelephonyManager fakes (TrigDroid's bypassTelephonyChecks values).
    var TELEPHONY = [
        ['getDeviceId', [], '358240051111110'],
        ['getDeviceId', ['int'], '358240051111110'],
        ['getSubscriberId', [], '310260000000000'],
        ['getLine1Number', [], '+15551234567'],
        ['getSimSerialNumber', [], '89014103211118510720'],
        ['getNetworkOperatorName', [], 'T-Mobile'],
        ['getNetworkOperator', [], '310260'],
        ['getPhoneType', [], 1],   // PHONE_TYPE_GSM
        ['getSimState', [], 5]     // SIM_STATE_READY
    ];
    try {
        var TM = Java.use('android.telephony.TelephonyManager');
        TELEPHONY.forEach(function (row) {
            var name = row[0], sig = row[1], fake = row[2];
            try {
                var m = TM[name].overload.apply(TM[name], sig);
                _emuHook(m, function () {
                    if (!FLAGS.emulator) return m.apply(this, arguments);
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
            });
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
    # ids, like the debug category's ``libc:read:tracerpid``).
    "libc:__system_property_get:emulator",
    "libc:access:emulator",
    "libc:faccessat:emulator",
    "libc:fopen:emulator",
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


_CATEGORY_DISPLAY = {
    "ssl": "SSL Pinning Bypass",
    "frida": "Frida Detection Bypass",
    "root": "Root Detection Bypass",
    "debug": "Debug Detection Bypass",
    "integrity": "Integrity / Attestation Bypass",
    "emulator": "Emulator Detection Bypass",
}


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

    # -- mutual exclusion with other bypass sources (Dexray) --------------

    def claim_exclusive(
        self,
        owner: str,
        *,
        what: str = "its bypass group",
        categories=None,
        choice: str = BYPASS_CONFLICT_CHOICE,
        is_alive: Callable[[], bool] | None = None,
    ) -> tuple[str | None, str]:
        """Claim bypass categories for another source (e.g. Dexray's group).

        Refused while any claimed category is armed or active, or while a
        bypass load is in flight. While the claim is held, arming or starting
        a claimed category is refused in turn. Arming checks under ``_lock``
        and a load checks while holding ``_mutate_lock``, so neither side can
        slip in between.

        Args:
            owner: User-facing name of the claiming source.
            what: What of the owner conflicts (``"its telephony hooks"``).
            categories: Categories claimed; None claims every category.
            choice: The "choose one: ..." sentence both refusals end with.
            is_alive: Optional liveness probe; a claim whose probe returns
                False (or raises) is dropped the next time it is checked.

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
            if not on and self._mutate_lock.locked():
                return None, (
                    f"Not starting {owner} with {what}: a Bypass (b) change "
                    f"is in progress — {choice}."
                )
            if on:
                names = ", ".join(self._plain_name(c) for c in on)
                return None, (
                    f"Not starting {owner} with {what}: Bypass (b) has "
                    f"{names} on — {choice}."
                )
            token = uuid.uuid4().hex
            self._claims[token] = _ExclusiveClaim(owner, what, cats, choice, is_alive)
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
            return f"{claim.owner} is running with {claim.what} — {claim.choice}."
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
        """Ensure a Frida session for the spotlight app, reusing any existing.

        Records :attr:`_app_package` / :attr:`_process_id` and surfaces the PID
        to the spotlight panel. On the spawn path the session already exists
        (created paused by ``spawn_app_paused``); on the attach path this
        attaches to the running PID.

        Returns:
            True iff this call *itself* created a fresh **spawn** session (so a
            live caller knows it must resume the now-paused process). False when
            reusing a session or attaching to a running PID.

        Raises:
            ValueError: If no spotlight app is selected, or attach mode is
                requested for an app that is not running.
        """
        from sandroid.core.adb import Adb

        spotlight = get_spotlight_service()
        app_tuple = spotlight.get_app_tuple()
        if not app_tuple:
            raise ValueError(
                "No spotlight app selected. Press 'C' to select an app first."
            )

        self._app_package = app_tuple[0]
        process_id = spotlight.get_pid()
        should_spawn = spotlight.is_spawn_mode()

        if not should_spawn and not process_id:
            process_id = Adb.get_pid_for_package_name(self._app_package)
            if not process_id:
                raise ValueError(
                    f"App {self._app_package} not running. "
                    "Start it or use spawn mode (Shift+C)."
                )

        created_spawn = False
        jm = Toolbox.get_frida_job_manager()
        if not jm.has_active_session():
            logger.debug("No existing Frida session — creating new one")
            target = self._app_package if should_spawn else process_id
            jm.setup_frida_session(
                target, self._message_handler, should_spawn=should_spawn
            )
            if should_spawn:
                created_spawn = True
                info = jm.get_session_info()
                if info and info.get("pid"):
                    process_id = info["pid"]
        else:
            session_pkg = jm.package_name
            if session_pkg and session_pkg != self._app_package:
                logger.info(
                    "Session targets %s but spotlight is %s — resetting",
                    session_pkg,
                    self._app_package,
                )
                jm.reset_session()
                target = self._app_package if should_spawn else process_id
                jm.setup_frida_session(
                    target,
                    self._message_handler,
                    should_spawn=should_spawn,
                )
                if should_spawn:
                    created_spawn = True
                    info = jm.get_session_info()
                    if info and info.get("pid"):
                        process_id = info["pid"]
            else:
                logger.debug("Reusing existing Frida session")
                if not process_id:
                    info = jm.get_session_info()
                    if info and info.get("pid"):
                        process_id = info["pid"]

        self._process_id = process_id
        # Surface the resolved PID so the spotlight panel shows it (non-
        # publishing, so this does not retrigger a panel refresh loop).
        if process_id:
            spotlight.set_pid(process_id)
        return created_spawn

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
        - Each category source wrapped in a ``try``/``catch`` IIFE (reusing AFM's
          ``_build_merged_source`` shape for ``var`` isolation + failure
          reporting via ``send({merge_error: <label>})``), ordered by priority so
          the anti-anti-Frida prelude installs first.

        Category bodies read the shared ``FLAGS`` via closure over this
        realm-top declaration and must NOT re-declare ``var FLAGS``. Each source
        keeps its own leading ``'use strict';`` which is a harmless no-op string
        once nested inside the IIFE's ``try`` block.
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
            "        for (var i = 0; i < FLAG_LISTENERS.length; i++) {\n"
            "            try { FLAG_LISTENERS[i](FLAGS); } catch (e) {}\n"
            "        }\n"
            "        return FLAGS;\n"
            "    },\n"
            "    getFlags: function () { return FLAGS; }\n"
            "};\n"
        )
        parts = [preamble]
        for category in self._categories_by_priority(self.categories()):
            src = self._frida_script(category)
            if not src:
                continue
            label = json.dumps(category)
            parts.append(
                "(function () {\ntry {\n"
                + src
                + "\n} catch (e) {\n"
                + "send({merge_error: "
                + label
                + ", error: '' + e});\n"
                + "}\n})();\n"
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

        # Not live — drop any stale handles/temp, then load fresh.
        self._reset_script_state()
        with self._lock:
            self._merge_errors = set()

        try:
            created_spawn = self._setup_session(paused=paused)
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
            self._job = job
            self._script = script
            self._temp_path = path

        # If this live transition itself spawned a fresh (now paused) session —
        # e.g. start()/start_many() against a spawn-selected app with no prior
        # session — nothing has resumed it yet. Resume once, preserving the
        # anti-Frida self-kill diagnostic. The explicit paused-spawn flow
        # (paused=True) resumes separately, so skip it there.
        if not paused and created_spawn and jm.is_paused():
            try:
                Toolbox.resume_spawned_process_after_hooks(
                    self._frida_device(), self._process_id
                )
            except frida.ProcessNotFoundError:
                msg = (
                    "Process died during hook load — target likely has "
                    "anti-Frida detection. Enable the Frida detection "
                    "bypass first, or attach instead of spawning."
                )
                logger.error(msg)
                self._reset_script_state()
                return False, msg, False
            except frida.InvalidOperationError as exc:
                logger.info(
                    "[Bypass] Process already running; skipping resume (%s)",
                    exc,
                )

        return True, "Bypass script loaded", True

    # -- the single transition point --------------------------------------

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
            # Checked while holding _mutate_lock: claim_exclusive refuses while
            # it is held, so a Dexray claim and this load cannot interleave.
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
            self._mutate_lock.release()

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

    def start(
        self,
        category: str,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Add one category live (attach path). Idempotent."""
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
        return self.set_active(target, paused=False, on_message=on_message)

    def start_many(
        self,
        categories,
        on_message: Callable[[Any], None] | None = None,
    ) -> tuple[bool, str]:
        """Add several categories live in ONE set_flags op (no N reloads)."""
        with self._lock:
            target = set(self._active) | set(categories)
        return self.set_active(target, paused=False, on_message=on_message)

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
                if getattr(self._manager_class(category), "APPLY_AT_SPAWN", False):
                    return True, (
                        f"{name} active — restart the app (R) so checks it "
                        "ran at startup see it too"
                    )
                return True, f"{name} active"
            return True, f"{name} armed — Start to apply"

        # Turning OFF.
        self._disarm(category)
        with self._lock:
            active = category in self._active
            target = set(self._active) - {category}
        if active:
            self.set_active(target, paused=False)
        return False, f"{name} off"

    # -- queries ----------------------------------------------------------

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
            return False, (
                f"Failed to spawn {package} (no PID — is frida-server running?)"
            )

        if not self.is_paused_session():
            logger.warning(
                "Expected a paused session after spawn_app_paused(%s); "
                "proceeding cautiously",
                package,
            )

        # 2. Surface the PID immediately.
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

        # 4'. Resume exactly once, preserving the anti-Frida self-kill
        # diagnostic: resume_spawned_process_after_hooks lets a
        # ProcessNotFoundError propagate (resume_app would swallow it).
        spotlight.set_auto_resume(True)  # spawn_app_paused had set it False
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

        Only active in spawn mode: outside spawn mode this is EXACTLY one
        :meth:`apply_to_fresh_spawn` call (zero behaviour change; attach is the
        separate ``apply_armed`` path).

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

        # Gate: the ladder only augments spawn mode. Outside it, behave EXACTLY
        # like the pre-change single call.
        if not spotlight.is_spawn_mode():
            return do_spawn(package, categories, on_message, resume)

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
                if klass == "dirty" and not restarted_server:
                    logger.warning(
                        "[Bypass] frida-server looks wedged; restarting it "
                        "once before re-spawn"
                    )
                    self._recover_frida_server()
                    restarted_server = True
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

    def _recover_frida_server(self) -> None:
        """Restart a wedged frida-server and drop the stale device handle.

        Fires at most once per ladder run (the caller guards that). Uses the
        AFM recovery primitive, then invalidates the cached frida device so the
        next spawn resolves a fresh, ready one — the same pattern the TUI uses
        after a manual frida install/start.
        """
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
            job = self._job
            path = self._temp_path
            self._job = None
            self._script = None
            self._temp_path = None
            self._active = set()
            self._merge_errors = set()
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
