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
- :class:`BypassService` — process-wide singleton that owns the armed/active
  category sets and one persistent flag-gated Frida script (toggled via the
  ``set_flags`` RPC — instant, gap-free, one Java bridge).

Emulator detection has no native manager: incoherent field spoofing gives
false confidence and can trip heuristics harder, so that one category stays on
TrigDroid's RPC device-profile path.

For authorized security testing, forensic analysis, and research only.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
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
    """

    TOOL_NAME: str = "bypass"
    DISPLAY_NAME: str = "Detection Bypass"
    HOOKS_REGISTRY: list[str] = []
    FRIDA_SCRIPT: str = ""
    PRIORITY: int = 10


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
    var libc = 'libc.so';
    var procFds = {};  // fd -> 1 if it's a /proc/{self,N}/maps|status read

    function _maybeTrack(pathPtr, fd) {
        try {
            var path = Memory.readUtf8String(pathPtr);
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
        var openat = Module.findExportByName(libc, 'openat');
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function (args) { this._path = args[1]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _maybeTrack(this._path, fd);
                }
            });
        }
        var openFn = Module.findExportByName(libc, 'open');
        if (openFn) {
            Interceptor.attach(openFn, {
                onEnter: function (args) { this._path = args[0]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _maybeTrack(this._path, fd);
                }
            });
        }
        var closeFn = Module.findExportByName(libc, 'close');
        if (closeFn) {
            Interceptor.attach(closeFn, {
                onEnter: function (args) { delete procFds[args[0].toInt32()]; }
            });
        }
        var readFn = Module.findExportByName(libc, 'read');
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
                        var data = Memory.readUtf8String(this._buf, n);
                        if (!data) return;
                        var filtered = data.split('\n').filter(function (l) {
                            return l.indexOf('frida') === -1 &&
                                   l.indexOf('gum-js-loop') === -1 &&
                                   l.indexOf('gmain') === -1 &&
                                   l.indexOf('linjector') === -1 &&
                                   l.indexOf('gadget') === -1;
                        }).join('\n');
                        if (filtered.length !== data.length) {
                            Memory.writeUtf8String(this._buf, filtered);
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
        var strstr = Module.findExportByName(libc, 'strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function (args) {
                    try {
                        var needle = Memory.readUtf8String(args[1]);
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
            var p = Module.findExportByName(libc, sym);
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
    DISPLAY_NAME = "Frida Detection Bypass"
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
        var sysprop = Module.findExportByName('libc.so', '__system_property_get');
        if (sysprop) {
            Interceptor.attach(sysprop, {
                onEnter: function (args) {
                    try { this._key = Memory.readUtf8String(args[0]); }
                    catch (e) { this._key = null; }
                    this._out = args[1];
                },
                onLeave: function (rv) {
                    if (!FLAGS.root) return;  // inert when root bypass off
                    try {
                        if (this._key === 'ro.debuggable') {
                            Memory.writeUtf8String(this._out, '0');
                            rv.replace(ptr(1));
                            send({type: 'info', hook: 'root-bypass:prop:ro.debuggable'});
                        } else if (this._key === 'ro.secure') {
                            Memory.writeUtf8String(this._out, '1');
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
// so the Java File.exists hook never sees them. We intervene ONLY on a
// root-path match (rare) and keep onEnter lean so this never throttles a
// Hermes app at boot. We deliberately do NOT hook open/openat (far too hot —
// fopen/access cover RootBeer's actual primitives).
(function () {
    var libc = 'libc.so';

    // access(path, mode): 0 = exists. Force -1 on a su-path so it "doesn't
    // exist".
    try {
        var accessP = Module.findExportByName(libc, 'access');
        if (accessP) {
            Interceptor.attach(accessP, {
                onEnter: function (args) {
                    this._hide = false;
                    if (!FLAGS.root) return;  // skip path matching when off
                    try {
                        var p = Memory.readUtf8String(args[0]);
                        if (_looksLikeRootPath(p)) {
                            this._hide = true;
                            this._path = p;
                        }
                    } catch (e) {}
                },
                onLeave: function (rv) {
                    if (!FLAGS.root) return;  // leave rv untouched when off
                    if (this._hide) {
                        rv.replace(ptr('-1'));
                        send({type: 'info', hook: 'root-bypass:access(' + this._path + ')'});
                    }
                }
            });
            send({type: 'info', hook: 'root-bypass:access'});
        }
    } catch (e) {
        send({type: 'debug', hook: 'root-bypass:access', error: e.message});
    }

    // faccessat(dirfd, path, mode, flags): path is args[1]. Same as access().
    try {
        var faccessatP = Module.findExportByName(libc, 'faccessat');
        if (faccessatP) {
            Interceptor.attach(faccessatP, {
                onEnter: function (args) {
                    this._hide = false;
                    if (!FLAGS.root) return;  // skip path matching when off
                    try {
                        var p = Memory.readUtf8String(args[1]);
                        if (_looksLikeRootPath(p)) {
                            this._hide = true;
                            this._path = p;
                        }
                    } catch (e) {}
                },
                onLeave: function (rv) {
                    if (!FLAGS.root) return;  // leave rv untouched when off
                    if (this._hide) {
                        rv.replace(ptr('-1'));
                        send({type: 'info', hook: 'root-bypass:faccessat(' + this._path + ')'});
                    }
                }
            });
            send({type: 'info', hook: 'root-bypass:faccessat'});
        }
    } catch (e) {
        send({type: 'debug', hook: 'root-bypass:faccessat', error: e.message});
    }

    // fopen(path, mode) / fopen64(path, mode): non-NULL FILE* = opened. Force
    // NULL on a su-path so the open "fails".
    function _hookFopen(sym) {
        try {
            var p = Module.findExportByName(libc, sym);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this._hide = false;
                    if (!FLAGS.root) return;  // skip path matching when off
                    try {
                        var path = Memory.readUtf8String(args[0]);
                        if (_looksLikeRootPath(path)) {
                            this._hide = true;
                            this._path = path;
                        }
                    } catch (e) {}
                },
                onLeave: function (rv) {
                    if (!FLAGS.root) return;  // leave rv untouched when off
                    if (this._hide) {
                        rv.replace(ptr('0'));
                        send({type: 'info', hook: 'root-bypass:' + sym + '(' + this._path + ')'});
                    }
                }
            });
            send({type: 'info', hook: 'root-bypass:' + sym});
        } catch (e) {
            send({type: 'debug', hook: 'root-bypass:' + sym, error: e.message});
        }
    }
    _hookFopen('fopen');
    _hookFopen('fopen64');
})();

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
    DISPLAY_NAME = "Root Detection Bypass"
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
    var libc = 'libc.so';
    var statusFds = {};

    function _trackStatus(pathPtr, fd) {
        try {
            var path = Memory.readUtf8String(pathPtr);
            if (path && path.indexOf('/status') !== -1) statusFds[fd] = 1;
        } catch (e) {}
    }

    try {
        var openat = Module.findExportByName(libc, 'openat');
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function (args) { this._p = args[1]; },
                onLeave: function (rv) {
                    var fd = rv.toInt32();
                    if (fd >= 0) _trackStatus(this._p, fd);
                }
            });
        }
        var closeFn = Module.findExportByName(libc, 'close');
        if (closeFn) {
            Interceptor.attach(closeFn, {
                onEnter: function (args) { delete statusFds[args[0].toInt32()]; }
            });
        }
        var readFn = Module.findExportByName(libc, 'read');
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
                        var data = Memory.readUtf8String(this._buf, n);
                        if (!data || data.indexOf('TracerPid:') === -1) return;
                        var filtered = data.replace(/TracerPid:\s*\d+/g, 'TracerPid:\t0');
                        if (filtered.length === data.length) return;
                        // Rewrite the buffer and shrink the reported byte count
                        // so the caller doesn't see stale trailing bytes.
                        Memory.writeUtf8String(this._buf, filtered);
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
    DISPLAY_NAME = "Debug Detection Bypass"
    HOOKS_REGISTRY = DEBUG_DETECTION_HOOKS
    FRIDA_SCRIPT = _DEBUG_DETECTION_SCRIPT
    PRIORITY = 10


# ---------------------------------------------------------------------------
# Bypass service (singleton owning all managers)
# ---------------------------------------------------------------------------

# Category keys are the stable identifiers used by the panel, MitmproxyService,
# and TrigDroid delegation. "ssl" maps to SSLUnpinManager (imported lazily to
# avoid a circular import: ssl_unpin imports this module's base class).
_CATEGORY_DISPLAY = {
    "ssl": "SSL Pinning Bypass",
    "frida": "Frida Detection Bypass",
    "root": "Root Detection Bypass",
    "debug": "Debug Detection Bypass",
}


class BypassService:
    """Owns the armed/active bypass categories and one flag-gated Frida script.

    Process-wide singleton so the bypass job survives TUI screen changes —
    Textual recreates widgets on screen change, so panel-local state would
    orphan the running job.

    **One persistent flag-gated script.** Instead of loading/unloading a script
    per category (a fresh ``script.load`` each time = a new frida-java-bridge on
    the contended JS thread, which is slow and causes a no-hooks gap on
    off-toggle), this assembles ONE combined script (preamble + all four
    category sources, each hook body early-checking its ``FLAGS[category]``) and
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
        # directly, e.g. Ctrl+P SSL unpin). The panel renders armed ∪ active.
        self._armed: set[str] = set()
        self._on_message: Callable[[Any], None] | None = None
        # Display string of the currently-registered TaskService entry (None
        # when unregistered), so _register_task can refresh a changed display
        # without re-registering identically every toggle.
        self._task_display: str | None = None

    # -- category metadata (data holders) ---------------------------------

    def _manager_class(self, category: str):
        if category == "ssl":
            from sandroid.analysis.ssl_unpin import SSLUnpinManager

            return SSLUnpinManager
        return {
            "frida": FridaDetectionBypassManager,
            "root": RootDetectionBypassManager,
            "debug": DebugDetectionBypassManager,
        }.get(category)

    def categories(self) -> list[str]:
        """All known category keys, in display order."""
        return ["ssl", "root", "frida", "debug"]

    def display_name(self, category: str) -> str:
        return _CATEGORY_DISPLAY.get(category, category)

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

        Always carries all four keys so the baked ``FLAGS`` object and every
        ``set_flags`` RPC are complete (the JS preamble's ``setFlags`` merges,
        but a complete dict keeps state unambiguous).
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
                        logger.info(f"[Bypass] Hooked: {hook}")
                    elif ptype == "ready":
                        logger.info(f"[Bypass] {payload.get('message', 'Ready')}")
                    elif ptype == "debug":
                        logger.debug(
                            f"[Bypass] {hook}: {payload.get('error', '')}"
                        )
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

        - Preamble: ``'use strict';`` + ``var FLAGS = <json>;`` + ``rpc.exports``
          (``setFlags`` merges a partial dict and returns FLAGS; ``getFlags``
          returns it). ``json.dumps`` is used everywhere — category names are
          never string-interpolated.
        - Each category source wrapped in a ``try``/``catch`` IIFE (reusing AFM's
          ``_build_merged_source`` shape for ``var`` isolation + failure
          reporting via ``send({merge_error: <label>})``), ordered by priority so
          the anti-anti-Frida prelude installs first.

        Category bodies read the shared ``FLAGS`` via closure over this
        realm-top declaration and must NOT re-declare ``var FLAGS``. Each source
        keeps its own leading ``'use strict';`` which is a harmless no-op string
        once nested inside the IIFE's ``try`` block.
        """
        preamble = (
            "'use strict';\n"
            "var FLAGS = " + json.dumps(initial_flags) + ";\n"
            "rpc.exports = {\n"
            "    setFlags: function (f) {\n"
            "        if (f) {\n"
            "            for (var k in f) {\n"
            "                if (Object.prototype.hasOwnProperty.call(f, k)) {\n"
            "                    FLAGS[k] = !!f[k];\n"
            "                }\n"
            "            }\n"
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
                + "send({merge_error: " + label + ", error: '' + e});\n"
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
                    logger.warning(
                        "set_active(live) while session paused; skipping"
                    )
                    return False, (
                        "Session paused — resume before changing hooks"
                    )

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
            ok, msg, fresh = self._ensure_loaded(
                paused=paused, initial_flags=flags
            )
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
                    logger.warning(
                        "[Bypass] set_flags failed: %s — reloading", exc
                    )
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
            display = "Bypass: " + ", ".join(
                self.display_name(c)
                for c in self._categories_by_priority(active_now)
            )
            self._register_task(display)
            return True, display
        self._unregister_task()
        return True, "All bypasses off"

    # -- armed set (user intent, independent of live state) ---------------

    def _arm(self, category: str) -> None:
        with self._lock:
            self._armed.add(category)

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
        """Toggle a category against the armed ∪ active set.

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
            # Turning ON.
            self._arm(category)
            if self._spotlight_running():
                with self._lock:
                    target = set(self._active) | {category}
                ok, msg = self.set_active(
                    target, paused=False, on_message=on_message
                )
                if not ok:
                    self._disarm(category)
                    return False, msg
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
        return True, "Applied: " + ", ".join(
            self.display_name(c) for c in self._categories_by_priority(armed)
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
                f"Failed to spawn {package} "
                "(no PID — is frida-server running?)"
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
                f"Spawned (paused) {package} with {active_n} bypass(es) "
                "(Resume to run)"
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
                f"Spawned {package} with {len(loaded)} bypass(es): "
                + ", ".join(self.display_name(c) for c in loaded)
            )
        return True, f"Spawned {package} (no bypasses armed)"

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
        return frida.get_usb_device()

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
