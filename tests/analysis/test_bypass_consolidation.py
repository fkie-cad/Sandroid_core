"""BypassService is the only source of detection bypasses.

Covers the consolidation: TrigDroid's bypass wrapper is gone (no module,
import or key left), emulator detection is a BypassService category, and
Dexray Intercept's own bypass group never runs alongside BypassService.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "sandroid"

# -- TrigDroid bypass wrapper removed ------------------------------------------

_REMOVED_MODULES = (
    "sandroid.analysis.trigdroid_bypass",
    "sandroid.tui.controllers.trigdroid_controller",
    "sandroid.tui.modals.trigdroid_modal",
)

_REMOVED_NAMES = re.compile(
    r"trigdroid_bypass|TrigDroidBypass|trigdroid_controller|TrigDroidController"
    r"|trigdroid_modal|TrigDroidModal|_find_bypass_script|action_trigdroid"
    r"|trigdroid_bypass_config"
)


@pytest.mark.parametrize("module", _REMOVED_MODULES)
def test_removed_bypass_modules_are_gone(module: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


def test_no_source_file_references_the_removed_wrapper() -> None:
    offenders = [
        f"{path.relative_to(_SRC)}:{n}"
        for path in _SRC.rglob("*.py")
        for n, line in enumerate(path.read_text("utf-8").splitlines(), 1)
        if _REMOVED_NAMES.search(line)
    ]
    assert not offenders, offenders


def test_trigger_execution_survives() -> None:
    """TrigDroid's real purpose (trigger runs) stays importable."""
    from sandroid.features.trigdroid import Trigdroid
    from sandroid.services import get_trigdroid_config_service

    assert callable(Trigdroid.perform)
    state = get_trigdroid_config_service().get_state_dict()
    assert state == {"spawn_mode": True, "auto_resume": True}


# -- emulator category -----------------------------------------------------------


def test_emulator_is_a_bypass_service_category() -> None:
    from sandroid.analysis.detection_bypass import (
        EMULATOR_DETECTION_HOOKS,
        BypassService,
        EmulatorDetectionBypassManager,
    )

    svc = BypassService()
    assert svc.categories()[-1] == "emulator"
    assert svc._manager_class("emulator") is EmulatorDetectionBypassManager
    assert EmulatorDetectionBypassManager.APPLY_AT_SPAWN is True
    assert "experimental" in svc.display_name("emulator").lower()
    assert svc._flag_dict({"emulator"})["emulator"] is True
    assert svc._flag_dict({"root"})["emulator"] is False
    union = svc._union_hooks(svc.categories())
    for hook in EMULATOR_DETECTION_HOOKS:
        assert hook in union
    for hook in ("android.os.Build.FINGERPRINT", "android.os.SystemProperties.get"):
        assert hook in EMULATOR_DETECTION_HOOKS


def test_emulator_hooks_are_known_to_conflict_detection() -> None:
    from sandroid.core.known_hooks import KNOWN_TOOLS

    tool = KNOWN_TOOLS["emulator_detection_bypass"]
    assert "android.os.SystemProperties.get" in tool.java_hooks
    assert "__system_property_get" in tool.native_hooks


def test_emulator_script_is_merged_into_the_one_flag_gated_script() -> None:
    import json

    from sandroid.analysis.detection_bypass import (
        _EMULATOR_DETECTION_SCRIPT,
        BypassService,
    )

    svc = BypassService()
    flags = svc._flag_dict({"emulator"})
    src = svc._assemble_source(flags)
    # Exactly one script: the emulator body sits in its own guarded IIFE...
    assert src.count(_EMULATOR_DETECTION_SCRIPT) == 1
    assert 'send({merge_error: "emulator"' in src
    # ...with the flag baked in at load (the paused-spawn path) and a
    # set_flags listener hook for the live flip.
    assert "var FLAGS = " + json.dumps(flags) in src
    assert "var FLAG_LISTENERS = [];" in src
    assert src.index("var FLAG_LISTENERS") < src.index(_EMULATOR_DETECTION_SCRIPT)
    # Load order: anti-anti-Frida (5) < emulator (8) < root/debug (10).
    order = svc._categories_by_priority(svc.categories())
    assert order.index("frida") < order.index("emulator") < order.index("root")
    # One Java.perform-gated Build write path, gated on FLAGS.emulator.
    assert "if (FLAGS.emulator) _emuInstall();" in _EMULATOR_DETECTION_SCRIPT
    # Java methods are only replaced through _emuHook (so flip-off reverts
    # them): one assignment there, one revert to null in _emuUninstall.
    assert _EMULATOR_DETECTION_SCRIPT.count(".implementation =") == 2
    assert "FLAGS.root" not in _EMULATOR_DETECTION_SCRIPT.replace(
        "if (f === 'TAGS' && FLAGS.root) return;", ""
    )


def test_live_emulator_toggle_says_restart(monkeypatch) -> None:
    from sandroid.analysis.detection_bypass import BypassService

    svc = BypassService()
    monkeypatch.setattr(svc, "_spotlight_running", lambda: True)
    monkeypatch.setattr(
        svc, "set_active", lambda target, paused, on_message=None: (True, "ok")
    )
    now_on, msg = svc.toggle("emulator")
    assert now_on is True
    assert "restart" in msg.lower()
    _now_on, msg = svc.toggle("root")
    assert "restart" not in msg.lower()


_NODE_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const out = [];
// A Java method with per-signature overloads; calling the dispatcher (what
// ``this.name(...)`` does inside a replacement) reaches the original.
function method(orig) {
    const f = function (...a) { return orig.apply(this, a); };
    const sigs = {};
    f.overload = function (...sig) {
        const key = sig.join(',');
        if (!sigs[key]) {
            sigs[key] = function (...a) { return orig.apply(this, a); };
        }
        return sigs[key];
    };
    f.sig = (...sig) => f.overload(...sig);
    return f;
}
const build = {
    FINGERPRINT: {value: 'google/sdk_gphone64_x86_64/emu64xa:16/BP22/1:userdebug/dev-keys'},
    MODEL: {value: 'sdk_gphone64_x86_64'}, MANUFACTURER: {value: 'Google'},
    BRAND: {value: 'google'}, DEVICE: {value: 'emu64xa'},
    PRODUCT: {value: 'sdk_gphone64_x86_64'}, HARDWARE: {value: 'ranchu'},
    BOARD: {value: 'goldfish_x86_64'}, TAGS: {value: 'dev-keys'},
    TYPE: {value: 'userdebug'}, ID: {value: 'BP22.250325.006'},
    DISPLAY: {value: 'sdk_gphone64_x86_64-userdebug 16 BP22.250325.006 13 dev-keys'},
    IS_EMULATOR: {value: true},
    getSerial: method(() => 'EMULATOR36X'),
};
if (process.argv[4] === 'real') {  // a real (userdebug) phone
    Object.assign(build, {
        FINGERPRINT: {value: 'google/oriole/oriole:14/AP1A/1:userdebug/release-keys'},
        MODEL: {value: 'Pixel 6'}, DEVICE: {value: 'oriole'},
        PRODUCT: {value: 'oriole'}, HARDWARE: {value: 'oriole'},
        BOARD: {value: 'oriole'}, TAGS: {value: 'release-keys'},
    });
}
const props = {'ro.kernel.qemu': '1', 'ro.product.model': 'sdk_gphone64_x86_64',
               'ro.build.tags': 'dev-keys', 'ro.debuggable': '1', 'persist.x': 'y',
               'ro.build.version.sdk': process.argv[5] || '36',
               'ro.build.version.release': '16', 'ro.build.id': 'BP22.250325.006',
               'ro.build.version.incremental': '13',
               'ro.build.flavor': 'sdk_gphone64_x86_64-userdebug'};
const sysprops = {get: method((k, d) => (k in props ? props[k] : (d === undefined ? '' : d)))};
const tm = {};
['getDeviceId', 'getSubscriberId', 'getLine1Number', 'getSimSerialNumber',
 'getNetworkOperatorName', 'getNetworkOperator', 'getPhoneType', 'getSimState']
    .forEach(n => { tm[n] = method(() => 'REAL-' + n); });
// A normal app on API 29+: identifier getters throw.
tm.getSubscriberId = method(() => { throw new Error('SecurityException'); });
const classes = {
    'android.os.Build': build,
    'android.os.Build$VERSION': {RELEASE: {value: '16'}, INCREMENTAL: {value: '13'},
                                 SDK_INT: {value: 36}},
    'android.os.SystemProperties': sysprops,
    'android.telephony.TelephonyManager': tm,
};
globalThis.Java = {perform: fn => fn(), use: n => classes[n]};
globalThis.send = m => out.push(m);
globalThis.ptr = v => ({ptr: String(v)});
const listeners = {};
const replaced = {};
globalThis.Interceptor = {
    attach: (addr, cb) => {
        listeners[addr] = cb;
        return {detach() { delete listeners[addr]; }};
    },
    replace: (addr, cb) => { replaced[addr] = cb; },
};
globalThis.NativeFunction = function (addr) {
    if (addr === '__system_property_get') {
        return (key, buf) => { buf.writeUtf8String(props[key.s] || ''); return 0; };
    }
    return () => 'REAL';
};
globalThis.Memory = {alloc: () => cstr(''), allocUtf8String: v => cstr(v)};
globalThis.NativeCallback = function (fn) { return fn; };
globalThis.NULL = 'NULL';
const modules = {app: '/data/app/x/lib/arm64/libapp.so', sys: '/vendor/lib64/libEGL_emu.so',
                 jdk: '/apex/com.android.art/lib64/libopenjdk.so',
                 webview: '/data/app/~~a/com.google.android.trichromelibrary_6/base.apk',
                 gms: '/data/user_de/0/com.google.android.gms/app_chimera/m/x/libm.so',
                 agent: '/memfd:frida-agent-64.so (deleted)'};
globalThis.Process = {
    findModuleByAddress: a => ({path: modules[a]}),
    findModuleByName: () => ({findExportByName: n => n}),
};
globalThis.Module = {findExportByName: (l, n) => n};
globalThis.FLAGS = {emulator: process.argv[3] === 'on', root: false};
globalThis.FLAG_LISTENERS = [];
(0, eval)(src);

function cstr(s) { return {s, readUtf8String() { return this.s; },
                           writeUtf8String(v) { this.s = v; }}; }
// The path hider replaces the export: [return value, errno] when it hid the
// path, null when the real function ran.
function callNative(sym, path, caller) {
    const fn = replaced[sym];
    if (!fn) return null;  // not installed: the real function runs
    const ctx = {returnAddress: caller, errno: 0};
    const args = sym === 'faccessat' ? [-100, cstr(path), 0, 0] : [cstr(path), 0];
    const ret = fn.apply(ctx, args);
    return ret === 'REAL' ? null : [ret, ctx.errno];
}
function callProp(key, caller) {
    const cb = listeners['__system_property_get'];
    const outBuf = cstr(props[key] || '');
    if (!cb) return [outBuf.s, null];  // not installed
    const ctx = {returnAddress: caller};
    cb.onEnter.call(ctx, [cstr(key), outBuf]);
    let rv = null;
    cb.onLeave.call(ctx, {replace: v => { rv = v.ptr; }});
    return [outBuf.s, rv];
}
const get1 = sysprops.get.sig('java.lang.String');
const get2 = sysprops.get.sig('java.lang.String', 'java.lang.String');
// Installed replacement, or the original method when none is installed.
function impl(m) { return m.implementation || m; }
function snapshot() {
    return {
        model: build.MODEL.value, fp: build.FINGERPRINT.value, tags: build.TAGS.value,
        serial: impl(build.getSerial).call(build),
        qemu: impl(get1).call(sysprops, 'ro.kernel.qemu'),
        model_prop: impl(get1).call(sysprops, 'ro.product.model'),
        debuggable: impl(get1).call(sysprops, 'ro.debuggable'),
        other: impl(get2).call(sysprops, 'persist.x', 'd'),
        qemu_def: impl(get2).call(sysprops, 'ro.kernel.qemu', 'd'),
        line1: impl(tm.getLine1Number.sig()).call(tm),
        imei: impl(tm.getDeviceId.sig()).call(tm),
        imsi: (() => { try { return impl(tm.getSubscriberId.sig()).call(tm); }
                       catch (e) { return '' + e.message; } })(),
        display: build.DISPLAY.value,
        is_emulator: build.IS_EMULATOR.value,
        flavor_prop: callProp('ro.build.flavor', 'app'),
        pipe_webview: callNative('access', '/dev/qemu_pipe', 'webview'),
        pipe_gms: callNative('access', '/dev/qemu_pipe', 'gms'),
        pipe_agent: callNative('access', '/dev/qemu_pipe', 'agent'),
        pipe_app: callNative('access', '/dev/qemu_pipe', 'app'),
        pipe_java: callNative('faccessat', '/dev/socket/qemud', 'jdk'),
        pipe_sys: callNative('access', '/dev/goldfish_pipe', 'sys'),
        rc_app: callNative('fopen', '/init.ranchu.rc', 'app'),
        plain_app: callNative('access', '/data/local/tmp/x', 'app'),
        prop_app: callProp('ro.kernel.qemu', 'app'),
        prop_sys: callProp('ro.kernel.qemu', 'sys'),
    };
}
// What the script has hooked right now (natives + replaced Java methods).
function installed() {
    const java = [build.getSerial, get1, get2, tm.getLine1Number.sig(),
                  tm.getDeviceId.sig()].filter(m => m.implementation).length;
    return {natives: Object.keys(listeners).length + Object.keys(replaced).length,
            java};
}
const result = {installedAtLoad: installed(), load: snapshot()};
globalThis.FLAGS.emulator = !globalThis.FLAGS.emulator;
FLAG_LISTENERS.forEach(l => l(globalThis.FLAGS));
result.flipped = snapshot();
result.installedAfterFlip = installed();
console.log(JSON.stringify(result));
"""


def _run_emulator_harness(
    tmp_path: Path, flag_at_load: str, device: str = "emulator", sdk: str = "36"
) -> dict:
    import json
    import shutil
    import subprocess

    from sandroid.analysis.detection_bypass import (
        _EMULATOR_DETECTION_SCRIPT,
        _PREAMBLE_HELPERS_JS,
    )

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed; JS behaviour check skipped")
    script = tmp_path / "emulator.js"
    script.write_text(_PREAMBLE_HELPERS_JS + _EMULATOR_DETECTION_SCRIPT)
    harness = tmp_path / "harness.js"
    harness.write_text(_NODE_HARNESS)
    proc = subprocess.run(
        [node, str(harness), str(script), flag_at_load, device, sdk],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


_SPOOFED = {
    "model": "Pixel 8 Pro",  # API 36: a Pixel that really runs Android 16
    "fp": "google/husky/husky:16/BP22.250325.006/13:user/release-keys",
    "tags": "release-keys",
    "serial": "2B111FDH2004QG",
    "qemu": "",
    "model_prop": "Pixel 8 Pro",
    "debuggable": "1",  # ro.debuggable is the root category's, not ours
    "other": "y",
    "qemu_def": "d",
    "line1": "",
    "imei": "358813084172653",
    "imsi": "SecurityException",  # what a real phone does on API 29+
    "display": "BP22.250325.006",
    "is_emulator": False,
    "flavor_prop": ["husky-user", "10"],
    "pipe_webview": None,  # updatable system code is not the app
    "pipe_gms": None,
    "pipe_agent": None,  # nor is a memfd module (the frida agent)
    "pipe_app": [-1, 2],  # -1 with errno ENOENT, like a missing file
    "pipe_java": [-1, 2],  # File.exists() via libopenjdk counts as the app
    "pipe_sys": None,  # the emulator's own graphics stack keeps its pipe
    "rc_app": ["NULL", 2],
    "plain_app": None,
    "prop_app": ["", "0"],
    "prop_sys": ["1", None],
}
_REAL = {
    "model": "sdk_gphone64_x86_64",
    "fp": "google/sdk_gphone64_x86_64/emu64xa:16/BP22/1:userdebug/dev-keys",
    "tags": "dev-keys",
    "serial": "EMULATOR36X",
    "qemu": "1",
    "model_prop": "sdk_gphone64_x86_64",
    "debuggable": "1",
    "other": "y",
    "qemu_def": "1",
    "line1": "REAL-getLine1Number",
    "imei": "REAL-getDeviceId",
    "imsi": "SecurityException",
    "display": "sdk_gphone64_x86_64-userdebug 16 BP22.250325.006 13 dev-keys",
    "is_emulator": True,
    "flavor_prop": ["sdk_gphone64_x86_64-userdebug", None],
    "pipe_webview": None,
    "pipe_gms": None,
    "pipe_agent": None,
    "pipe_app": None,
    "pipe_java": None,
    "pipe_sys": None,
    "rc_app": None,
    "plain_app": None,
    "prop_app": ["1", None],
    "prop_sys": ["1", None],
}


def test_emulator_script_applies_at_load_and_restores_on_flag_off(tmp_path) -> None:
    """Armed before Start: baked FLAGS.emulator spoofs from the first read."""
    result = _run_emulator_harness(tmp_path, "on")
    assert result["installedAtLoad"] == {"natives": 5, "java": 5}
    assert result["load"] == _SPOOFED
    assert result["flipped"] == _REAL
    # Flip-off reverts the Java replacements and detaches the property
    # listener; only the shared path-hider replacements stay (flag-gated).
    assert result["installedAfterFlip"] == {"natives": 4, "java": 0}


def test_emulator_script_is_inert_until_flag_flips_on(tmp_path) -> None:
    """Off at load: nothing changes until set_flags turns it on live."""
    result = _run_emulator_harness(tmp_path, "off")
    # Off at load: nothing is hooked (no always-on cost, no telephony clash).
    assert result["installedAtLoad"] == {"natives": 0, "java": 0}
    assert result["load"] == _REAL
    assert result["flipped"] == _SPOOFED


def test_emulator_script_never_relabels_a_real_device(tmp_path) -> None:
    """Build.* is replaced as one profile only when it shows an emulator."""
    result = _run_emulator_harness(tmp_path, "on", device="real")
    assert result["load"]["model"] == "Pixel 6"
    assert result["load"]["tags"] == "release-keys"


# -- Dexray bypass group <-> BypassService mutual exclusion ----------------------

#: The user-facing choice both refusals must offer (verbatim from the spec).
BYPASS_CONFLICT_CHOICE_TEXT = (
    "choose one: Dexray's bypass group or the Bypass (b) categories"
)


@pytest.fixture
def bypass_service(monkeypatch):
    """A fresh BypassService that the Dexray side also sees."""
    import sandroid.analysis.detection_bypass as db

    svc = db.BypassService()
    monkeypatch.setattr(db, "get_bypass_service", lambda: svc)
    monkeypatch.setattr(svc, "_spotlight_running", lambda: False)
    return svc


def _dexray_monitor(bypass_hooks: bool, telephony_hooks: bool = False):
    import types

    from sandroid.analysis.malwaremonitor import MalwareMonitor

    mm = MalwareMonitor.__new__(MalwareMonitor)
    mm.available = True
    mm.running = False
    mm.last_error = None
    mm._accept_messages = False
    mm._bypass_claims = []
    mm._owns_session = False
    mm._spawned_at = None
    mm.hook_config = {
        "aes_hooks": True,
        "bypass_hooks": bypass_hooks,
        "telephony_hooks": telephony_hooks,
    }
    mm.reached_setup = False
    toolbox = types.SimpleNamespace(malware_monitor_running=False)
    mm._get_toolbox = lambda: toolbox
    mm._check_and_warn_hook_conflicts = lambda: None
    mm._run_interactive_configuration = lambda: True
    mm._snapshot_manager = types.SimpleNamespace(discard_snapshot=lambda tb: None)

    def _setup_reached(toolbox):
        mm.reached_setup = True
        raise RuntimeError("stop here: no device in tests")

    mm._create_pre_analysis_snapshot = _setup_reached
    return mm


def test_dexray_bypass_group_refused_while_a_b_category_is_armed(
    bypass_service,
) -> None:
    from sandroid.analysis.detection_bypass import BYPASS_CONFLICT_CHOICE

    now_on, _msg = bypass_service.toggle("root")  # app not running: arm only
    assert now_on is True
    mm = _dexray_monitor(bypass_hooks=True)

    assert mm.start_monitoring() is False
    assert BYPASS_CONFLICT_CHOICE in mm.last_error
    assert "Root" in mm.last_error
    assert mm.reached_setup is False  # refused before any snapshot/session
    assert bypass_service.exclusive_conflict() is None  # nothing claimed


def test_dexray_without_its_bypass_group_is_not_affected(bypass_service) -> None:
    bypass_service.toggle("root")
    mm = _dexray_monitor(bypass_hooks=False)

    assert mm.start_monitoring() is False  # our stub stops it at setup
    assert mm.reached_setup is True
    assert "choose one" not in (mm.last_error or "")
    assert bypass_service.exclusive_conflict() is None


def test_b_categories_refused_while_dexray_bypass_group_runs(
    bypass_service, monkeypatch
) -> None:
    import sandroid.analysis.detection_bypass as db

    mm = _dexray_monitor(bypass_hooks=True)
    assert mm._claim_bypass_exclusivity() is True

    # Arming (b chord), starting (Ctrl+P / AI), the live path and Start with
    # armed categories are all refused with the same choice.
    now_on, msg = bypass_service.toggle("emulator")
    assert now_on is False
    assert BYPASS_CONFLICT_CHOICE_TEXT in msg
    assert bypass_service.armed_categories() == []
    ok, msg = bypass_service.start("ssl")
    assert ok is False
    assert BYPASS_CONFLICT_CHOICE_TEXT in msg
    ok, msg = bypass_service.start_many(["root", "frida"])
    assert ok is False
    assert BYPASS_CONFLICT_CHOICE_TEXT in msg

    class _NoSpawn:
        def spawn_app_paused(self, package):
            raise AssertionError("must refuse before spawning")

        def is_spawn_mode(self):
            return True

    monkeypatch.setattr(db, "get_spotlight_service", _NoSpawn)
    monkeypatch.setattr("sandroid.services.get_spotlight_service", _NoSpawn)
    ok, msg = bypass_service.apply_to_fresh_spawn("org.example", ["root"])
    assert ok is False
    assert BYPASS_CONFLICT_CHOICE_TEXT in msg
    ok, msg = bypass_service.apply_to_fresh_spawn_with_retry("org.example", ["root"])
    assert ok is False
    assert BYPASS_CONFLICT_CHOICE_TEXT in msg
    # Turning everything off is never refused (checked before any Frida work).
    assert bypass_service.exclusive_conflict() is not None

    class _IdleJobManager:
        def is_paused(self) -> bool:
            return False

    monkeypatch.setattr(
        "sandroid.core.toolbox.Toolbox.get_frida_job_manager", _IdleJobManager
    )
    monkeypatch.setattr(bypass_service, "_is_job_live", lambda jm: False)
    assert bypass_service.set_active(set(), paused=False) == (True, "All bypasses off")

    # Dexray stops (or a failed start aborts): the b categories are free.
    mm._abort_start(mm._get_toolbox())
    assert bypass_service.exclusive_conflict() is None
    now_on, _msg = bypass_service.toggle("emulator")
    assert now_on is True


def test_a_dropped_dexray_monitor_releases_its_claim(bypass_service) -> None:
    import gc

    mm = _dexray_monitor(bypass_hooks=True)
    assert mm._claim_bypass_exclusivity() is True
    assert bypass_service.exclusive_conflict() is not None
    del mm
    gc.collect()
    assert bypass_service.exclusive_conflict() is None


def test_hook_editor_labels_the_dexray_bypass_group_as_conflicting() -> None:
    from sandroid.analysis.hook_config import HOOK_GROUPS

    assert "Bypass (b)" in HOOK_GROUPS["bypass"]["name"]
    assert HOOK_GROUPS["bypass"]["hooks"] == ["bypass_hooks"]


# -- Frida 17 API guard ------------------------------------------------------------

#: Static APIs Frida 17 removed: a hook using them throws inside its ``try``
#: and silently never installs (root's native su hiding did, on 17.10).
_FRIDA16_STATIC_API = re.compile(
    r"\bModule\.(?:findExportByName|getExportByName|findBaseAddress"
    r"|getBaseAddress|enumerate\w+)\(|\bMemory\.(?:read|write)\w*\("
)


def _merged_bundle(monkeypatch) -> str:
    import sandroid.analysis.detection_bypass as db

    monkeypatch.setattr(db, "_java_bridge_prelude", lambda: "")
    svc = db.BypassService()
    return svc._assemble_source(dict.fromkeys(svc.categories(), True))


def test_merged_bundle_has_no_frida16_static_api_text(monkeypatch) -> None:
    src = _merged_bundle(monkeypatch)
    code = "\n".join(line.split("//", 1)[0] for line in src.splitlines())
    assert not _FRIDA16_STATIC_API.findall(code)


_NODE_GUARD = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const banned = [];
const sent = [];
function deep(name) {
    const target = function () {};
    return new Proxy(target, {
        get(t, k) {
            if (k === Symbol.toPrimitive) return () => 0;
            if (k === 'toString' || k === 'valueOf') return () => '';
            if (k === 'then') return undefined;
            if (k === 'length') return 0;
            if (k === Symbol.iterator) return function* () {};
            return deep(name + '.' + String(k));
        },
        set() { return true; },
        apply() { return deep(name + '()'); },
        construct() { return deep('new ' + name); },
        has() { return true; },
    });
}
function banning(objName, keys) {
    const real = deep(objName);
    return new Proxy(real, {
        get(t, k) {
            if (keys.includes(String(k))) {
                return function () { banned.push(objName + '.' + String(k)); throw new Error('banned static API ' + objName + '.' + String(k)); };
            }
            return real[k];
        },
    });
}
globalThis.Module = banning('Module', ['findExportByName', 'getExportByName', 'findBaseAddress', 'getBaseAddress', 'enumerateExports', 'enumerateImports', 'enumerateSymbols', 'ensureInitialized']);
globalThis.Memory = banning('Memory', ['readUtf8String', 'writeUtf8String', 'readCString', 'readUtf16String', 'writeUtf16String', 'readAnsiString', 'writeAnsiString', 'readPointer', 'writePointer', 'readByteArray', 'writeByteArray', 'readU8', 'readS32', 'readU32', 'writeU8', 'writeS32', 'writeU32']);
for (const g of ['Java', 'Stalker', 'Thread', 'DebugSymbol', 'ObjC', 'Script', 'Socket', 'File', 'Kernel', 'ApiResolver', 'ModuleMap', 'CModule', 'Instruction', 'Backtracer', 'hexdump', 'recv', 'Arm64Relocator', 'X86Relocator', 'Arm64Writer', 'X86Writer']) globalThis[g] = deep(g);
globalThis.Java = new Proxy(deep('Java'), { get(t, k) { if (k === 'perform' || k === 'performNow') return fn => { try { fn(); } catch (e) { sent.push({javaError: '' + e}); } }; if (k === 'available') return true; return t[k]; } });
globalThis.ptr = () => deep('ptr');
globalThis.NULL = 'NULL';
// Exports resolve to their names; replacements are recorded so the shared
// path hider can be driven below.
const replaced = {};
globalThis.Process = new Proxy(deep('Process'), { get(t, k) {
    if (k === 'findModuleByName') return () => ({ findExportByName: n => n });
    if (k === 'findModuleByAddress') return () => ({ path: '/data/app/x/lib/arm64/libapp.so' });
    return t[k];
} });
globalThis.Interceptor = new Proxy(deep('Interceptor'), { get(t, k) {
    if (k === 'replace') return (addr, cb) => { replaced[addr] = cb; };
    return t[k];
} });
globalThis.NativeFunction = function () { return () => 'REAL'; };
globalThis.NativeCallback = function (fn) { return fn; };
globalThis.int64 = () => deep('int64'); globalThis.uint64 = () => deep('uint64');
globalThis.send = m => sent.push(m);
globalThis.rpc = { exports: {} };
globalThis.setTimeout = () => 0; globalThis.setInterval = () => 0; globalThis.setImmediate = () => 0;
globalThis.clearTimeout = () => {}; globalThis.clearInterval = () => {};
(0, eval)(src);
if (rpc.exports.setFlags) rpc.exports.setFlags({});
function probe(sym, path) {
    const ctx = { returnAddress: 'app', errno: 0 };
    const p = { readUtf8String: () => path };
    const args = sym === 'faccessat' ? [-100, p, 0, 0] : [p, 0];
    const ret = replaced[sym].apply(ctx, args);
    return ret === 'REAL' ? 'REAL' : [ret, ctx.errno];
}
const probes = {};
for (const flag of [true, false]) {
    rpc.exports.setFlags({ root: flag, emulator: false });
    for (const sym of ['access', 'faccessat', 'fopen', 'fopen64']) {
        probes[sym + ':' + flag] = [probe(sym, '/system/xbin/su'), probe(sym, '/data/local/tmp/x')];
    }
}
console.log(JSON.stringify({banned, mergeErrors: sent.filter(m => m && m.merge_error), probes}));
"""


def test_merged_bundle_calls_no_frida16_static_api(tmp_path, monkeypatch) -> None:
    """Run every category in node with the removed statics throwing."""
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed; JS behaviour check skipped")
    bundle = tmp_path / "merged.js"
    bundle.write_text(_merged_bundle(monkeypatch))
    guard = tmp_path / "guard.js"
    guard.write_text(_NODE_GUARD)
    proc = subprocess.run(
        [node, str(guard), str(bundle)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result["banned"] == []
    assert result["mergeErrors"] == []
    # Root's native su hiding is installed (one replacement per probe):
    # a su path fails like a missing file, everything else runs for real.
    for sym, fail in (("access", -1), ("faccessat", -1), ("fopen", "NULL")):
        assert result["probes"][f"{sym}:true"] == [[fail, 2], "REAL"], sym
        assert result["probes"][f"{sym}:false"] == ["REAL", "REAL"], sym


#: The telephony refusal (Dexray's telephony_hooks vs the emulator category).
TELEPHONY_CHOICE_TEXT = (
    "choose one: Dexray's telephony hooks or the Emulator bypass (b 6)"
)


def test_dexray_telephony_hooks_refused_while_emulator_is_armed(
    bypass_service,
) -> None:
    bypass_service.toggle("emulator")
    mm = _dexray_monitor(bypass_hooks=False, telephony_hooks=True)

    assert mm.start_monitoring() is False
    assert TELEPHONY_CHOICE_TEXT in mm.last_error
    assert mm.reached_setup is False
    assert mm._bypass_claims == []


def test_dexray_telephony_hooks_only_block_the_emulator_category(
    bypass_service,
) -> None:
    bypass_service.toggle("root")  # root does not touch TelephonyManager
    mm = _dexray_monitor(bypass_hooks=False, telephony_hooks=True)
    assert mm._claim_bypass_exclusivity() is True

    now_on, msg = bypass_service.toggle("emulator")
    assert now_on is False
    assert TELEPHONY_CHOICE_TEXT in msg
    assert bypass_service.toggle("ssl")[0] is True  # other categories are fine
    ok, msg = bypass_service.start("emulator")
    assert ok is False
    assert TELEPHONY_CHOICE_TEXT in msg

    mm._release_bypass_exclusivity()
    assert bypass_service.toggle("emulator")[0] is True


def test_claims_are_per_token_not_per_owner(bypass_service) -> None:
    """A headless and a TUI MalwareMonitor never release each other's claim."""
    headless = _dexray_monitor(bypass_hooks=True)
    tui = _dexray_monitor(bypass_hooks=True)
    assert headless._claim_bypass_exclusivity() is True
    assert tui._claim_bypass_exclusivity() is True
    assert headless._bypass_claims != tui._bypass_claims

    headless._release_bypass_exclusivity()
    assert bypass_service.exclusive_conflict(["root"]) is not None  # tui's
    tui._release_bypass_exclusivity()
    assert bypass_service.exclusive_conflict(["root"]) is None


@pytest.mark.parametrize(
    ("sdk", "model", "device"),
    [
        ("25", "Pixel", "sailfish"),
        ("28", "Pixel 3", "blueline"),
        ("33", "Pixel 4 XL", "coral"),
        ("34", "Pixel 8 Pro", "husky"),
    ],
)
def test_emulator_profile_matches_the_real_api_level(
    tmp_path, sdk, model, device
) -> None:
    """No coral on Android 14+: the Pixel really ran that Android version."""
    result = _run_emulator_harness(tmp_path, "on", sdk=sdk)
    assert result["load"]["model"] == model
    assert result["load"]["fp"].startswith(f"google/{device}/{device}:16/")
    assert result["load"]["flavor_prop"][0] == f"{device}-user"
