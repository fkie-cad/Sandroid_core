"""SSL Pinning Bypass via Frida.

Single source of truth for SSL/TLS certificate pinning bypass. Used by:
- MitmproxyPanel (Ctrl+P toggle) via MitmproxyService → BypassService
- TrigDroidBypass (delegates ssl_unpinning here)
- Spotlight Panel toggle ``[1] SSL`` via BypassService

Hooks comprehensive Java and native SSL verification methods to accept all
certificates, enabling mitmproxy interception of pinned apps.

This script is **SSL-only** — anti-anti-Frida hooks live in the dedicated
``FridaDetectionBypassManager`` so the two concerns stay independent (enable
the Frida bypass first to survive on anti-Frida apps, then SSL).

For authorized security testing, forensic analysis, and research only.
"""

import logging

from sandroid.analysis.detection_bypass import BypassManagerBase

logger = logging.getLogger(__name__)

SSL_UNPIN_HOOKS = [
    "javax.net.ssl.SSLContext.init",
    "javax.net.ssl.HttpsURLConnection.setHostnameVerifier",
    "javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier",
    "javax.net.ssl.HttpsURLConnection.setSSLSocketFactory",
    "javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory",
    "okhttp3.CertificatePinner.check",
    "okhttp3.CertificatePinner.check$okhttp",
    "com.squareup.okhttp.CertificatePinner.check",
    "android.webkit.WebViewClient.onReceivedSslError",
    "com.android.org.conscrypt.TrustManagerImpl.verifyChain",
    "com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive",
    "com.android.org.conscrypt.CertPinManager.isChainValid",
    "android.net.http.X509TrustManagerExtensions.checkServerTrusted",
    "com.datatheorem.android.trustkit.pinning.PinningTrustManager.checkServerTrusted",
    # Tier 4: native cronet / Chromium-BoringSSL verify entry points. Hooked at
    # runtime by export/symbol enumeration (no fixed module name), listed here
    # for the hook registry / display only.
    "cronet:SSL_set_custom_verify",
    "cronet:SSL_CTX_set_custom_verify",
    "cronet:SSL_get_verify_result",
    "cronet:bssl::ssl_verify_peer_cert",
    "cronet:net::CertVerifyProc::Verify",
    # Tier 5: native mbedTLS verify entry points + the Meta Network Stack (MNS)
    # cert verifier. Resolved at runtime by export name across all modules (no
    # fixed module name); the universal mbedtls_x509_crt_verify* family makes
    # this generic to ANY mbedTLS-pinning app, the MNS symbol is a Meta-specific
    # supplement. Runtime emits "mbedtls:MNS:<joined>"; listed here per-symbol
    # for the hook registry / display only.
    "mbedtls:MNSCertificateVerifierVerifyMaybeCreateError",
    "mbedtls:mbedtls_ssl_conf_verify",
    "mbedtls:mbedtls_ssl_conf_authmode",
    "mbedtls:mbedtls_ssl_set_hs_authmode",
    "mbedtls:mbedtls_x509_crt_verify",
    "mbedtls:mbedtls_x509_crt_verify_with_profile",
    "mbedtls:mbedtls_x509_crt_verify_restartable",
    "mbedtls:mbedtls_ssl_set_verify",
    # Deterministic pre-init verifier install via the linker's constructor caller
    # (soinfo::call_constructors interpose). Installs the right tier's hooks in a
    # module's mapped-but-pre-init window, BEFORE its early-init TLS handshake, so
    # any app's early-init TLS is unpinned before its first connection. Runtime
    # emits "<tier>:early-ctor-install@<module>"; listed here for the registry.
    "cronet:early-ctor-install",
    "mbedtls:early-ctor-install",
    "flutter:early-ctor-install",
]

_FRIDA_SCRIPT = r"""
'use strict';

// Flag-gated SSL pinning bypass. Every hook body early-checks FLAGS.ssl (a
// shared object defined in the combined-script preamble, see
// BypassService._assemble_source) and passes through to the *original* method
// when the SSL category is toggled off — so this single resident script can be
// armed/disarmed at runtime via the set_flags RPC with no reload and no gap.
//
// Pass-throughs are hand-authored, not mechanical: a void/swallow body must
// reconstruct the original call (e.g. SSLContext.init must forward the ORIGINAL
// TrustManagers, not the forged PermissiveTrustManager), and value-forgers must
// return what the original would. Multi-overload methods forward the declared
// args so Frida resolves the right overload by runtime type (same idiom as the
// root bypass's Runtime.exec). Methods whose body ignores args use
// .apply(this, arguments) — safe because they were hooked via .implementation
// (single overload).

// ===========================================================================
// SPAWN-SURVIVAL HARDENING — debounced dlopen re-scan scheduler.
//
// Problem this fixes (diagnosed on com.facebook.stella / Meta AI, Android 16):
// the native tiers below (cronet / mbedTLS-MNS) each hook the linker's
// android_dlopen_ext/dlopen and, on EVERY dlopen return, RE-RAN a full
// Process.enumerateModules() scan that installs hooks on hot verify functions.
// During a cold SPAWN the linker maps dozens of libraries back-to-back (incl.
// the ~17 MB libstartup.so), so those re-scans fired RE-ENTRANTLY, dozens of
// times, from inside dlopen's onLeave WHILE the splash thread was executing —
// tearing a freshly-installed Interceptor trampoline. Result: the main thread
// jumped through a clobbered code pointer (tombstone: SIGSEGV, "jump to
// unmapped address") on most cold spawns; a plain ATTACH to an already-running
// pid was stable because no dlopen-storm coincides with hooking.
//
// Fix (general, not stella-specific): never do heavy work inside dlopen onLeave.
// Instead COALESCE all dlopen returns into a SINGLE re-scan scheduled a short
// time AFTER the burst settles (debounce), so module hooking happens on a quiet
// linker, never mid-load. The per-symbol / per-module latches already make each
// re-scan idempotent, so coalescing loses no late-loaded module. Defined ONCE at
// file scope and shared by all native tiers below.
// ===========================================================================
var _SU_debounce = (function() {
    var timers = {};   // key -> pending timeout id
    // Schedule fn under `key`; repeated calls within `delay` ms collapse into one
    // run that fires `delay` ms after the LAST call (classic trailing debounce).
    return function(key, fn, delay) {
        try {
            if (timers[key]) { try { clearTimeout(timers[key]); } catch (e) {} }
            var d = (typeof delay === 'number') ? delay : 300;
            timers[key] = setTimeout(function() {
                timers[key] = null;
                try { fn(); } catch (e) {}
            }, d);
        } catch (e) {
            // setTimeout/clearTimeout unavailable — fall back to a direct (still
            // try/catch-guarded) call so behaviour degrades safely.
            try { fn(); } catch (e2) {}
        }
    };
})();

// --- Java tier, guarded for spawn/early-attach -----------------------------
// On a cold SPAWN the ART VM is not up when the script loads, so Java.perform
// would throw and abort the whole script (taking the native tiers with it).
// Wrap the Java hooks in a named function and only run them once Java.available
// is true, retrying on a short timer until the VM initialises. The native tiers
// below run independently of this.
function _suJavaTier() {
    var ArrayList = Java.use('java.util.ArrayList');

    // --- Tier 1: Core SSL hooks (~90% coverage) ---

    // 1. SSLContext.init — replace TrustManagers with permissive one.
    // registerClass stays UNGATED: in the single-load model it runs exactly
    // once, and the reuse-when-present guard makes a re-run a no-op anyway.
    try {
        var PermissiveTrustManager;
        try {
            PermissiveTrustManager = Java.use('com.sandroid.unpin.PermissiveTrustManager');
        } catch (e) {
            PermissiveTrustManager = Java.registerClass({
                name: 'com.sandroid.unpin.PermissiveTrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
        }
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function(km, tm, sr) {
            // Pass-through MUST forward the ORIGINAL TrustManagers (tm), never
            // the forged one — highest-risk gate in the whole bypass.
            if (!FLAGS.ssl) return this.init(km, tm, sr);
            this.init(km, [PermissiveTrustManager.$new()], sr);
            send({type: 'info', hook: 'SSLContext.init'});
        };
    } catch(e) { send({type: 'debug', hook: 'SSLContext.init', error: e.message}); }

    // 2. HttpsURLConnection — hostname verifier + socket factory (static + instance).
    // Armed bodies are empty swallows; pass-through reconstructs the original call.
    try {
        var HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsConn.setHostnameVerifier.implementation = function(v) {
            if (!FLAGS.ssl) return this.setHostnameVerifier(v);
        };
        HttpsConn.setSSLSocketFactory.implementation = function(f) {
            if (!FLAGS.ssl) return this.setSSLSocketFactory(f);
        };
        try {
            HttpsConn.setDefaultHostnameVerifier.implementation = function(v) {
                if (!FLAGS.ssl) return this.setDefaultHostnameVerifier(v);
            };
        } catch(e) {}
        try {
            HttpsConn.setDefaultSSLSocketFactory.implementation = function(f) {
                if (!FLAGS.ssl) return this.setDefaultSSLSocketFactory(f);
            };
        } catch(e) {}
        send({type: 'info', hook: 'HttpsURLConnection'});
    } catch(e) { send({type: 'debug', hook: 'HttpsURLConnection', error: e.message}); }

    // 3. Conscrypt TrustManagerImpl.verifyChain — return untrusted chain as-is
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function(untrustedChain) {
            if (!FLAGS.ssl) return this.verifyChain.apply(this, arguments);
            send({type: 'info', hook: 'TrustManagerImpl.verifyChain'});
            return untrustedChain;
        };
    } catch(e) { send({type: 'debug', hook: 'TrustManagerImpl.verifyChain', error: e.message}); }

    // 4. Conscrypt TrustManagerImpl.checkTrustedRecursive
    try {
        var TMImpl2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl2.checkTrustedRecursive.implementation = function() {
            if (!FLAGS.ssl) return this.checkTrustedRecursive.apply(this, arguments);
            return ArrayList.$new();
        };
    } catch(e) {}

    // 5. OkHttp3 CertificatePinner.check — all overloads
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(h, p) {
            if (!FLAGS.ssl) return this.check(h, p);
        };
        send({type: 'info', hook: 'okhttp3.CertificatePinner'});
    } catch(e) {}
    try {
        var CertPinner2 = Java.use('okhttp3.CertificatePinner');
        CertPinner2['check$okhttp'].overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(h, p) {
            if (!FLAGS.ssl) return this['check$okhttp'](h, p);
        };
    } catch(e) {}

    // 6. OkHttp2 (SquareUp) CertificatePinner
    try {
        var SqCertPinner = Java.use('com.squareup.okhttp.CertificatePinner');
        SqCertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(h, p) {
            if (!FLAGS.ssl) return this.check(h, p);
        };
        send({type: 'info', hook: 'squareup.CertificatePinner'});
    } catch(e) {}

    // 7. WebView SSL error handler
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            if (!FLAGS.ssl) return this.onReceivedSslError(view, handler, error);
            handler.proceed();
            send({type: 'info', hook: 'WebViewClient.onReceivedSslError'});
        };
    } catch(e) {}

    // 8. X509TrustManagerExtensions.checkServerTrusted
    try {
        var TMExt = Java.use('android.net.http.X509TrustManagerExtensions');
        TMExt.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ).implementation = function(chain, authType, host) {
            if (!FLAGS.ssl) return this.checkServerTrusted(chain, authType, host);
            var list = ArrayList.$new();
            for (var i = 0; i < chain.length; i++) { list.add(chain[i]); }
            return list;
        };
        send({type: 'info', hook: 'X509TrustManagerExtensions'});
    } catch(e) {}

    // --- Tier 2: Framework-specific + CT ---

    // 9. Conscrypt CertPinManager
    try {
        var CertPinMgr = Java.use('com.android.org.conscrypt.CertPinManager');
        try {
            CertPinMgr.isChainValid.implementation = function() {
                if (!FLAGS.ssl) return this.isChainValid.apply(this, arguments);
                return true;
            };
        } catch(e) {}
        try {
            CertPinMgr.checkChainPinning.implementation = function() {
                if (!FLAGS.ssl) return this.checkChainPinning.apply(this, arguments);
            };
        } catch(e) {}
        send({type: 'info', hook: 'CertPinManager'});
    } catch(e) {}

    // 10. Certificate Transparency checks (3 namespace variants)
    ['com.android.org.conscrypt.ct.CertificateTransparency',
     'org.conscrypt.ct.CertificateTransparency',
     'com.google.android.gms.org.conscrypt.ct.CertificateTransparency'].forEach(function(cls) {
        try {
            var CT = Java.use(cls);
            CT.checkCT.implementation = function() {
                if (!FLAGS.ssl) return this.checkCT.apply(this, arguments);
            };
        } catch(e) {}
    });

    // 11. TrustKit
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        TrustKit.checkServerTrusted.implementation = function(chain, authType) {
            if (!FLAGS.ssl) return this.checkServerTrusted(chain, authType);
        };
        send({type: 'info', hook: 'TrustKit'});
    } catch(e) {}

    // 12. Android OkHostnameVerifier — two same-arity overloads, so forward the
    // declared args and let Frida resolve by the 2nd arg's runtime type.
    try {
        var OkHV = Java.use('com.android.okhttp.internal.tls.OkHostnameVerifier');
        OkHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(host, session) {
            if (!FLAGS.ssl) return this.verify(host, session);
            return true;
        };
        OkHV.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(host, cert) {
            if (!FLAGS.ssl) return this.verify(host, cert);
            return true;
        };
        send({type: 'info', hook: 'OkHostnameVerifier'});
    } catch(e) {}

    // --- Tier 3: Native hooks ---

    // 13. BoringSSL/OpenSSL SSL_CTX_set_verify — when off, leave args untouched
    // so the app's real verify mode stands.
    ['libssl.so', 'libboringssl.so'].forEach(function(lib) {
        try {
            var set_verify = Module.findExportByName(lib, 'SSL_CTX_set_verify');
            if (set_verify) {
                Interceptor.attach(set_verify, {
                    onEnter: function(args) {
                        if (!FLAGS.ssl) return;
                        args[1] = ptr(0);  // Set verify mode to SSL_VERIFY_NONE
                    }
                });
                send({type: 'info', hook: lib + ':SSL_CTX_set_verify'});
            }
        } catch(e) {}
    });

    send({type: 'ready', message: 'SSL pinning bypass hooks loaded'});
}

// Run the Java tier behind a Java.available retry guard: on frida the global
// `Java` is only usable once a Java bridge is injected AND the ART VM is up.
// On a cold spawn that is not true at load time, so retry on a short timer
// (bounded) until the VM initialises instead of throwing and aborting the
// script. The native tiers below install independently of this.
(function _suRunJavaTier(attempt) {
    try {
        if (typeof Java === 'undefined' || !Java.available) {
            if ((attempt || 0) < 50) {
                setTimeout(function() { _suRunJavaTier((attempt || 0) + 1); }, 200);
            }
            return;
        }
        Java.perform(_suJavaTier);
    } catch (e) {
        // Never let the Java tier abort the script — the native tiers below are
        // what defeat the cronet/mbedTLS/MNS pins and must always install.
        try { send({type: 'debug', hook: 'java-tier-skipped', error: '' + e}); } catch (e2) {}
    }
})(0);

// --- Tier 4: native cronet / Chromium-BoringSSL unpin (FLAGS.ssl-gated) ------
//
// Google's cronet net stack (statically-linked BoringSSL) bypasses the Java
// TrustManager + classic SSL_CTX_set_verify paths above, so okhttp/Conscrypt
// unpinning leaves cronet endpoints (e.g. lens-pa.googleapis.com) encrypted
// ("client does not trust the proxy's certificate"). cronet verifies the server
// cert in TWO places, both defeated here:
//   (1) SSL_set_custom_verify / SSL_CTX_set_custom_verify -> install an
//       always-OK callback (ssl_verify_ok).
//   (2) bssl::ssl_verify_peer_cert / ssl_reverify_peer_cert -> the BoringSSL
//       INTERNAL entry point actually invoked during the handshake. DECISIVE:
//       cronet does not re-call the custom_verify setter per connection, so
//       hooking only the setter is too late; this defeats pinning regardless.
//   (3) SSL_get_verify_result -> X509_V_OK.
//   (4) net::CertVerifyProc::Verify / CertVerifyProcAndroid|Builtin::VerifyInternal
//       -> the Chromium net:: layer verifier ABOVE BoringSSL re-checks the
//       platform trust store; force net::OK + zero CertVerifyResult.cert_status
//       or cronet accepts the TLS cert yet still refuses to send (idle timeout).
//
// Robustness: cronet's BoringSSL lives in its own apex/mainline module
// (observed stable_cronet_libssl.so; also libsscronet/libcronet/libmonochrome
// or embedded), and `Module.findExportByName` returns null for these modules on
// Frida 17 / Android 16 — so we enumerate exports AND the symbol table of every
// loaded module and hook any that carry the symbols, re-scanning on dlopen and
// on timers for lazy loads. Each body re-checks FLAGS.ssl (calling the original
// when off) so the set_flags RPC toggles it at runtime, exactly like the Java
// hooks. Pure-native, so it runs outside Java.perform and is a harmless no-op on
// apps without cronet.
//
// NOTE: cronet/Lens networking runs in the app's :search/:interactor CHILD
// process (zygote-spawned, NOT forked from main), so reaching it needs
// spawn-gated injection of this combined script into that child — see
// JobManager.setup_gated_session() in AndroidFridaManager (proven recipe; not
// yet wired into BypassService). cronet also ignores the device http_proxy, so
// its TCP/443 must be transparently redirected (FocusManager per-UID REDIRECT ->
// gost -> mitmproxy SOCKS5 + QUIC block) — the global http_proxy path won't see it.
(function() {
    var SSL_VERIFY_OK = 0;   // bssl ssl_verify_result_t / custom-verify OK
    var X509_V_OK = 0;       // SSL_get_verify_result OK

    var _okCb = null;
    function okVerifyCallback() {
        if (_okCb === null) {
            _okCb = new NativeCallback(function(ssl, out_alert) {
                return SSL_VERIFY_OK;
            }, 'int', ['pointer', 'pointer']);
        }
        return _okCb;
    }

    var hookedModules = {};   // module.name -> true (don't double-hook)

    function exportAddrMap(mod) {
        var map = {};
        try { mod.enumerateExports().forEach(function(e) { map[e.name] = e.address; }); } catch (e) {}
        return map;
    }
    function symbolAddr(mod, name) {
        try {
            var syms = mod.enumerateSymbols();
            for (var i = 0; i < syms.length; i++) {
                if (syms[i].name === name && !syms[i].address.isNull()) return syms[i].address;
            }
        } catch (e) {}
        return null;
    }

    function hookModule(mod) {
        if (!mod || hookedModules[mod.name]) return false;
        var em = exportAddrMap(mod);
        var setCV    = em['SSL_set_custom_verify']     || symbolAddr(mod, 'SSL_set_custom_verify');
        var setCtxCV = em['SSL_CTX_set_custom_verify'] || symbolAddr(mod, 'SSL_CTX_set_custom_verify');
        var getVR    = em['SSL_get_verify_result']     || symbolAddr(mod, 'SSL_get_verify_result');
        if (!setCV && !setCtxCV && !getVR) return false;   // not a BoringSSL module
        hookedModules[mod.name] = true;
        var done = [];

        // (1) custom-verify setters: make cronet install OUR always-OK callback
        // instead of its own. attach + onEnter arg-rewrite (args[2] = the cb
        // pointer) rather than Interceptor.replace: attaching only inserts a
        // prologue hook and leaves the real setter body intact, so it cannot tear
        // a trampoline mid-execution the way replacing a hot function can (see
        // SPAWN-SURVIVAL HARDENING header). Pass-through when off needs no special
        // handling — we simply don't rewrite args[2], so the app's own cb stands.
        [['SSL_set_custom_verify', setCV],
         ['SSL_CTX_set_custom_verify', setCtxCV]].forEach(function(pair) {
            var addr = pair[1];
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        if (!FLAGS.ssl) return;
                        try { args[2] = okVerifyCallback(); } catch (e) {}   // ignore cronet's cb
                    }
                });
                done.push(pair[0]);
            } catch (e) {}
        });

        // (3) SSL_get_verify_result -> X509_V_OK. attach + onLeave retval.replace
        // instead of replacing the whole function (leave the result intact when off).
        if (getVR) {
            try {
                Interceptor.attach(getVR, {
                    onLeave: function(retval) {
                        if (!FLAGS.ssl) return;
                        retval.replace(X509_V_OK);
                    }
                });
                done.push('SSL_get_verify_result');
            } catch (e) {}
        }

        // (2) BoringSSL internal verify entry points (bssl:: symbols, symbol
        // table only). attach + onLeave retval.replace (not Interceptor.replace):
        // the original verify runs; we just overwrite its return value to
        // ssl_verify_ok when armed, and leave it intact when off. Avoids
        // trampolining the hot handshake function (see SPAWN-SURVIVAL HARDENING).
        [['_ZN4bssl20ssl_verify_peer_certEPNS_13SSL_HANDSHAKEE', 'ssl_verify_peer_cert'],
         ['_ZN4bssl22ssl_reverify_peer_certEPNS_13SSL_HANDSHAKEEb', 'ssl_reverify_peer_cert']
        ].forEach(function(t) {
            var addr = symbolAddr(mod, t[0]);
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onLeave: function(retval) {
                        if (!FLAGS.ssl) return;
                        retval.replace(SSL_VERIFY_OK);   // bssl::ssl_verify_ok
                    }
                });
                done.push(t[1]);
            } catch (e) {}
        });

        if (done.length) {
            try { send({type: 'info', hook: 'cronet:' + mod.name + ':' + done.join('+')}); } catch (e) {}
        }
        return done.length > 0;
    }

    // (4) Chromium net:: layer verifier — lives in the cronet net module, which
    // does NOT export the BoringSSL symbols, so hook it separately. The
    // CertVerifyResult* out-param is arg index 6 (after `this`) on arm64.
    var hookedNetVerify = {};
    var NET_VERIFY_SYMS = [
        ['_ZN3net14CertVerifyProc6VerifyEPNS_15X509CertificateERKNSt4__Cr12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_SB_iPNS_16CertVerifyResultERKNS_16NetLogWithSourceE', 'CertVerifyProc::Verify'],
        ['_ZN3net21CertVerifyProcAndroid14VerifyInternalEPNS_15X509CertificateERKNSt4__Cr12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_SB_iPNS_16CertVerifyResultERKNS_16NetLogWithSourceE', 'CertVerifyProcAndroid::VerifyInternal'],
        ['_ZN3net21CertVerifyProcBuiltin14VerifyInternalEPNS_15X509CertificateERKNSt4__Cr12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_SB_iPNS_16CertVerifyResultERKNS_16NetLogWithSourceE', 'CertVerifyProcBuiltin::VerifyInternal']
    ];
    function hookNetCertVerify(mod) {
        if (!mod || hookedNetVerify[mod.name]) return false;
        var done = [];
        NET_VERIFY_SYMS.forEach(function(pair) {
            var addr = symbolAddr(mod, pair[0]);
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) { this.cvr = args[6]; },   // CertVerifyResult*
                    onLeave: function(retval) {
                        if (!FLAGS.ssl) return;   // original ran; leave result intact
                        try { if (this.cvr && !this.cvr.isNull()) this.cvr.add(8).writeU32(0); } catch (e) {}
                        retval.replace(0);   // net::OK
                    }
                });
                done.push(pair[1]);
            } catch (e) {}
        });
        if (done.length) {
            hookedNetVerify[mod.name] = true;
            try { send({type: 'info', hook: 'cronet:' + mod.name + ':' + done.join('+')}); } catch (e) {}
        }
        return done.length > 0;
    }

    // (5) STRIPPED, statically-linked BoringSSL (e.g. GmsCore split_CronetDynamite
    // libcronet.*.so): .dynsym carries ZERO SSL symbols and there is no .symtab, so the
    // export/symbol gate in hookModule() (the `if (!setCV && !setCtxCV && !getVR) return
    // false;` above) and the mangled-name lookups in hookNetCertVerify() BOTH find
    // nothing and skip the module entirely. Locate the cert-verify functions by a
    // version-STABLE code signature instead of a symbol name or a fixed offset, so this
    // self-adapts across cronet updates:
    //   anchor  = PUT_ERROR(ERR_LIB_SSL=16, SSL_R_CERTIFICATE_VERIFY_FAILED=125), i.e.
    //             `mov w0,#0x10 ; mov w1,wzr ; mov w2,#0x7d`  (aarch64, 12 bytes).
    // This triple occurs in exactly the two cert-verify functions ssl_verify_peer_cert
    // and ssl_reverify_peer_cert (proven: 2 hits in a stripped libcronet 149.x). From
    // each hit we walk BACKWARDS to the `paciasp` prologue to recover the function entry,
    // then find the custom_verify_callback dispatch inside it (`blr xN` immediately
    // followed by `cmp w0,#1`) and rewrite the callback's ssl_verify_invalid(1) return to
    // ssl_verify_ok(0) *before* the fatal-alert path runs. A plain onLeave return-flip is
    // too late here: the invalid path calls ssl_send_alert() to QUEUE a fatal
    // certificate_unknown(46) alert *inside* the function body before returning, which
    // already aborts the TLS handshake (verified live). We keep an onLeave flip too as a
    // belt-and-braces for any non-callback (x509_method) path. arm64 only.
    //
    // ADDITIVE + INDEPENDENT: this is a SEPARATE path from hookModule()'s symbol gate
    // above — it does NOT touch that gate. It is the only tier that reaches
    // stripped/symbol-less cronet libs, which the symbol gate necessarily misses. Keyed
    // on per-load addresses (not module name) so a transient CronetDynamite reload is
    // re-hooked.
    var hookedCronetStripped = {};                 // addr/site keys -> true (per-load dedupe)
    var _CV_PAT   = '00 02 80 52 e1 03 1f 2a a2 0f 80 52'; // mov w0,#0x10; mov w1,wzr; mov w2,#0x7d
    var _CV_PACIASP = 0xd503233f, _CV_CMPW01 = 0x7100041f;
    function _cvIsBlr(w) { return (((w & 0xFFFFFC1F)) >>> 0) === 0xD63F0000; }
    function hookCronetStrippedVerify(mod) {
        if (!mod || Process.arch !== 'arm64') return false;
        var done = [];
        var ranges = Process.enumerateRanges('r-x').filter(function(r) {
            return r.base.compare(mod.base) >= 0 && r.base.compare(mod.base.add(mod.size)) < 0; });
        var sites = [];
        ranges.forEach(function(r) {
            var mm; try { mm = Memory.scanSync(r.base, r.size, _CV_PAT); } catch (e) { mm = []; }
            mm.forEach(function(m) { sites.push(m.address); });
        });
        if (!sites.length) return false;
        sites.forEach(function(site) {
            // dedupe by SITE address so a re-scan after we patch the prologue can't walk
            // back past the (now-overwritten) paciasp into the previous function.
            var sk = 's' + site.toString();
            if (hookedCronetStripped[sk]) return;
            hookedCronetStripped[sk] = true;
            // walk back to the paciasp prologue -> function entry
            var p = site, lim = site.sub(0x1000), entry = null;
            while (p.compare(lim) >= 0) {
                try { if (p.readU32() === _CV_PACIASP) { entry = p; break; } } catch (e) { break; }
                p = p.sub(4);
            }
            if (!entry) return;
            // custom_verify_callback dispatch: `blr xN` immediately followed by `cmp w0,#1`
            var a = entry;
            while (a.compare(site) < 0) {
                var isDispatch = false;
                try { isDispatch = _cvIsBlr(a.readU32()) && (a.add(4).readU32() === _CV_CMPW01); } catch (e) {}
                if (isDispatch) {
                    var cmpAddr = a.add(4), ck = 'c' + cmpAddr.toString();
                    if (!hookedCronetStripped[ck]) {
                        hookedCronetStripped[ck] = true;
                        try {
                            Interceptor.attach(cmpAddr, { onEnter: function() {
                                if (!FLAGS.ssl) return;
                                if ((this.context.x0.toInt32() | 0) === 1) this.context.x0 = ptr(0);
                            }});
                            done.push('cb@' + cmpAddr);
                        } catch (e) {}
                    }
                }
                a = a.add(4);
            }
            // belt-and-braces: flip the function's own return 1 -> 0 (covers x509_method path)
            var ek = 'e' + entry.toString();
            if (!hookedCronetStripped[ek]) {
                hookedCronetStripped[ek] = true;
                try {
                    Interceptor.attach(entry, { onLeave: function(rv) {
                        if (!FLAGS.ssl) return;
                        if (rv.toInt32() === 1) rv.replace(0);
                    }});
                    done.push('fn@' + entry);
                } catch (e) {}
            }
        });
        if (done.length) {
            try { send({type: 'info', hook: 'cronet_stripped:' + mod.name + ':' + done.join('+')}); } catch (e) {}
        }
        return done.length > 0;
    }

    function scanModules() {
        try {
            Process.enumerateModules().forEach(function(m) {
                var n = m.name.toLowerCase();
                var looksRelevant =
                    n.indexOf('ssl') !== -1 || n.indexOf('cronet') !== -1 ||
                    n.indexOf('boring') !== -1 || n.indexOf('chrome') !== -1 ||
                    n.indexOf('monochrome') !== -1 || n.indexOf('crypto') !== -1;
                if (!looksRelevant) return;
                if (!hookedModules[m.name]) hookModule(m);
                if (!hookedNetVerify[m.name]) hookNetCertVerify(m);
                // Stripped static BoringSSL inside cronet (no symbols at all): a
                // SEPARATE, additive path from the symbol gate in hookModule() above,
                // for symbol-less cronet libs it necessarily misses. Keyed on per-load
                // addresses (not module name) so a transient CronetDynamite reload is
                // re-hooked.
                if (n.indexOf('cronet') !== -1) hookCronetStrippedVerify(m);
            });
        } catch (e) {}
    }

    // Expose a TARGETED cronet hook to the file scope so the deterministic ctor-
    // interpose (in the mbedTLS tier) can hook a cronet BoringSSL module in its
    // mapped-but-pre-init window. We expose hookModule/hookNetCertVerify (single-
    // module, light) rather than scanModules (full Process.enumerateModules() —
    // too heavy/unsafe to run from inside the linker ctor caller).
    try {
        globalThis._SU_hookCronetModule = function(mod) {
            var r = false;
            try { if (!hookedModules[mod.name]) r = hookModule(mod) || r; } catch (e) {}
            try { if (!hookedNetVerify[mod.name]) r = hookNetCertVerify(mod) || r; } catch (e) {}
            return r;
        };
    } catch (e) {}

    try {
        // Initial scan (cronet's BoringSSL is often already mapped at spawn).
        // DEFERRED via setTimeout(0): on a cold SPAWN this otherwise runs during
        // script.load() while the process is still spawn-gated and frida is mid-
        // RPC; doing Interceptor work synchronously there contributed to the torn-
        // trampoline crash. Deferring to a tick lets load() return and the caller
        // resume() the process first. Debounced so it coalesces with the dlopen
        // scans below. Harmless for any app.
        _SU_debounce('cronet', scanModules, 0);

        // Re-scan when libraries load lazily after startup. DEBOUNCED: never
        // re-scan re-entrantly from inside dlopen (see SPAWN-SURVIVAL HARDENING
        // header) — coalesce the cold-spawn dlopen-storm into one scan after the
        // linker goes quiet.
        try {
            new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach(function(d) {
                Interceptor.attach(d.address, {
                    onLeave: function() { _SU_debounce('cronet', scanModules, 50); }
                });
            });
        } catch (e) {}
        // Belt-and-braces timed re-scans for loaders dlopen doesn't surface.
        setTimeout(scanModules, 2000);
        setTimeout(scanModules, 5000);
        setTimeout(scanModules, 10000);
    } catch (e) {}
})();

// ===========================================================================
// Tier 5: Native mbedTLS / Meta Network Stack (MNS / "Silverstone DataGateway")
// SSL-pinning unpin tier.
//
// Why this exists: Meta's apps (e.g. Meta AI = com.facebook.stella) do NOT route
// their image-upload / DataGateway traffic through the Android system CA store,
// the Java TrustManager/Conscrypt path, OkHttp, or cronet's BoringSSL. They use
// Meta's OWN native network stack ("MNS" = Meta Network Stack) inside
// libsilverstonedgw-*.so, which performs TLS with a STATICALLY-LINKED copy of
// mbedTLS that lives (with its exported symbols intact) in the giant runtime lib
// libstartup.so, and then ADDITIONALLY pins the server cert in a Meta-specific
// verifier. Logcat on a pin failure shows:
//   MNSCertificateVerifier: Pin verification failed
//   mbedtls_ssl_handshake(): Pin verification failed (-0x2700 =
//     MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
// so the system-CA path and every Java/cronet tier above leave the
// rupload.facebook.com image upload encrypted. This tier defeats the mbedTLS +
// MNS pin so that channel decrypts through mitmproxy. More broadly it is a
// GENERIC mbedTLS unpin: the universal mbedtls_x509_crt_verify* family makes it
// work for ANY mbedTLS-pinning app, not just Meta.
//
// What we hook (resolved by EXPORT name across ALL loaded modules):
//  1. MNSCertificateVerifierVerifyMaybeCreateError -> force the return value to 0
//     (null / "no error"). The exact symbol named in the logcat pin failure;
//     "MaybeCreateError" returns a non-null error object on a pin mismatch and
//     null/0 on success, so forcing 0 makes every cert pass. Meta-specific
//     supplement (the Meta pin lives here, ABOVE standard mbedTLS verification).
//  2. mbedtls_ssl_conf_verify(conf, f_vrfy, p_vrfy) -> swap whatever custom
//     verify callback is installed for one that zeroes *flags and returns 0.
//  3. mbedtls_ssl_conf_authmode(conf, authmode) -> force VERIFY_NONE (0) so the
//     standard chain verification is skipped (belt-and-braces).
//  3b. mbedtls_ssl_set_hs_authmode(ssl, authmode) -> VERIFY_NONE. Per-handshake
//     override of (3) for apps that re-arm verification per connection.
//  4. mbedtls_x509_crt_verify / _with_profile / _restartable -> zero the *flags
//     out-param and return 0. The UNIVERSAL mbedTLS chain-verify entry points;
//     hooking them defeats a standard mbedTLS pin in ANY app regardless of any
//     app-specific verifier, so the generic path stands on its own.
//  5. mbedtls_ssl_set_verify(ssl, f_vrfy, p_vrfy) -> per-connection analogue of
//     (2); swap the app's verify callback for one that returns success.
//
// Robustness measures (mirror the cronet tier):
//  * mbedTLS lives in libstartup.so (~17 MB) and the MNS libs load LAZILY, so we
//    DON'T hardcode a module: resolve each symbol across ALL loaded modules,
//    hook dlopen and re-scan on every load, plus timed re-scans.
//  * Clean no-op when none of these symbols resolve (the common case -- non-
//    mbedTLS apps), wrapped in try/catch so it NEVER throws. Each symbol hooked
//    at most once (latch map).
//  * FLAGS.ssl-gated. Emits send({type:'info', hook:'mbedtls:...'}) per hook
//    installed so success is observable exactly like the cronet tier above.
//
// Pure-native, runs outside Java.perform. Like cronet, MNS ignores the device
// http_proxy, so its TCP/443 must be transparently redirected (per-UID REDIRECT
// -> gost -> mitmproxy SOCKS5 + QUIC block) and reached via spawn-gated injection.
// ===========================================================================
(function() {
    if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;

    var MBEDTLS_SSL_VERIFY_NONE = 0;
    var _mbedHooked = {};   // symbol name -> true (hook at most once)

    // When set (by the ctor-interpose path), resolve symbols ONLY from this one
    // module via a cheap findExportByName — NOT a full Process.enumerateModules()
    // walk. Enumerating all modules from inside the linker's call_constructors hot
    // path is heavy and unsafe (it crashed the splash in testing); the targeted
    // lookup against the just-mapped libstartup.so is light and stable.
    var _mbedTargetModule = null;

    // Resolve a symbol by EXPORT name. If a target module is pinned (ctor path),
    // look there first/only. Otherwise walk every loaded module. On Frida 17 /
    // Android 16 Module.findExportByName(null, ...) is unreliable for these
    // statically-linked-but-exported symbols, so we walk modules (the same
    // "enumerate, don't trust global lookups" stance as the cronet tier).
    function resolveAnyExport(name) {
        var addr = null;
        if (_mbedTargetModule) {
            try { var a0 = _mbedTargetModule.findExportByName(name); if (a0 && !a0.isNull()) return a0; }
            catch (e) {}
            return null;   // ctor path: don't fall back to a full enumerate in the hot path
        }
        try {
            Process.enumerateModules().some(function(m) {
                try { var a = m.findExportByName(name); if (a && !a.isNull()) { addr = a; return true; } }
                catch (e) {}
                return false;
            });
        } catch (e) {}
        return addr;
    }

    // A single shared "always trust" mbedTLS verify callback:
    // int f_vrfy(void *p_vrfy, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    // Zero *flags and return 0 (success).
    var _okMbedVrfy = null;
    function okMbedtlsVerifyCb() {
        if (_okMbedVrfy === null) {
            _okMbedVrfy = new NativeCallback(function(p, crt, depth, flags) {
                try { if (flags && !flags.isNull()) flags.writeU32(0); } catch (e) {}
                return 0;
            }, 'int', ['pointer', 'pointer', 'int', 'pointer']);
        }
        return _okMbedVrfy;
    }

    // Hook a mbedtls_x509_crt_verify* variant: zero the *flags out-param and
    // force the return value to 0 (success). `flagsIdx` is the zero-based arg
    // index of the `uint32_t *flags` out-parameter for that variant. This is the
    // UNIVERSAL mbedTLS chain-verification entry point used by every public
    // mbedTLS unpin -- hooking it defeats standard mbedTLS pinning regardless of
    // any app-specific verifier, so the generic path stands on its own.
    function hookX509Verify(latchKey, symName, flagsIdx, done) {
        if (_mbedHooked[latchKey]) return;
        var a = resolveAnyExport(symName);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter: function(args) {
                    if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) { this._skip = true; return; }
                    this._flags = args[flagsIdx];   // uint32_t *flags out-param
                },
                onLeave: function(rv) {
                    if (this._skip) return;
                    try { if (this._flags && !this._flags.isNull()) this._flags.writeU32(0); } catch (e) {}
                    rv.replace(0);   // 0 == verification succeeded
                }
            });
            _mbedHooked[latchKey] = true;
            done.push(symName);
        } catch (e) {}
    }

    function installMbedtlsHooks() {
        var done = [];

        // (1) MNSCertificateVerifierVerifyMaybeCreateError -> return 0 (no error).
        if (!_mbedHooked['MNSVerify']) {
            var aMns = resolveAnyExport('MNSCertificateVerifierVerifyMaybeCreateError');
            if (aMns) {
                try {
                    Interceptor.attach(aMns, {
                        onLeave: function(rv) {
                            if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;
                            rv.replace(0);   // null / "no error" == pin passed
                        }
                    });
                    _mbedHooked['MNSVerify'] = true;
                    done.push('MNSCertificateVerifierVerifyMaybeCreateError');
                } catch (e) {}
            }
        }

        // (2) mbedtls_ssl_conf_verify(conf, f_vrfy, p_vrfy) -> swap callback for OK.
        // attach + onEnter arg-rewrite (args[1] = f_vrfy) instead of replacing the
        // setter: leaves the setter body intact so it can't tear a trampoline mid-
        // call (see SPAWN-SURVIVAL HARDENING header). When off we don't rewrite, so
        // the app's own callback stands.
        if (!_mbedHooked['conf_verify']) {
            var aCV = resolveAnyExport('mbedtls_ssl_conf_verify');
            if (aCV) {
                try {
                    Interceptor.attach(aCV, {
                        onEnter: function(args) {
                            if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;
                            try { args[1] = okMbedtlsVerifyCb(); } catch (e) {}   // ignore the app's callback
                        }
                    });
                    _mbedHooked['conf_verify'] = true;
                    done.push('mbedtls_ssl_conf_verify');
                } catch (e) {}
            }
        }

        // (3) mbedtls_ssl_conf_authmode(conf, authmode) -> force VERIFY_NONE.
        if (!_mbedHooked['conf_authmode']) {
            var aAM = resolveAnyExport('mbedtls_ssl_conf_authmode');
            if (aAM) {
                try {
                    Interceptor.attach(aAM, {
                        onEnter: function(args) {
                            if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;
                            args[1] = ptr(MBEDTLS_SSL_VERIFY_NONE);
                        }
                    });
                    _mbedHooked['conf_authmode'] = true;
                    done.push('mbedtls_ssl_conf_authmode');
                } catch (e) {}
            }
        }

        // (3b) mbedtls_ssl_set_hs_authmode(ssl, authmode) -> per-HANDSHAKE
        //      analogue of (3): it OVERRIDES the conf-level authmode for the
        //      current connection, so an app that re-arms verification per
        //      handshake (set_hs_authmode(ssl, REQUIRED) after config) would
        //      otherwise beat (3). Force VERIFY_NONE here too. Public mbedTLS
        //      API in both 2.x and 3.x; clean no-op when the symbol is absent.
        if (!_mbedHooked['set_hs_authmode']) {
            var aHS = resolveAnyExport('mbedtls_ssl_set_hs_authmode');
            if (aHS) {
                try {
                    Interceptor.attach(aHS, {
                        onEnter: function(args) {
                            if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;
                            args[1] = ptr(MBEDTLS_SSL_VERIFY_NONE);
                        }
                    });
                    _mbedHooked['set_hs_authmode'] = true;
                    done.push('mbedtls_ssl_set_hs_authmode');
                } catch (e) {}
            }
        }

        // (4) The GENERIC mbedTLS chain-verification family. These are the
        //     universal unpin points: zero the *flags out-param and return 0 so
        //     the chain "verifies" no matter what CA signed it. Arg indices of
        //     the `uint32_t *flags` out-param per the mbedTLS public signatures:
        //       mbedtls_x509_crt_verify(crt, trust_ca, ca_crl, cn,
        //                               *flags, f_vrfy, p_vrfy)            -> idx 4
        //       mbedtls_x509_crt_verify_with_profile(crt, trust_ca, ca_crl,
        //                               profile, cn, *flags, f_vrfy, p_vrfy) -> idx 5
        //       mbedtls_x509_crt_verify_restartable(crt, trust_ca, ca_crl,
        //                               profile, cn, *flags, f_vrfy, p_vrfy,
        //                               rs_ctx)                            -> idx 5
        hookX509Verify('x509_verify', 'mbedtls_x509_crt_verify', 4, done);
        hookX509Verify('x509_verify_profile', 'mbedtls_x509_crt_verify_with_profile', 5, done);
        hookX509Verify('x509_verify_restartable', 'mbedtls_x509_crt_verify_restartable', 5, done);

        // (5) mbedtls_ssl_set_verify(ssl, f_vrfy, p_vrfy) -> per-CONNECTION
        //     analogue of mbedtls_ssl_conf_verify. Some stacks install the
        //     custom verify callback per-connection rather than per-conf; swap it
        //     for the always-OK callback. attach + onEnter arg-rewrite (args[1] =
        //     f_vrfy) instead of replacing the setter (see SPAWN-SURVIVAL HARDENING
        //     header). Reuses okMbedtlsVerifyCb().
        if (!_mbedHooked['set_verify']) {
            var aSV = resolveAnyExport('mbedtls_ssl_set_verify');
            if (aSV) {
                try {
                    Interceptor.attach(aSV, {
                        onEnter: function(args) {
                            if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return;
                            try { args[1] = okMbedtlsVerifyCb(); } catch (e) {}   // ignore the app's callback
                        }
                    });
                    _mbedHooked['set_verify'] = true;
                    done.push('mbedtls_ssl_set_verify');
                } catch (e) {}
            }
        }

        if (done.length) {
            try {
                send({type: 'info', hook: 'mbedtls:MNS:' + done.join('+')});
            } catch (e) {}
        }
        // "All hooked?" early-stop signal. The generic mbedTLS unpin is complete
        // once the UNIVERSAL chain-verify entry (mbedtls_x509_crt_verify) and the
        // authmode override are both installed -- that pair alone defeats a
        // standard mbedTLS pin in ANY app. The Meta-specific MNS symbol and the
        // optional x509 verify variants and the per-conf/per-conn verify
        // callbacks are supplements that may legitimately be absent, so they are
        // NOT required for the "done" signal. The re-scan loop ignores this
        // return value anyway (each symbol is latched), so it is purely an honest
        // completeness indicator.
        return _mbedHooked['x509_verify'] && _mbedHooked['conf_authmode'];
    }

    // =======================================================================
    // DETERMINISTIC pre-init verifier install via the linker's constructor caller.
    //
    // The race we close: Meta's DataGateway opens the gateway.facebook.com TLS
    // connection from libstartup.so's OWN init code, and bionic runs a library's
    // .init_array / DT_INIT constructors INSIDE do_dlopen, BEFORE dlopen/
    // android_dlopen_ext returns. So a dlopen onLeave hook (and any setTimeout/
    // debounce on Frida's JS loop, which runs concurrently with the resumed app)
    // is structurally TOO LATE — libstartup's constructor has already handshaked
    // gateway.facebook.com by then, and it pin-fails because our mbedTLS/MNS hooks
    // aren't in yet.
    //
    // The fix: interpose on soinfo::call_constructors (the linker function that
    // invokes a freshly-mapped library's constructors). In its onEnter the target
    // library is fully mapped + relocated but its .init_array has NOT run yet — the
    // "mapped-but-pre-init" window. We detect each SSL-bearing module there and
    // synchronously install ONLY that tier's verifier hooks on it (targeted — NOT a
    // full enumerateModules re-scan in the hot path), then Interceptor.flush() so
    // the patches are committed before we return into the linker which immediately
    // runs the library's constructor. One-shot per module + idempotent.
    //
    // Robustness/generality:
    //  * call_constructors is a LOCAL HIDDEN symbol -> resolve via enumerateSymbols
    //    on linker64 (fall back to linker). getExportByName won't find it.
    //  * Clean no-op if the symbol can't be resolved (then the debounced dlopen path
    //    below remains the fallback) OR if none of the target sonames ever load (the
    //    soname gate simply never matches) — so it cannot regress any other app.
    //  * Identifies a module by Process.findModuleByName(soname) becoming non-null
    //    at a ctor call — NO dependence on soinfo struct layout / get_soname.
    //  * Armed on the first post-resume JS tick (NOT synchronously in load()):
    //    attaching to a linker .text function during the mid-RPC load() window
    //    crashes the spawn (measured), but the SSL libs load late enough in startup
    //    (dozens of libraries after resume) that arming one tick after resume is
    //    still well before their constructors run — race won, spawn survival kept.
    // =======================================================================
    var _ctorEarlyDone = false;
    var _ctorListener = null;
    function installEarlyVerifierViaCtors() {
        if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) return false;
        var linker = null;
        try {
            linker = Process.findModuleByName('linker64') || Process.findModuleByName('linker');
        } catch (e) {}
        if (!linker) return false;   // no-op: fall back to debounced dlopen path

        var ctorAddr = null;
        try {
            linker.enumerateSymbols().some(function(s) {
                if (s.name === '__dl__ZN6soinfo17call_constructorsEv' && !s.address.isNull()) {
                    ctorAddr = s.address; return true;
                }
                return false;
            });
        } catch (e) {}
        if (!ctorAddr) return false;   // no-op: fall back to debounced dlopen path

        // GENERIC, STACK-AGNOSTIC pre-init unpin table. Each entry names a module
        // (by the soname an SSL-bearing library is loaded under) and the tier that
        // should hook it, TARGETED to that module. This is intentionally driven by
        // soname + a cheap findModuleByName check — NOT a full Process.enumerate-
        // Modules() in the hot ctor path (which regressed spawn survival). The set
        // covers every TLS stack the script supports, so ANY app's early-init TLS
        // gets unpinned before its first handshake:
        //   * system / conscrypt BoringSSL : libssl.so, libjavacrypto.so
        //     (graph.facebook.com and other early OkHttp/HttpsURLConnection traffic)
        //   * cronet (Chromium net)        : (stable_)cronet_libssl.so,
        //     libmainlinecronet*.so  (ar-genai.graph.meta.com graphql)
        //   * Meta MNS / mbedTLS           : libstartup.so  (gateway.facebook.com)
        //   * Flutter                      : libflutter.so  (Dart BoringSSL)
        // A module not present on a given app is simply skipped (clean no-op). The
        // 'flutter' tier resolves to a no-op here unless _SU_scanFlutterModule is
        // defined (this script ships no Flutter tier yet), so the libflutter.so
        // entry is harmless and forward-compatible.
        var _EARLY_TARGETS = [
            { name: 'libstartup.so',                 tier: 'mbedtls' },
            { name: 'stable_cronet_libssl.so',       tier: 'cronet'  },
            { name: 'cronet_libssl.so',              tier: 'cronet'  },
            { name: 'libmainlinecronet.so',          tier: 'cronet'  },
            { name: 'libssl.so',                     tier: 'cronet'  },  // system/conscrypt BoringSSL
            { name: 'libjavacrypto.so',              tier: 'cronet'  },  // conscrypt JNI BoringSSL
            { name: 'libflutter.so',                 tier: 'flutter' }
        ];
        var _earlyDoneSet = {};   // soname -> true (hooked once)

        // Install the right tier's hooks TARGETED to module `mod` (pre-init window).
        function _earlyInstall(mod, tier) {
            try {
                if (tier === 'mbedtls') {
                    _mbedTargetModule = mod;            // cheap findExportByName on this module
                    try { installMbedtlsHooks(); } finally { _mbedTargetModule = null; }
                } else if (tier === 'cronet') {
                    if (typeof _SU_hookCronetModule === 'function') _SU_hookCronetModule(mod);
                } else if (tier === 'flutter') {
                    if (typeof _SU_scanFlutterModule === 'function') _SU_scanFlutterModule(mod);
                }
                Interceptor.flush();   // commit before the linker runs mod's constructor
                send({type: 'info', hook: tier + ':early-ctor-install@' + mod.name});
                return true;
            } catch (e) { return false; }
        }

        var _ctorCalls = 0;
        try {
            _ctorListener = Interceptor.attach(ctorAddr, {
                onEnter: function() {
                    if (_ctorEarlyDone) return;
                    _ctorCalls++;
                    // For each not-yet-handled target, cheap findModuleByName (NOT a
                    // full enumerate). When it first appears it is mapped-but-pre-init
                    // (its ctor is about to run) -> install + flush now.
                    var allDone = true;
                    for (var i = 0; i < _EARLY_TARGETS.length; i++) {
                        var t = _EARLY_TARGETS[i];
                        if (_earlyDoneSet[t.name]) continue;
                        var mod = null;
                        try { mod = Process.findModuleByName(t.name); } catch (e) {}
                        if (mod) {
                            _earlyDoneSet[t.name] = _earlyInstall(mod, t.tier) || true;
                        } else {
                            allDone = false;   // may still load on a later ctor call
                        }
                    }
                    // Detach the (hot) ctor caller once either every target has loaded
                    // OR we've watched enough ctor calls that any further SSL module is
                    // unlikely to be the early-init one (bounded so a non-matching app —
                    // which never satisfies allDone — does not keep paying the per-call
                    // findModuleByName cost forever; the app's own startup runs FAR more
                    // than 400 constructors, and the SSL libs that back early traffic are
                    // mapped well within that). The debounced dlopen rescans remain as
                    // the safety net for anything that loads later.
                    if (allDone || _ctorCalls > 400) {
                        _ctorEarlyDone = true;
                        try { if (_ctorListener) _ctorListener.detach(); } catch (e) {}
                    }
                }
            });
            return true;
        } catch (e) { return false; }
    }

    try {
        // DETERMINISTIC PATH (primary): hook the linker's constructor caller so the
        // verifier installs in libstartup's mapped-but-pre-init window — BEFORE its
        // constructor opens gateway.facebook.com. Armed on the FIRST post-resume JS
        // tick (setTimeout 0), NOT synchronously during script.load(): attaching to
        // a linker .text function DURING load() (process spawn-gated, frida mid-RPC)
        // tears the trampoline and crashes the splash, exactly the class of crash
        // the SPAWN-SURVIVAL HARDENING fixes. Deferring the ATTACH to the first tick
        // after resume is crash-safe and still wins the race (libstartup loads late
        // in startup, well after the hook is armed).
        try {
            setTimeout(function() { try { installEarlyVerifierViaCtors(); } catch (e) {} }, 0);
        } catch (e) {}

        // Initial attempt (libstartup.so is often already mapped at attach time —
        // e.g. when ATTACHing to an already-running pid rather than spawning).
        // DEFERRED via setTimeout(0) so script.load() returns and the caller can
        // resume() the spawn-gated process before we do native Interceptor work on
        // libstartup.so (~17 MB) — doing it synchronously during load(), mid-RPC,
        // was part of the torn-trampoline crash. Debounced + per-symbol-latched so
        // coverage is unchanged. Clean no-op for non-mbedTLS apps.
        _SU_debounce('mbedtls', installMbedtlsHooks, 0);

        // Re-attempt when libs load lazily (the silverstone JNI libs / DataGateway
        // spin up after process start). DEBOUNCED: the mbedTLS/MNS tier resolves
        // symbols across libstartup.so (~17 MB); doing that re-entrantly on every
        // dlopen during the cold-spawn linker-storm is what tore the trampoline.
        // Coalesce into one post-burst scan. 10 ms: still coalesces the dlopen storm
        // but installs almost immediately once libstartup.so maps — Meta's
        // DataGateway opens its gateway.facebook.com TLS very early after libstartup
        // loads, so a longer delay would let that handshake race ahead of the bypass.
        try {
            new ApiResolver('module')
                .enumerateMatches('exports:linker*!*dlopen*')
                .forEach(function(d) {
                    Interceptor.attach(d.address, {
                        onLeave: function() { _SU_debounce('mbedtls', installMbedtlsHooks, 10); }
                    });
                });
        } catch (e) {}

        // Belt-and-braces timed re-scans for loaders dlopen doesn't surface.
        setTimeout(installMbedtlsHooks, 1000);
        setTimeout(installMbedtlsHooks, 3000);
        setTimeout(installMbedtlsHooks, 6000);
        setTimeout(installMbedtlsHooks, 10000);
    } catch (e) {}
})();
"""


class SSLUnpinManager(BypassManagerBase):
    """Data holder for the SSL pinning bypass hook-set.

    Like the other bypass managers it only declares the Frida payload and its
    hook registry; :class:`BypassService` (+ AFM's bundle API) owns the
    session, merge strategy, resume, and message handling. Reached via the
    ``"ssl"`` category key.
    """

    TOOL_NAME = "ssl_unpin"
    DISPLAY_NAME = "SSL Pinning Bypass"
    HOOKS_REGISTRY = SSL_UNPIN_HOOKS
    FRIDA_SCRIPT = _FRIDA_SCRIPT
    PRIORITY = 15
