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

Java.perform(function() {
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
});

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

        // (1) custom-verify setters: install the always-OK callback when armed,
        // forward cronet's real callback when off.
        [['SSL_set_custom_verify', setCV],
         ['SSL_CTX_set_custom_verify', setCtxCV]].forEach(function(pair) {
            var addr = pair[1];
            if (!addr) return;
            try {
                var orig = new NativeFunction(addr, 'void', ['pointer', 'int', 'pointer']);
                Interceptor.replace(addr, new NativeCallback(function(ssl, mode, cb) {
                    if (!FLAGS.ssl) { orig(ssl, mode, cb); return; }
                    orig(ssl, mode, okVerifyCallback());   // ignore cronet's cb
                }, 'void', ['pointer', 'int', 'pointer']));
                done.push(pair[0]);
            } catch (e) {}
        });

        // (3) SSL_get_verify_result -> X509_V_OK (forward original when off).
        if (getVR) {
            try {
                var origGVR = new NativeFunction(getVR, 'long', ['pointer']);
                Interceptor.replace(getVR, new NativeCallback(function(ssl) {
                    if (!FLAGS.ssl) return origGVR(ssl);
                    return X509_V_OK;
                }, 'long', ['pointer']));
                done.push('SSL_get_verify_result');
            } catch (e) {}
        }

        // (2) BoringSSL internal verify entry points (bssl:: symbols, symbol
        // table only). Return ssl_verify_ok when armed; forward original when off.
        [['_ZN4bssl20ssl_verify_peer_certEPNS_13SSL_HANDSHAKEE', 'ssl_verify_peer_cert', ['pointer']],
         ['_ZN4bssl22ssl_reverify_peer_certEPNS_13SSL_HANDSHAKEEb', 'ssl_reverify_peer_cert', ['pointer', 'int']]
        ].forEach(function(t) {
            var addr = symbolAddr(mod, t[0]);
            if (!addr) return;
            try {
                var origVP = new NativeFunction(addr, 'int', t[2]);
                Interceptor.replace(addr, new NativeCallback(function() {
                    if (!FLAGS.ssl) return origVP.apply(null, arguments);
                    return SSL_VERIFY_OK;
                }, 'int', t[2]));
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
            });
        } catch (e) {}
    }

    try {
        scanModules();   // cronet's BoringSSL is often already mapped at spawn
        // Re-scan when libraries load lazily after startup.
        try {
            new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach(function(d) {
                Interceptor.attach(d.address, { onLeave: function() { scanModules(); } });
            });
        } catch (e) {}
        // Belt-and-braces timed re-scans for loaders dlopen doesn't surface.
        setTimeout(scanModules, 2000);
        setTimeout(scanModules, 5000);
        setTimeout(scanModules, 10000);
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
