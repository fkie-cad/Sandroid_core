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

    // Resolve a symbol by EXPORT name across every loaded module. On Frida 17 /
    // Android 16 Module.findExportByName(null, ...) is unreliable for these
    // statically-linked-but-exported symbols, so we walk modules (the same
    // "enumerate, don't trust global lookups" stance as the cronet tier).
    function resolveAnyExport(name) {
        var addr = null;
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
        if (!_mbedHooked['conf_verify']) {
            var aCV = resolveAnyExport('mbedtls_ssl_conf_verify');
            if (aCV) {
                try {
                    var origCV = new NativeFunction(aCV, 'void', ['pointer', 'pointer', 'pointer']);
                    Interceptor.replace(aCV, new NativeCallback(function(conf, f, p) {
                        if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) { origCV(conf, f, p); return; }
                        origCV(conf, okMbedtlsVerifyCb(), p);   // ignore the app's callback
                    }, 'void', ['pointer', 'pointer', 'pointer']));
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
        //     for the always-OK callback. Reuses okMbedtlsVerifyCb().
        if (!_mbedHooked['set_verify']) {
            var aSV = resolveAnyExport('mbedtls_ssl_set_verify');
            if (aSV) {
                try {
                    var origSV = new NativeFunction(aSV, 'void', ['pointer', 'pointer', 'pointer']);
                    Interceptor.replace(aSV, new NativeCallback(function(ssl, f, p) {
                        if (typeof FLAGS !== 'undefined' && !FLAGS.ssl) { origSV(ssl, f, p); return; }
                        origSV(ssl, okMbedtlsVerifyCb(), p);   // ignore the app's callback
                    }, 'void', ['pointer', 'pointer', 'pointer']));
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

    try {
        // Initial attempt (libstartup.so is often already mapped at attach time).
        installMbedtlsHooks();

        // Re-attempt when libs load lazily (the silverstone JNI libs / DataGateway
        // spin up after process start). Same dlopen-intercept strategy as above.
        try {
            new ApiResolver('module')
                .enumerateMatches('exports:linker*!*dlopen*')
                .forEach(function(d) {
                    Interceptor.attach(d.address, {
                        onLeave: function() { try { installMbedtlsHooks(); } catch (e) {} }
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
