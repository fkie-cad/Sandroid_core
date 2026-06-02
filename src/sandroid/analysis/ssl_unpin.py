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
