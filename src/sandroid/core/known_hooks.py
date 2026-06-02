"""Known Frida hooks for Sandroid tools.

This module provides a registry of known hooks used by different Frida-based tools.
Since there's no automatic hook discovery in Frida, this is a manually curated list
that serves as best-effort conflict detection.

Important Notes:
----------------
1. These lists are APPROXIMATE - actual hooks depend on tool version and configuration
2. Some tools (like objection) have dynamic hooks based on runtime commands
3. This is used for WARNING purposes, not prevention - hooks may still conflict
4. Update these lists when tool implementations change

Hook Conflict Levels:
--------------------
- CRITICAL: Same native function hooked (will crash)
- HIGH: Same Java method hooked (unpredictable behavior)
- MEDIUM: Same functional area (may interfere with results)
- LOW: Related but unlikely to conflict
"""

from dataclasses import dataclass, field
from enum import Enum


class HookCategory(Enum):
    """Categories of hooks for conflict analysis."""

    SSL_TLS = "ssl_tls"
    ROOT_DETECTION = "root_detection"
    EMULATOR_DETECTION = "emulator_detection"
    FRIDA_DETECTION = "frida_detection"
    DEBUG_DETECTION = "debug_detection"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    CRYPTO = "crypto"
    PROCESS = "process"
    MEMORY = "memory"
    CLIPBOARD = "clipboard"
    KEYSTORE = "keystore"
    INTENT = "intent"
    SQLITE = "sqlite"
    PREFERENCES = "preferences"
    SENSORS = "sensors"
    BUILD_PROPERTIES = "build_properties"


class SessionType(Enum):
    """How the tool manages its Frida session."""

    JOB_MANAGER = "job_manager"  # Uses our JobManager (coordinated)
    OWN_SESSION = "own_session"  # Creates its own Frida session (uncoordinated)
    SUBPROCESS = "subprocess"  # Runs as subprocess with own session (uncoordinated)
    EXTERNAL = "external"  # External tool, completely outside our control


@dataclass
class ToolHookInfo:
    """Information about a tool's hook usage."""

    name: str
    display_name: str
    session_type: SessionType
    categories: list[HookCategory]
    native_hooks: list[str] = field(default_factory=list)
    java_hooks: list[str] = field(default_factory=list)
    description: str = ""
    dynamic_hooks: bool = False  # True if hooks change at runtime
    notes: str = ""


# ============================================================================
# FRITAP - SSL/TLS Traffic Interception
# ============================================================================
FRITAP_HOOKS = ToolHookInfo(
    name="fritap",
    display_name="FriTap SSL Logger",
    session_type=SessionType.JOB_MANAGER,
    categories=[HookCategory.SSL_TLS, HookCategory.NETWORK],
    native_hooks=[
        # OpenSSL
        "SSL_read",
        "SSL_write",
        "SSL_get_fd",
        "SSL_get_session",
        "SSL_SESSION_get_id",
        "SSL_new",
        "SSL_do_handshake",
        "SSL_connect",
        "SSL_accept",
        # BoringSSL (Android's default)
        "boringssl_read",
        "boringssl_write",
        # Apple Security Framework
        "SSLRead",
        "SSLWrite",
        "SSLHandshake",
        # NSS (Mozilla)
        "PR_Read",
        "PR_Write",
        # GnuTLS
        "gnutls_record_recv",
        "gnutls_record_send",
    ],
    java_hooks=[],
    description="Intercepts SSL/TLS traffic at the native layer",
    dynamic_hooks=False,
)

# ============================================================================
# OBJECTION - Mobile Security Testing
# ============================================================================
OBJECTION_HOOKS = ToolHookInfo(
    name="objection",
    display_name="Objection",
    session_type=SessionType.SUBPROCESS,
    categories=[
        HookCategory.SSL_TLS,
        HookCategory.ROOT_DETECTION,
        HookCategory.FILE_SYSTEM,
        HookCategory.CLIPBOARD,
        HookCategory.KEYSTORE,
        HookCategory.INTENT,
        HookCategory.SQLITE,
        HookCategory.PREFERENCES,
    ],
    native_hooks=[
        # SSL pinning bypass (if enabled)
        "SSL_CTX_set_verify",
        "SSL_set_verify",
    ],
    java_hooks=[
        # SSL Pinning (android sslpinning disable)
        "javax.net.ssl.SSLContext.init",
        "javax.net.ssl.X509TrustManager.checkServerTrusted",
        "okhttp3.CertificatePinner.check",
        "com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive",
        # Root Detection (android root disable)
        "java.io.File.exists",  # For su/magisk checks
        "java.lang.Runtime.exec",  # For which su checks
        "android.app.ApplicationPackageManager.getPackageInfo",  # Root app detection
        # File System
        "java.io.FileInputStream.<init>",
        "java.io.FileOutputStream.<init>",
        # Keystore
        "java.security.KeyStore.load",
        "android.security.keystore.KeyGenParameterSpec$Builder.build",
        # Clipboard
        "android.content.ClipboardManager.getPrimaryClip",
        "android.content.ClipboardManager.setPrimaryClip",
        # SQLite
        "android.database.sqlite.SQLiteDatabase.rawQuery",
        "android.database.sqlite.SQLiteDatabase.execSQL",
        # SharedPreferences
        "android.app.SharedPreferencesImpl.getString",
        "android.app.SharedPreferencesImpl$EditorImpl.putString",
    ],
    description="Interactive mobile security testing tool",
    dynamic_hooks=True,  # Hooks depend on user commands
    notes="Objection creates its own Frida session via subprocess. "
    "Hooks are loaded dynamically based on REPL commands. "
    "Cannot be coordinated with JobManager.",
)

# ============================================================================
# TRIGDROID - Malware Trigger Framework
# ============================================================================
TRIGDROID_HOOKS = ToolHookInfo(
    name="trigdroid",
    display_name="TrigDroid",
    session_type=SessionType.OWN_SESSION,  # Has its own TrigDroidAPI
    categories=[
        HookCategory.SENSORS,
        HookCategory.BUILD_PROPERTIES,
        HookCategory.ROOT_DETECTION,
        HookCategory.EMULATOR_DETECTION,
        HookCategory.FRIDA_DETECTION,
        HookCategory.DEBUG_DETECTION,
    ],
    native_hooks=[],
    java_hooks=[
        # Sensor hooks
        "android.hardware.Sensor.getPower",
        "android.hardware.Sensor.getMaximumRange",
        "android.hardware.Sensor.getResolution",
        # Build property hooks
        "android.os.Build.MODEL",
        "android.os.Build.MANUFACTURER",
        "android.os.Build.BRAND",
        "android.os.Build.DEVICE",
        "android.os.Build.FINGERPRINT",
        # Root Detection Bypass (if enabled)
        "java.io.File.exists",
        "java.lang.Runtime.exec",
        "android.app.ApplicationPackageManager.getPackageInfo",
        # Debug Detection Bypass (if enabled)
        "android.os.Debug.isDebuggerConnected",
    ],
    description="Automated malware trigger execution and analysis",
    dynamic_hooks=True,
    notes="TrigDroid has its own API and session management. "
    "SSL unpinning delegated to SSLUnpinManager (ssl_unpin).",
)

# ============================================================================
# SSL PINNING BYPASS
# ============================================================================
SSL_UNPIN_TOOL = ToolHookInfo(
    name="ssl_unpin",
    display_name="SSL Pinning Bypass",
    session_type=SessionType.JOB_MANAGER,
    categories=[HookCategory.SSL_TLS],
    native_hooks=[
        "SSL_CTX_set_verify",
    ],
    java_hooks=[
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
    ],
    description="Comprehensive SSL/TLS pinning bypass for mitmproxy interception",
    dynamic_hooks=False,
    notes="Used by mitmproxy panel (Ctrl+P) and TrigDroid (ssl_unpinning). "
    "Shares session with other JobManager-based tools.",
)

# ============================================================================
# NATIVE DETECTION BYPASSES (Sandroid built-in, BypassService)
# ============================================================================
# Self-contained Frida bypasses owned by BypassService — no trigdroid bundle
# required. Hook scopes are disjoint *among these three* so the AFM runtime
# registry does not flag false intra-set conflicts. Native libc hooks may
# still stack with Dexray/MalwareMonitor (Frida tolerates that); those
# overlaps are advisory, not fatal.
FRIDA_DETECTION_BYPASS_TOOL = ToolHookInfo(
    name="frida_detection_bypass",
    display_name="Frida Detection Bypass",
    session_type=SessionType.JOB_MANAGER,
    categories=[HookCategory.FRIDA_DETECTION, HookCategory.PROCESS],
    native_hooks=[
        "open",
        "openat",
        "read",
        "close",
        "strstr",
        "exit",
        "_exit",
        "abort",
    ],
    java_hooks=[
        "android.os.Process.killProcess",
        "java.lang.Runtime.exit",
        "java.lang.System.exit",
    ],
    description="Anti-anti-Frida prelude: self-kill suppression, /proc scan "
    "filtering, frida-needle strstr nulling",
    dynamic_hooks=False,
    notes="Does NOT hook Debug.isDebuggerConnected (lives in the Debug "
    "detection bypass). Load first / in spawn mode for hardened apps.",
)

ROOT_DETECTION_BYPASS_TOOL = ToolHookInfo(
    name="root_detection_bypass",
    display_name="Root Detection Bypass",
    session_type=SessionType.JOB_MANAGER,
    categories=[HookCategory.ROOT_DETECTION, HookCategory.BUILD_PROPERTIES],
    native_hooks=[
        "__system_property_get",
    ],
    java_hooks=[
        "java.io.File.exists",
        "java.io.File.<init>",
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start",
        "android.app.ApplicationPackageManager.getPackageInfo",
        "android.os.Build.TAGS",
    ],
    description="Hide su/magisk/busybox paths, block su exec, hide root apps, "
    "release-keys build tags, ro.debuggable/ro.secure spoofing",
    dynamic_hooks=False,
)

DEBUG_DETECTION_BYPASS_TOOL = ToolHookInfo(
    name="debug_detection_bypass",
    display_name="Debug Detection Bypass",
    session_type=SessionType.JOB_MANAGER,
    categories=[HookCategory.DEBUG_DETECTION],
    native_hooks=[
        "read",  # /proc/self/status TracerPid filter (stacks with frida bypass)
    ],
    java_hooks=[
        "android.os.Debug.isDebuggerConnected",
        "android.os.Debug.waitingForDebugger",
    ],
    description="Defeat debugger-attached checks: isDebuggerConnected, "
    "waitingForDebugger, TracerPid filtering",
    dynamic_hooks=False,
)

# ============================================================================
# MALWARE MONITOR (Dexray-Intercept)
# ============================================================================
MALWARE_MONITOR_HOOKS = ToolHookInfo(
    name="malwaremonitor",
    display_name="Malware Monitor (Dexray)",
    session_type=SessionType.OWN_SESSION,  # Uses dexray-intercept's AppProfiler
    categories=[
        HookCategory.FILE_SYSTEM,
        HookCategory.NETWORK,
        HookCategory.CRYPTO,
        HookCategory.PROCESS,
        HookCategory.SQLITE,
        HookCategory.PREFERENCES,
    ],
    native_hooks=[
        # File operations
        "open",
        "read",
        "write",
        "close",
        "unlink",
        "rename",
        # Network
        "connect",
        "send",
        "recv",
        "socket",
    ],
    java_hooks=[
        # File operations
        "java.io.File.<init>",
        "java.io.FileInputStream.<init>",
        "java.io.FileOutputStream.<init>",
        "java.io.File.delete",
        # Network
        "java.net.URL.openConnection",
        "java.net.Socket.<init>",
        "okhttp3.OkHttpClient.newCall",
        # Crypto
        "javax.crypto.Cipher.getInstance",
        "javax.crypto.Cipher.doFinal",
        "java.security.MessageDigest.digest",
        # Process
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start",
        # SQLite
        "android.database.sqlite.SQLiteDatabase.openDatabase",
        "android.database.sqlite.SQLiteDatabase.rawQuery",
        # SharedPreferences
        "android.content.SharedPreferences.getString",
        "android.content.SharedPreferences$Editor.putString",
    ],
    description="Comprehensive malware behavior monitoring",
    dynamic_hooks=True,  # Depends on selected categories
    notes="Uses dexray-intercept's AppProfiler for session management. "
    "Hooks depend on which monitoring categories are enabled.",
)

# ============================================================================
# MalwareMonitor Hook Configuration Mapping
# ============================================================================
# Maps hook_config keys to actual hooks that dexray-intercept installs
MALWARE_MONITOR_HOOK_CONFIG_MAP: dict[str, dict[str, list[str]]] = {
    "aes_hooks": {
        "java": [
            "javax.crypto.Cipher.getInstance",
            "javax.crypto.Cipher.init",
            "javax.crypto.Cipher.doFinal",
            "javax.crypto.spec.SecretKeySpec.<init>",
            "javax.crypto.spec.IvParameterSpec.<init>",
        ],
        "native": [],
    },
    "web_hooks": {
        "java": [
            "java.net.URL.openConnection",
            "java.net.HttpURLConnection.connect",
            "java.net.HttpURLConnection.getInputStream",
            "java.net.HttpURLConnection.getOutputStream",
            "okhttp3.OkHttpClient.newCall",
            "okhttp3.Call.execute",
            "okhttp3.Call.enqueue",
        ],
        "native": [],
    },
    "socket_hooks": {
        "java": [
            "java.net.Socket.<init>",
            "java.net.Socket.connect",
            "java.net.Socket.getInputStream",
            "java.net.Socket.getOutputStream",
            "java.net.ServerSocket.<init>",
            "java.net.ServerSocket.accept",
        ],
        "native": [
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "sendto",
            "recvfrom",
        ],
    },
    "file_system_hooks": {
        "java": [
            "java.io.File.<init>",
            "java.io.File.exists",
            "java.io.File.delete",
            "java.io.File.mkdir",
            "java.io.File.mkdirs",
            "java.io.File.renameTo",
            "java.io.FileInputStream.<init>",
            "java.io.FileOutputStream.<init>",
            "java.io.RandomAccessFile.<init>",
        ],
        "native": [
            "open",
            "openat",
            "read",
            "write",
            "close",
            "unlink",
            "rename",
            "mkdir",
            "rmdir",
            "stat",
            "fstat",
            "lstat",
        ],
    },
    "database_hooks": {
        "java": [
            "android.database.sqlite.SQLiteDatabase.openDatabase",
            "android.database.sqlite.SQLiteDatabase.openOrCreateDatabase",
            "android.database.sqlite.SQLiteDatabase.rawQuery",
            "android.database.sqlite.SQLiteDatabase.execSQL",
            "android.database.sqlite.SQLiteDatabase.insert",
            "android.database.sqlite.SQLiteDatabase.update",
            "android.database.sqlite.SQLiteDatabase.delete",
        ],
        "native": [],
    },
    "dex_unpacking_hooks": {
        "java": [],
        "native": [
            "mmap",
            "mprotect",
            "memcpy",
        ],
    },
    "java_dex_unpacking_hooks": {
        "java": [
            "dalvik.system.DexClassLoader.<init>",
            "dalvik.system.PathClassLoader.<init>",
            "dalvik.system.InMemoryDexClassLoader.<init>",
            "java.lang.ClassLoader.loadClass",
        ],
        "native": [],
    },
}


def get_malwaremonitor_hooks_for_config(
    hook_config: dict[str, bool],
) -> tuple[list[str], list[str]]:
    """Get the actual hooks that will be installed based on MalwareMonitor's hook_config.

    Args:
        hook_config: Dictionary mapping hook category names to enabled status

    Returns:
        Tuple of (native_hooks, java_hooks) that will be active
    """
    native_hooks = []
    java_hooks = []

    for config_key, enabled in hook_config.items():
        if enabled and config_key in MALWARE_MONITOR_HOOK_CONFIG_MAP:
            mapping = MALWARE_MONITOR_HOOK_CONFIG_MAP[config_key]
            native_hooks.extend(mapping.get("native", []))
            java_hooks.extend(mapping.get("java", []))

    # Remove duplicates while preserving order
    native_hooks = list(dict.fromkeys(native_hooks))
    java_hooks = list(dict.fromkeys(java_hooks))

    return native_hooks, java_hooks


# ============================================================================
# Tool Registry
# ============================================================================
KNOWN_TOOLS: dict[str, ToolHookInfo] = {
    "fritap": FRITAP_HOOKS,
    "objection": OBJECTION_HOOKS,
    "trigdroid": TRIGDROID_HOOKS,
    "ssl_unpin": SSL_UNPIN_TOOL,
    "frida_detection_bypass": FRIDA_DETECTION_BYPASS_TOOL,
    "root_detection_bypass": ROOT_DETECTION_BYPASS_TOOL,
    "debug_detection_bypass": DEBUG_DETECTION_BYPASS_TOOL,
    "malwaremonitor": MALWARE_MONITOR_HOOKS,
}


def get_tool_info(tool_name: str) -> ToolHookInfo | None:
    """Get hook information for a tool.

    Args:
        tool_name: Name of the tool (lowercase)

    Returns:
        ToolHookInfo if found, None otherwise
    """
    return KNOWN_TOOLS.get(tool_name.lower())


def get_conflicting_categories(tool1: str, tool2: str) -> list[HookCategory]:
    """Get hook categories that conflict between two tools.

    Args:
        tool1: First tool name
        tool2: Second tool name

    Returns:
        List of conflicting categories
    """
    info1 = get_tool_info(tool1)
    info2 = get_tool_info(tool2)

    if not info1 or not info2:
        return []

    return list(set(info1.categories) & set(info2.categories))


def check_hook_conflicts(tool1: str, tool2: str) -> dict[str, list[str]]:
    """Check for specific hook conflicts between two tools.

    Args:
        tool1: First tool name
        tool2: Second tool name

    Returns:
        Dict with "native" and "java" lists of conflicting hooks
    """
    info1 = get_tool_info(tool1)
    info2 = get_tool_info(tool2)

    if not info1 or not info2:
        return {"native": [], "java": []}

    native_conflicts = list(set(info1.native_hooks) & set(info2.native_hooks))
    java_conflicts = list(set(info1.java_hooks) & set(info2.java_hooks))

    return {
        "native": native_conflicts,
        "java": java_conflicts,
    }


def get_session_conflict_warning(tool_name: str) -> str | None:
    """Get a warning message if the tool creates its own Frida session.

    Args:
        tool_name: Name of the tool

    Returns:
        Warning message if tool has session conflicts, None otherwise
    """
    info = get_tool_info(tool_name)
    if not info:
        return None

    if info.session_type == SessionType.SUBPROCESS:
        return (
            f"{info.display_name} runs as a subprocess and creates its own Frida session. "
            f"Any other Frida tools currently running may experience conflicts or "
            f"unpredictable behavior. Consider stopping other tools first."
        )
    if info.session_type == SessionType.OWN_SESSION:
        return (
            f"{info.display_name} manages its own Frida session. "
            f"If other Frida tools are running, hook conflicts may occur."
        )

    return None


def get_tools_with_category(category: HookCategory) -> list[str]:
    """Get all tools that hook a specific category.

    Args:
        category: The hook category to search for

    Returns:
        List of tool names that use this category
    """
    return [name for name, info in KNOWN_TOOLS.items() if category in info.categories]


def format_conflict_report(running_tools: list[str], new_tool: str) -> str:
    """Generate a human-readable conflict report.

    Args:
        running_tools: List of currently running tool names
        new_tool: Name of the tool about to be started

    Returns:
        Formatted conflict report string
    """
    new_info = get_tool_info(new_tool)
    if not new_info:
        return ""

    lines = [f"Conflict Analysis for {new_info.display_name}:", ""]

    for running in running_tools:
        running_info = get_tool_info(running)
        if not running_info:
            continue

        conflicts = check_hook_conflicts(running, new_tool)
        categories = get_conflicting_categories(running, new_tool)

        if conflicts["native"] or conflicts["java"] or categories:
            lines.append(f"vs {running_info.display_name}:")

            if categories:
                cat_names = [c.value for c in categories]
                lines.append(f"  Overlapping areas: {', '.join(cat_names)}")

            if conflicts["native"]:
                lines.append(
                    f"  Native hook conflicts: {', '.join(conflicts['native'][:5])}"
                )
                if len(conflicts["native"]) > 5:
                    lines.append(f"    ...and {len(conflicts['native']) - 5} more")

            if conflicts["java"]:
                lines.append(
                    f"  Java hook conflicts: {', '.join(conflicts['java'][:5])}"
                )
                if len(conflicts["java"]) > 5:
                    lines.append(f"    ...and {len(conflicts['java']) - 5} more")

            lines.append("")

    # Add session warning
    warning = get_session_conflict_warning(new_tool)
    if warning:
        lines.append("Session Warning:")
        lines.append(f"  {warning}")

    return "\n".join(lines)
