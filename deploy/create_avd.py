#!/usr/bin/env python3
# Cross-platform AVD creator with SDK/AVD autodetect
# Windows 10/11 (x64/ARM64), Linux (x64/ARM64), macOS (Intel/Apple Silicon)

import os
import platform
import re
import shutil
import ssl
import stat
import subprocess  # nosec B404 # Required for Android SDK management
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# Import readline at module level for line editing support
try:
    import readline
except ImportError:
    readline = None


# ============ Defaults (can be overridden by env or user input) ============
DEFAULT_ROOT = os.environ.get("AVD_ROOT", str(Path("~/android_avd").expanduser()))
DEFAULT_API = os.environ.get("AVD_API_LEVEL", "34")
DEFAULT_NAME = os.environ.get("AVD_NAME", f"universal-avd-{DEFAULT_API}-googleapis")
# ==========================================================================


def info(m):
    print(f"[+] {m}")


def warn(m):
    print(f"[!] {m}")


def err(m):
    print(f"[x] {m}")


def is_windows():
    return platform.system().lower().startswith("win")


def is_macos():
    return platform.system().lower() == "darwin"


def is_linux():
    return platform.system().lower() == "linux"


def cpu_arch():
    a = platform.machine().lower()
    if a in ("x86_64", "amd64"):
        return "x86_64"
    if a in ("arm64", "aarch64"):
        return "arm64"
    pa = os.environ.get("PROCESSOR_ARCHITECTURE", "").lower()
    if pa in ("amd64", "x86_64"):
        return "x86_64"
    if pa in ("arm64", "aarch64"):
        return "arm64"
    return a


def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)
    return p


def make_exec(p):
    path = Path(p)
    if path.exists() and not is_windows():
        current_mode = path.stat().st_mode
        path.chmod(current_mode | stat.S_IEXEC)


def run_cmd(
    cmd: list[str], env=None, input_text: str | None = None
) -> tuple[int, str, str]:
    try:
        input_bytes = input_text.encode() if input_text else None
        res = subprocess.run(  # nosec B603 # Controlled subprocess call for SDK tools
            cmd, input=input_bytes, env=env, capture_output=True, check=False
        )
        stdout = res.stdout.decode(errors="replace")
        stderr = res.stderr.decode(errors="replace")
        return res.returncode, stdout, stderr
    except FileNotFoundError:
        return 127, "", f"Executable not found: {cmd[0]}"
    except Exception as e:
        return 1, "", f"{e.__class__.__name__}: {e}"


def ask_yes_no(q: str, default_yes=True) -> bool:
    default = "Y/n" if default_yes else "y/N"
    try:
        a = input(f"{q} [{default}]: ").strip().lower()
    except EOFError:
        return default_yes
    if not a:
        return default_yes
    return a in ("y", "yes")


def ask_str(prompt_text: str, default_val: str) -> str:
    try:
        v = input(f"{prompt_text} [{default_val}]: ").strip()
        return v if v else default_val
    except EOFError:
        return default_val


def ascii_only(s: str) -> bool:
    try:
        return s.isascii()
    except Exception:
        try:
            s.encode("ascii")
            return True
        except UnicodeEncodeError:
            return False


def sanitize_name(n: str) -> str:
    n = "".join(ch if re.match(r"[A-Za-z0-9_\-]", ch) else "-" for ch in n)
    return n.strip(" .")


def best_download(url: str, dest: str) -> bool:
    # urllib with certifi or default
    try:
        try:
            import certifi

            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, context=ctx) as r, open(dest, "wb") as f:  # nosec B310 # Legitimate Android SDK download
            shutil.copyfileobj(r, f)
        return True
    except Exception:  # nosec B110 # Optional download fallback is acceptable
        pass
    # curl
    if shutil.which("curl") and (
        subprocess.call(["curl", "-L", "-o", dest, url]) == 0  # nosec B603 # nosec B607
        and os.path.exists(dest)
        and os.path.getsize(dest) > 0
    ):
        return True
    # powershell
    if is_windows():
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if (
            ps
            and subprocess.call(  # nosec B603 # System PowerShell is validated
                [
                    ps,
                    "-NoProfile",
                    "-Command",
                    f"Invoke-WebRequest -Uri '{url}' -OutFile '{dest}' -UseBasicParsing",
                ]
            )
            == 0
        ):
            return os.path.exists(dest) and os.path.getsize(dest) > 0
    return False


# --------- Detect existing SDK & AVD locations ----------
def looks_like_sdk(path: str) -> bool:
    """Check if the given path looks like a valid Android SDK root."""
    if not os.path.isdir(path):
        return False
    critical = ["platform-tools", "cmdline-tools"]
    return any(os.path.isdir(os.path.join(path, c)) for c in critical)


def find_existing_sdk() -> str | None:
    """Try to detect the Android SDK root from environment vars, known locations,
    and fallback strategies. Must contain cmdline-tools or platform-tools.
    """
    # 1. Check env vars first
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        sdk = os.environ.get(var)
        if sdk and looks_like_sdk(sdk):
            return sdk

    # 2. Check common defaults per OS
    candidates = []
    if is_macos():
        candidates += [
            os.path.expanduser("~/Library/Android/sdk"),
            os.path.expanduser("~/Library/Android"),
        ]
    elif is_linux():
        candidates += [
            os.path.expanduser("~/Android/Sdk"),
            os.path.expanduser("~/Android/sdk"),
            os.path.expanduser("~/android-sdk"),
        ]
    elif is_windows():
        candidates += [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
            os.path.join(os.environ.get("APPDATA", ""), "Android", "Sdk"),
        ]

    # 3. Check sdkmanager on PATH
    sm = shutil.which("sdkmanager") or shutil.which("sdkmanager.bat")
    if sm:
        possible_sdk = os.path.abspath(os.path.join(os.path.dirname(sm), "..", ".."))
        if looks_like_sdk(possible_sdk):
            return possible_sdk

    # 4. Validate candidates
    for c in candidates:
        if looks_like_sdk(c):
            return c
        # Check if <c>/sdk exists instead (common on macOS)
        sub = os.path.join(c, "sdk")
        if looks_like_sdk(sub):
            return sub

    return None


def find_existing_avd_home() -> str | None:
    p = os.environ.get("ANDROID_AVD_HOME")
    if p and os.path.isdir(p):
        return p
    default = os.path.expanduser("~/.android/avd")
    if os.path.isdir(default):
        return default
    return None


def normalize_sdk_root(sdk_root: str) -> str:
    """Auto-correct if user provided parent folder but real SDK is in <root>/sdk."""
    root = os.path.abspath(sdk_root)
    sdk_subdir = os.path.join(root, "sdk")
    if looks_like_sdk(sdk_subdir) and not looks_like_sdk(root):
        warn(f"SDK detected under '{sdk_subdir}', adjusting path.")
        return sdk_subdir
    return root


# --------- Begin interactive setup ----------
print("=== AVD Setup (auto-detect SDK/AVD) ===\n")

detected_sdk = find_existing_sdk()
if detected_sdk:
    use = ask_yes_no(
        f"Detected existing Android SDK at '{detected_sdk}'. Use this SDK?",
        default_yes=True,
    )
    SDK_ROOT = (
        detected_sdk
        if use
        else ask_str("Enter SDK install directory", os.path.join(DEFAULT_ROOT, "sdk"))
    )
else:
    info("No existing Android SDK detected.")
    if ask_yes_no("Install a fresh SDK with commandline-tools now?", default_yes=True):
        SDK_ROOT = ask_str(
            "Enter SDK install directory", os.path.join(DEFAULT_ROOT, "sdk")
        )
    else:
        err("Cannot proceed without an SDK.")
        sys.exit(2)

detected_avd = find_existing_avd_home()
if detected_avd:
    use_avd = ask_yes_no(
        f"Detected AVD home at '{detected_avd}'. Use this AVD directory?",
        default_yes=True,
    )
    ANDROID_AVD_HOME = (
        detected_avd
        if use_avd
        else ask_str("Enter AVD directory", os.path.join(DEFAULT_ROOT, "avd"))
    )
else:
    info("No existing AVD home detected.")
    ANDROID_AVD_HOME = ask_str("Enter AVD directory", os.path.join(DEFAULT_ROOT, "avd"))

api_level = ask_str("API level to install", DEFAULT_API).strip()
if not api_level.isdigit():
    warn(f"API level '{api_level}' is not numeric. Falling back to {DEFAULT_API}.")
    api_level = DEFAULT_API
try:
    api_i = int(api_level)
    if api_i < 23 or api_i > 35:
        warn(f"API level {api_i} may be unavailable; proceeding anyway.")
except Exception:
    api_level = DEFAULT_API

avd_name = ask_str("Default AVD name (press Enter to accept)", DEFAULT_NAME)
if not ascii_only(avd_name):
    warn("AVD name contains non-ASCII characters; sanitizing.")
    avd_name = sanitize_name(avd_name)
if not avd_name:
    warn("AVD name empty after sanitization; using fallback.")
    avd_name = f"universal-avd-{api_level}-googleapis"

# --------- Normalize and prepare paths ----------
SDK_ROOT = normalize_sdk_root(SDK_ROOT)
CMDLINE_DIR = os.path.join(SDK_ROOT, "cmdline-tools")
LATEST_DIR = os.path.join(CMDLINE_DIR, "latest")
TOOLS_BIN = os.path.join(LATEST_DIR, "bin")
SDKMANAGER = os.path.join(TOOLS_BIN, "sdkmanager" + (".bat" if is_windows() else ""))
AVDMANAGER = os.path.join(TOOLS_BIN, "avdmanager" + (".bat" if is_windows() else ""))
EMULATOR_CANDIDATES = [
    os.path.join(SDK_ROOT, "emulator", "emulator" + (".exe" if is_windows() else "")),
    os.path.join(
        os.path.dirname(SDK_ROOT),
        "emulator",
        "emulator" + (".exe" if is_windows() else ""),
    ),  # parent/emulator
]
EMULATOR_BIN = None  # we will resolve later once installed/verified

ensure_dir(SDK_ROOT)
ensure_dir(CMDLINE_DIR)
ensure_dir(ANDROID_AVD_HOME)

# --------- cmdline-tools URL ----------
if is_windows():
    zip_name = "commandlinetools-win-10406996_latest.zip"
elif is_macos():
    zip_name = "commandlinetools-mac-10406996_latest.zip"
elif is_linux():
    zip_name = "commandlinetools-linux-10406996_latest.zip"
else:
    err(f"Unsupported OS: {platform.system()}")
    sys.exit(1)
cmdline_tools_url = f"https://dl.google.com/android/repository/{zip_name}"


def repair_cmdline_layout():
    # Merge latest-* into latest
    if os.path.isdir(CMDLINE_DIR):
        for entry in os.listdir(CMDLINE_DIR):
            if entry.startswith("latest-"):
                src = os.path.join(CMDLINE_DIR, entry)
                if os.path.isdir(src):
                    ensure_dir(LATEST_DIR)
                    for name in os.listdir(src):
                        s = os.path.join(src, name)
                        d = os.path.join(LATEST_DIR, name)
                        if os.path.isdir(s):
                            shutil.copytree(s, d, dirs_exist_ok=True)
                        else:
                            ensure_dir(os.path.dirname(d))
                            shutil.copy2(s, d)
                    shutil.rmtree(src, ignore_errors=True)
    for exe in ("sdkmanager", "avdmanager"):
        p = os.path.join(TOOLS_BIN, exe + (".bat" if is_windows() else ""))
        if os.path.exists(p):
            make_exec(p)


def ensure_cmdline_tools() -> bool:
    if os.path.exists(SDKMANAGER):
        repair_cmdline_layout()
        return True
    info(f"Installing Android commandline-tools into: {LATEST_DIR}")
    with tempfile.TemporaryDirectory() as td:
        zpath = os.path.join(td, zip_name)
        info(f"Downloading:\n  {cmdline_tools_url}")
        if not best_download(cmdline_tools_url, zpath):
            err("Download failed for commandline-tools.")
            if is_macos():
                print("\nmacOS trust-store tip (python.org installs):")
                print("  open '/Applications/Python 3.*/*Install Certificates.command'")
            return False
        info("Unpacking commandline-tools...")
        try:
            with zipfile.ZipFile(zpath, "r") as zf:
                zf.extractall(td)
        except zipfile.BadZipFile:
            err("Downloaded zip is corrupt.")
            return False
        # locate folder containing bin/sdkmanager
        candidate = None
        for root, _dirs, files in os.walk(td):
            if ("sdkmanager" in files) or ("sdkmanager.bat" in files):
                candidate = (
                    os.path.dirname(root) if os.path.basename(root) == "bin" else root
                )
                break
        if candidate is None:
            candidate = os.path.join(td, "cmdline-tools")
        ensure_dir(LATEST_DIR)
        # clean stale content
        for name in os.listdir(LATEST_DIR):
            p = os.path.join(LATEST_DIR, name)
            if os.path.isfile(p):
                os.remove(p)
            else:
                shutil.rmtree(p, ignore_errors=True)
        # copy into latest/
        for name in os.listdir(candidate):
            s = os.path.join(candidate, name)
            d = os.path.join(LATEST_DIR, name)
            if os.path.isdir(s):
                shutil.copytree(s, d, dirs_exist_ok=True)
            else:
                shutil.copy2(s, d)
    repair_cmdline_layout()
    return os.path.exists(SDKMANAGER)


# --------- Ensure tools available ----------
if not ensure_cmdline_tools():
    sys.exit(2)

# --------- Tool environment ----------
env = os.environ.copy()
env["ANDROID_SDK_ROOT"] = SDK_ROOT
env["ANDROID_HOME"] = SDK_ROOT
env["ANDROID_AVD_HOME"] = ANDROID_AVD_HOME
env["PATH"] = TOOLS_BIN + os.pathsep + env.get("PATH", "")
if env.get("JAVA_HOME"):
    env["PATH"] = os.path.join(env["JAVA_HOME"], "bin") + os.pathsep + env["PATH"]

# --------- Licenses (quiet) ----------
info("Accepting Android SDK licenses (quiet)...")
code, out, err_ = run_cmd(
    [SDKMANAGER, "--sdk_root=" + SDK_ROOT, "--licenses"],
    env=env,
    input_text=("y\n" * 30),
)
if code != 0:
    # Not fatal; continue and retry if needed during package install
    warn("License acceptance had issues; continuing.")

# --------- Install base packages ----------
sys_img_suffix = "arm64-v8a" if cpu_arch() == "arm64" else "x86_64"
base_pkgs = ["emulator", "platform-tools", f"platforms;android-{api_level}"]
# NOTE: we do NOT add 'cmdline-tools;latest' again to avoid latest-2 duplication

info("Installing base packages (quiet)...")
code, out, err_ = run_cmd([SDKMANAGER, "--sdk_root=" + SDK_ROOT, *base_pkgs], env=env)
if code != 0:
    if "Accept? (y/N)" in (out + err_):
        warn("Re-running license acceptance and retrying package install...")
        run_cmd(
            [SDKMANAGER, "--sdk_root=" + SDK_ROOT, "--licenses"],
            env=env,
            input_text=("y\n" * 30),
        )
        code, out, err_ = run_cmd(
            [SDKMANAGER, "--sdk_root=" + SDK_ROOT, *base_pkgs], env=env
        )
    if code != 0:
        print((out or err_).strip())
        err("Failed to install base packages.")
        sys.exit(3)

# Repair any latest-2 created by sdkmanager
repair_cmdline_layout()

# --------- Resolve EMULATOR_BIN now that emulator pkg is installed ----------
for cand in EMULATOR_CANDIDATES:
    if os.path.isfile(cand):
        EMULATOR_BIN = cand
        break
if not EMULATOR_BIN:
    # As a last resort, search a few typical spots under SDK_ROOT
    possible = []
    for root, _dirs, files in os.walk(SDK_ROOT):
        if "emulator" in files:
            EMULATOR_BIN = os.path.join(root, "emulator")
            break
        if "emulator.exe" in files:
            EMULATOR_BIN = os.path.join(root, "emulator.exe")
            break
    if not EMULATOR_BIN:
        # Ask the user to locate it
        warn("Unable to locate the emulator binary automatically.")
        manual = ask_str(
            "Please enter the full path to the emulator binary",
            os.path.join(
                SDK_ROOT, "emulator", "emulator" + (".exe" if is_windows() else "")
            ),
        )
        if not os.path.isfile(manual):
            err(f"Emulator binary not found at '{manual}'. Aborting.")
            sys.exit(3)
        EMULATOR_BIN = manual

make_exec(EMULATOR_BIN)

# --------- Install a system image ----------
sys_img_candidates = [
    f"system-images;android-{api_level};google_apis;{sys_img_suffix}",
    f"system-images;android-{api_level};google_apis_playstore;{sys_img_suffix}",
    f"system-images;android-{api_level};aosp_atd;{sys_img_suffix}",
]
chosen_img = None
for pkg in sys_img_candidates:
    info(f"Ensuring system image: {pkg}")
    c, o, e = run_cmd([SDKMANAGER, "--sdk_root=" + SDK_ROOT, pkg], env=env)
    if c == 0:
        chosen_img = pkg
        break
    warn(f"Could not install {pkg}. Trying next...")
if not chosen_img:
    err("No suitable system image could be installed. Try a different API level.")
    sys.exit(4)


# --------- Device profile selection ----------
def list_device_ids() -> list[str]:
    c, o, e = run_cmd([AVDMANAGER, "list", "device"], env=env)
    if c != 0:
        return []
    return re.findall(r'id:\s*\d+\s+or\s+"([^"]+)"', o)


devices = list_device_ids()
preferred = [
    "pixel_8",
    "pixel_7",
    "pixel_7_pro",
    "pixel_6",
    "pixel_6_pro",
    "pixel_6a",
    "pixel_5",
    "pixel_4",
    "pixel_4_xl",
    "pixel",
    "Nexus 5X",
]
device_def = next(
    (d for d in preferred if d in devices), devices[0] if devices else None
)

# --------- Create (or re-create) AVD ----------
ini_path = os.path.join(ANDROID_AVD_HOME, f"{avd_name}.ini")
avd_dir = os.path.join(ANDROID_AVD_HOME, f"{avd_name}.avd")

# Double-check AVD home exists and is writable; if not, ask for a different path
try:
    ensure_dir(ANDROID_AVD_HOME)
    testfile = os.path.join(ANDROID_AVD_HOME, ".write_test")
    with open(testfile, "w") as f:
        f.write("ok")
    os.remove(testfile)
except Exception as e:
    warn(f"AVD home '{ANDROID_AVD_HOME}' not writable: {e}")
    ANDROID_AVD_HOME = ask_str(
        "Enter a writable AVD directory", os.path.join(DEFAULT_ROOT, "avd")
    )
    env["ANDROID_AVD_HOME"] = ANDROID_AVD_HOME
    ensure_dir(ANDROID_AVD_HOME)

# If already exists, ask user what to do
if os.path.exists(ini_path) or os.path.isdir(avd_dir):
    if ask_yes_no(
        f"AVD '{avd_name}' already exists in '{ANDROID_AVD_HOME}'. Recreate it?",
        default_yes=True,
    ):
        run_cmd([AVDMANAGER, "delete", "avd", "--name", avd_name], env=env)
    else:
        info("Keeping existing AVD and skipping creation.")
        device_def = None

if not (os.path.exists(ini_path) and os.path.isdir(avd_dir)):
    info(
        f"Creating AVD '{avd_name}' using image '{chosen_img}'"
        + (f" and device '{device_def}'" if device_def else "")
    )
    args = [
        AVDMANAGER,
        "create",
        "avd",
        "--name",
        avd_name,
        "--package",
        chosen_img,
        "--sdcard",
        "2048M",
    ]
    if device_def:
        args += ["--device", device_def]
    c, o, e = run_cmd(
        args, env=env, input_text="no\n"
    )  # "no" to custom hardware profile
    if c != 0 and device_def and "No device found matching --device" in (o + e):
        warn(f"Device '{device_def}' not available. Retrying without --device...")
        args = [
            AVDMANAGER,
            "create",
            "avd",
            "--name",
            avd_name,
            "--package",
            chosen_img,
            "--sdcard",
            "2048M",
        ]
        c, o, e = run_cmd(args, env=env, input_text="no\n")
    if c != 0:
        print((o or e).strip())
        err("Failed to create the AVD.")
        sys.exit(5)

# --------- Final summary & ready-to-run command with correct env ---------
print("\n====================================")
print("✅ AVD ready!")
print("SDK:")
print(f"  ANDROID_SDK_ROOT: {SDK_ROOT}")
print("AVD:")
print(f"  ANDROID_AVD_HOME: {ANDROID_AVD_HOME}")
print(f"  AVD name:         {avd_name}")
print(f"  API level:        {api_level}")
print("====================================\n")


# Print an env-inlined launcher so it works even if user env lacks these vars:
def quote(s: str) -> str:
    if " " in s or "(" in s or ")" in s:
        return f'"{s}"'
    return s


if is_windows():
    launcher_cmd = f"set ANDROID_SDK_ROOT={SDK_ROOT}&& set ANDROID_HOME={SDK_ROOT}&& set ANDROID_AVD_HOME={ANDROID_AVD_HOME}&& {quote(EMULATOR_BIN)} -avd {avd_name}"
    headless_cmd = launcher_cmd + " -no-window -no-boot-anim -gpu swiftshader_indirect"
else:
    launcher_cmd = f"ANDROID_SDK_ROOT={quote(SDK_ROOT)} ANDROID_HOME={quote(SDK_ROOT)} ANDROID_AVD_HOME={quote(ANDROID_AVD_HOME)} {quote(EMULATOR_BIN)} -avd {quote(avd_name)}"
    headless_cmd = launcher_cmd + " -no-window -no-boot-anim -gpu swiftshader_indirect"

print("Start it (windowed):")
print(f"  {launcher_cmd}")
print("\nStart it (headless / CI):")
print(f"  {headless_cmd}")

print("\nCheck with ADB:")
print("  adb devices")

if is_macos():
    print("\nmacOS trust-store tip (if downloads ever fail):")
    print("  open '/Applications/Python 3.*/*Install Certificates.command'")
