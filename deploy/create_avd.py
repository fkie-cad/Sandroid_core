#!/usr/bin/env python3
# Cross-platform AVD creator with SDK/AVD autodetect
# Windows 10/11 (x64/ARM64), Linux (x64/ARM64), macOS (Intel/Apple Silicon)

import os, sys, platform, shutil, subprocess, zipfile, tempfile, urllib.request, ssl, stat, re
from typing import List, Tuple, Optional

# ============ Defaults (can be overridden by env or user choice during prompts) ============
DEFAULT_ROOT = os.environ.get("AVD_ROOT", os.path.expanduser("~/android_avd"))
DEFAULT_API  = os.environ.get("AVD_API_LEVEL", "34")
DEFAULT_NAME = os.environ.get("AVD_NAME", f"universal-avd-{DEFAULT_API}-googleapis")
# ==========================================================================================

def info(m): print(f"[+] {m}")
def warn(m): print(f"[!] {m}")
def err(m):  print(f"[x] {m}")

def is_windows(): return platform.system().lower().startswith("win")
def is_macos():   return platform.system().lower() == "darwin"
def is_linux():   return platform.system().lower() == "linux"

def cpu_arch():
    a = platform.machine().lower()
    if a in ("x86_64","amd64"): return "x86_64"
    if a in ("arm64","aarch64"): return "arm64"
    pa = os.environ.get("PROCESSOR_ARCHITECTURE","").lower()
    if pa in ("amd64","x86_64"): return "x86_64"
    if pa in ("arm64","aarch64"): return "arm64"
    return a

def ensure_dir(p): os.makedirs(p, exist_ok=True); return p
def make_exec(p):
    if os.path.exists(p) and not is_windows():
        st = os.stat(p); os.chmod(p, st.st_mode | stat.S_IEXEC)

def run_cmd(cmd: List[str], env=None, input_text: Optional[str]=None) -> Tuple[int,str,str]:
    try:
        res = subprocess.run(cmd, input=(input_text.encode() if input_text else None),
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return res.returncode, res.stdout.decode(errors="replace"), res.stderr.decode(errors="replace")
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
    if not a: return default_yes
    return a in ("y","yes")

def ask_str(prompt_text: str, default_val: str) -> str:
    try:
        v = input(f"{prompt_text} [{default_val}]: ").strip()
        return v if v else default_val
    except EOFError:
        return default_val

def ascii_only(s: str) -> bool:
    try: return s.isascii()
    except Exception:
        try: s.encode("ascii"); return True
        except UnicodeEncodeError: return False

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
        with urllib.request.urlopen(url, context=ctx) as r, open(dest,"wb") as f:
            shutil.copyfileobj(r,f)
        return True
    except Exception:
        pass
    # curl
    if shutil.which("curl"):
        if subprocess.call(["curl","-L","-o",dest,url]) == 0 and os.path.exists(dest) and os.path.getsize(dest)>0:
            return True
    # powershell
    if is_windows():
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps and subprocess.call([ps,"-NoProfile","-Command",
                                   f"Invoke-WebRequest -Uri '{url}' -OutFile '{dest}' -UseBasicParsing"]) == 0:
            return os.path.exists(dest) and os.path.getsize(dest)>0
    return False

# --------- Detect existing SDK & AVD locations ----------
def find_existing_sdk() -> Optional[str]:
    # 1) env
    for k in ("ANDROID_SDK_ROOT","ANDROID_HOME"):
        p = os.environ.get(k)
        if p and os.path.isdir(p): return p
    # 2) common defaults
    candidates = []
    if is_macos():
        candidates += [os.path.expanduser("~/Library/Android/sdk")]
    if is_linux():
        candidates += [os.path.expanduser("~/Android/Sdk"), os.path.expanduser("~/Android/sdk"), os.path.expanduser("~/android-sdk")]
    if is_windows():
        candidates += [
            os.path.join(os.environ.get("LOCALAPPDATA",""), "Android","Sdk"),
            os.path.join(os.environ.get("APPDATA",""), "Android","Sdk"),
        ]
    # 3) sdkmanager on PATH
    sm = shutil.which("sdkmanager") or shutil.which("sdkmanager.bat")
    if sm:
        # resolve .../cmdline-tools/latest/bin/sdkmanager -> SDK root is a few dirs up
        p = os.path.abspath(sm)
        # expected: <sdk>/cmdline-tools/latest/bin/sdkmanager
        parts = p.replace("\\","/").split("/")
        try:
            i = parts.index("cmdline-tools")
            sdk_root = "/".join(parts[:i])
            if os.path.isdir(sdk_root): return sdk_root
        except ValueError:
            pass
        # else, try up-three
        sdk_root = os.path.abspath(os.path.join(os.path.dirname(p), "..","..",".."))
        if os.path.isdir(sdk_root): return sdk_root
    for c in candidates:
        if c and os.path.isdir(c): return c
    return None

def find_existing_avd_home() -> Optional[str]:
    # 1) env
    p = os.environ.get("ANDROID_AVD_HOME")
    if p and os.path.isdir(p): return p
    # 2) default
    default = os.path.expanduser("~/.android/avd")
    if os.path.isdir(default): return default
    return None

# --------- Begin interactive setup ----------
print("=== AVD Setup (auto-detect SDK/AVD) ===\n")

# Detect SDK
detected_sdk = find_existing_sdk()
if detected_sdk:
    use = ask_yes_no(f"Detected existing Android SDK at '{detected_sdk}'. Use this SDK?", default_yes=True)
    if use:
        SDK_ROOT = detected_sdk
    else:
        SDK_ROOT = ask_str("Enter SDK install directory", os.path.join(DEFAULT_ROOT, "sdk"))
else:
    info("No existing Android SDK detected.")
    if ask_yes_no("Install a fresh SDK with commandline-tools now?", default_yes=True):
        SDK_ROOT = ask_str("Enter SDK install directory", os.path.join(DEFAULT_ROOT, "sdk"))
    else:
        err("Cannot proceed without an SDK."); sys.exit(2)

# Detect AVD home
detected_avd = find_existing_avd_home()
if detected_avd:
    use_avd = ask_yes_no(f"Detected AVD home at '{detected_avd}'. Use this AVD directory?", default_yes=True)
    if use_avd:
        ANDROID_AVD_HOME = detected_avd
    else:
        ANDROID_AVD_HOME = ask_str("Enter AVD directory", os.path.join(DEFAULT_ROOT, "avd"))
else:
    info("No existing AVD home detected.")
    ANDROID_AVD_HOME = ask_str("Enter AVD directory", os.path.join(DEFAULT_ROOT, "avd"))

# Ask API/Name
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

default_name = ask_str("Default AVD name (press Enter to accept)", DEFAULT_NAME)
avd_name = default_name
if not ascii_only(avd_name):
    warn("AVD name contains non-ASCII characters; sanitizing.")
    avd_name = sanitize_name(avd_name)
if not avd_name:
    warn("AVD name empty after sanitization; using fallback.")
    avd_name = f"universal-avd-{api_level}-googleapis"

# --------- Paths & constants ----------
CMDLINE_DIR = os.path.join(SDK_ROOT, "cmdline-tools")
LATEST_DIR  = os.path.join(CMDLINE_DIR, "latest")
TOOLS_BIN   = os.path.join(LATEST_DIR, "bin")
SDKMANAGER  = os.path.join(TOOLS_BIN, "sdkmanager" + (".bat" if is_windows() else ""))
AVDMANAGER  = os.path.join(TOOLS_BIN, "avdmanager" + (".bat" if is_windows() else ""))
EMULATOR_BIN = os.path.join(SDK_ROOT, "emulator", "emulator" + (".exe" if is_windows() else ""))

ensure_dir(SDK_ROOT); ensure_dir(CMDLINE_DIR); ensure_dir(ANDROID_AVD_HOME)

# --------- Platform-specific cmdline-tools URL ----------
arch = cpu_arch()
if is_windows(): zip_name = "commandlinetools-win-10406996_latest.zip"
elif is_macos(): zip_name = "commandlinetools-mac-10406996_latest.zip"
elif is_linux(): zip_name = "commandlinetools-linux-10406996_latest.zip"
else:
    err(f"Unsupported OS: {platform.system()}"); sys.exit(1)
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
                        s = os.path.join(src, name); d = os.path.join(LATEST_DIR, name)
                        if os.path.isdir(s): shutil.copytree(s, d, dirs_exist_ok=True)
                        else:
                            ensure_dir(os.path.dirname(d)); shutil.copy2(s, d)
                    shutil.rmtree(src, ignore_errors=True)
    for exe in ("sdkmanager","avdmanager"):
        p = os.path.join(TOOLS_BIN, exe + (".bat" if is_windows() else ""))
        if os.path.exists(p): make_exec(p)

def ensure_cmdline_tools() -> bool:
    if os.path.exists(SDKMANAGER):
        repair_cmdline_layout(); return True
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
            with zipfile.ZipFile(zpath,"r") as zf: zf.extractall(td)
        except zipfile.BadZipFile:
            err("Downloaded zip is corrupt."); return False
        # locate folder containing bin/sdkmanager
        candidate = None
        for root, dirs, files in os.walk(td):
            if ("sdkmanager" in files) or ("sdkmanager.bat" in files):
                candidate = os.path.dirname(root) if os.path.basename(root)=="bin" else root
                break
        if candidate is None:
            candidate = os.path.join(td, "cmdline-tools")
        ensure_dir(LATEST_DIR)
        # clean stale content
        for name in os.listdir(LATEST_DIR):
            p = os.path.join(LATEST_DIR, name)
            if os.path.isfile(p): os.remove(p)
            else: shutil.rmtree(p, ignore_errors=True)
        # copy into latest/
        for name in os.listdir(candidate):
            s = os.path.join(candidate, name); d = os.path.join(LATEST_DIR, name)
            if os.path.isdir(s): shutil.copytree(s, d, dirs_exist_ok=True)
            else: shutil.copy2(s, d)
    repair_cmdline_layout()
    return os.path.exists(SDKMANAGER)

if not ensure_cmdline_tools():
    sys.exit(2)

# --------- Tool environment ----------
env = os.environ.copy()
env["ANDROID_SDK_ROOT"] = SDK_ROOT
env["ANDROID_HOME"]     = SDK_ROOT
env["ANDROID_AVD_HOME"] = ANDROID_AVD_HOME
env["PATH"] = TOOLS_BIN + os.pathsep + env.get("PATH","")
if env.get("JAVA_HOME"):
    env["PATH"] = os.path.join(env["JAVA_HOME"],"bin") + os.pathsep + env["PATH"]

# --------- Licenses (quiet) ----------
info("Accepting Android SDK licenses (quiet)...")
code, out, err_ = run_cmd([SDKMANAGER, "--sdk_root="+SDK_ROOT, "--licenses"], env=env, input_text=("y\n"*30))
if code != 0:
    warn("License acceptance had issues; continuing.")

# --------- Install base packages ----------
sys_img_suffix = "arm64-v8a" if cpu_arch()=="arm64" else "x86_64"
base_pkgs = ["emulator", "platform-tools", f"platforms;android-{api_level}"]
# Only add cmdline-tools;latest if sdkmanager was missing at first (avoid latest-2)
if not os.path.exists(SDKMANAGER):
    base_pkgs.insert(0, "cmdline-tools;latest")

info("Installing base packages (quiet)...")
code, out, err_ = run_cmd([SDKMANAGER, "--sdk_root="+SDK_ROOT, *base_pkgs], env=env)
if code != 0:
    if "Accept? (y/N)" in (out+err_):
        warn("Re-running license acceptance and retrying package install...")
        run_cmd([SDKMANAGER, "--sdk_root="+SDK_ROOT, "--licenses"], env=env, input_text=("y\n"*30))
        code, out, err_ = run_cmd([SDKMANAGER, "--sdk_root="+SDK_ROOT, *base_pkgs], env=env)
    if code != 0:
        print((out or err_).strip()); err("Failed to install base packages."); sys.exit(3)

# repair any latest-2 created by sdkmanager
repair_cmdline_layout()

# --------- Install a system image ----------
sys_img_candidates = [
    f"system-images;android-{api_level};google_apis;{sys_img_suffix}",
    f"system-images;android-{api_level};google_apis_playstore;{sys_img_suffix}",
    f"system-images;android-{api_level};aosp_atd;{sys_img_suffix}",
]
chosen_img = None
for pkg in sys_img_candidates:
    info(f"Ensuring system image: {pkg}")
    c,o,e = run_cmd([SDKMANAGER, "--sdk_root="+SDK_ROOT, pkg], env=env)
    if c == 0:
        chosen_img = pkg; break
    warn(f"Could not install {pkg}. Trying next...")
if not chosen_img:
    err("No suitable system image could be installed. Try a different API level."); sys.exit(4)

# --------- Device profile selection ----------
def list_device_ids() -> List[str]:
    c,o,e = run_cmd([AVDMANAGER,"list","device"], env=env)
    if c!=0: return []
    return re.findall(r'id:\s*\d+\s+or\s+"([^"]+)"', o)

devices = list_device_ids()
preferred = ["pixel_8","pixel_7","pixel_7_pro","pixel_6","pixel_6_pro","pixel_6a","pixel_5","pixel_4","pixel_4_xl","pixel","Nexus 5X"]
device_def = next((d for d in preferred if d in devices), devices[0] if devices else None)

# --------- Create (or re-create) AVD ----------
ini_path = os.path.join(ANDROID_AVD_HOME, f"{avd_name}.ini")
avd_dir  = os.path.join(ANDROID_AVD_HOME, f"{avd_name}.avd")
if os.path.exists(ini_path) or os.path.exists(avd_dir):
    if ask_yes_no(f"AVD '{avd_name}' already exists in '{ANDROID_AVD_HOME}'. Recreate it?", default_yes=True):
        run_cmd([AVDMANAGER,"delete","avd","--name",avd_name], env=env)
    else:
        info("Keeping existing AVD and skipping creation.")
        device_def = None  # avoid passing an invalid device to creation below

if not (os.path.exists(ini_path) and os.path.isdir(avd_dir)):
    info(f"Creating AVD '{avd_name}' using image '{chosen_img}'" + (f" and device '{device_def}'" if device_def else ""))
    args = [AVDMANAGER,"create","avd","--name",avd_name,"--package",chosen_img,"--sdcard","2048M"]
    if device_def: args += ["--device", device_def]
    c,o,e = run_cmd(args, env=env, input_text="no\n")  # "no" to custom hardware profile
    if c!=0 and device_def and "No device found matching --device" in (o+e):
        warn(f"Device '{device_def}' not available. Retrying without --device...")
        args = [AVDMANAGER,"create","avd","--name",avd_name,"--package",chosen_img,"--sdcard","2048M"]
        c,o,e = run_cmd(args, env=env, input_text="no\n")
    if c!=0:
        print((o or e).strip()); err("Failed to create the AVD."); sys.exit(5)

# Ensure emulator is executable
make_exec(EMULATOR_BIN)

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
launcher_cmd = f'ANDROID_SDK_ROOT="{SDK_ROOT}" ANDROID_HOME="{SDK_ROOT}" ANDROID_AVD_HOME="{ANDROID_AVD_HOME}" "{EMULATOR_BIN}" -avd "{avd_name}"'
if is_windows():
    launcher_cmd = f'set ANDROID_SDK_ROOT={SDK_ROOT}&& set ANDROID_HOME={SDK_ROOT}&& set ANDROID_AVD_HOME={ANDROID_AVD_HOME}&& "{EMULATOR_BIN}" -avd {avd_name}'

print("Start it (windowed):")
print(f"  {launcher_cmd}")
print("\nStart it (headless / CI):")
if is_windows():
    print(f"  {launcher_cmd} -no-window -no-boot-anim -gpu swiftshader_indirect")
else:
    print(f"  {launcher_cmd} -no-window -no-boot-anim -gpu swiftshader_indirect")

print("\nCheck with ADB:")
print("  adb devices")

if is_macos():
    print("\nmacOS trust-store tip (if downloads ever fail):")
    print("  open '/Applications/Python 3.*/*Install Certificates.command'")

print("\n")
print(f"export ANDROID_SDK_ROOT={SDK_ROOT}")
print(f"export ANDROID_HOME={SDK_ROOT}")
print(f"export ANDROID_AVD_HOME={ANDROID_AVD_HOME}")
print("\nHave a nice day :-)")