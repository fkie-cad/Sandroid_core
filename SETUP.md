# Sandroid Setup Guide

This comprehensive guide walks you through setting up Sandroid for forensic analysis of Android Virtual Devices.

## 🚀 Quick Start (Recommended)

### Prerequisites

- **Python 3.12 or 3.13**
- **Internet connection** (for automated Android SDK detection)
- **Linux, macOS, or Windows** (WSL2 recommended for Windows)
- **Android SDK** platform-tools (`adb`) + Android Emulator (Android Studio or command-line tools)
- **A rooted Android emulator with snapshots enabled** -- see [Device Requirements](#-device-requirements) below

### One-Command Setup

```bash
# Install Sandroid from PyPI
pip install sandroid

# Initialize configuration with automatic Android environment setup
sandroid-config init
```

The `sandroid-config init` command now provides:
- 🔍 **Automatic Android SDK detection**
- 📱 **AVD discovery and configuration**
- ⚙️ **Interactive setup** with validation
- 🎯 **Smart path detection** with user overrides
- ✅ **Ready-to-use configuration**

## 📋 Interactive Setup Experience

When you run `sandroid-config init`, here's what happens:

```bash
$ sandroid-config init
🔧 Initializing Sandroid configuration...

🔍 Detecting Android development environment...
✓ Found Android SDK: /Users/user/Android/Sdk
✓ Found ADB: /opt/homebrew/bin/adb
✓ Found Android Emulator: /Users/user/Android/Sdk/emulator/emulator
✓ Found AVD Home: /Users/user/.android/avd
✓ Found 3 AVDs: Pixel_6_Pro_API_31, Test_Device, sandroid_avd

📱 Found 3 existing AVDs
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Index ┃ AVD Name            ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ 1     │ Pixel_6_Pro_API_31  │
│ 2     │ Test_Device         │
│ 3     │ sandroid_avd        │
└───────┴─────────────────────┘

Choose an option:
  1. Pixel_6_Pro_API_31
  2. Test_Device
  3. sandroid_avd
  4. Create new 'sandroid' AVD
  5. Skip AVD configuration

Enter choice [1-5]: 1
✓ Selected AVD: Pixel_6_Pro_API_31

Start AVD 'Pixel_6_Pro_API_31' with UI by default? [Y/n]: Y
Automatically start AVD when Sandroid needs it? [y/N]: n

✅ Configuration created successfully!
📍 Location: ~/.config/sandroid/sandroid.toml
📱 Configured AVD: Pixel_6_Pro_API_31

🚀 Start AVD 'Pixel_6_Pro_API_31' now? [y/N]: y
✓ AVD 'Pixel_6_Pro_API_31' starting in background...

Next steps:
• Use sandroid-config show to view your configuration
• Use sandroid-config avd list to see available AVDs
• Use sandroid-config avd start to start your configured AVD
• Run sandroid to begin Android forensic analysis
```

## 🛠️ Detailed Setup

### 1. System Dependencies (Optional - Usually Auto-Detected)

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip \
    sqlite3-tools \
    cmake \
    build-essential \
    libxml2-dev \
    libxslt-dev

# Android SDK (if not installed via Android Studio)
sudo apt install adb  # Or install Android Studio
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python sqlite cmake

# Android tools (if not installed via Android Studio)
brew install android-platform-tools  # Or install Android Studio
```

#### Windows
```powershell
# Install via Chocolatey (recommended) or manually
choco install python sqlite cmake

# For Android development
choco install androidstudio
# OR manually download Android Studio
```

### 2. Android Development Environment

#### Option A: Automatic Setup (Recommended)
```bash
# Let Sandroid detect and configure Android environment automatically
sandroid-config init

# If detection fails, provide paths manually during setup
```

#### Option B: Manual Android Studio Setup
If automatic detection fails, install Android Studio manually:

1. **Download Android Studio** from https://developer.android.com/studio
2. **Install Android Studio** and launch it
3. **Install SDK components**:
   - Android SDK Platform-Tools (includes ADB)
   - Android Emulator
   - At least one Android system image (API 31+ recommended; the team mainly uses API 34-36)
4. **Create an AVD**:
   - Open Virtual Device Manager in Android Studio
   - Click "Create Device"
   - Choose a device profile (Pixel devices work well)
   - Select a system image (x86_64 for Intel/AMD, arm64 for Apple Silicon) -- see
     [Device Requirements](#-device-requirements) for which image *type* to pick
   - Configure settings and create the AVD

## 📱 Device Requirements

Sandroid needs **root on the device**: it runs `adb root`, pushes and starts
`frida-server`, injects CA certificates into the system trust store, and sets
SELinux to *permissive* (`setenforce 0`) on its own -- you do not need to do
that manually.

### Option 1: Google APIs image (simplest)

Use a **Google APIs** system image (`system-images;android-<api>;google_apis;<abi>`,
*not* `google_apis_playstore`). These are `userdebug`-style builds on which
`adb root` works out of the box:

```bash
sdkmanager "system-images;android-35;google_apis;arm64-v8a"   # or x86_64
avdmanager create avd -n sandroid_api35 -k "system-images;android-35;google_apis;arm64-v8a" -d pixel_6
adb root   # after boot: should print "restarting adbd as root"
```

### Option 2: Google Play image rooted with rootAVD + Magisk (team setup)

If you need the Play Store, use a **Google Play** image and root it with
[rootAVD](https://gitlab.com/newbit/rootAVD), which patches the AVD ramdisk
with Magisk. Production (Play) builds refuse `adb root` ("adbd cannot run as
root in production builds"), so additionally install the **`adb_root` Magisk
module** from the Magisk app and reboot -- afterwards `adbd` runs as root and
Sandroid works exactly as on a Google APIs image. This is how the Sandroid
team's own AVDs are set up.

Verify with:

```bash
adb root && adb shell id    # must report uid=0(root)
```

### Snapshots

The record/play workflow and the Snapshots tab rely on **AVD snapshots**.
Keep snapshots enabled: do **not** start the emulator with `-no-snapshot`. If
you do not want the emulator to overwrite its quick-boot snapshot on exit, use
`-no-snapshot-save`, or start it via `sandroid-config avd start`
(`--boot-mode default|cold|snapshot|wipe`).

### Physical devices

Rooted physical devices work for many features (Frida, spotlight, file
monitoring, proxies), but everything that relies on the emulator is
unavailable: snapshots (and therefore record/play baselines), emulator-console
network capture and `--degrade-network`.

## 📱 AVD Management

Sandroid now includes comprehensive AVD management commands:

### List Available AVDs
```bash
# Show all available Android Virtual Devices
sandroid-config avd list
```

### Start an AVD
```bash
# Start your configured AVD (from sandroid-config init)
sandroid-config avd start

# Start a specific AVD with UI
sandroid-config avd start --avd-name Pixel_6_Pro_API_31

# Start in headless mode (no UI - good for CI/CD)
sandroid-config avd start --headless
```

### Stop Running AVDs
```bash
# Stop all running emulators
sandroid-config avd stop
```

### Create New AVD
```bash
# Create a new AVD (basic - for complex setup use Android Studio)
sandroid-config avd create --name my-avd --api-level 34

# For full AVD creation with system image installation
python deploy/create_avd.py
```

## ⚙️ Configuration Management

### View Current Configuration
```bash
# Show complete configuration with rich formatting
sandroid-config show

# Show configuration in TOML/YAML/JSON format
sandroid-config show --format toml

# Validate your configuration
sandroid-config validate
```

### Manual Configuration Updates
```bash
# Set Android paths manually if needed
sandroid-config set -k emulator.sdk_path -v "/path/to/Android/Sdk"
sandroid-config set -k emulator.adb_path -v "/path/to/adb"
sandroid-config set -k emulator.android_emulator_path -v "/path/to/emulator"

# Configure AVD settings
sandroid-config set -k emulator.selected_avd -v "Pixel_6_Pro_API_31"
sandroid-config set -k emulator.avd_headless -v true
sandroid-config set -k emulator.avd_auto_start -v false

# Set other analysis options
sandroid-config set -k analysis.number_of_runs -v 3
sandroid-config set -k analysis.capture_network -v true
```

### Configuration File Locations
Configuration files named `sandroid.toml` (or `config.toml`; `.yaml`, `.yml` and
`.json` are accepted too) are searched in this order -- run `sandroid-config paths`
to see the exact directories on your system:
1. `./sandroid.toml` (current directory)
2. `~/.config/sandroid/sandroid.toml` (user config, written by `sandroid-config init`)
3. the platform user/site config directory (e.g. `~/Library/Application Support/sandroid/` on macOS)

Supported formats: **TOML (default and recommended)**, YAML, JSON.
`sandroid-config init --format yaml|json` writes the other formats.

### Environment Variables
All configuration can be set via environment variables:
```bash
export SANDROID_LOG_LEVEL="DEBUG"
export SANDROID_EMULATOR__DEVICE_NAME="Pixel_8_Pro_API_34"
export SANDROID_ANALYSIS__NUMBER_OF_RUNS=3
export SANDROID_EMULATOR__AVD_HEADLESS=true
```

## 🚨 Troubleshooting

### Android Environment Issues

**Problem: No Android SDK detected**
```bash
# Solution 1: Install Android Studio and re-run init
sandroid-config init --force

# Solution 2: Set paths manually
sandroid-config set -k emulator.sdk_path -v "/path/to/Android/Sdk"
```

**Problem: ADB not found**
```bash
# Check if ADB is in PATH
which adb  # Linux/macOS
where adb  # Windows

# If not found, install Android SDK or set path manually
sandroid-config set -k emulator.adb_path -v "/path/to/adb"
```

**Problem: No AVDs found**
```bash
# Create AVD using Android Studio or
python deploy/create_avd.py

# Or point to existing AVD directory
sandroid-config set -k emulator.avd_home -v "/path/to/avd"
```

**Problem: AVD won't start**
```bash
# Check AVD exists
sandroid-config avd list

# Try starting manually with debug info
sandroid-config avd start --avd-name YourAVD

# Check emulator path is correct
sandroid-config show
```

### Configuration Issues

**Problem: Configuration validation fails**
```bash
# Check what's wrong
sandroid-config validate

# Reset to defaults
sandroid-config init --force

# View configuration paths
sandroid-config paths
```

### Skip AVD Setup
```bash
# If you want to configure Android environment separately
sandroid-config init --skip-avd-setup
```

## 🔧 Advanced Setup

### Docker Deployment (best effort)

`docker/dockerfile` builds an image that installs Sandroid from `pyproject.toml`;
the emulator keeps running on the host and the container talks to the host's
adb server. Docker is **not tested in CI** -- see the comments at the top of
the Dockerfile and `docs/advanced/docker_deployment.rst`.

```bash
docker build -t sandroid -f docker/dockerfile .
docker run --rm -it --network host -v "$PWD/results:/sandroid/results" sandroid
```

### Custom Android SDK Installation

If you need a completely fresh Android SDK installation:

```bash
# Use the comprehensive AVD creation script
python deploy/create_avd.py

# This script will:
# - Download and install Android SDK
# - Install system images
# - Create optimized AVDs
# - Set up the complete environment
```

### Development Installation

For contributors and developers:

```bash
# Install in development mode (dev tools + optional extras)
pip install -e ".[dev,full]"

# Install pre-commit hooks
pre-commit install

# Run tests (hermetic: tests/conftest.py blocks every adb/emulator/frida call,
# so this is safe with an emulator attached)
pytest

# Build documentation
cd docs && make html
```

## 🚀 Usage Examples

### Basic Malware Analysis

```bash
# Start your configured AVD
sandroid-config avd start

# Run analysis with network monitoring
sandroid --network --screenshot 5 --report

# Or use interactive mode
sandroid
```

### Automated Analysis Pipeline

```bash
# Headless analysis for CI/CD
sandroid-config avd start --headless

# Run comprehensive analysis
sandroid -f malware-analysis.json \
  --network \
  --screenshot 3 \
  --trigdroid com.malware.example \
  --hash \
  --apk \
  --report
```

### Custom Configuration Environment

```bash
# Create environment-specific config
sandroid-config init --output production.toml

# Use specific configuration
sandroid --config production.toml --network
```

## ✅ Verification

After setup, verify everything works:

```bash
# Check configuration
sandroid-config validate

# List available AVDs
sandroid-config avd list

# Test AVD startup
sandroid-config avd start --avd-name YourAVD

# Verify device connectivity
adb devices

# Run Sandroid help
sandroid --help
```

## 📚 Next Steps

- **Read the Documentation**: Check out the full documentation at `docs/`
- **Interactive Mode**: Try `sandroid` and press `?` to see every action and keybinding
- **Ground Truth APK**: Install and test with the included `ground_truth.apk`
- **Configuration**: Use `sandroid-config show` to understand all available options
- **Troubleshooting**: Refer to the troubleshooting section above for common issues

## 🆘 Getting Help

- **Configuration Issues**: Use `sandroid-config validate` for detailed error messages
- **AVD Problems**: Try `sandroid-config avd list` and `sandroid-config avd start`
- **Documentation**: Full documentation available in the `docs/` directory
- **Issue Reporting**: Report bugs at the project's GitHub issue tracker

---

**Happy Android Forensics with Sandroid! 🔍📱**
