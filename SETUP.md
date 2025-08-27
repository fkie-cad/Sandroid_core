# Sandroid Setup Guide

This comprehensive guide walks you through setting up Sandroid for forensic analysis of Android Virtual Devices.

## 🚀 Quick Start (Recommended)

### Prerequisites

- **Python 3.10 or newer**
- **Internet connection** (for automated Android SDK detection)
- **Linux, macOS, or Windows** (WSL2 recommended for Windows)

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
📍 Location: ~/.config/sandroid/sandroid.yaml
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
   - At least one Android system image (API 31+ recommended)
4. **Create an AVD**:
   - Open Virtual Device Manager in Android Studio
   - Click "Create Device"
   - Choose a device profile (Pixel devices work well)
   - Select a system image (x86_64 for Intel/AMD, arm64 for Apple Silicon)
   - Configure settings and create the AVD

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

# Show configuration in YAML format
sandroid-config show --format yaml

# Validate your configuration
sandroid-config validate
```

### Manual Configuration Updates
```bash
# Set Android paths manually if needed
sandroid-config set emulator.sdk_path "/path/to/Android/Sdk"
sandroid-config set emulator.adb_path "/path/to/adb"
sandroid-config set emulator.android_emulator_path "/path/to/emulator"

# Configure AVD settings
sandroid-config set emulator.selected_avd "Pixel_6_Pro_API_31"
sandroid-config set emulator.avd_headless true
sandroid-config set emulator.avd_auto_start false

# Set other analysis options
sandroid-config set analysis.number_of_runs 3
sandroid-config set analysis.monitor_network true
```

### Configuration File Locations
Configuration files are searched in this order:
1. `./sandroid.yaml` (current directory)
2. `~/.config/sandroid/sandroid.yaml` (user config)
3. `/etc/sandroid/sandroid.yaml` (system config)

Supported formats: YAML (recommended), TOML, JSON

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
sandroid-config set emulator.sdk_path "/path/to/Android/Sdk"
```

**Problem: ADB not found**
```bash
# Check if ADB is in PATH
which adb  # Linux/macOS
where adb  # Windows

# If not found, install Android SDK or set path manually
sandroid-config set emulator.adb_path "/path/to/adb"
```

**Problem: No AVDs found**
```bash
# Create AVD using Android Studio or
python deploy/create_avd.py

# Or point to existing AVD directory
sandroid-config set emulator.avd_home "/path/to/avd"
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

### Legacy Installation Method (Still Supported)

For users who prefer the original installation method:

```bash
# Clone the repository
git clone https://github.com/fkie-cad/Sandroid_core.git
cd Sandroid_core

# Install system dependencies
./install-requirements.sh

# Install Python dependencies manually
pip install -r docker/requirements.txt

# Use the legacy CLI directly
./sandroid.legacy
```

### Docker Deployment

For containerized environments:

```bash
# Build Docker image
./build_and_export_docker.sh

# Deploy with Docker
cd deploy
./deploy [output_path]
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
# Install in development mode
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Run tests
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
sandroid-config init --output production.yaml

# Use specific configuration
sandroid --config production.yaml --network --ai
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
- **Interactive Mode**: Try `sandroid` to explore the interactive menu
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
