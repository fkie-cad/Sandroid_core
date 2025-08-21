# Sandroid Setup Guide

This guide walks you through setting up Sandroid for forensic analysis of Android Virtual Devices.

## Quick Start

### Prerequisites

- Python 3.10 or newer
- Android Studio with Android SDK
- A running Android Virtual Device (AVD)
- Linux, macOS, or Windows with WSL2

### Installation

```bash
# Install Sandroid
pip install sandroid

# Initialize configuration
sandroid-config init

# Run your first analysis
sandroid --help
```

## Detailed Setup

### 1. System Dependencies

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip \
    sqlite3-tools \
    adb \
    cmake \
    build-essential \
    libxml2-dev \
    libxslt-dev
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python sqlite android-platform-tools cmake
```

#### Windows (WSL2)
```bash
# Use Ubuntu WSL2 and follow Linux instructions
wsl --install -d Ubuntu
# Then follow Linux setup in WSL2 environment
```

### 2. Android Development Setup

#### Install Android Studio

1. Download Android Studio from https://developer.android.com/studio
2. Install and complete the setup wizard
3. Install Android SDK and platform tools

#### Create Android Virtual Device

1. Open Android Studio
2. Click "More Actions" → "Virtual Device Manager"
3. Click "Create device"
4. Choose a device (recommended: Pixel 6 Pro)
5. Select API level (recommended: API 31+)
6. Click "Finish"
7. Start the emulator

### 3. Python Environment Setup

#### Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv sandroid-env

# Activate virtual environment
source sandroid-env/bin/activate  # Linux/macOS
# or
sandroid-env\Scripts\activate  # Windows

# Install Sandroid
pip install sandroid

# Install optional dependencies if needed
pip install sandroid[ai,dev]
```

#### Global Installation

```bash
# Install globally (not recommended for development)
pip install sandroid
```

### 4. Configuration Setup

#### Initialize Default Configuration

```bash
# Create default configuration
sandroid-config init

# View configuration paths
sandroid-config paths

# Show current configuration
sandroid-config show
```

#### Customize Configuration

```bash
# Edit the configuration file
# Location: ~/.config/sandroid/sandroid.yaml

# Or set individual values
sandroid-config set emulator.device_name "Your_Device_Name"
sandroid-config set analysis.number_of_runs 3
sandroid-config set paths.results_path "/path/to/results"
```

#### Environment-Specific Configurations

```bash
# Create development configuration
cp ~/.config/sandroid/sandroid.yaml ~/.config/sandroid/development.yaml

# Edit development.yaml for dev-specific settings
# Use with: sandroid --environment development
```

### 5. Verify Installation

#### Check System Requirements

```bash
# Verify Python version
python3 --version  # Should be 3.10+

# Verify ADB
adb version

# List connected devices/emulators
adb devices
```

#### Test Sandroid

```bash
# Show help
sandroid --help

# Show configuration
sandroid-config show

# Validate configuration
sandroid-config validate
```

## Configuration Examples

### Basic Analysis Configuration

```yaml
# ~/.config/sandroid/sandroid.yaml

log_level: INFO
output_file: sandroid.json

emulator:
  device_name: Pixel_6_Pro_API_31

analysis:
  number_of_runs: 2
  monitor_processes: true
  monitor_network: false

paths:
  results_path: ./results/
```

### Advanced Security Analysis

```yaml
# ~/.config/sandroid/security.yaml

log_level: DEBUG
output_file: security-analysis.json

analysis:
  number_of_runs: 3
  avoid_strong_noise_filter: false
  monitor_processes: true
  monitor_sockets: true
  monitor_network: true
  show_deleted_files: true
  hash_files: true
  list_apks: true
  screenshot_interval: 10

trigdroid:
  enabled: true
  package_name: com.example.suspicious

ai:
  enabled: true
  provider: google-genai
  model: gemini-pro

report:
  generate_pdf: true
  include_screenshots: true

credentials:
  # Set via environment variables or CLI for security
  # google_genai_api_key: your-api-key-here
```

### Development Configuration

```yaml
# ~/.config/sandroid/development.yaml

log_level: DEBUG
output_file: dev-results.json
environment: development

emulator:
  device_name: Pixel_7_Pro_API_33

paths:
  results_path: ./dev-results/
  temp_path: /tmp/sandroid-dev/

analysis:
  number_of_runs: 2
  screenshot_interval: 5
```

## Usage Examples

### Basic Malware Analysis

```bash
# Simple malware analysis
sandroid --network --sockets --hash --screenshot 10

# With custom config
sandroid --config security.toml --trigdroid com.suspicious.app

# With environment variables
export SANDROID_ANALYSIS__MONITOR_NETWORK=true
export SANDROID_ANALYSIS__HASH_FILES=true
sandroid
```

### Automated Analysis Pipeline

```bash
#!/bin/bash
# analysis-pipeline.sh

# Initialize environment
sandroid-config set analysis.number_of_runs 5
sandroid-config set report.generate_pdf true

# Run comprehensive analysis
sandroid \
    --network \
    --sockets \
    --show-deleted \
    --hash \
    --apk \
    --screenshot 30 \
    --ai \
    --report \
    --file "analysis-$(date +%Y%m%d-%H%M%S).json"
```

### Configuration Management Workflow

```bash
# Setup different environments
sandroid-config init --output production.yaml
sandroid-config init --output testing.yaml
sandroid-config init --output development.yaml

# Customize each environment  
sandroid-config set --config testing.yaml log_level DEBUG
sandroid-config set --config testing.yaml analysis.number_of_runs 1

# Use specific environment
sandroid --config testing.yaml --network
```

## Environment Variables Reference

Set these environment variables to override configuration:

```bash
# Core settings
export SANDROID_LOG_LEVEL="DEBUG"
export SANDROID_OUTPUT_FILE="/path/to/output.json"

# Emulator settings
export SANDROID_EMULATOR__DEVICE_NAME="Custom_Device"
export SANDROID_EMULATOR__ANDROID_EMULATOR_PATH="/custom/path/emulator"

# Analysis settings
export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
export SANDROID_ANALYSIS__MONITOR_NETWORK=true
export SANDROID_ANALYSIS__MONITOR_SOCKETS=true

# Paths
export SANDROID_PATHS__RESULTS_PATH="/custom/results"
export SANDROID_PATHS__TEMP_PATH="/custom/temp"

# AI settings (API keys should use environment variables)
export SANDROID_AI__ENABLED=true
export SANDROID_AI__API_KEY="your-secret-api-key"

# Credentials (recommended for API keys)
export SANDROID_CREDENTIALS__GOOGLE_GENAI_API_KEY="your-google-api-key"
```

## Troubleshooting

### Common Issues

#### "Device not found"
```bash
# Check ADB connection
adb devices

# Restart ADB server
adb kill-server && adb start-server

# Check emulator is running
sandroid-config get emulator.device_name
```

#### "Configuration validation failed"
```bash
# Check configuration syntax
sandroid-config validate

# Show current configuration
sandroid-config show

# Reset to defaults
sandroid-config init --force
```

#### "Permission denied" for directories
```bash
# Check and fix directory permissions
sandroid-config get paths.results_path
mkdir -p "$(sandroid-config get paths.results_path)"
chmod 755 "$(sandroid-config get paths.results_path)"
```

#### "Frida server not running"
```bash
# Check Frida configuration
sandroid-config get frida.server_auto_start

# Enable auto-start
sandroid-config set frida.server_auto_start true
```

### Getting Help

```bash
# CLI help
sandroid --help
sandroid-config --help

# Configuration help
sandroid-config paths
sandroid-config show
sandroid-config validate

# Check version
sandroid --version
```

### Docker Alternative

If you encounter installation issues, use Docker:

```bash
# Build and run with Docker
./build_and_export_docker.sh
cd deploy && ./deploy

# Or pull from registry (when available)
docker pull sandroid/sandroid:latest
docker run -it --rm sandroid/sandroid:latest
```

## Next Steps

1. **Configure your environment**: Edit `~/.config/sandroid/sandroid.yaml`
2. **Test with ground truth APK**: Install and test with the included test app
3. **Run your first analysis**: `sandroid --network --screenshot 10`
4. **Review results**: Check the generated JSON and logs
5. **Automate workflows**: Create scripts for common analysis patterns

For advanced usage and upgrading from legacy installations, see the [MIGRATION.md](MIGRATION.md) guide.