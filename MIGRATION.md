# Migration Guide: Sandroid Legacy to PyPI Package

This guide helps you migrate from the legacy Sandroid installation to the new PyPI-based package with modern configuration management.

## Overview of Changes

### What's New
- **PyPI Installation**: Install with `pip install sandroid`
- **Modern Configuration**: YAML/TOML/JSON configuration files with validation
- **XDG Base Directory Compliance**: Follows standard config file locations
- **Environment Variables**: Full support with `SANDROID_` prefix
- **Configuration CLI**: `sandroid-config` tool for configuration management
- **Type Safety**: Pydantic-based configuration with validation
- **Rich CLI**: Enhanced command-line interface with better help and formatting

### What's Changed
- Configuration moved from hardcoded values to external config files
- Command-line arguments remain the same for compatibility
- Log files and output follow XDG directory standards
- Environment variables use `SANDROID_` prefix

## Installation

### New PyPI Installation (Recommended)

```bash
# Install from PyPI
pip install sandroid

# Or install with optional dependencies
pip install sandroid[ai,dev]

# Initialize default configuration
sandroid-config init

# Run analysis
sandroid --help
```

### Legacy Installation (Still Supported)

The old installation method still works:

```bash
git clone <repository>
cd Sandroid_core
./install-requirements.sh
./sandroid
```

## Configuration Migration

### 1. Create Modern Configuration

Generate a default configuration file:

```bash
# Create default config in user directory (~/.config/sandroid/sandroid.yaml)
sandroid-config init

# Or create in specific location
sandroid-config init --output ./my-config.yaml --format yaml
```

### 2. Migrate Hardcoded Settings

Replace hardcoded values in your workflows:

#### Before (Legacy)
```bash
# Hardcoded in toolbox.py
device_name = "Pixel_6_Pro_API_31"
android_emulator_path = "~/Android/Sdk/emulator/emulator"
```

#### After (Modern)
```yaml
# ~/.config/sandroid/sandroid.yaml
emulator:
  device_name: Pixel_6_Pro_API_31
  android_emulator_path: ~/Android/Sdk/emulator/emulator
```

### 3. Environment Variables

Replace custom environment variables:

#### Before (Legacy)
```bash
export RESULTS_PATH="/path/to/results"
export RAW_RESULTS_PATH="/path/to/raw"
```

#### After (Modern)
```bash
export SANDROID_PATHS__RESULTS_PATH="/path/to/results"
export SANDROID_PATHS__RAW_RESULTS_PATH="/path/to/raw"

# Or use configuration file
```

### 4. Command Line Usage

Commands remain largely the same:

#### Before (Legacy)
```bash
./sandroid -f results.json -ll DEBUG --network --sockets
```

#### After (Modern)
```bash
sandroid -f results.json -ll DEBUG --network --sockets

# Or with custom config
sandroid --config my-config.toml --network --sockets
```

## Configuration Management

### View Current Configuration

```bash
# Show configuration with nice formatting
sandroid-config show

# Show in specific format
sandroid-config show --format toml
sandroid-config show --format yaml
sandroid-config show --format json
```

### Modify Configuration

```bash
# Set individual values
sandroid-config set emulator.device_name "Pixel_7_Pro_API_33"
sandroid-config set analysis.number_of_runs 3
sandroid-config set analysis.monitor_network true

# Get individual values
sandroid-config get emulator.device_name
sandroid-config get analysis.monitor_network
```

### Validate Configuration

```bash
# Check if configuration is valid
sandroid-config validate

# Validate specific config file
sandroid-config validate --config ./my-config.yaml
```

### Find Configuration Files

```bash
# Show where Sandroid looks for config files
sandroid-config paths
```

## Environment-Specific Configurations

Create different configurations for different environments:

```bash
# Create development config
sandroid-config init --output development.yaml
# Edit development.yaml for dev-specific settings

# Use development config
sandroid --environment development
# or
sandroid --config development.yaml
```

## Configuration Hierarchy

Configuration values are loaded in this order (highest priority first):

1. **Command-line arguments** (highest priority)
2. **Environment variables** (with `SANDROID_` prefix)
3. **Environment-specific config file** (if `--environment` specified)
4. **Explicit config file** (if `--config` specified)
5. **Discovered config files** (in XDG directories)
6. **Default values** (lowest priority)

## Configuration File Locations

Sandroid looks for configuration files in these locations (in order):

1. **Current directory**: `./sandroid.yaml`, `./config.yaml`, then `.toml`, `.json`
2. **User config directory**: `~/.config/sandroid/sandroid.yaml`
3. **System config directories**: `/etc/sandroid/sandroid.yaml`

Supported formats: `.yaml`, `.yml`, `.toml`, `.json` (YAML preferred)

## Environment Variables

All configuration can be overridden with environment variables:

```bash
# Basic format
export SANDROID_LOG_LEVEL="DEBUG"
export SANDROID_OUTPUT_FILE="my-results.json"

# Nested format (use double underscore)
export SANDROID_EMULATOR__DEVICE_NAME="Pixel_8_Pro_API_34"
export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
export SANDROID_PATHS__RESULTS_PATH="/custom/results"
```

## Docker Usage

The Docker installation remains the same, but you can now mount config files:

```bash
# Mount custom configuration
docker run -v $(pwd)/my-config.yaml:/app/config.yaml sandroid --config /app/config.yaml

# Or use environment variables
docker run -e SANDROID_LOG_LEVEL=DEBUG sandroid
```

## Troubleshooting

### Configuration Issues

```bash
# Check configuration paths and discovered files
sandroid-config paths

# Validate current configuration
sandroid-config validate

# Show current configuration with all merged values
sandroid-config show
```

### Compatibility Issues

If you encounter issues with the new package:

1. **Check Python version**: Requires Python 3.10+
2. **Check dependencies**: Run `pip install -e .` in development
3. **Check configuration**: Use `sandroid-config validate`
4. **Use legacy mode**: Fall back to `./sandroid` script if needed

### Migration Checklist

- [ ] Install new package: `pip install sandroid`
- [ ] Create default config: `sandroid-config init`
- [ ] Migrate hardcoded settings to config file
- [ ] Update environment variables to use `SANDROID_` prefix
- [ ] Update scripts to use `sandroid` command instead of `./sandroid`
- [ ] Test configuration: `sandroid-config validate`
- [ ] Test analysis: `sandroid --dry-run`

## Support

For migration issues:
1. Check this migration guide
2. Use `sandroid-config --help` for configuration help
3. Use `sandroid --help` for CLI help
4. File issues on the project repository

The legacy installation method will continue to work during the transition period.
