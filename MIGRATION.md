# Migration Guide

- [Upgrading to the Devices screen (unreleased)](#upgrading-to-the-devices-screen-unreleased)
- [Upgrading from 2.0.x to 2.1](#upgrading-from-20x-to-21)
- [Migrating from the legacy installation](#migrating-from-the-legacy-installation)

## Upgrading to the Devices screen (unreleased)

Device and AVD management moved from `sandroid-config` into the TUI.

### Breaking changes

| Removed | Use instead |
|---|---|
| `sandroid-config avd list` | Devices screen (`D`) or `emulator -list-avds` |
| `sandroid-config avd start [--avd-name N] [--headless] [--boot-mode M]` | `sandroid --avd N` (remembered options; headless on first launch from `emulator.avd_headless`), or `⏎` in the Devices screen after setting the launch options (`c` cold / `n` snapshot / `h` headless / `s` save state / `w` wipe once) |
| `sandroid-config avd stop` | `x` on the emulator in the Devices screen (stops that emulator only) or `adb -s emulator-5554 emu kill` |
| `sandroid-config avd rename` | `e` on a stopped AVD in the Devices screen |
| `sandroid-config avd create` | Android Studio's Device Manager or `python deploy/create_avd.py` |
| `sandroid-config devices` | Devices screen (`D`) or `adb devices -l` |
| `sandroid-config init` AVD selection/start prompts | `init` only detects the SDK/adb/emulator paths; pick the AVD in the Devices screen (it opens at startup when no device runs). `--skip-avd-setup` still works as an alias of `--skip-android-setup`. |
| `emulator.selected_avd`, `emulator.avd_auto_start` | Removed; old configs still load (the keys are ignored). For a scripted start use `sandroid --avd NAME`; the last-used AVD is preselected in the Devices screen. |
| `set_avd_location.py` (repository-root GPS script) | Device settings: `E` in the TUI, `sandroid --device-settings FILE` or `--preset CODE` |
| `sandroid --trigdroid PKG` (also the package flag of `--headless`/`--batch` modes) | `sandroid --package PKG` / `-p PKG`. `--trigdroid` now exits with a usage error; `--trigdroid-ccf` is gone. Malware mode performs no trigger actions (it never did: TrigDroid failed before its first trigger). |
| `[trigdroid]` config section (`enabled`, `package_name`, `config_mode`) | Removed; an old section still loads and is ignored with one warning. Pass the target with `--package`/`-p`. |
| `trigdroid[full]` dependency, `sandroid.features.trigdroid`, `get_trigdroid_config_service()` | Removed; nothing replaces them yet (device playbooks are planned). Device events: device settings (`E`, `--device-settings FILE`, `--preset CODE`). |
| `sandroid.services.EnvironmentService` / `get_environment_service()` | `SetupService` / `get_setup_service()` (`sandroid.services.SetupResult` now refers to `SetupService`'s result) |

Launch options chosen in the Devices screen (headless, boot mode, snapshot)
are remembered per AVD in `~/.config/sandroid/devices.json`.

---

## Upgrading from 2.0.x to 2.1

```bash
pip install --upgrade sandroid    # requires Python >= 3.12
```

### Breaking changes

| Change | What to do |
|---|---|
| **Python 3.12+ required.** 3.10 and 3.11 are no longer supported (tested on 3.12 and 3.13). | Recreate your virtualenv with Python 3.12 or 3.13. |
| **Legacy Rich menu removed** (`sandroid -i` / `--interactive`). | Use the Textual TUI (`sandroid`) or `--headless`. |
| **`--ai` (Gemini video summarisation) removed**, together with its Gemini API-key setting. | The new AI Chat (`Ctrl+Y`, EXPERIMENTAL) talks to any OpenAI-compatible endpoint; configure it under `[ai]` (see README). |
| **TUI views removed.** The Forensic/Malware/Security views (switched with `TAB`) are replaced by one flat action catalog (`?`); `--view` no longer has an effect. | Drop `--view` from scripts (`analysis.default_view` is ignored by the TUI). `--mode` for `--headless` is unchanged. |
| **TUI layout redesigned**: the `Ctrl+B` bottom panel with Spotlight/Mitmproxy/Snapshots tabs became always-on tool tabs **Spotlight / Network / Snapshots / Files**; navigation uses `Shift+Arrows`. | Press `?` for the current keymap and to re-check custom bindings in `tui.keybindings`. |
| **Record/Play moved** into **Files -> Diffs** (`r`/`p` there); results are stored as run bundles under `<results_path>/runs/<run_id>/`. | Old flat `runs/run_*.json` histories are still read. |
| **Proxy redesign**: the on-device redirector changed from `ipt2socks` to `gost`; Device Proxy and per-app App Proxies are configured in one modal (`y`). | Nothing to migrate; the `focus.*` config keys are new (defaults work). |
| **Config save location**: configuration is saved to `~/.config/sandroid/` again (2.0.0 could write to the platformdirs location, e.g. `~/Library/Application Support/sandroid/` on macOS). | If settings seem lost after upgrading, move that file to `~/.config/sandroid/sandroid.toml`. |

### New (opt-in) features

- AI Chat dock (`Ctrl+Y`) -- **EXPERIMENTAL**; sends device data to the configured LLM endpoint, so prefer a local endpoint (e.g. Ollama) and pass the key via `SANDROID_AI__API_KEY`.
- mitmproxy integration: Device/App proxies, CA injection into the system trust store, custom addons.
- Frida bypass suite (SSL / Root / Frida / Debug / Integrity) -- **EXPERIMENTAL**.
- kprobe-based filesystem monitor (`tui.monitor_backend = "kprobe"`, falls back to fsmon).
- Snapshot slots, run history, real-time device disconnect/reconnect detection.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

---

## Migrating from the Legacy Installation

This part helps you migrate from the legacy Sandroid installation (source checkout + `./sandroid` script) to the PyPI-based package with modern configuration management.

## Overview of Changes

### What's New
- **PyPI Installation**: Install with `pip install sandroid`
- **Modern Configuration**: TOML (default), YAML or JSON configuration files with validation
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

# Or install with the optional static-analysis extras
pip install "sandroid[full]"

# Initialize default configuration
sandroid-config init

# Run analysis
sandroid --help
```

### Legacy Installation (Deprecated)

The old installation method is deprecated, unmaintained and untested; it may
break at any time:

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
# Create default config in user directory (~/.config/sandroid/sandroid.toml)
sandroid-config init

# Or create in a specific location / format
sandroid-config init --output ./my-config.toml
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
```toml
# ~/.config/sandroid/sandroid.toml
[emulator]
device_name = "Pixel_6_Pro_API_31"
android_emulator_path = "~/Android/Sdk/emulator/emulator"
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
sandroid-config set -k emulator.device_name -v "Pixel_7_Pro_API_33"
sandroid-config set -k analysis.number_of_runs -v 3
sandroid-config set -k analysis.capture_network -v true

# Get individual values
sandroid-config get -k emulator.device_name
sandroid-config get -k analysis.capture_network
```

### Validate Configuration

```bash
# Check if configuration is valid
sandroid-config validate

# Validate specific config file
sandroid-config validate --config ./my-config.toml
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
sandroid-config init --output development.toml
# Edit development.toml for dev-specific settings

# Use development config
sandroid --environment development
# or
sandroid --config development.toml
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

1. **Current directory**: `./sandroid.toml`, `./config.toml` (then `.yaml`, `.yml`, `.json`)
2. **User config directory**: `~/.config/sandroid/sandroid.toml`
3. **Platform config directories** (e.g. `~/Library/Application Support/sandroid/` on macOS)

Run `sandroid-config paths` for the exact list. Supported formats: `.toml` (default, preferred), `.yaml`, `.yml`, `.json`

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

## Docker Usage (best effort)

The Docker image (`docker/dockerfile`) is not tested in CI. You can mount config files:

```bash
# Mount custom configuration
docker run -it -v $(pwd)/my-config.toml:/sandroid/my-config.toml sandroid sandroid --config /sandroid/my-config.toml

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

1. **Check Python version**: Requires Python 3.12+
2. **Check dependencies**: Run `pip install -e ".[dev,full]"` in development
3. **Check configuration**: Use `sandroid-config validate`

### Migration Checklist

- [ ] Install new package: `pip install sandroid`
- [ ] Create default config: `sandroid-config init`
- [ ] Migrate hardcoded settings to config file
- [ ] Update environment variables to use `SANDROID_` prefix
- [ ] Update scripts to use `sandroid` command instead of `./sandroid`
- [ ] Test configuration: `sandroid-config validate`
- [ ] Test the CLI: `sandroid --help`, then start the TUI with `sandroid`

## Support

For migration issues:
1. Check this migration guide
2. Use `sandroid-config --help` for configuration help
3. Use `sandroid --help` for CLI help
4. File issues on the project repository

The legacy installation method is deprecated and will be removed in a future release.
