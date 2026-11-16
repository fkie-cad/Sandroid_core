# Changelog

All notable changes to the Sandroid project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-11-XX

Sandroid 2.1 redesigns the TUI around always-on tool tabs, adds an mitmproxy-based
network interception stack with per-app proxies and CA injection, a tiered Frida
bypass suite, a kprobe filesystem monitor, a rewritten analysis engine with
persistent run history, and an experimental AI Chat assistant.

### ⚠️ Breaking Changes
- **Python 3.12 or newer is required** (3.12 and 3.13 are tested in CI); Python 3.10/3.11 support was dropped.
- **Legacy Rich interactive mode removed**: `sandroid -i` / `--interactive` no longer exist — use the Textual TUI (`sandroid`) or `--headless`.
- **`--ai` removed**: the Gemini-based video summarisation feature and its API-key setting are gone, superseded by the new (experimental) AI Chat.
- **TUI views removed**: the Forensic / Malware / Security views (`TAB`) were replaced by a single flat action catalog; `--view` and `analysis.default_view` no longer have any effect in the TUI (`--mode` for `--headless` is unchanged).
- **TUI layout changed**: the `Ctrl+B` bottom panel was replaced by always-on tool tabs (Spotlight / Network / Snapshots / Files) with `Shift+Arrow` navigation; Record/Play moved into **Files → Diffs**.
- The internal `ActionQ`/`DataGather` analysis pipeline was replaced by `AnalysisEngine`; third-party code importing those internals must be updated.
- The on-device proxy redirector changed from `ipt2socks` to `gost`.

### Added

#### TUI
- **Glance band**: permanent, boxed status strip (device, frida-server, mitmproxy engine, device/app proxies, spotlight) derived from live device state.
- **Always-on tool tabs**: **Spotlight**, **Network** (Mitmproxy + friTap sub-tabs), **Snapshots** and **Files** (Monitor / Watchlist / Diffs sub-tabs), unified under `Shift+Arrow` navigation.
- **Help & keybinding editor** (`?`): browse every action by category and rebind any key (incl. `Ctrl` combos) with live conflict detection; persisted to `tui.keybindings`.
- **Snapshots tab** with an 8-slot snapshot memory per AVD (`1`–`8` load, `Ctrl+1`–`Ctrl+8` save, `a` assign).
- **friTap panel** with status header and live log tail.
- **Startup device picker** and real-time device shutdown/reconnect detection (`adb host:track-devices`).
- **Monitor settings tab** (kprobe/fsmon source, multiple paths, per-category event visibility).
- Theming of the chat/tool panels and the chat transcript; compact form widgets.

#### Analysis engine & run history
- **`AnalysisEngine`** replaces the ActionQ/DataGather pipeline (same `sandroid.json` keys).
- **Run history / run bundles**: every Play is stored as a self-contained bundle (`<results_path>/runs/<run_id>/` with `run.json`, `recording.txt`, raw pull tree), listed in **Files → Diffs**, scoped per device; Record/Play UX fixes and a redesigned Diffs layout.
- **Unified Files tab**: fsmon/kprobe monitor stream, Spotlight-Files watchlist and Play diffing in one place, with grouped, de-duplicated event display.
- **kprobe filesystem monitor** (`tui.monitor_backend = "kprobe"`, default): kernel tracefs kprobes with per-process/child-tree attribution and path-scoped capture, no binary pushed to the device; automatic fallback to `fsmon`.

#### Network interception
- **mitmproxy integration** (Network → Mitmproxy): start/stop `mitmweb`, live flow and TLS-failure tail, flow log.
- **Device Proxy and per-app App Proxies** in one Proxy Settings modal (`y`); App Proxies route individual apps (by UID) through Sandroid's mitmproxy or an external proxy (Burp/ZAP) via an on-device `gost` redirector; optional QUIC (UDP/443) blocking; emulator-aware host IP detection, device-reachability probe and `adb reverse` fallback.
- **CA certificate injection** into the system trust store (APEX bind-mount on Android 14+, Zygote mount namespace on Android 10–13, with confirmation before restarting Zygote); CA status reported on start.
- **Custom mitmproxy addons** from `~/.config/sandroid/mitm_addons/` and `./mitm_addons/`, managed with `Ctrl+A`, hot-reloaded on edit.

#### Bypass suite (EXPERIMENTAL)
- Flag-gated, single resident Frida script with **SSL**, **Root**, **Frida**, **Debug** and new **Integrity** (PairIP / licensing / attestation) categories; instant toggles without un-hooked gaps; auto-reload and package validation.
- SSL unpinning tiers: Java/Conscrypt/OkHttp/WebView/TrustKit/CT, native BoringSSL, **Chromium/cronet BoringSSL** (incl. stripped, symbol-less libraries), **mbedTLS / Meta Network Stack**; pre-init constructor interposition and a spawn-reliability ladder for hardened apps.

#### AI Chat (EXPERIMENTAL)
- `sandroid.ai`: streaming OpenAI-compatible client, tool-calling loop, MCP client bridge, concurrent subtasks with a device-resource arbiter.
- Chat dock (`Ctrl+Y`) with markdown rendering, ambient device/session context on every turn and ~76 tools (app/process lifecycle, device/network/flow queries, certificate/environment control, file transfer with host-path confinement, file monitor, record/replay).
- Per-tool permission gate (allow once / always / never, persisted).
- New `[ai]` and `[mcp]` config sections with secret redaction in `sandroid-config show`. **Note:** prompts, device context and tool output are sent to the configured endpoint — prefer a local endpoint (e.g. Ollama) and set the key via `SANDROID_AI__API_KEY`.

#### Evidence documentation & reporting
- **SHA-256** alongside MD5 for artifacts and APKs (new JSON keys; existing keys unchanged), keyed by full device path.
- **`Run Metadata`** in every results JSON: Sandroid/frida/friTap/dexray versions, host, device serial, AVD, Android version/API level, build fingerprint, ISO-8601 start/end timestamps with timezone, and the (secret-free) analysis settings.
- **Evidence manifest**: `manifest.json` + `SHA256SUMS` over the whole result folder (verifiable with `sha256sum -c` / `shasum -a 256 -c`); its own hash is logged.
- **`sandroid --report-from <dir>`** verifies the manifest and (re)generates the PDF for an existing result folder; `P` in **Files → Diffs** does the same for a run; `report.generate_pdf` creates it after every Play.
- PDF title page with run metadata, readable wrapping tables, deterministic timeline.

#### Device selection & safety defaults
- **`--serial/-s`**, `$ANDROID_SERIAL` and `emulator.serial` select the device; every adb call is pinned to it.
- **AI Chat is off unless configured**, accepts only local endpoints unless `ai.allow_remote = true`, shows a data-egress notice naming endpoint and model, and no MCP server is enabled by default (the bundled demo server returns clearly marked fake data only).
- All bypass categories are labelled *experimental* and off by default.

#### Tooling
- Hermetic test suite (~1300 tests); `tests/conftest.py` blocks all real adb/emulator/frida access.
- CI runs ruff and pytest on Python 3.12 and 3.13 for `main` and `dev`, and checks the built distribution.
- Releases are tagged `v<version>` with notes taken from this changelog.

### Changed
- **friTap 2.0** compatibility; tested with friTap 2.6.7, AndroidFridaManager 2.0.7 (verified frida-server downloads), dexray-intercept 1.0.1.9, objection 1.12.5, mvt 2026.11, frida 17.26.
- Dependencies have upper bounds for fast-moving packages; `mcp`, `mitmproxy`, `androguard` and `psutil` are core dependencies (`.[ai]` is kept as an empty alias).
- Package metadata now states the actual license (GPL-3.0).
- Simplified app picker (system apps toggle on `Ctrl+S`).
- Spotlight header self-heals a stale "paused" state against the live process.
- Configuration is saved to `~/.config/sandroid/` again instead of the platformdirs location.
- ABX (binary XML) files are decoded in-process instead of shelling out.
- Documentation brought up to date (requirements, rooted-AVD setup, TOML configuration, new features).
- Docker image installs Sandroid from `pyproject.toml` (best effort, not tested in CI).

### Fixed
- frida-server start failures are reported honestly instead of always "started"; clean frida install prompt and Java bridge restored on frida 17.
- CA injection on Android 10–13; mitmproxy start/stop no longer deadlocks the TUI when triggered from AI Chat; `start_mitmproxy` can retry on another port.
- Glance band never updating from panels; tab-bar visibility; startup logo wobble.
- Shared-global ADB serial race between devices; zombie retries capped; `DeviceManagerProtocol` drift.
- kprobe backend: off-thread setup, path-mode scoping, preflight self-check hang, noisy teardown warnings.
- `ADB_PATH` is quoted when building shell commands (paths with spaces, Windows).
- ChangedFiles `.xml` branch reuses the joined pull paths.
- **Intra-file diffs restored**: the first pull after the action was always empty, so changed SQLite databases and XML/ABX files showed "Not enough data for intra file analysis" instead of row/attribute diffs.
- **Network results**: capture files are located on disk (the last capture was skipped with the noise filter off or N=1), TCP/UDP targets and IPv6 are reported with their DNS names, and a missing noise capture no longer wipes the result.
- Record→Play from the TUI now runs the same gatherers as the CLI (processes, sockets, network per `[analysis]` settings) and writes the full results JSON; processes/sockets polling stops with the action.
- Snapshot loads that fail abort the run; the guest clock is resynced to the host after every snapshot load (it drifted minutes behind).
- Noise: ART profiles, `package-dex-usage`, `monotonic_clock.xml`, battery history are always filtered; the dry run also subtracts deleted files.
- Artifact hashes are computed over the full pull tree (they were empty) and split APKs are hashed per part.
- `adb root` + `setenforce 0` are applied on every path that needs them (`--install-apk`, `--dexray`, `--fritap`, …); `--install-apk` no longer prints "too many values to unpack".
- The TUI starts without the AI dependencies; the forensic APK manager no longer crashes on a missing `WarningModal`; `features/screenshot.py` imports cleanly; several silently broken imports fixed; importing Sandroid never parses `sys.argv`.
- Headless: the CLI configuration is kept (wrong device name in reports), forensic mode forwards `--network` and no longer needs a package.
- TUI results are stored in one place under `paths.results_path` (previously split between the CWD and the run bundle); quitting no longer hangs on leftover helper threads.
- PDF report: logo shipped as package data, no crash without `RAW_RESULTS_PATH`, no empty file-name rows, no ANSI escape codes in PDF or JSON; the screenshot grid no longer converts/deletes the original PNGs.
- friTap: spawned targets are resumed (Android killed them after 10 s), hooks of dead jobs are unregistered, the panel shows when capturing stopped, and `fritap_output.json` is written on close.
- dexray-intercept: fixed a deadlock during script load ("TransportError … timeout") and stop not stopping the job.
- objection command lines fixed for objection 1.12; `frida.server_auto_start` is honoured; frida-server download errors (offline, rate limit, digest mismatch) are explained; MVT IOC download fallback fixed; `mitmweb` is found next to the Python interpreter.
- AI Chat: tools from external MCP servers and evidence deletion always require confirmation; the API key is never written to logs, results or the config file from the environment.
- `json_encoder` no longer recurses on duck-typed objects.

### Removed
- Legacy Rich interactive menu (`-i`), Gemini video summarisation (`--ai`), TUI view modes, the `ipt2socks` redirector, the stale `docker/requirements.txt`.

## [2.0.0] - 2026-03-17

### Complete Rewrite: Textual TUI, Click CLI, and Three Analysis Views

This release represents a complete rewrite of Sandroid's user interface and CLI, introducing a modern terminal user interface, a new Click-based command-line interface, and three specialized analysis views.

### Added

#### Textual TUI
- **Modern terminal user interface** using the Textual framework replacing the Rich-based menu
- **Three analysis views**: Forensic, Malware, and Security (early stage) — switch with TAB
- **Status bar** showing Frida server status, HTTP proxy, spotlight app, and spotlight files
- **Activity log** with real-time command output and status messages
- **Theme system** with 8 built-in themes (default, dark, light, high_contrast, cyberpunk, nord, dracula, solarized)
- **Custom CSS support** for TUI customization
- **Welcome dialog** for first-time users

#### Click-Based CLI
- **Migrated from argparse to Click** with hyphenated flags (e.g., `--avoid-strong-noise-filter`)
- **View selection**: `--view forensic|malware|security`
- **Headless mode**: `--headless` with `--batch` for batch processing
- **Legacy mode**: `sandroid -i` for the classic Rich interactive menu

#### New Analysis Tools
- **Dexray-Intercept** integration for dynamic hooking and malware monitoring (`--dexray`)
- **Dexray-Insight** integration for static analysis (replacing asam)
- **Fridump** integration for memory dumping (`--fridump`)
- **FriTap** headless mode for SSL/TLS key extraction (`--fritap`)
- **Objection** integration with resume support
- **MVT** (Mobile Verification Toolkit) forensic evidence scanning

#### Device Management
- **HTTP proxy management**: `--proxy`, `--proxy-clear`
- **APK installation**: `--install-apk`
- **Action import**: `--import-action`
- **Device settings**: `--device-settings`, `--preset`
- **Country presets** (de, us, ru, cn, etc.)

#### Configuration Management
- **AVD management commands**: `sandroid-config avd list|start|stop|rename|create`
- **Theme management**: `sandroid-config theme list|set|show`
- **IOC management**: `sandroid-config ioc show|set-path|set-url|download|validate`
- **Device listing**: `sandroid-config devices`
- **TOML as default** configuration format (replacing YAML)

#### New TUI Commands
- `C` — Spawn spotlight application
- `E` — Device settings and presets
- `F` — Forensic evidence scan (MVT)
- `G` — Manage forensic APKs
- `k` — Reconfigure Frida hooks
- `O` — Resume objection session

### Changed
- **Default mode**: `sandroid` now launches the Textual TUI (previously Rich menu)
- **Legacy mode**: Rich interactive menu available via `sandroid -i`
- **TrigDroid**: Now fully integrated (previously marked as not fully integrated)
- **Frida handling**: Smart per-command requirement with modal prompts instead of manual install-first workflow
- **Command registry**: 12 command categories across 3 views replacing 5 static menu sections

### Removed
- **AM3 (Android Malware Motion Monitor)**: Replaced by Dexray-Intercept
- **asam**: Renamed to Dexray-Insight

## [1.1.9] - 2025-09-15

Updated Fridump class to work with frida >= 17.0

## [1.1.0] - 2025-08-27

### Complete Package Migration: PyPI Distribution Now Feature-Complete

This release resolves the critical "Legacy analysis modules not available" error and makes the PyPI installation fully feature-complete with the legacy version.

### Fixed
- **Package Migration**: Migrated 32 analysis modules from `src/utils/`, `src/datagather/`, and `src/functionality/` to proper pip-installable packages
- **Import Errors**: Fixed "No module named 'src'" errors that prevented PyPI installation from working
- **Module Structure**: Reorganized code into modern package structure:
  - `src/utils/` → `src/sandroid/core/` (15 modules)
  - `src/datagather/` → `src/sandroid/analysis/` (10 modules)
  - `src/functionality/` → `src/sandroid/features/` (5 modules)

### Added
- **Dual-Mode Architecture**: Both legacy (`./sandroid`) and modern (`sandroid`) CLI work identically
- **Compatibility Layer**: Transparent import redirection maintains 100% backward compatibility
- **Code Quality**: Comprehensive linting configuration with security rule exemptions for forensic tools
- **Modern Dependencies**: Updated Frida to v17+ and frida-tools to v14+

### Changed
- **Package Structure**: Migrated to modern Python packaging while preserving all functionality
- **Import Paths**: Fixed hardcoded `from src.` imports throughout the codebase
- **Build Configuration**: Updated `pyproject.toml` to include all migrated packages

### Technical Details
- **32 Modules Migrated**: Complete analysis framework now properly packaged
- **Circular Import Resolution**: Fixed complex interdependencies between modules
- **Linting Compliance**: Resolved F403, TID252, F405, and security (S*) linting issues
- **Type Safety**: Fixed Pydantic v2 API compatibility (`regex` → `pattern`)

## [1.0.0] - 2025-01-21

### 🚀 Major Release: Modern PyPI Package with Advanced Configuration

This release represents a complete modernization of the Sandroid framework while maintaining full backward compatibility. The project now offers professional-grade packaging, configuration management, and development workflows.

### Added

#### PyPI Package Infrastructure
- **Modern pyproject.toml** with comprehensive dependency management
- **Entry points** for CLI commands (`sandroid`, `sandroid-config`)
- **Optional dependencies** for different use cases (`[ai,dev,docs]`)
- **Development tools integration** (black, isort, pytest, mypy, flake8)
- **Build system** using modern setuptools backend
- **Proper package structure** under `src/sandroid/`

#### Advanced Configuration System
- **Pydantic-based configuration schema** with full type validation
- **Multi-format support**: TOML, YAML, JSON configuration files
- **XDG Base Directory compliance** for standard config file locations
- **Hierarchical configuration loading**: CLI args > env vars > config files > defaults
- **Environment variable support** with `SANDROID_` prefix and nested configuration
- **Configuration validation** with clear error messages and helpful suggestions
- **Configuration CLI tool** (`sandroid-config`) for easy management

#### Modern CLI Interface
- **Rich console output** with colors, tables, and syntax highlighting
- **Click framework** for robust argument parsing and help system
- **Interactive configuration** management commands
- **Environment-specific configurations** for development, testing, production
- **Comprehensive help system** with examples and detailed descriptions

#### Configuration Management Features
- `sandroid-config init` - Create default configuration files (YAML format)
- `sandroid-config show` - Display current configuration with formatting
- `sandroid-config validate` - Validate configuration files
- `sandroid-config set/get` - Modify individual configuration values
- `sandroid-config paths` - Show configuration file search locations
- **Configuration file discovery** in standard XDG directories
- **Template configurations** for different use cases
- **YAML-first approach** with support for TOML and JSON
- **Secure credentials section** for API keys and tokens

#### Documentation Suite
- **SETUP.md** - Comprehensive setup guide for new users
- **MIGRATION.md** - Detailed migration guide from legacy to modern installation
- **Updated development documentation** - Modern development workflows and installation methods
- **Configuration examples** for basic analysis, security analysis, and development
- **Environment variable reference** with complete configuration mapping
- **Troubleshooting guides** for common setup and configuration issues

#### Development Infrastructure
- **Modern testing framework** with pytest and coverage reporting
- **Code quality tools** with black, isort, flake8, mypy configurations
- **Type hints** throughout the configuration system
- **Mock testing infrastructure** for ADB and emulator interactions
- **CI/CD ready** configurations for automated testing and building

### Enhanced

#### CLI Experience
- **Backward compatible** command-line interface preserving all existing arguments
- **Enhanced help system** with detailed descriptions and examples
- **Rich formatting** for error messages and output
- **Configuration integration** allowing CLI arguments to override config files
- **Environment detection** with automatic configuration loading

#### Configuration Management
- **Replaced hardcoded values** with configurable options throughout the system
- **Path management** with automatic directory creation and validation
- **Security improvements** with environment variable support for sensitive data
- **Extensibility** through custom configuration sections
- **Validation** preventing invalid configurations from being used

#### Developer Experience
- **Modern package structure** following Python packaging best practices
- **Development mode installation** with `pip install -e .[dev]`
- **Comprehensive testing** with unit, integration, and configuration tests
- **Documentation generation** with Sphinx support
- **Code formatting** with automatic black and isort integration

### Changed

#### Installation Method
- **Primary installation** now via PyPI: `pip install sandroid`
- **Optional dependencies** for different use cases
- **Simplified setup** with automatic dependency resolution
- **Configuration initialization** as separate step for better user control

#### Configuration Architecture
- **Moved from hardcoded values** to external configuration files
- **Standardized configuration locations** following XDG specification
- **Environment variable standardization** with `SANDROID_` prefix
- **Hierarchical loading** allowing multiple configuration sources
- **Type validation** preventing configuration errors

#### Project Structure
- **New package layout** under `src/sandroid/` for proper packaging
- **Separated configuration system** into dedicated module
- **Modern CLI entry points** while preserving legacy script
- **Documentation organization** with dedicated setup and migration guides

### Maintained

#### Backward Compatibility
- **Legacy installation method** still fully supported
- **Existing CLI arguments** work unchanged
- **Legacy scripts** (`./sandroid`) continue to function
- **Existing workflows** require no immediate changes
- **Gradual migration path** with comprehensive guides

#### Core Functionality
- **All analysis capabilities** preserved without modification
- **Frida integration** unchanged
- **Android emulator support** maintained
- **Output formats** (JSON, PDF) unchanged
- **Ground truth APK** functionality preserved

#### Dependencies
- **Core dependencies** remain the same
- **Analysis modules** work without modification
- **Frida manager** integration preserved
- **ADB communication** unchanged

### Technical Details

#### Configuration Schema
```toml
# Example modern configuration
log_level = "INFO"
output_file = "sandroid.json"

[emulator]
device_name = "Pixel_6_Pro_API_31"
android_emulator_path = "~/Android/Sdk/emulator/emulator"

[analysis]
number_of_runs = 2
monitor_network = false
monitor_processes = true

[paths]
results_path = "./results/"
cache_path = "~/.cache/sandroid/"
```

#### Environment Variables
```bash
# All configuration can be set via environment variables
export SANDROID_LOG_LEVEL="DEBUG"
export SANDROID_EMULATOR__DEVICE_NAME="Custom_Device"
export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
export SANDROID_PATHS__RESULTS_PATH="/custom/results"
```

#### CLI Commands
```bash
# Modern installation and usage
pip install sandroid[ai,dev]
sandroid-config init
sandroid-config validate
sandroid --config production.toml --network --ai --report

# Configuration management
sandroid-config show --format toml
sandroid-config set analysis.monitor_network true
sandroid-config get emulator.device_name
```

### Migration Path

#### For New Users
1. Install via PyPI: `pip install sandroid`
2. Initialize configuration: `sandroid-config init`
3. Customize configuration as needed
4. Run analysis: `sandroid --help`

#### For Existing Users
1. Continue using legacy installation (no changes required)
2. When ready, install PyPI package alongside legacy
3. Use migration guide to transfer settings
4. Switch to modern CLI when convenient
5. Remove legacy installation when comfortable

### Dependencies

#### New Dependencies
- `pydantic>=2.0.0` - Configuration validation and type safety
- `platformdirs>=3.0.0` - XDG directory compliance
- `rich>=13.0.0` - Enhanced console output and formatting
- `tomli>=2.0.1` (Python <3.11) - TOML file parsing
- `tomli-w>=1.0.0` - TOML file writing
- `pyyaml>=6.0` - YAML configuration support

#### Optional Dependencies
- `[ai]` - Google Generative AI support
- `[dev]` - Development tools (pytest, black, isort, mypy, flake8)
- `[docs]` - Documentation generation tools (sphinx, themes)

### Breaking Changes
**None** - This release maintains full backward compatibility.

### Security
- **Secure credentials management** with dedicated configuration section
- **API key extraction** from source code to configuration files
- **Environment variable support** for sensitive configuration (API keys)
- **Configuration validation** prevents invalid or dangerous settings
- **Path validation** ensures secure file operations
- **Input sanitization** in configuration loading
- **GitLab token management** moved from hardcoded values to secure configuration

### Performance
- **Lazy loading** of configuration only when needed
- **Cached configuration** parsing for repeated access
- **Optimized dependency loading** with optional imports
- **Efficient file discovery** using XDG standard locations

### Documentation Updates
- **Complete SETUP.md** with step-by-step installation guide
- **Comprehensive MIGRATION.md** for upgrading from legacy
- **Updated development documentation** with modern development workflows
- **Configuration examples** for different use cases
- **Environment variable reference** documentation
- **Troubleshooting guides** for common issues
- **API documentation** for configuration schema

---

## Previous Versions

### [0.x.x] - Legacy Versions
- Original hardcoded configuration system
- Manual installation via `install-requirements.sh`
- Direct script execution with `./sandroid`
- Limited configuration options
- Basic CLI interface

---

## Migration Notes

### From Legacy to Modern
1. **No immediate action required** - legacy installation continues to work
2. **Try modern installation** alongside legacy for evaluation
3. **Use migration guide** when ready to switch
4. **Gradual migration** - move configurations over time
5. **Full backward compatibility** ensures no functionality loss

### Configuration Migration
- Use `sandroid-config init` to create modern configuration
- Transfer hardcoded values from `toolbox.py` to config files
- Replace custom environment variables with `SANDROID_` prefixed versions
- Validate new configuration with `sandroid-config validate`

### Development Migration
- Install development dependencies: `pip install -e .[dev]`
- Use modern testing: `pytest` instead of custom test scripts
- Apply code formatting: `black src/` and `isort src/`
- Add type hints using configuration schema as example

## Acknowledgments

This modernization maintains the core forensic analysis capabilities of Sandroid while providing a professional, maintainable foundation for future development. The extensive backward compatibility ensures existing users can migrate at their own pace while new users benefit from modern Python packaging and configuration practices.
