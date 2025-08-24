# Changelog

All notable changes to the Sandroid project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
