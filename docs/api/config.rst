Configuration API
=================

The Sandroid configuration system provides robust, type-safe configuration management with support for multiple file formats, environment variables, and validation.

Configuration Schema
--------------------

.. automodule:: sandroid.config.schema
   :members:
   :undoc-members:
   :show-inheritance:

The configuration schema defines the structure and validation rules for Sandroid configuration using Pydantic models.

**Main Configuration Class:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig

   # Load configuration with validation
   config = SandroidConfig.from_file("config.toml")

   # Access configuration values
   print(f"Log level: {config.log_level}")
   print(f"Device name: {config.emulator.device_name}")
   print(f"Results path: {config.paths.results_path}")

Configuration Loader
--------------------

.. automodule:: sandroid.config.loader
   :members:
   :undoc-members:
   :show-inheritance:

The configuration loader handles file discovery, parsing, and environment variable integration.

**Key Features:**

- XDG Base Directory compliance
- Multi-format support (TOML, YAML, JSON)
- Environment variable override
- Hierarchical configuration loading
- Validation and error reporting

**Basic Usage:**

.. code-block:: python

   from sandroid.config.loader import load_config, find_config_file

   # Load configuration from default locations
   config = load_config()

   # Load specific configuration file
   config = load_config("custom-config.toml")

   # Find configuration file path
   config_path = find_config_file()
   print(f"Using config: {config_path}")

Configuration CLI
-----------------

.. automodule:: sandroid.config.cli
   :members:
   :undoc-members:
   :show-inheritance:

Command-line interface for configuration management.

**Available Commands:**

- ``sandroid-config init`` - Create default configuration
- ``sandroid-config show`` - Display current configuration
- ``sandroid-config validate`` - Validate configuration files
- ``sandroid-config set`` - Modify configuration values
- ``sandroid-config get`` - Retrieve configuration values
- ``sandroid-config paths`` - Show configuration file locations

**Usage Examples:**

.. code-block:: bash

   # Initialize configuration
   sandroid-config init

   # Show current configuration
   sandroid-config show

   # Validate configuration
   sandroid-config validate

   # Set configuration value
   sandroid-config set analysis.number_of_runs 5

   # Get configuration value
   sandroid-config get emulator.device_name

Configuration Structure
-----------------------

**Complete Configuration Schema:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig

   # Example complete configuration
   config_data = {
       "log_level": "INFO",
       "output_file": "analysis_results.json",

       "emulator": {
           "device_name": "Pixel_6_Pro_API_31",
           "android_emulator_path": "~/Android/Sdk/emulator/emulator",
           "avd_manager_path": "~/Android/Sdk/cmdline-tools/latest/bin/avdmanager"
       },

       "frida": {
           "server_version": "latest",
           "install_path": "/data/local/tmp/",
           "timeout": 30
       },

       "network": {
           "capture_enabled": False,
           "proxy_host": None,
           "proxy_port": None,
           "interface": "eth0"
       },

       "paths": {
           "results_path": "./results/",
           "raw_results_path": "./results/raw/",
           "temp_path": "/tmp/sandroid/",
           "cache_path": "~/.cache/sandroid/",
           "log_path": "~/.cache/sandroid/logs/"
       },

       "analysis": {
           "number_of_runs": 2,
           "monitor_processes": True,
           "monitor_network": False,
           "show_deleted_files": False,
           "calculate_hashes": False,
           "list_apks": False,
           "avoid_noise_filter": False
       },

       "trigdroid": {
           "enabled": False,
           "timeout": 300,
           "trigger_sets": ["network", "filesystem", "permissions"]
       },

       "ai": {
           "enabled": False,
           "provider": "google",
           "model": "gemini-pro",
           "api_key": None,
           "temperature": 0.7
       },

       "report": {
           "generate_pdf": False,
           "include_screenshots": True,
           "include_ai_analysis": True,
           "template": "default"
       },

       "features": {
           "screenshot_interval": 0,
           "recording_enabled": False,
           "max_screenshot_size": "1920x1080"
       },

       "custom": {}  # For user extensions
   }

   # Create and validate configuration
   config = SandroidConfig(**config_data)

Environment Variables
---------------------

**Environment Variable Mapping:**

All configuration values can be set via environment variables using the ``SANDROID_`` prefix:

.. code-block:: python

   import os
   from sandroid.config.loader import load_config

   # Set environment variables
   os.environ['SANDROID_LOG_LEVEL'] = 'DEBUG'
   os.environ['SANDROID_EMULATOR__DEVICE_NAME'] = 'Custom_Device'
   os.environ['SANDROID_ANALYSIS__NUMBER_OF_RUNS'] = '5'
   os.environ['SANDROID_PATHS__RESULTS_PATH'] = '/custom/results'

   # Load configuration (environment variables override file settings)
   config = load_config()

   print(f"Log level: {config.log_level}")  # DEBUG
   print(f"Device: {config.emulator.device_name}")  # Custom_Device
   print(f"Runs: {config.analysis.number_of_runs}")  # 5

**Environment Variable Format:**

- Use double underscores (``__``) for nested configuration
- All uppercase for variable names
- Prefix with ``SANDROID_``

.. code-block:: bash

   # Basic configuration
   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_OUTPUT_FILE=custom_results.json

   # Nested configuration
   export SANDROID_EMULATOR__DEVICE_NAME=Pixel_8_API_34
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=3
   export SANDROID_PATHS__RESULTS_PATH=/tmp/analysis

   # Boolean values
   export SANDROID_ANALYSIS__MONITOR_NETWORK=true
   export SANDROID_REPORT__GENERATE_PDF=false

Configuration File Formats
---------------------------

**TOML Format (Recommended):**

.. code-block:: toml

   log_level = "INFO"
   output_file = "sandroid.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"
   android_emulator_path = "~/Android/Sdk/emulator/emulator"

   [analysis]
   number_of_runs = 2
   monitor_processes = true
   monitor_network = false

   [paths]
   results_path = "./results/"
   cache_path = "~/.cache/sandroid/"

   [ai]
   enabled = false
   provider = "google"
   model = "gemini-pro"

**YAML Format:**

.. code-block:: yaml

   log_level: INFO
   output_file: sandroid.json

   emulator:
     device_name: Pixel_6_Pro_API_31
     android_emulator_path: ~/Android/Sdk/emulator/emulator

   analysis:
     number_of_runs: 2
     monitor_processes: true
     monitor_network: false

   paths:
     results_path: ./results/
     cache_path: ~/.cache/sandroid/

**JSON Format:**

.. code-block:: json

   {
     "log_level": "INFO",
     "output_file": "sandroid.json",
     "emulator": {
       "device_name": "Pixel_6_Pro_API_31",
       "android_emulator_path": "~/Android/Sdk/emulator/emulator"
     },
     "analysis": {
       "number_of_runs": 2,
       "monitor_processes": true,
       "monitor_network": false
     },
     "paths": {
       "results_path": "./results/",
       "cache_path": "~/.cache/sandroid/"
     }
   }

Configuration Loading Priority
------------------------------

Configuration values are loaded in the following priority order (highest to lowest):

1. **Command-line arguments**
2. **Environment variables** (``SANDROID_*``)
3. **Configuration file** (specified with ``--config``)
4. **Default configuration files** (in search order):
   - ``./sandroid.toml`` (current directory)
   - ``./config.toml`` (current directory)
   - ``~/.config/sandroid/sandroid.toml`` (user config)
   - ``/etc/sandroid/sandroid.toml`` (system config)
5. **Default values** (hardcoded in schema)

**Search Path Example:**

.. code-block:: python

   from sandroid.config.loader import get_config_search_paths

   # Get configuration search paths
   search_paths = get_config_search_paths()
   for path in search_paths:
       print(f"Searching: {path}")

Configuration Validation
-------------------------

**Automatic Validation:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig
   from pydantic import ValidationError

   try:
       # This will validate all fields
       config = SandroidConfig.from_file("config.toml")
       print("Configuration is valid")

   except ValidationError as e:
       print("Configuration validation failed:")
       for error in e.errors():
           print(f"- {error['loc']}: {error['msg']}")

**Manual Validation:**

.. code-block:: python

   from sandroid.config.loader import validate_config_file

   # Validate configuration file
   is_valid, errors = validate_config_file("config.toml")

   if is_valid:
       print("✅ Configuration is valid")
   else:
       print("❌ Configuration validation failed:")
       for error in errors:
           print(f"- {error}")

**Field Validation Rules:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig
   from pydantic import Field, validator

   class CustomConfig(SandroidConfig):
       # Add custom validation
       @validator('analysis.number_of_runs')
       def validate_runs(cls, v):
           if v < 2:
               raise ValueError('number_of_runs must be at least 2')
           return v

       @validator('paths.results_path')
       def validate_results_path(cls, v):
           if not os.path.exists(os.path.dirname(v)):
               raise ValueError(f'Results directory does not exist: {v}')
           return v

Dynamic Configuration
---------------------

**Runtime Configuration Updates:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig
   from sandroid.config.loader import load_config, save_config

   # Load current configuration
   config = load_config()

   # Modify configuration
   config.analysis.number_of_runs = 5
   config.analysis.monitor_network = True
   config.log_level = "DEBUG"

   # Save updated configuration
   save_config(config, "updated_config.toml")

   # Reload to verify
   updated_config = load_config("updated_config.toml")
   print(f"Updated runs: {updated_config.analysis.number_of_runs}")

**Configuration Templates:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig

   def create_malware_analysis_config():
       """Create configuration optimized for malware analysis"""

       config = SandroidConfig()

       # Malware analysis settings
       config.log_level = "DEBUG"
       config.analysis.number_of_runs = 3
       config.analysis.monitor_network = True
       config.analysis.show_deleted_files = True
       config.analysis.calculate_hashes = True
       config.analysis.avoid_noise_filter = True

       # Enhanced monitoring
       config.features.screenshot_interval = 5
       config.trigdroid.enabled = True
       config.trigdroid.timeout = 600

       # AI analysis
       config.ai.enabled = True
       config.report.generate_pdf = True

       return config

   def create_development_config():
       """Create configuration for app development testing"""

       config = SandroidConfig()

       # Development settings
       config.log_level = "INFO"
       config.analysis.number_of_runs = 1
       config.analysis.monitor_processes = False
       config.features.screenshot_interval = 10

       # Faster analysis
       config.analysis.avoid_noise_filter = False
       config.paths.results_path = "./dev_results/"

       return config

   # Usage
   malware_config = create_malware_analysis_config()
   dev_config = create_development_config()

Configuration Integration
-------------------------

**Using Configuration in Analysis:**

.. code-block:: python

   from sandroid.config.loader import load_config
   from sandroid.core.toolbox import Toolbox
   from sandroid.analysis.network import Network
   from sandroid.features.screenshot import Screenshot

   def run_configured_analysis():
       """Run analysis using configuration settings"""

       # Load configuration
       config = load_config()

       # Configure toolbox
       Toolbox.configure(config)

       # Configure network monitoring
       if config.analysis.monitor_network:
           network_monitor = Network()
           network_monitor.configure(config.network)
           network_monitor.gather()

       # Configure screenshots
       if config.features.screenshot_interval > 0:
           screenshot = Screenshot()
           screenshot.set_interval(config.features.screenshot_interval)
           screenshot.run()

       # Run analysis with configured parameters
       return Toolbox.run_analysis(
           runs=config.analysis.number_of_runs,
           monitor_processes=config.analysis.monitor_processes
       )

**Configuration-Aware Classes:**

.. code-block:: python

   from sandroid.config.loader import load_config
   from sandroid.config.schema import SandroidConfig

   class ConfigurableAnalyzer:
       def __init__(self, config: SandroidConfig = None):
           self.config = config or load_config()

       def run_analysis(self):
           """Run analysis using configuration settings"""

           # Use configuration values
           runs = self.config.analysis.number_of_runs
           monitor_network = self.config.analysis.monitor_network

           print(f"Running {runs} analysis iterations")
           print(f"Network monitoring: {'enabled' if monitor_network else 'disabled'}")

           # Implementation here...

Configuration Extensions
------------------------

**Custom Configuration Sections:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig
   from pydantic import BaseModel
   from typing import Dict, Any

   class CustomAnalysisConfig(BaseModel):
       custom_timeout: int = 300
       custom_flags: Dict[str, Any] = {}
       special_mode: bool = False

   class ExtendedSandroidConfig(SandroidConfig):
       custom_analysis: CustomAnalysisConfig = CustomAnalysisConfig()

   # Usage
   config_data = {
       "log_level": "INFO",
       "custom_analysis": {
           "custom_timeout": 600,
           "custom_flags": {"experimental": True},
           "special_mode": True
       }
   }

   config = ExtendedSandroidConfig(**config_data)
   print(f"Custom timeout: {config.custom_analysis.custom_timeout}")

**Plugin Configuration:**

.. code-block:: python

   from sandroid.config.schema import SandroidConfig

   def load_plugin_config(plugin_name: str, config: SandroidConfig):
       """Load configuration for a specific plugin"""

       plugin_config = config.custom.get(plugin_name, {})

       # Apply plugin-specific defaults
       defaults = {
           'enabled': True,
           'timeout': 120,
           'options': {}
       }

       # Merge with defaults
       for key, value in defaults.items():
           plugin_config.setdefault(key, value)

       return plugin_config

   # Usage
   config = load_config()
   my_plugin_config = load_plugin_config('my_plugin', config)

Error Handling
--------------

**Configuration Error Handling:**

.. code-block:: python

   from sandroid.config.loader import load_config
   from sandroid.config.schema import ConfigurationError
   from pydantic import ValidationError
   import logging

   logger = logging.getLogger(__name__)

   def safe_load_config(config_path=None):
       """Safely load configuration with comprehensive error handling"""

       try:
           config = load_config(config_path)
           logger.info("Configuration loaded successfully")
           return config

       except FileNotFoundError as e:
           logger.error(f"Configuration file not found: {e}")
           logger.info("Using default configuration")
           return SandroidConfig()  # Return default config

       except ValidationError as e:
           logger.error("Configuration validation failed:")
           for error in e.errors():
               logger.error(f"- {'.'.join(str(x) for x in error['loc'])}: {error['msg']}")
           raise ConfigurationError("Invalid configuration") from e

       except Exception as e:
           logger.error(f"Unexpected error loading configuration: {e}")
           raise ConfigurationError("Configuration loading failed") from e

Best Practices
--------------

1. **Use TOML format** for human-readable configuration files
2. **Validate configuration** before running analysis
3. **Use environment variables** for sensitive values (API keys)
4. **Create configuration templates** for common use cases
5. **Document custom configuration** sections
6. **Version configuration files** for reproducibility
7. **Use XDG-compliant paths** for configuration storage
8. **Handle configuration errors gracefully**
9. **Provide sensible defaults** for all configuration values
10. **Test configuration changes** before production use

See Also
--------

- :doc:`core` - Core API using configuration
- :doc:`analysis` - Analysis modules configuration
- :doc:`features` - Feature modules configuration
- :doc:`../configuration` - Detailed configuration guide
- :doc:`../installation` - Configuration during installation
