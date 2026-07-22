Configuration
=============

This guide covers Sandroid's comprehensive configuration system, including file formats, environment variables, and advanced configuration scenarios.

Quick Start
-----------

**Initialize Default Configuration:**

::

   sandroid-config init

This creates ``~/.config/sandroid/sandroid.toml`` with default settings.

**Basic Configuration:**

.. code-block:: toml

   log_level = "INFO"
   output_file = "analysis_results.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"

   [analysis]
   number_of_runs = 2
   monitor_network = false

   [paths]
   results_path = "./results/"

Configuration File Locations
-----------------------------

Sandroid searches for configuration files in this order:

1. **Current directory**: ``./sandroid.toml``, ``./config.toml``
2. **User config**: ``~/.config/sandroid/sandroid.toml``
3. **System config**: ``/etc/sandroid/sandroid.toml``

**Check Configuration Paths:**

::

   sandroid-config paths

Configuration Formats
---------------------

**TOML (Recommended)**

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

**YAML**

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

**JSON**

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
     }
   }

Configuration Sections
----------------------

Core Settings
~~~~~~~~~~~~~

.. code-block:: toml

   # Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
   log_level = "INFO"

   # Output file for analysis results
   output_file = "sandroid.json"

Emulator Configuration
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [emulator]
   # Android Virtual Device name
   device_name = "Pixel_6_Pro_API_31"

   # Path to Android emulator binary
   android_emulator_path = "~/Android/Sdk/emulator/emulator"

   # Path to AVD manager
   avd_manager_path = "~/Android/Sdk/cmdline-tools/latest/bin/avdmanager"

Frida Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [frida]
   # Frida server version (use "latest" for auto-download)
   server_version = "latest"

   # Installation path on device
   install_path = "/data/local/tmp/"

   # Connection timeout (seconds)
   timeout = 30

Analysis Settings
~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [analysis]
   # Number of analysis runs (minimum 2 for comparison)
   number_of_runs = 2

   # Monitor running processes
   monitor_processes = true

   # Capture network traffic
   monitor_network = false

   # Perform full filesystem scan for deleted files
   show_deleted_files = false

   # Calculate MD5 hashes for changed/new files
   calculate_hashes = false

   # List all installed APKs
   list_apks = false

   # Skip noise filtering (comprehensive analysis)
   avoid_noise_filter = false

Network Configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [network]
   # Enable network traffic capture
   capture_enabled = false

   # HTTP proxy configuration
   proxy_host = "127.0.0.1"
   proxy_port = 8080

   # Network interface for monitoring
   interface = "eth0"

Path Configuration
~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [paths]
   # Main results directory
   results_path = "./results/"

   # Raw analysis data
   raw_results_path = "./results/raw/"

   # Temporary files
   temp_path = "/tmp/sandroid/"

   # Cache directory
   cache_path = "~/.cache/sandroid/"

   # Log files location
   log_path = "~/.cache/sandroid/logs/"

TrigDroid Integration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [trigdroid]
   # Enable TrigDroid malware triggers
   enabled = false

   # Trigger execution timeout (seconds)
   timeout = 300

   # Trigger categories to execute
   trigger_sets = ["network", "filesystem", "permissions"]

Report Generation
~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [report]
   # Generate PDF reports
   generate_pdf = false

   # Include screenshots in reports
   include_screenshots = true

   # Include AI analysis in reports
   include_ai_analysis = true

   # Report template
   template = "default"

Feature Configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [features]
   # Screenshot interval (0 = disabled, >0 = seconds between screenshots)
   screenshot_interval = 0

   # Enable action recording
   recording_enabled = false

   # Maximum screenshot resolution
   max_screenshot_size = "1920x1080"

Environment Variables
---------------------

All configuration can be overridden with environment variables using the ``SANDROID_`` prefix:

**Basic Usage:**

.. code-block:: bash

   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_OUTPUT_FILE=custom_results.json

**Nested Configuration:**

Use double underscores (``__``) for nested values:

.. code-block:: bash

   export SANDROID_EMULATOR__DEVICE_NAME=Custom_Device
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
   export SANDROID_PATHS__RESULTS_PATH=/custom/path

**Boolean Values:**

.. code-block:: bash

   export SANDROID_ANALYSIS__MONITOR_NETWORK=true
   export SANDROID_REPORT__GENERATE_PDF=false

**Complete Example:**

.. code-block:: bash

   # Core settings
   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_OUTPUT_FILE=malware_analysis.json

   # Emulator
   export SANDROID_EMULATOR__DEVICE_NAME=Malware_Analysis_Device

   # Analysis settings
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=3
   export SANDROID_ANALYSIS__MONITOR_NETWORK=true
   export SANDROID_ANALYSIS__SHOW_DELETED_FILES=true
   export SANDROID_ANALYSIS__CALCULATE_HASHES=true

   # Features
   export SANDROID_FEATURES__SCREENSHOT_INTERVAL=5

   # AI and reporting
   export SANDROID_AI__ENABLED=true
   export SANDROID_AI__API_KEY=your_api_key_here
   export SANDROID_REPORT__GENERATE_PDF=true

Configuration Management
------------------------

**View Current Configuration:**

::

   sandroid-config show

**Validate Configuration:**

::

   sandroid-config validate

**Set Configuration Value:**

::

   sandroid-config set analysis.monitor_network true
   sandroid-config set emulator.device_name MyDevice

**Get Configuration Value:**

::

   sandroid-config get analysis.number_of_runs
   sandroid-config get paths.results_path

Configuration Templates
-----------------------

**Malware Analysis Configuration:**

.. code-block:: toml

   log_level = "DEBUG"
   output_file = "malware_analysis.json"

   [emulator]
   device_name = "Malware_Analysis_AVD"

   [analysis]
   number_of_runs = 3
   monitor_processes = true
   monitor_network = true
   show_deleted_files = true
   calculate_hashes = true
   avoid_noise_filter = true

   [features]
   screenshot_interval = 5

   [trigdroid]
   enabled = true
   timeout = 600

   [report]
   generate_pdf = true

**Development Testing Configuration:**

.. code-block:: toml

   log_level = "INFO"
   output_file = "dev_test_results.json"

   [emulator]
   device_name = "Development_Test_Device"

   [analysis]
   number_of_runs = 1
   monitor_processes = false
   monitor_network = false

   [features]
   screenshot_interval = 10

   [paths]
   results_path = "./dev_results/"

**Performance Testing Configuration:**

.. code-block:: toml

   log_level = "WARNING"
   output_file = "performance_results.json"

   [emulator]
   device_name = "Performance_Test_AVD"

   [analysis]
   number_of_runs = 1
   monitor_processes = true
   monitor_network = true

   [features]
   screenshot_interval = 30

   [network]
   capture_enabled = true

Environment-Specific Configuration
----------------------------------

**Development Environment:**

Create ``~/.config/sandroid/development.toml``:

.. code-block:: toml

   log_level = "DEBUG"

   [analysis]
   number_of_runs = 1

   [paths]
   results_path = "./dev_results/"

**Production Environment:**

Create ``~/.config/sandroid/production.toml``:

.. code-block:: toml

   log_level = "WARNING"

   [analysis]
   number_of_runs = 3
   monitor_network = true

   [report]
   generate_pdf = true

**Usage:**

::

   sandroid --environment development
   sandroid --environment production

Advanced Configuration
----------------------

**Custom Configuration Sections:**

.. code-block:: toml

   # Standard configuration
   log_level = "INFO"

   [analysis]
   number_of_runs = 2

   # Custom sections for extensions
   [custom]
   my_plugin_enabled = true
   my_plugin_timeout = 120

   [custom.advanced_settings]
   experimental_feature = false
   debug_mode = true

**Configuration Validation:**

.. code-block:: toml

   [analysis]
   # This will be validated (must be >= 2)
   number_of_runs = 2

   [paths]
   # This will be validated (directory must exist)
   results_path = "./results/"

**Security Configuration:**

.. code-block:: toml

   # Don't put sensitive values in config files
   # Use environment variables instead

   [ai]
   base_url = "https://api.example.com/v1"
   # api_key = ""  # Don't put API keys in files

.. code-block:: bash

   # Set sensitive values via environment
   export SANDROID_AI__API_KEY=your_secret_api_key

Troubleshooting Configuration
-----------------------------

**Configuration Not Found:**

.. code-block:: bash

   # Check search paths
   sandroid-config paths

   # Initialize if missing
   sandroid-config init

**Invalid Configuration:**

.. code-block:: bash

   # Validate configuration
   sandroid-config validate

   # Check for syntax errors
   python -c "import tomli; tomli.load(open('config.toml', 'rb'))"

**Environment Variables Not Working:**

.. code-block:: bash

   # Check environment variables
   env | grep SANDROID

   # Test variable format
   export SANDROID_LOG_LEVEL=DEBUG
   sandroid-config get log_level  # Should return DEBUG

**Configuration Priority Issues:**

Configuration loading priority:

1. Command-line arguments (highest)
2. Environment variables
3. Configuration file (--config)
4. Default configuration files
5. Built-in defaults (lowest)

**Debug Configuration Loading:**

::

   SANDROID_LOG_LEVEL=DEBUG sandroid --config my-config.toml

Integration with Tools
----------------------

**Docker Configuration:**

.. code-block:: dockerfile

   FROM sandroid:latest

   # Copy configuration
   COPY sandroid-docker.toml /app/config.toml

   # Set environment variables
   ENV SANDROID_PATHS__RESULTS_PATH=/app/results
   ENV SANDROID_LOG_LEVEL=INFO

   # Run with custom config
   CMD ["sandroid", "--config", "/app/config.toml"]

**CI/CD Configuration:**

.. code-block:: yaml

   # GitHub Actions example
   - name: Configure Sandroid
     run: |
       sandroid-config init
       sandroid-config set analysis.number_of_runs 1
       sandroid-config set features.screenshot_interval 10

   - name: Run Analysis
     env:
       SANDROID_AI__API_KEY: ${{ secrets.AI_API_KEY }}
     run: sandroid --network --report

**Batch Processing Configuration:**

.. code-block:: bash

   #!/bin/bash

   # Different configs for different analysis types
   sandroid --config malware-analysis.toml --trigdroid com.malware.app
   sandroid --config performance-test.toml --degrade-network
   sandroid --config development.toml --number 1

Best Practices
--------------

1. **Use configuration files** for consistent settings across runs
2. **Keep sensitive values** (API keys) in environment variables
3. **Validate configuration** before running analysis
4. **Use environment-specific configs** for different use cases
5. **Version control** configuration files (excluding secrets)
6. **Document custom** configuration sections
7. **Test configuration changes** before production use
8. **Use appropriate log levels** for different environments
9. **Set resource paths** correctly for your environment
10. **Monitor configuration** file sizes and complexity

See Also
--------

- :doc:`installation` - Initial configuration setup
- :doc:`quickstart` - Basic configuration for getting started
- :doc:`api/config` - Configuration API reference
- :doc:`troubleshooting` - Configuration-related troubleshooting
