Installation
============

Sandroid features a streamlined installation process with automatic Android environment setup.

🚀 Quick Start (Recommended)
-----------------------------

**One-Command Setup**

.. code-block:: bash

   # Install Sandroid from PyPI
   pip install sandroid

   # Initialize with automatic Android environment setup
   sandroid-config init

The ``sandroid-config init`` command provides:

- 🔍 **Automatic Android SDK detection**
- 📱 **AVD discovery and configuration**
- ⚙️ **Interactive setup** with validation
- 🎯 **Smart path detection** with user overrides
- ✅ **Ready-to-use configuration**

📋 Interactive Setup Experience
-------------------------------

When you run ``sandroid-config init``, the system will:

1. **Detect Android environment** - Find SDK, ADB, emulator paths
2. **Discover existing AVDs** - List available virtual devices
3. **Interactive selection** - Choose or create AVD for Sandroid
4. **Configure preferences** - Set UI/headless mode, auto-start options
5. **Validate setup** - Ensure everything works correctly

.. code-block:: bash

   $ sandroid-config init
   🔧 Initializing Sandroid configuration...

   🔍 Detecting Android development environment...
   ✓ Found Android SDK: /Users/user/Android/Sdk
   ✓ Found ADB: /opt/homebrew/bin/adb
   ✓ Found Android Emulator: /Users/user/Android/Sdk/emulator/emulator
   ✓ Found 3 AVDs: Pixel_6_Pro_API_31, Test_Device, sandroid_avd

   📱 Found 3 existing AVDs
   Choose an option:
     1. Pixel_6_Pro_API_31 (recommended)
     2. Test_Device
     3. sandroid_avd
     4. Create new 'sandroid' AVD
     5. Skip AVD configuration

   ✅ Configuration created successfully!

System Requirements
-------------------

**Prerequisites**

- Python 3.10 or newer
- Internet connection (for automated detection)
- Linux, macOS, or Windows (WSL2 recommended for Windows)

**Optional Dependencies**

.. code-block:: bash

   # With AI analysis support
   pip install sandroid[ai]

   # With development tools
   pip install sandroid[dev]

   # With documentation tools
   pip install sandroid[docs]

   # Install everything
   pip install sandroid[ai,dev,docs]
   adb version

3. Create an Android Virtual Device (AVD)::

   # List available AVDs
   emulator -list-avds

   # Create a new AVD (recommended: Pixel_6_Pro_API_31)
   avdmanager create avd -n Pixel_6_Pro_API_31 -k "system-images;android-31;google_apis;x86_64"

**System Dependencies**

**Linux (Ubuntu/Debian)**::

   sudo apt update
   sudo apt install -y sqlite3-tools python3-pip python3-dev build-essential

**Linux (CentOS/RHEL)**::

   sudo yum install -y sqlite python3-pip python3-devel gcc gcc-c++

**macOS**::

   # Using Homebrew
   brew install sqlite3

**Windows**::

   # Install SQLite tools from https://sqlite.org/download.html
   # Add to PATH

Legacy Installation (Still Supported)
--------------------------------------

For users who prefer the original installation method::

   git clone https://github.com/fkie-cad/Sandroid_core.git
   cd Sandroid_core
   ./install-requirements.sh
   ./sandroid.legacy

Configuration
-------------

After installation, initialize the configuration::

   sandroid-config init

This creates a configuration file at ``~/.config/sandroid/sandroid.toml``. Edit this file to customize:

.. code-block:: toml

   log_level = "INFO"
   output_file = "sandroid.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"
   android_emulator_path = "~/Android/Sdk/emulator/emulator"

   [analysis]
   number_of_runs = 2
   capture_processes = true
   capture_network = false

   [paths]
   results_path = "./results/"
   cache_path = "~/.cache/sandroid/"

Environment Variables
---------------------

All configuration can be overridden with environment variables::

   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_EMULATOR__DEVICE_NAME=Custom_Device
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
   export SANDROID_PATHS__RESULTS_PATH=/custom/results

Verification
------------

Test your installation::

   # Check version
   sandroid --version

   # Validate configuration
   sandroid-config validate

   # Test ADB connection (with emulator running)
   sandroid --help

   # Run in interactive mode
   sandroid

Docker Installation
-------------------

For containerized deployment::

   # Build Docker image
   ./build_and_export_docker.sh

   # Deploy with Docker
   cd deploy
   ./deploy /path/to/output

Troubleshooting
---------------

**Common Issues**

1. **"ADB not found"**
   - Ensure Android SDK is installed
   - Add ADB to your PATH
   - Test with ``adb version``

2. **"No emulator found"**
   - Create an AVD using Android Studio
   - Start the emulator before running Sandroid
   - Verify with ``adb devices``

3. **"Legacy analysis modules not available"**
   - This was fixed in v1.1.0
   - Upgrade with ``pip install --upgrade sandroid``

4. **Permission errors**
   - On Linux, ensure your user is in the correct groups::

     sudo usermod -a -G plugdev $USER

5. **SQLite tools missing**
   - Install sqlite3-tools package
   - Some features will be limited without it

**Getting Help**

- Check the troubleshooting guide: :doc:`troubleshooting`
- Report issues: https://github.com/fkie-cad/Sandroid_core/issues
- Review logs in ``~/.cache/sandroid/logs/``

Next Steps
----------

After installation:

1. :doc:`quickstart` - Quick introduction to Sandroid
2. :doc:`configuration` - Detailed configuration guide
3. :doc:`interactive_mode` - Learn the interactive interface
4. :doc:`command_line_usage` - Command-line options
