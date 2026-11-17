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

Without a terminal (scripts, CI, ``docker run`` without ``-t``) or with
``--yes``, ``sandroid-config init`` asks nothing: it uses the detected paths,
the first existing AVD and default settings.

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

- **Python 3.12 or 3.13** (Python 3.10/3.11 are not supported since 2.1)
- Android SDK platform-tools (``adb``) and the Android Emulator
- A **rooted** Android emulator with snapshots enabled (see below)
- Internet connection (for automated detection and tool downloads)
- Linux or macOS (Windows: WSL2 recommended)

**Optional Dependencies**

.. code-block:: bash

   # Static-analysis extras (dexray-insight, androguard)
   pip install "sandroid[full]"

   # Development install from a source checkout (tests, linters)
   pip install -e ".[dev,full]"

   # Documentation tools
   pip install "sandroid[docs]"

.. _device-requirements:

Device Requirements
-------------------

Sandroid needs **root on the device**: it runs ``adb root``, pushes and starts
``frida-server``, injects CA certificates into the system trust store and sets
SELinux to *permissive* (``setenforce 0``) itself. Two emulator setups are
known to work:

1. **Google APIs image** (simplest) -- a ``google_apis`` system image (*not*
   ``google_apis_playstore``); ``adb root`` works out of the box::

      sdkmanager "system-images;android-35;google_apis;arm64-v8a"   # or x86_64
      avdmanager create avd -n sandroid_api35 \
          -k "system-images;android-35;google_apis;arm64-v8a" -d pixel_6

2. **Google Play image rooted with rootAVD** -- root a Play Store image with
   `rootAVD <https://gitlab.com/newbit/rootAVD>`_ (Magisk) and install the
   **Magisk** ``adb_root`` **module**, so that ``adbd`` runs as root (Play
   images otherwise refuse ``adb root`` as production builds). This is how the
   Sandroid team's own AVDs are set up.

Verify root with ``adb root && adb shell id`` (must report ``uid=0(root)``).

**Snapshots are required** for the Record/Play workflow and the snapshot picker (``S``).
Do not start the emulator with ``-no-snapshot``; use ``-no-snapshot-save`` if
you do not want the quick-boot snapshot overwritten, or start it with
``sandroid-config avd start``.

**Physical devices** (rooted) are only partially supported: snapshots,
emulator-console network capture and ``--degrade-network`` are unavailable.

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

A Dockerfile is provided on a **best-effort** basis (not tested in CI); the
emulator keeps running on the host. See :doc:`advanced/docker_deployment`.

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

3. **"adbd cannot run as root in production builds"**
   - You are using a Google Play image without root
   - Use a ``google_apis`` image or root the AVD (see :ref:`device-requirements`)

4. **Permission errors**
   - On Linux, ensure your user is in the correct groups::

     sudo usermod -a -G plugdev $USER

5. **SQLite tools missing**
   - Install sqlite3-tools package
   - Some features will be limited without it

**Getting Help**

- Check the troubleshooting guide: :doc:`troubleshooting`
- Report issues: https://github.com/fkie-cad/Sandroid_core/issues
- Review the session logs in ``./results/<timestamp>/sandroid.log`` and ``sandroid_error.log``

Next Steps
----------

After installation:

1. :doc:`quickstart` - Quick introduction to Sandroid
2. :doc:`configuration` - Detailed configuration guide
3. :doc:`interactive_mode` - Learn the interactive interface
4. :doc:`command_line_usage` - Command-line options
