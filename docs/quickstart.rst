Quick Start Guide
=================

This guide will help you get up and running with Sandroid in minutes.

Prerequisites
-------------

Before starting, ensure you have:

1. **Sandroid installed** (see :doc:`installation`)
2. **Android emulator running** or physical device connected
3. **ADB working** - test with ``adb devices``

Basic Usage
-----------

**1. Initialize Configuration**::

   sandroid-config init

**2. Start Your Android Emulator**::

   # List available AVDs
   emulator -list-avds

   # Start an emulator
   emulator -avd Pixel_6_Pro_API_31 -no-snapshot

   # Verify connection
   adb devices

**3. Run Sandroid**::

   sandroid

Sandroid launches in the Textual TUI by default, providing a modern terminal user interface with three analysis views:

- **Forensic View**: File system analysis, artifact extraction, action recording
- **Malware View**: Behavioral analysis, Dexray-Intercept monitoring, memory dumping
- **Security View**: Vulnerability scanning and security testing (early stage)

Use ``TAB`` to switch between views and single-key shortcuts to execute commands.

For the legacy Rich interactive menu, use::

   sandroid -i

First Analysis - Recording User Actions
---------------------------------------

**1. Install Frida Server** (if needed for dynamic analysis)

   Sandroid will automatically prompt you to install Frida when a command requires it. You can also manually install it by pressing ``f`` in the TUI.

**2. Record User Interactions**::

   # In interactive mode, press 'r'
   r

   # This will:
   # - Take a baseline snapshot of the system
   # - Start monitoring file changes, processes, and network
   # - Wait for you to interact with the device

**3. Perform Actions on Device**

   - Install an APK
   - Open apps, interact with them
   - Browse, use features
   - When done, press Enter in the Sandroid terminal

**4. View Results**

   Sandroid will analyze the changes and show:

   - **New files** created during your actions
   - **Changed files** and their differences
   - **Network connections** made
   - **Processes** that ran
   - **Screenshots** taken during analysis

Command-Line Analysis
---------------------

For automated analysis without interaction::

   # Basic analysis with 2 runs
   sandroid --number 2

   # Network monitoring with screenshots every 5 seconds
   sandroid --network --screenshot 5

   # Complete analysis with all features
   sandroid --network --sockets --screenshot 3 --hash --apk --report

Configuration Examples
----------------------

**Basic Configuration**

Create ``~/.config/sandroid/sandroid.toml``::

   log_level = "INFO"
   output_file = "analysis_results.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"

   [analysis]
   number_of_runs = 2
   capture_processes = true

**Security Analysis Configuration**::

   log_level = "DEBUG"

   [analysis]
   number_of_runs = 3
   capture_network = true
   capture_processes = true
   show_deleted_files = true

   [features]
   screenshot_interval = 5
   enable_hash_calculation = true
   list_apks = true

Common Workflows
----------------

**Malware Analysis Workflow**

1. **Setup**::

      sandroid-config init
      # Edit config for malware analysis
      sandroid-config set analysis.capture_network true
      sandroid-config set log_level DEBUG

2. **Start Analysis**::

      sandroid --trigdroid com.suspicious.app --network --screenshot 3

3. **Install and Run Malware**::

      # Use TrigDroid for automated trigger execution
      # Or manually install and interact with suspicious APK

4. **Generate Report**::

      sandroid --report

**App Development Testing**

1. **Configure for Development**::

      sandroid-config set analysis.number_of_runs 1
      sandroid-config set paths.results_path ./test_results/

2. **Test Your App**::

      sandroid --number 1 --screenshot 2

3. **Monitor Specific App**::

      # Set spotlight app in interactive mode
      # Press 'c' to set current foreground app as spotlight

Understanding Results
---------------------

**Output Files**

- ``sandroid.json`` - Complete analysis results
- ``results/`` - Raw data and screenshots
- ``sandroid.pdf`` - Generated report (with --report)
- ``sandroid.log`` - Detailed execution logs

**Key Result Sections**

- **Changed Files**: Files modified during analysis
- **New Files**: Files created during analysis
- **Network**: Connections and traffic captured
- **Processes**: Applications and services that ran
- **Static Analysis**: APK information and metadata

**Example Results**::

   {
     "Changed Files": [
       {"/data/data/com.app/shared_prefs/settings.xml": [
         "- <string name=\"user_id\">old_value</string>",
         "+ <string name=\"user_id\">new_value</string>"
       ]}
     ],
     "New Files": [
       "/sdcard/Download/malware_payload.bin",
       "/data/data/com.app/files/config.json"
     ],
     "Network": {
       "connections": ["192.168.1.100:8080", "malicious-c2.com:443"],
       "dns_queries": ["api.legitimate-service.com", "tracking.ads.com"]
     }
   }

Next Steps
----------

Now that you've completed your first analysis:

1. **Learn Interactive Mode**: :doc:`interactive_mode`
2. **Explore Command-Line Options**: :doc:`command_line_usage`
3. **Configure for Your Needs**: :doc:`configuration`
4. **Handle Issues**: :doc:`troubleshooting`
5. **Advanced Features**: :doc:`advanced/custom_analysis`

Tips for Better Analysis
-------------------------

**Performance Tips**

- Use SSDs for faster file system monitoring
- Close unnecessary applications during analysis
- Use ``--avoid-strong-noise-filter`` for comprehensive analysis

**Accuracy Tips**

- Run multiple analysis iterations (``--number 3``)
- Use clean snapshots as baselines
- Allow sufficient time between actions for monitoring

**Security Tips**

- Use isolated emulators for malware analysis
- Enable network monitoring for suspicious apps
- Use AI analysis for automated threat detection

**Troubleshooting Tips**

- Check ADB connection: ``adb devices``
- Verify emulator is rooted for advanced features
- Monitor logs: ``tail -f ~/.cache/sandroid/logs/sandroid.log``
