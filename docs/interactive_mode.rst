Interactive Mode
================

Sandroid's interactive mode provides a user-friendly menu-driven interface for performing forensic analysis. This mode is perfect for manual analysis, learning the tool, and complex investigations requiring multiple steps.

Starting Interactive Mode
--------------------------

Sandroid has two interactive modes:

**Default: Textual TUI** (recommended)::

   sandroid

The Textual TUI provides a modern terminal user interface with three specialized analysis views (Forensic, Malware, Security), a status bar, activity log, and keyboard-driven navigation.

**Legacy: Rich Interactive Menu**::

   sandroid -i
   sandroid --interactive

The legacy Rich mode provides the classic single-page menu interface.

**With Custom Configuration**::

   sandroid --config my-analysis.toml
   sandroid --config my-analysis.toml -i   # For legacy mode

The Textual TUI
-----------------

When you start Sandroid (without ``-i``), the Textual TUI launches with:

- **Header Bar**: Shows Sandroid logo and current view mode
- **Status Bar**: Displays Frida server status, HTTP proxy, spotlight app, and spotlight files
- **Menu Panel**: Lists available commands organized by category for the current view
- **Activity Log**: Shows real-time command output and status messages
- **Footer**: Keyboard shortcuts (TAB to switch views, Q to quit)

Three Analysis Views
~~~~~~~~~~~~~~~~~~~~~

The TUI provides three specialized views, each with its own set of commands. Switch between views using the ``TAB`` key.

**Forensic View**
   Focus on forensic artifact extraction and file system analysis:
   - Record and playback user actions
   - File system monitoring with fsmon
   - Spotlight file management
   - Screenshot and video capture
   - Forensic evidence scanning (MVT)
   - Manage forensic APKs

**Malware View**
   Focus on malware behavioral analysis and instrumentation:
   - Dexray-Intercept malware monitoring (formerly AM3)
   - Dexray-Insight static analysis (formerly asam)
   - Memory dumping with Fridump
   - TrigDroid malware triggers
   - Objection interactive shell
   - FriTap SSL/TLS interception

**Security View** *(Early Stage)*
   Focus on vulnerability scanning and security testing:
   - Network proxy management
   - Device settings and presets
   - Security-focused analysis tools

   .. note::
      The Security view is in early development. Features are functional but the command set is still expanding.

Command Reference
-------------------

Action Recording & Playback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**[r] Record an Action**
   Records user interactions and system changes:

   1. Takes a baseline snapshot of the system
   2. Starts monitoring file system changes, network connections, processes, and sockets
   3. Waits for user interaction with the device
   4. Analyzes changes when you press Enter

**[p] Play Currently Loaded Action**
   Replays a previously recorded action sequence for regression testing.

**[x] Export Currently Loaded Action**
   Saves recorded actions to a file for sharing or backup.

**[i] Import Action**
   Loads previously saved action recordings.

Spotlight Application
~~~~~~~~~~~~~~~~~~~~~

**[c] / [C] Set Spotlight App**
   - ``c``: Detect and set the foreground application as spotlight
   - ``C``: Spawn a new application as spotlight (select from installed apps)

**[a] Analyze with Dexray-Insight**
   Performs static analysis of the spotlight app's APK using Dexray-Insight (formerly asam).

**[d] Dump Memory (Fridump)**
   Uses Fridump to extract memory contents of the spotlight app.

**[m] Dexray-Intercept Malware Monitor**
   Start Dexray-Intercept dynamic hooking on the spotlight app (formerly Android Malware Motion Monitor / AM3). Intercepts sensitive data flows, network traffic, and runtime behaviors.

**[b] / [O] Objection Shell**
   - ``b``: Launch objection interactive shell for the spotlight app
   - ``O``: Resume a previous objection session

**[t] TrigDroid Malware Triggers**
   Automatically execute malware trigger conditions for the spotlight app.

Spotlight Files & Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**[l] List/Add Spotlight Files**
   Add files on the device to monitor for changes.

**[v] Remove Spotlight File**
   Remove files from the monitoring list.

**[u] Pull Spotlight Files**
   Download monitored files from the device.

**[o] File System Monitor (fsmon)**
   Real-time file system change monitoring with timestamps.

**[F] Forensic Evidence Scan**
   Run MVT (Mobile Verification Toolkit) forensic evidence scanning using configured IOCs.

**[G] Manage Forensic APKs**
   Manage APKs used for forensic testing and analysis.

Device & Emulator Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**[e] / [E] Device Information & Settings**
   - ``e``: Show emulator/device information
   - ``E``: Apply device settings (locale, timezone, country presets)

**[1-8] Create Snapshots**
   Save current emulator state for quick rollback.

**[0] List/Load Snapshots**
   Manage and restore saved snapshots.

**[s] Take Screenshot**
   Capture the current device screen.

**[g] Grab Video**
   Record screen activity.

**[n] Install APK**
   Install applications for analysis.

**[f] Frida Server Management**
   Download, install, and manage the Frida server on the device.

**[k] Reconfigure Hooks**
   Reconfigure Frida hook settings for the current session.

Network Management
~~~~~~~~~~~~~~~~~~

**[y] Network Proxy**
   Configure or clear HTTP/HTTPS proxy on the device.

**[h] FriTap SSL/TLS Hooking**
   Hook encryption routines for SSL/TLS traffic decryption.

**[w] Write Network Capture**
   Save network traffic to PCAP files.

Step-by-Step Workflows
----------------------

Basic Analysis Workflow
~~~~~~~~~~~~~~~~~~~~~~~~

1. **Initialize Frida** (if not running)::

   Press 'f' → Install and start Frida server

2. **Start Recording**::

   Press 'r' → Begin monitoring system changes

3. **Perform Analysis Target Actions**

   - Install and run the target application
   - Interact with features you want to analyze
   - Generate the behaviors you want to capture

4. **Complete Analysis**

   Press Enter → Stop recording and generate results

5. **Review Results**

   Examine the generated JSON report and logs

Malware Analysis Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Setup Baseline**::

   Press '1' → Create clean snapshot

2. **Install Frida**::

   Press 'f' → Install Frida server

3. **Set Spotlight App**::

   # Install malware APK first
   Press 'n' → Install malware APK
   Press 'c' → Set as spotlight app

4. **Configure Network Monitoring**::

   Press 'y' → Set up proxy (optional)
   Press 'h' → Enable friTap for SSL interception

5. **Execute Triggers**::

   Press 't' → Run TrigDroid automated triggers

6. **Monitor Behavior**::

   Press 'm' → Start malware motion monitor

7. **Capture Evidence**::

   Press 's' → Take screenshots
   Press 'w' → Save network capture

8. **Memory Analysis**::

   Press 'd' → Dump memory for analysis

9. **Clean Up**::

   Press '0' → Restore clean snapshot

App Development Testing Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Install Development APK**::

   Press 'n' → Install your APK

2. **Set as Spotlight**::

   Press 'c' → Set your app as spotlight

3. **Record User Flows**::

   Press 'r' → Record specific user interactions

4. **Static Analysis**::

   Press 'a' → Analyze APK structure and permissions

5. **Export Test Cases**::

   Press 'x' → Export recorded interactions for regression testing

Status Indicators
-----------------

The menu shows real-time status information:

**Frida Server Status**
   - ``[Running]`` - Frida server is active and ready
   - ``[Not running]`` - Frida server needs to be started

**HTTP Proxy Status**
   - ``[Set]`` - Network proxy is configured
   - ``[Not set]`` - No proxy configuration

**Spotlight Application**
   - Shows package name of currently monitored app
   - ``[Not set]`` if no app is being monitored

**Spotlight Files**
   - Number of files being monitored
   - ``[Not set]`` if no files are being watched

Tips for Interactive Mode
--------------------------

**Best Practices**

1. **Start with Frida**: Always install Frida server first for dynamic analysis
2. **Use Snapshots**: Create clean snapshots before analysis for repeatability
3. **Set Spotlight Apps**: Focus analysis on specific applications for better results
4. **Monitor Network**: Enable network monitoring for comprehensive analysis
5. **Take Screenshots**: Document your analysis with visual evidence

**Performance Tips**

1. **Clean Baselines**: Use fresh snapshots to avoid noise from previous analysis
2. **Focused Monitoring**: Only monitor specific files/apps when possible
3. **Resource Management**: Close unnecessary apps during analysis

**Troubleshooting**

1. **Frida Connection Issues**: Restart Frida server with 'f'
2. **No Device Detected**: Check ADB connection with 'e'
3. **Permission Errors**: Ensure device is rooted for advanced features
4. **Slow Performance**: Create a new snapshot and restart analysis

**Advanced Tips**

1. **Combine Tools**: Use objection ('b') with memory dumping ('d') for comprehensive analysis
2. **Automate Triggers**: Use TrigDroid ('t') for consistent malware activation
3. **Network Analysis**: Combine proxy ('y') with friTap ('h') for complete traffic visibility
4. **Evidence Chain**: Use screenshots ('s') and network capture ('w') to document findings

Keyboard Shortcuts
------------------

All commands use single-key shortcuts. Available keys depend on the current view:

- **Navigation**: ``TAB`` (switch views), ``q`` (quit)
- **Recording**: ``r``, ``p``, ``x``, ``i``
- **App Analysis**: ``c``, ``C``, ``a``, ``d``, ``m``, ``b``, ``O``, ``t``
- **File Monitoring**: ``l``, ``v``, ``u``, ``o``, ``F``, ``G``
- **Device Management**: ``e``, ``E``, ``1-8``, ``0``, ``s``, ``g``, ``n``, ``f``, ``k``
- **Network**: ``y``, ``h``, ``w``

Configuration in Interactive Mode
----------------------------------

Interactive mode respects your configuration file settings. You can:

1. **Modify behavior** with environment variables::

   SANDROID_LOG_LEVEL=DEBUG sandroid

2. **Use different configs**::

   sandroid --config analysis-config.toml

3. **Override settings**::

   sandroid --network --screenshot 5

The interactive mode will honor these settings while providing the menu interface.

Getting Help
------------

- Press ``q`` to quit safely
- Check logs at ``~/.cache/sandroid/logs/`` for detailed information
- Use ``sandroid --help`` for command-line options
- See :doc:`troubleshooting` for common issues
