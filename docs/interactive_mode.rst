Interactive Mode
================

Sandroid's interactive mode provides a user-friendly menu-driven interface for performing forensic analysis. This mode is perfect for manual analysis, learning the tool, and complex investigations requiring multiple steps.

Starting Interactive Mode
--------------------------

**Launch Interactive Mode**::

   sandroid

or explicitly::

   sandroid --interactive

**With Custom Configuration**::

   sandroid --config my-analysis.toml --interactive

The Interactive Menu
---------------------

When you start interactive mode, you'll see the main menu:

.. code-block:: text

   ┌───────────────────────────────────────────────────────────────────────┐
   │                       Sandroid Interactive Menu                       │
   ├───────────────────────────────────────────────────────────────────────┤
   │Frida Server: [Not running]                                            │
   │HTTP Proxy: [Not set]                                                  │
   │Spotlight Application: [Not set]                                       │
   │Spotlight Files: [Not set]                                             │
   │                                                                       │
   │    === Action Recording & Playback ===                                │
   │    * [r]ecord an action                                               │
   │    * [p]lay the currently loaded action                               │
   │    * e[x]port currently loaded action                                 │
   │    * [i]mport action                                                  │
   │                                                                       │
   │    === Spotlight Application ===                                      │
   │    * set [c]urrent app in focus as spotlight app                      │
   │    * [a]nalyze spotlight app with asam                                │
   │    * [d]ump memory of spotlight app (using fridump)                   │
   │    * start android [m]alware motion monitor (am3) on spotlight app    │
   │    * start o[b]jection interactive shell for spotlight app            │
   │    * run [t]rigdroid malware triggers                                 │
   │                                                                       │
   │    === Spotlight Files ===                                            │
   │    * [l]ist/add spotlight file                                        │
   │    * remo[v]e spotlight file                                          │
   │    * p[u]ll spotlight files                                           │
   │    * [o]bserve file system changes (fsmon)                            │
   │                                                                       │
   │    === Emulator Management ===                                        │
   │    * show [e]mulator information                                      │
   │    * keys [1-8] create snapshots, key [0] lists/loads snapshots       │
   │    * take [s]creenshot of device                                      │
   │    * [g]rab video of screen                                           │
   │    * [n]ew APK installation                                           │
   │    * run/install [f]rida server                                       │
   │                                                                       │
   │    === Network Management ===                                         │
   │    * set/unset network prox[y]                                        │
   │    * [h]ook encryption routines with friTap                           │
   │    * [w]rite network capture file                                     │
   │                                                                       │
   │                                                                       │
   │    * [q]uit                                                           │
   └───────────────────────────────────────────────────────────────────────┘

Menu Sections Explained
------------------------

Action Recording & Playback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**[r] Record an Action**
   Records user interactions and system changes:

   1. Takes a baseline snapshot of the system
   2. Starts monitoring:
      - File system changes
      - Network connections
      - Process activity
      - Socket usage
   3. Waits for user interaction with the device
   4. Analyzes changes when you press Enter
   5. Generates comprehensive results

   **Usage Flow**:
   - Press ``r`` to start recording
   - Perform actions on your Android device/emulator
   - Install apps, browse, use features
   - Press Enter in Sandroid terminal when done
   - Review the analysis results

**[p] Play Currently Loaded Action**
   Replays a previously recorded action sequence:

   - Automated playback of recorded touch events
   - Reproduces user interactions exactly
   - Useful for regression testing and consistent analysis

**[x] Export Currently Loaded Action**
   Saves recorded actions to a file for sharing or backup

**[i] Import Action**
   Loads previously saved action recordings

Spotlight Application
~~~~~~~~~~~~~~~~~~~~~

The "spotlight app" is the application currently being analyzed in detail.

**[c] Set Current App as Spotlight**
   - Automatically detects the foreground application
   - Sets it as the target for detailed analysis
   - Enables app-specific monitoring and analysis

**[a] Analyze Spotlight App**
   - Performs static analysis of the APK
   - Extracts metadata, permissions, components
   - Identifies potential security issues

**[d] Dump Memory of Spotlight App**
   - Uses Fridump to extract memory contents
   - Captures heap, stack, and loaded libraries
   - Useful for malware analysis and reverse engineering

**[m] Android Malware Motion Monitor (AM3)**
   - Advanced malware behavior monitoring
   - Tracks file system, network, and process activities
   - Specialized for detecting malicious behaviors

**[b] Objection Interactive Shell**
   - Launches objection for runtime manipulation
   - Allows hooking functions, bypassing security
   - Advanced dynamic analysis capabilities

**[t] Run TrigDroid Malware Triggers**
   - Automatically executes malware trigger conditions
   - Simulates user interactions that activate malware
   - Comprehensive trigger pattern execution

Spotlight Files
~~~~~~~~~~~~~~~

Monitor specific files of interest:

**[l] List/Add Spotlight Files**
   - Add files to monitor for changes
   - Track configuration files, databases, logs
   - Monitor sensitive file modifications

**[v] Remove Spotlight File**
   - Remove files from monitoring list
   - Clean up file watch list

**[u] Pull Spotlight Files**
   - Download monitored files from device
   - Compare versions before/after analysis
   - Archive important artifacts

**[o] File System Monitor (fsmon)**
   - Real-time file system change monitoring
   - Tracks file creation, modification, deletion
   - Detailed change logging with timestamps

Emulator Management
~~~~~~~~~~~~~~~~~~~

**[e] Show Emulator Information**
   - Display device specifications
   - Show running processes and services
   - Network configuration and status

**[1-8] Create Snapshots**
   - Save current emulator state
   - Quick rollback to clean states
   - Useful for repeatable analysis

**[0] List/Load Snapshots**
   - Manage saved snapshots
   - Restore previous states
   - Clean baseline management

**[s] Take Screenshot**
   - Capture current device screen
   - Document analysis progress
   - Evidence collection

**[g] Grab Video**
   - Record screen activity
   - Capture dynamic behaviors
   - Create demonstration videos

**[n] Install APK**
   - Install applications for analysis
   - Remote APK download and installation
   - Automated installation process

**[f] Frida Server Management**
   - Download and install Frida server
   - Start/stop Frida services
   - Manage different Frida versions

Network Management
~~~~~~~~~~~~~~~~~~

**[y] Network Proxy**
   - Configure HTTP/HTTPS proxy
   - Route device traffic through proxy
   - Enable traffic interception and analysis

**[h] friTap SSL/TLS Hooking**
   - Hook encryption routines
   - Decrypt SSL/TLS traffic
   - Monitor encrypted communications

**[w] Write Network Capture**
   - Save network traffic to PCAP files
   - Preserve network evidence
   - Enable offline analysis

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

All menu options use single-key shortcuts:

- **Recording**: ``r``, ``p``, ``x``, ``i``
- **App Analysis**: ``c``, ``a``, ``d``, ``m``, ``b``, ``t``
- **File Monitoring**: ``l``, ``v``, ``u``, ``o``
- **Device Management**: ``e``, ``1-8``, ``0``, ``s``, ``g``, ``n``, ``f``
- **Network**: ``y``, ``h``, ``w``
- **Exit**: ``q``

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
