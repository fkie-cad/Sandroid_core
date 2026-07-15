Command-Line Usage
==================

Sandroid provides a comprehensive command-line interface for automated analysis and batch processing. This mode is ideal for CI/CD integration, scripted analysis, and headless operation.

Basic Syntax
------------

::

   sandroid [OPTIONS]

All command-line options can be combined for customized analysis workflows.

Configuration Options
---------------------

**Configuration File**::

   sandroid -c config.toml
   sandroid --config /path/to/config.yaml

Specify a custom configuration file (TOML, YAML, or JSON format).

**Environment Selection**::

   sandroid --environment development
   sandroid --environment testing
   sandroid --environment production

Load environment-specific configurations.

**Output File**::

   sandroid -f analysis_results.json
   sandroid --file /path/to/results.json

Specify where to save analysis results (default: ``sandroid.json``).

**Log Level**::

   sandroid --loglevel DEBUG
   sandroid -ll INFO
   sandroid --loglevel WARNING

Set logging verbosity. Options: ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``, ``CRITICAL``.

**View Mode**::

   sandroid --view forensic
   sandroid --view malware
   sandroid --view security

Set the initial TUI view mode. Default is from config or forensic.

**Interactive Mode**::

   sandroid -i
   sandroid --interactive

Start in legacy Rich interactive mode. Without ``-i``, Sandroid launches the Textual TUI by default.

**Fresh Start**::

   sandroid --fresh

Reset the welcome screen and start as if running for the first time.

Analysis Options
----------------

**Number of Runs**::

   sandroid -n 3
   sandroid --number 5

Run the analysis multiple times for better accuracy. Minimum is 2 runs for comparison.

**Noise Filtering**::

   sandroid --avoid-strong-noise-filter

Disable noise filtering to capture all changes. This will:

- Skip the "dry run" baseline
- Capture more system noise
- Disable intra-file noise detection
- Provide comprehensive but potentially noisy results

Monitoring Options
------------------

**Network Traffic Capture**::

   sandroid --network

Enable comprehensive network monitoring:

- Capture all network connections
- Log DNS queries
- Monitor traffic patterns
- Generate network analysis report

**Process Monitoring**::

   sandroid --no-processes

Disable process monitoring (enabled by default):

- Skip active process tracking
- Reduce system overhead
- Focus on file and network changes

**Socket Monitoring**::

   sandroid --sockets

Monitor listening sockets during analysis:

- Track port bindings
- Monitor service startup
- Detect network service changes

**File System Monitoring**::

   sandroid --show-deleted
   sandroid -d

Perform full filesystem checks to reveal deleted files:

- Deep filesystem analysis
- Detect file deletion patterns
- Higher resource usage but comprehensive coverage

**Screenshot Capture**::

   sandroid --screenshot 5

Take screenshots every N seconds:

- Visual documentation of analysis
- Capture UI changes and behaviors
- Useful for malware analysis and app testing

Specialized Analysis
--------------------

**Hash Calculation**::

   sandroid --hash

Generate MD5 hashes for all changed and new files:

- File integrity verification
- Change detection
- Evidence preservation

**APK Enumeration**::

   sandroid --apk

List all APKs from the emulator with their hashes:

- Inventory installed applications
- Track APK modifications
- Generate application manifest

**TrigDroid Integration**::

   sandroid --trigdroid com.malware.package

Execute malware triggers for the specified package:

- Automated malware activation
- Comprehensive trigger pattern execution
- Behavioral analysis automation

**TrigDroid Configuration**::

   sandroid --trigdroid-ccf I    # Interactive mode
   sandroid --trigdroid-ccf D    # Create default config

Configure TrigDroid Component Coverage Framework:

- ``I`` - Interactive configuration mode
- ``D`` - Generate default configuration file

Headless Mode
-------------

**Basic Headless Operation**::

   sandroid --headless --trigdroid com.example.app
   sandroid --headless --mode forensic --trigdroid com.example.app

Run analysis without the interactive UI. Requires ``--trigdroid`` or ``--batch``.

**Batch Processing**::

   sandroid --batch batch_config.json
   sandroid --batch batch_config.json --mode malware

Process multiple packages from a JSON configuration file.

**Analysis Mode**::

   sandroid --headless --mode forensic
   sandroid --headless --mode malware
   sandroid --headless --mode security
   sandroid --headless --mode network

Set the analysis mode for headless operation. Default is ``malware``.

Dexray & Advanced Tools
-----------------------

**Dexray-Intercept Monitoring**::

   sandroid --dexray com.example.app
   sandroid --dexray com.example.app --dexray-hooks aes,web,socket
   sandroid --dexray com.example.app --dexray-fritap

Start Dexray-Intercept malware monitoring in headless mode. Runs until Ctrl+C.

Hook groups: ``aes``, ``web``, ``socket``, ``filesystem``, ``database``, ``dex``, ``java_dex``

**FriTap SSL/TLS Extraction**::

   sandroid --fritap com.example.app

Start FriTap SSL/TLS key extraction in headless mode. Runs until Ctrl+C.

**Fridump Memory Dump**::

   sandroid --fridump com.example.app

Dump memory of a running application using Fridump.

**Network Capture (Headless)**::

   sandroid --headless --mode network --duration 120
   sandroid --headless --mode network --with-fritap com.example.app

Capture network traffic in headless mode. Default duration is 60 seconds.

Device Management
-----------------

**HTTP Proxy**::

   sandroid --proxy 192.168.1.100:8080
   sandroid --proxy-clear

Set or clear HTTP proxy settings on the device.

**APK Installation**::

   sandroid --install-apk /path/to/app.apk

Install an APK on the device in headless mode.

**Action Import**::

   sandroid --import-action /path/to/action.json

Import a previously exported action recording file.

**Device Settings**::

   sandroid --device-settings settings.json
   sandroid --preset de
   sandroid --preset us

Apply device settings from a JSON file or use a country preset code.

Network Configuration
---------------------

**Network Speed Simulation**::

   sandroid --degrade-network

Simulate slower network conditions (UMTS/3G):

- Lower bandwidth simulation
- Increased latency
- Test app behavior under poor network conditions

**Whitelist Filtering**::

   sandroid --whitelist /path/to/whitelist.txt

Exclude specific files/paths from analysis results:

- Filter out known system noise
- Focus on application-specific changes
- Customize analysis scope

Advanced Features
-----------------

**PDF Report Generation**::

   sandroid --report

Generate comprehensive PDF reports:

- Professional forensic reports
- Visual analysis summaries
- Exportable documentation

**Debug Mode**::

   sandroid --debug

Enable debug/verbose mode for detailed output.

**Terminal Log**::

   sandroid --log

Show log messages directly in the terminal. Useful for debugging TUI display issues.

**Legacy Interactive Mode**::

   sandroid --interactive
   sandroid -i

Start in the legacy Rich interactive menu. Note: running ``sandroid`` without ``-i`` launches the modern Textual TUI instead.

Common Usage Patterns
----------------------

**Basic Analysis**::

   # Simple 2-run analysis
   sandroid --number 2

   # With output file
   sandroid -n 2 -f my_analysis.json

**Comprehensive Analysis**::

   # Full feature analysis
   sandroid --network --sockets --screenshot 3 --hash --apk --report

**Malware Analysis**::

   # Automated malware analysis
   sandroid --trigdroid com.malware.sample \
            --network --screenshot 2 \
            --show-deleted --hash \
            --report

   # Manual malware analysis
   sandroid --network --sockets --screenshot 3 \
            --avoid-strong-noise-filter \
            --show-deleted --hash

**App Development Testing**::

   # Performance testing
   sandroid --number 1 --screenshot 5 --degrade-network

   # Feature testing
   sandroid --network --sockets --apk

**Security Audit**::

   # Complete security analysis
   sandroid --network --sockets --show-deleted \
            --hash --apk --report \
            --avoid-strong-noise-filter

Configuration Integration
-------------------------

Command-line options override configuration file settings::

   # Config file sets number_of_runs = 2
   # This overrides to 5 runs
   sandroid --config analysis.toml --number 5

**Environment Variables**

All options can be set via environment variables::

   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=3
   export SANDROID_ANALYSIS__MONITOR_NETWORK=true
   sandroid

**Priority Order**

1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

Output and Results
------------------

**Result Files**

- **Primary Output**: JSON file with complete analysis results
- **Raw Data**: ``results/`` directory with detailed artifacts
- **Screenshots**: Captured device screenshots (if enabled)
- **Network Capture**: PCAP files (if network monitoring enabled)
- **Logs**: Detailed execution logs in ``~/.cache/sandroid/logs/``

**JSON Result Structure**::

   {
     "timestamp": "2024-08-27T10:30:00Z",
     "configuration": {...},
     "Changed Files": [...],
     "New Files": [...],
     "Deleted Files": [...],
     "Network": {...},
     "Processes": [...],
     "APKs": [...],
     "AI Analysis": {...}
   }

Batch Processing
----------------

**Script Integration**::

   #!/bin/bash

   # Batch analysis of multiple APKs
   for apk in *.apk; do
       echo "Analyzing $apk..."
       adb install "$apk"
       sandroid --number 2 --network --report \
                -f "results_$(basename "$apk" .apk).json"
       adb uninstall "$(aapt dump badging "$apk" | grep package | cut -d"'" -f2)"
   done

**CI/CD Integration**::

   # In your CI pipeline
   - name: Android Security Analysis
     run: |
       # Start emulator
       emulator -avd test_device -no-window -no-audio &
       adb wait-for-device

       # Run analysis
       sandroid --network --report \
                --output-file ci_analysis_results.json

       # Archive results
       tar -czf analysis_results.tar.gz results/ *.json *.pdf

**Parallel Analysis**::

   # Multiple simultaneous analyses
   sandroid --config config1.toml -f results1.json &
   sandroid --config config2.toml -f results2.json &
   sandroid --config config3.toml -f results3.json &
   wait

Error Handling
--------------

**Exit Codes**

- ``0`` - Analysis completed successfully
- ``1`` - Analysis failed with errors
- ``2`` - Configuration or setup error

**Common Error Scenarios**::

   # Handle device not found
   sandroid --network || echo "Analysis failed - check device connection"

   # Timeout protection
   timeout 1800 sandroid --network --screenshot 5

   # Resource cleanup
   trap 'kill $(jobs -p)' EXIT
   sandroid --network &

Performance Optimization
------------------------

**Resource Management**::

   # Lightweight analysis
   sandroid --number 1 --no-processes

   # High-performance analysis
   sandroid --avoid-strong-noise-filter --number 1

**Storage Optimization**::

   # Minimal storage usage
   sandroid --number 2  # No screenshots, no network capture

   # Custom output location
   sandroid --config <(echo 'paths.results_path="/tmp/analysis"')

Debugging and Troubleshooting
------------------------------

**Debug Mode**::

   sandroid --loglevel DEBUG --network

**Verbose Output**::

   SANDROID_LOG_LEVEL=DEBUG sandroid --network 2>&1 | tee analysis.log

**Common Issues**

1. **Device not found**::

   # Check ADB connection
   adb devices
   sandroid --loglevel DEBUG

2. **Permission errors**::

   # Ensure device is rooted
   adb shell su -c 'id'

3. **Frida issues**::

   # Test Frida separately
   frida-ps -U

4. **Configuration problems**::

   # Validate configuration
   sandroid-config validate

**Log Analysis**::

   # Find specific errors
   grep -i error ~/.cache/sandroid/logs/sandroid.log

   # Monitor real-time
   tail -f ~/.cache/sandroid/logs/sandroid.log

Integration Examples
--------------------

**Jenkins Pipeline**::

   pipeline {
       agent any
       stages {
           stage('Android Analysis') {
               steps {
                   sh '''
                       sandroid --network --report \
                                --file analysis_${BUILD_NUMBER}.json
                   '''
                   archiveArtifacts artifacts: '*.json,*.pdf,results/**'
               }
           }
       }
   }

**Docker Integration**::

   # Dockerfile
   FROM sandroid:latest
   COPY config.toml /app/
   CMD ["sandroid", "--config", "/app/config.toml", "--network", "--report"]

**GitHub Actions**::

   - name: Run Sandroid Analysis
     uses: actions/setup-python@v2
     with:
       python-version: '3.10'
   - run: |
       sandroid --network --report
   - uses: actions/upload-artifact@v2
     with:
       name: analysis-results
       path: |
         *.json
         *.pdf
         results/

Best Practices
--------------

1. **Always use multiple runs** (``--number 2`` minimum) for accurate change detection
2. **Enable network monitoring** (``--network``) for comprehensive analysis
3. **Use configuration files** for consistent analysis parameters
4. **Archive results** in structured directories with timestamps
5. **Monitor resource usage** during analysis to avoid system overload
6. **Validate configurations** before batch processing
7. **Use appropriate log levels** for your use case (INFO for production, DEBUG for troubleshooting)

See Also
--------

- :doc:`configuration` - Detailed configuration options
- :doc:`interactive_mode` - Interactive analysis interface
- :doc:`troubleshooting` - Common issues and solutions
- :doc:`api/core` - Python API for custom automation
