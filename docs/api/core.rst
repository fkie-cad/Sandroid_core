Core API
========

The Sandroid core API provides the fundamental building blocks for Android forensic analysis. These modules handle device communication, orchestration, and core functionality.

Toolbox - Main Orchestrator
----------------------------

.. automodule:: sandroid.core.toolbox
   :members:
   :undoc-members:
   :show-inheritance:

The Toolbox class is the central orchestrator for Sandroid analysis. It manages configuration, logging, and coordinates between different components.

**Key Features:**

- Configuration management and validation
- ADB device communication coordination
- Emulator state management
- File system change detection
- Network monitoring coordination
- Analysis result aggregation

**Basic Usage:**

.. code-block:: python

   from sandroid.core.toolbox import Toolbox

   # Initialize Toolbox (typically done automatically)
   Toolbox.init_logging()

   # Check if device is connected
   if Toolbox.is_device_connected():
       print("Device is connected and ready")

   # Get device information
   device_info = Toolbox.get_device_info()
   print(f"Device: {device_info}")

ADB Interface
-------------

.. automodule:: sandroid.core.adb
   :members:
   :undoc-members:
   :show-inheritance:

The ADB class provides a Python interface to Android Debug Bridge functionality.

**Key Features:**

- Direct ADB command execution
- Device connection management
- File transfer operations
- Shell command execution
- Package management

**Basic Usage:**

.. code-block:: python

   from sandroid.core.adb import Adb

   # Execute ADB command
   stdout, stderr = Adb.send_adb_command("devices")
   print(f"Connected devices: {stdout}")

   # Execute shell command on device
   result = Adb.send_adb_command("shell ls /data/local/tmp")
   print(f"Files: {result}")

   # Install APK
   Adb.send_adb_command("install path/to/app.apk")

   # Pull file from device
   Adb.send_adb_command("pull /sdcard/file.txt ./local_file.txt")

Action Queue System
-------------------

.. automodule:: sandroid.core.actionQ
   :members:
   :undoc-members:
   :show-inheritance:

The ActionQ class manages the analysis workflow and orchestrates data gathering modules.

**Key Features:**

- Analysis workflow orchestration
- Data gathering module management
- Result aggregation and processing
- Interactive mode menu handling
- Background task coordination

**Basic Usage:**

.. code-block:: python

   from sandroid.core.actionQ import ActionQ

   # Create action queue instance
   action_queue = ActionQ()

   # Run analysis with specific modules
   action_queue.run_analysis()

   # Get analysis results
   results = action_queue.get_results()

Frida Manager
-------------

.. automodule:: sandroid.core.frida_manager
   :members:
   :undoc-members:
   :show-inheritance:

The FridaManager class handles Frida server installation, management, and communication.

**Key Features:**

- Frida server installation and management
- Device architecture detection
- Frida process lifecycle management
- Version compatibility handling

**Basic Usage:**

.. code-block:: python

   from sandroid.core.frida_manager import FridaManager

   # Initialize Frida manager
   frida_mgr = FridaManager(verbose=True)

   # Install Frida server
   frida_mgr.install_frida_server()

   # Start Frida server
   if frida_mgr.run_frida_server():
       print("Frida server started successfully")

   # Check if running
   if frida_mgr.is_frida_server_running():
       print("Frida server is active")

Emulator Management
-------------------

.. automodule:: sandroid.core.emulator
   :members:
   :undoc-members:
   :show-inheritance:

The Emulator class provides control over Android emulator instances.

**Key Features:**

- Emulator startup and shutdown
- Snapshot management
- Network configuration
- Performance optimization

**Basic Usage:**

.. code-block:: python

   from sandroid.core.emulator import Emulator

   # Create emulator instance
   emulator = Emulator("Pixel_6_Pro_API_31")

   # Start emulator
   emulator.start()

   # Take snapshot
   emulator.create_snapshot("clean_baseline")

   # Load snapshot
   emulator.load_snapshot("clean_baseline")

File Operations
---------------

.. automodule:: sandroid.core.file_diff
   :members:
   :undoc-members:
   :show-inheritance:

File comparison and difference detection utilities.

**Key Features:**

- File content comparison
- Database diff analysis
- XML structure comparison
- Binary file change detection

**Basic Usage:**

.. code-block:: python

   from sandroid.core import file_diff

   # Compare two files
   diff_result = file_diff.txt_diff("/path/to/file1.txt", "/path/to/file2.txt")

   # Compare XML files
   xml_diff = file_diff.xml_diff("config1.xml", "config2.xml")

   # Database comparison
   db_diff = file_diff.db_diff("db1.sqlite", "db2.sqlite")

APK Management
--------------

.. automodule:: sandroid.core.apk_downloader
   :members:
   :undoc-members:
   :show-inheritance:

APK download, installation, and management utilities.

**Key Features:**

- Remote APK downloading
- APK installation automation
- Package metadata extraction
- Version management

**Basic Usage:**

.. code-block:: python

   from sandroid.core.apk_downloader import ApkDownloader

   # Initialize downloader
   downloader = ApkDownloader()

   # Download and install APK
   downloader.download_and_install("https://example.com/app.apk")

File System Monitoring
-----------------------

.. automodule:: sandroid.core.fsmon
   :members:
   :undoc-members:
   :show-inheritance:

Real-time file system monitoring and change detection.

**Key Features:**

- Real-time file system monitoring
- Change event capture
- File metadata tracking
- Performance optimization

**Basic Usage:**

.. code-block:: python

   from sandroid.core.fsmon import FSMon

   # Initialize file system monitor
   fs_monitor = FSMon()

   # Start monitoring
   fs_monitor.start_monitoring("/data/data/com.app.name")

   # Get detected changes
   changes = fs_monitor.get_changes()

Memory Analysis
---------------

.. automodule:: sandroid.core.fridump
   :members:
   :undoc-members:
   :show-inheritance:

Memory dumping and analysis using Frida.

**Key Features:**

- Process memory dumping
- Heap analysis
- Memory pattern detection
- Binary extraction

**Basic Usage:**

.. code-block:: python

   from sandroid.core.fridump import Fridump

   # Initialize memory dumper
   fridump = Fridump()

   # Dump process memory
   fridump.dump_process("com.target.app")

PDF Report Generation
---------------------

.. automodule:: sandroid.core.pdf_report
   :members:
   :undoc-members:
   :show-inheritance:

Professional PDF report generation from analysis results.

**Key Features:**

- Comprehensive report formatting
- Visual chart generation
- Evidence documentation
- Template customization

**Basic Usage:**

.. code-block:: python

   from sandroid.core.pdf_report import PDFReport

   # Initialize report generator
   report_gen = PDFReport()

   # Generate report from analysis results
   report_gen.generate_report(analysis_results, "forensic_report.pdf")

Timeline Generation
-------------------

.. automodule:: sandroid.core.timeline_generator
   :members:
   :undoc-members:
   :show-inheritance:

Timeline analysis and visualization of events during analysis.

**Key Features:**

- Event timeline construction
- Temporal analysis
- Activity correlation
- Visual timeline generation

Integration Examples
--------------------

**Complete Analysis Workflow:**

.. code-block:: python

   from sandroid.core.toolbox import Toolbox
   from sandroid.core.adb import Adb
   from sandroid.core.actionQ import ActionQ
   from sandroid.core.frida_manager import FridaManager

   # Initialize components
   Toolbox.init_logging()
   frida_mgr = FridaManager(verbose=True)
   action_queue = ActionQ()

   # Setup Frida if needed
   if not frida_mgr.is_frida_server_running():
       frida_mgr.install_frida_server()
       frida_mgr.run_frida_server()

   # Run analysis
   results = action_queue.run_analysis()

   # Process results
   print(f"Analysis complete. Found {len(results.get('New Files', []))} new files")

**Custom APK Analysis:**

.. code-block:: python

   from sandroid.core.adb import Adb
   from sandroid.core.apk_downloader import ApkDownloader
   from sandroid.core.toolbox import Toolbox

   # Download and install APK
   downloader = ApkDownloader()
   downloader.download_and_install("https://example.com/suspicious.apk")

   # Get package name
   packages = Adb.send_adb_command("shell pm list packages -3")

   # Analyze installed package
   analysis_results = Toolbox.analyze_package("com.suspicious.app")

**Memory Dumping Workflow:**

.. code-block:: python

   from sandroid.core.frida_manager import FridaManager
   from sandroid.core.fridump import Fridump
   from sandroid.core.adb import Adb

   # Ensure Frida is running
   frida_mgr = FridaManager()
   if not frida_mgr.is_frida_server_running():
       frida_mgr.run_frida_server()

   # Start target application
   Adb.send_adb_command("shell am start -n com.target.app/.MainActivity")

   # Dump memory
   fridump = Fridump()
   fridump.dump_process("com.target.app")

Error Handling
--------------

**Common Error Patterns:**

.. code-block:: python

   from sandroid.core.adb import Adb
   from sandroid.core.frida_manager import FridaManager

   try:
       # Check device connection
       stdout, stderr = Adb.send_adb_command("devices")
       if "device" not in stdout:
           raise ConnectionError("No device connected")

       # Initialize Frida
       frida_mgr = FridaManager()
       if not frida_mgr.run_frida_server():
           raise RuntimeError("Failed to start Frida server")

   except ConnectionError as e:
       print(f"Device connection error: {e}")
   except RuntimeError as e:
       print(f"Runtime error: {e}")
   except Exception as e:
       print(f"Unexpected error: {e}")

**Best Practices:**

1. **Always check device connectivity** before operations
2. **Initialize logging** early in your scripts
3. **Handle Frida lifecycle** properly (start/stop)
4. **Use try-catch blocks** for error handling
5. **Clean up resources** after analysis
6. **Validate inputs** before processing
7. **Monitor system resources** during analysis

Threading and Concurrency
--------------------------

**Multi-threaded Analysis:**

.. code-block:: python

   import threading
   from sandroid.core.toolbox import Toolbox
   from sandroid.analysis.processes import Processes
   from sandroid.analysis.network import Network

   def monitor_processes():
       proc_monitor = Processes()
       proc_monitor.gather()

   def monitor_network():
       net_monitor = Network()
       net_monitor.gather()

   # Run monitors in parallel
   proc_thread = threading.Thread(target=monitor_processes)
   net_thread = threading.Thread(target=monitor_network)

   proc_thread.start()
   net_thread.start()

   # Wait for completion
   proc_thread.join()
   net_thread.join()

See Also
--------

- :doc:`../analysis` - Data gathering modules API
- :doc:`../features` - Feature modules API
- :doc:`../config` - Configuration system API
- :doc:`../advanced/custom_analysis` - Custom analysis development
- :doc:`../troubleshooting` - Common issues and solutions
