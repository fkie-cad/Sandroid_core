Analysis API
============

The Sandroid analysis API provides modules for gathering forensic data from Android devices. All analysis modules inherit from the base DataGather class and follow a consistent interface.

Base Data Gathering Class
--------------------------

.. automodule:: sandroid.analysis.datagather
   :members:
   :undoc-members:
   :show-inheritance:

All analysis modules inherit from DataGather, which provides the common interface:

- ``gather()`` - Collect data from the device
- ``return_data()`` - Return structured analysis results
- ``pretty_print()`` - Generate formatted output for display
- ``process_data()`` - Process and filter collected data

File System Analysis
--------------------

Changed Files Detection
~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.changedfiles
   :members:
   :undoc-members:
   :show-inheritance:

Detects and analyzes files that have been modified during analysis.

**Key Features:**

- File modification detection
- Content difference analysis
- Noise filtering
- Database and XML diff support

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.changedfiles import ChangedFiles

   # Initialize detector
   changed_files = ChangedFiles()

   # Gather changed file data
   changed_files.gather()

   # Get results
   results = changed_files.return_data()
   print(f"Found {len(results['Changed Files'])} changed files")

   # Pretty print results
   formatted_output = changed_files.pretty_print()
   print(formatted_output)

New Files Detection
~~~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.newfiles
   :members:
   :undoc-members:
   :show-inheritance:

Identifies files created during the analysis period.

**Key Features:**

- New file detection
- File type classification
- Static analysis integration
- Size and metadata tracking

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.newfiles import NewFiles

   # Initialize detector
   new_files = NewFiles()

   # Gather new file data
   new_files.gather()

   # Get structured results
   results = new_files.return_data()

   # Process each new file
   for file_info in results['New Files']:
       print(f"New file: {file_info}")

Deleted Files Detection
~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.deletedfiles
   :members:
   :undoc-members:
   :show-inheritance:

Tracks files that were deleted during analysis (requires ``--show-deleted`` flag).

**Key Features:**

- Deleted file detection
- File recovery attempts
- Deletion pattern analysis
- Forensic timeline integration

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.deletedfiles import DeletedFiles

   # Initialize detector (requires full filesystem scan)
   deleted_files = DeletedFiles()

   # Gather deleted file data
   deleted_files.gather()

   # Get results
   results = deleted_files.return_data()
   print(f"Detected {len(results['Deleted Files'])} deleted files")

Process Monitoring
------------------

.. automodule:: sandroid.analysis.processes
   :members:
   :undoc-members:
   :show-inheritance:

Monitors running processes during analysis.

**Key Features:**

- Real-time process monitoring
- Process lifecycle tracking
- CPU and memory usage
- Parent-child relationship mapping

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.processes import Processes
   import time

   # Initialize process monitor
   proc_monitor = Processes()

   # Start monitoring
   proc_monitor.gather()

   # Monitor for 30 seconds
   time.sleep(30)

   # Get process data
   results = proc_monitor.return_data()

   # Display running processes
   for process in results['Processes']:
       print(f"Process: {process['name']} (PID: {process['pid']})")

Network Analysis
----------------

Network Connection Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.network
   :members:
   :undoc-members:
   :show-inheritance:

Captures and analyzes network traffic during analysis.

**Key Features:**

- Real-time network monitoring
- DNS query logging
- Connection tracking
- Traffic pattern analysis
- PCAP file generation

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.network import Network
   import time

   # Initialize network monitor
   net_monitor = Network()

   # Start network capture
   net_monitor.gather()

   # Monitor network activity
   time.sleep(60)  # Monitor for 1 minute

   # Get network data
   results = net_monitor.return_data()

   # Analyze connections
   for connection in results['Network']['connections']:
       print(f"Connection: {connection}")

Socket Monitoring
~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.sockets
   :members:
   :undoc-members:
   :show-inheritance:

Monitors socket activity and listening ports.

**Key Features:**

- Socket state monitoring
- Port binding detection
- Service identification
- Network service analysis

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.sockets import Sockets

   # Initialize socket monitor
   socket_monitor = Sockets()

   # Gather socket data
   socket_monitor.gather()

   # Get socket information
   results = socket_monitor.return_data()

   # Display active sockets
   for socket_info in results['Sockets']:
       print(f"Socket: {socket_info}")

SSL/TLS Traffic Analysis
~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sandroid.analysis.fritap
   :members:
   :undoc-members:
   :show-inheritance:

Intercepts and analyzes SSL/TLS encrypted traffic using friTap.

**Key Features:**

- SSL/TLS traffic interception
- Certificate analysis
- Encrypted payload extraction
- Protocol detection

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.fritap import FriTap

   # Initialize friTap (requires Frida server)
   fritap = FriTap()

   # Start SSL interception
   fritap.gather()

   # Get intercepted data
   results = fritap.return_data()

   # Process SSL traffic
   for ssl_session in results['SSL_Traffic']:
       print(f"SSL Session: {ssl_session}")

Static Analysis
---------------

.. automodule:: sandroid.analysis.static_analysis
   :members:
   :undoc-members:
   :show-inheritance:

Performs static analysis on APK files and system components.

**Key Features:**

- APK structure analysis
- Manifest parsing
- Permission analysis
- Code signature verification
- Certificate chain validation

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.static_analysis import StaticAnalysis

   # Initialize static analyzer
   static_analyzer = StaticAnalysis()

   # Analyze APK files
   static_analyzer.gather()

   # Get analysis results
   results = static_analyzer.return_data()

   # Display APK information
   for apk_info in results['APK_Analysis']:
       print(f"APK: {apk_info['package_name']}")
       print(f"Permissions: {apk_info['permissions']}")

Malware Detection
-----------------

.. automodule:: sandroid.analysis.malwaremonitor
   :members:
   :undoc-members:
   :show-inheritance:

Specialized malware behavior monitoring and detection.

**Key Features:**

- Malicious behavior detection
- API call monitoring
- Suspicious activity flagging
- IOC (Indicator of Compromise) generation

**Usage Example:**

.. code-block:: python

   from sandroid.analysis.malwaremonitor import MalwareMonitor

   # Initialize malware monitor
   malware_monitor = MalwareMonitor()

   # Start monitoring malicious activity
   malware_monitor.gather()

   # Get malware analysis results
   results = malware_monitor.return_data()

   # Check for malicious indicators
   if results['Malware_Indicators']:
       print("⚠️  Malicious behavior detected!")
       for indicator in results['Malware_Indicators']:
           print(f"- {indicator}")

Analysis Orchestration
----------------------

**Complete Analysis Workflow:**

.. code-block:: python

   from sandroid.analysis.changedfiles import ChangedFiles
   from sandroid.analysis.newfiles import NewFiles
   from sandroid.analysis.processes import Processes
   from sandroid.analysis.network import Network
   from sandroid.analysis.malwaremonitor import MalwareMonitor
   import threading
   import time

   def comprehensive_analysis():
       # Initialize all analyzers
       analyzers = [
           ChangedFiles(),
           NewFiles(),
           Processes(),
           Network(),
           MalwareMonitor()
       ]

       # Start all analyzers
       threads = []
       for analyzer in analyzers:
           thread = threading.Thread(target=analyzer.gather)
           thread.start()
           threads.append(thread)

       # Wait for analysis period
       time.sleep(300)  # 5 minutes of monitoring

       # Collect results
       results = {}
       for analyzer in analyzers:
           analyzer_results = analyzer.return_data()
           results.update(analyzer_results)

       # Wait for threads to complete
       for thread in threads:
           thread.join()

       return results

**Targeted Application Analysis:**

.. code-block:: python

   from sandroid.analysis.processes import Processes
   from sandroid.analysis.network import Network
   from sandroid.analysis.changedfiles import ChangedFiles
   from sandroid.core.adb import Adb

   def analyze_specific_app(package_name):
       # Start the target application
       Adb.send_adb_command(f"shell am start -n {package_name}/.MainActivity")

       # Initialize focused analyzers
       proc_monitor = Processes()
       net_monitor = Network()
       file_monitor = ChangedFiles()

       # Start monitoring
       proc_monitor.gather()
       net_monitor.gather()

       # Interact with app (manual or automated)
       print(f"Monitoring {package_name}. Interact with the app now...")
       time.sleep(120)  # 2 minutes of interaction

       # Gather file changes
       file_monitor.gather()

       # Collect results
       results = {
           **proc_monitor.return_data(),
           **net_monitor.return_data(),
           **file_monitor.return_data()
       }

       return results

**Real-time Monitoring:**

.. code-block:: python

   from sandroid.analysis.processes import Processes
   from sandroid.analysis.network import Network
   import time

   def real_time_monitor(duration=300):
       """Monitor system in real-time for specified duration (seconds)"""

       proc_monitor = Processes()
       net_monitor = Network()

       start_time = time.time()

       while (time.time() - start_time) < duration:
           # Gather current state
           proc_monitor.gather()
           net_monitor.gather()

           # Get current results
           proc_results = proc_monitor.return_data()
           net_results = net_monitor.return_data()

           # Display real-time updates
           print(f"\n--- Time: {time.time() - start_time:.1f}s ---")
           print(f"Active processes: {len(proc_results.get('Processes', []))}")
           print(f"Network connections: {len(net_results.get('Network', {}).get('connections', []))}")

           time.sleep(10)  # Update every 10 seconds

       return {**proc_results, **net_results}

Data Processing and Filtering
-----------------------------

**Custom Data Filtering:**

.. code-block:: python

   from sandroid.analysis.changedfiles import ChangedFiles

   class CustomChangedFiles(ChangedFiles):
       def process_data(self):
           """Custom processing with application-specific filtering"""
           raw_data = super().process_data()

           # Filter for specific file types
           filtered_files = []
           for file_path in raw_data:
               if any(file_path.endswith(ext) for ext in ['.db', '.json', '.xml']):
                   filtered_files.append(file_path)

           return filtered_files

   # Use custom analyzer
   custom_analyzer = CustomChangedFiles()
   custom_analyzer.gather()
   results = custom_analyzer.return_data()

**Result Aggregation:**

.. code-block:: python

   from sandroid.analysis.datagather import DataGather

   class AnalysisAggregator:
       def __init__(self):
           self.analyzers = []

       def add_analyzer(self, analyzer):
           if isinstance(analyzer, DataGather):
               self.analyzers.append(analyzer)

       def run_all(self):
           results = {}
           for analyzer in self.analyzers:
               analyzer.gather()
               analyzer_results = analyzer.return_data()
               results.update(analyzer_results)
           return results

       def generate_report(self):
           report = []
           for analyzer in self.analyzers:
               formatted_output = analyzer.pretty_print()
               report.append(formatted_output)
           return "\n\n".join(report)

   # Usage
   aggregator = AnalysisAggregator()
   aggregator.add_analyzer(ChangedFiles())
   aggregator.add_analyzer(NewFiles())
   aggregator.add_analyzer(Processes())

   results = aggregator.run_all()
   report = aggregator.generate_report()

Performance Optimization
------------------------

**Memory-Efficient Analysis:**

.. code-block:: python

   from sandroid.analysis.changedfiles import ChangedFiles
   import gc

   def memory_efficient_analysis():
       """Analyze with memory optimization"""

       # Process one analyzer at a time
       analyzers = [ChangedFiles, NewFiles, Processes]
       all_results = {}

       for analyzer_class in analyzers:
           # Initialize analyzer
           analyzer = analyzer_class()

           # Run analysis
           analyzer.gather()
           results = analyzer.return_data()

           # Store results
           all_results.update(results)

           # Clean up
           del analyzer
           gc.collect()

       return all_results

**Parallel Processing:**

.. code-block:: python

   import concurrent.futures
   from sandroid.analysis.changedfiles import ChangedFiles
   from sandroid.analysis.newfiles import NewFiles
   from sandroid.analysis.processes import Processes

   def parallel_analysis():
       """Run analyzers in parallel for better performance"""

       analyzers = [ChangedFiles(), NewFiles(), Processes()]

       def run_analyzer(analyzer):
           analyzer.gather()
           return analyzer.return_data()

       # Run analyzers in parallel
       with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
           futures = [executor.submit(run_analyzer, analyzer) for analyzer in analyzers]

           # Collect results
           all_results = {}
           for future in concurrent.futures.as_completed(futures):
               result = future.result()
               all_results.update(result)

       return all_results

Error Handling in Analysis
--------------------------

**Robust Analysis with Error Handling:**

.. code-block:: python

   from sandroid.analysis.datagather import DataGather
   import logging

   class RobustAnalyzer:
       def __init__(self, analyzers):
           self.analyzers = analyzers
           self.logger = logging.getLogger(__name__)

       def run_with_fallback(self):
           results = {}

           for analyzer in self.analyzers:
               try:
                   # Attempt analysis
                   analyzer.gather()
                   analyzer_results = analyzer.return_data()
                   results.update(analyzer_results)

                   self.logger.info(f"✅ {analyzer.__class__.__name__} completed successfully")

               except Exception as e:
                   self.logger.error(f"❌ {analyzer.__class__.__name__} failed: {e}")

                   # Add error information to results
                   error_key = f"{analyzer.__class__.__name__}_Error"
                   results[error_key] = str(e)

                   # Continue with other analyzers
                   continue

           return results

Best Practices
--------------

1. **Initialize analyzers** before starting analysis
2. **Use threading** for concurrent monitoring
3. **Handle errors gracefully** to prevent analysis interruption
4. **Clean up resources** after analysis completion
5. **Filter noise** appropriately for your use case
6. **Monitor system resources** during analysis
7. **Validate device connectivity** before starting
8. **Use appropriate timeouts** for network operations

See Also
--------

- :doc:`core` - Core API for device management
- :doc:`features` - Feature modules API
- :doc:`config` - Configuration system
- :doc:`../interactive_mode` - Using analysis in interactive mode
- :doc:`../command_line_usage` - Command-line analysis options
