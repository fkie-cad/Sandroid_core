Features API
============

The Sandroid features API provides functionality modules for enhanced analysis capabilities. These modules extend the core analysis with specialized features like recording, playback, screenshots, and automated triggers.

Base Functionality Class
-------------------------

.. automodule:: sandroid.features.functionality
   :members:
   :undoc-members:
   :show-inheritance:

All feature modules inherit from Functionality, which provides the common interface:

- ``run()`` - Execute the feature functionality
- ``setup()`` - Initialize the feature
- ``cleanup()`` - Clean up resources after execution
- ``get_status()`` - Get current feature status

Action Recording and Playback
------------------------------

Action Recorder
~~~~~~~~~~~~~~~

.. automodule:: sandroid.features.recorder
   :members:
   :undoc-members:
   :show-inheritance:

Records user interactions and device events for later playback.

**Key Features:**

- Touch event recording
- Screen interaction capture
- Timing information preservation
- Action sequence optimization

**Usage Example:**

.. code-block:: python

   from sandroid.features.recorder import Recorder

   # Initialize recorder
   recorder = Recorder()

   # Start recording user interactions
   recorder.run()

   # Record for specific duration
   import time
   print("Recording started. Interact with the device...")
   time.sleep(60)  # Record for 1 minute

   # Stop and save recording
   recorder.cleanup()

   # Export recorded actions
   recorder.export_actions("user_interaction_sequence.json")

Action Player
~~~~~~~~~~~~~

.. automodule:: sandroid.features.player
   :members:
   :undoc-members:
   :show-inheritance:

Replays previously recorded action sequences.

**Key Features:**

- Precise action replay
- Timing accuracy
- Error handling during playback
- Playback speed control

**Usage Example:**

.. code-block:: python

   from sandroid.features.player import Player

   # Initialize player
   player = Player()

   # Load action sequence
   player.load_actions("user_interaction_sequence.json")

   # Play back actions
   player.run()

   # Monitor playback status
   while player.is_playing():
       status = player.get_status()
       print(f"Playback progress: {status['progress']}%")
       time.sleep(1)

Screenshot Capture
------------------

.. automodule:: sandroid.features.screenshot
   :members:
   :undoc-members:
   :show-inheritance:

Automated screenshot capture during analysis.

**Key Features:**

- Periodic screenshot capture
- Configurable intervals
- Image quality optimization
- Storage management

**Usage Example:**

.. code-block:: python

   from sandroid.features.screenshot import Screenshot
   import time

   # Initialize screenshot feature
   screenshot = Screenshot()

   # Configure screenshot interval (seconds)
   screenshot.set_interval(5)  # Every 5 seconds

   # Start automatic screenshot capture
   screenshot.run()

   # Run analysis while capturing screenshots
   time.sleep(300)  # 5 minutes of analysis

   # Stop screenshot capture
   screenshot.cleanup()

   # Get captured screenshot paths
   screenshots = screenshot.get_screenshots()
   print(f"Captured {len(screenshots)} screenshots")

**Manual Screenshot Capture:**

.. code-block:: python

   from sandroid.features.screenshot import Screenshot

   # Initialize screenshot feature
   screenshot = Screenshot()

   # Take single screenshot
   screenshot_path = screenshot.take_screenshot("manual_capture.png")
   print(f"Screenshot saved: {screenshot_path}")

   # Take screenshot with timestamp
   timestamped_path = screenshot.take_timestamped_screenshot()
   print(f"Timestamped screenshot: {timestamped_path}")

Automated Trigger Execution
----------------------------

.. automodule:: sandroid.features.trigdroid
   :members:
   :undoc-members:
   :show-inheritance:

TrigDroid integration for automated malware trigger execution.

**Key Features:**

- Comprehensive trigger pattern execution
- Malware activation techniques
- Behavioral trigger simulation
- Custom trigger definition

**Usage Example:**

.. code-block:: python

   from sandroid.features.trigdroid import Trigdroid

   # Initialize TrigDroid
   trigdroid = Trigdroid()

   # Set target package for trigger execution
   trigdroid.set_target_package("com.suspicious.malware")

   # Run automated triggers
   trigdroid.run()

   # Get trigger execution results
   results = trigdroid.get_results()

   # Display triggered behaviors
   for trigger_result in results['triggered_behaviors']:
       print(f"Trigger: {trigger_result['trigger_type']}")
       print(f"Result: {trigger_result['outcome']}")

**Custom Trigger Configuration:**

.. code-block:: python

   from sandroid.features.trigdroid import Trigdroid

   # Initialize with custom configuration
   trigdroid = Trigdroid()

   # Define custom triggers
   custom_triggers = {
       'network_triggers': ['connect_to_c2', 'download_payload'],
       'file_triggers': ['create_config', 'encrypt_files'],
       'system_triggers': ['request_permissions', 'hide_icon']
   }

   # Apply custom configuration
   trigdroid.configure_triggers(custom_triggers)

   # Execute custom trigger set
   trigdroid.run()

Feature Integration Examples
----------------------------

**Complete Analysis with All Features:**

.. code-block:: python

   from sandroid.features.recorder import Recorder
   from sandroid.features.screenshot import Screenshot
   from sandroid.features.trigdroid import Trigdroid
   from sandroid.core.toolbox import Toolbox
   import time

   def comprehensive_feature_analysis(package_name):
       """Run complete analysis with all features"""

       # Initialize all features
       recorder = Recorder()
       screenshot = Screenshot()
       trigdroid = Trigdroid()

       # Setup features
       screenshot.set_interval(10)  # Every 10 seconds
       trigdroid.set_target_package(package_name)

       try:
           # Start recording and screenshots
           recorder.run()
           screenshot.run()

           # Execute automated triggers
           print("Executing automated triggers...")
           trigdroid.run()

           # Allow time for behaviors to manifest
           time.sleep(180)  # 3 minutes

           # Collect results
           results = {
               'recorded_actions': recorder.export_actions(),
               'screenshots': screenshot.get_screenshots(),
               'trigger_results': trigdroid.get_results()
           }

           return results

       finally:
           # Clean up all features
           recorder.cleanup()
           screenshot.cleanup()
           trigdroid.cleanup()

**Malware Analysis Workflow:**

.. code-block:: python

   from sandroid.features.screenshot import Screenshot
   from sandroid.features.trigdroid import Trigdroid
   from sandroid.core.adb import Adb
   import time

   def automated_malware_analysis(apk_path, package_name):
       """Automated malware analysis with triggers and screenshots"""

       # Install malware sample
       Adb.send_adb_command(f"install {apk_path}")

       # Initialize features
       screenshot = Screenshot()
       trigdroid = Trigdroid()

       # Configure for malware analysis
       screenshot.set_interval(5)  # Frequent screenshots
       trigdroid.set_target_package(package_name)

       try:
           # Start monitoring
           screenshot.run()

           # Launch app
           Adb.send_adb_command(f"shell am start -n {package_name}/.MainActivity")
           time.sleep(10)

           # Execute malware triggers
           print("Executing malware triggers...")
           trigger_results = trigdroid.run()

           # Monitor for behavioral changes
           time.sleep(120)  # 2 minutes observation

           # Collect evidence
           screenshots = screenshot.get_screenshots()

           return {
               'trigger_results': trigger_results,
               'visual_evidence': screenshots,
               'package_name': package_name
           }

       finally:
           screenshot.cleanup()
           trigdroid.cleanup()

**Interactive Session Recording:**

.. code-block:: python

   from sandroid.features.recorder import Recorder
   from sandroid.features.player import Player
   from sandroid.features.screenshot import Screenshot

   def record_and_replay_session():
       """Record user session and replay for consistency testing"""

       recorder = Recorder()
       screenshot = Screenshot()

       # Phase 1: Record user session
       print("=== Recording Phase ===")
       recorder.run()
       screenshot.run()

       print("Please interact with the device. Press Enter when done...")
       input()

       # Save recording
       actions_file = recorder.export_actions("session_recording.json")
       recorder.cleanup()
       screenshot.cleanup()

       print(f"Session recorded to: {actions_file}")

       # Phase 2: Replay recorded session
       print("=== Replay Phase ===")
       player = Player()
       screenshot_replay = Screenshot()

       player.load_actions(actions_file)
       screenshot_replay.set_interval(2)  # Frequent screenshots during replay
       screenshot_replay.run()

       # Replay the session
       player.run()

       # Wait for replay completion
       while player.is_playing():
           time.sleep(1)

       screenshot_replay.cleanup()

       print("Session replay completed")

Advanced Feature Usage
-----------------------

**Custom Screenshot Analysis:**

.. code-block:: python

   from sandroid.features.screenshot import Screenshot
   import cv2
   import numpy as np

   class AnalyticalScreenshot(Screenshot):
       def __init__(self):
           super().__init__()
           self.screenshot_analysis = []

       def take_screenshot(self, filename=None):
           # Take standard screenshot
           screenshot_path = super().take_screenshot(filename)

           # Perform image analysis
           image = cv2.imread(screenshot_path)

           # Detect UI changes
           if hasattr(self, 'previous_image'):
               diff = cv2.absdiff(image, self.previous_image)
               change_percentage = np.sum(diff) / (diff.shape[0] * diff.shape[1] * 255)

               self.screenshot_analysis.append({
                   'timestamp': time.time(),
                   'change_percentage': change_percentage,
                   'path': screenshot_path
               })

           self.previous_image = image.copy()
           return screenshot_path

       def get_ui_changes(self):
           """Get detected UI changes over time"""
           return self.screenshot_analysis

   # Usage
   analytical_screenshot = AnalyticalScreenshot()
   analytical_screenshot.set_interval(3)
   analytical_screenshot.run()

   time.sleep(60)  # Monitor for 1 minute

   ui_changes = analytical_screenshot.get_ui_changes()
   analytical_screenshot.cleanup()

**Conditional Trigger Execution:**

.. code-block:: python

   from sandroid.features.trigdroid import Trigdroid
   from sandroid.analysis.processes import Processes
   from sandroid.analysis.network import Network

   class ConditionalTrigdroid(Trigdroid):
       def __init__(self):
           super().__init__()
           self.process_monitor = Processes()
           self.network_monitor = Network()

       def execute_conditional_triggers(self, package_name):
           """Execute triggers based on system state"""

           self.set_target_package(package_name)

           # Monitor initial state
           self.process_monitor.gather()
           self.network_monitor.gather()

           initial_processes = self.process_monitor.return_data()
           initial_network = self.network_monitor.return_data()

           # Execute triggers
           self.run()

           # Wait and check for changes
           time.sleep(30)

           self.process_monitor.gather()
           self.network_monitor.gather()

           final_processes = self.process_monitor.return_data()
           final_network = self.network_monitor.return_data()

           # Analyze changes
           process_changes = len(final_processes['Processes']) - len(initial_processes['Processes'])
           network_changes = len(final_network['Network']['connections']) - len(initial_network['Network']['connections'])

           return {
               'trigger_success': process_changes > 0 or network_changes > 0,
               'process_changes': process_changes,
               'network_changes': network_changes
           }

**Synchronized Feature Execution:**

.. code-block:: python

   import threading
   from sandroid.features.recorder import Recorder
   from sandroid.features.screenshot import Screenshot
   from sandroid.features.trigdroid import Trigdroid

   class SynchronizedFeatures:
       def __init__(self):
           self.recorder = Recorder()
           self.screenshot = Screenshot()
           self.trigdroid = Trigdroid()
           self.sync_event = threading.Event()

       def synchronized_execution(self, package_name, duration=120):
           """Execute features in synchronized manner"""

           # Configure features
           self.screenshot.set_interval(5)
           self.trigdroid.set_target_package(package_name)

           # Define synchronized execution
           def start_recording():
               self.recorder.run()
               self.sync_event.set()  # Signal other features

           def start_screenshots():
               self.sync_event.wait()  # Wait for sync signal
               self.screenshot.run()

           def execute_triggers():
               self.sync_event.wait()  # Wait for sync signal
               time.sleep(10)  # Delay trigger execution
               self.trigdroid.run()

           # Start threads
           threads = [
               threading.Thread(target=start_recording),
               threading.Thread(target=start_screenshots),
               threading.Thread(target=execute_triggers)
           ]

           for thread in threads:
               thread.start()

           # Monitor execution
           time.sleep(duration)

           # Cleanup
           self.recorder.cleanup()
           self.screenshot.cleanup()
           self.trigdroid.cleanup()

           # Wait for threads to complete
           for thread in threads:
               thread.join()

Performance Considerations
--------------------------

**Resource Management:**

.. code-block:: python

   from sandroid.features.screenshot import Screenshot
   import psutil
   import time

   class ResourceAwareScreenshot(Screenshot):
       def __init__(self, cpu_threshold=80, memory_threshold=85):
           super().__init__()
           self.cpu_threshold = cpu_threshold
           self.memory_threshold = memory_threshold

       def adaptive_interval(self):
           """Adjust screenshot interval based on system load"""

           cpu_percent = psutil.cpu_percent(interval=1)
           memory_percent = psutil.virtual_memory().percent

           if cpu_percent > self.cpu_threshold or memory_percent > self.memory_threshold:
               # Reduce frequency under high load
               self.set_interval(15)
               print("High system load detected. Reducing screenshot frequency.")
           else:
               # Normal frequency
               self.set_interval(5)

       def run(self):
           """Run with adaptive performance monitoring"""

           while self.is_running:
               self.adaptive_interval()
               super().take_screenshot()
               time.sleep(self.interval)

Error Handling and Recovery
---------------------------

**Robust Feature Execution:**

.. code-block:: python

   from sandroid.features.functionality import Functionality
   import logging

   class RobustFeatureManager:
       def __init__(self, features):
           self.features = features
           self.logger = logging.getLogger(__name__)
           self.failed_features = []

       def execute_with_recovery(self):
           """Execute features with error recovery"""

           results = {}

           for feature in self.features:
               try:
                   # Setup feature
                   feature.setup()

                   # Execute feature
                   feature.run()

                   # Get results
                   if hasattr(feature, 'get_results'):
                       results[feature.__class__.__name__] = feature.get_results()

                   self.logger.info(f"✅ {feature.__class__.__name__} completed successfully")

               except Exception as e:
                   self.logger.error(f"❌ {feature.__class__.__name__} failed: {e}")
                   self.failed_features.append((feature, str(e)))

                   # Attempt recovery
                   try:
                       feature.cleanup()
                   except:
                       pass

                   continue

               finally:
                   # Ensure cleanup
                   try:
                       feature.cleanup()
                   except:
                       pass

           return results, self.failed_features

Best Practices
--------------

1. **Always call cleanup()** after feature execution
2. **Use appropriate intervals** for screenshot capture to balance detail and performance
3. **Monitor system resources** during feature execution
4. **Handle errors gracefully** to prevent feature interruption
5. **Coordinate feature timing** to avoid conflicts
6. **Test trigger patterns** before production analysis
7. **Validate device state** before feature execution
8. **Archive recordings and screenshots** for evidence preservation

Configuration Integration
-------------------------

Features can be configured via the configuration system:

.. code-block:: python

   # Configuration file (sandroid.toml)
   [features]
   screenshot_interval = 5
   recording_quality = "high"
   trigdroid_timeout = 300

   [features.screenshot]
   format = "png"
   quality = 95
   max_size = "1920x1080"

   [features.trigdroid]
   trigger_sets = ["network", "filesystem", "permissions"]
   execution_timeout = 120

.. code-block:: python

   from sandroid.config import load_config
   from sandroid.features.screenshot import Screenshot

   # Load configuration
   config = load_config()

   # Configure screenshot feature
   screenshot = Screenshot()
   screenshot.set_interval(config.features.screenshot_interval)
   screenshot.set_quality(config.features.screenshot.quality)

See Also
--------

- :doc:`core` - Core API for device management
- :doc:`analysis` - Analysis modules API
- :doc:`config` - Configuration system
- :doc:`../interactive_mode` - Using features in interactive mode
- :doc:`../advanced/custom_analysis` - Creating custom features
