Features API
============

The Sandroid features API provides functionality modules for enhanced analysis capabilities. These modules extend the core analysis with specialized features like recording, playback and automated triggers.

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

Screenshots
-----------

There is no screenshot feature module any more: the periodic screenshot
thread (``sandroid.features.screenshot``, ``--screenshot``,
``analysis.screenshot_interval``) was removed. Screenshots are taken by
Tracking (``Ctrl+T`` in the TUI) on the triggers set in the ``[tracking]``
configuration section (``shot_before_tap``, ``shot_screen_change``,
``shot_after_tap``, ``shot_label``); ``s`` adds one by hand while Tracking is
on. They are stored under ``tracking/shots/`` in the session device folder,
recorded on the session timeline and shown in the report.

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
   from sandroid.features.trigdroid import Trigdroid
   from sandroid.core.toolbox import Toolbox
   import time

   def comprehensive_feature_analysis(package_name):
       """Run complete analysis with all features"""

       # Initialize all features
       recorder = Recorder()
       trigdroid = Trigdroid()

       # Setup features
       trigdroid.set_target_package(package_name)

       try:
           # Start recording
           recorder.run()

           # Execute automated triggers
           print("Executing automated triggers...")
           trigdroid.run()

           # Allow time for behaviors to manifest
           time.sleep(180)  # 3 minutes

           # Collect results
           results = {
               'recorded_actions': recorder.export_actions(),
               'trigger_results': trigdroid.get_results()
           }

           return results

       finally:
           # Clean up all features
           recorder.cleanup()
           trigdroid.cleanup()

**Malware Analysis Workflow:**

.. code-block:: python

   from sandroid.features.trigdroid import Trigdroid
   from sandroid.core.adb import Adb
   import time

   def automated_malware_analysis(apk_path, package_name):
       """Automated malware analysis with triggers"""

       # Install malware sample
       Adb.send_adb_command(f"install {apk_path}")

       # Initialize features
       trigdroid = Trigdroid()

       # Configure for malware analysis
       trigdroid.set_target_package(package_name)

       try:
           # Launch app
           Adb.send_adb_command(f"shell am start -n {package_name}/.MainActivity")
           time.sleep(10)

           # Execute malware triggers
           print("Executing malware triggers...")
           trigger_results = trigdroid.run()

           # Monitor for behavioral changes
           time.sleep(120)  # 2 minutes observation

           return {
               'trigger_results': trigger_results,
               'package_name': package_name
           }

       finally:
           trigdroid.cleanup()

**Interactive Session Recording:**

.. code-block:: python

   from sandroid.features.recorder import Recorder
   from sandroid.features.player import Player

   def record_and_replay_session():
       """Record user session and replay for consistency testing"""

       recorder = Recorder()

       # Phase 1: Record user session
       print("=== Recording Phase ===")
       recorder.run()

       print("Please interact with the device. Press Enter when done...")
       input()

       # Save recording
       actions_file = recorder.export_actions("session_recording.json")
       recorder.cleanup()

       print(f"Session recorded to: {actions_file}")

       # Phase 2: Replay recorded session
       print("=== Replay Phase ===")
       player = Player()
       player.load_actions(actions_file)

       # Replay the session
       player.run()

       # Wait for replay completion
       while player.is_playing():
           time.sleep(1)

       print("Session replay completed")

Advanced Feature Usage
-----------------------

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
   from sandroid.features.trigdroid import Trigdroid

   class SynchronizedFeatures:
       def __init__(self):
           self.recorder = Recorder()
           self.trigdroid = Trigdroid()
           self.sync_event = threading.Event()

       def synchronized_execution(self, package_name, duration=120):
           """Execute features in synchronized manner"""

           # Configure features
           self.trigdroid.set_target_package(package_name)

           # Define synchronized execution
           def start_recording():
               self.recorder.run()
               self.sync_event.set()  # Signal other features

           def execute_triggers():
               self.sync_event.wait()  # Wait for sync signal
               time.sleep(10)  # Delay trigger execution
               self.trigdroid.run()

           # Start threads
           threads = [
               threading.Thread(target=start_recording),
               threading.Thread(target=execute_triggers)
           ]

           for thread in threads:
               thread.start()

           # Monitor execution
           time.sleep(duration)

           # Cleanup
           self.recorder.cleanup()
           self.trigdroid.cleanup()

           # Wait for threads to complete
           for thread in threads:
               thread.join()

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
2. **Enable only the Tracking screenshot triggers you need** to balance detail and storage
3. **Monitor system resources** during feature execution
4. **Handle errors gracefully** to prevent feature interruption
5. **Coordinate feature timing** to avoid conflicts
6. **Test trigger patterns** before production analysis
7. **Validate device state** before feature execution
8. **Archive recordings and Tracking screenshots** for evidence preservation

Configuration Integration
-------------------------

Tracking screenshots are configured in the ``[tracking]`` section:

.. code-block:: toml

   # Configuration file (sandroid.toml)
   [tracking]
   shot_before_tap = true
   shot_screen_change = true
   shot_after_tap = false
   shot_label = false

   [trigdroid]
   enabled = false

See Also
--------

- :doc:`core` - Core API for device management
- :doc:`analysis` - Analysis modules API
- :doc:`config` - Configuration system
- :doc:`../interactive_mode` - Using features in interactive mode
- :doc:`../advanced/custom_analysis` - Creating custom features
