Features API
============

The Sandroid features API provides functionality modules for enhanced analysis capabilities. These modules extend the core analysis with specialized features like recording and playback.

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

Trigger Execution
-----------------

There is no trigger feature module: the TrigDroid integration
(``sandroid.features.trigdroid``) was removed because it never worked inside
Sandroid. Scripted device events (sensors, network toggles, battery, ...)
will come as playbooks; until then use
:class:`sandroid.services.device_settings_service.DeviceSettingsService`.

Feature Integration Examples
----------------------------

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
6. **Validate device state** before feature execution
7. **Archive recordings and Tracking screenshots** for evidence preservation

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

See Also
--------

- :doc:`core` - Core API for device management
- :doc:`analysis` - Analysis modules API
- :doc:`config` - Configuration system
- :doc:`../interactive_mode` - Using features in interactive mode
- :doc:`../advanced/custom_analysis` - Creating custom features
