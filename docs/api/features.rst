Features API
============

The Sandroid features API provides functionality modules for enhanced analysis capabilities. These modules extend the core analysis with specialized features; recording and replay are done by Rewind.

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

Rewind
------

Rewind replaced the old record & replay batch in the TUI. ``r`` saves a
start point (an emulator snapshot named ``sandroid_rec_<YYYYmmdd_HHMMSS>``)
and records; ``r`` again stops and opens the Review list of new, changed and
deleted files and the requests seen. Selecting a file copies it as *After*.
**Rewind** loads the start point and copies *Before*; **Rewind + Replay**
also repeats the recorded steps and copies *After (replay)*. Each recording
lives in ``<session device folder>/recordings/rec-*/`` with its
``recording.json``. ``x`` exports a recording (with its copied files and,
when it still exists, its start point) and ``i`` imports it again.

.. automodule:: sandroid.core.rewind
   :members:

Replay of input events
~~~~~~~~~~~~~~~~~~~~~~

:class:`sandroid.features.player.Player` sends recorded input events back to
the device. Rewind + Replay and the headless ``--import-action`` batch use
it.

.. automodule:: sandroid.features.player
   :members:
   :exclude-members: STORE_LINE_RE
   :show-inheritance:

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
