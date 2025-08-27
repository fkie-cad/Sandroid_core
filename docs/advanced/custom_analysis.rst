Custom Analysis
===============

This guide shows how to create custom analysis modules and extend Sandroid's capabilities.

Creating Custom Analysis Modules
---------------------------------

All analysis modules inherit from the ``DataGather`` base class:

.. code-block:: python

   from sandroid.analysis.datagather import DataGather
   from sandroid.core.toolbox import Toolbox
   from logging import getLogger

   class CustomAnalyzer(DataGather):
       def __init__(self):
           super().__init__()
           self.logger = getLogger(__name__)

       def gather(self):
           """Collect custom data from the device"""
           # Your custom analysis logic here
           pass

       def return_data(self):
           """Return structured analysis results"""
           return {"Custom Analysis": self.results}

       def pretty_print(self):
           """Return formatted output for display"""
           return f"Custom Analysis Results: {self.results}"

Example: Custom File Monitor
----------------------------

.. code-block:: python

   import os
   from sandroid.analysis.datagather import DataGather
   from sandroid.core.adb import Adb

   class CustomFileMonitor(DataGather):
       def __init__(self, watch_paths=None):
           super().__init__()
           self.watch_paths = watch_paths or ["/sdcard/", "/data/local/tmp/"]
           self.initial_files = {}
           self.final_files = {}

       def gather(self):
           """Monitor specific file locations"""
           # Take initial snapshot
           for path in self.watch_paths:
               self.initial_files[path] = self._get_files_in_path(path)

           # Wait for user interaction or analysis period
           input("Press Enter after performing actions...")

           # Take final snapshot
           for path in self.watch_paths:
               self.final_files[path] = self._get_files_in_path(path)

       def _get_files_in_path(self, path):
           """Get list of files in specified path"""
           stdout, stderr = Adb.send_adb_command(f"shell find {path} -type f 2>/dev/null")
           return stdout.strip().split('\n') if stdout.strip() else []

       def return_data(self):
           """Return detected file changes"""
           changes = {}
           for path in self.watch_paths:
               initial = set(self.initial_files.get(path, []))
               final = set(self.final_files.get(path, []))

               new_files = final - initial
               deleted_files = initial - final

               if new_files or deleted_files:
                   changes[path] = {
                       "new_files": list(new_files),
                       "deleted_files": list(deleted_files)
                   }

           return {"Custom File Monitor": changes}

Creating Custom Features
-------------------------

Features inherit from the ``Functionality`` base class:

.. code-block:: python

   from sandroid.features.functionality import Functionality
   from sandroid.core.adb import Adb
   import time

   class CustomFeature(Functionality):
       def __init__(self):
           super().__init__()
           self.feature_name = "Custom Feature"

       def run(self):
           """Execute the feature"""
           self.logger.info("Running custom feature...")
           # Your feature logic here

       def cleanup(self):
           """Clean up resources"""
           pass

Integration with Sandroid
-------------------------

To integrate your custom modules:

.. code-block:: python

   from sandroid.core.actionQ import ActionQ
   from your_module import CustomAnalyzer, CustomFeature

   # Add to analysis workflow
   action_queue = ActionQ()
   custom_analyzer = CustomAnalyzer()
   custom_feature = CustomFeature()

   # Use in analysis
   custom_analyzer.gather()
   results = custom_analyzer.return_data()

For more detailed examples and advanced topics, see the API documentation.
