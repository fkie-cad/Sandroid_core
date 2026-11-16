Quick Start Guide
=================

This guide will help you get up and running with Sandroid in minutes.

Prerequisites
-------------

Before starting, ensure you have:

1. **Sandroid installed** with Python 3.12+ (see :doc:`installation`)
2. **A rooted Android emulator** -- a ``google_apis`` image, or a Google Play
   image rooted with rootAVD/Magisk plus the ``adb_root`` module (see
   :ref:`device-requirements`)
3. **ADB working** -- test with ``adb devices``

Basic Usage
-----------

**1. Initialize Configuration**::

   sandroid-config init

**2. Start Your Android Emulator**::

   # Easiest: start the configured AVD (snapshots stay enabled)
   sandroid-config avd start

   # ...or start it manually
   emulator -list-avds
   emulator -avd Pixel_6_Pro_API_34 -no-snapshot-save

   # Verify connection
   adb devices

.. important::

   Do **not** use ``-no-snapshot``: Sandroid's Record/Play workflow and the
   Snapshots tab need AVD snapshots. ``-no-snapshot-save`` (do not overwrite
   the quick-boot snapshot on exit) is fine.

**3. Run Sandroid**::

   sandroid

Sandroid launches the Textual TUI. The top **glance band** shows device,
frida-server, proxy and spotlight state; below the activity log are four
always-on tool tabs:

- **Spotlight** -- the app under investigation (start, attach, restart, kill)
  and the Frida bypass toggles ``1``-``5`` (SSL, Root, Frida, Debug, Integrity;
  experimental)
- **Network** -- *Mitmproxy* (proxying, CA injection) and *friTap* sub-tabs
- **Snapshots** -- create/load/delete AVD snapshots, 8 quick slots
- **Files** -- *Monitor* (live file events), *Watchlist* (Spotlight files) and
  *Diffs* (Record/Play run history)

Press ``?`` for every action and its key (all keys are rebindable),
``Ctrl+Shift+P`` for the command palette, ``Ctrl+B`` to focus the tool tabs
and ``Shift+Arrows`` to move between tabs.

First Analysis - Recording User Actions
---------------------------------------

**1. Install Frida Server** (if needed for dynamic analysis)

   Sandroid prompts you to install ``frida-server`` when a command requires it.
   You can also install/start it manually with ``f``.

**2. Record User Interactions**

   Press ``r`` (from any panel). Name the run, confirm with ``Enter``;
   Sandroid saves a snapshot of the current device state, then records your
   touch input until you stop the recording (``Esc``/``Enter``).

**3. Perform Actions on Device**

   - Install an APK
   - Open apps, interact with them
   - Browse, use features
   - Stop the recording when done

**4. Play and View Results**

   Stopping the recording starts the replay automatically; ``p`` replays it
   again later. Sandroid opens **Files -> Diffs**, reverts to the snapshot, replays
   your recording, measures background noise with a dry run of the same
   duration and pulls/diffs everything that changed. The result shows:

   - **New files** created during your actions
   - **Changed files** and their (inline) differences
   - **Deleted files** (with ``--show-deleted``)
   - **Processes**, **listening sockets** and **network** activity (with ``--network``)

   Each Play is stored as a run bundle and stays available in the Diffs run
   history.

Command-Line Options
--------------------

Analysis options given on the command line pre-configure the session::

   # Repeat the action twice to filter noise more aggressively
   sandroid --number 2

   # Network monitoring with screenshots every 5 seconds
   sandroid --network --screenshot 5

   # Everything, plus a PDF report
   sandroid --network --sockets --screenshot 3 --hash --apk --report

For fully non-interactive runs use ``--headless`` (see :doc:`command_line_usage`)::

   sandroid --headless --trigdroid com.suspicious.app
   sandroid --headless --batch batch.json

Configuration Examples
----------------------

**Basic Configuration**

Create ``~/.config/sandroid/sandroid.toml``::

   log_level = "INFO"

   [emulator]
   device_name = "Pixel_6_Pro_API_34"

   [analysis]
   number_of_runs = 2
   capture_processes = true

**Security Analysis Configuration**::

   log_level = "DEBUG"

   [analysis]
   number_of_runs = 3
   capture_network = true
   capture_processes = true
   capture_sockets = true
   show_deleted_files = true
   screenshot_interval = 5
   hash_files = true
   list_apks = true

Common Workflows
----------------

**Malware Analysis Workflow**

1. **Setup**::

      sandroid-config init
      sandroid-config set -k analysis.capture_network -v true
      sandroid-config set -k log_level -v DEBUG

2. **Start Analysis**::

      sandroid --trigdroid com.suspicious.app --network --screenshot 3

3. **Inspect the app** in the TUI: set it as Spotlight app, enable the Frida
   bypasses it needs, route it through mitmproxy (**Network -> Mitmproxy**,
   ``y`` for App Proxies) and watch file activity in **Files -> Monitor**.

4. **Generate Report**::

      sandroid --report

**App Development Testing**

1. **Configure for Development**::

      sandroid-config set -k analysis.number_of_runs -v 2
      sandroid-config set -k paths.results_path -v ./test_results/

2. **Test Your App**::

      sandroid --screenshot 2

3. **Monitor Specific App**: press ``c`` (attach) or ``C`` (spawn) to make the
   foreground/selected app the Spotlight app.

Understanding Results
---------------------

**Output Files**

Every session writes to ``./results/<YYYYmmdd_HHMMSS>/`` (``paths.results_path``):

- ``sandroid.json`` -- analysis results (see below)
- ``sandroid.log`` / ``sandroid_error.log`` -- execution logs
- ``<device name>/`` -- per-device raw data: ``raw/`` (pulled files,
  ``recording.txt``, screenshots, network traces), ``spotlight_files/``,
  ``fritap/``, ``dexray_insight/``, ``timeline.png``
- ``sandroid.pdf`` -- generated report (with ``--report``)

Record/Play run bundles are kept under ``<results_path>/runs/<run_id>/``.

**Key Result Sections**

- **Changed Files**: files modified during the action, with diffs
- **New Files** / **Deleted Files**: files created / removed during the action
- **Processes**, **Listening Sockets**: captured during the action
- **Network** (DNS names) and **Network IP:Port (send/recv)**: with ``--network``
- **Other Data**: hashes, APK list, timeline data

**Example** ``sandroid.json``::

   {
     "Device Name": "Pixel_6_Pro_API_34",
     "Emulator relative action timestamp": 1731760000,
     "Action Duration": 42,
     "Changed Files": {
       "/data/data/com.example.app/shared_prefs/settings.xml": [
         "- <string name=\"user_id\">old_value</string>",
         "+ <string name=\"user_id\">new_value</string>"
       ]
     },
     "New Files": [
       "/data/data/com.example.app/files/config.json",
       "/sdcard/Download/payload.bin"
     ],
     "Deleted Files": [],
     "Processes": ["u0_a190  4711  com.example.app"],
     "Listening Sockets": [],
     "Network": ["api.example.com", "tracking.ads.example"],
     "Network IP:Port (send/recv)": ["93.184.216.34:443"],
     "Other Data": {
       "Timeline Data": [[]]
     }
   }

Next Steps
----------

Now that you've completed your first analysis:

1. **Learn Interactive Mode**: :doc:`interactive_mode`
2. **Explore Command-Line Options**: :doc:`command_line_usage`
3. **Configure for Your Needs**: :doc:`configuration`
4. **Handle Issues**: :doc:`troubleshooting`
5. **Advanced Features**: :doc:`advanced/custom_analysis`

Tips for Better Analysis
-------------------------

**Accuracy Tips**

- Run multiple analysis iterations (``--number 3``)
- Start from a clean snapshot as baseline
- Allow sufficient time between actions for monitoring
- Use ``--avoid-strong-noise-filter`` only if you want *more* (noisier) output

**Security Tips**

- Use isolated emulators for malware analysis
- Enable network monitoring for suspicious apps
- The AI Chat (``Ctrl+Y``) is **experimental** and sends device data to the
  configured LLM endpoint -- prefer a local endpoint (e.g. Ollama) for
  sensitive cases

**Troubleshooting Tips**

- Check ADB connection: ``adb devices``
- Verify root: ``adb root && adb shell id``
- Run with ``--log`` / ``-ll DEBUG`` and check ``results/<timestamp>/sandroid.log``
