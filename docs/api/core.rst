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

Snapshot protection
~~~~~~~~~~~~~~~~~~~

``sandroid.core.snapshot_policy`` decides who may overwrite or delete which
snapshot; ``EmulatorService.create_snapshot`` / ``delete_snapshot`` enforce
it before any console call (loads are never restricted):

- **Pinned** names (per AVD in ``devices.json``; ``clean_8g`` and
  ``default_boot`` by default) are never overwritten or deleted.
  ``pin(avd, name)`` / ``unpin(avd, name)``; only the user unpins (Devices
  screen ``p``), never the AI.
- **Owned** names belong to a ``Namespace`` (``rewind``: start points via
  ``rewind.is_start_point_name``; ``persona``: ``sandroid_persona_*``;
  ``analysis``: ``sandroid_malware*``). Only the owner saves or deletes
  them; the user may delete one after a confirm (``confirmed=True``).
- The caller says who it is with ``actor=`` or, through layers that don't
  pass it on, ``with snapshot_policy.acting_as("rewind"): ...``; the
  default is the user. ``EmulatorService.snapshot_refusal(op, name)``
  returns the ``Refusal`` (``reason``, ``pinned``, ``owner``,
  ``confirmable``) to explain it beforehand.

.. code-block:: python

   from sandroid.core.snapshot_policy import acting_as
   from sandroid.services import get_emulator_service

   with acting_as("persona"):
       get_emulator_service().create_snapshot("sandroid_persona_ab12cd34_ef56ab78")

Deleting through the console frees the snapshot's RAM image; the qcow2 disk
files never shrink (the freed clusters are reused). ``snapshot_complete(avd,
name)`` tells a loadable snapshot from a stub that only has ``snapshot.pb``.
``vanished_pins(avd, present)`` reports a pinned snapshot that disappeared
outside Sandroid, once.

Launch hooks
~~~~~~~~~~~~

Code that has to prepare an AVD before it boots (patch files under its
directory, add emulator arguments) and undo that afterwards registers hooks
with the emulator backend instead of wrapping each launch path:

.. code-block:: python

   from sandroid.core import emulator

   def prepare(ctx: emulator.LaunchContext) -> tuple[str, ...]:
       # ctx.avd, ctx.avd_dir (ini path= redirect honoured), ctx.port, ctx.options
       patch_config(ctx.avd_dir)
       return ("-writable-system",)

   def restore(ctx: emulator.LaunchContext) -> None:
       unpatch_config(ctx.avd_dir)

   emulator.register_pre_launch_hook(prepare)
   emulator.register_post_stop_hook(restore)

- **Pre-launch** hooks run before every emulator process Sandroid spawns --
  ``launch_avd``, ``restart_emulator`` and ``ensure_avd_running`` (the
  Devices screen, ``--avd``, and the AI tools via ``EmulatorService``'s
  restart / kill, i.e. ``restart_emulator`` / ``stop_emulator``) all funnel
  through one spot -- after the console port was chosen, in registration order (registering a callable
  twice is a no-op). Their arguments are appended after
  ``options.extra_args`` and never become remembered options. They are
  kept in ``devices.json`` (``hook_args``) only so that a later Sandroid
  process restarting that emulator strips them from its command line and
  the hooks decide afresh. Reusing an AVD that already runs calls no hook.
- ``restart_emulator`` relaunches an emulator this process did not launch
  the way it was started: the options come from its process command line
  (``running_options``), falling back to the remembered ones. Sandroid's
  safe GPU flags replace ``-gpu`` / ``-feature -Vulkan``, and ``-wipe-data``
  is never repeated.
- A pre-launch hook that raises fails the launch closed: no process is
  started, the port is released, the post-stop hooks run (best effort) and
  ``EmulatorLaunchError`` names the hook and its error.
- **Post-stop** hooks get the same ``LaunchContext`` once that emulator's
  process has really exited: on stop, on restart, on a startup crash, and
  best effort when it died on its own (noticed by the boot waiter or
  ``reap_exited_launches()``, which the next launch, the TUI's device poll
  worker and interpreter exit call). They run exactly once per launch, and
  always *finish* before any later pre-launch for the same AVD starts: a
  launch waits for a restore another thread is running (up to
  ``POST_STOP_WAIT`` s, then it fails closed), and an AVD whose old process
  is still exiting (e.g. saving its snapshot) is refused as "still shutting
  down" (``restart_emulator`` waits for it, see its ``exit_timeout``).
  Their exceptions are logged and never block a stop or restart.
- An emulator still running when Sandroid exits keeps running (it is
  detached) **with its patches**: post-stop hooks run only for launches
  Sandroid saw exit. Pre-launch hooks must therefore tolerate leftover
  state from an earlier session (e.g. a backup that is already there).
- Pre-launch and post-stop hooks are **not paired**: when any pre-launch hook
  fails, *all* registered post-stop hooks run, including ones whose own
  pre-launch hook never ran or stopped half-way. Every post-stop hook must
  therefore be idempotent and may run without its pre-launch hook -- e.g.
  have pre-launch write a marker (pointing at its backup) before it patches
  anything, and make post-stop a no-op when there is no marker.
- Emulators Sandroid did not launch can still be stopped, but get no
  post-stop hooks.
- Hooks run on the backend's worker threads, never on the Textual UI
  thread and never under the backend's internal locks;
  ``unregister_pre_launch_hook`` / ``unregister_post_stop_hook``
  remove them.

Launch record
~~~~~~~~~~~~~

Every emulator Sandroid starts has a record,
``emulator.launch_record(serial)`` (``None`` for one it did not start): a new
``launch_id`` per process, the AVD, port, options, full command, emulator
and system-image revision, a ``config.ini`` hash, ``meta`` (what the caller
passed: ``launch_avd(..., meta={"persona_id": ..., "persona_fp": ...})``;
a restart keeps it), ``hooks`` (what pre-launch hooks put into
``LaunchContext.record``, e.g. ``ctx.record["identity_sim"] = {...}``) and,
once the device was first prepared, ``boot_id`` and ``first_uptime``. The
launch is a timeline line (``emulator``/``launch``) carrying the record.

The device-prepared step treats a new ``launch_id`` as a new world even when
the boot id is the same (two boots from one snapshot); it then resets the
identity service once (``forget`` + ``sim_launch_changed``).

Blocking prepare stages
~~~~~~~~~~~~~~~~~~~~~~~

``device_prep.register_prepare_stage(name, stage, order=..., budget_s=...)``
runs ``stage(serial, fresh_boot, budget_s)`` on every prepare run, after
root / SELinux / the clock sync and before the device-prepared hooks (a
framework restart would undo what the hooks set up). Stages run in
``order``; the built-in ``identity`` stage
(``IdentityService.ensure_applied``, ``IDENTITY_BUDGET_S`` = 240 s, nothing
when identity mode is off) has ``IDENTITY_STAGE_ORDER`` = 20, so a persona
check registers below it. A stage returns ``None``, an info text or a
``StageNote(level, text)``; an exception or running past its budget plus
``STAGE_GRACE_S`` is a warning (``PrepResult.stage_notes``, the activity
log, a ``device``/``prep_stage`` timeline line) and the step goes on. App
starts and Frida wait for a running stage up to its own budget, even past
the usual gate timeout.

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

Report Engine
-------------

.. automodule:: sandroid.core.report_engine
   :members:
   :undoc-members:
   :show-inheritance:

JSON-first report engine: builds ``report.json`` from the sealed session
timeline (transcript steps with Tracking screenshots, coverage, the legacy
results tables and the seal). ``report.md`` and the optional PDF are
rendered from ``report.json`` alone.

**Basic Usage:**

.. code-block:: python

   from pathlib import Path

   from sandroid.core.report_engine import build_report, write_report

   # Build the report document (scope: see scope_for_run)
   doc = build_report(
       timeline=timeline_path,
       seal=seal,
       scope=scope,
       bundle_dir=Path(result_dir),
   )

   # Write report.json and render report.md / report.pdf from it
   written = write_report(doc, Path(result_dir), formats=("json", "md", "pdf"))

Report Rendering
----------------

.. automodule:: sandroid.core.report_render
   :members:
   :undoc-members:
   :show-inheritance:

Markdown and PDF renderers for a ``report.json`` document
(``render_markdown``, ``render_pdf``).

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
