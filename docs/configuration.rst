Configuration
=============

This guide covers Sandroid's comprehensive configuration system, including file formats, environment variables, and advanced configuration scenarios.

Quick Start
-----------

**Initialize Default Configuration:**

::

   sandroid-config init

This creates ``~/.config/sandroid/sandroid.toml`` with default settings.

**Basic Configuration:**

.. code-block:: toml

   log_level = "INFO"
   output_file = "analysis_results.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"

   [analysis]
   number_of_runs = 2
   capture_network = false

   [paths]
   results_path = "./results/"

Configuration File Locations
-----------------------------

Sandroid searches for configuration files in this order:

1. **Current directory**: ``./sandroid.toml``, ``./sandroid.yaml``/``.yml``
   (``sandroid.json`` -- the default results file -- and generic ``config.*``
   files are deliberately *not* picked up from the working directory)
2. **User config**: ``~/.config/sandroid/sandroid.toml`` (written by ``sandroid-config init``)
3. **Platform config directories** (e.g. ``~/Library/Application Support/sandroid/`` on macOS)

In the user/platform/system directories ``sandroid.*`` and ``config.*`` with
``.toml``, ``.yaml``, ``.yml`` and ``.json`` are tried in that order; TOML is
the default and recommended format. ``sandroid --config FILE`` works on its
own, without any discovered file.

Changes made in the TUI Settings screen are validated first and written to the
configuration file actually in use (the ``--config`` file if one was given,
otherwise the highest-priority discovered file, otherwise
``~/.config/sandroid/sandroid.toml``); only the changed keys are written.

**Check Configuration Paths:**

::

   sandroid-config paths

Configuration Formats
---------------------

**TOML (Recommended)**

.. code-block:: toml

   log_level = "INFO"
   output_file = "sandroid.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"
   android_emulator_path = "~/Android/Sdk/emulator/emulator"

   [analysis]
   number_of_runs = 2
   capture_processes = true
   capture_network = false

**YAML**

.. code-block:: yaml

   log_level: INFO
   output_file: sandroid.json

   emulator:
     device_name: Pixel_6_Pro_API_31
     android_emulator_path: ~/Android/Sdk/emulator/emulator

   analysis:
     number_of_runs: 2
     capture_processes: true
     capture_network: false

**JSON**

.. code-block:: json

   {
     "log_level": "INFO",
     "output_file": "sandroid.json",
     "emulator": {
       "device_name": "Pixel_6_Pro_API_31",
       "android_emulator_path": "~/Android/Sdk/emulator/emulator"
     },
     "analysis": {
       "number_of_runs": 2,
       "capture_processes": true,
       "capture_network": false
     }
   }

Configuration Sections
----------------------

The reference below lists every key of the main sections with its default
value (generated from ``sandroid/config/schema.py``). Keys shown as
``<not set>`` have no default (paths are auto-detected). ``sandroid-config show``
prints your effective configuration.

Top-level keys:

.. code-block:: toml

   log_level = "INFO"              # DEBUG, INFO, WARNING, ERROR, CRITICAL
   output_file = "sandroid.json"
   # whitelist_file = "whitelist.txt"
   environment = "production"

Emulator (``[emulator]``)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [emulator]
   # Android Virtual Device name
   device_name = "Pixel_6_Pro_API_31"

   # Path to Android emulator executable (auto-detected if not provided)
   # android_emulator_path = <not set>

   # Path to Android SDK (auto-detected if not provided)
   # sdk_path = <not set>

   # Path to ADB executable (auto-detected if not provided)
   # adb_path = <not set>

   # Android AVD home directory (auto-detected if not provided)
   # avd_home = <not set>

   # Start an AVD headless (no window) the first time it is launched from
   # the Devices screen; afterwards its remembered option wins
   avd_headless = false

   # Host-memory guard for the active emulator (GB, 0 disables it)
   max_host_memory_gb = 10

   # What to do above the limit: "kill" or "warn"
   memory_guard_action = "kill"

   # Set the device clock to host time at session start and after every
   # snapshot load (old name, still read: sync_clock_after_snapshot)
   sync_device_clock = true

**Host-memory guard.** With guest Vulkan enabled, the emulator leaks host
memory on every snapshot load and can grow to tens of GB. Sandroid therefore
watches the qemu process behind the active serial every 10 s:

* On macOS it measures the *physical footprint* (``footprint -p <pid>``), the
  memory the leak grows. Elsewhere, or without ``footprint``, it measures the
  resident set size (RSS). macOS RSS also counts resident guest RAM a second
  time: a healthy 8 GB AVD showed 8.5–15.0 GB RSS but 6.5–9.3 GB footprint.
* The enforced limit scales with the AVD's RAM (``-memory`` or ``hw.ramSize``
  in the AVD's ``hardware-qemu.ini`` / ``config.ini``) so a healthy AVD is
  never stopped:

  * footprint: ``max(max_host_memory_gb, RAM + 4 GB)``, e.g. 12 GB for an
    8 GB AVD and 10 GB for a 2 GB AVD;
  * RSS: ``max(max_host_memory_gb, 2 × RAM + 4 GB)``, e.g. 20 GB for an 8 GB
    AVD.

  When the RAM cannot be read, ``max_host_memory_gb`` applies unchanged.
* The emulator is stopped (``kill``) or reported (``warn``) only when a second
  reading, one poll interval later, is still above the limit. A warning is
  logged once at 75 % of the limit.

**Device clock at session start and after a snapshot load.** A snapshot
restores the guest clock it was saved with, so an emulator booted from a
snapshot, and every load, can leave the device minutes or hours behind the
host. With ``sync_device_clock`` on (default, also in Settings → General;
the old name ``sync_clock_after_snapshot`` is still read), Sandroid sets the
device wall clock to host time with a root ``date`` when it is more than 1 s
off, and re-measures: when a device is connected (once SELinux is
Permissive, after startup's ``setenforce 0``) and after every snapshot load. Either way the
offsets before and after go to the session timeline as ``clock`` lines (see
the ``[timeline]`` section below); a failed sync is logged once as a warning and the
offset is still recorded. Off keeps the snapshot's frozen clock. The device's
CLOCK_MONOTONIC (used by getevent, Frida, ``logcat -v monotonic``, kprobe) is
never changed; its offset is recorded too.

Frida (``[frida]``)
~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [frida]
   # Automatically start Frida server if not running
   server_auto_start = true

   # Frida server port
   server_port = 27042

   # Timeout for spawning processes (seconds)
   spawn_timeout = 30

   # Frida-server version to install. 'host' matches the installed frida Python
   # package (frida.__version__), 'latest' grabs the newest from GitHub, or
   # specify an explicit version like '17.9.11'. Legacy 'auto' is accepted as
   # an alias for 'host'.
   server_version = "host"

   # Max spawn-freeze attempts before failing loud (spawn-reliability ladder)
   spawn_attempts = 4

   # Seconds to poll the spawned PID for liveness after resume (crash-relaunch
   # detection)
   spawn_splash_window = 5.0

   # Seconds to sleep between spawn re-attempts
   spawn_retry_sleep = 0.6

Paths (``[paths]``)
~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [paths]
   # Directory for analysis results
   results_path = "results"

   # Directory for raw analysis data
   raw_results_path = "results/raw"

   # Directory for temporary files
   temp_path = "/var/folders/yy/5j4pjh1x5k35lpzkcxst2llnvrp4kt/T/sandroid"

   # Directory for cache files
   cache_path = "~/.cache/sandroid"

Analysis (``[analysis]``)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [analysis]
   # Minimum number of analysis runs
   number_of_runs = 2

   # Disable strong noise filtering (dry run)
   avoid_strong_noise_filter = false

   # Hide well-known Android/GMS background files (see below)
   system_noise_filter = true

   # Extra fnmatch globs treated as system noise
   noise_patterns = []

   # Packages whose files are never filtered as noise
   protected_packages = []

   # Generate MD5 hashes of changed/new files
   hash_files = false

   # Capture active processes during analysis run
   capture_processes = true

   # Capture listening sockets during analysis run
   capture_sockets = false

   # Capture network traffic during analysis run
   capture_network = false

   # Perform full filesystem checks for deleted files
   show_deleted_files = false

   # Seconds to keep capturing after each replay (see below)
   replay_settle_seconds = 8

   # Cycle the network after each snapshot load: airplane | svc | off (see below)
   network_reset_after_snapshot = "airplane"

   # List all APKs and their hashes
   list_apks = false

   # Simulate UMTS/3G connection speeds
   degrade_network = false

   # Default view mode for interactive menu (forensic, malware, or security)
   default_view = "forensic"

System noise filter
^^^^^^^^^^^^^^^^^^^

On a Google Play emulator image many files change in the background whether
or not the analysed app does anything: Digital Wellbeing, Play services
(``clearcut`` telemetry, SafetyNet), Gboard, the launcher, WebView, netstats,
``package-restrictions.xml``, ``recent_tasks`` and the permission module's
``access.abx``/``roles.xml``. The dry-run noise pass cannot catch all of them
because some are only touched while an app is in the foreground.

With ``system_noise_filter = true`` (the default) Sandroid hides paths that
match the curated ``DEFAULT_SYSTEM_NOISE_PATTERNS`` list in
``sandroid/analysis/filters.py`` plus your own ``noise_patterns``. Nothing is
deleted:

* hidden paths are listed with the pattern that matched them in the result
  JSON under ``"Other Data" -> "Filtered Noise"`` (raw pulls stay in the run
  bundle);
* files of the spotlight (target) app and of ``protected_packages`` are never
  hidden, even if a pattern matches them (any path component equal to, or
  starting with, the package name counts);
* set ``system_noise_filter = false`` to show everything.

Replay settle time
^^^^^^^^^^^^^^^^^^

A replay ends with the last recorded input event, so its capture window is
as long as the recording. On a slow link the app may still be loading when
the replay ends: a 16 s recording that opened an article 8 s before the end
produced an empty run. ``replay_settle_seconds`` (default 8) keeps every
replay's window open that much longer -- network, process and socket
captures keep running and files written in that time count as changed. The
dry run waits the same extra time, so noise subtraction still compares
windows of equal length. Each analysis gets ``(runs + 1) x`` that much
longer; set it to 0 to end the window with the replay.

Network reset after snapshot load
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every run starts by loading the ``tmp`` snapshot taken when the recording
started. The snapshot restores the app's open TCP connections, but not the
emulator's host-side NAT state. An app that was already open when you pressed
record therefore keeps sending requests over dead pooled connections (for
example an HTTP/2 connection to its API). The replay then shows "Cannot
connect ... timeout" and the run comes out empty.

``network_reset_after_snapshot`` (default ``"airplane"``) briefly takes the
device network down after every snapshot load that is followed by a replay
or by the dry run, and waits (up to 30 s) until a default network is back:

* ``"airplane"``: ``cmd connectivity airplane-mode enable``/``disable``
  (Android 11+; falls back to ``svc`` if the device rejects it);
* ``"svc"``: ``svc wifi``/``svc data`` ``disable``/``enable``;
* ``"off"``: leave the network alone (2.0 behaviour).

Removing the interface addresses makes Android destroy the sockets bound to
them, so the app sees an error at once and reconnects instead of waiting for
its read timeout. The UI state of the snapshot is kept: taps are still
replayed against the screen as it was when recording started. The reset
runs before the capture window opens and is done identically before every
action run and the dry run, so its own traffic and file writes are
subtracted as noise. Each reset adds about 5-10 s per run. It is skipped when
the snapshot has airplane mode on or no active network.

If an app reacts badly to briefly losing the network (for example it shows
an offline screen that changes the layout the replay taps on), either set
this to ``"off"`` and start recordings from the launcher with the app
force-stopped, or keep it on and record from a cold start anyway.

Network noise (dry run)
^^^^^^^^^^^^^^^^^^^^^^^

The network results are compared with the dry-run capture per destination
(IP:port) and per DNS name, by volume rather than by mere presence. Shared CDN
and load-balancer IPs are often contacted once in the background and then
carry most of the app's traffic. A destination also seen in the dry run is
therefore only treated as noise when its busiest action run is comparable to
the background:

* it stays in the results when its payload bytes exceed
  ``3 x background + 2048``, its packets exceed ``3 x background + 20`` or its
  connections exceed ``3 x background + 2``. It is then annotated with
  ``also seen in background: <bytes> in <packets> / <connections>``;
* a DNS name also queried in the dry run stays (annotated
  ``also seen in background: N queries``) when a destination reported above
  background resolved to it, or when it was queried more than
  ``3 x background + 2`` times;
* everything subtracted is listed with both volumes in the result JSON under
  ``"Other Data" -> "Filtered Noise"`` (sections ``Network`` and
  ``Network IP:Port (send/recv)``).

The thresholds are the ``NOISE_*`` constants in
``sandroid/analysis/network.py``. Without a dry run nothing is subtracted.

Report (``[report]``)
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [report]
   # Generate PDF report
   generate_pdf = false

   # Include screenshots in reports
   include_screenshots = true

   # Custom report template path
   # template_path = <not set>

   # Seconds after an input in which file/network lines count as its effects
   # in the report transcript
   effects_window_s = 2.0

   # Screenshot triggers shown in the report
   shot_triggers = ["before_tap", "after_tap", "screen_change", "label", "manual"]

   # Formats written besides report.json
   formats = ["pdf", "md"]

Session timeline (``[timeline]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every session device folder (``<results>/<session>/<device>/``) holds one
``timeline.jsonl``: an append-only JSON Lines file with one line per event --
labels, file-monitor events, monitor notes, pulls and checks, device-clock
samples, snapshot loads (world changes), device connects, record/play phases.
Each line carries ``seq``, its host time ``t`` (device times converted, with
``clk`` and ``t_err_ms``), ``world``/``epoch``/``phase``/``run``, ``src``,
``kind``, ``actor``, a ``summary`` and ``data``, and ends with ``h``, a
sha256 chained over every line before it. It replaces the former
``marks.jsonl``, ``files/timeline.jsonl`` and ``clock.jsonl``. A second
Sandroid on the same folder records no timeline (``.timeline.lock``). Check a
file with ``python -m sandroid.core.timeline verify PATH`` (also ``seal``,
``tail``, ``labels``; exit code 0 ok, 1 broken, 2 unreadable).

``label``, ``sandroid``, ``clock``, ``snapshot``, ``device``, ``run``,
``identity`` and ``privacy`` lines are always written; the policy below
applies to the other sources (``ai``: the AI Chat's prompts, tool calls and approvals).
Every change (Settings or ``update_config``) is recorded as a
``sandroid/policy`` line.

.. code-block:: toml

   [timeline]
   # Per-source switch (off = not written)
   sources = { files = true, monitor = true, net = true, input = true, screen = true, shot = true, ai = true }

   # Kinds not written: "src.kind" or "src.*"
   kinds_off = []

   # Kinds only counted, as one "<src>/count" line per window
   count_only = ["files.open", "files.close"]

   # files.attrs: a line inside the analysed app's data directories and a
   # count elsewhere (app_dirs), always a line (lines) or always a count
   files_attrs = "app_dirs"

   # files.modify lines of one path and process within this window become
   # one line (data.n/first/last); 0 = off
   files_modify_coalesce_ms = 1000

   # Seconds per count line
   count_window_s = 5.0

   # Bulk lines (files, monitor, net) queued per device before they are
   # dropped (a sandroid/dropped line says how many)
   queue_max = 10000

   # Seconds between periodic device-clock samples; 0 = off
   clock_every_s = 60

   # Mask sensitive lines (typed text, TLS keys) in the lens, the Inspector,
   # exports and reports. The file always holds the content.
   mask_sensitive = false

Tracking (``[tracking]``)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [tracking]
   # UI helper: full (accessibility events and element lookup; detectable by
   # the app), invisible (screenshots only), off
   helper_mode = "full"

   # Start Tracking with every recording
   auto_on_record = true

   # Screenshot triggers (taken while Tracking is on, Ctrl+T; stored under
   # tracking/shots/ of the session device folder; the s key adds one)
   shot_before_tap = true
   shot_screen_change = true
   shot_after_tap = false
   shot_label = false

   # Also store a marked copy of every screenshot of an input (before or
   # after a tap, and the screen change after a tap or after typing): a ring
   # at the tap with a box around the element, a double ring for a long
   # press, a line with an arrow head for a swipe, a box with the typed text
   # for typing. Stored next to the original as <sha>_<trigger>_marked.png
   # (its path and sha256 in the shot line's data.marked); the original and
   # its sha256 stay unchanged. Reports and the Inspector show the marked copy.
   mark_screenshots = true

   # After a tap: re-check the screen every settle_interval_ms until it is
   # stable or settle_max_ms passed
   settle_interval_ms = 300
   settle_max_ms = 2000

   # Typed text (a line once the field is idle for text_idle_ms); the line's
   # summary quotes it, passwords included (timeline.mask_sensitive hides it).
   # Off: only the number of characters is recorded.
   capture_text = true
   text_idle_ms = 1500

   # Gesture thresholds
   long_press_ms = 500
   swipe_slop_px = 24

   # Activity changes from logcat when accessibility events are unavailable
   logcat_screen_backup = true

Identity profile (``[identity]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An identity profile is a named set of distinctive fake values (Android ID,
advertising ID, device name, phone number, location, contacts, SMS, call
log, ...) seeded on the emulator, so the privacy scan can find them in
traffic and pulled files and name the value that leaked. Profiles are YAML
files in ``~/.config/sandroid/profiles/<id>.yaml`` (or
``$XDG_CONFIG_HOME/sandroid/profiles/``); the Identity lens (``6``) creates,
edits, imports and exports them and writes the keys below. Sandroid keeps
your comments and key order when it saves a profile.

A new profile (``P`` in the lens) is a full copy of one of the profiles
shipped with Sandroid (one per country preset), so a Sandroid upgrade never
changes its values. You can also write a profile that builds on another one
with ``extends: builtin:<id>`` or ``extends: <profile id>``: it then holds
only the keys it changes, and ``null`` removes an inherited key (``[]``
empties an inherited list). The lens tells you when the profile it extends
has changed since your last save; a hand-written profile records the state
of its parents at its first save, so that notice can only appear after it. A profile that others extend cannot be
renamed or deleted; export writes one standalone file that imports anywhere.

Its ``owner`` (``first``, ``last``, ``phone``, ``email``) can be used in value
templates as ``{owner.first}`` and so on; the owner's names must not contain
the profile's token. The ``world:`` section describes generated phone
contents (checked by the world module; a problem there never stops the
identity values from being applied); ``seed: auto`` there gets a fresh seed
on the first save.

Profiles from older versions (schema 1, ``<id>.toml``) are converted to YAML
once, the first time the library is read; the old file stays as
``<id>.toml.bak``. Their values, and with them the markers of earlier
applies, stay the same. Import also accepts such a TOML file. In a library
folder Sandroid cannot write to, they are read as they are.

.. code-block:: yaml

   # Created from builtin:de (Sandroid 2.1.0).
   format: sandroid-identity
   schema: 2
   id: mara-de
   name: Mara Kessler (DE)
   preset: de
   token: 3f9a1c07
   seed: hex:...            # 64 hex digits
   revision: 3
   created: 2026-11-19T10:00:00+01:00
   retired_tokens: []
   owner: {first: Mara, last: Kessler, phone: "+491520{digits:7}"}
   values:
     gps: {value: "52.516375, 13.397874"}
     # ... every other value, contacts, SMS and calls
   world: {seed: hex:..., size: medium, country: de}

.. code-block:: toml

   [identity]
   # Id of the active profile in the profile library
   profile = ""

   # off, or profile: seed the active profile before an app starts
   mode = "off"

   # Values such as the Android ID (SSAID) or the locale need a framework
   # restart, which stops every app: ask (default), always, or never (those
   # values stay pending)
   restart = "ask"

TUI (``[tui]``)
~~~~~~~~~~~~~~~

.. code-block:: toml

   [tui]
   # Path to custom CSS file for TUI styling. If not set, uses default styles.
   # custom_css_path = <not set>

   # TUI theme: default, dark, light, high_contrast, cyberpunk, nord, dracula,
   # solarized
   theme = "default"

   # Show current theme name in status bar. Disabled by default.
   show_theme_indicator = false

   # Custom logo color (hex, e.g., '#00ff00'). Overrides theme's logo color.
   # logo_color = <not set>

   # Custom 'Sandroid' text color in logo (hex, e.g., '#ffffff'). Overrides
   # theme.
   # logo_text_color = <not set>

   # If True, Ctrl+C exits immediately. If False (default), shows quit
   # confirmation dialog.
   immediate_exit_on_ctrl_c = false

   # Monitor output buffer flush interval in seconds. Lower values = faster
   # display, higher CPU. 0 = near-realtime.
   monitor_buffer_interval = 0.15

   # Maximum lines kept in Monitor observer log. Higher values use more memory
   # but allow scrolling back further.
   monitor_max_lines = 500

   # Per-category Monitor visibility: 'always', 'verbose', or 'never'.
   # Categories: create, modify, delete, rename, attrs, noise (monitor
   # OPEN/CLOSE).
   monitor_event_visibility = { create = "always", modify = "always", delete = "always", rename = "always", attrs = "always", noise = "verbose" }

   # Filesystem monitor backend: 'kprobe' (kernel tracefs kprobes; prefer
   # kprobe, auto-fall-back to fsmon when the kernel lacks support) or 'fsmon'
   # (the fsmon binary).
   monitor_backend = "kprobe"
   # Files lens: pull a watched (★) file when the monitor sees a write to it
   # (debounced ~1.5 s; a database and its -wal/-journal are one group)
   auto_pull_on_change = true
   # File monitor, App mode: follow the app -- every process, also ones that
   # start or restart later (kprobe) -- instead of one PID
   monitor_follow_app = true
   # Files lens hide / group rules (edited live with R in the Files lens):
   # {action = "hide"|"group", kind = "prefix"|"segment"|"suffix"|"glob",
   # pattern, enabled}. Default: hide /proc/ /sys/ /dev/ /system/ /apex/
   # /vendor/ /product/ /data/dalvik-cache/ /data/misc/ /data/system/
   # /data/app/; group cache and code_cache folders.
   # files_noise_rules = [ ... ]

   # Override keys: maps a binding id (the MenuController action name) to a key
   # string, e.g. {'proxy': 'ctrl+y'}. Edited by the in-app ? keybinding editor
   # or by hand.
   keybindings = {}

   # Per-AVD snapshot slot memory: maps an AVD name to a slot table
   # {slot_number: snapshot_tag}, e.g. {'Pixel_6_API_33': {'1': 'clean-boot',
   # '3': 'post-install'}}. Edited via the snapshot picker (key S).
   snapshot_slots = {}

   # Save to an occupied slot: 'ask' (prompt), 'overwrite' (re-save in place),
   # 'fresh' (new timestamped snapshot + re-point).
   snapshot_save_mode = "ask"

mitmproxy (``[mitmproxy]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [mitmproxy]
   # Listen port for the mitmproxy HTTP proxy
   proxy_port = 8080

   # Bind address for the proxy and app-proxy SOCKS listeners. 127.0.0.1 keeps
   # intercepted traffic off the LAN and is enough for emulators (10.0.2.2 is
   # the host loopback) and USB devices routed via adb reverse. Set 0.0.0.0
   # only for a physical device that reaches the host over Wi-Fi.
   listen_host = "127.0.0.1"

   # Also point the device's global http_proxy at mitmproxy when it is started
   # with Enter in the Network lens (off: start touches nothing on the device;
   # use Ctrl+D). The device proxy Sandroid set is cleared when mitmproxy stops
   # and when Sandroid exits.
   auto_device_proxy = false

   # Port for the mitmweb web UI
   web_port = 8081

   # Bind host for the mitmweb web UI
   web_host = "127.0.0.1"

   # Directory scanned for user-supplied mitmproxy addons
   addons_dir = "~/.config/sandroid/mitm_addons"

   # Resolved absolute path strings of addons to load into mitmweb
   enabled_addons = []

   # DEPRECATED: vestigial mode field. The proxy UI now derives display and
   # control from ground truth (device http_proxy + live app-proxy lanes), not
   # this stored mode. Kept (with its validator) so existing configs validate;
   # no longer drives behavior.
   capture_scope = "none"

   # Base host SOCKS5 port for our-mitmproxy app-proxy lanes
   socks_base = 8082

   # Number of app-proxy lanes (each = 1 on-device redirector + 1 mitmproxy
   # SOCKS port for our-mitmproxy lanes)
   focus_lanes = 5

   # Write every captured flow to a structured, queryable log under the
   # session's raw-results directory (mitm_flows/), so the AI chat's
   # get_captured_flows/get_flow_detail tools can read what was intercepted.
   # Disable to skip this bookkeeping entirely.
   flow_log_enabled = true

   # Maximum number of flow records kept in the structured flow log. Once
   # exceeded, the oldest records (and their detail files) are dropped to make
   # room for new ones.
   max_stored_flows = 5000

   # Maximum request/response body size, in bytes, captured per side into a
   # flow's detail file. Capped once at capture time -- raising this later
   # cannot recover bodies already truncated under a smaller value.
   max_captured_body_bytes = 65536

App Proxies (``[focus]``)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [focus]
   # Base on-device REDIRECT port for app-proxy lanes
   redirect_base = 60080

   # On-device path for the gost binary
   gost_binary_dst = "/data/local/tmp/gost"

   # Force the host IP our-mitmproxy lanes forward to (blank = auto, 10.0.2.2
   # on emulator)
   host_ip_override = ""

   # REJECT UDP/443 (QUIC) for proxied apps so they fall back to interceptable
   # TCP/TLS. Off = QUIC bypasses the app proxy.
   block_quic = true

   # gost release tag whose assets are downloaded
   gost_version = "v3.2.6"

   # Path to the lane→app sidecar map (consumers must expanduser() it)
   sidecar_path = "~/.cache/sandroid/focus_lanes.json"

   # Per-ABI gost download URLs and sha256 checksums. NOTE: assets are .tar.gz
   # archives; the sha256 is of the EXTRACTED `gost` ELF, not the tarball (the
   # download path extracts before checksumming).
   # gost_assets = <not set>

   # DEPRECATED (ipt2socks): superseded by gost_binary_dst
   binary_dst = "/data/local/tmp/ipt2socks"

   # DEPRECATED (ipt2socks): superseded by gost_version
   ipt2socks_version = "v1.1.4"

   # DEPRECATED (ipt2socks): superseded by gost_assets
   ipt2socks_assets = {}

MVT forensic scan (``[mvt]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [mvt]
   # Enable MVT forensic evidence scanning
   enabled = false

   # Path to STIX2 IOC file or directory containing IOC files
   # ioc_path = <not set>

   # URL to download STIX2 IOC files (e.g., from Amnesty International)
   # ioc_url = <not set>

   # Automatically update IOC files from URL before scanning
   auto_update_iocs = false

   # Scan SMS messages for IOC matches
   scan_sms = true

   # Scan call logs for IOC matches
   scan_calls = true

   # Scan installed applications for IOC matches
   scan_apps = true

   # Scan filesystem for IOC matches
   scan_files = true

   # Output format for MVT results (json, csv, or both)
   output_format = "json"

   # Remember IOC source preference (skip choice modal)
   remember_ioc_choice = false

AI Chat (``[ai]``) -- EXPERIMENTAL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [ai]
   # OpenAI-compatible chat-completions base URL
   # base_url = <not set>

   # API key for the endpoint -- prefer the SANDROID_AI__API_KEY environment
   # variable; a key in this file is stored in plaintext
   # api_key = <not set>

   # Model name to request
   # model = <not set>

   # Only loopback endpoints (localhost, 127.0.0.1, ::1) are used unless this
   # is true. Set it only if you accept sending case data to that remote
   # service.
   allow_remote = false

   # Show the model's full reasoning/thinking text in the Chat transcript. Off
   # (default) collapses it into a single 'Thought for Ns' line once the
   # reasoning phase ends.
   show_verbose_thinking = false

   # Chat mascot beside the input: auto | blocks | ascii | off. "auto" picks
   # ASCII on non-UTF-8 terminals. show_chat_mascot = false (the old switch)
   # still hides it.
   chat_mascot = "auto"

   # Model profile (context window, reasoning echo, system-message handling),
   # matched by model name; unknown models get a conservative 32k profile.
   # profile = "deepseek-v4"
   # context_window = 131072
   # Request parameters (unset = server default) and transport policy:
   # max_tokens = 8192, temperature = 0.6, top_p = 0.95, extra_body = {...}
   # request_timeout = [10, 120], retry_max = 4

   # [ai.budgets]  per turn: chat_max_rounds = 25, chat_max_tokens,
   #               chat_max_wall_s, agent_max_rounds = 20, ... (0 = off)
   # [ai.context]  result_cap_tokens = 8000 (larger results: preview + R-id),
   #               mask_at = 0.50, summarize_at = 0.85, output_reserve_tokens
   # [ai.agents]   gateway_concurrency = 4, researcher_max = 3,
   #               operator_max = 1, max_auto_wakes = 3
   # [ai.row_classify]  concurrency = 2, batch_rows = 40, batch_tokens = 24000,
   #               max_rows = 1000, max_tokens = 4096 (classify_rows)

   # Always-available host directory for the AI's file tools. Bare relative
   # paths given to list_host_dir/read_host_file/push_path/install_apk are
   # resolved against this directory -- drop a file here (e.g. an APK to
   # install) and the AI can reach it by filename alone. Created automatically
   # if missing.
   data_share_path = "~/Sandroid/ai_share"

   # Additional host roots the AI's file tools may access, beyond
   # data_share_path and the current session's results/raw-results/cache
   # directories. Empty by default.
   extra_host_paths = []

   # Mask the content of sensitive session-timeline lines (typed text, TLS
   # keys) in what the AI reads
   mask_sensitive = false

Approval rules for the AI's tools live in their own file,
``~/.config/sandroid/ai_tool_permissions.toml``:

.. code-block:: toml

   mode = "ask"            # "ask" (default) | "allow_all"
   allow = ["launch_app", "kill_process(package_name=com.example.*)"]
   deny  = []

A matching ``deny`` rule always wins; ``allow_all`` runs device-changing tools
without asking. Tools whose risk depends on an argument only accept rules that
constrain it. ``/permissions`` in the chat shows the rules and switches the
current session to ``allow_all`` or back. Conversation threads, stored tool
results (``R<n>``) and subagent transcripts are written to ``<session>/ai/``.

MCP servers (``[mcp]``) -- EXPERIMENTAL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   # One table per MCP server whose tools the AI Chat may use. None is
   # configured by default. The bundled demo server below is a test fixture
   # that returns FAKE data only (never use its output as a finding).
   [[mcp.servers]]
   name = "sandroid-demo-fake-data"
   transport = "stdio"        # "stdio" (command/args) or "sse" (url)
   command = "python3"
   args = ["-m", "sandroid.ai.mcp_demo_server"]
   enabled = true


Further sections -- ``[network]``, ``[timeouts]``,
``[device_paths]``, ``[external_urls]``, ``[display]``, ``[credentials]`` --
contain advanced tuning knobs (timeouts, on-device paths, download URLs,
display widths) whose defaults rarely need changing; see
``sandroid-config show`` or :doc:`api/config` for the full schema.

A ``[trigdroid]`` section from older versions still loads but is ignored, with
one warning: TrigDroid was removed. Pass the target package with
``--package``/``-p`` instead.

Environment Variables
---------------------

All configuration can be overridden with environment variables using the ``SANDROID_`` prefix:

**Basic Usage:**

.. code-block:: bash

   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_OUTPUT_FILE=custom_results.json

**Nested Configuration:**

Use double underscores (``__``) for nested values:

.. code-block:: bash

   export SANDROID_EMULATOR__DEVICE_NAME=Custom_Device
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
   export SANDROID_PATHS__RESULTS_PATH=/custom/path

**Boolean Values:**

.. code-block:: bash

   export SANDROID_ANALYSIS__CAPTURE_NETWORK=true
   export SANDROID_REPORT__GENERATE_PDF=false

**Complete Example:**

.. code-block:: bash

   # Core settings
   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_OUTPUT_FILE=malware_analysis.json

   # Emulator
   export SANDROID_EMULATOR__DEVICE_NAME=Malware_Analysis_Device

   # Analysis settings
   export SANDROID_ANALYSIS__NUMBER_OF_RUNS=3
   export SANDROID_ANALYSIS__CAPTURE_NETWORK=true
   export SANDROID_ANALYSIS__SHOW_DELETED_FILES=true
   export SANDROID_ANALYSIS__HASH_FILES=true

   # AI Chat (experimental) and reporting
   export SANDROID_AI__BASE_URL=http://localhost:11434/v1
   export SANDROID_AI__MODEL=qwen2.5:14b
   export SANDROID_AI__API_KEY=your_api_key_here
   export SANDROID_REPORT__GENERATE_PDF=true

Configuration Management
------------------------

**View Current Configuration:**

::

   sandroid-config show

**Validate Configuration:**

::

   sandroid-config validate

**Set Configuration Value:**

::

   sandroid-config set -k analysis.capture_network -v true
   sandroid-config set -k emulator.device_name -v MyDevice

**Get Configuration Value:**

::

   sandroid-config get -k analysis.number_of_runs
   sandroid-config get -k paths.results_path

Configuration Templates
-----------------------

**Malware Analysis Configuration:**

.. code-block:: toml

   log_level = "DEBUG"
   output_file = "malware_analysis.json"

   [emulator]
   device_name = "Malware_Analysis_AVD"

   [analysis]
   number_of_runs = 3
   capture_processes = true
   capture_network = true
   show_deleted_files = true
   hash_files = true

   [tracking]
   # Screenshots before each tap and on every screen change
   shot_before_tap = true
   shot_screen_change = true

   [report]
   generate_pdf = true

**Development Testing Configuration:**

.. code-block:: toml

   log_level = "INFO"
   output_file = "dev_test_results.json"

   [emulator]
   device_name = "Development_Test_Device"

   [analysis]
   number_of_runs = 1
   capture_processes = false
   capture_network = false

   [paths]
   results_path = "./dev_results/"

**Performance Testing Configuration:**

.. code-block:: toml

   log_level = "WARNING"
   output_file = "performance_results.json"

   [emulator]
   device_name = "Performance_Test_AVD"

   [analysis]
   number_of_runs = 1
   capture_processes = true
   capture_network = true

   [tracking]
   # Fewer screenshots: only before taps
   shot_screen_change = false

Environment-Specific Configuration
----------------------------------

**Development Environment:**

Create ``~/.config/sandroid/development.toml``:

.. code-block:: toml

   log_level = "DEBUG"

   [analysis]
   number_of_runs = 1

   [paths]
   results_path = "./dev_results/"

**Production Environment:**

Create ``~/.config/sandroid/production.toml``:

.. code-block:: toml

   log_level = "WARNING"

   [analysis]
   number_of_runs = 3
   capture_network = true

   [report]
   generate_pdf = true

**Usage:**

::

   sandroid --environment development
   sandroid --environment production

Advanced Configuration
----------------------

**Custom Configuration Sections:**

.. code-block:: toml

   # Standard configuration
   log_level = "INFO"

   [analysis]
   number_of_runs = 2

   # Custom sections for extensions
   [custom]
   my_plugin_enabled = true
   my_plugin_timeout = 120

   [custom.advanced_settings]
   experimental_feature = false
   debug_mode = true

**Configuration Validation:**

.. code-block:: toml

   [analysis]
   # This will be validated (must be >= 2)
   number_of_runs = 2

   [paths]
   # This will be validated (directory must exist)
   results_path = "./results/"

**Security Configuration:**

.. code-block:: toml

   # Don't put sensitive values in config files
   # Use environment variables instead

   [ai]
   base_url = "https://api.example.com/v1"
   allow_remote = true  # a remote endpoint is refused without it
   # api_key = ""  # Don't put API keys in files

.. code-block:: bash

   # Set sensitive values via environment
   export SANDROID_AI__API_KEY=your_secret_api_key

Troubleshooting Configuration
-----------------------------

**Configuration Not Found:**

.. code-block:: bash

   # Check search paths
   sandroid-config paths

   # Initialize if missing
   sandroid-config init

**Invalid Configuration:**

.. code-block:: bash

   # Validate configuration
   sandroid-config validate

   # Check for syntax errors
   python -c "import tomllib; tomllib.load(open('config.toml', 'rb'))"

**Environment Variables Not Working:**

.. code-block:: bash

   # Check environment variables
   env | grep SANDROID

   # Test variable format
   export SANDROID_LOG_LEVEL=DEBUG
   sandroid-config get log_level  # Should return DEBUG

**Configuration Priority Issues:**

Configuration loading priority:

1. Command-line arguments (highest)
2. Environment variables
3. Configuration file (--config)
4. Default configuration files
5. Built-in defaults (lowest)

**Debug Configuration Loading:**

::

   SANDROID_LOG_LEVEL=DEBUG sandroid --config my-config.toml

Integration with Tools
----------------------

**Docker Configuration:**

.. code-block:: dockerfile

   FROM sandroid:latest

   # Copy configuration
   COPY sandroid-docker.toml /app/config.toml

   # Set environment variables
   ENV SANDROID_PATHS__RESULTS_PATH=/app/results
   ENV SANDROID_LOG_LEVEL=INFO

   # Run with custom config
   CMD ["sandroid", "--headless", "--mode", "forensic", "--config", "/app/config.toml"]

**CI/CD Configuration:**

.. code-block:: yaml

   # GitHub Actions example
   - name: Configure Sandroid
     run: |
       sandroid-config init
       sandroid-config set -k analysis.number_of_runs -v 2

   - name: Run Analysis
     env:
       SANDROID_AI__API_KEY: ${{ secrets.AI_API_KEY }}
     run: sandroid --headless --mode forensic --network --report

**Batch Processing Configuration:**

.. code-block:: bash

   #!/bin/bash

   # Different configs for different analysis types
   sandroid --config malware-analysis.toml --package com.malware.app
   sandroid --config performance-test.toml --degrade-network
   sandroid --config development.toml -n 2

Best Practices
--------------

1. **Use configuration files** for consistent settings across runs
2. **Keep sensitive values** (API keys) in environment variables
3. **Validate configuration** before running analysis
4. **Use environment-specific configs** for different use cases
5. **Version control** configuration files (excluding secrets)
6. **Document custom** configuration sections
7. **Test configuration changes** before production use
8. **Use appropriate log levels** for different environments
9. **Set resource paths** correctly for your environment
10. **Monitor configuration** file sizes and complexity

See Also
--------

- :doc:`installation` - Initial configuration setup
- :doc:`quickstart` - Basic configuration for getting started
- :doc:`api/config` - Configuration API reference
- :doc:`troubleshooting` - Configuration-related troubleshooting
