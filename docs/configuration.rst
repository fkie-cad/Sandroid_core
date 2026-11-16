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

   # AVD name to use for Sandroid analysis
   # selected_avd = <not set>

   # Start AVD in headless mode (no UI)
   avd_headless = false

   # Automatically start AVD when needed
   avd_auto_start = false

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

   # Screenshot interval in seconds
   # screenshot_interval = <not set>

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

   # Override keys: maps a binding id (the MenuController action name) to a key
   # string, e.g. {'proxy': 'ctrl+y'}. Edited by the in-app ? keybinding editor
   # or by hand.
   keybindings = {}

   # Per-AVD snapshot slot memory: maps an AVD name to a slot table
   # {slot_number: snapshot_tag}, e.g. {'Pixel_6_API_33': {'1': 'clean-boot',
   # '3': 'post-install'}}. Edited via the Snapshots tab (assign/save to slot).
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
   # with Enter in the Mitmproxy tab (off: start touches nothing on the device;
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

   # Show the model's full reasoning/thinking text in the Chat transcript. Off
   # (default) collapses it into a single 'Thought for Ns' line once the
   # reasoning phase ends.
   show_verbose_thinking = false

   # Show the small animated ASCII mascot in the Chat panel.
   show_chat_mascot = true

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

MCP servers (``[mcp]``) -- EXPERIMENTAL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   # One table per MCP server whose tools the AI Chat may use.
   # Default: only the bundled demo server (returns fabricated data!).
   [[mcp.servers]]
   name = "sandroid-dummy"
   transport = "stdio"        # "stdio" (command/args) or "sse" (url)
   command = "python"
   args = ["-m", "sandroid.ai.mcp_dummy_server"]
   enabled = true


Further sections -- ``[network]``, ``[trigdroid]``, ``[timeouts]``,
``[device_paths]``, ``[external_urls]``, ``[display]``, ``[credentials]`` --
contain advanced tuning knobs (timeouts, on-device paths, download URLs,
display widths) whose defaults rarely need changing; see
``sandroid-config show`` or :doc:`api/config` for the full schema.

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

   export SANDROID_ANALYSIS__SCREENSHOT_INTERVAL=5

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
   screenshot_interval = 5

   [trigdroid]
   enabled = true
   package_name = "com.suspicious.app"

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
   screenshot_interval = 10

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
   screenshot_interval = 30

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
       sandroid-config set -k analysis.screenshot_interval -v 10

   - name: Run Analysis
     env:
       SANDROID_AI__API_KEY: ${{ secrets.AI_API_KEY }}
     run: sandroid --headless --mode forensic --network --report

**Batch Processing Configuration:**

.. code-block:: bash

   #!/bin/bash

   # Different configs for different analysis types
   sandroid --config malware-analysis.toml --trigdroid com.malware.app
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
