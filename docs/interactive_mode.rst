Interactive Mode (TUI)
======================

Sandroid's default interface is a keyboard-driven terminal UI built with
Textual. It is ideal for manual analysis, exploring an app, and complex
investigations that need several tools at once.

Starting the TUI
----------------

::

   sandroid                              # default config discovery
   sandroid --config my-analysis.toml    # explicit config
   sandroid --network --screenshot 5     # pre-configure analysis options
   sandroid --log                        # also print log messages to the terminal

.. note::

   Sandroid 2.1 removed the legacy Rich menu (``sandroid -i``) and the
   Forensic/Malware/Security *views* (``TAB`` / ``--view``). All actions now
   live in one flat, rebindable catalog.

Screen Layout
-------------

- **Glance band** (top, boxed, device name in the border): frida-server state,
  mitmproxy engine, Device Proxy and App Proxies, spotlight app -- derived from
  the live device state.
- **Activity log**: real-time command output and status messages.
- **Tool tabs** (always visible): **Spotlight**, **Network**, **Snapshots**,
  **Files** -- see below.
- **AI Chat dock** (optional, ``Ctrl+Y``, experimental): see :ref:`ai-chat`.

Navigation
~~~~~~~~~~

==========================  ==================================================
Key                         Action
==========================  ==================================================
``r`` / ``p``               Record / Play (replay + diff) -- from any panel
``?``                       Help & keybinding editor (all actions by category)
``Ctrl+Shift+P``            Command palette (fuzzy-search any action)
``Ctrl+B``                  Focus the tool tabs
``Shift+Left/Right``        Previous/next tab (or sub-tab)
``Shift+Up/Down``           Move between tab levels (tabs / sub-tabs)
``Ctrl+Y``                  Toggle the AI Chat dock
``D`` (Shift+D)             Switch device
``q`` / ``Ctrl+C``          Quit
==========================  ==================================================

Every binding can be changed in the ``?`` editor (with live conflict
detection); overrides are stored in ``tui.keybindings`` in your config. Keys
are case-sensitive: an upper-case key means Shift+key and is shown as ``⇧R``
in the footer and ``Shift+R`` in the ``?`` list. The ``?`` list also shows
each panel's own keys (they only work while that panel has focus).

Tool Tabs
---------

Spotlight
~~~~~~~~~

The app under investigation. ``c`` attaches to the foreground app, ``C``
(Shift+C) spawns an installed app as spotlight. With the tab focused:

- ``Enter`` start (or resume a paused start), Shift+``A`` attach, Shift+``P``
  start paused, Shift+``R`` restart with the armed hooks, Shift+``K`` kill and
  tear down hooks, Shift+``X`` clear the selection
- ``1``-``5`` toggle/arm the Frida bypass categories **SSL**, **Root**,
  **Frida**, **Debug** and **Integrity** (PairIP/licensing/attestation).
  ``Ctrl+P`` toggles SSL unpinning globally.

.. warning::

   The bypass suite is **EXPERIMENTAL**. SSL unpinning covers Java/Conscrypt/
   OkHttp/WebView/TrustKit/Certificate Transparency, native BoringSSL,
   Chromium/cronet BoringSSL and mbedTLS / Meta Network Stack, but hardened
   apps may still detect or defeat it. Verify results independently.

Network
~~~~~~~

Two sub-tabs:

**Mitmproxy** -- embedded ``mitmweb`` (requires ``pip install mitmproxy``):

- ``Enter`` start/stop mitmweb (proxy ``:8080``, web UI ``http://127.0.0.1:8081/``)
- ``Ctrl+D`` toggle the Device Proxy (global ``http_proxy``)
- ``Ctrl+N`` install the mitmproxy CA into the system trust store (APEX
  bind-mount on Android 14+, Zygote namespace on Android 10-13)
- ``y`` Proxy Settings: Device Proxy, per-app **App Proxies** (iptables UID
  rules + on-device ``gost`` redirector, to Sandroid's mitmproxy or an
  external proxy such as Burp/ZAP; QUIC blocked by default) and CA
- ``Ctrl+R`` restart and re-apply proxies, ``Ctrl+O`` open the web UI,
  ``Ctrl+A`` manage custom mitmproxy addons, ``Ctrl+L`` clear the log

**friTap** -- status header and live log tail of friTap TLS key extraction
(``h`` starts friTap for the spotlight app).

Snapshots
~~~~~~~~~

AVD snapshot list: ``c`` create, ``l`` load, ``d`` delete, ``a`` assign to a
slot, ``Ctrl+R`` refresh. Globally, ``0`` opens the tab, ``1``-``8`` **pressed
twice** (within 3 s) load a slot -- the first press only asks, because loading
reverts the emulator and ``1``-``5`` are also Spotlight's bypass toggles -- and
``Ctrl+1``-``Ctrl+8`` save the current state into a slot (8 slots per AVD).
Snapshots require an emulator.

Files
~~~~~

- **Monitor** -- live filesystem events (``o`` / ``Enter`` start/stop). The
  default ``kprobe`` backend uses kernel tracefs kprobes (per-process and
  child-tree attribution, path-scoped capture, nothing pushed to the device)
  and falls back to ``fsmon`` automatically (``tui.monitor_backend``).
  Per-category visibility is configurable in the Monitor settings.
- **Watchlist** -- Spotlight Files: add device files to watch (``n``), pull
  and diff them (``u`` one, Shift+``U`` all; ``l`` opens the list).
- **Diffs** -- Record/Play results and the run history (``r``/``p`` work from
  every panel; Shift+``P`` here generates the PDF report of the selected run):

  1. ``r`` **Record**: name the run and the number of replays, then Sandroid
     snapshots the device and records your input (Esc in the settings form
     cancels without recording).
  2. Interact with the device, then stop: ``Esc``/``Enter`` (or *Stop*) stop
     and save, and the replay starts automatically; *Discard* throws the
     recording away.
  3. ``p`` **Play** (again): the emulator is reverted to the snapshot, the recording
     is replayed, background noise is measured with a dry run, and changed /
     new / deleted files (with inline diffs), processes, sockets and network
     activity are shown.

  Every Play is saved as a run bundle under ``<results_path>/runs/<run_id>/``
  and listed in the run history (per device). ``x`` / ``i`` export / import a
  recording.

Other Actions
-------------

==================  =========================================================
Key                 Action
==================  =========================================================
``f``               Frida server: download, install, start
``k``               Reconfigure Frida hooks
``a``               Static analysis of the spotlight APK (Dexray-Insight)
``m``               Dexray-Intercept malware monitor
``d``               Dump memory (Fridump)
``t``               TrigDroid malware triggers
``b`` / ``O``       Objection shell / resume objection session
``F``               Forensic evidence scan (MVT)
``G``               Manage forensic APKs
``e`` / ``E``       Emulator information / device settings & country presets
``s`` / ``g``       Screenshot / screen recording
``n``               Install APK
``w``               Network capture (PCAP)
``y`` / ``h``       Proxy settings / friTap
==================  =========================================================

Press ``?`` for the authoritative, up-to-date list.

.. _ai-chat:

AI Chat (EXPERIMENTAL)
----------------------

``Ctrl+Y`` opens a chat dock backed by any OpenAI-compatible chat-completions
endpoint. The assistant can query the device and drive ~76 Sandroid tools
(app lifecycle, flows, certificates, file transfer, monitor, record/replay),
spawn background subtasks, and use tools from configured MCP servers. Each
state-changing tool call asks for approval (once / always / never).

.. warning::

   Prompts, the live device/session context and tool output (file contents,
   flows, package data) are sent to the configured endpoint. Prefer a **local**
   endpoint such as Ollama for sensitive evidence, and pass the API key via
   ``SANDROID_AI__API_KEY`` instead of writing it into the config file.

.. code-block:: toml

   [ai]
   base_url = "http://localhost:11434/v1"   # e.g. Ollama
   model = "qwen2.5:14b"                     # a tool-calling capable model
   # api_key via: export SANDROID_AI__API_KEY=...  (any non-empty value for Ollama)

Tips
----

1. **Start with Frida**: install/start frida-server (``f``) before dynamic analysis.
2. **Use snapshots**: save a clean state into a slot (``Ctrl+1``) before
   each experiment and reload it (``1``) afterwards.
3. **Focus on one app**: set a spotlight app; App Proxies and the kprobe
   monitor can be scoped to it.
4. **Combine tools**: App Proxy + CA injection + SSL bypass for HTTPS
   inspection, friTap for apps that defeat proxies, the file monitor while
   exercising features.

Troubleshooting
---------------

- **frida-server does not start**: check root (``adb root && adb shell id``)
  and see :ref:`device-requirements`.
- **No device detected**: ``adb devices``; switch devices with ``D``.
- **TUI rendering issues**: run with ``--log`` and check
  ``results/<timestamp>/sandroid.log``.
- See :doc:`troubleshooting` for more.
