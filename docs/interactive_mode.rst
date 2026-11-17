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
   sandroid -s emulator-5556             # use this device (adb serial)

The startup screen checks adb, the device, root and SELinux. If that fails it
says why (e.g. ``Device 'emulator-5556' not found`` with the devices adb does
list) and only these keys work: ``r`` retries, ``d`` opens the device
selector (the device you pick is used for this session), ``q`` quits with exit
status 2.

.. note::

   Sandroid 2.1 removed the legacy Rich menu (``sandroid -i``) and the
   Forensic/Malware/Security *views* (``TAB`` / ``--view``). All actions now
   live in one flat, rebindable catalog.

Screen Layout
-------------

Sandroid shows one **lens** (a full-width analysis view) at a time and keeps
everything else out of the way until you ask for it:

- **Header** (one row): ``Sandroid ▸ device ▸ app``, the last loaded snapshot,
  the scope pill (``● LIVE``; ``● REC`` while recording; ``◆ REVIEW Run …``
  while reviewing a run) and the clock.
- **Status strip** (one or two rows): app state and pid, frida-server, active
  hooks and bypasses, mitmproxy / Device Proxy / App Proxies, capture.
- **Lens bar**: ``1 App  2 Network  3 Files  4 Runs`` (a lens may show an
  alert badge such as ``⚑2``).
- **Lens** (full width). ``Enter`` on a row opens the **Inspector** on the
  right where the lens offers details; ``[`` / ``]`` (or ``←``/``→`` when the
  lens does not use them) switch its tabs while focus stays in the lens;
  ``Esc`` closes it. Switching to another lens closes it too.
- **Log ticker** (one row): the newest activity-log line. The backtick key
  opens the **log drawer** with the full activity log.
- **AI Chat** (optional, ``Ctrl+Y``, experimental) opens in the same
  right-hand slot as the Inspector: see :ref:`ai-chat`.

Navigation
~~~~~~~~~~

==========================  ==================================================
Key                         Action
==========================  ==================================================
``1`` - ``4``               App / Network / Files / Runs lens
``Shift+Left/Right``        Previous/next lens
``Enter`` / ``Esc``         Open the Inspector (where offered) / close it
``[`` / ``]``               Previous/next Inspector tab
Backtick (grave accent)     Toggle the log drawer
``S`` (or ``0``)            Snapshot picker
``r`` / ``p``               Record / Play (replay + diff) -- from any lens
``L`` (Shift+L)             Back to LIVE while reviewing a run (``◆ REVIEW``)
``?``                       Help & keybinding editor (all actions by category)
``Ctrl+Shift+P``            Command palette (fuzzy-search any action)
``Ctrl+Y``                  AI Chat in the right-hand slot
``Ctrl+B``                  Focus the active lens (e.g. after the chat)
``,``                       Settings
``D`` (Shift+D)             Switch device
``q`` / ``Ctrl+C``          Quit
==========================  ==================================================

``Esc`` closes the Inspector / AI Chat first, then the log drawer; it never
quits. Every binding can be changed in the ``?`` editor (with live conflict
detection); overrides are stored in ``tui.keybindings`` in your config.
Overrides for ids from 2.1 that no longer exist (``load_slot_1`` …
``load_slot_8``, ``pick_save_slot``) are ignored. Keys are case-sensitive:
an upper-case key means Shift+key and is shown as ``⇧R`` in the footer and
``Shift+R`` in the ``?`` list. The ``?`` list also shows each lens's own keys
(they only work while that lens has focus). The footer shows at most seven
keys: Record, Play, the active lens's own keys, ``1-4``, quit and help.

Lenses
------

App (1)
~~~~~~~

The app under investigation (the spotlight). ``c`` attaches to the
foreground app, ``C`` (Shift+C) spawns an installed app as spotlight. With the
lens focused:

- ``Enter`` start (or resume a paused start), Shift+``A`` attach, Shift+``P``
  start paused, Shift+``R`` restart with the armed hooks, Shift+``K`` kill and
  tear down hooks, Shift+``X`` clear the selection
- ``b`` then ``1``-``5`` toggles/arms the Frida bypass categories **SSL**,
  **Root**, **Frida**, **Debug** and **Integrity**
  (PairIP/licensing/attestation); ``b`` then ``o`` (or ``b`` again) opens
  the Objection shell (elsewhere ``b`` opens it directly). Its launch dialog
  uses the same digits (``1`` SSL, ``2`` Root, ``3`` Frida, ``4`` Debug) plus
  ``e`` for emulator detection. ``Ctrl+P`` toggles SSL unpinning globally.

.. warning::

   The bypass suite is **EXPERIMENTAL**. SSL unpinning covers Java/Conscrypt/
   OkHttp/WebView/TrustKit/Certificate Transparency, native BoringSSL,
   Chromium/cronet BoringSSL and mbedTLS / Meta Network Stack, but hardened
   apps may still detect or defeat it. Verify results independently.

Network (2)
~~~~~~~~~~~

Who is the app talking to, and what did it send? One flow table
(time, recipient, request, status, size) read from the embedded
``mitmweb``'s flow log; ``Enter`` on a row opens Summary / Request /
Response in the Inspector. TLS failures and errored flows show as ✗ rows
(a ``⚑N`` badge on the lens counts TLS failures you have not seen yet).
``/`` filters by host, path or app, ``T`` shows only the spotlight (target) app's
flows, ``N`` shows OS background traffic (connectivity checks, Play
services), hidden by default. In REVIEW scope the table shows the reviewed
run's flows (those captured between its start and end). Proxy state is in
the frame caption (``mitm ● :<port> · device ✓ · CA ✓``, ``<port>`` being
``mitmproxy.proxy_port``); ``I`` opens the
Capture status page with mitmproxy and friTap tabs.

Proxy keys (embedded ``mitmweb`` requires ``pip install mitmproxy``):

- ``Enter`` (while nothing is captured) or ``M`` start/stop mitmweb (proxy on
  ``mitmproxy.proxy_port``, web UI on ``mitmproxy.web_port``; defaults
  ``127.0.0.1:8080`` and ``http://127.0.0.1:8081/``). Start does not touch the device unless
  ``mitmproxy.auto_device_proxy = true``; stop (and quitting Sandroid) clears
  the Device Proxy Sandroid set
- ``Ctrl+D`` toggle the Device Proxy (global ``http_proxy``)
- ``Ctrl+N`` install the mitmproxy CA into the system trust store (APEX
  bind-mount on Android 14+, Zygote namespace on Android 10-13)
- ``y`` Proxy Settings: Device Proxy, per-app **App Proxies** (iptables UID
  rules + on-device ``gost`` redirector, to Sandroid's mitmproxy or an
  external proxy such as Burp/ZAP; QUIC blocked by default) and CA
- ``Ctrl+R`` restart and re-apply proxies, ``Ctrl+O`` open the web UI,
  ``Ctrl+A`` manage custom mitmproxy addons, ``Ctrl+L`` clear the view
  (on screen only), ``Ctrl+V`` verbose mitmweb output in the log drawer

**friTap** -- ``h`` starts friTap for the spotlight app and shows its status
(the friTap tab of the Capture status page); ``Ctrl+F`` opens its output
folder. friTap's output goes to the log drawer.

Snapshot picker (S)
~~~~~~~~~~~~~~~~~~~

Snapshots are not a lens. ``S`` (or ``0``) opens the picker with the AVD's
snapshots: ``c`` create, ``Enter``/``l`` load, ``d`` delete (both confirmed),
``a`` assign the highlighted snapshot to a slot, ``Ctrl+R`` refresh. ``1``-``8``
load that slot after a confirm; ``s`` then ``1``-``8`` saves the current state
into a slot (8 slots per AVD). ``Ctrl+1``-``Ctrl+8`` save into a slot from
anywhere. The highlighted row stays on its snapshot while the list refreshes,
and the confirm names the snapshot (with date and size). Deleting a snapshot
clears the slots that pointed at it. After a load Sandroid sets SELinux back to
Permissive (a snapshot restores the mode it was saved with) and restarts
frida-server when ``frida.server_auto_start`` is on. The header shows the last
loaded snapshot. Snapshots require an emulator.

.. note::

   ``Ctrl`` + digit can only be sent by terminals that speak the kitty
   keyboard protocol (kitty, WezTerm, foot, Ghostty, recent iTerm2).
   Terminal.app, GNOME Terminal/VTE and tmux never deliver it -- use ``S``
   then ``s`` and the slot digit instead.

Files (3)
~~~~~~~~~

One table of what the app writes, one row per file (★, path, ops
``C``/``M``/``R``/``D``/``A``, count, last time). ``o`` starts/stops the
file monitor: the default ``kprobe`` backend uses kernel tracefs kprobes
(per-process and child-tree attribution, path-scoped capture, nothing pushed
to the device) and falls back to ``fsmon`` automatically
(``tui.monitor_backend``). Caches, temp files, OS paths and OPEN/CLOSE are
hidden until ``N`` (the same "show noise" key as in the Network lens);
per-category visibility is configurable in the Monitor
settings.

- ``w`` watches/unwatches the row (Spotlight Files); watched files are
  pinned on top with ★, also before any activity; ``n`` watches any path or
  ``*`` pattern; ``l`` jumps here.
- ``u`` pulls the row and diffs it against the previous pull, Shift+``U``
  pulls every watched file, ``a`` auto-pulls changed files while the lens
  is shown.
- ``Enter`` opens the Inspector: Summary (full path, ops, processes, last
  pull), Diff (``z`` zooms) and Events. ``/`` filters, ``.`` shows full
  paths.
- While a run is under review (``◆ REVIEW``), the table lists that run's
  changed, new and deleted files and ``Enter`` shows the file's diff.

Runs (4)
~~~~~~~~

Record/Play results and the run history (``r``/``p`` work from every lens;
``p`` lands here; Shift+``P`` generates the PDF report of the selected run):

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
and listed in the Runs lens (per device, newest first): ``#``, label, when,
how long (``×3`` for a run with three replays) and what changed
(files · hosts, ``⚠`` step errors, ``✕`` aborted). ``x`` / ``i`` export /
import a recording.

==================  =========================================================
Key (Runs lens)     Action
==================  =========================================================
``Enter``           Inspector: *Summary* (time, device, status, evidence
                    check, errors, settings used), *Changes* (files, hosts),
                    *Report* (PDF files, folder)
``v``               **Review** this run: the header shows ``◆ REVIEW <label>``
                    and the Files / Network lenses show this run instead of
                    the live session; ``v`` again or ``L`` (any lens) goes
                    back to LIVE. Recording or replaying always goes LIVE.
``=``               Compare with the run under review (or the previous run)
``z``               The run's full file diff (search / export)
Shift+``P``         Write a PDF report for the run
``n`` / ``Del``     Rename / delete the run (each asks first)
==================  =========================================================

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

``Ctrl+Y`` opens a chat in the right-hand slot, backed by any OpenAI-compatible chat-completions
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
2. **Use snapshots**: save a clean state into a slot (``Ctrl+1``, or ``S``
   then ``s`` ``1``) before each experiment and reload it (``S`` then ``1``)
   afterwards.
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
