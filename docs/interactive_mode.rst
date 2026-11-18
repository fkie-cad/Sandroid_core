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
  the scope pill (``● LIVE``; ``● REC`` while recording; ``● REPLAY ·
  <phase>`` while a Play runs -- ``loading snapshot``, ``replay 1/2``,
  ``settle 8s``, ``dry run``, ``analysing``; ``◆ REVIEW #<n> <label>`` while
  reviewing a run) and the clock.
- **Status strip** (one or two rows): app state and pid, frida-server, active
  hooks and bypasses, mitmproxy / Device Proxy / App Proxies, capture.
- **Lens bar**: ``1 App  2 Network  3 Files  4 Runs`` (a lens may show an
  alert badge such as ``⚑2``).
- **Lens** (full width). ``Enter`` on a row opens the **Inspector** on the
  right where the lens offers details; ``[`` / ``]`` (or ``←``/``→``, except
  in a text input) switch its tabs while focus stays in the lens;
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
``q`` / ``Ctrl+C``          Quit (asks first; ``Ctrl+Q`` too)
==========================  ==================================================

``Esc`` closes the Inspector / AI Chat first, then the log drawer, then
clears an applied lens filter; it never quits. The quit dialog always comes
first and lists what quitting stops (mitmweb, friTap, the file monitor, a
recording, ...) and that it clears the device proxy Sandroid set. After the
confirm the dialog stays up as "Quitting Sandroid…" and ignores keys until
Sandroid has exited; every step is time-boxed and runs off the UI thread,
so a tool that does not stop (e.g. a friTap agent stuck in a frozen app)
cannot hang the quit. Every binding can be changed in the ``?`` editor (with live conflict
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
- ``b`` then ``1``-``6`` toggles/arms the Frida bypass categories **SSL**,
  **Root**, **Frida**, **Debug**, **Integrity**
  (PairIP/licensing/attestation) and **Emulator** (Build profile, qemu
  properties, emulator files, telephony; arm it before Start, since apps
  check this at startup); ``b`` then ``o`` (or ``b`` again) opens
  the Objection shell (elsewhere ``b`` opens it directly). Objection loads no
  bypass hooks of its own: the ``b`` categories (BypassService) are the only
  source of bypasses. ``Ctrl+P`` toggles SSL unpinning globally.

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
``/`` filters by host, path, app or status (``/404``, ``/tls``, ``/✗``
for every failed row; ``Esc`` clears the filter), ``T`` shows only the
spotlight (target) app's flows, ``N`` shows OS background traffic
(connectivity checks, Play services and Google's ``*-pa.googleapis.com``
APIs, Sandroid's own ``mitm.it`` probe), hidden by default; the caption
says how many flows it hides (``N: 163 OS noise hidden``). ``Home`` /
``End`` jump to the first / last flow. Compressed bodies (gzip, br,
deflate, zstd) are shown decoded; the Inspector notes the encoding. TLS
failures are kept in the flow log too, so a later session or a reviewed run
still shows them. In REVIEW scope the table shows the reviewed
run's flows from its bundle (``<run>/network/flows.jsonl``, stored when the
run finishes and covered by its ``SHA256SUMS``, so they are there in any
later session). Only the flows of the **replays** are shown by default; the
dry run (the noise measurement) and the setup phases (snapshot loads, network
reset, baseline scan, collecting results) are hidden and counted in the
caption (``A: 29 dry run · 3 setup hidden``); ``A`` shows them, marked
``dry`` / ``setup``. A run without flows says why (mitmproxy was not running,
or captured nothing) and names the run's packet capture (pcap, with its size).
Runs from before this version have no flows in their bundle: they are looked
up in the current session's flow log by time, which only works in the session
that ran them, and the empty state says so. Snapshot loads (Play, the
snapshot picker) put mitmproxy's device proxy back when they reset it
(the snapshot restores the device's ``http_proxy``). Proxy state is in
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
  bind-mount on Android 14+, Zygote namespace on Android 10-13). This
  restarts Zygote: all apps close and System UI restarts. A busy emulator
  can need a minute or more and show "System UI isn't responding" meanwhile
  (choose Wait); Sandroid waits for the device to settle before it
  re-checks the proxy, then closes leftover system dialogs. Bypass hooks
  (``Ctrl+P``) die with their app; the indicators follow that.
- ``y`` Proxy Settings: Device Proxy, per-app **App Proxies** (iptables UID
  rules + on-device ``gost`` redirector, to Sandroid's mitmproxy or an
  external proxy such as Burp/ZAP; QUIC blocked by default) and CA
- ``Ctrl+R`` restart and re-apply proxies, ``Ctrl+O`` open the web UI
  (logged in: the URL carries the access token Sandroid gives mitmweb),
  ``Ctrl+A`` manage custom mitmproxy addons, ``Ctrl+L`` clear the view
  (on screen only), ``Ctrl+V`` verbose mitmweb output in the log drawer

**friTap** -- ``h`` starts friTap for the spotlight app and shows its status
(the friTap tab of the Capture status page); ``Ctrl+F`` opens its output
folder. friTap's output goes to the log drawer. The caption and the status
page follow friTap's real lifecycle: starting (attaching, loading the
agent), running, stopping (unloading the agent), stopped or failed. While
friTap runs, Sandroid watches the app for an "isn't responding" dialog and
says so ("app not responding -- h stops friTap"); it does not stop friTap on
its own.

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

What the ops mean: ``C`` a file or directory that did not exist before
(an ``O_CREAT`` open of an existing file -- SQLite reopening its database,
a ``>>`` append -- is an ``OPEN W``, shown with the noise; ``mkdir -p`` on
an existing directory is nothing), ``M`` written or truncated, ``R``
renamed (the old name shows ``old → new`` struck through), ``D`` deleted
(deleting a directory also marks its known files), ``A`` attributes.
Sandroid's own pulls (adb's ``sync svc``) never count as activity.

- ``w`` watches/unwatches the row (Spotlight Files); watched files are
  pinned on top with ★, also before any activity; ``n`` watches any
  absolute path or ``*`` pattern (relative paths and shell metacharacters
  are refused; the prefill is extended, not replaced); ``l`` jumps here. A
  pattern stars files only, not directories or deleted paths. Watches (★
  paths and patterns) are kept per app in
  ``~/.config/sandroid/watchlists/<package>.json`` (or
  ``$XDG_CONFIG_HOME/sandroid/...``) and come back after a restart.
- ``u`` pulls the row and diffs it against the previous pull, Shift+``U``
  pulls every watched file. With ``tui.auto_pull_on_change`` (default on)
  a write the monitor reports for a ★ file pulls it ~1.5 s after the last
  write (a database with its ``-wal``/``-journal`` is one group); nothing
  polls, so with the monitor off the caption says "monitor off — watched
  files not tracked · o starts it". ``w`` / ``n`` pull a first version of
  every newly watched file right away, so the first change can be diffed.
  Every pull with a real change is kept, never pruned, in the session
  results folder:
  ``files/<package>/<app path>/v001_HH-MM-SS/`` with the copy (+ database
  companions), ``diff.json`` (the diff against the version before as data:
  per table / key, operation, column names, old / new values, primary key;
  with the compared files and their sha256, the base version and the engine
  version), ``diff.txt`` (the same diff as plain text, rendered from
  ``diff.json``: column names, raw values, readable times for epoch-like
  values) and ``acquisition.json`` (device path; for the file *and* its
  ``-wal`` / ``-journal``: device mtime and size, sha256 computed on the
  device before the pull, local sha256; one combined set hash; pull time,
  trigger manual/auto/watch, the active mark); files outside an app
  directory go under ``files/_device/<path>/``. When the on-device sha256
  of the file and its companions equals the newest version's, nothing is
  pulled: one line goes to ``checks.jsonl`` in the file's folder and the
  Versions tab shows it as ``· 12:41:02 auto checked, no change (2×)``
  between versions. ``marks.jsonl`` in the session results folder (every
  mark: number, name, time) and ``files/timeline.jsonl`` (every monitor
  event: sequence number, time, operation, path, package, process, source,
  mark) are written as they happen, with millisecond times. All timestamps
  carry their UTC offset; readers ignore fields they do not know.
- **Marks**: ``B`` drops a mark (optional name; ⏎ on an empty name keeps
  it unnamed, Esc drops none). The table then shows only the activity
  since that mark (★ rows with activity in it stay on top; the idle ★ rows
  fold into one row, ``▸ ★ 21 watched · idle since mark 3``, that ⏎ or →
  opens and ← folds); ``A`` toggles everything / since the last mark (4 or
  more never-touched ★ rows fold there too) and ``<``/``>`` step through
  the segments. The caption names the segment, the log and the Inspector's
  Events tab show the marks as separator lines.
- **Hidden and grouped rows**: by default only OS paths (``/proc/``,
  ``/system/``, ``/data/dalvik-cache/``, ``/data/app/`` ...) and rows with
  only OPEN/CLOSE are hidden -- never the app's own data, nor
  ``/data/local/tmp``. ``cache/`` and ``code_cache/`` collapse into one row
  per folder (⏎ or → opens it, ← folds it). ``N`` shows every path raw.
  ``R`` opens the rule editor (hide / group by prefix, segment, suffix or
  glob; add, remove, toggle, reset); changes apply at once and are saved as
  ``tui.files_noise_rules``. The caption counts hidden rows per rule kind.
- ``Enter`` opens the Inspector: Summary (full path, ops, processes, last
  pull), Versions, Content and Events. The keys in its footer work while
  the Inspector has focus too.

  *Versions* lists every kept pull, newest first (time, size, manual/auto,
  what changed, e.g. ``moz_places +3 ~1 · moz_meta ~3``). Below the list is
  the selected version's diff against the version before it: SQLite per
  table with +inserted / ~updated / −deleted rows under their column names
  (an update shows only the changed cells, old → new; epoch ms/µs values get
  a dim local time), SharedPreferences / ABX / JSON as a key table, text as
  numbered hunks, binary files as size, sha256 and the bytes around the first
  difference. Above the diff, the version's acquisition record: when and
  how it was pulled (manual ``u`` or auto), the device's mtime and size, and
  whether the sha256 taken on the device before the pull matches the local
  copy (``= local ✓``; a mismatch is shown in red and flagged ``✗ sha256`` in
  the list). ``{`` / ``}`` (or a click) pick an older / newer version;
  ``*`` makes the selected version the base the others are diffed against
  (``*`` on it again clears it). These keys work only while the Inspector
  is open and are bound nowhere else, so they never collide with the lens's
  ``B`` / ``A`` / ``<`` / ``>`` mark keys; ``{`` ``}`` pair with ``[`` ``]``
  (tabs).

  *Content* is a first look inside the selected version's local copy:
  SQLite tables with row counts and the first 200 rows of one table (``{`` /
  ``}`` or a click picks the table), preference keys with their types, a
  JSON tree, the first lines of a text file, image facts, or a hex dump with
  a type guess. Only local copies are read, never the device; a database is
  read through a temporary copy with its ``-wal`` folded in.

  ``z`` shows the selected diff or table full-screen (nothing cut; wide
  tables scroll sideways). ``/`` filters,
  ``.`` shows full paths, Shift+``O`` sorts by recency / name / count,
  ``Home``/``End`` jump to the first/last row.
- While a run is under review (``◆ REVIEW``), the table lists that run's
  changed, new and deleted files and ``Enter`` shows the file's diff (drawn
  like the Versions diff; with a Content tab when the run kept the file). Their
  short paths name the owning app (``com.google.android.apps.messaging:
  databases/bugle_db``), as do live rows of apps other than the monitored
  one.

What the kprobe monitor can and cannot see:

- The probes match the path *string* a process uses. Apps reach their data
  as ``/data/user/0/<pkg>`` (what ``getFilesDir()`` returns) as well as
  ``/data/data/<pkg>``, so a target is watched under all its names
  (``/data/data/<pkg>`` also covers ``/data/user/0/<pkg>`` and the
  device-encrypted ``/data/user_de/0/<pkg>``) and both show as one row,
  ``/data/data/...``; ``@de/`` and ``@ext/`` mark the device-encrypted and
  external (``Android/data``) directories in short paths.
- Every write is named by the kernel at write time: the write probe reads
  the file's directory chain (up to eight names, e.g. ``places.sqlite-wal``
  < ``files`` < ``<pkg>`` < ``data``) and its filesystem, and the monitor
  maps that onto the watched directory. So writes through files the app
  opened *before* the monitor started -- its SQLite database and ``-wal``
  when you attach to a running app -- show up live, with their real time;
  attaching is as good as spawning. Files nested deeper than the chain
  reaches below the app directory are named only if the app opens them
  while the monitor runs.
- ``C`` is the kernel's verdict too (the open created the file /
  ``mkdir`` succeeded), so nothing is scanned at start or stop.
- Relative names (``cd dir && echo > f``, toybox ``rm -r``) don't match the
  path filter: such creations and deletions are not reported (a deleted
  directory marks its known files deleted); writes to such files are.
  Attribute changes (``A``) are named the same way as writes; in pure path
  mode they are not captured at all.
- The ``fsmon`` fallback reports writes through already-open files too
  (inotify/fanotify see every write, whenever the file was opened), but it
  watches a single path and, on kernels without fanotify, its per-process
  filter is unreliable.

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
3. ``p`` **Play** (again): asks first -- it names the recording, the number
   of replays and roughly how long it takes -- because the emulator is
   reverted to the snapshot taken when recording started. Then the recording
   is replayed, background noise is measured with a dry run, and changed /
   new / deleted files (with inline diffs), processes, sockets and network
   activity are shown. The header pill and the status strip show the phase
   (``● REPLAY · replay 1/2``, ``dry run``, ``analysing``). A Play takes
   roughly (replays + 1) x (recording length + settle time + ~2.5 min) + ~3
   min -- each replay window adds a snapshot load, a network reset and a
   result pull, and the baseline scan runs once. An 80 s recording with 2
   replays took 13-16 minutes on the emulator; the dialog shows a range.

   The Play that starts right after a recording keeps the name chosen in the
   Record dialog; a later ``p`` gets a fresh name (``Run <n> · <time>``).

Every Play is saved as a run bundle under ``<results_path>/runs/<run_id>/``
and listed in the Runs lens (per device, newest first): ``#``, label, when,
how long the Play took (``×3`` for a run with three replays) and what changed
(files · hosts, ``⚠`` step errors, ``✕`` aborted, ``≠ #2`` when it disagrees
strongly with another run of the *same* recording -- e.g. 0 vs 74 new files:
at least one replay did not do what the recording did). ``Home`` / ``End``
jump to the newest / oldest run. ``x`` / ``i`` export / import a recording.

==================  =========================================================
Key (Runs lens)     Action
==================  =========================================================
``Enter``           Inspector: *Summary* (run number and id, time, recording
                    length, other runs of the same recording and whether
                    they agree, device, status, evidence check, errors,
                    settings used), *Changes* (files, hosts), *Report* (PDF,
                    stored flows, pcaps, folder). The evidence check is
                    re-run on every ``Enter`` (and when a file's size or
                    time changes) and names the changed files.
``v``               **Review** this run: the header shows ``◆ REVIEW <label>``
                    and the Files / Network lenses show this run instead of
                    the live session; ``v`` again or ``L`` (any lens) goes
                    back to LIVE. Recording or replaying always goes LIVE.
``=``               Compare with the run under review (or the previous run);
                    hosts are compared without the "(also seen in
                    background …)" note, and two runs of the same recording
                    get a *Replay consistency* verdict
``z``               The run's full file diff (search / export)
Shift+``P``         Write a PDF report for the run
``n`` / ``Del``     Rename (the old label is selected, typing replaces it) /
                    delete the run (each asks first; dialogs name the run by
                    ``#`` and id)
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
