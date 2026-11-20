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
   sandroid --network                    # pre-configure analysis options
   sandroid --log                        # also print log messages to the terminal
   sandroid -s emulator-5556             # use this device (adb serial)
   sandroid --avd Pixel_6_Pro_API_34     # start/reuse this AVD, then use it

The startup screen checks adb, the device, root and SELinux. If that fails it
says why (e.g. ``Device 'emulator-5556' not found`` with the devices adb does
list) and only these keys work: ``r`` retries, ``d`` opens the Devices
screen (the device you pick or start there is used for this session), ``q``
quits with exit status 2.

**Devices screen.** Opens by itself at startup when no device (or more than
one, without ``--serial``/``--avd``) is connected, after a disconnect that does
not reconnect, and with ``D`` any time. The *Devices* box lists everything
once: the devices adb sees (emulators, USB and network devices: AVD or model,
API, booting/ready/offline/unauthorized, root, serial), then the AVDs that are
stopped, then AVDs running elsewhere (another session holds them). ``⏎``
attaches a ready device or starts a stopped AVD (the last-used AVD is
preselected); ``x`` stops an emulator (``emu kill`` for that serial only),
``R`` restarts it, ``e`` renames a stopped AVD, ``a`` runs ``adb connect
host:port``.

The *Launch options* box below shows the highlighted row's options. For a
stopped AVD they are editable and saved for that AVD at once (in
``~/.config/sandroid/devices.json``): boot (quick boot, ``c`` cold boot, ``n``
from a snapshot), ``h`` headless, ``s`` save state on exit (off by default:
the emulator starts with ``-no-snapshot-save``, so every boot starts from the
same state) and ``w`` wipe data once (asks on start, never remembered). The
keys work while the list keeps the focus, and the boxes can be clicked. ``⏎``
starts the AVD with exactly what is shown. For a running emulator the box
shows, read-only, what Sandroid started it with -- what ``R`` reuses -- or,
for one started outside Sandroid, the AVD's saved options (``R`` restarts
such an emulator with the options of its own command line). For a physical
device it shows its state and what to do about it (e.g. authorize USB
debugging). ``emulator.avd_headless`` is only the first-launch default.

``p`` pins or unpins a snapshot of the highlighted AVD. A pinned snapshot
can neither be overwritten nor deleted -- not from the Snapshots panel, by
Rewind or by the AI assistant. ``clean_8g`` and ``default_boot`` are pinned
on every AVD by default; unpinning asks first, and the AI can never unpin.
(The emulator's own quick-boot save on exit -- launch option ``s`` -- still
updates ``default_boot``; pinning only stops Sandroid from touching it.)
Rewind start points and persona snapshots belong to their feature: the
Snapshots panel deletes one only after a confirm that says whose it is. A
pinned snapshot deleted outside Sandroid (e.g. ``qemu-img`` while the AVD is
stopped) is reported once in the Devices screen and on the timeline.

.. note::

   Sandroid 2.1 removed the legacy Rich menu (``sandroid -i``) and the
   Forensic/Malware/Security *views* (``TAB`` / ``--view``). All actions now
   live in one flat, rebindable catalog.

Screen Layout
-------------

Sandroid shows one **lens** (a full-width analysis view) at a time and keeps
everything else out of the way until you ask for it:

- **Header** (one row): ``Sandroid ▸ device ▸ app``, the last loaded snapshot,
  the scope pill (``● LIVE``; while recording ``Recording 'Recording 13:36'
  · 0:12 · press r to stop``; during a rewind its step in plain words --
  ``Going back to the start point``, ``Saving Before of 3 files``,
  ``Replaying step 2 of 5: tap 'Accept all'``; ``◆ REVIEW #<n> <label>``
  while reviewing a run), the innermost open section (``Section 7 'accept cookies'
  0:12``; a new note shows ``Note 8 'text'`` there for 5 s),
  ``◉ TRK`` while Tracking runs, ``⚠ timeline locked (…)`` / ``⚠ timeline
  failed`` when this window records no timeline, and the clock.
- **Status strip** (one or two rows): app state and pid, frida-server, active
  hooks and bypasses, mitmproxy / Device Proxy / App Proxies, capture.
- **Lens bar**: ``1 App  2 Network  3 Files  4 Sessions  5 Timeline
  6 Identity`` (a lens
  may show an alert badge such as ``⚑2``).
- **Lens** (full width). ``Enter`` on a row opens the **Inspector** on the
  right where the lens offers details; ``[`` / ``]`` (or ``←``/``→``, except
  in a text input) switch its tabs while focus stays in the lens;
  ``Esc`` closes it. Switching to another lens closes it too.
- **Log ticker** (one row): the newest activity-log line. The backtick key
  opens the **log drawer** with the full activity log.
- **AI Chat** (optional, ``Ctrl+Y``, experimental) docks under the lens,
  beside the Inspector: see :ref:`ai-chat`.

Navigation
~~~~~~~~~~

==========================  ==================================================
Key                         Action
==========================  ==================================================
``1`` - ``6``               App / Network / Files / Sessions / Timeline /
                            Identity lens
``Shift+Left/Right``        Previous/next lens
``Enter`` / ``Esc``         Open the Inspector (where offered) / close it
``[`` / ``]``               Previous/next Inspector tab
Backtick (grave accent)     Toggle the log drawer
``S`` (or ``0``)            Snapshot picker
``r`` / ``p``               Record (``r`` again stops) / Review -- from any lens
``#``                       Section: start one (ends open sections; name)
``+``                       Sub-section: start one (name prompt)
``-``                       End section: ends the innermost one
``B`` (Shift+B)             Note: a point in time (asks for its text)
``Ctrl+T``                  Tracking on/off (input + screens into the timeline)
``L`` (Shift+L)             Back to LIVE while reviewing a run (``◆ REVIEW``)
``?``                       Help & keybinding editor (all actions by category)
``Ctrl+Shift+P``            Command palette (fuzzy-search any action)
``Ctrl+Y``                  AI Chat under the lens (focus it; again: close)
``Shift+Up``/``Down``       AI Chat size: 30% / 50% / 70% / max
``Ctrl+B``                  Focus the active lens (e.g. after the chat)
``,``                       Settings
``D`` (Shift+D)             Devices screen (attach / start / stop devices)
``q`` / ``Ctrl+C``          Quit (asks first; ``Ctrl+Q`` too)
==========================  ==================================================

``Esc`` in the AI Chat goes back to the lens; otherwise it closes the
Inspector first, then the log drawer, then the AI Chat, then clears an
applied lens filter, then turns an AI filter off (Network and Files); it
never quits. The quit dialog always comes
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
keys: Record, Review, the active lens's own keys, ``1-6``, quit and help.

Lenses
------

App (1)
~~~~~~~

The app under investigation (the spotlight) is a selection: ``c`` uses the
foreground app, ``C`` (Shift+C) picks an installed app. Selecting starts
nothing; the header shows the app's state (``● running pid N``,
``◐ paused · ␣ resume``, ``○ not running · ␣ start``). Frida tools (friTap,
Dexray, the bypasses, fridump, …) attach to a running app and start a stopped
one; they ask before restarting a running app (friTap's and Dexray's "Restart
the app first" option), and only Shift+``R`` restarts without asking. With the
lens focused:

- ``Space`` start (or resume a paused start; never restarts a running app),
  Shift+``A`` attach, Shift+``P`` start paused (asks first when the app runs;
  the app stays paused until ``Space``, which Android limits to about 10 s),
  Shift+``R`` restart with the armed hooks, Shift+``K`` kill the app and stop
  its tools (the bypasses that were on stay armed, so ``Space`` starts with
  them), Shift+``X`` clear the selection
- ``b`` then ``1``-``6`` toggles/arms the Frida bypass categories **SSL**,
  **Root**, **Frida**, **Debug**, **Integrity**
  (PairIP/licensing/attestation) and **Emulator** (Build profile, qemu
  properties, emulator files, telephony; arm it before Start, since apps
  check this at startup); ``b`` then ``o`` (or ``b`` again) opens
  the Objection shell (elsewhere ``b`` opens it directly). Objection loads no
  bypass hooks of its own: the ``b`` categories (BypassService) are the only
  source of bypasses. ``Ctrl+P`` toggles SSL unpinning globally. Dexray
  Intercept's own *Anti-Analysis Bypass* hook group and the ``b`` categories
  exclude each other: starting one while the other is on is refused.

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
Response in the Inspector. TLS failures and errored flows say so in the
status column (``TLS failed`` / ``error reset``, in the error colour; a
``⚑N`` badge on the lens counts TLS failures you have not seen yet). New
flows appear at the bottom; while *live* the newest flow stays selected
(and an open Inspector follows it); ↑, PgUp, Home, a wheel up or a click
above the newest row stop following (capturing goes on), ``End`` resumes.
The caption title starts with ``live`` or ``scrolled back · 12 new below ·
End = live``, then the capture state in words (``Mitmproxy on :8080 ·
device routed · CA installed · friTap on``).
``/`` filters by host, path, app or status (``/404``, ``/tls``, ``/error``
for every errored flow; ``Esc`` clears the filter), ``T`` shows only the
spotlight (target) app's flows, ``N`` shows OS background traffic
(connectivity checks, Play services and Google's ``*-pa.googleapis.com``
APIs, Sandroid's own ``mitm.it`` probe), hidden by default; the caption
says how many flows it hides (``N: 163 OS noise hidden``). ``Home`` /
``End`` jump to the first / newest flow (``End``: live again). Compressed bodies (gzip, br,
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
that ran them, and the empty state says so. Snapshot loads (Rewind, the
snapshot picker) put mitmproxy's device proxy back when they reset it
(the snapshot restores the device's ``http_proxy``). Proxy state is in
the frame caption (``mitm ● :<port> · device ✓ · CA ✓``, ``<port>`` being
``mitmproxy.proxy_port``); ``I`` opens the
Capture status page with mitmproxy and friTap tabs.

Proxy keys (embedded ``mitmweb`` requires ``pip install mitmproxy``):

- ``Space`` starts mitmweb (it never stops it), ``M`` starts/stops it (proxy on
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

.. _ai-highlights:

**AI highlights** (Network and Files lenses). The AI Chat (see
:ref:`ai-chat`) can highlight rows or show only some of them on request
("highlight all POST requests to api.example.com", "show only files with
personal data"). Each request becomes a *highlight set*: a row tint, a
*Highlight* column with the set's short label (when the lens is wide
enough) and a bar at the top of the lens with each set's label and row
count, ``filtering`` while its filter is on, and the keys. ``H`` cycles the
AI filter: off, the first set, the next set, ..., off again (the rows stay
highlighted when it is off). ``X`` removes the lens's highlight sets after a
confirm; the rows stay. ``Esc`` clears an applied ``/`` filter first and
only then turns the AI filter off. While the AI filter is on, its rows are
shown even when the OS-noise or path rules would hide them. The sets belong
to the analysis session (``<session>/ai/highlights.json``).

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
``C``/``M``/``R``/``D``/``A``, count, last time), oldest first: a file that
changes moves to the bottom (watched ★ rows stay pinned on top). While
*live* the cursor sticks to that newest row; ↑, PgUp, Home, a wheel up or a
click on a row above it stop following (the monitor keeps recording), and
``End`` resumes -- also with a file open in the Inspector, which then
follows the newest row. The caption title says ``live`` or ``scrolled back
· 3 new below · End = live`` (unpinned rows that changed since), then
``monitor on`` / ``monitor off``; it applies to the default "recent" order
only (Shift+``O`` sorts by name or count). ``o`` starts/stops the
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
  between versions. Every monitor event, pull, check, label and mark is a
  line of the session timeline (see :ref:`timeline-lens`), with millisecond
  times and their UTC offset.
- **Device clock** (``clock`` lines of the session timeline): the device
  clocks drift from the host's, and a snapshot
  load restores the clock the snapshot was saved with (75 min behind in one
  test). Sandroid samples the device's wall clock and its CLOCK_MONOTONIC
  (getevent, Frida, ``logcat -v monotonic`` and kprobe times use it)
  against the host over one persistent ``adb shell`` -- the best of several
  queries, good to about ``err_ms`` -- and writes one JSON line per sample:
  ``reason`` (``device-connect``, ``monitor-start``, ``periodic`` every
  60 s, ``pull``, ``snapshot-load``, ``sync``), ``off_wall`` (host − device
  wall clock, s), ``off_mono`` (host epoch = device monotonic +
  ``off_mono``), ``rtt_ms`` / ``err_ms``, ``host_at`` / ``device_at`` and
  ``jump``. ``jump`` is true after every snapshot load and clock sync and
  whenever either offset moved by more than 2 s (``jump_wall_s`` /
  ``jump_mono_s``), so every clock change of the session is visible.
  ``off_mono`` is null without root (``mono_note`` says why). With
  ``emulator.sync_device_clock`` on (default) the device wall clock is set
  to host time at session start and after a load (a telephony time
  suggestion to Android's time detector, which also replaces the
  snapshot's stale one; ``date`` when that is not taken), and a ``sync`` line
  records ``trigger`` (``session-start`` / ``snapshot-load``),
  ``before_off_wall`` / ``after_off_wall`` / ``ok`` / ``sets``; the
  ``device-connect`` and ``snapshot-load`` lines record the setting as
  ``sync_policy``. File and database timestamps (mtimes, values inside
  app databases) are device-clock values. After a snapshot reset the device
  wall clock can pass through the same times again, so such a value may not
  map to a single real time; the timeline records every clock jump and sync
  so an analyst can judge it. Each
  ``acquisition.json`` and ``checks.jsonl`` line carries the
  ``device_clock`` sample of its pull; when the device clock is more than
  1 s off, the Inspector (Summary, Versions) and the header (``dev
  16:01:02 75 min behind``, amber; ``dev 17:16:02 in sync`` dimmed
  otherwise) show it.
- **Session-start baselines**: watches persist across sessions, pulled
  versions do not. When the file monitor starts, each watched file of the
  monitored app is pulled once (``trigger: session-start``; at most 50, the
  rest named in the log), so the first change has a version to diff
  against; an unchanged file only gets a ``checks.jsonl`` line.
- **Notes and sections**: ``B`` (any lens) adds a Note (it asks for the
  note's text, which it needs: an empty Enter keeps asking, Esc adds
  none); a Section's start (``#``) and end (``-``) are boundaries too
  (segments ``Section 7 'x'`` and ``after Section 7 (no section)``). The
  table then shows only the activity since that note or section (★ rows
  with activity in it stay on top; the idle ★ rows fold into one row,
  ``▸ ★ 21 watched · idle since Note 3 'x'``, that ⏎ or → opens and ←
  folds); ``A`` toggles everything / since the last note or section (4 or
  more never-touched ★ rows fold there too) and ``<``/``>`` step through
  the segments. The caption names the segment, the log and the Inspector's
  Events tab show the notes and sections as separator lines.
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
  ``B`` / ``A`` / ``<`` / ``>`` note and section keys; ``{`` ``}`` pair with ``[`` ``]``
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
- **AI highlights**: as in the Network lens (see :ref:`ai-highlights`),
  ``H`` cycles the AI filter, ``X`` clears the highlight sets (asks first)
  and ``Esc`` clears the ``/`` filter before the AI filter.
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

Sessions (4)
~~~~~~~~~~~~

Rewind results and the run history (``r``/``p`` work from every lens;
Shift+``P`` generates the PDF report of the selected run). **Rewind** answers
"which file did my action change, and how?" for actions that cannot simply be
repeated (a cookie banner is gone once accepted):

1. ``r`` saves a **start point** (an emulator snapshot named
   ``sandroid_rec_<date>_<time>``, about 5 s) and starts recording your input
   (Tracking), the file monitor on the app's folders and a list of the app's
   files. An app must be selected. The recording is named
   ``Recording HH:MM``; rename it in Review.
2. Do the action on the device (accept the cookies, log in, ...).
3. ``r`` again stops and opens **Review**: the files that changed (``new`` /
   ``changed`` / ``deleted``, with size; the list keeps filling for a few
   seconds while the app finishes writing) and, when Network data exists, the
   requests seen. ``p`` opens Review again later.
4. **Select** files: a selected file is watched (★ in the Files lens) and its
   current version is copied at once -- that copy is **After**. Select
   requests to compare them after a replay (requests are compared after
   Rewind + Replay; Rewind alone does not compare them).
5. Press one of two buttons (nothing runs before):

   - **Rewind + Replay**: back to the start point, copy **Before** of the
     selected files, repeat your steps, copy **After (replay)**. The device
     ends after the action. Each step is replayed *by element* (the tapped
     element is found again and tapped where you tapped it: the same spot
     relative to its bounds, not its centre), else *by position* (the
     recorded coordinates); the Timeline shows ``by element``,
     ``by position``, ``failed: <reason>`` or ``diverged: <reason>`` for
     every step. Before a tap by element the UI helper tests the spot live:
     only when the element (or something inside it) is the topmost there is
     the step *verified*. When a dialog or the keyboard covers that spot,
     other visible spots of the element are tried; when none is free the
     recorded position is tapped, ``by position (element covered)``,
     unchecked. Without a live hit test the step is ``not hit-tested``,
     unchecked. A tap position is never scaled to another screen: on a
     display of another size or rotation the step is unchecked, and a
     position outside it is not tapped. A tap Tracking could not name
     surely (it read the element from an outdated snapshot and could not
     read it again in time) goes by position, unchecked. Text typed with
     keyboard taps is typed into its field when the replay finds that
     field focused and empty (the key positions depend on the keyboard's
     state); otherwise the keys are tapped, unchecked. Text typed another
     way is typed one character at a time at your recorded pace; either
     way the field is then read back: ``diverged: field reads '<x>', expected
     '<y>'`` when it holds something else (an autocomplete suffix after the
     recorded text is fine; password fields only say ``field text
     differs``). A tap that misses its element right after the step before
     missed its own also diverges. A replay with a diverged step ends
     **diverged**, never "Done": the log, Review, the Sessions lens and
     ``run.json`` say so, and every result after it carries a note naming
     the step. An element whose centre is not on the screen (a web page's
     element can report a position far below it) or that reached beyond
     the screen when you tapped it is not tapped by element: the recorded
     position is, ``by position (element off-screen)``. A step that could
     have been checked and was not (element not found or off-screen, field
     not read back) is *unchecked*; the run then ends **done, N steps
     unchecked**, a warning, not "Done". Swipes, keys and taps without a
     recorded element have nothing to check and do not count.
   - **Rewind**: back to the start point and copy **Before**. The device stays
     at the start point.

Every selected file gets **What your action changed** (Before → After). After
a replay it also gets **What the replay changed** and one of ``same change in
the replay``, ``differs only in volatile fields``, ``replay changed it
differently`` (with ``only in your run`` / ``only in the replay`` lines) or
``replay did not change it``. Both runs are compared field by field with the
Files lens's diff (SQLite cells by table, row key and column, preference keys,
JSON paths, text line blocks). A field both runs changed to different values
is *volatile* only when a rule explains it, never by its name: a **time of
its own run** (each value lies in its run, give or take 10 s), the **same
distance from its run** (measured from each run's first step, e.g. a cookie
that expires a year after its run) or a **freshly generated ID** (a UUID, or
16+ characters of one kind mixing letters and digits, random looking, the two
differing almost everywhere, and neither value was in Before). Columns added
to a table are compared byte for byte. Volatile fields are always listed with both
values and their rule, in the warning colour; ``replay changed it
differently`` is shown as a failure. Files without fields (binary, unknown)
are ``compared byte for byte``. While ``timeline.mask_sensitive`` (or
``ai.mask_sensitive`` for the assistant) is on, text typed into a password or
other sensitive field is hidden in every value shown. A selected
request shows ``found in the replay`` or ``not seen in the replay``, the two
requests side by side (URL, headers, body) and ``same`` / ``different`` for
the request body and the response status. All requests are listed per run
(``Your run``, ``Replay``), never diffed. One start point is kept at a time:
the next ``r`` replaces it unless *Keep this start point* is ticked. Physical
devices have no snapshots: Record and Review work, Rewind does not. Esc during
a rewind asks before stopping it.

The command line and headless runs keep the batch replay (replay count, dry
run, noise filter); the TUI no longer has it.

Every Rewind is saved as a run (its Inspector *Changes* tab shows the
per-file results, the replayed steps and the requests per run); its Changes column says how many files your run changed
and how many of them were compared (``159 changed, 0 compared``). Pressing
Rewind with no file selected asks once whether to go on (nothing would be
compared), and a file selected after a Rewind ran says that it has no After
from your run. The next ``r`` also removes the start points earlier
recordings left on the AVD (``Removed 3 old start points (11 GB)``), except
pinned and imported ones and any snapshot that is not Sandroid's; when it
cannot tell which are pinned it removes none. Command-line
analyses are saved as a run bundle under ``<results_path>/runs/<run_id>/``
and listed in the Sessions lens (per device, newest first): ``#``, label, when,
how long the run took (``×3`` for a run with three replays) and what changed
(files · hosts, ``⚠`` step errors, ``✕`` aborted, ``≠ #2`` when it disagrees
strongly with another run of the *same* recording -- e.g. 0 vs 74 new files:
at least one replay did not do what the recording did). ``Home`` / ``End``
jump to the newest / oldest run. ``x`` / ``i`` export / import a recording.

===================  =========================================================
Key (Sessions lens)  Action
===================  =========================================================
``Enter``            Inspector: *Summary* (run number and id, time, recording
                     length, other runs of the same recording and whether
                     they agree, device, status, evidence check, errors,
                     settings used), *Changes* (files, hosts), *Report* (PDF,
                     stored flows, pcaps, folder). The evidence check is
                     re-run on every ``Enter`` (and when a file's size or
                     time changes) and names the changed files.
``v``                **Review** this run: the header shows ``◆ REVIEW <label>``
                     and the Files / Network lenses show this run instead of
                     the live session; ``v`` again or ``L`` (any lens) goes
                     back to LIVE. Recording or replaying always goes LIVE.
``=``                Compare with the run under review (or the previous run);
                     hosts are compared without the "(also seen in
                     background …)" note, and two runs of the same recording
                     get a *Replay consistency* verdict
``z``                The run's full file diff (search / export)
Shift+``P``          Write a PDF report for the run
``n`` / ``Del``      Rename (the old label is selected, typing replaces it) /
                     delete the run (each asks first; dialogs name the run by
                     ``#`` and id)
===================  =========================================================

.. _timeline-lens:

Timeline (5)
~~~~~~~~~~~~

Everything the session recorded, one line per event and newest at the
bottom: file events, monitor notes, clock samples, snapshot loads, labels,
runs, Tracking input and screens, network flows. It reads the device folder's
``timeline.jsonl`` (the newest 20,000 lines first; ``Home`` at the top loads
older pages) and follows new lines live while it is shown. Columns: section
depth (``│``) and a flag (``!`` warning, ``~`` uncertain device time, ``▒``
masked), time, the step to the previous row, the type in plain words
(``tap``, ``long press``, ``swipe``, ``typed``, ``key``, ``screen``,
``screenshot``, ``request``, ``TLS failed``, ``file``, ``clock``,
``system`` ...), kind, actor and the summary (``· n times`` for coalesced or
counted lines). Colour, brightness and a background tint tell the types
apart (from the theme): your own input is the brightest row on a tinted
band, screens and screenshots have a second accent, requests a muted type
word, file, clock and system rows are dimmed; warnings and errors keep their
colours.

The **type bar** above the list lists every type present in its colour with
its count (``tap 21 · typed 2 · screen 76 · request 445 · file 3,084``) and
then the apps present: a click on a type hides / shows it, a click on an app
shows only its lines (the ``pkg:`` filter; ``all`` for every app; the apps
have their own second line). ``t``
reaches it from the keyboard (←/→, ``Space``; ``t`` or ``Esc`` back). It
combines with the ``/`` filter.

**Folding** (view only; the rows, the Inspector, ``J``/``V`` and reports keep
every line): consecutive file rows of one app less than 2 s apart fold into
one row (``file · org.x · 214 changes (88 modify, 61 create, 40 rename …) in
cache2, databases``); ``Enter`` or a click opens / closes it. ``z`` or a
click on a section's header row folds the section into one row (``Section 3
'Login' · 2:14 · 412 lines (12 taps, 300 files, 80 requests)``). Filters
apply before folding.

Separators mark what changes how to read the lines after them, in plain
words: ``snapshot 'clean' loaded · world 3`` (a world change: snapshot
load, cold boot, a device clock that went backwards), ``clock epoch 2``,
``Section`` / ``Sub-section … in Section 1`` / ``End section`` / ``Note``,
``recording started`` / ``replay started`` / ``replay finished`` runs (a
failed one says ``replay failed`` / ``recording failed`` in the error
colour), ``restarted`` (Sandroid), Tracking and intervention (e.g.
accessibility helper) on/off. No row starts with a symbol; a masked line
says ``masked`` in its kind column, an uncertain device time shows as an
amber time. Clock samples, count lines and a quick
device reconnect are hidden until ``N``.

===================  ========================================================
Key (Timeline lens)  Action
===================  ========================================================
``Space``            Live on / off: ``live`` sticks to the newest line; ↑
                     or a click above it stops that (recording goes on):
                     ``scrolled back · 23 new below · End = live`` in the
                     caption title. The Files and Network lenses follow
                     the same way
``End`` / ``Home``   Newest + follow / oldest (at the top: load older lines)
``t``                Type bar: ←/→, ``Space`` hides / shows a type or picks
                     an app
``z``                Fold / unfold the section around the cursor
``/``                Filter: ``src:files,label`` ``-src:clock``
                     ``kind:modify`` ``actor:user`` ``phase:replay``
                     ``run:<id>`` ``world:3`` ``pkg:x`` ``level:warn`` and
                     words (quoted for phrases) matching the summary; shown
                     as chips with the count; ``Esc`` clears it
``N``                Show / hide clock samples, counts, reconnects
``Enter``            Inspector: *Line* (envelope, data, follow-ups, enclosing
                     sections), *JSON*, *Ref* (the referenced line, file with
                     sha256 check, diff, run), *Chain* (hash, previous hash,
                     a one-line verify)
``J``                Jump to the source: a pulled file (Files, Versions
                     tab), a flow (Network), a run (Sessions) or the line it
                     refers to
``V``                Reveal a masked line (asks first; the reveal is recorded
                     on the timeline)
===================  ========================================================

In REVIEW scope the lens shows the reviewed run's lines (an implicit
``run:<id>`` chip) plus the separators inside its time window.

**Sections and notes** (any lens; the timeline's labels): ``#`` starts a
Section and ends every open one; ``+`` starts a Sub-section inside the open
section (or a sibling of an open sub-section; with nothing open it starts a
section); ``-`` ends the innermost section (End section); ``B`` drops a Note.
``#``, ``+`` and ``B`` take their time when the key is pressed; ``#`` and
``+`` ask for an optional name, ``B`` for the note's text, which it needs (an
empty ``Enter`` keeps asking); ``Esc`` writes nothing. Sections survive
snapshot loads and are ended when Sandroid quits or the device changes.

**Masking**: lines marked sensitive (typed text, passwords) are shown
masked in the lens, exports and reports while ``timeline.mask_sensitive`` is
on (Settings → Timeline; default off). ``ai.mask_sensitive`` does the same
for the AI assistant. A typed-text line's summary quotes what was typed
(``typed "hunter22" into password field 'Passwort'``); while masked it only
gives the count (``typed 8 chars into password field 'Passwort'``).

**Web pages**: a tap in a browser or an app's WebView names the HTML element
from the accessibility tree alone (no script in the page): its role, label,
html id, a link's target and the page (``tap button 'Accept all'
(#accept-all) on example.com``, ``... in page '<title>'`` inside an app).
Fields that send no text events (browser address bars, Jetpack Compose) are
read back once typing pauses (``data.via`` ``readback``).

**Settings → Timeline** sets which sources are recorded, kinds that are off
or only counted, the file-event coalescing window, the clock sampling
interval, both mask switches and the Tracking capture settings (helper
mode, screenshots before/after taps and on screen changes, marked copies of
those screenshots, text capture, gesture thresholds).

Identity (6)
~~~~~~~~~~~~

The identity profile: distinctive fake values (Android ID, advertising ID,
device name, phone number, location, contacts, SMS, call log, ...) seeded
on the emulator, so the privacy scan can find them in requests and pulled
files and name the value that left the device. One table, grouped into
Identifiers / Telephony / Place & language / Personal data; per value its
status, where it was found (``3 recipients``, ``stored on device``, ``sent
and stored``, or ``not seen``), the profile value, the value on the device
now and how it is applied. A value that was found gets a tinted row.
``Enter`` opens the Inspector: *Found* lists the hits by recipient or file
(time, where, how it was encoded, confidence, the snippet; ``{`` / ``}``
pick a hit, ``J`` jumps to it in the Network, Files or Timeline lens) and
*Value* the profile value, the apply mechanism and the value before the
apply. In the Network lens ``!`` shows only the flows that carry a profile
value.

=================  ==========================================================
Key (Identity)     Action
=================  ==========================================================
``Space``          Apply the profile to the device
``e`` / ``v``      Edit the selected value / verify the device's values
``P``              Profiles (switch, create, duplicate, rename, delete)
``R``              Regenerate values
``I`` / ``X``      Import / export a profile
``M``              Identity mode on/off (``identity.mode``)
``J`` / ``/``      Jump to the selected hit's source / filter rows
=================  ==========================================================

Profiles are TOML files in ``~/.config/sandroid/profiles/`` (see
``[identity]`` in :doc:`configuration`). Values such as the Android ID or
the locale need a framework restart, which stops every app;
``identity.restart`` says whether Sandroid asks first.

Other Actions
-------------

==================  =========================================================
Key                 Action
==================  =========================================================
``f``               Frida server: download, install, start
``k``               Reconfigure Frida hooks
``a``               Static analysis of the spotlight APK (Dexray-Insight); the
                    dialog picks the profile (``p``: privacy or generic) and
                    switches trackers (``t``), security analysis (``s``) and
                    verbose output (``v``); the last choice is remembered
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

``Ctrl+Y`` opens a chat docked under the lens (``Ctrl+Y`` again focuses it,
then closes it; ``Esc`` goes back to the lens), backed by any OpenAI-compatible
chat-completions endpoint. ``Shift+Up`` / ``Shift+Down`` step its size through
30%, 50%, 70% and max; dragging its top border resizes it and a double-click
there toggles max. The size is remembered in ``tui.chat_dock``. The assistant can query the device and drive ~80 Sandroid tools
(app lifecycle, flows, certificates, file transfer, monitor, record/replay),
start ``researcher`` / ``operator`` subagents (cards in the chat, the agents
bar opens their transcripts), and use tools from configured MCP servers. Each
state-changing tool call asks for approval (Yes / Yes, don't ask again / No
with a note). ``Ctrl+L`` starts a new thread, ``Ctrl+X`` stops a reply and its
subagents, and ``/`` lists the slash commands (``/threads``, ``/compact``,
``/context``, ``/permissions``, ``/agents``, ``/doctor``).

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
- **No device detected**: ``adb devices``; open the Devices screen with ``D``.
- **TUI rendering issues**: run with ``--log`` and check
  ``results/<timestamp>/sandroid.log``.
- See :doc:`troubleshooting` for more.
