# Changelog

All notable changes to the Sandroid project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Session timeline (`timeline.jsonl`) replaces `marks.jsonl`, `files/timeline.jsonl` and `clock.jsonl`.** Every session device folder (`<results>/<session>/<device>/`) gets one append-only, hash-chained JSON Lines file written by one process-wide service (`core/timeline.py`). Every line carries `seq` (contiguous, continued across restarts), the host time `t` (device CLOCK_MONOTONIC / wall times converted through the device clock, with `clk` and `t_err_ms`), `world` (+1 on every snapshot load, cold boot or inferred monotonic-clock rewind), `epoch`, `phase` (`live`/`record`/`replay`/`dry-run`/`setup`) and `run`, `src`/`kind`/`actor`, a `summary`, `data`/`ref`, and `h` — sha256 over the previous line's `h` and this line's canonical bytes. Sources written now: labels (`label/start|end|point`), the file monitor (`files/create|modify|delete|rename|attrs|other`, written from the monitor's reader thread before any buffer can drop them; `files.modify` coalesced per path and process within `timeline.files_modify_coalesce_ms`; attrs inside the analysed app's data directories as lines, elsewhere and OPEN/CLOSE as `files/count` lines), pulls and checks (`files/pull`/`files/check` pointing to the version's `diff.json` with its sha256), monitor notes (`monitor/start|stop|end|fallback|proc-start|proc-restart|follow|proc-exit|lost|blind|sight`), device-clock samples (`clock/sample|jump|sync`, sampled every `timeline.clock_every_s` by the writer — headless runs too), snapshots (`snapshot/load|save|delete`), devices (`device/connect|lost|switch|boot`), record/play (`run/record-start|record-stop|record-result|play-start|phase|play-end`; `RunConfig.run_id`) and the writer's own `sandroid/open|resume|policy|dropped|world|seal|close`. Writing never blocks the caller (the queue is written every ≤100 ms, fsynced at most once a second and at flush/seal/close); bulk lines over `timeline.queue_max` are dropped and counted in a `sandroid/dropped` line, label/clock/snapshot/device/run lines never. A restart resumes the file (a torn last line is closed and declared, open labels end with `ended_by: "close"`); a second Sandroid on the same folder records no timeline (`.timeline.lock`). `python -m sandroid.core.timeline verify|seal|tail|labels PATH [--json]` checks a file (exit 0 ok, 1 broken, 2 unreadable). New config sections `[timeline]` (sources, kinds_off, count_only, files_attrs, files_modify_coalesce_ms, count_window_s, queue_max, clock_every_s, mask_sensitive) and `[tracking]`, plus `ai.mask_sensitive` and `report.effects_window_s/shot_triggers/formats`; every change of `timeline.*`/`tracking.*` is recorded as a `sandroid/policy` line (`config.add_update_listener`). `acquisition.json`/`checks.jsonl` `mark` blocks now name the active label (innermost open span, else the last point) with its `kind` and `seq`. The quit flushes the timeline first and closes it last; AI tools' lines are attributed to `ai`, the snapshot picker's to `user`.
- **TUI: Timeline lens (`5`)** over the session timeline: live follow, filters (`/` grammar with chips), world/epoch/label/run separators, Inspector with Line/JSON/Ref/hash-chain tabs, `J` jumps to the referenced Files version or Network flow, `V` reveals a masked line (only when `timeline.mask_sensitive` is on; recorded as `sandroid/reveal`). Global label keys in every lens: `#` starts a label (closing open ones), `+` a sub-label (ending a running sub-label first), `-` stops the innermost, `B` drops a point mark (moved from the Files lens; name prompt, `Esc` writes nothing). `Ctrl+T` toggles Tracking. The header shows the open label, Tracking and a locked/failed timeline. Settings → Timeline edits the recording policy, masking and Tracking options. The Files lens builds its segments from the labels.
- **Reports are JSON-first** (`core/report_engine.py`, `core/report_render.py`; replaces `core/pdf_report.py` and `core/timeline_generator.py`): every run writes `report.json` (the only renderer input), `report.md` and, with `--report` / `report.generate_pdf`, the PDF. Each report seals the session timeline (`timeline_seal.json`: seq range, last hash, sha256 of the sealed byte prefix) and has overview, coverage/validity (tracking, interventions, recording policy, dropped lines, integrity, clock quality, masking), interaction transcript (per label: inputs with element, typed text, screen, confirmation, screenshots and the file/network effects within `report.effects_window_s`), analysis results and seal sections. `--report-from` writes `report_regenerated_<UTC>.*` and re-renders from `report.json` when the timeline is gone. Removed: `--screenshot` (interval screenshots) and the `timeline.png` page.
- **On-device UI helper** (`tools/uihelper` Java source, packaged `assets/uihelper/uihelper.jar` with its sha256, host `sandroid.core.uihelper`): holds the device's single UiAutomation connection. FULL mode (accessibility events, element at a point, UI dumps, windows, screenshots; the app can detect it) and INVISIBLE mode (screenshots only, `accessibility_enabled` untouched). Pushed and sha256-verified like other device tools, restarted with backoff when it dies, `accessibility_enabled` restored on stop. A CI job checks that the jar is built from the checked-in source.
- **Dependencies:** Textual is pinned to `>=6.2,<9` (the suite runs on 6.2.1 and 8.2.8).
- **Device clock recorded, synced after snapshot loads; session-start baselines.** Sandroid samples the device wall clock and CLOCK_MONOTONIC against the host over one persistent `adb shell` (min round trip of several queries) and writes `clock.jsonl` in the session folder (`reason`, `off_wall`, `off_mono`, `rtt_ms`, `err_ms`, `host_at`, `jump`, `snapshot`): on device connect, monitor start, every 60 s, after every snapshot load and on any jump over 2 s. After a snapshot load the device wall clock is set to host time when `emulator.sync_clock_after_snapshot` is on (default; Settings → General), recorded as a `sync` line; a failed sync and a remaining offset are warned about once. Every `acquisition.json` and `checks.jsonl` line carries a `device_clock` block; the Files Inspector and the header (`device 17:16:02 −75 min ⚠`, amber) show the offset when it exceeds 1 s. `device_clock.to_host_time()` maps device monotonic times to host time. When the file monitor starts, the monitored app's watched files are pulled once per session (`trigger: session-start`, at most 50), so persisted watches have a baseline; unchanged files only get a `checks.jsonl` line.
- **TUI: Lenses + Inspector shell.** The tool tabs and the half-screen "Background Activity" log are replaced by full-width **lenses** — `1` App (was Spotlight), `2` Network, `3` Files, `4` Runs (was Files → Diffs) — with `Shift+←/→` still cycling them. `Enter` on a row opens an on-demand **Inspector** on the right where a lens offers details; `Esc` closes it (before anything else, never quits). The header shows a device ▸ app breadcrumb, the last loaded snapshot and a `● LIVE` / `● REC` / `◆ REVIEW Run …` scope pill; the status band is condensed to one or two rows; the footer shows at most seven keys.
- **Activity log → log drawer**: a one-row ticker shows the newest log line; `` ` `` (backtick) toggles a bottom drawer with the full log. **AI Chat** (`Ctrl+Y`) opens in the right-hand slot shared with the Inspector.
- **Snapshots are a picker, not a tab**: `S` (or `0`) opens it — list, create, load / delete with confirm, assign to slot, `1`–`8` load a slot (confirmed), `s` then a digit saves into a slot. `Ctrl+1`–`Ctrl+8` still save directly.
- **Network lens**: one full-width flow table (time · recipient · request · status · size) read from the embedded mitmweb's structured flow log, polled off the UI thread; `Enter` opens Summary / Request / Response (headers, decoded bodies: pretty JSON, form fields, hex preview for binary) in the Inspector. TLS failures and errored flows are ✗ rows, unseen TLS failures badge the lens (`⚑N`). `/` filters, `T` toggles spotlight-(target-)app-only, `N` shows OS noise (hidden by default); counts are in the frame caption. REVIEW scope shows the reviewed run's flows (by its start/end time). The Mitmproxy/friTap sub-tabs are gone: proxy state is in the caption, `I` opens a Capture status page (`h` lands on its friTap tab), all proxy keys (`Ctrl+D/N/P/R/A/O/V`, `y`) still work, `M` starts/stops mitmweb once flows exist, and mitmproxy messages go to the log drawer.
- **Runs lens**: the run history is one full-width table (`#` · run · when · took · changes, newest first) instead of a diff pane over a bottom rail. `Enter` opens the run in the Inspector (Summary with status, evidence check, errors and settings; Changes; Report), `v` puts the UI in **REVIEW** scope for that run (`◆ REVIEW <run>`; Files / Network follow it) and `L` returns to LIVE (also automatic when recording or replaying starts), `=` compares two runs, `z` shows the full diff; rename (`n`), delete (`Del`) and the PDF report (`⇧P`) work as before. The `[` rail toggle is gone.
- **Keys**: digits `1`–`4` now switch lenses (the press-twice slot loading on `1`–`8` is gone); Spotlight's bypass toggles moved from `1`–`5` to `b` then `1`–`5` in the App lens (`b` `o` opens Objection there; elsewhere `b` is still Objection). Keybinding overrides for the removed ids `load_slot_1`…`load_slot_8` and `pick_save_slot` are ignored; `show_snapshots` now names the `S` picker key.
- **Files lens: one table + watch marks.** The Monitor and Watchlist sub-tabs are merged into one full-width table of live file activity, collapsed per file (★ · path · ops C/M/R/D/A · count · last time; SQLite `-wal`/`-journal` writes fold onto their database). Watched files carry ★ and are pinned on top, also before any activity and for wildcard patterns (now persisted). Caches, temp/lock files, OS paths and OPEN/CLOSE are hidden by default (`N` shows all, the same "show noise" key as in the Network lens; the frame shows how many). Keys: `w` watch/unwatch, `u` pull the row (watching it first), `U` pull all watched, `/` filter, `n` watch any path or pattern, `a` auto-pull, `.` full paths, `z` zoom the diff, `Ctrl+L` clear; `o` still starts/stops the monitor. `Enter` opens the Inspector (Summary: full path, ops, processes, last pull time/size/sha256; Diff: the last pull against the one before; Events). In REVIEW scope the table lists the run's changed/new/deleted files and `Enter` shows that file's diff.
- **Files lens Inspector: Versions + Content tabs** (replace Diff and History). *Versions* lists every kept pull newest first (`v3 · 10:42:07 · 1.2 MB · auto · moz_places +3 ~1 · moz_meta ~3`); the selected one's acquisition record (pulled at, manual/auto, device mtime/size, on-device sha256 = local ✓ or ✗) and its diff against the version before it are drawn below — `{`/`}` pick an older/newer version (or click one), `*` makes the selected version the base to diff others against (again clears it). These Inspector keys are bound nowhere else, so they never clash with the Files lens's `B` mark / `<` `>` segment keys; `{` `}` pair with `[` `]` for the tabs. Diffs are structured and coloured instead of wrapped text: SQLite per table with +inserted/~updated/−deleted counts, rows with their column names (cards when the columns do not fit), updates showing only the changed cells old → new, epoch ms/µs values with a dim local time; SharedPreferences/ABX and JSON as a key table (changed/added/removed); text as numbered hunks; binary as size/sha256 and a hex window around the first difference. *Content* is a first look inside the selected version's local copy: SQLite tables with row counts and the first 200 rows of one (`{`/`}` or a click picks the table), preference keys with types, a JSON tree, the first lines of text, image facts, or a hex dump with a type guess. Everything reads local copies only (SQLite through a temporary copy with its `-wal` folded in, opened read-only). `z` shows the selected diff or table full-screen (wide tables scroll sideways). REVIEW scope draws a run's diffs the same way (with column names when the run kept its pulled copies). The stored and printed text diffs (`diff.txt`, run results, CLI) are unchanged by this (see "Files lens evidence trail" and "Run results no longer contain display markup" below); `file_diff.diff_files_structured` returns the structured form next to them.

- **Files lens: marks, editable path rules, monitor-driven auto-pull, evidence in the session folder.**
  - **Marks**: `B` drops a timestamped mark (time of the key press) and asks for an optional name (`⏎` on an empty name = unnamed, `Esc` = no mark). The table then shows only what happened since the mark — counts and ops per segment, rows without activity in it hidden, ★ rows pinned but dimmed when untouched; the caption names the segment (`since mark 3 'tap login' · 10:42:07`). `A` toggles everything / since the last mark, `<` / `>` step through the segments. Marks are one list on the main screen (`MainScreen.marks` / `add_mark`, `MarksChanged` to every lens), written to the log/ticker as a separator line and shown as separators in the Inspector's Events tab; only the Files lens uses them so far.
  - **Noise**: only OS paths (`/proc/ /sys/ /dev/ /system/ /apex/ /vendor/ /product/ /data/dalvik-cache/ /data/misc/ /data/system/ /data/app/`) and open-only rows are hidden by default — the app's own data (`app_webview/`, `no_backup/`, `databases/`, dot-files, `files/`, temp/lock files) and `/data/local/tmp` are shown. `cache/` and `code_cache/` collapse into one row per folder (`▸ cache/ · 340 files`, `⏎`/`→` opens, `←` folds). `N` still shows everything raw. `R` opens a live editor of the hide / group rules (prefix, segment, suffix, glob; add / remove / toggle, reset to defaults) that applies at once and is saved as `tui.files_noise_rules`. The caption counts hidden rows by rule kind (`14 hidden: prefix 12 · open-only 2`).
  - **Auto-pull on change** (`tui.auto_pull_on_change`, default on; Settings → Monitor): when the file monitor reports a write / create / rename-into for a ★ file it is pulled once the writes have been quiet for ~1.5 s, then versioned and diffed; a database with its `-wal`/`-journal` is one group, and a write to a file a ★ pattern covers adds it. The periodic stat-poll auto mode (`a`, its backoff and the pattern re-expansion timer) is removed — `a` is the app-wide Analyze key again on this lens. With files watched and the monitor off the caption says "monitor off — watched files not tracked · o starts it". `u`/`U` pull by hand.
  - **Storage**: pulled versions go to the session results folder, readable and never pruned: `files/<package>/<app path>/v001_10-42-07/` holds the copy (+ db companions), `diff.txt` (against the version before) and `acquisition.json` (device path, device mtime + size, sha256 computed on the device before the pull, local sha256 after it, pull time, trigger manual/auto with the triggering event time); files outside an app directory go under `files/_device/<path>/`. Only the ★ membership (paths + patterns) persists across sessions, one file per package in `~/.config/sandroid/watchlists/<package>.json`. `tui.watchlist_max_versions` is removed. The old per-device store (`watchlists/<device>/`) is ignored, not migrated or deleted.
- **Files lens evidence trail.**
  - **`diff.json` is the canonical diff** of every kept version: the structured diff (SQLite per table with column names, primary key, insert/update/delete rows with old/new values; XML/ABX/JSON keys; text hunks; binary summary) with a schema version, the diff-engine version, the base version, the compared files with their sha256 (incl. `-wal`/`-journal`) and `created_at`. `diff.txt` next to it is rendered from it as plain text for people (no Rich markup, column names, raw values with a readable local time for epoch-like values). The Inspector reads `diff.json` directly; folders without one (kept earlier) still fall back to parsing `diff.txt`.
  - **Unchanged pulls keep no copy**: before pulling, the on-device sha256 of the file *and* its `-wal`/`-journal` is compared with the newest version's; if it is the same, nothing is pulled and one line goes to `checks.jsonl` in the file's folder (`at`, `trigger`, `event_at`, per-member `device_sha256`, `same_as`, `note`, `mark`). Without on-device hashes (no root) the pulled copy is compared instead and dropped when identical. Version numbers count only real changes; the Versions tab shows the checks collapsed between versions (`· 12:41:02 auto checked, no change (2×)`).
  - **The hash line covers the companions**: `acquisition.json` (schema 2) records device/local sha256 per member and a `set` block (members, one combined hash per side, mismatching members, newest device mtime and which member it is, total size); `sha256_match` is the verdict for the whole set. The Inspector shows `sha256 (db+wal) …`, `device sha256 = local ✓ (both)` or `≠ local ✗ (wal)`, `changed 12:33:10 (wal)` and the size per member; Summary shows the set hash.
  - **Baseline on watch**: `w` and `n` (also each file a new pattern matches) pull a first version (v001) immediately (`trigger: "watch"`), so the first change is diffable. A file a pattern adopts on its first write is pulled once that write settles.
  - **Marks and the event timeline are written to the session folder** as JSON Lines, append-only, times with milliseconds: `marks.jsonl` in the session results folder (number, name, `at`, `recorded_at`) and `files/timeline.jsonl` (every monitor event: `seq`, time, op, path, new path, package, process, pid when the backend reports one, source fsmon/kprobe, the mark segment it fell in). Both grow additively; readers ignore unknown fields. Each version's `acquisition.json` names the mark that was active when it was pulled.
  - **Timezones**: every timestamp written there (`acquisition.json`, `checks.jsonl`, `diff.json`, `marks.jsonl`, `timeline.jsonl`) is ISO 8601 with the UTC offset.
- **Run results no longer contain display markup** (run format change): the changed-files diffs stored in sealed run results (`run.json`, the results JSON) are plain text — `[INSERT] Table [t] row [...]` instead of `\[[success]INSERT[/success]] …`. Colour is added only where a diff is shown (console, TUI). Runs recorded before keep working: their markup is rendered in the TUI and stripped for the results JSON, the PDF, the zoom export and the AI tools. The AI tool `get_file_diff` keeps its version with `diff.json` too and returns the plain diff text.

- **File monitor follows the app** (`tui.monitor_follow_app`, default on; a checkbox in the `o` dialog, a switch in Settings → Monitor). App mode (was "PID") records every process of the app — its UID, or named `<pkg>` / `<pkg>:<sub>` (Firefox: main, tabs, gpu, crash helper) — not just one PID's tree, and picks up new and restarted processes: a `task:task_rename` tracepoint in a separate small tracefs instance notices a start, a `ps` poll is the fallback (and the only way where the tracepoint is missing), and every candidate's UID/name is checked before its TIDs are added to `set_event_pid`. A paused spawn (App lens Start) is handed to the running monitor before it resumes, so App mode can be started before the app runs. A restart is a separator in the Files Events and the log (`org.x restarted 12:47:03 · new PID 25983 · gap ≈0.3 s`), and Summary "by" names the process that wrote (main / tab_17 / gpu_process). Without follow (or on fsmon) the Files caption says "monitor blind since HH:MM:SS · target gone" instead of LIVE once the app's process is gone, with how to re-target. While running the caption names the scope and how to stop it ("App org.x · 5 proc · following · o stops", "Path /sdcard · every process").

### Fixed
- **Safety round 4.**
  - **App lens Kill / Restart**: `⇧K` asks first (No focused, a typed-ahead `y` is ignored, any other letter cancels, as the Play confirm). `⇧R` still restarts without a dialog, but not inside the stray-typing window (right after a dialog cancelled as typing): it is ignored with a "Restart not run" notice.
  - **Quit dialog** opens with Cancel focused (and highlighted); `Enter` still quits, as before.
  - **SELinux is handed back on quit**: Sandroid remembers, per device, the mode it found before it first switched to Permissive; a clean quit (`q` `y`, Ctrl+C, SIGTERM) restores that mode where Sandroid changed it (also when a snapshot load had changed it in between) and logs it ("restore on quit"). A device that is gone is skipped.
  - **No empty result folders**: a session no longer creates empty `dexray_insight/`, `fritap/`, `forensic_apks/`, `spotlight_files/` and `raw/{first_pull,second_pull,noise_pull,new_pull,network_trace_pull,screenshots,spotlight_files}`; each is created when something is written into it.
- **Monitor trace buffer**: the kprobe instance reserved 64 MB per CPU (256 MB on a 4-CPU 2 GB AVD; the device got sluggish and the LMK killed the app). It is 4 MB per CPU now (trace_pipe is streamed continuously; ~230 B per event), and lost events are no longer silent: the per-CPU `overrun` counters are read every 5 s and at stop, "N events lost" shows in the Files caption and the log.
- **Startup with a missing device**: `sandroid -s <serial>` for a serial adb does not know said "ADB not found in PATH" (any "not found" in adb's stderr was taken for a missing adb binary). The adb check now runs `adb version` without `-s` and only reports a missing adb for real shell/OS errors; the device check reports `Device '<serial>' not found` and lists the available devices. On that error screen `d` opens the device selector (picking a device pins it for the session and retries).
- **Startup error screen owns its keys**: `r` retried *and* fired the global Record ("Cannot record – No device connected…"); no app-level key works while the startup screen is up now. `r`/`R` retry, `q`/`Q` quit, and the hint names the keys as they work.
- **Quitting a failed start** exits with status 2 (130 when aborted with `Ctrl+C` during startup), repeats the error on the terminal, and removes that run's session folder when it holds nothing but its own log files.
- **Network lens**: the stopped-state hint names the configured `mitmproxy.proxy_port`; the proxy prompt's default address uses it too (was a fixed `:8080`).
- **Consistent filter keys across lenses**: `N` shows hidden noise in both the Network and the Files lens (Files used `v`), the Network lens's spotlight-app-only filter moved from `v` to `T`; `v` is now only "review run" in the Runs lens.
- **Snapshot picker acted on the wrong snapshot**: the list refresh (every ~9 s) moved the highlight back to the first row, so `Enter`/`l` loaded and `d` deleted the newest snapshot instead of the picked one. The highlight now stays on its snapshot (by name; on the same row if that snapshot is gone), an unchanged list is not redrawn, the refresh pauses while a confirm is open, and the confirms name the snapshot with its date and size. Deleting a snapshot clears the slots that pointed at it, and a slot whose snapshot is gone says so before asking to load it.
- **SELinux after a snapshot load**: a snapshot restores the SELinux mode it was saved with, so loading one taken before `setenforce 0` left the device Enforcing and `settings`, `dumpsys` and `screencap` failed until a restart. Every snapshot load (picker, slots, replays) sets it back to Permissive; picker loads also restart frida-server when `frida.server_auto_start` is on.
- **Inspector tabs**: `[` / `]` switch the Inspector's tabs while focus stays in the lens (`←`/`→` too, except in a text input); the Inspector's footer says so. Switching lenses closes the Inspector, whose content and key hints (e.g. `w watch`) belonged to the previous lens.
- **Bypass digits**: the Objection launch dialog used `3` for emulator detection while `b` `3` toggles the Frida bypass. Both now read one table (`1` SSL, `2` Root, `3` Frida, `4` Debug, `5` Integrity); Objection's emulator-detection option moved to `e`, and its rows use ●/○.
- **`?` help**: fits 80x24 (no detail pane and margins on small terminals, columns sized to the window), lists `Ctrl+Y`, `Ctrl+B`, `,`, `Ctrl+C`, `0` and the other app-wide keys under "General", merges keys that do the same thing (`o / b`, `Del / Backspace`, `1-8`), drops the dead Shift+↑/↓ "level" keys, shows `` ` `` and `=` instead of their key names and lists the lenses in key order.
- **AI chat**: the privacy/endpoint notice was wrapped at a fixed 78 columns and cut off at the panel edge; it now wraps to the panel and re-wraps on resize. The mascot hides when the text reaches its corner (it covered the notice at 80x24). `Ctrl+L` is labelled "Clear chat".
- **`LookupError: active_app` traceback** in the log on the first bypass toggle: background threads marshalled UI updates onto the event loop without Textual's app context, so a timer started there crashed. Those callbacks now run in the UI context.
- **Quit could hang and leave mitmweb running**: after a friTap stop whose agent could not unload, `q` → `y` closed the dialog but Sandroid never exited, no key worked any more, and mitmweb plus the device proxy stayed; SIGTERM then orphaned the mitmweb child. The dialog's exit skipped the cleanup. Now every quit path (dialog, `Ctrl+C`, `Ctrl+Q`, SIGTERM/SIGHUP) runs the same cleanup — device proxy cleared and mitmweb stopped first, then friTap/Frida/captures — with every step time-boxed; the app exits after at most ~12 s even if a step hangs, and a watchdog ends the process (after the same mitmweb/proxy teardown) if the UI loop itself is stuck. mitmweb runs in its own process group and exits by itself if Sandroid dies without stopping it. Frida job threads no longer keep the process alive. The quit dialog says what quitting stops.
- **`Ctrl+Q` quit without asking** (Textual's built-in binding, no cleanup): it now asks like `q` / `Ctrl+C` and is listed in `?`.
- **Network lens: compressed bodies** (gzip, br, deflate, zstd) are stored and shown decoded — JSON/HTML were a hex dump; the Inspector says which encoding was decoded and the size on the wire, and a body that cannot be decoded is shown as received with a note. The binary hex preview shows 128 bytes at 8 per line (fits the Inspector).
- **Recurring errors no longer flood the log**: background-thread → UI hand-off is one shared helper (`sandroid.tui.utils.ui_thread`) used by every panel, and the Network lens's status refresh never starts a timer outside the app context (the `LookupError: active_app` fired once per mitmweb line during live traffic, 562× in 28 min on the old build). The log folds a recurring warning/error (same text up to numbers/addresses) to one line per minute with "+N more like this", and the ticker shows the first line of a traceback and `adb: <error>` instead of raw adb command lines (the drawer keeps the full line).
- **friTap state follows its real lifecycle**: the caption and the friTap status page show starting / running / stopping / stopped / failed (it said "stopped" for ~50 s while friTap attached and "running" for ~20 s after a stop). While friTap runs, Sandroid watches the target for an "isn't responding" dialog and says so (log + caption: "app not responding — h stops friTap"); a hung agent unload is marked as failed with the recovery hint. Cancelling the friTap config is logged as a cancel, not "Command 'h' failed".
- **"SSL unpin ✓" after the app died**: bypass hooks (SSL unpin and the other `b` categories) are checked against their process every 3 s; when the hooked app is gone (Zygote restart, crash, restart under a new PID) the indicators clear and the log says how to re-apply them.
- **OS-noise filter (`N`)** hides Google's private `*-pa.googleapis.com` APIs (except Firebase Analytics), Play-services paths on `www.googleapis.com`, Play Store images, Safe Browsing and Sandroid's own `mitm.it` reachability probe; the caption says how many flows it hides (`N: 163 OS noise hidden`).
- **`Ctrl+O` opened mitmweb without its access token (403)**: Sandroid now gives mitmweb a token (only its argon2 hash is on the command line) and opens the UI logged in, with a toast naming the URL; a mitmweb from another install that prints its own token is picked up from its output.
- **After `Ctrl+N` (Zygote restart)** the dialog no longer promises a quick recovery: it says System UI restarts and a busy emulator can show "isn't responding" for a minute. Sandroid waits up to 2 min for the device to settle (quietly — no raw adb lines), re-checks the proxy for ~30 s before any "CANNOT reach" verdict, and then closes leftover system dialogs.
- **Network lens details**: `/` also matches the status column (`/404`, `/tls`, `/✗`); `Esc` clears the filter (in the input, or an applied one); `Home`/`End` jump to the first/last flow (End scrolled sideways); sizes like `190.9 KB` keep their unit; protocols read `HTTPS/2` (not `2.0`); TLS failures are written to `flows.jsonl` (`kind: "tls"`), so a reviewed run or a later session shows them, without doubling the live row.
- **Status strip** reads `mitm ● 10.0.2.2:8090 · device ○` while the device proxy is off (it read like the device was proxied). The `Ctrl+A` addons dialog says how to add one when none is found. A focused log drawer no longer offers "⏎ Inspect", and the drawer wraps its lines instead of showing a stray horizontal scrollbar at 80–100 columns.
- **Files lens missed the app's writes**: the kprobe filters match the path string a process passes, and apps write via `/data/user/0/<pkg>` (`getFilesDir()`), not the `/data/data/<pkg>` the monitor dialog prefills. Every target is now watched under all its names (`/data/data/<pkg>` also covers `/data/user/0/<pkg>` and `/data/user_de/0/<pkg>`; `/sdcard` = `/storage/emulated/0`), and both forms are **one row** keyed `/data/data/...`, so a ★ applies to the app's real writes (was two identical-looking rows). `@de/` / `@ext/` mark the device-encrypted and external app directories in short paths.
- **Writes through files opened before the monitor started** (an app's SQLite db and `-wal` when attaching) were silently invisible: the kprobe write probes only carry the `struct file*`, and its path was learned at open time. The write probes now also read the file's dentry chain (up to eight names) and filesystem, and the monitor maps that onto the watched directories (mount table + real paths read once at start), so such writes appear live with their real time — attaching is as good as spawning. The write probes are also filtered in-kernel by the targets' filesystem and directory name (socket/pipe/eventfd writes no longer reach Sandroid). No scan, re-`stat` or stop rescan; `tui.monitor_stat_interval` is gone (ignored in existing configs).
- **Recursive deletes**: deleting a directory marks its known files deleted (`rm -r` unlinks them by relative name, which the path filter can't match).
- **Ops**: `C` only for a file/directory the kernel really created (the open's `FMODE_CREATED`, `do_mkdirat`'s result): SQLite reopening its database and `>>` appends are `OPEN W` (noise), `O_TRUNC` on an existing file is `M`, `mkdir -p` on an existing directory is ignored. Sandroid's own pulls (adb `sync svc`) are no longer activity, and OPEN noise no longer re-dates rows (`U` re-sorted 100+ rows). Attribute events are named from their dentry chain like writes, or dropped when outside the targets (no more `wikipedia.db A` orphan rows); `databases/` and `databases` are one row; the old name of a renamed file shows `old → new` (struck through, also for deleted rows); the actor is never `<...>` (ftrace's comm cache is enlarged for the session; unknown comms use the tid's earlier name or, in PID mode, the app).
- **Auto-pull missed WAL-only changes**: `a` stats a database together with its `-wal`/`-journal`; a WAL write triggers the pull.
- **Pulls are versioned**: each pull is kept as a timestamped version with its diff (newest `tui.watchlist_max_versions`, default 10) instead of overwriting the previous copy; the Inspector's new **History** tab lists them with their diffs.
- **Files lens names the package**: short paths drop `/data/data/<pkg>/`, so in REVIEW a run's `databases/bugle_db` (Messages) read like the reviewed app's file. REVIEW rows now show `<package>: <path>`; live rows do too when the file belongs to another app than the monitored one (`.` still shows full paths).
- **Watches survive a restart**: the watchlist and its pull history live per device in `~/.config/sandroid/watchlists/<device>/` (was the per-session results folder).
- **`n` add-path**: the prefilled app directory is no longer selected (typing replaced it); relative paths and paths with shell metacharacters are refused with a message.
- **Inspector keys**: with focus in the Inspector (to scroll it), its advertised keys (`w` watch, `u` pull, `z` zoom ...) now act on the lens's row instead of doing nothing.
- **Monitor stop log**: a stop Sandroid asked for (SIGTERM) is no longer logged as "monitor process exited unexpectedly (code -15)".
- **Files lens details**: XML diffs name the changed key again (`string[@name="…"]` was parsed as a Rich tag and vanished); text diffs show each change at its place (`@@ line N @@`, old/new interleaved) instead of all deletions then all additions; the diff zoom wraps long lines; a missing `-journal`/`-wal` on a database pull is no longer a warning; `Home`/`End` move the cursor; Shift+`O` sorts by recency / name (natural: `f_2` before `f_10`) / count; a wildcard watch no longer stars deleted paths and directories (`u` on them explains why there is nothing to pull); the caption counts patterns apart and "hidden" only counts rows really hidden; the "last" column stays visible beside the Inspector at 100 columns; a running monitor no longer counts as a hook (`Hooks 1`); the monitor dialog opens on the PID/Path choice (Enter no longer starts PID mode from the path field), remembers the mode, focuses a newly added path row, says "(+1 path)" for two paths, and explains that the path is a prefix filter.
- **REVIEW Network showed dry-run noise as the run's traffic**: a reviewed run's flow window ran from the Play press to the end of its analysis, so the noise-measuring dry run (and snapshot loads, baseline scan, result collection) was listed as if the replays had caused it. Runs now record their phase windows (each replay incl. its settle time, and the dry run; `run.json` → `phases`), every flow is tagged with its phase, and REVIEW shows the replays' flows; dry-run and setup flows are hidden and counted (`A: 29 dry run · 3 setup hidden`), `A` shows them marked `dry` / `setup`, and the Inspector names a flow's phase.
- **REVIEW Network of a run from an earlier session said "No flows were captured"**: run bundles did not store flows and the lookup read the *current* session's flow log. At the end of every Play the run's flows (TLS-failure records included) and their detail files are copied into the bundle (`network/flows.jsonl`, `network/details/`, `network/meta.json`; at most 5000 flows / 64 MB of details, bodies already capped by `mitmproxy.max_captured_body_bytes`) before `SHA256SUMS` is written, so they are covered by it; REVIEW reads the bundle first. Older runs fall back to the session's flow log, and the empty state says that this only works in the session that ran them.
- **A run without mitmproxy said "No flows were captured"** although it had a pcap: the empty state now says whether mitmproxy ran during the run and names the run's packet capture with its size; the Runs Inspector's *Report* tab lists the pcaps and the stored flows.
- **Scope pill**: `● REC` never showed while recording (the update looked for the main screen as the *active* screen, but the Record dialog was on top), and `● REPLAY` stayed after the run ended. The pill now follows every recorder/player transition (start, stop, cancel, error), shows the Play's phase (`● REPLAY · replay 1/2`, `settle 8s`, `dry run`, `analysing`, `saving`), the status strip shows it too (`● REPLAYING · dry run`), the Runs lens caption/empty state show it during the first Play, and `v` during a Play reads `◆ REVIEW … · ● REPLAY`.
- **Play reverted the device without asking**: `p` asks first, naming the recording, the number of replays (+ dry run) and an estimated duration as a range that counts the snapshot loads, network resets, the baseline scan and the result pulls ("roughly 13-17 min" for an 80 s recording with 2 replays; it promised ~6 min for a 16 min Play); the Play that auto-starts after a recording does not ask. Phase lines (`Play · loading snapshot`, `Play · replay 2/2`, …) go to the log ticker.
- **Snapshot loads dropped mitmproxy's device proxy**: the snapshot restores the device's `http_proxy` (`:0` for Play's `tmp`), so mitmproxy saw none of the replays and nothing said so. After every snapshot load (Play, picker, slots) the device proxy Sandroid set is re-applied while mitmproxy runs (a warning says so); if that fails, an error says mitmproxy will not see the traffic. Without a device proxy of Sandroid's this costs no adb call.
- **Runs of the same recording that disagree are flagged**: when two runs replayed the same `recording.txt` (by SHA-256) and their file counts differ by ≥10 and ≥2× (hosts: ≥5 and ≥2×), the Runs table shows `≠ #n`, the Inspector's Summary says which run it diverges from and how, and `=` compare adds a *Replay consistency* verdict. (Replay determinism itself is unchanged.)
- **Rename showed a collapsed input** and typing appended to the invisible old label ("Run 2 · 18:34B replay of A"): text inputs in dialogs are full-height again (the compact sweep had left a border without a text row), and the rename dialog selects the old label so typing replaces it. Other text dialogs keep the cursor at the end.
- **A `p` run copied the previous run's label** (two runs named "Run 2 · 18:34"; a cancelled Record dialog had replaced the seed): a manual Play gets a fresh `Run <n> · <time>`, the Play after a recording keeps the Record dialog's name, and cancelling a Record dialog keeps the previous recording's settings. The REVIEW pill, the rename/delete dialogs and the Inspector identify runs by `#` (and run id) as well as label.
- **`=` compare listed the same host as added and removed** when its "(also seen in background: N queries)" note differed; hosts are compared by name (note and trailing dot removed, case-folded).
- **Evidence check was cached for the session**: a file changed after the first check still showed "✓ verified" (and a restored one stayed ✕). `Enter` on a run and `v` re-verify the bundle against `SHA256SUMS`; cursor moves re-verify when any file's size or mtime changed. A failed check names the changed files.
- **Runs lens details**: "Took" is the Play's own run time (press → analysis done; it showed the recording length), the Inspector shows the recording length separately; `Home` / `End` move to the newest / oldest run; the delete dialog says it removes the whole bundle; the exit summary no longer lists runs deleted in the session; the header pill no longer parses a run label as markup.
- **`q` / `Ctrl+C` / `Ctrl+Q` always ask first**: with friTap, the file monitor or a resident bypass script running, quitting stopped them instead of asking — on the UI thread (the UI froze ~6 s), and the `y` meant for the quit dialog then opened Proxy Settings while Sandroid kept mitmweb and the device proxy running. The dialog now lists what quitting stops (mitmweb, the device proxy, friTap, the file monitor, a recording, …); after the confirm it stays up as "Quitting Sandroid…", ignores keys, and the cleanup runs off the UI thread. A second quit key while the dialog is open no longer stacks a second dialog. The exit no longer warns about "untracked background tasks" for Sandroid's own daemon threads.
- **Session summary overwritten after quitting**: the terminal reset left the alternate screen a second time after the summary was printed, which moved the cursor back above it.
- **Live Network lens emptied during a Play**: the Play points `RAW_RESULTS_PATH` at its run bundle while it runs, and the live flow log followed it, so the table dropped every HTTP row (only ✗ TLS rows stayed) though mitmproxy kept capturing. The live lens (and a mitmweb started meanwhile) stays on the session's flow log.
- **Status strip after a picker snapshot load**: "Frida ○ off" stayed for minutes while frida-server ran — status refreshes found no status bar while a dialog (the picker) was open. The strip also keeps the device proxy while it cannot be read (it showed "device ○" during the `Ctrl+N` settle) and that read failure is no longer logged as "Invalid proxy format".
- **Inspector tabs**: `←`/`→` switch the tabs at every window size (they scrolled the Runs table at 80x24 instead); only a text input keeps them.
- **friTap caption** keeps "✗ failed" after an agent that could not unload (it dropped friTap, reading like a clean stop).
- **Runs**: the Record dialog numbers its default label after the device's runs (it restarted at "Run 1" every session); a manual Play's label uses its start time; `p`'s confirm names the recording by its current label (after a rename); the rename confirm names the run's # and id; the Inspector's "Recording" is the recording's own length (it showed the replay window); the phase before replay 2 reads "pulling original files" (was "collecting results"); setup / dry-run ✗ TLS rows are tagged in REVIEW `A` mode.
- **Bypass log**: the combined bypass script's per-category "Hooked:" / "hooks loaded" lines are logged at DEBUG — every category's hooks are installed up front and gated by its flag, so a Frida-only `b 3` read like root/debug/SSL hooks were active.
- **Files lens**: `Enter` on the monitor dialog's PID/Path choice starts monitoring with the chosen mode (it did nothing); a missing `-journal`/`-wal` companion is no longer a warning on every database pull.
- **Stray keys ran global commands** (E2E, Files lens on Firefox): after `B` + a name with nothing new since the mark, the lens hid its (still focus-bound) table and Textual left focus on nothing; the next dialog close (`?`) then focused the *hidden* App lens. `/` opened no filter, the typed "places" fired `p` `l` `a` `c` `e` `s`, and `A` ran the hidden App lens's Attach. The main screen now gives focus back to the active lens whenever it lands on nothing or inside a hidden view, a key the active lens binds reaches it even when focus is elsewhere unbound, and `/` in a lens without a filter swallows the word typed after it instead of running single-letter commands. Safety net: `p` Play (reverts the device) and stopping a replay confirm with No focused, ignore `y` for 0.4 s, and close as No on any other letter ("that looked like typing", the rest of the word is ignored too); the quit dialog cancels the same way.
- **Files lens: idle watches fold**: in a mark segment the ★ rows without activity in it fold into one row (`▸ ★ 21 watched · idle since mark 3`, `⏎`/`→` opens, `←` folds) below the ★ rows that changed — 20 watched `shared_prefs/*.xml` no longer push the segment's activity off the screen (at 100x30 it was all idle ★ rows). The everything view (`A`) folds them only when 4 or more were never touched this session (`★ 20 watched · idle`).
- **Log drawer** wrapped every line at 20 columns (lines written while the drawer was closed were rendered at width 0) and painted paths red: lines now wrap to the drawer and re-wrap when it opens or the terminal is resized; paths are no longer coloured (only ERROR lines are red), and a normal "Stopped" line is muted and shown once.
- **`?` help opens on the current lens**: its keys come first (highlighted), then the Inspector's, the global keys and the other lenses. A lens key that shadows a global one (Files `w`/`n`/`O`, App `b`, Runs `n`) says "overrides global w = Start/stop network capture" and the global row says where it does not apply ("not in Files, Runs · …").
- **Files lens LOWs**: the Content tab opens on the largest data table, never on `android_metadata` / `room_master_table` (Firefox's downloads DB opened on its locale row); narrow paths keep part of the distinguishing directory (`files/…/688012…,heise.de)/ls/data.sqlite`, was `files/…/ls/data.sqlite` for every site); the rule editor (`R`) shows which button has focus.

## [2.1.0] - 2026-11-17

Sandroid 2.1 redesigns the TUI around always-on tool tabs, adds an mitmproxy-based
network interception stack with per-app proxies and CA injection, a tiered Frida
bypass suite, a kprobe filesystem monitor, a rewritten analysis engine with
persistent run history, and an experimental AI Chat assistant.

### ⚠️ Breaking Changes
- **Python 3.12 or newer is required** (3.12 and 3.13 are tested in CI); Python 3.10/3.11 support was dropped.
- **Legacy Rich interactive mode removed**: `sandroid -i` / `--interactive` no longer exist — use the Textual TUI (`sandroid`) or `--headless`.
- **`--ai` removed**: the Gemini-based video summarisation feature and its API-key setting are gone, superseded by the new (experimental) AI Chat.
- **TUI views removed**: the Forensic / Malware / Security views (`TAB`) were replaced by a single flat action catalog; `--view` and `analysis.default_view` no longer have any effect in the TUI (`--mode` for `--headless` is unchanged).
- **TUI layout changed**: the `Ctrl+B` bottom panel was replaced by always-on tool tabs (Spotlight / Network / Snapshots / Files) with `Shift+Arrow` navigation; Record/Play results live in **Files → Diffs** (`r`/`p` work from every panel). Global `1`–`8` must be pressed twice to load a snapshot slot; Snapshots refresh is `Ctrl+R`, Watchlist pull is `u`/`U`.
- The internal `ActionQ`/`DataGather` analysis pipeline was replaced by `AnalysisEngine`; third-party code importing those internals must be updated.
- The on-device proxy redirector changed from `ipt2socks` to `gost`.

### Added

#### TUI
- **Glance band**: permanent, boxed status strip (device, frida-server, mitmproxy engine, device/app proxies, spotlight) derived from live device state.
- **Always-on tool tabs**: **Spotlight**, **Network** (Mitmproxy + friTap sub-tabs), **Snapshots** and **Files** (Monitor / Watchlist / Diffs sub-tabs), unified under `Shift+Arrow` navigation.
- **Help & keybinding editor** (`?`): browse every action by category and rebind any key (incl. `Ctrl` combos) with live conflict detection; persisted to `tui.keybindings`.
- **Snapshots tab** with an 8-slot snapshot memory per AVD (`1`–`8` load, `Ctrl+1`–`Ctrl+8` save, `a` assign).
- **friTap panel** with status header and live log tail.
- **Startup device picker** and real-time device shutdown/reconnect detection (`adb host:track-devices`).
- **Monitor settings tab** (kprobe/fsmon source, multiple paths, per-category event visibility).
- Theming of the chat/tool panels and the chat transcript; compact form widgets.

#### Analysis engine & run history
- **`AnalysisEngine`** replaces the ActionQ/DataGather pipeline (same `sandroid.json` keys).
- **Run history / run bundles**: every Play is stored as a self-contained bundle (`<results_path>/runs/<run_id>/` with `run.json`, `recording.txt`, raw pull tree), listed in **Files → Diffs**, scoped per device; Record/Play UX fixes and a redesigned Diffs layout.
- **Unified Files tab**: fsmon/kprobe monitor stream, Spotlight-Files watchlist and Play diffing in one place, with grouped, de-duplicated event display.
- **kprobe filesystem monitor** (`tui.monitor_backend = "kprobe"`, default): kernel tracefs kprobes with per-process/child-tree attribution and path-scoped capture, no binary pushed to the device; automatic fallback to `fsmon`.
- **Replay settle time** (`analysis.replay_settle_seconds`, default 8 s, also in Settings → Analysis): every replay's capture window stays open that much longer so slow network responses and late writes land in the run; the dry run waits the same extra time, so noise subtraction still compares equal windows.
- **Network reset after snapshot loads** (`analysis.network_reset_after_snapshot`, `"airplane"` (default) | `"svc"` | `"off"`, also in Settings → Analysis): after every snapshot load that precedes a replay or the dry run, the device network is briefly cycled and Sandroid waits for a default network, so connections restored from the snapshot (whose emulator NAT state is gone) fail at once and the app reconnects. Recordings started with the app already open now replay with working network instead of "Cannot connect … timeout". With the reset off, starting a recording in the open spotlight app shows a warning. The mode is recorded in `run_settings`.
- `mitmproxy.auto_device_proxy` is editable in Settings → Network & Frida.

#### Network interception
- **mitmproxy integration** (Network → Mitmproxy): start/stop `mitmweb`, live flow and TLS-failure tail, flow log.
- **Device Proxy and per-app App Proxies** in one Proxy Settings modal (`y`); App Proxies route individual apps (by UID) through Sandroid's mitmproxy or an external proxy (Burp/ZAP) via an on-device `gost` redirector; optional QUIC (UDP/443) blocking; emulator-aware host IP detection, device-reachability probe and `adb reverse` fallback.
- **CA certificate injection** into the system trust store (APEX bind-mount on Android 14+, Zygote mount namespace on Android 10–13, with confirmation before restarting Zygote); CA status reported on start.
- **Custom mitmproxy addons** from `~/.config/sandroid/mitm_addons/` and `./mitm_addons/`, managed with `Ctrl+A`, hot-reloaded on edit.

#### Bypass suite (EXPERIMENTAL)
- Flag-gated, single resident Frida script with **SSL**, **Root**, **Frida**, **Debug** and new **Integrity** (PairIP / licensing / attestation) categories; instant toggles without un-hooked gaps; auto-reload and package validation.
- SSL unpinning tiers: Java/Conscrypt/OkHttp/WebView/TrustKit/CT, native BoringSSL, **Chromium/cronet BoringSSL** (incl. stripped, symbol-less libraries), **mbedTLS / Meta Network Stack**; pre-init constructor interposition and a spawn-reliability ladder for hardened apps.

#### AI Chat (EXPERIMENTAL)
- `sandroid.ai`: streaming OpenAI-compatible client, tool-calling loop, MCP client bridge, concurrent subtasks with a device-resource arbiter.
- Chat dock (`Ctrl+Y`) with markdown rendering, ambient device/session context on every turn and ~76 tools (app/process lifecycle, device/network/flow queries, certificate/environment control, file transfer with host-path confinement, file monitor, record/replay).
- Per-tool permission gate (allow once / always / never, persisted).
- New `[ai]` and `[mcp]` config sections with secret redaction in `sandroid-config show`. **Note:** prompts, device context and tool output are sent to the configured endpoint — prefer a local endpoint (e.g. Ollama) and set the key via `SANDROID_AI__API_KEY`.

#### Evidence documentation & reporting
- **SHA-256** alongside MD5 for artifacts and APKs (new JSON keys; existing keys unchanged), keyed by full device path.
- **`Run Metadata`** in every results JSON: Sandroid/frida/friTap/dexray versions, host, device serial, AVD, Android version/API level, build fingerprint, ISO-8601 start/end timestamps with timezone, and the (secret-free) analysis settings.
- **Evidence manifest**: `manifest.json` + `SHA256SUMS` over the whole result folder (verifiable with `sha256sum -c` / `shasum -a 256 -c`); its own hash is logged.
- **`sandroid --report-from <dir>`** verifies the manifest and (re)generates the PDF for an existing result folder; `P` in **Files → Diffs** does the same for a run; `report.generate_pdf` creates it after every Play.
  Verification runs first: on a mismatch nothing is written (exit code 2). Existing files are never overwritten: the PDF is written as `Sandroid_Forensic_Report_regenerated_<UTC>.pdf` and recorded in `SHA256SUMS.addendum-<UTC>` (checked together with `SHA256SUMS`) plus a line in `sandroid_report.log`; the original `SHA256SUMS` stays unchanged.
- PDF reports never fail on long diffs: diffs continue over several table rows, lines over 400 characters and diffs over 200 lines are shortened with a visible note, and a section that still cannot be laid out is replaced by a note instead of aborting the report.
- PDF title page with run metadata, readable wrapping tables, deterministic timeline.

#### Device selection & safety defaults
- **Emulator memory guard**: the qemu process of the active emulator is watched; above `emulator.max_host_memory_gb` (default 10 GB) it is shut down (`memory_guard_action = "warn"` only logs). Sandroid warns when an emulator was started without `-feature -Vulkan`.
- **`--serial/-s`**, `$ANDROID_SERIAL` and `emulator.serial` select the device; every adb call is pinned to it.
- **AI Chat is off unless configured**, accepts only local endpoints unless `ai.allow_remote = true`, shows a data-egress notice naming endpoint and model, and no MCP server is enabled by default (the bundled demo server returns clearly marked fake data only).
- All bypass categories are labelled *experimental* and off by default.

#### Tooling
- Hermetic test suite (~1300 tests); `tests/conftest.py` blocks all real adb/emulator/frida access.
- CI runs ruff and pytest on Python 3.12 and 3.13 for `main` and `dev`, and checks the built distribution.
- Releases are tagged `v<version>` with notes taken from this changelog.

### Changed
- **friTap 2.0** compatibility; tested with friTap 2.6.7, AndroidFridaManager 2.0.7 (verified frida-server downloads), dexray-intercept 1.0.1.9, objection 1.12.5, mvt 2026.11, frida 17.26.
- Dependencies have upper bounds for fast-moving packages; `mcp`, `mitmproxy`, `androguard` and `psutil` are core dependencies (`.[ai]` is kept as an empty alias).
- Package metadata now states the actual license (GPL-3.0).
- Simplified app picker (system apps toggle on `Ctrl+S`).
- Spotlight header self-heals a stale "paused" state against the live process.
- Configuration is saved to `~/.config/sandroid/` again instead of the platformdirs location.
- ABX (binary XML) files are decoded in-process instead of shelling out.
- Documentation brought up to date (requirements, rooted-AVD setup, TOML configuration, new features).
- Docker image installs Sandroid from `pyproject.toml` (best effort, not tested in CI).

### Fixed
- frida-server start failures are reported honestly instead of always "started"; clean frida install prompt and Java bridge restored on frida 17.
- CA injection on Android 10–13; mitmproxy start/stop no longer deadlocks the TUI when triggered from AI Chat; `start_mitmproxy` can retry on another port.
- Glance band never updating from panels; tab-bar visibility; startup logo wobble.
- Shared-global ADB serial race between devices; zombie retries capped; `DeviceManagerProtocol` drift.
- kprobe backend: off-thread setup, path-mode scoping, preflight self-check hang, noisy teardown warnings.
- `ADB_PATH` is quoted when building shell commands (paths with spaces, Windows).
- ChangedFiles `.xml` branch reuses the joined pull paths.
- **Intra-file diffs restored**: the first pull after the action was always empty, so changed SQLite databases and XML/ABX files showed "Not enough data for intra file analysis" instead of row/attribute diffs.
- **Network results**: capture files are located on disk (the last capture was skipped with the noise filter off or N=1), TCP/UDP targets and IPv6 are reported with their DNS names, and a missing noise capture no longer wipes the result.
- Record→Play from the TUI now runs the same gatherers as the CLI (processes, sockets, network per `[analysis]` settings) and writes the full results JSON; processes/sockets polling stops with the action.
- Snapshot loads that fail abort the run; the guest clock is resynced to the host after every snapshot load (it drifted minutes behind).
- Noise: ART profiles, `package-dex-usage`, `monotonic_clock.xml`, battery history are always filtered; the dry run also subtracts deleted files.
- Artifact hashes are computed over the full pull tree (they were empty) and split APKs are hashed per part.
- `adb root` + `setenforce 0` are applied on every path that needs them (`--install-apk`, `--dexray`, `--fritap`, …); `--install-apk` no longer prints "too many values to unpack".
- The TUI starts without the AI dependencies; the forensic APK manager no longer crashes on a missing `WarningModal`; `features/screenshot.py` imports cleanly; several silently broken imports fixed; importing Sandroid never parses `sys.argv`.
- Headless: the CLI configuration is kept (wrong device name in reports), forensic mode forwards `--network` and no longer needs a package.
- TUI results are stored in one place under `paths.results_path` (previously split between the CWD and the run bundle); quitting no longer hangs on leftover helper threads.
- PDF report: logo shipped as package data, no crash without `RAW_RESULTS_PATH`, no empty file-name rows, no ANSI escape codes in PDF or JSON; the screenshot grid no longer converts/deletes the original PNGs.
- friTap: spawned targets are resumed (Android killed them after 10 s), hooks of dead jobs are unregistered, the panel shows when capturing stopped, and `fritap_output.json` is written on close.
- dexray-intercept: fixed a deadlock during script load ("TransportError … timeout") and stop not stopping the job.
- objection command lines fixed for objection 1.12; `frida.server_auto_start` is honoured; frida-server download errors (offline, rate limit, digest mismatch) are explained; MVT IOC download fallback fixed; `mitmweb` is found next to the Python interpreter.
- AI Chat: tools from external MCP servers and evidence deletion always require confirmation; the API key is never written to logs, results or the config file from the environment.
- `json_encoder` no longer recurses on duck-typed objects.
- Every Sandroid-launched emulator (incl. `sandroid-config avd start`, headless) disables guest Vulkan: SwiftShader Vulkan leaked host memory on each snapshot load, growing qemu to tens of GB over a session.
- **System noise filter**: well-known Android/GMS/Play background files (package-restrictions, netstats, usagestats, Wellbeing, Gboard, clearcut, …) are hidden from Changed/New/Deleted Files after the dry-run subtraction; the analysed app's files are never filtered and every hidden path is listed under `Other Data → Filtered Noise` (`analysis.system_noise_filter`, `noise_patterns`, `protected_packages`).
- XML/ABX diffs match elements by key (`name`/`key`/`id`/…) instead of position, so additions, updates and deletions are reported as such (`[ADDED]`/`[UPDATED]`/`[DELETED]`).
- Network results list every DNS name seen for an IP plus the TLS SNI; IPv6 attempts without a reply are labelled as such.
- PDF: long diffs (e.g. BLOB rows) are split across rows and capped instead of raising a ReportLab `LayoutError`; a failing section degrades on its own.
- Headless prints a short summary instead of the full JSON, exits non-zero (3) when a requested report/manifest could not be written, announces each action window with a countdown; `--import-action` replays a run bundle's `recording.txt`.
- TUI: no more `NoActiveAppError` crash (and lost results) on the second recording of a session; results are persisted even if the UI fails; replays can be cancelled and are stopped on quit; Enter on a focused Cancel/Discard button no longer starts playback; `Esc` never opens Quit; stale frida device handles are reset after snapshot loads.
- dexray-intercept from the TUI no longer stalls for minutes, resumes its spawned app and removes its temporary snapshot; the hook modal only changes groups the user toggled; failure reasons are shown.
- frida-server auto-start (`frida.server_auto_start`) works at TUI startup, on device change and in headless `--dexray`/`--fritap`; stale `frida-helper-*.dex` files are removed before a server (re)start.
- friTap stop completes with one keypress and finalizes the keylog and `fritap_output.json` even when the agent unload blocks.
- **Network noise by volume**: a destination also seen in the dry run is only subtracted when its traffic is comparable to the background (3× + floor on bytes/packets/connections); otherwise it is reported with an "also seen in background" note. Subtracted destinations and DNS names are listed under `Filtered Noise`. Payload sizes come from IP/UDP length fields.
- Files and directories with spaces (`Session Storage`, `Web Data`, …) are pulled correctly and no longer truncated by the `ls` parser; all `adb pull`/`push` paths are quoted.
- **Device selection is strict**: an explicitly requested serial (`--serial`, `ANDROID_SERIAL`, `emulator.serial`) that is not connected is an error (exit 1) in headless/batch modes — no evidence files are written and Frida never falls back to another device; every adb call keeps `-s` across brief device drop-outs; `Run Metadata` only records a device name confirmed by the device.
- Headless runs follow the `[analysis]` configuration (network, processes, dry run, number of runs) and `Run Metadata` records the settings actually used.
- mitmproxy: the device-reachability probe waits for the device to settle after the Zygote restart of CA injection and re-probes automatically; the CA status recognises an existing injection by fingerprint.
- friTap no longer crashes the app on re-attach: attach mode refuses a process that already carried a friTap/Frida agent (restart the app or use spawn mode) and re-resolves a stale spotlight PID. When the target dies, friTap stops itself, finalizes its outputs and clears the PID. Each session writes its own `fritap_keylog_<timestamp>.log`, `fritap_output_<timestamp>.json` and `fritap_capture_<timestamp>_1.pcap` (the capture now stops with friTap). A previous session's detach no longer marks a new spawn as "target process gone", and the Spotlight shows the PID of a process re-spawned by friTap or dexray.
- mitmproxy listens on `127.0.0.1` by default (`mitmproxy.listen_host`), the status shows the configured port while stopped, the device-reachability probe no longer reports false errors, and only a device proxy Sandroid set is cleared on stop/exit (`mitmproxy.auto_device_proxy` sets it on start).
- **Evidence integrity**: SQLite diffs integrate `-wal`/`-journal` files and run `sqldiff` on temporary copies, so pulled databases under `raw/` are no longer rewritten (VACUUM, WAL checkpoint, `-shm`) before they are hashed.
- Changed Files: one file whose diff fails (non-UTF-8 `.txt`, malformed ABX) is listed with a "could not analyse" note instead of emptying the whole section.
- Diff failures (missing/failed `sqldiff`, unparsable XML/ABX, missing pull) are reported as such and never shown as "No changes" or dropped as "ITS ALL NOISE"; CLI/headless warn at startup when `sqldiff` is missing.
- **Failed runs are no longer sealed as clean**: fatal and per-step errors (incl. failed result sections) are stored as `Run Errors` in the results JSON and `Run Metadata` (`run_status`), shown as a banner on the PDF's first page, and make `--trigdroid` / `--headless` / `--batch` exit with code 3.
- Device file names that are not valid UTF-8 no longer abort the filesystem scan (they are kept byte-exact for pulls, JSON and `SHA256SUMS`); the scan timeout is 300 s (`SANDROID_SCAN_TIMEOUT`), and an empty or failed baseline scan aborts the run instead of producing empty results.
- `--trigdroid` writes its results, PDF and manifest into the session folder instead of the base results directory.
- `--batch`: every package gets its own result folder (raw pulls, JSON, PDF, manifest) instead of sharing one session folder; per-path diff caches are reset per run.
- Renaming a run in Files → Diffs no longer rewrites the sealed `run.json` (the label is kept in `runs/labels.json` / `index.json`), so the bundle still verifies.
- A result folder whose `SHA256SUMS` was deleted is verified against `manifest.json` and reported as failed instead of being treated as unsealed; the `--report-from` message reflects an addendum.
- Artifact hashes include files that also changed in the dry run.
- Files hidden as structural noise (ART profiles, package-manager bookkeeping) or dry-run noise are listed under `Other Data → Filtered Noise` with their reason, and the PDF has a compact Filtered Noise appendix.
- Changed/New Files and SQLite update columns are reported in a deterministic order.
- **pcap analysis is streamed and bounded**: a dup-ACK/FIN storm on a half-open connection restored from the snapshot (1.3 M packets, 94 MB per capture) made the network analysis take ~4 min and >11 GB RAM. Captures are now read packet by packet into per-flow totals (same results, ~7 s for two such captures), repeated zero-payload TCP segments are not counted as traffic, progress is logged, and a capture over 5 M packets is cut with an "analysis truncated after N packets" note in the results.
- friTap: when the agent cannot unload (an app thread stuck in a hooked SSL call, which left the app permanently "isn't responding"), a spawned app is force-stopped after 19 s; for an attached app the log says it is likely frozen and how to recover. The routine "agent still unloading" note is no longer a warning.
- The header's App PID is re-checked while other tabs are shown, so an app restarted outside Sandroid no longer shows its dead PID as running.
- A replayed recording's run gets a distinct label (`<label> · play 2`) instead of a duplicate in the Runs rail.
- The dry run's start, window length and end are logged (headless output showed no sign of it).
- **Settings keep the live configuration**: saving in the TUI Settings screen (or changing mitmproxy addons) no longer reloads the config from disk, which silently dropped `--config`/`--environment`/CLI flags (results path, `--network`/`--hash`). Changes are validated against the whole config first (e.g. Number of Runs < 2 is refused with an error in the screen instead of breaking every later start), applied in place and written to the config file actually in use (the `--config` file if given) — only the changed keys, including sections missing from a minimal file. The Settings screen shows the values actually in effect.
- `sandroid --config FILE` (and `--environment`/`SANDROID_*`-only setups) no longer fail with "No configuration found!" when no config file is auto-discovered.
- `sandroid-config init` without `-o` no longer overwrites an existing user config without `--force`; `sandroid-config set KEY VALUE` / `get KEY` accept positional arguments (as the built-in hints and docs show), besides `-k`/`-v`.
- Config discovery no longer picks up `sandroid.json` (the default results file) or `config.*` from the working directory, and saves never write to such files.
- `q` and the command palette's Quit go through the same path as `Ctrl+C` (stop running tasks / confirm) — `q` used to exit immediately and the palette entry did nothing; the `QuitCommand` no longer logs a misleading "Exiting application...".
- Snapshot slots can be saved with `S` then `1`–`8` in every terminal; `Ctrl+1`–`8` only work in terminals with the kitty keyboard protocol (documented).
- Switching views with Shift+Arrows never leaves focus in a text field (Watchlist's "Add path" swallowed the next `⇧P`), and Shift+Arrows also work when nothing is focused.
- `--trigdroid-ccf` (never functional with the current TrigDroid API) is hidden and fails with a clear error; `--trigdroid … -f dir/out.json` also writes the results to `dir/out.json` (the directory was dropped) and prints the final path.
- Importing the TUI module no longer registers a terminal reset at exit, which printed escape sequences / `stty` errors after headless and `sandroid-config` runs.
- Docs: non-working commands fixed (`--output` → `-f`, `--number 1` → `-n 2`, CI/Docker/script examples use `--headless`), exit-code table matches the code (1 = analysis/config error, 2 = invalid command line, 3 = documentation failed).
- The device proxy and app-proxy lanes are bound to the device they were set on: switching devices releases them on the old device, and later cleanup never runs against the newly selected one; "already proxied" is checked per device.
- Emulator memory guard: the qemu behind a serial is found by its console port socket (emulators started without `-port` get auto-assigned ports), so with two emulators the guard no longer measures or stops the wrong one; ambiguous cases are left alone with a warning.
- Starting an AVD from the TUI disables guest Vulkan like the CLI; detached emulators log to `~/.cache/sandroid/emulator/<avd>.log` instead of a pipe that stalled them after ~64 KiB of output; "Restart emulator" relaunches the running AVD with the safe flags and only reports success once it has booted.
- Deleting a snapshot the console rejects (`KO: …`) is reported as a failure.
- Creating, loading or slot-saving a snapshot that fails (e.g. an invalid name) shows an error toast instead of "Created snapshot …"; invalid names are rejected before any adb call.
- After the CA install restarts Zygote (and with it system_server), a running frida-server is restarted and cached frida handles are dropped, so the next spawn no longer fails with `DeadSystemException`; at startup a frida-server older than system_server is restarted instead of reported as "already running".
- TUI replays record `replay_settle_seconds` in `run_settings` (only headless runs did).
- Watchlist: after adding a path, focus returns to the list (the next `n`/`a` was typed into the field); re-expanding a wildcard no longer logs "already in spotlight files" for every known match or toasts "new file(s)" when nothing is new, and expanded files that disappear are dropped quietly instead of erroring on every auto-mode tick.
- The startup CA-status probe no longer logs two ADB WARNINGs when the CA is simply not installed yet (one INFO line instead).
- Headless API network capture starts tcpdump detached on the device (it blocked for 30 s), honours `output_file`, and stops exactly its own tcpdump PID instead of `pkill tcpdump`.

#### Security
- Host command injection from the device or the AI: values that reach `adb` through the host shell — device filenames (watchlist auto-refresh, wildcard spotlight files), package names, PIDs, snapshot names, emulator-console arguments, root/kprobe command wrappers — are now quoted for both the host and the device shell or validated (Android package format, `[A-Za-z0-9._-]` snapshot names, positive integer PIDs). Previously a device file named `$(cmd)` or a READ_ONLY AI tool call such as `get_process_detail(pid="1;cmd")` ran `cmd` on the analyst's machine without approval.
- AI tool arguments are type-checked against each tool's JSON schema before dispatch; `set_spotlight_app`, `enable_app_proxy` and the spotlight service reject invalid package names; `get_file_diff` accepts only one absolute path without wildcards.
- The tool-approval prompt no longer hides arguments past 300 characters: long arguments are flagged and shown in full (scrollable), model-supplied markup is escaped, and an omitted package shows the spotlight app it resolves to.

### Removed
- Legacy Rich interactive menu (`-i`), Gemini video summarisation (`--ai`), TUI view modes, the `ipt2socks` redirector, the stale `docker/requirements.txt`.

## [2.0.0] - 2026-03-17

### Complete Rewrite: Textual TUI, Click CLI, and Three Analysis Views

This release represents a complete rewrite of Sandroid's user interface and CLI, introducing a modern terminal user interface, a new Click-based command-line interface, and three specialized analysis views.

### Added

#### Textual TUI
- **Modern terminal user interface** using the Textual framework replacing the Rich-based menu
- **Three analysis views**: Forensic, Malware, and Security (early stage) — switch with TAB
- **Status bar** showing Frida server status, HTTP proxy, spotlight app, and spotlight files
- **Activity log** with real-time command output and status messages
- **Theme system** with 8 built-in themes (default, dark, light, high_contrast, cyberpunk, nord, dracula, solarized)
- **Custom CSS support** for TUI customization
- **Welcome dialog** for first-time users

#### Click-Based CLI
- **Migrated from argparse to Click** with hyphenated flags (e.g., `--avoid-strong-noise-filter`)
- **View selection**: `--view forensic|malware|security`
- **Headless mode**: `--headless` with `--batch` for batch processing
- **Legacy mode**: `sandroid -i` for the classic Rich interactive menu

#### New Analysis Tools
- **Dexray-Intercept** integration for dynamic hooking and malware monitoring (`--dexray`)
- **Dexray-Insight** integration for static analysis (replacing asam)
- **Fridump** integration for memory dumping (`--fridump`)
- **FriTap** headless mode for SSL/TLS key extraction (`--fritap`)
- **Objection** integration with resume support
- **MVT** (Mobile Verification Toolkit) forensic evidence scanning

#### Device Management
- **HTTP proxy management**: `--proxy`, `--proxy-clear`
- **APK installation**: `--install-apk`
- **Action import**: `--import-action`
- **Device settings**: `--device-settings`, `--preset`
- **Country presets** (de, us, ru, cn, etc.)

#### Configuration Management
- **AVD management commands**: `sandroid-config avd list|start|stop|rename|create`
- **Theme management**: `sandroid-config theme list|set|show`
- **IOC management**: `sandroid-config ioc show|set-path|set-url|download|validate`
- **Device listing**: `sandroid-config devices`
- **TOML as default** configuration format (replacing YAML)

#### New TUI Commands
- `C` — Spawn spotlight application
- `E` — Device settings and presets
- `F` — Forensic evidence scan (MVT)
- `G` — Manage forensic APKs
- `k` — Reconfigure Frida hooks
- `O` — Resume objection session

### Changed
- **Default mode**: `sandroid` now launches the Textual TUI (previously Rich menu)
- **Legacy mode**: Rich interactive menu available via `sandroid -i`
- **TrigDroid**: Now fully integrated (previously marked as not fully integrated)
- **Frida handling**: Smart per-command requirement with modal prompts instead of manual install-first workflow
- **Command registry**: 12 command categories across 3 views replacing 5 static menu sections

### Removed
- **AM3 (Android Malware Motion Monitor)**: Replaced by Dexray-Intercept
- **asam**: Renamed to Dexray-Insight

## [1.1.9] - 2025-09-15

Updated Fridump class to work with frida >= 17.0

## [1.1.0] - 2025-08-27

### Complete Package Migration: PyPI Distribution Now Feature-Complete

This release resolves the critical "Legacy analysis modules not available" error and makes the PyPI installation fully feature-complete with the legacy version.

### Fixed
- **Package Migration**: Migrated 32 analysis modules from `src/utils/`, `src/datagather/`, and `src/functionality/` to proper pip-installable packages
- **Import Errors**: Fixed "No module named 'src'" errors that prevented PyPI installation from working
- **Module Structure**: Reorganized code into modern package structure:
  - `src/utils/` → `src/sandroid/core/` (15 modules)
  - `src/datagather/` → `src/sandroid/analysis/` (10 modules)
  - `src/functionality/` → `src/sandroid/features/` (5 modules)

### Added
- **Dual-Mode Architecture**: Both legacy (`./sandroid`) and modern (`sandroid`) CLI work identically
- **Compatibility Layer**: Transparent import redirection maintains 100% backward compatibility
- **Code Quality**: Comprehensive linting configuration with security rule exemptions for forensic tools
- **Modern Dependencies**: Updated Frida to v17+ and frida-tools to v14+

### Changed
- **Package Structure**: Migrated to modern Python packaging while preserving all functionality
- **Import Paths**: Fixed hardcoded `from src.` imports throughout the codebase
- **Build Configuration**: Updated `pyproject.toml` to include all migrated packages

### Technical Details
- **32 Modules Migrated**: Complete analysis framework now properly packaged
- **Circular Import Resolution**: Fixed complex interdependencies between modules
- **Linting Compliance**: Resolved F403, TID252, F405, and security (S*) linting issues
- **Type Safety**: Fixed Pydantic v2 API compatibility (`regex` → `pattern`)

## [1.0.0] - 2025-01-21

### 🚀 Major Release: Modern PyPI Package with Advanced Configuration

This release represents a complete modernization of the Sandroid framework while maintaining full backward compatibility. The project now offers professional-grade packaging, configuration management, and development workflows.

### Added

#### PyPI Package Infrastructure
- **Modern pyproject.toml** with comprehensive dependency management
- **Entry points** for CLI commands (`sandroid`, `sandroid-config`)
- **Optional dependencies** for different use cases (`[ai,dev,docs]`)
- **Development tools integration** (black, isort, pytest, mypy, flake8)
- **Build system** using modern setuptools backend
- **Proper package structure** under `src/sandroid/`

#### Advanced Configuration System
- **Pydantic-based configuration schema** with full type validation
- **Multi-format support**: TOML, YAML, JSON configuration files
- **XDG Base Directory compliance** for standard config file locations
- **Hierarchical configuration loading**: CLI args > env vars > config files > defaults
- **Environment variable support** with `SANDROID_` prefix and nested configuration
- **Configuration validation** with clear error messages and helpful suggestions
- **Configuration CLI tool** (`sandroid-config`) for easy management

#### Modern CLI Interface
- **Rich console output** with colors, tables, and syntax highlighting
- **Click framework** for robust argument parsing and help system
- **Interactive configuration** management commands
- **Environment-specific configurations** for development, testing, production
- **Comprehensive help system** with examples and detailed descriptions

#### Configuration Management Features
- `sandroid-config init` - Create default configuration files (YAML format)
- `sandroid-config show` - Display current configuration with formatting
- `sandroid-config validate` - Validate configuration files
- `sandroid-config set/get` - Modify individual configuration values
- `sandroid-config paths` - Show configuration file search locations
- **Configuration file discovery** in standard XDG directories
- **Template configurations** for different use cases
- **YAML-first approach** with support for TOML and JSON
- **Secure credentials section** for API keys and tokens

#### Documentation Suite
- **SETUP.md** - Comprehensive setup guide for new users
- **MIGRATION.md** - Detailed migration guide from legacy to modern installation
- **Updated development documentation** - Modern development workflows and installation methods
- **Configuration examples** for basic analysis, security analysis, and development
- **Environment variable reference** with complete configuration mapping
- **Troubleshooting guides** for common setup and configuration issues

#### Development Infrastructure
- **Modern testing framework** with pytest and coverage reporting
- **Code quality tools** with black, isort, flake8, mypy configurations
- **Type hints** throughout the configuration system
- **Mock testing infrastructure** for ADB and emulator interactions
- **CI/CD ready** configurations for automated testing and building

### Enhanced

#### CLI Experience
- **Backward compatible** command-line interface preserving all existing arguments
- **Enhanced help system** with detailed descriptions and examples
- **Rich formatting** for error messages and output
- **Configuration integration** allowing CLI arguments to override config files
- **Environment detection** with automatic configuration loading

#### Configuration Management
- **Replaced hardcoded values** with configurable options throughout the system
- **Path management** with automatic directory creation and validation
- **Security improvements** with environment variable support for sensitive data
- **Extensibility** through custom configuration sections
- **Validation** preventing invalid configurations from being used

#### Developer Experience
- **Modern package structure** following Python packaging best practices
- **Development mode installation** with `pip install -e .[dev]`
- **Comprehensive testing** with unit, integration, and configuration tests
- **Documentation generation** with Sphinx support
- **Code formatting** with automatic black and isort integration

### Changed

#### Installation Method
- **Primary installation** now via PyPI: `pip install sandroid`
- **Optional dependencies** for different use cases
- **Simplified setup** with automatic dependency resolution
- **Configuration initialization** as separate step for better user control

#### Configuration Architecture
- **Moved from hardcoded values** to external configuration files
- **Standardized configuration locations** following XDG specification
- **Environment variable standardization** with `SANDROID_` prefix
- **Hierarchical loading** allowing multiple configuration sources
- **Type validation** preventing configuration errors

#### Project Structure
- **New package layout** under `src/sandroid/` for proper packaging
- **Separated configuration system** into dedicated module
- **Modern CLI entry points** while preserving legacy script
- **Documentation organization** with dedicated setup and migration guides

### Maintained

#### Backward Compatibility
- **Legacy installation method** still fully supported
- **Existing CLI arguments** work unchanged
- **Legacy scripts** (`./sandroid`) continue to function
- **Existing workflows** require no immediate changes
- **Gradual migration path** with comprehensive guides

#### Core Functionality
- **All analysis capabilities** preserved without modification
- **Frida integration** unchanged
- **Android emulator support** maintained
- **Output formats** (JSON, PDF) unchanged
- **Ground truth APK** functionality preserved

#### Dependencies
- **Core dependencies** remain the same
- **Analysis modules** work without modification
- **Frida manager** integration preserved
- **ADB communication** unchanged

### Technical Details

#### Configuration Schema
```toml
# Example modern configuration
log_level = "INFO"
output_file = "sandroid.json"

[emulator]
device_name = "Pixel_6_Pro_API_31"
android_emulator_path = "~/Android/Sdk/emulator/emulator"

[analysis]
number_of_runs = 2
monitor_network = false
monitor_processes = true

[paths]
results_path = "./results/"
cache_path = "~/.cache/sandroid/"
```

#### Environment Variables
```bash
# All configuration can be set via environment variables
export SANDROID_LOG_LEVEL="DEBUG"
export SANDROID_EMULATOR__DEVICE_NAME="Custom_Device"
export SANDROID_ANALYSIS__NUMBER_OF_RUNS=5
export SANDROID_PATHS__RESULTS_PATH="/custom/results"
```

#### CLI Commands
```bash
# Modern installation and usage
pip install sandroid[ai,dev]
sandroid-config init
sandroid-config validate
sandroid --config production.toml --network --ai --report

# Configuration management
sandroid-config show --format toml
sandroid-config set analysis.monitor_network true
sandroid-config get emulator.device_name
```

### Migration Path

#### For New Users
1. Install via PyPI: `pip install sandroid`
2. Initialize configuration: `sandroid-config init`
3. Customize configuration as needed
4. Run analysis: `sandroid --help`

#### For Existing Users
1. Continue using legacy installation (no changes required)
2. When ready, install PyPI package alongside legacy
3. Use migration guide to transfer settings
4. Switch to modern CLI when convenient
5. Remove legacy installation when comfortable

### Dependencies

#### New Dependencies
- `pydantic>=2.0.0` - Configuration validation and type safety
- `platformdirs>=3.0.0` - XDG directory compliance
- `rich>=13.0.0` - Enhanced console output and formatting
- `tomli>=2.0.1` (Python <3.11) - TOML file parsing
- `tomli-w>=1.0.0` - TOML file writing
- `pyyaml>=6.0` - YAML configuration support

#### Optional Dependencies
- `[ai]` - Google Generative AI support
- `[dev]` - Development tools (pytest, black, isort, mypy, flake8)
- `[docs]` - Documentation generation tools (sphinx, themes)

### Breaking Changes
**None** - This release maintains full backward compatibility.

### Security
- **Secure credentials management** with dedicated configuration section
- **API key extraction** from source code to configuration files
- **Environment variable support** for sensitive configuration (API keys)
- **Configuration validation** prevents invalid or dangerous settings
- **Path validation** ensures secure file operations
- **Input sanitization** in configuration loading
- **GitLab token management** moved from hardcoded values to secure configuration

### Performance
- **Lazy loading** of configuration only when needed
- **Cached configuration** parsing for repeated access
- **Optimized dependency loading** with optional imports
- **Efficient file discovery** using XDG standard locations

### Documentation Updates
- **Complete SETUP.md** with step-by-step installation guide
- **Comprehensive MIGRATION.md** for upgrading from legacy
- **Updated development documentation** with modern development workflows
- **Configuration examples** for different use cases
- **Environment variable reference** documentation
- **Troubleshooting guides** for common issues
- **API documentation** for configuration schema

---

## Previous Versions

### [0.x.x] - Legacy Versions
- Original hardcoded configuration system
- Manual installation via `install-requirements.sh`
- Direct script execution with `./sandroid`
- Limited configuration options
- Basic CLI interface

---

## Migration Notes

### From Legacy to Modern
1. **No immediate action required** - legacy installation continues to work
2. **Try modern installation** alongside legacy for evaluation
3. **Use migration guide** when ready to switch
4. **Gradual migration** - move configurations over time
5. **Full backward compatibility** ensures no functionality loss

### Configuration Migration
- Use `sandroid-config init` to create modern configuration
- Transfer hardcoded values from `toolbox.py` to config files
- Replace custom environment variables with `SANDROID_` prefixed versions
- Validate new configuration with `sandroid-config validate`

### Development Migration
- Install development dependencies: `pip install -e .[dev]`
- Use modern testing: `pytest` instead of custom test scripts
- Apply code formatting: `black src/` and `isort src/`
- Add type hints using configuration schema as example

## Acknowledgments

This modernization maintains the core forensic analysis capabilities of Sandroid while providing a professional, maintainable foundation for future development. The extensive backward compatibility ensures existing users can migrate at their own pace while new users benefit from modern Python packaging and configuration practices.
