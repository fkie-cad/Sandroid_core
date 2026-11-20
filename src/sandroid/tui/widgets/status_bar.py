"""Status bar widget showing application state."""

import os
import threading

from rich.console import RenderableType
from rich.markup import escape
from rich.text import Text
from textual.widgets import Static

from sandroid.core.adb import Adb
from sandroid.core.enums import ViewMode
from sandroid.services import (
    get_frida_session_service,
    get_network_capture_service,
    get_spotlight_service,
    get_task_service,
    get_ui_service,
)
from sandroid.tui.themes import fixed_color
from sandroid.tui.utils.ui_thread import UiDispatcher


class StatusBar(Static):
    """Status bar showing current application state.

    A compact strip (at most ``MAX_ROWS`` rows, full width) under the shell
    header: App state (pid / paused), Frida, Hooks + bypass (when active),
    Proxy (engine, device route, per-app lanes), Capture (when running) and
    Record/Replay (while active -- see ``recording_active``/``replay_active``,
    set by app.py's ``_set_status_bar_mode``). Device and package names are
    exposed through :meth:`breadcrumb_markup` for the header instead.

    Status indicators (running/stopped, spawn/attach) use fixed colors
    that don't change with theme for instant recognition.
    View colors and text colors are pulled from the current theme.

    All status properties are regular instance attributes (not Textual reactives).
    Using 19 reactive() descriptors caused Textual's mount chain to stall,
    preventing MainScreen.on_mount() from firing. Regular attributes work
    identically here because there are no watch_* methods and all callers
    explicitly call self.refresh() after setting values.
    """

    def __init__(self, **kwargs):
        # Initialize all status properties as regular attributes BEFORE super().__init__
        # (avoids Textual reactive descriptor overhead that blocks mount chain)
        self.frida_status = "Not running"
        self.spotlight_app = "None"
        self.current_view = "FORENSIC"
        self.current_theme = ""
        self.show_theme_indicator = False
        self.active_device = ""
        self.device_type = ""
        # Cached device metadata (populated at discovery — no ADB on refresh):
        self.device_android_version = ""
        self.device_api_level = 0
        self.device_rooted: bool | None = None  # None = unknown
        self.background_tasks_count = 0
        self.background_tasks_display = ""
        self.forensic_apks_count = 0
        self.proxy_address = ""
        # Per-app proxy lanes managed by FocusManager: pkg -> "ours"|"http://…".
        # Replaces the retired mutually-exclusive capture_scope/focus_apps model.
        self.app_proxies: dict = {}
        # App Proxy lanes that pass no traffic: ``{state_label: count}``
        # (e.g. "waiting for mitmproxy"), from the last reconcile; no adb.
        self.app_proxy_problems: dict[str, int] = {}
        # mitmweb (our bundled proxy) status, distinct from where the device
        # points: ``mitmweb_address`` is our canonical host:port even when
        # stopped, so the Proxy row can tell "ours" from a foreign proxy.
        self.mitmweb_running = False
        self.mitmweb_address = ""
        self.network_capture_running = False
        self.network_capture_file = ""
        # Record/Replay mode indicator — set directly by app.py's
        # _set_status_bar_mode() (wired from RecordingController's
        # set_recording_indicator/set_replay_indicator callbacks), never
        # derived here in update_from_toolbox(). Independent booleans: both
        # could in principle be true only very briefly around the auto-chain
        # boundary, so render() checks each on its own.
        self.recording_active = False
        self.replay_active = False
        # Phase of the running Play ("replay 1/2", "dry run", ...), or None.
        self.replay_phase: str | None = None
        # Glance-band datums (cheap, in-process reads — no ADB):
        self.spotlight_pid: int | None = None
        self.spotlight_paused = False
        #: Sandroid is restarting the app (Shift+R): the old PID is gone.
        self.spotlight_restarting = False
        #: Why the Frida session was lost (frida-server gone), until it runs
        #: again; see _on_frida_detached.
        self._frida_lost: str | None = None
        self.hook_count = 0  # running hook tasks for the spotlight app
        # Armed/active bypass categories, in BypassService display order.
        self.bypass_categories: list[str] = []
        self.tools_checking = True
        self.sqldiff_available = False
        self.objection_available = False
        self.frida_available_check = False
        self._frida_version_mismatch: bool | None = None  # None = not checked yet
        self._frida_last_status: str = ""  # Track status transitions
        #: frida-server is being (auto-)started right now; read on the 1.5 s
        #: poll from core/frida_manager.py (in-process, no ADB).
        self.frida_starting = False
        #: Re-check Frida once the running check is done (a start ended).
        self._frida_recheck = False
        #: Stage of a running device-prepared step ("" when none), see
        #: core/device_prep.py; read on the 1.5 s poll.
        self.device_prep_stage = ""
        self._ui = UiDispatcher()
        super().__init__(**kwargs)

    def on_mount(self) -> None:
        """Initialize theme name and visibility from app/config on mount."""
        try:
            if hasattr(self.app, "sandroid_theme"):
                self.current_theme = self.app.sandroid_theme.display_name
            # Check config for show_theme_indicator setting
            if hasattr(self.app, "sandroid_config") and self.app.sandroid_config:
                self.show_theme_indicator = (
                    self.app.sandroid_config.tui.show_theme_indicator
                )
        except Exception:
            self.current_theme = "Default"
            self.show_theme_indicator = False

        self._ui = UiDispatcher.capture()
        # Defer EventBus subscription to avoid deadlocks during mount chain
        # (same pattern as MainScreen lines 81-84)
        self.call_later(self._subscribe_to_tool_events)

        # The glance band has no other periodic refresh, so mitmproxy
        # start/stop (and device→mitmproxy linkage) would lag until some
        # unrelated event repaints. A cheap in-process poll keeps it honest.
        self._capture_poll_timer = self.set_interval(1.5, self._poll_capture_state)

    def _subscribe_to_tool_events(self) -> None:
        """Subscribe to TOOL_AVAILABILITY_UPDATED event from SetupService."""
        try:
            from sandroid.core.events import EventBus, EventType

            EventBus.get().subscribe(
                EventType.TOOL_AVAILABILITY_UPDATED,
                self._on_tool_availability_updated,
            )
            EventBus.get().subscribe(EventType.STATE_CHANGED, self._on_state_changed)
        except ImportError:
            pass  # Events module not available
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            get_bypass_service().add_state_listener(self._on_bypass_state)
        except Exception:
            pass
        from sandroid.services.app_start import add_pre_start_status_listener

        add_pre_start_status_listener(self._on_pre_start_status)

    def on_unmount(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            EventBus.get().unsubscribe(EventType.STATE_CHANGED, self._on_state_changed)
        except Exception:
            pass
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            get_bypass_service().remove_state_listener(self._on_bypass_state)
        except Exception:
            pass
        from sandroid.services.app_start import remove_pre_start_status_listener

        remove_pre_start_status_listener(self._on_pre_start_status)

    def _on_state_changed(self, event) -> None:
        """A Frida session detached because frida-server went away (any
        thread): say so in the Frida pill at once, not at the next refresh.
        """
        data = getattr(event, "data", None) or {}
        if data.get("change_type") == "frida_server_after_load":
            ok = bool(data.get("ok"))
            reason = str(data.get("reason") or "")
            try:
                self.app.call_from_thread(self._on_frida_after_load, ok, reason)
            except RuntimeError:  # already on the UI thread
                self._on_frida_after_load(ok, reason)
            except Exception:
                pass  # app shutting down
            return
        if data.get("change_type") != "frida_detached" or not data.get("server_lost"):
            return
        reason = str(data.get("reason") or "lost")
        try:
            self.app.call_from_thread(self._on_frida_detached, reason)
        except RuntimeError:  # already on the UI thread
            self._on_frida_detached(reason)
        except Exception:
            pass  # app shutting down

    def _on_frida_after_load(self, ok: bool, reason: str) -> None:
        """frida-server auto-start after a snapshot load finished (UI thread):
        refresh the Frida row; say why when it failed.
        """
        if ok:
            self._frida_lost = None
        self._schedule_frida_check()
        if not ok:
            try:
                self.app.notify(
                    f"frida-server auto-start failed: {reason}",
                    severity="warning",
                    timeout=10,
                )
            except Exception:
                pass

    def _on_frida_detached(self, reason: str) -> None:
        """Mark the session lost, re-check the server, tell the user once."""
        first = self._frida_lost is None
        self._frida_lost = reason
        self.frida_status = "Not running"
        self._frida_version_mismatch = None
        self.refresh()
        self._schedule_frida_check()
        if first:
            try:
                self.app.notify(
                    f"Frida: connection to frida-server lost ({reason}) — "
                    "hooks are gone. Shift+R restarts the app and frida-server.",
                    severity="warning",
                )
            except Exception:
                pass

    def _on_tool_availability_updated(self, event) -> None:
        """Handle tool availability update from deferred setup checks.

        Args:
            event: Event with tool availability data
        """
        try:
            data = event.data
            # Update reactive properties from background thread safely
            self.app.call_from_thread(
                self._apply_tool_availability,
                data.get("sqldiff_available", False),
                data.get("objection_available", False),
                data.get("frida_available", False),
            )
        except Exception:
            pass  # Ignore errors during app shutdown

    def _apply_tool_availability(
        self, sqldiff: bool, objection: bool, frida: bool
    ) -> None:
        """Apply tool availability updates to reactive properties.

        Args:
            sqldiff: Whether sqldiff is available
            objection: Whether objection is available
            frida: Whether frida module is available
        """
        self.tools_checking = False
        self.sqldiff_available = sqldiff
        self.objection_available = objection
        self.frida_available_check = frida
        self.refresh()

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for status bar rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",
            "success": "#00ff00",
            "error": "#fb7185",
            "warning": "#facc15",
            "text_muted": "#8f9bb3",
            "header_muted": "#8f9bb3",
            ViewMode.FORENSIC: "#2dd4bf",
            ViewMode.MALWARE: "#fb7185",
            ViewMode.SECURITY: "#facc15",
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["success"] = theme.success
                colors["error"] = theme.error
                colors["warning"] = theme.warning
                colors["text_muted"] = theme.text_muted
                colors["header_muted"] = theme.header_muted or theme.text_muted
                colors[ViewMode.FORENSIC] = theme.forensic_color
                colors[ViewMode.MALWARE] = theme.malware_color
                colors[ViewMode.SECURITY] = theme.security_color
        except Exception:
            pass

        return colors

    def breadcrumb_markup(self) -> str:
        """Device / app breadcrumb for the shell header (markup, no I/O)."""
        colors = self._get_theme_colors()
        muted = colors["header_muted"]
        parts = []
        if self.active_device:
            device = f"{self.device_type} {self.active_device}".strip()
            specs = []
            if self.device_android_version or self.device_api_level:
                specs.append(f"A{self.device_android_version or '?'}")
            if self.device_rooted is True:
                specs.append("root")
            spec_txt = f" [{muted}]{' · '.join(specs)}[/]" if specs else ""
            parts.append(f"{device}{spec_txt}")
        else:
            parts.append(f"[{muted}]no device — D to select[/]")
        if self.spotlight_app and self.spotlight_app != "None":
            parts.append(f"[b]{self.spotlight_app}[/b]")
        return "  [dim]/[/dim]  ".join(parts)

    def _segments(self) -> list[Text]:
        """Status segments in priority order (most important first).

        Only what changes decisions is shown; idle tools (no capture, no
        hooks) are omitted rather than printed as "none" -- the header owns
        device + app identity, the pill owns record/replay/review.
        """
        colors = self._get_theme_colors()
        muted = colors["text_muted"]
        primary = colors["primary"]
        warn = colors["warning"]
        run = fixed_color("running")
        stop = fixed_color("stopped")
        paused = fixed_color("paused")
        segs: list[str] = []

        # The device is being prepared (root, SELinux, proxy restore):
        # Frida / app actions wait for it.
        if self.device_prep_stage:
            segs.append(
                f"[{paused}]◌ Preparing device…[/] "
                f"[{muted}]{escape(self.device_prep_stage)}[/]"
            )

        # App state (package itself is in the header breadcrumb). A status
        # dot plus the word, both in the state colour: ● on, ○ off, ◌ pending.
        if self.spotlight_app and self.spotlight_app != "None":
            pid = self.spotlight_pid
            step = self._pre_start_step()
            if step:
                # Identity's apply can take minutes: say so, not "not running".
                state = f"[{paused}]◌ {escape(step[:1].lower() + step[1:])}[/]"
            elif self.spotlight_paused:
                pid_part = f" pid {pid}" if pid else ""
                state = f"[{paused}]◌ paused[/][{muted}]{pid_part}  Space resumes[/]"
            elif pid:
                state = f"[{run}]● running[/] [{muted}]pid {pid}[/]"
            elif self.spotlight_restarting:
                state = f"[{paused}]◌ restarting…[/]"
            else:
                state = f"[{muted}]○ not running[/] [{muted}] Space starts[/]"
            segs.append(f"[{muted}]App[/] {state}")
        else:
            segs.append(f"[{muted}]App ○ none[/]")

        # Frida.
        if self.frida_starting:
            frida = f"[{paused}]◌ starting[/]"
        elif self.frida_status != "Running" and self._frida_lost:
            frida = f"[{stop}]connection lost[/] [{muted}] Shift+R restarts[/]"
        elif self.frida_status == "Running":
            if self._frida_version_mismatch:
                frida = f"[{fixed_color('notice')}]● running, version mismatch[/]"
            else:
                frida = f"[{run}]● running[/]"
        elif self.frida_status == "Checking...":
            frida = f"[{muted}]◌ checking[/]"
        else:
            frida = f"[{muted}]○ off[/]"
        segs.append(f"[{muted}]Frida[/] {frida}")

        # Hooks + bypass, only when something is active.
        on = list(self.bypass_categories)
        if self.hook_count or on:
            bypass = f"  [{muted}]bypass[/] [{run}]{', '.join(on)}[/]" if on else ""
            segs.append(f"[{muted}]Hooks[/] [b]{self.hook_count}[/]{bypass}")

        # Proxy: engine + device route + per-app lanes, on one segment.
        pointed_at_us = bool(self.proxy_address) and (
            self.proxy_address == self.mitmweb_address
            # A loopback proxy is our adb-reverse route, never foreign.
            or self.proxy_address.startswith("127.0.0.1:")
        )
        # "Mitmproxy" is our engine; "Device proxy" says where the device
        # points, so a running Mitmproxy never reads as "the device is
        # proxied". Status dot + word in theme colours.
        if self.mitmweb_running:
            addr = f" {self.mitmweb_address}" if self.mitmweb_address else ""
            proxy = f"[{muted}]Mitmproxy[/] [{run}]● on{addr}[/]"
        else:
            proxy = f"[{muted}]Mitmproxy[/] [{muted}]○ off[/]"
        if pointed_at_us:
            if self.mitmweb_running:
                proxy += f" [{muted}]· Device proxy[/] [{run}]● on[/]"
            else:
                # Device points at our stopped proxy: traffic goes nowhere.
                proxy += f" [{warn}]· Device proxy to the stopped Mitmproxy[/]"
        elif self.proxy_address:
            proxy += (
                f" [{muted}]· Device proxy to[/] [{primary}]{self.proxy_address}[/]"
            )
        elif self.mitmweb_running:
            proxy += f" [{muted}]· Device proxy ○ off[/]"
        proxied = list(self.app_proxies.values())
        n_ours = sum(1 for v in proxied if v == "ours")
        m_ext = len(proxied) - n_ours
        if n_ours:
            apps = "app" if n_ours == 1 else "apps"
            proxy += f" [{muted}]·[/] [{run}]App Proxy for {n_ours} {apps}[/]"
        if m_ext:
            apps = "app" if m_ext == 1 else "apps"
            proxy += f" [{muted}]· App Proxy for {m_ext} {apps} to an external proxy[/]"
        for label, count in sorted(self.app_proxy_problems.items()):
            what = "app" if count == 1 else "apps"
            proxy += f" [{warn}]· {count} {what} {escape(label)}[/]"
        segs.append(f"[{muted}]Proxy[/] {proxy}")

        # Capture, only while running.
        if self.network_capture_running:
            filename = (
                os.path.basename(self.network_capture_file)
                if self.network_capture_file
                else "capture.pcap"
            )
            segs.append(
                f"[{muted}]Capture[/] [{run}]● running[/] [{muted}]{escape(filename)}[/]"
            )

        # Record / Rewind: ● + state word; the controller's phase line as is.
        if self.recording_active or self.replay_active or self.replay_phase:
            text = self.replay_phase or (
                "● Recording" if self.recording_active else "● Rewind running"
            )
            color = stop if self.recording_active else fixed_color("spawn_mode")
            segs.append(f"[{color} bold]{escape(text)}[/]")

        if self.show_theme_indicator:
            segs.append(f"[{muted}]Theme[/] [{primary}]{self.current_theme}[/]")

        out = []
        for markup in segs:
            try:
                out.append(Text.from_markup(markup))
            except Exception:
                out.append(Text(markup))
        return out

    #: Maximum rows the status strip may take (the rest is dropped).
    MAX_ROWS = 2

    def on_resize(self, event) -> None:
        self.refresh(layout=True)

    def render(self) -> RenderableType:
        """Render the status strip: segments packed into at most two rows.

        Segments are never split across rows; whatever does not fit in
        ``MAX_ROWS`` is dropped (lowest priority last). ``fixed_color`` drives the
        status glyphs so they read the same across themes.
        """
        width = self.content_size.width or 160
        gap = "    "
        rows: list[Text] = [Text()]
        for seg in self._segments():
            row = rows[-1]
            needed = seg.cell_len + (len(gap) if row.cell_len else 0)
            if row.cell_len and row.cell_len + needed > width:
                if len(rows) >= self.MAX_ROWS:
                    continue
                rows.append(Text())
                row = rows[-1]
            if row.cell_len:
                row.append(gap)
            row.append_text(seg)
        result = Text("\n").join(rows)
        result.no_wrap = True
        result.overflow = "ellipsis"
        return result

    def update_from_toolbox(self) -> None:
        """Update status from Toolbox state."""
        try:
            from sandroid.core.toolbox import Toolbox

            # Update view
            self.current_view = get_ui_service().get_current_view().upper()

            # Frida status check is DEFERRED to background thread
            # is_frida_server_running() makes 3 sequential ADB shell commands
            # which blocks the UI for several hundred milliseconds
            # Show "Checking..." and schedule async check
            if self.frida_status not in ("Running", "Not running", "N/A"):
                # Only show "Checking..." if we haven't gotten a result yet
                self.frida_status = "Checking..."

            # Schedule background check (doesn't block UI)
            self._schedule_frida_check()

            # Update spotlight app
            spotlight = get_spotlight_service()
            self.spotlight_app = spotlight.get_effective_package() or "None"

            # PID + paused state (cheap, cached — no ADB on the hot path).
            try:
                self.spotlight_pid = spotlight.get_pid()
            except Exception:
                self.spotlight_pid = None
            try:
                self.spotlight_paused = bool(spotlight.is_app_paused())
            except Exception:
                self.spotlight_paused = False
            try:
                self.spotlight_restarting = bool(spotlight.is_restarting())
            except Exception:
                self.spotlight_restarting = False

            # Hook count: running hook tasks bound to the spotlight package.
            # Mirrors SpotlightPanel._hooks_for_app — this is the HOOK count,
            # which is a different datum from the bypass-category list below.
            try:
                package = spotlight.get_effective_package()
            except Exception:
                package = None
            try:
                tasks = get_task_service().get_running_tasks()
                # The file monitor registers with the app's name too, but it
                # is not a Frida hook.
                self.hook_count = sum(
                    1
                    for t in tasks
                    if package
                    and getattr(t, "app_name", None) == package
                    and getattr(t, "name", None) != "monitor"
                )
            except Exception:
                self.hook_count = 0

        except Exception:
            pass

        self._read_bypass_state()

        # Update device info (separate try to ensure it always runs)
        # Use Toolbox.get_device_manager() to ensure auto-refresh on first access
        try:
            dm = Toolbox.get_device_manager()
            device = dm.active_device
            if device:
                self.active_device = device.short_name
                self.device_type = "\\[E]" if device.is_emulator else "\\[P]"
                # android_version / api_level are cached on the Device at
                # discovery (ro.build.version.*); root is a cached capability
                # flag — all cheap in-memory reads, no ADB on this path.
                self.device_android_version = (
                    getattr(device, "android_version", "") or ""
                )
                self.device_api_level = getattr(device, "api_level", 0) or 0
                try:
                    from sandroid.core.device import DeviceCapability

                    self.device_rooted = device.has_capability(
                        DeviceCapability.ADB_ROOT
                    )
                except Exception:
                    self.device_rooted = None
            else:
                self.active_device = ""
                self.device_type = ""
                self.device_android_version = ""
                self.device_api_level = 0
                self.device_rooted = None
        except Exception:
            pass

        # Update theme name from app (separate try to ensure it always runs)
        try:
            if hasattr(self.app, "sandroid_theme"):
                self.current_theme = self.app.sandroid_theme.display_name
        except Exception:
            pass

        # Update background tasks (separate try to ensure it always runs)
        try:
            running_tasks = get_task_service().get_running()
            self.background_tasks_count = len(running_tasks)
            if running_tasks:
                # Build display string with task names and PIDs
                # Use warning color for PIDs (consistent with filenames in menus)
                warn_color = fixed_color("warning_status")
                task_parts = []
                for task_name in running_tasks:
                    task = get_task_service().get_task(task_name)
                    if task:
                        if task.target_pid:
                            task_parts.append(
                                f"[{fixed_color('running')}]{task.display_name}[/]"
                                f" ([{warn_color}]{task.target_pid}[/])"
                            )
                        else:
                            task_parts.append(
                                f"[{fixed_color('running')}]{task.display_name}[/]"
                            )
                self.background_tasks_display = ", ".join(task_parts)
            else:
                self.background_tasks_display = ""
        except Exception:
            self.background_tasks_count = 0
            self.background_tasks_display = ""

        # Update forensic APKs count (separate try to ensure it always runs)
        try:
            forensic_apks = Toolbox.get_forensic_apks()
            self.forensic_apks_count = len(forensic_apks)
        except Exception:
            self.forensic_apks_count = 0

        # Update proxy status (separate try to ensure it always runs).
        # get_proxy_settings() does a synchronous ADB read (30s timeout);
        # skip it entirely when no device is active — a proxy can't be set on
        # an absent device, and on a just-disconnected device this would block
        # the UI thread when the status-bar refresh is marshaled here.
        try:
            from sandroid.core.proxy_manager import ProxyManager, ProxyStatus

            if self.active_device:
                status, config = ProxyManager().get_proxy_settings()
                if status == ProxyStatus.SET and config:
                    self.proxy_address = config.address
                elif status == ProxyStatus.NOT_SET:
                    self.proxy_address = ""
                # ERROR (unreadable, e.g. while system_server restarts after
                # ^N): keep the last known value -- "device ○" while the
                # caption said "device ✓" was a read failure, not a change.
            else:
                self.proxy_address = ""
        except Exception:
            self.proxy_address = ""

        # Mitmproxy service status + per-app proxy lanes. Cheap in-process
        # reads, factored out so the on_mount poll can keep them live without
        # re-running the ADB-backed checks above.
        self._read_capture_state()

        # Update network capture status (separate try to ensure it always runs)
        try:
            network_service = get_network_capture_service()
            self.network_capture_running = network_service.is_capturing()
            self.network_capture_file = network_service.get_capture_file() or ""
        except Exception:
            self.network_capture_running = False
            self.network_capture_file = ""

    def _read_capture_state(self) -> None:
        """Read mitmproxy + per-app proxy state from the singletons (no ADB).

        Only cheap in-process reads (process liveness + config + host IP +
        FocusManager's lane map), so this is safe to call on a short poll. The
        device's *actual* global proxy address is ADB-sourced and refreshed
        separately in update_from_toolbox.
        """
        try:
            from sandroid.core.proxy_manager import (
                get_focus_manager,
                resolve_proxy_host_ip,
            )
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            svc = get_mitmproxy_service()
            self.mitmweb_running = svc.is_running()
            port = getattr(svc.state, "proxy_port", "")
            # Emulator-aware (10.0.2.2 on an emulator), so the glance agrees with
            # the Mitmproxy panel on which device proxy is "ours" — NOT the raw
            # host LAN/VPN IP, which the device can't reach.
            self.mitmweb_address = f"{resolve_proxy_host_ip()}:{port}" if port else ""
            focus = get_focus_manager()
            routes = focus.app_proxies_nonblocking()
            if routes is not None:  # a reconcile holds the lock: keep the last
                self.app_proxies = dict(routes)
            health = focus.lane_health_nonblocking()
            if health is not None:
                problems: dict[str, int] = {}
                for lane in health.values():
                    if not lane.ok:
                        problems[lane.label] = problems.get(lane.label, 0) + 1
                self.app_proxy_problems = problems
        except Exception:
            self.mitmweb_running = False
            self.mitmweb_address = ""
            self.app_proxies = {}
            self.app_proxy_problems = {}

    def _read_bypass_state(self) -> None:
        """Bypass categories armed or active, in display order.

        In-process read, NOT the hook count (what toggle() acts on).
        """
        try:
            from sandroid.analysis.detection_bypass import get_bypass_service

            svc = get_bypass_service()
            on = set(svc.on_categories())
            self.bypass_categories = [c for c in svc.categories() if c in on]
        except Exception:
            self.bypass_categories = []

    def _on_bypass_state(self) -> None:
        """BypassService armed/active set changed (any thread, UI included).

        Never blocks the changing thread (it may hold a bypass lock): runs
        inline on the UI thread, else is posted to it.
        """
        self._ui.call(self._apply_bypass_state)

    def _pre_start_step(self) -> str | None:
        """The short text of a pre-start step running for the app, or None."""
        try:
            from sandroid.services.app_start import pre_start_status

            return pre_start_status(self.spotlight_app, short=True)
        except Exception:
            return None

    def _on_pre_start_status(self) -> None:
        """A pre-start step (identity apply) began or ended: repaint (any thread)."""
        self._ui.call(self.refresh)

    def _apply_bypass_state(self) -> None:
        before = list(self.bypass_categories)
        self._read_bypass_state()
        if self.bypass_categories != before:
            self.refresh()

    def _read_frida_starting(self) -> None:
        """Whether frida-server is being started (in-process, no ADB)."""
        try:
            from sandroid.core.frida_manager import frida_server_starting

            self.frida_starting = frida_server_starting()
        except Exception:
            self.frida_starting = False

    def _read_device_prep_stage(self) -> None:
        """Stage of a running device-prepared step (in-process, no ADB)."""
        try:
            from sandroid.core import device_prep

            running = device_prep.preparing_stage()
        except Exception:
            running = None
        self.device_prep_stage = running[1] if running else ""

    def _poll_capture_state(self) -> None:
        """Keep the Mitmproxy/Proxy glance rows live.

        The glance band has no other periodic refresh, so a mitmproxy
        start/stop would otherwise not show until some unrelated event
        repaints the bar. Repaints only when the cheap state actually
        changed, so an idle band does no work.
        """
        before = (
            self.mitmweb_running,
            self.mitmweb_address,
            tuple(sorted(self.app_proxies.items())),
            tuple(sorted(self.app_proxy_problems.items())),
            self.device_prep_stage,
            self.frida_starting,
        )
        was_starting = self.frida_starting
        self._read_capture_state()
        self._read_device_prep_stage()
        self._read_frida_starting()
        after = (
            self.mitmweb_running,
            self.mitmweb_address,
            tuple(sorted(self.app_proxies.items())),
            tuple(sorted(self.app_proxy_problems.items())),
            self.device_prep_stage,
            self.frida_starting,
        )
        if was_starting and not self.frida_starting:
            # The start ended: show running / off from a fresh check (again
            # after a check that was already running, it sampled too early).
            self._frida_recheck = True
            self._schedule_frida_check()
        if after != before:
            self.refresh()

    def set_device_proxy(self, address: str) -> None:
        """Set the device-proxy address shown in the glance directly.

        Called by whoever just changed the device's global ``http_proxy`` —
        the mitmproxy panel's Ctrl+D and the Proxy modal's Apply — so the
        glance reflects the new value the instant it is set, with no ADB
        re-read to lag behind or race. The glance "Device" line and the
        mitmproxy tab read the *same* ground truth, so they must never
        disagree; writing the just-set value here keeps them in lockstep.

        Args:
            address: The new proxy "ip:port", or "" when the proxy is cleared.
        """
        self.proxy_address = address
        self.refresh()

    def refresh_status(self) -> None:
        """Refresh all status bar information.

        Called when settings change (e.g., proxy configured).
        """
        self.update_from_toolbox()
        self.refresh()

    def _schedule_frida_check(self) -> None:
        """Schedule Frida status check in background thread.

        This avoids blocking the UI thread with ADB calls.
        The is_frida_server_running() method makes 3 sequential ADB shell
        commands which can take several hundred milliseconds.
        """
        # Avoid scheduling multiple checks
        if hasattr(self, "_frida_check_pending") and self._frida_check_pending:
            return
        self._frida_check_pending = True
        self._frida_recheck = False

        def _check_frida():
            """Background thread function to check Frida status."""
            try:
                frida_service = get_frida_session_service()
                frida_manager = frida_service.get_frida_manager()
                if frida_manager and frida_manager.is_frida_server_running():
                    status = "Running"
                else:
                    status = "Not running"
            except ImportError:
                status = "N/A"
            except (RuntimeError, Exception):
                # AndroidFridaManager throws RuntimeError on non-rooted devices
                status = "N/A"

            # Update UI from background thread safely (the check is done:
            # _update_frida_status may schedule the next one).
            self._frida_check_pending = False
            try:
                self.app.call_from_thread(self._update_frida_status, status)
            except Exception:
                pass  # App may have exited

        # Start background thread
        thread = threading.Thread(target=_check_frida, daemon=True)
        thread.start()

    def _update_frida_status(self, status: str) -> None:
        """Update Frida status from background thread result.

        Args:
            status: The Frida status string
        """
        prev_status = self._frida_last_status
        self._frida_last_status = status
        self.frida_status = status
        if status == "Running":
            self._frida_lost = None  # the server is back (Shift+R / auto-start)

        # Check version mismatch only on transition to Running
        if status == "Running" and prev_status != "Running":
            self._frida_version_mismatch = None  # Reset until checked
            self._schedule_frida_version_check()
        elif status != "Running":
            self._frida_version_mismatch = None

        self.refresh()
        if getattr(self, "_frida_recheck", False):
            self._schedule_frida_check()

    def _schedule_frida_version_check(self) -> None:
        """Check frida-server version against host frida in background."""

        def _check_version():
            try:
                import frida as _frida_mod

                host_version = _frida_mod.__version__
                stdout, _stderr = Adb.send_adb_command(
                    "shell /data/local/tmp/frida-server --version"
                )
                if stdout and stdout.strip():
                    server_version = stdout.strip()
                    mismatch = server_version != host_version
                else:
                    mismatch = False  # Can't determine, assume OK
            except Exception:
                mismatch = False  # Can't determine, assume OK

            try:
                self.app.call_from_thread(self._apply_version_mismatch, mismatch)
            except Exception:
                pass

        thread = threading.Thread(target=_check_version, daemon=True)
        thread.start()

    def _apply_version_mismatch(self, mismatch: bool) -> None:
        """Apply version mismatch result from background thread."""
        self._frida_version_mismatch = mismatch
        self.refresh()
