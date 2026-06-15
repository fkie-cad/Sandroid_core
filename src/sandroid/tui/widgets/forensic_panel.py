"""TUI panel that runs the MVT-style forensic IOC scan inside a dedicated tab.

The Forensic tab lives in the permanent tool area next to Snapshots and is
**only visible when a physical device is connected** (MainScreen gates the tab's
visibility on ``DeviceManager.is_physical_device()``). Forensic analysis on an
emulator is meaningless, so the whole surface is hidden there.

Like :class:`SnapshotsPanel`, this panel is **thin** and delegates the real work
to existing pieces — it owns no scan engine. The single orchestration point is
``ForensicController`` (``app._forensic_controller``):

    Enter   run the scan (configure first if no IOCs are loaded yet)
    Ctrl+X  request cancellation of the running scan (best-effort)
    c       configure / switch the IOC source (reuses IOCChoice/IOCSetup modals)
    v       open the detailed results modal (MVTResultsModal: scroll + APK pull)
    p / s   pull all / select matched APKs (reuses the Shift+F APK pipeline)
    Ctrl+O  open the forensic results folder in the OS file manager
    Ctrl+L  clear the in-tab record

Layout (rich forensic view, modeled on SnapshotsPanel's header/list/actions):
    #forensic-header   one/two status lines (state · device · IOC source · summary)
    #forensic-stages   per-stage progress block (APPS/SMS/CALLS/FILES); hidden idle
    #forensic-results  persistent, severity-sorted OptionList of IOC matches
    #forensic-actions  clickable action row with key hints

Thread-safety: the scan runs on a worker thread (owned by the controller). The
controller marshals progress/completion onto the Textual main thread via
``App.call_from_thread`` before invoking this panel's ``on_*`` sinks, so those
sinks may touch widgets directly. The off-thread IOC-status probe uses the
``loop.call_soon_threadsafe`` idiom (``_post``) to update the header.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import OptionList, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# Ordered scan stages. Strategies emit ScanProgress.scan_type == ScanType.name,
# so these strings match the live progress callbacks 1:1.
_STAGES = ("APPS", "SMS", "CALLS", "FILES")

# Clickable action-cell id -> panel action method (routed from MainScreen.on_click).
_ACTION_CELLS = {
    "forensic-run": "action_run",
    "forensic-cancel": "action_cancel",
    "forensic-configure": "action_configure",
    "forensic-details": "action_view_results",
    "forensic-pull": "action_pull_all",
    "forensic-open": "action_open_output",
    "forensic-clear": "action_clear",
}

# Severity → display, by MatchSeverity.value (avoids importing the enum here).
_SEV_COLOR = {
    "critical": "#ff0000",
    "high": "#ff6600",
    "medium": "#ffcc00",
    "low": "#5b6479",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ForensicPanel(Widget):
    """Forensic tab: run an MVT-style IOC scan on a physical device in-tab.

    Stateless re: lifecycle in the sense that it owns no scan engine — the
    authoritative scan state lives in ``ForensicController._scan_in_progress``
    and the ``ForensicEvidence`` singleton. The panel keeps only transient
    display state (last results, per-stage status, IOC summary) needed to
    render the header / stages / results list.
    """

    can_focus = True

    DEFAULT_CSS = """
    ForensicPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    ForensicPanel > #forensic-header {
        height: auto;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    ForensicPanel > #forensic-stages {
        height: auto;
        background: #060a14;
        padding: 0 1;
    }
    ForensicPanel > #forensic-results {
        height: 1fr;
        background: #050811;
        padding: 0 1;
        border: none;
    }
    ForensicPanel > #forensic-actions {
        height: 1;
        dock: bottom;
        background: #0b1628;
    }
    ForensicPanel .act-cell {
        width: auto;
        padding: 0 1;
        color: #93a4c3;
    }
    ForensicPanel .act-cell:hover {
        background: #1f2937;
        color: #7dd3fc;
        text-style: bold;
    }
    """

    BINDINGS = [
        ("enter", "run", "Run scan"),
        ("r", "run", "Run scan"),
        ("ctrl+x", "cancel", "Cancel"),
        ("c", "configure", "Configure IOCs"),
        ("v", "view_results", "View results"),
        ("p", "pull_all", "Pull APKs"),
        ("s", "pull_all", "Pull APKs"),
        ("ctrl+o", "open_output", "Open results"),
        ("ctrl+l", "clear", "Clear"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._main_loop = None
        self._event_handlers: list = []
        # Transient display state.
        self._results: list = []  # list[ScanResult] from the last scan
        self._stages: dict[str, dict] = {}
        self._reset_stage_state()
        self._scan_started = False
        self._cancelled = False
        self._active_stage: str | None = None
        self._last_scan: dict | None = None  # {when, items, duration}
        self._ioc_info: dict | None = None  # {configured, indicator_count, file_count}

    def _reset_stage_state(self) -> None:
        self._stages = {
            name: {"state": "pending", "current": 0, "total": 0, "item": "", "matches": None}
            for name in _STAGES
        }
        self._active_stage = None

    # -- lazy facades -----------------------------------------------------

    @staticmethod
    def _toolbox():
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _controller(self):
        """The app's shared ForensicController, or None if not ready."""
        return getattr(self.app, "_forensic_controller", None)

    def _physical_available(self) -> bool:
        try:
            return bool(self._toolbox().is_physical_device())
        except Exception:
            return False

    def _device_name(self) -> str:
        try:
            device = self._toolbox().get_active_device()
        except Exception:
            device = None
        if device is None:
            return "device"
        for attr in ("short_name", "name", "model"):
            value = getattr(device, attr, None)
            if value:
                return str(value)
        return str(getattr(device, "serial", "device"))

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="forensic-header")
        yield Static(self._render_stages(), id="forensic-stages")
        yield OptionList(id="forensic-results")
        with Horizontal(id="forensic-actions"):
            yield Static("r run", id="forensic-run", classes="act-cell")
            yield Static("ctrl+x cancel", id="forensic-cancel", classes="act-cell")
            yield Static("c configure", id="forensic-configure", classes="act-cell")
            yield Static("v / enter details", id="forensic-details", classes="act-cell")
            yield Static("p pull APKs", id="forensic-pull", classes="act-cell")
            yield Static("ctrl+o open", id="forensic-open", classes="act-cell")
            yield Static("ctrl+l clear", id="forensic-clear", classes="act-cell")

    def on_mount(self) -> None:
        self._subscribe_events()
        self._rebuild_results()
        # IOC status touches the filesystem (counts ~22k indicators) — never on
        # the UI thread; refresh the header once the worker reports back.
        self._refresh_ioc_status()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    # -- focus forwarding -------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the results list so up/down navigation works."""
        try:
            self.query_one("#forensic-results", OptionList).focus(scroll_visible)
        except Exception:
            super().focus(scroll_visible)
        return self

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------

    def _subscribe_events(self) -> None:
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            try:
                self._main_loop = asyncio.get_running_loop()
            except RuntimeError:
                self._main_loop = None

            bus = EventBus.get()

            def _make_cb():
                def _cb(_event) -> None:
                    # Device/state changes can flip the device name in the header;
                    # re-render it (cheap, reuses cached IOC info). The IOC source
                    # only changes via the configure flow, so we do NOT re-probe
                    # (re-parse) IOCs here — that would reload on every task event.
                    self._post(self.refresh_header)

                return _cb

            for event_type in (
                EventType.STATE_CHANGED,
                EventType.TASK_STARTED,
                EventType.TASK_STOPPED,
            ):
                cb = _make_cb()
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"ForensicPanel event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    # -- thread marshalling ----------------------------------------------

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread (fire-and-forget)."""
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        loop = self._main_loop
        try:
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            pass

    # -- IOC status probe (off the UI thread) -----------------------------

    def _refresh_ioc_status(self) -> None:
        """Probe IOC configuration/counts off-thread, then refresh the header.

        Skipped while a scan is running: the probe loads/parses the IOC source
        into the shared ``ForensicEvidence`` singleton, which must not race the
        in-flight scan's loader.
        """
        if self._scan_in_progress():
            return
        self.run_worker(
            self._ioc_status_worker,
            name="forensic_ioc_status",
            exclusive=False,
            thread=True,
        )

    def _ioc_status_worker(self) -> None:
        """Compute the header's IOC summary for the CONFIGURED source.

        The header must reflect the IOC source the scan will actually use — i.e.
        ``config.mvt.ioc_path`` loaded via ``ForensicEvidence`` — not the MVT
        cache pool. (Previously it always showed the cache's counts, so picking a
        small custom file like ``ground_truth_ioc.stix2`` appeared to do nothing.)
        The cache pool is surfaced only as a hint when nothing is configured yet.
        """
        info = {
            "configured": False,
            "indicator_count": 0,
            "file_count": 0,
            "source_label": None,
        }
        try:
            from sandroid.core.forensic_evidence import ForensicEvidence

            fe = ForensicEvidence.get()
            if fe.is_configured():
                info["configured"] = True
                path = fe.get_ioc_path()
                if fe.load_iocs():
                    info["indicator_count"] = fe.total_indicators
                info["file_count"], info["source_label"] = self._ioc_source_summary(
                    path
                )
        except Exception as exc:
            logger.debug(f"Configured IOC probe failed: {exc}")

        if not info["configured"]:
            # Nothing configured yet — surface any cached MVT pool as a hint.
            try:
                controller = self._controller()
                cached = controller.has_cached_iocs() if controller else None
                if cached:
                    info["indicator_count"] = int(cached.get("indicator_count") or 0)
                    info["file_count"] = int(cached.get("file_count") or 0)
            except Exception as exc:
                logger.debug(f"Cached IOC probe failed: {exc}")

        self._ioc_info = info
        self._post(self.refresh_header)

    @staticmethod
    def _ioc_source_summary(path) -> tuple[int, str | None]:
        """(file_count, label) for a configured IOC path (a file or a directory)."""
        if path is None:
            return 0, None
        try:
            p = Path(path)
            if p.is_file():
                return 1, p.name
            if p.is_dir():
                files = list(p.glob("*.json")) + list(p.glob("*.stix2"))
                return len(files), f"{len(files)} files"
        except OSError:
            pass
        return 0, None

    def _iocs_ready(self) -> bool:
        try:
            from sandroid.core.forensic_evidence import ForensicEvidence

            return bool(ForensicEvidence.get().is_configured())
        except Exception:
            return False

    # -- rendering --------------------------------------------------------

    def _render_header(self) -> str:
        if not self._physical_available():
            return "[#fb7185]○ Forensic scan requires a physical device[/]"

        # State dot.
        running = self._scan_in_progress()
        if running:
            stage = self._active_stage or "…"
            cur = self._stages.get(stage, {}).get("current", 0)
            tot = self._stages.get(stage, {}).get("total", 0)
            count = f" {cur}/{tot}" if tot else ""
            state = f"[#4ade80]● scanning {stage}{count}[/]"
        elif self._cancelled:
            state = "[#facc15]○ cancelled[/]"
        elif self._results:
            total = sum(len(r.matches) for r in self._results)
            state = (
                f"[#fb7185]⚠ {total} matches[/]"
                if total
                else "[#4ade80]✓ complete[/]"
            )
        else:
            state = "[#5b6479]○ idle[/]"

        device = f"[#93a4c3]physical · {self._device_name()}[/]"
        ioc = self._render_ioc_status()
        line1 = f"{state}   {device}   {ioc}"

        line2 = self._render_summary()
        return f"{line1}\n{line2}" if line2 else line1

    def _render_ioc_status(self) -> str:
        info = self._ioc_info
        if info is None:
            return "[#5b6479]IOC …[/]"
        indicators = info.get("indicator_count", 0)
        if info.get("configured"):
            # Show the configured source (count + file/dir name) so the analyst
            # can confirm THEIR IOC file is loaded — not the MVT cache pool.
            label = info.get("source_label")
            parts = [f"{indicators:,} indicators"] if indicators else []
            if label:
                parts.append(label)
            detail = " · ".join(parts) if parts else "ready"
            return f"[#4ade80]IOC ✓ {detail}[/]"
        if indicators:
            return f"[#facc15]IOC ○ {indicators:,} cached — press c[/]"
        return "[#facc15]IOC ○ not configured — press c[/]"

    def _render_summary(self) -> str:
        """Second header line: last-scan stats + severity badge (after a scan)."""
        if not self._last_scan or self._scan_in_progress():
            return ""
        when = self._last_scan.get("when", "")
        items = self._last_scan.get("items", 0)
        dur = self._last_scan.get("duration", 0.0)
        head = f"[#5b6479]last scan {when} · {items} items · {dur:.1f}s[/]"
        crit = sum(len(r.critical_matches) for r in self._results)
        high = sum(len(r.high_matches) for r in self._results)
        total = sum(len(r.matches) for r in self._results)
        med_low = total - crit - high
        if total == 0:
            return f"{head}   [#4ade80]✓ clean[/]"
        badge = []
        if crit:
            badge.append(f"[#ff0000]{crit} CRIT[/]")
        if high:
            badge.append(f"[#ff6600]{high} HIGH[/]")
        if med_low:
            badge.append(f"[#ffcc00]{med_low} MED/LOW[/]")
        return f"{head}   ⚠ {'  '.join(badge)}"

    @staticmethod
    def _bar(current: int, total: int, cells: int = 16) -> str:
        pct = (current / total) if total else 0.0
        filled = max(0, min(cells, int(pct * cells)))
        return "█" * filled + "░" * (cells - filled)

    def _render_stages(self) -> str:
        if not self._scan_started:
            return ""
        lines = []
        for name in _STAGES:
            st = self._stages[name]
            label = f"{name:<6}"
            state = st["state"]
            if state == "pending":
                lines.append(f"[#5b6479]{label} pending[/]")
            elif state == "active":
                bar = self._bar(st["current"], st["total"])
                item = st["item"] or ""
                if len(item) > 28:
                    item = item[:27] + "…"
                lines.append(
                    f"[#7dd3fc]{label}[/] {bar} "
                    f"[#93a4c3]{st['current']}/{st['total']}[/]  [#5b6479]{item}[/]"
                )
            else:  # done
                matches = st["matches"]
                if matches is None:
                    tail = "[#5b6479]done[/]"
                elif matches:
                    tail = f"[#4ade80]done ✓[/]  [#fb7185]{matches} matches[/]"
                else:
                    tail = "[#4ade80]done ✓[/]  [#5b6479]0 matches[/]"
                lines.append(f"[#7dd3fc]{label}[/] {tail}")
        return "\n".join(lines)

    def _match_label(self, match, stage: str) -> str:
        sev = getattr(match.severity, "value", "medium")
        color = _SEV_COLOR.get(sev, "#5b6479")
        bold = "bold " if sev in ("critical", "high") else ""
        value = match.indicator_value or ""
        if len(value) > 36:
            value = value[:35] + "…"
        matched = match.matched_data or ""
        if len(matched) > 36:
            matched = matched[:35] + "…"
        return (
            f"[{bold}{color}][{sev.upper()}][/] "
            f"[b]{match.indicator_type}[/]  {value} → {matched}  "
            f"[#5b6479]({stage})[/]"
        )

    def _sorted_matches(self) -> list[tuple]:
        pairs = []
        for result in self._results:
            stage = getattr(result.scan_type, "name", str(result.scan_type))
            for match in result.matches:
                pairs.append((match, stage))
        pairs.sort(key=lambda p: _SEV_RANK.get(getattr(p[0].severity, "value", ""), 99))
        return pairs

    def _rebuild_results(self) -> None:
        try:
            option_list = self.query_one("#forensic-results", OptionList)
        except Exception:
            return
        try:
            option_list.clear_options()
            if not self._physical_available():
                option_list.add_option(
                    "[#5b6479]Forensic scan requires a physical device[/]"
                )
                return
            matches = self._sorted_matches()
            if matches:
                for match, stage in matches:
                    option_list.add_option(self._match_label(match, stage))
            elif self._scan_in_progress():
                option_list.add_option("[#5b6479]scanning…[/]")
            elif self._results:
                option_list.add_option(
                    "[#4ade80]✓ no indicators of compromise found[/]"
                )
            else:
                option_list.add_option(
                    "[#5b6479]no scan yet — press enter to run · c to configure[/]"
                )
            # Pre-highlight the first row so Enter (which OptionList turns into
            # an OptionSelected message) always has a target — otherwise Enter
            # on a freshly-built list is a no-op until the user navigates.
            try:
                option_list.highlighted = 0
            except Exception:
                pass
        except Exception as exc:
            logger.debug(f"ForensicPanel rebuild failed: {exc}")

    def on_option_list_option_selected(self, event) -> None:
        """Context action for Enter / click on the results list.

        Focus is forwarded to ``#forensic-results`` and ``OptionList`` binds
        Enter to emit this message, so the panel-level ``enter`` binding never
        fires while the list is focused. Make Enter mean the obvious thing for
        what is on screen: with results, open the detailed view (where matched
        APKs can be pulled) — pressing Enter on a finding must NOT wipe it by
        re-scanning; with no results yet, start the scan. Re-running is ``r``.
        """
        event.stop()
        if not self._physical_available() or self._scan_in_progress():
            return
        if self._results:
            self.action_view_results()
        else:
            self.action_run()

    def refresh_header(self) -> None:
        """Re-render the status header + stages block (main thread; best-effort).

        Public so ``MainScreen._select_bottom_tab`` refreshes it the moment the
        Forensic tab is activated, avoiding a stale header.
        """
        try:
            self.query_one("#forensic-header", Static).update(self._render_header())
        except Exception:
            pass
        try:
            self.query_one("#forensic-stages", Static).update(self._render_stages())
        except Exception:
            pass

    # -- scan progress sinks (called on main thread via call_from_thread) --

    def _scan_in_progress(self) -> bool:
        controller = self._controller()
        try:
            return bool(controller.is_scan_in_progress()) if controller else False
        except Exception:
            return False

    def on_scan_started(self) -> None:
        self._scan_started = True
        self._cancelled = False
        self._results = []
        self._last_scan = None
        self._reset_stage_state()
        self.refresh_header()
        self._rebuild_results()

    def on_progress(self, progress) -> None:
        """Live per-item progress for the active stage (main thread)."""
        stage = getattr(progress, "scan_type", None)
        if stage not in self._stages:
            return
        # A new active stage means the previous one finished (match count is
        # filled in at completion, when the full ScanResult list is available).
        if self._active_stage and self._active_stage != stage:
            prev = self._stages[self._active_stage]
            if prev["state"] != "done":
                prev["state"] = "done"
        self._active_stage = stage
        st = self._stages[stage]
        st["state"] = "active"
        st["current"] = getattr(progress, "current", 0)
        st["total"] = getattr(progress, "total", 0)
        st["item"] = getattr(progress, "item", "") or ""
        self.refresh_header()

    def on_scan_complete(self, results, cancelled: bool) -> None:
        """Final results for the stages that completed (main thread)."""
        self._results = list(results or [])
        self._cancelled = bool(cancelled)
        # Finalize each completed stage with its true match count.
        done_stages = set()
        for result in self._results:
            name = getattr(result.scan_type, "name", str(result.scan_type))
            if name in self._stages:
                self._stages[name]["state"] = "done"
                self._stages[name]["matches"] = len(result.matches)
                done_stages.add(name)
        if cancelled:
            # The stage running when aborted (and any not-yet-started ones) never
            # finished — don't leave a frozen progress bar; show them as stopped.
            for name, st in self._stages.items():
                if name not in done_stages and st["state"] == "active":
                    st["state"] = "done"
                    st["matches"] = None
        items = sum(getattr(r, "scanned_items", 0) for r in self._results)
        duration = sum(getattr(r, "scan_duration", 0.0) for r in self._results)
        self._last_scan = {
            "when": time.strftime("%H:%M"),
            "items": items,
            "duration": duration,
        }
        self.refresh_header()
        self._rebuild_results()
        total = sum(len(r.matches) for r in self._results)
        if cancelled:
            msg = "Forensic scan cancelled."
            if total:
                msg += (
                    f" Kept {total} match(es) from completed stages — "
                    f"press v for details / p to pull APKs."
                )
            self._notify(msg, "warning")
        elif total:
            self._notify(
                f"Forensic scan complete: {total} IOC match(es) — "
                f"press v for details / p to pull APKs.",
                "warning",
            )
        else:
            self._notify(
                "Forensic scan complete: no indicators of compromise found.",
                "information",
            )

    def on_scan_error(self, message: str) -> None:
        self._scan_started = False
        self.refresh_header()
        self._rebuild_results()
        self._notify(f"Forensic scan failed: {message}", "error")

    # -- actions (main-thread entry points) -------------------------------

    def action_run(self) -> None:
        """Enter — run the scan (configuring the IOC source first if needed)."""
        if not self._physical_available():
            self._notify("Forensic scan requires a physical device.", "warning")
            return
        if self._scan_in_progress():
            self._notify("A forensic scan is already in progress.", "warning")
            return
        if not self._iocs_ready():
            # No usable IOC source yet — configure first, then start the scan.
            self.action_configure(then_run=True)
            return
        self._start_scan()

    def _start_scan(self) -> None:
        controller = self._controller()
        if controller is None:
            self._notify("Forensic controller unavailable.", "error")
            return
        self.on_scan_started()
        started = controller.run_forensic_scan_inline(
            run_worker=self.app.run_worker,
            call_from_thread=self.app.call_from_thread,
            on_progress=self.on_progress,
            on_complete=self.on_scan_complete,
            on_error=self.on_scan_error,
        )
        if not started:
            self._scan_started = False
            self.refresh_header()
            self._rebuild_results()

    def action_cancel(self) -> None:
        if not self._scan_in_progress():
            return
        controller = self._controller()
        if controller is not None:
            controller.cancel_scan()
        self._notify("Cancelling forensic scan…", "warning")

    def action_configure(self, then_run: bool = False) -> None:
        """Configure / switch the IOC source (``c`` key; reuses the IOC modals)."""
        controller = self._controller()
        if controller is None:
            self._notify("Forensic controller unavailable.", "error")
            return

        def on_done() -> None:
            self._refresh_ioc_status()
            self.refresh_header()
            if then_run:
                self._start_scan()

        controller.configure_iocs_only(
            push_modal=self.app.push_screen,
            on_done=on_done,
        )

    def action_view_results(self) -> None:
        """Open the detailed results modal (``v`` key; scroll + APK pull)."""
        if not self._results:
            self._notify("Run a scan first.", "information")
            return
        from sandroid.tui.modals import MVTResultsModal

        def on_result(result) -> None:
            if result is None or getattr(result, "action", "close") == "close":
                return
            try:
                self.app._handle_mvt_result(result)
            except Exception as exc:
                logger.warning(f"MVT result handling failed: {exc}")

        self.app.push_screen(MVTResultsModal(results=self._results), on_result)

    def action_pull_all(self) -> None:
        """Pull matched APKs via the shared forensic APK pipeline (``p`` / ``s``)."""
        if not self._results:
            self._notify("Run a scan first.", "information")
            return
        action = self._build_apk_action("pull_all")
        if not action.matched_packages:
            self._notify("No matched APKs to pull.", "information")
            return
        try:
            self.app._handle_mvt_result(action)
        except Exception as exc:
            logger.warning(f"APK pull failed: {exc}")
            self._notify(f"APK pull failed: {exc}", "error")

    def _build_apk_action(self, action: str):
        """Build an MVTResultsAction from the current results.

        Uses the shared core extractor, so quick-pull from the tab pulls the
        same packages the detailed modal would — including ones found only by an
        APK hash match.
        """
        from sandroid.core.forensic_evidence import extract_matched_packages
        from sandroid.tui.modals import MVTResultsAction

        packages, by_package = extract_matched_packages(self._results)
        return MVTResultsAction(
            action=action,
            matched_packages=packages,
            matches_by_package=by_package,
        )

    def action_clear(self) -> None:
        if self._scan_in_progress():
            self._notify("Cannot clear while a scan is running.", "warning")
            return
        self._results = []
        self._last_scan = None
        self._scan_started = False
        self._cancelled = False
        self._reset_stage_state()
        self.refresh_header()
        self._rebuild_results()

    def action_open_output(self) -> None:
        """Ctrl+O — open the forensic results folder in the OS file manager."""
        folder = self._output_folder()
        if folder is None or not folder.exists():
            self._notify(
                "Forensic results folder not found yet — run a scan first.",
                "warning",
            )
            return
        self._open_folder(folder)

    def dispatch_action_cell(self, wid: str) -> None:
        """Run the action bound to a clicked action cell (from MainScreen)."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    # -- helpers ----------------------------------------------------------

    def _output_folder(self) -> Path | None:
        """Resolve the device results folder (where forensic output lands)."""
        try:
            from sandroid.services import get_initialization_service

            device_path = get_initialization_service().get_device_path()
            if device_path:
                return Path(device_path)
        except Exception:
            pass
        return None

    def _open_folder(self, target: Path) -> None:
        """Open ``target`` in the OS file manager (mirrors FriTapPanel)."""
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            elif sys.platform.startswith("win"):
                os.startfile(str(target))  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", str(target)])
            else:
                webbrowser.open(Path(target).as_uri())
        except Exception as exc:
            logger.warning("Failed to open forensic output folder %s: %s", target, exc)

    def _notify(self, message: str, severity: str = "information") -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass
