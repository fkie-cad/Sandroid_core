"""TUI panel for listing / creating / loading / deleting AVD snapshots.

The Snapshots tab lives in the permanent tool area alongside the
spotlight and mitmproxy panels. It surfaces the AVD's saved snapshots and
offers the four lifecycle actions (Create / Load / Delete / Refresh).

It is intentionally **stateless** in the same spirit as :class:`SpotlightPanel`:
it owns no manager instances and reads everything live from the process-wide
services (via the static ``Toolbox``/``Adb`` facades). Textual recreates
widgets on screen change, so keeping authoritative state here would be wrong —
the device/emulator is the single source of truth.

All blocking work (telnet ``list``, ``save``, ``load`` — ``load`` sleeps 2s in
the service layer) runs on worker threads; UI updates are always marshalled
back to the Textual main thread.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import ContentSwitcher, OptionList, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# Clickable action-cell id -> panel action method. Routed from
# MainScreen.on_click (same dispatch as the bottom tab bar / arrow).
_ACTION_CELLS = {
    "snap-create": "action_create",
    "snap-load": "action_load",
    "snap-delete": "action_delete",
    "snap-assign": "action_assign",
    "snap-refresh": "action_refresh",
}

# How often the slow fallback poll re-checks the snapshot list (seconds).
# Telnet ``list`` is slow, so this stays lazy: each tick is a no-op unless this
# panel is the active tool-body ContentSwitcher child.
_POLL_INTERVAL = 9.0


class SnapshotsPanel(Widget):
    """Bottom-strip panel: AVD snapshot list + create/load/delete actions.

    Bindings (when focused):
        c: create a snapshot (prompts for a name; blank = timestamp)
        l: load the highlighted snapshot (current state is lost)
        d: delete the highlighted snapshot (irreversible)
        a: assign the highlighted snapshot to a slot (1-8)
        r: refresh the list

    The keys are deliberately **lowercase**. App-level priority bindings fire
    App-first regardless of focus (e.g. ``D`` opens the device selector), so an
    uppercase ``D`` here would be dead. Lowercase c/l/d/r map to non-priority
    app bindings, and a focused descendant's ancestor (this panel) wins the
    non-priority pass — so these shadow the globals only while the snapshots
    panel is focused. ``OptionList`` binds only navigation keys (up/down/enter/
    home/end/pageup/pagedown), so the letter keys never clash with it nor with
    ``_ToolPanel``'s Left/Right tab cycling. The action row is also clickable.
    """

    can_focus = True

    DEFAULT_CSS = """
    SnapshotsPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    SnapshotsPanel > #snapshots-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    SnapshotsPanel > #snapshots-list {
        height: 1fr;
        background: #050811;
        padding: 0 1;
        border: none;
    }
    SnapshotsPanel > #snapshots-slots {
        height: auto;
        background: #060a14;
        padding: 0 1;
        border-top: solid #1f2937;
    }
    SnapshotsPanel > #snapshots-actions {
        height: 1;
        dock: bottom;
        background: #0b1628;
    }
    SnapshotsPanel .act-cell {
        width: auto;
        padding: 0 1;
        color: #93a4c3;
    }
    SnapshotsPanel .act-cell:hover {
        background: #1f2937;
        color: #7dd3fc;
        text-style: bold;
    }
    """

    BINDINGS = [
        ("c", "create", "Create"),
        ("l", "load", "Load"),
        ("d", "delete", "Delete"),
        ("a", "assign", "Assign slot"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        # Slow fallback poll bookkeeping.
        self._poll_timer = None
        self._poll_inflight = False
        # Guard against overlapping blocking actions (create/load/delete) and
        # against stacking refresh fetches.
        self._action_inflight = False
        self._refresh_inflight = False
        # Newest-first list of snapshot dicts ({id,tag,size,date,clock}).
        self._snapshots: list[dict] = []

    # -- services (lazy) --------------------------------------------------

    @staticmethod
    def _toolbox():
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    @staticmethod
    def _adb():
        from sandroid.core.adb import Adb

        return Adb

    # -- emulator gate (None-safe) ----------------------------------------

    def _emulator_available(self) -> bool:
        """True if the active device supports AVD snapshots."""
        try:
            from sandroid.core.device import DeviceCapability

            return bool(
                self._toolbox().check_device_capability(DeviceCapability.SNAPSHOTS)
            )
        except Exception:
            return False

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id="snapshots-header")
        yield OptionList(id="snapshots-list")
        yield Static(self._render_slots(), id="snapshots-slots")
        with Horizontal(id="snapshots-actions"):
            yield Static("c create", id="snap-create", classes="act-cell")
            yield Static("l load", id="snap-load", classes="act-cell")
            yield Static("d delete", id="snap-delete", classes="act-cell")
            yield Static("a slot", id="snap-assign", classes="act-cell")
            yield Static("r refresh", id="snap-refresh", classes="act-cell")

    def on_mount(self) -> None:
        self._subscribe_events()
        # Only fetch if the tab is already on screen — the slow telnet ``list``
        # must not run for a hidden tab. When the user opens the tab,
        # MainScreen._select_bottom_tab triggers refresh_snapshots() directly.
        self._refresh_if_visible()
        # Event-driven refresh (STATE_CHANGED) covers most cases; this slow
        # poll is the safety net. Stopped in on_unmount; each tick is a no-op
        # unless this panel is the active tool-body child.
        self._poll_timer = self.set_interval(_POLL_INTERVAL, self._poll)

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        if self._poll_timer is not None:
            try:
                self._poll_timer.stop()
            except Exception:
                pass
            self._poll_timer = None

    # -- focus forwarding -------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the OptionList so row navigation works.

        ``MainScreen._select_bottom_tab`` focuses ``#snapshots-panel`` (this
        container), but up/down/enter row navigation needs the OptionList
        focused. Forward focus there, falling back to the container.
        """
        try:
            self.query_one("#snapshots-list", OptionList).focus(scroll_visible)
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
                    # Fire-and-forget onto the main loop; never blocks the
                    # publisher's thread (avoids the call_from_thread deadlock).
                    loop = self._main_loop
                    try:
                        if loop is not None and not loop.is_closed():
                            # Visibility-gated: a state change must not fire the
                            # slow telnet ``list`` while the tab is hidden.
                            loop.call_soon_threadsafe(self._refresh_if_visible)
                    except RuntimeError:
                        pass

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
            logger.debug(f"SnapshotsPanel event subscribe failed: {exc}")

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
        """Run ``fn(*args)`` on the Textual main thread (fire-and-forget).

        Safe to call from worker threads. Used for list rebuild + notify so we
        never touch widgets off the main thread.
        """
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        loop = self._main_loop
        try:
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            pass

    # -- rendering --------------------------------------------------------

    def _avd_name(self) -> str:
        """Best-effort AVD/emulator name without an extra telnet call."""
        try:
            device = self._toolbox().get_active_device()
        except Exception:
            device = None
        if device is None:
            return "Emulator"
        for attr in ("short_name", "name"):
            try:
                value = getattr(device, attr, None)
            except Exception:
                value = None
            if value:
                return str(value)
        return "Emulator"

    def _render_header(self) -> str:
        if not self._emulator_available():
            return "[#fb7185]○ Snapshots require a running emulator[/]"
        count = len(self._snapshots)
        return f"[b]{self._avd_name()}[/] — {count} snapshot(s)"

    def _render_slots(self) -> str:
        """Render the slot memory (all 8 slots; empties shown), 2 per line.

        Pads on plain text and colours after, since Rich markup has no width.
        """
        if not self._emulator_available():
            return ""
        slot_map = self._slot_map()
        cells: list[tuple[str, str]] = []  # (plain, markup) per slot
        for i in range(1, 9):
            tag = slot_map.get(str(i))
            if tag:
                disp = tag if len(tag) <= 18 else tag[:17] + "…"
                cells.append((f"[{i}] {disp}", f"[b #fbbf24]\\[{i}][/] {disp}"))
            else:
                cells.append((f"[{i}] (empty)", f"[#5b6479]\\[{i}] (empty)[/]"))
        width = max((len(p) for p, _ in cells), default=0) + 3
        lines = ["[dim]Snapshot memory (slots)[/]"]
        for row in range(0, 8, 2):
            left_plain, left = cells[row]
            right = cells[row + 1][1]
            pad = " " * max(3, width - len(left_plain))
            lines.append(f"{left}{pad}{right}")
        return "\n".join(lines)

    def _option_label(self, snap: dict) -> str:
        """Single-row label: ``[slot] date · size · tag`` (slot if assigned)."""
        date = snap.get("date") or "—"
        size = snap.get("size") or "—"
        tag = snap.get("tag") or snap.get("id") or "—"
        slot = self._reverse_slot_map().get(tag)
        prefix = f"[b #fbbf24]\\[{slot}][/] " if slot else ""
        return f"{prefix}{date}  ·  {size}  ·  [b]{tag}[/]"

    def _rebuild_list(self) -> None:
        """Rebuild the OptionList + header + slot memory on the main thread."""
        try:
            header = self.query_one("#snapshots-header", Static)
            header.update(self._render_header())
        except Exception:
            pass
        try:
            self.query_one("#snapshots-slots", Static).update(self._render_slots())
        except Exception:
            pass
        try:
            option_list = self.query_one("#snapshots-list", OptionList)
        except Exception:
            return
        try:
            option_list.clear_options()
            if not self._emulator_available():
                option_list.add_option("Snapshots require a running emulator")
                return
            if not self._snapshots:
                option_list.add_option("[#5b6479]no snapshots — press c to create[/]")
                return
            for snap in self._snapshots:
                option_list.add_option(self._option_label(snap))
            # Pre-select the newest row: OptionList leaves ``highlighted`` None
            # until the user navigates, which would make Load/Delete report "no
            # selection" on a freshly-opened tab. Default to the first (newest).
            try:
                option_list.highlighted = 0
            except Exception:
                pass
        except Exception as exc:
            logger.debug(f"SnapshotsPanel rebuild failed: {exc}")

    def _highlighted_tag(self) -> str | None:
        """Tag of the currently highlighted snapshot, or None."""
        if not self._snapshots:
            return None
        try:
            option_list = self.query_one("#snapshots-list", OptionList)
            idx = option_list.highlighted
        except Exception:
            return None
        if idx is None or idx < 0 or idx >= len(self._snapshots):
            return None
        snap = self._snapshots[idx]
        return snap.get("tag") or snap.get("id") or None

    # -- slot memory (per-AVD; persisted in tui.snapshot_slots) ------------

    def _config(self):
        """The live app config, or None before the app is ready."""
        return getattr(self.app, "sandroid_config", None)

    def _slot_map(self) -> dict[str, str]:
        """The current AVD's ``{slot: tag}`` table (a copy)."""
        cfg = self._config()
        if cfg is None or getattr(cfg, "tui", None) is None:
            return {}
        return dict(cfg.tui.snapshot_slots.get(self._avd_name(), {}))

    def _reverse_slot_map(self) -> dict[str, str]:
        """``{tag: slot}`` for the current AVD (for the row prefix)."""
        return {tag: slot for slot, tag in self._slot_map().items()}

    def _save_mode(self) -> str:
        """Configured save-to-occupied-slot mode ('ask'|'overwrite'|'fresh')."""
        cfg = self._config()
        if cfg is None or getattr(cfg, "tui", None) is None:
            return "ask"
        return getattr(cfg.tui, "snapshot_save_mode", "ask") or "ask"

    def _write_slot(self, slot: str, tag: str | None) -> None:
        """Set (or clear, when ``tag is None``) slot->tag for the current AVD.

        Persists the whole ``snapshot_slots`` map via
        ``ConfigLoader.load_and_update_section`` (the ``exclude_unset`` trap means
        a bare attribute mutation would drop the section) and syncs the live app
        config. Safe to call from a worker thread (no widget access).
        """
        cfg = self._config()
        avd = self._avd_name()
        full: dict[str, dict[str, str]] = {}
        if cfg is not None and getattr(cfg, "tui", None) is not None:
            full = {k: dict(v) for k, v in cfg.tui.snapshot_slots.items()}
        table = full.get(avd, {})
        if tag is None:
            table.pop(slot, None)
        else:
            table[slot] = tag
        if table:
            full[avd] = table
        else:
            full.pop(avd, None)
        try:
            from sandroid.config.loader import ConfigLoader

            updated, _ = ConfigLoader().load_and_update_section(
                "tui", {"snapshot_slots": full}
            )
            self.app._sandroid_config = updated
        except Exception as exc:
            logger.warning(f"Could not persist snapshot slot: {exc}")
            self._notify(f"Could not save slot: {exc}", "error")

    def _persist_save_mode(self, mode: str) -> None:
        """Remember the save-to-occupied-slot choice as the default."""
        try:
            from sandroid.config.loader import ConfigLoader

            updated, _ = ConfigLoader().load_and_update_section(
                "tui", {"snapshot_save_mode": mode}
            )
            self.app._sandroid_config = updated
        except Exception as exc:
            logger.warning(f"Could not persist save mode: {exc}")

    # -- list fetch (off the UI thread) -----------------------------------

    def refresh_snapshots(self) -> None:
        """Fetch the snapshot list off the UI thread, then rebuild.

        No-op when no emulator is available or a fetch is already in flight.
        ``Adb.get_avd_snapshots`` returns ``[]`` on a physical device and never
        raises, so a missing emulator simply yields an empty list.
        """
        if self._refresh_inflight:
            return
        if not self._emulator_available():
            # Still reflect the unavailable state in the UI.
            self._snapshots = []
            self._post(self._rebuild_list)
            return
        self._refresh_inflight = True
        self.run_worker(
            self._refresh_worker,
            name="snapshots_refresh",
            exclusive=False,
            thread=True,
        )

    def _refresh_worker(self) -> None:
        """Worker-thread body of the list fetch."""
        snapshots: list[dict] = []
        try:
            snapshots = list(self._adb().get_avd_snapshots() or [])
        except Exception as exc:
            logger.debug(f"Snapshot list fetch failed: {exc}")
        finally:
            self._refresh_inflight = False
        # Telnet usually lists oldest->newest and the ``date`` strings do not
        # sort reliably, so reverse for newest-first rather than sort by date.
        snapshots.reverse()
        self._snapshots = snapshots
        self._post(self._rebuild_list)

    # -- live poll (slow fallback) ----------------------------------------

    def _is_active_child(self) -> bool:
        """True if this panel is the active tool-body ContentSwitcher child."""
        try:
            switcher = self.screen.query_one("#tool-body", ContentSwitcher)
            return switcher.current == "snapshots-panel"
        except Exception:
            return False

    def _is_on_screen(self) -> bool:
        """True if the Snapshots tab is the shown tool-body child."""
        return self._is_active_child()

    def _refresh_if_visible(self) -> None:
        """Refresh only when the tab is on screen (main thread).

        Used by on-mount and the EventBus callbacks so a hidden tab never
        triggers the slow telnet ``list``. Explicit refreshes (the ``r`` key /
        cell, after an action, and the tab-activation hook) call
        ``refresh_snapshots`` directly instead.
        """
        if self._is_on_screen():
            self.refresh_snapshots()

    def _poll(self) -> None:
        """Timer tick (main thread): refresh the list when worth it.

        No-op unless an emulator is available, the strip is expanded, and this
        panel is the active child — telnet ``list`` is slow, so we never poll
        a hidden tab.
        """
        if not self._emulator_available():
            return
        if not self._is_on_screen():
            return
        self.refresh_snapshots()

    # -- actions (main-thread entry points) -------------------------------

    def _require_emulator(self) -> bool:
        if not self._emulator_available():
            self._notify("Snapshots require a running emulator.", "warning")
            return False
        return True

    def action_create(self) -> None:
        """Prompt for a name then create a snapshot (blank = timestamp)."""
        if not self._require_emulator():
            return
        from sandroid.tui.modals import InputModal

        def on_result(value: str | None) -> None:
            if value is None:
                return
            name = value.strip()
            if not name:
                # App code runs normal Python; a runtime timestamp is fine.
                name = time.strftime("%Y-%m-%d_%H-%M-%S")

            def _work() -> tuple[bool, str]:
                # create_snapshot delegates without returning, so completing
                # without raising is treated as success.
                self._toolbox().create_snapshot(name)
                return True, f"Created snapshot '{name}'"

            self._run_action_bg(_work, "create", refresh_after=True)

        self.app.push_screen(
            InputModal(
                title="Create snapshot",
                message="Name for the new snapshot.",
                placeholder="name (blank = timestamp)",
            ),
            on_result,
        )

    def action_load(self) -> None:
        """Confirm then load the highlighted snapshot."""
        if not self._require_emulator():
            return
        tag = self._highlighted_tag()
        if not tag:
            self._notify("No snapshot selected to load.", "warning")
            return
        from sandroid.tui.modals import ConfirmModal

        def on_result(yes: bool | None) -> None:
            if not yes:
                return

            def _work() -> tuple[bool, str]:
                self._toolbox().load_snapshot(tag)
                return True, f"Loaded '{tag}'"

            self._run_action_bg(_work, "load", refresh_after=True)

        self.app.push_screen(
            ConfirmModal(
                title="Load snapshot",
                message=f"Load '{tag}'? Current state will be lost.",
            ),
            on_result,
        )

    def action_delete(self) -> None:
        """Confirm then delete the highlighted snapshot."""
        if not self._require_emulator():
            return
        tag = self._highlighted_tag()
        if not tag:
            self._notify("No snapshot selected to delete.", "warning")
            return
        from sandroid.tui.modals import ConfirmModal

        def on_result(yes: bool | None) -> None:
            if not yes:
                return

            def _work() -> tuple[bool, str]:
                # delete propagates the service bool (unlike create/load) so a
                # rejected `avd snapshot del` surfaces as a real failure.
                ok = self._toolbox().delete_snapshot(tag)
                if ok:
                    return True, f"Deleted '{tag}'"
                return False, f"Could not delete '{tag}' (emulator rejected it)"

            self._run_action_bg(_work, "delete", refresh_after=True)

        self.app.push_screen(
            ConfirmModal(
                title="Delete snapshot",
                message=f"Delete '{tag}'? This cannot be undone.",
            ),
            on_result,
        )

    def action_refresh(self) -> None:
        """Trigger a background list refresh."""
        if not self._require_emulator():
            return
        self.refresh_snapshots()

    def action_assign(self) -> None:
        """Assign the highlighted snapshot to a slot (1-8)."""
        self.assign_highlighted_to_slot()

    # -- slot operations (load / save / assign) ---------------------------

    def load_slot(self, slot: int | str) -> None:
        """Load the snapshot assigned to ``slot`` (no confirm — deliberate key).

        Reachable from the app's ``1``-``8`` bindings even when the tab is not
        on screen, so it never depends on a populated list.
        """
        if not self._require_emulator():
            return
        slot = str(slot)
        tag = self._slot_map().get(slot)
        if not tag:
            self._notify(
                f"Slot {slot} is empty — assign a snapshot from the Snapshots tab.",
                "warning",
            )
            return
        # If we have a fresh list, catch a slot that points at a deleted tag.
        if self._snapshots:
            known = {s.get("tag") or s.get("id") for s in self._snapshots}
            if tag not in known:
                self._notify(
                    f"Slot {slot} points to '{tag}', which no longer exists.",
                    "warning",
                )
                return

        def _work() -> tuple[bool, str]:
            self._toolbox().load_snapshot(tag)
            return True, f"Loaded slot {slot} ('{tag}')"

        self._run_action_bg(_work, f"load slot {slot}", refresh_after=True)

    def save_slot(self, slot: int | str) -> None:
        """Snapshot the current state into ``slot`` (save-state).

        Empty slot -> create ``slot-N`` and assign. Occupied slot -> honour
        ``tui.snapshot_save_mode``: overwrite in place, save fresh + re-point, or
        ask (the choice modal, with an optional persist).
        """
        if not self._require_emulator():
            return
        slot = str(slot)
        existing = self._slot_map().get(slot)
        if not existing:
            self._do_save(f"slot-{slot}", slot)
            return

        mode = self._save_mode()
        if mode == "overwrite":
            self._do_save(existing, slot)
            return
        if mode == "fresh":
            self._do_save(self._fresh_tag(slot), slot)
            return

        # mode == "ask": prompt for overwrite vs fresh.
        from sandroid.tui.modals import SnapshotSaveChoiceModal

        def on_result(result) -> None:
            if result is None or result.cancelled:
                return
            if result.remember:
                self._persist_save_mode(result.mode)
            if result.mode == "fresh":
                self._do_save(self._fresh_tag(slot), slot)
            else:
                self._do_save(existing, slot)

        self.app.push_screen(
            SnapshotSaveChoiceModal(slot=slot, existing_tag=existing),
            on_result,
        )

    @staticmethod
    def _fresh_tag(slot: str) -> str:
        """Timestamped tag for a 'save fresh' into ``slot``."""
        return f"slot-{slot}-{time.strftime('%Y%m%d-%H%M%S')}"

    def _do_save(self, tag: str, slot: str) -> None:
        """Create a snapshot named ``tag`` and point ``slot`` at it (off-thread)."""

        def _work() -> tuple[bool, str]:
            # create_snapshot delegates without returning, so no raise = success.
            self._toolbox().create_snapshot(tag)
            # Pure config/file write + attr set — safe off the UI thread.
            self._write_slot(slot, tag)
            return True, f"Saved slot {slot} → '{tag}'"

        self._run_action_bg(_work, f"save slot {slot}", refresh_after=True)

    def assign_highlighted_to_slot(self) -> None:
        """Point a slot at the highlighted *existing* snapshot (no new snapshot)."""
        if not self._require_emulator():
            return
        tag = self._highlighted_tag()
        if not tag:
            self._notify("No snapshot selected to assign.", "warning")
            return
        from sandroid.tui.modals import InputModal

        def on_result(value: str | None) -> None:
            if value is None:
                return
            value = value.strip()
            if not (value.isdigit() and 1 <= int(value) <= 8):
                self._notify("Enter a slot number from 1 to 8.", "warning")
                return
            self._write_slot(value, tag)
            self._rebuild_list()  # list unchanged; re-render to show the [n] prefix
            self._notify(f"Assigned '{tag}' to slot {value}", "information")

        self.app.push_screen(
            InputModal(
                title="Assign to slot",
                message=f"Assign '{tag}' to which slot?",
                placeholder="1-8",
            ),
            on_result,
        )

    def dispatch_action_cell(self, wid: str) -> None:
        """Run the action bound to a clicked action cell (from MainScreen)."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    # -- background action runner -----------------------------------------

    #: Upper bound for any single snapshot action. ``load`` sleeps 2s in the
    #: service layer and telnet round-trips are quick, so this only trips on a
    #: genuine wedge and exists so ``_action_inflight`` can NEVER stay stuck.
    _ACTION_TIMEOUT = 90.0

    def _run_action_bg(self, work, label: str, refresh_after: bool = False) -> None:
        """Run a blocking snapshot action off the UI thread, then notify.

        ``work`` returns ``(success, message)`` and must be safe to run on a
        worker thread (no widget access). A single in-flight guard prevents
        overlapping actions. ``work`` runs under a bounded watchdog so a hung
        telnet call can never wedge ``_action_inflight``; on timeout the flag
        is cleared and the orphaned worker is abandoned (``shutdown(wait=False)``
        — never block on the hang we are escaping).
        """
        if self._action_inflight:
            self._notify("Snapshot action already in progress…", "warning")
            return
        self._action_inflight = True

        def _job() -> None:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(work)
                try:
                    ok, msg = future.result(timeout=self._ACTION_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    ok, msg = (
                        False,
                        f"{label} timed out after "
                        f"{int(self._ACTION_TIMEOUT)}s — see logs",
                    )
                    logger.error(
                        "Snapshot action %s exceeded %.0fs watchdog; abandoning",
                        label,
                        self._ACTION_TIMEOUT,
                    )
                self._notify(msg, "information" if ok else "error")
            except Exception as exc:
                logger.warning(f"{label} failed: {exc}")
                self._notify(f"{label} failed: {exc}", "error")
            finally:
                # Never wedge: clear the guard no matter how work() ended, and
                # do not wait on a possibly-hung worker thread.
                executor.shutdown(wait=False)
                self._action_inflight = False
                if refresh_after:
                    self._post(self.refresh_snapshots)

        self.run_worker(_job, name=f"snapshots_{label}", exclusive=False, thread=True)

    # -- notifications ----------------------------------------------------

    def _notify(self, message: str, severity: str = "information") -> None:
        """Notify the user. Safe to call from worker threads."""
        self._post(self._do_notify, message, severity)

    def _do_notify(self, message: str, severity: str) -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass
