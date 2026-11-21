"""TUI panel for listing / creating / loading / deleting AVD snapshots.

Snapshots are not a lens: this panel lives inside the snapshot picker modal
(``S`` / ``0``, :class:`~sandroid.tui.modals.SnapshotPickerModal`). It
surfaces the AVD's saved snapshots and offers the lifecycle actions
(Create / Load / Delete / Assign / Refresh).

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
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from sandroid.tui.utils.ui_thread import UiDispatcher
from sandroid.tui.widgets.lens_shell import is_shown

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


# Clickable action-cell id -> panel action method (see on_click).
_ACTION_CELLS = {
    "snap-create": "action_create",
    "snap-load": "action_load",
    "snap-delete": "action_delete",
    "snap-assign": "action_assign",
    "snap-refresh": "action_refresh",
}

# How often the slow fallback poll re-checks the snapshot list (seconds).
# Telnet ``list`` is slow, so this stays lazy: each tick is a no-op unless this
# panel is on screen (the picker is open).
_POLL_INTERVAL = 9.0


def _as_user(work):
    """Run ``work()`` with the session-timeline actor ``user``."""
    from sandroid.core.timeline import acting_as

    with acting_as("user"):
        return work()


def _refusal_reason(op: str, name: str, *, confirmed: bool = False) -> str | None:
    """Why the snapshot policy refused *op* on *name* (worker thread), else None."""
    try:
        from sandroid.services import get_emulator_service

        check = getattr(get_emulator_service(), "snapshot_refusal", None)
        if not callable(check):
            return None
        refusal = check(op, name, confirmed=confirmed)
    except Exception:
        return None
    return None if refusal is None else refusal.reason


class SnapshotsPanel(Widget):
    """Snapshot list + create/load/delete/assign actions (hosted by the picker).

    Bindings (when focused):
        c: create a snapshot (prompts for a name; blank = timestamp)
        l: load the highlighted snapshot (current state is lost)
        d: delete the highlighted snapshot (irreversible)
        a: assign the highlighted snapshot to a slot (1-8)
        r: refresh the list

    The keys are deliberately **lowercase**. App-level priority bindings fire
    App-first regardless of focus (e.g. ``D`` opens the Devices screen), so an
    uppercase ``D`` here would be dead. Lowercase c/l/d/r map to non-priority
    app bindings, and a focused descendant's ancestor (this panel) wins the
    non-priority pass — so these shadow the globals only while the snapshots
    panel is focused. ``OptionList`` binds only navigation keys (up/down/enter/
    home/end/pageup/pagedown), so the letter keys never clash with it nor with
    the picker's slot digits. The action row is also
    clickable.
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
        # Ctrl+R, not r: plain r is the global Record key and must work on
        # every panel.
        ("ctrl+r", "refresh", "Refresh"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        self._ui = UiDispatcher()
        # Slow fallback poll bookkeeping.
        self._poll_timer = None
        self._poll_inflight = False
        # Guard against overlapping blocking actions (create/load/delete) and
        # against stacking refresh fetches.
        self._action_inflight = False
        self._refresh_inflight = False
        # Newest-first list of snapshot dicts ({id,tag,size,date,clock}).
        self._snapshots: list[dict] = []
        #: The last list fetch was refused: the console is not authenticated.
        self._console_refused = False
        # The (label, tag) rows the OptionList shows: a rebuild with the same
        # rows is skipped so the highlight and scroll position stay put.
        self._shown_rows: list[tuple[str, str | None]] | None = None
        #: A snapshot just created here: the next rebuild that lists it
        #: highlights it (the new row shifts the others down).
        self._select_tag: str | None = None

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
            yield Static("^r refresh", id="snap-refresh", classes="act-cell")

    def on_mount(self) -> None:
        self._app_ref = self.app
        self._subscribe_events()
        # Only fetch while on screen -- the slow telnet ``list`` must not run
        # for a hidden panel.
        self._refresh_if_visible()
        # Event-driven refresh (STATE_CHANGED) covers most cases; this slow
        # poll is the safety net. Stopped in on_unmount; each tick is a no-op
        # unless this panel is on screen.
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

        Focusing ``#snapshots-panel`` (this container) is not enough for
        up/down/enter row navigation -- the OptionList needs focus. Forward focus there, falling back to the container.
        """
        try:
            self.query_one("#snapshots-list", OptionList).focus(scroll_visible)
        except Exception:
            super().focus(scroll_visible)
        return self

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            # Thread -> UI hand-off in the UI's contextvars context (see
            # sandroid.tui.utils.ui_thread: a bare loop callback lacks
            # Textual's active_app and its timers raised LookupError).
            self._ui = UiDispatcher.capture()
            self._main_loop = self._ui.loop

            bus = EventBus.get()

            def _make_cb():
                def _cb(_event) -> None:
                    # Fire-and-forget onto the main loop; never blocks the
                    # publisher's thread (avoids the call_from_thread deadlock).
                    # Visibility-gated: a state change must not fire the
                    # slow telnet ``list`` while the tab is hidden.
                    self._ui.post(self._refresh_if_visible)

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
        self._ui.post(fn, *args)

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
            from sandroid.tui.themes import lens_palette

            dim = lens_palette().dim
            return f"Emulator [{dim}]○ not running · snapshots need one[/]"
        if self._console_refused:
            from sandroid.core.adb_emulator import CONSOLE_NOT_AUTHENTICATED

            text = CONSOLE_NOT_AUTHENTICATED[0].upper() + CONSOLE_NOT_AUTHENTICATED[1:]
            return f"[b]{self._avd_name()}[/] — [#fb7185]{text}[/]"
        count = len(self._snapshots)
        return f"[b]{self._avd_name()}[/] — {count} snapshot(s)"

    def _render_slots(self) -> str:
        """Render the slot memory (all 8 slots; empties shown), 2 per line.

        Pads on plain text and colours after, since Rich markup has no width.
        """
        if not self._emulator_available():
            return ""
        slot_map = self._slot_map()
        known = self._known_tags() if self._snapshots else None
        cells: list[tuple[str, str]] = []  # (plain, markup) per slot
        for i in range(1, 9):
            tag = slot_map.get(str(i))
            if tag and known is not None and tag not in known:
                disp = tag if len(tag) <= 12 else tag[:11] + "…"
                cells.append(
                    (
                        f"[{i}] {disp} (gone)",
                        f"[#5b6479]\\[{i}] [s]{disp}[/s] (gone)[/]",
                    )
                )
            elif tag:
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
        """Rebuild the OptionList + header + slot memory on the main thread.

        The highlighted snapshot is kept **by tag**: the slow poll rebuilds
        the list every few seconds, and resetting the highlight to row 0 made
        Enter / ``d`` act on whatever snapshot happened to be newest. When
        the rows did not change at all, the options are left alone.
        """
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
        # (label, tag) per row; the tag doubles as the option id, so the
        # highlighted row always names its own snapshot -- even while a
        # worker has already swapped ``_snapshots`` for a newer list.
        if not self._emulator_available():
            rows = [
                ("[#5b6479]start an emulator (D) to save and load snapshots[/]", None)
            ]
        elif not self._snapshots:
            rows = [("[#5b6479]no snapshots — press c to create[/]", None)]
        else:
            rows = []
            for snap in self._snapshots:
                tag = self._tag_of(snap)
                if tag is not None and all(tag != t for _l, t in rows):
                    rows.append((self._option_label(snap), tag))
        if rows == self._shown_rows and option_list.option_count == len(rows):
            return  # unchanged: keep the user's highlight and scroll position
        previous_tag = self._highlighted_tag()
        previous_index = option_list.highlighted
        try:
            option_list.clear_options()
            option_list.add_options([Option(label, id=tag) for label, tag in rows])
            self._shown_rows = rows
            tags = [tag for _label, tag in rows if tag is not None]
            if not tags:
                return
            if self._select_tag in tags:
                index = tags.index(self._select_tag)
                self._select_tag = None
            elif previous_tag in tags:
                index = tags.index(previous_tag)
            elif previous_index is not None:
                # The highlighted snapshot is gone (deleted): stay on the same
                # row position rather than jumping to the top.
                index = min(previous_index, len(tags) - 1)
            else:
                # Fresh list: OptionList leaves ``highlighted`` None until the
                # user navigates, which would make Load/Delete report "no
                # selection". Default to the first (newest) row.
                index = 0
            option_list.highlighted = index
        except Exception as exc:
            logger.debug(f"SnapshotsPanel rebuild failed: {exc}")

    @staticmethod
    def _tag_of(snap: dict) -> str | None:
        return snap.get("tag") or snap.get("id") or None

    def snapshot_summary(self, tag: str) -> str:
        """``'tag' (date · size)`` for confirm dialogs, so they name the row."""
        for snap in self._snapshots:
            if self._tag_of(snap) == tag:
                bits = [b for b in (snap.get("date"), snap.get("size")) if b]
                if bits:
                    return f"'{tag}' ({' · '.join(str(b) for b in bits)})"
        return f"'{tag}'"

    def _highlighted_tag(self) -> str | None:
        """Tag of the currently highlighted snapshot row, or None.

        Read from the highlighted option's id (= its tag), not by indexing
        ``_snapshots``: that list can already hold a newer fetch whose rows
        are not on screen yet.
        """
        try:
            option = self.query_one("#snapshots-list", OptionList).highlighted_option
        except Exception:
            return None
        if option is None:
            return None
        return option.id or None

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
        if self._refresh_inflight or not self.is_attached:
            return
        if not self._emulator_available():
            # Still reflect the unavailable state in the UI.
            self._snapshots = []
            self._console_refused = False
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
        from sandroid.core.adb_emulator import console_auth_failed_since

        snapshots: list[dict] = []
        started = time.monotonic()
        try:
            snapshots = list(self._adb().get_avd_snapshots() or [])
        except Exception as exc:
            logger.debug(f"Snapshot list fetch failed: {exc}")
        finally:
            self._refresh_inflight = False
        self._console_refused = not snapshots and console_auth_failed_since(started)
        # Telnet usually lists oldest->newest and the ``date`` strings do not
        # sort reliably, so reverse for newest-first rather than sort by date.
        snapshots.reverse()
        self._snapshots = snapshots
        self._post(self._rebuild_list)

    # -- live poll (slow fallback) ----------------------------------------

    def _is_on_screen(self) -> bool:
        """True while this panel is mounted and visible (the picker is open)."""
        return is_shown(self)

    _is_active_child = _is_on_screen

    def _refresh_if_visible(self) -> None:
        """Refresh only when the tab is on screen (main thread).

        Used by on-mount and the EventBus callbacks so a hidden panel never
        triggers the slow telnet ``list``. Explicit refreshes (Ctrl+R / the
        cell, after an action) call ``refresh_snapshots`` directly instead.
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
        try:
            if self.app.screen is not self.screen:
                return  # a confirm/input dialog is open on top of the picker
        except Exception:
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
            from sandroid.core.adb_utils import validate_snapshot_name

            try:
                validate_snapshot_name(name)
            except ValueError as exc:
                self._notify(f"Not created: {exc}", "error")
                return

            def _work() -> tuple[bool, str]:
                # The service returns False (and logs why) on a rejected save;
                # ``None`` (older/fake toolboxes) counts as success.
                if self._toolbox().create_snapshot(name) is False:
                    why = _refusal_reason("save", name) or "see the log"
                    return False, f"Could not create snapshot '{name}' ({why})"
                self._select_tag = name  # plain attribute: safe off-thread
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
                if self._toolbox().load_snapshot(tag, reset_network=True) is False:
                    return False, f"Could not load '{tag}' (see the log)"
                self._post(self._note_loaded, tag, None)
                return True, f"Loaded '{tag}'"

            self._run_action_bg(_work, "load", refresh_after=True)

        self.app.push_screen(
            ConfirmModal(
                title="Load snapshot",
                message=(
                    f"Load snapshot {self.snapshot_summary(tag)}? "
                    "Current state will be lost."
                ),
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
        from sandroid.core import snapshot_policy as policy
        from sandroid.tui.modals import ConfirmModal

        # A name another part of Sandroid owns (a Rewind start point, a
        # persona snapshot): the confirm says whose it is, and only that
        # confirm lets the user delete it. Pinned names are refused by the
        # service (unpin in the Devices screen first).
        owner = policy.owner_of(tag)

        def on_result(yes: bool | None) -> None:
            if not yes:
                return

            def _work() -> tuple[bool, str]:
                # delete propagates the service bool (unlike create/load) so a
                # rejected `avd snapshot del` surfaces as a real failure.
                with policy.acting_as(policy.USER, confirmed=owner is not None):
                    ok = self._toolbox().delete_snapshot(tag)
                if ok:
                    # A slot must not outlive its snapshot.
                    for slot, slot_tag in self._slot_map().items():
                        if slot_tag == tag:
                            self._write_slot(slot, None)
                    return True, f"Deleted '{tag}'"
                why = _refusal_reason("delete", tag, confirmed=owner is not None) or (
                    "emulator rejected it"
                )
                return False, f"Could not delete '{tag}' ({why})"

            self._run_action_bg(_work, "delete", refresh_after=True)

        message = (
            f"Delete snapshot {self.snapshot_summary(tag)}? This cannot be undone."
        )
        if owner is not None:
            message += f"\n\nThis is a {owner.label}. {owner.delete_warning}".rstrip()
        self.app.push_screen(
            ConfirmModal(title="Delete snapshot", message=message),
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

    def slot_tag(self, slot: int | str) -> str | None:
        """Tag assigned to ``slot`` if it could be loaded right now, else None.

        Used by the picker's 1-8 keys: only a loadable slot needs a confirm;
        anything else is reported immediately by :meth:`load_slot`.
        """
        try:
            if not self._emulator_available():
                return None
            tag = self._slot_map().get(str(slot)) or None
            if tag and self._snapshots and tag not in self._known_tags():
                return None  # load_slot explains that it no longer exists
            return tag
        except Exception:
            return None

    def _known_tags(self) -> set[str]:
        return {t for t in (self._tag_of(s) for s in self._snapshots) if t}

    def load_slot(self, slot: int | str) -> None:
        """Load the snapshot assigned to ``slot`` (no confirm here).

        Never depends on a populated list. The picker's ``1``-``8`` keys ask
        for a confirm first (see ``SnapshotPickerModal.action_load_slot``).
        """
        if not self._require_emulator():
            return
        slot = str(slot)
        tag = self._slot_map().get(slot)
        if not tag:
            self._notify(
                f"Slot {slot} is empty — highlight a snapshot and press a to assign.",
                "warning",
            )
            return
        # If we have a fresh list, catch a slot that points at a deleted tag.
        if self._snapshots:
            if tag not in self._known_tags():
                self._notify(
                    f"Slot {slot} points to '{tag}', which no longer exists.",
                    "warning",
                )
                return

        def _work() -> tuple[bool, str]:
            if self._toolbox().load_snapshot(tag, reset_network=True) is False:
                return False, f"Could not load slot {slot} ('{tag}', see the log)"
            self._post(self._note_loaded, tag, slot)
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
            if self._toolbox().create_snapshot(tag) is False:
                why = _refusal_reason("save", tag) or "see the log"
                return False, f"Could not save slot {slot} ('{tag}', {why})"
            # Pure config/file write + attr set — safe off the UI thread.
            self._write_slot(slot, tag)
            self._select_tag = tag
            return True, f"Saved '{tag}' to slot {slot}"

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
        """Run the action bound to a clicked action cell."""
        method = _ACTION_CELLS.get(wid)
        if method:
            getattr(self, method)()

    def on_click(self, event) -> None:
        """Route clicks on the action row (the picker is not MainScreen)."""
        wid = getattr(getattr(event, "widget", None), "id", None)
        if wid in _ACTION_CELLS:
            event.stop()
            self.dispatch_action_cell(wid)

    def _note_loaded(self, tag: str, slot: str | None) -> None:
        """Tell the main screen which snapshot is loaded (header indicator)."""
        try:
            app = getattr(self, "_app_ref", None) or self.app
            for screen in app.screen_stack:
                note = getattr(screen, "note_snapshot", None)
                if note is not None:
                    note(tag, slot)
        except Exception:
            pass

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
                # The panel's actions are the user's (session-timeline actor);
                # entered on the thread that runs ``work``.
                future = executor.submit(_as_user, work)
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
        # The picker may have closed (panel unmounted) while a worker ran;
        # fall back to the app captured at mount.
        app = getattr(self, "_app_ref", None)
        try:
            app = self.app
        except Exception:
            pass
        try:
            if app is not None:
                app.notify(message, severity=severity)
        except Exception:
            pass
