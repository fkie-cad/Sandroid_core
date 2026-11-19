"""Devices screen: every running device and every installed AVD, live.

One screen replaces the old device / AVD / boot-mode pickers:

* **Running** -- what ``adb devices -l`` lists plus emulators Sandroid is
  still launching: serial, AVD name, model, API level, state (booting with
  elapsed time, ready, offline, unauthorized, no permissions), root kind and
  the active-device marker. ⏎ attaches a ready device; ``x`` stops and ``R``
  restarts an emulator (per serial, never by process name).
* **Available AVDs** -- installed AVDs that are not running, with API level,
  image tag, snapshot count and the remembered launch options. ⏎ starts one
  with those options; ``c`` cold boot, ``n`` from a snapshot, ``w`` wipe,
  ``h`` toggles headless (remembered), ``e`` renames.

The module is split in two halves:

* a pure model (:class:`RowState`, :class:`DeviceRow`, :class:`AvdRow`,
  :class:`HubSnapshot`, :func:`build_snapshot`) that unit tests drive
  without Textual or adb, and the :class:`HubCollector` that feeds it from
  adb / the AVD catalogue (off the UI thread, every adb call bounded);
* :class:`DevicesScreen`, a full-screen ``ModalScreen`` that dismisses with
  the serial to attach (or ``None``).

Threading: all adb work runs in one thread worker at a time (in-flight +
pending flags). Refreshes are triggered by the adb ``track-devices`` stream,
a 2 s poll while something boots, a 10 s backstop and every finished action.
A 1 s tick only repaints the elapsed boot time.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Static

from sandroid.core.adb_device_monitor import AdbDeviceMonitor
from sandroid.tui.themes import lens_palette

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterable, Sequence

    from textual import events
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pure model
# ---------------------------------------------------------------------------

#: Our launch is shown as booting at most this long (matches core.emulator).
_BOOTING_MAX_AGE = 600.0

UNAUTHORIZED_HELP = (
    "Unauthorized: unlock the device and accept the “Allow USB debugging?” "
    "prompt (tick “Always allow from this computer”). No prompt? In Developer "
    "options choose “Revoke USB debugging authorizations”, replug the cable "
    "and run `adb kill-server`."
)

NO_PERMISSIONS_HELP = (
    "No permissions: adb may not open this USB device. Linux: install the "
    "Android udev rules (e.g. the android-udev-rules package), add your user "
    "to the plugdev group, replug and run `adb kill-server`. Elsewhere: "
    "replug, use a data cable and set the USB mode to File transfer."
)

RUNNING_ELSEWHERE_HELP = (
    "Running elsewhere: an emulator holds this AVD's lock files (another "
    "session, or an adb server this one does not see), so it cannot be "
    "started, renamed or wiped here. If no emulator runs it, delete the "
    "stale *.lock files in its .avd directory."
)

OFFLINE_HELP = (
    "Offline: adb sees the device but cannot talk to it. Wait a moment, "
    "replug it / run `adb reconnect offline`, or restart the emulator (R)."
)


class RowState(Enum):
    """State of a running-device row."""

    BOOTING = "booting"
    READY = "ready"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    NO_PERMISSIONS = "no permissions"
    OTHER = "other"


@dataclass(frozen=True)
class SerialProbe:
    """What one getprop round-trip told about a serial.

    Attributes:
        booted: ``sys.boot_completed`` is 1 (``None``: not probed).
        api: ``ro.build.version.sdk``.
        avd_name: The emulator's AVD name (``ro.boot.qemu.avd_name``).
    """

    booted: bool | None = None
    api: int | None = None
    avd_name: str = ""


@dataclass(frozen=True)
class DeviceRow:
    """One running device (or an emulator Sandroid is still launching).

    Attributes:
        serial: adb serial.
        avd_name: AVD name of an emulator ("" if unknown / physical).
        model: Model (``adb devices -l``).
        api: API level, ``None`` if unknown.
        state: Classified state.
        raw_state: adb's state word (``starting`` for a launch not yet listed).
        boot_elapsed: Seconds since our launch started (booting rows we
            launched), else ``None``.
        root_kind: ``adbd root`` / ``adb root`` / ``su`` / ``none`` / ``""``.
        is_emulator: ``emulator-<port>`` serial.
        active: The session's active device.
        ours: Sandroid launched it in this session.
        log_path: Our launch's emulator log ("" otherwise).
    """

    serial: str
    avd_name: str = ""
    model: str = ""
    api: int | None = None
    state: RowState = RowState.READY
    raw_state: str = "device"
    boot_elapsed: float | None = None
    root_kind: str = ""
    is_emulator: bool = False
    active: bool = False
    ours: bool = False
    log_path: str = ""

    @property
    def key(self) -> str:
        return f"dev:{self.serial}"

    @property
    def title(self) -> str:
        """The name to show / to talk about the device."""
        return self.avd_name or self.model or self.serial


@dataclass(frozen=True)
class AvdRow:
    """One installed AVD that is not running.

    Attributes:
        name: AVD name.
        api: API level, ``None`` if unknown.
        tag: System image tag (``google_apis``...).
        snapshot_count: Saved snapshots.
        options: Remembered launch options (``AvdLaunchOptions``).
        last_used: The last AVD launched from Sandroid.
        abi: Image ABI.
        device_name: Hardware profile.
        running_elsewhere: Its directory holds an emulator's lock files
            although no listed device runs it (another session / adb
            server): listed, but not startable, renamable or wipeable here.
    """

    name: str
    api: int | None = None
    tag: str = ""
    snapshot_count: int = 0
    options: Any = None
    last_used: bool = False
    abi: str = ""
    device_name: str = ""
    running_elsewhere: bool = False

    @property
    def key(self) -> str:
        return f"avd:{self.name}"


@dataclass(frozen=True)
class HubSnapshot:
    """Everything the Devices screen shows at one moment.

    Attributes:
        devices: Running devices, sorted by serial.
        avds: Installed AVDs that are not running.
        notes: Warnings (adb missing, a launch that crashed...).
        taken_at: ``time.monotonic()`` when it was built.
    """

    devices: tuple[DeviceRow, ...] = ()
    avds: tuple[AvdRow, ...] = ()
    notes: tuple[str, ...] = ()
    taken_at: float = 0.0

    @property
    def booting(self) -> bool:
        return any(row.state is RowState.BOOTING for row in self.devices)


def _launch_booting(launch: Any, now: float) -> bool:
    return (
        launch is not None
        and not launch.ready
        and launch.alive
        and now - launch.started_at < _BOOTING_MAX_AGE
    )


def classify(raw_state: str, probe: SerialProbe | None, booting: bool) -> RowState:
    """Map an adb state (+ readiness probe / our launch) to a :class:`RowState`.

    Args:
        raw_state: adb's state (``device``, ``offline``, ``no permissions``...).
        probe: Readiness probe of a ``device`` row (``None``: not probed --
            the pin rule forbids probing someone else's device).
        booting: Sandroid launched it and its boot has not completed yet.
            A probe that saw the boot complete wins over it (the launch's
            boot waiter may have given up long ago).
    """
    if raw_state == "device":
        if probe is not None and probe.booted:
            return RowState.READY
        if booting or (probe is not None and probe.booted is False):
            return RowState.BOOTING
        return RowState.READY
    if raw_state in ("offline", "connecting"):
        return RowState.BOOTING if booting else RowState.OFFLINE
    if raw_state in ("unauthorized", "authorizing"):
        return RowState.UNAUTHORIZED
    if raw_state.startswith("no permissions"):
        return RowState.NO_PERMISSIONS
    return RowState.OTHER


def build_snapshot(
    entries: Iterable[Any],
    probes: dict[str, SerialProbe],
    avd_names: dict[str, str],
    avds: Iterable[Any],
    prefs: dict[str, Any],
    launches: Iterable[Any],
    active_serial: str | None,
    now: float,
    *,
    known: dict[str, Any] | None = None,
    notes: Sequence[str] = (),
    locked_avds: Collection[str] = (),
) -> HubSnapshot:
    """Combine adb, probes, the AVD catalogue and our launches (pure).

    Args:
        entries: ``AdbDeviceEntry`` items of ``adb devices -l``.
        probes: Readiness / API probes by serial (only probed serials).
        avd_names: AVD names of running emulators by serial.
        avds: ``AvdInfo`` of every installed AVD.
        prefs: Remembered launch options (``load_launch_prefs()``).
        launches: ``EmulatorLaunch`` records of this session.
        active_serial: The active device's serial.
        now: ``time.monotonic()``.
        known: ``Device`` objects of the DeviceManager by serial (model, API
            and root kind it already probed).
        notes: Extra notes to show.
        locked_avds: AVDs whose directory holds emulator lock files
            (:func:`~sandroid.core.emulator.avd_lock_files`); those not
            running here are listed last as running elsewhere.

    Returns:
        The snapshot. Our launch not yet listed (or still offline) shows as
        booting with its elapsed time; a ``device`` that has not finished
        booting shows as booting; running AVDs are not offered as available;
        a launch whose process died during boot becomes a note naming its log.
    """
    from sandroid.core.emulator import options_from_prefs, serial_port

    known = known or {}
    by_serial = {launch.serial: launch for launch in launches}
    rows: dict[str, DeviceRow] = {}
    out_notes = list(notes)

    for entry in entries:
        serial = entry.serial
        launch = by_serial.get(serial)
        booting = _launch_booting(launch, now)
        probe = probes.get(serial)
        device = known.get(serial)
        avd_name = avd_names.get(serial) or (launch.avd if launch else "")
        api = (probe.api if probe else None) or (
            getattr(device, "api_level", 0) or None
        )
        state = classify(entry.state, probe, booting)
        rows[serial] = DeviceRow(
            serial=serial,
            avd_name=avd_name,
            model=entry.props.get("model", "") or getattr(device, "model", ""),
            api=api,
            state=state,
            raw_state=entry.state,
            boot_elapsed=(
                now - launch.started_at
                if booting and state is RowState.BOOTING
                else None
            ),
            root_kind=getattr(device, "root_kind", "") or "",
            is_emulator=serial_port(serial) is not None,
            active=serial == active_serial,
            ours=launch is not None,
            log_path=str(launch.log_path or "") if launch else "",
        )

    for serial, launch in by_serial.items():
        if serial in rows:
            continue
        if _launch_booting(launch, now):
            rows[serial] = DeviceRow(
                serial=serial,
                avd_name=launch.avd,
                state=RowState.BOOTING,
                raw_state="starting",
                boot_elapsed=now - launch.started_at,
                is_emulator=True,
                active=serial == active_serial,
                ours=True,
                log_path=str(launch.log_path or ""),
            )
        elif (
            not launch.ready
            and not launch.alive
            and now - launch.started_at < _BOOTING_MAX_AGE
        ):
            log = f" -- log: {launch.log_path}" if launch.log_path else ""
            out_notes.append(f"AVD '{launch.avd}' ({serial}) exited while booting{log}")

    running_avds = {row.avd_name for row in rows.values() if row.avd_name}
    last_avd = prefs.get("last_avd")
    locked = set(locked_avds)
    avd_rows = sorted(
        (
            AvdRow(
                name=info.name,
                api=info.api_level,
                tag=info.tag,
                snapshot_count=info.snapshot_count,
                options=options_from_prefs(prefs, info.name),
                last_used=info.name == last_avd,
                abi=info.abi,
                device_name=info.device_name,
                running_elsewhere=info.name in locked,
            )
            for info in avds
            if info.name not in running_avds
        ),
        key=lambda row: row.running_elsewhere,  # stable: keeps catalogue order
    )
    return HubSnapshot(
        devices=tuple(rows[s] for s in sorted(rows)),
        avds=tuple(avd_rows),
        notes=tuple(out_notes),
        taken_at=now,
    )


def format_elapsed(seconds: float | None) -> str:
    """``0:42`` / ``1:05:00`` (empty for ``None``)."""
    if seconds is None:
        return ""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def describe_options(options: Any) -> str:
    """Remembered launch options in a few words (``window · quick boot``)."""
    if options is None:
        return ""
    window = "headless" if options.headless else "window"
    boot = {
        "normal": "quick boot",
        "cold": "cold boot",
        "wipe": "wipe data",
        "snapshot": f"snapshot {options.snapshot}",
    }.get(options.boot, options.boot)
    return f"{window} · {boot}"


# ---------------------------------------------------------------------------
# Collection (worker thread)
# ---------------------------------------------------------------------------

#: Seconds the AVD catalogue (``emulator -list-avds`` + ini files) is cached.
AVD_CACHE_SECONDS = 30.0
#: Timeout of every adb call made by the collector.
ADB_TIMEOUT = 10.0
_PROBE_SCRIPT = (
    'shell "getprop sys.boot_completed; getprop ro.build.version.sdk; '
    'getprop ro.boot.qemu.avd_name; getprop ro.kernel.qemu.avd_name"'
)


class HubCollector:
    """Builds :class:`HubSnapshot` objects from adb (worker thread only).

    Keeps per-serial caches: a ready device is not probed again until it
    leaves ``device`` state; AVD names are looked up once per serial. With
    a pinned serial (``--serial`` / ``ANDROID_SERIAL``) only that serial and
    our own launches are probed -- other devices of a shared lab show what
    ``adb devices -l`` says and are never touched.
    """

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb
        self._lock = threading.Lock()
        self._probes: dict[str, SerialProbe] = {}
        self._avd_names: dict[str, str] = {}
        self._avds: list[Any] | None = None
        self._avds_at = 0.0

    def invalidate_avds(self) -> None:
        """Re-read the AVD catalogue on the next collect."""
        with self._lock:
            self._avds = None

    def _adb_cls(self) -> Any:
        if self._adb is not None:
            return self._adb
        from sandroid.core.adb import Adb

        return Adb

    def _run(self, command: str, serial: str) -> tuple[str, str]:
        try:
            out, err = self._adb_cls().send_adb_command(
                command, serial=serial, timeout=ADB_TIMEOUT
            )
        except Exception as e:
            return "", str(e)
        return out or "", err or ""

    def _probe(self, serial: str) -> SerialProbe | None:
        out, _err = self._run(_PROBE_SCRIPT, serial)
        lines = [line.strip() for line in out.splitlines()]
        if not lines:
            return None
        lines += [""] * (4 - len(lines))
        api = int(lines[1]) if lines[1].isdigit() else None
        return SerialProbe(
            booted=lines[0] == "1", api=api, avd_name=lines[2] or lines[3]
        )

    def _console_avd_name(self, serial: str) -> str:
        """AVD name via the emulator console (images without the property)."""
        out, _err = self._run("emu avd name", serial)
        for line in out.splitlines():
            line = line.strip()
            if line and line not in ("OK", "KO") and not line.startswith("KO:"):
                return line
        return ""

    def _catalogue(self, force: bool, notes: list[str]) -> list[Any]:
        from sandroid.core import emulator

        with self._lock:
            fresh = (
                self._avds is not None
                and time.monotonic() - self._avds_at < AVD_CACHE_SECONDS
            )
            if fresh and not force:
                return list(self._avds or [])
        if emulator.emulator_binary() is None:
            notes.append(
                "Android emulator not found -- set emulator.android_emulator_path "
                "or ANDROID_SDK_ROOT to list your AVDs."
            )
            avds: list[Any] = []
        else:
            avds = []
            for name in emulator.list_avds(timeout=15.0):
                try:
                    avds.append(emulator.avd_info(name))
                except Exception:
                    avds.append(emulator.AvdInfo(name=name))
        with self._lock:
            self._avds, self._avds_at = avds, time.monotonic()
        return avds

    def collect(self, force_avds: bool = False) -> HubSnapshot:
        """Read everything once (blocking; bounded adb timeouts)."""
        from sandroid.core import emulator
        from sandroid.core.device import parse_adb_devices
        from sandroid.core.device_manager import DeviceManager

        notes: list[str] = []
        out, err = self._run("devices -l", "")
        if "list of devices" in out.lower():
            entries = parse_adb_devices(out)
        else:
            entries = []
            notes.append(f"adb is not answering: {err or 'no output'}")

        pinned = DeviceManager.preferred_serial()
        launches = emulator.launches()
        ours = {launch.serial for launch in launches}
        alive = {launch.serial for launch in launches if launch.alive}
        # Our live launches still booting: a cached "booted" probe may be the
        # previous emulator's on the same port (restart), so probe again.
        unconfirmed = {
            launch.serial for launch in launches if launch.alive and not launch.ready
        }
        listed = {entry.serial for entry in entries}
        known: dict[str, Any] = {}
        active_serial = None
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            active = dm.active_device
            active_serial = active.serial if active is not None else None
            for serial in listed:
                device = dm.get_device(serial)
                if device is not None:
                    known[serial] = device
        except Exception:
            logger.debug("Devices screen: no device manager", exc_info=True)

        with self._lock:
            # Per-serial caches end with the serial: a later emulator on the
            # same port may run another AVD.
            for serial in set(self._probes) | set(self._avd_names):
                if serial not in listed:
                    self._probes.pop(serial, None)
                    self._avd_names.pop(serial, None)
        for entry in entries:
            serial = entry.serial
            if entry.state != "device":
                with self._lock:
                    if self._probes.get(serial, SerialProbe()).booted:
                        self._probes.pop(serial, None)
                continue
            if pinned and serial != pinned and serial not in ours:
                continue  # someone else's device in a shared lab
            with self._lock:
                cached = self._probes.get(serial)
            if cached is not None and cached.booted and serial not in unconfirmed:
                continue  # readiness is sticky until the serial goes away
            probe = self._probe(serial)
            if probe is None:
                continue
            if probe.booted and serial in alive:
                # Our launch booted: it no longer counts as booting (nor is
                # it kept from auto-selection) even if its waiter gave up.
                emulator.mark_ready(serial)
            with self._lock:
                self._probes[serial] = probe
                if probe.avd_name:
                    self._avd_names[serial] = probe.avd_name
        for entry in entries:
            serial = entry.serial
            if emulator.serial_port(serial) is None or entry.state != "device":
                continue
            if pinned and serial != pinned and serial not in ours:
                continue
            if serial in alive:
                continue  # our launch knows its AVD
            with self._lock:
                if serial in self._avd_names:
                    continue
            name = self._console_avd_name(serial)
            with self._lock:
                self._avd_names[serial] = name

        avds = self._catalogue(force_avds, notes)
        locked: set[str] = set()
        for info in avds:
            try:
                if emulator.avd_lock_files(info.name):
                    locked.add(info.name)
            except Exception:
                logger.debug(f"lock check of {info.name} failed", exc_info=True)
        with self._lock:
            probes = dict(self._probes)
            avd_names = {k: v for k, v in self._avd_names.items() if v}
        return build_snapshot(
            entries,
            probes,
            avd_names,
            avds,
            emulator.load_launch_prefs(),
            launches,
            active_serial,
            time.monotonic(),
            known=known,
            notes=notes,
            locked_avds=locked,
        )


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------

def _c(role: str) -> str:
    """The current theme's lens color *role* (``themes.LensPalette``: ok,
    warn, bad, title, dim, text), read per render so a theme change
    re-colors the rows (see ``DevicesScreen._repaint_for_theme``).
    """
    return getattr(lens_palette(), role)


_STATE_STYLE = {
    RowState.READY: "ok",
    RowState.BOOTING: "warn",
    RowState.OFFLINE: "bad",
    RowState.UNAUTHORIZED: "bad",
    RowState.NO_PERMISSIONS: "bad",
    RowState.OTHER: "dim",
}

#: Actions that need a row of the given kind (see ``check_action``).
_DEVICE_ACTIONS = frozenset({"attach"})
_EMULATOR_ACTIONS = frozenset({"stop", "restart"})
_AVD_ACTIONS = frozenset({"start", "cold", "snapshot", "wipe", "headless", "rename"})
#: AVD actions refused while another emulator holds the AVD's lock files.
_LOCKED_AVD_ACTIONS = frozenset({"start", "cold", "snapshot", "wipe", "rename"})


class _HubTable(DataTable):
    """A Devices list where a click only highlights.

    Selecting a row starts or attaches something, so a single (stray) click
    must never do it: ⏎ selects, and so does a second click on the row the
    previous click highlighted. Textual's own rule ("click the cell that has
    the cursor") also fired on the very first click when it hit the cell
    the screen had highlighted on its own.
    """

    _armed_row: int | None = None

    async def _on_click(self, event: events.Click) -> None:
        row = event.style.meta.get("row")
        if not isinstance(row, int) or row < 0 or "column" not in event.style.meta:
            return  # header / outside the rows: DataTable's own handling
        event.prevent_default()
        event.stop()
        if row >= self.row_count:
            return
        if row == self.cursor_row and self._armed_row == row:
            self._armed_row = None
            self.action_select_cursor()
            return
        self._armed_row = row
        self.move_cursor(row=row, animate=False)


class _RunningTable(_HubTable):
    """The running-devices list (⏎ attaches; shown in the footer)."""

    BINDINGS = [Binding("enter", "select_cursor", "Attach")]


class _AvdTable(_HubTable):
    """The available-AVDs list (⏎ starts; shown in the footer)."""

    BINDINGS = [Binding("enter", "select_cursor", "Start")]


class DevicesScreen(ModalScreen[str | None]):
    """Full-screen live list of running devices and installed AVDs.

    Dismisses with the serial to attach, or ``None``. Starting, stopping and
    restarting emulators happens in place (the screen stays open and shows
    the boot progress); the app attaches a freshly booted emulator itself
    when no device is active.

    Args:
        mode: ``session`` (opened with ``D``) or ``startup`` (before the main
            screen; Ctrl+C then aborts the start).
        reason: Why the screen opened (shown under the title).
        collect: ``collect(force_avds=bool) -> HubSnapshot`` (worker thread;
            default: a :class:`HubCollector`).
        actions: Object with ``start_avd`` / ``stop_emulator`` /
            ``restart_emulator`` / ``connect`` / ``rename_avd`` (default: the
            app's ``DeviceController``).
    """

    #: Factory of the adb ``track-devices`` monitor (tests set ``None``).
    monitor_factory: Callable[..., Any] | None = AdbDeviceMonitor

    #: Seconds between refreshes while something boots / the backstop.
    BOOT_POLL_SECONDS = 2.0
    BACKSTOP_SECONDS = 10.0

    DEFAULT_CSS = """
    DevicesScreen {
        background: $lens-bg;
        align: center top;
    }
    DevicesScreen #hub {
        width: 100%;
        height: 1fr;
        background: $lens-panel;
        border: round $lens-rule;
        border-title-color: $lens-accent;
        border-title-style: bold;
        border-subtitle-color: $lens-muted;
        padding: 0 1;
    }
    DevicesScreen #hub-reason {
        color: $lens-warn;
        height: auto;
        margin: 0 0 1 0;
    }
    DevicesScreen DataTable {
        height: auto;
        max-height: 45%;
        margin: 1 0 0 0;
        border: none;
        border-top: solid $lens-rule;
        border-title-color: $lens-title;
        border-title-style: bold;
        background: $lens-panel;
        scrollbar-size-vertical: 1;
    }
    DevicesScreen DataTable:focus {
        border-top: heavy $lens-rule-focus;
    }
    DevicesScreen DataTable > .datatable--header {
        background: $lens-panel;
        color: $lens-header;
        text-style: none;
    }
    DevicesScreen DataTable > .datatable--cursor {
        background: $lens-cursor;
        text-style: none;
    }
    DevicesScreen DataTable:focus > .datatable--cursor {
        background: $lens-cursor-focus;
    }
    DevicesScreen .hub-empty {
        color: $lens-dim;
        height: auto;
        padding: 0 1;
    }
    DevicesScreen #hub-spacer {
        height: 1fr;
    }
    DevicesScreen #hub-detail {
        height: auto;
        min-height: 3;
        color: $lens-text;
        border-top: solid $lens-rule;
        padding: 0 1;
    }
    DevicesScreen #hub-notes {
        height: auto;
        color: $lens-warn;
        padding: 0 1;
    }
    DevicesScreen Footer {
        background: $lens-action-bg;
    }
    """

    BINDINGS = [
        Binding("c", "cold", "Cold boot"),
        Binding("n", "snapshot", "Snapshot…"),
        Binding("w", "wipe", "Wipe…"),
        Binding("h", "headless", "Headless"),
        Binding("e", "rename", "Rename…"),
        Binding("x", "stop", "Stop…"),
        Binding("R", "restart", "Restart"),
        Binding("a", "connect", "adb connect…"),
        Binding("ctrl+r", "refresh", "Refresh"),
        Binding("tab", "switch_table", "Other list"),
        Binding("j", "cursor('down')", "Down", show=False),
        Binding("k", "cursor('up')", "Up", show=False),
        Binding("escape", "cancel", "Close"),
        Binding("ctrl+c", "abort", "Quit", show=False),
    ]

    def __init__(
        self,
        mode: Literal["startup", "session"] = "session",
        reason: str = "",
        collect: Callable[..., HubSnapshot] | None = None,
        actions: Any = None,
    ) -> None:
        super().__init__()
        self.mode = mode
        self.reason = reason
        self._collector: HubCollector | None = None
        if collect is None:
            self._collector = HubCollector()
            collect = self._collector.collect
        self._collect_fn = collect
        self._actions = actions
        self.snapshot: HubSnapshot | None = None
        #: Row key -> what is being done to it ("stopping…").
        self._busy: dict[str, str] = {}
        self._in_flight = False
        self._pending = False
        self._pending_force = False
        self._first_apply = True
        self._monitor: Any = None
        self._last_backstop = time.monotonic()
        #: ``time.monotonic()`` when the shown snapshot was applied.
        self._applied_at = time.monotonic()

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="hub") as hub:
            hub.border_title = "Devices"
            if self.reason:
                yield Static(self.reason, id="hub-reason", markup=False)
            running = _RunningTable(id="hub-running", cursor_type="row")
            running.border_title = "Running"
            yield running
            yield Static("", id="hub-running-empty", classes="hub-empty")
            avds = _AvdTable(id="hub-avds", cursor_type="row")
            avds.border_title = "Available AVDs"
            yield avds
            yield Static("", id="hub-avds-empty", classes="hub-empty")
            yield Static("", id="hub-spacer")
            yield Static("", id="hub-detail")
            yield Static("", id="hub-notes")
        yield Footer()

    def on_mount(self) -> None:
        running = self.query_one("#hub-running", DataTable)
        running.add_column(" ", key="mark", width=1)
        running.add_column("Serial", key="serial")
        running.add_column("AVD / device", key="name")
        running.add_column("Model", key="model")
        running.add_column("API", key="api")
        running.add_column("State", key="state")
        running.add_column("Root", key="root")
        running.add_column("", key="active")
        avds = self.query_one("#hub-avds", DataTable)
        avds.add_column(" ", key="mark", width=1)
        avds.add_column("AVD", key="name")
        avds.add_column("API", key="api")
        avds.add_column("Image", key="tag")
        avds.add_column("Snapshots", key="snapshots")
        avds.add_column("Launch", key="launch")
        self.query_one("#hub-running-empty", Static).update("Looking for devices…")
        self.query_one("#hub-avds-empty", Static).display = False
        running.focus()
        if self.monitor_factory is not None:
            try:
                self._monitor = self.monitor_factory(on_change=self._on_adb_change)
                self._monitor.start()
            except Exception:
                logger.debug("Devices screen: no adb monitor", exc_info=True)
                self._monitor = None
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            logger.debug("Devices screen: no theme signal", exc_info=True)
        self.set_interval(1.0, self._tick)
        self.set_interval(self.BOOT_POLL_SECONDS, self._boot_poll)
        self.request_refresh(force_avds=True)

    def on_unmount(self) -> None:
        monitor, self._monitor = self._monitor, None
        if monitor is not None:
            # stop() joins the reader thread, which may be waiting for the UI
            # thread inside call_from_thread: never join on the UI thread.
            threading.Thread(target=monitor.stop, daemon=True).start()

    # -- refresh (UI thread) -------------------------------------------------

    def _on_adb_change(self) -> None:
        """Reader thread of the adb monitor: something was (un)plugged."""
        try:
            self.app.call_from_thread(self.request_refresh)
        except Exception:
            pass

    def request_refresh(self, force_avds: bool = False) -> None:
        """Collect a fresh snapshot in a worker (coalesces bursts)."""
        if not self.is_attached:
            return
        self._last_backstop = time.monotonic()
        if self._in_flight:
            self._pending = True
            self._pending_force = self._pending_force or force_avds
            return
        self._in_flight = True
        self.run_worker(
            lambda: self._collect(force_avds),
            thread=True,
            group="devices-hub",
            exit_on_error=False,
        )

    def _collect(self, force_avds: bool) -> None:
        """Worker thread: run the collector, hand the result to the UI."""
        snap: HubSnapshot | None = None
        try:
            snap = self._collect_fn(force_avds=force_avds)
        except Exception:
            logger.exception("Devices screen: collecting devices failed")
        try:
            self.app.call_from_thread(self._collected, snap)
        except Exception:
            self._in_flight = False

    def _collected(self, snap: HubSnapshot | None) -> None:
        self._in_flight = False
        if snap is not None:
            self._apply(snap)
        if self._pending:
            force, self._pending, self._pending_force = (
                self._pending_force,
                False,
                False,
            )
            self.request_refresh(force_avds=force)

    def _boot_poll(self) -> None:
        snap = self.snapshot
        busy = (snap is not None and snap.booting) or bool(self._busy)
        stale = time.monotonic() - self._last_backstop >= self.BACKSTOP_SECONDS
        if busy or stale:
            self.request_refresh()

    def _tick(self) -> None:
        """Repaint the elapsed boot times (no adb)."""
        snap = self.snapshot
        if snap is None or not snap.booting or not self.is_attached:
            return
        table = self.query_one("#hub-running", DataTable)
        for row in snap.devices:
            if row.state is RowState.BOOTING and row.boot_elapsed is not None:
                try:
                    table.update_cell(row.key, "state", self._state_cell(row))
                except Exception:
                    pass
        self._update_detail()

    # -- rendering -----------------------------------------------------------

    def _elapsed(self, row: DeviceRow) -> float | None:
        if row.boot_elapsed is None:
            return None
        return row.boot_elapsed + max(0.0, time.monotonic() - self._applied_at)

    def _state_cell(self, row: DeviceRow) -> Text:
        busy = self._busy.get(row.key)
        if busy:
            return Text(busy, style=_c("title"))
        label = row.state.value
        if row.state is RowState.BOOTING:
            elapsed = format_elapsed(self._elapsed(row))
            label = f"booting {elapsed}".strip()
        elif row.state is RowState.OTHER:
            label = row.raw_state
        return Text(label, style=_c(_STATE_STYLE[row.state]))

    def _device_cells(self, row: DeviceRow) -> tuple[Any, ...]:
        dim = Text("–", style=_c("dim"))
        return (
            Text("●", style=_c("ok")) if row.active else Text(""),
            Text(row.serial, style="bold" if row.active else ""),
            Text(row.avd_name) if row.avd_name else dim,
            Text(row.model) if row.model else dim,
            Text(str(row.api)) if row.api else dim,
            self._state_cell(row),
            Text(row.root_kind) if row.root_kind else dim,
            Text("◀ active", style=f"bold {_c('ok')}") if row.active else Text(""),
        )

    def _avd_cells(self, row: AvdRow) -> tuple[Any, ...]:
        dim = Text("–", style=_c("dim"))
        busy = self._busy.get(row.key)
        if busy:
            launch = Text(busy, style=_c("title"))
        elif row.running_elsewhere:
            launch = Text("running elsewhere", style=_c("warn"))
        else:
            launch = Text(describe_options(row.options), style=_c("text"))
        name_style = (
            _c("dim") if row.running_elsewhere else "bold" if row.last_used else ""
        )
        return (
            Text("★", style=_c("warn")) if row.last_used else Text(""),
            Text(row.name, style=name_style),
            Text(str(row.api)) if row.api else dim,
            Text(row.tag) if row.tag else dim,
            Text(str(row.snapshot_count)) if row.snapshot_count else dim,
            launch,
        )

    @staticmethod
    def _fill(table: DataTable, rows: Sequence[Any], cells: Callable) -> None:
        """Replace *table*'s rows, keeping the cursor on the same row key."""
        keep = None
        if table.row_count:
            try:
                keep = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            except Exception:
                keep = None
        old_index = table.cursor_row
        table.clear()
        for row in rows:
            table.add_row(*cells(row), key=row.key)
        if not rows:
            return
        keys = [row.key for row in rows]
        index = (
            keys.index(keep.value)
            if keep is not None and keep.value in keys
            else old_index
        )
        table.move_cursor(row=max(0, min(index, len(rows) - 1)), animate=False)

    def _apply(self, snap: HubSnapshot) -> None:
        """Show *snap* (UI thread)."""
        if not self.is_attached:
            return
        if self.snapshot is None or snap.taken_at != self.snapshot.taken_at:
            self._applied_at = time.monotonic()  # boot_elapsed is as of now
        self.snapshot = snap
        running = self.query_one("#hub-running", DataTable)
        avds = self.query_one("#hub-avds", DataTable)
        self._fill(running, snap.devices, self._device_cells)
        self._fill(avds, snap.avds, self._avd_cells)
        booting = sum(1 for d in snap.devices if d.state is RowState.BOOTING)
        running.border_title = f"Running · {len(snap.devices)}" + (
            f" · {booting} booting" if booting else ""
        )
        elsewhere = sum(1 for a in snap.avds if a.running_elsewhere)
        avds.border_title = f"Available AVDs · {len(snap.avds) - elsewhere}" + (
            f" · {elsewhere} running elsewhere" if elsewhere else ""
        )
        running.display = bool(snap.devices)
        avds.display = bool(snap.avds)
        empty_running = self.query_one("#hub-running-empty", Static)
        empty_running.display = not snap.devices
        empty_running.update(
            "Running · none -- start an AVD below (⏎) or connect a device "
            "over the network (a)."
            if snap.avds
            else "Running · none -- plug in a device with USB debugging on, or "
            "connect one over the network (a)."
        )
        empty_avds = self.query_one("#hub-avds-empty", Static)
        empty_avds.display = not snap.avds
        empty_avds.update(
            "Available AVDs · none (create one in Android Studio's Device Manager)"
        )
        notes = self.query_one("#hub-notes", Static)
        notes.update(Text("\n".join(f"⚠ {n}" for n in snap.notes)))
        notes.display = bool(snap.notes)
        if self._first_apply:
            self._first_apply = False
            self._initial_cursor(snap)
        elif not running.display and self.focused is running:
            avds.focus()
        elif not avds.display and self.focused is avds and running.display:
            running.focus()
        self._update_detail()
        self.refresh_bindings()

    def _initial_cursor(self, snap: HubSnapshot) -> None:
        running = self.query_one("#hub-running", DataTable)
        avds = self.query_one("#hub-avds", DataTable)
        if snap.devices:
            index = next((i for i, d in enumerate(snap.devices) if d.active), 0)
            running.move_cursor(row=index, animate=False)
            running.focus()
        elif snap.avds:
            index = next((i for i, a in enumerate(snap.avds) if a.last_used), 0)
            avds.move_cursor(row=index, animate=False)
            avds.focus()

    def current_row(self) -> DeviceRow | AvdRow | None:
        """The highlighted row of the focused list."""
        snap = self.snapshot
        focused = self.focused
        if snap is None or not isinstance(focused, DataTable):
            return None
        rows: Sequence[Any] = snap.devices if focused.id == "hub-running" else snap.avds
        if not rows or not focused.row_count:
            return None
        index = focused.cursor_row
        return rows[index] if 0 <= index < len(rows) else None

    def _detail_text(self, row: DeviceRow | AvdRow | None) -> Text:
        if row is None:
            return Text("")
        if isinstance(row, AvdRow):
            parts = [describe_options(row.options)]
            facts = " · ".join(
                p
                for p in (
                    f"API {row.api}" if row.api else "",
                    row.tag,
                    row.abi,
                    row.device_name,
                )
                if p
            )
            text = Text()
            text.append(row.name, style=f"bold {_c('title')}")
            if facts:
                text.append(f"  {facts}", style=_c("dim"))
            if row.running_elsewhere:
                text.append(f"\n{RUNNING_ELSEWHERE_HELP}", style=_c("warn"))
                return text
            text.append("\n⏎ starts it with ", style=_c("text"))
            text.append(parts[0], style="bold")
            text.append(
                " (remembered). c cold boot · n from a snapshot · w wipe data · "
                "h headless on/off · e rename",
                style=_c("text"),
            )
            return text
        text = Text()
        text.append(row.title, style=f"bold {_c('title')}")
        text.append(f"  {row.serial}", style=_c("dim"))
        text.append("\n")
        if row.state is RowState.UNAUTHORIZED:
            text.append(UNAUTHORIZED_HELP, style=_c("warn"))
        elif row.state is RowState.NO_PERMISSIONS:
            text.append(NO_PERMISSIONS_HELP, style=_c("warn"))
        elif row.state is RowState.OFFLINE:
            text.append(OFFLINE_HELP, style=_c("warn"))
        elif row.state is RowState.BOOTING:
            elapsed = format_elapsed(self._elapsed(row))
            since = f" for {elapsed}" if elapsed else ""
            text.append(
                f"Booting{since} -- it can be attached once Android is ready.",
                style=_c("warn"),
            )
            if row.log_path:
                text.append(f"  log: {row.log_path}", style=_c("dim"))
        elif row.state is RowState.OTHER:
            text.append(f"adb state: {row.raw_state}", style=_c("dim"))
        elif row.active:
            text.append("The active device of this session.", style=_c("ok"))
        else:
            text.append("⏎ attaches it to this session.", style=_c("text"))
        if row.is_emulator and row.state is not RowState.UNAUTHORIZED:
            text.append("  x stop · R restart", style=_c("dim"))
        return text

    def _update_detail(self) -> None:
        try:
            detail = self.query_one("#hub-detail", Static)
        except Exception:
            return
        detail.update(self._detail_text(self.current_row()))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._update_detail()
        self.refresh_bindings()

    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
        self._update_detail()
        self.refresh_bindings()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        row = self.current_row()
        if isinstance(row, DeviceRow):
            self.action_attach()
        elif isinstance(row, AvdRow):
            self.action_start()

    # -- bindings ------------------------------------------------------------

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Show only the keys that apply to the highlighted row."""
        if action in _DEVICE_ACTIONS | _EMULATOR_ACTIONS | _AVD_ACTIONS:
            row = self.current_row()
            if action in _DEVICE_ACTIONS:
                return isinstance(row, DeviceRow)
            if action in _EMULATOR_ACTIONS:
                return isinstance(row, DeviceRow) and row.is_emulator
            if not isinstance(row, AvdRow):
                return False
            if row.running_elsewhere and action in _LOCKED_AVD_ACTIONS:
                return None  # shown, disabled
            if action == "snapshot" and not row.snapshot_count:
                return None  # shown, disabled
            return True
        return True

    def _get_actions(self) -> Any:
        if self._actions is not None:
            return self._actions
        return getattr(self.app, "_device_controller", None)

    def _call(self, method: str, key: str, busy: str, *args: Any, **kw: Any) -> None:
        """Run an action of the controller, showing *busy* on row *key*."""
        actions = self._get_actions()
        fn = getattr(actions, method, None)
        if fn is None:
            self.app.notify("Device actions are not available", severity="error")
            return
        if key in self._busy:
            # A second ⏎ / key while the first action still runs.
            self.app.notify(
                f"Already {self._busy[key] or 'busy'}", title="Devices", timeout=3
            )
            return
        self._busy[key] = busy
        self._repaint_busy()

        def done(ok: bool, message: str) -> None:
            self._action_done(key, ok, message)

        try:
            fn(*args, on_done=done, **kw)
        except Exception as e:
            logger.exception(f"Devices screen: {method} failed")
            self._action_done(key, False, f"{type(e).__name__}: {e}")

    def _action_done(self, key: str, ok: bool, message: str) -> None:
        """UI thread: an action finished (or its process started)."""
        if not self.is_attached:
            return
        self._busy.pop(key, None)
        if not ok:
            self.app.notify(message, title="Devices", severity="error", timeout=8)
        if self._collector is not None:
            self._collector.invalidate_avds()
        self._repaint_busy()
        self.request_refresh(force_avds=True)

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        """Re-render the rows: their Rich colors come from the theme's tokens."""
        self._repaint_busy()

    def _repaint_busy(self) -> None:
        if self.snapshot is not None:
            self._apply(self.snapshot)

    # -- actions -------------------------------------------------------------

    def action_cancel(self) -> None:
        """Esc: close without attaching (sync, see quit_controller)."""
        self.dismiss(None)

    def action_abort(self) -> None:
        """Ctrl+C: quit the app (in startup mode: abort the start)."""
        if self.mode == "startup":
            from sandroid.tui.screens.startup_screen import StartupScreen

            starter = next(
                (s for s in self.app.screen_stack if isinstance(s, StartupScreen)),
                None,
            )
            self.dismiss(None)
            if starter is not None:
                starter.action_abort()
            return
        request_quit = getattr(self.app, "action_request_quit", None)
        if request_quit is not None:
            request_quit()

    def action_refresh(self) -> None:
        if self._collector is not None:
            self._collector.invalidate_avds()
        self.request_refresh(force_avds=True)

    def action_switch_table(self) -> None:
        tables = [t for t in self.query(DataTable) if t.display and t.row_count]
        if not tables:
            return
        index = tables.index(self.focused) if self.focused in tables else -1
        tables[(index + 1) % len(tables)].focus()

    def action_cursor(self, direction: str) -> None:
        if isinstance(self.focused, DataTable):
            if direction == "down":
                self.focused.action_cursor_down()
            else:
                self.focused.action_cursor_up()

    def action_attach(self) -> None:
        row = self.current_row()
        if not isinstance(row, DeviceRow):
            return
        if row.state is RowState.READY:
            self.dismiss(row.serial)
            return
        hint = {
            RowState.BOOTING: "is still booting -- it can be attached once ready",
            RowState.UNAUTHORIZED: "is not authorized (see the help below)",
            RowState.NO_PERMISSIONS: "cannot be opened (see the help below)",
            RowState.OFFLINE: "is offline",
        }.get(row.state, f"is in state '{row.raw_state}'")
        self.app.notify(f"{row.title} {hint}", title="Devices", severity="warning")

    def _avd_row(self, *, startable: bool = True) -> AvdRow | None:
        """The highlighted AVD row (``None`` if it may not be started here)."""
        row = self.current_row()
        if not isinstance(row, AvdRow):
            return None
        if startable and row.running_elsewhere:
            self.app.notify(
                f"'{row.name}' is running elsewhere (it holds lock files)",
                title="Devices",
                severity="warning",
            )
            return None
        return row

    def _start(self, row: AvdRow, options: Any, label: str) -> None:
        self._call("start_avd", row.key, label, row.name, options)

    def action_start(self) -> None:
        row = self._avd_row()
        if row is not None:
            self._start(row, row.options, "starting…")

    def action_cold(self) -> None:
        row = self._avd_row()
        if row is not None:
            self._start(
                row, replace(row.options, boot="cold", snapshot=None), "cold boot…"
            )

    def action_snapshot(self) -> None:
        row = self._avd_row()
        if row is None:
            return
        from sandroid.core.emulator import avd_snapshots
        from sandroid.tui.modals.selection_modal import SelectionModal

        names = [s.name for s in avd_snapshots(row.name)]
        if not names:
            self.app.notify(f"'{row.name}' has no snapshots", severity="warning")
            return

        def picked(name: str | None) -> None:
            if name:
                opts = replace(row.options, boot="snapshot", snapshot=name)
                self._start(row, opts, f"loading {name}…")

        self.app.push_screen(
            SelectionModal(title=f"Start {row.name} from a snapshot", options=names),
            picked,
        )

    def action_wipe(self) -> None:
        row = self._avd_row()
        if row is None:
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        def confirmed(yes: bool | None) -> None:
            if yes:
                opts = replace(row.options, boot="wipe", snapshot=None)
                self._start(row, opts, "wiping…")

        self.app.push_screen(
            ConfirmModal(
                title=f"Wipe '{row.name}'?",
                message="Factory reset: all apps and data on this AVD are "
                "deleted, then it boots fresh.",
                yes_label="Wipe & start",
                no_label="Cancel",
                guard_typing=True,
            ),
            confirmed,
        )

    def action_headless(self) -> None:
        row = self._avd_row(startable=False)
        if row is None or row.options is None:
            return
        from sandroid.core.emulator import remember_launch

        options = replace(row.options, headless=not row.options.headless)
        remember_launch(row.name, options, make_last=False)
        if self.snapshot is not None:
            avds = tuple(
                replace(a, options=options) if a.name == row.name else a
                for a in self.snapshot.avds
            )
            self._apply(replace(self.snapshot, avds=avds))
        mode = "headless" if options.headless else "with a window"
        self.app.notify(f"'{row.name}' starts {mode} from now on", timeout=4)

    def action_rename(self) -> None:
        row = self._avd_row()
        if row is None:
            return
        from sandroid.tui.modals.input_modal import InputModal

        def renamed(new: str | None) -> None:
            new = (new or "").strip()
            if new and new != row.name:
                self._call("rename_avd", row.key, "renaming…", row.name, new)

        self.app.push_screen(
            InputModal(
                title=f"Rename AVD '{row.name}'",
                message="Letters, digits, '.', '_' and '-'; must start with a letter.",
                default=row.name,
                select_all=True,
            ),
            renamed,
        )

    def action_stop(self) -> None:
        row = self.current_row()
        if not isinstance(row, DeviceRow) or not row.is_emulator:
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        def confirmed(yes: bool | None) -> None:
            if yes:
                self._call("stop_emulator", row.key, "stopping…", row.serial)

        warning = (
            "\nIt is the active device: running tasks lose their device."
            if row.active
            else ""
        )
        self.app.push_screen(
            ConfirmModal(
                title=f"Stop {row.title}?",
                message=f"Shuts down emulator {row.serial} (emu kill).{warning}",
                yes_label="Stop",
                no_label="Cancel",
            ),
            confirmed,
        )

    def action_restart(self) -> None:
        row = self.current_row()
        if not isinstance(row, DeviceRow) or not row.is_emulator:
            return
        if not (row.active and self._session_busy()):
            self._call("restart_emulator", row.key, "restarting…", row.serial)
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        def confirmed(yes: bool | None) -> None:
            if yes:
                self._call("restart_emulator", row.key, "restarting…", row.serial)

        self.app.push_screen(
            ConfirmModal(
                title=f"Restart {row.title}?",
                message=f"Restarts emulator {row.serial} (same AVD and port).\n"
                "It is the active device: running tasks lose their device.",
                yes_label="Restart",
                no_label="Cancel",
            ),
            confirmed,
        )

    def _session_busy(self) -> bool:
        """True while the session runs tasks or has a spotlight app."""
        check = getattr(self.app, "_has_active_session", None)
        try:
            return bool(check()) if callable(check) else False
        except Exception:
            return False

    def action_connect(self) -> None:
        from sandroid.tui.modals.input_modal import InputModal

        def entered(address: str | None) -> None:
            address = (address or "").strip()
            if address:
                self._call("connect", f"connect:{address}", "", address)

        self.app.push_screen(
            InputModal(
                title="adb connect",
                message="Network address of a device with wireless debugging "
                "(port 5555 if omitted). Pair it once with `adb pair` first.",
                placeholder="192.168.1.20:5555",
            ),
            entered,
        )


__all__ = [
    "NO_PERMISSIONS_HELP",
    "RUNNING_ELSEWHERE_HELP",
    "UNAUTHORIZED_HELP",
    "AvdRow",
    "DeviceRow",
    "DevicesScreen",
    "HubCollector",
    "HubSnapshot",
    "RowState",
    "SerialProbe",
    "build_snapshot",
    "classify",
    "describe_options",
    "format_elapsed",
]
