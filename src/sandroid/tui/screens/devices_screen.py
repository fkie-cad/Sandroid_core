"""Devices screen: every device and every installed AVD in one live list.

One screen replaces the old device / AVD / boot-mode pickers. Two boxes:

* **Devices** -- one list, each AVD exactly once: running devices first
  (what ``adb devices -l`` lists plus emulators Sandroid is still launching;
  physical and network devices included, with booting / ready / offline /
  unauthorized / no-permissions states), then the stopped AVDs, then AVDs
  running elsewhere (another session holds their lock files). ⏎ attaches a
  ready device or starts a stopped AVD; ``x`` stops and ``R`` restarts an
  emulator (per serial, never by process name); ``e`` renames an AVD;
  ``P`` starts a stopped AVD as a persona (an identity profile's phone
  contents: its persona snapshot, else clean_8g and the persona stage
  builds it). A snapshot whose ``snapshot.pb`` (read only) records a failed
  load or another emulator build is marked on the row and named in the box.
* **Launch options** -- for the highlighted row. A stopped AVD's options
  are editable and saved for that AVD at once (``devices.json``): boot
  (quick / cold / a snapshot), headless, save state on exit and a one-off
  wipe; ⏎ starts with exactly what is shown. ``c`` / ``n`` / ``h`` / ``s``
  / ``w`` change them without leaving the list (the mouse works too). A
  running emulator shows, read-only, what it was started with -- what ``R``
  reuses. Physical devices show their state and what to do about it.

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
from textual.await_complete import AwaitComplete
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.content import Content
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import (
    Checkbox,
    DataTable,
    Footer,
    RadioButton,
    RadioSet,
    Select,
    Static,
)

from sandroid.core.adb_device_monitor import AdbDeviceMonitor
from sandroid.tui.key_display import format_key
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
#: Prefix of persona snapshots (``sandroid.world.persona.PERSONA_PREFIX``;
#: not imported: the world package is loaded only when a persona starts).
PERSONA_PREFIX = "sandroid_persona_"

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

UNPROBED_HELP = (
    "In use · not probed: this session is pinned to another serial, so this "
    "device was never asked anything -- it is most likely another session's "
    "(its AVD shows as running elsewhere). Enter attaches it only after you "
    "confirm."
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
    #: Online, but someone else's under a pin: never probed (shared lab).
    UNPROBED = "in use · not probed"
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
        launch_options: The options our launch used (``None`` when Sandroid
            did not start it in this session).
        saved_options: The remembered options of its AVD (what a restart
            of an emulator we did not launch uses); ``None`` if no AVD.
        persona: The persona our launch started it as (``meta.persona_id``).
        snapshot_warnings: ``(snapshot, why it may not load)`` of its AVD's
            snapshots (``snapshot.pb``, read only).
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
    launch_options: Any = None
    saved_options: Any = None
    persona: str = ""
    snapshot_warnings: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> str:
        return f"dev:{self.serial}"

    @property
    def network(self) -> bool:
        """Connected over the network (``host:port`` serial)."""
        return not self.is_emulator and ":" in self.serial

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
        snapshots: Names of its saved snapshots.
        port: Console port a start would use (``None``: unknown / none free).
        port_reason: Why: ``pinned``, ``last used`` or ``auto``.
        snapshot_warnings: ``(snapshot, why it may not load)`` per snapshot
            whose ``snapshot.pb`` records a failed load or another emulator
            build (read only).
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
    snapshots: tuple[str, ...] = ()
    port: int | None = None
    port_reason: str = ""
    snapshot_warnings: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> str:
        return f"avd:{self.name}"

    @property
    def persona_snapshots(self) -> tuple[str, ...]:
        """Its persona snapshots (``sandroid_persona_*``)."""
        return tuple(n for n in self.snapshots if n.startswith(PERSONA_PREFIX))


@dataclass(frozen=True)
class HubSnapshot:
    """Everything the Devices screen shows at one moment.

    Attributes:
        devices: Running devices, sorted by serial.
        avds: Installed AVDs that are not running (those running elsewhere
            last).
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

    @property
    def rows(self) -> tuple[DeviceRow | AvdRow, ...]:
        """The one list: running devices, stopped AVDs, AVDs elsewhere."""
        return (*self.devices, *self.avds)


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
    unprobed: Collection[str] = (),
    ports: dict[str, tuple[int, str]] | None = None,
    snapshot_warnings: dict[str, dict[str, str]] | None = None,
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
        unprobed: Serials deliberately not probed (someone else's devices
            under a pin): online ones show as :attr:`RowState.UNPROBED`,
            never as ready.
        ports: ``(port, reason)`` a start of each stopped AVD would use
            (:func:`~sandroid.core.emulator.preferred_console_port`).
        snapshot_warnings: Per AVD, ``{snapshot: why it may not load}``
            (:func:`~sandroid.core.snapshot_policy.snapshot_warnings`).

    Returns:
        The snapshot. Our launch not yet listed (or still offline) shows as
        booting with its elapsed time; a ``device`` that has not finished
        booting shows as booting; running AVDs are not offered as available;
        a launch whose process died during boot becomes a note naming its log.
    """
    from sandroid.core.emulator import options_from_prefs, serial_port

    known = known or {}
    warnings = snapshot_warnings or {}

    def warned(avd: str) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((warnings.get(avd) or {}).items())) if avd else ()

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
        if state is RowState.READY and probe is None and serial in unprobed:
            state = RowState.UNPROBED
        is_emulator = serial_port(serial) is not None
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
            is_emulator=is_emulator,
            active=serial == active_serial,
            ours=launch is not None,
            log_path=str(launch.log_path or "") if launch else "",
            launch_options=launch.options if launch else None,
            saved_options=(
                options_from_prefs(prefs, avd_name)
                if is_emulator and avd_name
                else None
            ),
            persona=_persona_of(launch),
            snapshot_warnings=warned(avd_name),
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
                launch_options=launch.options,
                saved_options=options_from_prefs(prefs, launch.avd),
                persona=_persona_of(launch),
                snapshot_warnings=warned(launch.avd),
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
    ports = ports or {}
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
                snapshots=tuple(getattr(info, "snapshots", ()) or ()),
                port=ports.get(info.name, (None, ""))[0],
                port_reason=ports.get(info.name, (None, ""))[1],
                snapshot_warnings=warned(info.name),
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


def _persona_of(launch: Any) -> str:
    """The persona a launch of ours started as (``""``: none)."""
    meta = getattr(launch, "meta", None) if launch is not None else None
    value = meta.get("persona_id") if isinstance(meta, dict) else None
    return value if isinstance(value, str) else ""


def format_elapsed(seconds: float | None) -> str:
    """``0:42`` / ``1:05:00`` (empty for ``None``)."""
    if seconds is None:
        return ""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def describe_options(options: Any) -> str:
    """Launch options in a few words (``window · quick boot``).

    Saving the state on exit and a one-off wipe are named only when set.
    """
    if options is None:
        return ""
    window = "headless" if options.headless else "window"
    boot = {
        "normal": "quick boot",
        "cold": "cold boot",
        "snapshot": f"snapshot {options.snapshot}",
    }.get(options.boot, options.boot)
    parts = [window, boot]
    if getattr(options, "save_on_exit", False):
        parts.append("saves state on exit")
    if getattr(options, "wipe_once", False):
        parts.append("wipe data")
    return " · ".join(parts)


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


def _vanished_pin_notes(info: Any) -> list[str]:
    """Notes for pinned snapshots of AVD *info* that vanished (once each).

    A pinned snapshot can still disappear outside Sandroid (``qemu-img
    snapshot -d`` or a removed folder while the AVD is stopped, a wipe):
    say so loudly, once, and add a timeline warning; never recreate it.
    """
    from sandroid.core import snapshot_policy as policy

    if getattr(info, "path", None) is None:
        return []  # folder not readable (fallback info, unmounted disk)
    try:
        gone = policy.vanished_pins(info.name, getattr(info, "snapshots", ()) or ())
    except Exception:
        logger.debug("Devices: pinned snapshot check failed", exc_info=True)
        return []
    notes = []
    for name in gone:
        text = (
            f"Pinned snapshot '{name}' of {info.name} is gone -- it was deleted "
            "outside Sandroid (or by a wipe)"
        )
        notes.append(text)
        try:
            from sandroid.core.timeline import get_timeline

            get_timeline().emit(
                "snapshot",
                "pin_lost",
                summary=text,
                data={"name": name, "avd": info.name},
                level="warn",
            )
        except Exception:
            logger.debug("timeline: pin_lost line failed", exc_info=True)
    return notes


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
        self._pin_notes: list[str] = []

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
            for info in avds:
                # Reported once by the policy; kept on this screen until it
                # closes so a 2 s refresh does not hide it at once.
                self._pin_notes.extend(_vanished_pin_notes(info))
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
        unprobed = {
            entry.serial
            for entry in entries
            if pinned and entry.serial != pinned and entry.serial not in ours
        }
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
        notes.extend(self._pin_notes)
        locked: set[str] = set()
        for info in avds:
            try:
                if emulator.avd_lock_files(info.name):
                    locked.add(info.name)
            except Exception:
                logger.debug(f"lock check of {info.name} failed", exc_info=True)
        prefs = emulator.load_launch_prefs()
        ports = self._start_ports(avds, locked, entries, launches, prefs)
        warnings = self._snapshot_warnings(avds, launches)
        with self._lock:
            probes = dict(self._probes)
            avd_names = {k: v for k, v in self._avd_names.items() if v}
        return build_snapshot(
            entries,
            probes,
            avd_names,
            avds,
            prefs,
            launches,
            active_serial,
            time.monotonic(),
            known=known,
            notes=notes,
            locked_avds=locked,
            unprobed=unprobed,
            ports=ports,
            snapshot_warnings=warnings,
        )

    @staticmethod
    def _snapshot_warnings(
        avds: Iterable[Any], launches: Iterable[Any]
    ) -> dict[str, dict[str, str]]:
        """Per AVD, why its snapshots may not load (``snapshot.pb``, read
        only): a recorded failed load, or another emulator build than the
        installed one -- or than the one our live launch of it runs.
        """
        from sandroid.core import emulator
        from sandroid.core import snapshot_policy as policy

        try:
            installed = emulator.installed_emulator()
        except Exception:
            installed = ("", "")
        running = {
            launch.avd: str(
                (getattr(launch, "info", None) or {}).get("emulator_build_id") or ""
            )
            for launch in launches
            if getattr(launch, "alive", False)
        }
        out: dict[str, dict[str, str]] = {}
        for info in avds:
            names = tuple(getattr(info, "snapshots", ()) or ())
            if getattr(info, "path", None) is None or not names:
                continue
            try:
                found = policy.snapshot_warnings(
                    info.name,
                    names,
                    installed=installed,
                    launch_build=running.get(info.name, ""),
                )
            except Exception:
                logger.debug(f"snapshot.pb check of {info.name} failed", exc_info=True)
                continue
            if found:
                out[info.name] = found
        return out

    @staticmethod
    def _start_ports(
        avds: Iterable[Any],
        locked: Collection[str],
        entries: Iterable[Any],
        launches: Iterable[Any],
        prefs: dict[str, Any],
    ) -> dict[str, tuple[int, str]]:
        """Console port (and why) a start of each startable AVD would use."""
        from sandroid.core import emulator

        serials = [entry.serial for entry in entries]
        serials += [launch.serial for launch in launches if launch.alive]
        taken = {port for serial in serials if (port := emulator.serial_port(serial))}
        ports: dict[str, tuple[int, str]] = {}
        for info in avds:
            if info.name in locked:
                continue
            try:
                ports[info.name] = emulator.preferred_console_port(
                    info.name, taken, prefs=prefs
                )
            except Exception:
                logger.debug(f"no console port for {info.name}", exc_info=True)
        return ports


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
    RowState.UNPROBED: "dim",
    RowState.OTHER: "dim",
}

#: Actions that need a row of the given kind (see ``check_action``).
_DEVICE_ACTIONS = frozenset({"attach"})
_EMULATOR_ACTIONS = frozenset({"stop", "restart"})
#: Launch-option keys: they edit the highlighted stopped AVD's options.
_OPTION_ACTIONS = frozenset({"cold", "snapshot", "headless", "save", "wipe"})
_AVD_ACTIONS = frozenset({"start", "rename", "persona"}) | _OPTION_ACTIONS

#: Boot radio button ids -> ``AvdLaunchOptions.boot``.
_BOOT_IDS = {"opt-quick": "normal", "opt-cold": "cold", "opt-snap": "snapshot"}
#: Option control ids -> (label, its key). The key is shown only while the
#: options can be edited.
_LABELS = {
    "opt-quick": ("Quick boot", ""),
    "opt-cold": ("Cold boot", "c"),
    "opt-snap": ("Snapshot", "n"),
    "opt-headless": ("Headless", "h"),
    "opt-save": ("Save state on exit", "s"),
    "opt-wipe": ("Wipe data, once", "w"),
}


def _label(control_id: str, with_key: bool) -> str:
    """Markup label of an option control (``Headless  h`` when editable)."""
    label, key = _LABELS[control_id]
    return f"{label}  [dim]{key}[/]" if with_key and key else label


class _HubTable(DataTable):
    """The Devices list, where a click only highlights.

    Selecting a row starts or attaches something, so a single (stray) click
    must never do it: ⏎ selects, and so does a second click on the row the
    previous click highlighted. Textual's own rule ("click the cell that has
    the cursor") also fired on the very first click when it hit the cell
    the screen had highlighted on its own.

    ⏎ has two footer labels, *Attach* (a running device) and *Start* (a
    stopped AVD); the screen's ``check_action`` decides which one shows.
    """

    BINDINGS = [
        Binding("enter", "attach_row", "Attach"),
        Binding("enter", "start_row", "Start"),
    ]

    _armed_row: int | None = None

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "attach_row":
            return self.screen.check_action("attach", parameters)
        if action == "start_row":
            return self.screen.check_action("start", parameters)
        return super().check_action(action, parameters)

    def action_attach_row(self) -> None:
        self.action_select_cursor()

    def action_start_row(self) -> None:
        self.action_select_cursor()

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


class _BootRadios(RadioSet, can_focus=False):
    """Boot mode; clicked or set with ``c`` / ``n`` (the list keeps focus)."""


class _Radio(RadioButton):
    """A boot mode drawn as ``(•)`` / ``( )``: readable on any background."""

    @property
    def _button(self) -> Content:
        style = self.get_visual_style("toggle--button")
        return Content.assemble(("(" + ("•" if self.value else " ") + ")", style))


class _Option(Checkbox, can_focus=False):
    """A launch option drawn as ``[x]`` / ``[ ]``; clicked or toggled with
    its key (focus stays on the list).
    """

    @property
    def _button(self) -> Content:
        style = self.get_visual_style("toggle--button")
        return Content.assemble(("[" + ("x" if self.value else " ") + "]", style))


def _snapshot_prompt(row: DeviceRow | AvdRow) -> str:
    """What the snapshot Select shows while no snapshot is chosen.

    "no snapshots" only for an AVD that really has none; a running device
    row does not know its AVD's snapshots, so it claims nothing.
    """
    if not isinstance(row, AvdRow):
        return "snapshot"
    count = row.snapshot_count or len(row.snapshots)
    if not count:
        return "no snapshots"
    return f"{count} snapshot{'s' if count != 1 else ''}"


class DevicesScreen(ModalScreen[str | None]):
    """Full-screen live list of devices and AVDs plus the launch options.

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
    DevicesScreen .hub-box {
        width: 100%;
        background: $lens-panel;
        border: round $lens-rule;
        border-title-color: $lens-accent;
        border-title-style: bold;
        border-subtitle-color: $lens-muted;
        padding: 0 1;
    }
    DevicesScreen #hub {
        height: 1fr;
        min-height: 7;
    }
    DevicesScreen #hub-reason {
        color: $lens-warn;
        height: auto;
        margin: 0 0 1 0;
    }
    DevicesScreen DataTable {
        height: 1fr;
        border: none;
        background: $lens-panel;
        scrollbar-size-vertical: 1;
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
    DevicesScreen #hub-empty {
        color: $lens-dim;
        height: auto;
        padding: 1 1;
    }
    DevicesScreen #hub-notes {
        height: auto;
        color: $lens-warn;
        padding: 0 1;
    }
    DevicesScreen #hub-options {
        height: auto;
        margin: 1 0 0 0;
    }
    DevicesScreen #opt-row {
        height: auto;
        margin: 0 0 1 0;
    }
    DevicesScreen .opt-col {
        width: auto;
        height: auto;
        margin: 0 3 0 0;
    }
    DevicesScreen .opt-heading {
        color: $lens-header;
        height: 1;
    }
    DevicesScreen #opt-boot {
        border: none;
        background: transparent;
        padding: 0;
        width: auto;
        height: auto;
    }
    DevicesScreen #hub-options ToggleButton {
        border: none;
        background: transparent;
        padding: 0;
        height: 1;
        width: auto;
        color: $lens-text;
    }
    DevicesScreen #hub-options ToggleButton > .toggle--button {
        background: transparent;
        color: $lens-dim;
    }
    DevicesScreen #hub-options ToggleButton.-on > .toggle--button {
        background: transparent;
        color: $lens-ok;
        text-style: bold;
    }
    DevicesScreen #hub-options ToggleButton > .toggle--label {
        background: transparent;
    }
    DevicesScreen #hub-options ToggleButton:hover > .toggle--label {
        background: $lens-cursor;
    }
    DevicesScreen #hub-options ToggleButton:disabled,
    DevicesScreen #hub-options ToggleButton:disabled > .toggle--button,
    DevicesScreen #hub-options ToggleButton.-on:disabled > .toggle--button {
        color: $lens-label;
    }
    DevicesScreen #hub-options #opt-wipe.-on,
    DevicesScreen #hub-options #opt-wipe.-on > .toggle--button {
        color: $lens-warn;
    }
    DevicesScreen #opt-snapshot {
        width: 26;
        margin: 0 0 0 4;
    }
    DevicesScreen #opt-facts {
        width: 1fr;
        height: auto;
        color: $lens-dim;
    }
    DevicesScreen #opt-note {
        height: auto;
        color: $lens-text;
    }
    DevicesScreen Footer {
        background: $lens-action-bg;
    }
    """

    BINDINGS = [
        Binding("c", "cold", "Cold"),
        Binding("n", "snapshot", "Snapshot…"),
        Binding("h", "headless", "Headless"),
        Binding("s", "save", "Save state"),
        Binding("w", "wipe", "Wipe"),
        Binding("e", "rename", "Rename…"),
        Binding("p", "pins", "Pins…"),
        Binding("P", "persona", "Start as persona…"),
        Binding("x", "stop", "Stop…"),
        Binding("R", "restart", "Restart"),
        Binding("a", "connect", "Connect…"),
        Binding("ctrl+r", "refresh", "Refresh"),
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
        #: AVDs whose next start wipes their data (never persisted).
        self._wipe: set[str] = set()
        self._in_flight = False
        self._pending = False
        self._pending_force = False
        self._first_apply = True
        self._monitor: Any = None
        self._last_backstop = time.monotonic()
        #: ``time.monotonic()`` when the shown snapshot was applied.
        self._applied_at = time.monotonic()
        #: Snapshot names the Select currently offers.
        self._select_names: tuple[str, ...] | None = None
        #: A dismiss that came in while the screen was still mounting.
        self._dismiss_deferred = False

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="hub", classes="hub-box") as hub:
            hub.border_title = "Devices"
            if self.reason:
                yield Static(self.reason, id="hub-reason", markup=False)
            yield _HubTable(id="hub-table", cursor_type="row")
            yield Static("", id="hub-empty")
            yield Static("", id="hub-notes")
        with Vertical(id="hub-options", classes="hub-box") as box:
            box.border_title = "Launch options"
            with Horizontal(id="opt-row"):
                with Vertical(classes="opt-col"):
                    yield Static("Boot", classes="opt-heading")
                    with _BootRadios(id="opt-boot", compact=True):
                        yield _Radio(_label("opt-quick", True), id="opt-quick")
                        yield _Radio(_label("opt-cold", True), id="opt-cold")
                        yield _Radio(_label("opt-snap", True), id="opt-snap")
                    yield Select(
                        [],
                        prompt="no snapshots",
                        allow_blank=True,
                        compact=True,
                        id="opt-snapshot",
                    )
                with Vertical(classes="opt-col"):
                    yield Static("Options", classes="opt-heading")
                    for option_id in ("opt-headless", "opt-save", "opt-wipe"):
                        yield _Option(
                            _label(option_id, True), id=option_id, compact=True
                        )
                yield Static("", id="opt-facts")
            yield Static("", id="opt-note")
        yield Footer()

    def dismiss(self, result: str | None = None) -> AwaitComplete:
        """Close with *result*; while still mounting, once it has mounted.

        Popping the screen mid-mount prunes the snapshot ``Select`` between
        its compose and its Mount, and Textual's ``Select._on_mount`` then
        raises ``NoMatches`` for its ``SelectOverlay`` -- which crashes the
        app. A reconnect, Esc or a ready emulator can dismiss that early.
        """
        if self.is_mounted:
            return super().dismiss(result)
        if not self._dismiss_deferred:
            self._dismiss_deferred = True
            # The screen's own queue runs only once it has mounted.
            self.call_later(self._deferred_dismiss, result)
        return AwaitComplete()

    def _deferred_dismiss(self, result: str | None) -> None:
        try:
            on_top = self.app.screen is self
        except Exception:
            on_top = False
        if on_top:  # pop_screen pops whatever is on top
            super().dismiss(result)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#hub-table", DataTable)
        except NoMatches:
            return  # dismissed before it mounted
        table.add_column(" ", key="mark", width=1)
        table.add_column("Name", key="name")
        table.add_column("API", key="api")
        table.add_column("State", key="state")
        table.add_column("Root", key="root")
        table.add_column("Serial", key="serial")
        table.display = False
        self.query_one("#hub-empty", Static).update("Looking for devices…")
        self.query_one("#hub-options").display = False
        table.focus()
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
        table = self.query_one("#hub-table", DataTable)
        for row in snap.devices:
            if row.state is RowState.BOOTING and row.boot_elapsed is not None:
                try:
                    table.update_cell(row.key, "state", self._state_cell(row))
                except Exception:
                    pass
        row = self.current_row()
        if isinstance(row, DeviceRow) and row.state is RowState.BOOTING:
            self.query_one("#opt-note", Static).update(self._note_text(row))

    # -- rendering -----------------------------------------------------------

    def _elapsed(self, row: DeviceRow) -> float | None:
        if row.boot_elapsed is None:
            return None
        return row.boot_elapsed + max(0.0, time.monotonic() - self._applied_at)

    def _state_cell(self, row: DeviceRow | AvdRow) -> Text:
        """The State cell: a status dot plus the word, in the state colour
        (● up, ○ stopped, ◌ pending). Failure states (offline,
        unauthorized, no permissions, adb's raw words) get no dot.
        """
        busy = self._busy.get(row.key)
        if busy:
            return Text(f"◌ {busy}", style=_c("title"))
        if isinstance(row, AvdRow):
            if row.running_elsewhere:
                return Text("● running elsewhere", style=_c("warn"))
            return Text("○ stopped", style=_c("dim"))
        if row.active:
            return Text("● ready, active", style=f"bold {_c('ok')}")
        label = row.state.value
        if row.state is RowState.READY:
            label = f"● {label}"
        elif row.state is RowState.BOOTING:
            elapsed = format_elapsed(self._elapsed(row))
            label = f"◌ booting {elapsed}".strip()
        elif row.state is RowState.OTHER:
            label = row.raw_state
        elif row.state is RowState.UNPROBED:
            label = "in use · ◌ not probed" if row.is_emulator else "◌ not probed"
        return Text(label, style=_c(_STATE_STYLE[row.state]))

    def _cells(self, row: DeviceRow | AvdRow) -> tuple[Any, ...]:
        dim = Text("–", style=_c("dim"))
        if isinstance(row, AvdRow):
            # The State column says it in words and colour; the mark column
            # keeps only the last-used star (the user's exception to the
            # no-glyph rule).
            if row.running_elsewhere:
                mark, name_style = Text(""), _c("dim")
            else:
                mark = Text("★" if row.last_used else "", style=_c("dim"))
                name_style = "bold" if row.last_used else ""
            name = Text(row.name, style=name_style)
            if row.snapshot_warnings:
                name.append(" · snapshot warning", style=_c("warn"))
            return (
                mark,
                name,
                Text(str(row.api)) if row.api else dim,
                self._state_cell(row),
                dim,
                dim,
            )
        name = Text(row.title, style="bold" if row.active else "")
        if not row.is_emulator:
            name.append(" · network" if row.network else " · USB", style=_c("dim"))
        if row.persona:
            name.append(f" · persona {row.persona}", style=_c("dim"))
        return (
            Text(""),
            name,
            Text(str(row.api)) if row.api else dim,
            self._state_cell(row),
            Text(row.root_kind) if row.root_kind else dim,
            Text(row.serial, style=_c("dim")),
        )

    def _fill(self, table: DataTable, rows: Sequence[DeviceRow | AvdRow]) -> None:
        """Replace *table*'s rows, keeping the cursor on the same row.

        A stopped AVD that was just started keeps the cursor: its row
        becomes the running emulator of that AVD.
        """
        keep = None
        if table.row_count:
            try:
                keep = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            except Exception:
                keep = None
        old_index = table.cursor_row
        table.clear()
        for row in rows:
            table.add_row(*self._cells(row), key=row.key)
        if not rows:
            return
        keys = [row.key for row in rows]
        index = old_index
        if keep is not None and keep.value in keys:
            index = keys.index(keep.value)
        elif keep is not None and str(keep.value).startswith("avd:"):
            name = str(keep.value)[4:]
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if isinstance(row, DeviceRow) and row.avd_name == name
                ),
                old_index,
            )
        table.move_cursor(row=max(0, min(index, len(rows) - 1)), animate=False)

    def _apply(self, snap: HubSnapshot) -> None:
        """Show *snap* (UI thread)."""
        if not self.is_attached:
            return
        if self.snapshot is None or snap.taken_at != self.snapshot.taken_at:
            self._applied_at = time.monotonic()  # boot_elapsed is as of now
        self.snapshot = snap
        table = self.query_one("#hub-table", DataTable)
        rows = snap.rows
        self._fill(table, rows)
        running = len(snap.devices)
        booting = sum(1 for d in snap.devices if d.state is RowState.BOOTING)
        elsewhere = sum(1 for a in snap.avds if a.running_elsewhere)
        counts = [f"{running} connected"]
        if booting:
            counts.append(f"{booting} booting")
        counts.append(f"{len(snap.avds) - elsewhere} stopped")
        if elsewhere:
            counts.append(f"{elsewhere} elsewhere")
        self.query_one("#hub").border_title = "Devices · " + " · ".join(counts)
        table.display = bool(rows)
        empty = self.query_one("#hub-empty", Static)
        empty.display = not rows
        empty.update(
            "No devices and no AVDs. Plug in a device with USB debugging on, "
            "connect one over the network (a), or create an AVD in Android "
            "Studio's Device Manager."
        )
        notes = self.query_one("#hub-notes", Static)
        notes.update(Text("\n".join(f"⚠ {n}" for n in snap.notes)))
        notes.display = bool(snap.notes)
        if self._first_apply:
            self._first_apply = False
            self._initial_cursor(snap)
        self._sync_options()
        self.refresh_bindings()

    def _initial_cursor(self, snap: HubSnapshot) -> None:
        """The active device, else the first device, else the last-used AVD."""
        table = self.query_one("#hub-table", DataTable)
        mine = [
            i for i, d in enumerate(snap.devices) if d.state is not RowState.UNPROBED
        ]
        if mine:
            index = next((i for i in mine if snap.devices[i].active), mine[0])
        elif not snap.avds:
            index = 0
        else:
            index = next((i for i, a in enumerate(snap.avds) if a.last_used), 0)
        if snap.rows:
            table.move_cursor(row=index, animate=False)

    def current_row(self) -> DeviceRow | AvdRow | None:
        """The highlighted row of the list (whatever has the focus)."""
        snap = self.snapshot
        if snap is None:
            return None
        try:
            table = self.query_one("#hub-table", DataTable)
        except NoMatches:
            return None
        rows = snap.rows
        if not rows or not table.row_count:
            return None
        index = table.cursor_row
        return rows[index] if 0 <= index < len(rows) else None

    # -- the launch-options box -----------------------------------------------

    def _editable(self, row: Any = None) -> AvdRow | None:
        """The highlighted AVD if its options may be changed here."""
        row = self.current_row() if row is None else row
        if (
            isinstance(row, AvdRow)
            and not row.running_elsewhere
            and row.options is not None
        ):
            return row
        return None

    def _shown_options(self, row: DeviceRow | AvdRow) -> Any:
        """The options the box shows for *row* (``None``: no options)."""
        if isinstance(row, AvdRow):
            if row.options is None:
                return None
            return replace(row.options, wipe_once=row.name in self._wipe)
        if not row.is_emulator:
            return None
        return row.launch_options or row.saved_options

    def _sync_options(self) -> None:
        """Make the options box show the highlighted row (no events)."""
        try:
            box = self.query_one("#hub-options")
        except NoMatches:
            return
        row = self.current_row()
        box.display = row is not None
        if row is None:
            return
        options = self._shown_options(row)
        editable = self._editable(row) is not None
        if isinstance(row, AvdRow):
            title = f"Launch options · {row.name}"
            if row.running_elsewhere:
                title += " · read-only"
        elif row.is_emulator:
            title = f"Launch options · {row.title} · read-only"
        else:
            title = f"Device · {row.title} · {row.serial}"
        box.border_title = title
        controls = self.query_one("#opt-row")
        controls.display = options is not None
        if options is not None:
            self._set_controls(row, options, editable)
        self.query_one("#opt-facts", Static).update(self._facts_text(row))
        self.query_one("#opt-note", Static).update(self._note_text(row))

    def _set_controls(self, row: Any, options: Any, editable: bool) -> None:
        names = row.snapshots if isinstance(row, AvdRow) else ()
        select = self.query_one("#opt-snapshot", Select)
        select.prompt = _snapshot_prompt(row)
        if options.boot == "snapshot" and options.snapshot not in names:
            names = (*names, options.snapshot) if options.snapshot else names
        with self.prevent(
            RadioButton.Changed, RadioSet.Changed, Checkbox.Changed, Select.Changed
        ):
            if names != self._select_names:
                self._select_names = names
                select.set_options([(n, n) for n in names])
            # Every button explicitly: with RadioButton.Changed prevented the
            # RadioSet would not switch the others off.
            for button_id, boot in _BOOT_IDS.items():
                button = self.query_one(f"#{button_id}", RadioButton)
                button.value = options.boot == boot
            select.value = (
                options.snapshot
                if options.boot == "snapshot" and options.snapshot in names
                else Select.NULL
            )
            self.query_one("#opt-headless", Checkbox).value = bool(options.headless)
            self.query_one("#opt-save", Checkbox).value = bool(options.save_on_exit)
            self.query_one("#opt-wipe", Checkbox).value = bool(options.wipe_once)
        for widget in self.query("#opt-row RadioButton, #opt-row Checkbox"):
            if widget.disabled == editable:  # editability changed
                widget.label = _label(widget.id or "", editable)
            widget.disabled = not editable
        self.query_one("#opt-boot").disabled = not editable
        self.query_one("#opt-snap", RadioButton).disabled = not editable or not names
        # Lists the AVD's snapshots in every boot mode; pickable only for a
        # Snapshot boot (the Snapshot radio / ``n`` switch to it).
        select.disabled = not editable or not names or options.boot != "snapshot"

    def _facts_text(self, row: DeviceRow | AvdRow) -> Text:
        text = Text()
        if isinstance(row, AvdRow):
            facts = [
                f"API {row.api}" if row.api else "",
                row.tag,
                row.abi,
                row.device_name,
            ]
            count = row.snapshot_count or len(row.snapshots)
            facts.append(
                f"{count} snapshot{'s' if count != 1 else ''}"
                if count
                else "no snapshots"
            )
            personas = len(row.persona_snapshots)
            if personas:
                facts.append(
                    f"{personas} persona snapshot{'s' if personas != 1 else ''}"
                )
            if row.port is not None and not row.running_elsewhere:
                text.append(f"Port: {row.port} ({row.port_reason})\n")
            text.append(" · ".join(f for f in facts if f), style=_c("dim"))
            return text
        from sandroid.core.emulator import serial_port

        port = serial_port(row.serial)
        if port is not None:
            text.append(f"Port: {port}\n")
        facts = [
            f"API {row.api}" if row.api else "",
            f"root: {row.root_kind}" if row.root_kind else "",
            f"persona: {row.persona}" if row.persona else "",
            row.serial,
        ]
        if row.log_path:
            facts.append(f"log: {row.log_path}")
        text.append(" · ".join(f for f in facts if f), style=_c("dim"))
        return text

    def _note_text(self, row: DeviceRow | AvdRow) -> Text:
        """What the box says under the options (state, help, what ⏎ does)."""
        text = Text()
        if isinstance(row, AvdRow):
            if row.running_elsewhere:
                text.append(RUNNING_ELSEWHERE_HELP, style=_c("warn"))
                return text
            text.append("Enter starts it with these options", style=_c("text"))
            if row.name in self._wipe:
                text.append(" -- and wipes its data first (asks)", style=_c("warn"))
            text.append(". Changes are saved for this AVD at once; ", style=_c("text"))
            text.append("a wipe is never remembered.", style=_c("dim"))
            text.append(
                f"\n{format_key('P')} starts it as a persona (an identity "
                "profile's phone contents, loaded from its persona snapshot "
                "or built from clean_8g).",
                style=_c("dim"),
            )
            self._warning_lines(text, row.snapshot_warnings)
            return text
        help_text = {
            RowState.UNAUTHORIZED: UNAUTHORIZED_HELP,
            RowState.NO_PERMISSIONS: NO_PERMISSIONS_HELP,
            RowState.OFFLINE: OFFLINE_HELP,
            RowState.UNPROBED: UNPROBED_HELP,
        }.get(row.state)
        if help_text:
            text.append(help_text, style=_c("warn"))
            return text
        if row.state is RowState.BOOTING:
            elapsed = format_elapsed(self._elapsed(row))
            since = f" for {elapsed}" if elapsed else ""
            text.append(
                f"Booting{since} -- it can be attached once Android is ready.",
                style=_c("warn"),
            )
        elif row.state is RowState.OTHER:
            text.append(f"adb state: {row.raw_state}", style=_c("dim"))
        elif row.active:
            text.append("The active device of this session.", style=_c("ok"))
        else:
            text.append("Enter attaches it to this session.", style=_c("text"))
        if not row.is_emulator:
            kind = "Network device" if row.network else "Physical device"
            text.append(f"\n{kind}: no launch options.", style=_c("dim"))
            return text
        if row.persona:
            text.append(
                f"\nStarted as persona {row.persona}; the Identity lens refreshes it.",
                style=_c("text"),
            )
        if row.launch_options is not None:
            text.append(
                "\nStarted by Sandroid with these options; R restarts with them "
                "(never wipes).",
                style=_c("dim"),
            )
        elif row.saved_options is not None:
            text.append(
                f"\nStarted outside Sandroid (its options are unknown); these are "
                f"{row.avd_name}'s saved options, which R restarts with.",
                style=_c("dim"),
            )
        else:
            text.append(
                "\nStarted outside Sandroid; its AVD is not known yet.",
                style=_c("dim"),
            )
        self._warning_lines(text, row.snapshot_warnings)
        return text

    @staticmethod
    def _warning_lines(text: Text, warnings: Sequence[tuple[str, str]]) -> None:
        """One warning line per snapshot that may not load."""
        for name, why in warnings:
            text.append(f"\nSnapshot {name}: {why}.", style=_c("warn"))

    def _set_options(self, row: AvdRow, options: Any) -> None:
        """Save *options* for *row*'s AVD and show them (wipe stays local)."""
        from sandroid.core import emulator

        if options.wipe_once:
            self._wipe.add(row.name)
        else:
            self._wipe.discard(row.name)
        saved = replace(options, wipe_once=False)
        if saved != row.options:
            emulator.remember_launch(row.name, saved, make_last=False)
        if self.snapshot is not None:
            avds = tuple(
                replace(a, options=saved) if a.name == row.name else a
                for a in self.snapshot.avds
            )
            self._apply(replace(self.snapshot, avds=avds))
        else:
            self._sync_options()

    def _edit(self, **changes: Any) -> None:
        """Change the highlighted stopped AVD's options (key / mouse)."""
        row = self._editable()
        if row is None:
            self._sync_options()  # undo a click on a read-only control
            return
        current = self._shown_options(row)
        updated = replace(current, **changes)
        if updated.boot != "snapshot":
            updated = replace(updated, snapshot=None)
        if updated != current:
            self._set_options(row, updated)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        event.stop()
        boot = _BOOT_IDS.get(event.pressed.id or "", "normal")
        row = self._editable()
        if boot == "snapshot" and row is not None:
            current = self._shown_options(row)
            name = current.snapshot if current.snapshot in row.snapshots else None
            name = name or (row.snapshots[0] if row.snapshots else None)
            if name is None:
                self._sync_options()
                return
            self._edit(boot="snapshot", snapshot=name)
            return
        self._edit(boot=boot)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        field_name = {
            "opt-headless": "headless",
            "opt-save": "save_on_exit",
            "opt-wipe": "wipe_once",
        }.get(event.checkbox.id or "")
        if field_name:
            self._edit(**{field_name: bool(event.value)})

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        if isinstance(event.value, str):
            self._edit(boot="snapshot", snapshot=event.value)
        else:
            row = self._editable()
            if row is not None and self._shown_options(row).boot == "snapshot":
                self._edit(boot="normal")
        self._focus_list()

    def _focus_list(self) -> None:
        try:
            self.query_one("#hub-table", DataTable).focus()
        except NoMatches:
            pass

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._sync_options()
        self.refresh_bindings()

    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
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
            if row.running_elsewhere:
                return None  # shown, disabled
            if action == "snapshot" and not row.snapshots:
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
        """Esc: close an open snapshot list, else close without attaching.

        Sync on purpose (the app's priority Esc calls it, see quit_controller).
        """
        try:
            select = self.query_one("#opt-snapshot", Select)
        except NoMatches:
            select = None
        if select is not None and (select.expanded or self.focused is select):
            select.expanded = False
            self._focus_list()
            return
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

    def action_cursor(self, direction: str) -> None:
        table = self.query_one("#hub-table", DataTable)
        if direction == "down":
            table.action_cursor_down()
        else:
            table.action_cursor_up()

    def action_attach(self) -> None:
        row = self.current_row()
        if not isinstance(row, DeviceRow):
            return
        if row.state is RowState.READY:
            self.dismiss(row.serial)
            return
        if row.state is RowState.UNPROBED:
            self._confirm_foreign_attach(row)
            return
        hint = {
            RowState.BOOTING: "is still booting -- it can be attached once ready",
            RowState.UNAUTHORIZED: "is not authorized (see the help below)",
            RowState.NO_PERMISSIONS: "cannot be opened (see the help below)",
            RowState.OFFLINE: "is offline",
        }.get(row.state, f"is in state '{row.raw_state}'")
        self.app.notify(f"{row.title} {hint}", title="Devices", severity="warning")

    def _confirm_foreign_attach(self, row: DeviceRow) -> None:
        """⏎ on a device the pin rule never probed: attach only on "yes"."""
        from sandroid.core.device_manager import DeviceManager
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        pinned = DeviceManager.preferred_serial() or "another serial"

        def confirmed(yes: bool | None) -> None:
            if yes and self.is_attached:
                self.dismiss(row.serial)

        self.app.push_screen(
            ConfirmModal(
                title=f"Attach {row.serial}?",
                message=f"This session is pinned to {pinned}. {row.serial} is "
                "not pinned and was not probed: it is probably another "
                "session's device, whose work an attach can disturb.",
                yes_label="Attach anyway",
                no_label="Cancel",
            ),
            confirmed,
        )

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

    def action_start(self) -> None:
        """⏎ on a stopped AVD: start it with exactly the shown options."""
        row = self._avd_row()
        if row is None or row.options is None:
            return
        options = self._shown_options(row)
        if not options.wipe_once:
            self._call("start_avd", row.key, "starting…", row.name, options)
            return
        if row.key in self._busy:
            self._call("start_avd", row.key, "", row.name, options)  # "Already…"
            return
        from sandroid.tui.modals.confirm_modal import ConfirmModal

        def confirmed(yes: bool | None) -> None:
            if not yes:
                return
            self._wipe.discard(row.name)
            self._call("start_avd", row.key, "wiping…", row.name, options)
            self._sync_options()

        self.app.push_screen(
            ConfirmModal(
                title=f"Wipe '{row.name}'?",
                message="Factory reset: all apps and data on this AVD are "
                f"deleted, then it boots ({describe_options(options)}). The "
                "wipe is done once and not remembered.",
                yes_label="Wipe & start",
                no_label="Cancel",
                guard_typing=True,
            ),
            confirmed,
        )

    def action_persona(self) -> None:
        """``P``: start the highlighted stopped AVD as a persona.

        Lists the identity profiles with a world section (worker thread),
        then starts the AVD from the chosen profile's persona snapshot, or
        from clean_8g when there is none yet (the persona stage builds and
        saves it). Never saves on exit, never changes the AVD's remembered
        options.
        """
        row = self._avd_row()
        if row is None:
            return
        if row.key in self._busy:
            self.app.notify(
                f"Already {self._busy[row.key] or 'busy'}", title="Devices", timeout=3
            )
            return

        def work() -> None:
            from sandroid.world import persona

            try:
                result: Any = persona.persona_choices(row.name)
            except Exception as exc:
                result = exc
            self.app.call_from_thread(self._persona_choices, row, result)

        self.run_worker(work, thread=True, group="devices-persona", exit_on_error=False)

    def _persona_choices(self, row: AvdRow, result: Any) -> None:
        """UI thread: offer the personas (or say why there are none)."""
        if not self.is_attached:
            return
        if isinstance(result, Exception):
            self.app.notify(
                f"Could not list the identity profiles: {result}",
                title="Devices",
                severity="error",
                timeout=8,
            )
            return
        if not result:
            self.app.notify(
                "No identity profile has a world section (phone contents); "
                f"add one in the Identity lens ({format_key('P')}) first.",
                title="Devices",
                severity="warning",
                timeout=8,
            )
            return
        from sandroid.tui.modals.selection_modal import SelectionModal

        labels = {}
        for choice in result:
            saved = (
                f"{choice.snapshots} persona snapshot"
                f"{'s' if choice.snapshots != 1 else ''} saved"
                if choice.snapshots
                else "built from clean_8g on the first start"
            )
            labels[f"{choice.name} ({choice.id}) · {saved}"] = choice.id

        def picked(label: str | None) -> None:
            pid = labels.get(label or "")
            if pid and self.is_attached:
                self._start_persona(row, pid)

        self.app.push_screen(
            SelectionModal(
                title=f"Start {row.name} as a persona",
                options=list(labels),
                message="The persona snapshot of the profile as it is now is "
                "loaded; without one, clean_8g boots and the persona is built "
                "and saved (a few minutes). The state is never saved on exit.",
            ),
            picked,
        )

    def _start_persona(self, row: AvdRow, profile_id: str) -> None:
        """Work out the persona launch (worker), then start it."""
        options = self._shown_options(row)
        headless = bool(getattr(options, "headless", False))
        self._busy[row.key] = "preparing persona…"
        self._repaint_busy()

        def work() -> None:
            from sandroid.world import persona

            try:
                result: Any = persona.persona_start(
                    row.name, profile_id, api=row.api, headless=headless
                )
            except Exception as exc:
                result = exc
            self.app.call_from_thread(self._persona_ready, row, profile_id, result)

        self.run_worker(work, thread=True, group="devices-persona", exit_on_error=False)

    def _persona_ready(self, row: AvdRow, profile_id: str, start: Any) -> None:
        if not self.is_attached:
            return
        self._busy.pop(row.key, None)
        if isinstance(start, Exception):
            self._repaint_busy()
            self.app.notify(
                f"Cannot start {row.name} as persona {profile_id}: {start}",
                title="Devices",
                severity="error",
                timeout=8,
            )
            return
        how = (
            f"loading {start.snapshot}"
            if start.cached
            else "from clean_8g; the persona is built and saved after boot"
        )
        self.app.notify(
            f"Starting {row.name} as persona {profile_id}, {how}.",
            title="Devices",
            timeout=6,
        )
        self._call(
            "start_avd",
            row.key,
            "starting as persona…",
            row.name,
            start.options,
            meta=start.meta,
            remember=False,
        )

    def action_cold(self) -> None:
        """``c``: cold boot on / off (back to a quick boot)."""
        row = self._editable()
        if row is not None:
            cold = self._shown_options(row).boot != "cold"
            self._edit(boot="cold" if cold else "normal")

    def action_snapshot(self) -> None:
        """``n``: pick the snapshot to boot from."""
        row = self._editable()
        if row is None:
            return
        if not row.snapshots:
            self.app.notify(f"'{row.name}' has no snapshots", severity="warning")
            return
        from sandroid.tui.modals.selection_modal import SelectionModal

        def picked(name: str | None) -> None:
            if name and self._editable() == row:
                self._edit(boot="snapshot", snapshot=name)

        self.app.push_screen(
            SelectionModal(
                title=f"Boot {row.name} from a snapshot", options=list(row.snapshots)
            ),
            picked,
        )

    def action_headless(self) -> None:
        row = self._editable()
        if row is not None:
            self._edit(headless=not self._shown_options(row).headless)

    def action_save(self) -> None:
        row = self._editable()
        if row is not None:
            self._edit(save_on_exit=not self._shown_options(row).save_on_exit)

    def action_wipe(self) -> None:
        """``w``: wipe the data on the next start (asks then; not saved)."""
        row = self._editable()
        if row is not None:
            self._edit(wipe_once=row.name not in self._wipe)

    def action_pins(self) -> None:
        """``p``: pin or unpin a snapshot of the highlighted AVD.

        Pinned snapshots (``clean_8g`` and ``default_boot`` by default) can
        neither be overwritten nor deleted -- not by the Snapshots panel,
        Rewind or the AI. Unpinning asks first; the AI can never unpin.
        """
        row = self.current_row()
        avd = row.name if isinstance(row, AvdRow) else getattr(row, "avd_name", "")
        if not avd:
            return
        from sandroid.core import emulator
        from sandroid.core import snapshot_policy as policy
        from sandroid.tui.modals.selection_modal import SelectionModal

        try:
            names = [s.name for s in emulator.avd_snapshots(avd)]
        except Exception:
            names = list(getattr(row, "snapshots", ()) or ())
        pins = policy.pinned(avd)
        if not names:
            self.app.notify(f"'{avd}' has no snapshots", severity="warning")
            return

        def label(name: str) -> str:
            parts = [name]
            if name in pins:
                parts.append("pinned")
            owner = policy.owner_of(name)
            if owner is not None:
                parts.append(owner.label)
            return " · ".join(parts)

        def picked(name: str | None) -> None:
            if not name:
                return
            if name not in pins:
                policy.pin(avd, name)
                self.app.notify(
                    f"Pinned '{name}' on {avd}: it can't be overwritten or "
                    "deleted until you unpin it",
                    title="Devices",
                )
                return
            from sandroid.tui.modals.confirm_modal import ConfirmModal

            def confirmed(yes: bool | None) -> None:
                if yes:
                    policy.unpin(avd, name)
                    self.app.notify(f"Unpinned '{name}' on {avd}", title="Devices")

            self.app.push_screen(
                ConfirmModal(
                    title=f"Unpin '{name}'?",
                    message=(
                        f"'{name}' on {avd} can then be overwritten or deleted "
                        "again -- by the Snapshots panel, Rewind and the AI."
                    ),
                ),
                confirmed,
            )

        self.app.push_screen(
            SelectionModal(
                title=f"Pin or unpin a snapshot of {avd}",
                options=names,
                message="Pinned snapshots can't be overwritten or deleted.",
                display_func=label,
            ),
            picked,
        )

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
