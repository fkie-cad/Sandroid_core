"""Prepare: seed a generated world onto a clean device.

:func:`prepare` takes a device that runs the clean base snapshot
(``clean_8g``) and a :class:`~sandroid.world.manifest.WorldManifest`, and
writes the world's phone contents onto it:

1. Preflight: root, API level, free space, no world stamp; record what the
   base already holds (``clean_8g`` has a Google account with its contacts
   and calendars). Photos are fetched and processed on the host meanwhile.
2. Offline: Wi-Fi and mobile data off (the previous state is restored).
3. Backup and sync off: ``bmgr enable false``; automatic sync off for every
   Google account on the contacts and calendar authorities.
4. Contacts, calendar, call log and SMS through the world helper (one JVM).
5. Photos (EXIF rewritten on the host) and 6. files and notes: one push
   each, ``touch -d @epoch`` per file, then one media scan.
7. Ledger and stamp: every new row id is written to the host ledger as it
   arrives; the device stamp records the world and the ledger's hash.
8. Network restored; backup and sync re-verified.

The ledger also lists every item by its world id with its row id and a
hash of the row (``items``), so :func:`refresh` can later bring the device
to an edited world by removing and adding only what differs. :func:`topup`
adds the world's SMS, calls and events of the time since the anchor (a
loaded persona snapshot looks used today); the device stamp records each
top-up before its rows go in.

Run it from a worker thread (it blocks for minutes), never the UI thread.
Every adb call names the serial. The identity layer and the persona snapshot
are the caller's next steps (see :func:`persona_snapshot_name`).
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sandroid.core.adb_utils import SNAPSHOT_NAME_RE
from sandroid.world.content import file_bytes
from sandroid.world.helper import (
    DEVICE_DIR,
    Device,
    HelperClient,
    HelperError,
    chunked,
    ensure_jar,
)
from sandroid.world.photos import (
    PhotoError,
    ensure_photos,
    is_screenshot,
    photo_entries,
    plan_names,
    process_photo,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from sandroid.world.manifest import RenderedWorld, WorldManifest
    from sandroid.world.packs import PackSet

logger = logging.getLogger(__name__)

#: The device stamp (JSON, see :func:`stamp_record`).
STAMP_PATH = f"{DEVICE_DIR}/world.json"
STAMP_FORMAT = "sandroid-world-stamp"
LEDGER_FORMAT = "sandroid-world-ledger"
LEDGER_VERSION = 1
#: Ledger lists of provider rows (ids from the helper or MediaStore).
LEDGER_LISTS = ("contacts", "calendars", "events", "calls", "sms", "images")
#: Default SMS apps re-import new rows and ANR under load: stopped while seeding.
MESSAGING_PACKAGES = ("com.google.android.apps.messaging", "com.android.messaging")
GMS = "com.google.android.gms"
#: Sync authorities switched off for every Google account.
SYNC_AUTHORITIES = ("com.android.contacts", "com.android.calendar")
#: Account of OUR local calendar (type LOCAL: no sync adapter, no upload).
CALENDAR_ACCOUNT_TYPE = "LOCAL"
#: Tables whose highest _id preflight records: a killed run's rows above it
#: that the ledger never heard of are removed by a cleanup (guarded per table).
MAX_ID_TABLES = ("contacts", "calendars", "events", "calls", "sms")
#: The only device folders Prepare writes files to (and a cleanup removes from).
DEVICE_FILE_DIRS = (
    "/sdcard/DCIM/Camera/",
    "/sdcard/Pictures/Screenshots/",
    "/sdcard/Download/",
    "/sdcard/Documents/",
)
#: Seconds to wait for the device to have no active network after svc ... disable.
OFFLINE_WAIT_S = 20.0
OFFLINE_POLL_S = 0.5
#: Rows per helper request (a ledger write after each).
CHUNKS = {"contacts": 25, "events": 50, "calls": 100, "sms": 50}
#: Seconds per helper request.
CHUNK_TIMEOUT_S = 600.0
#: Free space needed besides the photos (KiB).
MIN_FREE_KIB = 64 * 1024
#: Warn when the device clock is this far off the host clock (the default anchor).
CLOCK_SKEW_WARN_S = 300
#: MediaStore datetaken may differ this much from our capture time (ms).
DATETAKEN_TOLERANCE_MS = 1500
#: Notes file name per language (Documents), default ``Notes.txt``.
NOTES_FILE = {"de": "Notizen.txt", "fr": "Notes.txt", "es": "Notas.txt",
              "it": "Note.txt", "pt": "Notas.txt", "tr": "Notlar.txt",
              "nl": "Notities.txt", "pl": "Notatki.txt"}  # fmt: skip

_PHONE_TYPES = {"home": 1, "landline": 1, "mobile": 2, "work": 3, "other": 7}
_CALL_TYPES = {"incoming": 1, "outgoing": 2, "missed": 3}
_ACCOUNT_RE = re.compile(r"Account \{name=(.+?), type=([^}]+)\}")


class PrepareError(RuntimeError):
    """Prepare refused or failed; :attr:`report` says how far it got."""

    def __init__(self, message: str, report: PrepareReport | None = None) -> None:
        super().__init__(message)
        self.report = report


# ------------------------------------------------------------------ report


@dataclass
class StepTiming:
    """One pipeline step: wall time, outcome and a short detail."""

    name: str
    seconds: float
    ok: bool = True
    detail: str = ""


@dataclass
class PrepareReport:
    """What :func:`prepare` did.

    Attributes:
        serial: The device.
        avd: The AVD name (None for a physical device).
        world_fp: The world.
        anchor: The anchor the world was rendered at (ISO 8601).
        ok: True when every step finished.
        error: Why it stopped (``ok`` False).
        steps: Timings per step, in order.
        expected: Items per list in the rendered world.
        seeded: Items per list that reached the device.
        preexisting: What the base held before (contacts, calendars, events,
            sms, calls, images, accounts).
        backup: ``bmgr`` (``off``/``on``/``unknown``), ``sync`` (``off`` or
            the rows still on), ``contacts_backup`` (``unconfirmed``,
            ``absent``).
        network: The Wi-Fi/data state before and after.
        warnings: Everything a person should know.
        ledger_path: The host ledger.
        stamp: The device stamp written.
        changes: What a :func:`refresh` added and removed, per list.
    """

    serial: str
    avd: str | None = None
    world_fp: str = ""
    anchor: str = ""
    ok: bool = False
    error: str = ""
    steps: list[StepTiming] = field(default_factory=list)
    expected: dict[str, int] = field(default_factory=dict)
    seeded: dict[str, int] = field(default_factory=dict)
    preexisting: dict[str, Any] = field(default_factory=dict)
    backup: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    ledger_path: str = ""
    stamp: dict[str, Any] = field(default_factory=dict)
    changes: dict[str, Any] = field(default_factory=dict)

    @property
    def seconds(self) -> float:
        """Total wall time of the steps."""
        return round(sum(s.seconds for s in self.steps), 2)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["seconds"] = self.seconds
        return out

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            logger.warning(f"world prepare: {msg}")
            self.warnings.append(msg)


# ------------------------------------------------------------------ ledger


def ledgers_dir() -> Path:
    """``$XDG_DATA_HOME/sandroid/world/ledgers``."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "sandroid" / "world" / "ledgers"


def device_key(serial: str, avd: str | None) -> str:
    """Folder name of a device's ledgers: the AVD name, else the serial."""
    raw = avd or serial
    return re.sub(r"[^A-Za-z0-9._-]", "_", raw).strip(".") or "device"


def ledger_path(serial: str, avd: str | None, world_fp: str) -> Path:
    """Host ledger of one world on one device."""
    return ledgers_dir() / device_key(serial, avd) / f"{world_fp}.json"


class Ledger:
    """Everything Prepare put on a device, written after every step.

    The JSON holds ``lists`` (provider row ids per list), ``paths`` (device
    files pushed) and ``pending`` (files about to be pushed), ``photos``
    (world id, device path, capture time), the calendar ``account``,
    ``max_ids`` (each table's highest _id before seeding), the network state
    before going offline, the ``anchor`` and ``state`` (``partial`` until the
    end).
    """

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        self.path = path
        self.data = data

    @classmethod
    def new(
        cls,
        path: Path,
        *,
        serial: str,
        avd: str | None,
        world_fp: str,
        anchor: str,
        account: dict[str, str] | None = None,
        max_ids: dict[str, int] | None = None,
    ) -> Ledger:
        return cls(
            path,
            {
                "format": LEDGER_FORMAT,
                "version": LEDGER_VERSION,
                "world_fp": world_fp,
                "serial": serial,
                "avd": avd,
                "anchor": anchor,
                "state": "partial",
                "started_at": _now_iso(),
                "finished_at": None,
                "account": account,
                "max_ids": dict(max_ids or {}),
                "lists": {name: [] for name in LEDGER_LISTS},
                "paths": [],
                "pending": [],
                "photos": [],
                "network_before": None,
            },
        )

    @classmethod
    def load(cls, path: Path) -> Ledger:
        """Read a ledger.

        Raises:
            ValueError: Not a world ledger.
        """
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("format") != LEDGER_FORMAT:
            raise ValueError(f"{path} is not a world ledger")
        return cls(path, data)

    def add(self, name: str, ids: list[int]) -> None:
        self.data["lists"].setdefault(name, []).extend(int(i) for i in ids)
        self.save()

    def add_pending(self, paths: list[str]) -> None:
        """Record files BEFORE they are pushed (a killed push leaves them)."""
        self.data.setdefault("pending", []).extend(paths)
        self.save()

    def add_paths(self, paths: list[str]) -> None:
        """Files that are on the device (no longer pending)."""
        done = set(paths)
        self.data["pending"] = [
            p for p in self.data.get("pending", []) if p not in done
        ]
        self.data["paths"].extend(paths)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8")
        tmp.replace(self.path)

    def to_json(self) -> str:
        return json.dumps(self.data, sort_keys=True, ensure_ascii=False, indent=1)

    def sha256(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    def counts(self) -> dict[str, int]:
        out = {k: len(v) for k, v in self.data["lists"].items()}
        out["paths"] = len(self.data["paths"])
        return out


def stamp_record(
    manifest: WorldManifest,
    *,
    state: str,
    anchor: str,
    ledger: Ledger,
    counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """The device stamp: which world, when, and the ledger's hash."""
    return {
        "format": STAMP_FORMAT,
        "state": state,
        "world_fp": manifest.world_fp,
        "generator_version": manifest.generator_version,
        "anchor": anchor,
        "prepared_at": _now_iso() if state == "complete" else None,
        "started_at": ledger.data.get("started_at"),
        "ledger_sha256": ledger.sha256() if state == "complete" else None,
        "counts": dict(counts or {}),
    }


def persona_snapshot_name(persona_id: str, world_fp: str, identity_fp: str) -> str:
    """Name of the persona snapshot of one persona, world and identity.

    ``sandroid_persona_<persona>_<world_fp[:12]>_<identity_fp[:12]>``; the
    persona id is reduced to ``[a-z0-9-]``.

    Raises:
        ValueError: An empty id or fingerprint.
    """
    slug = re.sub(r"[^a-z0-9-]+", "-", persona_id.lower()).strip("-")[:40]
    fps = [re.sub(r"[^0-9a-f]", "", x.lower())[:12] for x in (world_fp, identity_fp)]
    if not slug or not all(fps):
        raise ValueError("persona id, world_fp and identity_fp are required")
    name = f"sandroid_persona_{slug}_{fps[0]}_{fps[1]}"
    if not SNAPSHOT_NAME_RE.match(name):
        raise ValueError(f"invalid snapshot name {name!r}")
    return name


# ============================================================================
# INTEGRATION POINT (persona snapshot, sandroid-startup):
# Saving the persona snapshot needs sandroid-startup's snapshot namespace API
# (actor="persona", prefix "sandroid_persona_"), which does not exist yet.
# The caller runs, in this order: prepare() -> the identity layer
# (insight-privacy) -> save the snapshot under persona_snapshot_name(...).
# Wire the save here once that API lands; never save over clean_8g.
# ============================================================================


def write_device_stamp(dev: Device, record: dict[str, Any], tmp: Path) -> None:
    """Write the device stamp atomically (push to a temp file, then ``mv``).

    Raises:
        PrepareError: The stamp did not land.
    """
    local = tmp / "world.json"
    local.write_text(
        json.dumps(record, sort_keys=True, indent=1) + "\n", encoding="utf-8"
    )
    remote_tmp = f"{STAMP_PATH}.tmp"
    dev.shell(f"mkdir -p {DEVICE_DIR} && rm -f {remote_tmp}", zygote=False)
    res = dev.push([local], remote_tmp, timeout=60)
    out = dev.shell(
        f"chmod 644 {remote_tmp} && mv -f {remote_tmp} {STAMP_PATH} && echo stamped",
        zygote=False,
    ).out
    if "stamped" not in out:
        raise PrepareError(
            f"cannot write the world stamp: {(res.err or res.out).strip()[:200]}"
        )


# ------------------------------------------------------------------- utils


def _host_now() -> float:
    """The host's clock (Unix seconds): the default anchor."""
    return time.time()


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def world_timezone(manifest: WorldManifest, packs: PackSet | None = None) -> ZoneInfo:
    """The world's time zone: the country pack's first ``timezones`` entry."""
    if packs is None:
        from sandroid.world.packs import load_packs

        packs = load_packs()
    country = manifest.spec.get("country")
    zones: list[str] = []
    with contextlib.suppress(Exception):
        zones = list(packs.country(country).data.get("timezones") or [])
    for name in zones:
        with contextlib.suppress(ZoneInfoNotFoundError, ValueError):
            return ZoneInfo(name)
    return ZoneInfo("UTC")


def owner_language(manifest: WorldManifest, packs: PackSet) -> str:
    """The owner's language: the country's biggest language share (base tag)."""
    langs: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        langs = dict(
            packs.country(manifest.spec.get("country")).data.get("languages") or {}
        )
    if not langs:
        return ""
    best = max(sorted(langs.items()), key=lambda kv: float(kv[1] or 0))[0]
    return str(best).split("-")[0]


def _sections(text: str) -> dict[str, str]:
    """Split ``@@name@@`` delimited shell output (each marker on its own
    line: the scripts echo a newline before every marker).
    """
    out: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        m = re.fullmatch(r"@@([a-z_]+)@@", line.strip())
        if m:
            name = m.group(1)
            out[name] = ""
        elif name:
            out[name] += line + "\n"
    return {k: v.strip() for k, v in out.items()}


def _free_kib(df: str) -> int | None:
    """Available KiB from ``df -k <path>`` (the last data row; the mount
    point differs from the path, e.g. /sdcard -> /storage/emulated).
    """
    free = None
    for line in df.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[3].isdigit():
            free = int(parts[3])
    return free


def _q(text: str) -> str:
    return shlex.quote(text)


def device_file_ok(path: str) -> bool:
    """A file Prepare may write or remove: directly inside one of
    :data:`DEVICE_FILE_DIRS`, no ``..``, no NUL, already normalised.
    """
    if not isinstance(path, str) or "\0" in path or path != posixpath.normpath(path):
        return False
    for base in DEVICE_FILE_DIRS:
        if path.startswith(base):
            name = path[len(base) :]
            return bool(name) and "/" not in name and name not in (".", "..")
    return False


def safe_file_name(name: str) -> bool:
    """A world file name usable as one path component."""
    return (
        isinstance(name, str)
        and bool(name.strip())
        and "/" not in name
        and "\\" not in name
        and "\0" not in name
        and name not in (".", "..")
        and not name.startswith("..")
    )


# ---------------------------------------------------------------- payloads


def contact_items(world: RenderedWorld) -> list[dict[str, Any]]:
    """Helper ``contacts`` items (see :func:`contact_rows`)."""
    return [row for _key, row in contact_rows(world)]


def contact_rows(world: RenderedWorld) -> list[tuple[str, dict[str, Any]]]:
    """``(world id, helper item)`` of every contact: a raw contact (no
    account) plus data rows.

    The address book holds what the owner typed: a contact saved as "Mama"
    or "Dirk" has only that name. Given and family name go in only when the
    display name is exactly "given family" (the provider rebuilds the
    display name from them, which would turn "Mama" into the full name).
    """
    items = []
    for c in world.contacts:
        display = c.get("display_name") or ""
        given, family = c.get("given_name") or "", c.get("family_name") or ""
        name: dict[str, Any] = {
            "mimetype": "vnd.android.cursor.item/name",
            "data1": display,
        }
        if display == " ".join(x for x in (given, family) if x):
            if given:
                name["data2"] = given
            if family:
                name["data3"] = family
        rows = [name]
        for ph in c.get("phones") or []:
            rows.append(
                {
                    "mimetype": "vnd.android.cursor.item/phone_v2",
                    "data1": ph["number"],
                    "data2": _PHONE_TYPES.get(ph.get("type") or "", 2),
                }
            )
        if c.get("email"):
            rows.append(
                {
                    "mimetype": "vnd.android.cursor.item/email_v2",
                    "data1": c["email"],
                    "data2": 1,
                }
            )
        items.append(
            (
                str(c.get("id") or len(items)),
                {"raw": {"starred": 1 if c.get("starred") else 0}, "data": rows},
            )
        )
    return items


def calendar_create(world: RenderedWorld, tz: ZoneInfo) -> dict[str, Any]:
    """Columns of OUR local calendar."""
    return {
        "name": world.calendar_name,
        "calendar_displayName": world.calendar_name,
        "calendar_color": -16737844,
        "calendar_access_level": 700,
        "ownerAccount": world.calendar_name,
        "visible": 1,
        "sync_events": 1,
        "calendar_timezone": tz.key,
    }


def event_items(world: RenderedWorld, tz: ZoneInfo) -> list[dict[str, Any]]:
    """Helper ``calendar`` items (see :func:`event_rows`)."""
    return [row for _key, row in event_rows(world, tz)]


def event_rows(world: RenderedWorld, tz: ZoneInfo) -> list[tuple[str, dict[str, Any]]]:
    """``(world id, helper calendar item)`` of every event, by start. All-day
    events start at UTC midnight of their local date (the provider's rule);
    birthdays recur yearly.
    """
    out = []
    for ev in world.events:
        row: dict[str, Any] = {
            "title": ev["title"],
            "eventLocation": ev.get("location"),
            "availability": 0,
            "eventStatus": 1,
            "hasAlarm": 0,
        }
        if ev.get("all_day"):
            day = dt.datetime.fromtimestamp(ev["ts_ms"] / 1000, tz).date()
            start = dt.datetime.combine(day, dt.time(), tzinfo=dt.UTC)
            row.update(
                allDay=1, eventTimezone="UTC", dtstart=int(start.timestamp() * 1000)
            )
            if ev.get("recurrence") == "yearly":
                row.update(rrule="FREQ=YEARLY", duration="P1D")
            else:
                row["dtend"] = int((start + dt.timedelta(days=1)).timestamp() * 1000)
        else:
            row.update(
                allDay=0,
                eventTimezone=tz.key,
                dtstart=int(ev["ts_ms"]),
                dtend=int(ev["end_ms"]),
            )
        out.append((str(ev["id"]), {k: v for k, v in row.items() if v is not None}))
    out.sort(key=lambda kr: kr[1]["dtstart"])
    return out


def call_items(world: RenderedWorld) -> list[dict[str, Any]]:
    """Helper ``calls`` items (see :func:`call_rows`)."""
    return [row for _key, row in call_rows(world)]


def call_rows(world: RenderedWorld) -> list[tuple[str, dict[str, Any]]]:
    """``(world id, helper calls item)``, oldest first, with the cached
    contact name.
    """
    names = {
        ph["number"]: c.get("display_name")
        for c in world.contacts
        for ph in c.get("phones") or []
    }
    out = []
    for call in sorted(world.calls, key=lambda c: (c["ts_ms"], c["id"])):
        typ = _CALL_TYPES.get(call["type"], 1)
        row = {
            "number": call["number"],
            "type": typ,
            "date": int(call["ts_ms"]),
            "duration": 0 if typ == 3 else int(call.get("duration_s") or 0),
            "new": 0,
            "is_read": 1,
            "presentation": 1,
        }
        if names.get(call["number"]):
            row["name"] = names[call["number"]]
        out.append((str(call["id"]), row))
    return out


def sms_items(world: RenderedWorld) -> list[dict[str, Any]]:
    """Helper ``sms`` items (see :func:`sms_rows`)."""
    return [row for _key, row in sms_rows(world)]


def sms_rows(world: RenderedWorld) -> list[tuple[str, dict[str, Any]]]:
    """``(world id, helper sms item)``, oldest first."""
    out = []
    for m in sorted(world.sms, key=lambda s: (s["ts_ms"], s["id"])):
        sent = m.get("direction") == "sent"
        date = int(m["ts_ms"])
        out.append(
            (
                str(m["id"]),
                {
                    "address": m["address"],
                    "body": m["body"],
                    "date": date,
                    "date_sent": date if sent else date - 3000,
                    "type": 2 if sent else 1,
                    "read": 1 if sent or m.get("read", True) else 0,
                    "seen": 1,
                },
            )
        )
    return out


def row_hash(row: Any) -> str:
    """Short hash of a helper row (or any JSON value): what a refresh compares."""
    data = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def file_lines(f: Mapping[str, Any], tz: ZoneInfo) -> list[str]:
    """Text of a seeded file: its title and its date."""
    stem = Path(str(f["name"])).stem.replace("_", " ")
    when = dt.datetime.fromtimestamp(f["ts_ms"] / 1000, tz)
    return [stem, when.strftime("%Y-%m-%d")]


def notes_text(world: RenderedWorld, tz: ZoneInfo) -> tuple[str, int]:
    """The notes file (newest first) and its mtime (the newest note, ms)."""
    notes = sorted(world.notes, key=lambda n: -n["ts_ms"])
    parts = [
        f"{dt.datetime.fromtimestamp(n['ts_ms'] / 1000, tz):%Y-%m-%d}\n{n['text']}"
        for n in notes
    ]
    return "\n\n".join(parts) + "\n", (notes[0]["ts_ms"] if notes else 0)


# ---------------------------------------------------------------- pipeline


class _Run:
    """One prepare run (internal)."""

    def __init__(
        self,
        device: Device,
        manifest: WorldManifest,
        anchor: dt.datetime | None,
        progress: Callable[[str, int, int], None] | None,
        packs: PackSet | None,
        photos_cache: Path | None,
        force_cleanup: bool,
        workers: int,
    ) -> None:
        self.dev = device
        self.manifest = manifest
        self.anchor_in = anchor
        self.progress = progress or (lambda step, done, total: None)
        if packs is None:
            from sandroid.world.packs import load_packs

            packs = load_packs()
        self.packs = packs
        self.photos_cache = photos_cache
        self.force_cleanup = force_cleanup
        self.workers = workers
        self.report = PrepareReport(serial=device.serial, world_fp=manifest.world_fp)
        self.tz = world_timezone(manifest, packs)
        self.helper: HelperClient | None = None
        self.ledger: Ledger | None = None
        self.pre: dict[str, str] = {}
        self.accounts: list[dict[str, str]] = []
        self.network_before: dict[str, bool] | None = None
        self.tmp: Path | None = None
        self.photo_jobs: dict[str, concurrent.futures.Future] = {}
        self.pool: concurrent.futures.ThreadPoolExecutor | None = None
        self.cleanup_from: dict[str, Any] | None = None
        self.network_inherited: dict[str, bool] | None = None
        self.max_ids: dict[str, int] = {}
        self.online_done = False
        #: A :func:`refresh`: the device holds a complete world (``old_stamp``).
        self.refreshing = False
        self.old_stamp: dict[str, Any] | None = None

    # -- infrastructure

    @contextlib.contextmanager
    def step(self, name: str):
        t0 = time.monotonic()
        rec = StepTiming(name, 0.0)
        self.report.steps.append(rec)
        logger.info(f"world prepare [{self.dev.serial}]: {name}")
        try:
            yield rec
        except BaseException as exc:
            rec.ok = False
            rec.detail = rec.detail or str(exc)[:300]
            raise
        finally:
            rec.seconds = round(time.monotonic() - t0, 2)

    def shell(self, script: str, *, timeout: float = 60, zygote: bool = True) -> str:
        return self.dev.shell(script, timeout=timeout, zygote=zygote).out

    def write_stamp(self, record: dict[str, Any]) -> None:
        assert self.tmp is not None
        write_device_stamp(self.dev, record, self.tmp)
        self.report.stamp = record

    # -- 1. preflight

    def preflight(self) -> None:
        script = "\n".join(
            [
                "echo; echo @@uid@@; id -u",
                "echo; echo @@sdk@@; getprop ro.build.version.sdk",
                "echo; echo @@avd@@; getprop ro.boot.qemu.avd_name;"
                " getprop ro.kernel.qemu.avd_name",
                "echo; echo @@now@@; date +%s",
                "echo; echo @@df_sdcard@@; df -k /sdcard/ 2>/dev/null",
                "echo; echo @@df_data@@; df -k /data 2>/dev/null",
                f"echo; echo @@stamp@@; cat {STAMP_PATH} 2>/dev/null",
                "echo; echo @@wifi@@; settings get global wifi_on",
                "echo; echo @@data@@; settings get global mobile_data",
                "echo; echo @@accounts@@; dumpsys account 2>/dev/null"
                " | grep -E 'Account [{]name='",
                f"echo; echo @@gms@@; pm path {GMS} 2>/dev/null | head -n 1",
                "echo; echo @@end@@",
            ]
        )
        res = self.dev.shell(script, timeout=60, zygote=True)
        pre = _sections(res.out)
        if "end" not in pre:
            raise PrepareError(
                f"device {self.dev.serial} did not answer: "
                f"{(res.err or res.out).strip()[:200]}"
            )
        self.pre = pre
        r = self.report
        avd = next((x for x in pre.get("avd", "").splitlines() if x.strip()), None)
        r.avd = avd.strip() if avd else None
        if pre.get("uid") != "0":
            raise PrepareError("Prepare needs adb root (adb root)")
        sdk = int(pre["sdk"]) if pre.get("sdk", "").isdigit() else None
        want = self.manifest.target_sdk
        if want is not None and sdk != want:
            raise PrepareError(
                f"the world was made for API {want}, the device runs API {sdk}"
            )
        need_kib = MIN_FREE_KIB + self._photo_bytes() // 1024 * 2
        for mount in ("/sdcard", "/data"):
            free = _free_kib(pre.get(f"df_{mount.strip('/')}", ""))
            if free is None:
                r.warn(f"free space on {mount} unknown")
            elif free < need_kib:
                raise PrepareError(
                    f"{mount} has {free // 1024} MiB free, Prepare needs "
                    f"{need_kib // 1024} MiB"
                )
        self.accounts = [
            {"name": m.group(1), "type": m.group(2)}
            for m in _ACCOUNT_RE.finditer(pre.get("accounts", ""))
        ]
        self._check_stamp(pre.get("stamp", ""))
        self._anchor(pre.get("now", ""))

    def _photo_bytes(self) -> int:
        total = 0
        with contextlib.suppress(Exception):
            entries = {e["id"]: e for e in photo_entries(self.manifest, self.packs)}
            total = sum(
                int(entries[p["source"]].get("bytes") or 0)
                for p in self.manifest.photos
            )
        return total

    def _check_stamp(self, text: str) -> None:
        if not text.strip():
            if self.refreshing:
                raise PrepareError("the device holds no world to refresh")
            return
        try:
            stamp = json.loads(text)
        except ValueError:
            stamp = {"state": "unreadable"}
        state = stamp.get("state") if isinstance(stamp, dict) else "unreadable"
        if self.refreshing:
            if state != "complete" or stamp.get("format") != STAMP_FORMAT:
                raise PrepareError(
                    "a refresh needs a device that holds a complete world "
                    f"(the stamp says {state})"
                )
            self.old_stamp = stamp
            return
        if state == "complete":
            raise PrepareError(
                f"the device already holds world {str(stamp.get('world_fp'))[:12]}; "
                "Prepare needs a clean base (load clean_8g first)"
            )
        if state != "partial":
            raise PrepareError(
                f"unreadable world stamp {STAMP_PATH} on the device; "
                "load clean_8g instead"
            )
        if not self.force_cleanup:
            raise PrepareError(
                "an interrupted Prepare left a partial world on the device; "
                "re-run with force_cleanup=True or load clean_8g"
            )
        self.cleanup_from = stamp if isinstance(stamp, dict) else {}

    def _anchor(self, device_now: str) -> None:
        host = _host_now()
        if device_now.isdigit() and abs(int(device_now) - host) > CLOCK_SKEW_WARN_S:
            self.report.warn(
                f"the device clock is {(int(device_now) - host) / 60:+.0f} min off "
                "the host clock"
            )
        if self.anchor_in is not None:
            a = self.anchor_in
            a = a.replace(tzinfo=self.tz) if a.tzinfo is None else a.astimezone(self.tz)
        else:
            a = dt.datetime.fromtimestamp(int(host), dt.UTC).astimezone(self.tz)
        self.anchor = a.replace(microsecond=0)
        self.report.anchor = self.anchor.isoformat()

    def start_helper(self) -> None:
        try:
            ensure_jar(self.dev)
            self.helper = self.dev.helper(timeout=60)
        except HelperError as exc:
            raise PrepareError(str(exc)) from exc

    def record_preexisting(self) -> None:
        assert self.helper is not None
        totals = self.helper.request(
            "count",
            totals=[
                "contacts",
                "aggregates",
                "calendars",
                "events",
                "sms",
                "calls",
                "images",
            ],
            timeout=120,
        )["totals"]
        self.report.preexisting = {
            **totals,
            "accounts": [{"type": a["type"]} for a in self.accounts],
        }
        reply = self.helper.request("max_ids", tables=list(MAX_ID_TABLES), timeout=120)
        self.max_ids = {k: int(v) for k, v in reply["max"].items()}

    # -- cleanup of an interrupted run

    def cleanup(self) -> None:
        """Remove an interrupted run's world (``force_cleanup``).

        Its ledger must belong to the partial stamp (same world and start).
        The network state recorded before that run went offline becomes the
        state this run restores, whatever happens next. Rows by ledger id go
        first, then rows above the recorded max ids that the ledger missed
        (guarded per table), then the files (allow-listed folders only).
        """
        stamp = self.cleanup_from or {}
        fp = str(stamp.get("world_fp") or "")
        path = ledger_path(self.dev.serial, self.report.avd, fp) if fp else None
        if path is None or not path.is_file():
            raise PrepareError(
                "a partial world is on the device but its host ledger is missing; "
                "load clean_8g instead"
            )
        old = Ledger.load(path)
        if old.data.get("world_fp") != fp or old.data.get("started_at") != stamp.get(
            "started_at"
        ):
            raise PrepareError(
                "the host ledger does not belong to the partial world on the "
                "device (another run's); load clean_8g instead"
            )
        inherited = old.data.get("network_before")
        if isinstance(inherited, dict) and {"wifi", "data"} <= set(inherited):
            self.network_inherited = {
                "wifi": bool(inherited["wifi"]),
                "data": bool(inherited["data"]),
            }
            # From here on the network comes back even if this run fails
            # before it goes offline itself.
            self.network_before = dict(self.network_inherited)
        assert self.helper is not None
        account = old.data.get("account")
        lists = {k: v for k, v in old.data["lists"].items() if v and k != "images"}
        if lists:
            self.helper.request("delete", lists=lists, account=account, timeout=600)
        orphans: dict[str, int] = {}
        max_ids = old.data.get("max_ids") or {}
        if max_ids:
            reply = self.helper.request(
                "delete_above", max=max_ids, account=account, timeout=600
            )
            orphans = {k: int(v) for k, v in reply["deleted"].items() if int(v) > 0}
        files = list(old.data.get("paths") or []) + list(old.data.get("pending") or [])
        bad = [f for f in files if not device_file_ok(f)]
        if bad:
            self.report.warn(
                f"cleanup: {len(bad)} ledger paths outside the world folders were "
                f"left alone (e.g. {bad[0]!r})"
            )
        files = [f for f in files if device_file_ok(f)]
        for batch in chunked(files, 100):
            self.shell("rm -f " + " ".join(_q(p) for p in batch), zygote=False)
        if files:
            self._scan()
        self.shell(f"rm -f {STAMP_PATH}", zygote=False)
        old.data["state"] = "cleaned"
        old.save()
        self.report.warn(
            f"removed an interrupted world ({fp[:12]}): "
            + ", ".join(f"{k} {len(v)}" for k, v in sorted(lists.items()))
            + f", files {len(files)}"
            + (
                "; rows the ledger missed: "
                + ", ".join(f"{k} {v}" for k, v in sorted(orphans.items()))
                if orphans
                else ""
            )
        )

    # -- 2. offline / 8. online

    def go_offline(self) -> None:
        wifi = self.pre.get("wifi", "")
        data = self.pre.get("data", "")
        now = {"wifi": wifi not in ("0", ""), "data": data == "1"}
        # A killed run never reached its "online" step: restore what the
        # device had before THAT run, not the offline state it left behind.
        self.network_before = self.network_inherited or now
        self.report.network["before"] = dict(self.network_before)
        if self.network_inherited and self.network_inherited != now:
            self.report.network["found"] = now
            self.report.warn(
                f"an interrupted run left the network at {now}; it is restored "
                f"to {self.network_inherited}"
            )
        assert self.ledger is not None
        self.ledger.data["network_before"] = dict(self.network_before)
        self.ledger.save()
        res = self.dev.shell(
            "svc wifi disable; svc data disable", timeout=60, zygote=True
        )
        state = self.wait_offline()
        self.report.network["offline"] = state
        if state["wifi"] or state["data"] or state["default"] != "none":
            raise PrepareError(
                f"the device is still online after svc wifi/data disable ({state}; "
                f"svc rc {res.rc}{': ' + (res.err or res.out).strip()[:120] if res.rc else ''}"
                "); an ethernet or other link Prepare cannot turn off? Nothing was seeded"
            )

    def network_state(self) -> dict[str, Any]:
        """Wi-Fi and mobile-data settings plus the active default network
        (``none``, a net id, or ``unknown`` when dumpsys has no such line).
        """
        out = _sections(
            self.shell(
                "echo; echo @@wifi@@; settings get global wifi_on;"
                " echo; echo @@data@@; settings get global mobile_data;"
                " echo; echo @@default@@; dumpsys connectivity 2>/dev/null"
                " | grep -m 1 'Active default network'",
                timeout=60,
            )
        )
        m = re.search(r"Active default network:\s*(\S+)", out.get("default", ""))
        return {
            "wifi": out.get("wifi", "") not in ("0", ""),
            "data": out.get("data") == "1",
            "default": m.group(1) if m else "unknown",
        }

    def wait_offline(self) -> dict[str, Any]:
        """Poll :meth:`network_state` until nothing is up (or the wait ends)."""
        end = time.monotonic() + OFFLINE_WAIT_S
        while True:
            state = self.network_state()
            offline = not state["wifi"] and not state["data"]
            if offline and state["default"] == "none":
                return state
            if time.monotonic() >= end:
                return state
            time.sleep(OFFLINE_POLL_S)

    def restore_network(self) -> None:
        before = self.network_before
        if before is None:
            return
        cmds = []
        if before["wifi"]:
            cmds.append("svc wifi enable")
        if before["data"]:
            cmds.append("svc data enable")
        if cmds:
            self.shell("; ".join(cmds), timeout=60)
        out = _sections(
            self.shell(
                "echo; echo @@wifi@@; settings get global wifi_on;"
                " echo; echo @@data@@; settings get global mobile_data",
                timeout=30,
            )
        )
        after = {
            "wifi": out.get("wifi", "") not in ("0", ""),
            "data": out.get("data") == "1",
        }
        self.report.network["after"] = after
        if after != before:
            self.report.warn(
                f"network state after Prepare {after} differs from {before}"
            )

    # -- 3. backup and sync

    def backup_off(self) -> None:
        r = self.report
        self.shell("bmgr enable false", timeout=60)
        r.backup["bmgr"] = self._bmgr_state()
        if r.backup["bmgr"] != "off":
            raise PrepareError(f"Android backup is still {r.backup['bmgr']}")
        r.backup["sync"] = self._sync(off=True)
        if r.backup["sync"] != "off":
            raise PrepareError(f"automatic sync still on: {r.backup['sync']}")
        r.backup["contacts_backup"] = "unconfirmed" if self.pre.get("gms") else "absent"
        if self.pre.get("gms"):
            r.warn(
                "Google Contacts device-contacts backup: unconfirmed (it has no "
                "non-UI switch; sync is off and the device was offline while seeding)"
            )

    def _bmgr_state(self) -> str:
        out = self.shell("bmgr enabled", timeout=60).lower()
        if "disabled" in out:
            return "off"
        if "enabled" in out:
            return "on"
        return "unknown"

    def _sync(self, *, off: bool) -> str | list[dict[str, Any]]:
        assert self.helper is not None
        google = [a for a in self.accounts if a["type"] == "com.google"]
        if not google:
            return "off"
        state = self.helper.request(
            "sync_off" if off else "sync_state",
            accounts=google,
            authorities=list(SYNC_AUTHORITIES),
            timeout=60,
        )
        on = [
            {"type": row["type"], "authority": row["authority"]}
            for row in state.get("rows") or []
            if row.get("auto")
        ]
        return on or "off"

    def verify_backup_still_off(self) -> None:
        r = self.report
        bmgr = self._bmgr_state()
        sync = self._sync(off=False)
        r.backup["bmgr_after"] = bmgr
        r.backup["sync_after"] = sync
        if bmgr != "off":
            r.warn(f"Android backup is {bmgr} after Prepare")
        if sync != "off":
            r.warn(f"automatic sync came back on: {sync}")

    # -- 4. lists

    def _seed(self, name: str, rows: list[tuple[str, dict[str, Any]]], send) -> None:
        """Insert keyed helper ``rows``; each new row id goes to the ledger's
        list and, with the row's world id and hash, to its ``items`` map
        (what a later :func:`refresh` compares against).
        """
        r = self.report
        r.expected[name] = r.expected.get(name, 0) + len(rows)
        done = 0
        bad = 0
        assert self.ledger is not None
        keyed = self.ledger.data.setdefault("items", {}).setdefault(name, {})
        for batch in chunked(rows, CHUNKS.get(name, 50)):
            ids = send([row for _key, row in batch])
            good = []
            for (key, row), rid in zip(batch, ids, strict=False):
                if isinstance(rid, int) and rid > 0:
                    good.append(rid)
                    keyed[key] = [rid, row_hash(row)]
            bad += len(batch) - len(good)
            self.ledger.add(name, good)
            done += len(batch)
            self.progress(name, done, len(rows))
        r.seeded[name] = len(self.ledger.data["lists"][name])
        if bad:
            r.warn(f"{name}: {bad} of {len(rows)} rows were refused by the provider")

    def seed_lists(self, world: RenderedWorld) -> None:
        h = self.helper
        assert h is not None
        assert self.ledger is not None

        def req(cmd: str, **kw: Any) -> dict:
            return h.request(cmd, timeout=CHUNK_TIMEOUT_S, **kw)

        with self.step("contacts"):
            self._seed(
                "contacts",
                contact_rows(world),
                lambda b: req("contacts", items=b)["ids"],
            )
        with self.step("calendar"):
            account = {"name": world.calendar_name, "type": CALENDAR_ACCOUNT_TYPE}
            cal = req(
                "calendar", account=account, create=calendar_create(world, self.tz)
            )
            self.ledger.add("calendars", [cal["calendar_id"]])
            self._seed_events(event_rows(world, self.tz), cal["calendar_id"], world)
        with self.step("calls"):
            self._seed(
                "calls", call_rows(world), lambda b: req("calls", items=b)["ids"]
            )
        with self.step("sms") as st:
            st.detail = self._seed_sms(sms_rows(world))

    def _req(self, cmd: str, **kw: Any) -> dict:
        assert self.helper is not None
        return self.helper.request(cmd, timeout=CHUNK_TIMEOUT_S, **kw)

    def _seed_events(
        self, rows: list[tuple[str, dict[str, Any]]], cal_id: int, world: RenderedWorld
    ) -> None:
        account = {"name": world.calendar_name, "type": CALENDAR_ACCOUNT_TYPE}
        self._seed(
            "events",
            rows,
            lambda b: self._req(
                "calendar", account=account, calendar_id=cal_id, items=b
            )["ids"],
        )

    def _seed_sms(self, rows: list[tuple[str, dict[str, Any]]]) -> str:
        """Insert SMS rows with the messaging apps stopped; the provider mode."""
        self._stop_messaging()
        modes: set[str] = set()

        def send(b: list[dict[str, Any]]) -> list[int]:
            reply = self._req("sms", items=b)
            modes.add(str(reply.get("mode")))
            return reply["ids"]

        try:
            self._seed("sms", rows, send)
        finally:
            self._stop_messaging()
        return "provider " + "/".join(sorted(modes))

    def _stop_messaging(self) -> None:
        self.shell(
            "; ".join(f"am force-stop {p}" for p in MESSAGING_PACKAGES), timeout=60
        )

    # -- 5. photos (host side starts during preflight)

    def start_photo_jobs(self, world: RenderedWorld) -> None:
        if not world.photos:
            return
        assert self.tmp is not None
        entries = photo_entries(self.manifest, self.packs)
        fetch = ensure_photos(entries, self.photos_cache)
        if fetch.stopped:
            self.report.warn(f"photo downloads stopped: {fetch.stopped}")
        for pid, why in sorted(fetch.failed.items()):
            self.report.warn(f"photo {pid} unavailable: {why}")
        names = plan_names(world.photos, self.tz)
        self.pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, self.workers), thread_name_prefix="world-photos"
        )
        for rec in world.photos:
            src = fetch.paths.get(rec["source"])
            if src is None:
                continue
            name, taken = names[rec["id"]]
            out = self.tmp / (
                "Pictures/Screenshots" if is_screenshot(rec) else "DCIM/Camera"
            )
            self.photo_jobs[rec["id"]] = self.pool.submit(
                process_photo, src, rec, self.tz, out, name=name, taken_ms=taken
            )

    def push_photos(self, world: RenderedWorld) -> list[Any]:
        r = self.report
        r.expected["photos"] = len(world.photos)
        done = []
        for pid, job in self.photo_jobs.items():
            try:
                done.append(job.result())
            except PhotoError as exc:
                r.warn(f"{pid}: {exc}")
        if not done:
            return []
        assert self.tmp is not None
        assert self.ledger is not None
        roots = sorted({self.tmp / p.remote_dir.split("/")[0] for p in done})
        self.shell(
            "mkdir -p /sdcard/DCIM/Camera /sdcard/Pictures/Screenshots", zygote=False
        )
        paths = [f"/sdcard/{p.remote_dir}/{p.name}" for p in done]
        self.ledger.add_pending(paths)
        res = self.dev.push(roots, "/sdcard/", timeout=900)
        if not res.ok:
            raise PrepareError(
                f"photo push failed: {(res.err or res.out).strip()[:200]}"
            )
        recs = {rec["id"]: rec for rec in world.photos}
        keyed = self.ledger.data.setdefault("items", {}).setdefault("photos", {})
        photos = self.ledger.data.setdefault("photos", [])
        for p in done:
            path = f"/sdcard/{p.remote_dir}/{p.name}"
            photos.append({"id": p.id, "path": path, "taken_ms": p.taken_ms})
            keyed[p.id] = [path, row_hash(recs.get(p.id))]
        self.ledger.add_paths(paths)
        self._touch([(path, p.taken_ms) for path, p in zip(paths, done, strict=True)])
        return done

    def _touch(self, items: list[tuple[str, int]]) -> None:
        for batch in chunked(items, 200):
            script = "; ".join(
                f"touch -d @{ms // 1000} {_q(path)}" for path, ms in batch
            )
            self.shell(script, timeout=120, zygote=False)

    # -- 6. files and notes

    def push_files(self, world: RenderedWorld) -> list[tuple[str, int]]:
        assert self.tmp is not None
        assert self.ledger is not None
        r = self.report
        made: list[tuple[str, int]] = []
        items = self.ledger.data.setdefault("items", {})
        keyed = {"files": items.setdefault("files", {})}
        for f in world.files:
            sub = "Download" if f.get("dir") == "Download" else "Documents"
            name = str(f.get("name"))
            remote = f"/sdcard/{sub}/{name}"
            local = self.tmp / sub / name
            if (
                not safe_file_name(name)
                or not device_file_ok(remote)
                or local.resolve().parent != (self.tmp / sub).resolve()
            ):
                r.warn(f"files: unsafe file name {name!r} left out")
                continue
            when = dt.datetime.fromtimestamp(f["ts_ms"] / 1000, self.tz)
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(file_bytes(local.name, file_lines(f, self.tz), when))
            made.append((remote, int(f["ts_ms"])))
            keyed["files"][str(f["id"])] = [remote, row_hash(f)]
        r.expected["files"] = len(world.files)
        n_files = len(made)
        if world.notes:
            text, ts = notes_text(world, self.tz)
            name = NOTES_FILE.get(
                owner_language(self.manifest, self.packs), "Notes.txt"
            )
            local = self.tmp / "Documents" / name
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_text(text, encoding="utf-8")
            made.append((f"/sdcard/Documents/{name}", int(ts)))
            items["notes"] = {"notes": [f"/sdcard/Documents/{name}", row_hash(text)]}
        r.expected["notes"] = len(world.notes)
        if not made:
            return []
        roots = sorted({self.tmp / p.split("/")[2] for p, _ in made})
        self.ledger.add_pending([p for p, _ in made])
        res = self.dev.push(roots, "/sdcard/", timeout=300)
        if not res.ok:
            raise PrepareError(
                f"file push failed: {(res.err or res.out).strip()[:200]}"
            )
        self.ledger.add_paths([p for p, _ in made])
        self._touch(made)
        r.seeded["files"] = n_files
        r.seeded["notes"] = len(world.notes)
        return made

    # -- media scan and verification

    def _scan(self) -> None:
        out = self.shell(
            "content call --uri content://media/external/file --method scan_volume"
            " --arg external_primary",
            timeout=300,
        )
        if "error" in out.lower() or "exception" in out.lower():
            self.report.warn(f"media scan: {out.strip()[:200]}")

    def verify_media(self, photos: list[Any]) -> None:
        r = self.report
        if not photos:
            r.seeded["photos"] = 0
            return
        assert self.helper is not None
        assert self.ledger is not None
        by_name = {p.name: p for p in photos}
        rows: list[dict[str, Any]] = []
        for batch in chunked(sorted(by_name), 200):
            rows += self.helper.request(
                "query",
                uri="content://media/external/images/media",
                projection=["_id", "_display_name", "datetaken", "relative_path"],
                selection="_display_name IN (" + ",".join("?" * len(batch)) + ")",
                args=list(batch),
                timeout=120,
            )["rows"]
        found = {}
        for row in rows:
            p = by_name.get(row.get("_display_name"))
            rel = str(row.get("relative_path") or "").rstrip("/")
            if p is not None and rel == p.remote_dir:
                found[p.name] = row
        self.ledger.add("images", [int(row["_id"]) for row in found.values()])
        r.seeded["photos"] = len(found)
        missing = len(by_name) - len(found)
        if missing:
            r.warn(f"photos: {missing} of {len(by_name)} are not in MediaStore")
        off = [
            n
            for n, row in found.items()
            if row.get("datetaken") is None
            or abs(int(row["datetaken"]) - by_name[n].taken_ms) > DATETAKEN_TOLERANCE_MS
        ]
        if off:
            r.warn(
                f"photos: MediaStore datetaken differs from the capture time for "
                f"{len(off)} (e.g. {off[0]})"
            )

    def verify_counts(self) -> None:
        assert self.helper is not None
        assert self.ledger is not None
        lists = {k: v for k, v in self.ledger.data["lists"].items() if v}
        if not lists:
            return
        counts = self.helper.request("count", lists=lists, timeout=120)["counts"]
        for name, ids in lists.items():
            if counts.get(name) != len(ids):
                self.report.warn(
                    f"{name}: {counts.get(name)} of {len(ids)} ledger rows are on the device"
                )

    # -- the whole run

    def run(self, world_for: Callable[[dt.datetime], RenderedWorld]) -> PrepareReport:
        r = self.report
        self.tmp = Path(tempfile.mkdtemp(prefix="sandroid-world-"))
        try:
            with self.step("preflight") as st:
                self.preflight()
                world = world_for(self.anchor)
                self.start_photo_jobs(world)
                self.start_helper()
                if self.cleanup_from is not None:
                    self.cleanup()
                self.record_preexisting()
                st.detail = f"API {self.pre.get('sdk')}, avd {r.avd or '-'}"
            path = ledger_path(self.dev.serial, r.avd, self.manifest.world_fp)
            r.ledger_path = str(path)
            self.ledger = Ledger.new(
                path,
                serial=self.dev.serial,
                avd=r.avd,
                world_fp=self.manifest.world_fp,
                anchor=r.anchor,
                account={
                    "name": self.manifest.calendar_name,
                    "type": CALENDAR_ACCOUNT_TYPE,
                },
                max_ids=self.max_ids,
            )
            self.ledger.save()
            self.write_stamp(
                stamp_record(
                    self.manifest, state="partial", anchor=r.anchor, ledger=self.ledger
                )
            )
            with self.step("offline"):
                self.go_offline()
            with self.step("backup_sync_off"):
                self.backup_off()
            self.seed_lists(world)
            with self.step("photos"):
                photos = self.push_photos(world)
            with self.step("files"):
                self.push_files(world)
            with self.step("media_scan"):
                if photos or world.files or world.notes:
                    self._scan()
                self.verify_media(photos)
            with self.step("verify"):
                self.verify_counts()
            with self.step("stamp"):
                self.ledger.data["state"] = "complete"
                self.ledger.data["finished_at"] = _now_iso()
                self.ledger.save()
                self.write_stamp(
                    stamp_record(
                        self.manifest,
                        state="complete",
                        anchor=r.anchor,
                        ledger=self.ledger,
                        counts=self.ledger.counts(),
                    )
                )
            self.online()
            r.ok = True
            return r
        except PrepareError as exc:
            r.error = str(exc)
            exc.report = r
            raise
        except Exception as exc:
            # Anything else (a malformed helper reply, a decompression bomb):
            # the same error type with the report; the network still returns.
            r.error = f"{type(exc).__name__}: {exc}"
            raise PrepareError(r.error, r) from exc
        finally:
            if not self.online_done and self.network_before is not None:
                try:
                    self.online()
                except Exception as exc:  # the original error matters more
                    r.warn(f"restoring the network failed: {exc}")
            if self.pool is not None:
                self.pool.shutdown(wait=True, cancel_futures=True)
            if self.helper is not None:
                self.helper.close()
            shutil.rmtree(self.tmp, ignore_errors=True)

    # -- refresh: only what changed against the ledger

    def refresh(self) -> PrepareReport:
        """Bring the device's world to :attr:`manifest` (see :func:`refresh`)."""
        r = self.report
        self.refreshing = True
        self.tmp = Path(tempfile.mkdtemp(prefix="sandroid-world-"))
        try:
            with self.step("preflight") as st:
                self.preflight()
                old = self._refresh_ledger()
                world = self.manifest.render(self.anchor)
                plan = refresh_plan(old.data, world, self.tz, self._notes_name())
                plan.drop_topups(self.old_stamp or {})
                r.changes = plan.summary()
                st.detail = plan.words()
                if plan.empty and old.data.get("world_fp") == self.manifest.world_fp:
                    r.ok = True
                    return r
                self.start_helper()
            self._refresh_apply(old, world, plan)
            self.online()
            r.ok = True
            return r
        except PrepareError as exc:
            r.error = str(exc)
            exc.report = r
            raise
        except Exception as exc:
            r.error = f"{type(exc).__name__}: {exc}"
            raise PrepareError(r.error, r) from exc
        finally:
            if not self.online_done and self.network_before is not None:
                try:
                    self.online()
                except Exception as exc:
                    r.warn(f"restoring the network failed: {exc}")
            if self.pool is not None:
                self.pool.shutdown(wait=True, cancel_futures=True)
            if self.helper is not None:
                self.helper.close()
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _notes_name(self) -> str:
        return NOTES_FILE.get(owner_language(self.manifest, self.packs), "Notes.txt")

    def _refresh_ledger(self) -> Ledger:
        """The host ledger of the world on the device; the anchor it used."""
        stamp = self.old_stamp or {}
        fp = str(stamp.get("world_fp") or "")
        path = ledger_path(self.dev.serial, self.report.avd, fp) if fp else None
        if path is None or not path.is_file():
            raise PrepareError(
                "the host ledger of the world on the device is missing; build "
                "the persona again from clean_8g"
            )
        old = Ledger.load(path)
        if old.data.get("world_fp") != fp or old.data.get("state") != "complete":
            raise PrepareError(
                "the host ledger does not belong to the world on the device; "
                "build the persona again from clean_8g"
            )
        if not isinstance(old.data.get("items"), dict):
            raise PrepareError(
                "this persona was built before refresh existed (its ledger "
                "lists no items); build it again from clean_8g"
            )
        anchor = _parse_iso(old.data.get("anchor"))
        if anchor is None:
            raise PrepareError("the host ledger has no anchor")
        # The same anchor: an unchanged item renders to the same row.
        self.anchor = anchor.astimezone(self.tz)
        self.report.anchor = self.anchor.isoformat()
        return old

    def _refresh_apply(
        self, old: Ledger, world: RenderedWorld, plan: RefreshPlan
    ) -> None:
        r = self.report
        data = json.loads(old.to_json())
        data.update(
            world_fp=self.manifest.world_fp,
            state="partial",
            started_at=_now_iso(),
            finished_at=None,
            refreshed_from=old.data.get("world_fp"),
        )
        path = ledger_path(self.dev.serial, r.avd, self.manifest.world_fp)
        r.ledger_path = str(path)
        self.ledger = Ledger(path, data)
        self.ledger.save()
        self.write_stamp(
            stamp_record(
                self.manifest, state="partial", anchor=r.anchor, ledger=self.ledger
            )
        )
        with self.step("offline"):
            self.go_offline()
        with self.step("backup_sync_off"):
            self.backup_off()
        with self.step("remove"):
            self._refresh_remove(plan)
        lists = plan.added
        with self.step("contacts"):
            self._seed(
                "contacts",
                lists["contacts"],
                lambda b: self._req("contacts", items=b)["ids"],
            )
        with self.step("calendar"):
            if lists["events"]:
                cals = self.ledger.data["lists"].get("calendars") or []
                if not cals:
                    raise PrepareError("the host ledger names no calendar")
                self._seed_events(lists["events"], int(cals[0]), world)
        with self.step("calls"):
            self._seed(
                "calls", lists["calls"], lambda b: self._req("calls", items=b)["ids"]
            )
        with self.step("sms") as st:
            if lists["sms"]:
                st.detail = self._seed_sms(lists["sms"])
        sub = replace(
            world,
            photos=plan.photos,
            files=plan.files,
            notes=world.notes if plan.notes else [],
        )
        with self.step("photos"):
            self.start_photo_jobs(sub)
            photos = self.push_photos(sub)
        with self.step("files"):
            self.push_files(sub)
        with self.step("media_scan"):
            if photos or plan.files or plan.notes or plan.removed_paths:
                self._scan()
            self._requery_images()
        with self.step("verify"):
            self.verify_counts()
        with self.step("stamp"):
            self.ledger.data["state"] = "complete"
            self.ledger.data["finished_at"] = _now_iso()
            self.ledger.save()
            self.write_stamp(
                stamp_record(
                    self.manifest,
                    state="complete",
                    anchor=r.anchor,
                    ledger=self.ledger,
                    counts=self.ledger.counts(),
                )
            )

    def _refresh_remove(self, plan: RefreshPlan) -> None:
        """Delete the changed and removed rows and files (and old top-ups)."""
        assert self.ledger is not None
        data = self.ledger.data
        lists = {k: v for k, v in plan.removed.items() if v}
        if lists:
            self._req("delete", lists=lists, account=data.get("account"))
        for name, ids in lists.items():
            gone = set(ids)
            data["lists"][name] = [
                i for i in data["lists"].get(name, []) if i not in gone
            ]
            keyed = data.get("items", {}).get(name, {})
            for key in [k for k, v in keyed.items() if v[0] in gone]:
                del keyed[key]
        paths = [p for p in plan.removed_paths if device_file_ok(p)]
        for batch in chunked(paths, 100):
            self.shell("rm -f " + " ".join(_q(p) for p in batch), zygote=False)
        gone_paths = set(paths)
        data["paths"] = [p for p in data.get("paths", []) if p not in gone_paths]
        data["photos"] = [
            p for p in data.get("photos", []) if p.get("path") not in gone_paths
        ]
        items = data.setdefault("items", {})
        for kind in ("photos", "files", "notes"):
            keyed = items.get(kind, {})
            for key in [k for k, v in keyed.items() if v[0] in gone_paths]:
                del keyed[key]
        self.ledger.save()

    def _requery_images(self) -> None:
        """The ledger's MediaStore ids: those of the photos it lists now."""
        assert self.ledger is not None
        assert self.helper is not None
        want = {
            posixpath.basename(p["path"]): posixpath.dirname(p["path"])[
                len("/sdcard/") :
            ]
            for p in self.ledger.data.get("photos", [])
        }
        ids: list[int] = []
        for batch in chunked(sorted(want), 200):
            rows = self.helper.request(
                "query",
                uri="content://media/external/images/media",
                projection=["_id", "_display_name", "relative_path"],
                selection="_display_name IN (" + ",".join("?" * len(batch)) + ")",
                args=list(batch),
                timeout=120,
            )["rows"]
            for row in rows:
                rel = str(row.get("relative_path") or "").rstrip("/")
                if want.get(row.get("_display_name")) == rel:
                    ids.append(int(row["_id"]))
        self.ledger.data["lists"]["images"] = sorted(set(ids))
        self.ledger.save()
        self.report.seeded["photos"] = len(self.ledger.data["lists"]["images"])

    def online(self) -> None:
        """Restore the network and re-check backup/sync (step ``online``)."""
        self.online_done = True
        with self.step("online"):
            self.restore_network()
            if (
                self.helper is not None
                and not self.helper.broken
                and self.report.backup.get("bmgr") == "off"
            ):
                self.verify_backup_still_off()


def prepare(
    serial: str,
    manifest: WorldManifest,
    *,
    anchor: dt.datetime | None = None,
    progress: Callable[[str, int, int], None] | None = None,
    force_cleanup: bool = False,
    packs: PackSet | None = None,
    photos_cache: Path | None = None,
    device: Device | None = None,
    workers: int = 3,
) -> PrepareReport:
    """Seed ``manifest`` onto the device ``serial`` (see the module docstring).

    Args:
        serial: The device; every adb call is pinned to it.
        manifest: The world (``world_fp`` must verify).
        anchor: When the world is seeded; default the host's clock (now). A naive
            datetime is taken in the world's time zone.
        progress: Called with ``(step, done, total)`` while lists are seeded.
        force_cleanup: Remove an interrupted run's items (from its host
            ledger) before seeding, instead of refusing.
        packs: The packs (time zone, photo pack); default the built-in and
            user packs.
        photos_cache: Photo cache folder; default the XDG cache.
        device: The device wrapper (tests); default ``Device(serial)``.
        workers: Threads processing photos on the host.

    Returns:
        The report (``ok`` True).

    Raises:
        PrepareError: Refused (no root, wrong API, too little space, a world
            stamp present) or failed; ``exc.report`` says how far it got. On
            a failure after going offline the network is still restored.
    """
    if not manifest.verify():
        raise PrepareError("the manifest's world_fp does not match its content")
    dev = device or Device(serial)
    if dev.serial != serial:
        raise PrepareError(f"device wrapper is for {dev.serial}, not {serial}")
    run = _Run(
        dev, manifest, anchor, progress, packs, photos_cache, force_cleanup, workers
    )
    return run.run(manifest.render)


# ------------------------------------------------------------------ refresh

#: Provider lists a refresh compares row by row.
REFRESH_LISTS = ("contacts", "events", "calls", "sms")


@dataclass
class RefreshPlan:
    """What :func:`refresh` changes: rows and files to remove (changed or
    gone), rows and records to add (changed or new).
    """

    removed: dict[str, list[int]] = field(default_factory=dict)
    added: dict[str, list[tuple[str, dict[str, Any]]]] = field(default_factory=dict)
    removed_paths: list[str] = field(default_factory=list)
    photos: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    notes: bool = False
    unchanged: dict[str, int] = field(default_factory=dict)
    topups: dict[str, int] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (
            any(self.removed.values())
            or any(self.added.values())
            or self.removed_paths
            or self.photos
            or self.files
            or self.notes
        )

    def drop_topups(self, stamp: Mapping[str, Any]) -> None:
        """Also remove the rows earlier top-ups added (from the device stamp)."""
        for entry in stamp.get("topups") or []:
            if not isinstance(entry, dict):
                continue
            for name, ids in (entry.get("ids") or {}).items():
                good = [int(i) for i in ids if isinstance(i, int) and i > 0]
                if name in REFRESH_LISTS and good:
                    self.removed.setdefault(name, []).extend(good)
                    self.topups[name] = self.topups.get(name, 0) + len(good)

    def summary(self) -> dict[str, Any]:
        """Counts per list: added, removed, unchanged, top-up rows removed."""
        added = {k: len(v) for k, v in self.added.items() if v}
        removed = {k: len(v) for k, v in self.removed.items() if v}
        if self.photos:
            added["photos"] = len(self.photos)
        if self.files:
            added["files"] = len(self.files)
        if self.notes:
            added["notes"] = 1
        if self.removed_paths:
            removed["files"] = len(self.removed_paths)
        return {
            "added": added,
            "removed": removed,
            "unchanged": {k: v for k, v in self.unchanged.items() if v},
            "topups_removed": dict(self.topups),
        }

    def words(self) -> str:
        """``3 added, 2 removed, 410 unchanged`` (rows and files)."""
        s = self.summary()
        return (
            f"{sum(s['added'].values())} added, {sum(s['removed'].values())} "
            f"removed, {sum(s['unchanged'].values())} unchanged"
        )


def _changed(old: Mapping[str, Any], key: str, new_hash: str) -> bool:
    entry = old.get(key)
    return not (isinstance(entry, list) and len(entry) > 1 and entry[1] == new_hash)


def refresh_plan(
    ledger: Mapping[str, Any], world: RenderedWorld, tz: ZoneInfo, notes_name: str
) -> RefreshPlan:
    """Compare ``world`` (rendered at the ledger's anchor) with the ledger's
    ``items`` map: a row whose world id is gone or whose hash changed is
    removed, a new or changed one added; the rest stays untouched.
    """
    items = ledger.get("items") or {}
    plan = RefreshPlan()
    builders = {
        "contacts": contact_rows(world),
        "events": event_rows(world, tz),
        "calls": call_rows(world),
        "sms": sms_rows(world),
    }
    for name, rows in builders.items():
        old = items.get(name) or {}
        new = {key: row_hash(row) for key, row in rows}
        plan.removed[name] = [
            int(v[0]) for k, v in old.items() if new.get(k) is None or new[k] != v[1]
        ]
        plan.added[name] = [(k, row) for k, row in rows if _changed(old, k, new[k])]
        plan.unchanged[name] = len(rows) - len(plan.added[name])
    for kind, records in (("photos", world.photos), ("files", world.files)):
        old = items.get(kind) or {}
        new = {str(rec["id"]): row_hash(rec) for rec in records}
        plan.removed_paths += [
            v[0] for k, v in old.items() if new.get(k) is None or new[k] != v[1]
        ]
        fresh = [
            rec for rec in records if _changed(old, str(rec["id"]), new[str(rec["id"])])
        ]
        setattr(plan, kind, fresh)
        plan.unchanged[kind] = len(records) - len(fresh)
    old_notes = (items.get("notes") or {}).get("notes")
    text = notes_text(world, tz)[0] if world.notes else ""
    path = f"/sdcard/Documents/{notes_name}"
    if old_notes and (not text or old_notes != [path, row_hash(text)]):
        plan.removed_paths.append(old_notes[0])
        plan.notes = bool(text)
    elif not old_notes and text:
        plan.notes = True
    return plan


def _parse_iso(value: Any) -> dt.datetime | None:
    """An aware datetime from ISO 8601 text (naive: UTC); ``None`` if not one."""
    if not isinstance(value, str) or not value:
        return None
    try:
        out = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return out if out.tzinfo is not None else out.replace(tzinfo=dt.UTC)


def refresh(
    serial: str,
    manifest: WorldManifest,
    *,
    progress: Callable[[str, int, int], None] | None = None,
    packs: PackSet | None = None,
    photos_cache: Path | None = None,
    device: Device | None = None,
    workers: int = 3,
) -> PrepareReport:
    """Bring the world on ``serial`` to ``manifest``, changing only what differs.

    The device must hold a complete world whose host ledger lists its items
    (every :func:`prepare` since refresh exists writes that list). The new
    world is rendered at the ledger's anchor, so an unchanged item renders
    to the same row; rows and files whose world id is gone or whose content
    changed are removed (by ledger id / path), new and changed ones added,
    and so are the rows earlier top-ups added. Offline, with backup and sync
    off, like :func:`prepare`. The ledger moves to the new world's file; the
    stamp names the new world. When nothing differs, ``report.changes``
    says so and nothing on the device changes.

    Raises:
        PrepareError: No complete world on the device, no usable ledger, or
            a step failed (``exc.report`` says how far it got).
    """
    if not manifest.verify():
        raise PrepareError("the manifest's world_fp does not match its content")
    dev = device or Device(serial)
    if dev.serial != serial:
        raise PrepareError(f"device wrapper is for {dev.serial}, not {serial}")
    run = _Run(dev, manifest, None, progress, packs, photos_cache, False, workers)
    return run.refresh()


# ------------------------------------------------------------------- top-up

#: A top-up adds nothing when the newest seeded items are younger than this.
TOPUP_MIN_GAP_S = 3600
#: A top-up covers at most this many days (an older snapshot keeps a gap).
TOPUP_MAX_DAYS = 30
#: Calendar events up to this far ahead of now are part of a top-up.
TOPUP_EVENTS_AHEAD_S = 86400
#: How many weeks back a top-up may look for SMS / calls to re-date.
TOPUP_MAX_WEEKS = 52
_WEEK_MS = 7 * 86400 * 1000

_TOPUP_LOCKS: dict[str, threading.Lock] = {}
_TOPUP_LOCKS_GUARD = threading.Lock()


def _topup_lock(serial: str) -> threading.Lock:
    with _TOPUP_LOCKS_GUARD:
        return _TOPUP_LOCKS.setdefault(serial, threading.Lock())


@dataclass
class TopUpReport:
    """What :func:`topup` did.

    Attributes:
        serial: The device.
        world_fp: The world.
        ran: The window was looked at (and the stamp records this top-up).
        skipped: Why nothing was done (``ran`` False).
        anchor: The top-up's anchor (now), ISO 8601.
        since: The start of the window it covered, ISO 8601.
        counts: Rows added per list (``sms``, ``calls``, ``events``).
        newest: Newest added time per list, ISO 8601.
        weeks_back: Per list, how many weeks back its items were re-dated
            from (0: the world's own items of the window).
        warnings: Everything a person should know.
        seconds: Wall time.
    """

    serial: str
    world_fp: str = ""
    ran: bool = False
    skipped: str = ""
    anchor: str = ""
    since: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    newest: dict[str, str] = field(default_factory=dict)
    weeks_back: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def words(self) -> str:
        """``topped up with 4 SMS, 2 calls`` (or why not)."""
        if not self.ran:
            return self.skipped
        names = {
            "sms": ("SMS", "SMS"),
            "calls": ("call", "calls"),
            "events": ("calendar event", "calendar events"),
        }
        parts = [
            f"{n} {names.get(k, (k, k))[n != 1]}" for k, n in self.counts.items() if n
        ]
        return "topped up with " + (", ".join(parts) or "nothing new")


def topup_world(
    world: RenderedWorld, since: dt.datetime, now: dt.datetime
) -> tuple[RenderedWorld, dict[str, int]]:
    """The SMS, calls and events of a top-up for the window ``(since, now]``.

    ``world`` is rendered at ``now``. SMS and calls: the world's own items of
    the window when one of them lies in the window's last day; otherwise
    those of the same window ``k`` whole weeks earlier (the smallest ``k``
    up to :data:`TOPUP_MAX_WEEKS` with an item in that last day), re-dated
    by ``k`` weeks -- so a sparse world still gets messages and calls from
    today, on the weekdays and at the times of day the world uses. Events:
    the world's own (no birthdays or holidays, which recur anyway), up to
    :data:`TOPUP_EVENTS_AHEAD_S` ahead. Deterministic for a world, window
    and now.

    Returns:
        The world holding only those items, and the weeks each list was
        taken from (``{"sms": k, "calls": k}``).
    """
    lo, hi = _ms_of(since), _ms_of(now)
    day = max(lo, hi - 86400 * 1000)
    weeks: dict[str, int] = {}
    picked: dict[str, list[dict[str, Any]]] = {}
    for name in ("sms", "calls"):
        items = getattr(world, name)
        chosen = 0
        for k in range(TOPUP_MAX_WEEKS + 1):
            shift = k * _WEEK_MS
            if any(day < i["ts_ms"] + shift <= hi for i in items):
                chosen = k
                break
        shift = chosen * _WEEK_MS
        picked[name] = [
            {**i, "ts_ms": i["ts_ms"] + shift}
            for i in items
            if lo < i["ts_ms"] + shift <= hi
        ]
        weeks[name] = chosen
    ahead = hi + TOPUP_EVENTS_AHEAD_S * 1000
    events = [e for e in world.events if not e.get("rule") and lo < e["ts_ms"] <= ahead]
    sub = replace(world, sms=picked["sms"], calls=picked["calls"], events=events)
    return sub, weeks


def last_world_anchor(stamp: Mapping[str, Any]) -> dt.datetime | None:
    """The newest anchor on the device: the prepare's or a top-up's."""
    found = [_parse_iso(stamp.get("anchor"))]
    found += [
        _parse_iso(e.get("anchor"))
        for e in stamp.get("topups") or []
        if isinstance(e, dict)
    ]
    real = [a for a in found if a is not None]
    return max(real) if real else None


def topup(
    serial: str,
    manifest: WorldManifest,
    *,
    now: dt.datetime | None = None,
    packs: PackSet | None = None,
    device: Device | None = None,
    max_days: int = TOPUP_MAX_DAYS,
    min_gap_s: float = TOPUP_MIN_GAP_S,
) -> TopUpReport:
    """Add the world's SMS, calls and calendar events of the time since the
    device's world was seeded (or last topped up), so it looks used today.

    The world is rendered at ``now`` (default the host clock) -- the same
    deterministic render :func:`prepare` uses -- and its items between the
    newest anchor on the device and now go in, at most ``max_days`` back
    (:func:`topup_world`: a sparse world's SMS and calls come from the same
    window whole weeks earlier, re-dated, so some are from today). The device stamp records each top-up
    (anchor, window, row ids) BEFORE the rows go in, so a second call, or
    one after an interrupted top-up, never adds them twice; within
    ``min_gap_s`` of the newest anchor nothing is done. Contacts, photos
    and files stay as they are. Call from a worker thread (seconds).

    Raises:
        PrepareError: No root, no complete world of ``manifest`` on the
            device, or the helper failed.
    """
    t0 = time.monotonic()
    dev = device or Device(serial)
    if dev.serial != serial:
        raise PrepareError(f"device wrapper is for {dev.serial}, not {serial}")
    if packs is None:
        from sandroid.world.packs import load_packs

        packs = load_packs()
    tz = world_timezone(manifest, packs)
    out = TopUpReport(serial=serial, world_fp=manifest.world_fp)
    with _topup_lock(serial):
        script = "\n".join(
            [
                "echo; echo @@uid@@; id -u",
                "echo; echo @@now@@; date +%s",
                f"echo; echo @@stamp@@; cat {STAMP_PATH} 2>/dev/null",
                "echo; echo @@end@@",
            ]
        )
        res = dev.shell(script, timeout=30, zygote=False)
        pre = _sections(res.out)
        if "end" not in pre:
            raise PrepareError(
                f"device {serial} did not answer: {(res.err or res.out).strip()[:200]}"
            )
        if pre.get("uid") != "0":
            raise PrepareError("the top-up needs adb root (adb root)")
        try:
            stamp = json.loads(pre.get("stamp") or "null")
        except ValueError:
            stamp = None
        if (
            not isinstance(stamp, dict)
            or stamp.get("format") != STAMP_FORMAT
            or stamp.get("state") != "complete"
            or stamp.get("world_fp") != manifest.world_fp
        ):
            raise PrepareError(
                f"the device holds no complete world {manifest.world_fp[:12]}"
            )
        host = now.timestamp() if now is not None else _host_now()
        device_now = pre.get("now", "")
        if device_now.isdigit() and int(device_now) - host < -CLOCK_SKEW_WARN_S:
            out.warnings.append(
                f"the device clock is {(host - int(device_now)) / 60:.0f} min behind "
                "the host; today's items may look like they lie ahead"
            )
        now_dt = dt.datetime.fromtimestamp(int(host), dt.UTC).astimezone(tz)
        last = last_world_anchor(stamp)
        if last is not None and (now_dt - last).total_seconds() < min_gap_s:
            when = last.astimezone(tz)
            out.skipped = f"already fresh (newest items from {when:%Y-%m-%d %H:%M})"
            out.seconds = round(time.monotonic() - t0, 2)
            return out
        floor = now_dt - dt.timedelta(days=max(1, max_days))
        since = max(last, floor) if last is not None else floor
        if last is not None and last < floor:
            out.warnings.append(
                f"the world was seeded {(now_dt - last).days} days ago; only the "
                f"last {max_days} days are topped up"
            )
        sub, weeks = topup_world(manifest.render(now_dt), since, now_dt)
        entry: dict[str, Any] = {
            "anchor": now_dt.isoformat(),
            "since": since.isoformat(),
            "weeks_back": weeks,
            "state": "running",
            "counts": {},
            "ids": {},
        }
        topups = [e for e in stamp.get("topups") or [] if isinstance(e, dict)]
        tmp = Path(tempfile.mkdtemp(prefix="sandroid-topup-"))
        try:
            # Recorded first: a killed top-up is never repeated (no doubles).
            write_device_stamp(dev, {**stamp, "topups": [*topups, entry]}, tmp)
            try:
                if sub.sms or sub.calls or sub.events:
                    _topup_insert(dev, sub, tz, out, entry["ids"])
            except BaseException:
                # What landed stays recorded (a refresh removes it).
                entry["state"] = "failed"
                entry["counts"] = {k: len(v) for k, v in entry["ids"].items()}
                with contextlib.suppress(Exception):
                    write_device_stamp(dev, {**stamp, "topups": [*topups, entry]}, tmp)
                raise
            entry["counts"] = {k: len(v) for k, v in entry["ids"].items()}
            entry["state"] = "complete"
            write_device_stamp(dev, {**stamp, "topups": [*topups, entry]}, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    out.ran = True
    out.anchor = entry["anchor"]
    out.since = entry["since"]
    out.weeks_back = dict(weeks)
    out.counts = dict(entry["counts"])
    for name, rows in (("sms", sub.sms), ("calls", sub.calls), ("events", sub.events)):
        if rows and out.counts.get(name):
            newest = max(r["ts_ms"] for r in rows)
            out.newest[name] = dt.datetime.fromtimestamp(newest / 1000, tz).isoformat()
    out.seconds = round(time.monotonic() - t0, 2)
    return out


def _ms_of(moment: dt.datetime) -> int:
    return int(moment.timestamp() * 1000)


def _topup_insert(
    dev: Device,
    sub: RenderedWorld,
    tz: ZoneInfo,
    out: TopUpReport,
    ids: dict[str, list[int]],
) -> None:
    """Insert the top-up rows with one helper; each list's new row ids go
    into ``ids`` as soon as they are known (a failure keeps what landed).

    Raises:
        PrepareError: The helper failed.
    """
    try:
        ensure_jar(dev)
        helper = dev.helper(timeout=60)
    except HelperError as exc:
        raise PrepareError(str(exc)) from exc

    def good(reply: dict) -> list[int]:
        return [i for i in reply.get("ids") or [] if isinstance(i, int) and i > 0]

    try:
        if sub.calls:
            reply = helper.request(
                "calls", items=call_items(sub), timeout=CHUNK_TIMEOUT_S
            )
            ids["calls"] = good(reply)
        if sub.sms:
            stop = "; ".join(f"am force-stop {p}" for p in MESSAGING_PACKAGES)
            dev.shell(stop, timeout=60, zygote=True)
            try:
                reply = helper.request(
                    "sms", items=sms_items(sub), timeout=CHUNK_TIMEOUT_S
                )
                ids["sms"] = good(reply)
            finally:
                dev.shell(stop, timeout=60, zygote=True)
        if sub.events:
            rows = (
                helper.request(
                    "query",
                    uri="content://com.android.calendar/calendars",
                    projection=["_id"],
                    selection="account_name=? AND account_type=?",
                    args=[sub.calendar_name, CALENDAR_ACCOUNT_TYPE],
                    timeout=60,
                ).get("rows")
                or []
            )
            if not rows:
                out.warnings.append("the world's calendar is gone; no events added")
            else:
                account = {"name": sub.calendar_name, "type": CALENDAR_ACCOUNT_TYPE}
                reply = helper.request(
                    "calendar",
                    account=account,
                    calendar_id=int(rows[0]["_id"]),
                    items=event_items(sub, tz),
                    timeout=CHUNK_TIMEOUT_S,
                )
                ids["events"] = good(reply)
    except HelperError as exc:
        raise PrepareError(f"top-up: {exc}") from exc
    finally:
        helper.close()
    for name, rows_in in (
        ("calls", sub.calls),
        ("sms", sub.sms),
        ("events", sub.events),
    ):
        if name in ids and len(ids[name]) < len(rows_in):
            out.warnings.append(
                f"{name}: {len(rows_in) - len(ids[name])} rows were refused"
            )
