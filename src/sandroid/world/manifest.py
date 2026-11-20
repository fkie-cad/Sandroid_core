"""World spec, owner, the generated :class:`WorldManifest` and its rendering.

The manifest is plain JSON: every list item is a dict, so the manifest
serialises byte-identically and round-trips without loss. ``world_fp`` is the
SHA-256 of the canonical JSON of everything except ``warnings``.

The manifest holds no absolute time. Items carry ``t_rel_s`` (seconds before
the anchor); texts that name a date keep a ``{@n}`` slot per date with its
offset in ``date_slots``; holidays and birthdays keep their ``rule`` and an
``occurrence`` index (0: the latest date up to 60 days after the anchor).
:meth:`WorldManifest.render` turns all of that into absolute timestamps and
final text for one anchor, so ``world_fp`` does not depend on the anchor.
"""

# Invalid specs raise ValueError, also for wrong types: callers catch one class.
# ruff: noqa: TRY004

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any

from sandroid.world.packs import (
    device_problem,
    normalize_device,
    nth_occurrence,
)
from sandroid.world.stream import parse_seed

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sandroid.core.privacy_markers import Marker

#: Count defaults per world size.
SIZES: dict[str, dict[str, int]] = {
    "small": {
        "contacts": 25,
        "sms": 40,
        "calls": 20,
        "events": 8,
        "photos": 12,
        "files": 3,
        "notes": 5,
    },
    "medium": {
        "contacts": 80,
        "sms": 150,
        "calls": 50,
        "events": 30,
        "photos": 50,
        "files": 8,
        "notes": 10,
    },
    "large": {
        "contacts": 250,
        "sms": 600,
        "calls": 200,
        "events": 120,
        "photos": 200,
        "files": 20,
        "notes": 20,
    },
}
#: Number levels, safest first.
NUMBER_LEVELS = ("fiction", "unallocated", "realistic")
#: Text field of each list that may carry ``{@n}`` date slots.
TEXT_FIELDS = {"sms": "body", "events": "title", "files": "name", "notes": "text"}

_HISTORY_RE = re.compile(r"^(\d+)\s*(d|w|mo|y)$")
_HISTORY_DAYS = {"d": 1.0, "w": 7.0, "mo": 30.44, "y": 365.25}
_SPEC_KEYS = (
    "seed",
    "size",
    "country",
    "mix",
    "numbers",
    "history",
    "counts",
    "places",
    "device",
)
_SLOT_RE = re.compile(r"\{@(\d+)\}")
_JAVA_DATE = re.compile(r"yyyy|yy|MM|M|dd|d|HH|H|hh|h|mm|a")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass
class WorldSpec:
    """The ``world:`` section of a persona/identity profile.

    Attributes:
        seed: ``"auto"`` or ``"hex:<32+ hex>"``.
        size: ``small``, ``medium`` or ``large``.
        country: Primary country pack id; None derives it from the owner's
            phone country code.
        mix: Culture shares of the people (country-pack ids, each > 0); None
            uses the country pack's ``cultures``. Normalised to sum 1.
        numbers: ``fiction``, ``unallocated`` or ``realistic``.
        history: How far back items go: ``<n>d``, ``<n>w``, ``<n>mo``, ``<n>y``.
        counts: Overrides of the size defaults (contacts, sms, calls, events,
            photos, files, notes).
        places: Optional ``home`` / ``work``: ``{city: ...}`` or
            ``{lat: ..., lon: ...}``.
        device: Optional persona phone ``{make, model, codename, min_sdk,
            max_sdk}`` (photo EXIF, later the Build spoof); None picks a
            Google Pixel from the seed.
    """

    seed: str = "auto"
    size: str = "medium"
    country: str | None = None
    mix: dict[str, float] | None = None
    numbers: str = "unallocated"
    history: str = "18mo"
    counts: dict[str, int] = field(default_factory=dict)
    places: dict[str, Any] = field(default_factory=dict)
    device: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> WorldSpec:
        """Build a spec from a ``world:`` mapping.

        Raises:
            ValueError: Unknown keys or invalid values.
        """
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError("the world spec must be a mapping")
        unknown = sorted(str(k) for k in set(data) - set(_SPEC_KEYS))
        if unknown:
            raise ValueError(f"unknown world spec keys: {', '.join(unknown)}")
        spec = cls(**data)
        spec.validate()
        return spec

    def to_dict(self) -> dict[str, Any]:
        """Return the spec as a plain mapping."""
        return {
            "seed": self.seed,
            "size": self.size,
            "country": self.country,
            "mix": dict(sorted(self.mix.items())) if self.mix else None,
            "numbers": self.numbers,
            "history": self.history,
            "counts": dict(sorted(self.counts.items())),
            "places": self.places,
            "device": normalize_device(self.device) if self.device else None,
        }

    def validate(self) -> None:
        """Check every value.

        Raises:
            ValueError: An invalid value (never TypeError or AttributeError).
        """
        if not isinstance(self.seed, str):
            raise ValueError("world seed must be 'auto' or 'hex:<hex>'")
        if self.seed != "auto":
            parse_seed(self.seed)
        if not isinstance(self.size, str) or self.size not in SIZES:
            raise ValueError(f"world size must be one of {tuple(SIZES)}")
        if self.country is not None and (
            not isinstance(self.country, str) or not self.country
        ):
            raise ValueError("world country must be a country pack id")
        if not isinstance(self.numbers, str) or self.numbers not in NUMBER_LEVELS:
            raise ValueError(f"world numbers must be one of {NUMBER_LEVELS}")
        self.history_seconds()
        if not isinstance(self.counts, dict):
            raise ValueError("world counts must be a mapping")
        for key, value in self.counts.items():
            if key not in SIZES["small"]:
                raise ValueError(f"unknown world count {key!r}")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"world count {key!r} must be an integer >= 0")
        if self.mix is not None:
            if not isinstance(self.mix, dict) or not self.mix:
                raise ValueError("world mix must be a non-empty mapping")
            for key, value in self.mix.items():
                if not isinstance(key, str):
                    raise ValueError("world mix keys must be country pack ids")
                if not _is_number(value) or not value > 0 or math.isinf(value):
                    raise ValueError(f"world mix share for {key!r} must be > 0")
        if not isinstance(self.places, dict):
            raise ValueError("world places must be a mapping")
        for key, place in self.places.items():
            if key not in ("home", "work"):
                raise ValueError(f"unknown world place {key!r} (home, work)")
            if not isinstance(place, dict):
                raise ValueError(f"world place {key!r} must be a mapping")
            has_city = isinstance(place.get("city"), str) and place["city"]
            has_point = "lat" in place or "lon" in place
            if has_point:
                lat, lon = place.get("lat"), place.get("lon")
                if not (_is_number(lat) and _is_number(lon)):
                    raise ValueError(f"world place {key!r} needs numeric lat and lon")
                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    raise ValueError(f"world place {key!r} is off the globe")
            elif not has_city:
                raise ValueError(f"world place {key!r} needs a city or lat/lon")
        if self.device is not None:
            problem = device_problem(self.device)
            if problem:
                raise ValueError(f"world device: {problem}")

    def history_seconds(self) -> int:
        """Return :attr:`history` in seconds.

        Raises:
            ValueError: The history is not ``<n>d|w|mo|y``.
        """
        m = (
            _HISTORY_RE.match(self.history.strip())
            if isinstance(self.history, str)
            else None
        )
        if not m or int(m.group(1)) <= 0:
            raise ValueError("world history must look like 18mo, 2y, 6w or 90d")
        return int(int(m.group(1)) * _HISTORY_DAYS[m.group(2)] * 86400)

    def resolved_counts(self) -> dict[str, int]:
        """Return the size defaults with :attr:`counts` applied."""
        out = dict(SIZES[self.size])
        out.update(self.counts)
        return out


@dataclass(frozen=True)
class Owner:
    """The phone's owner, from the identity profile.

    Only :attr:`first` and :attr:`last` ever reach the manifest. The phone
    number and e-mail may carry the identity profile's token, so the
    generator reads only the phone's country code.

    Attributes:
        first: First name.
        last: Last name.
        phone: E.164 number (never written to the manifest).
        email: E-mail address (never written to the manifest).
    """

    first: str
    last: str
    phone: str = field(default="", repr=False)
    email: str = field(default="", repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | Owner) -> Owner:
        """Build an owner from a mapping with first, last, phone, email.

        Raises:
            ValueError: Not a mapping, or a field is not a string.
        """
        if isinstance(data, Owner):
            return data
        if not isinstance(data, dict):
            raise ValueError("the owner must be a mapping")
        values = {k: data.get(k) or "" for k in ("first", "last", "phone", "email")}
        for key, value in values.items():
            if not isinstance(value, str):
                raise ValueError(f"owner {key} must be a string")
        return cls(**values)

    @property
    def phone_e164(self) -> str:
        """The phone as ``+<digits>`` (empty when there is none).

        A leading ``00`` (international call prefix) is dropped.
        """
        text = self.phone.strip()
        digits = re.sub(r"\D", "", text)
        if not text.startswith("+") and digits.startswith("00"):
            digits = digits[2:]
        return f"+{digits}" if digits else ""

    def to_dict(self) -> dict[str, str]:
        """Return the manifest form: first and last only."""
        return {"first": self.first, "last": self.last}


@dataclass
class RenderedWorld:
    """A manifest rendered for one anchor: absolute times and final text.

    Every item is a plain dict. Timed items carry ``ts_ms`` (Unix epoch
    milliseconds); events also ``end_ms``. ``t_rel_s``, ``date_slots`` and
    ``occurrence`` are gone, and texts have their dates filled in.

    Attributes:
        anchor: The effective anchor (local midnight of a Monday), ISO 8601.
        world_fp: The manifest's fingerprint.
        device: The persona phone.
        owner: ``{first, last}``.
        calendar_name: Neutral calendar display name.
        contacts: Address book.
        sms: Messages.
        calls: Call log.
        events: Calendar events; holidays and birthdays on their real dates,
            holidays older than the world's history left out.
        photos: Photo records.
        files: Files.
        notes: Notes.
    """

    anchor: str
    world_fp: str
    device: dict[str, Any]
    owner: dict[str, str]
    calendar_name: str
    contacts: list[dict[str, Any]]
    sms: list[dict[str, Any]]
    calls: list[dict[str, Any]]
    events: list[dict[str, Any]]
    photos: list[dict[str, Any]]
    files: list[dict[str, Any]]
    notes: list[dict[str, Any]]

    def markers(self) -> list[dict[str, Any]]:
        """Return the scanner markers (see :mod:`sandroid.world.markers`)."""
        from sandroid.world.markers import build_markers

        return build_markers(self)


@dataclass
class WorldManifest:
    """A generated world.

    Attributes:
        spec: The spec with the seed resolved.
        seed: The resolved seed (``"hex:..."``); write it back to the profile
            when the spec said ``auto``.
        generator_version: :data:`sandroid.world.generator.GENERATOR_VERSION`.
        time_base: How ``t_rel_s`` relates to the clock (see :meth:`render`).
        packs: ``"<kind>/<id>"`` to the SHA-256 of each pack used.
        owner: ``{first, last}``.
        calendar_name: Neutral display name of the seeded calendar.
        device: The persona's phone ``{make, model, codename, min_sdk,
            max_sdk}``; every photo record carries make and model for EXIF.
        target_sdk: The API level the device was picked for (None: any).
        people: The social graph.
        contacts: Address-book entries.
        sms: Messages.
        calls: Call-log entries.
        events: Calendar events.
        photos: Photo records (metadata only).
        files: Download/Documents files.
        notes: Note snippets.
        warnings: Generation warnings (fallbacks, skipped data); not part of
            :attr:`world_fp`.
        world_fp: SHA-256 over the canonical JSON of all other fields.
    """

    spec: dict[str, Any]
    seed: str
    generator_version: str
    time_base: dict[str, Any]
    packs: dict[str, str]
    owner: dict[str, str]
    calendar_name: str = "Personal"
    device: dict[str, Any] = field(default_factory=dict)
    target_sdk: int | None = None
    people: list[dict[str, Any]] = field(default_factory=list)
    contacts: list[dict[str, Any]] = field(default_factory=list)
    sms: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    photos: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    world_fp: str = ""

    def fingerprint_body(self) -> dict[str, Any]:
        """Return everything :attr:`world_fp` covers."""
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name not in ("warnings", "world_fp")
        }

    def compute_fp(self) -> str:
        """Return the SHA-256 of the canonical JSON of :meth:`fingerprint_body`."""
        return hashlib.sha256(canonical_json(self.fingerprint_body())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return the manifest as a plain mapping."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialise to JSON (sorted keys, UTF-8 text)."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            indent=indent,
            separators=(",", ": ") if indent is not None else (",", ":"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> WorldManifest:
        """Build a manifest from :meth:`to_dict` output.

        Raises:
            ValueError: Unknown or missing keys.
        """
        names = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - names)
        if unknown:
            raise ValueError(f"unknown manifest keys: {', '.join(unknown)}")
        return cls(**dict(data))

    @classmethod
    def from_json(cls, text: str) -> WorldManifest:
        """Parse :meth:`to_json` output."""
        return cls.from_dict(json.loads(text))

    def verify(self) -> bool:
        """Return whether :attr:`world_fp` matches the content."""
        return self.world_fp == self.compute_fp()

    def render(self, anchor: dt.datetime) -> RenderedWorld:
        """Render absolute times and final text for one anchor.

        Args:
            anchor: When the world is seeded. A naive datetime is taken as
                UTC; pass an aware one in the device's time zone. The
                effective anchor is local midnight of the Monday on or before
                it, so the weekly rhythm of the world (weekend outings,
                working hours) keeps its weekdays.

        Returns:
            The rendered world.
        """
        return render_world(self, anchor)

    def markers(self, anchor: dt.datetime) -> list[dict[str, Any]]:
        """Return the scanner markers of the world rendered at ``anchor``."""
        return self.render(anchor).markers()

    def to_markers(self, anchor: dt.datetime) -> list[Marker]:
        """Return :meth:`markers` as ``privacy_markers.Marker`` objects."""
        from sandroid.world.markers import to_markers

        return to_markers(self.markers(anchor))


def canonical_json(value: Any) -> bytes:
    """Return the canonical JSON bytes used for fingerprints."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


# ----------------------------------------------------------------- rendering


def format_date(day: dt.date | dt.datetime, pattern: str) -> str:
    """Render a Java-style date/time pattern (``dd.MM.yyyy``, ``HH:mm``, ``h:mm a``)."""
    hour = getattr(day, "hour", 0)
    minute = getattr(day, "minute", 0)

    def sub(m: re.Match[str]) -> str:
        return {
            "yyyy": f"{day.year:04d}",
            "yy": f"{day.year % 100:02d}",
            "MM": f"{day.month:02d}",
            "M": str(day.month),
            "dd": f"{day.day:02d}",
            "d": str(day.day),
            "HH": f"{hour:02d}",
            "H": str(hour),
            "hh": f"{(hour % 12) or 12:02d}",
            "h": str((hour % 12) or 12),
            "mm": f"{minute:02d}",
            "a": "AM" if hour < 12 else "PM",
        }[m.group(0)]

    return _JAVA_DATE.sub(sub, pattern)


def week_anchor(anchor: dt.datetime) -> dt.datetime:
    """Return local midnight of the Monday on or before ``anchor``.

    A naive ``anchor`` is taken as UTC.
    """
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=dt.UTC)
    midnight = anchor.replace(hour=0, minute=0, second=0, microsecond=0)
    monday = (midnight - dt.timedelta(days=midnight.weekday())).date()
    return dt.datetime.combine(monday, dt.time(), tzinfo=anchor.tzinfo)


def fill_slots(text: str, slots: list[dict[str, Any]], anchor: dt.datetime) -> str:
    """Replace ``{@n}`` date slots for an (effective) anchor.

    A slot is ``{t_rel_s, kind, pattern?, fs?, names?}``: ``kind`` ``date``
    uses ``pattern`` (``fs``: "/" becomes "-" for file names), ``date_file``
    is ISO ``YYYY-MM-DD`` and ``day`` picks from the seven ``names``.
    """

    def sub(m: re.Match[str]) -> str:
        slot = slots[int(m.group(1))]
        day = anchor - dt.timedelta(seconds=slot["t_rel_s"])
        kind = slot["kind"]
        if kind == "day":
            return slot["names"][day.weekday()]
        if kind == "date_file":
            return day.date().isoformat()
        out = format_date(day.date(), slot["pattern"])
        return out.replace("/", "-") if slot.get("fs") else out

    return _SLOT_RE.sub(sub, text)


def _ms(moment: dt.datetime) -> int:
    return int(moment.timestamp() * 1000)


def render_world(manifest: WorldManifest, anchor: dt.datetime) -> RenderedWorld:
    """Render ``manifest`` for ``anchor`` (see :meth:`WorldManifest.render`)."""
    base = week_anchor(anchor)
    oldest = base.date() - dt.timedelta(
        seconds=WorldSpec(
            history=manifest.spec.get("history", "18mo")
        ).history_seconds()
    )

    def at(t_rel: int) -> dt.datetime:
        return base - dt.timedelta(seconds=t_rel)

    def timed(name: str) -> list[dict[str, Any]]:
        key = TEXT_FIELDS.get(name)
        out = []
        for item in getattr(manifest, name):
            row = {k: v for k, v in item.items() if k not in ("t_rel_s", "date_slots")}
            if key and item.get("date_slots"):
                row[key] = fill_slots(item[key], item["date_slots"], base)
            row["ts_ms"] = _ms(at(item["t_rel_s"]))
            out.append(row)
        return out

    events = []
    for ev in manifest.events:
        row = {
            k: v
            for k, v in ev.items()
            if k not in ("t_rel_s", "date_slots", "occurrence")
        }
        if ev.get("date_slots"):
            row["title"] = fill_slots(ev["title"], ev["date_slots"], base)
        if ev.get("rule"):
            day = nth_occurrence(
                ev["rule"], base.date(), int(ev.get("occurrence") or 0)
            )
            if day is None or (ev["kind"] == "holiday" and day < oldest):
                continue
            start = dt.datetime.combine(day, dt.time(), tzinfo=base.tzinfo)
        else:
            start = at(ev["t_rel_s"])
        minutes = ev.get("minutes")
        end = start + (
            dt.timedelta(days=1)
            if ev.get("all_day")
            else dt.timedelta(minutes=minutes or 60)
        )
        row["ts_ms"], row["end_ms"] = _ms(start), _ms(end)
        events.append(row)
    events.sort(key=lambda e: (e["ts_ms"], e["id"]))
    return RenderedWorld(
        anchor=base.isoformat(),
        world_fp=manifest.world_fp,
        device=dict(manifest.device),
        owner=dict(manifest.owner),
        calendar_name=manifest.calendar_name,
        contacts=[dict(c) for c in manifest.contacts],
        sms=timed("sms"),
        calls=timed("calls"),
        events=events,
        photos=timed("photos"),
        files=timed("files"),
        notes=timed("notes"),
    )
