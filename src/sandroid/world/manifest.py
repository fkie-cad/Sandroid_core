"""World spec, owner and the generated :class:`WorldManifest`.

The manifest is plain JSON: every list item is a dict, so the manifest
serialises byte-identically and round-trips without loss. ``world_fp`` is the
SHA-256 of the canonical JSON of everything else except ``warnings``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any

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
#: The item lists of a manifest, in manifest order.
LISTS = ("people", "contacts", "sms", "calls", "events", "photos", "files", "notes")

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


@dataclass
class WorldSpec:
    """The ``world:`` section of a persona/identity profile.

    Attributes:
        seed: ``"auto"`` or ``"hex:<32+ hex>"``.
        size: ``small``, ``medium`` or ``large``.
        country: Primary country pack id; None derives it from the owner's
            phone country code.
        mix: Culture shares of the people (country-pack ids); None uses the
            country pack's ``cultures``.
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
    device: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> WorldSpec:
        """Build a spec from a ``world:`` mapping.

        Raises:
            ValueError: Unknown keys or invalid values.
        """
        data = dict(data or {})
        unknown = sorted(set(data) - set(_SPEC_KEYS))
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
        """Check the values.

        Raises:
            ValueError: An invalid value.
        """
        if self.size not in SIZES:
            raise ValueError(f"world size must be one of {tuple(SIZES)}")
        if self.numbers not in NUMBER_LEVELS:
            raise ValueError(f"world numbers must be one of {NUMBER_LEVELS}")
        self.history_seconds()
        for key, value in self.counts.items():
            if key not in SIZES["small"]:
                raise ValueError(f"unknown world count {key!r}")
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"world count {key!r} must be a non-negative int")
        if self.mix is not None:
            if not isinstance(self.mix, dict) or not self.mix:
                raise ValueError("world mix must be a non-empty mapping")
            for key, value in self.mix.items():
                if not isinstance(value, (int, float)) or value < 0:
                    raise ValueError(f"world mix share for {key!r} must be >= 0")
        if self.device is not None:
            problem = device_problem(self.device)
            if problem:
                raise ValueError(f"world device: {problem}")
        if not isinstance(self.places, dict):
            raise ValueError("world places must be a mapping")  # noqa: TRY004

    def history_seconds(self) -> int:
        """Return :attr:`history` in seconds.

        Raises:
            ValueError: The history is not ``<n>d|w|mo|y``.
        """
        m = _HISTORY_RE.match(str(self.history).strip())
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
        """Build an owner from a mapping with first, last, phone, email."""
        if isinstance(data, Owner):
            return data
        return cls(
            first=str(data.get("first") or ""),
            last=str(data.get("last") or ""),
            phone=str(data.get("phone") or ""),
            email=str(data.get("email") or ""),
        )

    def to_dict(self) -> dict[str, str]:
        """Return the manifest form: first and last only."""
        return {"first": self.first, "last": self.last}


@dataclass
class WorldManifest:
    """A generated world.

    Attributes:
        spec: The spec with the seed resolved.
        seed: The resolved seed (``"hex:..."``); write it back to the profile
            when the spec said ``auto``.
        generator_version: :data:`sandroid.world.generator.GENERATOR_VERSION`.
        time_base: How ``t_rel_s`` and rendered text dates relate to the clock
            (see ``PACK_SCHEMA.md``, "Time").
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

    def markers(self) -> list[dict[str, Any]]:
        """Return the scanner markers (see :mod:`sandroid.world.markers`)."""
        from sandroid.world.markers import build_markers

        return build_markers(self)

    def to_markers(self) -> list[Marker]:
        """Return :meth:`markers` as ``privacy_markers.Marker`` objects."""
        from sandroid.world.markers import to_markers

        return to_markers(self.markers())


DEVICE_KEYS = ("make", "model", "codename", "min_sdk", "max_sdk")


def device_problem(device: Any) -> str | None:
    """Return what is wrong with a device mapping, or None.

    A device needs non-empty ``make``, ``model`` and ``codename`` strings;
    ``min_sdk`` and ``max_sdk`` are optional API levels (null: open-ended);
    a pack entry may add a weight ``w``.
    """
    if not isinstance(device, dict):
        return "must be a mapping {make, model, codename, min_sdk, max_sdk}"
    unknown = sorted(set(device) - set(DEVICE_KEYS) - {"w"})
    if unknown:
        return f"unknown keys {', '.join(unknown)}"
    for key in ("make", "model", "codename"):
        if not isinstance(device.get(key), str) or not device[key].strip():
            return f"{key} must be a non-empty string"
    for key in ("min_sdk", "max_sdk"):
        value = device.get(key)
        if value is not None and (not isinstance(value, int) or value <= 0):
            return f"{key} must be a positive API level or null"
    if not isinstance(device.get("w", 1), (int, float)) or device.get("w", 1) < 0:
        return "w must be a non-negative number"
    return None


def normalize_device(device: Mapping[str, Any]) -> dict[str, Any]:
    """Return a device with exactly :data:`DEVICE_KEYS` (no weight)."""
    return {key: device.get(key) for key in DEVICE_KEYS}


def canonical_json(value: Any) -> bytes:
    """Return the canonical JSON bytes used for fingerprints."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
