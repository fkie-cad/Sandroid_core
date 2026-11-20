"""World data packs: loading, the schema v1.1 validator and holiday rules.

Packs are YAML files (see ``PACK_SCHEMA.md`` next to this module):

* ``countries/<cc>.yaml``: one country (phone plan, names, places, services);
* ``languages/<lang>.yaml``: text templates of one language;
* ``photos/manifest.yaml``: the photo pool (the files are downloaded later).

Built-in packs ship in ``sandroid/assets/world``. User packs in
``$XDG_CONFIG_HOME/sandroid/world/{countries,languages,photos}`` replace a
built-in pack with the same id. Packs are parsed lazily: a generator run only
reads the packs it needs.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Schema versions this module reads. v1 packs are v1.1-compatible.
SCHEMA_VERSIONS = (1, 1.1, "1", "1.1")

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "assets" / "world"
#: A photo id: it names files in the photo cache, so no path characters.
PHOTO_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
PACK_KINDS = ("countries", "languages", "photos")

#: Service kinds known to the generator. Unknown kinds only warn.
SERVICE_KINDS = (
    "courier",
    "bank",
    "telecom",
    "otp_service",
    "doctor",
    "pharmacy",
    "delivery_food",
    "ride_hailing",
    "airline",
    "rail",
    "government",
    "retail",
    "utility",
    "mobile_money",
    "lender",
    "betting",
)
#: Alternative spellings of service kinds (``service_sms`` keys too).
KIND_ALIASES = {"loan": "lender"}
SENDER_TYPES = ("alphanumeric", "number", "shortcode")
RELATIONSHIPS = ("family", "partner", "friend", "colleague", "neighbor")
CALL_NAME_KEYS = (
    "mom",
    "dad",
    "grandma",
    "grandpa",
    "partner",
    "sister",
    "brother",
    "aunt",
    "uncle",
    "son",
    "daughter",
)
PLACE_CATEGORIES = (
    "park",
    "landmark",
    "station",
    "airport",
    "beach",
    "mountain",
    "museum",
    "stadium",
    "market",
    "lake",
)
PHOTO_CATEGORIES = (
    "food",
    "street",
    "nature",
    "pet",
    "interior",
    "landmark_generic",
    "sky",
    "document_like",
    "screenshot_like",
    "vehicle",
    "sport",
    "plant",
    "travel",
    "event",
    "shopping",
    "selfie_like_no_face",
)
PHOTO_LICENCES = ("CC0-1.0", "PDM-1.0", "authored")

#: Placeholders allowed in language-pack text (``digits:N`` is a pattern).
TEXT_PLACEHOLDERS = frozenset(
    {
        "owner_first",
        "first",
        "partner_first",
        "last",
        "place",
        "city",
        "state",
        "district",
        "time",
        "day",
        "date",
        "date_file",
        "amount",
        "balance",
        "fee",
        "code",
        "tracking",
        "shop",
        "bank",
        "courier",
    }
)
EMAIL_PLACEHOLDERS = frozenset({"first", "last", "f", "l", "yy", "yyyy", "nn"})
ADDRESS_PLACEHOLDERS = frozenset(
    {"street", "number", "postcode", "city", "state", "district"}
)
NAME_PLACEHOLDERS = frozenset({"first", "last"})

_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
_DIGITS_RE = re.compile(r"digits:(\d+)")
_MMDD_RE = re.compile(r"^(\d{2})-(\d{2})$")
_EASTER_RE = re.compile(r"^easter(?:([+-])(\d+))?$")
_DOW_RE = re.compile(r"^(\d{2})-(mon|tue|wed|thu|fri|sat|sun)#(-1|[1-5])$")
_HIJRI_RE = re.compile(r"^hijri:(\d{2})-(\d{2})$")
_LUNISOLAR_RE = re.compile(r"^lunisolar:[a-z0-9_]+$")
_MARKUP_RE = re.compile(r"[{}\[\]|<>]")
_DOWS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class WorldError(ValueError):
    """A world cannot be built: unknown country, invalid user pack, no device.

    Attributes:
        report: The validation report when a pack is invalid, else None.
    """

    def __init__(self, message: str, report: ValidationReport | None = None) -> None:
        super().__init__(message)
        self.report = report


#: Fields of a persona device.
DEVICE_KEYS = ("make", "model", "codename", "min_sdk", "max_sdk")


def device_problem(device: Any) -> str | None:
    """Return what is wrong with a device mapping, or None.

    A device needs non-empty ``make``, ``model`` and ``codename`` strings;
    ``min_sdk`` and ``max_sdk`` are optional API levels (null: open-ended);
    a pack entry may add a weight ``w``.
    """
    if not isinstance(device, dict):
        return "must be a mapping {make, model, codename, min_sdk, max_sdk}"
    unknown = sorted(str(k) for k in set(device) - set(DEVICE_KEYS) - {"w"})
    if unknown:
        return f"unknown keys {', '.join(unknown)}"
    for key in ("make", "model", "codename"):
        if not isinstance(device.get(key), str) or not device[key].strip():
            return f"{key} must be a non-empty string"
    for key in ("min_sdk", "max_sdk"):
        value = device.get(key)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
        ):
            return f"{key} must be a positive API level or null"
    lo, hi = device.get("min_sdk"), device.get("max_sdk")
    if lo is not None and hi is not None and lo > hi:
        return "min_sdk is above max_sdk"
    w = device.get("w", 1)
    if isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0:
        return "w must be a non-negative number"
    return None


def normalize_device(device: dict[str, Any]) -> dict[str, Any]:
    """Return a device with exactly :data:`DEVICE_KEYS` (no weight)."""
    return {key: device.get(key) for key in DEVICE_KEYS}


def device_fits(device: dict[str, Any], sdk: int) -> bool:
    """Return whether ``min_sdk <= sdk <= max_sdk`` (missing bounds are open)."""
    lo, hi = device.get("min_sdk"), device.get("max_sdk")
    return (lo is None or lo <= sdk) and (hi is None or sdk <= hi)


def _yaml_load(text: str) -> Any:
    """Parse YAML with the safe loader (the C build when available)."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return yaml.load(text, Loader=loader)  # noqa: S506 - safe loaders only


def user_pack_dir() -> Path:
    """Return the user pack directory (``$XDG_CONFIG_HOME/sandroid/world``)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "sandroid" / "world"


def photo_cache_dir() -> Path:
    """Return the photo download cache (``$XDG_CACHE_HOME/sandroid/world/photos``)."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sandroid" / "world" / "photos"


# --------------------------------------------------------------------- loading


@dataclass(frozen=True)
class Pack:
    """One parsed pack.

    Attributes:
        kind: ``"countries"``, ``"languages"`` or ``"photos"``.
        id: Pack id (file stem; ``"manifest"`` for photos).
        data: The parsed YAML mapping.
        path: Source file.
        sha256: SHA-256 of the file bytes.
        builtin: True for a pack shipped with Sandroid.
    """

    kind: str
    id: str
    data: dict[str, Any] = field(repr=False, compare=False, hash=False)
    path: Path
    sha256: str
    builtin: bool

    @property
    def key(self) -> str:
        """``"<kind>/<id>"``, e.g. ``"countries/de"``."""
        return f"{self.kind}/{self.id}"


def read_pack(path: Path, kind: str, *, builtin: bool = False) -> Pack:
    """Read one pack file.

    Args:
        path: The YAML file.
        kind: One of :data:`PACK_KINDS`.
        builtin: Whether the file ships with Sandroid.

    Returns:
        The parsed pack.

    Raises:
        ValueError: The file is not a YAML mapping.
    """
    raw = path.read_bytes()
    data = _yaml_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: a pack must be a YAML mapping")  # noqa: TRY004
    pack_id = "manifest" if kind == "photos" else path.stem
    return Pack(
        kind=kind,
        id=pack_id,
        data=data,
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        builtin=builtin,
    )


class PackSet:
    """The available packs, built-in overridden by user packs, parsed lazily.

    Args:
        builtin_dir: Directory with the built-in packs.
        user_dir: Directory with user packs; ``None`` uses
            :func:`user_pack_dir`, ``False`` disables user packs.
    """

    def __init__(
        self,
        builtin_dir: Path | None = None,
        user_dir: Path | None | bool = None,
    ) -> None:
        self.builtin_dir = Path(builtin_dir) if builtin_dir else BUILTIN_DIR
        if user_dir is None or user_dir is True:
            self.user_dir: Path | None = user_pack_dir()
        elif user_dir is False:
            self.user_dir = None
        else:
            self.user_dir = Path(user_dir)
        self._files: dict[str, dict[str, tuple[Path, bool]]] = {
            k: {} for k in PACK_KINDS
        }
        roots = [(self.builtin_dir, True)]
        if self.user_dir is not None:
            roots.append((self.user_dir, False))
        for root, builtin in roots:  # later roots override earlier ones
            for kind in ("countries", "languages"):
                folder = root / kind
                if folder.is_dir():
                    for path in sorted(folder.glob("*.yaml")):
                        self._files[kind][path.stem] = (path, builtin)
            manifest = root / "photos" / "manifest.yaml"
            if manifest.is_file():
                self._files["photos"]["manifest"] = (manifest, builtin)
        self._cache: dict[str, Pack] = {}

    def ids(self, kind: str) -> list[str]:
        """Return the sorted pack ids of one kind."""
        return sorted(self._files[kind])

    def has(self, kind: str, pack_id: str) -> bool:
        """Return whether a pack exists."""
        return pack_id in self._files[kind]

    def get(self, kind: str, pack_id: str, *, validate: bool = True) -> Pack:
        """Return one pack, parsing it on first use.

        User packs are validated on first use (built-in packs are validated by
        the test suite).

        Args:
            kind: One of :data:`PACK_KINDS`.
            pack_id: The pack id.
            validate: Validate a user pack; False only reads it.

        Raises:
            KeyError: No such pack.
            WorldError: A user pack cannot be parsed or has validation errors.
        """
        key = f"{kind}/{pack_id}"
        pack = self._cache.get(key)
        if pack is not None:
            return pack
        if pack_id not in self._files[kind]:
            raise KeyError(f"no {kind} pack {pack_id!r}")
        path, builtin = self._files[kind][pack_id]
        try:
            pack = read_pack(path, kind, builtin=builtin)
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            raise WorldError(f"cannot read {kind} pack {path}: {exc}") from exc
        if not builtin and validate:
            report = validate_pack(pack, packs=self)
            if report.errors:
                shown = "; ".join(report.errors[:5])
                more = len(report.errors) - 5
                raise WorldError(
                    f"user pack {path} is invalid: {shown}"
                    + (f" (+{more} more)" if more > 0 else ""),
                    report,
                )
        self._cache[key] = pack
        return pack

    def country(self, pack_id: str) -> Pack:
        """Return a country pack."""
        return self.get("countries", pack_id)

    def language(self, pack_id: str) -> Pack:
        """Return a language pack."""
        return self.get("languages", pack_id)

    def photos(self) -> Pack | None:
        """Return the photo manifest, or None when there is none."""
        return (
            self.get("photos", "manifest") if self.has("photos", "manifest") else None
        )

    def validate_all(self) -> dict[str, ValidationReport]:
        """Validate every pack; keys are ``"<kind>/<id>"``."""
        out: dict[str, ValidationReport] = {}
        for kind in PACK_KINDS:
            for pack_id in self.ids(kind):
                try:
                    pack = self.get(kind, pack_id, validate=False)
                except WorldError as exc:
                    out[f"{kind}/{pack_id}"] = ValidationReport(
                        f"{kind}/{pack_id}", errors=[str(exc)]
                    )
                    continue
                out[pack.key] = validate_pack(pack, packs=self)
        return out


def load_packs(user_dir: Path | None | bool = None) -> PackSet:
    """Return the built-in packs overridden by the user's packs.

    Args:
        user_dir: See :class:`PackSet`.
    """
    return PackSet(user_dir=user_dir)


# ------------------------------------------------------------------- holidays


def easter(year: int) -> dt.date:
    """Return Western (Gregorian) Easter Sunday (anonymous Gregorian algorithm)."""
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l_ = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l_) // 451
    month, day = divmod(h + l_ - 7 * m + 114, 31)
    return dt.date(year, month, day + 1)


def _hijri_to_jd(year: int, month: int, day: int) -> int:
    """Tabular Islamic calendar (civil epoch) to Julian day number."""
    return (
        day
        + math.ceil(29.5 * (month - 1))
        + (year - 1) * 354
        + (3 + 11 * year) // 30
        + 1948440
        - 1
    )


def _jd_to_date(jd: int) -> dt.date:
    return dt.date.fromordinal(jd - 1721425)


def parse_holiday(entry: dict[str, Any]) -> tuple[str, tuple[Any, ...]] | None:
    """Parse a holiday's ``date`` or ``rule``.

    Returns:
        ``(form, args)`` where form is one of ``"fixed"``, ``"easter"``,
        ``"dow"``, ``"hijri"``, ``"lunisolar"``; None when the entry is
        malformed.
    """
    if "date" in entry and "rule" not in entry:
        m = _MMDD_RE.match(str(entry["date"]))
        if not m:
            return None
        month, day = int(m.group(1)), int(m.group(2))
        try:
            dt.date(2024, month, day)  # leap year accepts 02-29
        except ValueError:
            return None
        return ("fixed", (month, day))
    if "rule" in entry and "date" not in entry:
        rule = str(entry["rule"]).strip()
        m = _MMDD_RE.match(rule)
        if m:
            return parse_holiday({"date": rule})
        m = _EASTER_RE.match(rule)
        if m:
            offset = int(m.group(2) or 0) * (-1 if m.group(1) == "-" else 1)
            return ("easter", (offset,))
        m = _DOW_RE.match(rule)
        if m and 1 <= int(m.group(1)) <= 12:
            return ("dow", (int(m.group(1)), _DOWS.index(m.group(2)), int(m.group(3))))
        m = _HIJRI_RE.match(rule)
        if m and 1 <= int(m.group(1)) <= 12 and 1 <= int(m.group(2)) <= 30:
            return ("hijri", (int(m.group(1)), int(m.group(2))))
        if _LUNISOLAR_RE.match(rule):
            return ("lunisolar", (rule.split(":", 1)[1],))
    return None


def holiday_dates(entry: dict[str, Any], year: int) -> list[dt.date]:
    """Return the dates of a holiday in one Gregorian year.

    Calendar systems the generator cannot compute (``lunisolar:``) give an
    empty list. ``hijri:`` uses the tabular Islamic calendar, which may be one
    or two days off the observed (moon-sighted) date.
    """
    parsed = parse_holiday(entry)
    if parsed is None:
        return []
    form, args = parsed
    if form == "fixed":
        month, day = args
        try:
            return [dt.date(year, month, day)]
        except ValueError:
            return []  # 02-29 in a common year
    if form == "easter":
        return [easter(year) + dt.timedelta(days=args[0])]
    if form == "dow":
        month, dow, nth = args
        if nth > 0:
            first = dt.date(year, month, 1)
            day = first + dt.timedelta(days=(dow - first.weekday()) % 7 + 7 * (nth - 1))
            return [day] if day.month == month else []
        nxt = dt.date(year + (month == 12), month % 12 + 1, 1)
        last = nxt - dt.timedelta(days=1)
        return [last - dt.timedelta(days=(last.weekday() - dow) % 7)]
    if form == "hijri":
        month, day = args
        out = []
        approx = int((year - 622) * 33 / 32)  # hijri year near this Gregorian year
        for hy in range(approx - 1, approx + 3):
            d = _jd_to_date(_hijri_to_jd(hy, month, day))
            if d.year == year:
                out.append(d)
        return sorted(out)
    return []


#: Calendar events may lie this far after the anchor.
LOOKAHEAD_DAYS = 60


def recent_occurrences(
    entry: dict[str, Any], ref: dt.date, years: int
) -> list[dt.date]:
    """Return a rule's dates on or before ``ref``, newest first.

    Looks back ``years`` years. A ``02-29`` rule falls on 1 March in common
    years.
    """
    out: list[dt.date] = []
    for year in range(ref.year - years, ref.year + 1):
        days = holiday_dates(entry, year)
        if not days and str(entry.get("date", entry.get("rule"))) == "02-29":
            days = [dt.date(year, 3, 1)]
        out += [d for d in days if d <= ref]
    return sorted(set(out), reverse=True)


def nth_occurrence(rule: str, anchor: dt.date, n: int) -> dt.date | None:
    """Return the n-th newest date of ``rule`` up to ``LOOKAHEAD_DAYS`` after ``anchor``.

    ``n = 0`` is the latest occurrence not more than :data:`LOOKAHEAD_DAYS`
    after the anchor, ``n = 1`` the one before it, and so on. This keeps a
    holiday or birthday at the same place in the world's history whatever
    the anchor's date.
    """
    ref = anchor + dt.timedelta(days=LOOKAHEAD_DAYS)
    days = recent_occurrences({"rule": rule}, ref, n + 2)
    return days[n] if n < len(days) else None


# ------------------------------------------------------------------ validator


@dataclass
class ValidationReport:
    """Result of :func:`validate_pack`.

    Attributes:
        pack: ``"<kind>/<id>"``.
        errors: Problems that make the pack unusable or wrong.
        warnings: Content gaps and soft-limit misses; the pack still works.
    """

    pack: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when there are no errors."""
        return not self.errors


def placeholders(text: str) -> list[str]:
    """Return the placeholder names in a template (``digits:6`` kept as is)."""
    return _PLACEHOLDER_RE.findall(text)


def _unknown_placeholders(text: str, allowed: frozenset[str]) -> list[str]:
    bad = []
    for name in placeholders(text):
        if name in allowed or _DIGITS_RE.fullmatch(name):
            continue
        bad.append(name)
    return bad


def entry_text(entry: Any, *keys: str) -> str | None:
    """Return the text of a v1.1 text entry (a string or a mapping)."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in keys or ("text", "title", "name"):
            value = entry.get(key)
            if isinstance(value, str):
                return value
    return None


class _Checker:
    """Collects errors and warnings with a path prefix."""

    def __init__(self, report: ValidationReport) -> None:
        self.r = report

    def err(self, path: str, msg: str) -> None:
        self.r.errors.append(f"{path}: {msg}")

    def warn(self, path: str, msg: str) -> None:
        self.r.warnings.append(f"{path}: {msg}")

    def require(self, data: dict[str, Any], key: str, typ: Any, path: str) -> Any:
        if key not in data:
            self.err(f"{path}.{key}" if path else key, "missing")
            return None
        value = data[key]
        if not isinstance(value, typ):
            self.err(
                f"{path}.{key}" if path else key,
                f"expected {getattr(typ, '__name__', typ)}, got {type(value).__name__}",
            )
            return None
        return value

    def count(
        self, items: Any, path: str, *, minimum: int = 1, recommended: int = 0
    ) -> None:
        n = len(items) if isinstance(items, (list, dict)) else 0
        if n < minimum:
            self.err(path, f"needs at least {minimum} entries, has {n}")
        elif recommended and n < recommended:
            self.warn(path, f"has {n} entries, schema recommends {recommended}+")

    def text(self, text: str, path: str, allowed: frozenset[str]) -> None:
        for name in _unknown_placeholders(text, allowed):
            self.err(path, f"unknown placeholder {{{name}}}")


def validate_pack(
    pack: Pack | dict[str, Any],
    *,
    packs: PackSet | None = None,
    pack_id: str | None = None,
) -> ValidationReport:
    """Validate one pack against schema v1.1.

    Errors: missing required keys, wrong types, counts below the hard
    minimum, unknown placeholders, malformed phone ranges and holiday rules.
    Warnings: counts below the schema's recommendation, unknown service kinds
    and categories, missing number levels, and references (languages,
    cultures) that no pack resolves.

    Args:
        pack: A :class:`Pack` or a raw mapping.
        packs: The pack set used to resolve references; None skips them.
        pack_id: Expected id for a raw mapping (the file stem).

    Returns:
        The report.
    """
    if isinstance(pack, Pack):
        data, kind, pid = pack.data, pack.kind, pack.id
    else:
        data = pack
        kind = {
            "country": "countries",
            "language": "languages",
            "photos": "photos",
        }.get(str(data.get("pack")), "?")
        pid = pack_id or str(data.get("country") or data.get("lang") or "manifest")
    report = ValidationReport(pack=f"{kind}/{pid}")
    c = _Checker(report)
    if data.get("schema") not in SCHEMA_VERSIONS:
        c.err("schema", f"unsupported schema {data.get('schema')!r}")
    expected = {"countries": "country", "languages": "language", "photos": "photos"}
    if data.get("pack") != expected.get(kind):
        c.err("pack", f"expected {expected.get(kind)!r}, got {data.get('pack')!r}")
        return report
    if kind == "countries":
        _validate_country(c, data, pid, packs)
    elif kind == "languages":
        _validate_language(c, data, pid)
    else:
        _validate_photos(c, data)
    return report


def _validate_country(
    c: _Checker, d: dict[str, Any], pid: str, packs: PackSet | None
) -> None:
    if d.get("country") != pid:
        c.err("country", f"{d.get('country')!r} does not match the file name {pid!r}")
    c.require(d, "name", str, "")
    langs = c.require(d, "languages", dict, "")
    if langs:
        for lang, share in langs.items():
            if not isinstance(share, (int, float)) or share < 0:
                c.err(f"languages.{lang}", "share must be a non-negative number")
            elif packs is not None and not packs.has("languages", str(lang)):
                c.warn(f"languages.{lang}", "no language pack")
    tzs = c.require(d, "timezones", list, "")
    if tzs is not None:
        c.count(tzs, "timezones")
    c.require(d, "date_format", str, "")
    c.require(d, "time_format", str, "")
    cur = c.require(d, "currency", dict, "")
    if cur:
        for key in ("code", "symbol", "format"):
            c.require(cur, key, str, "currency")
        for key in ("format", "sms_format"):
            if isinstance(cur.get(key), str) and not re.search(r"\d", cur[key]):
                c.err(f"currency.{key}", "needs an example amount with digits")
    _validate_phone(c, d.get("phone"))
    carriers = c.require(d, "carriers", list, "")
    if carriers is not None:
        c.count(carriers, "carriers")
        for i, car in enumerate(carriers):
            if not isinstance(car, dict) or not isinstance(car.get("name"), str):
                c.err(f"carriers[{i}]", "needs a name")
    cities = c.require(d, "cities", list, "")
    if cities is not None:
        c.count(cities, "cities", recommended=8)
        for i, city in enumerate(cities):
            p = f"cities[{i}]"
            if not isinstance(city, dict):
                c.err(p, "must be a mapping")
                continue
            c.require(city, "name", str, p)
            _check_latlon(c, city, p)
            if not isinstance(city.get("population", 0), (int, float)):
                c.err(f"{p}.population", "must be a number")
    streets = c.require(d, "streets", list, "")
    if streets is not None:
        c.count(streets, "streets", recommended=40)
    addr = c.require(d, "address_format", str, "")
    if addr:
        c.text(addr, "address_format", ADDRESS_PLACEHOLDERS)
    places = c.require(d, "places", list, "")
    if places is not None:
        c.count(places, "places", minimum=0, recommended=10)
        for i, place in enumerate(places):
            p = f"places[{i}]"
            if not isinstance(place, dict) or not isinstance(place.get("name"), str):
                c.err(p, "needs a name")
                continue
            _check_latlon(c, place, p)
            if place.get("category") not in PLACE_CATEGORIES:
                c.warn(f"{p}.category", f"unknown category {place.get('category')!r}")
    _validate_names(c, d.get("names"))
    cultures = c.require(d, "cultures", list, "")
    for i, cult in enumerate(cultures or []):
        p = f"cultures[{i}]"
        if not isinstance(cult, dict) or not isinstance(cult.get("culture"), str):
            c.err(p, "needs a culture id")
            continue
        if not isinstance(cult.get("share"), (int, float)) or cult["share"] < 0:
            c.err(f"{p}.share", "must be a non-negative number")
        if packs is not None and not packs.has("countries", cult["culture"]):
            c.warn(p, f"culture {cult['culture']!r} has no country pack")
    email = c.require(d, "email", dict, "")
    if email:
        doms = c.require(email, "domains", list, "email")
        if doms is not None:
            c.count(doms, "email.domains")
        pats = c.require(email, "patterns", list, "email")
        if pats is not None:
            c.count(pats, "email.patterns")
            for i, pat in enumerate(pats):
                if isinstance(pat, str):
                    c.text(pat, f"email.patterns[{i}]", EMAIL_PLACEHOLDERS)
    services = c.require(d, "services", list, "")
    for i, svc in enumerate(services or []):
        p = f"services[{i}]"
        if not isinstance(svc, dict) or not isinstance(svc.get("sender"), str):
            c.err(p, "needs a sender string")
            continue
        kind = KIND_ALIASES.get(svc.get("kind"), svc.get("kind"))
        if kind not in SERVICE_KINDS:
            c.warn(f"{p}.kind", f"unknown service kind {svc.get('kind')!r}")
        stype = svc.get("sender_type")
        if stype not in SENDER_TYPES:
            c.err(f"{p}.sender_type", f"must be one of {SENDER_TYPES}, got {stype!r}")
        elif stype == "number" and not re.fullmatch(
            r"\+\d[\d ]*(\.\.\.)?", svc["sender"]
        ):
            c.err(f"{p}.sender", "a number sender is '+<digits>' or '+<digits>...'")
        elif stype == "shortcode" and not svc["sender"].isdigit():
            c.warn(
                f"{p}.sender",
                f"shortcode {svc['sender']!r} has no numeric code"
                + (" (label set)" if svc.get("label") else ""),
            )
        if "label" in svc and not isinstance(svc["label"], str):
            c.err(f"{p}.label", "must be a string")
    holidays = c.require(d, "holidays", list, "")
    for i, hol in enumerate(holidays or []):
        p = f"holidays[{i}]"
        if not isinstance(hol, dict) or not isinstance(hol.get("name"), str):
            c.err(p, "needs a name")
            continue
        parsed = parse_holiday(hol)
        if parsed is None:
            c.err(p, f"bad date/rule {hol.get('date', hol.get('rule'))!r}")
        for flag in ("regional", "observance"):
            if flag in hol and not isinstance(hol[flag], bool):
                c.err(f"{p}.{flag}", "must be true or false")
    devices = d.get("devices")
    if devices is not None:
        if not isinstance(devices, list):
            c.err("devices", "must be a list of devices")
        else:
            for i, dev in enumerate(devices):
                problem = device_problem(dev)
                if problem:
                    c.err(f"devices[{i}]", problem)
                elif dev["make"] != "Google":
                    c.warn(f"devices[{i}]", "apps will see a Google Pixel instead")
    apps = c.require(d, "popular_apps", list, "")
    if apps is not None:
        c.count(apps, "popular_apps", minimum=0, recommended=20)
        for i, app in enumerate(apps):
            if not isinstance(app, dict) or not isinstance(app.get("package"), str):
                c.err(f"popular_apps[{i}]", "needs a package id")


def _check_latlon(c: _Checker, d: dict[str, Any], path: str) -> None:
    lat, lon = d.get("lat"), d.get("lon")
    if not isinstance(lat, (int, float)) or not -90 <= lat <= 90:
        c.err(f"{path}.lat", f"bad latitude {lat!r}")
    if not isinstance(lon, (int, float)) or not -180 <= lon <= 180:
        c.err(f"{path}.lon", f"bad longitude {lon!r}")


def parse_range(text: str) -> tuple[int, int, int] | None:
    """Parse a fiction range ``"A-B"`` into ``(low, high, digits)``."""
    m = re.fullmatch(r"(\d+)-(\d+)", str(text).strip())
    if not m or len(m.group(1)) != len(m.group(2)):
        return None
    low, high = int(m.group(1)), int(m.group(2))
    return (low, high, len(m.group(1))) if low <= high else None


def _validate_phone(c: _Checker, phone: Any) -> None:
    if not isinstance(phone, dict):
        c.err("phone", "missing or not a mapping")
        return
    cc = c.require(phone, "country_code", str, "phone")
    if cc is not None and not re.fullmatch(r"[1-9]\d{0,2}", cc):
        c.err("phone.country_code", f"bad country code {cc!r}")
    trunk = c.require(phone, "trunk_prefix", str, "phone")
    if trunk and not trunk.isdigit():
        c.err("phone.trunk_prefix", "must be digits or empty")
    max_nsn = 15 - len(cc or "")
    mobile = c.require(phone, "mobile", dict, "phone")
    usable = 0
    if mobile is not None:
        for level in ("realistic", "unallocated"):
            entries = mobile.get(level)
            p = f"phone.mobile.{level}"
            if entries is None:
                c.warn(p, "no ranges at this level")
                continue
            if not isinstance(entries, list):
                c.err(p, "must be a list or null")
                continue
            usable += len(entries)
            for i, e in enumerate(entries):
                q = f"{p}[{i}]"
                if not isinstance(e, dict):
                    c.err(q, "must be a mapping")
                    continue
                prefix, length = str(e.get("prefix", "")), e.get("length")
                if not prefix.isdigit():
                    c.err(f"{q}.prefix", f"bad prefix {e.get('prefix')!r}")
                elif not isinstance(length, int) or not (
                    len(prefix) < length <= max_nsn
                ):
                    c.err(f"{q}.length", f"bad length {length!r} for {prefix!r}")
        usable += _validate_ranges(
            c, mobile.get("fiction"), "phone.mobile.fiction", max_nsn
        )
    if mobile is not None and not usable:
        c.err("phone.mobile", "no mobile numbers at any level")
    land = c.require(phone, "landline", dict, "phone")
    if land is not None:
        lcities = land.get("cities")
        if not isinstance(lcities, list):
            c.err("phone.landline.cities", "must be a list")
        else:
            for i, e in enumerate(lcities):
                q = f"phone.landline.cities[{i}]"
                if not isinstance(e, dict):
                    c.err(q, "must be a mapping")
                    continue
                area = str(e.get("area_code", ""))
                sub = e.get("subscriber_length")
                if not area.isdigit():
                    c.err(f"{q}.area_code", f"bad area code {e.get('area_code')!r}")
                elif not isinstance(sub, int) or not 3 <= len(area) + sub <= max_nsn:
                    c.err(f"{q}.subscriber_length", f"bad length {sub!r}")
        _validate_ranges(c, land.get("fiction"), "phone.landline.fiction", max_nsn)


def _validate_ranges(c: _Checker, entries: Any, path: str, max_nsn: int) -> int:
    if entries is None:
        c.warn(path, "no ranges at this level")
        return 0
    if not isinstance(entries, list):
        c.err(path, "must be a list or null")
        return 0
    for i, e in enumerate(entries):
        q = f"{path}[{i}]"
        parsed = parse_range(e.get("range", "")) if isinstance(e, dict) else None
        if parsed is None:
            c.err(q, f"bad range {e!r}")
        elif parsed[2] > max_nsn:
            c.err(q, "range longer than an E.164 number allows")
    return len(entries)


def _validate_names(c: _Checker, names: Any) -> None:
    if not isinstance(names, dict):
        c.err("names", "missing or not a mapping")
        return
    tags: set[str] = set()
    for pool, rec in (("female", 80), ("male", 80), ("surnames", 150)):
        entries = c.require(names, pool, list, "names")
        if entries is None:
            continue
        c.count(entries, f"names.{pool}", recommended=rec)
        for i, e in enumerate(entries):
            p = f"names.{pool}[{i}]"
            if not isinstance(e, dict) or not isinstance(e.get("name"), str):
                c.err(p, "needs a name")
                continue
            if _MARKUP_RE.search(e["name"]):
                c.err(p, f"markup in name {e['name']!r}")
            if not isinstance(e.get("w", 1), (int, float)) or e.get("w", 1) < 0:
                c.err(f"{p}.w", "weight must be a non-negative number")
            g = e.get("g")
            if g is not None:
                if not isinstance(g, list) or not all(isinstance(x, str) for x in g):
                    c.err(f"{p}.g", "must be a list of group tags")
                else:
                    tags.update(g)
    groups = names.get("groups")
    if groups is not None:
        if not isinstance(groups, dict) or not all(
            isinstance(v, (int, float)) and v >= 0 for v in groups.values()
        ):
            c.err("names.groups", "must map group tags to non-negative shares")
        else:
            for tag in sorted(tags - set(groups)):
                c.warn("names.groups", f"tag {tag!r} has no share")
            for tag in sorted(set(groups) - tags):
                c.warn("names.groups", f"group {tag!r} is used by no name")
            for pool in ("female", "male", "surnames"):
                for tag in groups:
                    if not any(
                        tag in (e.get("g") or []) or not e.get("g")
                        for e in names.get(pool) or []
                        if isinstance(e, dict)
                    ):
                        c.err("names.groups", f"group {tag!r} has no {pool}")
    elif tags:
        c.warn(
            "names",
            "names carry g tags but names.groups is missing: tags only keep the "
            "surname in the first name's group",
        )
    display = c.require(names, "display", str, "names")
    if display:
        c.text(display, "names.display", NAME_PLACEHOLDERS)
    variants = names.get("display_variants")
    if variants is not None:
        if not isinstance(variants, list):
            c.err("names.display_variants", "must be a list")
        else:
            for i, v in enumerate(variants):
                p = f"names.display_variants[{i}]"
                if not isinstance(v, dict) or not isinstance(v.get("pattern"), str):
                    c.err(p, "needs a pattern")
                    continue
                c.text(v["pattern"], p, NAME_PLACEHOLDERS)
                if not isinstance(v.get("w", 1), (int, float)):
                    c.err(f"{p}.w", "weight must be a number")
    share = names.get("single_name_share")
    if share is not None and not (isinstance(share, (int, float)) and 0 <= share <= 1):
        c.err("names.single_name_share", "must be between 0 and 1")
    nick = names.get("nicknames")
    if nick is not None and not isinstance(nick, dict):
        c.err("names.nicknames", "must be a mapping")


def _validate_language(c: _Checker, d: dict[str, Any], pid: str) -> None:
    if d.get("lang") != pid:
        c.err("lang", f"{d.get('lang')!r} does not match the file name {pid!r}")
    c.require(d, "name", str, "")
    threads = c.require(d, "threads", dict, "")
    if threads is not None:
        for rel in RELATIONSHIPS:
            if rel not in threads:
                c.err(f"threads.{rel}", "missing")
                continue
            entries = threads[rel]
            if not isinstance(entries, list):
                c.err(f"threads.{rel}", "must be a list")
                continue
            c.count(entries, f"threads.{rel}", recommended=15)
            for i, t in enumerate(entries):
                p = f"threads.{rel}[{i}]"
                msgs = t.get("msgs") if isinstance(t, dict) else None
                if not isinstance(msgs, list) or not msgs:
                    c.err(p, "needs a non-empty msgs list")
                    continue
                for j, msg in enumerate(msgs):
                    if (
                        not isinstance(msg, list)
                        or len(msg) != 2
                        or msg[0] not in ("o", "p")
                        or not isinstance(msg[1], str)
                    ):
                        c.err(f"{p}.msgs[{j}]", "must be [o|p, text]")
                        continue
                    c.text(msg[1], f"{p}.msgs[{j}]", TEXT_PLACEHOLDERS)
                _check_tags(c, t, p)
        for rel in sorted(set(threads) - set(RELATIONSHIPS)):
            c.warn(f"threads.{rel}", "unknown relationship (ignored)")
    sms = c.require(d, "service_sms", dict, "")
    if sms is not None:
        for kind, entries in sms.items():
            p = f"service_sms.{kind}"
            if KIND_ALIASES.get(kind, kind) not in SERVICE_KINDS:
                c.warn(p, "unknown service kind")
            if not isinstance(entries, list):
                c.err(p, "must be a list")
                continue
            c.count(entries, p, recommended=5)
            _check_entries(c, entries, p, ("text",))
        for kind in SERVICE_KINDS[:13]:
            if kind not in sms:
                c.warn(f"service_sms.{kind}", "missing")
    cal = c.require(d, "calendar", list, "")
    if cal is not None:
        c.count(cal, "calendar", recommended=40)
        _check_entries(c, cal, "calendar", ("title",))
        for i, e in enumerate(cal):
            if isinstance(e, dict) and "minutes" in e:
                if not isinstance(e["minutes"], int) or e["minutes"] <= 0:
                    c.err(f"calendar[{i}].minutes", "must be a positive integer")
    files = c.require(d, "files", list, "")
    if files is not None:
        c.count(files, "files", recommended=30)
        _check_entries(c, files, "files", ("name",))
    notes = c.require(d, "notes", list, "")
    if notes is not None:
        c.count(notes, "notes", recommended=20)
        _check_entries(c, notes, "notes", ("text",))
    weekdays = d.get("weekdays")
    if weekdays is not None and (
        not isinstance(weekdays, list)
        or len(weekdays) != 7
        or not all(isinstance(x, str) for x in weekdays)
    ):
        c.err("weekdays", "must list seven day names, Monday first")
    if weekdays is None and "{day}" in _yaml_text(d):
        c.warn(
            "weekdays",
            "templates use {day} but the pack has no weekdays list; "
            "the generator skips them",
        )
    calls = c.require(d, "call_names", dict, "")
    if calls is not None:
        for key, value in calls.items():
            p = f"call_names.{key}"
            if key not in CALL_NAME_KEYS:
                c.warn(p, "unknown key (ignored)")
            values = value if isinstance(value, list) else [value]
            if not values or not all(isinstance(v, str) for v in values):
                c.err(p, "must be a string or a list of strings")
                continue
            for v in values:
                c.text(v, p, frozenset({"first"}))
        for key in ("mom", "dad", "partner"):
            if key not in calls:
                c.warn(f"call_names.{key}", "missing")


def _yaml_text(value: Any) -> str:
    """Concatenate every string in a nested structure."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_yaml_text(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_yaml_text(v) for v in value)
    return ""


def _check_entries(
    c: _Checker, entries: list[Any], path: str, keys: tuple[str, ...]
) -> None:
    for i, e in enumerate(entries):
        p = f"{path}[{i}]"
        text = entry_text(e, *keys)
        if text is None:
            c.err(p, f"must be a string or a mapping with {'/'.join(keys)}")
            continue
        c.text(text, p, TEXT_PLACEHOLDERS)
        if isinstance(e, dict):
            _check_tags(c, e, p)


def _check_tags(c: _Checker, e: dict[str, Any], path: str) -> None:
    regions = e.get("regions")
    if regions is not None and (
        not isinstance(regions, list) or not all(isinstance(r, str) for r in regions)
    ):
        c.err(f"{path}.regions", "must be a list of region ids")
    script = e.get("script")
    if script is not None and not (
        isinstance(script, str) and re.fullmatch(r"[A-Z][a-z]{3}", script)
    ):
        c.err(f"{path}.script", f"must be an ISO 15924 code, got {script!r}")


def _validate_photos(c: _Checker, d: dict[str, Any]) -> None:
    photos = c.require(d, "photos", list, "")
    if photos is None:
        return
    c.count(photos, "photos")
    seen: set[str] = set()
    for i, ph in enumerate(photos):
        p = f"photos[{i}]"
        if not isinstance(ph, dict):
            c.err(p, "must be a mapping")
            continue
        pid = c.require(ph, "id", str, p)
        if pid is not None and not PHOTO_ID_RE.fullmatch(pid):
            c.err(f"{p}.id", f"invalid id {pid!r} (a-z, 0-9, '_', '-')")
        if pid in seen:
            c.err(f"{p}.id", f"duplicate id {pid!r}")
        seen.add(pid or "")
        c.require(ph, "file", str, p)
        sha = c.require(ph, "sha256", str, p)
        if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
            c.err(f"{p}.sha256", "must be 64 lower-case hex digits")
        lic = ph.get("licence")
        if lic not in PHOTO_LICENCES:
            c.err(f"{p}.licence", f"must be one of {PHOTO_LICENCES}, got {lic!r}")
        if lic != "authored":
            for key in ("url", "page"):
                c.require(ph, key, str, p)
        for key in ("width", "height", "bytes"):
            value = ph.get(key)
            if not isinstance(value, int) or value <= 0:
                c.err(f"{p}.{key}", "must be a positive integer")
        if ph.get("category") not in PHOTO_CATEGORIES:
            c.warn(f"{p}.category", f"unknown category {ph.get('category')!r}")
        for key in ("has_people", "country_neutral"):
            if not isinstance(ph.get(key), bool):
                c.err(f"{p}.{key}", "must be true or false")
        if ph.get("has_people"):
            c.warn(f"{p}.has_people", "photo shows identifiable people")
        if ph.get("country_neutral") is False and not isinstance(
            ph.get("country"), str
        ):
            c.err(f"{p}.country", "required when country_neutral is false")
        for key in ("original_had_exif", "original_had_gps", "downscaled"):
            if key in ph and not isinstance(ph[key], bool):
                c.err(f"{p}.{key}", "must be true or false")
        if "original_exif_stripped" in ph:
            c.warn(f"{p}.original_exif_stripped", "dropped in v1.1 (ignored)")
        if ph.get("downscaled"):
            for key in ("sha256_original", "bytes_original"):
                if key not in ph:
                    c.warn(f"{p}.{key}", "missing for a downscaled photo")
