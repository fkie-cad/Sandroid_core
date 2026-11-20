"""Deterministic "lived-in world" generator (host only, no device).

:func:`generate` turns a world spec, the owner's name and the data packs into
a :class:`~sandroid.world.manifest.WorldManifest`: a social graph and the
phone contents derived from it (contacts, SMS, calls, calendar, photo
metadata, files, notes).

Determinism: every list draws from its own :class:`SeedStream` (label
``people``, ``sms``, ``photos`` ...), so the output depends only on the spec,
the owner's first and last name, the pack contents and
:data:`GENERATOR_VERSION`, and adding photos never changes the contacts.

Time: items carry ``t_rel_s``, seconds before the anchor (negative: after
it); the anchor is local midnight at the start of a Monday. Dates inside texts
stay ``{@n}`` slots with their own offset, and holidays and birthdays keep
their rule, so :meth:`WorldManifest.render` can place everything for any
anchor. :data:`NOMINAL_ANCHOR` only fixes the weekday arithmetic and the
holiday years while generating.
"""

from __future__ import annotations

import datetime as dt
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NamedTuple

from sandroid.world.manifest import (
    Owner,
    WorldManifest,
    WorldSpec,
    format_date,
)
from sandroid.world.packs import (
    KIND_ALIASES,
    LOOKAHEAD_DAYS,
    PackSet,
    WorldError,
    device_fits,
    device_problem,
    entry_text,
    load_packs,
    normalize_device,
    parse_range,
    recent_occurrences,
)
from sandroid.world.stream import Cumulative, SeedStream, new_seed, parse_seed

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from sandroid.world.packs import Pack

#: Bump when the output for the same inputs changes.
GENERATOR_VERSION = "1"
#: Local midnight (a Monday) used while generating (weekdays, holiday years).
NOMINAL_ANCHOR = dt.datetime(2026, 1, 5, 0, 0, 0)
DAY = 86400

# Relationship -> (thread type, closeness range). Closeness weights SMS/calls.
_RELATIONS: dict[str, tuple[str, float, float]] = {
    "partner": ("partner", 9.0, 12.0),
    "family": ("family", 2.0, 6.0),
    "friend": ("friend", 1.0, 4.0),
    "colleague": ("colleague", 0.6, 2.0),
    "neighbor": ("neighbor", 0.3, 1.0),
    "acquaintance": ("friend", 0.05, 0.4),
}
_FAMILY_ROLES = {
    "mom": ("f", 2.0),
    "dad": ("m", 2.0),
    "sister": ("f", 1.2),
    "brother": ("m", 1.2),
    "grandma": ("f", 0.8),
    "grandpa": ("m", 0.6),
    "aunt": ("f", 0.4),
    "uncle": ("m", 0.4),
    "son": ("m", 1.6),
    "daughter": ("f", 1.6),
}
# Activity by local hour (messages, calls).
_HOUR_W = (
    0.3, 0.15, 0.08, 0.05, 0.05, 0.1, 0.4, 1.0, 1.6, 1.5, 1.4, 1.5,
    1.9, 1.7, 1.4, 1.4, 1.5, 1.8, 2.2, 2.4, 2.3, 2.0, 1.4, 0.8,
)  # fmt: skip
_HOUR_CUM = Cumulative(_HOUR_W)
_PHOTO_CATEGORY_W = {
    "food": 0.14,
    "street": 0.08,
    "nature": 0.14,
    "pet": 0.08,
    "interior": 0.08,
    "landmark_generic": 0.07,
    "sky": 0.07,
    "document_like": 0.06,
    "screenshot_like": 0.12,
    "vehicle": 0.04,
    "sport": 0.04,
    "plant": 0.08,
}
_SERVICE_KIND_W = {
    "bank": 3.0,
    "mobile_money": 3.0,
    "otp_service": 3.0,
    "courier": 2.0,
    "telecom": 2.0,
    "delivery_food": 1.5,
    "ride_hailing": 1.0,
    "retail": 1.0,
    "lender": 0.8,
    "betting": 0.5,
}
#: Persona phones when neither the spec nor the country pack names devices.
#: Google Pixels only: the emulator bypass builds Google-format fingerprints.
#: min_sdk is the launch API level; max_sdk None means still supported.
FALLBACK_DEVICES: tuple[dict[str, Any], ...] = (
    {"make": "Google", "model": "Pixel 4a", "codename": "sunfish", "min_sdk": 29,
     "max_sdk": None, "w": 0.4},
    {"make": "Google", "model": "Pixel 5", "codename": "redfin", "min_sdk": 30,
     "max_sdk": None, "w": 0.5},
    {"make": "Google", "model": "Pixel 6", "codename": "oriole", "min_sdk": 31,
     "max_sdk": None, "w": 0.7},
    {"make": "Google", "model": "Pixel 6 Pro", "codename": "raven", "min_sdk": 31,
     "max_sdk": None, "w": 0.6},
    {"make": "Google", "model": "Pixel 6a", "codename": "bluejay", "min_sdk": 32,
     "max_sdk": None, "w": 0.7},
    {"make": "Google", "model": "Pixel 7", "codename": "panther", "min_sdk": 33,
     "max_sdk": None, "w": 1.0},
    {"make": "Google", "model": "Pixel 7a", "codename": "lynx", "min_sdk": 33,
     "max_sdk": None, "w": 1.0},
    {"make": "Google", "model": "Pixel 8", "codename": "shiba", "min_sdk": 34,
     "max_sdk": None, "w": 1.3},
    {"make": "Google", "model": "Pixel 8 Pro", "codename": "husky", "min_sdk": 34,
     "max_sdk": None, "w": 1.2},
    {"make": "Google", "model": "Pixel 8a", "codename": "akita", "min_sdk": 34,
     "max_sdk": None, "w": 1.3},
    {"make": "Google", "model": "Pixel 9", "codename": "tokay", "min_sdk": 35,
     "max_sdk": None, "w": 1.5},
)  # fmt: skip
_SERVICE_PICKS = {"bank": 2, "courier": 3, "otp_service": 3, "retail": 3}
_DOWNLOAD_KINDS = {"invoice", "receipt", "ticket", "statement", "payslip", "scan"}
_TRIP_CATEGORIES = ("beach", "mountain", "lake", "landmark", "museum")
_OUTING_CATEGORIES = ("park", "market", "lake", "museum", "stadium", "landmark")
# Emoji: pictographs (U+1F000..1FAFF), BMP symbols that default to emoji
# presentation, or any BMP symbol followed by the emoji selector U+FE0F.
# Plain dingbats (a check mark) and a lone joiner or selector are no emoji.
_EMOJI_RE = re.compile(
    "[\U0001f000-\U0001faff]"
    "|[\u231a\u231b\u23e9-\u23ec\u23f0\u23f3\u25fd\u25fe\u2614\u2615"
    "\u2648-\u2653\u267f\u2693\u26a1\u26aa\u26ab\u26bd\u26be\u26c4\u26c5"
    "\u26ce\u26d4\u26ea\u26f2\u26f3\u26f5\u26fa\u26fd\u2705\u270a\u270b"
    "\u2728\u274c\u274e\u2753-\u2755\u2757\u2795-\u2797\u27b0\u27bf\u2b1b"
    "\u2b1c\u2b50\u2b55]"
    "|[\u00a9\u00ae\u203c\u2049\u2122-\u2bff\u3030\u303d\u3297\u3299]\ufe0f"
)
#: Placeholders whose value makes a text distinctive enough for a marker.
_DISTINCTIVE = frozenset(
    {"first", "last", "partner_first", "owner_first", "code", "tracking",
     "amount", "balance", "fee"}
)  # fmt: skip
_DATE_SLOTS = frozenset({"date", "date_file", "day"})
_TRANSLIT = str.maketrans(
    {"ß": "ss", "ı": "i", "ø": "o", "Ø": "o", "æ": "ae", "Æ": "ae", "đ": "d",
     "ł": "l", "Ł": "l", "œ": "oe", "þ": "th", "ð": "d"}
)  # fmt: skip


class _Text(NamedTuple):
    """A rendered template: text with ``{@n}`` date slots."""

    text: str
    slots: list[dict[str, Any]]
    distinctive: bool

    def fields(self, key: str) -> dict[str, Any]:
        """Return the item fields for text field ``key``."""
        out: dict[str, Any] = {key: self.text, "distinctive": self.distinctive}
        if self.slots:
            out["date_slots"] = self.slots
        return out


@dataclass
class _Person:
    """A person of the social graph (internal)."""

    n: int
    role: str
    relation: str
    closeness: float
    culture: str
    language: str
    gender: str
    first: str
    last: str
    birth: dt.date
    numbers: list[dict[str, Any]] = field(default_factory=list)
    email: str | None = None
    city: str = ""

    @property
    def id(self) -> str:
        return f"world.people.{self.n}"

    @property
    def full_name(self) -> str:
        return f"{self.first} {self.last}".strip()

    @property
    def mobile(self) -> str | None:
        for num in self.numbers:
            if num["type"] == "mobile":
                return num["number"]
        return None


def generate(
    spec: WorldSpec | Mapping[str, Any],
    owner: Owner | Mapping[str, Any],
    *,
    packs: PackSet | None = None,
    target_sdk: int | None = None,
) -> WorldManifest:
    """Generate a world.

    Args:
        spec: The ``world:`` section (a :class:`WorldSpec` or a mapping).
        owner: ``{first, last, phone, email}``. Only first and last name and
            the phone's country code are used; phone and e-mail never reach
            the manifest.
        packs: The packs; None loads the built-in and user packs.
        target_sdk: API level of the emulator image. When the spec sets no
            device, only phones whose ``min_sdk <= target_sdk <= max_sdk``
            are drawn. Part of ``world_fp``.

    Returns:
        The manifest, with ``seed`` resolved (write it back when the spec said
        ``auto``) and ``world_fp`` set.

    Raises:
        WorldError: Unknown country, an invalid user pack, no usable packs,
            or no phone model for ``target_sdk``.
        ValueError: The spec or owner is invalid (WorldError is one too).
    """
    if not isinstance(spec, WorldSpec):
        spec = WorldSpec.from_dict(spec)
    spec.validate()
    owner = Owner.from_dict(owner)
    if target_sdk is not None and (
        isinstance(target_sdk, bool)
        or not isinstance(target_sdk, int)
        or target_sdk <= 0
    ):
        raise ValueError("target_sdk must be a positive API level")
    gen = _Generator(spec, owner, packs or load_packs())
    gen.target_sdk = target_sdk
    return gen.run()


# ----------------------------------------------------------------- helpers


def _ascii_slug(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.translate(_TRANSLIT))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _fill_email(pattern: str, values: dict[str, str], s: SeedStream) -> str:
    """Fill an e-mail pattern and keep only characters valid in a local part."""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name.startswith("digits:"):
            return s.digits(int(name[7:]))
        return values.get(name, "")

    local = re.sub(r"\{([^{}]+)\}", sub, pattern)
    return re.sub(r"[^a-z0-9._]", "", local.lower()).strip("._")


def _cum(entries: Sequence[dict[str, Any]], key: str = "w") -> Cumulative:
    return Cumulative([float(e.get(key, 1.0) or 0.0) for e in entries])


def has_emoji(text: str) -> bool:
    """Return whether a text contains an emoji (live SMS cannot carry them)."""
    return bool(_EMOJI_RE.search(text))


def parse_amount_format(example: str) -> tuple[str, str, str, str, int, float]:
    """Read a currency example such as ``"49,99 €"`` or ``"KSh 1,250.00"``.

    Returns:
        ``(prefix, suffix, decimal_sep, group_sep, decimals, value)``.
    """
    m = re.search(r"\d[\d.,\s  ']*\d|\d", example)
    if not m:
        raise ValueError(f"no amount in {example!r}")
    num = m.group(0)
    prefix, suffix = example[: m.start()], example[m.end() :]
    seps = [(i, ch) for i, ch in enumerate(num) if not ch.isdigit()]
    decimal_sep, group_sep, decimals = "", "", 0
    if seps:
        i, ch = seps[-1]
        tail = len(num) - i - 1
        if tail != 3 or (len(seps) > 1 and seps[0][1] != ch):
            decimal_sep, decimals = ch, tail
            if len(seps) > 1:
                group_sep = seps[0][1]
        else:
            group_sep = ch
    if not group_sep:
        group_sep = {",": ".", ".": ","}.get(decimal_sep, ",")
    digits = num
    for sep in (group_sep, " ", " ", " ", "'"):
        digits = digits.replace(sep, "")
    if decimal_sep:
        digits = digits.replace(decimal_sep, ".")
    return prefix, suffix, decimal_sep, group_sep, decimals, float(digits)


def format_amount(value: float, example: str) -> str:
    """Format ``value`` like the currency ``example``."""
    prefix, suffix, dec, grp, decimals, _ = parse_amount_format(example)
    whole, frac = f"{value:.{decimals}f}".partition(".")[::2]
    groups = []
    while len(whole) > 3:
        groups.insert(0, whole[-3:])
        whole = whole[:-3]
    groups.insert(0, whole)
    text = grp.join(groups)
    if decimals:
        text += dec + frac
    return f"{prefix}{text}{suffix}"


# --------------------------------------------------------------- numbers


def phone_check(e164: str) -> dict[str, Any]:
    """Check a number with libphonenumber (``phonenumberslite``).

    The generator itself never consults libphonenumber (its metadata changes
    between releases, which would break determinism); this is for tests,
    reports and the seeder. ``phonenumberslite`` is a development
    dependency; install it to use this function.

    Returns:
        ``{possible, valid, type}`` where type is the libphonenumber number
        type name (``MOBILE``, ``FIXED_LINE`` ...).

    Raises:
        ImportError: ``phonenumberslite`` is not installed.
    """
    import phonenumbers

    num = phonenumbers.parse(e164)
    ntype = phonenumbers.number_type(num)
    names = {
        v: k
        for k, v in vars(phonenumbers.PhoneNumberType).items()
        if k.isupper() and isinstance(v, int)
    }
    return {
        "possible": phonenumbers.is_possible_number(num),
        "valid": phonenumbers.is_valid_number(num),
        "type": names.get(ntype, str(ntype)),
    }


class NumberFactory:
    """Generates unique phone numbers from a country pack at a number level.

    Args:
        country: The country pack data.
        level: Requested level (``fiction``, ``unallocated``, ``realistic``).
        warn: Callback for fallback warnings.
        exclude: E.164 numbers never to produce (e.g. the owner's).
    """

    _CHAINS = {
        "fiction": ("fiction", "unallocated", "realistic"),
        "unallocated": ("unallocated", "fiction", "realistic"),
        "realistic": ("realistic", "unallocated", "fiction"),
    }

    def __init__(
        self,
        country: dict[str, Any],
        level: str,
        warn: Callable[[str], None],
        exclude: set[str] | None = None,
    ) -> None:
        phone = country["phone"]
        self.cc = phone["country_code"]
        self.trunk = phone.get("trunk_prefix") or ""
        self.level = level
        self.warn = warn
        self.used: set[str] = set(exclude or ())
        mobile = phone.get("mobile") or {}
        land = phone.get("landline") or {}
        self.pools: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("mobile", "realistic"): list(mobile.get("realistic") or []),
            ("mobile", "unallocated"): list(mobile.get("unallocated") or []),
            ("mobile", "fiction"): list(mobile.get("fiction") or []),
            ("landline", "realistic"): [
                {"prefix": c["area_code"], "sub": c["subscriber_length"], **c}
                for c in land.get("cities") or []
            ],
            ("landline", "fiction"): list(land.get("fiction") or []),
        }
        self._exhausted: set[tuple[str, str]] = set()
        self._warned: set[tuple[str, str, str]] = set()

    def levels(self, kind: str) -> list[str]:
        """Return the usable levels for a kind, in fallback order."""
        return [
            lv
            for lv in self._CHAINS[self.level]
            if self.pools.get((kind, lv)) and (kind, lv) not in self._exhausted
        ]

    def landline_ok(self) -> bool:
        """True when landlines exist at a level no less safe than mobiles'."""
        mob, land = self.levels("mobile"), self.levels("landline")
        if not mob or not land:
            return False
        chain = self._CHAINS[self.level]
        return chain.index(land[0]) <= chain.index(mob[0])

    def _note(self, kind: str, wanted: str, used: str, why: str) -> None:
        key = (kind, wanted, used)
        if key not in self._warned:
            self._warned.add(key)
            self.warn(f"{kind} numbers: {why} at level {wanted!r}; used {used!r}")

    @staticmethod
    def _window(entry: dict[str, Any], want: str) -> tuple[int, int, int] | None:
        """Return the part ``(low, high, width)`` of a range starting ``want``."""
        low, high, width = parse_range(entry["range"]) or (0, -1, 0)
        if want:
            if len(want) >= width:
                value = int(want[:width])
                return (value, value, width) if low <= value <= high else None
            pad = width - len(want)
            low = max(low, int(want + "0" * pad))
            high = min(high, int(want + "9" * pad))
        return (low, high, width) if low <= high else None

    @classmethod
    def fits(cls, entry: dict[str, Any], want: str) -> bool:
        """Return whether an entry can produce a number starting with ``want``."""
        if "range" in entry:
            return cls._window(entry, want) is not None
        prefix = str(entry["prefix"])
        length = (
            len(prefix) + int(entry["sub"]) if "sub" in entry else int(entry["length"])
        )
        if not (want.startswith(prefix) or prefix.startswith(want)):
            return False
        return max(len(want), len(prefix)) < length

    def _draw(
        self, entry: dict[str, Any], stream: SeedStream, want: str = ""
    ) -> str | None:
        if "range" in entry:
            window = self._window(entry, want)
            if window is None:
                return None
            low, high, width = window
            return str(low + stream.below(high - low + 1)).zfill(width)
        prefix = str(entry["prefix"])
        if "sub" in entry:
            length = len(prefix) + int(entry["sub"])
            if want and not (want.startswith(prefix) or prefix.startswith(want)):
                return None
            head = want if len(want) > len(prefix) else prefix
            rest = length - len(head)
            if rest <= 0:
                return None
            first = "" if len(head) > len(prefix) else str(2 + stream.below(8))
            return head + first + stream.digits(rest - len(first))
        length = int(entry["length"])
        if want and not (want.startswith(prefix) or prefix.startswith(want)):
            return None
        head = want if len(want) > len(prefix) else prefix
        if len(head) >= length:
            return None
        return head + stream.digits(length - len(head))

    def make(
        self,
        kind: str,
        stream: SeedStream,
        *,
        city: str | None = None,
        want: str = "",
    ) -> dict[str, Any] | None:
        """Return a new number ``{number, national, type, level}`` or None.

        Args:
            kind: ``"mobile"`` or ``"landline"``.
            stream: Random stream.
            city: Prefer landline area codes of this city.
            want: National digits the number must start with (number-type
                service senders such as ``"+4930..."``).
        """
        chain = self._CHAINS[self.level]
        levels = self.levels(kind)
        if want:  # a prefix never justifies a less safe level
            levels = levels[:1]
        for lv in levels:
            entries = self.pools[(kind, lv)]
            if want:
                entries = [e for e in entries if self.fits(e, want)]
            elif city and kind == "landline" and lv == "realistic":
                local = [e for e in entries if e.get("city") == city]
                entries = local or entries
            if not entries:
                continue
            for _ in range(24):
                nsn = self._draw(stream.choice(entries), stream, want)
                if nsn is None:
                    continue
                e164 = f"+{self.cc}{nsn}"
                if e164 in self.used:
                    continue
                self.used.add(e164)
                if lv != chain[0]:
                    why = (
                        "pool used up"
                        if (kind, chain[0]) in self._exhausted
                        else "no ranges"
                    )
                    self._note(kind, chain[0], lv, why)
                return {
                    "number": e164,
                    "national": self.trunk + nsn,
                    "type": kind,
                    "level": lv,
                }
            if not want:
                self._exhausted.add((kind, lv))
        return None


# --------------------------------------------------------------- generator


class _Generator:
    """One generation run (internal)."""

    def __init__(self, spec: WorldSpec, owner: Owner, packs: PackSet) -> None:
        self.spec = spec
        self.owner = owner
        self.packs = packs
        self.warnings: list[str] = []
        self.used_packs: dict[str, str] = {}
        self.history_s = spec.history_seconds()
        self.counts = spec.resolved_counts()
        self.seed = new_seed() if spec.seed == "auto" else spec.seed
        self.seed_bytes = parse_seed(self.seed)
        self._cums: dict[Any, Cumulative] = {}
        self.country = self._country_pack()
        self.cd = self.country.data
        self.mix = self._mix()
        self.owner_lang = self._pick_language(self.country.id, None)
        self.numbers = NumberFactory(
            self.cd,
            spec.numbers,
            self.warn,
            exclude={owner.phone_e164} if owner.phone_e164 else None,
        )
        self.people: list[_Person] = []
        self.partner: _Person | None = None
        self.used_emails: set[str] = set()
        self.target_sdk: int | None = None
        self.services: list[dict[str, Any]] = []
        self._codes: set[str] = set()
        self.services_by_kind: dict[str, list[dict[str, Any]]] = {}

    # -- infrastructure

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def stream(self, label: str) -> SeedStream:
        return SeedStream(self.seed_bytes, label)

    def use(self, pack: Pack) -> Pack:
        self.used_packs[pack.key] = pack.sha256
        return pack

    def cum(
        self, key: Any, entries: Sequence[dict[str, Any]], wkey: str = "w"
    ) -> Cumulative:
        c = self._cums.get(key)
        if c is None:
            c = self._cums[key] = _cum(entries, wkey)
        return c

    def _country_pack(self) -> Pack:
        cid = self.spec.country
        if not cid:
            digits = self.owner.phone_e164[1:]
            best, best_cc = "", ""
            for pid in self.packs.ids("countries"):
                cc = str(self.packs.country(pid).data["phone"]["country_code"])
                if digits.startswith(cc) and len(cc) > len(best_cc):
                    best, best_cc = pid, cc
            if not best:
                raise WorldError(
                    "world spec names no country and the owner's phone matches none"
                )
            cid = best
        if not self.packs.has("countries", cid):
            raise WorldError(f"no country pack {cid!r}")
        return self.use(self.packs.country(cid))

    def _mix(self) -> dict[str, float]:
        if self.spec.mix:
            raw = dict(self.spec.mix)
            total = sum(raw.values())
            if not 0.99 <= total <= 1.01:
                self.warn(f"mix: shares add up to {total:g}, not 1; normalised")
        else:
            cults = [c for c in self.cd.get("cultures") or [] if c.get("share")]
            raw = {c["culture"]: float(c["share"]) for c in cults}
            raw[self.country.id] = max(0.0, 1.0 - sum(raw.values())) + raw.get(
                self.country.id, 0.0
            )
        mix = {}
        for cid in sorted(raw):
            if raw[cid] <= 0:
                continue
            if not self.packs.has("countries", cid):
                self.warn(f"mix: culture {cid!r} has no country pack; left out")
                continue
            mix[cid] = float(raw[cid])
        if not mix:
            raise WorldError("world mix has no culture with a country pack")
        total = sum(mix.values())
        return {k: v / total for k, v in mix.items()}

    def _pick_language(self, country_id: str, stream: SeedStream | None) -> str:
        langs = self.packs.country(country_id).data.get("languages") or {}
        avail = sorted(
            (lang, float(w))
            for lang, w in langs.items()
            if self.packs.has("languages", lang)
        )
        if not avail:
            fallback = self.owner_lang if hasattr(self, "owner_lang") else None
            if fallback is None:
                fallback = "en" if self.packs.has("languages", "en") else None
            if fallback is None:
                raise WorldError(f"no language pack for country {country_id!r}")
            self.warn(f"country {country_id!r}: no language pack; using {fallback!r}")
            return fallback
        if stream is None:  # the owner: the biggest share
            return max(avail, key=lambda x: (x[1], x[0] == "en", x[0]))[0]
        return stream.weighted([a[0] for a in avail], [a[1] for a in avail])

    def lang(self, lang: str) -> dict[str, Any]:
        return self.use(self.packs.language(lang)).data

    # -- time

    def pick_time(
        self,
        s: SeedStream,
        *,
        bias: float = 1.7,
        weekend: bool = False,
        hours: Cumulative = _HOUR_CUM,
    ) -> int:
        """Return a recency-biased ``t_rel_s`` with a daily rhythm.

        With ``weekend`` the day moves back to the Saturday or Sunday before
        it (the anchor is a Monday, so weekdays survive rendering).
        """
        days = max(1, self.history_s // DAY)
        back = 1 + int((s.random() ** bias) * days)
        if weekend:
            weekday = (NOMINAL_ANCHOR - dt.timedelta(days=back)).weekday()
            back += (weekday - 5) % 7  # the Saturday on or before
            if s.chance(0.5):
                back -= 1  # Sunday
            if back > days:
                back -= 7
            back = max(1, back)
        hour = s.weighted_index(hours)
        sec = hour * 3600 + s.below(3600)
        return back * DAY - sec

    # -- names

    def _draw_name(
        self, s: SeedStream, culture: str, gender: str, group: str | None
    ) -> tuple[str, str]:
        names = self.packs.country(culture).data["names"]
        pool = names["female" if gender == "f" else "male"]
        groups = names.get("groups")
        if groups and group is None:
            keys = sorted(groups)
            group = s.weighted(keys, [groups[k] for k in keys])

        def fits(e: dict[str, Any], tags: set[str] | None) -> bool:
            g = e.get("g")
            return not g or tags is None or bool(tags & set(g))

        tags = {group} if group else None
        firsts = [e for e in pool if fits(e, tags)] if tags else pool
        first_e = firsts[
            s.weighted_index(self.cum(("n", culture, gender, group), firsts))
        ]
        if not groups and first_e.get("g"):
            tags = set(first_e["g"])
        surnames = names["surnames"]
        lasts = [e for e in surnames if fits(e, tags)] if tags else surnames
        last_e = lasts[
            s.weighted_index(self.cum(("s", culture, tuple(sorted(tags or ()))), lasts))
        ]
        last = last_e["name"]
        if s.chance(float(names.get("single_name_share") or 0.0)):
            last = ""
        return first_e["name"], last

    # -- people

    def build_people(self) -> None:
        g = self.stream("graph")
        n_people = self.counts["contacts"]
        roles: list[tuple[str, str]] = []
        if g.chance(0.65):
            roles.append(("partner", "partner"))
        for role, p in (("mom", 0.92), ("dad", 0.85)):
            if g.chance(p):
                roles.append((role, "family"))
        for _ in range(g.weighted([0, 1, 2, 3], [0.2, 0.4, 0.25, 0.15])):
            roles.append((g.choice(["sister", "brother"]), "family"))
        for _ in range(g.weighted([0, 1, 2], [0.4, 0.35, 0.25])):
            roles.append((g.choice(["grandma", "grandpa"]), "family"))
        for _ in range(g.randint(0, 3 if n_people >= 60 else 1)):
            roles.append((g.choice(["aunt", "uncle"]), "family"))
        owner_age = g.randint(23, 48)
        if roles and roles[0][0] == "partner" and owner_age >= 30 and g.chance(0.4):
            for _ in range(g.randint(1, 2)):
                roles.append((g.choice(["son", "daughter"]), "family"))
        roles = roles[:n_people]
        rest = n_people - len(roles)
        others = ["friend", "colleague", "neighbor", "acquaintance"]
        weights = [0.38, 0.3, 0.08, 0.24]
        roles += [(r, r) for r in (g.weighted(others, weights) for _ in range(rest))]

        mix_ids = list(self.mix)
        mix_cum = Cumulative([self.mix[k] for k in mix_ids])
        family_culture = max(mix_ids, key=lambda k: (self.mix[k], k == self.country.id))
        fam_groups = self.packs.country(family_culture).data["names"].get("groups")
        family_group: str | None = None
        if fam_groups:
            keys = sorted(fam_groups)
            family_group = g.weighted(keys, [fam_groups[k] for k in keys])
        cities = self.cd["cities"]
        city_cum = self.cum("cities", cities, "population")
        home = self.home_city
        owner_last = self.owner.last
        for n, (role, relation) in enumerate(roles, start=1):
            s = self.stream(f"people/{n}")
            culture = (
                family_culture
                if relation in ("family",)
                else mix_ids[s.weighted_index(mix_cum)]
            )
            gender = _FAMILY_ROLES[role][0] if role in _FAMILY_ROLES else s.choice("fm")
            first, last = self._draw_name(
                s, culture, gender, family_group if relation == "family" else None
            )
            if (
                role
                in (
                    "mom",
                    "dad",
                    "sister",
                    "brother",
                    "grandpa",
                    "grandma",
                    "son",
                    "daughter",
                )
                and owner_last
            ):
                last = owner_last
            age = self._age(s, role, owner_age)
            birth = dt.date(NOMINAL_ANCHOR.year - age, 1, 1) + dt.timedelta(
                days=s.below(365)
            )
            lo_hi = _RELATIONS[relation]
            close = s.uniform(lo_hi[1], lo_hi[2])
            if role in _FAMILY_ROLES:
                close *= _FAMILY_ROLES[role][1] / 2
            local = relation in ("partner", "neighbor") or s.chance(0.6)
            city = home if local else cities[s.weighted_index(city_cum)]["name"]
            p = _Person(
                n=n,
                role=role,
                relation=relation,
                closeness=round(close, 3),
                culture=culture,
                language=self._pick_language(culture, s),
                gender=gender,
                first=first,
                last=last,
                birth=birth,
                city=city,
            )
            self._numbers(p, s, age)
            self._email(p, s, age)
            self.people.append(p)
            if role == "partner":
                self.partner = p
        for cid in self.mix:
            self.use(self.packs.country(cid))

    @staticmethod
    def _age(s: SeedStream, role: str, owner_age: int) -> int:
        spans = {
            "partner": (-4, 4),
            "mom": (24, 36),
            "dad": (25, 38),
            "sister": (-8, 8),
            "brother": (-8, 8),
            "grandma": (48, 66),
            "grandpa": (50, 68),
            "aunt": (20, 40),
            "uncle": (20, 42),
            "son": (-30, -20),
            "daughter": (-30, -20),
            "friend": (-6, 6),
            "neighbor": (-30, 40),
            "acquaintance": (-15, 25),
        }
        if role == "colleague":
            return s.randint(21, 63)
        lo, hi = spans.get(role, (-10, 10))
        return max(4, min(98, owner_age + s.randint(lo, hi)))

    def _numbers(self, p: _Person, s: SeedStream, age: int) -> None:
        mob = self.numbers.make("mobile", s)
        if mob:
            p.numbers.append(mob)
        second = 0.35 if age >= 60 else 0.12
        if s.chance(second):
            kind = (
                "landline" if self.numbers.landline_ok() and s.chance(0.7) else "mobile"
            )
            extra = self.numbers.make(kind, s, city=p.city)
            if extra:
                p.numbers.append(extra)

    def _email(self, p: _Person, s: SeedStream, age: int) -> None:
        prob = 0.45 if p.relation == "family" or age >= 65 else 0.7
        if not s.chance(prob):
            return
        cdata = self.packs.country(p.culture).data.get("email") or self.cd["email"]
        domains = self.cd["email"]["domains"]
        domain = domains[s.weighted_index(self.cum("domains", domains, "share"))][
            "domain"
        ]
        first, last = _ascii_slug(p.first), _ascii_slug(p.last)
        if len(first) < 2:
            return
        pats = [
            x
            for x in cdata["patterns"]
            if last or ("{last}" not in x and "{l}" not in x)
        ]
        if not pats:
            return
        for _ in range(4):
            pat = s.choice(pats)
            vals = {
                "first": first,
                "last": last,
                "f": first[:1],
                "l": last[:1],
                "yy": f"{p.birth.year % 100:02d}",
                "yyyy": str(p.birth.year),
                "nn": s.digits(2),
            }
            local = _fill_email(pat, vals, s)
            if len(local) < 3:
                continue
            addr = f"{local}@{domain}"
            if (
                addr not in self.used_emails
                and addr.lower() != self.owner.email.lower()
            ):
                self.used_emails.add(addr)
                p.email = addr
                return

    # -- places

    def setup_places(self) -> None:
        s = self.stream("places")
        cities = self.cd["cities"]
        by_name = {c["name"]: c for c in cities}

        def resolve(
            key: str, default_city: dict[str, Any], radius: float
        ) -> tuple[str, float, float]:
            want = self.spec.places.get(key) or {}
            if "lat" in want and "lon" in want:
                return (
                    str(want.get("city") or default_city["name"]),
                    float(want["lat"]),
                    float(want["lon"]),
                )
            city = by_name.get(str(want.get("city"))) if want.get("city") else None
            if want.get("city") and city is None:
                self.warn(
                    f"places.{key}: city {want['city']!r} not in the country pack"
                )
            city = city or default_city
            lat, lon = self.jitter(s, city["lat"], city["lon"], 200, radius)
            return city["name"], lat, lon

        home_default = cities[
            s.weighted_index(self.cum("cities", cities, "population"))
        ]
        self.home_city, self.home_lat, self.home_lon = resolve(
            "home", home_default, 4000
        )
        home_c = by_name.get(self.home_city, home_default)
        work_default = (
            home_c
            if s.chance(0.75)
            else cities[s.weighted_index(self.cum("cities", cities, "population"))]
        )
        self.work_city, self.work_lat, self.work_lon = resolve(
            "work", work_default, 3000
        )
        places = self.cd.get("places") or []
        self.home_places = [p for p in places if p.get("city") == self.home_city]
        if not self.home_places and places:
            self.home_places = sorted(
                places,
                key=lambda p: (p["lat"] - home_c["lat"]) ** 2
                + (p["lon"] - home_c["lon"]) ** 2,
            )[:6]
        self.far_places = [
            p for p in places if p.get("city") != self.home_city
        ] or places

    @staticmethod
    def jitter(
        s: SeedStream, lat: float, lon: float, lo: float, hi: float
    ) -> tuple[float, float]:
        d = s.uniform(lo, hi)
        a = s.uniform(0, 2 * math.pi)
        dlat = d * math.cos(a) / 111320.0
        dlon = d * math.sin(a) / (111320.0 * max(0.2, math.cos(math.radians(lat))))
        return round(lat + dlat, 6), round(lon + dlon, 6)

    # -- text rendering

    def render(
        self,
        template: str,
        s: SeedStream,
        *,
        t_rel: int,
        lang: dict[str, Any],
        person: _Person | None = None,
        service: dict[str, Any] | None = None,
        context: str = "thread",
    ) -> _Text | None:
        """Fill a template; None when a placeholder cannot be resolved.

        Date placeholders become ``{@n}`` slots that keep their offset from
        the anchor (``t_rel`` plus a few days), so the date is rendered for
        the real anchor later. The same placeholder twice gets the same value.
        """
        memo: dict[str, str] = {}
        slots: list[dict[str, Any]] = []
        cur = self.cd["currency"]
        money_fmt = (
            cur.get("sms_format")
            if context == "service" and cur.get("sms_format")
            else cur["format"]
        )
        base_amount = parse_amount_format(cur["format"])[5]
        failed = False
        distinctive = False

        def other_person() -> _Person | None:
            pool = [
                p
                for p in self.people
                if p.relation in ("friend", "colleague", "family", "acquaintance")
            ]
            return s.choice(pool) if pool else None

        def value(name: str) -> str | None:
            nonlocal person
            if name.startswith("digits:"):
                return s.digits(int(name[7:]))
            if name == "owner_first":
                return self.owner.first or None
            if name in ("first", "last"):
                if context == "file":
                    return (
                        self.owner.first if name == "first" else self.owner.last
                    ) or None
                if person is None:
                    if (
                        context == "service"
                        and service
                        and service["kind"]
                        in ("courier", "delivery_food", "ride_hailing")
                    ):
                        f, l_ = self._draw_name(
                            s, self.country.id, s.choice("fm"), None
                        )
                        memo.setdefault("first", f)
                        memo.setdefault("last", l_)
                        return memo[name]
                    person = other_person()
                if person is None:
                    return None
                return person.first if name == "first" else person.last
            if name == "partner_first":
                if self.partner is None or self.partner is person:
                    return None
                return self.partner.first
            if name == "city":
                return (
                    self.home_city
                    if s.chance(0.7)
                    else s.choice(self.cd["cities"])["name"]
                )
            if name in ("state", "district"):
                home = next(
                    (c for c in self.cd["cities"] if c["name"] == self.home_city), {}
                )
                if name == "state":
                    return home.get("state")
                return s.choice(home["districts"]) if home.get("districts") else None
            if name == "place":
                pool = self.home_places or self.cd.get("places") or []
                return s.choice(pool)["name"] if pool else None
            if name == "time":
                t = dt.datetime(2000, 1, 1, s.randint(8, 20), s.choice([0, 15, 30, 45]))
                return format_date(t, self.cd["time_format"])
            if name in _DATE_SLOTS:
                if name == "day":
                    names = lang.get("weekdays")
                    if not isinstance(names, list) or len(names) != 7:
                        return None
                    slot = {"kind": "day", "names": list(names)}
                    ahead = s.randint(1, 6)
                elif name == "date_file":
                    slot = {"kind": "date_file"}
                    ahead = s.randint(0, 10)
                else:
                    slot = {"kind": "date", "pattern": self.cd["date_format"]}
                    if context == "file":
                        slot["fs"] = True
                    ahead = s.randint(0, 10)
                slot["t_rel_s"] = t_rel - ahead * DAY
                slots.append(slot)
                return f"{{@{len(slots) - 1}}}"
            if name in ("amount", "balance", "fee"):
                scale = {
                    "amount": (0.2, 6.0),
                    "balance": (5.0, 60.0),
                    "fee": (0.01, 0.06),
                }[name]
                v = base_amount * math.exp(
                    s.uniform(math.log(scale[0]), math.log(scale[1]))
                )
                return format_amount(v, money_fmt)
            if name == "code":
                alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                return "".join(s.choice(alphabet) for _ in range(6))
            if name == "tracking":
                return (
                    s.choice("ABCDEFGHJKLMNPRSTUVWXYZ")
                    + s.choice("ABCDEFGHJKLMNPRSTUVWXYZ")
                    + s.digits(10)
                )
            kinds = {"shop": "retail", "bank": "bank", "courier": "courier"}
            if name in kinds:
                kind = kinds[name]
                if service and (
                    service["kind"] == kind
                    or (
                        kind == "bank" and service["kind"] in ("mobile_money", "lender")
                    )
                ):
                    return service.get("label") or service["sender"]
                pool = self.services_by_kind.get(kind) or []
                if not pool:
                    return None
                svc = s.choice(pool)
                return svc.get("label") or svc["sender"]
            return None

        def sub(m: re.Match[str]) -> str:
            nonlocal failed, distinctive
            name = m.group(1)
            if name not in memo:
                v = value(name)
                if v is None:
                    failed = True
                    return ""
                memo[name] = v
            if name in _DISTINCTIVE or name.startswith("digits:"):
                distinctive = distinctive or bool(memo[name].strip())
            return memo[name]

        out = re.sub(r"\{([^{}@]*)\}", sub, template)
        if failed:
            return None
        out = re.sub(r"[ \t]{2,}", " ", out).strip()
        return _Text(out, slots, distinctive)

    def region_ok(self, entry: Any, culture: str | None = None) -> bool:
        if not isinstance(entry, dict) or not entry.get("regions"):
            return True
        regions = {str(r).lower().split("-")[0] for r in entry["regions"]}
        return self.country.id in regions or (culture or "") in regions

    # -- contacts

    def build_contacts(self) -> list[dict[str, Any]]:
        s = self.stream("contacts")
        call_names = self.lang(self.owner_lang).get("call_names") or {}
        out = []
        starred_friends = {
            p.n
            for p in sorted(
                (p for p in self.people if p.relation == "friend"),
                key=lambda p: (-p.closeness, p.n),
            )[:3]
        }
        for p in self.people:
            if not p.numbers and not p.email:
                continue
            names = self.packs.country(p.culture).data["names"]
            display = None
            key = "partner" if p.role == "partner" else p.role
            if key in call_names and s.chance(0.85):
                options = call_names[key]
                options = options if isinstance(options, list) else [options]
                display = s.choice(options).replace("{first}", p.first)
            if display is None:
                variants = names.get("display_variants")
                pattern = names.get("display") or "{first} {last}"
                if variants and s.chance(0.3):
                    pattern = s.weighted(
                        [v["pattern"] for v in variants],
                        [v.get("w", 1) for v in variants],
                    )
                first = p.first
                nick = (names.get("nicknames") or {}).get(p.first)
                if nick and p.relation in ("friend", "partner") and s.chance(0.35):
                    first = nick
                if p.relation == "acquaintance" and s.chance(0.25):
                    pattern = "{first}"
                display = pattern.replace("{first}", first).replace("{last}", p.last)
                display = re.sub(r"\s{2,}", " ", display).strip()
            out.append(
                {
                    "id": f"world.contacts.{len(out) + 1}",
                    "person": p.id,
                    "display_name": display,
                    "given_name": p.first,
                    "family_name": p.last,
                    "phones": [
                        {"number": n["number"], "type": n["type"]} for n in p.numbers
                    ],
                    "email": p.email,
                    "starred": p.role in ("partner", "mom", "dad")
                    or p.n in starred_friends,
                    "relation": p.relation,
                }
            )
        return out

    # -- services

    def setup_services(self) -> None:
        s = self.stream("services")
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for svc in self.cd.get("services") or []:
            kind = KIND_ALIASES.get(svc.get("kind"), svc.get("kind"))
            by_kind.setdefault(kind, []).append({**svc, "kind": kind})
        self.services_by_kind = by_kind
        chosen: list[dict[str, Any]] = []
        for kind in sorted(by_kind):
            pool = by_kind[kind]
            k = min(len(pool), _SERVICE_PICKS.get(kind, 1))
            for svc in s.shuffled(pool)[:k]:
                lang = self._pick_language(self.country.id, s)
                templates = self._service_templates(lang, kind)
                if not templates:
                    continue
                if svc["sender_type"] == "number":
                    want = re.sub(r"\D", "", svc["sender"])
                    want = (
                        want[len(self.numbers.cc) :]
                        if want.startswith(self.numbers.cc)
                        else ""
                    )
                    kind_n = (
                        "landline"
                        if svc["kind"] == "doctor" and self.numbers.landline_ok()
                        else "mobile"
                    )
                    num = self.numbers.make(kind_n, s, want=want) or self.numbers.make(
                        "mobile", s
                    )
                    if num is None:
                        continue
                    address = num["number"]
                elif svc["sender_type"] == "shortcode" and not svc["sender"].isdigit():
                    address = self._shortcode(svc["sender"])
                    svc = {**svc, "label": svc.get("label") or svc["sender"]}
                else:
                    address = svc["sender"]
                chosen.append(
                    {**svc, "address": address, "lang": lang, "templates": templates}
                )
        if not chosen:
            self.warn(
                "no service SMS: no service kind has templates in the language packs"
            )
        self.services = chosen

    def _shortcode(self, sender: str) -> str:
        """Return a stable 5-6 digit short code for a sender without one."""
        s = self.stream(f"shortcode/{sender}")
        taken = {
            str(svc.get("sender"))
            for svc in self.cd.get("services") or []
            if str(svc.get("sender", "")).isdigit()
        }
        while True:
            code = s.digits(s.randint(5, 6), first_nonzero=True)
            if code not in taken and code not in self._codes:
                self._codes.add(code)
                return code

    def _service_templates(self, lang: str, kind: str) -> list[Any]:
        sms = self.lang(lang).get("service_sms") or {}
        out: list[Any] = []
        for key, entries in sms.items():
            if KIND_ALIASES.get(key, key) == kind:
                out += [e for e in entries if self.region_ok(e)]
        return out

    # -- sms

    def build_sms(self) -> list[dict[str, Any]]:
        s = self.stream("sms")
        total = self.counts["sms"]
        n_service = round(total * 0.35) if self.services else 0
        items: list[dict[str, Any]] = []
        threads: dict[str, int] = {}
        reachable = [p for p in self.people if p.mobile]
        if reachable:
            pcum = Cumulative([p.closeness for p in reachable])
            guard = 0
            while len(items) < total - n_service and guard < total * 20:
                guard += 1
                p = reachable[s.weighted_index(pcum)]
                lang = self.lang(p.language)
                ttype = _RELATIONS[p.relation][0]
                options = [
                    t
                    for t in lang["threads"].get(ttype) or []
                    if self.region_ok(t, p.culture)
                ]
                if not options:
                    continue
                thread = s.choice(options)
                t_rel = self.pick_time(s)
                rendered = []
                t = t_rel
                for speaker, text in thread["msgs"]:
                    body = self.render(text, s, t_rel=t, lang=lang, person=p)
                    if body is None:
                        rendered = []
                        break
                    rendered.append((speaker, body, t))
                    t = max(1, t - int(min(6 * 3600, s.lognormal(150, 1.2))))
                if not rendered:
                    continue
                tid = threads.setdefault(p.mobile, len(threads) + 1)
                for speaker, body, t in rendered:
                    if len(items) >= total - n_service:
                        break
                    items.append(
                        {
                            "address": p.mobile,
                            **body.fields("body"),
                            "direction": "sent" if speaker == "o" else "inbox",
                            "person": p.id,
                            "service": None,
                            "sender_type": "number",
                            "lang": p.language,
                            "emoji": has_emoji(body.text),
                            "t_rel_s": t,
                            "thread": tid,
                        }
                    )
        if self.services:
            scum = Cumulative(
                [_SERVICE_KIND_W.get(v["kind"], 0.7) for v in self.services]
            )
            guard = 0
            while len(items) < total and guard < total * 20:
                guard += 1
                svc = self.services[s.weighted_index(scum)]
                lang = self.lang(svc["lang"])
                text = entry_text(s.choice(svc["templates"]), "text")
                t_rel = self.pick_time(s, bias=1.4)
                body = self.render(
                    text or "",
                    s,
                    t_rel=t_rel,
                    lang=lang,
                    service=svc,
                    context="service",
                )
                if not body or not body.text:
                    continue
                tid = threads.setdefault(svc["address"], len(threads) + 1)
                items.append(
                    {
                        "address": svc["address"],
                        "label": svc.get("label"),
                        **body.fields("body"),
                        "direction": "inbox",
                        "person": None,
                        "service": svc["kind"],
                        "sender_type": svc["sender_type"],
                        "lang": svc["lang"],
                        "emoji": has_emoji(body.text),
                        "t_rel_s": t_rel,
                        "thread": tid,
                    }
                )
        if len(items) < total:
            self.warn(f"sms: generated {len(items)} of {total}")
        items.sort(key=lambda m: (-m["t_rel_s"], m["thread"]))
        for i, m in enumerate(items, start=1):
            m["id"] = f"world.sms.{i}"
            m["read"] = (
                m["direction"] == "sent" or m["t_rel_s"] > 2 * DAY or s.chance(0.5)
            )
        return [{"id": m.pop("id"), **m} for m in items]

    # -- calls

    def build_calls(self) -> list[dict[str, Any]]:
        s = self.stream("calls")
        reachable = [p for p in self.people if p.numbers]
        out: list[dict[str, Any]] = []
        if not reachable:
            return out
        pcum = Cumulative([p.closeness for p in reachable])
        medians = {"partner": 240, "family": 180, "friend": 120, "colleague": 90}
        for _ in range(self.counts["calls"]):
            if s.chance(0.06):
                num = self.numbers.make("mobile", s)
                if num is None:
                    continue
                person, number, median = None, num["number"], 40
                ctype = s.weighted(["incoming", "missed"], [0.4, 0.6])
            else:
                person = reachable[s.weighted_index(pcum)]
                number = person.numbers[0 if s.chance(0.85) else -1]["number"]
                median = medians.get(person.relation, 60)
                ctype = s.weighted(
                    ["incoming", "outgoing", "missed"], [0.42, 0.43, 0.15]
                )
            dur = (
                0
                if ctype == "missed"
                else max(3, min(3 * 3600, int(s.lognormal(median, 0.9))))
            )
            out.append(
                {
                    "number": number,
                    "person": person.id if person else None,
                    "type": ctype,
                    "duration_s": dur,
                    "t_rel_s": self.pick_time(s, bias=1.5),
                }
            )
        out.sort(key=lambda c: -c["t_rel_s"])
        return [{"id": f"world.calls.{i}", **c} for i, c in enumerate(out, start=1)]

    # -- calendar

    def build_events(self) -> list[dict[str, Any]]:
        s = self.stream("events")
        total = self.counts["events"]
        lang = self.lang(self.owner_lang)
        cal = [e for e in lang.get("calendar") or [] if self.region_ok(e)]
        out: list[dict[str, Any]] = []
        bday_tpl = [
            e for e in cal if isinstance(e, dict) and e.get("kind") == "birthday"
        ]
        close = sorted(
            (
                p
                for p in self.people
                if p.relation in ("partner", "family") or p.closeness >= 2.5
            ),
            key=lambda p: (-p.closeness, p.n),
        )
        for p in close[: round(total * 0.25)]:
            if not bday_tpl:
                break
            title = self.render(
                entry_text(s.choice(bday_tpl), "title") or "",
                s,
                t_rel=0,
                lang=lang,
                person=p,
            )
            if not title:
                continue
            out.append(
                {
                    **title.fields("title"),
                    "kind": "birthday",
                    "all_day": True,
                    "minutes": None,
                    "t_rel_s": None,
                    "location": None,
                    "recurrence": "yearly",
                    "rule": f"{p.birth.month:02d}-{p.birth.day:02d}",
                    "occurrence": 0,
                    "person": p.id,
                }
            )
        # Holidays: a rule plus an occurrence index counted back from 60
        # days after the anchor; the renderer places them for any anchor.
        hol_slots = round(total * 0.2)
        ref = (NOMINAL_ANCHOR + dt.timedelta(days=LOOKAHEAD_DAYS)).date()
        start = (NOMINAL_ANCHOR - dt.timedelta(seconds=self.history_s)).date()
        years = self.history_s // (365 * DAY) + 2
        hols: list[tuple[int, dict[str, Any]]] = []
        skipped = set()
        for h in self.cd.get("holidays") or []:
            if h.get("regional"):
                continue
            days = recent_occurrences(h, ref, years)
            if not days and str(h.get("rule", "")).startswith("lunisolar:"):
                skipped.add(h["rule"])
            hols += [(n, h) for n, d in enumerate(days) if d >= start]
        if skipped:
            self.warn(
                "holidays skipped (calendar not computable): "
                + ", ".join(sorted(skipped))
            )
        hols.sort(key=lambda x: (x[0], x[1]["name"]))
        for n, h in s.shuffled(hols)[:hol_slots]:
            out.append(
                {
                    "title": h["name"],
                    "distinctive": False,
                    "kind": "holiday",
                    "all_day": True,
                    "minutes": None,
                    "t_rel_s": None,
                    "location": None,
                    "recurrence": None,
                    "rule": h.get("rule") or h.get("date"),
                    "occurrence": n,
                    "person": None,
                }
            )
        plain = [
            e for e in cal if not (isinstance(e, dict) and e.get("kind") == "birthday")
        ]
        guard = 0
        while len(out) < total and plain and guard < total * 20:
            guard += 1
            e = s.choice(plain)
            e = e if isinstance(e, dict) else {"title": e}
            kind = e.get("kind", "reminder")
            future = s.chance(0.3)
            t_rel = self.pick_time(
                s, bias=1.3, hours=_WORK_HOURS if kind == "work" else _EVENT_HOURS
            )
            if future:
                t_rel = -int(s.uniform(0.5, 60) * DAY) // 900 * 900
            t_rel -= t_rel % 900
            title = self.render(entry_text(e, "title") or "", s, t_rel=t_rel, lang=lang)
            if not title or not title.text:
                continue
            all_day = bool(e.get("all_day"))
            loc = None
            if kind in ("social", "sport", "travel") and s.chance(0.5):
                pool = (
                    self.far_places
                    if kind == "travel"
                    else (self.home_places or self.far_places)
                )
                loc = s.choice(pool)["name"] if pool else None
            if all_day:
                t_rel = int(math.ceil(t_rel / DAY) * DAY)
            out.append(
                {
                    **title.fields("title"),
                    "kind": kind,
                    "all_day": all_day,
                    "minutes": None if all_day else int(e.get("minutes") or 60),
                    "t_rel_s": t_rel,
                    "location": loc,
                    "recurrence": None,
                    "rule": None,
                    "occurrence": None,
                    "person": None,
                }
            )
        out = out[:total]
        out.sort(key=lambda e: (e["t_rel_s"] is None, -(e["t_rel_s"] or 0), e["title"]))
        return [{"id": f"world.events.{i}", **e} for i, e in enumerate(out, start=1)]

    # -- photos

    def build_photos(self) -> list[dict[str, Any]]:
        s = self.stream("photos")
        total = self.counts["photos"]
        pack = self.packs.photos()
        if pack is None or not total:
            if total:
                self.warn("photos: no photo manifest")
            return []
        self.use(pack)
        pool = [
            p
            for p in pack.data.get("photos") or []
            if not p.get("has_people")
            and (p.get("country_neutral") or p.get("country") == self.country.id)
        ]
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for p in sorted(pool, key=lambda x: x["id"]):
            by_cat.setdefault(p["category"], []).append(p)
        cats = sorted(by_cat)
        if not cats:
            self.warn("photos: no usable photo in the manifest")
            return []
        queues = {c: s.shuffled(by_cat[c]) for c in cats}
        taken = dict.fromkeys(cats, 0)
        ccum = Cumulative([_PHOTO_CATEGORY_W.get(c, 0.05) for c in cats])

        def next_photo(cat: str | None = None) -> dict[str, Any]:
            cat = cat if cat in queues else cats[s.weighted_index(ccum)]
            q = queues[cat]
            photo = q[taken[cat] % len(q)]
            taken[cat] += 1
            return photo

        # Clusters: trips (far places, several days), weekend outings, everyday.
        n_trip = round(total * 0.3)
        n_out = round(total * 0.25)
        plan: list[tuple[str, int, dict[str, Any] | None]] = []
        trips = max(1, min(6, round(total / 25))) if n_trip and self.far_places else 0
        for k in range(trips):
            place = s.choice(
                [p for p in self.far_places if p["category"] in _TRIP_CATEGORIES]
                or self.far_places
            )
            days = min(s.randint(2, 5), max(1, self.history_s // DAY - 1))
            start = self.pick_time(s, bias=1.2)
            start = min(max(start, (days + 1) * DAY), self.history_s)
            share = n_trip // trips + (1 if k < n_trip % trips else 0)
            for _ in range(share):
                t = start - s.below(days * DAY)
                t -= t % DAY
                t += DAY - (s.randint(9, 20) * 3600 + s.below(3600))
                plan.append(("trip", max(60, min(t, self.history_s)), place))
        outs = max(1, n_out // 4) if n_out and self.home_places else 0
        for k in range(outs):
            place = s.choice(
                [p for p in self.home_places if p["category"] in _OUTING_CATEGORIES]
                or self.home_places
            )
            t0 = self.pick_time(s, weekend=True, hours=_DAYTIME_HOURS)
            share = n_out // outs + (1 if k < n_out % outs else 0)
            for _ in range(share):
                plan.append(("outing", max(60, t0 - s.below(3 * 3600)), place))
        while len(plan) < total:
            plan.append(("everyday", self.pick_time(s, bias=1.5), None))
        out = []
        for cluster, t_rel, place in plan[:total]:
            if cluster == "everyday":
                photo = next_photo()
            else:
                outdoor = [
                    c
                    for c in cats
                    if c
                    in (
                        "nature",
                        "landmark_generic",
                        "sky",
                        "food",
                        "street",
                        "sport",
                        "plant",
                    )
                ]
                photo = next_photo(s.choice(outdoor) if outdoor else None)
            lat = lon = None
            label = None
            if photo["category"] != "screenshot_like":
                if place is not None:
                    lat, lon = self.jitter(s, place["lat"], place["lon"], 10, 300)
                    label = place["name"]
                elif photo.get("indoor") or photo["category"] in (
                    "interior",
                    "document_like",
                    "pet",
                ):
                    at_work = photo["category"] == "document_like" and s.chance(0.5)
                    base = (
                        (self.work_lat, self.work_lon)
                        if at_work
                        else (self.home_lat, self.home_lon)
                    )
                    lat, lon = self.jitter(s, base[0], base[1], 2, 40)
                    label = "work" if at_work else "home"
                else:
                    base = (
                        (self.home_lat, self.home_lon)
                        if s.chance(0.6)
                        else (self.work_lat, self.work_lon)
                    )
                    lat, lon = self.jitter(s, base[0], base[1], 50, 2500)
                    label = "near home" if base[0] == self.home_lat else "near work"
            out.append(
                {
                    "source": photo["id"],
                    "sha256": photo["sha256"],
                    "file": photo["file"],
                    "category": photo["category"],
                    "width": photo["width"],
                    "height": photo["height"],
                    "t_rel_s": int(t_rel),
                    "lat": lat,
                    "lon": lon,
                    "place": label,
                    "cluster": cluster,
                    "make": self.device["make"],
                    "model": self.device["model"],
                }
            )
        if any(taken[c] > len(queues[c]) for c in cats):
            self.warn(
                "photos: the manifest has fewer photos than requested; some repeat"
            )
        out.sort(key=lambda p: (-p["t_rel_s"], p["source"]))
        return [{"id": f"world.photos.{i}", **p} for i, p in enumerate(out, start=1)]

    # -- files and notes

    def build_files(self) -> list[dict[str, Any]]:
        s = self.stream("files")
        lang = self.lang(self.owner_lang)
        entries = [e for e in lang.get("files") or [] if self.region_ok(e)]
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        guard = 0
        while len(out) < self.counts["files"] and entries and guard < 200:
            guard += 1
            e = s.choice(entries)
            e = e if isinstance(e, dict) else {"name": e}
            t_rel = self.pick_time(s, bias=1.4)
            rendered = self.render(
                entry_text(e, "name") or "", s, t_rel=t_rel, lang=lang, context="file"
            )
            if not rendered or not rendered.text:
                continue
            name = re.sub(r'[\\/:*?"<>|]', "-", rendered.text)
            if name in seen:
                continue
            seen.add(name)
            kind = e.get("kind", "other")
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            median = {
                "pdf": 180_000,
                "docx": 60_000,
                "xlsx": 40_000,
                "jpg": 1_200_000,
                "png": 400_000,
            }.get(ext, 80_000)
            out.append(
                {
                    **rendered._replace(text=name).fields("name"),
                    "kind": kind,
                    "dir": "Download" if kind in _DOWNLOAD_KINDS else "Documents",
                    "size_bytes": max(2_000, int(s.lognormal(median, 0.7))),
                    "t_rel_s": t_rel,
                }
            )
        out.sort(key=lambda f: (-f["t_rel_s"], f["name"]))
        return [{"id": f"world.files.{i}", **f} for i, f in enumerate(out, start=1)]

    def build_notes(self) -> list[dict[str, Any]]:
        s = self.stream("notes")
        lang = self.lang(self.owner_lang)
        entries = [e for e in lang.get("notes") or [] if self.region_ok(e)]
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        guard = 0
        while len(out) < self.counts["notes"] and entries and guard < 200:
            guard += 1
            t_rel = self.pick_time(s, bias=1.4)
            text = self.render(
                entry_text(s.choice(entries), "text") or "",
                s,
                t_rel=t_rel,
                lang=lang,
                context="note",
            )
            if not text or not text.text or text.text in seen:
                continue
            seen.add(text.text)
            out.append({**text.fields("text"), "t_rel_s": t_rel})
        out.sort(key=lambda n: (-n["t_rel_s"], n["text"]))
        return [{"id": f"world.notes.{i}", **n} for i, n in enumerate(out, start=1)]

    # -- run

    def pick_device(self) -> dict[str, Any]:
        """Return the persona phone.

        The spec's device wins. Otherwise one is drawn (sub-stream
        ``device``) from the country pack's ``devices``, else from
        :data:`FALLBACK_DEVICES`, keeping only phones that support
        ``target_sdk`` when it is given.

        Raises:
            WorldError: No phone supports ``target_sdk``.
        """
        sdk = self.target_sdk
        if self.spec.device:
            dev = normalize_device(self.spec.device)
            if sdk is not None and not device_fits(dev, sdk):
                self.warn(
                    f"device {dev['make']} {dev['model']} does not support "
                    f"target_sdk {sdk}; used as set"
                )
        else:
            s = self.stream("device")
            pool = [
                d for d in self.cd.get("devices") or [] if device_problem(d) is None
            ] or list(FALLBACK_DEVICES)
            if sdk is not None:
                pool = [d for d in pool if device_fits(d, sdk)]
                if not pool:
                    raise WorldError(f"no phone model supports target_sdk {sdk}")
            dev = normalize_device(
                pool[s.weighted_index(Cumulative([d.get("w", 1.0) for d in pool]))]
            )
        if dev["make"] != "Google":
            self.warn(
                f"device {dev['make']} {dev['model']} is used for photos only; "
                "apps will see a Google Pixel (the emulator bypass only "
                "spoofs Pixel fingerprints)."
            )
        return dev

    def run(self) -> WorldManifest:
        self.device = self.pick_device()
        self.setup_places()
        self.build_people()
        self.setup_services()
        contacts = self.build_contacts()
        sms = self.build_sms()
        calls = self.build_calls()
        events = self.build_events()
        photos = self.build_photos()
        files = self.build_files()
        notes = self.build_notes()
        spec = self.spec.to_dict()
        spec["seed"] = self.seed
        spec["device"] = self.spec.device
        spec["country"] = self.country.id
        spec["mix"] = {k: round(v, 6) for k, v in self.mix.items()}
        manifest = WorldManifest(
            spec=spec,
            seed=self.seed,
            generator_version=GENERATOR_VERSION,
            time_base={
                "t_rel_s": "seconds before the anchor (negative: after it)",
                "anchor": "local midnight starting a Monday",
                "date_slots": "{@n} in a text: a date rendered for the anchor",
                "rule": "holidays and birthdays: date rule plus occurrence index",
            },
            packs=dict(sorted(self.used_packs.items())),
            owner=self.owner.to_dict(),
            calendar_name="Personal",
            device=dict(self.device),
            target_sdk=self.target_sdk,
            people=[self._person_dict(p) for p in self.people],
            contacts=contacts,
            sms=sms,
            calls=calls,
            events=events,
            photos=photos,
            files=files,
            notes=notes,
            warnings=list(self.warnings),
        )
        manifest.world_fp = manifest.compute_fp()
        return manifest

    @staticmethod
    def _person_dict(p: _Person) -> dict[str, Any]:
        return {
            "id": p.id,
            "role": p.role,
            "relation": p.relation,
            "closeness": p.closeness,
            "culture": p.culture,
            "language": p.language,
            "gender": p.gender,
            "first": p.first,
            "last": p.last,
            "birthday": f"{p.birth.month:02d}-{p.birth.day:02d}",
            "age": NOMINAL_ANCHOR.year - p.birth.year,
            "city": p.city,
            "numbers": p.numbers,
            "email": p.email,
        }


_WORK_HOURS = Cumulative([0] * 8 + [3, 3, 3, 2, 1, 2, 3, 3, 2, 1] + [0] * 6)
_EVENT_HOURS = Cumulative(
    [0] * 7 + [1, 2, 2, 2, 2, 1, 1, 2, 2, 2, 2, 3, 3, 2, 1] + [0] * 2
)
_DAYTIME_HOURS = Cumulative([0] * 9 + [1, 2, 2, 2, 2, 2, 2, 2, 1, 1] + [0] * 5)
