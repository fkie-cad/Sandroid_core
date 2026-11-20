"""Find identity-profile marker values in captured bytes (flows, files, logs).

An identity profile seeds distinctive canary values on the device (advertising
ID, Android ID, e-mail, phone number, GPS fix, ...). Apps rarely send such a
value verbatim: they URL-encode it, wrap it in base64, hash it (Facebook and
most attribution SDKs send ``sha256(lower(email))``), drop the dashes of a
UUID or round a coordinate. This module turns each marker into the set of
byte patterns ("needles") those transformations produce and finds them in a
haystack.

It is deterministic and keeps no state besides the immutable needle set and
its Aho-Corasick automata (``ahocorasick_rs``, built once on the first scan),
so one :class:`NeedleSet` can be shared by any number of threads.

Example::

    needles = build_needles([Marker("ad_id", ad_id, kind="uuid", label="Ad ID")])
    for hit in needles.scan(flow_body):
        print(hit.label, hit.transform, hit.offset)
"""

from __future__ import annotations

import base64
import hashlib
import struct
import threading
import urllib.parse
import uuid
from dataclasses import dataclass, replace
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import TYPE_CHECKING

import ahocorasick_rs

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

#: Marker kinds that shape which plain forms are generated.
KINDS = (
    "text",  # free text (names, device name): the value as is
    "hex_id",  # hex identifiers such as the Android ID
    "uuid",  # advertising ID, App Set ID: also without dashes
    "email",
    "phone",  # E.164 ("+4930..."): also digits-only and 00-prefixed
    "mac",  # with ":", "-" or no separators
    "latitude",  # decimal degrees: rounded/truncated to 3-6 places, E7
    "longitude",
)

#: Confidence levels, strongest first.
CONFIDENCES = ("high", "medium", "low")

#: Needles shorter than this are dropped: they match by chance.
MIN_NEEDLE_LEN = 6

#: A single needle reports at most this many hits per haystack.
MAX_HITS_PER_NEEDLE = 50

#: Hits of a marker group (e.g. latitude and longitude) raise each other's
#: confidence only when they lie at most this many bytes apart.
GROUP_PROXIMITY = 128

_HASHES = ("md5", "sha1", "sha256")
_COORDINATE_KINDS = ("latitude", "longitude")


@dataclass(frozen=True)
class Marker:
    """One value to look for.

    Attributes:
        id: Stable identifier from the profile, e.g. ``"advertising_id"``.
        value: The seeded value as the device reports it.
        kind: One of :data:`KINDS`; decides the plain forms that are generated.
        label: Human label, e.g. ``"Advertising ID"`` (defaults to ``id``).
        forms: Extra plain forms the caller knows about, e.g. a national
            phone number format.
        group: Markers sharing a group (e.g. ``"gps"`` for latitude and
            longitude) raise each other's confidence when all of them are
            found close together (:data:`GROUP_PROXIMITY` bytes).
        tag: Short display tag for row markers, e.g. ``"AdID"`` (defaults to
            ``label``).
    """

    id: str
    value: str
    kind: str = "text"
    label: str = ""
    forms: tuple[str, ...] = ()
    group: str = ""
    tag: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown marker kind {self.kind!r}")
        if not self.label:
            object.__setattr__(self, "label", self.id)
        if not self.tag:
            object.__setattr__(self, "tag", self.label)


@dataclass(frozen=True)
class Needle:
    """A byte pattern derived from a marker.

    Attributes:
        pattern: Bytes to search for; lower-cased when ``folded``.
        folded: Match case-insensitively (ASCII) against the lower-cased
            haystack. Base64 needles are case-sensitive.
        marker: The marker this needle belongs to.
        transform: How the pattern was derived, e.g. ``"sha256(lower(value))"``.
        confidence: ``"high"``, ``"medium"`` or ``"low"``.
    """

    pattern: bytes
    folded: bool
    marker: Marker
    transform: str
    confidence: str


@dataclass(frozen=True)
class MarkerHit:
    """One occurrence of a marker in a haystack.

    Attributes:
        marker_id: :attr:`Marker.id`.
        kind: :attr:`Marker.kind`.
        label: :attr:`Marker.label`.
        tag: :attr:`Marker.tag`.
        transform: How the value was encoded where it was found.
        confidence: ``"high"``, ``"medium"`` or ``"low"``.
        offset: Byte offset of the match in the haystack.
        length: Length of the match in bytes.
    """

    marker_id: str
    kind: str
    label: str
    tag: str
    transform: str
    confidence: str
    offset: int
    length: int

    @property
    def end(self) -> int:
        """Offset just past the match."""
        return self.offset + self.length


class NeedleSet:
    """Immutable set of needles; :meth:`scan` finds them in a haystack."""

    def __init__(self, needles: Sequence[Needle]) -> None:
        self._folded = tuple(n for n in needles if n.folded)
        self._exact = tuple(n for n in needles if not n.folded)
        self.markers: tuple[Marker, ...] = tuple(
            dict.fromkeys(n.marker for n in needles)
        )
        self._automata: _Automata | None = None
        self._build_lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._folded) + len(self._exact)

    @property
    def max_needle_len(self) -> int:
        """Longest pattern; chunked callers overlap chunks by this minus one."""
        return max((len(n.pattern) for n in self.needles), default=0)

    @property
    def needles(self) -> tuple[Needle, ...]:
        """All needles, case-insensitive ones first."""
        return self._folded + self._exact

    def scan(self, data: bytes | str) -> list[MarkerHit]:
        """Find every marker occurrence in ``data``.

        Every occurrence of every needle is found, overlapping ones and
        needles inside other needles included, at most
        :data:`MAX_HITS_PER_NEEDLE` (the first ones) per needle. Weaker
        matches of a marker that lie inside a stronger match of the same
        marker (e.g. the 3-decimal form of a coordinate inside its 6-decimal
        form) are dropped, so each place is reported once.

        Args:
            data: The haystack. ``str`` is encoded as UTF-8.

        Returns:
            Hits sorted by offset.
        """
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogatepass")
        if not data:
            return []
        hits = self._compiled().hits(data)
        if not hits:
            return []
        hits = _drop_contained(hits)
        hits = _boost_groups(hits, self.markers)
        hits.sort(key=lambda h: (h.offset, -h.length))
        return hits

    def _compiled(self) -> _Automata:
        """The automata, built on first use (a worker thread, not the UI)."""
        automata = self._automata
        if automata is None:
            with self._build_lock:
                automata = self._automata
                if automata is None:
                    automata = self._automata = _Automata(self.needles)
        return automata


def build_needles(markers: Iterable[Marker]) -> NeedleSet:
    """Derive the needles for ``markers``.

    Args:
        markers: The markers to look for. Markers with an empty value are
            skipped.

    Returns:
        The needle set; duplicate patterns are generated once.
    """
    seen: set[tuple[bytes, bool, str]] = set()
    needles: list[Needle] = []
    for marker in markers:
        if not marker.value.strip():
            continue
        for needle in _needles_for(marker):
            if len(needle.pattern) < MIN_NEEDLE_LEN:
                continue
            key = (needle.pattern, needle.folded, marker.id)
            if key in seen:
                continue
            seen.add(key)
            needles.append(needle)
    return NeedleSet(needles)


def snippet(data: bytes | str, hit: MarkerHit, width: int = 32) -> tuple[str, str, str]:
    """Return printable ``(before, match, after)`` text around a hit.

    Non-printable bytes are shown as spaces so binary files stay readable.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    start = max(0, hit.offset - width)
    end = min(len(data), hit.end + width)
    return (
        _printable(data[start : hit.offset]),
        _printable(data[hit.offset : hit.end]),
        _printable(data[hit.end : end]),
    )


# --------------------------------------------------------------- generation


def _needles_for(marker: Marker) -> list[Needle]:
    if marker.kind in _COORDINATE_KINDS:
        return _coordinate_needles(marker)
    needles: list[Needle] = []
    for form, name in _plain_forms(marker):
        needles.extend(_encoded_needles(marker, form, name))
    if marker.kind == "uuid":
        needles.extend(_uuid_binary_needles(marker))
    return needles


def _uuid_binary_needles(marker: Marker) -> list[Needle]:
    """The 16 raw bytes of a UUID (protobuf ``bytes`` fields, binary files)."""
    try:
        raw = uuid.UUID(marker.value.strip()).bytes
    except ValueError:
        return []
    needles = [Needle(raw, False, marker, "bytes(value)", "high")]
    needles += _base64_needles(marker, raw, "bytes(value)", "high")
    return needles


def _plain_forms(marker: Marker) -> list[tuple[str, str]]:
    """The plain spellings of a marker value, with a transform name each."""
    value = marker.value.strip()
    forms: list[tuple[str, str]] = [(value, "value")]
    if marker.kind == "uuid":
        forms.append((value.replace("-", ""), "strip_dashes(value)"))
    elif marker.kind == "mac":
        bare = value.replace(":", "").replace("-", "")
        forms += [
            (bare, "strip_separators(value)"),
            (value.replace(":", "-"), "dashes(value)"),
            (value.replace("-", ":"), "colons(value)"),
        ]
    elif marker.kind == "phone":
        digits = "".join(ch for ch in value if ch.isdigit())
        forms.append((digits, "digits(value)"))
        if value.startswith("+"):
            forms.append(("00" + digits, "intl_00(value)"))
    forms += [(extra.strip(), "value") for extra in marker.forms if extra.strip()]
    unique: dict[str, str] = {}
    for text, name in forms:
        unique.setdefault(text, name)
    return list(unique.items())


def _encoded_needles(marker: Marker, form: str, name: str) -> list[Needle]:
    """Plain, URL, UTF-16, hex, base64 and hashed needles for one plain form."""
    confidence = "high" if len(form) >= 8 else "medium"
    raw = form.encode("utf-8")
    out = [
        Needle(raw.lower(), True, marker, name, confidence),
        Needle(
            form.encode("utf-16-le").lower(),
            True,
            marker,
            f"utf16({name})",
            confidence,
        ),
        Needle(raw.hex().encode(), True, marker, f"hex({name})", confidence),
    ]
    for quoted in {urllib.parse.quote(form, safe=""), urllib.parse.quote_plus(form)}:
        if quoted != form:
            out.append(
                Needle(
                    quoted.encode().lower(), True, marker, f"url({name})", confidence
                )
            )
    out += _base64_needles(marker, raw, name, confidence)

    # The plainest label wins when cases coincide (a value without letters):
    # a later case never replaces an earlier one's label.
    cases: dict[str, str] = {}
    for text, case_name in (
        (form, name),
        (form.lower(), f"lower({name})"),
        (form.upper(), f"upper({name})"),
    ):
        cases.setdefault(text, case_name)
    for text, case_name in cases.items():
        data = text.encode("utf-8")
        for algo in _HASHES:
            digest = hashlib.new(algo, data).digest()
            label = f"{algo}({case_name})"
            out.append(Needle(digest.hex().encode(), True, marker, label, "high"))
            for b64 in _digest_base64(digest):
                out.append(Needle(b64, False, marker, f"base64({label})", "high"))
    return out


def _base64_needles(
    marker: Marker, raw: bytes, name: str, confidence: str
) -> list[Needle]:
    """Needles for ``raw`` embedded anywhere in a base64 (or base64url) text.

    Base64 encodes 3 bytes as 4 characters, so the characters a value produces
    depend on where it starts inside a 3-byte group. For each of the three
    alignments only the characters that do not depend on the unknown
    neighbouring bytes are kept.
    """
    out: list[Needle] = []
    for fragment in _base64_fragments(raw):
        if len(fragment) < MIN_NEEDLE_LEN:
            continue
        # A short fragment matches by chance more often: lower, never raise.
        conf = confidence if len(fragment) >= 12 else _weaker(confidence, "medium")
        out.append(Needle(fragment, False, marker, f"base64({name})", conf))
        url_safe = fragment.translate(bytes.maketrans(b"+/", b"-_"))
        if url_safe != fragment:
            out.append(Needle(url_safe, False, marker, f"base64url({name})", conf))
    return out


def _weaker(a: str, b: str) -> str:
    """The weaker of two confidences."""
    return a if CONFIDENCES.index(a) >= CONFIDENCES.index(b) else b


def _base64_fragments(raw: bytes) -> list[bytes]:
    fragments = []
    for pad in range(3):
        total = pad + len(raw)
        encoded = base64.b64encode(b"\0" * pad + raw + b"\0\0")
        first = -(-8 * pad // 6)  # first char not touching the prefix bytes
        last = (8 * total - 6) // 6  # last char not touching following bytes
        if last >= first:
            fragments.append(encoded[first : last + 1])
    return fragments


def _digest_base64(digest: bytes) -> list[bytes]:
    std = base64.b64encode(digest).rstrip(b"=")
    url_safe = base64.urlsafe_b64encode(digest).rstrip(b"=")
    return [std] if std == url_safe else [std, url_safe]


def _coordinate_needles(marker: Marker) -> list[Needle]:
    """Rounded and truncated spellings of a decimal-degree coordinate.

    Only plain and base64 forms: coordinates are sent as numbers (JSON, query
    strings, protobuf-as-text), not hashed. Fewer decimals match more random
    numbers, so 4 places is ``medium`` and 3 places ``low`` confidence.
    """
    try:
        number = Decimal(marker.value.strip())
    except InvalidOperation:
        return []
    texts: dict[str, tuple[str, str]] = {}

    def add(text: str, transform: str, confidence: str) -> None:
        if text not in texts:
            texts[text] = (transform, confidence)

    def confidence_of(places: int) -> str:
        return "high" if places >= 5 else ("medium" if places == 4 else "low")

    for places in (6, 5, 4, 3):
        quantum = Decimal(1).scaleb(-places)
        for mode, verb in ((ROUND_HALF_UP, "round"), (ROUND_DOWN, "truncate")):
            text = format(number.quantize(quantum, rounding=mode), "f")
            add(text, f"{verb}(value, {places})", confidence_of(places))
            stripped = text.rstrip("0").rstrip(".")
            # Named and weighed by the decimals it really has: "52.5145" from
            # round(52.514499, 5) = 52.51450 is a 4-place spelling.
            shown = len(stripped.split(".")[1]) if "." in stripped else 0
            if shown >= 3:
                add(stripped, f"{verb}(value, {shown})", confidence_of(shown))
    e7 = str(int(number.scaleb(7).to_integral_value(rounding=ROUND_HALF_UP)))
    add(e7, "e7(value)", "medium")

    needles = []
    for text, (transform, confidence) in texts.items():
        raw = text.encode("ascii")
        needles.append(Needle(raw, True, marker, transform, confidence))
        needles += _base64_needles(marker, raw, transform, confidence)
    # Binary IEEE-754 doubles (protobuf/FlatBuffers). Only the exact seeded
    # value can match, so these are strong evidence. (A 4-byte float is
    # shorter than MIN_NEEDLE_LEN, so it is not generated.)
    exact = float(number)
    for fmt, name in (("<d", "double_le"), (">d", "double_be")):
        raw = struct.pack(fmt, exact)
        needles.append(Needle(raw, False, marker, f"{name}(value)", "high"))
    return needles


# ----------------------------------------------------------------- scanning


class _Automata:
    """One Aho-Corasick automaton per case mode over the unique patterns.

    Read-only after construction, so concurrent scans share it safely
    (``ahocorasick_rs`` releases the GIL while it searches).
    """

    def __init__(self, needles: Sequence[Needle]) -> None:
        self._needles = tuple(needles)
        # (folded, automaton, pattern index -> needle indices), folded first:
        # hits come out in needle order like the reference loop's.
        self._passes: list[
            tuple[bool, ahocorasick_rs.BytesAhoCorasick, list[tuple[int, ...]]]
        ] = []
        for folded in (True, False):
            owners: dict[bytes, list[int]] = {}
            for index, needle in enumerate(self._needles):
                if needle.folded is folded:
                    owners.setdefault(needle.pattern, []).append(index)
            if owners:
                # Standard match kind: the only one reporting overlapping
                # matches. Never force the DFA implementation (>1 GB at 70k
                # patterns); the default picks a compact NFA.
                automaton = ahocorasick_rs.BytesAhoCorasick(
                    list(owners), matchkind=ahocorasick_rs.MatchKind.Standard
                )
                self._passes.append(
                    (folded, automaton, [tuple(v) for v in owners.values()])
                )

    def hits(self, data: bytes) -> list[MarkerHit]:
        """Raw hits in needle order, then offset order; capped per needle."""
        # pattern index per pass -> offsets: a pattern's matches arrive in
        # offset order (same length, reported by end), so its first
        # MAX_HITS_PER_NEEDLE are the ones the reference loop finds.
        found: list[tuple[int, list[int]]] = []
        for folded, automaton, owners in self._passes:
            haystack = data.lower() if folded else data
            offsets: dict[int, list[int]] = {}
            for pattern, start, _end in automaton.find_matches_as_indexes(
                haystack, overlapping=True
            ):
                starts = offsets.get(pattern)
                if starts is None:
                    offsets[pattern] = [start]
                elif len(starts) < MAX_HITS_PER_NEEDLE:
                    starts.append(start)
            for pattern, starts in offsets.items():
                found += [(index, starts) for index in owners[pattern]]
        found.sort(key=lambda item: item[0])
        hits: list[MarkerHit] = []
        for index, starts in found:
            needle = self._needles[index]
            marker = needle.marker
            length = len(needle.pattern)
            hits += [
                MarkerHit(
                    marker_id=marker.id,
                    kind=marker.kind,
                    label=marker.label,
                    tag=marker.tag,
                    transform=needle.transform,
                    confidence=needle.confidence,
                    offset=start,
                    length=length,
                )
                for start in starts
            ]
        return hits


def _reference_scan(needles: NeedleSet, data: bytes | str) -> list[MarkerHit]:
    """:meth:`NeedleSet.scan` with one ``bytes.find`` loop per needle.

    The matcher before the automata, kept only so tests can check the two
    agree hit for hit. Slow: linear in the number of needles.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    if not data:
        return []
    hits: list[MarkerHit] = []
    folded = [n for n in needles.needles if n.folded]
    exact = [n for n in needles.needles if not n.folded]
    if folded:
        _find_all(data.lower(), folded, hits)
    if exact:
        _find_all(data, exact, hits)
    hits = _drop_contained(hits)
    hits = _boost_groups(hits, needles.markers)
    hits.sort(key=lambda h: (h.offset, -h.length))
    return hits


def _find_all(
    haystack: bytes, needles: Sequence[Needle], hits: list[MarkerHit]
) -> None:
    for needle in needles:
        start = 0
        for _ in range(MAX_HITS_PER_NEEDLE):
            index = haystack.find(needle.pattern, start)
            if index < 0:
                break
            marker = needle.marker
            hits.append(
                MarkerHit(
                    marker_id=marker.id,
                    kind=marker.kind,
                    label=marker.label,
                    tag=marker.tag,
                    transform=needle.transform,
                    confidence=needle.confidence,
                    offset=index,
                    length=len(needle.pattern),
                )
            )
            start = index + 1


def _drop_contained(hits: list[MarkerHit]) -> list[MarkerHit]:
    """Drop hits lying inside a longer hit of the same marker."""
    by_marker: dict[str, list[MarkerHit]] = {}
    for hit in hits:
        by_marker.setdefault(hit.marker_id, []).append(hit)
    kept: list[MarkerHit] = []
    for group in by_marker.values():
        group.sort(key=lambda h: (-h.length, CONFIDENCES.index(h.confidence)))
        chosen: list[MarkerHit] = []
        for hit in group:
            if any(c.offset <= hit.offset and hit.end <= c.end for c in chosen):
                continue
            chosen.append(hit)
        kept += chosen
    return kept


def _near(a: MarkerHit, b: MarkerHit) -> bool:
    """The two hits lie at most :data:`GROUP_PROXIMITY` bytes apart."""
    return max(a.offset, b.offset) - min(a.end, b.end) <= GROUP_PROXIMITY


def _boost_groups(hits: list[MarkerHit], markers: Sequence[Marker]) -> list[MarkerHit]:
    """Raise a hit's confidence when every other marker of its group is found
    close to it (``lat=52.520&lon=13.405``), not just anywhere in the
    haystack (a price and a weight far apart are no GPS fix).
    """
    groups = {m.id: m.group for m in markers if m.group}
    if not groups:
        return hits
    members: dict[str, set[str]] = {}
    for marker_id, group in groups.items():
        members.setdefault(group, set()).add(marker_id)
    by_marker: dict[str, list[MarkerHit]] = {}
    for hit in hits:
        if hit.marker_id in groups:
            by_marker.setdefault(hit.marker_id, []).append(hit)
    if len(by_marker) < 2:
        return hits
    out = []
    for hit in hits:
        group = groups.get(hit.marker_id)
        others = members.get(group, set()) - {hit.marker_id} if group else set()
        if others and all(
            any(_near(hit, o) for o in by_marker.get(other, ())) for other in others
        ):
            hit = replace(hit, confidence="high")
        out.append(hit)
    return out


def _printable(chunk: bytes) -> str:
    text = chunk.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() else " " for ch in text)
