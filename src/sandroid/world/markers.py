"""Scanner markers for a generated world, built from a rendered world.

Each marker is a plain dict::

    {id, value, kind, label, origin, population, dataset, record, field, refs}

``kind`` is one of :data:`MARKER_KINDS`. A value used by several records (a
phone number in a contact, an SMS thread and the call log) is emitted once;
``refs`` lists every ``{record, field}`` that uses it and ``dataset`` /
``record`` / ``field`` name the first one.

Texts (SMS bodies, calendar titles, file names, notes) become markers only
when they are at least :data:`MIN_TEXT_LEN` characters long and the generator
filled a distinctive value into them (a name, a number, a code, an amount):
"Christi Himmelfahrt" or "Lohnsteuerbescheinigung.pdf" exist on countless
phones and would only produce false hits. Holiday events never become
markers. The scanner rules belong to the privacy scanner; this module only
provides the data.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.core.privacy_markers import Marker
    from sandroid.world.manifest import RenderedWorld

MARKER_KINDS = (
    "phone",
    "email",
    "name",
    "sms_body",
    "calendar_title",
    "geo",
    "file_name",
    "note",
)
_LABELS = {
    "phone": "World phone number",
    "email": "World e-mail",
    "name": "World name",
    "sms_body": "World SMS text",
    "calendar_title": "World calendar title",
    "geo": "World photo location",
    "file_name": "World file name",
    "note": "World note",
}
#: Shortest text emitted (shorter ones match by chance).
MIN_TEXT_LEN = 16
#: Fewest decimals a coordinate needs to be distinctive.
MIN_GEO_DECIMALS = 4


def _decimals(value: float) -> int:
    text = repr(float(value))
    return len(text.split(".", 1)[1]) if "." in text and "e" not in text else 0


def build_markers(world: RenderedWorld) -> list[dict[str, Any]]:
    """Return the markers of a rendered world.

    Args:
        world: :meth:`WorldManifest.render` output.

    Returns:
        Marker dicts in first-use order (contacts, sms, calls, events, photos,
        files, notes).
    """
    found: dict[tuple[str, str], dict[str, Any]] = {}
    seen_refs: set[tuple[str, str, str, str]] = set()

    def add(kind: str, value: str, dataset: str, record: str, fld: str) -> None:
        value = value.strip()
        if not value:
            return
        key = (kind, value)
        marker = found.get(key)
        if marker is None:
            digest = hashlib.sha256(f"{kind}\x00{value}".encode()).hexdigest()[:16]
            marker = found[key] = {
                "id": f"world.{kind}.{digest}",
                "value": value,
                "kind": kind,
                "label": _LABELS[kind],
                "origin": "world",
                "population": f"world.{dataset}",
                "dataset": dataset,
                "record": record,
                "field": fld,
                "refs": [],
            }
        if (kind, value, record, fld) not in seen_refs:
            seen_refs.add((kind, value, record, fld))
            marker["refs"].append({"record": record, "field": fld})

    def text(kind: str, item: dict[str, Any], dataset: str, fld: str) -> None:
        value = item.get(fld) or ""
        if item.get("distinctive") and len(value) >= MIN_TEXT_LEN:
            add(kind, value, dataset, item["id"], fld)

    for c in world.contacts:
        for i, phone in enumerate(c.get("phones") or []):
            add("phone", phone["number"], "contacts", c["id"], f"phones[{i}].number")
        if c.get("email"):
            add("email", c["email"], "contacts", c["id"], "email")
        full = " ".join(x for x in (c.get("given_name"), c.get("family_name")) if x)
        if len(full.split()) >= 2:
            add("name", full, "contacts", c["id"], "name")
        if len(str(c.get("display_name", "")).split()) >= 2:
            add("name", c["display_name"], "contacts", c["id"], "display_name")
    for m in world.sms:
        if str(m.get("address", "")).startswith("+"):
            add("phone", m["address"], "sms", m["id"], "address")
        text("sms_body", m, "sms", "body")
    for call in world.calls:
        if str(call.get("number", "")).startswith("+"):
            add("phone", call["number"], "calls", call["id"], "number")
    for ev in world.events:
        if ev.get("kind") != "holiday":
            text("calendar_title", ev, "events", "title")
    for ph in world.photos:
        lat, lon = ph.get("lat"), ph.get("lon")
        if lat is None or lon is None:
            continue
        if min(_decimals(lat), _decimals(lon)) >= MIN_GEO_DECIMALS:
            add("geo", f"{lat},{lon}", "photos", ph["id"], "lat,lon")
    for f in world.files:
        text("file_name", f, "files", "name")
    for n in world.notes:
        text("note", n, "notes", "text")
    return list(found.values())


def to_markers(markers: list[dict[str, Any]]) -> list[Marker]:
    """Build ``sandroid.core.privacy_markers.Marker`` objects.

    Only fields that ``Marker`` has today are set; the rest stays in the
    dicts. A ``geo`` marker becomes a latitude and a longitude marker sharing
    a ``group``. Free-text kinds map to ``"text"``; ``refs`` becomes a tuple
    of record ids.

    Args:
        markers: Output of :func:`build_markers`.

    Returns:
        The markers.
    """
    from sandroid.core.privacy_markers import Marker

    names = {f.name for f in dataclasses.fields(Marker)}
    out: list[Marker] = []
    for m in markers:
        base = {
            "label": m["label"],
            "origin": m.get("origin"),
            "population": m.get("population"),
            "dataset": m.get("dataset"),
            "record": m.get("record"),
            "field": m.get("field"),
            "refs": tuple(r["record"] for r in m.get("refs", [])),
        }
        if m["kind"] == "geo":
            lat, lon = m["value"].split(",", 1)
            parts = [
                (f"{m['id']}.lat", lat, "latitude"),
                (f"{m['id']}.lon", lon, "longitude"),
            ]
            extra = {"group": m["id"]}
        else:
            kind = m["kind"] if m["kind"] in ("phone", "email") else "text"
            parts = [(m["id"], m["value"], kind)]
            extra = {}
        for mid, value, kind in parts:
            kwargs = {"id": mid, "value": value, "kind": kind, **base, **extra}
            out.append(Marker(**{k: v for k, v in kwargs.items() if k in names}))
    return out
