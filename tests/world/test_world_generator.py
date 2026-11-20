"""World generator: determinism, numbers, mix, privacy, placeholders, markers."""

from __future__ import annotations

import collections
import dataclasses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sandroid.world import (
    GENERATOR_VERSION,
    NumberFactory,
    PackSet,
    SeedStream,
    WorldManifest,
    WorldSpec,
    generate,
    phone_check,
)
from sandroid.world.generator import FALLBACK_DEVICES, WorldError, has_emoji
from sandroid.world.packs import parse_range

PACKS = PackSet(user_dir=False)
SEED = "hex:" + "5a" * 16
OWNER = {
    "first": "Mara",
    "last": "Keller",
    "phone": "+4915112345678",
    "email": "mara.keller@example.org",
}
MIX = {"de": 0.80, "tr": 0.12, "gb": 0.08}
TEXT_FIELDS = (
    ("sms", "body"),
    ("events", "title"),
    ("files", "name"),
    ("notes", "text"),
)
#: world_fp of the reference world below. A change here means the generator's
#: output changed: bump GENERATOR_VERSION and update the value.
GOLDEN_FP = "d8a2f4978f9f31e5bc14495bbad651dcfff3c72546ae4a6a2c50adb6004e42b9"


def _world(**spec: object) -> WorldManifest:
    base = {"seed": SEED, "size": "medium", "country": "de", "mix": MIX}
    base.update(spec)
    return generate(base, OWNER, packs=PACKS)


@pytest.fixture(scope="module")
def medium() -> WorldManifest:
    return _world()


# ------------------------------------------------------------ determinism


def test_same_inputs_give_identical_manifest(medium: WorldManifest) -> None:
    again = _world()
    assert again.to_json() == medium.to_json()
    assert again.world_fp == medium.world_fp


def test_different_seed_gives_different_world(medium: WorldManifest) -> None:
    other = _world(seed="hex:" + "a5" * 16)
    assert other.world_fp != medium.world_fp
    assert [c["display_name"] for c in other.contacts] != [
        c["display_name"] for c in medium.contacts
    ]


def test_more_photos_leaves_other_lists_unchanged(medium: WorldManifest) -> None:
    more = _world(counts={"photos": 90})
    assert len(more.photos) == 90
    for name in ("people", "contacts", "sms", "calls", "events", "files", "notes"):
        assert getattr(more, name) == getattr(medium, name), name
    assert more.photos[0] != medium.photos[0] or more.world_fp != medium.world_fp


def test_auto_seed_is_resolved_and_reproducible() -> None:
    first = _world(seed="auto", size="small")
    assert re.fullmatch(r"hex:[0-9a-f]{64}", first.seed)
    assert first.spec["seed"] == first.seed
    again = _world(seed=first.seed, size="small")
    assert again.world_fp == first.world_fp


def test_world_fp_stable_across_processes(medium: WorldManifest) -> None:
    code = (
        "from sandroid.world import generate, PackSet;"
        f"m = generate({{'seed': {SEED!r}, 'size': 'medium', 'country': 'de',"
        f" 'mix': {MIX!r}}}, {OWNER!r}, packs=PackSet(user_dir=False));"
        "print(m.world_fp)"
    )
    env = dict(os.environ, PYTHONHASHSEED="12345")
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        check=True,
        timeout=120,
    )
    assert out.stdout.strip() == medium.world_fp


def test_world_fp_golden_value() -> None:
    world = _world(size="small")
    assert GENERATOR_VERSION == "1"
    assert world.world_fp == GOLDEN_FP


def test_world_fp_covers_content(medium: WorldManifest) -> None:
    assert medium.verify()
    changed = WorldManifest.from_json(medium.to_json())
    changed.sms[0]["body"] += "!"
    assert not changed.verify()
    changed = WorldManifest.from_json(medium.to_json())
    changed.warnings.append("not covered")
    assert changed.verify()


def test_manifest_json_round_trip(medium: WorldManifest) -> None:
    text = medium.to_json()
    back = WorldManifest.from_json(text)
    assert back == medium
    assert back.to_json() == text
    assert WorldManifest.from_json(medium.to_json(indent=2)) == medium
    with pytest.raises(ValueError, match="unknown manifest keys"):
        WorldManifest.from_dict({**json.loads(text), "extra": 1})


# ---------------------------------------------------------------- numbers


def _in_pack(number: dict, country: dict) -> bool:
    """Whether a generated number lies in a pack range of its recorded level."""
    cc = country["phone"]["country_code"]
    nsn = number["number"][1 + len(cc) :]
    level, kind = number["level"], number["type"]
    if kind == "mobile":
        entries = country["phone"]["mobile"].get(level) or []
    elif level == "realistic":
        entries = [
            {
                "prefix": c["area_code"],
                "length": len(c["area_code"]) + c["subscriber_length"],
            }
            for c in country["phone"]["landline"]["cities"]
        ]
    else:
        entries = country["phone"]["landline"].get(level) or []
    for e in entries:
        if "range" in e:
            low, high, width = parse_range(e["range"])
            if len(nsn) == width and low <= int(nsn) <= high:
                return True
        elif nsn.startswith(str(e["prefix"])) and len(nsn) == int(e["length"]):
            return True
    return False


@pytest.mark.parametrize("country_id", PACKS.ids("countries"))
def test_numbers_match_pack_ranges_at_every_level(country_id: str) -> None:
    country = PACKS.country(country_id).data
    for level in ("fiction", "unallocated", "realistic"):
        factory = NumberFactory(country, level, lambda _msg: None)
        stream = SeedStream(b"\x01" * 16, f"numbers/{country_id}/{level}")
        for kind in ("mobile", "landline"):
            for _ in range(40):
                num = factory.make(kind, stream)
                if num is None:
                    break
                assert num["number"].startswith("+" + country["phone"]["country_code"])
                assert num["national"].startswith(country["phone"]["trunk_prefix"])
                assert _in_pack(num, country), (level, num)
                check = phone_check(num["number"])
                if num["level"] == "realistic" and kind == "mobile":
                    assert check["valid"], num
                if num["level"] == "realistic":
                    assert check["possible"], num


def test_world_numbers_stay_at_requested_level() -> None:
    world = _world(numbers="unallocated", size="large", mix={"de": 1.0})
    levels = {n["level"] for p in world.people for n in p["numbers"]}
    assert levels == {"unallocated"}
    country = PACKS.country("de").data
    for person in world.people:
        for num in person["numbers"]:
            assert _in_pack(num, country), num
    numbers = [n["number"] for p in world.people for n in p["numbers"]]
    assert len(numbers) == len(set(numbers))


def test_fiction_pool_exhaustion_falls_back_with_warning() -> None:
    world = _world(numbers="fiction", size="large")
    levels = collections.Counter(n["level"] for p in world.people for n in p["numbers"])
    assert levels["fiction"] > 0
    assert any("fiction" in w for w in world.warnings) == (len(levels) > 1)


# -------------------------------------------------------------- mix + graph


def test_mix_proportions_within_tolerance() -> None:
    for size, tol in (("medium", 0.12), ("large", 0.07)):
        world = _world(size=size)
        others = [p for p in world.people if p["relation"] != "family"]
        shares = collections.Counter(p["culture"] for p in others)
        for culture, share in MIX.items():
            assert abs(shares[culture] / len(others) - share) <= tol, (size, culture)


def test_people_language_and_names_follow_culture(medium: WorldManifest) -> None:
    for p in medium.people:
        pack = PACKS.country(p["culture"]).data
        assert p["language"] in pack["languages"]
        pool = pack["names"]["female" if p["gender"] == "f" else "male"]
        assert p["first"] in {e["name"] for e in pool}


def test_name_groups_keep_first_and_last_together() -> None:
    world = _world(country="in", mix={"in": 1.0}, size="large")
    names = PACKS.country("in").data["names"]
    tags = {
        pool: {e["name"]: set(e.get("g") or []) for e in names[pool]}
        for pool in ("female", "male", "surnames")
    }
    for p in world.people:
        if p["role"] in ("mom", "dad", "sister", "brother", "grandma", "grandpa"):
            continue  # they carry the owner's surname
        first = tags["female" if p["gender"] == "f" else "male"][p["first"]]
        last = tags["surnames"].get(p["last"], set())
        assert not first or not last or first & last, p


# ----------------------------------------------------------- privacy


def test_no_identity_token_in_manifest() -> None:
    token = "zq7tokenx"  # noqa: S105 - a canary, not a secret
    owner = {
        "first": "Mara",
        "last": "Keller",
        "phone": "+4915112345678",
        "email": f"mara.{token}@example.org",
    }
    for numbers in ("fiction", "unallocated", "realistic"):
        world = generate(
            {"seed": SEED, "size": "large", "country": "de", "numbers": numbers},
            owner,
            packs=PACKS,
        )
        dump = world.to_json() + json.dumps(world.markers(), ensure_ascii=False)
        for needle in (token, owner["email"], owner["phone"], owner["phone"][1:]):
            assert needle not in dump
        assert world.owner == {"first": "Mara", "last": "Keller"}


def test_country_from_owner_phone() -> None:
    world = generate({"seed": SEED, "size": "small"}, OWNER, packs=PACKS)
    assert world.spec["country"] == "de"
    with pytest.raises(WorldError):
        generate(
            {"seed": SEED, "size": "small"}, {"first": "A", "last": "B"}, packs=PACKS
        )


def test_device_from_spec_or_seed(medium: WorldManifest) -> None:
    codenames = {d["codename"] for d in FALLBACK_DEVICES}
    assert medium.device["make"] == "Google"
    assert medium.device["codename"] in codenames
    assert set(medium.device) == {"make", "model", "codename", "min_sdk", "max_sdk"}
    assert {(p["make"], p["model"]) for p in medium.photos} == {
        (medium.device["make"], medium.device["model"])
    }
    pinned = _world(device={"make": "Google", "model": "Pixel 8", "codename": "shiba"})
    assert pinned.device["codename"] == "shiba"
    assert all(p["model"] == "Pixel 8" for p in pinned.photos)
    assert pinned.contacts == medium.contacts
    assert not any("Pixel fingerprints" in w for w in pinned.warnings)
    other = _world(
        device={"make": "Fairphone", "model": "Fairphone 5", "codename": "FP5"}
    )
    assert other.device["make"] == "Fairphone"
    assert any(
        "used for photos only; apps will see a Google Pixel" in w
        for w in other.warnings
    )
    with pytest.raises(ValueError, match="device"):
        WorldSpec.from_dict({"device": {"make": "Google", "model": "Pixel 8"}})


def test_device_is_token_free_and_seeded() -> None:
    token = "zq7tokenx"  # noqa: S105 - a canary, not a secret
    owner = {**OWNER, "email": f"{token}@example.org"}
    seen = set()
    for i in range(16):
        world = generate(
            {"seed": f"hex:{i:032x}", "size": "small", "country": "de"},
            owner,
            packs=PACKS,
        )
        text = json.dumps(world.device)
        assert token not in text
        assert "keller" not in text.lower()
        seen.add(world.device["codename"])
    assert len(seen) > 1


def test_target_sdk_filters_devices() -> None:
    newer = {"shiba", "husky", "akita", "tokay"}
    fps = set()
    for i in range(24):
        world = generate(
            {"seed": f"hex:{i:032x}", "size": "small", "country": "de"},
            OWNER,
            packs=PACKS,
            target_sdk=33,
        )
        assert world.device["codename"] not in newer
        assert world.target_sdk == 33
        fps.add(world.world_fp)
    base = {"seed": SEED, "size": "small", "country": "de"}
    any_sdk = generate(base, OWNER, packs=PACKS)
    sdk35 = generate(base, OWNER, packs=PACKS, target_sdk=35)
    assert any_sdk.target_sdk is None
    assert sdk35.device["min_sdk"] <= 35
    assert sdk35.world_fp != any_sdk.world_fp  # target_sdk is fingerprinted
    old = generate(base, OWNER, packs=PACKS, target_sdk=30)
    assert any("target_sdk 30" in w for w in old.warnings)


# ------------------------------------------------------------- content


@pytest.mark.parametrize("country_id", PACKS.ids("countries"))
def test_no_unresolved_placeholders(country_id: str) -> None:
    world = generate(
        {"seed": SEED, "size": "large", "country": country_id}, OWNER, packs=PACKS
    )
    for name, key in TEXT_FIELDS:
        for item in getattr(world, name):
            assert not re.search(r"\{[^{}]*\}", item[key]), (name, item[key])
    for c in world.contacts:
        assert "{" not in c["display_name"]
    counts = world.spec["counts"] or {}
    assert len(world.contacts) >= 0.9 * counts.get("contacts", 250)
    assert len(world.sms) == 600


def test_alphanumeric_senders_are_preserved() -> None:
    world = _world(country="ke", mix=None, size="large")
    alnum = {
        s["sender"]
        for s in PACKS.country("ke").data["services"]
        if s["sender_type"] == "alphanumeric"
    }
    service = [m for m in world.sms if m["service"]]
    assert service
    for m in service:
        if m["sender_type"] == "alphanumeric":
            assert m["address"] in alnum
        elif m["sender_type"] == "number":
            assert m["address"].startswith("+254")
    assert any(m["address"] == "MPESA" for m in service) or any(
        m["service"] == "mobile_money" for m in service
    )


def test_emoji_detected_per_message() -> None:
    world = _world(country="ke", mix=None, size="large")
    flagged = [m for m in world.sms if m["emoji"]]
    assert flagged
    for m in world.sms:
        assert m["emoji"] == has_emoji(m["body"])
    assert has_emoji("Poa 👌")
    assert has_emoji("Love ❤️")
    assert not has_emoji("Bis morgen, 12:30 Uhr")


def test_times_are_within_history(medium: WorldManifest) -> None:
    limit = WorldSpec(history="18mo").history_seconds()
    for name in ("sms", "calls", "photos", "files", "notes"):
        for item in getattr(medium, name):
            assert 0 < item["t_rel_s"] <= limit + 86400, (name, item)


# --------------------------------------------------------------- markers


def test_markers_cover_every_kind(medium: WorldManifest) -> None:
    markers = medium.markers()
    kinds = collections.Counter(m["kind"] for m in markers)
    for kind in (
        "phone",
        "email",
        "name",
        "sms_body",
        "calendar_title",
        "geo",
        "file_name",
    ):
        assert kinds[kind] > 0, kind
    values = [(m["kind"], m["value"]) for m in markers]
    assert len(values) == len(set(values))
    for m in markers:
        assert m["origin"] == "world"
        assert m["population"] == f"world.{m['dataset']}"
        assert {"record": m["record"], "field": m["field"]} == m["refs"][0]
        if m["kind"] in ("sms_body", "calendar_title"):
            assert len(m["value"]) >= 16
        if m["kind"] == "geo":
            lat, lon = m["value"].split(",")
            assert len(lat.split(".")[1]) >= 4
            assert len(lon.split(".")[1]) >= 4
        if m["kind"] == "phone":
            assert re.fullmatch(r"\+\d{8,15}", m["value"])


def test_shared_number_refs_link_contacts_sms_and_calls(medium: WorldManifest) -> None:
    phones = [m for m in medium.markers() if m["kind"] == "phone"]
    linked = [
        m
        for m in phones
        if {r["record"].split(".")[1] for r in m["refs"]}
        >= {"contacts", "sms", "calls"}
    ]
    assert linked
    marker = linked[0]
    for ref in marker["refs"]:
        _, dataset, n = ref["record"].split(".")
        item = getattr(medium, dataset)[int(n) - 1]
        assert item["id"] == ref["record"]
        assert marker["value"] in json.dumps(item)


def test_to_markers_sets_only_existing_fields(medium: WorldManifest) -> None:
    from sandroid.core.privacy_markers import Marker

    dicts = medium.markers()
    objs = medium.to_markers()
    names = {f.name for f in dataclasses.fields(Marker)}
    geo = sum(1 for m in dicts if m["kind"] == "geo")
    assert len(objs) == len(dicts) + geo
    assert all(isinstance(o, Marker) for o in objs)
    assert {o.kind for o in objs} <= {"phone", "email", "text", "latitude", "longitude"}
    lat = next(o for o in objs if o.kind == "latitude")
    assert "group" not in names or lat.group == lat.id.rsplit(".", 1)[0]


# ---------------------------------------------------------- spec errors


@pytest.mark.parametrize(
    "spec",
    [
        {"size": "huge"},
        {"numbers": "random"},
        {"history": "forever"},
        {"counts": {"sms": -1}},
        {"counts": {"tweets": 3}},
        {"seed": "hex:abc"},
        {"colour": "blue"},
    ],
)
def test_invalid_spec_is_rejected(spec: dict) -> None:
    with pytest.raises(ValueError):
        generate({"country": "de", **spec}, OWNER, packs=PACKS)


def test_unknown_country_is_rejected() -> None:
    with pytest.raises(WorldError):
        _world(country="xx")


# ------------------------------------------------------------ performance


@pytest.mark.perf
def test_large_world_under_five_seconds() -> None:
    packs = PackSet(user_dir=False)
    start = time.perf_counter()
    world = generate(
        {"seed": SEED, "size": "large", "country": "de", "mix": MIX}, OWNER, packs=packs
    )
    elapsed = time.perf_counter() - start
    print(f"large world incl. pack loading: {elapsed:.3f} s")
    assert len(world.sms) == 600
    assert elapsed < 5.0


def test_packs_ship_next_to_the_module() -> None:
    import sandroid.world

    root = Path(sandroid.world.__file__).resolve().parent
    assert (root / "PACK_SCHEMA.md").is_file()
    assert (root.parent / "assets" / "world" / "CHANGES.md").is_file()
