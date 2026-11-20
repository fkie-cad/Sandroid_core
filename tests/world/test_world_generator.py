"""World generator: determinism, numbers, mix, privacy, rendering, markers."""

from __future__ import annotations

import collections
import dataclasses
import datetime as dt
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
    RenderedWorld,
    SeedStream,
    WorldError,
    WorldManifest,
    WorldSpec,
    generate,
    phone_check,
)
from sandroid.world.generator import (
    FALLBACK_DEVICES,
    RESERVED_EMAIL_DOMAINS,
    has_emoji,
)
from sandroid.world.manifest import week_anchor
from sandroid.world.packs import easter, parse_range

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
ANCHOR = dt.datetime(2026, 11, 20, 15, 30, tzinfo=dt.UTC)
#: world_fp of the reference world below. A change here means the generator's
#: output changed: bump GENERATOR_VERSION and update the value.
GOLDEN_FP = "ed3c8e1d305ad211034feae3b9473caecb358c3b83eb37fe94daed5a6a75ce87"


def _world(**spec: object) -> WorldManifest:
    base = {"seed": SEED, "size": "medium", "country": "de", "mix": MIX}
    base.update(spec)
    return generate(base, OWNER, packs=PACKS)


@pytest.fixture(scope="module")
def medium() -> WorldManifest:
    return _world()


@pytest.fixture(scope="module")
def large_de() -> WorldManifest:
    return _world(size="large")


@pytest.fixture(scope="module")
def many() -> WorldManifest:
    """A large world with every holiday and many files and notes."""
    return _world(size="large", counts={"events": 400, "files": 60, "notes": 40})


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
    assert GENERATOR_VERSION == "3"
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


def test_prefix_filter_sees_the_whole_range() -> None:
    entry = {"range": "3023125000-3023125999"}
    assert NumberFactory.fits(entry, "302312")
    assert NumberFactory.fits(entry, "3023125")
    assert NumberFactory.fits(entry, "30231259")  # not at the range's low end
    assert not NumberFactory.fits(entry, "3024")
    country = PACKS.country("de").data
    factory = NumberFactory(country, "fiction", lambda _msg: None)
    stream = SeedStream(b"\x02" * 16, "prefix")
    num = factory.make("landline", stream, want="30231259")
    assert num is not None
    assert num["number"].startswith("+4930231259")


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


def test_owner_number_is_never_generated() -> None:
    country = PACKS.country("de").data
    entry = {"range": "1713920000-1713920001"}
    owner = "+49 171 3920000"
    factory = NumberFactory(
        {**country, "phone": {**country["phone"], "mobile": {"fiction": [entry]}}},
        "fiction",
        lambda _msg: None,
        exclude={"+" + re.sub(r"\D", "", owner)},
    )
    stream = SeedStream(b"\x03" * 16, "owner")
    assert factory.make("mobile", stream)["number"] == "+491713920001"
    assert factory.make("mobile", stream) is None


# -------------------------------------------------------------- mix + graph


def test_mix_proportions_within_tolerance() -> None:
    for size, tol in (("medium", 0.12), ("large", 0.07)):
        world = _world(size=size)
        others = [p for p in world.people if p["relation"] != "family"]
        shares = collections.Counter(p["culture"] for p in others)
        for culture, share in MIX.items():
            assert abs(shares[culture] / len(others) - share) <= tol, (size, culture)


def test_mix_is_normalised_with_a_warning() -> None:
    world = _world(mix={"de": 2, "tr": 1}, size="small")
    assert world.spec["mix"] == {"de": pytest.approx(2 / 3), "tr": pytest.approx(1 / 3)}
    assert any("add up to 3" in w for w in world.warnings)
    exact = _world(mix={"de": 0.995, "tr": 0.005}, size="small")
    assert not any("add up" in w for w in exact.warnings)
    unknown = _world(mix={"de": 0.9, "zz": 0.1}, size="small")
    assert any("'zz' has no country pack" in w for w in unknown.warnings)


def test_people_language_and_names_follow_culture(medium: WorldManifest) -> None:
    for p in medium.people:
        pack = PACKS.country(p["culture"]).data
        assert p["language"] in pack["languages"]
        pool = pack["names"]["female" if p["gender"] == "f" else "male"]
        assert p["first"] in {e["name"] for e in pool}
        assert re.fullmatch(r"\d\d-\d\d", p["birthday"])


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
        rendered = world.render(ANCHOR)
        dump = (
            world.to_json()
            + json.dumps(dataclasses.asdict(rendered), ensure_ascii=False)
            + json.dumps(world.markers(ANCHOR), ensure_ascii=False)
        )
        for needle in (token, owner["email"], owner["phone"], owner["phone"][1:]):
            assert needle not in dump
        assert world.owner == {"first": "Mara", "last": "Keller"}


def test_country_from_owner_phone() -> None:
    world = generate(
        {"seed": SEED, "size": "small"}, {**OWNER, "phone": "0049 151 123"}, packs=PACKS
    )
    assert world.spec["country"] == "de"
    with pytest.raises(WorldError):
        generate(
            {"seed": SEED, "size": "small"}, {"first": "A", "last": "B"}, packs=PACKS
        )


# ------------------------------------------------------------------ device


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
        assert "w" not in world.device
        seen.add(world.device["codename"])
    assert len(seen) > 1


def test_target_sdk_filters_devices() -> None:
    newer = {"shiba", "husky", "akita", "tokay"}
    for i in range(24):
        world = generate(
            {"seed": f"hex:{i:032x}", "size": "small", "country": "de"},
            OWNER,
            packs=PACKS,
            target_sdk=33,
        )
        assert world.device["codename"] not in newer
        assert world.target_sdk == 33
    old = {
        generate(
            {"seed": f"hex:{i:032x}", "size": "small", "country": "de"},
            OWNER,
            packs=PACKS,
            target_sdk=30,
        ).device["codename"]
        for i in range(16)
    }
    assert old <= {"sunfish", "redfin"}
    base = {"seed": SEED, "size": "small", "country": "de"}
    any_sdk = generate(base, OWNER, packs=PACKS)
    sdk35 = generate(base, OWNER, packs=PACKS, target_sdk=35)
    assert any_sdk.target_sdk is None
    assert sdk35.device["min_sdk"] <= 35
    assert sdk35.world_fp != any_sdk.world_fp  # target_sdk is fingerprinted


def test_device_fallback_errors_and_warnings() -> None:
    base = {"seed": SEED, "size": "small", "country": "de"}
    with pytest.raises(WorldError, match="target_sdk 28"):
        generate(base, OWNER, packs=PACKS, target_sdk=28)
    pinned = {"make": "Google", "model": "Pixel 9", "codename": "tokay", "min_sdk": 35}
    world = generate({**base, "device": pinned}, OWNER, packs=PACKS, target_sdk=28)
    assert world.device["codename"] == "tokay"
    assert any("does not support target_sdk 28" in w for w in world.warnings)
    with pytest.raises(ValueError, match="target_sdk"):
        generate(base, OWNER, packs=PACKS, target_sdk=True)


def test_pack_devices_are_used_and_non_google_warns(tmp_path: Path) -> None:
    import yaml

    from sandroid.world.packs import BUILTIN_DIR

    data = yaml.safe_load((BUILTIN_DIR / "countries" / "de.yaml").read_text("utf-8"))
    data["devices"] = [
        {"make": "Fairphone", "model": "Fairphone 5", "codename": "FP5", "w": 1.0}
    ]
    (tmp_path / "countries").mkdir()
    (tmp_path / "countries" / "de.yaml").write_text(
        yaml.safe_dump(data, allow_unicode=True), "utf-8"
    )
    world = generate(
        {"seed": SEED, "size": "small", "country": "de"},
        OWNER,
        packs=PackSet(user_dir=tmp_path),
    )
    assert world.device == {
        "make": "Fairphone",
        "model": "Fairphone 5",
        "codename": "FP5",
        "min_sdk": None,
        "max_sdk": None,
    }
    assert any("apps will see a Google Pixel" in w for w in world.warnings)


# --------------------------------------------------------------- user packs


def test_malformed_user_pack_raises_world_error(tmp_path: Path) -> None:
    import yaml

    from sandroid.world.packs import BUILTIN_DIR

    data = yaml.safe_load((BUILTIN_DIR / "countries" / "de.yaml").read_text("utf-8"))
    del data["phone"]
    (tmp_path / "countries").mkdir()
    (tmp_path / "countries" / "de.yaml").write_text(
        yaml.safe_dump(data, allow_unicode=True), "utf-8"
    )
    (tmp_path / "countries" / "xx.yaml").write_text("pack: [unclosed", "utf-8")
    packs = PackSet(user_dir=tmp_path)
    with pytest.raises(WorldError) as err:
        generate({"seed": SEED, "size": "small", "country": "de"}, OWNER, packs=packs)
    assert err.value.report is not None
    assert any(e.startswith("phone") for e in err.value.report.errors)
    with pytest.raises(WorldError, match="cannot read"):
        packs.country("xx")
    reports = packs.validate_all()
    assert reports["countries/de"].errors
    assert reports["countries/xx"].errors


# ------------------------------------------------------------- content


@pytest.mark.parametrize("country_id", PACKS.ids("countries"))
def test_no_unresolved_placeholders(country_id: str) -> None:
    world = generate(
        {"seed": SEED, "size": "large", "country": country_id}, OWNER, packs=PACKS
    )
    for name, key in TEXT_FIELDS:
        for item in getattr(world, name):
            left = re.sub(r"\{@\d+\}", "", item[key])
            assert not re.search(r"[{}]", left), (name, item[key])
            assert len(item.get("date_slots", [])) == len(
                set(re.findall(r"\{@(\d+)\}", item[key]))
            )
    rendered = world.render(ANCHOR)
    for name, key in TEXT_FIELDS:
        for item in getattr(rendered, name):
            assert not re.search(r"[{}]", item[key]), (name, item[key])
    for c in world.contacts:
        assert "{" not in c["display_name"]
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
    assert any(m["service"] == "mobile_money" for m in service)


def test_short_codes_are_numeric_and_keep_the_brand() -> None:
    world = _world(country="br", mix=None, size="large")
    brands = {
        s["sender"]
        for s in PACKS.country("br").data["services"]
        if s["sender_type"] == "shortcode" and not s["sender"].isdigit()
    }
    codes = [m for m in world.sms if m["sender_type"] == "shortcode"]
    assert any(m["label"] in brands for m in codes)
    for m in codes:
        assert m["address"].isdigit()
        if m["label"] in brands:
            assert 5 <= len(m["address"]) <= 6
    again = _world(country="br", mix=None, size="large")
    assert [m["address"] for m in again.sms] == [m["address"] for m in world.sms]


def test_emoji_detected_per_message() -> None:
    world = _world(country="ke", mix=None, size="large")
    assert any(m["emoji"] for m in world.sms)
    for m in world.sms:
        assert m["emoji"] == has_emoji(m["body"])
    assert has_emoji("Poa 👌")
    assert has_emoji("Love ❤️")
    assert has_emoji("Kaffee ☕")
    assert not has_emoji("Bis morgen, 12:30 Uhr")
    assert not has_emoji("Erledigt ✓")
    assert not has_emoji("a‍b️")


def test_times_are_within_history(medium: WorldManifest) -> None:
    for history in ("18mo", "10d"):
        world = medium if history == "18mo" else _world(history=history)
        limit = WorldSpec(history=history).history_seconds()
        for name in ("sms", "calls", "photos", "files", "notes"):
            for item in getattr(world, name):
                assert 0 < item["t_rel_s"] <= limit, (history, name, item["t_rel_s"])


def test_daily_rhythm(large_de: WorldManifest) -> None:
    hours = collections.Counter(
        dt.datetime.fromtimestamp(m["ts_ms"] / 1000, dt.UTC).hour
        for m in large_de.render(ANCHOR).sms
    )
    night = sum(hours[h] for h in range(1, 6))
    evening = sum(hours[h] for h in range(18, 22))
    assert evening > 5 * max(night, 1)
    outings = [p for p in large_de.photos if p["cluster"] == "outing"]
    rendered = {p["id"]: p for p in large_de.render(ANCHOR).photos}
    weekend = sum(
        dt.datetime.fromtimestamp(rendered[p["id"]]["ts_ms"] / 1000, dt.UTC).weekday()
        >= 5
        for p in outings
    )
    assert outings
    assert weekend == len(outings)


# ------------------------------------------------------------- rendering


def test_render_anchor_snaps_to_monday_midnight() -> None:
    wed = dt.datetime(2026, 11, 18, 17, 45, tzinfo=dt.UTC)
    assert week_anchor(wed) == dt.datetime(2026, 11, 16, tzinfo=dt.UTC)
    naive = week_anchor(dt.datetime(2026, 11, 22, 3))
    assert naive == dt.datetime(2026, 11, 16, tzinfo=dt.UTC)


def _de_date(text: str) -> dt.date:
    day, month, year = (int(x) for x in text.split("."))
    return dt.date(year, month, day)


@pytest.mark.parametrize(
    "anchor",
    [
        dt.datetime(2026, 11, 22, 23, 0, tzinfo=dt.UTC),  # Sunday 23:00
        dt.datetime(2026, 11, 16, 0, 0, tzinfo=dt.UTC),  # Monday 00:00
        dt.datetime(2026, 11, 18, 9, 30, tzinfo=dt.UTC),  # Wednesday
    ],
)
def test_render_is_relative_to_the_real_anchor(
    large_de: WorldManifest, anchor: dt.datetime
) -> None:
    rendered = large_de.render(anchor)
    now = _ms(anchor)
    assert rendered.anchor == anchor.isoformat()
    week = dt.datetime.fromisoformat(rendered.week_anchor)
    assert week.weekday() == 0
    assert dt.timedelta(0) <= week - anchor < dt.timedelta(days=7)
    future = [e for e in large_de.events if (e["t_rel_s"] or 0) < 0]
    assert future
    by_id = {e["id"]: e for e in rendered.events}
    for ev in future:
        assert by_id[ev["id"]]["ts_ms"] > now
    past = [
        row["ts_ms"]
        for name in ("sms", "calls", "photos", "files", "notes")
        for row in getattr(rendered, name)
    ]
    assert max(past) <= now
    assert now - max(past) <= 2 * 86400 * 1000
    newest_sms = max(m["ts_ms"] for m in rendered.sms)
    assert now - newest_sms <= 2 * 86400 * 1000
    for name in ("sms", "photos"):
        rows = getattr(rendered, name)
        key = "conv" if name == "sms" else "group"
        groups: dict[object, list[int]] = collections.defaultdict(list)
        items = {i["id"]: i for i in getattr(large_de, name)}
        for row in rows:
            if row.get(key) is not None:
                groups[row[key]].append(
                    row["ts_ms"] + items[row["id"]]["t_rel_s"] * 1000
                )
        for stamps in groups.values():
            assert len(set(stamps)) == 1  # a group moves as one


def _ms(moment: dt.datetime) -> int:
    return int(moment.timestamp() * 1000)


def test_render_one_week_apart(large_de: WorldManifest) -> None:
    first = large_de.render(ANCHOR)
    second = large_de.render(ANCHOR + dt.timedelta(days=7))
    assert isinstance(first, RenderedWorld)
    week_ms = 7 * 86400 * 1000
    for a, b in zip(first.sms, second.sms, strict=True):
        assert b["ts_ms"] - a["ts_ms"] == week_ms
    slotted = [m for m in large_de.sms if m.get("date_slots")]
    assert slotted
    by_id = {m["id"]: m for m in first.sms}
    by_id2 = {m["id"]: m for m in second.sms}
    pattern = PACKS.country("de").data["date_format"]
    assert pattern == "dd.MM.yyyy"
    for m in slotted:
        sent = dt.datetime.fromtimestamp(by_id[m["id"]]["ts_ms"] / 1000, dt.UTC).date()
        dates = re.findall(r"\d\d\.\d\d\.\d{4}", by_id[m["id"]]["body"])
        assert dates, by_id[m["id"]]["body"]
        for text in dates:
            day = _de_date(text)
            assert 0 <= (day - sent).days <= 10, (text, sent)
        later = re.findall(r"\d\d\.\d\d\.\d{4}", by_id2[m["id"]]["body"])
        assert [
            (_de_date(x) - _de_date(y)).days for x, y in zip(later, dates, strict=True)
        ] == [7] * len(dates)


def test_weekday_slots_follow_the_anchor(tmp_path: Path) -> None:
    import yaml

    from sandroid.world.packs import BUILTIN_DIR

    names = [
        "Montag",
        "Dienstag",
        "Mittwoch",
        "Donnerstag",
        "Freitag",
        "Samstag",
        "Sonntag",
    ]
    data = yaml.safe_load((BUILTIN_DIR / "languages" / "de.yaml").read_text("utf-8"))
    data["weekdays"] = names
    (tmp_path / "languages").mkdir()
    (tmp_path / "languages" / "de.yaml").write_text(
        yaml.safe_dump(data, allow_unicode=True), "utf-8"
    )
    world = generate(
        {"seed": SEED, "size": "large", "country": "de", "mix": {"de": 1}},
        OWNER,
        packs=PackSet(user_dir=tmp_path),
    )
    day_items = [
        (m, slot)
        for m in world.sms
        for slot in m.get("date_slots", [])
        if slot["kind"] == "day"
    ]
    assert day_items
    for anchor in (
        ANCHOR,
        ANCHOR + dt.timedelta(days=7),
        ANCHOR + dt.timedelta(days=3),
    ):
        rendered = {m["id"]: m for m in world.render(anchor).sms}
        for m, slot in day_items:
            row = rendered[m["id"]]
            sent = dt.datetime.fromtimestamp(row["ts_ms"] / 1000, dt.UTC)
            target = sent + dt.timedelta(seconds=m["t_rel_s"] - slot["t_rel_s"])
            assert names[target.weekday()] in row["body"]
            assert 1 <= (target.date() - sent.date()).days <= 7


def test_easter_holidays_land_on_the_right_day(many: WorldManifest) -> None:
    assert any(str(e.get("rule") or "").startswith("easter") for e in many.events)
    for anchor in (
        dt.datetime(2026, 11, 20, tzinfo=dt.UTC),
        dt.datetime(2028, 3, 1, tzinfo=dt.UTC),
    ):
        seen = 0
        for ev in many.render(anchor).events:
            rule = str(ev.get("rule") or "")
            if not rule.startswith("easter"):
                continue
            seen += 1
            day = dt.datetime.fromtimestamp(ev["ts_ms"] / 1000, dt.UTC).date()
            assert day == easter(day.year) + dt.timedelta(days=int(rule[6:] or 0))
            assert day <= anchor.date() + dt.timedelta(days=60)
            assert (anchor.date() - day).days <= 18 * 31
        assert seen


def test_birthdays_render_every_year(large_de: WorldManifest) -> None:
    bdays = [e for e in large_de.events if e["kind"] == "birthday"]
    assert bdays
    for anchor in (ANCHOR, dt.datetime(2029, 7, 1, tzinfo=dt.UTC)):
        rendered = {e["id"]: e for e in large_de.render(anchor).events}
        for ev in bdays:
            day = dt.datetime.fromtimestamp(rendered[ev["id"]]["ts_ms"] / 1000, dt.UTC)
            if ev["rule"] != "02-29":
                assert f"{day.month:02d}-{day.day:02d}" == ev["rule"]


# --------------------------------------------------------------- markers


def test_markers_cover_every_kind(large_de: WorldManifest) -> None:
    markers = large_de.markers(ANCHOR)
    kinds = collections.Counter(m["kind"] for m in markers)
    for kind in ("phone", "email", "name", "sms_body", "calendar_title", "geo"):
        assert kinds[kind] > 0, kind
    assert kinds["file_name"] + kinds["note"] > 0
    values = [(m["kind"], m["value"]) for m in markers]
    assert len(values) == len(set(values))
    for m in markers:
        assert m["origin"] == "world"
        assert m["population"] == f"world.{m['dataset']}"
        assert {"record": m["record"], "field": m["field"]} == m["refs"][0]
        if m["kind"] in ("sms_body", "calendar_title", "file_name", "note"):
            assert len(m["value"]) >= 16
            assert "{" not in m["value"]
        if m["kind"] == "geo":
            lat, lon = m["value"].split(",")
            assert len(lat.split(".")[1]) >= 4
            assert len(lon.split(".")[1]) >= 4
        if m["kind"] == "phone":
            assert re.fullmatch(r"\+\d{8,15}", m["value"])


def test_generic_texts_are_not_markers(many: WorldManifest) -> None:
    rendered = many.render(ANCHOR)
    titles = {e["title"] for e in rendered.events}
    names = {f["name"] for f in rendered.files}
    generic = {
        "Christi Himmelfahrt",
        "Mitarbeitergespräch",
        "Lohnsteuerbescheinigung.pdf",
    }
    assert generic & (titles | names), "the generic samples should occur"
    values = {m["value"] for m in rendered.markers()}
    assert not generic & values
    holidays = {e["title"] for e in rendered.events if e["kind"] == "holiday"}
    assert not holidays & values
    texts = {
        m["value"]
        for m in rendered.markers()
        if m["kind"] in ("sms_body", "calendar_title", "file_name", "note")
    }
    items = [
        (item, key)
        for name, key in TEXT_FIELDS
        for item in getattr(rendered, name)
        if item[key] in texts
    ]
    assert items
    assert all(item["distinctive"] for item, _ in items)


def test_shared_number_refs_link_contacts_sms_and_calls(medium: WorldManifest) -> None:
    rendered = medium.render(ANCHOR)
    phones = [m for m in rendered.markers() if m["kind"] == "phone"]
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
        item = getattr(rendered, dataset)[int(n) - 1]
        assert item["id"] == ref["record"]
        assert marker["value"] in json.dumps(item)


def test_to_markers_sets_only_existing_fields(medium: WorldManifest) -> None:
    from sandroid.core.privacy_markers import Marker

    dicts = medium.markers(ANCHOR)
    objs = medium.to_markers(ANCHOR)
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
        {"size": ["medium"]},
        {"numbers": "random"},
        {"history": "forever"},
        {"history": 18},
        {"history": "3000y"},
        {"history": "1000000000y"},
        {"history": "40000d"},
        {"counts": {"sms": -1}},
        {"counts": {"sms": True}},
        {"counts": {"sms": 1.5}},
        {"counts": {"tweets": 3}},
        {"counts": [1, 2]},
        {"seed": "hex:abc"},
        {"seed": 12},
        {"mix": {"de": 0}},
        {"mix": {"de": "lots"}},
        {"mix": {"de": True}},
        {"mix": ["de"]},
        {"places": {"home": "Berlin"}},
        {"places": {"home": {"lat": "52", "lon": 13}}},
        {"places": {"home": {"lat": 952, "lon": 13}}},
        {"places": {"garden": {"city": "Berlin"}}},
        {"places": {"home": {}}},
        {"country": 49},
        {"colour": "blue"},
        {"emails": "real"},
        {"emails": 1},
    ],
)
def test_invalid_spec_is_rejected(spec: dict) -> None:
    with pytest.raises(ValueError):
        generate({"country": "de", **spec}, OWNER, packs=PACKS)


@pytest.mark.parametrize(
    "owner",
    [
        None,
        "Mara",
        {"first": 3, "last": "K"},
        {"first": "Mara", "last": "K", "phone": []},
        {"first": "Mara", "last": "K", "email": 0},
    ],
)
def test_invalid_owner_is_rejected(owner: object) -> None:
    with pytest.raises(ValueError, match="owner"):
        generate({"country": "de", "size": "small"}, owner, packs=PACKS)


def test_unknown_country_is_rejected() -> None:
    with pytest.raises(WorldError):
        _world(country="xx")


# ------------------------------------------------------------ e-mail levels


def _emails(world: WorldManifest) -> list[str]:
    out = [p["email"] for p in world.people if p["email"]]
    out += [c["email"] for c in world.contacts if c["email"]]
    return out


def test_default_emails_use_reserved_domains_only(medium: WorldManifest) -> None:
    assert medium.spec["emails"] == "reserved"
    emails = _emails(medium)
    assert len(emails) > 10
    real = {d["domain"] for d in PACKS.country("de").data["email"]["domains"]}
    for addr in emails:
        assert addr.split("@", 1)[1] in RESERVED_EMAIL_DOMAINS, addr
        assert addr.split("@", 1)[1] not in real
    blob = medium.to_json()
    for domain in real:
        assert "@" + domain not in blob


def test_realistic_emails_use_pack_domains_with_same_local_parts(
    medium: WorldManifest,
) -> None:
    world = _world(emails="realistic")
    real = {d["domain"] for d in PACKS.country("de").data["email"]["domains"]}
    assert {a.split("@", 1)[1] for a in _emails(world)} <= real
    # Same stream draws: only the domains differ.
    assert [a.split("@")[0] for a in _emails(world)] == [
        a.split("@")[0] for a in _emails(medium)
    ]
    assert world.world_fp != medium.world_fp


def test_owned_emails_use_the_given_domain() -> None:
    world = generate(
        {"seed": SEED, "size": "small", "country": "de", "emails": "owned"},
        OWNER,
        packs=PACKS,
        email_domain="Lab.Sandroid.Test",
    )
    emails = _emails(world)
    assert emails
    assert all(a.endswith("@lab.sandroid.test") for a in emails)
    assert not world.warnings or not any("emails" in w for w in world.warnings)


@pytest.mark.parametrize("domain", [None, "", "not a domain", "x"])
def test_owned_without_domain_falls_back_to_reserved(
    domain: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "sandroid.world.generator.configured_email_domain", lambda: None
    )
    world = generate(
        {"seed": SEED, "size": "small", "country": "de", "emails": "owned"},
        OWNER,
        packs=PACKS,
        email_domain=domain,
    )
    reserved = generate(
        {"seed": SEED, "size": "small", "country": "de"}, OWNER, packs=PACKS
    )
    assert _emails(world) == _emails(reserved)
    assert any("email_domain" in w for w in world.warnings)
    # The level is part of world_fp even when the output falls back.
    assert world.world_fp != reserved.world_fp


def test_owned_reads_the_sandroid_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sandroid.world.generator.configured_email_domain", lambda: "mine.test"
    )
    world = generate(
        {"seed": SEED, "size": "small", "country": "de", "emails": "owned"},
        OWNER,
        packs=PACKS,
    )
    assert all(a.endswith("@mine.test") for a in _emails(world))


def test_emails_are_markers_at_every_level() -> None:
    for level in ("reserved", "realistic"):
        world = _world(size="small", emails=level)
        kinds = {m["value"] for m in world.markers(ANCHOR) if m["kind"] == "email"}
        assert kinds
        assert kinds <= set(_emails(world))
        assert {c["email"] for c in world.contacts if c["email"]} <= kinds


# ------------------------------------------------------------ performance


@pytest.mark.perf
def test_large_world_under_five_seconds() -> None:
    packs = PackSet(user_dir=False)
    start = time.perf_counter()
    world = generate(
        {"seed": SEED, "size": "large", "country": "de", "mix": MIX}, OWNER, packs=packs
    )
    world.render(ANCHOR).markers()
    elapsed = time.perf_counter() - start
    print(f"large world incl. pack loading, render and markers: {elapsed:.3f} s")
    assert len(world.sms) == 600
    assert elapsed < 5.0


def test_packs_ship_next_to_the_module() -> None:
    import sandroid.world

    root = Path(sandroid.world.__file__).resolve().parent
    assert (root / "PACK_SCHEMA.md").is_file()
    assert (root.parent / "assets" / "world" / "CHANGES.md").is_file()
