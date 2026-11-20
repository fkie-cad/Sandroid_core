"""Identity profile schema 2 (YAML): comments kept on save, ``extends``
overlays, built-in profiles, the owner, the ``world:`` pass-through and the
one-time conversion of schema 1 TOML profiles. No device.
"""

from __future__ import annotations

import pytest

from sandroid.services import identity as ident
from sandroid.services import identity_store as store
from sandroid.services.identity import IdentityService, Profile, ProfileError

TOKEN = "3f9a1c07"  # noqa: S105 - a canary token, not a secret
SEED = "hex:" + "11" * 32


@pytest.fixture
def lib(tmp_path, monkeypatch):
    """A private profile library."""
    monkeypatch.setenv(ident.PROFILES_DIR_ENV, str(tmp_path / "profiles"))
    return ident.profiles_dir()


@pytest.fixture
def svc(lib):
    return IdentityService()


def _errors(profile: Profile) -> list[ident.Issue]:
    return [i for i in ident.validate(profile) if i.severity == "error"]


def _paths(profile: Profile, severity: str) -> set[str]:
    return {i.path for i in ident.validate(profile) if i.severity == severity}


HAND_WRITTEN = """\
# Mara's test persona (hand written)
format: sandroid-identity
schema: 2
id: mara
name: Mara Schneider (DE)   # shown in the lens
extends: builtin:de
token: "3f9a1c07"
seed: hex:{seed}
revision: 4
created: 2026-11-19T10:00:00+01:00
retired_tokens: []
owner:
  first: Mara       # verbatim in the world
  last: Schneider
  phone: "+4915204902863"
  email: "mara.schneider.{{token}}@example.org"
values:
  # the SIM number is the owner's
  phone_number: {{template: "{{owner.phone}}"}}
  gps:
    value: "52.517201, 13.388910"   # Mitte
world:
  seed: auto   # resolved on the first save
  size: medium
  country: de
  mix: {{de: 0.8, tr: 0.12, gb: 0.08}}
notes: ""
"""


def _write(lib, pid: str, text: str) -> None:
    (lib / f"{pid}.yaml").write_text(text, encoding="utf-8")


def _hand_written(lib) -> str:
    text = HAND_WRITTEN.format(seed="11" * 32)
    _write(lib, "mara", text)
    return text


# ---------------------------------------------------------------------------
# round trip with comments
# ---------------------------------------------------------------------------


def test_an_edit_keeps_comments_order_and_other_nodes(svc, lib):
    _hand_written(lib)
    profile = svc.load("mara")
    assert profile.name == "Mara Schneider (DE)"
    assert profile.values["gps"].value == "52.517201, 13.388910"
    assert "imei" in profile.values  # inherited from builtin:de
    profile.values["gps"].value = "52.500001, 13.400001"
    svc.save(profile)
    text = (lib / "mara.yaml").read_text(encoding="utf-8")
    for comment in (
        "# Mara's test persona (hand written)",
        "# shown in the lens",
        "# verbatim in the world",
        "# the SIM number is the owner's",
        "# Mitte",
        "# resolved on the first save",
    ):
        assert comment in text
    assert 'value: "52.500001, 13.400001"' in text
    assert "revision: 5" in text
    assert "created: 2026-11-19T10:00:00+01:00" in text
    keys = [line.split(":")[0] for line in text.splitlines() if line[:1].isalpha()]
    assert keys == [
        "format",
        "schema",
        "id",
        "name",
        "extends",
        "token",
        "seed",
        "revision",
        "created",
        "retired_tokens",
        "owner",
        "values",
        "world",
        "notes",
    ]
    # inherited values are not copied into the file
    assert "imei" not in text
    assert "contacts" not in text
    again = svc.load("mara")
    assert again.values["gps"].value == "52.500001, 13.400001"
    assert ident.fingerprint(again) == ident.fingerprint(profile)


def test_a_save_without_changes_only_bumps_the_revision(svc, lib):
    pinned = "hex:" + "ab" * 32  # nothing to resolve
    text = HAND_WRITTEN.format(seed="11" * 32).replace("seed: auto", f"seed: {pinned}")
    _write(lib, "mara", text)
    svc.save(svc.load("mara"))
    after = (lib / "mara.yaml").read_text(encoding="utf-8")
    assert after == text.replace("revision: 4", "revision: 5")


def test_regenerate_rename_and_duplicate_keep_comments(svc, lib):
    _hand_written(lib)
    profile = svc.regenerate("mara")
    assert profile.token != TOKEN
    assert profile.retired_tokens == [TOKEN]
    text = (lib / "mara.yaml").read_text(encoding="utf-8")
    assert "# verbatim in the world" in text
    assert f'token: "{profile.token}"' in text  # the quote style is kept
    assert "retired_tokens: [3f9a1c07]" in text
    dup = svc.duplicate("mara")
    dup_text = (lib / f"{dup.id}.yaml").read_text(encoding="utf-8")
    assert "# Mara's test persona (hand written)" in dup_text
    assert "# Mitte" in dup_text
    svc.rename("mara", "Mara (renamed)", new_id="mara2")
    renamed = (lib / "mara2.yaml").read_text(encoding="utf-8")
    assert "id: mara2" in renamed
    assert "name: Mara (renamed)" in renamed
    assert "# shown in the lens" in renamed
    assert not (lib / "mara.yaml").exists()


def test_an_inherited_value_edited_is_written_as_an_own_override(svc, lib):
    _hand_written(lib)
    profile = svc.load("mara")
    assert profile.values["imei"].template
    profile.values["imei"].template = None
    profile.values["imei"].value = "358476310000004"
    profile.values["clipboard"].enabled = False
    svc.save(profile)
    own = store.plain(store.load_yaml((lib / "mara.yaml").read_text("utf-8")))
    assert own["values"]["imei"] == {"value": "358476310000004"}
    assert own["values"]["clipboard"] == {"enabled": False}
    again = svc.load("mara")
    assert again.values["imei"].value == "358476310000004"
    assert again.values["imei"].template is None  # the parent's source dropped
    assert again.values["clipboard"].template == "Notiz {token} merken"
    assert not again.values["clipboard"].enabled


def test_lens_draft_copy_has_no_document(svc, lib):
    _hand_written(lib)
    profile = svc.load("mara")
    draft = profile.copy()
    assert draft._doc is None
    draft.values["gps"].value = "1.000001, 2.000001"
    draft.owner["first"] = "Other"
    assert profile.values["gps"].value == "52.517201, 13.388910"
    assert profile.owner["first"] == "Mara"


# ---------------------------------------------------------------------------
# extends
# ---------------------------------------------------------------------------


def test_merge_maps_key_by_key_and_lists_replace():
    base = {
        "owner": {"first": "A", "last": "B"},
        "values": {"gps": {"template": "x", "provider": "native"}},
        "lists": {"contacts": [{"name": "a"}], "sms": [{"body": "b"}]},
    }
    child = {
        "owner": {"last": "C"},
        "values": {"gps": {"value": "1, 2"}},
        "lists": {"contacts": [{"name": "z"}]},
    }
    merged = store.merge(base, child)
    assert merged["owner"] == {"first": "A", "last": "C"}
    assert merged["values"]["gps"] == {"provider": "native", "value": "1, 2"}
    assert merged["lists"] == {"contacts": [{"name": "z"}], "sms": [{"body": "b"}]}
    assert base["owner"] == {"first": "A", "last": "B"}  # not changed


def test_extends_a_library_profile_and_leaf_keys_stay_own(svc, lib):
    _hand_written(lib)
    _write(
        lib,
        "child",
        "format: sandroid-identity\nschema: 2\nid: child\nextends: mara\n"
        'token: "ab12cd34"\nseed: hex:' + "22" * 32 + "\n"
        "owner: {first: Lena}\nvalues:\n  clipboard: {value: 'child ab12cd34'}\n",
    )
    child = svc.load("child")
    assert child.token == "ab12cd34"  # noqa: S105 - a canary token
    assert child.seed == "hex:" + "22" * 32
    assert child.revision == 0  # the parent's revision is not inherited
    assert child.created is None
    assert child.owner["first"] == "Lena"
    assert child.owner["last"] == "Schneider"
    assert child.values["gps"].value == "52.517201, 13.388910"  # from mara
    assert child.values["imei"].template  # from builtin:de through mara
    assert child.values["clipboard"].value == "child ab12cd34"
    assert child.preset == "de"


def test_extends_cycles_and_depth_are_errors(svc, lib):
    head = "format: sandroid-identity\nschema: 2\n"
    _write(lib, "a", head + "id: a\nextends: b\n")
    _write(lib, "b", head + "id: b\nextends: a\n")
    with pytest.raises(ProfileError, match="cycle"):
        svc.load("a")
    _write(lib, "self", head + "id: self\nextends: self\n")
    with pytest.raises(ProfileError, match="cycle"):
        svc.load("self")
    for n in range(store.EXTENDS_DEPTH_MAX + 1):
        _write(lib, f"p{n}", head + f"id: p{n}\nextends: p{n + 1}\n")
    _write(lib, f"p{store.EXTENDS_DEPTH_MAX + 1}", head + "id: end\n")
    with pytest.raises(ProfileError, match="deeper"):
        svc.load("p0")
    assert svc.load("p1").id == "p1"  # exactly the limit
    _write(lib, "lost", head + "id: lost\nextends: builtin:atlantis\n")
    with pytest.raises(ProfileError, match="atlantis"):
        svc.load("lost")
    listed = {i.id: i.error for i in svc.list_profiles()}
    assert "cycle" in listed["a"]
    assert listed["p1"] == ""


# ---------------------------------------------------------------------------
# built-in profiles
# ---------------------------------------------------------------------------


def test_every_builtin_validates_and_matches_its_preset():
    from sandroid.services.device_settings_service import COUNTRY_PRESETS

    ids = store.builtin_ids()
    assert set(ids) == set(COUNTRY_PRESETS)
    for bid in ids:
        raw = store.load_builtin(bid)
        assert not {"token", "seed", "revision", "created"} & set(raw)
        assert raw["preset"] == bid
        profile = ident.profile_from_builtin(bid)
        assert not _errors(profile), (bid, _errors(profile))
        assert set(profile.values) == set(ident.generate_profile(bid).values)
        assert (
            ident.render_value(profile, profile.values["phone_number"])
            == (ident.render_owner(profile)["phone"])
        )
        if "world" in raw:
            assert raw["world"]["seed"] == "auto"


def test_create_from_a_builtin_writes_only_its_own_keys(svc, lib):
    first = svc.create("de")
    second = svc.create("de")
    assert (first.id, second.id) == ("mara-de", "mara-de-2")
    own = store.plain(store.load_yaml((lib / "mara-de.yaml").read_text("utf-8")))
    assert own["extends"] == "builtin:de"
    assert set(own) == {
        "format",
        "schema",
        "id",
        "name",
        "extends",
        "token",
        "seed",
        "revision",
        "created",
        "retired_tokens",
        "values",
        "world",
    }
    assert set(own["values"]) == {"gps"}  # its own GPS fix
    assert own["world"] == {"seed": first.world["seed"]}
    assert store.WORLD_SEED_RE.fullmatch(own["world"]["seed"])
    loaded = svc.load(first.id)
    assert not _errors(loaded)
    assert loaded.world["country"] == "de"
    assert first.token != second.token
    assert first.world["seed"] != second.world["seed"]
    assert first.values["gps"].value != second.values["gps"].value
    assert ident.fingerprint(first) != ident.fingerprint(second)
    assert [b for b, _ in svc.builtins()] == store.builtin_ids()


# ---------------------------------------------------------------------------
# owner
# ---------------------------------------------------------------------------


def _owned(**owner) -> Profile:
    profile = ident.generate_profile("de")
    profile.token, profile.seed = TOKEN, SEED
    profile.owner = {
        "first": "Mara",
        "last": "Schneider",
        "phone": "+4915204902863",
        "email": "mara.schneider.{token}@example.org",
        **owner,
    }
    return profile


def test_owner_names_must_not_carry_a_token():
    assert not _errors(_owned())
    assert "owner.first" in _paths(_owned(first=f"Mara{TOKEN}"), "error")
    retired = _owned(last="Schneider-ab12cd34")
    retired.retired_tokens = ["ab12cd34"]
    assert "owner.last" in _paths(retired, "error")
    assert "owner.first" in _paths(_owned(first="Mara {token}"), "error")
    assert "owner.last" in _paths(_owned(last=""), "error")
    assert "owner.phone" in _paths(_owned(phone="015204902863"), "error")
    assert "owner.email" in _paths(_owned(email="nobody"), "error")
    assert "owner.nick" in _paths(_owned(nick="M"), "warning")
    none = _owned()
    none.owner = {}
    assert "owner" in _paths(none, "warning")
    assert not _errors(none)


def test_templates_use_owner_fields():
    profile = _owned()
    profile.values["device_name"].template = "{owner.first}s Pixel {token}"
    profile.values["account"].template = "{owner.email}"
    profile.values["phone_number"].template = "{owner.phone}"
    profile.contacts[0]["name"] = "{owner.last} Family {token}"
    assert ident.render_owner(profile)["email"] == f"mara.schneider.{TOKEN}@example.org"
    assert ident.render_value(profile, profile.values["device_name"]) == (
        f"Maras Pixel {TOKEN}"
    )
    assert ident.render_value(profile, profile.values["account"]) == (
        f"mara.schneider.{TOKEN}@example.org"
    )
    assert ident.render_value(profile, profile.values["phone_number"]) == (
        "+4915204902863"
    )
    assert ident.render_lists(profile)["contacts"][0]["name"] == (
        f"Schneider Family {TOKEN}"
    )
    assert not _errors(profile)
    before = ident.fingerprint(profile)
    profile.owner["phone"] = "+4915204902864"
    assert ident.fingerprint(profile) != before  # the seeded value changed
    profile.owner.pop("phone")
    assert "values.phone_number" in _paths(profile, "error")
    with pytest.raises(ident.TemplateError):
        ident.render_template("{owner.first}", token=TOKEN, seed=b"", key="k")
    with pytest.raises(ident.TemplateError):
        ident.render_template(
            "{owner.nick}", token=TOKEN, seed=b"", key="k", owner={"nick": "x"}
        )


# ---------------------------------------------------------------------------
# world
# ---------------------------------------------------------------------------

GOOD_WORLD = {
    "seed": "auto",
    "size": "medium",
    "country": "de",
    "mix": {"de": 0.8, "tr": 0.12, "gb": 0.08},
    "numbers": "unallocated",
    "history": "18mo",
    "counts": {"contacts": 40, "photos": 0},
    "places": {"home": {"city": "Berlin"}},
    "device": {"make": "Google", "model": "Pixel 8", "codename": "shiba"},
    "emails": "reserved",
}


def test_a_good_world_has_no_issues():
    assert store.world_issues(GOOD_WORLD) == []
    assert store.world_issues({"seed": "hex:" + "a" * 32}) == []
    assert store.world_issues({}) == []


@pytest.mark.parametrize(
    ("patch", "path", "severity"),
    [
        ({"seed": "hex:abc"}, "world.seed", "error"),
        ({"seed": 7}, "world.seed", "error"),
        ({"size": "huge"}, "world.size", "error"),
        ({"numbers": "real"}, "world.numbers", "error"),
        ({"emails": "gmail"}, "world.emails", "error"),
        ({"country": ""}, "world.country", "error"),
        ({"mix": {"de": "most"}}, "world.mix.de", "error"),
        ({"mix": [1]}, "world.mix", "error"),
        ({"history": "18 months"}, "world.history", "error"),
        ({"counts": {"sms": -1}}, "world.counts.sms", "error"),
        ({"counts": {"sms": 1.5}}, "world.counts.sms", "error"),
        ({"counts": {"faxes": 3}}, "world.counts.faxes", "warning"),
        ({"places": [1]}, "world.places", "error"),
        ({"device": {"make": "Google"}}, "world.device.model", "error"),
        ({"device": "Pixel 8"}, "world.device", "error"),
        (
            {"device": {**GOOD_WORLD["device"], "min_sdk": "35"}},
            "world.device.min_sdk",
            "error",
        ),
        (
            {"device": {**GOOD_WORLD["device"], "min_sdk": 35, "max_sdk": 33}},
            "world.device",
            "error",
        ),
        (
            {"device": {"make": "Samsung", "model": "S24"}},
            "world.device.make",
            "warning",
        ),
        (
            {"device": {**GOOD_WORLD["device"], "colour": "red"}},
            "world.device.colour",
            "warning",
        ),
        ({"weather": "sunny"}, "world.weather", "warning"),
    ],
)
def test_world_shape_issues(patch, path, severity):
    issues = store.world_issues({**GOOD_WORLD, **patch})
    assert (severity, path) in {(s, p) for s, p, _m in issues}
    if severity == "warning":
        assert not [i for i in issues if i[0] == "error"]


def test_world_is_passed_through_and_not_fingerprinted():
    profile = _owned()
    profile.world = dict(GOOD_WORLD)
    before = ident.fingerprint(profile)
    profile.world["size"] = "large"
    profile.world["weather"] = "sunny"
    assert ident.fingerprint(profile) == before
    assert "world.weather" in _paths(profile, "warning")
    assert not _errors(profile)
    profile.world["size"] = "huge"
    assert "world.size" in _paths(profile, "error")
    back = Profile.loads(profile.dumps())
    assert back.world == profile.world


def test_world_seed_auto_is_resolved_once_and_duplicate_resets_it(svc, lib):
    _hand_written(lib)
    assert svc.load("mara").world["seed"] == "auto"
    seed = svc.resolve_world_seed("mara")
    assert store.WORLD_SEED_RE.fullmatch(seed)
    text = (lib / "mara.yaml").read_text(encoding="utf-8")
    assert f"seed: {seed}" in text
    assert "# resolved on the first save" in text
    assert "revision: 4" in text  # a resolution is no edit
    assert svc.resolve_world_seed("mara") == seed
    profile = svc.load("mara")
    profile.notes = "x"
    svc.save(profile)
    assert svc.load("mara").world["seed"] == seed
    dup = svc.duplicate("mara")
    assert store.WORLD_SEED_RE.fullmatch(dup.world["seed"])
    assert dup.world["seed"] != seed
    assert svc.load(dup.id).world["seed"] == dup.world["seed"]
    # a save resolves it too
    _write(
        lib, "auto", HAND_WRITTEN.format(seed="33" * 32).replace("id: mara", "id: auto")
    )
    profile = svc.load("auto")
    svc.save(profile)
    assert store.WORLD_SEED_RE.fullmatch(svc.load("auto").world["seed"])
    assert svc.resolve_world_seed("auto") == profile.world["seed"]


def test_no_world_means_no_seed(svc, lib):
    profile = svc.save(ident.generate_profile("de"))
    assert profile.world == {}
    assert svc.resolve_world_seed(profile.id) == ""


# ---------------------------------------------------------------------------
# schema 1 conversion
# ---------------------------------------------------------------------------


def _v1(lib, pid: str = "old") -> tuple[str, Profile]:
    profile = ident.generate_profile("de", profile_id=pid)
    profile.token, profile.seed = TOKEN, SEED
    profile.retired_tokens = ["ab12cd34"]
    profile.revision = 7
    profile.calls[0]["date"] = profile.created  # a TOML datetime in a list
    profile.values["gaid"].extra["future_key"] = 7
    data = profile.to_dict()
    data.pop("owner", None)
    text = ident.tomli_w.dumps(data)
    (lib / f"{pid}.toml").write_text(text, encoding="utf-8")
    return text, Profile.loads(text)


def test_v1_profiles_are_converted_once_with_the_same_fingerprint(svc, lib):
    text, v1 = _v1(lib)
    assert v1.schema == ident.SCHEMA_V1
    assert [p.id for p in svc.list_profiles()] == ["old"]
    yaml_path, bak = lib / "old.yaml", lib / "old.toml.bak"
    assert yaml_path.exists()
    assert bak.exists()
    assert not (lib / "old.toml").exists()
    assert bak.read_text(encoding="utf-8") == text
    converted = svc.load("old")
    assert ident.fingerprint(converted) == ident.fingerprint(v1)
    assert ident.markers_for(converted, {}) == ident.markers_for(v1, {})
    assert converted.to_dict() == v1.to_dict()
    yaml_text = yaml_path.read_text(encoding="utf-8")
    created = ident._raw_toml_scalar(text, "created")
    assert created
    assert f"created: {created}\n" in yaml_text
    assert f"token: '{TOKEN}'" in yaml_text or f"token: {TOKEN}" in yaml_text
    assert f"seed: {SEED}\n" in yaml_text
    assert "revision: 7\n" in yaml_text
    assert "retired_tokens: [ab12cd34]" in yaml_text
    assert converted.owner == {
        "first": "Mara",
        "last": "Kessler",
        "phone": ident.render_owner(converted)["phone"],
        "email": "mara.kessler.{token}@example.org",
    }
    assert ident.render_owner(converted)["phone"] == "+49" + ident.render_value(
        converted, converted.values["phone_number"]
    )
    assert not _errors(converted)
    # idempotent
    assert ident._migrate_library() == []
    svc.list_profiles()
    assert yaml_path.read_text(encoding="utf-8") == yaml_text
    # a save after the conversion keeps the fingerprint and the header
    svc.save(converted)
    assert ident.fingerprint(svc.load("old")) == ident.fingerprint(v1)
    assert "converted from a schema 1 TOML" in yaml_path.read_text("utf-8")


def test_yaml_wins_when_both_files_exist(svc, lib):
    _hand_written(lib)
    _v1(lib, "mara")
    assert svc.load("mara").name == "Mara Schneider (DE)"
    assert (lib / "mara.toml").exists()  # left alone
    assert not (lib / "mara.toml.bak").exists()
    assert [p.id for p in svc.list_profiles()] == ["mara"]
    svc.delete("mara")
    assert not (lib / "mara.toml").exists()  # would come back otherwise
    assert svc.list_profiles() == []


def test_a_broken_toml_stays_and_is_listed_with_its_error(svc, lib):
    (lib / "bad.toml").write_text("format = 'sandroid-identity'\n[", "utf-8")
    infos = svc.list_profiles()
    assert [(i.id, bool(i.error)) for i in infos] == [("bad", True)]
    assert (lib / "bad.toml").exists()


def test_import_accepts_v1_toml_and_v2_yaml_and_export_writes_yaml(svc, lib, tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    profile = ident.generate_profile("de", profile_id="imp")
    profile.token, profile.seed = TOKEN, SEED
    data = profile.to_dict()
    (src / "imp.toml").write_text(ident.tomli_w.dumps(data), encoding="utf-8")
    assert svc.import_profile(src / "imp.toml") == ("imp", "imported")
    imported = svc.load("imp")
    assert ident.fingerprint(imported) == ident.fingerprint(Profile.from_dict(data))
    assert svc.import_profile(src / "imp.toml") == ("imp", "identical")
    out = tmp_path / "out"
    out.mkdir()
    exported = svc.export_profile("imp", out)
    assert exported == out / "imp.yaml"
    assert exported.read_bytes() == (lib / "imp.yaml").read_bytes()
    # a YAML with world.seed auto and comments: verbatim, then the seed
    hand = src / "mara.yaml"
    hand.write_text(HAND_WRITTEN.format(seed="11" * 32), encoding="utf-8")
    assert svc.import_profile(hand) == ("mara", "imported")
    text = (lib / "mara.yaml").read_text(encoding="utf-8")
    assert "# Mara's test persona (hand written)" in text
    assert "seed: auto" not in text
    assert svc.import_profile(hand) == ("mara", "identical")  # auto vs resolved
    other = src / "other.yaml"
    other.write_text(hand.read_text("utf-8").replace('notes: ""', "notes: x"), "utf-8")
    assert svc.import_profile(other) == ("mara-2", "renamed")
    renamed = (lib / "mara-2.yaml").read_text(encoding="utf-8")
    assert "id: mara-2" in renamed
    assert "# Mitte" in renamed
    broken = src / "broken.yaml"
    broken.write_text(
        HAND_WRITTEN.format(seed="11" * 32).replace("builtin:de", "nowhere"), "utf-8"
    )
    with pytest.raises(ProfileError, match="nowhere"):
        svc.import_profile(broken)
