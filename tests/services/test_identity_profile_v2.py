"""Identity profile schema 2 (YAML): comments kept on save, ``extends``
overlays, built-in profiles, the owner, the ``world:`` pass-through and the
one-time conversion of schema 1 TOML profiles. No device.
"""

from __future__ import annotations

import sys

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
        "extends_digest",
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
    text = (
        HAND_WRITTEN.format(seed="11" * 32)
        .replace("seed: auto", f"seed: {pinned}")
        .replace("extends: builtin:de\n", "")  # standalone: no digest to add
    )
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


def test_a_default_over_a_parents_setting_is_written(svc, lib):
    _hand_written(lib)
    profile = svc.load("mara")
    assert not profile.values["build_model"].enabled  # off in builtin:de
    profile.values["build_model"].enabled = True
    svc.save(profile)
    assert svc.load("mara").values["build_model"].enabled
    own = store.plain(store.load_yaml((lib / "mara.yaml").read_text("utf-8")))
    assert own["values"]["build_model"] == {"enabled": True}
    profile = svc.load("mara")
    profile.values["build_model"].enabled = False
    svc.save(profile)
    assert not svc.load("mara").values["build_model"].enabled
    profile = svc.load("mara")
    profile.values["build_model"].enabled = True  # the key is in the file now
    svc.save(profile)
    assert svc.load("mara").values["build_model"].enabled


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
    with pytest.raises(ProfileError, match="loop: a extends b extends a") as err:
        svc.load("a")
    assert "->" not in str(err.value)
    _write(lib, "self", head + "id: self\nextends: self\n")
    with pytest.raises(ProfileError, match="loop"):
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
    assert "loop" in listed["a"]
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


def test_create_writes_a_standalone_copy_of_the_builtin(svc, lib, monkeypatch):
    first = svc.create("de")
    second = svc.create("de")
    assert (first.id, second.id) == ("mara-de", "mara-de-2")
    text = (lib / "mara-de.yaml").read_text("utf-8")
    from sandroid._version import __version__

    assert text.startswith(f"# Created from builtin:de (Sandroid {__version__}).\n")
    own = store.plain(store.load_yaml(text))
    assert "extends" not in own
    assert set(own["values"]) == set(store.load_builtin("de")["values"])
    assert own["lists"] == store.load_builtin("de")["lists"]
    assert own["owner"] == store.load_builtin("de")["owner"]
    assert store.WORLD_SEED_RE.fullmatch(own["world"]["seed"])
    assert own["world"]["country"] == "de"
    loaded = svc.load(first.id)
    assert not _errors(loaded)
    assert first.token != second.token
    assert first.world["seed"] != second.world["seed"]
    assert first.values["gps"].value != second.values["gps"].value
    assert ident.fingerprint(first) != ident.fingerprint(second)
    assert [b for b, _ in svc.builtins()] == store.builtin_ids()
    # a later Sandroid with another built-in never changes the copy
    before = ident.fingerprint(loaded)
    changed = store.load_builtin("de")
    changed["values"]["imei"] = {"template": "99999999{digits:6}{luhn}"}
    changed["values"]["clipboard"] = {"template": "Anders {token}"}
    monkeypatch.setattr(store, "load_builtin", lambda bid: changed)
    assert ident.fingerprint(svc.load(first.id)) == before


def test_no_pack_builtins_promise_no_world_seed():
    for bid in store.builtin_ids():
        raw = store.load_builtin(bid)
        text = (store._builtin_dir() / f"{bid}.yaml").read_text("utf-8")
        header = text.split("format:")[0]
        assert ("world seed" in header) == ("world" in raw), bid


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
}


def test_a_good_world_has_no_issues():
    assert store.world_issues(GOOD_WORLD) == []
    assert store.world_issues({"seed": "hex:" + "a" * 32}) == []
    assert store.world_issues({}) == []
    assert store.world_shape_issues({**GOOD_WORLD, "emails": "reserved"}) == []


def test_world_problems_come_from_the_world_module_as_warnings():
    from sandroid.world import WorldSpec

    def says(world: dict) -> str:
        try:
            WorldSpec.from_dict(world)
        except ValueError as exc:
            return str(exc)
        return ""

    for world in (
        {**GOOD_WORLD, "size": "huge"},
        {**GOOD_WORLD, "emails": "bogus"},  # not a known e-mail level
        {**GOOD_WORLD, "device": {"make": "Google", "model": "Pixel 8"}},
        {**GOOD_WORLD, "places": {"home": {"town": "Berlin"}}},
    ):
        message = says(world)
        assert message
        assert store.world_issues(world) == [("error", "world", message)]
        profile = _owned()
        profile.world = world
        assert ("warning", "world", message) in {
            (i.severity, i.path, i.message) for i in ident.validate(profile)
        }
        assert not _errors(profile)  # never blocks the identity apply
    # null country and open SDK bounds are what the world module allows
    text = (
        "format: sandroid-identity\nschema: 2\nid: w\nworld:\n  seed: auto\n"
        "  country: null\n  device: {make: Google, model: Pixel 8, codename: "
        "shiba, min_sdk: null, max_sdk: null}\n"
    )
    world = Profile.loads(text).world
    assert world == {
        "seed": "auto",
        "device": {"make": "Google", "model": "Pixel 8", "codename": "shiba"},
    }
    assert says(world) == ""
    assert store.world_issues(world) == []
    raw = {
        "seed": "auto",
        "country": None,
        "device": {**world["device"], "min_sdk": None},
    }
    assert says(raw) == ""
    assert store.world_issues(raw) == []


def test_without_the_world_module_the_shape_check_is_used(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "sandroid.world", None)
    assert ("error", "world.size") in {
        (s, p) for s, p, _m in store.world_issues({**GOOD_WORLD, "size": "huge"})
    }
    profile = _owned()
    profile.world = {**GOOD_WORLD, "size": "huge"}
    assert "world.size" in _paths(profile, "warning")
    assert not _errors(profile)


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
    issues = store.world_shape_issues({**GOOD_WORLD, **patch})
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
    assert "world" in _paths(profile, "warning")
    assert not _errors(profile)
    profile.world["size"] = "huge"
    assert "world" in _paths(profile, "warning")
    assert not _errors(profile)
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


# ---------------------------------------------------------------------------
# removals over a parent (null tombstones)
# ---------------------------------------------------------------------------


def test_removals_over_a_parent_survive_save_and_reload(svc, lib):
    _hand_written(lib)
    profile = svc.load("mara")
    assert profile.contacts  # inherited from builtin:de
    assert "clipboard" in profile.values
    profile.contacts = []
    del profile.values["clipboard"]
    profile.owner = {}
    profile.world = {}
    svc.save(profile)
    own = store.plain(store.load_yaml((lib / "mara.yaml").read_text("utf-8")))
    assert own["lists"] == {"contacts": []}
    assert own["values"]["clipboard"] is None
    assert own["owner"] is None
    assert own["world"] is None  # no new seed drawn for a removed world
    again = svc.load("mara")
    assert again.contacts == []
    assert again.sms  # still inherited
    assert "clipboard" not in again.values
    assert again.owner == {}
    assert again.world == {}
    assert ident.fingerprint(again) == ident.fingerprint(profile)
    assert "owner" in _paths(again, "warning")
    # undoing a removal writes the value again
    again.values["clipboard"] = ident.ValueSpec("clipboard", template="Hi {token}")
    again.owner = {"first": "Mara", "last": "Schneider"}
    svc.save(again)
    back = svc.load("mara")
    assert back.values["clipboard"].template == "Hi {token}"
    assert back.owner == {"first": "Mara", "last": "Schneider"}


def test_an_emptied_list_is_always_written(svc, lib):
    profile = ident.generate_profile("de", profile_id="solo")
    svc.save(profile)
    profile = svc.load("solo")
    profile.sms = []
    profile.calls = []
    svc.save(profile)
    own = store.plain(store.load_yaml((lib / "solo.yaml").read_text("utf-8")))
    assert own["lists"]["sms"] == []
    assert own["lists"]["calls"] == []
    assert svc.load("solo").sms == []


def test_merge_null_removes_a_key():
    base = {"owner": {"first": "A", "phone": "+491"}, "values": {"x": {"value": "1"}}}
    child = {"owner": {"phone": None}, "values": {"x": None}, "world": None}
    assert store.merge(base, child) == {"owner": {"first": "A"}, "values": {}}
    assert store.merge({}, {"owner": {"phone": None, "first": "B"}}) == {
        "owner": {"first": "B"}
    }


# ---------------------------------------------------------------------------
# lists edited in place
# ---------------------------------------------------------------------------

LISTED = """\
format: sandroid-identity
schema: 2
id: listed
token: "3f9a1c07"
seed: hex:{seed}
revision: 1
retired_tokens: []
lists:
  contacts:
    - name: "Jonas Weber {{token}}"   # the neighbour
      phone: "+4915100000001"
    - name: "Lena Hoffmann {{token}}"   # a colleague
      phone: "+4915100000002"
  # the inbox below
  sms:
    - address: "+4915100000001"
      body: "Hallo {{token}} bis morgen"
notes: ""
"""


def test_editing_one_list_item_keeps_comments_and_block_style(svc, lib):
    _write(lib, "listed", LISTED.format(seed="11" * 32))
    profile = svc.load("listed")
    profile.contacts[1]["name"] = "Lena Brandt {token}"
    svc.save(profile)
    text = (lib / "listed.yaml").read_text("utf-8")
    assert '- name: "Jonas Weber {token}"   # the neighbour\n' in text
    assert "Lena Brandt {token}" in text
    assert "# a colleague" in text
    assert "  # the inbox below\n  sms:\n" in text
    assert '      phone: "+4915100000002"\n' in text  # still block style
    assert "{name:" not in text
    # append and remove items, in place
    profile = svc.load("listed")
    profile.contacts.append({"name": "Tobias {token}", "phone": "+4915100000003"})
    svc.save(profile)
    text = (lib / "listed.yaml").read_text("utf-8")
    assert "# the neighbour" in text
    assert "{name:" not in text  # the new item follows its siblings' style
    profile = svc.load("listed")
    del profile.contacts[0]
    svc.save(profile)
    back = svc.load("listed")
    assert [c["phone"] for c in back.contacts] == ["+4915100000002", "+4915100000003"]
    assert "# the inbox below" in (lib / "listed.yaml").read_text("utf-8")


def test_regenerate_patches_retired_tokens_in_place(svc, lib):
    text = LISTED.format(seed="11" * 32).replace(
        "retired_tokens: []", "retired_tokens:   # old ones\n  - ab12cd34"
    )
    _write(lib, "listed", text)
    svc.regenerate("listed")
    out = (lib / "listed.yaml").read_text("utf-8")
    assert "retired_tokens:   # old ones\n  - ab12cd34\n  - 3f9a1c07\n" in out


# ---------------------------------------------------------------------------
# migration robustness
# ---------------------------------------------------------------------------


def test_one_bad_toml_never_stops_the_listing(svc, lib, monkeypatch):
    _v1(lib, "good")
    _v1(lib, "boom")
    real = ident.migrate_v1_text

    def flaky(text: str) -> str:
        if "boom" in text:
            raise RuntimeError("disk on fire")
        return real(text)

    monkeypatch.setattr(ident, "migrate_v1_text", flaky)
    infos = {i.id: i for i in svc.list_profiles()}
    assert infos["good"].error == ""
    assert infos["good"].path.suffix == ".yaml"
    assert infos["boom"].error == ""  # still usable (the "Use" picker)
    assert "disk on fire" in infos["boom"].notice
    assert (lib / "boom.toml").exists()
    assert svc.load("boom").token == TOKEN  # read as it is


def test_two_processes_converting_at_once(lib):
    _v1(lib, "old")
    toml, target = lib / "old.toml", lib / "old.yaml"
    a = ident._convert_step(toml)
    b = ident._convert_step(toml)
    assert ident._publish_yaml(target, a)
    assert not ident._publish_yaml(target, "# other\n" + b)  # never overwritten
    assert target.read_text("utf-8") == a
    assert ident._retire_toml(toml) == lib / "old.toml.bak"
    assert ident._retire_toml(toml) is None  # the TOML is gone: done already
    assert ident._convert_step(toml) is None
    assert not ident._migrate_one(toml)
    assert sorted(p.name for p in lib.iterdir()) == ["old.toml.bak", "old.yaml"]


def test_an_existing_backup_is_never_overwritten(svc, lib):
    (lib / "old.toml.bak").write_text("first backup", "utf-8")
    (lib / "old.toml.bak.1").write_text("second backup", "utf-8")
    text, _p = _v1(lib, "old")
    svc.list_profiles()
    assert (lib / "old.toml.bak").read_text("utf-8") == "first backup"
    assert (lib / "old.toml.bak.1").read_text("utf-8") == "second backup"
    assert (lib / "old.toml.bak.2").read_text("utf-8") == text


@pytest.mark.skipif(
    not hasattr(ident.os, "geteuid") or ident.os.geteuid() == 0,
    reason="root ignores folder permissions",
)
def test_a_read_only_library_is_read_without_converting(svc, lib):
    _text, v1 = _v1(lib, "old")
    lib.chmod(0o555)
    try:
        infos = svc.list_profiles()
        assert [(i.id, i.error, i.path.name) for i in infos] == [
            ("old", "", "old.toml")
        ]
        assert "read-only" in infos[0].notice
        loaded = svc.load("old")
        assert ident.fingerprint(loaded) == ident.fingerprint(v1)
        assert sorted(p.name for p in lib.iterdir()) == ["old.toml"]
    finally:
        lib.chmod(0o755)


def test_rename_removes_a_leftover_toml(svc, lib):
    _hand_written(lib)
    _v1(lib, "mara")
    toml = (lib / "mara.toml").read_text("utf-8")
    (lib / "mara.toml.bak").write_text("an older backup", "utf-8")
    svc.rename("mara", "Mara", new_id="mara2")
    assert not (lib / "mara.toml").exists()
    assert (lib / "mara.toml.bak").read_text("utf-8") == "an older backup"
    assert (lib / "mara.toml.bak.1").read_text("utf-8") == toml  # not lost
    assert [p.id for p in svc.list_profiles()] == ["mara2"]


def test_save_and_parent_lookup_do_not_scan_the_library(svc, lib, monkeypatch):
    _hand_written(lib)
    head = "format: sandroid-identity\nschema: 2\n"
    _write(lib, "child", head + "id: child\nextends: mara\n")
    _v1(lib, "v1parent")
    _write(lib, "kid", head + "id: kid\nextends: v1parent\n")

    def no(*_a, **_k):
        raise AssertionError("the library was scanned")

    monkeypatch.setattr(ident, "_migrate_library", no)
    profile = svc.load("child")
    profile.notes = "x"
    svc.save(profile)
    kid = svc.load("kid")  # a parent still in TOML is read as it is
    assert kid.token == ""
    assert kid.values["gps"].value
    assert (lib / "v1parent.toml").exists()


# ---------------------------------------------------------------------------
# world seed race
# ---------------------------------------------------------------------------


def test_a_seed_resolved_elsewhere_is_kept(svc, lib):
    _hand_written(lib)
    stale = svc.load("mara")  # still says auto
    assert stale.world["seed"] == "auto"
    seed = IdentityService().resolve_world_seed("mara")  # another instance
    stale.notes = "edited"
    svc.save(stale)
    assert stale.world["seed"] == seed
    assert svc.load("mara").world["seed"] == seed
    assert IdentityService().resolve_world_seed("mara") == seed


# ---------------------------------------------------------------------------
# extends: parent digest, children, export
# ---------------------------------------------------------------------------

CHILD = (
    "format: sandroid-identity\nschema: 2\nid: child\nextends: mara\n"
    'token: "ab12cd34"\nseed: hex:' + "22" * 32 + "\n"
)


def test_a_changed_parent_is_noticed(svc, lib):
    from sandroid.tui.widgets.identity_lens import IdentityLens

    _hand_written(lib)
    _write(lib, "child", CHILD)
    child = svc.load("child")
    assert not child.parent_changed  # no digest yet
    svc.save(child)
    own = store.plain(store.load_yaml((lib / "child.yaml").read_text("utf-8")))
    assert own["extends_digest"] == store.base_digest(child._base)
    assert not svc.load("child").parent_changed
    parent = svc.load("mara")
    parent.values["gps"].value = "52.500001, 13.400001"
    svc.save(parent)
    child = svc.load("child")
    assert child.parent_changed
    lens = IdentityLens()
    lens.profile = child
    notice = lens.notice_text() or ""
    assert "The profile it extends (mara) changed since the last save" in notice
    assert " · " not in notice
    svc.save(child)
    assert not svc.load("child").parent_changed


def test_lens_notice_names_a_world_problem(svc, lib):
    from sandroid.tui.widgets.identity_lens import IdentityLens

    profile = _owned()
    profile.world = {"seed": "auto", "size": "huge"}
    lens = IdentityLens()
    lens.profile = profile
    notice = lens.notice_text() or ""
    assert notice.startswith(
        "World section: world size must be one of small, medium or large"
    )
    assert "not affected" in notice


def test_rename_and_delete_refuse_while_children_extend(svc, lib):
    _hand_written(lib)
    _write(lib, "child", CHILD)
    _write(lib, "other", CHILD.replace("id: child", "id: other"))
    with pytest.raises(ProfileError, match="child, other extend it"):
        svc.delete("mara")
    with pytest.raises(ProfileError, match="cannot rename 'mara'"):
        svc.rename("mara", "Mara", new_id="mara2")
    assert (lib / "mara.yaml").exists()
    svc.rename("mara", "Only the name")  # the id stays: fine
    svc.delete("other")
    with pytest.raises(ProfileError, match="child extends it"):
        svc.delete("mara")
    svc.delete("child")
    svc.delete("mara")
    assert svc.list_profiles() == []


def test_export_writes_a_standalone_resolved_profile(svc, lib, tmp_path, monkeypatch):
    _hand_written(lib)
    _write(lib, "child", CHILD)
    child = svc.load("child")
    out = tmp_path / "out"
    out.mkdir()
    exported = svc.export_profile("child", out)
    text = exported.read_text("utf-8")
    assert "from the profile child extends mara extends builtin:de" in text
    own = store.plain(store.load_yaml(text))
    assert "extends" not in own
    assert "extends_digest" not in own
    monkeypatch.setenv(ident.PROFILES_DIR_ENV, str(tmp_path / "elsewhere"))
    fresh = IdentityService()
    assert fresh.import_profile(exported) == ("child", "imported")
    assert ident.fingerprint(fresh.load("child")) == ident.fingerprint(child)


# ---------------------------------------------------------------------------
# nits: aliases, alias bombs, key placement, parent schema
# ---------------------------------------------------------------------------


def test_saving_into_an_aliased_node_leaves_the_alias_alone(svc, lib):
    text = (
        HAND_WRITTEN.format(seed="11" * 32)
        .replace("owner:\n", "owner: &me\n")
        .replace('notes: ""\n', 'notes: ""\nx-owner-at-start: *me\n')
    )
    _write(lib, "mara", text)
    profile = svc.load("mara")
    assert profile.extra["x-owner-at-start"]["first"] == "Mara"
    profile.owner["first"] = "Lena"
    svc.save(profile)
    back = svc.load("mara")
    assert back.owner["first"] == "Lena"
    assert back.extra["x-owner-at-start"]["first"] == "Mara"


def test_an_alias_bomb_is_refused(svc, lib):
    rows = ['a: &a ["x","x","x","x","x","x","x","x","x","x"]']
    for n in range(1, 9):
        prev, cur = chr(ord("a") + n - 1), chr(ord("a") + n)
        rows.append(f"{cur}: &{cur} [{', '.join(['*' + prev] * 10)}]")
    head = "format: sandroid-identity\nschema: 2\nid: bomb\n"
    _write(lib, "bomb", head + "\n".join(rows) + "\n")
    with pytest.raises(ProfileError, match="nodes"):
        svc.load("bomb")
    assert [(i.id, "nodes" in i.error) for i in svc.list_profiles()] == [("bomb", True)]
    # an alias inside its own anchor: ruamel reads it as null, no endless loop
    looped = Profile.loads(
        "format: sandroid-identity\nschema: 2\nid: l\nx: &x [1, *x]\n"
    )
    assert looped.extra["x"] == [1, None]
    with pytest.raises(ProfileError, match="larger"):
        store.load_yaml("x: " + "y" * (store.MAX_FILE_CHARS + 1))


def test_a_new_created_goes_right_after_revision(svc, lib):
    text = HAND_WRITTEN.format(seed="11" * 32)
    _write(lib, "mara", text.replace("created: 2026-11-19T10:00:00+01:00\n", ""))
    svc.save(svc.load("mara"))
    keys = [
        line.split(":")[0]
        for line in (lib / "mara.yaml").read_text("utf-8").splitlines()
        if line[:1].isalpha()
    ]
    assert keys[keys.index("revision") + 1] == "created"


@pytest.mark.parametrize(
    ("parent", "error"),
    [
        ("format: other\nschema: 2\nid: p\n", "not a sandroid-identity file"),
        ("format: sandroid-identity\nschema: 3\nid: p\n", "newer"),
        ("format: sandroid-identity\nschema: one\nid: p\n", "invalid schema"),
    ],
)
def test_a_library_parent_is_checked(svc, lib, parent, error):
    _write(lib, "p", parent)
    _write(lib, "kid", "format: sandroid-identity\nschema: 2\nid: kid\nextends: p\n")
    with pytest.raises(ProfileError, match=error):
        svc.load("kid")


# ---------------------------------------------------------------------------
# round 3: list matching, lock timeout, unconverted TOML, plain words, seeds
# ---------------------------------------------------------------------------

THREE = LISTED.replace(
    """  # the inbox below""",
    """    - name: "Tobias Brandt {{token}}"   # the cousin
      phone: "+4915100000003"
  # the inbox below""",
)


def test_a_deleted_item_takes_its_comment_with_it(svc, lib):
    _write(lib, "listed", THREE.format(seed="11" * 32))
    profile = svc.load("listed")
    del profile.contacts[0]
    profile.contacts[0]["phone"] = "+4915100000009"  # Lena, edited too
    svc.save(profile)
    text = (lib / "listed.yaml").read_text("utf-8")
    assert "# the neighbour" not in text
    assert '- name: "Lena Hoffmann {token}"   # a colleague\n' in text
    assert '- name: "Tobias Brandt {token}"   # the cousin\n' in text
    assert '      phone: "+4915100000009"\n' in text
    assert "  # the inbox below\n  sms:\n" in text
    # a renamed item in the middle keeps its own comment (position fallback)
    profile = svc.load("listed")
    profile.contacts[1]["name"] = "Tobi Brandt {token}"
    profile.contacts.insert(0, {"name": "Neu {token}", "phone": "+4915100000004"})
    svc.save(profile)
    text = (lib / "listed.yaml").read_text("utf-8")
    assert "Tobi Brandt {token}" in text
    assert "# the cousin" in text.split("Tobi Brandt")[1].split("\n")[0]
    assert "# a colleague" in text.split("Lena Hoffmann")[1].split("\n")[0]
    assert [c["phone"] for c in svc.load("listed").contacts] == [
        "+4915100000004",
        "+4915100000009",
        "+4915100000003",
    ]


def test_items_are_matched_by_content_then_key_then_position():
    a, b, c = {"name": "A", "x": 1}, {"name": "B", "x": 2}, {"name": "C", "x": 3}
    assert store._match_items([a, b, c], [b, c]) == [1, 2]
    assert store._match_items([a, b, c], [{"name": "B", "x": 9}, c]) == [1, 2]
    assert store._match_items([a, b], [{"name": "Z", "x": 1}, b]) == [0, 1]
    assert store._match_items([a], [a, b]) == [0, None]
    assert store._match_items(["t1", "t2"], ["t2", "t3"]) == [1, 0]


@pytest.mark.skipif(sys.platform == "win32", reason="needs fcntl")
def test_a_library_locked_elsewhere_times_out_plainly(svc, lib, monkeypatch):
    import fcntl

    profile = svc.save(ident.generate_profile("de", profile_id="solo"))
    monkeypatch.setattr(ident, "LIBRARY_LOCK_TIMEOUT_S", 0.2)
    other = (lib / ".identity.lock").open("a")  # another process's handle
    fcntl.flock(other, fcntl.LOCK_EX)
    try:
        with pytest.raises(ProfileError, match="locked by another Sandroid process"):
            svc.save(profile)
    finally:
        other.close()
    assert svc.save(profile).revision == 2  # works again once it is free


def test_without_hard_links_conversion_still_works(svc, lib, monkeypatch):
    import errno

    _text, v1 = _v1(lib, "old")

    def no_links(*_a, **_k):
        raise OSError(errno.EPERM, "hard links not supported")

    monkeypatch.setattr(ident.os, "link", no_links)
    infos = svc.list_profiles()
    assert [(i.id, i.path.name, i.notice) for i in infos] == [("old", "old.yaml", "")]
    assert (lib / "old.toml.bak").exists()
    assert not (lib / "old.toml").exists()
    assert ident.fingerprint(svc.load("old")) == ident.fingerprint(v1)
    assert not ident._create_exclusive(lib / "old.yaml", "x")  # never overwrites


@pytest.mark.parametrize(
    ("message", "plain"),
    [
        (
            "world count 'sms' must be an integer >= 0",
            "world count sms must be an integer 0 or more",
        ),
        (
            "world mix share for 'de' must be > 0",
            "world mix share for de must be above 0",
        ),
        (
            "world numbers must be one of ('fiction', 'unallocated', 'realistic')",
            "world numbers must be one of fiction, unallocated or realistic",
        ),
        (
            "world seed must be 'auto' or 'hex:<hex>'",
            "the world module reports a problem with seed",
        ),
    ],
)
def test_world_messages_are_shown_in_plain_words(message, plain):
    from sandroid.tui.widgets.identity_lens import plain_world_message

    assert plain_world_message(message) == plain
    for symbol in "<>=|{}[]*":
        assert symbol not in plain_world_message(message)


def test_a_child_without_a_digest_records_it_on_the_next_save(svc, lib):
    _hand_written(lib)
    _write(lib, "child", CHILD)
    assert "extends_digest" not in (lib / "child.yaml").read_text("utf-8")
    child = svc.load("child")
    assert not child.parent_changed
    child.notes = "first save"
    svc.save(child)
    own = store.plain(store.load_yaml((lib / "child.yaml").read_text("utf-8")))
    assert own["extends_digest"] == store.base_digest(svc.load("child")._base)


def test_new_world_seed_really_replaces_it(svc, lib):
    _hand_written(lib)
    first = svc.resolve_world_seed("mara")
    profile = svc.load("mara")
    profile.world["seed"] = "auto"  # auto over a seed on disk keeps it
    svc.save(profile)
    assert svc.load("mara").world["seed"] == first
    second = svc.new_world_seed("mara")
    assert store.WORLD_SEED_RE.fullmatch(second)
    assert second != first
    text = (lib / "mara.yaml").read_text("utf-8")
    assert f"seed: {second}" in text
    assert "# resolved on the first save" in text
    svc.save(ident.generate_profile("de", profile_id="nw"))
    with pytest.raises(ProfileError, match="no world section"):
        svc.new_world_seed("nw")
