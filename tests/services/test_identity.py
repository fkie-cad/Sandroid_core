"""Identity profiles (``services/identity.py``): model, validation, markers,
library and the apply pipeline against a fake device (no adb, no emulator).
"""

from __future__ import annotations

import base64
import re
import shlex
import sys
import types
from pathlib import Path

import pytest

from sandroid.core import timeline
from sandroid.core.privacy_markers import Marker, build_needles
from sandroid.services import identity as ident
from sandroid.services.identity import (
    APPSET_FILE,
    GAID_FILE,
    PREFLIGHT_TAG,
    RESTART_MARKER,
    SSAID_FILE,
    ZYGOTE_PREFIX,
    IdentityService,
    Profile,
    ProfileError,
    ValueSpec,
)

SERIAL = "emulator-5580"
TOKEN = "3f9a1c07"  # noqa: S105 - a canary token, not a secret
OTHER = "ab12cd34"
CERT = "3082" + "ab" * 40  # a fake DER certificate (hex)
OTHER_CERT = "3082" + "cd" * 40


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Private profile library and session folder; identity mode on."""
    monkeypatch.setenv(ident.PROFILES_DIR_ENV, str(tmp_path / "profiles"))
    monkeypatch.setenv("SDROID_FILES_DIR", str(tmp_path / "session" / "files"))
    from sandroid.config import get_config

    cfg = get_config().identity
    monkeypatch.setattr(cfg, "mode", "off")
    monkeypatch.setattr(cfg, "profile", "")
    monkeypatch.setattr(cfg, "restart", "ask")
    return tmp_path


def _profile(**kw) -> Profile:
    """A deterministic, valid profile."""
    profile = ident.generate_profile("de")
    profile.token = TOKEN
    profile.seed = "hex:" + "11" * 32
    for key, value in kw.items():
        setattr(profile, key, value)
    assert not [i for i in ident.validate(profile) if i.severity == "error"]
    return profile


@pytest.fixture
def service(env, monkeypatch):
    svc = IdentityService()
    svc._sleep = lambda s: None
    svc.restarts_seen = []
    svc._after_restart = svc.restarts_seen.append
    profile = svc.save(_profile())
    from sandroid.config import get_config

    monkeypatch.setattr(get_config().identity, "mode", "profile")
    monkeypatch.setattr(get_config().identity, "profile", profile.id)
    return svc


# ---------------------------------------------------------------------------
# fake device
# ---------------------------------------------------------------------------

SSAID_XML = (
    "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
    '<settings version="-1">\n'
    '<setting id="0" name="userkey" value="ABCD" package="android" '
    'defaultValue="ABCD" defaultSysSet="true" tag="null" />\n'
    '<setting id="1" name="10123" value="1111222233334444" package="com.example.app"'
    ' defaultValue="1111222233334444" defaultSysSet="false" tag="null" />\n'
    "</settings>\n"
)
GAID_XML = (
    "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
    '    <string name="adid_key">00000000-1111-4222-8333-444444444444</string>\n'
    '    <int name="adid_reset_count" value="0" />\n</map>\n'
)


SYSTEM_LABEL = "u:object_r:system_data_file:s0"
APP_LABEL = "u:object_r:app_data_file:s0"


def _segments(line: str):
    """``(simple command, operator after it)`` of one shell line: split at
    ``&&``, ``||`` and ``;`` outside quotes and ``$(...)``.
    """
    seg, quote, depth, i = "", "", 0, 0
    while i < len(line):
        ch, two = line[i], line[i : i + 2]
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif two == "$(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth and two in ("&&", "||"):
            yield seg.strip(), two
            seg, i = "", i + 2
            continue
        elif not depth and ch == ";":
            yield seg.strip(), ";"
            seg, i = "", i + 1
            continue
        seg += ch
        i += 1
    if seg.strip():
        yield seg.strip(), None


def _expand(text: str, env: dict) -> str:
    """``$NAME`` / ``${NAME:-default}`` outside single quotes."""
    parts = re.split(r"('[^']*')", text)

    def sub(m: re.Match) -> str:
        if m.group(1):
            return env.get(m.group(1)) or m.group(2)
        return env.get(m.group(3), "")

    pattern = r"\$\{(\w+):-([^}]*)\}|\$(\w+)"
    return "".join(p if p.startswith("'") else re.sub(pattern, sub, p) for p in parts)


def _test(args: list[str]) -> bool:
    """``[ -n X ]``, ``[ X -gt Y ]`` (integers only, like the real one)."""
    if args[0] == "-n":
        return bool(args[1])
    left, op, right = args
    assert op == "-gt", args
    return left.isdigit() and right.isdigit() and int(left) > int(right)


class FakeDevice:
    """Answers the commands :mod:`identity` sends (monkeypatched ``_send``).

    ``content``/``abx2xml``/``xml2abx`` do nothing unless the script sources
    the zygote environment, like the real rooted image.
    """

    def __init__(self, n_packages: int = 0) -> None:
        self.calls: list[str] = []
        self.writes: list[str] = []
        self.running = True
        self.pid = 1000
        self.crash_when_stopped = False
        self.ignore: set[str] = set()
        self.props = {
            "ro.kernel.qemu": "1",
            "ro.build.version.sdk": "35",
            "ro.product.model": "sdk_gphone64_arm64",
            "persist.sys.locale": "en-US",
            "persist.sys.timezone": "America/Los_Angeles",
            "gsm.sim.operator.alpha": "T-Mobile",
            "gsm.sim.operator.numeric": "310260",
            "ro.boot.qemu.avd_name": "Dev1",
            "sys.boot_completed": "1",
        }
        self.settings = {"device_name": "sdk_gphone64", "auto_time_zone": "1"}
        self.fs: dict[str, bytes] = {
            SSAID_FILE: b"ABX\0" + SSAID_XML.encode(),
            GAID_FILE: GAID_XML.encode(),
            APPSET_FILE: b"\x0a\x249b1e2a40-0000-4000-8000-000000000001\x10",
        }
        #: owner / mode / SELinux label per file (``stat``, ``chown``, ``mv``).
        self.meta: dict[str, dict[str, str]] = {
            SSAID_FILE: {"owner": "1000:1000", "mode": "600", "label": SYSTEM_LABEL},
            GAID_FILE: {"owner": "10050:10050", "mode": "660", "label": APP_LABEL},
            APPSET_FILE: {"owner": "10050:10050", "mode": "600", "label": APP_LABEL},
        }
        #: Commands that fail (exit status 1, no effect).
        self.fail_cmds: set[str] = set()
        self.fail_raw_insert = False  # a raw_contacts insert silently does nothing
        self.sync_insert = False  # a sync adapter inserts a contact concurrently
        self.packages = {
            "com.example.app": (10123, CERT),
            "com.example.two": (10124, CERT),  # same signer, never launched
            "com.other.app": (10125, OTHER_CERT),
        }
        for i in range(n_packages):
            self.packages[f"com.bulk.p{i}"] = (11000 + i, CERT)
        self.contacts: list[dict] = []
        self.sms: list[dict] = []
        self.call_log: list[dict] = []
        self.next_id = 100
        self.emu_state: dict[str, str] = {}

    # -- transport --------------------------------------------------------

    def __call__(self, command: str, serial: str | None, timeout: float = 60):
        assert serial == SERIAL, "every call names the device"
        self.calls.append(command)
        if self.crash_when_stopped and not self.running:
            self.crash_when_stopped -= 1  # True: the next call only
            raise RuntimeError("adb connection lost")
        argv = shlex.split(command)
        if argv[0] == "push":
            self.writes.append(command)
            self.fs[argv[2]] = Path(argv[1]).read_bytes()
            return f"{argv[1]}: 1 file pushed", ""
        if argv[0] == "emu":
            self.writes.append(command)
            if argv[1] == "phonenumber":
                self.emu_state["phone"] = argv[2]
            elif argv[1:3] == ["geo", "fix"]:
                self.emu_state["geo"] = " ".join(argv[3:])
            return "OK\n", ""
        assert argv[0] == "shell"
        assert len(argv) == 2
        return self._shell(argv[1]), ""

    def _shell(self, script: str) -> str:
        if PREFLIGHT_TAG in script:
            return self._preflight(script)
        if script.startswith("pidof system_server"):
            return f"{self.pid}\npackage:/system/framework/framework-res.apk\n"
        zygote = script.startswith(ZYGOTE_PREFIX)
        if not (zygote and script.count("\n") == 1 and "abx2xml" in script):
            self.writes.append(script)
        out: list[str] = []
        env: dict[str, str] = {}
        for line in script.splitlines():
            if line.startswith("[ -r "):
                continue
            ok, op = True, None
            for seg, nxt in _segments(line):
                if op in (None, ";") or (op == "&&") == ok:
                    text, ok = self._segment(seg, env, zygote)
                    if text:
                        out.append(text)
                op = nxt
        return "\n".join(o for o in out if o)

    def _segment(self, seg: str, env: dict, zygote: bool) -> tuple[str, bool]:
        """One simple command: ``(output, exit ok)``."""
        assign = re.fullmatch(r"(\w+)=(.*)", seg, re.S)
        if assign:
            name, expr = assign.groups()
            if expr.startswith("$(") and expr.endswith(")"):
                env[name] = self._capture(expr[2:-1], env, zygote)
            else:
                env[name] = (shlex.split(_expand(expr, env)) or [""])[0]
            return "", True
        argv = shlex.split(_expand(seg, env))
        if argv[0] == "[":
            return "", _test(argv[1:-1])
        if argv[0] in self.fail_cmds:
            return "", False
        return self._run(argv, zygote), True

    def _capture(self, inner: str, env: dict, zygote: bool) -> str:
        """``$(cmd | sed ...)``: ``stat`` and ``content query`` + sed."""
        stages = [s.strip() for s in re.split(r"(?<!\|)\|(?!\|)", inner)]
        argv = shlex.split(_expand(stages[0], env))
        if argv[0] == "stat":
            meta = self.meta.get(argv[3]) if argv[3] in self.fs else None
            if meta is None:
                return ""
            return {"%u:%g": meta["owner"], "%a": meta["mode"], "%C": meta["label"]}[
                argv[2]
            ]
        assert argv[:2] == ["content", "query"], argv
        if not zygote:
            return ""
        assert argv[argv.index("--uri") + 1] == ident._RAW_CONTACTS
        ids = sorted(c["id"] for c in self.contacts)
        if "--where" in argv:
            floor = int(argv[argv.index("--where") + 1].split(">")[1])
            ids = [i for i in ids if i > floor]
        if "--sort" in argv and argv[argv.index("--sort") + 1] == "_id DESC":
            ids.reverse()
        for stage in stages[1:]:
            script = shlex.split(stage)[-1]
            assert stage.startswith("sed -n"), stage
            assert "_id=" in script, stage
            if script.startswith("1"):
                ids = ids[:1]
        return "\n".join(str(i) for i in ids)

    # -- commands -----------------------------------------------------------

    def _run(self, argv: list[str], zygote: bool) -> str:
        name = argv[0]
        if name == "echo":
            if ">" in argv:
                self.fs[argv[-1]] = " ".join(argv[1:-2]).encode()
                return ""
            return " ".join(argv[1:])
        if name == "cat" and ">" in argv:
            self.fs[argv[3]] = self.fs[argv[1]]
            self.meta[argv[3]] = {"owner": "0:0", "mode": "644", "label": "new"}
            return ""
        if name == "mv":
            src, dst = argv[-2:]
            self.fs[dst] = self.fs.pop(src)
            self.meta[dst] = self.meta.pop(src)
            return ""
        if name in ("chown", "chmod", "chcon"):
            key = {"chown": "owner", "chmod": "mode", "chcon": "label"}[name]
            self.meta[argv[2]][key] = argv[1]
            return ""
        if name == "rm":
            for path in argv[2:]:
                self.fs.pop(path, None)
            return ""
        if name in ("restorecon", "am"):
            return ""
        if name == "stop":
            self.running = False
            return ""
        if name == "start":
            self.running, self.pid = True, self.pid + 1
            return ""
        if name == "settings" and argv[1] == "put":
            if argv[3] not in self.ignore:
                self.settings[argv[3]] = argv[4]
            return ""
        if name == "cmd" and argv[1:3] == ["alarm", "set-timezone"]:
            self.props["persist.sys.timezone"] = argv[3]
            return ""
        if name in ("setprop", "resetprop"):
            self.props[argv[1]] = argv[2]
            return ""
        if not zygote:
            return ""  # app_process tools silently do nothing without the env
        if name == "xml2abx":
            self.fs[argv[2]] = b"ABX\0" + self.fs[argv[1]]
            return ""
        if name == "abx2xml":
            return self.fs[argv[1]].removeprefix(b"ABX\0").decode()
        if name == "content":
            return self._content(argv)
        raise AssertionError(f"unexpected command {argv}")

    def _content(self, argv: list[str]) -> str:
        op = argv[1]
        uri = argv[argv.index("--uri") + 1]
        binds = {}
        for i, tok in enumerate(argv):
            if tok == "--bind":
                key, _type, value = argv[i + 1].split(":", 2)
                binds[key] = value
        if op == "delete":
            rid = argv[argv.index("--where") + 1].split("=")[1]
            for table in (self.contacts, self.sms, self.call_log):
                table[:] = [r for r in table if str(r["id"]) != rid]
            return ""
        assert op == "insert"
        if uri.endswith("/raw_contacts"):
            if not self.fail_raw_insert:
                self.contacts.append({"id": self.next_id})
                self.next_id += 1
            if self.sync_insert:
                self.contacts.append({"id": self.next_id, "name": "Synced Person"})
                self.next_id += 1
        elif uri.endswith("/data"):
            row = next(
                c for c in self.contacts if str(c["id"]) == binds["raw_contact_id"]
            )
            field = {"name": "name", "phone_v2": "phone", "email_v2": "email"}[
                binds["mimetype"].rsplit("/", 1)[1]
            ]
            row[field] = binds["data1"]
        elif uri.startswith("content://sms"):
            self.sms.append({"id": self.next_id, **binds})
            self.next_id += 1
        else:
            self.call_log.append({"id": self.next_id, **binds})
            self.next_id += 1
        return ""

    def _preflight(self, script: str) -> str:
        assert ZYGOTE_PREFIX in script
        lines = [PREFLIGHT_TAG, "@@props@@"]
        lines += [f"{k}={v}" for k, v in self.props.items()]
        lines += ["@@root@@", "0", "@@resetprop@@", "/debug_ramdisk/resetprop"]
        lines += ["@@system_server@@", str(self.pid) if self.running else ""]
        lines += ["@@marker@@", self.fs.get(RESTART_MARKER, b"").decode()]
        lines += [
            "@@gms@@",
            "package:/system/priv-app/GmsCore.apk" if self.running else "",
        ]
        lines.append("@@settings@@")
        if self.running:
            lines += [f"{k}={v}" for k, v in self.settings.items()]
        lines += ["@@ssaid@@", self.fs[SSAID_FILE].removeprefix(b"ABX\0").decode()]
        lines += ["@@gaid_owner@@", "10050:10050"]
        lines += ["@@gaid@@", self.fs.get(GAID_FILE, b"").decode()]
        lines += [
            "@@appset@@",
            base64.b64encode(self.fs.get(APPSET_FILE, b"")).decode(),
        ]
        lines.append("@@location@@")
        lines.append("@@uids@@")
        lines += [f"package:{p} uid:{u}" for p, (u, _c) in self.packages.items()]
        for pkg, (_uid, cert) in self.packages.items():
            if f"@@pkg:{pkg}@@" in script:
                lines += [f"@@pkg:{pkg}@@", f'cert index="3" key="{cert}"']
        if "@@list:" in script:
            lines.append("@@list:contacts@@")
            n = 0
            for c in self.contacts:
                for field, mime in ident._CONTACT_MIME.items():
                    if c.get(field):
                        lines.append(
                            f"Row: {n} raw_contact_id={c['id']}, display_name="
                            f"{c.get('name', '')}, mimetype={mime}, data1={c[field]}"
                        )
                        n += 1
            lines.append("@@list:sms@@")
            for n, s in enumerate(self.sms):
                type_ = s.get("type")
                lines.append(
                    f"Row: {n} _id={s['id']}, address={s['address']}, "
                    f"body={s['body']}, type={type_}"
                )
            lines.append("@@list:calls@@")
            for n, c in enumerate(self.call_log):
                lines.append(
                    f"Row: {n} _id={c['id']}, number={c['number']}, name={c['name']}, "
                    f"type={c['type']}, duration={c['duration']}"
                )
        lines.append("@@end@@")
        return "\n".join(lines) + "\n"

    @property
    def ssaid(self) -> dict[str, str]:
        return {
            pkg: value
            for pkg, (_uid, value) in ident._parse_ssaid(
                self.fs[SSAID_FILE].removeprefix(b"ABX\0").decode()
            ).items()
        }


@pytest.fixture
def device(monkeypatch):
    fake = FakeDevice()
    monkeypatch.setattr(ident, "_send", fake)
    return fake


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------


def test_toml_round_trip_keeps_everything():
    profile = _profile(notes="note")
    profile.values["gaid"].extra["future_key"] = 7
    text = profile.dumps()
    back = Profile.loads(text)
    assert back.to_dict() == profile.to_dict()
    assert back.dumps() == text
    assert back.created == profile.created
    assert ident.fingerprint(back) == ident.fingerprint(profile)


def test_newer_schema_and_wrong_format_are_refused(env):
    data = _profile().to_dict()
    with pytest.raises(ProfileError, match="newer"):
        Profile.from_dict({**data, "schema": ident.SCHEMA + 1})
    with pytest.raises(ProfileError, match="format"):
        Profile.from_dict({**data, "format": "other"})
    path = env / "new.toml"
    path.write_text(Profile.loads(_profile().dumps()).dumps().replace(
        "schema = 1", "schema = 2"), encoding="utf-8")  # fmt: skip
    with pytest.raises(ProfileError, match="newer"):
        IdentityService().import_profile(path)


@pytest.mark.parametrize(
    ("kind", "value", "provider", "ok"),
    [
        ("android_id", "3f9a1c07deadbeef", "native", True),
        ("android_id", "3F9A1C07DEADBEEF", "native", False),
        ("android_id", "3f9a1c07dead", "native", False),
        ("gaid", "3f9a1c07-6c1e-4b7a-9f2d-08e5d1c4a9b3", "native", True),
        ("gaid", "00000000-0000-0000-0000-000000000000", "native", False),
        ("gaid", "3f9a1c076c1e4b7a9f2d08e5d1c4a9b3", "native", False),
        ("imei", "490154203237518", "hook", True),
        ("imei", "490154203237519", "hook", False),
        ("imei", "49015420323751", "hook", False),
        ("iccid", "8949" + "0" * 14 + ident.luhn_check_digit("8949" + "0" * 14), "hook", True),
        ("iccid", "8849" + "0" * 15, "hook", False),
        ("imsi", "262011234567890", "hook", True),
        ("imsi", "310261234567890", "hook", False),
        ("phone_number", "15201234567", "native", True),
        ("phone_number", "152012345678", "native", False),
        ("phone_number", "+4915201234567", "native", False),
        ("phone_number", "+4915201234567", "hook", True),
        ("gps", "52.520008, 13.404954", "native", True),
        ("gps", "91.000001, 13.404954", "native", False),
        ("gps", "52.520008, 181.000001", "native", False),
        ("gps", "52.520008", "native", False),
        ("timezone", "Europe/Berlin", "native", True),
        ("timezone", "Europe/Atlantis", "native", False),
        ("locale", "de-DE", "native", True),
        ("locale", "de_DE", "native", False),
        ("sim_mccmnc", "26201", "native", True),
        ("sim_mccmnc", "262", "native", False),
    ],
)  # fmt: skip
def test_value_validators(kind, value, provider, ok):
    errors = [m for sev, m in ident._check_value(kind, value, provider, "26201")
              if sev == "error"]  # fmt: skip
    assert (not errors) == ok, errors


def test_gps_with_few_decimals_is_only_a_warning():
    found = ident._check_value("gps", "52.52, 13.40", "native", "")
    assert found == [("warning", "fewer than 6 decimals: weak marker")]


def test_luhn_digit_matches_a_known_imei():
    assert ident.luhn_check_digit("49015420323751") == "8"
    assert ident.luhn_ok("490154203237518")


def test_template_rendering_is_deterministic_and_luhn_valid():
    seed = bytes(32)
    one = ident.render_template("35847631{digits:6}{luhn}", token=TOKEN,
                                seed=seed, key="imei")  # fmt: skip
    two = ident.render_template("35847631{digits:6}{luhn}", token=TOKEN,
                                seed=seed, key="imei")  # fmt: skip
    assert one == two
    assert len(one) == 15
    assert ident.luhn_ok(one)
    other = ident.render_template("35847631{digits:6}{luhn}", token=TOKEN,
                                  seed=seed, key="imei2")  # fmt: skip
    assert other != one
    assert ident.render_template("{{x}} {token}", token=OTHER, seed=seed,
                                 key="k") == "{x} " + OTHER  # fmt: skip
    for bad in ("{nope}", "a { b", "{digits:99}"):
        with pytest.raises(ident.TemplateError):
            ident.render_template(bad, token=OTHER, seed=seed, key="k")


def test_regenerate_replaces_token_and_seed_and_retires_the_old_token(env):
    svc = IdentityService()
    profile = _profile()
    profile.values["gaid"] = ValueSpec(
        "gaid", value="3f9a1c07-6c1e-4b7a-9f2d-08e5d1c4a9b3"
    )
    svc.save(profile)
    before = ident.render_lists(profile)
    again = svc.regenerate(profile.id)
    assert again.token != TOKEN
    assert again.seed != profile.seed
    assert again.retired_tokens == ["3f9a1c07"]
    assert again.revision == profile.revision + 1
    assert again.values["gaid"].value.startswith(again.token)
    after = ident.render_lists(again)
    assert after["contacts"][0]["name"] == before["contacts"][0]["name"].replace(
        "3f9a1c07", again.token
    )
    # Same token and seed -> same values (deterministic from the seed).
    assert ident.render_lists(Profile.loads(again.dumps())) == after


def test_ssaid_is_derived_per_signing_certificate():
    seed = bytes(range(32))
    a = ident.ssaid_for("3f9a1c07", seed, "sha256:aa")
    assert a == ident.ssaid_for("3f9a1c07", seed, "sha256:aa")
    assert a != ident.ssaid_for("3f9a1c07", seed, "sha256:bb")
    assert re.fullmatch(r"3f9a1c07[0-9a-f]{8}", a)
    vs = ValueSpec("android_id", derive="ssaid", scope="signer")
    profile = _profile()
    info = ident.PackageInfo("com.a", 10001, "sha256:aa")
    same_signer = ident.PackageInfo("com.b", 10002, "sha256:aa")
    assert IdentityService._ssaid_value(profile, vs, "com.a", info) == (
        IdentityService._ssaid_value(profile, vs, "com.b", same_signer)
    )
    vs.scope = "package"
    assert IdentityService._ssaid_value(profile, vs, "com.a", info) != (
        IdentityService._ssaid_value(profile, vs, "com.b", same_signer)
    )


def test_markers_must_be_distinct_and_not_contain_each_other():
    profile = _profile()
    profile.sms[0]["body"] = "Hi from Jonas Weber {token}"  # contains a contact name
    errors = [i for i in ident.validate(profile) if i.severity == "error"]
    assert any("substring" in i.message for i in errors), errors
    profile = _profile()
    profile.values["device_name"] = ValueSpec("device_name", template="Telekom {token}")
    errors = [i for i in ident.validate(profile) if i.severity == "error"]
    assert any("same value" in i.message for i in errors), errors


@pytest.mark.parametrize("duration", [-1, "12s", 1.5, True, 2**31, "\u0663"])
def test_validation_rejects_a_bad_call_duration(duration):
    profile = _profile()
    profile.calls[0]["duration"] = duration
    paths = [i.path for i in ident.validate(profile) if i.severity == "error"]
    assert paths == ["calls.0.duration"]


def test_validation_accepts_call_durations_in_seconds():
    profile = _profile()
    profile.calls[0]["duration"] = "17"
    profile.calls[1].pop("duration", None)
    assert not [i for i in ident.validate(profile) if i.severity == "error"]


def test_validators_reject_a_trailing_newline():
    bad = _profile()
    bad.token = TOKEN + "\n"
    assert [i.path for i in ident.validate(bad)] == ["token"]
    bad = _profile()
    bad.id = "mara-de\n"
    assert "id" in [i.path for i in ident.validate(bad)]
    for kind, value, provider in [
        ("gaid", "3f9a1c07-6c1e-4b7a-9f2d-08e5d1c4a9b3\n", "native"),
        ("phone_number", "+4915201234567\n", "hook"),
        ("phone_number", "1520123\u0664", "native"),
        ("locale", "de-DE\n", "native"),
        ("account", "a@b.de\n", "hook"),
        ("imei", "49015420323751\u0668", "hook"),
    ]:
        found = ident._check_value(kind, value, provider, "")
        assert [m for sev, m in found if sev == "error"], (kind, value)
    profile = _profile()
    profile.contacts[0]["phone"] = "+4917012345\n"
    profile.contacts[0]["email"] = "x.{token}@example.org\n"
    paths = {i.path for i in ident.validate(profile) if i.severity == "error"}
    assert {"contacts.0.phone", "contacts.0.email"} <= paths
    with pytest.raises(ProfileError):
        ident._profile_path("mara\n")
    assert TOKEN not in ident.preflight_script([], [TOKEN + "\n"])


def test_validation_flags_structure_errors():
    profile = _profile()
    profile.values["gaid"] = ValueSpec("gaid", value="x", derive="uuid")
    profile.values["imei"].provider = "native"
    profile.contacts[0]["name"] = "Jonas without token"
    paths = {i.path for i in ident.validate(profile) if i.severity == "error"}
    assert {"values.gaid", "values.imei", "contacts.0.name"} <= paths
    bad = _profile()
    bad.token = "XYZ"  # noqa: S105
    assert [i.path for i in ident.validate(bad)] == ["token"]


# ---------------------------------------------------------------------------
# library
# ---------------------------------------------------------------------------


def test_library_crud_and_import_never_overwrites(env):
    svc = IdentityService()
    created = svc.create("de")
    assert created.revision == 1
    assert [p.id for p in svc.list_profiles()] == [created.id]
    exported = svc.export_profile(created.id, env)
    assert exported.read_bytes() == ident.profiles_dir().joinpath(
        f"{created.id}.toml").read_bytes()  # fmt: skip
    # identical content -> no-op
    assert svc.import_profile(exported) == (created.id, "identical")
    # same id, other content -> <id>-2 (the original stays)
    changed = Profile.loads(exported.read_text(encoding="utf-8"))
    changed.notes = "edited elsewhere"
    other = env / "other.toml"
    other.write_text(changed.dumps(), encoding="utf-8")
    assert svc.import_profile(other) == (f"{created.id}-2", "renamed")
    assert svc.load(created.id).notes == ""
    assert svc.load(f"{created.id}-2").notes == "edited elsewhere"
    # a new id is written verbatim
    fresh = env / "fresh.toml"
    fresh.write_text(changed.dumps().replace(f'id = "{created.id}"', 'id = "fresh"'),
                     encoding="utf-8")  # fmt: skip
    assert svc.import_profile(fresh) == ("fresh", "imported")
    assert (ident.profiles_dir() / "fresh.toml").read_bytes() == fresh.read_bytes()
    dup = svc.duplicate("fresh")
    assert dup.id == "fresh-copy"
    assert dup.token != changed.token
    renamed = svc.rename("fresh-copy", "Copy", new_id="copy")
    assert renamed.id == "copy"
    assert not (ident.profiles_dir() / "fresh-copy.toml").exists()
    svc.delete("copy")
    assert "copy" not in {p.id for p in svc.list_profiles()}


def test_service_is_registered_and_reset(env):
    from sandroid import services

    first = services.get_identity_service()
    assert first is ident.get_identity_service()
    services.reset_services()
    assert services.get_identity_service() is not first


# ---------------------------------------------------------------------------
# apply pipeline (fake device)
# ---------------------------------------------------------------------------


def test_preflight_is_one_adb_call(service, device):
    plan = service.plan(SERIAL, "com.example.app")
    assert len(device.calls) == 1
    assert not device.writes
    assert plan.disruptive
    assert {"android_id", "gaid", "device_name", "contacts"} <= set(plan.todo)
    info = plan.infos["android_id"]
    assert info.per_app["com.example.app"]["before"] == "1111222233334444"


def test_apply_seeds_everything_and_second_apply_writes_nothing(service, device):
    with timeline.capture() as lines:
        plan = service.apply(SERIAL, "com.example.app")
    st = {k: (v.status, v.reason) for k, v in plan.infos.items()}
    for vid in (
        "android_id",
        "gaid",
        "app_set_id",
        "device_name",
        "timezone",
        "locale",
        "sim_operator",
        "sim_mccmnc",
        "contacts",
        "sms",
        "calls",
    ):
        assert st[vid] == ("verified", ""), (vid, st[vid])  # fmt: skip
    assert st["phone_number"] == ("applied", "")
    assert st["gps"] == ("applied", "unverified")  # no app ran a GPS session
    assert st["imei"][0] == "hook-only"
    assert st["build_model"] == ("skipped", "disabled")
    # device state
    profile = service.active_profile()
    android_id = device.ssaid["com.example.app"]
    assert android_id.startswith("3f9a1c07")
    assert device.fs[SSAID_FILE].startswith(b"ABX\0")  # re-encoded
    assert device.settings["device_name"] == "Maras Pixel 3f9a1c07"
    assert device.props["persist.sys.locale"] == "de-DE"
    assert device.emu_state["phone"].startswith("1520")
    lon, lat, _alt = device.emu_state["geo"].split()
    assert lat.endswith("0001")
    assert lon.endswith("0001")
    assert lon.startswith("13.")  # longitude first
    assert len(device.contacts) == 3
    assert all("3f9a1c07" in c["name"] for c in device.contacts)
    assert len(device.sms) == 2
    assert len(device.call_log) == 2
    assert b"3f9a1c07-" in device.fs[APPSET_FILE]
    assert RESTART_MARKER not in device.fs
    # timeline
    kinds = [(x["src"], x["kind"]) for x in lines]
    assert ("identity", "apply") in kinds
    assert ("identity", "restart") in kinds
    assert ("identity", "applied") in kinds
    restart = next(x for x in lines if x["kind"] == "restart")
    assert restart["level"] == "warn"
    applied = next(x for x in lines if x["kind"] == "applied")
    frozen = service_folder(applied)
    assert frozen.name.startswith("001-mara-de-r1")
    assert applied["ref"]["sha256"]
    record = ident.tomllib.loads(frozen.read_text(encoding="utf-8"))
    assert record["ssaid"]["com.example.app"]["value"] == android_id
    assert record["ssaid"]["com.example.app"]["before"] == "1111222233334444"
    assert record["values"]["phone_number"]["before"] == "15555215580"
    assert record["values"]["device_name"]["before"] == "sdk_gphone64"
    assert record["profile"]["token"] == profile.token
    # second apply: one read, no writes, no second freeze
    device.calls.clear()
    device.writes.clear()
    with timeline.capture() as lines2:
        again = service.apply(SERIAL, "com.example.app")
    assert device.writes == []
    assert len(device.calls) == 1
    assert not lines2
    assert again.infos["phone_number"].status == "applied"


def service_folder(applied_line: dict) -> Path:
    return timeline.timeline_folder() / applied_line["ref"]["path"]


def test_never_launched_app_of_the_same_signer_gets_a_preadded_row(service, device):
    service.apply(SERIAL, "com.example.app")
    service.apply(SERIAL, "com.example.two")
    ssaid = device.ssaid
    assert ssaid["com.example.two"] == ssaid["com.example.app"]  # same signer
    service.apply(SERIAL, "com.other.app")
    assert device.ssaid["com.other.app"] != ssaid["com.example.app"]
    assert device.pid == 1003  # one framework restart per new app


def test_frida_server_is_restarted_after_the_framework_window(service, device):
    service.apply(SERIAL, "com.example.app")
    assert service.restarts_seen == [SERIAL]
    service.apply(SERIAL, "com.example.app")  # nothing to do: no restart
    assert service.restarts_seen == [SERIAL]


def test_zygote_env_prefixes_content_and_abx_commands(service, device):
    service.apply(SERIAL, "com.example.app")
    for script in [c for c in device.calls if c.startswith("shell ")]:
        body = shlex.split(script)[1]
        for line in body.splitlines():
            if re.search(r"\b(content|abx2xml|xml2abx) ", line):
                before = body[: body.index(line)]
                assert ZYGOTE_PREFIX in before or ZYGOTE_PREFIX in line, line


def test_crash_after_stop_resumes(service, device):
    device.crash_when_stopped = 2  # the link stays down for the `start` too
    with pytest.raises(RuntimeError, match="adb connection lost"):
        service.apply(SERIAL, "com.example.app")
    assert not device.running
    assert RESTART_MARKER in device.fs
    with timeline.capture() as lines:
        plan = service.apply(SERIAL, "com.example.app")
    assert device.running
    assert RESTART_MARKER not in device.fs
    assert plan.infos["android_id"].status == "verified"
    assert device.ssaid["com.example.app"].startswith("3f9a1c07")
    recover = [x for x in lines if x["kind"] == "restart"]
    assert recover[0]["data"]["recovery"] is True


def _cmds(device) -> list[list[str]]:
    """Every simple command sent, in order (``shell`` scripts split up)."""
    out = []
    for call in device.calls:
        argv = shlex.split(call)
        if argv[0] != "shell":
            continue
        for line in argv[1].splitlines():
            out += [shlex.split(seg) for seg, _op in _segments(line) if seg]
    return out


def test_an_error_in_the_restart_window_still_starts_the_framework(service, device):
    device.crash_when_stopped = True  # one dropped call, then adb is back
    with pytest.raises(RuntimeError, match="adb connection lost"):
        service.apply(SERIAL, "com.example.app")
    cmds = _cmds(device)
    assert cmds.index(["start"]) > cmds.index(["stop"])
    assert device.running
    assert RESTART_MARKER not in device.fs  # the framework is back
    assert device.ssaid["com.example.app"] == "1111222233334444"  # untouched
    st = {s.id: s for s in service.statuses()}
    assert st["android_id"].status == "failed"
    assert st["android_id"].reason.startswith("restart window aborted")


def test_a_host_error_while_writing_still_starts_the_framework(
    service, device, monkeypatch
):
    real_mkstemp = ident.tempfile.mkstemp

    def no_temp(*a, **k):
        if device.running:
            return real_mkstemp(*a, **k)
        raise OSError("disk full")  # only inside the restart window

    monkeypatch.setattr(ident.tempfile, "mkstemp", no_temp)
    with pytest.raises(OSError, match="disk full"):
        service.apply(SERIAL, "com.example.app")
    assert device.running
    assert ["start"] in _cmds(device)
    assert RESTART_MARKER not in device.fs


def test_malformed_ssaid_rows_do_not_break_the_edit(service, device):
    xml = SSAID_XML.replace('id="1"', 'id="x1"')
    device.fs[SSAID_FILE] = b"ABX\0" + xml.encode()
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["android_id"].status == "verified"
    assert ident._edit_ssaid(xml, {"com.new": {"uid": "1", "value": "ab"}})
    assert ident._edit_ssaid("<settings", {}) is None


def test_ssaid_file_with_namespace_hashes_is_edited(service, device):
    # Android 14+ (abx2xml): a second top-level element after </settings>.
    xml = SSAID_XML + "<namespaceHashes />"
    device.fs[SSAID_FILE] = b"ABX\0" + xml.encode()
    assert ident._parse_ssaid(xml)["com.example.app"][1] == "1111222233334444"
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["android_id"].status == "verified"
    written = device.fs[SSAID_FILE].removeprefix(b"ABX\0").decode()
    assert written.rstrip().endswith("</settings>\n<namespaceHashes />")
    edited = ident._edit_ssaid(xml, {"com.new": {"uid": "1", "value": "ab"}})
    assert edited is not None
    assert 'package="com.new"' in edited
    assert "<namespaceHashes />" in edited


def test_ssaid_write_goes_through_a_sibling_temp_file_and_mv(service, device):
    before = dict(device.meta[SSAID_FILE])
    service.apply(SERIAL, "com.example.app")
    script = next(w for w in device.writes if "xml2abx" in w)
    assert f"> {SSAID_FILE} " not in script  # never truncated in place
    tmp = re.search(rf"> ({re.escape(SSAID_FILE)}\.sandroid-[0-9a-f]+)", script)
    assert tmp
    assert f"mv -f {tmp.group(1)} {SSAID_FILE}" in script
    assert f'chcon "$L" {tmp.group(1)}' in script
    assert device.meta[SSAID_FILE] == before  # owner, mode, label copied
    assert not [p for p in device.fs if ".sandroid-" in p]


def test_a_failed_label_copy_leaves_the_ssaid_file_alone(service, device):
    original = device.fs[SSAID_FILE]
    device.fail_cmds.add("chcon")
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["android_id"].status == "failed"
    assert device.fs[SSAID_FILE] == original
    assert not [p for p in device.fs if ".sandroid-" in p]  # temp file removed
    assert device.running


@pytest.mark.parametrize("trouble", ["fail_raw_insert", "sync_insert"])
def test_contact_rows_never_attach_to_another_contact(service, device, trouble):
    real = {"id": 50, "name": "Real Person", "phone": "+4917000000"}
    device.contacts.append(dict(real))
    setattr(device, trouble, True)
    plan = service.apply(SERIAL, "com.example.app")
    info = plan.infos["contacts"]
    assert info.status == "failed"
    assert "contacts.0" in info.reason
    assert device.contacts[0] == real
    assert not [c for c in device.contacts if "email" in c]  # no data rows
    script = next(w for w in device.writes if "raw_contacts" in w)
    inserts = [ln for ln in script.splitlines() if "content insert" in ln]
    assert inserts
    assert all(" && " in ln and " || echo " in ln for ln in inserts)
    assert '[ "$NEW" -gt "$MAX" ]' in script


def test_contacts_are_seeded_when_others_exist(service, device):
    device.contacts.append({"id": 50, "name": "Real Person"})
    device.next_id = 51
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["contacts"].status == "verified"
    assert device.contacts[0] == {"id": 50, "name": "Real Person"}
    assert len(device.contacts) == 4


def test_statuses_name_their_profile_fingerprint_and_time(service, device):
    before = ident.time.time()
    plan = service.apply(SERIAL, "com.example.app")
    statuses = service.statuses()
    assert statuses
    for info in statuses:
        assert info.profile_id == plan.profile_id == "mara-de"
        assert info.fingerprint == plan.fingerprint
        assert info.at >= before
    assert plan.infos["gaid"].at == statuses[0].at


def test_no_restart_mode_leaves_framework_values_pending(service, device):
    plan = service.apply(SERIAL, "com.example.app", allow_restart=False)
    for vid in ("android_id", "locale"):
        assert plan.infos[vid].status == "pending"
        assert plan.infos[vid].reason == ident.NEEDS_RESTART
    assert plan.infos["gaid"].status == "verified"
    assert device.ssaid["com.example.app"] == "1111222233334444"
    assert device.pid == 1000
    assert not any(shlex.split(c)[1:] == ["stop"] for c in device.calls)
    device.writes.clear()
    service.apply(SERIAL, "com.example.app", allow_restart=False)
    assert device.writes == []


def test_read_back_mismatch_fails(service, device):
    device.ignore.add("device_name")  # the device silently refuses
    plan = service.apply(SERIAL, "com.example.app")
    info = plan.infos["device_name"]
    assert info.status == "failed"
    assert info.reason.startswith("read-back mismatch")


def test_regenerate_removes_rows_of_the_retired_token(service, device):
    service.apply(SERIAL, "com.example.app")
    old = service.active_profile().token
    new = service.regenerate(service.config().profile)
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["contacts"].status == "verified"
    names = [c["name"] for c in device.contacts]
    assert len(names) == 3
    assert all(new.token in n and old not in n for n in names)
    assert all(old not in s["body"] for s in device.sms)
    assert len(device.call_log) == 2


def test_frozen_timeline_data_stays_small_with_300_apps_and_50_contacts(
    service, monkeypatch
):
    fake = FakeDevice(n_packages=300)
    monkeypatch.setattr(ident, "_send", fake)
    profile = service.active_profile()
    profile.contacts = [
        {"name": f"Person {i} {{token}}", "phone": "+49170{digits:7}",
         "email": f"p{i}.{{token}}@example.org"}
        for i in range(50)
    ]  # fmt: skip
    service.save(profile)
    service.apply(SERIAL, "com.example.app")
    mem = service._applied[SERIAL]
    mem.ssaids.update({f"com.bulk.p{i}": "" for i in range(300)})
    with timeline.capture() as lines:
        plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["android_id"].status == "verified"
    applied = next(x for x in lines if x["kind"] == "applied")
    assert "_truncated" not in applied["data"]
    assert len(timeline.canonical(applied["data"])) < timeline.DATA_MAX
    record = ident.tomllib.loads(service_folder(applied).read_text(encoding="utf-8"))
    assert len(record["ssaid"]) == 301
    assert record["ssaid"]["com.bulk.p0"]["before"] == ""  # pre-added row
    assert len(record["lists"]["contacts"]) == 50


def test_missing_device_answer_fails_closed(service, monkeypatch):
    monkeypatch.setattr(ident, "_send", lambda *a, **k: ("", "device offline"))
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["gaid"].status == "failed"


# ---------------------------------------------------------------------------
# pre-spawn hook
# ---------------------------------------------------------------------------


@pytest.fixture
def app_start(monkeypatch):
    """A stand-in for ``sandroid.services.app_start`` (owned elsewhere)."""
    from dataclasses import dataclass

    module = types.ModuleType("sandroid.services.app_start")
    hooks: list = []

    @dataclass(frozen=True)
    class PreSpawnPlan:
        description: str
        disruptive: bool
        apply: object

    module.PreSpawnPlan = PreSpawnPlan
    module.register_pre_spawn_hook = hooks.append
    module.unregister_pre_spawn_hook = hooks.remove
    module.hooks = hooks
    monkeypatch.setitem(sys.modules, "sandroid.services.app_start", module)
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))
    return module


def test_pre_spawn_hook_is_idempotent(service, device, app_start):
    assert service.install_pre_spawn_hook()
    assert service.install_pre_spawn_hook()
    assert len(app_start.hooks) == 1
    hook = app_start.hooks[0]
    plan = hook("com.example.app")
    assert isinstance(plan, app_start.PreSpawnPlan)
    assert plan.disruptive
    assert "mara-de" in plan.description
    plan.apply()
    assert hook("com.example.app") is None  # no dialog on every start
    other = hook("com.other.app")
    assert other is not None
    service.uninstall_pre_spawn_hook()
    assert app_start.hooks == []


def test_pre_spawn_apply_raises_on_failure_and_is_off_without_mode(
    service, device, app_start, monkeypatch
):
    device.ignore.add("device_name")
    plan = service.pre_spawn("com.example.app")
    with pytest.raises(ident.IdentityApplyError, match="Device name"):
        plan.apply()
    assert service.pre_spawn("com.example.app") is not None
    monkeypatch.setattr(service.config(), "mode", "off")
    assert service.pre_spawn("com.example.app") is None


def test_restart_never_makes_the_plan_non_disruptive(service, device, app_start,
                                                     monkeypatch):  # fmt: skip
    monkeypatch.setattr(service.config(), "restart", "never")
    plan = service.pre_spawn("com.example.app")
    assert not plan.disruptive
    plan.apply()
    assert device.pid == 1000
    assert service.pre_spawn("com.example.app") is None


def test_install_hook_is_a_no_op_without_app_start(service, monkeypatch):
    monkeypatch.setitem(sys.modules, "sandroid.services.app_start", None)
    assert service.install_pre_spawn_hook() is False


# ---------------------------------------------------------------------------
# markers contract
# ---------------------------------------------------------------------------


def test_markers_contract(service, device, monkeypatch):
    seen: list = []
    service.add_markers_listener(lambda fp, markers: seen.append((fp, markers)))
    assert service.active_markers() is None  # nothing applied yet
    service.apply(SERIAL, "com.example.app")
    fp, markers = service.active_markers()
    assert seen[-1] == (fp, markers)
    assert all(isinstance(m, Marker) for m in markers)
    by_id = {m.id: m for m in markers}
    assert by_id["android_id"].value == device.ssaid["com.example.app"]
    assert by_id["android_id"].tag == "AndroidID"
    assert by_id["gaid"].kind == "uuid"
    assert by_id["gaid"].label == "Advertising ID"
    assert by_id["gaid"].tag == "AdID"
    lat, lon = by_id["gps.latitude"], by_id["gps.longitude"]
    assert (lat.kind, lon.kind, lat.group, lon.group) == (
        "latitude", "longitude", "gps", "gps")  # fmt: skip
    phone = by_id["phone_number"]
    assert phone.value.startswith("+491520")
    assert "0" + phone.value[3:] in phone.forms  # national format
    assert by_id["contacts.0.name"].label.startswith("Contact: Jonas Weber")
    assert by_id["contacts.0.email"].tag == "Email"
    assert "sms.1.body" in by_id
    assert "timezone" not in by_id
    # the scanner can build needles from them
    needles = build_needles(markers)
    hits = needles.scan(f"id={by_id['gaid'].value}".encode())
    assert hits[0].marker_id == "gaid"
    # a fresh service (TUI restart) reloads the frozen ground truth
    fresh = IdentityService()
    assert fresh.active_markers()[0] == fp
    # mode off -> None
    monkeypatch.setattr(service.config(), "mode", "off")
    assert service.active_markers() is None


def test_describe_lists_per_value_metadata(env):
    infos = {i.id: i for i in IdentityService().describe(_profile())}
    assert infos["android_id"].restart == "framework"
    assert infos["gaid"].restart == "gms"
    assert infos["contacts"].permission == "READ_CONTACTS"
    assert infos["imei"].status == "hook-only"
    assert infos["phone_number"].permission == "READ_PHONE_NUMBERS"
