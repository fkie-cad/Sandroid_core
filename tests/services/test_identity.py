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
NOW = 1_700_000_000.0  # the services' wall clock (apply / verify times)
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
    svc._now = lambda: NOW
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


STOCK_SIM = {
    "imsi": "310260000000000",
    "iccid": "89860318640220133897",
    "msisdn": "+15555215580",
}


def _parcel(text: str) -> str:
    """A ``service call ... s16`` reply carrying ``text`` (as the device prints)."""
    data = (0).to_bytes(4, "little") + len(text).to_bytes(4, "little")
    data += text.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    words = [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]
    rows = []
    for i in range(0, len(words), 4):
        chunk = " ".join(f"{w:08x}" for w in words[i : i + 4])
        rows.append(f"  0x{i * 4:08x}: {chunk:<35} '................'")
    return "Result: Parcel(\n" + "\n".join(rows) + ")"


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
            "gsm.operator.alpha": "T-Mobile",
            "gsm.operator.numeric": "310260",
            "ro.boot.qemu.avd_name": "Dev1",
            "sys.boot_completed": "1",
        }
        self.settings = {
            "device_name": "sdk_gphone64",
            "auto_time_zone": "1",
            "airplane_mode_on": "0",
        }
        #: The SIM the guest reports (``service call iphonesubinfo``) and the
        #: one the modem holds (the guest reads it after an airplane toggle).
        self.sim = dict(STOCK_SIM)
        self.modem = dict(STOCK_SIM)
        self.airplane: list[str] = []
        #: Airplane-mode commands that are refused once (exit status 1).
        self.airplane_fail: set[str] = set()
        self.on_airplane = None  # called (no arguments) after "disable"
        self.shell_reads_sim = False  # the shell user may read the SIM
        #: (command, timeout) of every adb call.
        self.timeouts: list[tuple[str, float]] = []
        self.fs: dict[str, bytes] = {
            SSAID_FILE: b"ABX\0" + SSAID_XML.encode(),
            GAID_FILE: GAID_XML.encode(),
            APPSET_FILE: b"\x0a\x249b1e2a40-0000-4000-8000-000000000001\x10",
            ident.BOOT_ID_FILE: b"boot-1\n",
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
        #: Inode of each app's data directory (a reinstall gets a new one).
        self.inodes = {pkg: 5000 + i for i, pkg in enumerate(self.packages)}
        self.contacts: list[dict] = []
        self.sms: list[dict] = []
        self.call_log: list[dict] = []
        self.next_id = 100
        #: The call-log provider clears the name of an inserted call (it
        #: looks the number up in the contacts).
        self.clear_call_names = False
        #: Preflights whose list providers are not up yet (no answer).
        self.providers_down = 0
        self.emu_state: dict[str, str] = {}
        #: Reads of the device record (``identity.applied``); while
        #: ``record_down`` they get no answer.
        self.record_reads = 0
        self.record_down = False
        self.root = True  # adbd runs as root
        self.stat_down = False  # ``stat`` of app data prints nothing
        self.resetprop = True  # Magisk's resetprop is installed

    # -- transport --------------------------------------------------------

    def __call__(self, command: str, serial: str | None, timeout: float = 60):
        assert serial == SERIAL, "every call names the device"
        self.calls.append(command)
        self.timeouts.append((command, timeout))
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
                self.sim["msisdn"] = self.modem["msisdn"] = argv[2]
            elif argv[1:3] == ["geo", "fix"]:
                self.emu_state["geo"] = " ".join(argv[3:])
            return "OK\n", ""
        assert argv[0] == "shell"
        assert len(argv) == 2
        return self._shell(argv[1]), ""

    def _shell(self, script: str) -> str:
        light = "@@ssaid@@" not in script and "iphonesubinfo" in script
        if PREFLIGHT_TAG in script and light:
            return self._sim_read()
        if PREFLIGHT_TAG in script:
            return self._preflight(script)
        if script.startswith("pidof system_server"):
            return f"{self.pid}\npackage:/system/framework/framework-res.apk\n"
        zygote = script.startswith(ZYGOTE_PREFIX)
        record_read = script.startswith("echo @@applied@@")
        if record_read:
            self.record_reads += 1
            if self.record_down:
                return ""  # no answer (adb timed out)
        if not record_read and not (
            zygote and script.count("\n") == 1 and "abx2xml" in script
        ):
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
        if argv[:3] == ["cmd", "connectivity", "airplane-mode"] and (
            argv[3] in self.airplane_fail
        ):
            self.airplane_fail.discard(argv[3])
            self.airplane.append(f"refused {argv[3]}")
            return "Security exception: not allowed", False
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
        if name == "getprop" and len(argv) == 2:
            return self.props.get(argv[1], "")
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
        if name == "cat":
            return self.fs.get(argv[1], b"").decode().strip()
        if name == "stat" and argv[3].startswith("/data/data/"):
            if self.stat_down:
                return ""
            return self.install(argv[3].removeprefix("/data/data/"))
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
        if name == "cmd" and argv[1:3] == ["connectivity", "airplane-mode"]:
            self.airplane.append(argv[3])
            self.settings["airplane_mode_on"] = "1" if argv[3] == "enable" else "0"
            if argv[3] == "disable":
                self.sim = dict(self.modem)  # the radio reads the SIM again
                if self.on_airplane is not None:
                    self.on_airplane()
            return ""
        if name == "sleep":
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
            row = {"id": self.next_id, **binds}
            if self.clear_call_names:
                row["name"] = ""
            self.call_log.append(row)
            self.next_id += 1
        return ""

    def _preflight(self, script: str) -> str:
        assert ZYGOTE_PREFIX in script
        lines = [PREFLIGHT_TAG, "@@props@@"]
        lines += [f"{k}={v}" for k, v in self.props.items()]
        lines += ["@@root@@", "0" if self.root else "2000"]
        lines += ["@@resetprop@@", "/debug_ramdisk/resetprop" if self.resetprop else ""]
        lines += ["@@system_server@@", str(self.pid) if self.running else ""]
        lines += ["@@marker@@", self.fs.get(RESTART_MARKER, b"").decode()]
        lines += ["@@boot_id@@", self.fs[ident.BOOT_ID_FILE].decode().strip()]
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
        if "iphonesubinfo" in script:
            lines += self._sim_sections()
        lines.append("@@uids@@")
        lines += [f"package:{p} uid:{u}" for p, (u, _c) in self.packages.items()]
        for pkg, (_uid, cert) in self.packages.items():
            if f"@@pkg:{pkg}@@" in script:
                lines += [f"@@pkg:{pkg}@@", f'cert index="3" key="{cert}"']
            if f"@@inst:{pkg}@@" in script:
                lines += [f"@@inst:{pkg}@@", self.install(pkg)]
        if "@@list:" in script and self.providers_down:
            # Not up yet: ``content query`` fails (stderr is dropped).
            self.providers_down -= 1
            lines += ["@@list:contacts@@", "@@list:sms@@", "@@list:calls@@"]
        elif "@@list:" in script:
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
            if not n:
                lines.append(ident._NO_RESULT)
            lines.append("@@list:sms@@")
            for n, s in enumerate(self.sms):
                type_ = s.get("type")
                lines.append(
                    f"Row: {n} _id={s['id']}, address={s['address']}, "
                    f"body={s['body']}, type={type_}"
                )
            if not self.sms:
                lines.append(ident._NO_RESULT)
            lines.append("@@list:calls@@")
            for n, c in enumerate(self.call_log):
                name = c.get("name") or "NULL"
                lines.append(
                    f"Row: {n} _id={c['id']}, number={c['number']}, name={name}, "
                    f"type={c['type']}, duration={c['duration']}, "
                    f"date={c.get('date', 'NULL')}"
                )
            if not self.call_log:
                lines.append(ident._NO_RESULT)
        lines.append("@@end@@")
        return "\n".join(lines) + "\n"

    def _sim_sections(self) -> list[str]:
        if self.props["ro.build.version.sdk"] != "35":
            return []  # unknown transaction codes: the script reads nothing
        out = []
        for key in ("imsi", "iccid", "msisdn"):
            if not self.root and not self.shell_reads_sim:  # SecurityException
                out += [f"@@sim:{key}@@", "Result: Parcel(ffffffb5 00000000 '....')"]
            else:
                out += [f"@@sim:{key}@@", _parcel(self.sim.get(key, ""))]
        return out

    def _sim_read(self) -> str:
        lines = [PREFLIGHT_TAG, "@@props@@"]
        lines += [f"{k}={v}" for k, v in self.props.items() if k.startswith("gsm.")]
        lines += self._sim_sections()
        lines.append("@@end@@")
        return "\n".join(lines) + "\n"

    def install(self, pkg: str) -> str:
        """``uid:inode`` of the app's data directory (``""`` when absent)."""
        if pkg not in self.packages:
            return ""
        return f"{self.packages[pkg][0]}:{self.inodes[pkg]}"

    def reinstall(self, pkg: str) -> None:
        """Uninstall and install again: same uid, new data directory and a
        new Android ID (the framework drops the old one).
        """
        self.inodes[pkg] += 1000
        xml = self.fs[SSAID_FILE].removeprefix(b"ABX\0").decode()
        xml = re.sub(rf'value="[0-9a-f]+" package="{re.escape(pkg)}"',
                     f'value="9999888877776666" package="{pkg}"', xml)  # fmt: skip
        self.fs[SSAID_FILE] = b"ABX\0" + xml.encode()

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
    # The emulator was not launched with the profile's SIM (no host files);
    # a restart from the Devices hub would set it.
    fake.launched = None
    fake.token = "launch-1"  # noqa: S105 - a launch id, not a secret
    fake.blocker = ""
    monkeypatch.setattr(
        ident.identity_sim,
        "running_emulator",
        lambda serial, avd="": ident.identity_sim.RunningEmulator(
            serial, "Dev1", Path("/avd/Dev1.avd"), fake.launched, fake.token
        ),
    )
    monkeypatch.setattr(
        ident.identity_sim, "restart_blocker", lambda emu, profile: fake.blocker
    )
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
        ("phone_number", "152012345678", "native", True),
        ("phone_number", "+4915201234567", "native", True),
        ("phone_number", "+49152012345678901", "native", False),
        ("phone_number", "0152-0123", "native", False),
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
        "contacts",
        "sms",
        "calls",
    ):
        assert st[vid] == ("verified", ""), (vid, st[vid])  # fmt: skip
    # The SIM operator name comes from the emulator's carrier: hook-only.
    assert st["sim_operator"] == ("hook-only", ident.EMULATOR_SIM_OPERATOR)
    assert plan.infos["sim_operator"].provider == "hook"
    assert plan.infos["sim_operator"].current == "T-Mobile"
    # The emulator was not started with the profile's SIM: pending until it
    # restarts, nothing written (no setprop, no airplane toggle).
    for vid in ("imsi", "iccid", "sim_mccmnc"):
        assert st[vid] == ("pending", ident.NEEDS_EMULATOR_START), vid
        assert plan.infos[vid].mechanism == ident.SIM_MECHANISM
    assert plan.infos["imsi"].current == STOCK_SIM["imsi"]
    assert device.props["gsm.sim.operator.alpha"] == "T-Mobile"
    assert not [w for w in device.writes if "gsm.sim" in w or "airplane" in w]
    # The phone number fits adb emu phonenumber: the fallback, read back.
    assert st["phone_number"] == ("verified", "")
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
    assert record["values"]["phone_number"]["before"] == "+15555215580"
    assert record["values"]["imsi"]["before"] == STOCK_SIM["imsi"]
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
    assert again.infos["phone_number"].status == "verified"


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
    service._now = ident.time.time  # the real clock
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


def test_call_log_is_matched_by_number_type_date_not_name(service, device):
    """The call-log provider clears a call's name: rows are found by number
    and matched on number, type, date and duration, so a re-apply inserts
    nothing (it used to add both calls again every time).
    """
    device.clear_call_names = True
    first = service.apply(SERIAL, "com.example.app")
    assert first.infos["calls"].status == "verified"
    assert len(device.call_log) == 2
    dates = sorted(c["date"] for c in device.call_log)
    for _ in range(3):
        device.writes.clear()
        plan = service.apply(SERIAL, "com.example.app")
        assert plan.infos["calls"].status == "verified"
        assert plan.infos["calls"].current == "2/2 on device"
        assert not [w for w in device.writes if "call_log" in w]
    assert len(device.call_log) == 2
    assert sorted(c["date"] for c in device.call_log) == dates  # stable dates
    # The same for contacts and SMS: nothing written again.
    assert len(device.contacts) == 3
    assert len(device.sms) == 2


def test_call_rows_of_an_older_apply_are_replaced_once(service, device):
    """Rows written with another date (the old "now"-relative dates) are
    found by number and replaced: one row per call afterwards.
    """
    service.apply(SERIAL, "com.example.app")
    for row in device.call_log:
        row["date"] = str(int(row["date"]) - 7_200_000)
        row["name"] = ""
    device.call_log.append({**device.call_log[0], "id": 999})  # a duplicate
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["calls"].status == "verified"
    assert len(device.call_log) == 2
    assert 999 not in [c["id"] for c in device.call_log]


def test_list_read_back_waits_for_the_providers_after_a_restart(service, device):
    """Right after the framework restart the providers do not answer: the
    read-back retries (bounded, about 10 s) instead of failing 0/3.
    """
    slept: list[float] = []
    service._sleep = slept.append
    real_shell = device._shell

    def shell(script: str) -> str:
        if script.startswith("start") or "\nstart" in script:
            device.providers_down = 2  # down for the next two reads
        return real_shell(script)

    device._shell = shell
    plan = service.apply(SERIAL, "com.example.app")
    for name in ("contacts", "sms", "calls"):
        assert plan.infos[name].status == "verified", plan.infos[name]
    assert slept[-2:] == list(ident.PROVIDER_WAITS_S[:2])  # two re-reads
    assert sum(ident.PROVIDER_WAITS_S) <= 11
    assert len(device.contacts) == 3  # no blind insert
    # Providers that never come up: pending with the reason, not "failed".
    device.providers_down = 99
    slept.clear()
    state = service.preflight(SERIAL, ("com.example.app",), service.active_profile())
    assert state.lists_unread == {"contacts", "sms", "calls"}
    again = service.apply(SERIAL, "com.example.app")
    info = again.infos["contacts"]
    assert (info.status, info.reason) == ("pending", ident.PROVIDER_DOWN)
    assert len(device.contacts) == 3
    assert not slept  # nothing was written, nothing to wait for


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
    # The Android ID and the locale stayed pending: not done, so every start
    # tries again (never a restart while the policy says never).
    again = service.pre_spawn("com.example.app")
    assert again is not None
    assert not again.disruptive
    assert service.applied_state("com.example.app") == "not_applied"


def test_install_hook_is_a_no_op_without_app_start(service, monkeypatch):
    monkeypatch.setitem(sys.modules, "sandroid.services.app_start", None)
    assert service.install_pre_spawn_hook() is False


def test_applied_state_follows_the_current_profile_and_serial(
    service, device, monkeypatch, tmp_path
):
    from sandroid.core.adb import Adb

    # One level deeper: other tests' "other sessions on this device" glob
    # (tmp_path.parent/*/session) must not pick up this test's applies.
    monkeypatch.setenv("SDROID_FILES_DIR", str(tmp_path / "own" / "session" / "files"))
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))
    pkg = "com.example.app"
    assert service.applied_state(pkg) == "not_applied"
    service.apply(SERIAL, pkg)
    monkeypatch.setattr(ident, "_send", lambda *a, **k: pytest.fail("device read"))

    assert service.applied_state(pkg) == "applied"
    assert service.applied_state(pkg, SERIAL) == "applied"
    assert service.applied_state(pkg, "emulator-5582") == "not_applied"
    assert service.applied_state("com.other.app") == "not_applied"

    monkeypatch.setattr(ident, "_send", device)
    # Switch to another profile -> not applied; back -> applied again.
    original = service.config().profile
    other = service.save(_profile(id="other-profile"))
    monkeypatch.setattr(service.config(), "profile", other.id)
    assert service.applied_state(pkg) == "not_applied"
    monkeypatch.setattr(service.config(), "profile", original)
    assert service.applied_state(pkg) == "applied"

    # Regenerate: same id, new fingerprint -> not applied any more.
    service.regenerate(original)
    assert service.applied_state(pkg) == "not_applied"

    # Identity mode off, or an unusable profile: no state at all.
    monkeypatch.setattr(service.config(), "profile", "missing")
    assert service.applied_state(pkg) is None
    monkeypatch.setattr(service.config(), "mode", "off")
    assert service.applied_state(pkg) is None


# ---------------------------------------------------------------------------
# markers contract
# ---------------------------------------------------------------------------


def test_markers_contract(service, device, monkeypatch):
    seen: list = []
    service.add_markers_listener(lambda fp, markers: seen.append((fp, markers)))
    # Nothing applied yet: the markers come from the profile (no Android ID:
    # it needs the app's signer).
    fp0, before = service.active_markers()
    assert fp0 == ident.fingerprint(service.active_profile())
    assert seen[-1] == (fp0, before)  # the first read notifies the scan
    assert {"gaid", "gps.latitude"} <= {m.id for m in before}
    assert not [m for m in before if m.id.startswith("android_id")]
    service.apply(SERIAL, "com.example.app")
    fp, markers = service.active_markers()
    assert seen[-1] == (fp, markers)
    assert all(isinstance(m, Marker) for m in markers)
    by_id = {m.id: m for m in markers}
    aid = by_id["android_id@com.example.app"]  # per app, whichever is applied
    assert aid.value == device.ssaid["com.example.app"]
    assert aid.tag == "AndroidID"
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


def test_restart_in_a_new_session_scans_without_a_re_apply(
    service, device, env, monkeypatch
):
    """A TUI restart starts a new session: the markers come from the profile
    and the Android ID from the newest apply on this device in another
    session (nothing is applied to the device).
    """
    monkeypatch.setenv("SDROID_FILES_DIR", str(env / "s1" / "dev" / "files"))
    service.apply(SERIAL, "com.example.app")
    fp, applied = service.active_markers()
    by_id = {m.id: m for m in applied}
    monkeypatch.setenv("SDROID_FILES_DIR", str(env / "s2" / "dev" / "files"))
    device.calls.clear()
    fresh = IdentityService()
    fp2, markers = fresh.active_markers()
    assert (fp2, markers) == (fp, applied)  # the same profile: its markers
    assert device.calls == []  # nothing went to the device
    # The profile changed since: values from it, the Android ID derived
    # from the token and the signer the earlier apply recorded.
    profile = service.active_profile()
    profile.values["device_name"].value = "Changed Phone"
    service.save(profile)
    changed = IdentityService()
    fp3, markers = changed.active_markers()
    assert fp3 != fp
    new_by_id = {m.id: m for m in markers}
    aid = "android_id@com.example.app"
    assert new_by_id[aid].value == by_id[aid].value
    assert new_by_id["device_name"].value == "Changed Phone"
    assert device.calls == []
    # Another profile's apply is not used.
    monkeypatch.setattr(service.config(), "profile", "nope")
    assert IdentityService().active_markers() is None


def test_describe_lists_per_value_metadata(env):
    infos = {i.id: i for i in IdentityService().describe(_profile())}
    assert infos["android_id"].restart == "framework"
    assert infos["gaid"].restart == "gms"
    assert infos["contacts"].permission == "READ_CONTACTS"
    assert infos["imei"].status == "hook-only"
    assert infos["phone_number"].permission == "READ_PHONE_NUMBERS"


def test_sim_properties_are_set_natively_off_the_emulator(service, device, monkeypatch):
    parse = ident.parse_preflight

    def real_device(serial, text):
        state = parse(serial, text)
        state.emulator = False
        return state

    monkeypatch.setattr(ident, "parse_preflight", real_device)
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["sim_operator"].status == "verified"
    assert plan.infos["sim_operator"].provider == "native"
    assert device.props["gsm.sim.operator.alpha"] == "Telekom 3f9a1c07"


def test_provider_wait_is_bounded_on_an_overloaded_device(service, device):
    """After the restart adb calls hang (ANR storm): the wait uses a light
    lists-only probe with a short timeout, stops at the first unanswered
    probe and never exceeds PROVIDER_WAIT_DEADLINE_S, so an app start is
    not held for minutes. Unanswered lists stay pending, not failed.
    """
    now = [1000.0]
    service._clock = lambda: now[0]
    service._sleep = lambda s: now.__setitem__(0, now[0] + s)
    real_shell = device._shell
    probes: list[str] = []
    restarted = [False]

    def shell(script: str) -> str:
        if script.startswith("start") or "\nstart" in script:
            restarted[0] = True
            device.providers_down = 99
        if restarted[0] and "@@list:" in script and "@@props@@" not in script:
            probes.append(script)
            now[0] += ident.PROVIDER_PROBE_TIMEOUT_S  # adb timed out
            return ""
        return real_shell(script)

    device._shell = shell
    timeouts: list[float] = []
    real_send = ident._send

    def send(command, serial, timeout=60):
        if "@@list:" in command and "@@props@@" not in command:
            timeouts.append(timeout)
        return real_send(command, serial, timeout)

    ident._send = send
    try:
        start = now[0]
        plan = service.apply(SERIAL, "com.example.app")
    finally:
        ident._send = real_send
    assert len(probes) == 1  # stopped at the first unanswered probe
    assert timeouts
    assert max(timeouts) <= ident.PROVIDER_PROBE_TIMEOUT_S
    assert now[0] - start <= ident.PROVIDER_WAIT_DEADLINE_S + 60  # + restart
    for script in probes:  # light: no packages.xml, settings or dumpsys
        assert "packages.xml" not in script
        assert "dumpsys" not in script
    for name in ("contacts", "sms", "calls"):
        assert plan.infos[name].status != "failed", plan.infos[name]


def test_lists_script_reads_only_the_lists():
    script = ident.lists_script([TOKEN], ["+4930123456"])
    assert script.startswith(f"echo {PREFLIGHT_TAG}")
    assert script.rstrip().endswith("echo @@end@@")
    assert "@@list:contacts@@" in script
    assert "@@list:calls@@" in script
    assert "abx2xml" not in script
    assert ident.lists_script([TOKEN + "\n"]).count("@@list:") == 0


# ---------------------------------------------------------------------------
# after a framework restart: frida-server, then the proxy check
# ---------------------------------------------------------------------------


def test_after_restart_runs_the_proxy_check(monkeypatch):
    calls = []
    module = types.ModuleType("sandroid.services.proxy_restore")

    def restore_proxy_infra(serial, *, cause, fresh_boot):
        calls.append((serial, cause, fresh_boot))

    module.restore_proxy_infra = restore_proxy_infra
    monkeypatch.setitem(sys.modules, "sandroid.services.proxy_restore", module)
    monkeypatch.setattr(
        ident, "_restart_frida_after_framework", lambda s: calls.append(("frida", s))
    )
    assert IdentityService()._after_restart is ident._after_framework_restart
    ident._after_framework_restart(SERIAL)
    assert calls == [("frida", SERIAL), (SERIAL, "framework_restart", False)]


def test_after_restart_tolerates_a_missing_or_failing_proxy_check(monkeypatch):
    monkeypatch.setitem(sys.modules, "sandroid.services.proxy_restore", None)
    ident._restore_proxy_after_framework(SERIAL)  # no module: a no-op

    module = types.ModuleType("sandroid.services.proxy_restore")

    def boom(serial, *, cause, fresh_boot):
        raise RuntimeError("device gone")

    module.restore_proxy_infra = boom
    monkeypatch.setitem(sys.modules, "sandroid.services.proxy_restore", module)
    ident._restore_proxy_after_framework(SERIAL)  # swallowed


# ---------------------------------------------------------------------------
# SIM identity (set when the emulator starts, see identity_sim)
# ---------------------------------------------------------------------------


def _profile_sim(service) -> ident.identity_sim.SimValues:
    """What the active profile's SIM carries (as the launch hook builds it)."""
    sim = ident.identity_sim.sim_values(service.active_profile())
    assert sim is not None
    return sim


def _sim_infos(plan) -> dict[str, tuple[str, str]]:
    return {
        vid: (plan.infos[vid].status, plan.infos[vid].reason)
        for vid in ("imsi", "iccid", "sim_mccmnc", "phone_number")
    }


def test_sim_values_the_device_reports_are_verified_without_writes(service, device):
    sim = _profile_sim(service)
    device.sim = device.modem = {
        "imsi": sim.imsi,
        "iccid": sim.iccid,
        "msisdn": sim.phone,
    }
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    plan = service.apply(SERIAL, "com.example.app")
    assert set(_sim_infos(plan).values()) == {("verified", "")}
    assert sim.phone.startswith("+49")  # the national number got +49
    assert not device.airplane
    assert not [w for w in device.writes if "phonenumber" in w]


def _launched(service, device) -> ident.identity_sim.SimValues:
    """The emulator started with the profile's SIM; the guest has the old one."""
    sim = _profile_sim(service)
    device.launched = sim
    device.modem = {"imsi": sim.imsi, "iccid": sim.iccid, "msisdn": sim.phone}
    return sim


def test_a_failed_sim_value_never_blocks_a_start_through_app_start(
    service, device, monkeypatch
):
    """The real ``app_start`` pre-start step: a failed SIM value (set at the
    emulator's start) stays failed in the lens but the app starts, and the
    SIM alone never makes the start disruptive.
    """
    from sandroid.core.adb import Adb
    from sandroid.services import app_start as real

    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))
    monkeypatch.setattr(real, "_system_server_pid", lambda serial=None: 4242)
    profile = service.active_profile()
    for vid in ("android_id", "locale"):  # no framework value left
        profile.values[vid].enabled = False
    service.save(profile)
    _launched(service, device)
    device.modem = dict(STOCK_SIM)  # the radio keeps the old SIM
    assert service.install_pre_spawn_hook()
    try:
        plans = real._collect_pre_spawn("com.example.app", "the app")
        assert len(plans) == 1
        assert isinstance(plans[0], real.PreSpawnPlan)
        assert not plans[0].disruptive  # the SIM toggle restarts nothing
        real._apply_pre_spawn(plans, "com.example.app")  # no AppStartError
        assert device.airplane == ["enable", "disable"]
        infos = {i.id: i for i in service.statuses()}
        assert infos["imsi"].status == "failed"
        assert infos["imsi"].sim_launch
        assert "com.example.app" in _record(device)["done"]
        # Done: the next start of the app has nothing to do.
        assert real._collect_pre_spawn("com.example.app", "the app") == []
    finally:
        service.uninstall_pre_spawn_hook()


def test_a_snapshot_with_the_old_sim_gets_one_airplane_toggle(service, device):
    sim = _launched(service, device)
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    with timeline.capture() as lines:
        plan = service.apply(SERIAL, "com.example.app")
    assert set(_sim_infos(plan).values()) == {("verified", "")}
    assert device.airplane == ["enable", "disable"]  # once, back to off
    assert device.settings["airplane_mode_on"] == "0"
    # Never adb emu phonenumber for a number the SIM carries (it would
    # replace the international MSISDN with the national form).
    assert not [w for w in device.writes if "phonenumber" in w]
    assert ("identity", "sim") in [(x["src"], x["kind"]) for x in lines]
    device.airplane.clear()
    again = service.apply(SERIAL, "com.example.app")
    assert set(_sim_infos(again).values()) == {("verified", "")}
    assert not device.airplane


def test_a_launch_checked_with_airplane_mode_on_is_not_planned_again(
    service, device, app_start
):
    """Airplane mode on: the apply checks the launch (no toggle) and later
    starts do not plan again for it.
    """
    profile = service.active_profile()
    for vid in ("android_id", "locale"):
        profile.values[vid].enabled = False
    service.save(profile)
    _launched(service, device)
    device.props["ro.boot.qemu.avd_name"] = "Dev1"
    device.settings["airplane_mode_on"] = "1"
    plan = service.pre_spawn("com.example.app")
    assert plan is not None
    plan.apply()
    assert not device.airplane
    for _ in range(3):
        assert service.pre_spawn("com.example.app") is None


def test_a_new_launch_with_a_same_country_sim_is_due(service, device, app_start):
    """The guest's MCC/MNC already matches (same country), yet the guest
    still has another profile's IMSI: a new launch with this profile's SIM
    is checked once all the same.
    """
    profile = service.active_profile()
    for vid in ("android_id", "locale"):
        profile.values[vid].enabled = False
    service.save(profile)
    sim = _launched(service, device)
    device.props["ro.boot.qemu.avd_name"] = "Dev1"
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    service.apply(SERIAL, "com.example.app")
    assert service.pre_spawn("com.example.app") is None
    device.token = "launch-2"  # noqa: S105 - a launch id, not a secret
    device.sim = {
        **dict(STOCK_SIM),
        "imsi": sim.mccmnc + "0000000000"[: 15 - len(sim.mccmnc)],
    }
    device.airplane.clear()
    plan = service.pre_spawn("com.example.app")
    assert plan is not None
    plan.apply()
    assert device.airplane == ["enable", "disable"]
    assert service.pre_spawn("com.example.app") is None


def test_a_launch_whose_sim_verifies_is_not_planned_again(service, device, app_start):
    """A cold boot with the profile's SIM: the guest reports it, the apply
    marks the launch checked, and later starts plan nothing.
    """
    profile = service.active_profile()
    for vid in ("android_id", "locale"):
        profile.values[vid].enabled = False
    service.save(profile)
    sim = _launched(service, device)
    device.sim = dict(device.modem)  # already read at boot
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    device.props["ro.boot.qemu.avd_name"] = "Dev1"
    plan = service.pre_spawn("com.example.app")
    assert plan is not None
    plan.apply()
    assert not device.airplane
    for _ in range(3):
        assert service.pre_spawn("com.example.app") is None


def test_started_with_compares_only_the_values_the_profile_sets():
    sim_cls = ident.identity_sim.SimValues
    launched = sim_cls(
        iccid="89860318640220133897",  # the image's default (not patched)
        imsi="262011234567890",
        msisdn="15551234567",
        msisdn_international=False,
        mccmnc="26201",
        operator="",
    )
    profile_sim = sim_cls(
        iccid="",
        imsi="262011234567890",
        msisdn="",
        msisdn_international=False,
        mccmnc="26201",
        operator="",
    )
    assert ident._started_with(launched, profile_sim)
    other = sim_cls(
        iccid="",
        imsi="262019999999999",
        msisdn="",
        msisdn_international=False,
        mccmnc="26201",
        operator="",
    )
    assert not ident._started_with(launched, other)
    assert not ident._started_with(None, profile_sim)


def test_rows_without_a_step_show_the_device_after_the_toggle(service, device):
    """The SIM operator name (hook-only, no step) changes with the toggle:
    the apply reports what the device shows afterwards.
    """
    sim = _launched(service, device)
    device.props["gsm.sim.operator.numeric"] = "310260"
    device.props["gsm.sim.operator.alpha"] = "T-Mobile"

    def refreshed() -> None:
        device.props["gsm.sim.operator.numeric"] = sim.mccmnc
        device.props["gsm.sim.operator.alpha"] = "Telekom"

    device.on_airplane = refreshed
    plan = service.apply(SERIAL, "com.example.app")
    assert device.airplane == ["enable", "disable"]
    assert plan.infos["sim_operator"].current == "Telekom"


def test_the_toggle_runs_once_per_launch_and_a_mismatch_fails(
    service, device, app_start
):
    sim = _launched(service, device)
    device.modem = dict(STOCK_SIM)  # the radio keeps the old SIM
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "failed"
    assert plan.infos["imsi"].reason == (
        f"the device still reports {STOCK_SIM['imsi']} after the airplane mode toggle"
    )
    assert device.airplane == ["enable", "disable"]
    assert plan.infos["imsi"].sim_launch
    # A failed SIM value does not block app starts and the app counts as
    # done: no re-apply on the next start.
    assert "com.example.app" in service._applied[SERIAL].done
    assert service.pre_spawn("com.example.app") is None
    # Later applies neither toggle nor wait again, and do not raise.
    device.airplane.clear()
    device.calls.clear()
    service.pre_spawn("com.example.two").apply()
    assert not device.airplane
    assert not [c for c in device.calls if "@@ssaid@@" not in c and "@@props@@" in c]
    assert service.statuses()
    assert {i.id: i.status for i in service.statuses()}["imsi"] == "failed"
    # A new launch of the emulator (new launch token): one toggle again.
    device.token = "launch-2"  # noqa: S105 - a launch id, not a secret
    device.modem = {"imsi": sim.imsi, "iccid": sim.iccid, "msisdn": sim.phone}
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "verified"
    assert device.airplane == ["enable", "disable"]


def test_a_quickboot_snapshot_with_the_old_sim_is_not_done(service, device, app_start):
    """A new launch from a quickboot snapshot whose record says done: the
    guest still has the old SIM, so the start applies (one toggle) instead
    of skipping; once refreshed the next start has nothing to do.
    """
    profile = service.active_profile()
    for vid in ("android_id", "locale"):  # no framework value left
        profile.values[vid].enabled = False
    service.save(profile)
    sim = _launched(service, device)
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    device.props["ro.boot.qemu.avd_name"] = "Dev1"
    service.apply(SERIAL, "com.example.app")
    assert service.pre_spawn("com.example.app") is None
    # The emulator is started again from a snapshot taken before the SIM
    # refresh: same boot id, new launch token, the old SIM in the guest.
    device.token = "launch-2"  # noqa: S105 - a launch id, not a secret
    device.sim = dict(STOCK_SIM)  # cached by the snapshot
    device.props["gsm.sim.operator.numeric"] = "310260"
    device.airplane.clear()
    plan = service.pre_spawn("com.example.app")
    assert plan is not None
    assert not plan.disruptive

    def refreshed() -> None:
        device.props["gsm.sim.operator.numeric"] = sim.mccmnc

    device.on_airplane = refreshed
    plan.apply()
    assert device.airplane == ["enable", "disable"]
    assert service.pre_spawn("com.example.app") is None
    # Not started with the profile's SIM: a toggle would not help, no plan.
    device.launched = None
    device.props["gsm.sim.operator.numeric"] = "310260"
    assert service.pre_spawn("com.example.app") is None


def test_a_failed_toggle_switches_airplane_mode_off_again(service, device):
    _launched(service, device)
    device.modem = dict(STOCK_SIM)  # the guest still shows the old SIM
    device.airplane_fail = {"disable"}  # on worked, off was refused
    plan = service.apply(SERIAL, "com.example.app")
    assert device.airplane == ["enable", "refused disable", "disable"]
    assert device.settings["airplane_mode_on"] == "0"
    assert plan.infos["iccid"].status == "failed"
    assert plan.infos["iccid"].reason.startswith("airplane mode: ")


def test_an_error_during_the_toggle_still_switches_airplane_mode_off(
    service, device, monkeypatch
):
    _launched(service, device)
    real = ident._Device.shell

    def shell(self, script, **kw):
        if "airplane-mode enable" in script:
            device.settings["airplane_mode_on"] = "1"
            raise RuntimeError("adb connection lost")
        return real(self, script, **kw)

    monkeypatch.setattr(ident._Device, "shell", shell)
    with pytest.raises(RuntimeError):
        service.apply(SERIAL, "com.example.app")
    assert device.airplane == ["disable"]
    assert device.settings["airplane_mode_on"] == "0"


def test_airplane_mode_that_is_on_is_left_alone(service, device):
    _launched(service, device)
    device.settings["airplane_mode_on"] = "1"
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "applied"
    assert plan.infos["imsi"].reason == ident.SIM_AIRPLANE_ON
    assert plan.infos["phone_number"].reason == ident.SIM_AIRPLANE_ON
    assert not device.airplane
    assert device.settings["airplane_mode_on"] == "1"


def test_the_sim_probe_never_outlasts_the_deadline(service, device):
    _launched(service, device)
    device.modem = dict(STOCK_SIM)  # never matches: probes until the deadline
    now = [0.0]
    service._clock = lambda: now[0]
    service._sleep = lambda s: now.__setitem__(0, now[0] + s + 2.0)
    service.apply(SERIAL, "com.example.app")
    probes = [
        t for c, t in device.timeouts if "@@ssaid@@" not in c and "@@props@@" in c
    ]
    assert probes
    assert all(t <= ident.SIM_WAIT_DEADLINE_S for t in probes)
    assert probes[-1] < 30.0  # bounded by what was left


def test_a_sim_the_emulator_did_not_start_with_stays_pending(service, device):
    profile = service.active_profile()
    profile.values["phone_number"].template = "+49152{digits:8}"
    service.save(profile)
    plan = service.apply(SERIAL, "com.example.app")
    infos = _sim_infos(plan)
    # Too long for adb emu phonenumber: only the emulator start sets it.
    assert set(infos.values()) == {("pending", ident.NEEDS_EMULATOR_START)}
    assert not device.airplane
    assert not [w for w in device.writes if "phonenumber" in w]
    # Pending until the emulator restarts: no re-apply on every app start.
    assert "com.example.app" in service._applied[SERIAL].done
    assert "com.example.app" in _record(device)["done"]
    assert service.pre_spawn("com.example.app") is None


def test_no_restart_advice_when_a_restart_would_not_help(service, device):
    device.blocker = ident.identity_sim.NO_TEMPLATE
    profile = service.active_profile()
    profile.values["phone_number"].template = "+49152{digits:8}"
    service.save(profile)
    plan = service.plan(SERIAL, "com.example.app")
    infos = _sim_infos(plan)
    assert set(infos.values()) == {("skipped", ident.identity_sim.NO_TEMPLATE)}


def test_without_a_sim_read_back_the_launch_values_still_get_the_toggle(
    service, device
):
    device.props["ro.build.version.sdk"] = "36"  # transaction codes unknown
    sim = _launched(service, device)
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    plan = service.apply(SERIAL, "com.example.app")
    for vid in ("imsi", "iccid", "phone_number"):
        assert plan.infos[vid].status == "applied", vid
        assert plan.infos[vid].reason == ident.SIM_NOT_READ
    assert device.airplane == ["enable", "disable"]  # a snapshot caches the SIM
    assert not [w for w in device.writes if "phonenumber" in w]


def test_without_root_the_launch_values_are_applied_not_failed(service, device):
    sim = _launched(service, device)
    device.root = False
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    plan = service.plan(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "pending"  # the toggle is planned
    service._sim_toggles.clear()
    device.airplane_fail = {"enable"}  # the shell user may not switch it
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "applied"
    assert plan.infos["imsi"].reason == ident.SIM_TOGGLE_REFUSED
    assert device.airplane == ["refused enable", "disable"]
    # Allowed for the shell user: not read back without root.
    service._sim_toggles.clear()
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["iccid"].reason == ident.SIM_NOT_READ_ROOT


def test_sim_values_are_hook_only_on_a_real_device(service, device, monkeypatch):
    device.props["ro.kernel.qemu"] = "0"
    parse = ident.parse_preflight

    def real_device(serial, text):
        state = parse("R58M123", text)
        state.serial = serial
        return state

    monkeypatch.setattr(ident, "parse_preflight", real_device)
    with timeline.capture() as lines:
        plan = service.apply(SERIAL, "com.example.app")
    for vid in ("imsi", "iccid"):
        assert plan.infos[vid].status == "hook-only"
        assert plan.infos[vid].reason == "a real SIM card cannot be changed"
        assert plan.infos[vid].provider == "hook"
        assert not plan.infos[vid].current
    assert plan.infos["imei"].reason == "Android lets no tool change a phone's IMEI"
    # A real phone's SIM identity is never recorded.
    applied = next(x for x in lines if x["kind"] == "applied")
    record = ident.tomllib.loads(service_folder(applied).read_text(encoding="utf-8"))
    for vid in ("imsi", "iccid", "phone_number"):
        assert not record["values"][vid]["before"], vid
    assert STOCK_SIM["iccid"] not in str(record)
    assert STOCK_SIM["imsi"] not in str(record)


def test_real_phones_parse_no_sim_and_the_script_checks_for_an_emulator():
    script = ident.preflight_script([], [TOKEN])
    assert 'if [ "$(getprop ro.kernel.qemu)" = 1 ]' in script
    text = "\n".join(
        [PREFLIGHT_TAG, "@@props@@", "ro.kernel.qemu=0", "@@sim:iccid@@",
         _parcel("8949012345678901234"), "@@end@@"]
    )  # fmt: skip
    state = ident.parse_preflight("R58M123", text)
    assert not state.sim
    assert not state.sim_read


def test_network_operator_name_carrying_the_sim_operator_is_noted(service, device):
    device.props["gsm.operator.alpha"] = "Telekom 3f9a1c07"
    plan = service.plan(SERIAL, "com.example.app")
    info = plan.infos["sim_operator"]
    assert info.status == "hook-only"
    assert info.reason.endswith(ident.NETWORK_OPERATOR_CARRIES)


def test_imei_says_why_it_is_hook_only(service, device):
    plan = service.plan(SERIAL, "com.example.app")
    assert plan.infos["imei"].reason == "the emulator's modem reports a fixed IMEI"
    assert plan.infos["imsi"].provider == "native"


def test_preflight_reads_the_sim_on_known_api_levels():
    script = ident.preflight_script([], [TOKEN])
    assert "35) echo @@sim:imsi@@; service call iphonesubinfo 8 s16" in script
    assert "service call iphonesubinfo 12 s16" in script
    assert "service call iphonesubinfo 15 s16" in script
    # One boot id read serves the SIM toggle key and the device record, the
    # same file the record read (pre-spawn) uses.
    assert script.count("@@boot_id@@") == 1
    assert f"cat {ident.BOOT_ID_FILE}" in script
    assert f"cat {ident.BOOT_ID_FILE}" in ident.record_script("com.example.app")
    state = ident.parse_preflight(
        SERIAL,
        "\n".join(
            [PREFLIGHT_TAG, "@@boot_id@@", "abc", "@@sim:iccid@@",
             _parcel("8949012345678901234"), "@@sim:msisdn@@",
             "Result: Parcel(ffffffb5 00000000 '....')", "@@end@@"]
        ),
    )  # fmt: skip
    assert state.sim == {"iccid": "8949012345678901234"}
    assert state.sim_read
    assert state.boot_id == "abc"


def test_an_imsi_without_a_known_mcc_mnc_warns_and_keeps_the_emulator_sim():
    profile = _profile()
    del profile.values["sim_mccmnc"]
    profile.preset = ""
    issues = [i for i in ident.validate(profile) if i.path == "values.imsi"]
    assert [i.severity for i in issues] == ["warning"]
    assert "MCC/MNC" in issues[0].message
    assert not [i for i in ident.validate(profile) if i.severity == "error"]
    # No guess at the MNC length: no SIM launch at all.
    assert ident.identity_sim.sim_values(profile) is None
    profile.values["imsi"].enabled = False
    assert not [i for i in ident.validate(profile) if i.path == "values.imsi"]


@pytest.mark.parametrize(
    ("number", "value", "forms"),
    [
        ("+4915112345678", "+4915112345678", ("015112345678",)),
        ("015112345678", "+4915112345678", ("015112345678",)),
        ("15112345678", "+4915112345678", ("15112345678", "015112345678")),
        ("004915112345678", "+4915112345678", ("004915112345678", "015112345678")),
    ],
)
def test_phone_markers_carry_the_number_the_sim_carries(number, value, forms):
    assert ident._phone_marker_value(number, "49") == (value, forms)
    digits, international = ident.identity_sim.msisdn_digits(number, "49")
    assert international
    assert "+" + digits == value


def test_the_emulator_phone_number_fallback_is_no_sim_launch_value(service, device):
    # adb emu phonenumber can be retried: its failure still blocks as before.
    plan = service.plan(SERIAL, "com.example.app")
    assert not plan.infos["phone_number"].sim_launch
    assert plan.infos["imsi"].sim_launch


def _no_answer_toggle(monkeypatch, device) -> list[str]:
    """The toggle times out (adb returns nothing); every attempt is logged."""
    tries: list[str] = []
    real = ident._Device.shell

    def shell(self, script, **kw):
        if "airplane-mode enable" in script:
            tries.append(script)
            return ""
        return real(self, script, **kw)

    monkeypatch.setattr(ident._Device, "shell", shell)
    return tries


def test_a_toggle_without_answer_is_tried_once_more(
    service, device, app_start, monkeypatch
):
    _launched(service, device)
    device.modem = dict(STOCK_SIM)  # the guest keeps showing the old SIM
    tries = _no_answer_toggle(monkeypatch, device)
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "pending"
    assert plan.infos["imsi"].reason == ident.SIM_TOGGLE_RETRY
    assert device.airplane == ["disable"]  # switched off again
    # Not done: the next start applies again, and tries once more.
    assert service.pre_spawn("com.example.app") is not None
    plan = service.apply(SERIAL, "com.example.app")
    assert len(tries) == 2
    assert plan.infos["imsi"].status == "failed"
    assert plan.infos["imsi"].reason == "airplane mode: no answer"
    service.apply(SERIAL, "com.example.app")
    assert len(tries) == 2  # the launch's result is final now
    # Final: later starts do not plan for this launch again.
    device.props["ro.boot.qemu.avd_name"] = "Dev1"
    for _ in range(3):
        assert service.pre_spawn("com.example.app") is None


def test_a_snapshot_load_allows_a_new_toggle(service, device, monkeypatch):
    from sandroid.services import emulator_service

    sim = _launched(service, device)
    device.props["gsm.sim.operator.numeric"] = sim.mccmnc
    service.apply(SERIAL, "com.example.app")
    assert device.airplane == ["enable", "disable"]
    # The console restores a snapshot: same boot id and launch token, the
    # guest has the old SIM cached again.
    device.sim = dict(STOCK_SIM)
    device.airplane.clear()
    service.apply(SERIAL, "com.example.app")
    assert not device.airplane  # without the notice: no new toggle
    monkeypatch.setattr(ident, "get_identity_service", lambda: service)
    emulator_service._world_change("snapshot-load", dev=SERIAL)
    plan = service.apply(SERIAL, "com.example.app")
    assert device.airplane == ["enable", "disable"]
    assert plan.infos["imsi"].status == "verified"
    service.sim_launch_changed()  # all serials
    assert not service._sim_toggles


def test_a_refused_toggle_with_the_old_sim_read_back_fails(service, device):
    _launched(service, device)
    device.modem = dict(STOCK_SIM)  # the guest keeps showing the old SIM
    device.root = False
    device.shell_reads_sim = True  # API 35 read-back works for the shell user
    device.airplane_fail = {"enable"}
    plan = service.apply(SERIAL, "com.example.app")
    assert plan.infos["imsi"].status == "failed"
    assert plan.infos["imsi"].reason == (
        "airplane mode could not be switched without root; the device still "
        f"reports {STOCK_SIM['imsi']}"
    )
    assert plan.infos["imsi"].sim_launch  # does not block app starts


def test_an_unreadable_system_image_gives_no_restart_advice(
    service, device, monkeypatch
):
    def broken(emu, profile):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(ident.identity_sim, "restart_blocker", broken)
    plan = service.plan(SERIAL, "com.example.app")
    assert plan.infos["iccid"].status == "skipped"
    assert plan.infos["iccid"].reason == "the emulator's system image could not be read"


# ---------------------------------------------------------------------------
# device record (identity.applied): survives a TUI restart
# ---------------------------------------------------------------------------

PKG = "com.example.app"


def _record(device) -> dict:
    return ident.json.loads(device.fs[ident.APPLIED_FILE])


def _fresh() -> IdentityService:
    """A new service on the same library and device: a TUI restart."""
    svc = IdentityService()
    svc._sleep = lambda s: None
    svc._now = lambda: NOW
    svc._after_restart = lambda serial: None
    return svc


def test_apply_writes_the_device_record(service, device):
    service.apply(SERIAL, PKG)
    record = _record(device)
    profile = service.active_profile()
    assert record["format"] == ident.APPLIED_FORMAT
    assert record["profile"] == profile.id
    assert record["fingerprint"] == ident.fingerprint(profile)
    assert record["boot_id"] == "boot-1"
    assert record["done"] == [PKG]
    assert record["ssaids"] == {PKG: device.ssaid[PKG]}
    assert record["framework"] == {"locale": False}
    assert record["at"] > 0
    assert device.meta[ident.APPLIED_FILE]["owner"] == ident.APPLIED_OWNER
    # Updated per package (the second app joins the record).
    service.apply(SERIAL, "com.other.app")
    record = _record(device)
    assert record["done"] == [PKG, "com.other.app"]
    assert set(record["ssaids"]) == {PKG, "com.other.app"}
    # Nothing new: nothing written (and no write outside apply).
    device.writes.clear()
    service.apply(SERIAL, PKG)
    service.verify(SERIAL)
    assert device.writes == []


def test_a_fresh_service_reads_the_record_before_a_start(service, device, app_start):
    service.apply(SERIAL, PKG)
    fresh = _fresh()
    device.calls.clear()
    device.writes.clear()
    assert fresh.pre_spawn(PKG) is None
    assert len(device.calls) == 1  # one cheap read, nothing else
    assert device.record_reads == 1
    assert device.writes == []
    assert fresh.applied_state(PKG) == "applied"
    # A package the record does not know needs an apply (its Android ID).
    plan = fresh.pre_spawn("com.other.app")
    assert plan is not None
    assert plan.disruptive


def test_the_record_is_the_truth_after_a_snapshot_load(service, device, app_start):
    service.apply(SERIAL, PKG)
    assert service.pre_spawn(PKG) is None
    # A snapshot from before the apply: no record (memory still says done).
    saved = device.fs.pop(ident.APPLIED_FILE)
    plan = service.pre_spawn(PKG)
    assert plan is not None
    assert plan.disruptive
    assert service.applied_state(PKG) == "not_applied"
    device.fs[ident.APPLIED_FILE] = saved
    assert service.pre_spawn(PKG) is None


def test_without_an_answer_pre_spawn_applies(service, device, app_start):
    service.apply(SERIAL, PKG)
    device.record_down = True
    # The device did not answer: memory may be stale, so apply, but the
    # memory still says no framework restart is pending.
    plan = service.pre_spawn(PKG)
    assert plan is not None
    assert not plan.disruptive
    assert plan.description == "apply identity profile mara-de"
    plan = _fresh().pre_spawn(PKG)
    assert plan is not None
    assert plan.disruptive  # nothing known: conservative


def test_a_reboot_makes_the_package_pending_but_not_disruptive(
    service, device, app_start
):
    service.apply(SERIAL, PKG)
    pid = device.pid
    device.fs[ident.BOOT_ID_FILE] = b"boot-2\n"
    for svc in (service, _fresh()):
        plan = svc.pre_spawn(PKG)
        assert plan is not None
        # The Android ID (a file) and the locale (persistent) are still there.
        assert not plan.disruptive
    plan.apply()
    assert device.pid == pid  # no framework restart
    assert _record(device)["boot_id"] == "boot-2"
    assert service.pre_spawn(PKG) is None


def test_a_reboot_loses_volatile_framework_values(service, device, app_start):
    profile = service.active_profile()
    profile.values["build_model"].enabled = True
    service.save(profile)
    service.apply(SERIAL, PKG)
    assert _record(device)["framework"] == {"build_model": True, "locale": False}
    assert _fresh().pre_spawn(PKG) is None
    device.fs[ident.BOOT_ID_FILE] = b"boot-2\n"
    device.props["ro.product.model"] = "sdk_gphone64_arm64"  # resetprop is gone
    fresh = _fresh()
    plan = fresh.pre_spawn(PKG)
    assert plan is not None
    assert plan.disruptive
    assert set(fresh._applied[SERIAL].settled) == {"locale"}


def test_a_new_fingerprint_means_not_applied(service, device, app_start):
    service.apply(SERIAL, PKG)
    service.regenerate(service.config().profile)
    fresh = _fresh()
    plan = fresh.pre_spawn(PKG)
    assert plan is not None
    assert plan.disruptive
    assert fresh.applied_state(PKG) == "not_applied"


def test_disruptive_only_while_a_framework_value_is_pending(service, device, app_start):
    device.ignore.add("device_name")  # a live value fails: the app is not done
    service.apply(SERIAL, PKG)
    assert _record(device)["done"] == []
    for svc in (service, _fresh()):
        plan = svc.pre_spawn(PKG)
        assert plan is not None
        assert not plan.disruptive  # Android ID and locale are on the device
        assert svc.pre_spawn("com.other.app").disruptive  # a new Android ID
    # An interrupted restart window: the next apply restarts.
    device.fs[RESTART_MARKER] = b"x 1 android_id"
    assert service.pre_spawn(PKG).disruptive


def test_applied_state_hydrates_in_the_background(
    service, device, app_start, monkeypatch
):
    service.apply(SERIAL, PKG)
    fresh = _fresh()
    heard: list = []
    fresh.add_status_listener(heard.append)
    threads: list = []
    gate = ident.threading.Event()
    real_send = ident._send

    def send(command, serial, timeout=60):
        threads.append(ident.threading.current_thread())
        assert gate.wait(5)
        return real_send(command, serial, timeout)

    monkeypatch.setattr(ident, "_send", send)
    # Memory only: the answer comes at once, before the device was read.
    assert fresh.applied_state(PKG) == "not_applied"
    assert fresh.applied_state(PKG) == "not_applied"  # one read at a time
    gate.set()
    fresh._join_hydration(5)
    assert len(threads) == 1
    assert threads
    assert ident.threading.main_thread() not in threads
    assert len(heard) == 1  # the answer changed
    assert fresh.applied_state(PKG) == "applied"
    assert fresh.last_apply(SERIAL)[0] == _record(device)["at"]
    # Once per serial.
    fresh._join_hydration(5)
    assert device.record_reads == 1


def test_a_hydration_never_overwrites_a_newer_apply(service, device):
    read = service._read_record(SERIAL)  # before the apply: no record
    assert read is not None
    assert read.record is None
    service.apply(SERIAL, PKG)
    assert service._hydrate(SERIAL, read, gen=0) is False
    assert PKG in service._applied[SERIAL].done


def test_last_apply_follows_apply_and_verify(service, device, monkeypatch):
    fp = ident.fingerprint(service.active_profile())
    assert service.last_apply(SERIAL, fp) is None
    service._join_hydration(5)
    now = [1000.0]
    service._now = lambda: now[0]
    service.apply(SERIAL, PKG)
    assert service.last_apply(SERIAL, fp) == (1000.0, 1000.0)
    now[0] = 2000.0
    service.verify(SERIAL)
    assert service.last_apply(SERIAL, fp) == (1000.0, 2000.0)
    assert service.last_apply(SERIAL, "other-fingerprint") is None


def test_applied_record_parse_rejects_garbage():
    assert ident.parse_applied_record("") is None
    assert ident.parse_applied_record("{") is None
    assert ident.parse_applied_record('{"format": "other"}') is None
    mem = ident._Applied(fingerprint="f", done={PKG})
    mem.seeded = {PKG: "3f9a1c07deadbeef"}
    mem.installs = {PKG: "10123:5000"}
    mem.ssaids = {PKG: "3f9a1c07deadbeef", "com.old": "x"}
    mem.settled = {"locale": False}
    mem.unappliable = {"build_model"}
    record = ident.applied_record("p", "f", mem, "boot", 12.5)
    assert ident.parse_applied_record(ident.json.dumps(record)) == record
    assert record["ssaids"] == {PKG: "3f9a1c07deadbeef"}  # only seeded ones
    assert record["installs"] == {PKG: "10123:5000"}
    assert record["unappliable"] == ["build_model"]
    # Sub-second noise is the same record; a later second is a new one.
    sig = ident._record_sig(record)
    assert ident._record_sig(dict(record, at=12.9)) == sig
    assert ident._record_sig(dict(record, at=13.0)) != sig
    assert (
        ident.parse_applied_record(ident.json.dumps(dict(record, installs=[]))) is None
    )
    bad = dict(record, done=[1])
    assert ident.parse_applied_record(ident.json.dumps(bad)) is None
    newer = dict(record, version=2)
    assert ident.parse_applied_record(ident.json.dumps(newer)) is None


# ---------------------------------------------------------------------------
# device record: review round (false "applied" paths)
# ---------------------------------------------------------------------------


def test_a_start_never_restarts_unannounced(service, device, app_start):
    """The record says the locale is on the device, so the start is not
    announced as disruptive; the device disagrees (someone changed it). The
    apply then does no restart: the locale stays pending, the app is not
    done, and the next start asks.
    """
    service.apply(SERIAL, PKG)
    pid = device.pid
    device.fs[ident.BOOT_ID_FILE] = b"boot-2\n"  # reboot: done is gone
    device.props["persist.sys.locale"] = "en-US"
    plan = service.pre_spawn(PKG)
    assert not plan.disruptive
    # The locale stays pending: no restart, and the app does not start.
    with pytest.raises(ident.IdentityApplyError, match="start the app again"):
        plan.apply()
    assert device.pid == pid  # no framework restart
    assert device.props["persist.sys.locale"] == "en-US"
    assert PKG not in _record(device)["done"]
    assert "locale" not in _record(device)["framework"]
    assert service.pre_spawn(PKG).disruptive


def test_hydration_backs_off_while_an_apply_runs(service, device):
    read = service._read_record(SERIAL)
    with service._apply_lock:
        assert service._hydrate(SERIAL, read, gen=0) is False
    assert SERIAL not in service._hydrated
    service._hydrate(SERIAL, read, gen=0)
    assert SERIAL in service._hydrated


def test_finish_skips_the_record_of_another_fingerprint(service, device, monkeypatch):
    """A plan of another profile reset memory while the apply ran: neither
    memory nor the device record take this apply's results.
    """
    real_emit = service._emit

    def emit(kind, *args, **kwargs):
        if kind == "verify":
            service._applied[SERIAL].fingerprint = "other-profile"
        return real_emit(kind, *args, **kwargs)

    monkeypatch.setattr(service, "_emit", emit)
    service.apply(SERIAL, PKG)
    assert ident.APPLIED_FILE not in device.fs
    assert service._applied[SERIAL].done == set()


def test_gen_moves_after_the_record_write(service, device, monkeypatch):
    seen: list[int] = []
    real_write = service._write_record

    def write(serial, record):
        seen.append(service._applied[serial].gen)
        return real_write(serial, record)

    monkeypatch.setattr(service, "_write_record", write)
    service.apply(SERIAL, PKG)
    assert seen
    # A read that began before (or during) the write backs off.
    assert service._applied[SERIAL].gen > seen[-1]
    read = ident._RecordRead(None, "boot-1", "")
    assert service._hydrate(SERIAL, read, gen=seen[-1]) is False
    assert PKG in service._applied[SERIAL].done


def test_hydration_merges_ssaids_only_for_the_same_fingerprint(service):
    record = ident.applied_record(
        "p",
        "fp-b",
        ident._Applied(seeded={PKG: "bbbb"}, installs={PKG: "1:2"}),
        "boot-1",
        NOW,
    )
    read = ident._RecordRead(record, "boot-1", "")
    service._applied[SERIAL] = ident._Applied(fingerprint="fp-a", ssaids={PKG: "aaaa"})
    service._hydrate(SERIAL, read, gen=0)
    mem = service._applied[SERIAL]
    assert mem.ssaids == {PKG: "aaaa"}  # profile A's value stays for the markers
    assert mem.seeded == {PKG: "bbbb"}
    assert mem.fingerprint == "fp-b"
    # A fresh process (nothing known) or the same profile: merged.
    service._applied[SERIAL] = ident._Applied()
    service._hydrate(SERIAL, read, gen=0)
    assert service._applied[SERIAL].ssaids == {PKG: "bbbb"}


def test_a_failed_record_write_removes_or_marks_the_record(service, device, app_start):
    service.apply(SERIAL, PKG)
    now = [NOW]
    service._now = lambda: now[0]
    # The write fails, the removal works: the device reads as unknown.
    device.fail_cmds.add("mv")
    now[0] += 10
    service.apply(SERIAL, PKG)
    assert ident.APPLIED_FILE not in device.fs
    assert SERIAL not in service._record_dirty
    fresh = _fresh()
    assert fresh.pre_spawn(PKG) is not None
    # Even the removal fails: the stale record is ignored until a write works.
    stale = ident.json.dumps(
        dict(_stale_record(service), done=[PKG, "com.other.app"])
    ).encode()
    device.fs[ident.APPLIED_FILE] = stale
    device.fail_cmds.add("rm")
    now[0] += 10
    service.apply(SERIAL, PKG)
    assert device.fs[ident.APPLIED_FILE] == stale
    assert SERIAL in service._record_dirty
    service.pre_spawn("com.other.app")
    assert "com.other.app" not in service._applied[SERIAL].done
    assert service.applied_state("com.other.app") == "not_applied"
    device.fail_cmds.clear()
    now[0] += 10
    service.apply(SERIAL, PKG)
    assert SERIAL not in service._record_dirty
    assert _record(device)["done"] == [PKG]


def _stale_record(service) -> dict:
    mem = service._applied[SERIAL]
    return ident.applied_record("p", mem.fingerprint, mem, mem.boot_id, NOW)


def test_a_reinstalled_app_is_not_done_and_not_seeded(service, device, app_start):
    service.apply(SERIAL, PKG)
    assert _record(device)["installs"] == {PKG: device.install(PKG)}
    device.reinstall(PKG)
    for svc in (service, _fresh()):
        plan = svc.pre_spawn(PKG)
        assert plan is not None
        assert plan.disruptive  # its new Android ID needs a restart
        assert PKG not in svc._applied[SERIAL].seeded
    plan.apply()
    assert device.ssaid[PKG].startswith(TOKEN)
    assert service.pre_spawn(PKG) is None


def test_done_needs_the_android_id_seeded(service, device, app_start):
    service.apply(SERIAL, PKG, allow_restart=False)
    record = _record(device)
    assert record["done"] == []
    assert record["ssaids"] == {}
    assert "locale" not in record["framework"]
    plan = _fresh().pre_spawn(PKG)
    assert plan.disruptive


def test_structural_failures_do_not_make_starts_disruptive(service, device, app_start):
    profile = service.active_profile()
    profile.values["build_model"].enabled = True
    service.save(profile)
    device.resetprop = False
    plan = service.apply(SERIAL, PKG)
    assert plan.infos["build_model"].reason == ident.NO_RESETPROP
    assert _record(device)["unappliable"] == ["build_model"]
    for svc in (service, _fresh()):
        again = svc.pre_spawn(PKG)
        assert again is not None  # build_model failed: not done
        assert not again.disruptive  # but no restart can apply it here
    # resetprop appears: the next apply plans it again (a start asks then).
    device.resetprop = True
    service.apply(SERIAL, PKG, allow_restart=False)
    assert service._applied[SERIAL].unappliable == set()
    assert service.pre_spawn(PKG).disruptive


def test_no_root_makes_no_start_disruptive(service, device, app_start):
    device.root = False
    service.apply(SERIAL, PKG)
    assert {"android_id", "locale"} <= service._applied[SERIAL].unappliable
    assert not service.pre_spawn(PKG).disruptive


def test_forget_drops_the_times_and_reads_the_record_again(service, device):
    service.apply(SERIAL, PKG)
    fp = ident.fingerprint(service.active_profile())
    heard: list = []
    service.add_status_listener(heard.append)
    service._hydrated.add(SERIAL)
    service.forget(SERIAL)
    assert heard
    assert service._applied[SERIAL].applied_at == 0.0
    assert SERIAL not in service._hydrated
    # The next look reads the record again (in the background).
    service.last_apply(SERIAL, fp)
    service._join_hydration(5)
    assert service.last_apply(SERIAL, fp) == (NOW, NOW)  # both from the record
    # A record that is gone (a snapshot from before): no times at all.
    del device.fs[ident.APPLIED_FILE]
    service.forget()
    service.last_apply(SERIAL, fp)
    service._join_hydration(5)
    assert service.last_apply(SERIAL, fp) is None
    assert service.applied_state(PKG) == "not_applied"


def test_snapshot_loads_and_device_switches_forget(monkeypatch):
    from sandroid.services import emulator_service

    calls: list = []
    fake = types.SimpleNamespace(
        forget=lambda serial=None, restored=False: calls.append((serial, restored))
    )
    monkeypatch.setattr(ident, "get_identity_service", lambda: fake)
    monkeypatch.setattr(
        "sandroid.core.timeline.get_timeline",
        lambda: types.SimpleNamespace(on_world_change=lambda *a, **k: None),
    )
    emulator_service._world_change("snapshot-load", src="snapshot", dev=SERIAL)
    emulator_service._world_change("cold-boot", src="device", dev=None)
    assert calls == [(SERIAL, True), (None, True)]

    from sandroid import services
    from sandroid.core.device_manager import DeviceManager

    stub = types.SimpleNamespace(stop_all=lambda: None, reset=lambda: None)
    monkeypatch.setattr(services, "get_task_service", lambda: stub)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: stub)
    manager = DeviceManager.__new__(DeviceManager)
    manager._reset_device_state()
    assert calls == [(SERIAL, True), (None, True), (None, False)]


def test_a_thread_that_does_not_start_is_not_registered(service, monkeypatch):
    class NoStart(ident.threading.Thread):
        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(ident.threading, "Thread", NoStart)
    service._ensure_hydrated(SERIAL)
    assert service._hydrate_threads == {}
    assert service._hydrating == set()
    # An unstarted thread in the table does not break the join.
    service._hydrate_threads[SERIAL] = NoStart(target=lambda: None)
    service._join_hydration(1)


def test_a_later_apply_rewrites_the_record_time(service, device):
    now = [NOW]
    service._now = lambda: now[0]
    service.apply(SERIAL, PKG)
    assert _record(device)["at"] == NOW
    device.writes.clear()
    now[0] = NOW + 0.4  # the same second: nothing written
    service.apply(SERIAL, PKG)
    assert device.writes == []
    now[0] = NOW + 5
    service.apply(SERIAL, PKG)
    assert _record(device)["at"] == NOW + 5
    assert all("identity.applied" in w for w in device.writes)  # only the record


def test_the_start_read_is_one_short_round_trip(
    service, device, app_start, monkeypatch
):
    service.apply(SERIAL, PKG)
    timeouts: list = []
    real_send = ident._send

    def send(command, serial, timeout=60):
        timeouts.append(timeout)
        return real_send(command, serial, timeout)

    monkeypatch.setattr(ident, "_send", send)
    assert _fresh().pre_spawn(PKG) is None
    assert len(timeouts) == 1
    assert timeouts[0] <= 3


# ---------------------------------------------------------------------------
# device record: second review round
# ---------------------------------------------------------------------------


def test_no_native_android_id_is_done_once(service, device, app_start):
    """With the Android ID hook-only no install identity is recorded; the
    app is done after one apply and later starts touch nothing.
    """
    profile = service.active_profile()
    profile.values["android_id"].provider = "hook"
    service.save(profile)
    now = [NOW]
    service._now = lambda: now[0]
    service.apply(SERIAL, PKG)
    assert _record(device)["done"] == [PKG]
    assert _record(device)["installs"] == {}
    for _ in range(3):
        now[0] += 5
        device.writes.clear()
        assert service.pre_spawn(PKG) is None
        assert _fresh().pre_spawn(PKG) is None
        assert device.writes == []


def test_an_unreadable_install_does_not_undo_done(service, device, app_start):
    service.apply(SERIAL, PKG)
    device.stat_down = True  # e.g. adbd lost root: stat prints nothing
    assert service.pre_spawn(PKG) is None
    assert _fresh().pre_spawn(PKG) is None


def test_a_stale_unappliable_entry_never_starts_the_app_unseeded(
    service, device, app_start, monkeypatch
):
    profile = service.active_profile()
    profile.values["build_model"].enabled = True
    service.save(profile)
    device.resetprop = False
    service.apply(SERIAL, PKG)
    assert service._applied[SERIAL].unappliable == {"build_model"}
    device.resetprop = True  # Magisk arrived
    plan = service.pre_spawn(PKG)
    assert not plan.disruptive  # memory still says it cannot be applied
    pid = device.pid
    with pytest.raises(ident.IdentityApplyError, match="framework restart"):
        plan.apply()
    assert device.pid == pid  # no unannounced restart
    assert service._applied[SERIAL].unappliable == set()
    assert service.pre_spawn(PKG).disruptive  # the next start asks
    # The restart policy "never": nothing to confirm, the app starts.
    monkeypatch.setattr(service.config(), "restart", "never")
    service.pre_spawn(PKG).apply()


def test_every_preflight_relearns_unappliable(service, device, app_start):
    profile = service.active_profile()
    profile.values["build_model"].enabled = True
    service.save(profile)
    device.resetprop = False
    service.apply(SERIAL, PKG)
    device.resetprop = True
    service.plan(SERIAL, PKG)  # a plain read (the lens, a verify)
    assert service._applied[SERIAL].unappliable == set()
    assert service.pre_spawn(PKG).disruptive


def test_forget_moves_gen_and_clears_the_dirty_mark(service, device):
    service.apply(SERIAL, PKG)
    gen = service._applied[SERIAL].gen
    service._record_dirty.update({SERIAL, "emulator-5582"})
    service.forget(SERIAL, restored=True)
    assert service._applied[SERIAL].gen > gen
    assert service._record_dirty == {"emulator-5582"}
    read = service._read_record(SERIAL)
    assert service._hydrate(SERIAL, read, gen=gen) is False  # started before
    service.forget()  # a device switch: the device record is still stale
    assert service._record_dirty == {"emulator-5582"}
    service.forget(restored=True)  # a snapshot load or cold boot
    assert service._record_dirty == set()


def test_the_record_keeps_the_verify_time(service, device):
    now = [NOW]
    service._now = lambda: now[0]
    service.apply(SERIAL, PKG)
    assert _record(device)["verified_at"] == NOW
    now[0] = NOW + 60
    service.verify(SERIAL)  # no write outside apply
    assert _record(device)["verified_at"] == NOW
    now[0] = NOW + 120
    service.apply(SERIAL, PKG)
    assert _record(device)["verified_at"] == NOW + 120
    fresh = _fresh()
    fresh.last_apply(SERIAL)
    fresh._join_hydration(5)
    assert fresh.last_apply(SERIAL) == (NOW + 120, NOW + 120)


def test_an_uninstalled_app_leaves_the_per_app_set(service, device, app_start):
    other = "com.other.app"
    service.apply(SERIAL, other)
    service.apply(SERIAL, PKG)
    assert set(_record(device)["ssaids"]) == {PKG, other}
    del device.packages[other]
    device.fs[ident.BOOT_ID_FILE] = b"boot-2\n"  # PKG needs an apply again
    plan = service.pre_spawn(PKG)
    plan.apply()
    record = _record(device)
    assert record["done"] == [PKG]
    assert set(record["ssaids"]) == {PKG}
    assert other not in service._applied[SERIAL].ssaids
    assert service.pre_spawn(PKG) is None


def test_android_id_markers_keep_their_id_whichever_app_was_applied():
    """A per-app Android ID is always ``android_id@<package>``: an apply for
    another app reorders the markers but renames none (the privacy scan
    keys its coverage and findings on them).
    """
    profile = _profile()
    ssaids = {"com.a": "1111aaaa2222bbbb", "com.b": "3333cccc4444dddd"}

    def android_ids(markers: list[Marker]) -> list[tuple[str, str]]:
        return [(m.id, m.value) for m in markers if m.id.startswith("android_id")]

    first = android_ids(ident.markers_for(profile, ssaids, "com.a"))
    second = android_ids(ident.markers_for(profile, ssaids, "com.b"))
    assert first == [
        ("android_id@com.a", "1111aaaa2222bbbb"),
        ("android_id@com.b", "3333cccc4444dddd"),
    ]
    assert second == first[::-1]  # the applied app first


def test_older_frozen_records_get_the_per_app_android_id():
    """Records frozen before the per-app ids gave the applied app's Android
    ID the plain id: it is read back as ``android_id@<package>``.
    """
    record = {
        "ssaid": {"com.a": {"value": "1111aaaa2222bbbb", "signer": "x"}},
        "markers": [
            {"id": "android_id", "value": "1111aaaa2222bbbb", "kind": "hex_id"},
            {"id": "android_id@com.b", "value": "3333cccc4444dddd", "kind": "hex_id"},
            {"id": "label", "value": "1111aaaa2222bbbb", "kind": "text"},
        ],
    }
    ids = [m.id for m in ident._frozen_markers(record)]
    assert ids == ["android_id@com.a", "android_id@com.b", "label"]
    # Two apps with one value: the applied one (its label names it) wins.
    shared = {
        "ssaid": {
            "com.a": {"value": "5555eeee6666ffff"},
            "com.z": {"value": "5555eeee6666ffff"},
        },
        "markers": [
            {
                "id": "android_id",
                "value": "5555eeee6666ffff",
                "kind": "hex_id",
                "label": "Android ID (com.a)",
            }
        ],
    }
    assert [m.id for m in ident._frozen_markers(shared)] == ["android_id@com.a"]
    shared["markers"][0]["label"] = "Android ID (com.z)"
    assert [m.id for m in ident._frozen_markers(shared)] == ["android_id@com.z"]
