"""Prepare pipeline against a recording stub device (no adb, no emulator)."""

from __future__ import annotations

import datetime as dt
import io
import json
import re
import shlex
import zipfile
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from PIL import Image

from sandroid.world import PackSet, generate
from sandroid.world import prepare as pr
from sandroid.world.content import file_bytes, pdf_bytes
from sandroid.world.helper import JAR_SHA256, REMOTE_JAR, HelperError, ShellResult
from sandroid.world.photos import PhotoFetch

PACKS = PackSet(user_dir=False)
SERIAL = "emulator-5998"
OWNER = {"first": "Mara", "last": "Keller", "phone": "+4915112345678"}
ANCHOR = dt.datetime(2026, 11, 20, 15, 30, tzinfo=ZoneInfo("Europe/Berlin"))
SPEC = {
    "seed": "hex:" + "3c" * 16,
    "size": "small",
    "country": "de",
    "counts": {"photos": 6, "files": 4, "notes": 3},
}


@pytest.fixture(scope="module")
def manifest():
    return generate(SPEC, OWNER, packs=PACKS)


@pytest.fixture(scope="module")
def world(manifest):
    return manifest.render(ANCHOR)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("SDROID_WORLD_PHOTOS_DIR", raising=False)

    def fake_fetch(entries, cache=None, **kw):
        out = PhotoFetch()
        for e in entries:
            path = tmp_path / "src" / f"{e['id']}{Path(e['file']).suffix}"
            path.parent.mkdir(exist_ok=True)
            fmt = "PNG" if path.suffix == ".png" else "JPEG"
            Image.new("RGB", (48, 32), (90, 120, 150)).save(path, format=fmt)
            out.paths[e["id"]] = path
        return out

    monkeypatch.setattr(pr, "ensure_photos", fake_fetch)


# ---------------------------------------------------------------- the stub


class FakeHelper:
    def __init__(self, dev: FakeDevice) -> None:
        self.dev = dev
        self.next_id = 1000
        self.rows: dict[str, list[int]] = {}
        self.sync_auto = True
        self.closed = False

    def _ids(self, name: str, n: int) -> list[int]:
        ids = list(range(self.next_id, self.next_id + n))
        self.next_id += n
        self.rows.setdefault(name, []).extend(ids)
        if name in self.dev.refuse:
            ids[0] = -1
        return ids

    def request(self, cmd: str, *, timeout: float = 120, **kw):
        self.dev.log.append(f"helper:{cmd}")
        if self.dev.helper_fails == cmd:
            raise HelperError(f"world helper {cmd}: boom")
        if cmd == "count" and "totals" in kw:
            return {"totals": dict.fromkeys(kw["totals"], 3)}
        if cmd == "count":
            return {"counts": {k: len(v) for k, v in kw["lists"].items()}}
        if cmd == "contacts":
            assert self.dev.offline
            return {"ids": self._ids("contacts", len(kw["items"]))}
        if cmd == "calendar":
            cal = kw.get("calendar_id")
            if cal is None:
                cal = self._ids("calendars", 1)[0]
            return {
                "calendar_id": cal,
                "ids": self._ids("events", len(kw.get("items") or [])),
            }
        if cmd == "calls":
            return {"ids": self._ids("calls", len(kw["items"]))}
        if cmd == "sms":
            return {"ids": self._ids("sms", len(kw["items"])), "mode": "batch"}
        if cmd in ("sync_off", "sync_state"):
            if cmd == "sync_off":
                self.sync_auto = False
            return {
                "master": True,
                "rows": [
                    {"type": a["type"], "authority": auth, "auto": self.sync_auto}
                    for a in kw["accounts"]
                    for auth in kw["authorities"]
                ],
            }
        if cmd == "query":
            rows = []
            for name in kw["args"]:
                path = next(p for p in self.dev.files if p.endswith("/" + name))
                rel = path[len("/sdcard/") : -len(name) - 1] + "/"
                rows.append(
                    {
                        "_id": self._ids("images", 1)[0],
                        "_display_name": name,
                        "relative_path": rel,
                        "datetaken": self.dev.mtimes.get(path, 0) * 1000,
                    }
                )
            return {"rows": rows}
        if cmd == "delete":
            self.dev.deleted.append(kw["lists"])
            return {"deleted": {k: len(v) for k, v in kw["lists"].items()}}
        raise AssertionError(f"unexpected helper cmd {cmd}")

    def close(self) -> None:
        self.closed = True


class FakeDevice:
    """Answers the pipeline's shell scripts and records what happened."""

    def __init__(self, serial: str = SERIAL) -> None:
        self.serial = serial
        self.log: list[str] = []
        self.uid = "0"
        self.sdk = "35"
        self.free_kib = 8_000_000
        self.stamp: str = ""
        self.wifi = "1"
        self.data = "1"
        self.offline = False
        self.bmgr = "enabled"
        self.files: dict[str, int] = {}
        self.mtimes: dict[str, int] = {}
        self.pending_stamp: str | None = None
        self.stamps: list[dict] = []
        self.deleted: list[dict] = []
        self.refuse: set[str] = set()
        self.helper_fails: str | None = None
        self.helpers: list[FakeHelper] = []
        self.calls_seen: list[tuple[str, str]] = []
        self.now = int(ANCHOR.timestamp())

    # Device API

    def shell(self, script: str, *, timeout: float = 60, zygote: bool = False):
        self.calls_seen.append(("shell", script))
        out = []
        if "@@uid@@" in script:
            self.log.append("preflight")
            out += [
                "@@uid@@", self.uid, "@@sdk@@", self.sdk,
                "@@avd@@", "Dev9_test", "",
                "@@now@@", str(self.now),
                "@@df_sdcard@@",
                "Filesystem 1K-blocks Used Available Use% Mounted on",
                f"/dev/fuse 9000000 1000 {self.free_kib} 1% /storage/emulated",
                "@@df_data@@",
                "Filesystem 1K-blocks Used Available Use% Mounted on",
                f"/dev/block/dm-5 9000000 1000 {self.free_kib} 1% /data",
                "@@stamp@@", self.stamp,
                "@@wifi@@", self.wifi, "@@data@@", self.data,
                "@@accounts@@",
                "    Account {name=test.user@gmail.com, type=com.google}",
                "@@gms@@", "package:/system/priv-app/GmsCore.apk",
                "@@end@@",
            ]  # fmt: skip
            return ShellResult(0, "\n".join(out) + "\n", "")
        if script.startswith("sha256sum"):
            return ShellResult(0, f"{JAR_SHA256}  {REMOTE_JAR}\n", "")
        if "svc wifi disable" in script:
            self.log.append("offline")
            self.offline = True
            self.wifi_saved, self.wifi, self.data = self.wifi, "0", "0"
        if "svc wifi enable" in script or "svc data enable" in script:
            self.log.append("online")
            self.offline = False
            if "svc wifi enable" in script:
                self.wifi = "1"
            if "svc data enable" in script:
                self.data = "1"
        if "@@wifi@@" in script and "@@uid@@" not in script:
            out += ["@@wifi@@", self.wifi, "@@data@@", self.data]
        if "bmgr enable false" in script:
            self.log.append("bmgr_off")
            self.bmgr = "disabled"
        if script.strip() == "bmgr enabled":
            out.append(f"Backup Manager currently {self.bmgr}")
        if "am force-stop" in script:
            self.log.append("stop_messaging")
        if "touch -d" in script:
            self.log.append("touch")
            for m in re.finditer(r"touch -d @(\d+) ('[^']*'|[^;\s]+)", script):
                self.mtimes[shlex.split(m.group(2))[0]] = int(m.group(1))
        if "scan_volume" in script:
            self.log.append("scan")
        if script.startswith("rm -f /sdcard") or "rm -f '/sdcard" in script:
            self.log.append("rm_files")
            for p in shlex.split(script)[2:]:
                self.files.pop(p, None)
        if script == f"rm -f {pr.STAMP_PATH}":
            self.log.append("rm_stamp")
            self.stamp = ""
        if "&& echo stamped" in script:
            self.stamp = self.pending_stamp or ""
            rec = json.loads(self.stamp)
            self.stamps.append(rec)
            self.log.append(f"stamp:{rec['state']}")
            out.append("stamped")
        return ShellResult(0, "\n".join(out) + ("\n" if out else ""), "")

    def push(self, sources, remote, *, timeout: float = 600):
        self.calls_seen.append(("push", remote))
        if remote.endswith("world.json.tmp"):
            self.pending_stamp = Path(sources[0]).read_text()
            return ShellResult(0, "1 file pushed", "")
        self.log.append("push:" + ",".join(Path(s).name for s in sources))
        for src in sources:
            root = Path(src)
            for f in root.rglob("*"):
                if f.is_file():
                    rel = f.relative_to(root.parent).as_posix()
                    self.files[f"/sdcard/{rel}"] = f.stat().st_size
        return ShellResult(0, "pushed", "")

    def helper(self, *, timeout: float = 30):
        self.log.append("helper_start")
        h = FakeHelper(self)
        self.helpers.append(h)
        return h


def _run(manifest, dev: FakeDevice, **kw):
    return pr.prepare(SERIAL, manifest, anchor=ANCHOR, device=dev, packs=PACKS, **kw)


# ---------------------------------------------------------------- the run


def test_prepare_orders_offline_sync_seed_and_restore(manifest, world) -> None:
    dev = FakeDevice()
    report = _run(manifest, dev)
    assert report.ok
    log = dev.log
    first = log.index
    assert first("preflight") < first("stamp:partial") < first("offline")
    assert first("offline") < first("bmgr_off") < first("helper:sync_off")
    assert first("helper:sync_off") < first("helper:contacts")
    seeds = [first(f"helper:{c}") for c in ("contacts", "calendar", "calls", "sms")]
    assert seeds == sorted(seeds)
    assert log[first("helper:sms") - 1] == "stop_messaging"
    push = next(i for i, x in enumerate(log) if x.startswith("push:DCIM"))
    assert first("helper:sms") < push < first("scan")
    assert first("scan") < first("stamp:complete") < first("online")
    assert log.index("online") > max(
        i
        for i, x in enumerate(log)
        if x.startswith("helper:") and x != "helper:sync_state"
    )
    assert "helper:sync_state" in log[first("online") :]
    assert dev.wifi == "1"
    assert dev.data == "1"
    assert report.network == {
        "before": {"wifi": True, "data": True},
        "after": {"wifi": True, "data": True},
    }
    assert dev.helpers[0].closed


def test_every_adb_call_goes_through_the_pinned_device(manifest) -> None:
    dev = FakeDevice()
    _run(manifest, dev)
    assert dev.calls_seen
    with pytest.raises(pr.PrepareError, match="not emulator-1"):
        pr.prepare("emulator-1", manifest, device=dev, packs=PACKS)


def test_counts_seeded_match_expected(manifest, world) -> None:
    dev = FakeDevice()
    report = _run(manifest, dev)
    exp = report.expected
    assert exp["contacts"] == len(world.contacts)
    assert exp["events"] == len(world.events)
    assert exp["calls"] == len(world.calls)
    assert exp["sms"] == len(world.sms)
    assert exp["photos"] == len(world.photos) == 6
    for key in ("contacts", "events", "calls", "sms", "photos", "files", "notes"):
        assert report.seeded[key] == exp[key], key
    assert report.preexisting["contacts"] == 3
    assert report.preexisting["accounts"] == [{"type": "com.google"}]
    assert "test.user@gmail.com" not in json.dumps(report.to_dict())
    assert report.backup["bmgr"] == "off"
    assert report.backup["sync"] == "off"
    assert report.backup["sync_after"] == "off"
    assert report.backup["contacts_backup"] == "unconfirmed"
    assert any("unconfirmed" in w for w in report.warnings)
    names = [s.name for s in report.steps]
    assert names[:2] == ["preflight", "offline"]
    assert names[-2:] == ["stamp", "online"]
    assert all(s.ok for s in report.steps)


def test_photos_and_files_land_with_their_times(manifest, world) -> None:
    dev = FakeDevice()
    _run(manifest, dev)
    camera = [p for p in dev.files if p.startswith("/sdcard/DCIM/Camera/PXL_")]
    shots = [p for p in dev.files if p.startswith("/sdcard/Pictures/Screenshots/")]
    assert len(camera) + len(shots) == len(world.photos)
    for f in world.files:
        sub = "Download" if f["dir"] == "Download" else "Documents"
        path = f"/sdcard/{sub}/{f['name']}"
        assert path in dev.files
        assert dev.mtimes[path] == f["ts_ms"] // 1000
    assert "/sdcard/Documents/Notizen.txt" in dev.files
    for path in camera + shots:
        assert path in dev.mtimes


def test_ledger_and_stamp_formats(manifest) -> None:
    dev = FakeDevice()
    report = _run(manifest, dev)
    path = Path(report.ledger_path)
    assert path.parent.name == "Dev9_test"
    assert path.name == f"{manifest.world_fp}.json"
    assert path.is_relative_to(pr.ledgers_dir())
    ledger = pr.Ledger.load(path)
    data = ledger.data
    assert data["format"] == pr.LEDGER_FORMAT
    assert data["state"] == "complete"
    assert data["serial"] == SERIAL
    assert data["anchor"] == ANCHOR.isoformat()
    assert data["account"] == {"name": "Personal", "type": "LOCAL"}
    h = dev.helpers[0]
    for name in ("contacts", "calendars", "events", "calls", "sms", "images"):
        assert data["lists"][name] == h.rows[name], name
    assert len(data["photos"]) == 6
    assert set(data["paths"]) == set(dev.files)
    partial, complete = dev.stamps
    assert partial["state"] == "partial"
    assert partial["ledger_sha256"] is None
    assert complete["state"] == "complete"
    assert set(complete) >= {
        "world_fp", "generator_version", "anchor", "prepared_at",
        "ledger_sha256", "counts",
    }  # fmt: skip
    assert complete["world_fp"] == manifest.world_fp
    assert complete["ledger_sha256"] == ledger.sha256()
    assert complete["counts"]["contacts"] == len(data["lists"]["contacts"])
    assert report.stamp == complete


def test_refused_rows_are_left_out_and_warned(manifest) -> None:
    dev = FakeDevice()
    dev.refuse = {"sms"}
    report = _run(manifest, dev)
    assert report.ok
    assert report.seeded["sms"] < report.expected["sms"]
    assert any(w.startswith("sms:") and "refused" in w for w in report.warnings)
    ledger = pr.Ledger.load(Path(report.ledger_path))
    assert all(i > 0 for i in ledger.data["lists"]["sms"])


# ---------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    ("attr", "value", "match"),
    [
        ("uid", "2000", "adb root"),
        ("free_kib", 1000, "MiB free"),
        (
            "stamp",
            json.dumps({"state": "complete", "world_fp": "ab" * 32}),
            "clean base",
        ),
        (
            "stamp",
            json.dumps({"state": "partial", "world_fp": "ab" * 32}),
            "force_cleanup",
        ),
    ],
)
def test_preflight_refusals_touch_nothing(manifest, attr, value, match) -> None:
    dev = FakeDevice()
    setattr(dev, attr, value)
    with pytest.raises(pr.PrepareError, match=match) as err:
        _run(manifest, dev)
    assert err.value.report is not None
    assert err.value.report.ok is False
    assert "offline" not in dev.log
    assert not any(x.startswith("stamp:") for x in dev.log)
    assert not any(x.startswith("helper:") and x != "helper:count" for x in dev.log)


def test_api_level_must_match_target_sdk() -> None:
    m = generate(SPEC, OWNER, packs=PACKS, target_sdk=34)
    dev = FakeDevice()
    with pytest.raises(pr.PrepareError, match="API 34"):
        _run(m, dev)


def test_default_anchor_is_the_device_clock(manifest) -> None:
    dev = FakeDevice()
    dev.now = int(ANCHOR.timestamp()) - 400 * 86400  # a stale snapshot clock
    report = pr.prepare(SERIAL, manifest, device=dev, packs=PACKS)
    want = dt.datetime.fromtimestamp(dev.now, ZoneInfo("Europe/Berlin"))
    assert report.anchor == want.isoformat()
    assert any("device clock" in w for w in report.warnings)


def test_a_tampered_manifest_is_refused(manifest) -> None:
    import copy

    bad = copy.deepcopy(manifest)
    bad.contacts[0]["display_name"] = "Changed"
    with pytest.raises(pr.PrepareError, match="world_fp"):
        _run(bad, FakeDevice())


def test_failure_mid_seed_restores_the_network(manifest) -> None:
    dev = FakeDevice()
    dev.helper_fails = "calls"
    with pytest.raises(pr.PrepareError, match="boom") as err:
        _run(manifest, dev)
    assert dev.log[-1] == "online" or "online" in dev.log
    assert dev.wifi == "1"
    assert dev.data == "1"
    report = err.value.report
    assert not report.ok
    assert [s.name for s in report.steps if not s.ok] == ["calls"]
    ledger = pr.Ledger.load(Path(report.ledger_path))
    assert ledger.data["state"] == "partial"
    assert ledger.data["lists"]["contacts"]  # written incrementally
    assert dev.stamps[-1]["state"] == "partial"


def test_interrupted_run_is_cleaned_with_force(manifest) -> None:
    dev = FakeDevice()
    dev.helper_fails = "sms"
    with pytest.raises(pr.PrepareError):
        _run(manifest, dev)
    old = pr.Ledger.load(Path(pr.ledger_path(SERIAL, "Dev9_test", manifest.world_fp)))
    seeded = {k: list(v) for k, v in old.data["lists"].items() if v}
    assert seeded
    dev.helper_fails = None
    with pytest.raises(pr.PrepareError, match="force_cleanup"):
        _run(manifest, dev)
    report = _run(manifest, dev, force_cleanup=True)
    assert report.ok
    assert dev.deleted[0] == seeded
    log = dev.log
    assert (
        log.index("helper:delete")
        < log.index("rm_stamp")
        < len(log) - log[::-1].index("stamp:partial") - 1
    )
    assert any("removed an interrupted world" in w for w in report.warnings)


def test_partial_stamp_without_ledger_is_refused(manifest) -> None:
    dev = FakeDevice()
    dev.stamp = json.dumps({"state": "partial", "world_fp": "cd" * 32})
    with pytest.raises(pr.PrepareError, match="ledger is missing"):
        _run(manifest, dev, force_cleanup=True)
    assert "offline" not in dev.log


# ---------------------------------------------------------------- payloads


def test_contact_payload(world) -> None:
    items = pr.contact_items(world)
    assert len(items) == len(world.contacts)
    starred = [c for c in world.contacts if c["starred"]]
    assert sum(i["raw"]["starred"] for i in items) == len(starred)
    first, c0 = items[0], world.contacts[0]
    name = first["data"][0]
    assert name["mimetype"] == "vnd.android.cursor.item/name"
    assert name["data1"] == c0["display_name"]
    phones = [d for d in first["data"] if d["mimetype"].endswith("phone_v2")]
    assert [p["data1"] for p in phones] == [p["number"] for p in c0["phones"]]
    assert all("account" not in k for k in first["raw"])


def test_event_payload_all_day_and_birthdays(world) -> None:
    tz = ZoneInfo("Europe/Berlin")
    items = pr.event_items(world, tz)
    assert len(items) == len(world.events)
    for row in items:
        if row["allDay"]:
            assert row["eventTimezone"] == "UTC"
            assert row["dtstart"] % 86_400_000 == 0
        else:
            assert row["eventTimezone"] == "Europe/Berlin"
            assert row["dtend"] > row["dtstart"]
    yearly = [r for r in items if r.get("rrule")]
    assert yearly
    assert all(r["rrule"] == "FREQ=YEARLY" and "dtend" not in r for r in yearly)
    assert [r["dtstart"] for r in items] == sorted(r["dtstart"] for r in items)


def test_call_and_sms_payloads(world) -> None:
    calls = pr.call_items(world)
    assert [c["date"] for c in calls] == sorted(c["date"] for c in calls)
    assert {c["type"] for c in calls} <= {1, 2, 3}
    assert all(c["duration"] == 0 for c in calls if c["type"] == 3)
    known = {p["number"] for c in world.contacts for p in c["phones"]}
    assert all("name" in c for c in calls if c["number"] in known)
    sms = pr.sms_items(world)
    assert len(sms) == len(world.sms)
    assert {m["type"] for m in sms} <= {1, 2}
    alnum = [m for m in world.sms if m["sender_type"] == "alphanumeric"]
    assert {m["address"] for m in alnum} <= {s["address"] for s in sms}


def test_world_timezone_and_language(manifest) -> None:
    assert pr.world_timezone(manifest, PACKS).key == "Europe/Berlin"
    assert pr.owner_language(manifest, PACKS) == "de"


def test_persona_snapshot_name() -> None:
    name = pr.persona_snapshot_name("Mara Keller (DE)", "a" * 64, "B" * 64)
    assert name == f"sandroid_persona_mara-keller-de_{'a' * 12}_{'b' * 12}"
    with pytest.raises(ValueError):
        pr.persona_snapshot_name("!!", "a" * 64, "b" * 64)
    with pytest.raises(ValueError):
        pr.persona_snapshot_name("x", "", "b" * 64)


def test_device_key_is_a_safe_folder() -> None:
    assert pr.device_key("emulator-5554", None) == "emulator-5554"
    assert pr.device_key("x", "Dev 1/../2") == "Dev_1_.._2"
    assert pr.device_key("192.168.0.5:5555", None) == "192.168.0.5_5555"


# ---------------------------------------------------------------- contents


def test_pdf_is_well_formed() -> None:
    data = pdf_bytes(["Rechnung März", "2026-01-02"])
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    start = int(data.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    assert data[start : start + 4] == b"xref"
    assert b"(Rechnung M\xe4rz) Tj" in data


@pytest.mark.parametrize(
    ("name", "part"),
    [
        ("Lebenslauf.docx", "word/document.xml"),
        ("Budget.xlsx", "xl/worksheets/sheet1.xml"),
        ("Vortrag.pptx", "ppt/slides/slide1.xml"),
    ],
)
def test_office_files_are_zip_packages(name: str, part: str) -> None:
    when = dt.datetime(2025, 3, 4, 10, 0, tzinfo=dt.UTC)
    data = file_bytes(name, ["Titel & <Sonder>", "2025-03-04"], when)
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert "[Content_Types].xml" in zf.namelist()
    text = zf.read(part).decode()
    assert "Titel &amp; &lt;Sonder&gt;" in text
    assert zf.getinfo(part).date_time[:3] == (2025, 3, 4)


@pytest.mark.parametrize("name", ["Scan.jpg", "Quittung.png"])
def test_image_files_have_no_metadata(name: str) -> None:
    data = file_bytes(name, ["Quittung"], dt.datetime(2025, 1, 1, tzinfo=dt.UTC))
    im = Image.open(io.BytesIO(data))
    assert not im.getexif()
    assert im.format == ("PNG" if name.endswith("png") else "JPEG")


def test_text_ics_vcf_files() -> None:
    when = dt.datetime(2025, 1, 1, 12, tzinfo=dt.UTC)
    assert file_bytes("a.txt", ["x", "y"], when) == b"x\ny\n"
    assert b"BEGIN:VCALENDAR" in file_bytes("a.ics", ["Termin"], when)
    assert file_bytes("a.ics", ["T"], when) == file_bytes("a.ics", ["T"], when)
    assert b"FN:Anna" in file_bytes("a.vcf", ["Anna"], when)
