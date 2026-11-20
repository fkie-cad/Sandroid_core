"""Tests for the JSON-first report engine (``core/report_engine.py``) and its
renderers (``core/report_render.py``), plus the report parts of
``run_report.finalize_run`` / ``report_from_folder`` and the manifest.

The timeline core (``sandroid.core.timeline``, WP1) is replaced by a fake in
``sys.modules``: a plain JSON-lines reader honouring ``end``, ``mask``,
``should_mask``, ``Seal``, ``seal_file`` and a fake service. Fixture timelines
are hand-written lines in the frozen envelope (the hash chain is irrelevant
here). Two tests at the end use the real module once it exists.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import types
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core import report_engine, report_render, run_report

TZ = timezone(timedelta(hours=1))
BASE = datetime(2026, 11, 19, 12, 0, 0, tzinfo=TZ)
SERIAL = "emulator-5554"
SESSION_ID = "20261119_120000/Pixel_API_35"
RUN_ID = "20261119-121000-ab12"
PASSWORD = "hunter22"  # noqa: S105 - fixture value


# ---------------------------------------------------------------------------
# Fake timeline module
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeSeal:
    path: str
    session_id: str
    seq_first: int
    seq_last: int
    last_h: str
    sha256: str
    bytes: int
    verified: bool
    seal_seq: int | None


def _fake_mask(line: dict) -> dict:
    if not line.get("sensitive"):
        return line
    out = copy.deepcopy(line)
    data = out.get("data")
    if isinstance(data, dict):
        out["data"] = {"_masked": True, "keys": sorted(data)}
    if isinstance(out.get("ref"), dict) and "raw" in out["ref"]:
        out["ref"]["raw"] = "•••"
    return out


def _fake_read_lines(path, *, start=0, end=None, reader="ui", mask_sensitive=None):
    data = Path(path).read_bytes()
    if end is not None:
        data = data[:end]
    mask_on = FAKE_STATE["mask"] if mask_sensitive is None else mask_sensitive
    FAKE_STATE["reads"].append({"path": str(path), "end": end, "reader": reader})
    offset = 0
    for raw in data.split(b"\n"):
        if raw.strip() and offset >= start:
            try:
                line = json.loads(raw)
            except ValueError:
                line = None  # a torn fragment (declared by the next resume)
            if isinstance(line, dict):
                yield offset, (_fake_mask(line) if mask_on else line)
        offset += len(raw) + 1


def _fake_seal_file(path) -> FakeSeal:
    path = Path(path)
    data = path.read_bytes()
    keep = data[: data.rfind(b"\n") + 1]
    lines = []
    for raw in keep.split(b"\n"):
        try:
            line = json.loads(raw)
        except ValueError:
            continue  # empty or torn
        if isinstance(line, dict):
            lines.append(line)
    opened = next((ln for ln in lines if ln.get("kind") == "open"), {})
    return FakeSeal(
        path=str(path),
        session_id=(opened.get("data") or {}).get("session_id") or SESSION_ID,
        seq_first=lines[0]["seq"] if lines else 0,
        seq_last=lines[-1]["seq"] if lines else 0,
        last_h="f" * 64,
        sha256=hashlib.sha256(keep).hexdigest(),
        bytes=len(keep),
        verified=True,
        seal_seq=None,
    )


class FakeService:
    """``get_timeline()`` stand-in: one bound sink at ``folder`` (or none)."""

    def __init__(self, folder: Path | None, state: str = "open"):
        self.folder = folder
        self.state = state
        self.seals: list[dict] = []

    def status(self, dev=None):
        return SimpleNamespace(
            folder=str(self.folder) if self.folder else None,
            serial=SERIAL,
            session_id=SESSION_ID,
            state=self.state,
            lines=0,
            bytes=0,
            queued=0,
            dropped={},
            locked_by="PID 4711 on host" if self.state == "locked" else None,
        )

    def seal(self, *, by, dev=None, report=None, timeout=5.0):
        path = Path(self.folder) / "timeline.jsonl"
        seal = _fake_seal_file(path)
        self.seals.append({"by": by, "report": report})
        # Like the real service: the seal line is appended after the seal.
        line = {
            "v": 1,
            "seq": seal.seq_last + 1,
            "t": BASE.isoformat(timespec="milliseconds"),
            "src": "sandroid",
            "kind": "seal",
            "summary": "seal",
            "data": {"by": by, "report": report},
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        return FakeSeal(**{**asdict(seal), "seal_seq": seal.seq_last + 1})


FAKE_STATE: dict = {"mask": False, "service": None, "reads": []}


@pytest.fixture
def fake_timeline(monkeypatch):
    """Install the fake ``sandroid.core.timeline``; returns its state dict."""
    mod = types.ModuleType("sandroid.core.timeline")
    mod.FILE_NAME = "timeline.jsonl"
    mod.LOCK_NAME = ".timeline.lock"
    mod.Seal = FakeSeal
    mod.read_lines = _fake_read_lines
    mod.mask = _fake_mask
    mod.should_mask = lambda reader="ui": FAKE_STATE["mask"]
    mod.seal_file = _fake_seal_file
    mod.verify_chain = lambda path, upto=None: SimpleNamespace(ok=True)
    mod.reset_for_tests = lambda: None
    mod.get_timeline = lambda: FAKE_STATE["service"] or FakeService(None, "detached")
    FAKE_STATE.update(mask=False, service=None, reads=[])
    monkeypatch.setitem(sys.modules, "sandroid.core.timeline", mod)
    return FAKE_STATE


# ---------------------------------------------------------------------------
# Fixture timeline (envelope v1, §4 shapes)
# ---------------------------------------------------------------------------


def _png(path: Path, color, label: str = "") -> str:
    from PIL import Image, ImageDraw

    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (270, 600), (245, 245, 245))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 270, 56], fill=color)
    draw.rectangle([30, 420, 240, 470], fill=(12, 154, 124))
    draw.text((40, 438), label, fill=(255, 255, 255))
    draw.text((12, 20), "com.x", fill=(255, 255, 255))
    img.save(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TimelineFixture:
    """Builds a ``timeline.jsonl`` line by line (seq is assigned here)."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.path = folder / "timeline.jsonl"
        self.lines: list[dict] = []
        self.world = 0
        self.epoch = 0
        self.phase = "live"
        self.run = None
        folder.mkdir(parents=True, exist_ok=True)
        # The real writer's lock file marks the folder as a live sink.
        (folder / ".timeline.lock").write_text("{}")

    def add(self, sec: float, src: str, kind: str, summary: str = "", **kw) -> int:
        seq = len(self.lines) + 1
        t = (BASE + timedelta(seconds=sec)).isoformat(timespec="milliseconds")
        line = {
            "v": 1,
            "seq": seq,
            "t": t,
            "t_rx": t,
            "clk": kw.pop("clk", "host"),
            "mono": round(sec, 3),
            "world": self.world,
            "epoch": self.epoch,
            "phase": self.phase,
            "run": self.run,
            "src": src,
            "kind": kind,
            "actor": kw.pop("actor", "sandroid"),
            "dev": SERIAL,
            "summary": summary or f"{src}/{kind}",
            "level": kw.pop("level", "info"),
            **kw,
            "h": "0" * 64,
        }
        self.lines.append(line)
        return seq

    def shot(self, sec: float, trigger: str, of: int | None, color, label="", dup=None):
        seq = len(self.lines) + 1
        if dup is not None:
            ref_line = next(ln for ln in self.lines if ln["seq"] == dup)
            rel, sha = ref_line["ref"]["path"], ref_line["ref"]["sha256"]
        else:
            rel = f"tracking/shots/{seq}_{trigger}.png"
            sha = _png(self.folder / rel, color, label)
        ref = {"path": rel, "sha256": sha}
        if of is not None:
            ref["of"] = of
        return self.add(
            sec,
            "shot",
            trigger,
            f"screenshot {trigger.replace('_', ' ')}",
            clk="dev_mono",
            ref=ref,
            data={
                "trigger": trigger,
                "w": 270,
                "h": 600,
                "cap_ms": 14,
                "via": "helper",
                "dup_of": dup,
            },
        )

    def write(self, *, torn_after: int | None = None) -> Path:
        out = []
        for line in self.lines:
            out.append(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")
            if torn_after is not None and line["seq"] == torn_after:
                # A torn tail; resume appends b"\n" and never truncates.
                out.append('{"v":1,"seq":999,"t":"2026-11-19T12:00:3\n')
        self.path.write_text("".join(out), encoding="utf-8")
        return self.path


POLICY = {
    "timeline": {
        "sources": {
            "files": True,
            "monitor": True,
            "net": True,
            "input": True,
            "screen": True,
            "shot": True,
        },
        "kinds_off": [],
        "count_only": ["files.open", "files.close"],
        "files_attrs": "app_dirs",
        "files_modify_coalesce_ms": 1000,
        "count_window_s": 5.0,
        "queue_max": 10000,
        "clock_every_s": 60,
    },
    "tracking": {
        "helper_mode": "full",
        "auto_on_record": True,
        "shot_before_tap": True,
        "shot_screen_change": True,
        "shot_after_tap": False,
        "shot_label": False,
        "capture_text": True,
    },
}


def _policy(before_tap: bool) -> dict:
    pol = copy.deepcopy(POLICY)
    pol["tracking"]["shot_before_tap"] = before_tap
    return pol


def _target(text=None, rid=None, cls="android.widget.Button", desc=None):
    return {
        "rid": rid,
        "text": text,
        "desc": desc,
        "cls": cls,
        "path": "0/1/3",
        "bounds": [60, 1600, 1020, 1700],
        "source": "cached",
    }


def _tap(tl, sec, target, x=540, y=1650, actor="user", kind="tap"):
    name = target.get("text") or target.get("rid")
    return tl.add(
        sec,
        "input",
        kind,
        f"{kind} '{name}' ({target['cls'].rsplit('.', 1)[-1]})",
        actor=actor,
        clk="dev_mono",
        dev_mono=81234.5 + sec,
        t_err_ms=9.4,
        pkg="com.x",
        data={
            "x": x,
            "y": y,
            "rx": 0.5,
            "ry": 0.68,
            "screen": [1080, 2424],
            "rotation": 0,
            "dur_ms": 84,
            "pointer": 0,
            "xy_uncertain": False,
            "target": target,
            "node_ms": 12,
            "helper": "full",
        },
        ref={"raw": f"tracking/raw/getevent.txt#L{int(sec * 10)}-{int(sec * 10) + 9}"},
    )


def _files(tl, sec, kind, path, actor="app", n=None):
    data = {"op": kind.upper(), "path": path, "backend": "kprobe", "process": "com.x"}
    if n:
        data.update(n=n)
    return tl.add(
        sec,
        "files",
        kind,
        f"{kind.upper()} {path.rsplit('/', 1)[-1]}",
        actor=actor,
        pkg="com.x" if actor == "app" else None,
        pid=4242,
        data=data,
    )


def _flow(tl, sec, method, host, path, status):
    return tl.add(
        sec,
        "net",
        "flow",
        f"{method} {status} {host}{path}",
        actor="app",
        pkg="com.x",
        data={
            "method": method,
            "host": host,
            "path": path,
            "status": status,
            "req_bytes": 1240,
            "resp_bytes": 88,
            "dur_ms": 312,
            "protocol": "HTTPS",
            "app": "com.x",
            "error": None,
        },
        ref={"id": "f1", "path": "mitm_flows/details/f1.json", "lens": "network"},
    )


def build_fixture(folder: Path) -> tuple[TimelineFixture, dict[str, int]]:
    """A realistic session: labels, taps, a password, shots, effects, ..."""
    tl = TimelineFixture(folder)
    s: dict[str, int] = {}
    tl.add(
        0,
        "sandroid",
        "open",
        "timeline opened",
        data={
            "session_id": SESSION_ID,
            "serial": SERIAL,
            "device_name": "Pixel_API_35",
            "schema": 1,
            "detached": {"adopted": 2, "dropped": 0},
        },
    )
    tl.add(
        0.01, "sandroid", "policy", "policy · open", data={"reason": "open", **POLICY}
    )
    tl.add(
        0.02,
        "device",
        "connect",
        "device · emulator-5554",
        data={"serial": SERIAL, "name": "Pixel_API_35", "emulator": True},
    )
    tl.add(1, "clock", "sample", "clock · device +0.0 s ±7 ms", t_err_ms=7.0)
    s["label1"] = tl.add(
        5,
        "label",
        "start",
        "▶ 1 'Onboarding'",
        actor="user",
        data={"number": 1, "name": "Onboarding", "parent": None, "depth": 0},
    )
    tl.add(
        6,
        "tracking",
        "start",
        "tracking on",
        actor="user",
        data={"mode": "full", "reason": "user", "helper": "connected"},
    )
    tl.add(
        6.1,
        "sandroid",
        "intervention",
        "a11y helper on",
        data={"what": "a11y_helper", "state": "on", "detectable": True},
    )
    s["screen1"] = tl.add(
        7,
        "screen",
        "window",
        "→ com.x/.MainActivity",
        actor="app",
        clk="dev_mono",
        pkg="com.x",
        data={
            "pkg": "com.x",
            "cls": ".MainActivity",
            "title": "Welcome",
            "via": "a11y",
        },
    )
    s["shot_screen1"] = tl.shot(
        7.2, "screen_change", s["screen1"], (31, 32, 65), "Welcome"
    )
    s["tap_accept"] = _tap(tl, 10, _target("Accept all", "com.x:id/accept"))
    s["shot_accept"] = tl.shot(
        10.01, "before_tap", s["tap_accept"], (31, 32, 65), "Accept all"
    )
    tl.add(
        10.3,
        "input",
        "confirm",
        "confirmed",
        actor="app",
        ref={"of": s["tap_accept"]},
        data={"a11y": "CLICKED", "node": {"rid": "com.x:id/accept"}},
    )
    _files(tl, 10.5, "modify", "/data/data/com.x/databases/app.db", n=3)
    _files(tl, 10.8, "create", "/data/data/com.x/shared_prefs/consent.xml")
    _files(tl, 10.9, "modify", "/data/system/netstats/x.bin", actor="system")
    _flow(tl, 11.0, "POST", "api.x.com", "/v1/consent", 200)
    s["record_start"] = tl.add(
        14,
        "run",
        "record-start",
        "● recording",
        actor="user",
        data={"label": "login", "via": "modal"},
    )
    s["label2"] = tl.add(
        15,
        "label",
        "start",
        "▶ 2 'Login' (in 1)",
        actor="user",
        data={"number": 2, "name": "Login", "parent": 1, "depth": 1},
    )
    s["screen2"] = tl.add(
        15.5,
        "screen",
        "activity",
        "→ com.x/.LoginActivity",
        actor="app",
        clk="dev_mono",
        pkg="com.x",
        data={
            "pkg": "com.x",
            "cls": ".LoginActivity",
            "title": "Sign in",
            "via": "a11y",
        },
    )
    tl.shot(15.7, "screen_change", s["screen2"], (12, 154, 124), "Sign in")
    s["tap_user"] = _tap(
        tl, 17, _target(None, "com.x:id/username", "android.widget.EditText"), y=900
    )
    _files(tl, 18.5, "modify", "/data/data/com.x/files/draft.txt")
    s["text_user"] = tl.add(
        19,
        "input",
        "text",
        "typed 5 chars into 'username' (EditText)",
        actor="user",
        clk="dev_mono",
        data={
            "text": "alice",
            "password": False,
            "edits": 5,
            "target": {"rid": "com.x:id/username", "cls": "android.widget.EditText"},
        },
    )
    _files(tl, 19.5, "modify", "/data/data/com.x/files/notes.txt")
    s["tap_pw"] = _tap(
        tl, 20, _target(None, "com.x:id/pw", "android.widget.EditText", "Password")
    )
    s["shot_pw"] = tl.shot(20.01, "before_tap", s["tap_pw"], None, dup=s["shot_accept"])
    s["text_pw"] = tl.add(
        23,
        "input",
        "text",
        "typed 8 chars into 'Password' (EditText, password)",
        actor="user",
        clk="dev_mono",
        sensitive=True,
        data={
            "text": PASSWORD,
            "password": True,
            "edits": 8,
            "target": {"rid": "com.x:id/pw", "cls": "android.widget.EditText"},
        },
    )
    tl.add(
        25,
        "sandroid",
        "policy",
        "policy · settings",
        actor="user",
        data={
            "reason": "settings",
            "by": "user",
            "changed": {"tracking.shot_before_tap": [True, False]},
            **_policy(before_tap=False),
        },
    )
    s["tap_signin"] = _tap(tl, 26, _target("Sign in", "com.x:id/login"))
    _flow(tl, 26.4, "POST", "api.x.com", "/v1/login", 200)
    tl.add(
        26.6,
        "net",
        "tls-fail",
        "TLS fail tracker.x",
        actor="app",
        data={"host": "tracker.x", "reason": "cert", "app": "com.x"},
    )
    _files(tl, 26.8, "modify", "/data/data/com.x/databases/app.db")
    tl.add(
        28,
        "label",
        "point",
        "◆ 3 'logged in'",
        actor="user",
        data={"number": 3, "name": "logged in", "parent": 2},
    )
    tl.add(
        29,
        "sandroid",
        "dropped",
        "dropped 142",
        level="warn",
        data={
            "window": ["a", "b"],
            "by_src": {"files": 140, "monitor": 2},
            "reason": {"queue-full": 130, "no-device": 12},
            "cumulative": 142,
            "queue_max": 10000,
        },
    )
    tl.add(
        30,
        "label",
        "end",
        "■ 2 'Login' · 15.0 s",
        actor="user",
        ref={"of": s["label2"]},
        data={"number": 2, "ended_by": "stop", "duration_s": 15.0},
    )
    s["record_stop"] = tl.add(
        32,
        "run",
        "record-stop",
        "■ recording",
        actor="user",
        ref={"of": s["record_start"]},
    )
    s["manual"] = tl.shot(33, "manual", None, (255, 111, 89), "manual")
    tl.add(
        35,
        "sandroid",
        "policy",
        "policy · settings",
        actor="user",
        data={
            "reason": "settings",
            "by": "user",
            "changed": {"tracking.shot_before_tap": [False, True]},
            **_policy(before_tap=True),
        },
    )
    s["torn_after"] = len(tl.lines)
    s["resume"] = tl.add(
        80,
        "sandroid",
        "resume",
        "timeline resumed (unclean)",
        level="warn",
        data={
            "prev_seq": len(tl.lines),
            "verified": True,
            "torn": {"offset": 12345, "bytes": 37, "sha256": "a" * 64},
            "unclean": True,
            "gap_s": 42,
        },
    )
    tl.add(
        80.01,
        "sandroid",
        "policy",
        "policy · resume",
        data={"reason": "resume", **POLICY},
    )
    tl.add(
        80.02,
        "label",
        "end",
        "■ 1 'Onboarding'",
        ref={"of": s["label1"]},
        data={"number": 1, "ended_by": "close", "duration_s": 75.0, "late": True},
    )
    s["key_back"] = tl.add(
        90,
        "input",
        "key",
        "key BACK",
        actor="user",
        clk="dev_mono",
        data={"code": 158, "name": "BACK", "dur_ms": 60},
    )
    tl.add(
        91,
        "screen",
        "activity",
        "→ com.x/.MainActivity",
        actor="app",
        clk="none",
        data={"pkg": "com.x", "cls": ".MainActivity", "via": "logcat"},
    )
    tl.world, tl.epoch = 1, 1
    tl.add(
        95,
        "snapshot",
        "load",
        "snapshot · tmp loaded",
        t_err_ms=12.0,
        data={"name": "tmp", "ok": True, "world_before": 0},
    )
    tl.add(
        100, "tracking", "stop", "tracking off", actor="user", data={"reason": "user"}
    )
    tl.add(
        100.1,
        "sandroid",
        "intervention",
        "a11y helper off",
        data={"what": "a11y_helper", "state": "off", "detectable": True},
    )
    tl.phase, tl.run = "replay", RUN_ID
    s["play_start"] = tl.add(
        110,
        "run",
        "play-start",
        "▶ play",
        data={"label": "login", "number_of_runs": 1, "bundle": f"runs/{RUN_ID}"},
        replays={"run": None, "seq_range": [s["record_start"], s["record_stop"]]},
    )
    _tap(tl, 115, _target("Sign in", "com.x:id/login"), actor="replay")
    s["play_end"] = tl.add(
        140,
        "run",
        "play-end",
        "■ play",
        ref={"of": s["play_start"], "run": RUN_ID, "lens": "runs"},
        data={"error": None, "saved": True},
    )
    tl.phase, tl.run = "live", None
    tl.write(torn_after=s["torn_after"])
    return tl, s


def _results() -> dict:
    return {
        "Device Name": "Pixel_API_35",
        "Emulator relative action timestamp": 1794828274,
        "Action Duration": 19,
        "Changed Files": [
            "/data/data/a/plain.db",
            {
                "/data/data/com.x/databases/app.db": [
                    "\t[INSERT] Table [t] row [1,'<x> & y']"
                ]
            },
        ],
        "New Files": ["/data/data/com.x/shared_prefs/consent.xml"],
        "Deleted Files": [],
        "Processes": ["[kworker/0:0+events]"],
        "Listening Sockets": [],
        "Network": ["api.x.com."],
        "Network IP:Port (send/recv)": [],
        "Other Data": {
            "Artifact Hashes": [
                {
                    "new_file_hashes": {"/data/data/x/file_2.txt": "0" * 32},
                    "changed_file_hashes(old,new)": {
                        "/data/data/x/a.db": ["1" * 32, "2" * 32]
                    },
                    "new_file_hashes_sha256": {"/data/data/x/file_2.txt": "a" * 64},
                    "changed_file_hashes_sha256(old,new)": {
                        "/data/data/x/a.db": ["b" * 64, "c" * 64]
                    },
                }
            ],
            "APK Hashes": [["com.example: " + "d" * 32]],
            "APK Hashes SHA-256": [["com.example: " + "e" * 64]],
            "Filtered Noise": [
                {
                    "enabled": True,
                    "note": "hidden",
                    "Changed Files": {
                        "/data/system/netstats/x": "/data/system/netstats/*"
                    },
                }
            ],
        },
    }


@pytest.fixture
def session(tmp_path, fake_timeline):
    """``<tmp>/session/dev/timeline.jsonl`` + a run bundle with results."""
    tl, seqs = build_fixture(tmp_path / "session" / "dev")
    bundle = tmp_path / "results" / "runs" / RUN_ID
    bundle.mkdir(parents=True)
    (bundle / "sandroid.json").write_text(json.dumps(_results()), encoding="utf-8")
    return SimpleNamespace(tl=tl, seqs=seqs, bundle=bundle, root=tmp_path)


def _build(sess, *, scope=None, seal=True, **opts) -> dict:
    return report_engine.build_report(
        timeline=sess.tl.path,
        seal=_fake_seal_file(sess.tl.path) if seal else None,
        scope=scope or report_engine.ReportScope(),
        bundle_dir=sess.bundle,
        options=report_engine.ReportOptions(**opts),
    )


def _section(doc: dict, sid: str) -> dict:
    return next(s for s in doc["sections"] if s["id"] == sid)


def _steps(doc: dict) -> list[dict]:
    return [
        b
        for b in _section(doc, "transcript")["blocks"]
        if b["type"] == "transcript_step"
    ]


def _step(doc: dict, seq: int) -> dict:
    return next(b for b in _steps(doc) if b["seq"] == seq)


def _sentences(doc: dict) -> list[str]:
    out = []
    for block in _section(doc, "coverage")["blocks"]:
        if block["type"] == "list":
            out += block["items"]
        elif block["type"] == "text":
            out.append(block["text"])
    return out


# ---------------------------------------------------------------------------
# Privacy (identity data leaving the device)
# ---------------------------------------------------------------------------


def _privacy_line(tl, sec, kind, label, transform, **data):
    if kind == "sent":
        summary = f"{label} sent to {data['host']}, request body, {transform}"
    else:
        summary = f"{label} stored in {data['path']}, {transform}"
    return tl.add(
        sec,
        "privacy",
        kind,
        summary,
        actor="app",
        pkg="com.x",
        data={"marker_id": label.lower(), "label": label, "transform": transform,
              "confidence": "high", "direction": kind, "count": 1, **data},
        ref={"of": 1, "path": "privacy/hits.jsonl", "lens": "network"},
    )  # fmt: skip


class TestPrivacy:
    def test_privacy_section_recipients_values_evidence_and_effects(self, session):
        # Without privacy lines the section only says so.
        empty = _section(_build(session, sections=("privacy",)), "privacy")
        assert [b["type"] for b in empty["blocks"]] == ["text"]
        assert "privacy lines" in empty["blocks"][0]["text"]
        tl = session.tl
        tl.add(1, "identity", "applied", "identity applied", data={"markers": 5})
        meta = {"host": "graph.facebook.com", "recipient": "Meta", "party": "third"}
        fit = {"host": "api.x.com", "recipient": "x.com", "party": "first"}
        sent = _privacy_line(
            tl, 10.5, "sent", "Ad ID", "sha256(lower(value))", part="req.body", **meta
        )
        _privacy_line(tl, 12, "sent", "Ad ID", "value", part="url", **meta)
        _privacy_line(tl, 13, "sent", "Email", "value", part="url", **fit)
        _privacy_line(tl, 14, "sent", "GPS", "round(value, 4)", part="req.body", **meta)
        _privacy_line(tl, 15, "stored", "Email", "value", part="file:p.xml",
                      path="/data/data/com.x/shared_prefs/p.xml")  # fmt: skip
        tl.write()
        doc = _build(session)
        section = _section(doc, "privacy")
        assert section["title"] == "Identity data leaving the device"
        ids = [s["id"] for s in doc["sections"]]
        assert ids.index("privacy") == ids.index("coverage") + 1
        intro = section["blocks"][0]["text"]
        # No frozen apply record to count against: no "n of m" total.
        assert intro.startswith(
            "3 profile values left the device to 2 recipients, the first at "
            f"12:00:10 (line {sent})."
        )
        assert "1 of the recipients are known third parties" in intro
        assert "1 value was written to app storage" in intro
        matrix = next(b for b in section["blocks"] if b["type"] == "table")
        assert matrix["columns"] == ["Recipient", "Ad ID", "Email", "GPS"]
        assert matrix["rows"] == [
            ["Meta (third party)", "as is, hashed", "", "rounded"],
            ["x.com (first party)", "", "as is", ""],
        ]
        evidence = [b for b in section["blocks"] if b["type"] == "table"][1]
        first = evidence["rows"][0]
        assert first == [
            "Ad ID", "Meta", "graph.facebook.com", "request body",
            "sha256 of the lower-case value", "12:00:10", str(sent),
        ]  # fmt: skip
        assert evidence["rows"][3][4] == "rounded to 4 decimals"
        assert evidence["rows"][-1][:3] == [
            "Email", "stored on the device", "/data/data/com.x/shared_prefs/p.xml"
        ]  # fmt: skip
        glyphs = set("■▲◆●✓✗⚑⌁")
        assert not glyphs & set(json.dumps(section, ensure_ascii=False))
        # The tap's effects name the value that left within its window.
        effects = _step(doc, session.seqs["tap_accept"])["effects"]["privacy"]
        assert effects["count"] == 1
        assert effects["top"][0] == {
            "seq": sent, "kind": "sent", "label": "Ad ID", "to": "Meta",
            "encoding": "hashed",
        }  # fmt: skip
        # Markdown: the section, its table and the step's effect line.
        md = report_engine.write_report(doc, session.bundle, formats=("md",))
        text = md["md"].read_text()
        assert "## Identity data leaving the device" in text
        row = next(ln for ln in text.splitlines() if ln.startswith("| Meta (third"))
        assert row.split(" | ")[1:2] == ["as is, hashed"], row
        assert row.rstrip(" |").endswith("rounded"), row
        assert (
            f"  - Profile values: 1 finding(s): Ad ID sent to Meta, hashed (#{sent})"
            in text
        )

    def test_report_counts_the_values_the_header_counts(self, session):
        """The report's "n of m found" is the header's PRIVACY n/m: values
        found (any direction, a group counts once, older records mapped to
        their marker, other profiles' hits left out) of the seeded values.
        """
        import tomli_w

        from sandroid.core.privacy_markers import Marker
        from sandroid.services import privacy_scan as ps
        from sandroid.services.privacy_scan import HitRecord

        markers = [
            Marker("advertising_id", "3b9f0c1d-1111-2222-3333-444455556666",
                   "uuid", "Advertising ID", (), "", "Ad ID"),
            Marker("gps.latitude", "52.520008", "text", "GPS", (), "gps", "GPS"),
            Marker("gps.longitude", "13.404954", "text", "GPS", (), "gps", "GPS"),
            Marker("email", "jane.canary@example.org", "email", "Email", (), "",
                   "Email"),
            Marker("android_id@com.x", "3f9a1c07aa55bb66", "hex_id",
                   "Android ID (com.x)", (), "", "Android ID"),
        ]  # fmt: skip
        digest_of, _groups = ps.value_keys(markers)

        def hit(sec, marker_id, label, direction, *, fp="fpA", vkey=True):
            source = (
                {"type": "flow", "flow_id": f"f{sec}", "host": "graph.facebook.com"}
                if direction != "stored"
                else {"type": "file", "device_path": "/data/data/com.x/p.xml"}
            )
            return HitRecord(
                v=1, at=0.0, t=(BASE + timedelta(seconds=sec)).timestamp(),
                fp=fp, engine=1, marker_id=marker_id, label=label, tag=label,
                kind="text", transform="value", confidence="high", part="url",
                direction=direction, count=1, offsets=(0,),
                snippet=("", "x", ""), source=source,
                recipient=(
                    {"label": "Meta", "party": "third", "host": "graph.facebook.com"}
                    if direction == "sent"
                    else None
                ),
                value_key=digest_of.get(marker_id) if vkey else None,
            )  # fmt: skip

        records = [
            hit(20, "advertising_id", "Advertising ID", "sent"),
            hit(21, "gps.latitude", "GPS", "received"),  # found, not sent
            hit(22, "gps.longitude", "GPS", "sent"),  # the same value: GPS
            # An older record (no value key, the plain Android ID id).
            hit(23, "android_id", "Android ID (com.x)", "stored", vkey=False),
            hit(24, "email", "Email", "sent", fp="fpOld"),  # another profile
        ]
        folder = session.tl.folder
        (folder / "identity").mkdir()
        record = {
            "fingerprint": "fpA",
            "markers": [
                {"id": m.id, "value": m.value, "kind": m.kind, "label": m.label,
                 "forms": list(m.forms), "group": m.group, "tag": m.tag}
                for m in markers
            ],
        }  # fmt: skip
        (folder / "identity" / "001-mara-r1.toml").write_text(tomli_w.dumps(record))
        session.tl.add(
            1, "identity", "applied", "identity applied",
            data={"fingerprint": "fpA", "markers": len(markers)},
            ref={"path": "identity/001-mara-r1.toml", "sha256": "x"},
        )  # fmt: skip
        session.tl.write()
        (folder / "privacy").mkdir()
        (folder / "privacy" / "hits.jsonl").write_text(
            "".join(json.dumps(r.to_json()) + "\n" for r in records)
        )
        # The header: the privacy scan service over the same records.
        service = ps.PrivacyScanService(folder_fn=lambda: folder)
        try:
            service.load_session(folder)
            service.set_markers("fpA", markers)
            summary = service.summary()
        finally:
            service.close()
        assert (summary.values_found, summary.values_total) == (3, 4)
        doc = _build(session, scope=report_engine.ReportScope(), sections=("privacy",))
        intro = _section(doc, "privacy")["blocks"][0]["text"]
        assert intro.startswith(
            f"{summary.values_found} of {summary.values_total} profile values were "
            "found in this report's scope. 2 profile values left the device to "
            "1 recipient,"
        ), intro

    def test_every_run_counts_its_hits_not_only_the_first_line(self, session):
        """A value leaked in two runs of one session is in both run reports
        (the timeline line is written once per session, the store keeps
        every hit); the run scope spans the recording and the Play.
        """
        from sandroid.services.privacy_scan import HitRecord

        def hit(sec, *, tl_seq=None, run_id=None, host="graph.facebook.com"):
            label = "Meta" if host == "graph.facebook.com" else host
            source = {"type": "flow", "flow_id": f"f{sec}", "host": host}
            if run_id:
                source["run_id"] = run_id
            return HitRecord(
                v=1, at=0.0, t=(BASE + timedelta(seconds=sec)).timestamp(),
                fp="fp", engine=1, marker_id="adid", label="Ad ID", tag="Ad ID",
                kind="uuid", transform="value", confidence="high", part="url",
                direction="sent", count=1, offsets=(0,), snippet=("", "x", ""),
                source=source,
                recipient={"label": label, "party": "third", "host": host},
                tl_seq=tl_seq,
            )  # fmt: skip

        tl = session.tl
        first = _privacy_line(tl, 20, "sent", "Ad ID", "value", part="url",
                              host="graph.facebook.com", recipient="Meta",
                              party="third")  # fmt: skip
        play2 = tl.add(150, "run", "play-start", "play 2", data={"bundle": "x"})
        tl.add(170, "run", "play-end", "play 2 done", ref={"of": play2})
        tl.write()
        privacy = session.tl.folder / "privacy"
        privacy.mkdir()
        records = [
            hit(20, tl_seq=first),  # during the recording (run 1 replays it)
            hit(50),  # between the runs: in neither run
            hit(160, host="ads.example.net"),  # during run 2's Play
        ]
        (privacy / "hits.jsonl").write_text(
            "".join(json.dumps(r.to_json()) + "\n" for r in records)
        )
        run1 = report_engine.scope_for_run(session.tl.path, RUN_ID)
        run2 = report_engine.ReportScope(
            kind="run",
            run_id="run-2",
            window=(
                (BASE + timedelta(seconds=150)).timestamp(),
                (BASE + timedelta(seconds=170)).timestamp(),
            ),
        )

        def intro(scope):
            doc = _build(session, scope=scope, sections=("privacy",))
            return _section(doc, "privacy")["blocks"][0]["text"]

        assert intro(run1).startswith(
            f"1 profile value left the device to 1 recipient, the first at "
            f"12:00:20 (line {first})."
        )
        # Run 2 has no privacy line of its own; its hit still counts.
        text2 = intro(run2)
        assert text2.startswith(
            "1 profile value left the device to 1 recipient, the first at 12:02:40."
        ), text2
        # An end-of-run sweep hit attributed to run 2 counts in run 2 only.
        records.append(hit(400, run_id="run-2", host="sweep.example.org"))
        (privacy / "hits.jsonl").write_text(
            "".join(json.dumps(r.to_json()) + "\n" for r in records)
        )
        assert "to 2 recipients" in intro(run2)
        assert "to 1 recipient," in intro(run1)
        # The whole session counts every hit.
        assert "to 3 recipients" in intro(report_engine.ReportScope())
        # A store without a hit in scope: nothing left the device.
        (privacy / "hits.jsonl").write_text("")
        assert intro(run1).startswith(
            "No profile value left the device in this report's scope."
        )


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------


class TestTranscript:
    def test_sections_in_plan_order_and_schema(self, session):
        doc = _build(session)
        assert [s["id"] for s in doc["sections"]] == [
            "overview",
            "coverage",
            "privacy",
            "transcript",
            "results",
            "seal",
        ]
        assert doc["schema"] == report_engine.SCHEMA
        json.dumps(doc)  # serialisable
        # The engine read the timeline only through read_lines, up to the seal.
        reads = [r for r in FAKE_STATE["reads"] if r["path"] == str(session.tl.path)]
        assert reads
        assert all(r["end"] == doc["seal"]["bytes"] for r in reads)
        assert all(r["reader"] == "report" for r in reads)

    def test_label_groups_nest_and_unlabelled(self, session):
        blocks = _section(_build(session), "transcript")["blocks"]
        heads = [(b["level"], b["text"]) for b in blocks if b["type"] == "heading"]
        assert heads == [
            (2, "Label 1 'Onboarding'"),
            (3, "Label 2 'Login'"),
            (2, "Label 1 'Onboarding' (continued)"),
            (2, "Unlabelled"),
        ]
        steps = _steps(_build(session))
        by_seq = {s["seq"]: s for s in steps}
        assert by_seq[session.seqs["tap_accept"]]["label"] == [1]
        assert by_seq[session.seqs["tap_pw"]]["label"] == [1, 2]
        assert by_seq[session.seqs["manual"]]["label"] == [1]
        assert by_seq[session.seqs["key_back"]]["label"] == []
        # Steps are input, screen, manual shots and marks; never confirm lines.
        kinds = [(s["src"], s["kind"]) for s in steps]
        assert ("input", "confirm") not in kinds
        assert ("label", "point") in kinds
        assert ("shot", "manual") in kinds
        assert ("screen", "activity") in kinds

    def test_tap_step_target_shots_screen_and_effects(self, session):
        doc = _build(session)
        step = _step(doc, session.seqs["tap_accept"])
        assert step["element"] == "Accept all"
        assert step["element_class"] == "Button"
        assert step["xy"] == [540, 1650]
        assert step["confirmed"] is True
        assert step["screen"]["cls"] == ".MainActivity"
        assert [s["trigger"] for s in step["shots"]] == ["before_tap"]
        assert step["shots"][0]["of"] == step["seq"]
        assert Path(step["shots"][0]["path"]).is_file()
        files = step["effects"]["files"]
        # Only the app's lines; the system netstats line is not an effect.
        assert files["count"] == 2
        assert files["by_kind"] == {"modify": 1, "create": 1}
        assert files["top"][0]["path"] == "/data/data/com.x/databases/app.db"
        assert files["top"][0]["n"] == 3
        assert step["effects"]["net"]["top"][0]["host"] == "api.x.com"
        assert step["effects"]["window_s"] == 2.0

    def test_effects_window_stops_at_next_input(self, session):
        doc = _build(session)
        tap_user = _step(doc, session.seqs["tap_user"])
        text_user = _step(doc, session.seqs["text_user"])
        paths = [i["path"] for i in tap_user["effects"]["files"]["top"]]
        assert paths == ["/data/data/com.x/files/draft.txt"]  # 19.5 belongs to text
        assert tap_user["effects"]["window_s"] == 2.0  # 17 -> 19 (next input)
        assert [i["path"] for i in text_user["effects"]["files"]["top"]] == [
            "/data/data/com.x/files/notes.txt"
        ]
        assert text_user["effects"]["window_s"] == 1.0  # 19 -> 20 (next input)
        wide = _build(session, effects_window_s=0.4)
        assert _step(wide, session.seqs["tap_user"])["effects"] is None

    def test_element_name_priority(self):
        name = report_engine.element_name
        assert name({"text": "OK", "desc": "d", "rid": "a:id/b", "cls": "x.Y"}) == "OK"
        assert name({"text": " ", "desc": "Password", "rid": "a:id/pw"}) == "Password"
        assert name({"rid": "com.x:id/username", "cls": "x.EditText"}) == "username"
        assert name({"cls": "android.widget.EditText"}) == "EditText"
        assert name(None) is None

    def test_element_name_uses_the_rows_descendant_label(self):
        """F3 (E2E): a tapped LinearLayout row without own text, named by its
        child TextViews -- the report named it 'LinearLayout'.
        """
        row = {  # the real target of the E2E tap on Settings > Battery
            "bounds": [0, 1703, 1080, 1934],
            "cls": "android.widget.LinearLayout",
            "desc": None,
            "rid": None,
            "source": "cached",
            "text": None,
            "label": "Battery / Charged",
        }
        assert report_engine.element_name(row) == "Battery / Charged"
        # the node's own text/desc still wins over the descendants' label
        assert report_engine.element_name({**row, "desc": "Battery"}) == "Battery"
        assert report_engine.element_name({**row, "label": None}) == "LinearLayout"

    def test_password_clear_when_masking_off(self, session):
        doc = _build(session, mask_sensitive=False)
        step = _step(doc, session.seqs["text_pw"])
        assert step["text"] == PASSWORD
        assert step["password"] is True
        assert doc["masking"]["sensitive_masked"] is False
        # Exactly once: the step's text field; never a summary or other field.
        assert json.dumps(doc).count(PASSWORD) == 1
        assert PASSWORD not in step["summary"]
        assert all(PASSWORD not in str(s.get("summary")) for s in _steps(doc))
        md = report_render.render_markdown(doc, base_dir=session.bundle)
        assert md.count(PASSWORD) == 1
        assert f"Typed text: `{PASSWORD}` (password field)" in md

    def test_password_masked_when_on(self, session):
        doc = _build(session, mask_sensitive=True)
        step = _step(doc, session.seqs["text_pw"])
        assert step["text"] is None
        assert step["text_masked"] is True
        assert doc["masking"]["sensitive_masked"] is True
        assert PASSWORD not in json.dumps(doc)
        md = report_render.render_markdown(doc, base_dir=session.bundle)
        assert PASSWORD not in md
        assert "Typed text: *masked*" in md
        # Non-sensitive text stays readable.
        assert _step(doc, session.seqs["text_user"])["text"] == "alice"

    def test_masking_default_follows_should_mask(self, session, fake_timeline):
        fake_timeline["mask"] = True
        doc = _build(session)
        assert doc["masking"]["sensitive_masked"] is True
        assert PASSWORD not in json.dumps(doc)

    def test_shot_dedupe_points_at_the_same_file(self, session):
        doc = _build(session)
        first = _step(doc, session.seqs["tap_accept"])["shots"][0]
        dup = _step(doc, session.seqs["tap_pw"])["shots"][0]
        assert dup["path"] == first["path"]
        assert dup["sha256"] == first["sha256"]
        assert dup["dup_of"] == session.seqs["shot_accept"]

    def test_shot_trigger_filter(self, session):
        doc = _build(session, shot_triggers=frozenset({"screen_change"}))
        assert _step(doc, session.seqs["tap_accept"])["shots"] == []
        assert [s["trigger"] for s in _step(doc, session.seqs["screen1"])["shots"]] == [
            "screen_change"
        ]
        assert all(s["src"] != "shot" for s in _steps(doc))  # manual hidden too
        texts = [
            b["text"]
            for b in _section(doc, "transcript")["blocks"]
            if b["type"] == "text"
        ]
        assert "3 screenshots hidden by the trigger filter." in texts

    def test_include_screenshots_off(self, session):
        doc = _build(session, include_screenshots=False)
        assert '"type": "image"' not in json.dumps(doc, indent=1)
        assert all(not s["shots"] for s in _steps(doc))

    def test_run_scope_uses_record_window(self, session):
        scope = report_engine.scope_for_run(session.tl.path, RUN_ID)
        assert scope.kind == "run"
        assert scope.seq_range == (
            session.seqs["record_start"],
            session.seqs["record_stop"],
        )
        assert scope.window[1] - scope.window[0] == pytest.approx(30.0)
        doc = _build(session, scope=scope)
        seqs = {s["seq"] for s in _steps(doc)}
        assert session.seqs["tap_pw"] in seqs
        assert session.seqs["tap_accept"] not in seqs  # before the recording
        assert session.seqs["key_back"] not in seqs
        assert doc["scope"]["run_id"] == RUN_ID

    def test_unknown_run_reports_whole_timeline_with_note(self, session):
        scope = report_engine.scope_for_run(session.tl.path, "nope")
        assert scope.window is None
        assert scope.seq_range is None
        doc = _build(session, scope=scope)
        assert any("Run nope was not found" in s for s in _sentences(doc))


def _screen(tl, sec, kind, cls, title=None, via="a11y"):
    return tl.add(
        sec,
        "screen",
        kind,
        f"→ com.android.settings/{cls}",
        actor="app",
        clk="dev_mono",
        pkg="com.android.settings",
        data={"pkg": "com.android.settings", "cls": cls, "title": title, "via": via},
    )


@pytest.fixture
def gap_session(tmp_path, fake_timeline):
    """E2E round 5 (FULL): screen lines whose screen-change shots were
    dropped, each followed by a tap with a before-tap shot.
    """
    tl = TimelineFixture(tmp_path / "gap" / "dev")
    tl.add(0, "sandroid", "open", "timeline opened",
           data={"session_id": SESSION_ID, "serial": SERIAL, "schema": 1})  # fmt: skip
    tl.add(0.01, "sandroid", "policy", "policy · open",
           data={"reason": "open", **POLICY})  # fmt: skip
    s: dict[str, int] = {}
    home, battery = (40, 40, 160), (200, 120, 0)
    s["tap13"] = _tap(tl, 10, _target("Battery / Charged"))
    s["bt15"] = tl.shot(10.01, "before_tap", s["tap13"], home, "home")
    s["act16"] = _screen(tl, 11, "activity", ".SubSettings", via="logcat")
    s["win17"] = _screen(tl, 12, "window", ".SubSettings", "Battery")
    s["tap18"] = _tap(tl, 14, _target(None, "com.x:id/up"))
    s["bt20"] = tl.shot(14.01, "before_tap", s["tap18"], battery, "battery")
    s["act19"] = _screen(tl, 14.5, "activity", ".Settings", via="logcat")
    s["win21"] = _screen(tl, 15.4, "window", ".homepage.SettingsHomepageActivity")
    s["tap22"] = _tap(tl, 16.5, _target("Network & internet"))
    s["bt23"] = tl.shot(16.6, "before_tap", s["tap22"], None, dup=s["bt15"])
    s["win25"] = _screen(tl, 18, "window", ".SubSettings", "Network & internet")
    s["sc25"] = tl.shot(18.5, "screen_change", s["win25"], (0, 150, 90), "net")
    s["tap26"] = _tap(tl, 19, _target("Airplane mode"))
    s["bt27"] = tl.shot(19.01, "before_tap", s["tap26"], (0, 150, 90), "net")
    s["win34"] = _screen(tl, 20, "window", ".homepage.SettingsHomepageActivity")
    s["key"] = tl.add(21, "input", "key", "key BACK", actor="user",
                      clk="dev_mono", data={"code": 158, "name": "BACK"})  # fmt: skip
    tl.write()
    bundle = tmp_path / "gap_results" / "runs" / RUN_ID
    bundle.mkdir(parents=True)
    (bundle / "sandroid.json").write_text(json.dumps(_results()), encoding="utf-8")
    return SimpleNamespace(tl=tl, seqs=s, bundle=bundle, root=tmp_path)


class TestScreenGapFill:
    """R4: a screen line without a screen-change shot shows the next
    input's before-tap shot, unless another screen line comes first.
    """

    def test_dropped_screens_show_the_next_before_tap_shot(self, gap_session):
        s = gap_session.seqs
        doc = _build(gap_session)
        win17 = _step(doc, s["win17"])["shots"]
        assert len(win17) == 1
        fill = win17[0]
        assert fill["source"] == "next_before_tap"
        assert fill["caption"] == f"screen at next input #{s['tap18']}"
        assert fill["seq"] == s["bt20"]
        assert fill["of"] == s["tap18"]
        assert fill["for"] == s["win17"]
        assert fill["trigger"] == "before_tap"
        bt20 = next(ln for ln in gap_session.tl.lines if ln["seq"] == s["bt20"])
        assert fill["sha256"] == bt20["ref"]["sha256"]
        assert Path(fill["path"]).is_file()  # report.json is self-contained
        home = _step(doc, s["win21"])["shots"]
        assert [b["seq"] for b in home] == [s["bt23"]]
        assert home[0]["dup_of"] == s["bt15"]
        assert home[0]["caption"] == f"screen at next input #{s['tap22']}"

    def test_no_fill_when_another_screen_line_comes_first(self, gap_session):
        s = gap_session.seqs
        doc = _build(gap_session)
        assert _step(doc, s["act16"])["shots"] == []  # win17 is in between
        assert _step(doc, s["act19"])["shots"] == []  # win21 is in between

    def test_no_fill_for_a_stored_shot_or_an_input_without_one(self, gap_session):
        s = gap_session.seqs
        doc = _build(gap_session)
        own = _step(doc, s["win25"])["shots"]
        assert [(b["seq"], b.get("source")) for b in own] == [(s["sc25"], None)]
        assert _step(doc, s["win34"])["shots"] == []  # the key has no before-tap
        md = report_render.render_markdown(doc, base_dir=gap_session.bundle)
        assert f"screen at next input #{s['tap18']}" in md

    def test_fill_follows_the_screen_change_trigger_filter(self, gap_session):
        s = gap_session.seqs
        only = _build(gap_session, shot_triggers=frozenset({"screen_change"}))
        assert _step(only, s["win17"])["shots"][0]["source"] == "next_before_tap"
        assert _step(only, s["tap18"])["shots"] == []  # before_tap hidden
        none = _build(gap_session, shot_triggers=frozenset({"before_tap"}))
        assert _step(none, s["win17"])["shots"] == []
        off = _build(gap_session, include_screenshots=False)
        assert _step(off, s["win17"])["shots"] == []


#: The fix7 R1 fixtures (E2E round 5, downscaled): Notifications, the same
#: screen with its scrollbar faded (another sha256), and Battery.
R1_FIXTURES = Path(__file__).parents[1] / "services" / "fixtures" / "tracking_r1"


def _file_shot(tl, sec, of, name):
    """A before-tap shot line whose file is the R1 fixture ``name``."""
    seq = len(tl.lines) + 1
    rel = f"tracking/shots/{seq}_before_tap.png"
    png = (R1_FIXTURES / name).read_bytes()
    (tl.folder / rel).parent.mkdir(parents=True, exist_ok=True)
    (tl.folder / rel).write_bytes(png)
    sha = hashlib.sha256(png).hexdigest()
    return tl.add(sec, "shot", "before_tap", "screenshot before tap", clk="dev_mono",
                  ref={"of": of, "path": rel, "sha256": sha},
                  data={"trigger": "before_tap", "w": 270, "h": 606, "cap_ms": 14,
                        "via": "helper", "dup_of": None})  # fmt: skip


def _refusal_session(tmp_path, next_shot: str | None):
    """E2E round 6 #47-#51 (INVISIBLE): tap #47 on Notifications, the
    SubSettings activity #48 (its shot dropped), then tap #50 whose before-tap
    shot is ``next_shot``: None = the same file as #47's (#51 = #49).
    """
    tl = TimelineFixture(tmp_path / "refuse" / "dev")
    tl.add(0, "sandroid", "open", "timeline opened",
           data={"session_id": SESSION_ID, "serial": SERIAL, "schema": 1})  # fmt: skip
    tl.add(0.01, "sandroid", "policy", "policy · open",
           data={"reason": "open", **POLICY})  # fmt: skip
    s: dict[str, int] = {}
    s["tap47"] = _tap(tl, 10, _target("Battery"))
    s["bt49"] = _file_shot(tl, 10.01, s["tap47"], "r5_65_notifications_before_tap.png")
    s["act48"] = _screen(tl, 10.4, "activity", ".SubSettings", via="logcat")
    s["tap50"] = _tap(tl, 12, _target(None, "com.x:id/up"))
    if next_shot is None:
        s["bt51"] = tl.shot(12.01, "before_tap", s["tap50"], None, dup=s["bt49"])
    else:
        s["bt51"] = _file_shot(tl, 12.01, s["tap50"], next_shot)
    tl.write()
    bundle = tmp_path / "refuse_results" / "runs" / RUN_ID
    bundle.mkdir(parents=True)
    (bundle / "sandroid.json").write_text(json.dumps(_results()), encoding="utf-8")
    return SimpleNamespace(tl=tl, seqs=s, bundle=bundle, root=tmp_path)


class TestGapFillRefusesThePreviousScreen:
    """R4 (E2E round 6 #48): the next before-tap shot that still shows the
    previous screen (the triggering input's before-tap shot) is no image of
    the new screen: no gap-fill, a ``shot_note`` instead.
    """

    @pytest.mark.parametrize(
        "next_shot",
        [None, "r5_66_notifications_scrollbar_faded.png"],
        ids=["sha256", "perceptual"],
    )
    def test_refused(self, tmp_path, fake_timeline, next_shot):
        sess = _refusal_session(tmp_path, next_shot)
        s = sess.seqs
        doc = _build(sess)
        step = _step(doc, s["act48"])
        assert step["shots"] == []
        assert step["shot_note"] == report_engine.GAP_FILL_REFUSED
        assert step["shot_note"] == (
            "no screenshot: the new screen had not drawn before the next input"
        )
        assert [b["seq"] for b in _step(doc, s["tap50"])["shots"]] == [s["bt51"]]
        md = report_render.render_markdown(doc, base_dir=sess.bundle)
        assert report_engine.GAP_FILL_REFUSED in md
        assert "screen at next input" not in md
        pdf = report_render.render_pdf(doc, sess.root / "r.pdf")
        assert pdf.is_file()

    def test_a_different_screen_is_still_filled(self, tmp_path, fake_timeline):
        sess = _refusal_session(tmp_path, "r5_55_battery_before_tap.png")
        s = sess.seqs
        step = _step(_build(sess), s["act48"])
        assert "shot_note" not in step
        assert [(b["seq"], b["source"]) for b in step["shots"]] == [
            (s["bt51"], "next_before_tap")
        ]


# ---------------------------------------------------------------------------
# Coverage, results, seal, isolation
# ---------------------------------------------------------------------------


class TestClockSync:
    """Coverage → Clock quality: the clock-sync policy line and the caveat."""

    STEM = "Device clock synced to host at session start and after snapshot loads"

    def _text(self, tmp_path, *clock_lines) -> str:
        tl = TimelineFixture(tmp_path / "dev")
        tl.add(0, "sandroid", "open", data={"session_id": SESSION_ID})
        for sec, kind, data in clock_lines:
            tl.add(sec, "clock", kind, data=data)
        tl.write()
        doc = report_engine.build_report(
            timeline=tl.path,
            seal=_fake_seal_file(tl.path),
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        return "\n".join(_sentences(doc))

    def test_policy_on_and_syncs_counted(self, tmp_path, fake_timeline):
        text = self._text(
            tmp_path,
            (1, "sample", {"reason": "device-connect", "sync_policy": True}),
            (
                2,
                "sync",
                {"reason": "sync", "trigger": "session-start", "ok": True, "sets": 1},
            ),
            (
                5,
                "jump",
                {"reason": "snapshot-load", "sync_policy": True, "snapshot": "clean"},
            ),
            (
                6,
                "sync",
                {
                    "reason": "sync",
                    "trigger": "snapshot-load",
                    "snapshot": "clean",
                    "ok": False,
                    "sets": 1,
                },
            ),
        )
        assert f"{self.STEM}: yes." in text
        assert (
            "2 clock syncs (1 at session start, 1 after snapshot loads), "
            "1 failed (the offset was recorded instead)." in text
        )
        assert report_engine.CLOCK_CAVEAT in text

    def test_policy_on_without_needed_sync(self, tmp_path, fake_timeline):
        text = self._text(
            tmp_path,
            (1, "sample", {"reason": "device-connect", "sync_policy": True}),
        )
        assert f"{self.STEM}: yes." in text
        assert "No sync was needed" in text

    def test_policy_off(self, tmp_path, fake_timeline):
        text = self._text(
            tmp_path,
            (1, "sample", {"reason": "device-connect", "sync_policy": False}),
        )
        assert f"{self.STEM}: no." in text
        assert "No sync was needed" not in text

    def test_policy_changed(self, tmp_path, fake_timeline):
        text = self._text(
            tmp_path,
            (1, "sample", {"reason": "device-connect", "sync_policy": True}),
            (5, "jump", {"reason": "snapshot-load", "sync_policy": False}),
        )
        assert f"{self.STEM}: partly" in text

    def test_legacy_shape(self, tmp_path, fake_timeline):
        """a080e46 lines: no sync_policy, no trigger -> snapshot-load syncs."""
        text = self._text(
            tmp_path,
            (5, "jump", {"reason": "snapshot-load", "snapshot": "clean"}),
            (6, "sync", {"reason": "sync", "snapshot": "clean", "ok": True}),
        )
        assert f"{self.STEM}: after snapshot loads" in text
        assert "1 clock sync (0 at session start, 1 after snapshot loads)." in text

    def test_nothing_recorded(self, tmp_path, fake_timeline):
        text = self._text(tmp_path)
        assert f"{self.STEM}: not recorded in this timeline." in text
        assert report_engine.CLOCK_CAVEAT in text

    def test_caveat_without_timeline_lines(self):
        ctx = report_engine.ReportContext(
            scope=report_engine.ReportScope(),
            options=report_engine.ReportOptions(),
            masked=False,
            generated_at="2026-11-19T12:00:00+00:00",
        )
        doc = report_engine.build_coverage(ctx)
        items = [i for b in doc["blocks"] if b["type"] == "list" for i in b["items"]]
        assert report_engine.CLOCK_CAVEAT in items


class TestCoverage:
    def test_sentences_for_each_interval_type(self, session):
        text = "\n".join(_sentences(_build(session)))
        expected = [
            "Tracking was on from 12:00:06 to 12:01:40 (mode full, started by user).",
            "The accessibility UI helper was active from 12:00:06 to 12:01:40; "
            "the app can detect it.",
            "Screenshots before taps were off from 12:00:25 to 12:00:35.",
            "Screenshots after taps were off for the whole timeline.",
            "files.open lines were stored as counts only for the whole timeline.",
            "File modifications were coalesced within 1000 ms windows for the whole "
            "timeline.",
            "The policy changed at 12:00:25 (settings, by user): "
            "tracking.shot_before_tap True → False.",
            "142 bulk lines were dropped and are missing from the timeline "
            "(files: 140, monitor: 2; reasons queue-full: 130, no-device: 12).",
            "The timeline was resumed at 12:01:20 after an unclean shutdown, 42 s later.",
            "A torn fragment of 37 bytes at offset 12345 was left by the interruption",
            "The largest stated time uncertainty is ±12.0 ms.",
            "(snapshot loads 1, cold boots 0, inferred clock rewinds 0); world 0–1",
            "Sensitive values such as typed passwords are shown in clear (1 sensitive "
            "line)",
            "The hash chain verified up to the seal",
        ]
        for snippet in expected:
            assert snippet in text, snippet
        assert re.search(r"1 of \d+ lines have no reliable event time", text)

    def test_tracking_never_on_and_no_interventions(self, tmp_path, fake_timeline):
        tl = TimelineFixture(tmp_path / "dev")
        tl.add(0, "sandroid", "open", data={"session_id": SESSION_ID})
        tl.write()
        doc = report_engine.build_report(
            timeline=tl.path,
            seal=_fake_seal_file(tl.path),
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        text = "\n".join(_sentences(doc))
        assert "Tracking was off for the whole report window" in text
        assert "No interventions" in text
        assert "No lines were dropped." in text
        assert "No recording-policy line was found" in text
        assert _section(doc, "transcript")["blocks"][0]["text"].startswith(
            "Nothing to show"
        )

    def test_dropped_screen_shots_are_stated_not_shown(self, tmp_path, fake_timeline):
        """DESIGN_FINAL §12 (F2 under load): Tracking drops a screen-change
        shot that would be taken after the next input or a newer screen; the
        report says how many, and no step shows an image for them.
        """
        tl = TimelineFixture(tmp_path / "dev")
        tl.add(0, "sandroid", "open", data={"session_id": SESSION_ID})
        tl.add(1, "tracking", "start", "tracking on", actor="user",
               data={"mode": "full", "reason": "user"})  # fmt: skip
        win = tl.add(2, "screen", "window", "→ com.x/.Home", actor="app",
                     data={"pkg": "com.x", "cls": "com.x.Home", "via": "a11y"})  # fmt: skip
        tl.add(9, "tracking", "stop", "tracking off", actor="user",
               data={"reason": "user",
                     "shots_dropped": {"late": 2, "superseded": 1}})  # fmt: skip
        tl.write()
        doc = report_engine.build_report(
            timeline=tl.path,
            seal=_fake_seal_file(tl.path),
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        text = "\n".join(_sentences(doc))
        assert "3 screen-change screenshots were not taken: the next input" in text
        assert "not kept" not in text
        assert _step(doc, win)["shots"] == []

    def test_unverified_screen_shots_are_stated_not_shown(
        self, tmp_path, fake_timeline
    ):
        """DESIGN_FINAL §12: a screen-change frame still equal to the old
        screen when the wait ended is dropped (``unverified``); the report
        states it apart from the late/superseded ones.
        """
        tl = TimelineFixture(tmp_path / "dev")
        tl.add(0, "sandroid", "open", data={"session_id": SESSION_ID})
        tl.add(1, "tracking", "start", "tracking on", actor="user",
               data={"mode": "invisible", "reason": "user"})  # fmt: skip
        act = tl.add(2, "screen", "activity", "→ com.x/.Sub", actor="app",
                     data={"pkg": "com.x", "cls": "com.x.Sub", "via": "logcat"})  # fmt: skip
        tl.add(9, "tracking", "stop", "tracking off", actor="user",
               data={"reason": "user",
                     "shots_dropped": {"late": 1, "unverified": 2}})  # fmt: skip
        tl.write()
        doc = report_engine.build_report(
            timeline=tl.path,
            seal=_fake_seal_file(tl.path),
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        text = "\n".join(_sentences(doc))
        assert "1 screen-change screenshot was not taken: the next input" in text
        assert (
            "2 screen-change screenshots were not kept: the device still showed "
            "the previous screen" in text
        )
        assert _step(doc, act)["shots"] == []

    def test_no_timeline_is_stated(self, tmp_path):
        doc = report_engine.build_report(
            timeline=None, seal=None, scope=report_engine.ReportScope(), bundle_dir=None
        )
        text = "\n".join(_sentences(doc))
        assert "No session timeline was available" in text
        assert "This report is not sealed" in json.dumps(_section(doc, "seal"))


class TestResultsAndSeal:
    def test_results_parity_with_legacy_sections(self, session):
        data = _results()
        data[run_report.RUN_METADATA_KEY] = {"settings": {"analysis": {"x": 1}}}
        (session.bundle / "sandroid.json").write_text(json.dumps(data))
        blocks = _section(_build(session), "results")["blocks"]
        titles = [b["text"] for b in blocks if b["type"] == "heading"]
        assert titles == [
            "Summary",
            "Analysis settings",
            "Changed Files",
            "New Files",
            "Deleted Files",
            "Processes",
            "Listening Sockets",
            "Network (DNS names)",
            "Network IP:Port (send/recv)",
            "APKs & Hashes",
            "Hashes of new files",
            "Hashes of changed files (before / after action)",
            "Filtered Noise",
        ]
        dumped = json.dumps(blocks)
        assert "Total number of artifacts found" in dumped
        assert "SHA-256: " + "e" * 64 in dumped
        assert "/data/system/netstats/x" in dumped
        assert "[INSERT] Table [t] row [1,'<x> & y']" in dumped

    def test_run_errors_banner_in_overview(self, session):
        from sandroid.analysis.run_config import RunResult, StepError

        result = RunResult(
            device_name="emu",
            error="Failed to load emulator snapshot 'tmp'",
            per_step_errors=[
                StepError(label="gather:NewFiles", run_number=2, error="boom")
            ],
        )
        out = run_report.finalize_run(session.bundle, result.to_json_dict())
        assert out.errors == []
        doc = json.loads(out.report_json.read_text())
        overview = json.dumps(_section(doc, "overview"))
        assert "RUN ABORTED" in overview
        assert "boom" in overview

    def test_seal_block_equals_seal(self, session):
        seal = _fake_seal_file(session.tl.path)
        doc = report_engine.build_report(
            timeline=session.tl.path,
            seal=seal,
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        assert doc["seal"] == asdict(seal)
        rows = dict(_section(doc, "seal")["blocks"][0]["rows"])
        assert rows["File SHA-256"] == seal.sha256
        assert rows["Bytes covered"] == seal.bytes
        assert rows["Lines"] == f"{seal.seq_first}–{seal.seq_last}"

    def test_failing_builder_becomes_error_block(self, session, monkeypatch):
        def boom(ctx):
            raise RuntimeError("transcript exploded")

        plan = tuple(
            report_engine.SectionSpec(s.id, s.title, boom)
            if s.id == "transcript"
            else s
            for s in report_engine.SECTION_PLAN
        )
        monkeypatch.setattr(report_engine, "SECTION_PLAN", plan)
        doc = _build(session)
        assert _section(doc, "transcript")["blocks"] == [
            {"type": "error", "error": "RuntimeError: transcript exploded"}
        ]
        assert _section(doc, "results")["blocks"]
        assert _section(doc, "coverage")["blocks"]
        md = report_render.render_markdown(doc, base_dir=session.bundle)
        assert "this part could not be built (RuntimeError: transcript exploded)" in md

    def test_sections_option_selects_and_orders(self, session):
        doc = _build(session, sections=("seal", "overview", "bogus"))
        assert [s["id"] for s in doc["sections"]] == ["seal", "overview"]


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _page_count(pdf: Path) -> int:
    counts = re.findall(rb"/Count (\d+)", pdf.read_bytes())
    return max(int(c) for c in counts)


def _paragraph_texts(flowables) -> list[str]:
    out: list[str] = []
    for f in flowables:
        if isinstance(f, (list, tuple)):
            out.extend(_paragraph_texts(f))
        elif hasattr(f, "_cellvalues"):
            for row in f._cellvalues:
                out.extend(_paragraph_texts([c for c in row if c is not None]))
        elif isinstance(getattr(f, "text", None), str):
            out.append(f.text)
    return out


class TestRenderers:
    def test_write_report_json_md_pdf(self, session):
        doc = _build(session)
        written = report_engine.write_report(doc, session.bundle)
        assert set(written) == {"json", "md", "pdf"}
        data = json.loads(written["json"].read_text())
        # Image paths are relative to the report folder.
        shot = _step(data, session.seqs["tap_accept"])["shots"][0]
        assert not Path(shot["path"]).is_absolute()
        assert (session.bundle / shot["path"]).resolve().is_file()
        pdf = written["pdf"]
        assert pdf.read_bytes()[:5] == b"%PDF-"
        assert _page_count(pdf) >= 4

    def test_pdf_story_has_every_section(self, session):
        data = json.loads(
            report_engine.write_report(
                _build(session), session.bundle, formats=("json",)
            )["json"].read_text()
        )
        renderer = report_render.PdfRenderer(data, session.bundle)
        renderer.build(session.root / "x.pdf")
        texts = "\n".join(_paragraph_texts(renderer.story))
        for title in (
            "Overview",
            "Coverage and validity",
            "Interaction transcript",
            "Analysis results",
            "Timeline seal",
        ):
            assert title in texts
        assert "Accept all" in texts
        assert "&lt;x&gt; &amp; y" in texts
        assert renderer.degraded_sections == []

    def test_markdown_golden_snippets(self, session):
        doc = _build(session)
        written = report_engine.write_report(
            doc, session.bundle, formats=("json", "md")
        )
        md = written["md"].read_text()
        snippets = [
            "# Sandroid Forensic Report",
            "## Interaction transcript",
            "### Label 1 'Onboarding' · 12:00:05–12:01:20 · 75 s",
            "#### Label 2 'Login' · 12:00:15–12:00:30 · 15 s",
            f"- **12:00:10.000** · tap · 'Accept all' (Button) at (540, 1650) · "
            f"#{session.seqs['tap_accept']} ✓",
            "  - Screen: com.x/.MainActivity 'Welcome'",
            "  - Files (app): 2 event(s) (create 1, modify 1): "
            r"/data/data/com.x/databases/app.db ×3 (#",
            "  - Network: 1 flow(s): POST 200 api.x.com/v1/consent (#",
            f"  - ![before tap · #{session.seqs['shot_accept']}]"
            f"(../../../session/dev/tracking/shots/{session.seqs['shot_accept']}"
            "_before_tap.png)",
            f"- **12:00:15.500** · activity · Screen → com.x/.LoginActivity 'Sign in' · "
            f"#{session.seqs['screen2']}",
            "- **12:01:30.000** · key · 'BACK' · #",
            "### Unlabelled",
            "| **File SHA-256** |",
        ]
        for snippet in snippets:
            assert snippet in md, snippet

    def test_image_hash_mismatch_becomes_warning(self, session):
        doc = _build(session)
        shot = _step(doc, session.seqs["tap_accept"])["shots"][0]
        Path(shot["path"]).write_bytes(b"not the screenshot")
        written = report_engine.write_report(doc, session.bundle)
        md = written["md"].read_text()
        assert "does not match its recorded SHA-256" in md
        assert written["pdf"].read_bytes()[:5] == b"%PDF-"

    def test_renderers_never_read_the_timeline(self, session):
        doc = _build(session)
        written = report_engine.write_report(doc, session.bundle, formats=("json",))
        data = json.loads(written["json"].read_text())
        session.tl.path.unlink()
        FAKE_STATE["reads"].clear()
        md = report_render.render_markdown(data, base_dir=session.bundle)
        report_render.render_pdf(data, session.root / "r.pdf", base_dir=session.bundle)
        assert "Accept all" in md
        assert FAKE_STATE["reads"] == []

    def test_assets_load_independent_of_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert (
            report_render._asset_bytes(report_render.FRAUNHOFER_LOGO)[:2] == b"\xff\xd8"
        )
        assert report_render._asset_bytes(report_render.SANDROID_LOGO)[:4] == b"\x89PNG"


# ---------------------------------------------------------------------------
# finalize_run / report_from_folder / manifest
# ---------------------------------------------------------------------------


def _bound(session) -> FakeService:
    service = FakeService(session.tl.folder)
    FAKE_STATE["service"] = service
    return service


class TestFinalize:
    def test_finalize_seals_and_writes_reports(self, session):
        service = _bound(session)
        size_before = session.tl.path.stat().st_size
        outcome = run_report.finalize_run(
            session.bundle, _results(), run_id=RUN_ID, generate_pdf=True
        )
        assert outcome.errors == []
        assert service.seals == [
            {"by": "report", "report": f"../../results/runs/{RUN_ID}/report.json"}
        ]
        assert outcome.report_json == session.bundle / "report.json"
        assert outcome.markdown == session.bundle / "report.md"
        assert outcome.pdf == session.bundle / run_report.DEFAULT_PDF_NAME
        seal_doc = json.loads(outcome.timeline_seal.read_text())
        assert seal_doc["timeline_path"] == str(session.tl.path.resolve())
        assert seal_doc["seal"]["bytes"] == size_before
        assert seal_doc["session_id"] == SESSION_ID
        doc = json.loads(outcome.report_json.read_text())
        assert doc["seal"] == seal_doc["seal"]
        assert doc["scope"]["seq_range"] == [
            session.seqs["record_start"],
            session.seqs["record_stop"],
        ]
        assert _steps(doc)
        listed = {
            f["path"]
            for f in json.loads(outcome.manifest.manifest_path.read_text())["files"]
        }
        assert {
            "sandroid.json",
            "report.json",
            "report.md",
            "timeline_seal.json",
            run_report.DEFAULT_PDF_NAME,
        } <= listed
        assert run_report.verify_hash_manifest(session.bundle).ok

    def test_finalize_without_pdf(self, session):
        _bound(session)
        outcome = run_report.finalize_run(session.bundle, _results(), run_id=RUN_ID)
        assert outcome.pdf is None
        assert outcome.report_json.is_file()
        assert outcome.markdown.is_file()
        assert not list(session.bundle.glob("*.pdf"))

    def test_finalize_cli_session_folder_uses_seal_file(self, session):
        FAKE_STATE["service"] = FakeService(None, "detached")
        root = session.root / "session"
        outcome = run_report.finalize_run(root, _results())
        assert outcome.errors == []
        doc = json.loads(outcome.report_json.read_text())
        assert doc["seal"]["bytes"] == session.tl.path.stat().st_size
        assert _steps(doc)
        manifest = json.loads(outcome.manifest.manifest_path.read_text())
        excluded = {e["path"] for e in manifest["excluded"]}
        assert "dev/timeline.jsonl" in excluded
        assert manifest["timeline_seals"][0]["sha256"] == doc["seal"]["sha256"]
        assert manifest["timeline_seals"][0]["rel"] == "dev/timeline.jsonl"

    def test_finalize_locked_timeline_is_noted(self, session):
        FAKE_STATE["service"] = FakeService(session.tl.folder, "locked")
        outcome = run_report.finalize_run(session.bundle, _results())
        doc = json.loads(outcome.report_json.read_text())
        assert outcome.timeline_seal is None
        assert any("PID 4711" in s for s in _sentences(doc))

    def test_finalize_report_failure_is_reported_not_raised(self, session, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("render failed")

        monkeypatch.setattr(report_render, "render_pdf", boom)
        outcome = run_report.finalize_run(session.bundle, _results(), generate_pdf=True)
        assert outcome.pdf is None
        assert outcome.errors == ["pdf: render failed"]
        assert outcome.report_json is not None
        assert outcome.manifest is not None


class TestReportFromFolder:
    @staticmethod
    def _snapshot(folder: Path) -> dict[str, bytes]:
        return {
            p.relative_to(folder).as_posix(): p.read_bytes()
            for p in sorted(folder.rglob("*"))
            if p.is_file()
        }

    def _sealed(self, session) -> Path:
        _bound(session)
        outcome = run_report.finalize_run(
            session.bundle, _results(), run_id=RUN_ID, generate_pdf=True
        )
        assert outcome.errors == []
        FAKE_STATE["service"] = None
        return session.bundle

    def test_regenerates_without_overwriting(self, session):
        root = self._sealed(session)
        before = self._snapshot(root)
        out = run_report.report_from_folder(root)
        assert out.check.ok
        assert out.timeline_note is None
        stem = out.report_json.stem
        assert stem.startswith("report_regenerated_")
        assert stem.endswith("Z")
        assert out.pdf.name == f"{stem}.pdf"
        assert out.markdown.name == f"{stem}.md"
        after = self._snapshot(root)
        assert {k: after[k] for k in before} == before
        added = set(after) - set(before)
        assert added == {
            out.report_json.name,
            out.markdown.name,
            out.pdf.name,
            out.addendum.name,
        }
        lines = out.addendum.read_text().splitlines()
        assert lines[-1] == f"{run_report.sha256_file(root / 'SHA256SUMS')}  SHA256SUMS"
        assert len(lines) == 4
        doc = json.loads(out.report_json.read_text())
        assert _steps(doc)  # re-derived from the (unchanged) timeline prefix
        assert "regenerated" not in doc
        again = run_report.report_from_folder(root)
        assert again.pdf != out.pdf
        assert run_report.verify_hash_manifest(root).ok

    def test_changed_timeline_prefix_is_detected(self, session):
        root = self._sealed(session)
        raw = bytearray(session.tl.path.read_bytes())
        raw[raw.index(b"Pixel_API_35")] = ord("Q")
        session.tl.path.write_bytes(bytes(raw))
        out = run_report.report_from_folder(root)
        assert "changed" in out.timeline_note
        doc = json.loads(out.report_json.read_text())
        assert doc["regenerated"]["from"] == "report.json"
        first = _section(doc, "coverage")["blocks"][0]
        assert first["level"] == "warn"
        assert "could not be re-derived from the timeline" in first["text"]
        assert _steps(doc)  # copied from the self-contained report.json
        md = out.markdown.read_text()
        assert "'Sign in' (Button)" in md

    def test_missing_timeline_is_detected(self, session):
        root = self._sealed(session)
        session.tl.path.unlink()
        out = run_report.report_from_folder(root)
        assert "is missing" in out.timeline_note
        assert out.pdf.read_bytes()[:5] == b"%PDF-"

    def test_appended_timeline_still_verifies(self, session):
        root = self._sealed(session)
        with open(session.tl.path, "a", encoding="utf-8") as fh:
            fh.write('{"seq": 999, "src": "label", "kind": "point"}\n')
        out = run_report.report_from_folder(root)
        assert out.timeline_note is None

    def test_folder_without_seal_omits_transcript(self, session):
        (session.bundle / "sandroid.json").write_text(json.dumps(_results()))
        out = run_report.report_from_folder(session.bundle)
        assert out.report_json.name == "report.json"
        assert out.pdf.name == run_report.DEFAULT_PDF_NAME
        doc = json.loads(out.report_json.read_text())
        assert not _steps(doc)
        assert any("no sealed session timeline" in s for s in _sentences(doc))

    def test_fallback_masks_and_does_not_claim_a_verified_chain(self, session):
        root = self._sealed(session)  # masking off: the password is in clear
        assert PASSWORD in (root / "report.json").read_text()
        session.tl.path.unlink()
        FAKE_STATE["mask"] = True  # the user turned masking on since
        out = run_report.report_from_folder(root)
        assert "is missing" in out.timeline_note
        text = out.report_json.read_text()
        assert PASSWORD not in text
        assert PASSWORD not in out.markdown.read_text()
        doc = json.loads(text)
        assert doc["masking"]["sensitive_masked"] is True
        pw = next(s for s in _steps(doc) if s.get("kind") == "text" and s["password"])
        assert (pw["text"], pw["text_masked"], pw["masked"]) == (None, True, True)
        assert doc["seal"]["verified"] is None
        assert doc["seal"]["verified_originally"] is True
        rows = {
            r[0]: r[1]
            for b in _section(doc, "seal")["blocks"]
            if b.get("type") == "kv"
            for r in b["rows"]
        }
        assert rows["Chain verified"].startswith("not re-checked")
        assert not any(
            s.startswith("The hash chain verified") and "not re-checked" not in s
            for s in _sentences(doc)
        )
        assert "Chain verified | yes" not in out.markdown.read_text()

    def test_a_failed_render_leaves_no_regenerated_files(self, session, monkeypatch):
        from sandroid.core import report_render

        root = self._sealed(session)
        before = self._snapshot(root)

        def broken(*args, **kwargs):
            raise RuntimeError("renderer broke")

        monkeypatch.setattr(report_render, "render_markdown", broken)
        with pytest.raises(RuntimeError):
            run_report.report_from_folder(root)
        assert self._snapshot(root) == before
        assert not list(root.glob("report_regenerated_*"))


class TestManifest:
    def test_live_timeline_excluded_and_sealed(self, tmp_path, fake_timeline):
        tl, _ = build_fixture(tmp_path / "dev")
        (tmp_path / "dev" / ".timeline.lock").write_text("{}")
        raw = tmp_path / "dev" / "tracking" / "raw" / "getevent.txt"
        raw.parent.mkdir(parents=True)
        raw.write_text("[ 1.0] /dev/input/event1: 0003 0035 00000010\n")
        (tmp_path / "sandroid.json").write_text("{}")
        info = run_report.write_hash_manifest(tmp_path)
        manifest = json.loads(info.manifest_path.read_text())
        files = {f["path"] for f in manifest["files"]}
        excluded = {e["path"]: e["reason"] for e in manifest["excluded"]}
        assert "dev/timeline.jsonl" in excluded
        assert "dev/.timeline.lock" in excluded
        assert "dev/tracking/raw/getevent.txt" in excluded
        assert "dev/tracking/shots" not in " ".join(excluded)
        assert any(f.startswith("dev/tracking/shots/") for f in files)
        seal = manifest["timeline_seals"][0]
        assert seal["sha256"] == _fake_seal_file(tl.path).sha256
        # Growing the live timeline does not break verification.
        with open(tl.path, "a") as fh:
            fh.write("{}\n")
        assert run_report.verify_hash_manifest(tmp_path).ok

    def test_seal_fallback_without_timeline_module(self, tmp_path, monkeypatch):
        monkeypatch.setattr(report_engine, "_timeline_module", lambda: None)
        path = tmp_path / "dev" / "timeline.jsonl"
        path.parent.mkdir()
        path.write_bytes(b'{"seq":1}\n')
        (path.parent / ".timeline.lock").write_text("{}")
        manifest = json.loads(
            run_report.write_hash_manifest(tmp_path).manifest_path.read_text()
        )
        assert manifest["timeline_seals"] == [
            {
                "rel": "dev/timeline.jsonl",
                "path": str(path.resolve()),
                "bytes": 10,
                "sha256": hashlib.sha256(b'{"seq":1}\n').hexdigest(),
            }
        ]

    def test_only_the_real_sink_locations_are_live(self, tmp_path):
        dev = tmp_path / "dev"
        tl, _ = build_fixture(dev)  # dev/timeline.jsonl + dev/.timeline.lock
        files = {
            # The legacy Files-lens timeline and an app file of that name.
            "dev/files/timeline.jsonl": b"legacy\n",
            "dev/files/com.app/cache/timeline.jsonl": b"forged by the app\n",
            "dev/files/com.app/tracking/raw/x.bin": b"app data\n",
            "dev/files/com.app/.timeline.lock": b"{}",
            "dev/tracking/raw/getevent.txt": b"[ 1.0] event\n",
        }
        for rel, data in files.items():
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_bytes(data)
        for root, prefix in ((tmp_path, "dev/"), (dev, "")):
            manifest = json.loads(
                run_report.write_hash_manifest(root).manifest_path.read_text()
            )
            hashed = {f["path"] for f in manifest["files"]}
            excluded = {e["path"] for e in manifest["excluded"]}
            assert {f"{prefix}timeline.jsonl", f"{prefix}.timeline.lock",
                    f"{prefix}tracking/raw/getevent.txt"} <= excluded  # fmt: skip
            assert {
                f"{prefix}files/timeline.jsonl",
                f"{prefix}files/com.app/cache/timeline.jsonl",
                f"{prefix}files/com.app/tracking/raw/x.bin",
                f"{prefix}files/com.app/.timeline.lock",
            } <= hashed
            assert [s["rel"] for s in manifest["timeline_seals"]] == [
                f"{prefix}timeline.jsonl"
            ]
            assert [r["rel"] for r in manifest["raw_prefixes"]] == [
                f"{prefix}tracking/raw/getevent.txt"
            ]
            for name in ("manifest.json", "SHA256SUMS"):
                (root / name).unlink()

    def test_sealed_prefixes_of_live_files_are_verified(self, tmp_path):
        dev = tmp_path / "dev"
        dev.mkdir()
        (dev / ".timeline.lock").write_text("{}")
        path = dev / "timeline.jsonl"
        path.write_bytes(b'{"seq":1,"summary":"tap OK"}\n')
        raw = dev / "tracking" / "raw" / "getevent.txt"
        raw.parent.mkdir(parents=True)
        raw.write_bytes(b"original raw\n")
        run_report.write_hash_manifest(tmp_path)
        # Appending is fine (both files are append-only).
        with open(path, "ab") as fh:
            fh.write(b'{"seq":2}\n')
        with open(raw, "ab") as fh:
            fh.write(b"more\n")
        assert run_report.verify_hash_manifest(tmp_path).ok
        # Changing the sealed prefix is not.
        path.write_bytes(path.read_bytes().replace(b"tap OK", b"tap NO"))
        raw.write_bytes(b"forged raw!!\nmore\n")
        check = run_report.verify_hash_manifest(tmp_path)
        assert not check.ok
        assert check.mismatched == [
            "dev/timeline.jsonl",
            "dev/tracking/raw/getevent.txt",
        ]
        raw.unlink()
        assert "dev/tracking/raw/getevent.txt" in (
            run_report.verify_hash_manifest(tmp_path).missing
        )


class TestRemovedApi:
    def test_old_modules_and_flags_are_gone(self):
        src = Path(report_engine.__file__).resolve().parents[1]
        pattern = re.compile(
            r"PDFReport|generate_pdf_report|timeline_generator|pdf_report"
        )
        offenders = [
            str(p.relative_to(src))
            for p in src.rglob("*.py")
            if pattern.search(p.read_text(encoding="utf-8", errors="replace"))
        ]
        # analysis/engine.py and analysis/run_config.py only mention the old
        # module names in docstrings (not WP5's files).
        assert set(offenders) <= {"analysis/engine.py", "analysis/run_config.py"}
        with pytest.raises(ImportError):
            __import__("sandroid.core.pdf_report")

    def test_cli_help_works_without_screenshot_flag(self):
        from click.testing import CliRunner

        from sandroid.cli import main

        res = CliRunner().invoke(main, ["--help"])
        assert res.exit_code == 0
        assert "--screenshot" not in res.output
        assert "--report" in res.output


# ---------------------------------------------------------------------------
# Real timeline module (active after the WP1 merge)
# ---------------------------------------------------------------------------


def _real_timeline():
    mod = pytest.importorskip("sandroid.core.timeline")
    if not hasattr(mod, "TimelineService"):
        pytest.skip("sandroid.core.timeline is not the WP1 module yet")
    return mod


def test_real_timeline_finalize_run(tmp_path):
    tl = _real_timeline()
    tl.reset_for_tests()
    try:
        service = tl.get_timeline()
        service.bind("emulator-test", tmp_path / "session" / "dev")
        service.labels.start("Login", level="top", source="api")
        service.emit(
            "input",
            "tap",
            summary="tap 'OK' (Button)",
            actor="user",
            data={"x": 1, "y": 2, "target": {"text": "OK", "cls": "x.Button"}},
        )
        service.emit(
            "input",
            "text",
            summary="typed 8 chars into 'pw' (EditText, password)",
            actor="user",
            sensitive=True,
            data={"text": PASSWORD, "password": True},
        )
        assert service.flush(2.0)
        bundle = tmp_path / "results" / "runs" / "r1"
        outcome = run_report.finalize_run(bundle, {"Device Name": "emu"})
        assert outcome.errors == []
        doc = json.loads(outcome.report_json.read_text())
        assert doc["seal"]["verified"] is True
        steps = _steps(doc)
        assert [s["element"] for s in steps][:1] == ["OK"]
        assert PASSWORD not in [s.get("summary") for s in steps]
    finally:
        tl.reset_for_tests()


def test_real_timeline_report_from_closed_file(tmp_path):
    tl = _real_timeline()
    tl.reset_for_tests()
    try:
        service = tl.get_timeline()
        service.bind("emulator-test", tmp_path / "session" / "dev")
        service.labels.point("mark", source="api")
        service.close("quit")
        path = tmp_path / "session" / "dev" / tl.FILE_NAME
        doc = report_engine.build_report(
            timeline=path,
            seal=tl.seal_file(path),
            scope=report_engine.ReportScope(),
            bundle_dir=None,
        )
        assert doc["timeline"]["available"] is True
        assert any(s["src"] == "label" for s in _steps(doc))
    finally:
        tl.reset_for_tests()


def _label_path_brute(labels, ts, seq):
    """The former O(spans) scan of ``_label_path`` (reference)."""
    open_spans = [
        s
        for s in labels
        if s.kind == "span"
        and (s.ts, s.seq) <= (ts, seq)
        and (s.end_ts is None or (ts, seq) < (s.end_ts, s.end_seq or 0))
    ]
    if not open_spans:
        return []
    inner = max(open_spans, key=lambda s: (s.depth, s.ts, s.seq))
    by_number = {s.number: s for s in labels}
    path = [inner.number]
    parent = inner.parent
    while parent is not None and parent in by_number and len(path) < 32:
        path.insert(0, parent)
        parent = by_number[parent].parent
    return path


@pytest.mark.perf
def test_label_path_index_matches_the_scan_and_is_fast():
    import random
    import time as _time

    rng = random.Random(7)  # noqa: S311 - test data
    labels = []
    for number in range(1, 301):
        ts = rng.uniform(0, 1000)
        kind = rng.choice(["span", "span", "point"])
        end = ts + rng.uniform(0, 80) if kind == "span" and rng.random() < 0.9 else None
        if rng.random() < 0.05 and end is not None:
            end = ts  # starts and ends at the same instant
        parent = rng.choice([None, *range(1, number)]) if number > 1 else None
        labels.append(
            report_engine.LabelSpan(
                number=number, name="", kind=kind, parent=parent,
                depth=rng.randint(0, 3), seq=number * 10, t="", ts=ts,
                end_t="" if end is not None else None, end_ts=end,
                end_seq=number * 10 + 5 if end is not None else None,
            )
        )  # fmt: skip
    ctx = SimpleNamespace(labels=labels, label_index=None)
    queries = [(rng.uniform(-10, 1100), rng.randint(0, 3100)) for _ in range(3000)]
    queries += [(s.ts, s.seq) for s in labels]
    queries += [(s.end_ts, s.end_seq) for s in labels if s.end_ts is not None]
    for ts, seq in queries:
        assert report_engine._label_path(ctx, ts, seq) == _label_path_brute(
            labels, ts, seq
        ), (ts, seq)
    # 20k lookups over 1k spans: one bisect each, not a scan.
    many = labels * 4
    for i, s in enumerate(many):
        s.number = i + 1
    ctx = SimpleNamespace(labels=many, label_index=None)
    start = _time.perf_counter()
    for i in range(20_000):
        report_engine._label_path(ctx, i * 0.05, i)
    assert _time.perf_counter() - start < 2.0


def test_a_marked_copy_is_shown_and_the_original_stays_the_evidence(tmp_path):
    """tracking.mark_screenshots: the report shows the marked copy
    (verified against its own sha256); R1 comparisons read the original.
    """
    shots = tmp_path / "tracking" / "shots"
    shots.mkdir(parents=True)
    original, marked = b"\x89PNG original", b"\x89PNG marked"
    (shots / "7_before_tap.png").write_bytes(original)
    (shots / "abc_before_tap_marked.png").write_bytes(marked)
    sha = hashlib.sha256
    line = {
        "seq": 8, "src": "shot", "kind": "before_tap", "t": "2026-11-19T12:00:00Z",
        "ref": {"of": 7, "path": "tracking/shots/7_before_tap.png",
                "sha256": sha(original).hexdigest()},
        "data": {"trigger": "before_tap", "w": 1080, "h": 2424,
                 "marked": {"path": "tracking/shots/abc_before_tap_marked.png",
                            "sha256": sha(marked).hexdigest()}},
    }  # fmt: skip
    ctx = report_engine.ReportContext(
        scope=report_engine.ReportScope(),
        options=report_engine.ReportOptions(),
        masked=False,
        generated_at="2026-11-19T12:00:00+00:00",
        timeline_dir=tmp_path,
    )
    block = report_engine._image_block(ctx, line)
    assert block["marked"] is True
    assert block["sha256"] == sha(marked).hexdigest()
    assert block["path"].endswith("abc_before_tap_marked.png")
    assert block["original"]["sha256"] == sha(original).hexdigest()
    assert report_engine._png_of(block) == original
    path, warning = report_render.ImageCheck(tmp_path).resolve(block)
    assert warning is None
    assert path.read_bytes() == marked
    rel = report_engine._relativize({"blocks": [block]}, tmp_path)["blocks"][0]
    assert rel["path"] == "tracking/shots/abc_before_tap_marked.png"
    assert rel["original"]["path"] == "tracking/shots/7_before_tap.png"
    # masked (a sensitive line): no data, the original image only
    plain = report_engine._image_block(ctx, {**line, "data": {"_masked": True}})
    assert "marked" not in plain
    assert plain["sha256"] == sha(original).hexdigest()


def test_a_web_form_control_is_named_by_its_label():
    target = {"rid": "chk", "cls": "android.widget.CheckBox",
              "web": {"field": "I agree", "role": "check box"}}  # fmt: skip
    assert report_engine.element_name(target) == "I agree"


def test_a_masked_copy_hides_quoted_text_and_marked_images():
    """annotate_rerender with masking on: the summary that quotes typed text
    becomes the count, a marked copy gives way to the original.
    """
    marked = {"type": "image", "path": "m.png", "sha256": "m" * 64, "marked": True,
              "original": {"path": "o.png", "sha256": "o" * 64}}  # fmt: skip
    doc = {"sections": [{"blocks": [
        {"type": "transcript_step", "sensitive": True, "kind": "text",
         "src": "input", "text": "hunter2",
         "summary": "typed \"hunter2\" into password field 'pw'",
         "masked_summary": "typed 7 chars into password field 'pw'",
         "shots": [dict(marked)]},
        {"type": "transcript_step", "sensitive": True, "kind": "text",
         "src": "input", "text": "hunter2",
         "summary": "typed \"hunter2\" into password field 'pw'"},
        {"type": "transcript_step", "kind": "window", "src": "screen",
         "summary": "screen", "shots": [{**marked, "sensitive": True}]},
    ]}]}  # fmt: skip
    out = report_engine.annotate_rerender(doc, "gone", mask_sensitive=True)
    blocks = [
        b
        for sec in out["sections"]
        for b in sec["blocks"]
        if b.get("type") == "transcript_step"
    ]
    assert "hunter2" not in json.dumps(blocks)
    assert blocks[0]["summary"] == "typed 7 chars into password field 'pw'"
    assert blocks[1]["summary"] == "typed text (masked)"  # an older report
    for shot in (blocks[0]["shots"][0], blocks[2]["shots"][0]):
        assert shot["path"] == "o.png"
        assert shot["sha256"] == "o" * 64
        assert "marked" not in shot


def test_a_sensitive_step_keeps_its_masked_summary_for_later_copies():
    ctx = report_engine.ReportContext(
        scope=report_engine.ReportScope(),
        options=report_engine.ReportOptions(),
        masked=False,
        generated_at="2026-11-20T12:00:00+00:00",
    )
    line = {"seq": 3, "src": "input", "kind": "text", "sensitive": True,
            "summary": "typed \"hunter2\" into password field 'pw'",
            "data": {"text": "hunter2", "password": True,
                     "masked_summary": "typed 7 chars into password field 'pw'"}}  # fmt: skip
    step = report_engine._step(
        ctx, line, screen=None, shots=report_engine._Shots(ctx, []),
        confirmed=set(), label=[],
    )  # fmt: skip
    assert step["masked_summary"] == "typed 7 chars into password field 'pw'"
    copy_doc = {"sections": [{"blocks": [step]}]}
    out = report_engine.annotate_rerender(copy_doc, "gone", mask_sensitive=True)
    assert "hunter2" not in json.dumps(out["sections"])
