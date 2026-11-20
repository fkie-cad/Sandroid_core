"""Tracking v1 (WP4): getevent decoding, input/text/screen/shot/tracking lines,
the shared getevent reader with Record, the player formats and net flows.

No device: getevent/logcat are fake processes fed from fixtures, the UI helper
is a fake, and every line is collected with ``timeline.capture()``.
"""

from __future__ import annotations

import hashlib
import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.config.schema import TrackingConfig
from sandroid.core import timeline
from sandroid.core.uihelper import ShotResult
from sandroid.services import tracking_service as ts

FIX = Path(__file__).parent / "fixtures"
PNG_A = b"\x89PNG\r\n\x1a\n" + b"A" * 64
PNG_B = b"\x89PNG\r\n\x1a\n" + b"B" * 64
SERIAL = "emulator-test"


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeStdout:
    def __init__(self) -> None:
        self.q: queue.Queue = queue.Queue()

    def readline(self) -> bytes:
        item = self.q.get()
        return b"" if item is None else item


class FakeProc:
    def __init__(self, argv) -> None:
        self.argv = argv
        self.stdout = FakeStdout()
        self.rc = None
        self.terminated = False

    def feed(self, *lines: str) -> None:
        for line in lines:
            self.stdout.q.put((line.rstrip("\n") + "\n").encode())

    def poll(self):
        return self.rc

    def wait(self, timeout=None):
        return self.rc

    def terminate(self) -> None:
        self.terminated = True
        self.rc = -15
        self.stdout.q.put(None)

    kill = terminate


class FakePopen:
    def __init__(self) -> None:
        self.procs: list[FakeProc] = []

    def __call__(self, argv, **kwargs):
        proc = FakeProc(argv)
        self.procs.append(proc)
        return proc

    def of(self, word: str) -> list[FakeProc]:
        return [p for p in self.procs if word in " ".join(p.argv)]


GETEVENT_P = """add device 1: /dev/input/event0
  name:     "gpio-keys"
add device 2: /dev/input/event1
  name:     "virtio_input_multi_touch_1"
  events:
    ABS (0003): 002f  : value 0, min 0, max 9, fuzz 0, flat 0, resolution 0
                0035  : value 0, min 0, max 32767, fuzz 0, flat 0, resolution 0
                0036  : value 0, min 0, max 32767, fuzz 0, flat 0, resolution 0
"""


class FakeRun:
    def __init__(self, screencap: bytes | None = PNG_A) -> None:
        self.calls: list[list[str]] = []
        self.screencap = screencap

    def __call__(self, argv, timeout=10.0):
        self.calls.append(list(argv))
        cmd = " ".join(argv)
        if "getevent -p" in cmd:
            return 0, GETEVENT_P.encode()
        if "wm size" in cmd:
            return 0, b"Physical size: 1080x2424\n"
        if "SurfaceOrientation" in cmd:
            return 0, b"      SurfaceOrientation: 0\n"
        if "cat " + ts.PIDFILE in cmd:
            return 0, b"4242\n"
        if "screencap" in cmd:
            return (0, self.screencap) if self.screencap else (1, b"")
        return 0, b""


class FakeHelper:
    def __init__(self, serial, mode, on_event, on_status, raw_log, **kw) -> None:
        self.serial = serial
        self.mode = mode
        self.on_event = on_event
        self.on_status = on_status
        self.alive = False
        self.hello = {"display": {"w": 1080, "h": 2424, "rotation": 0}}
        self.node_reply: dict | None = None
        self.node_gate: threading.Event | None = None  # node_at blocks on it
        self.node_returned = 0
        self.node_calls: list[tuple] = []
        self.cached_calls: list[tuple] = []
        self.shots: list[ShotResult] = []
        self.hashes: list[str] = []
        self.shot_calls = 0
        self.shot_t_ms = 500.0
        self.last_error = None
        self.start_ok = True
        self.stopped = False
        self.focus_reply: dict | None = None  # the read-back of a field
        self.focus_calls: list[tuple] = []
        #: the live re-read after a dropped cache (``node_at`` live)
        self.fresh_reply: dict | None = None
        self.fresh_calls: list[tuple] = []
        self.first_clears: list[tuple] = []
        self.cleared = 0

    def clear_cache(self, timeout=1.0):
        self.cleared += 1
        return True

    def _info(self) -> dict:
        info = {"serial": self.serial, "mode": self.mode, "pid": 77}
        info["flags"] = 1 if self.mode == "full" else 2
        info["a11y_before"] = (
            {"accessibility_enabled": "0"} if self.mode == "full" else {}
        )
        return info

    def start(self) -> bool:
        if not self.start_ok:
            self.last_error = "busy"
            self.on_status("busy", self._info())
            return False
        self.alive = True
        self.on_status("connected", self._info())
        return True

    def stop(self) -> None:
        self.alive = False
        self.stopped = True
        self.on_status("stopped", {**self._info(), "a11y_restored": True})

    def node_at(
        self, x, y, *, t_mono_ms=None, timeout=1.0, mode="both", clear_first=False
    ):
        if clear_first:  # the cache is dropped right ahead of the lookup
            self.cleared += 1
            self.first_clears.append((x, y))
            if self.fresh_reply is not None:
                return {**(self.node_reply or {}), "live": self.fresh_reply}
        if mode == "cached":  # the snapshot alone: answered at once
            self.cached_calls.append((x, y, t_mono_ms))
            cached = (self.node_reply or {}).get("cached")
            return {"type": "node_at", "cached": cached} if cached else None
        if mode == "live" and self.fresh_reply is not None:
            self.fresh_calls.append((x, y, self.cleared))
            return {"type": "node_at", "live": self.fresh_reply}
        self.node_calls.append((x, y, t_mono_ms))
        if self.node_gate is not None:
            self.node_gate.wait(10.0)
        self.node_returned += 1
        return self.node_reply

    def focus(self, x=None, y=None, *, timeout=1.0):
        self.focus_calls.append((x, y))
        return self.focus_reply

    def shot(self, *, hash_only=False, timeout=5.0):
        self.shot_calls += 1
        if hash_only:
            h = self.hashes.pop(0) if self.hashes else "h-final"
            return ShotResult(1.0, 1080, 2424, h, 3.0, None, None)
        if self.shots:
            return self.shots.pop(0)
        # captured before the taps of the tests (a later capture is "late")
        return ShotResult(self.shot_t_ms, 1080, 2424, "h-before", 14.0, PNG_A, "/x")


def wait_for(cond, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def of(lines, src, kind=None):
    return [x for x in lines if x["src"] == src and (kind is None or x["kind"] == kind)]


NODE_REPLY = {
    "type": "node_at",
    "cached": {
        "hit": {"cls": "android.widget.TextView", "text": "Accept all"},
        "target": {
            "rid": "com.x:id/accept",
            "text": "Accept all",
            "cls": "android.widget.Button",
            "bounds": [60, 1600, 1020, 1700],
        },
        "path": "0/1/3",
        "pkg": "com.x",
        "label": "Accept all",
    },
    "live": {"hit": None, "reason": "no_window"},
}


@pytest.fixture
def cfg(monkeypatch):
    config = TrackingConfig(shot_screen_change=False, logcat_screen_backup=False)
    monkeypatch.setattr(ts, "_config", lambda: config)
    return config


@pytest.fixture
def env(tmp_path, cfg, monkeypatch):
    popen, run = FakePopen(), FakeRun()
    helpers: list[FakeHelper] = []

    def factory(*args):
        h = FakeHelper(*args)
        h.node_reply = NODE_REPLY
        helpers.append(h)
        return h

    svc = ts.TrackingService(
        popen=popen,
        run=run,
        helper_factory=factory,
        folder_fn=lambda serial: tmp_path,
        clock_record=lambda reason, serial: None,
    )
    monkeypatch.setattr(ts, "_SERVICE", svc)
    yield svc, popen, run, helpers, tmp_path
    svc.shutdown(2.0)


def start(svc, popen, helpers, cfg, mode="full"):
    cfg.helper_mode = mode
    assert svc.start(SERIAL, reason="user", actor="user")
    assert wait_for(svc._geometry_ready.is_set)
    if mode != "off":
        assert wait_for(lambda: helpers and helpers[-1].alive)
    return popen.of("getevent -t")[0]


def tap_lines(t: float, x: int = 0x4000, y: int = 0x5000, *, dur: float = 0.08):
    return [
        f"[{t:15.6f}] /dev/input/event1: 0003 0039 00000001",
        f"[{t:15.6f}] /dev/input/event1: 0003 0035 {x:08x}",
        f"[{t:15.6f}] /dev/input/event1: 0003 0036 {y:08x}",
        f"[{t:15.6f}] /dev/input/event1: 0000 0000 00000000",
        f"[{t + dur:15.6f}] /dev/input/event1: 0003 0039 ffffffff",
        f"[{t + dur:15.6f}] /dev/input/event1: 0000 0000 00000000",
    ]


# --------------------------------------------------------------------------
# decoder
# --------------------------------------------------------------------------


def _decode(path: Path):
    d = ts.TouchDecoder()
    out = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        out += d.feed(line, i)
    return out


@pytest.mark.parametrize("name", ["ge_gestures.txt", "ge_chrome.txt"])
def test_decoder_matches_the_prototype_on_fixtures(name):
    expected = json.loads((FIX / "ge_prototype_expected.json").read_text())[name]
    geo = ts.Geometry(1080, 2424)
    events = _decode(FIX / name)
    downs = [e.gesture for e in events if e.kind == "down"]
    ends = [e.gesture for e in events if e.kind == "end"]
    proto_downs = [r for r in expected if r[0] == "down"]
    proto_ups = [r for r in expected if r[0] == "up"]
    assert len(downs) == len(proto_downs) == len(ends) == len(proto_ups) > 5
    for g, (_p, t, x, y, unc) in zip(downs, proto_downs, strict=True):
        assert abs(g.t_down - t) < 1e-6
        assert geo.to_px(g.dev, g.x0, g.y0) == (x, y)
        assert g.uncertain == unc
    for g, (_p, t, x, y, _u) in zip(ends, proto_ups, strict=True):
        assert abs(g.t_up - t) < 1e-6
        assert geo.to_px(g.dev, g.x1, g.y1) == (x, y)
        assert g.line_a <= g.line_b


def test_decoder_ignores_listing_and_garbage_and_btn_keys():
    d = ts.TouchDecoder()
    assert d.feed("add device 1: /dev/input/event0") == []
    assert d.feed('  name:     "gpio-keys"') == []
    assert d.feed("garbage") == []
    assert d.feed("[ 1.000000] /dev/input/event1: 0001 014a 00000001", 1) == []
    assert d.feed("[ 1.000000] /dev/input/event1: 0001 014a 00000000", 2) == []


def test_xy_uncertain_and_scaling_and_rotation():
    d = ts.TouchDecoder()
    first = [  # X never seen: only Y arrives with the down
        "[ 1.000000] /dev/input/event1: 0003 0039 00000001",
        "[ 1.000000] /dev/input/event1: 0003 0036 00004000",
        "[ 1.000000] /dev/input/event1: 0000 0000 00000000",
        "[ 1.050000] /dev/input/event1: 0003 0039 ffffffff",
        "[ 1.050000] /dev/input/event1: 0000 0000 00000000",
    ]
    second = [  # X and Y seen, then a tap at the same spot repeats neither
        "[ 2.000000] /dev/input/event1: 0003 0039 00000002",
        "[ 2.000000] /dev/input/event1: 0003 0035 00004000",
        "[ 2.000000] /dev/input/event1: 0000 0000 00000000",
        "[ 2.050000] /dev/input/event1: 0003 0039 ffffffff",
        "[ 2.050000] /dev/input/event1: 0000 0000 00000000",
        "[ 3.000000] /dev/input/event1: 0003 0039 00000003",
        "[ 3.000000] /dev/input/event1: 0000 0000 00000000",
        "[ 3.050000] /dev/input/event1: 0003 0039 ffffffff",
        "[ 3.050000] /dev/input/event1: 0000 0000 00000000",
    ]
    downs = [
        e.gesture
        for i, line in enumerate(first + second, 1)
        for e in d.feed(line, i)
        if e.kind == "down"
    ]
    assert [g.uncertain for g in downs] == [True, False, False]
    assert (downs[2].x0, downs[2].y0) == (0x4000, 0x4000)
    geo = ts.Geometry(1080, 2400, 0, {"/dev/input/event1": (32767, 32767)})
    assert geo.to_px("/dev/input/event1", 16384, 8192) == (540, 600)
    assert geo.screen == (1080, 2400)
    geo.rotation = 1  # landscape: x' = y, y' = W - 1 - x
    assert geo.screen == (2400, 1080)
    assert geo.to_px("/dev/input/event1", 16384, 8192) == (600, 1080 - 1 - 540)
    geo.rotation = 2
    assert geo.to_px("/dev/input/event1", 0, 0) == (1079, 2399)
    geo.rotation = 3
    assert geo.to_px("/dev/input/event1", 0, 0) == (2399, 0)


def test_probe_parsers():
    assert ts.parse_getevent_p(GETEVENT_P) == {"/dev/input/event1": (32767, 32767)}
    assert ts.parse_wm_size("Physical size: 1080x2400\nOverride size: 720x1600") == (
        720,
        1600,
    )
    assert ts.parse_wm_size("Physical size: 1080x2400") == (1080, 2400)


# --------------------------------------------------------------------------
# gestures and the input line
# --------------------------------------------------------------------------


def test_gestures_from_the_fixture_without_helper(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="off")
        ge.feed(*(FIX / "ge_gestures.txt").read_text().splitlines())
        assert wait_for(lambda: len(of(lines, "input")) >= 27)
        svc.stop()
    inputs = of(lines, "input")
    kinds = {x["kind"] for x in inputs}
    assert {"tap", "long_press", "swipe"} <= kinds
    assert not of(lines, "input", "key")  # KEY_A/B/1: never written
    stop = of(lines, "tracking", "stop")[0]
    assert stop["data"]["keys_unnamed"] == 3
    swipe = of(lines, "input", "swipe")[0]
    assert 2 <= len(swipe["data"]["path"]) <= ts.PATH_MAX
    assert {"x1", "y1"} <= set(swipe["data"])
    assert all(x["data"]["helper"] == "off" for x in inputs)
    assert not of(lines, "shot")  # no helper: never a before-tap shot


def test_key_and_multitouch_gesture(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    two = [
        "[ 5.000000] /dev/input/event1: 0003 002f 00000000",
        "[ 5.000000] /dev/input/event1: 0003 0039 00000010",
        "[ 5.000000] /dev/input/event1: 0003 0035 00001000",
        "[ 5.000000] /dev/input/event1: 0003 0036 00001000",
        "[ 5.000000] /dev/input/event1: 0003 002f 00000001",
        "[ 5.000000] /dev/input/event1: 0003 0039 00000011",
        "[ 5.000000] /dev/input/event1: 0003 0035 00006000",
        "[ 5.000000] /dev/input/event1: 0003 0036 00006000",
        "[ 5.000000] /dev/input/event1: 0000 0000 00000000",
        "[ 5.200000] /dev/input/event1: 0003 002f 00000000",
        "[ 5.200000] /dev/input/event1: 0003 0039 ffffffff",
        "[ 5.200000] /dev/input/event1: 0003 002f 00000001",
        "[ 5.200000] /dev/input/event1: 0003 0039 ffffffff",
        "[ 5.200000] /dev/input/event1: 0000 0000 00000000",
    ]
    back = [
        "[ 7.000000] /dev/input/event0: 0001 009e 00000001",
        "[ 7.000000] /dev/input/event0: 0000 0000 00000000",
        "[ 7.090000] /dev/input/event0: 0001 009e 00000000",
        "[ 7.090000] /dev/input/event0: 0000 0000 00000000",
    ]
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="off")
        ge.feed(*two, *back)
        assert wait_for(lambda: len(of(lines, "input")) == 2)
    gesture, key = of(lines, "input")
    assert gesture["kind"] == "gesture"
    assert gesture["data"]["pointers"] == 2
    assert key["kind"] == "key"
    assert key["data"]["name"] == "BACK"
    assert key["data"]["dur_ms"] == 90.0
    assert key["dev_mono"] == 7.0
    assert key["ref"]["raw"].startswith("tracking/raw/getevent.txt#L")


def test_input_line_at_up_with_target_raw_ref_and_dev_mono(env, cfg):
    svc, popen, _run, helpers, tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        n0 = svc._stream.line_no()
        ge.feed(*tap_lines(81234.567891))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))
    tap = of(lines, "input", "tap")[0]
    assert tap["dev_mono"] == 81234.567891
    assert tap["clk"] in ("dev_mono", "none")
    assert tap["actor"] == "user"
    assert tap["pkg"] == "com.x"
    assert tap["summary"] == "tap 'Accept all' (Button)"
    target = tap["data"]["target"]
    assert target == {
        "rid": "com.x:id/accept",
        "text": "Accept all",
        "desc": None,
        "cls": "android.widget.Button",
        "path": "0/1/3",
        "bounds": [60, 1600, 1020, 1700],
        "source": "cached",
    }
    assert tap["data"]["helper"] == "full"
    assert "node_ms" in tap["data"]
    assert tap["ref"]["raw"] == f"tracking/raw/getevent.txt#L{n0 + 1}-L{n0 + 6}"
    raw = (tmp / "tracking/raw/getevent.txt").read_text().splitlines()
    assert raw[n0:] == tap_lines(81234.567891)
    assert (tmp / "tracking/raw/getevent.txt").stat().st_mode & 0o777 == 0o600
    x, y, t_ms = helpers[0].node_calls[0]
    assert (x, y) == (tap["data"]["x"], tap["data"]["y"])
    assert t_ms == 81234567.9
    shot = of(lines, "shot", "before_tap")[0]
    assert shot["ref"]["of"] == tap["seq"]
    assert shot["seq"] > tap["seq"]


def test_input_line_is_written_when_node_at_times_out(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        gate = helpers[0].node_gate = threading.Event()
        try:
            ge.feed(*tap_lines(10.0))
            assert wait_for(lambda: of(lines, "input"))
            # never waits for the slow node_at: it has not returned yet
            assert helpers[0].node_calls
            assert helpers[0].node_returned == 0
        finally:
            gate.set()
    tap = of(lines, "input", "tap")[0]
    # the late live hit test costs nothing the snapshot saw at finger-down
    assert tap["data"]["node_timeout"] is True
    assert tap["data"]["target"]["source"] == "cached"
    assert tap["summary"] == "tap 'Accept all' (Button)"
    assert helpers[0].cached_calls[0][2] == 10000.0  # at the finger-down


def test_confirm_line_refers_to_the_input(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        ge.feed(*tap_lines(10.0))
        assert wait_for(lambda: of(lines, "input"))
        helpers[0].on_event(
            {
                "type": "ev",
                "ev": "CLICKED",
                "t_mono_ms": 10_090.0,
                "src": {"rid": "com.x:id/accept", "text": "Accept all"},
            },
            time.time(),
        )
        # a click on another element, or too late, confirms nothing more
        helpers[0].on_event(
            {"type": "ev", "ev": "CLICKED", "t_mono_ms": 13_000.0, "src": {}},
            time.time(),
        )
    tap = of(lines, "input", "tap")[0]
    confirms = of(lines, "input", "confirm")
    assert len(confirms) == 1
    assert confirms[0]["ref"] == {"of": tap["seq"]}
    assert confirms[0]["actor"] == "app"
    assert confirms[0]["dev_mono"] == 10.09


def test_click_before_the_input_line_still_confirms(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].on_event(
            {
                "type": "ev",
                "ev": "CLICKED",
                "t_mono_ms": 20_050.0,
                "src": {"bounds": [60, 1600, 1020, 1700]},
            },
            time.time(),
        )
        svc._stream and popen.of("getevent -t")[0].feed(*tap_lines(20.0))
        assert wait_for(lambda: of(lines, "input", "confirm"))
    assert (
        of(lines, "input", "confirm")[0]["ref"]["of"]
        == of(lines, "input", "tap")[0]["seq"]
    )


def test_replay_phase_makes_the_actor_replay(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="off")
        timeline.get_timeline().set_phase("replay", "r1", kind="play-start")
        ge.feed(*tap_lines(3.0))
        assert wait_for(lambda: of(lines, "input"))
    assert of(lines, "input")[0]["actor"] == "replay"


# --------------------------------------------------------------------------
# text and screen
# --------------------------------------------------------------------------


def _text_ev(t, text, *, rid="com.x:id/pw", password=False, sensitive=False, win=31):
    d = {
        "type": "ev",
        "ev": "TEXT_CHANGED",
        "t_mono_ms": t,
        "pkg": "com.x",
        "cls": "android.widget.EditText",
        "text": text,
        "window_id": win,
        "src": {
            "rid": rid,
            "cls": "android.widget.EditText",
            "hint": "Password",
            "editable": True,
        },
    }
    if password:
        d["password"] = True
    if sensitive:
        d["data_sensitive"] = True
    return d


def test_text_is_coalesced_per_field_and_flushed_on_field_change(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        for i, text in enumerate(["a", "al", "ali", "alic", "alice"]):
            h.on_event(_text_ev(1000 + i, text, rid="com.x:id/user"), time.time())
        h.on_event(_text_ev(2000, "x", rid="com.x:id/other"), time.time())
        h.on_event({"type": "ev", "ev": "FOCUSED"}, time.time())
    texts = of(lines, "input", "text")
    assert [x["data"]["edits"] for x in texts] == [5, 1]
    assert texts[0]["data"]["text"] == "alice"
    assert texts[0]["dev_mono"] == 1.0
    assert "sensitive" not in texts[0]
    assert texts[0]["summary"] == "typed \"alice\" into 'Password'"
    assert texts[0]["data"]["via"] == "a11y"


@pytest.mark.parametrize(
    "shape",
    [
        {"password": True},
        {"sensitive": True},
        {"password": True, "sensitive": True},
    ],
)
def test_sensitive_text_is_in_the_summary_and_masked_by_readers(env, cfg, shape):
    """The user's decision: typed text, passwords included, is in the
    summary; a reader that masks sensitive lines shows only the count.
    """
    svc, popen, _run, helpers, _tmp = env
    secret = "hunter22-Secret"  # noqa: S105 - a typed test value
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].on_event(_text_ev(5000, secret, **shape), time.time())
        svc.tick(time.time() + 10)  # idle flush
    line = of(lines, "input", "text")[0]
    assert line["sensitive"] is True
    field = "password field 'Password'" if shape.get("password") else "'Password'"
    assert line["summary"] == f'typed "{secret}" into {field}'
    assert line["data"]["text"] == secret
    masked = timeline.mask(line)
    assert secret not in json.dumps(masked)
    assert masked["summary"] == f"typed 15 chars into {field}"


def test_text_capture_off_keeps_the_line_without_content(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.capture_text = False
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].on_event(_text_ev(1, "secret"), time.time())
        svc.stop()
    line = of(lines, "input", "text")[0]
    assert "text" not in line["data"]
    assert line["data"]["captured"] is False
    assert line["summary"] == "typed 6 chars into 'Password' (EditText)"
    assert "masked_summary" not in line["data"]


def test_screen_window_dedupe_and_screen_change_shot(env, cfg):
    svc, popen, _run, helpers, tmp = env
    cfg.shot_screen_change = True
    cfg.settle_interval_ms = 100
    win = {
        "type": "ev",
        "ev": "WINDOW_STATE_CHANGED",
        "t_mono_ms": 3000.0,
        "pkg": "com.x",
        "cls": "com.x.LoginActivity",
        "text": "Sign in",
        "window_id": 31,
    }
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].hashes = ["s1", "s1"]
        helpers[0].on_event(win, time.time())
        helpers[0].on_event(dict(win, t_mono_ms=3100.0), time.time())
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    windows = of(lines, "screen", "window")
    assert len(windows) == 1
    assert windows[0]["summary"] == "screen com.x/.LoginActivity · Sign in"
    assert windows[0]["data"]["via"] == "a11y"
    assert windows[0]["actor"] == "app"
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["of"] == windows[0]["seq"]


def test_no_screen_change_shot_once_tracking_stops(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_screen_change = True
    cfg.settle_interval_ms = 100
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")
        svc.stop()
        # a logcat line that was already on its way when stop() began
        svc._emit_screen(
            "activity", pkg="a", cls="a.B", title=None, window_id=None,
            via="logcat", dev_mono=1.0,
        )  # fmt: skip
        time.sleep(0.4)
    assert of(lines, "screen", "activity")
    assert not of(lines, "shot")


ACTIVITY = (
    "  4553.443  1543  1580 I wm_set_resumed_activity: "
    "[0,com.android.settings/.Settings,resumeTopActivity]"
)


def test_logcat_activity_when_the_helper_is_not_full(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.logcat_screen_backup = True
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")
        logcat = popen.of("wm_set_resumed_activity")
        assert logcat
        assert "-s" in logcat[0].argv
        logcat[0].feed(ACTIVITY)
        assert wait_for(lambda: of(lines, "screen", "activity"))
    act = of(lines, "screen", "activity")[0]
    assert act["dev_mono"] == 4553.443
    assert act["data"]["pkg"] == "com.android.settings"
    assert act["data"]["cls"] == "com.android.settings.Settings"
    assert act["data"]["via"] == "logcat"


def test_logcat_activity_is_a_backup_for_a_full_helper(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        now = time.time()
        svc.on_logcat_line(ACTIVITY, now)  # an a11y window line follows
        helpers[0].on_event(
            {"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": "a", "cls": "a.B"},
            now + 0.1,
        )
        svc.tick(now + 1.0)
        assert not of(lines, "screen", "activity")
        svc.on_logcat_line(ACTIVITY.replace("4553", "4999"), now + 5)  # none follows
        svc.tick(now + 5.2)
        assert not of(lines, "screen", "activity")
        svc.tick(now + 5.6)
    assert len(of(lines, "screen", "activity")) == 1


# --------------------------------------------------------------------------
# shots
# --------------------------------------------------------------------------


def test_before_tap_trigger_follows_the_live_config(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        cfg.shot_before_tap = False  # no restart needed
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input"))
        time.sleep(0.2)
        assert not of(lines, "shot")
        cfg.shot_before_tap = True
        ge.feed(*tap_lines(2.0))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))


def test_sha256_dedupe_one_file_two_lines_and_seq_file_name(env, cfg):
    svc, popen, _run, helpers, tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        ge.feed(*tap_lines(1.0), *tap_lines(2.0))
        assert wait_for(lambda: len(of(lines, "shot", "before_tap")) == 2)
    first, second = of(lines, "shot", "before_tap")
    assert first["ref"]["path"] == f"tracking/shots/{first['seq']}_before_tap.png"
    assert second["ref"]["path"] == first["ref"]["path"]
    assert second["data"]["dup_of"] == first["seq"]
    assert first["data"]["dup_of"] is None
    assert first["ref"]["sha256"] == second["ref"]["sha256"]
    files = sorted(p.name for p in (tmp / "tracking/shots").glob("*.png"))
    assert files == [f"{first['seq']}_before_tap.png"]
    assert (tmp / "tracking/shots" / files[0]).read_bytes() == PNG_A
    assert not list((tmp / "tracking/shots/.incoming").iterdir())
    assert first["dev_mono"] == 0.5
    assert first["data"]["via"] == "helper"


@pytest.mark.parametrize(
    ("hashes", "expect"),
    [
        (["x1", "x2", "x2"], "stable"),  # settles on a new frame
        (["h-before", "h-before"], "unchanged"),  # the tap changed nothing
        (["a", "b", "c", "d", "e", "f", "g", "h"], "cutoff"),  # keeps moving
    ],
)
def test_after_tap_settle_rules(env, cfg, hashes, expect):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_after_tap = True
    cfg.settle_interval_ms = 100
    cfg.settle_max_ms = 500
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        helpers[0].hashes = list(hashes)
        helpers[0].shots = [
            ShotResult(1000.0, 1080, 2424, "h-before", 14.0, PNG_A, "/a"),
            ShotResult(2000.0, 1080, 2424, "x2", 14.0, PNG_B, "/b"),
        ]
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))
        time.sleep(0.9)
    after = of(lines, "shot", "after_tap")
    tap = of(lines, "input", "tap")[0]
    if expect == "unchanged":
        assert after == []
        return
    assert len(after) == 1
    assert after[0]["ref"]["of"] == tap["seq"]
    assert after[0]["data"]["stable"] is (expect == "stable")
    assert after[0]["summary"] == f"screenshot after tap #{tap['seq']}"


def test_label_trigger_shoots_once_per_label_line(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_label = True
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        timeline.get_timeline().labels.point("tap login")
        svc.on_timeline_event({"srcs": ["label"]})
        assert wait_for(lambda: of(lines, "shot", "label"))
        svc.on_timeline_event({"srcs": ["label"]})  # no new label line
        time.sleep(0.2)
    label = of(lines, "label")[0]
    shots = of(lines, "shot", "label")
    assert len(shots) == 1
    assert shots[0]["ref"]["of"] == label["seq"]


def test_no_helper_fallback_and_manual_shot(env, cfg):
    svc, popen, run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="off")
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input"))
        pressed = time.time() - 5
        assert svc.manual_shot(t=pressed) is True
        assert wait_for(lambda: of(lines, "shot", "manual"))
    assert not of(lines, "shot", "before_tap")
    manual = of(lines, "shot", "manual")[0]
    assert manual["data"]["via"] == "screencap"
    assert manual["actor"] == "user"
    assert abs(timeline._instant(manual["t"]) - pressed) < 0.01
    assert manual["clk"] == "host"
    cap = [c for c in run.calls if "screencap" in c]
    assert cap
    assert cap[0][:3] == [cap[0][0], "-s", SERIAL]


def _fallback_lines(lines):
    return [x for x in of(lines, "tracking", "helper") if x["data"].get("fallback")]


def test_screencap_fallback_is_said_once_per_run_with_why(env, cfg, caplog):
    import logging

    svc, popen, _run, helpers, _tmp = env
    caplog.set_level(logging.INFO, logger=ts.__name__)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="off")
        for _ in range(2):
            svc.manual_shot()
        assert wait_for(lambda: len(of(lines, "shot", "manual")) == 2)
        svc.stop()
        start(svc, popen, helpers, cfg, mode="off")  # a new run says it again
        svc.manual_shot()
        assert wait_for(lambda: len(of(lines, "shot", "manual")) == 3)
    notes = _fallback_lines(lines)
    assert len(notes) == 2
    assert notes[0]["data"] == {
        "helper": "off",
        "mode": "off",
        "fallback": "screencap",
        "reason": "the UI helper is off (tracking helper_mode = off)",
    }
    assert notes[0]["level"] == "info"
    assert "adb screencap" in notes[0]["summary"]
    logged = [
        r for r in caplog.records if "screenshots with adb screencap" in r.message
    ]
    assert len(logged) == 2
    assert all(r.levelno == logging.INFO for r in logged)
    assert "helper is off" in logged[0].message


def test_screencap_fallback_names_a_failed_helper_capture(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")

        def broken(*, hash_only=False, timeout=5.0):
            raise OSError("helper socket closed")

        helpers[0].shot = broken
        svc.manual_shot()
        assert wait_for(lambda: of(lines, "shot", "manual"))
    assert of(lines, "shot", "manual")[0]["data"]["via"] == "screencap"
    (note,) = _fallback_lines(lines)
    assert note["data"]["reason"] == (
        "the UI helper's capture failed (helper socket closed)"
    )


def test_screencap_fallback_names_a_helper_that_failed_to_start(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")
        helpers[0].alive = False
        with svc._lock:
            svc._helper_state = "failed"
        svc.manual_shot()
        assert wait_for(lambda: of(lines, "shot", "manual"))
    (note,) = _fallback_lines(lines)
    assert note["data"]["reason"] == "the UI helper failed to start (invisible mode)"


def test_report_says_when_screenshots_fell_back_to_screencap():
    from sandroid.core import report_engine

    lines = [
        {"src": "tracking", "kind": "helper", "t": "2026-11-20T10:00:00Z",
         "data": {"helper": "failed", "mode": "invisible",
                  "fallback": "screencap",
                  "reason": "the UI helper failed to start (invisible mode)"}},
        {"src": "tracking", "kind": "helper", "t": "2026-11-20T10:00:05Z",
         "data": {"helper": "connected", "mode": "invisible"}},
    ]  # fmt: skip
    ctx = report_engine.ReportContext(
        scope=report_engine.ReportScope(),
        options=report_engine.ReportOptions(),
        masked=False,
        generated_at="2026-11-20T10:01:00+00:00",
        lines=lines,
    )
    items = report_engine._cov_tracking(ctx)
    fallback = [x for x in items if "adb screencap" in x]
    assert len(fallback) == 1
    assert fallback[0].endswith(": the UI helper failed to start (invisible mode).")
    assert not any("was failed" in x for x in items)
    assert any("was connected" in x for x in items)


def test_failed_capture_is_a_warn_line_without_path(env, cfg):
    svc, popen, run, helpers, _tmp = env
    run.screencap = None
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="off")
        svc.manual_shot()
        assert wait_for(lambda: of(lines, "shot", "manual"))
    line = of(lines, "shot", "manual")[0]
    assert line["level"] == "warn"
    assert "error" in line["data"]
    assert "path" not in (line.get("ref") or {})


def test_s_key_records_a_manual_shot_while_tracking(env, cfg, monkeypatch):
    from sandroid.tui.controllers.screenshot_controller import ScreenshotController

    svc, popen, _run, helpers, _tmp = env
    calls, pushed = [], []
    monkeypatch.setattr(svc, "manual_shot", lambda **kw: calls.append(kw) or True)
    logs: list[str] = []
    ctrl = ScreenshotController(
        log_success=logs.append, push_modal=lambda m, cb: pushed.append(m)
    )
    ctrl.show_screenshot_modal()
    assert pushed
    assert not calls
    with timeline.capture():
        start(svc, popen, helpers, cfg, mode="off")
        ctrl.show_screenshot_modal()
    assert len(pushed) == 1
    assert len(calls) == 1
    assert "t" in calls[0]
    assert logs == ["Screenshot recorded (Tracking)"]


# --------------------------------------------------------------------------
# helper status / intervention / start-stop
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("mode", "what", "detectable"), [
    ("full", "a11y_helper", True),
    ("invisible", "ui_helper_invisible", False),
])  # fmt: skip
def test_helper_status_and_intervention_lines(env, cfg, mode, what, detectable):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode=mode)
        helpers[0].on_status("lost", {"mode": mode, "rc": 1})
        helpers[0].on_status("restarted", {"mode": mode, "attempt": 1})
        svc.stop()
        assert wait_for(lambda: helpers[0].stopped)
        assert wait_for(lambda: len(of(lines, "sandroid", "intervention")) == 2)
    states = [x["data"]["helper"] for x in of(lines, "tracking", "helper")]
    assert states == ["connected", "lost", "restarted", "stopped"]
    on, off = of(lines, "sandroid", "intervention")
    assert on["data"]["what"] == what
    assert on["data"]["detectable"] is detectable
    assert (on["data"]["state"], off["data"]["state"]) == ("on", "off")
    if detectable:
        assert on["data"]["detail"] == {"flags": 1, "accessibility_enabled_before": "0"}
    order = [(x["src"], x["kind"]) for x in lines if x["src"] != "label"]
    assert order[0] == ("tracking", "start")
    assert order.index(("tracking", "start")) < order.index(
        ("sandroid", "intervention")
    )
    assert of(lines, "tracking", "stop")[0]["data"]["reason"] == "user"


def test_busy_helper_is_a_status_and_tracking_keeps_running(env, cfg, monkeypatch):
    svc, popen, _run, helpers, _tmp = env
    cfg.helper_mode = "full"
    orig = FakeHelper.start

    def busy(self):
        self.start_ok = False
        return orig(self)

    monkeypatch.setattr(FakeHelper, "start", busy)
    with timeline.capture() as lines:
        assert svc.start(SERIAL)
        assert wait_for(lambda: of(lines, "tracking", "helper"))
        assert wait_for(lambda: svc.state().helper == "busy")
    line = of(lines, "tracking", "helper")[0]
    assert line["data"]["helper"] == "busy"
    assert "waiting" in line["summary"]
    assert svc.is_active()
    assert not of(lines, "sandroid", "intervention")


def test_toggle_state_and_module_is_active(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.helper_mode = "off"
    with timeline.capture() as lines:
        assert ts.is_active() is False
        assert svc.toggle(SERIAL) is True
        assert ts.is_active()
        assert ts.is_active(SERIAL)
        assert not ts.is_active("x")
        st = svc.state()
        assert st.active
        assert st.serial == SERIAL
        assert st.mode == "off"
        assert svc.toggle() is False
    assert [x["kind"] for x in of(lines, "tracking")] == ["start", "stop"]
    start_line = of(lines, "tracking", "start")[0]
    assert start_line["data"] == {"mode": "off", "helper": "off", "reason": "user"}


# --------------------------------------------------------------------------
# the shared getevent stream and Record
# --------------------------------------------------------------------------


def test_one_getevent_shared_and_killed_by_pid(env, cfg):
    svc, popen, run, helpers, _tmp = env
    cfg.helper_mode = "off"
    a = svc.getevent(SERIAL)
    a.subscribe(lambda *x: None)
    popen.of("getevent -t")[0].feed("add device 1: /dev/input/event0")
    assert wait_for(lambda: a._pid == 4242)
    b = svc.getevent(SERIAL)
    assert a is b
    assert len(popen.of("getevent -t")) == 1
    argv = popen.of("getevent -t")[0].argv
    assert argv[1:3] == ["-s", SERIAL]
    assert argv[-1] == f"echo $$ > {ts.PIDFILE}; exec getevent -t"
    a.release()
    assert not any("kill" in " ".join(c) for c in run.calls)
    b.release()
    b.wait_closed()
    kills = [c for c in run.calls if "kill" in " ".join(c)]
    assert len(kills) == 1
    assert "kill 4242" in kills[0][-1]
    assert "-s" in kills[0]
    assert not any(
        "pkill" in " ".join(c) or "killall" in " ".join(c) for c in run.calls
    )


def test_line_numbers_continue_an_existing_raw_file(env, cfg):
    svc, popen, _run, _helpers, tmp = env
    raw = tmp / "tracking/raw/getevent.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("a\nb\nc\n")
    s = svc.getevent(SERIAL)
    seen = []
    s.subscribe(lambda line, n, host: seen.append(n))
    popen.of("getevent -t")[0].feed("x")
    assert wait_for(lambda: seen == [4])
    s.release()


def _record(monkeypatch, svc, tmp, out_name="recording.getevent.txt"):
    from sandroid.tui.utils.recording_wrapper import RecordingWrapper

    return RecordingWrapper(output_file=str(tmp / "raw" / out_name), serial=SERIAL)


def test_record_starts_and_stops_only_its_own_tracking(env, cfg, monkeypatch):
    svc, popen, _run, _helpers, tmp = env
    cfg.helper_mode = "off"
    monkeypatch.setattr(
        "sandroid.config.get_config",
        type("C", (), {"tracking": cfg}),
    )
    with timeline.capture() as lines:
        rec = _record(monkeypatch, svc, tmp)
        assert rec.start()
        assert svc.is_active()
        assert len(popen.of("getevent -t")) == 1  # Tracking + Record share it
        rec.stop()
        assert not svc.is_active()
        # Tracking the user started survives a Record
        assert svc.start(SERIAL)
        rec2 = _record(monkeypatch, svc, tmp)
        assert rec2.start()
        assert len([p for p in popen.of("getevent -t") if not p.terminated]) == 1
        rec2.stop()
        assert svc.is_active()
    reasons = [x["data"]["reason"] for x in of(lines, "tracking")]
    assert reasons == ["record", "record", "user"]


def test_recording_is_the_exact_raw_slice(env, cfg, monkeypatch):
    svc, popen, _run, _helpers, tmp = env
    cfg.auto_on_record = False
    monkeypatch.setattr(
        "sandroid.config.get_config",
        type("C", (), {"tracking": cfg}),
    )
    live: list[str] = []
    counts: list[int] = []
    from sandroid.tui.utils.recording_wrapper import RecordingWrapper

    before = svc.getevent(SERIAL)  # someone already reads (e.g. Tracking)
    ge = popen.of("getevent -t")[0]
    ge.feed("add device 1: /dev/input/event1", *tap_lines(1.0))
    assert wait_for(lambda: before.line_no() == 7)
    rec = RecordingWrapper(
        output_file=str(tmp / "raw/recording.getevent.txt"),
        on_event=live.append,
        on_count_update=counts.append,
        serial=SERIAL,
    )
    assert rec.start()
    assert not svc.is_active()
    body = tap_lines(2.0) + ['  name:     "virtio"', "add device 2: x"] + tap_lines(3.0)
    ge.feed(*body)
    assert wait_for(lambda: before.line_no() == 7 + len(body))
    assert wait_for(lambda: counts and counts[-1] == 12)
    rec.stop()
    ge.feed(*tap_lines(4.0))  # after the stop: not in the recording
    out = (tmp / "raw/recording.getevent.txt").read_text().splitlines()
    # the events verbatim, between the start/stop markers (clamped here: the
    # fake kernel times are far from the host clock)
    assert out[1:-1] == tap_lines(2.0) + tap_lines(3.0)
    first, last = ts.parse_getevent(out[0]), ts.parse_getevent(out[-1])
    assert first == (2.0, "/dev/input/event1", 0, 0, 0)
    assert last[1:] == ("/dev/input/event1", 0, 0, 0)
    assert last[0] >= 3.08
    assert rec.event_count == 12
    assert live[0] == "/dev/input/event1: 0003 0039 00000001"
    assert not (tmp / "raw/recording.txt").exists()
    before.release()


def test_cli_resolve_recording_accepts_both(tmp_path):
    from sandroid.cli import resolve_recording

    new = tmp_path / "recording.getevent.txt"
    new.write_text("\n".join(tap_lines(1.0)) + "\n")
    legacy = tmp_path / "recording.txt"
    legacy.write_text("1700000000000 /dev/input/event1 3 57 0\n")
    assert resolve_recording(str(new)) == (str(new.resolve()), None)
    assert resolve_recording(str(legacy)) == (str(legacy.resolve()), None)
    bad = tmp_path / "bad.txt"
    bad.write_text("add device 1: /dev/input/event0\n")
    assert resolve_recording(str(bad))[0] is None


def test_recording_seconds_reads_both_formats(tmp_path):
    from sandroid.tui.controllers.recording_controller import RecordingController

    new = tmp_path / "recording.getevent.txt"
    new.write_text("\n".join(tap_lines(100.0) + tap_lines(112.5)) + "\n")
    assert RecordingController.recording_seconds(str(new)) == pytest.approx(12.58)


# --------------------------------------------------------------------------
# net flows
# --------------------------------------------------------------------------


def _flow_dir(tmp: Path, records: list[dict], earliest: int | None = None) -> Path:
    d = tmp / "raw/mitm_flows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "flows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    seqs = [r["seq"] for r in records]
    meta = {
        "earliest_seq": earliest
        if earliest is not None
        else (seqs[0] if seqs else None),
        "latest_seq": seqs[-1] if seqs else 0,
        "generation": 0,
    }
    (d / "meta.json").write_text(json.dumps(meta))
    return d


def _rec(seq: int, **kw) -> dict:
    rec = {
        "seq": seq,
        "id": f"f{seq}",
        "ts_start": 1_700_000_000.0 + seq,
        "ts_end": 1_700_000_000.312 + seq,
        "protocol": "HTTPS",
        "method": "POST",
        "host": "api.x.com",
        "path": "/v1/collect",
        "status_code": 200,
        "error": None,
        "request_bytes": 1240,
        "response_bytes": 88,
        "app": "com.x",
    }
    rec.update(kw)
    return rec


def test_net_flow_lines_tls_fail_and_cursor(tmp_path):
    flow_dir = _flow_dir(tmp_path, [_rec(1)])
    src = ts.NetFlowSource(flow_dir_fn=lambda: flow_dir, folder_fn=lambda: tmp_path)
    src.start()
    try:
        assert src.cursor == 1  # flows from before the start are not repeated
        _flow_dir(
            tmp_path,
            [
                _rec(1),
                _rec(2),
                _rec(3, kind="tls", id="tls-3", host="tracker.x", tls_reason="cert"),
            ],
        )
        with timeline.capture() as lines:
            assert src.poll() == 2
            assert src.poll() == 0
    finally:
        src.stop()
    flow, tls = lines
    assert src.cursor == 3
    assert (flow["src"], flow["kind"], tls["kind"]) == ("net", "flow", "tls-fail")
    assert timeline._instant(flow["t"]) == pytest.approx(1_700_000_002.0, abs=1e-3)
    assert flow["clk"] == "host"
    assert flow["pkg"] == "com.x"
    assert flow["actor"] == "app"
    assert flow["summary"] == "POST 200 api.x.com/v1/collect · 1.3 KB"
    assert flow["data"]["dur_ms"] == 312.0
    assert flow["data"]["flow_seq"] == 2
    assert flow["ref"] == {
        "id": "f2",
        "path": "raw/mitm_flows/details/f2.json",
        "lens": "network",
    }
    assert tls["data"]["host"] == "tracker.x"
    assert tls["data"]["reason"] == "cert"


def test_net_gap_warns(tmp_path, caplog):
    flow_dir = _flow_dir(tmp_path, [_rec(9), _rec(10)], earliest=9)
    src = ts.NetFlowSource(flow_dir_fn=lambda: flow_dir, folder_fn=lambda: tmp_path)
    src.cursor = 3
    with timeline.capture() as lines:
        src.poll()
    assert lines[0]["level"] == "warn"
    assert lines[0]["data"]["gap"]["after"] == 3
    assert "gap" not in lines[1]["data"]
    assert "trimmed" in caplog.text


def test_net_doorbell_never_works_on_the_listener_thread(tmp_path, monkeypatch):
    flow_dir = _flow_dir(tmp_path, [])
    src = ts.NetFlowSource(
        flow_dir_fn=lambda: flow_dir, folder_fn=lambda: tmp_path, debounce_s=0.05
    )
    polled: list[str] = []
    gate = threading.Event()  # every poll blocks until the burst is over
    real = src.poll

    def poll():
        polled.append(threading.current_thread().name)
        gate.wait(10.0)
        return real()

    monkeypatch.setattr(src, "poll", poll)
    src.start()
    try:
        for _ in range(20):  # a burst of doorbells is debounced
            src.on_line("[FLOW]|12:00:00|HTTPS|200|GET|x/|1 KB|app")
        src.on_line("[INFO] not a flow")
        # on_line returned with every poll blocked: none ran on this thread
        assert threading.current_thread().name not in polled
        gate.set()
        assert wait_for(lambda: polled)
    finally:
        gate.set()
        src.stop()  # joins the worker (its last poll included)
    assert threading.current_thread().name not in polled
    assert set(polled) == {"net-flows"}
    assert len(polled) <= 3


def test_mitmproxy_service_starts_and_stops_the_net_source(monkeypatch):
    from sandroid.services import mitmproxy_service as ms

    started, stopped = [], []

    class Fake:
        def start(self):
            started.append(self)

        def stop(self):
            stopped.append(self)

        def on_line(self, line):
            pass

    monkeypatch.setattr(ts, "NetFlowSource", Fake)
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._listeners = []
    svc._net_source = None
    svc._start_net_source()
    assert started
    assert svc._listeners == [started[0].on_line]
    svc._stop_net_source()
    assert stopped == started
    assert svc._listeners == []


def test_mitmproxy_stops_the_net_source_after_mitmweb_is_gone(monkeypatch):
    """Flows that finish while mitmweb shuts down must still become lines:
    the source's final drain runs after the process is gone.
    """
    from sandroid.services import mitmproxy_service as ms

    order: list[str] = []

    class Source:
        def on_line(self, line):
            pass

        def stop(self):
            order.append("net-source-stop")

    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._lock = threading.RLock()
    svc._listeners = []
    svc._net_source = Source()
    svc._listeners.append(svc._net_source.on_line)
    svc._proc = object()
    svc._ssl_via_mitm = False
    svc._state = type("S", (), {"running": True, "pid": 1})()
    svc._addon_path = None
    svc._web_token = None
    svc._emit = lambda msg: None
    monkeypatch.setattr(
        svc, "_terminate", lambda proc, timeout: order.append("mitmweb-terminated")
    )
    monkeypatch.setattr(
        "sandroid.core.proxy_manager.get_focus_manager",
        lambda: SimpleNamespace(disable_focus=lambda: None),
    )
    svc.stop(release_device_proxy=False)
    assert order == ["mitmweb-terminated", "net-source-stop"]
    assert svc._net_source is None


# --------------------------------------------------------------------------
# the interval screenshot is gone
# --------------------------------------------------------------------------


def test_interval_screenshot_feature_is_gone():
    # The package only: an editable install's stale ``*.egg-info`` under src/
    # still lists the deleted file.
    src = Path(__file__).resolve().parents[2] / "src" / "sandroid"
    out = subprocess.run(
        [
            "grep",
            "-rnI",  # text files only: a stale .pyc is no source
            "--exclude-dir=__pycache__",
            r"screenshot_interval\|features.screenshot\|StartScreenshotStep",
            str(src),
        ],
        capture_output=True,
        text=True,
    )
    assert out.stdout == ""


# --------------------------------------------------------------------------
# review 3/4 fixes (repros from scratchpad/review3, review4)
# --------------------------------------------------------------------------

E1 = "/dev/input/event1"


def ge(t: float, typ: int, code: int, val: int, dev: str = E1) -> str:
    return f"[{t:15.6f}] {dev}: {typ:04x} {code:04x} {val & 0xFFFFFFFF:08x}"


def decode_all(lines: list[str], d: ts.TouchDecoder | None = None):
    d = d or ts.TouchDecoder()
    out = []
    for i, line in enumerate(lines, 1):
        out += d.feed(line, i)
    return out


def taps_on_slot0(t0: float, n: int, *, x: int = 0x3000, y: int = 0x3000):
    lines = []
    for i in range(n):
        t = t0 + i
        lines += [ge(t, 3, 0x39, 10 + i), ge(t, 3, 0x35, x), ge(t, 3, 0x36, y),
                  ge(t, 0, 0, 0), ge(t + 0.05, 3, 0x39, -1), ge(t + 0.05, 0, 0, 0)]  # fmt: skip
    return lines


def test_syn_dropped_closes_the_gesture_and_skips_to_the_next_report():
    """r_decoder #2 / r1_decoder #3: a SYN_DROPPED that lost the finger-up
    must not merge the next tap into the stuck gesture.
    """
    lines = [
        ge(1.0, 3, 0x39, 1), ge(1.0, 3, 0x35, 0x1000), ge(1.0, 3, 0x36, 0x1000),
        ge(1.0, 0, 0, 0),
        ge(1.05, 0, 3, 0),  # SYN_DROPPED: the up frame was lost
        ge(1.05, 3, 0x39, -1),  # dropped (until the SYN_REPORT)
        ge(1.05, 0, 0, 0),
        ge(9.0, 3, 0x39, 2), ge(9.0, 3, 0x35, 0x6000), ge(9.0, 3, 0x36, 0x6000),
        ge(9.0, 0, 0, 0), ge(9.05, 3, 0x39, -1), ge(9.05, 0, 0, 0),
    ]  # fmt: skip
    ends = [e.gesture for e in decode_all(lines) if e.kind == "end"]
    assert len(ends) == 2
    first, second = ends
    assert first.dropped
    assert first.uncertain
    assert (first.t_down, first.t_up) == (1.0, 1.05)
    assert (first.line_a, first.line_b) == (1, 5)
    assert not second.dropped
    assert (second.t_down, second.t_up, second.x0) == (9.0, 9.05, 0x6000)


def test_syn_dropped_without_a_report_does_not_swallow_a_later_tap():
    """r1_decoder #3 shape: no SYN_REPORT after the SYN_DROPPED."""
    lines = [
        ge(3.0, 3, 0x39, 7), ge(3.0, 3, 0x35, 100), ge(3.0, 3, 0x36, 100),
        ge(3.0, 0, 0, 0), ge(3.1, 0, 3, 0),
        ge(60.0, 3, 0x39, 8), ge(60.0, 3, 0x35, 30000), ge(60.0, 3, 0x36, 30000),
        ge(60.0, 0, 0, 0), ge(60.1, 3, 0x39, -1), ge(60.1, 0, 0, 0),
    ]  # fmt: skip
    ends = [e.gesture for e in decode_all(lines) if e.kind == "end"]
    assert [(g.t_down, g.t_up, g.dropped) for g in ends] == [
        (3.0, 3.1, True),
        (60.0, 60.1, False),
    ]
    assert (ends[1].x0, ends[1].y0) == (30000, 30000)


def test_lost_up_in_a_pinch_never_blocks_later_taps():
    """r_dropped2: before, 10 taps after a pinch with a lost up gave 0 lines."""
    pinch = [
        ge(1.0, 3, 0x2F, 0), ge(1.0, 3, 0x39, 1), ge(1.0, 3, 0x35, 0x1000),
        ge(1.0, 3, 0x36, 0x1000), ge(1.0, 3, 0x2F, 1), ge(1.0, 3, 0x39, 2),
        ge(1.0, 3, 0x35, 0x2000), ge(1.0, 3, 0x36, 0x2000), ge(1.0, 0, 0, 0),
        ge(1.5, 0, 3, 0),  # SYN_DROPPED (slot 1's up is lost)
        ge(1.6, 3, 0x2F, 0), ge(1.6, 3, 0x39, -1), ge(1.6, 0, 0, 0),
    ]  # fmt: skip
    events = decode_all(pinch + taps_on_slot0(3.0, 10))
    ends = [e.gesture for e in events if e.kind == "end"]
    assert len(ends) == 11
    assert ends[0].dropped
    assert ends[0].pointers == 2
    assert [g.t_down for g in ends[1:]] == [3.0 + i for i in range(10)]
    assert not any(g.dropped for g in ends[1:])


def test_new_tracking_id_on_a_held_slot_closes_the_gesture():
    lines = [
        ge(1.0, 3, 0x39, 7), ge(1.0, 3, 0x35, 100), ge(1.0, 3, 0x36, 100),
        ge(1.0, 0, 0, 0),
        # the up of id 7 never came; id 8 starts on the same slot
        ge(2.0, 3, 0x39, 8), ge(2.0, 3, 0x35, 30000), ge(2.0, 3, 0x36, 30000),
        ge(2.0, 0, 0, 0), ge(2.1, 3, 0x39, -1), ge(2.1, 0, 0, 0),
    ]  # fmt: skip
    ends = [e.gesture for e in decode_all(lines) if e.kind == "end"]
    assert [(g.t_down, g.dropped) for g in ends] == [(1.0, True), (2.0, False)]
    assert ends[0].line_b == 4
    assert ends[1].x0 == 30000


def test_a_slot_held_for_ever_is_closed_by_a_new_contact_after_idle():
    lines = [  # slot 1 never lifts (no SYN_DROPPED either)
        ge(1.0, 3, 0x2F, 1), ge(1.0, 3, 0x39, 5), ge(1.0, 3, 0x35, 100),
        ge(1.0, 3, 0x36, 100), ge(1.0, 0, 0, 0),
        ge(1.0, 3, 0x2F, 0),
    ]  # fmt: skip
    events = decode_all(lines + taps_on_slot0(1.0 + ts.GESTURE_IDLE_S + 1, 2))
    ends = [e.gesture for e in events if e.kind == "end"]
    assert [g.dropped for g in ends] == [True, False, False]


def test_app_switch_key_is_a_key_and_btn_codes_are_not():
    """r_decoder #1: KEY_APPSELECT (580) is above 0x100 but not a BTN_*."""
    k = "/dev/input/event12"
    events = decode_all([
        ge(1.0, 1, 580, 1, k), ge(1.0, 0, 0, 0, k),
        ge(1.1, 1, 580, 0, k), ge(1.1, 0, 0, 0, k),
        ge(2.0, 1, 0x14A, 1), ge(2.1, 1, 0x14A, 0),  # BTN_TOUCH
        ge(3.0, 1, 0x2C0, 1), ge(3.1, 1, 0x2C0, 0),  # BTN_TRIGGER_HAPPY1
    ])  # fmt: skip
    assert [(e.kind, e.gesture.key_code) for e in events] == [("key", 580)]
    assert ts.KEY_NAMES[580] == "APP_SWITCH"


def test_an_unseen_axis_is_never_zero():
    """r1_decoder #2 / r_decoder #3: Y unseen at down -> not (x, 0), and a
    still tap whose Y arrives later is not a 1465 px swipe.
    """
    d = ts.TouchDecoder()
    events = decode_all([
        ge(2.0, 3, 0x39, 5), ge(2.0, 3, 0x35, 16000), ge(2.0, 0, 0, 0),
        ge(2.02, 3, 0x36, 20000), ge(2.02, 0, 0, 0),  # first Y seen
        ge(2.05, 3, 0x39, -1), ge(2.05, 0, 0, 0),
    ], d)  # fmt: skip
    down = next(e.gesture for e in events if e.kind == "down")
    end = next(e.gesture for e in events if e.kind == "end")
    assert down is end
    assert end.uncertain
    assert (end.x0, end.y0) == (16000, 20000)  # the first Y is the origin
    assert all(None not in p[:2] for p in end.path)
    assert all(p[1] == 20000 for p in end.path)  # no point at y = 0


def _tap_y_unseen(t: float):
    return [ge(t, 3, 0x39, 9), ge(t, 3, 0x35, 16000), ge(t, 0, 0, 0),
            ge(t + 0.05, 3, 0x39, -1), ge(t + 0.05, 0, 0, 0)]  # fmt: skip


def test_uncertain_tap_skips_node_at_and_the_click_names_the_target(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        g.feed(*_tap_y_unseen(10.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        helpers[0].on_event(
            {"type": "ev", "ev": "CLICKED", "t_mono_ms": 10_080.0,
             "src": {"rid": "com.x:id/ok", "text": "OK", "bounds": [1, 2, 3, 4]}},
            time.time(),
        )  # fmt: skip
        assert wait_for(lambda: of(lines, "input", "confirm"))
    tap = of(lines, "input", "tap")[0]
    assert helpers[0].node_calls == []  # never node_at(x, 0)
    assert tap["data"]["x"] is None
    assert tap["data"]["y"] is None
    assert tap["data"]["xy_uncertain"] is True
    assert tap["data"]["target"] is None
    assert tap["summary"] == "tap · position unknown"
    confirm = of(lines, "input", "confirm")[0]
    assert confirm["ref"] == {"of": tap["seq"]}
    assert confirm["data"]["target_of_input"] is True
    assert confirm["data"]["node"]["bounds"] == [1, 2, 3, 4]


def test_axis_values_outlive_a_tracking_restart(env, cfg, monkeypatch):
    """One decoder per stream lifetime: Record keeps the stream while
    Tracking restarts, the X/Y seen before stay known.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    lease = svc.getevent(SERIAL)  # e.g. Record
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg, mode="off")
        g.feed(*tap_lines(1.0, 0x4000, 0x5000))
        assert wait_for(lambda: len(of(lines, "input")) == 1)
        svc.stop()
        start(svc, popen, helpers, cfg, mode="off")
        assert len(popen.of("getevent -t")) == 1
        g.feed(  # the same spot: the kernel repeats neither axis
            ge(2.0, 3, 0x39, 3), ge(2.0, 0, 0, 0),
            ge(2.05, 3, 0x39, -1), ge(2.05, 0, 0, 0),
        )  # fmt: skip
        assert wait_for(lambda: len(of(lines, "input")) == 2)
    first, second = of(lines, "input")
    assert second["data"]["xy_uncertain"] is False
    assert (second["data"]["x"], second["data"]["y"]) == (
        first["data"]["x"],
        first["data"]["y"],
    )
    lease.release()


def test_dropped_gesture_is_flagged_on_the_input_line(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg, mode="off")
        g.feed(ge(1.0, 3, 0x39, 1), ge(1.0, 3, 0x35, 0x1000),
               ge(1.0, 3, 0x36, 0x1000), ge(1.0, 0, 0, 0), ge(1.2, 0, 3, 0),
               ge(1.2, 0, 0, 0), *taps_on_slot0(3.0, 2))  # fmt: skip
        assert wait_for(lambda: len(of(lines, "input")) == 3)
    first, *rest = of(lines, "input")
    assert first["data"]["dropped"] is True
    assert first["data"]["xy_uncertain"] is True
    assert not any("dropped" in x["data"] for x in rest)


def test_before_tap_shots_never_pile_up_and_late_ones_are_dropped(env, cfg):
    """r_before / r2_shots B: fast taps with a slow capture used to queue a
    "before" shot per tap that landed long after its tap.
    """
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        h = helpers[0]
        t_dev0 = 100.0
        t_host0 = time.monotonic()

        def slow_shot(*, hash_only=False, timeout=5.0):
            cap = t_dev0 + (time.monotonic() - t_host0)  # capture instant
            time.sleep(0.3)
            return ShotResult(cap * 1000.0, 1080, 2424, "h", 9.0, PNG_A, "/x")

        h.shot = slow_shot
        for i in range(6):  # one tap every 125 ms, 50 ms long
            g.feed(*tap_lines(t_dev0 + i * 0.125, dur=0.05))
            time.sleep(0.125)
        assert wait_for(lambda: len(of(lines, "input")) == 6)
        time.sleep(0.8)
    taps = {x["seq"]: x for x in of(lines, "input", "tap")}
    shots = of(lines, "shot", "before_tap")
    skipped = [x for x in taps.values() if x["data"].get("before_shot") == "skipped"]
    # one capture at a time: the taps meanwhile get none (before: 6 queued
    # captures, the last one 1 s after its tap)
    assert len(shots) + len(skipped) == 6
    assert 1 <= len(shots) <= 2
    assert shots[0]["ref"]["of"] == min(taps)
    for shot in shots:  # never captured after its tap's finger-up
        assert shot["dev_mono"] <= taps[shot["ref"]["of"]]["dev_mono"] + 0.05


def test_a_before_shot_captured_after_the_finger_up_is_dropped(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        helpers[0].shot_t_ms = 1_200.0  # captured after the up at 1.08 s
        g.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input"))
        time.sleep(0.3)
    assert not of(lines, "shot", "before_tap")
    assert of(lines, "input", "tap")[0]["data"]["before_shot"] == "late"


def test_a_before_shot_queued_behind_a_settle_sample_is_late(env, cfg):
    """E2E round 6 #18 (FULL) / #80 (Record): the helper serialises its
    requests, and the before-tap capture waited behind a screen-change
    sample (#18: a 166 ms hash sample begun 3 ms after the finger-down; #80:
    a fallback PNG capture, 670 ms encode). Captured after the finger-up
    (+28 / +696 ms), it was dropped and the tap line said nothing. Now it
    says ``before_shot: "late"`` (the capture may show the screen after the
    tap, so it is still not stored).
    """
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        h = helpers[0]
        t_dev0, t_host0 = 100.0, time.monotonic()
        busy = threading.Lock()  # the helper: one request at a time

        def serial_shot(*, hash_only=False, timeout=5.0):
            with busy:
                cap = (t_dev0 + time.monotonic() - t_host0) * 1000.0
                if hash_only:  # the settle sample, slow under load
                    time.sleep(0.5)
                    return ShotResult(cap, 1080, 2424, "h-old", 3.0, None, None)
                return ShotResult(cap, 1080, 2424, "h-before", 14.0, PNG_A, "/x")

        h.shot = serial_shot
        sample = svc._shot_lane.submit(svc._shot_seen, h, hash_only=True)
        time.sleep(0.03)  # the sample is running at the finger-down
        g.feed(*tap_lines(t_dev0 + time.monotonic() - t_host0, dur=0.15))
        assert wait_for(lambda: of(lines, "input"))
        assert sample.result(timeout=2.0).hash == "h-old"
        time.sleep(0.2)
    tap = of(lines, "input", "tap")[0]
    assert tap["data"]["before_shot"] == "late"
    assert not of(lines, "shot", "before_tap")


BEFORE_SHOT_STATES = {"taken", "skipped", "late", "failed", "no_helper", "off"}


def _pointer_inputs(lines):
    return [
        x for x in of(lines, "input") if x["kind"] not in ("key", "text", "confirm")
    ]


@pytest.mark.parametrize("mode", ["full", "invisible", "off"])
def test_every_pointer_input_says_what_became_of_its_before_shot(env, cfg, mode):
    """Every tap / long_press / swipe / gesture line carries
    ``data.before_shot``; ``taken`` ones (and only they) have a before-tap
    shot line with ``ref.of`` = the input.
    """
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode=mode)
        ge.feed(*(FIX / "ge_gestures.txt").read_text().splitlines())
        assert wait_for(lambda: len(of(lines, "input")) >= 27, timeout=10.0)
        time.sleep(0.3)
        svc.stop()
    inputs = _pointer_inputs(lines)
    assert {"tap", "long_press", "swipe"} <= {x["kind"] for x in inputs}
    states = {x["seq"]: x["data"].get("before_shot") for x in inputs}
    assert set(states.values()) <= BEFORE_SHOT_STATES
    shot_of = {x["ref"]["of"] for x in of(lines, "shot", "before_tap")}
    assert shot_of == {seq for seq, st in states.items() if st == "taken"}
    if mode == "off":
        assert set(states.values()) == {"no_helper"}
    else:
        assert "taken" in states.values()


def test_before_shot_off_and_failed(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        cfg.shot_before_tap = False
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: len(of(lines, "input")) == 1)
        cfg.shot_before_tap = True

        def broken(*, hash_only=False, timeout=5.0):
            raise OSError("helper socket closed")

        h.shot = broken
        ge.feed(*tap_lines(2.0))
        assert wait_for(lambda: len(of(lines, "input")) == 2)
        h.shot = lambda **kw: ShotResult(500.0, 1080, 2424, "h", 9.0, None, None)
        ge.feed(*tap_lines(3.0))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))
    taps = of(lines, "input", "tap")
    assert [t["data"]["before_shot"] for t in taps] == ["off", "failed", "failed"]
    failed = of(lines, "shot", "before_tap")  # the helper answered: a warn line
    assert [(x["ref"]["of"], x["level"]) for x in failed] == [(taps[2]["seq"], "warn")]


#: Every shot's answer once the system server restarted under the helper.
DEAD_SYSTEM = "DeadSystemRuntimeException: android.os.DeadSystemException"


class FakeHelperShell:
    """``adb shell <helper>`` for a real :class:`UiHelper`: the line protocol
    over queues. ``node_at`` and ``shot`` answer; once ``dead`` is set every
    shot fails while the process stays up, as after a Zygote restart.
    """

    def __init__(self, argv) -> None:
        self.argv = argv
        self.stdout, self.stderr = FakeStdout(), FakeStdout()
        self.stdin = self
        self.returncode = None
        self.dead = False
        self.emit({"type": "hello", "pid": 4242, "mode": "full", "flags": 1,
                   "display": {"w": 1080, "h": 2424, "rotation": 0}})  # fmt: skip
        self.emit({"type": "status", "state": "connected", "reason": "start"})

    def emit(self, obj: dict) -> None:
        self.stdout.q.put((json.dumps(obj) + "\n").encode())

    def write(self, data: bytes) -> int:
        name, *args = data.decode().split()
        rid = args[-1].removeprefix("id=")
        if name == "node_at":
            self.emit({**NODE_REPLY, "id": rid})
        elif name == "shot" and self.dead:
            self.emit({"type": "error", "id": rid, "cmd": "shot", "error": DEAD_SYSTEM})
        elif name == "shot":
            path = [a[5:] for a in args if a.startswith("path=")]
            self.emit({"type": "shot", "id": rid, "t_mono_ms": 500.0, "w": 1080,
                       "h": 2424, "hash": "h-before", "cap_ms": 9.0,
                       **({"path": path[0]} if path else {})})  # fmt: skip
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:  # stdin EOF: the helper disconnects and exits
        if self.returncode is None:
            self.returncode = 0
            self.stdout.q.put(None)
            self.stderr.q.put(None)

    kill = close

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def _helper_states(lines) -> list[str]:
    return [x["data"]["helper"] for x in of(lines, "tracking", "helper")]


def test_before_tap_shots_recover_after_a_system_server_restart(
    tmp_path, cfg, monkeypatch
):
    """A real session: the CA injection restarted Zygote mid-tracking. The
    helper's watchdog reconnected UiAutomation in place, node_at answered
    again, but the process kept handles into the dead system server: every
    later before-tap shot was ``failed`` (26 in a row) while screen-change
    shots fell back to screencap. The real UiHelper now replaces it.
    """
    from sandroid.core import uihelper
    from sandroid.core.adb import Adb

    def fake_adb(cmd, serial=None, timeout=30):
        if cmd.startswith("shell sha256sum"):
            return f"{uihelper.JAR_SHA256}  {uihelper.REMOTE_JAR}\n", ""
        return ("0\n" if cmd.startswith("shell settings get") else ""), ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_adb)
    shells: list[FakeHelperShell] = []

    def helper_popen(argv, **kw):
        if "exec-out" in argv:  # the PNG fetch
            return SimpleNamespace(communicate=lambda timeout=None: (PNG_A, b""))
        shells.append(FakeHelperShell(argv))
        return shells[-1]

    helpers: list[uihelper.UiHelper] = []

    def factory(serial, mode, on_event, on_status, raw_log):
        helpers.append(uihelper.UiHelper(
            serial, uihelper.Mode(mode), on_event=on_event, on_status=on_status,
            raw_log=raw_log, popen=helper_popen, adb_argv=["adb", "-s", serial],
            sleep=lambda s: None))  # fmt: skip
        return helpers[-1]

    popen = FakePopen()
    svc = ts.TrackingService(popen=popen, run=FakeRun(), helper_factory=factory,
                             folder_fn=lambda serial: tmp_path,
                             clock_record=lambda reason, serial: None)  # fmt: skip
    monkeypatch.setattr(ts, "_SERVICE", svc)
    try:
        with timeline.capture() as lines:
            ge = start(svc, popen, helpers, cfg)
            ge.feed(*tap_lines(10.0))
            assert wait_for(lambda: len(of(lines, "input", "tap")) == 1)
            shells[0].dead = True  # the Zygote restart, then the watchdog:
            shells[0].emit({"type": "status", "state": "lost", "reason": "watchdog"})
            shells[0].emit(
                {"type": "status", "state": "connected", "reason": "reconnect"}
            )
            restarted = wait_for(lambda: "restarted" in _helper_states(lines))
            ge.feed(*tap_lines(20.0))
            assert wait_for(lambda: len(of(lines, "input", "tap")) == 2)
            svc.stop()
    finally:
        svc.shutdown(2.0)
    taps = of(lines, "input", "tap")
    assert [t["data"]["before_shot"] for t in taps] == ["taken", "taken"]
    assert restarted
    assert len(shells) == 2
    lost = [x for x in of(lines, "tracking", "helper") if x["data"]["helper"] == "lost"]
    assert [x["data"]["reason"] for x in lost] == ["system_restart"]
    assert "system server restarted" in lost[0]["summary"]


def test_sha_dedupe_is_per_folder(tmp_path, cfg):
    """r_sha / r2_shots A: a new session's identical image is stored again
    in its own folder (it pointed into the old session's folder).
    """
    cfg.helper_mode = "off"
    folders = {"devA": tmp_path / "A", "devB": tmp_path / "B"}
    popen, run = FakePopen(), FakeRun()
    svc = ts.TrackingService(popen=popen, run=run, helper_factory=lambda *a: None,
                             folder_fn=lambda s: folders[s],
                             clock_record=lambda r, s: None)  # fmt: skip
    try:
        with timeline.capture() as lines:
            for n, dev in enumerate(("devA", "devB", "devB"), 1):
                assert svc.start(dev)
                assert wait_for(svc._geometry_ready.is_set)
                svc.manual_shot()
                assert wait_for(lambda n=n: len(of(lines, "shot")) == n)
                svc.stop()
    finally:
        svc.shutdown(2.0)
    a, b, b2 = of(lines, "shot")
    assert b["data"]["dup_of"] is None
    assert (folders["devB"] / b["ref"]["path"]).exists()
    assert (folders["devA"] / a["ref"]["path"]).exists()
    assert b2["data"]["dup_of"] == b["seq"]  # same folder: deduped


def test_a_kept_stream_writes_its_raw_log_into_the_new_folder(tmp_path, cfg):
    """Record keeps the stream alive across a session change: the raw log
    (and the input refs into it) follow the new timeline folder.
    """
    cfg.helper_mode = "off"
    folder = {"now": tmp_path / "s1"}
    popen, run = FakePopen(), FakeRun()
    svc = ts.TrackingService(popen=popen, run=run, helper_factory=lambda *a: None,
                             folder_fn=lambda s: folder["now"],
                             clock_record=lambda r, s: None)  # fmt: skip
    try:
        record = svc.getevent(SERIAL)
        g = popen.of("getevent -t")[0]
        g.feed(*tap_lines(1.0))
        assert wait_for(lambda: record.line_no() == 6)
        folder["now"] = tmp_path / "s2"  # a new session
        with timeline.capture() as lines:
            assert svc.start(SERIAL)
            g.feed(*tap_lines(2.0))
            assert wait_for(lambda: of(lines, "input"))
            svc.stop()
        record.release()
    finally:
        svc.shutdown(2.0)
    raw2 = (tmp_path / "s2" / ts.RAW_DIR / ts.GETEVENT_FILE).read_text().splitlines()
    assert raw2 == tap_lines(2.0)
    assert of(lines, "input")[0]["ref"]["raw"].endswith("#L1-L6")
    assert len((tmp_path / "s1/tracking/raw/getevent.txt").read_text().split()) > 0


def test_rotation_follows_the_screen(env, cfg):
    svc, popen, run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        assert svc.geometry.rotation == 0
        helpers[0].display = lambda timeout=2.0: {"w": 2424, "h": 1080, "rotation": 1}
        helpers[0].on_event(
            {"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": "a", "cls": "a.B"},
            time.time(),
        )
        assert wait_for(lambda: svc.geometry.rotation == 1)
        g.feed(*tap_lines(5.0, 0x4000, 0x2000))
        assert wait_for(lambda: of(lines, "input"))
    tap = of(lines, "input", "tap")[0]
    assert tap["data"]["rotation"] == 1
    assert tap["data"]["screen"] == [2424, 1080]
    # no helper display: dumpsys input
    svc.geometry.rotation = 0
    helpers[0].display = None
    real = run.__class__.__call__

    def rotated(self, argv, timeout=10.0):
        if "SurfaceOrientation" in " ".join(argv):
            return 0, b"      SurfaceOrientation: 3\n"
        return real(self, argv, timeout)

    run.__class__ = type("R", (FakeRun,), {"__call__": rotated})
    svc.on_logcat_line(ACTIVITY, time.time())
    with timeline.capture():
        helpers[0].alive = False  # logcat activity without a FULL helper
        svc.on_logcat_line(ACTIVITY.replace("Settings", "Other"), time.time())
        assert wait_for(lambda: svc.geometry.rotation == 3)


IME_REPLY = {
    "type": "node_at",
    "cached": {
        "window": {"id": 9, "type": "ime"},
        "hit": {"cls": "android.widget.Key", "text": "q"},
        "target": {"cls": "android.widget.Key", "text": "q", "desc": "q",
                   "bounds": [0, 2000, 100, 2100]},
        "pkg": "com.google.android.inputmethod.latin",
        "label": "q",
    },
}  # fmt: skip


def test_password_focus_and_keyboard_taps_are_sensitive(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        g = start(svc, popen, helpers, cfg)
        h = helpers[0]
        g.feed(*tap_lines(1.0))  # an ordinary tap
        assert wait_for(lambda: len(of(lines, "shot", "before_tap")) == 1)
        h.on_event({"type": "ev", "ev": "FOCUSED", "password": True,
                    "src": {"rid": "com.x:id/pw"}}, time.time())  # fmt: skip
        h.node_reply = IME_REPLY  # a key of the keyboard
        g.feed(*tap_lines(2.0))
        assert wait_for(lambda: len(of(lines, "shot", "before_tap")) == 2)
        h.node_reply = NODE_REPLY  # "Sign in" while the password is focused
        g.feed(*tap_lines(3.0))
        assert wait_for(lambda: len(of(lines, "shot", "before_tap")) == 3)
        h.on_event({"type": "ev", "ev": "FOCUSED", "src": {"rid": "com.x:id/u"}},
                   time.time())  # fmt: skip
        h.node_reply = IME_REPLY  # keyboard, plain field: still sensitive
        g.feed(*tap_lines(4.0))
        assert wait_for(lambda: len(of(lines, "input")) == 4)
        svc.manual_shot()
        assert wait_for(lambda: of(lines, "shot", "manual"))
    plain, key, sign_in, key2 = of(lines, "input")
    shots = {x["ref"]["of"]: x for x in of(lines, "shot", "before_tap")}
    assert "sensitive" not in plain
    assert "sensitive" not in shots[plain["seq"]]
    assert key["sensitive"] is True
    assert shots[key["seq"]]["sensitive"] is True
    assert key["summary"] == "tap on keyboard (password field)"
    assert "q" not in json.dumps(key["data"]["target"])  # no key label
    assert key["data"]["ime"] is True
    assert sign_in["sensitive"] is True
    assert shots[sign_in["seq"]]["sensitive"] is True
    assert key2["sensitive"] is True
    assert key2["summary"] == "tap on keyboard"
    assert "sensitive" not in of(lines, "shot", "manual")[0]  # focus moved on
    masked = timeline.mask(key)
    assert masked["data"]["_masked"] is True


def test_buffered_shot_keeps_its_file(env, cfg, monkeypatch):
    """A must-keep shot line held back by a detached timeline (emit returns
    None, the line is written later) must find its image.
    """
    svc, popen, _run, helpers, tmp = env
    emitted: list[dict] = []
    monkeypatch.setattr(svc, "_sink_buffering", lambda: True)
    monkeypatch.setattr(
        ts, "_emit", lambda src, kind, **kw: emitted.append(kw) and None
    )
    svc._folder = tmp
    seq = svc._store(
        "manual", PNG_A, of=None, via="helper", w=1, h=1, cap_ms=1.0, t=1.0,
        dev_mono=None,
    )  # fmt: skip
    assert seq is None
    path = emitted[0]["ref"]["path"]
    assert "{seq}" not in path
    assert (tmp / path).read_bytes() == PNG_A
    assert not list((tmp / "tracking/shots/.incoming").iterdir())


def test_stale_helper_callbacks_are_ignored_but_its_end_is_written(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        old = helpers[0]
        svc.stop()
        assert wait_for(lambda: old.stopped)
        start(svc, popen, helpers, cfg)
        new = helpers[1]
        assert wait_for(lambda: svc.state().helper == "connected")
        # the old helper (a late restart / event) must not touch this session
        old.on_status("lost", {"mode": "full"})
        old.on_event({"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": "old",
                      "cls": "old.A"}, time.time())  # fmt: skip
        new.on_event({"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": "new",
                      "cls": "new.A"}, time.time())  # fmt: skip
        assert svc.state().helper == "connected"
        svc.stop()
        assert wait_for(lambda: new.stopped)
        assert wait_for(lambda: len(of(lines, "sandroid", "intervention")) == 4)
    assert [x["data"]["pkg"] for x in of(lines, "screen", "window")] == ["new"]
    states = [x["data"]["state"] for x in of(lines, "sandroid", "intervention")]
    assert states == ["on", "off", "on", "off"]
    assert "lost" not in [x["data"]["helper"] for x in of(lines, "tracking")
                          if x["kind"] == "helper"]  # fmt: skip


def test_new_session_waits_for_the_old_helper_to_stop(env, cfg, monkeypatch):
    """a11y_before must be read after the old helper restored a11y."""
    svc, popen, _run, helpers, _tmp = env
    order: list[str] = []
    orig_stop = FakeHelper.stop

    def slow_stop(self):
        time.sleep(0.4)
        order.append("stopped")
        orig_stop(self)

    monkeypatch.setattr(FakeHelper, "stop", slow_stop)
    orig_start = FakeHelper.start
    monkeypatch.setattr(
        FakeHelper, "start", lambda self: order.append("start") or orig_start(self)
    )
    with timeline.capture():
        start(svc, popen, helpers, cfg)
        svc.stop()
        start(svc, popen, helpers, cfg)
    assert order == ["start", "stopped", "start"]


def test_a_dead_getevent_pid_is_never_killed(env, cfg):
    svc, popen, run, _helpers, _tmp = env
    s = svc.getevent(SERIAL)
    p = popen.of("getevent -t")[0]
    p.feed("add device 1: /dev/input/event0")
    assert wait_for(lambda: s._pid == 4242)
    p.rc = 1  # getevent died: the pid may be reused
    p.stdout.q.put(None)
    assert wait_for(lambda: s._pid is None)
    s.release()
    s.wait_closed()
    kill = [c for c in run.calls if "kill" in " ".join(c)][-1][-1]
    assert "kill 4242" not in kill
    assert "grep -q getevent /proc/$p/cmdline" in kill  # never a reused pid


def test_the_kill_checks_the_pid_is_still_getevent(env, cfg):
    svc, popen, run, _helpers, _tmp = env
    s = svc.getevent(SERIAL)
    popen.of("getevent -t")[0].feed("add device 1: /dev/input/event0")
    assert wait_for(lambda: s._pid == 4242)
    s.release()
    s.wait_closed()
    kill = [c for c in run.calls if "kill" in " ".join(c)][-1][-1]
    assert "p=4242;" in kill
    assert "grep -q getevent /proc/$p/cmdline" in kill


def test_last_release_and_a_new_lease_are_atomic(env, cfg):
    svc, popen, run, _helpers, _tmp = env
    s = svc.getevent(SERIAL)
    with svc._lock:  # a getevent() racing with the last release
        t = threading.Thread(target=s.release)
        t.start()
        time.sleep(0.1)
        again = svc.getevent(SERIAL)
    t.join(2.0)
    assert again is s
    assert s.leases == 1
    assert svc._streams.get(SERIAL) is s
    assert not any("kill" in " ".join(c) for c in run.calls)
    s.release()
    s.wait_closed()
    assert s.acquire() is False  # closed for good
    fresh = svc.getevent(SERIAL)
    assert fresh is not s
    fresh.release()


def test_record_never_stops_a_tracking_session_restarted_meanwhile(
    env, cfg, monkeypatch
):
    svc, popen, _run, _helpers, tmp = env
    cfg.helper_mode = "off"
    monkeypatch.setattr("sandroid.config.get_config", type("C", (), {"tracking": cfg}))
    with timeline.capture() as lines:
        rec = _record(monkeypatch, svc, tmp)
        assert rec.start()  # Record starts Tracking
        svc.stop()  # the user stops it ...
        assert svc.start(SERIAL)  # ... and starts their own
        rec.stop()
        assert svc.is_active()
        svc.stop()
    reasons = [x["data"]["reason"] for x in of(lines, "tracking")]
    assert reasons == ["record", "user", "user", "user"]


def test_start_never_blocks_the_header(env, cfg, monkeypatch):
    """start() used to hold the state lock across wait_closed (up to 5 s)."""
    svc, popen, run, _helpers, _tmp = env
    cfg.helper_mode = "off"
    real = FakeRun.__call__
    release = threading.Event()  # the teardown (kill) blocks until set

    def slow_kill(self, argv, timeout=10.0):
        if "kill" in " ".join(argv):
            release.wait(10.0)
        return real(self, argv, timeout)

    monkeypatch.setattr(FakeRun, "__call__", slow_kill)
    s = svc.getevent(SERIAL)
    waiting = threading.Event()
    real_wait = s.wait_closed

    def wait_closed(*args, **kwargs):
        waiting.set()
        return real_wait(*args, **kwargs)

    monkeypatch.setattr(s, "wait_closed", wait_closed)
    s.release()  # the teardown hangs in kill
    with timeline.capture():
        t = threading.Thread(target=svc.start, args=(SERIAL,))
        t.start()
        try:
            assert waiting.wait(10.0)  # start() waits for the teardown ...
            done = threading.Event()
            threading.Thread(
                target=lambda: (svc.state(), done.set()), daemon=True
            ).start()
            assert done.wait(10.0)  # ... and state() still answers
            assert t.is_alive()  # while start() is still blocked
        finally:
            release.set()
        t.join(10.0)
    assert svc.is_active()


def test_record_markers_keep_lead_in_and_tail(env, cfg, monkeypatch):
    """Play waits from the record start to the first touch and keeps the
    trailing pause (the old dummy start/stop events), ``recording_seconds``
    is the record length, and the real events replay unchanged.
    """
    import sandroid.features.player as player_module
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox
    from sandroid.features.player import Player
    from sandroid.tui.controllers.recording_controller import RecordingController

    svc, popen, _run, _helpers, tmp = env
    cfg.auto_on_record = False
    monkeypatch.setattr("sandroid.config.get_config", type("C", (), {"tracking": cfg}))
    off = 5_000.0 - time.time()  # device CLOCK_MONOTONIC - host epoch
    rec = _record(monkeypatch, svc, tmp)
    assert rec.start()
    g = popen.of("getevent -t")[0]
    t_start = time.time()
    time.sleep(0.4)
    taps = tap_lines(time.time() + off)
    g.feed(*taps)
    assert wait_for(lambda: rec.event_count == 6)
    time.sleep(0.4)
    t_stop = time.time()
    rec.stop()
    path = tmp / "raw/recording.getevent.txt"
    out = path.read_text().splitlines()
    assert out[1:-1] == taps
    first, last = ts.parse_getevent(out[0]), ts.parse_getevent(out[-1])
    assert first[1:] == last[1:] == (E1, 0, 0, 0)
    assert abs(first[0] - (t_start + off)) < 0.1
    assert abs(last[0] - (t_stop + off)) < 0.1
    seconds = RecordingController.recording_seconds(str(path))
    assert seconds == pytest.approx(t_stop - t_start, abs=0.1)
    sent: list[str] = []
    waits: list[float] = []
    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(sent.append))
    monkeypatch.setattr(Toolbox, "set_action_time", staticmethod(lambda: None))
    monkeypatch.setattr(Toolbox, "set_action_duration", staticmethod(lambda s: None))
    monkeypatch.setattr(player_module._cancel_event, "wait", waits.append)
    Player(recording_path=str(path)).perform()
    assert sent[0] == sent[-1] == f"shell sendevent {E1} 0 0 0"
    real = [player_module.parse_store_line(x) for x in taps]
    assert sent[1:-1] == [f"shell sendevent {d} {a} {b} {c}" for _t, d, a, b, c in real]
    assert waits[0] == pytest.approx(0.4, abs=0.1)  # lead-in
    # tail after the up (the fake's up is stamped 80 ms "ahead" of the host,
    # which the offset estimate absorbs)
    assert 0.25 < waits[-1] < 0.6


def test_record_display_callbacks_never_block_the_reader(env, cfg, monkeypatch):
    """A UI that does not answer (call_from_thread) must not stall the shared
    getevent reader: Tracking keeps decoding while the display hangs.
    """
    svc, popen, _run, helpers, tmp = env
    cfg.auto_on_record = False
    monkeypatch.setattr("sandroid.config.get_config", type("C", (), {"tracking": cfg}))
    from sandroid.tui.utils.recording_wrapper import RecordingWrapper

    hang = threading.Event()
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="off")
        rec = RecordingWrapper(
            output_file=str(tmp / "raw/recording.getevent.txt"),
            on_event=lambda line: hang.wait(5.0),
            on_count_update=lambda n: hang.wait(5.0),
            serial=SERIAL,
        )
        assert rec.start()
        popen.of("getevent -t")[0].feed(*tap_lines(1.0), *tap_lines(2.0))
        assert wait_for(lambda: len(of(lines, "input")) == 2, 1.0)
        assert rec.event_count == 12
        hang.set()
        rec.stop()


# --------------------------------------------------------------------------
# E2E round 1 fixes (scratchpad/e2e)
# --------------------------------------------------------------------------


def _quit_stubs(monkeypatch, on_task_kill):
    from sandroid import services
    from sandroid.core import ui_request_bus
    from sandroid.services import setup_checks
    from sandroid.tui.controllers import quit_controller as qc

    monkeypatch.setattr(qc, "_flush_timeline", lambda timeout: None)
    monkeypatch.setattr(qc, "_close_timeline", lambda reason, timeout: None)
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: None)
    monkeypatch.setattr(qc, "run_shutdown_hooks", lambda timeout=0: None)
    monkeypatch.setattr(qc.QuitController, "_stop_frida_sessions",
                        staticmethod(lambda: None))  # fmt: skip
    monkeypatch.setattr(qc.QuitController, "_cleanup_rest", staticmethod(lambda: None))
    monkeypatch.setattr(setup_checks, "restore_selinux_on_quit", lambda: None)
    bus = SimpleNamespace(shutdown=lambda: None)
    monkeypatch.setattr(ui_request_bus.UIRequestBus, "get", staticmethod(lambda: bus))
    monkeypatch.setattr(services, "get_task_service",
                        lambda: SimpleNamespace(stop_all=on_task_kill))  # fmt: skip
    return qc


def test_quit_stops_tracking_before_the_task_kill_and_nothing_restarts(
    env, cfg, monkeypatch
):
    """F1: quitting with Tracking on wrote no tracking/stop and no
    intervention-off line; the task kill then killed getevent and the helper,
    which restarted ("helper lost · restarting") during the quit.
    """
    svc, popen, _run, helpers, _tmp = env
    seen: dict = {}

    def task_kill():  # what the background-task / untracked-work kill does
        seen["active"] = svc.is_active()
        seen["helper_stopped"] = helpers[0].stopped
        seen["leases"] = sum(s.leases for s in svc._streams.values())
        for proc in popen.of("getevent -t"):
            proc.terminate()

    qc = _quit_stubs(monkeypatch, task_kill)
    monkeypatch.setattr(ts, "RESTART_BACKOFF_S", (0.05,))
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        qc.QuitController().force_exit()
        time.sleep(0.4)
        assert svc.start(SERIAL) is False  # nothing starts while quitting
    assert seen == {"active": False, "helper_stopped": True, "leases": 0}
    stop = of(lines, "tracking", "stop")
    assert len(stop) == 1
    assert stop[0]["data"]["reason"] == "quit"
    off = [x for x in of(lines, "sandroid", "intervention")
           if x["data"]["state"] == "off"]  # fmt: skip
    assert len(off) == 1
    assert [x["data"]["helper"] for x in of(lines, "tracking", "helper")] == [
        "connected",
        "stopped",
    ]
    assert len(popen.of("getevent -t")) == 1  # never respawned
    assert popen.of("getevent -t")[0].terminated


def test_a_getevent_killed_while_quitting_is_not_respawned(tmp_path):
    """F1: the getevent restart loop stops once a quit suppressed it."""
    popen = FakePopen()
    stream = ts.GeteventStream(
        SERIAL, tmp_path / "ge.txt", popen=popen, run=FakeRun(), backoff=(0.05,)
    )
    assert stream.acquire()
    popen.procs[0].terminate()  # not suppressed: respawned
    assert wait_for(lambda: len(popen.procs) == 2)
    stream.suppress_restarts()
    popen.procs[1].terminate()
    time.sleep(0.3)
    assert len(popen.procs) == 2
    stream.release()
    stream.wait_closed(2.0)


def test_quit_paths_stop_tracking(monkeypatch):
    """F1: emergency_cleanup and the atexit hook stop Tracking too (and
    never create the service on the way out).
    """
    from sandroid.tui.controllers import quit_controller as qc

    calls = []
    fake = SimpleNamespace(
        shutdown=lambda timeout, reason, actor: calls.append((reason, timeout))
    )
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: None)
    monkeypatch.setattr(qc, "_close_timeline", lambda reason, timeout: None)
    monkeypatch.setattr(ts, "_SERVICE", None)
    qc.emergency_cleanup()
    ts._atexit_stop()
    assert calls == []
    assert ts._SERVICE is None
    monkeypatch.setattr(ts, "_SERVICE", fake)
    qc.emergency_cleanup()
    ts._atexit_stop()
    assert calls == [("forced-exit", 2.0), ("exit", 5.0)]


ROW_REPLY = {  # the real node_at answer of the E2E tap on Settings > Battery
    "type": "node_at",
    "cached": {
        "window": {"id": 379, "type": "app", "title": "Settings"},
        "pkg": "com.android.settings",
        "hit": {
            "cls": "android.widget.TextView",
            "text": "Battery",
            "rid": "android:id/title",
            "bounds": [189, 1757, 357, 1828],
        },
        "path": ["RecyclerView#recycler_view", "LinearLayout", "TextView#title"],
        "target": {
            "cls": "android.widget.LinearLayout",
            "bounds": [0, 1703, 1080, 1934],
            "clickable": True,
        },
        "label": "Battery / Charged",
    },
    "live": {"hit": None, "reason": "no_window"},
}


def test_a_row_without_text_keeps_its_descendant_label(env, cfg):
    """F3: the summary said 'Battery / Charged' but the target kept no name,
    so the report printed 'LinearLayout'.
    """
    from sandroid.core import report_engine

    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        helpers[0].node_reply = ROW_REPLY
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
    tap = of(lines, "input", "tap")[0]
    target = tap["data"]["target"]
    assert tap["summary"] == "tap 'Battery / Charged' (LinearLayout)"
    assert target["text"] is None  # still the node's OWN text
    assert target["label"] == "Battery / Charged"
    assert report_engine.element_name(target) == "Battery / Charged"


def _frame_png(frame: str) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + frame.encode() * 8


def _screen_helper(h: FakeHelper, frame: str) -> None:
    """The helper's frame is ``h.frame`` (what the device shows now)."""
    h.frame = frame

    def shot(*, hash_only=False, timeout=5.0):
        f = h.frame
        if hash_only:
            return ShotResult(1.0, 1080, 2424, f, 3.0, None, None)
        return ShotResult(1.0, 1080, 2424, f, 14.0, _frame_png(f), "/x")

    h.shot = shot


def _sha(frame: str) -> str:
    import hashlib

    return hashlib.sha256(_frame_png(frame)).hexdigest()


SETTINGS = "com.android.settings"
SUB = "com.android.settings.SubSettings"


def test_screen_change_shot_waits_for_the_new_screen(env, cfg):
    """F2: a logcat activity line fires before the new activity draws; the
    shot showed the PREVIOUS screen, and the window line that followed lost
    its own shot. E2E: activity SubSettings (#191), window SubSettings ·
    Battery (#193), window homepage (#198).
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_screen_change = True
    cfg.settle_interval_ms = 100
    cfg.settle_max_ms = 2000
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        _screen_helper(h, "home")
        svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                         window_id=None, via="logcat", dev_mono=1.0)  # fmt: skip
        time.sleep(0.15)
        h.on_event({"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": SETTINGS,
                    "cls": SUB, "text": "Battery", "window_id": 422,
                    "t_mono_ms": 2000.0}, time.time())  # fmt: skip
        time.sleep(0.3)
        h.frame = "battery"  # drawn late (a loaded emulator)
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 2)
        time.sleep(0.2)
        h.on_event({"type": "ev", "ev": "WINDOW_STATE_CHANGED", "pkg": SETTINGS,
                    "cls": f"{SETTINGS}.homepage.SettingsHomepageActivity",
                    "text": "Settings", "window_id": 413,
                    "t_mono_ms": 3000.0}, time.time())  # fmt: skip
        time.sleep(0.3)
        h.frame = "home"
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 3)
    act = of(lines, "screen", "activity")[0]
    win_battery, win_home = of(lines, "screen", "window")
    shots = of(lines, "shot", "screen_change")
    assert [s["ref"]["of"] for s in shots] == [
        act["seq"],
        win_battery["seq"],
        win_home["seq"],
    ]
    assert [s["ref"]["sha256"] for s in shots] == [
        _sha("battery"),
        _sha("battery"),  # the window's own line, same capture
        _sha("home"),
    ]
    assert shots[1]["data"]["dup_of"] == shots[0]["seq"]
    for s in shots:
        assert s["data"]["stable"] is True
        assert "unchanged" not in s["data"]


def test_screen_change_shot_flags_a_frame_that_never_changed(env, cfg):
    """F2: no new frame within settle_max_ms: the stable frame is kept,
    flagged ``data.unchanged``.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_screen_change = True
    cfg.settle_interval_ms = 100
    cfg.settle_max_ms = 500
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        _screen_helper(helpers[0], "same")
        svc._emit_screen("window", pkg="a", cls="a.B", title="T",
                         window_id=1, via="a11y", dev_mono=1.0)  # fmt: skip
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["data"]["unchanged"] is True
    assert shot["data"]["stable"] is True
    assert shot["data"]["settle_ms"] >= 400
    assert shot["ref"]["sha256"] == _sha("same")


def test_invisible_mode_logcat_shot_waits_for_the_new_screen(env, cfg):
    """F2, invisible mode (screen lines from logcat only): E2E #106 was the
    before-tap image, #101 the splash of the previous screen.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_screen_change = True
    cfg.logcat_screen_backup = True
    cfg.settle_interval_ms = 100
    cfg.settle_max_ms = 2000
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")
        _screen_helper(helpers[0], "before")
        assert wait_for(lambda: popen.of("wm_set_resumed_activity"))
        popen.of("wm_set_resumed_activity")[0].feed(ACTIVITY)
        assert wait_for(lambda: of(lines, "screen", "activity"))
        time.sleep(0.35)
        helpers[0].frame = "after"
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["of"] == of(lines, "screen", "activity")[0]["seq"]
    assert shot["ref"]["sha256"] == _sha("after")
    assert "unchanged" not in shot["data"]


# --------------------------------------------------------------------------
# F2 under device load (E2E round 2: #39, #100, #142)
# --------------------------------------------------------------------------


def _stop_data(svc, lines) -> dict:
    svc.stop()
    return of(lines, "tracking", "stop")[-1]["data"]


def _load_cfg(cfg, settle_max_ms: int = 2000) -> None:
    cfg.shot_screen_change = True
    cfg.shot_before_tap = False
    cfg.settle_interval_ms = 100
    cfg.settle_max_ms = settle_max_ms


def test_screen_shot_is_dropped_when_the_next_tap_comes_first(env, cfg):
    """#39: the shot of Settings home was captured 12.8 s late, after the
    next tap, showed the next screen and claimed ``unchanged``. A capture
    that would start after the next finger-down is dropped (counted).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        _screen_helper(helpers[0], "home")  # never settles to a new frame
        svc._emit_screen("window", pkg="a", cls="a.Home", title="Home",
                         window_id=1, via="a11y", dev_mono=10.0)  # fmt: skip
        time.sleep(0.25)
        ge.feed(*tap_lines(10.4))  # the next tap, before the shot was taken
        assert wait_for(lambda: svc._shot_drops.get("late") == 1)
        time.sleep(0.2)
        data = _stop_data(svc, lines)
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"late": 1}
    assert "1 dropped" in of(lines, "tracking", "stop")[-1]["summary"]


def test_the_tap_that_caused_the_screen_change_is_not_the_next_input(env, cfg):
    """The causal tap went down before the screen event (device clock),
    even when its getevent line reaches the host after the a11y line.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        _screen_helper(h, "old")
        svc._emit_screen("window", pkg="a", cls="a.Next", title="Next",
                         window_id=1, via="a11y", dev_mono=10.0)  # fmt: skip
        ge.feed(*tap_lines(9.9, dur=0.05))  # down 100 ms before the event
        time.sleep(0.2)
        h.frame = "new"
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["sha256"] == _sha("new")
    assert not svc._shot_drops


def test_a_capture_the_busy_helper_took_after_the_next_tap_is_dropped(env, cfg):
    """The capture started in time, but the busy helper took it (device
    time) after the next finger-down: not this screen's image.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        _screen_helper(h, "old")
        hash_shot = h.shot

        def busy_shot(*, hash_only=False, timeout=5.0):
            if hash_only:
                return hash_shot(hash_only=True)
            ge.feed(*tap_lines(10.2))  # the user taps while the helper is busy
            wait_for(lambda: svc._input_seen)
            return ShotResult(10_400.0, 1080, 2424, "new", 14.0,
                              _frame_png("new"), "/x")  # fmt: skip

        h.shot = busy_shot
        svc._emit_screen("window", pkg="a", cls="a.B", title="B",
                         window_id=1, via="a11y", dev_mono=10.0)  # fmt: skip
        time.sleep(0.15)
        h.frame = "new"
        assert wait_for(lambda: svc._shot_drops.get("late") == 1)
    assert not of(lines, "shot", "screen_change")


@pytest.mark.parametrize("late_by", ["host", "device"])
def test_a_late_before_hash_makes_no_unchanged_claim(env, cfg, late_by):
    """#100 / #142: the pre-change hash was taken late (busy lane/helper),
    already showed the new screen, and the shot claimed ``unchanged``. Now
    no claim; ``data.before_late_ms`` and ``data.lag_ms`` say why.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=1000)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        _screen_helper(h, "new")  # the new screen is already up
        frame_shot = h.shot
        calls = {"n": 0}

        def slow_first_hash(*, hash_only=False, timeout=5.0):
            res = frame_shot(hash_only=hash_only)
            if hash_only and calls["n"] == 0 and late_by == "device":
                calls["n"] += 1  # the busy helper took it 450 ms after the event
                return ShotResult(1_450.0, 1080, 2424, res.hash, 3.0, None, None)
            return res

        h.shot = slow_first_hash
        if late_by == "host":  # the screen-pre lane is still busy
            svc._screen_pre_lane.submit(time.sleep, 0.4)
        svc._emit_screen("window", pkg="a", cls="a.B", title="B",
                         window_id=1, via="a11y", dev_mono=1.0)  # fmt: skip
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shot = of(lines, "shot", "screen_change")[0]
    assert "unchanged" not in shot["data"]
    assert shot["data"]["before_late_ms"] > ts.SCREEN_BEFORE_MAX_MS
    assert shot["data"]["lag_ms"] >= shot["data"]["before_late_ms"]
    assert shot["data"]["stable"] is True


def test_a_timely_before_hash_still_flags_unchanged_with_its_lag(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=500)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        _screen_helper(helpers[0], "same")
        svc._emit_screen("window", pkg="a", cls="a.B", title="T",
                         window_id=1, via="a11y", dev_mono=1.0)  # fmt: skip
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    data = of(lines, "shot", "screen_change")[0]["data"]
    assert data["unchanged"] is True
    assert "before_late_ms" not in data
    assert 400 <= data["lag_ms"] < 2000  # settled for settle_max_ms first


def test_screencap_fallback_records_the_lag_and_never_claims_unchanged(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="off")
        svc._emit_screen("activity", pkg="a", cls="a.B", title=None,
                         window_id=None, via="logcat", dev_mono=1.0,
                         t_evt=time.time() - 3.0)  # fmt: skip
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    data = of(lines, "shot", "screen_change")[0]["data"]
    assert data["via"] == "screencap"
    assert "unchanged" not in data
    assert data["lag_ms"] >= 3000


def test_queued_screen_shots_coalesce_to_the_latest_screen(env, cfg):
    """No backlog: screens queued behind a busy shot lane are superseded by
    a newer distinct screen (dropped, counted); the latest one is shot.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        _screen_helper(helpers[0], "old")
        gate = threading.Event()
        svc._shot_lane.submit(gate.wait, 5.0)  # e.g. a slow screencap
        svc._screen_pre_lane.submit(gate.wait, 5.0)  # and a busy helper
        seqs = []
        for i, name in enumerate(("A", "B", "C")):
            seq = svc._emit_screen("window", pkg="a", cls=f"a.{name}", title=name,
                                   window_id=i, via="a11y", dev_mono=1.0 + i)  # fmt: skip
            seqs.append(seq)
        assert len(svc._screen_q) == 1
        helpers[0].frame = "C"
        gate.set()
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
        time.sleep(0.3)
        data = _stop_data(svc, lines)
    shots = of(lines, "shot", "screen_change")
    assert [s["ref"]["of"] for s in shots] == [seqs[2]]
    assert data["shots_dropped"] == {"superseded": 2}


def test_a_settling_screen_shot_yields_to_a_newer_screen(env, cfg):
    """A screen still settling when the next distinct screen arrives would
    be captured after that event: it is dropped, the newer one is shot.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        _screen_helper(helpers[0], "old")  # A never changes: it would wait 2 s
        first = svc._emit_screen("window", pkg="a", cls="a.A", title="A",
                                 window_id=1, via="a11y", dev_mono=1.0)  # fmt: skip
        time.sleep(0.25)
        second = svc._emit_screen("window", pkg="a", cls="a.B", title="B",
                                  window_id=2, via="a11y", dev_mono=1.3)  # fmt: skip
        time.sleep(0.1)  # B draws after its pre-change hash
        helpers[0].frame = "B"
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shots = of(lines, "shot", "screen_change")
    assert [s["ref"]["of"] for s in shots] == [second]
    assert shots[0]["ref"]["sha256"] == _sha("B")
    assert first not in [s["ref"]["of"] for s in shots]
    assert svc._shot_drops == {"superseded": 1}


# --------------------------------------------------------------------------
# F2: a logcat screen line before the new screen draws (E2E runC #78/#82/#105)
# --------------------------------------------------------------------------


def _spy_pre_hash(svc) -> list[tuple]:
    """The pre-change hashes taken: ``(result, host start)``."""
    taken, orig = [], svc._pre_hash

    def spy(helper):
        res = orig(helper)
        taken.append(res)
        return res

    svc._pre_hash = spy
    return taken


def _tap_with_before_shot(ge, lines, t: float) -> None:
    n = len(of(lines, "shot", "before_tap"))
    ge.feed(*tap_lines(t))
    assert wait_for(lambda: len(of(lines, "shot", "before_tap")) == n + 1)


def test_a_late_before_hash_equal_to_the_old_screen_is_not_stored(env, cfg):
    """#78 (of logcat #76): the pre-change hash was 644 ms late and already
    the old screen; the new activity had not drawn when the wait ended. The
    shot was stored with no flag. The before-tap frame proves it is the old
    screen: dropped, counted ``unverified``.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)  # a logcat line waits 1.5 s
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        _screen_helper(helpers[0], "old")
        _tap_with_before_shot(ge, lines, 9.5)
        taken = _spy_pre_hash(svc)
        svc._screen_pre_lane.submit(time.sleep, 0.4)  # the pre-change hash is late
        t_evt = time.time()
        svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                         window_id=None, via="logcat", dev_mono=10.0)  # fmt: skip
        assert wait_for(lambda: svc._shot_drops.get("unverified") == 1, timeout=10.0)
        data = _stop_data(svc, lines)
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"unverified": 1}
    # the hash was late, and itself the old screen: no frame ever differed
    assert taken[0][1] - t_evt > ts.SCREEN_BEFORE_MAX_MS / 1000.0
    assert {f[3] for f in svc._frames} == {"old"}
    assert "1 dropped" in of(lines, "tracking", "stop")[-1]["summary"]


def test_a_frame_equal_to_an_earlier_before_tap_shot_is_not_stored(env, cfg):
    """#105 (of logcat #102) was ``dup_of`` #98, the before-tap image of the
    screen the tap left. The late pre-change hash and the latest frame seen
    before the event were the pressed row (a ripple), so the frame "changed"
    back to the old screen. Every frame seen between the tap and the event
    is the old screen: dropped, counted ``unverified``.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        _screen_helper(h, "home")
        _tap_with_before_shot(ge, lines, 9.5)
        h.frame = "ripple"
        svc._shot_seen(h, hash_only=True)  # seen after the tap, before the event
        taken = _spy_pre_hash(svc)
        svc._screen_pre_lane.submit(time.sleep, 0.4)
        svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                         window_id=None, via="logcat", dev_mono=10.0)  # fmt: skip
        time.sleep(0.6)
        h.frame = "home"  # the ripple ends; the new activity has not drawn yet
        assert wait_for(lambda: svc._shot_drops.get("unverified") == 1, timeout=10.0)
    assert not of(lines, "shot", "screen_change")
    assert all(s["data"]["dup_of"] is None for s in of(lines, "shot"))
    assert taken[0][0].hash == "ripple"  # the late pre-change hash


def test_a_logcat_screen_drawn_3_s_later_is_still_captured(env, cfg):
    """#78: the activity drew more than 2 s after its logcat line. A logcat
    line waits ``settle_max_ms`` x 2.5 for the change, so the shot shows it.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)  # settle_max_ms 2000: a logcat line waits up to 5 s
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg, mode="invisible")
        _screen_helper(helpers[0], "old")
        seq = svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                               window_id=None, via="logcat", dev_mono=10.0)  # fmt: skip
        time.sleep(3.0)
        helpers[0].frame = "new"
        assert wait_for(lambda: of(lines, "shot", "screen_change"), timeout=10.0)
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["of"] == seq
    assert shot["ref"]["sha256"] == _sha("new")
    assert "unchanged" not in shot["data"]
    assert shot["data"]["stable"] is True
    assert shot["data"]["settle_ms"] > cfg.settle_max_ms
    assert shot["data"]["lag_ms"] >= 3000
    assert not svc._shot_drops


def test_going_back_to_an_earlier_screen_is_still_captured(env, cfg):
    """Only frames since the last input count as the old screen: a back
    navigation to a screen shot earlier is stored (a dedup line).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        _screen_helper(h, "A")
        _tap_with_before_shot(ge, lines, 5.0)
        svc._emit_screen("activity", pkg="a", cls="a.B", title=None,
                         window_id=None, via="logcat", dev_mono=5.2)  # fmt: skip
        time.sleep(0.05)
        h.frame = "B"
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
        _tap_with_before_shot(ge, lines, 9.5)  # back
        svc._screen_pre_lane.submit(time.sleep, 0.4)  # a late pre-change hash
        svc._emit_screen("activity", pkg="a", cls="a.A", title=None,
                         window_id=None, via="logcat", dev_mono=10.0)  # fmt: skip
        time.sleep(0.5)
        h.frame = "A"
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 2)
    first_before = of(lines, "shot", "before_tap")[0]
    shot_b, shot_a = of(lines, "shot", "screen_change")
    assert shot_b["ref"]["sha256"] == _sha("B")
    assert shot_a["ref"]["sha256"] == _sha("A")
    assert shot_a["data"]["dup_of"] == first_before["seq"]
    assert shot_a["data"]["before_late_ms"] > ts.SCREEN_BEFORE_MAX_MS
    assert not svc._shot_drops


# --------------------------------------------------------------------------
# Coverage: the fallback capture (E2E runD #12/#16/#20/#35/#38 dropped late)
# --------------------------------------------------------------------------


def _clocked_helper(h: FakeHelper, frame: str, dev0: float) -> dict:
    """Like :func:`_screen_helper`, with a device clock (``dev0`` s now) in
    the replies' ``t_mono_ms``. ``h.frame`` may be a callable (an animation:
    a new frame per shot). Returns counters (``full``: frames captured in
    full, ``seen``: every frame shot, in order).
    """
    h.frame = frame
    host0 = time.time()
    stats: dict = {"full": [], "seen": []}

    def now_dev() -> float:
        return dev0 + (time.time() - host0)

    def shot(*, hash_only=False, timeout=5.0):
        f = h.frame() if callable(h.frame) else h.frame
        stats["seen"].append(f)
        t_ms = now_dev() * 1000.0
        if hash_only:
            return ShotResult(t_ms, 1080, 2424, f, 3.0, None, None)
        stats["full"].append(f)
        return ShotResult(t_ms, 1080, 2424, f, 14.0, _frame_png(f), "/x")

    h.shot = shot
    stats["now"] = now_dev
    return stats


def _animation(prefix: str, n: int | None = None):
    """A new frame per shot (``n``: cycle through ``n`` frames, a blink)."""
    k = {"i": 0}

    def frame() -> str:
        k["i"] += 1
        return f"{prefix}{k['i'] % n if n else k['i']}"

    return frame


def test_an_animated_new_screen_gets_its_fallback_when_the_next_tap_comes(env, cfg):
    """An animated new screen never settles; the next tap ends the wait. The
    fallback (a new frame captured in full before the tap) is stored,
    ``stable:false``, instead of dropping the shot as late.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        stats = _clocked_helper(h, "old", 100.0)
        seq = svc._emit_screen("window", pkg="a", cls="a.Anim", title="Anim",
                               window_id=1, via="a11y", dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.1)
        h.frame = _animation("anim-")
        time.sleep(0.8)
        t_tap = stats["now"]()
        ge.feed(*tap_lines(t_tap))
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
        data = _stop_data(svc, lines)
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["of"] == seq
    assert shot["data"]["stable"] is False
    assert shot["data"]["fallback"] is True
    assert shot["ref"]["sha256"] == _sha(stats["full"][-1])  # the newest
    assert shot["dev_mono"] < t_tap  # captured before the finger-down
    assert 0 < shot["data"]["lag_ms"] < 1500
    assert 1 <= len(stats["full"]) <= ts.SHOT_FALLBACK_MAX
    assert not data.get("shots_dropped")


def test_a_new_logcat_screen_seen_before_the_next_tap_is_stored(env, cfg):
    """E2E runD #38: the new screen appeared (a blinking cursor: it never
    settled) and the next tap came: the shot was dropped as late. Now a
    fallback from before the tap is stored. R2: a blinking frame is never
    seen twice in a row, so it is the settle's capture only when that is
    also the last frame before the tap, else the tap's before-tap capture
    (taken at its finger-down, before its finger-up).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "home", 50.0)
        _tap_with_before_shot(ge, lines, stats["now"]())
        seq = svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                               window_id=None, via="logcat", dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.4)
        h.frame = _animation("net-", 2)  # drawn, cursor blinking
        time.sleep(0.6)
        t_tap = stats["now"]()
        n_before = len(stats["full"])
        _tap_with_before_shot(ge, lines, t_tap)
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
        data = _stop_data(svc, lines)
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["ref"]["of"] == seq
    assert shot["data"]["stable"] is False
    assert shot["data"]["fallback"] is True
    assert shot["ref"]["sha256"] in {_sha("net-0"), _sha("net-1")}
    if shot["data"].get("source") == "next_before_tap":
        assert (
            shot["ref"]["sha256"] == of(lines, "shot", "before_tap")[1]["ref"]["sha256"]
        )
        assert t_tap <= shot["dev_mono"] <= t_tap + 0.08  # down .. up
    else:
        assert shot["dev_mono"] < t_tap
    assert n_before >= 2  # the first before-tap shot and the fallback
    assert not data.get("shots_dropped")


def test_no_new_frame_before_the_next_tap_is_still_dropped_late(env, cfg):
    """E2E runD #35: the device showed the old screen until after the next
    tap. No new frame was seen before it: nothing to fall back on, dropped
    ``late`` (a frame seen after the tap may show the next screen).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "battery", 70.0)
        svc._emit_screen("activity", pkg=SETTINGS, cls=SETTINGS + ".Settings",
                         title=None, window_id=None, via="logcat",
                         dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.5)
        ge.feed(*tap_lines(stats["now"]()))
        time.sleep(0.05)
        h.frame = "home"  # drawn only after the tap
        assert wait_for(lambda: svc._shot_drops.get("late") == 1)
        time.sleep(0.2)
        data = _stop_data(svc, lines)
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"late": 1}


def test_a_transition_back_to_the_old_screen_is_no_fallback(env, cfg):
    """E2E runD #12: the late pre-change hash was the pressed row (a ripple)
    and the next before-tap shot the old screen again. Frames that were new
    for a moment (captured in full as fallbacks) are void once the old
    screen comes back after them; the late pre-change hash (either screen)
    is never captured as one.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "home", 30.0)
        svc._shot_seen(h, hash_only=True)  # the old screen, before the event
        late = threading.Event()  # the pre-change hash is late until set
        svc._screen_pre_lane.submit(late.wait, 10.0)
        taken = _spy_pre_hash(svc)
        svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                         window_id=None, via="logcat", dev_mono=stats["now"]())  # fmt: skip
        # the settle samples the old screen while the hash is pending
        assert wait_for(lambda: stats["seen"].count("home") >= 3)
        h.frame = "pressed"  # the late hash sees the ripple
        late.set()
        assert wait_for(lambda: taken)
        fade = _animation("fade-")  # the ripple fades (captured in full) ...

        def fading() -> str:
            # ... and the old screen is back right after the first full
            # capture; the new one never drew
            return "home" if stats["full"] else fade()

        h.frame = fading
        assert wait_for(lambda: stats["full"] and stats["seen"][-2:] == ["home"] * 2)
        ge.feed(*tap_lines(stats["now"]()))
        assert wait_for(lambda: svc._shot_drops.get("late") == 1, timeout=10.0)
        time.sleep(0.2)
        data = _stop_data(svc, lines)
    assert taken[0][0].hash == "pressed"
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"late": 1}
    assert stats["full"]
    assert all(f.startswith("fade-") for f in stats["full"])


def test_stability_counts_only_from_samples_after_the_references(env):
    """The settle wait may not end on a frame it saw while the old-screen
    references were pending: the first sample after them is compared with
    nothing, not with a pending-phase sample (deterministic version of the
    race behind the ripple test above: two samples of a short ripple, one
    on each side of ``ready()``, used to settle the wait on the ripple).
    """
    svc = env[0]
    frames = iter(["ripple", "ripple", "fade-1", "home", "home", "home"])
    sampled: list[str] = []

    class _Helper:
        def shot(self, *, hash_only=False, timeout=5.0):
            f = next(frames, "home")
            sampled.append(f)
            return ShotResult(1000.0, 1080, 2424, f, 3.0, None, None)

    cfg = SimpleNamespace(settle_interval_ms=1, settle_max_ms=200)
    st = svc._settle_change(
        _Helper(),
        cfg,
        lambda: {"home"},
        max_ms=200.0,
        ready=lambda: len(sampled) >= 2,  # the references arrive with sample 2
        fresh=lambda frame: True,
    )
    assert sampled[:2] == ["ripple", "ripple"]
    assert st["last"] != "ripple" or not st["stable"]
    assert len(sampled) > 2  # the second ripple sample did not end the wait


def test_a_settling_screen_with_a_fallback_survives_a_newer_screen(env, cfg):
    """A newer screen supersedes a still-settling one: its fallback, taken
    before the newer event, is stored; the newer screen gets its own shot.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        stats = _clocked_helper(h, "old", 10.0)
        first = svc._emit_screen("window", pkg="a", cls="a.A", title="A",
                                 window_id=1, via="a11y", dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.1)
        h.frame = _animation("a-", 2)
        time.sleep(0.6)
        second = svc._emit_screen("window", pkg="a", cls="a.B", title="B",
                                  window_id=2, via="a11y", dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.05)
        h.frame = "B"
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 2)
    shot_a, shot_b = of(lines, "shot", "screen_change")
    assert shot_a["ref"]["of"] == first
    assert shot_a["data"]["fallback"] is True
    assert shot_a["ref"]["sha256"] in {_sha("a-0"), _sha("a-1")}
    assert shot_b["ref"]["of"] == second
    assert shot_b["ref"]["sha256"] == _sha("B")
    assert not svc._shot_drops


# --------------------------------------------------------------------------
# R1/R2: the before-tap frame anchors the previous screen (E2E round 5)
# --------------------------------------------------------------------------


def _lagging_helper(h: FakeHelper, frame: str, dev0: float) -> tuple[dict, object]:
    """A clocked helper whose hash-only samples lag behind the screen (E2E
    round 5: the settle samples kept showing the old screen until after
    the next tap; only that tap's before-tap capture showed the new one).
    ``view["hash"]``: what hash-only samples see, ``view["full"]``: what a
    full capture sees. Returns the view and the device clock.
    """
    view = {"hash": frame, "full": frame}
    host0 = time.time()

    def now_dev() -> float:
        return dev0 + (time.time() - host0)

    def shot(*, hash_only=False, timeout=5.0):
        t_ms = now_dev() * 1000.0
        if hash_only:
            return ShotResult(t_ms, 1080, 2424, view["hash"], 3.0, None, None)
        f = view["full"]
        return ShotResult(t_ms, 1080, 2424, f, 14.0, _frame_png(f), "/x")

    h.shot = shot
    return view, now_dev


def test_round5_full_battery_and_home_after_back_get_the_next_before_tap(env, cfg):
    """E2E round 5, FULL (#16/#17 Battery, #19/#21 home after back): no
    sample before the next tap showed the new screen; the next tap's
    before-tap capture (#20, #23) did. The fallback rule rejected it because
    a frame after the next tap matched the old screen. R2: only frames
    before the next input count, and its before-tap capture is the last of
    them: both screens are stored from it (``data.source``).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        view, now = _lagging_helper(helpers[0], "home", 42320.0)
        _tap_with_before_shot(ge, lines, now())  # #13 'Battery'
        act = svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                               window_id=None, via="logcat", dev_mono=now())  # fmt: skip
        win = svc._emit_screen("window", pkg=SETTINGS, cls=SUB, title="Battery",
                               window_id=468, via="a11y", dev_mono=now())  # fmt: skip
        time.sleep(0.6)
        view["full"] = "battery"  # what the next tap sees
        _tap_with_before_shot(ge, lines, now())  # #18 back
        view["hash"] = "battery"
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 2)
        back = svc._emit_screen("activity", pkg=SETTINGS, cls=SETTINGS + ".Settings",
                                title=None, window_id=None, via="logcat",
                                dev_mono=now())  # fmt: skip
        time.sleep(0.15)
        home = svc._emit_screen("window", pkg=SETTINGS,
                                cls=SETTINGS + ".homepage.SettingsHomepageActivity",
                                title="Settings", window_id=461, via="a11y",
                                dev_mono=now())  # fmt: skip
        time.sleep(0.6)
        view["full"] = "home"
        _tap_with_before_shot(ge, lines, now())  # #22
        view["hash"] = "home"
        assert wait_for(lambda: len(of(lines, "shot", "screen_change")) == 3)
        time.sleep(0.2)
        data = _stop_data(svc, lines)
    shots = of(lines, "shot", "screen_change")
    befores = of(lines, "shot", "before_tap")
    assert [s["ref"]["of"] for s in shots] == [act, win, home]
    assert [s["ref"]["sha256"] for s in shots] == [
        _sha("battery"),
        _sha("battery"),
        _sha("home"),
    ]
    assert befores[1]["ref"]["sha256"] == _sha("battery")  # #20
    assert befores[2]["ref"]["sha256"] == _sha("home")  # #23
    for s in shots:
        assert s["data"]["fallback"] is True
        assert s["data"]["stable"] is False
        assert s["data"]["source"] == "next_before_tap"
    assert back not in [s["ref"]["of"] for s in shots]  # superseded by home
    assert data["shots_dropped"] == {"superseded": 1}


def test_round5_invisible_63_old_screen_after_a_late_hash_is_unverified(env, cfg):
    """E2E round 5 #63 (of logcat #60, Notifications): the before-tap shot
    of #59 was late (dropped), the pre-change hash 607 ms late; the old
    references were transition frames only, so the shot stored the HOME
    image. R1: the cached frame at #59's finger-down (home) is the previous
    screen; a final frame equal to it is dropped ``unverified``.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "home", 42436.0)
        clocked = h.shot

        def late_before_tap(*, hash_only=False, timeout=5.0):
            res = clocked(hash_only=hash_only)
            if hash_only:
                return res
            h.shot = clocked  # the busy helper took it after the finger-up
            return ShotResult(res.t_mono_ms + 300.0, 1080, 2424, "trans", 14.0,
                              _frame_png("trans"), "/x")  # fmt: skip

        svc._shot_seen(h, hash_only=True)  # home, just before the tap
        h.shot = late_before_tap
        ge.feed(*tap_lines(stats["now"]()))  # #59
        assert wait_for(lambda: h.shot is clocked)
        time.sleep(0.4)  # the event came after that capture (device time)
        svc._screen_pre_lane.submit(time.sleep, 0.4)  # a late pre-change hash
        seq = svc._emit_screen("activity", pkg=SETTINGS, cls=SUB, title=None,
                               window_id=None, via="logcat",
                               dev_mono=stats["now"]())  # fmt: skip
        assert wait_for(lambda: svc._shot_drops.get("unverified") == 1, timeout=10.0)
        time.sleep(0.1)
        data = _stop_data(svc, lines)
    assert seq is not None
    assert not of(lines, "shot", "before_tap")  # late: dropped
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"unverified": 1}


def test_round5_invisible_66_like_previous_screen_is_unverified(env, cfg):
    """E2E round 5 #66 (of logcat #64, home after back): the shot stored the
    NOTIFICATIONS screen the back tap left (#65, before-tap). R1 drops a
    final frame equal to the before-tap frame (here: the same hash; in the
    E2E the scrollbar had faded, so the hashes differed).
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "notif", 42438.0)
        _tap_with_before_shot(ge, lines, stats["now"]())  # #62 back
        svc._screen_pre_lane.submit(time.sleep, 0.4)  # 727 ms late in the E2E
        svc._emit_screen("activity", pkg=SETTINGS, cls=SETTINGS + ".Settings",
                         title=None, window_id=None, via="logcat",
                         dev_mono=stats["now"]())  # fmt: skip
        h.frame = "fade"  # seen once
        time.sleep(0.25)
        h.frame = "notif"  # home has not drawn when the wait ends
        assert wait_for(lambda: svc._shot_drops.get("unverified") == 1, timeout=10.0)
        data = _stop_data(svc, lines)
    assert not of(lines, "shot", "screen_change")
    assert data["shots_dropped"] == {"unverified": 1}


#: Round-5 evidence (INVISIBLE), downscaled 4x to grayscale: #65 (the
#: before-tap of the back tap #62, Notifications), #66 (the shot of logcat
#: #64: the same Notifications screen, scrollbar faded, content 1 px off --
#: a different hash) and #55 (Battery, a different screen).
R1_FIXTURES = Path(__file__).parent / "fixtures" / "tracking_r1"
R1_PNGS = {
    "notif": "r5_65_notifications_before_tap.png",
    "notif-faded": "r5_66_notifications_scrollbar_faded.png",
    "battery": "r5_55_battery_before_tap.png",
}


def _r1_png(frame: str) -> bytes:
    return (R1_FIXTURES / R1_PNGS[frame]).read_bytes()


def test_r1_frame_distance_on_the_round5_evidence():
    """The perceptual R1 metric: #66 vs #65 is the same screen (the hash
    differs), Notifications vs Battery is not; undecodable frames are
    never "the same".
    """
    notif, faded, battery = (_r1_png(f) for f in R1_PNGS)
    assert notif != faded
    same = ts.frame_distance(notif, faded)
    other = ts.frame_distance(notif, battery)
    assert same is not None
    assert other is not None
    assert same < ts.SAME_MAX_DIFF / 5  # 0.08
    assert other > ts.SAME_MAX_DIFF * 5  # 10.3
    assert ts.frame_distance(faded, notif) == pytest.approx(same)
    assert ts.same_screen(notif, faded)
    assert not ts.same_screen(notif, battery)
    assert not ts.same_screen(notif, _frame_png("x"))  # not a PNG
    assert not ts.same_screen(notif, None)


@pytest.mark.parametrize(
    ("final", "stored"), [("notif-faded", False), ("battery", True)]
)
def test_r1_late_logcat_near_duplicate_of_the_before_tap_is_unverified(
    env, cfg, final, stored
):
    """E2E round 5 #66 as it happened: the final frame's hash differs from
    the before-tap #65 only because the scrollbar faded; perceptually it is
    the previous screen: dropped ``unverified`` (R4 shows the next
    before-tap). A final frame that differs (Battery) is stored.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=600)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "notif", 42438.0)
        clocked = h.shot

        def shot(*, hash_only=False, timeout=5.0):
            res = clocked(hash_only=hash_only, timeout=timeout)
            if hash_only:
                return res
            return ShotResult(res.t_mono_ms, 1080, 2424, res.hash, 14.0,
                              _r1_png(res.hash), "/x")  # fmt: skip

        h.shot = shot
        _tap_with_before_shot(ge, lines, stats["now"]())  # #62 back
        svc._screen_pre_lane.submit(time.sleep, 0.4)  # 727 ms late in the E2E
        svc._emit_screen("activity", pkg=SETTINGS, cls=SETTINGS + ".Settings",
                         title=None, window_id=None, via="logcat",
                         dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.1)
        h.frame = final
        if stored:
            assert wait_for(lambda: of(lines, "shot", "screen_change"), timeout=10.0)
        else:
            assert wait_for(
                lambda: svc._shot_drops.get("unverified") == 1, timeout=10.0
            )
        data = _stop_data(svc, lines)
    shots = of(lines, "shot", "screen_change")
    if stored:
        assert [s["ref"]["sha256"] for s in shots] == [
            hashlib.sha256(_r1_png("battery")).hexdigest()
        ]
        assert not data.get("shots_dropped")
    else:
        assert not shots
        assert data["shots_dropped"] == {"unverified": 1}


def test_r1_a_timely_a11y_frame_equal_to_the_before_tap_keeps_unchanged(env, cfg):
    """The one R1 exception: an a11y window line whose timely pre-change
    hash equals the final frame keeps ``data.unchanged``.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg, settle_max_ms=400)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        stats = _clocked_helper(helpers[0], "same", 500.0)
        _tap_with_before_shot(ge, lines, stats["now"]())
        svc._emit_screen("window", pkg="a", cls="a.B", title="B", window_id=1,
                         via="a11y", dev_mono=stats["now"]())  # fmt: skip
        assert wait_for(lambda: of(lines, "shot", "screen_change"))
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["data"]["unchanged"] is True
    assert not svc._shot_drops


def test_r2_a_fallback_followed_by_the_old_screen_before_the_tap_is_void(env, cfg):
    """R2 within the window: new frames (captured in full), then the
    previous screen again before the next tap (a transition of the old
    screen), and the next before-tap shows the previous screen: no
    fallback, dropped ``late``.
    """
    svc, popen, _run, helpers, _tmp = env
    _load_cfg(cfg)
    cfg.shot_before_tap = True
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg, mode="invisible")
        h = helpers[0]
        stats = _clocked_helper(h, "home", 300.0)
        _tap_with_before_shot(ge, lines, stats["now"]())
        svc._emit_screen("activity", pkg="a", cls="a.B", title=None, window_id=None,
                         via="logcat", dev_mono=stats["now"]())  # fmt: skip
        time.sleep(0.2)
        h.frame = _animation("fade-")  # never settles; captured in full
        time.sleep(0.5)
        h.frame = "home"
        time.sleep(0.4)
        _tap_with_before_shot(ge, lines, stats["now"]())
        assert wait_for(lambda: svc._shot_drops.get("late") == 1, timeout=10.0)
    assert not of(lines, "shot", "screen_change")


# --------------------------------------------------------------------------
# web elements (accessibility only), typed text, read-back, markers
# --------------------------------------------------------------------------

CHROME_BAR = "127.0.0.1:8097/index.html?c=1. Connection is not secure"
GECKO_BAR = " 127.0.0.1:8097/index.html?f=3. Search or enter address"


def _web_reply(node, *, pkg="com.android.chrome", bar=CHROME_BAR, hit=None,
               title="A11y Probe Page", frame=None, label=None):  # fmt: skip
    doc = {"title": title}
    if bar is not None:
        doc["bar"] = bar
    if frame:
        doc["frame"] = frame
    answer = {
        "window": {"id": 5, "type": "app"},
        "pkg": pkg,
        "hit": hit or dict(node),
        "target": node,
        "path": ["FrameLayout", "WebView", "Button"],
        "web_doc": doc,
    }
    if label:
        answer["label"] = label
    return {"type": "node_at", "cached": answer, "live": {"hit": None}}


def _web(role, **kw):
    return {"engine": kw.pop("engine", "chromium"), "role": role, **kw}


WEB_CASES = [  # (node, reply kw, summary, web fields)
    (
        {"cls": "android.widget.Button", "text": "Accept all", "rid": "accept-all",
         "clickable": True, "bounds": [404, 2181, 700, 2310], "web": _web("button")},
        {},
        "tap button 'Accept all' (#accept-all) on 127.0.0.1:8097",
        {"role": "button", "raw_role": "button", "html_id": "accept-all",
         "doc": "A11y Probe Page", "page": "127.0.0.1:8097"},
    ),
    (
        {"cls": "android.widget.Button", "text": "Class only", "clickable": True,
         "web": _web("button")},
        {},
        "tap button 'Class only' on 127.0.0.1:8097",
        {"html_id": None},
    ),
    (
        {"cls": "android.widget.Button", "desc": "Close dialog", "rid": "btn-icon",
         "clickable": True, "web": _web("button")},
        {},
        "tap button 'Close dialog' (#btn-icon) on 127.0.0.1:8097",
        {},
    ),
    (
        {"cls": "android.view.View", "desc": "External link", "rid": "lnk-ext",
         "clickable": True,
         "web": _web("link", role_desc="link", href="https://example.com/path?q=1")},
        {},
        "tap link 'External link' to example.com/path?q=1 (#lnk-ext) on 127.0.0.1:8097",
        {"role": "link", "href": "https://example.com/path?q=1"},
    ),
    (
        {"cls": "android.widget.EditText", "rid": "in-email", "editable": True,
         "clickable": True, "text": "me@x.org",
         "web": _web("textField", label="E-mail address", input_type=0xD1)},
        {},
        "tap text field 'E-mail address' (#in-email) on 127.0.0.1:8097",
        {"role": "text field", "field": "E-mail address", "input": "email"},
    ),
    (
        {"cls": "android.widget.EditText", "rid": "in-pass", "editable": True,
         "password": True, "web": _web("textField", label="Password", input_type=0xE1)},
        {},
        "tap password field 'Password' (#in-pass) on 127.0.0.1:8097",
        {"role": "password field", "input": "password"},
    ),
    (
        {"cls": "android.widget.CheckBox", "rid": "chk", "clickable": True,
         "web": _web("checkBox", label="I agree")},
        {},
        "tap check box 'I agree' (#chk) on 127.0.0.1:8097",
        {"role": "check box", "field": "I agree"},
    ),
    (
        {"cls": "android.view.View", "text": "Germany", "rid": "sel", "clickable": True,
         "web": _web("comboBoxSelect", role_desc="menu pop up button", label="Country")},
        {},
        "tap drop-down 'Country' (#sel) on 127.0.0.1:8097",
        {"role": "drop-down", "raw_role": "comboBoxSelect"},
    ),
    (
        {"cls": "android.widget.Button", "text": "Alle akzeptieren", "rid": "ensCancel",
         "clickable": True, "web": _web("pushbutton", engine="gecko")},
        {"pkg": "org.mozilla.firefox", "bar": " www.audi.de/de/. Search or enter address",
         "title": "Modelle, Aktionen, Angebote | Audi Deutschland"},
        "tap button 'Alle akzeptieren' (#ensCancel) on www.audi.de",
        {"engine": "gecko", "raw_role": "pushbutton", "page": "www.audi.de"},
    ),
    (
        {"cls": "android.widget.EditText", "rid": "in-text", "hint": "Your name",
         "editable": True, "web": _web("entry", engine="gecko", label="Your name",
                                       input_type=0xA1)},
        {"pkg": "org.mozilla.firefox", "bar": GECKO_BAR},
        "tap text field 'Your name' (#in-text) on 127.0.0.1:8097",
        {"input": "text"},  # 0xA1: TYPE_TEXT_VARIATION_WEB_EDIT_TEXT
    ),
    (
        {"cls": "android.widget.CheckBox", "text": "I agree", "rid": "chk",
         "checkable": True, "web": _web("checkbutton", engine="gecko")},
        {"pkg": "org.mozilla.firefox", "bar": GECKO_BAR},
        "tap check box 'I agree' (#chk) on 127.0.0.1:8097",
        {},
    ),
    (
        {"cls": "android.widget.TextView", "text": "Clickable div", "rid": "div-click",
         "web": _web("genericContainer")},
        {},
        "tap 'Clickable div' (#div-click) on 127.0.0.1:8097",
        {"role": None, "raw_role": "genericContainer"},
    ),
    (
        {"cls": "android.widget.Button", "text": "Frame button", "rid": "if-btn",
         "clickable": True, "web": _web("button")},
        {"frame": "Inner"},
        "tap button 'Frame button' (#if-btn) on 127.0.0.1:8097",
        {"doc": "A11y Probe Page"},
    ),
    (
        {"cls": "android.widget.Button", "text": "Plain button", "rid": "btn-plain",
         "clickable": True, "web": _web("button")},
        {"pkg": "sandroid.a11yprobe", "bar": None},
        "tap button 'Plain button' (#btn-plain) in page 'A11y Probe Page'",
        {"page": None, "doc": "A11y Probe Page"},
    ),
]  # fmt: skip


@pytest.mark.parametrize(("node", "kw", "summary", "fields"), WEB_CASES)
def test_a_tapped_web_element_is_named_in_plain_words(
    env, cfg, node, kw, summary, fields
):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        helpers[0].node_reply = _web_reply(node, **kw)
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
    tap = of(lines, "input", "tap")[0]
    assert tap["summary"] == summary
    web = tap["data"]["target"]["web"]
    assert set(web) == {"engine", "role", "raw_role", "html_id", "href", "field",
                        "input", "doc", "page"}  # fmt: skip
    for key, value in fields.items():
        assert web[key] == value, key
    if node.get("editable"):
        assert node.get("text", "") not in tap["summary"] or not node.get("text")
        assert tap["data"]["target"]["text"] is None  # a field's value never


def test_the_live_answer_names_a_web_element_the_snapshot_did_not_see(env, cfg):
    """Gecko builds the page lazily: the snapshot saw only the WebView."""
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    button = WEB_CASES[0][0]
    reply = _web_reply(button)
    live = reply["cached"]
    reply["cached"] = {"window": {"id": 5, "type": "app"}, "pkg": "com.android.chrome",
                       "hit": {"cls": "android.webkit.WebView", "web": _web("rootWebArea")},
                       "bare_web": True, "path": ["WebView"]}  # fmt: skip
    reply["live"] = live
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        helpers[0].node_reply = reply
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
    tap = of(lines, "input", "tap")[0]
    assert tap["summary"] == WEB_CASES[0][2]
    assert tap["data"]["target"]["source"] == "live"


def test_native_taps_keep_their_wording(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
    tap = of(lines, "input", "tap")[0]
    assert tap["summary"] == "tap 'Accept all' (Button)"
    assert "web" not in tap["data"]["target"]


@pytest.mark.parametrize(
    ("bar", "host"),
    [
        (CHROME_BAR, "127.0.0.1:8097"),
        (GECKO_BAR, "127.0.0.1:8097"),
        ("example.com. Connection is secure", "example.com"),
        ("https://www.audi.de/de/", "www.audi.de"),
        ("localhost:8080/x", "localhost:8080"),
        ("[::1]:8080/", "[::1]:8080"),
        ("Search or type URL", None),
        ("Search Google or type URL", None),
        ("", None),
        (None, None),
    ],
)
def test_page_host_keeps_only_the_leading_host(bar, host):
    assert ts.page_host(bar) == host


B = ts.BULLET


@pytest.mark.parametrize(
    ("events", "value", "partial"),
    [
        # Firefox, `input text Pw9x`: "9" was masked before it was seen
        ([("P", 0), (B, 0), (B, 0), (B + "w", 1), (B * 2, 1), (B * 2, 1),
          (B * 3 + "x", 2), (B * 4, 3), (B * 4, 3)], ["P", "w", None, "x"], True),
        ([("a", 0), (B, 0), (B + "b", 1), (B * 2, 1), (B * 2 + "c", 2), (B * 3, 2)],
         ["a", "b", "c"], False),
        # the previous character still in clear when the next one comes
        ([("x", 0), (B + "y", 1), (B * 2 + "a", 2), (B * 2 + "ab", 3)],
         ["x", "y", "a", "b"], False),
        # a backspace at the end, then one more character
        ([("a", 0), (B + "b", 1), (B * 2 + "c", 2), (B * 2, 2), (B * 2 + "d", 2)],
         ["a", "b", "d"], False),
        # Chrome and native fields send the clear text
        ([("P", 0), ("Pw9", 1), ("Pw9x", 3)], ["P", "w", "9", "x"], False),
        # a field that already held a password
        ([(B * 5 + "a", 5)], [None] * 5 + ["a"], True),
    ],
)  # fmt: skip
def test_a_bullet_password_is_rebuilt_keystroke_by_keystroke(events, value, partial):
    known: list = []
    part = False
    for text, frm in events:
        known, part = ts.rebuild_password(known, part, text, frm)
    assert known == value
    assert part is partial


def _pw_ev(t, text, frm):
    d = _text_ev(t, text, rid="in-pass")
    d["src"]["password"] = True
    d["src"]["text"] = B * len(text)
    d["from"] = frm
    d["pkg"] = "org.mozilla.firefox"
    return d


def test_firefox_password_bullets_give_the_typed_value(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        for i, (text, frm) in enumerate(
            [("h", 0), (B + "u", 1), (B * 2 + "n", 2), (B * 3 + "t", 3), (B * 4, 3)]
        ):
            helpers[0].on_event(_pw_ev(1000 + i, text, frm), time.time())
        svc.tick(time.time() + 10)
    line = of(lines, "input", "text")[0]
    assert line["summary"] == "typed \"hunt\" into password field 'Password'"
    assert line["data"]["text"] == "hunt"
    assert "partial" not in line["data"]
    assert timeline.mask(line)["summary"] == (
        "typed 4 chars into password field 'Password'"
    )


def test_a_password_read_only_partly_says_so(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    seq = [("P", 0), (B, 0), (B + "w", 1), (B * 2, 1), (B * 3 + "x", 2), (B * 4, 3)]
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        for i, (text, frm) in enumerate(seq):
            helpers[0].on_event(_pw_ev(1000 + i, text, frm), time.time())
        svc.tick(time.time() + 10)
    line = of(lines, "input", "text")[0]
    assert line["summary"] == (
        "typed 4 chars into password field 'Password' (partly read)"
    )
    assert line["data"]["partial"] is True
    assert line["data"]["text"] == f"Pw{B}x"


def test_text_events_of_non_editable_sources_are_dropped(env, cfg):
    """audi.de in Firefox: a document change came as TEXT_CHANGED of the
    WebView with U+FFFC ("typed 1 chars into 'WebView'").
    """
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        doc = {"type": "ev", "ev": "TEXT_CHANGED", "t_mono_ms": 10.0,
               "pkg": "org.mozilla.firefox", "cls": "android.webkit.WebView",
               "text": ts.OBJ_CHAR, "window_id": 3,
               "src": {"cls": "android.webkit.WebView", "text": "Audi"}}  # fmt: skip
        h.on_event(doc, time.time())
        # Dev3, Firefox navigating away: no source, only U+FFFC removed
        h.on_event({"type": "ev", "ev": "TEXT_CHANGED", "t_mono_ms": 15.0,
                    "pkg": "org.mozilla.firefox", "cls": "android.webkit.WebView",
                    "before": ts.OBJ_CHAR, "from": 0, "added": 0, "removed": 1,
                    "window_id": 52}, time.time())  # fmt: skip
        h.on_event({**_text_ev(16.0, ts.OBJ_CHAR, rid="com.x:id/q"),
                    "before": ""}, time.time())  # fmt: skip
        field = _text_ev(20.0, "ab" + ts.OBJ_CHAR, rid="com.x:id/q")
        h.on_event(field, time.time())
        svc.tick(time.time() + 10)
    texts = of(lines, "input", "text")
    assert len(texts) == 1
    assert texts[0]["data"]["text"] == "ab"
    assert texts[0]["summary"] == "typed \"ab\" into 'Password'"


def test_counts_are_singular_and_long_text_is_clipped(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    long = "x" * 100
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].on_event(_text_ev(1.0, long, rid="com.x:id/a"), time.time())
        helpers[0].on_event(_text_ev(2.0, "q", rid="com.x:id/b"), time.time())
        cfg.capture_text = False
        svc.tick(time.time() + 10)
    first, second = of(lines, "input", "text")
    assert first["summary"] == 'typed "' + "x" * 59 + "…\" into 'Password'"
    assert first["data"]["text"] == long
    assert second["summary"] == "typed 1 char into 'Password' (EditText)"


URL_BAR = {
    "cls": "android.widget.EditText", "rid": "com.android.chrome:id/url_bar",
    "text": "127.0.0.1:8097/index.html?c=1", "editable": True, "clickable": True,
    "focused": True, "bounds": [211, 142, 691, 289], "hint": "Search Google or type URL",
}  # fmt: skip
URL_REPLY = {
    "type": "node_at",
    "cached": {"window": {"id": 5, "type": "app"}, "pkg": "com.android.chrome",
               "hit": URL_BAR, "target": URL_BAR, "path": ["EditText#url_bar"]},
}  # fmt: skip


def _focus(text, *, rid="com.android.chrome:id/url_bar", **kw):
    node = {**URL_BAR, "rid": rid, "text": text, "window_id": 5,
            "pkg": "com.android.chrome", **kw}  # fmt: skip
    return {"type": "focus", "input": node}


def _key(t: float, code: int) -> list[str]:
    return [
        f"[{t:15.6f}] /dev/input/event0: 0001 {code:04x} 00000001",
        f"[{t:15.6f}] /dev/input/event0: 0000 0000 00000000",
        f"[{t + 0.03:15.6f}] /dev/input/event0: 0001 {code:04x} 00000000",
        f"[{t + 0.03:15.6f}] /dev/input/event0: 0000 0000 00000000",
    ]


def test_the_address_bar_is_read_back_once_typing_pauses(env, cfg):
    """Chrome's url_bar sends no TEXT_CHANGED: keyboard taps after a tap on
    it are read back (``focus``) and written as one line.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    cfg.text_idle_ms = 400
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.node_reply = IME_REPLY
        h.focus_reply = _focus("audi.de")
        for i in range(3):
            ge.feed(*tap_lines(2.0 + i * 0.2))
        assert wait_for(lambda: of(lines, "input", "text"))
        # read 300 ms after the last keystroke, not at once
        assert h.focus_calls
    line = of(lines, "input", "text")[0]
    assert line["summary"] == 'typed "audi.de" into the address bar'
    assert line["data"]["via"] == "readback"
    assert line["data"]["edits"] == 3
    assert line["data"]["text"] == "audi.de"
    assert line["dev_mono"] == 2.0  # the first keystroke
    assert h.focus_calls[0] == (451, 215)  # the tapped field's centre
    assert len(of(lines, "input", "text")) == 1


def test_a_field_that_reports_its_text_is_never_read_back(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    cfg.text_idle_ms = 300
    field = {**URL_BAR, "rid": "com.x:id/q", "text": ""}
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = {**URL_REPLY, "cached": {**URL_REPLY["cached"], "target": field,
                                                "hit": field}}  # fmt: skip
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.node_reply = IME_REPLY
        h.focus_reply = _focus("hi", rid="com.x:id/q")
        ge.feed(*tap_lines(2.0))
        assert wait_for(lambda: len(of(lines, "input", "tap")) == 2)
        h.on_event(_text_ev(2100.0, "h", rid="com.x:id/q"), time.time())
        ge.feed(*tap_lines(2.3))
        assert wait_for(lambda: len(of(lines, "input", "tap")) == 3)
        h.on_event(_text_ev(2400.0, "hi", rid="com.x:id/q"), time.time())
        assert wait_for(lambda: of(lines, "input", "text"))
        # a pause longer than READBACK_TEXT_GRACE_S, then a keyboard key
        # that changes no text (Shift, ?123, Go): its read-back reads "hi"
        svc._last_text_host -= 5.0
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: len(of(lines, "input", "tap")) == 4)
        svc.tick(time.time() + 10)  # any read-back would be due now
        svc._rb_lane.drain(2.0)
        svc.tick(time.time() + 20)
        svc._rb_lane.drain(2.0)
    assert h.focus_calls  # it was read ...
    texts = of(lines, "input", "text")
    assert [t["data"]["via"] for t in texts] == ["a11y"]  # ... and not written


def test_enter_writes_the_read_back_line_before_its_key_line(env, cfg):
    """Keys typed on a keyboard device, ENTER right behind the last one:
    the read happens at ENTER, the text line comes before ``key ENTER``.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.focus_reply = _focus("ab")
        ge.feed(*_key(2.0, 30), *_key(2.05, 48), *_key(2.1, 28))  # a, b, ENTER
        assert wait_for(lambda: of(lines, "input", "key"))
    text = of(lines, "input", "text")
    key = of(lines, "input", "key")[0]
    assert key["data"]["name"] == "ENTER"
    assert len(text) == 1
    assert text[0]["seq"] < key["seq"]
    assert text[0]["summary"] == 'typed "ab" into the address bar'
    assert text[0]["data"]["edits"] == 2


def test_an_unchanged_field_writes_no_read_back_line(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.focus_reply = _focus(URL_BAR["text"])
        ge.feed(*_key(2.0, 30), *_key(2.1, 28))
        assert wait_for(lambda: of(lines, "input", "key"))
    assert not of(lines, "input", "text")


def _real_png(w: int = 108, h: int = 242, colour: str = "#ffffff") -> bytes:
    import io

    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (w, h), colour).save(out, "PNG")
    return out.getvalue()


def test_marked_copies_keep_the_original_as_evidence(env, cfg):
    svc, popen, _run, helpers, tmp = env
    cfg.mark_screenshots = True
    png = _real_png()
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.shots = [ShotResult(500.0, 108, 242, "h-before", 14.0, png, "/x")]
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))
    shot = of(lines, "shot", "before_tap")[0]
    assert shot["ref"]["sha256"] == hashlib.sha256(png).hexdigest()
    assert (
        tmp / shot["ref"]["path"].replace("{seq}", str(shot["seq"]))
    ).read_bytes() == png
    marked = shot["data"]["marked"]
    assert marked["path"].startswith("tracking/shots/")
    assert marked["path"].endswith("_before_tap_marked.png")
    data = (tmp / marked["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == marked["sha256"]
    assert data != png


def test_screenshot_markers_are_on_by_default():
    """The user's choice (2026-11-20): marked copies by default."""
    assert TrackingConfig().mark_screenshots is True


def test_no_marked_copy_while_the_setting_is_off(env, cfg):
    svc, popen, _run, helpers, tmp = env
    cfg.mark_screenshots = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        helpers[0].shots = [ShotResult(500.0, 108, 242, "h", 14.0, _real_png(), "/x")]
        ge.feed(*tap_lines(5.0))
        assert wait_for(lambda: of(lines, "shot", "before_tap"))
    assert "marked" not in of(lines, "shot", "before_tap")[0]["data"]
    assert not list((tmp / "tracking/shots").glob("*_marked.png"))


def test_a_screen_change_after_typing_is_marked_with_the_field(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.mark_screenshots = True
    cfg.shot_before_tap = False
    with timeline.capture():
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        h.focus_reply = _focus("audi.de")
        ge.feed(*_key(2.0, 30), *_key(2.5, 28))
        assert wait_for(lambda: len(svc._marks) == 2)
    req = {"ev_dev": 2.6, "t_evt": time.time()}
    mark = svc._screen_mark(req)
    assert mark["kind"] == "text"
    assert mark["text"] == "audi.de"
    assert mark["bounds"] == URL_BAR["bounds"]


def test_marker_colours_are_the_lens_independent_highlight_slots():
    from sandroid.core import frames
    from sandroid.tui.themes import HIGHLIGHT_DARK

    assert {frames.MARK_TAP, frames.MARK_LONG_PRESS, frames.MARK_SWIPE,
            frames.MARK_TEXT} == set(HIGHLIGHT_DARK)  # fmt: skip


@pytest.mark.parametrize(
    ("mark", "probe"),
    [
        ({"kind": "tap", "xy": [540, 1200], "bounds": [400, 1100, 700, 1300]},
         (540 + 34, 1200)),  # on the ring (radius 9 units of 4 px)
        ({"kind": "long_press", "xy": [540, 1200]}, (540 + 55, 1200)),
        ({"kind": "swipe", "xy": [540, 2000],
          "path": [[540, 2000, 0], [540, 1500, 50], [540, 900, 120]]},
         (540, 1500)),
        ({"kind": "text", "bounds": [100, 1000, 900, 1150], "text": "hunter22"},
         (100, 1075)),
    ],
)  # fmt: skip
def test_mark_shot_draws_the_input_on_a_copy(mark, probe):
    import io

    from PIL import Image

    from sandroid.core import frames

    png = _real_png(1080, 2424)
    out = frames.mark_shot(png, {**mark, "screen": [1080, 2424]})
    assert out is not None
    assert out != png
    with Image.open(io.BytesIO(out)) as im:
        assert im.size == (1080, 2424)
        px = im.convert("RGB").getpixel(probe)
    assert px != (255, 255, 255)
    with Image.open(io.BytesIO(png)) as im:  # the original is untouched
        assert im.convert("RGB").getpixel(probe) == (255, 255, 255)


def test_mark_shot_scales_to_the_image_and_refuses_nothing_to_draw():
    import io

    from PIL import Image

    from sandroid.core import frames

    png = _real_png(540, 1212)  # a half-size capture of a 1080 x 2424 screen
    out = frames.mark_shot(
        png, {"kind": "tap", "xy": [540, 1200], "bounds": [400, 1100, 700, 1300],
              "screen": [1080, 2424]}
    )  # fmt: skip
    with Image.open(io.BytesIO(out)) as im:
        assert im.convert("RGB").getpixel((200, 575)) != (255, 255, 255)  # box edge
    assert frames.mark_shot(png, {"kind": "tap", "screen": [1080, 2424]}) is None
    assert frames.mark_shot(b"not a png", {"kind": "tap", "xy": [1, 1]}) is None


@pytest.mark.parametrize(
    ("cached", "live", "better"),
    [
        # Gecko had not built the page: the snapshot saw the WebView only
        ({"hit": {"cls": "android.webkit.WebView"}, "bare_web": True},
         {"hit": {"cls": "android.widget.Button", "web": _web("button")}}, True),
        # an outdated snapshot without the page tree (keyboard moving)
        ({"hit": {"cls": "android.widget.FrameLayout"},
          "snapshot": {"changes_since_start": 6}},
         {"hit": {"web": _web("textField")}, "target": {"web": _web("textField")}},
         True),
        # ... but an accurate one (no change since) wins
        ({"hit": {"cls": "android.widget.FrameLayout"},
          "snapshot": {"changes_since_start": 0}},
         {"hit": {"web": _web("textField")}}, False),
        # an outdated toolbar without its url_bar
        ({"hit": {"rid": "toolbar"}, "target": {"rid": "toolbar", "clickable": True,
                                                  "bounds": [0, 142, 1080, 289]},
          "snapshot": {"changes_since_start": 3, "truncated": True}},
         {"hit": URL_BAR, "target": URL_BAR}, True),
        # a native button the snapshot saw: the screen behind it is not it
        ({"hit": {"text": "OK"}, "target": {"text": "OK", "clickable": True},
          "snapshot": {"changes_since_start": 2}},
         {"hit": {"web": _web("button")}, "target": {"web": _web("button")}}, False),
        ({"hit": {"cls": "x"}, "snapshot": {"changes_since_start": 2}},
         {"hit": {"cls": "android.webkit.WebView"}, "bare_web": True}, False),
    ],
)  # fmt: skip
def test_the_live_answer_wins_only_where_the_snapshot_was_blind(cached, live, better):
    assert ts.TrackingService._live_is_better(cached, live) is better


def test_the_keyboard_taking_focus_keeps_the_field_and_its_text(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.on_event(_text_ev(1.0, "h", rid="com.x:id/q", password=True), time.time())
        h.on_event({"type": "ev", "ev": "FOCUSED", "pkg":
                    "com.google.android.inputmethod.latin"}, time.time())  # fmt: skip
        assert svc._pw_focus is True
        h.on_event(_text_ev(2.0, "hi", rid="com.x:id/q", password=True), time.time())
        svc.tick(time.time() + 10)
    texts = of(lines, "input", "text")
    assert len(texts) == 1
    assert texts[0]["data"]["text"] == "hi"


# --------------------------------------------------------------------------
# review findings (2026-11-20)
# --------------------------------------------------------------------------


def test_input_type_words_follow_android():
    assert ts._input_word(0x01) == "text"
    assert ts._input_word(0xA1) == "text"  # WEB_EDIT_TEXT
    assert ts._input_word(0xB1) == "filter"
    assert ts._input_word(0xC1) == "text"  # PHONETIC
    assert ts._input_word(0xD1) == "email"
    assert ts._input_word(0xE1) == "password"
    assert ts._input_word(0x12) == "password"  # NUMBER_VARIATION_PASSWORD
    assert ts._input_word(0x03) == "phone"


def test_a_text_mark_holds_no_text_while_capture_text_is_off(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.mark_screenshots = True
    cfg.capture_text = False
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        h.focus_reply = _focus("secret-typed")
        ge.feed(*_key(2.0, 30), *_key(2.5, 28))
        assert wait_for(lambda: len(svc._marks) == 2)
    assert "text" not in of(lines, "input", "text")[0]["data"]
    mark = svc._screen_mark({"ev_dev": 2.6, "t_evt": time.time()})
    assert mark["kind"] == "text"
    assert not mark["text"]


@pytest.mark.parametrize("shape", [{"password": True}, {"sensitive": True}])
def test_a_sensitive_field_marks_its_shot_sensitive_and_draws_no_text(env, cfg, shape):
    """Password (or data-sensitive) typing, Go, then the focus moves on
    (``_pw_focus`` is off again by the time the screen-change shot is
    stored): the shot line is still sensitive and its marked copy shows the
    field's box only.
    """
    svc, popen, _run, helpers, tmp = env
    cfg.mark_screenshots = True
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        ev = _text_ev(1500.0, "hunter22", **shape)
        ev["src"]["bounds"] = [100, 1000, 900, 1150]
        h.on_event(ev, time.time())
        ge.feed(*_key(2.0, 28))  # Go
        assert wait_for(lambda: of(lines, "input", "key"))
        h.on_event({"type": "ev", "ev": "FOCUSED", "pkg": "com.x",
                    "src": {"rid": "com.x:id/next"}}, time.time())  # fmt: skip
        assert svc._pw_focus is False
        assert wait_for(lambda: len(svc._marks) == 1)
        mark = svc._screen_mark({"ev_dev": 2.6, "t_evt": time.time()})
        assert mark["sensitive"] is True
        assert mark["text"] == ""
        svc._store("screen_change", _real_png(1080, 2424), of=1, via="helper",
                   w=1080, h=2424, cap_ms=1.0, dev_mono=None, t=None,
                   mark=mark)  # fmt: skip
    shot = of(lines, "shot", "screen_change")[0]
    assert shot["sensitive"] is True
    assert shot["data"]["marked"]["path"].endswith("_screen_change_marked.png")
    assert "marked" not in timeline.mask(shot)["data"]  # only its key name


def test_stop_reads_the_watched_field_before_the_helper_goes(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = URL_REPLY
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.focus_reply = _focus("a")
        svc._tick_stop.set()  # no 300 ms read: only the stop reads it
        ge.feed(*_key(2.0, 30))
        assert wait_for(lambda: svc._rb is not None and svc._rb["keys"] == 1)
        assert not h.focus_calls
        svc.stop()
    texts = of(lines, "input", "text")
    assert [t["summary"] for t in texts] == ['typed "a" into the address bar']
    stop = of(lines, "tracking", "stop")[0]
    assert texts[0]["seq"] < stop["seq"]


def test_a_moved_compose_field_without_id_is_still_read_back(env, cfg):
    """A rid-less (Compose) field the keyboard panned 100 px up: same class,
    overlapping columns; its hint differs (or is gone) once focused.
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    cfg.text_idle_ms = 400
    field = {**URL_BAR, "rid": None, "text": "", "pkg": "com.x"}
    reply = {"type": "node_at", "cached": {"window": {"id": 5, "type": "app"},
             "pkg": "com.x", "hit": field, "target": field, "path": ["x"]}}  # fmt: skip
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = reply
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.node_reply = IME_REPLY
        h.focus_reply = _focus("hello", rid=None, hint=None, pkg="com.x",
                               bounds=[211, 42, 691, 189])  # fmt: skip
        for i in range(3):
            ge.feed(*tap_lines(2.0 + i * 0.2))
        assert wait_for(lambda: of(lines, "input", "text"))
    line = of(lines, "input", "text")[0]
    assert line["summary"].startswith('typed "hello" into ')
    assert line["data"]["via"] == "readback"


def test_a_weak_read_never_replaces_a_good_value_with_less():
    pizza = {"rid": "com.x:id/q", "cls": "android.widget.EditText"}
    other = {"rid": "com.x:id/other", "cls": "android.widget.EditText"}
    good = ("pizza", pizza, 5)
    pick = ts.TrackingService._rb_pick
    assert pick(good, ("", pizza, 6)) is good  # emptied after Search
    assert pick(good, ("x", other, 6)) is good  # another field at the point
    assert pick(good, ("pizzas", pizza, 6))[0] == "pizzas"  # kept its text
    assert pick(None, ("", pizza, 1))[0] == ""


def test_a_flush_in_flight_writes_its_line_when_a_new_field_is_armed(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        g = ts.Gesture(dev="-", t_down=1.0, line_a=1, t_up=1.05)
        svc._rb_arm(URL_BAR, URL_REPLY["cached"], g)
        first = svc._rb
        svc._rb_key(ts.Gesture(dev="-", t_down=2.0, line_a=2, t_up=2.05))
        node = _focus("audi.de")["input"]
        first["good"] = ("audi.de", node, 1)
        first["read_keys"] = 1
        other = {**URL_BAR, "rid": "com.x:id/q", "text": ""}
        svc._rb_arm(other, URL_REPLY["cached"], g)  # the tap that ended it
        assert svc._rb is not first
        svc._rb_flush(first)
        svc._rb_flush(first)  # once only
    texts = of(lines, "input", "text")
    assert [t["summary"] for t in texts] == ['typed "audi.de" into the address bar']
    assert svc._rb is not None  # the new watch is untouched


# --------------------------------------------------------------------------
# an outdated snapshot is re-read live (Firefox's suggestion list)
# --------------------------------------------------------------------------


def _row(label, t_snap=9_000.0, **snap):
    """A ``cached`` answer on a suggestion row, from a snapshot taken at
    ``t_snap`` (device ms).
    """
    return {
        "window": {"id": 10, "type": "app"},
        "pkg": "org.mozilla.firefox",
        "hit": {"cls": "android.widget.TextView", "text": label},
        "target": {"rid": "mozac.awesomebar.suggestion", "cls": "android.view.View",
                   "bounds": [0, 415, 1080, 541], "clickable": True},
        "path": ["View#mozac.awesomebar.suggestion", "TextView"],
        "label": label,
        "snapshot": {"start_ms": t_snap, "end_ms": t_snap + 3,
                     "changes_since_start": 0, **snap},
    }  # fmt: skip


_KEY = {
    "type": "node_at",
    "cached": {"window": {"id": 1, "type": "ime"}, "pkg": "com.google.android.inputmethod.latin",
               "hit": {"cls": "android.widget.FrameLayout"}, "path": ["FrameLayout"]},
}  # fmt: skip


def _typed_then_tapped(env, cfg, reply, *, fresh=None, events=(), key=True):
    """A keyboard tap at 10 s (unless not ``key``), helper ``events``,
    then a tap at 15 s answered by ``reply`` (and the re-read ``fresh``).
    """
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        if key:
            helpers[0].node_reply = _KEY
            ge.feed(*tap_lines(10.0, y=0x7000))
            assert wait_for(lambda: of(lines, "input", "tap"))
        for ev in events:
            helpers[0].on_event(ev, time.time())
        helpers[0].node_reply = reply
        helpers[0].fresh_reply = fresh
        ge.feed(*tap_lines(15.0))
        assert wait_for(lambda: len(of(lines, "input", "tap")) == (2 if key else 1))
    return of(lines, "input", "tap")[-1], helpers[0]


def test_typing_after_the_snapshot_reads_the_tapped_row_live(env, cfg):
    reply = {"type": "node_at", "cached": _row("spi"), "live": _row("spi")}
    fresh = {**_row("spiegel.de"), "t_start_ms": 15_010.0}
    fresh.pop("snapshot")
    tap, helper = _typed_then_tapped(env, cfg, reply, fresh=fresh)
    assert tap["summary"] == "tap 'spiegel.de' (View)"
    target = tap["data"]["target"]
    assert target["source"] == "live"
    assert target["source_why"] == "you typed after the snapshot"
    assert "stale_possible" not in target
    # you typed: the cache was dropped right ahead of the lookup, no
    # second round trip (it would come after a quick tap's finger-up)
    assert len(helper.first_clears) == 1
    assert helper.fresh_calls == []


def test_a_window_change_after_the_snapshot_reads_it_live(env, cfg):
    reply = {"type": "node_at", "cached": _row("googee test"), "live": None}
    fresh = {**_row("spiegel.de"), "t_start_ms": 15_010.0}
    ev = {"type": "ev", "ev": "WINDOW_CONTENT_CHANGED", "window_id": 10,
          "t_mono_ms": 12_000.0}  # fmt: skip
    tap, _helper = _typed_then_tapped(env, cfg, reply, fresh=fresh, events=[ev],
                                      key=False)  # fmt: skip
    assert tap["data"]["target"]["source"] == "live"
    assert (
        tap["data"]["target"]["source_why"] == "its window changed after the snapshot"
    )
    assert tap["summary"] == "tap 'spiegel.de' (View)"


def test_an_up_to_date_snapshot_is_not_read_again(env, cfg):
    reply = {"type": "node_at", "cached": _row("spiegel.de", t_snap=12_000.0)}
    tap, helper = _typed_then_tapped(env, cfg, reply, fresh=_row("other"))
    assert tap["data"]["target"]["source"] == "cached"
    assert "source_why" not in tap["data"]["target"]
    assert helper.fresh_calls == []
    assert len(helper.first_clears) == 1  # you typed: read fresh anyway


@pytest.mark.parametrize(
    "fresh",
    [
        {"hit": None},  # the live re-read found nothing
        # a re-read that started after the finger was up is no better
        {**_row("spiegel.de"), "t_start_ms": 15_500.0},
    ],
)
def test_no_live_re_read_marks_the_target_stale_possible(env, cfg, fresh):
    reply = {"type": "node_at", "cached": _row("spi"), "live": {"hit": None}}
    tap, _helper = _typed_then_tapped(env, cfg, reply, fresh=fresh)
    target = tap["data"]["target"]
    assert target["source"] == "cached"
    assert target["stale_possible"] is True
    assert target["source_why"] == "you typed after the snapshot"
    assert tap["summary"] == "tap 'spi' (View)"


@pytest.mark.parametrize(
    ("snap", "window", "why"),
    [
        ({"changes_since_start": 2}, {}, "the screen changed after the snapshot"),
        ({"truncated": True}, {}, "the snapshot was cut short"),
        ({}, {"dialog_like": True}, "a popup window"),
        ({}, {"type": "ime"}, ""),
        ({}, {}, ""),
    ],
)
def test_stale_reasons(env, snap, window, why):
    svc = env[0]
    cached = _row("x", **snap)
    cached["window"] = {**cached["window"], **window}
    assert svc._stale_why(cached) == why


def test_an_inline_autocomplete_is_kept_apart_from_what_you_typed(env, cfg):
    svc, popen, _run, helpers, _tmp = env
    cfg.shot_before_tap = False
    cfg.text_idle_ms = 400
    empty = {**URL_BAR, "text": "", "showing_hint": True}
    reply = {**URL_REPLY, "cached": {**URL_REPLY["cached"], "hit": empty,
                                     "target": empty}}  # fmt: skip
    with timeline.capture() as lines:
        ge = start(svc, popen, helpers, cfg)
        h = helpers[0]
        h.node_reply = reply
        ge.feed(*tap_lines(1.0))
        assert wait_for(lambda: of(lines, "input", "tap"))
        h.node_reply = IME_REPLY
        h.focus_reply = _focus("wdr.de/")
        for i in range(6):
            ge.feed(*tap_lines(2.0 + i * 0.2))
        assert wait_for(lambda: of(lines, "input", "text"))
    line = of(lines, "input", "text")[0]
    assert line["data"]["text"] == "wdr.de"
    assert line["data"]["autocomplete"] == "/"
    assert line["summary"] == 'typed "wdr.de" into the address bar'


@pytest.mark.parametrize(
    ("value", "initial", "keys", "node", "n"),
    [
        ("wdr.de/", "", 6, {"rid": "url_bar"}, 6),
        ("wdr.de", "", 6, {"rid": "url_bar"}, None),  # nothing added
        ("wdr.de/", "", 9, {"rid": "url_bar"}, None),  # more keys than chars
        # unknown start: an address bar selects its text when tapped
        ("wdr.de/", None, 6, {"rid": "url_bar"}, 6),
        ("abc.de", "old", 1, {"rid": "url_bar"}, None),  # replaced: unknown
        # a suggestion or glide put a word in with one keystroke: no split
        ("spiegel ", "", 3, {"rid": "url_bar"}, None),
        ("spieg", "", 1, {"rid": "url_bar"}, None),
        ("wdr.de/", "", 6, {"rid": "com.x:id/q"}, None),  # not an address bar
        ("wdr.de/", "", 6, {"rid": "url_bar", "password": True}, None),
        # the field's selection tells, in any field
        ("spiegel.de/", "", 20, {"rid": "q", "sel_start": 7, "sel_end": 11}, 7),
        ("spiegel.de", "", 3, {"rid": "url_bar", "sel_start": 10, "sel_end": 10},
         None),
    ],
)  # fmt: skip
def test_typed_part(value, initial, keys, node, n):
    assert ts.typed_part(value, initial, keys, node) == n
