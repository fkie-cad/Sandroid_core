"""Tracking v1 (WP4): getevent decoding, input/text/screen/shot/tracking lines,
the shared getevent reader with Record, the player formats and net flows.

No device: getevent/logcat are fake processes fed from fixtures, the UI helper
is a fake, and every line is collected with ``timeline.capture()``.
"""

from __future__ import annotations

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
        self.node_delay = 0.0
        self.node_calls: list[tuple] = []
        self.shots: list[ShotResult] = []
        self.hashes: list[str] = []
        self.shot_calls = 0
        self.shot_t_ms = 500.0
        self.last_error = None
        self.start_ok = True
        self.stopped = False

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

    def node_at(self, x, y, *, t_mono_ms=None, timeout=1.0):
        self.node_calls.append((x, y, t_mono_ms))
        if self.node_delay:
            time.sleep(self.node_delay)
        return self.node_reply

    def shot(self, *, hash_only=False, timeout=5.0):
        self.shot_calls += 1
        if hash_only:
            h = self.hashes.pop(0) if self.hashes else "h-final"
            return ShotResult(1.0, 1080, 2424, h, 3.0, None, None)
        if self.shots:
            return self.shots.pop(0)
        # captured before the taps of the tests (a later capture is "late")
        return ShotResult(self.shot_t_ms, 1080, 2424, "h-before", 14.0, PNG_A, "/x")


def wait_for(cond, timeout: float = 3.0) -> bool:
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
        helpers[0].node_delay = 1.0
        t0 = time.monotonic()
        ge.feed(*tap_lines(10.0))
        assert wait_for(lambda: of(lines, "input"))
        took = time.monotonic() - t0
    tap = of(lines, "input", "tap")[0]
    assert tap["data"]["target"] is None
    assert tap["data"]["node_timeout"] is True
    assert tap["summary"].startswith("tap at ")
    assert took < 0.9  # never waits for the slow node_at


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
        "src": {"rid": rid, "cls": "android.widget.EditText", "hint": "Password"},
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
    assert texts[0]["summary"] == "typed 5 chars into 'Password' (EditText)"


@pytest.mark.parametrize(
    "shape",
    [
        {"password": True},
        {"sensitive": True},
        {"password": True, "sensitive": True},
    ],
)
def test_sensitive_text_never_reaches_the_summary(env, cfg, shape):
    svc, popen, _run, helpers, _tmp = env
    secret = "hunter22-Secret"  # noqa: S105 - a typed test value
    with timeline.capture() as lines:
        start(svc, popen, helpers, cfg)
        helpers[0].on_event(_text_ev(5000, secret, **shape), time.time())
        svc.tick(time.time() + 10)  # idle flush
    line = of(lines, "input", "text")[0]
    assert line["sensitive"] is True
    assert secret not in line["summary"]
    assert "hunter" not in line["summary"]
    assert line["data"]["text"] == secret  # raw, masked by readers
    masked = timeline.mask(line)
    assert secret not in json.dumps(masked)
    if shape.get("password"):
        assert line["summary"].endswith("(EditText, password)")


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
    assert windows[0]["summary"] == "→ com.x/.LoginActivity · Sign in"
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
    real = src.poll
    monkeypatch.setattr(
        src, "poll", lambda: polled.append(threading.current_thread().name) or real()
    )
    src.start()
    try:
        t0 = time.monotonic()
        for _ in range(20):  # a burst of doorbells is debounced
            src.on_line("[FLOW]|12:00:00|HTTPS|200|GET|x/|1 KB|app")
        src.on_line("[INFO] not a flow")
        assert time.monotonic() - t0 < 0.05
        assert wait_for(lambda: polled)
        time.sleep(0.2)
    finally:
        src.stop()
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
    src = Path(__file__).resolve().parents[2] / "src"
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

    def slow_kill(self, argv, timeout=10.0):
        if "kill" in " ".join(argv):
            time.sleep(1.0)
        return real(self, argv, timeout)

    monkeypatch.setattr(FakeRun, "__call__", slow_kill)
    s = svc.getevent(SERIAL)
    s.release()  # the teardown takes 1 s
    with timeline.capture():
        t = threading.Thread(target=svc.start, args=(SERIAL,))
        t.start()
        time.sleep(0.1)
        t0 = time.monotonic()
        svc.state()
        took = time.monotonic() - t0
        t.join(3.0)
    assert took < 0.2
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
