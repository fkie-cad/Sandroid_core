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
        return ShotResult(81_234_000.0, 1080, 2424, "h-before", 14.0, PNG_A, "/x")


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
    assert first["dev_mono"] == 81234.0
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
    rec.stop()
    ge.feed(*tap_lines(4.0))  # after the stop: not in the recording
    out = (tmp / "raw/recording.getevent.txt").read_text().splitlines()
    assert out == tap_lines(2.0) + tap_lines(3.0)
    assert rec.event_count == 12
    assert counts[-1] == 12
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


# --------------------------------------------------------------------------
# the interval screenshot is gone
# --------------------------------------------------------------------------


def test_interval_screenshot_feature_is_gone():
    src = Path(__file__).resolve().parents[2] / "src"
    out = subprocess.run(
        [
            "grep",
            "-rn",
            r"screenshot_interval\|features.screenshot\|StartScreenshotStep",
            str(src),
        ],
        capture_output=True,
        text=True,
    )
    assert out.stdout == ""
