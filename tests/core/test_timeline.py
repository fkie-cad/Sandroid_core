"""The session timeline (``core/timeline.py``): envelope, chain, writer,
policy, labels, resume, lock, readers, CLI and the quit order.

No device: device-clock epochs are fed directly; files live in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core import device_clock, timeline
from sandroid.core.timeline import TimelineService

ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")
SERIAL = "emulator-test"


@pytest.fixture(autouse=True)
def _clean_clock():
    device_clock.reset()
    yield
    device_clock.reset()


def _lines(path: Path) -> list[dict]:
    return [json.loads(raw) for raw in path.read_bytes().split(b"\n")[:-1]]


def _kinds(lines: list[dict]) -> list[str]:
    return [f"{line['src']}/{line['kind']}" for line in lines]


def _service(folder: Path, serial: str = SERIAL) -> TimelineService:
    service = TimelineService()
    status = service.bind(serial, folder)
    assert status.state == "open", status
    return service


def _crash(service: TimelineService) -> None:
    """Simulate a killed process: everything written, no close line."""
    assert service.flush(5.0)
    with service._lock:
        service._closed = True
        service._stop = True
        sinks = list(service._sinks.values())
        for sink in sinks:
            sink.state = "closed"
    for sink in sinks:
        service._release(sink)
    service._kick.set()


# ---------------------------------------------------------------------------
# envelope and canonical form
# ---------------------------------------------------------------------------


def test_envelope_has_every_required_field():
    with timeline.capture() as lines:
        seq = timeline.emit(
            "input", "tap", summary="tap 'OK'", data={"x": 1}, pkg="com.x", pid=7
        )
    (line,) = lines
    assert line["seq"] == seq == 1
    for key in ("v", "seq", "t", "t_rx", "clk", "mono", "world", "epoch", "phase",
                "run", "src", "kind", "actor", "dev", "summary", "level", "h"):  # fmt: skip
        assert key in line, key
    assert line["v"] == 1
    assert ISO_MS.match(line["t"])
    assert ISO_MS.match(line["t_rx"])
    assert (line["clk"], line["phase"], line["run"]) == ("host", "live", None)
    assert (line["world"], line["epoch"]) == (0, 0)
    assert (line["actor"], line["level"]) == ("sandroid", "info")
    assert (line["pkg"], line["pid"]) == ("com.x", 7)
    assert "t_err_ms" not in line
    assert "sensitive" not in line
    assert re.fullmatch(r"[0-9a-f]{64}", line["h"])
    assert list(line)[-1] == "h"


def test_summary_and_data_caps():
    with timeline.capture() as lines:
        timeline.emit("input", "tap", summary="x" * 500, data={"blob": "y" * 20_000})
    (line,) = lines
    assert len(line["summary"]) == timeline.SUMMARY_MAX
    assert line["summary"].endswith("…")
    assert line["data"] == {"_truncated": True, "_bytes": line["data"]["_bytes"],
                            "keys": ["blob"]}  # fmt: skip
    assert line["data"]["_bytes"] > timeline.DATA_MAX
    assert line["level"] == "warn"


def test_canonical_escapes_line_separators_and_sanitises_surrogates():
    with timeline.capture() as lines:
        timeline.emit(
            "input", "text",
            summary="a\u2028b\u0085c\u2029d \ud800 e",
            data={"v": float("nan"), "when": datetime(2026, 1, 1, 12), "p": Path("/x"),
                  "tup": (1, 2)},
        )  # fmt: skip
    (line,) = lines
    body = timeline.canonical({k: v for k, v in line.items() if k != "h"})
    assert b"\\u2028" in body
    assert b"\\u0085" in body
    assert b"\\u2029" in body
    assert "\u2028".encode() not in body
    assert line["summary"].endswith("\ufffd e")
    assert line["data"]["v"] is None
    assert line["data"]["_nonfinite"] == ["v"]
    assert line["data"]["when"].startswith("2026-01-01T12:00:00.000")
    assert line["data"]["p"] == "/x"
    assert line["data"]["tup"] == [1, 2]


def test_invalid_src_or_kind_is_ignored():
    with timeline.capture() as lines:
        assert timeline.emit("Bad Src", "x", summary="") is None
        assert timeline.emit("input", "X!", summary="") is None
    assert lines == []


def test_seq_substitution_in_ref():
    with timeline.capture() as lines:
        seq = timeline.emit("shot", "manual", summary="shot",
                            ref={"path": "tracking/shots/{seq}_manual.png", "of": 3})  # fmt: skip
    assert lines[0]["ref"] == {"path": f"tracking/shots/{seq}_manual.png", "of": 3}


# ---------------------------------------------------------------------------
# the file, the chain, verify
# ---------------------------------------------------------------------------


def test_file_is_0600_and_verifies_byte_exactly(timeline_sink):
    service, path = timeline_sink
    service.emit("input", "tap", summary="tap", data={"t": "\u2028"})
    assert service.close("test", 3.0)
    assert path.stat().st_mode & 0o777 == 0o600
    assert (path.parent / timeline.LOCK_NAME).stat().st_mode & 0o777 == 0o600
    lines = _lines(path)
    assert _kinds(lines) == ["sandroid/open", "sandroid/policy", "device/connect",
                             "input/tap", "sandroid/close"]  # fmt: skip
    opened = lines[0]["data"]
    assert opened["session_id"] == "session/dev"
    assert opened["genesis"] == timeline.genesis("session/dev")
    assert lines[-1]["data"]["bytes"] == sum(
        len(r) + 1 for r in path.read_bytes().split(b"\n")[:-2]
    )
    result = timeline.verify_chain(path, strict=True)
    assert result.ok, result.errors
    assert (result.lines, result.first_seq, result.last_seq) == (5, 1, 5)
    assert result.session_id == "session/dev"


def _tamper_cases(path: Path) -> dict[str, tuple[bytes, int]]:
    """Name -> (tampered bytes, offset of the first bad line)."""
    raw = path.read_bytes()
    rows = raw.split(b"\n")[:-1]
    offsets = [0]
    for row in rows:
        offsets.append(offsets[-1] + len(row) + 1)
    k = 3  # input/tap
    cases = {}
    flipped = rows[k].replace(b'"tap"', b'"tip"', 1)
    cases["byte"] = (
        b"\n".join([*rows[:k], flipped, *rows[k + 1 :]]) + b"\n",
        offsets[k],
    )
    cases["delete"] = (b"\n".join([*rows[:k], *rows[k + 1 :]]) + b"\n", offsets[k])
    swapped = [*rows[:k], rows[k + 1], rows[k], *rows[k + 2 :]]
    cases["swap"] = (b"\n".join(swapped) + b"\n", offsets[k])
    dup = rows[k].replace(b'{"actor"', b'{"actor":"ai","actor"', 1)
    cases["dup key"] = (
        b"\n".join([*rows[:k], dup, *rows[k + 1 :]]) + b"\n",
        offsets[k],
    )
    cases["missing genesis"] = (b"\n".join(rows[1:]) + b"\n", 0)
    return cases


def test_verify_finds_each_tamper_at_its_offset(timeline_sink, tmp_path):
    service, path = timeline_sink
    service.emit("input", "tap", summary="tap 1")
    service.emit("input", "tap", summary="tap 2")
    assert service.close("test", 3.0)
    assert timeline.verify_chain(path).ok
    for name, (data, offset) in _tamper_cases(path).items():
        copy = tmp_path / f"{name.replace(' ', '_')}.jsonl"
        copy.write_bytes(data)
        result = timeline.verify_chain(copy)
        assert not result.ok, name
        assert result.errors[0].offset == offset, (name, result.errors)
        assert timeline.main(["verify", str(copy)]) == 1


def test_cli_exit_codes_and_commands(timeline_sink, tmp_path, capsys):
    service, path = timeline_sink
    service.labels.start("login", actor="user")
    service.emit("input", "text", summary="typed 6 chars", sensitive=True,
                 data={"text": "hunter"}, ref={"raw": "tracking/raw/x#L1"})  # fmt: skip
    assert service.close("test", 3.0)
    assert timeline.main(["verify", str(path)]) == 0
    assert timeline.main(["verify", str(path.parent), "--json"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out.strip().splitlines()[-1])["ok"] is True
    assert timeline.main(["seal", str(path), "--json"]) == 0
    seal = json.loads(capsys.readouterr().out)
    assert seal["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert timeline.main(["labels", str(path), "--json"]) == 0
    labels = json.loads(capsys.readouterr().out)
    assert [(x["kind"], x["number"], x["ended_by"]) for x in labels] == [
        ("start", 1, None), ("end", 1, "close")]  # fmt: skip
    assert timeline.main(["verify", str(tmp_path / "missing.jsonl")]) == 2


def test_cli_tail_masks_per_export_setting_unless_revealed(
    timeline_sink, monkeypatch, capsys
):
    from sandroid.config import get_config

    service, path = timeline_sink
    service.emit("input", "text", summary="typed 6 chars", sensitive=True,
                 data={"text": "hunter"})  # fmt: skip
    assert service.close("test", 3.0)
    monkeypatch.setattr(get_config().timeline, "mask_sensitive", True)
    assert timeline.main(["tail", str(path), "--json", "-n", "50"]) == 0
    assert "hunter" not in capsys.readouterr().out
    assert timeline.main(["tail", str(path), "--json", "--reveal"]) == 0
    assert "hunter" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# writer: non-blocking, ordered, drops
# ---------------------------------------------------------------------------


def test_emit_never_waits_for_a_writer_stalled_in_io(timeline_sink, monkeypatch):
    """The monitor reader thread calls emit: it must not wait on file I/O
    (trace_pipe overruns otherwise). The writer holds no lock while writing.
    """
    service, path = timeline_sink
    entered, release = threading.Event(), threading.Event()
    real_write = timeline._write

    def stalled(fd, data):
        entered.set()
        release.wait(10)
        return real_write(fd, data)

    monkeypatch.setattr(timeline, "_write", stalled)
    service.emit("input", "tap", summary="first")
    service._kick.set()
    assert entered.wait(5), "the writer never wrote"
    durations = []
    for i in range(200):
        start = time.perf_counter()
        service.file_event(op="FSE_CONTENT_MODIFIED", path=f"/data/data/com.x/f{i}",
                           t=time.time(), backend="kprobe", pid=1)  # fmt: skip
        service.emit("monitor", "lost", summary="x")
        durations.append(time.perf_counter() - start)
    assert max(durations) < 0.005
    assert statistics.median(durations) < 0.001
    release.set()
    assert service.flush(5.0)


def test_eight_threads_get_contiguous_seqs(timeline_sink):
    service, path = timeline_sink
    seqs: list[list[int]] = [[] for _ in range(8)]

    def worker(n: int) -> None:
        for i in range(10_000):
            seqs[n].append(service.emit("input", "tap", summary=f"{n}/{i}"))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    got = sorted(s for chunk in seqs for s in chunk)
    assert None not in got
    assert got == list(range(got[0], got[0] + 80_000))
    for chunk in seqs:
        assert chunk == sorted(chunk)  # per thread in order
    assert service.flush(30.0)
    written = [line["seq"] for line in _lines(path)]
    assert written == list(range(1, len(written) + 1))
    assert timeline.verify_chain(path).ok


def test_bulk_lines_drop_when_the_queue_is_full_must_keep_never(
    timeline_sink, monkeypatch
):
    service, path = timeline_sink
    service._policy.queue_max = 5
    service._policy.coalesce_s = 0
    entered, release = threading.Event(), threading.Event()
    real_write = timeline._write

    def stalled(fd, data):
        entered.set()
        release.wait(10)
        return real_write(fd, data)

    monkeypatch.setattr(timeline, "_write", stalled)
    service.emit("input", "tap", summary="wake the writer")
    service._kick.set()
    assert entered.wait(5)
    kept = [service.emit("monitor", "lost", summary=str(i)) for i in range(20)]
    assert sum(s is not None for s in kept) == 5
    must = [service.emit("input", "tap", summary=str(i)) for i in range(50)]
    assert None not in must
    # No seq was consumed by a dropped line: contiguous.
    seqs = sorted([s for s in kept if s is not None] + must)
    assert seqs == list(range(seqs[0], seqs[0] + 55))
    release.set()
    assert service.close("test", 5.0)
    lines = _lines(path)
    (dropped,) = [x for x in lines if x["src"] == "sandroid" and x["kind"] == "dropped"]
    assert dropped["level"] == "warn"
    assert dropped["data"]["by_src"] == {"monitor": 15}
    assert dropped["data"]["reason"] == {"queue-full": 15}
    assert dropped["data"]["queue_max"] == 5
    assert lines[-1]["data"]["dropped_total"] == 15
    assert timeline.verify_chain(path).ok


# ---------------------------------------------------------------------------
# policy, counts, coalescing, attrs
# ---------------------------------------------------------------------------


def _event(service, op, path, *, pid=1, app_pkg="com.app", t=None):
    return service.file_event(op=op, path=path, t=t or time.time(), backend="kprobe",
                              pid=pid, app_pkg=app_pkg, process="main")  # fmt: skip


def test_policy_off_count_and_always_on():
    policy = timeline.Policy({
        "sources": {"files": False, "clock": False}, "kinds_off": ["net.flow"],
        "count_only": ["monitor.*"], "files_attrs": "counts",
    })  # fmt: skip
    assert policy.decide("files", "modify") == "off"
    assert policy.decide("clock", "sample") == "keep"  # always on
    assert policy.decide("net", "flow") == "off"
    assert policy.decide("net", "tls-fail") == "keep"
    assert policy.decide("monitor", "lost") == "count"
    default = timeline.Policy({})
    assert default.decide("files", "attrs", in_app=True) == "keep"
    assert default.decide("files", "attrs") == "count"
    # The schema drops always-on sources from the switches.
    from sandroid.config.schema import TimelineConfig

    cfg = TimelineConfig(sources={"clock": False, "files": False},
                         kinds_off=["label.start", "files.*"])  # fmt: skip
    assert cfg.sources == {"files": False}
    assert cfg.kinds_off == ["files.*"]
    with pytest.raises(ValueError):
        TimelineConfig(count_only=["not a kind"])
    assert (
        timeline.ALWAYS_ON
        == __import__("sandroid.config.schema", fromlist=["x"]).TIMELINE_ALWAYS_ON
    )


def test_count_lines_come_before_every_boundary():
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        for _ in range(3):
            _event(service, "FSE_OPEN", "/data/data/com.app/a")
        _event(service, "FSE_CLOSE", "/data/data/com.app/a")
        assert lines == []
        service.labels.start("go")
    assert _kinds(lines) == ["files/count", "label/start"]
    count = lines[0]
    assert count["data"]["counts"] == {"open": 3, "close": 1}
    assert count["data"]["by_pkg"] == {"com.app": {"open": 3, "close": 1}}
    assert count["actor"] == "system"
    assert len(count["data"]["window"]) == 2


def test_modify_coalesces_per_path_and_pid_and_a_delete_flushes_first():
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        t0 = time.time()
        for i in range(4):
            _event(
                service, "FSE_CONTENT_MODIFIED", "/data/data/com.app/db", t=t0 + i / 10
            )
        _event(service, "FSE_CONTENT_MODIFIED", "/data/data/com.app/db", pid=2, t=t0)
        assert lines == []
        _event(service, "FSE_DELETE", "/data/data/com.app/db", t=t0 + 0.5)
    assert _kinds(lines) == ["files/modify", "files/modify", "files/delete"]
    first = next(x for x in lines if x.get("pid") == 1 and x["kind"] == "modify")
    assert first["data"]["n"] == 4
    assert first["t"] == first["data"]["first"]
    assert first["data"]["last"] > first["data"]["first"]
    assert first["summary"] == "MODIFY db · main ×4"
    assert first["actor"] == "app"


def test_coalescing_window_expires_and_zero_is_off():
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        _event(service, "FSE_CONTENT_MODIFIED", "/data/data/com.app/a")
        with service._lock:
            service._flush_coalescer(time.time() + 0.5)  # still open
        assert lines == []
        with service._lock:
            service._flush_coalescer(time.time() + 2)
        assert _kinds(lines) == ["files/modify"]
        service._policy.coalesce_s = 0
        _event(service, "FSE_CONTENT_MODIFIED", "/data/data/com.app/a")
    assert _kinds(lines) == ["files/modify", "files/modify"]
    assert "n" not in lines[1]["data"]


def test_attrs_are_lines_in_the_app_dirs_and_counted_elsewhere():
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        for path in ("/data/data/com.app/x", "/data/user_de/0/com.app/y",
                     "/sdcard/Android/data/com.app/z"):  # fmt: skip
            assert _event(service, "FSE_ATTRIB", path) is not None
        assert _event(service, "FSE_ATTRIB", "/data/data/other/x") is None
        assert (
            _event(service, "FSE_ATTRIB", "/data/data/com.app/x", app_pkg=None) is None
        )
        service.labels.point("p")
    assert _kinds(lines) == ["files/attrs"] * 3 + ["files/count", "label/point"]
    assert lines[3]["data"]["counts"] == {"attrs": 2}


def test_file_kinds_from_tokens_and_labels():
    assert timeline.file_kind("FSE_CREATE_DIR") == ("create", "CREATE DIR", True)
    assert timeline.file_kind("OPEN W")[0] == "open"
    assert timeline.file_kind("XATTR")[0] == "attrs"
    assert timeline.file_kind("FSE_WEIRD") == ("other", "FSE_WEIRD", False)


def test_the_config_listener_writes_a_policy_line(monkeypatch):
    import sandroid.config as config_mod
    from sandroid.config.schema import SandroidConfig

    monkeypatch.setattr(config_mod, "_config_instance", SandroidConfig())
    with timeline.capture() as lines:
        config_mod.update_config({"timeline.count_window_s": 7.0}, persist=False)
        config_mod.update_config({"emulator.sync_device_clock": False},
                                 persist=False)  # fmt: skip
    (policy,) = lines
    assert (policy["src"], policy["kind"]) == ("sandroid", "policy")
    assert policy["data"]["reason"] == "settings"
    assert policy["data"]["changed"] == {"timeline.count_window_s": [5.0, 7.0]}
    assert policy["data"]["timeline"]["count_window_s"] == 7.0
    assert "mask_sensitive" not in policy["data"]["timeline"]
    assert "helper_mode" in policy["data"]["tracking"]
    assert timeline.get_timeline()._policy.count_window_s == 7.0


def test_a_users_settings_save_is_attributed_and_no_ops_write_nothing(
    monkeypatch,
):
    """F5: actor/by "user" inside acting_as("user"); no empty changed:{}."""
    import sandroid.config as config_mod
    from sandroid.config.schema import SandroidConfig

    monkeypatch.setattr(config_mod, "_config_instance", SandroidConfig())
    with timeline.capture() as lines:
        with timeline.acting_as("user"):
            config_mod.update_config({"tracking.helper_mode": "invisible"},
                                     persist=False)  # fmt: skip
            # Same value again: the listener fires, but nothing changed.
            config_mod.update_config({"tracking.helper_mode": "invisible",
                                      "timeline.count_window_s": 5.0},
                                     persist=False)  # fmt: skip
    (policy,) = lines
    assert policy["actor"] == "user"
    assert policy["data"]["by"] == "user"
    assert policy["data"]["changed"] == {"tracking.helper_mode": ["full", "invisible"]}


# ---------------------------------------------------------------------------
# time model: transitions, dev_mono, world
# ---------------------------------------------------------------------------


def test_lines_are_stamped_by_their_time_not_their_seq():
    now = time.time()
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        service.set_phase("record", None, t=now)
        service.emit("input", "tap", summary="before", t=now - 1)
        service.emit("input", "tap", summary="after", t=now + 1)
        service.on_world_change("snapshot-load", t=now + 2, data={"name": "x"})
        service.emit("input", "tap", summary="late, before the load", t=now + 1.5)
    start, before, after, world, late = lines
    assert (start["phase"], start["data"]["from"], start["data"]["to"]) == (
        "record", "live", "record")  # fmt: skip
    assert before["phase"] == "live"
    assert after["phase"] == "record"
    assert (world["world"], world["epoch"]) == (1, 1)
    assert world["data"] == {"name": "x", "cause": "snapshot-load", "world_before": 0}
    assert late["world"] == 0  # its time is before the world change


def _epoch_sample(serial, mono, host, err_ms=4.0):
    with device_clock._LOCK:
        device_clock._add_to_epochs(serial, {
            "off_mono": round(host - mono, 6), "dev_mono": mono, "err_ms": err_ms,
            "_host": host})  # fmt: skip


def test_dev_mono_is_converted_and_the_world_barrier_holds(monkeypatch):
    now = time.time()
    monkeypatch.setattr(device_clock, "_now", lambda: now)
    _epoch_sample(SERIAL, 1000.0, now - 60)  # off1 = now - 1060
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        # A line received now that happened 10 s ago.
        service.emit("input", "tap", summary="a", dev_mono=1050.0, dev=SERIAL,
                     t_err_ms=1.5)  # fmt: skip
        monkeypatch.setattr(device_clock, "_now", lambda: now - 20)
        service.on_world_change("snapshot-load", t=now - 20, dev=SERIAL)
        monkeypatch.setattr(device_clock, "_now", lambda: now)
        # After the barrier, before a new sample: not mappable.
        service.emit("input", "tap", summary="b", dev_mono=1045.0, dev=SERIAL)
        # A late pre-load event (happened at now - 25) maps into the old world.
        service.emit("input", "tap", summary="c", dev_mono=1035.0, dev=SERIAL)
        _epoch_sample(SERIAL, 500.0, now - 10)  # after the load: off2 = now - 510
        service.emit("input", "tap", summary="d", dev_mono=505.0, dev=SERIAL)
        # Mappable only far outside [t_rx - 30 s, t_rx + 1 s]: rejected.
        service.emit("input", "tap", summary="e", dev_mono=300.0, dev=SERIAL)
    a, _world, b, c, d, e = lines
    assert a["clk"] == "dev_mono"
    assert datetime.fromisoformat(a["t"]).timestamp() == pytest.approx(
        now - 10, abs=2e-3
    )
    assert a["dev_mono"] == 1050.0
    assert a["t_err_ms"] == pytest.approx(4.0 + 0.01 * 50 + 1.5, abs=0.05)
    assert (b["clk"], b["dev_mono"]) == ("none", 1045.0)
    assert b["t"] == b["t_rx"]
    assert "t_err_ms" not in b
    assert c["clk"] == "dev_mono"
    assert c["world"] == 0
    assert datetime.fromisoformat(c["t"]).timestamp() == pytest.approx(
        now - 25, abs=2e-3
    )
    assert d["clk"] == "dev_mono"
    assert d["world"] == 1
    assert e["clk"] == "none"


def test_an_unexplained_monotonic_rewind_is_an_inferred_world_change():
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        service.emit("clock", "sample", summary="s", data={"dev_mono": 900.0})
        service.emit(
            "clock", "jump", summary="j", data={"dev_mono": 50.0, "jump": True}
        )
        service.emit("clock", "sample", summary="s", data={"dev_mono": 60.0})
        service.emit(
            "clock", "jump", summary="j", data={"dev_mono": 70.0, "jump": True}
        )
    assert _kinds(lines) == ["clock/sample", "sandroid/world", "clock/jump",
                             "clock/sample", "clock/jump"]  # fmt: skip
    world = lines[1]
    assert world["level"] == "warn"
    assert world["data"] == {"cause": "mono-rewind", "world_before": 0}
    assert world["t"] == lines[2]["t"]
    # The rewind's own jump line is the first after the world change: no
    # second epoch; a later jump is one.
    assert [(x["world"], x["epoch"]) for x in lines] == [
        (0, 0), (1, 1), (1, 1), (1, 1), (1, 2)]  # fmt: skip


def test_device_clock_begin_epoch_near_and_seed(monkeypatch):
    now = time.time()
    monkeypatch.setattr(device_clock, "_now", lambda: now)
    _epoch_sample("s", 1000.0, now - 60)
    host, _err = device_clock.to_host_time("s", 1055.0)
    assert host == pytest.approx(now - 5)
    assert device_clock.to_host_time("s", 1055.0, near=now) is not None
    assert device_clock.to_host_time("s", 1055.0, near=now - 100) is None
    monkeypatch.setattr(device_clock, "_now", lambda: now - 10)
    device_clock.begin_epoch("s")  # a world change 10 s ago
    monkeypatch.setattr(device_clock, "_now", lambda: now)
    assert device_clock.to_host_time("s", 1055.0) is None  # past the barrier
    assert device_clock.to_host_time("s", 1049.0) == pytest.approx((now - 11, 4.0))
    # A new sample with the same offset after a barrier starts a new epoch.
    _epoch_sample("s", 1065.0, now + 5)
    assert len(device_clock._EPOCHS["s"]) == 2
    device_clock.seed("s", off_wall=4500.0, off_mono=10.0, host_t=now)
    assert device_clock._LOGGED["s"] == (4500.0, 10.0)


# ---------------------------------------------------------------------------
# labels
# ---------------------------------------------------------------------------


def test_label_keys_semantics():
    with timeline.capture() as lines:
        labels = timeline.get_timeline().labels
        top = labels.start("Accept cookies", actor="user")  # '#'
        sub = labels.start("Click OK", level="sub")  # '+' under the top
        sibling = labels.start("Next", level="sub")  # '+' again: a sibling
        point = labels.point("tap login")  # 'B'
        nested = labels.start("deep", level="nest")
        assert [e.number for e in labels.open_spans()] == [1, 3, 5]
        assert labels.stop().number == 5  # '-'
        top2 = labels.start("Second")  # '#': closes the stack
        assert labels.open_spans() == [top2]
        ended = labels.end_all("stop")
        assert [e.number for e in ended] == [6]
        assert labels.stop() is None
        assert labels.next_number() == 7
    assert (top.number, top.depth, top.parent, top.seq) == (1, 0, None, 1)
    assert (sub.number, sub.depth, sub.parent) == (2, 1, 1)
    assert (sibling.number, sibling.depth, sibling.parent) == (3, 1, 1)
    assert (point.number, point.parent, point.kind) == (4, 3, "point")
    assert (nested.parent, nested.depth) == (3, 2)
    ends = [x for x in lines if x["kind"] == "end"]
    assert [(x["data"]["number"], x["data"]["ended_by"]) for x in ends] == [
        (2, "sibling"), (5, "stop"), (3, "new_label"), (1, "new_label"), (6, "stop")]  # fmt: skip
    assert ends[0]["ref"]["of"] == sub.seq
    assert lines[0]["summary"] == "▶ 1 'Accept cookies'"
    assert lines[1]["summary"] == "▶ 2 'Click OK' (in 1)"
    assert lines[0]["actor"] == "user"
    assert lines[0]["data"] == {"number": 1, "name": "Accept cookies", "parent": None,
                                "depth": 0, "source": "key"}  # fmt: skip
    assert re.fullmatch(r"■ 2 'Click OK' · \d+\.\d s", ends[0]["summary"])
    # '+' with nothing open is a top-level start.
    with timeline.capture():
        labels = timeline.get_timeline().labels
        assert labels.start("x", level="sub").depth == 0


def test_boundaries_are_top_level_spans_and_every_point():
    with timeline.capture():
        labels = timeline.get_timeline().labels
        labels.start("a", t=100.0)
        labels.start("b", level="sub", t=101.0)
        labels.point("p", t=102.0)
        labels.start("c", t=103.0)  # ends b and a at 103
        got = [(e.kind, e.number, e.t) for e in labels.boundaries()]
    assert got == [("start", 1, 100.0), ("point", 3, 102.0), ("end", 1, 103.0),
                   ("start", 4, 103.0)]  # fmt: skip


def test_active_label_prefers_the_innermost_open_span():
    def mark(when, kind=None, number=1):
        m = SimpleNamespace(when=datetime(2026, 1, 1, 12, 0, when), number=number)
        if kind is not None:
            m.kind = kind
        return m

    marks = [mark(1, "start", 1), mark(2, None, 2), mark(3, "start", 3),
             mark(5, "end", 3), mark(7, "end", 1)]  # fmt: skip
    at = lambda s: datetime(2026, 1, 1, 12, 0, s)  # noqa: E731
    assert timeline.active_label(marks, at(0)) is None
    assert timeline.active_label(marks, at(2)) is marks[0]
    assert timeline.active_label(marks, at(4)) is marks[2]
    assert timeline.active_label(marks, at(6)) is marks[0]
    assert timeline.active_label(marks, at(8)) is marks[1]  # last point
    assert timeline.active_label([mark(1)], at(3)).number == 1  # no kind = point


# ---------------------------------------------------------------------------
# resume, torn tail, lock, detached, device switch
# ---------------------------------------------------------------------------


def test_resume_continues_seq_h_world_epoch_and_labels(tmp_path):
    folder = tmp_path / "s1" / "dev"
    service = _service(folder)
    service.labels.start("open across restart", actor="user")
    service.on_world_change("snapshot-load")
    service.emit("clock", "jump", summary="j", data={"dev_mono": 10.0, "jump": True,
                                                    "off_wall": 4500.0, "off_mono": 1.0})  # fmt: skip
    _crash(service)
    before = _lines(folder / timeline.FILE_NAME)
    last = before[-1]
    assert last["epoch"] == 1  # the first clock line after the world change

    again = _service(folder)
    again.labels.start("next")
    assert again.close("test", 3.0)
    lines = _lines(folder / timeline.FILE_NAME)
    resumed = lines[len(before)]
    assert (resumed["src"], resumed["kind"]) == ("sandroid", "resume")
    assert resumed["seq"] == last["seq"] + 1
    assert resumed["data"]["prev_h"] == last["h"]
    assert resumed["data"]["prev_seq"] == last["seq"]
    assert resumed["data"]["verified"] is True
    assert resumed["data"]["unclean"] is True
    assert resumed["data"]["torn"] is None
    assert (resumed["world"], resumed["epoch"]) == (1, 1)
    after = lines[len(before) :]
    assert _kinds(after)[:4] == ["sandroid/resume", "sandroid/policy", "label/end",
                                 "device/connect"]  # fmt: skip
    late_end = after[2]
    assert late_end["data"] == {"number": 1, "ended_by": "close", "late": True,
                                "duration_s": late_end["data"]["duration_s"]}  # fmt: skip
    nxt = next(x for x in after if x["src"] == "label" and x["kind"] == "start")
    assert nxt["data"]["number"] == 2
    assert device_clock._LOGGED[SERIAL] == (4500.0, 1.0)  # seeded
    assert timeline.verify_chain(folder / timeline.FILE_NAME, strict=True).ok


def test_a_torn_tail_is_closed_declared_and_verifies(tmp_path):
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    service.emit("input", "tap", summary="x")
    _crash(service)
    path = folder / timeline.FILE_NAME
    size = path.stat().st_size
    fragment = b'{"v":1,"seq":99,"src":"inp'
    with open(path, "ab") as handle:
        handle.write(fragment)
    assert timeline.verify_chain(path).torn == ((size, len(fragment)),)
    again = _service(folder)
    assert again.close("test", 3.0)
    raw = path.read_bytes()
    assert raw[size : size + len(fragment) + 1] == fragment + b"\n"  # never truncated
    resume = next(x for x in _lines_skip(path) if x["kind"] == "resume")
    assert resume["data"]["torn"] == {"offset": size, "bytes": len(fragment),
                                      "sha256": hashlib.sha256(fragment).hexdigest()}  # fmt: skip
    assert resume["level"] == "warn"
    result = timeline.verify_chain(path, strict=True)
    assert result.ok, result.errors
    assert result.torn == ((size, len(fragment)),)
    rows = [line for _o, line in timeline.read_lines(path)]
    assert all(r.get("seq") != 99 for r in rows)  # the fragment is skipped


def _lines_skip(path: Path) -> list[dict]:
    return [line for _o, line in timeline.read_lines(path, mask_sensitive=False)]


def test_a_tampered_last_line_resumes_unverified(tmp_path):
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    service.emit("input", "tap", summary="original")
    _crash(service)
    path = folder / timeline.FILE_NAME
    path.write_bytes(path.read_bytes().replace(b"original", b"tampered"))
    again = _service(folder)
    assert again.close("test", 3.0)
    resume = next(x for x in _lines(path) if x["kind"] == "resume")
    assert resume["data"]["verified"] is False
    assert resume["level"] == "warn"
    assert not timeline.verify_chain(path).ok


def test_a_second_process_on_a_locked_folder_writes_nothing(tmp_path):
    folder = tmp_path / "s" / "dev"
    first = _service(folder)
    assert first.flush(3.0)
    path = folder / timeline.FILE_NAME
    size = path.stat().st_size
    second = TimelineService()
    status = second.bind(SERIAL, folder)
    assert status.state == "locked"
    assert (
        status.locked_by == f"PID {os.getpid()} on {__import__('socket').gethostname()}"
    )
    assert second.emit("input", "tap", summary="nope") is None
    assert second.labels.start("nope") is None
    second.close("test", 1.0)
    assert path.stat().st_size == size
    assert first.close("test", 3.0)


def test_detached_lines_are_adopted_by_the_first_bind(tmp_path):
    service = TimelineService()
    early = service.labels.start("before the device", actor="user")
    assert early.seq is None
    assert service.emit("files", "modify", summary="bulk") is None
    assert service.status().state == "detached"
    assert service.status().dropped == {"no-device": 1}
    folder = tmp_path / "s" / "dev"
    assert service.bind(SERIAL, folder).state == "open"
    assert service.close("test", 3.0)
    lines = _lines(folder / timeline.FILE_NAME)
    assert _kinds(lines)[:4] == ["sandroid/open", "sandroid/policy", "label/start",
                                 "device/connect"]  # fmt: skip
    assert lines[0]["data"]["detached"] == {"adopted": 1, "dropped": 1}
    assert lines[2]["data"]["number"] == 1
    assert lines[2]["actor"] == "user"
    end = next(x for x in lines if x["kind"] == "end")
    assert end["ref"]["of"] == lines[2]["seq"]
    dropped = next(x for x in lines if x["kind"] == "dropped")
    assert dropped["data"]["reason"] == {"no-device": 1}


def test_without_any_device_user_lines_go_to_the_session_root(tmp_path):
    service = TimelineService()
    service.labels.point("no device yet", actor="user")
    service.emit("clock", "sample", summary="not a user line")
    assert service.close("quit", 3.0)
    root = timeline.timeline_folder().parent
    path = root / timeline.FILE_NAME
    lines = _lines(path)
    assert _kinds(lines) == ["sandroid/open", "sandroid/policy", "label/point",
                             "sandroid/close"]  # fmt: skip
    assert lines[0]["data"]["session_id"] == f"{root.name}/-"
    assert all(line["dev"] is None for line in lines)
    assert timeline.verify_chain(path).ok


def test_a_device_switch_keeps_the_old_timeline_open(tmp_path):
    service = TimelineService()
    a, b = tmp_path / "s" / "a", tmp_path / "s" / "b"
    assert service.bind("emu-a", a).state == "open"
    service.labels.start("on a", actor="user")
    assert service.bind("emu-b", b).state == "open"
    assert service.active_serial == "emu-b"
    assert service.emit("input", "tap", summary="late on a", dev="emu-a") is not None
    assert service.emit("input", "tap", summary="on b") is not None
    assert service.emit("input", "tap", summary="nowhere", dev="emu-x") is None
    assert service.labels.open_spans() == []  # b's labels
    assert service.close("test", 3.0)
    on_a = _lines(a / timeline.FILE_NAME)
    assert _kinds(on_a)[-4:] == ["label/end", "device/switch", "input/tap",
                                 "sandroid/close"]  # fmt: skip
    assert on_a[-4]["data"]["ended_by"] == "device_switch"
    assert on_a[-3]["data"] == {"to": "emu-b"}
    assert on_a[-1]["data"]["labels_closed"] == []
    on_b = _lines(b / timeline.FILE_NAME)
    assert [x["summary"] for x in on_b if x["src"] == "input"] == ["on b"]
    assert service.status("emu-b").dropped.get("unrouted") == 1
    # The same folder with a new serial (a restarted emulator): one file.
    again = TimelineService()
    assert again.bind("emu-a2", a).state == "open"
    assert again.close("test", 3.0)


def test_rebinding_the_same_folder_with_a_new_serial_notes_it(tmp_path):
    service = _service(tmp_path / "s" / "d", "emulator-5556")
    service.bind("emulator-5558", tmp_path / "s" / "d")
    assert service.close("test", 3.0)
    connects = [x for x in _lines(tmp_path / "s" / "d" / timeline.FILE_NAME)
                if x["kind"] == "connect"]  # fmt: skip
    assert connects[-1]["data"]["serial_changed"] is True
    assert connects[-1]["dev"] == "emulator-5558"


# ---------------------------------------------------------------------------
# seal, readers, masking, doorbell
# ---------------------------------------------------------------------------


def test_seal_is_checkable_while_the_file_grows(timeline_sink):
    service, path = timeline_sink
    service.emit("input", "tap", summary="x")
    seal = service.seal(by="report", report="runs/r1")
    assert seal is not None
    assert seal.verified
    assert seal.sha256 == hashlib.sha256(path.read_bytes()[: seal.bytes]).hexdigest()
    assert (seal.seq_first, seal.session_id) == (1, "session/dev")
    service.emit("input", "tap", summary="later")
    assert service.close("test", 3.0)
    assert hashlib.sha256(path.read_bytes()[: seal.bytes]).hexdigest() == seal.sha256
    (line,) = [x for x in _lines(path) if x["kind"] == "seal"]
    assert line["seq"] == seal.seal_seq == seal.seq_last + 1
    assert line["data"]["sha256"] == seal.sha256
    assert line["data"]["by"] == "report"
    offline = timeline.seal_file(path)
    assert offline.verified
    assert offline.seal_seq is None


def test_tail_reads_the_ring_and_tail_lines_the_file(timeline_sink):
    service, path = timeline_sink
    for i in range(5):
        service.emit("input", "tap", summary=str(i))
    assert service.flush(3.0)
    result = service.tail(after_seq=3)
    assert [x["seq"] for x in result.lines] == list(range(4, result.last_seq + 1))
    assert result.gap is False
    rows, first = timeline.tail_lines(path, 3)
    assert [r[1]["summary"] for r in rows] == ["2", "3", "4"]
    assert first == rows[0][0]
    assert timeline.read_line_at(path, rows[1][0])["summary"] == "3"
    service._active.ring.clear()
    service._active.ring.append(({"seq": 100}, 0))
    assert service.tail(after_seq=3).gap is True


def test_masking_per_reader(monkeypatch):
    from sandroid.config import get_config
    from sandroid.config.schema import AI_MASK_SENSITIVE_DEFAULT

    assert AI_MASK_SENSITIVE_DEFAULT is False
    line = {"src": "input", "summary": "typed 8 chars", "sensitive": True,
            "data": {"text": "hunter22", "password": True}, "ref": {"raw": "f#L1"}}  # fmt: skip
    masked = timeline.mask(line)
    assert masked["data"] == {"_masked": True, "keys": ["password", "text"]}
    assert masked["ref"] == {"raw": "•••"}
    assert masked["summary"] == line["summary"]
    assert timeline.mask({"data": {"a": 1}}) == {"data": {"a": 1}}
    cfg = get_config()
    assert not timeline.should_mask("ui")
    assert not timeline.should_mask("ai")
    monkeypatch.setattr(cfg.timeline, "mask_sensitive", True)
    assert timeline.should_mask("ui")
    assert timeline.should_mask("report")
    assert not timeline.should_mask("ai")
    monkeypatch.setattr(cfg.ai, "mask_sensitive", True)
    assert timeline.should_mask("ai")


def test_readers_mask_unless_told_not_to(timeline_sink, monkeypatch):
    from sandroid.config import get_config

    service, path = timeline_sink
    service.emit("input", "text", summary="typed 3 chars", sensitive=True,
                 data={"text": "abc"})  # fmt: skip
    assert service.flush(3.0)
    monkeypatch.setattr(get_config().timeline, "mask_sensitive", True)
    rows = [line for _o, line in timeline.read_lines(path) if line.get("sensitive")]
    assert rows[0]["data"]["_masked"] is True
    rows = [x for _o, x in timeline.read_lines(path, mask_sensitive=False)
            if x.get("sensitive")]  # fmt: skip
    assert rows[0]["data"]["text"] == "abc"
    # The ring is unmasked; the reader applies the mask.
    assert service.tail().lines[-1]["data"]["text"] == "abc"


def test_the_doorbell_is_gated_and_carries_no_lines(timeline_sink):
    from sandroid.core.events import EventBus, EventType

    service, _path = timeline_sink
    # A fresh bus: subscribers left by earlier (e.g. TUI) tests would open the gate.
    EventBus.reset()
    bus = EventBus.get()
    service.emit("input", "tap", summary="unheard")
    assert service.flush(3.0)
    assert bus.get_history(EventType.TIMELINE_EVENT, count=100) == []
    got: list = []
    rang = threading.Event()

    def handler(event):
        got.append(event.data)
        rang.set()

    bus.subscribe(EventType.TIMELINE_EVENT, handler)
    try:
        time.sleep(0.3)  # past the rate limit
        service.emit("input", "tap", summary="heard")
        point = service.labels.point("p")
        assert service.flush(3.0)
        assert rang.wait(3.0)
        # The first ring may cover only "heard" (written before the point
        # existed); the ring covering the point's line follows within the
        # rate limit (the writer publishes a pending ring on every tick).
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not any(
            (p.get("last_seq") or 0) >= point.seq for p in got
        ):
            time.sleep(0.02)
    finally:
        bus.unsubscribe(EventType.TIMELINE_EVENT, handler)
    payload = next(p for p in got if (p.get("last_seq") or 0) >= point.seq)
    # A ring that covers a label line carries that label's version or newer
    # (the bump and the line are queued under one lock).
    assert all(
        p["labels_version"] == service.labels.version
        for p in got
        if (p.get("last_seq") or 0) >= point.seq
    )
    assert set(payload) == {"op", "dev", "folder", "session_id", "labels_version",
                            "active", "first_seq", "last_seq", "srcs"}  # fmt: skip
    assert payload["op"] == "lines"
    assert payload["active"] is True
    assert payload["labels_version"] == service.labels.version
    assert payload["dev"] == SERIAL
    assert "input" in {src for p in got for src in p["srcs"]}


def test_acting_as_scopes_the_actor_to_the_thread():
    seen = []
    with timeline.capture() as lines:
        with timeline.acting_as("ai"):
            timeline.emit("input", "tap", summary="x")
            thread = threading.Thread(
                target=lambda: seen.append(timeline.current_actor())
            )
            thread.start()
            thread.join()
        timeline.emit("input", "tap", summary="y")
    assert [x["actor"] for x in lines] == ["ai", "sandroid"]
    assert seen == ["sandroid"]


def test_tool_dispatch_runs_tools_as_the_ai():
    from sandroid.ai.tools.registry import ToolRegistry, ToolSpec

    registry = ToolRegistry()
    registry.register(ToolSpec(name="probe", description="d",
                               parameters={"type": "object", "properties": {}},
                               func=timeline.current_actor))  # fmt: skip
    assert registry.dispatch("probe", {}) == "ai"
    assert timeline.current_actor() == "sandroid"


def test_no_ai_module_reads_the_timeline_without_reader_ai():
    """Lint: AI code reads the timeline only through ``reader="ai"``."""
    root = Path(timeline.__file__).resolve().parents[1] / "ai"
    call = re.compile(r"\b(read_lines|read_line_at|tail_lines)\(")
    bad = []
    for file in root.rglob("*.py"):
        text = file.read_text(encoding="utf-8")
        for match in call.finditer(text):
            depth, end = 0, match.end() - 1
            for end in range(match.end() - 1, len(text)):
                depth += {"(": 1, ")": -1}.get(text[end], 0)
                if depth == 0:
                    break
            if 'reader="ai"' not in text[match.start() : end]:
                bad.append(f"{file.name}:{text[: match.start()].count(chr(10)) + 1}")
    assert bad == []


# ---------------------------------------------------------------------------
# quit order
# ---------------------------------------------------------------------------


def _stub_quit(monkeypatch, steps):
    from sandroid import services
    from sandroid.core import ui_request_bus
    from sandroid.services import setup_checks
    from sandroid.tui.controllers import quit_controller as qc

    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: steps.append("net"))
    monkeypatch.setattr(
        qc, "run_shutdown_hooks", lambda timeout=0: steps.append("hooks")
    )
    monkeypatch.setattr(qc.QuitController, "_stop_frida_sessions",
                        staticmethod(lambda: None))  # fmt: skip
    monkeypatch.setattr(qc.QuitController, "_cleanup_rest", staticmethod(lambda: None))
    monkeypatch.setattr(setup_checks, "restore_selinux_on_quit", lambda: None)
    bus = SimpleNamespace(shutdown=lambda: steps.append("bus"))
    monkeypatch.setattr(ui_request_bus.UIRequestBus, "get", staticmethod(lambda: bus))
    monkeypatch.setattr(services, "get_task_service",
                        lambda: SimpleNamespace(stop_all=lambda: None))  # fmt: skip
    real = qc.run_bounded

    def bounded(name, fn, timeout):
        steps.append(name)
        return real(name, fn, min(timeout, 2.5))

    monkeypatch.setattr(qc, "run_bounded", bounded)
    return qc


def test_quit_flushes_the_timeline_first_and_closes_it_last(monkeypatch, timeline_sink):
    steps: list[str] = []
    qc = _stub_quit(monkeypatch, steps)
    service, path = timeline_sink
    service.labels.start("open at quit", actor="user")
    qc.QuitController().force_exit()
    assert steps[0] == "timeline flush"
    assert steps[-1] == "timeline close"
    assert steps.index("SELinux restore") < steps.index("timeline close")
    lines = _lines(path)
    assert _kinds(lines)[-2:] == ["label/end", "sandroid/close"]
    assert lines[-2]["data"]["ended_by"] == "close"
    assert lines[-1]["data"]["reason"] == "quit"
    assert lines[-1]["data"]["labels_closed"] == [1]
    assert service.emit("input", "tap", summary="after close") is None


def test_quit_steps_are_bounded_even_if_the_timeline_hangs(monkeypatch):
    steps: list[str] = []
    qc = _stub_quit(monkeypatch, steps)
    hang = threading.Event()
    monkeypatch.setattr(timeline, "flush_timeline", lambda timeout=1.0: hang.wait(30))
    monkeypatch.setattr(timeline, "close_timeline",
                        lambda reason="quit", timeout=2.0: hang.wait(30))  # fmt: skip
    started = time.monotonic()
    qc.QuitController().force_exit()
    hang.set()
    assert time.monotonic() - started < 8
    assert steps[0] == "timeline flush"
    assert steps[-1] == "timeline close"


def test_emergency_cleanup_and_the_launcher_close_the_timeline(monkeypatch):
    from sandroid.tui import launcher
    from sandroid.tui.controllers import quit_controller as qc

    calls = []
    monkeypatch.setattr(timeline, "close_timeline",
                        lambda reason="quit", timeout=2.0: calls.append((reason, timeout)))  # fmt: skip
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: None)
    qc.emergency_cleanup()
    launcher._close_timeline()
    launcher._close_timeline("crash")
    assert calls == [("forced-exit", 1.0), ("exit", 1.5), ("crash", 1.5)]


def test_the_close_reason_after_the_tui_is_honest(monkeypatch):
    """E2E crash: a worker's SystemExit(1) ended the TUI and the timeline
    said ``closed (quit)``. A normal quit closes it as "quit" itself; what
    the launcher or atexit closes is "exit", or "crash" when it was one.
    """
    import sys

    from sandroid.tui import launcher

    assert launcher.exit_close_reason(0) == "exit"
    assert launcher.exit_close_reason(None) == "exit"
    assert launcher.exit_close_reason(1) == "crash"
    monkeypatch.delattr(sys, "last_exc", raising=False)
    monkeypatch.delattr(sys, "last_value", raising=False)
    assert timeline._atexit_reason() == "exit"
    monkeypatch.setattr(sys, "last_value", RuntimeError("boom"), raising=False)
    assert timeline._atexit_reason() == "crash"


def test_run_tui_closes_the_timeline_as_crash_when_app_run_raises(monkeypatch):
    from sandroid.tui import app as tui_app
    from sandroid.tui import launcher
    from sandroid.tui.controllers import quit_controller as qc

    class CrashingApp:
        return_code = None

        def __init__(self, **kw):
            pass

        def run(self):
            raise SystemExit(1)  # a worker's SystemExit, as in the E2E crash

    reasons = []
    monkeypatch.setattr(tui_app, "SandroidTUI", CrashingApp)
    monkeypatch.setattr(launcher.atexit, "register", lambda fn: None)
    monkeypatch.setattr(launcher.signal, "signal", lambda *a: None)
    monkeypatch.setattr(launcher, "reset_terminal", lambda: None)
    monkeypatch.setattr(qc, "enable_hard_exit", lambda enabled=True: None)
    monkeypatch.setattr(qc, "mark_app_returned", lambda: None)
    monkeypatch.setattr(
        launcher,
        "_shutdown_services",
        lambda task, capture, close_reason="exit": reasons.append(close_reason),
    )
    with pytest.raises(SystemExit):
        launcher.run_tui(startup_config=None)
    assert reasons == ["crash"]


def test_close_is_idempotent_and_bounded(timeline_sink):
    service, path = timeline_sink
    assert timeline.close_timeline("quit", 2.0)
    size = path.stat().st_size
    assert timeline.close_timeline("quit", 2.0)
    assert timeline.flush_timeline(1.0)
    assert path.stat().st_size == size
    assert service.status().state == "closed"


# ---------------------------------------------------------------------------
# review fixes (bad t, transitions, doorbell, resume, close, routing, ...)
# ---------------------------------------------------------------------------


def test_a_bad_t_never_loses_the_batch_or_leaves_a_seq_gap(tmp_path):
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    before = service.emit("monitor", "a", summary="before")
    label = service.labels.point("must keep", actor="user")
    bad = service.emit("monitor", "b", summary="ms as s", t=time.time() * 1000)
    after = service.emit("monitor", "c", summary="after")
    assert service.flush(3.0)
    assert service.close("test", 3.0)
    lines = _lines(folder / timeline.FILE_NAME)
    assert [x["seq"] for x in lines] == list(range(1, len(lines) + 1))
    by_seq = {x["seq"]: x for x in lines}
    assert {before, label.seq, bad, after} <= set(by_seq)
    flagged = by_seq[bad]
    assert (flagged["clk"], flagged["level"]) == ("none", "warn")
    assert flagged["t"] == flagged["t_rx"]
    assert flagged["data"]["_bad_t"].startswith("1")
    assert timeline.verify_chain(folder / timeline.FILE_NAME, strict=True).ok


def test_a_line_that_cannot_be_finalized_is_written_as_an_error_line(
    tmp_path, monkeypatch
):
    real = timeline._finalize

    def flaky(sink, item, *args):
        if item.fields.get("summary") == "boom":
            raise RuntimeError("cannot finalize")
        return real(sink, item, *args)

    monkeypatch.setattr(timeline, "_finalize", flaky)
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    service.emit("monitor", "a", summary="before")
    boom = service.emit("monitor", "b", summary="boom", sensitive=True)
    service.emit("monitor", "c", summary="after")
    seal = service.seal(by="test", timeout=3.0)
    assert seal is not None
    assert seal.verified
    assert service.close("test", 3.0)
    lines = _lines(folder / timeline.FILE_NAME)
    assert [x["seq"] for x in lines] == list(range(1, len(lines) + 1))
    error = next(x for x in lines if x["seq"] == boom)
    assert (error["src"], error["kind"], error["level"]) == ("monitor", "b", "error")
    assert error["sensitive"] is True
    assert "cannot finalize" in error["data"]["_finalize_error"]
    assert timeline.verify_chain(folder / timeline.FILE_NAME).ok


def test_a_transition_inserted_earlier_refolds_the_later_states(tmp_path):
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    now = time.time()
    service.set_phase("record", "r1", t=now)
    # A clock jump sampled 0.3 s earlier, emitted after the phase change.
    service.emit("clock", "jump", summary="jump", t=now - 0.3,
                 data={"jump": True, "off_wall": 1.0})  # fmt: skip
    service.emit("sandroid", "note", summary="after both", t=now + 0.05)
    assert service.close("test", 3.0)
    lines = {x["kind"]: x for x in _lines(folder / timeline.FILE_NAME)}
    states = {k: (lines[k]["epoch"], lines[k]["phase"]) for k in ("jump", "phase",
                                                                   "note")}  # fmt: skip
    assert states == {"jump": (1, "live"), "phase": (1, "record"),
                      "note": (1, "record")}  # fmt: skip


def test_switching_back_to_an_open_sink_rings_bound_with_its_labels_version(
    tmp_path,
):
    from sandroid.core.events import EventBus, EventType

    got: list[dict] = []
    bus = EventBus.get()
    handler = lambda event: got.append(event.data)  # noqa: E731
    bus.subscribe(EventType.TIMELINE_EVENT, handler)
    try:
        service = TimelineService()
        a, b = tmp_path / "s" / "a", tmp_path / "s" / "b"
        assert service.bind("A", a).state == "open"
        service.labels.start("on A", actor="user")
        version_a = service.labels.version
        assert service.bind("B", b).state == "open"
        service.labels.start("on B", actor="user")
        version_b = service.labels.version
        assert version_a != version_b  # unique across files
        got.clear()
        assert service.bind("A", a).state == "open"
        version = service.labels.version
    finally:
        bus.unsubscribe(EventType.TIMELINE_EVENT, handler)
    bound = [x for x in got if x["op"] == "bound"]
    assert len(bound) == 1
    assert bound[0]["dev"] == "A"
    assert bound[0]["folder"] == str(a.absolute())
    assert bound[0]["session_id"] == "s/a"
    assert bound[0]["labels_version"] == version
    assert version not in (version_b,)
    assert bound[0]["active"] is True
    assert service.close("test", 3.0)


@pytest.mark.parametrize("cut", ["newline", "reterminated"])
def test_a_tail_missing_only_its_newline_is_adopted(tmp_path, cut):
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    for i in range(3):
        service.emit("monitor", "note", summary=f"n{i}")
    _crash(service)
    path = folder / timeline.FILE_NAME
    data = path.read_bytes()
    if cut == "newline":  # a crash right before the last line's newline
        path.write_bytes(data[:-1])
        expect_torn = None
    else:  # a torn fragment closed by a resume that crashed before its line
        fragment = b'{"v":1,"seq":99,"src":"mon'
        path.write_bytes(data + fragment + b"\n")
        expect_torn = {"offset": len(data), "bytes": len(fragment),
                       "sha256": hashlib.sha256(fragment).hexdigest()}  # fmt: skip
    again = _service(folder)
    again.emit("monitor", "note", summary="after")
    assert again.close("test", 3.0)
    resume = next(x for x in _lines_skip(path) if x["kind"] == "resume")
    assert resume["data"]["torn"] == expect_torn
    if cut == "newline":
        assert resume["data"]["verified"] is True
        assert resume["data"]["adopted_tail"] == data.rfind(b"\n", 0, -1) + 1
    result = timeline.verify_chain(path, strict=True)
    assert result.ok, result.errors


def test_close_while_a_sink_is_still_opening_writes_its_close_line(
    tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()
    real = timeline._try_lock

    def slow_lock(path, serial):
        entered.set()
        release.wait(5.0)
        return real(path, serial)

    monkeypatch.setattr(timeline, "_try_lock", slow_lock)
    service = TimelineService()
    folder = tmp_path / "s" / "dev"
    binder = threading.Thread(target=service.bind, args=(SERIAL, folder))
    binder.start()
    assert entered.wait(3.0)
    result: list[bool] = []
    closer = threading.Thread(target=lambda: result.append(service.close("quit", 5.0)))
    closer.start()
    deadline = time.monotonic() + 3.0
    while not service._closed and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    closer.join(6.0)
    binder.join(3.0)
    assert result == [True]
    lines = _lines(folder / timeline.FILE_NAME)
    assert _kinds(lines)[-1] == "sandroid/close"
    assert lines[-1]["data"]["reason"] == "quit"
    assert timeline.verify_chain(folder / timeline.FILE_NAME).ok
    thread = service._thread
    if thread is not None:
        thread.join(2.0)
        assert not thread.is_alive()


def test_dev_mono_without_dev_converts_with_the_sinks_serial(tmp_path, monkeypatch):
    now = time.time()
    monkeypatch.setattr(device_clock, "_now", lambda: now)
    _epoch_sample(SERIAL, 1000.0, now - 60)
    folder = tmp_path / "s" / "dev"
    service = _service(folder)
    service.emit("input", "tap", summary="no dev", dev_mono=1050.0)
    assert service.close("test", 3.0)
    tap = next(x for x in _lines(folder / timeline.FILE_NAME) if x["src"] == "input")
    assert tap["clk"] == "dev_mono"
    assert datetime.fromisoformat(tap["t"]).timestamp() == pytest.approx(
        now - 10, abs=2e-3
    )


def test_the_root_fallback_goes_to_the_session_folder_not_results(
    tmp_path, monkeypatch
):
    from sandroid import services

    session = tmp_path / "results" / "session_A"
    session.mkdir(parents=True)
    monkeypatch.delenv("SDROID_FILES_DIR", raising=False)
    monkeypatch.delenv("SESSION_PATH", raising=False)
    monkeypatch.setenv("RESULTS_PATH", str(session) + "/")
    monkeypatch.setattr(services, "get_initialization_service",
                        lambda: SimpleNamespace(get_session_path=lambda: None,
                                                get_device_path=lambda: None))  # fmt: skip
    service = TimelineService()
    service.labels.point("before any device", actor="user")
    assert service.close("quit", 3.0)
    assert (session / timeline.FILE_NAME).is_file()
    assert not (tmp_path / "results" / timeline.FILE_NAME).exists()
    monkeypatch.delenv("RESULTS_PATH")
    assert timeline.session_folder() is None  # never ./results or the cwd


def test_a_rename_flushes_the_targets_pending_modifies_oldest_first():
    service = timeline.get_timeline()
    p = "/data/data/com.x/databases/a.db"
    with timeline.capture() as out:
        t = time.time()
        for i in range(3):
            _event(service, "MODIFY", p, pid=10, t=t + i * 0.1)
        _event(service, "MODIFY", p, pid=11, t=t + 0.35)
        service.file_event(op="RENAME", path="/data/data/com.x/x.tmp", new_path=p,
                           t=t + 0.4, backend="kprobe", pid=10,
                           app_pkg="com.x")  # fmt: skip
        _event(service, "DELETE", p, pid=10, t=t + 0.5)
    assert [(x["kind"], x.get("pid"), (x.get("data") or {}).get("n")) for x in out] == [
        ("modify", 10, 3), ("modify", 11, 1), ("rename", 10, None),
        ("delete", 10, None)]  # fmt: skip


def test_a_locked_folder_is_retried_and_active_so_nothing_is_misrouted(tmp_path):
    a, b = tmp_path / "s" / "a", tmp_path / "s" / "b"
    other = _service(b, "B")
    service = TimelineService()
    assert service.bind("A", a).state == "open"
    assert service.bind("B", b).state == "locked"
    assert service.bind("A", a).state == "open"
    assert service.bind("B", b).state == "locked"
    assert service.active_serial == "B"
    service.emit("snapshot", "save", summary="meant for B")
    assert service.labels.start("meant for B") is None
    assert other.close("test", 3.0)
    # The other process quit: the next bind gets the lock.
    assert service.bind("B", b).state == "open"
    assert service.close("test", 3.0)
    on_a = [x["summary"] for x in _lines(a / timeline.FILE_NAME)]
    assert "meant for B" not in on_a
    assert timeline.verify_chain(b / timeline.FILE_NAME).ok


def test_a_clock_sample_from_before_a_world_change_does_not_count_it_twice():
    now = time.time()
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        service.emit("clock", "sample", summary="s", t=now - 5,
                     data={"dev_mono": 900.0})  # fmt: skip
        service.on_world_change("snapshot-load", t=now)
        # Measured before the load (old world), emitted after it.
        service.emit("clock", "sample", summary="stale", t=now - 1,
                     data={"dev_mono": 904.0})  # fmt: skip
        # The first sample of the new world: rewound, already explained.
        service.emit("clock", "jump", summary="j", t=now + 1,
                     data={"dev_mono": 50.0, "jump": True})  # fmt: skip
    assert _kinds(lines) == ["clock/sample", "snapshot/load", "clock/sample",
                             "clock/jump"]  # fmt: skip
    assert [(x["world"], x["epoch"]) for x in lines] == [
        (0, 0), (1, 1), (0, 0), (1, 1)]  # fmt: skip


def test_tail_returns_the_file_offset_of_every_line(timeline_sink):
    service, path = timeline_sink
    for i in range(5):
        service.emit("input", "tap", summary=f"tap {i}")
    assert service.flush(3.0)
    result = service.tail(2)
    assert len(result.offsets) == len(result.lines) > 0
    for line, offset in zip(result.lines, result.offsets, strict=True):
        assert timeline.read_line_at(path, offset, mask_sensitive=False) == line
    assert service.tail(result.last_seq).offsets == []
    with timeline.capture():
        timeline.emit("input", "tap", summary="in memory")
        assert timeline.get_timeline().tail().offsets is None  # no file


def test_every_change_of_the_active_sink_rings_bound(tmp_path):
    from sandroid.core.events import EventBus, EventType

    a, b, c = (tmp_path / "s" / name for name in ("a", "b", "c"))
    other = _service(c, "C")  # holds c's lock
    got: list[dict] = []
    bus = EventBus.get()
    handler = lambda event: got.append(event.data)  # noqa: E731
    bus.subscribe(EventType.TIMELINE_EVENT, handler)
    try:
        service = TimelineService()
        assert service.bind("A", a).state == "open"  # new
        assert service.bind("B", b).state == "open"  # new
        assert service.bind("A", a).state == "open"  # re-activated
        assert service.bind("C", c).state == "locked"  # active, no file
        deadline = time.monotonic() + 3.0
        while sum(x["op"] == "bound" for x in got) < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        bus.unsubscribe(EventType.TIMELINE_EVENT, handler)
    bound = [x for x in got if x["op"] == "bound"]
    assert [(x["dev"], x["folder"], x["session_id"], x["active"]) for x in bound] == [
        ("A", str(a.absolute()), "s/a", True),
        ("B", str(b.absolute()), "s/b", True),
        ("A", str(a.absolute()), "s/a", True),
        ("C", str(c.absolute()), "s/c", True),
    ]
    assert service.status().state == "locked"
    assert service.close("test", 3.0)
    assert other.close("test", 3.0)
