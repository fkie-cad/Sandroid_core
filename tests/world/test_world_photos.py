"""World photos: the cache (local dirs, fake HTTP server) and the EXIF privacy step."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.server
import io
import struct
import threading
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from PIL import Image

from sandroid.world import photos as ph
from sandroid.world.packs import PackSet

BERLIN = ZoneInfo("Europe/Berlin")
LEAKS = (b"LeakCamMake", b"LeakModelX9", b"SECRETMAKERNOTE", b"LEAKXMP", b"LEAKCOMMENT")
ORIG_LAT = 48.137154
ORIG_LON = 11.576124


@pytest.fixture(autouse=True)
def _no_dev_photo_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ph.PHOTOS_DIR_ENV, raising=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jpeg(size: tuple[int, int] = (64, 32), colour=(200, 40, 40)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, colour).save(out, format="JPEG")
    return out.getvalue()


def _rat_dms(value: float) -> tuple:
    d = int(value)
    m = int((value - d) * 60)
    s = round(((value - d) * 60 - m) * 60, 4)
    return (d, m, s)


def _leaky_exif(orientation: int = 6) -> Image.Exif:
    exif = Image.Exif()
    exif[0x010F] = "LeakCamMake"
    exif[0x0110] = "LeakModelX9"
    exif[0x0112] = orientation
    exif[0x8769] = {0x9003: "2001:02:03 04:05:06", 0x927C: b"SECRETMAKERNOTE"}
    exif[0x8825] = {
        1: "N",
        2: _rat_dms(ORIG_LAT),
        3: "E",
        4: _rat_dms(ORIG_LON),
    }
    return exif


def _add_segments(jpeg: bytes) -> bytes:
    """Insert an XMP APP1 and a COM segment right after SOI."""
    xmp = b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta xmlns:x='adobe:ns:meta/'>LEAKXMP</x:xmpmeta>"
    app1 = b"\xff\xe1" + struct.pack(">H", len(xmp) + 2) + xmp
    com = b"LEAKCOMMENT"
    seg = b"\xff\xfe" + struct.pack(">H", len(com) + 2) + com
    return jpeg[:2] + app1 + seg + jpeg[2:]


@pytest.fixture
def leaky_jpeg(tmp_path: Path) -> Path:
    out = io.BytesIO()
    im = Image.new("RGB", (64, 32))
    for x in range(64):
        for y in range(32):
            im.putpixel((x, y), (x * 4, y * 8, 100))
    im.save(out, format="JPEG", exif=_leaky_exif().tobytes(), quality=95)
    path = tmp_path / "leaky.jpg"
    path.write_bytes(_add_segments(out.getvalue()))
    return path


@pytest.fixture
def leaky_mpo(tmp_path: Path) -> Path:
    first = Image.new("RGB", (40, 30), (10, 200, 10))
    second = Image.new("RGB", (40, 30), (250, 0, 250))
    path = tmp_path / "leaky.mpo.jpg"
    first.save(
        path,
        format="MPO",
        save_all=True,
        append_images=[second],
        exif=_leaky_exif(orientation=1).tobytes(),
    )
    return path


REC = {
    "id": "world.photos.7",
    "source": "wm-0001",
    "file": "files/wm-0001.jpg",
    "category": "nature",
    "ts_ms": 1_750_000_000_000,
    "lat": 52.520008,
    "lon": 13.404954,
    "make": "Google",
    "model": "Pixel 8a",
}


def _dms_value(dms) -> float:
    d, m, s = (float(x) for x in dms)
    return d + m / 60 + s / 3600


# ------------------------------------------------------------- processing


def test_processing_drops_every_original_byte(leaky_jpeg: Path, tmp_path: Path) -> None:
    out = ph.process_photo(leaky_jpeg, REC, BERLIN, tmp_path / "out")
    data = out.path.read_bytes()
    for leak in LEAKS:
        assert leak not in data
    assert b"<x:xmpmeta" not in data
    assert b"2001:02:03" not in data
    assert data.count(b"\xff\xd8\xff") == 1  # no thumbnail, no second image
    gps = Image.open(out.path).getexif().get_ifd(0x8825)
    assert abs(_dms_value(gps[2]) - ORIG_LAT) > 1
    assert abs(_dms_value(gps[4]) - ORIG_LON) > 1


def test_orientation_is_applied_to_the_pixels(leaky_jpeg: Path, tmp_path: Path) -> None:
    out = ph.process_photo(leaky_jpeg, REC, BERLIN, tmp_path / "out")
    im = Image.open(out.path)
    assert im.size == (32, 64)  # orientation 6: rotated a quarter turn
    assert im.getexif()[0x0112] == 1
    assert "icc_profile" not in im.info
    assert "comment" not in im.info


def test_mpo_keeps_only_the_first_frame(leaky_mpo: Path, tmp_path: Path) -> None:
    assert Image.open(leaky_mpo).format == "MPO"
    assert leaky_mpo.read_bytes().count(b"\xff\xd8\xff") >= 2
    out = ph.process_photo(leaky_mpo, REC, BERLIN, tmp_path / "out")
    data = out.path.read_bytes()
    assert data.count(b"\xff\xd8\xff") == 1
    im = Image.open(out.path)
    assert im.format == "JPEG"
    assert getattr(im, "n_frames", 1) == 1
    r, g, b = im.convert("RGB").getpixel((20, 15))
    assert g > 150
    assert r < 60  # the green first frame, not the magenta second one
    for leak in LEAKS[:3]:
        assert leak not in data


def test_new_exif_round_trips(leaky_jpeg: Path, tmp_path: Path) -> None:
    out = ph.process_photo(leaky_jpeg, REC, BERLIN, tmp_path / "out")
    exif = Image.open(out.path).getexif()
    assert exif[0x010F] == "Google"
    assert exif[0x0110] == "Pixel 8a"
    sub = ph.subsecond_ms(REC["id"])
    taken = REC["ts_ms"] + sub
    assert out.taken_ms == taken
    local = dt.datetime.fromtimestamp(taken / 1000, BERLIN)
    stamp = local.strftime("%Y:%m:%d %H:%M:%S")
    ifd = exif.get_ifd(0x8769)
    assert exif[0x0132] == stamp
    assert ifd[0x9003] == stamp
    assert ifd[0x9004] == stamp
    assert ifd[0x9011] == "+02:00"  # CEST in June
    assert ifd[0x9291] == f"{sub:03d}"
    gps = exif.get_ifd(0x8825)
    assert gps[1] == "N"
    assert gps[3] == "E"
    assert _dms_value(gps[2]) == pytest.approx(REC["lat"], abs=1e-5)
    assert _dms_value(gps[4]) == pytest.approx(REC["lon"], abs=1e-5)
    utc = dt.datetime.fromtimestamp(taken / 1000, dt.UTC)
    assert gps[29] == utc.strftime("%Y:%m:%d")
    assert tuple(int(float(x)) for x in gps[7]) == (utc.hour, utc.minute, utc.second)
    assert float(gps[6]) == pytest.approx(ph.altitude_m(REC["lat"], REC["lon"]))
    assert out.name == f"PXL_{utc:%Y%m%d_%H%M%S}{sub:03d}.jpg"
    assert out.remote_dir == "DCIM/Camera"


def test_no_gps_without_a_position(leaky_jpeg: Path, tmp_path: Path) -> None:
    rec = {**REC, "lat": None, "lon": None}
    out = ph.process_photo(leaky_jpeg, rec, BERLIN, tmp_path / "out")
    assert not Image.open(out.path).getexif().get_ifd(0x8825)
    assert out.lat is None


def test_screenshots_carry_only_a_systemui_style_exif(tmp_path: Path) -> None:
    src = sorted(ph.SCREENSHOT_DIR.glob("ss-*.png"))[0]
    rec = {**REC, "source": "ss-0001", "file": "files/ss-0001.png",
           "category": "screenshot_like", "lat": None, "lon": None}  # fmt: skip
    out = ph.process_photo(src, rec, BERLIN, tmp_path / "out")
    im = Image.open(out.path)
    assert im.format == "PNG"
    exif = im.getexif()
    assert set(exif) == {0x0100, 0x0101, 0x8769}  # size + Exif IFD; no camera
    assert (exif[0x0100], exif[0x0101]) == im.size
    ifd = exif.get_ifd(0x8769)
    local = dt.datetime.fromtimestamp(out.taken_ms / 1000, BERLIN)
    assert ifd == {
        0x9003: local.strftime("%Y:%m:%d %H:%M:%S"),
        0x9011: local.strftime("%z")[:3] + ":" + local.strftime("%z")[3:],
        0x9291: f"{out.taken_ms % 1000:03d}",
    }
    assert not exif.get_ifd(0x8825)
    assert not {k for k in im.info if k not in ("dpi", "exif")}
    assert out.remote_dir == "Pictures/Screenshots"
    local = dt.datetime.fromtimestamp(out.taken_ms / 1000, BERLIN)
    assert out.name == f"Screenshot_{local:%Y%m%d-%H%M%S}.png"


def test_unreadable_source_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jpg"
    bad.write_bytes(b"not an image")
    with pytest.raises(ph.PhotoError):
        ph.process_photo(bad, REC, BERLIN, tmp_path / "out")


def test_plan_names_are_unique() -> None:
    recs = [{**REC, "id": f"world.photos.{i}"} for i in range(1, 40)]
    shots = [
        {**REC, "id": f"world.photos.s{i}", "category": "screenshot_like"}
        for i in range(5)
    ]
    plan = ph.plan_names(recs + shots, BERLIN)
    names = [n for n, _ in plan.values()]
    assert len(set(names)) == len(names)
    for rid, (name, ms) in plan.items():
        rec = next(r for r in recs + shots if r["id"] == rid)
        assert name == ph.device_name(rec, BERLIN, ms)


# ------------------------------------------------------------------ cache


def test_screenshots_ship_and_verify() -> None:
    pack = PackSet(user_dir=False).photos()
    shots = [p for p in pack.data["photos"] if p["id"].startswith("ss-")]
    assert len(shots) == 10
    total = sum(f.stat().st_size for f in ph.SCREENSHOT_DIR.glob("*.png"))
    assert total < 3 * 1024 * 1024
    result = ph.ensure_photos(shots, Path("/nonexistent-cache"), download=False)
    assert not result.failed
    assert set(result.paths) == {s["id"] for s in shots}


def _entry(pid: str, data: bytes, url: str | None = None) -> dict:
    return {"id": pid, "file": f"files/{pid}.jpg", "sha256": _sha(data), "url": url}


def test_local_dir_override_and_cache(tmp_path: Path, monkeypatch) -> None:
    data = _jpeg()
    local = tmp_path / "local"
    local.mkdir()
    (local / "wm-9001.jpg").write_bytes(data)
    (local / "wm-9002.jpg").write_bytes(b"tampered")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "wm-9003.jpg").write_bytes(data)
    monkeypatch.setenv(ph.PHOTOS_DIR_ENV, str(local))
    entries = [
        _entry("wm-9001", data),
        {**_entry("wm-9002", data), "url": None},
        _entry("wm-9003", data),
    ]
    result = ph.ensure_photos(entries, cache, download=False)
    assert result.paths["wm-9001"] == local / "wm-9001.jpg"
    assert result.paths["wm-9003"] == cache / "wm-9003.jpg"
    assert "wm-9002" in result.failed
    assert not result.downloaded


def test_bad_cache_file_is_deleted(tmp_path: Path) -> None:
    data = _jpeg()
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "wm-9004.jpg").write_bytes(b"truncated")
    result = ph.ensure_photos([_entry("wm-9004", data)], cache, download=False)
    assert "wm-9004" in result.failed
    assert not (cache / "wm-9004.jpg").exists()


def test_import_photos_matches_by_sha(tmp_path: Path) -> None:
    a, b = _jpeg(colour=(1, 2, 3)), _jpeg(colour=(9, 9, 9))
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "whatever.jpg").write_bytes(a)
    (folder / "b.jpg").write_bytes(b)
    (folder / "stray.txt").write_text("x")
    cache = tmp_path / "cache"
    entries = [_entry("wm-1", a), _entry("wm-2", b)]
    first = ph.import_photos(folder, cache, entries)
    assert sorted(first.imported) == ["wm-1", "wm-2"]
    assert first.unknown == ["stray.txt"]
    assert (cache / "wm-1.jpg").read_bytes() == a
    again = ph.import_photos(folder, cache, entries)
    assert sorted(again.present) == ["wm-1", "wm-2"]
    with pytest.raises(ph.PhotoError):
        ph.import_photos(tmp_path / "missing", cache, entries)


class _Server:
    """A local HTTP server: Range, 429 with Retry-After, a wrong body."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.requests: list[dict] = []
        self.throttle: dict[str, int] = {}
        srv = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:
                pass

            def do_GET(self) -> None:
                name = self.path.lstrip("/")
                srv.requests.append({"path": name, **dict(self.headers.items())})
                if srv.throttle.get(name, 0) > 0:
                    srv.throttle[name] -= 1
                    self.send_response(429)
                    self.send_header("Retry-After", "7")
                    self.end_headers()
                    return
                body = srv.files.get(name)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                rng = self.headers.get("Range")
                if rng:
                    start = int(rng.split("=")[1].split("-")[0])
                    self.send_response(206)
                    body = body[start:]
                else:
                    self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    srv = _Server({})
    yield srv
    srv.close()


class _Clock:
    def __init__(self) -> None:
        self.t = 100.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


def test_download_verifies_paces_and_uses_a_generic_agent(
    server, tmp_path: Path
) -> None:
    a, b = _jpeg(colour=(5, 5, 5)), _jpeg(colour=(6, 6, 6))
    server.files.update({"a.jpg": a, "b.jpg": b})
    clock = _Clock()
    entries = [
        _entry("wm-a", a, server.url + "a.jpg"),
        _entry("wm-b", b, server.url + "b.jpg"),
    ]
    result = ph.ensure_photos(
        entries, tmp_path / "cache", sleep=clock.sleep, clock=clock.now
    )
    assert result.downloaded == ["wm-a", "wm-b"]
    assert (tmp_path / "cache" / "wm-b.jpg").read_bytes() == b
    assert clock.sleeps == [pytest.approx(1.0)]  # one request per second
    for req in server.requests:
        assert req["User-Agent"] == ph.USER_AGENT
    assert "@" not in ph.USER_AGENT


def test_download_honours_retry_after(server, tmp_path: Path) -> None:
    data = _jpeg()
    server.files["t.jpg"] = data
    server.throttle["t.jpg"] = 2
    clock = _Clock()
    result = ph.ensure_photos(
        [_entry("wm-t", data, server.url + "t.jpg")],
        tmp_path / "cache",
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert result.paths["wm-t"].read_bytes() == data
    assert clock.sleeps.count(7.0) == 2
    assert len(server.requests) == 3


def test_download_resumes_a_part_file(server, tmp_path: Path) -> None:
    data = _jpeg((300, 300))
    server.files["r.jpg"] = data
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "wm-r.jpg.part").write_bytes(data[:1000])
    clock = _Clock()
    result = ph.ensure_photos(
        [_entry("wm-r", data, server.url + "r.jpg")],
        cache,
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert result.paths["wm-r"].read_bytes() == data
    assert server.requests[0]["Range"] == "bytes=1000-"
    assert not (cache / "wm-r.jpg.part").exists()


def test_download_rejects_a_wrong_body(server, tmp_path: Path) -> None:
    server.files["w.jpg"] = b"something else"
    clock = _Clock()
    result = ph.ensure_photos(
        [_entry("wm-w", _jpeg(), server.url + "w.jpg")],
        tmp_path / "cache",
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert "sha256 mismatch" in result.failed["wm-w"]
    assert not (tmp_path / "cache" / "wm-w.jpg").exists()


def test_download_404_fails_without_retry(server, tmp_path: Path) -> None:
    clock = _Clock()
    result = ph.ensure_photos(
        [_entry("wm-x", _jpeg(), server.url + "missing.jpg")],
        tmp_path / "cache",
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert result.failed["wm-x"] == "HTTP 404"
    assert len(server.requests) == 1


def test_retry_after_parsing() -> None:
    assert ph._retry_after(None) == 0.0
    assert ph._retry_after("12") == 12.0
    assert ph._retry_after("garbage") == 0.0
    future = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=30)
    when = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert 20 < ph._retry_after(when) <= 31
