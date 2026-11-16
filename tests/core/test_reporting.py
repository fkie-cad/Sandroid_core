"""Tests for reporting & evidence documentation.

Covers ``core/run_report.py`` (plain-text sanitising, run metadata, hash
manifest, finalisation, ``report_from_folder``), ``core/pdf_report.py``
(env-free, cwd-independent rendering), ``core/timeline_generator.py`` and the
SHA-256 hashing in ``FileExtractionService``. No device access: adb is faked.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
from datetime import datetime
from pathlib import Path

import pytest

from sandroid.core import pdf_report, run_report, timeline_generator
from sandroid.services.file_extraction_service import FileExtractionService

ESC = "\x1b"


class FakeAdb:
    """Records commands and answers from a dict; ``pull`` writes a file."""

    def __init__(self, answers=None, pull_bytes=b"APKDATA"):
        self.answers = answers or {}
        self.pull_bytes = pull_bytes
        self.calls: list[str] = []

    def send_adb_command(self, command):
        self.calls.append(command)
        if command.startswith("pull "):
            _, _src, dst = command.split(" ", 2)
            Path(dst).write_bytes(self.pull_bytes)
            return "", ""
        return self.answers.get(command, ""), ""


DEVICE_ANSWERS = {
    "get-serialno": "emulator-5554\n",
    "shell getprop ro.build.version.release": "15\n",
    "shell getprop ro.build.version.sdk": "35\n",
    "shell getprop ro.build.fingerprint": "google/sdk_gphone64/emu64a:15/X/1:userdebug/dev-keys\n",
    "shell getprop ro.build.version.security_patch": "2024-09-05\n",
    "shell getprop ro.product.model": "sdk_gphone64_arm64\n",
    "shell getprop ro.boot.qemu.avd_name": "SanDroid_-_API_35\n",
}


def _results(tmp_path: Path | None = None) -> dict:
    return {
        "Device Name": "SanDroid_-_API_35",
        "Emulator relative action timestamp": 1794828274,
        "Action Duration": 19,
        "Changed Files": [
            "/data/data/a/plain.db",
            {
                "/data/data/de.fkie.ground_truth/files/GroundTruth.xml": [
                    "\tNot enough data for intra file analysis."
                ]
            },
            {
                "/data/data/de.fkie.ground_truth/databases/GroundTruth.db": [
                    f"\t[{ESC}[32mINSERT{ESC}[0m] Table [t] row [1,'<x> & y']",
                    (
                        "\t\\[[success]INSERT[/success]] Table \\[t] row "
                        "\\[[success]2,'b'[/success]] has been added"
                    ),
                ]
            },
        ],
        "New Files": ["/data/data/de.fkie.ground_truth/files/file_2.txt"],
        "Deleted Files": [],
        "Processes": ["[kworker/0:0+events]", f"{ESC}[1mbold{ESC}[0m"],
        "Listening Sockets": [],
        "Network": ["fkie.fraunhofer.de."],
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
            "Timeline Data": [
                [
                    {
                        "id": "/data/data/de.fkie.ground_truth/files/GroundTruth.xml",
                        "name": "GroundTruth.xml",
                        "seconds_after_start": 4,
                        "timeline_color": "#1A535C",
                    },
                    {
                        "id": "/data/data/de.fkie.ground_truth/files/GroundTruth.xml",
                        "name": "GroundTruth.xml",
                        "seconds_after_start": 8,
                        "timeline_color": "#1A535C",
                    },
                    {
                        "id": "/data/data/de.fkie.ground_truth/files/file_2.txt",
                        "name": "file_2.txt",
                        "seconds_after_start": 3,
                        "timeline_color": "#1A535C",
                    },
                    {
                        "id": "/data/system/noise.pb",
                        "name": "noise.pb",
                        "seconds_after_start": 1,
                        "timeline_color": "#1A535C",
                    },
                ]
            ],
        },
    }


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """No RESULTS_PATH/RAW_RESULTS_PATH and a cwd without ``assets/``."""
    monkeypatch.delenv("RESULTS_PATH", raising=False)
    monkeypatch.delenv("RAW_RESULTS_PATH", raising=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    return elsewhere


def _paragraph_texts(flowables) -> list[str]:
    """All Paragraph texts from a list of flowables (incl. table cells)."""
    out: list[str] = []
    for f in flowables:
        if isinstance(f, (list, tuple)):
            out.extend(_paragraph_texts(f))
        elif hasattr(f, "_cellvalues"):
            for row in f._cellvalues:
                out.extend(_paragraph_texts([c for c in row if c is not None]))
        elif hasattr(f, "text") and isinstance(getattr(f, "text", None), str):
            out.append(f.text)
    return out


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------


class TestPlainText:
    def test_strip_ansi(self):
        assert run_report.strip_ansi(f"{ESC}[32mINSERT{ESC}[0m") == "INSERT"
        assert run_report.strip_ansi(f"a{ESC}]8;;http://x{ESC}\\b") == "ab"

    def test_strip_markup_unescapes_and_keeps_data_brackets(self):
        line = "\t\\[[success]INSERT[/success]] Table \\[t] row \\[[error]1[/error]]"
        assert run_report.strip_markup(line) == "\t[INSERT] Table [t] row [1]"
        assert run_report.strip_markup("[kworker/0:0+events]") == "[kworker/0:0+events]"
        assert run_report.strip_markup("[/info bold][info]x[/]") == "x"

    def test_sanitize_results_is_pure_and_plain(self):
        data = _results()
        cleaned = run_report.sanitize_results(data)
        dumped = json.dumps(cleaned)
        assert ESC not in json.dumps(cleaned, ensure_ascii=False)
        assert "\\u001b" not in dumped
        assert "[success]" not in dumped
        assert cleaned["Processes"] == ["[kworker/0:0+events]", "bold"]
        diff = cleaned["Changed Files"][2][
            "/data/data/de.fkie.ground_truth/databases/GroundTruth.db"
        ]
        assert diff[1] == "\t[INSERT] Table [t] row [2,'b'] has been added"
        # input untouched
        assert "[success]" in json.dumps(data)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_device_metadata_from_fake_adb(self):
        meta = run_report.collect_device_metadata(
            FakeAdb(DEVICE_ANSWERS), "SanDroid_-_API_35"
        )
        assert meta == {
            "device_name": "SanDroid_-_API_35",
            "serial": "emulator-5554",
            "avd_name": "SanDroid_-_API_35",
            "android_version": "15",
            "api_level": 35,
            "build_fingerprint": "google/sdk_gphone64/emu64a:15/X/1:userdebug/dev-keys",
            "security_patch": "2024-09-05",
            "model": "sdk_gphone64_arm64",
        }

    def test_device_metadata_avd_fallback_to_emu_console(self):
        answers = {"emu avd name": "Pixel_6\r\nOK\r\n"}
        meta = run_report.collect_device_metadata(FakeAdb(answers))
        assert meta["avd_name"] == "Pixel_6"
        assert meta["api_level"] is None

    def test_device_metadata_survives_broken_adb(self):
        class Broken:
            def send_adb_command(self, command):
                raise OSError("no adb")

        # The device did not answer: the label (e.g. the config default
        # "Pixel_6_Pro_API_31") is not recorded as if it were confirmed.
        meta = run_report.collect_device_metadata(Broken(), "x")
        assert meta["device_name"] is None
        assert meta["serial"] is None
        assert run_report.collect_device_metadata(None)["serial"] is None
        # No adb at all (offline tooling): only the label is known.
        assert run_report.collect_device_metadata(None, "x")["device_name"] == "x"

    def test_device_metadata_replaces_unconfirmed_label(self):
        """A config-default label never survives when the device says otherwise."""
        meta = run_report.collect_device_metadata(
            FakeAdb(DEVICE_ANSWERS), "Pixel_6_Pro_API_31"
        )
        assert meta["device_name"] == "SanDroid_-_API_35"
        physical = {
            "get-serialno": "1A2B3C\n",
            "shell getprop ro.product.model": "Pixel 6 Pro\n",
        }
        meta = run_report.collect_device_metadata(FakeAdb(physical), "Pixel_6_Pro")
        assert meta["device_name"] == "Pixel_6_Pro"  # resolve_device_name form
        meta = run_report.collect_device_metadata(FakeAdb(physical), "Other")
        assert meta["device_name"] == "Pixel_6_Pro"

    def test_finalize_run_without_device_writes_unknown_device(self, tmp_path):
        """N2: no answering device -> Device Name "unknown", device_name null."""

        class Silent:
            def send_adb_command(self, command):
                return "", "adb: device 'emulator-5999' not found"

        outcome = run_report.finalize_run(
            tmp_path,
            {"Device Name": "Pixel_6_Pro_API_31", "New Files": []},
            adb=Silent(),
            write_manifest=False,
        )
        doc = json.loads(outcome.results_json.read_text(encoding="utf-8"))
        assert doc["Device Name"] == "unknown"
        device = doc[run_report.RUN_METADATA_KEY]["device"]
        assert device["device_name"] is None
        assert device["serial"] is None
        assert "Pixel_6" not in json.dumps(doc)

    def test_run_settings_override_config_settings(self):
        """Metadata records the settings used, not the config file's wishes."""
        from sandroid.analysis.run_config import RunConfig
        from sandroid.config.schema import SandroidConfig

        cfg = SandroidConfig(
            analysis={
                "capture_network": True,
                "capture_processes": True,
                "avoid_strong_noise_filter": False,
            }
        )
        used = RunConfig(network=False, processes=False, noise_filter=False)
        meta = run_report.build_run_metadata(
            config=cfg, run_settings=run_report.describe_run_settings(used)
        )
        analysis = meta["settings"]["analysis"]
        assert analysis["capture_network"] is False
        assert analysis["capture_processes"] is False
        assert analysis["avoid_strong_noise_filter"] is True
        assert meta["run_settings"]["capture_network"] is False

    def test_run_settings_record_replay_settle(self):
        """A replayed run records the post-replay settle time it used."""
        from types import SimpleNamespace

        Player = type("Player", (), {})
        used = SimpleNamespace(action=Player(), replay_settle_seconds=12)
        assert run_report.describe_run_settings(used)["replay_settle_seconds"] == 12
        plain = SimpleNamespace(action=None, replay_settle_seconds=12)
        assert "replay_settle_seconds" not in run_report.describe_run_settings(plain)

    def test_host_metadata(self):
        from sandroid._version import __version__

        host = run_report.collect_host_metadata()
        assert host["sandroid_version"] == __version__
        assert host["python_version"]
        assert "frida" in host["tool_versions"]
        assert "friTap" in host["tool_versions"]

    def test_settings_are_sanitized(self):
        from sandroid.config.schema import SandroidConfig

        cfg = SandroidConfig(
            ai={"api_key": "sk-SECRET"},
            analysis={"hash_files": True},
            credentials={"custom_api_keys": {"vt": "VTSECRET"}},
        )
        settings = run_report.sanitize_settings(cfg)
        dumped = json.dumps(settings)
        assert "sk-SECRET" not in dumped
        assert "VTSECRET" not in dumped
        assert "ai" not in settings
        assert "credentials" not in settings
        assert settings["analysis"]["hash_files"] is True

    def test_redact_secret_keys(self):
        assert run_report._redact(
            {"api_key": "x", "n": 1, "nested": {"token": "t"}}
        ) == {
            "api_key": "<redacted>",
            "n": 1,
            "nested": {"token": "<redacted>"},
        }

    def test_build_run_metadata_iso_timestamps(self):
        meta = run_report.build_run_metadata(
            adb=FakeAdb(DEVICE_ANSWERS),
            device_name="dev",
            started_at=datetime(2026, 11, 16, 12, 0, 0),
            ended_at="2026-11-16T12:00:30",
        )
        started = datetime.fromisoformat(meta["started_at"])
        ended = datetime.fromisoformat(meta["ended_at"])
        assert started.tzinfo is not None
        assert ended.tzinfo is not None
        assert meta["duration_seconds"] == 30
        assert meta["device"]["serial"] == "emulator-5554"
        assert meta["hash_algorithms"] == ["md5", "sha256"]


# ---------------------------------------------------------------------------
# JSON + manifest
# ---------------------------------------------------------------------------


class TestResultsJson:
    def test_write_results_json_adds_metadata_and_keeps_keys(self, tmp_path):
        data = _results()
        out = run_report.write_results_json(data, tmp_path / "sandroid.json", {"k": 1})
        written = json.loads(out.read_text(encoding="utf-8"))
        assert set(data) <= set(written)
        assert written[run_report.RUN_METADATA_KEY] == {"k": 1}
        assert ESC not in out.read_text(encoding="utf-8")


class TestManifest:
    def _tree(self, root: Path):
        (root / "raw" / "network_trace_pull").mkdir(parents=True)
        (root / "raw" / "network_trace_pull" / "trace.pcap").write_bytes(b"pcap")
        (root / "sandroid.json").write_text("{}")
        (root / "sandroid.log").write_text("live log")

    def test_write_and_verify(self, tmp_path, caplog):
        self._tree(tmp_path)
        with caplog.at_level(logging.INFO, logger="sandroid.core.run_report"):
            info = run_report.write_hash_manifest(tmp_path)
        manifest = json.loads(info.manifest_path.read_text())
        paths = {f["path"]: f for f in manifest["files"]}
        assert set(paths) == {"raw/network_trace_pull/trace.pcap", "sandroid.json"}
        assert (
            paths["raw/network_trace_pull/trace.pcap"]["sha256"]
            == hashlib.sha256(b"pcap").hexdigest()
        )
        assert (
            paths["raw/network_trace_pull/trace.pcap"]["md5"]
            == hashlib.md5(b"pcap").hexdigest()
        )
        assert manifest["excluded"][0]["path"] == "sandroid.log"
        sums = info.sha256sums_path.read_text().splitlines()
        assert any(line.endswith("  manifest.json") for line in sums)
        assert (
            info.sha256sums_sha256
            == hashlib.sha256(info.sha256sums_path.read_bytes()).hexdigest()
        )
        assert info.sha256sums_sha256 in caplog.text

        check = run_report.verify_hash_manifest(tmp_path)
        assert check.ok
        assert not check.unlisted

        (tmp_path / "sandroid.log").write_text("more log")  # live file: ignored
        (tmp_path / "sandroid.json").write_text('{"tampered": 1}')
        (tmp_path / "raw" / "network_trace_pull" / "trace.pcap").unlink()
        (tmp_path / "new.txt").write_text("x")
        check = run_report.verify_hash_manifest(tmp_path)
        assert not check.ok
        assert check.mismatched == ["sandroid.json"]
        assert check.missing == ["raw/network_trace_pull/trace.pcap"]
        assert check.unlisted == ["new.txt"]

    def test_verify_without_manifest(self, tmp_path):
        assert run_report.verify_hash_manifest(tmp_path).present is False


# ---------------------------------------------------------------------------
# Hashing in FileExtractionService
# ---------------------------------------------------------------------------


def _service() -> FileExtractionService:
    svc = FileExtractionService.__new__(FileExtractionService)
    svc._logger = logging.getLogger("test")
    return svc


class TestServiceHashing:
    def test_calculate_hashes_nested_tree(self, tmp_path):
        raw = tmp_path / "raw"
        for slot, rel, content in (
            ("new_pull", "data/data/p/files/new.txt", b"new"),
            ("new_pull", "data/data/p/files/noisy.txt", b"noise"),
            ("noise_pull", "data/data/p/files/noisy.txt", b"noise"),
            ("first_pull", "data/data/p/db/a.db", b"old"),
            ("second_pull", "data/data/p/db/a.db", b"cur"),
            ("second_pull", "data/data/p/db/b.db", b"only-new"),
        ):
            path = raw / slot / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        h = _service().calculate_hashes(str(raw))
        md5 = lambda b: hashlib.md5(b).hexdigest()  # noqa: E731
        sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
        # Files also seen in the dry run (noise_pull) are hashed too: their
        # copies are part of the evidence (A10).
        assert h["new_file_hashes"] == {
            "/data/data/p/files/new.txt": md5(b"new"),
            "/data/data/p/files/noisy.txt": md5(b"noise"),
        }
        assert h["new_file_hashes_sha256"] == {
            "/data/data/p/files/new.txt": sha(b"new"),
            "/data/data/p/files/noisy.txt": sha(b"noise"),
        }
        assert h["changed_file_hashes(old,new)"] == {
            "/data/data/p/db/a.db": [md5(b"old"), md5(b"cur")],
            "/data/data/p/db/b.db": ["n/a", md5(b"only-new")],
        }
        assert h["changed_file_hashes_sha256(old,new)"]["/data/data/p/db/a.db"] == [
            sha(b"old"),
            sha(b"cur"),
        ]

    def test_calculate_hashes_env_fallback(self, tmp_path, monkeypatch):
        (tmp_path / "new_pull").mkdir()
        (tmp_path / "new_pull" / "f").write_bytes(b"x")
        monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
        assert list(_service().calculate_hashes()["new_file_hashes"]) == ["/f"]

    def test_pull_and_hash_apks_sha256(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
        adb = FakeAdb(
            {
                "shell pm list packages": "package:com.example\n",
                "shell pm path com.example": "package:/data/app/base.apk\n",
            }
        )
        svc = _service()
        svc._get_adb = lambda: adb
        result = svc.pull_and_hash_apks()
        assert result["apk_hashes"] == [
            f"com.example: {hashlib.md5(b'APKDATA').hexdigest()}"
        ]
        assert result["apk_hashes_sha256"] == [
            f"com.example: {hashlib.sha256(b'APKDATA').hexdigest()}"
        ]
        assert not list(tmp_path.glob("*.apk"))

    def test_pull_and_hash_apks_split_apks(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
        adb = FakeAdb(
            {
                "shell pm list packages": "package:com.split\npackage:com.gone\n",
                "shell pm path com.split": (
                    "package:/data/app/x/base.apk\n"
                    "package:/data/app/x/split_config.arm64_v8a.apk\n"
                ),
                "shell pm path com.gone": "",
            }
        )
        svc = _service()
        svc._get_adb = lambda: adb
        result = svc.pull_and_hash_apks()
        md5 = hashlib.md5(b"APKDATA").hexdigest()
        assert result["apk_hashes"] == [
            f"com.split: {md5}",
            f"com.split/split_config.arm64_v8a.apk: {md5}",
            "com.gone: n/a",
        ]
        pulls = [c for c in adb.calls if c.startswith("pull ")]
        assert pulls[0].startswith("pull /data/app/x/base.apk ")
        assert pulls[1].startswith("pull /data/app/x/split_config.arm64_v8a.apk ")
        assert not list(tmp_path.glob("*.apk"))


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TestTimeline:
    def test_events_are_averaged_filtered_and_deterministic(self):
        events = timeline_generator.build_timeline_events(_results())
        assert events == [
            ("file_2.txt", 3.0, timeline_generator.NEW_COLOR, "new"),
            ("GroundTruth.xml", 6.0, "#1A535C", "changed"),
        ]
        assert events == timeline_generator.build_timeline_events(_results())

    def test_parse_timeline_writes_next_to_json(self, tmp_path, clean_env):
        js = tmp_path / "sandroid.json"
        js.write_text(json.dumps(_results()))
        png = timeline_generator.parse_timeline(js)
        assert png == str(tmp_path.resolve() / "timeline.png")
        assert Path(png).stat().st_size > 0

    def test_parse_timeline_without_events(self, tmp_path):
        js = tmp_path / "sandroid.json"
        js.write_text(json.dumps({"Device Name": "x", "Action Duration": 1}))
        assert timeline_generator.parse_timeline(js) is None

    def test_spread_labels_no_overlap_and_in_range(self):
        ys = timeline_generator._spread_labels([5.0] * 30 + [19.0] * 10, 20.0)
        gap = 20.0 / (timeline_generator.MAX_LABELS_PER_SIDE + 2)
        assert all(b - a >= gap - 1e-9 for a, b in itertools.pairwise(ys))
        assert max(ys) <= 20.0


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


class TestPdf:
    def test_assets_load_independent_of_cwd(self, clean_env):
        assert pdf_report._asset_bytes(pdf_report.FRAUNHOFER_LOGO)[:2] == b"\xff\xd8"
        assert pdf_report._asset_bytes(pdf_report.SANDROID_LOGO)[:4] == b"\x89PNG"

    def test_generate_without_env_and_screenshots_untouched(self, tmp_path, clean_env):
        from PIL import Image

        result_dir = tmp_path / "run"
        shots = result_dir / "raw" / "screenshots"
        shots.mkdir(parents=True)
        Image.new("RGB", (60, 120), (10, 20, 30)).save(shots / "s1.png")
        data = _results()
        data[run_report.RUN_METADATA_KEY] = run_report.build_run_metadata(
            adb=FakeAdb(DEVICE_ANSWERS), device_name="SanDroid_-_API_35"
        )
        (result_dir / "sandroid.json").write_text(json.dumps(data))

        report = pdf_report.PDFReport(
            str(result_dir / "out.pdf"), str(result_dir / "sandroid.json")
        )
        assert (result_dir / "out.pdf").read_bytes()[:5] == b"%PDF-"
        assert (result_dir / "timeline.png").exists()
        # Screenshot evidence is not converted/deleted.
        assert sorted(p.name for p in shots.iterdir()) == ["s1.png"]

        texts = "\n".join(_paragraph_texts(report.elements))
        assert ESC not in texts
        assert "[success]" not in texts
        # Regression: the last changed-files row used to lose its file name
        # (stray SPAN), e.g. GroundTruth.xml.
        assert "/data/data/de.fkie.ground_truth/databases/GroundTruth.db" in texts
        assert "/data/data/de.fkie.ground_truth/files/GroundTruth.xml" in texts
        assert "[2,&#x27;b&#x27;]" in texts or "[2,'b']" in texts
        assert "&lt;x&gt; &amp; y" in texts  # escaped, not parsed as markup
        assert "emulator-5554" in texts
        assert "API level 35" in texts
        assert "e" * 64 in texts  # APK SHA-256
        assert "SHA-256: " + "a" * 64 in texts

    def test_old_json_without_metadata_or_other_data(self, tmp_path, clean_env):
        js = tmp_path / "sandroid.json"
        js.write_text(json.dumps({"Device Name": "x", "Action Duration": 0}))
        out = pdf_report.generate_pdf_report(tmp_path)
        assert out == tmp_path / run_report.DEFAULT_PDF_NAME
        assert out.read_bytes()[:5] == b"%PDF-"

    def test_huge_diffs_never_exceed_a_page(self, tmp_path, clean_env):
        """P2-H3: the Wikipedia run's PDF failed with a 15718 pt table row.

        Shape taken from the real bundle: app_icons.db has 5 diff lines of up
        to 26,286 characters (icon BLOBs), wikipedia.db a 53-line diff.
        """
        data = _results()
        blob_lines = [
            f"[INSERT] Table [icons] row [{i},'pkg',x'{'89504e47' * 3300}']"
            for i in range(5)
        ]
        wiki_lines = [
            f"[INSERT] Table [Category] row [{i},2026,11,'Category:Example "
            f"category number {i} with a long name','en',1] has been added"
            for i in range(53)
        ]
        many_lines = [f"Updated attribute: /root/pkg[{i}] to 'x'" for i in range(260)]
        data["Changed Files"] = [
            {
                "/data/data/com.google.android.apps.nexuslauncher/databases/app_icons.db": blob_lines
            },
            {"/data/data/org.wikipedia/databases/wikipedia.db": wiki_lines},
            {"/data/system/users/0/package-restrictions.xml": many_lines},
        ]
        data["Network"] = ["x" * 50_000]
        (tmp_path / "sandroid.json").write_text(json.dumps(data))

        report = pdf_report.PDFReport(
            str(tmp_path / "out.pdf"), str(tmp_path / "sandroid.json")
        )
        assert (tmp_path / "out.pdf").read_bytes()[:5] == b"%PDF-"
        assert report.degraded_sections == []
        texts = "\n".join(_paragraph_texts(report.elements))
        # All 53 wikipedia.db lines are in the report (continuation rows).
        assert "Category:Example category number 52" in texts
        assert "continued, part 2/" in texts
        # Long lines and over-long diffs are shortened, visibly.
        assert "more characters]" in texts
        assert "60 more line(s) not shown — see sandroid.json / raw/" in texts

    def test_cell_paragraph_height_is_bounded(self):
        style = pdf_report.ParagraphStyle(
            "t", fontName="Helvetica", fontSize=7.5, leading=9.5
        )
        para = pdf_report.bounded_lines_paragraph(["word " * 4000] * 30, style, 260)
        assert para.wrap(260, 1e9)[1] <= pdf_report.MAX_CELL_HEIGHT
        cells = pdf_report.split_lines_into_cells(["y " * 300] * 300, style, 260)
        assert all(c.wrap(260, 1e9)[1] <= pdf_report.MAX_CELL_HEIGHT for c in cells)
        assert "100 more line(s) not shown" in cells[-1].text

    def test_unlayoutable_section_degrades_instead_of_failing(
        self, tmp_path, clean_env, monkeypatch
    ):
        """A section that cannot be laid out is replaced by a note."""

        def too_tall(self, key, title=None):
            self.sectionTitle(title or key)
            if key == "Processes":  # ReportLab drawing error (negative width)
                self.elements.append(pdf_report.Table([[pdf_report.Spacer(10, 9)]]))
            else:  # LayoutError: one row taller than a page
                self.elements.append(
                    pdf_report.Table([[pdf_report.Spacer(10, 5000)]], colWidths=[100])
                )

        def broken(self):
            raise ValueError("bad data")

        monkeypatch.setattr(pdf_report.PDFReport, "generalTableMaker", too_tall)
        monkeypatch.setattr(pdf_report.PDFReport, "APKTableMaker", broken)
        (tmp_path / "sandroid.json").write_text(json.dumps(_results()))
        report = pdf_report.PDFReport(
            str(tmp_path / "out.pdf"), str(tmp_path / "sandroid.json")
        )
        assert (tmp_path / "out.pdf").read_bytes()[:5] == b"%PDF-"
        titles = {t for t, _ in report.degraded_sections}
        assert "APKs & Hashes" in titles
        assert "New Files" in titles
        assert "Processes" in titles
        assert any("layout error" in r for _, r in report.degraded_sections)
        texts = "\n".join(_paragraph_texts(report.elements))
        assert "could not be laid out in the PDF" in texts
        # Unaffected sections are still there.
        assert "GroundTruth.db" in texts

    def test_find_results_json(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            pdf_report.find_results_json(tmp_path)
        (tmp_path / "other.json").write_text("[]")
        (tmp_path / "custom.json").write_text('{"Device Name": "d"}')
        assert pdf_report.find_results_json(tmp_path).name == "custom.json"


# ---------------------------------------------------------------------------
# Finalisation and report-from
# ---------------------------------------------------------------------------


class TestFinalize:
    def test_finalize_run_end_to_end(self, tmp_path, clean_env):
        from sandroid.config.schema import SandroidConfig

        cfg = SandroidConfig(ai={"api_key": "sk-SECRET"})
        outcome = run_report.finalize_run(
            tmp_path,
            _results(),
            adb=FakeAdb(DEVICE_ANSWERS),
            config=cfg,
            started_at="2026-11-16T12:00:00+01:00",
            mode="test",
            generate_pdf=True,
        )
        assert outcome.errors == []
        text = outcome.results_json.read_text(encoding="utf-8")
        assert "sk-SECRET" not in text
        assert ESC not in text
        meta = json.loads(text)[run_report.RUN_METADATA_KEY]
        assert meta["device"]["build_fingerprint"].startswith("google/")
        assert meta["mode"] == "test"
        assert outcome.pdf is not None
        assert outcome.pdf.exists()
        listed = {
            f["path"]
            for f in json.loads(outcome.manifest.manifest_path.read_text())["files"]
        }
        assert {"sandroid.json", run_report.DEFAULT_PDF_NAME, "timeline.png"} <= listed
        assert run_report.verify_hash_manifest(tmp_path).ok

    def test_finalize_pdf_failure_is_reported_not_raised(self, tmp_path, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("render failed")

        monkeypatch.setattr(pdf_report, "generate_pdf_report", boom)
        outcome = run_report.finalize_run(tmp_path, _results(), generate_pdf=True)
        assert outcome.pdf is None
        assert outcome.errors == ["pdf: render failed"]
        assert outcome.manifest is not None

    @staticmethod
    def _snapshot(folder: Path) -> dict[str, bytes]:
        return {
            p.relative_to(folder).as_posix(): p.read_bytes()
            for p in sorted(folder.rglob("*"))
            if p.is_file()
        }

    def _sealed_run(self, tmp_path) -> Path:
        outcome = run_report.finalize_run(tmp_path, _results(), generate_pdf=True)
        assert outcome.errors == []
        assert outcome.pdf is not None
        return tmp_path

    def test_report_from_unsealed_folder_writes_default_pdf_and_manifest(
        self, tmp_path, clean_env
    ):
        (tmp_path / "sandroid.json").write_text(json.dumps(_results()))
        first = run_report.report_from_folder(tmp_path)
        assert first.check.present is False
        assert first.pdf == tmp_path / run_report.DEFAULT_PDF_NAME
        assert first.manifest is not None
        assert not (tmp_path / "timeline.png").exists()  # nothing extra added
        assert run_report.verify_hash_manifest(tmp_path).ok

    def test_report_from_sealed_folder_never_overwrites(self, tmp_path, clean_env):
        """P2-H4: intact bundle -> new PDF name + addendum, originals untouched."""
        root = self._sealed_run(tmp_path)
        before = self._snapshot(root)

        outcome = run_report.report_from_folder(root)
        assert outcome.check.ok
        assert outcome.manifest is None
        assert outcome.pdf.name.startswith("Sandroid_Forensic_Report_regenerated_")
        assert outcome.pdf.name.endswith("Z.pdf")
        after = self._snapshot(root)
        # Every original file is byte-identical, incl. PDF, timeline, SHA256SUMS.
        assert {k: after[k] for k in before} == before
        added = set(after) - set(before)
        assert added == {outcome.pdf.name, outcome.addendum.name}
        assert outcome.addendum.name.startswith("SHA256SUMS.addendum-")
        lines = outcome.addendum.read_text().splitlines()
        assert lines == [
            f"{run_report.sha256_file(outcome.pdf)}  {outcome.pdf.name}",
            f"{run_report.sha256_file(root / 'SHA256SUMS')}  SHA256SUMS",
        ]
        check = run_report.verify_hash_manifest(root)
        assert check.ok
        assert check.unlisted == []

        # A second regeneration in the same second gets yet another name.
        again = run_report.report_from_folder(root)
        assert again.pdf != outcome.pdf
        assert again.addendum != outcome.addendum
        assert run_report.verify_hash_manifest(root).ok

        # Tampering with a regenerated PDF is detected through the addendum.
        outcome.pdf.write_bytes(b"%PDF-forged")
        assert run_report.verify_hash_manifest(root).mismatched == [outcome.pdf.name]

    def test_report_from_tampered_folder_writes_nothing(self, tmp_path, clean_env):
        """P2-H4: verification runs first; a mismatch aborts before writing."""
        root = self._sealed_run(tmp_path)
        (root / "sandroid.json").write_text(json.dumps(_results()) + " ")
        before = self._snapshot(root)
        with pytest.raises(run_report.EvidenceVerificationError) as info:
            run_report.report_from_folder(root)
        assert info.value.check.mismatched == ["sandroid.json"]
        assert "Nothing was written" in str(info.value)
        assert self._snapshot(root) == before

    def test_report_from_refuses_existing_output(self, tmp_path, clean_env):
        root = self._sealed_run(tmp_path)
        with pytest.raises(FileExistsError):
            run_report.report_from_folder(
                root, output_pdf=root / run_report.DEFAULT_PDF_NAME
            )

    def test_cli_report_from(self, tmp_path, clean_env):
        from click.testing import CliRunner

        from sandroid.cli import main

        (tmp_path / "sandroid.json").write_text(json.dumps(_results()))
        res = CliRunner().invoke(main, ["--report-from", str(tmp_path)])
        assert res.exit_code == 0, res.output
        assert (tmp_path / run_report.DEFAULT_PDF_NAME).exists()
        assert (tmp_path / "SHA256SUMS").exists()
        assert (
            "Report regeneration requested"
            in (tmp_path / "sandroid_report.log").read_text()
        )

        res = CliRunner().invoke(main, ["--report-from", str(tmp_path)])
        assert res.exit_code == 0, res.output
        log = (tmp_path / "sandroid_report.log").read_text()
        assert "Recorded in SHA256SUMS.addendum-" in log

    def test_cli_report_from_tampered_exits_2_and_writes_nothing(
        self, tmp_path, clean_env
    ):
        from click.testing import CliRunner

        from sandroid.cli import main

        root = self._sealed_run(tmp_path)
        (root / "sandroid.json").write_text("{}")
        before = self._snapshot(root)
        res = CliRunner().invoke(main, ["--report-from", str(root)])
        assert res.exit_code == 2, res.output
        assert "verification FAILED" in res.output
        assert "PDF report written" not in res.output
        assert self._snapshot(root) == before
