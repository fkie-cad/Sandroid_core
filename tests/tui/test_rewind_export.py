"""``x`` Export and ``i`` Import of Rewind recordings.

The TUI export used to package ``$RAW_RESULTS_PATH/recording.getevent.txt``
and the AVD's ``tmp`` snapshot (the CLI batch's files). It now offers the
Rewind recording (``<session>/recordings/rec-*/``) and its ``sandroid_rec_*``
start point, and ``i`` imports such a file again.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from pilot_helpers import until
from textual.app import App
from textual.widgets import Button, Checkbox, Input

from sandroid.core import emulator, rewind, watchlist_store
from sandroid.tui.modals.export_modal import ExportModal

SP = "sandroid_rec_20261120_133600"
DB = "/data/data/org.x/databases/c.sqlite"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A session folder, a files root, an AVD home with a start point, and
    the CLI batch's stale ``recording.getevent.txt`` + ``tmp`` snapshot.
    """
    session = tmp_path / "session"
    monkeypatch.setattr(rewind, "recordings_root", lambda: session / "recordings")
    monkeypatch.setenv(watchlist_store.FILES_DIR_ENV, str(session / "files"))
    avds = tmp_path / "avds"
    monkeypatch.setattr(emulator, "avd_dir", lambda name: avds / f"{name}.avd")
    for snap in (SP, "tmp"):
        folder = avds / "Dev1.avd" / "snapshots" / snap
        folder.mkdir(parents=True)
        (folder / "snapshot.pb").write_bytes(b"pb-" + snap.encode())
        (folder / "ram.bin").write_bytes(b"\0" * 64)
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "recording.getevent.txt").write_text("[ 1.0] /dev/input/event1: 1 2 3\n")
    monkeypatch.setenv("RAW_RESULTS_PATH", str(raw))
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    return tmp_path


def _recording(rec_id: str = "rec-20261120-133600-ab12") -> rewind.Recording:
    """A stopped recording with its steps, file lists and one After copy."""
    rec = rewind.Recording(
        rec_id=rec_id,
        name="Recording 13:36",
        pkg="org.x",
        serial="emulator-5560",
        avd="Dev1",
        start_point={"name": SP, "saved_ok": True, "pinned": False},
        started=100.0,
        stopped=114.0,
    )
    rec.changed = [{"path": DB, "state": "changed", "size": 3}]
    rec.selected = [DB]
    folder = rewind.recording_dir(rec_id)
    folder.mkdir(parents=True)
    (folder / "recording.getevent.txt").write_text("rewind steps\n")
    (folder / "files_start.tsv").write_text("3\t1\tx\t" + DB + "\n")
    version = watchlist_store.row_dir(DB) / "v001_13-36-10"
    version.mkdir(parents=True)
    (version / "c.sqlite").write_bytes(b"new")
    rec.set_role(DB, "after", "v001_13-36-10")
    rewind.save_recording(rec)
    return rec


class Host(App):
    def __init__(self, modal: ExportModal) -> None:
        super().__init__()
        self.modal = modal
        self.results: list = []

    def on_mount(self) -> None:
        self.push_screen(self.modal, self.results.append)


def _row_text(modal: ExportModal, chk_id: str) -> str:
    chk = modal.query_one(f"#{chk_id}", Checkbox)
    status = chk.parent.query(".component-status").first()
    return f"{chk.label} | {status.render()}"


async def test_export_after_a_recording_offers_it_and_its_start_point(env):
    """``r``, ``r``, ``x``: the newest recording and its start point are
    offered; the CLI batch's getevent file and ``tmp`` snapshot are not.
    """
    _recording()
    modal = ExportModal()
    app = Host(modal)
    async with app.run_test(size=(120, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        rec_row = _row_text(modal, "chk-recording")
        sp_row = _row_text(modal, "chk-snapshot")
        assert "Recording 'Recording 13:36'" in rec_row
        assert "available" in rec_row
        assert SP in sp_row
        assert "available" in sp_row
        assert "getevent" not in rec_row
        assert "tmp" not in sp_row
        assert modal.query_one("#chk-recording", Checkbox).value
        assert modal.query_one("#name-input", Input).value == "Recording_13-36"
        modal.query_one("#btn-export", Button).press()
        await until(pilot, lambda: app.results)
    result = app.results[0]
    assert result.success
    with zipfile.ZipFile(result.export_path) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read(rewind.EXPORT_MANIFEST))
        steps = zf.read("recording/recording.getevent.txt")
    assert manifest["start_point"] == SP
    assert "recording/recording.json" in names
    assert "recording/files_start.tsv" in names
    assert steps == b"rewind steps\n"
    assert f"start_point/{SP}/snapshot.pb" in names
    assert any(n.startswith("pulls/") and n.endswith("c.sqlite") for n in names)
    # Nothing of the CLI batch: no tmp snapshot, no RAW_RESULTS_PATH file.
    assert not any("/tmp/" in n or n.startswith("tmp/") for n in names)
    assert "recording.getevent.txt" not in names


async def test_export_without_a_recording_ignores_the_stale_batch_files(env):
    """No Rewind recording: nothing is offered, even though the CLI batch's
    ``recording.getevent.txt`` and ``tmp`` snapshot exist.
    """
    modal = ExportModal()
    app = Host(modal)
    async with app.run_test(size=(120, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        rec_chk = modal.query_one("#chk-recording", Checkbox)
        sp_chk = modal.query_one("#chk-snapshot", Checkbox)
        assert not rec_chk.value
        assert rec_chk.disabled
        assert not sp_chk.value
        assert sp_chk.disabled
        assert "none yet" in _row_text(modal, "chk-recording")
        modal.query_one("#btn-export", Button).press()
        await until(pilot, lambda: modal.query_one("#error-label").has_class("visible"))
        assert "No recording yet" in str(modal.query_one("#error-label").render())
        modal.action_cancel()
        await until(pilot, lambda: app.results)
    assert app.results == [None]
    assert list((env / "out").iterdir()) == []


async def test_export_says_gone_when_the_start_point_was_deleted(env):
    rec = _recording()
    rec.start_point["saved_ok"] = False
    rec.start_point["deleted"] = True
    modal = ExportModal(rec)
    app = Host(modal)
    async with app.run_test(size=(120, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        assert "gone" in _row_text(modal, "chk-snapshot")
        assert modal.query_one("#chk-snapshot", Checkbox).disabled


def test_an_unstopped_recording_falls_back_to_the_newest_stopped(env):
    done = _recording()
    running = rewind.Recording(
        rec_id="rec-20261120-140000-cd34", name="Recording 14:00", pkg="org.x",
        serial="emulator-5560", started=200.0,
    )  # fmt: skip
    rewind.save_recording(running)
    modal = ExportModal(running)
    assert modal._rec is not None
    assert modal._rec.rec_id == done.rec_id


def test_import_round_trip_restores_recording_copies_and_start_point(env, tmp_path):
    rec = _recording()
    archive = rewind.export_recording(
        rec, tmp_path / "out" / "r.action", with_start_point=True
    )
    # Another machine: empty session, no start point in the AVD.
    other = tmp_path / "other"
    rewind_root = other / "recordings"
    shutil.rmtree(tmp_path / "avds" / "Dev1.avd" / "snapshots" / SP)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(rewind, "recordings_root", lambda: rewind_root)
        mp.setenv(watchlist_store.FILES_DIR_ENV, str(other / "files"))
        assert rewind.is_recording_export(archive)
        got, note = rewind.import_recording(archive)
        assert got.rec_id == rec.rec_id
        assert got.changed == rec.changed
        assert got.start_point_name == SP
        assert got.pinned
        assert "added to Dev1" in note
        loaded = rewind.load_recording(got.rec_id)
        assert loaded is not None
        assert loaded.role_version(DB, "after") == "v001_13-36-10"
        steps = rewind.recording_dir(got.rec_id) / "recording.getevent.txt"
        assert steps.read_text() == "rewind steps\n"
        copy = watchlist_store.row_dir(DB) / "v001_13-36-10" / "c.sqlite"
        assert copy.read_bytes() == b"new"
        snap = tmp_path / "avds" / "Dev1.avd" / "snapshots" / SP / "snapshot.pb"
        assert snap.read_bytes() == b"pb-" + SP.encode()
        # A second import keeps the first: a new id.
        again, _ = rewind.import_recording(archive)
        assert again.rec_id != got.rec_id


def test_import_without_start_point_says_review_only(env, tmp_path):
    rec = _recording()
    archive = rewind.export_recording(rec, tmp_path / "out" / "r.action")
    shutil.rmtree(tmp_path / "avds" / "Dev1.avd" / "snapshots" / SP)
    shutil.rmtree(rewind.recording_dir(rec.rec_id))
    got, note = rewind.import_recording(archive)
    assert got.start_point_name is None
    assert "Review works, Rewind does not" in note


def test_import_rejects_files_that_are_not_an_export(env, tmp_path):
    bad = tmp_path / "bad.action"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("recording.getevent.txt", "x")
    assert not rewind.is_recording_export(bad)
    with pytest.raises(ValueError, match="Not an exported recording"):
        rewind.import_recording(bad)
    evil = tmp_path / "evil.action"
    data = _recording().to_dict()
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr(rewind.EXPORT_MANIFEST, json.dumps({"format": "sandroid-rewind"}))
        zf.writestr("recording/recording.json", json.dumps(data))
        zf.writestr("pulls/../../escaped.txt", "x")
    assert rewind.recording_dir(data["rec_id"]).exists()
    got, _ = rewind.import_recording(evil)
    assert got.rec_id != data["rec_id"]
    assert not (env / "escaped.txt").exists()
    assert not (env / "session" / "escaped.txt").exists()


def test_i_imports_an_exported_recording_and_makes_it_current(
    env, tmp_path, monkeypatch
):
    """The TUI ``i`` (ImportResultsCommand) recognises the ``.action`` file."""
    from sandroid.commands.base import CommandContext
    from sandroid.commands.io_commands import ImportResultsCommand
    from sandroid.tui import controller_registry
    from sandroid.tui.controllers.recording_controller import RecordingController

    rec = _recording()
    archive = rewind.export_recording(rec, tmp_path / "out" / "r.action")
    ctl = RecordingController()
    monkeypatch.setattr(controller_registry, "_recording_controller", ctl)
    cmd = ImportResultsCommand()

    async def path(_ctx):
        return str(archive)

    cmd._get_import_path = path
    ctx = CommandContext(action_queue=object())
    result = asyncio.run(cmd._import_from_json(ctx))
    assert result.success, result.message
    assert "imported" in result.message
    assert "Press p to review it" in result.message
    assert ctl.recording is not None
    assert ctl.recording.rec_id == result.data["rec_id"]
    assert ctl.recording.rec_id != rec.rec_id  # the original is still here
