"""Headless Textual Pilot smoke tests for the Runs lens (DiffsView).

No physical device and no full ``App(MainScreen, ...)`` needed: DiffsView
only talks to ``core/run_history.py`` (an on-disk JSON store, pointed at a
pytest ``tmp_path`` via ``RESULTS_PATH``) and
``sandroid.core.toolbox.Toolbox.device_name`` (which has a deterministic
default, ``"Pixel_6_Pro_API_31"``, even with no device connected). A minimal
single-widget host App is enough to exercise mount/compose, table rendering,
the gated auto-select/unread-marker rule for ``on_new_run``, the Inspector
content, compare, and the REVIEW scope (``v`` / ``L``) inside the full app.

Detail loading goes through a real background thread (``run_worker`` inside
``DiffsView._run_bg``, since ``is_running`` is True once mounted under
Pilot), so assertions that depend on it use ``_wait_for`` to poll with real
wall-clock pauses rather than assuming synchronous completion.
"""

from __future__ import annotations

import pytest
from pilot_helpers import boot, settle, until
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Input

from sandroid.core import run_history
from sandroid.tui.widgets.diffs_view import DiffsView

DEVICE = "Pixel_6_Pro_API_31"  # SessionStateService's deterministic default


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    # run_history v2 resolves its storage root config-first
    # (get_config().paths.results_path), so setting RESULTS_PATH alone is no
    # longer enough. Pin the resolver itself (run_bundle shares it) instead
    # of faking get_config(), so the full SandroidTUI tests below still get
    # their real config.
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    monkeypatch.setattr(run_history, "_results_path", lambda: tmp_path)
    return tmp_path


def _make_record(
    run_id: str, label: str = "Run · 10:00", **overrides
) -> run_history.RunRecord:
    # v2 records carry an absolute in-bundle recording_path + bundle_dir.
    bundle_dir = f"/tmp/sandroid-test/runs/{run_id}"
    fields = {
        "schema_version": run_history.SCHEMA_VERSION,
        "run_id": run_id,
        "label": label,
        "recorded_at": "2026-07-21T10:00:00",
        "completed_at": "2026-07-21T10:05:00",
        "device_name": DEVICE,
        "recording_path": f"{bundle_dir}/recording.txt",
        "bundle_dir": bundle_dir,
        "duration": 10,
        "error": None,
        "changed_files": [{"/data/data/app/db.sqlite": ["- old", "+ new"]}],
        "new_files": ["/data/new.txt"],
        "deleted_files": [],
        "counts": {"changed": 1, "new": 1, "deleted": 0},
    }
    fields.update(overrides)
    return run_history.RunRecord(**fields)


def _save(run_id: str, **kwargs) -> run_history.RunRecord:
    record = _make_record(run_id, **kwargs)
    run_history.save_run(record)
    return record


class _DiffsHarness(App):
    """Minimal single-widget host app for DiffsView."""

    def compose(self) -> ComposeResult:
        yield DiffsView(id="files-diffs")


@pytest.mark.asyncio
async def test_empty_state_before_any_run() -> None:
    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summaries == [] or view._detail_record is None)
        assert view.glance_fragment() == "Diffs — no runs yet"
        table = view.query_one("#runs-table", DataTable)
        assert table.row_count == 0
        assert not table.display
        assert view.query_one("#runs-empty").display


@pytest.mark.asyncio
async def test_mount_loads_existing_runs_and_selects_newest() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)

        assert view._selected_run_id == "20260101_000001_bbbbbb"
        assert view._detail_record.run_id == "20260101_000001_bbbbbb"
        assert view.glance_fragment() == "Diffs — 2 runs"

        table = view.query_one("#runs-table", DataTable)
        assert table.row_count == 2
        # Newest first, numbered chronologically (oldest = #1).
        first = table.get_row_at(0)
        assert str(first[0]) == "2"
        assert "Run B" in str(first[1])


@pytest.mark.asyncio
async def test_on_new_run_auto_selects_when_viewing_latest() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._selected_run_id == "20260101_000000_aaaaaa")

        _save("20260101_000001_bbbbbb", label="Run B")
        view.on_new_run("20260101_000001_bbbbbb")

        await until(
            pilot,
            lambda: view._detail_record is not None
            and view._detail_record.run_id == "20260101_000001_bbbbbb",
        )
        assert view._selected_run_id == "20260101_000001_bbbbbb"
        assert "20260101_000001_bbbbbb" not in view._unread_run_ids


@pytest.mark.asyncio
async def test_on_new_run_does_not_steal_selection_from_older_run() -> None:
    """Viewing an older run: a new run arrives as unread, selection untouched."""
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)

        # Navigate to the OLDER run (not the latest).
        view._select_run("20260101_000000_aaaaaa")
        await until(
            pilot,
            lambda: view._detail_record is not None
            and view._detail_record.run_id == "20260101_000000_aaaaaa",
        )

        _save("20260101_000002_cccccc", label="Run C")
        view.on_new_run("20260101_000002_cccccc")
        await until(pilot, lambda: "20260101_000002_cccccc" in view._unread_run_ids)
        await settle(pilot)

        # Selection must NOT have moved to the new run.
        assert view._selected_run_id == "20260101_000000_aaaaaa"
        assert "20260101_000002_cccccc" in view._unread_run_ids
        assert "unread" in view.glance_fragment()


@pytest.mark.asyncio
async def test_new_run_cursor_stays_on_older_run_row() -> None:
    """The table is newest-first: a new row on top must not move the cursor
    off the older run the user is looking at.
    """
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await until(pilot, lambda: view._detail_record is not None)
        view.focus()
        await pilot.press("down")
        await until(pilot, lambda: view._selected_run_id == "20260101_000000_aaaaaa")
        _save("20260101_000002_cccccc", label="Run C")
        view.on_new_run("20260101_000002_cccccc")
        # The reload runs on a worker: wait for the new row, not a fixed time.
        await until(pilot, lambda: table.row_count == 3)
        await settle(pilot)
        assert view._cursor_run_id() == "20260101_000000_aaaaaa"
        assert "●" in str(table.get_row_at(0)[1])


@pytest.mark.asyncio
async def test_rename_run_persists_via_run_history() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)

        # Exercise the same worker path action_rename_run() would use after
        # the InputModal resolves, without driving the modal's keystrokes.
        view._rename_run_bg("20260101_000000_aaaaaa", "Renamed run")
        await until(
            pilot,
            lambda: run_history.load_run("20260101_000000_aaaaaa").label
            == "Renamed run",
        )
        assert view._current_label("20260101_000000_aaaaaa") == "Renamed run"


class _RPHarness(App):
    """Host app with *app-level* r/p bindings, like ``SandroidTUI``.

    Record/Play used to be panel-scoped to the Diffs view, which made them
    undiscoverable (``r`` on the main screen did nothing). They are global
    app bindings now; DiffsView no longer declares its own r/p.
    """

    BINDINGS = [("r", "record", "Record"), ("p", "play", "Play")]

    def __init__(self) -> None:
        super().__init__()
        self.record_calls = 0
        self.play_calls = 0

    def compose(self) -> ComposeResult:
        yield Input(id="other-widget")
        yield DiffsView(id="files-diffs")

    def action_record(self) -> None:
        self.record_calls += 1

    def action_play(self) -> None:
        self.play_calls += 1


def test_diffs_view_does_not_shadow_global_record_play() -> None:
    keys = {(b[0] if isinstance(b, tuple) else b.key) for b in DiffsView.BINDINGS}
    assert "r" not in keys
    assert "p" not in keys


@pytest.mark.asyncio
async def test_rp_reach_app_from_diffs_but_not_from_text_input() -> None:
    """r/p fire the app actions with the Diff panel focused.

    Typing them into an Input still just types (Input consumes printable keys).
    """
    app = _RPHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summaries is not None)

        app.query_one("#other-widget", Input).focus()
        await pilot.pause()
        await pilot.press("r", "p")
        await pilot.pause()
        assert app.record_calls == 0
        assert app.play_calls == 0
        assert app.query_one("#other-widget", Input).value == "rp"

        view.focus()
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        assert app.record_calls == 1
        assert app.play_calls == 1


@pytest.mark.asyncio
async def test_delete_run_removes_it_and_selects_remaining() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)
        assert view._selected_run_id == "20260101_000001_bbbbbb"

        view._delete_run_bg("20260101_000001_bbbbbb")
        await until(
            pilot,
            lambda: view._selected_run_id == "20260101_000000_aaaaaa",
        )

        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run("20260101_000001_bbbbbb")
        assert len(view._summaries) == 1


# --------------------------------------------------------------------------
# Runs lens: table facts, Inspector, compare
# --------------------------------------------------------------------------


def _write_results(run_id: str, *, steps: int = 0, replays: int = 1) -> None:
    """A run folder's ``sandroid.json`` like ``run_report.finalize_run``'s."""
    import json

    run_dir = run_history.run_dir_for_scope(run_id)
    doc = {
        "Network": ["app-measurement.com", "graph.facebook.com", "api.fit.pro"],
        "Run Metadata": {
            "run_settings": {
                "number_of_runs": replays,
                "replay_settle_seconds": 8,
                "network_reset_after_snapshot": "airplane",
                "capture_network": True,
            }
        },
    }
    if steps:
        doc["Run Errors"] = {
            "status": "completed with errors",
            "fatal": None,
            "steps": [
                {"step": f"Step{i}", "run": 1, "error": "boom"} for i in range(steps)
            ],
        }
    (run_dir / run_history.RESULTS_JSON_NAME).write_text(json.dumps(doc))


@pytest.mark.asyncio
async def test_table_row_shows_changes_errors_and_batch() -> None:
    _save("20260101_000000_aaaaaa", label="Consent · accept")
    _write_results("20260101_000000_aaaaaa", replays=3)
    _save("20260101_000001_bbbbbb", label="Consent · refuse")
    _write_results("20260101_000001_bbbbbb", steps=2)
    _save("20260101_000002_cccccc", label="Workout", error="Device disconnected")

    app = _DiffsHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await until(pilot, lambda: len(view._facts) == 3)
        await pilot.pause()
        rows = [[str(c) for c in table.get_row_at(i)] for i in range(3)]
        assert [r[0] for r in rows] == ["3", "2", "1"]
        assert "✕ aborted" in rows[0][4]
        assert "2 files · 3 hosts" in rows[1][4]
        assert "⚠ 2 errors" in rows[1][4]
        assert "×3" in rows[2][3]
        assert len(table.columns) == 5


@pytest.mark.asyncio
async def test_inspector_content_has_summary_changes_report_tabs() -> None:
    from rich.console import Console

    from sandroid.core import run_report

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Consent · refuse")
    _write_results(run_id, steps=1)
    run_report.write_hash_manifest(run_history.run_dir_for_scope(run_id))

    def text(sections) -> str:
        console = Console(width=200, record=True)
        for heading, body in sections:
            console.print(heading)
            console.print(body)
        return console.export_text()

    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(
            pilot, lambda: view._detail_record is not None and run_id in view._facts
        )
        view.inspect_selected()  # starts the evidence check
        await until(pilot, lambda: view._evidence.get(run_id) == "verified")
        content = view.inspect_selected()
        assert content.key == ("run", run_id)
        assert content.title == "Consent · refuse"
        assert [name for name, _ in content.tabs] == [
            "Summary",
            "Changes",
            "Report",
            "Privacy",
        ]

        summary, changes, report, _privacy = (text(s) for _, s in content.tabs)
        assert "8 s after replay" in summary
        assert "airplane" in summary
        assert "Step0" in summary  # the run's step error
        assert "verified" in summary
        assert "/data/data/app/db.sqlite" in changes
        assert "/data/new.txt" in changes
        assert "Hosts (3)" in changes
        assert str(run_history.run_dir_for_scope(run_id)) in report


def test_compare_sections_list_files_only_in_each_run() -> None:
    a = _make_record(
        "20260101_000000_aaaaaa",
        changed_files=[{"/data/shared.db": ["x"]}],
        new_files=["/data/only_a.txt"],
    )
    b = _make_record(
        "20260101_000001_bbbbbb",
        changed_files=[{"/data/shared.db": ["y"]}],
        new_files=["/data/only_b.txt", "/data/also_b.txt"],
    )
    sections = DiffsView.compare_sections(a, b, numbers=(1, 2))
    head = str(sections[0][1])
    assert "2 files only in #2" in head
    assert "1 only in #1" in head
    assert "1 in both" in head
    by_title = dict(sections[1:])
    assert "only_b.txt" in str(by_title["Only in #2 · Run · 10:00"])
    assert "only_a.txt" in str(by_title["Only in #1 · Run · 10:00"])


# --------------------------------------------------------------------------
# Full app: Enter → Inspector, REVIEW scope (v / L), REC forces LIVE
# --------------------------------------------------------------------------


async def _boot_runs_lens(pilot, app, labels: list[str]):
    """Boot SandroidTUI, save runs for its device, land on the Runs lens."""
    ms = await boot(app, pilot)
    view = ms.query_one("#runs-panel", DiffsView)
    device = view._current_device_name()
    ids = [f"2026010{i}_100000_00000{i}" for i in range(len(labels))]
    for run_id, label in zip(ids, labels, strict=True):
        _save(run_id, label=label, device_name=device)
    await pilot.press("4")
    await settle(pilot)
    view._reload_index()
    view.focus()
    await until(pilot, lambda: view._detail_record is not None)
    return ms, view, ids


def _sandroid_app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


@pytest.mark.asyncio
async def test_enter_inspects_run_and_v_reviews_it_until_l() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, ids = await _boot_runs_lens(
            pilot, app, ["Consent · accept", "Consent · refuse"]
        )
        newest = ids[-1]
        await pilot.press("enter")
        await settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.key == ("run", newest)
        assert [t for t, _ in ms.inspector_content.tabs] == [
            "Summary",
            "Changes",
            "Report",
            "Privacy",
        ]
        # The open Inspector follows the cursor.
        await pilot.press("down")
        await until(pilot, lambda: ms.inspector_content.key == ("run", ids[0]))
        await pilot.press("escape")
        await settle(pilot)

        assert ms.check_action("back_to_live", ()) is False
        await pilot.press("v")
        await settle(pilot)
        assert ms.scope == run_history.scope_for_run(ids[0])
        assert ms.query_one("#shell-header").pill_text == "◆ REVIEW #1 Consent · accept"
        assert view._scope_run_id == ids[0]
        assert "◆" in str(view.query_one("#runs-table").get_row_at(1)[1])
        assert ms.check_action("back_to_live", ()) is True

        await pilot.press("3")  # another lens: L works from there too
        await settle(pilot)
        await pilot.press("L")
        await settle(pilot)
        assert ms.scope is None
        assert ms.query_one("#shell-header").pill_text == "● LIVE"

        await pilot.press("4")
        await settle(pilot)
        await pilot.press("v")
        await settle(pilot)
        assert ms.scope is not None
        await pilot.press("v")  # same run again: back to LIVE
        await settle(pilot)
        assert ms.scope is None


@pytest.mark.asyncio
async def test_recording_or_replay_forces_live_scope() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, _view, ids = await _boot_runs_lens(pilot, app, ["Run A"])
        for flag in ("recording", "replaying"):
            ms.set_scope(run_history.scope_for_run(ids[0]), "Run A")
            await settle(pilot)
            assert ms.scope is not None
            app._set_status_bar_mode(**{flag: True})
            await settle(pilot)
            assert ms.scope is None
            app._set_status_bar_mode(**{flag: False})


@pytest.mark.asyncio
async def test_delete_key_confirms_and_leaves_review_scope() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, ids = await _boot_runs_lens(pilot, app, ["Run A", "Run B"])
        await pilot.press("v")
        await settle(pilot)
        assert ms.scope == run_history.scope_for_run(ids[-1])

        await pilot.press("delete")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("n")  # No: nothing happens
        await settle(pilot)
        assert run_history.load_run(ids[-1]).label == "Run B"

        await pilot.press("delete")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("y")
        await until(pilot, lambda: len(view._summaries) == 1)
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(ids[-1])
        assert ms.scope is None


@pytest.mark.asyncio
async def test_new_run_after_play_lands_in_runs_lens_and_is_selected() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, _ids = await _boot_runs_lens(pilot, app, ["Run A"])
        await pilot.press("1")
        await settle(pilot)
        ms.open_files_tab("files-diffs")  # what Play-press does (legacy id)
        await settle(pilot)
        assert ms.active_lens == "runs"

        new_id = "20260201_100000_ffffff"
        _save(new_id, label="Run B", device_name=view._current_device_name())
        app._notify_diffs_new_run(new_id)
        await until(pilot, lambda: view._selected_run_id == new_id)
        assert view._cursor_run_id() == new_id
        assert view.query_one("#runs-table").row_count == 2


@pytest.mark.asyncio
async def test_table_refresh_keeps_a_pending_cursor_move() -> None:
    """Facts arriving between a cursor move and its RowHighlighted event must
    not snap the cursor back to the previous selection.
    """
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await until(pilot, lambda: view._detail_record is not None)
        assert view._selected_run_id == "20260101_000001_bbbbbb"
        # Move the cursor and refresh before the highlight event is handled.
        table.move_cursor(row=1, animate=False)
        view._apply_facts({})
        assert view._cursor_run_id() == "20260101_000000_aaaaaa"
        await until(pilot, lambda: view._selected_run_id == "20260101_000000_aaaaaa")


# --------------------------------------------------------------------------
# Fix round 3c (tester 4): rename input, evidence re-check, compare, identity
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rename_input_shows_the_old_label_selected_so_typing_replaces() -> None:
    """M-30: the collapsed input hid the prefill and typing appended to it."""
    from sandroid.tui.modals import InputModal

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Run 2 · 18:34")
    app = _DiffsHarness()
    async with app.run_test(size=(120, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)
        view.focus()
        await pilot.pause()
        await pilot.press("n")
        await until(pilot, lambda: isinstance(app.screen, InputModal))
        await settle(pilot)
        field = app.screen.query_one("#input-field", Input)
        assert field.region.height == 3  # a real text row between the borders
        assert field.value == "Run 2 · 18:34"
        assert "#1" in app.screen.title_text
        for ch in "B replay":
            await pilot.press("space" if ch == " " else ch)
        assert field.value == "B replay"
        # R4-N3: the confirm named the run only by its label.
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        message = str(app.screen.message_text)
        assert "#1" in message
        assert run_id in message


@pytest.mark.asyncio
async def test_input_modal_without_select_all_appends() -> None:
    """The other InputModal users keep the cursor at the end (complete a path)."""
    from sandroid.tui.modals import InputModal

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(InputModal(title="Path", default="/data/data/"))

    app = _Host()
    async with app.run_test(size=(120, 30)) as pilot:
        await settle(pilot)
        field = app.screen.query_one("#input-field", Input)
        await pilot.press("x")
        assert field.value == "/data/data/x"
        assert field.region.height == 3


@pytest.mark.asyncio
async def test_evidence_is_rechecked_when_a_sealed_file_changes() -> None:
    """M-34: the evidence check was cached per session; a tampered file kept
    showing "✓ verified".
    """
    from sandroid.core import run_report

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Run A")
    run_dir = run_history.run_dir_for_scope(run_id)
    (run_dir / "recording.txt").write_text("1 /dev/input/event1 0 0 0\n")
    run_report.write_hash_manifest(run_dir)

    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)
        view.inspect_selected()
        await until(pilot, lambda: view._evidence.get(run_id) == "verified")

        with open(run_dir / "recording.txt", "a", encoding="utf-8") as f:
            f.write("x")  # one byte appended after sealing
        view.inspect_selected()  # Enter again: always re-verified
        await until(
            pilot, lambda: view._evidence.get(run_id, "").startswith("modified:")
        )
        text = str(view._evidence_text(run_id))
        assert "1 file(s) changed since sealing" in text
        assert "recording.txt" in text

        # restored (same bytes): verified again on the next look
        (run_dir / "recording.txt").write_text("1 /dev/input/event1 0 0 0\n")
        view.inspect_selected()
        await until(pilot, lambda: view._evidence.get(run_id) == "verified")


def test_bundle_fingerprint_changes_with_size_or_mtime(tmp_path) -> None:
    from sandroid.tui.widgets.diffs_view import bundle_fingerprint

    (tmp_path / "a").write_text("1")
    fp = bundle_fingerprint(tmp_path)
    assert bundle_fingerprint(tmp_path) == fp
    (tmp_path / "a").write_text("12")
    assert bundle_fingerprint(tmp_path) != fp


def test_compare_treats_background_suffixes_as_the_same_host() -> None:
    """M-32: "youtubei.googleapis.com. (also seen in background: 2 queries)"
    and "youtubei.googleapis.com." showed up as both + and -.
    """
    from sandroid.tui.widgets.diffs_view import host_key

    assert host_key(
        "youtubei.googleapis.com. (also seen in background: 2 queries)"
    ) == ("youtubei.googleapis.com")
    a = _make_record("20260101_000000_aaaaaa")
    b = _make_record("20260101_000001_bbbbbb")
    facts = {
        a.run_id: {"hosts": ["youtubei.googleapis.com.", "a.example."]},
        b.run_id: {
            "hosts": [
                "youtubei.googleapis.com. (also seen in background: 2 queries)",
                "b.example.",
            ]
        },
    }
    sections = DiffsView.compare_sections(a, b, facts, numbers=(1, 2))
    hosts = str(dict(sections)["Hosts"])
    assert "youtubei" not in hosts
    assert "+ b.example" in hosts
    assert "− a.example" in hosts


def test_replay_divergence_thresholds() -> None:
    from sandroid.tui.widgets.diffs_view import replay_divergence

    assert replay_divergence(22, 107) == ["22 vs 107 files"]
    assert replay_divergence(0, 74) == ["0 vs 74 files"]
    assert replay_divergence(22, 30) == []  # within normal jitter
    assert replay_divergence(3, 9) == []  # too few files to call it
    assert replay_divergence(10, 10, 4, 15) == ["4 vs 15 hosts"]


@pytest.mark.asyncio
async def test_runs_of_the_same_recording_that_diverge_are_flagged() -> None:
    """M-28: A (0 new files) and B (74) replayed the same recording; nothing
    said so. The table, the Inspector and = compare flag it now.
    """
    many = [f"/data/data/org.wikipedia/files/{i}" for i in range(40)]
    _save("20260101_000000_aaaaaa", label="A", new_files=[], counts={"changed": 2})
    _save(
        "20260101_000001_bbbbbb",
        label="B",
        new_files=many,
        counts={"changed": 2, "new": len(many)},
    )
    _save("20260101_000002_cccccc", label="other recording", counts={"new": 60})
    for run_id, rec in (
        ("20260101_000000_aaaaaa", "same"),
        ("20260101_000001_bbbbbb", "same"),
        ("20260101_000002_cccccc", "different"),
    ):
        path = run_history.run_dir_for_scope(run_id) / "recording.txt"
        path.write_text(f"1 /dev/input/event1 0 0 0 {rec}\n")

    app = _DiffsHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await until(pilot, lambda: len(view._facts) == 3)
        await pilot.pause()
        rows = [[str(c) for c in table.get_row_at(i)] for i in range(3)]
        assert "≠ #1" in rows[1][4]  # B (#2) diverges from A (#1)
        assert "≠ #2" in rows[2][4]
        assert "≠" not in rows[0][4]  # another recording: not compared
        summary = view._summary_sections(
            view._summary("20260101_000000_aaaaaa"),
            view._facts["20260101_000000_aaaaaa"],
        )
        from rich.console import Console

        console = Console(width=200, record=True)
        for _heading, body in summary:
            console.print(body)
        out = console.export_text()
        assert "same recording as #2" in out
        assert "diverges from #2" in out

    a = run_history.load_run("20260101_000000_aaaaaa")
    b = run_history.load_run("20260101_000001_bbbbbb")
    facts = {r: DiffsView._read_facts(r) for r in (a.run_id, b.run_id)}
    sections = dict(DiffsView.compare_sections(a, b, facts, numbers=(1, 2)))
    assert "replays diverged" in str(sections["Replay consistency"])


@pytest.mark.asyncio
async def test_took_is_the_run_time_and_dialogs_name_the_run_number() -> None:
    """L4: "Took" showed the recording length; L11/M-31: the delete dialog
    identified the run only by its label and undersold what it removes.
    """
    from sandroid.tui.modals import ConfirmModal

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Run A", duration=93)  # 10:00 -> 10:05 (5 min run)
    app = _DiffsHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await until(pilot, lambda: view._detail_record is not None)
        assert str(table.get_row_at(0)[3]).startswith("5m 00s")
        view.focus()
        await pilot.press("delete")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        message = app.screen.message_text
        assert "#1 'Run A'" in message
        assert run_id in message
        assert "whole bundle" in message
        await pilot.press("n")


@pytest.mark.asyncio
async def test_scope_pill_follows_the_recorder_and_the_player() -> None:
    """M-25: REC never showed (the Record dialog was the active screen, so the
    update was dropped). M-26: REPLAY stayed after the run ended.
    """
    from sandroid.tui.modals import ConfirmModal

    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        header = ms.query_one("#shell-header")
        assert header.pill_text == "● LIVE"

        app.push_screen(ConfirmModal(title="stand-in for the Record dialog"))
        await settle(pilot)
        app._set_status_bar_mode(recording=True)  # capture started
        assert header.pill_text == "● REC"
        app._set_status_bar_mode(recording=False)  # stopped / cancelled
        assert header.pill_text == "● LIVE"
        app.pop_screen()
        await settle(pilot)

        app._set_status_bar_mode(replaying=True)
        assert header.pill_text == "● REPLAY"
        app._set_replay_phase("replay 1/2")
        assert header.pill_text == "● REPLAY · replay 1/2"
        app._set_replay_phase("dry run")
        assert header.pill_text == "● REPLAY · dry run"
        assert "dry run" in str(
            ms.query_one("#runs-panel").query_one("#runs-empty").render()
        )
        app._set_status_bar_mode(replaying=False)  # done, failed or stopped
        app._set_replay_phase(None)
        assert header.pill_text == "● LIVE"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 30), (160, 45)])
async def test_arrows_switch_inspector_tabs_at_every_size(size) -> None:
    """R2-N4: ←/→ switched the Inspector's tabs at 100x30 / 160x45 but
    scrolled the Runs table sideways at 80x24, where it overflowed.
    """
    app = _sandroid_app()
    async with app.run_test(size=size) as pilot:
        ms, view, _ids = await _boot_runs_lens(
            pilot, app, ["Consent · accept with a long label", "Consent · refuse"]
        )
        await pilot.press("enter")
        await settle(pilot)
        assert ms.inspector_is_open
        table = view.query_one("#runs-table", DataTable)
        table.focus()
        await settle(pilot)
        inspector = ms.query_one("#inspector")
        start = inspector.tab_index
        await pilot.press("right")
        await settle(pilot)
        assert inspector.tab_index == (start + 1) % 4
        assert table.scroll_x == 0
        await pilot.press("left")
        await settle(pilot)
        assert inspector.tab_index == start
        # A text input keeps its caret keys.
        field = Input(value="abc", id="probe-input")
        await ms.mount(field)
        field.focus()
        await settle(pilot)
        field.cursor_position = 3
        await pilot.press("left")
        assert inspector.tab_index == start
        assert field.cursor_position == 2


@pytest.mark.asyncio
async def test_inspector_recording_is_the_recordings_own_length() -> None:
    """R4-N4: "Recording 1m 33s" for an 80 s recording (93 s is the replay
    window: replay + settle).
    """
    from rich.console import Console

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Bookmark", duration=93)
    run_dir = run_history.run_dir_for_scope(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "recording.txt").write_text(
        "1794955664890 /dev/input/event1 3 53 100\n"
        "1794955745064 /dev/input/event1 3 53 120\n",
        encoding="utf-8",
    )
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(
            pilot, lambda: view._detail_record is not None and run_id in view._facts
        )
        content = view.inspect_selected()
        console = Console(width=200, record=True)
        for heading, body in dict(content.tabs)["Summary"]:
            console.print(heading)
            console.print(body)
        summary = console.export_text()
        assert "1m 20s" in summary
        assert "1m 33s" not in summary


# ---------------------------------------------------------------------------
# Privacy tab (identity profile values found during the run)
# ---------------------------------------------------------------------------


def _at(minute: int) -> float:
    from datetime import datetime

    return datetime(2026, 7, 21, 10, minute).astimezone().timestamp()


def _privacy_run_hits():
    from privacy_fakes import file_hit, flow_hit

    return [
        flow_hit("flow-1", t=_at(1), tl_seq=41),
        flow_hit("flow-2", t=_at(2), tl_seq=42),  # same finding again
        flow_hit(
            "flow-3",
            "Email",
            "Email",
            party="first",
            recipient="fittrack.de",
            host="api.fittrack.de",
            part="url",
            transform="value",
            t=_at(3),
        ),
        file_hit("/data/data/app/shared_prefs/p.xml", t=_at(4), version="v002"),
        flow_hit("flow-9", "GPS", "GPS", t=_at(30)),  # after the run
    ]


def _text_of(sections) -> str:
    from io import StringIO

    from rich.console import Console

    console = Console(width=200, file=StringIO(), color_system=None)
    for heading, body in sections:
        if heading:
            console.print(heading)
        console.print(body)
    return console.file.getvalue()


@pytest.mark.asyncio
async def test_privacy_tab_lists_the_runs_findings_by_recipient(monkeypatch) -> None:
    import privacy_fakes

    privacy_fakes.install(monkeypatch, _privacy_run_hits())
    run_id = "20260101_000000_bbbbbb"
    _save(run_id, label="Consent · accept")
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(run_id) is not None)
        content = view._run_content(run_id)
        privacy = dict(content.tabs)["Privacy"]
        text = _text_of(privacy)
        lines = [ln.rstrip() for ln in text.splitlines()]
        assert lines[0] == ("2 profile values sent to 2 recipients or stored")
        assert "Meta  third party" in lines
        assert any(
            ln.startswith("  Advertising ID, sha256 of the lower-case value, "
                          "request body, 10:01:00")
            for ln in lines
        )  # fmt: skip
        assert "fittrack.de  first party" in lines
        assert any(ln.startswith("  Email, as is, URL path") for ln in lines)
        assert "Stored in shared_prefs/p.xml  app" in lines
        assert any(ln.startswith("  Email, as is") for ln in lines)
        assert "GPS" not in text  # found after the run
        assert text.count("Advertising ID") == 1  # first hit per finding
        assert not set(privacy_fakes.GLYPHS) & set(text)
        # { } and clicks pick a finding (other tabs ignore them).
        content.keys["right_curly_bracket"]("Summary")
        assert view._privacy_pick.get(run_id, 0) == 0
        content.keys["right_curly_bracket"]("Privacy")
        assert view._privacy_pick[run_id] == 1
        _body, line_map = view._privacy_render(
            run_id, view._privacy_findings(view._summary(run_id))[0]
        )
        last = max(i for i in line_map if i is not None)
        assert content.click("Privacy", 2 + line_map.index(last))
        assert view._privacy_pick[run_id] == last
        assert not content.click("Privacy", 2)  # a recipient heading


@pytest.mark.asyncio
async def test_privacy_tab_empty_states_and_jump(monkeypatch) -> None:
    import privacy_fakes

    fake = privacy_fakes.install(monkeypatch, [], active=False)
    run_id = "20260101_000000_cccccc"
    _save(run_id)
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(run_id) is not None)
        # The run does not name its session: say what was (not) looked at.
        text = _text_of(dict(view._run_content(run_id).tabs)["Privacy"])
        assert "No identity profile was active in this session." in text
        assert "Findings for runs of other sessions are not loaded." in text
        fake.is_active = True
        text = _text_of(dict(view._run_content(run_id).tabs)["Privacy"])
        assert "No profile values found for this run in this session" in text
        assert "Findings for runs of other sessions are not loaded." in text
        # J: flow -> Network, file -> Files, else the timeline line.
        calls: list = []

        class _Lens:
            def reveal_flow(self, fid, record=None):
                calls.append(("net", fid, record["host"]))
                return True

            def reveal(self, path, version=None):
                calls.append(("files", path, version))
                return False

            def select_seq(self, seq):
                calls.append(("timeline", seq))
                return True

        class _Screen:
            def switch_lens(self, lens_id):
                calls.append(("switch", lens_id))

            def lens_widget(self, lens_id):
                return _Lens()

        monkeypatch.setattr(view, "_main_screen", lambda: _Screen())
        from privacy_fakes import file_hit, flow_hit

        assert view.privacy_jump(flow_hit("flow-1"))
        assert view.privacy_jump(file_hit("/data/data/a/p.xml", tl_seq=7))
        assert calls == [
            ("switch", "network"),
            ("net", "flow-1", "graph.facebook.com"),
            ("switch", "files"),
            ("files", "/data/data/a/p.xml", "v001_x"),
            ("switch", "timeline"),
            ("timeline", 7),
        ]


@pytest.mark.asyncio
async def test_privacy_tab_reads_a_past_sessions_findings(
    monkeypatch, tmp_path
) -> None:
    """A run of another session (its record names that session's timeline
    folder) shows that session's findings, read off the UI thread, instead
    of a false "nothing found"; a run of the live session with nothing
    found says so plainly.
    """
    import json

    import privacy_fakes
    from privacy_fakes import flow_hit

    from sandroid.services.privacy_scan import FOLDER_NAME, HITS_FILE

    past = tmp_path / "session-old" / "device"
    (past / FOLDER_NAME).mkdir(parents=True)
    old_hit = flow_hit("flow-old", t=_at(2))
    (past / FOLDER_NAME / HITS_FILE).write_text(json.dumps(old_hit.to_json()) + "\n")
    live = tmp_path / "session-new" / "device"
    fake = privacy_fakes.install(monkeypatch, [], active=True, folder=live)
    old_run, new_run = "20260101_000000_dddddd", "20260101_000001_eeeeee"
    _save(old_run, timeline_folder=str(past))
    _save(new_run, timeline_folder=str(live))
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(old_run) is not None)
        assert view._summary(old_run)["timeline_folder"] == str(past)

        def privacy_text(run_id: str) -> str:
            return _text_of(dict(view._run_content(run_id).tabs)["Privacy"])

        privacy_text(old_run)  # starts the read (a worker thread)
        await until(pilot, lambda: str(past) in view._privacy_other)
        text = privacy_text(old_run)
        assert "1 profile value sent to 1 recipient" in text
        assert "Advertising ID" in text
        assert "No profile values" not in text
        assert "No profile values found in this run." in privacy_text(new_run)
        assert fake.hits() == []  # the live session's records are untouched


@pytest.mark.asyncio
async def test_privacy_tab_includes_the_end_of_run_sweep(monkeypatch) -> None:
    """The sweep runs after the run's end; its records carry the run id."""
    import privacy_fakes
    from privacy_fakes import file_hit

    run_id = "20260101_000000_ffffff"
    hits = [
        file_hit("/data/data/app/shared_prefs/s.xml", t=_at(20), run_id=run_id),
        file_hit("/data/data/app/shared_prefs/o.xml", t=_at(21), run_id="other"),
    ]
    privacy_fakes.install(monkeypatch, hits)
    _save(run_id)
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(run_id) is not None)
        text = _text_of(dict(view._run_content(run_id).tabs)["Privacy"])
        assert "s.xml" in text
        assert "o.xml" not in text


@pytest.mark.asyncio
async def test_privacy_tab_two_runs_leaking_the_same_value(monkeypatch) -> None:
    """Both runs show a value both leaked (the timeline line is written once
    per session; the tab counts every hit). The run's recording window
    counts as well as its Play.
    """
    import privacy_fakes
    from privacy_fakes import flow_hit

    first, second = "20260101_000000_aaaaab", "20260101_000001_aaaaac"
    hits = [
        flow_hit("flow-rec", t=_at(1), tl_seq=41),  # recording of run 1
        flow_hit("flow-p1", t=_at(5)),  # Play of run 1
        flow_hit("flow-p2", t=_at(22)),  # Play of run 2 (no line any more)
    ]
    privacy_fakes.install(monkeypatch, hits)
    _save(
        first,
        recorded_at="2026-07-21T10:04:00",
        completed_at="2026-07-21T10:10:00",
        record_window=[_at(0), _at(3)],
    )
    _save(second, recorded_at="2026-07-21T10:20:00", completed_at="2026-07-21T10:25:00")
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(second) is not None)
        assert view._summary(first)["record_window"] == [_at(0), _at(3)]
        for run_id, at in ((first, "10:01:00"), (second, "10:22:00")):
            text = _text_of(dict(view._run_content(run_id).tabs)["Privacy"])
            assert "1 profile value sent to 1 recipient" in text, run_id
            # The first hit in the run's scope (the recording's, for run 1).
            assert f"request body, {at}" in text, (run_id, text)


@pytest.mark.asyncio
async def test_privacy_tab_names_each_stored_file_once(monkeypatch) -> None:
    """Stored findings are grouped per file, the group names the file, and a
    file seen under an alias path is one group.
    """
    import privacy_fakes
    from privacy_fakes import file_hit

    run_id = "20260101_000000_abcdef"
    hits = [
        file_hit("/data/data/app/shared_prefs/p.xml", t=_at(1)),
        file_hit("/data/user/0/app/shared_prefs/p.xml", t=_at(2), version="v002"),
        file_hit("/data/data/app/databases/x.db", "Phone", "Phone", t=_at(3)),
    ]
    privacy_fakes.install(monkeypatch, hits)
    _save(run_id)
    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._summary(run_id) is not None)
        text = _text_of(dict(view._run_content(run_id).tabs)["Privacy"])
        lines = [ln.rstrip() for ln in text.splitlines()]
        heads = [ln for ln in lines if ln.startswith("Stored")]
        assert heads == [
            "Stored in databases/x.db  app",
            "Stored in shared_prefs/p.xml  app",
        ]
        assert text.count("Email") == 1
        assert "Stored on the device" not in text
