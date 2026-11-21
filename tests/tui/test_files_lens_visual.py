"""Files lens: display-only refinements (E2E night visual items).

Count column, rename pairs, paths, caption, highlight bar, Inspector
Events, monitor dialog and quit dialog. Same hermetic fixtures as
``test_files_lens``.
"""

from __future__ import annotations

import pytest
from test_files_lens import (  # _isolated: autouse fixture
    ROOT,
    T0,
    _Device,
    _fse,
    _Harness,
    _isolated,
    _items,
    _keys,
    _markup_plain,
    _plain,
    _register_watched_monitor,
    _tab,
)

from sandroid.tui.widgets.files_panel import FilesPanel, count_text


def _row(panel: FilesPanel, key: str):
    return next(r for r in panel._rows if r.key == key)


# --------------------------------------------------------------------------
# V1: count column
# --------------------------------------------------------------------------


def test_count_text_keeps_the_times_sign_in_six_cells() -> None:
    assert count_text(812) == "812×"
    assert count_text(9999) == "9999×"
    assert count_text(94807) == "94.8k×"
    assert count_text(99960) == "100k×"
    assert count_text(123456) == "123k×"
    assert count_text(1_234_567) == "1.2M×"
    for n in (0, 9, 10_000, 99_949, 999_999, 12_345_678, 5_000_000_000):
        assert len(count_text(n)) <= 6
        assert count_text(n).endswith("×")


async def test_a_five_digit_count_cell_keeps_its_times_sign() -> None:
    db = f"{ROOT}/databases/big.db"
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(*[_fse("FSE_CONTENT_MODIFIED", db)] * 10_500), now=T0)
        _keys(panel)
        assert str(panel._cells(_row(panel, db))[3]) == "10.5k×"
        await pilot.pause()


# --------------------------------------------------------------------------
# V2: atomic writes (temp file renamed onto the final file) are one row
# --------------------------------------------------------------------------

ICON = f"{ROOT}/no_backup/icons/03523e83b5d8.0"
ICON_TMP = ICON + ".tmp"


def _atomic(final: str, tmp: str, writes: int = 2) -> list[str]:
    return [
        _fse("FSE_CREATE_FILE", tmp),
        *[_fse("FSE_CONTENT_MODIFIED", tmp)] * writes,
        _fse("FSE_RENAME", tmp, final),
    ]


async def test_an_atomic_write_is_one_row_with_the_temp_files_ops() -> None:
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(*_atomic(ICON, ICON_TMP)), now=T0)
        assert _keys(panel) == [ICON]
        ops, count = (str(c) for c in panel._cells(_row(panel, ICON))[2:4])
        assert ops == "CMR"
        assert count == "4×"  # C + 2 M + the rename, counted once
        # Display only: both paths keep their own activity.
        assert set(panel.activity.paths) == {ICON, ICON_TMP}
        content = panel._inspector_for(_row(panel, ICON))
        summary = _plain(_tab(content, "Summary"))
        assert "temp file" in summary
        assert "03523e83b5d8.0.tmp  C 1×  M 2×  renamed to this file" in summary
        events = _plain(_tab(content, "Events"))
        assert "from no_backup/icons/03523e83b5d8.0.tmp" in events
        # The raw view (N) shows every path as it is.
        panel.activity.show_all = True
        assert sorted(_keys(panel)) == [ICON, ICON_TMP]
        panel.activity.show_all = False
        # A filter that only the temp file matches shows its own row.
        panel._filter = ".tmp"
        assert _keys(panel) == [ICON_TMP]
        await pilot.pause()


async def test_a_backup_rename_and_a_move_to_another_folder_stay_rows() -> None:
    prefs = f"{ROOT}/shared_prefs/app.xml"
    moved = f"{ROOT}/files/old/report.txt"
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", prefs),
                _fse("FSE_RENAME", prefs, prefs + ".bak"),
                _fse("FSE_CREATE_FILE", moved + ".tmp"),
                _fse("FSE_RENAME", moved + ".tmp", f"{ROOT}/files/new/report.txt"),
            ),
            now=T0,
        )
        keys = _keys(panel)
        assert prefs in keys
        assert prefs + ".bak" in keys
        assert moved + ".tmp" in keys
        await pilot.pause()


# --------------------------------------------------------------------------
# V3: paths (group members, profile marker, shared prefixes, "/" breaks)
# --------------------------------------------------------------------------

PROFILE = f"{ROOT}/files/mozilla/k3m7yjvw.default"


def test_a_browser_profile_folder_reads_profile() -> None:
    from sandroid.tui.widgets.files_panel import short_profile

    assert short_profile("files/mozilla/k3m7yjvw.default/cookies.sqlite") == (
        "@profile/cookies.sqlite"
    )
    assert short_profile("files/mozilla/ab12cd34.default-release/x/y") == (
        "@profile/x/y"
    )
    assert short_profile("files/places.sqlite") == "files/places.sqlite"
    assert short_profile("files/mozilla/k3m7yjvw.default/") == (
        "files/mozilla/k3m7yjvw.default/"
    )


async def test_members_of_an_open_group_show_their_name_only() -> None:
    folder = f"{PROFILE}/safebrowsing-updating"
    files = [f"{folder}/list-{i:02d}.sbstore" for i in range(25)]
    app = _Harness()
    async with app.run_test(size=(160, 40)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(*[_fse("FSE_CREATE_FILE", f) for f in files]), now=T0)
        _keys(panel)
        group = next(r for r in panel._rows if r.group == folder)
        assert str(panel._path_cell(group)).startswith(
            "@profile/safebrowsing-updating/ · 25 files"
        )
        panel._expanded.add(folder)
        _keys(panel)
        member = _row(panel, files[3])
        assert str(panel._path_cell(member)) == "  list-03.sbstore"
        # Full paths (.) show the whole path again.
        panel._full_paths = True
        _keys(panel)
        assert str(panel._path_cell(_row(panel, files[3]))) == f"  {files[3]}"
        await pilot.pause()


async def test_siblings_share_one_truncated_prefix() -> None:
    origin = f"{PROFILE}/storage/default/https+++www.a-very-long-origin.example.org"
    short = f"{origin}/ls/usage"
    long = f"{origin}/ls/data-with-a-much-longer-name.sqlite"
    app = _Harness()
    async with app.run_test(size=(90, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(_fse("FSE_CREATE_FILE", short), _fse("FSE_CREATE_FILE", long)),
            now=T0,
        )
        _keys(panel)
        cells = [str(panel._path_cell(_row(panel, k))) for k in (short, long)]
        heads = {c.rpartition("/")[0] for c in cells}
        assert len(heads) == 1, cells
        assert "…" in heads.pop()
        assert cells[0].endswith("/usage")
        assert cells[1].endswith("/data-with-a-much-longer-name.sqlite")
        await pilot.pause()


def test_paths_break_after_a_slash() -> None:
    from rich.console import Console

    from sandroid.tui.widgets.lens_shell import SlashWrap, slash_lines, toast_paths

    path = f"{PROFILE}/storage/default/https+++www.zeit.de/ls/data.sqlite"
    lines = slash_lines(path, 40)
    assert "".join(lines) == path
    assert all(len(line) <= 40 for line in lines)
    assert all(line.endswith("/") for line in lines[:-1])
    assert slash_lines(f"Watching {path} now", 57)[0] == (
        "Watching /data/data/com.example.fit/files/mozilla/"
    )
    console = Console(width=40, color_system=None, record=True)
    console.print(SlashWrap(path))
    assert console.export_text().splitlines() == lines

    class _App:
        size = type("S", (), {"width": 120})()

    toast = toast_paths(_App(), f"Watching {path}")
    assert all(len(line) <= 57 for line in toast.splitlines())
    assert toast.replace("\n", "") == f"Watching {path}"


# --------------------------------------------------------------------------
# V4: caption (modes in the title, short counts, fitted to the frame)
# --------------------------------------------------------------------------


async def test_the_caption_is_short_and_fits_the_frame() -> None:
    from sandroid.core.kprobe_tracer import AppProcess

    app = _Harness()
    async with app.run_test(size=(200, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        watch = _register_watched_monitor(
            _Device({10: AppProcess(10, 10100, "com.example.fit")}),
            mode="pid",
            follow=True,
        )
        watch.seed({10: [10]}, watch.initial_processes())
        panel.activity.max_paths = 5
        lines = [_fse("FSE_CREATE_FILE", f"{ROOT}/files/f{i}") for i in range(8)]
        lines += [_fse("FSE_OPEN", f"{ROOT}/files/o{i}") for i in range(2)]
        panel.ingest(_items(*lines), now=T0)
        panel._watched_only = False
        panel._sort = "name"
        _keys(panel)
        title, info = panel.caption()
        assert _markup_plain(title) == "by name · monitor ● on"
        assert info == (
            "App com.example.fit · 1 proc · following · o stops · 5 paths · "
            "5 dropped (cap 5)"
        )
        # Narrow (the Inspector open): the stop hint goes first, the scope
        # and losses stay.
        await pilot.resize_terminal(60, 30)
        await pilot.pause()
        info = panel.caption()[1]
        assert len(info) <= 56
        assert "o stops" not in info
        assert info.startswith("App com.example.fit")
        watch.lost_events = 3
        await pilot.resize_terminal(40, 30)
        await pilot.pause()
        assert "3 events lost" in panel.caption()[1]


async def test_no_live_in_the_title_while_the_monitor_is_off() -> None:
    app = _Harness()
    async with app.run_test(size=(160, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", f"{ROOT}/files/a")), now=T0)
        _keys(panel)
        assert panel.following
        assert _markup_plain(panel.caption()[0]) == "monitor ○ off"
        panel._watched_only = True
        panel.refresh_rows()
        assert _markup_plain(panel.caption()[0]) == "watched only · monitor ○ off"
        await pilot.pause()


# --------------------------------------------------------------------------
# V5: highlight bar (full labels when they fit, short ones else, the keys)
# --------------------------------------------------------------------------


def _files_view_with_two_sets():
    from sandroid.services import row_highlights
    from sandroid.services.row_highlights import get_row_highlights
    from sandroid.tui.widgets.highlight_bar import HighlightView

    row_highlights.reset_for_tests()
    store = get_row_highlights()
    a = store.create(
        "files",
        "browsing history database (privacy-relevant)",
        short="history DB",
        reasons={"/a/places.sqlite": "r"},
        basis={"judged_at": 1.0},
    )
    b = store.create(
        "files",
        "privacy-relevant cookie store of the browser",
        short="cookies",
        reasons={"/a/cookies.sqlite": "r"},
        basis={"judged_at": 1.0},
    )
    view = HighlightView("files", noun="file", calm=True)
    view.measure(
        iter(
            [
                ("/a/places.sqlite", True, None, 2.0),
                ("/a/cookies.sqlite", True, None, 2.0),
            ]
        ),
        live=True,
        changes=True,
    )
    return store, view, a, b


def test_the_bar_shows_full_labels_when_they_fit():
    from sandroid.services import row_highlights

    _store, view, a, b = _files_view_with_two_sets()
    try:
        plain = view.bar_text(240).plain
        assert a.label in plain  # never clipped at a fixed 32 cells
        assert b.label in plain
        assert plain.count("1 changed since highlighted") == 2
        assert "Shift+H filter · Shift+X clear" in plain
        # 200 columns: one label in full, the other short; words and keys whole.
        plain = view.bar_text(200).plain
        assert b.label in plain
        assert "history DB 1" in plain
        assert plain.count("1 changed since highlighted") == 2
        assert "Shift+H filter · Shift+X clear" in plain
    finally:
        row_highlights.reset_for_tests()


@pytest.mark.parametrize("width", [160, 140, 120, 110])
def test_the_bar_uses_short_labels_before_it_drops_the_keys(width):
    from sandroid.services import row_highlights

    _store, view, a, b = _files_view_with_two_sets()
    try:
        text = view.bar_text(width)
        plain = text.plain
        assert text.cell_len <= width - 2
        assert "…" not in plain  # a label is whole: long or short
        assert a.label in plain or "history DB" in plain
        assert b.label in plain or "cookies" in plain
        assert "Shift+H filter · Shift+X clear" in plain
    finally:
        row_highlights.reset_for_tests()


# --------------------------------------------------------------------------
# V6: Inspector Events ("last 30 of N", runs of identical events)
# --------------------------------------------------------------------------


async def test_events_say_how_many_are_kept_and_fold_identical_runs() -> None:
    from datetime import timedelta

    db = f"{ROOT}/databases/places.sqlite"
    app = _Harness()
    async with app.run_test(size=(160, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(*[_fse("FSE_CONTENT_MODIFIED", db + "-wal")] * 40), now=T0)
        later = T0 + timedelta(seconds=5)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", db + "-journal")), now=later)
        panel.ingest(
            _items(*[_fse("FSE_CONTENT_MODIFIED", db + "-wal")] * 3), now=later
        )
        _keys(panel)
        events = _plain(_tab(panel._inspector_for(_row(panel, db)), "Events"))
        lines = events.splitlines()
        assert lines[0] == "last 30 of 44 events"
        assert lines[1].startswith("10:40:05  MODIFY")
        assert lines[1].endswith("×3")
        assert "-journal" in lines[2]
        assert not lines[2].endswith("×1")
        assert lines[3].startswith("10:40:00  MODIFY")
        assert lines[3].endswith("×26")  # 30 kept: 3 + 1 + 26
        assert len(lines) == 4
        await pilot.pause()
