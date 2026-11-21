"""Files lens: display-only refinements (E2E night visual items).

Count column, rename pairs, paths, caption, highlight bar, Inspector
Events, monitor dialog and quit dialog. Same hermetic fixtures as
``test_files_lens``.
"""

from __future__ import annotations

from test_files_lens import (  # _isolated: autouse fixture
    ROOT,
    T0,
    _fse,
    _Harness,
    _isolated,
    _items,
    _keys,
    _plain,
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
