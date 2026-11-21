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
