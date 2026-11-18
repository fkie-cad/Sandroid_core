"""Files lens Inspector: Versions / Content tabs and the structured diff
renderer (``tui/widgets/file_inspect``), incl. keys, clicks and zoom in the
real app. No device: versions are written into the (per-test) watchlist
store directly.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from file_inspect_samples import (
    PREFS_NEW,
    PREFS_OLD,
    make_places,
    write_pairs,
)

from sandroid.core import file_diff
from sandroid.core import file_inspect as fi
from sandroid.core import watchlist_store as store
from sandroid.services import get_forensic_service
from sandroid.tui.widgets import file_inspect as fins

PKG = "org.mozilla.firefox"
PLACES = f"/data/data/{PKG}/files/mozilla/x.default/places.sqlite"
PREFS = f"/data/data/{PKG}/shared_prefs/prefs.xml"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path / "results"))
    fins.clear_caches()
    get_forensic_service()._spotlight_files.clear()
    yield
    fins.clear_caches()
    get_forensic_service()._spotlight_files.clear()


def _render(renderable, width: int = 55) -> str:
    console = Console(file=StringIO(), width=width, color_system=None)
    console.print(renderable)
    return console.file.getvalue()


def _sections_text(sections, width: int = 55) -> str:
    console = Console(file=StringIO(), width=width, color_system=None)
    for heading, body in sections:
        if heading:
            console.print(heading)
        console.print(body)
    return console.file.getvalue()


def _add_version(path: str, when: datetime, files: dict, diff=None, record=None):
    """One kept version in the real session-folder layout (``vNNN_HH-MM-SS``
    + ``acquisition.json``), written through the store's own write API.
    """
    staging = store.reset_current(path)
    for name, src in files.items():
        shutil.copyfile(src, staging / name)
    return store.promote(path, diff, record, when=when)


def _record(file: Path, when: datetime, trigger: str, match: bool = True) -> dict:
    """An ``acquisition.json`` as ``WatchlistView`` writes it."""
    sha = hashlib.sha256(file.read_bytes()).hexdigest()
    size = file.stat().st_size
    return {
        "schema_version": 1,
        "device": {
            "mtime": int(when.timestamp()) - 5,
            "size": size,
            "sha256": sha if match else "0" * 64,
        },
        "local": {"file": file.name, "size": size, "sha256": sha},
        "sha256_match": match,
        "pulled_at": when.isoformat(timespec="seconds"),
        "trigger": trigger,
    }


def _places_versions(tmp_path) -> list[Path]:
    t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=10)
    dirs = []
    for v in (1, 2, 3):
        db = make_places(tmp_path / f"src{v}" / "places.sqlite", v)
        when = t0 + timedelta(minutes=v)
        dirs.append(
            _add_version(
                PLACES,
                when,
                {"places.sqlite": db},
                diff=None if v == 1 else "",
                record=_record(db, when, "manual" if v == 1 else "auto"),
            )
        )
    return dirs


# ---------------------------------------------------------------------------
# renderer
# ---------------------------------------------------------------------------


def test_sqlite_diff_renders_tables_named_columns_and_hints(tmp_path):
    old = make_places(tmp_path / "a" / "places.sqlite", 2)
    new = make_places(tmp_path / "b" / "places.sqlite", 3)
    diff = fi.structured_diff(old, new)
    narrow = _render(fins.DiffRenderable(diff), 55)
    assert "moz_historyvisits" in narrow
    assert "moz_meta" in narrow
    assert "+ inserted" in narrow
    assert "visit_date" in narrow
    assert "1794994868383" in narrow
    assert "2026-11-1" in narrow  # dim time hint under the raw value
    assert "origin_frecency_count" in narrow
    assert "7 → 8" in narrow
    assert "https://accounts.example.com/" in narrow
    assert "%2Finbox" not in narrow  # clipped at the Inspector width ...
    assert "…" in narrow
    wide = _render(fins.DiffRenderable(diff, full=True), 140)
    assert "https://accounts.example.com/login?next=%2Finbox" in wide  # ... not here
    assert all(len(line) <= 55 for line in narrow.splitlines())


def test_xml_text_binary_render(tmp_path):
    pairs = write_pairs(tmp_path)
    xml = _render(fins.DiffRenderable(fi.structured_diff(*pairs["xml"])))
    assert "~4 changed" in xml
    assert "+2 added" in xml
    assert "−1 removed" in xml
    assert "consent_state" in xml
    assert "pending → granted" in xml
    assert "session_token" in xml
    text = _render(fins.DiffRenderable(fi.structured_diff(*pairs["text"])), 70)
    assert "@@ −9,7 +9,7 @@" in text
    assert "12    − line 12: steady state" in text
    assert "   12 + line 12: user logged in" in text
    binary = _render(fins.DiffRenderable(fi.structured_diff(*pairs["binary"])), 70)
    assert "at byte 300 (0x12c)" in binary
    assert "de ad be ef" in binary
    parsed = fi.parse_text_diff(file_diff.xml_diff(*map(str, pairs["xml"])))
    assert "consent_state" in _render(fins.DiffRenderable(parsed))


def test_change_text_emphasises_the_changed_part_of_long_values():
    old = "x" * 80 + "OLD" + "y" * 80
    new = "x" * 80 + "NEW" + "y" * 80
    text = fins.change_text(old, new, budget=30)
    plain = text.plain
    assert "OLD" in plain
    assert "NEW" in plain
    assert plain.startswith("− …")


# ---------------------------------------------------------------------------
# versions / content tabs (no app)
# ---------------------------------------------------------------------------


def test_versions_tab_newest_first_selection_base_and_clicks(tmp_path):
    _places_versions(tmp_path)
    sections = fins.versions_sections(PLACES)
    listing = _render(sections[0][1], 60).splitlines()
    assert listing[0].startswith("▸ v3")
    assert listing[2].lstrip().startswith("v1")
    assert "first pull" in listing[2]
    assert "moz_meta ~3" in listing[0]  # summary from the structured diff
    assert "auto" in listing[0]
    assert "manual" in listing[2]
    text = _sections_text(sections)
    assert "Diff  v3" in text
    assert "← v2" in text

    assert fins.step_version(PLACES, -1)  # <: older
    assert "Diff  v2" in _sections_text(fins.versions_sections(PLACES))
    assert fins.step_version(PLACES, 1)
    assert not fins.step_version(PLACES, 1)  # already the newest

    assert fins.select_version_row(PLACES, 2)  # click on the v1 line
    assert "first kept version" in _sections_text(fins.versions_sections(PLACES))
    assert "v1" in fins.toggle_base(PLACES)
    assert fins.select_version_row(PLACES, 0)
    text = _sections_text(fins.versions_sections(PLACES))
    assert "v3" in text
    assert "← v1" in text
    assert "(base)" in text
    assert "base" in _render(fins.versions_sections(PLACES)[0][1], 60)
    fins.select_version_row(PLACES, 2)
    assert "cleared" in fins.toggle_base(PLACES)
    assert not fins.select_version_row(PLACES, 9)


def test_versions_tab_without_pulls_says_how(tmp_path):
    text = _sections_text(fins.versions_sections(PLACES))
    assert "Not pulled yet" in text
    assert "u" in text


def test_content_tab_tables_rows_and_table_selection(tmp_path):
    _places_versions(tmp_path)
    sections = fins.content_sections(PLACES)
    text = _sections_text(sections, 60)
    assert "moz_places" in text
    assert "8 rows · 15 cols" in text
    assert "moz_historyvisits · 9 of 9 rows" in text
    assert "visit_date" in text
    file = fins.content_file(PLACES)
    assert fins.step_table(PLACES, file, 1)  # >: next table
    assert "moz_meta · 3 of 3 rows" in _sections_text(fins.content_sections(PLACES))
    assert fins.select_table_row(PLACES, file, 4)  # click on moz_places
    assert "moz_places · 8 of 8 rows" in _sections_text(fins.content_sections(PLACES))
    # the selected version's copy is shown
    fins.select_version_row(PLACES, 2)
    text = _sections_text(fins.content_sections(PLACES))
    assert "v1" in text
    assert "moz_places · 5 of 5 rows" in text


def test_content_tab_for_prefs_json_and_binary(tmp_path):
    a, b = tmp_path / "a.xml", tmp_path / "b.xml"
    a.write_text(PREFS_OLD, encoding="utf-8")
    b.write_text(PREFS_NEW, encoding="utf-8")
    t0 = datetime.now() - timedelta(minutes=3)
    _add_version(PREFS, t0, {"prefs.xml": a})
    _add_version(PREFS, t0 + timedelta(minutes=1), {"prefs.xml": b}, diff="x")
    text = _sections_text(fins.content_sections(PREFS), 70)
    assert "consent_state" in text
    assert "granted" in text
    assert "boolean" in text
    pairs = write_pairs(tmp_path / "pairs")
    state = fins.InspectState()
    js = _sections_text(fins.content_sections_for_file(pairs["json"][1], state, ""))
    assert "Pixel 7" in js
    assert "flags" in js
    blob = _sections_text(
        fins.content_sections_for_file(pairs["binary"][1], state, ""), 80
    )
    assert "First 512 bytes" in blob
    assert "000000" in blob
    assert "binary data" in blob


def test_review_diff_uses_the_runs_copies_or_parses_the_lines(tmp_path):
    run_dir = tmp_path / "results" / "runs" / "r1"
    for slot, version in (("first_pull", 1), ("second_pull", 2)):
        make_places(run_dir / "raw" / slot / PLACES.lstrip("/"), version)
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    body = fins.review_diff_body(str(run_dir), PLACES, None)
    assert "visit_date" in _render(body)  # column names from the copies
    content = fins.review_content_sections(str(run_dir), PLACES, "changed")
    assert "moz_places" in _sections_text(content)
    lines = file_diff.xml_diff(
        *map(str, write_pairs(tmp_path / "p")["xml"])
    ).splitlines()
    parsed = fins.review_diff_body(None, PREFS, lines)
    assert "consent_state" in _render(parsed)
    assert fins.review_diff_body(None, PREFS, ["[red]- a[/red]"]) is None


# ---------------------------------------------------------------------------
# in the app: keys, clicks, zoom
# ---------------------------------------------------------------------------


async def _settle(pilot, n: int = 5) -> None:
    for _ in range(n):
        await pilot.pause(0.03)


async def _wait(pilot, predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not predicate():
        await pilot.pause(0.03)
    assert predicate()


async def test_versions_and_content_tabs_in_the_app(tmp_path):
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.file_inspect import InspectZoomModal

    _places_versions(tmp_path)
    get_forensic_service().add_spotlight_file(PLACES)
    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        await _settle(pilot, 8)
        if type(app.screen).__name__ != "MainScreen":
            await pilot.press("enter")
            await _settle(pilot)
        ms = app.screen
        await pilot.press("3")
        await _settle(pilot)
        panel = ms.lens_widget("files")
        panel.refresh_rows()
        panel.table.focus()
        await _settle(pilot)
        assert panel.current_row().key == PLACES
        await pilot.press("enter")
        await _wait(pilot, lambda: ms.inspector_is_open)
        inspector = ms.query_one("#inspector")
        assert [t for t, _s in ms.inspector_content.tabs] == [
            "Summary",
            "Versions",
            "Content",
            "Events",
        ]
        # No "found by a re-stat" note on database rows any more: the write
        # probes name writes through files opened before the monitor.
        assert "re-stat" not in _sections_text(ms.inspector_content.tabs[0][1])
        await pilot.press("right_square_bracket")
        assert inspector.tab_name == "Versions"
        assert "Diff  v3" in _sections_text(ms.inspector_content.tabs[1][1])

        await pilot.press("left_curly_bracket")  # older
        await _settle(pilot)
        assert "Diff  v2" in _sections_text(ms.inspector_content.tabs[1][1])
        await pilot.press("asterisk")  # v2 is the base
        await _settle(pilot)
        assert fins.state_for(PLACES).base is not None
        await pilot.click("#inspector-body", offset=(3, 0))  # newest line
        await _settle(pilot)
        text = _sections_text(ms.inspector_content.tabs[1][1])
        assert "Diff  v3" in text
        assert "(base)" in text
        # A click focuses the Inspector (to scroll it); { } still work.
        await pilot.press("left_curly_bracket")
        await _settle(pilot)
        assert "Diff  v2" in _sections_text(ms.inspector_content.tabs[1][1])
        await pilot.press("right_curly_bracket")
        await _settle(pilot)

        await pilot.press("z")
        await _wait(pilot, lambda: isinstance(app.screen, InspectZoomModal))
        await pilot.press("escape")
        await _wait(pilot, lambda: app.screen is ms)

        await pilot.press("right_square_bracket")
        assert inspector.tab_name == "Content"
        assert "moz_historyvisits · 9 of 9" in _sections_text(
            ms.inspector_content.tabs[2][1]
        )
        await pilot.press("right_curly_bracket")  # next table
        await _settle(pilot)
        assert "moz_meta · 3 of 3" in _sections_text(ms.inspector_content.tabs[2][1])
        await pilot.click("#inspector-body", offset=(3, 4))  # moz_places line
        await _settle(pilot)
        assert "moz_places · 8 of 8" in _sections_text(ms.inspector_content.tabs[2][1])
        await pilot.press("z")
        await _wait(pilot, lambda: isinstance(app.screen, InspectZoomModal))
        await pilot.press("escape")
        await _wait(pilot, lambda: app.screen is ms)

        # { } * do nothing (and are not offered) without the Inspector.
        await pilot.press("escape")
        await _settle(pilot)
        assert not ms.inspector_is_open
        assert ms.check_action("inspector_key", ("asterisk",)) is False


# ---------------------------------------------------------------------------
# keys: no key means two things on the Files lens
# ---------------------------------------------------------------------------


def _binding_map(cls) -> dict[str, set[str]]:
    from textual.binding import Binding

    out: dict[str, set[str]] = {}
    for entry in cls.__dict__.get("BINDINGS", []):
        key, action = (
            (entry.key, entry.action) if isinstance(entry, Binding) else entry[:2]
        )
        for k in key.split(","):
            out.setdefault(k.strip(), set()).add(action)
    return out


#: Inspector-content keys the MainScreen binds (``inspector_key``).
INSPECTOR_KEYS = {"left_curly_bracket", "right_curly_bracket", "asterisk"}


def test_files_lens_and_inspector_keys_never_clash():
    """The Files lens's own keys (marks ``B`` ``A`` ``<`` ``>``, ``w`` ``u``
    ...) and the keys of the open Inspector (tabs, versions, tables, base)
    are disjoint, so no key changes meaning with the focus or the Inspector.
    The Inspector-content keys are free in every lens and app-wide too.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.help_screen import _panel_bindings
    from sandroid.tui.screens.main_screen import MainScreen, _LensHost
    from sandroid.tui.widgets.diffs_view import DiffsView
    from sandroid.tui.widgets.files_panel import FilesPanel
    from sandroid.tui.widgets.lens_shell import Inspector
    from sandroid.tui.widgets.network_panel import NetworkPanel
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    files = _binding_map(FilesPanel)
    screen = _binding_map(MainScreen)
    for key in ("B", "A", "less_than_sign", "greater_than_sign"):
        assert key in files  # the marks keys stay on the lens
    inspector_side = {**_binding_map(Inspector)}
    for key, actions in [*screen.items(), *_binding_map(_LensHost).items()]:
        inspector_side.setdefault(key, set()).update(actions)
    clashes = {
        key: (files[key], inspector_side[key])
        for key in files.keys() & inspector_side.keys()
    }
    assert clashes == {}

    bound = {k for k, acts in screen.items() if any("inspector_key" in a for a in acts)}
    assert bound == INSPECTOR_KEYS
    for cls in (SandroidTUI, FilesPanel, NetworkPanel, DiffsView, SpotlightPanel):
        assert not INSPECTOR_KEYS & _binding_map(cls).keys(), cls.__name__
    rows = _panel_bindings("sandroid.tui.screens.main_screen", "MainScreen")
    shown = {desc: key for key, desc in rows}
    assert shown["Inspector: older version / previous table"] == "{"
    assert shown["Inspector: newer version / next table"] == "}"
    assert shown["Inspector: diff against this version (base)"] == "*"


def test_versions_tab_shows_the_acquisition_record(tmp_path):
    dirs = _places_versions(tmp_path)
    text = _sections_text(fins.versions_sections(PLACES), 70)
    assert "pulled" in text
    assert "auto" in text
    assert "device sha256 = local ✓ · changed" in text
    # A copy that does not match the on-device sha256 is flagged.
    record = store.version_record(dirs[-1])
    record["sha256_match"] = False
    record["device"]["sha256"] = "f" * 64
    (dirs[-1] / "acquisition.json").write_text(json.dumps(record), encoding="utf-8")
    fins.clear_caches()
    text = _sections_text(fins.versions_sections(PLACES), 70)
    assert "device sha256 ≠ local ✗" in text
    assert "✗ sha256" in _render(fins.versions_sections(PLACES)[0][1], 70)
    # Without a record (older pulls) the line still shows time and size.
    (dirs[-1] / "acquisition.json").unlink()
    fins.clear_caches()
    assert "pulled" in _sections_text(fins.versions_sections(PLACES), 70)


def test_listing_versions_of_an_unpulled_file_creates_no_folder(tmp_path):
    root = store.files_root()
    assert fins.load_versions(PLACES) == []
    assert fins.versions_sections(PLACES)
    assert fins.content_sections(PLACES)
    assert not root.exists() or not any(root.rglob("*"))


# ---------------------------------------------------------------------------
# diff.json, "checked, no change" lines and the file-set hash line
# ---------------------------------------------------------------------------


def _keep(path: str, src: Path, when: datetime, record: dict | None = None) -> Path:
    """One version kept the way the Files lens keeps it (``keep_version``:
    acquisition.json + diff.json + diff.txt).
    """
    staging = store.reset_current(path)
    for suffix in ("", "-wal"):
        if Path(f"{src}{suffix}").exists():
            shutil.copyfile(f"{src}{suffix}", staging / f"{src.name}{suffix}")
    return store.keep_version(path, record, when).dir


def test_versions_tab_reads_diff_json_not_the_copies(tmp_path):
    t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=5)
    _keep(PLACES, make_places(tmp_path / "a" / "places.sqlite", 1), t0)
    v2 = _keep(
        PLACES,
        make_places(tmp_path / "b" / "places.sqlite", 2),
        t0 + timedelta(minutes=1),
    )
    doc = store.version_diff_doc(v2)
    assert doc["kind"] == "sqlite"
    # Prove the Inspector draws diff.json: rename a table there only, and
    # drop the copies (a diff is still shown, from the record).
    doc["tables"][0]["name"] = "renamed_in_diff_json"
    doc["summary"] = "renamed_in_diff_json +1"
    (v2 / "diff.json").write_text(json.dumps(doc), encoding="utf-8")
    for version in store.version_dirs(PLACES):
        (version / "places.sqlite").unlink()
    fins.clear_caches()
    text = _sections_text(fins.versions_sections(PLACES), 90)
    assert "renamed_in_diff_json" in text
    assert "Column names: the stored text diff has none" not in text
    assert "visit_date" in text or "frecency" in text or "id" in text


def test_checks_collapse_into_one_line_between_versions(tmp_path):
    t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=5)
    _keep(PLACES, make_places(tmp_path / "a" / "places.sqlite", 1), t0)
    _keep(
        PLACES,
        make_places(tmp_path / "b" / "places.sqlite", 2),
        t0 + timedelta(minutes=2),
    )
    for minute, trigger in ((1, "auto"), (1, "auto")):
        store.append_check(
            PLACES,
            {
                "at": store.iso_tz(t0 + timedelta(minutes=minute, seconds=7)),
                "trigger": trigger,
                "event_at": None,
                "device_sha256": {"places.sqlite": "a" * 64},
                "same_as": "v001",
                "note": "no change",
            },
        )
    store.append_check(
        PLACES,
        {
            "at": store.iso_tz(t0 + timedelta(minutes=3)),
            "trigger": "manual",
            "same_as": "v002",
            "note": "no change",
        },
    )
    fins.clear_caches()
    listing = _render(fins.versions_sections(PLACES)[0][1], 90).splitlines()
    assert len(listing) == 4
    assert listing[0].lstrip().startswith("·")
    assert "manual" in listing[0]
    assert "checked, no change" in listing[0]
    assert "×" not in listing[0]
    assert "v2" in listing[1]
    stamp = (t0 + timedelta(minutes=1, seconds=7)).strftime("%H:%M:%S")
    assert stamp in listing[2]
    assert "auto" in listing[2]
    assert "checked, no change (2×)" in listing[2]
    assert "v1" in listing[3]
    # A click on a check line selects the version it found unchanged.
    assert fins.select_version_row(PLACES, 2) is True
    assert fins.state_for(PLACES).selected == store.version_dirs(PLACES)[0].name
    assert fins.select_version_row(PLACES, 1) is True
    assert fins.state_for(PLACES).selected is None  # v2 = newest
    assert fins.select_version_row(PLACES, 4) is False


def test_the_hash_line_covers_the_wal(tmp_path):
    t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=5)
    src = make_places(tmp_path / "a" / "places.sqlite", 3, wal=True)
    main_sha = hashlib.sha256(src.read_bytes()).hexdigest()
    wal = Path(f"{src}-wal")
    wal_sha = hashlib.sha256(wal.read_bytes()).hexdigest()
    mtime = int(t0.timestamp())
    record = {
        "schema_version": 2,
        "device_path": PLACES,
        "device": {"mtime": mtime - 60, "size": src.stat().st_size, "sha256": main_sha},
        "local": {
            "file": "places.sqlite",
            "size": src.stat().st_size,
            "sha256": main_sha,
        },
        "companions": [
            {
                "device_path": f"{PLACES}-wal",
                "device": {
                    "mtime": mtime,
                    "size": wal.stat().st_size,
                    "sha256": wal_sha,
                },
                "local": {
                    "file": "places.sqlite-wal",
                    "size": wal.stat().st_size,
                    "sha256": wal_sha,
                },
                "sha256_match": True,
            }
        ],
        "set": {
            "local_sha256": store.set_sha256(
                {"places.sqlite": main_sha, "places.sqlite-wal": wal_sha}
            ),
            "missing_locally": [],
        },
        "sha256_match": True,
        "pulled_at": store.iso_tz(t0),
        "trigger": "auto",
    }
    version = _keep(PLACES, src, t0, record)
    text = _sections_text(fins.versions_sections(PLACES), 100)
    set_sha = record["set"]["local_sha256"]
    assert f"sha256 (db+wal) {set_sha[:10]}" in text
    assert main_sha[:10] not in text  # not the main file's hash alone
    assert "device sha256 = local ✓ (both)" in text
    assert f"changed {t0:%H:%M:%S} (wal)" in text
    assert " wal" in text.split("pulled", 1)[1].splitlines()[0]  # "… + 2.0 KB wal"
    # A WAL that differs from the device is named.
    stored = store.version_record(version)
    stored["companions"][0]["device"]["sha256"] = "0" * 64
    stored["sha256_match"] = False
    (version / "acquisition.json").write_text(json.dumps(stored), encoding="utf-8")
    fins.clear_caches()
    text = _sections_text(fins.versions_sections(PLACES), 100)
    assert "device sha256 ≠ local ✗ (wal)" in text
