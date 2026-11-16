"""Keyed XML diff, checked against data from the 2.1 phase-2 live test.

The ground-truth app (``ground_truth_src/.../XMLHelper.java``) appends an
``<Element ID=n>``, deletes one at random and rewrites another one's text.
The old positional xmldiff reported this as moves and ID changes; matching
by the ``ID``/``name`` attribute must report one add, one delete and one
update. The Wikipedia excerpts and the package-restrictions ABX files are
the tester's real pulls (run 20261116_173858_df1034).
"""

from __future__ import annotations

from pathlib import Path

from sandroid.core import file_diff

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "p2_live"

# Verbatim first/second pulls of files/GroundTruth.xml (run 20261116_171021_af03b8).
GT_FIRST = (
    '<?xml version="1.0" encoding="UTF-8"?><root><Element ID="0">1794845342'
    '</Element><Element ID="1">1794845344</Element></root>'
)
GT_SECOND = (
    '<?xml version="1.0" encoding="UTF-8"?><root><Element ID="0">1794845501'
    '</Element><Element ID="2">1794845498</Element></root>'
)

PREFS_FIRST = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="languageApp">en</string>
    <long name="generateRecommendedReadingListTask-lastrun" value="1794846183341" />
    <boolean name="SEHighestPriorityEnabled" value="false" />
    <boolean name="showSearchTabTooltip" value="false" />
    <int name="exploreFeedVisitCount" value="3" />
</map>
"""
PREFS_SECOND = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="languageApp">en</string>
    <boolean name="downloadReadingListArticles" value="true" />
    <boolean name="downloadOnlyOverWiFi" value="false" />
    <long name="generateRecommendedReadingListTask-lastrun" value="1794846183341" />
    <boolean name="preferOfflineContent" value="false" />
    <boolean name="SEHighestPriorityEnabled" value="false" />
    <boolean name="showImages" value="true" />
    <boolean name="showSearchTabTooltip" value="false" />
    <int name="exploreFeedVisitCount" value="3" />
</map>
"""

SAFETYNET_FIRST = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <set name="snet_verify_apps_api_usage">
        <string>com.google.android.googlequicksearchbox</string>
        <string>fr.doctolib.www</string>
        <string>com.ebay.kleinanzeigen</string>
        <string>com.google.android.youtube</string>
    </set>
</map>
"""
SAFETYNET_SECOND = SAFETYNET_FIRST.replace(
    "        <string>com.google.android.youtube</string>",
    "        <string>org.wikipedia</string>\n"
    "        <string>com.google.android.youtube</string>",
)


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def _lines(diff: str) -> list[str]:
    return [line.strip() for line in diff.splitlines() if line.strip()]


def test_ground_truth_add_update_delete(tmp_path):
    first = _write(tmp_path, "first.xml", GT_FIRST)
    second = _write(tmp_path, "second.xml", GT_SECOND)

    lines = _lines(file_diff.xml_diff(first, second, str(tmp_path / "missing")))

    assert lines == [
        '[DELETED] /root/Element[@ID="1"] text="1794845344"',
        '[UPDATED] /root/Element[@ID="0"] text: "1794845342" → "1794845501"',
        '[ADDED] /root/Element[@ID="2"] text="1794845498"',
    ]
    assert not any("Moved" in line for line in lines)


def test_shared_prefs_inserts_are_adds_not_moves(tmp_path):
    first = _write(tmp_path, "first.xml", PREFS_FIRST)
    second = _write(tmp_path, "second.xml", PREFS_SECOND)

    lines = _lines(file_diff.xml_diff(first, second, None))

    assert lines == [
        '[ADDED] /map/boolean[@name="downloadReadingListArticles"] value="true"',
        '[ADDED] /map/boolean[@name="downloadOnlyOverWiFi"] value="false"',
        '[ADDED] /map/boolean[@name="preferOfflineContent"] value="false"',
        '[ADDED] /map/boolean[@name="showImages"] value="true"',
    ]


def test_shared_prefs_value_update_and_removal(tmp_path):
    second_text = PREFS_FIRST.replace(
        'name="exploreFeedVisitCount" value="3"', 'name="exploreFeedVisitCount" value="4"'
    ).replace('    <boolean name="showSearchTabTooltip" value="false" />\n', "")
    first = _write(tmp_path, "first.xml", PREFS_FIRST)
    second = _write(tmp_path, "second.xml", second_text)

    lines = _lines(file_diff.xml_diff(first, second, None))

    assert lines == [
        '[DELETED] /map/boolean[@name="showSearchTabTooltip"] value="false"',
        '[UPDATED] /map/int[@name="exploreFeedVisitCount"] value: "3" → "4"',
    ]


def test_string_set_insert_is_single_add(tmp_path):
    first = _write(tmp_path, "first.xml", SAFETYNET_FIRST)
    second = _write(tmp_path, "second.xml", SAFETYNET_SECOND)

    lines = _lines(file_diff.xml_diff(first, second, None))

    assert lines == [
        '[ADDED] /map/set[@name="snet_verify_apps_api_usage"]/string[4] '
        'text="org.wikipedia"'
    ]


def test_noise_lines_are_subtracted(tmp_path):
    first = _write(tmp_path, "first.xml", PREFS_FIRST)
    second = _write(tmp_path, "second.xml", PREFS_SECOND)
    # The dry run (no app action) already added showImages -> noise.
    noise = _write(
        tmp_path,
        "noise.xml",
        PREFS_FIRST.replace(
            "</map>", '    <boolean name="showImages" value="true" />\n</map>'
        ),
    )

    lines = _lines(file_diff.xml_diff(first, second, noise))

    assert '[ADDED] /map/boolean[@name="showImages"] value="true"' not in lines
    assert len(lines) == 3
    assert file_diff.xml_diff(first, noise, noise) == "ITS ALL NOISE"


def test_long_values_are_trimmed_to_the_change(tmp_path):
    cookie = "x" * 300 + "expires=Mon, 16 Nov 2026 17:24:36 GMT" + "y" * 300
    first = _write(
        tmp_path, "first.xml", f'<map><string name="cookie_map">{cookie}</string></map>'
    )
    second = _write(
        tmp_path,
        "second.xml",
        f'<map><string name="cookie_map">{cookie.replace("17:24:36", "17:41:01")}'
        "</string></map>",
    )

    (line,) = _lines(file_diff.xml_diff(first, second, None))

    assert line.startswith('[UPDATED] /map/string[@name="cookie_map"] text: "…')
    assert "17:24:36" in line
    assert "17:41:01" in line
    assert len(line) < 400


def test_multiline_values_stay_on_one_line(tmp_path):
    first = _write(tmp_path, "a.xml", '<map><string name="lm">a\nb</string></map>')
    second = _write(tmp_path, "b.xml", '<map><string name="lm">b\nc</string></map>')

    diff = file_diff.xml_diff(first, second, None)

    assert diff == '\t[UPDATED] /map/string[@name="lm"] text: "a\\nb" → "b\\nc"\n'


def test_real_package_restrictions_abx_diff():
    """Real ABX pulls: Wikipedia's first launch disables one component."""
    first = FIXTURES / "package-restrictions.first.abx.xml"
    second = FIXTURES / "package-restrictions.second.abx.xml"
    assert first.read_bytes()[:3] == b"ABX"

    lines = _lines(file_diff.xml_diff(str(first), str(second), None))

    pkg = '/root/package-restrictions/pkg[@name="org.wikipedia"]'
    assert lines == [
        f"[ADDED] {pkg}/disabled-components",
        f"[ADDED] {pkg}/disabled-components/item"
        '[@name="androidx.work.impl.background.systemalarm.RescheduleReceiver"]',
    ]


def test_identical_files_report_no_change(tmp_path):
    first = _write(tmp_path, "first.xml", GT_FIRST)
    second = _write(tmp_path, "second.xml", GT_FIRST)

    assert "No change detected" in file_diff.xml_diff(first, second, None)
