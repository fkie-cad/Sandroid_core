"""Regression test: abx_xml_diff decodes ABX files in-process via AbxReader
(no subprocess, no ccl_abx.py CLI invocation) and diffs the resulting XML.

The two byte sequences below are minimal, hand-built valid ABX streams
(MAGIC + START_DOCUMENT/START_TAG/TEXT/END_TAG/END_DOCUMENT tokens per the
documented ABX token format in ccl_abx.py) encoding `<foo>v1</foo>` and
`<foo>v2</foo>` respectively.
"""

from __future__ import annotations

import struct
import subprocess

import pytest

from sandroid.core import file_diff


def _interned(s):
    return struct.pack(">h", -1) + struct.pack(">h", len(s)) + s.encode("utf-8")


def _raw_string(s):
    return struct.pack(">h", len(s)) + s.encode("utf-8")


def _build_abx(text):
    return (
        b"ABX\x00"
        + bytes([0x10])  # START_DOCUMENT
        + bytes([0x32]) + _interned("foo")  # START_TAG foo
        + bytes([0x04]) + _raw_string(text)  # TEXT
        + bytes([0x33]) + _interned("foo")  # END_TAG foo
        + bytes([0x11])  # END_DOCUMENT
    )


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch):
    """The old bug shelled out to ccl_abx.py -- assert it never does again."""

    def _boom(*args, **kwargs):
        raise AssertionError("abx_xml_diff must not spawn a subprocess")

    monkeypatch.setattr(subprocess, "run", _boom)


def test_abx_xml_diff_decodes_in_process_and_reports_change(tmp_path):
    path1 = tmp_path / "first.xml"
    path2 = tmp_path / "second.xml"
    path1.write_bytes(_build_abx("v1"))
    path2.write_bytes(_build_abx("v2"))

    diff = file_diff.abx_xml_diff(str(path1), str(path2))

    assert "No change detected" not in diff
    assert "v2" in diff


def test_abx_xml_diff_handles_corrupt_file_without_raising(tmp_path):
    path1 = tmp_path / "first.xml"
    path2 = tmp_path / "second.xml"
    path1.write_bytes(b"not an abx file")
    path2.write_bytes(_build_abx("v2"))

    diff = file_diff.abx_xml_diff(str(path1), str(path2))

    assert "Failed to convert ABX files" in diff
