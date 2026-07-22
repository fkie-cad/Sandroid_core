"""Unit tests for sandroid.ai.tools.host_files.

``resolve_confined_host_path``/``_allowed_roots`` are imported by name into
``host_files``'s own namespace (``from sandroid.ai.tools._host_paths import
_allowed_roots, resolve_confined_host_path``), so tests monkeypatch
``host_files.resolve_confined_host_path``/``host_files._allowed_roots``
directly rather than patching ``_host_paths``'s own names (which would not
affect the already-bound names here) -- confinement behavior itself is
covered by ``tests/ai/tools/test_host_paths.py``. Once past confinement,
these tools do plain filesystem I/O, so tests point the (mocked) resolved
path at real files/directories under ``tmp_path``.
"""

import base64

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import host_files

# -- list_host_dir --------------------------------------------------------------


def test_list_host_dir_lists_files_and_dirs_sorted_by_name(monkeypatch, tmp_path):
    (tmp_path / "b_file.txt").write_text("hello")
    (tmp_path / "a_dir").mkdir()
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: tmp_path)

    result = host_files.list_host_dir("whatever")

    assert result["path"] == str(tmp_path)
    assert result["count"] == 2
    names = [e["name"] for e in result["entries"]]
    assert names == ["a_dir", "b_file.txt"]  # sorted

    dir_entry = next(e for e in result["entries"] if e["name"] == "a_dir")
    assert dir_entry["is_dir"] is True
    assert dir_entry["size_bytes"] is None

    file_entry = next(e for e in result["entries"] if e["name"] == "b_file.txt")
    assert file_entry["is_dir"] is False
    assert file_entry["size_bytes"] == len("hello")
    assert "modified_time" in file_entry


def test_list_host_dir_empty_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: tmp_path)

    assert host_files.list_host_dir("empty") == {
        "path": str(tmp_path),
        "entries": [],
        "count": 0,
    }


def test_list_host_dir_rejects_a_file_path(monkeypatch, tmp_path):
    file_path = tmp_path / "not_a_dir.txt"
    file_path.write_text("x")
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    with pytest.raises(ToolExecutionError, match="not a directory"):
        host_files.list_host_dir("not_a_dir.txt")


def test_list_host_dir_marks_symlinks(monkeypatch, tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("data")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: tmp_path)

    result = host_files.list_host_dir("whatever")

    link_entry = next(e for e in result["entries"] if e["name"] == "link.txt")
    assert link_entry["is_symlink"] is True


# -- read_host_file ---------------------------------------------------------------


def test_read_host_file_utf8_content(monkeypatch, tmp_path):
    file_path = tmp_path / "hello.txt"
    file_path.write_text("hello world")
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    result = host_files.read_host_file("hello.txt")

    assert result["content"] == "hello world"
    assert result["encoding"] == "utf-8"
    assert result["truncated"] is False
    assert result["size_bytes"] == len("hello world")
    assert result["bytes_read"] == len("hello world")
    assert result["path"] == str(file_path)


def test_read_host_file_truncates_at_max_bytes(monkeypatch, tmp_path):
    file_path = tmp_path / "big.txt"
    file_path.write_text("a" * 100)
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    result = host_files.read_host_file("big.txt", max_bytes=10)

    assert result["truncated"] is True
    assert result["size_bytes"] == 100
    assert result["bytes_read"] == 10
    assert result["content"] == "a" * 10


def test_read_host_file_max_bytes_hard_capped_at_1mib(monkeypatch, tmp_path):
    file_path = tmp_path / "huge.bin"
    file_path.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MiB
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    result = host_files.read_host_file("huge.bin", max_bytes=10 * 1024 * 1024)

    assert result["bytes_read"] == 1024 * 1024
    assert result["truncated"] is True


def test_read_host_file_binary_content_is_base64_encoded(monkeypatch, tmp_path):
    file_path = tmp_path / "binary.bin"
    raw_bytes = b"\xff\xfe\x00\x01binary-garbage\x80"
    file_path.write_bytes(raw_bytes)
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    result = host_files.read_host_file("binary.bin")

    assert result["encoding"] == "base64"
    assert base64.b64decode(result["content"]) == raw_bytes


def test_read_host_file_nonexistent_raises(monkeypatch, tmp_path):
    missing = tmp_path / "missing.txt"
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: missing)

    with pytest.raises(ToolExecutionError, match="does not exist"):
        host_files.read_host_file("missing.txt")


def test_read_host_file_rejects_a_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: tmp_path)

    with pytest.raises(ToolExecutionError, match="directory"):
        host_files.read_host_file("some_dir")


def test_read_host_file_rejects_non_positive_max_bytes(monkeypatch, tmp_path):
    file_path = tmp_path / "hello.txt"
    file_path.write_text("hi")
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    with pytest.raises(ToolExecutionError, match="positive"):
        host_files.read_host_file("hello.txt", max_bytes=0)


def test_read_host_file_rejects_non_integer_max_bytes(monkeypatch, tmp_path):
    file_path = tmp_path / "hello.txt"
    file_path.write_text("hi")
    monkeypatch.setattr(host_files, "resolve_confined_host_path", lambda p: file_path)

    with pytest.raises(ToolExecutionError, match="integer"):
        host_files.read_host_file("hello.txt", max_bytes="not-a-number")


# -- list_allowed_host_paths ----------------------------------------------------------


def test_list_allowed_host_paths_stringifies_paths(monkeypatch, tmp_path):
    fake_roots = [
        {
            "label": "ai_data_share",
            "path": tmp_path / "share",
            "available": True,
            "reason": None,
        },
        {
            "label": "session_results",
            "path": None,
            "available": False,
            "reason": "no analysis session started yet",
        },
    ]
    monkeypatch.setattr(host_files, "_allowed_roots", lambda: fake_roots)

    result = host_files.list_allowed_host_paths()

    assert result == {
        "roots": [
            {
                "label": "ai_data_share",
                "path": str(tmp_path / "share"),
                "available": True,
                "reason": None,
            },
            {
                "label": "session_results",
                "path": None,
                "available": False,
                "reason": "no analysis session started yet",
            },
        ]
    }
