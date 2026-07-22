"""Unit tests for sandroid.ai.tools._host_paths.

``_allowed_roots()`` reads ``Toolbox.config.ai``/``Toolbox.config.paths``
(a plain class attribute assigned at runtime by ``core/initializer.py``, see
that module's ``Toolbox.config = config``) and lazily imports
``sandroid.services.get_configuration_service`` from inside its own body --
so tests monkeypatch ``Toolbox.config`` directly and
``sandroid.services.get_configuration_service`` the same way
``tests/ai/tools/test_environment_control.py`` patches sibling lazy getters.
"""

from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import _host_paths
from sandroid.core.toolbox import Toolbox


def _patch_config(
    monkeypatch, *, data_share_path, extra_host_paths=None, cache_path=None
):
    """Point ``Toolbox.config`` at a fake config exposing just what
    ``_allowed_roots`` reads (``config.ai.data_share_path``,
    ``config.ai.extra_host_paths``, ``config.paths.cache_path``).
    """
    ai_cfg = SimpleNamespace(
        data_share_path=data_share_path,
        extra_host_paths=extra_host_paths or [],
    )
    paths_cfg = SimpleNamespace(cache_path=cache_path)
    monkeypatch.setattr(
        Toolbox, "config", SimpleNamespace(ai=ai_cfg, paths=paths_cfg), raising=False
    )


def _patch_no_session(monkeypatch, tmp_path):
    """Point the session results/raw-results getters at dirs that don't exist,
    so ``session_results``/``session_raw_results`` are unavailable roots --
    matching "no analysis session started yet".
    """
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(
            get_results_path=lambda: str(tmp_path / "no-such-results"),
            get_raw_results_path=lambda: str(tmp_path / "no-such-raw-results"),
        ),
    )


# -- relative-path anchoring to ai_data_share -----------------------------------


def test_relative_path_anchors_to_ai_data_share(monkeypatch, tmp_path):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    resolved = _host_paths.resolve_confined_host_path("some_file.txt")

    assert resolved == (share / "some_file.txt").resolve()
    assert share.is_dir()  # created automatically


def test_relative_path_with_subdirectory_still_anchors_inside_share(
    monkeypatch, tmp_path
):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    resolved = _host_paths.resolve_confined_host_path("sub/dir/file.txt")

    assert resolved == (share / "sub" / "dir" / "file.txt").resolve()


# -- ".."-escape rejection -------------------------------------------------------


def test_dotdot_escape_is_rejected(monkeypatch, tmp_path):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    with pytest.raises(ToolExecutionError, match="outside every allowed"):
        _host_paths.resolve_confined_host_path("../escaped.txt")


def test_dotdot_escape_is_rejected_even_with_absolute_looking_prefix(
    monkeypatch, tmp_path
):
    """A deeper '../../' climb from inside the share dir must still land
    outside every allowed root and be rejected.
    """
    share = tmp_path / "share" / "nested"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    with pytest.raises(ToolExecutionError):
        _host_paths.resolve_confined_host_path("../../../etc/passwd")


# -- symlink-escape rejection -----------------------------------------------------


def test_symlink_escaping_the_share_dir_is_rejected(monkeypatch, tmp_path):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)
    # Ensure the share dir exists before planting a symlink inside it.
    _host_paths.resolve_confined_host_path("noop_to_create_dir.txt")

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("top secret")

    link = share / "escape_link"
    link.symlink_to(outside_dir)

    with pytest.raises(ToolExecutionError, match="outside every allowed"):
        _host_paths.resolve_confined_host_path("escape_link/secret.txt")


def test_symlink_staying_inside_the_share_dir_is_allowed(monkeypatch, tmp_path):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    real_dir = share / "real"
    real_dir.mkdir(parents=True)
    (real_dir / "file.txt").write_text("hello")

    link = share / "link"
    link.symlink_to(real_dir)

    resolved = _host_paths.resolve_confined_host_path("link/file.txt")

    assert resolved == (real_dir / "file.txt").resolve()


# -- extra_host_paths extension ---------------------------------------------------


def test_extra_host_paths_extension_allows_absolute_path_within_it(
    monkeypatch, tmp_path
):
    share = tmp_path / "share"
    extra = tmp_path / "extra_root"
    extra.mkdir()
    (extra / "payload.bin").write_bytes(b"data")

    _patch_config(monkeypatch, data_share_path=share, extra_host_paths=[extra])
    _patch_no_session(monkeypatch, tmp_path)

    resolved = _host_paths.resolve_confined_host_path(str(extra / "payload.bin"))

    assert resolved == (extra / "payload.bin").resolve()


def test_extra_host_paths_entry_marked_unavailable_when_missing(monkeypatch, tmp_path):
    share = tmp_path / "share"
    missing_extra = tmp_path / "does-not-exist"

    _patch_config(monkeypatch, data_share_path=share, extra_host_paths=[missing_extra])
    _patch_no_session(monkeypatch, tmp_path)

    roots = _host_paths._allowed_roots()
    extra_entries = [r for r in roots if r["label"] == "extra"]

    assert len(extra_entries) == 1
    assert extra_entries[0]["available"] is False
    assert extra_entries[0]["reason"] == "configured but does not exist"


def test_path_outside_share_and_outside_extra_root_is_still_rejected(
    monkeypatch, tmp_path
):
    share = tmp_path / "share"
    extra = tmp_path / "extra_root"
    extra.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "file.txt").write_text("nope")

    _patch_config(monkeypatch, data_share_path=share, extra_host_paths=[extra])
    _patch_no_session(monkeypatch, tmp_path)

    with pytest.raises(ToolExecutionError):
        _host_paths.resolve_confined_host_path(str(unrelated / "file.txt"))


# -- empty-path rejection ----------------------------------------------------------


def test_empty_path_is_rejected(monkeypatch, tmp_path):
    share = tmp_path / "share"
    _patch_config(monkeypatch, data_share_path=share)
    _patch_no_session(monkeypatch, tmp_path)

    with pytest.raises(ToolExecutionError, match="must not be empty"):
        _host_paths.resolve_confined_host_path("")


# -- "no roots available" message ---------------------------------------------------


def test_no_roots_available_raises_with_hint(monkeypatch, tmp_path):
    """When ai_data_share can't be created and no session/cache/extra root
    is available either, resolve_confined_host_path must raise a distinct
    "no host paths are currently accessible" error rather than a confinement
    rejection naming an empty root list.
    """
    # A file (not a directory) in the data_share_path's place makes
    # share.mkdir(parents=True, exist_ok=True) raise.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    unusable_share = blocker / "share"

    _patch_config(monkeypatch, data_share_path=unusable_share)
    _patch_no_session(monkeypatch, tmp_path)

    with pytest.raises(
        ToolExecutionError, match="no host paths are currently accessible"
    ):
        _host_paths.resolve_confined_host_path("anything.txt")


def test_no_roots_available_reflected_in_allowed_roots_listing(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    unusable_share = blocker / "share"

    _patch_config(monkeypatch, data_share_path=unusable_share)
    _patch_no_session(monkeypatch, tmp_path)

    roots = _host_paths._allowed_roots()

    assert all(not r["available"] for r in roots)
    share_entry = next(r for r in roots if r["label"] == "ai_data_share")
    assert share_entry["path"] is None
    assert share_entry["reason"]


# -- cache root -----------------------------------------------------------------


def test_cache_path_becomes_an_available_root_when_configured(monkeypatch, tmp_path):
    share = tmp_path / "share"
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "cached.bin").write_bytes(b"x")

    _patch_config(monkeypatch, data_share_path=share, cache_path=cache)
    _patch_no_session(monkeypatch, tmp_path)

    resolved = _host_paths.resolve_confined_host_path(str(cache / "cached.bin"))

    assert resolved == (cache / "cached.bin").resolve()
