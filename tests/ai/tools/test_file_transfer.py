"""Unit tests for sandroid.ai.tools.file_transfer.

``file_transfer.py`` builds its own small helpers (``_raw_results_root``,
``_long_timeout_extraction_service``, ``_run_transfer_command``) rather than
going through the shared ``FileExtractionService`` singleton -- see that
module's docstring for why (the 30s ``Adb.send_adb_command`` timeout is too
short for large device<->host transfers). Tests here monkeypatch those
module-level names directly, plus ``resolve_confined_host_path`` and
``resolve_package_name`` (both imported by name into ``file_transfer``'s own
namespace, so patching ``_host_paths``/``_shared`` would not affect the
already-bound names here -- same convention as
``tests/ai/tools/test_app_lifecycle.py``). ``Adb.send_adb_command`` is
monkeypatched directly on the class, matching
``tests/ai/tools/test_device_query.py``.
"""

import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import file_transfer
from sandroid.ai.tools._shared import validate_package_name
from sandroid.core.adb import Adb
from sandroid.services.file_extraction_service import ExtractionResult

# -- shared helpers ---------------------------------------------------------------


def _passthrough_confinement(monkeypatch):
    """No-op confinement: returns whatever Path was asked for, unmodified.

    Confinement rejection behavior itself is covered by
    ``tests/ai/tools/test_host_paths.py`` -- these tests are about
    file_transfer's own destination-building/quoting/dispatch logic.
    """
    monkeypatch.setattr(file_transfer, "resolve_confined_host_path", Path)


def _fixed_timestamp(monkeypatch, value="2026-01-01_00-00-00"):
    monkeypatch.setattr(file_transfer.time, "strftime", lambda fmt: value)


def _fake_extraction_service(monkeypatch, **methods):
    monkeypatch.setattr(
        file_transfer,
        "_long_timeout_extraction_service",
        lambda: SimpleNamespace(**methods),
    )


# -- pull_path ----------------------------------------------------------------------


def test_pull_path_empty_remote_path_raises():
    with pytest.raises(ToolExecutionError, match="must not be empty"):
        file_transfer.pull_path("")


def test_pull_path_success_uses_remote_path_basename(monkeypatch, tmp_path):
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch)

    captured = {}

    def fake_pull_file(remote_path, local_path, compute_hash):
        captured.update(
            remote_path=remote_path, local_path=local_path, compute_hash=compute_hash
        )
        return ExtractionResult(
            source_path=remote_path,
            local_path=local_path,
            success=True,
            hash_sha256="deadbeef",
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    result = file_transfer.pull_path("/data/local/tmp/config.xml")

    expected_destination = tmp_path / "ai_pulls" / "2026-01-01_00-00-00_config.xml"
    assert captured["remote_path"] == shlex.quote("/data/local/tmp/config.xml")
    assert captured["local_path"] == str(expected_destination)
    assert captured["compute_hash"] is True
    assert result == {
        "remote_path": "/data/local/tmp/config.xml",
        "local_path": str(expected_destination),
        "success": True,
        "error": None,
        "hash_sha256": "deadbeef",
    }


def test_pull_path_local_filename_hint_is_basenamed(monkeypatch, tmp_path):
    """A directory component or '../' escape in local_filename must be
    stripped down to a bare filename -- it can only name the file, never
    redirect where it lands.
    """
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")

    captured = {}

    def fake_pull_file(remote_path, local_path, compute_hash):
        captured["local_path"] = local_path
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    file_transfer.pull_path("/data/local/tmp/x", local_filename="../../etc/evil.txt")

    assert captured["local_path"] == str(tmp_path / "ai_pulls" / "TS_evil.txt")


def test_pull_path_sanitizes_shell_metacharacters_in_local_filename(
    monkeypatch, tmp_path
):
    """Regression (review-caught, PoC-confirmed HIGH bug): a local_filename
    whose basename contains shell metacharacters used to reach
    FileExtractionService.pull_file's unquoted
    f"pull {remote_path} {local_path}" completely unsanitized beyond
    stripping '/', letting a crafted filename execute on the HOST machine.
    The destination actually used must be built from the *sanitized*
    basename -- not merely "doesn't crash". (No '/' in the payload itself --
    os.path.basename() already reduces anything containing '/' down to the
    last path component, which is a separate, pre-existing protection this
    test is not about.)
    """
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")

    captured = {}

    def fake_pull_file(remote_path, local_path, compute_hash):
        captured["local_path"] = local_path
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    malicious_filename = "innocent.txt; touch POC_MARKER #"
    file_transfer.pull_path("/data/local/tmp/x", local_filename=malicious_filename)

    # Disallowed characters are stripped outright (not replaced), so
    # "innocent.txt; touch POC_MARKER #" collapses to the concatenation of
    # its allowed-charset runs.
    expected = tmp_path / "ai_pulls" / "TS_innocent.txttouchPOC_MARKER"
    assert captured["local_path"] == str(expected)
    for char in (";", "#", " ", "/"):
        assert char not in Path(captured["local_path"]).name


def test_pull_path_falls_back_to_pulled_file_when_sanitized_basename_is_empty(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")

    captured = {}

    def fake_pull_file(remote_path, local_path, compute_hash):
        captured["local_path"] = local_path
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    file_transfer.pull_path("/data/local/tmp/x", local_filename=";;;###")

    assert captured["local_path"] == str(tmp_path / "ai_pulls" / "TS_pulled_file")


def test_pull_path_failure_propagates_error(monkeypatch, tmp_path):
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch)
    _fake_extraction_service(
        monkeypatch,
        pull_file=lambda remote_path, local_path, compute_hash: ExtractionResult(
            source_path=remote_path,
            local_path=local_path,
            success=False,
            error="remote object 'foo' does not exist",
        ),
    )

    result = file_transfer.pull_path("/data/local/tmp/foo")

    assert result["success"] is False
    assert result["error"] == "remote object 'foo' does not exist"


def test_pull_path_builds_absolute_destination_before_confinement_check(
    monkeypatch, tmp_path
):
    """Regression (review-caught bug): ConfigurationService.get_raw_results_path()
    returns a RELATIVE string by construction (e.g. "results/raw/"). pull_path
    must resolve that to an ABSOLUTE path before ever calling
    resolve_confined_host_path -- passing the raw relative string straight
    through would silently anchor the destination against ai_data_share
    instead of the session's own raw-results directory.

    This deliberately does *not* mock ``_raw_results_root`` -- it exercises
    the real implementation against a mocked (relative-returning)
    ``get_configuration_service()``.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(get_raw_results_path=lambda: "results/raw/"),
    )
    _fixed_timestamp(monkeypatch, "TS")

    captured_confine_arg = {}

    def fake_resolve_confined(path_str):
        captured_confine_arg["path"] = path_str
        return Path(path_str)

    monkeypatch.setattr(
        file_transfer, "resolve_confined_host_path", fake_resolve_confined
    )
    _fake_extraction_service(
        monkeypatch,
        pull_file=lambda remote_path, local_path, compute_hash: ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        ),
    )

    file_transfer.pull_path("/data/local/tmp/foo.txt")

    destination = Path(captured_confine_arg["path"])
    ai_data_share_default = Path("~/Sandroid/ai_share/").expanduser().resolve()

    assert destination.is_absolute()
    assert ai_data_share_default != destination
    assert ai_data_share_default not in destination.parents
    assert (
        destination
        == (tmp_path / "results" / "raw").resolve() / "ai_pulls" / "TS_foo.txt"
    )


# -- push_path ------------------------------------------------------------------------


def test_push_path_empty_remote_path_raises():
    with pytest.raises(ToolExecutionError, match="must not be empty"):
        file_transfer.push_path("payload.bin", "")


def test_push_path_success(monkeypatch):
    resolved = Path("/host/share/payload.bin")
    monkeypatch.setattr(file_transfer, "resolve_confined_host_path", lambda p: resolved)

    captured = {}

    def fake_run(command):
        captured["command"] = command
        return "", ""

    monkeypatch.setattr(file_transfer, "_run_transfer_command", fake_run)

    result = file_transfer.push_path("payload.bin", "/data/local/tmp/payload.bin")

    expected_command = (
        f"push {shlex.quote(str(resolved))} "
        f"{shlex.quote('/data/local/tmp/payload.bin')}"
    )
    assert captured["command"] == expected_command
    assert result == {
        "pushed": True,
        "local_path": str(resolved),
        "remote_path": "/data/local/tmp/payload.bin",
        "message": f"Pushed {resolved} to /data/local/tmp/payload.bin",
    }


def test_push_path_quotes_paths_with_shell_metacharacters(monkeypatch):
    resolved = Path("/host/share/weird; rm -rf.bin")
    monkeypatch.setattr(file_transfer, "resolve_confined_host_path", lambda p: resolved)

    captured = {}
    monkeypatch.setattr(
        file_transfer,
        "_run_transfer_command",
        lambda command: (captured.setdefault("command", command), ("", ""))[1],
    )

    file_transfer.push_path("weird.bin", "/data/local/tmp/x; rm -rf /")

    assert shlex.quote(str(resolved)) in captured["command"]
    assert shlex.quote("/data/local/tmp/x; rm -rf /") in captured["command"]


def test_push_path_detects_failure_from_stderr(monkeypatch):
    monkeypatch.setattr(
        file_transfer,
        "resolve_confined_host_path",
        lambda p: Path("/host/share/payload.bin"),
    )
    monkeypatch.setattr(
        file_transfer,
        "_run_transfer_command",
        lambda command: ("", "Permission denied"),
    )

    result = file_transfer.push_path("payload.bin", "/data/local/tmp/x")

    assert result["pushed"] is False
    assert "Permission denied" in result["message"]


def test_push_path_resolution_failure_propagates(monkeypatch):
    def fake_resolve(p):
        raise ToolExecutionError("path is outside every allowed host directory")

    monkeypatch.setattr(file_transfer, "resolve_confined_host_path", fake_resolve)

    with pytest.raises(ToolExecutionError, match="outside every allowed"):
        file_transfer.push_path("/etc/passwd", "/data/local/tmp/x")


# -- pull_apk -----------------------------------------------------------------------


def test_pull_apk_pulls_every_split(monkeypatch, tmp_path):
    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(
            lambda command: (
                "package:/data/app/pkg/base.apk\n"
                "package:/data/app/pkg/split_config.apk\n",
                "",
            )
        ),
    )
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")

    pulled = []

    def fake_pull_file(remote_path, local_path, compute_hash):
        pulled.append((remote_path, local_path))
        return ExtractionResult(
            source_path=remote_path,
            local_path=local_path,
            success=True,
            hash_sha256="h",
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    result = file_transfer.pull_apk("com.example.app")

    expected_dir = tmp_path / "ai_pulls" / "apks" / "com.example.app_TS"
    assert result["package_name"] == "com.example.app"
    assert result["destination_dir"] == str(expected_dir)
    assert result["success"] is True
    assert len(result["splits"]) == 2
    assert pulled[0][1] == str(expected_dir / "base.apk")
    assert pulled[1][1] == str(expected_dir / "split_config.apk")


def test_pull_apk_sanitizes_shell_metacharacters_in_split_basename(
    monkeypatch, tmp_path
):
    """Regression (review-caught HIGH bug, defense in depth): each split's
    destination filename (derived from the device-side path's basename) must
    go through the same sanitization as pull_path's local_filename, even
    though real 'pm path' output rarely contains metacharacters.
    """
    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(
            lambda command: (
                "package:/data/app/pkg/base; touch POC_MARKER #.apk\n",
                "",
            )
        ),
    )
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")

    pulled = []

    def fake_pull_file(remote_path, local_path, compute_hash):
        pulled.append(local_path)
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    _fake_extraction_service(monkeypatch, pull_file=fake_pull_file)

    file_transfer.pull_apk("com.example.app")

    expected_dir = tmp_path / "ai_pulls" / "apks" / "com.example.app_TS"
    assert pulled == [str(expected_dir / "basetouchPOC_MARKER.apk")]
    for char in (";", "#", " ", "/"):
        assert char not in Path(pulled[0]).name


def test_pull_apk_rejects_malicious_package_name(monkeypatch):
    """Regression (MEDIUM finding): package_name must be validated against
    Android's package-identifier format before it is used anywhere -- not
    just relied on for shlex.quote()-ing the 'pm path' shell command.
    """
    monkeypatch.setattr(
        file_transfer,
        "resolve_package_name",
        lambda p: p or "com.example; touch POC_MARKER #",
    )
    called = []
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(lambda command: (called.append(command), ("", ""))[1]),
    )

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        file_transfer.pull_apk("com.example; touch POC_MARKER #")

    assert called == []


def test_pull_apk_not_installed_raises(monkeypatch):
    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(lambda command: ("", "")))

    with pytest.raises(ToolExecutionError, match="not installed"):
        file_transfer.pull_apk("com.example.app")


def test_pull_apk_uses_spotlight_fallback_when_package_name_omitted(
    monkeypatch, tmp_path
):
    captured = {}

    def fake_resolve_package_name(package_name):
        captured["package_name"] = package_name
        return "com.spotlight.app"

    monkeypatch.setattr(
        file_transfer, "resolve_package_name", fake_resolve_package_name
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(lambda command: ("package:/data/app/pkg/base.apk\n", "")),
    )
    monkeypatch.setattr(file_transfer, "_raw_results_root", lambda: tmp_path)
    _passthrough_confinement(monkeypatch)
    _fixed_timestamp(monkeypatch, "TS")
    _fake_extraction_service(
        monkeypatch,
        pull_file=lambda remote_path, local_path, compute_hash: ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        ),
    )

    result = file_transfer.pull_apk()

    assert captured["package_name"] is None
    assert result["package_name"] == "com.spotlight.app"


def test_pull_apk_builds_absolute_destination_before_confinement_check(
    monkeypatch, tmp_path
):
    """Regression (review-caught bug), pull_apk's own copy of the same bug
    class as pull_path's -- see that test's docstring. Deliberately does not
    mock ``_raw_results_root``.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(get_raw_results_path=lambda: "results/raw/"),
    )
    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(lambda command: ("package:/data/app/pkg/base.apk\n", "")),
    )
    _fixed_timestamp(monkeypatch, "TS")

    captured_confine_arg = {}

    def fake_resolve_confined(path_str):
        captured_confine_arg["path"] = path_str
        return Path(path_str)

    monkeypatch.setattr(
        file_transfer, "resolve_confined_host_path", fake_resolve_confined
    )
    _fake_extraction_service(
        monkeypatch,
        pull_file=lambda remote_path, local_path, compute_hash: ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        ),
    )

    file_transfer.pull_apk("com.example.app")

    destination = Path(captured_confine_arg["path"])
    ai_data_share_default = Path("~/Sandroid/ai_share/").expanduser().resolve()

    assert destination.is_absolute()
    assert ai_data_share_default not in destination.parents
    assert destination == (
        (tmp_path / "results" / "raw").resolve()
        / "ai_pulls"
        / "apks"
        / "com.example.app_TS"
        / "base.apk"
    )


# -- pull_app_data --------------------------------------------------------------------


def test_pull_app_data_success_mixed_results(monkeypatch):
    captured = {}

    def fake_pull_all_for_package(pkg):
        captured["package_name"] = pkg
        return [
            ExtractionResult(
                source_path="/data/data/com.example.app/db1",
                local_path="/host/db1",
                success=True,
                hash_sha256="a",
            ),
            ExtractionResult(
                source_path="/data/data/com.example.app/db2",
                local_path="/host/db2",
                success=False,
                error="permission denied",
            ),
        ]

    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    _fake_extraction_service(
        monkeypatch, pull_all_for_package=fake_pull_all_for_package
    )

    result = file_transfer.pull_app_data("com.example.app")

    assert captured["package_name"] == "com.example.app"
    assert result["package_name"] == "com.example.app"
    assert result["count"] == 2
    assert result["success"] is False
    assert result["files"][0]["hash_sha256"] == "a"
    assert result["files"][1]["error"] == "permission denied"


def test_pull_app_data_rejects_malicious_package_name(monkeypatch):
    """Regression (HIGH bug, PoC confirmed): package_name previously reached
    FileExtractionService.pull_all_for_package with ZERO shlex.quote() at
    all -- a package_name like "com.example; touch POC_MARKER #" executed on
    the HOST machine via pull_all_for_package's internal
    'shell find {app_path} ...' command. Must now be rejected by
    validate_package_name() before pull_all_for_package is ever called.
    """
    monkeypatch.setattr(
        file_transfer,
        "resolve_package_name",
        lambda p: p or "com.example.app",
    )
    called = []
    _fake_extraction_service(monkeypatch, pull_all_for_package=called.append)

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        file_transfer.pull_app_data("com.example; touch POC_MARKER #")

    assert called == []


def test_pull_app_data_empty_is_vacuously_successful(monkeypatch):
    monkeypatch.setattr(
        file_transfer, "resolve_package_name", lambda p: p or "com.example.app"
    )
    _fake_extraction_service(monkeypatch, pull_all_for_package=lambda pkg: [])

    result = file_transfer.pull_app_data("com.example.app")

    assert result == {
        "package_name": "com.example.app",
        "files": [],
        "count": 0,
        "success": True,
    }


# -- validate_package_name (sandroid.ai.tools._shared) ---------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "com.example.app",
        "com.example",
        "com.example.app.debug",
        "a.b",
        "com.example_app.v2",
    ],
)
def test_validate_package_name_accepts_valid_names(name):
    assert validate_package_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "com",  # single segment -- no dot at all
        "com.example; touch POC_MARKER #",
        "com.example && rm -rf /",
        "com.example`whoami`",
        "com.example$(whoami)",
        "com.example/../etc",
        "com.example app",  # bare space
        ".com.example",  # leading dot / empty first segment
        "com..example",  # empty middle segment
        "com.example.",  # trailing dot / empty last segment
        "1com.example",  # segment starting with a digit
    ],
)
def test_validate_package_name_rejects_invalid_names(name):
    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        validate_package_name(name)
