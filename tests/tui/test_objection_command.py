"""build_objection_command must produce an objection >= 1.12 command line."""

from __future__ import annotations

from click.testing import CliRunner

from sandroid.tui.modals.objection_modal import ObjectionConfig, build_objection_command


def test_attach_command():
    cmd = build_objection_command(
        "com.example.app", ObjectionConfig(spawn_mode=False), None, serial="emulator-5556"
    )
    assert cmd[1:] == ["-S", "emulator-5556", "-n", "com.example.app", "start"]


def test_spawn_with_bypass_script():
    cmd = build_objection_command(
        "com.example.app", ObjectionConfig(spawn_mode=True), "/x/b.js", serial="s1"
    )
    assert cmd[1:] == [
        "-S", "s1", "-n", "com.example.app", "-s", "-p", "start", "-S", "/x/b.js"
    ]


def test_bypass_script_skipped_when_disabled():
    cfg = ObjectionConfig(spawn_mode=False, use_bypass_script=False)
    cmd = build_objection_command("com.example.app", cfg, "/x/b.js", serial="s1")
    assert "/x/b.js" not in cmd


def test_command_line_parses_with_installed_objection(tmp_path, monkeypatch):
    """Parse our argv with objection's real click CLI (no device needed).

    The pre-2.1 argv (``-g pkg -S explore -s script``) failed here: ``-S`` is
    ``--serial`` (it swallowed "explore" -> "Missing command") and
    ``explore -s`` is a REPL startup *command*, not a script.
    """
    import requests

    # objection.utils starts an update-check thread on import; keep it offline.
    def _offline(*args, **kwargs):
        raise requests.ConnectionError("offline in tests")

    monkeypatch.setattr(requests, "get", _offline)
    from objection.console import cli as objection_cli

    script = tmp_path / "b.js"
    script.write_text("// noop")
    cmd = build_objection_command(
        "com.example.app", ObjectionConfig(spawn_mode=True), str(script), serial="s1"
    )
    seen = {}

    def fake_start(**kwargs):
        seen.update(kwargs)

    start = objection_cli.cli.commands["start"]
    original = start.callback
    start.callback = fake_start
    try:
        result = CliRunner().invoke(objection_cli.cli, cmd[1:])
    finally:
        start.callback = original
    assert result.exit_code == 0, result.output
    assert seen["startup_script"].name == str(script)
    assert objection_cli.state_connection.name == "com.example.app"
    assert objection_cli.state_connection.device_id == "s1"
    assert objection_cli.state_connection.spawn is True
    assert objection_cli.state_connection.no_pause is True
