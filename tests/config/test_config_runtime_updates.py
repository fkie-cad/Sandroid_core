"""Regression tests for runtime config updates, discovery and the config CLIs.

- Settings saves must update the *live* config (``--config`` / CLI-flag
  overrides survive), validate the whole config, and persist only the
  changed keys to the config file actually in use.
- Discovery must not pick up ``sandroid.json`` / ``config.*`` from the
  working directory (analysis result files), and saves never write there.
- ``sandroid --config FILE`` works without an auto-discovered config.
- ``sandroid-config init`` without ``-o`` refuses to clobber the user config.
- ``sandroid-config set/get`` accept positional ``KEY [VALUE]``.
- The removed ``--trigdroid`` fails with a pointer to ``--package``;
  ``-f DIR/FILE`` keeps DIR; an old ``[trigdroid]`` section loads with one
  warning.
"""

from __future__ import annotations

import json
import time
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandroid.config import (
    ConfigLoader,
    ConfigUpdateError,
    SandroidConfig,
    get_config,
    set_config,
    update_config,
)


@pytest.fixture
def xdg(tmp_path, monkeypatch):
    """Isolated user config dir + empty working directory."""
    cfg_home = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg_home))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    yield cfg_home / "sandroid", work
    set_config(None)


def _read_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text())


# -- B1: settings save keeps the live config ----------------------------------


def test_settings_save_keeps_cli_and_explicit_config(xdg, tmp_path):
    from sandroid.analysis.run_config import _analysis_toggle_defaults
    from sandroid.tui.controllers.settings_controller import SettingsController

    user_dir, _work = xdg
    user_dir.mkdir(parents=True)
    user_file = user_dir / "sandroid.toml"
    user_file.write_text('[paths]\nresults_path = "HOMERES"\n')
    explicit = tmp_path / "case.toml"
    explicit.write_text('[paths]\nresults_path = "CASERES"\n')

    cfg = ConfigLoader().load(
        config_file=explicit,
        cli_overrides={
            "emulator": {"serial": "emulator-5556"},
            "analysis": {"capture_network": True, "hash_files": True},
        },
    )
    set_config(cfg, source_file=explicit)
    before = _analysis_toggle_defaults()

    class _App:
        _sandroid_theme_name = "default"

    returned = SettingsController(_App()).save({"tui.show_theme_indicator": True})

    live = get_config()
    assert returned is live is cfg
    assert str(live.paths.results_path) == "CASERES"
    assert live.emulator.serial == "emulator-5556"
    assert live.tui.show_theme_indicator is True
    assert _analysis_toggle_defaults() == before
    assert before["network"] is True
    assert before["hash_files"] is True

    # Persisted to the --config file, only the changed key; CLI overrides
    # are not leaked into it and the user config is untouched.
    assert _read_toml(explicit) == {
        "paths": {"results_path": "CASERES"},
        "tui": {"show_theme_indicator": True},
    }
    assert user_file.read_text() == '[paths]\nresults_path = "HOMERES"\n'


def test_tui_app_load_config_uses_live_config(xdg):
    from sandroid.tui.app import SandroidTUI

    live = SandroidConfig()
    live.analysis.number_of_runs = 7
    set_config(live)
    assert SandroidTUI._load_config(object()) is live


def test_mitmproxy_enabled_addons_update_live_config(xdg, tmp_path):
    from sandroid.services.mitmproxy_service import MitmproxyService

    explicit = tmp_path / "case.toml"
    explicit.write_text('[paths]\nresults_path = "CASERES"\n')
    cfg = ConfigLoader().load(config_file=explicit)
    set_config(cfg, source_file=explicit)

    addon = tmp_path / "addon.py"
    addon.write_text("")
    svc = MitmproxyService.__new__(MitmproxyService)
    svc.is_running = lambda: False
    svc.set_enabled_addons([addon])

    assert get_config() is cfg  # not reset / reloaded
    assert str(cfg.paths.results_path) == "CASERES"
    assert cfg.mitmproxy.enabled_addons == [str(addon.resolve())]
    assert _read_toml(explicit)["mitmproxy"]["enabled_addons"] == [str(addon.resolve())]


# -- B2: validation + minimal files -------------------------------------------


def test_invalid_value_is_rejected_and_not_written(xdg):
    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    user_file = user_dir / "sandroid.toml"
    user_file.write_text('log_level = "INFO"\n')
    set_config(ConfigLoader().load())

    with pytest.raises(ConfigUpdateError, match="number_of_runs"):
        update_config({"analysis.number_of_runs": 1, "tui.show_theme_indicator": True})

    assert get_config().analysis.number_of_runs == 2
    assert get_config().tui.show_theme_indicator is not True
    assert user_file.read_text() == 'log_level = "INFO"\n'
    ConfigLoader().load()  # next start still loads


def test_change_to_section_missing_from_minimal_file_is_persisted(xdg):
    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    user_file = user_dir / "sandroid.toml"
    user_file.write_text('log_level = "INFO"\n')
    set_config(ConfigLoader().load())

    _live, saved = update_config(
        {"analysis.number_of_runs": 4, "paths.results_path": "/tmp/x"}
    )

    assert saved == user_file
    data = _read_toml(user_file)
    # Exactly the changed keys -- no dump of every default.
    assert data == {
        "log_level": "INFO",
        "analysis": {"number_of_runs": 4},
        "paths": {"results_path": "/tmp/x"},
    }
    assert isinstance(get_config().paths.results_path, Path)  # coerced
    assert ConfigLoader().load().analysis.number_of_runs == 4


async def _until(pilot, cond, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < deadline, f"condition not met within {timeout} s"
        await pilot.pause(0.01)


async def test_settings_screen_shows_error_for_invalid_runs(xdg, monkeypatch):
    from textual.app import App
    from textual.widgets import Input

    from sandroid.tui.screens.settings_screen import SettingsScreen

    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    user_file = user_dir / "sandroid.toml"
    user_file.write_text('log_level = "INFO"\n')
    live = ConfigLoader().load()
    set_config(live)

    class _Harness(App):
        sandroid_config = live

        def on_mount(self) -> None:
            self.push_screen(SettingsScreen())

    monkeypatch.setattr(SettingsScreen, "_fetch_frida_versions", lambda self: None)
    app = _Harness()
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)
        runs = screen.query_one("#setting-analysis--number_of_runs", Input)
        runs.value = "1"
        # Input.Changed bubbles to the screen: the field is checked against
        # the schema bounds, marked red and never staged (N6-B3).
        await _until(pilot, lambda: runs.id in screen._invalid)
        assert "analysis.number_of_runs" not in screen._pending
        assert runs.has_class("-invalid")
        screen.action_save()

        def messages() -> list[str]:
            return [n.message for n in app._notifications]

        await _until(pilot, lambda: any("at least 2" in m for m in messages()))
        assert app.screen is screen  # stays open

    assert user_file.read_text() == 'log_level = "INFO"\n'
    assert live.analysis.number_of_runs == 2


# -- B4: discovery / save target ----------------------------------------------


def test_cwd_result_json_and_generic_config_not_discovered(xdg):
    user_dir, work = xdg
    (work / "sandroid.json").write_text('{"output_file": "sandroid.json"}')
    (work / "config.json").write_text('{"x": 1}')
    (work / "config.toml").write_text("x = 1\n")
    original = (work / "sandroid.json").read_text()

    loader = ConfigLoader()
    assert loader._config_files == []
    target = loader.detect_and_save(SandroidConfig(log_level="DEBUG"))

    assert target == user_dir / "sandroid.toml"
    assert (work / "sandroid.json").read_text() == original


def test_cwd_sandroid_toml_still_discovered(xdg):
    _, work = xdg
    (work / "sandroid.toml").write_text('log_level = "DEBUG"\n')
    loader = ConfigLoader()
    assert loader._config_files == [work / "sandroid.toml"]
    assert loader.resolve_save_target() == work / "sandroid.toml"


def test_user_dir_config_json_still_discovered(xdg):
    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    (user_dir / "sandroid.json").write_text(json.dumps({"log_level": "DEBUG"}))
    assert ConfigLoader()._config_files == [user_dir / "sandroid.json"]


# -- B5: sandroid --config without discovered config ---------------------------


def test_cli_accepts_explicit_config_without_discovered_files(xdg, monkeypatch):
    import sandroid.cli as cli_mod

    _, work = xdg
    explicit = work / "explicit.toml"
    explicit.write_text('log_level = "INFO"\n')

    reached = {}

    def _stop(*_a, **_k):
        reached["loaded"] = True
        raise SystemExit(0)

    # Stop right after the config was loaded (before any device work).
    monkeypatch.setattr(cli_mod, "build_cli_overrides", _stop)
    result = CliRunner().invoke(cli_mod.main, ["--config", str(explicit)])

    assert "No configuration found" not in result.output
    assert reached.get("loaded") is True


def test_cli_without_any_config_still_errors(xdg):
    import sandroid.cli as cli_mod

    result = CliRunner().invoke(cli_mod.main, [])
    assert result.exit_code == 1
    assert "No configuration found" in result.output


# -- B3: sandroid-config init without -o must not clobber ----------------------


def test_config_init_without_output_refuses_to_overwrite(xdg):
    from sandroid.config.cli import main as config_main

    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    user_file = user_dir / "sandroid.toml"
    user_file.write_text('log_level = "DEBUG"\n')

    result = CliRunner().invoke(config_main, ["init", "--yes", "--skip-android-setup"])

    assert result.exit_code == 1
    assert "already exists" in result.output
    assert user_file.read_text() == 'log_level = "DEBUG"\n'

    forced = CliRunner().invoke(
        config_main, ["init", "--yes", "--skip-avd-setup", "--force"]
    )
    assert forced.exit_code == 0, forced.output
    assert user_file.read_text() != 'log_level = "DEBUG"\n'


def test_config_init_only_detects_android_paths(xdg, monkeypatch):
    """Init writes the detected tool paths and never picks or starts an AVD."""
    from sandroid.config import android_env
    from sandroid.config.cli import main as config_main

    monkeypatch.setattr(android_env, "sdk_root", lambda: Path("/sdk"))
    monkeypatch.setattr(android_env, "adb_binary", lambda: Path("/sdk/adb"))
    monkeypatch.setattr(android_env, "emulator_binary", lambda: None)
    monkeypatch.setattr(android_env, "avd_home", lambda: Path("/avd"))
    out = xdg[1] / "init.toml"

    result = CliRunner().invoke(config_main, ["init", "--yes", "-o", str(out)])

    assert result.exit_code == 0, result.output
    emulator = _read_toml(out)["emulator"]
    assert emulator["sdk_path"] == "/sdk"
    assert emulator["adb_path"] == "/sdk/adb"
    assert emulator["avd_home"] == "/avd"
    assert "android_emulator_path" not in emulator
    assert "selected_avd" not in emulator
    assert "avd_auto_start" not in emulator
    assert "Devices screen" in result.output


def test_removed_device_commands_and_old_avd_keys(xdg):
    """``avd``/``devices`` are gone; configs that still set the old keys load."""
    from sandroid.config.cli import main as config_main

    for args in (["avd", "list"], ["devices"]):
        result = CliRunner().invoke(config_main, args)
        assert result.exit_code == 2
        assert "No such command" in result.output

    user_dir, _ = xdg
    user_dir.mkdir(parents=True)
    (user_dir / "sandroid.toml").write_text(
        "[emulator]\n"
        'selected_avd = "Pixel_9"\n'
        "avd_auto_start = true\n"
        "avd_headless = true\n"
    )
    emulator = ConfigLoader().load().emulator
    assert emulator.avd_headless is True
    assert not hasattr(emulator, "selected_avd")
    assert not hasattr(emulator, "avd_auto_start")


# -- B11: positional KEY [VALUE] for set/get -----------------------------------


def test_config_set_get_accept_positional_key_value(xdg):
    from sandroid.config.cli import main as config_main

    user_dir, _ = xdg
    runner = CliRunner()

    res = runner.invoke(config_main, ["set", "mvt.enabled", "true"])
    assert res.exit_code == 0, res.output
    assert _read_toml(user_dir / "sandroid.toml")["mvt"]["enabled"] is True

    res = runner.invoke(
        config_main, ["set", "-k", "analysis.number_of_runs", "-v", "3"]
    )
    assert res.exit_code == 0, res.output
    res = runner.invoke(config_main, ["set", "-k", "analysis.number_of_runs", "4"])
    assert res.exit_code == 0, res.output

    res = runner.invoke(config_main, ["get", "analysis.number_of_runs"])
    assert res.exit_code == 0, res.output
    assert "analysis.number_of_runs = 4" in res.output
    res = runner.invoke(config_main, ["get", "-k", "mvt.enabled"])
    assert "mvt.enabled = True" in res.output

    res = runner.invoke(config_main, ["set", "mvt.enabled"])
    assert res.exit_code == 2
    assert "Missing VALUE" in res.output


def test_config_set_out_of_bounds_is_one_clean_line(xdg):
    """N6-B3/V13: a negative timeout is refused with one plain line."""
    from sandroid.config.cli import main as config_main

    user_dir, _ = xdg
    runner = CliRunner()
    for args in (
        ["set", "timeouts.adb_command", "--", "-5"],
        ["set", "-k", "timeouts.adb_command", "-v", "-5"],
        ["set", "mitmproxy.proxy_port", "70000"],
    ):
        res = runner.invoke(config_main, args)
        assert res.exit_code == 1, (args, res.output)
        lines = [line for line in res.output.splitlines() if line.strip()]
        assert len(lines) == 1, res.output
        assert lines[0].startswith("Not saved: "), res.output
        assert "errors.pydantic.dev" not in res.output
        assert "validation error" not in res.output
    assert "timeouts.adb_command: must be at least 1 (got -5)" in (
        runner.invoke(config_main, ["set", "-v", "-5", "timeouts.adb_command"]).output
    )
    assert not (user_dir / "sandroid.toml").exists()


def test_config_set_unknown_avd_warns(xdg, monkeypatch):
    """Setting a device name that is no AVD warns (but saves: CLI scripts)."""
    from sandroid.config.cli import main as config_main
    from sandroid.core import emulator

    monkeypatch.setattr(emulator, "known_avd_names", lambda: {"Dev4"})
    res = CliRunner().invoke(config_main, ["set", "emulator.device_name", "0"])
    assert res.exit_code == 0, res.output
    assert "No AVD named '0' exists (known: Dev4)" in res.output


# -- B9: the removed --trigdroid is hidden and errors clearly -------------------


def test_removed_trigdroid_option_is_hidden_and_points_to_package(xdg):
    import sandroid.cli as cli_mod

    runner = CliRunner()
    help_text = runner.invoke(cli_mod.main, ["--help"]).output
    assert "--trigdroid" not in help_text
    assert "--package" in help_text
    assert "-p," in help_text

    result = runner.invoke(cli_mod.main, ["--trigdroid", "com.example.app"])
    assert result.exit_code == 2
    assert "TrigDroid was removed (it never worked)." in result.output
    assert "Use --package/-p PKG" in result.output
    assert cli_mod.TRIGDROID_REMOVED_MESSAGE.endswith("will come as playbooks.")

    # A bare --trigdroid (no value) gets the same pointer.
    result = runner.invoke(cli_mod.main, ["--trigdroid"])
    assert result.exit_code == 2
    assert "TrigDroid was removed (it never worked)." in result.output

    # --trigdroid-ccf is gone without a replacement.
    result = runner.invoke(cli_mod.main, ["--trigdroid-ccf", "D"])
    assert result.exit_code == 2
    assert "No such option" in result.output


# -- B9b: an old [trigdroid] section still loads, with one warning --------------


def test_old_trigdroid_section_loads_and_warns_once(xdg, monkeypatch):
    from sandroid.config import loader as loader_mod

    monkeypatch.setattr(loader_mod, "_warned_removed_sections", set())
    warnings: list[str] = []
    monkeypatch.setattr(
        loader_mod.logger, "warning", lambda msg, *a: warnings.append(msg % a)
    )
    user_dir, work = xdg
    user_dir.mkdir(parents=True)
    (user_dir / "sandroid.toml").write_text(
        '[trigdroid]\nenabled = true\npackage_name = "com.example.app"\n'
        'config_mode = "I"\n\n[paths]\nresults_path = "res"\n'
    )

    config = ConfigLoader().load()
    ConfigLoader().load()

    assert not hasattr(config, "trigdroid")
    assert "trigdroid" not in config.model_dump()
    assert config.paths.results_path.name == "res"
    assert len(warnings) == 1
    assert "[trigdroid] ignored: TrigDroid was removed" in warnings[0]


# -- B10: -f DIR/FILE keeps the directory ---------------------------------------


def test_cli_results_copied_to_full_f_path(xdg, tmp_path):
    from sandroid.cli_modes.analysis import _deliver_to_requested_path

    _, work = xdg
    session = tmp_path / "session"
    session.mkdir()
    written = session / "out.json"
    written.write_text('{"ok": true}')

    final = _deliver_to_requested_path(written, Path("reports/case1/out.json"))
    assert final == work / "reports" / "case1" / "out.json"
    assert final.read_text() == '{"ok": true}'
    assert written.exists()  # session copy (covered by the manifest) stays

    absolute = tmp_path / "abs" / "out.json"
    assert _deliver_to_requested_path(written, absolute) == absolute
    assert absolute.exists()

    # A bare file name keeps the old behaviour: only the session copy.
    assert _deliver_to_requested_path(written, Path("out.json")) == written
    assert not (work / "out.json").exists()


# -- load_and_update_section: only the given keys, never secrets ---------------


def test_section_update_writes_only_its_keys_and_keeps_the_file(xdg, monkeypatch):
    """A project ``sandroid.toml`` holding an API key must not become a dump
    of the whole merged config (defaults, env secrets, other sections).
    """
    import stat

    _user_dir, work = xdg
    project = work / "sandroid.toml"
    project.write_text('# my project\n[ai]\napi_key = "sk-file-key"\nmodel = "m"\n')
    project.chmod(0o640)
    monkeypatch.setenv("SANDROID_CREDENTIALS__CUSTOM_API_KEYS__X", "sk-env-cred")
    monkeypatch.setenv("SANDROID_AI__BASE_URL", "https://env.example/v1")

    updated, path = ConfigLoader().load_and_update_section(
        "tui", {"snapshot_save_mode": "overwrite"}
    )

    assert path == project
    assert updated.tui.snapshot_save_mode == "overwrite"
    data = _read_toml(project)
    assert data == {
        "ai": {"api_key": "sk-file-key", "model": "m"},
        "tui": {"snapshot_save_mode": "overwrite"},
    }
    text = project.read_text()
    assert "sk-env-cred" not in text
    assert "env.example" not in text
    assert stat.S_IMODE(project.stat().st_mode) == 0o640


def test_section_update_never_writes_secrets(xdg):
    _user_dir, _work = xdg
    loader = ConfigLoader()
    with pytest.raises(ValueError, match="secret"):
        loader.load_and_update_section("ai", {"api_key": "sk-x"})
    with pytest.raises(ValueError, match="secret"):
        loader.load_and_update_section("credentials", {"custom_api_keys": {"a": "b"}})
    with pytest.raises(ValueError, match="unknown"):
        loader.load_and_update_section("tui", {"no_such_key": 1})
    assert not _user_dir.exists() or not any(_user_dir.iterdir())


def test_section_update_new_user_file_is_private(xdg):
    import stat

    user_dir, _work = xdg
    _cfg, path = ConfigLoader().load_and_update_section(
        "tui", {"snapshot_slots": {"avd": {"1": "tag"}}}
    )
    assert path == user_dir / "sandroid.toml"
    assert _read_toml(path) == {"tui": {"snapshot_slots": {"avd": {"1": "tag"}}}}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_ui_state_file_is_private_atomic_and_separate(xdg):
    import stat

    from sandroid.config.ui_state import load_ui_state, ui_state_path, update_ui_state

    user_dir, _work = xdg
    path = update_ui_state("chat_dock", {"ratio": 0.7, "maximized": True})
    assert path == ui_state_path() == user_dir / "tui_state.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    update_ui_state("other", 1)
    assert load_ui_state() == {
        "chat_dock": {"ratio": 0.7, "maximized": True},
        "other": 1,
    }
    update_ui_state("other", None)
    assert load_ui_state() == {"chat_dock": {"ratio": 0.7, "maximized": True}}
    assert [p.name for p in user_dir.iterdir()] == ["tui_state.json"]  # no temp left
    # Never discovered as a config file.
    assert path not in ConfigLoader()._config_files
    path.write_text("not json")
    assert load_ui_state() == {}
