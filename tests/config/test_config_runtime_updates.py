"""Regression tests for runtime config updates, discovery and the config CLIs.

- Settings saves must update the *live* config (``--config`` / CLI-flag
  overrides survive), validate the whole config, and persist only the
  changed keys to the config file actually in use.
- Discovery must not pick up ``sandroid.json`` / ``config.*`` from the
  working directory (analysis result files), and saves never write there.
- ``sandroid --config FILE`` works without an auto-discovered config.
- ``sandroid-config init`` without ``-o`` refuses to clobber the user config.
- ``sandroid-config set/get`` accept positional ``KEY [VALUE]``.
"""

from __future__ import annotations

import json
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
        await pilot.pause()
        screen.action_save()
        await pilot.pause()
        assert app.screen is screen  # stays open
        messages = [n.message for n in app._notifications]
        assert any("number_of_runs" in m for m in messages)

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

    result = CliRunner().invoke(config_main, ["init", "--yes", "--skip-avd-setup"])

    assert result.exit_code == 1
    assert "already exists" in result.output
    assert user_file.read_text() == 'log_level = "DEBUG"\n'

    forced = CliRunner().invoke(
        config_main, ["init", "--yes", "--skip-avd-setup", "--force"]
    )
    assert forced.exit_code == 0, forced.output
    assert user_file.read_text() != 'log_level = "DEBUG"\n'


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
