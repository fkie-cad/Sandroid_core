"""Unit tests for config/schema.py's TUIConfig -- the monitor_event_visibility
field/validator (per-category Monitor visibility, configurable in Settings)
added alongside monitor_max_lines, the monitor_backend validator, and the
legacy ``fsmon_*`` -> ``monitor_*`` back-fill.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandroid.config.schema import AnalysisConfig, TUIConfig


class TestMonitorEventVisibility:
    def test_default_value(self):
        config = TUIConfig()

        assert config.monitor_event_visibility == {
            "create": "always",
            "modify": "always",
            "delete": "always",
            "rename": "always",
            "attrs": "always",
            "noise": "verbose",
        }

    def test_invalid_mode_raises_validation_error(self):
        with pytest.raises(ValidationError):
            TUIConfig(monitor_event_visibility={"create": "bogus"})

    def test_valid_partial_override_round_trips(self):
        config = TUIConfig(monitor_event_visibility={"noise": "never"})

        assert config.monitor_event_visibility == {"noise": "never"}


class TestMonitorBackend:
    def test_default_value(self):
        assert TUIConfig().monitor_backend == "kprobe"

    def test_invalid_backend_raises_validation_error(self):
        with pytest.raises(ValidationError):
            TUIConfig(monitor_backend="bogus")

    @pytest.mark.parametrize("backend", ["fsmon", "kprobe"])
    def test_valid_backends_round_trip(self, backend):
        assert TUIConfig(monitor_backend=backend).monitor_backend == backend

    def test_legacy_auto_migrates_to_kprobe(self):
        """A config carrying the dropped ``"auto"`` value normalizes in-memory
        to ``"kprobe"``, while an unknown value still raises.
        """
        assert TUIConfig(monitor_backend="auto").monitor_backend == "kprobe"
        with pytest.raises(ValidationError):
            TUIConfig(monitor_backend="bogus")


class TestAnalysisCaptureKeys:
    """The automated-analysis-run toggles were renamed ``monitor_*`` ->
    ``capture_*``; new-name construction works with the documented defaults and
    a config dict carrying the legacy ``monitor_*`` keys back-fills them.
    """

    def test_new_name_defaults(self):
        config = AnalysisConfig()

        assert config.capture_processes is True
        assert config.capture_sockets is False
        assert config.capture_network is False

    def test_new_name_construction_round_trips(self):
        config = AnalysisConfig(
            capture_processes=False,
            capture_sockets=True,
            capture_network=True,
        )

        assert config.capture_processes is False
        assert config.capture_sockets is True
        assert config.capture_network is True

    def test_legacy_monitor_keys_backfill(self):
        config = AnalysisConfig(
            monitor_processes=False,
            monitor_sockets=True,
            monitor_network=True,
        )

        assert config.capture_processes is False
        assert config.capture_sockets is True
        assert config.capture_network is True

    def test_new_key_wins_when_both_present(self):
        config = AnalysisConfig(
            monitor_network=True,
            capture_network=False,
        )

        assert config.capture_network is False


class TestLegacyMonitorKeyBackfill:
    """Existing configs still carrying the old ``fsmon_*`` keys must have those
    values copied onto the new ``monitor_*`` fields (sub-models default to
    ``extra="ignore"``, so without the back-fill they would be silently lost).
    """

    def test_all_three_legacy_keys_backfill(self):
        config = TUIConfig(
            fsmon_buffer_interval=0.42,
            fsmon_max_lines=1234,
            fsmon_event_visibility={"noise": "never"},
        )

        assert config.monitor_buffer_interval == 0.42
        assert config.monitor_max_lines == 1234
        assert config.monitor_event_visibility == {"noise": "never"}

    def test_new_key_wins_when_both_present(self):
        config = TUIConfig(
            fsmon_max_lines=1234,
            monitor_max_lines=777,
        )

        assert config.monitor_max_lines == 777
