"""Unit tests for config/schema.py's TUIConfig -- the monitor_event_visibility
field/validator (per-category Monitor visibility, configurable in Settings)
added alongside monitor_max_lines, the monitor_backend validator, and the
legacy ``fsmon_*`` -> ``monitor_*`` back-fill.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandroid.config.schema import TUIConfig


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
        assert TUIConfig().monitor_backend == "auto"

    def test_invalid_backend_raises_validation_error(self):
        with pytest.raises(ValidationError):
            TUIConfig(monitor_backend="bogus")

    @pytest.mark.parametrize("backend", ["auto", "fsmon", "kprobe"])
    def test_valid_backends_round_trip(self, backend):
        assert TUIConfig(monitor_backend=backend).monitor_backend == backend


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
