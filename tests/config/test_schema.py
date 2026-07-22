"""Unit tests for config/schema.py's TUIConfig -- specifically the new
fsmon_event_visibility field/validator (per-category Monitor visibility,
configurable in Settings) added alongside fsmon_max_lines.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandroid.config.schema import TUIConfig


class TestFsmonEventVisibility:
    def test_default_value(self):
        config = TUIConfig()

        assert config.fsmon_event_visibility == {
            "create": "always",
            "modify": "always",
            "delete": "always",
            "rename": "always",
            "attrs": "always",
            "noise": "verbose",
        }

    def test_invalid_mode_raises_validation_error(self):
        with pytest.raises(ValidationError):
            TUIConfig(fsmon_event_visibility={"create": "bogus"})

    def test_valid_partial_override_round_trips(self):
        config = TUIConfig(fsmon_event_visibility={"noise": "never"})

        assert config.fsmon_event_visibility == {"noise": "never"}
