"""R3: a cancel made two log lines in the TUI (its own + the result line)."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from sandroid.commands import CommandResult
from sandroid.core import actionq_commands as aq


@pytest.mark.parametrize(("app", "level"), [(object(), "DEBUG"), (None, "INFO")])
def test_a_cancel_logs_one_line(monkeypatch, caplog, app, level):
    result = CommandResult(
        success=False, message="Screen recording cancelled", error="cancelled"
    )
    registry = SimpleNamespace(has=lambda c: True, execute_sync=lambda c, ctx: result)
    monkeypatch.setattr(aq, "get_command_registry", lambda: registry)
    monkeypatch.setattr(
        "sandroid.commands.context_factory.create_context_from_actionq",
        lambda q, app=None: None,
    )
    with caplog.at_level(logging.DEBUG, logger=aq.logger.name):
        assert aq.execute_command_from_actionq(None, "g", app=app) is result
    (record,) = [r for r in caplog.records if "cancelled" in r.getMessage()]
    assert record.levelname == level
