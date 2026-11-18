"""BypassService is the only source of detection bypasses.

Covers the consolidation: TrigDroid's bypass wrapper is gone (no module,
import or key left).
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "sandroid"

# -- TrigDroid bypass wrapper removed ------------------------------------------

_REMOVED_MODULES = (
    "sandroid.analysis.trigdroid_bypass",
    "sandroid.tui.controllers.trigdroid_controller",
    "sandroid.tui.modals.trigdroid_modal",
)

_REMOVED_NAMES = re.compile(
    r"trigdroid_bypass|TrigDroidBypass|trigdroid_controller|TrigDroidController"
    r"|trigdroid_modal|TrigDroidModal|_find_bypass_script|action_trigdroid"
    r"|trigdroid_bypass_config"
)


@pytest.mark.parametrize("module", _REMOVED_MODULES)
def test_removed_bypass_modules_are_gone(module: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


def test_no_source_file_references_the_removed_wrapper() -> None:
    offenders = [
        f"{path.relative_to(_SRC)}:{n}"
        for path in _SRC.rglob("*.py")
        for n, line in enumerate(path.read_text("utf-8").splitlines(), 1)
        if _REMOVED_NAMES.search(line)
    ]
    assert not offenders, offenders


def test_trigger_execution_survives() -> None:
    """TrigDroid's real purpose (trigger runs) stays importable."""
    from sandroid.features.trigdroid import Trigdroid
    from sandroid.services import get_trigdroid_config_service

    assert callable(Trigdroid.perform)
    state = get_trigdroid_config_service().get_state_dict()
    assert state == {"spawn_mode": True, "auto_resume": True}
