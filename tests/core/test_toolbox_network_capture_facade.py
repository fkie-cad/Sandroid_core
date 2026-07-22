"""Unit tests for Toolbox's network-capture read-side facade.

Regression coverage for ``Toolbox.is_capturing_network()``, which was
previously missing entirely -- ``hook_config_ui.py`` called it expecting a
``StateManagementProtocol``-style method that no real class implemented,
crashing uncaught (only ``except ImportError`` guarded the call site, which
doesn't catch ``AttributeError``).
"""

from __future__ import annotations

from sandroid import services as svc_module
from sandroid.core.toolbox import Toolbox


class _FakeNetworkCaptureService:
    def __init__(self, capturing: bool):
        self._capturing = capturing

    def is_capturing(self) -> bool:
        return self._capturing


def test_is_capturing_network_delegates_true(monkeypatch):
    monkeypatch.setattr(
        svc_module,
        "get_network_capture_service",
        lambda: _FakeNetworkCaptureService(True),
    )

    assert Toolbox.is_capturing_network() is True


def test_is_capturing_network_delegates_false(monkeypatch):
    monkeypatch.setattr(
        svc_module,
        "get_network_capture_service",
        lambda: _FakeNetworkCaptureService(False),
    )

    assert Toolbox.is_capturing_network() is False
