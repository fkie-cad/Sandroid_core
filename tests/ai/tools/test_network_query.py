"""Unit tests for sandroid.ai.tools.network_query.

``Adb`` is imported at module level, so its classmethods are monkeypatched
directly on ``sandroid.core.adb.Adb`` (matching
``tests/ai/tools/test_device_query.py``).
"""

from sandroid.ai.tools import network_query
from sandroid.core.adb import Adb

# -- list_connections ---------------------------------------------------------------


def test_list_connections_passes_through_and_counts(monkeypatch):
    connections = [
        {
            "protocol": "tcp",
            "local_address": "127.0.0.1",
            "local_port": 5555,
            "remote_address": "10.0.2.2",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "uid": 10123,
            "package_name": "com.example.app",
        }
    ]
    monkeypatch.setattr(Adb, "list_connections", staticmethod(lambda: connections))

    assert network_query.list_connections() == {
        "connections": connections,
        "count": 1,
    }


def test_list_connections_empty(monkeypatch):
    monkeypatch.setattr(Adb, "list_connections", staticmethod(list))

    assert network_query.list_connections() == {"connections": [], "count": 0}


# -- get_network_info ----------------------------------------------------------------


def test_get_network_info_converts_tuples_to_dicts(monkeypatch):
    monkeypatch.setattr(
        Adb,
        "get_network_info",
        staticmethod(lambda: [("wlan0", "192.168.1.100"), ("lo", "127.0.0.1")]),
    )

    assert network_query.get_network_info() == {
        "interfaces": [
            {"interface": "wlan0", "ip": "192.168.1.100"},
            {"interface": "lo", "ip": "127.0.0.1"},
        ],
        "count": 2,
    }


def test_get_network_info_empty(monkeypatch):
    monkeypatch.setattr(Adb, "get_network_info", staticmethod(list))

    assert network_query.get_network_info() == {"interfaces": [], "count": 0}
