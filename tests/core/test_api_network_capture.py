"""Headless API network capture: device-side detach, PID-based stop.

A fake adb (``fakeadb`` in ``tmp_path``) runs ``adb shell <cmd>`` through a
local ``sh -c`` -- standing in for the device shell -- with a fake
``tcpdump`` on its PATH, and implements ``adb pull`` as ``cp``. The real
``Adb.send_adb_command`` (host shell, 30 s timeout) is used unchanged.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import stat
import subprocess
import time

import pytest

from sandroid.api.handlers.monitoring_handler import MonitoringHandler
from sandroid.core.adb import Adb

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX shells only")


def _script(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.fixture
def device(tmp_path, monkeypatch):
    bin_dir = tmp_path / "devbin"
    bin_dir.mkdir()
    _script(
        bin_dir / "tcpdump",
        "#!/bin/sh\n"
        'out=""\n'
        'while [ $# -gt 0 ]; do [ "$1" = "-w" ] && out="$2"; shift; done\n'
        "trap 'echo FLUSHED >> \"$out\"; exit 0' TERM\n"
        'echo PCAP > "$out"\n'
        "while :; do sleep 0.1; done\n",
    )
    other = subprocess.Popen(  # an unrelated tcpdump that must survive
        [str(bin_dir / "tcpdump"), "-w", str(tmp_path / "other.pcap")],
        start_new_session=True,
    )
    fakeadb = _script(
        tmp_path / "fakeadb",
        "#!/bin/sh\n"
        f"export PATH={shlex.quote(str(bin_dir))}:$PATH\n"
        'cmd="$1"; shift\n'
        'case "$cmd" in\n'
        '  shell) exec sh -c "$*" ;;\n'
        '  pull) cp "$1" "$2" ;;\n'
        "esac\n",
    )
    monkeypatch.setattr(Adb, "ADB_PATH", str(fakeadb))
    monkeypatch.setattr(Adb, "_target_device", None)
    monkeypatch.setattr(
        MonitoringHandler, "_DEVICE_PCAP", str(tmp_path / "device capture.pcap")
    )

    from sandroid import services

    class _Tasks:
        @staticmethod
        def is_running(name):
            return False

    monkeypatch.setattr(services, "get_task_service", lambda: _Tasks())
    api = type("Api", (), {"_adb": Adb})()
    yield MonitoringHandler(api), other
    other.kill()
    other.wait(timeout=5)


def test_start_detaches_on_device_and_stop_kills_only_that_pid(device, tmp_path):
    handler, other = device
    out_file = tmp_path / "results" / "mine.pcap"

    started = time.monotonic()
    result = asyncio.run(handler.start_network_capture(str(out_file)))
    assert result.success, result
    # Returned promptly (the old host-side `&` blocked for the 30 s timeout).
    assert time.monotonic() - started < 10
    pid = result.data["pid"]
    os.kill(pid, 0)  # the capture really runs, detached

    again = asyncio.run(handler.start_network_capture(str(out_file)))
    assert not again.success

    stopped = asyncio.run(handler.stop_network_capture())
    assert stopped.success, stopped
    assert stopped.data["pcap_path"] == str(out_file)  # output_file honoured
    assert out_file.read_text().splitlines() == ["PCAP", "FLUSHED"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert other.poll() is None  # no blanket pkill
    assert not (tmp_path / "device capture.pcap").exists()


def test_stop_without_start_does_not_kill_anything(device):
    handler, other = device
    result = asyncio.run(handler.stop_network_capture())
    assert not result.success
    assert other.poll() is None
