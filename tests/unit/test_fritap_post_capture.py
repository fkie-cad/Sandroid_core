"""Unit tests for the friTap panel's post-capture flow.

Covers: the Capture Results modal, the gated "Decrypt captured traffic?" offer,
and the decrypt-to-tap worker that opens ``fritap -r`` in a new terminal. Uses a
bare ``FriTapPanel`` + a fake app (no Textual runtime, no device).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import sandroid.tui.widgets.fritap_panel as fp_mod
from sandroid.tui.modals import ConfirmModal, MessageModal
from sandroid.tui.widgets.fritap_panel import FriTapPanel


class _FakeApp:
    def __init__(self):
        self.screens = []  # (modal, callback)
        self.notes = []
        self.deferred = []  # (fn, args) recorded by call_later

    def push_screen(self, modal, callback=None):
        self.screens.append((modal, callback))

    def notify(self, message, severity="information"):
        self.notes.append((message, severity))

    def call_from_thread(self, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def call_later(self, fn, *args, **kwargs):
        # Record the deferral, then run it synchronously so the modal-creation
        # path is still exercised (mirrors Textual running it in app context).
        self.deferred.append((fn, args))
        return fn(*args, **kwargs)


def _panel_with_app(monkeypatch) -> tuple[FriTapPanel, _FakeApp]:
    panel = FriTapPanel()
    app = _FakeApp()
    monkeypatch.setattr(type(panel), "app", property(lambda _self: app))
    return panel, app


def _full_capture_instance(tmp_path):
    pcap = tmp_path / "capture.pcapng"
    pcap.write_text("x")
    return SimpleNamespace(
        app_package="com.example.app",
        result_paths={"Key log (tls)": "/r/keys.tls.log", "PCAP": str(pcap)},
        result_stats={"PCAP": "160.4 KB", "Key log (tls)": "3 keys"},
        result_keylogs={"tls": "/r/keys.tls.log", "signal": "/r/keys.signal.log"},
        full_capture_done=True,
        pcap_has_packets=True,
    )


def test_show_capture_results_pushes_message_modal(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)
    inst = _full_capture_instance(tmp_path)

    panel._show_capture_results(inst, inst.result_paths)

    assert len(app.screens) == 1
    modal, callback = app.screens[0]
    assert isinstance(modal, MessageModal)
    assert "Capture Results" == modal.title_text
    assert "com.example.app" in modal.message_text
    assert callback is not None  # chains into the decrypt offer


def test_on_stopped_defers_results_into_app_context(monkeypatch, tmp_path):
    # _on_fritap_stopped runs from an EventBus loop callback with no active_app
    # ContextVar set, so it must route the modal creation through app.call_later
    # (which Textual runs in app context) rather than building the modal inline.
    # Otherwise MessageModal.compose() raises NoActiveAppError.
    panel, app = _panel_with_app(monkeypatch)
    inst = _full_capture_instance(tmp_path)
    panel._results_instance = inst

    panel._on_fritap_stopped()

    assert len(app.deferred) == 1
    fn, args = app.deferred[0]
    assert fn == panel._show_capture_results
    assert args == (inst, inst.result_paths)
    # ...and the deferred call actually produced the Capture Results modal.
    assert isinstance(app.screens[0][0], MessageModal)


def test_decrypt_offered_for_full_capture(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)
    inst = _full_capture_instance(tmp_path)

    panel._maybe_offer_decrypt(inst)

    assert len(app.screens) == 1
    modal, _ = app.screens[0]
    assert isinstance(modal, ConfirmModal)
    assert modal.title_text == "Decrypt captured traffic?"


def test_decrypt_not_offered_when_pcap_empty(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)
    inst = _full_capture_instance(tmp_path)
    inst.pcap_has_packets = False

    panel._maybe_offer_decrypt(inst)
    assert app.screens == []


def test_decrypt_not_offered_when_not_full_capture(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)
    inst = _full_capture_instance(tmp_path)
    inst.full_capture_done = False

    panel._maybe_offer_decrypt(inst)
    assert app.screens == []


def test_on_fritap_stopped_no_instance_is_noop(monkeypatch):
    panel, app = _panel_with_app(monkeypatch)
    panel._results_instance = None
    panel._on_fritap_stopped()
    assert app.screens == []


def test_start_decrypt_runs_converter_and_launches_replay(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)

    # Run the worker thunk synchronously.
    monkeypatch.setattr(panel, "run_worker", lambda fn, **kw: fn())

    captured = {}

    def _fake_convert(pcap, **kwargs):
        captured["pcap"] = pcap
        captured["kwargs"] = kwargs
        return SimpleNamespace(flow_count=6)

    import friTap.offline.pcap_to_tap as conv_mod

    monkeypatch.setattr(conv_mod, "convert_pcap_to_tap", _fake_convert)

    # Don't actually open a terminal; just record the replay target.
    launched = []
    monkeypatch.setattr(panel, "_launch_fritap_replay", launched.append)

    # Avoid touching the real Toolbox registry.
    import sandroid.core.toolbox as tb_mod

    monkeypatch.setattr(tb_mod.Toolbox, "mark_tool_used", classmethod(lambda cls, *a, **k: None))

    pcap = str(tmp_path / "capture.pcapng")
    keylogs = {"tls": "/r/keys.tls.log", "signal": "/r/keys.signal.log"}
    panel._start_decrypt_to_tap(pcap, keylogs)

    # Converter called with the right pcap + split keylogs.
    assert captured["pcap"] == pcap
    assert captured["kwargs"]["keylog_path"] == "/r/keys.tls.log"
    assert captured["kwargs"]["signal_keylog"] == "/r/keys.signal.log"

    # Replay opened on the produced .tap (same stem, .tap extension).
    assert launched == [Path(tmp_path / "capture.tap")]


def test_start_decrypt_surfaces_converter_error(monkeypatch, tmp_path):
    panel, app = _panel_with_app(monkeypatch)
    monkeypatch.setattr(panel, "run_worker", lambda fn, **kw: fn())

    import friTap.offline.pcap_to_tap as conv_mod

    def _boom(*a, **k):
        raise RuntimeError("tshark not found")

    monkeypatch.setattr(conv_mod, "convert_pcap_to_tap", _boom)

    launched = []
    monkeypatch.setattr(panel, "_launch_fritap_replay", launched.append)

    panel._start_decrypt_to_tap(str(tmp_path / "c.pcapng"), {"tls": "/r/k.log"})

    assert launched == []  # no replay on failure
    assert any(sev == "error" for _, sev in app.notes)
