"""Unit tests for ForensicController's inline-scan + IOC-config routing.

These cover the non-modal scan path used by the Forensic tab and the shared
IOC modal routing, with fakes for the scan engine / worker / modals so the
tests need neither a connected device nor the Textual runtime.
"""

from __future__ import annotations

from types import SimpleNamespace

from sandroid.tui.controllers.forensic_controller import ForensicController


class _FakeToolbox:
    """Minimal Toolbox stand-in for can_run_forensic_scan()."""

    def __init__(self, *, emulator: bool) -> None:
        self._emulator = emulator

    def is_emulator_device(self) -> bool:
        return self._emulator


def _sync_run_worker(work, **_kwargs) -> None:
    """run_worker fake: execute the work body synchronously."""
    work()


def _sync_call_from_thread(fn, *args) -> None:
    """call_from_thread fake: invoke directly (already 'on the main thread')."""
    fn(*args)


class _FakeEvidence:
    """ForensicEvidence stand-in with scriptable load + run results."""

    _STAGE_FLAGS = ("scan_apps", "scan_sms", "scan_calls", "scan_files")
    _STAGE_NAMES = {
        "scan_apps": "APPS",
        "scan_sms": "SMS",
        "scan_calls": "CALLS",
        "scan_files": "FILES",
    }

    def __init__(
        self,
        *,
        load_ok: bool,
        indicators: int = 7,
        cancel_on: str | None = None,
        controller=None,
    ) -> None:
        self._load_ok = load_ok
        self.total_indicators = indicators
        self._configured = True
        self.stages_run: list[str] = []
        self._cancel_on = cancel_on  # stage NAME that requests cancellation
        self._controller = controller

    def load_iocs(self) -> bool:
        return self._load_ok

    def is_configured(self) -> bool:
        return self._configured

    def run_scan(self, progress_callback=None, **flags):
        # The inline runner enables exactly one stage per call.
        stage = next(
            (self._STAGE_NAMES[f] for f in self._STAGE_FLAGS if flags.get(f)), None
        )
        self.stages_run.append(stage)
        if self._cancel_on == stage and self._controller is not None:
            self._controller.cancel_scan()
        if progress_callback:
            # The controller wraps this; it raises _ScanAborted when cancelled.
            progress_callback(SimpleNamespace(scan_type=stage, current=1, total=1))
        return [SimpleNamespace(matches=[], scan_type=SimpleNamespace(name=stage))]


def _patch_evidence(monkeypatch, fake: _FakeEvidence) -> None:
    import sandroid.core.forensic_evidence as fe_mod

    monkeypatch.setattr(fe_mod.ForensicEvidence, "get", classmethod(lambda cls: fake))


def test_run_inline_happy_path_runs_all_stages(monkeypatch):
    fake = _FakeEvidence(load_ok=True)
    _patch_evidence(monkeypatch, fake)

    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    seen = {"progress": [], "complete": None, "error": None}

    started = controller.run_forensic_scan_inline(
        run_worker=_sync_run_worker,
        call_from_thread=_sync_call_from_thread,
        on_progress=seen["progress"].append,
        on_complete=lambda r, cancelled: seen.update(complete=(r, cancelled)),
        on_error=lambda m: seen.update(error=m),
    )

    assert started is True
    assert seen["error"] is None
    # All four stages run, in order, each contributing one result.
    assert fake.stages_run == ["APPS", "SMS", "CALLS", "FILES"]
    completed_results, cancelled = seen["complete"]
    assert len(completed_results) == 4
    assert cancelled is False
    assert len(seen["progress"]) == 4
    assert controller.is_scan_in_progress() is False  # cleared in finally


def test_run_inline_load_failure_calls_on_error(monkeypatch):
    _patch_evidence(monkeypatch, _FakeEvidence(load_ok=False))
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    seen = {"complete": None, "error": None}

    started = controller.run_forensic_scan_inline(
        run_worker=_sync_run_worker,
        call_from_thread=_sync_call_from_thread,
        on_progress=lambda p: None,
        on_complete=lambda r, c: seen.update(complete=(r, c)),
        on_error=lambda m: seen.update(error=m),
    )

    assert started is False
    assert seen["complete"] is None
    assert "IOC" in seen["error"]
    assert controller.is_scan_in_progress() is False


def test_run_inline_blocked_on_emulator(monkeypatch):
    _patch_evidence(monkeypatch, _FakeEvidence(load_ok=True))
    controller = ForensicController(toolbox=_FakeToolbox(emulator=True))
    seen = {"error": None}

    started = controller.run_forensic_scan_inline(
        run_worker=_sync_run_worker,
        call_from_thread=_sync_call_from_thread,
        on_progress=lambda p: None,
        on_complete=lambda r, c: None,
        on_error=lambda m: seen.update(error=m),
    )

    assert started is False
    assert seen["error"] is not None  # the emulator-disabled reason


def test_run_inline_abort_on_first_stage_stops_immediately(monkeypatch):
    # Cancelling on APPS must abort before any later stage runs, with no results.
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    fake = _FakeEvidence(load_ok=True, cancel_on="APPS", controller=controller)
    _patch_evidence(monkeypatch, fake)

    seen = {"complete": None}
    controller.run_forensic_scan_inline(
        run_worker=_sync_run_worker,
        call_from_thread=_sync_call_from_thread,
        on_progress=lambda p: None,
        on_complete=lambda r, c: seen.update(complete=(r, c)),
        on_error=lambda m: None,
    )

    results, cancelled = seen["complete"]
    assert cancelled is True
    assert results == []  # aborted before APPS produced a result
    assert fake.stages_run == ["APPS"]  # SMS/CALLS/FILES never started
    assert controller.is_scan_in_progress() is False


def test_run_inline_abort_preserves_completed_stage_results(monkeypatch):
    # Cancelling during the last (FILES) stage keeps APPS/SMS/CALLS results.
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    fake = _FakeEvidence(load_ok=True, cancel_on="FILES", controller=controller)
    _patch_evidence(monkeypatch, fake)

    seen = {"complete": None}
    controller.run_forensic_scan_inline(
        run_worker=_sync_run_worker,
        call_from_thread=_sync_call_from_thread,
        on_progress=lambda p: None,
        on_complete=lambda r, c: seen.update(complete=(r, c)),
        on_error=lambda m: None,
    )

    results, cancelled = seen["complete"]
    assert cancelled is True
    assert len(results) == 3  # APPS, SMS, CALLS survived the abort
    assert fake.stages_run == ["APPS", "SMS", "CALLS", "FILES"]


def test_cancel_scan_no_op_when_idle():
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    assert controller.cancel_scan() is False


def _install_fake_modals(monkeypatch):
    """Replace the IOC modal classes with cheap stand-ins (no Textual)."""
    from sandroid.tui import modals

    class _Stub:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(modals, "IOCChoiceModal", _Stub, raising=False)
    monkeypatch.setattr(modals, "IOCSetupModal", _Stub, raising=False)
    return _Stub


def test_configure_only_no_cache_routes_to_setup(monkeypatch):
    _install_fake_modals(monkeypatch)
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    monkeypatch.setattr(controller, "has_cached_iocs", lambda: None)
    monkeypatch.setattr(controller, "_save_ioc_config_from_setup", lambda r: None)
    monkeypatch.setattr(controller, "reset_forensic_evidence", lambda: None)

    pushed = {}
    done = {"called": False}

    def push_modal(modal, cb):
        pushed["modal"] = modal
        # Simulate the user saving a new source.
        cb(SimpleNamespace(cancelled=False))

    controller.configure_iocs_only(
        push_modal=push_modal, on_done=lambda: done.update(called=True)
    )

    assert "modal" in pushed  # the setup modal was shown
    assert done["called"] is True


def test_configure_only_cancel_does_not_call_done(monkeypatch):
    _install_fake_modals(monkeypatch)
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    monkeypatch.setattr(controller, "has_cached_iocs", lambda: None)

    done = {"called": False}
    controller.configure_iocs_only(
        push_modal=lambda modal, cb: cb(SimpleNamespace(cancelled=True)),
        on_done=lambda: done.update(called=True),
    )
    assert done["called"] is False


def test_configure_only_cached_use_cached_calls_done(monkeypatch):
    _install_fake_modals(monkeypatch)
    _patch_evidence(monkeypatch, _FakeEvidence(load_ok=True))
    controller = ForensicController(toolbox=_FakeToolbox(emulator=False))
    monkeypatch.setattr(
        controller,
        "has_cached_iocs",
        lambda: {"path": "/x", "file_count": 1, "indicator_count": 10},
    )

    done = {"called": False}

    def push_modal(modal, cb):
        # Simulate "Use cached IOCs" with no remember.
        cb(SimpleNamespace(cancelled=False, use_cached=True, remember_choice=False))

    controller.configure_iocs_only(
        push_modal=push_modal, on_done=lambda: done.update(called=True)
    )
    assert done["called"] is True
