"""App lens sections (identity ... suspected defences) on a fake data layer.

No device: ``app_lens.make_service`` is replaced by :class:`FakeService`
built from the real result dataclasses of ``app_info_service``; the
spotlight package comes from a patched ``SpotlightPanel._current_package``.
"""

from __future__ import annotations

import threading
import time

import pytest

from sandroid.services.app_info_service import (
    AppOpEntry,
    AppOpsState,
    DataFootprint,
    Fact,
    PermissionGrant,
    PermissionState,
    RunningService,
    ServicesState,
    StaticOverview,
    suspect_defences,
)
from sandroid.tui.widgets import app_lens
from sandroid.tui.widgets.app_lens import (
    ANALYSIS_HINT,
    AppFacts,
    AppLensSections,
    LensSection,
    build_defences,
    build_permissions,
    build_trackers,
    route_text,
)
from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

PKG = "com.example.app"
OTHER = "org.other.app"

OVERVIEW = {
    "schema": 2,
    "package": PKG,
    "version_name": "4.2.0",
    "version_code": 420,
    "min_sdk": 24,
    "target_sdk": 34,
    "debuggable": False,
    "allow_backup": True,
    "components": {
        "activities": [
            {
                "name": f"{PKG}.MainActivity",
                "exported": True,
                "permission": None,
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.VIEW"],
                        "categories": ["android.intent.category.BROWSABLE"],
                        "data": [{"scheme": "exapp", "host": "open"}],
                    }
                ],
            },
            {"name": f"{PKG}.Hidden", "exported": False, "permission": None},
        ],
        "services": [
            {
                "name": f"{PKG}.SyncService",
                "exported": True,
                "permission": "android.permission.BIND_JOB_SERVICE",
                "intent_filters": [],
            }
        ],
        "receivers": [],
        "providers": [
            {
                "name": f"{PKG}.Files",
                "exported": True,
                "read_permission": None,
                "write_permission": None,
                "authorities": [f"{PKG}.files"],
            }
        ],
    },
    "deep_links": [
        {
            "component": f"{PKG}.MainActivity",
            "exported": True,
            "scheme": "exapp",
            "host": "open",
        }
    ],
    "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
    "permission_protection": {"android.permission.CAMERA": "dangerous"},
    "nsc": {
        "present": True,
        "cleartext_effective": False,
        "cleartext_source": "NSC base-config",
        "cleartext_domains": [],
        "pin_sets": [{"domains": ["api.example.com"], "pins": 2, "expiration": None}],
        "trust_user_ca": False,
        "trust_user_ca_domains": ["debug.example.com"],
        "trust_user_ca_source": None,
    },
    "native_libs": ["libssl.so", "libcrypto.so", "libapp.so"],
    "signer": {
        "schemes": ["v2", "v3"],
        "certificates": [{"sha256": "ab" * 32, "subject": "CN=Example"}],
    },
}
META = {
    "splits": [
        {"name": "base.apk", "sha256": "1" * 64, "size": 12 * 1024 * 1024},
        {"name": "split_config.arm64_v8a.apk", "size": 2048, "config": True},
    ]
}
INSIGHT = {
    "library_detection": {
        "detected_libraries": [
            {"name": "Firebase Analytics", "category": "analytics", "version": "21"},
            {"name": "OkHttp", "category": "network", "version": "4.12"},
            {"name": "RootBeer", "package_name": "com.scottyab.rootbeer"},
        ]
    },
    "apk_overview": {"native_libs": [], "cross_platform_framework": None},
}


def _grants() -> PermissionState:
    return PermissionState(
        package=PKG,
        permissions=[
            PermissionGrant(
                "android.permission.CAMERA",
                requested=True,
                kind="runtime",
                granted=True,
                flags=["USER_SET"],
                protection="dangerous",
            ),
            PermissionGrant(
                "android.permission.ACCESS_FINE_LOCATION",
                requested=True,
                kind="runtime",
                granted=True,
                protection="dangerous",
            ),
            PermissionGrant(
                "android.permission.READ_CONTACTS",
                requested=True,
                kind="runtime",
                granted=False,
                protection="dangerous",
            ),
            PermissionGrant(
                "android.permission.INTERNET",
                requested=True,
                kind="install",
                granted=True,
                protection="normal",
            ),
        ],
    )


def _appops() -> AppOpsState:
    return AppOpsState(
        package=PKG,
        ops=[
            AppOpEntry(
                "CAMERA",
                mode="allow",
                permission="android.permission.CAMERA",
                last_access="+5m",
                last_access_ago_s=300,
            ),
            AppOpEntry(
                "FINE_LOCATION",
                mode="foreground",
                permission="android.permission.ACCESS_FINE_LOCATION",
            ),
            AppOpEntry(
                "READ_CLIPBOARD",
                mode="allow",
                last_access="+10s",
                last_access_ago_s=10,
            ),
        ],
    )


class FakeService:
    """``AppInfoService`` stand-in. Records (method, package, thread name)."""

    calls: list[tuple[str, str, str]] = []
    cached: set[str] = {PKG}
    unhashable: set[str] = set()
    no_insight: set[str] = set()
    fail: set[tuple[str, str]] = set()
    footprint_dirs: list[str | None] = []
    extra_ops: list[AppOpEntry] = []
    gates: dict[tuple[str, str], threading.Event] = {}
    version: dict[str, str] = {PKG: "4.2.0", OTHER: "9.9"}

    def __init__(self, serial):
        self.serial = serial

    def _note(self, method: str, package: str) -> None:
        FakeService.calls.append((method, package, threading.current_thread().name))
        gate = FakeService.gates.get((method, package))
        if gate is not None:
            gate.wait(5)
        if (method, package) in FakeService.fail:
            raise RuntimeError(f"{method} failed")

    def details(self, package):
        self._note("details", package)
        return Fact(
            value={
                "package_name": package,
                "version_name": FakeService.version.get(package, "1"),
                "version_code": 420,
                "target_sdk": 34,
                "min_sdk": 24,
                "uid": 10123,
                "install_source": None,
                "install_date": "2026-11-01 10:00:00",
                "last_update": "2026-11-17 09:00:00",
                "data_dir": f"/data/user/0/{package}",
            }
        )

    def static_overview(self, package, *, allow_pull=True):
        self._note("static_pull" if allow_pull else "static_cache", package)
        if package in FakeService.unhashable:
            return StaticOverview(
                package=package, ok=False, reason="could not hash APK on device"
            )
        if package in FakeService.cached or allow_pull:
            FakeService.cached.add(package)
            return StaticOverview(
                package=package,
                key="k" * 64,
                overview=dict(OVERVIEW, package=package),
                meta=META,
                insight=(
                    INSIGHT
                    if package == PKG and package not in FakeService.no_insight
                    else None
                ),
                from_cache=not allow_pull,
            )
        return StaticOverview(package=package, ok=False, reason="not cached yet")

    @staticmethod
    def defences(static):
        return suspect_defences(static.overview, static.insight)

    def permissions(self, package, overview=None):
        self._note("permissions", package)
        return _grants()

    def appops(self, package):
        self._note("appops", package)
        state = _appops()
        state.ops.extend(FakeService.extra_ops)
        return state

    def services(self, package):
        self._note("services", package)
        return ServicesState(
            package=package,
            services=[
                RunningService(
                    f"{package}/.Loc", foreground=True, types=["location"], pid=4242
                )
            ],
        )

    def footprint(self, package, data_dir=None):
        FakeService.footprint_dirs.append(data_dir)
        self._note("footprint", package)
        return DataFootprint(
            package=package,
            private_dir=f"/data/data/{package}",
            private_kb=2048,
            external_dir=f"/sdcard/Android/data/{package}",
            external_kb=None,
            external_reason="no external dir",
            shared_prefs_count=3,
            databases_count=2,
            root_method="adb root",
        )


@pytest.fixture
def fake(monkeypatch):
    FakeService.calls = []
    FakeService.cached = {PKG}
    FakeService.unhashable = set()
    FakeService.no_insight = set()
    FakeService.fail = set()
    FakeService.footprint_dirs = []
    FakeService.extra_ops = []
    FakeService.gates = {}
    state = {"pkg": PKG}
    monkeypatch.setattr(app_lens, "make_service", FakeService)
    monkeypatch.setattr(SpotlightPanel, "_current_package", lambda self: state["pkg"])
    monkeypatch.setattr(SpotlightPanel, "_safe_pid", lambda self: 4242)
    monkeypatch.setattr(SpotlightPanel, "_poll_running_state", lambda self: None)
    yield state
    for gate in FakeService.gates.values():
        gate.set()


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def _wait(pilot, cond, timeout: float = 5.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        await pilot.pause(0.05)
    assert cond()


async def _boot(app, pilot):
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")
        await _settle(pilot, 4)
    assert type(app.screen).__name__ == "MainScreen"
    return app.screen


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _sections(ms) -> AppLensSections:
    return ms.query_one("#app-sections", AppLensSections)


def _loaded(sections: AppLensSections) -> bool:
    f = sections.facts
    return bool(
        f is not None
        and f.footprint is not None
        and f.appops is not None
        and f.static_state == "ready"
    )


def _texts(section: LensSection) -> list[str]:
    return [r.text for r in section.rows_shown]


def _screen_text(app) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(seg.text for seg in strip) for strip in strips)


# --------------------------------------------------------------------------
# pure builders
# --------------------------------------------------------------------------


def test_permission_rows_join_appops_and_list_op_only_rows() -> None:
    f = AppFacts(package=PKG, permissions=_grants(), appops=_appops())
    data = build_permissions(f)
    keys = [r.key for r in data.rows]
    # dangerous first; the clipboard op has no permission and gets its own row
    assert keys[0].startswith("perm:android.permission.")
    assert "op:READ_CLIPBOARD" in keys
    by_key = {r.key: r.text for r in data.rows}
    assert "while-in-use" in by_key["perm:android.permission.ACCESS_FINE_LOCATION"]
    assert "used recently" in by_key["perm:android.permission.CAMERA"]
    assert "req → ✗" in by_key["perm:android.permission.READ_CONTACTS"]
    assert data.summary == (
        "4 requested · 3 dangerous (2 granted) · 2 used recently · " "1 no recorded use"
    )


def test_trackers_hint_without_insight_and_defences_are_static() -> None:
    static = StaticOverview(package=PKG, overview=OVERVIEW, from_cache=True)
    f = AppFacts(package=PKG, static=static, static_state="ready")
    f.defences = suspect_defences(OVERVIEW, None)
    trackers = build_trackers(f)
    assert trackers.rows[0].text == ANALYSIS_HINT
    assert not trackers.rows[0].inspectable
    defences = build_defences(f)
    titles = " ".join(r.text for r in defences.rows)
    assert "pin" in titles.lower()
    # TLS stacks are listed under MANIFEST & NETWORK, not as a defence row
    assert "OpenSSL" not in titles
    assert "a = deeper" in defences.summary


def test_trackers_render_insight_tracker_rows() -> None:
    static = StaticOverview(package=PKG, overview=OVERVIEW, from_cache=True)
    static.set_insight(
        {
            **INSIGHT,
            "tracker_analysis": {
                "detected_trackers": [
                    {
                        "name": "Google AdMob",
                        "category": "Advertisement",
                        "version": "22.1",
                        "network_signature": "googleads.g.doubleclick.net",
                        "locations": ["/Users/someone/tmp/x"],
                    }
                ]
            },
        }
    )
    assert static.trackers[0]["name"] == "Google AdMob"
    assert "locations" not in static.trackers[0]
    f = AppFacts(package=PKG, static=static, static_state="ready")
    section = build_trackers(f)
    texts = [r.text for r in section.rows]
    assert "Google AdMob" in texts[0]
    assert "googleads.g" in texts[0]
    assert any("Firebase Analytics" in t for t in texts)
    assert section.summary.startswith("1 tracker · 3 SDKs")


def test_revoked_grant_and_de_storage_are_shown() -> None:
    grants = PermissionState(
        package=PKG,
        permissions=[
            PermissionGrant(
                "android.permission.RECORD_AUDIO",
                requested=True,
                kind="runtime",
                granted=True,
                flags=["REVOKED_COMPAT"],
                protection="dangerous",
                revoked=True,
                revoked_reason="REVOKED_COMPAT (legacy app: AppOps denies it)",
            ),
            PermissionGrant(
                "android.permission.CAMERA",
                requested=True,
                kind="runtime",
                granted=True,
                protection="dangerous",
            ),
        ],
    )
    ops = AppOpsState(
        package=PKG,
        ops=[
            AppOpEntry(
                "CAMERA",
                mode="ignore",
                uid_mode="ignore",
                permission="android.permission.CAMERA",
            )
        ],
    )
    f = AppFacts(package=PKG, permissions=grants, appops=ops)
    section = build_permissions(f)
    texts = {r.key: r.text for r in section.rows}
    assert "revoked" in texts["perm:android.permission.RECORD_AUDIO"]
    assert "revoked" in texts["perm:android.permission.CAMERA"]  # uid ignore
    assert "0 granted" in section.summary
    f.footprint = DataFootprint(
        package=PKG,
        private_dir=f"/data/data/{PKG}",
        private_kb=24,
        de_dir=f"/data/user_de/0/{PKG}",
        de_kb=1048,
        data_dir=f"/data/user_de/0/{PKG}",
    )
    data = {r.key: r.text for r in app_lens.build_data(f).rows}
    assert "1.0 MB" in data["private_de"] or "1048" in data["private_de"]


def test_route_text_names_keys_and_marks_missing_digits() -> None:
    assert route_text(["h", "b1", "v"]) == "h friTap · b1 ssl"
    assert route_text(["b6"]) == "b6 emulator (n/a)"


def test_analysing_state_is_visible_in_static_sections() -> None:
    f = AppFacts(package=PKG, static_state="analysing")
    for builder in (build_defences, app_lens.build_exposure, app_lens.build_manifest):
        assert "analysing manifest" in builder(f).rows[0].text


# --------------------------------------------------------------------------
# mounted lens
# --------------------------------------------------------------------------


@pytest.mark.parametrize("size", [(160, 45), (100, 30)])
async def test_sections_render_inspect_and_space_starts(fake, monkeypatch, size):
    started: list[int] = []
    monkeypatch.setattr(SpotlightPanel, "action_primary", lambda s: started.append(1))
    app = _app()
    async with app.run_test(size=size) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        await _settle(pilot)
        titles = [str(s.border_title) for s in sections.sections()]
        assert [t.split(" · ")[0][2:] for t in titles] == [
            t for _id, t in app_lens.SECTIONS
        ]
        perms = sections.section("permissions")
        assert "4 requested · 3 dangerous (2 granted)" in str(perms.border_title)
        assert any("READ_CLIPBOARD" in t for t in _texts(perms))
        exposure = _texts(sections.section("exposure"))
        assert any(".Files" in t and "no permission" in t for t in exposure)
        assert any("exapp://open" in t for t in exposure)
        manifest = " ".join(_texts(sections.section("manifest")))
        assert "debug.example.com" in manifest
        assert "pin-set" in manifest
        assert "OpenSSL" in manifest
        trackers = _texts(sections.section("trackers"))
        assert any("Firebase Analytics" in t for t in trackers)
        data = " ".join(_texts(sections.section("data")))
        assert "2.0 MB" in data
        assert "3 shared_prefs" in data
        assert "Files lens" in data
        defences = sections.section("defences")
        assert "not observed" in str(defences.border_title)
        assert any("RootBeer" in t and "b2 root" in t for t in _texts(defences))
        # every device call ran off the UI thread
        main = threading.main_thread().name
        assert FakeService.calls
        assert all(name != main for _m, _p, name in FakeService.calls)
        # focus sits in a section; Enter inspects the selected row
        assert isinstance(app.focused, LensSection)
        assert ms.check_action("inspect", ()) is True
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await _settle(pilot)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert content.lens == "app"
        assert [name for name, _s in content.tabs] == ["Evidence", "Raw"]
        assert content.key.startswith("app:identity:")
        # Space = Start/Resume, also from inside a section table
        await pilot.press("space")
        await _settle(pilot)
        assert started == [1]
        # the caption advertises the lens keys
        assert "⏎ inspect" in (ms._lens_captions["app"][1] or "")
        if size == (100, 30):
            # header, the frame and the action row stay on screen
            ms.close_inspector()
            await _settle(pilot)
            text = _screen_text(app)
            assert "␣ Start" in text or "● running" in text
            assert "⇧K kill" in text
            assert "IDENTITY" in text


async def test_permissions_row_inspector_has_grant_and_appops(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        perms.focus()
        await _settle(pilot)
        index = next(
            i for i, r in enumerate(perms.rows_shown) if r.key.endswith("CAMERA")
        )
        perms.move_cursor(row=index)
        await pilot.press("enter")
        await _settle(pilot)
        content = ms.inspector_content
        assert content.key == "app:permissions:perm:android.permission.CAMERA"
        evidence = dict(content.tabs[0][1])
        assert "Manifest" in evidence
        assert "AppOps CAMERA" in evidence
        assert "uses-permission" in str(evidence["Manifest"])


async def test_tab_moves_between_sections_and_z_folds(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        first = sections.section("identity")
        first.focus()
        await _settle(pilot)
        await pilot.press("tab")
        await _settle(pilot)
        assert app.focused is sections.section("permissions")
        await pilot.press("z")
        await _settle(pilot)
        perms = sections.section("permissions")
        assert perms.folded
        assert perms.size.height == 0
        assert str(perms.border_title).startswith("▸ PERMISSIONS")
        # still in the focus order while folded
        await pilot.press("tab")
        await pilot.press("shift+tab")
        await _settle(pilot)
        assert app.focused is perms
        await pilot.press("z")
        await _settle(pilot)
        assert not perms.folded
        assert perms.size.height > 3


async def test_slash_filters_rows_across_sections_and_esc_clears(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        await pilot.press("slash")
        await _settle(pilot)
        assert app.focused.id == "app-filter"
        for ch in "camera":
            await pilot.press(ch)
        await _wait(pilot, lambda: sections.filter_text == "camera")
        perms = _texts(sections.section("permissions"))
        assert len(perms) == 1
        assert "CAMERA" in perms[0]
        assert "no rows match" in _texts(sections.section("exposure"))[0]
        assert "1 of" in str(sections.section("permissions").border_title)
        await pilot.press("escape")
        await _settle(pilot)
        assert sections.filter_text == ""
        assert len(_texts(sections.section("permissions"))) > 1


async def test_u_refreshes_runtime_facts_off_thread(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        before = len(FakeService.calls)
        await pilot.press("u")
        await _wait(
            pilot,
            lambda: {"footprint", "static_cache"}
            <= {m for m, _p, _t in FakeService.calls[before:]},
        )
        assert all(
            name != threading.main_thread().name
            for _m, _p, name in FakeService.calls[before:]
        )


async def test_uncached_apk_shows_analysing_then_pulls(fake):
    FakeService.cached = set()
    gate = threading.Event()
    FakeService.gates[("static_pull", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: sections.facts and sections.facts.footprint)
        assert sections.facts.static_state == "analysing"
        assert "analysing manifest" in str(sections.section("exposure").border_title)
        gate.set()
        await _wait(pilot, lambda: sections.facts.static_state == "ready")
        await _settle(pilot)
        assert any(".Files" in t for t in _texts(sections.section("exposure")))
        # the decoded manifest triggers a permissions re-read
        await _wait(
            pilot,
            lambda: sum(m == "permissions" for m, _p, _t in FakeService.calls) >= 2,
        )


async def test_a_slow_footprint_does_not_hold_up_the_manifest(fake):
    FakeService.cached = set()
    gate = threading.Event()
    FakeService.gates[("footprint", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: sections.facts.static_state == "ready")
        assert sections.facts.footprint is None
        assert "measuring" in _texts(sections.section("data"))[0]
        gate.set()
        await _wait(pilot, lambda: sections.facts.footprint is not None)


async def test_unhashable_apk_is_not_pulled_and_says_why(fake):
    FakeService.cached = set()
    FakeService.unhashable = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: sections.facts and sections.facts.footprint)
        await _settle(pilot)
        assert sections.facts.static_state == "missing"
        assert "could not hash" in _texts(sections.section("defences"))[0]
        assert "static_pull" not in {m for m, _p, _t in FakeService.calls}


async def test_stale_results_of_a_previous_app_are_dropped(fake):
    gate = threading.Event()
    FakeService.gates[("details", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: sections.package == PKG)
        fake["pkg"] = OTHER
        ms.query_one(SpotlightPanel).refresh_panel()
        await _wait(pilot, lambda: _loaded(sections) and sections.package == OTHER)
        gate.set()  # the old app's details arrive late
        await _wait(
            pilot, lambda: sum(m == "details" for m, _p, _t in FakeService.calls) >= 2
        )
        await _settle(pilot, 6)
        assert sections.package == OTHER
        assert sections.facts.details.value["version_name"] == "9.9"


async def test_appops_poll_only_while_visible(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        await pilot.press("2")
        await _settle(pilot)
        before = len(FakeService.calls)
        sections._last_runtime = sections.facts.appops_at = 0.0  # 10 s are over
        sections._poll_tick()
        sections.note_state_changed()
        await _settle(pilot)
        assert len(FakeService.calls) == before
        assert sections._stale
        await pilot.press("1")
        await _wait(pilot, lambda: len(FakeService.calls) > before)
        sections_calls = {m for m, _p, _t in FakeService.calls[before:]}
        assert "appops" in sections_calls


async def test_no_app_keeps_the_old_panel_and_no_inspector(fake):
    fake["pkg"] = None
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        assert sections.facts is None
        assert not sections.display
        assert app.focused.id == "spotlight-panel"
        assert ms.check_action("inspect", ()) is True
        await pilot.press("enter")
        await _settle(pilot)
        assert not ms.inspector_is_open
        assert FakeService.calls == []


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def test_app_and_network_lens_keys_do_not_clash() -> None:
    """Enter inspects in App + Network; Space starts; / z u are lens-local."""
    from textual.containers import VerticalScroll
    from textual.widgets import DataTable

    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen
    from sandroid.tui.widgets.network_panel import NetworkPanel

    def keys(cls) -> dict[str, str]:
        return {b.key: b.action for b in cls.BINDINGS if hasattr(b, "key")}

    app_lens_keys = keys(SpotlightPanel)
    net = keys(NetworkPanel)
    assert "enter" not in app_lens_keys
    assert "enter" not in net
    assert app_lens_keys["space"] == "primary"
    assert net["space"] == "start_mitm"  # Space never stops mitmproxy
    assert app_lens_keys["slash"] == "filter" == net["slash"]
    assert app_lens_keys["z"] == "fold"
    assert app_lens_keys["u"] == "refresh_facts"
    global_keys = set(keys(SandroidTUI)) | set(keys(MainScreen))
    assert not {"space", "slash", "z", "u"} & global_keys
    # What a focused section table / the scroller bind never shadows them.
    widget_keys = {
        k.strip()
        for cls in (DataTable, VerticalScroll)
        for b in cls.BINDINGS
        for k in b.key.split(",")
    }
    assert not {"space", "slash", "z", "u", "b"} & widget_keys
    assert MainScreen.BINDINGS
    assert keys(MainScreen)["enter"] == "inspect"


# --------------------------------------------------------------------------
# review fixes
# --------------------------------------------------------------------------


def _many_rows(n: int, stamp: str, extra: int = 0) -> app_lens.SectionData:
    rows = [
        app_lens.Row(
            key=f"r{i}",
            cells=(app_lens._t(f"op {i}"), app_lens._t(f"allow · {stamp}")),
        )
        for i in range(n + extra)
    ]
    return app_lens.SectionData(("op", "AppOps"), rows, f"{n} ops")


async def test_a_poll_keeps_the_scroll_position_and_the_cursor() -> None:
    """300 rows scrolled to 150: a changed "Ns ago" must not snap back."""
    from textual.app import App

    class Harness(App):
        def compose(self):
            yield LensSection("permissions")

    app = Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        section = app.query_one(LensSection)
        section.show(_many_rows(300, "5s ago"))
        section.focus()
        await _settle(pilot)
        section.move_cursor(row=160, animate=False)
        section.scroll_to(y=150, animate=False)
        await _settle(pilot)
        assert section.scroll_y == 150
        # same rows, new text: cells update in place
        section.show(_many_rows(300, "15s ago"))
        await _settle(pilot)
        assert section.scroll_y == 150
        assert section.cursor_row == 160
        assert "15s ago" in str(section.get_row("r10")[1])
        # a row more: the table is rebuilt, the view is restored
        section.show(_many_rows(300, "25s ago", extra=1))
        await _settle(pilot)
        assert section.scroll_y == 150
        assert section.cursor_row == 160


async def test_trackers_re_read_the_cache_when_static_analysis_ends(fake):
    """'press a' must go away once ``a`` recorded an Insight result."""
    from sandroid.core.events.events import AnalysisCompleted

    FakeService.no_insight = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        await _settle(pilot)
        assert _texts(sections.section("trackers"))[0] == ANALYSIS_HINT
        FakeService.no_insight = set()  # the analysis wrote meta.json
        AnalysisCompleted(source="static_analysis").publish()
        await _wait(
            pilot,
            lambda: any(
                "Firebase Analytics" in t for t in _texts(sections.section("trackers"))
            ),
        )


async def test_lens_activation_re_reads_a_cache_without_insight(fake):
    FakeService.no_insight = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        await pilot.press("2")
        await _settle(pilot)
        FakeService.no_insight = set()
        before = len(FakeService.calls)
        await pilot.press("1")
        await _wait(
            pilot,
            lambda: "static_cache" in {m for m, _p, _t in FakeService.calls[before:]},
        )
        await _wait(pilot, lambda: sections.facts.static.insight is not None)


async def test_a_failed_worker_clears_only_its_own_flags(fake):
    FakeService.fail = {("footprint", PKG)}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: sections.facts and sections.facts.services)
        await _wait(pilot, lambda: sections._footprint_inflight is None)
        # a failed runtime worker of another generation / request is ignored
        token = sections._token()
        sections._runtime_rid = 99
        sections._runtime_done((token[0], token[1] - 1), 99)
        sections._runtime_done(token, 98)
        assert sections._runtime_rid == 99
        sections._runtime_done(token, 99)
        assert sections._runtime_rid is None
        # a failing appops refresh still ends its in-flight state
        FakeService.fail = {("appops", PKG)}
        assert sections.refresh_runtime(("appops",))
        await _wait(pilot, lambda: not sections._runtime_inflight)


async def test_u_during_a_running_poll_runs_right_after_it(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        gate = threading.Event()
        FakeService.gates[("appops", PKG)] = gate
        sections._last_runtime = sections.facts.appops_at = 0.0
        sections._poll_tick()  # the 10 s AppOps poll, held at the gate
        assert sections._runtime_inflight
        before = len(FakeService.calls)
        await pilot.press("u")
        await _settle(pilot)
        gate.set()
        start = time.monotonic()
        await _wait(
            pilot,
            lambda: "static_cache" in {m for m, _p, _t in FakeService.calls[before:]},
            timeout=3.0,
        )
        assert time.monotonic() - start < 3.0  # not the 10 s throttle


async def test_footprint_gets_the_known_data_dir(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        assert FakeService.footprint_dirs == [f"/data/user/0/{PKG}"]


async def test_caption_offers_space_only_when_it_does_something(fake, monkeypatch):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        await _wait(pilot, lambda: _sections(ms).facts is not None)
        panel = ms.query_one(SpotlightPanel)

        def caption() -> str:
            panel._update_caption()
            return ms._lens_captions["app"][1] or ""

        assert "␣" not in caption()  # running (PID 4242): Space does nothing
        monkeypatch.setattr(SpotlightPanel, "_safe_pid", lambda self: None)
        assert caption().endswith("· ␣ start")
        monkeypatch.setattr(SpotlightPanel, "_safe_pid", lambda self: 4242)
        monkeypatch.setattr(SpotlightPanel, "_is_paused", lambda self: True)
        assert caption().endswith("· ␣ resume")


async def test_narrow_lens_keeps_bypass_and_actions_on_one_line_each(fake):
    """100x30 with the Inspector open: the lens is ~44 columns wide."""
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        await _settle(pilot)
        wide = _screen_text(app)
        assert "⇧K kill" in wide
        assert "1 ○ SSL" in wide  # the full toggle row fits
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await _settle(pilot)
        assert ms.inspector_is_open
        panel = ms.query_one(SpotlightPanel)
        assert panel.size.width < 60
        text = _screen_text(app)
        assert "b bypass: none" in text
        assert "1 ○ SSL" not in text
        actions = next(line for line in text.splitlines() if "⇧R" in line)
        for key in ("⇧R", "⇧A", "⇧P", "⇧K", "⇧X"):
            assert key in actions
        ms.close_inspector()
        await _settle(pilot)
        assert "⇧K kill" in _screen_text(app)


def _bookkeeping_ops() -> list[AppOpEntry]:
    """What API 35 printed for org.wikipedia: uid ``ignore`` per ungranted op."""
    ops = [
        AppOpEntry(name, mode="ignore", uid_mode="ignore", permission=perm)
        for name, perm in (
            ("READ_SMS", "android.permission.READ_SMS"),
            ("READ_CALENDAR", "android.permission.READ_CALENDAR"),
            ("ACCEPT_HANDOVER", None),
        )
    ]
    ops.append(
        AppOpEntry("ACCESS_RESTRICTED_SETTINGS", mode="default", package_mode="default")
    )
    ops.append(AppOpEntry("SYSTEM_ALERT_WINDOW", mode="deny", package_mode="deny"))
    return ops


def test_bookkeeping_ops_collapse_and_are_counted() -> None:
    ops = _appops()
    ops.ops.extend(_bookkeeping_ops())
    data = build_permissions(AppFacts(package=PKG, permissions=_grants(), appops=ops))
    keys = [r.key for r in data.rows]
    assert "op:SYSTEM_ALERT_WINDOW" in keys  # deny: a mode worth a row
    assert "op:READ_CLIPBOARD" in keys  # recorded access
    assert {r.key for r in data.hidden_rows} == {
        "op:READ_SMS",
        "op:READ_CALENDAR",
        "op:ACCEPT_HANDOVER",
        "op:ACCESS_RESTRICTED_SETTINGS",
    }
    # FINE_LOCATION (granted, no access) + 5 never-used op-only rows
    assert data.summary.endswith("2 used recently · 6 no recorded use")
    noted = [r for r in [*data.rows, *data.hidden_rows] if "no recorded use" in r.text]
    assert len(noted) == 6


async def test_other_ops_row_expands_with_z_enter_and_filter(fake):
    FakeService.extra_ops = _bookkeeping_ops()
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        await _settle(pilot)
        perms = sections.section("permissions")
        keys = [r.key for r in perms.rows_shown]
        assert keys[-1] == app_lens.MORE_KEY
        assert "op:READ_SMS" not in keys
        assert "+4 other ops (no recorded use)" in perms.rows_shown[-1].text
        perms.focus()
        perms.move_cursor(row=len(keys) - 1)
        await _settle(pilot)
        await pilot.press("z")
        await _settle(pilot)
        assert perms.expanded
        assert not perms.folded
        assert "op:READ_SMS" in [r.key for r in perms.rows_shown]
        assert perms.cursor_key() == perms.data.hidden_rows[0].key
        perms.move_cursor(row=len(perms.rows_shown) - 1)
        await _settle(pilot)
        assert perms.cursor_key() == app_lens.LESS_KEY
        await pilot.press("enter")  # Enter on "hide" collapses, no Inspector
        await _settle(pilot)
        assert not perms.expanded
        assert not ms.inspector_is_open
        # a filter searches the hidden rows too
        sections.set_filter("read_sms")
        await _settle(pilot)
        assert [r.key for r in perms.rows_shown] == ["op:READ_SMS"]


def test_compact_permission_cells_combine_grant_and_use() -> None:
    data = build_permissions(
        AppFacts(package=PKG, permissions=_grants(), appops=_appops())
    )
    assert data.compact_columns == ("permission", "✓·use", "last use")
    compact = {
        r.key: " | ".join(c.plain for c in r.compact) for r in data.rows if r.compact
    }
    assert compact["perm:android.permission.CAMERA"] == "CAMERA | ✓● | 5m ago"
    assert (
        compact["perm:android.permission.ACCESS_FINE_LOCATION"]
        == "ACCESS_FINE_LOCATION | ✓○ | —"
    )
    assert compact["perm:android.permission.READ_CONTACTS"] == "READ_CONTACTS | ✗ | —"
    assert compact["perm:android.permission.INTERNET"] == "INTERNET | ✓ | —"
    assert compact["op:READ_CLIPBOARD"] == "READ_CLIPBOARD | op● | 10s ago"


async def test_narrow_lens_shows_the_compact_permission_columns(fake):
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await _boot(app, pilot)
        sections = _sections(ms)
        await _wait(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        assert len(perms.columns) == 5
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await _wait(pilot, lambda: perms.compact)
        await _settle(pilot)
        labels = [str(c.label) for c in perms.columns.values()]
        assert labels == ["permission", "✓·use", "last use"]
        cam = next(
            i for i, r in enumerate(perms.rows_shown) if r.key.endswith("CAMERA")
        )
        assert [str(c) for c in perms.get_row_at(cam)] == ["CAMERA", "✓●", "5m ago"]
        # the whole grant / AppOps detail is still in the Inspector
        perms.focus()
        perms.move_cursor(row=cam)
        await pilot.press("enter")
        await _settle(pilot)
        assert "AppOps CAMERA" in dict(ms.inspector_content.tabs[0][1])
        ms.close_inspector()
        await _wait(pilot, lambda: not perms.compact)
        assert len(perms.columns) == 5


def test_data_says_dash_for_an_absent_external_dir() -> None:
    fp = DataFootprint(
        package=PKG,
        private_dir=f"/data/data/{PKG}",
        private_kb=13040,
        external_dir=f"/sdcard/Android/data/{PKG}",
        external_reason="absent",
    )
    data = app_lens.build_data(AppFacts(package=PKG, footprint=fp))
    assert data.summary == "private 12.7 MB · external —"
    external = next(r for r in data.rows if r.key == "external")
    assert external.text.startswith("external —")
    fp.external_reason = "permission denied"
    assert app_lens.build_data(AppFacts(package=PKG, footprint=fp)).summary.endswith(
        "external ?"
    )
