"""App lens sections (identity ... suspected defences) on a fake data layer.

No device: ``app_lens.make_service`` is replaced by :class:`FakeService`
built from the real result dataclasses of ``app_info_service``; the
spotlight package comes from a patched ``SpotlightPanel._current_package``.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from pilot_helpers import boot, settle, until

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
    build_identity,
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


def _band(section: LensSection) -> str:
    """The plain text of a section's header band."""
    from textual.content import Content

    plain = Content.from_markup(str(section.border_title or "")).plain
    return plain.strip()


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
    assert "denied" in by_key["perm:android.permission.READ_CONTACTS"]
    assert data.summary == (
        "4 requested, 3 dangerous (2 granted), 2 used recently, 1 no recorded use"
    )
    assert " · " not in data.summary  # plain words and commas, no glyphs


def test_permissions_header_counts_what_the_device_keeps() -> None:
    """Requested = dumpsys (what the device keeps); the manifest count beside
    it when it differs; "no recorded use" never counts op-only rows.
    """
    overview = dict(
        OVERVIEW,
        requested_permissions=[
            {"name": g.name, "tag": "uses-permission", "max_sdk_version": None}
            for g in _grants().permissions
        ]
        + [
            {
                "name": "android.permission.WRITE_EXTERNAL_STORAGE",
                "tag": "uses-permission",
                "max_sdk_version": 28,
            },
            {
                "name": "android.permission.BLUETOOTH_SCAN",
                "tag": "uses-permission-sdk-23",
                "max_sdk_version": None,
            },
        ],
    )
    static = StaticOverview(package=PKG, overview=overview, from_cache=True)
    ops = _appops()
    ops.ops.extend(_bookkeeping_ops())
    f = AppFacts(package=PKG, permissions=_grants(), appops=ops, static=static)
    data = build_permissions(f)
    # N6-V2: the gap is explained (device API unknown: not kept).
    assert data.summary == (
        "4 requested, 6 in the manifest (2 not kept on this device), "
        "3 dangerous (2 granted), 2 used recently, 1 no recorded use"
    )
    # the manifest evidence names the real request tag
    camera = next(r for r in data.rows if r.key == "perm:android.permission.CAMERA")
    assert '<uses-permission android:name="android.permission.CAMERA" />' in str(
        camera.evidence[0][1]
    )
    # grants unreadable (device API unknown): the manifest count alone
    f.permissions = PermissionState(package=PKG, ok=False, reason="offline")
    assert build_permissions(f).summary.startswith("6 in the manifest, 0 dangerous")
    # equal counts: no manifest note
    f.permissions = _grants()
    overview["requested_permissions"] = overview["requested_permissions"][:4]
    assert build_permissions(f).summary.startswith("4 requested, 3 dangerous")


def test_permissions_header_explains_the_manifest_gap() -> None:
    """N6-V2: "33 requested, 36 in the manifest" said nothing about why."""
    from sandroid.tui.widgets.app_lens import _manifest_gap

    entries = [
        {"name": f"p{i}", "tag": "uses-permission", "max_sdk_version": None}
        for i in range(4)
    ] + [{"name": "old", "tag": "uses-permission", "max_sdk_version": 28}]
    overview = {"requested_permissions": entries}
    on_35 = SimpleNamespace(api_level=35)
    assert _manifest_gap(4, 5, on_35, overview) == " (1 capped by maxSdkVersion)"
    assert _manifest_gap(3, 5, on_35, overview) == " (2 not kept on this device)"
    assert _manifest_gap(7, 5, on_35, overview) == " (2 added by Android)"
    assert _manifest_gap(None, 5, on_35, overview) == ""


def test_identity_says_system_app_and_whole_split_names() -> None:
    from sandroid.tui.widgets.app_lens import _split_names

    details = SimpleNamespace(value={"install_source": None, "system_app": True})
    rows = build_identity(AppFacts(package=PKG, details=details)).rows
    installer = next(r for r in rows if r.key == "installer")
    assert "system app" in installer.text
    assert "sideloaded" not in installer.text
    details.value["system_app"] = False
    rows = build_identity(AppFacts(package=PKG, details=details)).rows
    assert "sideloaded" in next(r for r in rows if r.key == "installer").text
    names = ["split_config.arm64_v8a.apk", "split_config.xxhdpi.apk", "split_x.apk"]
    assert _split_names(names[:2]) == "split_config.arm64_v8a, split_config.xxhdpi"
    assert _split_names(names) == "split_config.arm64_v8a, +2 more"


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
                        "network_signature": r"googleads\.g\.doubleclick\.net",
                        "website": "https://admob.google.com/home/",
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
    # N6-B4: the vendor column is the website's host, not the detection regex.
    assert "admob.google.com" in texts[0]
    assert "googleads" not in texts[0]
    assert any("Firebase Analytics" in t for t in texts)
    assert section.summary.startswith("1 tracker, 3 SDKs")


def test_tracker_vendor_prefers_the_vendor_then_the_website_host() -> None:
    from sandroid.tui.widgets.app_lens import _tracker_vendor

    assert _tracker_vendor({"vendor": "Google", "website": "x.io"}) == "Google"
    assert _tracker_vendor({"website": "https://www.facebook.com/x"}) == (
        "facebook.com"
    )
    assert _tracker_vendor({"website": "appsflyer.com"}) == "appsflyer.com"
    assert _tracker_vendor({"network_signature": r"a\.b"}) == "—"


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
    # b6 (emulator) is a real chord key once BypassService has the category.
    assert route_text(["b6"]) == "b6 emulator"
    # A digit the chord does not have is still marked instead of dead.
    assert route_text(["b9"]).endswith("(n/a)")


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
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        titles = [_band(s) for s in sections.sections()]
        # " TITLE   summary" on the header band (no fold glyph)
        assert [t.split("   ")[0] for t in titles] == [
            t for _id, t in app_lens.SECTIONS
        ]
        perms = sections.section("permissions")
        assert "4 requested, 3 dangerous (2 granted)" in _band(perms)
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
        assert "not observed" in _band(defences)
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
        await settle(pilot)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert content.lens == "app"
        assert [name for name, _s in content.tabs] == ["Evidence", "Raw"]
        assert content.key.startswith("app:identity:")
        # Space = Start/Resume, also from inside a section table
        await pilot.press("space")
        await settle(pilot)
        assert started == [1]
        # the caption advertises the lens keys
        assert "Enter inspect" in (ms._lens_captions["app"][1] or "")
        if size == (100, 30):
            # header, the frame and the action row stay on screen
            ms.close_inspector()
            await settle(pilot)
            text = _screen_text(app)
            assert "Space start" in text or "running" in text
            assert "Shift+K kill" in text
            assert "IDENTITY" in text


async def test_permissions_row_inspector_has_grant_and_appops(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        perms.focus()
        await settle(pilot)
        index = next(
            i for i, r in enumerate(perms.rows_shown) if r.key.endswith("CAMERA")
        )
        perms.move_cursor(row=index)
        await pilot.press("enter")
        await settle(pilot)
        content = ms.inspector_content
        assert content.key == "app:permissions:perm:android.permission.CAMERA"
        evidence = dict(content.tabs[0][1])
        assert "Manifest" in evidence
        assert "AppOps CAMERA" in evidence
        assert "uses-permission" in str(evidence["Manifest"])


async def test_tab_moves_between_sections_and_z_folds(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        first = sections.section("identity")
        first.focus()
        await settle(pilot)
        await pilot.press("tab")
        await settle(pilot)
        assert app.focused is sections.section("permissions")
        await pilot.press("z")
        await settle(pilot)
        perms = sections.section("permissions")
        assert perms.folded
        assert perms.size.height == 0
        assert _band(perms).startswith("PERMISSIONS folded")
        # still in the focus order while folded
        await pilot.press("tab")
        await pilot.press("shift+tab")
        await settle(pilot)
        assert app.focused is perms
        await pilot.press("z")
        await settle(pilot)
        assert not perms.folded
        assert perms.size.height > 3


async def test_clicking_a_section_header_band_folds_and_unfolds_it(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        perms.scroll_visible(animate=False)
        await settle(pilot)
        await pilot.click(perms, offset=(4, 0))  # the PERMISSIONS band
        await settle(pilot)
        assert perms.folded
        assert app.focused is perms
        assert _band(perms).startswith("PERMISSIONS folded")
        assert not ms.inspector_is_open
        await pilot.click(perms, offset=(4, 0))
        await settle(pilot)
        assert not perms.folded
        # a click on a row still moves the cursor and does not fold
        await pilot.click(perms, offset=(4, 3))
        await settle(pilot)
        assert not perms.folded


async def test_slash_filters_rows_across_sections_and_esc_clears(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await pilot.press("slash")
        await settle(pilot)
        assert app.focused.id == "app-filter"
        for ch in "camera":
            await pilot.press(ch)
        await until(pilot, lambda: sections.filter_text == "camera")
        perms = _texts(sections.section("permissions"))
        assert len(perms) == 1
        assert "CAMERA" in perms[0]
        assert "no rows match" in _texts(sections.section("exposure"))[0]
        assert "1 of" in _band(sections.section("permissions"))
        await pilot.press("escape")
        await settle(pilot)
        assert sections.filter_text == ""
        assert len(_texts(sections.section("permissions"))) > 1


async def test_u_refreshes_runtime_facts_off_thread(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        before = len(FakeService.calls)
        await pilot.press("u")
        await until(
            pilot,
            lambda: (
                {"footprint", "static_cache"}
                <= {m for m, _p, _t in FakeService.calls[before:]}
            ),
        )
        assert all(
            name != threading.main_thread().name
            for _m, _p, name in FakeService.calls[before:]
        )


async def test_u_says_refreshing_then_refreshed(fake, monkeypatch):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        toasts: list[tuple[str, str]] = []
        monkeypatch.setattr(
            app,
            "notify",
            lambda msg, severity="information", **_k: toasts.append((msg, severity)),
        )
        sections = _sections(ms)
        panel = ms.query_one(SpotlightPanel)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        gate = threading.Event()
        FakeService.gates[("appops", PKG)] = gate
        await pilot.press("u")
        await settle(pilot)
        assert sections.refreshing
        assert "refreshing app facts" in panel._render_header()
        assert "u refreshing" in (ms._lens_captions["app"][1] or "")
        assert toasts == []  # the header says it; no toast before the end
        gate.set()
        await until(pilot, lambda: toasts)
        assert toasts == [("App facts refreshed", "information")]
        assert not sections.refreshing
        assert "refreshing" not in panel._render_header()


async def test_u_says_what_could_not_be_read(fake, monkeypatch):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        toasts: list[tuple[str, str]] = []
        monkeypatch.setattr(
            app,
            "notify",
            lambda msg, severity="information", **_k: toasts.append((msg, severity)),
        )
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        monkeypatch.setattr(
            FakeService,
            "appops",
            lambda self, package: AppOpsState(
                package=package, ok=False, reason="appops: permission denied"
            ),
        )
        await pilot.press("u")
        await until(pilot, lambda: toasts)
        msg, severity = toasts[0]
        assert severity == "warning"
        assert msg.startswith("App facts refreshed, but not all could be read")
        assert "AppOps: appops: permission denied" in msg
        # A worker that raised says so too.
        toasts.clear()
        FakeService.fail = {("services", PKG)}
        await pilot.press("u")
        await until(pilot, lambda: toasts)
        assert "the refresh failed (see the log)" in toasts[0][0]
        assert not sections.refreshing


async def test_uncached_apk_shows_analysing_then_pulls(fake):
    FakeService.cached = set()
    gate = threading.Event()
    FakeService.gates[("static_pull", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: sections.facts and sections.facts.footprint)
        assert sections.facts.static_state == "analysing"
        assert "analysing manifest" in _band(sections.section("exposure"))
        gate.set()
        await until(pilot, lambda: sections.facts.static_state == "ready")
        await settle(pilot)
        assert any(".Files" in t for t in _texts(sections.section("exposure")))
        # the decoded manifest triggers a permissions re-read
        await until(
            pilot,
            lambda: sum(m == "permissions" for m, _p, _t in FakeService.calls) >= 2,
        )


async def test_a_slow_footprint_does_not_hold_up_the_manifest(fake):
    FakeService.cached = set()
    gate = threading.Event()
    FakeService.gates[("footprint", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: sections.facts.static_state == "ready")
        assert sections.facts.footprint is None
        assert "measuring" in _texts(sections.section("data"))[0]
        gate.set()
        await until(pilot, lambda: sections.facts.footprint is not None)


async def test_unhashable_apk_is_not_pulled_and_says_why(fake):
    FakeService.cached = set()
    FakeService.unhashable = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: sections.facts and sections.facts.footprint)
        await settle(pilot)
        assert sections.facts.static_state == "missing"
        assert "could not hash" in _texts(sections.section("defences"))[0]
        assert "static_pull" not in {m for m, _p, _t in FakeService.calls}


async def test_stale_results_of_a_previous_app_are_dropped(fake):
    gate = threading.Event()
    FakeService.gates[("details", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: sections.package == PKG)
        fake["pkg"] = OTHER
        ms.query_one(SpotlightPanel).refresh_panel()
        await until(pilot, lambda: _loaded(sections) and sections.package == OTHER)
        gate.set()  # the old app's details arrive late
        await until(
            pilot, lambda: sum(m == "details" for m, _p, _t in FakeService.calls) >= 2
        )
        await settle(pilot)
        assert sections.package == OTHER
        assert sections.facts.details.value["version_name"] == "9.9"


async def test_appops_poll_only_while_visible(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        await pilot.press("2")
        await settle(pilot)
        before = len(FakeService.calls)
        sections._last_runtime = sections.facts.appops_at = 0.0  # 10 s are over
        sections._poll_tick()
        sections.note_state_changed()
        await settle(pilot)
        assert len(FakeService.calls) == before
        assert sections._stale
        await pilot.press("1")
        await until(pilot, lambda: len(FakeService.calls) > before)
        sections_calls = {m for m, _p, _t in FakeService.calls[before:]}
        assert "appops" in sections_calls


async def test_no_app_keeps_the_old_panel_and_no_inspector(fake):
    fake["pkg"] = None
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        assert sections.facts is None
        assert not sections.display
        assert app.focused.id == "spotlight-panel"
        assert ms.check_action("inspect", ()) is True
        await pilot.press("enter")
        await settle(pilot)
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
        await settle(pilot)
        section.move_cursor(row=160, animate=False)
        section.scroll_to(y=150, animate=False)
        await settle(pilot)
        assert section.scroll_y == 150
        # same rows, new text: cells update in place
        section.show(_many_rows(300, "15s ago"))
        await settle(pilot)
        assert section.scroll_y == 150
        assert section.cursor_row == 160
        assert "15s ago" in str(section.get_row("r10")[1])
        # a row more: the table is rebuilt, the view is restored
        section.show(_many_rows(300, "25s ago", extra=1))
        await settle(pilot)
        assert section.scroll_y == 150
        assert section.cursor_row == 160


async def test_theme_switch_recolors_the_lens_css_and_rich_text(fake):
    """Settings preview / revert re-colors the sections and the panel live."""
    from sandroid.tui.themes import (
        DEFAULT_LENS,
        DEFAULT_THEME,
        LIGHT_THEME,
        get_theme_css_path,
    )

    def dangerous_style(perms: LensSection) -> str:
        index = next(
            i for i, r in enumerate(perms.rows_shown) if r.key.endswith("CAMERA")
        )
        return str(perms.get_row_at(index)[1].style)

    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        body = ms.query_one("#spotlight-body")
        assert dangerous_style(perms) == DEFAULT_LENS.warn
        assert perms.styles.background.hex.lower() == DEFAULT_LENS.bg

        app._apply_theme(LIGHT_THEME, get_theme_css_path("light"))
        await settle(pilot)
        light = LIGHT_THEME.lens
        assert app.theme == "sandroid-light"
        assert perms.styles.background.hex.upper() == light.bg
        assert dangerous_style(perms) == light.warn
        assert light.label in str(body.content)
        assert DEFAULT_LENS.label not in str(body.content)

        app._apply_theme(DEFAULT_THEME, get_theme_css_path("default"))
        await settle(pilot)
        assert dangerous_style(perms) == DEFAULT_LENS.warn
        assert perms.styles.background.hex.lower() == DEFAULT_LENS.bg


async def test_dense_dark_theme_keeps_cell_colors_under_the_cursor(fake):
    """Graphite: a cell keeps its own color on the cursor row; default: not."""
    from sandroid.tui.themes import (
        DEFAULT_THEME,
        GRAPHITE_THEME,
        get_theme_css_path,
    )

    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        assert perms.cursor_foreground_priority == "css"

        app._apply_theme(GRAPHITE_THEME, get_theme_css_path("graphite"))
        await until(
            pilot,
            lambda: (
                app.theme == "sandroid-graphite"
                and perms.cursor_foreground_priority == "renderable"
                and perms.styles.background.hex.upper() == GRAPHITE_THEME.lens.bg
            ),
        )
        footer_key = app.theme_variables["footer-key-foreground"].upper()
        assert footer_key == GRAPHITE_THEME.lens.title

        app._apply_theme(DEFAULT_THEME, get_theme_css_path("default"))
        await until(pilot, lambda: perms.cursor_foreground_priority == "css")


def test_dense_dark_themes_meet_their_contrast_floors():
    """Body text >= 7:1, every text tier >= 4.5:1, also on the cursor rows."""
    from sandroid.tui.themes import THEMES, get_theme_css_path

    def lum(hexv: str) -> float:
        rgb = [int(hexv.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    def ratio(a: str, b: str) -> float:
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    for name in ("graphite", "deep_sea", "evergreen"):
        theme = THEMES[name]
        p = theme.lens
        assert get_theme_css_path(name).name == f"{name}.tcss"
        assert p.cursor_keeps_colors
        assert lum(p.bg) < lum(p.panel) < lum(p.cursor_focus)
        assert lum(p.text) > lum(p.label) > lum(p.dim)
        for surface in (p.bg, p.panel, p.cursor, p.cursor_focus):
            assert ratio(p.text, surface) >= 7, (name, surface)
            for tier in ("label", "dim", "muted", "header", "ok", "warn", "bad"):
                assert ratio(getattr(p, tier), surface) >= 4.5, (name, tier)
        band = theme.textual_variables["footer-background"]
        assert ratio(theme.text_muted, band) >= 4.5, name
        assert ratio(p.accent_text, p.accent) >= 4.5, name


async def test_light_themes_recolor_the_shell_chrome_and_status_glyphs(fake):
    """Paper / Daylight load (their .tcss parses), re-color the header and the
    status strip's "running"-style colors, and the default comes back intact.
    """
    from sandroid.tui.themes import (
        DEFAULT_THEME,
        FIXED_COLORS,
        THEME_ORDER,
        THEMES,
        fixed_color,
        get_theme_css_path,
    )

    for name in ("paper", "daylight"):
        assert name in THEME_ORDER
        assert get_theme_css_path(name).name == f"{name}.tcss"
        assert set(THEMES[name].status_colors) <= set(FIXED_COLORS)

    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        header = ms.query_one("#shell-header")
        for name in ("paper", "daylight"):
            theme = THEMES[name]
            app._apply_theme(theme, get_theme_css_path(name))
            await settle(pilot)
            assert app.theme == f"sandroid-{name}"
            assert fixed_color("running") == theme.status_colors["running"]
            assert (
                app.get_css_variables()["footer-key-foreground"]
                == (theme.textual_variables["footer-key-foreground"])
            )
            assert header.styles.background.hex.upper() != "#0B1628"

        app._apply_theme(DEFAULT_THEME, get_theme_css_path("default"))
        await settle(pilot)
        assert fixed_color("running") == FIXED_COLORS["running"]
        assert header.styles.background.hex.lower() == "#0b1628"


def _static_event(state: str, **data) -> None:
    """Publish a static analysis (``a``) state TaskOutput off the UI thread."""
    from sandroid.core.events.events import TaskOutput

    payload = {"state": state, "package": PKG, "profile": "privacy", **data}
    event = TaskOutput(
        task_name="static_analysis",
        message="free text the panel never parses",
        data=payload,
        source="static_analysis",
    )
    worker = threading.Thread(target=event.publish)
    worker.start()
    worker.join()


async def test_trackers_re_read_the_cache_when_static_analysis_ends(fake):
    """'press a' must go away once ``a`` recorded an Insight result."""
    FakeService.no_insight = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        assert _texts(sections.section("trackers"))[0] == ANALYSIS_HINT
        FakeService.no_insight = set()  # the analysis wrote meta.json
        _static_event("finished", duration_s=12.0, results_dir="/x")
        await until(
            pilot,
            lambda: any(
                "Firebase Analytics" in t for t in _texts(sections.section("trackers"))
            ),
        )


async def test_static_analysis_progress_in_the_header_and_toasts(fake, monkeypatch):
    app = _app()
    async with app.run_test(size=(200, 45)) as pilot:
        ms = await boot(app, pilot)
        toasts: list[tuple[str, str]] = []
        monkeypatch.setattr(
            app,
            "notify",
            lambda msg, severity="information", **_k: toasts.append((msg, severity)),
        )
        sections = _sections(ms)
        panel = ms.query_one(SpotlightPanel)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        assert "static analysis" not in panel._render_header()

        _static_event("started", trackers=True, security=False, verbose=False)
        await until(pilot, lambda: panel._static_timer is not None)
        assert "static analysis running (privacy profile), 0 s" in str(
            panel.query_one("#spotlight-header").render()
        )
        # the 1 s timer keeps the elapsed time current
        next(iter(panel._static_runs.values()))["since"] -= 80
        await until(
            pilot,
            lambda: "privacy profile), 1 min 2"
            in str(panel.query_one("#spotlight-header").render()),
        )
        # another app's run and a local APK (package unknown) stay out of it
        _static_event("started", package=OTHER)
        _static_event("started", package=None, apk="sample.apk")
        await until(pilot, lambda: len(panel._static_runs) == 3)
        assert panel._render_header().count("static analysis") == 1

        before = len(FakeService.calls)
        _static_event("finished", duration_s=95.4, results_dir="/x")
        await until(pilot, lambda: toasts)
        assert toasts == [("Static analysis done in 1 min 35 s", "information")]
        assert "static analysis" not in panel._render_header()
        await until(
            pilot,
            lambda: any(
                m == "static_cache" for m, _p, _t in FakeService.calls[before:]
            ),
        )
        assert panel._static_timer is not None  # two runs still going

        toasts.clear()
        _static_event("failed", package=OTHER, error="dexray-insight crashed")
        _static_event("cancelled", package=None, apk="sample.apk")
        await until(pilot, lambda: len(toasts) == 2)
        assert toasts == [
            (
                "Static analysis failed for org.other.app: dexray-insight crashed",
                "warning",
            ),
            ("Static analysis cancelled for sample.apk", "information"),
        ]
        assert panel._static_runs == {}
        assert panel._static_timer is None  # no timer while nothing runs


def test_static_analysis_state_keys_only_on_data_state() -> None:
    from sandroid.core.events import Event, EventType
    from sandroid.tui.widgets.spotlight_panel import (
        duration_words,
        static_analysis_state,
    )

    def event(data, source="static_analysis"):
        return Event(type=EventType.TASK_OUTPUT, data=data, source=source)

    payload = {"state": "finished", "package": PKG}
    assert static_analysis_state(event({"data": payload})) == payload
    # "Found 12 permissions" outputs carry no state; other tools are ignored
    assert static_analysis_state(event({"message": "finished", "data": None})) is None
    assert static_analysis_state(event({"data": {"state": "odd"}})) is None
    assert static_analysis_state(event({"data": payload}, source="network")) is None
    assert [duration_words(s) for s in (0.4, 45, 60, 80, 3600, 23002)] == [
        "0 s",
        "45 s",
        "1 min",
        "1 min 20 s",
        "1 h",
        "6 h 23 min",  # N6-V5: not "383 min 22 s"
    ]


def _static_with(insight: dict, **insight_meta) -> StaticOverview:
    static = StaticOverview(
        package=PKG,
        overview=OVERVIEW,
        meta={"insight": {"summary": insight, **insight_meta}},
        from_cache=True,
    )
    static.set_insight(insight)
    return static


def test_trackers_say_not_analysed_when_the_run_had_trackers_off() -> None:
    static = _static_with(
        {**INSIGHT, "tracker_analysis": None},
        options={"profile": "privacy", "trackers": False},
        trackers_from_previous_run=False,
    )
    section = build_trackers(AppFacts(package=PKG, static=static))
    assert section.summary.startswith("trackers not analysed, 3 SDKs")
    assert section.rows[0].text.startswith("trackers not analysed")
    assert not section.rows[0].inspectable
    assert "no trackers" not in section.summary
    assert "0 tracker" not in section.summary
    # trackers on and none found: say so in words
    analysed = _static_with(
        {**INSIGHT, "tracker_analysis": {"detected_trackers": []}},
        options={"profile": "privacy", "trackers": True},
    )
    summary = build_trackers(AppFacts(package=PKG, static=analysed)).summary
    assert summary.startswith("no trackers, 3 SDKs")


def test_trackers_carried_over_say_from_the_previous_run() -> None:
    static = _static_with(
        {
            **INSIGHT,
            "tracker_analysis": {
                "detected_trackers": [{"name": "Google AdMob", "category": "ads"}]
            },
        },
        options={"profile": "privacy", "trackers": False},
        trackers_from_previous_run=True,
    )
    section = build_trackers(AppFacts(package=PKG, static=static))
    assert section.summary.startswith("1 tracker (from the previous run), 3 SDKs")
    assert "Google AdMob" in section.rows[0].text


async def test_lens_activation_re_reads_a_cache_without_insight(fake):
    FakeService.no_insight = {PKG}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        await pilot.press("2")
        await settle(pilot)
        FakeService.no_insight = set()
        before = len(FakeService.calls)
        await pilot.press("1")
        await until(
            pilot,
            lambda: "static_cache" in {m for m, _p, _t in FakeService.calls[before:]},
        )
        await until(pilot, lambda: sections.facts.static.insight is not None)


async def test_a_failed_worker_clears_only_its_own_flags(fake):
    FakeService.fail = {("footprint", PKG)}
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: sections.facts and sections.facts.services)
        await until(pilot, lambda: sections._footprint_inflight is None)
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
        await until(pilot, lambda: not sections._runtime_inflight)


async def test_u_during_a_running_poll_runs_right_after_it(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections) and not sections._runtime_inflight)
        gate = threading.Event()
        FakeService.gates[("appops", PKG)] = gate
        sections._last_runtime = sections.facts.appops_at = 0.0
        sections._poll_tick()  # the 10 s AppOps poll, held at the gate
        assert sections._runtime_inflight
        before = len(FakeService.calls)
        await pilot.press("u")
        await settle(pilot)
        gate.set()
        start = time.monotonic()
        await until(
            pilot,
            lambda: "static_cache" in {m for m, _p, _t in FakeService.calls[before:]},
            timeout=3.0,
        )
        assert time.monotonic() - start < 3.0  # not the 10 s throttle


async def test_footprint_gets_the_known_data_dir(fake):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        assert FakeService.footprint_dirs == [f"/data/user/0/{PKG}"]


async def test_caption_offers_space_only_when_it_does_something(fake, monkeypatch):
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        await until(pilot, lambda: _sections(ms).facts is not None)
        panel = ms.query_one(SpotlightPanel)

        def caption() -> str:
            panel._update_caption()
            return ms._lens_captions["app"][1] or ""

        assert "Space" not in caption()  # running (PID 4242): Space does nothing
        monkeypatch.setattr(SpotlightPanel, "_safe_pid", lambda self: None)
        assert caption().endswith("· Space starts")
        monkeypatch.setattr(SpotlightPanel, "_safe_pid", lambda self: 4242)
        monkeypatch.setattr(SpotlightPanel, "_is_paused", lambda self: True)
        assert caption().endswith("· Space resumes")


@pytest.mark.parametrize("size", [(100, 30), (200, 50)])
async def test_header_does_not_repeat_the_hooks_and_bypass_rows(fake, size):
    """The header line says state, PID and app; hooks and bypass have their
    own rows below it. "experimental" is said once, not "(exp.)" six times.
    """
    app = _app()
    async with app.run_test(size=size) as pilot:
        ms = await boot(app, pilot)
        await until(pilot, lambda: _loaded(_sections(ms)))
        await settle(pilot)
        text = _screen_text(app)
        head = next(line for line in text.splitlines() if "pid 4242" in line)
        assert PKG in head
        assert "hooks:" not in head
        assert "bypass:" not in head
        assert "(exp.)" not in text
        assert text.count("experimental") == 1
        bypass = next(line for line in text.splitlines() if "1 SSL" in line)
        assert "6 Emulator" in bypass  # one line at 100 columns too


async def test_narrow_lens_keeps_bypass_and_actions_on_one_line_each(fake):
    """100x30 with the Inspector open: the lens is ~44 columns wide."""
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        wide = _screen_text(app)
        assert "Shift+K kill" in wide
        assert "1 SSL   2 Root" in wide  # the full toggle row fits
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await settle(pilot)
        assert ms.inspector_is_open
        panel = ms.query_one(SpotlightPanel)
        assert panel.size.width < 60
        text = _screen_text(app)
        assert "b bypass: none" in text
        assert "1 SSL" not in text
        actions = next(line for line in text.splitlines() if "Shift+" in line)
        assert "Shift+ R A P K X" in " ".join(actions.split())
        ms.close_inspector()
        await settle(pilot)
        assert "Shift+K kill" in _screen_text(app)
        # Between the two widths: the keys alone, each with its Shift+.
        await pilot.resize_terminal(80, 30)
        await until(pilot, lambda: 60 <= panel.size.width < 92)
        await settle(pilot)
        assert str(panel.query_one("#act-kill").render()) == "Shift+K"
        assert not panel.query_one("#act-shift").display


async def test_action_row_follows_the_width_without_resize_events(fake, monkeypatch):
    """Under host load the lens came back to full width after the Inspector
    closed but kept the narrow "Shift+ R A P K X" row: its Resize handler
    alone decided the layout. Every layout pass of the screen re-fits it.
    """
    monkeypatch.setattr(SpotlightPanel, "on_resize", lambda self, _event: None)
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        panel = ms.query_one(SpotlightPanel)
        assert "Shift+K kill" in _screen_text(app)
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await until(pilot, lambda: panel._narrow == 2)
        await settle(pilot)
        assert str(panel.query_one("#act-kill").render()) == "K"
        ms.close_inspector()
        await until(pilot, lambda: panel._narrow == 0)
        await settle(pilot)
        assert "Shift+K kill" in _screen_text(app)


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
    # Only FINE_LOCATION (requested, granted, no access) counts: the 5
    # never-used op-only rows stay on the "+N other ops" line
    assert data.summary.endswith("2 used recently, 1 no recorded use")
    noted = [r for r in [*data.rows, *data.hidden_rows] if "no recorded use" in r.text]
    assert len(noted) == 6


async def test_other_ops_row_expands_with_enter_z_folds_and_filter(fake):
    FakeService.extra_ops = _bookkeeping_ops()
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        perms = sections.section("permissions")
        keys = [r.key for r in perms.rows_shown]
        assert keys[-1] == app_lens.MORE_KEY
        assert "op:READ_SMS" not in keys
        assert "+4 other ops (no recorded use)" in perms.rows_shown[-1].text
        perms.focus()
        perms.move_cursor(row=len(keys) - 1)
        await settle(pilot)
        assert "Enter shows them" in str(perms.rows_shown[-1].cells[-1])
        # z folds the section from any row, also from "+N other ops"
        await pilot.press("z")
        await settle(pilot)
        assert perms.folded
        assert not perms.expanded
        await pilot.press("z")
        await settle(pilot)
        assert not perms.folded
        perms.move_cursor(row=len(keys) - 1)
        await settle(pilot)
        await pilot.press("enter")  # Enter on "+N" shows them, no Inspector
        await settle(pilot)
        assert perms.expanded
        assert not perms.folded
        assert not ms.inspector_is_open
        assert "op:READ_SMS" in [r.key for r in perms.rows_shown]
        assert perms.cursor_key() == perms.data.hidden_rows[0].key
        perms.move_cursor(row=len(perms.rows_shown) - 1)
        await settle(pilot)
        assert perms.cursor_key() == app_lens.LESS_KEY
        await pilot.press("enter")  # Enter on "hide" collapses, no Inspector
        await settle(pilot)
        assert not perms.expanded
        assert not ms.inspector_is_open
        # a filter searches the hidden rows too
        sections.set_filter("read_sms")
        await settle(pilot)
        assert [r.key for r in perms.rows_shown] == ["op:READ_SMS"]


def test_compact_permission_cells_combine_grant_and_use() -> None:
    data = build_permissions(
        AppFacts(package=PKG, permissions=_grants(), appops=_appops())
    )
    assert data.compact_columns == ("permission", "grant, use", "last use")
    compact = {
        r.key: " | ".join(c.plain for c in r.compact) for r in data.rows if r.compact
    }
    assert compact["perm:android.permission.CAMERA"] == "CAMERA | yes recent | 5m ago"
    assert (
        compact["perm:android.permission.ACCESS_FINE_LOCATION"]
        == "ACCESS_FINE_LOCATION | yes unused | —"
    )
    assert compact["perm:android.permission.READ_CONTACTS"] == "READ_CONTACTS | no | —"
    assert compact["perm:android.permission.INTERNET"] == "INTERNET | yes | —"
    assert compact["op:READ_CLIPBOARD"] == "READ_CLIPBOARD | op recent | 10s ago"


async def test_narrow_lens_shows_the_compact_permission_columns(fake):
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        perms = sections.section("permissions")
        assert len(perms.columns) == 5
        app.focused.move_cursor(row=0)
        await pilot.press("enter")
        await until(pilot, lambda: perms.compact)
        await settle(pilot)
        labels = [str(c.label) for c in perms.columns.values()]
        assert labels == ["permission", "grant, use", "last use"]
        cam = next(
            i for i, r in enumerate(perms.rows_shown) if r.key.endswith("CAMERA")
        )
        assert [str(c) for c in perms.get_row_at(cam)] == [
            "CAMERA",
            "yes recent",
            "5m ago",
        ]
        # the whole grant / AppOps detail is still in the Inspector
        perms.focus()
        perms.move_cursor(row=cam)
        await pilot.press("enter")
        await settle(pilot)
        assert "AppOps CAMERA" in dict(ms.inspector_content.tabs[0][1])
        ms.close_inspector()
        await until(pilot, lambda: not perms.compact)
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
    fp.de_kb = 1024  # N6-V2: DE storage is in the summary too
    summary = app_lens.build_data(AppFacts(package=PKG, footprint=fp)).summary
    assert summary == "private 12.7 MB · DE 1.0 MB · external —"
    fp.de_kb = None
    external = next(r for r in data.rows if r.key == "external")
    assert external.text.startswith("external —")
    fp.external_reason = "permission denied"
    assert app_lens.build_data(AppFacts(package=PKG, footprint=fp)).summary.endswith(
        "external ?"
    )


async def test_quit_hook_stops_device_work_and_no_new_work_starts(fake, monkeypatch):
    """No adb work after a quit / unmount; a running worker stops at its
    next call (TUI exit reported an untracked "ADB Command").
    """
    from sandroid.tui.controllers import quit_controller as qc

    killed: list[str | None] = []
    monkeypatch.setattr(app_lens, "kill_app_lens_adb", killed.append)
    gate = threading.Event()
    FakeService.gates[("details", PKG)] = gate
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(
            pilot, lambda: ("details", PKG) in {c[:2] for c in FakeService.calls}
        )
        assert sections.shutdown in [fn for _n, fn in qc._SHUTDOWN_HOOKS]
        qc.run_shutdown_hooks(timeout=1.0)  # what force_exit does first
        assert killed == [PKG]  # a worker was in flight
        before = len(FakeService.calls)
        gate.set()  # the load goes on: its next call is refused
        await until(pilot, lambda: sections._inflight_workers == 0)
        await until(pilot, lambda: not sections._runtime_inflight)
        sections.refresh_runtime(static=True, explicit=True)
        await settle(pilot)
        assert FakeService.calls[before:] == []
    # unmount unregistered the hook
    assert sections.shutdown not in [fn for _n, fn in qc._SHUTDOWN_HOOKS]


def test_kill_app_lens_adb_only_kills_its_own_commands(monkeypatch) -> None:
    import types

    class Proc:
        def __init__(self, name, cmd):
            self._name, self._cmd, self.killed = name, cmd, False

        def name(self):
            return self._name

        def cmdline(self):
            return self._cmd.split()

        def kill(self):
            self.killed = True

    procs = {
        "du": Proc("adb", "adb -s e shell echo @@SANDROID_SEP@@ du -sk /data/x"),
        "pull": Proc("adb", "adb pull /data/app/b.apk /tmp/sandroid_app_lens_1/b"),
        "dumpsys": Proc("adb", f"adb -s e shell dumpsys package {PKG}"),
        "server": Proc("adb", "adb -L tcp:5037 fork-server server --reply-fd 4"),
        "other": Proc("adb", "adb -s e shell screencap -p"),
        "fritap": Proc("python", f"fritap {PKG}"),
    }
    from sandroid.core import background_tracker

    monkeypatch.setitem(__import__("sys").modules, "psutil", types.SimpleNamespace())
    monkeypatch.setattr(
        background_tracker, "child_processes", lambda: list(procs.values())
    )
    assert app_lens.kill_app_lens_adb(PKG) == 3
    assert {k for k, p in procs.items() if p.killed} == {"du", "pull", "dumpsys"}


def test_force_exit_runs_the_shutdown_hooks(monkeypatch) -> None:
    import types

    from sandroid.tui.controllers import quit_controller as qc

    calls: list[str] = []
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: calls.append("net"))
    monkeypatch.setattr(qc, "_SHUTDOWN_HOOKS", [("lens", lambda: calls.append("hook"))])
    monkeypatch.setattr(
        qc.QuitController, "_stop_frida_sessions", staticmethod(lambda: None)
    )
    monkeypatch.setattr(qc.QuitController, "_cleanup_rest", staticmethod(lambda: None))
    from sandroid.core import ui_request_bus

    bus = types.SimpleNamespace(shutdown=lambda: calls.append("bus"))
    monkeypatch.setattr(ui_request_bus.UIRequestBus, "get", staticmethod(lambda: bus))

    class _Tasks:
        def stop_all(self):
            calls.append("tasks")

    from sandroid import services

    monkeypatch.setattr(services, "get_task_service", _Tasks)
    qc.QuitController().force_exit()
    assert calls == ["bus", "net", "hook", "tasks"]


async def test_hooks_list_keys_run_through_the_main_screen(fake, monkeypatch):
    """Shift+H from a section, { } * from MainScreen's Inspector keys."""
    from sandroid.services import get_spotlight_service
    from sandroid.tui.widgets import spotlight_panel as sp

    apps = [
        sp.AppHooks("org.mozilla.firefox", 88, ("ssl", "root"), (), 100.0),
        sp.AppHooks("org.third.app", 99, (), ("friTap",), 200.0),
        sp.AppHooks(PKG, 4242, ("ssl",), (), 300.0),
    ]
    monkeypatch.setattr(sp, "collect_app_hooks", lambda: list(apps))
    app = _app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        sections = _sections(ms)
        await until(pilot, lambda: _loaded(sections))
        await settle(pilot)
        assert isinstance(app.focused, LensSection)
        await pilot.press("H")
        await settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.key == sp.HOOKS_KEY
        panel = ms.query_one(SpotlightPanel)
        assert panel._hooks_pick == "org.mozilla.firefox"
        await pilot.press("right_curly_bracket")
        await settle(pilot)
        assert panel._hooks_pick == "org.third.app"
        await pilot.press("asterisk")
        await settle(pilot)
        assert get_spotlight_service().get_effective_package() == "org.third.app"


def test_static_cache_row_names_the_security_findings() -> None:
    """N6-V6: finished OWASP findings appeared nowhere in the TUI."""
    from sandroid.tui.widgets.app_lens import _security_text

    meta = {"insight": {"security_findings": {"total": 3, "by_severity": {"high": 3}}}}
    assert _security_text(meta) == "3 security findings (3 high)"
    assert _security_text({"insight": {"security_findings": None}}) is None
    assert _security_text({}) is None
