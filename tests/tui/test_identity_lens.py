"""Identity lens (lens 6) and the header privacy indicator.

The identity and privacy scan services are fakes (the getters are patched);
the profile itself is a real generated one, so the lens's library calls,
``describe`` and ``validate`` run for real. No device is touched.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from pilot_helpers import boot, settle, until
from textual.widgets.data_table import ColumnKey

from sandroid.services import identity as identity_mod
from sandroid.services import privacy_scan as privacy_mod
from sandroid.services.identity import (
    IdentityPlan,
    IdentityService,
    Step,
    generate_profile,
)
from sandroid.services.privacy_scan import HitRecord, PrivacySummary
from sandroid.tui.widgets import identity_lens as il
from sandroid.tui.widgets.identity_lens import (
    IdentityLens,
    ValueEditModal,
    describe_transform,
    part_words,
    row_id_for_marker,
)

SIZE = (160, 45)
SERIAL = "emulator-5580"
PKG = "de.fittrack.pro"
FP = "fp-1"
GLYPHS = "■▲◆●✓✗⚑⌁"


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeIdentity:
    """The identity service surface the lens and the app use."""

    def __init__(self) -> None:
        self.profile = generate_profile("de", profile_id="mara-de")
        self.profile.revision = 3
        self.cfg = SimpleNamespace(profile="mara-de", mode="profile", restart="ask")
        self.real = IdentityService()
        self.listeners: list = []
        self.saves = 0
        self.regenerated: list[str] = []
        self.applied: list[tuple] = []
        self.verified: list[str] = []
        self.disruptive = False
        self.block: threading.Event | None = None
        #: What ``last_apply`` answers (the service keeps every apply/verify).
        self.times: tuple[float, float] | None = None
        self.clock = 1_700_000_000.0
        self.status_over: dict[str, str] = {
            "gaid": "verified",
            "device_name": "applied",
            "android_id": "failed",
        }

    # library
    def list_profiles(self):
        return [
            SimpleNamespace(
                id=self.profile.id,
                name=self.profile.name,
                revision=self.profile.revision,
                error="",
            )
        ]

    def load(self, profile_id):
        if profile_id != self.profile.id:
            raise identity_mod.ProfileError(f"no profile {profile_id!r}")
        return self.profile

    def save(self, profile):
        self.saves += 1
        profile.revision += 1
        self.profile = profile
        return profile

    def regenerate(self, profile_id):
        self.regenerated.append(profile_id)
        return self.save(self.profile)

    def describe(self, profile):
        return self.real.describe(profile)

    def validate(self, profile):
        return self.real.validate(profile)

    def config(self):
        return self.cfg

    def set_active(self, profile_id=None, mode=None, restart=None):
        if profile_id is not None:
            self.cfg.profile = profile_id
        if mode is not None:
            self.cfg.mode = mode

    def active_markers(self, *, load=True):
        return None

    def install_pre_spawn_hook(self):
        return False

    # statuses
    def add_status_listener(self, cb):
        self.listeners.append(cb)

    def remove_status_listener(self, cb):
        if cb in self.listeners:
            self.listeners.remove(cb)

    def _infos(self, over=None):
        infos = {i.id: i for i in self.real.describe(self.profile)}
        for vid, status in (over or self.status_over).items():
            if vid in infos:
                infos[vid].status = status
                infos[vid].current = "on device"
        infos["android_id"].reason = "adbd is not root"
        return infos

    def statuses(self):
        return list(self._infos().values())

    def _plan(self, over=None):
        steps = []
        if self.disruptive:
            steps.append(Step("locale", "framework", "de-DE"))
        return IdentityPlan(
            SERIAL, (PKG,), self.profile.id, FP, steps, self._infos(over)
        )

    # device
    def plan(self, serial, package=None):
        if self.block is not None:
            self.block.wait(10)
        return self._plan()

    def last_apply(self, serial, fp=None):
        return self.times

    def apply(self, serial, package=None, allow_restart=None):
        self.applied.append((serial, package, allow_restart))
        self.times = (self.clock, self.clock)
        over = dict.fromkeys(self.status_over, "verified")
        return self._plan(over)

    def verify(self, serial):
        self.verified.append(serial)
        self.times = ((self.times or (0.0, 0.0))[0], self.clock)
        return self._plan()


def _hit(marker_id, direction="sent", *, t=0.0, **kw) -> HitRecord:
    source = kw.pop("source", None) or {
        "type": "flow",
        "flow_id": kw.pop("flow_id", "f1"),
        "host": kw.pop("host", "t.appsflyer.com"),
        "method": "POST",
        "path": "/api/v1/track",
    }
    recipient = kw.pop("recipient", None)
    if recipient is None and source.get("type") == "flow":
        recipient = {"label": source["host"], "party": "third"}
    return HitRecord(
        v=1,
        at=time.time() + t,
        t=time.time() + t,
        fp=FP,
        engine=1,
        marker_id=marker_id,
        label=marker_id,
        tag=marker_id,
        kind="uuid",
        transform=kw.pop("transform", "value"),
        confidence=kw.pop("confidence", "high"),
        part=kw.pop("part", "req.body"),
        direction=direction,
        count=1,
        offsets=(0,),
        snippet=("adid=", "3b9f00aa", "&x=1"),
        source=source,
        recipient=recipient,
        tl_seq=kw.pop("tl_seq", None),
    )


def _hits() -> list[HitRecord]:
    return [
        _hit("gaid", host="t.appsflyer.com", flow_id="f1", t=1),
        _hit(
            "gaid",
            host="graph.facebook.com",
            flow_id="f2",
            t=2,
            transform="sha256(lower(value))",
        ),
        _hit("gaid", host="api.fittrack.de", flow_id="f3", t=3),
        _hit(
            "device_name",
            "stored",
            source={
                "type": "file",
                "device_path": f"/data/data/{PKG}/shared_prefs/a.xml",
                "version": "v2_1",
                "member": "a.xml",
            },
            t=4,
        ),
        _hit("phone_number", host="t.appsflyer.com", flow_id="f4", t=5),
        _hit(
            "phone_number",
            "stored",
            source={
                "type": "file",
                "device_path": f"/data/data/{PKG}/databases/x.db",
                "version": "v1_1",
                "member": "x.db",
            },
            t=6,
        ),
        _hit(
            "gps.latitude",
            source={"type": "other"},
            recipient={"label": "?", "party": "unknown"},
            tl_seq=77,
            t=7,
        ),
    ]


class FakePrivacy:
    def __init__(self) -> None:
        self.records: list[HitRecord] = []
        self.listeners: list = []
        self.active = True
        self.found = 0
        self.total = 12

    def summary(self):
        return PrivacySummary(
            active=self.active,
            fingerprint=FP if self.active else None,
            values_total=self.total,
            values_found=self.found,
            hits_total=len(self.records),
            last_hit_at=None,
        )

    def hits(self, *, marker_id=None):
        return list(self.records)

    def add_listener(self, cb):
        self.listeners.append(cb)

    def remove_listener(self, cb):
        if cb in self.listeners:
            self.listeners.remove(cb)

    def attach_identity(self):
        return True


class FakeSpotlight:
    def __init__(self, pid=4242) -> None:
        self.pid = pid

    def get_effective_package(self):
        return PKG

    def get_pid(self):
        return self.pid


@pytest.fixture
def fakes(monkeypatch):
    ident = FakeIdentity()
    privacy = FakePrivacy()
    spot = FakeSpotlight()
    monkeypatch.setattr(identity_mod, "get_identity_service", lambda: ident)
    monkeypatch.setattr(privacy_mod, "get_privacy_scan_service", lambda: privacy)
    monkeypatch.setattr(il, "_target_serial", lambda: SERIAL)
    monkeypatch.setattr(il, "_spotlight", lambda: spot)
    return SimpleNamespace(ident=ident, privacy=privacy, spot=spot)


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _messages(app) -> list[str]:
    return [n.message for n in app._notifications]


def _region_text(app, widget) -> str:
    strips = app.screen._compositor.render_strips()
    r = widget.region
    lines = []
    for y in range(r.y, r.y + r.height):
        line = "".join(seg.text for seg in strips[y])
        lines.append(line[r.x : r.x + r.width])
    return "\n".join(lines)


async def _open_lens(app, pilot) -> IdentityLens:
    ms = await boot(app, pilot)
    await pilot.press("6")
    await settle(pilot)
    assert ms.active_lens == "identity"
    lens = ms.lens_widget()
    assert isinstance(lens, IdentityLens)
    await until(pilot, lambda: lens.rows)
    return lens


def _cell(lens, key, col) -> str:
    index = [k for k, _ in il.COLUMNS].index(col)
    return lens.table.get_row(key)[index].plain


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------


def test_words_for_markers_transforms_and_parts() -> None:
    assert row_id_for_marker("android_id@com.x") == "android_id"
    assert row_id_for_marker("gps.latitude") == "gps"
    assert row_id_for_marker("contacts.0.name") == "contacts"
    assert describe_transform("value") == "as is"
    assert describe_transform("sha256(lower(value))") == (
        "sha256 of the lower-case value"
    )
    assert describe_transform("round(value, 4)") == "rounded to 4 decimals"
    assert describe_transform("base64(value)") == "base64 of the value"
    assert part_words("req.body") == "request body"
    assert part_words("resp.header:Set-Cookie") == "response header Set-Cookie"
    assert part_words("url") == "in the URL"


# --------------------------------------------------------------------------
# lens
# --------------------------------------------------------------------------


async def test_key_6_shows_the_table_with_status_words_and_no_glyphs(fakes) -> None:
    fakes.privacy.records = _hits()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        ms = app.screen
        assert ms.query_one("#lens-tab-identity").has_class("-active")
        assert _cell(lens, "gaid", "status") == "verified"
        assert _cell(lens, "device_name", "status") == "applied"
        assert _cell(lens, "android_id", "status") == "failed"
        assert _cell(lens, "imei", "status") == "hook only"
        assert _cell(lens, "imei", "via") == "hook"
        assert _cell(lens, "locale", "restart") == "framework"
        # Sections in order, as rows.
        keys = lens._row_keys
        sections = [k for k in keys if k.startswith(il.SECTION_PREFIX)]
        assert [s[len(il.SECTION_PREFIX) :] for s in sections] == list(il.SECTIONS)
        # The badge counts failed values (plain number).
        assert ms.query_one("#lens-bar").badge("identity") == "1"
        # Caption: name, revision, mode; plain words, no separator glyphs.
        host = ms.query_one("#lens-host")
        assert "rev 3, mode on" in host.border_title
        assert host.border_title.startswith("Identity  ")
        assert "·" not in host.border_title
        assert "·" not in str(host.border_subtitle or "")
        await settle(pilot)
        text = _region_text(app, ms.query_one("#lens-host"))
        assert "verified" in text
        assert "hook only" in text
        assert not set(GLYPHS) & set(text), text


async def test_found_column_reflects_hits_and_tints_rows(fakes) -> None:
    fakes.privacy.records = _hits()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        assert _cell(lens, "gaid", "found") == "3 recipients"
        assert _cell(lens, "device_name", "found") == "stored on device"
        assert _cell(lens, "phone_number", "found") == "sent and stored"
        assert _cell(lens, "timezone", "found") == "not seen"
        assert {"gaid", "device_name", "phone_number", "gps"} <= lens.table.found_keys
        # A live hit arrives on the scan thread: the cell follows, the
        # cursor stays where it was.
        lens.select_value("timezone")
        fakes.privacy.records.append(
            _hit("timezone", host="x.example", flow_id="f9", t=9)
        )
        il.REFRESH_MIN_S = 0.0
        try:
            # Like the real service: every registered listener hears the hit
            # (the Network lens's privacy feed registers one too).
            def _notify() -> None:
                for cb in list(fakes.privacy.listeners):
                    cb(None)

            threading.Thread(target=_notify).start()
            await until(
                pilot, lambda: _cell(lens, "timezone", "found") == "1 recipient"
            )
        finally:
            il.REFRESH_MIN_S = 1.0
        assert lens.table.current_key() == "timezone"


async def test_columns_widen_when_a_live_hit_arrives(fakes) -> None:
    # The table is first built with every Found cell "not seen": a later,
    # longer word must widen the column, not be cut to "sent and".
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        assert _cell(lens, "gaid", "found") == "not seen"
        fakes.privacy.records = _hits()
        il.REFRESH_MIN_S = 0.0
        try:
            for cb in list(fakes.privacy.listeners):
                cb(None)
            await until(
                pilot, lambda: _cell(lens, "phone_number", "found") == "sent and stored"
            )
        finally:
            il.REFRESH_MIN_S = 1.0
        found = lens.table.columns[ColumnKey("found")]
        assert found.content_width >= len("sent and stored")


async def test_inspector_found_tab_selection_and_jump(fakes, monkeypatch) -> None:
    from sandroid.tui.widgets.files_panel import FilesPanel
    from sandroid.tui.widgets.network_panel import NetworkPanel
    from sandroid.tui.widgets.timeline_lens import TimelineLens

    fakes.privacy.records = _hits()
    flows, files, seqs = [], [], []
    monkeypatch.setattr(
        NetworkPanel, "reveal_flow", lambda self, fid, record=None: flows.append(fid)
    )
    monkeypatch.setattr(
        FilesPanel,
        "reveal",
        lambda self, path, version=None: files.append((path, version)) or True,
    )
    monkeypatch.setattr(
        TimelineLens, "_select_seq", lambda self, seq, quiet=False: seqs.append(seq)
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        ms = app.screen
        lens.select_value("gaid")
        await pilot.press("enter")
        await until(pilot, lambda: ms.inspector_is_open)
        content = ms.inspector_content
        assert content.key == "identity:gaid"
        assert [t[0] for t in content.tabs] == ["Found", "Value"]
        body = "\n".join(s[1].plain for s in content.tabs[0][1])
        assert "t.appsflyer.com" in body
        assert "graph.facebook.com" in body
        assert "third party" in body
        assert "sha256 of the lower-case value" in body
        assert "POST t.appsflyer.com/api/v1/track, request body" in body
        assert "·" not in body
        assert "·" not in content.subtitle
        assert lens._hit_sel.get("gaid", 0) == 0
        await pilot.press("right_curly_bracket")
        await settle(pilot)
        assert lens._hit_sel["gaid"] == 1
        second = il.flat_hits(lens.selected_row().found.hits)[1]
        # The Inspector shows the new selection (reverse/bold line).
        sel_line = f"{second.source['host']}{second.source['path']}"
        spans = [
            (t.plain, s)
            for _h, t in ms.inspector_content.tabs[0][1]
            for s in t.spans
            if "reverse" in str(s.style)
        ]
        assert any(sel_line in plain[s.start : s.end] for plain, s in spans)
        await pilot.press("J")
        await settle(pilot)
        assert flows == [second.source["flow_id"]]
        assert ms.active_lens == "network"
        # A stored hit jumps to the Files lens.
        await pilot.press("6")
        await settle(pilot)
        lens.select_value("device_name")
        await pilot.press("J")
        await settle(pilot)
        assert files == [(f"/data/data/{PKG}/shared_prefs/a.xml", "v2_1")]
        assert ms.active_lens == "files"
        # Neither a flow nor a file: the timeline line.
        await pilot.press("6")
        await settle(pilot)
        lens.select_value("gps")
        await pilot.press("J")
        await until(pilot, lambda: seqs)
        assert seqs[0] == 77
        assert ms.active_lens == "timeline"


async def test_edit_validates_inline_and_save_bumps_the_revision(fakes) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        lens.select_value("gaid")
        await pilot.press("e")
        await until(pilot, lambda: isinstance(app.screen, ValueEditModal))
        modal = app.screen
        from textual.widgets import Input, Label

        field = modal.query_one("#input-field", Input)
        field.value = "not-a-uuid"
        await pilot.press("enter")
        await settle(pilot)
        assert app.screen is modal
        assert "UUID" in str(modal.query_one("#edit-error", Label).render())
        assert fakes.ident.saves == 0
        field.value = "3b9f00aa-1111-4222-8333-444455556666"
        await pilot.press("enter")
        await until(pilot, lambda: not isinstance(app.screen, ValueEditModal))
        assert fakes.ident.saves == 1
        assert lens.profile.revision == 4
        assert fakes.ident.profile.values["gaid"].value == (
            "3b9f00aa-1111-4222-8333-444455556666"
        )
        await until(pilot, lambda: _cell(lens, "gaid", "profile").startswith("3b9f"))
        assert "rev 4" in app.screen.query_one("#lens-host").border_title


async def test_regenerate_asks_first(fakes) -> None:
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _open_lens(app, pilot)
        await pilot.press("R")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert fakes.ident.regenerated == []
        await pilot.press("R")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        app.screen.dismiss(True)
        await until(pilot, lambda: fakes.ident.regenerated == ["mara-de"])


async def test_apply_runs_in_a_worker_and_asks_before_a_restart(fakes) -> None:
    from sandroid.tui.modals.selection_modal import SelectionModal

    fakes.ident.disruptive = True
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        ui_thread = threading.get_ident()
        threads = []
        real_plan = fakes.ident.plan

        def plan(serial, package=None):
            threads.append(threading.get_ident())
            return real_plan(serial, package)

        fakes.ident.plan = plan
        await pilot.press("space")
        await until(pilot, lambda: isinstance(app.screen, SelectionModal))
        # The explanation wraps inside the dialog instead of being cut off.
        message = app.screen.query_one(".modal-message")
        await settle(pilot)
        assert message.region.height > 1
        assert (
            message.region.right
            <= app.screen.query_one(".modal-container").region.right
        )
        assert threads
        assert threads[0] != ui_thread
        assert fakes.ident.applied == []
        await pilot.press("enter")  # "Restart Android & apply"
        await until(pilot, lambda: fakes.ident.applied)
        assert fakes.ident.applied == [(SERIAL, PKG, True)]
        await until(pilot, lambda: _cell(lens, "android_id", "status") == "verified")
        # The app ran during the apply: the notice asks for a restart.
        notice = lens.query_one("#identity-notice")
        await until(pilot, lambda: notice.has_class("-shown"))
        assert "Shift+R" in str(notice.render())
        fakes.spot.pid = 5555  # restarted
        await until(pilot, lambda: not notice.has_class("-shown"))
        # Esc on the question cancels.
        await pilot.press("space")
        await until(pilot, lambda: isinstance(app.screen, SelectionModal))
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, SelectionModal))
        assert len(fakes.ident.applied) == 1
        # Not disruptive: no question.
        fakes.ident.disruptive = False
        await pilot.press("space")
        await until(pilot, lambda: len(fakes.ident.applied) == 2)
        assert fakes.ident.applied[1] == (SERIAL, PKG, None)


async def test_header_privacy_indicator_states(fakes) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        header = ms.query_one("#shell-header")
        piece = header.query_one("#privacy-note")
        fakes.privacy.active = False
        header.refresh_privacy_state()
        assert header.privacy_text is None
        assert not piece.has_class("-on")
        fakes.privacy.active = True
        header.refresh_privacy_state()
        assert header.privacy_text == "PRIVACY mara-de"
        assert piece.has_class("-on")
        assert not piece.has_class("-found")
        fakes.privacy.found = 3
        header.refresh_privacy_state()
        assert header.privacy_text == "PRIVACY 3/12 found"
        assert piece.has_class("-found")
        assert not set(GLYPHS) & set(header.privacy_text)
        # While an apply runs.
        fakes.ident.block = threading.Event()
        await pilot.press("6")
        await settle(pilot)
        await pilot.press("space")
        await until(pilot, lambda: header.privacy_text == "PRIVACY applying")
        fakes.ident.block.set()
        await until(pilot, lambda: header.privacy_text == "PRIVACY 3/12 found")
        # A click opens the Identity lens.
        await pilot.press("1")
        await settle(pilot)
        await pilot.click("#privacy-note")
        await settle(pilot)
        assert ms.active_lens == "identity"


async def test_empty_state_explains_and_offers_P(fakes) -> None:
    fakes.ident.cfg.profile = ""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("6")
        await settle(pilot)
        lens = ms.lens_widget()
        await until(pilot, lambda: not lens._loading)
        await settle(pilot)
        assert lens.has_class("-empty")
        text = _region_text(app, ms.query_one("#lens-host"))
        assert "No identity profile yet" in text
        assert "P to" in text


async def test_help_lists_the_identity_lens_keys_first(fakes) -> None:
    from textual.widgets import OptionList

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _open_lens(app, pilot)
        await pilot.press("question_mark")
        await settle(pilot)
        options = app.screen.query_one("#kb-list", OptionList)
        rows = [
            str(options.get_option_at_index(i).prompt)
            for i in range(options.option_count)
        ]
        assert "Identity lens" in rows[0]
        text = "\n".join(rows)
        for words in ("Apply", "Regenerate", "Jump to the selected hit"):
            assert words in text
        await pilot.press("escape")


async def test_reload_reads_the_library_off_the_ui_thread(fakes) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        ui_thread = threading.get_ident()
        threads: list[int] = []
        gate = threading.Event()
        real_load = fakes.ident.load

        def load(profile_id):
            threads.append(threading.get_ident())
            gate.wait(10)
            return real_load(profile_id)

        fakes.ident.load = load
        try:
            await pilot.press("1")
            await settle(pilot)
            await pilot.press("6")
            await until(pilot, lambda: threads)
            assert threads[0] != ui_thread
            # The read blocks; the lens keeps its rows and the UI answers.
            assert lens._loading
            assert lens.rows
            lens.select_value("timezone")
            await pilot.press("down")
            await settle(pilot)
            assert lens.table.current_key() != "timezone"
        finally:
            gate.set()
        await until(pilot, lambda: not lens._loading)
        assert lens.profile is fakes.ident.profile


async def test_statuses_of_another_profile_are_ignored(fakes) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)
        assert _cell(lens, "timezone", "status") == "pending"
        il.REFRESH_MIN_S = 0.0
        try:
            for owner, word in (("other-profile", "pending"), ("mara-de", "failed")):
                infos = fakes.ident._infos({"timezone": "failed"})
                for info in infos.values():
                    info.profile_id = owner
                threading.Thread(
                    target=fakes.ident.listeners[0], args=(list(infos.values()),)
                ).start()
                await until(
                    pilot, lambda o=owner: lens._statuses["timezone"].profile_id == o
                )
                await until(
                    pilot, lambda w=word: _cell(lens, "timezone", "status") == w
                )
        finally:
            il.REFRESH_MIN_S = 1.0


async def test_caption_uses_the_service_times(fakes) -> None:
    applied_at = fakes.ident.clock
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)

        def info() -> str:
            return lens.screen._lens_captions["identity"][1] or ""

        await until(pilot, lambda: "not applied yet" in info())
        await pilot.press("space")
        stamp = f"{il.datetime.fromtimestamp(applied_at):%H:%M:%S}"
        await until(pilot, lambda: f"applied {stamp}" in info())
        assert f"verified {stamp}" in info()
        fakes.ident.clock += 3600
        await pilot.press("v")
        later = f"{il.datetime.fromtimestamp(applied_at + 3600):%H:%M:%S}"
        await until(pilot, lambda: f"verified {later}" in info())
        assert f"applied {stamp}" in info()
        assert not hasattr(lens, "applied_at")  # the service is the only source


async def test_caption_shows_an_apply_made_outside_the_lens(fakes) -> None:
    """An apply before an app start, or one an earlier TUI process left in
    the device record: the service's times reach the footer.
    """
    real = fakes.ident.real
    real._hydrated.add(SERIAL)  # no background device read
    fakes.ident.last_apply = real.last_apply
    fp = identity_mod.fingerprint(fakes.ident.profile)
    applied_at = 1_700_000_000.0
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _open_lens(app, pilot)

        def info() -> str:
            return lens.screen._lens_captions["identity"][1] or ""

        await until(pilot, lambda: "not applied yet" in info())
        # Another profile's apply does not count.
        real._applied[SERIAL] = identity_mod._Applied(
            fingerprint="other", applied_at=applied_at
        )
        il.REFRESH_MIN_S = 0.0
        try:
            threading.Thread(
                target=fakes.ident.listeners[0], args=(fakes.ident.statuses(),)
            ).start()
            await settle(pilot)
            assert "not applied yet" in info()
            # The service applied this profile (the lens did nothing).
            real._applied[SERIAL] = identity_mod._Applied(
                fingerprint=fp, applied_at=applied_at, verified_at=applied_at
            )
            threading.Thread(
                target=fakes.ident.listeners[0], args=(fakes.ident.statuses(),)
            ).start()
            stamp = f"{il.datetime.fromtimestamp(applied_at):%H:%M:%S}"
            await until(pilot, lambda: f"applied {stamp}" in info())
        finally:
            il.REFRESH_MIN_S = 1.0
        assert f"verified {stamp}" in info()
        assert "not applied" not in info()
