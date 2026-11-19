"""Unit tests for sandroid.ai.tool_permissions (rules, modes, migration, broker).

Every store is backed by a file under ``tmp_path`` -- never the real
``~/.config/sandroid`` (the test session also points ``XDG_CONFIG_HOME`` at a
temp dir).
"""

import os
import threading
import time
import tomllib

import pytest

import sandroid.ai.tool_permissions as tp
from sandroid.ai.tool_permissions import (
    ApprovalBroker,
    Decision,
    PermissionRule,
    RuleSyntaxError,
    ToolPermissionStore,
    describe_rule,
    get_approval_broker,
    get_tool_permission_store,
    resolve_tool_policy,
    suggest_rule,
)
from sandroid.ai.tools.registry import RiskTier

R, C, RO, NX = (
    RiskTier.REVERSIBLE,
    RiskTier.CONSEQUENTIAL,
    RiskTier.READ_ONLY,
    RiskTier.NOT_EXPOSED,
)


@pytest.fixture(autouse=True)
def _fresh_singletons():
    tp.reset_for_tests()
    yield
    tp.reset_for_tests()


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def _store(tmp_path, text=None, arg_dep=()):
    path = tmp_path / "ai_tool_permissions.toml"
    if text is not None:
        _write(path, text)
    return ToolPermissionStore(path=path, arg_dependent=lambda n: n in arg_dep)


def _data(store):
    return tomllib.loads(store.path.read_text(encoding="utf-8"))


# -- rule parsing -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "tool", "constraints"),
    [
        ("launch_app", "launch_app", ()),
        ("  launch_app  ", "launch_app", ()),
        ("mcp:srv:do_thing", "mcp:srv:do_thing", ()),
        (
            "kill_process(package=com.example.*)",
            "kill_process",
            (("package", "com.example.*"),),
        ),
        ("t( a = x , b=y )", "t", (("a", "x"), ("b", "y"))),
        ('t(a="x, (y)=z")', "t", (("a", "x, (y)=z"),)),
        ('t(a="q\\"\\\\")', "t", (("a", 'q"\\'),)),
    ],
)
def test_rule_parse(text, tool, constraints):
    rule = PermissionRule.parse(text)
    assert rule.tool == tool
    assert rule.constraints == constraints
    # canonical form round-trips
    assert PermissionRule.parse(str(rule)) == rule


@pytest.mark.parametrize(
    "text",
    [
        "",
        "(a=b)",
        "t(",
        "t()",
        "t(a)",
        "t(a=)",
        't(a="x)',
        "t(a=b,a=c)",
        "t x",
        "t(a=b))",
    ],
)
def test_rule_parse_rejects_garbage(text):
    with pytest.raises(RuleSyntaxError):
        PermissionRule.parse(text)


def test_rule_matching_globs_and_types():
    rule = PermissionRule.parse("t(package=com.example.*, force=true, n=4?)")
    assert rule.matches("t", {"package": "com.example.app", "force": True, "n": 42})
    assert not rule.matches("t", {"package": "com.other", "force": True, "n": 42})
    assert not rule.matches("t", {"package": "com.example.a", "force": False, "n": 42})
    assert not rule.matches(
        "other", {"package": "com.example.a", "force": True, "n": 42}
    )
    # case-sensitive on every platform
    assert not PermissionRule.parse("t(p=COM.*)").matches("t", {"p": "com.x"})


@pytest.mark.parametrize("missing", [{}, {"package": None}, {"package": ""}])
def test_constrained_rule_never_matches_a_missing_argument(missing):
    assert not PermissionRule.parse("t(package=*)").matches("t", missing)


def test_bare_rule_matches_any_arguments():
    assert PermissionRule.parse("t").matches("t", {"x": 1})
    assert PermissionRule.parse("t").matches("t", None)


def test_suggest_rule():
    assert suggest_rule("launch_app", {"package": "a"}) == "launch_app"
    # argument-dependent: names the key argument, glob-escaped
    assert (
        suggest_rule("kill_process", {"package": "a.b*"}, permission_key="package")
        == "kill_process(package=a.b[*])"
    )
    rule = PermissionRule.parse(
        suggest_rule("kill_process", {"package": "a.b*"}, permission_key="package")
    )
    assert rule.matches("kill_process", {"package": "a.b*"})
    assert not rule.matches("kill_process", {"package": "a.bc"})
    # missing key argument or no key -> nothing can be remembered
    assert suggest_rule("kill_process", {}, permission_key="package") is None
    assert suggest_rule("clear", {}, can_remember_choice=False) is None
    # values needing quotes round-trip
    text = suggest_rule("push_path", {"path": "/a,b (c)"}, permission_key="path")
    assert PermissionRule.parse(text).matches("push_path", {"path": "/a,b (c)"})


def test_describe_rule():
    assert describe_rule("install_apk") == "Install APK"
    assert describe_rule("kill_process(package=com.x)") == (
        "Kill Process with package = com.x"
    )
    assert describe_rule("kill_process(package=com.*)") == (
        "Kill Process with package matching com.*"
    )
    assert describe_rule("k(p=a[*])") == "K with p = a*"
    assert describe_rule("not valid (") == "not valid ("


# -- resolution order -----------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "tool", "risk", "args", "outcome", "reason"),
    [
        # 1. NOT_EXPOSED beats everything, even allow_all + allow rule
        ('mode="allow_all"\nallow=["t"]', "t", NX, {}, "deny", "not_exposed"),
        # 2. deny beats allow_all and allow and READ_ONLY
        ('mode="allow_all"\nallow=["t"]\ndeny=["t"]', "t", C, {}, "deny", "deny_rule"),
        ('deny=["t"]', "t", RO, {}, "deny", "deny_rule"),
        ('deny=["t(p=a*)"]', "t", RO, {"p": "abc"}, "deny", "deny_rule"),
        ('deny=["t(p=a*)"]', "t", RO, {"p": "xyz"}, "allow", "read_only"),
        # 3. allow_all
        ('mode="allow_all"', "t", C, {}, "allow", "allow_all"),
        # 4. allow rule
        ('allow=["t"]', "t", C, {}, "allow", "allow_rule"),
        ('allow=["t(p=a*)"]', "t", C, {"p": "abc"}, "allow", "allow_rule"),
        ('allow=["t(p=a*)"]', "t", C, {"p": "zzz"}, "ask", "ask"),
        # 5. READ_ONLY
        ("", "t", RO, {}, "allow", "read_only"),
        # 6. ask
        ("", "t", R, {}, "ask", "ask"),
        ("", "t", C, {}, "ask", "ask"),
        ('allow=["other"]', "t", C, {}, "ask", "ask"),
    ],
)
def test_resolution_order(tmp_path, file, tool, risk, args, outcome, reason):
    store = _store(tmp_path, file)
    res = store.resolve(tool, risk, args)
    assert (res.outcome, res.reason) == (outcome, reason)


def test_ask_carries_suggested_rule(tmp_path):
    store = _store(tmp_path)
    assert store.resolve("t", C, {}).suggested_rule == "t"
    res = store.resolve("k", C, {"package": "com.x"}, permission_key="package")
    assert res.suggested_rule == "k(package=com.x)"


def test_bare_allow_rule_ignored_for_argument_dependent_tools(tmp_path, caplog):
    store = _store(tmp_path, 'allow=["k", "k(package=com.x)"]', arg_dep={"k"})
    assert any("ignored" in w for w in store.warnings())
    # via permission_key
    assert (
        store.resolve("k", C, {"package": "other"}, permission_key="package").outcome
        == "ask"
    )
    # via can_remember_choice=False
    assert (
        store.resolve("k", C, {"package": "other"}, can_remember_choice=False).outcome
        == "ask"
    )
    # the constrained rule still applies
    assert store.resolve("k", C, {"package": "com.x"}, permission_key="package").allowed
    # constrained rule never matches the missing argument (spotlight fallback)
    assert store.resolve("k", C, {}, permission_key="package").outcome == "ask"
    assert "Ignoring allow rule" in caplog.text


def test_bare_deny_rule_applies_to_argument_dependent_tools(tmp_path):
    store = _store(tmp_path, 'deny=["k"]')
    assert store.resolve("k", C, {"package": "x"}, permission_key="package").denied


def test_add_allow_rule_rejects_bare_rule_for_argument_dependent_tool(tmp_path):
    store = _store(tmp_path, arg_dep={"k"})
    with pytest.raises(ValueError):
        store.add_allow_rule("k")
    with pytest.raises(ValueError):
        store.add_allow_rule("j", argument_dependent=True)
    assert store.add_allow_rule("k(package=com.x)") == "k(package=com.x)"
    with pytest.raises(RuleSyntaxError):
        store.add_allow_rule("k(")


def test_invalid_rules_are_skipped_with_warnings_and_bad_deny_fails_closed(tmp_path):
    store = _store(tmp_path, 'mode="weird"\nallow=["ok", "bad(", 3]\ndeny=["kill(p=x"]')
    assert store.mode == "ask"
    assert store.allow_rules() == ["ok"]
    assert store.deny_rules() == ["kill"]
    assert len(store.warnings()) == 4
    assert store.resolve("kill", RO, {"p": "y"}).denied


# -- modes ------------------------------------------------------------------


def test_session_mode_override_is_not_persisted(tmp_path):
    store = _store(tmp_path, 'mode="ask"')
    assert store.toggle_session_allow_all() == "allow_all"
    assert store.resolve("t", C).reason == "allow_all"
    assert _data(store)["mode"] == "ask"
    assert ToolPermissionStore(store.path).mode == "ask"
    assert store.toggle_session_allow_all() == "ask"
    store.set_session_mode(None)
    assert store.mode == "ask"
    with pytest.raises(ValueError):
        store.set_session_mode("yolo")


def test_set_mode_persists(tmp_path):
    store = _store(tmp_path)
    store.set_mode("allow_all")
    assert _data(store)["mode"] == "allow_all"
    assert ToolPermissionStore(store.path).mode == "allow_all"


# -- persistence --------------------------------------------------------------


def test_missing_file_is_ask_and_created_on_first_write(tmp_path):
    store = _store(tmp_path)
    assert store.mode == "ask"
    assert store.allow_rules() == []
    assert not store.path.exists()
    store.add_allow_rule("t")
    assert _data(store) == {"mode": "ask", "allow": ["t"], "deny": []}
    assert oct(store.path.stat().st_mode & 0o777) == "0o600"


def test_write_preserves_unknown_keys_and_hand_edits(tmp_path):
    store = _store(
        tmp_path, '# keep me\nmode = "ask"\nallow = ["a"]\ndeny = []\nfoo = 1\n'
    )
    # someone edits the file after the store loaded it
    _write(store.path, store.path.read_text() + 'bar = "x"\n')
    store.add_allow_rule("b")
    data = _data(store)
    assert data["allow"] == ["a", "b"]
    assert data["foo"] == 1
    assert data["bar"] == "x"
    if tp._tomlkit is not None:
        assert "# keep me" in store.path.read_text()


def test_atomic_write_leaves_no_temp_files_and_survives_failed_replace(
    tmp_path, monkeypatch
):
    store = _store(tmp_path, 'allow = ["a"]\n')
    store.add_allow_rule("b")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []

    original = store.path.read_text()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(tp.os, "replace", boom)
    store.add_allow_rule("c")  # falls back to session-only
    assert store.path.read_text() == original
    assert "c" in store.allow_rules()
    assert [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_concurrent_writes_do_not_lose_rules(tmp_path):
    store = _store(tmp_path)
    threads = [
        threading.Thread(target=store.add_allow_rule, args=(f"t{i}",))
        for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(_data(store)["allow"]) == sorted(f"t{i}" for i in range(20))


def test_two_stores_on_one_file_merge_writes(tmp_path):
    a = _store(tmp_path)
    b = ToolPermissionStore(a.path)
    a.add_allow_rule("x")
    b.add_allow_rule("y")
    assert _data(a)["allow"] == ["x", "y"]


def test_parse_error_fails_closed_and_preserves_file(tmp_path):
    text = 'mode = "allow_all"\nallow = ["t"\n'  # broken
    store = _store(tmp_path, text)
    assert store.load_error
    assert not store.writable
    assert store.mode == "ask"
    assert store.resolve("t", C).outcome == "ask"
    # remembering keeps the rule for the session but never rewrites the file
    store.add_allow_rule("t")
    store.set_mode("allow_all")
    store.add_deny_rule("z")
    assert store.path.read_text() == text
    assert store.resolve("z", RO).denied


def test_remove_rule(tmp_path):
    store = _store(tmp_path, 'allow=["a", "k(p=1)"]\ndeny=["d"]')
    assert store.remove_rule("allow", "k( p=1 )")
    assert store.remove_rule("deny", "d")
    assert not store.remove_rule("deny", "d")
    assert _data(store)["allow"] == ["a"]
    assert _data(store)["deny"] == []


# -- legacy migration ---------------------------------------------------------


def test_legacy_migration(tmp_path):
    store = _store(
        tmp_path,
        'allowed = ["launch_app", "install_apk"]\nnever = ["clear_app_data"]\nfoo = 1\n',
        arg_dep={"install_apk"},
    )
    data = _data(store)
    assert "allowed" not in data
    assert "never" not in data
    assert data["allow"] == ["launch_app"]  # bare arg-dependent name dropped
    assert data["deny"] == []  # never is NOT migrated
    assert data["mode"] == "ask"
    assert data["foo"] == 1
    assert store.resolve("clear_app_data", C).outcome == "ask"
    assert store.resolve("launch_app", C).allowed
    # one-time "previous declines (not enforced)" notice
    assert store.legacy_declines() == ["clear_app_data"]
    assert store.legacy_notice_pending()
    store.acknowledge_legacy_notice()
    assert not store.legacy_notice_pending()
    again = ToolPermissionStore(store.path)
    assert again.legacy_declines() == ["clear_app_data"]
    assert not again.legacy_notice_pending()


def test_legacy_migration_merges_with_new_keys_and_is_idempotent(tmp_path):
    store = _store(
        tmp_path, 'mode="allow_all"\nallow=["x"]\nallowed=["x","y"]\nnever=[]\n'
    )
    assert _data(store)["allow"] == ["x", "y"]
    assert store.mode == "allow_all"
    assert not store.legacy_notice_pending()
    before = store.path.read_text()
    ToolPermissionStore(store.path)
    assert store.path.read_text() == before


def test_legacy_migration_of_corrupt_file_does_not_touch_it(tmp_path):
    text = 'allowed = ["a"\n'
    store = _store(tmp_path, text)
    assert store.load_error
    assert store.path.read_text() == text


def test_legacy_migration_uses_registry_resolver_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(tp, "_registry_argument_dependent", lambda n: n == "push_path")
    path = _write(tmp_path / "p.toml", 'allowed = ["push_path", "ok"]\n')
    assert ToolPermissionStore(path).allow_rules() == ["ok"]
    tp.set_argument_dependency_resolver(lambda n: n == "ok")
    path2 = _write(tmp_path / "p2.toml", 'allowed = ["push_path", "ok"]\n')
    assert ToolPermissionStore(path2).allow_rules() == ["push_path"]


# -- legacy shims (current loop / chat panel) -----------------------------------


def test_legacy_shims(tmp_path, monkeypatch):
    store = _store(tmp_path, arg_dep={"argy"})
    monkeypatch.setattr(tp, "_tool_permission_store", store)
    assert get_tool_permission_store() is store
    assert resolve_tool_policy("t", R) == "ask"
    store.mark_allowed("t")
    assert store.is_allowed("t")
    assert resolve_tool_policy("t", R) == "allowed"
    assert _data(store)["allow"] == ["t"]
    # mark_never is session-only now
    store.mark_never("u")
    assert store.is_never("u")
    assert resolve_tool_policy("u", R) == "never"
    assert _data(store)["deny"] == []
    assert not ToolPermissionStore(store.path).is_never("u")
    # arg-dependent: mark_allowed refuses; stale bare rule never bypasses asking
    store.mark_allowed("argy")
    assert not store.is_allowed("argy")
    assert resolve_tool_policy("x", R, can_remember_choice=False) == "ask"
    assert resolve_tool_policy("x", NX) == "never"


def test_singletons_and_reset(tmp_path, monkeypatch):
    monkeypatch.setattr(tp, "_default_permissions_path", lambda: tmp_path / "s.toml")
    assert get_tool_permission_store() is get_tool_permission_store()
    broker = get_approval_broker()
    assert broker is get_approval_broker()
    pending = broker.submit(agent_id="a", agent_label="A", tool="t", args={}, risk=C)
    tp.reset_for_tests()
    assert pending.done
    assert pending.decision.by == "cancelled"
    assert get_approval_broker() is not broker


# -- ApprovalBroker -------------------------------------------------------------


@pytest.fixture
def broker(tmp_path):
    store = _store(tmp_path, arg_dep={"k"})
    return ApprovalBroker(store, timeout_s=5)


def _submit(broker, tool="t", agent="orchestrator", args=None, **kw):
    return broker.submit(
        agent_id=agent, agent_label=agent, tool=tool, args=args or {}, risk=C, **kw
    )


def test_broker_fifo_and_listener(broker):
    events = []
    remove = broker.add_listener(
        lambda kind, req, dec: events.append((kind, req.tool, dec))
    )
    a = _submit(broker, "a")
    b = _submit(broker, "b", agent="operator a-op-1")
    assert [r.tool for r in broker.pending()] == ["a", "b"]
    assert broker.head().tool == "a"
    assert broker.resolve(a.request.request_id, "once")
    assert broker.head().tool == "b"
    assert broker.resolve(b.request.request_id, Decision("no", note="use adb instead"))
    assert not broker.resolve(b.request.request_id, "once")  # first answer wins
    assert a.wait().choice == "once"
    assert b.wait() == Decision("no", note="use adb instead")
    assert [e[0] for e in events] == ["added", "added", "resolved", "resolved"]
    remove()
    _submit(broker)
    assert len(events) == 4


def test_broker_blocking_request_across_threads(broker):
    result = {}

    def worker():
        result["d"] = broker.request(
            agent_id="x", agent_label="X", tool="t", args={}, risk=C
        )

    thread = threading.Thread(target=worker)
    thread.start()
    deadline = time.monotonic() + 5
    while broker.head() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    broker.resolve(broker.head().request_id, "no", note=" stop ")
    thread.join(5)
    assert result["d"] == Decision("no", note="stop")


def test_broker_timeout_counts_as_no(broker):
    events = []
    broker.add_listener(lambda kind, req, dec: events.append(kind))
    decision = broker.request(
        agent_id="x", agent_label="X", tool="t", args={}, risk=C, timeout_s=0.05
    )
    assert decision == Decision("no", by="timeout")
    assert broker.pending() == []
    assert events == ["added", "resolved"]


def test_broker_default_timeout_is_300s():
    assert ApprovalBroker().timeout_s == 300.0


def test_broker_cancel_event_and_cancel(broker):
    cancel = threading.Event()
    cancel.set()
    d = broker.request(
        agent_id="x", agent_label="X", tool="t", args={}, risk=C, cancel_event=cancel
    )
    assert d.by == "cancelled"
    assert d.choice == "no"
    p = _submit(broker)
    assert broker.cancel(p.request.request_id)
    assert p.wait().by == "cancelled"
    assert not broker.cancel(p.request.request_id)


def test_broker_cancel_agent_only_hits_that_agent(broker):
    a1 = _submit(broker, agent="a")
    b1 = _submit(broker, agent="b")
    a2 = _submit(broker, agent="a")
    assert broker.cancel_agent("a") == 2
    assert a1.done
    assert a2.done
    assert not b1.done
    assert broker.cancel_all() == 1


def test_broker_always_persists_rule_and_auto_resolves_matching(broker):
    store = broker._get_store()
    first = _submit(broker, "t", suggested_rule="t")
    second = _submit(broker, "t", agent="operator")
    other = _submit(broker, "u")
    broker.resolve(first.request.request_id, "always")
    assert first.wait() == Decision("always", remembered_rule="t")
    assert store.allow_rules() == ["t"]
    assert second.done
    assert second.decision.by == "rule"
    assert not other.done
    assert store.resolve("t", C).allowed


def test_broker_always_with_constrained_rule(broker):
    store = broker._get_store()
    rule = suggest_rule("k", {"package": "com.x"}, permission_key="package")
    first = _submit(
        broker,
        "k",
        args={"package": "com.x"},
        suggested_rule=rule,
        argument_dependent=True,
    )
    same = _submit(broker, "k", args={"package": "com.x"}, argument_dependent=True)
    diff = _submit(broker, "k", args={"package": "com.y"}, argument_dependent=True)
    broker.resolve(first.request.request_id, "always")
    assert first.wait().remembered_rule == "k(package=com.x)"
    assert same.done
    assert not diff.done
    assert store.allow_rules() == ["k(package=com.x)"]


def test_broker_always_without_rule_degrades_to_once(broker):
    store = broker._get_store()
    p = _submit(broker, "k", argument_dependent=True)  # no suggestion
    broker.resolve(p.request.request_id, "always")
    assert p.wait().choice == "once"
    bare = _submit(broker, "k", suggested_rule="k", argument_dependent=True)
    broker.resolve(bare.request.request_id, "always")  # bare rule rejected
    assert bare.wait().choice == "once"
    assert store.allow_rules() == []


def test_broker_listener_errors_do_not_break_resolution(broker):
    broker.add_listener(lambda *a: 1 / 0)
    p = _submit(broker)
    broker.resolve(p.request.request_id, "once")
    assert p.wait().approved
