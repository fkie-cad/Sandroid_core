"""Unit tests for sandroid.ai.tool_permissions.

Every test builds its own fresh ``ToolPermissionStore`` backed by a temp file
(``tmp_path``, never the real ``~/.config/sandroid`` location) and
monkeypatches ``tool_permissions.get_tool_permission_store`` to return it, so
``resolve_tool_policy`` -- which calls that accessor internally -- consults
the test's isolated store rather than the process-wide singleton. This
mirrors ``test_loop.py``'s ``monkeypatch.setattr(loop_module,
"get_tool_registry", lambda: registry)`` pattern.
"""

import pytest

import sandroid.ai.tool_permissions as tool_permissions_module
from sandroid.ai.tool_permissions import (
    ToolPermissionStore,
    get_tool_permission_store,
    resolve_tool_policy,
)
from sandroid.ai.tools.registry import RiskTier


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A fresh store backed by a temp file, wired up as the module singleton."""
    instance = ToolPermissionStore(path=tmp_path / "ai_tool_permissions.toml")
    monkeypatch.setattr(tool_permissions_module, "_tool_permission_store", None)
    monkeypatch.setattr(
        tool_permissions_module, "get_tool_permission_store", lambda: instance
    )
    return instance


# -- ToolPermissionStore: round-trip + basic semantics -----------------------


def test_store_starts_empty_when_file_absent(tmp_path):
    fresh = ToolPermissionStore(path=tmp_path / "does_not_exist.toml")
    assert not fresh.is_allowed("some_tool")
    assert not fresh.is_never("some_tool")


def test_store_roundtrips_allowed_and_never_through_a_temp_file(tmp_path):
    path = tmp_path / "ai_tool_permissions.toml"
    first = ToolPermissionStore(path=path)
    first.mark_allowed("install_apk")
    first.mark_never("clear_app_data")

    # A brand-new instance reading the same path must see the persisted state.
    second = ToolPermissionStore(path=path)
    assert second.is_allowed("install_apk")
    assert not second.is_never("install_apk")
    assert second.is_never("clear_app_data")
    assert not second.is_allowed("clear_app_data")


def test_mark_allowed_clears_a_conflicting_never_entry(tmp_path):
    store = ToolPermissionStore(path=tmp_path / "perms.toml")
    store.mark_never("uninstall_apk")
    assert store.is_never("uninstall_apk")

    store.mark_allowed("uninstall_apk")

    assert store.is_allowed("uninstall_apk")
    assert not store.is_never("uninstall_apk")


def test_mark_never_clears_a_conflicting_allowed_entry(tmp_path):
    store = ToolPermissionStore(path=tmp_path / "perms.toml")
    store.mark_allowed("uninstall_apk")
    assert store.is_allowed("uninstall_apk")

    store.mark_never("uninstall_apk")

    assert store.is_never("uninstall_apk")
    assert not store.is_allowed("uninstall_apk")


def test_corrupt_file_is_swallowed_and_store_starts_empty(tmp_path):
    path = tmp_path / "corrupt.toml"
    path.write_text("this is not valid TOML {{{", encoding="utf-8")

    fresh = ToolPermissionStore(path=path)

    assert not fresh.is_allowed("anything")
    assert not fresh.is_never("anything")


def test_get_tool_permission_store_is_a_singleton(monkeypatch, tmp_path):
    monkeypatch.setattr(tool_permissions_module, "_tool_permission_store", None)
    monkeypatch.setattr(
        tool_permissions_module,
        "_default_permissions_path",
        lambda: tmp_path / "singleton.toml",
    )
    first = get_tool_permission_store()
    second = get_tool_permission_store()
    assert first is second


# -- resolve_tool_policy: derivation against an empty store ------------------


def test_read_only_derives_allowed_with_empty_store(store):
    assert resolve_tool_policy("get_status", RiskTier.READ_ONLY) == "allowed"


def test_reversible_derives_ask_with_empty_store(store):
    assert resolve_tool_policy("install_apk", RiskTier.REVERSIBLE) == "ask"


def test_consequential_derives_ask_with_empty_store(store):
    assert resolve_tool_policy("clear_app_data", RiskTier.CONSEQUENTIAL) == "ask"


def test_not_exposed_is_always_never_with_empty_store(store):
    assert resolve_tool_policy("secret_tool", RiskTier.NOT_EXPOSED) == "never"


# -- resolve_tool_policy: an explicit store entry wins over the risk default -


def test_store_never_wins_over_read_only_default_of_allowed(store):
    """A READ_ONLY tool would default to "allowed" -- an explicit "never" in
    the store must still override that default.
    """
    store.mark_never("get_status")

    assert resolve_tool_policy("get_status", RiskTier.READ_ONLY) == "never"


def test_store_allowed_wins_over_reversible_default_of_ask(store):
    """A REVERSIBLE tool would default to "ask" -- an explicit "allowed" in
    the store must override that default.
    """
    store.mark_allowed("install_apk")

    assert resolve_tool_policy("install_apk", RiskTier.REVERSIBLE) == "allowed"


def test_store_allowed_wins_over_consequential_default_of_ask(store):
    store.mark_allowed("clear_app_data")

    assert resolve_tool_policy("clear_app_data", RiskTier.CONSEQUENTIAL) == "allowed"


def test_store_never_wins_over_reversible_default_of_ask(store):
    store.mark_never("install_apk")

    assert resolve_tool_policy("install_apk", RiskTier.REVERSIBLE) == "never"


# -- resolve_tool_policy: NOT_EXPOSED is unconditional -----------------------


def test_not_exposed_is_never_even_when_store_says_allowed(store):
    """Defense in depth: even if the store somehow has an "allowed" entry for
    a NOT_EXPOSED tool's name (e.g. left over from before it was
    reclassified), the gate must still refuse it outright.
    """
    store.mark_allowed("secret_tool")

    assert resolve_tool_policy("secret_tool", RiskTier.NOT_EXPOSED) == "never"


def test_not_exposed_is_never_even_when_store_says_never(store):
    store.mark_never("secret_tool")

    assert resolve_tool_policy("secret_tool", RiskTier.NOT_EXPOSED) == "never"


# -- resolve_tool_policy: can_remember_choice=False bypasses the store -------


def test_can_remember_choice_false_still_asks_despite_a_stored_allowed_entry(store):
    """This is the fixed 3-arg signature's whole point, and the exact bug an
    earlier draft of this plan shipped: a tool marked can_remember_choice=False
    (its risk lives in its *arguments*, not its identity, e.g.
    invoke_exported_component) must NEVER silently bypass re-asking just
    because the store happens to have a stale/pre-existing "allowed" entry
    under that same tool name.
    """
    store.mark_allowed("invoke_exported_component")

    result = resolve_tool_policy(
        "invoke_exported_component",
        RiskTier.CONSEQUENTIAL,
        can_remember_choice=False,
    )

    assert result == "ask"


def test_can_remember_choice_false_asks_even_for_read_only_risk(store):
    """can_remember_choice=False must win even against RiskTier.READ_ONLY's
    normal "allowed" default -- the check happens strictly before the
    risk-tier fallback, per the plan's fixed 3-step order.
    """
    result = resolve_tool_policy(
        "some_tool", RiskTier.READ_ONLY, can_remember_choice=False
    )

    assert result == "ask"


def test_can_remember_choice_false_does_not_even_consult_the_store_for_never(store):
    """Symmetric to the "allowed" case: a stored "never" entry doesn't matter
    either -- can_remember_choice=False always resolves to "ask", not "never".
    """
    store.mark_never("invoke_exported_component")

    result = resolve_tool_policy(
        "invoke_exported_component",
        RiskTier.CONSEQUENTIAL,
        can_remember_choice=False,
    )

    assert result == "ask"


def test_can_remember_choice_true_is_the_default(store):
    """Sanity check for the signature's default value: omitting the argument
    entirely behaves like explicitly passing True.
    """
    store.mark_allowed("install_apk")

    assert resolve_tool_policy("install_apk", RiskTier.REVERSIBLE) == "allowed"
