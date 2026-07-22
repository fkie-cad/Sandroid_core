"""Unit tests for the structured flow-log logic embedded in
sandroid.services.mitmproxy_service's ``_ADDON_SOURCE``.

``_ADDON_SOURCE`` is a string blob only ever executed inside a real mitmweb
subprocess, so it can't be imported like a normal module. Instead, each test
gets a *fresh* ``exec()`` of the source into its own namespace (see the
``addon`` fixture) -- mirroring a fresh mitmweb subprocess's own fresh
Python process per addon load, and making sure module-level state (``_SEQ``,
the cached env-var values, the Focus-map cache) never leaks between tests.

Fake flows are built with ``mitmproxy.test.tflow`` (a real dependency
already, and much less brittle than hand-rolled fakes) rather than
hand-rolled stand-ins, since the real ``http``/``tls`` modules import fine
in this venv.
"""

from __future__ import annotations

import json

import pytest
from mitmproxy.test import tflow

from sandroid.services import mitmproxy_service


class _AddonModule:
    """Thin attribute-access wrapper around one exec()'d addon namespace.

    Unlike ``types.SimpleNamespace(**ns)``, setting an attribute here
    mutates the underlying ``ns`` dict directly -- the same dict the
    addon's own functions use as their ``__globals__`` -- so
    ``monkeypatch.setattr(addon, "_FLOW_MAX_BODY_BYTES", 5)`` actually
    affects what those functions see. A ``SimpleNamespace`` copy would not:
    it stores the value in its own separate ``__dict__``, invisible to code
    whose globals are the original ``ns``.
    """

    def __init__(self, ns: dict) -> None:
        object.__setattr__(self, "_ns", ns)

    def __getattr__(self, name):
        try:
            return self._ns[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value) -> None:
        self._ns[name] = value

    def __delattr__(self, name) -> None:
        del self._ns[name]


@pytest.fixture
def flow_paths(tmp_path):
    """The three on-disk paths under a fresh ``mitm_flows`` directory."""
    flow_dir = tmp_path / "mitm_flows"
    return {
        "dir": flow_dir,
        "log": flow_dir / "flows.jsonl",
        "details": flow_dir / "details",
        "meta": flow_dir / "meta.json",
    }


@pytest.fixture
def addon(flow_paths, monkeypatch):
    """A fresh exec()'d instance of the embedded addon's namespace.

    ``SANDROID_FLOW_LOG`` is set (to this test's own tmp_path-scoped log
    file) *before* the exec so the addon's lazily-cached env-var reads pick
    it up on first use. ``SANDROID_FOCUS_MAP`` is explicitly unset so
    attribution defaults to app="" unless a test sets it up itself.
    """
    monkeypatch.setenv("SANDROID_FLOW_LOG", str(flow_paths["log"]))
    monkeypatch.delenv("SANDROID_FOCUS_MAP", raising=False)
    ns: dict = {}
    exec(compile(mitmproxy_service._ADDON_SOURCE, "<addon>", "exec"), ns)  # noqa: S102
    return _AddonModule(ns)


def _read_lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


# -- _resume_seq --------------------------------------------------------------


def test_resume_seq_from_tail_of_existing_log(addon, flow_paths):
    flow_paths["dir"].mkdir(parents=True)
    flow_paths["log"].write_text(
        '{"seq": 1, "id": "a"}\n{"seq": 2, "id": "b"}\n{"seq": 5, "id": "c"}\n'
    )

    addon._resume_seq(str(flow_paths["log"]))

    assert addon._SEQ["n"] == 5


def test_resume_seq_from_meta_json_latest_seq_when_flows_jsonl_missing(
    addon, flow_paths
):
    """Regression: the clear+restart bug the design fixes.

    If flows.jsonl is gone (e.g. clear_captured_flows ran while mitmweb was
    stopped) the addon must NOT restart the seq counter at 0 -- it must
    resume from meta.json's preserved latest_seq, or a stale cached
    since_cursor from before the clear would collide with new flows.
    """
    flow_paths["dir"].mkdir(parents=True)
    flow_paths["meta"].write_text(json.dumps({"latest_seq": 42}))
    assert not flow_paths["log"].exists()

    addon._resume_seq(str(flow_paths["log"]))

    assert addon._SEQ["n"] == 42


def test_resume_seq_from_meta_json_when_flows_jsonl_is_empty(addon, flow_paths):
    flow_paths["dir"].mkdir(parents=True)
    flow_paths["log"].write_text("")
    flow_paths["meta"].write_text(json.dumps({"latest_seq": 7}))

    addon._resume_seq(str(flow_paths["log"]))

    assert addon._SEQ["n"] == 7


def test_resume_seq_defaults_to_zero_when_nothing_available(addon, flow_paths):
    addon._resume_seq(str(flow_paths["log"]))

    assert addon._SEQ["n"] == 0


def test_resume_seq_only_runs_once_per_process(addon, flow_paths):
    flow_paths["dir"].mkdir(parents=True)
    flow_paths["log"].write_text('{"seq": 9, "id": "a"}\n')

    addon._resume_seq(str(flow_paths["log"]))
    assert addon._SEQ["n"] == 9

    # Even if the file now claims a much higher seq, a second call is a
    # no-op -- resumption happens exactly once per addon-process-load.
    flow_paths["log"].write_text('{"seq": 999, "id": "a"}\n')
    addon._resume_seq(str(flow_paths["log"]))
    assert addon._SEQ["n"] == 9


# -- error() hook ---------------------------------------------------------------


def test_error_hook_records_flow_that_never_got_a_response(addon, flow_paths):
    flow = tflow.tflow(err=True)
    assert flow.response is None

    addon.SandroidLogger().error(flow)

    records = _read_lines(flow_paths["log"])
    assert len(records) == 1
    assert records[0]["id"] == flow.id
    assert records[0]["error"] == flow.error.msg
    assert records[0]["status_code"] is None


def test_error_hook_skips_flow_that_already_has_a_response(addon, flow_paths):
    flow = tflow.tflow(resp=True, err=True)
    assert flow.response is not None

    addon.SandroidLogger().error(flow)

    assert not flow_paths["log"].exists()


# -- app attribution --------------------------------------------------------------


def test_app_field_empty_without_active_focus_lane(addon, flow_paths):
    flow = tflow.tflow(resp=True)

    app = addon._attribute_and_tag(flow)

    assert app == ""
    assert flow.comment == ""


def test_app_field_empty_when_lane_lookup_raises(addon, flow_paths, monkeypatch):
    flow = tflow.tflow(resp=True)
    monkeypatch.setattr(
        addon,
        "_lane_entry",
        lambda _mode: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    app = addon._attribute_and_tag(flow)

    assert app == ""


# -- body capping -----------------------------------------------------------------


def test_body_truncated_at_configured_cap(addon, flow_paths, monkeypatch):
    monkeypatch.setattr(addon, "_FLOW_MAX_BODY_BYTES", 5)
    flow = tflow.tflow(resp=True)
    flow.response.content = b"0123456789"

    addon.SandroidLogger().response(flow)

    detail = json.loads((flow_paths["details"] / f"{flow.id}.json").read_text())
    body = detail["response_body"]
    assert body["truncated"] is True
    assert body["size_bytes"] == 10
    assert body["bytes_read"] == 5
    assert body["content"] == "01234"


def test_body_not_truncated_when_under_cap(addon, flow_paths):
    flow = tflow.tflow(resp=True)
    flow.response.content = b"short"

    addon.SandroidLogger().response(flow)

    detail = json.loads((flow_paths["details"] / f"{flow.id}.json").read_text())
    body = detail["response_body"]
    assert body["truncated"] is False
    assert body["size_bytes"] == 5
    assert body["bytes_read"] == 5


# -- header duplicate preservation --------------------------------------------------


def test_headers_preserve_duplicate_set_cookie_names(addon, flow_paths):
    flow = tflow.tflow(resp=True)
    flow.response.headers.add("Set-Cookie", "a=1")
    flow.response.headers.add("Set-Cookie", "b=2")

    addon.SandroidLogger().response(flow)

    detail = json.loads((flow_paths["details"] / f"{flow.id}.json").read_text())
    cookie_pairs = [
        pair for pair in detail["response_headers"] if pair[0] == "Set-Cookie"
    ]
    assert cookie_pairs == [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]


# -- retention trim -----------------------------------------------------------------


def test_retention_trim_drops_oldest_and_bumps_generation(
    addon, flow_paths, monkeypatch
):
    monkeypatch.setattr(addon, "_FLOW_MAX_STORED", 3)
    flows = [tflow.tflow(resp=True) for _ in range(5)]
    logger = addon.SandroidLogger()
    for flow in flows:
        logger.response(flow)

    records = _read_lines(flow_paths["log"])
    assert len(records) == 3
    kept_ids = {r["id"] for r in records}
    assert kept_ids == {f.id for f in flows[-3:]}

    # The two oldest flows' detail files must be gone; the three kept ones
    # must still be present.
    for flow in flows[:2]:
        assert not (flow_paths["details"] / f"{flow.id}.json").exists()
    for flow in flows[-3:]:
        assert (flow_paths["details"] / f"{flow.id}.json").exists()

    meta = json.loads(flow_paths["meta"].read_text())
    assert meta["earliest_seq"] == min(r["seq"] for r in records)
    assert meta["generation"] > 0


def test_retention_trim_leaves_no_leftover_tmp_file(addon, flow_paths, monkeypatch):
    # The rewrite is a temp-file + os.replace swap (matching _write_meta's
    # own atomicity), never a plain truncating open() -- regression pinning
    # that the temp file is always cleaned up (via the rename) rather than
    # left behind next to flows.jsonl.
    monkeypatch.setattr(addon, "_FLOW_MAX_STORED", 3)
    logger = addon.SandroidLogger()
    for _ in range(5):
        logger.response(tflow.tflow(resp=True))

    leftovers = list(flow_paths["dir"].glob("flows.jsonl.tmp-*"))
    assert leftovers == []


def test_line_count_tracked_in_memory_without_rereading_whole_file(
    addon, flow_paths, monkeypatch
):
    # Regression for the O(current file size)-per-flow cost: _maybe_trim
    # used to readlines() the ENTIRE file on every single append just to
    # learn its length. The in-memory _LINE_COUNT counter must track the
    # true count via pure increments, only actually reopening the file once
    # a trim is due (max_stored well above what's written here).
    monkeypatch.setattr(addon, "_FLOW_MAX_STORED", 1000)
    logger = addon.SandroidLogger()
    log_path = str(flow_paths["log"])

    logger.response(tflow.tflow(resp=True))
    assert addon._LINE_COUNT[log_path] == 1

    logger.response(tflow.tflow(resp=True))
    logger.response(tflow.tflow(resp=True))
    assert addon._LINE_COUNT[log_path] == 3
    assert len(_read_lines(flow_paths["log"])) == 3


def test_line_count_seeds_correctly_against_a_pre_existing_populated_log(
    addon, flow_paths, monkeypatch
):
    # Simulates an addon (re)load mid-session against a flows.jsonl that
    # already has records from before this process started -- the lazy seed
    # must count the pre-existing lines plus this call's own append exactly
    # once each, never double-counting the just-written line.
    monkeypatch.setattr(addon, "_FLOW_MAX_STORED", 1000)
    flow_paths["dir"].mkdir(parents=True)
    flow_paths["log"].write_text('{"seq": 1, "id": "a"}\n{"seq": 2, "id": "b"}\n')
    log_path = str(flow_paths["log"])

    addon.SandroidLogger().response(tflow.tflow(resp=True))

    assert addon._LINE_COUNT[log_path] == 3
    assert len(_read_lines(flow_paths["log"])) == 3


# -- write-safety: reopens the path per write -----------------------------------------


def test_append_reopens_the_path_per_write(addon, flow_paths):
    """Regression pinning the "safe to clear while mitmweb keeps running"
    property: _append_flow_record must never hold flows.jsonl open across
    calls. Deleting the file between two writes must not lose the second
    write -- the reopen recreates the path instead of writing into an
    unlinked, invisible inode.
    """
    logger = addon.SandroidLogger()
    first = tflow.tflow(resp=True)
    logger.response(first)
    assert flow_paths["log"].exists()

    flow_paths["log"].unlink()
    assert not flow_paths["log"].exists()

    second = tflow.tflow(resp=True)
    logger.response(second)

    assert flow_paths["log"].exists()
    records = _read_lines(flow_paths["log"])
    assert len(records) == 1
    assert records[0]["id"] == second.id


def test_flow_log_disabled_when_env_var_empty(flow_paths, monkeypatch):
    monkeypatch.setenv("SANDROID_FLOW_LOG", "")
    monkeypatch.delenv("SANDROID_FOCUS_MAP", raising=False)
    ns: dict = {}
    exec(compile(mitmproxy_service._ADDON_SOURCE, "<addon>", "exec"), ns)  # noqa: S102
    addon = _AddonModule(ns)

    flow = tflow.tflow(resp=True)
    addon.SandroidLogger().response(flow)

    assert not flow_paths["dir"].exists()
