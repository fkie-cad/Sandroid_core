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

    app, uid, via = addon._attribute_and_tag(flow)

    assert app == ""
    assert uid is None
    assert via == "device"
    assert flow.comment == ""


def test_app_field_empty_when_lane_lookup_raises(addon, flow_paths, monkeypatch):
    flow = tflow.tflow(resp=True)
    monkeypatch.setattr(
        addon,
        "_lane_entry",
        lambda _mode: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    app, _uid, _via = addon._attribute_and_tag(flow)

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


# -- fix round 3: decoded bodies, TLS failures, protocol token -------------------


def test_gzip_body_is_stored_decoded(addon, flow_paths):
    """M1: gzip JSON was stored as wire bytes and shown as a hex dump."""
    import gzip

    flow = tflow.tflow(resp=True)
    payload = b'{"items": [1, 2, 3], "title": "Featured"}'
    flow.response.headers["content-type"] = "application/json"
    flow.response.headers["content-encoding"] = "gzip"
    flow.response.raw_content = gzip.compress(payload)

    addon.SandroidLogger().response(flow)

    detail = json.loads((flow_paths["details"] / f"{flow.id}.json").read_text())
    body = detail["response_body"]
    assert body["encoding"] == "utf-8"
    assert body["content"] == payload.decode()
    assert body["content_encoding"] == "gzip"
    assert body["encoded_bytes"] == len(flow.response.raw_content)
    assert body["size_bytes"] == len(payload)
    # The record keeps the on-the-wire size (what the table shows).
    rec = _read_lines(flow_paths["log"])[-1]
    assert rec["response_bytes"] == len(flow.response.raw_content)


def test_undecodable_body_is_kept_as_received(addon, flow_paths):
    flow = tflow.tflow(resp=True)
    flow.response.headers["content-encoding"] = "gzip"
    flow.response.raw_content = b"\x1f\x8b\x08 this is not gzip"

    addon.SandroidLogger().response(flow)

    detail = json.loads((flow_paths["details"] / f"{flow.id}.json").read_text())
    body = detail["response_body"]
    assert body["decode_failed"] is True
    assert body["content_encoding"] == "gzip"
    assert body["size_bytes"] == len(flow.response.raw_content)


def test_tls_failure_is_persisted_in_the_flow_log(addon, flow_paths, capsys):
    """L7: TLS failures existed only as a stdout line."""
    from types import SimpleNamespace

    data = SimpleNamespace(
        context=SimpleNamespace(
            client=SimpleNamespace(sni="pinned.example.com", proxy_mode=None)
        ),
        conn=SimpleNamespace(error="Client TLS handshake failed: certificate unknown"),
    )
    addon.SandroidLogger().tls_failed_client(data)

    assert "[TLS_FAIL]|" in capsys.readouterr().out
    rec = _read_lines(flow_paths["log"])[-1]
    assert rec["kind"] == "tls"
    assert rec["host"] == "pinned.example.com"
    assert rec["tls_reason"] == "cert"
    assert rec["seq"] == 1
    assert json.loads(flow_paths["meta"].read_text())["latest_seq"] == 1


def test_tls_failure_ids_are_globally_unique(addon, flow_paths, capsys):
    """``tls-<uuid4 hex>``, never ``tls-<seq>`` (seq restarts with a new log);
    ``seq`` stays its own field.
    """
    import re
    from types import SimpleNamespace

    data = SimpleNamespace(
        context=SimpleNamespace(client=SimpleNamespace(sni="a.io", proxy_mode=None)),
        conn=SimpleNamespace(error="handshake failed"),
    )
    addon.SandroidLogger().tls_failed_client(data)
    addon.SandroidLogger().tls_failed_client(data)
    capsys.readouterr()
    recs = _read_lines(flow_paths["log"])[-2:]
    ids = [r["id"] for r in recs]
    assert all(re.fullmatch(r"tls-[0-9a-f]{32}", i) for i in ids)
    assert ids[0] != ids[1]
    assert [r["seq"] for r in recs] == [1, 2]


def test_protocol_token_is_short_for_http2(addon):
    """L13: "HTTPS/2.0" -> "HTTPS/2" as the docs promise."""
    flow = tflow.tflow(resp=True)
    flow.request.scheme = "https"
    flow.request.http_version = "HTTP/2.0"
    assert addon._protocol(flow) == "HTTPS/2"
    flow.request.http_version = "HTTP/1.1"
    assert addon._protocol(flow) == "HTTPS/1.1"


def test_parent_watch_needs_the_env_var(monkeypatch):
    """The orphan guard only runs inside a mitmweb Sandroid started."""
    import threading

    monkeypatch.delenv("SANDROID_PARENT_PID", raising=False)
    before = {t.name for t in threading.enumerate()}
    ns: dict = {}
    exec(compile(mitmproxy_service._ADDON_SOURCE, "<addon>", "exec"), ns)  # noqa: S102
    after = {t.name for t in threading.enumerate()}
    assert "sandroid-parent-watch" not in after - before


# -- device-proxy flows named by the identity relay --------------------------------


_SECRET = "5ec7e75ec7e75ec7e75ec7e75ec7e75e"  # noqa: S105 -- test value


def _relay_auth(uid, device="dev5570", secret=_SECRET) -> str:
    import base64

    return "Basic " + base64.b64encode(f"uid{uid}-{device}:{secret}".encode()).decode()


@pytest.fixture
def uid_map(tmp_path, monkeypatch):
    path = tmp_path / "device_uids.json"
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "devices": {
                    "dev5570": {
                        "serial": "emulator-5570",
                        "secret": _SECRET,
                        "uids": {"10215": "de.fkie.canary", "10300": "a.one,a.two"},
                    },
                    "dev5572": {
                        "serial": "emulator-5572",
                        "secret": "0ther5ecret0ther5ecret0ther5ecre",
                        "uids": {"10215": "com.other.app"},
                    },
                },
            }
        )
    )
    monkeypatch.setenv("SANDROID_DEVICE_UIDS", str(path))
    return path


def _connect(addon, uid, **auth):
    connect = tflow.tflow()
    connect.request.method = "CONNECT"
    connect.request.headers["Proxy-Authorization"] = _relay_auth(uid, **auth)
    addon.SandroidLogger().http_connect(connect)
    return connect


def _named(addon, flow_paths, connect) -> dict:
    flow = tflow.tflow(resp=True)
    flow.client_conn = connect.client_conn
    addon.SandroidLogger().response(flow)
    return _read_lines(flow_paths["log"])[-1]


def test_forged_identity_without_the_secret_names_nothing(addon, flow_paths, uid_map):
    """N4: an app without a REDIRECT (SDK sandbox, a new install, a relay
    that is down) sending ``uid<U>`` itself is not named as app U.
    """
    for auth in ({"secret": "x"}, {"secret": ""}, {"device": "nodevice"}):
        connect = _connect(addon, 10215, **auth)
        # The forged header is still not forwarded upstream.
        assert "Proxy-Authorization" not in connect.request.headers
        rec = _named(addon, flow_paths, connect)
        assert (rec["app"], rec["uid"]) == ("", None), auth
    # The old, secret-less identity format is not trusted either.
    import base64

    flow = tflow.tflow(resp=True)
    flow.request.headers["Proxy-Authorization"] = (
        "Basic " + base64.b64encode(b"uid10215:x").decode()
    )
    addon.SandroidLogger().requestheaders(flow)
    addon.SandroidLogger().response(flow)
    assert _read_lines(flow_paths["log"])[-1]["app"] == ""


def test_uid_resolves_on_its_own_device(addon, flow_paths, uid_map):
    """N5: two devices on one Mitmproxy: UID 10215 is another app on each."""
    a = _named(addon, flow_paths, _connect(addon, 10215))
    assert a["app"] == "de.fkie.canary"
    b = _named(
        addon,
        flow_paths,
        _connect(
            addon,
            10215,
            device="dev5572",
            secret="0ther5ecret0ther5ecret0ther5ecre",  # noqa: S106 -- test value
        ),
    )
    assert b["app"] == "com.other.app"
    # Device A's secret does not open device B's names.
    c = _named(addon, flow_paths, _connect(addon, 10215, device="dev5572"))
    assert c["app"] == ""


def test_relay_identity_tags_every_flow_of_its_connection(
    addon, flow_paths, uid_map, capsys
):
    connect = _connect(addon, 10215)
    assert "Proxy-Authorization" not in connect.request.headers  # not forwarded
    flow = tflow.tflow(resp=True)
    flow.client_conn = connect.client_conn  # inner request: no header of its own
    addon.SandroidLogger().response(flow)

    rec = _read_lines(flow_paths["log"])[-1]
    assert rec["app"] == "de.fkie.canary"
    assert rec["uid"] == 10215
    assert rec["via"] == "device"
    assert flow.metadata["sandroid_app"] == "de.fkie.canary"
    assert flow.comment == "de.fkie.canary"
    line = [x for x in capsys.readouterr().out.splitlines() if x.startswith("[FLOW]")]
    assert line[-1].endswith("|de.fkie.canary|device")


def test_plain_http_wrapped_as_connect_80_is_named(addon, flow_paths, uid_map):
    connect = _connect(addon, 10300)
    connect.request.port = 80
    flow = tflow.tflow(resp=True)
    flow.request.scheme = "http"
    flow.client_conn = connect.client_conn
    addon.SandroidLogger().response(flow)
    assert _read_lines(flow_paths["log"])[-1]["app"] == "a.one,a.two"


def test_identity_on_an_absolute_form_request(addon, flow_paths, uid_map):
    flow = tflow.tflow(resp=True)
    flow.request.headers["Proxy-Authorization"] = _relay_auth(10215)
    addon.SandroidLogger().requestheaders(flow)
    assert "Proxy-Authorization" not in flow.request.headers
    addon.SandroidLogger().response(flow)
    assert _read_lines(flow_paths["log"])[-1]["app"] == "de.fkie.canary"


def test_foreign_proxy_auth_is_left_alone(addon, flow_paths, uid_map):
    flow = tflow.tflow(resp=True)
    flow.request.headers["Proxy-Authorization"] = "Basic dXNlcjpwYXNz"  # user:pass
    addon.SandroidLogger().requestheaders(flow)
    assert flow.request.headers["Proxy-Authorization"] == "Basic dXNlcjpwYXNz"
    addon.SandroidLogger().response(flow)
    rec = _read_lines(flow_paths["log"])[-1]
    assert rec["app"] == ""
    assert rec["uid"] is None
    assert rec["via"] == "device"


def test_tls_failure_is_named_by_its_connection(addon, flow_paths, uid_map, capsys):
    from types import SimpleNamespace

    connect = _connect(addon, 10215)
    client = connect.client_conn
    data = SimpleNamespace(
        context=SimpleNamespace(client=client),
        conn=SimpleNamespace(error="certificate unknown"),
    )
    client.sni = "pinned.example.com"
    client.proxy_mode = None
    addon.SandroidLogger().tls_failed_client(data)
    assert "|cert|de.fkie.canary|device" in capsys.readouterr().out
    rec = _read_lines(flow_paths["log"])[-1]
    assert (rec["app"], rec["uid"], rec["via"]) == ("de.fkie.canary", 10215, "device")
    addon.SandroidLogger().client_disconnected(client)
    assert client.id not in addon._CONN_UID


def test_app_proxy_flows_say_via_app_proxy(addon, flow_paths, tmp_path, monkeypatch):
    lanes = tmp_path / "lanes.json"
    lanes.write_text(json.dumps({"8082": {"package": "com.lane", "marker": ""}}))
    monkeypatch.setenv("SANDROID_FOCUS_MAP", str(lanes))
    flow = tflow.tflow(resp=True)
    monkeypatch.setattr(addon, "_lane_entry", lambda mode: {"package": "com.lane"})
    assert addon._attribute_and_tag(flow) == ("com.lane", None, "app-proxy")


def test_direct_flow_line_uses_the_via_column():
    from sandroid.services.mitmproxy_service import _is_direct_flow_line

    head = "[FLOW]|10:00:00|HTTPS/2|200|GET|example.org/|1 B"
    assert _is_direct_flow_line(f"{head}|de.fkie.canary|device")  # named, device
    assert not _is_direct_flow_line(f"{head}|com.lane|app-proxy")
    assert _is_direct_flow_line(f"{head}|")  # an older addon: no app = device
    assert not _is_direct_flow_line(f"{head}|com.lane")
