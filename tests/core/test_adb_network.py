"""Unit tests for sandroid.core.adb_network.

Focuses on the byte-order correction called out explicitly in
``adb_network.py``'s module docstring: the *address* field in
``/proc/net/tcp[6]`` is stored byte-swapped per 32-bit word, but the *port*
field is plain big-endian hex and must NOT be swapped. A uniform "swap both"
implementation would silently produce a wrong port number while leaving the
address' *string form* looking plausible -- so these fixtures use well-known
values (``127.0.0.1:22`` -> ``0100007F:0016``) precisely so a byte-order
regression would visibly fail rather than coincidentally still parse right.
"""

from __future__ import annotations

from sandroid.core.adb_network import list_connections

# Column header row real /proc/net/tcp[6] output always starts with.
_TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)

# 127.0.0.1:22 (a well-known loopback SSH listener) encodes as "0100007F:0016"
# -- confirmed via socket.inet_aton("127.0.0.1")[::-1].hex() == "0100007f" and
# format(22, "04x") == "0016". This is the load-bearing fixture line: it
# catches both a byte-swapped-port regression (would decode port as 0x1600
# instead of 22) and an address-not-swapped regression (would decode as
# "1.0.0.127" or similar) in one assertion.
_TCP_LISTEN_LINE = (
    "   0: 0100007F:0016 00000000:0000 0A "
    "00000000:00000000 00:00000000 00000000     0        0 12345 1 "
    "0000000000000000 100 0 0 10 0"
)

# 10.0.2.15:57621 (local/ephemeral) <-> 142.250.72.14:443 (a Google HTTPS
# endpoint), ESTABLISHED, owned by uid 10123.
_TCP_ESTABLISHED_LINE = (
    "   1: 0F02000A:E115 0E48FA8E:01BB 01 "
    "00000000:00000000 00:00000000 00000000 10123        0 54321 1 "
    "0000000000000000 20 0 0 10 -1"
)

_TCP6_LISTEN_LINE = (
    "   0: 00000000000000000000000000000000:1F90 "
    "00000000000000000000000000000000:0000 0A "
    "00000000:00000000 00:00000000 00000000     0        0 99001 1 "
    "0000000000000000 100 0 0 10 0"
)

_PM_LIST_PACKAGES_U = (
    "package:com.example.app uid:10123\npackage:com.android.shell uid:2000\n"
)


def _tcp(*lines: str) -> str:
    return "\n".join((_TCP_HEADER, *lines)) + "\n"


def _make_send(
    tcp_body: str = "", tcp6_body: str = "", pm_output: str = _PM_LIST_PACKAGES_U
):
    calls = []

    def fake_send(command):
        calls.append(command)
        if command == "shell pm list packages -U":
            return pm_output, ""
        if command == "shell cat /proc/net/tcp":
            return tcp_body, ""
        if command == "shell cat /proc/net/tcp6":
            return tcp6_body, ""
        raise AssertionError(f"unexpected command: {command}")

    fake_send.calls = calls
    return fake_send


# ---------------------------------------------------------------------------
# Byte-order correctness (the plan's explicit concern)
# ---------------------------------------------------------------------------


def test_port_is_not_byte_swapped_while_address_is():
    """The headline case: 127.0.0.1:22 must decode to exactly that, not a
    byte-swapped port (which would read 5632) or an unswapped address
    (which would read something other than 127.0.0.1).
    """
    send = _make_send(tcp_body=_tcp(_TCP_LISTEN_LINE))

    connections = list_connections(send)

    assert len(connections) == 1
    conn = connections[0]
    assert conn["local_address"] == "127.0.0.1"
    assert conn["local_port"] == 22
    assert conn["remote_address"] == "0.0.0.0"
    assert conn["remote_port"] == 0


def test_established_ipv4_connection_fields_decode_correctly():
    send = _make_send(tcp_body=_tcp(_TCP_LISTEN_LINE, _TCP_ESTABLISHED_LINE))

    connections = list_connections(send)
    established = next(c for c in connections if c["state"] == "ESTABLISHED")

    assert established["protocol"] == "tcp"
    assert established["local_address"] == "10.0.2.15"
    assert established["local_port"] == 57621
    assert established["remote_address"] == "142.250.72.14"
    assert established["remote_port"] == 443
    assert established["uid"] == 10123
    assert established["package_name"] == "com.example.app"


def test_listen_state_hex_code_decoded_and_pid_less_socket_has_no_package():
    send = _make_send(tcp_body=_tcp(_TCP_LISTEN_LINE))

    connections = list_connections(send)

    assert connections[0]["state"] == "LISTEN"
    assert connections[0]["uid"] == 0
    # uid 0 (root) has no entry in the fixture's pm-list map.
    assert connections[0]["package_name"] is None


def test_unknown_state_hex_code_passed_through_raw():
    line = _TCP_LISTEN_LINE.replace(" 0A ", " FF ")
    send = _make_send(tcp_body=_tcp(line))

    connections = list_connections(send)

    assert connections[0]["state"] == "FF"


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


def test_ipv6_socket_is_parsed_as_tcp6_with_swapped_words():
    send = _make_send(tcp6_body=_tcp(_TCP6_LISTEN_LINE))

    connections = list_connections(send)

    assert len(connections) == 1
    assert connections[0]["protocol"] == "tcp6"
    assert connections[0]["local_address"] == "::"
    assert connections[0]["local_port"] == 8080


def test_both_tcp_and_tcp6_results_are_combined():
    send = _make_send(
        tcp_body=_tcp(_TCP_LISTEN_LINE),
        tcp6_body=_tcp(_TCP6_LISTEN_LINE),
    )

    connections = list_connections(send)

    assert {c["protocol"] for c in connections} == {"tcp", "tcp6"}
    assert len(connections) == 2


# ---------------------------------------------------------------------------
# uid -> package_name cross-reference
# ---------------------------------------------------------------------------


def test_uid_to_package_map_built_from_single_pm_call_not_per_socket():
    send = _make_send(tcp_body=_tcp(_TCP_LISTEN_LINE, _TCP_ESTABLISHED_LINE))

    list_connections(send)

    assert send.calls.count("shell pm list packages -U") == 1


def test_unmapped_uid_gets_null_package_name():
    line = _TCP_ESTABLISHED_LINE.replace(" 10123 ", " 99999 ")
    send = _make_send(tcp_body=_tcp(line), pm_output=_PM_LIST_PACKAGES_U)

    connections = list_connections(send)

    assert connections[0]["uid"] == 99999
    assert connections[0]["package_name"] is None


def test_malformed_pm_list_lines_are_skipped_without_raising():
    send = _make_send(
        tcp_body=_tcp(_TCP_ESTABLISHED_LINE),
        pm_output="package:com.example.app uid:not-a-number\ngarbage line\n"
        "package:com.example.app uid:10123\n",
    )

    connections = list_connections(send)

    assert connections[0]["package_name"] == "com.example.app"


# ---------------------------------------------------------------------------
# Malformed / missing input handling
# ---------------------------------------------------------------------------


def test_missing_proc_files_return_empty_list():
    send = _make_send(tcp_body="", tcp6_body="")

    assert list_connections(send) == []


def test_header_only_output_returns_empty_list():
    send = _make_send(tcp_body=_TCP_HEADER + "\n")

    assert list_connections(send) == []


def test_short_row_is_skipped_without_raising():
    send = _make_send(tcp_body=_tcp("   0: 0100007F:0016 00000000:0000 0A"))

    assert list_connections(send) == []


def test_row_with_non_numeric_uid_is_skipped_without_raising():
    line = _TCP_LISTEN_LINE.replace("     0        0 12345", "  notanum   0 12345")
    send = _make_send(tcp_body=_tcp(line))

    assert list_connections(send) == []
