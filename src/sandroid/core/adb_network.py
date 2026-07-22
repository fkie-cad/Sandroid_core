"""ADB ``/proc/net/tcp[6]`` parsing (device-side TCP socket listing).

Provides :func:`list_connections`, which parses the kernel's own connection
tables rather than a ``dumpsys``/shell-tool wrapper. Kept separate from
:mod:`adb_emulator` (whose ``ifconfig``-based ``get_network_info`` is a
different, historical concern -- interface addressing, not per-socket
connection state).

.. warning::
    Like :mod:`adb_dumpsys`, this has no existing verified precedent in this
    codebase (confirmed via grep), and non-root visibility into
    ``/proc/net/tcp`` can vary by Android version/SELinux policy. Treat
    :func:`list_connections` as needing the same live-device smoke-test
    verification as the ``dumpsys`` parsers, not as a safely-assumed-correct
    parse.
"""

from __future__ import annotations

import socket
from logging import getLogger
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)

_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _swap_word_bytes(hex_word: str) -> bytes:
    """Reverse the byte order of one 8-hex-char (32-bit) word.

    ``/proc/net/tcp[6]`` stores each 32-bit address word in the CPU's native
    byte order (little-endian on every Android target), so the hex text
    reads back reversed relative to network byte order. Reversing the four
    bytes here recovers the address bytes in their natural (network) order.

    Args:
        hex_word: Exactly 8 hex characters (4 bytes).

    Returns:
        The 4 address bytes in natural order.
    """
    return bytes.fromhex(hex_word)[::-1]


def _parse_ipv4_address(hex_addr: str) -> str:
    """Decode an 8-hex-char ``/proc/net/tcp`` IPv4 address field."""
    return ".".join(str(b) for b in _swap_word_bytes(hex_addr))


def _parse_ipv6_address(hex_addr: str) -> str:
    """Decode a 32-hex-char ``/proc/net/tcp6`` IPv6 address field.

    Each of the four 32-bit words is byte-swapped *independently* -- the
    16-byte address is deliberately NOT reversed as a single block, which
    would silently produce a wrong (mirrored-word) address.
    """
    words = [hex_addr[i : i + 8] for i in range(0, len(hex_addr), 8)]
    raw = b"".join(_swap_word_bytes(word) for word in words)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse_port(hex_port: str) -> int:
    """Decode a 4-hex-char ``/proc/net/tcp[6]`` port field.

    Plain big-endian hex -- unlike the address field, this must NOT be
    byte-swapped.
    """
    return int(hex_port, 16)


def _parse_address_field(field: str, is_ipv6: bool) -> tuple[str, int]:
    """Split and decode one ``address:port`` field from a ``/proc/net`` row."""
    addr_hex, _, port_hex = field.partition(":")
    address = (
        _parse_ipv6_address(addr_hex) if is_ipv6 else _parse_ipv4_address(addr_hex)
    )
    return address, _parse_port(port_hex)


def _build_uid_to_package_map(
    send_command: Callable[[str], tuple[str, str]],
) -> dict[int, str]:
    """Build a uid -> package_name map from one ``pm list packages -U`` call.

    Cross-referencing every socket's uid to a package name one at a time
    would cost N ADB round trips for N distinct uids; this single call
    avoids that.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).

    Returns:
        A dict mapping uid to package name. Lines that don't parse are
        skipped.
    """
    stdout, stderr = send_command("shell pm list packages -U")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"pm list packages -U warning: {stderr}")

    mapping: dict[int, str] = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        pkg_part, sep, uid_part = line.partition(" uid:")
        if not sep:
            continue
        try:
            uid = int(uid_part.strip())
        except ValueError:
            continue
        mapping[uid] = pkg_part[len("package:") :].strip()

    return mapping


def list_connections(
    send_command: Callable[[str], tuple[str, str]],
) -> list[dict[str, Any]]:
    """List TCP sockets via ``/proc/net/tcp`` and ``/proc/net/tcp6``.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).

    Returns:
        A list of dicts, each with keys ``'protocol'`` (``'tcp'`` or
        ``'tcp6'``), ``'local_address'``, ``'local_port'``,
        ``'remote_address'``, ``'remote_port'``, ``'state'`` (decoded where
        known, else the raw hex code), ``'uid'``, and ``'package_name'``
        (``None`` if the uid has no matching installed package). Empty if
        neither proc file could be read.
    """
    uid_to_package = _build_uid_to_package_map(send_command)

    connections: list[dict[str, Any]] = []
    for proc_path, is_ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        stdout, stderr = send_command(f"shell cat {proc_path}")
        if stderr and is_adb_error_actionable(stderr):
            logger.warning(f"Reading {proc_path} warning: {stderr}")
        if not stdout:
            continue

        lines = stdout.strip().splitlines()
        for line in lines[1:]:  # skip the column-header row
            parts = line.split()
            if len(parts) < 8:
                continue
            try:
                local_addr, local_port = _parse_address_field(parts[1], is_ipv6)
                remote_addr, remote_port = _parse_address_field(parts[2], is_ipv6)
                uid = int(parts[7])
            except (ValueError, IndexError):
                continue

            state_hex = parts[3].upper()
            connections.append(
                {
                    "protocol": "tcp6" if is_ipv6 else "tcp",
                    "local_address": local_addr,
                    "local_port": local_port,
                    "remote_address": remote_addr,
                    "remote_port": remote_port,
                    "state": _TCP_STATES.get(state_hex, state_hex),
                    "uid": uid,
                    "package_name": uid_to_package.get(uid),
                }
            )

    return connections
