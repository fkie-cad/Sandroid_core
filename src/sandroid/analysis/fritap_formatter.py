"""FriTap message formatting for activity log and console output.

Extracts the message parsing and formatting logic from the activity log wrapper,
keeping the FriTap class focused on Frida session management.
"""

import logging

logger = logging.getLogger(__name__)


class FriTapMessageFormatter:
    """Formats Frida message payloads into human-readable strings for display.

    Handles the different content types that friTap emits:
    - console: Log messages from the friTap Frida script
    - datalog: SSL/TLS connection data with addresses/ports
    - keylog: SSLKEYLOGFILE key material
    - error: Frida error messages
    """

    @staticmethod
    def format_message(message: dict, data) -> str | None:
        """Format a Frida message into a display string.

        Args:
            message: The Frida message dict with 'type' and 'payload'.
            data: The raw data bytes from Frida (used for length info).

        Returns:
            A formatted string for display, or None if the message should be skipped.
        """
        msg_type = message.get("type")

        if msg_type == "send":
            return FriTapMessageFormatter._format_send(message, data)
        if msg_type == "error":
            error_msg = message.get("description", str(message))
            return f"[error]ERROR: {error_msg}[/error]"
        return None

    @staticmethod
    def _format_send(message: dict, data) -> str | None:
        """Format a 'send' type Frida message."""
        payload = message.get("payload", {})

        if not isinstance(payload, dict):
            return None

        content_type = payload.get("contentType")

        if content_type == "console":
            return FriTapMessageFormatter._format_console(payload)
        if content_type == "datalog":
            return FriTapMessageFormatter._format_datalog(payload, data)
        if content_type == "keylog":
            return FriTapMessageFormatter._format_keylog(payload)
        return None

    @staticmethod
    def _format_console(payload: dict) -> str | None:
        """Format a console message from friTap."""
        console_msg = payload.get("console", "")
        return console_msg if console_msg else None

    @staticmethod
    def _format_datalog(payload: dict, data) -> str | None:
        """Format an SSL/TLS connection data message."""
        src_addr = payload.get("src_addr", "?")
        dst_addr = payload.get("dst_addr", "?")
        src_port = payload.get("src_port", 0)
        dst_port = payload.get("dst_port", 0)
        func = payload.get("function", "unknown")
        data_len = len(data) if data else 0
        return (
            f"[{func}] {src_addr}:{src_port} → {dst_addr}:{dst_port} ({data_len} bytes)"
        )

    @staticmethod
    def _format_keylog(payload: dict) -> str | None:
        """Format a key extraction message."""
        keylog = payload.get("keylog", "")
        if not keylog:
            return None

        parts = keylog.split(" ")
        if len(parts) >= 2:
            key_type = parts[0]
            key_preview = parts[-1][:16] + "..." if len(parts[-1]) > 16 else parts[-1]
            return f"🔑 {key_type}: {key_preview}"
        return f"🔑 KEY: {keylog[:24]}..." if len(keylog) > 24 else f"🔑 {keylog}"
