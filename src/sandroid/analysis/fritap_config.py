"""friTap interactive configuration UI for TUI and CLI modes.

Extracted from fritap.py to keep the friTap class focused on core functionality.
"""

import logging

import click

from sandroid.core.console import SandroidConsole
from sandroid.services import get_network_capture_service

try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


def _get_display_value(field: str, default):
    """Read a display config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().display, field, default)
    except Exception:
        pass
    return default


#: Toggle: restart a running app so friTap captures from launch (asks first).
_FRESH_LABEL = "Restart the app first (capture from launch)"


def configure_fritap_tui() -> dict | None:
    """Show friTap toggle configuration modal in TUI mode.

    Returns:
        Configuration dict if user confirms, None if cancelled.
    """
    from sandroid.core.ui_request_bus import request_toggle_config

    network_already_running = get_network_capture_service().is_capturing()

    toggle_options = {
        "Verbose Mode (detailed hook output)": False,
        "Debug Mode (Frida debug messages)": False,
        "Show Output in Activity Log": True,
        "Output Keylog (SSLKEYLOGFILE format)": True,
        "Output JSON (structured data)": True,
        _FRESH_LABEL: False,
    }

    if not network_already_running:
        toggle_options["Enable Network Capture (tcpdump)"] = False

    result = request_toggle_config(
        title="friTap Configuration",
        options=toggle_options,
        message="Configure friTap options"
        + (" (network capture already running)" if network_already_running else ""),
        theme="frida",
    )

    if result is None:
        return None

    return {
        "verbose": result.get("Verbose Mode (detailed hook output)", False),
        "debug_output": result.get("Debug Mode (Frida debug messages)", False),
        "show_in_activity_log": result.get("Show Output in Activity Log", False),
        "enable_network_capture": result.get("Enable Network Capture (tcpdump)", False),
        "output_keylog": result.get("Output Keylog (SSLKEYLOGFILE format)", True),
        "output_json": result.get("Output JSON (structured data)", True),
        "fresh": result.get(_FRESH_LABEL, False),
    }


def configure_fritap_cli() -> dict | None:
    """Show friTap interactive configuration in CLI/Rich console mode.

    Returns:
        Configuration dict if user confirms, None if cancelled.
    """
    from sandroid.tui.utils.box_renderer import make_box_line

    console = SandroidConsole.get()

    _DEFAULT_BOX_WIDTH = 60
    BOX_WIDTH = _get_display_value("box_width", _DEFAULT_BOX_WIDTH)
    _box_line = make_box_line(BOX_WIDTH)

    settings = {
        "verbose": False,
        "debug_output": False,
        "show_in_activity_log": True,
        "enable_network_capture": False,
        "output_keylog": True,
        "output_json": True,
        "fresh": False,
    }

    network_already_running = get_network_capture_service().is_capturing()

    while True:
        console.clear()
        _render_config_box(
            console, _box_line, BOX_WIDTH, settings, network_already_running
        )

        try:
            choice = click.getchar().lower()
        except (KeyboardInterrupt, EOFError):
            return None

        if choice in ("\r", "\n"):
            return settings
        if choice in ("\x1b", "q"):
            return None
        if choice == "v":
            settings["verbose"] = not settings["verbose"]
        elif choice == "d":
            settings["debug_output"] = not settings["debug_output"]
        elif choice == "a":
            settings["show_in_activity_log"] = not settings["show_in_activity_log"]
        elif choice == "n" and not network_already_running:
            settings["enable_network_capture"] = not settings["enable_network_capture"]
        elif choice == "k":
            settings["output_keylog"] = not settings["output_keylog"]
        elif choice == "j":
            settings["output_json"] = not settings["output_json"]
        elif choice == "r":
            settings["fresh"] = not settings["fresh"]


def _render_config_box(
    console, _box_line, BOX_WIDTH, settings, network_already_running
):
    """Render the friTap configuration box to the console."""
    console.print(f"[primary]╔{'═' * BOX_WIDTH}╗[/primary]")
    console.print(_box_line("[bold]friTap Configuration[/bold]"))
    console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")

    # Verbose mode option
    verbose_status = (
        "[success]●[/success]" if settings["verbose"] else "[error]○[/error]"
    )
    console.print(
        _box_line(
            f"[accent]\\[V][/accent] Verbose Mode:    {verbose_status} (detailed hook output)",
            align="left",
        )
    )

    # Debug mode option
    debug_status = (
        "[success]●[/success]" if settings["debug_output"] else "[error]○[/error]"
    )
    console.print(
        _box_line(
            f"[accent]\\[D][/accent] Debug Mode:      {debug_status} (Frida debug messages)",
            align="left",
        )
    )

    # Show in activity log option
    activity_status = (
        "[success]●[/success]"
        if settings["show_in_activity_log"]
        else "[error]○[/error]"
    )
    console.print(
        _box_line(
            f"[accent]\\[A][/accent] Activity Log:    {activity_status} (show output in TUI)",
            align="left",
        )
    )

    console.print(f"[primary]╟{'─' * BOX_WIDTH}╢[/primary]")

    # Network capture option
    if network_already_running:
        net_status = "[success]● Running[/success]"
        net_note = "(already active)"
    elif settings["enable_network_capture"]:
        net_status = "[success]● Enabled[/success]"
        net_note = "(will start tcpdump)"
    else:
        net_status = "[error]○ Disabled[/error]"
        net_note = ""
    console.print(
        _box_line(
            f"[accent]\\[N][/accent] Network Capture: {net_status} {net_note}",
            align="left",
        )
    )

    console.print(f"[primary]╟{'─' * BOX_WIDTH}╢[/primary]")

    # Output format options
    keylog_status = (
        "[success]●[/success]" if settings["output_keylog"] else "[error]○[/error]"
    )
    json_status = (
        "[success]●[/success]" if settings["output_json"] else "[error]○[/error]"
    )
    console.print(
        _box_line(
            f"[accent]\\[K][/accent] Keylog Output:   {keylog_status} (SSLKEYLOGFILE format)",
            align="left",
        )
    )
    console.print(
        _box_line(
            f"[accent]\\[J][/accent] JSON Output:     {json_status} (structured data)",
            align="left",
        )
    )

    fresh_status = (
        "[success]●[/success]" if settings.get("fresh") else "[error]○[/error]"
    )
    console.print(
        _box_line(
            f"[accent]\\[R][/accent] Restart App:     {fresh_status} (capture from launch)",
            align="left",
        )
    )

    console.print(f"[primary]╠{'═' * BOX_WIDTH}╣[/primary]")
    console.print(
        _box_line(
            "[success]\\[Enter][/success] Start friTap    [warning]\\[Esc/Q][/warning] Cancel",
            align="left",
        )
    )
    console.print(f"[primary]╚{'═' * BOX_WIDTH}╝[/primary]")
