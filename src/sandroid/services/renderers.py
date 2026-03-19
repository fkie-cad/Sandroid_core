"""Rendering utilities for emulator info, exit summary, and box drawing.

Contains self-contained renderers that were extracted from ``UIService`` so
that the main service module stays focused on UI state management.

Usage::

    from sandroid.services.renderers import (
        EmulatorInfoRenderer,
        ExitSummaryRenderer,
        BoxRenderer,
    )

    EmulatorInfoRenderer.print_emulator_information(info_dict)
    ExitSummaryRenderer.print_exit_summary(tools_used)
"""

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# Try to import wcwidth for Unicode text width calculation
try:
    from wcwidth import wcswidth
except ImportError:

    def wcswidth(s):
        """Fallback if wcwidth not available."""
        return len(s)


# ---------------------------------------------------------------------------
# Compiled regexes (module-level to avoid recompilation)
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_RICH_MARKUP_RE = re.compile(r"\[[a-zA-Z0-9_./#\s]+\]")
_ESCAPED_BRACKET_PLACEHOLDER = "\x00LBRACKET\x00"


# ---------------------------------------------------------------------------
# Box Renderer
# ---------------------------------------------------------------------------


class BoxRenderer:
    """Utility for creating bordered boxes with colored or plain-text borders.

    Both methods are stateless and can be called as class methods.
    """

    @staticmethod
    def create_colored_box(text: str, title: str, border_color: str = "cyan") -> str:
        """Create a bordered box with colored borders and a title section.

        The title gets its own row with a separator line below it.

        Args:
            text: The text to be enclosed in the box.
            title: The title of the box (can include Rich markup).
            border_color: Color for the box borders.

        Returns:
            The formatted box with Rich color markup.
        """

        def strip_rich_markup(s: str) -> str:
            s = s.replace("\\[", _ESCAPED_BRACKET_PLACEHOLDER)
            s = _RICH_MARKUP_RE.sub("", s)
            s = s.replace(_ESCAPED_BRACKET_PLACEHOLDER, "[")
            return s

        def strip_formatting(s: str) -> str:
            s = _ANSI_RE.sub("", s)
            s = strip_rich_markup(s)
            return s

        def cell_width(s: str) -> int:
            w = wcswidth(s)
            return 0 if w < 0 else w

        raw_lines = text.splitlines()
        stripped_lines = [strip_formatting(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [cell_width(ln) for ln in stripped_lines]

        stripped_title = strip_formatting(title)
        title_w = cell_width(stripped_title)

        content_max_width = max(visible_widths) if visible_widths else 0
        inner_width = max(content_max_width, title_w) + 4

        bc = border_color
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        h_line = "\u2500" * inner_width
        top = (
            f"[{bc}]\u250c{h_line}\u2510[/{bc}]\n"
            f"[{bc}]\u2502[/{bc}]{' ' * pad_left}{title}{' ' * pad_right}[{bc}]\u2502[/{bc}]\n"
            f"[{bc}]\u251c{h_line}\u2524[/{bc}]\n"
        )

        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = inner_width - cell_width(stripped)
            pad = max(pad, 0)
            body_parts.append(f"[{bc}]\u2502[/{bc}]{raw}{' ' * pad}[{bc}]\u2502[/{bc}]")
        body = "\n".join(body_parts)

        bottom = f"\n[{bc}]\u2514{h_line}\u2518[/{bc}]"

        return f"{top}{body}{bottom}"

    @staticmethod
    def create_ascii_box(text: str, title: str) -> str:
        """Create an ASCII box with a title.

        Args:
            text: The text to be enclosed in the ASCII box.
            title: The title of the ASCII box.

        Returns:
            The formatted ASCII box.
        """

        def strip_ansi(s: str) -> str:
            return _ANSI_RE.sub("", s)

        def cell_width(s: str) -> int:
            w = wcswidth(s)
            return 0 if w < 0 else w

        raw_lines = text.splitlines()
        stripped_lines = [strip_ansi(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [cell_width(ln) for ln in stripped_lines]
        inner_width = (max(visible_widths) if visible_widths else 0) + 2

        stripped_title = strip_ansi(title)
        title_w = cell_width(stripped_title)
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        h_line = "\u2500" * inner_width
        top = (
            f"\u250c{h_line}\u2510\n"
            f"\u2502{' ' * pad_left}{title}{' ' * pad_right}\u2502\n"
            f"\u251c{h_line}\u2524\n"
        )

        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = inner_width - cell_width(stripped)
            pad = max(pad, 0)
            body_parts.append(f"\u2502{raw}{' ' * pad}\u2502")
        body = "\n".join(body_parts)

        bottom = f"\n\u2514{h_line}\u2518"
        return f"{top}{body}{bottom}"


# ---------------------------------------------------------------------------
# Emulator Info Renderer
# ---------------------------------------------------------------------------


class EmulatorInfoRenderer:
    """Renders emulator / device information in a Rich Panel."""

    @staticmethod
    def print_emulator_information(emulator_info: dict[str, Any]) -> None:
        """Display emulator/device information in a formatted Rich Panel.

        Args:
            emulator_info: Dictionary containing emulator information with keys:
                - emulator_id: AVD name
                - emulator_path: Path to AVD configuration
                - device_time: Current device time
                - device_locale: Device locale setting
                - android_version: Android version string
                - api_level: Android API level
                - network_interfaces: List of (interface, ip) tuples
                - snapshots: List of snapshot dictionaries with 'tag' and 'date'
        """
        from rich.panel import Panel

        try:
            from sandroid.core.console import SandroidConsole

            console = SandroidConsole.get()
        except ImportError:
            from rich.console import Console

            console = Console()

        emulator_id = emulator_info.get("emulator_id", "Unknown")
        emulator_path = emulator_info.get("emulator_path", "Unknown")
        device_time = emulator_info.get("device_time", "Unknown")
        device_locale = emulator_info.get("device_locale", "Unknown")
        android_version = emulator_info.get("android_version", "Unknown")
        api_level = emulator_info.get("api_level", "Unknown")
        network_interfaces = emulator_info.get("network_interfaces", [])
        snapshots = emulator_info.get("snapshots", [])

        info_text = (
            f"[primary]Emulator ID:[/primary] [success]{emulator_id}[/success]\n"
        )
        info_text += (
            f"[primary]Emulator Path:[/primary] [success]{emulator_path}[/success]\n"
        )
        info_text += (
            f"[primary]Device Time:[/primary] [success]{device_time}[/success]\n"
        )
        info_text += (
            f"[primary]Device Locale:[/primary] [success]{device_locale}[/success]\n"
        )
        info_text += (
            f"[primary]Android Version & API Level:[/primary] "
            f"[success]{android_version} (API {api_level})[/success]\n\n"
        )

        info_text += "[warning]Network Interfaces:[/warning]\n"
        for interface, ip in network_interfaces:
            info_text += (
                f"[primary]Interface:[/primary] [success]{interface}[/success] "
                f"([info]{ip}[/info])\n"
            )

        if snapshots:
            info_text += "\n[warning]Available Snapshots:[/warning]\n"
            for snapshot in snapshots:
                info_text += (
                    f"[success]{snapshot['date']}[/success] - "
                    f"[primary]{snapshot['tag']}[/primary]\n"
                )

        panel = Panel(
            info_text.strip(),
            title="[accent]Emulator Information[/accent]",
            border_style="cyan",
            expand=False,
        )
        console.print(panel)


# ---------------------------------------------------------------------------
# Exit Summary Renderer
# ---------------------------------------------------------------------------


class ExitSummaryRenderer:
    """Renders the session-complete exit summary."""

    @staticmethod
    def print_exit_summary(tools_used: dict[str, Any] | None = None) -> None:
        """Print summary of results folder and generated files on exit.

        Args:
            tools_used: Optional dictionary of tools used and their files.
        """
        try:
            from sandroid.core.console import SandroidConsole

            console = SandroidConsole.get()
        except ImportError:
            from rich.console import Console

            console = Console()

        results_path = os.getenv("SESSION_PATH", os.getenv("RESULTS_PATH", "results/"))
        tools = tools_used or {}

        console.print()
        console.print(
            "[bold cyan]\u2550\u2550\u2550 Sandroid Session Complete \u2550\u2550\u2550[/bold cyan]"
        )
        console.print()
        console.print(f"[green]Results saved to:[/green] [bold]{results_path}[/bold]")

        if tools:
            console.print()
            console.print("[cyan]Generated files by tool:[/cyan]")
            for tool_name, tool_info in tools.items():
                if isinstance(tool_info, dict):
                    files = tool_info.get("files", [])
                else:
                    # Support ToolUsage-like objects
                    files = [getattr(tool_info, "file_path", None)]

                if files:
                    console.print(f"  [magenta]{tool_name}:[/magenta]")
                    for file_path in files:
                        if file_path and os.path.exists(file_path):
                            rel_path = os.path.relpath(file_path, results_path)
                            console.print(f"    \u2022 {rel_path}")

        console.print()


# ---------------------------------------------------------------------------
# Device Info Renderer
# ---------------------------------------------------------------------------


class DeviceInfoRenderer:
    """Renders comprehensive device information for TUI and plain text output."""

    @staticmethod
    def format_for_tui(info: dict[str, Any]) -> str:
        """Format device info as Rich markup for TUI display.

        Args:
            info: Dictionary from DeviceService.get_device_info()

        Returns:
            Rich markup formatted string with sections.
        """
        lines: list[str] = []
        is_emulator = info.get("is_emulator", True)

        # Device Overview section
        lines.append("[bold #6ba3ff]=== Device Overview ===[/bold #6ba3ff]")
        device_type = info.get("device_type", "unknown")
        type_label = "Emulator" if is_emulator else "Physical Device"
        lines.append(f"  [bold]Type:[/bold]   {type_label}")
        lines.append(f"  [bold]Name:[/bold]   {info.get('device_name', 'Unknown')}")
        lines.append(f"  [bold]Serial:[/bold] {info.get('device_serial', 'Unknown')}")

        if not is_emulator:
            brand = info.get("device_brand")
            model = info.get("device_model")
            if brand:
                lines.append(f"  [bold]Brand:[/bold]  {brand}")
            if model:
                lines.append(f"  [bold]Model:[/bold]  {model}")

        if is_emulator:
            path = info.get("device_path")
            if path:
                lines.append(f"  [bold]Path:[/bold]   {path}")

        lines.append("")

        # System section
        lines.append("[bold #6ba3ff]=== System ===[/bold #6ba3ff]")
        lines.append(
            f"  [bold]Android:[/bold] {info.get('android_version', 'Unknown')}"
            f" (API {info.get('api_level', 'Unknown')})"
        )
        lines.append(f"  [bold]Time:[/bold]    {info.get('device_time', 'Unknown')}")
        lines.append(f"  [bold]Locale:[/bold]  {info.get('device_locale', 'Unknown')}")
        lines.append("")

        # Location section
        lines.append("[bold #6ba3ff]=== Location ===[/bold #6ba3ff]")
        geo = info.get("geo_location")
        if geo:
            lines.append(f"  [bold]Latitude:[/bold]  {geo.get('latitude', 'N/A')}")
            lines.append(f"  [bold]Longitude:[/bold] {geo.get('longitude', 'N/A')}")
            provider = geo.get("provider", "")
            if provider:
                lines.append(f"  [bold]Provider:[/bold]  {provider}")
            accuracy = geo.get("accuracy")
            if accuracy is not None:
                lines.append(f"  [bold]Accuracy:[/bold]  {accuracy}m")
        else:
            lines.append("  [dim]Not available[/dim]")
        lines.append("")

        # Network section
        lines.append("[bold #6ba3ff]=== Network ===[/bold #6ba3ff]")
        network = info.get("network_interfaces", [])
        if network:
            for iface, ip in network:
                lines.append(f"  [bold]{iface}:[/bold] {ip}")
        else:
            lines.append("  [dim]No interfaces detected[/dim]")

        # Snapshots section (emulator only)
        if is_emulator:
            snapshots = info.get("snapshots", [])
            lines.append("")
            lines.append("[bold #6ba3ff]=== Snapshots ===[/bold #6ba3ff]")
            if snapshots:
                for snap in snapshots:
                    tag = snap.get("tag", "unknown")
                    date = snap.get("date", "")
                    if date:
                        lines.append(f"  {tag}  [dim]({date})[/dim]")
                    else:
                        lines.append(f"  {tag}")
            else:
                lines.append("  [dim]None available[/dim]")

        return "\n".join(lines)

    @staticmethod
    def format_plain_text(info: dict[str, Any]) -> str:
        """Format device info as plain text.

        Args:
            info: Dictionary from DeviceService.get_device_info()

        Returns:
            Plain text formatted string.
        """
        lines: list[str] = []
        is_emulator = info.get("is_emulator", True)

        # Device Overview
        type_label = "Emulator" if is_emulator else "Physical Device"
        lines.append(f"Type:            {type_label}")
        lines.append(f"Name:            {info.get('device_name', 'Unknown')}")
        lines.append(f"Serial:          {info.get('device_serial', 'Unknown')}")

        if not is_emulator:
            brand = info.get("device_brand")
            model = info.get("device_model")
            if brand:
                lines.append(f"Brand:           {brand}")
            if model:
                lines.append(f"Model:           {model}")

        if is_emulator:
            path = info.get("device_path")
            if path:
                lines.append(f"Path:            {path}")

        # System
        lines.append(f"Android Version: {info.get('android_version', 'Unknown')}")
        lines.append(f"API Level:       {info.get('api_level', 'Unknown')}")
        lines.append(f"Device Time:     {info.get('device_time', 'Unknown')}")
        lines.append(f"Locale:          {info.get('device_locale', 'Unknown')}")

        # Location
        geo = info.get("geo_location")
        if geo:
            lines.append(f"Latitude:        {geo.get('latitude', 'N/A')}")
            lines.append(f"Longitude:       {geo.get('longitude', 'N/A')}")
            provider = geo.get("provider", "")
            if provider:
                lines.append(f"Provider:        {provider}")
            accuracy = geo.get("accuracy")
            if accuracy is not None:
                lines.append(f"Accuracy:        {accuracy}m")
        else:
            lines.append("Location:        Not available")

        # Network
        network = info.get("network_interfaces", [])
        if network:
            lines.append("")
            lines.append("Network Interfaces:")
            for iface, ip in network:
                lines.append(f"  {iface}: {ip}")
        else:
            lines.append("")
            lines.append("Network Interfaces: None detected")

        # Snapshots (emulator only)
        if is_emulator:
            snapshots = info.get("snapshots", [])
            if snapshots:
                lines.append("")
                lines.append("Snapshots:")
                for snap in snapshots:
                    tag = snap.get("tag", "unknown")
                    date = snap.get("date", "")
                    lines.append(f"  {tag}  ({date})" if date else f"  {tag}")
            else:
                lines.append("")
                lines.append("Snapshots: None available")

        return "\n".join(lines)


__all__ = [
    "BoxRenderer",
    "DeviceInfoRenderer",
    "EmulatorInfoRenderer",
    "ExitSummaryRenderer",
]
