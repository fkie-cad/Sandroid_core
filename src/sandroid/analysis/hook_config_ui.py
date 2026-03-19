"""UI components for hook and AppProfiler configuration.

Provides interactive UI classes for configuring dexray-intercept hooks
and AppProfiler settings, supporting both TUI (Textual) and Rich console modes.

Data-model classes (``HookConfiguration``, ``HOOK_GROUPS``) live in
:mod:`sandroid.analysis.hook_config` and are re-exported here for backward
compatibility.
"""

import logging
from dataclasses import dataclass
from typing import Any

import click

# Re-export data-model symbols for backward compatibility.
from sandroid.analysis.hook_config import (
    HOOK_GROUPS,
    HookConfiguration,
)
from sandroid.core.console import SandroidConsole
from sandroid.core.ui_request_bus import UIRequestBus, request_toggle_config
from sandroid.tui.utils.box_renderer import box_line as _box_line
from sandroid.tui.utils.box_renderer import strip_color_codes as _strip_color_codes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Setting Definitions (data-driven _draw_box)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SettingDef:
    """Single boolean toggle shown in the AppProfiler config box."""

    key: str
    label: str
    hotkey: str
    enabled_text: str
    disabled_text: str
    description: str
    extra_line_fn: Any = None  # Callable[[dict], str | None] | None


_SETTING_DEFINITIONS: list[_SettingDef] = [
    _SettingDef(
        key="enable_stacktrace",
        label="Stack Traces:     ",
        hotkey="s",
        enabled_text="Enabled",
        disabled_text="Disabled",
        description="Show full call stacks for hook invocations (helps identify caller)",
    ),
    _SettingDef(
        key="deactivate_unlink",
        label="Deactivate Unlink:",
        hotkey="u",
        enabled_text="Yes (keep files)",
        disabled_text="No (normal behavior)",
        description="Prevent file unlink operations (keeps files from being deleted)",
    ),
    _SettingDef(
        key="enable_fritap",
        label="FriTap:           ",
        hotkey="f",
        enabled_text="Enabled",
        disabled_text="Disabled",
        description="Enable TLS key extraction and traffic capture",
        extra_line_fn=lambda s: f"Output Dir: {s['fritap_output_dir']}",
    ),
]

# Hotkey -> setting key lookup built from definitions.
_HOTKEY_MAP: dict[str, str] = {d.hotkey: d.key for d in _SETTING_DEFINITIONS}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_W = 76  # standard box width


def _box_header(
    console: SandroidConsole, title: str, *, style: str = "primary"
) -> None:
    """Print a single-line box header: top border + title + bottom border."""
    console.print(f"\n[{style}]\u2554{'═' * _W}\u2557[/{style}]")
    console.print(_box_line(f"[bold]{title}[/bold]", _W, border_style=style))
    console.print(f"[{style}]\u255a{'═' * _W}\u255d[/{style}]")


def _box_section_start(console: SandroidConsole) -> None:
    console.print(f"[primary]\u2554{'═' * _W}\u2557[/primary]")


def _box_divider(console: SandroidConsole) -> None:
    console.print(f"[primary]\u2560{'═' * _W}\u2563[/primary]")


def _box_end(console: SandroidConsole) -> None:
    console.print(f"[primary]\u255a{'═' * _W}\u255d[/primary]\n")


# ---------------------------------------------------------------------------
# HookConfigurationUI
# ---------------------------------------------------------------------------


class HookConfigurationUI:
    """Interactive UI for hook selection in dexray-intercept.

    Supports TUI mode (UIRequestBus) and Rich console mode.
    """

    def __init__(self, hook_config: HookConfiguration):
        self._hook_config = hook_config
        self._hook_groups = HOOK_GROUPS

    def show_selection(self) -> dict[str, bool] | None:
        """Show interactive hook selection dialog.

        Returns:
            Updated hook configuration dict, or None if cancelled.
        """
        bus = UIRequestBus.get()
        if bus.has_active_handler():
            return self._show_tui()
        return self._show_rich()

    # -- TUI mode -----------------------------------------------------------

    def _show_tui(self) -> dict[str, bool] | None:
        current_hooks = self._hook_config.get_hooks()
        hook_toggles: dict[str, bool] = {}
        for group_key, group_info in self._hook_groups.items():
            group_enabled = any(
                current_hooks.get(h, False) for h in group_info["hooks"]
            )
            hook_toggles[f"{group_info['name']} ({group_info['description']})"] = (
                group_enabled
            )

        result = request_toggle_config(
            title="Dexray-Intercept Hook Configuration",
            options=hook_toggles,
            message="Toggle hook categories on/off",
            theme="frida",
        )
        if result is None:
            return None

        updated_hooks = current_hooks.copy()
        for group_key, group_info in self._hook_groups.items():
            key = f"{group_info['name']} ({group_info['description']})"
            if key in result:
                for hook in group_info["hooks"]:
                    updated_hooks[hook] = result[key]
        return updated_hooks

    # -- Rich console mode --------------------------------------------------

    def _show_rich(self) -> dict[str, bool] | None:
        console = SandroidConsole.get()
        current_hooks = self._hook_config.get_hooks()
        updated_hooks = current_hooks.copy()

        self._display_hooks(updated_hooks, self._hook_groups, console)

        # Prompt: customize or accept?
        _box_section_start(console)
        console.print(_box_line("[bold]Would you like to customize hooks?[/bold]"))
        _box_divider(console)
        console.print(
            _box_line(
                "[accent]\\[y][/accent] Customize hook selection (toggle categories by number)",
                align="left",
            )
        )
        console.print(
            _box_line(
                "[accent]\\[n][/accent] Use current configuration (press [success]ENTER[/success] to accept default)",
                align="left",
            )
        )
        _box_end(console)

        try:
            choice = click.getchar().lower()
            if choice not in ["y", "yes"]:
                enabled_count = sum(1 for v in updated_hooks.values() if v)
                console.print(
                    f"\n[success]\u2713 Using current configuration ({enabled_count} hook categories enabled)[/success]\n"
                )
                return updated_hooks
        except (KeyboardInterrupt, EOFError):
            console.print("\n[warning]Using default configuration[/warning]\n")
            return updated_hooks

        # Interactive toggle loop
        while True:
            self._display_hooks(updated_hooks, self._hook_groups, console)
            _box_section_start(console)
            console.print(_box_line("[bold]Toggle Hook Categories[/bold]"))
            _box_divider(console)
            console.print(
                _box_line(
                    f"[accent]\\[1-{len(self._hook_groups)}][/accent] Toggle a hook category on/off",
                    align="left",
                )
            )
            console.print(
                _box_line(
                    "[accent]\\[a][/accent]   Enable all hook categories", align="left"
                )
            )
            console.print(
                _box_line(
                    "[accent]\\[d][/accent]   Disable all hook categories", align="left"
                )
            )
            console.print(
                _box_line(
                    "[accent]\\[q][/accent]   Finish and save configuration",
                    align="left",
                )
            )
            _box_end(console)

            console.print("[success]\u25ba Enter your choice:[/success] ", end="")

            try:
                choice = click.getchar().lower()
                console.print(f"[accent]{choice}[/accent]")

                if choice == "q":
                    break
                if choice == "a":
                    for group_info in self._hook_groups.values():
                        for hook in group_info["hooks"]:
                            updated_hooks[hook] = True
                    console.print("[success]\u2713 All hooks enabled[/success]\n")
                elif choice == "d":
                    for group_info in self._hook_groups.values():
                        for hook in group_info["hooks"]:
                            updated_hooks[hook] = False
                    console.print("[warning]\u2713 All hooks disabled[/warning]\n")
                elif choice.isdigit() and 1 <= int(choice) <= len(self._hook_groups):
                    idx = int(choice) - 1
                    group_key = list(self._hook_groups.keys())[idx]
                    group_info = self._hook_groups[group_key]
                    group_enabled = any(
                        updated_hooks.get(hook, False) for hook in group_info["hooks"]
                    )
                    new_state = not group_enabled
                    for hook in group_info["hooks"]:
                        updated_hooks[hook] = new_state
                    state_text = (
                        "[success]enabled[/success]"
                        if new_state
                        else "[error]disabled[/error]"
                    )
                    console.print(
                        f"[primary]\u2713 {group_info['name']} {state_text}[/primary]\n"
                    )
                else:
                    console.print("[error]Invalid choice. Please try again.[/error]\n")
            except (KeyboardInterrupt, EOFError):
                console.print(
                    "\n[warning]Configuration cancelled. Using previous settings.[/warning]\n"
                )
                return current_hooks

        # Final summary
        enabled_hooks = [h for h, on in updated_hooks.items() if on]
        console.print(f"\n[success]\u2554{'═' * _W}\u2557[/success]")
        console.print(
            _box_line("[bold]Configuration Saved[/bold]", border_style="success")
        )
        console.print(f"[success]\u255a{'═' * _W}\u255d[/success]\n")
        if enabled_hooks:
            console.print(
                f"[success]\u2713 {len(enabled_hooks)} hook categories enabled:[/success]"
            )
            for hook in enabled_hooks:
                console.print(
                    f"  [success]\u25cf[/success] {hook.replace('_', ' ').title()}"
                )
        else:
            console.print(
                "[warning]! Warning: No hooks enabled. Dexray-intercept will run but won't capture events.[/warning]"
            )
        console.print()
        return updated_hooks

    def _display_hooks(
        self,
        hooks: dict[str, bool],
        groups: dict[str, dict[str, Any]],
        console: SandroidConsole,
    ) -> None:
        """Display hooks with visual status indicators."""
        _box_header(console, "Dexray-Intercept Hook Configuration")
        console.print()

        enabled_count = sum(
            1 for g in groups.values() for h in g["hooks"] if hooks.get(h, False)
        )
        total = sum(len(g["hooks"]) for g in groups.values())
        console.print(
            f"Status: [success]{enabled_count}[/success]/{total} hook categories enabled\n"
        )

        for idx, (group_key, group_info) in enumerate(groups.items(), 1):
            group_enabled = any(hooks.get(h, False) for h in group_info["hooks"])
            icon = (
                "[success]\u25cf[/success]"
                if group_enabled
                else "[error]\u25cb[/error]"
            )
            status = "[success]ON [/success]" if group_enabled else "[error]OFF[/error]"
            name = group_info["name"]
            pad = " " * max(0, 35 - len(name))

            console.print(
                f"[accent]\\[{idx}][/accent] {icon} [bold]{name}[/bold]{pad}\\[{status}]"
            )
            console.print(f"    [primary]{group_info['description']}[/primary]")
            hooks_display = [
                f"[success]{h.replace('_', ' ').title()}[/success]"
                if hooks.get(h, False)
                else f"[error]{h.replace('_', ' ').title()}[/error]"
                for h in group_info["hooks"]
            ]
            console.print(f"    Hooks: {', '.join(hooks_display)}")
            console.print()


# ---------------------------------------------------------------------------
# AppProfilerConfigUI
# ---------------------------------------------------------------------------


class AppProfilerConfigUI:
    """Interactive UI for AppProfiler configuration.

    Supports TUI mode (UIRequestBus) and Rich console mode for configuring
    stack traces, unlink deactivation, FriTap, and custom scripts.
    """

    # Setting descriptions for display (kept for external consumers)
    DESCRIPTIONS: dict[str, str] = {d.key: d.description for d in _SETTING_DEFINITIONS}
    DESCRIPTIONS["fritap_output_dir"] = (
        "Directory for fritap output files (relative to dexray_intercept/)"
    )
    DESCRIPTIONS["custom_scripts"] = (
        "Additional Frida scripts to load alongside dexray-intercept"
    )

    def __init__(self, initial_settings: dict[str, Any] | None = None):
        self._settings: dict[str, Any] = {
            "enable_stacktrace": False,
            "deactivate_unlink": False,
            "enable_fritap": False,
            "fritap_output_dir": "fritap_output",
            "custom_scripts": [],
        }
        if initial_settings:
            for key in self._settings:
                if key in initial_settings:
                    self._settings[key] = initial_settings[key]

    def show_configuration(self) -> dict[str, Any] | None:
        """Show interactive configuration dialog.

        Returns:
            Configuration dict, or None if cancelled.
        """
        bus = UIRequestBus.get()
        if bus.has_active_handler():
            return self._show_tui()
        return self._show_rich()

    # -- TUI mode -----------------------------------------------------------

    def _show_tui(self) -> dict[str, Any] | None:
        toggle_options = {
            "Stack Traces (show call stacks for hook invocations)": self._settings[
                "enable_stacktrace"
            ],
            "Deactivate Unlink (keep files from being deleted)": self._settings[
                "deactivate_unlink"
            ],
            "Enable FriTap (TLS key extraction and traffic capture)": self._settings[
                "enable_fritap"
            ],
        }
        result = request_toggle_config(
            title="AppProfiler Configuration",
            options=toggle_options,
            message="Configure dexray-intercept options.\nAdvanced options (custom scripts, FriTap dir) use defaults.",
            theme="frida",
        )
        if result is None:
            return None
        return {
            "enable_stacktrace": result.get(
                "Stack Traces (show call stacks for hook invocations)", False
            ),
            "deactivate_unlink": result.get(
                "Deactivate Unlink (keep files from being deleted)", False
            ),
            "enable_fritap": result.get(
                "Enable FriTap (TLS key extraction and traffic capture)", False
            ),
            "fritap_output_dir": self._settings["fritap_output_dir"],
            "custom_scripts": self._settings["custom_scripts"],
        }

    # -- Rich console mode --------------------------------------------------

    def _show_rich(self) -> dict[str, Any] | None:
        import os

        console = SandroidConsole.get()
        settings = self._settings.copy()
        settings["custom_scripts"] = list(self._settings["custom_scripts"])

        while True:
            click.clear()
            self._draw_box(settings, console)
            console.print("\n[primary]Your choice:[/primary] ", end="")
            choice = click.getchar().lower()

            if choice in ("\r", "\n"):
                break
            if choice == "\x1b":
                console.print(
                    "\n[warning]Configuration cancelled. Using previous settings.[/warning]\n"
                )
                return None

            if choice in _HOTKEY_MAP:
                setting_key = _HOTKEY_MAP[choice]
                if setting_key == "enable_fritap" and not settings["enable_fritap"]:
                    settings["enable_fritap"] = True
                    self._prompt_network_capture(console)
                else:
                    settings[setting_key] = not settings[setting_key]
            elif choice == "d":
                console.print(
                    "\n[primary]Enter FriTap output directory (relative to dexray_intercept/):[/primary]"
                )
                console.print(f"[dim]Current: {settings['fritap_output_dir']}[/dim]")
                console.print(
                    "[dim]Press Enter to keep current, or type new path:[/dim]"
                )
                new_dir = input("\u00bb ").strip()
                if new_dir:
                    settings["fritap_output_dir"] = new_dir
            elif choice == "c":
                console.print("\n[primary]Enter path to custom Frida script:[/primary]")
                script_path = input("\u00bb ").strip()
                if script_path:
                    if os.path.exists(script_path):
                        settings["custom_scripts"].append(script_path)
                        console.print(
                            f"[success]\u2713 Script added: {script_path}[/success]"
                        )
                    else:
                        console.print(
                            f"[error]\u2717 File not found: {script_path}[/error]"
                        )
                    input("\nPress Enter to continue...")
            elif choice == "r":
                if settings["custom_scripts"]:
                    console.print("\n[primary]Custom Scripts:[/primary]")
                    for i, script in enumerate(settings["custom_scripts"], 1):
                        console.print(f"[accent]{i}.[/accent] {script}")
                    console.print(
                        "\n[primary]Enter number to remove (or press Enter to cancel):[/primary]"
                    )
                    choice_str = input("\u00bb ").strip()
                    if choice_str.isdigit():
                        idx = int(choice_str) - 1
                        if 0 <= idx < len(settings["custom_scripts"]):
                            removed = settings["custom_scripts"].pop(idx)
                            console.print(
                                f"[success]\u2713 Removed: {removed}[/success]"
                            )
                            input("\nPress Enter to continue...")

        # Final summary
        click.clear()
        console.print(f"\n[success]\u2554{'═' * _W}\u2557[/success]")
        console.print(
            _box_line("[bold]Configuration Saved[/bold]", border_style="success")
        )
        console.print(f"[success]\u255a{'═' * _W}\u255d[/success]\n")

        enabled_features: list[str] = []
        if settings["enable_stacktrace"]:
            enabled_features.append("Stack Traces")
        if settings["deactivate_unlink"]:
            enabled_features.append("Deactivate Unlink")
        if settings["enable_fritap"]:
            enabled_features.append(f"FriTap (output: {settings['fritap_output_dir']})")
        if settings["custom_scripts"]:
            enabled_features.append(
                f"{len(settings['custom_scripts'])} Custom Script(s)"
            )

        if enabled_features:
            console.print("[success]\u2713 Enabled features:[/success]")
            for feature in enabled_features:
                console.print(f"  [success]\u25cf[/success] {feature}")
        else:
            console.print(
                "[primary]Using default configuration (no optional features enabled)[/primary]"
            )
        console.print()
        return settings

    @staticmethod
    def _prompt_network_capture(console: SandroidConsole) -> None:
        """Prompt about network capture when enabling FriTap."""
        try:
            from sandroid.core.toolbox import Toolbox

            if not Toolbox.is_capturing_network():
                console.print(f"\n[warning]\u2554{'═' * 74}\u2557[/warning]")
                console.print(
                    "[warning]\u2551[/warning] [accent]Network capture is not currently active[/accent]"
                    + " " * 32
                    + "[warning]\u2551[/warning]"
                )
                console.print(
                    "[warning]\u2551[/warning] [dim]FriTap extracts TLS keys for decrypting HTTPS traffic.[/dim]"
                    + " " * 16
                    + "[warning]\u2551[/warning]"
                )
                console.print(
                    "[warning]\u2551[/warning] [dim]It works best when combined with network packet capture.[/dim]"
                    + " " * 13
                    + "[warning]\u2551[/warning]"
                )
                console.print(f"[warning]\u255a{'═' * 74}\u255d[/warning]")
                console.print(
                    "[primary]Would you like to enable network capture?[/primary]"
                )
                console.print("[accent]  [y][/accent] Yes, enable network capture")
                console.print("[dim]  [n][/dim] No, continue with FriTap only")

                if click.getchar().lower() == "y":
                    console.print(
                        "\n[success]Network capture will be started with FriTap.[/success]"
                    )
                    console.print(
                        "[dim]Note: You'll need to start network capture from the main menu (press 'w')[/dim]"
                    )
                else:
                    console.print(
                        "\n[dim]FriTap will be enabled without network capture.[/dim]"
                    )
                input("\nPress Enter to continue...")
        except ImportError:
            pass

    def _draw_box(self, settings: dict[str, Any], console: SandroidConsole) -> None:
        """Draw the configuration interface box (data-driven)."""
        _box_section_start(console)
        console.print(_box_line("[bold]AppProfiler Configuration[/bold]", _W))
        console.print(
            _box_line(
                "[accent]Press [success]Enter[/success] to use defaults, or configure options below[/accent]",
                _W,
            )
        )
        _box_divider(console)

        # Render each boolean setting from definitions
        for defn in _SETTING_DEFINITIONS:
            value = settings.get(defn.key, False)
            status = "[success]\u2713[/success]" if value else " "
            display_text = defn.enabled_text if value else defn.disabled_text
            console.print(
                _box_line(
                    f"\\[{status}] {defn.label} [accent]{display_text}[/accent]",
                    _W,
                    align="left",
                )
            )
            console.print(
                _box_line(f"    [dim]{defn.description}[/dim]", _W, align="left")
            )
            if defn.extra_line_fn is not None:
                extra = defn.extra_line_fn(settings)
                if extra is not None:
                    console.print(_box_line(f"    {extra}", _W, align="left"))
            console.print(_box_line("", _W))

        # Custom scripts
        script_count = len(settings["custom_scripts"])
        script_display = f"{script_count} script(s)" if script_count > 0 else "None"
        console.print(
            _box_line(
                f"Custom Scripts:    [accent]{script_display}[/accent]",
                _W,
                align="left",
            )
        )
        if script_count > 0:
            for i, script in enumerate(settings["custom_scripts"][:3], 1):
                console.print(
                    _box_line(f"    {i}. {script.split('/')[-1]}", _W, align="left")
                )
            if script_count > 3:
                console.print(
                    _box_line(f"    ... and {script_count - 3} more", _W, align="left")
                )

        # Controls
        _box_divider(console)
        console.print(
            _box_line(
                "\\[S] Toggle Stack Traces  \\[U] Toggle Unlink  \\[F] Toggle FriTap",
                _W,
                align="left",
            )
        )
        console.print(
            _box_line(
                "\\[D] Set FriTap Dir  \\[C] Add Custom Script  \\[R] Remove Script",
                _W,
                align="left",
            )
        )
        console.print(
            _box_line(
                "[success]\\[Enter][/success] Continue  [error]\\[Esc][/error] Cancel",
                _W,
                align="left",
            )
        )
        console.print(f"[primary]\u255a{'═' * _W}\u255d[/primary]")


# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------

__all__ = [
    "HOOK_GROUPS",
    "AppProfilerConfigUI",
    "HookConfiguration",
    "HookConfigurationUI",
]
