"""Menu panel widget using MenuController."""

import os
import re

from textual.containers import ScrollableContainer
from textual.reactive import reactive
from textual.widgets import Static

from sandroid.core.enums import ViewMode
from sandroid.core.menu_controller import ActionCategory, MenuController
from sandroid.services import (
    get_emulator_service,
    get_network_capture_service,
    get_objection_service,
    get_spotlight_service,
    get_task_service,
)
from sandroid.tui.themes import FIXED_COLORS


class MenuPanel(ScrollableContainer):
    """Scrollable menu panel displaying actions from MenuController.

    Uses the shared MenuController to display actions available
    in the current view, grouped by category. Colors are pulled
    from the current theme for dynamic theme switching.
    """

    current_view = reactive(ViewMode.FORENSIC.value)

    def __init__(self, **kwargs):
        """Initialize the menu panel."""
        super().__init__(**kwargs)
        self._controller = MenuController.get()

    def compose(self):
        """Compose the menu panel."""
        yield Static("Sandroid Interactive Menu", id="menu-title")
        yield Static("", id="menu-content")

    def on_mount(self) -> None:
        """Update menu on mount."""
        self.update_menu()

    def watch_current_view(self, view: str) -> None:
        """React to view changes."""
        self.update_menu()

    # Regex for finding [key] patterns in inline text
    _KEY_BRACKET_RE = re.compile(r"\[([^\]]+)\]")

    # Rich markup patterns to skip (not keyboard shortcuts)
    _RICH_MARKUP_PREFIXES = (
        "#",
        "/",
        "bold",
        "dim",
        "italic",
        "warning",
        "success",
        "error",
        "info",
    )

    def _format_inline_text(self, text: str, colors: dict, valid: bool = True) -> str:
        """Format inline text with key highlighting.

        Converts text like "[r]ecord an action" or "e[x]port action" to
        Rich markup with highlighted keys.

        Args:
            text: Inline text with bracketed keys (e.g., "[r]ecord")
            colors: Theme color dictionary
            valid: Whether the action is available

        Returns:
            Rich-formatted string with key highlighting
        """
        if not valid:
            # For unavailable actions, escape brackets so [d] displays literally
            # instead of being interpreted as Rich markup
            escaped = text.replace("[", "\\[")
            return escaped

        def replace_key(match):
            key = match.group(1)

            # Skip Rich markup patterns - return unchanged
            if key.startswith(self._RICH_MARKUP_PREFIXES):
                return match.group(0)
            # Skip style combinations like "bold #color" or "bold red"
            if " " in key and not key.startswith(("Shift+", "Ctrl+")):
                return match.group(0)

            # Style brackets and key separately to avoid Rich markup parsing issues
            return f"[{colors['key']}]\\[[/][bold {colors['key']}]{key}[/][{colors['key']}]][/][{colors['text']}]"

        result = self._KEY_BRACKET_RE.sub(replace_key, text)
        return f"[{colors['text']}]{result}[/]"

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for menu rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",  # Headers
            "key": "#ff00ff",  # Key brackets
            "text": "#e5e9f0",  # Main text
            "text_muted": "#8f9bb3",  # Dimmed text
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["key"] = theme.key_color
                colors["text"] = theme.text
                colors["text_muted"] = theme.text_muted
        except Exception:
            pass

        return colors

    def _has_spotlight_app(self) -> bool:
        """Check if a spotlight app is set (attach or spawn mode).

        Returns:
            True if a spotlight app is set, False otherwise
        """
        try:
            spotlight = get_spotlight_service()
            # Check both attach and spawn modes
            attach_app = spotlight.get_app_tuple()
            spawn_app = spotlight.get_spawn_package()

            return bool(attach_app or spawn_app)
        except Exception:
            return False

    def _is_spawn_mode(self) -> bool:
        """Check if spawn mode is active.

        Returns:
            True if spawn mode is active, False if attach mode
        """
        try:
            return get_spotlight_service().is_spawn_mode()
        except Exception:
            return False

    def update_menu(self, view: str | ViewMode = None) -> None:
        """Update menu content based on current view.

        Args:
            view: Optional view to switch to (ViewMode or string)
        """
        if view:
            # Ensure view is a string for MenuController compatibility
            self.current_view = view.value if isinstance(view, ViewMode) else view

        content = self._build_menu_content()
        try:
            menu_content = self.query_one("#menu-content", Static)
            menu_content.update(content)
        except Exception:
            pass

    def _get_dynamic_action_text(self, action, colors: dict) -> tuple[str, bool]:
        """Get dynamic text for actions that toggle on/off.

        For actions like FriTap, dexray, trigdroid, network capture, screen recording,
        we show "stop X on app_name" when running.

        Args:
            action: The action to check
            colors: Theme color dictionary

        Returns:
            Tuple of (display_text, is_running) where display_text is the
            potentially modified text and is_running indicates if task is active
        """
        try:
            # Use warning color from FIXED_COLORS for consistency
            warn_color = FIXED_COLORS.get("warning_status", "#facc15")

            # Map action names to their background task names
            task_mapping = {
                "fritap": "fritap",
                "dexray": "dexray-intercept",
                "trigdroid": "trigdroid_bypass",
                "network_capture": "network",
                "screen_record": None,  # Uses EmulatorService.is_recording()
            }

            task_name = task_mapping.get(action.name)

            # Handle screen recording separately (not a background task)
            if action.name == "screen_record":
                emulator_service = get_emulator_service()
                if emulator_service.is_recording():
                    recording_file = emulator_service.get_recording_file()
                    filename = (
                        os.path.basename(recording_file)
                        if recording_file
                        else "recording"
                    )
                    return (
                        f"stop [g]rabbing video of screen ([{warn_color}]{filename}[/])",
                        True,
                    )
                return action.inline_text or action.display_name, False

            # Handle network capture
            if action.name == "network_capture":
                network_service = get_network_capture_service()
                if network_service.is_capturing():
                    capture_file = network_service.get_capture_file()
                    filename = (
                        os.path.basename(capture_file) if capture_file else "capture"
                    )
                    return (
                        f"stop [w]riting network capture ([{warn_color}]{filename}[/])",
                        True,
                    )
                return action.inline_text or action.display_name, False

            # Handle background tasks (fritap, dexray, trigdroid)
            if task_name and get_task_service().is_running(task_name):
                task = get_task_service().get_task(task_name)
                app_name = task.app_name if task and task.app_name else "app"

                if action.name == "fritap":
                    return f"stop friTap [h]ooking on [{warn_color}]{app_name}[/]", True
                if action.name == "dexray":
                    return (
                        f"stop [m]alware monitor on [{warn_color}]{app_name}[/]",
                        True,
                    )
                if action.name == "trigdroid":
                    return (
                        f"stop [t]rigdroid on [{warn_color}]{app_name}[/]",
                        True,
                    )

            # Handle objection - show "resume" when session is minimized
            if action.name == "objection":
                if get_objection_service().has_session():
                    return (
                        f"resume o[b]jection session ([{warn_color}]minimized[/])",
                        True,
                    )

            return action.inline_text or action.display_name, False

        except Exception:
            return action.inline_text or action.display_name, False

    def _build_menu_content(self) -> str:
        """Build menu content from MenuController.

        Returns:
            Formatted menu string for Textual
        """
        colors = self._get_theme_colors()
        lines = [""]

        # Check if spotlight is set - if not, we'll highlight spotlight actions
        has_spotlight = self._has_spotlight_app()

        # Get actions grouped by category
        by_category = self._controller.get_actions_by_category(self.current_view)

        # Define display order for categories
        # Note: NAVIGATION is excluded because we have a custom navigation section below
        category_order = [
            ActionCategory.RECORDING,
            ActionCategory.SPOTLIGHT,
            ActionCategory.FILES,
            ActionCategory.EMULATOR,
            ActionCategory.ANALYSIS,
            ActionCategory.NETWORK,
        ]

        # Category display names to match Rich mode menu
        category_display_names = {
            ActionCategory.RECORDING: "Action Recording & Playback",
            ActionCategory.SPOTLIGHT: "Spotlight Application",
            ActionCategory.FILES: "Spotlight Files",
            ActionCategory.EMULATOR: "Emulator Management",
            ActionCategory.ANALYSIS: "Analysis",
            ActionCategory.NETWORK: "Network Management",
        }

        for category in category_order:
            if category not in by_category:
                continue

            actions = by_category[category]
            if not actions:
                continue

            # Category header - using theme primary color
            cat_name = category_display_names.get(
                category, category.name.replace("_", " ").title()
            )
            if category == ActionCategory.SPOTLIGHT and not has_spotlight:
                # Add hint text but keep theme color
                lines.append(
                    f"[bold {colors['primary']}]=== {cat_name} (select app!) ===[/]"
                )
            else:
                lines.append(f"[bold {colors['primary']}]=== {cat_name} ===[/]")

            # Sort actions by key for consistent display
            for action in sorted(actions, key=lambda a: a.key.lower()):
                # Skip individual snapshot actions (1-8) since they're covered by "show_snapshots"
                # which has the combined text "keys [1-8] create snapshots, key [0] lists/loads"
                if action.name.startswith("create_snapshot_"):
                    continue

                # Skip objection_resume entirely - "b" now handles both start and resume
                if action.name == "objection_resume":
                    continue

                # Skip device_settings - combined into emulator_info line
                if action.name == "device_settings":
                    continue

                # Check if action is available (preconditions met)
                valid, _ = self._controller.validate_action(
                    action.name, self.current_view
                )

                # Get dynamic text for toggle actions (fritap, dexray, trigdroid, network, screen record)
                display_text, is_task_running = self._get_dynamic_action_text(
                    action, colors
                )

                # Format the inline text with key highlighting
                formatted_text = self._format_inline_text(display_text, colors, valid)

                # Add mode indicator if present (but not for running tasks)
                # For Frida-based actions, show current mode (SPAWN or ATTACH) dynamically
                mode_suffix = ""
                if action.mode_indicator and not is_task_running:
                    # Check if this is a Frida-based action that should show current mode
                    frida_actions = {
                        "fritap",
                        "malware_monitor",
                        "objection",
                        "memory_dump",
                        "trigdroid",
                        "dexray",
                    }
                    if action.name in frida_actions:
                        # Show SPAWN or ATTACH based on current SpotlightService state
                        is_spawn = self._is_spawn_mode()
                        if is_spawn:
                            mode_color = FIXED_COLORS["spawn_mode"]
                            mode_suffix = f" [bold {mode_color}]\\[SPAWN][/]"
                        else:
                            mode_color = FIXED_COLORS["attach_mode"]
                            mode_suffix = f" [bold {mode_color}]\\[ATTACH][/]"
                    else:
                        # Static mode indicator (e.g., for spotlight_attach, spotlight_spawn)
                        if "SPAWN" in action.mode_indicator:
                            mode_color = FIXED_COLORS["spawn_mode"]
                        else:
                            mode_color = FIXED_COLORS["attach_mode"]
                        mode_suffix = (
                            f" [bold {mode_color}]\\[{action.mode_indicator}][/]"
                        )

                # Special highlighting for spotlight actions when no app is set
                is_spotlight_action = action.name in (
                    "spotlight_attach",
                    "spotlight_spawn",
                )
                if is_spotlight_action and not has_spotlight:
                    # Add extra visual emphasis when no spotlight app is set
                    mode_suffix = f" [bold {FIXED_COLORS['spawn_mode'] if 'SPAWN' in action.mode_indicator else FIXED_COLORS['attach_mode']}]\\[{action.mode_indicator}][/]"

                # Add running indicator for active tasks
                running_prefix = ""
                if is_task_running:
                    running_prefix = f"[{FIXED_COLORS['running']}]●[/] "

                if valid:
                    lines.append(f"  * {running_prefix}{formatted_text}{mode_suffix}")
                # Show disabled actions with muted styling
                # Use formatted_text to ensure brackets are escaped properly
                # Don't show unavailable_reason in brackets - just show muted text
                # Documentation and help overlay explain when/how to use each feature
                else:
                    lines.append(f"  [{colors['text_muted']}]* {formatted_text}[/]")

            lines.append("")

        # Add view-specific tips
        lines.append("")
        lines.append(
            f"[{colors['text_muted']}]Tip: Press same key to toggle active background tasks[/]"
        )
        lines.append("")

        return "\n".join(lines)

    def scroll_down_line(self) -> None:
        """Scroll down by one line (vim j key)."""
        self.scroll_relative(y=1)

    def scroll_up_line(self) -> None:
        """Scroll up by one line (vim k key)."""
        self.scroll_relative(y=-1)

    def scroll_to_top(self) -> None:
        """Scroll to top (vim g key)."""
        self.scroll_home()

    def scroll_to_bottom(self) -> None:
        """Scroll to bottom (vim G key)."""
        self.scroll_end()
