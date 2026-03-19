"""Shared menu controller for TUI and Rich mode.

This module implements the Controller in the MVC pattern for Sandroid's
interactive menu system. It provides a unified action registry used by
both the Textual TUI and Rich CLI menu modes.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from sandroid.services import get_spotlight_service, get_task_service

from .device import DeviceCapability

if TYPE_CHECKING:
    from collections.abc import Callable

    from .actionQ import ActionQ

logger = logging.getLogger(__name__)


class ActionCategory(Enum):
    """Categories for organizing menu actions."""

    RECORDING = auto()
    SPOTLIGHT = auto()
    FILES = auto()
    EMULATOR = auto()
    ANALYSIS = auto()
    NETWORK = auto()
    NAVIGATION = auto()


@dataclass
class Action:
    """Defines a menu action with metadata.

    Attributes:
        name: Unique identifier (e.g., "record", "play")
        display_name: Human readable name (e.g., "Record an action")
        key: Keyboard shortcut (e.g., "r", "p", "TAB")
        category: Category for grouping in menus
        views: List of views where this action is available
        description: Optional help text
        inline_text: Inline-formatted display text with key position marked
                     (e.g., "[r]ecord an action", "e[x]port loaded action")
        requires_spotlight: Whether action requires a spotlight app
        requires_frida: Whether action requires Frida server
        requires_dexray_running: Whether action requires dexray-intercept to be running
        requires_real_device: Whether action only works on physical devices (not emulators)
        requires_forensic_apks: Whether action requires forensic APKs to be available
        required_capabilities: Device capabilities required for this action
        unavailable_reason: Human-readable reason shown when action is unavailable
        mode_indicator: Optional mode indicator (e.g., "ATTACH", "SPAWN MODE")
    """

    name: str
    display_name: str
    key: str
    category: ActionCategory
    views: list[str]
    description: str = ""
    inline_text: str = ""  # Inline format like "[r]ecord an action"
    requires_spotlight: bool = False
    requires_frida: bool = False
    requires_dexray_running: bool = False
    requires_real_device: bool = False
    requires_forensic_apks: bool = False
    requires_dexray_insight: bool = False
    required_capabilities: list[DeviceCapability] = field(default_factory=list)
    unavailable_reason: str = ""
    mode_indicator: str = ""  # e.g., "ATTACH", "ATTACH MODE", "SPAWN MODE"


class MenuController:
    """Shared controller for menu actions across TUI and Rich mode.

    This controller provides:
    - Action registry with metadata
    - View-based action filtering
    - Action validation (preconditions)
    - Unified execution interface
    - Help text generation

    Uses singleton pattern to ensure consistent state across all views.
    """

    _instance = None

    def __init__(self):
        self._actions: dict[str, Action] = {}
        self._action_handlers: dict[str, Callable] = {}
        self._register_all_actions()

    @classmethod
    def get(cls) -> "MenuController":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton instance (for testing)."""
        cls._instance = None

    def _register_all_actions(self):
        """Register all available actions with their metadata."""
        # ===== Recording Actions =====
        self._register(
            "record",
            "Record an action",
            "r",
            ActionCategory.RECORDING,
            ["forensic", "malware"],
            description="Record user interactions for playback",
            inline_text="[r]ecord an action",
        )
        self._register(
            "play",
            "Play loaded action",
            "p",
            ActionCategory.RECORDING,
            ["forensic", "malware"],
            description="Replay previously recorded actions",
            inline_text="[p]lay the currently loaded action",
        )
        self._register(
            "export",
            "Export loaded action",
            "x",
            ActionCategory.RECORDING,
            ["forensic", "malware"],
            description="Export current action to file",
            inline_text="e[x]port currently loaded action",
        )
        self._register(
            "import",
            "Import action",
            "i",
            ActionCategory.RECORDING,
            ["forensic", "malware"],
            description="Import action from file",
            inline_text="[i]mport action",
        )

        # ===== Spotlight Actions =====
        self._register(
            "spotlight_attach",
            "Set spotlight app (ATTACH)",
            "c",
            ActionCategory.SPOTLIGHT,
            ["forensic", "malware", "security"],
            description="Attach to currently running app",
            inline_text="set [c]urrent app in focus as spotlight app",
            mode_indicator="ATTACH MODE",
        )
        self._register(
            "spotlight_spawn",
            "Set spotlight app (SPAWN)",
            "C",
            ActionCategory.SPOTLIGHT,
            ["forensic", "malware", "security"],
            description="Select app for spawning with Frida",
            inline_text="select app with [Shift+C] for spawning",
            mode_indicator="SPAWN MODE",
        )
        self._register(
            "dump_memory",
            "Dump memory of spotlight app",
            "d",
            ActionCategory.SPOTLIGHT,
            ["forensic"],
            description="Dump process memory using Fridump",
            inline_text="[d]ump memory of spotlight app",
            requires_spotlight=True,
            requires_frida=True,
        )

        # ===== File Actions =====
        self._register(
            "list_files",
            "List/add spotlight file",
            "l",
            ActionCategory.FILES,
            ["forensic"],
            description="List or add files to monitor",
            inline_text="[l]ist/add spotlight file",
        )
        self._register(
            "remove_file",
            "Remove spotlight file",
            "v",
            ActionCategory.FILES,
            ["forensic"],
            description="Remove file from monitoring",
            inline_text="remo[v]e spotlight file",
        )
        self._register(
            "pull_files",
            "Pull spotlight files",
            "u",
            ActionCategory.FILES,
            ["forensic"],
            description="Pull monitored files from device",
            inline_text="p[u]ll spotlight files",
        )
        self._register(
            "fsmon",
            "Observe filesystem changes",
            "o",
            ActionCategory.FILES,
            ["forensic"],
            description="Monitor filesystem changes with fsmon",
            inline_text="[o]bserve filesystem changes (fsmon)",
        )
        self._register(
            "pull_spotlight_db",
            "Pull spotlight DB file",
            " ",
            ActionCategory.FILES,
            ["forensic"],
            description="Pull spotlight database file",
            inline_text="[SPACE] pull spotlight database file",
        )

        # ===== Emulator Actions =====
        self._register(
            "emulator_info",
            "Show emulator info",
            "e",
            ActionCategory.EMULATOR,
            ["forensic", "malware", "security"],
            description="Display emulator/device information",
            inline_text="show [e]mulator information, [Shift+E] edit settings",
        )
        self._register(
            "device_settings",
            "Device environment settings",
            "E",
            ActionCategory.EMULATOR,
            ["forensic", "malware", "security"],
            description="Configure device environment settings",
            inline_text="devic[E] environment settings (Shift+E)",
        )
        self._register(
            "frida",
            "Run/install Frida server",
            "f",
            ActionCategory.EMULATOR,
            ["forensic", "malware", "security"],
            description="Install and start Frida server",
            inline_text="run/install [f]rida server",
        )
        self._register(
            "screenshot",
            "Take screenshot",
            "s",
            ActionCategory.EMULATOR,
            ["forensic", "malware"],
            description="Capture screenshot from device",
            inline_text="take [s]creenshot of device",
        )
        self._register(
            "screenrecord",
            "Record screen video",
            "g",
            ActionCategory.EMULATOR,
            ["forensic", "malware"],
            description="Start/stop screen recording",
            inline_text="[g]rab video of screen",
        )
        self._register(
            "new_apk",
            "Install new APK",
            "n",
            ActionCategory.EMULATOR,
            ["forensic", "malware", "security"],
            description="Install APK from file or search",
            inline_text="[n]ew APK installation",
        )

        # ===== Analysis Actions =====
        self._register(
            "dexray",
            "Start/stop dexray-intercept",
            "m",
            ActionCategory.ANALYSIS,
            ["malware"],
            description="Dynamic analysis with dexray-intercept",
            inline_text="start android [m]alware monitor (dexray-intercept)",
            requires_spotlight=True,
            requires_frida=True,
            mode_indicator="ATTACH",
        )
        self._register(
            "trigdroid",
            "Run TrigDroid triggers",
            "t",
            ActionCategory.ANALYSIS,
            ["malware"],
            description="Execute automatic malware triggers",
            inline_text="run [t]rigdroid malware triggers",
            requires_spotlight=True,
            requires_frida=True,
            mode_indicator="ATTACH",
        )
        self._register(
            "reconfigure_hooks",
            "Reconfigure dexray hooks",
            "k",
            ActionCategory.ANALYSIS,
            ["malware"],
            description="Change dexray-intercept hook configuration",
            inline_text="reconfigure dexray hoo[k]s",
            requires_dexray_running=True,
        )
        self._register(
            "objection",
            "Launch Objection shell",
            "b",
            ActionCategory.ANALYSIS,
            ["malware"],
            description="Start Objection mobile exploration",
            inline_text="start o[b]jection interactive shell",
            requires_spotlight=True,
            requires_frida=True,
            mode_indicator="ATTACH",
        )
        self._register(
            "objection_resume",
            "Resume Objection session",
            "O",
            ActionCategory.ANALYSIS,
            ["malware"],
            description="Return to minimized Objection session",
            inline_text="resume [O]bjection session",
        )
        self._register(
            "static_analysis",
            "Run static analysis",
            "a",
            ActionCategory.ANALYSIS,
            ["security"],
            description="Analyze APK with dexray-insight",
            inline_text="run static [a]nalysis (dexray-insight)",
            requires_spotlight=True,
            requires_dexray_insight=True,
            unavailable_reason="dexray-insight not installed. Install with: pip install dexray-insight",
        )
        self._register(
            "forensic_evidence",
            "Forensic Evidence Scan (MVT)",
            "F",
            ActionCategory.ANALYSIS,
            ["forensic"],
            description="Scan device for indicators of compromise using MVT",
            inline_text="[Shift+F] Forensic Evidence Scan (MVT)",
            requires_real_device=True,
            unavailable_reason="MVT forensic scan only available on physical devices",
        )
        self._register(
            "manage_forensic_apks",
            "Manage Forensic APKs",
            "G",
            ActionCategory.ANALYSIS,
            ["forensic"],
            description="View and install pulled forensic evidence APKs",
            inline_text="[Shift+G] Manage Forensic APKs",
            requires_forensic_apks=True,
            unavailable_reason="No forensic APKs found. Run MVT scan first or pull APKs manually.",
        )

        # ===== Network Actions =====
        self._register(
            "proxy",
            "Set/unset network proxy",
            "y",
            ActionCategory.NETWORK,
            ["forensic", "malware"],
            description="Configure network proxy settings",
            inline_text="set/unset network prox[y]",
        )
        self._register(
            "fritap",
            "Start/stop FriTap hooking",
            "h",
            ActionCategory.NETWORK,
            ["malware"],
            description="TLS interception with FriTap",
            inline_text="start friTap [h]ooking",
            requires_spotlight=True,
            requires_frida=True,
            mode_indicator="ATTACH",
        )
        self._register(
            "network_capture",
            "Start/stop network capture",
            "w",
            ActionCategory.NETWORK,
            ["forensic", "malware"],
            description="Capture network traffic (pcap)",
            inline_text="[w]rite network capture file",
        )

        # ===== Navigation Actions =====
        self._register(
            "switch_view",
            "Switch view",
            "TAB",
            ActionCategory.NAVIGATION,
            ["forensic", "malware", "security"],
            description="Cycle between forensic/malware/security views",
            inline_text="[TAB] switch view",
        )
        self._register(
            "quit",
            "Quit Sandroid",
            "q",
            ActionCategory.NAVIGATION,
            ["forensic", "malware", "security"],
            description="Exit the application",
            inline_text="[q]uit",
        )
        self._register(
            "help",
            "Show help overlay",
            "?",
            ActionCategory.NAVIGATION,
            ["forensic", "malware", "security"],
            description="Display keyboard shortcuts",
            inline_text="[?] help overlay",
        )
        self._register(
            "command_palette",
            "Open command palette",
            "ctrl+p",
            ActionCategory.NAVIGATION,
            ["forensic", "malware", "security"],
            description="Search and execute commands",
            inline_text="[Ctrl+P] command palette",
        )
        self._register(
            "device_selector",
            "Open device selector",
            "D",
            ActionCategory.NAVIGATION,
            ["forensic", "malware", "security"],
            description="Switch between connected devices or start AVD",
            inline_text="[Shift+D] device selector",
        )

        # ===== Snapshot Actions (Emulator-only) =====
        self._register(
            "show_snapshots",
            "Show/load snapshots",
            "0",
            ActionCategory.EMULATOR,
            ["forensic", "malware"],
            description="Display and load AVD snapshots",
            inline_text="keys [1-8] create snapshots, key [0] lists/loads snapshots",
            required_capabilities=[DeviceCapability.SNAPSHOTS],
            unavailable_reason="Snapshots only available on emulators",
        )
        for i in range(1, 9):
            self._register(
                f"create_snapshot_{i}",
                f"Create snapshot {i}",
                str(i),
                ActionCategory.EMULATOR,
                ["forensic", "malware"],
                description=f"Create snapshot in slot {i}",
                inline_text=f"create snapshot [{i}]",
                required_capabilities=[DeviceCapability.SNAPSHOTS],
                unavailable_reason="Snapshots only available on emulators",
            )

    def _register(
        self,
        name: str,
        display_name: str,
        key: str,
        category: ActionCategory,
        views: list[str],
        description: str = "",
        inline_text: str = "",
        requires_spotlight: bool = False,
        requires_frida: bool = False,
        requires_dexray_running: bool = False,
        requires_real_device: bool = False,
        requires_forensic_apks: bool = False,
        requires_dexray_insight: bool = False,
        required_capabilities: list[DeviceCapability] | None = None,
        unavailable_reason: str = "",
        mode_indicator: str = "",
    ):
        """Register an action in the registry.

        Args:
            name: Unique action identifier
            display_name: Human readable name
            key: Keyboard shortcut
            category: Category for menu grouping
            views: List of views where action is available
            description: Optional help text
            inline_text: Inline-formatted text with key marked (e.g., "[r]ecord an action")
            requires_spotlight: Whether action requires spotlight app
            requires_frida: Whether action requires Frida server
            requires_dexray_running: Whether action requires dexray-intercept running
            requires_real_device: Whether action only works on physical devices
            requires_forensic_apks: Whether action requires forensic APKs available
            requires_dexray_insight: Whether action requires dexray-insight package
            required_capabilities: Device capabilities required for this action
            unavailable_reason: Message shown when action unavailable due to device type
            mode_indicator: Mode indicator text (e.g., "ATTACH", "SPAWN MODE")
        """
        self._actions[name] = Action(
            name=name,
            display_name=display_name,
            key=key,
            category=category,
            views=views,
            description=description,
            inline_text=inline_text,
            requires_spotlight=requires_spotlight,
            requires_frida=requires_frida,
            requires_dexray_running=requires_dexray_running,
            requires_real_device=requires_real_device,
            requires_forensic_apks=requires_forensic_apks,
            requires_dexray_insight=requires_dexray_insight,
            required_capabilities=required_capabilities or [],
            unavailable_reason=unavailable_reason,
            mode_indicator=mode_indicator,
        )

    def get_actions_for_view(self, view: str) -> list[Action]:
        """Get all actions available in a view."""
        return [a for a in self._actions.values() if view in a.views]

    def get_actions_by_category(self, view: str) -> dict[ActionCategory, list[Action]]:
        """Get actions grouped by category for a view."""
        by_category: dict[ActionCategory, list[Action]] = {}
        for action in self.get_actions_for_view(view):
            if action.category not in by_category:
                by_category[action.category] = []
            by_category[action.category].append(action)
        return by_category

    def get_action_by_key(self, key: str, view: str) -> Action | None:
        """Get action by keyboard shortcut in a view."""
        for action in self._actions.values():
            if action.key == key and view in action.views:
                return action
        return None

    def get_action_by_name(self, name: str) -> Action | None:
        """Get action by name."""
        return self._actions.get(name)

    def get_all_actions(self) -> list[Action]:
        """Get all registered actions."""
        return list(self._actions.values())

    def validate_action(self, action_name: str, view: str) -> tuple[bool, str]:
        """Validate if action can be executed.

        Checks:
        - View availability
        - Device capabilities (for emulator-only features)
        - Frida server requirement
        - Spotlight app requirement

        Returns:
            Tuple of (valid, error_message)
        """
        action = self._actions.get(action_name)
        if not action:
            return False, f"Unknown action: {action_name}"

        if view not in action.views:
            return (
                False,
                f"Action '{action.display_name}' not available in {view.upper()} view. Press TAB to switch views.",
            )

        # Import here to avoid circular dependency
        from .toolbox import Toolbox

        # Check device capabilities (for physical device restrictions)
        if action.required_capabilities:
            dm = Toolbox.get_device_manager()
            for capability in action.required_capabilities:
                if not dm.check_capability(capability):
                    reason = (
                        action.unavailable_reason
                        or "Feature not available on this device"
                    )
                    return False, reason

        if action.requires_frida:
            try:
                from sandroid.services import get_frida_session_service

                frida_service = get_frida_session_service()
                frida_manager = frida_service.get_frida_manager()
                frida_running = frida_manager.is_frida_server_running()
            except (RuntimeError, ImportError, Exception):
                # External AndroidFridaManager throws RuntimeError on non-rooted devices
                # ImportError if services module not available
                frida_running = False
            if not frida_running:
                return (
                    False,
                    "Frida server not running. Press [f] to install and start.",
                )

        if action.requires_spotlight:
            spotlight = get_spotlight_service()
            has_attach_app = spotlight.get_app_tuple() is not None
            has_spawn_app = (
                spotlight.is_spawn_mode() and spotlight.get_spawn_package() is not None
            )
            if not has_attach_app and not has_spawn_app:
                return (
                    False,
                    "No spotlight app set. Press [c] for ATTACH or [C] for SPAWN mode.",
                )

        if action.requires_dexray_running:
            if not get_task_service().is_running("dexray-intercept"):
                return (
                    False,
                    "dexray-intercept not running. Press [m] to start.",
                )

        if action.requires_real_device:
            dm = Toolbox.get_device_manager()
            if dm and dm.is_emulator():
                reason = (
                    action.unavailable_reason
                    or "This feature only works on physical devices"
                )
                return False, reason

        if action.requires_forensic_apks:
            if not Toolbox.has_forensic_apks():
                reason = action.unavailable_reason or "No forensic APKs available"
                return False, reason

        if action.requires_dexray_insight:
            if not Toolbox.is_dexray_insight_available():
                reason = (
                    action.unavailable_reason
                    or "dexray-insight package not installed. Install with: pip install dexray-insight"
                )
                return False, reason

        return True, ""

    def get_help_text(self, view: str) -> str:
        """Generate formatted help text for current view.

        Returns formatted string showing all available shortcuts
        grouped by category.
        """
        lines = [f"[bold cyan]=== {view.upper()} View Shortcuts ===[/bold cyan]", ""]

        by_category = self.get_actions_by_category(view)

        # Define category display order
        category_order = [
            ActionCategory.RECORDING,
            ActionCategory.SPOTLIGHT,
            ActionCategory.FILES,
            ActionCategory.EMULATOR,
            ActionCategory.ANALYSIS,
            ActionCategory.NETWORK,
            ActionCategory.NAVIGATION,
        ]

        for category in category_order:
            if category in by_category:
                # Format category name nicely
                cat_name = category.name.replace("_", " ").title()
                lines.append(f"[cyan]--- {cat_name} ---[/cyan]")

                for action in sorted(by_category[category], key=lambda a: a.key):
                    # Format key display
                    if len(action.key) > 1:
                        key_display = action.key.upper()
                    elif action.key == " ":
                        key_display = "SPACE"
                    else:
                        key_display = action.key

                    lines.append(
                        f"  [yellow][{key_display}][/yellow] {action.display_name}"
                    )
                lines.append("")

        lines.append("[dim]Press ? again or ESC to close help[/dim]")
        return "\n".join(lines)

    def get_help_text_plain(self, view: str) -> str:
        """Generate plain text help (no Rich markup) for TUI."""
        lines = [f"=== {view.upper()} View Shortcuts ===", ""]

        by_category = self.get_actions_by_category(view)

        category_order = [
            ActionCategory.RECORDING,
            ActionCategory.SPOTLIGHT,
            ActionCategory.FILES,
            ActionCategory.EMULATOR,
            ActionCategory.ANALYSIS,
            ActionCategory.NETWORK,
            ActionCategory.NAVIGATION,
        ]

        for category in category_order:
            if category in by_category:
                cat_name = category.name.replace("_", " ").title()
                lines.append(f"--- {cat_name} ---")

                for action in sorted(by_category[category], key=lambda a: a.key):
                    if len(action.key) > 1:
                        key_display = action.key.upper()
                    elif action.key == " ":
                        key_display = "SPACE"
                    else:
                        key_display = action.key

                    lines.append(f"  [{key_display}] {action.display_name}")
                lines.append("")

        lines.append("Press ? again or ESC to close help")
        return "\n".join(lines)

    def execute_action(self, action_name: str, action_queue: "ActionQ") -> bool:
        """Execute an action through the command system.

        Routes actions directly to CommandRegistry for command keys,
        avoiding the double-bridging through ActionQ.parse_interactive_char().

        Args:
            action_name: Name of the action to execute
            action_queue: ActionQ instance (for legacy fallback if needed)

        Returns:
            True if action was executed, False otherwise
        """
        action = self._actions.get(action_name)
        if not action:
            logger.error(f"Unknown action: {action_name}")
            return False

        # Special handling for view-layer actions
        if action_name == "switch_view":
            from sandroid.services import get_ui_service

            get_ui_service().cycle_view()
            return True

        if action_name == "help":
            # Help is handled by the view layer (TUI or Rich mode)
            return True

        if action_name == "command_palette":
            # Command palette is handled by the view layer
            return True

        if action_name == "device_selector":
            # Device selector is handled by the view layer (TUI)
            return True

        # Route directly to command system if key is a command key
        from sandroid.core.actionq_commands import (
            execute_command_from_actionq,
            is_command_key,
        )

        if is_command_key(action.key):
            # Execute command directly through command system
            result = execute_command_from_actionq(action_queue, action.key)
            if result.should_return_to_menu:
                action_queue.q.append("interactive")
            if not result.success and result.error == "Precondition not met":
                # Raise exception with message so TUI can show modal
                raise ValueError(result.message)
            return result.success

        # Fall back to ActionQ for special keys (digits 0-8 for snapshots)
        action_queue.parse_interactive_char(action.key)
        return True
