import os
import warnings

import click

warnings.filterwarnings("ignore", category=ResourceWarning)  # it is what it is

from logging import getLogger

from sandroid.services import get_ui_service

from .console import SandroidConsole


class ActionQ:
    """Slimmed interactive shell for the TUI menu/palette.

    The legacy ``assembleQ``/``do_next`` queue-pump engine has been retired;
    all analysis now flows through :class:`~sandroid.analysis.engine.AnalysisEngine`.
    What remains here is the interactive key-dispatch surface the TUI still
    relies on:

    * ``parse_interactive_char`` — the special/digit-key fallback reached from
      ``MenuController.execute_action`` (and, historically, the Rich menu loop).
    * ``_execute_snapshot_command`` — snapshot digit-key handling, called from
      ``tui/controllers/menu_controller.py``.

    ``q`` is retained as an inert list only because the two methods above (and a
    couple of kept callers) still append the sentinel ``"interactive"`` to it;
    nothing consumes the queue anymore. Renaming this to ``InteractiveController``
    is a deferred follow-up.
    """

    q = []
    recently_installed_package = None  # Track the last installed package for spawn mode

    logger = getLogger(__name__)

    def parse_interactive_char(self, char):
        """Parses and handles interactive character input from the menu.

        :param char: The character input from the user.
        :type char: str
        """
        # Check if TUI mode is active (skip screen clear and use modals instead of Rich prompts)
        from sandroid.core.ui_request_bus import (
            UIRequestBus,
        )

        from .toolbox import Toolbox

        bus = UIRequestBus.get()
        is_tui_mode = bus.has_active_handler()

        # Only clear screen in Rich mode (TUI manages its own display)
        if not is_tui_mode and Toolbox.args.loglevel != "DEBUG":
            os.system(  # nosec S605 # Safe terminal clear command
                "cls" if os.name == "nt" else "clear"
            )  # Just to keep everything nice and clean

        # Check if char is a digit between 0-8 (Snapshot handling)
        # Delegate to command system for snapshot operations
        if char.isdigit() and 0 <= int(char) <= 8:
            self._execute_snapshot_command(char)
            self.q.append("interactive")
            return

        # Handle TAB key for view switching
        if char == "\t":  # TAB key
            get_ui_service().cycle_view()
            self.q.append("interactive")
            return

        # Import MenuController for key validation and help
        from sandroid.core.menu_controller import MenuController

        # Handle '?' key for help overlay (Rich mode only)
        # TUI mode has its own help screen that's triggered by the app bindings
        if char == "?":
            if is_tui_mode:
                # TUI handles help via its own help screen - just return to interactive
                self.q.append("interactive")
                return

            # Rich mode: Show help using console
            console = SandroidConsole.get()
            controller = MenuController.get()
            current_view = get_ui_service().get_current_view()

            # Print help text using Rich formatting
            help_text = controller.get_help_text(current_view)
            console.print()
            console.print(help_text)
            console.print()
            console.print("[dim]Press any key to return to menu...[/dim]")

            # Wait for key press
            try:
                click.getchar()
            except (KeyboardInterrupt, EOFError):
                pass

            self.q.append("interactive")
            return

        # Validate key based on current view using MenuController
        current_view = get_ui_service().get_current_view()
        controller = MenuController.get()

        # Get action for this key in the current view
        action = controller.get_action_by_key(char, current_view)

        # Special case: 'q' is always valid (quit)
        if char == "q":
            pass  # Allow quit in all views
        elif action is None:
            # Key not found in current view
            get_ui_service().show_blocking_warning(
                title="Key Not Available",
                message=f"Key '{char}' is not available in {current_view.upper()} view.",
                action_hint="Press TAB to switch between views: Forensic → Malware → Security\nPress ? for help or Ctrl+P for command palette",
            )
            self.q.append("interactive")
            return

        # === COMMAND SYSTEM DISPATCH ===
        # Route to new command system if a handler is registered
        # This allows gradual migration while preserving backward compatibility
        from sandroid.core.actionq_commands import (
            execute_command_from_actionq,
            is_command_key,
        )

        if is_command_key(char):
            result = execute_command_from_actionq(self, char)
            if result.should_return_to_menu:
                self.q.append("interactive")
            return

        # === LEGACY FALLBACK ===
        # NOTE: All command keys are now handled by the command system above.
        # This fallback handles any keys that weren't caught by:
        # 1. Special keys (digits 0-8, TAB, ?)
        # 2. Command keys (handled by CommandRegistry)
        # 3. View-based key validation (shows "Key Not Available" warning)
        #
        # If we reach here, it's an unexpected key that passed view validation
        # but isn't in the command system - this shouldn't normally happen.
        self.logger.warning(
            f"Unhandled key '{char}' reached legacy fallback - this shouldn't happen"
        )
        self.q.append("interactive")
        return

    def _execute_snapshot_command(self, char: str) -> None:
        """Execute snapshot command through the command system.

        Delegates snapshot operations (list/load for '0', create for '1'-'8')
        to the SnapshotCommands in the command registry.

        :param char: The digit character ('0'-'8')
        :type char: str
        """
        from .toolbox import Toolbox

        try:
            from sandroid.commands import CommandRegistry
            from sandroid.commands.context_factory import create_context_from_actionq

            # Create command context
            ctx = create_context_from_actionq(action_queue=self, toolbox=Toolbox)

            # Get registry and execute
            registry = CommandRegistry.get()
            if not registry.has(char):
                # Initialize commands if not already done
                registry.initialize_default_commands()

            if registry.has(char):
                # Execute synchronously (async wrapper)
                result = registry.execute_sync(char, ctx)
                if not result.success:
                    self.logger.warning(f"Snapshot command failed: {result.message}")
            else:
                self.logger.warning(f"No snapshot command registered for key '{char}'")
        except Exception as e:
            self.logger.error(f"Error executing snapshot command: {e}")
