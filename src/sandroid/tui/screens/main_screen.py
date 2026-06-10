"""Main screen for Sandroid TUI."""

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Header, Static

from sandroid.core.menu_controller import MenuController
from sandroid.services import get_frida_session_service, get_ui_service
from sandroid.tui.widgets import (
    ActivityLog,
    MitmproxyPanel,
    SandroidFooter,
    SnapshotsPanel,
    SpotlightPanel,
    StatusBar,
)

if TYPE_CHECKING:
    from sandroid.core.actionQ import ActionQ

logger = logging.getLogger(__name__)


class _ToolPanel(Vertical):
    """Wrapper for the permanent tool area (tab strip + tool body).

    Owns Left/Right tab-switching bindings. Because they live here (an
    ancestor of the focused inner panel) they only fire when focus is inside
    the tool area — Left/Right are never stolen from the activity log, which
    keeps its normal behaviour. The inner panels are plain focusable Widgets
    with no arrow bindings, so Left/Right bubble up to here.
    """

    BINDINGS = [
        Binding("left", "prev_tab", "Prev tab", show=False),
        Binding("right", "next_tab", "Next tab", show=False),
    ]

    def action_prev_tab(self) -> None:
        self.screen.cycle_bottom_tab(-1)

    def action_next_tab(self) -> None:
        self.screen.cycle_bottom_tab(1)


class MainScreen(Screen):
    """Main screen with split-pane layout.

    Layout:
    - Header with clock
    - Status bar showing application state
    - Left panel: Menu with actions
    - Right panel: Activity log
    - Footer with key bindings
    """

    BINDINGS = []  # Bindings are handled by the main app

    # Defined here (not in styles.tcss) so it applies under every theme — the
    # app loads exactly one theme-specific .tcss and none of them define these
    # ids, while app CSS always beats Screen DEFAULT_CSS. Putting the rules
    # here keeps them unopposed and theme-independent.
    #
    # #tool-panel is a plain Vertical that fills the space below the dock:top
    # status band: a single-row tab strip (#tool-tabbar) on top and the active
    # tool body (#tool-body, a ContentSwitcher) filling the rest. The tool area
    # is permanently visible — nothing collapses or pops up.
    DEFAULT_CSS = """
    #tool-tabbar {
        height: 1;
        background: #0b1628;
    }
    .tool-tab {
        width: auto;
        padding: 0 2;
        color: #8f9bb3;
    }
    .tool-tab:hover {
        background: #1f2937;
    }
    .tool-tab.-active {
        color: #7dd3fc;
        text-style: bold;
        background: #1f2937;
    }
    #tool-body {
        display: block;
        height: 1fr;
    }
    """

    def __init__(
        self,
        action_queue: "ActionQ" = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the main screen.

        Args:
            action_queue: ActionQ instance for executing actions
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        logger.debug("[MAIN_SCREEN] __init__ start")
        super().__init__(name=name, id=id, classes=classes)
        self.action_queue = action_queue
        self._controller = MenuController.get()
        self._event_handlers = []
        logger.debug("[MAIN_SCREEN] __init__ complete")

    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        logger.debug("[MAIN_SCREEN] compose start")
        yield Header(show_clock=True)

        with Horizontal():
            with Vertical(id="left-panel"):
                yield StatusBar(id="status-bar")
                # Permanent tool area: a single-row tab strip + the active
                # tool body. Nothing collapses; Left/Right (or clicking a tab)
                # switch tabs. A ContentSwitcher holds the three bodies.
                with _ToolPanel(id="tool-panel"):
                    with Horizontal(id="tool-tabbar"):
                        yield Static(
                            "Spotlight",
                            id="tab-spotlight",
                            classes="tool-tab -active",
                        )
                        yield Static("Mitmproxy", id="tab-mitm", classes="tool-tab")
                        yield Static(
                            "Snapshots", id="tab-snapshots", classes="tool-tab"
                        )
                    with ContentSwitcher(initial="spotlight-panel", id="tool-body"):
                        yield SpotlightPanel(id="spotlight-panel")
                        yield MitmproxyPanel(id="mitm-panel")
                        yield SnapshotsPanel(id="snapshots-panel")

            with Vertical(id="right-panel"):
                yield Static("[bold]Background Activity[/bold]", id="activity-title")
                yield ActivityLog(id="activity-log")

        yield SandroidFooter()
        logger.debug("[MAIN_SCREEN] compose complete")

    def on_mount(self) -> None:
        """Called when the screen is mounted.

        Uses call_later() to defer updates and allow the UI to render first.
        This ensures the TUI appears responsive even during initialization.
        """
        logger.debug("[MAIN_SCREEN] on_mount started")
        # Defer event subscription to next event loop iteration.
        # Subscribing during mount deadlocks: if a background thread publishes
        # an event, the subscriber calls call_from_thread which blocks waiting
        # for the main thread — but the main thread is stuck in on_mount.
        self.call_later(self._subscribe_to_events)
        logger.debug("[MAIN_SCREEN] on_mount: event subscription deferred")

        # Show welcome message immediately (fast)
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            logger.debug("[MAIN_SCREEN] on_mount: activity_log found")
            activity_log.show_welcome()
            activity_log.write(
                "[dim]Press [bold #ff00ff]?[/] for help, "
                "[bold #ff00ff]Ctrl+P[/] for command palette[/]"
            )
            logger.debug("[MAIN_SCREEN] on_mount: welcome shown")
        except Exception as e:
            logger.warning(f"Could not show welcome: {e}")

        # Defer state updates to allow UI to render first
        # This makes the TUI appear responsive immediately
        self.call_later(self._deferred_mount_updates)
        logger.debug("[MAIN_SCREEN] on_mount complete, deferred updates scheduled")

    # Clickable tab id -> ContentSwitcher child id (the panel widget's id).
    _TOOL_TABS = {
        "tab-spotlight": "spotlight-panel",
        "tab-mitm": "mitm-panel",
        "tab-snapshots": "snapshots-panel",
    }

    def on_click(self, event) -> None:
        """Route clicks on the tool tab bar.

        A tab name switches to that panel. Clicks elsewhere are ignored
        (event is not stopped, so normal handling continues).
        """
        wid = getattr(getattr(event, "widget", None), "id", None)
        if wid in self._TOOL_TABS:
            self._select_bottom_tab(self._TOOL_TABS[wid])
        elif wid and wid.startswith(("act-", "snap-")):
            # Tool-panel action cells. Route to the ACTIVE tool child
            # (spotlight uses act-*, snapshots uses snap-*). The hasattr guard
            # keeps panels without a dispatcher (e.g. MitmproxyPanel) safe.
            current = self._bottom_current()
            if current:
                try:
                    panel = self.query_one(f"#{current}")
                    if hasattr(panel, "dispatch_action_cell"):
                        panel.dispatch_action_cell(wid)
                except Exception:
                    pass

    def _bottom_current(self) -> str | None:
        """Return the id of the currently selected tool body, if any."""
        try:
            return self.query_one("#tool-body", ContentSwitcher).current
        except Exception:
            return None

    def _select_bottom_tab(self, panel_id: str) -> None:
        """Switch the active tool tab and focus its panel."""
        try:
            self.query_one("#tool-body", ContentSwitcher).current = panel_id
        except Exception:
            return
        # Reflect the active tab in the bar.
        for tab_id, pid in self._TOOL_TABS.items():
            try:
                self.query_one(f"#{tab_id}").set_class(pid == panel_id, "-active")
            except Exception:
                pass
        try:
            self.query_one(f"#{panel_id}").focus()
        except Exception:
            pass
        # Let a freshly-activated panel refresh itself immediately (e.g.
        # the Snapshots tab fetches its list as soon as it is shown).
        try:
            panel_widget = self.query_one(f"#{panel_id}")
            if hasattr(panel_widget, "refresh_snapshots"):
                panel_widget.refresh_snapshots()
        except Exception:
            pass

    def open_snapshots_tab(self) -> None:
        """Switch to the Snapshots tab (key 0)."""
        self._select_bottom_tab("snapshots-panel")

    def cycle_bottom_tab(self, delta: int) -> None:
        """Switch the active tab by *delta* (Left/Right while focus is inside).

        Bound on the tool-panel wrapper so it only fires when focus is inside
        the tool area; never steals Left/Right from the activity log.
        """
        order = list(self._TOOL_TABS.values())
        current = self._bottom_current() or order[0]
        try:
            idx = order.index(current)
        except ValueError:
            idx = 0
        self._select_bottom_tab(order[(idx + delta) % len(order)])

    def _deferred_mount_updates(self) -> None:
        """Run deferred updates after UI has rendered.

        This is called via call_later() from on_mount() to ensure the UI
        renders before we start updating status bar, menu, etc.
        """
        logger.debug("[MAIN_SCREEN] _deferred_mount_updates started")
        # Update UI state from Toolbox (now with background Frida checks)
        self._update_from_toolbox()

        # Set initial subtitle based on current view
        try:
            current_view = get_ui_service().get_current_view()
            self.app.update_subtitle_for_view(current_view)
        except Exception:
            pass

        # Display any buffered startup messages that were logged before TUI started
        # These were stored in EventBus history since no subscribers existed yet
        self._display_buffered_logs()

        # Land focus in the tool area (Spotlight tab) on startup rather than
        # wherever Textual's tab order happens to pick.
        try:
            self.query_one("#spotlight-panel").focus()
        except Exception:
            pass

    def _update_from_toolbox(self) -> None:
        """Update UI state from Toolbox."""
        try:
            # Update status bar (refresh_status = update_from_toolbox + repaint;
            # the multi-row glance band needs an explicit refresh() or it would
            # update its attributes without re-rendering on this path).
            status_bar = self.query_one("#status-bar", StatusBar)
            status_bar.refresh_status()
        except ImportError:
            logger.warning("Toolbox not available")
        except Exception as e:
            logger.error(f"Error updating from Toolbox: {e}")

    def _subscribe_to_events(self) -> None:
        """Subscribe to EventBus events.

        Uses loop.call_soon_threadsafe for non-blocking, fire-and-forget
        scheduling instead of App.call_from_thread which blocks the caller.
        call_from_thread deadlocks when:
        - Called from the main thread (self-deadlock: waits for event loop
          to process callback, but event loop IS the blocked main thread)
        - Called from a background thread that holds EventBus._handlers_lock
          while the main thread also needs that lock (cross-thread deadlock)
        """
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            # Capture the running event loop for thread-safe scheduling.
            # This runs on the main thread (deferred via call_later from on_mount).
            try:
                main_loop = asyncio.get_running_loop()
            except RuntimeError:
                main_loop = None

            def _safe_call(handler, event):
                """Schedule handler on main thread without blocking caller.

                Uses loop.call_soon_threadsafe (fire-and-forget) instead of
                App.call_from_thread (blocks until processed). This prevents
                deadlocks when EventBus subscribers are called from any thread.
                """
                try:
                    if main_loop is not None and not main_loop.is_closed():
                        main_loop.call_soon_threadsafe(handler, event)
                except RuntimeError:
                    pass  # Event loop closed during shutdown
                except Exception as e:
                    logger.debug(f"Failed to schedule event handler: {e}")

            # Map event types to their handler methods
            event_handler_map = {
                EventType.TASK_OUTPUT: self._handle_task_output,
                EventType.TASK_STARTED: self._handle_task_started,
                EventType.TASK_STOPPED: self._handle_task_stopped,
                EventType.TASK_UPDATED: self._handle_task_updated,
                EventType.LOG_MESSAGE: self._handle_log_message,
                EventType.FILE_CHANGED: self._handle_file_changed,
                EventType.HOOK_TRIGGERED: self._handle_hook_triggered,
                EventType.NETWORK_EVENT: self._handle_network_event,
            }

            def _make_callback(h):
                def _cb(event):
                    _safe_call(h, event)

                return _cb

            for event_type, handler in event_handler_map.items():
                cb = _make_callback(handler)
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))

        except ImportError:
            logger.warning(
                "Events module not available, TUI will not receive background updates"
            )

    def _handle_task_output(self, event) -> None:
        """Handle task output event."""
        try:
            message = event.data.get("message", "")
            if message.strip():
                activity_log = self.query_one("#activity-log", ActivityLog)
                task_name = event.data.get("task_name", "unknown")
                activity_log.log_message(message, task_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_started(self, event) -> None:
        """Handle task started event."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            app_name = event.data.get("app_name")
            activity_log.log_task_started(display_name, app_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_stopped(self, event) -> None:
        """Handle task stopped event."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            activity_log.log_task_stopped(display_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_updated(self, event) -> None:
        """Handle task display-name change (not a lifecycle event)."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            activity_log.log_task_updated(display_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_log_message(self, event) -> None:
        """Handle log message event (from TUILoggingHandler)."""
        message = event.data.get("message", "")
        if not message.strip():
            return
        levelno = event.data.get("levelno", 20)

        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            self._route_log_by_level(activity_log, message, levelno)
        except Exception:
            pass

    @staticmethod
    def _route_log_by_level(
        activity_log: ActivityLog, message: str, levelno: int
    ) -> None:
        """Route a log message to the appropriate ActivityLog method.

        Args:
            activity_log: The ActivityLog widget
            message: The log message
            levelno: Python logging level number
        """
        if levelno >= 40:  # ERROR and above
            activity_log.log_error(message)
        elif levelno >= 30:  # WARNING
            activity_log.log_warning(message)
        elif levelno >= 20:  # INFO
            activity_log.log_info(message)
        else:  # DEBUG
            activity_log.log_info(f"[dim]{message}[/dim]")

    def _handle_file_changed(self, event) -> None:
        """Handle file changed event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        file_path = event.data.get("file_path", "unknown")
        change_type = event.data.get("change_type", "modified")
        # Only show filename, not full path
        filename = file_path.split("/")[-1] if "/" in file_path else file_path
        activity_log.log_message(f"File {change_type}: {filename}", "files")

    def _handle_hook_triggered(self, event) -> None:
        """Handle Frida hook triggered event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        hook_name = event.data.get("hook_name", "unknown")
        method = event.data.get("method", "")
        msg = f"Hook: {hook_name}"
        if method:
            msg += f" - {method}"
        activity_log.log_message(msg, "frida")

    def _handle_network_event(self, event) -> None:
        """Handle network event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        event_type = event.data.get("event_type_name", "connection")
        dest_ip = event.data.get("dest_ip", "")
        dest_port = event.data.get("dest_port", 0)
        if dest_ip:
            msg = f"Network: {event_type} -> {dest_ip}:{dest_port}"
            activity_log.log_message(msg, "network")

    def _display_buffered_logs(self) -> None:
        """Display buffered log messages from EventBus history.

        When the TUI starts, there may be log messages that were published
        before the TUI subscribed to events. These are stored in EventBus
        history and need to be displayed in the ActivityLog.
        """
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            # Get buffered LOG_MESSAGE events (up to 50, newest first)
            buffered_logs = bus.get_history(EventType.LOG_MESSAGE, count=50)

            if not buffered_logs:
                return

            activity_log = self.query_one("#activity-log", ActivityLog)
            activity_log.write("[dim]─── Startup Messages ───[/dim]")

            # Process in chronological order (oldest first, so reverse the list)
            for event in reversed(buffered_logs):
                message = event.data.get("message", "")
                levelno = event.data.get("levelno", 20)
                self._route_log_by_level(activity_log, message, levelno)

            # Add separator after startup messages
            activity_log.write("[dim]────────────────────────[/dim]")
            activity_log.write("")

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Error displaying buffered logs: {e}")

    def switch_view(self) -> None:
        """No-op: view modes were removed from the TUI.

        TODO(modes-as-presets): Kept as a safe no-op so any lingering caller
        does not break. View modes (FORENSIC/MALWARE/SECURITY) will return as
        user-selectable presets in a later feature.
        """

    def execute_action(self, action_name: str) -> None:
        """Execute an action by name.

        Actions are executed in a background worker thread so that UI modals
        can be displayed while the action waits for user input. The UIRequestBus
        routes dialog requests to the ModalManager which runs on the main thread.

        Args:
            action_name: Name of the action to execute
        """
        activity_log = self.query_one("#activity-log", ActivityLog)

        # Validate action (view-agnostic flat catalog; modes removed)
        valid, error_msg = self._controller.validate_action(action_name)
        if not valid:
            activity_log.log_validation_error(error_msg)
            # Show modal for validation errors so user gets clear feedback
            from sandroid.tui.modals import MessageModal

            self.app.push_screen(
                MessageModal(
                    title="Action Not Available",
                    message=error_msg,
                    level="error",
                )
            )
            return

        # Get action for logging
        action = self._controller.get_action_by_name(action_name)
        if action:
            activity_log.log_action_triggered(action.display_name, action.key)

        # Execute through action queue in a background worker thread
        # This allows UIRequestBus modals to display while the action runs
        # The action code calls request_toggle_config() etc which blocks waiting
        # for modal result - this only works if we're NOT on the main thread
        if self.action_queue:
            import functools

            self.run_worker(
                functools.partial(
                    self._execute_action_sync, action_name, self.action_queue
                ),
                name=f"action_{action_name}",
                exclusive=False,
                thread=True,  # Run in thread pool
            )
        else:
            activity_log.log_error("ActionQ not initialized")
            from sandroid.tui.modals import MessageModal

            self.app.push_screen(
                MessageModal(
                    title="ActionQ Not Initialized",
                    message="The action queue is not available. Record/Play disabled.\n\n"
                    "This is a fundamental error. Please restart the application.",
                    level="error",
                )
            )

    def _execute_action_sync(self, action_name: str, action_queue: "ActionQ") -> None:
        """Execute an action synchronously (runs in worker thread).

        This runs in a thread pool worker, allowing the main Textual thread
        to remain responsive for displaying modals from UIRequestBus.

        Args:
            action_name: Name of the action to execute
            action_queue: ActionQ instance
        """
        try:
            # Get command result from execution
            from sandroid.core.actionq_commands import (
                execute_command_from_actionq,
                is_command_key,
            )

            action = self._controller.get_action_by_name(action_name)
            if action and is_command_key(action.key):
                # Execute through command system to get result
                result = execute_command_from_actionq(action_queue, action.key)

                # Display result message in activity log
                if result.message:
                    self.app.call_from_thread(
                        self._log_command_result, result.success, result.message
                    )

                # Show device settings modal (tabbed, Shift+E)
                if (
                    result.success
                    and result.data
                    and result.data.get("show_device_settings_modal")
                ):
                    self.app.call_from_thread(
                        self._show_device_settings_modal,
                        result.data.get("is_emulator", False),
                        result.data.get("has_root", False),
                    )
                # Show device info modal (scrollable, sectioned)
                elif (
                    result.success
                    and result.data
                    and result.data.get("show_device_info_modal")
                ):
                    self.app.call_from_thread(
                        self._show_device_info_modal, result.data["device_info"]
                    )

                # Show modal for validation failures or command errors
                if not result.success and result.error == "Precondition not met":
                    self.app.call_from_thread(
                        self._show_validation_error, result.message
                    )
                elif not result.success and result.error:
                    cancelled = (
                        "cancel" in (result.error or "").lower()
                        or "cancel" in (result.message or "").lower()
                    )
                    if not cancelled:
                        error_msg = result.message or str(result.error)
                        self.app.call_from_thread(
                            self._show_error_modal, "Command Failed", error_msg
                        )
            else:
                # Legacy path for non-command actions
                self._controller.execute_action(action_name, action_queue)

        except ValueError as e:
            # Validation error - show modal
            self.app.call_from_thread(self._show_validation_error, str(e))
        except Exception as e:
            # Log error on main thread
            self.app.call_from_thread(self._log_action_error, str(e))

        # Refresh UI state after action on main thread
        self.app.call_from_thread(self._refresh_after_action)

    def _log_action_error(self, error_msg: str) -> None:
        """Log an action error and show error modal (called from main thread).

        Ensures errors are always visible - either in the TUI ActivityLog
        or via stderr if the ActivityLog is not available. Also shows an
        ErrorModal so the user cannot miss the error.
        """
        try:
            from textual.css.query import NoMatches

            activity_log = self.query_one("#activity-log", ActivityLog)
            activity_log.log_error(f"Action failed: {error_msg}")
        except NoMatches:
            import sys

            print(f"[ERROR] Action failed: {error_msg}", file=sys.stderr)
        except Exception as e:
            import sys

            print(f"[ERROR] Action failed: {error_msg} (also: {e})", file=sys.stderr)

        self._show_error_modal("Action Failed", error_msg)

    def _log_command_result(self, success: bool, message: str) -> None:
        """Log a command result (called from main thread)."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            if success:
                activity_log.log_info(message)
            else:
                activity_log.log_error(message)
        except Exception:
            pass

    def _show_validation_error(self, error_msg: str) -> None:
        """Show validation error modal (called from main thread)."""
        self._show_error_modal("Action Not Available", error_msg)

    def _show_error_modal(self, title: str, error_msg: str) -> None:
        """Show error modal with red danger styling (called from main thread)."""
        from sandroid.tui.modals import ErrorModal

        self.app.push_screen(
            ErrorModal(
                title=title,
                message=error_msg,
            )
        )

    def _show_info_modal(self, title: str, message: str) -> None:
        """Show informational modal (called from main thread)."""
        from sandroid.tui.modals import MessageModal

        self.app.push_screen(
            MessageModal(
                title=title,
                message=message,
                level="info",
            )
        )

    def _show_device_settings_modal(self, is_emulator: bool, has_root: bool) -> None:
        """Show device settings modal (called from main thread).

        Args:
            is_emulator: Whether the device is an emulator
            has_root: Whether root access is available
        """
        from sandroid.tui.modals import DeviceSettingsModal

        self.app.push_screen(
            DeviceSettingsModal(is_emulator=is_emulator, has_root=has_root)
        )

    def _show_device_info_modal(self, info: dict) -> None:
        """Show device information modal (called from main thread).

        Args:
            info: Device info dictionary from DeviceService.get_device_info()
        """
        from sandroid.tui.modals import DeviceInfoModal

        self.app.push_screen(DeviceInfoModal(info=info))

    def _refresh_after_action(self) -> None:
        """Refresh UI state after action (called from main thread)."""
        self._update_from_toolbox()

    def execute_action_by_key(self, key: str) -> bool:
        """Execute an action by keyboard shortcut.

        Args:
            key: The key that was pressed

        Returns:
            True if an action was executed, False otherwise
        """
        action = self._controller.find_action_by_key(key)
        if action:
            # Check if action requires Frida and Frida isn't running
            if action.requires_frida:
                if not self._is_frida_running():
                    self._prompt_frida_install(action.name, action.display_name)
                    return True
            self.execute_action(action.name)
            return True

        return False

    def _is_frida_running(self) -> bool:
        """Check if Frida server is running on the active device.

        Returns:
            True if Frida is running, False otherwise
        """
        try:
            frida_service = get_frida_session_service()
            frida_manager = frida_service.get_frida_manager()
            if frida_manager:
                return frida_manager.is_frida_server_running()
        except Exception:
            pass
        return False

    def _prompt_frida_install(self, action_name: str, feature_name: str) -> None:
        """Show Frida installation modal and handle result.

        Args:
            action_name: Name of the action to execute after install
            feature_name: Display name of the feature that needs Frida
        """
        from sandroid.core.toolbox import Toolbox
        from sandroid.tui.modals import FridaInstallModal, FridaInstallResult

        # Get device name
        device_name = "device"
        try:
            dm = Toolbox.get_device_manager()
            if dm.active_device:
                device_name = dm.active_device.display_name
        except Exception:
            pass

        def on_frida_result(result: FridaInstallResult) -> None:
            """Handle Frida installation modal result."""
            if result.install:
                # Install and start Frida in a worker thread
                import functools

                self.run_worker(
                    functools.partial(self._install_frida_and_execute, action_name),
                    name=f"frida_install_{action_name}",
                    exclusive=False,
                    thread=True,
                )
            else:
                # User cancelled, log it
                try:
                    activity_log = self.query_one("#activity-log", ActivityLog)
                    activity_log.log_info("Frida installation cancelled")
                except Exception:
                    pass

        self.app.push_screen(
            FridaInstallModal(device_name=device_name, feature_name=feature_name),
            on_frida_result,
        )

    def _install_frida_and_execute(self, action_name: str) -> None:
        """Install Frida server and execute the action (runs in worker thread).

        Args:
            action_name: Name of the action to execute after installation
        """
        try:
            # Log start of installation on main thread
            self.app.call_from_thread(
                lambda: self._log_to_activity("Installing Frida server...")
            )

            # Install and start Frida using FridaSessionService
            frida_service = get_frida_session_service()
            frida_manager = frida_service.get_frida_manager()
            if frida_manager:
                frida_manager.install_frida_server()
                started = frida_manager.run_frida_server()

                if started:
                    # Log success
                    self.app.call_from_thread(
                        lambda: self._log_to_activity("Frida server installed and started")
                    )
                else:
                    self.app.call_from_thread(
                        lambda: self._log_to_activity(
                            "Frida server failed to start (see log / adb logcat)",
                            error=True,
                        )
                    )

                # Now execute the original action
                if self.action_queue:
                    self._controller.execute_action(action_name, self.action_queue)

        except ImportError as e:
            msg = f"Frida not available: {e}"
            self.app.call_from_thread(lambda: self._log_to_activity(msg, error=True))
        except Exception as e:
            msg = f"Frida installation failed: {e}"
            self.app.call_from_thread(lambda: self._log_to_activity(msg, error=True))

        # Refresh UI
        self.app.call_from_thread(self._refresh_after_action)

    def _log_to_activity(self, message: str, error: bool = False) -> None:
        """Log a message to the activity log (call from main thread).

        Args:
            message: Message to log
            error: If True, log as error
        """
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            if error:
                activity_log.log_error(message)
            else:
                activity_log.log_info(message)
        except Exception:
            pass

    def _safe_refresh_status_bar(self) -> None:
        """Refresh the status bar, tolerating missing widget.

        Uses refresh_status() (update + repaint) so the glance band re-renders
        on event-driven paths (task started/stopped/output) — important now
        that the band shows live hooks/bypass/pid that change on those events.
        """
        try:
            status_bar = self.query_one("#status-bar", StatusBar)
            status_bar.refresh_status()
        except Exception:
            pass

    def refresh_status(self) -> None:
        """Refresh the status bar from current state."""
        self._safe_refresh_status_bar()

    def refresh_menu(self) -> None:
        """No-op: the menu panel was removed. Kept for caller compatibility.

        Refreshes the status bar instead so external callers still get a
        sensible UI update.
        """
        self._safe_refresh_status_bar()

    def on_unmount(self) -> None:
        """Clean up when the screen is unmounted."""
        # Unsubscribe from events
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, handler in self._event_handlers:
                bus.unsubscribe(event_type, handler)
        except ImportError:
            pass
