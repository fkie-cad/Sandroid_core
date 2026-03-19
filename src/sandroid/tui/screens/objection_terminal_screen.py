"""Embedded terminal modal for interactive objection sessions."""

import logging
import re

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, RichLog, Static

from sandroid.core.pty_process import PTYProcess
from sandroid.services import get_objection_service

logger = logging.getLogger(__name__)


class ObjectionTerminalScreen(ModalScreen):
    """Modal terminal overlay for objection interactive sessions.

    Features:
    - Overlay modal covering most of the screen
    - Output area showing objection responses
    - Input line for entering commands
    - Status bar showing target app and session info
    - Minimizable to return to main menu

    Keyboard shortcuts:
    - Esc: Quit objection session
    - Ctrl+B: Minimize (go back to main menu, session continues)
    """

    DEFAULT_CSS = """
    ObjectionTerminalScreen {
        align: center middle;
        background: rgba(5, 8, 17, 0.7);
    }

    ObjectionTerminalScreen #terminal-container {
        background: #0d1117;
        border: solid #58a6ff;
        width: 95%;
        height: 85%;
        padding: 0;
        overflow: hidden;
    }

    ObjectionTerminalScreen #status-bar {
        dock: top;
        height: 1;
        width: 100%;
        background: #161b22;
        color: #58a6ff;
        text-style: bold;
        padding: 0 1;
    }

    ObjectionTerminalScreen #terminal-output {
        width: 100%;
        height: 1fr;
        background: #0d1117;
        border: none;
        scrollbar-size: 1 1;
        scrollbar-background: #0d1117;
        scrollbar-color: #30363d;
    }

    ObjectionTerminalScreen #terminal-output:focus {
        border: none;
    }

    ObjectionTerminalScreen #input-line {
        dock: bottom;
        height: 3;
        width: 100%;
        background: #161b22;
        padding: 0 1;
    }

    ObjectionTerminalScreen #command-input {
        width: 100%;
        background: #0d1117;
        border: solid #30363d;
        color: #c9d1d9;
        padding: 0 1;
    }

    ObjectionTerminalScreen #command-input:focus {
        border: solid #58a6ff;
    }

    ObjectionTerminalScreen #hint-bar {
        dock: bottom;
        height: 1;
        width: 100%;
        background: #161b22;
        color: #8b949e;
        text-align: center;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Quit Session"),
        Binding("ctrl+b", "minimize", "Back to Menu"),
    ]

    def __init__(
        self,
        cmd: list[str],
        package_name: str,
        spawn_mode: bool = True,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the terminal modal.

        Args:
            cmd: Command to execute (objection command list)
            package_name: Target package name for status display
            spawn_mode: Whether objection is in spawn mode
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.cmd = cmd
        self.package_name = package_name
        self.spawn_mode = spawn_mode
        self.pty_process: PTYProcess | None = None
        self._minimized = False
        self._output_buffer: list[str] = []  # Store output for resume
        self._stop_reader = False  # Flag to stop the reader thread
        self._command_history: list[str] = []  # Command history
        self._history_index = -1

    def compose(self) -> ComposeResult:
        """Create the terminal modal layout."""
        mode_str = "SPAWN" if self.spawn_mode else "ATTACH"
        mode_color = "#f0883e" if self.spawn_mode else "#3fb950"

        with Vertical(id="terminal-container"):
            yield Static(
                f"[bold #58a6ff]Objection Session[/] | "
                f"Target: [#f0883e]{self.package_name}[/] | "
                f"Mode: [bold {mode_color}]{mode_str}[/]",
                id="status-bar",
            )
            yield RichLog(
                id="terminal-output",
                highlight=False,
                markup=True,
                wrap=True,
                auto_scroll=True,
            )
            with Vertical(id="input-line"):
                yield Input(
                    placeholder="Enter objection command...",
                    id="command-input",
                )
            yield Static(
                "[dim][bold]Enter[/]=Send  "
                "[bold]↑↓[/]=History  "
                "[bold]Esc[/]=Quit  "
                "[bold]Ctrl+B[/]=Minimize[/dim]",
                id="hint-bar",
            )

    def on_mount(self) -> None:
        """Start the objection process when modal is mounted."""
        self._stop_reader = False

        if self._minimized:
            # Resuming from minimized - restore buffer to new widgets
            self._restore_buffer()
            self._minimized = False  # Reset after restoration
        else:
            # Fresh start
            self._start_process()

        # Focus the input
        try:
            cmd_input = self.query_one("#command-input", Input)
            cmd_input.focus()
        except Exception:
            pass

    def _start_process(self) -> None:
        """Start the PTY process and begin reading output."""
        if self.pty_process and self.pty_process.is_running():
            # Already running (resumed from minimize)
            return

        try:
            # Get terminal dimensions - use modal size
            container = self.query_one("#terminal-container")
            rows = max(20, container.size.height - 5)
            cols = max(80, container.size.width - 2)

            self.pty_process = PTYProcess(
                self.cmd,
                rows=rows,
                cols=cols,
            )

            # Start reading output
            self._start_output_reader()

            # Log startup - also store in buffer
            startup_msg1 = (
                f"[bold #58a6ff]Starting objection for {self.package_name}...[/]\n"
            )
            startup_msg2 = f"[dim]Command: {' '.join(self.cmd)}[/]\n\n"
            self._output_buffer.append(startup_msg1)
            self._output_buffer.append(startup_msg2)

            terminal = self.query_one("#terminal-output", RichLog)
            terminal.write(startup_msg1)
            terminal.write(startup_msg2)

            logger.info(f"Started objection terminal for {self.package_name}")

        except Exception as e:
            logger.error(f"Failed to start objection process: {e}")
            terminal = self.query_one("#terminal-output", RichLog)
            terminal.write(f"[bold red]Error starting objection: {e}[/]\n")
            terminal.write("[dim]Press Esc to close.[/dim]")

    @work(exclusive=True, thread=True)
    def _start_output_reader(self) -> None:
        """Background worker to read PTY output."""
        import time

        while (
            not self._stop_reader and self.pty_process and self.pty_process.is_running()
        ):
            try:
                data = self.pty_process.read(timeout=0.1)
                if data:
                    # Decode and post to main thread
                    text = data.decode("utf-8", errors="replace")
                    self.app.call_from_thread(self._append_output, text)
            except Exception as e:
                logger.debug(f"Read error: {e}")
                break

            time.sleep(0.01)  # Small delay to prevent CPU spin

        # Process ended
        if not self._stop_reader:
            self.app.call_from_thread(self._on_process_ended)

    def _append_output(self, text: str) -> None:
        """Append output to the terminal (called from main thread).

        Args:
            text: Text to append
        """
        try:
            # Strip ANSI codes for now (Textual's RichLog doesn't handle all of them)
            clean_text = self._strip_ansi(text)
            # Store in buffer for resume
            self._output_buffer.append(clean_text)
            # Write to terminal
            terminal = self.query_one("#terminal-output", RichLog)
            terminal.write(clean_text)
        except Exception:
            pass

    _ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    def _strip_ansi(self, text: str) -> str:
        """Strip ANSI escape codes from text.

        Args:
            text: Text potentially containing ANSI codes

        Returns:
            Clean text without ANSI codes
        """
        return self._ANSI_RE.sub("", text)

    def _on_process_ended(self) -> None:
        """Handle process termination."""
        try:
            terminal = self.query_one("#terminal-output", RichLog)
            exit_code = self.pty_process.get_exit_code() if self.pty_process else None
            end_msg1 = (
                f"\n[bold #f0883e]Objection session ended (exit code: {exit_code})[/]\n"
            )
            end_msg2 = "[dim]Press Esc to close.[/dim]"
            # Store in buffer
            self._output_buffer.append(end_msg1)
            self._output_buffer.append(end_msg2)
            terminal.write(end_msg1)
            terminal.write(end_msg2)
        except Exception:
            pass

    def _restore_buffer(self) -> None:
        """Restore output buffer to terminal after resume.

        Called from on_mount when _minimized is True. This ensures the
        buffer is restored to the newly created widgets after compose().
        """
        try:
            terminal = self.query_one("#terminal-output", RichLog)
            if self._output_buffer:
                logger.info(f"Restoring {len(self._output_buffer)} output entries")
                for text in self._output_buffer:
                    terminal.write(text)

            # Restart output reader if process is still running
            if self.pty_process and self.pty_process.is_running():
                self._start_output_reader()
        except Exception as e:
            logger.error(f"Error restoring buffer: {e}")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command submission from the input widget."""
        if event.input.id == "command-input":
            command = event.value.strip()
            if command:
                # Add to history
                self._command_history.append(command)
                self._history_index = len(self._command_history)

                # Echo command to output
                try:
                    terminal = self.query_one("#terminal-output", RichLog)
                    cmd_echo = f"[bold #58a6ff]> {command}[/]\n"
                    self._output_buffer.append(cmd_echo)
                    terminal.write(cmd_echo)
                except Exception:
                    pass

                # Send to PTY with newline
                if self.pty_process and self.pty_process.is_running():
                    self.pty_process.write_str(command + "\n")

            # Clear input
            event.input.value = ""

    def on_key(self, event) -> None:
        """Handle key presses for command history.

        Note: Escape and Ctrl+B are handled by BINDINGS with priority=True.
        This method only handles up/down arrow for command history navigation.
        """
        # Only handle up/down for command history - let bindings handle escape/ctrl+b
        try:
            cmd_input = self.query_one("#command-input", Input)
            if cmd_input.has_focus:
                if event.key == "up" and self._command_history:
                    if self._history_index > 0:
                        self._history_index -= 1
                        cmd_input.value = self._command_history[self._history_index]
                        cmd_input.cursor_position = len(cmd_input.value)
                    event.stop()
                    event.prevent_default()
                elif event.key == "down" and self._command_history:
                    if self._history_index < len(self._command_history) - 1:
                        self._history_index += 1
                        cmd_input.value = self._command_history[self._history_index]
                    else:
                        self._history_index = len(self._command_history)
                        cmd_input.value = ""
                    cmd_input.cursor_position = len(cmd_input.value)
                    event.stop()
                    event.prevent_default()
        except Exception:
            pass

    def on_resize(self, event) -> None:
        """Handle terminal resize.

        Args:
            event: Resize event from Textual
        """
        if self.pty_process and self.pty_process.is_running():
            try:
                container = self.query_one("#terminal-container")
                rows = max(20, container.size.height - 5)
                cols = max(80, container.size.width - 2)
                self.pty_process.resize(rows, cols)
            except Exception:
                pass

    def action_dismiss(self) -> None:
        """Quit the objection session and close modal.

        This overrides the standard ModalScreen dismiss action to include
        cleanup of the PTY process and session state.
        """
        logger.info("Quitting objection session")
        self._stop_reader = True  # Signal reader to stop
        self._cleanup()
        # Clear session from ObjectionService
        get_objection_service().clear()
        # Schedule refresh after dismissal
        self.app.call_later(self._refresh_app)
        self.dismiss(None)

    def action_minimize(self) -> None:
        """Minimize to main menu (session continues in background)."""
        logger.info("Minimizing objection session")
        self._minimized = True
        self._stop_reader = True  # Stop reader while minimized
        # Store session reference in ObjectionService
        get_objection_service().set_session(self)
        # Schedule refresh after dismissal
        self.app.call_later(self._refresh_app)
        self.dismiss("minimized")

    def _refresh_app(self) -> None:
        """Refresh the app display after modal closes."""
        try:
            self.app.refresh(layout=True)
            if hasattr(self.app, "refresh_menu"):
                self.app.refresh_menu()
        except Exception:
            pass

    def resume(self) -> None:
        """Prepare for resume from minimized state.

        Note: _minimized stays True so on_mount knows to restore buffer.
        Buffer restoration happens in on_mount via _restore_buffer.
        This method is called after push_screen, but on_mount has already
        run by then. So we just reset the reader flag here.
        """
        logger.info("Preparing to resume objection session")
        self._stop_reader = False
        # Don't set _minimized = False here - on_mount already handled it

    def _cleanup(self) -> None:
        """Clean up resources."""
        self._stop_reader = True
        if self.pty_process:
            try:
                self.pty_process.terminate(timeout=2.0)
            except Exception as e:
                logger.debug(f"Error terminating PTY: {e}")
            self.pty_process = None

    def on_unmount(self) -> None:
        """Clean up when modal is unmounted."""
        self._stop_reader = True
        if not self._minimized:
            self._cleanup()
