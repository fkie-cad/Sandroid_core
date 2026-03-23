"""PTY-based subprocess management for interactive terminal sessions.

This module provides a wrapper around subprocess that uses pseudo-terminals (PTY)
to enable proper interactive sessions with tools like objection that require
terminal input/output.
"""

from __future__ import annotations

import logging
import os
import signal
import struct
import subprocess

from typing_extensions import Self

# PTY support is only available on Unix-like systems
try:
    import fcntl
    import pty
    import select
    import termios

    _PTY_AVAILABLE = True
except ImportError:
    _PTY_AVAILABLE = False

logger = logging.getLogger(__name__)


class PTYProcess:
    """Manages a subprocess with PTY for interactive sessions.

    This class creates a pseudo-terminal and runs a subprocess connected to it,
    enabling proper interactive terminal behavior for tools like objection.

    Attributes:
        process: The underlying subprocess.Popen instance
        master_fd: File descriptor for the master side of the PTY
        running: Whether the process is currently running
    """

    def __init__(
        self,
        cmd: list[str],
        env: dict | None = None,
        cwd: str | None = None,
        rows: int = 24,
        cols: int = 80,
    ):
        """Initialize and start the PTY process.

        Args:
            cmd: Command to execute as a list of arguments
            env: Environment variables (defaults to current env)
            cwd: Working directory for the process
            rows: Terminal rows (height)
            cols: Terminal columns (width)
        """
        if not _PTY_AVAILABLE:
            raise OSError(
                "PTYProcess is not supported on Windows. "
                "Interactive terminal sessions require a Unix-like operating system."
            )

        self.cmd = cmd
        self.env = env or os.environ.copy()
        self.cwd = cwd
        self.rows = rows
        self.cols = cols

        self.master_fd: int | None = None
        self.slave_fd: int | None = None
        self.process: subprocess.Popen | None = None
        self.running = False

        self._start()

    def _start(self) -> None:
        """Start the PTY process."""
        try:
            # Create the pseudo-terminal pair
            self.master_fd, self.slave_fd = pty.openpty()

            # Set terminal size
            self._set_terminal_size(self.rows, self.cols)

            # Set master to non-blocking mode
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Start the process
            self.process = subprocess.Popen(
                self.cmd,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                env=self.env,
                cwd=self.cwd,
                preexec_fn=os.setsid,  # Create new session
                close_fds=True,
            )

            # Close slave fd in parent process (child has it)
            os.close(self.slave_fd)
            self.slave_fd = None

            self.running = True
            logger.debug(
                f"Started PTY process: {' '.join(self.cmd)} (PID: {self.process.pid})"
            )

        except Exception as e:
            logger.error(f"Failed to start PTY process: {e}")
            self._cleanup()
            raise

    def _set_terminal_size(self, rows: int, cols: int) -> None:
        """Set the terminal size.

        Args:
            rows: Number of rows (height)
            cols: Number of columns (width)
        """
        if self.master_fd is not None:
            # TIOCSWINSZ = Terminal I/O Control Set WINdow SiZe
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            self.rows = rows
            self.cols = cols

    def resize(self, rows: int, cols: int) -> None:
        """Resize the terminal.

        Args:
            rows: New number of rows
            cols: New number of columns
        """
        self._set_terminal_size(rows, cols)
        # Send SIGWINCH to notify process of size change
        if self.process and self.running:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGWINCH)
            except (OSError, ProcessLookupError):
                pass

    def read(self, timeout: float = 0.1) -> bytes:
        """Read available output from the PTY.

        Args:
            timeout: Maximum time to wait for data (seconds)

        Returns:
            Bytes read from the PTY, empty if nothing available
        """
        if self.master_fd is None or not self.running:
            return b""

        try:
            # Check if data is available
            ready, _, _ = select.select([self.master_fd], [], [], timeout)
            if ready:
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        # EOF - process likely exited
                        self.running = False
                    return data
                except OSError as e:
                    if e.errno == 5:  # Input/output error - process exited
                        self.running = False
                    return b""
            return b""
        except Exception as e:
            logger.debug(f"Read error: {e}")
            return b""

    def write(self, data: bytes) -> bool:
        """Write data to the PTY (send to process stdin).

        Args:
            data: Bytes to write

        Returns:
            True if write succeeded, False otherwise
        """
        if self.master_fd is None or not self.running:
            return False

        try:
            os.write(self.master_fd, data)
            return True
        except OSError as e:
            logger.debug(f"Write error: {e}")
            if e.errno == 5:  # Input/output error
                self.running = False
            return False

    def write_str(self, text: str) -> bool:
        """Write a string to the PTY.

        Args:
            text: String to write (will be encoded as UTF-8)

        Returns:
            True if write succeeded, False otherwise
        """
        return self.write(text.encode("utf-8"))

    def send_key(self, key: str) -> bool:
        """Send a special key to the PTY.

        Args:
            key: Key name (e.g., "enter", "tab", "ctrl+c")

        Returns:
            True if sent successfully
        """
        key_map = {
            "enter": b"\r",
            "tab": b"\t",
            "backspace": b"\x7f",
            "escape": b"\x1b",
            "ctrl+c": b"\x03",
            "ctrl+d": b"\x04",
            "ctrl+z": b"\x1a",
            "ctrl+l": b"\x0c",
            "up": b"\x1b[A",
            "down": b"\x1b[B",
            "right": b"\x1b[C",
            "left": b"\x1b[D",
            "home": b"\x1b[H",
            "end": b"\x1b[F",
            "page_up": b"\x1b[5~",
            "page_down": b"\x1b[6~",
            "delete": b"\x1b[3~",
        }

        if key.lower() in key_map:
            return self.write(key_map[key.lower()])
        return False

    def is_running(self) -> bool:
        """Check if the process is still running.

        Returns:
            True if process is running, False otherwise
        """
        if self.process is None:
            return False

        # Poll the process
        ret = self.process.poll()
        if ret is not None:
            self.running = False
            return False

        return self.running

    def get_exit_code(self) -> int | None:
        """Get the exit code if process has terminated.

        Returns:
            Exit code or None if still running
        """
        if self.process is None:
            return None
        return self.process.poll()

    def terminate(self, timeout: float = 5.0) -> int:
        """Terminate the process gracefully.

        First sends SIGTERM, waits for timeout, then SIGKILL if needed.

        Args:
            timeout: Seconds to wait for graceful termination

        Returns:
            Exit code of the process
        """
        if self.process is None:
            return 0

        exit_code = self.process.poll()
        if exit_code is not None:
            self._cleanup()
            return exit_code

        # Try graceful termination
        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

        try:
            exit_code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Force kill
            logger.warning(
                f"Process {self.process.pid} did not terminate, sending SIGKILL"
            )
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            exit_code = self.process.wait(timeout=1.0)

        self._cleanup()
        return exit_code

    def _cleanup(self) -> None:
        """Clean up resources."""
        self.running = False

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        if self.slave_fd is not None:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = None

        logger.debug("PTY process resources cleaned up")

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - ensures cleanup."""
        self.terminate()

    def __del__(self) -> None:
        """Destructor - ensures cleanup."""
        if self.running:
            try:
                self.terminate(timeout=1.0)
            except Exception:
                pass
