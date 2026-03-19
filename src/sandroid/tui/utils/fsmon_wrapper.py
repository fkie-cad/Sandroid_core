"""FSMon process wrapper for TUI integration."""

import logging
import subprocess

logger = logging.getLogger(__name__)


class FSMonWrapper:
    """Wrapper around fsmon subprocess for TUI background task management.

    Provides:
    - Process lifecycle management
    - Clean termination support
    - Configuration storage
    """

    def __init__(self, process: subprocess.Popen, config):
        """Initialize the FSMon wrapper.

        Args:
            process: The fsmon subprocess
            config: FSMonConfig from the configuration modal
        """
        self.process = process
        self.config = config
        self._stopped = False

    @property
    def is_running(self) -> bool:
        """Check if the process is still running."""
        return self.process.poll() is None and not self._stopped

    def stop(self) -> None:
        """Stop the fsmon process.

        Terminates the process gracefully, then forces kill if needed.
        """
        if self._stopped:
            return

        self._stopped = True

        try:
            if self.process.poll() is None:
                # Try graceful termination first
                self.process.terminate()

                # Wait briefly for termination
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    logger.warning("FSMon did not terminate gracefully, killing...")
                    self.process.kill()
                    self.process.wait(timeout=1)

            logger.info("FSMon process stopped")

        except Exception as e:
            logger.error(f"Error stopping fsmon: {e}")
            # Try to force kill
            try:
                self.process.kill()
            except Exception:
                pass

    def __del__(self):
        """Ensure process is stopped on garbage collection."""
        if not self._stopped:
            self.stop()
