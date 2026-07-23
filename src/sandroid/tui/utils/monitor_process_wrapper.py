"""Monitor process wrapper for TUI integration."""

import logging
import subprocess
from collections import deque
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

#: Bound on the new, non-cleared ``recent_events`` history (see
#: :attr:`MonitorProcessWrapper.recent_events`'s docstring). Mirrors
#: ``ai/tools/flow_query.py``'s ``_MAX_LIMIT`` hard-cap convention.
_MAX_RECENT_EVENTS = 2000


class MonitorProcessWrapper:
    """Wrapper around a monitor subprocess for TUI background task management.

    Provides:
    - Process lifecycle management
    - Clean termination support
    - Configuration storage
    - Optional backend teardown (kprobe) run AFTER the process is killed
    - Optional per-session stream translator (kprobe), stored here so the
      reader thread can run it AHEAD of its ring buffer
    - A bounded, non-cleared per-session event history for the AI chat's
      ``get_recent_file_changes`` tool (see :attr:`recent_events`)
    """

    def __init__(
        self,
        process: subprocess.Popen,
        config,
        teardown: Callable[[], None] | None = None,
        translator: Any | None = None,
    ):
        """Initialize the Monitor wrapper.

        Args:
            process: The monitor subprocess.
            config: MonitorConfig from the configuration modal.
            teardown: Optional idempotent backend teardown. Invoked by
                :meth:`stop` AFTER the process is killed (so a streaming
                ``cat trace_pipe`` releases the tracefs instance before it is
                removed) and again, harmlessly, from the natural-exit path
                (``MonitorController._monitor_ended``). fsmon passes ``None``.
            translator: Optional long-lived per-session stream translator
                (kprobe's ``KprobeStreamTranslator``). When present the reader
                thread routes raw lines through it, in the reader thread,
                before any ring-buffering. fsmon passes ``None``.
        """
        self.process = process
        self.config = config
        self.translator = translator
        self._teardown = teardown
        self._stopped = False
        self._torn_down = False
        # Genuinely NEW, separately-maintained, append-only event history --
        # NOT a rename/promotion of MonitorController._start_output_reader's
        # `item_buffer`/`line_buffer` closures, which are transient per-flush
        # batches `.clear()`-ed on every `flush_to_ui()` call (every ~0.15s
        # by default) and hold at most one flush interval's worth of events
        # at any instant. This deque is never cleared during a session (only
        # bounded by `maxlen`, oldest-evicted), so the AI chat's
        # `get_recent_file_changes` tool can read a real rolling window
        # instead of whatever happens to be in-flight in the next flush.
        # Populated from the reader thread via `record_event()` -- see
        # `MonitorController._start_output_reader`'s `ingest()` closures.
        self.recent_events: deque[dict] = deque(maxlen=_MAX_RECENT_EVENTS)
        self._event_seq = 0

    def record_event(self, event: dict) -> None:
        """Append one parsed event to :attr:`recent_events`.

        Tags *event* with the next monotonic ``seq`` (never reused, even
        past the ``maxlen`` eviction horizon) so cursor-style polling ("give
        me everything since seq N") works the same way
        ``mitmproxy_flow_log``'s cursor convention does. Mutates *event* in
        place (adds the ``"seq"`` key) purely to avoid an extra dict copy on
        this hot reader-thread path.

        Args:
            event: The parsed event dict to record (no fixed schema is
                enforced here -- see the two ``ingest()`` closures in
                ``MonitorController._start_output_reader`` for the actual
                shape each backend populates).
        """
        self._event_seq += 1
        event["seq"] = self._event_seq
        self.recent_events.append(event)

    @property
    def is_running(self) -> bool:
        """Check if the process is still running."""
        return self.process.poll() is None and not self._stopped

    def run_teardown(self) -> None:
        """Run the backend teardown exactly once (idempotent).

        Safe to call from BOTH exit paths -- ``stop`` (user stop / Play-revert,
        which route through ``TaskService.stop`` -> ``stop_callback``) AND
        ``MonitorController._monitor_ended`` (natural process exit / adb death,
        which calls ``unregister()`` and does NOT trigger ``stop_callback``).
        Without the natural-exit call a kprobe session's instance/probes/
        set_event_pid/buffer would leak and wedge the next start.
        """
        if self._torn_down:
            return
        self._torn_down = True
        if self._teardown is not None:
            try:
                self._teardown()
            except Exception:
                logger.debug("Monitor backend teardown failed", exc_info=True)

    def stop(self) -> None:
        """Stop the monitor process, THEN tear the backend down.

        Kills the Popen FIRST (releasing any ``cat trace_pipe`` holding the
        tracefs instance open) before running teardown -- removing the instance
        while ``cat`` still holds it would EBUSY.
        """
        if self._stopped:
            # Already stopped; still make sure teardown has run (idempotent).
            self.run_teardown()
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
                    logger.warning("Monitor did not terminate gracefully, killing...")
                    self.process.kill()
                    self.process.wait(timeout=1)

            logger.info("Monitor process stopped")

        except Exception as e:
            logger.error(f"Error stopping monitor: {e}")
            # Try to force kill
            try:
                self.process.kill()
            except Exception:
                pass
        finally:
            # Teardown ONLY after the process is dead (pipe released).
            self.run_teardown()

    def __del__(self):
        """Ensure process is stopped on garbage collection."""
        if not self._stopped:
            self.stop()
