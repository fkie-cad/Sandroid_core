"""Monitor Controller for TUI.

This controller manages Monitor filesystem monitoring operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop Monitor monitoring
- Configure monitoring paths and PIDs
- Process and display filesystem events
- Handle monitoring lifecycle
- Publish live events to the Files tab's Monitor sub-tab via the EventBus

Usage:
    from sandroid.tui.controllers import MonitorController

    controller = MonitorController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        call_from_thread=app.call_from_thread,
        force_ui_refresh=app._force_ui_refresh,
    )

    # Start Monitor monitoring
    controller.start_monitor()
"""

import logging
import re
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rich.markup import escape

logger = logging.getLogger(__name__)


@dataclass
class MonitorConfig:
    """Configuration for Monitor monitoring."""

    mode: str = "path"  # "pid" or "path"
    target_path: str = "/data/"
    target_pid: int | None = None
    app_name: str = ""
    cancelled: bool = False


# Regex to strip ANSI escape sequences and carriage returns from PTY output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\r")

# Regex matching a package-scoped Android data directory prefix, e.g.
# "/data/data/com.example.app/" or "/data/user/0/com.example.app/".
_PKG_PATH_RE = re.compile(r"^(/data/(?:data|user/\d+)/[^/]+/)")


@dataclass(frozen=True)
class MonitorEvent:
    r"""A parsed monitor filesystem-event line.

    monitor's raw wire format is tab-separated:
    ``<FSE_EVENT_TYPE>\t<pid>\t"<process_name>"\t<path>``, or for renames:
    ``FSE_RENAME\t<pid>\t"<process_name>"\t<old_path> -> <new_path>``.
    """

    event_type: str
    pid: int | None
    process: str
    path: str
    new_path: str | None = None


@dataclass(frozen=True)
class MonitorEventMeta:
    """Display metadata for one ``FSE_*`` token."""

    label: str
    color: str
    category: str


# Exact-token lookup for monitor event metadata (fixes the old substring-keyword
# matching, which silently missed real tokens like FSE_CONTENT_MODIFIED and
# FSE_CLOSE). No icon glyphs -- plain colored uppercase labels only (explicit
# user feedback rejecting an earlier icon-based design).
MONITOR_EVENT_INFO: dict[str, MonitorEventMeta] = {
    "FSE_CREATE_FILE": MonitorEventMeta("CREATE", "#4ade80", "create"),
    "FSE_CREATE_DIR": MonitorEventMeta("CREATE DIR", "#4ade80", "create"),
    "FSE_CONTENT_MODIFIED": MonitorEventMeta("MODIFY", "#a78bfa", "modify"),
    "FSE_DELETE": MonitorEventMeta("DELETE", "#fb7185", "delete"),
    "FSE_RENAME": MonitorEventMeta("RENAME", "#facc15", "rename"),
    "FSE_STAT_CHANGED": MonitorEventMeta("ATTRS", "#7dd3fc", "attrs"),
    "FSE_ATTRIB": MonitorEventMeta("ATTRS", "#7dd3fc", "attrs"),
    "FSE_XATTR_MODIFIED": MonitorEventMeta("XATTR", "#7dd3fc", "attrs"),
    "FSE_OPEN": MonitorEventMeta("OPEN", "#5b6479", "noise"),
    "FSE_CLOSE": MonitorEventMeta("CLOSE", "#5b6479", "noise"),
}


def parse_monitor_line(line: str) -> MonitorEvent | None:
    """Tokenize one raw monitor output line into an :class:`MonitorEvent`.

    Defensive by design: a future monitor version drifting slightly in its
    wire format must degrade gracefully (return ``None``) rather than crash
    the reader thread.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.

    Returns:
        The parsed event, or ``None`` if the line doesn't look like a valid
        monitor event line.
    """
    try:
        parts = line.split("\t")
        if len(parts) < 4:
            return None

        event_type = parts[0].strip()
        pid_str = parts[1].strip()
        process = parts[2].strip().strip('"')
        rest = "\t".join(parts[3:]).strip()

        pid: int | None
        try:
            pid = int(pid_str)
        except ValueError:
            pid = None

        new_path: str | None = None
        if event_type == "FSE_RENAME" and " -> " in rest:
            old_path, new_path = rest.split(" -> ", 1)
            path = old_path.strip()
            new_path = new_path.strip()
        else:
            path = rest

        if not event_type or not path:
            return None

        return MonitorEvent(
            event_type=event_type,
            pid=pid,
            process=process,
            path=path,
            new_path=new_path,
        )
    except Exception:
        return None


def colorize_monitor_line(line: str, max_width: int = 0) -> str:
    """Apply color markup to an monitor output line.

    Escapes raw content first to prevent Rich markup interpretation,
    then wraps in color tags based on the parsed event's exact ``FSE_*``
    token (via :func:`parse_monitor_line`/``MONITOR_EVENT_INFO``).

    Args:
        line: Raw monitor output line.
        max_width: Truncate to this width before escaping. 0 means no truncation.

    Returns:
        Escaped and optionally colorized Rich markup string.
    """
    truncated = line[:max_width] if max_width > 0 else line
    escaped = escape(truncated)
    event = parse_monitor_line(line)
    if event is not None:
        meta = MONITOR_EVENT_INFO.get(event.event_type)
        if meta is not None:
            return f"[{meta.color}]{escaped}[/{meta.color}]"
    return escaped


def _resolve_prefix_candidates(config: Any) -> tuple[str, ...]:
    """Build redundant-path-prefix candidates from an ``MonitorConfig``-like object.

    Used to strip a redundant ``/data/data/<pkg>/`` or ``/data/user/0/<pkg>/``
    prefix from displayed paths in Monitor's compact row -- computed once per
    batch flush (not per line).

    Args:
        config: An ``MonitorConfig`` (or duck-typed equivalent) with optional
            ``app_name``/``target_path`` attributes.

    Returns:
        A tuple of candidate prefixes (longest-match stripping is done by the
        caller).
    """
    candidates: list[str] = []
    if config is None:
        return ()

    app_name = getattr(config, "app_name", None)
    if app_name:
        candidates.append(f"/data/data/{app_name}/")
        candidates.append(f"/data/user/0/{app_name}/")

    target_path = getattr(config, "target_path", None)
    if target_path:
        match = _PKG_PATH_RE.match(target_path)
        if match:
            candidates.append(match.group(1))

    return tuple(candidates)


def _strip_prefix(path: str, prefix_candidates: tuple[str, ...]) -> str:
    """Strip the longest matching redundant path prefix (strip-only step).

    Split out of the old ``_display_path`` (which coupled prefix-stripping
    with truncate-keep-tail) so the strip step can be reused standalone --
    the grouped view's directory/filename split and the full-path view's
    untruncated display both need prefix-stripped (but NOT truncated)
    paths; ``_display_path`` below now just layers truncation on top of
    this.
    """
    best = ""
    for prefix in prefix_candidates:
        if path.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    return path[len(best) :] if best else path


def _display_path(
    path: str, prefix_candidates: tuple[str, ...], width: int = 36
) -> str:
    """Strip the longest matching prefix, then left-truncate keeping the tail.

    Mirrors the truncate-keep-tail idiom in ``tui/widgets/watchlist_view.py``
    (``_row_label``), since the filename/extension is the distinguishing part
    of long Android cache/data paths.
    """
    display = _strip_prefix(path, prefix_candidates)

    if len(display) > width:
        display = "…" + display[-(width - 1) :]
    return display


def _split_dir_filename(path: str) -> tuple[str, str]:
    """Split an already prefix-stripped path into ``(directory, filename)``.

    Used by :func:`build_monitor_item` for MonitorView's own
    grouping/breadcrumb pass (Part B) -- the view groups consecutive items
    by exact ``directory`` match and renders a ``▸ <directory>/`` breadcrumb
    for runs of 2+. ``directory`` has no trailing slash (the view adds its
    own when rendering the breadcrumb); a bare filename with no ``/`` at
    all yields an empty directory string (never groups into a breadcrumb
    run with anything else, which is correct -- it has no directory to
    share).
    """
    if "/" in path:
        directory, _, filename = path.rpartition("/")
        return directory, filename
    return "", path


def format_monitor_event_row(
    line: str, prefix_candidates: tuple[str, ...] = ()
) -> tuple[str, str | None]:
    """Format one raw monitor line into Monitor's compact row.

    Format: ``HH:MM:SS  [color]LABEL[/]  <path>`` (renames show
    ``old -> new``, a plain ASCII arrow matching monitor's own raw format).
    Unparseable lines or tokens missing from ``MONITOR_EVENT_INFO`` still
    produce a row (falling back to a plain, uncolored line) -- a line is
    never silently dropped.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.
        prefix_candidates: Redundant path prefixes to strip before display
            (see :func:`_resolve_prefix_candidates`).

    Returns:
        A ``(rich_markup_row, category)`` tuple. ``category`` is ``None`` if
        the line is unparseable or its token is unknown.
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    event = parse_monitor_line(line)

    if event is None:
        return f"{timestamp}  {escape(line)}", None

    meta = MONITOR_EVENT_INFO.get(event.event_type)

    if event.new_path is not None:
        old_display = _display_path(event.path, prefix_candidates)
        new_display = _display_path(event.new_path, prefix_candidates)
        path_display = f"{old_display} -> {new_display}"
    else:
        path_display = _display_path(event.path, prefix_candidates)

    escaped_path = escape(path_display)

    if meta is None:
        label = event.event_type
        return f"{timestamp}  {escape(label):<10}  {escaped_path}", None

    label = f"{meta.label:<10}"
    return f"{timestamp}  [{meta.color}]{label}[/]  {escaped_path}", meta.category


@dataclass(frozen=True)
class MonitorItem:
    """Backend-neutral base for one parsed monitor event.

    A typed hierarchy so future non-filesystem items (e.g. network) can share
    MonitorView's rendering pipeline. ``kind`` names the item family and
    ``source`` records which backend produced it (``"fsmon"`` | ``"kprobe"``);
    both carry defaults so builders/subclasses only set what they need.
    """

    label: str
    color: str | None
    category: str | None
    kind: str = "filesystem"
    source: str = "fsmon"


@dataclass(frozen=True)
class FileSystemMonitorItem(MonitorItem):
    """One parsed+categorized monitor line, structured for MonitorView's own
    grouping/dedup/visibility-filtering/tallying/width-aware rendering
    pipeline (Part B of the monitor follow-up plan).

    NOT a final rendered string -- see B1's "Defect 1"/"Defect 2" for why:
    grouping, dedup, visibility filtering, tallying, and width-aware
    formatting all need to live in ``MonitorView`` (the only place with a
    real widget reference and the "always tally, conditionally render"
    invariant the header/badge depend on), so the controller hands over
    parsed, prefix-stripped, directory/filename-split data instead of a
    finished row.

    ``directory``/``filename`` are prefix-stripped (see ``_strip_prefix``)
    but deliberately NOT truncated -- MonitorView decides truncation width
    itself (from its own RichLog's rendered content width) and whether to
    truncate at all (the 'u' full-path toggle bypasses truncation
    entirely).

    For a plain create/modify/delete/attrs event, only ``directory``/
    ``filename`` are set. For ``FSE_RENAME``, ``new_directory``/
    ``new_filename`` are also set (the new path, same prefix-stripping
    treatment) -- ``directory``/``filename`` describe the OLD path, which
    is what determines whether the rename joins the current directory-run
    (a rename groups based on where it originated).
    """

    directory: str = ""
    filename: str = ""
    new_directory: str | None = None
    new_filename: str | None = None


def build_monitor_item(
    line: str, prefix_candidates: tuple[str, ...] = ()
) -> FileSystemMonitorItem:
    """Parse+categorize one raw monitor line into a structured display item.

    Supersedes ``format_monitor_event_row`` for production wiring (Part B):
    grouping/dedup/tallying/width-aware truncation all now live in
    MonitorView, so the controller only needs to hand over parsed,
    prefix-stripped, directory/filename-split data -- not a final Rich
    markup string. ``format_monitor_event_row`` itself is left unchanged
    (still directly exercised by tests and available as a standalone
    formatter), it's simply no longer called by ``_log_monitor_output_batch``.

    Args:
        line: Raw (already ANSI-stripped) monitor output line.
        prefix_candidates: Redundant path prefixes to strip before display
            (see :func:`_resolve_prefix_candidates`).

    Returns:
        A structured :class:`FileSystemMonitorItem`. Malformed/unparseable
        input never raises and is never silently dropped -- it becomes an
        item with the raw line as its ``filename`` (no directory to
        derive), matching ``format_monitor_event_row``'s own "never drop a
        line" contract.
    """
    event = parse_monitor_line(line)

    if event is None:
        return FileSystemMonitorItem(
            label="", color=None, category=None, directory="", filename=line
        )

    meta = MONITOR_EVENT_INFO.get(event.event_type)
    label = meta.label if meta is not None else event.event_type
    color = meta.color if meta is not None else None
    category = meta.category if meta is not None else None

    directory, filename = _split_dir_filename(
        _strip_prefix(event.path, prefix_candidates)
    )

    new_directory: str | None = None
    new_filename: str | None = None
    if event.new_path is not None:
        new_directory, new_filename = _split_dir_filename(
            _strip_prefix(event.new_path, prefix_candidates)
        )

    return FileSystemMonitorItem(
        label=label,
        color=color,
        category=category,
        directory=directory,
        filename=filename,
        new_directory=new_directory,
        new_filename=new_filename,
    )


def _publish_monitor_batch(items: list[FileSystemMonitorItem]) -> None:
    """Publish a WHOLE BATCH of parsed monitor items as a single EventBus event.

    Supersedes the old per-line ``_publish_monitor_event`` (Part B, see B1):
    one call per BATCH, not one per line -- ``MonitorView`` needs the
    batch's items in order (with a real widget reference) to run its own
    grouping/dedup/visibility-filtering/tallying/width-aware rendering
    pass, none of which can happen here anymore. Mirrors
    ``analysis/fritap.py``'s ``_publish_fritap_event`` for the EventBus
    idiom itself (lazy import, ``source="monitor"``, silently-logged
    failure).

    Args:
        items: The batch's parsed items, in the original line order.
            A no-op on an empty list (nothing to publish).
    """
    if not items:
        return
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "Monitor", "batch": items},
                source="monitor",
            )
        )
    except Exception:
        logger.debug("Failed to publish monitor EventBus event", exc_info=True)


class MonitorController:
    """Controller for Monitor filesystem monitoring.

    This controller handles all Monitor-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of Monitor logic from UI rendering
    - Reusable Monitor management across different UI modes

    Thread Safety:
        Monitor output reading runs in background threads.
        Log callbacks are invoked via call_from_thread.

    Example:
        controller = MonitorController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            call_from_thread=lambda fn, *args: fn(*args),
            force_ui_refresh=lambda: None,
        )

        # Start Monitor
        controller.start_monitor()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        log_task_started: Callable[[str, str], None] | None = None,
        log_task_stopped: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        call_from_thread: Callable[..., None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        get_current_view: Callable[[], str] | None = None,
        open_files_tab: Callable[[], None] | None = None,
        on_pid_mode_fallback: Callable[[str], None] | None = None,
    ):
        """Initialize MonitorController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            log_task_started: Callback when task starts (name, description)
            log_task_stopped: Callback when task stops (name)
            push_modal: Callback to push a modal screen with result callback
            call_from_thread: Callback to execute function on main thread
            force_ui_refresh: Callback to force UI refresh after state changes
            get_current_view: Callback to get current view mode
            open_files_tab: Callback to switch the TUI to the Files tab's
                Monitor sub-tab, invoked once monitor has actually *started*
                (after ``_start_monitor`` registers with TaskService) — not
                merely when the config modal opens. Mirrors friTap's
                ``h`` key -> ``MainScreen.open_fritap_tab()`` jump
                (``app.py``'s ``action_action_key``). Injected rather than
                importing ``app.py``/``MainScreen`` directly here, same
                reasoning as every other UI callback on this controller.
            on_pid_mode_fallback: Callback invoked (with the path now being
                monitored instead) when a PID-mode start silently falls back
                to path-mode because ``FSMon.fanotify_supported()`` reports
                the device's kernel lacks fanotify. ``_start_monitor`` already
                runs on the main thread (see the ``_open_files_tab`` callback
                above for the same reasoning), so this is invoked directly,
                no ``call_from_thread`` marshaling needed.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._log_task_started = log_task_started
        self._log_task_stopped = log_task_stopped
        self._push_modal = push_modal
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._force_ui_refresh = force_ui_refresh
        self._get_current_view = get_current_view
        self._open_files_tab = open_files_tab
        self._on_pid_mode_fallback = on_pid_mode_fallback

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_task_service(self) -> Any:
        """Get task service instance."""
        from sandroid.services import get_task_service

        return get_task_service()

    # =========================================================================
    # Monitor Status
    # =========================================================================

    def is_running(self) -> bool:
        """Check if Monitor is currently running.

        Returns:
            True if Monitor is active
        """
        return self._get_task_service().is_running("monitor")

    def can_start(self) -> tuple[bool, str]:
        """Check if Monitor can be started.

        Returns:
            Tuple of (can_start, reason_if_not)
        """
        if self.is_running():
            return (
                False,
                "Monitor is already running. Press 'o' to stop it.",
            )

        return True, ""

    # =========================================================================
    # Monitor Operations
    # =========================================================================

    def show_config_modal(self) -> bool:
        """Show Monitor configuration modal.

        Returns:
            True if modal was shown
        """
        from sandroid.tui.modals import MonitorConfigModal

        can_start, reason = self.can_start()

        if not can_start:
            # Already running -> toggle it off (mirrors the old
            # already-running-in-background-mode behavior; there is no
            # observer modal to restore anymore, Monitor is the only
            # display surface).
            if self.is_running():
                return self.stop()
            self._log_warning(reason)
            return False

        if not self._push_modal:
            self._log_error("Cannot show config modal - push_modal not configured")
            return False

        def on_config(config: MonitorConfig) -> None:
            if config is None or config.cancelled:
                return
            self._start_monitor(config)

        self._push_modal(MonitorConfigModal(), on_config)
        return True

    def _get_buffer_interval(self) -> float:
        """Read monitor_buffer_interval from config.

        Returns:
            Interval in seconds (minimum 0.01 when set to 0).
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            interval = config.tui.monitor_buffer_interval
            return max(interval, 0.01) if interval > 0 else 0.01
        except Exception:
            return 0.15

    def _start_monitor(self, config: MonitorConfig) -> bool:
        """Start Monitor with the given configuration.

        Args:
            config: MonitorConfig from the configuration modal

        Returns:
            True if Monitor was started successfully
        """
        from sandroid.core.fsmon import FSMon
        from sandroid.tui.utils import MonitorProcessWrapper

        self._log_info("Installing/checking monitor binary...")

        # Check and install monitor binary
        try:
            FSMon.check_and_install_fsmon()
        except Exception as e:
            self._log_error(f"Failed to install monitor: {e}")
            return False

        # Start monitor based on mode
        try:
            if config.mode == "pid" and config.target_pid:
                if FSMon.fanotify_supported():
                    process = FSMon.run_fsmon_by_pid(
                        config.target_pid, config.target_path
                    )
                    mode_desc = f"PID {config.target_pid}"
                else:
                    # No fanotify on this device -- PID-mode attribution
                    # would silently be wrong (production monitor builds fall
                    # back to inotify and never error cleanly on -p). Fall
                    # back to path-mode instead, and make the substitution
                    # honest everywhere it's visible: mode_desc here, and
                    # the MonitorConfig registered below (so the header/
                    # resume-after-playback logic sees the actual running
                    # mode, not the originally requested one). See
                    # core/fsmon.py's TODO on run_fsmon_by_pid for the
                    # tracked future-work path to real fanotify-less PID
                    # attribution (tracefs kprobes).
                    #
                    # Known caveat (found via real on-device E2E testing,
                    # not fixed here -- an upstream monitor/inotify limitation,
                    # not something this fallback introduces): monitor adds
                    # inotify watches dynamically as new directories appear.
                    # If a brand-new, multi-level-deep directory tree is
                    # created and immediately written into (no delay between
                    # mkdir and the write), the deepest directory's contents
                    # can be silently missed -- a real forensic blind spot
                    # specific to the inotify backend this fallback relies
                    # on. Not present on real fanotify-backed PID-mode.
                    process = FSMon.run_fsmon_by_path(config.target_path)
                    mode_desc = (
                        f"path {config.target_path} "
                        "(PID mode unavailable — no fanotify on this device)"
                    )
                    config = MonitorConfig(
                        mode="path",
                        target_path=config.target_path,
                        target_pid=None,
                        app_name=config.app_name,
                    )
                    if self._on_pid_mode_fallback:
                        try:
                            self._on_pid_mode_fallback(config.target_path)
                        except Exception:
                            logger.debug(
                                "on_pid_mode_fallback callback failed", exc_info=True
                            )
            else:
                process = FSMon.run_fsmon_by_path(config.target_path)
                mode_desc = f"path {config.target_path}"

            if self._log_task_started:
                self._log_task_started("Monitor", mode_desc)
            else:
                self._log_info(f"Monitor started monitoring {mode_desc}")

            # Create wrapper to manage the process
            monitor_process_wrapper = MonitorProcessWrapper(process, config)

            # Register as background task
            self._get_task_service().register(
                name="monitor",
                display_name="Monitor",
                instance=monitor_process_wrapper,
                stop_callback=monitor_process_wrapper.stop,
                app_name=config.app_name if config.app_name else config.target_path,
            )

            # Start output reader thread
            self._start_output_reader(monitor_process_wrapper)

            # monitor actually STARTED (not just the config modal opening) —
            # jump to the Files tab's Monitor sub-tab so the live stream is
            # immediately visible, mirroring "h" (friTap) ->
            # MainScreen.open_fritap_tab(). This whole call chain runs on the
            # main thread already (originates from MonitorConfigModal's
            # push_modal dismiss callback — same reasoning as the
            # log_task_started call above needing no call_from_thread), so
            # invoke directly rather than via self._call_from_thread (which
            # asserts it is being called from a DIFFERENT thread than the
            # app's own and would raise here).
            if self._open_files_tab:
                try:
                    self._open_files_tab()
                except Exception:
                    logger.debug(
                        "Failed to open Files tab after monitor start", exc_info=True
                    )

            return True

        except Exception as e:
            self._log_error(f"Failed to start monitor: {e}")
            return False

    def _start_output_reader(self, monitor_process_wrapper: Any) -> None:
        """Start a thread to read monitor output with batched UI delivery.

        Instead of calling ``call_from_thread`` for every single monitor line
        (which floods Textual's event loop at high event rates), the reader
        thread accumulates lines in a thread-safe deque and flushes them to
        the main thread in a single batch every ``flush_interval`` seconds.

        Args:
            monitor_process_wrapper: MonitorProcessWrapper instance
        """
        import time

        line_buffer: deque[str] = deque(maxlen=2000)
        flush_interval = self._get_buffer_interval()

        def flush_to_ui() -> None:
            """Send accumulated lines to main thread in one batch."""
            if not line_buffer:
                return
            batch = list(line_buffer)
            line_buffer.clear()
            try:
                self._call_from_thread(self._log_monitor_output_batch, batch)
            except Exception:
                logger.debug("Failed to flush monitor batch to UI", exc_info=True)

        def read_output():
            """Read monitor output in background thread."""
            logger.info("monitor output reader thread started")
            process = monitor_process_wrapper.process
            last_flush = 0.0  # ensure first line triggers immediate flush
            first_line = True

            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                except Exception:
                    break
                if line:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if first_line:
                        logger.info("monitor reader: first output line received")
                        first_line = False
                    if line_str:
                        line_buffer.append(line_str)
                        now = time.monotonic()
                        if now - last_flush >= flush_interval:
                            flush_to_ui()
                            last_flush = now
                else:
                    time.sleep(0.01)

            # Final flush of remaining lines
            flush_to_ui()

            # Drain remaining buffered output after process exits
            try:
                for line in process.stdout:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        line_buffer.append(line_str)
                flush_to_ui()
            except Exception:
                logger.debug("Failed to drain monitor output", exc_info=True)

            # Log process exit diagnostics
            exit_code = process.poll()
            logger.info("monitor process exited with code %s", exit_code)
            if exit_code is not None and exit_code != 0:
                try:
                    self._call_from_thread(
                        self._log_warning,
                        f"monitor process exited unexpectedly (code {exit_code})",
                    )
                except Exception:
                    logger.debug("Failed to log monitor exit warning", exc_info=True)

            # Process ended
            try:
                self._call_from_thread(self._monitor_ended)
            except Exception:
                logger.debug("Failed to signal monitor ended", exc_info=True)

        thread = threading.Thread(target=read_output, daemon=True)
        thread.start()

    def _get_running_monitor_config(self) -> Any:
        """Best-effort fetch of the running monitor task's ``MonitorConfig``.

        Used once per batch flush to compute path-prefix candidates for
        ``build_monitor_item`` -- not looked up per line.
        """
        try:
            task = self._get_task_service().get_task("monitor")
            inst = getattr(task, "instance", None)
            return getattr(inst, "config", None)
        except Exception:
            return None

    def _log_monitor_output_batch(self, lines: list[str]) -> None:
        """Process a batch of monitor output lines (called from main thread).

        This replaces per-line ``_log_monitor_output`` to avoid flooding
        Textual's event loop. One ``call_from_thread`` delivers the entire
        batch instead of one message per event.

        Part B change: instead of formatting a final Rich-markup string per
        line and publishing one EventBus event per line, each line is
        parsed+categorized+prefix-stripped into a structured
        ``FileSystemMonitorItem`` (see ``build_monitor_item``), and the
        WHOLE BATCH is published as a SINGLE event (``_publish_monitor_batch``)
        -- grouping/dedup/visibility-filtering/tallying/width-aware
        rendering all now live in ``MonitorView`` (see B1), which needs the
        batch's items in order, with a real widget reference, to do any of
        that. Bus-publish only -- the old direct call into the Background
        Activity log was removed (that log now gets monitor lines a second
        time via the bus if not filtered by source, see
        ``MainScreen._handle_task_output``'s
        ``_ACTIVITY_LOG_EXCLUDED_SOURCES`` guard).

        Args:
            lines: Batch of output lines from the reader thread
        """
        prefix_candidates = _resolve_prefix_candidates(
            self._get_running_monitor_config()
        )

        items: list[FileSystemMonitorItem] = []
        for line in lines:
            try:
                items.append(build_monitor_item(line, prefix_candidates))
            except Exception:
                logger.debug("Failed to parse monitor line for batch", exc_info=True)

        # _publish_monitor_batch is a no-op on an empty list and swallows its
        # own EventBus-publish failures internally (matches the old
        # per-line _publish_monitor_event's error handling).
        _publish_monitor_batch(items)

    def _log_monitor_error(self, error: str) -> None:
        """Log monitor error to activity log.

        Args:
            error: Error message
        """
        self._log_error(f"Monitor error: {error}")

    def _monitor_ended(self) -> None:
        """Handle monitor process ending."""
        if self._log_task_stopped:
            self._log_task_stopped("Monitor")
        else:
            self._log_info("Monitor stopped")

        # Unregister background task
        task_service = self._get_task_service()
        if task_service.is_running("monitor"):
            task_service.unregister("monitor")

        # Update UI
        if self._force_ui_refresh:
            self._force_ui_refresh()

    def stop(self) -> bool:
        """Stop Monitor if running.

        Returns:
            True if Monitor was stopped
        """
        if not self.is_running():
            return False

        self._get_task_service().stop("monitor")
        self._log_info("Monitor stopped")

        if self._force_ui_refresh:
            self._force_ui_refresh()

        return True

    # =========================================================================
    # Resume after Play's snapshot-revert safety stop
    # =========================================================================

    def resume_after_playback(self, config: "MonitorConfig | None") -> bool:
        """Re-fork monitor after Play's snapshot revert auto-stopped it.

        Called from the main thread (this is a direct handler for
        MonitorView's "Resume monitoring" button — see ``app.py``'s
        ``resume_monitor_after_playback``), with the ``MonitorConfig`` monitor was
        running with just before ``RecordingController._stop_monitor_before_
        revert`` stopped it.

        In PID-mode, ``config.target_pid`` is almost always stale by the
        time Play finishes: the target app typically relaunches with a new
        PID during replay. This re-resolves the PID from ``config.app_name``
        (``Adb.get_pid_for_package_name``) before re-forking rather than
        trusting the stored one. If the app can no longer be found running,
        it falls back to path-mode (when ``config.target_path`` is
        available) instead of silently forking against a dead PID; if
        neither a fresh PID nor a path is available, it refuses to start at
        all and logs an explicit reason rather than failing silently.

        Reuses ``_start_monitor`` for the actual (re-)start rather than
        duplicating its binary-check/register/output-reader/open-files-tab
        sequence.

        Args:
            config: The MonitorConfig monitor was running with before the
                Play-triggered auto-stop. ``None`` (e.g. if it couldn't be
                recovered at stop time) is handled explicitly, not silently.

        Returns:
            True if monitor was successfully re-forked.
        """
        if config is None:
            self._log_warning(
                "Cannot resume monitoring: no prior Monitor configuration available."
            )
            return False

        if self.is_running():
            self._log_warning("Monitor is already running.")
            return False

        resolved = config
        if config.mode == "pid":
            new_pid = None
            if config.app_name:
                try:
                    from sandroid.core.adb import Adb

                    new_pid = Adb.get_pid_for_package_name(
                        config.app_name, use_frida_fallback=False, quiet=True
                    )
                except Exception:
                    logger.debug("PID re-resolution failed", exc_info=True)
                    new_pid = None

            if new_pid:
                resolved = MonitorConfig(
                    mode="pid",
                    target_path=config.target_path,
                    target_pid=new_pid,
                    app_name=config.app_name,
                )
            elif config.target_path:
                self._log_warning(
                    f"{config.app_name or 'Target app'} is no longer running — "
                    f"resuming in path mode ({config.target_path}) instead of "
                    "PID mode."
                )
                resolved = MonitorConfig(
                    mode="path",
                    target_path=config.target_path,
                    target_pid=None,
                    app_name=config.app_name,
                )
            else:
                self._log_warning(
                    f"Could not resume monitoring: {config.app_name or 'the target app'} "
                    "is no longer running and no path fallback was configured. "
                    "Start Monitor manually with 'o'."
                )
                return False

        return self._start_monitor(resolved)


__all__ = [
    "MONITOR_EVENT_INFO",
    "FileSystemMonitorItem",
    "MonitorConfig",
    "MonitorController",
    "MonitorEvent",
    "MonitorItem",
    "build_monitor_item",
    "colorize_monitor_line",
    "format_monitor_event_row",
    "parse_monitor_line",
]
