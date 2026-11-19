"""Recording Controller for the TUI: Record, Review, Rewind (+ Replay).

The user-approved Rewind flow (``docs/REWIND_PLAN.md``, data model and
device steps in :mod:`sandroid.core.rewind`):

* ``r`` saves a **start point** (an emulator snapshot) and starts recording
  (Tracking's input lines through the shared getevent lease, the file
  monitor, a file list of the app's folders);
* ``r`` again stops and opens **Review** (``tui/modals/review_modal.py``):
  the files that changed and the requests seen;
* selecting a file watches it (★) and pulls it at once: its **After**;
* **Rewind** loads the start point and pulls **Before**; **Rewind +
  Replay** then repeats the steps and pulls **After (replay)**.

Each Rewind saves a run (``core/run_history``) shown in the Sessions lens.
The old batch Play (replay count, dry run, noise filter) is gone from the
TUI; the command line and headless runs keep it (``analysis/engine.py``).

Every device call runs on a worker thread; UI callbacks are marshalled with
``call_from_thread`` (:meth:`RecordingController._ui`).
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


def drop_stale_frida_device() -> bool:
    """Drop the job manager's frida device handle if it can no longer work.

    For device (re)connects: after an emulator restart the serial is the
    same, so nothing else refreshes ``JobManager.device`` and every spawn
    fails with "device is gone". The handle is dropped when frida reports
    it lost, or when no process session uses it; the job manager re-creates
    it on the next spawn. Never raises.

    Returns:
        True if a handle was dropped.
    """
    try:
        from sandroid import services

        jm = getattr(services.get_frida_session_service(), "_job_manager", None)
        device = getattr(jm, "device", None)
        if device is None:
            return False
        lost = bool(getattr(device, "is_lost", False))
        if lost or getattr(jm, "process_session", None) is None:
            jm.device = None
            return True
    except Exception:
        logger.debug("Could not check the frida device handle", exc_info=True)
    return False


def recording_seconds(path: str) -> float | None:
    """Length of a raw recording (first to last input event), or None.

    Both formats: raw ``getevent -t`` lines (``recording.getevent.txt``) and
    legacy ``<epoch ms> <device> <type> <code> <value>`` lines.
    """
    from sandroid.features.player import parse_store_line

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            stamps = [
                parsed[0]
                for parsed in (parse_store_line(line) for line in f)
                if parsed is not None
            ]
    except OSError:
        return None
    if len(stamps) < 2:
        return None
    return max(0.0, (stamps[-1] - stamps[0]) / 1000.0)


class RecordingController:
    """Record / Review / Rewind (+ Replay), decoupled from widgets.

    Args:
        log_info: Activity-log callbacks (UI thread).
        log_warning: As above.
        log_error: As above.
        log_success: As above.
        push_modal: ``push_screen(modal, callback)``.
        run_worker: ``run_worker(fn, name=..., thread=True)``.
        call_from_thread: Marshal a call onto the UI thread.
        force_ui_refresh: Repaint after a state change.
        toolbox: Optional Toolbox reference (tests).
        on_run_saved: Called (UI thread) with a saved run id.
        on_monitor_stopped_for_playback: Called (UI thread) when Rewind
            stopped the file monitor before the snapshot load.
        on_monitor_resume_available: Called (UI thread) with the monitor's
            config when it could not be restarted after a Rewind.
        set_recording_indicator: ``(bool)``: recording on/off.
        set_replay_indicator: ``(bool)``: a Rewind runs.
        suppress_disconnect_guard: ``(bool)`` around snapshot save/load.
        set_replay_phase: ``(text | None)``: the plain status line.
        notify: ``(message, severity)`` toast (UI thread).
        watchlist: Returns the Files lens's ``WatchlistView`` (UI thread).
        resume_monitor: ``(config) -> bool`` restarts the monitor (UI thread).
        ensure_monitor: ``(pkg)`` starts the file monitor for the app if it
            is not running (UI thread).
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        run_worker: Callable[..., None] | None = None,
        call_from_thread: Callable[..., None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        toolbox: Any | None = None,
        on_run_saved: Callable[[str], None] | None = None,
        on_monitor_stopped_for_playback: Callable[[], None] | None = None,
        on_monitor_resume_available: Callable[[Any], None] | None = None,
        set_recording_indicator: Callable[[bool], None] | None = None,
        set_replay_indicator: Callable[[bool], None] | None = None,
        suppress_disconnect_guard: Callable[[bool], None] | None = None,
        set_replay_phase: Callable[[str | None], None] | None = None,
        notify: Callable[[str, str], None] | None = None,
        watchlist: Callable[[], Any] | None = None,
        resume_monitor: Callable[[Any], bool] | None = None,
        ensure_monitor: Callable[[str], None] | None = None,
    ) -> None:
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._run_worker = run_worker
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._force_ui_refresh = force_ui_refresh
        self._toolbox = toolbox
        self._on_run_saved = on_run_saved
        self._on_monitor_stopped_for_playback = on_monitor_stopped_for_playback
        self._on_monitor_resume_available = on_monitor_resume_available
        self._set_recording_indicator = set_recording_indicator
        self._set_replay_indicator = set_replay_indicator
        self._suppress_disconnect_guard = suppress_disconnect_guard
        self._set_replay_phase = set_replay_phase
        self._notify = notify
        self._watchlist = watchlist
        self._resume_monitor = resume_monitor
        self._ensure_monitor = ensure_monitor
        #: idle | saving | recording | stopping | running
        self._state = "idle"
        self._state_lock = threading.Lock()
        self._rec: Any = None  # core.rewind.Recording
        self._wrapper: Any = None
        self._cancel = threading.Event()
        self._review: Any = None  # the open ReviewModal
        self._tick_stop = threading.Event()
        self._last_run_id: str | None = None
        #: AI resource-arbiter owner whose WORLD lease a Rewind holds.
        self._replay_owner_id: str | None = None
        #: rec_id -> the first file list (None: it failed).
        self._start_facts: dict[str, dict | None] = {}

    # -- plumbing -------------------------------------------------------------

    def _default_log(self, message: str) -> None:
        logger.info(message)

    def _ui(self, fn: Callable[..., Any] | None, *args: Any) -> None:
        """Run a UI callback on the main thread; never raise."""
        if fn is None:
            return
        if threading.current_thread() is threading.main_thread():
            self._guarded(fn, *args)
            return
        try:
            self._call_from_thread(fn, *args)
        except Exception:
            logger.debug("UI update %r failed (ignored)", fn, exc_info=True)

    @staticmethod
    def _guarded(fn: Callable[..., Any] | None, *args: Any) -> None:
        if fn is None:
            return
        try:
            fn(*args)
        except Exception:
            logger.debug("Callback %r failed (ignored)", fn, exc_info=True)

    def _spawn(self, fn: Callable[[], None], name: str) -> None:
        """``fn`` on a worker thread (a Textual thread worker when wired)."""
        if self._run_worker is not None:
            try:
                self._run_worker(fn, name=name, exclusive=False, thread=True)
                return
            except Exception:
                logger.debug("run_worker failed; plain thread", exc_info=True)
        threading.Thread(target=fn, name=name, daemon=True).start()

    def _status(self, text: str | None) -> None:
        self._ui(self._set_replay_phase, text)
        review = self._review
        if review is not None and hasattr(review, "set_progress"):
            self._ui(review.set_progress, text or "")

    def _toast(self, message: str, severity: str = "information") -> None:
        self._ui(self._notify, message, severity)

    def _get_toolbox(self) -> Any:
        if self._toolbox:
            return self._toolbox
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _get_task_service(self) -> Any:
        from sandroid.services import get_task_service

        return get_task_service()

    @staticmethod
    def _active_device() -> Any:
        try:
            from sandroid.core.device_manager import DeviceManager

            return DeviceManager.get().active_device
        except Exception:
            return None

    @staticmethod
    def _active_device_name() -> str | None:
        """Name of the active device (AVD name for emulators), or None."""
        try:
            from sandroid.core.device_manager import (
                DeviceManager,
                resolve_device_name,
            )

            dm = DeviceManager.get()
            device = dm.active_device
            if device is None:
                return None
            if device.is_emulator:
                dm.get_avd_name_for_device(device)
            return resolve_device_name(device) or None
        except Exception:
            logger.debug("Could not resolve the active device name", exc_info=True)
            return None

    @staticmethod
    def _shell(serial: str | None) -> Callable[[str], str]:
        """A device shell runner for ``serial`` (raises when it is gone)."""
        from sandroid.core.adb import Adb
        from sandroid.core.adb_utils import device_shell_command

        def run(command: str) -> str:
            stdout, stderr = Adb.send_adb_command(
                device_shell_command(command), serial=serial, timeout=60
            )
            err = str(stderr or "").strip()
            low = err.lower()
            # adb's own failures (not the device command's stderr): the
            # device is gone, or the call hung.
            if (
                low.startswith("error:")
                and any(
                    w in low
                    for w in ("not found", "offline", "no devices", "unauthorized")
                )
            ) or low.startswith(("command timed out", "oserror")):
                raise RuntimeError(err or "the device did not answer")
            return stdout if isinstance(stdout, str) else str(stdout or "")

        return run

    def _set_state(self, state: str) -> None:
        with self._state_lock:
            self._state = state

    # -- state ----------------------------------------------------------------

    def is_recording(self) -> bool:
        """A recording is running (or its start point is being saved)."""
        return self._state in ("saving", "recording", "stopping")

    @property
    def is_replaying(self) -> bool:
        """A Rewind (or Rewind + Replay) is running."""
        return self._state == "running"

    @property
    def state(self) -> str:
        return self._state

    @property
    def recording(self) -> Any:
        """The current recording (:class:`sandroid.core.rewind.Recording`)."""
        return self._rec

    @property
    def current_recording_label(self) -> str | None:
        return self._rec.name if self._rec is not None else None

    def has_recording(self) -> bool:
        """A stopped recording exists that Review can show."""
        return self._rec is not None and self._rec.stopped is not None

    def get_recording_path(self) -> str:
        """The current recording's raw getevent slice (may not exist)."""
        from sandroid.core import rewind

        if self._rec is None:
            return ""
        try:
            return str(
                rewind.recording_dir(self._rec.rec_id) / "recording.getevent.txt"
            )
        except Exception:
            return ""

    recording_seconds = staticmethod(recording_seconds)

    # -- record -----------------------------------------------------------------

    def toggle_recording(self) -> bool:
        """``r``: start a recording, or stop the running one."""
        if self._state == "recording":
            return self.stop_recording()
        return self.start_recording()

    def _start_problem(self) -> tuple[str | None, Any, str | None]:
        """``(problem, device, package)`` for a new recording."""
        if self._state != "idle":
            if self._state == "running":
                return "A rewind is still running. Wait for it to finish.", None, None
            return "Already recording. Press r to stop.", None, None
        device = self._active_device()
        if device is None:
            return "No device connected.", None, None
        try:
            from sandroid.services import get_spotlight_service

            pkg = get_spotlight_service().get_effective_package()
        except Exception:
            pkg = None
        if not pkg:
            return (
                "Select an app first: Rewind needs to know whose files to list.",
                device,
                None,
            )
        return None, device, pkg

    def start_recording(self, name: str | None = None) -> bool:
        """``r``: save a start point, then start recording (UI thread).

        Returns:
            True when the recording is being started.
        """
        from sandroid.core import rewind

        problem, device, pkg = self._start_problem()
        if problem:
            self._log_warning(problem)
            self._toast(problem, "warning")
            return False
        now = datetime.now()
        rec = rewind.Recording(
            rec_id=rewind.new_rec_id(now),
            name=name or rewind.default_name(now),
            pkg=pkg,
            serial=getattr(device, "serial", None),
            emulator=bool(getattr(device, "is_emulator", False)),
        )
        self._set_state("saving")
        self._status(
            "Saving start point (about 5 s)"
            if rec.emulator
            else "Starting the recording (no start point on a physical device)"
        )
        self._spawn(lambda: self._start_worker(rec), "rewind_record_start")
        return True

    def _start_worker(self, rec: Any) -> dict[str, Any]:
        """Worker: start point, first file list, getevent lease, timeline."""
        from sandroid.core import rewind

        error = None
        try:
            error = self._save_start_point(rec)
            if error is None and self._ensure_monitor is not None:
                # After the save: the snapshot blinks the adb transport.
                self._ui(self._ensure_monitor, rec.pkg)
            if error is None:
                error = self._begin_capture(rec)
        except Exception as exc:  # never leave the state stuck
            logger.exception("Starting the recording failed")
            error = f"Could not start the recording: {exc}"
        if error is not None:
            # A start point saved for a recording that never started is
            # used by nothing: delete it (never the previous one).
            self._delete_start_point(rec)
            wrapper, self._wrapper = self._wrapper, None
            if wrapper is not None:  # capture failed after the lease
                with contextlib.suppress(Exception):
                    wrapper.stop()
                with contextlib.suppress(Exception):
                    self._get_task_service().unregister("recording")
            self._set_state("idle")
            self._status(None)
            self._ui(self._log_error, error)
            self._toast(error, "error")
            return {"success": False, "message": error}
        previous, self._rec = self._rec, rec
        self._set_state("recording")
        # A Review still open shows the previous recording; its buttons
        # and selections would act on this one.
        self._ui(self._close_review)
        self._ui(self._set_recording_indicator, True)
        self._replace_start_point(previous, rec)
        with contextlib.suppress(Exception):
            rewind.save_recording(rec)
        self._ui(self._log_info, f"Recording '{rec.name}' started")
        self._start_ticker(rec)
        return {
            "success": True,
            "rec_id": rec.rec_id,
            "name": rec.name,
            "start_point": rec.start_point_name,
        }

    def _save_start_point(self, rec: Any) -> str | None:
        """Save the snapshot (emulators); a plain error sentence or None."""
        from sandroid.core import rewind

        if not rec.emulator:
            rec.start_point = {"name": None, "saved_ok": False, "pinned": False}
            return None
        avd = self._active_device_name()
        rec.avd = avd
        folder = None
        if avd:
            with contextlib.suppress(Exception):
                from sandroid.core.emulator import avd_dir

                folder = avd_dir(avd)
        problem = rewind.disk_problem(folder)
        if problem:
            return problem
        name = rewind.start_point_name()
        self._guarded(self._suppress_disconnect_guard, True)
        try:
            from sandroid.services import get_emulator_service

            ok = bool(get_emulator_service().create_snapshot(name, rec.serial))
        except Exception as exc:
            logger.debug("create_snapshot raised", exc_info=True)
            ok, why = False, str(exc)
        else:
            why = "the emulator refused"
        finally:
            self._guarded(self._suppress_disconnect_guard, False)
        if not ok:
            return f"Could not save the start point: {why}. Nothing was recorded."
        rec.start_point = {"name": name, "saved_ok": True, "pinned": False}
        return None

    def _begin_capture(self, rec: Any) -> str | None:
        """First file list, the getevent lease, the record-start line."""
        from sandroid.core import rewind
        from sandroid.tui.utils.recording_wrapper import RecordingWrapper

        folder = rewind.recording_dir(rec.rec_id)
        folder.mkdir(parents=True, exist_ok=True)
        start = self._file_list(rec, "files_start.tsv")
        rec.file_lists["start"] = "files_start.tsv" if start is not None else ""
        # Per recording: the late-writes refresh of an older recording may
        # still run when a newer one starts. None: the list failed.
        self._start_facts[rec.rec_id] = start
        wrapper = RecordingWrapper(
            output_file=str(folder / "recording.getevent.txt"), serial=rec.serial
        )
        if not wrapper.start():
            return "Could not start the recording: the input stream did not start."
        self._wrapper = wrapper
        self._wait_tracking(rec.serial)
        self._get_task_service().register(
            name="recording",
            display_name="Recording",
            instance=wrapper,
            stop_callback=wrapper.stop,
        )
        rec.timeline_offset = rewind.timeline_size()
        rec.started = time.time()
        rec.seq["start"] = self._emit_phase(
            "record",
            None,
            kind="record-start",
            summary=f"recording started · {rec.name}",
            data={
                "label": rec.name,
                "rec_id": rec.rec_id,
                "start_point": rec.start_point_name,
                "pkg": rec.pkg,
                "via": "rewind",
            },
        )
        return None

    @staticmethod
    def _wait_tracking(serial: str | None, timeout: float = 5.0) -> bool:
        """Wait until Tracking's getevent stream is live (after a save the
        adb transport blinks; a tap before the stream is back is lost).
        """
        try:
            from sandroid.services.tracking_service import get_tracking

            stream = get_tracking().getevent(serial) if serial else None
        except Exception:
            return False
        if stream is None:
            return False
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if stream.alive:
                    return True
                time.sleep(0.1)
            return bool(stream.alive)
        finally:
            with contextlib.suppress(Exception):
                stream.release()

    def _file_list(self, rec: Any, name: str) -> dict | None:
        """List the app's folders on the device and keep it as TSV."""
        from sandroid.core import rewind

        try:
            text = self._shell(rec.serial)(rewind.file_list_command(rec.pkg))
        except Exception:
            logger.debug("file list failed", exc_info=True)
            return None
        facts = rewind.parse_file_list(text)
        with contextlib.suppress(Exception):
            rewind.write_file_list(rewind.recording_dir(rec.rec_id) / name, facts)
        return facts

    def _delete_start_point(self, rec: Any) -> None:
        """Delete ``rec``'s own start point (``sandroid_rec_*`` only)."""
        from sandroid.core import rewind

        name = rec.start_point_name
        if not rewind.is_start_point_name(name):
            return
        try:
            from sandroid.services import get_emulator_service

            ok = bool(get_emulator_service().delete_snapshot(name, rec.serial))
        except Exception:
            logger.debug("deleting the unused start point failed", exc_info=True)
            ok = False
        rec.start_point["deleted"] = ok
        if ok:
            rec.start_point["saved_ok"] = False

    def _close_review(self) -> None:
        """Close the open Review (UI thread); a new recording started."""
        review, self._review = self._review, None
        if review is not None and hasattr(review, "close_for_new_recording"):
            self._guarded(review.close_for_new_recording)

    def _replace_start_point(self, previous: Any, rec: Any) -> None:
        """Delete the previous start point unless it is pinned (only
        ``sandroid_rec_*`` names, only after the new one saved).
        """
        from sandroid.core import rewind

        if previous is None or previous.pinned or not rec.start_point_name:
            return
        name = previous.start_point_name
        if not rewind.is_start_point_name(name) or name == rec.start_point_name:
            return
        try:
            from sandroid.services import get_emulator_service

            ok = get_emulator_service().delete_snapshot(name, previous.serial)
        except Exception:
            logger.debug("deleting the old start point failed", exc_info=True)
            ok = False
        previous.start_point["deleted"] = bool(ok)
        if ok:
            previous.start_point["saved_ok"] = False
        with contextlib.suppress(Exception):
            rewind.save_recording(previous)

    def _start_ticker(self, rec: Any) -> None:
        self._tick_stop.clear()

        def tick() -> None:
            while not self._tick_stop.wait(1.0):
                if self._state != "recording" or self._rec is not rec:
                    return
                secs = int(time.time() - (rec.started or time.time()))
                tail = "press r to stop"
                if not rec.emulator:
                    tail = "no start point on a physical device"
                self._ui(
                    self._set_replay_phase,
                    f"Recording '{rec.name}' · {secs // 60}:{secs % 60:02d} · {tail}",
                )

        threading.Thread(target=tick, name="rewind-ticker", daemon=True).start()

    @staticmethod
    def _emit_phase(*args: Any, **kw: Any) -> int | None:
        try:
            from sandroid.core.timeline import get_timeline

            return get_timeline().set_phase(*args, **kw)
        except Exception:
            logger.debug("timeline line failed", exc_info=True)
            return None

    def stop_recording(self, *, open_review: bool = True) -> bool:
        """``r`` while recording: stop, list the changes, open Review."""
        if self._state != "recording":
            self._log_warning("Nothing is recording.")
            return False
        self._set_state("stopping")
        self._tick_stop.set()
        self._status("Stopping recording")
        rec = self._rec
        self._spawn(lambda: self._stop_worker(rec, open_review), "rewind_record_stop")
        return True

    def _stop_worker(self, rec: Any, open_review: bool = True) -> dict[str, Any]:
        """Worker: release the lease, second file list, the Review list."""
        from sandroid.core import rewind

        try:
            wrapper, self._wrapper = self._wrapper, None
            if wrapper is not None:
                wrapper.stop()
            with contextlib.suppress(Exception):
                self._get_task_service().unregister("recording")
            rec.stopped = time.time()
            rec.seq["stop"] = self._emit_phase(
                "live",
                None,
                kind="record-stop",
                summary="recording stopped",
                ref={"of": rec.seq.get("start")} if rec.seq.get("start") else None,
            )
            self._collect_changes(rec, "files_stop.tsv")
            self._emit_result(rec)
            rewind.save_recording(rec)
        except Exception as exc:
            logger.exception("Stopping the recording failed")
            self._ui(self._log_error, f"Stopping the recording failed: {exc}")
        finally:
            self._set_state("idle")
            self._ui(self._set_recording_indicator, False)
            self._status(None)
        self._ui(
            self._log_success,
            f"Recording '{rec.name}' stopped: {len(rec.changed)} files changed, "
            f"{len(rec.requests)} requests",
        )
        if open_review:
            self._ui(self.open_review)
        threading.Thread(
            target=self._late_writes, args=(rec,), name="rewind-late", daemon=True
        ).start()
        return self.review_dict(rec)

    def _collect_changes(self, rec: Any, list_name: str) -> None:
        """File-list diff + monitor paths + requests of the record window."""
        from sandroid.core import rewind

        stop = self._file_list(rec, list_name)
        if stop is not None:
            rec.file_lists["stop"] = list_name
        start = self._start_facts.get(rec.rec_id)
        if start is None and rec.file_lists.get("start"):
            start = _read_tsv(rewind.recording_dir(rec.rec_id) / "files_start.tsv")
        listed = (
            rewind.diff_file_lists(start or {}, stop)
            if stop is not None and start is not None
            else []
        )
        lines = rewind.lines_between(
            rec.seq.get("start"), None, offset=rec.timeline_offset
        )
        stop_seq = rec.seq.get("stop")
        in_window = [
            ln for ln in lines if stop_seq is None or (ln.get("seq") or 0) <= stop_seq
        ]
        rec.changed = rewind.merge_changes(
            listed, rewind.monitor_changes(lines, rec.pkg)
        )
        rec.requests = rewind.requests_in(in_window)
        if rec.emulator and not rec.start_point_name:
            rec.note = "The start point is gone. Record again to rewind."

    def _emit_result(self, rec: Any) -> None:
        try:
            from sandroid.core.timeline import get_timeline

            get_timeline().emit(
                "run",
                "record-result",
                summary=f"recording · {len(rec.changed)} files changed",
                data={
                    "rec_id": rec.rec_id,
                    "changed": len(rec.changed),
                    "selected": len(rec.selected),
                    "requests": len(rec.requests),
                    "completed": True,
                    "cancelled": False,
                },
                ref={"of": rec.seq.get("stop")} if rec.seq.get("stop") else None,
            )
        except Exception:
            logger.debug("record-result line failed", exc_info=True)

    def _late_writes(self, rec: Any, wait: float | None = None) -> None:
        """The Review list keeps filling for a few seconds after Stop."""
        from sandroid.core import rewind

        self._ui(self._review_refresh, rec, True)
        time.sleep(rewind.LATE_WRITES_S if wait is None else wait)
        # Not while a Rewind runs (the list would read the start point and
        # empty the Review) or a new recording is starting.
        if self._rec is not rec or _rewound(rec) or self._state != "idle":
            self._ui(self._review_refresh, rec, False)
            return
        with contextlib.suppress(Exception):
            self._collect_changes(rec, "files_late.tsv")
            rewind.save_recording(rec)
        self._ui(self._review_refresh, rec, False)

    def _review_refresh(self, rec: Any, filling: bool) -> None:
        review = self._review
        if review is not None and getattr(review, "rec", None) is rec:
            with contextlib.suppress(Exception):
                review.refresh_lists(filling=filling)

    # -- review and selection -------------------------------------------------

    def open_review(self) -> bool:
        """``p`` (or Stop): open Review for the current recording."""
        if self._rec is None or self._rec.stopped is None:
            self._toast("Nothing recorded yet. Press r to record.", "warning")
            return False
        if self._review is not None and getattr(self._review, "rec", None) is not (
            self._rec
        ):
            self._close_review()  # it shows an older recording
        if self._review is not None or self._push_modal is None:
            return self._review is not None
        from sandroid.tui.modals.review_modal import ReviewModal

        modal = ReviewModal(self._rec, self)
        self._review = modal

        def closed(_result: Any = None) -> None:
            if self._review is modal:
                self._review = None

        self._push_modal(modal, closed)
        return True

    def review_closed(self, modal: Any) -> None:
        if self._review is modal:
            self._review = None

    def rename(self, name: str) -> None:
        from sandroid.core import rewind

        rec = self._rec
        if rec is None or not name.strip():
            return
        rec.name = name.strip()[:80]
        with contextlib.suppress(Exception):
            rewind.save_recording(rec)

    def set_pinned(self, pinned: bool) -> None:
        from sandroid.core import rewind

        rec = self._rec
        if rec is None or not rec.start_point_name:
            return
        rec.start_point["pinned"] = bool(pinned)
        with contextlib.suppress(Exception):
            rewind.save_recording(rec)

    def rewind_problem(self, rec: Any = None) -> str | None:
        """Why Rewind cannot run now (plain words), or None."""
        rec = rec or self._rec
        # The state first: while recording, the current recording has not
        # stopped yet, which is not "nothing recorded".
        if self._state == "running":
            return "A rewind is already running."
        if self._state != "idle":
            return "Stop the recording first (press r)."
        if rec is None or rec.stopped is None:
            return "Nothing recorded yet."
        if not rec.emulator:
            return "Rewind needs an emulator: physical devices have no snapshots."
        if not rec.start_point_name:
            return "The start point is gone. Record again to rewind."
        device = self._active_device()
        if device is None:
            return "No device connected."
        if getattr(device, "serial", None) != rec.serial:
            return (
                f"The recording was made on {rec.serial}; the device now is "
                f"{getattr(device, 'serial', '?')}."
            )
        return None

    def select_file(self, path: str, selected: bool) -> None:
        """Select (watch ★ + pull After) or unselect a Review file."""
        from sandroid.core import rewind

        rec = self._rec
        if rec is None:
            return
        if not selected:
            if path in rec.selected:
                rec.selected.remove(path)
            with contextlib.suppress(Exception):
                rewind.save_recording(rec)
            return
        if path in rec.selected:
            return
        rec.selected.append(path)
        with contextlib.suppress(Exception):
            rewind.save_recording(rec)
        view = self._watchlist() if self._watchlist else None
        if view is not None:
            with contextlib.suppress(Exception):
                view.add_path(path, pull_first=False)
        if _rewound(rec):
            # The device is no longer after the action: no After any more.
            self._review_file_state(
                path, "selected (After exists only before a rewind)"
            )
            return
        if view is None:
            self._review_file_state(path, "could not watch: the Files lens is missing")
            return
        self._review_file_state(path, "saving After")
        self._spawn(lambda: self._pull_after(rec, view, path), "rewind_after")

    def _pull_after(self, rec: Any, view: Any, path: str) -> None:
        from sandroid.core import rewind

        version, error = view.pull_role(path, "after", rec.rec_id, 1)
        if version is not None or error is None:
            rec.set_role(path, "after", version)
            with contextlib.suppress(Exception):
                rewind.save_recording(rec)
        if error:
            text = f"Could not copy {path}: {error}."
            self._ui(self._log_warning, text)
            self._review_file_state(path, "After failed")
        elif version == rewind.ABSENT:
            self._review_file_state(path, "After saved (not on the device)")
        else:
            self._review_file_state(path, "After saved")

    def _review_file_state(self, path: str, text: str) -> None:
        review = self._review
        if review is not None and hasattr(review, "set_file_state"):
            self._ui(review.set_file_state, path, text)

    def select_flow(self, row: dict[str, Any], selected: bool) -> None:
        """Select a request for the comparison after Rewind + Replay."""
        from sandroid.core import rewind

        rec = self._rec
        if rec is None:
            return
        key = (row.get("seq"), row.get("flow_id"))
        rec.selected_flows = [
            r for r in rec.selected_flows if (r.get("seq"), r.get("flow_id")) != key
        ]
        if selected:
            rec.selected_flows.append(dict(row))
        with contextlib.suppress(Exception):
            rewind.save_recording(rec)

    # -- rewind -----------------------------------------------------------------

    def start_rewind(self, replay: bool, *, owner_id: str | None = None) -> bool:
        """Rewind (``replay=False``) or Rewind + Replay, on a worker."""
        problem = self.rewind_problem()
        if problem:
            self._log_warning(problem)
            self._toast(problem, "warning")
            return False
        rec = self._rec
        view = self._watchlist() if self._watchlist else None
        self._set_state("running")
        self._replay_owner_id = owner_id
        self._cancel.clear()
        self._ui(self._set_replay_indicator, True)
        self._spawn(lambda: self._rewind_worker(rec, replay, view), "rewind_run")
        return True

    def stop_rewind(self) -> bool:
        """Ask the running Rewind / Replay to stop (Esc)."""
        if self._state != "running":
            return False
        self._cancel.set()
        self._status("Stopping the replay")
        return True

    stop_playback = stop_rewind

    def _deps(self, rec: Any, view: Any, replay: bool) -> Any:
        from sandroid.core import rewind

        shell = self._shell(rec.serial)

        def load(name: str, serial: str | None) -> bool:
            self._guarded(self._suppress_disconnect_guard, True)
            try:
                from sandroid.services import get_emulator_service

                return bool(get_emulator_service().load_snapshot(name, serial))
            finally:
                self._guarded(self._suppress_disconnect_guard, False)

        def pull(path: str, role: str, rec_id: str, run: int) -> Any:
            if view is None:
                return rewind.PullOutcome(None, "the Files lens is missing")
            version, error = view.pull_role(path, role, rec_id, run)
            return rewind.PullOutcome(version, error)

        return rewind.RewindDeps(
            load_snapshot=load,
            shell=shell,
            pull=pull,
            # EmulatorService.load_snapshot already drops the frida handles
            # and the Spotlight PID and runs the post-load steps.
            stop_monitor=self._stop_monitor_before_revert,
            progress=self._status,
            cancelled=self._cancel.is_set,
            replay=self._replay if replay else None,
        )

    def _rewind_worker(self, rec: Any, replay: bool, view: Any) -> dict[str, Any]:
        from sandroid.core import rewind

        outcome = None
        run_id = None
        try:
            runner = rewind.RewindRunner(rec, self._deps(rec, view, replay))
            outcome = runner.run(replay=replay)
            if outcome.monitor_config is not None:
                self._ui(self._resume_after, outcome.monitor_config)
            run_id = self._persist(rec, outcome)
        except Exception as exc:
            logger.exception("Rewind failed")
            self._ui(self._log_error, f"Rewind failed: {exc}")
        finally:
            self._set_state("idle")
            self._release_replay_world_lease()
            self._ui(self._set_replay_indicator, False)
            self._status(None)
        if outcome is not None:
            if outcome.error:
                self._ui(self._log_warning, outcome.error)
                self._toast(outcome.error, "warning")
            else:
                done = (
                    "Done. The device shows the replayed result."
                    if replay
                    else "Done. The device is at the start point."
                )
                self._ui(self._log_success, done)
                self._toast(done)
        if run_id and self._on_run_saved:
            self._ui(self._on_run_saved, run_id)
        review = self._review
        if review is not None and hasattr(review, "refresh_lists"):
            self._ui(review.refresh_lists)
        return {
            "success": outcome is not None and not outcome.error,
            "run_id": run_id,
            "error": None if outcome is None else outcome.error,
            "result": None if outcome is None else outcome.result,
        }

    def _resume_after(self, config: Any) -> None:
        """Restart the monitor after a Rewind (offer it if that fails)."""
        ok = False
        if self._resume_monitor is not None:
            try:
                ok = bool(self._resume_monitor(config))
            except Exception:
                logger.debug("monitor resume failed", exc_info=True)
        if not ok:
            self._guarded(self._on_monitor_resume_available, config)

    def _replay(self, rec: Any, runner: Any) -> dict[str, Any]:
        """Rewind + Replay's steps (the device is at the start point)."""
        from sandroid.core import rewind
        from sandroid.features.player import StepReplayer, extract_steps

        lines = rewind.lines_between(
            rec.seq.get("start"), rec.seq.get("stop"), offset=rec.timeline_offset
        )
        steps = extract_steps(lines)
        if not steps:
            return {"steps": [], "stopped_at_step": None, "error": None}
        tracking = None
        own_gen = None
        try:
            from sandroid.services.tracking_service import get_tracking

            tracking = get_tracking()
            if not tracking.is_active(rec.serial):
                own_gen = tracking.start_session(rec.serial, reason="replay")
        except Exception:
            logger.debug("Tracking for the replay failed", exc_info=True)

        def helper() -> Any:
            return tracking.live_helper() if tracking is not None else None

        # The helper restarts after the load: give it a moment before step 1.
        deadline = time.monotonic() + 15.0
        while helper() is None and time.monotonic() < deadline:
            if self._cancel.wait(0.25):
                break

        def emit(*args: Any, **kw: Any) -> int | None:
            from sandroid.core.timeline import get_timeline

            return get_timeline().emit(*args, **kw)

        try:
            return StepReplayer(
                shell=runner.deps.shell,
                helper=helper,
                cancelled=self._cancel.is_set,
                progress=self._status,
                emit=emit,
                raw_lines=_raw_reader(),
            ).run(steps)
        finally:
            if own_gen is not None and tracking is not None:
                with contextlib.suppress(Exception):
                    tracking.stop(reason="replay", only_gen=own_gen)

    def _stop_monitor_before_revert(self) -> Any | None:
        """Stop the file monitor before a snapshot load (its adb shell does
        not survive it); returns its config so it can be restarted.
        """
        try:
            task_service = self._get_task_service()
            if not task_service.is_running("monitor"):
                return None
            task = task_service.get_task("monitor")
            config = getattr(getattr(task, "instance", None), "config", None)
            task_service.stop("monitor")
            self._ui(
                self._log_info,
                "File monitor paused for the rewind; it restarts afterwards.",
            )
            self._ui(self._on_monitor_stopped_for_playback)
            return config
        except Exception as e:
            logger.debug(f"monitor auto-stop failed: {e}", exc_info=True)
            return None

    def _release_replay_world_lease(self) -> None:
        """Release an AI-held ``ResourceId.WORLD`` lease, if any."""
        owner = self._replay_owner_id
        self._replay_owner_id = None
        if not owner:
            return
        try:
            from sandroid.ai.arbiter import ResourceId, get_arbiter

            get_arbiter().release_resources(owner, frozenset({ResourceId.WORLD}))
        except Exception:
            logger.debug("Failed to release replay WORLD lease", exc_info=True)

    # -- results ----------------------------------------------------------------

    def results(self, rec: Any = None) -> dict[str, Any]:
        """Per-file and per-request results of the recording's latest run."""
        from sandroid.core import rewind

        rec = rec or self._rec
        if rec is None:
            return {"files": [], "flows": []}
        files = [rewind.file_result(rec, p) for p in rec.selected]
        flows = []
        last = rec.runs[-1] if rec.runs else None
        if last and last.get("kind") == "rewind-replay" and rec.selected_flows:
            seq = last.get("seq") or {}
            replay_lines = rewind.lines_between(
                seq.get("start"), seq.get("end"), offset=rec.timeline_offset
            )
            replay_reqs = rewind.requests_in(replay_lines)
            read = rewind.flow_detail_reader()
            flows = [
                rewind.compare_flow(f, replay_reqs, read) for f in rec.selected_flows
            ]
        return {"files": files, "flows": flows}

    def run_requests(self, rec: Any = None) -> dict[str, list[dict[str, Any]]]:
        """Requests per run: ``{"Your run": [...], "Replay": [...]}``."""
        from sandroid.core import rewind

        rec = rec or self._rec
        out = {"Your run": list(rec.requests) if rec else []}
        last = rec.runs[-1] if rec and rec.runs else None
        if last and last.get("kind") == "rewind-replay":
            seq = last.get("seq") or {}
            out["Replay"] = rewind.requests_in(
                rewind.lines_between(
                    seq.get("start"), seq.get("end"), offset=rec.timeline_offset
                )
            )
        return out

    def _persist(self, rec: Any, outcome: Any) -> str | None:
        """Save the Rewind as a run (Sessions lens); returns its id."""
        from sandroid.core import rewind, run_history
        from sandroid.core.timeline import timeline_folder

        try:
            res = self.results(rec)
            files: list[Any] = []
            new, deleted, verdicts = [], [], {}
            for fr in res["files"]:
                files.append({fr.path: rewind.result_lines(fr)})
                verdicts[fr.path] = fr.verdict
                if fr.before == rewind.ABSENT:
                    new.append(fr.path)
                if fr.after == rewind.ABSENT:
                    deleted.append(fr.path)
            flows = [rewind.flow_result_lines(f) for f in res["flows"]]
            requests = {
                k: [rewind.request_text(r) for r in v]
                for k, v in self.run_requests(rec).items()
            }
            mode_word = (
                "Rewind + Replay" if outcome.mode == "rewind-replay" else "Rewind"
            )
            run_id = run_history.new_run_id()
            now = datetime.now().isoformat()
            record = run_history.RunRecord(
                schema_version=run_history.SCHEMA_VERSION,
                run_id=run_id,
                label=f"{rec.name} · {mode_word}",
                recorded_at=datetime.fromtimestamp(
                    rec.started or time.time()
                ).isoformat(),
                completed_at=now,
                device_name=rec.avd or self._active_device_name() or "unknown",
                recording_path=self.get_recording_path(),
                duration=int((rec.stopped or 0) - (rec.started or 0)),
                error=outcome.error,
                changed_files=files,
                new_files=new,
                deleted_files=deleted,
                counts={
                    "changed": len(files) - len(new) - len(deleted),
                    "new": len(new),
                    "deleted": len(deleted),
                },
                timeline_folder=str(timeline_folder()),
                record_window=[rec.started or 0.0, rec.stopped or 0.0],
                mode=outcome.mode,
                rec_id=rec.rec_id,
                verdicts=verdicts,
                rewind={
                    "steps": outcome.steps,
                    "stopped_at_step": outcome.stopped_at_step,
                    "flows": flows,
                    "requests": requests,
                    "run": outcome.n,
                },
            )
            run_history.save_run(record)
            rec.runs[-1]["run_id"] = run_id
            rewind.save_recording(rec)
            self._last_run_id = run_id
            return run_id
        except Exception as exc:
            logger.exception("Saving the rewind run failed")
            self._ui(self._log_error, f"Could not save the rewind results: {exc}")
            return None

    # -- AI chat (tool-dispatch thread, never the UI thread) --------------------

    def start_recording_chat(self, label: str | None = None) -> dict[str, Any]:
        """Start a recording from the AI chat (blocking; worker thread)."""
        from sandroid.core import rewind

        problem, device, pkg = self._start_problem()
        if problem:
            return {"success": False, "message": problem}
        now = datetime.now()
        rec = rewind.Recording(
            rec_id=rewind.new_rec_id(now),
            name=(label or "").strip() or rewind.default_name(now),
            pkg=pkg,
            serial=getattr(device, "serial", None),
            emulator=bool(getattr(device, "is_emulator", False)),
        )
        self._set_state("saving")
        self._status("Saving start point (about 5 s)")
        return self._start_worker(rec)

    def stop_recording_chat(self) -> dict[str, Any]:
        """Stop the recording from the AI chat; returns the Review list."""
        if self._state != "recording":
            return {"success": False, "message": "No recording in progress"}
        self._set_state("stopping")
        self._tick_stop.set()
        return {"success": True, **self._stop_worker(self._rec, open_review=False)}

    def start_rewind_chat(
        self,
        paths: list[str] | None = None,
        replay: bool = True,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Select ``paths`` (watch + After) and start Rewind (+ Replay)."""
        rec = self._rec
        problem = self.rewind_problem()
        if problem:
            return {"success": False, "message": problem}
        known = {e.get("path") for e in rec.changed}
        unknown = [p for p in paths or [] if p not in known and p not in rec.selected]
        if unknown:
            return {
                "success": False,
                "message": "Not in the Review list: " + ", ".join(unknown[:5]),
            }
        view = None
        if self._watchlist is not None:
            box: list[Any] = []
            done = threading.Event()

            def get() -> None:
                try:
                    box.append(self._watchlist())
                finally:
                    done.set()

            self._ui(get)
            done.wait(5.0)
            view = box[0] if box else None
        for path in paths or []:
            if path in rec.selected:
                continue
            rec.selected.append(path)
            if view is not None:
                self._ui(lambda p=path: view.add_path(p, pull_first=False))
                if not _rewound(rec):
                    self._pull_after(rec, view, path)
        started = self._call_from_thread(
            lambda: self.start_rewind(replay, owner_id=owner_id)
        )
        if started is False:
            return {"success": False, "message": self.rewind_problem() or "not started"}
        return {
            "success": True,
            "selected": list(rec.selected),
            "mode": "rewind-replay" if replay else "rewind",
        }

    def review_dict(self, rec: Any = None) -> dict[str, Any]:
        """The Review list and the latest results, for the AI tools."""
        rec = rec or self._rec
        if rec is None:
            return {"recording": None}
        res = self.results(rec)
        from sandroid.core import rewind

        return {
            "rec_id": rec.rec_id,
            "name": rec.name,
            "package": rec.pkg,
            "start_point": rec.start_point_name,
            "pinned": rec.pinned,
            "rewind_possible": self.rewind_problem(rec) is None,
            "rewind_problem": self.rewind_problem(rec),
            "changed_files": rec.changed,
            "selected": list(rec.selected),
            "requests": rec.requests,
            "selected_requests": rec.selected_flows,
            "runs": [
                {k: r.get(k) for k in ("n", "kind", "result", "error", "run_id")}
                for r in rec.runs
            ],
            "results": [
                {
                    "path": fr.path,
                    "verdict": fr.verdict,
                    "what_your_action_changed": fr.action_text,
                    "what_the_replay_changed": fr.replay_text or None,
                }
                for fr in res["files"]
            ],
            "request_results": [
                {
                    "request": rewind.request_text(f.original),
                    "found": f.found,
                    "request_body": f.body or None,
                    "response_status": f.status or None,
                }
                for f in res["flows"]
            ],
        }

    # -- export -----------------------------------------------------------------

    def show_export_modal(self) -> bool:
        """Export recorded action (the export modal)."""
        from sandroid.tui.modals import ExportModal, ExportResult

        if not self._push_modal:
            self._log_error("Cannot show export modal - push_modal not configured")
            return False

        def on_export_result(result: ExportResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Export cancelled")
                return
            if result.success:
                self._log_success(f"Exported to: {result.export_path}")
            elif result.error:
                self._log_error(f"Export failed: {result.error}")

        self._push_modal(ExportModal(), on_export_result)
        return True


def _rewound(rec: Any) -> bool:
    """A run of ``rec`` reached its start point (the device left the
    after-the-action state). A failed load or an Esc before it did not.
    """
    return any(run.get("loaded", True) for run in rec.runs)


def _read_tsv(path: Any) -> dict | None:
    from sandroid.core.rewind import FileFact

    try:
        out = {}
        for line in path.read_text().splitlines():
            size, mtime, stamp, p = line.split("\t", 3)
            out[p] = FileFact(int(size), int(mtime), stamp)
        return out
    except (OSError, ValueError):
        return None


def _raw_reader() -> Callable[[str, int, int], list[str]]:
    """``(file, first, last) -> lines`` of Tracking's raw getevent log."""

    def read(rel: str, first: int, last: int) -> list[str]:
        from sandroid.core.timeline import timeline_folder

        path = timeline_folder() / rel
        out = []
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for no, line in enumerate(handle, 1):
                    if no > last:
                        break
                    if no >= first:
                        out.append(line)
        except OSError:
            return []
        return out

    return read


__all__ = ["RecordingController", "recording_seconds"]
