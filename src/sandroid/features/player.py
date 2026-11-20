"""Event player based on adb-event-record by Tzutalin.

Source: https://github.com/tzutalin/adb-event-record
Modified to fit the needs of this project.
"""

import math
import re
import threading
import time
from dataclasses import dataclass
from logging import getLogger
from typing import Any

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .functionality import Functionality

logger = getLogger(__name__)

#: One recorded input event, either format:
#:
#: * ``recording.getevent.txt`` (raw ``getevent -t``):
#:   ``[   26404.737324] /dev/input/event1: 0003 0039 ffffffff`` -- device
#:   seconds, hex type/code/value;
#: * legacy ``recording.txt``: ``<epoch ms> <device> <type> <code> <value>``
#:   (decimal).
STORE_LINE_RE = re.compile(
    r"\[\s*(?P<gts>\d+\.\d+)\]\s+(?P<gdev>/dev/\S+):\s+"
    r"(?P<gtype>[0-9a-fA-F]{4})\s+(?P<gcode>[0-9a-fA-F]{4})\s+"
    r"(?P<gvalue>[0-9a-fA-F]{8})\s*$"
    r"|(?P<ts>\S+) (?P<dev>\S+) (?P<type>\S+) (?P<code>\S+) (?P<value>\S+)$"
)


def parse_store_line(line: str) -> tuple[float, str, str, str, str] | None:
    """``(ts_ms, device, type, code, value)`` of a recording line, or None.

    getevent lines are converted exactly like the legacy recorder did
    (``int(hex, 16)``, unsigned) so both formats yield the same ``sendevent``
    arguments; ``ts_ms`` is device seconds x 1000 there and host epoch ms in
    legacy lines (the player only uses differences).
    """
    m = STORE_LINE_RE.match(line.strip())
    if m is None:
        return None
    if m["gts"] is not None:
        return (
            float(m["gts"]) * 1000.0,
            m["gdev"],
            str(int(m["gtype"], 16)),
            str(int(m["gcode"], 16)),
            str(int(m["gvalue"], 16)),
        )
    try:
        ts = float(m["ts"])
    except ValueError:
        return None
    return ts, m["dev"], m["type"], m["code"], m["value"]


#: Process-wide "stop replaying" flag. Set by :meth:`Player.cancel_all` (TUI
#: stop/quit) and checked before every event and during every inter-event
#: wait, so a replay stops within one event instead of tapping on for minutes.
_cancel_event = threading.Event()


def _raise_cancelled() -> None:
    """Abort the current replay so the analysis engine stops the whole run.

    Raises the engine's ``FatalStepError`` (imported lazily: the engine
    imports this module) so the remaining steps, including the next
    iteration's snapshot load and replay, are skipped.
    """
    try:
        from sandroid.analysis.engine import FatalStepError
    except Exception:  # pragma: no cover - engine always importable
        FatalStepError = RuntimeError
    raise FatalStepError("Replay cancelled")


#: ``adb shell date`` attempts before a replay (or dry run) gives up: right
#: after a snapshot load adb can still report "device still authorizing".
ACTION_TIME_ATTEMPTS = 6
#: Wait between those attempts (seconds; a cancel ends it at once).
ACTION_TIME_RETRY_S = 1.5


def set_action_time_after_load(toolbox: object = None) -> None:
    """Set the action time from the device, retrying while adb is not ready.

    Retries :class:`~sandroid.core.exceptions.DeviceTimeError` up to
    :data:`ACTION_TIME_ATTEMPTS` times, :data:`ACTION_TIME_RETRY_S` apart (a
    cancel stops the wait). Still failing, it raises the engine's
    ``FatalStepError`` so the run (Play) ends cleanly with that error instead
    of continuing with a stale action window.

    Args:
        toolbox: Object with ``set_action_time()`` (default: :class:`Toolbox`).
    """
    from sandroid.core.exceptions import DeviceTimeError

    box = toolbox if toolbox is not None else Toolbox
    last: Exception | None = None
    for attempt in range(1, ACTION_TIME_ATTEMPTS + 1):
        try:
            box.set_action_time()
            return
        except DeviceTimeError as exc:
            last = exc
            logger.warning(
                f"Device time not readable (attempt {attempt}/"
                f"{ACTION_TIME_ATTEMPTS}): {exc}"
            )
        if attempt < ACTION_TIME_ATTEMPTS and _cancel_event.wait(ACTION_TIME_RETRY_S):
            _raise_cancelled()
    try:
        from sandroid.analysis.engine import FatalStepError
    except Exception:  # pragma: no cover - engine always importable
        FatalStepError = RuntimeError
    raise FatalStepError(f"Device not ready, replay aborted: {last}") from last


class Player(Functionality):
    """Replays previously recorded touch/input events on an Android device.

    Reads events from a recording (``recording.getevent.txt`` written by
    Record, or a legacy ``recording.txt``) and sends them to the device via ``adb shell sendevent``, preserving the
    original timing between events.

    Attributes:
        STORE_LINE_RE: Pattern matching a stored event line of either format
            (see :func:`parse_store_line`).
    """

    STORE_LINE_RE = STORE_LINE_RE

    @staticmethod
    def cancel_all() -> None:
        """Stop every running replay as soon as possible (thread-safe)."""
        _cancel_event.set()

    @staticmethod
    def clear_cancel() -> None:
        """Allow replays again; call before starting a new playback."""
        _cancel_event.clear()

    @staticmethod
    def is_cancelled() -> bool:
        """Whether :meth:`cancel_all` was called since the last clear."""
        return _cancel_event.is_set()

    def __init__(self, recording_path: str | None = None) -> None:
        """Initialize the player.

        Args:
            recording_path: Absolute path to the recording to replay
                (``recording.getevent.txt`` or a legacy ``recording.txt``).
                This is how the recording is supplied and is immune to the
                device-switch re-derivation bug (see module notes). May be
                left ``None`` here and passed to :meth:`perform` instead, but
                one of the two must provide a path.
        """
        self._recording_path = recording_path

    def _resolve_recording_path(self, override: str | None) -> str:
        """Resolve the recording path from the explicit args only.

        Resolution order: the explicit ``perform`` argument, then the value
        passed to the constructor. The recording path is never derived from
        the process-global ``RAW_RESULTS_PATH`` env var — doing so is exactly
        the device-switch orphaning bug this design removes.

        Args:
            override: Explicit path passed to :meth:`perform`, if any.

        Returns:
            The recording file path to read.

        Raises:
            RuntimeError: If no recording path was supplied to either the
                constructor or :meth:`perform`.
        """
        path = override or self._recording_path
        if not path:
            raise RuntimeError(
                "Player has no recording path: pass recording_path to the "
                "constructor or to perform()."
            )
        return str(path)

    def perform(self, recording_path: str | None = None) -> None:
        """Replay recorded actions from the recording file.

        Args:
            recording_path: Absolute path to the recording to replay. Takes
                precedence over the constructor value.

        Raises:
            RuntimeError: If no recording path was supplied, or if the
                recording file cannot be opened.
            FatalStepError: If :meth:`cancel_all` was called before or
                during the replay, or the device time stayed unreadable
                (see :func:`set_action_time_after_load`).
        """
        if _cancel_event.is_set():
            _raise_cancelled()
        set_action_time_after_load()
        start_time = int(round(time.time()))
        logger.info("Start playing")

        last_ts = None
        recording_file = self._resolve_recording_path(recording_path)

        # TODO: Improve replay of swiping motions
        try:
            with open(recording_file, encoding="utf-8") as fp:
                for line in fp:
                    parsed = parse_store_line(line)
                    if parsed is None:
                        if line.strip():
                            logger.warning(
                                f"Skipping malformed line in recording: {line.strip()}"
                            )
                        continue

                    ts, dev, etype, ecode, data = parsed

                    if last_ts and (ts - last_ts) > 0:
                        delta_second = (ts - last_ts) / 1000
                        # Interruptible sleep: returns early on cancel.
                        _cancel_event.wait(delta_second)

                    last_ts = ts
                    if _cancel_event.is_set():
                        logger.info("Replay cancelled")
                        _raise_cancelled()

                    Adb.send_adb_command(
                        f"shell sendevent {dev} {etype} {ecode} {data}"
                    )
        except FileNotFoundError as e:
            error_msg = f"Recording file not found: {recording_file}. Run 'record' first to create a recording."
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except PermissionError as e:
            error_msg = f"Permission denied reading recording file: {recording_file}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except OSError as e:
            error_msg = f"Failed to open recording file '{recording_file}': {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

        logger.info("Stop playing")
        action_duration = math.ceil(time.time() - start_time)
        Toolbox.set_action_duration(action_duration)
        logger.debug(f"Set action duration to {action_duration} seconds")


# ---------------------------------------------------------------------------
# Rewind + Replay: replaying recorded steps by element, else by position
# ---------------------------------------------------------------------------
#
# The steps are Tracking's ``input/*`` timeline lines of one recording
# (``core/rewind.py``). Every tap or long press that has a recorded element
# (``data.target``) is looked up again in a live helper ``dump`` and tapped at
# the element's current centre ("by element"); when no single element
# matches within the wait, the recorded coordinates are tapped instead ("by
# position"). Injection uses ``adb shell input``: getevent does not see it, so
# Tracking never records a replayed step as a new user input; each step
# writes its own ``run/step`` timeline line saying which way it went.

#: Seconds to wait for a recorded element before tapping its position.
ELEMENT_WAIT_S = 10.0
#: Poll interval of the element wait (s); bounds must match in two polls.
ELEMENT_POLL_S = 0.3
#: Longest recorded pause that is waited before a step (s).
MAX_GAP_S = 10.0
#: Waits after the last step before the replay's After copy is pulled (s): at
#: least this, else as long as your run went on after its last step (apps
#: write and send later), at most :data:`MAX_TAIL_S`.
SETTLE_AFTER_S = 3.0
MAX_TAIL_S = 120.0

WAY_ELEMENT = "by element"
WAY_POSITION = "by position"
#: Keys and typed text have no element or position to choose between.
WAY_REPLAYED = "replayed"
WAY_FAILED = "failed"
#: The step was done but the app is not where your run was: a typed field
#: reads something else, or two steps in a row missed their element. The
#: replay goes on; the run ends "diverged", never as a plain success.
WAY_DIVERGED = "diverged"

#: Typed text goes in one character at a time at your recorded pace (typing
#: time / characters), at least / at most this far apart (s). One fast
#: ``input text`` of the whole string loses characters in fields that
#: rewrite themselves while you type (Firefox's address bar autocomplete).
TYPE_MIN_GAP_S = 0.15
TYPE_MAX_GAP_S = 0.6
#: After typing, the field is read back for up to this long (s), every
#: :data:`TEXT_POLL_S`, until it holds the recorded text.
TEXT_CHECK_S = 3.0
TEXT_POLL_S = 0.5
#: What a password field shows instead of a character.
_MASK_CHARS = frozenset("\u2022\u25cf*")
#: A reason of a "by position" tap that says nothing about the app (no
#: element was recorded, or nothing could look for it).
_NO_EVIDENCE = ("", "nothing to match", "keyboard key", "the UI helper is not running")
#: A "by position" reason: the element was found but is not on the screen
#: (or reached beyond it when you tapped it); its centre is not tapped.
OFF_SCREEN = "element off-screen"
#: Nothing could check a step: no element was recorded (or it is a key on
#: the keyboard), a swipe, a key, a raw gesture.
_NOTHING_TO_CHECK = ("nothing to match", "keyboard key")

#: Per step: ``verified`` (found by element, or the typed field read
#: back), ``unchecked`` (it could have been checked and was not: element
#: not found, off-screen, no helper, field unreadable), ``diverged``, or
#: ``none`` (nothing to check). A run is a plain success only with no
#: unchecked and no diverged step.
CHECK_VERIFIED = "verified"
CHECK_UNCHECKED = "unchecked"
CHECK_NONE = "none"


def step_check(way: str, reason: str) -> str:
    """The check state of a tap that went ``way`` (see :data:`CHECK_VERIFIED`)."""
    if way == WAY_ELEMENT:
        return CHECK_VERIFIED
    if way == WAY_POSITION and reason in _NOTHING_TO_CHECK:
        return CHECK_NONE
    return CHECK_UNCHECKED


_STEP_KINDS = ("tap", "long_press", "swipe", "key", "gesture")
#: Linux key names (Tracking's ``KEY_NAMES``) -> ``input keyevent`` names.
_KEYEVENT = {"MUTE": "VOLUME_MUTE", "ESCAPE": "ESCAPE"}


class StepStoppedError(Exception):
    """The replay cannot go on; ``str(exc)`` is the plain reason."""


def _norm(value: object) -> str:
    return " ".join(str(value).split()) if value is not None else ""


def _short_cls(cls: object) -> str:
    return str(cls or "").rsplit(".", 1)[-1]


def _bounds(value: object) -> tuple[int, int, int, int] | None:
    if isinstance(value, (list, tuple)) and len(value) == 4:
        try:
            left, top, right, bottom = (int(v) for v in value)
        except (TypeError, ValueError):
            return None
        if right > left and bottom > top:
            return left, top, right, bottom
    return None


def centre(bounds: tuple[int, int, int, int]) -> tuple[int, int]:
    """The centre of ``[left, top, right, bottom]``."""
    left, top, right, bottom = bounds
    return (left + right) // 2, (top + bottom) // 2


def _screen(value: Any) -> tuple[int, int, int, int] | None:
    """``[0, 0, w, h]`` of a ``{w, h}`` display or a ``[w, h]`` screen."""
    if isinstance(value, dict):
        value = (value.get("w"), value.get("h"))
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return _bounds([0, 0, *value])
    return None


def clip(bounds: tuple[int, int, int, int], *areas: Any) -> tuple | None:
    """The part of ``bounds`` inside every area given (None areas are
    skipped); None when nothing of it is left.
    """
    left, top, right, bottom = bounds
    for area in areas:
        if area is None:
            continue
        left, top = max(left, area[0]), max(top, area[1])
        right, bottom = min(right, area[2]), min(bottom, area[3])
    return (left, top, right, bottom) if right > left and bottom > top else None


def _near(a: tuple[int, int, int, int], b: Any) -> bool:
    """Box ``b`` is box ``a`` or plausibly ``a`` moved (overlapping
    horizontally, at most 300 px apart vertically: a keyboard pan).
    """
    bb = _bounds(b)
    if bb is None:
        return True  # nothing to compare
    overlap_x = min(a[2], bb[2]) > max(a[0], bb[0])
    gap_y = max(0, max(a[1], bb[1]) - min(a[3], bb[3]))
    return overlap_x and gap_y <= 300


def _inside(xy: tuple[int, int], area: tuple[int, int, int, int]) -> bool:
    return area[0] <= xy[0] < area[2] and area[1] <= xy[1] < area[3]


def tap_point(
    item: dict[str, Any], reply: dict | None, target: dict, screen: Any = None
) -> tuple[int, int] | None:
    """Where to tap a matched element, or None when it is off the screen.

    The node's bounds are clipped to its window and the display (WebView
    nodes report their page position, which can lie far outside the
    screen; the dump has no visible-only bounds for them). The centre must
    lie in that visible part. A recorded target that reached beyond the
    recorded ``screen`` when you tapped it (a page-sized container) does
    not say where you tapped: None as well.
    """
    b = _bounds(item["node"].get("bounds"))
    if b is None:
        return None
    window = _bounds((item.get("window") or {}).get("bounds"))
    display = _screen((reply or {}).get("display"))
    visible = clip(b, window, display)
    if visible is None or not _inside(centre(b), visible):
        return None
    rec, rec_screen = _bounds(target.get("bounds")), _screen(screen)
    if rec is not None and rec_screen is not None and clip(rec, rec_screen) != rec:
        return None
    return centre(b)


def _node_path(chain: list[dict]) -> list[str]:
    out = []
    for node in chain:
        part = _short_cls(node.get("cls")) or "?"
        rid = node.get("rid")
        if rid:
            part += "#" + str(rid).split("/", 1)[-1]
        out.append(part)
    return out


def walk_dump(reply: dict | None) -> list[dict[str, Any]]:
    """Every node of a helper ``dump`` reply, flattened, top window first.

    Each item: ``node``, ``pkg`` (inherited down the tree), ``window``
    (the window dict without its tree), ``path`` (``cls#rid`` from the
    window root, as Tracking records it) and ``texts`` (the node's own and
    its descendants' text/desc, for a recorded ``label``).
    """
    out: list[dict[str, Any]] = []
    for window in (reply or {}).get("windows") or []:
        if not isinstance(window, dict) or not isinstance(window.get("root"), dict):
            continue
        meta = {k: v for k, v in window.items() if k != "root"}

        def visit(
            node: dict, pkg: str | None, chain: list[dict], meta: dict = meta
        ) -> list[str]:
            pkg = node.get("pkg") or pkg
            chain = [*chain, node]
            texts = [_norm(node.get(k)) for k in ("text", "desc") if _norm(node.get(k))]
            item = {
                "node": node,
                "pkg": pkg,
                "window": meta,
                "path": None,
                "anc": {id(n) for n in chain[:-1]},
            }
            out.append(item)
            for kid in node.get("kids") or []:
                if isinstance(kid, dict):
                    texts.extend(visit(kid, pkg, chain, meta))
            item["path"] = _node_path(chain)
            item["texts"] = texts
            return texts

        visit(window["root"], meta.get("pkg"), [])
    return out


def _input_word(input_type: Any) -> str | None:
    try:
        from sandroid.services.tracking_service import _input_word as word

        return word(input_type)
    except Exception:
        return None


def _identifying(target: dict) -> bool:
    """The recorded target names an element (not just a class)."""
    web = target.get("web") if isinstance(target.get("web"), dict) else {}
    keys = ("rid", "text", "desc", "label", "hint")
    return any(_norm(target.get(k)) for k in keys) or any(
        _norm(web.get(k)) for k in ("html_id", "field", "href", "raw_role")
    )


def _label_ok(label: str, texts: list[str]) -> bool:
    parts = [p.strip() for p in label.split(" / ") if p.strip()]
    have = set(texts)
    return bool(parts) and all(p in have for p in parts)


def node_matches(target: dict, item: dict[str, Any]) -> bool:
    """Every identifying field the target recorded equals the node's.

    Native fields: ``rid``, ``text`` (never recorded for editable or
    password fields), ``desc``, ``hint``, ``label`` (the text inside a row)
    and ``cls``. Web fields (feature/tracking-web's ``target.web``):
    ``html_id`` (the node's ``rid``), ``engine``, ``field`` (``web.label``),
    ``href``, ``raw_role`` (``web.role``) and ``input`` (the plain word of
    ``web.input_type``). ``role``, ``doc`` and ``page`` describe the page or
    a derived word and are not compared. A field the target lacks is not
    compared.
    """
    node = item["node"]
    if node.get("visible") is False:
        return False
    for key in ("rid", "text", "desc", "hint"):
        want = _norm(target.get(key))
        if want and _norm(node.get(key)) != want:
            return False
    label = _norm(target.get("label"))
    if label and not _label_ok(label, item.get("texts") or []):
        return False
    cls = target.get("cls")
    if cls and node.get("cls") and _short_cls(cls) != _short_cls(node.get("cls")):
        return False
    web = target.get("web")
    if isinstance(web, dict):
        nweb = node.get("web") if isinstance(node.get("web"), dict) else {}
        if _norm(web.get("html_id")) and _norm(node.get("rid")) != _norm(
            web.get("html_id")
        ):
            return False
        pairs = (
            ("engine", "engine"),
            ("field", "label"),
            ("href", "href"),
            ("raw_role", "role"),
        )
        for tkey, nkey in pairs:
            want = _norm(web.get(tkey))
            if want and nweb and _norm(nweb.get(nkey)) != want:
                return False
        want = _norm(web.get("input"))
        if want and nweb.get("input_type"):
            if _norm(_input_word(nweb.get("input_type"))) != want:
                return False
    return _bounds(node.get("bounds")) is not None


def find_element(
    target: dict, reply: dict | None, pkg: str | None = None
) -> tuple[dict[str, Any] | None, str]:
    """The one node of ``reply`` that is the recorded ``target``.

    Returns ``(item, "")`` or ``(None, reason)`` with a plain reason:
    ``nothing to match`` (the target names no element), ``not found``, or
    ``N elements match``. Several matches are narrowed by the recorded app,
    the recorded ancestry (``path``) and the recorded bounds, in that order;
    anything still ambiguous is not guessed.
    """
    if not target or not _identifying(target):
        return None, "nothing to match"
    found = [it for it in walk_dump(reply) if node_matches(target, it)]
    if not found:
        return None, "not found"
    # A container matches what its children match (their text is its
    # label): keep the innermost matches, not their ancestors.
    inner = set().union(*(it["anc"] for it in found))
    found = [it for it in found if id(it["node"]) not in inner] or found
    if len(found) > 1 and pkg:
        same = [it for it in found if it.get("pkg") == pkg]
        found = same or found
    path = target.get("path")
    if len(found) > 1 and isinstance(path, list) and path:
        same = [it for it in found if it.get("path") == path]
        found = same or found
    recorded = _bounds(target.get("bounds"))
    if len(found) > 1 and recorded is not None:
        same = [it for it in found if _bounds(it["node"].get("bounds")) == recorded]
        found = same or found
    if len(found) > 1:
        return None, f"{len(found)} elements match"
    return found[0], ""


@dataclass
class Step:
    """One recorded step to replay."""

    i: int
    seq: int
    kind: str
    t: float | None
    data: dict[str, Any]
    summary: str = ""
    pkg: str | None = None
    raw: str | None = None
    #: A password field (or data marked sensitive): typed values are never
    #: written into the step's words.
    sensitive: bool = False

    @property
    def target(self) -> dict | None:
        t = self.data.get("target")
        return t if isinstance(t, dict) else None

    @property
    def what(self) -> str:
        """The step in plain words (its timeline summary; the masked one for
        a sensitive step).
        """
        if self.sensitive and self.data.get("masked_summary"):
            return str(self.data["masked_summary"])
        return self.summary or self.kind.replace("_", " ")


def extract_steps(lines: list[dict]) -> list[Step]:
    """The user's ``input/*`` lines of a recording as replayable steps.

    Taps, long presses, swipes, keys and multi-finger gestures are steps;
    keyboard taps (``data.ime``) replay the typed text by position. An
    ``input/text`` line becomes a ``text`` step only when no keyboard tap
    came before it (text typed another way, e.g. a host keyboard).
    ``input/confirm`` lines are not steps; one that names the target of a
    tap whose position was unknown fills in that tap's target. The text of
    an ``input/text`` line typed by keyboard taps becomes the last keyboard
    tap's ``data.check_text``: the field is read back after that tap.
    """
    confirm: dict[int, dict] = {}
    for line in lines:
        if line.get("src") == "input" and line.get("kind") == "confirm":
            data = line.get("data") or {}
            of = (line.get("ref") or {}).get("of")
            if isinstance(of, int) and data.get("target_of_input"):
                confirm[of] = data.get("node") or {}
    steps: list[Step] = []
    ime_since_text = False
    last_ime: Step | None = None
    for line in sorted(lines, key=lambda ln: ln.get("seq") or 0):
        if line.get("src") != "input" or line.get("actor") not in (None, "user"):
            continue
        kind = line.get("kind")
        data = dict(line.get("data") or {})
        seq = line.get("seq")
        if not isinstance(seq, int):
            continue
        sensitive = bool(
            line.get("sensitive") or data.get("password") or data.get("data_sensitive")
        )
        if kind == "text":
            if not ime_since_text:
                steps.append(
                    Step(len(steps) + 1, seq, "text", line.get("t"), data,
                         line.get("summary") or "", line.get("pkg"),
                         sensitive=sensitive)
                )  # fmt: skip
            elif last_ime is not None and isinstance(data.get("text"), str):
                last_ime.data["check_text"] = data["text"]
                last_ime.data["check_target"] = data.get("target")
                last_ime.data["check_password"] = bool(data.get("password"))
                last_ime.sensitive = last_ime.sensitive or sensitive
            ime_since_text = False
            last_ime = None
            continue
        if kind not in _STEP_KINDS:
            continue
        if data.get("ime"):
            ime_since_text = True
        if data.get("target") is None and seq in confirm:
            data["target"] = confirm[seq]
        raw = (line.get("ref") or {}).get("raw")
        steps.append(
            Step(len(steps) + 1, seq, kind, line.get("t"), data,
                 line.get("summary") or "", line.get("pkg"), raw,
                 sensitive=sensitive)
        )  # fmt: skip
        if data.get("ime"):
            last_ime = steps[-1]
    return steps


def _epoch(value: Any) -> float | None:
    """A line's ``t`` (ISO text from the timeline file, or epoch seconds)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        from datetime import datetime

        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def input_text_arg(text: str) -> str | None:
    """``text`` for ``input text`` (spaces as ``%s``); None when it cannot be
    typed that way (not plain ASCII, or a literal ``%s`` in it).
    """
    if not text or "%s" in text or any(ord(c) < 32 or ord(c) > 126 for c in text):
        return None
    import shlex

    return shlex.quote(text.replace(" ", "%s"))


def _clip(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def text_check(
    expected: str, value: str, *, password: bool = False
) -> tuple[bool, str]:
    """Does a field reading ``value`` hold the recorded ``expected`` text?

    Both are stripped. The field may hold more after the recorded text (an
    autocomplete suffix: recorded ``wdr.de``, field ``wdr.de/``). A
    ``password`` field that shows mask characters is compared by length and
    by the characters it shows in clear (Firefox shows the last one for a
    moment). Returns ``(ok, reason)``; the reason names the values only
    when ``password`` is False.
    """
    want, have = (expected or "").strip(), (value or "").strip()
    if password:
        if any(c in _MASK_CHARS for c in have):
            ok = len(have) == len(want) and all(
                h in _MASK_CHARS or h == w for h, w in zip(have, want, strict=True)
            )
        else:
            ok = have == want or (bool(want) and have.startswith(want))
        return ok, "" if ok else "field text differs"
    if have == want or (want and have.startswith(want)):
        return True, ""
    return False, f"field reads '{_clip(have)}', expected '{_clip(want)}'"


def _raw_range(raw: str | None) -> tuple[str, int, int] | None:
    m = re.match(r"^(?P<file>.+)#L(?P<a>\d+)-L(?P<b>\d+)$", raw or "")
    if not m:
        return None
    return m["file"], int(m["a"]), int(m["b"])


class StepReplayer:
    """Replays :class:`Step` s on the device (call :meth:`run` on a worker).

    Args:
        shell: Runs one device shell command line, returns stdout; raises
            when the device is gone.
        helper: The live UI helper (``dump``), or None when there is none.
        cancelled: True once the user asked to stop.
        progress: Shows one plain progress line.
        emit: Writes a timeline line (``TimelineService.emit``-like).
        raw_lines: ``(file, first, last) -> getevent lines`` of a gesture.
    """

    def __init__(
        self,
        *,
        shell: Any,
        helper: Any,
        cancelled: Any = lambda: False,
        progress: Any = lambda _t: None,
        emit: Any = None,
        raw_lines: Any = None,
        sleep: Any = None,
        monotonic: Any = None,
        element_wait_s: float = ELEMENT_WAIT_S,
        tail_s: float | None = None,
    ) -> None:
        self.shell = shell
        self.helper = helper
        self.cancelled = cancelled
        self.progress = progress
        self.emit = emit
        self.raw_lines = raw_lines
        self._sleep = sleep or time.sleep
        self._mono = monotonic or time.monotonic
        self.element_wait_s = element_wait_s
        self.tail_s = tail_s

    # -- helpers ------------------------------------------------------------

    def _wait(self, seconds: float) -> None:
        end = self._mono() + max(0.0, seconds)
        while True:
            if self.cancelled():
                raise StepStoppedError("you pressed Esc")
            left = end - self._mono()
            if left <= 0:
                return
            self._sleep(min(left, 0.2))

    def _run(self, command: str) -> str:
        try:
            out = self.shell(command)
        except Exception as exc:
            raise StepStoppedError(f"the device did not answer ({exc})") from exc
        return out if isinstance(out, str) else str(out or "")

    def _dump(self) -> dict | None:
        helper = self.helper() if callable(self.helper) else self.helper
        if helper is None:
            return None
        try:
            return helper.dump(timeout=5.0)
        except Exception:
            logger.debug("replay: dump failed", exc_info=True)
            return None

    def locate(self, step: Step) -> tuple[tuple[int, int] | None, str]:
        """Wait for the step's element; ``(centre, "")`` or ``(None, why)``.

        The element must be the only match and have the same bounds in two
        polls :data:`ELEMENT_POLL_S` apart (the screen stopped moving).
        """
        target = step.target or {}
        if not _identifying(target):
            return None, "nothing to match"
        deadline = self._mono() + self.element_wait_s
        last_bounds = None
        why = "the UI helper is not running"
        current = self.helper() if callable(self.helper) else self.helper
        if current is None:
            return None, why  # no helper (the replay already waited for it)
        while True:
            if self.cancelled():
                raise StepStoppedError("you pressed Esc")
            reply = self._dump()
            if reply is not None:
                item, why = find_element(target, reply, step.pkg)
                if item is not None:
                    b = _bounds(item["node"].get("bounds"))
                    if b is not None and b == last_bounds:
                        xy = tap_point(item, reply, target, step.data.get("screen"))
                        return (xy, "") if xy else (None, OFF_SCREEN)
                    last_bounds = b
                    why = "the element kept moving"
                else:
                    last_bounds = None
            elif not callable(self.helper) and self.helper is None:
                return None, why
            if self._mono() >= deadline:
                return None, why
            self._sleep(ELEMENT_POLL_S)

    def _field_value(
        self,
        xy: tuple[int, int] | None,
        rid: str | None = None,
        bounds: tuple[int, int, int, int] | None = None,
    ) -> tuple[str | None, bool]:
        """``(text, password)`` of the focused field now (``text`` None: no
        field could be read, or the focus is on another field: its id is
        not the recorded ``rid``, or with no id its box is not near the
        recorded ``bounds``; a hint shown in an empty field reads as "").
        """
        helper = self.helper() if callable(self.helper) else self.helper
        fn = getattr(helper, "focus", None) if helper is not None else None
        if not callable(fn):
            return None, False
        try:
            reply = fn(*(xy or (None, None)), timeout=1.0)
        except Exception:
            logger.debug("replay: focus read failed", exc_info=True)
            return None, False
        if not isinstance(reply, dict):
            return None, False
        node = None
        for key in ("input", "node"):
            cand = reply.get(key)
            if isinstance(cand, dict) and cand.get("editable"):
                node = cand
                break
        if node is None:
            return None, False
        if rid and node.get("rid") and node.get("rid") != rid:
            return None, False  # the focus moved on (e.g. a code field)
        if not rid and bounds is not None and not _near(bounds, node.get("bounds")):
            return None, False  # no id: another field's box
        text = "" if node.get("showing_hint") else str(node.get("text") or "")
        return text, bool(node.get("password"))

    def check_text(
        self, expected: str, target: dict | None, *, password: bool = False
    ) -> tuple[str, str]:
        """Read the typed field back: ``("ok" | "diverged" | "unchecked",
        reason)``.

        Reads every :data:`TEXT_POLL_S` for up to :data:`TEXT_CHECK_S` (the
        app may still be updating the field) and stops at the first match.
        """
        bounds = _bounds((target or {}).get("bounds"))
        xy = centre(bounds) if bounds else None
        rid = (target or {}).get("rid") or None
        deadline = self._mono() + TEXT_CHECK_S
        last: tuple[bool, str] | None = None
        value: str | None = None
        while True:
            self._wait(TEXT_POLL_S)
            read, pw = self._field_value(xy, rid, bounds)
            if read is not None:
                value = read
                last = text_check(expected, read, password=password or pw)
                if last[0]:
                    return "ok", ""
            if self._mono() >= deadline:
                break
        if last is None or value is None:
            return "unchecked", "the typed field could not be read back"
        have, want = value.strip(), (expected or "").strip()
        if have and not (set(have) & _MASK_CHARS) and want.startswith(have):
            # Only the start of the text: a reading from before the field
            # caught up, not evidence of a different text.
            return "unchecked", "the field read back only part of the text"
        return "diverged", last[1]

    def _checked(self, res: dict[str, Any], text: str, target: dict | None,
                 password: bool) -> dict[str, Any]:  # fmt: skip
        """``res`` with the read-back's outcome (way ``diverged`` on a
        mismatch; a note when it could not be read).
        """
        state, why = self.check_text(text, target, password=password)
        res["check"] = {"ok": CHECK_VERIFIED}.get(state, state)
        base = res.get("reason") or ""
        if state == "diverged":
            res["way"] = WAY_DIVERGED
            res["reason"] = why
            res["was"] = base
        elif state == "ok":
            res["reason"] = (base + ", " if base else "") + "field checked"
        else:
            res["reason"] = (base + ", " if base else "") + f"not checked: {why}"
        return res

    def _type(self, text: str, dur_ms: Any) -> None:
        """Type ``text`` one character at a time at the recorded pace."""
        args = [input_text_arg(c) for c in text]
        if input_text_arg(text) is None or any(a is None for a in args):
            raise StepStoppedError("only plain ASCII text can be typed again")
        try:
            pace = float(dur_ms or 0.0) / 1000.0 / max(1, len(text) - 1)
        except (TypeError, ValueError):
            pace = 0.0
        pace = min(TYPE_MAX_GAP_S, max(TYPE_MIN_GAP_S, pace))
        sent: float | None = None
        for arg in args:
            if sent is not None:
                # The ``input`` call itself takes time: wait only the rest.
                self._wait(max(0.0, pace - (self._mono() - sent)))
            sent = self._mono()
            self._run(f"input text {arg}")

    @staticmethod
    def _xy(step: Step) -> tuple[int, int] | None:
        x, y = step.data.get("x"), step.data.get("y")
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            if step.data.get("xy_uncertain"):
                return None
            return int(x), int(y)
        return None

    # -- one step -------------------------------------------------------------

    def do_step(self, step: Step) -> dict[str, Any]:
        """Replay one step; returns ``{way, reason, x, y}``.

        Raises:
            StepStoppedError: the step could not be done at all (it is reported
                as ``failed: <reason>`` and the replay stops there).
        """
        kind, data = step.kind, step.data
        if kind in ("tap", "long_press"):
            xy, way, reason = None, WAY_ELEMENT, ""
            if data.get("ime"):
                reason = "keyboard key"
            else:
                xy, reason = self.locate(step)
            if xy is None:
                way = WAY_POSITION
                xy = self._xy(step)
                if xy is None:
                    raise StepStoppedError(
                        f"{reason}, and the recorded position is unknown"
                        if reason and reason != "nothing to match"
                        else "the recorded position is unknown"
                    )
                screen = _screen(data.get("screen"))
                if screen is not None and not _inside(xy, screen):
                    raise StepStoppedError("the recorded position is off the screen")
            x, y = xy
            if kind == "tap":
                self._run(f"input tap {x} {y}")
            else:
                dur = max(600, int(data.get("dur_ms") or 600))
                self._run(f"input swipe {x} {y} {x} {y} {dur}")
            res = {"way": way, "reason": reason, "x": x, "y": y}
            # A recorded element that was looked for and not found.
            res["missed"] = way == WAY_POSITION and reason not in (
                *_NO_EVIDENCE,
                OFF_SCREEN,
            )
            res["check"] = step_check(way, reason)
            check = data.get("check_text")
            if isinstance(check, str) and check:
                # The last keyboard tap of a typed text: read the field back.
                return self._checked(
                    res, check, data.get("check_target"),
                    bool(data.get("check_password")) or step.sensitive,
                )  # fmt: skip
            return res
        if kind == "swipe":
            start, x1, y1 = self._xy(step), data.get("x1"), data.get("y1")
            if (
                start is None
                or not isinstance(x1, (int, float))
                or not isinstance(y1, (int, float))
            ):
                raise StepStoppedError("the swipe's path is unknown")
            dur = max(100, int(data.get("dur_ms") or 300))
            self._run(f"input swipe {start[0]} {start[1]} {int(x1)} {int(y1)} {dur}")
            return {"way": WAY_POSITION, "reason": "", "x": start[0], "y": start[1],
                    "check": CHECK_NONE}  # fmt: skip
        if kind == "key":
            name = str(data.get("name") or "")
            if not re.match(r"^[A-Z_]+$", name):
                raise StepStoppedError("the key is unknown")
            self._run(f"input keyevent KEYCODE_{_KEYEVENT.get(name, name)}")
            return {"way": WAY_REPLAYED, "reason": f"key {name}", "check": CHECK_NONE}
        if kind == "text":
            text = data.get("text")
            if not isinstance(text, str) or not text:
                raise StepStoppedError("the typed text was not recorded")
            self._type(text, data.get("dur_ms"))
            res = {"way": WAY_REPLAYED, "reason": f"typed {len(text)} characters"}
            return self._checked(
                res, text, step.target, bool(data.get("password")) or step.sensitive
            )
        if kind == "gesture":
            return self._raw_gesture(step)
        raise StepStoppedError(f"{kind} steps cannot be replayed")

    def _raw_gesture(self, step: Step) -> dict[str, Any]:
        """A multi-finger gesture: its recorded getevent lines, as sendevent."""
        span = _raw_range(step.raw)
        lines = self.raw_lines(*span) if (span and self.raw_lines) else None
        if not lines:
            raise StepStoppedError("the gesture's raw events are missing")
        cmds: list[str] = []
        last_ts = None
        for line in lines:
            parsed = parse_store_line(line)
            if parsed is None:
                continue
            ts, dev, etype, ecode, value = parsed
            if last_ts is not None and ts - last_ts > 1:
                cmds.append(f"sleep {(ts - last_ts) / 1000.0:.3f}")
            last_ts = ts
            cmds.append(f"sendevent {dev} {etype} {ecode} {value}")
        if not cmds:
            raise StepStoppedError("the gesture's raw events are missing")
        self._run("; ".join(cmds))
        return {
            "way": WAY_POSITION,
            "reason": "replayed the raw finger events",
            "check": CHECK_NONE,
        }

    # -- the replay -----------------------------------------------------------

    def _line(self, step: Step, n: int, way: str, reason: str, res: dict) -> None:
        if self.emit is None:
            return
        word = f"{way}: {reason}" if way in (WAY_FAILED, WAY_DIVERGED) else way
        summary = f"step {step.i} of {n} · {step.what} · {word}"
        if (
            way in (WAY_POSITION, WAY_REPLAYED)
            and reason
            and reason != "nothing to match"
        ):
            summary += f" ({reason})"
        try:
            self.emit(
                "run",
                "step",
                summary=summary,
                actor="replay",
                data={
                    "i": step.i,
                    "of": n,
                    "kind": step.kind,
                    "way": way,
                    "reason": reason or None,
                    "check": res.get("check"),
                    "x": res.get("x"),
                    "y": res.get("y"),
                },
                ref={"of": step.seq},
                sensitive=step.sensitive,
                level={WAY_FAILED: "error", WAY_DIVERGED: "warn"}.get(way, "info"),
            )
        except Exception:
            logger.debug("replay: step line failed", exc_info=True)

    def run(self, steps: list[Step]) -> dict[str, Any]:
        """Replay ``steps`` in order, keeping the recorded pauses.

        Returns ``{"steps": [...], "stopped_at_step": i | None, "error":
        plain sentence | None, "diverged_at_step": i | None, "diverged":
        plain sentence | None, "unchecked_steps": [i, ...]}``; every step
        entry has ``check`` (:data:`CHECK_VERIFIED` ...). A step diverges when its typed field reads
        something else, or when it missed its element right after the step
        before it missed its own (each then went by position); the replay
        goes on, and the first such step is ``diverged_at_step``.
        """
        report: list[dict[str, Any]] = []
        n = len(steps)
        prev_t: float | None = None
        missed: int | None = None  # the step before missed its element
        div: dict[str, Any] = {
            "diverged_at_step": None,
            "diverged": None,
            "unchecked_steps": [],
        }
        for step in steps:
            gap = 0.0
            t = _epoch(step.t)
            if prev_t is not None and t is not None:
                gap = min(MAX_GAP_S, max(0.0, t - prev_t))
            if t is not None:
                prev_t = t
            self.progress(f"Replaying step {step.i} of {n}: {step.what}")
            entry = {"i": step.i, "seq": step.seq, "what": step.what}
            try:
                self._wait(gap)
                try:
                    res = self.do_step(step)
                except StepStoppedError:
                    raise
                except Exception as exc:  # a bad recorded step, not a crash
                    logger.debug("replay: step %s failed", step.i, exc_info=True)
                    why = f"the step could not be done ({exc})"
                    raise StepStoppedError(why) from exc
            except StepStoppedError as exc:
                reason = str(exc)
                entry.update(way=WAY_FAILED, reason=reason)
                report.append(entry)
                self._line(step, n, WAY_FAILED, reason, {})
                return {
                    "steps": report,
                    "stopped_at_step": step.i,
                    "error": f"Replay stopped at step {step.i} of {n}: "
                    f"{step.what}: {reason}.",
                    **div,
                }
            why = res.get("reason") or ""
            miss = bool(res.get("missed")) and res["way"] == WAY_POSITION
            if miss and missed is not None:
                res["way"] = WAY_DIVERGED
                res["reason"] = (
                    f"its element did not appear ({why}), and step {missed} "
                    "before it missed its element too; tapped the recorded position"
                )
            missed = step.i if miss else None
            if res["way"] == WAY_DIVERGED:
                res["check"] = WAY_DIVERGED
                if div["diverged_at_step"] is None:
                    div["diverged_at_step"] = step.i
                    div["diverged"] = f"step {step.i} of {n}: {res['reason']}"
            elif res.get("check") == CHECK_UNCHECKED:
                div["unchecked_steps"].append(step.i)
            entry.update(way=res["way"], reason=res.get("reason") or "")
            entry["check"] = res.get("check") or CHECK_NONE
            report.append(entry)
            self._line(step, n, res["way"], res.get("reason") or "", res)
        if n:
            tail = min(MAX_TAIL_S, max(SETTLE_AFTER_S, float(self.tail_s or 0.0)))
            self.progress(f"Waiting {tail:.0f} s for the app to finish, as in your run")
            self._wait(tail)
        return {"steps": report, "stopped_at_step": None, "error": None, **div}
