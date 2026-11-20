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
#: A "by position" reason: the element was found, but at none of its
#: visible spots is it the topmost element (a dialog, the keyboard or
#: another view lies over it); the recorded position is tapped instead.
COVERED = "element covered"
#: A "by element" reason: the element's spot was tapped, but nothing could
#: test that the element is the topmost one there (no live hit test).
NOT_HIT_TESTED = "not hit-tested"
#: The recorded element is unsure (Tracking took it from an outdated
#: snapshot and could not read the screen live): the recorded position is
#: tapped, never an element found by those words.
WEAK_TARGET = "recorded element unsure"
#: Grid of other visible spots (n x n) tried when your spot is covered or
#: off the screen; and how long one live hit test may take (s).
HIT_GRID = 3
HIT_TIMEOUT_S = 1.5
#: A keyboard key tapped by position after the player typed the text in
#: place of your keys (unchecked: the keyboard may look different now).
AFTER_TYPING = "keyboard key, the keyboard may look different after typing"
#: The display's size and rotation are asked again after this long (s).
DISPLAY_EVERY_S = 5.0
#: Nothing could check a step: no element was recorded (or it is a key on
#: the keyboard), a swipe, a key, a raw gesture.
_NOTHING_TO_CHECK = ("nothing to match", "keyboard key")

#: Per step: ``verified`` (found by element and the live hit test showed it
#: topmost at the tapped spot, or the typed field read back), ``unchecked``
#: (it could have been checked and was not: element not found, covered,
#: off-screen, not hit-tested, no helper, field unreadable, the screen is
#: not the recorded one), ``diverged``, or
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


#: Pixels two boxes may differ by and still be "the same size".
SIZE_SLOP_PX = 2


def _same_size(a: tuple[int, int, int, int], b: Any) -> bool:
    """Box ``b`` is box ``a`` shifted only up or down: the same left and
    right edge and height (within :data:`SIZE_SLOP_PX`). False when ``b``
    is unknown.
    """
    bb = _bounds(b)
    if bb is None:
        return False
    slop = SIZE_SLOP_PX
    return (
        abs(a[0] - bb[0]) <= slop
        and abs(a[2] - bb[2]) <= slop
        and abs((a[3] - a[1]) - (bb[3] - bb[1])) <= slop
    )


def _inside(xy: tuple[int, int], area: tuple[int, int, int, int]) -> bool:
    return area[0] <= xy[0] < area[2] and area[1] <= xy[1] < area[3]


def visible_part(
    item: dict[str, Any], reply: dict | None
) -> tuple[int, int, int, int] | None:
    """The matched node's bounds clipped to its window and the display
    (WebView nodes report their page position, which can lie far outside
    the screen; the dump has no visible-only bounds for them).
    """
    b = _bounds(item["node"].get("bounds"))
    if b is None:
        return None
    window = _bounds((item.get("window") or {}).get("bounds"))
    display = _screen((reply or {}).get("display"))
    return clip(b, window, display)


def rel_point(
    target: dict, xy: tuple[int, int] | None, now: tuple[int, int, int, int]
) -> tuple[int, int]:
    """Your tap's spot inside the recorded element, moved into its bounds
    ``now``: the same fraction of its width and height (a list row, a
    page, a large button is tapped where you tapped it, not at its centre).
    The centre when the recorded bounds or your position are unknown, or
    your position lay outside the recorded bounds.
    """
    rec = _bounds(target.get("bounds"))
    if rec is None or xy is None or not _inside(xy, rec):
        return centre(now)
    fx = (xy[0] - rec[0]) / (rec[2] - rec[0])
    fy = (xy[1] - rec[1]) / (rec[3] - rec[1])
    x = now[0] + int(fx * (now[2] - now[0]))
    y = now[1] + int(fy * (now[3] - now[1]))
    return min(max(x, now[0]), now[2] - 1), min(max(y, now[1]), now[3] - 1)


def tap_point(
    item: dict[str, Any],
    reply: dict | None,
    target: dict,
    screen: Any = None,
    xy: tuple[int, int] | None = None,
) -> tuple[int, int] | None:
    """Where to tap a matched element, or None when that spot is not on the
    screen.

    The spot is your recorded position ``xy`` relative to the recorded
    bounds, moved into the node's bounds now (:func:`rel_point`; the centre
    without one). It must lie in the node's visible part
    (:func:`visible_part`). A recorded target that reached beyond the
    recorded ``screen`` when you tapped it (a page-sized container) does
    not say where you tapped: None as well.
    """
    b = _bounds(item["node"].get("bounds"))
    if b is None:
        return None
    visible = visible_part(item, reply)
    point = rel_point(target, xy, b)
    if visible is None or not _inside(point, visible):
        return None
    rec, rec_screen = _bounds(target.get("bounds")), _screen(screen)
    if rec is not None and rec_screen is not None and clip(rec, rec_screen) != rec:
        return None
    return point


def other_spots(
    visible: tuple[int, int, int, int], near: tuple[int, int], n: int = HIT_GRID
) -> list[tuple[int, int]]:
    """Spots inside ``visible`` to try when your spot is covered or off the
    screen: your spot moved into it first, then the centres of an ``n`` x
    ``n`` grid, nearest to your spot first.
    """
    left, top, right, bottom = visible
    first = (min(max(near[0], left), right - 1), min(max(near[1], top), bottom - 1))
    grid = [
        (left + (2 * i + 1) * (right - left) // (2 * n),
         top + (2 * j + 1) * (bottom - top) // (2 * n))
        for j in range(n)
        for i in range(n)
    ]  # fmt: skip
    grid.sort(key=lambda p: (p[0] - near[0]) ** 2 + (p[1] - near[1]) ** 2)
    out: list[tuple[int, int]] = []
    for p in [first, *grid]:
        if p not in out:
            out.append(p)
    return out


def _same_node(a: Any, b: Any) -> bool:
    """``a`` and ``b`` are the same node: the same helper node id when both
    have one; else the same bounds and no differing id, class or text.
    """
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if a.get("nid") is not None and b.get("nid") is not None:
        return a["nid"] == b["nid"]
    if _bounds(a.get("bounds")) is None or _bounds(a.get("bounds")) != _bounds(
        b.get("bounds")
    ):
        return False
    for key in ("rid", "cls", "text", "desc"):
        va, vb = _norm(a.get(key)), _norm(b.get(key))
        if key == "cls":
            va, vb = _short_cls(va), _short_cls(vb)
        if va and vb and va != vb:
            return False
    return True


def _inner_of(
    node: dict, item: dict[str, Any], items: list[dict[str, Any]],
    path: Any = None,
) -> bool | None:  # fmt: skip
    """``node`` (of a live answer) lies inside the matched ``item``'s node:
    True / False when the dump knows ``node`` (its id), else by its bounds
    inside the item's and (when known) its ``path`` below the item's.
    None when nothing tells.
    """
    nid = node.get("nid")
    if nid is not None:
        for it in items:
            if it["node"].get("nid") == nid and (
                (it.get("window") or {}).get("id")
                == (item.get("window") or {}).get("id")
            ):
                return id(item["node"]) in it["anc"]
    nb, eb = _bounds(node.get("bounds")), _bounds(item["node"].get("bounds"))
    if nb is None or eb is None:
        return None
    if not (eb[0] <= nb[0] and eb[1] <= nb[1] and nb[2] <= eb[2] and nb[3] <= eb[3]):
        return False
    ep = item.get("path")
    if isinstance(path, list) and isinstance(ep, list) and ep:
        return path[: len(ep)] == ep and len(path) > len(ep)
    return True


def still_matches(target: dict, live: dict, item: dict[str, Any]) -> bool:
    """The node the live hit test found as the element still is what you
    tapped (a recycled list row keeps its id while it shows another text):
    the recorded ``target``'s fields against the live node. A node inside
    the element (not the element itself) is not compared again.
    """
    tgt, hit, node = live.get("target"), live.get("hit"), item["node"]
    if _same_node(tgt, node):
        cand, has_label = tgt, True
    elif _same_node(hit, node):
        cand, has_label = hit, not isinstance(tgt, dict)
    else:
        return True
    texts = [_norm(cand.get(k)) for k in ("text", "desc") if _norm(cand.get(k))]
    want = dict(target)
    if has_label and isinstance(live.get("label"), str):
        texts += [p.strip() for p in live["label"].split(" / ") if p.strip()]
    else:
        want.pop("label", None)
    return node_matches(want, {"node": cand, "texts": texts})


def _top_inside(
    top: dict, item: dict[str, Any], items: list[dict[str, Any]], live: dict
) -> bool:
    """The live ``top`` node lies inside the matched web element. A node the
    dump does not know (an overlay that appeared after it) is not: web paths
    are all ``View``, so bounds and path would take any overlay inside the
    element's box for a part of it.
    """
    nid = top.get("nid")
    if nid is not None and not any(it["node"].get("nid") == nid for it in items):
        return False
    return bool(_inner_of(top, item, items, live.get("top_path")))


def hit_is_element(
    live: Any, item: dict[str, Any], items: list[dict[str, Any]]
) -> bool:
    """The live hit test ``live`` (a ``node_at`` ``live`` answer) shows the
    matched element as the topmost at the tested spot: the element itself,
    or a node inside it with no other control inside it taking the tap.
    A node of another window (a dialog, the keyboard) is never it, nor a
    web element under another page element (``live.top``, the helper's
    top-most node there when it is not the hit).
    """
    if not isinstance(live, dict) or not isinstance(live.get("hit"), dict):
        return False
    hit, tgt = live["hit"], live.get("target")
    win = (live.get("window") or {}).get("id")
    own = (item.get("window") or {}).get("id")
    if win is not None and own is not None and win != own:
        return False
    node = item["node"]
    top = live.get("top")
    if isinstance(top, dict) and isinstance(node.get("web"), dict):
        # Web content takes the tap at the element painted on top, even one
        # that does not listen for it (a banner over part of a button).
        if not (_same_node(top, node) or _top_inside(top, item, items, live)):
            return False
    if _same_node(tgt, node) or _same_node(hit, node):
        return True
    if not _inner_of(hit, item, items, live.get("path")):
        return False
    if isinstance(tgt, dict) and not _same_node(tgt, hit):
        # The control that takes the tap: another one inside the element
        # (a button inside a row) is not the element.
        inside = _inner_of(tgt, item, items)
        tb, nb = _bounds(tgt.get("bounds")), _bounds(node.get("bounds"))
        if inside or (inside is None and tb != nb):
            return False
    elif isinstance(tgt, dict):
        return False  # the hit is a control of its own inside the element
    return True


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
                # (before check_text marks the last key as this text's); the
                # read-back follows the last character, not an action key
                planned = _plan_typing(steps, data, sensitive, line.get("t"))
                last_ime = planned or last_ime
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


#: A keyboard tap up to this long (s) after the text's last change still
#: belongs to it (the line's time and duration are the field's).
TYPING_SLACK_S = 0.3


def _plan_typing(
    steps: list[Step], data: dict, sensitive: bool, t: Any = None
) -> Step | None:
    """The keyboard taps at the end of ``steps`` typed ``data.text``: the
    first of them gets ``type_text`` (the text, its field, its pace) and
    each one ``typed_by`` (the first one's number), so the replay can type
    the text into the field instead of tapping keys whose positions depend
    on the keyboard's state.

    The taps are the keyboard taps since the text before (never one that
    already belongs to an earlier text) up to the text's last change (``t``
    + ``dur_ms``): a key tapped after it (Go, Next, Enter) is no character
    and stays a tap. Only when there is one tap per character (a shift,
    a suggestion, a glide or an action key in between: the taps are kept),
    the text was read in full and Tracking named its field. Returns the
    last character's tap (None: no plan).
    """
    trailing: list[Step] = []
    for step in reversed(steps):
        if not step.data.get("ime") or step.kind != "tap":
            break
        if step.data.get("typed_by") or step.data.get("check_text"):
            break  # an earlier text's keys
        trailing.insert(0, step)
    start = _epoch(t)
    try:
        dur = float(data.get("dur_ms") or 0.0) / 1000.0
    except (TypeError, ValueError):
        dur = 0.0
    if start is None:
        return None
    end = start + max(0.0, dur) + TYPING_SLACK_S
    group = []
    for step in trailing:
        st = _epoch(step.t)
        if st is None:
            return None
        if st <= end:
            group.append(step)
    text = data.get("text")
    target = data.get("target") if isinstance(data.get("target"), dict) else None
    if not group or target is None or data.get("partial"):
        return None
    if not isinstance(text, str) or len(group) != len(text):
        return None
    if not (target.get("rid") or _bounds(target.get("bounds"))):
        return None
    first = group[0]
    first.data["type_text"] = {
        "text": data["text"],
        "target": target,
        "password": bool(data.get("password")),
        "dur_ms": data.get("dur_ms"),
        "taps": len(group),
    }
    first.sensitive = first.sensitive or sensitive
    for step in group:
        step.data["typed_by"] = first.i
    return group[-1]


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


def _field_text(node: dict) -> str:
    """A field node's value ("" while it shows its hint)."""
    return "" if node.get("showing_hint") else str(node.get("text") or "")


def _all_selected(node: dict) -> bool:
    """The field's whole text is selected (the helper's ``sel_start`` /
    ``sel_end``): typing replaces it.
    """
    start, end = node.get("sel_start"), node.get("sel_end")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (start, end)):
        return False
    text = _field_text(node)
    if text.endswith("\u2026"):
        return False  # the helper cut a long text: its length is unknown
    lo, hi = min(start, end), max(start, end)
    # Android's offsets count UTF-16 units.
    return lo == 0 and hi > 0 and hi >= len(text.encode("utf-16-le")) // 2


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
        #: Steps whose keyboard taps were replaced by typing the text.
        self._typed: set[int] = set()
        #: Text was typed in place of keys and no other step came since:
        #: the keyboard may not look as in your run (key events can switch
        #: it to its compact bar; its suggestions differ).
        self._after_typing = False
        self._display_cache: tuple[float, Any] | None = None

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

    def _live_helper(self) -> Any:
        return self.helper() if callable(self.helper) else self.helper

    def _fresh(self) -> None:
        """Drop the helper's a11y cache before reading the screen: an app
        that changed its tree without telling a11y would else answer from
        the old tree (a dropdown that refilled while you typed).
        """
        helper = self._live_helper()
        fn = getattr(helper, "clear_cache", None) if helper is not None else None
        if callable(fn):
            try:
                fn()
            except Exception:
                logger.debug("replay: clear_cache failed", exc_info=True)

    def _hit(self, xy: tuple[int, int]) -> dict | None:
        """The live hit test at ``xy`` (``node_at`` live): its answer, ``{}``
        when it answered nothing, None when no hit test is possible.
        """
        helper = self._live_helper()
        fn = getattr(helper, "node_at", None) if helper is not None else None
        if not callable(fn):
            return None
        try:
            reply = fn(xy[0], xy[1], mode="live", timeout=HIT_TIMEOUT_S)
        except Exception:
            logger.debug("replay: hit test failed", exc_info=True)
            return None
        if not isinstance(reply, dict):
            return None
        live = reply.get("live")
        return live if isinstance(live, dict) else {}

    def _aim(
        self, step: Step, item: dict[str, Any], reply: dict
    ) -> tuple[tuple[int, int] | None, str, str]:
        """Where to tap the found element: ``(xy, reason, check)``.

        Your spot (relative to the element) is tapped when the live hit test
        shows the element topmost there; else the other visible spots
        (:func:`other_spots`) are tested. ``verified`` only after a hit test
        passed; no spot passing is ``(None, COVERED)``; no hit test possible
        taps your spot unchecked (:data:`NOT_HIT_TESTED`).
        """
        target = step.target or {}
        b = _bounds(item["node"].get("bounds"))
        visible = visible_part(item, reply)
        if b is None or visible is None:
            return None, OFF_SCREEN, CHECK_UNCHECKED
        rec = _bounds(target.get("bounds"))
        rec_screen = _screen(step.data.get("screen"))
        if rec is not None and rec_screen is not None and clip(rec, rec_screen) != rec:
            # A page-sized target does not say where on it you tapped.
            return None, OFF_SCREEN, CHECK_UNCHECKED
        mine = rel_point(target, self._xy(step), b)
        spots = other_spots(visible, mine)
        if _inside(mine, visible):
            spots = [mine, *[p for p in spots if p != mine]]
        self._fresh()
        items = walk_dump(reply)
        covered = False  # a spot answered with something else on top
        for n, xy in enumerate(spots):
            if self.cancelled():
                raise StepStoppedError("you pressed Esc")
            live = self._hit(xy)
            if live is None:
                if n == 0 and xy == mine:
                    return xy, NOT_HIT_TESTED, CHECK_UNCHECKED
                break
            if not isinstance(live.get("hit"), dict):
                continue  # no answer at this spot: no evidence either way
            if hit_is_element(live, item, items) and still_matches(target, live, item):
                if xy == mine:
                    return xy, "", CHECK_VERIFIED
                where = "covered" if _inside(mine, visible) else "off the screen"
                why = f"your spot was {where}, tapped another spot of it"
                return xy, why, CHECK_VERIFIED
            covered = True
        if not _inside(mine, visible):
            return None, OFF_SCREEN, CHECK_UNCHECKED
        return None, COVERED if covered else NOT_HIT_TESTED, CHECK_UNCHECKED

    def locate(self, step: Step) -> tuple[tuple[int, int] | None, str, str]:
        """Wait for the step's element: ``(xy, reason, check)``, xy None when
        it is not tapped by element (reason says why).

        The element must be the only match and have the same bounds in two
        polls :data:`ELEMENT_POLL_S` apart (the screen stopped moving); then
        :meth:`_aim` hit-tests where to tap it.
        """
        target = step.target or {}
        if not _identifying(target):
            return None, "nothing to match", CHECK_NONE
        if target.get("stale_possible"):
            return None, WEAK_TARGET, CHECK_UNCHECKED
        deadline = self._mono() + self.element_wait_s
        last_bounds = None
        why = "the UI helper is not running"
        current = self._live_helper()
        if current is None:
            # no helper (the replay already waited for it)
            return None, why, CHECK_UNCHECKED
        self._fresh()
        while True:
            if self.cancelled():
                raise StepStoppedError("you pressed Esc")
            reply = self._dump()
            if reply is not None:
                item, why = find_element(target, reply, step.pkg)
                if item is not None:
                    b = _bounds(item["node"].get("bounds"))
                    if b is not None and b == last_bounds:
                        return self._aim(step, item, reply)
                    last_bounds = b
                    why = "the element kept moving"
                else:
                    last_bounds = None
            elif not callable(self.helper) and self.helper is None:
                return None, why, CHECK_UNCHECKED
            if self._mono() >= deadline:
                return None, why, CHECK_UNCHECKED
            self._sleep(ELEMENT_POLL_S)

    def _field_node(
        self,
        xy: tuple[int, int] | None,
        rid: str | None = None,
        bounds: tuple[int, int, int, int] | None = None,
        *,
        focused_only: bool = False,
    ) -> dict | None:
        """The focused field's node now; None when no field could be read,
        or the focus is on another field: its id is not the recorded
        ``rid``, or with no id its box is not near the recorded ``bounds``.
        """
        helper = self.helper() if callable(self.helper) else self.helper
        fn = getattr(helper, "focus", None) if helper is not None else None
        if not callable(fn):
            return None
        try:
            reply = fn(*(xy or (None, None)), timeout=1.0)
        except Exception:
            logger.debug("replay: focus read failed", exc_info=True)
            return None
        if not isinstance(reply, dict):
            return None
        node = None
        for key in ("input",) if focused_only else ("input", "node"):
            cand = reply.get(key)
            if isinstance(cand, dict) and cand.get("editable"):
                node = cand
                break
        if node is None:
            return None
        if rid and node.get("rid") and node.get("rid") != rid:
            return None  # the focus moved on (e.g. a code field)
        if rid and not node.get("rid") and bounds is None:
            return None  # an id was recorded; this field has none
        if (not rid or not node.get("rid")) and bounds is not None:
            # No id: the box must be the recorded field's, at most moved up
            # or down (a keyboard pan): same left, right and height.
            if not _near(bounds, node.get("bounds")) or not _same_size(
                bounds, node.get("bounds")
            ):
                return None
        return node

    def _field_value(
        self,
        xy: tuple[int, int] | None,
        rid: str | None = None,
        bounds: tuple[int, int, int, int] | None = None,
        *,
        focused_only: bool = False,
    ) -> tuple[str | None, bool]:
        """``(text, password)`` of the focused field now (``text`` None: see
        :meth:`_field_node`; a hint shown in an empty field reads as "").
        """
        node = self._field_node(xy, rid, bounds, focused_only=focused_only)
        if node is None:
            return None, False
        return _field_text(node), bool(node.get("password"))

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

    def _display_now(self) -> tuple[int, int, int | None] | None:
        """``(w, h, rotation)`` of the display now: the helper's (current
        rotation), else ``wm size`` (natural orientation, rotation None);
        None when neither answers. Asked at most every
        :data:`DISPLAY_EVERY_S` (keyboard taps come fast).
        """
        now = self._mono()
        cached = self._display_cache
        if cached is not None and now - cached[0] < DISPLAY_EVERY_S:
            return cached[1]
        value = self._read_display()
        self._display_cache = (now, value)
        return value

    def _read_display(self) -> tuple[int, int, int | None] | None:
        helper = self._live_helper()
        fn = getattr(helper, "display", None) if helper is not None else None
        if callable(fn):
            try:
                disp = fn()
            except Exception:
                disp = None
            if isinstance(disp, dict):
                w, h = disp.get("w"), disp.get("h")
                if isinstance(w, int) and isinstance(h, int) and w > 0 and h > 0:
                    rot = disp.get("rotation")
                    return w, h, rot if isinstance(rot, int) else None
        try:
            out = self.shell("wm size")
        except Exception:
            return None
        found = re.findall(r"(Physical|Override) size:\s*(\d+)x(\d+)", str(out))
        sizes = {m[0]: (int(m[1]), int(m[2])) for m in found}
        size = sizes.get("Override") or sizes.get("Physical")
        return (*size, None) if size else None

    def _screen_differs(self, step: Step, points: list[tuple[int, int]]) -> str:
        """A position step on a display other than the recorded one: the
        plain reason ("" when it is the same or nothing tells). Positions
        are never scaled; one outside the current display stops the step.
        """
        rec = _screen(step.data.get("screen"))
        if rec is None:
            return ""
        now = self._display_now()
        if now is None:
            return ""
        w, h, rot = now
        rec_rot = step.data.get("rotation")
        rec_rot = rec_rot if isinstance(rec_rot, int) else None
        if rot is None:
            # ``wm size`` is the natural orientation: turn the recorded one.
            want = (rec[2], rec[3]) if rec_rot in (None, 0, 2) else (rec[3], rec[2])
            same = (w, h) == want
        else:
            same = (w, h) == (rec[2], rec[3]) and (rec_rot is None or rec_rot == rot)
        if same:
            return ""
        if rot is not None and rec_rot is not None and rot != rec_rot:
            if any(not _inside(p, (0, 0, w, h)) for p in points):
                raise StepStoppedError(
                    "the recorded position is off the screen now (it is turned)"
                )
            return "the screen is turned another way than in your run"
        cur = (w, h) if rot is not None or rec_rot in (None, 0, 2) else (h, w)
        if any(not _inside(p, (0, 0, *cur)) for p in points):
            raise StepStoppedError("the recorded position is off the screen now")
        return f"the screen is {w}x{h}, your run had {rec[2]}x{rec[3]}"

    def _type_into_field(self, step: Step) -> dict[str, Any] | None:
        """Keyboard taps that typed a known text: type that text into its
        field instead (per character, at the recorded pace) when the field
        has the input focus and is empty or has all its text selected (the
        first character replaces it, as your first key did), then read it
        back. None when the field cannot be verified: the keys are tapped
        as recorded.
        """
        plan = step.data.get("type_text")
        if not isinstance(plan, dict):
            return None
        text = plan.get("text")
        if not isinstance(text, str) or not text or input_text_arg(text) is None:
            return None
        if any(input_text_arg(c) is None for c in text):
            return None
        target = plan.get("target") if isinstance(plan.get("target"), dict) else {}
        bounds = _bounds(target.get("bounds"))
        rid = target.get("rid") or None
        node = self._field_node(None, rid, bounds, focused_only=True)
        if node is None:
            return None  # not the recorded field
        if _field_text(node).strip() and not _all_selected(node):
            # It holds text that typing would not replace: where would the
            # characters go? (An address bar selects its text on focus.)
            return None
        self._type(text, plan.get("dur_ms"))
        self._typed.add(step.i)
        self._after_typing = True
        taps = int(plan.get("taps") or 0)
        res = {
            "way": WAY_REPLAYED,
            "reason": f"typed {len(text)} characters into the field "
            f"instead of {taps} keyboard tap{'s' if taps != 1 else ''}",
        }
        return self._checked(
            res, text, target, bool(plan.get("password")) or step.sensitive
        )

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
        if not data.get("ime"):
            self._after_typing = False
        if kind == "tap" and data.get("typed_by") in self._typed:
            if data["typed_by"] != step.i:
                return {"way": WAY_REPLAYED, "check": CHECK_NONE,
                        "reason": f"typed with step {data['typed_by']}"}  # fmt: skip
        if kind == "tap" and data.get("type_text") and data.get("typed_by") == step.i:
            res = self._type_into_field(step)
            if res is not None:
                return res
        if kind in ("tap", "long_press"):
            xy, way, reason, check = None, WAY_ELEMENT, "", CHECK_NONE
            if data.get("ime"):
                reason = "keyboard key"
                # (step_check below makes both unchecked)
                if data.get("type_text"):
                    reason = "keyboard key, its field could not be verified"
                elif self._after_typing and not data.get("typed_by"):
                    # Go / Enter after the typed text: its spot on a keyboard
                    # that may look different says nothing.
                    reason = AFTER_TYPING
            else:
                xy, reason, check = self.locate(step)
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
            # A recorded element that was looked for and not found.
            missed = (
                way == WAY_POSITION
                and not data.get("ime")
                and reason
                not in (
                    *_NO_EVIDENCE,
                    OFF_SCREEN,
                    COVERED,
                    WEAK_TARGET,
                    NOT_HIT_TESTED,
                )
            )
            if way == WAY_POSITION:
                check = step_check(way, reason)
                differs = self._screen_differs(step, [xy])
                if differs:
                    check = CHECK_UNCHECKED
                    reason = f"{reason}, {differs}" if reason else differs
            x, y = xy
            if kind == "tap":
                self._run(f"input tap {x} {y}")
            else:
                dur = max(600, int(data.get("dur_ms") or 600))
                self._run(f"input swipe {x} {y} {x} {y} {dur}")
            res = {"way": way, "reason": reason, "x": x, "y": y}
            res["missed"] = missed
            res["check"] = check
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
            differs = self._screen_differs(step, [start, (int(x1), int(y1))])
            self._run(f"input swipe {start[0]} {start[1]} {int(x1)} {int(y1)} {dur}")
            return {"way": WAY_POSITION, "reason": differs, "x": start[0],
                    "y": start[1],
                    "check": CHECK_UNCHECKED if differs else CHECK_NONE}  # fmt: skip
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
            self._after_typing = True
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
            way in (WAY_POSITION, WAY_REPLAYED, WAY_ELEMENT)
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
        self._typed = set()
        self._after_typing = False
        self._display_cache = None
        prev_t: float | None = None
        missed: int | None = None  # the step before missed its element
        div: dict[str, Any] = {
            "diverged_at_step": None,
            "diverged": None,
            "unchecked_steps": [],
            # Wall-clock time of step 1 (the Rewind verdict measures a
            # value's distance from its run from here).
            "first_step_at": None,
        }
        for step in steps:
            gap = 0.0
            t = _epoch(step.t)
            if prev_t is not None and t is not None:
                gap = min(MAX_GAP_S, max(0.0, t - prev_t))
            if t is not None:
                prev_t = t
            if step.data.get("typed_by") in self._typed:
                gap = 0.0  # typed already, at the recorded pace
            self.progress(f"Replaying step {step.i} of {n}: {step.what}")
            entry = {"i": step.i, "seq": step.seq, "what": step.what}
            try:
                self._wait(gap)
                if div["first_step_at"] is None:
                    div["first_step_at"] = time.time()
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
