"""Device actions: things that happen TO the device, on request.

An SMS arrives, a call rings, the phone moves, the clock jumps, the
battery drains, the network drops. Each action is a :class:`DeviceAction`
in :data:`ACTIONS`: an ``id`` (``sms.receive``), typed :class:`Param` s
with validation, and a runner. :func:`run_action` is the one entry point
for every front end (the Shift+E modal, the headless API, later the YAML
playbooks and the AI tools):

* it validates the parameters (strings from a form or native values from
  YAML / JSON alike) and refuses an emulator-only action on a physical
  device, both before any adb call;
* it runs the action pinned to one serial (every adb call passes
  ``serial=``), off the UI thread (callers use a worker);
* it writes one ``action`` line on the session timeline (``kind`` = the
  id with ``-`` for ``.``, e.g. ``sms-receive``; ``data``: action, params,
  ok, details) so the action shows up in the Timeline lens, and returns an
  :class:`ActionResult` with a plain-words message.

``gps.route`` runs in the background (:func:`running_jobs`,
:func:`stop_job`); ``time.jump`` goes through
:func:`sandroid.core.device_clock.move_wall_clock`, which holds the moved
clock so the session clock sync does not snap it back.

Emulator facts this module relies on (emulator 35.4.9, API 35):

* ``sms send <sender> <text>`` takes a phone number (``[+]digits``) or a
  sender of up to 11 letters (``DHL``, ``PayPal``). A sender mixing letters
  and digits (``O2``, ``Shop24``) is accepted by the console but arrives
  with only its digits, so it is refused here. ``sms pdu`` is a no-op.
  The console splits on whitespace: runs of spaces and line breaks in the
  text arrive as single spaces.
* ``gsm call`` / ``gsm accept`` work for incoming calls; ``gsm cancel``
  does not end an outgoing call, so ``call.hangup`` uses the device's
  END CALL key (any call, any direction, also on a physical device).
* ``gsm list`` prints nothing; the call state is read from
  ``dumpsys telephony.registry`` (``mCallState``).
"""

from __future__ import annotations

import itertools
import logging
import math
import re
import shlex
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

#: Timeline source of every action line.
TIMELINE_SRC = "action"
#: Longest SMS text accepted (the console takes one line).
SMS_TEXT_MAX = 1000
#: Longest alphanumeric SMS sender (the GSM address field's limit).
ALPHA_SENDER_MAX = 11
#: Longest move of ``time.jump`` (days).
TIME_JUMP_MAX_DAYS = 3650
#: Seconds between the END CALL key and the check that the call ended.
HANGUP_CHECK_S = 1.0

#: Waits (tests replace them).
_sleep: Callable[[float], None] = time.sleep


def _wait(event: threading.Event, seconds: float) -> bool:
    """Wait up to ``seconds`` for ``event``; True when it was set."""
    return event.wait(seconds)


class ActionError(ValueError):
    """Invalid parameters or a refused action (nothing was sent)."""


class CommandError(RuntimeError):
    """The device or emulator console rejected a command."""


# ---------------------------------------------------------------------------
# parameters
# ---------------------------------------------------------------------------

_TRUE = frozenset({"1", "true", "on", "yes"})
_FALSE = frozenset({"0", "false", "off", "no"})


@dataclass(frozen=True)
class Param:
    """One parameter of an action.

    Attributes:
        name: Key in the params mapping (``sender``).
        label: Plain words for forms and errors (``Sender``).
        kind: ``text`` | ``number`` | ``int`` | ``bool`` | ``choice``.
        required: A value must be given (after the default).
        default: Used when the value is missing or empty.
        choices: ``(value, label)`` pairs of a ``choice``.
        placeholder: Example shown in an empty form field.
        minimum: Lowest allowed ``number`` / ``int``.
        maximum: Highest allowed ``number`` / ``int``.
        check: Extra validation of the parsed value: returns the value to
            use (possibly normalised) or raises :class:`ActionError`.
    """

    name: str
    label: str
    kind: str = "text"
    required: bool = True
    default: Any = None
    choices: tuple[tuple[str, str], ...] = ()
    placeholder: str = ""
    minimum: float | None = None
    maximum: float | None = None
    check: Callable[[Any], Any] | None = None

    def parse(self, raw: Any) -> Any:
        """The validated value of ``raw`` (``None``: not given, optional).

        Raises:
            ActionError: The value is missing or invalid.
        """
        if isinstance(raw, str):
            raw = raw.strip()
        if raw is None or raw == "":
            raw = self.default
        if raw is None or raw == "":
            if self.required:
                raise ActionError(f"{self.label}: enter a value")
            return None
        value = self._convert(raw)
        if self.check is not None:
            value = self.check(value)
        return value

    def _convert(self, raw: Any) -> Any:
        if self.kind == "bool":
            if isinstance(raw, bool):
                return raw
            word = str(raw).strip().lower()
            if word in _TRUE:
                return True
            if word in _FALSE:
                return False
            raise ActionError(f"{self.label}: on or off")
        if self.kind == "choice":
            values = [value for value, _label in self.choices]
            if str(raw) not in values:
                raise ActionError(f"{self.label}: one of {', '.join(values)}")
            return str(raw)
        if self.kind in ("number", "int"):
            if isinstance(raw, bool):
                raise ActionError(f"{self.label}: a number")
            try:
                text = raw.replace(",", ".") if isinstance(raw, str) else raw
                value = float(text)
            except (TypeError, ValueError):
                raise ActionError(f"{self.label}: a number") from None
            if not math.isfinite(value):
                raise ActionError(f"{self.label}: a number")
            if self.kind == "int":
                if value != int(value):
                    raise ActionError(f"{self.label}: a whole number")
                value = int(value)
            if self.minimum is not None and value < self.minimum:
                raise ActionError(f"{self.label}: at least {_num(self.minimum)}")
            if self.maximum is not None and value > self.maximum:
                raise ActionError(f"{self.label}: at most {_num(self.maximum)}")
            return value
        return str(raw)


def _num(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


# ---------------------------------------------------------------------------
# value checks
# ---------------------------------------------------------------------------

_PHONE_SEPARATORS = re.compile(r"[\s\-/().]")
_PHONE = re.compile(r"^\+?[0-9]{2,20}$")
_ALPHA = re.compile(r"^[A-Za-z]+$")
_ALNUM = re.compile(r"^[A-Za-z0-9]+$")


def phone_number(value: str) -> str:
    """``value`` as a dialable number (spaces, dashes, slashes and brackets
    dropped): ``+`` then 2-20 digits.
    """
    number = _PHONE_SEPARATORS.sub("", value)
    if not _PHONE.match(number):
        raise ActionError(
            "Number: digits with an optional leading +, e.g. +4915112345678"
        )
    return number


def sms_sender(value: str) -> str:
    """A phone number / short code or a sender of up to 11 letters."""
    number = _PHONE_SEPARATORS.sub("", value)
    if _PHONE.match(number):
        return number
    if _ALPHA.match(value):
        if len(value) > ALPHA_SENDER_MAX:
            raise ActionError(
                f"Sender: at most {ALPHA_SENDER_MAX} letters (the SMS sender limit)"
            )
        return value
    if _ALNUM.match(value):
        raise ActionError(
            "Sender: letters and digits mixed arrive as the digits only on "
            "the emulator; use letters only (e.g. DHL) or a phone number"
        )
    raise ActionError(
        "Sender: letters only without spaces or signs (e.g. DHL, PayPal) "
        "or a phone number"
    )


def sms_text(value: str) -> str:
    """The text as it arrives: whitespace runs become single spaces."""
    text = " ".join(value.split())
    if not text:
        raise ActionError("Text: enter a value")
    if len(text) > SMS_TEXT_MAX:
        raise ActionError(f"Text: at most {SMS_TEXT_MAX} characters")
    return text


def latitude(value: float) -> float:
    if not -90 <= value <= 90:
        raise ActionError("Latitude: between -90 and 90")
    return value


def longitude(value: float) -> float:
    if not -180 <= value <= 180:
        raise ActionError("Longitude: between -180 and 180")
    return value


_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(d|h|min|m|s)", re.IGNORECASE)
_DURATION = re.compile(
    r"^([+-])?\s*((?:\d+(?:\.\d+)?\s*(?:d|h|min|m|s)\s*)+)$", re.IGNORECASE
)
_UNIT_S = {"d": 86400, "h": 3600, "min": 60, "m": 60, "s": 1}


def duration(value: str) -> float:
    """Seconds of a signed duration: ``+2h``, ``-30m``, ``1d 2h``, ``90s``."""
    match = _DURATION.match(value.strip())
    if not match:
        raise ActionError("Move by: a duration with units, e.g. +2h, -30m, +1d 6h, 90s")
    seconds = sum(
        float(amount) * _UNIT_S[unit.lower()]
        for amount, unit in _DURATION_PART.findall(match.group(2))
    )
    if seconds == 0:
        raise ActionError("Move by: more than zero")
    if seconds > TIME_JUMP_MAX_DAYS * 86400:
        raise ActionError(f"Move by: at most {TIME_JUMP_MAX_DAYS} days")
    return -seconds if match.group(1) == "-" else seconds


_WHEN_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S",
                 "%Y-%m-%dT%H:%M", "%Y-%m-%d")  # fmt: skip


def _parse_when(text: str) -> datetime | None:
    """``text`` as a datetime; naive unless it carries a UTC offset (the
    device's zone is applied when the action runs).
    """
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in _WHEN_FORMATS:
        try:
            return datetime.strptime(text, fmt)  # noqa: DTZ007 - zone added later
        except ValueError:
            continue
    return None


def when(value: str) -> str:
    """A date and time ``YYYY-MM-DD HH:MM[:SS]`` (device local time, or
    with a UTC offset), kept as text until the device's zone is known.
    """
    text = value.strip()
    parsed = _parse_when(text)
    if parsed is None:
        raise ActionError("Move to: a date and time, e.g. 2026-12-24 18:00")
    if not 2000 <= parsed.year <= 2099:
        raise ActionError("Move to: a year from 2000 to 2099")
    return text


def format_delta(seconds: float) -> str:
    """``+2 h``, ``-1 h 30 min``, ``+3 d``, ``+45 s`` (ASCII signs)."""
    sign = "-" if seconds < 0 else "+"
    rest = round(abs(seconds))
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60), ("s", 1)):
        amount, rest = divmod(rest, size)
        if amount:
            parts.append(f"{amount} {unit}")
    return sign + (" ".join(parts[:2]) if parts else "0 s")


# ---------------------------------------------------------------------------
# GPS routes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoutePreset:
    """A built-in route: waypoints ``(lat, lon)`` and a typical speed."""

    label: str
    points: tuple[tuple[float, float], ...]
    speed_kmh: float


ROUTE_PRESETS: dict[str, RoutePreset] = {
    "berlin-walk": RoutePreset(
        "Berlin walk (Alexanderplatz to Brandenburg Gate)",
        (
            (52.5219, 13.4132),
            (52.5194, 13.4070),
            (52.5169, 13.4019),
            (52.5175, 13.3889),
            (52.5163, 13.3777),
        ),
        5.0,
    ),
    "munich-drive": RoutePreset(
        "Munich drive (Marienplatz to Olympiapark)",
        (
            (48.1374, 11.5755),
            (48.1402, 11.5600),
            (48.1500, 11.5580),
            (48.1620, 11.5540),
            (48.1731, 11.5466),
        ),
        40.0,
    ),
    "new-york-walk": RoutePreset(
        "New York walk (Times Square to Flatiron)",
        (
            (40.7580, -73.9855),
            (40.7527, -73.9772),
            (40.7484, -73.9857),
            (40.7411, -73.9897),
        ),
        5.0,
    ),
}
_POINT = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$")


def route_points(value: str) -> str:
    """``lat,lon; lat,lon; ...`` with at least two valid points."""
    parse_points(value)
    return value


def parse_points(value: str) -> list[tuple[float, float]]:
    """The points of ``lat,lon; lat,lon; ...``.

    Raises:
        ActionError: Fewer than two points or one is invalid.
    """
    points = []
    for chunk in [c for c in value.split(";") if c.strip()]:
        match = _POINT.match(chunk)
        if not match:
            raise ActionError(f"Points: '{chunk.strip()}' is not lat,lon")
        lat, lon = float(match.group(1)), float(match.group(2))
        latitude(lat)
        longitude(lon)
        points.append((lat, lon))
    if len(points) < 2:
        raise ActionError("Points: at least two, e.g. 52.52,13.40; 52.51,13.38")
    return points


def _distance_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance (m) between two ``(lat, lon)`` points."""
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = (
        math.sin((lat2 - lat1) / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    )
    return 2 * 6_371_000 * math.asin(math.sqrt(h))


def route_fixes(
    points: list[tuple[float, float]], speed_kmh: float, interval_s: float
) -> list[tuple[float, float]]:
    """Positions every ``interval_s`` seconds along ``points`` at
    ``speed_kmh`` (straight lines between waypoints), first and last
    waypoint included.
    """
    step = speed_kmh / 3.6 * interval_s  # metres per fix
    fixes = [points[0]]
    carry = 0.0  # metres already walked into the current segment
    for a, b in itertools.pairwise(points):
        length = _distance_m(a, b)
        pos = step - carry
        while pos < length:
            f = pos / length
            fixes.append((a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f))
            pos += step
        carry = length - (pos - step)
    if fixes[-1] != points[-1]:
        fixes.append(points[-1])
    return fixes


# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------


@dataclass
class ActionResult:
    """What an action did, in plain words.

    Attributes:
        action: The action id.
        ok: Whether it worked.
        message: What happened (``SMS received from DHL``) or, on failure,
            the reason.
        data: Details (also written to the timeline line).
        job: Id of the background job it started (``gps.route``).
        refused: Nothing was sent (invalid parameters, wrong device).
    """

    action: str
    ok: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    job: str | None = None
    refused: bool = False


Runner = Callable[["_Device", dict[str, Any], "DeviceAction"], ActionResult]


@dataclass(frozen=True)
class DeviceAction:
    """One device action of the registry.

    Attributes:
        id: ``group.verb`` (``sms.receive``).
        title: Plain words (``Receive an SMS``).
        group: Heading in front ends (``SMS``).
        params: The parameters, in form order.
        runner: ``(device, params, action) -> ActionResult``.
        emulator_only: Refused on a physical device.
        background: Starts a background job (see :func:`running_jobs`).
        help: One line on what it does.
        check: Cross-parameter validation of the parsed params.
    """

    id: str
    title: str
    group: str
    params: tuple[Param, ...]
    runner: Runner
    emulator_only: bool = True
    background: bool = False
    help: str = ""
    check: Callable[[dict[str, Any]], None] | None = None

    def validate(self, raw: Mapping[str, Any] | None) -> dict[str, Any]:
        """Parsed params of ``raw``.

        Raises:
            ActionError: A missing, invalid or unknown parameter.
        """
        raw = dict(raw or {})
        known = {p.name for p in self.params}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ActionError(f"Unknown parameter: {', '.join(unknown)}")
        params = {p.name: p.parse(raw.get(p.name)) for p in self.params}
        if self.check is not None:
            self.check(params)
        return params

    def describe(self) -> dict[str, Any]:
        """JSON-friendly description (API listings, AI tools)."""
        return {
            "id": self.id,
            "title": self.title,
            "group": self.group,
            "emulator_only": self.emulator_only,
            "background": self.background,
            "help": self.help,
            "params": [
                {
                    "name": p.name,
                    "label": p.label,
                    "kind": p.kind,
                    "required": p.required,
                    "default": p.default,
                    "choices": [value for value, _label in p.choices],
                    "placeholder": p.placeholder,
                }
                for p in self.params
            ],
        }


def is_emulator(serial: str | None) -> bool:
    """``serial`` is an emulator (``emulator-NNNN``: what ``adb emu`` needs)."""
    return bool(serial) and str(serial).startswith("emulator-")


class _Device:
    """adb and emulator-console calls pinned to one serial."""

    def __init__(self, serial: str, actor: str = "user") -> None:
        self.serial = serial
        self.actor = actor
        self.commands: list[str] = []

    @staticmethod
    def _adb() -> type:
        from sandroid.core.adb import Adb

        return Adb

    def emu(self, command: str) -> str:
        """One console command; ``KO`` or no ``OK`` raises :class:`CommandError`."""
        self.commands.append(f"emu {command}")
        stdout, stderr = self._adb().send_telnet_command(command, serial=self.serial)
        lines = [line.strip() for line in (stdout or "").splitlines()]
        for line in lines:
            if line.startswith("KO"):
                raise CommandError(line[2:].lstrip(": ").strip() or "refused")
        if not any(line.startswith("OK") for line in lines):
            detail = (stderr or "").strip() or (stdout or "").strip()
            raise CommandError(detail[:200] or "no answer from the emulator console")
        return stdout or ""

    def shell(self, command: str, check: bool = True) -> str:
        """One device shell command; an adb error (and with ``check`` an
        error in its output) raises :class:`CommandError`.
        """
        from sandroid.core.adb_utils import device_shell_command

        self.commands.append(f"shell {command}")
        stdout, stderr = self._adb().send_adb_command(
            device_shell_command(command), serial=self.serial
        )
        out = stdout or ""
        err = (stderr or "").strip()
        lowered = (out + "\n" + err).lower()
        failed = err.lower().startswith(("error", "adb: error"))
        if check and not failed:
            failed = any(
                marker in lowered
                for marker in ("exception", "unknown command", "not found", "error:")
            )
        if failed:
            raise CommandError((err or out).strip().splitlines()[0][:200])
        return out


#: serial -> the number of the newest incoming call (``call.accept``).
_LAST_CALL: dict[str, str] = {}
_STATE_LOCK = threading.Lock()


def _ok(action: DeviceAction, message: str, **data: Any) -> ActionResult:
    return ActionResult(action.id, True, message, data)


def _quote_preview(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


# -- SMS ----------------------------------------------------------------------


def _sms_receive(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    dev.emu(f"sms send {p['sender']} {p['text']}")
    kind = "number" if _PHONE.match(p["sender"]) else "alphanumeric"
    return _ok(
        action,
        f'SMS received from {p["sender"]}: "{_quote_preview(p["text"])}"',
        sender_type=kind,
    )


# -- calls --------------------------------------------------------------------


def _call_incoming(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    dev.emu(f"gsm call {p['number']}")
    with _STATE_LOCK:
        _LAST_CALL[dev.serial] = p["number"]
    return _ok(action, f"Incoming call from {p['number']}")


def _call_accept(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    number = p.get("number")
    if not number:
        with _STATE_LOCK:
            number = _LAST_CALL.get(dev.serial)
    if not number:
        raise ActionError("Number: enter the number of the ringing call")
    dev.emu(f"gsm accept {number}")
    return _ok(action, f"Call from {number} accepted", number=number)


_CALL_STATE = re.compile(r"mCallState=(\d+)")


def _call_state(dev: _Device) -> int | None:
    """0 idle, 1 ringing, 2 in a call; ``None`` unknown."""
    try:
        out = dev.shell("dumpsys telephony.registry", check=False)
    except CommandError:
        return None
    states = [int(s) for s in _CALL_STATE.findall(out)]
    return max(states) if states else None


def _call_hangup(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    if _call_state(dev) == 0:
        return ActionResult(action.id, False, "no call to hang up")
    dev.shell("input keyevent KEYCODE_ENDCALL")
    _sleep(HANGUP_CHECK_S)
    if (_call_state(dev) or 0) != 0:
        return ActionResult(action.id, False, "the call is still on")
    return _ok(action, "Call ended")


def _call_outgoing(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    number = p["number"]
    out = dev.shell(
        f"am start -a android.intent.action.CALL -d {shlex.quote('tel:' + number)}"
    )
    if "Starting" not in out:
        raise CommandError(out.strip()[:200] or "the dialer did not start")
    return _ok(action, f"Outgoing call to {number}")


# -- location -----------------------------------------------------------------


def _geo_fix(dev: _Device, lat: float, lon: float, alt: float | None = None) -> None:
    # The console expects longitude first.
    command = f"geo fix {lon:.6f} {lat:.6f}"
    if alt is not None:
        command += f" {alt:g}"
    dev.emu(command)


def _gps_fix(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    stopped = stop_jobs(dev.serial, action="gps.route")
    _geo_fix(dev, p["latitude"], p["longitude"], p.get("altitude"))
    message = f"GPS set to {p['latitude']:.5f}, {p['longitude']:.5f}"
    if stopped:
        message += " (the running route was stopped)"
    return _ok(action, message)


def _route_check(p: dict) -> None:
    if p["route"] == "custom" and not p.get("points"):
        raise ActionError("Points: enter at least two for a custom route")


def _gps_route(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    if p["route"] == "custom":
        points = parse_points(p["points"])
        label = "custom route"
        speed = p.get("speed_kmh") or 5.0
    else:
        preset = ROUTE_PRESETS[p["route"]]
        points = list(preset.points)
        label = preset.label.split(" (")[0]  # "Berlin walk"
        speed = p.get("speed_kmh") or preset.speed_kmh
    fixes = route_fixes(points, speed, p["interval_s"])
    length_m = sum(_distance_m(a, b) for a, b in itertools.pairwise(points))
    minutes = max(1, round(length_m / (speed / 3.6) / 60))
    stop_jobs(dev.serial, action="gps.route")
    _geo_fix(dev, *fixes[0])  # fail now, not in the background
    job = _start_job(
        action,
        dev,
        f"GPS route {label}",
        lambda job: _route_worker(job, dev, fixes, p["interval_s"], label),
    )
    job.progress = f"fix 1 of {len(fixes)}"  # the first fix was sent above
    return ActionResult(
        action.id,
        True,
        f"GPS route started: {label}, {length_m / 1000:.1f} km at {speed:g} km/h, "
        f"about {minutes} min",
        {"fixes": len(fixes), "length_m": round(length_m), "speed_kmh": speed},
        job=job.id,
    )


def _route_worker(
    job: Job,
    dev: _Device,
    fixes: list[tuple[float, float]],
    interval_s: float,
    label: str,
) -> None:
    done = 1
    job.progress = f"fix 1 of {len(fixes)}"
    error = None
    for lat, lon in fixes[1:]:
        if _wait(job.stop, interval_s):
            break
        try:
            _geo_fix(dev, lat, lon)
        except Exception as exc:
            error = str(exc)
            break
        done += 1
        job.progress = f"fix {done} of {len(fixes)}"
    if error:
        job.status = "failed"
        summary = f"GPS route failed: {label}: {error}"
    elif done < len(fixes):
        job.status = "stopped"
        summary = f"GPS route stopped: {label} after {done} of {len(fixes)} fixes"
    else:
        job.status = "finished"
        summary = f"GPS route finished: {label}"
    _timeline_line(
        "gps.route",
        dev.serial,
        summary,
        {
            "action": "gps.route",
            "job": job.id,
            "status": job.status,
            "fixes_sent": done,
            "fixes": len(fixes),
        },
        actor=job.actor,
        ok=error is None,
    )


# -- time ---------------------------------------------------------------------


def _time_check(p: dict) -> None:
    if (p.get("delta") is None) == (p.get("to") is None):
        raise ActionError("Time: give either Move by or Move to")


def _to_epoch(dev: _Device, text: str) -> float:
    """Epoch of ``text`` in the device's time zone (unless it has an offset)."""
    parsed = _parse_when(text)
    if parsed is None:  # validated by when(); kept for direct callers
        raise ActionError("Move to: a date and time, e.g. 2026-12-24 18:00")
    if parsed.tzinfo is None:
        try:
            from zoneinfo import ZoneInfo

            zone = dev.shell("getprop persist.sys.timezone", check=False).strip()
            if zone:
                parsed = parsed.replace(tzinfo=ZoneInfo(zone))
        except Exception:
            logger.debug("device time zone unknown; host zone used", exc_info=True)
    return parsed.timestamp()


def _time_jump(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    from sandroid.core import device_clock

    if p.get("delta") is not None:
        moved = device_clock.move_wall_clock(dev.serial, delta_s=p["delta"])
    else:
        moved = device_clock.move_wall_clock(
            dev.serial, to_epoch=_to_epoch(dev, p["to"])
        )
    data = {k: moved.get(k) for k in ("moved_s", "actual_moved_s", "set_by", "command")}
    if not moved.get("ok"):
        return ActionResult(action.id, False, moved.get("error") or "failed", data)
    return ActionResult(
        action.id,
        True,
        f"Device time moved {format_delta(moved['moved_s'])} "
        "(held until Back to real time or a snapshot load)",
        data,
    )


def _time_reset(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    from sandroid.core import device_clock

    reset = device_clock.reset_wall_clock(dev.serial)
    if not reset.get("ok"):
        return ActionResult(
            action.id, False, reset.get("error") or "failed",
            {"was_held": reset.get("was_held")},
        )  # fmt: skip
    return _ok(action, "Device time back to real time", was_held=reset["was_held"])


# -- power --------------------------------------------------------------------


def _power_battery(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    dev.emu(f"power capacity {p['level']}")
    return _ok(action, f"Battery set to {p['level']}%")


def _power_charging(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    if p["on"]:
        dev.emu("power ac on")
        dev.emu("power status charging")
        return _ok(action, "Charging on (charger plugged in)")
    dev.emu("power ac off")
    dev.emu("power status discharging")
    return _ok(action, "Charging off (charger unplugged)")


def _power_ac(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    dev.emu(f"power ac {'on' if p['on'] else 'off'}")
    return _ok(action, "Charger plugged in" if p["on"] else "Charger unplugged")


# -- network ------------------------------------------------------------------


def _toggle(service: str, label: str) -> Runner:
    def run(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
        dev.shell(f"svc {service} {'enable' if p['on'] else 'disable'}")
        return _ok(action, f"{label} {'on' if p['on'] else 'off'}")

    return run


def _net_airplane(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    dev.shell(f"cmd connectivity airplane-mode {'enable' if p['on'] else 'disable'}")
    return _ok(action, f"Airplane mode {'on' if p['on'] else 'off'}")


#: Emulator network profiles: value -> (label, speed, delay).
NETWORK_PROFILES: dict[str, tuple[str, str, str]] = {
    "full": ("Full speed, no added latency", "full", "none"),
    "lte": ("LTE", "lte", "none"),
    "3g": ("3G (UMTS)", "umts", "umts"),
    "edge": ("EDGE", "edge", "edge"),
    "gprs": ("GPRS (very slow)", "gprs", "gprs"),
}


def _net_profile(dev: _Device, p: dict, action: DeviceAction) -> ActionResult:
    label, speed, delay = NETWORK_PROFILES[p["profile"]]
    dev.emu(f"network speed {speed}")
    dev.emu(f"network delay {delay}")
    return _ok(action, f"Network profile: {label}", speed=speed, delay=delay)


# -- the registry ---------------------------------------------------------------

_ON = Param("on", "On", "bool", default=True)
_NUMBER = Param("number", "Number", placeholder="+4915112345678", check=phone_number)

ACTIONS: dict[str, DeviceAction] = {
    a.id: a
    for a in (
        DeviceAction(
            "sms.receive", "Receive an SMS", "SMS",
            (
                Param("sender", "Sender", placeholder="DHL or +4915112345678",
                      check=sms_sender),
                Param("text", "Text", placeholder="Your parcel arrives today",
                      check=sms_text),
            ),
            _sms_receive,
            help="An SMS arrives from a phone number or a letters-only sender.",
        ),
        DeviceAction(
            "call.incoming", "Incoming call", "Calls", (_NUMBER,), _call_incoming,
            help="The phone rings with a call from this number.",
        ),
        DeviceAction(
            "call.accept", "Accept the incoming call", "Calls",
            (Param("number", "Number", required=False,
                   placeholder="empty: the last incoming call", check=phone_number),),
            _call_accept,
            help="Answers the ringing call (as if the caller's network connected).",
        ),
        DeviceAction(
            "call.hangup", "Hang up", "Calls", (), _call_hangup,
            emulator_only=False,
            help="Ends the current call, incoming or outgoing (END CALL key).",
        ),
        DeviceAction(
            "call.outgoing", "Outgoing call", "Calls", (_NUMBER,), _call_outgoing,
            emulator_only=False,
            help="The phone dials this number (the dialer's call screen opens).",
        ),
        DeviceAction(
            "gps.fix", "Set the GPS position", "Location",
            (
                Param("latitude", "Latitude", "number", placeholder="52.52",
                      check=latitude),
                Param("longitude", "Longitude", "number", placeholder="13.405",
                      check=longitude),
                Param("altitude", "Altitude (m)", "number", required=False,
                      placeholder="optional", minimum=-500, maximum=10000),
            ),
            _gps_fix,
            help="The GPS reports this position (a running route is stopped).",
        ),
        DeviceAction(
            "gps.route", "Follow a GPS route", "Location",
            (
                Param("route", "Route", "choice", default="berlin-walk",
                      choices=(*((k, v.label) for k, v in ROUTE_PRESETS.items()),
                               ("custom", "Custom points"))),
                Param("points", "Points", required=False,
                      placeholder="custom: 52.52,13.40; 52.51,13.38",
                      check=route_points),
                Param("speed_kmh", "Speed (km/h)", "number", required=False,
                      placeholder="empty: the route's speed", minimum=0.5,
                      maximum=300),
                Param("interval_s", "Seconds per fix", "number", default=2,
                      placeholder="2", minimum=0.5, maximum=60),
            ),
            _gps_route,
            background=True,
            help="The GPS moves along the route in the background until it "
            "ends or is stopped.",
            check=_route_check,
        ),
        DeviceAction(
            "time.jump", "Move the device time", "Time",
            (
                Param("delta", "Move by", required=False,
                      placeholder="+2h, -30m, +1d 6h", check=duration),
                Param("to", "Move to", required=False,
                      placeholder="or: 2026-12-24 18:00 (device time)", check=when),
            ),
            _time_jump,
            emulator_only=False,
            help="Moves the device clock; Sandroid's clock sync leaves it there "
            "until Back to real time or a snapshot load.",
            check=_time_check,
        ),
        DeviceAction(
            "time.reset", "Back to real time", "Time", (), _time_reset,
            emulator_only=False,
            help="Automatic time back on as before, then the clock synced to "
            "the host.",
        ),
        DeviceAction(
            "power.battery", "Battery level", "Power",
            (Param("level", "Level (%)", "int", placeholder="15", minimum=0,
                   maximum=100),),
            _power_battery,
            help="The battery reports this charge level.",
        ),
        DeviceAction(
            "power.charging", "Charging", "Power", (_ON,), _power_charging,
            help="On: charger plugged in and charging. Off: unplugged, "
            "discharging.",
        ),
        DeviceAction(
            "power.ac", "Charger plugged in", "Power", (_ON,), _power_ac,
            help="Only the charger connection (the charging state stays).",
        ),
        DeviceAction(
            "net.wifi", "Wi-Fi", "Network", (_ON,), _toggle("wifi", "Wi-Fi"),
            emulator_only=False, help="Wi-Fi on or off.",
        ),
        DeviceAction(
            "net.data", "Mobile data", "Network", (_ON,),
            _toggle("data", "Mobile data"),
            emulator_only=False, help="Mobile data on or off.",
        ),
        DeviceAction(
            "net.airplane", "Airplane mode", "Network", (_ON,), _net_airplane,
            emulator_only=False, help="Airplane mode on or off.",
        ),
        DeviceAction(
            "net.profile", "Network speed and latency", "Network",
            (Param("profile", "Profile", "choice", default="full",
                   choices=tuple((k, v[0]) for k, v in NETWORK_PROFILES.items())),),
            _net_profile,
            help="The emulator's network speed and latency.",
        ),
    )
}  # fmt: skip


def list_actions() -> list[DeviceAction]:
    """Every action, in registry (form) order."""
    return list(ACTIONS.values())


def get_action(action_id: str) -> DeviceAction:
    """The action ``action_id``.

    Raises:
        ActionError: No such action.
    """
    action = ACTIONS.get(action_id)
    if action is None:
        raise ActionError(f"Unknown action: {action_id}")
    return action


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------


def _timeline_line(
    action_id: str,
    serial: str,
    summary: str,
    data: dict[str, Any],
    *,
    actor: str,
    ok: bool,
) -> None:
    """One ``action`` line on the session timeline (never raises)."""
    try:
        from sandroid.core.timeline import get_timeline

        get_timeline().emit(
            TIMELINE_SRC,
            action_id.replace(".", "-"),
            summary=summary,
            data=data,
            dev=serial,
            actor=actor,
            level="info" if ok else "warn",
        )
    except Exception:
        logger.debug("timeline: action line failed", exc_info=True)


def run_action(
    action_id: str,
    serial: str | None,
    params: Mapping[str, Any] | None = None,
    *,
    actor: str = "user",
) -> ActionResult:
    """Validate and run one action on ``serial``; write its timeline line.

    Blocks on adb: call it from a worker thread, never the UI thread.
    Refusals (unknown action, invalid parameters, an emulator-only action
    on a physical device, no device) send nothing and write no line.

    Args:
        action_id: Registry id (``sms.receive``).
        serial: The device; every adb call is pinned to it.
        params: Parameter values (form strings or native values).
        actor: Timeline actor (``user``, ``replay``, ``ai``).

    Returns:
        The result; never raises.
    """
    try:
        action = get_action(action_id)
        if not serial:
            raise ActionError("No device selected")
        if action.emulator_only and not is_emulator(serial):
            raise ActionError(
                f"{action.title} works on an emulator only, not on {serial}"
            )
        parsed = action.validate(params)
    except ActionError as exc:
        return ActionResult(action_id, False, str(exc), refused=True)

    dev = _Device(serial, actor)
    try:
        result = action.runner(dev, parsed, action)
    except ActionError as exc:
        return ActionResult(action_id, False, str(exc), refused=True)
    except CommandError as exc:
        result = ActionResult(action_id, False, str(exc))
    except Exception as exc:
        logger.debug("device action %s failed", action_id, exc_info=True)
        result = ActionResult(action_id, False, str(exc) or type(exc).__name__)
    shown = {k: v for k, v in parsed.items() if v is not None}
    summary = (
        result.message if result.ok else f"{action.title} failed: {result.message}"
    )
    _timeline_line(
        action_id,
        serial,
        summary,
        {
            "action": action_id,
            "params": shown,
            "ok": result.ok,
            "commands": dev.commands,
            **result.data,
            **({"job": result.job} if result.job else {}),
        },
        actor=actor,
        ok=result.ok,
    )
    if result.job is not None:
        _launch(result.job)  # after its "started" line, never before
    return result


# ---------------------------------------------------------------------------
# background jobs
# ---------------------------------------------------------------------------


@dataclass
class Job:
    """A running background action (``gps.route``).

    Attributes:
        id: ``job-<n>``.
        action: The action id.
        serial: The device.
        title: Plain words (``GPS route Berlin walk ...``).
        started: Host time it started.
        status: ``running`` | ``finished`` | ``stopped`` | ``failed``.
        progress: Plain words (``fix 12 of 300``).
        actor: Timeline actor of its lines.
    """

    id: str
    action: str
    serial: str
    title: str
    started: float
    stop: threading.Event = field(default_factory=threading.Event, repr=False)
    status: str = "running"
    progress: str = ""
    actor: str = "user"
    thread: threading.Thread | None = field(default=None, repr=False)


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()
_JOB_IDS = itertools.count(1)


def _start_job(
    action: DeviceAction, dev: _Device, title: str, work: Callable[[Job], None]
) -> Job:
    """Register a background job; :func:`run_action` starts its thread
    once the action's timeline line is written.
    """
    job = Job(
        f"job-{next(_JOB_IDS)}", action.id, dev.serial, title, time.time(),
        actor=dev.actor,
    )  # fmt: skip

    def run() -> None:
        try:
            work(job)
        except Exception:
            logger.debug("device action job %s failed", job.id, exc_info=True)
            job.status = "failed"
        finally:
            with _JOBS_LOCK:
                _JOBS.pop(job.id, None)

    job.thread = threading.Thread(
        target=run, name=f"device-action-{job.id}", daemon=True
    )
    with _JOBS_LOCK:
        _JOBS[job.id] = job
    return job


def _launch(job_id: str) -> None:
    """Start the thread of a job registered by :func:`_start_job`."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is not None and job.thread is not None and job.thread.ident is None:
        job.thread.start()


def running_jobs(serial: str | None = None) -> list[Job]:
    """Background jobs still running (of ``serial``, or all), oldest first."""
    with _JOBS_LOCK:
        jobs = list(_JOBS.values())
    return [j for j in jobs if serial is None or j.serial == serial]


def stop_job(job_id: str, wait: float | None = 5.0) -> bool:
    """Ask job ``job_id`` to stop (and wait up to ``wait`` s); False: unknown."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return False
    job.stop.set()
    if wait and job.thread is not None and job.thread is not threading.current_thread():
        job.thread.join(wait)
    return True


def stop_jobs(serial: str | None = None, action: str | None = None) -> int:
    """Stop the running jobs of ``serial`` (and ``action``); how many."""
    jobs = [j for j in running_jobs(serial) if action is None or j.action == action]
    for job in jobs:
        stop_job(job.id)
    return len(jobs)


__all__ = [
    "ACTIONS",
    "NETWORK_PROFILES",
    "ROUTE_PRESETS",
    "ActionError",
    "ActionResult",
    "CommandError",
    "DeviceAction",
    "Job",
    "Param",
    "format_delta",
    "get_action",
    "is_emulator",
    "list_actions",
    "parse_points",
    "route_fixes",
    "run_action",
    "running_jobs",
    "stop_job",
    "stop_jobs",
]
