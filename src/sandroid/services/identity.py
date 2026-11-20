"""Identity profiles: distinctive fake canary values seeded on an emulator.

An identity profile is a named set of fake values (Android ID, advertising
ID, device name, phone number, GPS fix, contacts, SMS, call log, ...) that
carry a per-profile random ``token``. Once seeded, a privacy scan can find
them in traffic and files (:mod:`sandroid.core.privacy_markers`) and
attribute every hit to the value that leaked.

The module has four layers:

* **Profile model** -- a TOML file per profile in the library
  (``$XDG_CONFIG_HOME/sandroid/profiles/<id>.toml``): parsing, templates,
  validation, the built-in generator, import/export.
* **Kind registry** (:data:`REGISTRY`) -- what the code knows per value kind:
  provider, restart class, app permission, mechanism and read-back. It is
  not user-editable.
* **Apply pipeline** (:class:`IdentityService`) -- P0 one batched preflight
  read, P1 plan, P2 the caller decides about a restart, P3 live steps, P4
  Google Play services steps, P5 one framework restart window, P6 verify
  (the same batched read), P7 freeze the ground truth into the session.
  Idempotent and resumable (a marker file on the device survives a crash in
  the restart window). Every device call runs on the caller's thread: call
  it from a worker, never from the UI thread.
* **Markers** -- the applied profile as :class:`Marker` objects for the
  privacy scanner, with change listeners.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shlex
import tempfile
import threading
import time
import tomllib
import uuid as uuidlib
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from glob import escape as glob_escape
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import tomli_w

from sandroid.core.privacy_markers import Marker
from sandroid.services import identity_sim

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

FORMAT = "sandroid-identity"
#: Profile schema this code writes; a newer one is refused on load/import.
SCHEMA = 1
#: Validators: always ``fullmatch`` (``^...$`` with ``match`` lets a trailing
#: newline through).
TOKEN_RE = re.compile(r"[0-9a-f]{8,32}")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PROFILES_DIR_ENV = "SDROID_PROFILES_DIR"

STATUSES = ("pending", "applied", "verified", "failed", "hook-only", "skipped")
#: Restart classes, cheapest first.
RESTARTS = ("none", "gms", "framework")
_RESTART_RANK = {name: i for i, name in enumerate(RESTARTS)}

DEVICE_DIR = "/data/local/tmp/sandroid"
STAGE_DIR = f"{DEVICE_DIR}/identity"
#: Sourceable copy of zygote's environment: ``content``, ``abx2xml`` and
#: ``xml2abx`` do nothing under adb root without it, and zygote is gone while
#: the framework is stopped, so it is captured once into a file.
ZYGOTE_ENV_FILE = f"{DEVICE_DIR}/zygote.env"
ZYGOTE_PREFIX = f"[ -r {ZYGOTE_ENV_FILE} ] && . {ZYGOTE_ENV_FILE}"
#: Present on the device while a framework restart window is open.
RESTART_MARKER = f"{DEVICE_DIR}/identity.restart"
#: What Sandroid applied on this device (JSON, see :func:`applied_record`).
#: It outlives the TUI process and travels with emulator snapshots.
APPLIED_FILE = f"{DEVICE_DIR}/identity.applied"
APPLIED_FORMAT = "sandroid-identity-applied"
#: Changes on every boot: a record from another boot does not prove that the
#: volatile values (and the emulator console ones) are still there.
BOOT_ID_FILE = "/proc/sys/kernel/random/boot_id"
#: Owner of :data:`APPLIED_FILE` (shell, so a non-root adbd can read it).
APPLIED_OWNER = "2000:2000"
#: The record read before an app start gives up after this many seconds.
RECORD_READ_TIMEOUT_S = 3.0
#: A failed background read of the record is tried again after this long.
HYDRATE_RETRY_S = 30.0
SSAID_FILE = "/data/system/users/0/settings_ssaid.xml"
PACKAGES_XML = "/data/system/packages.xml"
GMS = "com.google.android.gms"
GAID_DIR = f"/data/data/{GMS}/shared_prefs"
GAID_FILE = f"{GAID_DIR}/adid_settings.xml"
APPSET_FILE = f"/data/data/{GMS}/files/appset/shared/pvids.pb"
PREFLIGHT_TAG = "@@identity-preflight@@"
NEEDS_RESTART = "needs a framework restart"
#: The framework restart was refused (an app start holds the lifecycle lock).
NOT_RESTARTED = "not restarted"
#: A SIM value the running emulator did not start with.
NEEDS_EMULATOR_START = "set when the emulator starts; restart it from the Devices hub"
#: A SIM value the emulator started with but this Android version gives no
#: read-back for.
SIM_NOT_READ = "set when the emulator started; not read back on this Android version"
SIM_NOT_READ_ROOT = "set when the emulator started; not read back without root"
#: The emulator started with it, airplane mode is on: the guest reads the
#: SIM card when airplane mode is turned off (left on: often deliberate).
SIM_AIRPLANE_ON = "the device reads it when airplane mode is turned off"
#: The airplane-mode toggle got no answer (adb timeout, dropped link): the
#: next apply tries once more.
SIM_TOGGLE_RETRY = "airplane mode got no answer; the next apply tries again"
#: The toggle result that counts as no answer from the device.
_NO_ANSWER = "no answer"
_TOGGLE_INTERRUPTED = "the toggle was interrupted"
SIM_TOGGLE_REFUSED = (
    "set when the emulator started; airplane mode could not be switched "
    "without root, so the device may still show the old SIM"
)
#: Seconds between SIM re-reads after the airplane-mode toggle (at most
#: :data:`SIM_WAIT_DEADLINE_S` in all).
SIM_WAITS_S = (2.0, 2.0, 3.0, 3.0, 5.0, 5.0, 5.0, 5.0)
SIM_WAIT_DEADLINE_S = 30.0
#: ``service call iphonesubinfo`` transaction codes per API level (measured;
#: they change between Android versions): IMSI, ICCID, MSISDN of the
#: default subscription.
IPHONESUBINFO_CODES: dict[int, tuple[tuple[str, int], ...]] = {
    35: (("imsi", 8), ("iccid", 12), ("msisdn", 15)),
}
NEEDS_RESTART_AT_START = (
    "the identity profile needs an Android framework restart;"
    " start the app again to confirm it"
)
NOT_ROOT = "adbd is not root"
NO_RESETPROP = "resetprop (Magisk) missing"
#: Failures no apply can fix on this device as it is (no step is planned).
STRUCTURAL = (NOT_ROOT, NO_RESETPROP)
PROVIDER_DOWN = "its content provider did not answer (not up yet)"
#: Waits before re-reading lists whose provider was not up (about 10 s).
PROVIDER_WAITS_S = (1.0, 1.5, 2.0, 2.5, 3.0)
#: The whole provider wait never takes longer than this (a framework restart
#: can leave the device overloaded; adb calls then hang, see the light probe).
PROVIDER_WAIT_DEADLINE_S = 20.0
#: One light provider probe (lists only) gives up after this many seconds.
PROVIDER_PROBE_TIMEOUT_S = 8.0
_OK = "sandroid-identity-ok"

#: Framework restart: wait this long for a new system_server.
RESTART_TIMEOUT_S = 180.0
RESTART_POLL_S = 2.0
#: ``ensure_applied``: start a framework window only with this much of the
#: budget left (a restart usually takes 20 to 60 s; the wait is capped to
#: what is left).
ENSURE_WINDOW_MIN_S = 90.0
#: Why a framework value stays pending when the budget ran out.
OUT_OF_TIME = "not applied: device preparation ran out of time"

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_UUID_BYTES_RE = re.compile(
    rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_LOCALE_RE = re.compile(r"[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PHONE_RE = re.compile(r"\+?[0-9]{3,15}")
_COORD_RE = re.compile(r"-?[0-9]{1,3}(\.[0-9]+)?")
#: ``content insert --bind duration:i:`` takes a Java int.
_INT_MAX = 2**31 - 1


def _ascii_digits(text: str) -> bool:
    """Only ``0-9`` (``str.isdigit`` also accepts other scripts' digits)."""
    return bool(text) and text.isascii() and text.isdigit()


def _call_duration(value: Any) -> int | None:
    """A call-log ``duration`` as seconds (0 when absent), None when invalid."""
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str) and _ascii_digits(value):
        seconds = int(value)
    else:
        return None
    return seconds if 0 <= seconds <= _INT_MAX else None


class ProfileError(ValueError):
    """A profile file cannot be read, imported or saved."""


class IdentityApplyError(RuntimeError):
    """Applying a profile failed (raised by a pre-spawn ``apply``)."""


# ---------------------------------------------------------------------------
# kind registry (code, not user-editable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KindSpec:
    """What the code knows about one value kind.

    Attributes:
        kind: Registry key.
        label: Human label.
        tag: Short display tag for markers.
        marker: :data:`privacy_markers.KINDS` entry, ``None`` = not markable.
        providers: Allowed providers, the default first; ``("hook",)`` means
            the value is only recorded (a Frida hook would present it).
        restart: ``none`` | ``gms`` (force-stop Play services) | ``framework``
            (``stop``/``start``: every app stops).
        permission: Android permission an app needs to read the value.
        mechanism: How the value is applied natively.
        readback: How the value is read back.
        verify: ``strict`` (mismatch = failed), ``soft`` (match = verified,
            else it stays applied) or ``none`` (no read-back).
        needs_root: The native mechanism needs adbd as root.
        needs_emulator: The mechanism is an emulator console command.
        derives: Allowed ``derive`` methods.
        volatile: The device forgets the value on reboot / radio events.
        emulator_hook_only: Why the native mechanism does not hold on an
            emulator (there the value is hook-only, like a ``("hook",)``
            kind), or empty.
        emulator_mechanism: How the value is set on an emulator when that
            differs: non-empty means the emulator's SIM card profile carries
            it from the emulator's start (:mod:`identity_sim`).
        device_hook_only: Why there is no native mechanism off the emulator
            (there the value is hook-only), or empty.
        hook_reason: Why a hook-only kind (``("hook",)``) has no native
            mechanism on an emulator, or empty (``device_hook_only`` says
            it for a real device).
    """

    kind: str
    label: str
    tag: str
    marker: str | None
    providers: tuple[str, ...] = ("native",)
    restart: str = "none"
    permission: str = ""
    mechanism: str = ""
    readback: str = ""
    verify: str = "strict"
    needs_root: bool = False
    needs_emulator: bool = False
    derives: tuple[str, ...] = ()
    volatile: bool = False
    emulator_hook_only: str = ""
    emulator_mechanism: str = ""
    device_hook_only: str = ""
    hook_reason: str = ""


#: The emulator's radio reports the SIM operator name of the carrier its
#: MCC/MNC resolves to (``gsm.sim.operator.alpha``), not the SIM's own.
EMULATOR_SIM_OPERATOR = "the emulator takes the SIM operator name from its carrier"
#: Appended when the network operator name carries the value.
NETWORK_OPERATOR_CARRIES = "the network operator name carries it"
#: How SIM values reach an emulator (:mod:`identity_sim`).
SIM_MECHANISM = "set when the emulator starts (its SIM card profile)"
PHONE_MECHANISM = (
    f"{SIM_MECHANISM}, else adb emu phonenumber if a restart cannot (11 digits at most)"
)


def _spec(*args: Any, **kw: Any) -> tuple[str, KindSpec]:
    spec = KindSpec(*args, **kw)
    return spec.kind, spec


REGISTRY: dict[str, KindSpec] = dict(
    [
        _spec(
            "android_id",
            "Android ID",
            "AndroidID",
            "hex_id",
            ("native", "hook"),
            "framework",
            "",
            "edit settings_ssaid.xml (ABX) in a framework restart window",
            "abx2xml settings_ssaid.xml",
            needs_root=True,
            derives=("ssaid",),
        ),
        _spec(
            "gaid",
            "Advertising ID",
            "AdID",
            "uuid",
            ("native", "hook"),
            "gms",
            "",
            "adid_key in GMS adid_settings.xml",
            "cat adid_settings.xml",
            needs_root=True,
            derives=("uuid",),
        ),
        _spec(
            "app_set_id",
            "App Set ID",
            "AppSetID",
            "uuid",
            ("native", "hook"),
            "gms",
            "",
            "replace the UUIDs in GMS appset/shared/pvids.pb",
            "base64 pvids.pb",
            needs_root=True,
            derives=("uuid",),
        ),
        _spec(
            "device_name",
            "Device name",
            "DevName",
            "text",
            ("native", "hook"),
            "none",
            "BLUETOOTH_CONNECT",
            "settings put global device_name",
            "settings get global",
        ),
        _spec(
            "phone_number",
            "Phone number",
            "Phone",
            "phone",
            ("native", "hook"),
            "none",
            "READ_PHONE_NUMBERS",
            PHONE_MECHANISM,
            "service call iphonesubinfo (line 1 number)",
            verify="soft",
            needs_emulator=True,
            emulator_mechanism=PHONE_MECHANISM,
        ),
        _spec(
            "gps",
            "GPS position",
            "GPS",
            "latitude",
            ("native", "hook"),
            "none",
            "ACCESS_FINE_LOCATION",
            "adb emu geo fix <lon> <lat> <alt>",
            "dumpsys location (after an app's GPS session)",
            verify="soft",
            needs_emulator=True,
        ),
        _spec(
            "timezone",
            "Time zone",
            "TZ",
            None,
            ("native",),
            "none",
            "",
            "auto_time_zone 0; cmd alarm set-timezone",
            "getprop persist.sys.timezone",
        ),
        _spec(
            "locale",
            "Locale",
            "Locale",
            None,
            ("native",),
            "framework",
            "",
            "setprop persist.sys.locale (zygote restart)",
            "getprop persist.sys.locale",
            needs_root=True,
        ),
        _spec(
            "sim_operator",
            "SIM operator name",
            "SimOp",
            "text",
            ("native", "hook"),
            "none",
            "READ_PHONE_STATE",
            "setprop gsm.sim.operator.alpha",
            "getprop",
            needs_root=True,
            volatile=True,
            emulator_hook_only=EMULATOR_SIM_OPERATOR,
        ),
        _spec(
            "sim_mccmnc",
            "SIM operator MCC/MNC",
            "MCCMNC",
            None,
            ("native",),
            "none",
            "",
            "setprop gsm.sim.operator.numeric",
            "getprop",
            needs_root=True,
            volatile=True,
            emulator_mechanism=SIM_MECHANISM,
        ),
        _spec(
            "build_model",
            "Device model",
            "Model",
            "text",
            ("native", "hook"),
            "framework",
            "",
            "resetprop ro.product.model (framework restart)",
            "getprop ro.product.model",
            needs_root=True,
            volatile=True,
        ),
        _spec(
            "imei",
            "IMEI",
            "IMEI",
            "text",
            ("hook",),
            permission="READ_PRIVILEGED_PHONE_STATE",
            hook_reason="the emulator's modem reports a fixed IMEI",
            device_hook_only="Android lets no tool change a phone's IMEI",
        ),
        _spec(
            "imsi",
            "IMSI",
            "IMSI",
            "text",
            ("native", "hook"),
            "none",
            "READ_PRIVILEGED_PHONE_STATE",
            SIM_MECHANISM,
            "service call iphonesubinfo (subscriber id)",
            needs_root=True,
            emulator_mechanism=SIM_MECHANISM,
            device_hook_only="a real SIM card cannot be changed",
        ),
        _spec(
            "iccid",
            "ICCID",
            "ICCID",
            "text",
            ("native", "hook"),
            "none",
            "READ_PRIVILEGED_PHONE_STATE",
            SIM_MECHANISM,
            "service call iphonesubinfo (SIM serial number)",
            needs_root=True,
            emulator_mechanism=SIM_MECHANISM,
            device_hook_only="a real SIM card cannot be changed",
        ),
        _spec(
            "serial",
            "Serial number",
            "Serial",
            "text",
            ("hook",),
            permission="READ_PRIVILEGED_PHONE_STATE",
        ),
        _spec(
            "account",
            "Account e-mail",
            "Account",
            "email",
            ("hook",),
            permission="GET_ACCOUNTS",
        ),
        _spec("clipboard", "Clipboard text", "Clip", "text", ("hook",)),
    ]
)


@dataclass(frozen=True)
class ListSpec:
    """A list section (``[[contacts]]``, ``[[sms]]``, ``[[calls]]``)."""

    name: str
    label: str
    tag: str
    permission: str
    fields: tuple[str, ...]  # string fields rendered as templates
    token_field: str  # must carry the token: the idempotency key on device
    mechanism: str


LISTS: dict[str, ListSpec] = {
    "contacts": ListSpec(
        "contacts",
        "Contacts",
        "Contact",
        "READ_CONTACTS",
        ("name", "phone", "email"),
        "name",
        "content insert raw_contacts + data (name, phone_v2, email_v2)",
    ),
    "sms": ListSpec(
        "sms",
        "SMS",
        "SMS",
        "READ_SMS",
        ("address", "body"),
        "body",
        "content insert content://sms/inbox|sent",
    ),
    "calls": ListSpec(
        "calls",
        "Call log",
        "Call",
        "READ_CALL_LOG",
        ("number", "name"),
        "name",
        "content insert content://call_log/calls",
    ),
}

_CONTACT_MIME = {
    "name": "vnd.android.cursor.item/name",
    "phone": "vnd.android.cursor.item/phone_v2",
    "email": "vnd.android.cursor.item/email_v2",
}
_CALL_TYPES = {"incoming": 1, "outgoing": 2, "missed": 3}
_SMS_TYPES = {"inbox": 1, "sent": 2}

# ---------------------------------------------------------------------------
# profile model
# ---------------------------------------------------------------------------

_VALUE_KEYS = (
    "kind",
    "label",
    "value",
    "template",
    "derive",
    "scope",
    "provider",
    "enabled",
)


@dataclass
class ValueSpec:
    """One ``[values.<id>]`` table.

    Exactly one of ``value``, ``template`` and ``derive`` is set.
    """

    id: str
    kind: str = ""
    value: str | None = None
    template: str | None = None
    derive: str | None = None
    scope: str = "signer"
    provider: str = ""
    enabled: bool = True
    label: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind:
            self.kind = self.id

    @property
    def spec(self) -> KindSpec | None:
        """The registry row of :attr:`kind` (``None`` if unknown)."""
        return REGISTRY.get(self.kind)

    @property
    def effective_provider(self) -> str:
        """``provider`` or the kind's default."""
        if self.provider:
            return self.provider
        spec = self.spec
        return spec.providers[0] if spec else "native"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.kind != self.id:
            out["kind"] = self.kind
        if self.label:
            out["label"] = self.label
        for key in ("value", "template", "derive"):
            if getattr(self, key) is not None:
                out[key] = getattr(self, key)
        if self.derive == "ssaid":
            out["scope"] = self.scope
        if self.provider:
            out["provider"] = self.provider
        if not self.enabled:
            out["enabled"] = False
        out.update(self.extra)
        return out

    @classmethod
    def from_dict(cls, vid: str, data: dict[str, Any]) -> ValueSpec:
        def text(key: str) -> str | None:
            raw = data.get(key)
            return None if raw is None else str(raw)

        return cls(
            id=vid,
            kind=str(data.get("kind") or vid),
            value=text("value"),
            template=text("template"),
            derive=text("derive"),
            scope=str(data.get("scope") or "signer"),
            provider=str(data.get("provider") or ""),
            enabled=bool(data.get("enabled", True)),
            label=str(data.get("label") or ""),
            extra={k: v for k, v in data.items() if k not in _VALUE_KEYS},
        )


@dataclass
class Profile:
    """An identity profile (one TOML file in the library)."""

    id: str
    name: str = ""
    token: str = ""
    seed: str = ""  # "hex:<64 hex>"
    revision: int = 0
    created: datetime | None = None
    preset: str = ""
    notes: str = ""
    values: dict[str, ValueSpec] = field(default_factory=dict)
    contacts: list[dict[str, Any]] = field(default_factory=list)
    sms: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    retired_tokens: list[str] = field(default_factory=list)
    schema: int = SCHEMA
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def seed_bytes(self) -> bytes:
        """The seed as bytes (empty when missing or malformed)."""
        raw = self.seed[4:] if self.seed.startswith("hex:") else ""
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""

    def lists(self) -> dict[str, list[dict[str, Any]]]:
        """``{"contacts": [...], "sms": [...], "calls": [...]}``."""
        return {"contacts": self.contacts, "sms": self.sms, "calls": self.calls}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "format": FORMAT,
            "schema": self.schema,
            "id": self.id,
            "name": self.name,
            "revision": self.revision,
            "token": self.token,
            "seed": self.seed,
        }
        if self.created is not None:
            out["created"] = self.created
        out["preset"] = self.preset
        out["notes"] = self.notes
        if self.retired_tokens:
            out["retired_tokens"] = list(self.retired_tokens)
        out.update(self.extra)
        out["values"] = {vid: v.to_dict() for vid, v in self.values.items()}
        for name, items in self.lists().items():
            if items:
                out[name] = [dict(item) for item in items]
        return out

    def dumps(self) -> str:
        """The profile as TOML text."""
        return tomli_w.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        """Build a profile from parsed TOML.

        Raises:
            ProfileError: Wrong ``format``, newer ``schema`` or no ``id``.
        """
        if data.get("format") != FORMAT:
            raise ProfileError(f"not a {FORMAT} file (format={data.get('format')!r})")
        schema = data.get("schema")
        if not isinstance(schema, int) or schema < 1:
            raise ProfileError(f"invalid schema {schema!r}")
        if schema > SCHEMA:
            raise ProfileError(
                f"profile schema {schema} is newer than this Sandroid ({SCHEMA})"
            )
        pid = data.get("id")
        if not isinstance(pid, str) or not pid:
            raise ProfileError("profile has no id")
        values_raw = data.get("values") or {}
        if not isinstance(values_raw, dict):
            raise ProfileError("[values] must be a table")
        known = {
            "format",
            "schema",
            "id",
            "name",
            "revision",
            "token",
            "seed",
            "created",
            "preset",
            "notes",
            "values",
            "contacts",
            "sms",
            "calls",
            "retired_tokens",
        }
        created = data.get("created")
        return cls(
            id=pid,
            name=str(data.get("name") or ""),
            token=str(data.get("token") or ""),
            seed=str(data.get("seed") or ""),
            revision=int(data.get("revision") or 0),
            created=created if isinstance(created, datetime) else None,
            preset=str(data.get("preset") or ""),
            notes=str(data.get("notes") or ""),
            values={
                str(vid): ValueSpec.from_dict(
                    str(vid), v if isinstance(v, dict) else {}
                )
                for vid, v in values_raw.items()
            },
            contacts=[
                dict(x) for x in data.get("contacts") or [] if isinstance(x, dict)
            ],
            sms=[dict(x) for x in data.get("sms") or [] if isinstance(x, dict)],
            calls=[dict(x) for x in data.get("calls") or [] if isinstance(x, dict)],
            retired_tokens=[str(t) for t in data.get("retired_tokens") or []],
            schema=schema,
            extra={k: v for k, v in data.items() if k not in known},
        )

    @classmethod
    def loads(cls, text: str) -> Profile:
        """Parse TOML text (raises :class:`ProfileError`)."""
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ProfileError(f"invalid TOML: {exc}") from exc
        return cls.from_dict(data)


# ---------------------------------------------------------------------------
# templates and derivation
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\{\{|\}\}|\{([a-z_]+)(?::(\d+))?\}")


class TemplateError(ValueError):
    """A template has an unknown placeholder or an unbalanced brace."""


class _Stream:
    """Deterministic byte stream ``HMAC-SHA256(seed, key#n)``."""

    def __init__(self, seed: bytes, key: str) -> None:
        self._seed, self._key, self._n, self._buf = seed, key, 0, b""

    def byte(self) -> int:
        if not self._buf:
            self._buf = hmac.new(
                self._seed, f"{self._key}#{self._n}".encode(), hashlib.sha256
            ).digest()
            self._n += 1
        value, self._buf = self._buf[0], self._buf[1:]
        return value

    def digits(self, n: int) -> str:
        out = []
        while len(out) < n:
            b = self.byte()
            if b < 250:
                out.append(str(b % 10))
        return "".join(out)

    def hex(self, n: int) -> str:
        return "".join(f"{self.byte() & 0xF:x}" for _ in range(n))


def luhn_check_digit(digits: str) -> str:
    """The Luhn check digit to append to ``digits`` (non-digits ignored)."""
    total = 0
    for i, ch in enumerate(reversed([c for c in digits if c.isdigit()])):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_ok(number: str) -> bool:
    """True when the last digit of ``number`` is its Luhn check digit."""
    return (
        len(number) > 1
        and number.isdigit()
        and luhn_check_digit(number[:-1]) == number[-1]
    )


def token_uuid(token: str, seed: bytes, key: str) -> str:
    """A version-4 UUID that starts with ``token[:8]`` (rest from the seed)."""
    rest = hmac.new(seed, f"uuid|{key}".encode(), hashlib.sha256).hexdigest()
    h = list((token[:8] + rest)[:32])
    h[12] = "4"
    h[16] = "89ab"[int(h[16], 16) & 3]
    s = "".join(h)
    return f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:]}"


def ssaid_for(token: str, seed: bytes, scope_key: str) -> str:
    """Android ID for one app: ``token[:8]`` + ``HMAC(seed, scope)[:8]``."""
    tail = hmac.new(seed, f"ssaid|{scope_key}".encode(), hashlib.sha256).hexdigest()
    return (token[:8] + tail)[:16]


def render_template(template: str, *, token: str, seed: bytes, key: str) -> str:
    """Render ``{token}``, ``{digits:N}``, ``{hex:N}``, ``{luhn}``, ``{uuid}``.

    ``{luhn}`` is the Luhn digit of all digits rendered before it; ``{{`` and
    ``}}`` are literal braces. The result depends only on ``(template,
    token, seed, key)``.

    Raises:
        TemplateError: Unknown placeholder or a stray brace.
    """
    stream = _Stream(seed, key)
    out: list[str] = []
    pos = 0
    for match in _PLACEHOLDER_RE.finditer(template):
        literal = template[pos : match.start()]
        if "{" in literal or "}" in literal:
            raise TemplateError(f"unbalanced brace in {template!r}")
        out.append(literal)
        pos = match.end()
        whole, name, arg = match.group(0), match.group(1), match.group(2)
        if whole in ("{{", "}}"):
            out.append(whole[0])
            continue
        n = int(arg) if arg else 1
        if n > 64:
            raise TemplateError(f"{whole}: at most 64")
        if name == "token":
            out.append(token)
        elif name == "digits":
            out.append(stream.digits(n))
        elif name == "hex":
            out.append(stream.hex(n))
        elif name == "luhn":
            out.append(luhn_check_digit("".join(out)))
        elif name == "uuid":
            out.append(token_uuid(token, seed, key))
        else:
            raise TemplateError(f"unknown placeholder {whole}")
    tail = template[pos:]
    if "{" in tail or "}" in tail:
        raise TemplateError(f"unbalanced brace in {template!r}")
    out.append(tail)
    return "".join(out)


def render_value(profile: Profile, vs: ValueSpec) -> str | None:
    """The rendered value of ``vs`` (``None`` for a per-app ``derive``).

    Raises:
        TemplateError: For a broken template.
    """
    if vs.value is not None:
        return vs.value
    if vs.template is not None:
        return render_template(
            vs.template, token=profile.token, seed=profile.seed_bytes, key=vs.id
        )
    if vs.derive == "uuid":
        return token_uuid(profile.token, profile.seed_bytes, vs.id)
    return None


def render_lists(profile: Profile) -> dict[str, list[dict[str, Any]]]:
    """Every list item with its string fields rendered (others as is)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for name, items in profile.lists().items():
        spec = LISTS[name]
        rendered = []
        for i, item in enumerate(items):
            row = dict(item)
            for fname in spec.fields:
                if isinstance(row.get(fname), str):
                    row[fname] = render_template(
                        row[fname],
                        token=profile.token,
                        seed=profile.seed_bytes,
                        key=f"{name}.{i}.{fname}",
                    )
            rendered.append(row)
        out[name] = rendered
    return out


def split_gps(value: str) -> tuple[str, str, str]:
    """``"lat, lon[, alt]"`` -> ``(lat, lon, alt)`` (alt defaults to ``"34"``).

    Raises:
        ValueError: Not two or three comma-separated numbers.
    """
    parts = [p.strip() for p in value.split(",")]
    if len(parts) not in (2, 3) or not all(_COORD_RE.fullmatch(p) for p in parts[:2]):
        raise ValueError(f"GPS {value!r} is not 'lat, lon[, alt]'")
    alt = parts[2] if len(parts) == 3 else "34"
    float(alt)
    return parts[0], parts[1], alt


def fingerprint(profile: Profile) -> str:
    """Stable id of the profile's seeded content (16 hex)."""
    try:
        values = {
            vid: [
                vs.kind,
                vs.effective_provider,
                vs.enabled,
                render_value(profile, vs),
                vs.derive,
                vs.scope,
            ]
            for vid, vs in sorted(profile.values.items())
        }
        lists = render_lists(profile)
    except (TemplateError, ValueError):
        values, lists = {"_raw": profile.to_dict()["values"]}, {}
    blob = json.dumps(
        {
            "id": profile.id,
            "token": profile.token,
            "seed": profile.seed,
            "values": values,
            "lists": lists,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Issue:
    """One validation finding; ``error`` blocks apply, ``warning`` does not."""

    severity: str  # "error" | "warning"
    path: str  # "values.gaid", "contacts.0.phone", "token", ...
    message: str


def _mccmnc_of(profile: Profile, rendered: dict[str, str | None]) -> str:
    for vid, vs in profile.values.items():
        if vs.kind == "sim_mccmnc" and rendered.get(vid):
            return str(rendered[vid])
    if profile.preset:
        try:
            from sandroid.services.device_settings_service import COUNTRY_PRESETS

            preset = COUNTRY_PRESETS.get(profile.preset)
            if preset is not None:
                return preset.telephony_mnc
        except Exception:  # pragma: no cover - defensive
            pass
    return ""


def _check_value(
    kind: str, value: str, provider: str, mccmnc: str
) -> list[tuple[str, str]]:
    """``(severity, message)`` findings for one rendered value of ``kind``."""
    out: list[tuple[str, str]] = []
    if kind == "android_id":
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            out.append(("error", "Android ID must be 16 lower-case hex digits"))
    elif kind in ("gaid", "app_set_id"):
        if not _UUID_RE.fullmatch(value):
            out.append(("error", "must be a UUID (8-4-4-4-12 hex)"))
        elif uuidlib.UUID(value).int == 0:
            out.append(("error", "the nil UUID means 'no ID' to apps"))
    elif kind == "imei":
        if not (len(value) == 15 and _ascii_digits(value) and luhn_ok(value)):
            out.append(("error", "IMEI must be 15 digits with a valid Luhn digit"))
    elif kind == "iccid":
        if not (
            _ascii_digits(value)
            and len(value) in (19, 20)
            and value.startswith("89")
            and luhn_ok(value)
        ):
            out.append(("error", "ICCID must be 19-20 digits, start with 89, Luhn"))
    elif kind == "imsi":
        if not (_ascii_digits(value) and 14 <= len(value) <= 15):
            out.append(("error", "IMSI must be 14-15 digits"))
        elif mccmnc and not value.startswith(mccmnc):
            out.append(("error", f"IMSI must start with the SIM MCC/MNC {mccmnc}"))
    elif kind == "sim_mccmnc":
        if not (_ascii_digits(value) and len(value) in (5, 6)):
            out.append(("error", "MCC/MNC must be 5-6 digits"))
    elif kind == "phone_number":
        if not _PHONE_RE.fullmatch(value):
            out.append(("error", "phone number must be digits (optional '+')"))
    elif kind == "gps":
        try:
            lat, lon, _alt = split_gps(value)
        except ValueError as exc:
            out.append(("error", str(exc)))
        else:
            if not -90 <= float(lat) <= 90:
                out.append(("error", "latitude must be within ±90"))
            if not -180 <= float(lon) <= 180:
                out.append(("error", "longitude must be within ±180"))
            if any(len(c.partition(".")[2]) < 6 for c in (lat, lon)):
                out.append(("warning", "fewer than 6 decimals: weak marker"))
    elif kind == "timezone":
        try:
            ZoneInfo(value)
        except Exception:
            out.append(("error", f"unknown time zone {value!r}"))
    elif kind == "locale":
        if not _LOCALE_RE.fullmatch(value):
            out.append(("error", "locale must be BCP-47 like 'de-DE'"))
    elif kind == "account":
        if not _EMAIL_RE.fullmatch(value):
            out.append(("error", "not an e-mail address"))
    elif kind in ("device_name", "sim_operator", "build_model"):
        if not value.strip():
            out.append(("error", "must not be empty"))
        elif len(value) > 64:
            out.append(("error", "at most 64 characters"))
    return out


def _norm_marker(m: Marker) -> list[str]:
    forms = [m.value.casefold()]
    if m.kind == "phone":
        forms.append("".join(c for c in m.value if c.isdigit()))
    return forms


def validate(profile: Profile) -> list[Issue]:
    """Every problem of ``profile``; errors block apply, drafts may be saved."""
    issues: list[Issue] = []

    def add(sev: str, path: str, msg: str) -> None:
        issues.append(Issue(sev, path, msg))

    if not ID_RE.fullmatch(profile.id):
        add("error", "id", "id must be lower-case letters, digits, '.', '_', '-'")
    if not TOKEN_RE.fullmatch(profile.token):
        add("error", "token", "token must be 8-32 lower-case hex digits")
    if len(profile.seed_bytes) != 32:
        add("error", "seed", "seed must be 'hex:' + 32 bytes")
    if not profile.name.strip():
        add("warning", "name", "profile has no name")
    if issues and any(i.severity == "error" for i in issues):
        return issues  # templates need a token and a seed
    rendered: dict[str, str | None] = {}
    for vid, vs in profile.values.items():
        path = f"values.{vid}"
        spec = vs.spec
        if spec is None:
            add("error", path, f"unknown kind {vs.kind!r}")
            continue
        sources = [k for k in ("value", "template", "derive") if getattr(vs, k)]
        if len(sources) != 1:
            add("error", path, "exactly one of value, template, derive")
            continue
        if vs.provider and vs.provider not in spec.providers:
            allowed = ", ".join(spec.providers)
            add("error", path, f"provider {vs.provider!r} not allowed ({allowed})")
        if vs.derive and vs.derive not in spec.derives:
            add("error", path, f"derive {vs.derive!r} not supported for {vs.kind}")
        if vs.derive == "ssaid" and vs.scope not in ("signer", "package"):
            add("error", path, "scope must be 'signer' or 'package'")
        try:
            rendered[vid] = render_value(profile, vs)
        except TemplateError as exc:
            add("error", path, str(exc))
    mccmnc = _mccmnc_of(profile, rendered)
    for vid, value in rendered.items():
        vs = profile.values[vid]
        if value is None or not vs.enabled:
            continue
        for sev, msg in _check_value(vs.kind, value, vs.effective_provider, mccmnc):
            add(sev, f"values.{vid}", msg)
        if vs.kind == "imsi" and vs.effective_provider == "native" and not mccmnc:
            # A warning only: the emulator then keeps its own SIM.
            add(
                "warning",
                f"values.{vid}",
                "the IMSI needs the SIM MCC/MNC: add a SIM operator MCC/MNC "
                "value or a country preset",
            )
        if (
            vs.kind == "phone_number"
            and vs.effective_provider == "native"
            and _PHONE_RE.fullmatch(value)
        ):
            cc = CALLING_CODES.get(profile.preset, "")
            digits, international = identity_sim.msisdn_digits(value, cc)
            if international and len(digits) > 15:
                add(
                    "error",
                    f"values.{vid}",
                    "with its country code the number has more than 15 digits",
                )
        spec = vs.spec
        if (
            spec is not None
            and spec.marker in ("text", "email")
            and not value.isdigit()
            and profile.token not in value
        ):
            add("warning", f"values.{vid}", "no {token}: hits may be coincidental")
    try:
        lists = render_lists(profile)
    except TemplateError as exc:
        add("error", "lists", str(exc))
        lists = {}
    for name, items in lists.items():
        spec_l = LISTS[name]
        for i, item in enumerate(items):
            path = f"{name}.{i}"
            key_val = item.get(spec_l.token_field)
            if not isinstance(key_val, str) or profile.token not in key_val:
                add(
                    "error",
                    f"{path}.{spec_l.token_field}",
                    "must contain {token} (finds the row on the device)",
                )
            for fname in ("phone", "address", "number"):
                val = item.get(fname)
                if fname in spec_l.fields and val and not _PHONE_RE.fullmatch(str(val)):
                    add("error", f"{path}.{fname}", "phone must be digits (opt. '+')")
            email = item.get("email")
            if email and not _EMAIL_RE.fullmatch(str(email)):
                add("error", f"{path}.email", "not an e-mail address")
            if name == "sms" and str(item.get("box", "inbox")) not in _SMS_TYPES:
                add("error", f"{path}.box", "box must be inbox or sent")
            if name == "calls" and str(item.get("type", "incoming")) not in _CALL_TYPES:
                add("error", f"{path}.type", "type must be incoming, outgoing, missed")
            if name == "calls" and _call_duration(item.get("duration")) is None:
                add(
                    "error",
                    f"{path}.duration",
                    "duration must be whole seconds (0 or more)",
                )
            if name in ("sms", "calls") and item.get("date") is not None:
                try:
                    _resolve_date(item["date"], 0, datetime.now(UTC))
                except ValueError as exc:
                    add("error", f"{path}.date", str(exc))
    if any(i.severity == "error" for i in issues):
        return issues
    # Markers: distinct, and none inside another (the scanner folds case).
    markers = markers_for(profile, {}, dedupe=False)
    norm = [(m, _norm_marker(m)) for m in markers]
    for i, (a, fa) in enumerate(norm):
        for b, fb in norm[i + 1 :]:
            if a.group and a.group == b.group:
                continue
            clash = next(
                ((x, y) for x in fa for y in fb if x and y and (x in y or y in x)),
                None,
            )
            if clash:
                same = clash[0] == clash[1]
                what = "the same value as" if same else "a substring clash with"
                add("error", _marker_path(a.id), f"{what} {b.id}")
    return issues


def _marker_path(mid: str) -> str:
    return mid if mid.split(".")[0] in LISTS else f"values.{mid.split('.')[0]}"


def _resolve_date(raw: Any, index: int, now: datetime) -> datetime:
    """``raw`` (datetime, ISO text, ``"-3d"``/``"-2h"``/``"-30m"``, None)."""
    if raw is None:
        return now - timedelta(days=index + 1, hours=index * 3)
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    text = str(raw).strip()
    match = re.fullmatch(r"-(\d+)([dhm])", text)
    if match:
        unit = {"d": "days", "h": "hours", "m": "minutes"}[match.group(2)]
        return now - timedelta(**{unit: int(match.group(1))})
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"date {text!r}: ISO time or -Nd/-Nh/-Nm") from None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _list_anchor(profile: Profile) -> datetime:
    """What relative list dates (``"-3d"``, none) count back from: the day
    the profile was created (UTC midnight), so every apply writes, and every
    read-back expects, the same date (a call-log row is matched on it).
    """
    base = profile.created or datetime.now(UTC)
    base = base if base.tzinfo else base.replace(tzinfo=UTC)
    return base.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def _item_date_ms(item: dict[str, Any], index: int, anchor: datetime) -> int:
    """The ``date`` (epoch ms) a list item is written with."""
    return int(_resolve_date(item.get("date"), index, anchor).timestamp() * 1000)


# ---------------------------------------------------------------------------
# markers
# ---------------------------------------------------------------------------

#: Country calling codes of the presets (national <-> E.164 forms).
CALLING_CODES = {
    "de": "49",
    "us": "1",
    "gb": "44",
    "fr": "33",
    "ru": "7",
    "cn": "86",
    "jp": "81",
    "kr": "82",
    "br": "55",
    "in": "91",
    "ir": "98",
    "kp": "850",
}


def _phone_marker_value(number: str, cc: str) -> tuple[str, tuple[str, ...]]:
    """(marker value, extra forms) for a phone number.

    The value is the international form the emulator's SIM carries
    (:func:`identity_sim.msisdn_digits`); the forms add the national ones.
    """
    digits = "".join(c for c in number if c.isdigit())
    full, international = identity_sim.msisdn_digits(number, cc)
    if not international:
        return digits, ()
    national = full[len(cc) :] if cc and full.startswith(cc) else ""
    forms: list[str] = []
    if not number.strip().startswith("+") and digits != full:
        forms.append(digits)
    if national and "0" + national not in forms:
        forms.append("0" + national)
    return f"+{full}", tuple(forms)


def markers_for(
    profile: Profile,
    ssaids: dict[str, str],
    primary: str | None = None,
    *,
    dedupe: bool = True,
) -> list[Marker]:
    """The markers of ``profile``.

    Args:
        profile: A profile whose templates render.
        ssaids: ``{package: android id}`` recorded at apply.
        primary: The package whose Android ID is listed first. Every
            per-app Android ID is ``android_id@<package>``, whichever app
            was applied last: a marker id stays the same for its value.
        dedupe: List a value once (validation turns it off to see clashes).

    Returns:
        One marker per markable value (GPS: latitude and longitude, group
        ``gps``) and per list field; duplicate values are listed once.
    """
    cc = CALLING_CODES.get(profile.preset, "")
    out: list[Marker] = []
    seen: set[str] = set()

    def add(m: Marker) -> None:
        if m.value and (not dedupe or m.value not in seen):
            seen.add(m.value)
            out.append(m)

    for vid, vs in profile.values.items():
        spec = vs.spec
        if spec is None or spec.marker is None or not vs.enabled:
            continue
        label = vs.label or spec.label
        if vs.derive == "ssaid" or (vs.kind == "android_id" and ssaids):
            ordered = sorted(ssaids, key=lambda p: (p != primary, p))
            for pkg in ordered:
                add(
                    Marker(
                        f"{vid}@{pkg}",
                        ssaids[pkg],
                        "hex_id",
                        f"{label} ({pkg})",
                        tag=spec.tag,
                    )
                )
            if vs.derive == "ssaid":
                continue
        value = render_value(profile, vs)
        if value is None:
            continue
        if vs.kind == "gps":
            lat, lon, _alt = split_gps(value)
            add(
                Marker(
                    f"{vid}.latitude",
                    lat,
                    "latitude",
                    f"{label} latitude",
                    group=vid,
                    tag=spec.tag,
                )
            )
            add(
                Marker(
                    f"{vid}.longitude",
                    lon,
                    "longitude",
                    f"{label} longitude",
                    group=vid,
                    tag=spec.tag,
                )
            )
        elif spec.marker == "phone":
            mval, forms = _phone_marker_value(value, cc)
            add(Marker(vid, mval, "phone", label, forms, tag=spec.tag))
        else:
            add(Marker(vid, value, spec.marker, label, tag=spec.tag))
    for name, items in render_lists(profile).items():
        spec_l = LISTS[name]
        for i, item in enumerate(items):
            title = str(item.get(spec_l.token_field) or "")
            for fname in spec_l.fields:
                val = item.get(fname)
                if not isinstance(val, str) or not val:
                    continue
                label = f"{spec_l.tag}: {title} ({fname})"
                mid = f"{name}.{i}.{fname}"
                if fname in ("phone", "address", "number") and _PHONE_RE.fullmatch(val):
                    mval, forms = _phone_marker_value(val, cc)
                    add(Marker(mid, mval, "phone", label, forms, tag=spec_l.tag))
                elif fname == "email":
                    add(Marker(mid, val, "email", label, tag="Email"))
                else:
                    add(Marker(mid, val, "text", label, tag=spec_l.tag))
    return out


# ---------------------------------------------------------------------------
# built-in generator
# ---------------------------------------------------------------------------

_PEOPLE = {
    "de": {
        "owner": ("Mara", "Kessler"),
        "contacts": [("Jonas", "Weber"), ("Lena", "Hoffmann"), ("Tobias", "Brandt")],
        "carrier": "Telekom",
        "mobile": "+49151{digits:7}",
        "line": "1520{digits:7}",
        "sms": [
            "Dein Paket {token}{digits:3} kommt heute",
            "Termin bestaetigt, Code {token}-{digits:4}",
        ],
        "calls": ["Praxis Dr. Albers {token}", "Paketdienst {token}"],
    },
    "en": {
        "owner": ("Alex", "Morgan"),
        "contacts": [("Jordan", "Reed"), ("Casey", "Turner"), ("Riley", "Brooks")],
        "carrier": "Carrier",
        "mobile": "+1212555{digits:4}",
        "line": "212555{digits:4}",
        "sms": [
            "Your parcel {token}{digits:3} arrives today",
            "Appointment confirmed, code {token}-{digits:4}",
        ],
        "calls": ["Dr. Albers Office {token}", "Courier {token}"],
    },
}


def _jitter(value: float, rnd: secrets.SystemRandom) -> str:
    text = f"{value + rnd.uniform(-0.01, 0.01):.6f}"
    if text.endswith("0"):
        text = text[:-1] + str(rnd.randint(1, 9))
    return text


def generate_profile(
    preset: str = "de", *, name: str = "", profile_id: str = ""
) -> Profile:
    """A complete, valid profile seeded from a country preset.

    Uses ``COUNTRY_PRESETS`` (GPS around the capital, time zone, language,
    MCC/MNC) plus built-in fake people. Values carry a fresh random token.

    Args:
        preset: Key of ``COUNTRY_PRESETS`` (``"de"``, ``"us"``, ...).
        name: Display name (default: owner name and country).
        profile_id: Library id (default: ``<owner>-<preset>``).
    """
    from sandroid.services.device_settings_service import COUNTRY_PRESETS

    country = COUNTRY_PRESETS.get(preset) or COUNTRY_PRESETS["de"]
    preset = country.country_code
    people = _PEOPLE.get(preset, _PEOPLE["en"])
    rnd = secrets.SystemRandom()
    first, last = people["owner"]
    token = secrets.token_hex(4)
    mccmnc = country.telephony_mnc
    imsi_len = 15 - len(mccmnc)
    values = {
        "android_id": ValueSpec("android_id", derive="ssaid", scope="signer"),
        "gaid": ValueSpec("gaid", derive="uuid"),
        "app_set_id": ValueSpec("app_set_id", derive="uuid"),
        "device_name": ValueSpec("device_name", template=f"{first}s Pixel {{token}}"),
        "phone_number": ValueSpec("phone_number", template=people["line"]),
        "gps": ValueSpec(
            "gps",
            value=f"{_jitter(country.latitude, rnd)}, "
            f"{_jitter(country.longitude, rnd)}",
        ),
        "timezone": ValueSpec("timezone", value=country.timezone),
        "locale": ValueSpec("locale", value=f"{country.language}-{country.country}"),
        "sim_operator": ValueSpec(
            "sim_operator", template=f"{people['carrier']} {{token}}"
        ),
        "sim_mccmnc": ValueSpec("sim_mccmnc", value=mccmnc),
        "build_model": ValueSpec(
            "build_model", template="Pixel 8 {token}", enabled=False
        ),
        "imei": ValueSpec("imei", template="35847631{digits:6}{luhn}"),
        "imsi": ValueSpec("imsi", template=f"{mccmnc}{{digits:{imsi_len}}}"),
        "iccid": ValueSpec("iccid", template="8949{digits:14}{luhn}"),
        "serial": ValueSpec("serial", template="RF8N{token}"),
        "account": ValueSpec(
            "account", template=f"{first.lower()}.{last.lower()}.{{token}}@example.org"
        ),
        "clipboard": ValueSpec("clipboard", template="Notiz {token} merken"),
    }
    contacts = [
        {
            "name": f"{cf} {cl} {{token}}",
            "phone": people["mobile"],
            "email": f"{cf.lower()}.{{token}}@example.org",
        }
        for cf, cl in people["contacts"]
    ]
    sms = [
        {
            "address": people["mobile"],
            "body": body,
            "box": "inbox",
            "date": f"-{i + 1}d",
        }
        for i, body in enumerate(people["sms"])
    ]
    calls = [
        {
            "number": people["mobile"],
            "name": cname,
            "type": ctype,
            "duration": 42 + i,
            "date": f"-{i + 2}d",
        }
        for i, (cname, ctype) in enumerate(
            zip(people["calls"], ("incoming", "missed"), strict=False)
        )
    ]
    pid = profile_id or f"{first.lower()}-{preset}"
    profile = Profile(
        id=pid,
        name=name or f"{first} {last} ({preset.upper()})",
        token=token,
        seed="hex:" + secrets.token_hex(32),
        revision=0,
        created=datetime.now().astimezone().replace(microsecond=0),
        preset=preset,
        values=values,
        contacts=contacts,
        sms=sms,
        calls=calls,
    )
    # Random digits can collide (two equal phone numbers): draw again.
    for _ in range(20):
        if not any(i.severity == "error" for i in validate(profile)):
            break
        _regenerate(profile, retire=False)
    return profile


# ---------------------------------------------------------------------------
# library
# ---------------------------------------------------------------------------


def profiles_dir() -> Path:
    """``$XDG_CONFIG_HOME/sandroid/profiles`` (created)."""
    from sandroid.core.watchlist_store import _user_dir

    override = os.environ.get(PROFILES_DIR_ENV)
    directory = Path(override).expanduser() if override else _user_dir() / "profiles"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{uuidlib.uuid4().hex[:8]}")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _profile_path(pid: str) -> Path:
    if not ID_RE.fullmatch(pid):
        raise ProfileError(f"invalid profile id {pid!r}")
    return profiles_dir() / f"{pid}.toml"


@dataclass(frozen=True)
class ProfileInfo:
    """A library entry (for a list view)."""

    id: str
    name: str
    revision: int
    token: str
    preset: str
    path: Path
    error: str = ""  # unreadable / newer schema


# ---------------------------------------------------------------------------
# device access
# ---------------------------------------------------------------------------


def _send(command: str, serial: str | None, timeout: float = 60) -> tuple[str, str]:
    """One adb command for ``serial`` (tests monkeypatch this)."""
    from sandroid.core.adb import Adb

    return Adb.send_adb_command(command, serial=serial, timeout=timeout)


def _q(text: str) -> str:
    """Quote for the device shell."""
    return shlex.quote(text)


class _Device:
    """Thin per-serial wrapper around :func:`_send`."""

    def __init__(self, serial: str) -> None:
        self.serial = serial

    def shell(self, script: str, *, zygote: bool = False, timeout: float = 60) -> str:
        if zygote:
            script = f"{ZYGOTE_PREFIX}\n{script}"
        from sandroid.core.adb_utils import quote_host_arg

        out, err = _send(f"shell {quote_host_arg(script)}", self.serial, timeout)
        if err and not out:
            logger.debug(f"identity: shell stderr: {err}")
        return out

    def emu(self, args: str) -> tuple[str, str]:
        return _send(f"emu {args}", self.serial, 30)

    def write(
        self,
        remote: str,
        data: bytes,
        *,
        abx: bool = False,
        chown: str = "",
        restorecon: bool = False,
    ) -> str:
        """Write ``data`` to ``remote`` atomically.

        The data goes to a temp file next to ``remote`` (same directory, so
        the final ``mv`` is a rename) that gets the original's owner, mode
        and SELinux label first. A dropped adb link mid-write leaves the
        original file as it was, never a truncated one.

        Args:
            remote: Device path.
            data: New content (XML text when ``abx``).
            abx: Re-encode the XML as Android binary XML on the device.
            chown: ``uid:gid`` for a file that may not exist yet: owner and
                mode 660 are set instead of copied from the original.
            restorecon: Relabel ``remote`` from the policy afterwards.

        Returns:
            ``""`` on success, else the error text.
        """
        from sandroid.core.adb_utils import quote_host_arg

        tag = uuidlib.uuid4().hex[:8]
        stage = f"{STAGE_DIR}/{Path(remote).name}.{tag}"
        tmp = f"{remote}.sandroid-{tag}"
        fd, local = tempfile.mkstemp(prefix="sandroid-identity-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            out, err = _send(
                f"push {quote_host_arg(local)} {quote_host_arg(stage)}",
                self.serial,
                60,
            )
            text = f"{out}\n{err}".lower()
            if "error" in text or "failed" in text or "no such file" in text:
                return f"push failed: {(err or out).strip()[:200]}"
            src = stage
            steps = []
            if abx:
                src = f"{stage}.abx"
                steps.append(f"xml2abx {_q(stage)} {_q(src)}")
            if chown:
                steps += [
                    f"cat {_q(src)} > {_q(tmp)}",
                    f"chown {_q(chown)} {_q(tmp)}",
                    f"chmod 660 {_q(tmp)}",
                ]
            else:
                # Owner, mode and label of the original; empty when it is
                # missing or unreadable, which stops the chain (fail closed).
                steps += [
                    f"O=$(stat -c %u:%g {_q(remote)})",
                    f"M=$(stat -c %a {_q(remote)})",
                    f"L=$(stat -c %C {_q(remote)})",
                    '[ -n "$O" ]',
                    '[ -n "$M" ]',
                    '[ -n "$L" ]',
                    f"cat {_q(src)} > {_q(tmp)}",
                    f'chown "$O" {_q(tmp)}',
                    f'chmod "$M" {_q(tmp)}',
                    f'chcon "$L" {_q(tmp)}',
                ]
            steps.append(f"mv -f {_q(tmp)} {_q(remote)}")
            if restorecon:
                steps.append(f"restorecon {_q(remote)}")
            steps.append(f"echo {_OK}")
            script = (
                " && ".join(steps)
                + f"; rm -f {_q(stage)} {_q(stage + '.abx')} {_q(tmp)}"
            )
            result = self.shell(script, zygote=abx)
            return "" if _OK in result else f"write failed: {result.strip()[:200]}"
        finally:
            with contextlib.suppress(OSError):
                os.unlink(local)


# ---------------------------------------------------------------------------
# preflight (P0): one batched read
# ---------------------------------------------------------------------------

_PROPS = (
    "ro.kernel.qemu",
    "ro.boot.qemu",
    "ro.build.version.sdk",
    "ro.product.model",
    "persist.sys.locale",
    "persist.sys.timezone",
    "gsm.sim.operator.alpha",
    "gsm.sim.operator.numeric",
    "gsm.operator.alpha",
    "gsm.operator.numeric",
    "ro.boot.qemu.avd_name",
    "sys.boot_completed",
)
_LIST_QUERY = {
    "contacts": (
        "content://com.android.contacts/data",
        ("raw_contact_id", "display_name", "mimetype", "data1"),
        "display_name",
    ),
    "sms": ("content://sms", ("_id", "address", "body", "type"), "body"),
    "calls": (
        "content://call_log/calls",
        ("_id", "number", "name", "type", "duration", "date"),
        "name",
    ),
}
#: ``content query`` prints this when the provider answered with no row; no
#: row and no such line means the provider did not answer (not up yet).
_NO_RESULT = "No result found."


def _where_like(column: str, tokens: Iterable[str]) -> str:
    return " OR ".join(f"{column} LIKE '%{t}%'" for t in tokens)


def _phone_digits(value: Any) -> str:
    return "".join(c for c in str(value or "") if c.isdigit() or c == "+")


def call_numbers(profile: Profile) -> list[str]:
    """The numbers of the profile's call-log items (the provider rewrites a
    call's ``name``, so the rows are found by number too).
    """
    try:
        items = render_lists(profile).get("calls", [])
    except (TemplateError, ValueError):
        return []
    numbers = {_phone_digits(item.get("number")) for item in items}
    return sorted(n for n in numbers if _PHONE_RE.fullmatch(n))


def _sim_lines() -> list[str]:
    """Read IMSI, ICCID and MSISDN (``@@sim:<key>@@`` sections, one parcel
    each) on emulators of the API levels whose transaction codes are known.
    """
    cases = []
    for api, codes in sorted(IPHONESUBINFO_CODES.items()):
        reads = "; ".join(
            f"echo @@sim:{key}@@; service call iphonesubinfo {code} s16"
            " com.android.shell 2>/dev/null"
            for key, code in codes
        )
        cases.append(f"{api}) {reads};;")
    # Emulators only: a real phone's SIM identity is never read.
    return [
        'if [ "$(getprop ro.kernel.qemu)" = 1 ] || [ "$(getprop ro.boot.qemu)" = 1 ];'
        " then",
        'case "$(getprop ro.build.version.sdk)" in',
        *cases,
        "esac",
        "fi",
    ]


def sim_script() -> str:
    """A light re-read of the SIM values and operator properties only.

    Its output parses with :func:`parse_preflight` (props and SIM only).
    """
    props = (
        "gsm.sim.operator.numeric",
        "gsm.sim.operator.alpha",
        "gsm.operator.numeric",
        "gsm.operator.alpha",
    )
    return "\n".join(
        [
            f"echo {PREFLIGHT_TAG}",
            "echo @@props@@",
            f'for p in {" ".join(props)}; do echo "$p=$(getprop $p)"; done',
            *_sim_lines(),
            "echo @@end@@",
        ]
    )


def _install_cmd(pkg: str) -> str:
    """Prints ``<uid>:<inode>`` of the app's data directory: a reinstall
    gives a new directory (and usually a new uid), and a new Android ID.
    """
    return f"stat -c %u:%i /data/data/{pkg} 2>/dev/null"


def preflight_script(
    packages: Iterable[str], tokens: Iterable[str], numbers: Iterable[str] = ()
) -> str:
    """The one batched read: every current value the pipeline compares
    (``numbers``: the call-log numbers, found by number as well).
    """
    tokens = [t for t in tokens if TOKEN_RE.fullmatch(t)]
    numbers = [n for n in numbers if _PHONE_RE.fullmatch(n)]
    pkgs = [p for p in packages if re.fullmatch(r"[A-Za-z0-9_.]+", p)]
    px = f"{STAGE_DIR}/packages.xml"
    lines = [
        f"echo {PREFLIGHT_TAG}",
        f"mkdir -p {STAGE_DIR} 2>/dev/null",
        f"if [ ! -s {ZYGOTE_ENV_FILE} ]; then ZP=$(pidof zygote64 || pidof zygote);"
        f" ZP=${{ZP%% *}}; [ -n \"$ZP\" ] && tr '\\0' '\\n' < /proc/$ZP/environ"
        " | grep -E '^[A-Za-z_][A-Za-z0-9_]*=' | grep -v '^ANDROID_SOCKET_'"
        ' | sed -e "s/\'//g" -e "s/=/=\'/" -e "s/\\$/\'/" -e \'s/^/export /\''
        f" > {ZYGOTE_ENV_FILE}; fi",
        "echo @@props@@",
        f'for p in {" ".join(_PROPS)}; do echo "$p=$(getprop $p)"; done',
        "echo @@root@@; id -u",
        "echo @@resetprop@@; command -v resetprop",
        "echo @@system_server@@; pidof system_server",
        f"echo @@marker@@; cat {RESTART_MARKER} 2>/dev/null",
        f"echo @@boot_id@@; cat {BOOT_ID_FILE} 2>/dev/null",
        f"echo @@gms@@; pm path {GMS} 2>/dev/null | head -n 1",
        "echo @@settings@@",
        'echo "device_name=$(settings get global device_name)"',
        'echo "auto_time_zone=$(settings get global auto_time_zone)"',
        'echo "airplane_mode_on=$(settings get global airplane_mode_on)"',
        f"echo @@ssaid@@; ({ZYGOTE_PREFIX}; abx2xml {SSAID_FILE} - 2>/dev/null"
        f" || cat {SSAID_FILE})",
        f"echo @@gaid_owner@@; stat -c %u:%g {GAID_DIR} 2>/dev/null",
        f"echo @@gaid@@; cat {GAID_FILE} 2>/dev/null",
        f"echo @@appset@@; base64 -w 0 {APPSET_FILE} 2>/dev/null; echo",
        "echo @@location@@; dumpsys location 2>/dev/null"
        " | grep -m 3 -E 'Location\\[(gps|fused) '",
        *_sim_lines(),
    ]
    if pkgs:
        # One tag per line, whether or not abx2xml indents.
        lines.append(
            f"({ZYGOTE_PREFIX}; abx2xml {PACKAGES_XML} - 2>/dev/null) | tr '<' '\\n'"
            f" > {px}"
        )
        lines.append("echo @@uids@@; pm list packages -U 2>/dev/null")
        for pkg in pkgs:
            rx = pkg.replace(".", "\\.")
            lines.append(f"echo @@inst:{pkg}@@; {_install_cmd(pkg)}")
            # The certificate from packages.xml; the framework's short
            # signature hash (dumpsys) only when that fails.
            lines += [
                f"echo @@pkg:{pkg}@@; KEY=",
                f"IDX=$(sed -n '/^package name=\"{rx}\"/,/^\\/package>/p' {px}"
                " | grep -o '^cert index=\"[0-9]*\"' | head -n 1"
                " | grep -o '[0-9][0-9]*')",
                f'[ -n "$IDX" ] && KEY=$(grep -o "^cert index=\\"$IDX\\"'
                f' key=\\"[0-9a-fA-F]*\\"" {px} | head -n 1)',
                'if [ -n "$KEY" ]; then echo "$KEY"; else'
                f" dumpsys package {pkg} 2>/dev/null"
                " | grep -m 1 -o 'signatures:\\[[0-9a-f, ]*\\]'; fi",
            ]
        lines.append(f"rm -f {px}")
    if tokens:
        for name, (uri, proj, col) in _LIST_QUERY.items():
            where = _where_like(col, tokens)
            if name == "calls" and numbers:
                where += " OR number IN (" + ",".join(f"'{n}'" for n in numbers) + ")"
            lines.append(
                f"echo @@list:{name}@@; ({ZYGOTE_PREFIX}; content query --uri {uri}"
                f" --projection {':'.join(proj)} --where {_q(where)} 2>/dev/null)"
            )
    lines.append("echo @@end@@")
    return "\n".join(lines)


def lists_script(tokens: Iterable[str], numbers: Iterable[str] = ()) -> str:
    """A light re-read of the content-provider lists only (no packages.xml,
    settings or dumpsys): the provider wait after a framework restart.
    Its output parses with :func:`parse_preflight` (lists and ``ok`` only).
    """
    tokens = [t for t in tokens if TOKEN_RE.fullmatch(t)]
    numbers = [n for n in numbers if _PHONE_RE.fullmatch(n)]
    lines = [f"echo {PREFLIGHT_TAG}"]
    for name, (uri, proj, col) in _LIST_QUERY.items():
        if not tokens:
            break
        where = _where_like(col, tokens)
        if name == "calls" and numbers:
            where += " OR number IN (" + ",".join(f"'{n}'" for n in numbers) + ")"
        lines.append(
            f"echo @@list:{name}@@; ({ZYGOTE_PREFIX}; content query --uri {uri}"
            f" --projection {':'.join(proj)} --where {_q(where)} 2>/dev/null)"
        )
    lines.append("echo @@end@@")
    return "\n".join(lines)


def _sections(text: str) -> dict[str, str]:
    out: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        match = re.fullmatch(r"@@([a-z_]+(?::[A-Za-z0-9_.]+)?)@@", line.strip())
        if match:
            current = out.setdefault(match.group(1), [])
            continue
        if current is not None:
            current.append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


def parse_rows(text: str, keys: tuple[str, ...]) -> list[dict[str, str]]:
    """Rows of ``content query`` output (values may contain ``", "``)."""
    split = re.compile(r", (?=(?:" + "|".join(map(re.escape, keys)) + r")=)")
    rows = []
    for line in text.splitlines():
        match = re.match(r"Row: \d+ (.*)$", line.strip())
        if not match:
            continue
        row: dict[str, str] = {}
        for part in split.split(match.group(1)):
            key, _, value = part.partition("=")
            row[key] = "" if value == "NULL" else value
        rows.append(row)
    return rows


@dataclass
class PackageInfo:
    """A target package on the device."""

    package: str
    uid: int | None
    signer: str  # scope key: "sha256:<hex>" or "sighash:<hex>" or ""


@dataclass
class DeviceState:
    """Everything one preflight read returned."""

    serial: str
    ok: bool = False
    props: dict[str, str] = field(default_factory=dict)
    root: bool = False
    emulator: bool = False
    api: int = 0
    resetprop: bool = False
    system_server: str = ""
    marker: str = ""
    #: :data:`BOOT_ID_FILE`, one per boot: the device record's boot, and
    #: (with the host's launch token) one emulator launch from the next.
    boot_id: str = ""
    gms: bool = False
    settings: dict[str, str] = field(default_factory=dict)
    ssaid_xml: str = ""
    ssaid: dict[str, tuple[str, str]] = field(default_factory=dict)  # pkg->(uid, v)
    gaid_owner: str = ""
    gaid_xml: str = ""
    gaid: str = ""
    appset: bytes | None = None
    location: tuple[float, float] | None = None
    packages: dict[str, PackageInfo] = field(default_factory=dict)
    lists: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    #: Lists whose provider did not answer (no row, no "No result found."):
    #: not up yet, e.g. right after a framework restart.
    lists_unread: set[str] = field(default_factory=set)
    #: SIM values read with ``service call iphonesubinfo`` (``imsi``,
    #: ``iccid``, ``msisdn``; empty when the SIM has none).
    sim: dict[str, str] = field(default_factory=dict)
    #: The SIM values were read (known transaction codes, root).
    sim_read: bool = False
    #: The installed-packages list was read (``pm list packages -U``).
    uids_read: bool = False
    #: Package -> ``uid:inode`` of its data directory (see :func:`_install_cmd`).
    installs: dict[str, str] = field(default_factory=dict)


def _settings_document(xml_text: str) -> tuple[ET.Element, ET.Element] | None:
    """Parse a settings file as ``(document, settings element)``, or None.

    Android 14+ writes a second top-level element after ``</settings>``
    (``<namespaceHashes />``), which is not well-formed XML on its own, so
    the top-level elements are parsed inside a wrapper ``document``.
    """
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text)
    try:
        document = ET.fromstring(  # noqa: S314 - device file
            f"<sandroid-document>{body}</sandroid-document>".encode()
        )
    except ET.ParseError:
        return None
    root = document.find("settings")
    if root is None:
        root = next(iter(document), None)
    if root is None:
        return None
    return document, root


def _parse_ssaid(xml_text: str) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    if not xml_text.strip():
        return out
    parsed = _settings_document(xml_text)
    if parsed is None:
        return out
    _document, root = parsed
    for row in root.iter("setting"):
        pkg = row.get("package") or ""
        if pkg and pkg != "android":
            out[pkg] = (row.get("name") or "", row.get("value") or "")
    return out


def parse_preflight(serial: str, text: str) -> DeviceState:
    """Parse the output of :func:`preflight_script`."""
    state = DeviceState(serial=serial)
    if PREFLIGHT_TAG not in text:
        return state
    sec = _sections(text.split(PREFLIGHT_TAG, 1)[1])
    state.ok = "end" in sec
    for line in sec.get("props", "").splitlines():
        key, _, value = line.partition("=")
        state.props[key.strip()] = value.strip()
    state.root = sec.get("root", "").strip() == "0"
    state.emulator = (
        state.props.get("ro.kernel.qemu") == "1"
        or state.props.get("ro.boot.qemu") == "1"
        or serial.startswith("emulator-")
    )
    with contextlib.suppress(ValueError):
        state.api = int(state.props.get("ro.build.version.sdk") or 0)
    state.resetprop = bool(sec.get("resetprop"))
    state.system_server = sec.get("system_server", "").split(" ")[0]
    state.marker = sec.get("marker", "")
    state.boot_id = sec.get("boot_id", "")
    state.uids_read = "package:" in sec.get("uids", "")
    state.gms = sec.get("gms", "").startswith("package:")
    for line in sec.get("settings", "").splitlines():
        key, _, value = line.partition("=")
        state.settings[key.strip()] = value.strip()
    state.ssaid_xml = sec.get("ssaid", "")
    state.ssaid = _parse_ssaid(state.ssaid_xml)
    state.gaid_owner = sec.get("gaid_owner", "")
    state.gaid_xml = sec.get("gaid", "")
    match = re.search(r'name="adid_key">([^<]*)<', state.gaid_xml)
    state.gaid = match.group(1) if match else ""
    raw = sec.get("appset", "")
    if raw:
        with contextlib.suppress(ValueError):
            state.appset = base64.b64decode(raw, validate=False)
    match = re.search(
        r"Location\[\w+ (-?\d+\.\d+),(-?\d+\.\d+)", sec.get("location", "")
    )
    if match:
        state.location = (float(match.group(1)), float(match.group(2)))
    for key, body in sec.items():
        if key.startswith("sim:"):
            value = identity_sim.decode_parcel_string(body)
            if value is not None and state.emulator:
                state.sim[key[4:]] = value.strip()
                state.sim_read = True
        elif key.startswith("pkg:"):
            pkg = key[4:]
            uid = None
            m_uid = re.search(
                rf"^package:{re.escape(pkg)} uid:(\d+)", sec.get("uids", ""), re.M
            )
            if m_uid:
                uid = int(m_uid.group(1))
            signer = ""
            m_key = re.search(r'key="([0-9a-fA-F]+)"', body)
            m_hash = re.search(r"signatures:\[([0-9a-f]+)", body)
            if m_key:
                with contextlib.suppress(ValueError):
                    der = bytes.fromhex(m_key.group(1))
                    signer = "sha256:" + hashlib.sha256(der).hexdigest()
            if not signer and m_hash:
                signer = "sighash:" + m_hash.group(1)
            state.packages[pkg] = PackageInfo(pkg, uid, signer)
        elif key.startswith("inst:"):
            if re.fullmatch(r"\d+:\d+", body):
                state.installs[key[5:]] = body
        elif key.startswith("list:"):
            name = key[5:]
            rows = parse_rows(body, _LIST_QUERY[name][1])
            state.lists[name] = rows
            if not rows and _NO_RESULT not in body:
                state.lists_unread.add(name)
    return state


# ---------------------------------------------------------------------------
# statuses, plan
# ---------------------------------------------------------------------------


@dataclass
class ValueInfo:
    """Per-value metadata and status (for the lens)."""

    id: str
    kind: str
    label: str
    tag: str
    provider: str
    restart: str
    permission: str
    mechanism: str
    enabled: bool = True
    volatile: bool = False
    status: str = "pending"
    reason: str = ""
    rendered: str = ""
    current: str = ""
    before: str = ""
    per_app: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Set when the status is shared (plan / apply / verify): the profile
    #: and fingerprint it belongs to, and when the device was read (epoch s).
    profile_id: str = ""
    fingerprint: str = ""
    at: float = 0.0
    #: Set when the emulator's start sets the value (its SIM card): a failure
    #: never blocks an app start (restarting the app cannot fix it).
    sim_launch: bool = False


@dataclass
class Step:
    """One planned change."""

    value_id: str
    restart: str
    desired: Any
    current: Any = None
    #: ``sim``: the running emulator started with the value; an airplane-mode
    #: toggle makes the guest read its SIM card again. Else a write.
    via: str = ""


@dataclass
class IdentityPlan:
    """P1: what an apply would do on one device."""

    serial: str
    packages: tuple[str, ...]
    profile_id: str
    fingerprint: str
    steps: list[Step] = field(default_factory=list)
    infos: dict[str, ValueInfo] = field(default_factory=dict)
    recovery: bool = False  # a restart window was interrupted
    #: The emulator launch whose SIM this plan checked (serial, boot id,
    #: launch token), None when the emulator did not start with its SIM.
    sim_key: tuple[str, str, str] | None = None

    @property
    def restart(self) -> str:
        """Highest restart class among the steps (``none`` if no step)."""
        ranks = [_RESTART_RANK[s.restart] for s in self.steps]
        if self.recovery:
            ranks.append(_RESTART_RANK["framework"])
        return RESTARTS[max(ranks, default=0)]

    @property
    def disruptive(self) -> bool:
        """True when a framework restart (every app stops) is needed."""
        return self.restart == "framework"

    @property
    def todo(self) -> list[str]:
        """Value ids with a step."""
        return [s.value_id for s in self.steps]


def _pre_start_plan_cls() -> type:
    from sandroid.services.app_start import PreStartPlan

    return PreStartPlan


#: Deprecated alias (app_start's pre-start step was called pre-spawn hook).
_pre_spawn_plan_cls = _pre_start_plan_cls


def _list_sig(name: str, row: dict[str, Any], when: int | None = None) -> tuple:
    """What identifies one list item on the device.

    A call is matched on number, type, date and duration, never on its
    ``name``: the call-log provider clears or rewrites it (from contacts).
    ``when`` is the date (epoch ms) a profile item is written with; device
    rows carry their own.
    """
    phone = _phone_digits
    if name == "contacts":
        return (
            str(row.get("name") or ""),
            phone(row.get("phone")),
            str(row.get("email") or "").lower(),
        )
    if name == "sms":
        box = row.get("box", "inbox")
        box = _SMS_TYPES.get(str(box), box)
        return (phone(row.get("address")), str(row.get("body") or ""), str(box))
    ctype = row.get("type", "incoming")
    ctype = _CALL_TYPES.get(str(ctype), ctype)
    date = when if when is not None else row.get("date")
    return (
        phone(row.get("number")),
        str(ctype),
        str(date or ""),
        str(_call_duration(row.get("duration")) or 0),
    )


def _device_list_items(name: str, rows: list[dict[str, str]]) -> dict[str, dict]:
    """Device rows grouped into items: ``{row id: {fields}}``."""
    items: dict[str, dict] = {}
    if name == "contacts":
        for row in rows:
            rid = row.get("raw_contact_id", "")
            item = items.setdefault(rid, {"name": row.get("display_name", "")})
            mime = row.get("mimetype", "")
            for fname, m in _CONTACT_MIME.items():
                if mime == m:
                    item[fname] = row.get("data1", "")
        return items
    for row in rows:
        if name == "sms":
            items[row.get("_id", "")] = {
                "address": row.get("address"),
                "body": row.get("body"),
                "box": row.get("type"),
            }
        else:
            items[row.get("_id", "")] = dict(row)
    return items


_RAW_CONTACTS = "content://com.android.contacts/raw_contacts"
_LIST_FAIL = "@@identity-list-failed@@ "
#: sed script: the digits after ``_id=`` of each ``content query`` row.
_SED_IDS = r"s/.*_id=\([0-9][0-9]*\).*/\1/p"


def _contact_steps(item: dict[str, Any]) -> list[str]:
    """The ``&&`` chain that inserts one contact (raw contact + data rows).

    ``content insert`` does not print the new row id, so the chain reads the
    newest raw contact id before the insert (``MAX``) and the ids above it
    after (``NEW``). The data rows are attached only when that is exactly one
    id: no insert (empty) or a concurrent one, e.g. a sync adapter (two ids:
    not an integer for ``[ -gt ]``), breaks the chain, so canary data never
    lands on a real contact.
    """
    steps = [
        f"MAX=$(content query --uri {_RAW_CONTACTS} --projection _id"
        f" --sort {_q('_id DESC')} | sed -n {_q('1' + _SED_IDS)})",
        'MAX="${MAX:-0}"',
        f"content insert --uri {_RAW_CONTACTS}"
        " --bind account_type:n: --bind account_name:n:",
        f"NEW=$(content query --uri {_RAW_CONTACTS} --projection _id"
        f' --where "_id>$MAX" | sed -n {_q(_SED_IDS)})',
        '[ -n "$NEW" ]',
        '[ "$NEW" -gt "$MAX" ]',
    ]
    for fname, mime in _CONTACT_MIME.items():
        val = item.get(fname)
        if not val:
            continue
        extra = " --bind data2:i:2" if fname in ("phone", "email") else ""
        steps.append(
            "content insert --uri content://com.android.contacts/data"
            ' --bind raw_contact_id:i:"$NEW"'
            f" --bind {_q('mimetype:s:' + mime)}"
            f" --bind {_q('data1:s:' + str(val))}{extra}"
        )
    return steps


# ---------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------

MarkersListener = Callable[[str | None, list[Marker]], None]
StatusListener = Callable[[list[ValueInfo]], None]


@dataclass
class _Applied:
    """What was applied on one device (for idempotence).

    Filled by this process's applies and from the device record
    (:data:`APPLIED_FILE`, see :meth:`IdentityService._hydrate`). ``done``,
    ``seeded``, ``settled`` and the times belong to ``fingerprint``.
    """

    fingerprint: str = ""
    emu: dict[str, str] = field(default_factory=dict)  # value id -> sent value
    done: set[str] = field(default_factory=set)  # packages fully applied
    ssaids: dict[str, str] = field(default_factory=dict)
    befores: dict[str, str] = field(default_factory=dict)  # also "ssaid:<pkg>"
    befores_done: bool = False
    frozen: str = ""  # fingerprint+statuses digest of the last freeze
    #: Package -> Android ID verified with ``fingerprint``.
    seeded: dict[str, str] = field(default_factory=dict)
    #: Package -> ``uid:inode`` of its data directory when it was seeded.
    installs: dict[str, str] = field(default_factory=dict)
    #: Framework-restart value ids that fail structurally here
    #: (:data:`STRUCTURAL`, skipped, hook-only): no restart can apply them.
    unappliable: set[str] = field(default_factory=set)
    #: ``unappliable`` comes from a preflight of this process (fresher than
    #: the device record, which only an apply rewrites).
    observed: bool = False
    #: Framework-restart values other than the Android ID that are on the
    #: device: value id -> volatile (the device forgets it on reboot).
    settled: dict[str, bool] = field(default_factory=dict)
    boot_id: str = ""  # kernel boot id when this was learned
    applied_at: float = 0.0  # epoch s of the last apply (0 = unknown)
    verified_at: float = 0.0  # epoch s of the last read-back
    record_sig: str = ""  # signature of the record on the device
    #: Bumped whenever an apply changes this; a racing hydration backs off.
    gen: int = 0


@dataclass(frozen=True)
class _RecordRead:
    """One read of the device record (:func:`record_script`)."""

    record: dict[str, Any] | None  # None: missing or unreadable
    boot_id: str
    marker: str  # the restart marker's content ("" when there is none)
    install: str = ""  # ``uid:inode`` of the package asked for ("" = none)
    avd_name: str = ""  # ro.boot.qemu.avd_name ("" = not an emulator, unknown)


def applied_record(
    profile_id: str, fp: str, mem: _Applied, boot_id: str, at: float
) -> dict[str, Any]:
    """The device record (:data:`APPLIED_FILE`) for ``mem``.

    Keys: ``format``, ``version``, ``profile``, ``fingerprint``, ``boot_id``
    (kernel boot id of the apply), ``at`` (epoch s of the apply),
    ``verified_at`` (epoch s of its read-back), ``done`` (packages fully
    applied), ``ssaids`` (package -> Android ID verified with this
    fingerprint), ``installs`` (package -> ``uid:inode`` of its data
    directory when it was seeded), ``framework`` (framework-restart value id
    on the device -> volatile) and ``unappliable`` (framework-restart value
    ids no restart can apply here).
    """
    seeded = sorted(mem.seeded)
    return {
        "format": APPLIED_FORMAT,
        "version": 1,
        "profile": profile_id,
        "fingerprint": fp,
        "boot_id": boot_id,
        "at": round(at, 3),
        "verified_at": round(mem.verified_at, 3),
        "done": sorted(mem.done),
        "ssaids": {p: mem.seeded[p] for p in seeded},
        "installs": {p: mem.installs[p] for p in seeded if p in mem.installs},
        "framework": dict(sorted(mem.settled.items())),
        "unappliable": sorted(mem.unappliable),
    }


def _record_sig(record: dict[str, Any]) -> str:
    """Content signature of a record; the time counts to the second (a later
    apply rewrites the record, sub-second noise does not).
    """
    body = dict(
        record,
        at=int(record.get("at") or 0),
        verified_at=int(record.get("verified_at") or 0),
    )
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _str_map(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    )


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def parse_applied_record(text: str) -> dict[str, Any] | None:
    """The record in ``text``, or None when it is missing or malformed."""
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("format") != APPLIED_FORMAT:
        return None
    fw = data.get("framework")
    if (
        data.get("version") != 1
        or not isinstance(data.get("fingerprint"), str)
        or not isinstance(data.get("boot_id"), str)
        or not isinstance(data.get("at"), int | float)
        or not isinstance(data.get("verified_at"), int | float)
        or not _str_list(data.get("done"))
        or not _str_map(data.get("ssaids"))
        or not _str_map(data.get("installs"))
        or not isinstance(fw, dict)
        or not all(isinstance(v, bool) for v in fw.values())
        or not _str_list(data.get("unappliable"))
    ):
        return None
    return data


def record_script(package: str | None = None) -> str:
    """One cheap read: the device record, the boot id, the restart marker
    and (with ``package``) that app's install identity.
    """
    lines = [
        "echo @@applied@@",
        f"cat {APPLIED_FILE} 2>/dev/null",
        "echo",
        "echo @@boot_id@@",
        f"cat {BOOT_ID_FILE} 2>/dev/null",
        "echo @@marker@@",
        f"cat {RESTART_MARKER} 2>/dev/null",
        "echo",
        "echo @@avd_name@@",
        "getprop ro.boot.qemu.avd_name",
    ]
    if package and re.fullmatch(r"[A-Za-z0-9_.]+", package):
        lines += ["echo @@install@@", _install_cmd(package)]
    lines.append("echo @@end@@")
    return "\n".join(lines)


def _started_with(
    launched: identity_sim.SimValues | None, sim: identity_sim.SimValues | None
) -> bool:
    """The emulator started with ``sim``: every SIM value the profile sets
    (the launch leaves the others at the image's defaults) matches.
    """
    if launched is None or sim is None:
        return False
    kinds = [
        k for k in ("imsi", "iccid", "phone_number", "sim_mccmnc") if sim.value_of(k)
    ]
    return bool(kinds) and all(launched.value_of(k) == sim.value_of(k) for k in kinds)


def _learn_unappliable(mem: _Applied, plan: IdentityPlan) -> None:
    """Framework-restart values ``plan`` found structurally unappliable
    (:data:`STRUCTURAL`, skipped, hook-only); every other one is dropped.
    A SIM value the emulator's start sets is never one (no root check
    applies to it, see :meth:`IdentityService._plan_sim`).
    """
    for vid, info in plan.infos.items():
        spec = REGISTRY.get(info.kind)
        if spec is None or spec.restart != "framework":
            continue
        structural = not info.sim_launch and (
            info.status in ("skipped", "hook-only")
            or (info.status == "failed" and info.reason in STRUCTURAL)
        )
        if structural:
            mem.unappliable.add(vid)
        else:
            mem.unappliable.discard(vid)
    mem.observed = True


def _knowledge(mem: _Applied) -> tuple:
    """What callers can see of ``mem`` (to tell whether a hydration changed it)."""
    return (
        mem.fingerprint,
        frozenset(mem.done),
        frozenset(mem.seeded.items()),
        tuple(sorted(mem.settled.items())),
        frozenset(mem.unappliable),
        mem.applied_at,
        mem.verified_at,
    )


#: The proxy's world-change cause for a framework restart (it resets the
#: lane caches for these, see ``FocusManager._WORLD_CHANGES``).
PROXY_RESTART_CAUSE = "framework-restart"


def _recover_frida_after_framework(serial: str, previous_pid: int | None) -> None:
    """Drop Sandroid's stale Frida state after a framework restart window.

    The JobManager session, the spotlight PID and the bypass handles still
    point at the dead system_server; ``app_start`` drops them and restarts
    frida-server when it predates the new system_server. Never raises.
    """
    try:
        from sandroid.services import app_start

        app_start.recover_after_framework_restart(previous_pid, serial=serial)
    except Exception:
        logger.warning(
            "identity: Frida recovery after the restart failed", exc_info=True
        )


def _restore_proxy_after_framework(serial: str) -> None:
    """Let the proxy check its device state after a framework restart window.

    The proxy's CA and gost survive the restart; this cheap check (a no-op
    when healthy) re-adds ``adb reverse`` and repairs a lane if needed.
    Never raises.
    """
    try:
        from sandroid.services.proxy_restore import restore_proxy_infra

        restore_proxy_infra(serial, cause=PROXY_RESTART_CAUSE, fresh_boot=False)
    except Exception:
        logger.debug("identity: proxy check after the restart failed", exc_info=True)


def _after_framework_restart(serial: str, previous_pid: int | None = None) -> None:
    """Bring Frida and the proxy back after a framework restart window."""
    _recover_frida_after_framework(serial, previous_pid)
    _restore_proxy_after_framework(serial)


class IdentityService:
    """Identity profile library, apply pipeline and marker source."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._apply_lock = threading.Lock()
        self._markers_listeners: list[MarkersListener] = []
        self._status_listeners: list[StatusListener] = []
        self._active: tuple[str, list[Marker]] | None = None
        self._loaded_frozen = False
        self._statuses: dict[str, ValueInfo] = {}
        self._applied: dict[str, _Applied] = {}
        #: Airplane-mode toggles for the SIM, one per emulator launch:
        #: ``(serial, boot id, launch token) -> error text ("" = done)``.
        self._sim_toggles: dict[tuple[str, str, str], str] = {}
        #: Launches whose toggle got no answer once (one more try each).
        self._sim_retry: set[tuple[str, str, str]] = set()
        #: Emulator launches an apply checked the SIM of (see _sim_due).
        self._sim_checked: set[tuple[str, str, str]] = set()
        #: Serials whose device record was read (memory hydrated), the time
        #: of the last background read per serial, and the running ones.
        self._hydrated: set[str] = set()
        self._hydrate_tried: dict[str, float] = {}
        self._hydrating: set[str] = set()
        self._hydrate_threads: dict[str, threading.Thread] = {}
        #: Serials whose device record could neither be written nor removed:
        #: it may be stale, so hydration ignores it until a write succeeds.
        self._record_dirty: set[str] = set()
        #: Wall clock of the apply/verify times (tests replace it).
        self._now: Callable[[], float] = time.time
        self._hook_installed = False
        self._sleep: Callable[[float], None] = time.sleep
        self._clock: Callable[[], float] = time.monotonic
        #: Per call (thread): the ``ensure_applied`` deadline (monotonic,
        #: None outside it) and whether the device answered the preflight.
        self._call = threading.local()
        #: Called with the serial and the old system_server PID once the
        #: framework is back after a restart window (default: Frida recovery
        #: through app_start, then the proxy check).
        self._after_restart: Callable[[str, int | None], None] = (
            _after_framework_restart
        )

    # -- library ----------------------------------------------------------

    def list_profiles(self) -> list[ProfileInfo]:
        """Every profile in the library, by id."""
        out = []
        for path in sorted(profiles_dir().glob("*.toml")):
            if path.name.startswith("."):
                continue
            try:
                p = Profile.loads(path.read_text(encoding="utf-8"))
                out.append(
                    ProfileInfo(p.id, p.name, p.revision, p.token, p.preset, path)
                )
            except (OSError, ProfileError) as exc:
                out.append(ProfileInfo(path.stem, path.stem, 0, "", "", path, str(exc)))
        return out

    def load(self, profile_id: str) -> Profile:
        """Load one profile (raises :class:`ProfileError`)."""
        path = _profile_path(profile_id)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileError(f"no profile {profile_id!r}") from exc
        return Profile.loads(text)

    def save(self, profile: Profile) -> Profile:
        """Save ``profile`` (drafts with errors too); bumps ``revision``."""
        if not ID_RE.fullmatch(profile.id):
            raise ProfileError(f"invalid profile id {profile.id!r}")
        profile.revision += 1
        if profile.created is None:
            profile.created = datetime.now().astimezone().replace(microsecond=0)
        _atomic_write_text(_profile_path(profile.id), profile.dumps())
        return profile

    def create(
        self, preset: str = "de", *, name: str = "", profile_id: str = ""
    ) -> Profile:
        """Generate and save a new profile from a country preset."""
        profile = generate_profile(preset, name=name, profile_id=profile_id)
        profile.id = self._free_id(profile.id)
        return self.save(profile)

    def duplicate(
        self, profile_id: str, new_id: str = "", *, fresh: bool = True
    ) -> Profile:
        """Copy a profile; ``fresh`` gives the copy its own token and seed."""
        profile = self.load(profile_id)
        profile.id = self._free_id(new_id or f"{profile_id}-copy")
        profile.name = f"{profile.name} (copy)"
        profile.revision = 0
        profile.retired_tokens = []
        if fresh:
            _regenerate(profile, retire=False)
        return self.save(profile)

    def rename(self, profile_id: str, name: str, new_id: str = "") -> Profile:
        """Change the display name (and, with ``new_id``, the file/id)."""
        profile = self.load(profile_id)
        profile.name = name
        if new_id and new_id != profile_id:
            if _profile_path(new_id).exists():
                raise ProfileError(f"profile {new_id!r} exists")
            profile.id = new_id
            self.save(profile)
            _profile_path(profile_id).unlink(missing_ok=True)
            if self.config().profile == profile_id:
                self.set_active(new_id)
            return profile
        return self.save(profile)

    def delete(self, profile_id: str) -> None:
        """Delete a profile file (frozen session copies stay)."""
        _profile_path(profile_id).unlink(missing_ok=True)

    def regenerate(self, profile_id: str) -> Profile:
        """Fresh token and seed; the old token is retired (its rows are removed
        from the device at the next apply).
        """
        profile = self.load(profile_id)
        _regenerate(profile, retire=True)
        return self.save(profile)

    def import_profile(self, source: str | Path) -> tuple[str, str]:
        """Import a profile file; never overwrites.

        Returns:
            ``(id, outcome)`` with outcome ``imported`` (verbatim),
            ``renamed`` (same id, other content -> ``<id>-2``) or
            ``identical`` (no-op).

        Raises:
            ProfileError: Unreadable, wrong format or a newer schema.
        """
        try:
            text = Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileError(f"cannot read {source}: {exc}") from exc
        profile = Profile.loads(text)
        if not ID_RE.fullmatch(profile.id):
            raise ProfileError(f"invalid profile id {profile.id!r}")
        target = _profile_path(profile.id)
        if not target.exists():
            _atomic_write_text(target, text)
            return profile.id, "imported"
        try:
            existing = self.load(profile.id)
        except ProfileError:
            existing = None
        if existing is not None and _canonical(existing) == _canonical(profile):
            return profile.id, "identical"
        for other in self.list_profiles():
            if other.error:
                continue
            with contextlib.suppress(ProfileError):
                if _canonical(self.load(other.id)) == _canonical(
                    replace(profile, id=other.id)
                ):
                    return other.id, "identical"
        profile.id = self._free_id(profile.id)
        _atomic_write_text(_profile_path(profile.id), profile.dumps())
        return profile.id, "renamed"

    def export_profile(self, profile_id: str, dest: str | Path) -> Path:
        """Copy the profile file verbatim to ``dest`` (a file or a folder)."""
        src = _profile_path(profile_id)
        if not src.exists():
            raise ProfileError(f"no profile {profile_id!r}")
        target = Path(dest)
        if target.is_dir():
            target = target / src.name
        target.write_bytes(src.read_bytes())
        return target

    def validate(self, profile: Profile) -> list[Issue]:
        """:func:`validate`."""
        return validate(profile)

    def describe(self, profile: Profile) -> list[ValueInfo]:
        """Per-value metadata of ``profile`` (no device access)."""
        infos = self._infos(profile)
        return list(infos.values())

    def _free_id(self, base: str) -> str:
        if not _profile_path(base).exists():
            return base
        stem = re.sub(r"-\d+$", "", base)
        n = 2
        while _profile_path(f"{stem}-{n}").exists():
            n += 1
        return f"{stem}-{n}"

    # -- configuration ------------------------------------------------------

    @staticmethod
    def config() -> Any:
        """The ``[identity]`` config section."""
        from sandroid.config import get_config

        return get_config().identity

    def set_active(
        self,
        profile_id: str | None = None,
        mode: str | None = None,
        restart: str | None = None,
    ) -> None:
        """Persist the active profile / mode / restart policy."""
        from sandroid.config import update_config

        updates: dict[str, Any] = {}
        if profile_id is not None:
            updates["identity.profile"] = profile_id
        if mode is not None:
            updates["identity.mode"] = mode
        if restart is not None:
            updates["identity.restart"] = restart
        before = self.config().mode, self.config().profile
        update_config(updates)
        if (self.config().mode, self.config().profile) != before:
            with self._lock:
                self._active = None
                self._loaded_frozen = True  # a new choice: wait for an apply
            self._notify_markers()

    def active_profile(self) -> Profile | None:
        """The configured profile when mode is ``profile`` (else ``None``)."""
        cfg = self.config()
        if cfg.mode != "profile" or not cfg.profile:
            return None
        return self.load(cfg.profile)

    # -- listeners ----------------------------------------------------------

    def add_markers_listener(self, cb: MarkersListener) -> None:
        """Call ``cb(fingerprint | None, markers)`` (any thread) on changes."""
        with self._lock:
            if cb not in self._markers_listeners:
                self._markers_listeners.append(cb)

    def remove_markers_listener(self, cb: MarkersListener) -> None:
        """Stop calling ``cb``."""
        with self._lock:
            if cb in self._markers_listeners:
                self._markers_listeners.remove(cb)

    def add_status_listener(self, cb: StatusListener) -> None:
        """Call ``cb(statuses)`` (worker thread) after plan/apply/verify."""
        with self._lock:
            if cb not in self._status_listeners:
                self._status_listeners.append(cb)

    def remove_status_listener(self, cb: StatusListener) -> None:
        """Stop calling ``cb``."""
        with self._lock:
            if cb in self._status_listeners:
                self._status_listeners.remove(cb)

    def _notify_markers(self) -> None:
        with self._lock:
            active = self._active
            listeners = list(self._markers_listeners)
        fp, markers = active if active else (None, [])
        for cb in listeners:
            try:
                cb(fp, list(markers))
            except Exception:
                logger.exception("identity: markers listener failed")

    def _notify_status(self) -> None:
        statuses = self.statuses()
        with self._lock:
            listeners = list(self._status_listeners)
        for cb in listeners:
            try:
                cb(statuses)
            except Exception:
                logger.exception("identity: status listener failed")

    # -- markers ------------------------------------------------------------

    def active_markers(self, *, load: bool = True) -> tuple[str, list[Marker]] | None:
        """``(fingerprint, markers)`` of the active profile, ``None`` when the
        mode is off (or no profile is set).

        The first call reads the session's newest frozen apply; without one
        (a TUI restart) the markers come from the profile
        (:func:`startup_markers`), so the scan runs from the start without
        re-applying anything to the device.

        Args:
            load: Read the session's newest frozen apply the first time
                (file I/O); ``False`` only answers from memory (UI thread).
        """
        cfg = self.config()
        if cfg.mode != "profile":
            return None
        loaded = False
        with self._lock:
            if self._active is None and not self._loaded_frozen and load:
                self._loaded_frozen = True
                self._active = _load_latest_frozen()
                if self._active is None and cfg.profile:
                    try:
                        self._active = startup_markers(self.load(cfg.profile))
                    except (ProfileError, TemplateError, ValueError):
                        logger.warning(
                            "identity: profile %r has no markers", cfg.profile
                        )
                loaded = self._active is not None
            active = self._active
        if loaded:
            self._notify_markers()
        if active is None:
            return None
        return active[0], list(active[1])

    # -- statuses -----------------------------------------------------------

    def statuses(self) -> list[ValueInfo]:
        """Per-value status of the last plan/apply/verify."""
        with self._lock:
            return [
                replace(v, per_app=dict(v.per_app)) for v in self._statuses.values()
            ]

    def _infos(self, profile: Profile) -> dict[str, ValueInfo]:
        infos: dict[str, ValueInfo] = {}
        for vid, vs in profile.values.items():
            spec = vs.spec
            if spec is None:
                continue
            try:
                rendered = render_value(profile, vs) or ""
            except TemplateError:
                rendered = ""
            provider = vs.effective_provider
            info = ValueInfo(
                vid,
                vs.kind,
                vs.label or spec.label,
                spec.tag,
                provider,
                spec.restart if provider == "native" else "none",
                spec.permission,
                spec.mechanism if provider == "native" else "hook",
                vs.enabled,
                spec.volatile,
                rendered=rendered,
            )
            if not vs.enabled:
                info.status = "skipped"
                info.reason = "disabled"
            elif provider == "hook":
                info.status = "hook-only"
            infos[vid] = info
        for name, items in profile.lists().items():
            if not items:
                continue
            spec_l = LISTS[name]
            infos[name] = ValueInfo(
                name,
                name,
                spec_l.label,
                spec_l.tag,
                "native",
                "none",
                spec_l.permission,
                spec_l.mechanism,
                rendered=f"{len(items)} items",
            )
        return infos

    # -- P0/P1 --------------------------------------------------------------

    def _packages(self, serial: str, package: str | None) -> tuple[str, ...]:
        with self._lock:
            known = set(self._applied.get(serial, _Applied()).ssaids)
        if package:
            known.add(package)
        return tuple(sorted(known))

    def preflight(
        self, serial: str, packages: Iterable[str], profile: Profile
    ) -> DeviceState:
        """P0: one adb call reading every current value."""
        tokens = [profile.token, *profile.retired_tokens]
        script = preflight_script(packages, tokens, call_numbers(profile))
        timeout = self._capped(120.0, floor=10.0)
        return parse_preflight(serial, _Device(serial).shell(script, timeout=timeout))

    def plan(
        self,
        serial: str,
        package: str | None = None,
        profile: Profile | None = None,
        *,
        require_answer: bool = False,
    ) -> IdentityPlan:
        """P0+P1: read the device once and plan (no writes).

        The statuses are published unless an apply ran or runs meanwhile
        (``_Applied.gen`` changed during the read, or the apply lock is
        held): a slow read never overwrites an apply's newer statuses.

        Args:
            serial: Device serial.
            package: The app about to start.
            profile: Profile to plan (default: the active one).
            require_answer: A device that does not answer (offline, still
                booting) raises instead of publishing every value as failed.

        Raises:
            ProfileError: No profile.
            IdentityApplyError: ``require_answer`` and no answer.
        """
        profile = profile or self._require_profile()
        pkgs = self._packages(serial, package)
        gen = self._gen(serial)
        state = self.preflight(serial, pkgs, profile)
        if require_answer and not state.ok:
            raise IdentityApplyError(f"{serial} did not answer the identity read")
        stale = self._gen(serial) != gen
        plan = self._plan(profile, state, pkgs)
        if not stale and not self._apply_lock.locked():
            self._publish(plan)
        return plan

    def _gen(self, serial: str) -> int:
        with self._lock:
            mem = self._applied.get(serial)
            return mem.gen if mem is not None else 0

    def apply_running(self) -> bool:
        """An apply (any device) holds the apply lock right now."""
        return self._apply_lock.locked()

    def _require_profile(self) -> Profile:
        profile = self.active_profile()
        if profile is None:
            raise ProfileError("no active identity profile (mode off or none chosen)")
        return profile

    def _plan(
        self, profile: Profile, state: DeviceState, pkgs: tuple[str, ...]
    ) -> IdentityPlan:
        fp = fingerprint(profile)
        plan = IdentityPlan(
            state.serial,
            pkgs,
            profile.id,
            fp,
            infos=self._infos(profile),
            recovery=bool(state.marker),
        )
        with self._lock:
            mem = self._applied.setdefault(state.serial, _Applied())
            if mem.fingerprint != fp:
                mem.fingerprint, mem.emu, mem.done = fp, {}, set()
                mem.seeded, mem.installs, mem.settled = {}, {}, {}
                mem.unappliable, mem.observed = set(), False
                mem.applied_at = mem.verified_at = 0.0
                mem.gen += 1
            if state.ok and state.boot_id and mem.boot_id not in ("", state.boot_id):
                # Rebooted: the console and volatile values are gone.
                mem.emu, mem.done = {}, set()
                mem.settled = {v: vol for v, vol in mem.settled.items() if not vol}
                mem.boot_id = state.boot_id
                mem.gen += 1
        if not state.ok:
            for info in plan.infos.values():
                if info.status == "pending":
                    info.status, info.reason = "failed", "device did not answer"
            return plan
        cc = CALLING_CODES.get(profile.preset, "")
        host_emu: list[identity_sim.RunningEmulator | None] = []

        def running() -> identity_sim.RunningEmulator | None:
            """Host facts about this emulator (read once per plan)."""
            if not host_emu:
                try:
                    host_emu.append(
                        identity_sim.running_emulator(
                            state.serial, state.props.get("ro.boot.qemu.avd_name", "")
                        )
                    )
                except Exception:
                    logger.debug("identity: SIM launch check failed", exc_info=True)
                    host_emu.append(None)
            return host_emu[0]

        for vid, vs in profile.values.items():
            info = plan.infos.get(vid)
            spec = vs.spec
            if (
                info is not None
                and spec is not None
                and info.status == "hook-only"
                and spec.providers == ("hook",)
            ):
                info.reason = (
                    spec.hook_reason if state.emulator else spec.device_hook_only
                )
            if info is None or spec is None or info.status != "pending":
                continue
            if spec.device_hook_only and not state.emulator:
                info.status, info.reason = "hook-only", spec.device_hook_only
                info.provider = info.mechanism = "hook"
                continue
            if spec.emulator_hook_only and state.emulator:
                # Not natively settable here: hook-only, not a failure.
                info.status, info.reason = "hook-only", spec.emulator_hook_only
                info.provider = info.mechanism = "hook"
                info.current = self._current(vs.kind, state, "", mem, vid)[0]
                network = state.props.get("gsm.operator.alpha", "")
                if (
                    vs.kind == "sim_operator"
                    and network
                    and network == identity_sim.operator_name(info.rendered)
                ):
                    info.reason += f", {NETWORK_OPERATOR_CARRIES}"
                continue
            if state.emulator and spec.emulator_mechanism:
                # Before the root check: the SIM is set when the emulator
                # starts, root only reads it back.
                self._plan_sim(profile, vs, info, state, plan, mem, cc, running)
                continue
            if spec.needs_root and not state.root:
                info.status, info.reason = "failed", NOT_ROOT
                continue
            if spec.needs_emulator and not state.emulator:
                info.status, info.reason = "skipped", "not an emulator"
                continue
            if spec.restart == "gms" and not state.gms:
                info.status, info.reason = "skipped", "no Google Play services"
                continue
            if vs.kind == "android_id":
                self._plan_ssaid(profile, vs, state, pkgs, plan, info)
                continue
            desired = info.rendered
            current, verified = self._current(vs.kind, state, desired, mem, vid, cc)
            info.current = current
            if verified:
                info.status = "verified"
            elif vs.kind == "gps" and mem.emu.get(vid) == desired:
                info.status, info.reason = "applied", "unverified"
            elif vs.kind == "app_set_id" and state.appset is None:
                info.status, info.reason = "skipped", "no App Set ID store yet"
            elif vs.kind == "build_model" and not state.resetprop:
                info.status, info.reason = "failed", NO_RESETPROP
            else:
                plan.steps.append(Step(vid, spec.restart, desired, current))
        for name, items in render_lists(profile).items():
            info = plan.infos.get(name)
            if info is None:
                continue
            if not state.root:
                info.status, info.reason = "failed", NOT_ROOT
                continue
            if name in state.lists_unread:
                # Inserting blind would duplicate rows that are there.
                info.status, info.reason = "pending", PROVIDER_DOWN
                continue
            stale, missing = self._list_diff(name, items, state, profile)
            found = len(items) - len(missing)
            info.current = f"{found}/{len(items)} on device"
            if stale or missing:
                plan.steps.append(
                    Step(name, "none", {"stale": stale, "missing": missing})
                )
            else:
                info.status = "verified"
        if state.emulator and state.ok:
            # The launch this plan checked (verified or toggled): an apply
            # marks it, so later app starts do not plan for it again.
            try:
                sim = identity_sim.sim_values(profile)
            except Exception:
                sim = None
            emu = running() if sim is not None else None
            if emu is not None and _started_with(emu.sim, sim):
                plan.sim_key = self._sim_key(state, emu)
        with self._lock:
            if mem.fingerprint == fp:
                # Root or resetprop may have come (or gone) since: a start
                # announces the restart again once it can apply the value.
                _learn_unappliable(mem, plan)
        return plan

    def sim_launch_changed(self, serial: str | None = None) -> None:
        """Forget the airplane-mode toggles of ``serial`` (``None``: all).

        Call it when the guest state was replaced without a new emulator
        launch (a snapshot load from the console, a cold boot): the guest
        has the old SIM cached again while boot id and launch token stay.
        """
        with self._lock:
            for store in (self._sim_toggles, self._sim_retry, self._sim_checked):
                for key in list(store):
                    if serial is None or key[0] == serial:
                        if isinstance(store, dict):
                            store.pop(key, None)
                        else:
                            store.discard(key)

    def _sim_key(
        self, state: DeviceState, emu: identity_sim.RunningEmulator | None
    ) -> tuple[str, str, str]:
        """One emulator launch: serial, guest boot id, host launch token."""
        return (state.serial, state.boot_id, emu.token if emu is not None else "")

    def _plan_sim(
        self,
        profile: Profile,
        vs: ValueSpec,
        info: ValueInfo,
        state: DeviceState,
        plan: IdentityPlan,
        mem: _Applied,
        cc: str,
        running: Callable[[], identity_sim.RunningEmulator | None],
    ) -> None:
        """Plan a SIM value on an emulator (set when the emulator starts).

        Reported by the guest: verified. The emulator started with it: one
        airplane-mode toggle per launch makes the guest read the card again
        (a snapshot keeps the old SIM cached), never while airplane mode is
        on; afterwards a mismatch fails and an unreadable value stays
        applied. Not started with it: pending when a restart from Sandroid
        sets it, else skipped with the reason. Only where a restart would not
        set it, the phone number falls back to ``adb emu phonenumber`` when
        it fits (that rewrites the AVD's host-side SIM profile file).
        """
        spec = REGISTRY[vs.kind]
        vid, desired = vs.id, info.rendered
        info.sim_launch = True
        current, verified = self._current(vs.kind, state, desired, mem, vid, cc)
        info.current = current
        info.mechanism = spec.emulator_mechanism
        if verified:
            info.status, info.reason = "verified", ""
            return
        emu = running()
        sim = emu.sim if emu is not None else None
        if vs.kind == "phone_number":
            want = identity_sim.msisdn_digits(desired, cc)[0]
            launched = sim is not None and bool(sim.msisdn) and sim.msisdn == want
        else:
            have = sim.value_of(vs.kind) if sim is not None else ""
            launched = bool(have) and have == desired
        if launched:
            readable = vs.kind == "sim_mccmnc" or state.sim_read
            key = self._sim_key(state, emu)
            with self._lock:
                toggled = self._sim_toggles.get(key)
                retry = key in self._sim_retry
            if toggled is not None:
                if toggled and state.root:
                    info.status, info.reason = "failed", f"airplane mode: {toggled}"
                elif toggled and readable:
                    info.status = "failed"
                    info.reason = (
                        "airplane mode could not be switched without root; the "
                        f"device still reports {current or 'nothing'}"
                    )
                elif toggled:
                    info.status, info.reason = "applied", SIM_TOGGLE_REFUSED
                elif readable:
                    info.status = "failed"
                    info.reason = (
                        f"the device still reports {current or 'nothing'} after "
                        "the airplane mode toggle"
                    )
                else:
                    info.status = "applied"
                    info.reason = SIM_NOT_READ if state.root else SIM_NOT_READ_ROOT
            elif state.settings.get("airplane_mode_on") == "1":
                info.status, info.reason = "applied", SIM_AIRPLANE_ON
            else:
                plan.steps.append(Step(vid, "none", desired, current, via="sim"))
                if retry:
                    info.reason = SIM_TOGGLE_RETRY
            return
        if vs.kind == "phone_number" and mem.emu.get(vid) == desired:
            info.status, info.reason = "applied", ""
            info.sim_launch = False
            return
        try:
            blocker = identity_sim.restart_blocker(emu, profile)
        except (OSError, identity_sim.SimPatchError) as exc:
            logger.debug(f"identity: SIM restart check failed: {exc}")
            blocker = "the emulator's system image could not be read"
        if (
            blocker
            and vs.kind == "phone_number"
            and _ascii_digits(desired)
            and len(desired) <= 11
        ):
            # A restart would not set it: adb emu phonenumber (at most 11
            # digits, no '+'). Never when a restart can: the emulator writes
            # the number into the AVD's modem_simulator/iccprofile_for_sim0.xml
            # on the host, which the SIM launch hook would have to undo.
            info.sim_launch = False
            plan.steps.append(Step(vid, "none", desired, current))
            return
        if blocker:
            info.status, info.reason = "skipped", blocker
        else:
            info.status, info.reason = "pending", NEEDS_EMULATOR_START

    def _plan_ssaid(
        self,
        profile: Profile,
        vs: ValueSpec,
        state: DeviceState,
        pkgs: tuple[str, ...],
        plan: IdentityPlan,
        info: ValueInfo,
    ) -> None:
        if not pkgs:
            info.status, info.reason = "pending", "no target app yet"
            return
        if not state.ssaid_xml:
            info.status, info.reason = "failed", "cannot read settings_ssaid.xml"
            return
        desired: dict[str, dict[str, Any]] = {}
        all_ok = True
        for pkg in pkgs:
            pinfo = state.packages.get(pkg)
            row = state.ssaid.get(pkg)
            with self._lock:
                mem = self._applied.setdefault(state.serial, _Applied())
                before = mem.befores.setdefault(f"ssaid:{pkg}", row[1] if row else "")
            entry = {"before": before}
            if pinfo is None or pinfo.uid is None:
                entry.update(status="pending", reason="not installed")
                all_ok = False
            else:
                value = self._ssaid_value(profile, vs, pkg, pinfo)
                if value is None:
                    entry.update(status="failed", reason="signer not found")
                    all_ok = False
                else:
                    entry.update(value=value, uid=str(pinfo.uid), signer=pinfo.signer)
                    ok = (
                        row is not None and row[1] == value and row[0] == str(pinfo.uid)
                    )
                    entry["status"] = "verified" if ok else "pending"
                    if not ok:
                        desired[pkg] = entry
                        all_ok = False
            info.per_app[pkg] = {k: str(v) for k, v in entry.items()}
        info.current = ", ".join(
            f"{p}={(state.ssaid.get(p) or ('', '-'))[1]}" for p in pkgs
        )
        if desired:
            plan.steps.append(Step(vs.id, "framework", desired))
        elif all_ok:
            info.status = "verified"
        else:
            bad = [e for e in info.per_app.values() if e["status"] == "failed"]
            info.status = "failed" if bad else "pending"
            info.reason = (bad or list(info.per_app.values()))[0].get("reason", "")

    @staticmethod
    def _ssaid_value(
        profile: Profile, vs: ValueSpec, pkg: str, pinfo: PackageInfo
    ) -> str | None:
        if vs.value is not None or vs.template is not None:
            return render_value(profile, vs)
        if vs.scope == "package":
            return ssaid_for(profile.token, profile.seed_bytes, f"package:{pkg}")
        if not pinfo.signer:
            return None
        return ssaid_for(profile.token, profile.seed_bytes, pinfo.signer)

    @staticmethod
    def _current(
        kind: str,
        state: DeviceState,
        desired: str,
        mem: _Applied,
        vid: str,
        cc: str = "",
    ) -> tuple[str, bool]:
        """``(current device value, it equals the desired one)``.

        ``cc``: the profile's country calling code (a national phone number
        matches its international form).
        """
        p = state.props
        current = {
            "device_name": state.settings.get("device_name", ""),
            "timezone": p.get("persist.sys.timezone", ""),
            "locale": p.get("persist.sys.locale", ""),
            "sim_operator": p.get("gsm.sim.operator.alpha", ""),
            "sim_mccmnc": p.get("gsm.sim.operator.numeric", ""),
            "build_model": p.get("ro.product.model", ""),
            "gaid": state.gaid,
        }.get(kind)
        if kind == "app_set_id":
            found = _UUID_BYTES_RE.findall(state.appset or b"")
            uniq = {f.decode() for f in found}
            current = ", ".join(sorted(uniq))
            return current, bool(uniq) and uniq == {desired}
        if kind == "gps":
            if state.location is None:
                return "", False
            lat, lon, _alt = split_gps(desired)
            here = state.location
            ok = abs(here[0] - float(lat)) < 2e-6 and abs(here[1] - float(lon)) < 2e-6
            return f"{here[0]}, {here[1]}", ok
        if kind in ("imsi", "iccid"):
            current = state.sim.get(kind, "")
            return current, bool(current) and current == desired
        if kind == "phone_number":
            number = state.sim.get("msisdn", "")
            if not number:
                return mem.emu.get(vid, ""), False
            have = "".join(c for c in number if c.isdigit())
            want = {
                "".join(c for c in desired if c.isdigit()),
                identity_sim.msisdn_digits(desired, cc)[0],
            }
            return number, bool(have) and have in want
        if current is None:
            return "", False
        if kind == "timezone" and state.settings.get("auto_time_zone") not in ("0", ""):
            return current, False
        return current, current == desired

    def _list_diff(
        self, name: str, items: list[dict], state: DeviceState, profile: Profile
    ) -> tuple[list[str], list[int]]:
        """``(stale device row ids, indexes of missing items)``."""
        tokens = [profile.token, *profile.retired_tokens]
        numbers = set(call_numbers(profile)) if name == "calls" else set()
        rows = [
            r
            for r in state.lists.get(name, [])
            if any(t in " ".join(r.values()) for t in tokens)
            or (numbers and _phone_digits(r.get("number")) in numbers)
        ]
        device = _device_list_items(name, rows)
        anchor = _list_anchor(profile)
        want: dict[tuple, int] = {}
        for i, item in enumerate(items):
            when = _item_date_ms(item, i, anchor) if name == "calls" else None
            want.setdefault(_list_sig(name, item, when), i)
        stale: list[str] = []
        have: set[tuple] = set()
        for rid, item in device.items():
            sig = _list_sig(name, item)
            if sig in want and sig not in have:
                have.add(sig)
            else:
                stale.append(rid)
        missing = [i for sig, i in want.items() if sig not in have]
        return stale, missing

    # -- apply --------------------------------------------------------------

    def apply(
        self,
        serial: str,
        package: str | None = None,
        allow_restart: bool | None = None,
        profile: Profile | None = None,
    ) -> IdentityPlan:
        """P0-P7 on ``serial`` (call from a worker thread).

        Args:
            serial: Device serial.
            package: The app about to start (its Android ID is seeded).
            allow_restart: Allow the framework restart window (every app
                stops). ``None`` follows ``identity.restart`` (``ask`` counts
                as allowed: the caller asked already).
            profile: Profile to apply (default: the active one).

        Returns:
            The final plan (``infos`` hold the statuses after verify).

        Raises:
            ProfileError: No profile, or it has validation errors.
        """
        profile = profile or self._require_profile()
        errors = [i for i in validate(profile) if i.severity == "error"]
        if errors:
            raise ProfileError(
                f"profile {profile.id!r} is invalid: {errors[0].path}: {errors[0].message}"
            )
        if allow_restart is None:
            allow_restart = self.config().restart != "never"
        with self._apply_lock:
            return self._apply(serial, package, allow_restart, profile)

    def _apply(
        self, serial: str, package: str | None, allow_restart: bool, profile: Profile
    ) -> IdentityPlan:
        dev = _Device(serial)
        pkgs = self._packages(serial, package)
        state = self.preflight(serial, pkgs, profile)
        self._call.device_ok = state.ok
        if state.ok and state.marker:
            self._recover(dev, state)
            state = self.preflight(serial, pkgs, profile)
        with self._lock:
            mem = self._applied.setdefault(serial, _Applied())
        if state.ok and not mem.befores_done:
            mem.befores.update(self._befores(profile, state))
            mem.befores_done = True
        pkgs = self._drop_uninstalled(mem, state, pkgs, package)
        plan = self._plan(profile, state, pkgs)
        if not plan.steps:
            self._finish(profile, plan, state, wrote=False, package=package)
            return plan
        self._emit(
            "apply",
            f"apply identity profile {profile.id!r} r{profile.revision}"
            f" ({', '.join(plan.todo)})",
            serial,
            package,
            data={
                "profile": profile.id,
                "revision": profile.revision,
                "fingerprint": plan.fingerprint,
                "todo": plan.todo,
                "restart": plan.restart,
            },
        )
        if not allow_restart:
            for step in [s for s in plan.steps if s.restart == "framework"]:
                info = plan.infos[step.value_id]
                info.status, info.reason = "pending", NEEDS_RESTART
            plan.steps = [s for s in plan.steps if s.restart != "framework"]
            if not plan.steps:
                self._finish(profile, plan, state, wrote=False, package=package)
                return plan
        steps = {s.value_id: s for s in plan.steps}
        # P3: live steps (SIM values: one airplane-mode toggle for all)
        sim = [s for s in plan.steps if s.via == "sim"]
        if sim:
            self._run_sim(dev, profile, state, sim, plan.infos, mem)
        for step in plan.steps:
            if step.restart == "none" and step.via != "sim":
                self._run_live(dev, profile, step, plan.infos[step.value_id], mem)
        # P4: Google Play services steps
        gms = [s for s in plan.steps if s.restart == "gms"]
        if gms:
            dev.shell(f"am force-stop {GMS}")
            for step in gms:
                self._run_gms(dev, state, step, plan.infos[step.value_id])
        # P5: one framework restart window
        fw = [s for s in plan.steps if s.restart == "framework"]
        left = self._time_left()
        if fw and left is not None and left < ENSURE_WINDOW_MIN_S:
            # ensure_applied: no window that would outlast the budget.
            for step in fw:
                info = plan.infos[step.value_id]
                info.status, info.reason = "pending", OUT_OF_TIME
                steps.pop(step.value_id, None)
            fw = []
        if fw:
            self._framework_window(dev, profile, state, fw, plan)
        # P6: verify with the same batched read
        state2 = self.preflight(serial, pkgs, profile)
        verified = self._plan(profile, state2, pkgs)
        state2, verified = self._await_providers(
            serial, pkgs, profile, state2, verified, steps, restarted=bool(fw)
        )
        for vid, info in plan.infos.items():
            after = verified.infos.get(vid)
            if after is None:
                continue
            if vid not in steps:
                # No step of its own; after the SIM toggle the device may
                # report something new for it too (the SIM operator name).
                if (
                    sim
                    and (after.sim_launch or info.kind == "sim_operator")
                    and after.current != info.current
                ):
                    info.current = after.current
                    info.status, info.reason = after.status, after.reason
                continue
            if info.status == "failed" or info.reason.startswith(NOT_RESTARTED):
                continue  # never written: the read-back says nothing new
            spec = REGISTRY.get(info.kind)
            mode = spec.verify if spec else "strict"
            if steps[vid].via == "sim":
                mode = "strict"
            info.current = after.current
            info.sim_launch = after.sim_launch
            if after.per_app:
                info.per_app = after.per_app
            if after.status == "verified":
                info.status, info.reason = "verified", ""
            elif (
                after.status in ("pending", "skipped", "failed", "applied")
                and after.reason
            ):
                info.status, info.reason = after.status, after.reason
            elif mode == "strict":
                info.status = "failed"
                info.reason = f"read-back mismatch: {after.current or 'empty'}"
            else:
                info.status = "applied"
                info.reason = "unverified" if mode == "soft" else ""
        counts = _counts(plan.infos)
        self._emit(
            "verify",
            "identity verify: " + ", ".join(f"{v} {k}" for k, v in counts.items()),
            serial,
            package,
            data={"counts": counts},
        )
        self._finish(profile, plan, state2, wrote=True, package=package)
        return plan

    def ensure_applied(
        self, serial: str, budget_s: float = 240.0
    ) -> IdentityPlan | None:
        """Device preparation: apply the active profile within ``budget_s``.

        For a worker thread when a device comes up (no dialog). Like
        :meth:`apply` without a package. Only ``identity.restart = "always"``
        opens a framework window here; under ``ask`` (the default) and
        ``never`` the framework values stay pending (:data:`NEEDS_RESTART`),
        so the first app start's pre-start step asks as usual. Already
        applied, it costs one preflight and writes nothing. The budget is a
        monotonic deadline: the provider and SIM waits end with it, and no
        framework window starts with less than :data:`ENSURE_WINDOW_MIN_S`
        left (those values stay pending, :data:`OUT_OF_TIME`). A window that
        started waits the full :data:`RESTART_TIMEOUT_S` for the framework.

        Args:
            serial: Device serial.
            budget_s: Seconds the whole preparation may take.

        Returns:
            None at once when identity mode is off or no profile is set,
            else the final plan (per-value results are its statuses).

        Raises:
            ProfileError: The profile cannot be loaded or is invalid.
            IdentityApplyError: The device did not answer at all, or another
                apply held the device past the budget.
        """
        cfg = self.config()
        if cfg.mode != "profile" or not cfg.profile:
            return None
        profile = self._require_profile()
        errors = [i for i in validate(profile) if i.severity == "error"]
        if errors:
            raise ProfileError(
                f"profile {profile.id!r} is invalid: {errors[0].path}: "
                f"{errors[0].message}"
            )
        deadline = self._clock() + max(0.0, budget_s)
        if not self._apply_lock.acquire(timeout=max(0.0, budget_s)):
            raise IdentityApplyError(
                "another identity apply is running (it outlasted the budget)"
            )
        self._call.deadline = deadline
        self._call.device_ok = None
        try:
            plan = self._apply(serial, None, cfg.restart == "always", profile)
            device_ok = self._call.device_ok
        finally:
            self._call.deadline = None
            self._call.device_ok = None
            self._apply_lock.release()
        if device_ok is False:
            raise IdentityApplyError(f"{serial} did not answer the identity read")
        return plan

    def _time_left(self) -> float | None:
        """Seconds left of this call's ``ensure_applied`` budget (None: no
        budget).
        """
        deadline = getattr(self._call, "deadline", None)
        return None if deadline is None else deadline - self._clock()

    def _deadline(self, seconds: float) -> float:
        """``seconds`` from now, capped to the ``ensure_applied`` budget."""
        end = self._clock() + seconds
        budget = getattr(self._call, "deadline", None)
        return end if budget is None else min(end, budget)

    def _capped(self, seconds: float, *, floor: float) -> float:
        """An adb timeout capped to the budget left (at least ``floor``)."""
        left = self._time_left()
        return seconds if left is None else max(floor, min(seconds, left))

    def _drop_uninstalled(
        self,
        mem: _Applied,
        state: DeviceState,
        pkgs: tuple[str, ...],
        package: str | None,
    ) -> tuple[str, ...]:
        """Forget apps seeded earlier that are not installed any more.

        They would keep the Android ID pending ("not installed"), so no app
        would ever be done. The app being started stays (its own status).
        """
        if not state.ok or not state.uids_read:
            return pkgs
        gone = {
            p
            for p in pkgs
            if p != package
            and (state.packages.get(p) is None or state.packages[p].uid is None)
        }
        if not gone:
            return pkgs
        logger.info(f"identity: no longer installed: {', '.join(sorted(gone))}")
        with self._lock:
            for p in gone:
                mem.ssaids.pop(p, None)
                mem.seeded.pop(p, None)
                mem.installs.pop(p, None)
                mem.done.discard(p)
            mem.gen += 1
        return tuple(p for p in pkgs if p not in gone)

    def _await_providers(
        self,
        serial: str,
        pkgs: tuple[str, ...],
        profile: Profile,
        state: DeviceState,
        verified: IdentityPlan,
        steps: dict[str, Step],
        *,
        restarted: bool,
    ) -> tuple[DeviceState, IdentityPlan]:
        """Re-read the written lists while their providers are not up.

        Right after a framework restart (or a boot) the contacts, SMS and
        call-log providers answer late: a read-back then finds nothing
        although the rows are there. Waits :data:`PROVIDER_WAITS_S` (about
        10 s) at most before the verify result stands.
        """

        def waiting(st: DeviceState, plan: IdentityPlan) -> bool:
            for name in LISTS:
                if name not in steps:
                    continue
                if name in st.lists_unread:
                    return True
                after = plan.infos.get(name)
                if restarted and after is not None and after.status != "verified":
                    return True
            return False

        deadline = self._deadline(PROVIDER_WAIT_DEADLINE_S)
        tokens = [profile.token, *profile.retired_tokens]
        script = lists_script(tokens, call_numbers(profile))
        for delay in PROVIDER_WAITS_S:
            if not waiting(state, verified):
                break
            if self._clock() + delay + 1.0 > deadline:
                break
            self._sleep(delay)
            left = deadline - self._clock()
            if left < 1.0:
                break
            # Lists only, with a short timeout: an overloaded device (ANRs
            # after the restart) must not hold an app start for minutes.
            out = _Device(serial).shell(
                script, timeout=min(PROVIDER_PROBE_TIMEOUT_S, left)
            )
            probe = parse_preflight(serial, out)
            if not probe.ok:
                logger.info("identity: provider probe got no answer; stop waiting")
                break
            state = replace(state, lists=probe.lists, lists_unread=probe.lists_unread)
            verified = self._plan(profile, state, pkgs)
        return state, verified

    def _befores(self, profile: Profile, state: DeviceState) -> dict[str, str]:
        out = {}
        mem = _Applied()
        for vid, vs in profile.values.items():
            if vs.kind == "android_id" or not vs.spec:
                continue
            if not state.emulator and vs.kind in ("imsi", "iccid", "phone_number"):
                continue  # a real phone's SIM identity is never recorded
            try:
                desired = render_value(profile, vs) or ""
                out[vid] = self._current(vs.kind, state, desired, mem, vid)[0]
            except (TemplateError, ValueError):
                continue
            if vs.kind == "phone_number" and not out[vid]:
                port = state.serial.rpartition("-")[2]
                out[vid] = f"1555521{port}" if port.isdigit() else ""
        return out

    def _recover(self, dev: _Device, state: DeviceState) -> None:
        """A restart window was interrupted: bring the framework back.

        The framework is down (the window broke off): ``start`` it and wait,
        whatever holds the app-start lifecycle lock (no app start gets far
        without it). The framework is up: the marker is stale unless it was
        written in this boot (its ``boot=``) before a system_server that is
        gone now (its ``pid=``), i.e. ``_end_window`` stopped waiting and
        the framework came back late, unrecovered. The Frida/proxy recovery
        (:attr:`_after_restart`) then holds the lifecycle lock like the
        window itself; refused, the marker stays for the next apply. A stale
        marker (another boot, the same system_server, or an older marker
        without these fields) is only removed.
        """
        from sandroid.services.app_start import AppStartError, lifecycle_lock

        boot, old_pid = _marker_fields(state.marker)
        stale = bool(state.system_server) and (
            not (boot and old_pid and boot == state.boot_id)
            or state.system_server == old_pid
        )
        if stale:
            logger.info(f"identity: removed a stale restart marker on {state.serial}")
            dev.shell(f"rm -f {RESTART_MARKER}")
            return
        self._emit(
            "restart",
            "identity: resuming an interrupted framework restart",
            state.serial,
            None,
            level="warn",
            data={"marker": state.marker[:200], "recovery": True},
        )
        if not state.system_server:
            dev.shell("start")
            if not self._wait_framework(dev, ""):
                return  # still down: the marker stays, the next apply resumes
        guard = contextlib.ExitStack()
        try:
            guard.enter_context(lifecycle_lock(0.0))
        except AppStartError as exc:
            logger.info(
                f"identity: Frida recovery after the framework restart on "
                f"{state.serial} left for the next apply: {exc}"
            )
            return
        with guard:
            self._after_restart(
                state.serial, int(old_pid) if old_pid.isdigit() else None
            )
            dev.shell(f"rm -f {RESTART_MARKER}")

    def _run_sim(
        self,
        dev: _Device,
        profile: Profile,
        state: DeviceState,
        steps: list[Step],
        infos: dict[str, ValueInfo],
        mem: _Applied,
    ) -> None:
        """Make the guest read the SIM card the emulator started with.

        Airplane mode on and off, once per emulator launch (a guest that
        loaded a snapshot keeps the SIM identity it had cached). Only planned
        while airplane mode is off, and it is switched off again on every
        path. Re-reads the readable SIM values until they match (at most
        :data:`SIM_WAIT_DEADLINE_S`); P6 verifies them.
        """
        cc = CALLING_CODES.get(profile.preset, "")
        try:
            emu = identity_sim.running_emulator(
                state.serial, state.props.get("ro.boot.qemu.avd_name", "")
            )
        except Exception:
            emu = None
        key = self._sim_key(state, emu)
        self._emit(
            "sim",
            "identity: airplane mode on and off so the emulator reads its SIM "
            f"card again ({', '.join(s.value_id for s in steps)})",
            state.serial,
            None,
            data={"values": [s.value_id for s in steps]},
        )
        err = _TOGGLE_INTERRUPTED
        try:
            err = self._check(
                dev.shell(
                    "cmd connectivity airplane-mode enable && sleep 2"
                    f" && cmd connectivity airplane-mode disable && echo {_OK}"
                )
            )
            readable = [
                s
                for s in steps
                if infos[s.value_id].kind == "sim_mccmnc" or state.sim_read
            ]
            deadline = self._deadline(SIM_WAIT_DEADLINE_S)
            for delay in SIM_WAITS_S if readable and not err else ():
                if self._clock() + delay + 1.0 > deadline:
                    break
                self._sleep(delay)
                left = deadline - self._clock()
                if left < 1.0:
                    break
                probe = parse_preflight(
                    state.serial, dev.shell(sim_script(), timeout=min(30.0, left))
                )
                if not probe.ok:
                    continue
                now = replace(
                    state,
                    props={**state.props, **probe.props},
                    sim=probe.sim,
                    sim_read=probe.sim_read,
                )
                if all(
                    self._current(
                        infos[s.value_id].kind, now, s.desired, mem, s.value_id, cc
                    )[1]
                    for s in readable
                ):
                    break
        finally:
            with self._lock:
                if err in (_NO_ANSWER, _TOGGLE_INTERRUPTED) and key not in (
                    self._sim_retry
                ):
                    # No answer (adb timeout, dropped link): one more try on
                    # the next apply, not this launch's final result.
                    self._sim_retry.add(key)
                else:
                    self._sim_toggles[key] = err
                    self._sim_retry.discard(key)  # the result is final now
            if err:
                # Back to off (it was off) whatever failed.
                try:
                    dev.shell("cmd connectivity airplane-mode disable")
                except Exception:
                    logger.warning(
                        "identity: could not switch airplane mode off again",
                        exc_info=True,
                    )
        for step in steps:
            infos[step.value_id].status, infos[step.value_id].reason = "applied", ""

    def _run_live(
        self, dev: _Device, profile: Profile, step: Step, info: ValueInfo, mem: _Applied
    ) -> None:
        kind, value = info.kind, step.desired
        err = ""
        if kind == "device_name":
            err = self._check(
                dev.shell(f"settings put global device_name {_q(value)} && echo {_OK}")
            )
        elif kind == "timezone":
            err = self._check(
                dev.shell(
                    f"settings put global auto_time_zone 0 && cmd alarm set-timezone {_q(value)}"
                    f" && echo {_OK}"
                )
            )
        elif kind == "sim_operator":
            err = self._check(
                dev.shell(f"setprop gsm.sim.operator.alpha {_q(value)} && echo {_OK}")
            )
        elif kind == "sim_mccmnc":
            err = self._check(
                dev.shell(f"setprop gsm.sim.operator.numeric {_q(value)} && echo {_OK}")
            )
        elif kind == "phone_number":
            out, e = dev.emu(f"phonenumber {value}")
            err = "" if "OK" in out else f"emu phonenumber: {(e or out).strip()[:120]}"
            if not err:
                with self._lock:
                    mem.emu[step.value_id] = value
        elif kind == "gps":
            lat, lon, alt = split_gps(value)
            out, e = dev.emu(f"geo fix {_nmea_pad(lon)} {_nmea_pad(lat)} {alt}")
            err = "" if "OK" in out else f"emu geo fix: {(e or out).strip()[:120]}"
            if not err:
                with self._lock:
                    mem.emu[step.value_id] = value
        elif kind in LISTS:
            err = self._run_list(dev, profile, kind, step.desired)
        else:
            err = f"no native mechanism for {kind}"
        info.status, info.reason = ("failed", err) if err else ("applied", "")

    @staticmethod
    def _check(out: str) -> str:
        return "" if _OK in out else (out.strip()[:160] or "no answer")

    def _run_list(self, dev: _Device, profile: Profile, name: str, diff: dict) -> str:
        """Delete stale rows and insert missing items of list ``name``.

        Every row is one ``&&`` chain; a chain that breaks echoes
        :data:`_LIST_FAIL` with its item, and the list fails naming them.
        """
        items = render_lists(profile)[name]
        anchor = _list_anchor(profile)
        lines = []
        uri, _proj, _col = _LIST_QUERY[name]

        def chain(label: str, steps: list[str]) -> None:
            lines.append(" && ".join(steps) + f" || echo {_q(_LIST_FAIL + label)}")

        for rid in diff["stale"]:
            if not _ascii_digits(str(rid)):
                continue
            if name == "contacts":
                target = f"{_RAW_CONTACTS}?caller_is_syncadapter=true"
            else:
                target = uri
            chain(
                f"{name} row {rid}",
                [f"content delete --uri {_q(target)} --where {_q(f'_id={rid}')}"],
            )
        for i in diff["missing"]:
            item = items[i]
            if name == "contacts":
                chain(f"{name}.{i}", _contact_steps(item))
            elif name == "sms":
                box = str(item.get("box", "inbox"))
                when = _item_date_ms(item, i, anchor)
                chain(
                    f"{name}.{i}",
                    [
                        f"content insert --uri content://sms/{box}"
                        f" --bind {_q('address:s:' + str(item['address']))}"
                        f" --bind {_q('body:s:' + str(item['body']))}"
                        f" --bind date:l:{when} --bind read:i:1"
                        f" --bind type:i:{_SMS_TYPES[box]}"
                    ],
                )
            else:
                ctype = _CALL_TYPES[str(item.get("type", "incoming"))]
                when = _item_date_ms(item, i, anchor)
                duration = _call_duration(item.get("duration")) or 0
                chain(
                    f"{name}.{i}",
                    [
                        "content insert --uri content://call_log/calls"
                        f" --bind {_q('number:s:' + str(item['number']))}"
                        f" --bind {_q('name:s:' + str(item.get('name') or ''))}"
                        f" --bind type:i:{ctype} --bind date:l:{when}"
                        f" --bind duration:i:{duration} --bind new:i:0"
                    ],
                )
        lines.append(f"echo {_OK}")
        out = dev.shell("\n".join(lines), zygote=True, timeout=120)
        failed = re.findall(re.escape(_LIST_FAIL) + r"(.+)", out)
        if failed:
            return "not written: " + ", ".join(f.strip() for f in failed)[:160]
        return self._check(out)

    def _run_gms(
        self, dev: _Device, state: DeviceState, step: Step, info: ValueInfo
    ) -> None:
        err = ""
        if info.kind == "gaid":
            xml = state.gaid_xml
            entry = f'<string name="adid_key">{step.desired}</string>'
            if re.search(r'<string name="adid_key">[^<]*</string>', xml):
                xml = re.sub(r'<string name="adid_key">[^<]*</string>', entry, xml)
                chown = ""
            elif "<map>" in xml:
                xml = xml.replace("<map>", f"<map>\n    {entry}", 1)
                chown = ""
            else:
                xml = (
                    "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
                    f"<map>\n    {entry}\n</map>\n"
                )
                chown = (
                    state.gaid_owner
                    if re.fullmatch(r"\d+:\d+", state.gaid_owner)
                    else ""
                )
            err = dev.write(GAID_FILE, xml.encode(), chown=chown, restorecon=True)
        elif info.kind == "app_set_id":
            data = _UUID_BYTES_RE.sub(step.desired.encode(), state.appset or b"")
            err = dev.write(APPSET_FILE, data, restorecon=True)
        info.status, info.reason = ("failed", err) if err else ("applied", "")

    def _framework_window(
        self,
        dev: _Device,
        profile: Profile,
        state: DeviceState,
        steps: list[Step],
        plan: IdentityPlan,
    ) -> None:
        from sandroid.services.app_start import AppStartError, lifecycle_lock

        # No app start may run across the restart (re-entrant: the pre-start
        # step of an app start already holds it on this thread).
        guard = contextlib.ExitStack()
        try:
            guard.enter_context(lifecycle_lock(0.0))
        except AppStartError as exc:
            for step in steps:
                info = plan.infos[step.value_id]
                info.status = "pending"
                info.reason = f"{NOT_RESTARTED}: {exc}"[:200]
            return
        with guard:
            self._framework_window_locked(dev, profile, state, steps, plan)

    def _framework_window_locked(
        self,
        dev: _Device,
        profile: Profile,
        state: DeviceState,
        steps: list[Step],
        plan: IdentityPlan,
    ) -> None:
        names = ", ".join(plan.infos[s.value_id].label for s in steps)
        self._emit(
            "restart",
            f"framework restart for {names}: every app stops",
            state.serial,
            None,
            level="warn",
            data={"values": [s.value_id for s in steps]},
        )
        stamp = (
            f"{plan.fingerprint} {int(time.time())} "
            f"{','.join(s.value_id for s in steps)} "
            f"boot={state.boot_id or '-'} pid={state.system_server or '-'}"
        )
        dev.shell(f"echo {_q(stamp)} > {RESTART_MARKER}")
        dev.shell("stop")
        error: BaseException | None = None
        try:
            for step in steps:
                info = plan.infos[step.value_id]
                err = self._framework_step(dev, state, step, info)
                info.status, info.reason = ("failed", err) if err else ("applied", "")
        except BaseException as exc:
            # The framework is down: whatever broke, it must come back up.
            error = exc
            for step in steps:
                info = plan.infos.get(step.value_id)
                if info is not None and info.status == "pending":
                    info.status = "failed"
                    info.reason = f"restart window aborted: {exc}"[:200]
        try:
            back = self._end_window(dev, state)
        except Exception:
            if error is None:
                raise
            logger.warning(
                "identity: framework restart after an aborted window failed",
                exc_info=True,
            )
            back = False
        if not back:
            for step in steps:
                info = plan.infos[step.value_id]
                if info.status == "applied":
                    info.status, info.reason = "failed", "framework did not come back"
        if error is not None:
            self._publish(plan)
            raise error

    def _framework_step(
        self, dev: _Device, state: DeviceState, step: Step, info: ValueInfo
    ) -> str:
        """One write while the framework is stopped (``""`` or the error)."""
        if info.kind == "android_id":
            current = dev.shell(
                f"abx2xml {SSAID_FILE} - 2>/dev/null || cat {SSAID_FILE}",
                zygote=True,
            )
            xml = _edit_ssaid(current or state.ssaid_xml, step.desired)
            if xml is None:
                return "cannot parse settings_ssaid.xml"
            return dev.write(SSAID_FILE, xml.encode(), abx=True)
        if info.kind == "locale":
            return self._check(
                dev.shell(
                    f"setprop persist.sys.locale {_q(step.desired)} && echo {_OK}"
                )
            )
        if info.kind == "build_model":
            return self._check(
                dev.shell(
                    f"resetprop ro.product.model {_q(step.desired)} && echo {_OK}"
                )
            )
        return f"no framework mechanism for {info.kind}"

    def _end_window(self, dev: _Device, state: DeviceState) -> bool:
        """``start`` the framework; drop the marker once it is back.

        Returns:
            True when a new system_server answers. Otherwise the marker
            stays, and the next apply resumes the restart.
        """
        dev.shell("start")
        if not self._wait_framework(dev, state.system_server):
            return False
        dev.shell(f"rm -f {RESTART_MARKER}")
        pid = state.system_server
        self._after_restart(state.serial, int(pid) if pid.isdigit() else None)
        return True

    def _wait_framework(self, dev: _Device, old_pid: str) -> bool:
        """Wait for a new system_server and a working package manager.

        Always the full :data:`RESTART_TIMEOUT_S`, also under an
        ``ensure_applied`` budget: the framework is down, and the budget
        only decides whether a window starts.
        """
        deadline = self._clock() + RESTART_TIMEOUT_S
        while self._clock() < deadline:
            out = dev.shell("pidof system_server; pm path android 2>/dev/null")
            lines = out.split()
            pid = lines[0] if lines and lines[0].isdigit() else ""
            if pid and pid != old_pid and "package:" in out:
                return True
            self._sleep(RESTART_POLL_S)
        return False

    # -- verify -------------------------------------------------------------

    def verify(self, serial: str, profile: Profile | None = None) -> IdentityPlan:
        """P6 alone: read back and refresh the statuses (no writes).

        Like :meth:`plan`, an apply that ran or runs during the read keeps
        its newer statuses (nothing is published then).
        """
        profile = profile or self._require_profile()
        pkgs = self._packages(serial, None)
        gen = self._gen(serial)
        state = self.preflight(serial, pkgs, profile)
        stale = self._gen(serial) != gen or self._apply_lock.locked()
        plan = self._plan(profile, state, pkgs)
        now = self._now()
        if state.ok and not stale:
            with self._lock:
                mem = self._applied.setdefault(serial, _Applied())
                if mem.fingerprint == plan.fingerprint:
                    mem.verified_at = now
        if not stale:
            self._publish(plan, now)
        counts = _counts(plan.infos)
        self._emit(
            "verify",
            "identity verify: " + ", ".join(f"{v} {k}" for k, v in counts.items()),
            serial,
            None,
            data={"counts": counts},
        )
        return plan

    # -- device record -------------------------------------------------------

    def last_apply(
        self, serial: str | None = None, fp: str | None = None
    ) -> tuple[float, float] | None:
        """When the profile was last applied and verified on ``serial``.

        Memory only (UI thread): every apply and verify of this process,
        whoever called it, and the device record's time after a TUI restart
        (read in the background, see :meth:`applied_state`).

        Args:
            serial: Device serial (default: the target device).
            fp: Only answer for this profile fingerprint.

        Returns:
            ``(applied_at, verified_at)`` in epoch seconds (``0.0`` = not
            known), or None when nothing is known.
        """
        if serial is None:
            from sandroid.core.adb import Adb

            serial = Adb.get_target_device()
        if not serial:
            return None
        if self.config().mode == "profile":
            self._ensure_hydrated(serial)
        with self._lock:
            mem = self._applied.get(serial)
            if mem is None or (fp is not None and mem.fingerprint != fp):
                return None
            if not (mem.applied_at or mem.verified_at):
                return None
            return mem.applied_at, mem.verified_at

    def forget(self, serial: str | None = None, *, restored: bool = False) -> None:
        """Memory of ``serial`` (default: every device) may be stale.

        Called after a snapshot load or cold boot (``restored``) and when the
        active device changes: the apply times are dropped and the device
        record is read again (in the background, or by the next app start).
        Never blocks.

        Args:
            serial: The device; None means every device.
            restored: The device state (and its record) was restored or
                rebooted, so a record that could not be rewritten is
                consistent again. A device switch keeps that mark.
        """
        with self._lock:
            serials = [serial] if serial else [*self._applied, *self._record_dirty]
            for s in serials:
                self._hydrated.discard(s)
                self._hydrate_tried.pop(s, None)
                if restored:
                    self._record_dirty.discard(s)
                mem = self._applied.get(s)
                if mem is not None:
                    mem.applied_at = mem.verified_at = 0.0
                    mem.gen += 1  # a read that started before is stale
                    mem.observed = False  # the record is the truth again
        self._notify_status()

    def _sim_due(self, serial: str, profile: Profile, read: _RecordRead | None) -> bool:
        """The emulator started with the profile's SIM and no apply checked it
        for this launch yet (a quickboot snapshot whose record already says
        done keeps the old SIM until the one airplane toggle), or a toggle
        got no answer and is retried. Host-side file reads only.
        """
        if read is None or not read.avd_name or not read.boot_id:
            return False
        try:
            sim = identity_sim.sim_values(profile)
            if sim is None:
                return False
            emu = identity_sim.running_emulator(serial, read.avd_name)
        except Exception:
            logger.debug("identity: SIM launch check failed", exc_info=True)
            return False
        if emu is None or not _started_with(emu.sim, sim):
            return False  # started with another SIM: a restart sets it, no toggle
        key = (serial, read.boot_id, emu.token)
        with self._lock:
            if key not in self._sim_checked:
                return True
            return key in self._sim_retry and key not in self._sim_toggles

    def _read_record(
        self, serial: str, package: str | None = None
    ) -> _RecordRead | None:
        """One cheap read of the device record (None when the device did not
        answer: any error, a timeout).
        """
        try:
            out = _Device(serial).shell(
                record_script(package), timeout=RECORD_READ_TIMEOUT_S
            )
        except Exception:
            logger.debug("identity: device record read failed", exc_info=True)
            return None
        sec = _sections(out or "")
        if "end" not in sec:
            return None
        install = sec.get("install", "")
        return _RecordRead(
            parse_applied_record(sec.get("applied", "")),
            sec.get("boot_id", ""),
            sec.get("marker", ""),
            install if re.fullmatch(r"\d+:\d+", install) else "",
            avd_name=sec.get("avd_name", "").strip(),
        )

    def _write_record(self, serial: str, record: dict[str, Any]) -> bool:
        """Write the device record atomically (True on success).

        When the write fails the record is removed (the device then reads
        as unknown); when even that fails, the record is marked dirty and
        hydration ignores it until a write succeeds.
        """
        data = (json.dumps(record, indent=1, sort_keys=True) + "\n").encode()
        dev = _Device(serial)
        try:
            err = dev.write(APPLIED_FILE, data, chown=APPLIED_OWNER)
        except Exception as exc:
            err = str(exc) or type(exc).__name__
        if not err:
            with self._lock:
                mem = self._applied.get(serial)
                if mem is not None:
                    mem.record_sig = _record_sig(record)
                self._record_dirty.discard(serial)
            return True
        logger.warning(f"identity: device record not written: {err}")
        try:
            removed = _OK in dev.shell(
                f"rm -f {APPLIED_FILE} && echo {_OK}", timeout=RECORD_READ_TIMEOUT_S
            )
        except Exception:
            removed = False
        with self._lock:
            mem = self._applied.get(serial)
            if mem is not None:
                mem.record_sig = ""
            if removed:
                self._record_dirty.discard(serial)
            else:
                logger.warning("identity: stale device record ignored until rewritten")
                self._record_dirty.add(serial)
        return False

    def _hydrate(self, serial: str, read: _RecordRead, gen: int) -> bool:
        """Replace what memory knows about ``serial`` by the device record.

        The record is the truth (a snapshot load restores the device and the
        record together; memory does not follow). Rule for a record from
        another boot (``boot_id`` differs): no package counts as fully
        applied any more (volatile values and the emulator console ones may
        be gone), and the volatile framework values are pending again; the
        Android IDs and the other framework values stay known (they are
        files and persistent properties).

        Args:
            serial: Device serial.
            read: What :meth:`_read_record` returned.
            gen: ``_Applied.gen`` before the read; when an apply changed
                memory since, memory is newer and stays.

        Returns:
            True when what callers see changed (status listeners heard it).
        """
        rec = read.record
        with self._lock:
            mem = self._applied.setdefault(serial, _Applied())
            if mem.gen != gen or self._apply_lock.locked():
                return False  # an apply is running or was: memory is newer
            if serial in self._record_dirty:
                return False  # the record may be stale: memory is newer
            self._hydrated.add(serial)
            before = _knowledge(mem)
            if read.boot_id and mem.boot_id not in ("", read.boot_id):
                mem.emu = {}
            if rec is None:
                mem.done, mem.seeded, mem.installs = set(), {}, {}
                mem.settled, mem.unappliable = {}, set()
                mem.applied_at = mem.verified_at = 0.0
                mem.record_sig = ""
            else:
                if rec["fingerprint"] == mem.fingerprint or not mem.fingerprint:
                    # Same profile (or nothing known): the markers may use them.
                    mem.ssaids.update(rec["ssaids"])
                if rec["fingerprint"] != mem.fingerprint:
                    mem.fingerprint, mem.emu = rec["fingerprint"], {}
                    mem.applied_at = mem.verified_at = 0.0
                    mem.observed = False
                same_boot = bool(read.boot_id) and rec["boot_id"] == read.boot_id
                mem.done = set(rec["done"]) if same_boot else set()
                mem.seeded = dict(rec["ssaids"])
                mem.installs = dict(rec["installs"])
                mem.settled = {
                    vid: bool(vol)
                    for vid, vol in rec["framework"].items()
                    if same_boot or not vol
                }
                # A value counts as unappliable only while both say so (a
                # later preflight may have found root or resetprop).
                unappliable = set(rec["unappliable"])
                if mem.observed:
                    unappliable &= mem.unappliable
                mem.unappliable = unappliable
                mem.record_sig = _record_sig(rec)
                mem.applied_at = max(mem.applied_at, float(rec["at"]))
                mem.verified_at = max(mem.verified_at, float(rec["verified_at"]))
            if read.boot_id:
                mem.boot_id = read.boot_id
            changed = before != _knowledge(mem)
        if changed:
            self._notify_status()
        return changed

    def _ensure_hydrated(self, serial: str) -> None:
        """Read the device record of ``serial`` once, in a daemon thread.

        Never blocks (UI thread). One read per serial at a time; a failed
        read is tried again after :data:`HYDRATE_RETRY_S`.
        """
        with self._lock:
            if serial in self._hydrated or serial in self._hydrating:
                return
            now = self._clock()
            tried = self._hydrate_tried.get(serial)
            if tried is not None and now - tried < HYDRATE_RETRY_S:
                return
            self._hydrate_tried[serial] = now
            self._hydrating.add(serial)
        thread = threading.Thread(
            target=self._hydrate_worker,
            args=(serial,),
            name=f"identity-record-{serial}",
            daemon=True,
        )
        try:
            thread.start()
        except Exception:
            logger.warning("identity: device record read not started", exc_info=True)
            with self._lock:
                self._hydrating.discard(serial)
            return
        with self._lock:
            if serial in self._hydrating:  # not finished already
                self._hydrate_threads[serial] = thread

    def _hydrate_worker(self, serial: str) -> None:
        try:
            with self._lock:
                mem = self._applied.get(serial)
                gen = mem.gen if mem is not None else 0
            read = self._read_record(serial)
            if read is not None:
                self._hydrate(serial, read, gen)
        except BaseException:
            # A background read never ends in an unhandled thread exception.
            logger.debug("identity: device record hydration failed", exc_info=True)
        finally:
            with self._lock:
                self._hydrating.discard(serial)
                self._hydrate_threads.pop(serial, None)

    def _join_hydration(self, timeout: float | None = None) -> None:
        """Wait for the running background record reads (tests)."""
        with self._lock:
            threads = list(self._hydrate_threads.values())
        for thread in threads:
            if thread.ident is not None:  # started
                thread.join(timeout)

    # -- P7 freeze ----------------------------------------------------------

    def _finish(
        self,
        profile: Profile,
        plan: IdentityPlan,
        state: DeviceState,
        *,
        wrote: bool,
        package: str | None,
    ) -> None:
        mem = self._applied[plan.serial]
        if plan.sim_key is not None:
            with self._lock:
                self._sim_checked.add(plan.sim_key)
        info = plan.infos.get("android_id")
        ssaids = dict(mem.ssaids)
        if info is not None:
            for pkg, entry in info.per_app.items():
                if entry.get("status") == "verified" and entry.get("value"):
                    ssaids[pkg] = entry["value"]
        # Done means really seeded: nothing failed or pending (also not a
        # framework value whose restart was declined or not allowed) and the
        # app's Android ID verified with this profile. A SIM value set at the
        # emulator's start does not keep the app from being done, failed or
        # waiting for an emulator restart: re-applying on every app start
        # cannot fix it.
        bad = [
            i
            for i in plan.infos.values()
            if (i.status == "failed" and not i.sim_launch)
            or (i.status == "pending" and i.reason != NEEDS_EMULATOR_START)
        ]
        wants_ssaid = info is not None and info.enabled and info.provider == "native"
        now = self._now()
        write = False
        with self._lock:
            mem.ssaids = ssaids
            if mem.fingerprint == plan.fingerprint:
                self._learn(mem, plan, state)
                seeded = not wants_ssaid or (package or "") in mem.seeded
                if package and not bad and seeded:
                    mem.done.add(package)
                elif package:
                    mem.done.discard(package)
                if state.ok:
                    mem.boot_id = state.boot_id
                    mem.applied_at = mem.verified_at = now
                mem.gen += 1
                record = applied_record(
                    plan.profile_id, plan.fingerprint, mem, mem.boot_id, now
                )
                write = state.ok and _record_sig(record) != mem.record_sig
        if write:
            self._write_record(plan.serial, record)
            with self._lock:
                mem.gen += 1  # a read that started before the write is stale
        self._publish(plan, now)
        digest = hashlib.sha256(
            json.dumps(
                [
                    plan.fingerprint,
                    sorted(ssaids.items()),
                    sorted((k, v.status) for k, v in plan.infos.items()),
                ]
            ).encode()
        ).hexdigest()
        if not state.ok or (not wrote and mem.frozen == digest):
            return
        markers = markers_for(profile, ssaids, package)
        path, sha = self._freeze(profile, plan, state, ssaids, markers, mem.befores)
        mem.frozen = digest
        with self._lock:
            changed = self._active is None or self._active != (
                plan.fingerprint,
                markers,
            )
            self._active = (plan.fingerprint, markers)
            self._loaded_frozen = True
        counts = _counts(plan.infos)
        ref = {"path": _timeline_rel(path), "sha256": sha} if path else None
        self._emit(
            "applied",
            f"identity {profile.id!r} r{profile.revision} applied: "
            + ", ".join(f"{v} {k}" for k, v in counts.items()),
            plan.serial,
            package,
            ref=ref,
            data={
                "profile": profile.id,
                "name": profile.name,
                "revision": profile.revision,
                "fingerprint": plan.fingerprint,
                "token": profile.token,
                "counts": counts,
                "values": {k: v.status for k, v in plan.infos.items()},
                "ssaid_packages": len(ssaids),
                "markers": len(markers),
            },
        )
        if changed:
            self._notify_markers()

    @staticmethod
    def _learn(mem: _Applied, plan: IdentityPlan, state: DeviceState) -> None:
        """What ``plan`` proves about the device: seeded Android IDs, settled
        and structurally unappliable framework values (lock held).
        """
        info = plan.infos.get("android_id")
        for pkg, entry in (info.per_app if info is not None else {}).items():
            if entry.get("status") == "verified" and entry.get("value"):
                mem.seeded[pkg] = entry["value"]
                if pkg in state.installs:
                    mem.installs[pkg] = state.installs[pkg]
                else:
                    mem.installs.pop(pkg, None)
            else:
                mem.seeded.pop(pkg, None)
                mem.installs.pop(pkg, None)
        _learn_unappliable(mem, plan)
        for vid, vinfo in plan.infos.items():
            spec = REGISTRY.get(vinfo.kind)
            if spec is None or spec.restart != "framework":
                continue
            if vinfo.kind == "android_id":  # per package: ``seeded``
                continue
            if vinfo.status in ("verified", "applied"):
                mem.settled[vid] = spec.volatile
            else:
                mem.settled.pop(vid, None)

    def _freeze(
        self,
        profile: Profile,
        plan: IdentityPlan,
        state: DeviceState,
        ssaids: dict[str, str],
        markers: list[Marker],
        befores: dict[str, str],
    ) -> tuple[Path | None, str]:
        try:
            from sandroid.core.timeline import timeline_folder

            folder = timeline_folder() / "identity"
            folder.mkdir(parents=True, exist_ok=True)
        except Exception:
            logger.warning(
                "identity: no session folder; ground truth not frozen", exc_info=True
            )
            return None, ""
        numbers = [
            int(m.group(1))
            for p in folder.glob("*.toml")
            if (m := re.match(r"(\d+)-", p.name))
        ]
        path = (
            folder
            / f"{max(numbers, default=0) + 1:03d}-{profile.id}-r{profile.revision}.toml"
        )
        record = frozen_record(profile, plan, state, ssaids, markers, befores)
        text = tomli_w.dumps(_tomlable(record))
        _atomic_write_text(path, text)
        return path, hashlib.sha256(text.encode()).hexdigest()

    def _publish(self, plan: IdentityPlan, now: float | None = None) -> None:
        """Stamp the plan's statuses (profile, fingerprint, time) and share."""
        now = time.time() if now is None else now
        for info in plan.infos.values():
            info.profile_id, info.fingerprint, info.at = (
                plan.profile_id,
                plan.fingerprint,
                now,
            )
        with self._lock:
            self._statuses = {
                k: replace(v, per_app=dict(v.per_app)) for k, v in plan.infos.items()
            }
        self._notify_status()

    @staticmethod
    def _emit(
        kind: str,
        summary: str,
        serial: str,
        package: str | None,
        *,
        data: dict | None = None,
        ref: dict | None = None,
        level: str = "info",
    ) -> None:
        try:
            from sandroid.core import timeline

            timeline.emit(
                "identity",
                kind,
                summary=summary,
                data=data,
                ref=ref,
                dev=serial,
                pkg=package,
                level=level,
            )
        except Exception:
            logger.debug("identity: timeline emit failed", exc_info=True)

    # -- pre-spawn hook -----------------------------------------------------

    def applied_state(self, package: str, serial: str | None = None) -> str | None:
        """Whether this process applied the active profile to ``package``.

        Read-only, no device access (the App lens polls it).

        Returns:
            None when identity mode is off or the profile is unusable;
            ``"applied"`` when ``package`` was fully applied on ``serial``
            (default: the target device) with the current profile's
            fingerprint; ``"not_applied"`` otherwise (also after a profile
            switch or a regenerate).
        """
        cfg = self.config()
        if cfg.mode != "profile" or not cfg.profile:
            return None
        try:
            fp = fingerprint(self.load(cfg.profile))
        except ProfileError:
            return None
        if serial is None:
            from sandroid.core.adb import Adb

            serial = Adb.get_target_device()
        if serial:
            # After a TUI restart the device record says what an earlier
            # process applied: read once in the background; the status
            # listeners hear when that changes the answer.
            self._ensure_hydrated(serial)
        with self._lock:
            mem = self._applied.get(serial) if serial else None
            done = mem is not None and mem.fingerprint == fp and package in mem.done
        return "applied" if done else "not_applied"

    def pre_start(self, package: str) -> Any:
        """The pre-spawn hook: a plan when ``package`` needs seeding, else None.

        Runs on the app-start worker (never the UI thread). The only device
        access is one cheap read of the device record
        (:meth:`_read_record`), which refreshes memory (a TUI restart or a
        snapshot load); without an answer the decision comes from memory.
        Idempotent: once an apply for the package succeeded with the current
        profile (and the device did not reboot since), it returns ``None``.
        The plan is ``disruptive`` only while a value that needs a framework
        restart is not known to be on the device.
        """
        cfg = self.config()
        if cfg.mode != "profile" or not cfg.profile:
            return None
        try:
            profile = self.load(cfg.profile)
        except ProfileError as exc:
            logger.warning(f"identity: active profile unusable: {exc}")
            return None
        from sandroid.core.adb import Adb

        serial = Adb.get_target_device()
        if not serial:
            return None
        fp = fingerprint(profile)
        with self._lock:
            mem = self._applied.get(serial)
            gen = mem.gen if mem is not None else 0
        read = self._read_record(serial, package)
        if read is not None:
            self._hydrate(serial, read, gen)
        # An interrupted restart window: the next apply resumes it.
        recovery = read is not None and bool(read.marker)
        with self._lock:
            mem = self._applied.get(serial)
            ours = mem is not None and mem.fingerprint == fp
            if (
                ours
                and read is not None
                and read.install  # "" = not readable here (no root): unknown
                and package in mem.seeded
                and mem.installs.get(package) != read.install
            ):
                # Reinstalled: a new Android ID, nothing done.
                mem.done.discard(package)
                mem.seeded.pop(package, None)
                mem.installs.pop(package, None)
            # Without an answer from the device the memory may be stale (a
            # snapshot load, a reinstall): apply rather than skip.
            skip = ours and package in mem.done and not recovery and read is not None
            seeded = ours and package in mem.seeded
            settled = set(mem.settled) if ours else set()
            unappliable = set(mem.unappliable) if ours else set()
        if skip and not self._sim_due(serial, profile, read):
            return None
        # Only values a restart can really apply here count.
        needs_fw = recovery or any(
            vs.enabled
            and vs.effective_provider == "native"
            and vs.spec is not None
            and vs.spec.restart == "framework"
            and vid not in unappliable
            and (not seeded if vs.kind == "android_id" else vid not in settled)
            for vid, vs in profile.values.items()
        )
        allow = cfg.restart != "never"

        def run() -> None:
            # Never an unannounced restart: a value that turns out to need
            # one stays pending (the app is not done) and the next start asks.
            plan = self.apply(
                serial, package, allow_restart=allow and needs_fw, profile=profile
            )
            # A failed SIM value (set at the emulator's start) never blocks.
            failed = [
                i
                for i in plan.infos.values()
                if i.status == "failed" and not i.sim_launch
            ]
            if failed:
                raise IdentityApplyError(
                    f"identity profile {profile.id!r}: {failed[0].label}: {failed[0].reason}"
                )
            if allow and any(
                i.status == "pending"
                and (i.reason == NEEDS_RESTART or i.reason.startswith(NOT_RESTARTED))
                for i in plan.infos.values()
            ):
                # Starting now would show the app its real values (it may
                # cache them); the next start announces the restart.
                raise IdentityApplyError(NEEDS_RESTART_AT_START)

        return _pre_start_plan_cls()(
            description=f"apply identity profile {profile.id}",
            disruptive=needs_fw and allow,
            apply=run,
        )

    def install_pre_start_step(self) -> bool:
        """Register :meth:`pre_start` with ``services.app_start`` (once).
        Returns True.
        """
        from sandroid.services.app_start import register_pre_start_step

        with self._lock:
            if self._hook_installed:
                return True
            register_pre_start_step(self.pre_start)
            self._hook_installed = True
        return True

    def uninstall_pre_start_step(self) -> None:
        """Undo :meth:`install_pre_start_step`."""
        from sandroid.services.app_start import unregister_pre_start_step

        with self._lock:
            if self._hook_installed:
                unregister_pre_start_step(self.pre_start)
                self._hook_installed = False

    # Deprecated aliases (one round, until every caller uses the pre-start names).
    pre_spawn = pre_start
    install_pre_spawn_hook = install_pre_start_step
    uninstall_pre_spawn_hook = uninstall_pre_start_step


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _regenerate(profile: Profile, *, retire: bool) -> None:
    old = profile.token
    profile.token = secrets.token_hex(4)
    profile.seed = "hex:" + secrets.token_hex(32)
    if retire and old and old not in profile.retired_tokens:
        profile.retired_tokens = [*profile.retired_tokens, old][-10:]
    if old:
        for vs in profile.values.values():
            if vs.value is not None:
                vs.value = vs.value.replace(old, profile.token)
        for items in profile.lists().values():
            for item in items:
                for key, val in item.items():
                    if isinstance(val, str):
                        item[key] = val.replace(old, profile.token)


def _canonical(profile: Profile) -> str:
    data = profile.to_dict()
    data.pop("revision", None)
    return json.dumps(data, sort_keys=True, default=str)


def _nmea_pad(coord: str) -> str:
    """Append ``0001``: the emulator truncates to 4 NMEA minute decimals."""
    if "." not in coord:
        coord += ".0"
    return coord + "0001"


def _counts(infos: dict[str, ValueInfo]) -> dict[str, int]:
    out: dict[str, int] = {}
    for info in infos.values():
        out[info.status] = out.get(info.status, 0) + 1
    return out


def _marker_fields(marker: str) -> tuple[str, str]:
    """``(boot id, system_server PID)`` a restart marker was written with
    (``""`` each when it has none: an older marker).
    """
    boot = re.search(r"\bboot=(\S+)", marker or "")
    pid = re.search(r"\bpid=(\d+)", marker or "")
    value = boot.group(1) if boot else ""
    return ("" if value == "-" else value), (pid.group(1) if pid else "")


def _timeline_rel(path: Path) -> str:
    try:
        from sandroid.core.timeline import timeline_folder

        return os.path.relpath(path, timeline_folder())
    except ValueError:
        return str(path)


def _edit_ssaid(xml_text: str, desired: dict[str, dict[str, Any]]) -> str | None:
    """Set (or add) the SSAID rows of ``desired`` (``{pkg: {uid, value}}``).

    Other top-level elements (``<namespaceHashes />``) are written back as
    they were.
    """
    parsed = _settings_document(xml_text)
    if parsed is None:
        return None
    document, root = parsed
    rows = {r.get("package"): r for r in root.iter("setting") if r.get("package")}
    ids = [r.get("id") or "" for r in root.iter("setting")]
    # A malformed id is skipped (never reused: new ids only go up).
    next_id = max((int(i) for i in ids if re.fullmatch(r"-?[0-9]+", i)), default=0) + 1
    for pkg, entry in desired.items():
        if not entry.get("uid") or not entry.get("value"):
            return None
        row = rows.get(pkg)
        if row is None:
            row = ET.SubElement(root, "setting")
            row.set("id", str(next_id))
            next_id += 1
            row.set("name", entry["uid"])
            row.set("package", pkg)
            row.set("defaultSysSet", "false")
            row.set("tag", "null")
        row.set("name", entry["uid"])
        row.set("value", entry["value"])
        row.set("defaultValue", entry["value"])
    top = list(document)
    for element in top:
        element.tail = "\n"
    body = "".join(ET.tostring(element, encoding="unicode") for element in top)
    return "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n" + body


def frozen_record(
    profile: Profile,
    plan: IdentityPlan,
    state: DeviceState,
    ssaids: dict[str, str],
    markers: list[Marker],
    befores: dict[str, str],
) -> dict[str, Any]:
    """The ground truth written to ``<session>/identity/NNN-<id>-r<rev>.toml``."""
    values = {}
    for vid, info in plan.infos.items():
        values[vid] = {
            "kind": info.kind,
            "label": info.label,
            "provider": info.provider,
            "status": info.status,
            "reason": info.reason,
            "rendered": info.rendered,
            "current": info.current,
            "before": befores.get(vid, ""),
        }
    ssaid_info = plan.infos.get("android_id")
    per_app = ssaid_info.per_app if ssaid_info else {}
    return {
        "format": "sandroid-identity-applied",
        "schema": 1,
        "applied_at": datetime.now().astimezone().replace(microsecond=0),
        "device": {
            "serial": state.serial,
            "avd": state.props.get("ro.boot.qemu.avd_name", ""),
            "api": state.api,
            "emulator": state.emulator,
            "root": state.root,
        },
        "fingerprint": plan.fingerprint,
        "packages": list(plan.packages),
        "values": values,
        "ssaid": {
            pkg: {
                "value": value,
                **{
                    k: v
                    for k, v in per_app.get(pkg, {}).items()
                    if k in ("uid", "signer", "before")
                },
            }
            for pkg, value in sorted(ssaids.items())
        },
        "lists": render_lists(profile),
        "markers": [
            {
                "id": m.id,
                "value": m.value,
                "kind": m.kind,
                "label": m.label,
                "forms": list(m.forms),
                "group": m.group,
                "tag": m.tag,
            }
            for m in markers
        ],
        "profile": profile.to_dict(),
    }


def _tomlable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _tomlable(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [_tomlable(v) for v in value if v is not None]
    if isinstance(value, bytes):
        return value.hex()
    return value


#: Frozen apply records of other sessions looked at, at most (newest first).
STARTUP_RECORDS_MAX = 200


def _frozen_markers(data: dict[str, Any]) -> list[Marker]:
    """The markers of a frozen apply record.

    Older records gave the applied app's Android ID the plain id
    (``android_id``): it gets its per-app id (``android_id@<package>``), so
    a marker id stays the same for its value across applies.
    """
    entries = data.get("ssaid") or {}
    value_of = (
        {
            str(pkg): str(entry.get("value"))
            for pkg, entry in entries.items()
            if isinstance(entry, dict) and entry.get("value")
        }
        if isinstance(entries, dict)
        else {}
    )

    def stable(m: dict[str, Any]) -> str:
        mid = str(m["id"])
        value = str(m["value"])
        if "@" in mid or m.get("kind") != "hex_id":
            return mid
        # The applied app (its label names it, "Android ID (<pkg>)"), which
        # wins when apps share a value; else the first app with the value.
        label = re.search(r"\(([^()\s]+)\)\s*$", str(m.get("label") or ""))
        if label and value_of.get(label.group(1)) == value:
            return f"{mid}@{label.group(1)}"
        pkg = next((p for p in sorted(value_of) if value_of[p] == value), None)
        return f"{mid}@{pkg}" if pkg else mid

    return [
        Marker(
            stable(m),
            m["value"],
            m.get("kind", "text"),
            m.get("label", ""),
            tuple(m.get("forms") or ()),
            m.get("group", ""),
            m.get("tag", ""),
        )
        for m in data.get("markers") or []
    ]


def _read_frozen(path: Path) -> dict[str, Any] | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def read_frozen_markers(path: Path | str) -> tuple[str, list[Marker]] | None:
    """``(fingerprint, markers)`` of a frozen apply record (the ``ref`` of an
    ``identity/applied`` line), or None when it cannot be read. File I/O.
    """
    data = _read_frozen(Path(path))
    if data is None:
        return None
    try:
        return str(data.get("fingerprint") or ""), _frozen_markers(data)
    except (KeyError, TypeError):
        return None


def _load_latest_frozen() -> tuple[str, list[Marker]] | None:
    """The newest frozen apply of the live session (after a TUI restart)."""
    try:
        from sandroid.core.timeline import timeline_folder

        folder = timeline_folder() / "identity"
        files = sorted(folder.glob("[0-9]*.toml")) if folder.is_dir() else []
    except Exception:
        return None
    for path in reversed(files):
        data = _read_frozen(path)
        if data is None:
            continue
        try:
            return str(data.get("fingerprint") or ""), _frozen_markers(data)
        except (KeyError, TypeError):
            continue
    return None


def _latest_frozen_elsewhere(profile_id: str) -> dict[str, Any] | None:
    """The newest frozen apply of ``profile_id`` on this device in another
    session (``<results>/<session>/<device folder>/identity/*.toml``).
    """
    try:
        from sandroid.core.timeline import timeline_folder

        here = timeline_folder()
        pattern = f"*/{glob_escape(here.name)}/identity/[0-9]*.toml"
        files = [p for p in here.parent.parent.glob(pattern) if p.parent.parent != here]
    except Exception:
        return None

    def mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    for path in sorted(files, key=mtime, reverse=True)[:STARTUP_RECORDS_MAX]:
        data = _read_frozen(path)
        profile = (data or {}).get("profile") or {}
        if isinstance(profile, dict) and profile.get("id") == profile_id:
            return data
    return None


def startup_markers(profile: Profile) -> tuple[str, list[Marker]]:
    """``(fingerprint, markers)`` of ``profile`` without an apply in this
    session (a TUI restart with the mode on): nothing is applied to the
    device.

    The values come from the profile itself. An Android ID is per app and
    signing certificate (``ssaid_for(token, seed, signer)``), so it needs the
    app's signer: that comes from the newest apply of this profile on this
    device in another session. When that apply had the same fingerprint its
    markers are used as they are.
    """
    fp = fingerprint(profile)
    record = _latest_frozen_elsewhere(profile.id)
    if record is not None and str(record.get("fingerprint") or "") == fp:
        try:
            return fp, _frozen_markers(record)
        except (KeyError, TypeError):
            pass
    ssaids: dict[str, str] = {}
    primary = None
    vs = profile.values.get("android_id")
    entries = (record or {}).get("ssaid") or {}
    if vs is not None and vs.enabled and isinstance(entries, dict):
        # The applied app's Android ID: listed first (older records: the
        # plain id).
        applied_primary = next(
            (
                m.get("value")
                for m in (record or {}).get("markers") or []
                if isinstance(m, dict)
                and str(m.get("id") or "").partition("@")[0] == vs.id
            ),
            None,
        )
        for pkg, entry in sorted(entries.items()):
            if not isinstance(entry, dict):
                continue
            pinfo = PackageInfo(pkg, None, str(entry.get("signer") or ""))
            try:
                value = IdentityService._ssaid_value(profile, vs, pkg, pinfo)
            except (TemplateError, ValueError):
                value = None
            if value:
                ssaids[pkg] = value
                if entry.get("value") == applied_primary:
                    primary = pkg
    return fp, markers_for(profile, ssaids, primary)


def get_identity_service() -> IdentityService:
    """The process's :class:`IdentityService` (reset by ``reset_services``)."""
    from sandroid.services import _get_or_create

    return _get_or_create(IdentityService)


__all__ = [
    "CALLING_CODES",
    "FORMAT",
    "LISTS",
    "REGISTRY",
    "SCHEMA",
    "DeviceState",
    "IdentityApplyError",
    "IdentityPlan",
    "IdentityService",
    "Issue",
    "KindSpec",
    "Profile",
    "ProfileError",
    "ProfileInfo",
    "TemplateError",
    "ValueInfo",
    "ValueSpec",
    "fingerprint",
    "frozen_record",
    "generate_profile",
    "get_identity_service",
    "luhn_check_digit",
    "luhn_ok",
    "markers_for",
    "parse_preflight",
    "preflight_script",
    "profiles_dir",
    "read_frozen_markers",
    "render_lists",
    "render_template",
    "render_value",
    "ssaid_for",
    "token_uuid",
    "validate",
]
