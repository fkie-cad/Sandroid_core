"""Emulator SIM identity: IMSI, ICCID, MSISDN and network operator at launch.

The emulator's modem simulator reads the SIM card from
``<sysdir>/data/misc/modem_simulator/iccprofile_for_sim0.xml`` and the
network operator names from ``.../etc/modem_simulator/files/
numeric_operator.xml``. On every launch (cold boot and snapshot load) it
copies that template over ``<avd dir>/modem_simulator/``, so patching the AVD
directory does nothing. What works is a private system image directory
passed with ``-sysdir``: symlinks to every entry of the real image directory
except ``data/``, which is a small real copy whose two modem files carry the
profile's values.

This module holds:

* pure helpers: the BCD encodings, the text patches of both XML files (by
  regular expression, so the files stay otherwise byte-identical), the
  parcel decoder of ``service call iphonesubinfo``;
* the private sysdir (one per AVD under the Sandroid cache directory, built
  next to its final place and renamed into it);
* the launch hooks of :mod:`sandroid.core.emulator`: :func:`pre_launch` adds
  ``-sysdir <private dir>`` when identity mode is on and the active profile
  has native SIM values; :func:`post_stop` removes that directory;
* :func:`running_sim`: the SIM values a running emulator was launched with
  (read from the copy the emulator made in its AVD directory).

A guest that loaded a snapshot keeps the SIM identity cached; toggling
airplane mode makes it read the card again (see
:meth:`sandroid.services.identity.IdentityService.apply`).
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.core.emulator import LaunchContext
    from sandroid.services.identity import Profile

logger = getLogger(__name__)

#: Value kinds the private sysdir sets natively on an emulator.
SIM_KINDS = ("imsi", "iccid", "phone_number", "sim_mccmnc")

#: The modem simulator's template directory inside a system image directory.
MODEM_DIR = Path("data/misc/modem_simulator")
ICC_PROFILE = "iccprofile_for_sim0.xml"
NUMERIC_OPERATOR = Path("etc/modem_simulator/files/numeric_operator.xml")
SYSDIR_FLAG = "-sysdir"
#: Sub-directory of the Sandroid cache directory holding one sysdir per AVD.
SYSDIR_CACHE = "identity-sysdir"
#: A ``.tmp-*`` build directory younger than this may be another process's
#: build in progress and is left alone.
TMP_MAX_AGE_S = 600.0

#: ``EF_MSISDN`` record without the alpha identifier: length, TON/NPI,
#: 10 BCD bytes, capability and extension identifiers.
_MSISDN_TAIL_BYTES = 14
_MSISDN_BCD_BYTES = 10
_TON_INTERNATIONAL = "91"
_TON_UNKNOWN = "81"


class SimPatchError(ValueError):
    """A modem simulator file does not have the structure this module knows."""


class SymlinkError(SimPatchError):
    """The host cannot create symlinks (e.g. Windows without the privilege)."""


@dataclass(frozen=True)
class SimValues:
    """SIM identity of an emulator (empty string = not set / unknown).

    Attributes:
        iccid: 19-20 digits.
        imsi: 14-15 digits.
        msisdn: The phone number's digits (no ``+``).
        msisdn_international: ``msisdn`` includes the country calling code
            (type of number "international"; the guest shows a ``+``).
        mccmnc: MCC and MNC (5-6 digits); its length gives the MNC length.
        operator: Network operator name (long and short), empty for none.
    """

    iccid: str = ""
    imsi: str = ""
    msisdn: str = ""
    msisdn_international: bool = True
    mccmnc: str = ""
    operator: str = ""

    @property
    def phone(self) -> str:
        """The phone number as the guest shows it (``+`` when international)."""
        if not self.msisdn:
            return ""
        return f"+{self.msisdn}" if self.msisdn_international else self.msisdn

    def value_of(self, kind: str) -> str:
        """The value of an identity kind (:data:`SIM_KINDS`), ``""`` if unset."""
        return {
            "imsi": self.imsi,
            "iccid": self.iccid,
            "phone_number": self.phone,
            "sim_mccmnc": self.mccmnc,
        }.get(kind, "")


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------


def swap_bcd(digits: str) -> str:
    """Swapped-nibble BCD of ``digits`` (``F``-padded to an even length).

    ``digits`` may already end in ``F`` padding.

    >>> swap_bcd("4915112345678")
    '945111325476F8'
    """
    if not re.fullmatch(r"[0-9]*F*", digits):
        raise ValueError(f"not digits: {digits!r}")
    padded = digits + "F" * (len(digits) % 2)
    return "".join(padded[i + 1] + padded[i] for i in range(0, len(padded), 2))


def unswap_bcd(hex_text: str) -> str:
    """Digits of a swapped-nibble BCD string (stops at the first ``F``)."""
    out = []
    for i in range(0, len(hex_text) - 1, 2):
        for nibble in (hex_text[i + 1], hex_text[i]):
            if nibble in "Ff":
                return "".join(out)
            if not nibble.isdigit():
                return "".join(out)
            out.append(nibble)
    return "".join(out)


def iccid_bcd(iccid: str) -> str:
    """``EF_ICCID`` content: 20 nibbles, ``F``-padded, swapped (10 bytes)."""
    if not (iccid.isascii() and iccid.isdigit() and len(iccid) in (19, 20)):
        raise ValueError("ICCID must be 19 or 20 digits")
    return swap_bcd(iccid + "F" * (20 - len(iccid)))


def msisdn_record(digits: str, *, international: bool, record_len: int = 28) -> str:
    """One ``EF_MSISDN`` record (hex): empty alpha, number, no extension.

    Args:
        digits: The number's digits (no ``+``), at most 20.
        international: Type of number international (``91``) or unknown
            (``81``).
        record_len: Record size in bytes (alpha length + 14).

    Raises:
        ValueError: Not 1-20 digits, or a record shorter than 14 bytes.
    """
    if not (digits.isascii() and digits.isdigit() and 1 <= len(digits) <= 20):
        raise ValueError("MSISDN must be 1-20 digits")
    if record_len < _MSISDN_TAIL_BYTES:
        raise ValueError(f"EF_MSISDN record of {record_len} bytes is too short")
    bcd = swap_bcd(digits)
    nbytes = len(bcd) // 2
    return (
        "FF" * (record_len - _MSISDN_TAIL_BYTES)
        + f"{nbytes + 1:02X}"
        + (_TON_INTERNATIONAL if international else _TON_UNKNOWN)
        + bcd
        + "FF" * (_MSISDN_BCD_BYTES - nbytes)
        + "FFFF"
    ).upper()


def decode_msisdn_record(hex_text: str) -> tuple[str, bool]:
    """``(digits, international)`` of an ``EF_MSISDN`` record (``""`` if empty)."""
    raw = hex_text.strip().upper()
    if len(raw) % 2 or len(raw) < 2 * _MSISDN_TAIL_BYTES:
        return "", False
    base = len(raw) - 2 * _MSISDN_TAIL_BYTES
    try:
        length = int(raw[base : base + 2], 16)
    except ValueError:
        return "", False
    if length in (0, 0xFF) or length - 1 > _MSISDN_BCD_BYTES:
        return "", False
    ton = raw[base + 2 : base + 4]
    digits = unswap_bcd(raw[base + 4 : base + 4 + 2 * (length - 1)])
    return digits, ton == _TON_INTERNATIONAL


def msisdn_digits(number: str, calling_code: str) -> tuple[str, bool]:
    """``(digits, international)`` of a profile phone number for the SIM.

    ``+49...`` and ``0049...`` are international already; a national number
    gets ``calling_code`` with one trunk ``0`` dropped; without a calling
    code the digits stay national.
    """
    text = number.strip()
    digits = "".join(c for c in text if c.isdigit())
    if text.startswith("+"):
        return digits, True
    if digits.startswith("00"):
        return digits[2:], True
    if calling_code:
        return calling_code + digits.removeprefix("0"), True
    return digits, False


def decode_parcel_string(text: str) -> str | None:
    """The string of a ``service call ... s16`` reply parcel.

    The reply is ``Result: Parcel(<hex words> '<ascii>')``: word 0 is the
    exception code, word 1 the UTF-16 length, then the characters
    (little-endian). Returns ``None`` for an exception, a null string or
    output that is not a parcel.
    """
    words = re.findall(r"(?:^|[\s:(])([0-9a-fA-F]{8})(?=\s|')", text, re.M)
    data = b"".join(int(w, 16).to_bytes(4, "little") for w in words)
    if len(data) < 8:
        return None
    if int.from_bytes(data[:4], "little", signed=True) != 0:
        return None
    count = int.from_bytes(data[4:8], "little", signed=True)
    if count < 0 or 8 + 2 * count > len(data):
        return None
    try:
        return data[8 : 8 + 2 * count].decode("utf-16-le")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------------------
# XML text patches (regular expressions: the files stay byte-identical
# apart from the patched values)
# ---------------------------------------------------------------------------


def _ef_block(name: str, ef_id: str) -> re.Pattern[str]:
    return re.compile(
        rf'(<EF\s+name="{name}"\s+id="{ef_id}"[^>]*>)(.*?)(</EF>)', re.S | re.I
    )


_ICCID_EF = _ef_block("EF_ICCID", "2FE2")
_IMSI_EF = _ef_block("EF_IMSI", "6F07")
_MSISDN_EF = _ef_block("EF_MSISDN", "6F40")
_AD_EF = _ef_block("EF_AD", "6FAD")
_ICCID_READ = re.compile(
    r'(<SIMIO\s+cmd="B0"\s+p1="0"\s+p2="0"\s+p3="A"\s+data="">144,0,)'
    r"[0-9A-Fa-f]{20}(</SIMIO>)"
)
_CCID = re.compile(r"(<CCID>)([0-9A-Fa-f]+)(</CCID>)")
_CIMI = re.compile(r"(<CIMI>)([0-9]+)(</CIMI>)")
_MSISDN_READ = re.compile(
    r'(<SIMIO\s+cmd="B2"\s+p1="1"\s+p2="4"\s+p3="([0-9A-Fa-f]+)"\s+data="">144,0,)'
    r"([0-9A-Fa-f]*)(</SIMIO>)"
)
_AD_READ = re.compile(
    r'(<SIMIO\s+cmd="B0"\s+p1="0"\s+p2="0"\s+p3="4"\s+data="">144,0,[0-9A-Fa-f]{6})'
    r"([0-9A-Fa-f]{2})(</SIMIO>)"
)


def _sub_in_block(
    text: str, block: re.Pattern[str], inner: re.Pattern[str], repl: Any, what: str
) -> str:
    """Replace ``inner`` exactly once inside the one ``block`` of ``text``."""
    blocks = list(block.finditer(text))
    if len(blocks) != 1:
        raise SimPatchError(f"{what}: expected one element, found {len(blocks)}")
    match = blocks[0]
    body, count = inner.subn(repl, match.group(2))
    if count != 1:
        raise SimPatchError(f"{what}: expected one value, found {count}")
    return text[: match.start(2)] + body + text[match.end(2) :]


def patch_iccprofile(text: str, values: SimValues) -> str:
    """``iccprofile_for_sim0.xml`` with the set fields of ``values``.

    ICCID: ``EF_ICCID`` read response (swapped BCD) and ``<CCID>`` (plain
    digits). IMSI: ``<CIMI>`` of ``EF_IMSI``. MNC length: last byte of
    ``EF_AD``. MSISDN: record 1 of ``EF_MSISDN``.

    Raises:
        SimPatchError: The template lacks one of these elements (another
            modem simulator version).
        ValueError: A value has the wrong format.
    """
    if values.iccid:
        bcd = iccid_bcd(values.iccid)
        text = _sub_in_block(
            text,
            _ICCID_EF,
            _ICCID_READ,
            lambda m: m.group(1) + bcd + m.group(2),
            "EF_ICCID read",
        )
        text = _sub_in_block(
            text,
            _ICCID_EF,
            _CCID,
            lambda m: m.group(1) + values.iccid + m.group(3),
            "EF_ICCID CCID",
        )
    if values.imsi:
        if not (values.imsi.isascii() and values.imsi.isdigit()):
            raise ValueError("IMSI must be digits")
        text = _sub_in_block(
            text,
            _IMSI_EF,
            _CIMI,
            lambda m: m.group(1) + values.imsi + m.group(3),
            "EF_IMSI",
        )
    if values.mccmnc:
        mnc_len = len(values.mccmnc) - 3
        if mnc_len not in (2, 3):
            raise ValueError("MCC/MNC must be 5 or 6 digits")
        text = _sub_in_block(
            text,
            _AD_EF,
            _AD_READ,
            lambda m: m.group(1) + f"{mnc_len:02X}" + m.group(3),
            "EF_AD",
        )
    if values.msisdn:

        def record(m: re.Match[str]) -> str:
            size = int(m.group(2), 16)
            body = msisdn_record(
                values.msisdn,
                international=values.msisdn_international,
                record_len=size,
            )
            return m.group(1) + body + m.group(4)

        text = _sub_in_block(text, _MSISDN_EF, _MSISDN_READ, record, "EF_MSISDN")
    return text


def read_iccprofile(text: str) -> SimValues:
    """The SIM values an ``iccprofile_for_sim0.xml`` carries (lenient)."""

    def inside(block: re.Pattern[str], inner: re.Pattern[str]) -> re.Match | None:
        match = block.search(text)
        return inner.search(match.group(2)) if match else None

    ccid = inside(_ICCID_EF, _CCID)
    cimi = inside(_IMSI_EF, _CIMI)
    ad = inside(_AD_EF, _AD_READ)
    msisdn = inside(_MSISDN_EF, _MSISDN_READ)
    imsi = cimi.group(2) if cimi else ""
    mccmnc = ""
    if ad and imsi:
        mnc_len = int(ad.group(2), 16)
        if mnc_len in (2, 3):
            mccmnc = imsi[: 3 + mnc_len]
    digits, international = (
        decode_msisdn_record(msisdn.group(3)) if msisdn else ("", False)
    )
    return SimValues(
        iccid=ccid.group(2).upper().rstrip("F") if ccid else "",
        imsi=imsi,
        msisdn=digits,
        msisdn_international=international,
        mccmnc=mccmnc,
    )


def operator_name(text: str) -> str:
    """``text`` made safe for a ``numeric_operator.xml`` item.

    The item text is ``Long=Short``: ``=`` and control characters go,
    whitespace runs collapse, at most 64 characters stay; the XML specials
    are escaped by :func:`patch_numeric_operator`.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f=]", " ", text)
    return re.sub(r"\s+", " ", cleaned).strip()[:64]


def _xml_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def patch_numeric_operator(text: str, mccmnc: str, name: str) -> str:
    """``numeric_operator.xml`` mapping ``mccmnc`` to ``name`` (long and short).

    An item for ``mccmnc`` is replaced; else a new item goes after the last
    one, with its indentation and line ending.

    Raises:
        SimPatchError: The file has no ``numeric_to_operator`` array.
        ValueError: ``mccmnc`` is not 5-6 digits.
    """
    if not re.fullmatch(r"[0-9]{5,6}", mccmnc):
        raise ValueError("MCC/MNC must be 5 or 6 digits")
    label = _xml_text(operator_name(name) or mccmnc)
    entry = f'<item numeric="{mccmnc}">{label}={label}</item>'
    existing = re.compile(rf'<item\s+numeric="{mccmnc}"\s*>[^<]*</item>')
    if existing.search(text):
        return existing.sub(lambda _m: entry, text, count=1)
    array = re.search(
        r'<string-array\s+name="numeric_to_operator"\s*>(.*?)([ \t]*)</string-array>',
        text,
        re.S,
    )
    if array is None:
        raise SimPatchError("numeric_operator.xml: no numeric_to_operator array")
    newline = "\r\n" if "\r\n" in text else "\n"
    items = list(re.finditer(r"([ \t]*)<item\b[^>]*>[^<]*</item>", array.group(1)))
    indent = items[-1].group(1) if items else array.group(2) + "    "
    if items:
        at = array.start(1) + items[-1].end()
        return text[:at] + newline + indent + entry + text[at:]
    at = array.start(2)
    return text[:at] + indent + entry + newline + text[at:]


# ---------------------------------------------------------------------------
# profile -> SIM values
# ---------------------------------------------------------------------------


def sim_values(profile: Profile) -> SimValues | None:
    """The SIM values of ``profile`` set at launch, ``None`` when it has none.

    Uses the enabled values of :data:`SIM_KINDS` whose provider is
    ``native``; an invalid profile gives ``None`` (logged). Without an IMSI
    value but with an MCC/MNC, the IMSI becomes the MCC/MNC followed by
    zeros (the SIM's MCC/MNC comes from its IMSI). The network operator
    name is the profile's SIM operator name (``sim_operator``) when it is
    enabled, else the MCC/MNC digits.
    """
    from sandroid.services import identity as ident

    errors = [i for i in ident.validate(profile) if i.severity == "error"]
    if errors:
        logger.warning(
            "identity SIM: profile %r is invalid (%s: %s); the emulator keeps "
            "its own SIM",
            profile.id,
            errors[0].path,
            errors[0].message,
        )
        return None
    native: dict[str, str] = {}
    rendered: dict[str, str | None] = {}
    operator = ""
    for vid, vs in profile.values.items():
        try:
            value = ident.render_value(profile, vs)
        except (ident.TemplateError, ValueError):
            continue
        rendered[vid] = value
        if not vs.enabled or not value or vs.effective_provider != "native":
            continue
        if vs.kind in SIM_KINDS:
            native.setdefault(vs.kind, value)
        elif vs.kind == "sim_operator" and not operator:
            operator = value
    if not native:
        return None
    imsi = native.get("imsi", "")
    mccmnc = native.get("sim_mccmnc", "")
    if not mccmnc and imsi:
        known = ident._mccmnc_of(profile, rendered)
        mccmnc = known if known and imsi.startswith(known) else ""
        if not mccmnc:
            # The MNC length (EF_AD) would be a guess: no SIM launch.
            logger.warning(
                "identity SIM: profile %r has an IMSI but no SIM MCC/MNC; the "
                "emulator keeps its own SIM",
                profile.id,
            )
            return None
    if mccmnc and not imsi:
        imsi = mccmnc + "0" * (15 - len(mccmnc))
    msisdn, international = "", True
    if native.get("phone_number"):
        cc = ident.CALLING_CODES.get(profile.preset, "")
        msisdn, international = msisdn_digits(native["phone_number"], cc)
    return SimValues(
        iccid=native.get("iccid", ""),
        imsi=imsi,
        msisdn=msisdn,
        msisdn_international=international,
        mccmnc=mccmnc,
        operator=operator,
    )


def _no_sim_reason(profile: Profile) -> str:
    """Why :func:`sim_values` gives ``None`` for ``profile`` (best effort)."""
    from sandroid.services import identity as ident

    if any(i.severity == "error" for i in ident.validate(profile)):
        return PROFILE_INVALID
    wanted = {
        vs.kind
        for vs in profile.values.values()
        if vs.enabled and vs.kind in SIM_KINDS and vs.effective_provider == "native"
    }
    if "imsi" in wanted and "sim_mccmnc" not in wanted:
        return MNC_UNKNOWN
    return NO_SIM_VALUE


def _active_sim() -> tuple[str, SimValues | None, str] | None:
    """The active profile: ``(id, SIM values, why none)``.

    ``None`` when identity mode is off. Otherwise the SIM values are
    ``None`` when the profile is unusable or sets no SIM at launch, with
    the reason as third item (``""`` when there are values).
    """
    from sandroid.services.identity import ProfileError, get_identity_service

    service = get_identity_service()
    cfg = service.config()
    if cfg.mode != "profile" or not cfg.profile:
        return None
    try:
        profile = service.load(cfg.profile)
    except ProfileError as exc:
        logger.warning(f"identity SIM: active profile unusable: {exc}")
        return (cfg.profile, None, f"{PROFILE_UNUSABLE}: {exc}")
    values = sim_values(profile)
    if values is None:
        return (profile.id, None, _no_sim_reason(profile))
    return (profile.id, values, "")


def active_sim_values() -> SimValues | None:
    """SIM values of the active profile; ``None`` when identity mode is off."""
    found = _active_sim()
    return found[1] if found is not None else None


# ---------------------------------------------------------------------------
# private sysdir
# ---------------------------------------------------------------------------


def cache_root() -> Path:
    """The configured ``paths.cache_path``, else ``~/.cache/sandroid``."""
    try:
        from sandroid.config import get_config

        configured = getattr(get_config().paths, "cache_path", None)
        if configured:
            return Path(configured).expanduser()
    except Exception as exc:
        logger.debug(f"identity SIM: cache path from config unavailable: {exc}")
    return Path("~/.cache/sandroid").expanduser()


def _safe_name(avd: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", avd).lstrip(".") or "avd"


def sysdir_path(avd: str) -> Path:
    """Where the private sysdir of AVD ``avd`` lives."""
    return cache_root() / SYSDIR_CACHE / _safe_name(avd)


def image_dir(avd_directory: Path) -> Path | None:
    """The system image directory of an AVD (``image.sysdir.1`` of its
    ``config.ini``, relative to the SDK root unless absolute), or ``None``.
    """
    from sandroid.core import emulator

    rel = emulator._read_ini(Path(avd_directory) / "config.ini").get(
        "image.sysdir.1", ""
    )
    if not rel:
        return None
    path = Path(rel).expanduser()
    if not path.is_absolute():
        root = emulator.sdk_root()
        if root is None:
            return None
        path = root / rel
    return path if path.is_dir() else None


def _onexc(func: Any, path: str, exc: BaseException) -> None:
    """``rmtree`` error handler: make a read-only directory writable, retry."""
    if not isinstance(exc, PermissionError):
        raise exc
    parent = Path(path).parent
    if not parent.is_symlink():
        parent.chmod(0o700)
    target = Path(path)
    if target.is_dir() and not target.is_symlink():
        target.chmod(0o700)
    func(path)


def _rmtree(path: Path) -> None:
    """Remove ``path`` (a symlink is unlinked, never followed).

    Read-only directories (a copy made from a read-only image) are made
    writable on the way.
    """
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        # rmtree unlinks the symlinks into the system image, never follows.
        shutil.rmtree(path, onexc=_onexc)


def _remove_leftovers(base: Path, name: str) -> None:
    """Remove ``.<name>.old-*`` and stale ``.<name>.tmp-*`` directories.

    A ``.tmp-*`` younger than :data:`TMP_MAX_AGE_S` may be another
    process's build in progress: it stays.
    """
    now = time.time()
    leftovers = list(base.glob(f".{name}.old-*"))
    for tmp in base.glob(f".{name}.tmp-*"):
        try:
            if now - tmp.lstat().st_mtime < TMP_MAX_AGE_S:
                continue
        except OSError:
            continue
        leftovers.append(tmp)
    for leftover in leftovers:
        try:
            _rmtree(leftover)
        except OSError as exc:
            logger.warning(f"identity SIM: cannot remove {leftover}: {exc}")


def _copy_data(src: Path, dest: Path) -> None:
    """Copy ``data/`` of the image as real files, owner-writable.

    Symlinks inside are copied as the files they point to, so nothing
    written later reaches the SDK; image files may be read-only.
    """
    shutil.copytree(
        src,
        dest,
        symlinks=False,
        ignore_dangling_symlinks=True,
        copy_function=shutil.copyfile,
    )
    dest.chmod(0o700)
    for root, dirs, files in os.walk(dest):
        for name in dirs:
            path = Path(root) / name
            if not path.is_symlink():
                path.chmod(0o700)
        for name in files:
            path = Path(root) / name
            if not path.is_symlink():
                path.chmod(0o600)


def _read_text(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _write_text(path: Path, text: str) -> None:
    """Write a fresh file (a symlink or file at ``path`` is unlinked first)."""
    if path.is_symlink() or path.exists():
        path.unlink()
    with open(path, "x", encoding="utf-8", newline="") as handle:
        handle.write(text)


def patched_files(image: Path, values: SimValues) -> dict[Path, str]:
    """The patched modem simulator files of ``image`` (paths relative to it).

    Raises:
        SimPatchError: The image has no SIM card profile, or one with an
            unknown layout.
        ValueError: A value has the wrong format.
    """
    modem = Path(image) / MODEM_DIR
    icc = modem / ICC_PROFILE
    if not icc.is_file():
        raise SimPatchError(f"{image} has no modem simulator SIM profile")
    out = {MODEM_DIR / ICC_PROFILE: patch_iccprofile(_read_text(icc), values)}
    numeric = modem / NUMERIC_OPERATOR
    if values.mccmnc:
        if numeric.is_file():
            out[MODEM_DIR / NUMERIC_OPERATOR] = patch_numeric_operator(
                _read_text(numeric), values.mccmnc, values.operator
            )
        else:
            logger.warning(
                "identity SIM: %s has no numeric_operator.xml; the network "
                "operator stays the emulator's own",
                image,
            )
    return out


def _matches(target: Path, files: dict[Path, str]) -> bool:
    """``target`` is a built sysdir holding exactly ``files``."""
    try:
        return target.is_dir() and all(
            _read_text(target / rel) == text for rel, text in files.items()
        )
    except (OSError, UnicodeDecodeError):
        return False


def build_private_sysdir(image: Path, target: Path, values: SimValues) -> Path:
    """Build the private sysdir for ``values`` at ``target`` (atomically).

    ``target`` gets one symlink per entry of ``image`` except ``data/``,
    which is copied with the modem simulator files patched. It is built in
    a temporary directory next to ``target`` and renamed into place; an
    older ``target`` and stale leftovers of interrupted builds are removed.

    Args:
        image: The AVD's real system image directory.
        target: The private sysdir (:func:`sysdir_path`).
        values: What the SIM carries.

    Returns:
        ``target``.

    Raises:
        SimPatchError: The image has no modem simulator SIM profile, or one
            this module cannot patch (nothing is written).
        SymlinkError: This host cannot create symlinks (cleaned up).
        OSError: The directory could not be built.
    """
    image = Path(image).absolute()
    files = patched_files(image, values)
    base = Path(target).parent
    base.mkdir(parents=True, exist_ok=True)
    _remove_leftovers(base, target.name)
    tmp = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=base))
    old: Path | None = None
    try:
        for entry in sorted(image.iterdir(), key=lambda p: p.name):
            if entry.name == "data" and entry.is_dir() and not entry.is_symlink():
                try:
                    _copy_data(entry, tmp / "data")
                except shutil.Error as exc:
                    raise SimPatchError(f"cannot copy {entry}: {exc}") from exc
                continue
            try:
                os.symlink(entry, tmp / entry.name)
            except (OSError, NotImplementedError) as exc:
                raise SymlinkError(f"cannot link {entry}: {exc}") from exc
        for rel, text in files.items():
            _write_text(tmp / rel, text)
        if target.exists() or target.is_symlink():
            old = base / f".{target.name}.old-{uuid.uuid4().hex[:8]}"
            os.rename(target, old)
        os.rename(tmp, target)
    except BaseException:
        try:
            _rmtree(tmp)
        except OSError:
            logger.debug(f"identity SIM: cannot remove {tmp}", exc_info=True)
        raise
    finally:
        if old is not None:
            try:
                _rmtree(old)
            except OSError as exc:
                logger.warning(f"identity SIM: cannot remove {old}: {exc}")
    return target


def remove_private_sysdir(avd: str) -> None:
    """Remove AVD ``avd``'s private sysdir and leftovers (no-op if absent)."""
    target = sysdir_path(avd)
    base = target.parent
    if not base.is_dir():
        return
    try:
        _rmtree(target)
    except OSError as exc:
        logger.warning(f"identity SIM: cannot remove {target}: {exc}")
    _remove_leftovers(base, target.name)


# ---------------------------------------------------------------------------
# launch hooks
# ---------------------------------------------------------------------------


def has_sysdir(args: tuple[str, ...] | list[str]) -> bool:
    """``args`` name a ``-sysdir`` of their own."""
    return any(a == SYSDIR_FLAG or a.startswith(SYSDIR_FLAG + "=") for a in args)


def _avd_running(avd: str) -> bool:
    from sandroid.core import emulator

    try:
        return bool(emulator.avd_lock_files(avd))
    except Exception:
        logger.debug("identity SIM: lock check failed", exc_info=True)
        return False


#: Key of this module's entry in the launch record's ``hooks``.
RECORD_KEY = "identity_sim"


def _note(context: LaunchContext, profile: str, **entry: Any) -> None:
    """Put what this launch got into the launch record (``hooks``)."""
    context.record[RECORD_KEY] = {"profile": profile, **entry}


def pre_launch(context: LaunchContext) -> tuple[str, ...]:
    """Pre-launch hook: ``("-sysdir", <absolute private dir>)`` or ``()``.

    ``()`` when identity mode is off, the active profile has no native SIM
    value, the launch already names a ``-sysdir``, the image has no SIM
    profile this module can patch, the host cannot create symlinks, or
    another instance of the AVD runs and no matching sysdir exists (all
    logged). Raises only when the private directory cannot be written (the
    launch then fails closed).

    Whenever identity mode is on, the launch record gets
    ``hooks.identity_sim``: ``{"profile", "values", "sysdir"}`` when the
    emulator starts with the profile's SIM, else ``{"profile", "skipped":
    <reason>}`` (nothing only when the identity settings cannot be read).
    """
    try:
        found = _active_sim()
    except Exception:
        logger.warning(
            "identity SIM: cannot read the active profile; the SIM identity of "
            "AVD %r is not set",
            context.avd,
            exc_info=True,
        )
        return ()
    if found is None:
        return ()
    profile_id, values, why = found
    if values is None:
        _note(context, profile_id, skipped=why)
        return ()
    if has_sysdir(tuple(context.options.extra_args)):
        logger.warning(
            "identity SIM: AVD %r is launched with its own -sysdir; the SIM "
            "identity is not set",
            context.avd,
        )
        _note(context, profile_id, skipped=OWN_SYSDIR)
        return ()
    image = image_dir(context.avd_dir)
    if image is None:
        logger.warning(
            "identity SIM: no system image directory for AVD %r; the SIM "
            "identity is not set",
            context.avd,
        )
        _note(context, profile_id, skipped=NO_IMAGE)
        return ()
    target = sysdir_path(context.avd).absolute()
    try:
        if _avd_running(context.avd):
            # Another instance may run from this directory: never rebuild it.
            if _matches(target, patched_files(image.absolute(), values)):
                path = target
            else:
                logger.warning(
                    "identity SIM: AVD %r already runs; its SIM identity is not set",
                    context.avd,
                )
                _note(context, profile_id, skipped=ALREADY_RUNNING)
                return ()
        else:
            path = build_private_sysdir(image, target, values)
    except (SimPatchError, ValueError) as exc:
        logger.warning(
            f"identity SIM: SIM identity not set for AVD {context.avd!r}: {exc}"
        )
        _note(context, profile_id, skipped=str(exc) or UNKNOWN_TEMPLATE)
        return ()
    logger.info(f"identity SIM: AVD {context.avd!r} starts with {path}")
    _note(context, profile_id, values=asdict(values), sysdir=str(path))
    return (SYSDIR_FLAG, str(path))


def post_stop(context: LaunchContext) -> None:
    """Post-stop hook: remove the AVD's private sysdir (idempotent).

    Kept while another instance of the AVD runs (a refused duplicate
    launch must not take the running instance's sysdir away).
    """
    if _avd_running(context.avd):
        logger.info(
            "identity SIM: AVD %r still runs; its private sysdir stays",
            context.avd,
        )
        return
    remove_private_sysdir(context.avd)


def install_launch_hooks() -> None:
    """Register :func:`pre_launch` and :func:`post_stop` (idempotent).

    Call once at startup, before Sandroid can launch an emulator. They stay
    registered until the process exits: post-stop also runs for launches
    reaped at interpreter exit.
    """
    from sandroid.core import emulator

    emulator.register_pre_launch_hook(pre_launch)
    emulator.register_post_stop_hook(post_stop)


def uninstall_launch_hooks() -> None:
    """Undo :func:`install_launch_hooks` (no-op when not registered)."""
    from sandroid.core import emulator

    emulator.unregister_pre_launch_hook(pre_launch)
    emulator.unregister_post_stop_hook(post_stop)


# ---------------------------------------------------------------------------
# what a running emulator was launched with
# ---------------------------------------------------------------------------

#: Why a restart from the Devices hub would not set the SIM values.
NOT_STARTABLE = "not an emulator Sandroid starts"
AVD_UNKNOWN = "Sandroid does not know this emulator's AVD"
OWN_SYSDIR = "the emulator is started with its own -sysdir"
NO_TEMPLATE = "the system image has no SIM card profile"
UNKNOWN_TEMPLATE = "the system image's SIM card profile has an unknown layout"
PROFILE_INVALID = "the profile is invalid"
MNC_UNKNOWN = (
    "the SIM MCC/MNC is unknown: add a SIM operator MCC/MNC value or a country preset"
)
MODE_OFF = "identity mode is off"
NO_IMAGE = "the AVD has no system image directory"
ALREADY_RUNNING = "another instance of the AVD runs without this SIM"
NO_SIM_VALUE = "the profile sets no SIM value at launch"
PROFILE_UNUSABLE = "the profile cannot be loaded"
NOT_ACTIVE = "this profile is not the active one"


@dataclass(frozen=True)
class RunningEmulator:
    """What the host knows about a running emulator.

    Attributes:
        serial: Its ``emulator-<port>`` serial.
        avd: AVD name (empty when unknown).
        avd_dir: AVD directory (``None`` when unknown).
        sim: The SIM it started with (``None`` when unknown).
        token: Changes with every launch: ``launch:<launch_id>`` of
            Sandroid's launch record, else (an emulator Sandroid did not
            start) ``ini:<mtime>`` of ``hardware-qemu.ini``, which the
            emulator writes at each start (empty when unknown).
        own_sysdir: Sandroid launched it with a ``-sysdir`` of the user's.
    """

    serial: str
    avd: str = ""
    avd_dir: Path | None = None
    sim: SimValues | None = None
    token: str = ""
    own_sysdir: bool = False


def launched_sim(avd_directory: Path) -> SimValues | None:
    """SIM values in ``<avd dir>/modem_simulator/iccprofile_for_sim0.xml``.

    The emulator copies the template of its sysdir there at every launch,
    so for a running emulator this is the SIM it started with. ``None``
    when the file is missing or unreadable.
    """
    path = Path(avd_directory) / "modem_simulator" / ICC_PROFILE
    try:
        text = _read_text(path)
    except (OSError, UnicodeDecodeError):
        return None
    return read_iccprofile(text)


def running_emulator(serial: str, avd_name: str = "") -> RunningEmulator | None:
    """Host facts about the running emulator ``serial`` (``None``: not one).

    Args:
        serial: An ``emulator-<port>`` serial.
        avd_name: Its AVD name if known (``ro.boot.qemu.avd_name``); else
            the emulator console is asked.
    """
    if not serial.startswith("emulator-"):
        return None
    from sandroid.core import emulator

    record: dict[str, Any] | None = None
    try:
        record = emulator.launch_record(serial)
    except Exception:
        logger.debug("identity SIM: launch record unavailable", exc_info=True)
    if record is not None and not record.get("launch_id"):
        record = None
    name = (
        avd_name
        or (str(record.get("avd") or "") if record is not None else "")
        or emulator.avd_name_of(serial)
        or ""
    )
    directory = emulator.avd_dir(name) if name else None
    if directory is None:
        return RunningEmulator(serial, name)
    own = False
    if record is not None:
        token = f"launch:{record['launch_id']}"
        extra = (record.get("options") or {}).get("extra_args") or ()
        own = has_sysdir(tuple(str(a) for a in extra))
    else:
        try:
            ns = (directory / "hardware-qemu.ini").stat().st_mtime_ns
            token = f"ini:{ns}"
        except OSError:
            token = ""
    return RunningEmulator(
        serial, name, directory, launched_sim(directory), token, own_sysdir=own
    )


def running_sim(serial: str, avd_name: str = "") -> SimValues | None:
    """The SIM values the running emulator ``serial`` was launched with."""
    found = running_emulator(serial, avd_name)
    return found.sim if found is not None else None


def restart_blocker(running: RunningEmulator | None, profile: Profile) -> str:
    """Why restarting this emulator from Sandroid would not set ``profile``'s
    SIM values (``""``: a restart sets them).
    """
    if running is None:
        return NOT_STARTABLE
    if running.avd_dir is None:
        return AVD_UNKNOWN
    if running.own_sysdir:
        return OWN_SYSDIR
    try:
        from sandroid.services.identity import get_identity_service

        cfg = get_identity_service().config()
        if cfg.mode != "profile":
            return MODE_OFF
        if cfg.profile != profile.id:
            return NOT_ACTIVE
    except Exception:
        logger.debug("identity SIM: config unavailable", exc_info=True)
    from sandroid.services.identity import validate

    if any(i.severity == "error" for i in validate(profile)):
        return PROFILE_INVALID
    values = sim_values(profile)
    if values is None:
        return MNC_UNKNOWN
    image = image_dir(running.avd_dir)
    if image is None or not (image / MODEM_DIR / ICC_PROFILE).is_file():
        return NO_TEMPLATE
    try:
        patched_files(image, values)
    except (SimPatchError, ValueError):
        return UNKNOWN_TEMPLATE
    return ""


__all__ = [
    "SIM_KINDS",
    "RunningEmulator",
    "SimPatchError",
    "SimValues",
    "SymlinkError",
    "active_sim_values",
    "build_private_sysdir",
    "decode_msisdn_record",
    "decode_parcel_string",
    "has_sysdir",
    "iccid_bcd",
    "image_dir",
    "install_launch_hooks",
    "launched_sim",
    "msisdn_digits",
    "msisdn_record",
    "patch_iccprofile",
    "patch_numeric_operator",
    "patched_files",
    "post_stop",
    "pre_launch",
    "read_iccprofile",
    "remove_private_sysdir",
    "restart_blocker",
    "running_emulator",
    "running_sim",
    "sim_values",
    "swap_bcd",
    "sysdir_path",
    "uninstall_launch_hooks",
]
