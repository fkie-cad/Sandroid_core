"""Evidence documentation for analysis runs.

This module turns the in-memory result of an analysis into documented,
verifiable evidence in a result folder:

* :func:`plain_text` / :func:`sanitize_results` remove terminal colouring
  (ANSI escape sequences and Rich console markup) so the JSON and PDF hold
  plain text only. Colours stay a terminal concern.
* :func:`collect_host_metadata`, :func:`collect_device_metadata` and
  :func:`build_run_metadata` describe *how* a result was produced (tool
  versions, device build, timestamps, sanitised settings). Device values are
  read through any object exposing ``send_adb_command(cmd) -> (out, err)`` so
  they can be tested with fakes.
* :func:`write_hash_manifest` / :func:`verify_hash_manifest` produce and check
  ``manifest.json`` + ``SHA256SUMS`` over every file in the result folder. The
  SHA-256 of ``SHA256SUMS`` is written to the log so the whole folder is
  anchored by a single value.
* :func:`finalize_run` is the reusable "end of run" entry point: write the
  results JSON (with metadata), optionally render the PDF, then write the
  manifest. Every UI (CLI, TUI, API) should call it after an analysis instead of
  re-implementing these steps.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import logging
import os
import platform
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

#: Key under which run metadata is added to the results JSON. Existing keys
#: are left untouched for backward compatibility.
RUN_METADATA_KEY = "Run Metadata"

#: Default file names inside a result folder.
DEFAULT_RESULTS_NAME = "sandroid.json"
DEFAULT_PDF_NAME = "Sandroid_Forensic_Report.pdf"
MANIFEST_NAME = "manifest.json"
SHA256SUMS_NAME = "SHA256SUMS"

#: Regenerated reports never replace an existing file; they are written as
#: ``Sandroid_Forensic_Report_regenerated_<UTC timestamp>.pdf`` and recorded in
#: an addendum manifest ``SHA256SUMS.addendum-<UTC timestamp>`` (sha256sum
#: format) instead of rewriting the original ``SHA256SUMS``.
REGENERATED_PDF_TEMPLATE = "Sandroid_Forensic_Report_regenerated_{stamp}.pdf"
ADDENDUM_PREFIX = f"{SHA256SUMS_NAME}.addendum-"

#: Hash algorithms recorded for every evidence file (MD5 kept for
#: compatibility with older reports and tooling, SHA-256 is authoritative).
HASH_ALGORITHMS: tuple[str, ...] = ("md5", "sha256")

#: Files that are still being written after the manifest is created (the log
#: receives the manifest hash itself), so they cannot be part of it.
LIVE_FILE_PATTERNS: tuple[str, ...] = ("sandroid*.log", "sandroid*.log.*")

#: Python distributions whose versions are recorded in the run metadata.
TOOL_DISTRIBUTIONS: tuple[str, ...] = (
    "frida",
    "frida-tools",
    "friTap",
    "dexray-intercept",
    "dexray-insight",
    "AndroidFridaManager",
    "trigdroid",
    "mvt",
)

#: Config sections recorded as "analysis settings" in the metadata. Sections
#: that hold credentials or endpoints (ai, mcp, credentials, ...) are never
#: included.
SETTINGS_SECTIONS: tuple[str, ...] = ("analysis", "trigdroid", "report")

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|passw(or)?d|credential|auth|cookie|private)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Plain-text sanitising
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI sequences (colours, cursor movement)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (hyperlinks, titles)
    r"|\x1b[@-Z\\-_]"  # two-byte escapes
)

# Style names used in console markup by the diff/analysis code: the theme
# names from ``config/theme.py`` plus Rich's built-in styles and colours.
_STYLE_WORD = (
    r"(?:success|warning|error|info|accent|primary|secondary|default|dark|light"
    r"|logo|high_contrast|file_path|str|dim|bold|italic|underline|reverse|strike"
    r"|blink|red|green|yellow|blue|magenta|cyan|white|black"
    r"|(?:menu|box|mode|status)\.[a-z_.]+)"
)
_MARKUP_TAG_RE = re.compile(
    rf"(?<!\\)\[(?:/{_STYLE_WORD}?|{_STYLE_WORD})(?:\s+{_STYLE_WORD})*\]"
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (and stray ESC bytes) from ``text``."""
    return _ANSI_RE.sub("", text).replace("\x1b", "")


def strip_markup(text: str) -> str:
    r"""Remove Rich console markup tags such as ``[success]...[/success]``.

    Only known style names are treated as tags, so literal brackets in data
    (e.g. kernel thread names like ``[kworker/0:1]``) survive. Rich's escaped
    brackets (``\\[``) are turned back into plain ``[``.
    """
    return _MARKUP_TAG_RE.sub("", text).replace("\\[", "[")


def plain_text(text: str) -> str:
    """Return ``text`` without any terminal colouring (ANSI and markup)."""
    return strip_markup(strip_ansi(text))


def _deep_strip_ansi(value: Any) -> Any:
    if isinstance(value, str):
        return strip_ansi(value)
    if isinstance(value, list):
        return [_deep_strip_ansi(v) for v in value]
    if isinstance(value, tuple):
        return [_deep_strip_ansi(v) for v in value]
    if isinstance(value, dict):
        return {
            (strip_ansi(k) if isinstance(k, str) else k): _deep_strip_ansi(v)
            for k, v in value.items()
        }
    return value


def sanitize_results(results: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a results mapping that contains plain text only.

    ANSI sequences are removed from every string. The per-file diff lines in
    ``"Changed Files"`` are produced for the console and additionally have
    their Rich markup removed. The input is not modified.
    """
    cleaned = _deep_strip_ansi(copy.deepcopy(results))
    changed = cleaned.get("Changed Files")
    if isinstance(changed, list):
        new_changed: list[Any] = []
        for entry in changed:
            if isinstance(entry, dict):
                new_changed.append(
                    {
                        name: (
                            [plain_text(x) if isinstance(x, str) else x for x in v]
                            if isinstance(v, list)
                            else plain_text(v)
                            if isinstance(v, str)
                            else v
                        )
                        for name, v in entry.items()
                    }
                )
            else:
                new_changed.append(entry)
        cleaned["Changed Files"] = new_changed
    return cleaned


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def hash_file(
    path: str | os.PathLike[str],
    algorithms: tuple[str, ...] = HASH_ALGORITHMS,
    chunk_size: int = 1024 * 1024,
) -> dict[str, str]:
    """Hash a file with several algorithms in one streaming pass.

    Args:
        path: File to hash.
        algorithms: ``hashlib`` algorithm names.
        chunk_size: Read size in bytes.

    Returns:
        Mapping ``algorithm -> hex digest``.

    Raises:
        OSError: If the file cannot be read.
    """
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Return the SHA-256 hex digest of ``path``."""
    return hash_file(path, ("sha256",))["sha256"]


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class AdbLike(Protocol):
    """Anything that can run an adb command (``Adb`` class, fakes in tests)."""

    def send_adb_command(self, command: str) -> tuple[str, str]: ...


def iso_now() -> str:
    """Current local time as ISO-8601 with UTC offset (second precision)."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def to_iso(value: datetime | str | float | None) -> str | None:
    """Normalise a timestamp to ISO-8601 with timezone.

    Naive datetimes are interpreted as local time; numbers as Unix epoch.
    Strings are parsed when possible and returned unchanged otherwise.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value).astimezone()
    elif isinstance(value, datetime):
        dt = value if value.tzinfo else value.astimezone()
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
        dt = dt if dt.tzinfo else dt.astimezone()
    return dt.isoformat(timespec="seconds")


def _dist_version(name: str) -> str | None:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None
    except Exception:  # pragma: no cover - broken metadata
        return None


def collect_host_metadata() -> dict[str, Any]:
    """Describe the analysis host and the tool versions in use."""
    from sandroid._version import __version__

    return {
        "sandroid_version": __version__,
        "host_os": platform.platform(),
        "host_system": platform.system(),
        "host_release": platform.release(),
        "host_machine": platform.machine(),
        "host_name": platform.node(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "tool_versions": {name: _dist_version(name) for name in TOOL_DISTRIBUTIONS},
    }


def _adb_value(adb: AdbLike, command: str) -> str | None:
    try:
        stdout, _stderr = adb.send_adb_command(command)
    except Exception as exc:
        logger.debug("metadata: adb %r failed: %s", command, exc)
        return None
    if not isinstance(stdout, str):
        return None
    value = stdout.strip()
    if not value or value.lower().startswith(("error", "unknown")):
        return None
    return value


def collect_device_metadata(
    adb: AdbLike | None, device_name: str | None = None
) -> dict[str, Any]:
    """Read identifying properties of the analysed device.

    Args:
        adb: Object with ``send_adb_command(cmd) -> (stdout, stderr)``. When
            ``None`` only ``device_name`` is recorded.
        device_name: Name the analysis knows the device by (fallback for the
            AVD name).

    Returns:
        Mapping with ``device_name``, ``serial``, ``avd_name``,
        ``android_version``, ``api_level``, ``build_fingerprint``,
        ``security_patch``, ``model``. Unavailable values are ``None``.
    """
    meta: dict[str, Any] = {
        "device_name": device_name,
        "serial": None,
        "avd_name": None,
        "android_version": None,
        "api_level": None,
        "build_fingerprint": None,
        "security_patch": None,
        "model": None,
    }
    if adb is None:
        return meta

    meta["serial"] = _adb_value(adb, "get-serialno")
    props = {
        "android_version": "ro.build.version.release",
        "api_level": "ro.build.version.sdk",
        "build_fingerprint": "ro.build.fingerprint",
        "security_patch": "ro.build.version.security_patch",
        "model": "ro.product.model",
    }
    for key, prop in props.items():
        meta[key] = _adb_value(adb, f"shell getprop {prop}")
    if meta["api_level"] is not None:
        try:
            meta["api_level"] = int(meta["api_level"])
        except ValueError:
            pass

    avd = _adb_value(adb, "shell getprop ro.boot.qemu.avd_name") or _adb_value(
        adb, "shell getprop ro.kernel.qemu.avd_name"
    )
    if avd is None:
        emu = _adb_value(adb, "emu avd name")
        if emu:
            first = emu.splitlines()[0].strip()
            avd = first if first and first != "OK" else None
    meta["avd_name"] = avd
    return meta


def _redact(value: Any, key: str | None = None) -> Any:
    if key is not None and _SECRET_KEY_RE.search(key):
        return "<redacted>" if value not in (None, "", {}, []) else value
    if isinstance(value, dict):
        return {k: _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value") and not isinstance(value, (str, int, float, bool)):
        return getattr(value, "value", str(value))  # Enums
    return value


def sanitize_settings(config: Any) -> dict[str, Any]:
    """Return the analysis-relevant settings of a ``SandroidConfig``.

    Only :data:`SETTINGS_SECTIONS` plus a few top-level values are exported;
    any key that looks like a secret is redacted. API keys, credentials and
    endpoint configuration are never included.
    """
    if config is None:
        return {}
    settings: dict[str, Any] = {}
    for section in SETTINGS_SECTIONS:
        obj = getattr(config, section, None)
        if obj is None:
            continue
        try:
            dumped = obj.model_dump(mode="json")
        except Exception:
            try:
                dumped = dict(vars(obj))
            except TypeError:
                continue
        settings[section] = _redact(dumped)
    for attr in ("output_file", "whitelist_file", "environment"):
        if hasattr(config, attr):
            settings[attr] = _redact(getattr(config, attr), attr)
    return settings


def build_run_metadata(
    *,
    adb: AdbLike | None = None,
    config: Any = None,
    device_name: str | None = None,
    started_at: datetime | str | float | None = None,
    ended_at: datetime | str | float | None = None,
    run_id: str | None = None,
    mode: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the ``"Run Metadata"`` block stored in the results JSON."""
    started = to_iso(started_at)
    ended = to_iso(ended_at) or iso_now()
    duration = None
    if started and ended:
        try:
            duration = round(
                (
                    datetime.fromisoformat(ended) - datetime.fromisoformat(started)
                ).total_seconds()
            )
        except (TypeError, ValueError):
            duration = None
    meta: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": mode,
        "started_at": started,
        "ended_at": ended,
        "duration_seconds": duration,
        "host": collect_host_metadata(),
        "device": collect_device_metadata(adb, device_name),
        "settings": sanitize_settings(config),
        "hash_algorithms": list(HASH_ALGORITHMS),
    }
    if extra:
        meta.update(_redact(extra))
    return meta


# ---------------------------------------------------------------------------
# Results JSON
# ---------------------------------------------------------------------------


def prepare_results_document(
    results: dict[str, Any], metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Sanitise ``results`` and attach ``metadata`` under ``"Run Metadata"``."""
    doc = sanitize_results(results)
    if metadata is not None:
        doc[RUN_METADATA_KEY] = metadata
    return doc


def write_results_json(
    results: dict[str, Any],
    output_file: str | os.PathLike[str],
    metadata: dict[str, Any] | None = None,
) -> Path:
    """Write the sanitised results document (plus metadata) as JSON."""
    from sandroid.core.json_utils import json_encoder

    out = Path(output_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = prepare_results_document(results, metadata)
    # Round-trip through the encoder first so the file is never half-written.
    text = json.dumps(doc, indent=4, default=json_encoder, ensure_ascii=False)
    out.write_text(text, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Hash manifest
# ---------------------------------------------------------------------------


@dataclass
class ManifestInfo:
    """Outcome of :func:`write_hash_manifest`."""

    manifest_path: Path
    sha256sums_path: Path
    sha256sums_sha256: str
    file_count: int
    excluded: list[dict[str, str]] = field(default_factory=list)


def _is_live_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pat) for pat in LIVE_FILE_PATTERNS)


def _iter_result_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            yield full, rel


def write_hash_manifest(
    result_dir: str | os.PathLike[str],
    *,
    exclude_patterns: tuple[str, ...] = LIVE_FILE_PATTERNS,
) -> ManifestInfo:
    """Hash every file in ``result_dir`` and write ``manifest.json`` + ``SHA256SUMS``.

    ``manifest.json`` lists size, MD5 and SHA-256 of every file (plus files
    that were excluded and why). ``SHA256SUMS`` is in ``sha256sum`` format and
    additionally covers ``manifest.json``, so ``sha256sum -c SHA256SUMS`` inside
    the folder verifies everything. The SHA-256 of ``SHA256SUMS`` is logged.

    Args:
        result_dir: The run's result folder.
        exclude_patterns: Basename glob patterns of files still being written
            (logs). They are listed under ``excluded`` instead of hashed.

    Returns:
        A :class:`ManifestInfo`.
    """
    root = Path(result_dir).resolve()
    files: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for full, rel in _iter_result_files(root):
        if rel in (MANIFEST_NAME, SHA256SUMS_NAME):
            continue
        name = rel.rsplit("/", 1)[-1]
        if any(fnmatch.fnmatch(name, pat) for pat in exclude_patterns):
            excluded.append(
                {"path": rel, "reason": "live log file, still written after manifest"}
            )
            continue
        if full.is_symlink():
            excluded.append({"path": rel, "reason": f"symlink to {full.readlink()}"})
            continue
        try:
            digests = hash_file(full)
            size = full.stat().st_size
        except OSError as exc:
            excluded.append({"path": rel, "reason": f"unreadable: {exc}"})
            continue
        files.append({"path": rel, "size": size, **digests})

    from sandroid._version import __version__

    manifest = {
        "schema": "sandroid-evidence-manifest/1",
        "generated_at": iso_now(),
        "generator": f"Sandroid {__version__}",
        "root": str(root),
        "algorithms": list(HASH_ALGORITHMS),
        "file_count": len(files),
        "files": files,
        "excluded": excluded,
    }
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines = [f"{f['sha256']}  {f['path']}" for f in files]
    lines.append(f"{sha256_file(manifest_path)}  {MANIFEST_NAME}")
    sums_path = root / SHA256SUMS_NAME
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums_hash = sha256_file(sums_path)
    logger.info(
        "Evidence manifest written: %s (%d files). SHA-256 of %s: %s",
        manifest_path,
        len(files),
        SHA256SUMS_NAME,
        sums_hash,
    )
    return ManifestInfo(
        manifest_path=manifest_path,
        sha256sums_path=sums_path,
        sha256sums_sha256=sums_hash,
        file_count=len(files),
        excluded=excluded,
    )


@dataclass
class ManifestCheck:
    """Outcome of :func:`verify_hash_manifest`."""

    present: bool
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when a manifest exists and every listed file still matches."""
        return self.present and not self.mismatched and not self.missing


def _addendum_files(root: Path) -> list[Path]:
    return sorted(p for p in root.glob(f"{ADDENDUM_PREFIX}*") if p.is_file())


def _read_sums(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        entries.append((rel, digest.strip().lower()))
    return entries


def verify_hash_manifest(result_dir: str | os.PathLike[str]) -> ManifestCheck:
    """Re-hash ``result_dir`` against its ``SHA256SUMS`` (and its addenda).

    Every ``SHA256SUMS.addendum-*`` file (written when a report was
    regenerated later) is verified as well, so regenerated reports are
    covered by the same check.

    Returns:
        A :class:`ManifestCheck`; ``present`` is False when neither
        ``SHA256SUMS`` nor an addendum exists. ``unlisted`` lists files added
        after the manifest (excluding live log files), which is
        informational only.
    """
    root = Path(result_dir).resolve()
    sums_path = root / SHA256SUMS_NAME
    sum_files = ([sums_path] if sums_path.is_file() else []) + _addendum_files(root)
    if not sum_files:
        return ManifestCheck(present=False)
    expected: list[tuple[str, str]] = []
    for path in sum_files:
        expected.extend(_read_sums(path))
    check = ManifestCheck(present=True)
    hashes: dict[str, str] = {}
    for rel, digest in expected:
        path = root / rel
        if not path.is_file():
            if rel not in check.missing:
                check.missing.append(rel)
            continue
        if rel not in hashes:
            hashes[rel] = sha256_file(path)
        if hashes[rel] != digest and rel not in check.mismatched:
            check.mismatched.append(rel)
    listed = {rel for rel, _ in expected} | {
        p.relative_to(root).as_posix() for p in sum_files
    }
    for _full, rel in _iter_result_files(root):
        if rel in listed or _is_live_file(rel):
            continue
        check.unlisted.append(rel)
    return check


# ---------------------------------------------------------------------------
# Finalisation
# ---------------------------------------------------------------------------


@dataclass
class FinalizeOutcome:
    """Paths produced by :func:`finalize_run`."""

    results_json: Path
    pdf: Path | None = None
    manifest: ManifestInfo | None = None
    errors: list[str] = field(default_factory=list)


def finalize_run(
    result_dir: str | os.PathLike[str],
    results: dict[str, Any],
    *,
    output_name: str = DEFAULT_RESULTS_NAME,
    adb: AdbLike | None = None,
    config: Any = None,
    started_at: datetime | str | float | None = None,
    ended_at: datetime | str | float | None = None,
    run_id: str | None = None,
    mode: str | None = None,
    generate_pdf: bool = False,
    pdf_name: str = DEFAULT_PDF_NAME,
    write_manifest: bool = True,
) -> FinalizeOutcome:
    """Write all evidence documentation for a finished analysis run.

    Call this once per run, after the analysis engine returned (CLI, TUI and
    API alike). Steps: results JSON with ``"Run Metadata"`` → optional PDF →
    hash manifest. PDF and manifest failures are logged and reported in
    ``errors`` but never raised; failing to write the JSON raises.

    Args:
        result_dir: The run's result folder (where the JSON is written).
        results: The legacy results mapping (``RunResult.to_json_dict()``).
        output_name: File name of the results JSON inside ``result_dir``;
            an absolute path is honoured as-is.
        adb: adb-capable object for device metadata (``None`` to skip).
        config: ``SandroidConfig`` for the sanitised settings (optional).
        started_at: Analysis start (datetime/ISO string/epoch).
        ended_at: Analysis end; defaults to now.
        run_id: Optional run identifier (run bundles).
        mode: Free-form mode label (``"cli"``, ``"tui-play"``, ...).
        generate_pdf: Also render the PDF report.
        pdf_name: PDF file name inside ``result_dir``.
        write_manifest: Write ``manifest.json``/``SHA256SUMS`` at the end.

    Returns:
        A :class:`FinalizeOutcome`.
    """
    root = Path(result_dir)
    root.mkdir(parents=True, exist_ok=True)
    metadata = build_run_metadata(
        adb=adb,
        config=config,
        device_name=results.get("Device Name"),
        started_at=started_at,
        ended_at=ended_at,
        run_id=run_id,
        mode=mode,
    )
    out_json = Path(output_name)
    if not out_json.is_absolute():
        out_json = root / out_json
    outcome = FinalizeOutcome(
        results_json=write_results_json(results, out_json, metadata)
    )
    logger.info("Results written: %s", out_json)

    if generate_pdf:
        try:
            from sandroid.core.pdf_report import generate_pdf_report

            outcome.pdf = generate_pdf_report(
                root, json_file=out_json, output_pdf=root / pdf_name
            )
        except Exception as exc:
            logger.error("PDF report generation failed: %s", exc, exc_info=True)
            outcome.errors.append(f"pdf: {exc}")

    if write_manifest:
        try:
            outcome.manifest = write_hash_manifest(root)
        except Exception as exc:
            logger.error("Writing evidence manifest failed: %s", exc, exc_info=True)
            outcome.errors.append(f"manifest: {exc}")
    return outcome


@dataclass
class ReportFromFolderOutcome:
    """Outcome of :func:`report_from_folder`."""

    pdf: Path
    check: ManifestCheck
    manifest: ManifestInfo | None = None
    #: Addendum manifest recording the regenerated PDF (sealed folders).
    addendum: Path | None = None
    addendum_sha256: str | None = None


class EvidenceVerificationError(RuntimeError):
    """The result folder no longer matches its ``SHA256SUMS``.

    Raised by :func:`report_from_folder` *before* anything is written.
    """

    def __init__(self, result_dir: str | os.PathLike[str], check: ManifestCheck):
        self.result_dir = Path(result_dir)
        self.check = check
        names = (check.mismatched + check.missing)[:3]
        more = len(check.mismatched) + len(check.missing) - len(names)
        listed = ", ".join(names) + (f" (+{more} more)" if more > 0 else "")
        super().__init__(
            f"Evidence manifest verification FAILED for {self.result_dir}: "
            f"{len(check.mismatched)} modified, {len(check.missing)} missing "
            f"file(s): {listed}. Nothing was written."
        )


def utc_stamp(now: datetime | None = None) -> str:
    """UTC timestamp for file names, e.g. ``20261116T174938Z``."""
    return (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def _free_path(path: Path) -> Path:
    """``path`` or, if it exists, ``<stem>_2<suffix>``, ``_3``, ..."""
    candidate, n = path, 1
    while candidate.exists():
        n += 1
        candidate = path.with_name(f"{path.stem}_{n}{path.suffix}")
    return candidate


def write_manifest_addendum(
    result_dir: str | os.PathLike[str],
    new_files: list[Path],
    stamp: str,
) -> tuple[Path, str]:
    """Record files added to a sealed result folder in an addendum manifest.

    Writes ``SHA256SUMS.addendum-<stamp>`` (``sha256sum`` format) listing the
    SHA-256 of each new file plus the current ``SHA256SUMS`` (which chains the
    addendum to the original manifest). The original manifest is not touched;
    ``sha256sum -c SHA256SUMS.addendum-<stamp>`` verifies the addendum.

    Returns:
        ``(addendum path, SHA-256 of the addendum)``.
    """
    root = Path(result_dir).resolve()
    lines = [
        f"{sha256_file(f)}  {Path(f).resolve().relative_to(root).as_posix()}"
        for f in new_files
    ]
    sums = root / SHA256SUMS_NAME
    if sums.is_file():
        lines.append(f"{sha256_file(sums)}  {SHA256SUMS_NAME}")
    path = _free_path(root / f"{ADDENDUM_PREFIX}{stamp}")
    with open(path, "x", encoding="utf-8") as fh:  # never overwrite
        fh.write("\n".join(lines) + "\n")
    return path, sha256_file(path)


def report_from_folder(
    result_dir: str | os.PathLike[str],
    *,
    json_file: str | os.PathLike[str] | None = None,
    output_pdf: str | os.PathLike[str] | None = None,
    update_manifest: bool = True,
) -> ReportFromFolderOutcome:
    """(Re)generate the PDF report for an existing result folder.

    Shared by ``sandroid --report-from`` and the TUI ``P`` key. Evidence
    rules:

    1. The existing ``SHA256SUMS`` (and any addenda) is verified *before*
       anything is written. On a mismatch nothing is written and
       :class:`EvidenceVerificationError` is raised.
    2. No existing file is ever overwritten: the PDF is written as
       ``Sandroid_Forensic_Report_regenerated_<UTC>.pdf`` (only a folder
       without manifest and without a PDF gets the default name), an
       existing ``timeline.png`` is reused, a missing one is not added.
    3. In a sealed folder the new PDF is recorded in
       ``SHA256SUMS.addendum-<UTC>`` (plus a log line); the original
       ``SHA256SUMS``/``manifest.json`` stay unchanged. A folder without any
       manifest gets a fresh one.

    Args:
        result_dir: Existing result folder.
        json_file: Results JSON (located automatically if omitted).
        output_pdf: Explicit output path; must not exist yet.
        update_manifest: Record the new PDF (addendum or new manifest).

    Returns:
        A :class:`ReportFromFolderOutcome`.

    Raises:
        FileNotFoundError: ``result_dir`` does not exist.
        EvidenceVerificationError: The folder does not match its manifest.
        FileExistsError: ``output_pdf`` already exists.
    """
    from sandroid.core.pdf_report import generate_pdf_report

    root = Path(result_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Result folder not found: {root}")
    check = verify_hash_manifest(root)
    if check.present and not check.ok:
        error = EvidenceVerificationError(root, check)
        logger.error("%s", error)
        raise error
    sealed = check.present or (root / MANIFEST_NAME).exists()
    stamp = utc_stamp()
    if output_pdf is not None:
        out = Path(output_pdf)
        if out.exists():
            raise FileExistsError(f"Refusing to overwrite existing file: {out}")
    elif not sealed and not (root / DEFAULT_PDF_NAME).exists():
        out = root / DEFAULT_PDF_NAME
    else:
        out = _free_path(root / REGENERATED_PDF_TEMPLATE.format(stamp=stamp))
    try:
        pdf = generate_pdf_report(
            root, json_file=json_file, output_pdf=out, write_timeline=False
        )
    except BaseException:
        # Do not leave a half-written report behind (it did not exist before).
        out.unlink(missing_ok=True)
        raise
    outcome = ReportFromFolderOutcome(pdf=pdf, check=check)
    if not update_manifest:
        return outcome
    if sealed:
        outcome.addendum, outcome.addendum_sha256 = write_manifest_addendum(
            root, [pdf], stamp
        )
        logger.info(
            "Report regenerated: %s (SHA-256 %s). Recorded in %s (SHA-256 %s); "
            "the original %s was verified and left unchanged.",
            pdf.name,
            sha256_file(pdf),
            outcome.addendum.name,
            outcome.addendum_sha256,
            SHA256SUMS_NAME,
        )
    else:
        outcome.manifest = write_hash_manifest(root)
    return outcome


__all__ = [
    "ADDENDUM_PREFIX",
    "DEFAULT_PDF_NAME",
    "DEFAULT_RESULTS_NAME",
    "HASH_ALGORITHMS",
    "MANIFEST_NAME",
    "REGENERATED_PDF_TEMPLATE",
    "RUN_METADATA_KEY",
    "SHA256SUMS_NAME",
    "EvidenceVerificationError",
    "FinalizeOutcome",
    "ManifestCheck",
    "ManifestInfo",
    "ReportFromFolderOutcome",
    "build_run_metadata",
    "collect_device_metadata",
    "collect_host_metadata",
    "finalize_run",
    "hash_file",
    "iso_now",
    "plain_text",
    "prepare_results_document",
    "report_from_folder",
    "sanitize_results",
    "sanitize_settings",
    "sha256_file",
    "strip_ansi",
    "strip_markup",
    "to_iso",
    "utc_stamp",
    "verify_hash_manifest",
    "write_hash_manifest",
    "write_manifest_addendum",
    "write_results_json",
]
