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
  results JSON (with metadata), seal the session timeline, write the report
  (``report.json`` + ``report.md``, optionally the PDF; see
  :mod:`sandroid.core.report_engine`), then write the manifest. Every UI (CLI,
  TUI, API) should call it after an analysis instead of re-implementing these
  steps.
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

#: Results-JSON key of a run's fatal/per-step errors (absent on a clean run);
#: same value as ``sandroid.analysis.run_config.RUN_ERRORS_KEY``.
RUN_ERRORS_KEY = "Run Errors"

#: Default file names inside a result folder.
DEFAULT_RESULTS_NAME = "sandroid.json"
DEFAULT_PDF_NAME = "Sandroid_Forensic_Report.pdf"
MANIFEST_NAME = "manifest.json"
SHA256SUMS_NAME = "SHA256SUMS"

#: The JSON report (the renderers' only input) and its Markdown rendering.
REPORT_STEM = "report"
REPORT_JSON_NAME = f"{REPORT_STEM}.json"
REPORT_MD_NAME = f"{REPORT_STEM}.md"
#: Seal of the session timeline a report was built from (``{seal,
#: timeline_path, session_id, scope}``); the timeline itself is not copied.
TIMELINE_SEAL_NAME = "timeline_seal.json"
TIMELINE_FILE_NAME = "timeline.jsonl"

#: Regenerated reports never replace an existing file; they are written as
#: ``report_regenerated_<UTC timestamp>.{json,md,pdf}`` and recorded in an
#: addendum manifest ``SHA256SUMS.addendum-<UTC timestamp>`` (sha256sum
#: format) instead of rewriting the original ``SHA256SUMS``.
REGENERATED_STEM_TEMPLATE = "report_regenerated_{stamp}"
REGENERATED_PDF_TEMPLATE = f"{REGENERATED_STEM_TEMPLATE}.pdf"
ADDENDUM_PREFIX = f"{SHA256SUMS_NAME}.addendum-"

#: Hash algorithms recorded for every evidence file (MD5 kept for
#: compatibility with older reports and tooling, SHA-256 is authoritative).
HASH_ALGORITHMS: tuple[str, ...] = ("md5", "sha256")

#: Files that are still being written after the manifest is created (the log
#: receives the manifest hash itself; the session timeline keeps growing), so
#: they cannot be part of it. Log patterns match the file name. The session
#: timeline patterns match only the real sink locations (see
#: :func:`_sink_live`): ``timeline.jsonl`` and ``tracking/raw/*`` of a folder
#: holding a ``.timeline.lock``, at the root or one folder below (a session
#: folder's device folders); any other file of that name is hashed. A live
#: timeline's prefix seal is recorded in ``manifest.json["timeline_seals"]``
#: and every raw file's prefix in ``manifest.json["raw_prefixes"]``;
#: :func:`verify_hash_manifest` re-checks both.
LIVE_FILE_PATTERNS: tuple[str, ...] = (
    "sandroid*.log",
    "sandroid*.log.*",
    TIMELINE_FILE_NAME,
    ".timeline.lock",
    "tracking/raw/*",
)

_LIVE_REASONS: dict[str, str] = {
    TIMELINE_FILE_NAME: (
        "live session timeline, still appended; sealed in timeline_seals"
    ),
    ".timeline.lock": "timeline lock file of a running Sandroid",
    "tracking/raw/*": "live raw tracking evidence, still written",
}

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
    ``"Changed Files"`` are plain text; legacy lines (runs recorded while the
    diff engine still wrote Rich markup) additionally have their markup
    removed. Plain lines are never run through the markup stripper, so data
    in brackets survives. The input is not modified.
    """
    from sandroid.core.file_diff import plain_diff_line

    cleaned = _deep_strip_ansi(copy.deepcopy(results))
    changed = cleaned.get("Changed Files")
    if isinstance(changed, list):
        new_changed: list[Any] = []
        for entry in changed:
            if isinstance(entry, dict):
                new_changed.append(
                    {
                        name: (
                            [plain_diff_line(x) for x in v]
                            if isinstance(v, list)
                            else plain_diff_line(v)
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

    ``device_name`` is only a label the analysis carried (it may be the
    config default ``emulator.device_name``), so it is recorded only when the
    device confirms it: it must equal the AVD name or model the device
    reports. Otherwise the reported AVD name (emulators) or model is used,
    and when the device did not answer at all the name is ``None``; the
    metadata never names a device nobody talked to.

    Args:
        adb: Object with ``send_adb_command(cmd) -> (stdout, stderr)``. When
            ``None`` only ``device_name`` is recorded (no device query was
            requested, e.g. tests and offline tools).
        device_name: Name the analysis knows the device by.

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
    meta["device_name"] = _confirmed_device_name(meta, device_name)
    return meta


def _confirmed_device_name(meta: dict[str, Any], label: str | None) -> str | None:
    """``label`` if the device's own answers confirm it, else what it reported."""
    model = meta.get("model")
    safe_model = re.sub(r"[\s/\\]+", "_", model.strip()) if model else None
    reported = {v for v in (meta.get("avd_name"), model, safe_model) if v}
    if label and label in reported:
        return label
    answered = any(
        meta.get(k) is not None
        for k in ("serial", "avd_name", "model", "build_fingerprint", "api_level")
    )
    if not answered:
        if label:
            logger.warning(
                "metadata: device did not answer; not recording the unverified "
                "device name %r",
                label,
            )
        return None
    return meta.get("avd_name") or safe_model or None


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
    run_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the ``"Run Metadata"`` block stored in the results JSON.

    ``run_settings`` (see :func:`describe_run_settings`) are the settings the
    analysis actually ran with. They are stored as ``"run_settings"`` and
    override the matching keys of ``settings.analysis``, so the recorded
    settings never claim a capture (or dry run) that did not happen just
    because the config file has it switched on.
    """
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
    if run_settings is not None:
        used = _redact(dict(run_settings))
        meta["run_settings"] = used
        analysis = meta["settings"].setdefault("analysis", {})
        if isinstance(analysis, dict):
            analysis.update({k: v for k, v in used.items() if k != "whitelist_file"})
    if extra:
        meta.update(_redact(extra))
    return meta


def describe_run_settings(run_config: Any) -> dict[str, Any]:
    """The settings an analysis actually used, keyed like ``[analysis]``.

    Args:
        run_config: The :class:`~sandroid.analysis.run_config.RunConfig`
            handed to the engine.
    """
    settings: dict[str, Any] = {
        "number_of_runs": getattr(run_config, "number_of_runs", None),
        "avoid_strong_noise_filter": not getattr(run_config, "noise_filter", True),
        "capture_network": bool(getattr(run_config, "network", False)),
        "capture_processes": bool(getattr(run_config, "processes", False)),
        "capture_sockets": bool(getattr(run_config, "sockets", False)),
        "show_deleted_files": bool(getattr(run_config, "show_deleted", False)),
        "hash_files": bool(getattr(run_config, "hash_files", False)),
        "list_apks": bool(getattr(run_config, "pull_apk", False)),
    }
    window = getattr(run_config, "capture_window", 0)
    action = getattr(run_config, "action", None)
    if window and type(action).__name__ == "CaptureWindowAction":
        settings["capture_window"] = window
    whitelist = getattr(run_config, "whitelist", None)
    settings["whitelist_file"] = str(whitelist) if whitelist else None
    from sandroid.analysis.engine import _network_reset_mode, _replay_settle_seconds

    settings["network_reset_after_snapshot"] = _network_reset_mode(run_config)
    # A replay is either an explicit ``Player`` (headless) or, as the TUI
    # builds it via ``RunConfig.for_playback``, a ``recording_path`` with
    # ``action=None`` that the engine turns into a ``Player`` itself.
    is_replay = type(action).__name__ == "Player" or (
        action is None and bool(getattr(run_config, "recording_path", None))
    )
    if is_replay:
        settings["replay_settle_seconds"] = _replay_settle_seconds(run_config)
    return settings


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
    # Device file names that are not valid UTF-8 arrive as lone surrogates
    # (``surrogateescape``); "backslashreplace" writes them as the JSON escape
    # ``\udcXX`` instead of failing the whole results file.
    out.write_text(text, encoding="utf-8", errors="backslashreplace")
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


TIMELINE_LOCK_NAME = ".timeline.lock"
RAW_PATTERN = "tracking/raw/*"
#: The patterns that only match a real timeline sink (not by file name).
_SINK_PATTERNS = frozenset({TIMELINE_FILE_NAME, TIMELINE_LOCK_NAME, RAW_PATTERN})


def _sink_live(root: Path, rel: str) -> str | None:
    """The sink pattern of ``rel`` when it is a live file of a real timeline
    sink, else None.

    A sink folder is ``root`` itself or one folder below it (``root`` is a
    device folder or a session folder) that holds ``.timeline.lock``; its
    ``timeline.jsonl``, its lock and its ``tracking/raw/...`` are live.
    """
    parts = rel.split("/")
    for depth in (0, 1):
        rest = parts[depth:]
        if not rest or (depth and not parts[0]):
            continue
        folder = root.joinpath(*parts[:depth])
        if rest == [TIMELINE_LOCK_NAME]:
            return TIMELINE_LOCK_NAME
        if not (folder / TIMELINE_LOCK_NAME).is_file():
            continue
        if rest == [TIMELINE_FILE_NAME]:
            return TIMELINE_FILE_NAME
        if len(rest) >= 3 and rest[:2] == ["tracking", "raw"]:
            return RAW_PATTERN
    return None


def _live_pattern(
    rel: str, patterns: tuple[str, ...], root: Path | None = None
) -> str | None:
    """The first pattern ``rel`` matches, else None.

    Patterns without ``/`` match the file name, patterns with ``/`` the end
    of the relative path, except the session timeline's
    (``timeline.jsonl``, ``.timeline.lock``, ``tracking/raw/*``), which only
    match a real sink under ``root`` (:func:`_sink_live`).
    """
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        if pat in _SINK_PATTERNS:
            continue
        if "/" in pat:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"*/{pat}"):
                return pat
        elif fnmatch.fnmatch(name, pat):
            return pat
    if root is not None and _SINK_PATTERNS.intersection(patterns):
        hit = _sink_live(root, rel)
        if hit is not None and hit in patterns:
            return hit
    return None


def _is_live_file(rel: str, root: Path | None = None) -> bool:
    return _live_pattern(rel, LIVE_FILE_PATTERNS, root) is not None


def _prefix_entry(full: Path, rel: str) -> dict[str, Any]:
    """``{rel, bytes, sha256}`` of the current content of a live file."""
    from sandroid.core import report_engine

    size = full.stat().st_size
    return {
        "rel": rel,
        "bytes": size,
        "sha256": report_engine.sha256_prefix(full, size),
    }


def _timeline_prefix_seal(full: Path, rel: str) -> dict[str, Any]:
    """Read-only seal of a live timeline (``timeline.seal_file``).

    Falls back to ``{bytes, sha256}`` of the current prefix when the timeline
    module is unavailable or cannot seal the file.
    """
    from sandroid.core import report_engine

    tl = report_engine._timeline_module()
    entry: dict[str, Any] = {"rel": rel}
    if tl is not None:
        try:
            entry.update(report_engine.seal_to_dict(tl.seal_file(full)) or {})
            return entry
        except Exception as exc:
            entry["seal_error"] = f"{type(exc).__name__}: {exc}"
    size = full.stat().st_size
    entry.update(
        {
            "path": str(full),
            "bytes": size,
            "sha256": report_engine.sha256_prefix(full, size),
        }
    )
    return entry


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
        exclude_patterns: Patterns of files still being written (logs by
            name; the session timeline only at its real sink location, see
            :data:`LIVE_FILE_PATTERNS`). They are listed under ``excluded``
            instead of hashed.

    Returns:
        A :class:`ManifestInfo`.
    """
    root = Path(result_dir).resolve()
    files: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    timeline_seals: list[dict[str, Any]] = []
    raw_prefixes: list[dict[str, Any]] = []
    for full, rel in _iter_result_files(root):
        if rel in (MANIFEST_NAME, SHA256SUMS_NAME):
            continue
        pattern = _live_pattern(rel, exclude_patterns, root)
        if pattern is not None:
            excluded.append(
                {
                    "path": rel,
                    "reason": _LIVE_REASONS.get(
                        pattern, "live log file, still written after manifest"
                    ),
                }
            )
            if pattern == TIMELINE_FILE_NAME and not full.is_symlink():
                try:
                    timeline_seals.append(_timeline_prefix_seal(full, rel))
                except OSError as exc:
                    timeline_seals.append({"rel": rel, "seal_error": str(exc)})
            elif pattern == RAW_PATTERN and not full.is_symlink():
                # Raw evidence is append-only: its current prefix is sealed.
                try:
                    raw_prefixes.append(_prefix_entry(full, rel))
                except OSError as exc:
                    raw_prefixes.append({"rel": rel, "seal_error": str(exc)})
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
    if timeline_seals:
        manifest["timeline_seals"] = timeline_seals
    if raw_prefixes:
        manifest["raw_prefixes"] = raw_prefixes
    manifest_path = root / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines = [f"{f['sha256']}  {f['path']}" for f in files]
    lines.append(f"{sha256_file(manifest_path)}  {MANIFEST_NAME}")
    sums_path = root / SHA256SUMS_NAME
    # surrogateescape: non-UTF-8 file names are written as their original
    # bytes, so ``sha256sum -c SHA256SUMS`` finds them.
    sums_path.write_text(
        "\n".join(lines) + "\n", encoding="utf-8", errors="surrogateescape"
    )
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
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        entries.append((rel, digest.strip().lower()))
    return entries


def _manifest_entries(path: Path, check: ManifestCheck) -> list[tuple[str, str]]:
    """``(path, sha256)`` pairs from ``manifest.json`` (unreadable -> mismatch)."""
    try:
        files = json.loads(path.read_text(encoding="utf-8")).get("files") or []
        return [
            (str(f["path"]), str(f["sha256"]).lower())
            for f in files
            if isinstance(f, dict) and "path" in f and "sha256" in f
        ]
    except (OSError, ValueError, AttributeError) as exc:
        logger.error("Cannot read %s: %s", path, exc)
        check.mismatched.append(MANIFEST_NAME)
        return []


def verify_hash_manifest(result_dir: str | os.PathLike[str]) -> ManifestCheck:
    """Re-hash ``result_dir`` against its ``SHA256SUMS`` (and its addenda).

    Every ``SHA256SUMS.addendum-*`` file (written when a report was
    regenerated later) is verified as well, so regenerated reports are
    covered by the same check.

    A sealed folder whose ``SHA256SUMS`` was deleted is not treated as
    unsealed: the files are verified against the per-file SHA-256 in
    ``manifest.json`` and ``SHA256SUMS`` itself is reported as missing.

    Returns:
        A :class:`ManifestCheck`; ``present`` is False when neither
        ``SHA256SUMS``, ``manifest.json`` nor an addendum exists.
        ``unlisted`` lists files added after the manifest (excluding live
        log files), which is informational only.
    """
    root = Path(result_dir).resolve()
    sums_path = root / SHA256SUMS_NAME
    sum_files = ([sums_path] if sums_path.is_file() else []) + _addendum_files(root)
    manifest_path = root / MANIFEST_NAME
    sums_lost = not sums_path.is_file() and manifest_path.is_file()
    if not sum_files and not sums_lost:
        return ManifestCheck(present=False)
    expected: list[tuple[str, str]] = []
    for path in sum_files:
        expected.extend(_read_sums(path))
    check = ManifestCheck(present=True)
    if sums_lost:
        check.missing.append(SHA256SUMS_NAME)
        logger.error(
            "%s is missing from sealed folder %s; verifying against %s",
            SHA256SUMS_NAME,
            root,
            MANIFEST_NAME,
        )
        expected.extend(_manifest_entries(manifest_path, check))
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
    listed = (
        {rel for rel, _ in expected}
        | {p.relative_to(root).as_posix() for p in sum_files}
        | ({MANIFEST_NAME} if sums_lost else set())
    )
    for _full, rel in _iter_result_files(root):
        if rel in listed or _is_live_file(rel, root):
            continue
        check.unlisted.append(rel)
    if manifest_path.is_file():
        _verify_prefixes(root, manifest_path, check)
    return check


def _verify_prefixes(root: Path, manifest_path: Path, check: ManifestCheck) -> None:
    """Re-check the sealed prefixes of the live files (``timeline_seals``,
    ``raw_prefixes``): sha256 of ``file[0:bytes]``. A file that is gone is
    missing; one that is shorter or whose prefix changed is mismatched.
    """
    from sandroid.core import report_engine

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return  # unreadable: already reported through SHA256SUMS
    if not isinstance(manifest, dict):
        return
    entries = [
        *(manifest.get("timeline_seals") or []),
        *(manifest.get("raw_prefixes") or []),
    ]
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("rel"):
            continue
        rel, digest = str(entry["rel"]), entry.get("sha256")
        if not isinstance(digest, str):
            continue  # recorded with a seal_error: nothing to compare
        path = root / rel
        if not path.is_file():
            if rel not in check.missing:
                check.missing.append(rel)
            continue
        try:
            n_bytes = int(entry.get("bytes") or 0)
            same = path.stat().st_size >= n_bytes and (
                report_engine.sha256_prefix(path, n_bytes) == digest.lower()
            )
        except (OSError, TypeError, ValueError):
            same = False
        if not same:
            logger.error(
                "%s changed: the SHA-256 of its first %s bytes no longer "
                "matches the manifest",
                rel,
                entry.get("bytes"),
            )
            if rel not in check.mismatched:
                check.mismatched.append(rel)


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
    #: ``report.json`` (the renderers' input) and ``report.md``.
    report_json: Path | None = None
    markdown: Path | None = None
    #: ``timeline_seal.json`` (only when a session timeline was sealed).
    timeline_seal: Path | None = None


def _find_session_timeline(root: Path) -> Path | None:
    """A closed ``timeline.jsonl`` in ``root`` or one of its device folders."""
    candidates = [
        root / TIMELINE_FILE_NAME,
        *sorted(root.glob(f"*/{TIMELINE_FILE_NAME}")),
    ]
    found = [p for p in candidates if p.is_file()]
    if not found:
        return None
    return max(found, key=lambda p: p.stat().st_mtime)


def _seal_timeline_for_report(
    root: Path,
) -> tuple[Path | None, Any | None, str | None]:
    """Seal the session timeline for a report written into ``root``.

    With a bound timeline sink the live file is sealed through the service
    (``seal(by="report")`` writes a ``sandroid/seal`` line). Otherwise (pure
    CLI over a session folder) a ``timeline.jsonl`` under ``root``'s device
    folder is sealed read-only with ``seal_file``.

    Returns:
        ``(timeline path, seal, note)``; ``note`` explains a missing timeline.
    """
    from sandroid.core import report_engine

    tl = report_engine._timeline_module()
    if tl is None:
        return None, None, "The session timeline is not available in this build."
    status = None
    try:
        service = tl.get_timeline()
        status = service.status()
    except Exception as exc:
        logger.debug("report: no timeline service: %s", exc)
    state = getattr(status, "state", None)
    folder = getattr(status, "folder", None)
    if state == "open" and folder:
        report_rel = os.path.relpath(
            root.resolve() / REPORT_JSON_NAME, Path(folder).resolve()
        )
        path = Path(folder) / tl.FILE_NAME
        try:
            seal = service.seal(by="report", report=Path(report_rel).as_posix())
        except Exception as exc:
            logger.error("Sealing the session timeline failed: %s", exc, exc_info=True)
            seal = None
        if seal is None:
            return path, None, f"The session timeline {path} could not be sealed."
        return Path(getattr(seal, "path", None) or path), seal, None
    if state in ("locked", "failed"):
        who = getattr(status, "locked_by", None)
        return (
            None,
            None,
            f"The session timeline was {state}"
            + (f" ({who})" if who else "")
            + "; this Sandroid window recorded no timeline.",
        )
    path = _find_session_timeline(root)
    if path is None:
        return None, None, "No session timeline was found for this result folder."
    try:
        return path, tl.seal_file(path), None
    except Exception as exc:
        logger.error("Sealing %s failed: %s", path, exc, exc_info=True)
        return path, None, f"The session timeline {path} could not be sealed: {exc}"


def _write_timeline_seal(root: Path, timeline: Path, seal: Any, scope: Any) -> Path:
    from sandroid.core import report_engine

    sealed = report_engine.seal_to_dict(seal) or {}
    path = root / TIMELINE_SEAL_NAME
    doc = {
        "seal": sealed,
        "timeline_path": str(Path(timeline).resolve()),
        "session_id": sealed.get("session_id"),
        "scope": report_engine.scope_to_dict(scope),
    }
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return path


def _flush_privacy_scan(timeout: float = 5.0) -> None:
    """Let the privacy scan finish the queued flows and files (bounded), so
    the report's privacy section sees the run's last findings. Never raises.
    """
    try:
        from sandroid.services.privacy_scan import _existing_service

        service = _existing_service()
        if service is not None and service.is_active:
            service.flush(timeout)
    except Exception:
        logger.debug("privacy scan flush before the report failed", exc_info=True)


def _write_run_report(
    root: Path,
    outcome: FinalizeOutcome,
    *,
    config: Any,
    run_id: str | None,
    generate_pdf: bool,
    pdf_name: str,
) -> None:
    """Seal the timeline, then write report.json/.md (+ PDF) into ``root``."""
    from sandroid.core import report_engine, report_render

    doc = None
    _flush_privacy_scan()
    try:
        timeline, seal, note = _seal_timeline_for_report(root)
        scope = report_engine.ReportScope()
        if timeline is not None and seal is not None:
            if run_id:
                scope = report_engine.scope_for_run(
                    timeline, run_id, end=getattr(seal, "bytes", None)
                )
            outcome.timeline_seal = _write_timeline_seal(root, timeline, seal, scope)
        elif run_id:
            scope = report_engine.ReportScope(kind="run", run_id=run_id)
        options = report_engine.report_options_from_config(
            config, coverage_notes=(note,) if note else ()
        )
        doc = report_engine.build_report(
            timeline=timeline if seal is not None else None,
            seal=seal,
            scope=scope,
            bundle_dir=root,
            options=options,
            results_json=outcome.results_json,
        )
        formats = ["json"]
        if "md" in report_engine.report_formats(config):
            formats.append("md")
        written = report_engine.write_report(
            doc, root, stem=REPORT_STEM, formats=formats
        )
        outcome.report_json = written.get("json")
        outcome.markdown = written.get("md")
        logger.info("Report written: %s", outcome.report_json)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc, exc_info=True)
        outcome.errors.append(f"report: {exc}")

    if not generate_pdf:
        return
    try:
        if outcome.report_json is None:
            raise RuntimeError("report.json could not be written")
        data = json.loads(outcome.report_json.read_text(encoding="utf-8"))
        outcome.pdf = report_render.render_pdf(data, root / pdf_name, base_dir=root)
    except Exception as exc:
        logger.error("PDF report generation failed: %s", exc, exc_info=True)
        outcome.errors.append(f"pdf: {exc}")


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
    run_settings: dict[str, Any] | None = None,
) -> FinalizeOutcome:
    """Write all evidence documentation for a finished analysis run.

    Call this once per run, after the analysis engine returned (CLI, TUI and
    API alike). Steps: results JSON with ``"Run Metadata"`` → seal of the
    session timeline (``timeline_seal.json``) → ``report.json`` +
    ``report.md`` → optional PDF → hash manifest. Report, PDF and manifest
    failures are logged and reported in ``errors`` (``"report: …"``,
    ``"pdf: …"``, ``"manifest: …"``) but never raised; failing to write the
    JSON raises.

    Args:
        result_dir: The run's result folder (where the JSON is written).
        results: The legacy results mapping (``RunResult.to_json_dict()``).
        output_name: File name of the results JSON inside ``result_dir``;
            an absolute path is honoured as-is.
        adb: adb-capable object for device metadata (``None`` to skip).
        config: ``SandroidConfig`` for the sanitised settings (optional).
        started_at: Analysis start (datetime/ISO string/epoch).
        ended_at: Analysis end; defaults to now.
        run_id: Optional run identifier (run bundles); selects the run scope
            of the report.
        mode: Free-form mode label (``"cli"``, ``"tui-play"``, ...).
        generate_pdf: Also render the PDF report.
        pdf_name: PDF file name inside ``result_dir``.
        write_manifest: Write ``manifest.json``/``SHA256SUMS`` at the end.
        run_settings: Settings the analysis actually used
            (:func:`describe_run_settings`); recorded in the metadata.

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
        run_settings=run_settings,
    )
    run_errors = results.get(RUN_ERRORS_KEY)
    if isinstance(run_errors, dict) and run_errors:
        metadata["run_status"] = run_errors.get("status") or "completed with errors"
        metadata["run_errors"] = run_errors
        logger.error(
            "Run %s: %s",
            metadata["run_status"],
            run_errors.get("fatal")
            or f"{len(run_errors.get('steps') or [])} step error(s)",
        )
    else:
        metadata["run_status"] = "completed"
    if adb is not None:
        # The results' "Device Name" is a session label (it can still be the
        # config default); keep it in line with what the device confirmed.
        confirmed = metadata["device"].get("device_name") or "unknown"
        if results.get("Device Name") != confirmed:
            logger.warning(
                "Device Name %r not confirmed by the device; recording %r",
                results.get("Device Name"),
                confirmed,
            )
            results = {**results, "Device Name": confirmed}
    out_json = Path(output_name)
    if not out_json.is_absolute():
        out_json = root / out_json
    outcome = FinalizeOutcome(
        results_json=write_results_json(results, out_json, metadata)
    )
    logger.info("Results written: %s", out_json)

    _write_run_report(
        root,
        outcome,
        config=config,
        run_id=run_id,
        generate_pdf=generate_pdf,
        pdf_name=pdf_name,
    )

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
    #: Addendum manifest recording the regenerated files (sealed folders).
    addendum: Path | None = None
    addendum_sha256: str | None = None
    #: The regenerated ``report*.json`` and ``report*.md``.
    report_json: Path | None = None
    markdown: Path | None = None
    #: Why the timeline could not be re-read (missing or changed), if so.
    timeline_note: str | None = None


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
    with open(path, "x", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write("\n".join(lines) + "\n")
    return path, sha256_file(path)


def _timeline_problem(path: Path, seal: dict[str, Any]) -> str | None:
    """Why ``path`` no longer matches ``seal`` (``None``: the prefix matches)."""
    from sandroid.core import report_engine

    if not path.is_file():
        return f"The session timeline {path} is missing"
    try:
        n_bytes = int(seal.get("bytes") or 0)
        size = path.stat().st_size
        if size < n_bytes:
            return (
                f"The session timeline {path} is shorter ({size} bytes) than "
                f"when it was sealed ({n_bytes} bytes)"
            )
        if (
            report_engine.sha256_prefix(path, n_bytes)
            != str(seal.get("sha256") or "").lower()
        ):
            return (
                f"The session timeline {path} changed: the SHA-256 of its first "
                f"{n_bytes} bytes no longer matches the seal"
            )
    except (OSError, ValueError, TypeError) as exc:
        return f"The session timeline {path} could not be checked: {exc}"
    return None


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _regenerated_report(
    root: Path, json_file: str | os.PathLike[str] | None
) -> tuple[dict[str, Any], str | None]:
    """The report document for :func:`report_from_folder` and a timeline note.

    The timeline is re-read when ``timeline_seal.json`` still matches it.
    Otherwise the previous ``report.json`` is re-rendered with a coverage
    warning, or (no previous report) the report is built without timeline.
    """
    from sandroid.core import report_engine

    config = None
    try:
        from sandroid.config import get_config

        config = get_config()
    except Exception:
        config = None
    seal_info = _read_json(root / TIMELINE_SEAL_NAME)
    previous = _read_json(root / REPORT_JSON_NAME)
    scope = report_engine.scope_from_dict(
        (seal_info or {}).get("scope") or (previous or {}).get("scope")
    )
    results_json = Path(json_file) if json_file else None
    note: str | None = None
    if seal_info and isinstance(seal_info.get("seal"), dict):
        seal = seal_info["seal"]
        timeline = Path(str(seal_info.get("timeline_path") or seal.get("path") or ""))
        note = _timeline_problem(timeline, seal)
        if note is None and report_engine._timeline_module() is None:
            note = "The session timeline reader is not available in this build"
        if note is None:
            options = report_engine.report_options_from_config(config)
            doc = report_engine.build_report(
                timeline=timeline,
                seal=seal,
                scope=scope,
                bundle_dir=root,
                options=options,
                results_json=results_json,
            )
            return doc, None
        logger.warning("%s; the report is not re-derived from it.", note)
        if previous is not None:
            return report_engine.annotate_rerender(previous, note), note
        notes: tuple[str, ...] = (f"{note}. The transcript is omitted.",)
    else:
        notes = (
            "This result folder has no sealed session timeline "
            f"({TIMELINE_SEAL_NAME}); the transcript is omitted.",
        )
    options = report_engine.report_options_from_config(config, coverage_notes=notes)
    doc = report_engine.build_report(
        timeline=None,
        seal=None,
        scope=scope,
        bundle_dir=root,
        options=options,
        results_json=results_json,
    )
    return doc, note


def _free_stem(folder: Path, stem: str, suffixes: tuple[str, ...]) -> str:
    """``stem`` or ``<stem>_2``, ``_3``, ... so that no ``stem+suffix`` exists."""
    candidate, n = stem, 1
    while any((folder / f"{candidate}{sfx}").exists() for sfx in suffixes):
        n += 1
        candidate = f"{stem}_{n}"
    return candidate


def report_from_folder(
    result_dir: str | os.PathLike[str],
    *,
    json_file: str | os.PathLike[str] | None = None,
    output_pdf: str | os.PathLike[str] | None = None,
    update_manifest: bool = True,
) -> ReportFromFolderOutcome:
    """(Re)generate the report (JSON, Markdown, PDF) for a result folder.

    Shared by ``sandroid --report-from`` and the TUI ``P`` key. Evidence
    rules:

    1. The existing ``SHA256SUMS`` (and any addenda) is verified *before*
       anything is written. On a mismatch nothing is written and
       :class:`EvidenceVerificationError` is raised.
    2. The session timeline is re-read only if the SHA-256 of its first
       ``seal.bytes`` bytes still matches ``timeline_seal.json``. If it is
       missing or changed, the previous ``report.json`` is re-rendered and
       its coverage section states that the data was not re-derived.
    3. No existing file is ever overwritten: the files are written as
       ``report_regenerated_<UTC>.{json,md,pdf}`` (only a folder without
       manifest and without a report gets the default names).
    4. In a sealed folder the new files are recorded in
       ``SHA256SUMS.addendum-<UTC>`` (plus a log line); the original
       ``SHA256SUMS``/``manifest.json`` stay unchanged. A folder without any
       manifest gets a fresh one.

    Args:
        result_dir: Existing result folder.
        json_file: Results JSON (located automatically if omitted).
        output_pdf: Explicit PDF path; must not exist yet. The JSON and
            Markdown files are written next to it with the same stem.
        update_manifest: Record the new files (addendum or new manifest).

    Returns:
        A :class:`ReportFromFolderOutcome`.

    Raises:
        FileNotFoundError: ``result_dir`` does not exist.
        EvidenceVerificationError: The folder does not match its manifest.
        FileExistsError: ``output_pdf`` (or its JSON/Markdown) already exists.
    """
    from sandroid.core import report_engine, report_render

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
        pdf = Path(output_pdf)
        out_dir, stem = pdf.parent, pdf.stem
        for path in (pdf, out_dir / f"{stem}.json", out_dir / f"{stem}.md"):
            if path.exists():
                raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    elif not sealed and not any(
        (root / name).exists()
        for name in (REPORT_JSON_NAME, REPORT_MD_NAME, DEFAULT_PDF_NAME)
    ):
        out_dir, stem = root, REPORT_STEM
        pdf = root / DEFAULT_PDF_NAME
    else:
        out_dir = root
        stem = _free_stem(
            root,
            REGENERATED_STEM_TEMPLATE.format(stamp=stamp),
            (".json", ".md", ".pdf"),
        )
        pdf = root / f"{stem}.pdf"
    doc, note = _regenerated_report(root, json_file)
    written: dict[str, Path] = {}
    try:
        written = report_engine.write_report(
            doc, out_dir, stem=stem, formats=("json", "md")
        )
        data = json.loads(written["json"].read_text(encoding="utf-8"))
        written["pdf"] = report_render.render_pdf(data, pdf, base_dir=out_dir)
    except BaseException:
        # Do not leave half-written reports behind (they did not exist before:
        # the stem is free or the default names were checked). write_report
        # may fail after writing the JSON, before it returns anything.
        for path in (
            *written.values(),
            pdf,
            out_dir / f"{stem}.json",
            out_dir / f"{stem}.md",
        ):
            Path(path).unlink(missing_ok=True)
        raise
    outcome = ReportFromFolderOutcome(
        pdf=pdf,
        check=check,
        report_json=written.get("json"),
        markdown=written.get("md"),
        timeline_note=note,
    )
    if not update_manifest:
        return outcome
    if sealed:
        resolved = root.resolve()
        new_files = [
            p
            for p in (outcome.report_json, outcome.markdown, pdf)
            if p is not None and Path(p).resolve().is_relative_to(resolved)
        ]
        outcome.addendum, outcome.addendum_sha256 = write_manifest_addendum(
            root, new_files, stamp
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
    "REGENERATED_STEM_TEMPLATE",
    "REPORT_JSON_NAME",
    "REPORT_MD_NAME",
    "RUN_ERRORS_KEY",
    "RUN_METADATA_KEY",
    "SHA256SUMS_NAME",
    "TIMELINE_SEAL_NAME",
    "EvidenceVerificationError",
    "FinalizeOutcome",
    "ManifestCheck",
    "ManifestInfo",
    "ReportFromFolderOutcome",
    "build_run_metadata",
    "collect_device_metadata",
    "collect_host_metadata",
    "describe_run_settings",
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
