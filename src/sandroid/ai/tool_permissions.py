r"""Tool-call permissions for the AI runtime: rules, modes and the approval broker.

Claude-Code-style permission rules, persisted in
``~/.config/sandroid/ai_tool_permissions.toml`` (or under
``$XDG_CONFIG_HOME/sandroid``)::

    mode = "ask"            # "ask" | "allow_all"
    allow = ["launch_app", "kill_process(package=com.example.*)"]
    deny  = []

Rule syntax is ``tool`` or ``tool(arg=glob, ...)``. Globs are
:func:`fnmatch.fnmatchcase` patterns matched against the argument's string
form (strings as-is, booleans ``true``/``false``, numbers ``str()``, other
values as sorted JSON). A value that contains ``,``, ``)``, ``=``, ``"`` or
surrounding blanks is written in double quotes (``\"`` and ``\\`` escape).
Every constraint of a rule must match. A constrained rule never matches a
missing argument (absent, ``None`` or ``""``): those calls fall back to e.g.
the spotlight app, which the rule did not name.

Resolution order (:meth:`ToolPermissionStore.resolve`, design §8):

1. ``RiskTier.NOT_EXPOSED`` -> deny.
2. A matching ``deny`` rule -> deny.
3. ``mode = "allow_all"`` (from the file or a session override) -> allow.
4. A matching ``allow`` rule -> allow.
5. ``RiskTier.READ_ONLY`` -> allow.
6. Otherwise ask.

*Argument-dependent* tools (``permission_key`` set, or
``can_remember_choice=False``) are tools whose risk lives in their arguments.
Only argument-constrained ``allow`` rules apply to them; a bare ``allow`` rule
is rejected when added and ignored (with a logged warning) when found in the
file. A bare ``deny`` rule is honoured for every tool (it only restricts).

The legacy ``allowed``/``never`` file format (still read and written by
older Sandroid installs) is migrated in memory only: ``allowed`` becomes
``allow`` (minus bare names of argument-dependent tools); ``never`` is NOT
enforced any more, it is shown once as "previous declines (not enforced)"
(:meth:`legacy_notice_pending`). Loading never writes. The first explicit
change (a new rule, a mode) writes ``<file>.bak-legacy`` once, materialises
the migrated ``allow`` rules and marks the file ``version = 2``; the legacy
``allowed``/``never`` keys are kept untouched so older installs keep working,
and in a ``version = 2`` file they are never re-interpreted as rules.

A file that exists but cannot be parsed fails closed: mode ``ask``, no allow
rules, and the file is never overwritten (rules remembered meanwhile live for
this session only). Writes are serialized by a thread lock plus an advisory
file lock, re-read the file first (so hand edits survive) and are atomic
(temp file + rename). With ``tomlkit`` installed, comments are preserved.

:class:`ApprovalBroker` is the FIFO of pending approval requests from any
agent. It has no UI dependency: listeners are plain callbacks, the TUI
marshals them onto its own thread.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import logging
import os
import re
import tempfile
import threading
import time
import tomllib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

import tomli_w

from sandroid.ai.tools.registry import RiskTier

try:  # Optional: preserves comments and layout of a hand-edited file.
    import tomlkit as _tomlkit
except ImportError:  # pragma: no cover - depends on the environment
    _tomlkit = None

logger = logging.getLogger(__name__)

#: Legacy outcomes of :func:`resolve_tool_policy` (pre-WP4 loop).
ToolPolicy = Literal["allowed", "never", "ask"]
#: Permission modes. ``ask`` is the shipped default.
PermissionMode = Literal["ask", "allow_all"]
#: Outcome of a resolution.
Outcome = Literal["allow", "deny", "ask"]
#: Why a resolution came out the way it did.
ResolutionReason = Literal[
    "not_exposed",
    "deny_rule",
    "session_decline",
    "allow_all",
    "allow_rule",
    "read_only",
    "ask",
]
#: A user's answer to an approval prompt.
Choice = Literal["once", "always", "no"]
#: Who/what produced a :class:`Decision`.
DecidedBy = Literal["user", "rule", "timeout", "cancelled"]

MODES: tuple[str, ...] = ("ask", "allow_all")
#: What the egress notice / header say in ``allow_all`` mode (design §8).
ALLOW_ALL_NOTICE = "device-changing tools run without asking"
#: Default approval timeout; a timed-out request counts as No.
APPROVAL_TIMEOUT_S = 300.0

_FILE_HEADER = """\
# Sandroid AI tool permissions.
# mode  = "ask" asks before device-changing tools; "allow_all" runs them
#         without asking (deny rules still apply).
# Rules: "tool" or "tool(arg=glob, ...)", e.g. "kill_process(package=com.example.*)".
# Deny wins over everything; allow rules skip the approval prompt.
"""

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def _default_permissions_path() -> Path:
    """``$XDG_CONFIG_HOME/sandroid`` or ``~/.config/sandroid`` + file name."""
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        config_dir = Path(xdg_config_home) / "sandroid"
    else:
        config_dir = Path.home() / ".config" / "sandroid"
    return config_dir / "ai_tool_permissions.toml"


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

_ACRONYMS = {
    "Apk": "APK",
    "Pid": "PID",
    "Mcp": "MCP",
    "Url": "URL",
    "Ip": "IP",
    "Id": "ID",
    "Ssl": "SSL",
    "Tls": "TLS",
    "Ca": "CA",
    "Ui": "UI",
    "Adb": "ADB",
    "Avd": "AVD",
    "Quic": "QUIC",
}


def humanize_tool_name(name: str) -> str:
    """``install_apk`` -> ``"Install APK"``; MCP names are returned unchanged."""
    if ":" in name:
        return name
    words = name.replace("_", " ").title().split(" ")
    return " ".join(_ACRONYMS.get(word, word) for word in words)


def is_argument_dependent(
    permission_key: str | Sequence[str] | None = None,
    can_remember_choice: bool = True,
) -> bool:
    """Whether a tool's risk lives in its arguments (bare allow rules are void)."""
    return bool(permission_key) or not can_remember_choice


def _keys(permission_key: str | Sequence[str] | None) -> tuple[str, ...]:
    if not permission_key:
        return ()
    if isinstance(permission_key, str):
        return (permission_key,)
    return tuple(permission_key)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


class RuleSyntaxError(ValueError):
    """A permission rule string could not be parsed."""


_TOOL_RE = re.compile(r"[A-Za-z0-9_.:\-]+")
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NEEDS_QUOTES = re.compile(r'[,()="\\]|^\s|\s$')


def _arg_text(value: Any) -> str | None:
    """The string form an argument is matched as; ``None`` means missing."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value if value != "" else None
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(value, sort_keys=True, default=str)


def glob_escape(text: str) -> str:
    """Escape fnmatch metacharacters so ``text`` only matches itself."""
    return re.sub(r"([*?\[])", r"[\1]", text)


def _glob_unescape(pattern: str) -> str | None:
    """The literal a pattern matches, or ``None`` if it is a real glob."""
    literal = re.sub(r"\[([*?\[])\]", r"\1", pattern)
    return literal if glob_escape(literal) == pattern else None


def _quote_value(value: str) -> str:
    if value and not _NEEDS_QUOTES.search(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_body(body: str, source: str) -> tuple[tuple[str, str], ...]:
    """Parse ``k=v, k2="v, 2"`` into ``(("k", "v"), ("k2", "v, 2"))``."""
    pairs: list[tuple[str, str]] = []
    i, n = 0, len(body)
    while True:
        while i < n and body[i].isspace():
            i += 1
        match = _KEY_RE.match(body, i)
        if not match:
            raise RuleSyntaxError(f"expected an argument name in {source!r}")
        key = match.group(0)
        i = match.end()
        while i < n and body[i].isspace():
            i += 1
        if i >= n or body[i] != "=":
            raise RuleSyntaxError(f"expected '=' after {key!r} in {source!r}")
        i += 1
        while i < n and body[i].isspace():
            i += 1
        if i < n and body[i] == '"':
            i += 1
            chars: list[str] = []
            while True:
                if i >= n:
                    raise RuleSyntaxError(f"unterminated quote in {source!r}")
                ch = body[i]
                if ch == "\\" and i + 1 < n:
                    chars.append(body[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                chars.append(ch)
                i += 1
            value = "".join(chars)
            while i < n and body[i].isspace():
                i += 1
        else:
            start = i
            while i < n and body[i] != ",":
                if body[i] in '"()=':
                    raise RuleSyntaxError(
                        f"unexpected {body[i]!r} in value of {key!r} in {source!r}; "
                        "quote the value"
                    )
                i += 1
            value = body[start:i].strip()
        if value == "":
            raise RuleSyntaxError(
                f"empty value for {key!r} in {source!r} (it could never match)"
            )
        if any(key == k for k, _ in pairs):
            raise RuleSyntaxError(f"duplicate argument {key!r} in {source!r}")
        pairs.append((key, value))
        if i >= n:
            break
        if body[i] != ",":
            raise RuleSyntaxError(f"expected ',' in {source!r}")
        i += 1
    return tuple(pairs)


@dataclass(frozen=True)
class PermissionRule:
    """One ``tool`` or ``tool(arg=glob, ...)`` rule."""

    tool: str
    constraints: tuple[tuple[str, str], ...] = ()

    @classmethod
    def parse(cls, text: str) -> PermissionRule:
        """Parse a rule string.

        Raises:
            RuleSyntaxError: The text is not a valid rule.
        """
        if not isinstance(text, str):
            raise RuleSyntaxError(f"rule must be a string, got {type(text).__name__}")
        source = text.strip()
        match = _TOOL_RE.match(source)
        if not match:
            raise RuleSyntaxError(f"expected a tool name in {text!r}")
        tool = match.group(0)
        rest = source[match.end() :].strip()
        if not rest:
            return cls(tool)
        if not (rest.startswith("(") and rest.endswith(")")):
            raise RuleSyntaxError(f"expected 'tool' or 'tool(arg=glob, ...)': {text!r}")
        body = rest[1:-1]
        if not body.strip():
            raise RuleSyntaxError(f"empty argument list in {text!r}")
        return cls(tool, _parse_body(body, text))

    @property
    def is_bare(self) -> bool:
        """True for a rule without argument constraints."""
        return not self.constraints

    def matches(self, tool: str, args: Mapping[str, Any] | None) -> bool:
        """Whether this rule covers a call of ``tool`` with ``args``."""
        if tool != self.tool:
            return False
        if not self.constraints:
            return True
        args = args or {}
        for key, pattern in self.constraints:
            text = _arg_text(args.get(key))
            if text is None or not fnmatchcase(text, pattern):
                return False
        return True

    def __str__(self) -> str:
        if not self.constraints:
            return self.tool
        inner = ", ".join(f"{k}={_quote_value(v)}" for k, v in self.constraints)
        return f"{self.tool}({inner})"

    def describe(self) -> str:
        """Human text for the rule.

        ``Kill Process with package = com.x`` for an exact value,
        ``... with package matching com.x.*`` for a glob.
        """
        name = humanize_tool_name(self.tool)
        if not self.constraints:
            return name
        parts = []
        for key, pattern in self.constraints:
            literal = _glob_unescape(pattern)
            if literal is not None:
                parts.append(f"{key} = {literal}")
            else:
                parts.append(f"{key} matching {pattern}")
        return name + " with " + ", ".join(parts)


def parse_rule(text: str) -> PermissionRule:
    """Parse a rule string (see :meth:`PermissionRule.parse`)."""
    return PermissionRule.parse(text)


def describe_rule(rule: str | PermissionRule) -> str:
    """Human description of a rule; the raw text when it does not parse."""
    if isinstance(rule, PermissionRule):
        return rule.describe()
    try:
        return PermissionRule.parse(rule).describe()
    except RuleSyntaxError:
        return rule


def suggest_rule(
    tool: str,
    args: Mapping[str, Any] | None = None,
    *,
    permission_key: str | Sequence[str] | None = None,
    can_remember_choice: bool = True,
) -> str | None:
    """The rule "Yes, don't ask again" would add, or ``None`` if none is possible.

    Plain tools get the bare tool name. Argument-dependent tools get
    ``tool(key=<exact value>)`` for their ``permission_key`` (the value is
    glob-escaped so it matches only itself); without a key, or when the key
    argument is missing, nothing can be remembered.
    """
    if not is_argument_dependent(permission_key, can_remember_choice):
        return tool
    keys = _keys(permission_key)
    if not keys:
        return None
    args = args or {}
    constraints = []
    for key in keys:
        text = _arg_text(args.get(key))
        if text is None:
            return None
        constraints.append((key, glob_escape(text)))
    return str(PermissionRule(tool, tuple(constraints)))


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Resolution:
    """Result of resolving one pending tool call."""

    outcome: Outcome
    reason: ResolutionReason
    rule: str | None = None
    suggested_rule: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def denied(self) -> bool:
        return self.outcome == "deny"

    @property
    def needs_approval(self) -> bool:
        return self.outcome == "ask"

    @property
    def legacy_policy(self) -> ToolPolicy:
        return {"allow": "allowed", "deny": "never", "ask": "ask"}[self.outcome]


def _registry_argument_dependent(name: str) -> bool:
    """Default resolver: ask the tool registry (best effort)."""
    try:
        from sandroid.ai.tools.registry import get_tool_registry

        spec = get_tool_registry().get_spec(name)
    except Exception:
        return False
    if spec is None:
        return False
    return is_argument_dependent(
        getattr(spec, "permission_key", None), spec.can_remember_choice
    )


_argument_dependency_resolver: Callable[[str], bool] | None = None


def set_argument_dependency_resolver(resolver: Callable[[str], bool] | None) -> None:
    """Install the tool-name -> "is argument-dependent" lookup.

    Used for name-only paths (legacy migration, :meth:`mark_allowed`, rules
    added from ``/permissions``). WP4 points this at the central toolset table;
    the default asks the tool registry.
    """
    global _argument_dependency_resolver
    _argument_dependency_resolver = resolver


def _is_arg_dependent_name(name: str) -> bool:
    resolver = _argument_dependency_resolver or _registry_argument_dependent
    try:
        return bool(resolver(name))
    except Exception:
        logger.debug("argument-dependency resolver failed for %r", name, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# File locking / atomic write
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Advisory inter-process lock on ``<path>.lock`` (no-op where unsupported)."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        yield
        return
    lock_path = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        logger.debug("Cannot open lock file %s", lock_path, exc_info=True)
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file in the same dir + rename."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", text=False
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).chmod(0o600)
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class _Doc:
    """A TOML document being edited: tomlkit (keeps comments) or a plain dict."""

    def __init__(self, text: str) -> None:
        if _tomlkit is not None:
            self.doc: Any = _tomlkit.parse(text)
        else:
            self.doc = tomllib.loads(text)

    def get(self, key: str, default: Any = None) -> Any:
        return self.doc.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.doc

    def set(self, key: str, value: Any) -> None:
        self.doc[key] = value

    def delete(self, key: str) -> None:
        if key in self.doc:
            del self.doc[key]

    def list(self, key: str) -> Any:
        if key not in self.doc or not isinstance(self.doc[key], list):
            self.doc[key] = []
        return self.doc[key]

    def dumps(self) -> str:
        if _tomlkit is not None:
            return _tomlkit.dumps(self.doc)
        return tomli_w.dumps(dict(self.doc))

    def plain(self) -> dict[str, Any]:
        if _tomlkit is not None:
            return self.doc.unwrap()
        return dict(self.doc)


def _default_text() -> str:
    return _FILE_HEADER + 'mode = "ask"\nallow = []\ndeny = []\n'


#: Keys of the pre-rules file format (read by older Sandroid installs).
_LEGACY_KEYS = ("allowed", "never")

#: ``version`` written when a legacy file is first changed by this format.
_FORMAT_VERSION = 2

#: Suffix of the one-time backup of a legacy file before its first rewrite.
LEGACY_BACKUP_SUFFIX = ".bak-legacy"


def _names(raw: Any) -> list[str]:
    """String entries of a legacy name list (anything else: empty)."""
    if not isinstance(raw, list):
        return []
    return [n for n in raw if isinstance(n, str)]


def _is_legacy_format(data: Mapping[str, Any]) -> bool:
    """Legacy keys present and the file not yet migrated (``version < 2``)."""
    if not any(key in data for key in _LEGACY_KEYS):
        return False
    try:
        return int(data.get("version", 1)) < _FORMAT_VERSION
    except (TypeError, ValueError):
        return True


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class ToolPermissionStore:
    """Rules + mode from the permissions file, plus session-only overrides.

    Thread-safe: in-memory state is guarded by an ``RLock``; file writes also
    take an advisory file lock and are atomic.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        arg_dependent: Callable[[str], bool] | None = None,
    ) -> None:
        """Load the store.

        Args:
            path: The permissions file. Defaults to the real config location;
                tests pass a temp path.
            arg_dependent: Tool-name -> argument-dependent lookup for name-only
                paths (migration, :meth:`mark_allowed`). Defaults to the
                module resolver (:func:`set_argument_dependency_resolver`).
        """
        self._path = path if path is not None else _default_permissions_path()
        self._arg_dependent = arg_dependent
        self._lock = threading.RLock()
        self._file_mode: PermissionMode = "ask"
        self._allow: list[PermissionRule] = []
        self._deny: list[PermissionRule] = []
        self._legacy_declines: list[str] = []
        self._legacy_notified = False
        self._warnings: list[str] = []
        self._load_error: str | None = None
        # Session-only state (never written).
        self._session_mode: PermissionMode | None = None
        self._session_allow: list[PermissionRule] = []
        self._session_declines: set[str] = set()
        self._warned_bare: set[str] = set()
        self.reload()

    # -- properties --------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def load_error(self) -> str | None:
        """Why the file could not be read (then the store fails closed)."""
        return self._load_error

    @property
    def writable(self) -> bool:
        """False while the file is unparseable: it is never overwritten then."""
        return self._load_error is None

    @property
    def file_mode(self) -> PermissionMode:
        return self._file_mode

    @property
    def session_mode(self) -> PermissionMode | None:
        return self._session_mode

    @property
    def mode(self) -> PermissionMode:
        """The effective mode: the session override, else the file's mode."""
        with self._lock:
            return self._session_mode or self._file_mode

    def warnings(self) -> list[str]:
        """Problems found in the file (invalid or ignored rules)."""
        with self._lock:
            return list(self._warnings)

    def allow_rules(self) -> list[str]:
        """Persisted allow rules followed by session-only ones."""
        with self._lock:
            return [str(r) for r in self._allow + self._session_allow]

    def deny_rules(self) -> list[str]:
        with self._lock:
            return [str(r) for r in self._deny]

    def session_allow_rules(self) -> list[str]:
        with self._lock:
            return [str(r) for r in self._session_allow]

    # -- legacy declines notice -------------------------------------------

    def legacy_declines(self) -> list[str]:
        """Legacy ``never`` entries, shown as "previous declines (not enforced)"."""
        with self._lock:
            return list(self._legacy_declines)

    def legacy_notice_pending(self) -> bool:
        """True until :meth:`acknowledge_legacy_notice` (shown once in chat)."""
        with self._lock:
            return bool(self._legacy_declines) and not self._legacy_notified

    def acknowledge_legacy_notice(self) -> None:
        """Record that the one-time legacy-declines notice was shown.

        In memory only (loading or showing the notice never writes the
        file); the flag is persisted with the next explicit change.
        """
        with self._lock:
            self._legacy_notified = True

    # -- loading -----------------------------------------------------------

    def _name_is_arg_dependent(self, name: str) -> bool:
        if self._arg_dependent is not None:
            try:
                return bool(self._arg_dependent(name))
            except Exception:
                return False
        return _is_arg_dependent_name(name)

    def reload(self) -> None:
        """(Re)read the file. Never writes (a legacy file migrates in memory)."""
        with self._lock:
            self._load_error = None
            if not self._path.exists():
                self._apply({})
                return
            try:
                text = self._path.read_text(encoding="utf-8")
                data = tomllib.loads(text)
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                self._fail_closed(f"{type(exc).__name__}: {exc}")
                return
            self._apply(self._interpret(data))

    def _fail_closed(self, error: str) -> None:
        logger.warning(
            "AI tool permissions file %s is unreadable (%s); asking for every "
            "device-changing tool and leaving the file untouched",
            self._path,
            error,
        )
        self._load_error = error
        self._file_mode = "ask"
        self._allow = []
        self._deny = []
        self._warnings = [f"file unreadable: {error}"]

    def _legacy_allow(self, data: Mapping[str, Any]) -> list[str]:
        """Legacy ``allowed`` names that become ``allow`` rules."""
        legacy_allowed = _names(data.get("allowed"))
        dropped = [n for n in legacy_allowed if self._name_is_arg_dependent(n)]
        if dropped:
            logger.info(
                "Not migrating 'always allow' for argument-dependent tools: %s",
                ", ".join(sorted(dropped)),
            )
        return [n for n in legacy_allowed if n not in dropped]

    def _interpret(self, data: Mapping[str, Any]) -> dict[str, Any]:
        """The effective data of a file (pure; nothing is written).

        An unmigrated legacy file gets its ``allowed`` names as ``allow``
        rules (minus argument-dependent ones). Legacy ``never`` entries are
        only reported as previous declines, never enforced. In a migrated
        (``version = 2``) file the legacy keys are not re-interpreted.
        """
        out = dict(data)
        if _is_legacy_format(data):
            allow = out.get("allow", [])
            if isinstance(allow, list):
                out["allow"] = list(allow) + [
                    n for n in self._legacy_allow(data) if n not in allow
                ]
        declines: list[str] = []
        for name in _names(data.get("legacy_declines")) + _names(data.get("never")):
            if name not in declines:
                declines.append(name)
        out["legacy_declines"] = declines
        return out

    def _backup_legacy(self, text: str) -> None:
        """Write ``<file>.bak-legacy`` once (never overwritten)."""
        backup = self._path.with_name(self._path.name + LEGACY_BACKUP_SUFFIX)
        try:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())

    def _materialize_legacy(self, doc: _Doc) -> None:
        """Write the in-memory migration into *doc*; legacy keys stay as is."""
        data = doc.plain()
        allow = doc.list("allow")
        for name in self._legacy_allow(data):
            if name not in allow:
                allow.append(name)
        doc.list("deny")
        if "mode" not in doc:
            doc.set("mode", "ask")
        doc.set("version", _FORMAT_VERSION)

    def _parse_rules(self, raw: Any, kind: str) -> list[PermissionRule]:
        rules: list[PermissionRule] = []
        if raw is None:
            return rules
        if not isinstance(raw, list):
            self._warnings.append(f"'{kind}' must be a list of rule strings")
            return rules
        for entry in raw:
            try:
                rule = PermissionRule.parse(entry)
            except RuleSyntaxError as exc:
                if kind == "deny" and isinstance(entry, str):
                    # Fail closed: a garbled deny rule still denies its tool.
                    head = _TOOL_RE.match(entry.strip())
                    if head:
                        rules.append(PermissionRule(head.group(0)))
                        self._warnings.append(
                            f"invalid deny rule {entry!r} ({exc}); denying "
                            f"'{head.group(0)}' entirely"
                        )
                        continue
                self._warnings.append(f"invalid {kind} rule {entry!r}: {exc}")
                continue
            if rule not in rules:
                rules.append(rule)
        return rules

    def _apply(self, data: Mapping[str, Any]) -> None:
        self._warnings = []
        mode = data.get("mode", "ask")
        if mode not in MODES:
            self._warnings.append(f"unknown mode {mode!r}; using 'ask'")
            mode = "ask"
        self._file_mode = mode
        self._allow = self._parse_rules(data.get("allow", []), "allow")
        self._deny = self._parse_rules(data.get("deny", []), "deny")
        for rule in self._allow:
            if rule.is_bare and self._name_is_arg_dependent(rule.tool):
                self._warnings.append(
                    f"allow rule {str(rule)!r} is ignored: {rule.tool} depends "
                    "on its arguments, use e.g. "
                    f"'{rule.tool}(<argument>=<glob>)'"
                )
        self._legacy_declines = _names(data.get("legacy_declines"))
        # An acknowledgement made in this process survives re-reads.
        self._legacy_notified = self._legacy_notified or bool(
            data.get("legacy_declines_notified", False)
        )

    # -- writing -----------------------------------------------------------

    def _write(self, mutate: Callable[[_Doc], None]) -> dict[str, Any] | None:
        """Re-read, mutate and atomically rewrite the file (explicit changes).

        A legacy file is backed up once (``<file>.bak-legacy``) and its
        in-memory migration materialised first; its ``allowed``/``never``
        keys are preserved for older installs.

        Returns the new plain data (also applied in memory), or ``None``
        when the file must not or could not be written.
        """
        with self._lock:
            if self._load_error is not None:
                return None
            try:
                with _file_lock(self._path):
                    if self._path.exists():
                        text = self._path.read_text(encoding="utf-8")
                    else:
                        text = _default_text()
                    try:
                        doc = _Doc(text)
                    except Exception as exc:
                        # Changed under us into something unparseable.
                        self._fail_closed(f"{type(exc).__name__}: {exc}")
                        return None
                    if _is_legacy_format(doc.plain()):
                        self._backup_legacy(text)
                        self._materialize_legacy(doc)
                    mutate(doc)
                    if (
                        self._legacy_notified
                        and self._interpret(doc.plain())["legacy_declines"]
                        and "legacy_declines_notified" not in doc
                    ):
                        doc.set("legacy_declines_notified", True)
                    _atomic_write(self._path, doc.dumps())
                    data = doc.plain()
            except OSError as exc:
                logger.warning(
                    "Failed to save AI tool permissions to %s: %s", self._path, exc
                )
                return None
            self._apply(self._interpret(data))
            return data

    # -- mutations -----------------------------------------------------------

    def _check_allow(self, rule: PermissionRule, argument_dependent: bool | None):
        dependent = (
            self._name_is_arg_dependent(rule.tool)
            if argument_dependent is None
            else argument_dependent
        )
        if rule.is_bare and dependent:
            raise ValueError(
                f"{rule.tool} depends on its arguments: an allow rule must "
                f"constrain one, e.g. '{rule.tool}(<argument>=<glob>)'"
            )

    def add_allow_rule(
        self,
        rule: str | PermissionRule,
        *,
        argument_dependent: bool | None = None,
        persist: bool = True,
    ) -> str:
        """Add an allow rule ("Yes, don't ask again").

        Args:
            rule: The rule.
            argument_dependent: Whether the rule's tool is argument-dependent;
                ``None`` looks it up by name.
            persist: False keeps it for this session only. When the file is
                unreadable the rule is kept for the session regardless.

        Returns:
            The canonical rule text.

        Raises:
            RuleSyntaxError: The rule does not parse.
            ValueError: A bare rule for an argument-dependent tool.
        """
        parsed = rule if isinstance(rule, PermissionRule) else parse_rule(rule)
        self._check_allow(parsed, argument_dependent)
        text = str(parsed)
        with self._lock:
            if persist and self.writable:

                def mutate(doc: _Doc) -> None:
                    allow = doc.list("allow")
                    if text not in allow:
                        allow.append(text)

                if self._write(mutate) is not None:
                    return text
            if parsed not in self._session_allow and parsed not in self._allow:
                self._session_allow.append(parsed)
        return text

    def add_deny_rule(self, rule: str | PermissionRule) -> str:
        """Persist a deny rule (``/permissions`` only; never from a prompt)."""
        parsed = rule if isinstance(rule, PermissionRule) else parse_rule(rule)
        text = str(parsed)

        def mutate(doc: _Doc) -> None:
            deny = doc.list("deny")
            if text not in deny:
                deny.append(text)

        if self._write(mutate) is None:
            with self._lock:
                if parsed not in self._deny:
                    self._deny.append(parsed)
        return text

    def remove_rule(self, kind: Literal["allow", "deny"], rule: str) -> bool:
        """Remove a rule (matched by canonical text). Returns True if found."""
        try:
            text = str(parse_rule(rule))
        except RuleSyntaxError:
            text = rule
        with self._lock:
            found = False
            if kind == "allow":
                before = len(self._session_allow)
                self._session_allow = [r for r in self._session_allow if str(r) != text]
                found = len(self._session_allow) != before

            def mutate(doc: _Doc) -> None:
                nonlocal found
                items = doc.list(kind)
                for entry in list(items):
                    try:
                        canon = str(parse_rule(entry))
                    except RuleSyntaxError:
                        canon = entry
                    if canon == text or entry == rule:
                        items.remove(entry)
                        found = True

            self._write(mutate)
            return found

    def set_mode(self, mode: PermissionMode) -> None:
        """Persist the file's mode."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        if self._write(lambda doc: doc.set("mode", mode)) is None:
            with self._lock:
                self._session_mode = mode

    def set_session_mode(self, mode: PermissionMode | None) -> None:
        """Override the mode for this session only (``None`` clears it)."""
        if mode is not None and mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        with self._lock:
            self._session_mode = mode

    def toggle_session_allow_all(self) -> PermissionMode:
        """Flip the session between ``allow_all`` and ``ask``; returns the new mode."""
        with self._lock:
            new: PermissionMode = "ask" if self.mode == "allow_all" else "allow_all"
            self._session_mode = new
            return new

    # -- resolution --------------------------------------------------------

    def resolve(
        self,
        name: str,
        risk: RiskTier,
        args: Mapping[str, Any] | None = None,
        *,
        permission_key: str | Sequence[str] | None = None,
        can_remember_choice: bool = True,
    ) -> Resolution:
        """Resolve a pending call (order in the module docstring).

        Args:
            name: Tool name (the inner name for ``call_tool``).
            risk: The tool's risk tier.
            args: The call's arguments.
            permission_key: The argument(s) that carry the risk, from the
                central toolset table; makes the tool argument-dependent.
            can_remember_choice: The ``ToolSpec`` flag; ``False`` also makes
                the tool argument-dependent.
        """
        args = args or {}
        dependent = is_argument_dependent(permission_key, can_remember_choice)
        suggestion = suggest_rule(
            name,
            args,
            permission_key=permission_key,
            can_remember_choice=can_remember_choice,
        )
        if risk == RiskTier.NOT_EXPOSED:
            return Resolution("deny", "not_exposed")
        with self._lock:
            deny = list(self._deny)
            allow = self._allow + self._session_allow
            mode = self.mode
            declined = name in self._session_declines
        for rule in deny:
            if rule.matches(name, args):
                return Resolution("deny", "deny_rule", rule=str(rule))
        if declined:
            return Resolution("deny", "session_decline")
        if mode == "allow_all":
            return Resolution("allow", "allow_all")
        for rule in allow:
            if rule.tool != name:
                continue
            if dependent and rule.is_bare:
                self._warn_bare(rule)
                continue
            if rule.matches(name, args):
                return Resolution("allow", "allow_rule", rule=str(rule))
        if risk == RiskTier.READ_ONLY:
            return Resolution("allow", "read_only")
        return Resolution("ask", "ask", suggested_rule=suggestion)

    def _warn_bare(self, rule: PermissionRule) -> None:
        with self._lock:
            if rule.tool in self._warned_bare:
                return
            self._warned_bare.add(rule.tool)
        logger.warning(
            "Ignoring allow rule %r: %s depends on its arguments; use an "
            "argument-constrained rule instead",
            str(rule),
            rule.tool,
        )

    # -- legacy API (pre-WP4 loop / tests) ------------------------------------

    def is_allowed(self, name: str) -> bool:
        """Legacy: whether a bare allow rule for ``name`` exists."""
        with self._lock:
            return any(
                r.is_bare and r.tool == name for r in self._allow + self._session_allow
            )

    def is_never(self, name: str) -> bool:
        """Legacy: a bare deny rule or a session decline for ``name``."""
        with self._lock:
            return name in self._session_declines or any(
                r.is_bare and r.tool == name for r in self._deny
            )

    def mark_allowed(self, name: str) -> None:
        """Legacy "Allow always": add a bare allow rule.

        Refused (logged) for argument-dependent tools.
        """
        with self._lock:
            self._session_declines.discard(name)
        try:
            self.add_allow_rule(name)
        except ValueError as exc:
            logger.warning("Not remembering %r: %s", name, exc)

    def mark_never(self, name: str) -> None:
        """Legacy "Never": declines ``name`` for this session only.

        A single click no longer writes a persistent deny (design §4); deny
        rules come only from the file or ``/permissions``.
        """
        with self._lock:
            self._session_declines.add(name)


# ---------------------------------------------------------------------------
# Approval broker
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalRequest:
    """One pending approval, as shown to the user."""

    request_id: str
    agent_id: str
    agent_label: str
    tool: str
    args: Mapping[str, Any]
    risk: RiskTier
    suggested_rule: str | None = None
    description: str = ""
    argument_dependent: bool = False
    created_at: float = field(default_factory=time.time)

    @property
    def suggested_rule_description(self) -> str | None:
        return describe_rule(self.suggested_rule) if self.suggested_rule else None


@dataclass(frozen=True)
class Decision:
    """The answer to an :class:`ApprovalRequest`."""

    choice: Choice
    note: str | None = None
    by: DecidedBy = "user"
    remembered_rule: str | None = None

    @property
    def approved(self) -> bool:
        return self.choice in ("once", "always")


#: Listener signature: ``(kind, request, decision)``; kind is ``"added"`` or
#: ``"resolved"`` (decision is ``None`` for ``"added"``).
ApprovalListener = Callable[[str, ApprovalRequest, Decision | None], None]


class PendingApproval:
    """Handle on a submitted request; wait for its :class:`Decision`."""

    def __init__(self, broker: ApprovalBroker, request: ApprovalRequest) -> None:
        self._broker = broker
        self.request = request
        self._event = threading.Event()
        self._decision: Decision | None = None

    @property
    def done(self) -> bool:
        return self._event.is_set()

    @property
    def decision(self) -> Decision | None:
        return self._decision

    def _set(self, decision: Decision) -> None:
        self._decision = decision
        self._event.set()

    def wait(
        self,
        timeout: float | None = None,
        cancel_event: threading.Event | None = None,
        poll_s: float = 0.1,
    ) -> Decision:
        """Block until decided, ``cancel_event`` is set, or ``timeout``.

        Timeout resolves the request as No (``by="timeout"``), a set
        ``cancel_event`` as No (``by="cancelled"``); either is broadcast to
        listeners so the UI removes the card.
        """
        timeout = self._broker.timeout_s if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return (
                    self._broker._finish(
                        self.request.request_id, Decision("no", by="timeout")
                    )
                    or self._final()
                )
            if cancel_event is not None and cancel_event.is_set():
                return (
                    self._broker._finish(
                        self.request.request_id, Decision("no", by="cancelled")
                    )
                    or self._final()
                )
            step = remaining if cancel_event is None else min(poll_s, remaining)
            if self._event.wait(step):
                return self._final()

    def _final(self) -> Decision:
        self._event.wait()
        assert self._decision is not None
        return self._decision


class ApprovalBroker:
    """FIFO of pending approval requests from any agent.

    The UI shows :meth:`head` and answers with :meth:`resolve`. "Yes, don't
    ask again" persists the request's suggested rule in the permission store
    before the waiter wakes, then auto-approves other pending requests the
    new rule covers.
    """

    def __init__(
        self,
        store: ToolPermissionStore | Callable[[], ToolPermissionStore] | None = None,
        *,
        timeout_s: float = APPROVAL_TIMEOUT_S,
    ) -> None:
        self._store = store
        self.timeout_s = timeout_s
        self._lock = threading.Lock()
        self._queue: dict[str, PendingApproval] = {}
        self._listeners: list[ApprovalListener] = []
        self._ids = itertools.count(1)

    def _get_store(self) -> ToolPermissionStore:
        if isinstance(self._store, ToolPermissionStore):
            return self._store
        if callable(self._store):
            return self._store()
        return get_tool_permission_store()

    # -- listeners ---------------------------------------------------------

    def add_listener(self, listener: ApprovalListener) -> Callable[[], None]:
        """Register a callback; returns a function that removes it.

        Called on whatever thread submitted/resolved the request; a TUI
        must marshal to its own thread.
        """
        with self._lock:
            self._listeners.append(listener)

        def remove() -> None:
            with self._lock, contextlib.suppress(ValueError):
                self._listeners.remove(listener)

        return remove

    def _notify(
        self, kind: str, request: ApprovalRequest, decision: Decision | None
    ) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(kind, request, decision)
            except Exception:
                logger.exception("Approval listener failed")

    # -- queue -------------------------------------------------------------

    def submit(
        self,
        *,
        agent_id: str,
        agent_label: str,
        tool: str,
        args: Mapping[str, Any] | None,
        risk: RiskTier,
        suggested_rule: str | None = None,
        description: str = "",
        argument_dependent: bool = False,
    ) -> PendingApproval:
        """Queue a request (non-blocking); returns its handle."""
        with self._lock:
            request_id = f"ap-{next(self._ids)}"
            request = ApprovalRequest(
                request_id=request_id,
                agent_id=agent_id,
                agent_label=agent_label,
                tool=tool,
                args=dict(args or {}),
                risk=risk,
                suggested_rule=suggested_rule,
                description=description,
                argument_dependent=argument_dependent,
            )
            pending = PendingApproval(self, request)
            self._queue[request_id] = pending
        self._notify("added", request, None)
        return pending

    def request(
        self,
        *,
        agent_id: str,
        agent_label: str,
        tool: str,
        args: Mapping[str, Any] | None,
        risk: RiskTier,
        suggested_rule: str | None = None,
        description: str = "",
        argument_dependent: bool = False,
        timeout_s: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Decision:
        """Queue a request and block until it is decided (see :meth:`submit`)."""
        pending = self.submit(
            agent_id=agent_id,
            agent_label=agent_label,
            tool=tool,
            args=args,
            risk=risk,
            suggested_rule=suggested_rule,
            description=description,
            argument_dependent=argument_dependent,
        )
        return pending.wait(timeout=timeout_s, cancel_event=cancel_event)

    def pending(self) -> list[ApprovalRequest]:
        """Pending requests, oldest first."""
        with self._lock:
            return [p.request for p in self._queue.values()]

    def head(self) -> ApprovalRequest | None:
        """The oldest pending request (the one the UI shows)."""
        with self._lock:
            for pending in self._queue.values():
                return pending.request
        return None

    def get(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            pending = self._queue.get(request_id)
            return pending.request if pending else None

    # -- resolution --------------------------------------------------------

    def resolve(
        self,
        request_id: str,
        decision: Decision | Choice,
        note: str | None = None,
    ) -> bool:
        """Answer a request. Returns False if it is no longer pending."""
        if isinstance(decision, str):
            decision = Decision(decision, note=(note or "").strip() or None)
        return self._finish(request_id, decision) is not None

    def cancel(self, request_id: str) -> bool:
        """Resolve one request as No (``by="cancelled"``)."""
        return self._finish(request_id, Decision("no", by="cancelled")) is not None

    def cancel_agent(self, agent_id: str) -> int:
        """Cancel every pending request of one agent; returns how many."""
        with self._lock:
            ids = [
                rid for rid, p in self._queue.items() if p.request.agent_id == agent_id
            ]
        return sum(self.cancel(rid) for rid in ids)

    def cancel_all(self) -> int:
        with self._lock:
            ids = list(self._queue)
        return sum(self.cancel(rid) for rid in ids)

    def _finish(self, request_id: str, decision: Decision) -> Decision | None:
        """First answer wins: dequeue, persist "always", wake, notify."""
        with self._lock:
            pending = self._queue.pop(request_id, None)
        if pending is None:
            return None
        request = pending.request
        rule: PermissionRule | None = None
        if decision.choice == "always":
            text = decision.remembered_rule or request.suggested_rule
            try:
                if text is None:
                    raise ValueError("no rule can be remembered for this call")
                canonical = self._get_store().add_allow_rule(
                    text, argument_dependent=request.argument_dependent
                )
                rule = parse_rule(canonical)
                decision = Decision(
                    "always",
                    note=decision.note,
                    by=decision.by,
                    remembered_rule=canonical,
                )
            except (ValueError, OSError) as exc:
                logger.warning(
                    "Not remembering %s: %s; approving once", request.tool, exc
                )
                decision = Decision("once", note=decision.note, by=decision.by)
        pending._set(decision)
        self._notify("resolved", request, decision)
        if rule is not None:
            self._auto_resolve(rule)
        return decision

    def _auto_resolve(self, rule: PermissionRule) -> None:
        with self._lock:
            covered = [
                rid
                for rid, p in self._queue.items()
                if not (rule.is_bare and p.request.argument_dependent)
                and rule.matches(p.request.tool, p.request.args)
            ]
        for rid in covered:
            self._finish(rid, Decision("once", by="rule", remembered_rule=str(rule)))


# ---------------------------------------------------------------------------
# Singletons + legacy module API
# ---------------------------------------------------------------------------

_tool_permission_store: ToolPermissionStore | None = None
_approval_broker: ApprovalBroker | None = None
_singleton_lock = threading.Lock()


def get_tool_permission_store() -> ToolPermissionStore:
    """The process-wide store backed by the real config file."""
    global _tool_permission_store
    with _singleton_lock:
        if _tool_permission_store is None:
            _tool_permission_store = ToolPermissionStore()
        return _tool_permission_store


def get_approval_broker() -> ApprovalBroker:
    """The process-wide :class:`ApprovalBroker` (uses the store singleton)."""
    global _approval_broker
    with _singleton_lock:
        if _approval_broker is None:
            _approval_broker = ApprovalBroker()
        return _approval_broker


def resolve(
    name: str,
    risk: RiskTier,
    args: Mapping[str, Any] | None = None,
    *,
    permission_key: str | Sequence[str] | None = None,
    can_remember_choice: bool = True,
) -> Resolution:
    """:meth:`ToolPermissionStore.resolve` on the singleton store."""
    return get_tool_permission_store().resolve(
        name,
        risk,
        args,
        permission_key=permission_key,
        can_remember_choice=can_remember_choice,
    )


def resolve_tool_policy(
    name: str,
    risk: RiskTier,
    can_remember_choice: bool = True,
    args: Mapping[str, Any] | None = None,
    permission_key: str | Sequence[str] | None = None,
) -> ToolPolicy:
    """Legacy wrapper: ``"allowed"`` / ``"never"`` / ``"ask"``."""
    return (
        get_tool_permission_store()
        .resolve(
            name,
            risk,
            args,
            permission_key=permission_key,
            can_remember_choice=can_remember_choice,
        )
        .legacy_policy
    )


def reset_for_tests() -> None:
    """Drop the singletons (pending requests are cancelled) and the resolver."""
    global _tool_permission_store, _approval_broker, _argument_dependency_resolver
    with _singleton_lock:
        broker = _approval_broker
        _approval_broker = None
        _tool_permission_store = None
        _argument_dependency_resolver = None
    if broker is not None:
        broker.cancel_all()
