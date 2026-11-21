"""Conversation threads: :class:`AgentSession`, persistence and resume.

An :class:`AgentSession` is one conversation thread of one agent (the main
chat, or a subagent). It owns:

- the message history (``system[0]`` = prompt + toolset catalogue), the
  fixed ``tools`` array (computed once at open) and its hash;
- the client (built with :func:`sandroid.ai.safety.build_client`; refused
  while ``get_ai_settings().problem`` is set), the token meter and the
  thread's :class:`~sandroid.ai.tools.meta.LoadedTools`;
- the shared :class:`~sandroid.ai.results.ResultStore` of the session root;
- a :class:`ConversationStore` (append-only JSONL at
  ``<root>/ai/threads/<thread_id>.jsonl``; memory only when root is None);
- a single-runner turn queue (:meth:`submit_user_message`,
  :meth:`enqueue_wake`) that runs :func:`sandroid.ai.loop.run_turn` on an
  injected worker.

Per user turn an ambient "Live Sandroid state" block is built once and
inserted as a system message right before the user message, and kept in
history (``first_only`` profiles: appended to the user message). Before every
request :func:`sandroid.ai.compaction.prepare` may mask or summarise history;
the result is persisted as a checkpoint so resume reproduces it.

Timeline lines (``src="ai"``: prompt/tool/turn/compact/approval) are best
effort: a failing emit never breaks a turn. Streamed text, reasoning, full
results and the ambient block never reach the timeline.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import itertools
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import Future
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sandroid.ai import loop as _loop
from sandroid.ai.arbiter import get_arbiter
from sandroid.ai.errors import AIClientError
from sandroid.ai.loop import (
    ORCHESTRATOR_ID,
    AgentEvent,
    Budgets,
    EventSink,
    RunContext,
    TurnResult,
    build_request_messages,
)
from sandroid.ai.loop import repair_tool_pairs as _repair_tool_pairs
from sandroid.ai.prompts import (
    CONTINUE_MESSAGE,
    MCP_CATALOGUE_HEADER,
    ORCHESTRATOR_PROMPT_V2,
    TOOLSET_CATALOGUE_HEADER,
)
from sandroid.ai.results import ensure_private_dir, get_result_store, session_root
from sandroid.ai.tools.meta import LoadedTools
from sandroid.ai.tools.registry import (
    AllowedPredicate,
    ToolRegistry,
    get_tool_registry,
    tools_schema_hash,
)

try:  # WP4b; the runtime degrades to "no compaction" without it
    from sandroid.ai import compaction as _compaction
except ImportError:  # pragma: no cover - only before compaction.py existed
    _compaction = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

#: Version of the JSONL record format.
RECORD_VERSION = 1

#: Background-task name of the main chat turn (StatusBar, stop-all and
#: ``context.py`` rely on this exact name).
CHAT_TASK_NAME = "chat"

#: Sentinel: "use the current analysis session's root".
AUTO_ROOT: Any = object()

#: ``registrar(name, display_name, stop_callback) -> unregister``.
TaskRegistrar = Callable[[str, str, Callable[[], None]], Callable[[], None]]
#: ``spawn_worker(fn)`` runs *fn* (the queue drainer) somewhere.
WorkerSpawner = Callable[[Callable[[], None]], Any]

_THREAD_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


# =============================================================================
# Helpers
# =============================================================================


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _live_ai_config() -> Any:
    """``Toolbox.config.ai``, else ``get_config().ai``, else ``None``."""
    with contextlib.suppress(Exception):
        from sandroid.core.toolbox import Toolbox

        cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        if cfg is not None:
            return cfg
    with contextlib.suppress(Exception):
        from sandroid.config import get_config

        return get_config().ai
    return None


def _bind_row_highlights(root: Path) -> None:
    """Point the lens highlight store at this session folder (session switch).

    The store keeps ``<root>/ai/highlights.json``; the same root again is a
    no-op. Never raises.
    """
    try:
        from sandroid.services.row_highlights import get_row_highlights

        get_row_highlights().bind_folder(root)
    except Exception:
        logger.debug("binding row highlights failed", exc_info=True)


def new_thread_id() -> str:
    """Return a fresh, sortable thread id (``t-YYYYmmdd-HHMMSS-xxxx``)."""
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"t-{stamp}-{secrets.token_hex(2)}"


def _toolbox_task_registrar(
    name: str, display_name: str, stop: Callable[[], None]
) -> Callable[[], None]:
    """Register a Toolbox background task (best effort)."""
    try:
        from sandroid.core.toolbox import Toolbox

        Toolbox.register_background_task(
            name=name,
            display_name=display_name,
            instance=_TaskHandle(stop),
            stop_callback=stop,
        )
    except Exception as exc:
        logger.debug("Failed to register %r background task: %s", name, exc)
        return lambda: None

    def unregister() -> None:
        with contextlib.suppress(Exception):
            from sandroid.core.toolbox import Toolbox

            Toolbox.unregister_background_task(name)

    return unregister


class _TaskHandle:
    """Toolbox task instance with a ``stop()`` (like the old ChatTurnHandle)."""

    def __init__(self, stop: Callable[[], None]) -> None:
        self._stop = stop

    def stop(self) -> None:
        self._stop()


def _daemon_worker(fn: Callable[[], None]) -> threading.Thread:
    thread = threading.Thread(target=fn, name="ai-session", daemon=True)
    thread.start()
    return thread


def _device_folder() -> Path | None:
    with contextlib.suppress(Exception):
        from sandroid.services import get_initialization_service

        session = get_initialization_service().get_current_session()
        path = getattr(session, "device_path", None) if session else None
        if path:
            return Path(path).expanduser().absolute()
    return None


# =============================================================================
# Conversation store (append-only JSONL)
# =============================================================================


class ConversationStore:
    """Append-only JSONL records of one thread.

    Every record has ``v``, ``seq``, ``t`` and ``type`` (``header``, ``msg``,
    ``usage``, ``ambient``, ``compaction``, ``approval``, ``close``). The file
    and its folders are created lazily on the first non-header record (mode
    0700 folders, 0600 file), so an unused thread leaves nothing on disk.
    With ``path=None`` records are kept in memory only.
    """

    def __init__(self, path: Path | None, *, next_seq: int = 1) -> None:
        """Create a store writing to *path* (``None``: memory only)."""
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._seq = itertools.count(next_seq)
        self._pending: list[str] = []
        self._materialized = self.path is not None and self.path.exists()
        self.memory: list[dict] = []
        self.on_materialize: Callable[[], None] | None = None

    @property
    def persistent(self) -> bool:
        """Whether records go to disk."""
        return self.path is not None

    @property
    def materialized(self) -> bool:
        """Whether the file exists (something besides the header was written)."""
        return self._materialized

    def append(self, type: str, **fields: Any) -> tuple[dict, str]:
        """Append one record; returns ``(record, sha256 of its line)``."""
        with self._lock:
            record = {"v": RECORD_VERSION, "seq": next(self._seq), "t": _now_iso()}
            record["type"] = type
            record.update(fields)
            line = json.dumps(record, ensure_ascii=False, default=str)
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            if self.path is None:
                self.memory.append(record)
                return record, digest
            if not self._materialized and type == "header":
                self._pending.append(line)
                return record, digest
            lines = [*self._pending, line]
            self._pending.clear()
            first = not self._materialized
            self._write(lines)
            self._materialized = True
        if first and self.on_materialize is not None:
            try:
                self.on_materialize()
            except Exception:
                logger.exception("AI thread on_materialize failed")
        return record, digest

    def _write(self, lines: list[str]) -> None:
        assert self.path is not None
        ensure_private_dir(self.path.parent)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write("".join(f"{line}\n" for line in lines))

    @staticmethod
    def read(path: Path) -> list[dict]:
        """Read every parsable record of a thread file (bad lines skipped)."""
        records: list[dict] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        logger.warning("Skipping corrupt record in %s", path)
                        continue
                    if isinstance(rec, dict) and "type" in rec:
                        records.append(rec)
        except OSError:
            logger.debug("Cannot read thread file %s", path, exc_info=True)
        return records


# =============================================================================
# Thread index
# =============================================================================

_index_locks: dict[str, threading.Lock] = {}
_index_locks_guard = threading.Lock()


def _ai_dir(root: Path) -> Path:
    return Path(root) / "ai"


def threads_dir(root: Path) -> Path:
    """``<root>/ai/threads``."""
    return _ai_dir(root) / "threads"


def _index_lock(root: Path) -> threading.Lock:
    key = str(Path(root).absolute())
    with _index_locks_guard:
        return _index_locks.setdefault(key, threading.Lock())


def _read_index(root: Path) -> dict | None:
    try:
        data = json.loads((_ai_dir(root) / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("threads"), list):
        return None
    return data


def _write_index(root: Path, data: dict) -> None:
    folder = ensure_private_dir(_ai_dir(root))
    target = folder / "index.json"
    tmp = folder / f".index.{os.getpid()}.{threading.get_ident()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1, default=str)
    tmp.replace(target)


def _scan_threads(root: Path) -> list[dict]:
    """Rebuild index entries from the thread files."""
    entries: list[dict] = []
    folder = threads_dir(root)
    if not folder.is_dir():
        return entries
    for path in sorted(folder.glob("*.jsonl")):
        records = ConversationStore.read(path)
        header = next((r for r in records if r.get("type") == "header"), {})
        msgs = [r for r in records if r.get("type") == "msg"]
        first_user = next(
            (r for r in msgs if r.get("role") == "user" and r.get("kind") == "user"),
            None,
        )
        closed = next((r for r in reversed(records) if r.get("type") == "close"), None)
        reopened = closed is not None and records[-1] is not closed
        entries.append(
            {
                "thread_id": path.stem,
                "kind": header.get("kind", "chat"),
                "title": _title(first_user.get("text", "") if first_user else ""),
                "created": header.get("t") or (records[0]["t"] if records else None),
                "updated": records[-1]["t"] if records else None,
                "closed": closed is not None and not reopened,
                "model": header.get("model"),
                "msgs": len(msgs),
                "turns": len({r.get("turn") for r in msgs if r.get("turn")}),
                "path": f"threads/{path.name}",
            }
        )
    return entries


def _update_index(root: Path, entry: dict) -> None:
    with _index_lock(root):
        data = _read_index(root)
        if data is None:
            data = {"v": 1, "threads": _scan_threads(root)}
        threads = [
            t for t in data["threads"] if t.get("thread_id") != entry["thread_id"]
        ]
        old = next(
            (t for t in data["threads"] if t.get("thread_id") == entry["thread_id"]), {}
        )
        merged = {**old, **{k: v for k, v in entry.items() if v is not None}}
        threads.append(merged)
        data["threads"] = threads
        _write_index(root, data)


def list_threads(root: Path | None | Any = AUTO_ROOT) -> list[dict]:
    """Return the chat threads of a session root, most recently updated first.

    Reads ``ai/index.json`` and rebuilds it from the thread files when it is
    missing or corrupt. Returns ``[]`` without a root.
    """
    root = session_root() if root is AUTO_ROOT else root
    if root is None:
        return []
    root = Path(root)
    data = _read_index(root)
    if data is None:
        entries = _scan_threads(root)
        if entries:
            with contextlib.suppress(OSError), _index_lock(root):
                _write_index(root, {"v": 1, "threads": entries})
    else:
        entries = data["threads"]
    return sorted(entries, key=lambda e: e.get("updated") or "", reverse=True)


def _masked_prompt(text: str) -> str:
    """An analyst prompt as it is sent and stored (N2-B3).

    With ``ai.mask_sensitive`` on, secrets typed into a prompt (``sk-...``,
    bearer / AWS keys, ``password=...``, ``token: ...``) are masked by the
    tool-result rules before the prompt reaches the model, the thread title
    (``ai/index.json``) or the transcript (``threads/*.jsonl``); the live
    chat view keeps showing what the analyst typed. Off: unchanged.
    """
    try:
        from sandroid.ai.row_classifier import mask_enabled, mask_text

        if not mask_enabled():
            return text
        return mask_text(text)
    except Exception:
        logger.warning("masking an analyst prompt failed; redacting it instead")
        from sandroid.ai.safety import redact_secrets

        return redact_secrets(text)


def _title(text: str, limit: int = 80) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# =============================================================================
# Token meter fallback
# =============================================================================


class _FallbackMeter:
    """Minimal meter used only if ``ai/compaction.py`` is unavailable."""

    def __init__(self, window: int, output_reserve: int) -> None:
        self._window = int(window)
        self.output_reserve = int(output_reserve)
        self._used = 0

    @property
    def window(self) -> int:
        return self._window

    @property
    def used(self) -> int:
        return self._used

    @property
    def percent(self) -> float:
        return 100.0 * self._used / self._window if self._window else 0.0

    def update_from_usage(self, usage: Any, request_messages_chars: int, **_: Any):
        self._used = int(getattr(usage, "prompt_tokens", 0) or 0)

    def estimate(self, messages: list[dict], tools: list[dict] | None) -> int:
        chars = len(json.dumps([messages, tools or []], default=str))
        self._used = int(chars / 3.5)
        return self._used

    def breakdown(self, messages: list[dict], tools: list[dict] | None) -> dict:
        return {"total": self.estimate(messages, tools)}


def _messages_chars(messages: list[dict]) -> int:
    if _compaction is not None:
        return _compaction.messages_chars(messages)
    return len(json.dumps(messages, default=str))


# =============================================================================
# Session
# =============================================================================


@dataclass
class _Job:
    kind: str  # "user" | "wake" | "continue"
    text: str
    meta: dict = field(default_factory=dict)
    futures: list[Future] = field(default_factory=list)
    extra_rounds: int | None = None


class SessionBusyError(RuntimeError):
    """Raised for operations refused while a turn is running."""


class AgentSession:
    """One conversation thread of one agent.

    Create with :meth:`open_new` or :meth:`resume`. Thread safety: submit,
    enqueue, cancel and the read-only properties may be called from any
    thread; turns run one at a time on the injected worker.

    Event sink contract: ``sink(event: AgentEvent)`` is called on the worker
    thread for every event of every turn, in order; it must not block (a UI
    sink marshals and coalesces). Approvals: an ``approval_request`` event
    carries ``request_id``; the UI answers through
    ``get_approval_broker().resolve(request_id, "once"|"always"|"no", note)``
    (or listens to the broker directly). ``approval_mode="deny"`` refuses
    every call that needs approval (no UI).
    """

    def __init__(
        self,
        *,
        thread_id: str,
        root: Path | None,
        client: Any,
        kind: str = "chat",
        agent_id: str = ORCHESTRATOR_ID,
        parent_id: str | None = None,
        agent_label: str = "Sandroid AI",
        system_prompt: str = ORCHESTRATOR_PROMPT_V2,
        extra_tools: tuple = (),
        allowed: AllowedPredicate | None = None,
        registry: ToolRegistry | None = None,
        ai_cfg: Any = None,
        sink: EventSink | None = None,
        ambient_provider: Callable[[], str] | None = None,
        spawn_worker: WorkerSpawner | None = None,
        task_registrar: TaskRegistrar | None = _toolbox_task_registrar,
        approval_mode: str = "ask",
        broker: Any = None,
        budgets: Budgets | None = None,
        depth: int = 0,
        summaries: bool | None = None,
        thread_path: Path | None = None,
        _records: list[dict] | None = None,
    ) -> None:
        """Use :meth:`open_new` or :meth:`resume` instead."""
        _loop.install_permission_resolver()
        self.thread_id = thread_id
        self.root = Path(root) if root is not None else None
        self.client = client
        self.kind = kind
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.agent_label = agent_label
        self.registry = registry or get_tool_registry()
        self.allowed = allowed
        self.ai_cfg = ai_cfg
        self.approval_mode = approval_mode
        self.broker = broker
        self.depth = depth
        self._sink = sink
        self._ambient_provider = ambient_provider
        self._spawn_worker = spawn_worker or _daemon_worker
        self._task_registrar = task_registrar
        self._summaries = kind == "chat" if summaries is None else summaries
        self.budgets = budgets or self._default_budgets()
        self._context_cfg = getattr(ai_cfg, "context", None)
        self._seq = itertools.count(1)
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._queue: deque[_Job] = deque()
        self._runner_active = False
        self._current_cancel: threading.Event | None = None
        #: Cancel events of out-of-turn requests (report wrap-up, /compact).
        self._aux_cancels: set[threading.Event] = set()
        self._closed = False
        self._turn_counter = 0
        self._msg_counter = 0
        self.last_result: TurnResult | None = None
        self.title: str | None = None
        self.created = _now_iso()
        self.totals = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0}

        # Fixed for the life of the thread.
        self.tools: list[dict] = self.registry.fixed_tools_array(
            allowed=allowed, extras=extra_tools
        )
        self.tools_schema_hash = tools_schema_hash(self.tools)
        self.exposed = frozenset(t["function"]["name"] for t in self.tools)
        catalogue = self.registry.toolset_catalogue(allowed=allowed)
        self.system_prompt = (
            f"{system_prompt}\n\n{TOOLSET_CATALOGUE_HEADER}\n{catalogue}"
            if catalogue
            else system_prompt
        )
        self.prompt_hash = hashlib.sha256(self.system_prompt.encode()).hexdigest()
        self.result_store = get_result_store(self.root)
        if kind == "chat" and depth == 0 and self.root is not None:
            _bind_row_highlights(self.root)
        self.meter = self._make_meter()
        self.loaded = LoadedTools()
        self.messages: list[dict] = [{"role": "system", "content": self.system_prompt}]

        if thread_path is None and self.root is not None:
            thread_path = threads_dir(self.root) / f"{thread_id}.jsonl"
        self.thread_path = thread_path
        next_seq = 1 + max((r.get("seq", 0) for r in _records or []), default=0)
        self.store = ConversationStore(thread_path, next_seq=next_seq)
        self.store.on_materialize = self._index_now
        if _records is not None:
            self._rebuild(_records)
        self._persist(
            "header",
            kind=kind,
            thread_id=thread_id,
            agent_id=agent_id,
            parent_id=parent_id,
            model=getattr(client, "model", None),
            profile=getattr(self.profile, "name", None),
            prompt_sha256=self.prompt_hash,
            tools_schema_hash=self.tools_schema_hash,
            resumed=_records is not None,
        )

    # -- construction ---------------------------------------------------------------

    @classmethod
    def open_new(
        cls,
        *,
        root: Path | None | Any = AUTO_ROOT,
        client: Any = None,
        ai_cfg: Any = None,
        thread_id: str | None = None,
        **kwargs: Any,
    ) -> AgentSession:
        """Open a fresh thread.

        Args:
            root: Session root (default: the current analysis session; fixed
                now). ``None`` keeps the thread in memory only.
            client: Transport; default built from the live config with the
                policy check (raises :class:`AIClientError` when refused).
            ai_cfg: ``AIConfig``-like object (default: the live one).
            thread_id: Explicit id (default: generated).
            **kwargs: See :class:`AgentSession` (sink, kind, agent_id,
                extra_tools, allowed, spawn_worker, task_registrar, ...).
        """
        ai_cfg = ai_cfg if ai_cfg is not None else _live_ai_config()
        root = session_root() if root is AUTO_ROOT else root
        client = client if client is not None else build_session_client(ai_cfg)
        return cls(
            thread_id=thread_id or new_thread_id(),
            root=root,
            client=client,
            ai_cfg=ai_cfg,
            **kwargs,
        )

    @classmethod
    def resume(
        cls,
        thread_id: str,
        *,
        root: Path | None | Any = AUTO_ROOT,
        client: Any = None,
        ai_cfg: Any = None,
        **kwargs: Any,
    ) -> AgentSession:
        """Reopen a thread from its JSONL file.

        History is rebuilt from the latest compaction checkpoint plus every
        later message (ambient blocks included); tool calls left unanswered
        by a crash get a synthetic ``cancelled`` result; loaded tools are
        restored. ``system[0]`` and the tools array are rebuilt fresh.

        Raises:
            FileNotFoundError: Unknown thread (or no session root).
            ValueError: Malformed thread id.
        """
        if not _THREAD_ID_RE.match(thread_id or ""):
            raise ValueError(f"invalid thread id {thread_id!r}")
        ai_cfg = ai_cfg if ai_cfg is not None else _live_ai_config()
        root = session_root() if root is AUTO_ROOT else root
        path = kwargs.pop("thread_path", None)
        if path is None:
            if root is None:
                raise FileNotFoundError("no analysis session: nothing to resume")
            path = threads_dir(Path(root)) / f"{thread_id}.jsonl"
        if not Path(path).is_file():
            raise FileNotFoundError(f"no thread {thread_id!r} at {path}")
        records = ConversationStore.read(Path(path))
        client = client if client is not None else build_session_client(ai_cfg)
        session = cls(
            thread_id=thread_id,
            root=root,
            client=client,
            ai_cfg=ai_cfg,
            thread_path=Path(path),
            _records=records,
            **kwargs,
        )
        session._index_now()
        return session

    def _default_budgets(self) -> Budgets:
        cfg = getattr(self.ai_cfg, "budgets", None)
        prefix = "chat" if self.kind == "chat" else "agent"
        rounds = getattr(cfg, f"{prefix}_max_rounds", 25 if prefix == "chat" else 20)
        tokens = getattr(cfg, f"{prefix}_max_tokens", 0)
        wall = getattr(cfg, f"{prefix}_max_wall_s", 0)
        return Budgets(
            max_rounds=int(rounds), max_tokens=tokens or None, max_wall_s=wall or None
        )

    def _make_meter(self) -> Any:
        window = int(getattr(self.profile, "context_window", 32_768) or 32_768)
        reserve = int(getattr(self._context_cfg, "output_reserve_tokens", 32_000))
        reserve = min(reserve, window // 2)
        meter_cls = getattr(_compaction, "TokenMeter", None) or _FallbackMeter
        try:
            return meter_cls(window, reserve)
        except Exception:
            logger.exception("TokenMeter construction failed; using fallback")
            return _FallbackMeter(window, reserve)

    def _rebuild(self, records: list[dict]) -> None:
        checkpoint: list[dict] | None = None
        tail: list[dict] = []
        loaded: set[str] = set()
        for rec in records:
            rtype = rec.get("type")
            if rtype == "compaction" and isinstance(rec.get("checkpoint"), list):
                checkpoint = copy.deepcopy(rec["checkpoint"])
                tail = []
            elif rtype == "ambient" and not rec.get("merged"):
                tail.append({"role": "system", "content": rec.get("content", "")})
            elif rtype == "msg":
                tail.append(_msg_from_record(rec))
                if self.title is None and rec.get("kind") == "user":
                    self.title = _title(rec.get("text") or "")
                loaded.update(rec.get("loaded") or ())
                turn = str(rec.get("turn") or "")
                if turn.startswith("u") and turn[1:].isdigit():
                    self._turn_counter = max(self._turn_counter, int(turn[1:]))
                msg_id = str(rec.get("msg_id") or "")
                if msg_id.startswith("m") and msg_id[1:].isdigit():
                    self._msg_counter = max(self._msg_counter, int(msg_id[1:]))
            elif rtype == "usage":
                # N2-B7: /context's totals survive a resume (one record per
                # model request, as _after_turn counts them).
                with contextlib.suppress(TypeError, ValueError):
                    self.totals["prompt_tokens"] += int(rec.get("prompt") or 0)
                    self.totals["completion_tokens"] += int(rec.get("completion") or 0)
                    self.totals["requests"] += 1
            elif rtype == "header" and not rec.get("resumed"):
                self.created = rec.get("t") or self.created
        history = [*(checkpoint or []), *tail]
        self.messages = [self.messages[0], *_repair_tool_pairs(history)]
        self.loaded = LoadedTools(loaded)
        if _compaction is not None:
            count = sum(1 for m in self.messages if _compaction.is_summary_message(m))
            with contextlib.suppress(Exception):
                self.meter.state.summary_count = max(
                    self.meter.state.summary_count, count
                )

    # -- properties -----------------------------------------------------------------

    @property
    def profile(self) -> Any:
        """The client's model profile."""
        return getattr(self.client, "profile", None)

    @property
    def model(self) -> str | None:
        """Model name."""
        return getattr(self.client, "model", None)

    @property
    def persistent(self) -> bool:
        """Whether the thread is written to disk."""
        return self.store.persistent

    @property
    def running(self) -> bool:
        """Whether a turn is running or queued."""
        with self._lock:
            return self._runner_active or bool(self._queue)

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    def set_sink(self, sink: EventSink | None) -> None:
        """Replace the event sink (takes effect for the next event)."""
        self._sink = sink

    def context_breakdown(self) -> dict[str, int]:
        """Token breakdown for ``/context`` (meter estimate by category)."""
        try:
            return dict(self.meter.breakdown(list(self.messages), self.tools))
        except Exception:
            logger.exception("context breakdown failed")
            return {}

    # -- turn queue -----------------------------------------------------------------

    def submit_user_message(
        self,
        text: str,
        *,
        continuation: bool = False,
        extra_rounds: int | None = None,
    ) -> Future:
        """Queue an analyst message; returns a Future of its :class:`TurnResult`.

        Args:
            text: The message.
            continuation: Mark the message as a "Continue" (see
                :meth:`continue_turn`).
            extra_rounds: Round budget of this turn (default: configured).
        """
        if self.kind == "chat" and self.depth == 0:
            # On the UI thread (chat panel): which lens is open (N2-B1).
            with contextlib.suppress(Exception):
                from sandroid.ai.context import capture_lens_state

                capture_lens_state()
        job = _Job(
            "continue" if continuation else "user",
            text,
            {"continuation": True} if continuation else {},
            extra_rounds=extra_rounds,
        )
        return self._enqueue(job)

    def continue_turn(self, extra_rounds: int | None = None) -> Future:
        """Queue "Continue." (flagged ``continuation``) granting *extra_rounds*."""
        return self.submit_user_message(
            CONTINUE_MESSAGE, continuation=True, extra_rounds=extra_rounds
        )

    def enqueue_wake(self, text: str, meta: dict | None = None) -> Future:
        """Queue a wake-up turn (e.g. a subagent result for the orchestrator).

        Consecutive queued wakes are coalesced into one turn.
        """
        return self._enqueue(_Job("wake", text, dict(meta or {})))

    def _enqueue(self, job: _Job) -> Future:
        future: Future = Future()
        job.futures.append(future)
        with self._lock:
            if self._closed:
                future.set_exception(SessionBusyError("thread is closed"))
                return future
            self._queue.append(job)
            start = not self._runner_active
            if start:
                self._runner_active = True
        if start:
            try:
                self._spawn_worker(self._drain)
            except Exception as exc:
                with self._lock:
                    self._runner_active = False
                    self._queue.clear()
                future.set_exception(exc)
        return future

    def _drain(self) -> None:
        while True:
            with self._lock:
                if not self._queue:
                    self._runner_active = False
                    return
                job = self._queue.popleft()
                if job.kind == "wake":
                    while self._queue and self._queue[0].kind == "wake":
                        nxt = self._queue.popleft()
                        job.text = f"{job.text}\n\n{nxt.text}"
                        job.meta.setdefault("coalesced", []).append(nxt.meta)
                        job.futures.extend(nxt.futures)
                # Published together with the pop: a cancel() from now on
                # reaches this turn even before it starts running.
                cancel = threading.Event()
                self._current_cancel = cancel
            try:
                with self._run_lock:
                    result = self._run_job(job, cancel)
            except BaseException as exc:
                logger.exception("AI session job failed")
                for fut in job.futures:
                    if not fut.done():
                        fut.set_exception(exc)
                continue
            for fut in job.futures:
                if not fut.done():
                    fut.set_result(result)

    def cancel(self, clear_queue: bool = True) -> None:
        """Stop the running turn (and drop queued ones)."""
        dropped: list[_Job] = []
        with self._lock:
            events = [self._current_cancel, *self._aux_cancels]
            if clear_queue:
                dropped = list(self._queue)
                self._queue.clear()
        for event in events:
            if event is not None:
                event.set()
        for job in dropped:
            for fut in job.futures:
                if not fut.done():
                    fut.set_result(TurnResult(status="cancelled"))

    @contextlib.contextmanager
    def cancellable(self) -> Iterator[threading.Event]:
        """A cancel event for a request outside a turn, set by :meth:`cancel`.

        Used for the subagent report wrap-up and ``/compact``.
        """
        event = threading.Event()
        with self._lock:
            self._aux_cancels.add(event)
        try:
            yield event
        finally:
            with self._lock:
                self._aux_cancels.discard(event)

    def wait_idle(self, timeout: float | None = None) -> bool:
        """Block until no turn runs or is queued; returns False on timeout."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.running:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    # -- one turn -------------------------------------------------------------------

    def _run_job(self, job: _Job, cancel: threading.Event | None = None) -> TurnResult:
        if cancel is None:
            cancel = threading.Event()
            with self._lock:
                self._current_cancel = cancel
        task = CHAT_TASK_NAME if self.kind == "chat" else f"agent:{self.agent_id}"
        label = "AI Chat" if self.kind == "chat" else f"AI agent {self.agent_id}"
        unregister: Callable[[], None] = lambda: None  # noqa: E731
        if self._task_registrar is not None:
            try:
                unregister = self._task_registrar(task, label, self.cancel)
            except Exception:
                logger.debug("task registration failed", exc_info=True)
        try:
            self._turn_counter += 1
            turn_id = f"u{self._turn_counter}"
            ctx = self._make_context(turn_id, cancel)
            if job.extra_rounds:
                ctx.budgets = Budgets(
                    max_rounds=int(job.extra_rounds),
                    max_tokens=self.budgets.max_tokens,
                    max_wall_s=self.budgets.max_wall_s,
                )
            self._append_user_turn(job, turn_id)
            result = _loop.run_turn(
                self.messages,
                ctx,
                client=self.client,
                tools=self.tools,
                continuation=job.kind == "continue",
            )
            self.last_result = result
            self._after_turn(result, turn_id)
            return result
        finally:
            with self._lock:
                if self._current_cancel is cancel:
                    self._current_cancel = None
            with contextlib.suppress(Exception):
                unregister()

    def _make_context(self, turn_id: str, cancel: threading.Event) -> RunContext:
        cfg = self._context_cfg
        return RunContext(
            agent_id=self.agent_id,
            thread_id=self.thread_id,
            parent_id=self.parent_id,
            owner_id=self.agent_id,
            agent_label=self.agent_label,
            kind=self.kind,
            turn_id=turn_id,
            cancel_event=cancel,
            approval_mode="deny" if self.approval_mode == "deny" else "ask",
            broker=self.broker,
            allowed=self.allowed,
            exposed=self.exposed,
            loaded=self.loaded,
            store=self.result_store,
            registry=self.registry,
            budgets=Budgets(
                self.budgets.max_rounds,
                self.budgets.max_tokens,
                self.budgets.max_wall_s,
            ),
            depth=self.depth,
            cap_tokens=getattr(cfg, "result_cap_tokens", None),
            turn_result_budget_tokens=getattr(cfg, "turn_result_budget_tokens", None),
            sink=self._on_event,
            before_request=self._before_request,
            on_message=self._on_message,
            on_usage=self._on_usage,
            estimate=self._estimate,
            seq=self._seq.__next__,
        )

    def _build_ambient(self) -> str:
        if self._ambient_provider is not None:
            try:
                return self._ambient_provider() or ""
            except Exception:
                logger.exception("ambient provider failed")
                return ""
        parts: list[str] = []
        try:
            from sandroid.ai.context import build_ambient_block

            parts.append(build_ambient_block())
        except Exception:
            logger.debug("ambient block failed", exc_info=True)
        try:
            mcp = self.registry.mcp_catalogue(allowed=self.allowed)
        except Exception:
            mcp = ""
        if mcp:
            parts.append(f"{MCP_CATALOGUE_HEADER}\n{mcp}")
        return "\n\n".join(p for p in parts if p)

    def _append_user_turn(self, job: _Job, turn_id: str) -> None:
        text = _masked_prompt(job.text) if job.kind == "user" else job.text
        if self.title is None and job.kind == "user":
            self.title = _title(text)
        ambient = self._build_ambient()
        multi = getattr(self.profile, "system_mode", "multi") != "first_only"
        content = text
        if ambient and multi:
            msg = {"role": "system", "content": ambient}
            self.messages.append(msg)
            self._persist("ambient", content=ambient, turn=turn_id)
        elif ambient:
            content = f"{text}\n\n{ambient}"
            self._persist("ambient", content=ambient, turn=turn_id, merged=True)
        user = {"role": "user", "content": content}
        self.messages.append(user)
        meta = {"kind": job.kind, "text": text, **job.meta}
        ref = self._persist_msg(user, meta, turn_id)
        if job.kind in ("user", "continue"):
            self._timeline(
                "prompt",
                f"analyst message ({len(job.text)} chars)",
                actor="user",
                data={"length": len(job.text), "continuation": job.kind == "continue"},
                ref=ref,
                sensitive=True,
            )

    def _after_turn(self, result: TurnResult, turn_id: str) -> None:
        self.totals["prompt_tokens"] += result.usage.get("prompt_tokens", 0)
        self.totals["completion_tokens"] += result.usage.get("completion_tokens", 0)
        self.totals["requests"] += result.usage.get("requests", 0)
        self._timeline(
            "turn",
            f"turn {result.status} · {result.rounds} rounds",
            data={
                "turn": turn_id,
                "status": result.status,
                "rounds": result.rounds,
                "usage": result.usage,
                "budget": result.budget_kind,
            },
            ref=self._ref(),
            level="error" if result.status == "error" else "info",
        )
        self._index_now()

    # -- hooks (worker thread) ---------------------------------------------------

    def _on_message(self, msg: dict, meta: dict) -> dict | None:
        return self._persist_msg(msg, meta, self._current_turn())

    def _current_turn(self) -> str:
        return f"u{self._turn_counter}"

    def _persist_msg(self, msg: dict, meta: dict, turn_id: str) -> dict | None:
        self._msg_counter += 1
        msg_id = f"m{self._msg_counter}"
        fields: dict[str, Any] = {
            "role": msg.get("role"),
            "content": msg.get("content"),
            "msg_id": msg_id,
            "turn": turn_id,
        }
        if msg.get("reasoning_content"):
            fields["reasoning"] = msg["reasoning_content"]
        if msg.get("tool_calls"):
            fields["tool_calls"] = msg["tool_calls"]
        if msg.get("tool_call_id"):
            fields["tool_call_id"] = msg["tool_call_id"]
        if msg.get("role") == "tool":
            fields["loaded"] = self.loaded.names()
        for key, value in meta.items():
            if value is not None:
                fields.setdefault(key, value)
        return self._persist("msg", **fields)

    def _persist(self, type: str, **fields: Any) -> dict | None:
        """Append a record; returns a timeline ref (or None)."""
        try:
            record, digest = self.store.append(type, **fields)
        except Exception:
            logger.exception("Persisting AI %s record failed", type)
            return None
        return self._ref(record.get("msg_id"), digest)

    def _ref(self, msg_id: str | None = None, digest: str | None = None) -> dict:
        ref: dict[str, Any] = {"path": self._timeline_path(), "thread": self.thread_id}
        if msg_id:
            ref["msg_id"] = msg_id
        if digest:
            ref["sha256"] = digest
        return ref

    def _timeline_path(self) -> str:
        if self.thread_path is None:
            return f"memory:{self.thread_id}"
        device = _device_folder()
        if device is not None:
            with contextlib.suppress(ValueError):
                return os.path.relpath(self.thread_path, device)
        if self.root is not None:
            with contextlib.suppress(ValueError):
                return "../" + self.thread_path.relative_to(self.root).as_posix()
        return str(self.thread_path)

    def _on_usage(self, usage: Any, request_messages: list[dict]) -> dict | None:
        self._persist(
            "usage",
            turn=self._current_turn(),
            prompt=usage.prompt_tokens,
            completion=usage.completion_tokens,
            reasoning=usage.reasoning_tokens,
        )
        try:
            self.meter.update_from_usage(
                usage, _messages_chars(request_messages), tools=self.tools
            )
        except Exception:
            logger.exception("TokenMeter update failed")
        return {"context_used": self.meter.used, "context_window": self.meter.window}

    def _estimate(self, messages: list[dict], tools: list[dict]) -> int:
        return int(self.meter.estimate(messages, tools))

    def _before_request(self, ctx: RunContext, messages: list[dict]) -> list[dict]:
        prepare = getattr(_compaction, "prepare", None)
        if prepare is None:
            return messages
        try:
            result = prepare(
                messages,
                self.tools,
                self.meter,
                self._context_cfg,
                summarize=self._summarize if self._summaries else None,
                valid_ids=self._valid_ids,
            )
        except Exception:
            logger.exception("Compaction failed; sending the history unchanged")
            return messages
        self._apply_compaction(ctx, result)
        return result.messages if result.changed else messages

    def _apply_compaction(self, ctx: RunContext, result: Any) -> None:
        compaction_events = []
        for event in result.events:
            payload = {k: v for k, v in event.items() if k != "type"}
            etype = event.get("type", "compaction")
            ctx.emit(
                etype if etype in ("compaction", "warning") else "warning", payload
            )
            if etype == "compaction":
                compaction_events.append(payload)
                self._timeline(
                    "compact",
                    f"context {payload.get('kind')} · "
                    f"{payload.get('tokens_before')} → {payload.get('tokens_after')}",
                    data={
                        k: payload.get(k)
                        for k in ("kind", "tokens_before", "tokens_after", "trigger")
                    },
                    ref=self._ref(),
                )
        if result.changed:
            self._persist(
                "compaction",
                turn=self._current_turn(),
                events=compaction_events,
                kind=compaction_events[-1].get("kind") if compaction_events else None,
                checkpoint=result.messages[1:],
            )

    def _summarize(
        self,
        prefix: list[dict],
        instructions: str,
        cancel: threading.Event | None = None,
    ) -> str:
        """Summary request: same tools array, ``tool_choice="none"``.

        Args:
            prefix: Messages to summarise.
            instructions: The summary instructions.
            cancel: Cancel event (default: the running turn's).
        """
        event = cancel if cancel is not None else self._current_cancel
        if event is not None and event.is_set():
            raise AIClientError("summary request cancelled")
        request = build_request_messages(
            [*prefix, {"role": "user", "content": instructions}], self.profile
        )
        choice = "none" if getattr(self.profile, "tool_choice_none", False) else None
        text: list[str] = []
        for chunk in self.client.stream(
            request, self.tools, tool_choice=choice, cancel_event=event
        ):
            if chunk.kind == "text":
                text.append(chunk.text)
            elif chunk.kind == "error" and chunk.error is not None:
                raise AIClientError(chunk.error.message)
            elif chunk.kind == "cancelled":
                raise AIClientError("summary request cancelled")
            elif chunk.kind == "done":
                break
        return "".join(text)

    def _valid_ids(self, ids: set[str]) -> set[str]:
        """The ids in *ids* that exist (``R<n>`` results, ``#<seq>`` lines).

        Timeline ids are checked against seq bounds only (cheap; design §8).
        The read goes through :func:`_timeline_seq_limit`, which reads no
        line content; any future content read there must use
        ``reader="ai"`` so ``ai.mask_sensitive`` applies.
        """
        known = set(self.result_store.ids())
        valid = {i for i in ids if i in known}
        seqs = {i for i in ids if i.startswith("#") and i[1:].isdigit()}
        if seqs:
            limit = _timeline_seq_limit()
            valid |= {i for i in seqs if limit is None or 0 < int(i[1:]) <= limit}
        return valid

    def _on_event(self, event: AgentEvent) -> None:
        try:
            self._observe(event)
        except Exception:
            logger.exception("AI session event bookkeeping failed")
        sink = self._sink
        if sink is not None:
            sink(event)

    def _observe(self, event: AgentEvent) -> None:
        if event.agent_id != self.agent_id:
            # A subagent's event forwarded for display: the subagent's own
            # session already persisted it and wrote its timeline line.
            return
        p = event.payload
        if event.type == "approval_resolved":
            ref = self._persist(
                "approval",
                turn=event.turn_id,
                request_id=p.get("request_id"),
                tool=p.get("tool"),
                decision=p.get("decision"),
                by=p.get("by"),
                note=p.get("note"),
                remembered_rule=p.get("remembered_rule"),
            )
            self._timeline(
                "approval",
                f"{p.get('tool')}: {p.get('decision')} ({p.get('by')})",
                actor="user" if p.get("by") == "user" else "sandroid",
                data={
                    "tool": p.get("tool"),
                    "decision": p.get("decision"),
                    "by": p.get("by"),
                    "rule": p.get("remembered_rule"),
                    "agent": self.agent_id,
                },
                ref=ref,
            )
        elif event.type == "tool_result":
            self._timeline(
                "tool",
                f"{p.get('name')} {p.get('status')}"
                + (f" · {p['result_id']}" if p.get("result_id") else ""),
                data={
                    "tool": p.get("name"),
                    "args": _sanitise_args(p.get("args")),
                    "ok": p.get("status") == "ok",
                    "status": p.get("status"),
                    "error_code": p.get("error_code"),
                    "ms": p.get("duration_ms"),
                    "result_id": p.get("result_id"),
                    "agent": self.agent_id,
                },
                ref=p.get("ref") or self._ref(),
                level="warn" if p.get("status") != "ok" else "info",
            )

    # -- timeline -------------------------------------------------------------------

    def _timeline(
        self,
        kind: str,
        summary: str,
        *,
        actor: str = "ai",
        data: dict | None = None,
        ref: dict | None = None,
        sensitive: bool = False,
        level: str = "info",
    ) -> None:
        """Emit one ``ai/<kind>`` timeline line; never raises."""
        try:
            from sandroid.core import timeline

            timeline.emit(
                "ai",
                kind,
                summary=summary,
                actor=actor,
                data=data,
                ref=ref,
                sensitive=sensitive,
                level=level,
            )
        except Exception:
            logger.debug("AI timeline emit failed", exc_info=True)

    # -- index ----------------------------------------------------------------------

    def _index_now(self) -> None:
        if self.root is None or self.kind != "chat" or not self.store.materialized:
            return
        entry = {
            "thread_id": self.thread_id,
            "kind": self.kind,
            "title": self.title,
            "created": self.created,
            "updated": _now_iso(),
            "closed": self._closed,
            "model": self.model,
            "msgs": self._msg_counter,
            "turns": self._turn_counter,
            "path": f"threads/{self.thread_id}.jsonl",
        }
        try:
            _update_index(self.root, entry)
        except Exception:
            logger.exception("Updating ai/index.json failed")

    # -- lifecycle ------------------------------------------------------------------

    def compact_now(self, focus: str | None = None) -> Any:
        """Run summary compaction now (``/compact [focus]``).

        Returns the compaction result, or ``None`` when compaction is
        unavailable.

        Raises:
            SessionBusyError: A turn is running.
        """
        compact = getattr(_compaction, "compact_now", None)
        if compact is None:
            return None
        if not self._run_lock.acquire(blocking=False):
            raise SessionBusyError("a turn is running; stop it first (Ctrl+X)")
        try:
            with self.cancellable() as cancel:
                ctx = self._make_context(self._current_turn(), cancel)
                result = compact(
                    list(self.messages),
                    self.tools,
                    self.meter,
                    self._context_cfg,
                    summarize=lambda prefix, instructions: self._summarize(
                        prefix, instructions, cancel
                    ),
                    valid_ids=self._valid_ids,
                    focus=focus,
                )
            self._apply_compaction(ctx, result)
            if result.changed:
                self.messages[:] = result.messages
            return result
        finally:
            self._run_lock.release()

    def close(self, reason: str = "new") -> None:
        """Close the thread (Ctrl+L / ``/new``).

        Writes a ``close`` record (only if the thread was ever written),
        cancels this agent's pending approvals and releases its leases.

        Raises:
            SessionBusyError: A turn is running or queued.
        """
        with self._lock:
            if self._runner_active or self._queue:
                raise SessionBusyError("a turn is running; stop it first (Ctrl+X)")
            if self._closed:
                return
            self._closed = True
        if self.store.materialized or not self.store.persistent:
            self._persist("close", reason=reason)
        self._index_now()
        with contextlib.suppress(Exception):
            from sandroid.ai.tool_permissions import get_approval_broker

            (self.broker or get_approval_broker()).cancel_agent(self.agent_id)
        with contextlib.suppress(Exception):
            get_arbiter().release_all(self.agent_id)


# =============================================================================
# Module helpers
# =============================================================================


def build_session_client(ai_cfg: Any = None) -> Any:
    """Build the transport with the egress-policy check.

    Raises:
        AIClientError: When ``get_ai_settings().problem`` is set (redacted).
    """
    from sandroid.ai.safety import build_client, get_ai_settings, redact_secrets

    ai_cfg = ai_cfg if ai_cfg is not None else _live_ai_config()
    settings = get_ai_settings(ai_cfg)
    if settings.problem is not None:
        raise AIClientError(redact_secrets(settings.problem))
    return build_client(settings, ai_cfg)


def _msg_from_record(rec: dict) -> dict:
    msg: dict[str, Any] = {"role": rec.get("role"), "content": rec.get("content")}
    if rec.get("reasoning"):
        msg["reasoning_content"] = rec["reasoning"]
    if rec.get("tool_calls"):
        msg["tool_calls"] = rec["tool_calls"]
    if rec.get("tool_call_id"):
        msg["tool_call_id"] = rec["tool_call_id"]
    return msg


def _timeline_seq_limit() -> int | None:
    """Highest timeline seq written or queued (``None``: unknown).

    Seq bounds only (no line content is read, so nothing to mask).
    """
    try:
        from sandroid.core import timeline

        status = timeline.get_timeline().status()
        return int(status.lines + status.queued)
    except Exception:
        return None


def _sanitise_args(args: Any, limit: int = 120) -> Any:
    """Clip argument values for timeline lines."""
    if not isinstance(args, dict):
        return None
    out: dict[str, Any] = {}
    for key, value in list(args.items())[:20]:
        if isinstance(value, str):
            out[key] = value if len(value) <= limit else value[:limit] + "…"
        elif isinstance(value, int | float | bool) or value is None:
            out[key] = value
        else:
            text = json.dumps(value, default=str)
            out[key] = text if len(text) <= limit else text[:limit] + "…"
    return out


def reset_for_tests() -> None:
    """Forget the per-root index locks (test isolation)."""
    with _index_locks_guard:
        _index_locks.clear()


__all__ = [
    "AUTO_ROOT",
    "CHAT_TASK_NAME",
    "AgentSession",
    "ConversationStore",
    "SessionBusyError",
    "build_session_client",
    "list_threads",
    "new_thread_id",
    "reset_for_tests",
    "threads_dir",
]
