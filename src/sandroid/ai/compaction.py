"""Context management for the AI runtime: token meter, masking, summaries.

Two mechanisms keep a conversation inside the model's context window:

* **Masking** (deterministic, no LLM). Once context use reaches
  ``ai.context.mask_at`` of the window, old tool results are replaced by
  byte-stable stubs that point at the stored result (``read_result``) and
  old reasoning is replaced by ``"[reasoning elided]"``. Tool inputs stay.
* **Summary compaction** (one LLM request without tools). Once context use
  reaches ``ai.context.summarize_at`` (or the pending request would not
  fit), everything except ``system[0]`` and the most recent
  ``summary_keep_tokens`` is summarised. Cuts happen at turn boundaries, so
  an assistant ``tool_calls`` message is never separated from its tool
  replies. Summaries are validated (cited ids must exist, ids of the
  previous summary must survive); on failure a deterministic fallback moves
  the old turns to disk behind a marker message.

Nothing here mutates its inputs: every function returns new lists and new
message dicts for the messages it changes.

Ids: tool results are ``R<n>`` (``ai/results.py``); timeline entries are
cited as ``#<seq>``.
"""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from sandroid.ai.client import Usage

#: Initial chars-per-token ratio, before the first server measurement.
DEFAULT_CHARS_PER_TOKEN = 3.5

#: A mask pass must free at least this many tokens (cache invalidation is
#: only worth it for a large win); also the hysteresis step between passes.
MASK_MIN_CLEAR_TOKENS = 30_000

#: ``read_result`` results of this many most recent rounds are never masked.
READ_RESULT_EXEMPT_ROUNDS = 3

#: Consecutive failed automatic summaries after which auto-summaries stop.
MAX_CONSECUTIVE_FAILURES = 2

REASONING_ELIDED = "[reasoning elided]"
SUMMARY_PREFIX = "[Summary #"
MARKER_PREFIX = "[Context note]"
SUMMARY_ROLE = "user"
MARKER_ROLE = "system"

_REASONING_KEYS = ("reasoning_content", "reasoning")
_ONE_LINE_CHARS = 100

_RID_RE = re.compile(r"\bR([1-9][0-9]*)\b")
_SEQ_RE = re.compile(r"(?<![\w#&])#([0-9]+)\b")
_RID_FIELD_RE = re.compile(r'"(_rid|result_id|elided)"\s*:\s*"(R[1-9][0-9]*)"')
_SUMMARY_INDEX_RE = re.compile(r"^\[Summary #([0-9]+)")
_WS_RE = re.compile(r"\s+")

SUMMARY_HEADINGS = (
    "Goal/target",
    "Actions taken",
    "Findings",
    "Hypotheses (UNVERIFIED)",
    "Open tasks",
    "Running agents",
    "Analyst decisions",
)

SUMMARY_INSTRUCTIONS = (
    "Summarise the conversation above so that the summary can replace it. "
    "You have no tools in this step: write the summary only.\n\n"
    "Use exactly these headings, in this order:\n"
    + "\n".join(f"## {heading}" for heading in SUMMARY_HEADINGS)
    + "\n\nRules:\n"
    "- Every claim cites its evidence: tool-result ids such as R17 and "
    "timeline seqs such as #123. Cite only ids that appear above; never "
    "invent one.\n"
    "- Keep every id cited by an earlier summary.\n"
    "- Quote identifiers exactly as they appear (package names, paths, "
    "hashes, URLs, class and method names, PIDs, ports, serials); never "
    "paraphrase or shorten them.\n"
    "- Anything not confirmed by a cited result goes under "
    "Hypotheses (UNVERIFIED).\n"
    "- Under Running agents list every subagent still running, with its id "
    "and task.\n"
    "- Under Analyst decisions keep the user's instructions, choices and "
    "constraints verbatim where short.\n"
    '- Write "none" under a heading with nothing to report.\n'
    "- Be dense: bullet points, no preamble, no closing remarks."
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _cfg(cfg: Any, name: str, default: Any) -> Any:
    value = getattr(cfg, name, None) if cfg is not None else None
    return default if value is None else value


def _text(content: Any) -> str:
    """Return the text of a message ``content`` (string or content parts)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(str(part.get("text") or ""))
            else:
                parts.append(str(part))
        return "".join(parts)
    return str(content)


def _reasoning(msg: dict) -> str:
    for key in _REASONING_KEYS:
        value = msg.get(key)
        if value:
            return str(value)
    return ""


def message_chars(msg: dict) -> int:
    """Return the character count the meter uses for one message.

    Counts content, reasoning, tool calls and tool-call ids. Pass
    ``messages_chars(request_messages)`` to
    :meth:`TokenMeter.update_from_usage` so the meter can line it up with
    later message lists.
    """
    chars = len(_text(msg.get("content"))) + len(_reasoning(msg))
    tool_calls = msg.get("tool_calls")
    if tool_calls:
        chars += len(json.dumps(tool_calls, sort_keys=True, default=str))
    chars += len(str(msg.get("tool_call_id") or ""))
    chars += len(str(msg.get("role") or ""))
    return chars


def messages_chars(messages: list[dict]) -> int:
    """Return the meter's character count of a message list."""
    return sum(message_chars(m) for m in messages)


def tools_chars(tools: list[dict] | None) -> int:
    """Return the meter's character count of a ``tools`` array."""
    if not tools:
        return 0
    return len(json.dumps(tools, sort_keys=True, default=str))


def is_summary_message(msg: dict) -> bool:
    """Return True for a summary message inserted by compaction."""
    return _text(msg.get("content")).startswith(SUMMARY_PREFIX)


def is_marker_message(msg: dict) -> bool:
    """Return True for a fallback marker inserted by compaction."""
    return _text(msg.get("content")).startswith(MARKER_PREFIX)


def _is_compaction_message(msg: dict) -> bool:
    return is_summary_message(msg) or is_marker_message(msg)


def _compaction_body(msg: dict) -> str:
    """Text of a summary/marker without its ``[Summary #k …]`` header."""
    text = _text(msg.get("content"))
    if text.startswith(SUMMARY_PREFIX):
        end = text.find("]")
        return text[end + 1 :] if end >= 0 else ""
    return text


def find_result_id(content: Any) -> str | None:
    """Return the R-id a tool-result content refers to, if any.

    Looks at the top-level ``_rid`` (inline result), ``result_id``
    (preview) or ``elided`` (stub) key, falling back to a regex over those
    fields when the content is not a JSON object.
    """
    text = _text(content)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        for key in ("_rid", "result_id", "elided"):
            value = data.get(key)
            if isinstance(value, str) and _RID_RE.fullmatch(value):
                return value
    match = _RID_FIELD_RE.search(text)
    return match.group(2) if match else None


def cited_ids(text: str) -> set[str]:
    """Return the R-ids (``R17``) and timeline seqs (``#123``) in *text*."""
    ids = {f"R{m}" for m in _RID_RE.findall(text or "")}
    ids.update(f"#{m}" for m in _SEQ_RE.findall(text or ""))
    return ids


def _is_stub(content: Any) -> bool:
    text = _text(content)
    if not text.startswith("{"):
        return False
    try:
        data = json.loads(text)
    except ValueError:
        return False
    return isinstance(data, dict) and "elided" in data


def _one_line(content: Any) -> str:
    text = _text(content)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        err = data["error"]
        text = f"error {err.get('code', '')}: {err.get('message', '')}"
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > _ONE_LINE_CHARS:
        text = text[: _ONE_LINE_CHARS - 1].rstrip() + "…"
    return text


def make_stub(rid: str, tool: str, one_line: str) -> str:
    """Return the byte-stable stub that replaces a masked tool result."""
    return json.dumps(
        {
            "elided": rid,
            "tool": tool,
            "one_line": one_line,
            "note": f"content moved to disk, not empty — read_result('{rid}')",
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def _tool_names(messages: list[dict]) -> dict[str, str]:
    """Map ``tool_call_id`` -> effective tool name (``call_tool`` unwrapped)."""
    names: dict[str, str] = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            name = str(fn.get("name") or "")
            if name == "call_tool":
                args = fn.get("arguments")
                try:
                    parsed = json.loads(args) if isinstance(args, str) else args
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict) and parsed.get("name"):
                    name = str(parsed["name"])
            if call.get("id"):
                names[str(call["id"])] = name or "unknown"
    return names


def _compress_ids(rids: set[str]) -> str:
    """Return ``R1-R4, R9`` style text (en dash in ranges) for a set of R-ids."""
    numbers = sorted(int(r[1:]) for r in rids)
    parts: list[str] = []
    i = 0
    while i < len(numbers):
        j = i
        while j + 1 < len(numbers) and numbers[j + 1] == numbers[j] + 1:
            j += 1
        if j > i:
            parts.append(f"R{numbers[i]}–R{numbers[j]}")
        else:
            parts.append(f"R{numbers[i]}")
        i = j + 1
    return ", ".join(parts) if parts else "none"


def _sort_ids(ids: set[str]) -> list[str]:
    def key(value: str) -> tuple[int, int]:
        return (0 if value.startswith("R") else 1, int(value.lstrip("R#") or 0))

    return sorted(ids, key=key)


# ---------------------------------------------------------------------------
# Token meter
# ---------------------------------------------------------------------------


@dataclass
class CompactionState:
    """Compaction state carried between requests (lives on the meter).

    Attributes:
        mask_level: Token level right after the last mask pass; the next
            pass needs usage ``>= mask_level + MASK_MIN_CLEAR_TOKENS``.
        consecutive_failures: Failed automatic summaries in a row.
        auto_summary_disabled: Set after ``MAX_CONSECUTIVE_FAILURES``;
            cleared by a successful manual :func:`compact_now`.
        summary_count: Index of the last summary produced.
    """

    mask_level: int | None = None
    consecutive_failures: int = 0
    auto_summary_disabled: bool = False
    summary_count: int = 0


class TokenMeter:
    """Track context use: server ``prompt_tokens`` plus local estimates.

    The last server ``prompt_tokens`` is ground truth. A pending request is
    estimated as that value plus a local estimate (chars / ratio) of every
    message appended since; the chars/token ratio self-calibrates as a
    running average of server measurements.
    """

    def __init__(self, window: int, output_reserve: int) -> None:
        self._window = int(window)
        self.output_reserve = int(output_reserve)
        self.state = CompactionState()
        self._ratio_samples: list[float] = []
        self._ratio = DEFAULT_CHARS_PER_TOKEN
        self._last_prompt_tokens: int | None = None
        self._last_request_chars: int | None = None
        self._last_completion_tokens = 0
        self._last_reasoning_tokens = 0
        self._last_tools_chars = 0
        self._used = 0

    # -- properties -------------------------------------------------------

    @property
    def window(self) -> int:
        """The model's context window in tokens."""
        return self._window

    @property
    def used(self) -> int:
        """Tokens in use: the latest estimate, or the last server value."""
        return self._used

    @property
    def percent(self) -> float:
        """``used`` as a percentage (0-100) of the window."""
        if self._window <= 0:
            return 0.0
        return 100.0 * self._used / self._window

    @property
    def chars_per_token(self) -> float:
        """The current calibrated chars/token ratio."""
        return self._ratio

    @property
    def last_prompt_tokens(self) -> int | None:
        """The last server-reported ``prompt_tokens`` (None before any)."""
        return self._last_prompt_tokens

    @property
    def input_limit(self) -> int:
        """Largest request (tokens) that leaves the output reserve free."""
        return max(0, self._window - self.output_reserve)

    # -- measurement ------------------------------------------------------

    def update_from_usage(
        self,
        usage: Usage,
        request_messages_chars: int,
        *,
        tools: list[dict] | None = None,
    ) -> None:
        """Record the server's usage for a request.

        Args:
            usage: Usage of the finished request.
            request_messages_chars: ``messages_chars(request_messages)`` of
                the messages that were sent.
            tools: The ``tools`` array that was sent (defaults to the one
                seen by the last :meth:`estimate`), for calibration only.
        """
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        if prompt <= 0:
            return
        chars = int(request_messages_chars)
        t_chars = tools_chars(tools) if tools is not None else self._last_tools_chars
        if chars > 0:
            sample = (chars + t_chars) / prompt
            self._ratio_samples.append(min(10.0, max(1.0, sample)))
            self._ratio = sum(self._ratio_samples) / len(self._ratio_samples)
        self._last_prompt_tokens = prompt
        self._last_request_chars = chars
        self._last_completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        self._last_reasoning_tokens = int(getattr(usage, "reasoning_tokens", 0) or 0)
        self._used = prompt

    def local_tokens(self, chars: int) -> int:
        """Estimate tokens for *chars* characters with the calibrated ratio."""
        return math.ceil(chars / self._ratio) if chars > 0 else 0

    def _anchor(self, per_message: list[int]) -> int | None:
        """Return k such that ``messages[:k]`` is the last measured request."""
        target = self._last_request_chars
        if self._last_prompt_tokens is None or not target:
            return None
        total = 0
        for k, chars in enumerate(per_message, start=1):
            total += chars
            if total == target:
                return k
            if total > target:
                return None
        return None

    def estimate(self, messages: list[dict], tools: list[dict] | None) -> int:
        """Estimate the prompt tokens of a pending request.

        Uses the last server value plus a local estimate of the messages
        appended since when the old request is still a prefix (by char
        count); otherwise a full local estimate.
        """
        per_message = [message_chars(m) for m in messages]
        self._last_tools_chars = tools_chars(tools)
        k = self._anchor(per_message)
        if k is not None and self._last_prompt_tokens is not None:
            total = self._last_prompt_tokens
            for idx in range(k, len(messages)):
                local = self.local_tokens(per_message[idx])
                if idx == k and messages[idx].get("role") == "assistant":
                    replay = self._last_completion_tokens
                    if not _reasoning(messages[idx]):
                        replay -= self._last_reasoning_tokens
                    if replay > 0:
                        local = replay
                total += local
        else:
            total = self.local_tokens(sum(per_message) + self._last_tools_chars)
        self._used = total
        return total

    def breakdown(
        self, messages: list[dict], tools: list[dict] | None
    ) -> dict[str, int]:
        """Split the estimated total by category (for ``/context``).

        Keys: ``system``, ``tools_schema``, ``ambient``, ``history``,
        ``tool_results``, ``summaries``, ``reasoning``. Local estimates are
        scaled so they add up to :meth:`estimate` (the last server total
        plus anything appended since).
        """
        raw = {
            "system": 0,
            "tools_schema": tools_chars(tools),
            "ambient": 0,
            "history": 0,
            "tool_results": 0,
            "summaries": 0,
            "reasoning": 0,
        }
        for idx, msg in enumerate(messages):
            role = msg.get("role")
            reasoning = len(_reasoning(msg))
            rest = message_chars(msg) - reasoning
            raw["reasoning"] += reasoning
            if _is_compaction_message(msg):
                raw["summaries"] += rest
            elif role == "system":
                raw["system" if idx == 0 else "ambient"] += rest
            elif role == "tool":
                raw["tool_results"] += rest
            else:
                raw["history"] += rest
        total = self.estimate(messages, tools)
        chars_total = sum(raw.values())
        if chars_total <= 0:
            return dict.fromkeys(raw, 0)
        exact = {key: total * value / chars_total for key, value in raw.items()}
        result = {key: int(value) for key, value in exact.items()}
        remainder = total - sum(result.values())
        order = sorted(exact, key=lambda key: exact[key] - result[key], reverse=True)
        for key in order[:remainder]:
            result[key] += 1
        return result


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


@dataclass
class PrepareResult:
    """Outcome of :func:`prepare` / :func:`compact_now`.

    Attributes:
        messages: The messages to send (a new list; the input is untouched).
        events: Events for the UI/persistence, e.g.
            ``{"type": "compaction", "kind": "mask", ...}`` or
            ``{"type": "warning", "kind": "compaction_disabled", ...}``.
        changed: True when ``messages`` differ from the input.
    """

    messages: list[dict]
    events: list[dict] = field(default_factory=list)
    changed: bool = False


@dataclass
class _MaskOutcome:
    messages: list[dict]
    ids: list[str]
    saved_chars: int


def _read_result_exempt(messages: list[dict], names: dict[str, str]) -> set[str]:
    """Tool-call ids of ``read_result`` calls in the last few rounds."""
    exempt: set[str] = set()
    rounds = 0
    for msg in reversed(messages):
        if msg.get("role") != "assistant" or not msg.get("tool_calls"):
            continue
        rounds += 1
        if rounds > READ_RESULT_EXEMPT_ROUNDS:
            break
        for call in msg["tool_calls"]:
            call_id = str(call.get("id") or "") if isinstance(call, dict) else ""
            if call_id and names.get(call_id) == "read_result":
                exempt.add(call_id)
    return exempt


def _mask(
    messages: list[dict],
    *,
    keep_results: int,
    keep_reasoning: int,
    exempt_read_result: bool,
    start: int = 0,
    stop: int | None = None,
) -> _MaskOutcome:
    """Stub tool results / elide reasoning in ``messages[start:stop]``.

    The most recent ``keep_results`` tool results and ``keep_reasoning``
    assistant messages of the whole list are left alone.
    """
    stop = len(messages) if stop is None else stop
    names = _tool_names(messages)
    exempt = _read_result_exempt(messages, names) if exempt_read_result else set()
    tool_idx = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    asst_idx = [i for i, m in enumerate(messages) if m.get("role") == "assistant"]
    keep_tool = set(tool_idx[-keep_results:]) if keep_results > 0 else set()
    keep_asst = set(asst_idx[-keep_reasoning:]) if keep_reasoning > 0 else set()

    out = list(messages)
    ids: list[str] = []
    saved = 0
    for i in range(start, stop):
        msg = messages[i]
        role = msg.get("role")
        if role == "tool" and i not in keep_tool:
            call_id = str(msg.get("tool_call_id") or "")
            if call_id in exempt or _is_stub(msg.get("content")):
                continue
            rid = find_result_id(msg.get("content"))
            if rid is None:
                continue
            tool = names.get(call_id) or str(msg.get("name") or "unknown")
            stub = make_stub(rid, tool, _one_line(msg.get("content")))
            old_len = len(_text(msg.get("content")))
            if len(stub) >= old_len:
                continue
            out[i] = {**msg, "content": stub}
            ids.append(rid)
            saved += old_len - len(stub)
        elif role == "assistant" and i not in keep_asst:
            new = None
            for key in _REASONING_KEYS:
                value = (new or msg).get(key)
                if (
                    value
                    and value != REASONING_ELIDED
                    and len(str(value)) > len(REASONING_ELIDED)
                ):
                    new = dict(new or msg)
                    new[key] = REASONING_ELIDED
                    saved += len(str(value)) - len(REASONING_ELIDED)
            if new is not None:
                out[i] = new
    return _MaskOutcome(out, ids, saved)


# ---------------------------------------------------------------------------
# Summary compaction
# ---------------------------------------------------------------------------


def _head_len(messages: list[dict]) -> int:
    """1 when ``messages[0]`` is the static system prompt, else 0."""
    if messages and messages[0].get("role") == "system":
        if not _is_compaction_message(messages[0]):
            return 1
    return 0


def _turn_starts(messages: list[dict], begin: int) -> list[int]:
    """Start index of every turn (its ambient block, else its user msg)."""
    starts: list[int] = []
    for i in range(begin, len(messages)):
        msg = messages[i]
        if msg.get("role") != "user" or _is_compaction_message(msg):
            continue
        s = i
        while (
            s - 1 >= begin
            and messages[s - 1].get("role") == "system"
            and not _is_compaction_message(messages[s - 1])
        ):
            s -= 1
        starts.append(s)
    return starts


def _find_cut(messages: list[dict], meter: TokenMeter, keep_tokens: int) -> int | None:
    """Return the index where the verbatim tail starts, or None.

    The tail is whole turns totalling about ``keep_tokens`` (at least the
    last turn). None when nothing older than the tail could be summarised.
    """
    head = _head_len(messages)
    starts = _turn_starts(messages, head)
    if not starts:
        return None
    ends = starts[1:] + [len(messages)]
    cut = starts[-1]
    kept = 0
    for start, end in reversed(list(zip(starts, ends, strict=True))):
        tokens = meter.local_tokens(messages_chars(messages[start:end]))
        if kept and kept + tokens > keep_tokens:
            break
        kept += tokens
        cut = start
    old = messages[head:cut]
    if not any(not _is_compaction_message(m) for m in old):
        return None
    return cut


def _next_summary_index(messages: list[dict], state: CompactionState) -> int:
    best = state.summary_count
    for msg in messages:
        match = _SUMMARY_INDEX_RE.match(_text(msg.get("content")))
        if match:
            best = max(best, int(match.group(1)))
    return best + 1


def _validate(
    summary: Any,
    previous_ids: set[str],
    valid_ids: Callable[[set[str]], set[str]] | None,
) -> list[str]:
    if not isinstance(summary, str) or not summary.strip():
        return ["the summary is empty"]
    errors: list[str] = []
    cited = cited_ids(summary)
    if valid_ids is not None and cited:
        try:
            valid = set(valid_ids(set(cited)))
        except Exception:  # validator is best effort
            valid = set(cited)
        unknown = cited - valid
        if unknown:
            errors.append(
                "unknown ids cited (they do not exist): "
                + ", ".join(_sort_ids(unknown))
            )
    missing = previous_ids - cited
    if missing:
        errors.append(
            "ids cited by the previous summary are missing: "
            + ", ".join(_sort_ids(missing))
        )
    return errors


def _turn_range(messages: list[dict], begin: int, end: int) -> tuple[int, int]:
    """1-based turn numbers (``turn`` key, else position) of a range."""
    numbers: list[int] = []
    position = 0
    for i, msg in enumerate(messages[:end]):
        if msg.get("role") != "user" or _is_compaction_message(msg):
            continue
        position += 1
        if i >= begin:
            turn = msg.get("turn")
            numbers.append(int(turn) if isinstance(turn, int) else position)
    if not numbers:
        return (0, 0)
    return (min(numbers), max(numbers))


def _ids_in_messages(messages: list[dict]) -> set[str]:
    ids: set[str] = set()
    for msg in messages:
        if msg.get("role") == "tool":
            rid = find_result_id(msg.get("content"))
            if rid:
                ids.add(rid)
        elif _is_compaction_message(msg):
            ids.update(i for i in cited_ids(_compaction_body(msg)) if i[0] == "R")
    return ids


def _compaction_event(kind: str, before: int, after: int, ids, **extra) -> dict:
    event = {
        "type": "compaction",
        "kind": kind,
        "tokens_before": before,
        "tokens_after": after,
        "ids": list(ids),
    }
    event.update(extra)
    return event


def _fallback(
    messages: list[dict],
    tools: list[dict] | None,
    meter: TokenMeter,
    cfg: Any,
    cut: int,
    before: int,
    summary_index: int,
    errors: list[str],
    trigger: str,
) -> PrepareResult:
    """Deterministic fallback when no valid summary could be produced.

    First masks every tool result and reasoning older than the tail. If the
    request is still over the summary threshold (or would not fit), the old
    turns are dropped from the request; they stay on disk. Earlier
    summaries and markers are kept; a marker names the turns and R-ids.
    """
    head = _head_len(messages)
    old = messages[head:cut]
    prior = [m for m in old if _is_compaction_message(m)]
    first, last = _turn_range(messages, head, cut)
    rids = _ids_in_messages([m for m in old if not _is_compaction_message(m)])
    id_text = _compress_ids(rids)

    masked = _mask(
        messages,
        keep_results=0,
        keep_reasoning=0,
        exempt_read_result=False,
        start=head,
        stop=cut,
    )
    masked_old = [m for m in masked.messages[head:cut] if not _is_compaction_message(m)]
    marker = {
        "role": MARKER_ROLE,
        "content": (
            f"{MARKER_PREFIX} Tool results and reasoning of turns {first}–{last} "
            f"moved to disk (summary unavailable); R-ids: {id_text}"
        ),
    }
    candidate = [*messages[:head], *prior, marker, *masked_old, *messages[cut:]]
    after = meter.estimate(candidate, tools)
    summarize_at = float(_cfg(cfg, "summarize_at", 0.85))
    dropped = False
    if after >= summarize_at * meter.window or after > meter.input_limit:
        marker = {
            "role": MARKER_ROLE,
            "content": (
                f"{MARKER_PREFIX} Turns {first}–{last} moved to disk (summary "
                f"unavailable); R-ids: {id_text}"
            ),
        }
        candidate = [*messages[:head], *prior, marker, *messages[cut:]]
        after = meter.estimate(candidate, tools)
        dropped = True
    meter.state.mask_level = None
    event = _compaction_event(
        "fallback",
        before,
        after,
        sorted(rids, key=lambda r: int(r[1:])),
        summary_index=summary_index,
        errors=list(errors),
        dropped_turns=dropped,
        turns=[first, last],
        trigger=trigger,
    )
    return PrepareResult(candidate, [event], True)


def _summary_pass(
    messages: list[dict],
    tools: list[dict] | None,
    meter: TokenMeter,
    cfg: Any,
    *,
    summarize: Callable[[list[dict], str], str] | None,
    valid_ids: Callable[[set[str]], set[str]] | None,
    focus: str | None,
    trigger: str,
    manual: bool,
) -> PrepareResult | None:
    """Run one summary compaction; None when there is nothing to summarise."""
    keep_tokens = int(_cfg(cfg, "summary_keep_tokens", 40_000))
    cut = _find_cut(messages, meter, keep_tokens)
    if cut is None:
        return None
    before = meter.estimate(messages, tools)
    state = meter.state
    head = _head_len(messages)
    old = messages[head:cut]
    previous_ids: set[str] = set()
    for msg in old:
        if is_summary_message(msg):
            previous_ids |= cited_ids(_compaction_body(msg))
    index = _next_summary_index(messages, state)

    instructions = SUMMARY_INSTRUCTIONS
    if focus and focus.strip():
        instructions += (
            "\n\nFocus requested by the analyst (give it priority, keep the "
            f"other headings): {focus.strip()}"
        )

    summary: str | None = None
    errors: list[str] = []
    if summarize is not None:
        for attempt in range(2):
            prompt = instructions
            if attempt:
                prompt += (
                    "\n\nYour previous summary was rejected:\n"
                    + "\n".join(f"- {e}" for e in errors)
                    + "\nWrite the whole summary again and fix these problems."
                )
            try:
                text = summarize(copy.deepcopy(messages[:cut]), prompt)
            except Exception as exc:  # any failure -> fallback
                errors = [f"summary request failed: {type(exc).__name__}: {exc}"[:300]]
                break
            errors = _validate(text, previous_ids, valid_ids)
            if not errors:
                summary = text.strip()
                break
    else:
        errors = ["no summariser available"]

    events: list[dict] = []
    if summary is None:
        result = _fallback(
            messages, tools, meter, cfg, cut, before, index, errors, trigger
        )
        if not manual:
            state.consecutive_failures += 1
            if (
                state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES
                and not state.auto_summary_disabled
            ):
                state.auto_summary_disabled = True
                result.events.append(
                    {
                        "type": "warning",
                        "kind": "compaction_disabled",
                        "message": (
                            f"Automatic summary compaction stopped after "
                            f"{state.consecutive_failures} consecutive failures; "
                            "older context is masked instead. Use /compact to "
                            "try again."
                        ),
                    }
                )
        return result

    summary_msg = {
        "role": SUMMARY_ROLE,
        "content": (
            f"{SUMMARY_PREFIX}{index} of earlier conversation — cited evidence "
            f"retrievable via read_result]\n\n{summary}"
        ),
    }
    new_messages = [*messages[:head], summary_msg, *messages[cut:]]
    after = meter.estimate(new_messages, tools)
    state.consecutive_failures = 0
    state.summary_count = index
    state.mask_level = None
    if manual:
        state.auto_summary_disabled = False
    first, last = _turn_range(messages, head, cut)
    events.append(
        _compaction_event(
            "summary",
            before,
            after,
            _sort_ids(cited_ids(summary)),
            summary_index=index,
            summary=summary,
            turns=[first, last],
            trigger=trigger,
        )
    )
    return PrepareResult(new_messages, events, True)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def prepare(
    messages: list[dict],
    tools: list[dict] | None,
    meter: TokenMeter,
    cfg: Any,
    *,
    summarize: Callable[[list[dict], str], str] | None,
    valid_ids: Callable[[set[str]], set[str]] | None,
) -> PrepareResult:
    """Apply masking / summary compaction before a request, if due.

    Args:
        messages: The request history (``system[0]`` first). Not mutated.
        tools: The request's ``tools`` array.
        meter: The conversation's meter (also holds :class:`CompactionState`).
        cfg: The ``ai.context`` config (attributes read with defaults).
        summarize: ``summarize(prefix_messages, instructions) -> text``. It
            gets the exact request prefix ``messages[:cut]`` (including
            ``system[0]``) and should send it plus a final user message with
            *instructions*, without tool calls. None disables summaries
            (subagents: masking only).
        valid_ids: Returns the subset of the given ids (``R17``, ``#123``)
            that exist. None skips the existence check.

    Returns:
        A :class:`PrepareResult`; ``messages`` is always a new list.
    """
    state = meter.state
    window = meter.window
    mask_at = float(_cfg(cfg, "mask_at", 0.50))
    summarize_at = float(_cfg(cfg, "summarize_at", 0.85))
    keep = int(_cfg(cfg, "keep_recent_results", 10))
    min_clear = MASK_MIN_CLEAR_TOKENS

    before = meter.estimate(messages, tools)
    would_not_fit = before > meter.input_limit
    need_summary = before >= summarize_at * window or would_not_fit
    events: list[dict] = []

    if need_summary and summarize is not None and not state.auto_summary_disabled:
        result = _summary_pass(
            messages,
            tools,
            meter,
            cfg,
            summarize=summarize,
            valid_ids=valid_ids,
            focus=None,
            trigger="would_not_fit" if would_not_fit else "threshold",
            manual=False,
        )
        if result is not None:
            return result

    mask_due = before >= mask_at * window and (
        state.mask_level is None or before >= state.mask_level + min_clear
    )
    if mask_due or need_summary:
        outcome = _mask(
            messages,
            keep_results=keep,
            keep_reasoning=keep,
            exempt_read_result=True,
        )
        saved = meter.local_tokens(outcome.saved_chars)
        if outcome.saved_chars > 0 and (saved >= min_clear or need_summary):
            after = max(0, before - saved)
            meter._used = after
            state.mask_level = after
            events.append(
                _compaction_event(
                    "mask",
                    before,
                    after,
                    outcome.ids,
                    trigger="forced" if saved < min_clear else "threshold",
                )
            )
            return PrepareResult(outcome.messages, events, True)

    meter._used = before
    return PrepareResult(list(messages), events, False)


def compact_now(
    messages: list[dict],
    tools: list[dict] | None,
    meter: TokenMeter,
    cfg: Any,
    *,
    summarize: Callable[[list[dict], str], str] | None,
    valid_ids: Callable[[set[str]], set[str]] | None,
    focus: str | None = None,
) -> PrepareResult:
    """Force a summary compaction now (``/compact [focus]``).

    Ignores thresholds and the thrash guard; a success re-enables automatic
    summaries. A failure falls back deterministically but does not count
    towards the thrash guard. When there is nothing older than the kept
    tail, the messages are returned unchanged with a warning event.
    """
    result = _summary_pass(
        messages,
        tools,
        meter,
        cfg,
        summarize=summarize,
        valid_ids=valid_ids,
        focus=focus,
        trigger="manual",
        manual=True,
    )
    if result is not None:
        return result
    return PrepareResult(
        list(messages),
        [
            {
                "type": "warning",
                "kind": "compaction_noop",
                "message": "Nothing to compact: the conversation fits in the "
                "verbatim tail.",
            }
        ],
        False,
    )


__all__ = [
    "MASK_MIN_CLEAR_TOKENS",
    "REASONING_ELIDED",
    "SUMMARY_HEADINGS",
    "SUMMARY_INSTRUCTIONS",
    "CompactionState",
    "PrepareResult",
    "TokenMeter",
    "cited_ids",
    "compact_now",
    "find_result_id",
    "is_marker_message",
    "is_summary_message",
    "make_stub",
    "message_chars",
    "messages_chars",
    "prepare",
    "tools_chars",
]
