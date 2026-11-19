AI foundations: runtime, tools, context, subagents
==================================================

Status: design for branch ``feature/ai-foundations`` (2026-11-19). This replaces the
first-generation AI chat internals (``ai/loop.py``, ``ai/subtasks.py``, the loop logic in
``tui/widgets/chat_panel.py``). The tool *catalogue* is not redesigned here and will
change later. Only the mechanism for exposing tools is.

.. _1-decisions:

1. Decisions
------------

+---------------------------+--------------------------------------------------+
| Topic                     | Decision                                         |
+===========================+==================================================+
| Use cases                 | Analyst copilot chat now. Triage, report         |
|                           | narration and exploration later, all on the same |
|                           | runtime                                          |
+---------------------------+--------------------------------------------------+
| Backend                   | OpenAI-compatible chat completions. Default:     |
|                           | FhGenie ``deepseek-ai/DeepSeek-V4.1-Flash`` on   |
|                           | vLLM 0.34                                        |
+---------------------------+--------------------------------------------------+
| Context window            | Use the full 262,144 tokens. The display shows   |
|                           | usage against 262k                               |
+---------------------------+--------------------------------------------------+
| Reasoning                 | ``reasoning_content`` is sent back on every      |
|                           | assistant message, across user turns, and        |
|                           | persisted                                        |
+---------------------------+--------------------------------------------------+
| Conversation model        | One active main thread per analysis session.     |
|                           | Ctrl+L closes it and opens a new one; old        |
|                           | threads stay on disk and can be resumed. No      |
|                           | forks                                            |
+---------------------------+--------------------------------------------------+
| Tool exposure             | A fixed, byte-stable ``tools`` array: core tools |
|                           | plus ``tool_search``, ``call_tool`` and          |
|                           | ``read_result``. Everything else is loaded on    |
|                           | demand                                           |
+---------------------------+--------------------------------------------------+
| Tool results              | Capped at ingest with a selected preview. The    |
|                           | full result goes into the session's result store |
|                           | as ``R<n>``                                      |
+---------------------------+--------------------------------------------------+
| Approvals                 | Claude Code style: Yes / Yes, don't ask again /  |
|                           | No. Rules live in                                |
|                           | ``~/.config/sandroid/ai_tool_permissions.toml``. |
|                           | Modes are ``ask`` (shipped default) and          |
|                           | ``allow_all``                                    |
+---------------------------+--------------------------------------------------+
| Subagents                 | Kept and rebuilt: data-defined profiles,         |
|                           | structured results, visible result cards,        |
|                           | scheduler, persisted transcripts                 |
+---------------------------+--------------------------------------------------+
| Headless / automation     | The runtime has no TUI dependency. Automation    |
|                           | policy and the CLI are deferred to a later beta  |
+---------------------------+--------------------------------------------------+
| ``ai.mask_sensitive``     | Stays default off                                |
+---------------------------+--------------------------------------------------+
| UI input tools (tap/type) | Later                                            |
+---------------------------+--------------------------------------------------+

.. _2-backend-facts-measured-2026-11-19-on-fhgenie:

2. Backend facts (measured 2026-11-19 on FhGenie)
-------------------------------------------------

- ``GET /models`` lists ``deepseek-ai/DeepSeek-V4.1-Flash`` with ``max_input_tokens`` 262144.
  Simple replies take about 0.7 s.
- Streaming carries ``delta.reasoning_content`` first, then ``delta.content``.

  - With ``stream_options.include_usage=true``, the final chunk has ``choices: []`` and a
    ``usage`` object containing ``prompt_tokens``, ``completion_tokens`` and
    ``completion_tokens_details.reasoning_tokens``.
  - ``cached_tokens`` is not reported.

- OpenAI-format ``tool_calls`` work. A tool round works both with and without
  ``reasoning_content`` echoed back.
- A second system message is read; the old MiniMax model ignored it.
- vLLM renders ``tools`` into the first system message. Changing ``tools`` or ``system[0]``
  invalidates the prefix cache for everything after it.
- Prefix caching exists, but the gateway is load-balanced and noisy: the same 74k
  request took anywhere from 0.7 s to 8 s. A full miss costs about 2–3 s at 74k.
  A stable prefix is worth having but is not a hard constraint.
- A tool whose schema only appeared in a tool result is called correctly 4/4 times via
  ``call_tool(name, arguments)``, and 4/4 times directly by name, because vLLM's parser
  does not reject undeclared names.
- DeepSeek thinking mode rejects a forced ``tool_choice`` (``required`` or a named
  function).

.. _3-architecture:

3. Architecture
---------------

Calls only go downward through these layers:

::

   transport   ai/client.py        OpenAICompatClient, ModelProfile, StreamChunk/Usage
   runtime     ai/loop.py          AgentEvent, RunContext, TurnResult, run_turn(), ToolExecutor
               ai/session.py       AgentSession (one thread), ConversationStore (JSONL), resume
               ai/compaction.py    TokenMeter, masking, summary compaction, ID validator
               ai/results.py       ResultStore (R-ids), preview shaping
   tools       ai/tools/registry.py + toolsets; ai/tools/meta.py (tool_search, call_tool, read_result)
   policy      ai/tool_permissions.py  rules, modes, ApprovalBroker (FIFO, agent identity)
   agents      ai/agents.py        AgentProfile, AgentManager/scheduler, spawn/wait/... tools
   adapters    tui/widgets/chat_panel.py renders events only; future headless sink

These keep their roles: ``ai/arbiter.py`` (gaining lineage), ``ai/safety.py``,
``ai/context.py`` (ambient block), ``ai/prompts.py`` and ``ai/mcp_client.py``.

``ai/subtasks.py`` is deleted; it is replaced by ``ai/agents.py``.

Keep the sync worker-thread model: no asyncio rewrite. Each agent turn runs on a worker
thread, and the UI receives events through a thread-safe sink that marshals with
``call_from_thread``.

.. _31-event-stream:

3.1 Event stream
~~~~~~~~~~~~~~~~

Every event is ``AgentEvent{type, agent_id, parent_id, thread_id, turn_id, seq, ts, payload}``.

+----------------------------------+---------------------------------------------------------------+
| type                             | payload                                                       |
+==================================+===============================================================+
| ``turn_start``                   | mode, model                                                   |
+----------------------------------+---------------------------------------------------------------+
| ``request_start``                | iteration, est_prompt_tokens                                  |
+----------------------------------+---------------------------------------------------------------+
| ``retry``                        | attempt, delay_s, reason                                      |
+----------------------------------+---------------------------------------------------------------+
| ``reasoning_delta``,             | text                                                          |
| ``text_delta``                   |                                                               |
+----------------------------------+---------------------------------------------------------------+
| ``tool_call``                    | call_id, name, args, parse_error? (for ``call_tool``, the     |
|                                  | inner name and args)                                          |
+----------------------------------+---------------------------------------------------------------+
| ``approval_request``             | request_id, agent label, tool, args, rule suggestion          |
+----------------------------------+---------------------------------------------------------------+
| ``approval_resolved``            | decision, remembered_rule?, by user or rule                   |
+----------------------------------+---------------------------------------------------------------+
| ``tool_result``                  | call_id, status (ok/error/denied/cancelled/timeout),          |
|                                  | error_code, summary, bytes, result_id, truncated, duration_ms |
+----------------------------------+---------------------------------------------------------------+
| ``usage``                        | prompt, completion, reasoning, cumulative, context_used,      |
|                                  | context_window                                                |
+----------------------------------+---------------------------------------------------------------+
| ``compaction``                   | kind (mask/summary), tokens_before, tokens_after, ids         |
+----------------------------------+---------------------------------------------------------------+
| ``agent_spawned``,               | id, profile, title, status, usage, result card                |
| ``agent_status``,                |                                                               |
| ``agent_result``                 |                                                               |
+----------------------------------+---------------------------------------------------------------+
| ``budget_exhausted``             | kind (rounds/tokens/wall), can_continue                       |
+----------------------------------+---------------------------------------------------------------+
| ``warning``, ``error``           | kind, retryable, message (redacted)                           |
+----------------------------------+---------------------------------------------------------------+
| ``turn_end``                     | reason                                                        |
|                                  | (completed/max_rounds/cancelled/error/length/content_filter), |
|                                  | final_text, usage totals                                      |
+----------------------------------+---------------------------------------------------------------+

Hooks:

- ``before_request(ctx, messages) -> messages``, used for compaction and ambient placement.
- ``on_message_appended(msg)``, used for persistence.
- Event sinks.

.. _32-transport-aiclientpy:

3.2 Transport (``ai/client.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Keep ``requests`` with manual SSE parsing; add no new dependency.
- Send ``stream_options.include_usage`` when the profile allows it.
- **Fix:** a chunk with empty ``choices`` but with ``usage`` must yield a usage event. Today it
  is dropped at ``client.py:162``.
- **Retries:** connect errors and HTTP 408/429/500/502/503/504 are retried *before the
  first content byte* only.

  - Exponential backoff with jitter: 1/2/4/8 s, max 4 attempts, honouring
    ``Retry-After``.
  - Each retry emits a ``retry`` event.
  - A drop mid-stream becomes ``error(kind=interrupted)``, keeps the partial text, and the
    UI offers Continue.

- Close the response with ``closing()``, including on cancel.
- **``finish_reason``:**

  - ``tool_calls``, or any assembled tool calls: dispatch them.
  - ``length`` with incomplete tool arguments: do not dispatch; return an
    ``invalid_arguments`` error to the model. Otherwise end the turn with
    ``turn_end(reason=length)``.
  - ``content_filter``: ``error``.

- **Config** (``AIConfig``): ``max_tokens``, ``temperature``, ``top_p``, ``request_timeout``
  (connect, read) and ``extra_body`` passthrough. Also add ``context_window`` and
  ``profile`` as overrides.
- **``ModelProfile``:** a built-in table matched by glob on the model name.

  - Fields: ``context_window``, ``max_output``, ``system_mode`` (``multi`` \| ``first_only``),
    ``reasoning_field``, ``think_tags`` (move inline ``<think>`` into reasoning),
    ``echo_reasoning`` (``all`` \| ``turn`` \| ``none``), ``stream_usage``, ``parallel_tool_calls``,
    ``forced_tool_choice`` (bool), ``native_tool_search`` (False; reserved for vLLM with
    ``defer_loading``/``tool_reference`` support).
  - DeepSeek-V4\*: 262144, multi, ``reasoning_content``, ``echo_reasoning=all``,
    ``stream_usage``, ``forced_tool_choice=False``.
  - Unknown models get conservative defaults: ``first_only``, ``think_tags``,
    ``echo_reasoning=turn``, a 32k window unless configured.

- ``health()`` runs ``GET /models`` plus a 1-token ping. It is used by ``/doctor`` in the chat
  and by the header indicator.

.. _33-loop-ailooppy:

3.3 Loop (``ai/loop.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~

- ``run_turn(session, user_text, ctx) -> TurnResult(status, final_text, usage, rounds)``.
  There is no more ``""`` sentinel.
- **Round budgets:** chat 25 and subagents 20, each with a token budget and a wall-clock
  budget, all configurable.

  - On exhaustion, make one *wrap-up request without tools*: "Budget reached. Summarise
    what you found (cite R-ids) and what remains."
  - Then emit ``budget_exhausted`` and ``turn_end(max_rounds)``.
  - The UI shows ``Continue (+N)``, which resumes the same thread.

- **Malformed tool arguments:** never dispatch ``{}``.

  - Attempt one cheap repair: strip code fences and trailing commas.
  - If that fails, return ``{"error":{"code":"invalid_arguments","message":…,"received":<first 500 chars>}}``.

- **Validation:** the registry validates ``required``, types, ``enum`` and unknown keys, with
  no new dependency.
- **Structured errors:** ``ToolError{code, message, retryable, hint}`` with codes
  ``unknown_tool``, ``not_loaded``, ``invalid_arguments``, ``denied``, ``resource_conflict``,
  ``timeout``, ``cancelled``, ``device_unavailable`` and ``tool_failed``.
- **Execution:** tools run sequentially.

  - Each ``ToolSpec.timeout_s`` defaults to 120.
  - The executor stops waiting on timeout or cancel; leases are rolled back.

- **Dispatch order:** resolve (``call_tool`` unwraps the inner tool) → allowed for this
  agent → validate → permission/approval → arbiter leases → ``registry.dispatch``
  (``acting_as("ai")`` plus ``agent_id``) → result shaping and store → lease release or
  rollback.
- Every path, including ``call_tool`` and direct calls to loaded tools, goes through the
  same executor.

.. _34-request-assembly-and-tool-exposure:

3.4 Request assembly and tool exposure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   system[0]  static orchestrator/subagent prompt + toolset catalogue (one line per toolset)
   tools      FIXED for the session: core tools + tool_search + call_tool + read_result
              (+ agent tools for the orchestrator), deterministic order, sort_keys JSON
   history    messages (with reasoning_content on assistant msgs)
   system[n]  ambient "Live Sandroid state" block, inserted right before the newest user
              message on every request, never persisted
              (profile first_only → appended to the newest user message instead)

- **Toolsets:** ``ToolSpec.toolset`` replaces the free-form category.

  - Initial sets: ``core``, ``device``, ``apps``, ``processes``, ``files``, ``network``, ``proxy``,
    ``certs``, ``frida``, ``capture``, ``emulator``, ``monitor``, ``recording``, plus
    ``mcp:<server>``.
  - ``core`` holds about 15–20 tools: state/spotlight, device and app info, foreground
    app, package details, screenshot, flows summary and the like.

- **``tool_search(query)``:**

  - Ranks by BM25 over name, toolset, description and parameter names/descriptions.
  - ``select:a,b`` loads by exact name.
  - Returns the top 5 full schemas as JSON in the tool result, filtered to tools the
    calling agent may use.
  - Loaded names are remembered per thread, so direct calls to them are accepted.
  - Calls to a tool that is neither loaded nor in core return ``not_loaded`` with a hint
    to search.

- **``call_tool(name, arguments)``** is the documented path for loaded tools.
- **``read_result(id, offset?, length?, grep?)``** is capped at the ingest cap.
- MCP ``list_changed`` updates only the search index, never the ``tools`` array.
- A schema lint test enforces:

  - snake_case names
  - descriptions of 600 characters or fewer, covering what, when and returns
  - every parameter described
  - the size of the ``core`` set

.. _35-tool-results-airesultspy:

3.5 Tool results (``ai/results.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Store:** every result goes to ``<session>/ai/results/R<n>.json`` as
  ``{id, tool, args, agent_id, ts, sha256, bytes, result}``.

  - R-ids are session-global and also cover subagents.

- **Ingest cap:** 8k tokens (about 32 KB; configurable ``ai.context.result_cap_tokens``).

  - At or below the cap, the model sees the result plus ``"_rid": "R17"``.
  - Above the cap, the model sees a selected preview: about 1.5k tokens of head and
    about 2k of tail, plus keyword/error/IOC/package hits, plus structure (type, row
    count, keys/columns, top-N grouped counts).
  - The preview always includes ``{"truncated": true, "result_id": "R17", "bytes": …, "hint": "read_result('R17', grep=…)"}``.

- **Per-turn budget:** 25k tokens of tool results across one assistant message's calls.
  Above that, further results come back preview-only.

.. _36-conversations-and-persistence-aisessionpy:

3.6 Conversations and persistence (``ai/session.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Files live under ``<session_dir>/ai/`` (today ``SessionPaths.device_path``; later the
Analysis Session root). The directory is mode 0700 and files are 0600. The folder is
reached through a small ``session_root()`` helper so it can move later.

::

   ai/index.json                 threads list (derived, rebuildable)
   ai/threads/<thread_id>.jsonl  append-only records
   ai/agents/<agent_id>/transcript.jsonl + meta.json
   ai/results/R<n>.json

- **Records:** each has ``v, seq, t, type``. Types are:

  - ``header``: kind (chat/agent), parent links, model, profile, prompt and tools-schema
    hashes
  - ``msg``: role, content, reasoning, tool_calls, tool_call_id, result_id, msg_id, turn
  - ``usage``
  - ``compaction``: kind, range, summary, ids, tokens before and after
  - ``approval``
  - ``close``

- **Ctrl+L / ``/new``:** write ``close``, open a new thread.
- **``/threads``:** list threads and resume one. Resume rebuilds history from the latest
  summary plus later messages, with masked stubs re-applied.
- **TUI restart:** opens a fresh thread in the auto-session. ``/threads`` can resume.
- Spotlight changes stay in the same thread.
- **Timeline lines** (``src="ai"``), each with ``ref`` set to the thread file and msg_id:

  - ``ai/tool``: tool, sanitised args, ok, ms, result_id
  - ``ai/prompt``: sensitive, length only
  - ``ai/turn``: usage
  - ``ai/compact``
  - ``ai/agent``: spawn and done
  - ``ai/approval``

- Streamed text, reasoning, full results and the ambient block never go into the
  timeline.

.. _37-context-management-aicompactionpy:

3.7 Context management (``ai/compaction.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Window:** 262,144 for the DeepSeek profile. The output reserve is 32k, so the usable
  input is about 230k.
- **Accounting:** the last server ``prompt_tokens`` is the ground truth. The pending
  request adds the replayed completion and reasoning tokens plus a local estimate of
  everything new (chars/3.5, self-calibrated against the server).
- **Masking** (deterministic, no LLM), when context use reaches **50%** (≈131k):

  - Replace all tool results except the **last 10** with byte-stable stubs:
    ``{"elided": "R17", "tool": …, "one_line": …, "note": "content moved to disk, not empty — read_result('R17')"}``.
  - Also replace reasoning older than the last 10 assistant messages with
    ``"[reasoning elided]"``. It is on disk.
  - Keep tool *inputs*.
  - Exempt ``read_result`` results from the last 3 rounds.
  - Clear at least 30k tokens per pass, so the cache is invalidated rarely.

- **Summary compaction** (LLM, no tools), when context use reaches **85%** (≈222k) or
  the pending request would not fit:

  - Summarise everything except ``system[0]`` and the most recent ~40k tokens. Cuts happen
    at turn boundaries, so tool_call/tool pairs are never split.
  - Fixed headings: Goal/target · Actions taken · Findings · Hypotheses (UNVERIFIED) ·
    Open tasks · Running agents · Analyst decisions.
  - Every claim cites R-ids and timeline seqs. A validator rejects unknown IDs and checks
    that IDs from the previous summary survive.
  - **On failure:** mask everything older, add the marker "turns X–Y moved to disk".
    After 2 consecutive failures, stop auto-compacting and tell the user.

- **``/compact [focus]``** runs summary compaction manually.
- **Subagents:** masking only. At the hard limit they get a wrap-up request.
- Disk history is never deleted.

.. _38-permissions-aitool_permissionspy:

3.8 Permissions (``ai/tool_permissions.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: toml

   # ~/.config/sandroid/ai_tool_permissions.toml
   mode = "ask"            # "ask" | "allow_all"
   allow = ["launch_app", "kill_process(package=com.example.*)"]
   deny  = []

- **Rule syntax:** ``tool`` or ``tool(arg=glob,…)``.
- **Resolution:**

  1. A matching ``deny`` rule wins.
  2. Otherwise, ``mode="allow_all"`` allows.
  3. Otherwise a matching ``allow`` rule allows.
  4. Otherwise ``READ_ONLY`` allows.
  5. Otherwise ask.

- **Prompt choices:**

  - **Yes**: once.
  - **Yes, don't ask again**: appends the suggested rule. For tools whose risk depends on
    their arguments (``can_remember_choice=False`` today), the rule names the key
    argument.
  - **No**: this call only, with an optional note that goes back to the model as the
    denial reason.
  - Deny rules are added only by editing the file, or with ``/permissions``.

- **Session override:** ``/permissions`` shows mode and rules and can toggle ``allow_all``
  for the session.
- **Migration:** the legacy ``allowed`` list becomes ``allow``, and ``never`` becomes ``deny``,
  on first load.
- **``ApprovalBroker``:** a FIFO of pending requests from any agent. The prompt names the
  agent ("operator a-op-3f9c wants …"). It times out after 300 s, which counts as No.
- Bridged MCP tools are treated as CONSEQUENTIAL.

.. _39-subagents-aiagentspy:

3.9 Subagents (``ai/agents.py``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **``AgentProfile``** (frozen dataclass), with fields:

  - name, description, system_prompt
  - tool selector: toolsets and tiers, plus include/exclude lists
  - max_rounds, max_tokens, max_wall_s
  - max_concurrent, model (None means inherit)
  - resource_ceiling, may_spawn

- **Profiles now:**

  - ``researcher``: READ_ONLY tools, up to 3 concurrent.
  - ``operator``: all tiers, 1 concurrent; approvals go through the normal rules and
    broker with the agent's identity, never auto-approved.
  - More profiles (verifier, narrator, triage, explorer) are added later as data.

- **Orchestrator tools:**

  - ``spawn_agent(profile, task, title?, wait=false)``. ``wait=true`` blocks inside the tool
    call and returns the result.
  - ``wait_agent(id, timeout_s≤60)``, ``get_agent_result(id)``, ``cancel_agent(id)``,
    ``send_to_agent(id, text)`` (delivered at the next round boundary) and
    ``list_agents()``.
  - Agents cannot spawn agents (depth 1).

- **Result:** the agent prompt requires a final message in a fixed format:
  ``status / summary / claims (each with R-ids or timeline seqs) / open questions``.

  - The runtime parses it into ``AgentResult``.
  - If parsing fails, or the agent ran out of budget, there is one wrap-up request
    without tools. If that still fails, the result is ``status=partial`` with the last text.

- **Return path:** an ``agent_result`` event.

  - The parent receives a fenced, visible message:
    ``<subagent-result id=… status=…>`` summary + claims ``</subagent-result>``, capped at
    about 2k tokens and labelled as data, not analyst instructions.
  - It is shown as a card in the chat.
  - If the parent is idle, it is woken. Results are coalesced, with at most 3 automatic
    wakes per analyst message.

- **Scheduler:**

  - A process-wide gateway semaphore of 4 concurrent requests.
  - Per-profile caps.
  - Spawns over the cap are queued, not refused.
  - Each agent has its own ``UsageMeter``, rolled up to the parent for display.

- **Arbiter:**

  - The owner is the agent_id.
  - A synchronous (``wait=true``) child may use leases held by its blocked parent.
  - ``resource_ceiling`` is checked before claiming.
  - Lease reconcile moves from the panel timer into ``AgentManager``.

.. _310-tui:

3.10 TUI
~~~~~~~~

- ``ChatPanel`` only renders ``AgentEvent``\ s and forwards input, approvals and slash
  commands to the session. It no longer owns ``_messages``, the loop, approval polling or
  subtask draining.
- **Header:** state · model · ``◔ 41k/262k 16%`` (muted, then warn at 50%, error at 85%) ·
  ``⟲n`` compactions · agents running.
- **Tool calls:** ``● Humanized name`` plus args. The result is a collapsed one-line chip
  (``✓ R17 · 12 rows · 0.4s``, or ``✗ code: message``).
- **Slash commands:** ``/new``, ``/threads``, ``/compact [focus]``, ``/context`` (breakdown:
  system, tools schema, ambient, history, tool results, summaries, last request,
  session totals), ``/permissions``, ``/agents``, ``/doctor``.
- The agents bar replaces the subtask bar. Enter opens the agent's transcript, with
  cancel and send: a compact header (profile, status, time, live tokens, first line of
  task and result; Ctrl+T shows them in full), the transcript as chat blocks (Markdown
  kept) filling the rest, and the input and buttons always on screen; PageUp/PageDown
  and Ctrl+Home/End scroll it. Closing it returns the focus to the chat input. Keys
  typed on the agents bar go to the input.
- Layout and look of the chat dock, placement and hotkey: see §6.

.. _4-removed:

4. Removed
----------

- ``ai/subtasks.py``

  - ``spawn_subtask`` and ``spawn_privileged_subtask`` (replaced by ``spawn_agent``)
  - the blanket privileged auto-approve
  - ``READ_ONLY_SUBTASK_TOOLS`` and the duplicated ``_SPAWN_TOOL_NAMES``

- ``chat_panel.py`` loop internals:

  - ``_run_turn_sync``
  - message ownership
  - the approval poll loop
  - ``_drain_completions`` and the hidden-user-message injection
  - ``_subtask_outputs``
  - the int epoch
  - the MiniMax first-system-message merge (now a profile option)

- ``loop.py``:

  - the ``""`` sentinel
  - the ``{}`` fallback for bad arguments
  - the tuple ContextVar ``_current_turn_context``

- ``tool_permissions.py``: the "Never"-only denial that persisted on a single click
- ``api/headless.py``: the calls to the nonexistent ``EventBus.subscribe_all``/``unsubscribe_all``
- Stale ``__pycache__`` for removed modules

.. _5-deferred:

5. Deferred
-----------

- Headless automation policy and CLI, ``sandroid ai run`` (beta later)
- The evidence ledger and verifier (FD6)
- Verifier, narrator, triage and explorer profiles
- UI-input tools
- Native DeepSeek ``defer_loading`` (profile flag reserved)
- Parallel tool execution
- Embedding-based tool search
- A redesign of the tool catalogue

.. _6-chat-dock-ui:

6. Chat dock UI
---------------

Two UI design passes on 2026-11-19 produced this section. The mockups and headless
renders live in the session scratchpad (``ui-dock/mockups.txt``, ``ui-look/mock_transcript.txt``,
``ui-look/mascots.py``).

**Hotkey**

- Keep **Ctrl+Y**; there is no collision in Textual 8.2.7 or the app.
- Change it to ``Binding("ctrl+y", "toggle_chat", "AI chat", show=False, id="toggle_chat")``
  so ``tui.keybindings`` can rebind it.
- Register a ``toggle_chat`` action in ``menu_controller.py`` (NAVIGATION category,
  ``[^Y] AI chat``) so it appears in the command palette and the keymap editor.
- Show the hint ``^Y AI`` in the LogTicker, and update the help text, which still says
  "side panel".

**Placement**

- The chat docks in the **bottom half of the left column**, under the lens. The
  Inspector stays on the right, and the two can be open at the same time.
- Compose: ``#workspace > [Vertical#left-col > (#lens-host, ChatDock#chat-dock > ChatPanel), #side-slot > Inspector]``.
  ChatPanel is composed once and never unmounts.
- State:

  - ``_chat_mode`` is one of ``closed``, ``split`` or ``max``.
  - ``_chat_ratio`` takes the presets 0.3, 0.5 or 0.7 (default 0.5).
  - ``_side_mode`` is ``inspector`` or None.

- **Sizing.** Chat rows are ``clamp(round(H*ratio), 10, H-6)``. When ``H < 16``, the
  layout switches to an effective max. Inline height is always reset when switching to
  max.
- **Keys.**

  - **Shift+Up / Shift+Down** step through 0.3, 0.5, 0.7 and max. Ctrl+Up/Down are
    avoided because macOS uses them for Mission Control.
  - **Esc** in the dock focuses the lens, and the chat stays open.
  - **Ctrl+Y** opens the chat and focuses the input. If the chat is open but not
    focused, it focuses it. If it is open and focused, it closes it.
  - The ``handle_escape`` order is: dock focus → lens, then Inspector, then log
    drawer, then chat.

- **Mouse.** Dragging the top border resizes and snaps to the presets. A double-click
  toggles max.
- **Persistence.** The split (ratio, maximized) is remembered in the UI-state file
  ``$XDG_CONFIG_HOME/sandroid/tui_state.json`` (``sandroid.config.ui_state``; 0600,
  written atomically), never in a config file: going through
  ``ConfigLoader.load_and_update_section`` once rewrote the first config file found with
  the whole merged config, API key included. ``TUIConfig.chat_dock`` is only the
  first-run default. (``load_and_update_section`` itself now writes only the keys it is
  given and refuses ``ai.api_key`` and ``credentials.*``.) The chat always starts
  closed.
- **Narrow terminals.** Below 120 columns, add the screen class ``-narrow`` with
  ``#side-slot{width:45%;min-width:0}``. While the chat is open, the log drawer gets
  ``max-height:30%``.
- On first open, scroll to the top so the egress banner is visible.

**Look**

- **Theme tokens only.** Use the ``$lens-*`` tokens, plus six new variables built in
  ``themes/__init__.py`` ``build_textual_theme`` from existing ``Theme`` fields:

  - ``chat-user-band``
  - ``chat-reply``
  - ``chat-tool``
  - ``chat-wait``
  - ``chat-muted``
  - ``chat-brand``

  Delete the hard-coded ``#chat-*``/ChatPanel rules from ``styles.tcss`` and the 13
  ``themes/*.tcss`` files.
- **Dock frame.**

  - Border ``round $lens-rule``; under ``:focus-within`` it becomes ``$lens-rule-focus``.
  - Title ``▚▄▄▞ Sandroid AI`` in ``$lens-accent``.
  - Subtitle ``50% · ⇧↑↓ size · ^Y close``.

- **Transcript.** Replace the RichLog with ``ChatTranscript(VerticalScroll)``, holding one
  widget per block keyed by turn, call or agent id:

  - ``UserBlock``: the full-width band, "Variant I".
  - ``ReplyBlock``: ``Markdown`` fed by ``get_stream()``, so only the live block
    re-renders.
  - ``ReasoningLine``: ``✧ Thinking… 3s`` / ``✧ Thought for 4s``.
  - ``ToolBlock``:

    - The call line is ``● Name args``, with a spinner while running.
    - The result chip ``└ ✓ R17 · 12 rows · 0.4s`` or ``└ ✗ code: message`` is filled
      in place.

  - ``AgentCard``: a round border, the title ``◆ researcher r2 · ✓ done · 38s · 9.2k tok``,
    and claims shown as R-id chips.
  - ``CompactionRule``: ``─ ⟲ compacted · 182k → 41k ─``.
  - ``NoticeLine``: ``↻ Retrying in 4s · attempt 2/5``, updated in place.
  - ``BudgetNotice`` with ``[Continue] [Stop]``.

  Every block is ``width: 1fr``; message boxes use the full width. At most about 300
  blocks stay mounted, and older turns fold into ``▸ N earlier turns``.
- **Header** (one row): state dot, state, model, ``REMOTE`` / ``EXPERIMENTAL``, then
  ``◔ 41k/262k 16%``. The glyph steps through ○◔◑◕●. The colour is ``$lens-dim`` below
  50%, ``$lens-warn`` from 50% and ``$lens-bad`` from 85%. After that come ``⟲n`` and
  ``◆n``. At 60 columns the model is dropped. Updates are throttled to 10 Hz or less.
- **Approval card.** It is pinned above the input.

  - Title: ``⚠ <agent> wants to run <Tool>``.
  - Options:

    - ``1 Yes``
    - ``2 Yes, don't ask again for <rule>``
    - ``3 No, and tell it what to do instead…`` (opens a note Input)

  - Keys 1–3, ↑↓ and Enter; Esc means No. Once answered, the answer is shown on the
    tool call it belongs to, above its result chip (subagent approvals: one transcript
    line).
  - Only the selected option has the cursor background and a ``›`` marker; while the
    note input is open the card and its hint switch to ``$chat-wait``.
  - Focus: the card takes the focus only when the focus already is in the chat (or
    nowhere); stray letters are swallowed while it has it. A closed dock opens
    unfocused; then, and whenever the focus is elsewhere, a toast and the ticker badge
    ``⚠ approval needed · ^Y`` say so, and Ctrl+Y focuses the card.
  - All model text is ``Content`` (never markup): ``rich.markup.escape`` does not match
    Textual 8's parser.

- **Below the scroll area:** the agents bar (one line) and the input row
  (``Ask Sandroid… / for commands``, subtitle ``⏎ send · ^X stop``) with the mascot
  beside it. Typing ``/`` shows a slash-command hint list.
- **Empty state.** Mascot C (the head standing in a ``╘═══════╛`` sandbox tray), plus
  the model, endpoint and egress notice, two example prompts and the slash commands.
- **Mascot B, "Blockhead".** It is 9×3 and drawn with half and quadrant blocks. It sits
  in a normal ``Horizontal`` beside the 3-row input, with no overlay layer.

  ::

       ▚   ▞
      ▄█████▄
     ▐█▄███▄█▌

  The states and the ASCII fallback are in ``ui-look/mascots.py``:

  - idle blink
  - thinking eye-scan
  - streaming antennae
  - tool squint
  - approval in ``$chat-wait``
  - error with ``x`` eyes

  ``ai.chat_mascot`` is one of ``auto``, ``blocks``, ``ascii`` or ``off``, and the old
  ``show_chat_mascot`` is kept as an alias. ``auto`` chooses ASCII when the encoding is
  not UTF-8 or ``TERM`` is ``linux``, ``vt100`` or ``dumb``. The mascot is hidden below
  50 columns, and its timer runs only in animated states. The Braille mascot, overlay
  layer and ``_log_full`` gating are deleted. The startup logo is unchanged.
- **Files.** The block widgets, pure formatters and ``ChatMascot`` go in one new module,
  ``tui/widgets/chat_view.py``. The approval card replaces the body of
  ``tool_permission_prompt.py``.

.. _7-verification:

7. Verification
---------------

- Unit tests per module. Existing ``tests/ai`` and ``tests/tui/test_chat_panel.py`` are
  updated or replaced where behaviour changed.
- Verifiers run only the tests relevant to the changed files.
- Live gateway test: a scripted session against FhGenie covering streaming, usage, tool
  search followed by ``call_tool``, result cap plus ``read_result``, budget wrap-up, a
  spawned researcher, and persistence and resume.
- E2E: Sandroid in tmux on an emulator pinned four ways (config serial, ANDROID_SERIAL,
  ``--serial``, an adb wrapper allow-list). Open the chat and run a multi-tool task, a
  subagent, ``/context``, Ctrl+L plus ``/threads`` resume, and an approval prompt.

.. _8-review-amendments-binding-these-override-the-sections-above:

8. Review amendments (binding; these override the sections above)
-----------------------------------------------------------------

Two independent reviews (2026-11-19) agreed on the following. Live probes:
``tool_choice:"none"`` is accepted by DeepSeek-V4.1 (200, no tool call). Echoed
``reasoning_content`` IS rendered and counted, including across user turns (325 → 1167
prompt tokens), so echo growth is real and the meter must count it.

**Runtime and loop**

- **Owner id.**

  - Keep ``sandroid.ai.loop._current_owner_id`` with that exact name and module, because
    ``tools/session_control.py``, ``tools/recording_control.py`` and tests import it. It
    may become an alias of the new run-context var.
  - The main agent's owner id is the fixed string ``"orchestrator"``. It does not change
    per thread. Only subagents get new ids.

- **Tool threads.**

  - A tool that may time out runs on a helper thread under ``contextvars.copy_context().run``,
    so ``acting_as`` and the owner id propagate.
  - On timeout or cancel the executor stops waiting, but leases are released by a
    done-callback only when the tool thread actually exits. Never roll back while it
    still runs.
  - Per-tool ``timeout_s`` comes from the central toolset table. Long tools such as
    emulator restart, replay and install get 600 s or more.

- **Arguments.**

  - JSON that parses to a non-dict → ``invalid_arguments``.
  - ``call_tool.arguments`` given as a JSON string → parse it.
  - Results are serialized with ``json.dumps(..., default=str)`` inside the try.

- **Persistence on errors.** The user message is persisted before the first request.
  Assistant and tool messages are appended as they happen, so an exception never loses
  executed tool calls.
- **Wrap-up and summary requests** keep the SAME ``tools`` array and send
  ``tool_choice:"none"``, unless the profile says it is unsupported. They are built on the
  existing prefix.
- **Ambient block.** Built once per user turn and inserted as a system message
  immediately before that turn's user message. It is KEPT in the request history for
  later requests, which keeps the prefix stable; it is persisted as a ``ambient`` record so
  resume reproduces it. It is never sent to the timeline. A MiniMax-style ``first_only``
  profile appends it to the user message instead.
- **Safety gate in the runtime.** ``AgentSession`` refuses to start when
  ``get_ai_settings().problem`` is set. It uses ``build_client()`` from ``safety.py``, and all
  error text goes through ``redact_secrets``.
- **Toolbox task names.** The main turn registers as the background task ``"chat"``.
  ``context.py`` hides that exact name, and the StatusBar and stop-all rely on it. Each
  subagent registers as ``"agent:<id>"``.
- **Turn queue.** Each session has a single-runner lock plus a queue. Wakes caused by
  agent results are enqueued by ``AgentManager``, not by the TUI. The worker-spawning
  function is injected.
- **Event sink.** The sink coalesces text and reasoning deltas at about 20 Hz and posts
  without blocking. It checks for the UI thread, because ``call_from_thread`` raises when
  called on it. Subagent token deltas go only to the agent's transcript buffer, not to
  the main transcript.

**Tools**

- **Central toolset table.** ``ai/tools/toolsets.py`` maps tool name → toolset, core flag,
  ``timeout_s`` and ``permission_key``. No ``tools/*.py`` module is edited for this. A test
  checks that every core name exists.
- **MCP tools.**

  - Their names (``mcp:<server>:<tool>``) are exempt from the lint.
  - They are never core and are recommended via ``call_tool``.
  - ``tool_search`` reads the registry live, because MCP bridges arrive late from a worker
    thread.
  - MCP toolsets are announced in the ambient block, not in the frozen ``system[0]``
    catalogue.

- **The schema lint** has an allowlist for current violators, so app-lens changes to
  ``set_spotlight_app`` don't fail it.
- **Compatibility.** ``ToolError`` subclasses ``ToolExecutionError``, and ``ToolSpec(...)``
  keyword construction keeps working.

**Storage and timeline**

- **Session root.**

  - ``session_root()`` uses ``SessionPaths.session_path``, which survives device switches.
  - The root is fixed when a thread opens.
  - ``ai/`` is created lazily on the first write, so ``discard_unused_session`` still works.
  - With no session, the thread lives in memory only (no files) and the UI says so.

- **R-ids.** The counter is guarded by a lock. Files are created with O_EXCL.
  ``next = max(existing) + 1`` on resume. ``index.json`` is written atomically (tmp then
  rename).
- **Timeline lines.**

  - ``ref.path`` is relative to the device folder, e.g. ``../ai/threads/<id>.jsonl``, and
    carries a sha256.
  - ``ai/prompt`` uses ``actor="user"``.
  - Add ``"ai": True`` to ``TimelineConfig.sources`` (``config/schema.py``) and to
    ``_TIMELINE_SOURCE_ORDER`` (``tui/screens/settings_screen.py``).
  - Timeline reads by the compaction validator use ``reader="ai"`` and stay cheap (seq
    bounds only).

**Permissions**

- **Resolution order:**

  1. ``NOT_EXPOSED`` → never.
  2. A matching ``deny`` → never.
  3. ``mode = allow_all`` → allowed.
  4. A matching ``allow`` → allowed.
  5. ``READ_ONLY`` → allowed.
  6. Otherwise ask.

- **Argument-dependent tools** (``can_remember_choice=False`` / ``permission_key`` set)
  accept only rules with an argument constraint. Bare rules for them are rejected.
- **A rule with an argument constraint never matches a missing argument**, for example
  when the tool falls back to the spotlight app.
- **Migration.** Legacy ``allowed`` → ``allow``, dropping bare names for argument-dependent
  tools. Legacy ``never`` entries are NOT migrated: they are reported once in the chat and
  in ``/permissions`` as "previous declines (not enforced)".
- **File writes** are locked and atomic.
- **The egress notice and header show the current mode.** In ``allow_all`` mode they show
  "device-changing tools run without asking". ``EXPERIMENTAL`` and ``REMOTE`` markers stay.

**Agents**

- **Profiles have an ``exclude`` list.** ``start_replay`` and every async-lease tool are
  excluded from all subagents.
- **The gateway semaphore** is held only for the duration of one HTTP request. A
  ``wait=true`` parent holds no slot while waiting. One slot is reserved for the
  orchestrator.
- **Ctrl+L / ``/new``:**

  - It is refused while a turn is running; the user is told to press Ctrl+X first.
  - Running agents are cancelled. Their final records are still written to the old
    thread's agent files, and the orchestrator's leases are released, as today.

- **"Continue (+N)"** re-enters the same thread with the user message
  ``"Continue."``, flagged ``continuation=true``, and grants N more rounds.
- **Spawn transparency.** The transcript shows the full task of each ``spawn_agent`` call.
- **Test isolation.** New singletons (AgentManager, broker, scheduler, result store
  cache) expose ``reset_for_tests()``. ``tests/conftest.py`` resets them.

**TUI compatibility**

- Keep widget IDs ``#chat-header``, ``#chat-log``, ``#chat-input`` and ``#chat-mascot``, because
  12 theme files style them.
- Keep ``ChatPanel.refresh_header()``, which ``settings_screen.py`` and
  ``main_screen.toggle_chat_panel`` call.
- Keep the helpers exported by ``tool_permission_prompt.py``.
- Keep the egress banner.

**Out of scope**

- The ``api/headless.py`` ``subscribe_all`` crash is fixed in its own commit.

**Tests that will be rewritten**

- ``tests/ai/test_subtasks.py`` → ``test_agents.py``
- most of ``tests/ai/test_loop.py``
- the subtask, epoch and approval parts of ``tests/tui/test_chat_panel.py``
- ``tests/ai/test_safety.py`` (spawn and privileged parts)
- ``tests/ai/test_tool_permissions.py``
- ``tests/tui/test_tool_permission_prompt.py``

Keep ``tests/ai/tools/test_session_control.py`` untouched.

.. _9-work-packages:

9. Work packages
----------------

+----+-------------------------+-------------------------------------------+------------+
| WP | Content                 | Files (owner)                             | Depends on |
+====+=========================+===========================================+============+
| 0  | headless                | ``api/headless.py``                       | —          |
|    | ``subscribe_events``    |                                           |            |
|    | fix                     |                                           |            |
+----+-------------------------+-------------------------------------------+------------+
| 1  | Transport + config      | ``ai/client.py``, ``config/schema.py``    | —          |
|    |                         | (ALL new AIConfig fields + timeline       |            |
|    |                         | "ai"), ``config/default.toml``,           |            |
|    |                         | ``tui/screens/settings_screen.py``        |            |
|    |                         | (source order only)                       |            |
+----+-------------------------+-------------------------------------------+------------+
| 2  | Tool layer              | ``ai/tools/registry.py``,                 | —          |
|    |                         | ``ai/tools/toolsets.py``,                 |            |
|    |                         | ``ai/tools/meta.py`` (tool_search with    |            |
|    |                         | BM25, call_tool, read_result),            |            |
|    |                         | ``ai/results.py`` (ResultStore, preview,  |            |
|    |                         | ``session_root``),                        |            |
|    |                         | ``ai/tools/mcp_bridge.py`` (toolset tag)  |            |
+----+-------------------------+-------------------------------------------+------------+
| 3  | Permissions             | ``ai/tool_permissions.py`` (rules, modes, | —          |
|    |                         | migration, ApprovalBroker),               |            |
|    |                         | ``tui/widgets/tool_permission_prompt.py`` |            |
+----+-------------------------+-------------------------------------------+------------+
| 4  | Runtime                 | ``ai/loop.py`` (events, RunContext,       | 1, 2, 3    |
|    |                         | executor, ``run_turn``, legacy shims),    |            |
|    |                         | ``ai/session.py``, ``ai/compaction.py``,  |            |
|    |                         | new prompt constants appended at the END  |            |
|    |                         | of ``ai/prompts.py``                      |            |
+----+-------------------------+-------------------------------------------+------------+
| 5  | Agents                  | ``ai/agents.py``, ``ai/arbiter.py``       | 4          |
|    |                         | (lineage)                                 |            |
+----+-------------------------+-------------------------------------------+------------+
| 6a | Panel cut-over          | ``tui/widgets/chat_panel.py``,            | 5          |
|    |                         | ``ai/__init__.py``, ``tui/app.py`` (MCP   |            |
|    |                         | indexing), delete ``ai/subtasks.py`` and  |            |
|    |                         | the legacy loop shims, rewrite tests      |            |
+----+-------------------------+-------------------------------------------+------------+
| 6b | Panel extras + dock +   | slash commands, agents bar and transcript | 6a         |
|    | look                    | view, dock placement in                   |            |
|    |                         | ``tui/screens/main_screen.py``,           |            |
|    |                         | mascot/icon, themes                       |            |
+----+-------------------------+-------------------------------------------+------------+

Packages 0–3 touch disjoint files and run in parallel. Their config fields are owned by
WP1. WP2 and WP3 read config with ``getattr`` and use defaults until WP1 lands.
