"""Inline approval card for a pending AI tool call (Claude Code style).

Mounted in the chat dock between the transcript and the input box. Shows who
asks ("<agent> wants to run <Humanized tool>"), the risk tier, the tool's
description and an arguments preview, then three options:

1. Yes
2. Yes, don't ask again for <rule description>   (only when a rule exists)
3. No, and tell it what to do instead...         (reveals a note input)

Keys: ``1``-``3`` pick an option, ``↑``/``↓`` + ``Enter`` select, ``Esc``
answers No. Keyboard input is ignored for a short grace period after the
card appears, so keys typed into the chat input a moment earlier cannot
approve anything. Mouse clicks work at once. Other printable keys are
swallowed while the card has the focus, so a typed word never reaches the
App's one-letter hotkeys.

The card takes the focus on mount only when the focus already is inside its
parent (the chat panel) or nowhere, and only while it is visible: an approval
arriving while the analyst works in a lens must not capture the next Enter.
The answer goes to ``on_decision(Decision)`` (choice ``once``/``always``/
``no`` plus the note).

Every model-controlled string (tool name, description, arguments, the rule)
is put into :class:`~textual.content.Content` as plain text, never parsed as
markup: Textual 8's markup parser does not honour ``rich.markup.escape``
(``[Black on black]`` still hides text, ``[A-Z]`` disappears).

Inside the real app the App's priority ``escape`` binding fires before this
widget's own one; the screen's Esc handler should call
:meth:`ToolPermissionPrompt.action_cancel` (sync) when focus is inside a card.
"""

from __future__ import annotations

import contextlib
import json
import time
from typing import TYPE_CHECKING, Any

from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widgets import Input, Label, Static

from sandroid.ai.tool_permissions import (
    ApprovalRequest,
    Decision,
    describe_rule,
    humanize_tool_name,
    suggest_rule,
)
from sandroid.ai.tools.registry import RiskTier, ToolSpec

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from textual import events
    from textual.app import ComposeResult

#: Truncation ceiling for the args-preview JSON blob.
_ARGS_PREVIEW_MAX_LEN = 300

#: Truncation ceiling for the tool's own description text.
_DESCRIPTION_MAX_LEN = 150

#: Seconds after mounting during which keyboard input is ignored.
_INPUT_GRACE_S = 0.4


def _truncate(text: str, max_len: int) -> str:
    """Truncate ``text`` to ``max_len`` characters with a trailing ``"…"``."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _format_args_preview(arguments: Mapping[str, Any]) -> str:
    """Compact preview of a call's arguments.

    Returns:
        ``json.dumps`` of the arguments with keys sorted, truncated to
        ~300 characters with a trailing ``"…"`` if longer.
    """
    preview = json.dumps(dict(sorted(arguments.items())), default=str)
    return _truncate(preview, _ARGS_PREVIEW_MAX_LEN)


def _format_args_full(arguments: Mapping[str, Any]) -> str:
    """The complete arguments (sorted, indented) for review."""
    return json.dumps(
        dict(sorted(arguments.items())), indent=2, ensure_ascii=False, default=str
    )


#: Argument names that fall back to the spotlight app when omitted.
_SPOTLIGHT_DEFAULT_PARAMS = ("package", "package_name")


def _spotlight_default_note(
    spec: ToolSpec | None, arguments: Mapping[str, Any]
) -> str | None:
    """Name the spotlight app an omitted ``package``/``package_name`` resolves to.

    Best effort -- ``None`` when nothing applies.
    """
    if spec is None:
        return None
    properties = (spec.parameters or {}).get("properties") or {}
    for param in _SPOTLIGHT_DEFAULT_PARAMS:
        if param in properties and not arguments.get(param):
            try:
                from sandroid.services import get_spotlight_service

                package = get_spotlight_service().get_effective_package()
            except Exception:
                package = None
            target = f"'{package}'" if package else "none selected"
            return f"{param} omitted → current spotlight app: {target}"
    return None


_TIER_LABELS = {
    RiskTier.READ_ONLY: "read-only",
    RiskTier.REVERSIBLE: "reversible",
    RiskTier.CONSEQUENTIAL: "consequential",
    RiskTier.NOT_EXPOSED: "not exposed",
}

#: Option widget id per choice (kept from the Button era).
_OPTION_IDS = {"once": "btn-once", "always": "btn-always", "no": "btn-never"}

#: Hint line, normally and while the note input is open.
HINT = "1-3 or ↑↓ Enter · Esc = No"
HINT_NOTE = "Enter sends No with this note · empty = just No · Esc = No"


def approval_title(agent_label: str, tool: str) -> Content:
    """``<agent> wants to run <Tool>`` (§6); the agent in the warn colour."""
    return Content.assemble(
        (agent_label, "bold $lens-warn"),
        " wants to run ",
        (humanize_tool_name(tool), "bold"),
    )


def approval_message(
    tool: str,
    description: str,
    arguments: Mapping[str, Any],
    note: str | None = None,
) -> Content:
    """Tool, description, args preview (or the TRUNCATED flag) and a note.

    Plain text only: nothing here is parsed as markup.
    """
    args_full = _format_args_full(arguments)
    truncated = (
        len(json.dumps(dict(sorted(arguments.items())), default=str))
        > _ARGS_PREVIEW_MAX_LEN
    )
    parts: list[Any] = [(tool, "bold")]
    description = _truncate(description or "", _DESCRIPTION_MAX_LEN)
    if description:
        parts += [" — ", description]
    parts.append("\n")
    if truncated:
        parts.append(
            (
                "args TRUNCATED in this line — review the FULL arguments "
                f"below ({len(args_full)} chars)",
                "bold $lens-warn",
            )
        )
    else:
        parts += [("args: ", "$lens-dim"), _format_args_preview(arguments)]
    if note:
        parts += ["\n", (note, "bold")]
    return Content.assemble(*parts)


class ApprovalOption(Static):
    """One option row of the card (not a Button: the themes' ``Button``
    rules painted every option in the accent colour).
    """

    class Pressed(Message):
        """The option was clicked."""

        def __init__(self, option: ApprovalOption) -> None:
            super().__init__()
            self.option = option

    def __init__(self, label: str, choice: str, **kwargs: Any) -> None:
        super().__init__("", **kwargs)
        self.label = label
        self.choice = choice
        self.can_focus = False

    def render(self) -> Content:
        selected = self.has_class("-highlighted")
        marker = ("› ", "bold") if selected else "  "
        return Content.assemble(marker, self.label)

    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.post_message(self.Pressed(self))


class ToolPermissionPrompt(Vertical, can_focus=True):
    """Approval card for one pending tool call (see the module docstring).

    Option rows keep the ids ``btn-once``, ``btn-always`` and ``btn-never``;
    the note input is ``#tool-permission-note``.
    """

    BINDINGS = [
        Binding("1", "choose_index(0)", "Option 1", show=False),
        Binding("2", "choose_index(1)", "Option 2", show=False),
        Binding("3", "choose_index(2)", "Option 3", show=False),
        Binding("up", "move(-1)", "Up", show=False),
        Binding("down", "move(1)", "Down", show=False),
        Binding("enter", "select", "Select", show=False),
        Binding("escape", "cancel", "No", show=False),
    ]

    DEFAULT_CSS = """
    ToolPermissionPrompt {
        height: auto;
        padding: 0 1;
        background: $lens-panel;
        color: $lens-text;
        border: round $lens-warn;
    }
    ToolPermissionPrompt:focus-within {
        border: round $lens-accent;
    }
    ToolPermissionPrompt .tool-permission-body {
        width: 1fr;
        height: auto;
    }
    ToolPermissionPrompt .tool-permission-head {
        width: 1fr;
        height: auto;
    }
    ToolPermissionPrompt .tool-permission-title {
        width: 1fr;
        color: $lens-title;
    }
    ToolPermissionPrompt .tool-permission-tier {
        width: auto;
        padding: 0 1;
        color: $lens-warn;
    }
    ToolPermissionPrompt .tool-permission-tier.-consequential,
    ToolPermissionPrompt .tool-permission-tier.-not-exposed {
        color: $lens-bad;
    }
    ToolPermissionPrompt .tool-permission-tier.-read-only {
        color: $lens-ok;
    }
    ToolPermissionPrompt .tool-permission-message {
        width: 1fr;
        color: $lens-label;
    }
    ToolPermissionPrompt .tool-permission-args {
        height: auto;
        max-height: 10;
        border-left: tall $lens-warn;
        background: $lens-bg;
    }
    ToolPermissionPrompt .tool-permission-options {
        height: auto;
        margin-top: 1;
    }
    ToolPermissionPrompt ApprovalOption {
        width: 1fr;
        height: 1;
        padding: 0 1;
        background: $lens-panel;
        color: $lens-text;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    ToolPermissionPrompt ApprovalOption:hover {
        background: $lens-action-hover-bg;
        color: $lens-action-hover-text;
    }
    ToolPermissionPrompt ApprovalOption.-highlighted {
        background: $lens-cursor;
        text-style: bold;
    }
    ToolPermissionPrompt:focus ApprovalOption.-highlighted {
        background: $lens-cursor-focus;
    }
    ToolPermissionPrompt.-noting ApprovalOption.-highlighted {
        background: $lens-panel;
        color: $chat-wait;
    }
    ToolPermissionPrompt #tool-permission-note {
        margin-top: 1;
        border: tall $chat-wait;
        background: $lens-input-bg;
        color: $lens-input-text;
    }
    ToolPermissionPrompt #tool-permission-note:focus {
        border: tall $lens-accent;
        background: $lens-input-focus-bg;
    }
    ToolPermissionPrompt .-hidden {
        display: none;
    }
    ToolPermissionPrompt .tool-permission-hint {
        width: 1fr;
        color: $lens-dim;
    }
    ToolPermissionPrompt.-noting .tool-permission-hint {
        color: $chat-wait;
    }
    """

    def __init__(
        self,
        spec: ToolSpec | None = None,
        arguments: Mapping[str, Any] | None = None,
        *,
        request: ApprovalRequest | None = None,
        on_decision: Callable[[Decision], None] | None = None,
        agent_label: str | None = None,
        suggested_rule: str | None = None,
        permission_key: str | None = None,
        ask_note: bool = True,
        auto_focus: bool = True,
        input_grace_s: float = _INPUT_GRACE_S,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Build the card.

        Args:
            spec: The tool spec (optional with ``request``).
            arguments: The call's arguments (defaults to ``request.args``).
            request: The broker request; supplies tool, args, risk, agent
                label, description and suggested rule.
            on_decision: Receives the :class:`Decision`.
            agent_label: Who asks (overrides ``request.agent_label``).
            suggested_rule: Rule for option 2 (overrides the request's).
                Without either, it is derived with
                :func:`~sandroid.ai.tool_permissions.suggest_rule`.
            permission_key: Used for that derivation only.
            ask_note: Whether "No" reveals the note input first.
            auto_focus: May take the focus on mount (see the module
                docstring for when it actually does).
            input_grace_s: Keyboard grace period after mounting.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        if spec is None and request is None:
            raise ValueError("ToolPermissionPrompt needs a spec or a request")
        self._spec = spec
        self._request = request
        self._arguments: Mapping[str, Any] = (
            arguments
            if arguments is not None
            else (dict(request.args) if request is not None else {})
        )
        self._on_decision = on_decision
        self._tool = spec.name if spec is not None else request.tool  # type: ignore[union-attr]
        self._risk = spec.risk if spec is not None else request.risk  # type: ignore[union-attr]
        self._description = (
            spec.description
            if spec is not None and spec.description
            else (request.description if request is not None else "")
        )
        self._agent_label = (
            agent_label or (request.agent_label if request is not None else "") or "AI"
        )
        if suggested_rule is None and request is not None:
            suggested_rule = request.suggested_rule
        if suggested_rule is None and request is None and spec is not None:
            suggested_rule = suggest_rule(
                spec.name,
                self._arguments,
                permission_key=permission_key,
                can_remember_choice=spec.can_remember_choice,
            )
        self._suggested_rule = suggested_rule
        self._ask_note = ask_note
        self._auto_focus = auto_focus
        self._input_grace_s = input_grace_s
        self._mounted_at = 0.0
        self._highlight = 0
        self._decided = False

    # -- compose -------------------------------------------------------------

    @property
    def suggested_rule(self) -> str | None:
        return self._suggested_rule

    @property
    def decided(self) -> bool:
        return self._decided

    @property
    def tool(self) -> str:
        return self._tool

    @property
    def agent_label(self) -> str:
        return self._agent_label

    @property
    def noting(self) -> bool:
        """The note input is open (option 3 was chosen once)."""
        return self.has_class("-noting")

    def _choices(self) -> list[str]:
        choices = ["once"]
        if self._suggested_rule:
            choices.append("always")
        choices.append("no")
        return choices

    def _option_label(self, number: int, choice: str) -> str:
        if choice == "once":
            text = "Yes"
        elif choice == "always":
            text = f"Yes, don't ask again for {describe_rule(self._suggested_rule)}"
        elif self._ask_note:
            text = "No, and tell it what to do instead…"
        else:
            text = "No"
        return f"{number}  {text}"

    def compose(self) -> ComposeResult:
        """Build the header, details, options and the (hidden) note input."""
        args_full = _format_args_full(self._arguments)
        truncated = (
            len(json.dumps(dict(sorted(self._arguments.items())), default=str))
            > _ARGS_PREVIEW_MAX_LEN
        )
        tier = _TIER_LABELS.get(self._risk, str(self._risk))
        message = approval_message(
            self._tool,
            self._description,
            self._arguments,
            _spotlight_default_note(self._spec, self._arguments),
        )
        with Vertical(classes="tool-permission-body"):
            with Horizontal(classes="tool-permission-head"):
                yield Label(
                    approval_title(self._agent_label, self._tool),
                    classes="tool-permission-title",
                )
                yield Label(
                    Content(tier),
                    classes=f"tool-permission-tier -{tier.replace(' ', '-')}",
                )
            yield Label(message, classes="tool-permission-message")
            if truncated:
                with VerticalScroll(classes="tool-permission-args"):
                    yield Static(Content(args_full), id="tool-permission-args")
        with Vertical(classes="tool-permission-options"):
            for index, choice in enumerate(self._choices()):
                yield ApprovalOption(
                    self._option_label(index + 1, choice),
                    choice,
                    id=_OPTION_IDS[choice],
                    classes="-highlighted" if index == 0 else None,
                )
        yield Input(
            placeholder="Tell it what to do instead (Enter sends, empty = just No)",
            id="tool-permission-note",
            classes="-hidden",
        )
        yield Label(Content(HINT), classes="tool-permission-hint")

    def on_mount(self) -> None:
        self._mounted_at = time.monotonic()
        if self._auto_focus:
            self.call_after_refresh(self._focus_self)

    def may_take_focus(self) -> bool:
        """Visible, and the focus is nowhere or already inside the parent."""
        if self._decided or not self.is_attached:
            return False
        if not all(node.display for node in self.ancestors_with_self):
            return False
        focused = self.screen.focused
        if focused is None:
            return True
        parent = self.parent
        return parent is not None and parent in focused.ancestors_with_self

    def _focus_self(self) -> None:
        if self.may_take_focus():
            self.focus()

    # -- keyboard -------------------------------------------------------------

    def _in_grace(self) -> bool:
        return time.monotonic() - self._mounted_at < self._input_grace_s

    def _options(self) -> list[ApprovalOption]:
        return list(self.query(ApprovalOption).results(ApprovalOption))

    def _set_highlight(self, index: int) -> None:
        options = self._options()
        if not options:
            return
        self._highlight = max(0, min(index, len(options) - 1))
        for i, option in enumerate(options):
            option.set_class(i == self._highlight, "-highlighted")

    def on_key(self, event: events.Key) -> None:
        """Swallow stray printable keys while the card itself has the focus.

        ``1``-``3`` stay bindings; anything else typed here (e.g. the rest of
        a word meant for the chat input) must not reach the App's one-letter
        hotkeys. The note input handles its own typing.
        """
        if self._decided or self.screen.focused is not self:
            return
        if event.is_printable and event.character not in ("1", "2", "3"):
            event.stop()
            event.prevent_default()

    def action_move(self, delta: int) -> None:
        """Move the highlighted option."""
        if self._decided:
            return
        self._set_highlight(self._highlight + delta)

    def action_choose_index(self, index: int) -> None:
        """Pick the ``index``-th visible option (keys 1-3)."""
        if self._decided or self._in_grace():
            return
        choices = self._choices()
        if 0 <= index < len(choices):
            self._set_highlight(index)
            self._choose(choices[index])

    def action_select(self) -> None:
        """Pick the highlighted option (Enter)."""
        if self._decided or self._in_grace():
            return
        self._choose(self._choices()[self._highlight])

    def action_cancel(self) -> None:
        """Esc: answer No (with the note typed so far, if any). Sync on purpose."""
        if self._decided:
            return
        self._finish("no", self._note_text())

    # -- mouse / note -----------------------------------------------------------

    def on_approval_option_pressed(self, event: ApprovalOption.Pressed) -> None:
        event.stop()
        choice = event.option.choice
        self._set_highlight(self._choices().index(choice))
        self._choose(choice)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "tool-permission-note":
            return
        event.stop()
        self._finish("no", event.value)

    def _note_text(self) -> str | None:
        try:
            note = self.query_one("#tool-permission-note", Input)
        except Exception:
            return None
        if note.has_class("-hidden"):
            return None
        return note.value

    def _choose(self, choice: str) -> None:
        if self._decided:
            return
        if choice == "no" and self._ask_note:
            note = self.query_one("#tool-permission-note", Input)
            if note.has_class("-hidden"):
                note.remove_class("-hidden")
                self.add_class("-noting")
                with contextlib.suppress(Exception):
                    self.query_one(".tool-permission-hint", Label).update(
                        Content(HINT_NOTE)
                    )
                note.focus()
                return
            self._finish("no", note.value)
            return
        self._finish(choice, None)

    def _finish(self, choice: str, note: str | None) -> None:
        if self._decided:
            return
        self._decided = True
        note = (note or "").strip() or None
        if self._on_decision is not None:
            remembered = self._suggested_rule if choice == "always" else None
            self._on_decision(Decision(choice, note=note, remembered_rule=remembered))  # type: ignore[arg-type]
