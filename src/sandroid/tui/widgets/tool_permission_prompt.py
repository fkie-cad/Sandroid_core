"""Inline tool-permission-prompt widget for the AI chat tool-calling gate.

Mounted by ``ChatPanel`` (see :mod:`sandroid.tui.widgets.chat_panel`) between
the transcript and the input box whenever
:func:`sandroid.ai.tool_permissions.resolve_tool_policy` returns ``"ask"``
for a pending tool call -- i.e. a reversible/consequential tool with no
saved decision yet. Renders inline, not as a modal popup, so it doesn't
interrupt the surrounding transcript.
"""

import json
from collections.abc import Callable

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Label, Static

from sandroid.ai.tools.registry import ToolSpec

#: Truncation ceiling for the args-preview JSON blob (plan-specified: ~300
#: chars with a trailing ellipsis if longer).
_ARGS_PREVIEW_MAX_LEN = 300

#: Truncation ceiling for the tool's own description text.
_DESCRIPTION_MAX_LEN = 150


def _truncate(text: str, max_len: int) -> str:
    """Truncate ``text`` to ``max_len`` characters with a trailing ``"…"``."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _format_args_preview(arguments: dict) -> str:
    """Render a compact, truncated preview of a pending tool call's arguments.

    Args:
        arguments: The tool-call arguments the model wants to pass.

    Returns:
        ``json.dumps`` of the arguments with keys sorted, truncated to
        ~300 characters with a trailing ``"…"`` if longer.
    """
    preview = json.dumps(dict(sorted(arguments.items())))
    return _truncate(preview, _ARGS_PREVIEW_MAX_LEN)


def _format_args_full(arguments: dict) -> str:
    """Render the complete arguments (sorted, indented) for review."""
    return json.dumps(dict(sorted(arguments.items())), indent=2, ensure_ascii=False)


#: Argument names that fall back to the spotlight app when omitted.
_SPOTLIGHT_DEFAULT_PARAMS = ("package", "package_name")


def _spotlight_default_note(spec: ToolSpec, arguments: dict) -> str | None:
    """Name the spotlight app an omitted ``package``/``package_name`` resolves to.

    Tools such as ``enable_app_proxy()`` act on the spotlight app when called
    without a package; showing the resolved name lets the user see WHICH app
    they are approving. Best effort -- ``None`` when nothing applies.
    """
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


class ToolPermissionPrompt(Horizontal):
    """Inline, in-chat prompt asking the user to approve a pending tool call.

    Shows the tool's name, a truncated description, and a truncated JSON
    preview of its arguments, followed by up to three buttons:

    - "Run once" (always present)
    - "Allow always" (only when ``spec.can_remember_choice`` is ``True``)
    - "Never" (relabeled "Decline" when ``spec.can_remember_choice`` is
      ``False`` -- that choice is call-scoped only in that case, never
      persisted, because the tool's risk lives in its arguments rather than
      its identity)

    Clicking a button calls the ``on_choice`` callback passed to the
    constructor with ``"once"``, ``"always"``, or ``"never"``.

    Known, accepted gap: this is a plain widget, not a ``ModalScreen``, so
    the app's priority ESC binding (routed to quit-confirmation, see
    ``SandroidTUI.action_maybe_quit``) will **not** be intercepted by it the
    way a real modal would be -- only the three buttons or a turn-level
    Stop/Cancel resolve a pending prompt. Acceptable for v1; noted here so
    it isn't mistaken for an oversight later.
    """

    DEFAULT_CSS = """
    ToolPermissionPrompt {
        height: auto;
        padding: 0 1;
        background: $panel;
        border: round $warning;
    }

    ToolPermissionPrompt .tool-permission-body {
        width: 1fr;
        height: auto;
    }

    ToolPermissionPrompt .tool-permission-message {
        width: 1fr;
        content-align: left middle;
    }

    ToolPermissionPrompt .tool-permission-args {
        height: auto;
        max-height: 10;
        border-left: tall $warning;
    }

    ToolPermissionPrompt Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        spec: ToolSpec,
        arguments: dict,
        on_choice: Callable[[str], None],
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the prompt for one pending tool call.

        Args:
            spec: The tool spec pending approval.
            arguments: The arguments the model wants to call the tool with.
            on_choice: Called with ``"once"``, ``"always"``, or ``"never"``
                once the user clicks a button.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._spec = spec
        self._arguments = arguments
        self._on_choice = on_choice

    def compose(self) -> ComposeResult:
        """Build the message line and its buttons."""
        description = _truncate(self._spec.description, _DESCRIPTION_MAX_LEN)
        args_preview = _format_args_preview(self._arguments)
        args_full = _format_args_full(self._arguments)
        truncated = (
            len(json.dumps(dict(sorted(self._arguments.items()))))
            > _ARGS_PREVIEW_MAX_LEN
        )
        never_label = "Never" if self._spec.can_remember_choice else "Decline"

        # Everything model-controlled is markup-escaped: a ``[/]`` or
        # ``[#000000 on #000000]`` inside an argument must not hide text.
        if truncated:
            args_text = (
                "args TRUNCATED in this line — review the FULL arguments "
                f"below ({len(args_full)} chars)"
            )
        else:
            args_text = f"args: {escape(args_preview)}"
        message = (
            f"[bold]{escape(self._spec.name)}[/] wants to run — "
            f"{escape(description)} ({args_text})"
        )
        note = _spotlight_default_note(self._spec, self._arguments)
        if note:
            message += f"\n[b]{escape(note)}[/b]"

        with Vertical(classes="tool-permission-body"):
            yield Label(message, classes="tool-permission-message")
            if truncated:
                with VerticalScroll(classes="tool-permission-args"):
                    yield Static(args_full, markup=False, id="tool-permission-args")
        yield Button("Run once", id="btn-once", classes="-primary")
        if self._spec.can_remember_choice:
            yield Button("Allow always", id="btn-always", classes="-secondary")
        yield Button(never_label, id="btn-never", classes="-secondary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Map the clicked button's ID to a choice and invoke ``on_choice``."""
        choice_by_id = {
            "btn-once": "once",
            "btn-always": "always",
            "btn-never": "never",
        }
        choice = choice_by_id.get(event.button.id)
        if choice is not None:
            self._on_choice(choice)
