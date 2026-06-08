"""Modal for picking which user-supplied mitmproxy addons load.

Lists the ``*.py`` addons discovered in the configured user dir and the
project-local ``./mitm_addons/`` via a Textual ``SelectionList`` checklist,
pre-checking the currently-enabled ones. A free-form "Custom path" input
allows loading an addon that lives outside the scanned folders.

Styled with the green Frida theme to match the other tool-oriented modals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from .base import FridaModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from sandroid.services.mitmproxy_service import MitmproxyService


@dataclass
class MitmproxyAddonsResult:
    """Result returned from :class:`MitmproxyAddonsModal`.

    Attributes:
        cancelled: Whether the modal was dismissed without applying.
        enabled_paths: Resolved absolute path strings the user checked
            (plus any custom path entered).
        open_folder: Whether the user asked to open the addons folder.
    """

    cancelled: bool = True
    enabled_paths: list[str] = field(default_factory=list)
    open_folder: bool = False


class MitmproxyAddonsModal(FridaModal[MitmproxyAddonsResult]):
    """Checklist modal for enabling/disabling custom mitmproxy addons.

    The checklist values are resolved absolute path strings (keying by full
    path avoids cross-dir filename collisions). Checking an addon enables it;
    unchecking disables it. Applying persists the selection via the service,
    which restarts mitmweb if it is running.
    """

    DEFAULT_CSS = """
    MitmproxyAddonsModal .modal-container {
        width: 80;
        max-width: 90%;
        max-height: 85%;
    }

    MitmproxyAddonsModal #addons-dirs {
        color: $text-muted;
        padding: 0 1;
        margin-bottom: 1;
    }

    MitmproxyAddonsModal #addon-list {
        height: auto;
        max-height: 14;
        margin-bottom: 1;
    }

    MitmproxyAddonsModal #custom-path {
        width: 1fr;
    }

    MitmproxyAddonsModal .button-row {
        height: auto;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "apply", "Apply", priority=True),
    ]

    AUTO_FOCUS = "#addon-list"

    def __init__(self, service: MitmproxyService, **kwargs) -> None:
        """Initialize the addons modal.

        Args:
            service: The :class:`MitmproxyService` used to list, read and
                persist the enabled-addons selection.
            **kwargs: Forwarded to the base modal (``name``/``id``/``classes``).
        """
        super().__init__(**kwargs)
        self._service = service

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("mitmproxy Addons", classes="modal-title")

            user_dir = self._service.user_addons_dir
            yield Static(
                f"[dim]Scanning:[/dim] {user_dir}\n"
                "[dim]and ./mitm_addons (current working dir, if present)[/dim]",
                id="addons-dirs",
            )

            enabled = {str(p) for p in self._service.get_enabled_addons()}
            selections = [
                Selection(
                    f"{p.name}  [dim]({p.parent})[/dim]",
                    str(p),
                    str(p) in enabled,
                )
                for p in self._service.list_available_addons()
            ]
            yield SelectionList[str](*selections, id="addon-list")

            yield Input(placeholder="Custom: /path/to/addon.py", id="custom-path")

            with Horizontal(classes="button-row"):
                yield Button("Apply", id="btn-apply", classes="-primary")
                yield Button("Open Folder", id="btn-open")
                yield Button("Cancel", id="btn-cancel")

            yield KeyHintFooter(
                hints={"default": "[dim]Space=Toggle  Enter=Apply  Esc=Cancel[/dim]"}
            )

    def _collect_enabled(self) -> list[str]:
        """Return checked addon paths plus any non-empty custom path.

        Returns:
            Resolved absolute path strings; the custom path is expanded and
            resolved, and appended only if not already in the selection.
        """
        selected = list(self.query_one(SelectionList).selected)
        try:
            custom = self.query_one("#custom-path", Input).value.strip()
        except Exception:
            custom = ""
        if custom:
            resolved = str(Path(custom).expanduser().resolve())
            if resolved not in selected:
                selected.append(resolved)
        return selected

    def action_apply(self) -> None:
        """Collect the selection and dismiss with it applied."""
        self.dismiss(
            MitmproxyAddonsResult(
                cancelled=False,
                enabled_paths=self._collect_enabled(),
            )
        )

    def action_cancel(self) -> None:
        """Cancel and close the modal (sync — required for the ESC handler)."""
        self._dismiss_with_refresh(MitmproxyAddonsResult(cancelled=True))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route button presses to the matching action."""
        if event.button.id == "btn-apply":
            self.action_apply()
        elif event.button.id == "btn-cancel":
            self.action_cancel()
        elif event.button.id == "btn-open":
            self.dismiss(
                MitmproxyAddonsResult(
                    cancelled=False,
                    enabled_paths=self._collect_enabled(),
                    open_folder=True,
                )
            )
