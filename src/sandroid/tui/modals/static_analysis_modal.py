"""Static analysis launch dialog (``a``): Dexray Insight profile and options.

Keyboard only: ``p`` switches the analysis profile, ``t``/``s``/``v`` switch
trackers, the security analysis and verbose output, Enter starts, Esc cancels.
States are shown as plain words in theme colours, never as symbols.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, Static

from .base import ForensicModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult

#: Profiles offered in the dialog, in display order: ``(name, description)``.
#: The names are Dexray Insight analysis profiles.
STATIC_ANALYSIS_PROFILES: tuple[tuple[str, str], ...] = (
    (
        "privacy",
        "permissions, trackers, privacy-relevant APIs, strings and behaviour; "
        "skips native code and decompilation",
    ),
    (
        "generic",
        "full analysis: also library similarity, native code and decompilation",
    ),
)

#: Toggle options: ``(key, setting, label)``.
_TOGGLES: tuple[tuple[str, str, str], ...] = (
    ("t", "trackers", "Trackers"),
    # The OWASP checks run in either profile, only when this is on (the
    # profile texts used to promise "every security check" with it off).
    ("s", "security", "Security (OWASP)"),
    ("v", "verbose", "Verbose output"),
)

#: Defaults for a first run (nothing remembered yet): the full analysis that
#: ``a`` always ran.
DEFAULT_STATIC_ANALYSIS_CHOICE: dict[str, Any] = {
    "profile": "generic",
    "trackers": True,
    "security": True,
    "verbose": False,
}


def normalize_choice(raw: Any) -> dict[str, Any]:
    """A complete, valid dialog choice from a remembered (possibly stale) value.

    Args:
        raw: What was stored (any shape; unknown keys and bad values are dropped).

    Returns:
        ``{"profile": str, "trackers": bool, "security": bool, "verbose": bool}``.
    """
    choice = dict(DEFAULT_STATIC_ANALYSIS_CHOICE)
    if isinstance(raw, dict):
        if raw.get("profile") in {name for name, _ in STATIC_ANALYSIS_PROFILES}:
            choice["profile"] = raw["profile"]
        for _key, setting, _label in _TOGGLES:
            if isinstance(raw.get(setting), bool):
                choice[setting] = raw[setting]
    return choice


class StaticAnalysisModal(ForensicModal[dict]):
    """Choose the Dexray Insight profile and options before a static analysis.

    Returns the choice dict (see :func:`normalize_choice`) or ``None`` when
    cancelled.
    """

    DEFAULT_CSS = """
    StaticAnalysisModal .modal-container {
        width: 84;
        max-width: 95%;
        max-height: 90%;
    }

    StaticAnalysisModal .static-target {
        color: $text-muted;
        width: 100%;
        text-align: center;
        margin-bottom: 1;
    }

    StaticAnalysisModal .static-heading {
        text-style: bold;
        width: 100%;
        margin-top: 1;
    }

    StaticAnalysisModal .static-row {
        width: 100%;
        height: auto;
        padding: 0 2;
    }
    """

    BINDINGS = [
        Binding("enter", "submit", "Start", priority=True),
        Binding("p", "next_profile", "Profile", show=False),
        Binding("t", "toggle('trackers')", "Trackers", show=False),
        Binding("s", "toggle('security')", "Security", show=False),
        Binding("v", "toggle('verbose')", "Verbose", show=False),
    ]

    AUTO_FOCUS = ".modal-container"

    def __init__(
        self,
        choice: dict[str, Any] | None = None,
        target: str = "",
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize the dialog.

        Args:
            choice: Initial choice (normally the remembered one).
            target: Package or APK name shown under the title.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.choice = normalize_choice(choice)
        self._target = target

    def compose(self) -> ComposeResult:
        """Create the dialog layout."""
        with Vertical(classes="modal-container"):
            yield Label("Static analysis", classes="modal-title")
            target = f" on {self._target}" if self._target else ""
            yield Label(f"Dexray Insight{target}", classes="static-target")
            yield Label("Profile", classes="static-heading")
            for profile, _description in STATIC_ANALYSIS_PROFILES:
                yield Static(
                    self._profile_text(profile),
                    id=f"profile-{profile}",
                    classes="static-row",
                )
            yield Label("Options", classes="static-heading")
            for key, setting, label in _TOGGLES:
                yield Static(
                    self._toggle_text(key, setting, label),
                    id=f"option-{setting}",
                    classes="static-row",
                )
            yield KeyHintFooter(
                hints={
                    "default": (
                        "[dim]p profile   t trackers   s security   v verbose"
                        "   Enter start   Esc cancel[/dim]"
                    )
                }
            )

    def _profile_text(self, profile: str) -> str:
        description = dict(STATIC_ANALYSIS_PROFILES)[profile]
        if profile == self.choice["profile"]:
            return f"[$accent]●[/] [b $accent]{profile:<9}[/] {description}"
        return f"[$text-muted]○ {profile:<9} {description}[/]"

    def _toggle_text(self, key: str, setting: str, label: str) -> str:
        state = "[$success]● on[/]" if self.choice[setting] else "[$text-muted]○ off[/]"
        return f"[$accent]{key}[/]  {label:<20} {state}"

    def _refresh_rows(self) -> None:
        for profile, _description in STATIC_ANALYSIS_PROFILES:
            try:
                self.query_one(f"#profile-{profile}", Static).update(
                    self._profile_text(profile)
                )
            except Exception:
                pass
        for key, setting, label in _TOGGLES:
            try:
                self.query_one(f"#option-{setting}", Static).update(
                    self._toggle_text(key, setting, label)
                )
            except Exception:
                pass

    def action_next_profile(self) -> None:
        """Switch to the next profile."""
        names = [name for name, _ in STATIC_ANALYSIS_PROFILES]
        index = names.index(self.choice["profile"])
        self.choice["profile"] = names[(index + 1) % len(names)]
        self._refresh_rows()

    def action_toggle(self, setting: str) -> None:
        """Switch one on/off option."""
        if setting in self.choice and isinstance(self.choice[setting], bool):
            self.choice[setting] = not self.choice[setting]
            self._refresh_rows()

    def action_submit(self) -> None:
        """Start the analysis with the current choice."""
        self._dismiss_with_refresh(dict(self.choice))

    def action_cancel(self) -> None:
        """Cancel (sync on purpose: the app's Esc handler calls it directly)."""
        self._dismiss_with_refresh(None)
