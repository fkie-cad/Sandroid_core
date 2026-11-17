"""Custom footer with keybinding hints."""

import logging

from textual.app import ComposeResult
from textual.containers import HorizontalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets._footer import FooterKey

logger = logging.getLogger(__name__)


class SandroidFooter(Widget):
    """Footer bar showing active key bindings."""

    #: Actions always shown first (see ``_rebuild_keys``).
    #: ``back_to_live`` (MainScreen ``L``) only shows while in REVIEW scope.
    PINNED_ACTIONS = frozenset(
        {"record", "play", "app.record", "app.play", "back_to_live"}
    )

    #: The footer never shows more than this many keys (calm; ``?`` has all).
    MAX_KEYS = 7

    DEFAULT_CSS = """
    SandroidFooter {
        dock: bottom;
        height: 1;
        layout: horizontal;
        background: $footer-background;
        color: $footer-foreground;
    }
    SandroidFooter HorizontalScroll {
        width: 1fr;
        height: 1;
        scrollbar-size: 0 0;
    }
    SandroidFooter FooterKey {
        padding: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield HorizontalScroll(id="footer-keys")

    def on_mount(self) -> None:
        try:
            self.screen.bindings_updated_signal.subscribe(self, self.bindings_changed)
        except (AttributeError, Exception) as e:
            logger.debug(f"SandroidFooter signal subscribe skipped: {e}")

    def on_unmount(self) -> None:
        try:
            self.screen.bindings_updated_signal.unsubscribe(self)
        except AttributeError:
            pass

    def bindings_changed(self, screen: Screen) -> None:
        if not screen.app.app_focus:
            return
        if self.is_attached and screen is self.screen:
            self.call_after_refresh(self._rebuild_keys)

    @classmethod
    def footer_entries(cls, entries: list, app) -> list:
        """Pick at most ``MAX_KEYS`` shown bindings, context first.

        Order: the main flow (Record / Play, so it survives truncation on
        narrow projector terminals), then the focused lens/widget's own keys
        (the context), then the few global keys the app still shows (lens
        digits, Help, Quit). Context keys are trimmed first.
        """
        shown = [e for e in entries if e[1].show]
        pinned = [e for e in shown if e[1].action in cls.PINNED_ACTIONS]
        rest = [e for e in shown if e[1].action not in cls.PINNED_ACTIONS]
        global_keys = [e for e in rest if e[0] is app]
        context = [e for e in rest if e[0] is not app]
        budget = max(0, cls.MAX_KEYS - len(pinned) - len(global_keys))
        picked = pinned + context[:budget] + global_keys
        return picked[: cls.MAX_KEYS]

    def _rebuild_keys(self) -> None:
        """Rebuild keybinding display from current active bindings."""
        try:
            keys_container = self.query_one("#footer-keys", HorizontalScroll)
        except Exception:
            return
        keys_container.remove_children()
        entries = self.footer_entries(
            list(self.screen.active_bindings.values()), self.app
        )
        footer_keys = [
            FooterKey(
                binding.key,
                self.app.get_key_display(binding),
                binding.description,
                binding.action,
                disabled=not enabled,
                tooltip=tooltip or binding.description,
            )
            for _, binding, enabled, tooltip in entries
        ]
        if footer_keys:
            keys_container.mount(*footer_keys)
