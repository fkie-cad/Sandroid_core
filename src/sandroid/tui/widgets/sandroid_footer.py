"""Custom footer with keybinding hints (left) and minimized task bar (right)."""

import logging

from textual.app import ComposeResult
from textual.containers import HorizontalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets._footer import FooterKey

from sandroid.tui.widgets.minimized_task_bar import MinimizedTaskBar

logger = logging.getLogger(__name__)


class SandroidFooter(Widget):
    """Footer bar split into two zones: key bindings (left) and minimized tasks (right)."""

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
    SandroidFooter MinimizedTaskBar {
        width: auto;
        height: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield HorizontalScroll(id="footer-keys")
        yield MinimizedTaskBar(id="minimized-task-bar")

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

    def _rebuild_keys(self) -> None:
        """Rebuild keybinding display from current active bindings."""
        try:
            keys_container = self.query_one("#footer-keys", HorizontalScroll)
        except Exception:
            return
        keys_container.remove_children()
        active_bindings = self.screen.active_bindings
        footer_keys = [
            FooterKey(
                binding.key,
                self.app.get_key_display(binding),
                binding.description,
                binding.action,
                disabled=not enabled,
                tooltip=tooltip or binding.description,
            )
            for _, binding, enabled, tooltip in active_bindings.values()
            if binding.show
        ]
        if footer_keys:
            keys_container.mount(*footer_keys)
