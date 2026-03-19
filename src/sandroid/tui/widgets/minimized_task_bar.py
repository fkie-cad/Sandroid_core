"""Minimized task bar widget for showing minimized observer tasks."""

from textual.widgets import Static


class MinimizedTaskBar(Static):
    """Bar showing minimized observer tasks at bottom of right panel.

    Appears only when an observer modal is minimized.
    Docked to bottom of #right-panel so it sits just above the Footer,
    aligned with the activity log area.
    """

    DEFAULT_CSS = """
    MinimizedTaskBar {
        height: 1;
        background: $primary 15%;
        color: $foreground;
        padding: 0 1;
        display: none;
    }
    MinimizedTaskBar.visible {
        display: block;
    }
    """

    def show_minimized(
        self, task_name: str, description: str, restore_key: str = "o"
    ) -> None:
        """Show the minimized indicator for a task.

        Args:
            task_name: Name of the minimized task (e.g. "FSMon")
            description: Description of what's being monitored
            restore_key: Key to restore the task (default "o")
        """
        self.update(
            f"[#00ff00]\u25cf[/] [bold]{task_name}[/] minimized \u2014 {description}  "
            f"[bold $primary]\\[{restore_key}]=Restore[/]"
        )
        self.add_class("visible")

    def hide(self) -> None:
        """Hide the minimized indicator."""
        self.remove_class("visible")
        self.update("")
