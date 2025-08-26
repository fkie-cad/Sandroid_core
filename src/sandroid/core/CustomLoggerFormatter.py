from colorlog import ColoredFormatter


class CustomFormatter(ColoredFormatter):
    """Logging colored formatter using colorlog for consistent styling across the codebase"""

    def __init__(self, fmt=None):
        if fmt is None:
            fmt = "%(log_color)s[%(asctime)s] [%(levelname)-4s]%(reset)s - %(message)s"

        super().__init__(
            fmt=fmt,
            datefmt="%d-%m-%y %H:%M:%S",
            reset=True,
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "bold_yellow",
                "ERROR": "bold_red",
                "CRITICAL": "bold_red",
            },
            secondary_log_colors={},
            style="%",
        )
