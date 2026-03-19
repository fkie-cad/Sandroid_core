"""Shared logging setup for analysis modules (dexray-intercept, friTap, etc.).

Provides a common function to configure dedicated file logging for analysis
tool loggers, avoiding duplication between malwaremonitor.py and fritap.py.
"""

import logging
import os

logger = logging.getLogger(__name__)


def setup_analysis_logging(
    logger_name: str,
    log_dir: str,
    log_filename: str,
    log_level: int = logging.DEBUG,
    log_format: str = "%(asctime)s~%(levelname)s~%(message)s~module:%(module)s~function:%(funcName)s",
) -> str | None:
    """Set up dedicated file logging for an analysis tool.

    Adds a FileHandler to the named logger if one doesn't already exist and
    the RESULTS_PATH environment variable is set.

    Args:
        logger_name: The logger name to configure (e.g. "dexray_intercept", "friTap").
        log_dir: Directory path where the log file will be created.
        log_filename: Name of the log file (e.g. "dexray.log").
        log_level: Logging level for the file handler. Defaults to DEBUG.
        log_format: Format string for log messages.

    Returns:
        The full path to the log file if created, or None if skipped.
    """
    target_logger = logging.getLogger(logger_name)

    # Check if we already have a file handler to avoid duplicates
    has_file_handler = any(
        isinstance(handler, logging.FileHandler) for handler in target_logger.handlers
    )

    if has_file_handler:
        return None

    if not os.getenv("RESULTS_PATH"):
        return None

    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, log_filename)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(log_format)
    file_handler.setFormatter(file_formatter)
    target_logger.addHandler(file_handler)
    target_logger.setLevel(log_level)

    logger.info(f"{logger_name} logs will be saved to {log_path}")
    return log_path
