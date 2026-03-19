"""Factory for creating CommandContext instances.

This module provides a factory function to create properly initialized
CommandContext instances from ActionQ, bridging the old architecture
with the new command system.
"""

import logging
from typing import Any

from .base import CommandContext

logger = logging.getLogger(__name__)


def _safe_import(import_func, label: str):
    """Import a dependency with graceful fallback on failure.

    Args:
        import_func: Callable that performs the import and returns the result
        label: Human-readable label for logging on failure

    Returns:
        The imported object, or None if import failed
    """
    try:
        return import_func()
    except ImportError as e:
        logger.warning(f"Could not import {label}: {e}")
    except Exception as e:
        logger.warning(f"Could not initialize {label}: {e}")
    return None


def create_context_from_actionq(
    action_queue: Any,
    toolbox: Any | None = None,
) -> CommandContext:
    """Create a CommandContext from ActionQ and Toolbox.

    This factory function bridges the legacy ActionQ-based architecture
    with the new command system by populating a CommandContext with all
    necessary services, utilities, and request functions.

    Args:
        action_queue: ActionQ instance managing the analysis queue
        toolbox: Optional Toolbox class (defaults to imported Toolbox)

    Returns:
        Fully initialized CommandContext with all dependencies

    Raises:
        No exceptions are raised; missing dependencies result in None values
        with appropriate warning logs.
    """
    # Initialize services with graceful fallbacks
    task_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_task_service"]
        ).get_task_service(),
        "TaskService",
    )
    forensic_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_forensic_service"]
        ).get_forensic_service(),
        "ForensicService",
    )
    spotlight_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_spotlight_service"]
        ).get_spotlight_service(),
        "SpotlightService",
    )

    adb = _safe_import(
        lambda: __import__("sandroid.core.adb", fromlist=["Adb"]).Adb,
        "Adb",
    )

    # Get Toolbox class (use provided or import)
    if toolbox is None:
        toolbox = _safe_import(
            lambda: __import__("sandroid.core.toolbox", fromlist=["Toolbox"]).Toolbox,
            "Toolbox",
        )

    # Get UI request bus and determine TUI mode
    ui_bus = None
    is_tui_mode = False
    request_input_func = None
    request_confirm_func = None
    request_selection_func = None

    try:
        from sandroid.core.ui_request_bus import (
            UIRequestBus,
            request_confirm,
            request_input,
            request_selection,
        )

        ui_bus = UIRequestBus.get()
        is_tui_mode = ui_bus.has_active_handler()
        request_input_func = request_input
        request_confirm_func = request_confirm
        request_selection_func = request_selection
    except ImportError as e:
        logger.warning(f"Could not import UIRequestBus: {e}")
    except Exception as e:
        logger.warning(f"Could not initialize UIRequestBus: {e}")

    # Build and return the context
    context = CommandContext(
        task_service=task_service,
        forensic_service=forensic_service,
        spotlight_service=spotlight_service,
        adb=adb,
        toolbox=toolbox,
        ui_bus=ui_bus,
        config=None,
        is_tui_mode=is_tui_mode,
        action_queue=action_queue,
        logger=logging.getLogger(__name__),
        request_input=request_input_func,
        request_confirm=request_confirm_func,
        request_selection=request_selection_func,
    )

    logger.debug(
        f"Created CommandContext: "
        f"task_service={task_service is not None}, "
        f"forensic_service={forensic_service is not None}, "
        f"spotlight_service={spotlight_service is not None}, "
        f"adb={adb is not None}, "
        f"toolbox={toolbox is not None}, "
        f"ui_bus={ui_bus is not None}, "
        f"is_tui_mode={is_tui_mode}"
    )

    return context


def create_minimal_context() -> CommandContext:
    """Create a minimal CommandContext for testing or simple operations.

    This creates a CommandContext with minimal dependencies, useful for:
    - Unit testing command handlers
    - Running commands outside the full application context
    - Simple scripting scenarios

    Returns:
        CommandContext with only essential fields populated
    """
    task_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_task_service"]
        ).get_task_service(),
        "TaskService",
    )
    forensic_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_forensic_service"]
        ).get_forensic_service(),
        "ForensicService",
    )
    spotlight_service = _safe_import(
        lambda: __import__(
            "sandroid.services", fromlist=["get_spotlight_service"]
        ).get_spotlight_service(),
        "SpotlightService",
    )

    return CommandContext(
        task_service=task_service,
        forensic_service=forensic_service,
        spotlight_service=spotlight_service,
        logger=logging.getLogger(__name__),
    )


def create_context_with_toolbox(toolbox: Any) -> CommandContext:
    """Create a CommandContext with only a Toolbox reference.

    This is useful for legacy code that primarily uses Toolbox
    but wants to start using the command pattern.

    Args:
        toolbox: The Toolbox class to use

    Returns:
        CommandContext with toolbox and derived services
    """
    return create_context_from_actionq(action_queue=None, toolbox=toolbox)


__all__ = [
    "create_context_from_actionq",
    "create_context_with_toolbox",
    "create_minimal_context",
]
