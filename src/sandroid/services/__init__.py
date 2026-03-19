"""Sandroid Services Layer.

This package contains extracted services from the monolithic Toolbox class,
following SOLID principles and enabling dependency injection, testing, and
API layer support.

Services:
    - TaskService: Background task lifecycle management
    - ForensicService: File tracking, snapshots, baseline management
    - SpotlightService: App selection and monitoring
    - ConfigurationService: Session and path management
    - EmulatorService: Emulator operations (screenshots, recording, snapshots)
    - FridaSessionService: Frida session and job management
    - ObjectionService: Objection security testing sessions
    - DeviceService: Device connection and ADB management
    - UIService: UI notifications, dialogs, and user interaction

Usage:
    from sandroid.services import TaskService, ForensicService

    # Services can be instantiated with dependencies
    task_service = TaskService(event_bus=EventBus.get())
    forensic_service = ForensicService(adb=adb_instance, config=config)

    # Or use the service locator for backwards compatibility
    from sandroid.services import get_task_service
    task_service = get_task_service()

    # Or use the ServiceRegistry for type-safe DI
    from sandroid.services import ServiceRegistry
    task_service = ServiceRegistry.get(TaskService)

    # For testing, inject mocks:
    ServiceRegistry.register(TaskService, mock_task_service)
"""

import threading
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Service singleton registry & factory
# ---------------------------------------------------------------------------

# Maps factory function -> cached instance
_service_instances: dict[Callable, Any] = {}
_service_lock = threading.RLock()


def _get_event_bus() -> Any:
    """Get the EventBus singleton. Always available as a core module."""
    from sandroid.core.events import EventBus

    return EventBus.get()


def _get_or_create(factory: Callable[[], Any]) -> Any:
    """Get a cached service instance, or create it via *factory*.

    Uses the factory function itself as the cache key, eliminating
    fragile hand-typed string keys.  Thread-safe via double-checked
    locking.

    Args:
        factory: Zero-argument callable that creates a *new* service instance.

    Returns:
        The (possibly cached) service instance.
    """
    # Fast path without lock
    instance = _service_instances.get(factory)
    if instance is not None:
        return instance
    with _service_lock:
        # Double-check inside lock
        instance = _service_instances.get(factory)
        if instance is not None:
            return instance
        instance = factory()
        _service_instances[factory] = instance
        return instance


# ---------------------------------------------------------------------------
# Individual factory functions (called lazily by _get_or_create)
# ---------------------------------------------------------------------------


def _create_task_service() -> "TaskService":
    from .task_service import TaskService

    return TaskService(event_bus=_get_event_bus())


def _create_forensic_service() -> "ForensicService":
    from .forensic_service import ForensicService

    return ForensicService()


def _create_spotlight_service() -> "SpotlightService":
    from .spotlight_service import SpotlightService

    return SpotlightService()


def _create_configuration_service() -> "ConfigurationService":
    from .configuration_service import ConfigurationService

    return ConfigurationService(event_bus=_get_event_bus())


def _create_emulator_service() -> "EmulatorService":
    from .emulator_service import EmulatorService

    config_service = get_configuration_service()
    return EmulatorService(config_service=config_service, event_bus=_get_event_bus())


def _create_frida_session_service() -> "FridaSessionService":
    from .frida_session_service import FridaSessionService

    spotlight_service = get_spotlight_service()
    return FridaSessionService(
        event_bus=_get_event_bus(), spotlight_service=spotlight_service
    )


def _create_objection_service() -> "ObjectionService":
    from .objection_service import ObjectionService

    return ObjectionService(event_bus=_get_event_bus())


def _create_device_service() -> "DeviceService":
    from .device_service import DeviceService

    return DeviceService(event_bus=_get_event_bus())


def _create_ui_service() -> "UIService":
    from .ui_service import UIService

    return UIService(event_bus=_get_event_bus())


def _create_environment_service() -> "EnvironmentService":
    from .environment_service import EnvironmentService

    return EnvironmentService(event_bus=_get_event_bus())


def _create_forensic_apk_service() -> "ForensicAPKService":
    from .forensic_apk_service import ForensicAPKService

    return ForensicAPKService(event_bus=_get_event_bus())


def _create_tool_usage_service() -> "ToolUsageService":
    from .tool_usage_service import ToolUsageService

    return ToolUsageService(event_bus=_get_event_bus())


def _create_initialization_service() -> "InitializationService":
    from .initialization_service import InitializationService

    return InitializationService(event_bus=_get_event_bus())


def _create_file_extraction_service() -> "FileExtractionService":
    from .file_extraction_service import FileExtractionService

    return FileExtractionService(event_bus=_get_event_bus())


def _create_network_capture_service() -> "NetworkCaptureService":
    from .network_capture_service import NetworkCaptureService

    return NetworkCaptureService(event_bus=_get_event_bus())


def _create_setup_service() -> "SetupService":
    from .setup_service import SetupService

    return SetupService(event_bus=_get_event_bus())


def _create_app_selection_service() -> "AppSelectionService":
    from .app_selection_service import AppSelectionService

    return AppSelectionService(event_bus=_get_event_bus())


def _create_proxy_service() -> "ProxyService":
    from .proxy_service import ProxyService

    setup_service = get_setup_service()
    return ProxyService(setup_service=setup_service, event_bus=_get_event_bus())


def _create_action_window_service() -> "ActionWindowService":
    from .action_window_service import ActionWindowService

    return ActionWindowService()


def _create_session_state_service() -> "SessionStateService":
    from .session_state_service import SessionStateService

    return SessionStateService()


def _create_trigdroid_config_service() -> "TrigDroidConfigService":
    from .trigdroid_config_service import TrigDroidConfigService

    return TrigDroidConfigService()


def _create_device_settings_service() -> "DeviceSettingsService":
    from .device_settings_service import DeviceSettingsService

    return DeviceSettingsService()


# ---------------------------------------------------------------------------
# Public getter functions (thin wrappers for backwards compatibility)
# ---------------------------------------------------------------------------


def get_task_service() -> "TaskService":
    """Get or create the TaskService singleton."""
    return _get_or_create(_create_task_service)


def get_forensic_service() -> "ForensicService":
    """Get or create the ForensicService singleton."""
    return _get_or_create(_create_forensic_service)


def get_spotlight_service() -> "SpotlightService":
    """Get or create the SpotlightService singleton."""
    return _get_or_create(_create_spotlight_service)


def get_configuration_service() -> "ConfigurationService":
    """Get or create the ConfigurationService singleton."""
    return _get_or_create(_create_configuration_service)


def get_emulator_service() -> "EmulatorService":
    """Get or create the EmulatorService singleton."""
    return _get_or_create(_create_emulator_service)


def get_frida_session_service() -> "FridaSessionService":
    """Get or create the FridaSessionService singleton."""
    return _get_or_create(_create_frida_session_service)


def get_objection_service() -> "ObjectionService":
    """Get or create the ObjectionService singleton."""
    return _get_or_create(_create_objection_service)


def get_device_service() -> "DeviceService":
    """Get or create the DeviceService singleton."""
    return _get_or_create(_create_device_service)


def get_ui_service() -> "UIService":
    """Get or create the UIService singleton."""
    return _get_or_create(_create_ui_service)


def get_environment_service() -> "EnvironmentService":
    """Get or create the EnvironmentService singleton."""
    return _get_or_create(_create_environment_service)


def get_forensic_apk_service() -> "ForensicAPKService":
    """Get or create the ForensicAPKService singleton."""
    return _get_or_create(_create_forensic_apk_service)


def get_tool_usage_service() -> "ToolUsageService":
    """Get or create the ToolUsageService singleton."""
    return _get_or_create(_create_tool_usage_service)


def get_initialization_service() -> "InitializationService":
    """Get or create the InitializationService singleton."""
    return _get_or_create(_create_initialization_service)


def get_file_extraction_service() -> "FileExtractionService":
    """Get or create the FileExtractionService singleton."""
    return _get_or_create(_create_file_extraction_service)


def get_network_capture_service() -> "NetworkCaptureService":
    """Get or create the NetworkCaptureService singleton."""
    return _get_or_create(_create_network_capture_service)


def get_setup_service() -> "SetupService":
    """Get or create the SetupService singleton."""
    return _get_or_create(_create_setup_service)


def get_app_selection_service() -> "AppSelectionService":
    """Get or create the AppSelectionService singleton."""
    return _get_or_create(_create_app_selection_service)


def get_proxy_service() -> "ProxyService":
    """Get or create the ProxyService singleton."""
    return _get_or_create(_create_proxy_service)


def get_action_window_service() -> "ActionWindowService":
    """Get or create the ActionWindowService singleton."""
    return _get_or_create(_create_action_window_service)


def get_session_state_service() -> "SessionStateService":
    """Get or create the SessionStateService singleton."""
    return _get_or_create(_create_session_state_service)


def get_trigdroid_config_service() -> "TrigDroidConfigService":
    """Get or create the TrigDroidConfigService singleton."""
    return _get_or_create(_create_trigdroid_config_service)


def get_device_settings_service() -> "DeviceSettingsService":
    """Get or create the DeviceSettingsService singleton."""
    return _get_or_create(_create_device_settings_service)


def reset_services() -> None:
    """Reset all service singletons (useful for testing).

    Clears all cached service instances, allowing them to be
    re-created on next access.  Acquires the service lock to
    avoid racing with concurrent ``_get_or_create`` calls.
    """
    with _service_lock:
        _service_instances.clear()


# ---------------------------------------------------------------------------
# Direct imports for convenience
# ---------------------------------------------------------------------------
from .action_window_service import ActionWindowService
from .app_selection_service import AppSelectionService, PackageInfo, SelectionResult
from .configuration_service import ConfigurationService, SessionConfig
from .device_service import DeviceService, DeviceState
from .device_settings_service import DevicePreset, DeviceSettingsService, SettingsResult
from .emulator_service import EmulatorService, ScreenRecordingState, SnapshotInfo
from .environment_service import EnvironmentService, SetupResult
from .file_extraction_service import ExtractionResult, FileExtractionService
from .forensic_apk_service import ForensicAPK, ForensicAPKService
from .forensic_service import ForensicService, Snapshot, TimelineEntry
from .forensic_service_types import AdbProtocol
from .forensic_timeline import ForensicTimeline
from .frida_session_service import FridaJobInfo, FridaSessionService
from .initialization_service import (
    FolderStructure,
    InitializationResult,
    InitializationService,
    SessionPaths,
)
from .network_capture_service import CaptureSession, NetworkCaptureService
from .objection_service import ObjectionService
from .output_buffer_service import OutputBufferService
from .proxy_service import ProxyService, ProxySettings
from .renderers import BoxRenderer, EmulatorInfoRenderer, ExitSummaryRenderer
from .service_registry import ServiceRegistry
from .session_state_service import SessionStateService
from .setup_service import SetupCheckResult, SetupCheckStatus, SetupService
from .setup_service import SetupResult as SetupServiceResult
from .spotlight_service import SpotlightApp, SpotlightService
from .task_service import BackgroundTask, TaskService
from .tool_usage_service import ToolUsage, ToolUsageService
from .trigdroid_config_service import TrigDroidConfigService
from .ui_service import OutputLine, UIService
from .ui_service import (
    ToolUsage as UIToolUsage,  # Distinct from tool_usage_service.ToolUsage
)

__all__ = [
    "ActionWindowService",
    "AdbProtocol",
    "AppSelectionService",
    "BackgroundTask",
    "BoxRenderer",
    "CaptureSession",
    "ConfigurationService",
    "DevicePreset",
    "DeviceService",
    "DeviceSettingsService",
    "DeviceState",
    "EmulatorInfoRenderer",
    "EmulatorService",
    "EnvironmentService",
    "ExitSummaryRenderer",
    "ExtractionResult",
    "FileExtractionService",
    "FolderStructure",
    "ForensicAPK",
    "ForensicAPKService",
    "ForensicService",
    "ForensicTimeline",
    "FridaJobInfo",
    "FridaSessionService",
    "InitializationResult",
    "InitializationService",
    "NetworkCaptureService",
    "ObjectionService",
    # Extracted modules
    "OutputBufferService",
    "OutputLine",
    "PackageInfo",
    "ProxyService",
    "ProxySettings",
    "ScreenRecordingState",
    "SelectionResult",
    # Service Registry
    "ServiceRegistry",
    "SessionConfig",
    "SessionPaths",
    "SessionStateService",
    "SettingsResult",
    "SetupCheckResult",
    "SetupCheckStatus",
    "SetupResult",
    "SetupService",
    "SetupServiceResult",
    "Snapshot",
    "SnapshotInfo",
    "SpotlightApp",
    "SpotlightService",
    # Service classes
    "TaskService",
    "TimelineEntry",
    "ToolUsage",
    "ToolUsageService",
    "TrigDroidConfigService",
    "UIService",
    "UIToolUsage",
    "get_action_window_service",
    "get_app_selection_service",
    "get_configuration_service",
    "get_device_service",
    "get_device_settings_service",
    "get_emulator_service",
    "get_environment_service",
    "get_file_extraction_service",
    "get_forensic_apk_service",
    "get_forensic_service",
    "get_frida_session_service",
    "get_initialization_service",
    "get_network_capture_service",
    "get_objection_service",
    "get_proxy_service",
    "get_session_state_service",
    "get_setup_service",
    "get_spotlight_service",
    # Service getters
    "get_task_service",
    "get_tool_usage_service",
    "get_trigdroid_config_service",
    "get_ui_service",
    "reset_services",
]
