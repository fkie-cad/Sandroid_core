"""Service Registry for centralized service management.

This module provides a ServiceRegistry class for managing service instances
with support for dependency injection and testing.

Usage:
    from sandroid.services import ServiceRegistry

    # Get service by type
    task_service = ServiceRegistry.get(TaskService)

    # Register custom instance (for testing)
    mock_service = Mock(spec=TaskService)
    ServiceRegistry.register(TaskService, mock_service)

    # Reset all services
    ServiceRegistry.reset()
"""

import logging
from collections.abc import Callable
from threading import RLock
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _get_event_bus() -> Any:
    """Get the EventBus singleton.

    Returns:
        EventBus instance.
    """
    from sandroid.core.events import EventBus

    return EventBus.get()


def _create_with_event_bus(service_class: type) -> Any:
    """Create a service instance, injecting EventBus.

    This is the standard factory for services that accept an
    ``event_bus`` keyword argument and require no other dependencies.

    Args:
        service_class: The service class to instantiate.

    Returns:
        Service instance with event_bus injected.
    """
    return service_class(event_bus=_get_event_bus())


class ServiceRegistry:
    """Central registry for all services supporting dependency injection.

    This class provides:
    - Type-safe service lookup
    - Lazy initialization of services
    - Dependency injection support for testing
    - Thread-safe operations

    Example:
        # Production usage - get default singleton
        task_service = ServiceRegistry.get(TaskService)

        # Testing usage - inject mock
        mock_task = Mock(spec=TaskService)
        ServiceRegistry.register(TaskService, mock_task)

        # In tests, always reset after
        ServiceRegistry.reset()
    """

    _instances: dict[type, Any] = {}
    _lock = RLock()  # Re-entrant lock to allow nested get() calls from factories
    _factories: dict[type, Callable[[], Any]] = {}

    @classmethod
    def _register_default_factories(cls) -> None:
        """Register default factory functions for services."""
        if cls._factories:
            return  # Already registered

        # Import here to avoid circular imports
        from .app_selection_service import AppSelectionService
        from .configuration_service import ConfigurationService
        from .emulator_service import EmulatorService
        from .environment_service import EnvironmentService
        from .file_extraction_service import FileExtractionService
        from .forensic_apk_service import ForensicAPKService
        from .forensic_service import ForensicService
        from .frida_session_service import FridaSessionService
        from .initialization_service import InitializationService
        from .network_capture_service import NetworkCaptureService
        from .objection_service import ObjectionService
        from .setup_service import SetupService
        from .spotlight_service import SpotlightService
        from .task_service import TaskService
        from .tool_usage_service import ToolUsageService

        # Services that accept only event_bus (standard pattern)
        standard_services: list[type] = [
            AppSelectionService,
            ConfigurationService,
            EnvironmentService,
            FileExtractionService,
            ForensicAPKService,
            InitializationService,
            NetworkCaptureService,
            ObjectionService,
            SetupService,
            TaskService,
            ToolUsageService,
        ]

        cls._factories = {
            svc: (lambda s=svc: _create_with_event_bus(s)) for svc in standard_services
        }

        # Services with no event_bus parameter
        cls._factories[ForensicService] = ForensicService
        cls._factories[SpotlightService] = SpotlightService

        # Services with extra dependencies
        cls._factories[EmulatorService] = cls._create_emulator_service
        cls._factories[FridaSessionService] = cls._create_frida_session_service

    @classmethod
    def _create_emulator_service(cls) -> Any:
        """Factory for EmulatorService (requires ConfigurationService)."""
        from .configuration_service import ConfigurationService
        from .emulator_service import EmulatorService

        config_service = cls.get(ConfigurationService)
        return EmulatorService(
            config_service=config_service, event_bus=_get_event_bus()
        )

    @classmethod
    def _create_frida_session_service(cls) -> Any:
        """Factory for FridaSessionService (requires SpotlightService)."""
        from .frida_session_service import FridaSessionService
        from .spotlight_service import SpotlightService

        spotlight_service = cls.get(SpotlightService)
        return FridaSessionService(
            event_bus=_get_event_bus(), spotlight_service=spotlight_service
        )

    @classmethod
    def get(cls, service_type: type[T]) -> T:
        """Get a service instance by type.

        If no instance exists, creates one using the registered factory.
        Thread-safe lazy initialization.

        Args:
            service_type: The service class to get

        Returns:
            Service instance of the requested type

        Raises:
            ValueError: If no factory registered for the service type

        Example:
            task_service = ServiceRegistry.get(TaskService)
        """
        with cls._lock:
            if service_type in cls._instances:
                return cls._instances[service_type]

            # Ensure factories are registered
            cls._register_default_factories()

            if service_type not in cls._factories:
                raise ValueError(
                    f"No factory registered for service type: {service_type.__name__}. "
                    f"Available types: {list(cls._factories.keys())}"
                )

            instance = cls._factories[service_type]()
            cls._instances[service_type] = instance
            logger.debug(f"Created service instance: {service_type.__name__}")
            return instance

    @classmethod
    def register(cls, service_type: type[T], instance: T) -> None:
        """Register a service instance (for dependency injection).

        Useful for testing to inject mock services.

        Args:
            service_type: The service class type
            instance: The instance to register

        Example:
            mock_task = Mock(spec=TaskService)
            ServiceRegistry.register(TaskService, mock_task)
        """
        with cls._lock:
            cls._instances[service_type] = instance
            logger.debug(f"Registered custom instance for: {service_type.__name__}")

    @classmethod
    def register_factory(
        cls, service_type: type[T], factory: Callable[[], Any]
    ) -> None:
        """Register a custom factory for a service type.

        Allows overriding the default factory for a service type.

        Args:
            service_type: The service class type
            factory: Callable that creates the service instance

        Example:
            ServiceRegistry.register_factory(
                TaskService,
                lambda: TaskService(event_bus=custom_bus)
            )
        """
        with cls._lock:
            cls._factories[service_type] = factory
            logger.debug(f"Registered custom factory for: {service_type.__name__}")

    @classmethod
    def has(cls, service_type: type) -> bool:
        """Check if a service instance is registered.

        Args:
            service_type: The service class type

        Returns:
            True if an instance exists
        """
        with cls._lock:
            return service_type in cls._instances

    @classmethod
    def reset(cls) -> None:
        """Reset all service instances.

        Clears all cached instances, allowing fresh creation.
        Essential for test isolation.

        Example:
            @pytest.fixture(autouse=True)
            def reset_services():
                yield
                ServiceRegistry.reset()
        """
        with cls._lock:
            cls._instances.clear()
            logger.debug("Service registry reset")

    @classmethod
    def reset_type(cls, service_type: type) -> None:
        """Reset a specific service type.

        Removes just one service instance from the cache.

        Args:
            service_type: The service class type to reset
        """
        with cls._lock:
            if service_type in cls._instances:
                del cls._instances[service_type]
                logger.debug(f"Reset service: {service_type.__name__}")

    @classmethod
    def get_registered_types(cls) -> list[type]:
        """Get list of registered service types.

        Returns:
            List of service types that have instances
        """
        with cls._lock:
            return list(cls._instances.keys())

    @classmethod
    def get_available_types(cls) -> list[type]:
        """Get list of available service types.

        Returns:
            List of service types with registered factories
        """
        cls._register_default_factories()
        with cls._lock:
            return list(cls._factories.keys())


__all__ = ["ServiceRegistry"]
