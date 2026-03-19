"""Core data models and property descriptors for Sandroid.

This module contains:
- BackgroundTask and ForensicAPK dataclasses (moved from toolbox.py)
- ServiceProperty descriptor for metaclass-level property delegation

The dataclasses are the canonical definitions used by Toolbox; the service
layer has its own copies for independence, but Toolbox re-exports these for
backwards compatibility.
"""

import datetime
import functools
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class BackgroundTask:
    """Represents a running background task."""

    name: str  # e.g., "fritap", "dexray-intercept", "network"
    display_name: str  # e.g., "FriTap", "Dexray-Intercept"
    instance: object  # The actual tool instance
    stop_callback: Callable  # Function to call when stopping
    started_at: datetime.datetime  # When the task started
    started_by: str | None = None  # Which task started this one (for dependencies)
    app_name: str | None = None  # Target application package name (if applicable)
    target_pid: int | None = None  # Target process PID (if applicable)


@dataclass
class ForensicAPK:
    """Represents a forensic evidence APK pulled from a device.

    These are APKs that matched IOC indicators during forensic scanning
    and were pulled for further analysis or installation to an emulator.
    """

    package_name: str  # e.g., "com.suspicious.app"
    source_device: str  # Device serial it was pulled from
    source_device_name: str  # Display name of source device
    local_path: str  # Local filesystem path to the APK
    pull_timestamp: datetime.datetime  # When the APK was pulled
    ioc_matches: list  # List of IOC indicator values that matched
    severity: str  # Highest severity: "critical", "high", "medium", "low"
    file_hash: str = ""  # MD5 hash of APK file


class ServiceProperty:
    """Descriptor that delegates Toolbox class-attribute access to a service.

    This replaces the repetitive @property getter/setter pairs in _ToolboxMeta.
    Each instance maps a Toolbox attribute to a service getter function and an
    attribute (or getter/setter method pair) on that service.

    Because Toolbox uses a metaclass so that ``Toolbox.attr`` works at the
    *class* level, this descriptor must live on the **metaclass**, not on
    Toolbox itself.  _ToolboxMeta is built dynamically from
    ``_SERVICE_PROPERTY_TABLE`` at module load time.

    Args:
        service_getter_name: Importable function name in ``sandroid.services``
            (e.g., ``"get_session_state_service"``).
        attr_name: Attribute name on the service object for simple read/write.
            Mutually exclusive with ``getter_name``/``setter_name``.
        getter_name: Method name on the service to call for reads.
        setter_name: Method name on the service to call for writes.
            If *setter_name* is a plain attribute name starting with ``_``,
            a direct ``setattr`` is used instead of a method call.
    """

    def __init__(
        self,
        service_getter_name: str,
        attr_name: str | None = None,
        getter_name: str | None = None,
        setter_name: str | None = None,
    ) -> None:
        if attr_name and (getter_name or setter_name):
            raise ValueError(
                "Specify either attr_name OR getter_name/setter_name, not both."
            )
        self.service_getter_name = service_getter_name
        self.attr_name = attr_name
        self.getter_name = getter_name
        self.setter_name = setter_name

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    def _get_service(self, obj: Any) -> Any:
        """Lazily import and call the service getter."""
        from sandroid import services as svc_module

        getter_fn = getattr(svc_module, self.service_getter_name)
        return getter_fn()

    def __get__(self, obj: Any, objtype: type | None = None) -> Any:
        if obj is None:
            # Accessed on the metaclass instance (i.e. the Toolbox *class*).
            # ``obj`` is the class itself when the descriptor lives on the metaclass.
            # We still need to resolve; fall through using objtype is not needed here
            # because Python calls __get__ on the metaclass descriptor with
            # obj = <the class>, objtype = <the metaclass>.
            pass
        service = self._get_service(obj)
        if self.attr_name is not None:
            return getattr(service, self.attr_name)
        if self.getter_name is not None:
            return getattr(service, self.getter_name)()
        raise AttributeError(f"ServiceProperty {self.name!r} has no getter configured.")

    def __set__(self, obj: Any, value: Any) -> None:
        service = self._get_service(obj)
        if self.attr_name is not None:
            setattr(service, self.attr_name, value)
            return
        if self.setter_name is not None:
            # If setter_name starts with "_", treat as direct attribute write
            # (e.g., ``_spawn_mode`` on SpotlightService).
            target = getattr(service, self.setter_name, None)
            if callable(target):
                target(value)
            else:
                setattr(service, self.setter_name, value)
            return
        raise AttributeError(f"ServiceProperty {self.name!r} has no setter configured.")


def deprecated_method(replacement: str):
    """Decorator that adds a DeprecationWarning to a classmethod body.

    Usage::

        @deprecated_method("get_ui_service().get_current_view()")
        def get_current_view(cls):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                f"{func.__qualname__} is deprecated, use {replacement} instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            return func(*args, **kwargs)

        return wrapper

    return decorator
