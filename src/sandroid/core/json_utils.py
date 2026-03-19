"""Shared JSON encoding utilities for Sandroid.

Provides a custom encoder function for serializing complex Python objects
(Pydantic models, dataclasses, datetime, bytes, sets) to JSON.

Usage:
    import json
    from sandroid.core.json_utils import json_encoder

    json.dump(data, f, indent=2, default=json_encoder)
"""

from dataclasses import asdict, is_dataclass


def json_encoder(obj):
    """Custom JSON encoder for non-serializable objects.

    Handles Pydantic models (v1/v2), dataclasses, objects with ``__dict__``,
    datetime-like objects, bytes, and sets.  Falls back to ``str(obj)``
    for anything else.

    Args:
        obj: The object to serialize.

    Returns:
        A JSON-serializable representation of *obj*.
    """
    # Handle Pydantic models (v2)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    # Handle Pydantic models (v1)
    if hasattr(obj, "dict"):
        return obj.dict()
    # Handle dataclasses
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    # Handle objects with __dict__
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    # Handle datetime
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    # Handle bytes
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    # Handle sets
    if isinstance(obj, set):
        return list(obj)
    # Fallback to string representation
    return str(obj)
