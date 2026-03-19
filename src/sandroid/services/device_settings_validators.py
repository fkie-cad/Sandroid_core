"""Validators for device settings dictionaries.

Each validator function checks a specific section of the settings dict
and returns a list of error strings. An empty list means valid.
"""

from __future__ import annotations

from typing import Any


def validate_preset(
    settings: dict[str, Any], valid_presets: frozenset[str] | set[str]
) -> list[str]:
    """Validate the 'preset' key.

    Args:
        settings: Full settings dictionary.
        valid_presets: Set of valid preset key strings.

    Returns:
        List of error strings.
    """
    if "preset" not in settings:
        return []
    preset_val = settings["preset"]
    if not isinstance(preset_val, str):
        return ["preset must be a string"]
    if preset_val not in valid_presets:
        return [
            f"Unknown preset '{preset_val}'. "
            f"Available: {', '.join(sorted(valid_presets))}"
        ]
    return []


def validate_location(settings: dict[str, Any]) -> list[str]:
    """Validate the 'location' key.

    Args:
        settings: Full settings dictionary.

    Returns:
        List of error strings.
    """
    if "location" not in settings:
        return []
    loc = settings["location"]
    if not isinstance(loc, dict):
        return ["location must be a dictionary"]

    errors: list[str] = []
    if "latitude" not in loc or "longitude" not in loc:
        return ["location must have both 'latitude' and 'longitude'"]

    lat = loc["latitude"]
    lon = loc["longitude"]
    if not isinstance(lat, (int, float)):
        errors.append("latitude must be a number")
    elif not -90 <= lat <= 90:
        errors.append(f"latitude {lat} out of range (-90 to 90)")
    if not isinstance(lon, (int, float)):
        errors.append("longitude must be a number")
    elif not -180 <= lon <= 180:
        errors.append(f"longitude {lon} out of range (-180 to 180)")
    return errors


def validate_environment(
    settings: dict[str, Any],
    valid_keys: frozenset[str],
) -> list[str]:
    """Validate the 'environment' key.

    Args:
        settings: Full settings dictionary.
        valid_keys: Set of valid environment sub-keys.

    Returns:
        List of error strings.
    """
    if "environment" not in settings:
        return []
    env = settings["environment"]
    if not isinstance(env, dict):
        return ["environment must be a dictionary"]
    unknown_env = set(env.keys()) - valid_keys
    if unknown_env:
        return [f"Unknown environment keys: {', '.join(sorted(unknown_env))}"]
    return []


def validate_sensors(
    settings: dict[str, Any],
    valid_sensors: dict[str, str],
) -> list[str]:
    """Validate the 'sensors' key.

    Args:
        settings: Full settings dictionary.
        valid_sensors: Mapping of valid sensor names to emulator names.

    Returns:
        List of error strings.
    """
    if "sensors" not in settings:
        return []
    sensors = settings["sensors"]
    if not isinstance(sensors, dict):
        return ["sensors must be a dictionary"]
    errors: list[str] = []
    for name, value in sensors.items():
        if name not in valid_sensors:
            errors.append(
                f"Unknown sensor '{name}'. "
                f"Available: {', '.join(sorted(valid_sensors.keys()))}"
            )
        if not isinstance(value, int):
            errors.append(f"Sensor '{name}' value must be an integer")
        elif not 0 <= value <= 10:
            errors.append(f"Sensor '{name}' value {value} out of range (0-10)")
    return errors


def validate_battery(settings: dict[str, Any]) -> list[str]:
    """Validate the 'battery' key.

    Args:
        settings: Full settings dictionary.

    Returns:
        List of error strings.
    """
    if "battery" not in settings:
        return []
    battery = settings["battery"]
    if not isinstance(battery, int):
        return ["battery must be an integer"]
    if not 0 <= battery <= 100:
        return [f"battery {battery} out of range (0-100)"]
    return []


def validate_network(
    settings: dict[str, Any],
    valid_toggle_keys: frozenset[str],
) -> list[str]:
    """Validate the 'network' key.

    Args:
        settings: Full settings dictionary.
        valid_toggle_keys: Set of valid network toggle keys.

    Returns:
        List of error strings.
    """
    if "network" not in settings:
        return []
    net = settings["network"]
    if not isinstance(net, dict):
        return ["network must be a dictionary"]
    errors: list[str] = []
    unknown_net = set(net.keys()) - valid_toggle_keys
    if unknown_net:
        errors.append(f"Unknown network keys: {', '.join(sorted(unknown_net))}")
    for key, val in net.items():
        if key in valid_toggle_keys and not isinstance(val, bool):
            errors.append(f"network.{key} must be a boolean")
    return errors
