"""Device settings service for managing device environment configuration.

Provides methods to configure GPS location, timezone, locale, telephony,
sensors, network toggles, and battery level on Android devices/emulators.
Supports country presets for quick environment setup.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DevicePreset:
    """Country preset for device environment configuration.

    Attributes:
        name: Human-readable name (e.g., "Germany (Berlin)")
        country_code: ISO country code (e.g., "de")
        latitude: Default latitude for the country
        longitude: Default longitude for the country
        timezone: Timezone string (e.g., "Europe/Berlin")
        language: Language code (e.g., "de")
        telephony_mnc: Mobile Network Code (e.g., "26201")
    """

    name: str
    country_code: str
    latitude: float
    longitude: float
    timezone: str
    language: str
    telephony_mnc: str

    @property
    def country(self) -> str:
        """Country code uppercase (derived from country_code)."""
        return self.country_code.upper()


@dataclass
class SettingsResult:
    """Result of a device settings operation.

    Attributes:
        success: Whether the operation succeeded
        message: Human-readable result message
        error: Error details if failed
    """

    success: bool
    message: str = ""
    error: str | None = None

    @staticmethod
    def from_operation(
        operation: Callable[[], tuple[str, str]],
        success_msg: str,
        error_label: str,
        log_msg: str | None = None,
    ) -> "SettingsResult":
        """Run an ADB-style operation and return a SettingsResult.

        Handles the common try/except + stderr-check pattern used by most
        ADB methods in this module.

        Args:
            operation: Callable returning (stdout, stderr).
            success_msg: Message for the successful result.
            error_label: Label used in the failure message and log.
            log_msg: Optional info-level log message on success.

        Returns:
            SettingsResult with success/failure status.
        """
        try:
            _stdout, stderr = operation()
            if stderr and "error" in stderr.lower():
                return SettingsResult(
                    success=False,
                    message=f"Failed to {error_label}",
                    error=stderr,
                )
            if log_msg:
                logger.info(log_msg)
            return SettingsResult(success=True, message=success_msg)
        except Exception as e:
            logger.error(f"Failed to {error_label}: {e}")
            return SettingsResult(
                success=False,
                message=f"{error_label} error",
                error=str(e),
            )


COUNTRY_PRESETS: dict[str, DevicePreset] = {
    "ru": DevicePreset(
        name="Russia (Moscow)",
        country_code="ru",
        latitude=55.7558,
        longitude=37.6176,
        timezone="Europe/Moscow",
        language="ru",
        telephony_mnc="25001",
    ),
    "de": DevicePreset(
        name="Germany (Berlin)",
        country_code="de",
        latitude=52.52,
        longitude=13.405,
        timezone="Europe/Berlin",
        language="de",
        telephony_mnc="26201",
    ),
    "us": DevicePreset(
        name="United States (New York)",
        country_code="us",
        latitude=40.7128,
        longitude=-74.006,
        timezone="America/New_York",
        language="en",
        telephony_mnc="310030",
    ),
    "cn": DevicePreset(
        name="China (Beijing)",
        country_code="cn",
        latitude=39.9042,
        longitude=116.4074,
        timezone="Asia/Shanghai",
        language="zh",
        telephony_mnc="46000",
    ),
    "ir": DevicePreset(
        name="Iran (Tehran)",
        country_code="ir",
        latitude=35.6892,
        longitude=51.389,
        timezone="Asia/Tehran",
        language="fa",
        telephony_mnc="43211",
    ),
    "kp": DevicePreset(
        name="North Korea (Pyongyang)",
        country_code="kp",
        latitude=39.0392,
        longitude=125.7625,
        timezone="Asia/Pyongyang",
        language="ko",
        telephony_mnc="46705",
    ),
    "jp": DevicePreset(
        name="Japan (Tokyo)",
        country_code="jp",
        latitude=35.6762,
        longitude=139.6503,
        timezone="Asia/Tokyo",
        language="ja",
        telephony_mnc="44010",
    ),
    "kr": DevicePreset(
        name="South Korea (Seoul)",
        country_code="kr",
        latitude=37.5665,
        longitude=126.978,
        timezone="Asia/Seoul",
        language="ko",
        telephony_mnc="45005",
    ),
    "gb": DevicePreset(
        name="United Kingdom (London)",
        country_code="gb",
        latitude=51.5074,
        longitude=-0.1278,
        timezone="Europe/London",
        language="en",
        telephony_mnc="23410",
    ),
    "fr": DevicePreset(
        name="France (Paris)",
        country_code="fr",
        latitude=48.8566,
        longitude=2.3522,
        timezone="Europe/Paris",
        language="fr",
        telephony_mnc="20801",
    ),
    "br": DevicePreset(
        name="Brazil (Sao Paulo)",
        country_code="br",
        latitude=-23.5505,
        longitude=-46.6333,
        timezone="America/Sao_Paulo",
        language="pt",
        telephony_mnc="72407",
    ),
    "in": DevicePreset(
        name="India (New Delhi)",
        country_code="in",
        latitude=28.6139,
        longitude=77.209,
        timezone="Asia/Kolkata",
        language="hi",
        telephony_mnc="40445",
    ),
}

# Sensor name mapping: user-friendly name -> emulator sensor name
SENSOR_MAP: dict[str, str] = {
    "accelerometer": "acceleration",
    "gyroscope": "gyroscope",
    "light": "light",
    "pressure": "pressure",
}

# Sensors that use 3-axis vector values (x:y:z format)
VECTOR_SENSORS: frozenset[str] = frozenset({"acceleration", "gyroscope"})

# Default sensor values for reset
SENSOR_DEFAULTS: dict[str, str] = {
    "acceleration": "0:9.77622:0.813417",
    "gyroscope": "0:0:0",
    "light": "0",
    "pressure": "0",
}


VALID_SETTINGS_KEYS: frozenset[str] = frozenset(
    {"preset", "location", "environment", "sensors", "battery", "network"}
)

NETWORK_TOGGLE_KEYS: frozenset[str] = frozenset({"wifi", "mobile_data", "bluetooth"})

VALID_ENVIRONMENT_KEYS: frozenset[str] = frozenset(
    {"timezone", "language", "country", "telephony_iso", "telephony_mnc"}
)


def validate_settings_dict(settings: dict) -> list[str]:
    """Validate a device settings dictionary.

    Checks structure, key names, value types and ranges for all supported
    settings categories. Delegates to focused validators in
    :mod:`device_settings_validators`.

    Args:
        settings: Dictionary of device settings to validate.

    Returns:
        List of error strings. Empty list means valid.
    """
    from .device_settings_validators import (
        validate_battery,
        validate_environment,
        validate_location,
        validate_network,
        validate_preset,
        validate_sensors,
    )

    if not isinstance(settings, dict):
        return ["Settings must be a dictionary"]

    errors: list[str] = []

    # Check for unknown top-level keys
    unknown = set(settings.keys()) - VALID_SETTINGS_KEYS
    if unknown:
        errors.append(f"Unknown keys: {', '.join(sorted(unknown))}")

    errors.extend(validate_preset(settings, set(COUNTRY_PRESETS.keys())))
    errors.extend(validate_location(settings))
    errors.extend(validate_environment(settings, VALID_ENVIRONMENT_KEYS))
    errors.extend(validate_sensors(settings, SENSOR_MAP))
    errors.extend(validate_battery(settings))
    errors.extend(validate_network(settings, NETWORK_TOGGLE_KEYS))

    return errors


def _resolve_preset_field(
    env: dict[str, Any],
    env_key: str,
    preset: DevicePreset | None,
    preset_attr: str,
    default: str,
) -> str:
    """Resolve an environment field, falling back to a preset attribute.

    Args:
        env: The environment sub-dictionary from settings.
        env_key: Key to look up in *env*.
        preset: Optional DevicePreset to derive the fallback from.
        preset_attr: Attribute name on DevicePreset for the fallback.
        default: Hard-coded default when neither env nor preset has a value.

    Returns:
        Resolved string value.
    """
    if env_key in env:
        return env[env_key]
    if preset is not None:
        return getattr(preset, preset_attr)
    return default


class DeviceSettingsService:
    """Service for configuring device environment settings.

    Manages GPS location, timezone, locale, telephony properties,
    sensor values, network toggles, and battery level. Supports
    country presets for quick environment configuration.

    Uses TrigDroid TriggerExecutor when available, falls back to
    direct ADB commands.
    """

    def __init__(self) -> None:
        """Initialize the DeviceSettingsService."""
        self._trigger_executor = None
        self._root_available: bool | None = None
        self._geopy_available: bool | None = None
        self._try_init_trigger_executor()

    def _try_init_trigger_executor(self) -> None:
        """Try to initialize TrigDroid TriggerExecutor if available."""
        try:
            from trigdroid.api.trigger_executor import TriggerExecutor

            self._trigger_executor = TriggerExecutor()
            logger.debug("TrigDroid TriggerExecutor available")
        except ImportError:
            logger.debug("TrigDroid not installed, using direct ADB fallback")
            self._trigger_executor = None

    def _get_adb(self) -> type:
        """Get ADB class (lazy import)."""
        from sandroid.core.adb import Adb

        return Adb

    def _try_trigdroid_then_adb(
        self,
        trigdroid_call: Callable[[], Any] | None,
        adb_fallback: Callable[[], SettingsResult],
        success_msg: str,
        error_label: str,
    ) -> SettingsResult:
        """Try TrigDroid first, then fall back to ADB.

        Args:
            trigdroid_call: Callable that invokes TrigDroid (None to skip).
            adb_fallback: Callable that performs the ADB fallback.
            success_msg: Message to return on TrigDroid success.
            error_label: Label for error logging.

        Returns:
            SettingsResult from TrigDroid or ADB fallback.
        """
        if self._trigger_executor and trigdroid_call is not None:
            try:
                result = trigdroid_call()
                if result.success:
                    return SettingsResult(success=True, message=success_msg)
            except Exception as e:
                logger.debug(f"TrigDroid {error_label} failed, using ADB fallback: {e}")

        try:
            return adb_fallback()
        except Exception as e:
            logger.error(f"Failed {error_label}: {e}")
            return SettingsResult(
                success=False, message=f"{error_label} error", error=str(e)
            )

    # ── Location ────────────────────────────────────────────────────

    def set_gps_location(self, lat: float, lon: float) -> SettingsResult:
        """Set GPS location on the emulator.

        Args:
            lat: Latitude coordinate
            lon: Longitude coordinate

        Returns:
            SettingsResult with success/failure status
        """
        Adb = self._get_adb()
        return SettingsResult.from_operation(
            operation=lambda: Adb.set_geo_fix(lon, lat),
            success_msg=f"GPS set to {lat}, {lon}",
            error_label="set GPS location",
            log_msg=f"GPS location set to {lat}, {lon}",
        )

    def geocode_location(self, country: str, city: str) -> tuple[float, float] | None:
        """Geocode a city/country to coordinates.

        Requires geopy to be installed. Returns None if geopy is
        not available or geocoding fails.

        Args:
            country: Country name or code
            city: City name

        Returns:
            Tuple of (latitude, longitude) or None if unavailable
        """
        try:
            import ssl

            import certifi
            from geopy.geocoders import Nominatim

            ctx = ssl.create_default_context(cafile=certifi.where())
            geolocator = Nominatim(
                user_agent="sandroid_device_settings", ssl_context=ctx
            )
            location = geolocator.geocode(f"{city}, {country}")
            if location:
                return (location.latitude, location.longitude)
            return None
        except ImportError:
            logger.debug("geopy not installed, geocoding unavailable")
            return None
        except Exception as e:
            logger.warning(f"Geocoding failed: {e}")
            return None

    # ── Environment ─────────────────────────────────────────────────

    def set_timezone(self, tz: str) -> SettingsResult:
        """Set device timezone. Requires root.

        Args:
            tz: Timezone string (e.g., "Europe/Berlin")

        Returns:
            SettingsResult with success/failure status
        """
        Adb = self._get_adb()
        return SettingsResult.from_operation(
            operation=lambda: Adb.send_root_shell(
                f'setprop persist.sys.timezone "{tz}"'
            ),
            success_msg=f"Timezone set to {tz}",
            error_label="set timezone",
            log_msg=f"Timezone set to {tz}",
        )

    def set_locale(self, language: str, country: str) -> SettingsResult:
        """Set device locale. Requires root. Restarts runtime.

        Args:
            language: Language code (e.g., "de")
            country: Country code (e.g., "DE")

        Returns:
            SettingsResult with success/failure status
        """
        try:
            Adb = self._get_adb()
            commands = [
                f"setprop persist.sys.language {language}",
                f"setprop persist.sys.country {country}",
                "stop",
                "start",
            ]
            for cmd in commands:
                _stdout, stderr = Adb.send_root_shell(cmd)
                if stderr and "error" in stderr.lower():
                    return SettingsResult(
                        success=False,
                        message=f"Failed to set locale at: {cmd}",
                        error=stderr,
                    )
            logger.info(f"Locale set to {language}_{country}")
            return SettingsResult(
                success=True, message=f"Locale set to {language}_{country}"
            )
        except Exception as e:
            logger.error(f"Failed to set locale: {e}")
            return SettingsResult(success=False, message="Locale error", error=str(e))

    def set_telephony(self, iso_country: str, mnc: str) -> SettingsResult:
        """Set telephony properties. Requires root.

        Uses a single batched shell command for all properties.

        Args:
            iso_country: ISO country code for telephony (e.g., "de")
            mnc: Mobile Network Code (e.g., "26201")

        Returns:
            SettingsResult with success/failure status
        """
        Adb = self._get_adb()
        props = {
            "gsm.sim.operator.iso-country": iso_country,
            "gsm.operator.iso-country": iso_country,
            "gsm.sim.operator.numeric": mnc,
            "gsm.operator.numeric": mnc,
        }
        cmd = " && ".join(f"setprop {key} {val}" for key, val in props.items())
        return SettingsResult.from_operation(
            operation=lambda: Adb.send_root_shell(f"sh -c '{cmd}'"),
            success_msg=f"Telephony set to {iso_country}/{mnc}",
            error_label="set telephony properties",
            log_msg=f"Telephony set to {iso_country}/{mnc}",
        )

    # ── Presets ──────────────────────────────────────────────────────

    def apply_preset(self, preset_key: str) -> SettingsResult:
        """Apply a country preset (location + environment settings).

        Args:
            preset_key: Country code key (e.g., "de", "us")

        Returns:
            SettingsResult with combined status
        """
        preset = COUNTRY_PRESETS.get(preset_key)
        if not preset:
            return SettingsResult(
                success=False,
                message=f"Unknown preset: {preset_key}",
                error=f"Available presets: {', '.join(COUNTRY_PRESETS.keys())}",
            )

        results: list[SettingsResult] = []
        results.append(self.set_gps_location(preset.latitude, preset.longitude))
        results.append(self.set_timezone(preset.timezone))
        results.append(self.set_locale(preset.language, preset.country))
        results.append(self.set_telephony(preset.country_code, preset.telephony_mnc))

        failed = [r for r in results if not r.success]
        if failed:
            errors = "; ".join(r.message for r in failed)
            return SettingsResult(
                success=False,
                message=f"Preset {preset.name} partially applied: {errors}",
                error=errors,
            )

        logger.info(f"Preset {preset.name} applied successfully")
        return SettingsResult(success=True, message=f"Preset {preset.name} applied")

    def apply_settings_dict(self, settings: dict) -> list[SettingsResult]:
        """Apply device settings from a dictionary.

        Applies settings in order: preset first (if present), then location,
        environment, sensors, battery, network. Only applies keys that are
        present in the dictionary, supporting partial settings.

        Args:
            settings: Validated settings dictionary. Call
                ``validate_settings_dict()`` before this method.

        Returns:
            List of SettingsResult for each applied operation.
        """
        results: list[SettingsResult] = []

        # 1. Preset (applied first so explicit fields can override)
        if "preset" in settings:
            results.append(self.apply_preset(settings["preset"]))

        # 2. Location
        if "location" in settings:
            loc = settings["location"]
            results.append(self.set_gps_location(loc["latitude"], loc["longitude"]))

        # 3. Environment
        if "environment" in settings:
            env = settings["environment"]
            preset_obj = COUNTRY_PRESETS.get(settings.get("preset", ""))
            if "timezone" in env:
                results.append(self.set_timezone(env["timezone"]))
            if "language" in env or "country" in env:
                lang = _resolve_preset_field(
                    env, "language", preset_obj, "language", "en"
                )
                country = _resolve_preset_field(
                    env, "country", preset_obj, "country", "US"
                )
                results.append(self.set_locale(lang, country))
            if "telephony_iso" in env or "telephony_mnc" in env:
                iso = _resolve_preset_field(
                    env, "telephony_iso", preset_obj, "country_code", "us"
                )
                mnc = _resolve_preset_field(
                    env, "telephony_mnc", preset_obj, "telephony_mnc", "310030"
                )
                results.append(self.set_telephony(iso, mnc))

        # 4. Sensors
        if "sensors" in settings:
            for sensor_name, level in settings["sensors"].items():
                results.append(self.set_sensor(sensor_name, level))

        # 5. Battery
        if "battery" in settings:
            results.append(self.set_battery_level(settings["battery"]))

        # 6. Network
        if "network" in settings:
            net = settings["network"]
            if "wifi" in net:
                results.append(self.toggle_wifi(net["wifi"]))
            if "mobile_data" in net:
                results.append(self.toggle_mobile_data(net["mobile_data"]))
            if "bluetooth" in net:
                results.append(self.toggle_bluetooth(net["bluetooth"]))

        return results

    def get_presets(self) -> dict[str, DevicePreset]:
        """Get all available country presets.

        Returns:
            Dictionary of preset key -> DevicePreset
        """
        return COUNTRY_PRESETS

    # ── Sensors ─────────────────────────────────────────────────────

    def set_sensor(self, sensor_type: str, level: int) -> SettingsResult:
        """Set a sensor value on the emulator.

        Args:
            sensor_type: Sensor type (accelerometer, gyroscope, light, pressure)
            level: Sensor level (0-10)

        Returns:
            SettingsResult with success/failure status
        """
        sensor_name = SENSOR_MAP.get(sensor_type)
        if not sensor_name:
            return SettingsResult(
                success=False,
                message=f"Unknown sensor: {sensor_type}",
                error=f"Available sensors: {', '.join(SENSOR_MAP.keys())}",
            )

        # Convert level to sensor-specific values
        if sensor_name in VECTOR_SENSORS:
            values = f"{level}:{level}:{level}"
        else:
            values = str(level)

        def trigdroid_call() -> Any:
            return self._trigger_executor.set_sensor(sensor_type, level)

        def adb_fallback() -> SettingsResult:
            Adb = self._get_adb()
            _stdout, stderr = Adb.set_sensor_value(sensor_name, values)
            if stderr and "error" in stderr.lower():
                return SettingsResult(
                    success=False,
                    message=f"Failed to set {sensor_type}",
                    error=stderr,
                )
            logger.info(f"Sensor {sensor_type} set to {level}")
            return SettingsResult(success=True, message=f"{sensor_type} set to {level}")

        return self._try_trigdroid_then_adb(
            trigdroid_call=trigdroid_call,
            adb_fallback=adb_fallback,
            success_msg=f"{sensor_type} set to {level}",
            error_label=f"to set sensor {sensor_type}",
        )

    def reset_sensors(self) -> SettingsResult:
        """Reset all sensors to default values.

        Returns:
            SettingsResult with success/failure status
        """

        def trigdroid_call() -> Any:
            return self._trigger_executor.reset_sensors()

        def adb_fallback() -> SettingsResult:
            Adb = self._get_adb()
            for sensor_name, default_val in SENSOR_DEFAULTS.items():
                Adb.set_sensor_value(sensor_name, default_val)
            logger.info("All sensors reset to defaults")
            return SettingsResult(success=True, message="Sensors reset to defaults")

        return self._try_trigdroid_then_adb(
            trigdroid_call=trigdroid_call,
            adb_fallback=adb_fallback,
            success_msg="Sensors reset to defaults",
            error_label="to reset sensors",
        )

    # ── Network ─────────────────────────────────────────────────────

    def _toggle_service(
        self,
        service_name: str,
        svc_command: str,
        trigdroid_method: str,
        enabled: bool,
    ) -> SettingsResult:
        """Toggle a network service on/off.

        Tries TrigDroid first, then falls back to ADB svc command.

        Args:
            service_name: Human-readable name (e.g., "WiFi")
            svc_command: ADB svc command name (e.g., "wifi")
            trigdroid_method: TriggerExecutor method name (e.g., "toggle_wifi")
            enabled: True to enable, False to disable

        Returns:
            SettingsResult with success/failure status
        """
        state = "enabled" if enabled else "disabled"
        action = "enable" if enabled else "disable"

        def trigdroid_call() -> Any:
            method = getattr(self._trigger_executor, trigdroid_method)
            return method(enabled)

        def adb_fallback() -> SettingsResult:
            Adb = self._get_adb()
            _stdout, stderr = Adb.send_adb_command(f"shell svc {svc_command} {action}")
            if stderr and "error" in stderr.lower():
                return SettingsResult(
                    success=False,
                    message=f"Failed to {action} {service_name}",
                    error=stderr,
                )
            logger.info(f"{service_name} {state}")
            return SettingsResult(success=True, message=f"{service_name} {state}")

        return self._try_trigdroid_then_adb(
            trigdroid_call=trigdroid_call,
            adb_fallback=adb_fallback,
            success_msg=f"{service_name} {state}",
            error_label=f"to toggle {service_name}",
        )

    def toggle_wifi(self, enabled: bool) -> SettingsResult:
        """Toggle WiFi on/off.

        Args:
            enabled: True to enable, False to disable

        Returns:
            SettingsResult with success/failure status
        """
        return self._toggle_service("WiFi", "wifi", "toggle_wifi", enabled)

    def toggle_mobile_data(self, enabled: bool) -> SettingsResult:
        """Toggle mobile data on/off.

        Args:
            enabled: True to enable, False to disable

        Returns:
            SettingsResult with success/failure status
        """
        return self._toggle_service(
            "Mobile data", "data", "toggle_mobile_data", enabled
        )

    def toggle_bluetooth(self, enabled: bool) -> SettingsResult:
        """Toggle Bluetooth on/off.

        Args:
            enabled: True to enable, False to disable

        Returns:
            SettingsResult with success/failure status
        """
        return self._toggle_service(
            "Bluetooth", "bluetooth", "toggle_bluetooth", enabled
        )

    # ── Battery ─────────────────────────────────────────────────────

    def set_battery_level(self, level: int) -> SettingsResult:
        """Set battery level on the emulator.

        Args:
            level: Battery level (0-100)

        Returns:
            SettingsResult with success/failure status
        """
        if not 0 <= level <= 100:
            return SettingsResult(
                success=False,
                message="Battery level must be 0-100",
                error=f"Invalid level: {level}",
            )

        def trigdroid_call() -> Any:
            return self._trigger_executor.set_battery_level(level)

        def adb_fallback() -> SettingsResult:
            Adb = self._get_adb()
            _stdout, stderr = Adb.send_telnet_command(f"power capacity {level}")
            if stderr and "error" in stderr.lower():
                return SettingsResult(
                    success=False,
                    message="Failed to set battery level",
                    error=stderr,
                )
            logger.info(f"Battery level set to {level}%")
            return SettingsResult(success=True, message=f"Battery set to {level}%")

        return self._try_trigdroid_then_adb(
            trigdroid_call=trigdroid_call,
            adb_fallback=adb_fallback,
            success_msg=f"Battery set to {level}%",
            error_label="to set battery level",
        )

    # ── Capability checks ───────────────────────────────────────────

    def check_root_available(self) -> bool:
        """Check if root (su) is available on the device.

        Returns cached result after first check.

        Returns:
            True if root is available, False otherwise
        """
        if self._root_available is not None:
            return self._root_available

        try:
            Adb = self._get_adb()
            stdout, _stderr = Adb.send_adb_command("shell which su")
            self._root_available = bool(stdout and stdout.strip() and "su" in stdout)
        except Exception as e:
            logger.debug(f"Root check failed: {e}")
            self._root_available = False

        return self._root_available

    def is_geopy_available(self) -> bool:
        """Check if geopy is installed for geocoding.

        Returns cached result after first check.

        Returns:
            True if geopy is available, False otherwise
        """
        if self._geopy_available is not None:
            return self._geopy_available

        try:
            import geopy

            self._geopy_available = True
        except ImportError:
            self._geopy_available = False

        return self._geopy_available
