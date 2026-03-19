"""Device settings modal for configuring device environment.

Tabbed modal with Location, Environment, Sensors & Battery, and Network tabs.
Supports country presets for quick setup. Emulator-only and root-only controls
are disabled when not available.
"""

import logging
from dataclasses import dataclass

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Input,
    Label,
    ProgressBar,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter

logger = logging.getLogger(__name__)


@dataclass
class DeviceSettingsResult:
    """Result returned when modal closes.

    Attributes:
        applied: Whether any settings were applied
        messages: List of status messages from operations
    """

    applied: bool = False
    messages: list[str] | None = None


class DeviceSettingsModal(ForensicModal[DeviceSettingsResult]):
    """Tabbed modal for device environment settings (Shift+E).

    Features:
    - Location tab: GPS coordinates, country presets, geocoding
    - Environment tab: timezone, locale, telephony (root required)
    - Sensors & Battery tab: accelerometer, gyroscope, light, pressure, battery
    - Network tab: WiFi, mobile data, Bluetooth toggles
    - Per-tab Apply buttons + Ctrl+S for apply all
    - Preset dropdown auto-fills fields across tabs
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("ctrl+s", "apply_all", "Apply All", priority=True),
    ]

    ENTER_SUBMITS_FROM_INPUT = False  # Don't auto-submit on Enter in inputs

    DEFAULT_CSS = """
    DeviceSettingsModal .modal-container {
        height: auto;
        max-height: 85%;
        width: 85%;
        max-width: 100;
    }

    DeviceSettingsModal TabbedContent {
        height: auto;
        max-height: 30;
    }

    DeviceSettingsModal TabPane {
        padding: 1;
        height: auto;
    }

    DeviceSettingsModal .field-row {
        height: 3;
        margin: 0 0;
    }

    DeviceSettingsModal .field-label {
        width: 20;
        height: 3;
        content-align: left middle;
        padding: 1 1 0 0;
    }

    DeviceSettingsModal .field-input {
        width: 1fr;
    }

    DeviceSettingsModal .badge {
        width: 7;
        height: 3;
        content-align: center middle;
        padding: 1 0 0 0;
        color: $warning;
        text-style: bold;
    }

    DeviceSettingsModal .status-label {
        height: 1;
        margin-top: 1;
        color: $text-muted;
        text-align: center;
        width: 100%;
    }

    DeviceSettingsModal .switch-row {
        height: 3;
        margin: 0 0;
        padding: 0 1;
    }

    DeviceSettingsModal .switch-label {
        width: 1fr;
        height: 3;
        content-align: left middle;
        padding: 1 0 0 0;
    }

    DeviceSettingsModal Select {
        width: 100%;
        margin: 0 0 1 0;
    }

    DeviceSettingsModal #geocode-progress {
        width: 100%;
        height: 1;
        display: none;
    }

    DeviceSettingsModal #geocode-progress.visible {
        display: block;
    }
    """

    def __init__(
        self,
        is_emulator: bool = True,
        has_root: bool = True,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the DeviceSettingsModal.

        Args:
            is_emulator: Whether connected device is an emulator
            has_root: Whether root access is available
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self._is_emulator = is_emulator
        self._has_root = has_root
        self._messages: list[str] = []

    @property
    def _root_badge(self) -> str:
        return "[ROOT]" if not self._has_root else ""

    @property
    def _emu_badge(self) -> str:
        return "[EMU]" if not self._is_emulator else ""

    def compose(self) -> ComposeResult:
        """Create the modal layout with 4 tabs."""
        from sandroid.services.device_settings_service import COUNTRY_PRESETS

        preset_options = [(p.name, key) for key, p in COUNTRY_PRESETS.items()]

        with Vertical(classes="modal-container"):
            yield Static("[bold]Device Settings[/bold]", classes="modal-title")

            # Preset selector (above tabs, affects all tabs)
            yield Label("Country Preset:")
            yield Select(
                preset_options,
                prompt="Select a preset...",
                id="preset-select",
                allow_blank=True,
            )

            with TabbedContent(id="settings-tabs"):
                # Tab 1: Location
                with TabPane("Location", id="tab-location"):
                    with Horizontal(classes="field-row"):
                        yield Static("Latitude", classes="field-label")
                        yield Input(
                            placeholder="e.g. 52.52",
                            id="input-latitude",
                            classes="field-input",
                        )
                    with Horizontal(classes="field-row"):
                        yield Static("Longitude", classes="field-label")
                        yield Input(
                            placeholder="e.g. 13.405",
                            id="input-longitude",
                            classes="field-input",
                        )
                    # Geocode section (only if geopy available)
                    yield Static(
                        "[dim]Geocode (requires geopy)[/dim]",
                        id="geocode-header",
                    )
                    with Horizontal(classes="field-row"):
                        yield Static("City", classes="field-label")
                        yield Input(
                            placeholder="e.g. Berlin",
                            id="input-geocode-city",
                            classes="field-input",
                        )
                    with Horizontal(classes="field-row"):
                        yield Static("Country", classes="field-label")
                        yield Input(
                            placeholder="e.g. Germany",
                            id="input-geocode-country",
                            classes="field-input",
                        )
                    with Horizontal(classes="button-row"):
                        yield Button(
                            "Geocode",
                            id="btn-geocode",
                            classes="-secondary",
                        )
                        yield Button(
                            "Apply Location",
                            id="btn-apply-location",
                            classes="-primary",
                        )
                    yield ProgressBar(
                        id="geocode-progress",
                        total=None,
                        show_eta=False,
                        show_percentage=False,
                    )

                # Tab 2: Environment
                with TabPane("Environment", id="tab-environment"):
                    with Horizontal(classes="field-row"):
                        yield Static("Timezone", classes="field-label")
                        yield Input(
                            placeholder="e.g. Europe/Berlin",
                            id="input-timezone",
                            classes="field-input",
                            disabled=not self._has_root,
                        )
                        yield Static(self._root_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Language", classes="field-label")
                        yield Input(
                            placeholder="e.g. de",
                            id="input-language",
                            classes="field-input",
                            disabled=not self._has_root,
                        )
                        yield Static(self._root_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Country", classes="field-label")
                        yield Input(
                            placeholder="e.g. DE",
                            id="input-country",
                            classes="field-input",
                            disabled=not self._has_root,
                        )
                        yield Static(self._root_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Telephony ISO", classes="field-label")
                        yield Input(
                            placeholder="e.g. de",
                            id="input-tel-iso",
                            classes="field-input",
                            disabled=not self._has_root,
                        )
                        yield Static(self._root_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Telephony MNC", classes="field-label")
                        yield Input(
                            placeholder="e.g. 26201",
                            id="input-tel-mnc",
                            classes="field-input",
                            disabled=not self._has_root,
                        )
                        yield Static(self._root_badge, classes="badge")
                    with Horizontal(classes="button-row"):
                        yield Button(
                            "Apply Environment",
                            id="btn-apply-environment",
                            classes="-primary",
                            disabled=not self._has_root,
                        )

                # Tab 3: Sensors & Battery
                with TabPane("Sensors", id="tab-sensors"):
                    with Horizontal(classes="field-row"):
                        yield Static("Accelerometer", classes="field-label")
                        yield Input(
                            placeholder="0-10",
                            id="input-accelerometer",
                            classes="field-input",
                            disabled=not self._is_emulator,
                        )
                        yield Static(self._emu_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Gyroscope", classes="field-label")
                        yield Input(
                            placeholder="0-10",
                            id="input-gyroscope",
                            classes="field-input",
                            disabled=not self._is_emulator,
                        )
                        yield Static(self._emu_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Light", classes="field-label")
                        yield Input(
                            placeholder="0-10",
                            id="input-light",
                            classes="field-input",
                            disabled=not self._is_emulator,
                        )
                        yield Static(self._emu_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Pressure", classes="field-label")
                        yield Input(
                            placeholder="0-10",
                            id="input-pressure",
                            classes="field-input",
                            disabled=not self._is_emulator,
                        )
                        yield Static(self._emu_badge, classes="badge")
                    with Horizontal(classes="field-row"):
                        yield Static("Battery Level", classes="field-label")
                        yield Input(
                            placeholder="0-100",
                            id="input-battery",
                            classes="field-input",
                            disabled=not self._is_emulator,
                        )
                        yield Static(self._emu_badge, classes="badge")
                    with Horizontal(classes="button-row"):
                        yield Button(
                            "Apply Sensors",
                            id="btn-apply-sensors",
                            classes="-primary",
                            disabled=not self._is_emulator,
                        )

                # Tab 4: Network
                with TabPane("Network", id="tab-network"):
                    with Horizontal(classes="switch-row"):
                        yield Static("WiFi", classes="switch-label")
                        yield Switch(value=True, id="switch-wifi")
                    with Horizontal(classes="switch-row"):
                        yield Static("Mobile Data", classes="switch-label")
                        yield Switch(value=True, id="switch-mobile-data")
                    with Horizontal(classes="switch-row"):
                        yield Static("Bluetooth", classes="switch-label")
                        yield Switch(value=False, id="switch-bluetooth")
                    with Horizontal(classes="button-row"):
                        yield Button(
                            "Apply Network",
                            id="btn-apply-network",
                            classes="-primary",
                        )

            # Status label
            yield Static("", id="status-label", classes="status-label")

            # Bottom buttons
            with Horizontal(classes="button-row"):
                yield Button("Close", id="btn-close", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Check capabilities on mount."""
        super().on_mount()
        try:
            if not self._get_settings_service().is_geopy_available():
                self.query_one("#btn-geocode", Button).disabled = True
        except Exception:
            pass

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle preset selection."""
        if event.select.id != "preset-select" or event.value == Select.BLANK:
            return

        from sandroid.services.device_settings_service import COUNTRY_PRESETS

        preset = COUNTRY_PRESETS.get(str(event.value))
        if not preset:
            return

        field_values = {
            "input-latitude": str(preset.latitude),
            "input-longitude": str(preset.longitude),
            "input-timezone": preset.timezone,
            "input-language": preset.language,
            "input-country": preset.country,
            "input-tel-iso": preset.country_code,
            "input-tel-mnc": preset.telephony_mnc,
        }
        for input_id, value in field_values.items():
            self._set_input(input_id, value)

        self._update_status(f"Preset loaded: {preset.name}")

    def _set_input(self, input_id: str, value: str) -> None:
        """Safely set an input value."""
        try:
            inp = self.query_one(f"#{input_id}", Input)
            inp.value = value
        except Exception:
            pass

    def _get_input(self, input_id: str) -> str:
        """Safely get an input value."""
        try:
            inp = self.query_one(f"#{input_id}", Input)
            return inp.value.strip()
        except Exception:
            return ""

    def _update_status(self, message: str) -> None:
        """Update the status label."""
        try:
            label = self.query_one("#status-label", Static)
            label.update(message)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "btn-close":
            self._dismiss_with_refresh(
                DeviceSettingsResult(
                    applied=bool(self._messages),
                    messages=self._messages if self._messages else None,
                )
            )
        elif button_id == "btn-geocode":
            self._do_geocode()
        elif button_id == "btn-apply-location":
            self._apply_location()
        elif button_id == "btn-apply-environment":
            self._apply_environment()
        elif button_id == "btn-apply-sensors":
            self._apply_sensors()
        elif button_id == "btn-apply-network":
            self._apply_network()

    def action_apply_all(self) -> None:
        """Apply all settings (Ctrl+S)."""
        self._apply_location()
        if self._has_root:
            self._apply_environment()
        if self._is_emulator:
            self._apply_sensors()
        self._apply_network()
        self._update_status("All settings applied")

    def _get_settings_service(self):
        """Get the device settings service (lazy import)."""
        from sandroid.services import get_device_settings_service

        return get_device_settings_service()

    def _do_geocode(self) -> None:
        """Geocode city/country to coordinates (async with progress)."""
        city = self._get_input("input-geocode-city")
        country = self._get_input("input-geocode-country")

        if not city or not country:
            self._update_status("[red]Enter both city and country[/]")
            return

        btn = self.query_one("#btn-geocode", Button)
        btn.disabled = True
        progress = self.query_one("#geocode-progress", ProgressBar)
        progress.add_class("visible")
        self._update_status("Geocoding...")

        self._run_geocode(city, country)

    @work(thread=True)
    def _run_geocode(self, city: str, country: str) -> None:
        """Run geocode in a worker thread to keep UI responsive."""
        try:
            coords = self._get_settings_service().geocode_location(country, city)
            self.app.call_from_thread(self._geocode_done, city, country, coords, None)
        except Exception as e:
            self.app.call_from_thread(self._geocode_done, city, country, None, e)

    def _geocode_done(
        self,
        city: str,
        country: str,
        coords: tuple[float, float] | None,
        error: Exception | None,
    ) -> None:
        """Handle geocode result back on the main thread."""
        btn = self.query_one("#btn-geocode", Button)
        btn.disabled = False
        progress = self.query_one("#geocode-progress", ProgressBar)
        progress.remove_class("visible")

        if error:
            self._update_status(f"[red]Geocode error: {error}[/]")
        elif coords:
            lat, lon = coords
            self._set_input("input-latitude", str(lat))
            self._set_input("input-longitude", str(lon))
            self._update_status(f"Geocoded: {lat:.4f}, {lon:.4f}")
        else:
            self._update_status(f"[red]Could not geocode {city}, {country}[/]")

    def _apply_location(self) -> None:
        """Apply location settings."""
        lat_str = self._get_input("input-latitude")
        lon_str = self._get_input("input-longitude")

        if not lat_str or not lon_str:
            self._update_status("[yellow]Enter latitude and longitude[/]")
            return

        try:
            lat = float(lat_str)
            lon = float(lon_str)
        except ValueError:
            self._update_status("[red]Invalid coordinates[/]")
            return

        try:
            result = self._get_settings_service().set_gps_location(lat, lon)
            if result.success:
                self._messages.append(result.message)
                self._update_status(f"[green]{result.message}[/]")
            else:
                self._update_status(f"[red]{result.message}[/]")
        except Exception as e:
            self._update_status(f"[red]Location error: {e}[/]")

    def _apply_environment(self) -> None:
        """Apply environment settings (timezone, locale, telephony)."""
        try:
            svc = self._get_settings_service()
            messages = []

            tz = self._get_input("input-timezone")
            if tz:
                messages.append(svc.set_timezone(tz).message)

            lang = self._get_input("input-language")
            country = self._get_input("input-country")
            if lang and country:
                messages.append(svc.set_locale(lang, country).message)

            tel_iso = self._get_input("input-tel-iso")
            tel_mnc = self._get_input("input-tel-mnc")
            if tel_iso and tel_mnc:
                messages.append(svc.set_telephony(tel_iso, tel_mnc).message)

            self._report_results(
                messages, "No environment fields filled", "Environment"
            )
        except Exception as e:
            self._update_status(f"[red]Environment error: {e}[/]")

    def _apply_sensors(self) -> None:
        """Apply sensor and battery settings."""
        try:
            svc = self._get_settings_service()
            messages = []

            sensor_inputs = {
                "accelerometer": "input-accelerometer",
                "gyroscope": "input-gyroscope",
                "light": "input-light",
                "pressure": "input-pressure",
            }

            for sensor_type, input_id in sensor_inputs.items():
                val = self._get_input(input_id)
                if val:
                    try:
                        messages.append(svc.set_sensor(sensor_type, int(val)).message)
                    except ValueError:
                        messages.append(f"Invalid {sensor_type} value")

            battery_val = self._get_input("input-battery")
            if battery_val:
                try:
                    messages.append(svc.set_battery_level(int(battery_val)).message)
                except ValueError:
                    messages.append("Invalid battery value")

            self._report_results(messages, "No sensor fields filled", "Sensor")
        except Exception as e:
            self._update_status(f"[red]Sensor error: {e}[/]")

    def _apply_network(self) -> None:
        """Apply network toggle settings."""
        try:
            svc = self._get_settings_service()
            messages = [
                svc.toggle_wifi(self.query_one("#switch-wifi", Switch).value).message,
                svc.toggle_mobile_data(
                    self.query_one("#switch-mobile-data", Switch).value
                ).message,
                svc.toggle_bluetooth(
                    self.query_one("#switch-bluetooth", Switch).value
                ).message,
            ]
            self._messages.extend(messages)
            self._update_status(f"[green]{'; '.join(messages)}[/]")
        except Exception as e:
            self._update_status(f"[red]Network error: {e}[/]")

    def _report_results(
        self, messages: list[str], empty_msg: str, category: str
    ) -> None:
        """Report apply results to status and message list."""
        if messages:
            self._messages.extend(messages)
            self._update_status(f"[green]{'; '.join(messages)}[/]")
        else:
            self._update_status(f"[yellow]{empty_msg}[/]")
