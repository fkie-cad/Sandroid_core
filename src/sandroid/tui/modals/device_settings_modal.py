"""Device settings modal for configuring device environment.

Tabbed modal with Location, Environment, Sensors & Battery, Network and
Actions tabs. Supports country presets for quick setup. Emulator-only and
root-only controls are disabled when not available. The Actions tab is the
front end of the device-actions registry
(:mod:`sandroid.services.device_actions`): pick an action, fill its
parameters, run it (off the UI thread); background actions (a GPS route)
are listed and can be stopped.
"""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
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
    Tabs,
)

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter
from sandroid.tui.utils.markup import escape

logger = logging.getLogger(__name__)

#: Longest result detail (or failure reason) shown in the status line.
_REASON_MAX = 120

#: ``tui_state.json`` key remembering the last active tab.
_UI_STATE_TAB_KEY = "device_settings_tab"

#: The tab pane ids, in order.
_TAB_IDS = (
    "tab-location",
    "tab-environment",
    "tab-sensors",
    "tab-network",
    "tab-actions",
)


@dataclass
class DeviceSettingsResult:
    """Result returned when modal closes.

    Attributes:
        applied: Whether any settings were applied
        messages: List of status messages from operations
    """

    applied: bool = False
    messages: list[str] | None = None


@dataclass
class _Outcome:
    """Result of one apply step, in plain words.

    Attributes:
        label: What was applied (e.g. "Timezone")
        ok: Whether it worked
        detail: The service's message on success, the reason on failure
    """

    label: str
    ok: bool
    detail: str


#: One apply step: a label and a call on the settings service, or an input
#: error already known on the UI thread (shown in order with the results).
_PlanEntry = tuple[str, Callable[[Any], Any]] | _Outcome


class DeviceSettingsModal(ForensicModal[DeviceSettingsResult]):
    """Tabbed modal for device environment settings (Shift+E).

    Features:
    - Location tab: GPS coordinates, country presets, geocoding
    - Environment tab: timezone, locale, telephony (root required)
    - Sensors & Battery tab: accelerometer, gyroscope, light, pressure, battery
    - Network tab: WiFi, mobile data, Bluetooth toggles
    - Actions tab: device actions (SMS, calls, GPS, time, power, network)
    - Per-tab Apply buttons + Ctrl+S for apply all (on the Actions tab:
      run the action)
    - Preset dropdown auto-fills fields across tabs
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("ctrl+s", "apply_all", "Apply All", priority=True),
        # Not priority: in a text field Shift+Left/Right still select text.
        Binding("shift+left", "cycle_tab(-1)", "Previous tab", show=False),
        Binding("shift+right", "cycle_tab(1)", "Next tab", show=False),
    ]

    ENTER_SUBMITS_FROM_INPUT = False  # Don't auto-submit on Enter in inputs

    # No Textual auto focus: it would focus the preset picker and scroll.
    # :meth:`_auto_focus` puts the focus on the tab bar instead.
    AUTO_FOCUS = ""

    DEFAULT_CSS = """
    /* The container scrolls when the content is taller than the screen:
       the focused widget scrolls into view, Up/Down/PageUp/PageDown
       scroll, and the scrollbar is drawn in a visible colour. */
    DeviceSettingsModal .modal-container {
        height: auto;
        max-height: 85%;
        width: 85%;
        max-width: 100;
        scrollbar-size-vertical: 1;
        scrollbar-color: $primary;
    }

    DeviceSettingsModal SelectOverlay {
        scrollbar-size-vertical: 1;
        scrollbar-color: $primary;
    }

    DeviceSettingsModal TabbedContent {
        height: auto;
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

    /* SandroidModal gives Inputs "margin: 1 0": in a 3-row field row that
       pushed the box down and cut its bottom border (only the top showed). */
    DeviceSettingsModal .field-row Input {
        margin: 0;
    }

    /* An example in the box must not read as a value that is already set. */
    DeviceSettingsModal Input > .input--placeholder {
        color: $text-disabled;
        text-style: italic;
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
        height: auto;
        max-height: 6;
        overflow-y: auto;
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

    DeviceSettingsModal #actions-body {
        height: auto;
    }

    DeviceSettingsModal #action-params {
        height: auto;
    }

    DeviceSettingsModal #action-help {
        height: auto;
        color: $text-muted;
        margin: 0 0 1 0;
    }

    DeviceSettingsModal #action-jobs {
        height: auto;
    }

    DeviceSettingsModal .job-row {
        height: 3;
    }

    DeviceSettingsModal .job-label {
        width: 1fr;
        height: 3;
        content-align: left middle;
        padding: 1 1 0 0;
    }

    DeviceSettingsModal .job-row Button {
        margin: 1 0 0 0;
    }

    DeviceSettingsModal #action-params Switch {
        margin: 1 0 0 0;
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
        self._applying = False
        #: An action run is in progress (the Run button is locked).
        self._action_busy = False
        #: The action whose parameter fields are shown.
        self._action_id: str | None = None
        #: Job ids shown in the background list (rebuilt when they change).
        self._shown_jobs: tuple[str, ...] = ()
        #: The action whose fields are built, and the lock that keeps
        #: rebuilds (fields, background list) one at a time.
        self._built_for: str | None = None
        self._rebuild_lock = asyncio.Lock()
        #: The tab to open on: the one active when the modal was last used.
        self._initial_tab = self._remembered_tab()

    @staticmethod
    def _remembered_tab() -> str:
        """The last active tab from ``tui_state.json`` (Location if none)."""
        try:
            from sandroid.config.ui_state import load_ui_state

            tab = load_ui_state().get(_UI_STATE_TAB_KEY)
        except Exception:
            tab = None
        return tab if tab in _TAB_IDS else _TAB_IDS[0]

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        """Remember the active tab for the next opening."""
        tab = event.pane.id
        if tab not in _TAB_IDS or tab == self._initial_tab:
            return
        self._initial_tab = tab
        try:
            from sandroid.config.ui_state import update_ui_state

            update_ui_state(_UI_STATE_TAB_KEY, tab)
        except Exception:
            logger.debug("Could not remember the device settings tab", exc_info=True)

    def _auto_focus(self) -> None:
        """Open on the tab bar: Shift+Left/Right (and Left/Right) switch
        tabs at once, Tab goes into the fields. Without scrolling: a
        focus scroll would centre the tab bar and hide the title.
        """
        try:
            self.query_one("#settings-tabs Tabs", Tabs).focus(scroll_visible=False)
        except Exception:
            super()._auto_focus()

    def action_cancel(self) -> None:
        """Esc: close an open dropdown first, else close the modal.

        The modal's Esc binding has priority, so the dropdown's own Esc
        never runs; collapse it here instead.
        """
        for select in self.query(Select):
            if select.expanded:
                select.expanded = False
                select.focus()
                return
        super().action_cancel()

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

        # Not focusable itself: Tab goes straight to the widgets inside.
        with VerticalScroll(classes="modal-container", can_focus=False):
            yield Static("[bold]Device Settings[/bold]", classes="modal-title")

            # Preset selector (above tabs, affects all tabs)
            yield Label("Country Preset:")
            yield Select(
                preset_options,
                prompt="Select a preset...",
                id="preset-select",
                allow_blank=True,
            )

            with TabbedContent(id="settings-tabs", initial=self._initial_tab):
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

                # Tab 5: device actions (the registry's front end)
                with TabPane("Actions", id="tab-actions"):
                    yield from self._compose_actions()

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
        self.call_later(self._show_action, self._first_action_id())
        self.set_interval(1.0, self._refresh_jobs)
        self.call_later(self._refresh_jobs)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle preset and action selection."""
        if event.select.id == "action-select":
            if event.value != Select.BLANK and event.value != self._action_id:
                self.call_later(self._show_action, str(event.value))
            return
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

    def _alive(self) -> bool:
        """Whether the modal is still on screen (a worker may outlive it).

        ``is_mounted`` stays true after the modal is closed, so also check
        that it is still attached to the app.
        """
        return self.is_mounted and self.is_attached

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
            self._start_apply(self._location_plan(), "Enter latitude and longitude")
        elif button_id == "btn-apply-environment":
            self._start_apply(self._environment_plan(), "No environment fields filled")
        elif button_id == "btn-apply-sensors":
            self._start_apply(self._sensors_plan(), "No sensor fields filled")
        elif button_id == "btn-apply-network":
            self._start_apply(self._network_plan(), "")
        elif button_id == "btn-run-action":
            self._start_action()
        elif button_id and button_id.startswith("btn-stop-"):
            self._stop_job(button_id.removeprefix("btn-stop-"))

    def action_cycle_tab(self, delta: int) -> None:
        """Shift+Left/Right: the previous / next tab (wraps); the tab bar
        gets the focus, so Left/Right go on from there.
        """
        try:
            tabs = self.query_one("#settings-tabs", TabbedContent)
        except Exception:
            return
        panes = [pane.id for pane in tabs.query(TabPane) if pane.id]
        if not panes:
            return
        current = panes.index(tabs.active) if tabs.active in panes else 0
        tabs.active = panes[(current + delta) % len(panes)]
        try:
            tabs.query_one(Tabs).focus()
        except Exception:
            pass

    def action_apply_all(self) -> None:
        """Apply all settings (Ctrl+S); on the Actions tab: run the action."""
        try:
            tab = self.query_one("#settings-tabs", TabbedContent).active
        except Exception:
            tab = ""
        if tab == "tab-actions":
            self._start_action()
            return
        plan = self._location_plan()
        if self._has_root:
            plan += self._environment_plan()
        if self._is_emulator:
            plan += self._sensors_plan()
        plan += self._network_plan()
        self._start_apply(plan, "")

    def _get_settings_service(self):
        """Get the device settings service (lazy import)."""
        from sandroid.services import get_device_settings_service

        return get_device_settings_service()

    def _do_geocode(self) -> None:
        """Geocode city/country to coordinates (async with progress)."""
        city = self._get_input("input-geocode-city")
        country = self._get_input("input-geocode-country")

        if not city or not country:
            self._update_status("[$error]Enter both city and country[/]")
            return

        btn = self.query_one("#btn-geocode", Button)
        btn.disabled = True
        progress = self.query_one("#geocode-progress", ProgressBar)
        progress.add_class("visible")
        self._update_status("Geocoding...")

        self._run_geocode(self.app, city, country)

    @work(thread=True)
    def _run_geocode(self, app: App, city: str, country: str) -> None:
        """Run geocode in a worker thread to keep UI responsive.

        *app* is taken on the UI thread: once the modal is closed,
        ``self.app`` can no longer be resolved from this thread.
        """
        coords: tuple[float, float] | None = None
        error: Exception | None = None
        try:
            coords = self._get_settings_service().geocode_location(country, city)
        except Exception as e:
            error = e
        try:
            app.call_from_thread(self._geocode_done, city, country, coords, error)
        except Exception:
            logger.debug("Could not show the geocode result", exc_info=True)

    def _geocode_done(
        self,
        city: str,
        country: str,
        coords: tuple[float, float] | None,
        error: Exception | None,
    ) -> None:
        """Handle geocode result back on the main thread."""
        if not self._alive():
            return
        btn = self.query_one("#btn-geocode", Button)
        btn.disabled = False
        progress = self.query_one("#geocode-progress", ProgressBar)
        progress.remove_class("visible")

        if error:
            self._update_status(f"[$error]Geocode failed: {escape(str(error))}[/]")
        elif coords:
            lat, lon = coords
            self._set_input("input-latitude", str(lat))
            self._set_input("input-longitude", str(lon))
            self._update_status(f"Geocoded: {lat:.4f}, {lon:.4f}")
        else:
            self._update_status(
                f"[$error]Could not geocode {escape(city)}, {escape(country)}[/]"
            )

    # ── Apply: plans are read on the UI thread, run in a worker ─────

    def _location_plan(self) -> list[_PlanEntry]:
        """Location step, or nothing when no coordinates were entered."""
        lat_str = self._get_input("input-latitude")
        lon_str = self._get_input("input-longitude")
        if not lat_str or not lon_str:
            return []
        try:
            lat = float(lat_str)
            lon = float(lon_str)
        except ValueError:
            return [_Outcome("Location", False, "invalid coordinates")]
        return [("Location", lambda svc: svc.set_gps_location(lat, lon))]

    def _environment_plan(self) -> list[_PlanEntry]:
        """Timezone, locale and telephony steps for the filled fields."""
        plan: list[_PlanEntry] = []
        tz = self._get_input("input-timezone")
        if tz:
            plan.append(("Timezone", lambda svc: svc.set_timezone(tz)))

        lang = self._get_input("input-language")
        country = self._get_input("input-country")
        if lang and country:
            plan.append(("Locale", lambda svc: svc.set_locale(lang, country)))

        tel_iso = self._get_input("input-tel-iso")
        tel_mnc = self._get_input("input-tel-mnc")
        if tel_iso and tel_mnc:
            plan.append(("Telephony", lambda svc: svc.set_telephony(tel_iso, tel_mnc)))
        return plan

    def _sensors_plan(self) -> list[_PlanEntry]:
        """Sensor and battery steps for the filled fields."""
        plan: list[_PlanEntry] = []
        sensor_inputs = {
            "accelerometer": "input-accelerometer",
            "gyroscope": "input-gyroscope",
            "light": "input-light",
            "pressure": "input-pressure",
        }
        for sensor_type, input_id in sensor_inputs.items():
            val = self._get_input(input_id)
            if not val:
                continue
            label = sensor_type.capitalize()
            try:
                level = int(val)
            except ValueError:
                plan.append(_Outcome(label, False, "invalid value"))
                continue
            plan.append(
                (
                    label,
                    lambda svc, t=sensor_type, v=level: svc.set_sensor(t, v),
                )
            )

        battery_val = self._get_input("input-battery")
        if battery_val:
            try:
                level = int(battery_val)
            except ValueError:
                plan.append(_Outcome("Battery", False, "invalid value"))
            else:
                plan.append(("Battery", lambda svc, v=level: svc.set_battery_level(v)))
        return plan

    def _network_plan(self) -> list[_PlanEntry]:
        """WiFi, mobile data and Bluetooth steps from the switches."""
        wifi = self.query_one("#switch-wifi", Switch).value
        data = self.query_one("#switch-mobile-data", Switch).value
        bluetooth = self.query_one("#switch-bluetooth", Switch).value
        return [
            ("WiFi", lambda svc: svc.toggle_wifi(wifi)),
            ("Mobile data", lambda svc: svc.toggle_mobile_data(data)),
            ("Bluetooth", lambda svc: svc.toggle_bluetooth(bluetooth)),
        ]

    def _start_apply(self, plan: list[_PlanEntry], empty_msg: str) -> None:
        """Run *plan* in a worker; the UI stays responsive meanwhile.

        Args:
            plan: Steps (and already-known input errors) in display order.
            empty_msg: Status shown when *plan* is empty.
        """
        if self._applying:
            return
        if not plan:
            if empty_msg:
                self._update_status(f"[$warning]{empty_msg}[/]")
            return
        if all(isinstance(entry, _Outcome) for entry in plan):
            self._show_outcomes(plan)  # only input errors, nothing to send
            return

        from sandroid.core.adb import Adb

        # Pin the whole run to the device the user is looking at now, so a
        # device switch mid-run can't split the work across two devices.
        serial = Adb.get_target_device() or Adb.selected_serial()
        if not serial:
            self._update_status("[$error]No device selected[/]")
            return
        self._set_applying(True)
        self._update_status("Applying...")
        self._run_apply(self.app, plan, serial)

    @work(thread=True, exclusive=True, group="device-settings-apply")
    def _run_apply(self, app: App, plan: list[_PlanEntry], serial: str) -> None:
        """Run the adb/console round trips of *plan* off the UI thread.

        *app* is taken on the UI thread: once the modal is closed,
        ``self.app`` can no longer be resolved from this thread.
        """
        from sandroid.core.adb import Adb

        outcomes: list[_Outcome] = []
        try:
            svc = self._get_settings_service()
            with Adb.targeting(serial):
                for entry in plan:
                    if isinstance(entry, _Outcome):
                        outcomes.append(entry)
                        continue
                    label, call = entry
                    try:
                        result = call(svc)
                    except Exception as e:
                        logger.debug("%s failed", label, exc_info=True)
                        outcomes.append(_Outcome(label, False, str(e)))
                        continue
                    if result.success:
                        outcomes.append(_Outcome(label, True, result.message))
                    else:
                        reason = result.error or result.message
                        outcomes.append(_Outcome(label, False, reason))
        except Exception as e:
            logger.debug("Device settings apply failed", exc_info=True)
            outcomes.append(_Outcome("Settings", False, str(e)))
        # The modal may be closed (or the app gone) by now.
        try:
            app.call_from_thread(self._apply_done, outcomes)
        except Exception:
            logger.debug("Could not show the device settings results", exc_info=True)

    def _apply_done(self, outcomes: list[_Outcome]) -> None:
        """Show the results of a run (UI thread)."""
        self._applying = False
        if not self._alive():
            return
        self._set_applying(False)
        self._show_outcomes(outcomes)

    def _set_applying(self, busy: bool) -> None:
        """Disable the Apply buttons while a run is in progress."""
        self._applying = busy
        available = {
            "btn-apply-location": True,
            "btn-apply-environment": self._has_root,
            "btn-apply-sensors": self._is_emulator,
            "btn-apply-network": True,
        }
        for button_id, enabled in available.items():
            try:
                self.query_one(f"#{button_id}", Button).disabled = busy or not enabled
            except Exception:
                pass

    def _show_outcomes(self, outcomes: list[_Outcome]) -> None:
        """Report results in the status line: success and error colours."""
        parts = []
        for outcome in outcomes:
            label = escape(outcome.label)
            detail = escape(" ".join(outcome.detail.split())[:_REASON_MAX])
            if outcome.ok:
                self._messages.append(outcome.detail)
                if detail:
                    parts.append(f"[$success]{label} applied: {detail}[/]")
                else:
                    parts.append(f"[$success]{label} applied[/]")
            else:
                reason = detail or "unknown error"
                parts.append(f"[$error]{label} failed: {reason}[/]")
        self._update_status("; ".join(parts))

    # ── Actions tab: the device-actions registry ─────────────────────

    def _compose_actions(self) -> ComposeResult:
        """The Actions tab: picker, parameter fields, Run, background list."""
        from sandroid.services.device_actions import list_actions

        options = [(f"{a.group}: {a.title}", a.id) for a in list_actions()]
        # The modal container scrolls; no nested scroll area here.
        with Vertical(id="actions-body"):
            yield Select(
                options,
                id="action-select",
                allow_blank=False,
                value=self._first_action_id(),
            )
            yield Static("", id="action-help")
            yield Vertical(id="action-params")
            with Horizontal(classes="button-row"):
                yield Button("Run", id="btn-run-action", classes="-primary")
            yield Static("", id="action-jobs-title")
            yield Vertical(id="action-jobs")

    @staticmethod
    def _first_action_id() -> str:
        from sandroid.services.device_actions import list_actions

        return list_actions()[0].id

    def _action(self):
        """The selected :class:`DeviceAction` (``None`` before the first)."""
        from sandroid.services.device_actions import ACTIONS

        return ACTIONS.get(self._action_id or "")

    async def _show_action(self, action_id: str) -> None:
        """Show the help line and parameter fields of *action_id* (one
        rebuild at a time: the fields keep fixed ids).
        """
        async with self._rebuild_lock:
            if action_id != self._built_for:
                await self._build_action(action_id)

    async def _build_action(self, action_id: str) -> None:
        from sandroid.services.device_actions import ACTIONS

        action = ACTIONS.get(action_id)
        if action is None or not self._alive():
            return
        self._action_id = action_id
        self._built_for = action_id
        refused = action.emulator_only and not self._is_emulator
        help_text = escape(action.help)
        if refused:
            help_text += " [$warning]Works on an emulator only.[/]"
        self.query_one("#action-help", Static).update(help_text)
        container = self.query_one("#action-params", Vertical)
        await container.remove_children()
        rows = []
        for param in action.params:
            widget = self._param_widget(param)
            widget.disabled = refused
            rows.append(
                Horizontal(
                    Static(param.label, classes="field-label"),
                    widget,
                    classes="switch-row" if param.kind == "bool" else "field-row",
                )
            )
        if rows:
            await container.mount(*rows)
        self._set_action_busy(self._action_busy)

    @staticmethod
    def _param_widget(param) -> Input | Switch | Select:
        """The form widget of one ``Param`` (id ``action-param-<name>``)."""
        widget_id = f"action-param-{param.name}"
        if param.kind == "bool":
            return Switch(value=bool(param.default), id=widget_id)
        if param.kind == "choice":
            return Select(
                [(label, value) for value, label in param.choices],
                id=widget_id,
                allow_blank=param.default is None,
                value=param.default if param.default is not None else Select.BLANK,
                classes="field-input",
            )
        default = "" if param.default is None else str(param.default)
        return Input(
            value=default,
            placeholder=param.placeholder,
            id=widget_id,
            classes="field-input",
        )

    def _action_params(self) -> dict[str, Any]:
        """The form values of the shown action (raw; the registry validates)."""
        action = self._action()
        values: dict[str, Any] = {}
        for param in action.params if action else ():
            try:
                widget = self.query_one(f"#action-param-{param.name}")
            except Exception:
                continue
            if isinstance(widget, Switch):
                values[param.name] = widget.value
            elif isinstance(widget, Select):
                value = widget.value
                values[param.name] = None if value == Select.BLANK else value
            elif isinstance(widget, Input):
                values[param.name] = widget.value
        return values

    def _start_action(self) -> None:
        """Run the selected action in a worker (UI thread entry point)."""
        action = self._action()
        if self._action_busy or action is None:
            return
        if action.emulator_only and not self._is_emulator:
            self._update_status(
                f"[$error]{escape(action.title)} not run: works on an emulator only[/]"
            )
            return
        from sandroid.core.adb import Adb

        serial = Adb.get_target_device() or Adb.selected_serial()
        if not serial:
            self._update_status("[$error]No device selected[/]")
            return
        params = self._action_params()
        self._set_action_busy(True)
        self._update_status(f"Running: {escape(action.title)}...")
        self._run_action(self.app, action.id, params, serial)

    @work(thread=True, exclusive=True, group="device-actions-run")
    def _run_action(
        self, app: App, action_id: str, params: dict[str, Any], serial: str
    ) -> None:
        """Run one device action off the UI thread (pinned to *serial*).

        *app* is taken on the UI thread: once the modal is closed,
        ``self.app`` can no longer be resolved from this thread.
        """
        from sandroid.services.device_actions import ActionResult, run_action

        try:
            result = run_action(action_id, serial, params, actor="user")
        except Exception as e:  # run_action never raises; belt and braces
            logger.debug("Device action failed", exc_info=True)
            result = ActionResult(action_id, False, str(e))
        try:
            app.call_from_thread(self._action_done, result)
        except Exception:
            logger.debug("Could not show the device action result", exc_info=True)

    def _action_done(self, result) -> None:
        """Show the result line of a run (UI thread)."""
        self._action_busy = False
        if not self._alive():
            return
        self._set_action_busy(False)
        from sandroid.services.device_actions import ACTIONS

        action = ACTIONS.get(result.action)
        title = escape(action.title if action else result.action)
        detail = escape(" ".join(result.message.split())[: _REASON_MAX * 2])
        if result.ok:
            self._messages.append(result.message)
            self._update_status(f"[$success]{detail}[/]")
        elif result.refused:
            self._update_status(f"[$error]{title} not run: {detail}[/]")
        else:
            self._update_status(f"[$error]{title} failed: {detail}[/]")
        self.call_later(self._refresh_jobs)

    def _set_action_busy(self, busy: bool) -> None:
        """Lock the Run button while an action runs (and when refused)."""
        self._action_busy = busy
        action = self._action()
        refused = bool(action and action.emulator_only and not self._is_emulator)
        try:
            self.query_one("#btn-run-action", Button).disabled = busy or refused
        except Exception:
            pass

    async def _refresh_jobs(self) -> None:
        """List the running background actions with a Stop button each."""
        async with self._rebuild_lock:
            await self._render_jobs()

    async def _render_jobs(self) -> None:
        from sandroid.services.device_actions import running_jobs

        if not self._alive():
            return
        jobs = running_jobs()
        try:
            title = self.query_one("#action-jobs-title", Static)
            container = self.query_one("#action-jobs", Vertical)
        except Exception:
            return
        title.update("Running in the background" if jobs else "")
        ids = tuple(job.id for job in jobs)
        if ids != self._shown_jobs:
            self._shown_jobs = ids
            await container.remove_children()
            rows = [
                Horizontal(
                    Static(
                        self._job_text(job),
                        id=f"job-label-{job.id}",
                        classes="job-label",
                    ),
                    Button("Stop", id=f"btn-stop-{job.id}", classes="-secondary"),
                    classes="job-row",
                )
                for job in jobs
            ]
            if rows:
                await container.mount(*rows)
            return
        for job in jobs:
            try:
                label = self.query_one(f"#job-label-{job.id}", Static)
            except Exception:
                continue
            label.update(self._job_text(job))

    @staticmethod
    def _job_text(job) -> str:
        """``<name> ● running, <progress>`` (the dot in the success colour)."""
        progress = f", {escape(job.progress)}" if job.progress else ""
        return f"{escape(job.title)} [$success]●[/] running{progress}"

    def _stop_job(self, job_id: str) -> None:
        """Stop a background job (the wait for its thread runs off the UI)."""
        self._update_status("Stopping...")
        self._run_stop(self.app, job_id)

    @work(thread=True, group="device-actions-stop")
    def _run_stop(self, app: App, job_id: str) -> None:
        """Stop *job_id* and wait for its thread, off the UI thread."""
        from sandroid.services.device_actions import stop_job

        stopped = stop_job(job_id)
        try:
            app.call_from_thread(self._stop_done, stopped)
        except Exception:
            logger.debug("Could not show the stop result", exc_info=True)

    def _stop_done(self, stopped: bool) -> None:
        """Show the stop result (UI thread)."""
        if not self._alive():
            return
        self._update_status(
            "[$success]Background action stopped[/]"
            if stopped
            else "[$warning]That action had already ended[/]"
        )
        self.call_later(self._refresh_jobs)
