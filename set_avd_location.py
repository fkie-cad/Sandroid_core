#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import ssl
import certifi
import subprocess
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderServiceError


class AndroidLocationManager:
    def __init__(self, device_id=None, is_magisk_mode=False):
        """
        :param device_id:     E.g. "emulator-5554" or a real device ID.
        :param is_magisk_mode: If True, run 'su -c' commands for Magisk; otherwise 'su 0'.
        """
        self.device_id = device_id
        self.is_magisk_mode = is_magisk_mode

    def adb_check_root(self) -> bool:
        """
        A placeholder function that checks if the device is actually rooted.
        Return True if rooted, False otherwise.

        Implementation can vary: you could run `adb shell su -c id`, parse output, etc.
        For demonstration, we simply return True. Modify as needed.
        """
        # Example check: see if "su" binary is accessible. (Simplistic!)
        cmd = ["adb"]
        if self.device_id:
            cmd += ["-s", self.device_id]
        # We attempt a trivial root-check command
        cmd += ["shell", "which", "su"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and "su" in result.stdout.strip():
            return True
        return False

    def run_adb_command_as_root(self, command: str):
        """
        Runs the given `command` as root via su on the Android device.

        :param command: e.g. 'setprop persist.sys.timezone "Europe/Berlin"'
        :return: CompletedProcess with stdout/stderr
        """
        adb_command = ['adb']
        if self.device_id:
            adb_command.extend(['-s', self.device_id])

        # Check if device is rooted
        if not self.adb_check_root():
            print("[ERROR] Non-rooted device. Please root it before proceeding. "
                  "Ensure you can run 'su' on the device.")
            sys.exit(2)

        # Decide if we should run 'su -c ...' vs 'su 0 ...'
        if self.is_magisk_mode:
            full_cmd = adb_command + ['shell', f'su -c {command}']
        else:
            full_cmd = adb_command + ['shell', f'su 0 {command}']

        # Run the command
        result = subprocess.run(full_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # Improved error message
            print(f"[ERROR] Root command failed.\n"
                  f"  Command: {full_cmd}\n"
                  f"  Return code: {result.returncode}\n"
                  f"  STDOUT: {result.stdout}\n"
                  f"  STDERR: {result.stderr}")
        else:
            print(f"[OK] Ran root command successfully: {command}")
        return result

    def run_adb_command_no_root(self, command_list):
        """
        For commands which do NOT require root (like 'adb emu geo fix').
        :param command_list: List of strings, e.g. ['emu', 'geo', 'fix', '37.6176', '55.7558']
        """
        adb_command = ['adb']
        if self.device_id:
            adb_command.extend(['-s', self.device_id])
        adb_command.extend(command_list)

        result = subprocess.run(adb_command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Non-root adb command failed.\n"
                  f"  Command: {adb_command}\n"
                  f"  Return code: {result.returncode}\n"
                  f"  STDOUT: {result.stdout}\n"
                  f"  STDERR: {result.stderr}")
        else:
            print(f"[OK] Ran non-root command successfully: {adb_command}")
        return result

    def set_avd_location(self, latitude: float, longitude: float):
        """
        Set the GPS location on the emulator. (Doesn't typically need root.)
        """
        # On standard AVD, we do: adb emu geo fix <longitude> <latitude>
        cmd_list = ['emu', 'geo', 'fix', str(longitude), str(latitude)]
        self.run_adb_command_no_root(cmd_list)

    def set_time_zone(self, tz: str):
        """
        Set the system time zone, e.g. 'Europe/Moscow'.
        Usually requires root on modern Android.
        """
        command = f'setprop persist.sys.timezone "{tz}"'
        self.run_adb_command_as_root(command)

    def set_locale(self, language: str, country: str):
        """
        For older Android images, you might do:
            setprop persist.sys.language <lang>
            setprop persist.sys.country  <COUNTRY>
            stop
            start
        This definitely requires root privileges.
        """
        commands = [
            f'setprop persist.sys.language {language}',
            f'setprop persist.sys.country {country}',
            'stop',
            'start'
        ]
        for cmd in commands:
            self.run_adb_command_as_root(cmd)

    def set_telephony(self, iso_country: str, mnc: str):
        """
        e.g. iso_country='ru', mnc='25001'
        Sets typical telephony props. Requires root.
        """
        props_to_set = {
            "gsm.sim.operator.iso-country": iso_country,
            "gsm.operator.iso-country": iso_country,
            "gsm.sim.operator.numeric": mnc,
            "gsm.operator.numeric": mnc,
        }
        for key, val in props_to_set.items():
            cmd = f'setprop {key} {val}'
            self.run_adb_command_as_root(cmd)

    def geocode_location(self, country: str, city: str):
        """
        Returns (latitude, longitude) by geocoding the given city & country
        using Nominatim (OpenStreetMap).
        """
        ctx = ssl.create_default_context(cafile=certifi.where())
        geolocator = Nominatim(user_agent="avd_location_script", ssl_context=ctx)
        query_string = f"{city}, {country}"
        try:
            location = geolocator.geocode(query_string)
        except GeocoderServiceError as ex:
            print(f"[ERROR] Geocoding service error: {ex}")
            return None
        if location:
            return (location.latitude, location.longitude)
        return None


def main():
    """
    Example usage:
      python3 set_avd_location.py <country_code> <city> [<device_name>]
      or
      python3 set_avd_location.py <latitude> <longitude> [<device_name>]

    The script sets GPS location, then attempts to set time zone, locale, telephony, etc.
    """
    if len(sys.argv) < 3:
        print("Usage:\n"
              "  python set_avd_location.py <country_code> <city> [<device_id>]\n"
              "  OR\n"
              "  python set_avd_location.py <latitude> <longitude> [<device_id>]\n")
        sys.exit(1)

    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    if len(sys.argv) > 3:
        device_id = sys.argv[3]
    else:
        device_id = None

    # Example: we might guess whether we need magisk or not. For demo, false:
    loc_mgr = AndroidLocationManager(device_id=device_id, is_magisk_mode=False)

    try:
        # If the first two args are floats, interpret as lat/lon
        latitude = float(arg1)
        longitude = float(arg2)

        print(f"[INFO] Interpreting as direct lat/lon => lat={latitude}, lon={longitude}")
        loc_mgr.set_avd_location(latitude, longitude)
        print("[INFO] Not setting time zone / locale / telephony because we don't know the country code.")
        return

    except ValueError:
        # Otherwise interpret as country_code + city
        country_code = arg1
        city = arg2
        coords = loc_mgr.geocode_location(country_code, city)
        if not coords:
            print(f"[ERROR] Could not geocode '{city}, {country_code}'.")
            sys.exit(1)

        lat, lon = coords
        print(f"[INFO] Geocoded {city}, {country_code} => lat={lat}, lon={lon}")

        # 1) Set GPS
        loc_mgr.set_avd_location(lat, lon)

        # 2) Set time zone (demo: naive mapping)
        #   In reality you'd have a dictionary or logic to get the correct time zone for the country code.
        #   We'll just do 'Europe/Moscow' if user typed 'ru', etc. You can do your own logic.
        timezone_map = {
            "ru": "Europe/Moscow",
            "de": "Europe/Berlin",
            "us": "America/New_York",
            # ...
        }
        tz = timezone_map.get(country_code.lower())
        if tz:
            loc_mgr.set_time_zone(tz)
        else:
            print(f"[WARN] No time zone mapping for {country_code} - skipping time zone.")

        # 3) Set locale (demo)
        #   Similarly naive approach
        locale_map = {
            "ru": ("ru", "RU"),
            "de": ("de", "DE"),
            "us": ("en", "US"),
            # ...
        }
        if country_code.lower() in locale_map:
            language, ctry = locale_map[country_code.lower()]
            loc_mgr.set_locale(language, ctry)
        else:
            print(f"[WARN] No locale mapping for {country_code} - skipping locale.")

        # 4) Set telephony (demo)
        telephony_map = {
            "ru": ("ru", "25001"),  # ISO 'ru', MNC '25001'
            "de": ("de", "26201"),  # T-Mobile Germany
            "us": ("us", "310030"), # AT&T US
            # ...
        }
        if country_code.lower() in telephony_map:
            iso_cn, mnc = telephony_map[country_code.lower()]
            loc_mgr.set_telephony(iso_cn, mnc)
        else:
            print(f"[WARN] No telephony mapping for {country_code} - skipping telephony.")

        print("[INFO] Done.")


if __name__ == "__main__":
    main()