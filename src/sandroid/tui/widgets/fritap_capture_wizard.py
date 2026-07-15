#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""friTap capture-wizard orchestrator for Sandroid.

Ported from ``friTap/tui/wizard.py`` (``CaptureWizard`` steps 5-7 and their
conditional branching), decoupled from friTap's ``MainScreen`` / ``AppState``.

Because Sandroid already selects the device, target app, and attach-vs-spawn
mode (``DeviceManager`` + ``SpotlightService``), the wizard begins at
**Step 5: Select Capture Mode** — friTap's device / server-check / target-mode /
target-select steps (1-4) are skipped. Selections accumulate into a
:class:`FriTapSessionConfig`; on the final confirmation the config is armed in
``FriTapConfigService`` and the existing friTap start path is triggered
(``action_action_key("h")``), which consumes the armed config.

The transition logic mirrors the standalone wizard exactly:

* keys-only            → skip protocol sub-steps → Output
* tls/auto             → Encapsulated → (plaintext only) QUIC → (plaintext only) View → Output
* non-tls + plaintext  → View → Output
* otherwise            → force view_mode="legacy" → Output
"""

from __future__ import annotations

import logging
from typing import Optional

from sandroid.services import get_fritap_config_service, get_spotlight_service
from sandroid.services.fritap_config_service import FriTapSessionConfig

logger = logging.getLogger(__name__)


class FriTapCaptureWizard:
    """Guided setup wizard for Sandroid friTap capture sessions."""

    # mode_id -> (display, mode_id, default_keylog, default_pcap, is_live)
    # Mirrors CaptureWizard._CAPTURE_MODE_DEFAULTS in friTap/tui/wizard.py.
    _CAPTURE_MODE_DEFAULTS = {
        "full": ("Full Capture", "full", "keys.log", "capture.pcapng", False),
        "keys": ("Key Extraction Only", "keys", "keys.log", "", False),
        "plaintext": ("Plaintext PCAP", "plaintext", "", "plaintext.pcapng", False),
        "wireshark": ("Live Wireshark", "wireshark", "", "", True),
        "live_pcapng": ("Live Wireshark (auto-decrypt)", "live_pcapng", "", "", True),
    }

    def __init__(self, app) -> None:
        """Create the wizard bound to the Textual *app* (drives push_screen)."""
        self._app = app
        self._capture_mode_id: str = ""
        self._cfg = FriTapSessionConfig()
        self._live: bool = False

    def start(self) -> None:
        """Begin the wizard at Step 5 (Select Capture Mode)."""
        self._step_5_capture_mode()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _notify(
        self, message: str, *, title: str = "friTap", severity: str = "information"
    ) -> None:
        """Surface a message via the app's notification system (best-effort)."""
        try:
            self._app.notify(message, title=title, severity=severity)
        except Exception:
            pass

    # =========================================================================
    # Step 5: capture mode
    # =========================================================================

    def _step_5_capture_mode(self) -> None:
        from sandroid.tui.modals.fritap_wizard import CaptureSelectModal

        def _on_result(mode_id: Optional[str]) -> None:
            if mode_id is None:
                # Esc on the first step cancels the wizard (target already chosen
                # upstream in Sandroid; there is no friTap step 4 to return to).
                return
            self._capture_mode_id = mode_id
            self._cfg.capture_mode = mode_id
            self._step_5b_protocol()

        self._app.push_screen(CaptureSelectModal(), callback=_on_result)

    # =========================================================================
    # Step 5b: protocol
    # =========================================================================

    def _step_5b_protocol(self) -> None:
        from sandroid.tui.modals.fritap_wizard import ProtocolSelectModal

        def _on_result(protocol: Optional[str]) -> None:
            if protocol is None:
                self._step_5_capture_mode()
                return
            self._cfg.protocol = protocol
            if protocol != "tls":
                self._notify(f"Protocol: {protocol.upper()}")
            self._warn_protocol_backend(protocol)

            # Conditional branching (identical to friTap wizard _step_5b_protocol):
            if self._capture_mode_id == "keys":
                self._step_6_configure(self._capture_mode_id)
            elif protocol in ("tls", "auto"):
                self._step_5c_encapsulated_protocols()
            elif self._capture_mode_id == "plaintext":
                self._step_5d_view_mode()
            else:
                self._skip_view_mode_to_configure()

        self._app.push_screen(ProtocolSelectModal(), callback=_on_result)

    def _warn_protocol_backend(self, protocol: str) -> None:
        """Warn (notify) when an offline-decryption backend is missing.

        Mirrors the mtproto/telegram/signal dependency hints emitted by friTap's
        ``_step_5b_protocol``. Best-effort: any import/availability error is
        swallowed so the wizard never breaks on an optional backend.
        """
        try:
            if protocol in ("mtproto", "telegram"):
                from friTap.offline.mtproto import (
                    MTPROTO_DEPENDENCY_HINT,
                    mtproto_backend_available,
                )

                if not mtproto_backend_available():
                    self._notify(
                        MTPROTO_DEPENDENCY_HINT,
                        title=f"{protocol.capitalize()} dependency missing",
                        severity="warning",
                    )
            elif protocol == "signal":
                from friTap.offline.signal import (
                    SIGNAL_DEPENDENCY_HINT,
                    signal_backend_available,
                )

                if not signal_backend_available():
                    self._notify(
                        SIGNAL_DEPENDENCY_HINT,
                        title="Signal dependency missing",
                        severity="warning",
                    )
        except Exception as exc:  # optional backend not present
            logger.debug("Protocol backend availability check skipped: %s", exc)

    # =========================================================================
    # Step 5c: encapsulated protocols (TLS/auto only)
    # =========================================================================

    def _step_5c_encapsulated_protocols(self) -> None:
        from sandroid.tui.modals.fritap_wizard import EncapsulatedProtocolModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                self._step_5b_protocol()
                return
            if result:
                self._cfg.encapsulated_protocols = result
            if self._capture_mode_id == "plaintext":
                self._step_5c2_quic_capture_mode()
            else:
                self._skip_view_mode_to_configure()

        self._app.push_screen(EncapsulatedProtocolModal(), callback=_on_result)

    # =========================================================================
    # Step 5c2: QUIC capture mode (TLS/auto + plaintext only)
    # =========================================================================

    def _step_5c2_quic_capture_mode(self) -> None:
        from sandroid.tui.modals.fritap_wizard import QuicCaptureModeModal

        def _on_result(mode: Optional[str]) -> None:
            if mode is None:
                self._step_5c_encapsulated_protocols()
                return
            self._cfg.quic_capture_mode = mode
            if mode != "stream":
                self._notify(f"QUIC capture mode: {mode}")
            self._step_5d_view_mode()

        self._app.push_screen(QuicCaptureModeModal(), callback=_on_result)

    # =========================================================================
    # Step 5d: view mode (skipped for keys-only)
    # =========================================================================

    def _step_5d_view_mode(self) -> None:
        from sandroid.tui.modals.fritap_wizard import ViewModeModal

        def _on_result(view_mode: Optional[str]) -> None:
            if view_mode is None:
                # 5d is only reached in plaintext mode; tls/auto always passed
                # through the QUIC capture-mode step, others came from 5b.
                if self._cfg.protocol in ("tls", "auto"):
                    self._step_5c2_quic_capture_mode()
                else:
                    self._step_5b_protocol()
                return
            self._cfg.view_mode = view_mode
            if view_mode != "legacy":
                self._notify(f"Display mode: {view_mode}")
            self._step_6_configure(self._capture_mode_id)

        self._app.push_screen(ViewModeModal(), callback=_on_result)

    def _skip_view_mode_to_configure(self) -> None:
        """Force legacy view for non-plaintext modes, then go to Output."""
        self._cfg.view_mode = "legacy"
        self._step_6_configure(self._capture_mode_id)

    # =========================================================================
    # Step 6: output paths
    # =========================================================================

    def _step_6_configure(self, mode_id: str) -> None:
        from sandroid.tui.modals.fritap_wizard import CaptureModeModal

        display, mid, default_keylog, default_pcap, is_live = (
            self._CAPTURE_MODE_DEFAULTS[mode_id]
        )

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                self._step_5_capture_mode()
                return
            self._apply_mode(result)
            self._step_7_confirm()

        self._app.push_screen(
            CaptureModeModal(
                mode_id=mid,
                mode_display=display,
                default_keylog=default_keylog,
                default_pcap=default_pcap,
                is_live=is_live,
            ),
            callback=_on_result,
        )

    def _apply_mode(self, result: dict) -> None:
        """Store the output-path / live result from the CaptureModeModal."""
        self._cfg.keylog_path = result.get("keylog") or None
        self._cfg.pcap_path = result.get("pcap") or None
        self._live = bool(result.get("live", False))

    # =========================================================================
    # Step 7: confirm & start
    # =========================================================================

    def _step_7_confirm(self) -> None:
        from sandroid.tui.modals.fritap_wizard import StartConfirmModal

        confirm_modal = StartConfirmModal(summary=self._build_summary())

        def _on_result(confirmed: Optional[bool]) -> None:
            if confirmed is None:
                # Back -> re-pick capture mode (not just re-edit paths).
                self._step_5_capture_mode()
                return
            # Apply the toggles the confirm screen owns.
            self._cfg.verbose = confirm_modal.verbose
            self._cfg.experimental = confirm_modal.experimental
            self._cfg.library_scan = confirm_modal.library_scan
            self._cfg.debug_log = confirm_modal.debug_log
            self._finish_and_start()

        self._app.push_screen(confirm_modal, callback=_on_result)

    def _build_summary(self) -> dict:
        """Build the summary dict consumed by StartConfirmModal."""
        spotlight = get_spotlight_service()
        target_name = spotlight.get_effective_package() or "Unknown"
        target_mode = "spawn" if spotlight.is_spawn_mode() else "attach"
        device_name, device_type = self._device_info()
        display = self._CAPTURE_MODE_DEFAULTS.get(
            self._capture_mode_id, ("Custom", "", "", "", False)
        )[0]
        return {
            "device_name": device_name,
            "device_type": device_type,
            "target_name": target_name,
            "target_mode": target_mode,
            "capture_mode_display": display,
            "keylog_path": self._cfg.keylog_path or "",
            "pcap_path": self._cfg.pcap_path or "",
            "live": self._live,
            "capture_mode_id": self._capture_mode_id,
            "verbose": self._cfg.verbose,
            "protocol": self._cfg.protocol,
            "experimental": self._cfg.experimental,
            "library_scan": self._cfg.library_scan,
            "debug_log": self._cfg.debug_log,
            "quic_capture_mode": self._cfg.quic_capture_mode,
        }

    @staticmethod
    def _device_info() -> tuple[str, str]:
        """Return (device_name, device_type) for the active Sandroid device."""
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            dev = getattr(dm, "active_device", None)
            if dev is not None:
                name = getattr(dev, "display_name", None) or getattr(
                    dev, "serial", "Unknown"
                )
                dtype = getattr(dev, "device_type", "usb") or "usb"
                return str(name), str(dtype)
        except Exception as exc:
            logger.debug("Active-device lookup failed: %s", exc)
        return "Unknown", "local"

    def _finish_and_start(self) -> None:
        """Arm the collected config and trigger the existing friTap start path."""
        svc = get_fritap_config_service()
        svc.set_pending(self._cfg)
        svc.mark_configured()
        self._notify("friTap wizard complete — starting capture")
        try:
            self._app.action_action_key("h")
        except Exception as exc:
            logger.error("Failed to trigger friTap start after wizard: %s", exc)
            self._notify("Failed to start friTap", severity="error")
