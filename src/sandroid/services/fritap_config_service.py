"""friTap capture-session configuration service for Sandroid.

Holds the *armed* capture configuration that the TUI "friTap" tab collects via
the multi-step capture wizard, so the panel can drive a friTap session
**without** the legacy interactive (Rich / Textual-toggle) configuration prompt.

This is an additive bridge mirroring :mod:`sandroid.services.dexray_config_service`.
When the wizard finishes and arms a configuration (``mark_configured``),
``FriTapCommand._start_fritap`` consults this service (via
``consume_panel_config``) and passes the collected settings straight to
``FriTap.start(interactive=False, session_config=...)``. The flag is
**one-shot** — cleared the instant the command consumes it — so a
terminal/headless ``h`` invocation always falls back to the existing
interactive flow. Nothing in the interactive path is removed.

Thread safety:
    The wizard mutates configuration on the Textual UI thread; the command
    reads it on a worker thread (``FriTapCommand`` runs with
    ``is_blocking_io=True``). All reads/writes are guarded by an ``RLock`` and
    :meth:`consume_panel_config` returns an independent copy so a live capture
    run owns its own snapshot.

Usage:
    from sandroid.services import get_fritap_config_service

    svc = get_fritap_config_service()

    # Wizard (UI thread): build + arm.
    svc.set_pending(FriTapSessionConfig(capture_mode="full", protocol="tls"))
    svc.mark_configured()

    # Command (worker thread): consume once, then fall back if None.
    armed = svc.consume_panel_config()
    if armed is not None:
        ...  # armed is a FriTapSessionConfig
"""

import logging
import threading
from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FriTapSessionConfig:
    """The set of capture settings the friTap wizard collects.

    Mirrors the fields the standalone friTap TUI wizard accumulates in its
    ``AppState`` (see ``friTap/tui/wizard.py`` steps 5-7), reduced to the
    settings relevant once the device / target app / attach-vs-spawn choice is
    already made in Sandroid (``SpotlightService`` + ``DeviceManager``).
    """

    # Capture mode: one of "full" | "keys" | "plaintext" | "wireshark" | "live_pcapng"
    capture_mode: str = "full"
    # Protocol: "tls" | "ipsec" | "ssh" | "mtproto" | "telegram" | "signal" | "auto"
    protocol: str = "tls"
    # Output paths (None lets FriTap derive defaults under <device>/fritap/).
    keylog_path: Optional[str] = None
    pcap_path: Optional[str] = None
    # Encapsulated-protocol decryption toggles (TLS/auto only).
    encapsulated_protocols: dict = field(default_factory=lambda: {"ohttp": True})
    # QUIC plaintext-capture boundary: "stream" | "app-api".
    quic_capture_mode: str = "stream"
    # Display mode for the friTap output: "legacy" | "flow".
    view_mode: str = "legacy"
    # Toggle flags collected on the confirm screen.
    verbose: bool = False
    debug_log: bool = False
    library_scan: bool = False
    experimental: bool = False


class FriTapConfigService:
    """Process-wide store for the friTap tab's armed capture config.

    Holds a single :class:`FriTapSessionConfig` plus a one-shot
    "configured from panel" intent flag, both guarded by an ``RLock``.
    """

    def __init__(self) -> None:
        """Initialise with a default config and the armed flag cleared."""
        self._lock = threading.RLock()
        self._pending: FriTapSessionConfig = FriTapSessionConfig()
        self._configured_from_panel = False

    # =========================================================================
    # Wizard-facing API (Textual UI thread)
    # =========================================================================

    @property
    def pending(self) -> FriTapSessionConfig:
        """The current (not-yet-armed) config the wizard is building.

        Returned by reference so the wizard can mutate fields incrementally as
        the user walks the steps. Call :meth:`mark_configured` to arm it.
        """
        return self._pending

    def set_pending(self, config: FriTapSessionConfig) -> None:
        """Replace the working config with *config* (does not arm it)."""
        with self._lock:
            self._pending = config

    def update_pending(self, **fields) -> FriTapSessionConfig:
        """Update individual fields on the working config; return the new one."""
        with self._lock:
            self._pending = replace(self._pending, **fields)
            return self._pending

    def mark_configured(self) -> None:
        """Arm the working config so the next friTap start consumes it.

        One-shot: cleared by :meth:`consume_panel_config`.
        """
        with self._lock:
            self._configured_from_panel = True

    def reset(self) -> None:
        """Reset the working config to defaults and clear the armed flag."""
        with self._lock:
            self._pending = FriTapSessionConfig()
            self._configured_from_panel = False
        logger.debug("FriTapConfigService reset to defaults")

    # =========================================================================
    # Command-facing API (worker thread)
    # =========================================================================

    def is_configured_from_panel(self) -> bool:
        """Whether a panel config is currently armed (does not consume it)."""
        with self._lock:
            return self._configured_from_panel

    def consume_panel_config(self) -> Optional[FriTapSessionConfig]:
        """Atomically read the armed config and clear the flag (one-shot).

        Returns:
            An independent copy of the armed :class:`FriTapSessionConfig`, or
            ``None`` if no panel config was armed. The copy is deep so the
            caller owns its own snapshot for the lifetime of the run.
        """
        with self._lock:
            if not self._configured_from_panel:
                return None
            self._configured_from_panel = False  # one-shot
            return deepcopy(self._pending)


__all__ = [
    "FriTapConfigService",
    "FriTapSessionConfig",
]
