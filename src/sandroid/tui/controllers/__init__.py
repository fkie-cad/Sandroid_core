"""TUI Controllers Package.

This package contains controller classes extracted from the monolithic app.py,
following the Single Responsibility Principle for better testability and maintainability.

Controllers:
    - APKInstallController: APK installation and post-install setup
    - DeviceController: Device/AVD lifecycle management
    - ForensicController: Forensic scanning orchestration
    - ForensicAPKController: Forensic APK management (pull, install, manage)
    - FSMonController: Filesystem monitoring
    - NetworkCaptureController: Network capture toggle, start/stop
    - ObjectionResumeController: Objection session resumption
    - ProxyController: Proxy configuration
    - QuitController: Quit/exit orchestration
    - RecordingController: Input recording and playback
    - ScreenshotController: Screenshot operations
    - SpotlightController: Spotlight files management
    - TrigDroidController: TrigDroid bypass management
    - WidgetRefreshController: Widget refresh operations

Usage:
    from sandroid.tui.controllers import (
        APKInstallController,
        DeviceController,
        ForensicController,
        RecordingController,
        FSMonController,
        NetworkCaptureController,
        ObjectionResumeController,
        ProxyController,
        QuitController,
        ScreenshotController,
        SpotlightController,
        TrigDroidController,
        ForensicAPKController,
        WidgetRefreshController,
    )

    # Create controller with UI callbacks
    controller = RecordingController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        log_error=activity_log.log_error,
        push_modal=app.push_screen,
        run_worker=app.run_worker,
        call_from_thread=app.call_from_thread,
    )

    # Use controller methods
    controller.start_recording()
"""

from .apk_install_controller import APKInstallController
from .device_controller import DeviceController
from .forensic_apk_controller import ForensicAPK, ForensicAPKController, MVTResult
from .forensic_controller import ForensicController, ScanProgress, ScanResult
from .fsmon_controller import FSMonConfig, FSMonController
from .network_capture_controller import NetworkCaptureController
from .objection_resume_controller import ObjectionResumeController
from .proxy_controller import ProxyController
from .quit_controller import QuitController
from .recording_controller import PlaybackResult, RecordingController, RecordingResult
from .screenshot_controller import ScreenshotController
from .settings_controller import SettingsController
from .spotlight_controller import SpotlightController, SpotlightFilesAction
from .spotlight_selection_ui import SpotlightSelectionUI
from .trigdroid_controller import TrigDroidConfig, TrigDroidController
from .widget_refresh_controller import WidgetRefreshController

__all__ = [
    # APK Install
    "APKInstallController",
    # Device
    "DeviceController",
    "FSMonConfig",
    # FSMon
    "FSMonController",
    "ForensicAPK",
    # Forensic APK
    "ForensicAPKController",
    # Forensic
    "ForensicController",
    "MVTResult",
    # Network Capture
    "NetworkCaptureController",
    # Objection Resume
    "ObjectionResumeController",
    "PlaybackResult",
    # Proxy
    "ProxyController",
    # Quit
    "QuitController",
    # Recording
    "RecordingController",
    "RecordingResult",
    "ScanProgress",
    "ScanResult",
    # Screenshot
    "ScreenshotController",
    # Settings
    "SettingsController",
    # Spotlight
    "SpotlightController",
    "SpotlightFilesAction",
    "SpotlightSelectionUI",
    "TrigDroidConfig",
    # TrigDroid
    "TrigDroidController",
    # Widget Refresh
    "WidgetRefreshController",
]
