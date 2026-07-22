"""TUI Modal dialogs for Sandroid.

This package provides Textual-native modal dialogs that replace
Rich-based dialogs when running in TUI mode.
"""

# MonitorConfig is canonically defined in the controller; re-export for convenience
from sandroid.tui.controllers.monitor_controller import MonitorConfig

from .apk_install_modal import APKInstallModal, APKInstallResult
from .apk_selection_modal import APKSelectionModal, APKSelectionResult
from .app_selection_modal import AppSelectionModal, AppSelectionResult
from .avd_selection_modal import AVDInfo, AVDSelectionModal, AVDSelectionResult
from .boot_mode_modal import (
    BootMode,
    BootModeResult,
    BootModeSelectionModal,
    SnapshotInfo,
    SnapshotSelectionModal,
    SnapshotSelectionResult,
)
from .confirm_modal import ConfirmModal
from .device_info_modal import DeviceInfoModal
from .device_modal import DeviceSelectionModal
from .device_settings_modal import DeviceSettingsModal, DeviceSettingsResult
from .device_switch_modal import (
    DeviceSwitchConfirmModal,
    DeviceSwitchContext,
    DeviceSwitchResult,
)
from .diff_zoom_modal import DiffZoomModal
from .export_modal import ExportModal, ExportResult
from .folder_select_modal import (
    FolderSelectModal,
    FolderSelectResult,
    get_default_forensic_apks_folder,
)
from .forensic_apk_modal import ForensicAPKAction, ForensicAPKModal
from .frida_install_modal import (
    FridaInstallModal,
    FridaInstallResult,
    ensure_frida_running,
)
from .input_modal import InputModal
from .install_warning_modal import InstallWarningModal, InstallWarningResult
from .ioc_choice_modal import IOCChoiceModal, IOCChoiceResult
from .ioc_setup_modal import IOCSetupModal, IOCSetupResult
from .message_modal import ErrorModal, MessageModal
from .mitmproxy_addons_modal import MitmproxyAddonsModal, MitmproxyAddonsResult
from .monitor_modal import MonitorConfigModal
from .mvt_results_modal import MVTResultsAction, MVTResultsModal
from .network_capture_modal import NetworkCaptureModal, NetworkCaptureResult
from .objection_modal import ObjectionConfig, ObjectionModal, build_objection_command
from .proxy_modal import ProxyModal, ProxyModalResult
from .quit_modal import QuitConfirmModal
from .recording_modal import RecordingModal, RecordingResult
from .scan_progress_modal import ScanProgressModal, ScanProgressResult
from .screen_recording_modal import ScreenRecordingModal, ScreenRecordingResult
from .screenshot_modal import ScreenshotModal, ScreenshotResult
from .selection_modal import SelectionModal
from .snapshot_save_choice_modal import (
    SnapshotSaveChoiceModal,
    SnapshotSaveChoiceResult,
)
from .spawn_mode_modal import SpawnModeModal
from .toggle_modal import FridaToggleConfigModal, ToggleConfigModal
from .tool_selection_modal import ToolSelectionModal
from .trigdroid_modal import SpawnMode, TrigDroidConfig, TrigDroidModal

__all__ = [
    "APKInstallModal",
    "APKInstallResult",
    "APKSelectionModal",
    "APKSelectionResult",
    "AVDInfo",
    "AVDSelectionModal",
    "AVDSelectionResult",
    "AppSelectionModal",
    "AppSelectionResult",
    "BootMode",
    "BootModeResult",
    "BootModeSelectionModal",
    "ConfirmModal",
    "DeviceInfoModal",
    "DeviceSelectionModal",
    "DeviceSettingsModal",
    "DeviceSettingsResult",
    "DeviceSwitchConfirmModal",
    "DeviceSwitchContext",
    "DeviceSwitchResult",
    "DiffZoomModal",
    "ErrorModal",
    "ExportModal",
    "ExportResult",
    "FolderSelectModal",
    "FolderSelectResult",
    "ForensicAPKAction",
    "ForensicAPKModal",
    "FridaInstallModal",
    "FridaInstallResult",
    "FridaToggleConfigModal",
    "IOCChoiceModal",
    "IOCChoiceResult",
    "IOCSetupModal",
    "IOCSetupResult",
    "InputModal",
    "InstallWarningModal",
    "InstallWarningResult",
    "MVTResultsAction",
    "MVTResultsModal",
    "MessageModal",
    "MitmproxyAddonsModal",
    "MitmproxyAddonsResult",
    "MonitorConfig",
    "MonitorConfigModal",
    "NetworkCaptureModal",
    "NetworkCaptureResult",
    "ObjectionConfig",
    "ObjectionModal",
    "ProxyModal",
    "ProxyModalResult",
    "QuitConfirmModal",
    "RecordingModal",
    "RecordingResult",
    "ScanProgressModal",
    "ScanProgressResult",
    "ScreenRecordingModal",
    "ScreenRecordingResult",
    "ScreenshotModal",
    "ScreenshotResult",
    "SelectionModal",
    "SnapshotInfo",
    "SnapshotSaveChoiceModal",
    "SnapshotSaveChoiceResult",
    "SnapshotSelectionModal",
    "SnapshotSelectionResult",
    "SpawnMode",
    "SpawnModeModal",
    "ToggleConfigModal",
    "ToolSelectionModal",
    "TrigDroidConfig",
    "TrigDroidModal",
    "build_objection_command",
    "ensure_frida_running",
    "get_default_forensic_apks_folder",
]
