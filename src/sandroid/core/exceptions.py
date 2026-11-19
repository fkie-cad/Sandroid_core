"""Custom exceptions for Sandroid core modules."""


class SandroidError(Exception):
    """Base exception for all Sandroid errors."""


class DeviceNotAvailableError(SandroidError):
    """The requested (or any) Android device is not connected and online.

    Raised before any device work starts, so a headless run never documents
    evidence for a device it could not reach.
    """


class MultipleDevicesError(DeviceNotAvailableError):
    """More than one device is online and none was chosen explicitly.

    Raised by :func:`sandroid.core.initializer.initialize_core` before any
    device work (no ``adb root``, ``setenforce``, Frida), so Sandroid never
    guesses which of several devices -- possibly another session's emulator
    -- to prepare. The TUI answers it with the device picker; headless and
    CLI modes report it and exit.

    Attributes:
        serials: The online (``state == "device"``) serials, in adb order.
    """

    def __init__(self, serials: list[str]):
        self.serials = list(serials)
        super().__init__(
            f"More than one device is connected ({', '.join(self.serials)}) and "
            "none was selected. Choose one with --serial SERIAL, $ANDROID_SERIAL "
            "or emulator.serial in the config."
        )


class DeviceTimeError(SandroidError, RuntimeError):
    """The device time (``adb shell date +%s``) could not be read.

    Typical right after a snapshot load, while adb still reports the device
    as "authorizing". A normal exception (never ``SystemExit``): it is raised
    on worker threads, where ``SystemExit`` would end the whole TUI. A CLI
    reports it and exits non-zero at the top level.
    """


class APKDownloadError(SandroidError):
    """Base exception for APK download errors."""


class APKNotFoundError(APKDownloadError):
    """Raised when an APK package cannot be found in the repository."""

    def __init__(self, package_name: str, message: str | None = None):
        self.package_name = package_name
        self.message = (
            message or f"Package '{package_name}' not found in APK repository"
        )
        super().__init__(self.message)


class APKVersionNotFoundError(APKDownloadError):
    """Raised when a specific APK version cannot be found."""

    def __init__(
        self,
        package_name: str,
        version: str,
        available_versions: list[str] | None = None,
    ):
        self.package_name = package_name
        self.version = version
        self.available_versions = available_versions or []
        self.message = f"Version '{version}' not found for package '{package_name}'"
        if self.available_versions:
            self.message += f". Available: {', '.join(self.available_versions[:5])}"
        super().__init__(self.message)


class APKInstallError(APKDownloadError):
    """Raised when APK installation fails."""

    def __init__(self, package_name: str, reason: str):
        self.package_name = package_name
        self.reason = reason
        super().__init__(f"Failed to install '{package_name}': {reason}")


class APKNetworkError(APKDownloadError):
    """Raised when network errors occur during APK operations."""

    def __init__(self, message: str, original_error: Exception | None = None):
        self.original_error = original_error
        super().__init__(message)
