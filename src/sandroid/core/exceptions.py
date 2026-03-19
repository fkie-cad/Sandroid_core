"""Custom exceptions for Sandroid core modules."""


class SandroidError(Exception):
    """Base exception for all Sandroid errors."""


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
