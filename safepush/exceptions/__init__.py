"""
SafePush exception hierarchy.

All SafePush-specific exceptions inherit from :class:`SafePushError`, which
itself inherits from :class:`Exception`.  This means:

1. Callers can catch all SafePush errors with a single ``except SafePushError``.
2. More specific handlers can catch sub-classes (e.g. ``except ScannerError``).
3. SafePush errors will never be silently swallowed by bare ``except Exception``
   handlers in third-party code that wraps SafePush.

Design principle
----------------
Every exception class carries a human-readable ``message`` and, where relevant,
machine-readable context attributes so that error handlers (CLI formatters,
MCP responses, CI job annotations) can produce rich, actionable output without
parsing string messages.
"""

from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class SafePushError(Exception):
    """Base class for all SafePush-specific exceptions.

    Parameters
    ----------
    message:
        Human-readable description of the error.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r})"


# ---------------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------------


class ConfigurationError(SafePushError):
    """Raised when SafePush configuration is invalid or missing.

    Parameters
    ----------
    message:
        Human-readable description of the configuration problem.
    config_key:
        The specific configuration key that is invalid or missing.
    """

    def __init__(self, message: str, config_key: str | None = None) -> None:
        super().__init__(message)
        self.config_key = config_key


class PluginConfigurationError(ConfigurationError):
    """Raised when a scanner plugin's configuration is invalid.

    Parameters
    ----------
    message:
        Human-readable description.
    plugin_id:
        The ID of the plugin that is misconfigured.
    config_key:
        The specific configuration key that caused the error.
    """

    def __init__(
        self,
        message: str,
        plugin_id: str,
        config_key: str | None = None,
    ) -> None:
        super().__init__(message, config_key)
        self.plugin_id = plugin_id


# ---------------------------------------------------------------------------
# Scanner Errors
# ---------------------------------------------------------------------------


class ScannerError(SafePushError):
    """Base class for errors that originate in scanner plugins.

    Parameters
    ----------
    message:
        Human-readable description.
    scanner_id:
        The ID of the scanner that raised the error.
    """

    def __init__(self, message: str, scanner_id: str) -> None:
        super().__init__(message)
        self.scanner_id = scanner_id


class ScannerNotFoundError(ScannerError):
    """Raised when a requested scanner plugin is not registered.

    Parameters
    ----------
    scanner_id:
        The ID of the scanner that was requested but not found.
    """

    def __init__(self, scanner_id: str) -> None:
        super().__init__(
            f"Scanner '{scanner_id}' is not registered. "
            f"Install the corresponding plugin or check the scanner ID.",
            scanner_id=scanner_id,
        )


class ScannerExecutionError(ScannerError):
    """Raised when a scanner fails during execution.

    This exception represents a *recoverable* per-scanner failure.  The engine
    will catch this exception, record the error in ``ScanResult.errors``, and
    continue running other scanners.

    Parameters
    ----------
    message:
        Human-readable description of the execution failure.
    scanner_id:
        The ID of the failing scanner.
    exit_code:
        Optional process exit code if the scanner is a subprocess.
    """

    def __init__(
        self,
        message: str,
        scanner_id: str,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message, scanner_id)
        self.exit_code = exit_code


class ScannerTimeoutError(ScannerError):
    """Raised when a scanner exceeds its allocated execution time.

    Parameters
    ----------
    scanner_id:
        The ID of the scanner that timed out.
    timeout_seconds:
        The timeout that was exceeded.
    """

    def __init__(self, scanner_id: str, timeout_seconds: int) -> None:
        super().__init__(
            f"Scanner '{scanner_id}' timed out after {timeout_seconds}s. "
            f"Consider increasing the timeout or reducing the scan scope.",
            scanner_id=scanner_id,
        )
        self.timeout_seconds = timeout_seconds


# ---------------------------------------------------------------------------
# Scan Errors
# ---------------------------------------------------------------------------


class ScanError(SafePushError):
    """Base class for errors related to the scan pipeline itself."""


class ScanTargetError(ScanError):
    """Raised when the scan target is invalid or inaccessible.

    Parameters
    ----------
    message:
        Human-readable description.
    path:
        The filesystem path of the invalid target.
    """

    def __init__(self, message: str, path: Path | str) -> None:
        super().__init__(message)
        self.path = Path(path)


class ScanTargetNotFoundError(ScanTargetError):
    """Raised when the scan target path does not exist.

    Parameters
    ----------
    path:
        The path that was not found.
    """

    def __init__(self, path: Path | str) -> None:
        p = Path(path)
        super().__init__(
            f"Scan target does not exist: '{p}'. "
            f"Verify the path is correct and accessible.",
            path=p,
        )


# ---------------------------------------------------------------------------
# Report Errors
# ---------------------------------------------------------------------------


class ReportError(SafePushError):
    """Base class for errors that occur during report generation."""


class UnsupportedReportFormatError(ReportError):
    """Raised when a requested report format has no registered renderer.

    Parameters
    ----------
    format_name:
        The name of the unsupported format.
    supported_formats:
        List of format names that *are* supported.
    """

    def __init__(self, format_name: str, supported_formats: list[str]) -> None:
        super().__init__(
            f"Report format '{format_name}' is not supported. "
            f"Supported formats: {', '.join(supported_formats)}."
        )
        self.format_name = format_name
        self.supported_formats = supported_formats


# ---------------------------------------------------------------------------
# Plugin System Errors
# ---------------------------------------------------------------------------


class PluginError(SafePushError):
    """Base class for errors in the plugin system."""


class PluginRegistrationError(PluginError):
    """Raised when a plugin cannot be registered with the plugin registry.

    Parameters
    ----------
    message:
        Human-readable description.
    plugin_id:
        The ID of the plugin that failed to register.
    """

    def __init__(self, message: str, plugin_id: str) -> None:
        super().__init__(message)
        self.plugin_id = plugin_id


class DuplicatePluginError(PluginRegistrationError):
    """Raised when two plugins with the same ID are registered.

    Parameters
    ----------
    plugin_id:
        The duplicate plugin ID.
    """

    def __init__(self, plugin_id: str) -> None:
        super().__init__(
            f"A plugin with ID '{plugin_id}' is already registered. "
            f"Plugin IDs must be globally unique.",
            plugin_id=plugin_id,
        )
