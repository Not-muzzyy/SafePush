"""
SafePush scanner plugin protocol and base class.

This module defines the *interface contract* that all scanner plugins must
implement.  It is intentionally the only file in the scanner package that
the core engine imports — every concrete scanner lives in a separate plugin
package that depends on ``safepush-core`` but is **not** depended upon by it.

Architecture
------------
The scanner interface uses Python's :class:`typing.Protocol` for structural
subtyping.  This means:

* Plugin authors do not need to import or inherit from anything in ``safepush``
  to satisfy the interface.
* The engine can load plugins via entry points without creating circular
  dependencies.
* Third-party wrappers around existing tools (Semgrep, Gitleaks, etc.) can
  implement the protocol with minimal boilerplate.

For plugin authors who *want* a convenient base class with sensible defaults,
:class:`BaseScanner` is provided.  Using it is optional.

Plugin discovery
----------------
SafePush uses Python :pep:`entry_points` for plugin discovery.  A third-party
scanner package registers itself by adding an entry point in its own
``pyproject.toml``::

    [project.entry-points."safepush.scanners"]
    my-scanner = "my_scanner_package:MyScannerClass"

The :class:`~safepush.plugins.registry.ScannerRegistry` loads all entry points
under the ``safepush.scanners`` group at startup.
"""

from __future__ import annotations

import abc
import logging
from typing import Protocol, Sequence, runtime_checkable

from safepush.models.finding import Finding
from safepush.models.scan import ScanRequest

logger = logging.getLogger(__name__)


@runtime_checkable
class ScannerProtocol(Protocol):
    """Structural protocol that all SafePush scanner plugins must satisfy.

    A scanner is any object that:
    1. Has a unique :attr:`scanner_id` string property.
    2. Has a :attr:`version` string property.
    3. Implements :meth:`scan` to accept a :class:`~safepush.models.scan.ScanRequest`
       and return a sequence of :class:`~safepush.models.finding.Finding` objects.
    4. Implements :meth:`is_available` to report whether its backend tool is
       installed and ready to run.

    This is a :func:`~typing.runtime_checkable` protocol, meaning
    ``isinstance(obj, ScannerProtocol)`` works at runtime.
    """

    @property
    def scanner_id(self) -> str:
        """Unique, stable identifier for this scanner.

        The ``scanner_id`` is used throughout the pipeline for:
        * Plugin registry lookups
        * ``ScanResult.scanner_versions`` keys
        * Finding ``source_scanner`` values
        * Suppression rule matching

        Must be a non-empty string, lowercase, using only letters, digits, and
        hyphens (e.g. ``"semgrep"``, ``"gitleaks"``, ``"custom-secrets"``).
        """
        ...

    @property
    def version(self) -> str:
        """Version string of this scanner plugin or its backend tool.

        Embedded in :attr:`~safepush.models.scan.ScanResult.scanner_versions`
        for auditability and reproducibility.
        """
        ...

    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        """Execute the scan and return all findings.

        Parameters
        ----------
        request:
            The :class:`~safepush.models.scan.ScanRequest` describing the scan
            target and configuration.

        Returns
        -------
        Sequence[Finding]
            All findings produced by this scanner for the given request.  An
            empty sequence is valid and indicates a clean scan.

        Raises
        ------
        safepush.exceptions.ScannerExecutionError
            If the scanner encounters a fatal error it cannot recover from.
        safepush.exceptions.ScannerTimeoutError
            If the scanner exceeds its time allocation.
        """
        ...

    def is_available(self) -> bool:
        """Return True if the scanner's backend tool is installed and runnable.

        The engine calls this method before dispatching a scan.  If a scanner
        returns False, the engine will:
        * Log a warning with installation guidance.
        * Skip the scanner (findings will be empty for this scanner_id).
        * Record the unavailability in ``ScanResult.errors``.

        Returns
        -------
        bool
            True if the scanner is ready to run, False otherwise.
        """
        ...


class BaseScanner(abc.ABC):
    """Convenient abstract base class for SafePush scanner plugins.

    Plugin authors MAY inherit from this class to get:
    * A logger pre-configured with the scanner's ID.
    * Default implementations of :meth:`is_available` (returns True).
    * The structural guarantee that the class satisfies :class:`ScannerProtocol`.

    Using this class is entirely optional — a plain class that implements
    the :class:`ScannerProtocol` attributes and methods is equally valid.
    """

    @property
    @abc.abstractmethod
    def scanner_id(self) -> str:
        """Unique, stable identifier for this scanner."""
        ...

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Version string of this scanner plugin."""
        ...

    @abc.abstractmethod
    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        """Execute the scan and return all findings.

        Parameters
        ----------
        request:
            The ScanRequest describing the scan target and configuration.

        Returns
        -------
        Sequence[Finding]
            Findings produced by this scanner.
        """
        ...

    def is_available(self) -> bool:
        """Return True by default.

        Override this method in subclasses that depend on external binaries or
        services (e.g. Semgrep, Gitleaks) to provide a real availability check.

        Returns
        -------
        bool
            True — subclasses override this with real availability checks.
        """
        return True

    @property
    def _logger(self) -> logging.Logger:
        """Return a logger namespaced to this scanner.

        Returns
        -------
        logging.Logger
            Logger with name ``safepush.scanner.<scanner_id>``.
        """
        return logging.getLogger(f"safepush.scanner.{self.scanner_id}")
