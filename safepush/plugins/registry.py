"""
Scanner plugin registry for SafePush.

The :class:`ScannerRegistry` is the central catalogue of all available scanner
plugins.  The core engine depends **only** on this registry — it never imports
concrete scanner implementations.

Design decisions
----------------
* **Singleton-friendly but not forced**: The registry is a normal class.
  The application creates one instance at startup via the :class:`~safepush.core.
  engine.ScanEngine`.  Tests can create isolated registry instances without
  touching global state.
* **Entry-point discovery**: :meth:`ScannerRegistry.discover` loads plugins
  declared under the ``safepush.scanners`` entry-point group, enabling
  zero-configuration plugin installation.
* **Explicit registration**: :meth:`ScannerRegistry.register` allows
  programmatic registration for testing and embedded usage.
* **Thread safety**: The internal dictionary is protected by a
  :class:`threading.RLock` so that concurrent plugin loading is safe.
"""

from __future__ import annotations

import importlib.metadata
import logging
import threading
from typing import Iterator

from safepush.exceptions import (
    DuplicatePluginError,
    PluginRegistrationError,
    ScannerNotFoundError,
)
from safepush.scanner import ScannerProtocol

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "safepush.scanners"


class ScannerRegistry:
    """Thread-safe registry of SafePush scanner plugins.

    The registry maps ``scanner_id → scanner_instance``.  It is the single
    source of truth for which scanners are available at runtime.

    Usage
    -----
    Typical application startup::

        registry = ScannerRegistry()
        registry.discover()          # load entry-point plugins
        registry.register(MyScanner())  # optional: add custom scanner

        scanner = registry.get("semgrep")
        all_scanners = list(registry.all())

    Test isolation::

        registry = ScannerRegistry()          # fresh, empty instance
        registry.register(FakeScanner())      # inject test double
    """

    def __init__(self) -> None:
        self._scanners: dict[str, ScannerProtocol] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, scanner: ScannerProtocol, *, overwrite: bool = False) -> None:
        """Register a scanner plugin instance.

        Parameters
        ----------
        scanner:
            An object implementing :class:`~safepush.scanner.ScannerProtocol`.
        overwrite:
            If True, silently replace an existing scanner with the same ID.
            If False (default), raise :class:`~safepush.exceptions.DuplicatePluginError`.

        Raises
        ------
        safepush.exceptions.PluginRegistrationError
            If the scanner does not satisfy :class:`~safepush.scanner.ScannerProtocol`.
        safepush.exceptions.DuplicatePluginError
            If a scanner with the same ID is already registered and
            ``overwrite`` is False.
        """
        if not isinstance(scanner, ScannerProtocol):
            raise PluginRegistrationError(
                f"Object of type '{type(scanner).__name__}' does not implement "
                f"ScannerProtocol. Ensure scanner_id, version, scan(), and "
                f"is_available() are implemented.",
                plugin_id=getattr(scanner, "scanner_id", "<unknown>"),
            )

        scanner_id = scanner.scanner_id
        self._validate_scanner_id(scanner_id)

        with self._lock:
            if scanner_id in self._scanners and not overwrite:
                raise DuplicatePluginError(scanner_id)
            self._scanners[scanner_id] = scanner

        logger.debug("Registered scanner '%s' (version=%s)", scanner_id, scanner.version)

    def unregister(self, scanner_id: str) -> None:
        """Remove a scanner from the registry.

        Parameters
        ----------
        scanner_id:
            The ID of the scanner to remove.

        Raises
        ------
        safepush.exceptions.ScannerNotFoundError
            If no scanner with the given ID is registered.
        """
        with self._lock:
            if scanner_id not in self._scanners:
                raise ScannerNotFoundError(scanner_id)
            del self._scanners[scanner_id]
        logger.debug("Unregistered scanner '%s'", scanner_id)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    @classmethod
    def discover(cls) -> "ScannerRegistry":
        """Create a new registry populated from installed entry-point plugins.

        This method loads all entry points under the ``safepush.scanners``
        group and attempts to instantiate and register each one.

        Failed entry points are logged as warnings but do not prevent other
        plugins from loading.

        Returns
        -------
        ScannerRegistry
            A new registry instance containing all successfully loaded plugins.

        Examples
        --------
        ::

            registry = ScannerRegistry.discover()
            # All installed safepush-* scanner packages are now available.
        """
        registry = cls()
        try:
            entry_points = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception as exc:
            logger.warning("Failed to load entry points for '%s': %s", ENTRY_POINT_GROUP, exc)
            return registry

        for ep in entry_points:
            try:
                scanner_class = ep.load()
                scanner_instance: ScannerProtocol = scanner_class()
                registry.register(scanner_instance)
                logger.info("Loaded scanner plugin '%s' from '%s'", ep.name, ep.value)
            except DuplicatePluginError:
                logger.warning(
                    "Duplicate scanner plugin '%s' from '%s' — skipping.",
                    ep.name,
                    ep.value,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to load scanner plugin '%s' from '%s': %s",
                    ep.name,
                    ep.value,
                    exc,
                )

        return registry

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, scanner_id: str) -> ScannerProtocol:
        """Retrieve a registered scanner by ID.

        Parameters
        ----------
        scanner_id:
            The unique ID of the scanner to retrieve.

        Returns
        -------
        ScannerProtocol
            The registered scanner instance.

        Raises
        ------
        safepush.exceptions.ScannerNotFoundError
            If no scanner with the given ID is registered.
        """
        with self._lock:
            if scanner_id not in self._scanners:
                raise ScannerNotFoundError(scanner_id)
            return self._scanners[scanner_id]

    def get_or_none(self, scanner_id: str) -> ScannerProtocol | None:
        """Retrieve a registered scanner by ID, returning None if not found.

        Parameters
        ----------
        scanner_id:
            The unique ID of the scanner to retrieve.

        Returns
        -------
        ScannerProtocol | None
            The registered scanner, or None.
        """
        with self._lock:
            return self._scanners.get(scanner_id)

    def all(self) -> Iterator[ScannerProtocol]:
        """Iterate over all registered scanner instances.

        Returns
        -------
        Iterator[ScannerProtocol]
            Iterator over all registered scanner instances.
        """
        with self._lock:
            yield from self._scanners.values()

    def ids(self) -> list[str]:
        """Return a sorted list of all registered scanner IDs.

        Returns
        -------
        list[str]
            Sorted list of scanner IDs.
        """
        with self._lock:
            return sorted(self._scanners.keys())

    def is_registered(self, scanner_id: str) -> bool:
        """Return True if a scanner with the given ID is registered.

        Parameters
        ----------
        scanner_id:
            The scanner ID to check.

        Returns
        -------
        bool
            True if the scanner is registered.
        """
        with self._lock:
            return scanner_id in self._scanners

    def __len__(self) -> int:
        """Return the number of registered scanners."""
        with self._lock:
            return len(self._scanners)

    def __repr__(self) -> str:
        with self._lock:
            ids = ", ".join(sorted(self._scanners.keys()))
        return f"ScannerRegistry([{ids}])"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_scanner_id(scanner_id: str) -> None:
        """Validate scanner ID format.

        Scanner IDs must be non-empty strings containing only lowercase
        letters, digits, hyphens, and colons.

        Parameters
        ----------
        scanner_id:
            The scanner ID to validate.

        Raises
        ------
        safepush.exceptions.PluginRegistrationError
            If the scanner ID is invalid.
        """
        import re

        if not scanner_id:
            raise PluginRegistrationError(
                "scanner_id must be a non-empty string.",
                plugin_id="<empty>",
            )
        if not re.fullmatch(r"[a-z0-9][a-z0-9\-:]*", scanner_id):
            raise PluginRegistrationError(
                f"scanner_id '{scanner_id}' is invalid. "
                f"Use only lowercase letters, digits, hyphens, and colons.",
                plugin_id=scanner_id,
            )
