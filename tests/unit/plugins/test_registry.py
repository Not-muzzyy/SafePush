"""Unit tests for the ScannerRegistry plugin system."""

from __future__ import annotations

import pytest

from safepush.exceptions import (
    DuplicatePluginError,
    PluginRegistrationError,
    ScannerNotFoundError,
)
from safepush.plugins.registry import ScannerRegistry
from tests.conftest import StubScanner


class TestScannerRegistryRegister:
    """Tests for ScannerRegistry.register()."""

    def test_register_valid_scanner(self, empty_registry: ScannerRegistry) -> None:
        """Registering a valid scanner should succeed."""
        scanner = StubScanner(scanner_id="test-a")
        empty_registry.register(scanner)
        assert empty_registry.is_registered("test-a")

    def test_register_increments_len(self, empty_registry: ScannerRegistry) -> None:
        """Registry length should increase after each registration."""
        assert len(empty_registry) == 0
        empty_registry.register(StubScanner(scanner_id="a"))
        assert len(empty_registry) == 1
        empty_registry.register(StubScanner(scanner_id="b"))
        assert len(empty_registry) == 2

    def test_register_duplicate_raises(self, empty_registry: ScannerRegistry) -> None:
        """Registering the same scanner_id twice must raise DuplicatePluginError."""
        empty_registry.register(StubScanner(scanner_id="dup"))
        with pytest.raises(DuplicatePluginError):
            empty_registry.register(StubScanner(scanner_id="dup"))

    def test_register_with_overwrite(self, empty_registry: ScannerRegistry) -> None:
        """overwrite=True should replace an existing scanner silently."""
        scanner_v1 = StubScanner(scanner_id="s", version="1.0.0")
        scanner_v2 = StubScanner(scanner_id="s", version="2.0.0")
        empty_registry.register(scanner_v1)
        empty_registry.register(scanner_v2, overwrite=True)
        assert empty_registry.get("s").version == "2.0.0"

    def test_register_non_protocol_object_raises(
        self, empty_registry: ScannerRegistry
    ) -> None:
        """Registering an object that doesn't implement ScannerProtocol must raise."""
        with pytest.raises(PluginRegistrationError):
            empty_registry.register("not-a-scanner")  # type: ignore[arg-type]

    def test_register_invalid_scanner_id_raises(
        self, empty_registry: ScannerRegistry
    ) -> None:
        """Scanner IDs with uppercase or spaces must be rejected."""
        scanner = StubScanner(scanner_id="Invalid Scanner ID")
        with pytest.raises(PluginRegistrationError):
            empty_registry.register(scanner)


class TestScannerRegistryGet:
    """Tests for ScannerRegistry.get() and get_or_none()."""

    def test_get_registered_scanner(
        self, populated_registry: ScannerRegistry
    ) -> None:
        """get() should return the correct scanner for a registered ID."""
        scanner = populated_registry.get("stub-scanner")
        assert scanner.scanner_id == "stub-scanner"

    def test_get_unknown_raises(self, empty_registry: ScannerRegistry) -> None:
        """get() must raise ScannerNotFoundError for unknown IDs."""
        with pytest.raises(ScannerNotFoundError) as exc_info:
            empty_registry.get("unknown")
        assert "unknown" in exc_info.value.message

    def test_get_or_none_returns_none_for_unknown(
        self, empty_registry: ScannerRegistry
    ) -> None:
        """get_or_none() must return None instead of raising."""
        assert empty_registry.get_or_none("missing") is None

    def test_get_or_none_returns_scanner_when_registered(
        self, populated_registry: ScannerRegistry
    ) -> None:
        """get_or_none() must return the scanner when it is registered."""
        result = populated_registry.get_or_none("stub-scanner")
        assert result is not None
        assert result.scanner_id == "stub-scanner"


class TestScannerRegistryIteration:
    """Tests for iterating and listing registry contents."""

    def test_all_yields_all_scanners(self, empty_registry: ScannerRegistry) -> None:
        """all() should yield every registered scanner."""
        empty_registry.register(StubScanner(scanner_id="a"))
        empty_registry.register(StubScanner(scanner_id="b"))
        ids = {s.scanner_id for s in empty_registry.all()}
        assert ids == {"a", "b"}

    def test_ids_returns_sorted(self, empty_registry: ScannerRegistry) -> None:
        """ids() must return scanner IDs in sorted order."""
        empty_registry.register(StubScanner(scanner_id="z-scanner"))
        empty_registry.register(StubScanner(scanner_id="a-scanner"))
        empty_registry.register(StubScanner(scanner_id="m-scanner"))
        assert empty_registry.ids() == ["a-scanner", "m-scanner", "z-scanner"]


class TestScannerRegistryUnregister:
    """Tests for ScannerRegistry.unregister()."""

    def test_unregister_removes_scanner(
        self, populated_registry: ScannerRegistry
    ) -> None:
        """unregister() should remove the scanner from the registry."""
        populated_registry.unregister("stub-scanner")
        assert not populated_registry.is_registered("stub-scanner")

    def test_unregister_unknown_raises(self, empty_registry: ScannerRegistry) -> None:
        """Unregistering an unknown scanner must raise ScannerNotFoundError."""
        with pytest.raises(ScannerNotFoundError):
            empty_registry.unregister("does-not-exist")
