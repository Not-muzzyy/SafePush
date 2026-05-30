"""
Shared pytest fixtures for the SafePush test suite.

This conftest.py is at the test root and provides fixtures available to all
tests, both unit and integration.

Fixtures defined here should be:
* Broadly useful across multiple test modules
* Cheap to create (no slow I/O in the fixture setup itself)
* Properly cleaned up after each test

Scanner-specific fixtures, model factories, and filesystem fixtures are all
provided here to avoid duplication across test files.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import pytest

from safepush.models.finding import (
    Finding,
    FindingCategory,
    FindingLocation,
    FindingSeverity,
    FindingStatus,
)
from safepush.models.scan import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanTarget,
    ScanTargetType,
)
from safepush.models.score import ScoringWeights
from safepush.plugins.registry import ScannerRegistry
from safepush.scanner import BaseScanner


# ---------------------------------------------------------------------------
# Finding factories
# ---------------------------------------------------------------------------


def make_finding(
    *,
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: FindingCategory = FindingCategory.SECRET,
    source_scanner: str = "test-scanner",
    file_path: str = "src/app.py",
    line_start: int = 10,
    rule_id: str | None = None,
    title: str = "Test Finding",
    description: str = "A test security finding.",
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    """Create a Finding with sensible defaults for testing.

    Parameters
    ----------
    severity:
        Severity level (default HIGH).
    category:
        Finding category (default SECRET).
    source_scanner:
        Scanner ID (default 'test-scanner').
    file_path:
        File path for the finding location.
    line_start:
        Starting line number.
    rule_id:
        Rule ID (auto-generated if not provided).
    title:
        Finding title.
    description:
        Finding description.
    status:
        Finding status (default OPEN).

    Returns
    -------
    Finding
        A fully populated Finding instance.
    """
    return Finding(
        rule_id=rule_id or f"test:{uuid.uuid4().hex[:8]}",
        title=title,
        description=description,
        severity=severity,
        category=category,
        status=status,
        location=FindingLocation(
            file_path=file_path,
            line_start=line_start,
        ),
        source_scanner=source_scanner,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Return a single HIGH severity SECRET finding."""
    return make_finding()


@pytest.fixture
def critical_finding() -> Finding:
    """Return a CRITICAL severity finding."""
    return make_finding(severity=FindingSeverity.CRITICAL, title="Critical Issue")


@pytest.fixture
def informational_finding() -> Finding:
    """Return an INFORMATIONAL severity finding."""
    return make_finding(
        severity=FindingSeverity.INFORMATIONAL,
        title="Informational Note",
        category=FindingCategory.INSECURE_PATTERN,
    )


@pytest.fixture
def multi_severity_findings() -> list[Finding]:
    """Return a list of findings with mixed severity levels."""
    return [
        make_finding(severity=FindingSeverity.CRITICAL, title="CRIT-1"),
        make_finding(severity=FindingSeverity.CRITICAL, title="CRIT-2"),
        make_finding(severity=FindingSeverity.HIGH, title="HIGH-1"),
        make_finding(severity=FindingSeverity.MEDIUM, title="MED-1"),
        make_finding(severity=FindingSeverity.MEDIUM, title="MED-2"),
        make_finding(severity=FindingSeverity.LOW, title="LOW-1"),
        make_finding(severity=FindingSeverity.INFORMATIONAL, title="INFO-1"),
    ]


# ---------------------------------------------------------------------------
# Scan request/result factories
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_scan_dir(tmp_path: Path) -> Path:
    """Return a temporary directory with some dummy Python files."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text('password = "hunter2"\n')
    (tmp_path / "src" / "utils.py").write_text('# safe file\n')
    (tmp_path / "README.md").write_text("# Test project\n")
    return tmp_path


@pytest.fixture
def sample_scan_target(tmp_scan_dir: Path) -> ScanTarget:
    """Return a ScanTarget pointing at the temporary scan directory."""
    return ScanTarget(
        target_type=ScanTargetType.DIRECTORY,
        path=tmp_scan_dir,
    )


@pytest.fixture
def sample_scan_request(sample_scan_target: ScanTarget) -> ScanRequest:
    """Return a ScanRequest with default settings."""
    return ScanRequest(target=sample_scan_target)


@pytest.fixture
def empty_scan_result(sample_scan_request: ScanRequest) -> ScanResult:
    """Return a ScanResult with no findings (clean scan)."""
    now = datetime.now(timezone.utc)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        request=sample_scan_request,
        status=ScanStatus.COMPLETED,
        findings=[],
        started_at=now,
        completed_at=now,
    )


@pytest.fixture
def scan_result_with_findings(
    sample_scan_request: ScanRequest,
    multi_severity_findings: list[Finding],
) -> ScanResult:
    """Return a ScanResult with mixed-severity findings."""
    now = datetime.now(timezone.utc)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        request=sample_scan_request,
        status=ScanStatus.COMPLETED,
        findings=multi_severity_findings,
        scanner_versions={"test-scanner": "0.1.0"},
        started_at=now,
        completed_at=now,
    )


# ---------------------------------------------------------------------------
# Scanner test doubles
# ---------------------------------------------------------------------------


class StubScanner(BaseScanner):
    """A scanner test double that returns a fixed list of findings.

    Parameters
    ----------
    scanner_id:
        The scanner ID.
    findings:
        The findings to return from :meth:`scan`.
    available:
        Whether :meth:`is_available` returns True.
    version:
        Version string.
    """

    def __init__(
        self,
        scanner_id: str = "stub-scanner",
        findings: Sequence[Finding] | None = None,
        available: bool = True,
        version: str = "0.1.0",
    ) -> None:
        self._scanner_id = scanner_id
        self._findings = list(findings or [])
        self._available = available
        self._version = version

    @property
    def scanner_id(self) -> str:
        return self._scanner_id

    @property
    def version(self) -> str:
        return self._version

    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        return self._findings

    def is_available(self) -> bool:
        return self._available


@pytest.fixture
def stub_scanner() -> StubScanner:
    """Return a StubScanner with no findings."""
    return StubScanner()


@pytest.fixture
def stub_scanner_with_findings(
    multi_severity_findings: list[Finding],
) -> StubScanner:
    """Return a StubScanner pre-loaded with mixed-severity findings."""
    return StubScanner(findings=multi_severity_findings)


@pytest.fixture
def unavailable_scanner() -> StubScanner:
    """Return a StubScanner that reports itself as unavailable."""
    return StubScanner(scanner_id="unavailable", available=False)


# ---------------------------------------------------------------------------
# Registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_registry() -> ScannerRegistry:
    """Return an empty ScannerRegistry with no plugins."""
    return ScannerRegistry()


@pytest.fixture
def populated_registry(
    stub_scanner_with_findings: StubScanner,
) -> ScannerRegistry:
    """Return a ScannerRegistry pre-loaded with the stub scanner."""
    registry = ScannerRegistry()
    registry.register(stub_scanner_with_findings)
    return registry


# ---------------------------------------------------------------------------
# Scoring fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_weights() -> ScoringWeights:
    """Return default ScoringWeights."""
    return ScoringWeights.default()


@pytest.fixture
def strict_weights() -> ScoringWeights:
    """Return strict ScoringWeights suitable for high-security environments."""
    return ScoringWeights.strict()
