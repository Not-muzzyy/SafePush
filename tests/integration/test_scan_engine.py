"""Integration tests for the ScanEngine."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from safepush.core.engine import ScanEngine
from safepush.exceptions import ScanTargetNotFoundError
from safepush.models.report import Report, ReportFormat
from safepush.models.scan import ScanRequest, ScanTarget, ScanTargetType
from safepush.models.score import RiskLevel
from safepush.plugins.registry import ScannerRegistry
from safepush.scoring.engine import ScoringEngine
from tests.conftest import StubScanner, make_finding
from safepush.models.finding import FindingSeverity, FindingCategory


def _make_engine(
    *scanners: StubScanner,
) -> ScanEngine:
    """Build a ScanEngine with the given stub scanners."""
    registry = ScannerRegistry()
    for scanner in scanners:
        registry.register(scanner)
    return ScanEngine(registry=registry, scoring_engine=ScoringEngine())


def _make_request(path: Path, **kwargs) -> ScanRequest:
    """Build a ScanRequest targeting the given path."""
    target = ScanTarget(
        target_type=ScanTargetType.DIRECTORY,
        path=path,
    )
    return ScanRequest(target=target, **kwargs)


class TestScanEngineHappyPath:
    """Tests for successful scan scenarios."""

    def test_clean_scan_returns_report(self, tmp_scan_dir: Path) -> None:
        """A scan with no findings should return a NONE risk report."""
        engine = _make_engine(StubScanner(findings=[]))
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        assert isinstance(report, Report)
        assert report.risk_score.risk_level == RiskLevel.NONE
        assert report.summary.total_findings == 0
        assert report.summary.passed is True

    def test_scan_with_findings_returns_populated_report(
        self, tmp_scan_dir: Path
    ) -> None:
        """A scan with findings should populate the report summary."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
        ]
        engine = _make_engine(StubScanner(findings=findings))
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        assert report.summary.total_findings == 2
        assert report.summary.critical_count == 1
        assert report.summary.high_count == 1

    def test_scan_with_multiple_scanners(self, tmp_scan_dir: Path) -> None:
        """Results from multiple scanners should be aggregated."""
        scanner_a = StubScanner(
            scanner_id="scanner-a",
            findings=[make_finding(severity=FindingSeverity.HIGH)],
        )
        scanner_b = StubScanner(
            scanner_id="scanner-b",
            findings=[make_finding(severity=FindingSeverity.MEDIUM)],
        )
        engine = _make_engine(scanner_a, scanner_b)
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        assert report.summary.total_findings == 2
        assert set(report.summary.scanners_run) == {"scanner-a", "scanner-b"}

    def test_specific_scanner_selection(self, tmp_scan_dir: Path) -> None:
        """Specifying scanner_ids should run only those scanners."""
        scanner_a = StubScanner(
            scanner_id="scanner-a",
            findings=[make_finding(severity=FindingSeverity.CRITICAL)],
        )
        scanner_b = StubScanner(
            scanner_id="scanner-b",
            findings=[make_finding(severity=FindingSeverity.HIGH)],
        )
        engine = _make_engine(scanner_a, scanner_b)
        request = _make_request(tmp_scan_dir, scanner_ids=["scanner-a"])
        report = engine.scan(request)

        assert report.summary.total_findings == 1
        assert report.summary.critical_count == 1

    def test_severity_threshold_filters_low_findings(self, tmp_scan_dir: Path) -> None:
        """Findings below the severity threshold must be excluded."""
        findings = [
            make_finding(severity=FindingSeverity.HIGH),
            make_finding(severity=FindingSeverity.LOW),
            make_finding(severity=FindingSeverity.INFORMATIONAL),
        ]
        engine = _make_engine(StubScanner(findings=findings))
        request = _make_request(tmp_scan_dir, severity_threshold="HIGH")
        report = engine.scan(request)

        assert report.summary.total_findings == 1

    def test_max_findings_cap_is_applied(self, tmp_scan_dir: Path) -> None:
        """max_findings must cap the number of findings in the result."""
        findings = [
            make_finding(severity=FindingSeverity.HIGH, title=f"H{i}")
            for i in range(10)
        ]
        engine = _make_engine(StubScanner(findings=findings))
        request = _make_request(tmp_scan_dir, max_findings=3)
        report = engine.scan(request)

        assert report.summary.total_findings == 3

    def test_fail_on_severity_sets_passed_false(self, tmp_scan_dir: Path) -> None:
        """fail_on_severity=HIGH with a HIGH finding must set summary.passed=False."""
        engine = _make_engine(
            StubScanner(findings=[make_finding(severity=FindingSeverity.HIGH)])
        )
        request = _make_request(tmp_scan_dir, fail_on_severity="HIGH")
        report = engine.scan(request)
        assert report.summary.passed is False

    def test_fail_on_severity_below_threshold_is_ignored(
        self, tmp_scan_dir: Path
    ) -> None:
        """fail_on_severity=CRITICAL with only LOW findings must leave passed=True."""
        engine = _make_engine(
            StubScanner(findings=[make_finding(severity=FindingSeverity.LOW)])
        )
        request = _make_request(tmp_scan_dir, fail_on_severity="CRITICAL")
        report = engine.scan(request)
        assert report.summary.passed is True

    def test_unavailable_scanner_is_skipped(self, tmp_scan_dir: Path) -> None:
        """Unavailable scanners should be silently skipped."""
        available = StubScanner(
            scanner_id="available",
            findings=[make_finding(severity=FindingSeverity.HIGH)],
            available=True,
        )
        unavailable = StubScanner(
            scanner_id="unavailable",
            findings=[make_finding(severity=FindingSeverity.CRITICAL)],
            available=False,
        )
        engine = _make_engine(available, unavailable)
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        # Only findings from the available scanner should appear
        assert report.summary.total_findings == 1
        assert report.summary.high_count == 1

    def test_report_format_is_stored(self, tmp_scan_dir: Path) -> None:
        """The report_format argument should be reflected in the report."""
        engine = _make_engine(StubScanner())
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request, report_format=ReportFormat.JSON)
        assert report.format == ReportFormat.JSON

    def test_no_scanners_returns_clean_report(self, tmp_scan_dir: Path) -> None:
        """An engine with no scanners should return a clean empty report."""
        engine = _make_engine()  # no scanners
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)
        assert report.summary.total_findings == 0


class TestScanEngineErrorHandling:
    """Tests for error handling and resilience."""

    def test_nonexistent_path_raises(self) -> None:
        """Scanning a nonexistent path must raise ScanTargetNotFoundError."""
        engine = _make_engine(StubScanner())
        request = _make_request(Path("/nonexistent/path/xyz"))
        with pytest.raises(ScanTargetNotFoundError):
            engine.scan(request)

    def test_scanner_execution_error_is_recorded(self, tmp_scan_dir: Path) -> None:
        """A scanner that raises ScannerExecutionError should record an error."""
        from safepush.exceptions import ScannerExecutionError

        class BrokenScanner(StubScanner):
            def scan(self, request):
                raise ScannerExecutionError(
                    "Backend tool crashed", scanner_id=self.scanner_id
                )

        engine = _make_engine(BrokenScanner(scanner_id="broken"))
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        assert len(report.scan_result.errors) == 1
        assert "broken" in report.scan_result.errors[0]

    def test_scanner_unexpected_exception_is_recorded(
        self, tmp_scan_dir: Path
    ) -> None:
        """An unexpected scanner exception should be caught and recorded."""

        class CrashingScanner(StubScanner):
            def scan(self, request):
                raise RuntimeError("Unexpected explosion!")

        engine = _make_engine(CrashingScanner(scanner_id="crashing"))
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)

        # One error should be recorded, but the report should still be produced
        assert len(report.scan_result.errors) == 1
        assert "RuntimeError" in report.scan_result.errors[0]
        assert report.summary.total_findings == 0
