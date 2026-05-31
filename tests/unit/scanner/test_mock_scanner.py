"""
Comprehensive tests for MockScanner and its integration across the pipeline.

Test layers:
  1. MockScanner unit tests   — scanner in isolation
  2. Registry integration     — scanner_id discovery, registration, lookup
  3. Engine integration       — full pipeline: request → scanner → score → report
  4. Scoring validation       — risk score reflects the three findings correctly
  5. CLI smoke test           — subprocess invocation of `safepush scan`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Sequence

import pytest

from safepush.models.finding import FindingCategory, FindingSeverity, FindingStatus
from safepush.models.report import ReportFormat
from safepush.models.scan import ScanRequest, ScanTarget, ScanTargetType
from safepush.models.score import RiskLevel
from safepush.plugins.registry import ScannerRegistry
from safepush.scanner.mock import (
    MOCK_SCANNER_ID,
    MOCK_SCANNER_VERSION,
    RULE_HARDCODED_API_KEY,
    RULE_MISSING_VALIDATION,
    RULE_SQL_INJECTION,
    MockScanner,
)
from safepush.scoring.engine import ScoringEngine
from safepush.core.engine import ScanEngine


# ===========================================================================
# Shared helpers
# ===========================================================================


def _make_request(path: Path, **kwargs: object) -> ScanRequest:
    """Build a ScanRequest targeting the given path."""
    return ScanRequest(
        target=ScanTarget(target_type=ScanTargetType.DIRECTORY, path=path),
        **kwargs,  # type: ignore[arg-type]
    )


def _make_engine_with_mock(path: Path) -> tuple[ScanEngine, ScanRequest]:
    """Create a ScanEngine containing only MockScanner and a matching request."""
    registry = ScannerRegistry()
    registry.register(MockScanner())
    engine = ScanEngine(registry=registry, scoring_engine=ScoringEngine())
    request = _make_request(path)
    return engine, request


# ===========================================================================
# 1. MockScanner unit tests
# ===========================================================================


class TestMockScannerContract:
    """Verify MockScanner satisfies ScannerProtocol and BaseScanner requirements."""

    def test_scanner_id_is_mock(self) -> None:
        """scanner_id must be the canonical 'mock' identifier."""
        assert MockScanner().scanner_id == MOCK_SCANNER_ID
        assert MockScanner().scanner_id == "mock"

    def test_version_matches_constant(self) -> None:
        """version must match the MOCK_SCANNER_VERSION constant."""
        assert MockScanner().version == MOCK_SCANNER_VERSION

    def test_is_available_always_true(self) -> None:
        """MockScanner is always available — no external deps."""
        assert MockScanner().is_available() is True

    def test_satisfies_scanner_protocol(self) -> None:
        """MockScanner must be recognized as a ScannerProtocol instance."""
        from safepush.scanner import ScannerProtocol

        assert isinstance(MockScanner(), ScannerProtocol)

    def test_inherits_base_scanner(self) -> None:
        """MockScanner must inherit from BaseScanner."""
        from safepush.scanner import BaseScanner

        assert isinstance(MockScanner(), BaseScanner)


class TestMockScannerFindings:
    """Validate the findings returned by MockScanner.scan()."""

    def test_returns_exactly_three_findings(self, tmp_scan_dir: Path) -> None:
        """MockScanner must always return exactly 3 findings."""
        request = _make_request(tmp_scan_dir)
        findings = MockScanner().scan(request)
        assert len(findings) == 3

    def test_findings_are_deterministic(self, tmp_scan_dir: Path) -> None:
        """Two scans of the same target must produce identical rule_ids."""
        request = _make_request(tmp_scan_dir)
        scanner = MockScanner()
        run1 = {f.rule_id for f in scanner.scan(request)}
        run2 = {f.rule_id for f in scanner.scan(request)}
        assert run1 == run2

    def test_severity_distribution(self, tmp_scan_dir: Path) -> None:
        """Must return exactly 1 CRITICAL, 1 HIGH, 1 MEDIUM."""
        findings = list(MockScanner().scan(_make_request(tmp_scan_dir)))
        severities = [f.severity for f in findings]
        assert severities.count(FindingSeverity.CRITICAL) == 1
        assert severities.count(FindingSeverity.HIGH) == 1
        assert severities.count(FindingSeverity.MEDIUM) == 1

    def test_rule_ids_are_the_expected_constants(self, tmp_scan_dir: Path) -> None:
        """The three findings must use the module-level rule ID constants."""
        findings = list(MockScanner().scan(_make_request(tmp_scan_dir)))
        rule_ids = {f.rule_id for f in findings}
        assert RULE_HARDCODED_API_KEY in rule_ids
        assert RULE_SQL_INJECTION in rule_ids
        assert RULE_MISSING_VALIDATION in rule_ids

    def test_all_findings_source_scanner_is_mock(self, tmp_scan_dir: Path) -> None:
        """Every finding must attribute its source to 'mock'."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert finding.source_scanner == MOCK_SCANNER_ID

    def test_all_findings_status_is_open(self, tmp_scan_dir: Path) -> None:
        """Scanners must not pre-set triage status; all findings should be OPEN."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert finding.status == FindingStatus.OPEN

    def test_all_findings_have_locations(self, tmp_scan_dir: Path) -> None:
        """Every finding must have a non-None location with a valid line_start."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert finding.location is not None
            assert finding.location.line_start >= 1

    def test_all_findings_have_fix_guidance(self, tmp_scan_dir: Path) -> None:
        """All three findings must include non-empty fix_guidance."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert finding.fix_guidance is not None
            assert len(finding.fix_guidance) > 10

    def test_all_findings_have_references(self, tmp_scan_dir: Path) -> None:
        """All three findings must include at least one reference URL."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert len(finding.references) >= 1
            assert all(ref.startswith("https://") for ref in finding.references)

    def test_all_findings_have_metadata(self, tmp_scan_dir: Path) -> None:
        """All three findings must include a non-empty metadata dict."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert isinstance(finding.metadata, dict)
            assert len(finding.metadata) > 0

    def test_critical_finding_is_secret_category(self, tmp_scan_dir: Path) -> None:
        """The CRITICAL finding must be categorized as SECRET."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        critical = next(f for f in findings if f.severity == FindingSeverity.CRITICAL)
        assert critical.category == FindingCategory.SECRET

    def test_high_finding_is_insecure_pattern(self, tmp_scan_dir: Path) -> None:
        """The HIGH finding must be categorized as INSECURE_PATTERN (SQL injection)."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        high = next(f for f in findings if f.severity == FindingSeverity.HIGH)
        assert high.category == FindingCategory.INSECURE_PATTERN

    def test_medium_finding_is_insecure_pattern(self, tmp_scan_dir: Path) -> None:
        """The MEDIUM finding must be categorized as INSECURE_PATTERN (input validation)."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        medium = next(f for f in findings if f.severity == FindingSeverity.MEDIUM)
        assert medium.category == FindingCategory.INSECURE_PATTERN

    def test_file_paths_contain_target_path(self, tmp_scan_dir: Path) -> None:
        """Finding file paths must be relative to the scanned target directory."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert str(tmp_scan_dir) in finding.location.file_path

    def test_findings_are_pydantic_frozen(self, tmp_scan_dir: Path) -> None:
        """Findings must be immutable Pydantic models."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            with pytest.raises(Exception):  # ValidationError or TypeError
                finding.severity = FindingSeverity.LOW  # type: ignore[misc]

    def test_title_is_non_empty_and_under_120_chars(self, tmp_scan_dir: Path) -> None:
        """Each finding title must be non-empty and within the model's limit."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert 1 <= len(finding.title) <= 120

    def test_description_is_non_empty(self, tmp_scan_dir: Path) -> None:
        """Each finding description must be non-empty."""
        findings = MockScanner().scan(_make_request(tmp_scan_dir))
        for finding in findings:
            assert len(finding.description) > 0


# ===========================================================================
# 2. Registry integration
# ===========================================================================


class TestMockScannerRegistryIntegration:
    """Verify MockScanner integrates correctly with the ScannerRegistry."""

    def test_mock_scanner_can_be_registered(self) -> None:
        """MockScanner can be registered without raising."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        assert registry.is_registered(MOCK_SCANNER_ID)

    def test_mock_scanner_retrievable_by_id(self) -> None:
        """get() must return the MockScanner by its ID."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        scanner = registry.get(MOCK_SCANNER_ID)
        assert scanner.scanner_id == MOCK_SCANNER_ID

    def test_mock_scanner_appears_in_all(self) -> None:
        """all() must yield MockScanner once registered."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        ids = [s.scanner_id for s in registry.all()]
        assert MOCK_SCANNER_ID in ids

    def test_mock_scanner_id_in_ids_list(self) -> None:
        """ids() must include 'mock' after registration."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        assert MOCK_SCANNER_ID in registry.ids()

    def test_discover_loads_mock_scanner(self) -> None:
        """ScannerRegistry.discover() must auto-load MockScanner via entry-points."""
        registry = ScannerRegistry.discover()
        assert registry.is_registered(MOCK_SCANNER_ID), (
            "MockScanner was not discovered via entry-points. "
            "Ensure the package is installed with 'pip install -e .[dev]'."
        )

    def test_mock_scanner_version_in_registry(self) -> None:
        """The version returned by the registry scanner must match MOCK_SCANNER_VERSION."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        scanner = registry.get(MOCK_SCANNER_ID)
        assert scanner.version == MOCK_SCANNER_VERSION

    def test_mock_scanner_len_increments_registry(self) -> None:
        """len(registry) must increase by 1 after registering MockScanner."""
        registry = ScannerRegistry()
        before = len(registry)
        registry.register(MockScanner())
        assert len(registry) == before + 1


# ===========================================================================
# 3. Engine integration — full pipeline
# ===========================================================================


class TestMockScannerEngineIntegration:
    """Verify the full ScanEngine pipeline works with MockScanner."""

    def test_engine_runs_mock_scanner_and_returns_report(
        self, tmp_scan_dir: Path
    ) -> None:
        """Engine.scan() must produce a Report when MockScanner is registered."""
        from safepush.models.report import Report

        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert isinstance(report, Report)

    def test_report_contains_three_findings(self, tmp_scan_dir: Path) -> None:
        """Report must contain all 3 MockScanner findings."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.summary.total_findings == 3

    def test_report_counts_per_severity_are_correct(self, tmp_scan_dir: Path) -> None:
        """Summary severity counts must reflect the mock findings exactly."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.summary.critical_count == 1
        assert report.summary.high_count == 1
        assert report.summary.medium_count == 1
        assert report.summary.low_count == 0
        assert report.summary.informational_count == 0

    def test_report_scanners_run_includes_mock(self, tmp_scan_dir: Path) -> None:
        """The report must record 'mock' in its scanners_run list."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert MOCK_SCANNER_ID in report.summary.scanners_run

    def test_scan_result_scanner_versions_records_mock(
        self, tmp_scan_dir: Path
    ) -> None:
        """ScanResult.scanner_versions must include mock → version mapping."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert MOCK_SCANNER_ID in report.scan_result.scanner_versions
        assert report.scan_result.scanner_versions[MOCK_SCANNER_ID] == MOCK_SCANNER_VERSION

    def test_severity_threshold_filters_medium_and_below(
        self, tmp_scan_dir: Path
    ) -> None:
        """With threshold=HIGH only CRITICAL and HIGH findings pass through."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        engine = ScanEngine(registry=registry)
        request = _make_request(tmp_scan_dir, severity_threshold="HIGH")
        report = engine.scan(request)
        assert report.summary.total_findings == 2
        assert report.summary.critical_count == 1
        assert report.summary.high_count == 1
        assert report.summary.medium_count == 0

    def test_severity_threshold_critical_only(self, tmp_scan_dir: Path) -> None:
        """With threshold=CRITICAL only 1 finding passes through."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        engine = ScanEngine(registry=registry)
        request = _make_request(tmp_scan_dir, severity_threshold="CRITICAL")
        report = engine.scan(request)
        assert report.summary.total_findings == 1
        assert report.summary.critical_count == 1

    def test_max_findings_caps_at_one(self, tmp_scan_dir: Path) -> None:
        """max_findings=1 must cap the report at exactly 1 finding."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        engine = ScanEngine(registry=registry)
        request = _make_request(tmp_scan_dir, max_findings=1)
        report = engine.scan(request)
        assert report.summary.total_findings == 1

    def test_fail_on_high_marks_scan_as_failed(self, tmp_scan_dir: Path) -> None:
        """fail_on_severity=HIGH must set summary.passed=False given a HIGH finding."""
        registry = ScannerRegistry()
        registry.register(MockScanner())
        engine = ScanEngine(registry=registry)
        request = _make_request(tmp_scan_dir, fail_on_severity="HIGH")
        report = engine.scan(request)
        assert report.summary.passed is False

    def test_fail_on_none_marks_scan_as_passed(self, tmp_scan_dir: Path) -> None:
        """Without a fail_on_severity gate, the scan should pass."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.summary.passed is True

    def test_report_format_json_is_stored(self, tmp_scan_dir: Path) -> None:
        """Requesting JSON format must be reflected in report.format."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request, report_format=ReportFormat.JSON)
        assert report.format == ReportFormat.JSON

    def test_scan_result_has_no_errors(self, tmp_scan_dir: Path) -> None:
        """A clean MockScanner run must not produce any error records."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.scan_result.errors == []

    def test_discover_based_engine_finds_mock_scanner(
        self, tmp_scan_dir: Path
    ) -> None:
        """An engine built via discover() must find and run MockScanner."""
        registry = ScannerRegistry.discover()
        engine = ScanEngine(registry=registry)
        request = _make_request(tmp_scan_dir)
        report = engine.scan(request)
        assert MOCK_SCANNER_ID in report.summary.scanners_run
        assert report.summary.total_findings >= 3


# ===========================================================================
# 4. Scoring validation
# ===========================================================================


class TestMockScannerScoring:
    """Validate that the risk score correctly reflects MockScanner findings."""

    def test_risk_level_is_at_least_low(self, tmp_scan_dir: Path) -> None:
        """MockScanner 1 CRIT + 1 HIGH + 1 MEDIUM: floor rule fires → CRITICAL.

        Hybrid score breakdown (default weights):
          Numerical:
            CRITICAL: 10.0  (SECRET,            multiplier 1.0)
            HIGH:      7.0  (INSECURE_PATTERN,  multiplier 1.0)
            MEDIUM:    4.0  (INSECURE_PATTERN,  multiplier 1.0)
            Raw: 21.0  Normalised: 21/(21+50) = 0.2958 → LOW

          Severity floor:
            n_critical=1 AND n_high=1 → floor = CRITICAL

          Final: max(LOW, CRITICAL) = CRITICAL
        """
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        score = report.risk_score
        # Numerical path: LOW
        assert score.numerical_risk_level == RiskLevel.LOW
        # Floor: 1 CRIT + 1 HIGH → CRITICAL
        assert score.severity_floor == RiskLevel.CRITICAL
        # Final: CRITICAL
        assert score.risk_level == RiskLevel.CRITICAL
        assert score.floor_triggered is True

    def test_raw_score_is_positive(self, tmp_scan_dir: Path) -> None:
        """With three findings, the raw score must be > 0."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.risk_score.raw_score > 0.0

    def test_normalised_score_in_valid_range(self, tmp_scan_dir: Path) -> None:
        """Normalised score must be in (0, 1)."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert 0.0 < report.risk_score.normalised_score < 1.0

    def test_total_findings_matches_scanner_output(self, tmp_scan_dir: Path) -> None:
        """risk_score.total_findings must match the 3 active mock findings."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.risk_score.total_findings == 3

    def test_scanner_contributions_include_mock(self, tmp_scan_dir: Path) -> None:
        """Scoring engine must record a contribution from 'mock'."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert MOCK_SCANNER_ID in report.risk_score.scanner_contributions
        assert report.risk_score.scanner_contributions[MOCK_SCANNER_ID] > 0.0

    def test_exceeds_none_threshold(self, tmp_scan_dir: Path) -> None:
        """With any findings, risk_score.exceeds_threshold(NONE) must be True."""
        engine, request = _make_engine_with_mock(tmp_scan_dir)
        report = engine.scan(request)
        assert report.risk_score.exceeds_threshold(RiskLevel.NONE) is True


# ===========================================================================
# 5. CLI smoke test
# ===========================================================================


class TestMockScannerCLI:
    """Verify the CLI correctly invokes MockScanner through the full pipeline."""

    # Windows terminals default to cp1252 which cannot encode box-drawing chars
    # or non-ASCII Unicode used by the renderer.  Force UTF-8 for all subprocess
    # calls so the output is consistent regardless of the host code page.
    _ENV: dict[str, str] = {"PYTHONIOENCODING": "utf-8"}

    def test_cli_scan_exits_zero_by_default(self, tmp_scan_dir: Path) -> None:
        """safepush scan <dir> must exit 0 when no fail-on gate is set."""
        result = subprocess.run(
            [sys.executable, "-m", "safepush", "scan", str(tmp_scan_dir)],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, **self._ENV},
        )
        # Exit 0 means CI gate passed
        assert result.returncode == 0, (
            f"Expected exit 0 but got {result.returncode}.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    def test_cli_scan_output_contains_mock_scanner(self, tmp_scan_dir: Path) -> None:
        """Terminal output must mention the 'mock' scanner."""
        result = subprocess.run(
            [sys.executable, "-m", "safepush", "scan", str(tmp_scan_dir)],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, **self._ENV},
        )
        assert "mock" in result.stdout.lower()

    def test_cli_scan_output_contains_findings(self, tmp_scan_dir: Path) -> None:
        """Terminal output must mention the three mock findings."""
        result = subprocess.run(
            [sys.executable, "-m", "safepush", "scan", str(tmp_scan_dir)],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, **self._ENV},
        )
        # The report header and at least one severity label must appear
        combined = result.stdout + result.stderr
        assert "CRITICAL" in combined or "critical" in combined.lower()

    def test_cli_scan_fail_on_critical_exits_one(self, tmp_scan_dir: Path) -> None:
        """safepush scan --fail-on CRITICAL must exit 1 given a CRITICAL finding."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "safepush",
                "scan",
                str(tmp_scan_dir),
                "--fail-on",
                "CRITICAL",
            ],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, **self._ENV},
        )
        assert result.returncode == 1, (
            f"Expected exit 1 (CI gate failure) but got {result.returncode}.\n"
            f"stdout:\n{result.stdout}"
        )

    def test_cli_scan_json_format_is_valid_json(self, tmp_scan_dir: Path) -> None:
        """safepush scan --format json must produce parseable JSON output."""
        import json

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "safepush",
                "scan",
                str(tmp_scan_dir),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, **self._ENV},
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            pytest.fail(f"CLI JSON output is not valid JSON: {exc}\nOutput: {result.stdout[:500]}")

        # Pydantic serialises ReportSummary as a nested dict
        assert "summary" in data
        # total_findings key is present in the summary sub-dict
        assert "total_findings" in data["summary"]
        assert data["summary"]["total_findings"] == 3

    def test_cli_list_scanners_shows_mock(self, tmp_scan_dir: Path) -> None:
        """safepush list-scanners must display 'mock' in the output."""
        result = subprocess.run(
            [sys.executable, "-m", "safepush", "list-scanners"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**__import__('os').environ, **self._ENV},
        )
        assert "mock" in result.stdout.lower(), (
            f"Expected 'mock' in list-scanners output.\nOutput:\n{result.stdout}"
        )
        assert result.returncode == 0
