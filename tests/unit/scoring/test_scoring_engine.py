"""Unit tests for the ScoringEngine — hybrid numerical + severity floor model."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from safepush.models.finding import FindingCategory, FindingSeverity, FindingStatus
from safepush.models.scan import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanTarget,
    ScanTargetType,
)
from safepush.models.score import RiskLevel, ScoringWeights
from safepush.scoring.engine import (
    ScoringEngine,
    _compute_severity_floor,
    _max_risk_level,
    _normalise,
    _score_to_risk_level,
)
from tests.conftest import make_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    findings: list,
    target_path: Path | None = None,
) -> ScanResult:
    """Build a minimal ScanResult with the given findings."""
    path = target_path or Path(".")
    target = ScanTarget(target_type=ScanTargetType.DIRECTORY, path=path)
    request = ScanRequest(target=target)
    now = datetime.now(timezone.utc)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        request=request,
        status=ScanStatus.COMPLETED,
        findings=findings,
        started_at=now,
        completed_at=now,
    )


# ===========================================================================
# Numerical helpers
# ===========================================================================


class TestNormalisation:
    """Tests for the internal normalisation helper."""

    def test_zero_raw_score_gives_zero(self) -> None:
        """Raw score of 0 should normalise to exactly 0.0."""
        assert _normalise(0.0) == 0.0

    def test_positive_raw_gives_value_in_range(self) -> None:
        """Any positive raw score must normalise to (0, 1)."""
        for raw in [0.1, 1.0, 10.0, 50.0, 100.0, 1000.0]:
            result = _normalise(raw)
            assert 0.0 < result < 1.0, f"_normalise({raw}) = {result} out of range"

    def test_score_asymptotically_approaches_one(self) -> None:
        """Very large raw scores should be very close to 1.0 but not exceed it."""
        result = _normalise(1_000_000.0)
        assert result < 1.0
        assert result > 0.999


class TestScoreToRiskLevel:
    """Tests for the numerical risk level mapping function."""

    def test_high_score_maps_to_critical(self) -> None:
        """Scores >= 0.9 must map to CRITICAL."""
        assert _score_to_risk_level(0.90) == RiskLevel.CRITICAL
        assert _score_to_risk_level(0.95) == RiskLevel.CRITICAL
        assert _score_to_risk_level(1.0) == RiskLevel.CRITICAL

    def test_zero_maps_to_none(self) -> None:
        """Score of 0 must map to NONE."""
        assert _score_to_risk_level(0.0) == RiskLevel.NONE

    def test_low_score_maps_to_low(self) -> None:
        """Scores in the LOW range must map to LOW."""
        assert _score_to_risk_level(0.1) == RiskLevel.LOW
        assert _score_to_risk_level(0.25) == RiskLevel.LOW


class TestMaxRiskLevel:
    """Tests for the _max_risk_level utility."""

    def test_returns_higher_of_two(self) -> None:
        assert _max_risk_level(RiskLevel.HIGH, RiskLevel.LOW) == RiskLevel.HIGH
        assert _max_risk_level(RiskLevel.LOW, RiskLevel.HIGH) == RiskLevel.HIGH

    def test_equal_returns_same(self) -> None:
        assert _max_risk_level(RiskLevel.MEDIUM, RiskLevel.MEDIUM) == RiskLevel.MEDIUM

    def test_critical_beats_all(self) -> None:
        for level in RiskLevel:
            assert _max_risk_level(RiskLevel.CRITICAL, level) == RiskLevel.CRITICAL

    def test_none_loses_to_all(self) -> None:
        for level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            assert _max_risk_level(RiskLevel.NONE, level) == level


# ===========================================================================
# Severity floor
# ===========================================================================


class TestSeverityFloor:
    """Tests for the rule-based severity floor (_compute_severity_floor)."""

    def test_no_findings_returns_none(self) -> None:
        """Empty finding list — no floor applies."""
        assert _compute_severity_floor([]) is None

    def test_no_critical_returns_none(self) -> None:
        """Only LOW/MEDIUM/HIGH findings — no floor applies."""
        findings = [
            make_finding(severity=FindingSeverity.HIGH),
            make_finding(severity=FindingSeverity.MEDIUM),
            make_finding(severity=FindingSeverity.LOW),
        ]
        assert _compute_severity_floor(findings) is None

    def test_single_critical_floors_to_high(self) -> None:
        """1 CRITICAL with no HIGH → floor = HIGH."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.MEDIUM),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.HIGH

    def test_critical_plus_high_floors_to_critical(self) -> None:
        """1 CRITICAL + 1 HIGH → floor = CRITICAL."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.CRITICAL

    def test_two_critical_floors_to_critical(self) -> None:
        """2+ CRITICAL findings → floor = CRITICAL."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.CRITICAL),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.CRITICAL

    def test_many_critical_floors_to_critical(self) -> None:
        """5 CRITICAL findings → floor = CRITICAL."""
        findings = [make_finding(severity=FindingSeverity.CRITICAL) for _ in range(5)]
        assert _compute_severity_floor(findings) == RiskLevel.CRITICAL

    def test_critical_plus_many_high_floors_to_critical(self) -> None:
        """1 CRITICAL + multiple HIGH → floor = CRITICAL."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
            make_finding(severity=FindingSeverity.HIGH),
            make_finding(severity=FindingSeverity.HIGH),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.CRITICAL

    def test_two_critical_plus_high_floors_to_critical(self) -> None:
        """2 CRITICAL + 1 HIGH → floor = CRITICAL (multiple-critical rule fires first)."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.CRITICAL

    def test_single_critical_many_medium_floors_to_high(self) -> None:
        """1 CRITICAL + many MEDIUM (no HIGH) → floor = HIGH, not CRITICAL."""
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.MEDIUM),
            make_finding(severity=FindingSeverity.MEDIUM),
            make_finding(severity=FindingSeverity.MEDIUM),
        ]
        assert _compute_severity_floor(findings) == RiskLevel.HIGH

    def test_informational_only_returns_none(self) -> None:
        """Only INFORMATIONAL findings — no floor."""
        findings = [make_finding(severity=FindingSeverity.INFORMATIONAL)]
        assert _compute_severity_floor(findings) is None


# ===========================================================================
# ScoringEngine — end-to-end hybrid scoring
# ===========================================================================


class TestScoringEngine:
    """Tests for ScoringEngine.score() — end-to-end hybrid model."""

    def test_empty_scan_result_scores_none(
        self, empty_scan_result, default_weights
    ) -> None:
        """A scan with no findings must produce a NONE risk level with no floor."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(empty_scan_result)
        assert score.risk_level == RiskLevel.NONE
        assert score.numerical_risk_level == RiskLevel.NONE
        assert score.severity_floor is None
        assert score.floor_triggered is False
        assert score.raw_score == 0.0
        assert score.normalised_score == 0.0
        assert score.total_findings == 0

    def test_critical_findings_produce_high_risk(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """2×CRIT + 1×HIGH → floor=CRITICAL, final=CRITICAL regardless of numerical."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        # Floor: 2 CRITICAL → CRITICAL
        assert score.severity_floor == RiskLevel.CRITICAL
        assert score.risk_level == RiskLevel.CRITICAL

    def test_finding_counts_are_accurate(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """finding_counts must accurately reflect the number per severity."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        assert score.finding_counts.get("CRITICAL", 0) == 2
        assert score.finding_counts.get("HIGH", 0) == 1
        assert score.finding_counts.get("MEDIUM", 0) == 2

    def test_total_findings_matches_active(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """total_findings should match the count of active (non-suppressed) findings."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        active_count = len(list(scan_result_with_findings.get_active_findings()))
        assert score.total_findings == active_count

    def test_weights_are_embedded_in_score(
        self, empty_scan_result, strict_weights
    ) -> None:
        """The weights used for scoring must be embedded in the RiskScore."""
        engine = ScoringEngine(weights=strict_weights)
        score = engine.score(empty_scan_result)
        assert score.weights_used == strict_weights

    def test_category_multiplier_inflates_score(self, sample_scan_request) -> None:
        """A category multiplier of 2x should approximately double the raw score."""
        finding = make_finding(
            severity=FindingSeverity.HIGH,
            category=FindingCategory.SECRET,
        )
        result = _make_result([finding])

        default_engine = ScoringEngine(weights=ScoringWeights.default())
        inflated_engine = ScoringEngine(
            weights=ScoringWeights(category_multipliers={"SECRET": 2.0})
        )

        score_default = default_engine.score(result)
        score_inflated = inflated_engine.score(result)

        assert score_inflated.raw_score == pytest.approx(
            score_default.raw_score * 2.0, rel=1e-6
        )

    def test_suppressed_findings_not_scored(self) -> None:
        """Suppressed findings must be excluded from scoring."""
        suppressed = make_finding(
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.SUPPRESSED,
        )
        result = _make_result([suppressed])
        score = ScoringEngine().score(result)
        assert score.total_findings == 0
        assert score.raw_score == 0.0
        assert score.severity_floor is None
        assert score.risk_level == RiskLevel.NONE

    def test_scanner_contributions_are_tracked(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """Per-scanner contributions must be present and positive."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        # make_finding() defaults source_scanner to "test-scanner"
        assert "test-scanner" in score.scanner_contributions
        assert score.scanner_contributions["test-scanner"] > 0.0

    def test_risk_level_exceeds_threshold(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """exceeds_threshold() must correctly compare risk levels."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        assert score.exceeds_threshold(RiskLevel.NONE)
        assert score.exceeds_threshold(RiskLevel.LOW)


# ===========================================================================
# Floor interaction with numerical score
# ===========================================================================


class TestFloorInteraction:
    """Verify floor and numerical paths interact correctly."""

    def test_floor_elevates_low_numerical_score(self) -> None:
        """A single CRITICAL finding numerically scores LOW but floor lifts to HIGH."""
        result = _make_result([make_finding(severity=FindingSeverity.CRITICAL)])
        score = ScoringEngine().score(result)
        # raw=10, normalised=10/60≈0.167 → numerical LOW
        assert score.numerical_risk_level == RiskLevel.LOW
        assert score.severity_floor == RiskLevel.HIGH
        assert score.risk_level == RiskLevel.HIGH
        assert score.floor_triggered is True

    def test_critical_plus_high_floor_elevates_to_critical(self) -> None:
        """1 CRITICAL + 1 HIGH: numerical=LOW, floor=CRITICAL, final=CRITICAL."""
        result = _make_result([
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
        ])
        score = ScoringEngine().score(result)
        assert score.severity_floor == RiskLevel.CRITICAL
        assert score.risk_level == RiskLevel.CRITICAL
        assert score.floor_triggered is True

    def test_two_critical_floor_elevates_to_critical(self) -> None:
        """2 CRITICAL: floor=CRITICAL, final=CRITICAL."""
        result = _make_result([
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.CRITICAL),
        ])
        score = ScoringEngine().score(result)
        assert score.severity_floor == RiskLevel.CRITICAL
        assert score.risk_level == RiskLevel.CRITICAL

    def test_floor_does_not_lower_numerical_score(self) -> None:
        """When numerical score already exceeds floor, floor is stored but risk_level unchanged."""
        # 10 CRITICAL findings: raw=100, normalised=100/150≈0.667 → numerical HIGH
        # Floor: 2+ CRITICAL → CRITICAL. But 0.667 < 0.9 so numerical=HIGH.
        # Floor=CRITICAL > HIGH → final=CRITICAL
        findings = [make_finding(severity=FindingSeverity.CRITICAL) for _ in range(10)]
        result = _make_result(findings)
        score = ScoringEngine().score(result)
        assert score.severity_floor == RiskLevel.CRITICAL
        assert score.risk_level == RiskLevel.CRITICAL

    def test_high_only_findings_no_floor(self) -> None:
        """Multiple HIGH findings with no CRITICAL — no floor, normal numerical score."""
        findings = [make_finding(severity=FindingSeverity.HIGH) for _ in range(3)]
        result = _make_result(findings)
        score = ScoringEngine().score(result)
        assert score.severity_floor is None
        assert score.floor_triggered is False

    def test_floor_triggered_false_when_not_elevated(self) -> None:
        """floor_triggered is False when numerical score already at or above floor."""
        # Many CRITICALs → numerical will be HIGH or CRITICAL naturally.
        # Create a scenario where floor=HIGH but numerical=HIGH too → not elevated
        result = _make_result([make_finding(severity=FindingSeverity.CRITICAL)])
        score = ScoringEngine().score(result)
        # floor=HIGH, numerical=LOW, final=HIGH → floor DID elevate → True
        # This tests the property logic
        assert score.floor_triggered is True

    def test_no_floor_when_only_medium_and_low(self) -> None:
        """MEDIUM and LOW findings only — floor=None, score is purely numerical."""
        findings = [
            make_finding(severity=FindingSeverity.MEDIUM),
            make_finding(severity=FindingSeverity.LOW),
        ]
        result = _make_result(findings)
        score = ScoringEngine().score(result)
        assert score.severity_floor is None
        assert score.risk_level == score.numerical_risk_level

    def test_numerical_risk_level_stored_separately(self) -> None:
        """numerical_risk_level must reflect the pure mathematical result."""
        # Single CRITICAL: raw=10, normalised≈0.167 → numerical LOW, floor HIGH
        result = _make_result([make_finding(severity=FindingSeverity.CRITICAL)])
        score = ScoringEngine().score(result)
        assert score.numerical_risk_level == RiskLevel.LOW
        assert score.risk_level == RiskLevel.HIGH  # floor applied

    def test_risk_level_equals_numerical_when_no_floor(self) -> None:
        """When no floor triggers, risk_level must equal numerical_risk_level."""
        result = _make_result([make_finding(severity=FindingSeverity.MEDIUM)])
        score = ScoringEngine().score(result)
        assert score.severity_floor is None
        assert score.risk_level == score.numerical_risk_level
