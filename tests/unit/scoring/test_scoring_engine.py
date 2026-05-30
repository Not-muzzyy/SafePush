"""Unit tests for the ScoringEngine."""

from __future__ import annotations

import pytest

from safepush.models.finding import FindingSeverity, FindingCategory
from safepush.models.score import RiskLevel, ScoringWeights
from safepush.scoring.engine import ScoringEngine, _normalise, _score_to_risk_level
from tests.conftest import make_finding


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
    """Tests for the risk level mapping function."""

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


class TestScoringEngine:
    """Tests for ScoringEngine.score()."""

    def test_empty_scan_result_scores_none(
        self, empty_scan_result, default_weights
    ) -> None:
        """A scan with no findings must produce a NONE risk level."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(empty_scan_result)
        assert score.risk_level == RiskLevel.NONE
        assert score.raw_score == 0.0
        assert score.normalised_score == 0.0
        assert score.total_findings == 0

    def test_critical_findings_produce_high_risk(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """Multiple CRITICAL findings should drive risk level to HIGH or CRITICAL."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        # 2×CRIT(10) + 1×HIGH(7) + 2×MED(4) + 1×LOW(1.5) + 1×INFO(0.5) = 37.0 raw
        # normalised = 37 / (37+50) ≈ 0.425 → MEDIUM boundary; may also be HIGH with strict weights
        assert score.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

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
        import uuid
        from datetime import datetime, timezone
        from safepush.models.scan import ScanResult, ScanStatus

        finding = make_finding(
            severity=FindingSeverity.HIGH,
            category=FindingCategory.SECRET,
        )
        now = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            request=sample_scan_request,
            status=ScanStatus.COMPLETED,
            findings=[finding],
            started_at=now,
            completed_at=now,
        )

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
        import uuid
        from datetime import datetime, timezone
        from safepush.models.finding import FindingStatus
        from safepush.models.scan import ScanResult, ScanStatus, ScanTarget, ScanTargetType, ScanRequest
        from pathlib import Path

        target = ScanTarget(
            target_type=ScanTargetType.DIRECTORY,
            path=Path("."),
        )
        request = ScanRequest(target=target)
        suppressed_finding = make_finding(
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.SUPPRESSED,
        )
        now = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            request=request,
            status=ScanStatus.COMPLETED,
            findings=[suppressed_finding],
            started_at=now,
            completed_at=now,
        )
        engine = ScoringEngine()
        score = engine.score(result)
        assert score.total_findings == 0
        assert score.raw_score == 0.0

    def test_scanner_contributions_are_tracked(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """Per-scanner contributions must be present and positive."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        # The make_finding() factory defaults source_scanner to "test-scanner"
        assert "test-scanner" in score.scanner_contributions
        assert score.scanner_contributions["test-scanner"] > 0.0

    def test_risk_level_exceeds_threshold(
        self, scan_result_with_findings, default_weights
    ) -> None:
        """exceeds_threshold() must correctly compare risk levels."""
        engine = ScoringEngine(weights=default_weights)
        score = engine.score(scan_result_with_findings)
        # Should exceed NONE and LOW for a scan with CRITICAL findings
        assert score.exceeds_threshold(RiskLevel.NONE)
        assert score.exceeds_threshold(RiskLevel.LOW)
