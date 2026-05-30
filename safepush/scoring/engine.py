"""
SafePush risk scoring engine.

The :class:`ScoringEngine` converts a :class:`~safepush.models.scan.ScanResult`
into a :class:`~safepush.models.score.RiskScore` using a weighted, normalised
scoring algorithm.

Algorithm overview
------------------
1. For each finding, compute a per-finding score::

       per_finding_score = severity_weight × category_multiplier

2. Accumulate all per-finding scores into a raw aggregate.

3. Normalise to [0.0, 1.0] using a soft-cap sigmoid-like function::

       normalised = raw / (raw + NORMALISATION_CONSTANT)

   This ensures the score asymptotically approaches 1.0 as findings increase,
   rather than saturating at exactly 1.0 with a small number of findings.

4. Map the normalised score to a :class:`~safepush.models.score.RiskLevel`.

5. Compute per-scanner score contributions for auditability.

Customisation
-------------
The algorithm is tunable via :class:`~safepush.models.score.ScoringWeights`.
Operators can adjust severity weights and apply per-category multipliers without
changing any source code.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from safepush.models.finding import Finding, FindingSeverity
from safepush.models.scan import ScanResult
from safepush.models.score import RiskLevel, RiskScore, ScoringWeights

logger = logging.getLogger(__name__)

# Normalisation constant for the soft-cap formula: score = raw / (raw + K)
# At raw = K the normalised score is 0.5.
# Tune this to control how quickly scores approach 1.0.
_NORMALISATION_CONSTANT: float = 50.0

# Normalised score thresholds for qualitative risk levels
_RISK_LEVEL_THRESHOLDS: list[tuple[float, RiskLevel]] = [
    (0.9, RiskLevel.CRITICAL),
    (0.7, RiskLevel.HIGH),
    (0.4, RiskLevel.MEDIUM),
    (0.1, RiskLevel.LOW),
    (0.0, RiskLevel.NONE),
]


def _normalise(raw: float) -> float:
    """Apply a soft-cap normalisation to map raw score to [0, 1].

    Parameters
    ----------
    raw:
        Raw aggregate score (≥ 0).

    Returns
    -------
    float
        Normalised score in [0.0, 1.0].
    """
    if raw <= 0:
        return 0.0
    return raw / (raw + _NORMALISATION_CONSTANT)


def _score_to_risk_level(normalised: float) -> RiskLevel:
    """Map a normalised score to a qualitative :class:`~safepush.models.score.RiskLevel`.

    Parameters
    ----------
    normalised:
        Normalised score in [0.0, 1.0].

    Returns
    -------
    RiskLevel
        The qualitative risk level.
    """
    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if normalised >= threshold:
            return level
    return RiskLevel.NONE


class ScoringEngine:
    """Converts a :class:`~safepush.models.scan.ScanResult` into a :class:`~safepush.models.score.RiskScore`.

    Parameters
    ----------
    weights:
        The :class:`~safepush.models.score.ScoringWeights` to use.
        Defaults to :meth:`~safepush.models.score.ScoringWeights.default`.

    Examples
    --------
    ::

        engine = ScoringEngine()
        score = engine.score(scan_result)
        print(f"Risk level: {score.risk_level.value}")
        print(f"Score: {score.normalised_score:.2f}")
    """

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self._weights = weights or ScoringWeights.default()

    def score(self, scan_result: ScanResult) -> RiskScore:
        """Compute a :class:`~safepush.models.score.RiskScore` from a scan result.

        Parameters
        ----------
        scan_result:
            The completed scan result to score.

        Returns
        -------
        RiskScore
            The computed risk score.
        """
        findings = scan_result.get_active_findings()

        raw_score: float = 0.0
        finding_counts: dict[str, int] = defaultdict(int)
        scanner_contributions: dict[str, float] = defaultdict(float)

        for finding in findings:
            finding_counts[finding.severity.value] += 1
            contribution = self._score_finding(finding)
            raw_score += contribution
            scanner_contributions[finding.source_scanner] += contribution

        normalised = _normalise(raw_score)
        risk_level = _score_to_risk_level(normalised)

        logger.debug(
            "Scoring complete: raw=%.2f, normalised=%.4f, level=%s, findings=%d",
            raw_score,
            normalised,
            risk_level.value,
            len(list(findings)),
        )

        return RiskScore(
            raw_score=round(raw_score, 4),
            normalised_score=round(normalised, 4),
            risk_level=risk_level,
            finding_counts=dict(finding_counts),
            total_findings=len(list(findings)),
            weights_used=self._weights,
            scanner_contributions={
                k: round(v, 4) for k, v in scanner_contributions.items()
            },
        )

    def _score_finding(self, finding: Finding) -> float:
        """Compute the score contribution of a single finding.

        Parameters
        ----------
        finding:
            The finding to score.

        Returns
        -------
        float
            The numeric contribution of this finding to the raw aggregate score.
        """
        severity_weight = self._get_severity_weight(finding.severity)
        category_multiplier = self._weights.category_multipliers.get(
            finding.category.value, 1.0
        )
        return severity_weight * category_multiplier

    def _get_severity_weight(self, severity: FindingSeverity) -> float:
        """Return the configured weight for a given severity.

        Parameters
        ----------
        severity:
            The severity to look up.

        Returns
        -------
        float
            The numeric weight from the configured :class:`~safepush.models.score.ScoringWeights`.
        """
        weights_map: dict[FindingSeverity, float] = {
            FindingSeverity.CRITICAL: self._weights.critical_weight,
            FindingSeverity.HIGH: self._weights.high_weight,
            FindingSeverity.MEDIUM: self._weights.medium_weight,
            FindingSeverity.LOW: self._weights.low_weight,
            FindingSeverity.INFORMATIONAL: self._weights.informational_weight,
            FindingSeverity.UNKNOWN: self._weights.unknown_weight,
        }
        return weights_map.get(severity, self._weights.unknown_weight)
