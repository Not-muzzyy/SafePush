"""
SafePush risk scoring engine.

The :class:`ScoringEngine` converts a :class:`~safepush.models.scan.ScanResult`
into a :class:`~safepush.models.score.RiskScore` using a **hybrid** algorithm
that combines numerical scoring with a rule-based severity floor.

Algorithm overview
------------------
1. For each finding, compute a per-finding score::

       per_finding_score = severity_weight × category_multiplier

2. Accumulate all per-finding scores into a raw aggregate.

3. Normalise to [0.0, 1.0] using a soft-cap sigmoid-like function::

       normalised = raw / (raw + NORMALISATION_CONSTANT)

   This ensures the score asymptotically approaches 1.0 as findings increase,
   rather than saturating at exactly 1.0 with a small number of findings.

4. Map the normalised score to a **numerical** :class:`~safepush.models.score.RiskLevel`.

5. Compute the **severity floor** — the minimum risk level dictated by the
   presence of high-severity findings, regardless of numerical score:

   * 2+ CRITICAL findings                       → CRITICAL
   * 1+ CRITICAL **and** 1+ HIGH findings       → CRITICAL
   * Any CRITICAL finding                        → HIGH

6. The **final** ``risk_level`` = ``max(numerical_level, floor_level)``.

7. Compute per-scanner score contributions for auditability.

Why a severity floor?
---------------------
Pure normalisation undersells small numbers of severe findings.  A single
CRITICAL hardcoded API key in an otherwise clean repo scores 10/(10+50) ≈ 0.17
numerically → LOW.  That is dangerously misleading.  The floor corrects this
without discarding the numerical score (which remains valuable for trending).

Customisation
-------------
The numerical algorithm is tunable via :class:`~safepush.models.score.ScoringWeights`.
The severity floor rules are fixed and not operator-tunable, because security
minimums should not be overridden by configuration.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Sequence

from safepush.models.finding import Finding, FindingSeverity
from safepush.models.scan import ScanResult
from safepush.models.score import RiskLevel, RiskScore, ScoringWeights

logger = logging.getLogger(__name__)

# Normalisation constant for the soft-cap formula: score = raw / (raw + K)
# At raw = K the normalised score is 0.5.
# Tune this to control how quickly scores approach 1.0.
_NORMALISATION_CONSTANT: float = 50.0

# Normalised score thresholds for qualitative risk levels (numerical path only)
_RISK_LEVEL_THRESHOLDS: list[tuple[float, RiskLevel]] = [
    (0.9, RiskLevel.CRITICAL),
    (0.7, RiskLevel.HIGH),
    (0.4, RiskLevel.MEDIUM),
    (0.1, RiskLevel.LOW),
    (0.0, RiskLevel.NONE),
]

# Ordinal ordering of RiskLevel values — used for max() comparisons.
_RISK_LEVEL_ORDER: list[RiskLevel] = [
    RiskLevel.NONE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
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

    This function represents the *numerical* path only.  The severity floor
    is applied separately by :func:`_compute_severity_floor`.

    Parameters
    ----------
    normalised:
        Normalised score in [0.0, 1.0].

    Returns
    -------
    RiskLevel
        The qualitative risk level derived from the numerical score.
    """
    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if normalised >= threshold:
            return level
    return RiskLevel.NONE


def _compute_severity_floor(findings: Sequence[Finding]) -> RiskLevel | None:
    """Compute the severity floor from the active finding set.

    The floor is a **minimum** risk level that overrides the numerical score
    upward when high-severity findings are present.  It ensures the final risk
    level reflects real-world security impact, not only mathematical weight.

    Floor rules (applied in priority order, highest first):

    +-------------------------------------------------+--------------+
    | Condition                                       | Floor        |
    +=================================================+==============+
    | 2+ CRITICAL findings                            | CRITICAL     |
    +-------------------------------------------------+--------------+
    | 1+ CRITICAL **and** 1+ HIGH findings            | CRITICAL     |
    +-------------------------------------------------+--------------+
    | Any CRITICAL finding (no accompanying HIGH)     | HIGH         |
    +-------------------------------------------------+--------------+
    | No CRITICAL findings                            | None         |
    +-------------------------------------------------+--------------+

    Parameters
    ----------
    findings:
        Active (non-suppressed) findings to evaluate.

    Returns
    -------
    RiskLevel | None
        The minimum risk level to enforce, or ``None`` if no floor applies.
    """
    n_critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    n_high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)

    if n_critical >= 2:
        return RiskLevel.CRITICAL

    if n_critical >= 1 and n_high >= 1:
        return RiskLevel.CRITICAL

    if n_critical >= 1:
        return RiskLevel.HIGH

    return None


def _max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    """Return the higher of two :class:`~safepush.models.score.RiskLevel` values.

    Parameters
    ----------
    a, b:
        Risk levels to compare.

    Returns
    -------
    RiskLevel
        Whichever of ``a`` or ``b`` is higher in the ordinal ordering.
    """
    return a if _RISK_LEVEL_ORDER.index(a) >= _RISK_LEVEL_ORDER.index(b) else b


class ScoringEngine:
    """Converts a :class:`~safepush.models.scan.ScanResult` into a :class:`~safepush.models.score.RiskScore`.

    Uses a hybrid model:

    1. **Numerical score** — weighted sum of findings, normalised to [0, 1].
    2. **Severity floor** — rule-based minimum that overrides the numerical
       result upward for severe finding patterns.

    The final ``risk_level`` is ``max(numerical_level, floor_level)``.

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
        print(f"Risk level:    {score.risk_level.value}")
        print(f"Numerical:     {score.numerical_risk_level.value}")
        print(f"Floor applied: {score.severity_floor}")
        print(f"Score:         {score.normalised_score:.3f}")
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
            The computed risk score with both numerical and floor-adjusted values.
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

        # --- Numerical path ---
        normalised = _normalise(raw_score)
        numerical_level = _score_to_risk_level(normalised)

        # --- Severity floor ---
        floor = _compute_severity_floor(findings)
        final_level = _max_risk_level(numerical_level, floor) if floor else numerical_level

        logger.debug(
            "Scoring complete: raw=%.2f normalised=%.4f "
            "numerical=%s floor=%s final=%s findings=%d",
            raw_score,
            normalised,
            numerical_level.value,
            floor.value if floor else "none",
            final_level.value,
            len(findings),
        )

        return RiskScore(
            raw_score=round(raw_score, 4),
            normalised_score=round(normalised, 4),
            numerical_risk_level=numerical_level,
            severity_floor=floor,
            risk_level=final_level,
            finding_counts=dict(finding_counts),
            total_findings=len(findings),
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
