"""
Risk score domain models for SafePush.

Risk scoring converts a raw list of :class:`~safepush.models.finding.Finding`
objects into a single, actionable :class:`RiskScore` that integrates into CI/CD
gates, dashboards, and security policies.

Design philosophy
-----------------
The scoring model uses a **hybrid** approach combining two axes:

1. **Numerical score**: a weighted, normalised aggregate of all findings.
2. **Severity floor**: a rule-based minimum risk level that overrides the
   numerical result upward when severe findings are present.

The floor ensures that the risk level always reflects real-world security
severity, not only the mathematical weight of a small number of findings.  For
example, a single CRITICAL finding in an otherwise clean codebase should never
report as LOW just because the normalised number is 0.17.

Floor rules (applied after numerical scoring):
  - Any CRITICAL finding           → minimum HIGH
  - 1+ CRITICAL **and** 1+ HIGH   → minimum CRITICAL
  - 2+ CRITICAL findings           → minimum CRITICAL

The final ``risk_level`` is ``max(numerical_level, floor_level)``.
Both the numerical level and the applied floor are stored in :class:`RiskScore`
for full auditability.

The :class:`ScoringWeights` object allows operators to tune severity multipliers
without touching source code.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    """Qualitative risk level derived from a numeric :class:`RiskScore`.

    The numeric → qualitative mapping is defined in
    :meth:`RiskScore.risk_level` and can be customised by operators.
    """

    CRITICAL = "CRITICAL"
    """Score ≥ 0.9 — immediate action required, block the push."""

    HIGH = "HIGH"
    """Score 0.7–0.89 — serious issues, strongly recommended to block."""

    MEDIUM = "MEDIUM"
    """Score 0.4–0.69 — notable issues, warn the developer."""

    LOW = "LOW"
    """Score 0.1–0.39 — minor issues, informational only."""

    NONE = "NONE"
    """Score < 0.1 — no significant risk detected."""


class ScoringWeights(BaseModel):
    """Tunable multipliers used by the scoring algorithm.

    Each field represents the contribution weight of one severity bucket to the
    overall risk score.  Higher values make that severity bucket contribute more
    aggressively to the final score.

    The weights are normalised internally, so their *absolute* values do not
    matter — only their *relative* magnitudes.

    Attributes
    ----------
    critical_weight:
        Weight applied to CRITICAL findings.
    high_weight:
        Weight applied to HIGH findings.
    medium_weight:
        Weight applied to MEDIUM findings.
    low_weight:
        Weight applied to LOW findings.
    informational_weight:
        Weight applied to INFORMATIONAL findings.
    unknown_weight:
        Weight applied to findings whose severity could not be determined.
    category_multipliers:
        Optional per-category score multipliers.  For example,
        ``{"SECRET": 1.5}`` inflates the contribution of SECRET findings by
        50 %.  Category keys must match :class:`~safepush.models.finding.FindingCategory`
        values.
    """

    model_config = {"frozen": True}

    critical_weight: float = Field(
        default=10.0,
        gt=0,
        description="Score weight for CRITICAL severity findings.",
    )
    high_weight: float = Field(
        default=7.0,
        gt=0,
        description="Score weight for HIGH severity findings.",
    )
    medium_weight: float = Field(
        default=4.0,
        gt=0,
        description="Score weight for MEDIUM severity findings.",
    )
    low_weight: float = Field(
        default=1.5,
        gt=0,
        description="Score weight for LOW severity findings.",
    )
    informational_weight: float = Field(
        default=0.5,
        gt=0,
        description="Score weight for INFORMATIONAL severity findings.",
    )
    unknown_weight: float = Field(
        default=5.0,
        gt=0,
        description="Score weight for UNKNOWN severity findings (conservative penalty).",
    )
    category_multipliers: dict[str, float] = Field(
        default_factory=dict,
        description="Per-category multipliers keyed by FindingCategory value.",
        examples=[{"SECRET": 1.5, "VULNERABILITY": 1.2}],
    )

    @field_validator("category_multipliers", mode="before")
    @classmethod
    def validate_multipliers_positive(
        cls, v: dict[str, float]
    ) -> dict[str, float]:
        """Ensure all category multipliers are strictly positive."""
        for category, multiplier in v.items():
            if multiplier <= 0:
                raise ValueError(
                    f"Category multiplier for '{category}' must be > 0, "
                    f"got {multiplier}"
                )
        return v

    @classmethod
    def default(cls) -> "ScoringWeights":
        """Return the default scoring weights suitable for most projects.

        Returns
        -------
        ScoringWeights
            Default weights with no category multipliers.
        """
        return cls()

    @classmethod
    def strict(cls) -> "ScoringWeights":
        """Return weights tuned for high-security environments.

        SECRETs and VULNERABILITYs are heavily penalised.  Suitable for
        financial services, healthcare, and government projects.

        Returns
        -------
        ScoringWeights
            Strict weights with SECRET and VULNERABILITY category multipliers.
        """
        return cls(
            critical_weight=15.0,
            high_weight=10.0,
            medium_weight=6.0,
            low_weight=2.0,
            informational_weight=0.5,
            unknown_weight=8.0,
            category_multipliers={
                "SECRET": 2.0,
                "VULNERABILITY": 1.5,
                "SUPPLY_CHAIN": 1.3,
            },
        )


class RiskScore(BaseModel):
    """The computed risk score for a completed scan.

    Attributes
    ----------
    raw_score:
        Unnormalised aggregate score computed from finding weights.
    normalised_score:
        Score normalised to the range [0.0, 1.0].
    numerical_risk_level:
        Qualitative risk level derived purely from ``normalised_score``,
        before the severity floor is applied.  Stored for auditability.
    severity_floor:
        The minimum risk level imposed by the severity floor rules, or
        ``None`` if no floor was triggered.  When non-None, it overrides
        ``numerical_risk_level`` upward to produce ``risk_level``.
    risk_level:
        The final, authoritative risk level.  Equal to
        ``max(numerical_risk_level, severity_floor)``.
    finding_counts:
        Number of findings per severity bucket.
    total_findings:
        Total number of scored findings.
    weights_used:
        The :class:`ScoringWeights` configuration used for this score, embedded
        for full auditability.
    scanner_contributions:
        Map of ``scanner_id → contribution_score`` showing which scanners
        contributed most to the overall risk.
    """

    model_config = {"frozen": True}

    raw_score: float = Field(
        ...,
        ge=0.0,
        description="Unnormalised aggregate score.",
    )
    normalised_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Score normalised to [0.0, 1.0].",
    )
    numerical_risk_level: RiskLevel = Field(
        ...,
        description="Risk level derived purely from normalised_score (before floor).",
    )
    severity_floor: RiskLevel | None = Field(
        default=None,
        description=(
            "Minimum risk level imposed by severity floor rules. "
            "None if no floor was triggered. "
            "When set, risk_level = max(numerical_risk_level, severity_floor)."
        ),
    )
    risk_level: RiskLevel = Field(
        ...,
        description=(
            "Final authoritative risk level: max(numerical_risk_level, severity_floor). "
            "This is the value used for CI gates and dashboards."
        ),
    )
    finding_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Number of findings per severity bucket.",
        examples=[{"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 3}],
    )
    total_findings: int = Field(
        default=0,
        ge=0,
        description="Total number of scored findings.",
    )
    weights_used: ScoringWeights = Field(
        ...,
        description="ScoringWeights configuration used for this score.",
    )
    scanner_contributions: dict[str, float] = Field(
        default_factory=dict,
        description="Map of scanner_id → contribution_score.",
    )

    @property
    def floor_triggered(self) -> bool:
        """Return True if the severity floor overrode the numerical risk level.

        When True, the final ``risk_level`` is higher than what the normalised
        score alone would have produced.  Useful for explaining score elevation
        in reports and dashboards.

        Returns
        -------
        bool
            True if ``severity_floor`` raised ``risk_level`` above
            ``numerical_risk_level``.
        """
        return (
            self.severity_floor is not None
            and self.severity_floor != self.numerical_risk_level
            and self.risk_level != self.numerical_risk_level
        )

    def exceeds_threshold(self, min_risk_level: RiskLevel) -> bool:
        """Return True if this score is at or above the given risk level.

        Parameters
        ----------
        min_risk_level:
            The minimum :class:`RiskLevel` to compare against.

        Returns
        -------
        bool
            True if the current risk level is at or above ``min_risk_level``.
        """
        order = [
            RiskLevel.NONE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        return order.index(self.risk_level) >= order.index(min_risk_level)
