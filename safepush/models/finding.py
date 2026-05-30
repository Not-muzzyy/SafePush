"""
Core Finding domain model for SafePush.

A :class:`Finding` is the atomic unit of output produced by any scanner in the
SafePush ecosystem.  It intentionally carries no references to the scanner that
produced it — the scanner is recorded only as an opaque *source* string — so the
downstream pipeline (scoring, reporting, CLI output) never needs to know which
tool emitted the finding.

Design decisions
----------------
* ``FindingSeverity`` maps to the industry-standard CVSS scale (CRITICAL →
  INFORMATIONAL) so that findings from heterogeneous tools can be compared on a
  single axis.
* ``FindingCategory`` is an open-ended enum with a ``CUSTOM`` escape hatch,
  meaning community scanner plugins can introduce new categories without forking
  core.
* ``FindingStatus`` allows downstream consumers (IDE extensions, dashboards) to
  track triage state without mutating the original scan result.
* All fields that are not universally available across scanners are marked
  ``Optional`` with sensible defaults.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class FindingSeverity(str, Enum):
    """Severity levels aligned with the CVSS v3.1 qualitative rating scale.

    Scanners MUST map their native severity to one of these values.  The
    ``UNKNOWN`` sentinel is provided for scanners that cannot determine severity
    at scan time; the :mod:`safepush.scoring` module will apply a conservative
    penalty to unknown-severity findings.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"

    @property
    def numeric_weight(self) -> float:
        """Return a numeric weight used by the scoring subsystem.

        Returns
        -------
        float
            A value between 0.0 and 1.0 where 1.0 is most severe.
        """
        weights: dict[FindingSeverity, float] = {
            FindingSeverity.CRITICAL: 1.0,
            FindingSeverity.HIGH: 0.8,
            FindingSeverity.MEDIUM: 0.5,
            FindingSeverity.LOW: 0.2,
            FindingSeverity.INFORMATIONAL: 0.05,
            FindingSeverity.UNKNOWN: 0.6,  # Conservative penalty
        }
        return weights[self]


class FindingCategory(str, Enum):
    """High-level classification of what type of problem a finding represents.

    Categories are intentionally broad so that findings from very different
    scanners can be grouped meaningfully in reports and dashboards.
    """

    SECRET = "SECRET"
    """Hard-coded credentials, API keys, tokens, or other secrets."""

    VULNERABILITY = "VULNERABILITY"
    """Known CVEs, dependency vulnerabilities, or exploitable code patterns."""

    INSECURE_PATTERN = "INSECURE_PATTERN"
    """Code patterns that are insecure by design (e.g. SQL injection risk)."""

    AI_GENERATED_RISK = "AI_GENERATED_RISK"
    """Risky patterns commonly introduced by AI code generation."""

    LICENSE = "LICENSE"
    """License compliance issues (e.g. GPL code in a proprietary project)."""

    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    """Risks originating from the software supply chain."""

    MISCONFIGURATION = "MISCONFIGURATION"
    """Infrastructure or application configuration issues."""

    CUSTOM = "CUSTOM"
    """Catch-all for community plugins that introduce novel categories."""


class FindingStatus(str, Enum):
    """Lifecycle status of a finding as it is triaged.

    The status is mutable by downstream consumers (IDE, dashboard) and is
    intentionally **not** set by scanners — scanners only produce findings, they
    do not triage them.
    """

    OPEN = "OPEN"
    """Newly detected; not yet reviewed."""

    ACKNOWLEDGED = "ACKNOWLEDGED"
    """Reviewed and accepted as a real issue; awaiting fix."""

    SUPPRESSED = "SUPPRESSED"
    """Intentionally ignored (false positive or accepted risk)."""

    FIXED = "FIXED"
    """The underlying issue has been resolved."""


class FindingLocation(BaseModel):
    """Precise location of a finding within a file.

    All line numbers are 1-indexed, consistent with how editors and most
    security tools report positions.  The :attr:`column_start` and
    :attr:`column_end` fields are optional because many scanner backends do not
    provide column-level precision.
    """

    model_config = {"frozen": True}

    file_path: str = Field(
        ...,
        description="Absolute or repository-relative path to the affected file.",
        examples=["src/auth/login.py", "config/database.yml"],
    )
    line_start: int = Field(
        ...,
        ge=1,
        description="1-indexed line number where the finding begins.",
    )
    line_end: int | None = Field(
        default=None,
        ge=1,
        description="1-indexed line number where the finding ends (inclusive). "
        "If None the finding is considered a single-line finding.",
    )
    column_start: int | None = Field(
        default=None,
        ge=1,
        description="1-indexed column number where the finding begins.",
    )
    column_end: int | None = Field(
        default=None,
        ge=1,
        description="1-indexed column number where the finding ends (inclusive).",
    )
    code_snippet: str | None = Field(
        default=None,
        description="The raw source-code excerpt that triggered the finding. "
        "Scanners SHOULD redact credential values before populating this field.",
    )

    @model_validator(mode="after")
    def validate_line_range(self) -> "FindingLocation":
        """Ensure line_end is not before line_start when both are provided."""
        if self.line_end is not None and self.line_end < self.line_start:
            raise ValueError(
                f"line_end ({self.line_end}) must be >= line_start ({self.line_start})"
            )
        return self


class Finding(BaseModel):
    """The atomic unit of output produced by any SafePush scanner.

    Every scanner plugin MUST return a list of :class:`Finding` objects.  The
    pipeline makes no assumptions about how findings were detected — it only
    consumes this model.

    Attributes
    ----------
    id:
        Universally unique identifier for this finding.  Auto-generated using
        UUIDv4 if not supplied by the scanner.
    rule_id:
        The scanner's internal rule or check identifier (e.g. ``semgrep:python.
        lang.security.audit.formatted-sql-query``).  Used for deduplication and
        suppression matching.
    title:
        Short human-readable summary (≤ 120 characters).
    description:
        Full explanation of the issue and its security implications.
    severity:
        CVSS-aligned severity level.
    category:
        High-level classification of the finding type.
    status:
        Triage lifecycle state; defaults to ``OPEN``.
    location:
        Precise file/line location of the finding.
    source_scanner:
        Opaque identifier of the scanner that produced this finding
        (e.g. ``"semgrep"``, ``"gitleaks"``, ``"custom:my-rule"``).
    fix_guidance:
        Optional remediation advice shown to the developer.
    references:
        Optional list of URLs pointing to CVE entries, CWE definitions,
        documentation, or blog posts that explain the issue.
    metadata:
        Arbitrary key-value pairs that scanner plugins may attach for
        scanner-specific context.  The core pipeline ignores this field.
    detected_at:
        UTC timestamp of when the finding was produced.
    """

    model_config = {"frozen": True}

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this finding (UUIDv4).",
    )
    rule_id: str = Field(
        ...,
        description="The scanner's rule or check identifier.",
        examples=["semgrep:python.lang.security.audit.sql-injection"],
    )
    title: str = Field(
        ...,
        min_length=1,
        max_length=120,
        description="Short human-readable summary of the finding.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Full explanation of the issue and its security implications.",
    )
    severity: FindingSeverity = Field(
        ...,
        description="CVSS-aligned severity level.",
    )
    category: FindingCategory = Field(
        ...,
        description="High-level classification of the finding type.",
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Triage lifecycle state; defaults to OPEN.",
    )
    location: FindingLocation = Field(
        ...,
        description="Precise file/line location of the finding.",
    )
    source_scanner: str = Field(
        ...,
        description="Opaque identifier of the scanner that produced this finding.",
        examples=["semgrep", "gitleaks", "custom:my-rule"],
    )
    fix_guidance: str | None = Field(
        default=None,
        description="Optional remediation advice for the developer.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="URLs pointing to CVE entries, CWE definitions, or documentation.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary scanner-specific context (ignored by core pipeline).",
    )
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the finding was produced.",
    )

    @field_validator("references", mode="before")
    @classmethod
    def deduplicate_references(cls, v: list[str]) -> list[str]:
        """Remove duplicate reference URLs while preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for url in v:
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    def is_suppressed(self) -> bool:
        """Return True if this finding has been intentionally suppressed."""
        return self.status == FindingStatus.SUPPRESSED

    def with_status(self, status: FindingStatus) -> "Finding":
        """Return a new Finding with an updated status (immutable update).

        Parameters
        ----------
        status:
            The new triage status to apply.

        Returns
        -------
        Finding
            A new :class:`Finding` instance with the updated status.
        """
        return self.model_copy(update={"status": status})
