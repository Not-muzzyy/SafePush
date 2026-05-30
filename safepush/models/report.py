"""
Report domain models for SafePush.

A :class:`Report` is the final, human-and-machine-readable artefact produced at
the end of the SafePush pipeline.  It combines the raw :class:`~safepush.models.
scan.ScanResult` with a computed :class:`~safepush.models.score.RiskScore` and a
pre-calculated :class:`ReportSummary` to give consumers everything they need
without requiring them to re-compute aggregates.

Reports are format-agnostic at the model level.  The :class:`ReportFormat` enum
describes *which* serialisation format a downstream renderer should produce —
the model itself always stores the structured data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from safepush.models.scan import ScanResult
from safepush.models.score import RiskScore, RiskLevel


class ReportFormat(str, Enum):
    """Serialisation formats supported by the SafePush report renderer.

    Renderers for each format are located in :mod:`safepush.reports`.
    """

    JSON = "JSON"
    """Machine-readable JSON — used by integrations (MCP, VS Code, CI)."""

    TEXT = "TEXT"
    """Plain text output suitable for terminal display and log files."""

    SARIF = "SARIF"
    """Static Analysis Results Interchange Format v2.1.0 — GitHub native."""

    MARKDOWN = "MARKDOWN"
    """Markdown summary suitable for PR comments and GitHub step summaries."""

    HTML = "HTML"
    """Self-contained HTML report for sharing via email or browser."""


class ReportSummary(BaseModel):
    """Pre-computed aggregate statistics for quick consumption.

    Having these fields pre-calculated at report time means consumers (CLI,
    badge generators, Slack bots) can render a quick summary without iterating
    over potentially thousands of findings.

    Attributes
    ----------
    total_findings:
        Total findings regardless of severity or status.
    open_findings:
        Findings with status ``OPEN`` or ``ACKNOWLEDGED``.
    suppressed_findings:
        Findings with status ``SUPPRESSED``.
    fixed_findings:
        Findings with status ``FIXED``.
    critical_count:
        Number of CRITICAL severity findings.
    high_count:
        Number of HIGH severity findings.
    medium_count:
        Number of MEDIUM severity findings.
    low_count:
        Number of LOW severity findings.
    informational_count:
        Number of INFORMATIONAL severity findings.
    files_affected:
        Number of unique files containing at least one finding.
    scanners_run:
        List of scanner IDs that ran during this scan.
    risk_level:
        Overall risk level from the computed :class:`~safepush.models.score.RiskScore`.
    passed:
        True if the scan result would *not* trigger a CI/CD failure gate.
    """

    model_config = {"frozen": True}

    total_findings: int = Field(default=0, ge=0)
    open_findings: int = Field(default=0, ge=0)
    suppressed_findings: int = Field(default=0, ge=0)
    fixed_findings: int = Field(default=0, ge=0)

    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    informational_count: int = Field(default=0, ge=0)

    files_affected: int = Field(default=0, ge=0)
    scanners_run: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = Field(default=RiskLevel.NONE)
    passed: bool = Field(
        default=True,
        description="True if the scan would not fail a CI/CD gate.",
    )


class Report(BaseModel):
    """The final, self-contained output artefact of the SafePush pipeline.

    A ``Report`` is the root object that downstream consumers (CLI renderers,
    API responses, file writers) receive.  It is fully serialisable so that it
    can be:

    * Written to disk as ``safepush-report.json``
    * Uploaded as a CI artefact
    * Returned from an MCP tool call
    * Streamed over SSE to a VS Code panel

    Attributes
    ----------
    report_id:
        Unique identifier for this report (UUIDv4).
    scan_result:
        The underlying :class:`~safepush.models.scan.ScanResult`.
    risk_score:
        The computed :class:`~safepush.models.score.RiskScore` for this scan.
    summary:
        Pre-computed :class:`ReportSummary` statistics.
    format:
        The :class:`ReportFormat` this report is intended to be rendered as.
    generated_at:
        UTC timestamp when this report was generated.
    safepush_version:
        The version of SafePush that generated this report.  Embedded for
        long-term reproducibility — reports archived today should still be
        parseable in 5 years.
    """

    model_config = {"frozen": True}

    report_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this report (UUIDv4).",
    )
    scan_result: ScanResult = Field(
        ...,
        description="The underlying ScanResult.",
    )
    risk_score: RiskScore = Field(
        ...,
        description="Computed risk score for this scan.",
    )
    summary: ReportSummary = Field(
        ...,
        description="Pre-computed aggregate statistics.",
    )
    format: ReportFormat = Field(
        default=ReportFormat.TEXT,
        description="The format this report is intended to be rendered as.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this report was generated.",
    )
    safepush_version: str = Field(
        default="0.1.0",
        description="SafePush version that generated this report.",
    )
