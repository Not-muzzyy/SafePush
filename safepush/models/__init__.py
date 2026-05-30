"""
SafePush domain models package.

This package contains all Pydantic-based domain models that represent
the core data structures flowing through the SafePush pipeline:

    Scanner → Finding → Risk Score → Report

These models are intentionally decoupled from any scanner implementation,
making them stable contracts that can be consumed by CLI, VS Code extensions,
MCP servers, GitHub Actions, and any future integration surface.
"""

from safepush.models.finding import (
    Finding,
    FindingLocation,
    FindingSeverity,
    FindingCategory,
    FindingStatus,
)
from safepush.models.scan import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanTarget,
    ScanTargetType,
)
from safepush.models.report import (
    Report,
    ReportFormat,
    ReportSummary,
)
from safepush.models.score import (
    RiskScore,
    RiskLevel,
    ScoringWeights,
)

__all__ = [
    # Finding models
    "Finding",
    "FindingLocation",
    "FindingSeverity",
    "FindingCategory",
    "FindingStatus",
    # Scan models
    "ScanRequest",
    "ScanResult",
    "ScanStatus",
    "ScanTarget",
    "ScanTargetType",
    # Report models
    "Report",
    "ReportFormat",
    "ReportSummary",
    # Score models
    "RiskScore",
    "RiskLevel",
    "ScoringWeights",
]
