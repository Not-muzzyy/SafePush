"""
Scan domain models for SafePush.

These models represent the *input* to a scan (:class:`ScanRequest` and
:class:`ScanTarget`) and the *output* of a completed scan (:class:`ScanResult`).

The separation of :class:`ScanRequest` from :class:`ScanResult` follows the
Command-Query Responsibility Segregation (CQRS) pattern: callers build a
``ScanRequest`` describing *what* to scan and *how*, then the engine produces a
``ScanResult`` that is completely self-contained and serialisable.

This means a ``ScanResult`` can be:
- Persisted as JSON to disk for later processing
- Streamed over a WebSocket to a VS Code extension
- Serialised and passed as an MCP tool response
- Archived in CI artefact storage

…all without any additional transformation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Sequence

from pydantic import BaseModel, Field, field_validator

from safepush.models.finding import Finding


class ScanTargetType(str, Enum):
    """Describes what kind of entity is being scanned.

    This allows the engine and plugins to apply target-appropriate scanning
    strategies (e.g. a ``GIT_DIFF`` target should only scan changed lines,
    while a ``DIRECTORY`` target scans every file recursively).
    """

    FILE = "FILE"
    """A single file."""

    DIRECTORY = "DIRECTORY"
    """A directory to be scanned recursively."""

    GIT_DIFF = "GIT_DIFF"
    """The output of ``git diff`` — only changed lines are scanned."""

    GIT_STAGED = "GIT_STAGED"
    """Files currently staged in the Git index (``git diff --cached``)."""

    GIT_COMMIT = "GIT_COMMIT"
    """All files modified in a specific Git commit."""


class ScanTarget(BaseModel):
    """Describes the artefact to be scanned.

    Parameters
    ----------
    target_type:
        The kind of entity being scanned.
    path:
        Filesystem path to the target.  For ``GIT_DIFF`` and ``GIT_STAGED``
        this should be the root of the Git repository.
    ref:
        Optional Git ref (commit SHA, branch, or tag) relevant to
        ``GIT_COMMIT`` and ``GIT_DIFF`` target types.
    include_patterns:
        Glob patterns for files to include.  An empty list means *include all*.
    exclude_patterns:
        Glob patterns for files to exclude.
    """

    model_config = {"frozen": True}

    target_type: ScanTargetType = Field(
        ...,
        description="The kind of entity being scanned.",
    )
    path: Path = Field(
        ...,
        description="Filesystem path to the scan target.",
    )
    ref: str | None = Field(
        default=None,
        description="Git ref relevant to GIT_COMMIT and GIT_DIFF target types.",
    )
    include_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns for files to include. Empty list means all.",
        examples=[["*.py", "*.js"]],
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns for files to exclude.",
        examples=[["node_modules/**", "*.min.js"]],
    )

    @field_validator("path", mode="before")
    @classmethod
    def coerce_path(cls, v: str | Path) -> Path:
        """Ensure path is always a :class:`~pathlib.Path` instance."""
        return Path(v)


class ScanRequest(BaseModel):
    """Describes a complete scan job submitted to the SafePush engine.

    A ``ScanRequest`` is the *command* side of the scan pipeline.  It answers
    the question: "What do you want scanned, with which scanners, under which
    constraints?"

    Parameters
    ----------
    target:
        The scan target.
    scanner_ids:
        Explicit list of scanner plugin IDs to run.  An empty list means *run
        all registered scanners*.
    severity_threshold:
        The minimum severity level to report.  Findings below this threshold
        will be filtered from the :class:`ScanResult`.
    fail_on_severity:
        If set, the CLI will exit with a non-zero code when any finding at or
        above this severity is found.  Used in CI/CD gate scenarios.
    max_findings:
        Hard cap on the number of findings returned.  Useful for very large
        repositories where the first ``N`` findings are sufficient.
    timeout_seconds:
        Maximum wall-clock seconds allowed for the entire scan.  Individual
        scanner plugins are responsible for respecting this.
    """

    model_config = {"frozen": True}

    target: ScanTarget = Field(
        ...,
        description="The scan target.",
    )
    scanner_ids: list[str] = Field(
        default_factory=list,
        description="Scanner plugin IDs to run. Empty means run all.",
        examples=[["semgrep", "gitleaks"]],
    )
    severity_threshold: str = Field(
        default="LOW",
        description="Minimum severity level to include in results.",
        examples=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    fail_on_severity: str | None = Field(
        default=None,
        description="Exit non-zero if any finding at this severity or above is found.",
        examples=["HIGH", "CRITICAL"],
    )
    max_findings: int | None = Field(
        default=None,
        ge=1,
        description="Hard cap on findings returned. None means unlimited.",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum scan duration in seconds.",
    )


class ScanStatus(str, Enum):
    """Terminal and intermediate states of a scan execution."""

    PENDING = "PENDING"
    """The scan has been submitted but not yet started."""

    RUNNING = "RUNNING"
    """The scan is actively in progress."""

    COMPLETED = "COMPLETED"
    """The scan finished successfully (findings may or may not be present)."""

    FAILED = "FAILED"
    """The scan encountered a fatal error and could not complete."""

    TIMED_OUT = "TIMED_OUT"
    """The scan exceeded the configured ``timeout_seconds``."""

    CANCELLED = "CANCELLED"
    """The scan was cancelled by the caller before completion."""


class ScanResult(BaseModel):
    """The complete, self-contained output of a SafePush scan.

    A ``ScanResult`` is the *query* side of the scan pipeline.  It is
    intentionally immutable and fully self-describing — every field required to
    understand, render, and act on the result is embedded within it.

    Attributes
    ----------
    scan_id:
        Unique identifier for this scan run (UUIDv4).
    request:
        The original :class:`ScanRequest` that produced this result.
    status:
        Terminal status of the scan.
    findings:
        All findings produced by the enabled scanners, filtered by
        ``severity_threshold`` and capped by ``max_findings``.
    errors:
        Any non-fatal errors that occurred during scanning (e.g. a single
        scanner plugin failing while others succeed).
    scanner_versions:
        Map of ``scanner_id → version_string`` for auditing and reproducibility.
    started_at:
        UTC timestamp when scanning began.
    completed_at:
        UTC timestamp when scanning ended (or None if still running).
    duration_seconds:
        Wall-clock duration of the scan, computed from start/end timestamps.
    """

    model_config = {"frozen": True}

    scan_id: str = Field(
        ...,
        description="Unique identifier for this scan run (UUIDv4).",
    )
    request: ScanRequest = Field(
        ...,
        description="The original ScanRequest that produced this result.",
    )
    status: ScanStatus = Field(
        ...,
        description="Terminal status of the scan.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings produced by enabled scanners.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during scanning.",
    )
    scanner_versions: dict[str, str] = Field(
        default_factory=dict,
        description="Map of scanner_id → version_string for auditing.",
    )
    started_at: datetime = Field(
        ...,
        description="UTC timestamp when scanning began.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when scanning ended.",
    )

    @property
    def duration_seconds(self) -> float | None:
        """Return wall-clock scan duration, or None if the scan is still running."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    @property
    def has_critical_findings(self) -> bool:
        """Return True if any CRITICAL severity findings exist."""
        from safepush.models.finding import FindingSeverity

        return any(f.severity == FindingSeverity.CRITICAL for f in self.findings)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Return findings grouped by severity level.

        Returns
        -------
        dict[str, list[Finding]]
            Dictionary mapping severity name to list of findings, ordered from
            most to least severe.
        """
        from safepush.models.finding import FindingSeverity

        result: dict[str, list[Finding]] = {s.value: [] for s in FindingSeverity}
        for finding in self.findings:
            result[finding.severity.value].append(finding)
        return result

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Return findings grouped by file path.

        Returns
        -------
        dict[str, list[Finding]]
            Dictionary mapping file path to list of findings in that file.
        """
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            path = finding.location.file_path
            result.setdefault(path, []).append(finding)
        return result

    def get_active_findings(self) -> Sequence[Finding]:
        """Return only non-suppressed findings.

        Returns
        -------
        Sequence[Finding]
            Findings with status other than SUPPRESSED.
        """
        return [f for f in self.findings if not f.is_suppressed()]
