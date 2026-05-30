"""
SafePush core engine.

The :class:`ScanEngine` is the central orchestrator of the SafePush pipeline.
It coordinates the following stages in order:

1. **Validation** — ensure the scan request and target are valid.
2. **Scanner dispatch** — run each applicable scanner plugin.
3. **Result aggregation** — collect findings from all scanners.
4. **Filtering** — apply severity threshold and finding cap.
5. **Scoring** — compute a :class:`~safepush.models.score.RiskScore`.
6. **Report assembly** — build the final :class:`~safepush.models.report.Report`.

The engine depends only on the :class:`~safepush.plugins.registry.ScannerRegistry`
and the :class:`~safepush.scoring.engine.ScoringEngine`.  It never imports
concrete scanner implementations.

Thread safety
-------------
The engine is *not* thread-safe for concurrent scans on the same instance.
For concurrent usage, create one engine instance per scan or use an executor
that ensures exclusive access.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from safepush.exceptions import (
    ScannerExecutionError,
    ScannerTimeoutError,
    ScanTargetNotFoundError,
)
from safepush.models.finding import Finding, FindingSeverity
from safepush.models.report import Report, ReportFormat, ReportSummary
from safepush.models.scan import ScanRequest, ScanResult, ScanStatus
from safepush.models.score import RiskScore, RiskLevel, ScoringWeights
from safepush.plugins.registry import ScannerRegistry
from safepush.scanner import ScannerProtocol
from safepush.scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)

# Severity ordering from least to most severe for threshold filtering
_SEVERITY_ORDER: list[FindingSeverity] = [
    FindingSeverity.INFORMATIONAL,
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
    FindingSeverity.UNKNOWN,  # Unknown always passes threshold (conservative)
]


def _severity_passes_threshold(
    finding_severity: FindingSeverity,
    threshold: FindingSeverity,
) -> bool:
    """Return True if finding_severity meets or exceeds the threshold.

    UNKNOWN severity always passes (conservative approach).

    Parameters
    ----------
    finding_severity:
        The severity of the finding to check.
    threshold:
        The minimum severity threshold.

    Returns
    -------
    bool
        True if the finding should be included in results.
    """
    if finding_severity == FindingSeverity.UNKNOWN:
        return True  # Always include unknown severity (conservative)
    try:
        finding_idx = _SEVERITY_ORDER.index(finding_severity)
        threshold_idx = _SEVERITY_ORDER.index(threshold)
        return finding_idx >= threshold_idx
    except ValueError:
        return True  # Unknown enums always pass


class ScanEngine:
    """Orchestrates the complete SafePush scanning pipeline.

    Parameters
    ----------
    registry:
        The :class:`~safepush.plugins.registry.ScannerRegistry` containing
        all available scanner plugins.
    scoring_engine:
        The :class:`~safepush.scoring.engine.ScoringEngine` to use for
        risk score computation.  If None, a default engine is created.

    Examples
    --------
    ::

        registry = ScannerRegistry.discover()
        engine = ScanEngine(registry)

        request = ScanRequest(
            target=ScanTarget(
                target_type=ScanTargetType.DIRECTORY,
                path=Path("./my-project"),
            )
        )
        report = engine.scan(request)
        print(f"Risk level: {report.risk_score.risk_level}")
    """

    def __init__(
        self,
        registry: ScannerRegistry,
        scoring_engine: ScoringEngine | None = None,
    ) -> None:
        self._registry = registry
        self._scoring_engine = scoring_engine or ScoringEngine()

    def scan(
        self,
        request: ScanRequest,
        *,
        report_format: ReportFormat = ReportFormat.TEXT,
    ) -> Report:
        """Execute a full scan and return a complete :class:`~safepush.models.report.Report`.

        This is the primary entry point for all SafePush consumers.

        Parameters
        ----------
        request:
            The :class:`~safepush.models.scan.ScanRequest` describing the
            scan target and configuration.
        report_format:
            The :class:`~safepush.models.report.ReportFormat` that the
            downstream renderer will use.  Stored in the report for reference.

        Returns
        -------
        Report
            The complete, self-contained scan report.

        Raises
        ------
        safepush.exceptions.ScanTargetNotFoundError
            If the scan target path does not exist.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)

        logger.info(
            "Starting scan [id=%s] on target '%s' (type=%s)",
            scan_id,
            request.target.path,
            request.target.target_type.value,
        )

        # Stage 1: Validate target exists
        self._validate_target(request)

        # Stage 2: Determine which scanners to run
        scanners = self._resolve_scanners(request)
        if not scanners:
            logger.warning("No scanners available for this scan. Returning empty result.")

        # Stage 3: Execute scanners and collect findings
        all_findings: list[Finding] = []
        errors: list[str] = []
        scanner_versions: dict[str, str] = {}

        for scanner in scanners:
            findings, scanner_errors = self._run_scanner(scanner, request)
            all_findings.extend(findings)
            errors.extend(scanner_errors)
            scanner_versions[scanner.scanner_id] = scanner.version

        # Stage 4: Filter findings by severity threshold and cap
        threshold = FindingSeverity(request.severity_threshold.upper())
        filtered = self._apply_filters(all_findings, threshold, request.max_findings)

        completed_at = datetime.now(timezone.utc)

        # Stage 5: Assemble ScanResult
        scan_result = ScanResult(
            scan_id=scan_id,
            request=request,
            status=ScanStatus.COMPLETED,
            findings=filtered,
            errors=errors,
            scanner_versions=scanner_versions,
            started_at=started_at,
            completed_at=completed_at,
        )

        # Stage 6: Compute risk score
        risk_score = self._scoring_engine.score(scan_result)

        # Stage 7: Build summary and report
        summary = self._build_summary(scan_result, risk_score, request)
        report = Report(
            scan_result=scan_result,
            risk_score=risk_score,
            summary=summary,
            format=report_format,
        )

        logger.info(
            "Scan [id=%s] completed: %d findings, risk_level=%s, duration=%.2fs",
            scan_id,
            len(filtered),
            risk_score.risk_level.value,
            scan_result.duration_seconds or 0.0,
        )

        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_target(self, request: ScanRequest) -> None:
        """Validate that the scan target exists on disk.

        Parameters
        ----------
        request:
            The scan request to validate.

        Raises
        ------
        safepush.exceptions.ScanTargetNotFoundError
            If the target path does not exist.
        """
        path: Path = request.target.path
        if not path.exists():
            raise ScanTargetNotFoundError(path)

    def _resolve_scanners(self, request: ScanRequest) -> list[ScannerProtocol]:
        """Determine which scanners to run for this request.

        If ``request.scanner_ids`` is empty, all registered scanners are used.
        Only scanners that report :meth:`~safepush.scanner.ScannerProtocol.is_available`
        as True are included.

        Parameters
        ----------
        request:
            The scan request.

        Returns
        -------
        list[ScannerProtocol]
            The scanners to run, filtered to those that are available.
        """
        if request.scanner_ids:
            candidates: list[ScannerProtocol] = []
            for sid in request.scanner_ids:
                scanner = self._registry.get_or_none(sid)
                if scanner is None:
                    logger.warning("Requested scanner '%s' is not registered — skipping.", sid)
                else:
                    candidates.append(scanner)
        else:
            candidates = list(self._registry.all())

        available: list[ScannerProtocol] = []
        for scanner in candidates:
            if scanner.is_available():
                available.append(scanner)
            else:
                logger.warning(
                    "Scanner '%s' is not available (backend tool may not be installed).",
                    scanner.scanner_id,
                )
        return available

    def _run_scanner(
        self,
        scanner: ScannerProtocol,
        request: ScanRequest,
    ) -> tuple[list[Finding], list[str]]:
        """Execute a single scanner and collect its findings and errors.

        Parameters
        ----------
        scanner:
            The scanner to execute.
        request:
            The scan request.

        Returns
        -------
        tuple[list[Finding], list[str]]
            A tuple of (findings, error_messages).
        """
        try:
            logger.debug("Running scanner '%s'", scanner.scanner_id)
            findings = list(scanner.scan(request))
            logger.debug(
                "Scanner '%s' returned %d finding(s)", scanner.scanner_id, len(findings)
            )
            return findings, []

        except ScannerTimeoutError as exc:
            logger.warning("Scanner '%s' timed out: %s", scanner.scanner_id, exc.message)
            return [], [f"[{scanner.scanner_id}] Timeout: {exc.message}"]

        except ScannerExecutionError as exc:
            logger.warning(
                "Scanner '%s' execution failed: %s", scanner.scanner_id, exc.message
            )
            return [], [f"[{scanner.scanner_id}] Execution error: {exc.message}"]

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Scanner '%s' raised an unexpected error: %s",
                scanner.scanner_id,
                exc,
                exc_info=True,
            )
            return [], [
                f"[{scanner.scanner_id}] Unexpected error: {type(exc).__name__}: {exc}"
            ]

    @staticmethod
    def _apply_filters(
        findings: list[Finding],
        threshold: FindingSeverity,
        max_findings: int | None,
    ) -> list[Finding]:
        """Filter and cap findings.

        Parameters
        ----------
        findings:
            Raw findings from all scanners.
        threshold:
            Minimum severity to include.
        max_findings:
            Maximum number of findings to return (None means unlimited).

        Returns
        -------
        list[Finding]
            Filtered and capped findings.
        """
        filtered = [
            f for f in findings
            if _severity_passes_threshold(f.severity, threshold)
        ]
        if max_findings is not None:
            filtered = filtered[:max_findings]
        return filtered

    @staticmethod
    def _build_summary(
        scan_result: ScanResult,
        risk_score: RiskScore,
        request: ScanRequest,
    ) -> ReportSummary:
        """Build pre-computed summary statistics for the report.

        Parameters
        ----------
        scan_result:
            The completed scan result.
        risk_score:
            The computed risk score.
        request:
            The original scan request.

        Returns
        -------
        ReportSummary
            Aggregated statistics.
        """
        from safepush.models.finding import FindingStatus, FindingSeverity

        findings = scan_result.findings
        critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        informational_count = sum(
            1 for f in findings if f.severity == FindingSeverity.INFORMATIONAL
        )
        open_count = sum(
            1 for f in findings
            if f.status in (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)
        )
        suppressed_count = sum(1 for f in findings if f.status == FindingStatus.SUPPRESSED)
        fixed_count = sum(1 for f in findings if f.status == FindingStatus.FIXED)
        files_affected = len({f.location.file_path for f in findings})

        # Determine if the scan passes CI gate
        passed = True
        if request.fail_on_severity:
            fail_threshold = FindingSeverity(request.fail_on_severity.upper())
            passed = not any(
                _severity_passes_threshold(f.severity, fail_threshold)
                for f in scan_result.get_active_findings()
            )

        return ReportSummary(
            total_findings=len(findings),
            open_findings=open_count,
            suppressed_findings=suppressed_count,
            fixed_findings=fixed_count,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            informational_count=informational_count,
            files_affected=files_affected,
            scanners_run=list(scan_result.scanner_versions.keys()),
            risk_level=risk_score.risk_level,
            passed=passed,
        )
