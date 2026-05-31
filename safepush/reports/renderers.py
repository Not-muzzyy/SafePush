"""
JSON and plain-text report renderers.

These are the two built-in renderers shipped with the SafePush core package.
Additional formats (SARIF, Markdown, HTML) may be added as separate packages
or contributed to core in future releases.
"""

from __future__ import annotations

import json
from datetime import datetime

from safepush.models.finding import FindingSeverity
from safepush.models.report import Report, ReportFormat
from safepush.models.score import RiskLevel
from safepush.reports.base import BaseReportRenderer

# ANSI colour codes used by the text renderer
_ANSI: dict[str, str] = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "bright_red": "\033[91m",
    "yellow": "\033[33m",
    "bright_yellow": "\033[93m",
    "green": "\033[32m",
    "bright_green": "\033[92m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_white": "\033[97m",
    "grey": "\033[90m",
}

_SEVERITY_COLOURS: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: _ANSI["bright_red"] + _ANSI["bold"],
    FindingSeverity.HIGH: _ANSI["red"],
    FindingSeverity.MEDIUM: _ANSI["yellow"],
    FindingSeverity.LOW: _ANSI["cyan"],
    FindingSeverity.INFORMATIONAL: _ANSI["grey"],
    FindingSeverity.UNKNOWN: _ANSI["white"],
}

_RISK_LEVEL_COLOURS: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: _ANSI["bright_red"] + _ANSI["bold"],
    RiskLevel.HIGH: _ANSI["red"],
    RiskLevel.MEDIUM: _ANSI["yellow"],
    RiskLevel.LOW: _ANSI["cyan"],
    RiskLevel.NONE: _ANSI["bright_green"],
}


class JsonReportRenderer(BaseReportRenderer):
    """Renders a :class:`~safepush.models.report.Report` as pretty-printed JSON.

    The JSON output is the canonical machine-readable format used by all
    SafePush integrations (MCP tools, CI artefacts, VS Code extensions).

    Parameters
    ----------
    indent:
        JSON indentation (default 2).
    """

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    @property
    def format(self) -> ReportFormat:
        """Return the JSON report format."""
        return ReportFormat.JSON

    def render(self, report: Report) -> str:
        """Render the report as pretty-printed JSON.

        Parameters
        ----------
        report:
            The report to render.

        Returns
        -------
        str
            JSON string of the full report.
        """
        # Use Pydantic's model serialisation for correctness
        data = report.model_dump(mode="json")
        return json.dumps(data, indent=self._indent, default=str)


class TextReportRenderer(BaseReportRenderer):
    """Renders a :class:`~safepush.models.report.Report` as formatted terminal output.

    Uses ANSI escape codes for colour.  To disable colour (e.g. in CI logs),
    set ``use_colour=False``.

    Parameters
    ----------
    use_colour:
        Whether to include ANSI colour codes (default True).
    show_details:
        Whether to show the full description and fix guidance for each finding
        (default True).  Set to False for compact output.
    """

    def __init__(
        self,
        use_colour: bool = True,
        show_details: bool = True,
    ) -> None:
        self._colour = use_colour
        self._show_details = show_details

    @property
    def format(self) -> ReportFormat:
        """Return the TEXT report format."""
        return ReportFormat.TEXT

    def render(self, report: Report) -> str:
        """Render the report as a formatted terminal string.

        Parameters
        ----------
        report:
            The report to render.

        Returns
        -------
        str
            Formatted terminal string.
        """
        lines: list[str] = []
        s = report.summary
        score = report.risk_score

        # Header
        lines.append(self._c("bold") + "=" * 60 + self._r())
        lines.append(
            self._c("bold")
            + self._c("bright_white")
            + "  SafePush Security Scan Report"
            + self._r()
        )
        lines.append(self._c("bold") + "=" * 60 + self._r())
        lines.append("")

        # Target info
        target = report.scan_result.request.target
        lines.append(
            f"  {self._c('dim')}Target:{self._r()} {target.path} ({target.target_type.value})"
        )
        lines.append(
            f"  {self._c('dim')}Scan ID:{self._r()} {report.scan_result.scan_id}"
        )
        generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(f"  {self._c('dim')}Generated:{self._r()} {generated}")
        duration = report.scan_result.duration_seconds
        if duration is not None:
            lines.append(f"  {self._c('dim')}Duration:{self._r()} {duration:.2f}s")
        lines.append("")

        # Risk score panel
        risk_colour = _RISK_LEVEL_COLOURS.get(score.risk_level, "")
        lines.append(self._c("bold") + "  Risk Score" + self._r())
        lines.append(
            f"  ├─ Level:  {self._c_raw(risk_colour)}{score.risk_level.value}{self._r()}"
        )
        lines.append(f"  ├─ Score:  {score.normalised_score:.3f} / 1.000")
        lines.append(f"  └─ Raw:    {score.raw_score:.2f}")
        lines.append("")

        # Summary panel
        lines.append(self._c("bold") + "  Findings Summary" + self._r())
        lines.append(f"  ├─ Total:         {s.total_findings}")
        if s.critical_count:
            lines.append(
                f"  ├─ {self._c('bright_red')}CRITICAL{self._r()}:      {s.critical_count}"
            )
        if s.high_count:
            lines.append(
                f"  ├─ {self._c('red')}HIGH{self._r()}:          {s.high_count}"
            )
        if s.medium_count:
            lines.append(
                f"  ├─ {self._c('yellow')}MEDIUM{self._r()}:        {s.medium_count}"
            )
        if s.low_count:
            lines.append(
                f"  ├─ {self._c('cyan')}LOW{self._r()}:           {s.low_count}"
            )
        if s.informational_count:
            lines.append(
                f"  ├─ {self._c('grey')}INFORMATIONAL{self._r()}: {s.informational_count}"
            )
        lines.append(f"  ├─ Files affected: {s.files_affected}")
        lines.append(f"  └─ Scanners run:  {', '.join(s.scanners_run) or 'none'}")
        lines.append("")

        # CI gate status
        gate_text = "PASSED" if s.passed else "FAILED"
        gate_colour = self._c("bright_green") if s.passed else self._c("bright_red")
        lines.append(
            f"  CI Gate: {gate_colour}{self._c('bold')}{gate_text}{self._r()}"
        )
        lines.append("")

        # Findings detail
        if report.scan_result.findings and self._show_details:
            lines.append(self._c("bold") + "  Findings" + self._r())
            lines.append("  " + "─" * 56)

            for i, finding in enumerate(report.scan_result.findings, 1):
                sev_colour = _SEVERITY_COLOURS.get(finding.severity, "")
                sev = finding.severity.value
                lines.append(
                    f"\n  [{i}] {self._c_raw(sev_colour)}{sev}{self._r()} "
                    f"— {self._c('bold')}{finding.title}{self._r()}"
                )
                lines.append(
                    f"       {self._c('dim')}Rule:{self._r()} {finding.rule_id}"
                )
                lines.append(
                    f"       {self._c('dim')}Location:{self._r()} "
                    f"{finding.location.file_path}:{finding.location.line_start}"
                )
                lines.append(
                    f"       {self._c('dim')}Scanner:{self._r()} {finding.source_scanner}"
                )
                if self._show_details:
                    lines.append(
                        f"       {self._c('dim')}Category:{self._r()} {finding.category.value}"
                    )
                    if finding.fix_guidance:
                        lines.append(
                            f"       {self._c('dim')}Fix:{self._r()} {finding.fix_guidance}"
                        )

        # Errors
        if report.scan_result.errors:
            lines.append("")
            lines.append(
                self._c("yellow") + "  [!] Scanner Warnings" + self._r()
            )
            for error in report.scan_result.errors:
                lines.append(f"     • {error}")

        lines.append("")
        lines.append(self._c("bold") + "=" * 60 + self._r())
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal colour helpers
    # ------------------------------------------------------------------

    def _c(self, name: str) -> str:
        """Return the ANSI code for the given name if colour is enabled."""
        if not self._colour:
            return ""
        return _ANSI.get(name, "")

    def _c_raw(self, raw_code: str) -> str:
        """Return a raw ANSI code string if colour is enabled."""
        return raw_code if self._colour else ""

    def _r(self) -> str:
        """Return the ANSI reset code if colour is enabled."""
        return _ANSI["reset"] if self._colour else ""
