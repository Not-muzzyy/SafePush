"""
Unit tests for Finding and FindingLocation domain models.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from safepush.models.finding import (
    Finding,
    FindingCategory,
    FindingLocation,
    FindingSeverity,
    FindingStatus,
)


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_all_severities_have_numeric_weights(self) -> None:
        """Every severity must have a defined numeric weight."""
        for severity in FindingSeverity:
            weight = severity.numeric_weight
            assert 0.0 <= weight <= 1.0, (
                f"{severity.value} weight {weight} is out of [0, 1] range"
            )

    def test_critical_has_highest_weight(self) -> None:
        """CRITICAL must have the highest numeric weight."""
        assert FindingSeverity.CRITICAL.numeric_weight == 1.0

    def test_informational_has_lowest_non_unknown_weight(self) -> None:
        """INFORMATIONAL should have the lowest weight among known severities."""
        known = [s for s in FindingSeverity if s != FindingSeverity.UNKNOWN]
        lowest = min(s.numeric_weight for s in known)
        assert FindingSeverity.INFORMATIONAL.numeric_weight == lowest

    def test_unknown_is_conservative(self) -> None:
        """UNKNOWN severity should have a higher weight than LOW (conservative)."""
        assert FindingSeverity.UNKNOWN.numeric_weight > FindingSeverity.LOW.numeric_weight


class TestFindingLocation:
    """Tests for FindingLocation model validation."""

    def test_valid_location_single_line(self) -> None:
        """A minimal single-line location is valid."""
        loc = FindingLocation(file_path="src/app.py", line_start=42)
        assert loc.file_path == "src/app.py"
        assert loc.line_start == 42
        assert loc.line_end is None

    def test_valid_location_with_range(self) -> None:
        """A location with line_end >= line_start is valid."""
        loc = FindingLocation(file_path="src/app.py", line_start=10, line_end=20)
        assert loc.line_end == 20

    def test_valid_location_same_line_range(self) -> None:
        """line_end == line_start is a valid single-line range."""
        loc = FindingLocation(file_path="src/app.py", line_start=5, line_end=5)
        assert loc.line_start == loc.line_end

    def test_invalid_line_end_before_line_start(self) -> None:
        """line_end < line_start must raise a ValidationError."""
        with pytest.raises(ValidationError):
            FindingLocation(file_path="src/app.py", line_start=20, line_end=10)

    def test_line_start_must_be_positive(self) -> None:
        """line_start must be >= 1."""
        with pytest.raises(ValidationError):
            FindingLocation(file_path="src/app.py", line_start=0)

    def test_location_is_immutable(self) -> None:
        """FindingLocation must be frozen (immutable)."""
        loc = FindingLocation(file_path="src/app.py", line_start=1)
        with pytest.raises(Exception):  # pydantic raises on frozen model assignment
            loc.file_path = "other.py"  # type: ignore[misc]


class TestFinding:
    """Tests for the Finding domain model."""

    def test_finding_auto_generates_id(self, sample_finding: Finding) -> None:
        """A Finding with no explicit id should auto-generate a UUIDv4."""
        assert sample_finding.id
        # UUIDv4 format: 8-4-4-4-12 hex digits
        parts = sample_finding.id.split("-")
        assert len(parts) == 5

    def test_finding_has_defaults(self) -> None:
        """Defaults should be applied for optional fields."""
        finding = Finding(
            rule_id="test:rule",
            title="Title",
            description="Description",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.SECRET,
            location=FindingLocation(file_path="f.py", line_start=1),
            source_scanner="scanner",
        )
        assert finding.status == FindingStatus.OPEN
        assert finding.references == []
        assert finding.metadata == {}
        assert finding.fix_guidance is None

    def test_finding_title_max_length(self) -> None:
        """Title must not exceed 120 characters."""
        with pytest.raises(ValidationError):
            Finding(
                rule_id="r",
                title="x" * 121,
                description="d",
                severity=FindingSeverity.LOW,
                category=FindingCategory.VULNERABILITY,
                location=FindingLocation(file_path="f.py", line_start=1),
                source_scanner="s",
            )

    def test_finding_title_empty_is_invalid(self) -> None:
        """An empty title must be rejected."""
        with pytest.raises(ValidationError):
            Finding(
                rule_id="r",
                title="",
                description="d",
                severity=FindingSeverity.LOW,
                category=FindingCategory.VULNERABILITY,
                location=FindingLocation(file_path="f.py", line_start=1),
                source_scanner="s",
            )

    def test_finding_is_immutable(self, sample_finding: Finding) -> None:
        """Finding must be frozen."""
        with pytest.raises(Exception):
            sample_finding.title = "Changed"  # type: ignore[misc]

    def test_is_suppressed_false_for_open(self, sample_finding: Finding) -> None:
        """is_suppressed() returns False for OPEN findings."""
        assert not sample_finding.is_suppressed()

    def test_is_suppressed_true_for_suppressed(self, sample_finding: Finding) -> None:
        """is_suppressed() returns True for SUPPRESSED findings."""
        suppressed = sample_finding.with_status(FindingStatus.SUPPRESSED)
        assert suppressed.is_suppressed()

    def test_with_status_returns_new_instance(self, sample_finding: Finding) -> None:
        """with_status() must return a new Finding, not mutate the original."""
        updated = sample_finding.with_status(FindingStatus.FIXED)
        assert updated.status == FindingStatus.FIXED
        assert sample_finding.status == FindingStatus.OPEN  # original unchanged

    def test_references_are_deduplicated(self) -> None:
        """Duplicate reference URLs should be removed."""
        finding = Finding(
            rule_id="r",
            title="T",
            description="D",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.VULNERABILITY,
            location=FindingLocation(file_path="f.py", line_start=1),
            source_scanner="s",
            references=["https://cve.example.com/1", "https://cve.example.com/1"],
        )
        assert len(finding.references) == 1

    def test_references_preserve_order(self) -> None:
        """Deduplicated references must preserve insertion order."""
        urls = [
            "https://cve.example.com/3",
            "https://cve.example.com/1",
            "https://cve.example.com/2",
        ]
        finding = Finding(
            rule_id="r",
            title="T",
            description="D",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.VULNERABILITY,
            location=FindingLocation(file_path="f.py", line_start=1),
            source_scanner="s",
            references=urls,
        )
        assert finding.references == urls
