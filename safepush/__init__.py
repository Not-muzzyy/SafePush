"""
SafePush — Secure Every Push.

SafePush detects secrets, vulnerabilities, insecure coding patterns, and risky
AI-generated code before code reaches GitHub, CI/CD pipelines, or production.

This is the top-level package.  All public APIs flow through here.

Version
-------
The canonical version is maintained in this file and referenced by
``pyproject.toml`` via ``importlib.metadata`` at install time.

Public API
----------
The primary public API is:

* :class:`safepush.core.engine.ScanEngine` — the main engine
* :class:`safepush.models` — all domain models
* :class:`safepush.plugins.registry.ScannerRegistry` — plugin registry
* :class:`safepush.scanner.ScannerProtocol` — scanner interface
* :class:`safepush.scanner.BaseScanner` — optional base class for plugins
* :class:`safepush.exceptions` — exception hierarchy
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "SafePush Contributors"
__license__ = "MIT"
__url__ = "https://github.com/safepush/safepush"

# Convenience re-exports of the most commonly used symbols
from safepush.core.engine import ScanEngine
from safepush.models.finding import Finding, FindingSeverity, FindingCategory
from safepush.models.scan import ScanRequest, ScanResult, ScanTarget, ScanTargetType
from safepush.models.report import Report, ReportFormat
from safepush.models.score import RiskScore, RiskLevel, ScoringWeights
from safepush.plugins.registry import ScannerRegistry
from safepush.scanner import BaseScanner, ScannerProtocol
from safepush.scoring.engine import ScoringEngine

__all__ = [
    "__version__",
    # Engine
    "ScanEngine",
    # Models
    "Finding",
    "FindingSeverity",
    "FindingCategory",
    "ScanRequest",
    "ScanResult",
    "ScanTarget",
    "ScanTargetType",
    "Report",
    "ReportFormat",
    "RiskScore",
    "RiskLevel",
    "ScoringWeights",
    # Plugins
    "ScannerRegistry",
    "ScannerProtocol",
    "BaseScanner",
    # Scoring
    "ScoringEngine",
]
