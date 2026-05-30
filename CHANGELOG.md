# Changelog

All notable changes to SafePush will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Plugin-based scanner architecture with `ScannerProtocol` and `BaseScanner`
- Thread-safe `ScannerRegistry` with Python entry-point discovery
- Full Pydantic v2 domain models: `Finding`, `ScanRequest`, `ScanTarget`, `ScanResult`, `Report`, `RiskScore`
- Weighted, normalised `ScoringEngine` with configurable `ScoringWeights`
- JSON and ANSI-coloured terminal report renderers
- `ReportDispatcher` for pluggable report format routing
- Typer CLI with `scan`, `version`, and `list-scanners` commands
- Comprehensive exception hierarchy under `SafePushError`
- Filesystem utilities (`fs.py`) and Git subprocess wrappers (`git.py`)
- Structured logging configuration (`logging.py`)
- 80+ tests (unit + integration) with `pytest` and `pytest-cov`
- Full MyPy strict type checking
- Ruff + Black code style enforcement

---

[Unreleased]: https://github.com/safepush/safepush/compare/HEAD...HEAD
