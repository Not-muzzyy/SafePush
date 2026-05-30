# 🔐 SafePush

<div align="center">

**Secure Every Push.**

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/safepush?style=flat-square)](https://pypi.org/project/safepush)
[![CI](https://img.shields.io/github/actions/workflow/status/safepush/safepush/ci.yml?style=flat-square)](https://github.com/safepush/safepush/actions)
[![Coverage](https://img.shields.io/codecov/c/github/safepush/safepush?style=flat-square)](https://codecov.io/gh/safepush/safepush)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000?style=flat-square)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json&style=flat-square)](https://github.com/astral-sh/ruff)

*SafePush helps developers detect secrets, vulnerabilities, insecure coding patterns,
and risky AI-generated code before it reaches GitHub, CI/CD pipelines, or production.*

[**Installation**](#installation) · [**Quick Start**](#quick-start) · [**Architecture**](#architecture) · [**Roadmap**](#roadmap) · [**Contributing**](#contributing)

</div>

---

## Why SafePush?

Every week, developers accidentally push API keys, database passwords, and insecure code
to repositories. The consequences range from minor embarrassment to catastrophic breaches.

The problem is not carelessness — it is that the **feedback loop is too far from the keyboard**.

SafePush moves the security gate to the moment a developer is about to `git push`,
where fixing an issue takes seconds instead of hours.

### The Problem SafePush Solves

| Traditional Approach | SafePush Approach |
|---|---|
| Secrets detected in production | Secrets blocked at `git push` |
| Security review happens in PR | Security review happens in your editor |
| Monolithic scanner with all tools | Pluggable, composable scanner ecosystem |
| Binary pass/fail | Risk-scored findings with context |
| CI-only | CLI + VS Code + GitHub Action + MCP |

---

## Architecture

SafePush is designed as an **ecosystem**, not a single tool. The core is a
minimal, stable foundation that scanner plugins and integration surfaces build on.

```
                    ┌─────────────────────────────────────┐
                    │           Integration Surface        │
                    ├──────────┬──────────┬───────────────┤
                    │   CLI    │  VS Code │  GitHub Action│
                    │  Cursor  │ Windsurf │  MCP Server   │
                    └────┬─────┴────┬─────┴───────┬───────┘
                         │          │             │
                         └──────────┼─────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │         SafePush Core           │
                    │                                 │
                    │  ┌──────────┐  ┌─────────────┐ │
                    │  │  Engine  │  │    Models   │ │
                    │  │          │  │  (Pydantic) │ │
                    │  └────┬─────┘  └─────────────┘ │
                    │       │                         │
                    │  ┌────▼──────┐  ┌───────────┐  │
                    │  │ Registry  │  │  Scoring  │  │
                    │  │ (Plugins) │  │  Engine   │  │
                    │  └────┬──────┘  └───────────┘  │
                    └───────┼─────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
    ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
    │   Semgrep    │ │  Gitleaks   │ │   Trivy    │
    │   Scanner    │ │   Scanner   │ │  Scanner   │
    │  (Plugin)    │ │  (Plugin)   │ │  (Plugin)  │
    └──────────────┘ └─────────────┘ └────────────┘
```

### Core Pipeline

Every scan follows a deterministic, auditable pipeline:

```
ScanRequest
    → Engine validates target
    → Engine dispatches to Scanner plugins
    → Findings are collected & filtered
    → ScoringEngine computes RiskScore
    → ReportDispatcher renders output
    → ScanResult (immutable, serialisable)
```

All models are **Pydantic v2**, making them:
- Fully serialisable to JSON
- Self-validating at the boundary
- Usable in any integration surface without transformation

---

## Installation

### From PyPI (recommended)

```bash
pip install safepush
```

### From source

```bash
git clone https://github.com/safepush/safepush.git
cd safepush
pip install -e ".[dev]"
```

### Installing Scanner Plugins

SafePush ships with **no scanners by default** — the core is pure Python with
no external tool dependencies. Install the scanners you need:

```bash
# Coming soon — community plugins
pip install safepush-semgrep    # Semgrep integration
pip install safepush-gitleaks   # Gitleaks integration
pip install safepush-trivy      # Trivy container/dependency scanner
```

---

## Quick Start

### Scan a directory

```bash
safepush scan ./my-project
```

### Scan staged changes before committing

```bash
safepush scan . --type git-staged
```

### Fail CI/CD if any HIGH or CRITICAL finding is found

```bash
safepush scan . --fail-on HIGH
```

### Output machine-readable JSON

```bash
safepush scan . --format json > safepush-report.json
```

### List available scanner plugins

```bash
safepush list-scanners
```

### Run as a Python module

```bash
python -m safepush scan .
```

---

## Programmatic API

SafePush is designed to be consumed as a library, not just a CLI.

```python
from safepush import (
    ScanEngine,
    ScanRequest,
    ScanTarget,
    ScanTargetType,
    ScannerRegistry,
    ScoringEngine,
)
from pathlib import Path

# Build the engine
registry = ScannerRegistry.discover()   # loads all installed plugins
engine = ScanEngine(registry=registry)

# Build a scan request
request = ScanRequest(
    target=ScanTarget(
        target_type=ScanTargetType.DIRECTORY,
        path=Path("./my-project"),
    ),
    fail_on_severity="HIGH",
)

# Execute the scan
report = engine.scan(request)

# Inspect the results
print(f"Risk level: {report.risk_score.risk_level.value}")
print(f"Total findings: {report.summary.total_findings}")
print(f"CI gate passed: {report.summary.passed}")
```

---

## Building a Scanner Plugin

Implementing a scanner is straightforward:

```python
# my_scanner_package/__init__.py
from typing import Sequence
from safepush.scanner import BaseScanner
from safepush.models.finding import Finding, FindingSeverity, FindingCategory, FindingLocation
from safepush.models.scan import ScanRequest


class MyCustomScanner(BaseScanner):
    @property
    def scanner_id(self) -> str:
        return "my-custom-scanner"

    @property
    def version(self) -> str:
        return "1.0.0"

    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        # Your scanning logic here
        return [
            Finding(
                rule_id="my-scanner:hardcoded-password",
                title="Hardcoded password detected",
                description="A hardcoded password was found in the source code.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.SECRET,
                location=FindingLocation(file_path="src/config.py", line_start=42),
                source_scanner=self.scanner_id,
                fix_guidance="Use environment variables or a secrets manager instead.",
            )
        ]

    def is_available(self) -> bool:
        return True  # Pure Python — always available
```

Register it in your `pyproject.toml`:

```toml
[project.entry-points."safepush.scanners"]
my-custom-scanner = "my_scanner_package:MyCustomScanner"
```

That's it. SafePush discovers and runs it automatically.

---

## Roadmap

### Phase 1 — Foundation (Current) ✅

- [x] Plugin-based scanner architecture
- [x] Core domain models (Finding, ScanRequest, ScanResult, Report)
- [x] Weighted risk scoring engine
- [x] JSON and terminal report renderers
- [x] Typer CLI with scan/version/list-scanners commands
- [x] Thread-safe plugin registry with entry-point discovery
- [x] Comprehensive test suite (unit + integration)
- [x] Full type hints and Pydantic v2

### Phase 2 — Scanner Plugins

- [ ] `safepush-gitleaks` — secrets detection via Gitleaks
- [ ] `safepush-semgrep` — SAST via Semgrep community rules
- [ ] `safepush-trivy` — dependency and container vulnerability scanning
- [ ] `safepush-bandit` — Python-specific security linting
- [ ] SARIF and Markdown report renderers

### Phase 3 — Developer Integrations

- [ ] `safepush-vscode` — VS Code extension with inline finding annotations
- [ ] `safepush-action` — GitHub Action for CI/CD integration
- [ ] Cursor IDE compatibility
- [ ] Windsurf IDE compatibility
- [ ] Pre-commit hook configuration

### Phase 4 — AI Layer

- [ ] `safepush-ai` — AI-powered security review layer
- [ ] Detection of risky AI-generated code patterns
- [ ] Natural language fix explanations
- [ ] False-positive reduction via AI triage

### Phase 5 — Ecosystem

- [ ] `safepush-mcp` — MCP server for AI assistant integration
- [ ] SafePush Hub — community scanner registry
- [ ] Policy-as-code with `.safepush.toml`
- [ ] Suppression rules and audit logs
- [ ] Team-wide finding baseline management

---

## Configuration

SafePush will support a `.safepush.toml` configuration file in Phase 5.
Until then, all configuration is via CLI flags.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/safepush/safepush.git
cd safepush

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run the test suite
pytest

# Run with coverage
pytest --cov=safepush

# Type checking
mypy safepush

# Linting
ruff check safepush tests

# Formatting
ruff format safepush tests
black safepush tests
```

---

## Contributing

SafePush is an open-source project and **contributions are warmly welcome**.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of Conduct
- Development workflow
- How to implement a scanner plugin
- How to submit a pull request
- Coding standards and expectations

**First-time contributors**: Look for issues labelled
[`good first issue`](https://github.com/safepush/safepush/labels/good%20first%20issue).

---

## Security

If you discover a security vulnerability in SafePush itself, please **do not**
open a public issue.  Instead, email `security@safepush.dev` with a detailed
description.  We follow responsible disclosure and will respond within 48 hours.

---

## License

SafePush is licensed under the [MIT License](LICENSE).

Copyright © 2026 SafePush Contributors.

---

<div align="center">
  Made with ❤️ by the SafePush community.<br>
  <em>Secure Every Push.</em>
</div>
