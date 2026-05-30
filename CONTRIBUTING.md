# Contributing to SafePush

First, **thank you** for taking the time to contribute to SafePush. Every
contribution — whether a bug report, a documentation fix, a new scanner plugin,
or a core improvement — makes the project better for everyone.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Project Structure](#project-structure)
4. [Development Workflow](#development-workflow)
5. [Writing Tests](#writing-tests)
6. [Building a Scanner Plugin](#building-a-scanner-plugin)
7. [Submitting a Pull Request](#submitting-a-pull-request)
8. [Coding Standards](#coding-standards)
9. [Commit Message Format](#commit-message-format)
10. [Release Process](#release-process)

---

## Code of Conduct

SafePush is committed to a welcoming and respectful community.  All
contributors are expected to adhere to the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

Unacceptable behaviour should be reported to `conduct@safepush.dev`.

---

## Getting Started

### Prerequisites

- Python 3.12 or later
- Git
- A GitHub account

### Setup

```bash
# Fork the repository, then clone your fork
git clone https://github.com/<your-username>/safepush.git
cd safepush

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate          # Windows PowerShell

# Install with all development dependencies
pip install -e ".[dev]"

# Verify everything works
pytest
```

### Running the CLI locally

```bash
# After installation, the CLI is available as:
safepush --help

# Or via Python module:
python -m safepush --help
```

---

## Project Structure

```
safepush/
├── safepush/                   # Main package
│   ├── __init__.py             # Public API & version
│   ├── main.py                 # python -m safepush entry point
│   │
│   ├── cli/                    # Typer CLI (adapter layer only)
│   │   ├── __init__.py
│   │   └── commands.py         # scan, version, list-scanners commands
│   │
│   ├── core/                   # Central orchestration
│   │   ├── __init__.py
│   │   └── engine.py           # ScanEngine — the main pipeline
│   │
│   ├── models/                 # Pydantic domain models
│   │   ├── __init__.py
│   │   ├── finding.py          # Finding, FindingLocation, enums
│   │   ├── scan.py             # ScanRequest, ScanTarget, ScanResult
│   │   ├── score.py            # RiskScore, ScoringWeights, RiskLevel
│   │   └── report.py           # Report, ReportSummary, ReportFormat
│   │
│   ├── scanner/                # Scanner interface (protocol + base class)
│   │   └── __init__.py
│   │
│   ├── plugins/                # Plugin system
│   │   ├── __init__.py
│   │   └── registry.py         # ScannerRegistry
│   │
│   ├── scoring/                # Risk scoring
│   │   ├── __init__.py
│   │   └── engine.py           # ScoringEngine
│   │
│   ├── reports/                # Report rendering
│   │   ├── __init__.py
│   │   ├── base.py             # ReportRendererProtocol, BaseReportRenderer
│   │   ├── renderers.py        # JsonReportRenderer, TextReportRenderer
│   │   └── dispatcher.py      # ReportDispatcher
│   │
│   ├── utils/                  # Shared utilities
│   │   ├── __init__.py
│   │   ├── fs.py               # Filesystem helpers
│   │   ├── git.py              # Git subprocess wrappers
│   │   └── logging.py         # Logging configuration
│   │
│   └── exceptions/             # Exception hierarchy
│       └── __init__.py
│
├── tests/                      # Test suite
│   ├── conftest.py             # Shared fixtures and test doubles
│   ├── unit/                   # Pure unit tests (no I/O)
│   │   ├── models/
│   │   ├── plugins/
│   │   └── scoring/
│   └── integration/            # Tests using real filesystem/Git
│
├── docs/                       # Documentation source
├── pyproject.toml              # All project configuration
└── CONTRIBUTING.md             # This file
```

### Key architectural rules

1. **The core never imports concrete scanners.** The `safepush.core` and
   `safepush.models` packages must have zero dependencies on scanner
   implementations.

2. **The CLI is a thin adapter.** `safepush.cli` must never contain business
   logic — it parses arguments, calls the engine, and formats output.

3. **Models are immutable.** All Pydantic models use `model_config = {"frozen":
   True}`.  Mutation is done via `model_copy(update=...)`.

4. **Scanner plugins are discovered via entry points**, not by importing them.
   This maintains the decoupling between core and plugins.

---

## Development Workflow

SafePush uses a standard GitHub fork-and-PR workflow.

```bash
# Create a feature branch from main
git checkout -b feat/my-feature

# Make your changes...

# Run the full quality suite before pushing
ruff check safepush tests       # linting
ruff format safepush tests      # formatting
mypy safepush                   # type checking
pytest                          # tests with coverage

# Commit and push
git add .
git commit -m "feat(scanner): add support for foo scanning"
git push origin feat/my-feature
```

Then open a Pull Request on GitHub.

### Quality gates

All PRs must pass:

| Check | Command | Threshold |
|-------|---------|-----------|
| Ruff linting | `ruff check` | No errors |
| Ruff formatting | `ruff format --check` | No diffs |
| MyPy | `mypy safepush` | No errors |
| Pytest | `pytest` | All tests pass |
| Coverage | `pytest --cov` | ≥ 80% |

---

## Writing Tests

Tests live in `tests/` and mirror the package structure.

### Test philosophy

- **Fast**: Unit tests must run without I/O.  Use `tmp_path` for filesystem tests.
- **Isolated**: No shared mutable state between tests.
- **Descriptive**: Test names read like specifications.

### Test categories

Use the `@pytest.mark.unit` and `@pytest.mark.integration` markers to classify tests:

```python
import pytest

@pytest.mark.unit
def test_finding_severity_weight_is_in_range() -> None:
    ...

@pytest.mark.integration
def test_scan_engine_with_real_filesystem(tmp_path: Path) -> None:
    ...
```

### Using test doubles

The `tests/conftest.py` provides `StubScanner` and `make_finding()` factory
functions.  Use these instead of creating real scanner processes in tests.

```python
from tests.conftest import StubScanner, make_finding
from safepush.models.finding import FindingSeverity

def test_my_feature() -> None:
    scanner = StubScanner(
        findings=[make_finding(severity=FindingSeverity.CRITICAL)]
    )
    # ... test your feature using the stub scanner
```

---

## Building a Scanner Plugin

The recommended way to extend SafePush is to create a separate Python package
that declares itself as a SafePush scanner plugin.

### Minimal plugin structure

```
safepush-myscanner/
├── safepush_myscanner/
│   └── __init__.py         # Your scanner class
└── pyproject.toml
```

### Your scanner class

```python
# safepush_myscanner/__init__.py
from typing import Sequence
from safepush.scanner import BaseScanner
from safepush.models.finding import Finding
from safepush.models.scan import ScanRequest


class MyScanner(BaseScanner):
    @property
    def scanner_id(self) -> str:
        return "my-scanner"   # Must be lowercase letters, digits, hyphens

    @property
    def version(self) -> str:
        return "1.0.0"

    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        # Implement your scanning logic here
        # Return an empty list for a clean scan
        return []

    def is_available(self) -> bool:
        # Return True only if the backend tool is installed
        import shutil
        return shutil.which("my-backend-tool") is not None
```

### Entry point registration

```toml
# pyproject.toml
[project.entry-points."safepush.scanners"]
my-scanner = "safepush_myscanner:MyScanner"
```

### Error handling

Raise these exceptions from your `scan()` method for SafePush to handle gracefully:

- `safepush.exceptions.ScannerExecutionError` — backend tool failed
- `safepush.exceptions.ScannerTimeoutError` — scan exceeded time limit

Other exceptions are caught by the engine and recorded as errors.

---

## Submitting a Pull Request

### PR checklist

- [ ] My change has a clear, focused purpose
- [ ] I have added/updated tests for my changes
- [ ] All quality gates pass locally
- [ ] I have updated docstrings for modified public APIs
- [ ] I have added an entry to `CHANGELOG.md` (if applicable)
- [ ] My PR title follows the commit message format

### PR size guidelines

- **Small PRs are preferred.** A PR with 200 lines of change is easier to review
  than one with 2000.
- If your feature is large, consider opening a draft PR early to get feedback on
  the architecture before completing the implementation.

---

## Coding Standards

### Python style

- **Black + Ruff**: All code is formatted with Black and linted with Ruff.
  Run `ruff format` before committing.
- **Type hints**: All public functions and methods must have complete type hints.
- **Docstrings**: All public classes, methods, and functions must have Google-style
  docstrings.
- **Immutability**: Prefer immutable data structures.  All Pydantic models are
  frozen.

### Naming conventions

| Construct | Convention | Example |
|-----------|------------|---------|
| Modules | `snake_case` | `scan_engine.py` |
| Classes | `PascalCase` | `ScanEngine` |
| Functions/methods | `snake_case` | `get_findings()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_FINDINGS` |
| Private members | `_leading_underscore` | `_registry` |

### Dependency management

- All dependencies go in `pyproject.toml`.  No `requirements.txt`.
- Runtime dependencies should be **minimal**.  The core package must remain
  lightweight.
- Scanner plugins manage their own heavy dependencies.

---

## Commit Message Format

SafePush uses [Conventional Commits](https://www.conventionalcommits.org/).

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `style` | Formatting, missing semicolons, etc. |
| `refactor` | Code changes that neither add features nor fix bugs |
| `perf` | Performance improvements |
| `test` | Adding or fixing tests |
| `chore` | Build process, dependency updates, etc. |
| `ci` | CI/CD configuration changes |

### Scopes

Use the package name as the scope: `core`, `cli`, `scanner`, `scoring`,
`reports`, `plugins`, `models`, `utils`, `exceptions`, `docs`.

### Examples

```
feat(scanner): add ScannerProtocol runtime_checkable support
fix(scoring): handle zero-finding scans without division error
docs(readme): add programmatic API examples
test(core): add integration tests for fail_on_severity gate
chore(deps): update pydantic to 2.7.0
```

---

## Release Process

Releases are managed by the maintainers.  The process is:

1. Update `__version__` in `safepush/__init__.py`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v0.2.0`
4. Push the tag: `git push origin v0.2.0`
5. CI automatically builds and publishes to PyPI

---

Thank you again for contributing to SafePush. 🔐
