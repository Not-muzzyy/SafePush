"""
MockScanner — deterministic end-to-end pipeline validator for SafePush.

This scanner exists for one purpose: to prove the entire SafePush pipeline
works correctly without requiring any external binary tools.

It returns a fixed, deterministic set of three findings that exercise all
severity levels the scoring engine distinguishes:

* 1 × CRITICAL  — Hardcoded API key (SECRET category)
* 1 × HIGH      — SQL injection risk (INSECURE_PATTERN category)
* 1 × MEDIUM    — Missing input validation (INSECURE_PATTERN category)

The findings are modelled after patterns that real scanners (Gitleaks,
Semgrep) would produce so that the output looks and feels realistic.

Architecture notes
------------------
* This scanner lives **inside** the core package because it has zero external
  dependencies and is used for both development validation and testing.
* It is registered as a built-in entry point so that ``ScannerRegistry.discover()``
  picks it up automatically when the package is installed.
* It inherits from ``BaseScanner`` to get the logger and default
  ``is_available()`` (returns True — no external binary required).
* All findings use ``source_scanner = "mock"`` to identify their origin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from safepush.models.finding import (
    Finding,
    FindingCategory,
    FindingLocation,
    FindingSeverity,
)
from safepush.models.scan import ScanRequest
from safepush.scanner import BaseScanner

# ---------------------------------------------------------------------------
# Canonical finding definitions
#
# These are defined at module level so they can be imported by tests for
# assertion without re-instantiating the scanner.
# ---------------------------------------------------------------------------

#: Rule identifier for the hardcoded API key finding.
RULE_HARDCODED_API_KEY = "mock:security/secrets/hardcoded-api-key"

#: Rule identifier for the SQL injection finding.
RULE_SQL_INJECTION = "mock:security/injection/sql-string-format"

#: Rule identifier for the missing input validation finding.
RULE_MISSING_VALIDATION = "mock:security/input/missing-validation"

#: The scanner_id used across all MockScanner findings.
MOCK_SCANNER_ID = "mock"

#: The version of the MockScanner (matches the package version).
MOCK_SCANNER_VERSION = "0.1.0"


def _build_findings(target_path: Path) -> list[Finding]:
    """Build the fixed set of mock findings relative to the scan target.

    The file paths embedded in findings are constructed relative to the scan
    target so that the report output reflects the actual scanned location
    rather than hard-coded absolute paths.

    Parameters
    ----------
    target_path:
        The root path being scanned (from ``ScanRequest.target.path``).

    Returns
    -------
    list[Finding]
        The three deterministic mock findings.
    """
    # Represent files relative to the scanned root for realistic output
    config_file = str(target_path / "config" / "settings.py")
    db_file = str(target_path / "src" / "database" / "queries.py")
    api_file = str(target_path / "src" / "api" / "endpoints.py")

    return [
        # ------------------------------------------------------------------
        # Finding 1: CRITICAL — Hardcoded API key
        # ------------------------------------------------------------------
        Finding(
            rule_id=RULE_HARDCODED_API_KEY,
            title="Hardcoded API Key Detected",
            description=(
                "A plaintext API key was found assigned directly in source code. "
                "Hardcoded credentials are a critical security risk: anyone with "
                "read access to the repository (including historical commits) can "
                "extract and misuse the secret. This pattern is consistently in "
                "OWASP Top 10 (A02:2021 Cryptographic Failures) and the CWE-798 "
                "(Use of Hard-coded Credentials) weakness.\n\n"
                "Affected line:\n"
                "  STRIPE_API_KEY = \"SAFEPUSH_DEMO_STRIPE_KEY\""
            ),
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.SECRET,
            location=FindingLocation(
                file_path=config_file,
                line_start=42,
                line_end=42,
                column_start=1,
                column_end=56,
                code_snippet='STRIPE_API_KEY = "SAFEPUSH_DEMO_STRIPE_KEY"',
            ),
            source_scanner=MOCK_SCANNER_ID,
            fix_guidance=(
                "1. Rotate the exposed key immediately at https://dashboard.stripe.com/apikeys.\n"
                "2. Remove the key from source code and all Git history "
                "(use `git filter-repo` or BFG Repo Cleaner).\n"
                "3. Store the key in an environment variable: "
                "os.environ['STRIPE_API_KEY'] or use a secrets manager "
                "(AWS Secrets Manager, HashiCorp Vault, or GitHub Secrets)."
            ),
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            metadata={
                "secret_type": "stripe_api_key",
                "confidence": "HIGH",
                "pattern": "SAFEPUSH_DEMO_STRIPE_KEY",
            },
        ),
        # ------------------------------------------------------------------
        # Finding 2: HIGH — SQL Injection via string formatting
        # ------------------------------------------------------------------
        Finding(
            rule_id=RULE_SQL_INJECTION,
            title="Potential SQL Injection via String Formatting",
            description=(
                "User-controlled input is concatenated directly into an SQL query "
                "string using Python f-string or %-formatting. This pattern allows "
                "an attacker to manipulate the query structure, potentially bypassing "
                "authentication, reading unauthorized data, or executing destructive "
                "operations (DROP TABLE, etc.).\n\n"
                "Affected code:\n"
                '  query = f"SELECT * FROM users WHERE username = \'{username}\'"'
            ),
            severity=FindingSeverity.HIGH,
            category=FindingCategory.INSECURE_PATTERN,
            location=FindingLocation(
                file_path=db_file,
                line_start=87,
                line_end=88,
                column_start=5,
                code_snippet="query = f\"SELECT * FROM users WHERE username = '{username}'\"",
            ),
            source_scanner=MOCK_SCANNER_ID,
            fix_guidance=(
                "Use parameterised queries (prepared statements) instead of string formatting:\n\n"
                "  # Correct — parameterised query with sqlite3\n"
                "  cursor.execute('SELECT * FROM users WHERE username = ?', (username,))\n\n"
                "  # Correct — parameterised query with SQLAlchemy\n"
                "  session.execute(text('SELECT * FROM users WHERE username = :name'),\n"
                "                  {'name': username})\n\n"
                "Never concatenate or format user input into SQL strings."
            ),
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            metadata={
                "sink": "sql_query",
                "source": "user_input",
                "confidence": "MEDIUM",
                "language": "python",
            },
        ),
        # ------------------------------------------------------------------
        # Finding 3: MEDIUM — Missing input validation
        # ------------------------------------------------------------------
        Finding(
            rule_id=RULE_MISSING_VALIDATION,
            title="Missing Input Validation on API Endpoint",
            description=(
                "An API endpoint accepts user-supplied data and passes it to "
                "downstream processing without length checks, type coercion, or "
                "allowlist validation. Without explicit validation, this endpoint "
                "is vulnerable to:\n"
                "  • Buffer overflow / denial of service via oversized payloads\n"
                "  • Type confusion leading to unexpected behaviour\n"
                "  • Injection attacks if the data reaches a query or shell\n\n"
                "Affected code:\n"
                "  @app.route('/api/users/search')\n"
                "  def search_users():\n"
                "      query = request.args.get('q')  # No validation\n"
                "      return db.search(query)"
            ),
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.INSECURE_PATTERN,
            location=FindingLocation(
                file_path=api_file,
                line_start=134,
                line_end=137,
                code_snippet="query = request.args.get('q')  # No validation",
            ),
            source_scanner=MOCK_SCANNER_ID,
            fix_guidance=(
                "Add explicit input validation before processing:\n\n"
                "  from pydantic import BaseModel, Field\n\n"
                "  class SearchParams(BaseModel):\n"
                "      q: str = Field(min_length=1, max_length=100,\n"
                "                     pattern=r'^[\\w\\s-]+$')\n\n"
                "  @app.route('/api/users/search')\n"
                "  def search_users():\n"
                "      params = SearchParams(**request.args)\n"
                "      return db.search(params.q)\n\n"
                "Consider using a validation library such as Pydantic, marshmallow, "
                "or WTForms, and always validate at the API boundary."
            ),
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/20.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            ],
            metadata={
                "endpoint": "/api/users/search",
                "parameter": "q",
                "confidence": "MEDIUM",
                "framework": "flask",
            },
        ),
    ]


class MockScanner(BaseScanner):
    """Deterministic scanner for end-to-end pipeline validation.

    Returns a fixed set of three findings (CRITICAL, HIGH, MEDIUM) that
    exercise the full SafePush pipeline without requiring any external tools.

    This scanner is always available (:meth:`is_available` returns ``True``)
    and always returns the same three findings regardless of what is actually
    in the scanned directory — it is a *mock* scanner, not a real analyser.

    The findings use realistic examples of common security issues:
    * Hardcoded API keys (SECRET category)
    * SQL injection via string formatting (INSECURE_PATTERN category)
    * Missing input validation (INSECURE_PATTERN category)

    Parameters
    ----------
    None — the MockScanner has no configuration.

    Examples
    --------
    ::

        from safepush.scanner.mock import MockScanner
        from safepush.plugins.registry import ScannerRegistry

        registry = ScannerRegistry()
        registry.register(MockScanner())
        # MockScanner is now discoverable by the engine
    """

    @property
    def scanner_id(self) -> str:
        """Return the stable scanner identifier ``"mock"``."""
        return MOCK_SCANNER_ID

    @property
    def version(self) -> str:
        """Return the MockScanner version string."""
        return MOCK_SCANNER_VERSION

    def scan(self, request: ScanRequest) -> Sequence[Finding]:
        """Return the fixed set of three deterministic mock findings.

        The findings are always returned in severity-descending order:
        CRITICAL → HIGH → MEDIUM.

        Parameters
        ----------
        request:
            The scan request.  The target path is used to construct
            realistic-looking file paths in the findings.

        Returns
        -------
        Sequence[Finding]
            Exactly three findings: CRITICAL, HIGH, and MEDIUM.
        """
        self._logger.info(
            "MockScanner executing on target '%s' — returning %d deterministic findings.",
            request.target.path,
            3,
        )
        return _build_findings(request.target.path)

    def is_available(self) -> bool:
        """Return True — MockScanner has no external dependencies."""
        return True
