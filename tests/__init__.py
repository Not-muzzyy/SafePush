"""
SafePush test suite root package.

This package contains all automated tests for SafePush.  Tests are organised
to mirror the source package structure:

    tests/
    ├── unit/               # Pure unit tests with no I/O or subprocess calls
    │   ├── models/         # Pydantic model validation
    │   ├── scoring/        # Scoring algorithm correctness
    │   ├── plugins/        # Registry logic
    │   ├── reports/        # Renderer output
    │   └── utils/          # Utility function behaviour
    ├── integration/        # Tests that use real filesystem or Git operations
    └── fixtures/           # Shared pytest fixtures

Test philosophy
---------------
* **Fast**: Unit tests must complete in < 1ms each.  No network, no subprocess,
  no disk I/O in unit tests.
* **Isolated**: Each test is fully independent.  No shared mutable state.
* **Descriptive**: Test names document expected behaviour, not implementation.
* **Complete**: Every public function has at least one test for the happy path
  and one for the primary failure case.
"""
