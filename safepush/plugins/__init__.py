"""
SafePush plugin system.

This package manages the *lifecycle* of scanner plugins:

1. **Discovery** — finding plugins via Python entry points or explicit
   registration.
2. **Registration** — storing plugins in the :class:`ScannerRegistry`.
3. **Dispatch** — the registry is consumed by the engine to route scan requests
   to the correct scanner(s).

Plugin discovery model
----------------------
SafePush uses Python :pep:`entry_points` for zero-configuration plugin
discovery.  Third-party scanner packages declare themselves under the
``safepush.scanners`` group in their own ``pyproject.toml``::

    [project.entry-points."safepush.scanners"]
    semgrep = "safepush_semgrep:SemgrepScanner"
    gitleaks = "safepush_gitleaks:GitleaksScanner"

The :func:`~safepush.plugins.registry.ScannerRegistry.discover` class method
loads all such entry points and registers the scanners automatically.

Explicit registration is also supported for testing and programmatic use::

    from safepush.plugins import ScannerRegistry

    registry = ScannerRegistry()
    registry.register(MyScannerClass())
"""

from safepush.plugins.registry import ScannerRegistry

__all__ = ["ScannerRegistry"]
