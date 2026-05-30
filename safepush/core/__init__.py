"""
SafePush core package.

The core package contains the central :class:`~safepush.core.engine.ScanEngine`
that orchestrates the complete scanning pipeline.

The engine is the *only* entry point that application surfaces (CLI, MCP server,
VS Code extension) should use to initiate scans.  This keeps all pipeline logic
in one place and ensures consistent behaviour across all integration surfaces.
"""

from safepush.core.engine import ScanEngine

__all__ = ["ScanEngine"]
