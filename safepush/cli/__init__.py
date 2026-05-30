"""
SafePush CLI package.

Re-exports the Typer application and main entry point for use in
``pyproject.toml``'s ``[project.scripts]`` section.
"""

from safepush.cli.commands import app, main

__all__ = ["app", "main"]
