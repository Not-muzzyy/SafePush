"""
Entry point for ``python -m safepush``.

Delegates entirely to the Typer CLI application.

Usage::

    python -m safepush --help
    python -m safepush scan .
    python -m safepush version
    python -m safepush list-scanners
"""

from safepush.cli.commands import main

if __name__ == "__main__":
    main()
