"""
SafePush CLI entry point.

This module is the ``__main__`` entry point, allowing SafePush to be run as::

    python -m safepush

It delegates entirely to the CLI application.
"""

from safepush.cli.commands import main

if __name__ == "__main__":
    main()
