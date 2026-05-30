"""
Filesystem utility functions for SafePush.

These helpers are used by the scan engine and scanner plugins to work with
the local filesystem in a consistent, testable manner.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path


def collect_files(
    root: Path,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    follow_symlinks: bool = False,
) -> list[Path]:
    """Recursively collect files under ``root`` matching the given patterns.

    Parameters
    ----------
    root:
        The root directory to search.
    include_patterns:
        Glob patterns for files to include.  If None or empty, all files are
        included.
    exclude_patterns:
        Glob patterns for files to exclude.  Applied after include filtering.
    follow_symlinks:
        Whether to follow symbolic links (default False for safety).

    Returns
    -------
    list[Path]
        Sorted list of absolute paths to matching files.

    Raises
    ------
    ValueError
        If ``root`` is not a directory.

    Examples
    --------
    ::

        files = collect_files(
            Path("./src"),
            include_patterns=["*.py"],
            exclude_patterns=["**/test_*.py"],
        )
    """
    if not root.is_dir():
        raise ValueError(f"collect_files requires a directory, got: {root}")

    include_pats = include_patterns or []
    exclude_pats = exclude_patterns or []

    result: list[Path] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not follow_symlinks and path.is_symlink():
            continue

        relative = path.relative_to(root)
        rel_str = str(relative)

        # Include filter
        if include_pats:
            if not any(fnmatch.fnmatch(rel_str, p) for p in include_pats):
                continue

        # Exclude filter
        if any(fnmatch.fnmatch(rel_str, p) for p in exclude_pats):
            continue

        result.append(path.resolve())

    return sorted(result)


def safe_read_text(path: Path, encoding: str = "utf-8") -> str | None:
    """Read a file's text content, returning None on any read error.

    This is intentionally lenient — scanner plugins should skip files they
    cannot read rather than crashing the entire scan.

    Parameters
    ----------
    path:
        The file to read.
    encoding:
        The text encoding to use (default UTF-8).

    Returns
    -------
    str | None
        File contents, or None if the file could not be read.
    """
    try:
        return path.read_text(encoding=encoding, errors="replace")
    except (OSError, PermissionError):
        return None


def is_binary_file(path: Path, sample_bytes: int = 8192) -> bool:
    """Heuristically determine if a file is binary.

    Reads the first ``sample_bytes`` bytes and checks for null bytes, which
    reliably indicate binary content in the vast majority of cases.

    Parameters
    ----------
    path:
        The file to check.
    sample_bytes:
        Number of bytes to sample (default 8192).

    Returns
    -------
    bool
        True if the file is likely binary, False if it is likely text.
    """
    try:
        with path.open("rb") as f:
            chunk = f.read(sample_bytes)
        return b"\x00" in chunk
    except (OSError, PermissionError):
        return False  # If we can't read it, assume text (scanner will fail gracefully)
