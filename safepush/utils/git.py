"""
Git utility functions for SafePush.

Provides a thin wrapper around ``git`` subprocess calls used by the scan
engine when processing ``GIT_STAGED``, ``GIT_DIFF``, and ``GIT_COMMIT``
scan target types.

All functions are intentionally simple and isolated — they have no side effects
and return plain Python objects.  This makes them straightforward to mock in
tests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitNotAvailableError(Exception):
    """Raised when git is not installed or not on the PATH."""


class GitCommandError(Exception):
    """Raised when a git command exits with a non-zero status.

    Parameters
    ----------
    command:
        The git command that failed.
    returncode:
        The exit code.
    stderr:
        The captured stderr output.
    """

    def __init__(self, command: str, returncode: int, stderr: str) -> None:
        super().__init__(
            f"Git command failed (exit {returncode}): {command}\n{stderr}"
        )
        self.command = command
        self.returncode = returncode
        self.stderr = stderr


def _run_git(args: list[str], cwd: Path) -> str:
    """Run a git command and return its stdout.

    Parameters
    ----------
    args:
        List of arguments to pass to git (without the 'git' prefix).
    cwd:
        Working directory for the git command.

    Returns
    -------
    str
        Stripped stdout from the command.

    Raises
    ------
    GitNotAvailableError
        If git is not found on the PATH.
    GitCommandError
        If the command exits with a non-zero status.
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitNotAvailableError(
            "git executable not found. Install Git and ensure it is on your PATH."
        ) from exc

    if result.returncode != 0:
        raise GitCommandError(
            command="git " + " ".join(args),
            returncode=result.returncode,
            stderr=result.stderr.strip(),
        )
    return result.stdout.strip()


def get_staged_files(repo_root: Path) -> list[Path]:
    """Return a list of files currently staged in the Git index.

    Parameters
    ----------
    repo_root:
        Root of the Git repository.

    Returns
    -------
    list[Path]
        Absolute paths to staged files that exist on disk.
    """
    output = _run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRT"], repo_root)
    if not output:
        return []
    return [
        (repo_root / line.strip()).resolve()
        for line in output.splitlines()
        if line.strip()
    ]


def get_commit_files(repo_root: Path, ref: str) -> list[Path]:
    """Return a list of files modified in a specific Git commit.

    Parameters
    ----------
    repo_root:
        Root of the Git repository.
    ref:
        Git commit SHA, branch, or tag.

    Returns
    -------
    list[Path]
        Absolute paths to files modified in the given commit.
    """
    output = _run_git(
        ["diff-tree", "--no-commit-id", "-r", "--name-only", ref], repo_root
    )
    if not output:
        return []
    return [
        (repo_root / line.strip()).resolve()
        for line in output.splitlines()
        if line.strip()
    ]


def get_diff_content(repo_root: Path, ref: str | None = None) -> str:
    """Return the unified diff of changes relative to a ref.

    Parameters
    ----------
    repo_root:
        Root of the Git repository.
    ref:
        Git ref to diff against.  If None, diffs staged changes (HEAD vs index).

    Returns
    -------
    str
        Unified diff output.
    """
    if ref:
        return _run_git(["diff", ref, "--unified=5"], repo_root)
    return _run_git(["diff", "--cached", "--unified=5"], repo_root)


def is_git_repository(path: Path) -> bool:
    """Return True if the given path is inside a Git repository.

    Parameters
    ----------
    path:
        The path to check.

    Returns
    -------
    bool
        True if the path is inside a git repository.
    """
    try:
        _run_git(["rev-parse", "--git-dir"], path)
        return True
    except (GitCommandError, GitNotAvailableError):
        return False
