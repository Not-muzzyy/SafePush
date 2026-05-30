"""
Logging configuration for SafePush.

SafePush uses Python's standard :mod:`logging` module throughout.  This module
provides a single :func:`configure_logging` function that sets up the root
``safepush`` logger with appropriate formatting.

Design choices
--------------
* No global logging configuration at module import time.  Applications must
  call :func:`configure_logging` explicitly.  This respects the principle that
  libraries should never configure logging for their consumers.
* The SafePush logger hierarchy sits under ``safepush.*``.  All sub-loggers
  (``safepush.scanner``, ``safepush.core``, etc.) inherit from this root.
* In test environments, configure with level=DEBUG to observe all internal events.
"""

from __future__ import annotations

import logging
import sys
from typing import Literal

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

_SAFEPUSH_LOGGER_NAME = "safepush"

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def configure_logging(
    level: LogLevel = "WARNING",
    *,
    format_string: str = _LOG_FORMAT,
    date_format: str = _DATE_FORMAT,
    stream: object = sys.stderr,
) -> None:
    """Configure the SafePush logger hierarchy.

    Call this function once at application startup (e.g. in the CLI entry point
    or in the application factory of an MCP server).

    Parameters
    ----------
    level:
        Log level for the safepush logger hierarchy.  Defaults to WARNING so
        that normal CLI usage is quiet.  Set to DEBUG for verbose diagnostic
        output.
    format_string:
        Python logging format string.
    date_format:
        Date/time format for log records.
    stream:
        Output stream for the log handler (default :data:`sys.stderr`).

    Examples
    --------
    ::

        from safepush.utils.logging import configure_logging
        configure_logging(level="DEBUG")  # verbose mode
        configure_logging(level="WARNING")  # production default
    """
    logger = logging.getLogger(_SAFEPUSH_LOGGER_NAME)
    logger.setLevel(level)

    # Only add a handler if none exist (idempotent)
    if not logger.handlers:
        handler = logging.StreamHandler(stream)  # type: ignore[arg-type]
        handler.setLevel(level)
        formatter = logging.Formatter(fmt=format_string, datefmt=date_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Prevent propagation to the root logger to avoid duplicate output
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a logger namespaced under the SafePush hierarchy.

    Parameters
    ----------
    name:
        Sub-name to append to ``safepush.``.  Typically ``__name__``.

    Returns
    -------
    logging.Logger
        A logger with the full name ``safepush.<name>``.

    Examples
    --------
    ::

        logger = get_logger(__name__)
        logger.info("Starting scan")
    """
    return logging.getLogger(f"{_SAFEPUSH_LOGGER_NAME}.{name}")
