"""
SafePush reports package.

Provides built-in report renderers and the :class:`ReportDispatcher` for
routing report format selection to the appropriate renderer.

Built-in renderers:

* :class:`~safepush.reports.renderers.JsonReportRenderer` — machine-readable JSON
* :class:`~safepush.reports.renderers.TextReportRenderer` — ANSI-coloured terminal output

Future renderers (SARIF, Markdown, HTML) may be contributed to core or
provided as separate packages.
"""

from safepush.reports.base import BaseReportRenderer, ReportRendererProtocol
from safepush.reports.dispatcher import ReportDispatcher
from safepush.reports.renderers import JsonReportRenderer, TextReportRenderer

__all__ = [
    "BaseReportRenderer",
    "ReportRendererProtocol",
    "ReportDispatcher",
    "JsonReportRenderer",
    "TextReportRenderer",
]
