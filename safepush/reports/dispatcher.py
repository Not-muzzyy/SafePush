"""
Report dispatcher for SafePush.

The :class:`ReportDispatcher` routes a :class:`~safepush.models.report.Report`
to the correct :class:`~safepush.reports.base.ReportRendererProtocol` based on
the report's :attr:`~safepush.models.report.Report.format`.

It also acts as a renderer registry, allowing custom renderer implementations
to be registered without modifying core code.
"""

from __future__ import annotations

import logging

from safepush.exceptions import UnsupportedReportFormatError
from safepush.models.report import Report, ReportFormat
from safepush.reports.base import ReportRendererProtocol
from safepush.reports.renderers import JsonReportRenderer, TextReportRenderer

logger = logging.getLogger(__name__)


class ReportDispatcher:
    """Routes report rendering to the correct format-specific renderer.

    By default, the dispatcher is pre-loaded with the built-in JSON and TEXT
    renderers.  Additional renderers can be registered via :meth:`register`.

    Examples
    --------
    ::

        dispatcher = ReportDispatcher()
        output = dispatcher.render(report)   # uses report.format

        # Register a custom renderer
        dispatcher.register(MySarifRenderer())
        output = dispatcher.render(sarif_report)
    """

    def __init__(self) -> None:
        self._renderers: dict[ReportFormat, ReportRendererProtocol] = {}

        # Register built-in renderers
        self.register(JsonReportRenderer())
        self.register(TextReportRenderer())

    def register(self, renderer: ReportRendererProtocol) -> None:
        """Register a renderer for its declared format.

        Parameters
        ----------
        renderer:
            A renderer implementing :class:`~safepush.reports.base.ReportRendererProtocol`.
        """
        self._renderers[renderer.format] = renderer
        logger.debug("Registered renderer for format '%s'", renderer.format.value)

    def render(self, report: Report) -> str:
        """Render the report using the renderer matching its format.

        Parameters
        ----------
        report:
            The report to render.

        Returns
        -------
        str
            The rendered output string.

        Raises
        ------
        safepush.exceptions.UnsupportedReportFormatError
            If no renderer is registered for the report's format.
        """
        renderer = self._renderers.get(report.format)
        if renderer is None:
            supported = [f.value for f in self._renderers]
            raise UnsupportedReportFormatError(
                format_name=report.format.value,
                supported_formats=supported,
            )
        return renderer.render(report)

    def supported_formats(self) -> list[str]:
        """Return a list of format names for all registered renderers.

        Returns
        -------
        list[str]
            Sorted list of supported format names.
        """
        return sorted(f.value for f in self._renderers)
