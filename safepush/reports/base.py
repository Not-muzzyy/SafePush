"""
SafePush report renderer protocol and base class.

Report renderers transform a :class:`~safepush.models.report.Report` into a
concrete output format (JSON, plain text, SARIF, Markdown, HTML).

The renderer interface mirrors the scanner interface in its design philosophy:

* A :class:`ReportRendererProtocol` structural protocol defines the contract.
* A :class:`BaseReportRenderer` abstract class provides convenient defaults.
* Renderers are registered by :class:`~safepush.reports.registry.RendererRegistry`.
* The :class:`~safepush.reports.dispatcher.ReportDispatcher` routes format
  selection to the correct renderer at runtime.

This architecture allows future formats to be added as separate packages
without modifying core.
"""

from __future__ import annotations

import abc
from typing import Protocol, runtime_checkable

from safepush.models.report import Report, ReportFormat


@runtime_checkable
class ReportRendererProtocol(Protocol):
    """Structural protocol for SafePush report renderers.

    A renderer is any object that:
    1. Has a :attr:`format` property returning a :class:`~safepush.models.report.ReportFormat`.
    2. Implements :meth:`render` to convert a :class:`~safepush.models.report.Report`
       into a string.
    """

    @property
    def format(self) -> ReportFormat:
        """The :class:`~safepush.models.report.ReportFormat` this renderer produces."""
        ...

    def render(self, report: Report) -> str:
        """Render the report to a string in the configured format.

        Parameters
        ----------
        report:
            The :class:`~safepush.models.report.Report` to render.

        Returns
        -------
        str
            The rendered report as a string.
        """
        ...


class BaseReportRenderer(abc.ABC):
    """Convenient abstract base class for report renderers."""

    @property
    @abc.abstractmethod
    def format(self) -> ReportFormat:
        """The format this renderer produces."""
        ...

    @abc.abstractmethod
    def render(self, report: Report) -> str:
        """Render the report to a string.

        Parameters
        ----------
        report:
            The report to render.

        Returns
        -------
        str
            The rendered report string.
        """
        ...
