"""
SafePush scoring package.

Provides the :class:`~safepush.scoring.engine.ScoringEngine` for converting
raw scan results into actionable :class:`~safepush.models.score.RiskScore`
objects with configurable :class:`~safepush.models.score.ScoringWeights`.
"""

from safepush.scoring.engine import ScoringEngine

__all__ = ["ScoringEngine"]
