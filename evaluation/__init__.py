"""Evaluation against the private injection log (spec 31).

This package is the *only* consumer of ``ground_truth.json``. Nothing under
``core/`` imports from it, which is what makes the reported numbers mean
something.
"""

from evaluation.ground_truth import GroundTruth, load_ground_truth
from evaluation.metrics import EvaluationReport, evaluate

__all__ = ["EvaluationReport", "GroundTruth", "evaluate", "load_ground_truth"]
