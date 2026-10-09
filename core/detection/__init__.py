"""Detection engines.

Every engine implements :class:`~core.detection.base.Detector` and is
registered by name, so the active set is a configuration list rather than a
hardcoded call sequence::

    detection:
      enabled: [temporal, geospatial, route, cargo, duplicate, statistical, graph, provenance]

That indirection is the point: when the problem changes shape mid-event, a
new reasoning layer is a new registered detector and a line of YAML, and the
fusion weights for it are also YAML. Nothing downstream needs to know which
detectors ran -- it only sees evidence.
"""

from core.detection.base import (
    DETECTOR_REGISTRY,
    AnalysisContext,
    Detector,
    build_context,
    register_detector,
    run_detectors,
)

__all__ = [
    "DETECTOR_REGISTRY",
    "AnalysisContext",
    "Detector",
    "build_context",
    "register_detector",
    "run_detectors",
]
