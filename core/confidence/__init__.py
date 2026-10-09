"""Evidence fusion, blame arbitration and tampering classification.

This is the only layer permitted to turn evidence into an inference, and the
classifier is the only place a :class:`~core.types.TamperClass` is assigned.
Detectors observe; this decides.

Order matters:

1. :mod:`core.confidence.arbitration` -- resolve *who to blame* in a
   contradiction, before anything is scored.
2. :mod:`core.confidence.fusion` -- combine evidence into a calibrated
   tampering probability with an auditable breakdown.
3. :mod:`core.confidence.classifier` -- decide which *kind* of tampering the
   evidence pattern describes.
"""

from core.confidence.arbitration import ArbitrationResult, arbitrate
from core.confidence.classifier import classify
from core.confidence.fusion import fuse

__all__ = ["ArbitrationResult", "arbitrate", "classify", "fuse"]
