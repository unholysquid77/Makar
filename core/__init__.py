"""Makar forensic core.

Layering rule (spec 38): Observation -> Evidence -> Inference -> Decision.

Modules in this package observe the manifest and emit *evidence*. Only the
confidence layer turns evidence into an inference, and only the reconstruction
layer turns an inference into a decision. No detector may classify a record
on its own.
"""

__version__ = "1.0.0"
