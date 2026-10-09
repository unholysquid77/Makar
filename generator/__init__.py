"""Synthetic maritime world and manifest generation.

Pipeline (spec 6)::

    Clean World -> Clean Manifest -> Attack Injection
                -> Harmless Noise Injection -> Suspect Manifest

The injection log produced alongside the suspect manifest is *private ground
truth*. Nothing under ``core/`` may import from this package at analysis
time, which is what keeps the evaluation honest.
"""
