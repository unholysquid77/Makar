"""Manifest normalisation and entity resolution.

This layer is where the problem statement's hardest constraint is honoured:
*not every oddity is an attack*. A thousands separator, a day-first date, a
``"N/A"`` in a nullable column and an owner written as "MERIDIAN FREIGHT PVT.
LTD." are all export noise. Normalisation repairs them, records what it did
as low-weight ``FORMAT`` evidence, and hands the detectors clean typed
values.

Because ``FORMAT`` carries a *negative* fusion weight, a record that is merely
messy ends up with a lower tampering probability than an untouched one. That
is deliberate: messiness is affirmative evidence of a sloppy export rather
than of a deliberate edit.
"""

from core.normalization.normalizer import NormalizationResult, normalize_rows
from core.normalization.parsers import (
    BLANK_TOKENS,
    is_blank,
    parse_float,
    parse_int,
    parse_timestamp,
)
from core.normalization.resolver import EntityResolver

__all__ = [
    "BLANK_TOKENS",
    "EntityResolver",
    "NormalizationResult",
    "is_blank",
    "normalize_rows",
    "parse_float",
    "parse_int",
    "parse_timestamp",
]
