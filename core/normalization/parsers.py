"""Tolerant scalar parsers for a messy manifest export.

Each parser returns ``(value, note)``. ``note`` is ``None`` when the input was
already canonical and a short machine-readable tag otherwise, so the caller
can raise exactly one piece of FORMAT evidence per repaired field.

Date disambiguation is a documented convention, not a guess. The generator
emits dash-separated dates day-first (``03-01-2026``) and slash-separated
dates month-first (``01/03/2026``), which mirrors how two upstream systems
with different locales would each export. Where the leading component exceeds
12 the ambiguity resolves itself and the convention is overridden.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

#: Strings that mean "no value" in a real export.
BLANK_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "-",
        "--",
        "?",
        "n/a",
        "na",
        "null",
        "none",
        "nil",
        "unknown",
        "unspecified",
        "tbd",
        "#n/a",
        "nan",
    }
)

#: Unit and currency decorations stripped before numeric parsing.
_UNIT_SUFFIX = re.compile(
    r"\s*(kgs?|kilograms?|mt|tonnes?|tons?|lbs?|teu|usd|eur|inr|aed|\$|€|₹)\s*$",
    re.IGNORECASE,
)
_CURRENCY_PREFIX = re.compile(r"^\s*(usd|eur|inr|aed|\$|€|₹)\s*", re.IGNORECASE)

_EPOCH_RE = re.compile(r"^\d{9,13}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_DASH_DAYFIRST_RE = re.compile(r"^(\d{1,2})-(\d{1,2})-(\d{4})")
_SLASH_RE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})")


def is_blank(value: object) -> bool:
    """True when the value means 'absent' in manifest-export terms."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().casefold() in BLANK_TOKENS
    return False


def parse_float(value: object) -> tuple[float | None, str | None]:
    """Parse a numeric field that may carry formatting decoration.

    Handles padding, thousands separators, unit suffixes, currency prefixes
    and scientific notation. Returns ``(None, "unparseable")`` rather than
    raising, because an unparseable number is a finding, not a crash.
    """
    if is_blank(value):
        return None, "blank"
    if isinstance(value, (int, float)):
        return float(value), None

    text = str(value)
    note: str | None = None
    cleaned = text.strip()
    if cleaned != text:
        note = "padded"

    stripped = _UNIT_SUFFIX.sub("", cleaned)
    if stripped != cleaned:
        note = "unit_suffix"
        cleaned = stripped

    stripped = _CURRENCY_PREFIX.sub("", cleaned)
    if stripped != cleaned:
        note = "currency_prefix"
        cleaned = stripped

    if "," in cleaned:
        # Our exports use the US convention: comma groups thousands.
        cleaned = cleaned.replace(",", "")
        note = "thousands_separator"

    if not cleaned:
        return None, "blank"

    try:
        parsed = float(cleaned)
    except ValueError:
        return None, "unparseable"

    if note is None and ("e" in cleaned.lower()):
        note = "scientific"
    return parsed, note


def parse_int(value: object) -> tuple[int | None, str | None]:
    """Parse an integer field, tolerating ``"3.0"`` and decorated forms."""
    parsed, note = parse_float(value)
    if parsed is None:
        return None, note
    as_int = int(round(parsed))
    if abs(parsed - as_int) > 1e-9:
        return as_int, note or "rounded"
    return as_int, note


def parse_timestamp(value: object) -> tuple[datetime | None, str | None]:
    """Parse a timestamp in any of the formats the manifest may carry.

    Returned datetimes are naive UTC: every supported input is either
    explicitly UTC or has no zone at all, and carrying a mix of aware and
    naive values through the engines invites subtle comparison bugs.
    """
    if is_blank(value):
        return None, "blank"
    if isinstance(value, datetime):
        return value.replace(tzinfo=None), None

    text = str(value).strip()
    if not text:
        return None, "blank"

    # Epoch seconds / milliseconds.
    if _EPOCH_RE.match(text):
        raw = int(text)
        if raw > 10**11:
            raw //= 1000
        try:
            return datetime.fromtimestamp(raw, tz=UTC).replace(tzinfo=None), "epoch"
        except (OverflowError, OSError, ValueError):
            return None, "unparseable"

    # ISO-ish, the canonical form.
    if _ISO_RE.match(text):
        candidate = text
        note: str | None = None
        if candidate.endswith("Z"):
            candidate = candidate[:-1]
        elif "+" in candidate[10:]:
            candidate = candidate[:10] + candidate[10:].split("+")[0]
            note = "explicit_offset"
        else:
            note = "no_timezone"
        candidate = candidate.replace(" ", "T", 1)
        if "T" in text and text.endswith("Z") and "." not in text:
            note = None  # exactly canonical
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None, "unparseable"
        if "." in candidate:
            note = note or "subsecond"
        if " " in text:
            note = "space_separator"
        return parsed.replace(tzinfo=None), note

    # Dash-separated, day-first by convention.
    m = _DASH_DAYFIRST_RE.match(text)
    if m:
        a, b, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        day, month = (a, b) if a > 12 or b <= 12 else (b, a)
        return _with_time(text, year, month, day, "dash_dayfirst")

    # Slash-separated, month-first by convention.
    m = _SLASH_RE.match(text)
    if m:
        a, b, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        month, day = (a, b) if a <= 12 else (b, a)
        return _with_time(text, year, month, day, "slash_monthfirst")

    return None, "unparseable"


_TIME_RE = re.compile(r"(\d{1,2}):(\d{2})(?::(\d{2}))?")


def _with_time(
    text: str, year: int, month: int, day: int, note: str
) -> tuple[datetime | None, str | None]:
    """Combine a parsed date with any time component found in ``text``."""
    hour = minute = second = 0
    m = _TIME_RE.search(text)
    if m:
        hour = int(m.group(1))
        minute = int(m.group(2))
        second = int(m.group(3) or 0)
    try:
        return datetime(year, month, day, hour, minute, second), note
    except ValueError:
        return None, "unparseable"


def normalize_label(value: object) -> tuple[str | None, str | None]:
    """Canonicalise a free-text label: trim, collapse spaces, fix case drift.

    Returns the title-cased form plus a note when the input differed. Used
    for port names and statuses, where ``"colombo"``, ``"COLOMBO"`` and
    ``"Colombo"`` must all resolve to the same entity.
    """
    if is_blank(value):
        return None, "blank"
    text = str(value)
    collapsed = re.sub(r"\s+", " ", text.strip())
    note: str | None = None
    if collapsed != text:
        note = "whitespace"
    if collapsed and (collapsed.isupper() or collapsed.islower()) and len(collapsed) > 3:
        note = "case_drift"
    return collapsed, note


def normalize_enum(value: object, allowed: set[str]) -> tuple[str | None, str | None]:
    """Resolve a value against a known enum, case-insensitively."""
    if is_blank(value):
        return None, "blank"
    text = str(value).strip()
    if text in allowed:
        return text, None
    upper = text.upper().replace(" ", "_").replace("-", "_")
    if upper in allowed:
        return upper, "case_drift"
    return text, "unknown_value"
