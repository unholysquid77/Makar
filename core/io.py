"""Manifest and artifact I/O.

The suspect manifest is read as *rows of strings*, exactly as a CSV or a JSON
export would deliver it. Parsing happens in :mod:`core.normalization`, not
here, so that a malformed value becomes FORMAT evidence rather than an
exception during load.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _ensure_parent(path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def write_rows_csv(path: str | Path, rows: list[dict[str, Any]], columns: list[str] | None = None) -> Path:
    """Write manifest rows as CSV, preserving the string forms verbatim."""
    p = _ensure_parent(path)
    if not rows:
        p.write_text("", encoding="utf-8")
        return p
    fieldnames = columns or list(rows[0].keys())
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return p


def write_rows_json(path: str | Path, rows: list[dict[str, Any]]) -> Path:
    p = _ensure_parent(path)
    p.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def read_rows(path: str | Path) -> list[dict[str, Any]]:
    """Load manifest rows from CSV or JSON.

    Everything comes back as a string (or ``None`` for a genuinely absent
    JSON value). No type coercion happens here on purpose.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"manifest not found: {p}")

    if p.suffix.lower() == ".json":
        payload = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            # Tolerate {"records": [...]} wrappers.
            for key in ("records", "rows", "manifest", "data"):
                if key in payload and isinstance(payload[key], list):
                    payload = payload[key]
                    break
        if not isinstance(payload, list):
            raise ValueError(f"expected a list of records in {p}")
        return [
            {k: ("" if v is None else v if isinstance(v, str) else str(v)) for k, v in row.items()}
            for row in payload
        ]

    with p.open("r", encoding="utf-8", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def write_model(path: str | Path, model: BaseModel) -> Path:
    """Serialise a pydantic model to indented JSON."""
    p = _ensure_parent(path)
    p.write_text(model.model_dump_json(indent=2), encoding="utf-8")
    return p


def write_json(path: str | Path, payload: Any) -> Path:
    p = _ensure_parent(path)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return p


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))
