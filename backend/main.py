"""Makar forensic API service.

    uvicorn backend.main:app --reload
    python -m backend.main --port 8000

The dataset directory is taken from ``MAKAR_DATA_DIR`` (default ``out``) and
analysed lazily on the first request, so the service starts instantly and the
first call pays the analysis cost. ``POST /api/analyze`` re-runs it on demand.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from backend.api import router  # noqa: E402
from backend.services.store import store  # noqa: E402
from core.config import load_config  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.directory = Path(os.environ.get("MAKAR_DATA_DIR", "out"))
    store.manifest = os.environ.get("MAKAR_MANIFEST", "manifest_suspect.csv")
    # Deliberately not analysed here: a slow startup makes the dev loop
    # painful, and the first request can afford the ~10 s.
    yield


cfg = load_config()

app = FastAPI(
    title="Makar",
    description=(
        "Distributed cargo forensics, provenance and reconstruction. "
        "Every endpoint is a view over one analysis snapshot."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.list_("api.cors_origins", ["*"]),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "dataset": str(store.directory),
        "analysed": store.loaded,
    }


@app.exception_handler(FileNotFoundError)
async def missing_dataset(_request, exc: FileNotFoundError) -> JSONResponse:
    """Turn a missing dataset into actionable guidance rather than a 500."""
    return JSONResponse(
        status_code=404,
        content={
            "detail": str(exc),
            "hint": (
                "Generate a dataset first: "
                "python scripts/generate.py --seed 481516 --records 5000 --out out"
            ),
        },
    )


def main() -> None:
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=os.environ.get("MAKAR_API_HOST", cfg.get("api.host", "127.0.0.1")),
        port=int(os.environ.get("MAKAR_API_PORT", cfg.int_("api.port", 8000))),
        reload=False,
    )


if __name__ == "__main__":
    main()
