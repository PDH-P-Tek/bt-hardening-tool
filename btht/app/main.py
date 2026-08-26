"""Application entry point.

`uvicorn btht.app.main:app`. Single container, no external services, and no outbound
network calls from this half of the tool at all — `SPEC.md` §12.1.
"""

from __future__ import annotations

from fastapi import FastAPI

from btht.app.web.routes import router

app = FastAPI(title="BT Hardening Tool", docs_url=None, redoc_url=None)
app.include_router(router)
