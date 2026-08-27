"""Application entry point.

`uvicorn btht.app.main:app`. Single container, no external services.

The collector runs **in this process**, beside the ruleset builder — `MONITORING.md`
§3.1. That is the whole architecture: one container, one estate inventory, one baseline
artefact. It also means the only outbound traffic the tool ever makes is the monitor's
SSH to the management path. Nothing else here reaches the network at all.

Set `BTHT_MONITOR=0` to start the web app without the collector — useful when working
on the setup half with no range in front of you.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI

from btht.app.model.estate import Estate
from btht.app.model.policy import EstateFileError, load_estate
from btht.app.monitor.scheduler import Credentials, Scheduler
from btht.app.web.routes import MONITOR_DB, estate_path, router


def _estate() -> Estate | None:
    """Read on every cycle so a box declared mid-exercise is polled without a restart."""
    path = estate_path()
    if not path.exists():
        return None
    try:
        return load_estate(path)
    except (EstateFileError, OSError):
        return None


def _credentials() -> Credentials:
    """The monitor's key is the operator's, generated at setup and kept out of the tree."""
    return Credentials(
        user=os.environ.get("BTHT_SSH_USER", ""),
        key_path=os.environ.get("BTHT_SSH_KEY", ""),
        known_hosts=os.environ.get("BTHT_KNOWN_HOSTS", ""),
        timeout=int(os.environ.get("BTHT_SSH_TIMEOUT", "20")),
    )


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    scheduler = Scheduler(
        store_path=Path(MONITOR_DB),
        estate_source=_estate,
        credentials=_credentials(),
        enabled=os.environ.get("BTHT_MONITOR", "1") != "0",
    )
    application.state.scheduler = scheduler
    scheduler.start()
    try:
        yield
    finally:
        with suppress(Exception):
            await scheduler.stop()


app = FastAPI(title="BT Hardening Tool", docs_url=None, redoc_url=None, lifespan=lifespan)
app.include_router(router)
