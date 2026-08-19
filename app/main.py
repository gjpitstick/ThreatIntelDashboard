"""CTI Dashboard -- FastAPI application entrypoint."""
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.database import init_db
from app.routers import iocs, news, stats, vulnerabilities
from app.scheduler import run_all_sources, shutdown_scheduler, start_scheduler

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("ctidash.main")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database ready.")

    # Kick off the first ingestion run in the background so app startup
    # (and the dashboard UI) isn't blocked on external network calls.
    threading.Thread(target=run_all_sources, daemon=True, name="initial-ingest").start()

    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(title="CTI Dashboard", version="1.0.0", lifespan=lifespan)

app.include_router(vulnerabilities.router)
app.include_router(news.router)
app.include_router(iocs.router)
app.include_router(stats.router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
def health():
    return {"status": "ok"}
