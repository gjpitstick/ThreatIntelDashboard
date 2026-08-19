"""Background scheduling for periodic data ingestion."""
import logging
import traceback
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.database import get_session
from app.ingestion import iocs, kev, news, nvd
from app.models import IngestionLog

logger = logging.getLogger("ctidash.scheduler")

_scheduler: BackgroundScheduler | None = None

SOURCES = {
    "nvd": lambda session: nvd.ingest(session, days=settings.lookback_days),
    "cisa_kev": lambda session: kev.ingest(session),
    "news": lambda session: news.ingest(session),
    "iocs": lambda session: iocs.ingest(session, days=settings.lookback_days),
}


def run_source(source_name: str) -> None:
    fn = SOURCES.get(source_name)
    if fn is None:
        logger.error("Unknown ingestion source: %s", source_name)
        return

    with get_session() as session:
        log_entry = IngestionLog(source=source_name, status="running")
        session.add(log_entry)
        session.flush()

        try:
            fetched, new = fn(session)
            log_entry.status = "ok"
            log_entry.items_fetched = fetched
            log_entry.items_new = new
            log_entry.message = f"Fetched {fetched}, {new} new."
            logger.info("[%s] %s", source_name, log_entry.message)
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            log_entry = IngestionLog(
                source=source_name,
                status="error",
                message=f"{exc}\n{traceback.format_exc()[-1500:]}",
            )
            session.add(log_entry)
            logger.error("[%s] ingestion failed: %s", source_name, exc)
        finally:
            from datetime import datetime, timezone
            log_entry.finished_at = datetime.now(timezone.utc)


def run_all_sources() -> None:
    for source_name in SOURCES:
        run_source(source_name)


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    # The very first ingestion run is kicked off explicitly (in a background
    # thread) at app startup -- see main.py -- so schedule this recurring job's
    # first fire one full interval from now to avoid double-fetching on boot.
    first_run = datetime.now(timezone.utc) + timedelta(hours=settings.refresh_interval_hours)

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        run_all_sources,
        "interval",
        hours=settings.refresh_interval_hours,
        id="refresh_all",
        next_run_time=first_run,
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info(
        "Scheduler started, refreshing every %s hour(s).", settings.refresh_interval_hours
    )
    return _scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
