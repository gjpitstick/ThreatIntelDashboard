from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import db_dependency
from app.models import IOC, IngestionLog, NewsItem, Vulnerability
from app.scheduler import run_all_sources
from app.schemas import SourceStatus, SummaryStats

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/summary", response_model=SummaryStats)
def summary(session: Session = Depends(db_dependency)):
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    day_ago = now - timedelta(days=1)

    total_vulns = session.execute(select(func.count(Vulnerability.id))).scalar_one()
    kev_count = session.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.is_kev.is_(True))
    ).scalar_one()
    critical_count = session.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.cvss_severity == "CRITICAL")
    ).scalar_one()
    high_count = session.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.cvss_severity == "HIGH")
    ).scalar_one()
    new_vulns_7d = session.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.published_date >= week_ago)
    ).scalar_one()

    total_news = session.execute(select(func.count(NewsItem.id))).scalar_one()
    breach_count_7d = session.execute(
        select(func.count(NewsItem.id)).where(
            NewsItem.category == "breach", NewsItem.published_date >= week_ago
        )
    ).scalar_one()
    campaign_count_7d = session.execute(
        select(func.count(NewsItem.id)).where(
            NewsItem.category == "campaign", NewsItem.published_date >= week_ago
        )
    ).scalar_one()

    total_iocs = session.execute(select(func.count(IOC.id))).scalar_one()
    iocs_24h = session.execute(
        select(func.count(IOC.id)).where(IOC.fetched_at >= day_ago)
    ).scalar_one()

    severity_rows = session.execute(
        select(Vulnerability.cvss_severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.cvss_severity)
    ).all()
    severity_breakdown = {row[0]: row[1] for row in severity_rows}

    ioc_type_rows = session.execute(
        select(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type)
    ).all()
    ioc_type_breakdown = {row[0] or "unknown": row[1] for row in ioc_type_rows}

    news_cat_rows = session.execute(
        select(NewsItem.category, func.count(NewsItem.id)).group_by(NewsItem.category)
    ).all()
    news_category_breakdown = {row[0]: row[1] for row in news_cat_rows}

    # Daily new-vulnerability trend for the last 14 days (for a sparkline).
    trend_rows = session.execute(
        select(
            func.date(Vulnerability.published_date).label("day"),
            func.count(Vulnerability.id),
        )
        .where(Vulnerability.published_date >= now - timedelta(days=14))
        .group_by("day")
        .order_by("day")
    ).all()
    daily_vuln_trend = [{"date": row[0], "count": row[1]} for row in trend_rows if row[0]]

    # Latest status per source.
    sources = []
    for source_name in ("nvd", "cisa_kev", "news", "iocs"):
        latest = session.execute(
            select(IngestionLog)
            .where(IngestionLog.source == source_name)
            .order_by(IngestionLog.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if latest:
            sources.append(SourceStatus(
                source=source_name,
                status=latest.status,
                finished_at=latest.finished_at,
                items_fetched=latest.items_fetched,
                items_new=latest.items_new,
                message=latest.message,
            ))
        else:
            sources.append(SourceStatus(
                source=source_name, status="never_run", finished_at=None,
                items_fetched=0, items_new=0, message="",
            ))

    return SummaryStats(
        total_vulnerabilities=total_vulns,
        kev_count=kev_count,
        critical_count=critical_count,
        high_count=high_count,
        new_vulns_7d=new_vulns_7d,
        total_news=total_news,
        breach_count_7d=breach_count_7d,
        campaign_count_7d=campaign_count_7d,
        total_iocs=total_iocs,
        iocs_24h=iocs_24h,
        severity_breakdown=severity_breakdown,
        ioc_type_breakdown=ioc_type_breakdown,
        news_category_breakdown=news_category_breakdown,
        daily_vuln_trend=daily_vuln_trend,
        sources=sources,
    )


@router.post("/refresh", include_in_schema=True)
def trigger_refresh():
    """Manually kick off an out-of-band ingestion run (admin/troubleshooting use --
    the dashboard itself refreshes automatically on REFRESH_INTERVAL_HOURS).
    Runs synchronously so the caller gets a definitive done/error response."""
    run_all_sources()
    return {"status": "completed"}
