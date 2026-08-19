from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import db_dependency
from app.models import NewsItem
from app.schemas import NewsItemOut

router = APIRouter(prefix="/api/news", tags=["news"])


@router.get("", response_model=list[NewsItemOut])
def list_news(
    category: str | None = Query(None, description="breach, campaign, vulnerability, malware, general"),
    source: str | None = Query(None),
    search: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(db_dependency),
):
    stmt = select(NewsItem)
    if category:
        stmt = stmt.where(NewsItem.category == category.lower())
    if source:
        stmt = stmt.where(NewsItem.source == source)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            (NewsItem.title.ilike(like)) | (NewsItem.summary.ilike(like))
        )
    stmt = stmt.order_by(NewsItem.published_date.desc().nulls_last()).limit(limit).offset(offset)
    return session.execute(stmt).scalars().all()
