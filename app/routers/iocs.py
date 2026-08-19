from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import db_dependency
from app.models import IOC
from app.schemas import IOCOut

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("", response_model=list[IOCOut])
def list_iocs(
    ioc_type: str | None = Query(None, description="ip, domain, url, md5_hash, sha256_hash, ..."),
    malware: str | None = Query(None),
    search: str | None = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(db_dependency),
):
    stmt = select(IOC)
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if malware:
        stmt = stmt.where(IOC.malware.ilike(f"%{malware}%"))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(IOC.ioc_value.ilike(like))
    stmt = stmt.order_by(IOC.first_seen.desc().nulls_last()).limit(limit).offset(offset)
    return session.execute(stmt).scalars().all()
