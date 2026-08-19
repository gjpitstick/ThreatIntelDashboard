from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import db_dependency
from app.models import Vulnerability
from app.schemas import VulnerabilityOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    severity: str | None = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    kev_only: bool = Query(False),
    search: str | None = Query(None, description="Search CVE ID or description"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(db_dependency),
):
    stmt = select(Vulnerability)
    if severity:
        stmt = stmt.where(Vulnerability.cvss_severity == severity.upper())
    if kev_only:
        stmt = stmt.where(Vulnerability.is_kev.is_(True))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            (Vulnerability.cve_id.ilike(like)) | (Vulnerability.description.ilike(like))
        )
    stmt = stmt.order_by(
        Vulnerability.is_kev.desc(),
        Vulnerability.published_date.desc().nulls_last(),
    ).limit(limit).offset(offset)

    return session.execute(stmt).scalars().all()


@router.get("/{cve_id}", response_model=VulnerabilityOut)
def get_vulnerability(cve_id: str, session: Session = Depends(db_dependency)):
    stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper())
    result = session.execute(stmt).scalar_one_or_none()
    if result is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="CVE not found")
    return result
