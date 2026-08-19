"""SQLAlchemy ORM models for the four data pillars + ingestion bookkeeping."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str] = mapped_column(String(16), default="UNKNOWN")  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    published_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    vendor_products: Mapped[str] = mapped_column(Text, default="")  # comma-joined, best-effort
    source_url: Mapped[str] = mapped_column(String(255), default="")

    is_kev: Mapped[bool] = mapped_column(default=False)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_ransomware_use: Mapped[str] = mapped_column(String(8), default="")
    kev_required_action: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_vuln_severity", "cvss_severity"),
        Index("ix_vuln_is_kev", "is_kev"),
        Index("ix_vuln_published", "published_date"),
    )


class NewsItem(Base):
    __tablename__ = "news_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guid: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str] = mapped_column(String(1024), default="")
    source: Mapped[str] = mapped_column(String(128), default="")
    published_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    category: Mapped[str] = mapped_column(String(32), default="general")  # breach/campaign/vulnerability/malware/general
    cve_refs: Mapped[str] = mapped_column(Text, default="")  # comma-joined CVE IDs found in text
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_news_category", "category"),
        Index("ix_news_published", "published_date"),
    )


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_value: Mapped[str] = mapped_column(String(512))
    ioc_type: Mapped[str] = mapped_column(String(32), default="")  # ip, domain, url, md5_hash, sha256_hash, ...
    threat_type: Mapped[str] = mapped_column(String(64), default="")
    malware: Mapped[str] = mapped_column(String(128), default="")
    confidence_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reference: Mapped[str] = mapped_column(String(1024), default="")
    source: Mapped[str] = mapped_column(String(32), default="")  # threatfox / urlhaus
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("ioc_value", "source", name="uq_ioc_value_source"),
        Index("ix_ioc_type", "ioc_type"),
        Index("ix_ioc_first_seen", "first_seen"),
    )


class IngestionLog(Base):
    __tablename__ = "ingestion_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running/ok/error
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")
