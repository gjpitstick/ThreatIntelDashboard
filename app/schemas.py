"""Pydantic response models for the API."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: str
    published_date: datetime | None
    modified_date: datetime | None
    vendor_products: str
    source_url: str
    is_kev: bool
    kev_date_added: datetime | None
    kev_due_date: datetime | None
    kev_ransomware_use: str
    kev_required_action: str


class NewsItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    title: str
    summary: str
    link: str
    source: str
    published_date: datetime | None
    category: str
    cve_refs: str


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ioc_value: str
    ioc_type: str
    threat_type: str
    malware: str
    confidence_level: int | None
    first_seen: datetime | None
    reference: str
    source: str


class SourceStatus(BaseModel):
    source: str
    status: str
    finished_at: datetime | None
    items_fetched: int
    items_new: int
    message: str


class SummaryStats(BaseModel):
    total_vulnerabilities: int
    kev_count: int
    critical_count: int
    high_count: int
    new_vulns_7d: int
    total_news: int
    breach_count_7d: int
    campaign_count_7d: int
    total_iocs: int
    iocs_24h: int
    severity_breakdown: dict[str, int]
    ioc_type_breakdown: dict[str, int]
    news_category_breakdown: dict[str, int]
    daily_vuln_trend: list[dict]
    sources: list[SourceStatus]
