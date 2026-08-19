"""NVD CVE API 2.0 ingestion.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Base: https://services.nvd.nist.gov/rest/json/cves/2.0
Free, no key required, but rate-limited to 5 req/30s without a key
(50 req/30s with one, set NVD_API_KEY in .env).
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Vulnerability

logger = logging.getLogger("ctidash.ingestion.nvd")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cvss(metrics: dict) -> tuple[float | None, str]:
    """Pull the best-available CVSS score/severity from an NVD metrics block."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity")
            if severity is None and score is not None:
                # CVSS v2 entries don't carry a severity label -- derive one.
                if score >= 9:
                    severity = "CRITICAL"
                elif score >= 7:
                    severity = "HIGH"
                elif score >= 4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return score, (severity or "UNKNOWN").upper()
    return None, "UNKNOWN"


def _extract_vendor_products(configurations: list) -> str:
    products = set()
    for config in configurations or []:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    if vendor and vendor != "*":
                        products.add(f"{vendor}/{product}" if product not in ("*", "") else vendor)
    return ", ".join(sorted(products)[:10])


def fetch_recent_cves(days: int | None = None, results_per_page: int = 2000) -> list[dict]:
    """Fetch CVEs published in the last `days` days. Handles pagination."""
    days = days or settings.lookback_days
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }

    all_items: list[dict] = []
    with httpx.Client(timeout=30.0, headers=headers) as client:
        while True:
            resp = client.get(NVD_BASE_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            all_items.extend(vulns)
            total = data.get("totalResults", 0)
            params["startIndex"] += results_per_page
            if params["startIndex"] >= total or not vulns:
                break
    return all_items


def ingest(session: Session, days: int | None = None) -> tuple[int, int]:
    """Fetch recent CVEs and upsert into the database. Returns (fetched, new)."""
    raw_items = fetch_recent_cves(days=days)
    new_count = 0

    for item in raw_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score, severity = _extract_cvss(metrics)

        published = cve.get("published")
        modified = cve.get("lastModified")

        existing = session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        ).scalar_one_or_none()

        if existing is None:
            existing = Vulnerability(cve_id=cve_id)
            session.add(existing)
            new_count += 1

        existing.description = description[:4000]
        existing.cvss_score = score
        existing.cvss_severity = severity
        existing.published_date = _parse_dt(published)
        existing.modified_date = _parse_dt(modified)
        existing.vendor_products = _extract_vendor_products(cve.get("configurations", []))
        existing.source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return len(raw_items), new_count


def _parse_dt(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
