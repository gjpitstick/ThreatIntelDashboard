"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.

Free, public, no key/auth. Full catalog re-downloaded and diffed against
existing Vulnerability rows each run (the catalog is a few thousand rows,
small enough to just re-fetch in full rather than track deltas).

Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Vulnerability

logger = logging.getLogger("ctidash.ingestion.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CISA blocks generic/bot-looking user agents on some edge nodes; identify
# as a normal browser-ish client to avoid spurious 403s from a homelab IP.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ctidash-homelab/1.0"
    ),
    "Accept": "application/json",
}


def fetch_kev_catalog() -> list[dict]:
    with httpx.Client(timeout=30.0, headers=_HEADERS, follow_redirects=True) as client:
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    return data.get("vulnerabilities", [])


def ingest(session: Session) -> tuple[int, int]:
    """Mark matching CVEs as KEV, creating stub rows for any CVE not yet
    known from NVD ingestion. Returns (fetched, new)."""
    entries = fetch_kev_catalog()
    new_count = 0

    for entry in entries:
        cve_id = entry.get("cveID")
        if not cve_id:
            continue

        existing = session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        ).scalar_one_or_none()

        if existing is None:
            # KEV can reference a CVE before/without it appearing in our NVD
            # window -- create a minimal stub so it still shows on the dashboard.
            existing = Vulnerability(
                cve_id=cve_id,
                description=entry.get("shortDescription", ""),
                vendor_products=f"{entry.get('vendorProject', '')}/{entry.get('product', '')}",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
            session.add(existing)
            new_count += 1

        existing.is_kev = True
        existing.kev_date_added = _parse_date(entry.get("dateAdded"))
        existing.kev_due_date = _parse_date(entry.get("dueDate"))
        existing.kev_ransomware_use = entry.get("knownRansomwareCampaignUse", "")
        existing.kev_required_action = entry.get("requiredAction", "")

    return len(entries), new_count


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None
