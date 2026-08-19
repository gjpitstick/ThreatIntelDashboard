"""IOC ingestion from abuse.ch: ThreatFox (general IOCs) + URLhaus (malicious
URLs). Both are free but require the same Auth-Key, issued at
https://auth.abuse.ch/ -- set ABUSECH_API_KEY in .env.

Without a key, this module logs a warning and skips cleanly; the rest of
the dashboard (vulnerabilities + news) still works.
"""
import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import IOC

logger = logging.getLogger("ctidash.ingestion.iocs")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def _parse_dt(value: str | None):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def fetch_threatfox(days: int) -> list[dict]:
    if not settings.abusech_api_key:
        logger.warning("ABUSECH_API_KEY not set -- skipping ThreatFox ingestion.")
        return []

    headers = {"Auth-Key": settings.abusech_api_key}
    payload = {"query": "get_iocs", "days": max(1, min(days, 7))}

    try:
        with httpx.Client(timeout=30.0, headers=headers) as client:
            resp = client.post(THREATFOX_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("ThreatFox fetch failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        logger.warning("ThreatFox query_status: %s", data.get("query_status"))
        return []
    return data.get("data", [])


def fetch_urlhaus_recent() -> list[dict]:
    if not settings.abusech_api_key:
        logger.warning("ABUSECH_API_KEY not set -- skipping URLhaus ingestion.")
        return []

    headers = {"Auth-Key": settings.abusech_api_key}

    try:
        with httpx.Client(timeout=30.0, headers=headers) as client:
            resp = client.get(URLHAUS_RECENT_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("URLhaus fetch failed: %s", exc)
        return []

    if isinstance(data, dict):
        return data.get("urls", [])
    return []


def ingest(session: Session, days: int | None = None) -> tuple[int, int]:
    days = days or settings.lookback_days
    fetched = 0
    new_count = 0

    for entry in fetch_threatfox(days):
        fetched += 1
        ioc_value = entry.get("ioc")
        if not ioc_value:
            continue
        existing = session.execute(
            select(IOC).where(IOC.ioc_value == ioc_value, IOC.source == "threatfox")
        ).scalar_one_or_none()
        if existing is not None:
            continue
        session.add(IOC(
            ioc_value=ioc_value[:512],
            ioc_type=entry.get("ioc_type", ""),
            threat_type=entry.get("threat_type", ""),
            malware=entry.get("malware_printable", "") or entry.get("malware", ""),
            confidence_level=entry.get("confidence_level"),
            first_seen=_parse_dt(entry.get("first_seen")),
            reference=(entry.get("reference") or "")[:1024],
            source="threatfox",
        ))
        new_count += 1

    for entry in fetch_urlhaus_recent():
        fetched += 1
        ioc_value = entry.get("url")
        if not ioc_value:
            continue
        existing = session.execute(
            select(IOC).where(IOC.ioc_value == ioc_value, IOC.source == "urlhaus")
        ).scalar_one_or_none()
        if existing is not None:
            continue
        session.add(IOC(
            ioc_value=ioc_value[:512],
            ioc_type="url",
            threat_type=entry.get("threat", "malware_download"),
            malware="",
            confidence_level=None,
            first_seen=_parse_dt(entry.get("dateadded")),
            reference=(entry.get("urlhaus_reference") or "")[:1024],
            source="urlhaus",
        ))
        new_count += 1

    return fetched, new_count
