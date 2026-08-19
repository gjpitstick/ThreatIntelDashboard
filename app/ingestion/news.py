"""RSS news ingestion: The Hacker News, Cyber Security News, BleepingComputer,
Krebs on Security (configurable in app/config.py).

These feeds are free-text articles, not structured threat data, so we do
lightweight keyword categorization to bucket each item as one of:
breach, campaign, vulnerability, malware, or general. CVE IDs mentioned in
the title/summary are extracted via regex and stored so they can be
cross-linked to the vulnerabilities pillar.
"""
import logging
import re
from datetime import datetime, timezone
from time import mktime

import feedparser
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import NewsItem

logger = logging.getLogger("ctidash.ingestion.news")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Ordered: first matching category wins. Keep breach/campaign checks before
# the generic vulnerability/malware buckets since an article often mentions
# a CVE *within* a breach or campaign story.
CATEGORY_KEYWORDS = [
    ("breach", [
        "data breach", "breached", "leaked database", "exposed database",
        "records exposed", "customer data", "personal data exposed",
        "stolen data", "data leak", "hacked and leaked",
    ]),
    ("campaign", [
        "campaign", "threat actor", "apt", "nation-state", "espionage",
        "state-sponsored", "phishing campaign", "targets", "targeting",
    ]),
    ("malware", [
        "ransomware", "malware", "trojan", "botnet", "worm", "rat ",
        "backdoor", "spyware", "loader", "stealer",
    ]),
    ("vulnerability", [
        "vulnerability", "vulnerabilities", "exploit", "zero-day", "0-day",
        "patch", "cve-", "flaw", "rce", "remote code execution",
    ]),
]


def _categorize(title: str, summary: str) -> str:
    text = f"{title} {summary}".lower()
    for category, keywords in CATEGORY_KEYWORDS:
        if any(kw in text for kw in keywords):
            return category
    return "general"


def _extract_cves(text: str) -> str:
    found = sorted(set(m.upper() for m in CVE_RE.findall(text)))
    return ", ".join(found)


def _parse_published(entry) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        value = getattr(entry, field, None)
        if value:
            return datetime.fromtimestamp(mktime(value), tz=timezone.utc)
    return None


def fetch_feed(name: str, url: str) -> list[dict]:
    """Fetch and parse a single RSS feed. Returns [] on any failure so one
    dead feed doesn't take down the whole ingestion run."""
    try:
        with httpx.Client(timeout=20.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; ctidash-homelab/1.0)"
        }) as client:
            resp = client.get(url)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to fetch feed %s (%s): %s", name, url, exc)
        return []

    items = []
    for entry in parsed.entries:
        title = getattr(entry, "title", "").strip()
        summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
        summary = re.sub(r"<[^>]+>", "", summary).strip()[:1000]
        link = getattr(entry, "link", "")
        guid = getattr(entry, "id", None) or link or title
        items.append({
            "guid": guid,
            "title": title,
            "summary": summary,
            "link": link,
            "source": name,
            "published_date": _parse_published(entry),
        })
    return items


def ingest(session: Session) -> tuple[int, int]:
    fetched = 0
    new_count = 0

    for name, url in settings.news_feeds.items():
        items = fetch_feed(name, url)
        fetched += len(items)

        for item in items:
            existing = session.execute(
                select(NewsItem).where(NewsItem.guid == item["guid"])
            ).scalar_one_or_none()
            if existing is not None:
                continue  # news items are immutable once fetched

            category = _categorize(item["title"], item["summary"])
            cve_refs = _extract_cves(f"{item['title']} {item['summary']}")

            session.add(NewsItem(
                guid=item["guid"],
                title=item["title"][:500],
                summary=item["summary"],
                link=item["link"][:1024],
                source=item["source"],
                published_date=item["published_date"],
                category=category,
                cve_refs=cve_refs,
            ))
            new_count += 1

    return fetched, new_count
