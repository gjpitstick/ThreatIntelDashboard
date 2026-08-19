# CTI Dashboard

A self-hosted cyber threat intelligence dashboard: vulnerabilities, data
breaches, attack campaigns, and IOCs, pulled from free sources and shown on
one web page. Built for a homelab LXC container (Python/FastAPI + SQLite,
no external database or heavy dependencies).

## Data sources

| Pillar | Source | Auth |
|---|---|---|
| Vulnerabilities | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | none required (optional key raises rate limit) |
| Vulnerabilities (exploited-in-the-wild flag) | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | none |
| Breaches / campaigns / general news | RSS: The Hacker News, Cyber Security News, BleepingComputer, Krebs on Security | none |
| IOCs | [abuse.ch ThreatFox](https://threatfox.abuse.ch/) + [URLhaus](https://urlhaus.abuse.ch/) | free key from [auth.abuse.ch](https://auth.abuse.ch/) |

News articles are auto-tagged into `breach` / `campaign` / `vulnerability` /
`malware` / `general` by keyword matching (see `app/ingestion/news.py`), and
any CVE IDs mentioned in an article are extracted and cross-linked.

Data refreshes automatically in the background every `REFRESH_INTERVAL_HOURS`
(default 4). There's no manual refresh button in the UI by design; if you
need to force a refresh for troubleshooting, `POST /api/refresh` on the
running instance triggers one synchronously.

## Quick start (LXC container)

Requires a Debian/Ubuntu-based container (e.g. Debian 12 or Ubuntu 22.04+ on
Proxmox) with internet access and root access.

```bash
# copy/extract this project onto the container, then:
cd cti-dashboard
sudo bash install.sh
```

The installer will:
1. Install `python3`, `nginx`, `sqlite3`
2. Create a dedicated `ctidash` system user
3. Copy the app to `/opt/ctidash` and set up a virtualenv
4. Create `/opt/ctidash/.env` from the example (edit it to add API keys)
5. Install and start a `ctidash` systemd service (uvicorn, bound to `127.0.0.1:8000`)
6. Configure nginx to reverse-proxy a port of your choice (default `80`) to it

At the end it prints the URL to open, e.g. `http://192.168.1.50`.

Re-running `sudo bash install.sh` after pulling an updated copy of this
project safely updates the existing install in place.

### After installing

- Edit `/opt/ctidash/.env` to add `NVD_API_KEY` and/or `ABUSECH_API_KEY`
  (both free, both optional -- see the table above for where to get them).
  Without `ABUSECH_API_KEY` the IOC pillar stays empty; everything else
  works without any key.
- `sudo systemctl restart ctidash` after editing `.env`.
- `sudo journalctl -u ctidash -f` to watch logs / ingestion runs.
- The SQLite database lives at `/opt/ctidash/data/ctidash.db`.

## Running locally (development)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Then open http://127.0.0.1:8000.

## Project layout

```
app/
  main.py              FastAPI app, startup (DB init, first ingest, scheduler)
  config.py            Settings (env vars / .env)
  database.py          SQLAlchemy engine/session (SQLite)
  models.py            Vulnerability, NewsItem, IOC, IngestionLog
  schemas.py           Pydantic response models
  scheduler.py         APScheduler background refresh job
  ingestion/
    nvd.py             NVD CVE API 2.0 client
    kev.py             CISA KEV catalog client
    news.py            RSS fetch + keyword categorization + CVE extraction
    iocs.py             abuse.ch ThreatFox + URLhaus clients
  routers/
    vulnerabilities.py  GET /api/vulnerabilities
    news.py              GET /api/news
    iocs.py              GET /api/iocs
    stats.py             GET /api/summary, POST /api/refresh
static/
  index.html, css/style.css, js/app.js   Single-page dashboard (no build step)
install.sh             LXC installer (systemd + nginx)
.env.example           Config template
```

## Configuration reference (`.env`)

| Variable | Default | Notes |
|---|---|---|
| `NVD_API_KEY` | *(empty)* | Optional. Raises NVD rate limit from 5 to 50 req/30s. |
| `ABUSECH_API_KEY` | *(empty)* | Required for the IOC pillar (ThreatFox + URLhaus). |
| `APP_PORT` | `8000` | Internal uvicorn port (nginx proxies to this). |
| `REFRESH_INTERVAL_HOURS` | `4` | How often background ingestion runs. |
| `LOOKBACK_DAYS` | `7` | How far back CVE/IOC pulls look on each refresh. |
| `DATABASE_PATH` | `./data/ctidash.db` | SQLite file path. |
| `LOG_LEVEL` | `INFO` | Python logging level. |

RSS feed sources are configured in `app/config.py` (`news_feeds` dict) if
you want to add/remove sites.

## Notes and known limitations

- **First run is empty until the first ingestion completes** (typically
  under a minute for CVE/KEV/news; IOCs only populate once a key is set).
  The header shows a small status pill per source with the last run result.
- **CISA KEV** occasionally blocks requests from generic-looking clients;
  the ingester sends a browser-like User-Agent to avoid this, but if your
  homelab's outbound IP gets rate-limited, check `journalctl -u ctidash`.
- **News categorization is keyword-based**, not ML -- it's intentionally
  simple and transparent (see `CATEGORY_KEYWORDS` in `app/ingestion/news.py`)
  and easy to tune if you notice miscategorized stories.
- This is a read-only intelligence dashboard, not a SIEM/SOAR -- it doesn't
  correlate against your own assets or alert; it's a single pane of glass
  over public feeds.
