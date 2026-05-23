"""
Feed collector — pulls IoCs from open threat feeds automatically.
Runs on a schedule via APScheduler.
"""
import csv
import io
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.detector import detect_type, normalize
from app.models.feed import ThreatFeed, FeedEntry, FeedStatus, FeedType
from app.models.ioc import IoC, Severity

log = logging.getLogger("cti.feeds")


# ── Default feeds bundled with the platform ─────────────────────────────────

DEFAULT_FEEDS = [
    {
        "name": "URLhaus Recent URLs",
        "feed_type": FeedType.URLHAUS,
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "enabled": True,
        "meta": {"limit": 300},
    },
    {
        "name": "AbuseIPDB Recent Malicious IPs",
        "feed_type": FeedType.ABUSEIPDB,
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "enabled": True,
        "meta": {"limit": 200},
    },
    {
        "name": "AlienVault OTX Pulses",
        "feed_type": FeedType.ALIENVAULT_OTX,
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "enabled": True,
        "meta": {"limit": 200},
    },
    {
        "name": "MalwareBazaar Recent Samples",
        "feed_type": FeedType.MALWAREBAZAAR,
        "url": "https://mb-api.abuse.ch/api/v1/",
        "enabled": True,
        "meta": {"limit": 150},
    },
]


async def seed_default_feeds():
    async with AsyncSessionLocal() as db:
        for f in DEFAULT_FEEDS:
            exists = (await db.execute(
                select(ThreatFeed).where(ThreatFeed.name == f["name"])
            )).scalar_one_or_none()
            if not exists:
                db.add(ThreatFeed(**{k: v for k, v in f.items() if k != "meta"},
                                  meta=f.get("meta", {})))
        await db.commit()


# ── Per-feed collectors ──────────────────────────────────────────────────────

async def _collect_urlhaus_csv(url: str) -> list[dict]:
    """Parse URLhaus CSV — columns: id, dateadded, url, url_status, threat, tags, ..."""
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url)
        r.raise_for_status()
    rows = []
    for line in r.text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = next(csv.reader([line]))
        if len(parts) < 3:
            continue
        raw_url = parts[2].strip()
        ioc_type = detect_type(raw_url)
        if ioc_type is None:
            continue
        rows.append({
            "ioc_value": normalize(raw_url),
            "ioc_type": ioc_type.value,
            "threat_type": parts[4].strip() if len(parts) > 4 else None,
            "tags": [t.strip() for t in parts[5].split(",")] if len(parts) > 5 else [],
            "source_url": url,
            "raw": {"status": parts[3].strip() if len(parts) > 3 else None},
        })
    return rows


async def _collect_abuseipdb(url: str, limit: int = 200) -> list[dict]:
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
    rows = []
    for item in data.get("data", [])[:limit]:
        ip = item.get("ipAddress")
        if not ip:
            continue
        rows.append({
            "ioc_value": normalize(ip),
            "ioc_type": "ip",
            "threat_type": "malicious_ip",
            "tags": ["abuseipdb"],
            "source_url": url,
            "raw": item,
        })
    return rows

async def _collect_otx(url: str, limit: int = 200) -> list[dict]:
    headers = {
        "X-OTX-API-KEY": settings.ALIENVAULT_API_KEY
    }
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
    rows = []
    for pulse in data.get("results", [])[:limit]:
        indicators = pulse.get("indicators", [])
        for ind in indicators[:10]:
            value = ind.get("indicator")
            ioc_type = detect_type(value)
            if not ioc_type:
                continue
            rows.append({
                "ioc_value": normalize(value),
                "ioc_type": ioc_type.value,
                "threat_type": pulse.get("name"),
                "tags": pulse.get("tags", []),
                "source_url": pulse.get("references", [None])[0],
                "raw": pulse,
            })
    return rows[:limit]

async def _collect_malwarebazaar(url: str, limit: int = 150) -> list[dict]:
    payload = {
        "query": "get_recent",
        "selector": str(min(limit, 100)),  # API max = 100
    }

    headers = {}
    if settings.URLHAUS_API_KEY:
        headers["Auth-Key"] = settings.URLHAUS_API_KEY

    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(url, data=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
    
    query_status = data.get("query_status")
    if query_status != "ok":
        print(f"[WARN] MalwareBazaar returned status: {query_status}")
        return []

    rows = []
    for item in data.get("data", [])[:limit]:
        # Визначаємо, який саме хеш є в наявності (пріоритет на SHA256)
        sha256 = item.get("sha256_hash")
        sha1 = item.get("sha1_hash")
        md5 = item.get("md5_hash")
        
        # Динамічний мапінг під твій IoCType
        if sha256:
            ioc_value = sha256
            ioc_type = "hash_sha256"  # Відповідає IoCType.HASH_SHA256
        elif sha1:
            ioc_value = sha1
            ioc_type = "hash_sha1"    # Відповідає IoCType.HASH_SHA1
        elif md5:
            ioc_value = md5
            ioc_type = "hash_md5"     # Відповідає IoCType.HASH_MD5
        else:
            continue  # Якщо немає жодного хешу, пропускаємо запис
            
        item_tags = item.get("tags") or []
        file_type = item.get("file_type")
        if file_type and file_type not in item_tags:
            item_tags.append(file_type)

        rows.append({
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,  # Передаємо легітимний рядок, який SQLAlchemy змапить на Enum
            "threat_type": item.get("signature") or "Malware",
            "tags": item_tags,
            "source_url": f"https://bazaar.abuse.ch/sample/{sha256 or ioc_value}",
            "raw": item,
        })
        
    print(f"[INFO] Успішно імпортовано {len(rows)} хешів з MalwareBazaar")
    return rows

# ── Main runner ──────────────────────────────────────────────────────────────

async def run_feed(feed: ThreatFeed, db: AsyncSession) -> int:
    """Fetch one feed and upsert IoCs. Returns count of new entries."""
    try:
        cfg = feed.meta or {}
        limit = cfg.get("limit", 100)

        if feed.feed_type == FeedType.URLHAUS:
            rows = await _collect_urlhaus_csv(feed.url)
            rows = rows[:limit]
        elif feed.feed_type == FeedType.ABUSEIPDB:
            rows = await _collect_abuseipdb(feed.url, limit)
        elif feed.feed_type == FeedType.ALIENVAULT_OTX:
            rows = await _collect_otx(feed.url, limit)
        elif feed.feed_type == FeedType.MALWAREBAZAAR:
            rows = await _collect_malwarebazaar(feed.url, limit)
    except Exception as e:
        feed.status = FeedStatus.ERROR
        feed.last_error = str(e)[:500]
        feed.last_run = datetime.now(timezone.utc)
        await db.commit()
        log.error("Feed %s failed: %s", feed.name, e)
        return 0

    added = 0
    seen = set()
    for row in rows:
        val = row["ioc_value"]
        if not val or val in seen:
            continue
        seen.add(val)

        # Upsert into IoC table
        existing = (await db.execute(select(IoC).where(IoC.value == val))).scalar_one_or_none()
        if not existing:
            db.add(IoC(
                value=val,
                ioc_type=row["ioc_type"],
                severity=Severity.UNKNOWN,
                source=feed.name,
                tags=row.get("tags", []),
                description=row.get("threat_type"),
            ))
            added += 1

        # Always insert feed entry for history
        db.add(FeedEntry(
            feed_id=feed.id,
            ioc_value=val,
            ioc_type=row["ioc_type"],
            threat_type=row.get("threat_type"),
            tags=row.get("tags", []),
            source_url=row.get("source_url"),
            raw=row.get("raw", {}),
        ))

    feed.status = FeedStatus.OK
    feed.last_error = None
    feed.last_run = datetime.now(timezone.utc)
    feed.iocs_added = (feed.iocs_added or 0) + added
    feed.total_fetched = (feed.total_fetched or 0) + len(rows)
    await db.commit()
    log.info("Feed %s: %d new IoCs (total rows: %d)", feed.name, added, len(rows))
    return added


async def run_all_feeds():
    """Called by the scheduler to refresh all enabled feeds."""
    async with AsyncSessionLocal() as db:
        feeds = (await db.execute(
            select(ThreatFeed).where(ThreatFeed.enabled == True)
        )).scalars().all()
        for feed in feeds:
            await run_feed(feed, db)