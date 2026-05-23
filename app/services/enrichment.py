"""
Enrichment orchestrator — queries all configured APIs in parallel,
computes a unified risk score, and returns a structured dict.
"""
import asyncio
import base64
import httpx
from app.core.config import settings
from app.core.cache import cache_get, cache_set
from app.models.ioc import IoCType, Severity

# ── VirusTotal ───────────────────────────────────────────────────────────────

async def _vt(value: str, ioc_type: IoCType) -> dict | None:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    ep = {
        IoCType.IP: f"ip_addresses/{value}",
        IoCType.DOMAIN: f"domains/{value}",
        IoCType.URL: f"urls/{url_id}",
        IoCType.HASH_MD5: f"files/{value}",
        IoCType.HASH_SHA1: f"files/{value}",
        IoCType.HASH_SHA256: f"files/{value}",
    }.get(ioc_type)
    if not ep:
        return None
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            r = await c.get(f"https://www.virustotal.com/api/v3/{ep}", headers=headers)
            if r.status_code != 200:
                return None
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "tags": attrs.get("tags", []),
                "categories": attrs.get("categories", {}),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }
        except Exception:
            return None

# ── AbuseIPDB ────────────────────────────────────────────────────────────────

async def _abuse(value: str, ioc_type: IoCType) -> dict | None:
    if not settings.ABUSEIPDB_API_KEY or ioc_type != IoCType.IP:
        return None
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": True},
            )
            if r.status_code != 200:
                return None
            d = r.json().get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage_type": d.get("usageType"),
                "total_reports": d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "domain": d.get("domain"),
                "reports": [
                    {"categories": rep.get("categories", []),
                     "comment": rep.get("comment", "")[:300],
                     "reported_at": rep.get("reportedAt")}
                    for rep in d.get("reports", [])[:10]
                ],
            }
        except Exception:
            return None

# ── AlienVault OTX ───────────────────────────────────────────────────────────

def _extract_mitre_ttps(pulse_list: list) -> list[dict]:
    """
    Витягує унікальні ТЕХНІКИ MITRE ATT&CK з OTX-пульсів.
    Ігнорує абстрактні тактики (TAxxxx).
    """
    seen: set[str] = set()
    ttps: list[dict] = []

    for pulse in pulse_list:
        attack_ids = pulse.get("attack_ids", [])
        for ttp in attack_ids:
            tid = ttp.get("id", "").strip()
            
            # Якщо ідентифікатор порожній, дублюється або є ТАКТИКОЮ (починається з TA) — пропускаємо
            if not tid or tid in seen or tid.startswith("TA"):
                continue
                
            seen.add(tid)
            is_subtechnique = "." in tid

            ttps.append({
                "id": tid,
                "name": ttp.get("name") or ttp.get("display_name") or tid,
                "display_name": ttp.get("display_name") or ttp.get("name") or tid,
                "subtechnique": is_subtechnique,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                "pulse_name": pulse.get("name", ""),
            })

    # Спрощене сортування: звичайні техніки спочатку, підтехніки — наприкінці
    ttps.sort(key=lambda x: (x["subtechnique"], x["id"]))
    return ttps


async def _otx(value: str, ioc_type: IoCType) -> dict | None:
    headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY} if settings.ALIENVAULT_API_KEY else {}
    imap = {
        IoCType.IP:         ("IPv4",   ["general", "reputation", "geo", "malware", "url_list"]),
        IoCType.DOMAIN:     ("domain", ["general", "geo", "malware", "url_list", "whois"]),
        IoCType.URL:        ("url",    ["general"]),
        IoCType.HASH_MD5:   ("file",   ["general", "analysis"]),
        IoCType.HASH_SHA1:  ("file",   ["general", "analysis"]),
        IoCType.HASH_SHA256:("file",   ["general", "analysis"]),
    }
    mapping = imap.get(ioc_type)
    if not mapping:
        return None
    ind_type, sections = mapping

    result = {}
    async with httpx.AsyncClient(timeout=15) as c:
        tasks = [
            c.get(
                f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{value}/{s}",
                headers=headers,
            )
            for s in sections
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for s, resp in zip(sections, responses):
            if isinstance(resp, httpx.Response) and resp.status_code == 200:
                result[s] = resp.json()

    if not result:
        return None

    general    = result.get("general", {})
    pulse_info = general.get("pulse_info", {})
    pulses     = pulse_info.get("pulses", [])

    # Витягуємо повний список пульсів (перші 20, щоб не перевантажувати)
    # і збираємо MITRE TTPs
    mitre_ttps = _extract_mitre_ttps(pulses[:20])

    return {
        "pulse_count":     pulse_info.get("count", 0),
        "country":         general.get("country_name"),
        "city":            general.get("city"),
        "asn":             general.get("asn"),
        "reputation":      general.get("reputation", 0),
        "malware_samples": len(result.get("malware", {}).get("data", [])),
        "url_count":       result.get("url_list", {}).get("full_size", 0),
        "pulses": [
            {
                "name":        p.get("name"),
                "tags":        p.get("tags", []),
                "description": (p.get("description") or "")[:200],
                "created":     p.get("created"),
                "attack_ids":  p.get("attack_ids", []),
            }
            for p in pulses[:5]
        ],
        "mitre_ttps": mitre_ttps,
    }

# ── URLhaus ──────────────────────────────────────────────────────────────────

async def _urlhaus(value: str, ioc_type: IoCType) -> dict | None:
    if not settings.URLHAUS_ENABLED:
        return None
    if not settings.URLHAUS_API_KEY:
        return None
    if ioc_type not in (IoCType.URL, IoCType.DOMAIN, IoCType.IP, IoCType.HASH_MD5, IoCType.HASH_SHA256):
        return None
    base = "https://urlhaus-api.abuse.ch/v1"
    headers = {"Auth-Key": settings.URLHAUS_API_KEY}
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            if ioc_type == IoCType.URL:
                r = await c.post(f"{base}/url/", data={"url": value}, headers=headers)
            elif ioc_type in (IoCType.DOMAIN, IoCType.IP):
                r = await c.post(f"{base}/host/", data={"host": value}, headers=headers)
            else:
                key = "md5_hash" if ioc_type == IoCType.HASH_MD5 else "sha256_hash"
                r = await c.post(f"{base}/payload/", data={key: value}, headers=headers)
            if r.status_code != 200:
                return None
            d = r.json()
            if d.get("query_status") in ("no_results", "not_found"):
                return {"found": False}
            urls = d.get("urls", [])
            return {
                "found": True,
                "url_count":    len(urls),
                "urls_online":  sum(1 for u in urls if u.get("url_status") == "online"),
                "threat":       d.get("threat") or (urls[0].get("threat") if urls else None),
                "date_added":   d.get("date_added") or (urls[0].get("date_added") if urls else None),
                "tags":         list({t for u in urls for t in (u.get("tags") or [])}),
                "recent_urls": [
                    {"url": u.get("url"), "status": u.get("url_status"),
                     "threat": u.get("threat"), "date_added": u.get("date_added")}
                    for u in urls[:5]
                ],
            }
        except Exception:
            return None

# ── Shodan ───────────────────────────────────────────────────────────────────

async def _shodan(value: str, ioc_type: IoCType) -> dict | None:
    if not settings.SHODAN_API_KEY or ioc_type != IoCType.IP:
        return None
    async with httpx.AsyncClient(timeout=15) as c:
        try:
            r = await c.get(
                f"https://api.shodan.io/shodan/host/{value}",
                params={"key": settings.SHODAN_API_KEY},
            )
            if r.status_code != 200:
                return None
            d = r.json()
            ports = d.get("ports", [])
            vulns = d.get("vulns", {})
            return {
                "org":              d.get("org"),
                "isp":              d.get("isp"),
                "asn":              d.get("asn"),
                "country_name":     d.get("country_name"),
                "city":             d.get("city"),
                "os":               d.get("os"),
                "ports":            ports[:30],
                "open_ports_count": len(ports),
                "vuln_count":       len(vulns),
                "vulnerabilities":  list(vulns.keys())[:15],
                "hostnames":        d.get("hostnames", [])[:5],
                "tags":             d.get("tags", []),
                "last_update":      d.get("last_update"),
                "services": [
                    {"port": s.get("port"), "transport": s.get("transport"),
                     "product": s.get("product"), "version": s.get("version"),
                     "banner": (s.get("data") or "")[:200]}
                    for s in d.get("data", [])[:10]
                ],
            }
        except Exception:
            return None

# ── Risk score calculator ────────────────────────────────────────────────────

def compute_risk(vt, abuse, otx, urlhaus) -> tuple[float, Severity, bool | None]:
    scores = []

    # 1. Приводимо кожен сервіс до простої шкали 0-100
    if vt:
        # 5+ детекцій — це 100% загрози
        vt_score = min((vt.get("malicious", 0) * 20) + (vt.get("suspicious", 0) * 10), 100)
        scores.append(vt_score)

    if abuse:
        # Передаємо чистий скоринг AbuseIPDB (він уже від 0 до 100)
        scores.append(abuse.get("abuse_score", 0))

    if otx:
        # 10 пульсів — це 100% загрози
        otx_score = min(otx.get("pulse_count", 0) * 10, 100)
        scores.append(otx_score)

    if urlhaus and urlhaus.get("found"):
        # Якщо посилання онлайн — 100%, якщо мертве — 40%
        uh_score = 100 if urlhaus.get("urls_online", 0) > 0 else 40
        scores.append(uh_score)

    # Якщо взагалі жодне джерело не повернуло результат
    if not scores:
        return 0.0, Severity.UNKNOWN, None

    # 2. Брати максимум — це суть "Найгіршого сценарію" (Worst-case scenario)
    base_score = max(scores)

    # 3. Вагове згладжування (Бонус за консенсус джерел)
    # Якщо загрозу підтверджують КІЛЬКА джерел одночасно, ми трохи піднімаємо бал
    malicious_sources_count = sum(1 for s in scores if s >= 35)
    
    if malicious_sources_count > 1 and base_score < 100:
        # Додаємо по 5 балів за кожне додаткове джерело, що підтвердило загрозу
        base_score = min(base_score + (malicious_sources_count - 1) * 5, 100)

    # Округлення під інженерний стандарт
    final_score = round(base_score, 1)
    is_malicious = final_score >= 35.0

    # Стандартний мапінг категорій критичності
    if final_score >= 75:    sev = Severity.CRITICAL
    elif final_score >= 50:  sev = Severity.HIGH
    elif final_score >= 35:  sev = Severity.MEDIUM
    elif final_score > 0:    sev = Severity.LOW
    else:                    sev = Severity.UNKNOWN

    return final_score, sev, is_malicious

# ── Main entry point ─────────────────────────────────────────────────────────

async def enrich(value: str, ioc_type: IoCType) -> dict:
    cached = await cache_get("enrich", f"{ioc_type}:{value}")
    if cached:
        cached["from_cache"] = True
        return cached

    vt, abuse, otx, uh, shodan = await asyncio.gather(
        _vt(value, ioc_type),
        _abuse(value, ioc_type),
        _otx(value, ioc_type),
        _urlhaus(value, ioc_type),
        _shodan(value, ioc_type),
        return_exceptions=True,
    )

    def safe(x): return x if isinstance(x, dict) else None

    vt, abuse, otx, uh, shodan = map(safe, [vt, abuse, otx, uh, shodan])
    risk, sev, mal = compute_risk(vt, abuse, otx, uh)

    country = (
        (abuse or {}).get("country_code")
        or (otx   or {}).get("country")
        or (vt    or {}).get("country")
    )

    # Витягуємо MITRE TTPs з OTX
    mitre_ttps = (otx or {}).get("mitre_ttps", [])

    result = {
        "value": value, "ioc_type": ioc_type.value,
        "risk_score": risk, "severity": sev.value,
        "is_malicious": mal, "country": country,
        "virustotal":    vt,
        "abuseipdb":     abuse,
        "alienvault_otx": otx,
        "urlhaus":       uh,
        "shodan":        shodan,
        "mitre_ttps":    mitre_ttps,
        "from_cache":    False,
        "sources_ok": [k for k, v in {
            "VirusTotal": vt, "AbuseIPDB": abuse,
            "AlienVault OTX": otx, "URLhaus": uh,
            "Shodan": shodan
        }.items() if v],
    }

    await cache_set("enrich", f"{ioc_type}:{value}", result)
    return result