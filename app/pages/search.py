"""
IoC search & enrichment page — повний аналіз з усіма джерелами.
"""
from nicegui import ui

from app.core.detector import detect_type, normalize
from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC, SearchLog, Severity
from app.services.enrichment import enrich
from app.pages import theme
from datetime import datetime, timezone


# ── MITRE ATT&CK кольори тактик ──────────────────────────────────────────────

TACTIC_COLORS = {
    "TA0001": ("#dc2626", "Початковий доступ"),
    "TA0002": ("#ea580c", "Виконання"),
    "TA0003": ("#d97706", "Закріплення"),
    "TA0004": ("#ca8a04", "Підвищення привілеїв"),
    "TA0005": ("#65a30d", "Обхід захисту"),
    "TA0006": ("#16a34a", "Отримання облікових даних"),
    "TA0007": ("#0891b2", "Розвідка"),
    "TA0008": ("#2563eb", "Бічний рух"),
    "TA0009": ("#7c3aed", "Збір даних"),
    "TA0010": ("#db2777", "Ексфільтрація"),
    "TA0011": ("#e11d48", "Командування та управління"),
    "TA0040": ("#b45309", "Вплив"),
    "TA0042": ("#6d28d9", "Розвідка ресурсів"),
    "TA0043": ("#0e7490", "Збір інформації"),
}

TECHNIQUE_COLOR = "#3b82f6"


def _get_tactic_color(tid: str) -> str:
    return TACTIC_COLORS.get(tid, (TECHNIQUE_COLOR, ""))[0]


def _get_tactic_label(tid: str) -> str:
    return TACTIC_COLORS.get(tid, ("", tid))[1] or tid


async def _do_search(value: str, result_container) -> None:
    val = normalize(value)
    ioc_type = detect_type(val)
    if not ioc_type:
        ui.notify("Не вдалось визначити тип IoC. Введіть IP, домен, URL, хеш або email.", color="negative")
        return

    data = await enrich(val, ioc_type)

    async with AsyncSessionLocal() as db:
        existing = (await db.execute(
            __import__("sqlalchemy", fromlist=["select"]).select(IoC).where(IoC.value == val)
        )).scalar_one_or_none()
        if existing:
            existing.risk_score   = data["risk_score"]
            existing.severity     = Severity(data["severity"])
            existing.is_malicious = data["is_malicious"]
            existing.country      = data.get("country")
            existing.vt_data      = data.get("virustotal")
            existing.abuse_data   = data.get("abuseipdb")
            existing.otx_data     = data.get("alienvault_otx")
            existing.urlhaus_data = data.get("urlhaus")
            existing.shodan_data  = data.get("shodan")
            existing.mitre_ttps   = data.get("mitre_ttps", [])
            existing.last_seen    = datetime.now(timezone.utc)
            existing.search_count = (existing.search_count or 0) + 1
            ioc_obj = existing
        else:
            ioc_obj = IoC(
                value=val, ioc_type=ioc_type,
                severity=Severity(data["severity"]),
                risk_score=data["risk_score"],
                is_malicious=data["is_malicious"],
                country=data.get("country"),
                source="manual", tags=[],
                vt_data=data.get("virustotal"),
                abuse_data=data.get("abuseipdb"),
                otx_data=data.get("alienvault_otx"),
                urlhaus_data=data.get("urlhaus"),
                shodan_data=data.get("shodan"),
                mitre_ttps=data.get("mitre_ttps", []),
                search_count=1,
            )
            db.add(ioc_obj)
        db.add(SearchLog(query=val, ioc_type=ioc_type.value))
        await db.commit()
        await db.refresh(ioc_obj)

    data["ioc"] = {
        "value":        ioc_obj.value,
        "ioc_type":     ioc_obj.ioc_type.value if hasattr(ioc_obj.ioc_type, "value") else ioc_obj.ioc_type,
        "severity":     ioc_obj.severity.value if hasattr(ioc_obj.severity, "value") else ioc_obj.severity,
        "risk_score":   ioc_obj.risk_score,
        "is_malicious": ioc_obj.is_malicious,
        "country":      ioc_obj.country or "—",
        "source":       ioc_obj.source or "manual",
        "search_count": ioc_obj.search_count or 1,
        "first_seen":   ioc_obj.first_seen.strftime("%d.%m.%Y %H:%M") if ioc_obj.first_seen else "—",
        "last_seen":    ioc_obj.last_seen.strftime("%d.%m.%Y %H:%M")  if ioc_obj.last_seen  else "—",
    }

    result_container.clear()
    with result_container:
        _render_result(data)


def _kv(label: str, value: str):
    with ui.element("div").classes("kv-row"):
        ui.label(label).classes("kv-key")
        ui.html(str(value) if value else "—").classes("kv-val")


def _render_mitre(techniques: list[dict]):
    """Відображає список технік MITRE ATT&CK з посиланнями."""
    if not techniques:
        with ui.element("div").style(
            f"padding:24px;text-align:center;color:{theme.MUTED};"
            "background:rgba(255,255,255,0.02);border-radius:8px"
        ):
            ui.icon("security").style(f"font-size:2.5rem;color:{theme.MUTED};opacity:0.4")
            ui.label("Технік MITRE ATT&CK не знайдено").style("margin-top:8px;font-size:0.9rem")
            ui.label(
                "AlienVault OTX не повернув жодної техніки для цього IoC"
            ).style(f"font-size:0.75rem;color:{theme.MUTED};opacity:0.7;margin-top:4px")
        return

    with ui.element("div").classes("cti-card").style("width:100%"):
        with ui.row().style("align-items:center;justify-content:space-between;margin-bottom:16px"):
            ui.label("Виявлені техніки MITRE ATT&CK").classes("section-title").style("margin-bottom:0;border:none")
            ui.html(
                f'<span style="font-size:0.8rem;padding:3px 10px;'
                f'background:rgba(59,130,246,0.1);color:{theme.PRIMARY};'
                f'border:1px solid rgba(59,130,246,0.2);border-radius:6px">'
                f'{len(techniques)} технік</span>'
            )

        # Таблиця технік
        for t in techniques:
            is_sub = t.get("subtechnique", False)
            border_color = "rgba(139,92,246,0.3)" if is_sub else "rgba(59,130,246,0.25)"
            bg_color     = "rgba(139,92,246,0.05)" if is_sub else "rgba(59,130,246,0.05)"
            id_color     = "#a78bfa" if is_sub else theme.PRIMARY

            with ui.element("div").style(
                f"display:flex;align-items:center;justify-content:space-between;gap:12px;"
                f"padding:10px 14px;margin-bottom:6px;"
                f"background:{bg_color};border:1px solid {border_color};"
                f"border-radius:8px"
            ):
                with ui.row().style("align-items:center;gap:12px;flex:1;min-width:0"):
                    # ID бейдж
                    ui.html(
                        f'<span style="font-family:monospace;font-weight:700;font-size:0.88rem;'
                        f'color:{id_color};white-space:nowrap;flex-shrink:0">{t["id"]}</span>'
                    )
                    # Роздільник
                    ui.html(f'<span style="color:{theme.BORDER};flex-shrink:0">|</span>')
                    # Назва
                    name = t.get("name") or t["id"]
                    ui.label(name).style(
                        f"font-size:0.88rem;color:{theme.TEXT};overflow:hidden;"
                        "text-overflow:ellipsis;white-space:nowrap"
                    )
                    # Мітка підтехніки
                    if is_sub:
                        ui.html(
                            f'<span style="font-size:0.68rem;padding:1px 6px;'
                            f'background:rgba(139,92,246,0.15);color:#a78bfa;'
                            f'border:1px solid rgba(139,92,246,0.3);border-radius:3px;'
                            f'flex-shrink:0">sub-technique</span>'
                        )

                # Посилання
                ui.html(
                    f'<a href="{t["url"]}" target="_blank" style="'
                    f'font-size:0.78rem;padding:4px 10px;'
                    f'background:rgba(255,255,255,0.04);color:{theme.MUTED};'
                    f'border:1px solid {theme.BORDER};border-radius:6px;'
                    f'text-decoration:none;white-space:nowrap;flex-shrink:0;'
                    f'transition:color 0.15s" '
                    f'onmouseover="this.style.color=\'{theme.TEXT}\'" '
                    f'onmouseout="this.style.color=\'{theme.MUTED}\'">'
                    f'↗ MITRE ATT&CK</a>'
                )

def _render_result(data: dict):
    ioc        = data["ioc"]
    score      = ioc["risk_score"]
    color      = theme.risk_color(score)
    sources_ok = data.get("sources_ok", [])
    from_cache = data.get("from_cache", False)
    mitre_ttps = data.get("mitre_ttps", [])

    # ── Result header ──────────────────────────────────────────────────────
    with ui.element("div").classes("cti-card").style("margin-bottom:16px"):
        with ui.row().style("align-items:center;gap:20px;flex-wrap:wrap"):
            with ui.element("div").style(
                f"width:80px;height:80px;border-radius:50%;"
                f"border:4px solid {color};"
                f"display:flex;align-items:center;justify-content:center;flex-shrink:0"
            ):
                ui.html(f'<span style="font-size:1.4rem;font-weight:700;color:{color}">'
                        f'{score if score is not None else "?"}</span>')

            with ui.column().style("gap:6px;flex:1"):
                with ui.row().style("gap:8px;flex-wrap:wrap;align-items:center"):
                    ui.html(theme.type_badge_html(ioc["ioc_type"]))
                    sev = ioc["severity"] or "unknown"
                    ui.html(theme.sev_badge_html(sev))
                    if ioc["is_malicious"] is True:
                        ui.html('<span class="badge badge-critical">✕ Шкідливий</span>')
                    elif ioc["is_malicious"] is False:
                        ui.html('<span class="badge badge-low">✓ Чистий</span>')
                    if from_cache:
                        ui.html('<span class="badge badge-unknown">⚡ Кеш</span>')
                    # Бейдж MITRE ATT&CK якщо є TTPs
                    if mitre_ttps:
                        ui.html(
                            f'<span style="font-size:0.72rem;padding:2px 8px;'
                            f'background:rgba(220,38,38,0.12);color:#ef4444;'
                            f'border:1px solid rgba(220,38,38,0.3);border-radius:4px;'
                            f'font-weight:600">⚔ MITRE ATT&CK: {len(mitre_ttps)} TTP</span>'
                        )

                ui.label(ioc["value"]).classes("mono").style(
                    f"font-size:1rem;font-weight:600;color:{theme.TEXT};word-break:break-all"
                )

                with ui.row().style("gap:6px;flex-wrap:wrap"):
                    for src in sources_ok:
                        ui.html(f'<span style="font-size:0.75rem;padding:2px 7px;'
                                f'background:rgba(16,185,129,0.1);color:{theme.SUCCESS};'
                                f'border:1px solid rgba(16,185,129,0.3);border-radius:4px">✓ {src}</span>')

            with ui.column().style(f"text-align:right;flex-shrink:0;color:{theme.MUTED}"):
                ui.label("Перший запит").style("font-size:0.7rem;text-transform:uppercase")
                ui.label(ioc["first_seen"]).style("font-size:0.85rem;font-family:monospace")
                ui.label("Пошуків").style("font-size:0.7rem;text-transform:uppercase;margin-top:6px")
                ui.label(str(ioc["search_count"])).style(
                    f"font-size:1.8rem;font-weight:700;color:{theme.PRIMARY};font-family:monospace"
                )

    # ── Tabs ──────────────────────────────────────────────────────────────
    with ui.tabs().style(f"color:{theme.MUTED};border-bottom:1px solid {theme.BORDER}") as tabs:
        t_overview = ui.tab("overview", label="Огляд",          icon="grid_view")
        t_vt       = ui.tab("vt",       label="VirusTotal",     icon="bug_report")
        t_abuse    = ui.tab("abuse",    label="AbuseIPDB",      icon="warning")
        t_otx      = ui.tab("otx",      label="OTX",            icon="broadcast_on_home")
        t_mitre    = ui.tab("mitre",    label="MITRE ATT&CK",   icon="security")
        t_urlhaus  = ui.tab("urlhaus",  label="URLhaus",        icon="link")
        t_shodan   = ui.tab("shodan",   label="Shodan",         icon="dns")

    with ui.tab_panels(tabs, value="overview").style("background:transparent;padding:16px 0"):

        # ── Overview ───────────────────────────────────────────────────────
        with ui.tab_panel("overview"):
            with ui.grid(columns=2).style("gap:16px"):
                with ui.element("div").classes("cti-card"):
                    ui.label("Загальна інформація").classes("section-title")
                    with ui.grid(columns=2).style("gap:12px"):
                        _kv("Тип",       theme.type_badge_html(ioc["ioc_type"]))
                        _kv("Risk Score", f'<span style="color:{color};font-weight:700">{score}/100</span>')
                        _kv("Шкідливий",
                            '<span style="color:#ef4444">✕ Так</span>'  if ioc["is_malicious"] is True  else
                            '<span style="color:#10b981">✓ Ні</span>'   if ioc["is_malicious"] is False else "—")
                        _kv("Severity",  theme.sev_badge_html(ioc["severity"]))
                        _kv("Країна",    ioc["country"])
                        _kv("Джерело",   ioc["source"])
                        _kv("Перший запит",   ioc["first_seen"])
                        _kv("Останній запит", ioc["last_seen"])

                with ui.element("div").classes("cti-card"):
                    ui.label("Зведення по джерелах").classes("section-title")
                    vt  = data.get("virustotal")
                    ab  = data.get("abuseipdb")
                    otx = data.get("alienvault_otx")
                    uh  = data.get("urlhaus")
                    sh  = data.get("shodan")
                    with ui.grid(columns=2).style("gap:12px"):
                        _kv("VirusTotal",   f'<b>{vt["malicious"]}</b> виявлень' if vt else "—")
                        _kv("AbuseIPDB",    f'Confidence: <b>{ab["abuse_score"]}%</b>' if ab else "—")
                        _kv("OTX Pulses",   f'<b>{otx["pulse_count"]}</b> pulses' if otx else "—")
                        _kv("URLhaus",      f'<b>{uh["url_count"]}</b> URL' if uh and uh.get("found") else "—")
                        _kv("Shodan порти", f'<b>{sh["open_ports_count"]}</b>' if sh else "—")
                        _kv("CVE",
                            f'<b style="color:{theme.DANGER if sh and sh["vuln_count"]>0 else theme.SUCCESS}">'
                            f'{sh["vuln_count"]}</b>' if sh else "—")
                        _kv("MITRE TTP",
                            f'<span style="color:#ef4444;font-weight:700">⚔ {len(mitre_ttps)}</span>'
                            if mitre_ttps else
                            f'<span style="color:{theme.MUTED}">0</span>')

        # ── VirusTotal ─────────────────────────────────────────────────────
        with ui.tab_panel("vt"):
            vt = data.get("virustotal")
            if not vt:
                ui.label("Немає даних VirusTotal").style(f"color:{theme.MUTED}")
            else:
                with ui.grid(columns=4).style("gap:16px;margin-bottom:16px"):
                    for val_, label_, col_ in [
                        (vt.get("malicious",  0), "Шкідливих",   theme.DANGER),
                        (vt.get("suspicious", 0), "Підозрілих",  theme.WARNING),
                        (vt.get("harmless",   0), "Нешкідливих", theme.SUCCESS),
                        (vt.get("undetected", 0), "Не виявлено", theme.MUTED),
                    ]:
                        with ui.element("div").classes("cti-card").style("text-align:center"):
                            ui.html(f'<div style="font-size:2rem;font-weight:700;color:{col_}">{val_}</div>')
                            ui.label(label_).style(f"font-size:0.8rem;color:{theme.MUTED}")
                with ui.element("div").classes("cti-card"):
                    with ui.grid(columns=4).style("gap:12px"):
                        _kv("Репутація",  str(vt.get("reputation", "—")))
                        _kv("Країна",     vt.get("country") or "—")
                        _kv("AS власник", vt.get("as_owner") or "—")
                        _kv("Теги",       ", ".join(vt.get("tags", [])) or "—")

        # ── AbuseIPDB ──────────────────────────────────────────────────────
        with ui.tab_panel("abuse"):
            ab = data.get("abuseipdb")
            if not ab:
                ui.label("Дані AbuseIPDB доступні тільки для IP-адрес").style(f"color:{theme.MUTED}")
            else:
                s   = ab.get("abuse_score", 0)
                col = theme.risk_color(s)
                with ui.grid(columns=4).style("gap:16px;margin-bottom:16px"):
                    with ui.element("div").classes("cti-card").style("text-align:center"):
                        ui.html(f'<div style="font-size:2rem;font-weight:700;color:{col}">{s}%</div>')
                        ui.label("Confidence Score").style(f"font-size:0.8rem;color:{theme.MUTED}")
                    with ui.element("div").classes("cti-card").style("text-align:center"):
                        ui.html(f'<div style="font-size:2rem;font-weight:700;color:{theme.WARNING}">'
                                f'{ab.get("total_reports", 0)}</div>')
                        ui.label("Звітів").style(f"font-size:0.8rem;color:{theme.MUTED}")
                    with ui.element("div").classes("cti-card").style("text-align:center"):
                        ui.html(f'<div style="font-size:2rem;font-weight:700">{ab.get("distinct_users", 0)}</div>')
                        ui.label("Унікальних юзерів").style(f"font-size:0.8rem;color:{theme.MUTED}")
                    with ui.element("div").classes("cti-card").style("text-align:center"):
                        is_tor = ab.get("is_tor", False)
                        ui.html(f'<div style="font-size:2rem;font-weight:700;color:{"#ef4444" if is_tor else "#10b981"}">'
                                f'{"⚠" if is_tor else "✓"}</div>')
                        ui.label("TOR вузол").style(f"font-size:0.8rem;color:{theme.MUTED}")
                with ui.element("div").classes("cti-card").style("margin-bottom:12px"):
                    with ui.grid(columns=4).style("gap:12px"):
                        _kv("Країна",        ab.get("country_code") or "—")
                        _kv("ISP",           ab.get("isp") or "—")
                        _kv("Тип",           ab.get("usage_type") or "—")
                        _kv("Останній звіт", ab.get("last_reported_at") or "—")
                if ab.get("reports"):
                    with ui.element("div").classes("cti-card"):
                        ui.label("Останні звіти").classes("section-title")
                        cols = [
                            {"name": "reported_at", "label": "Дата",      "field": "reported_at", "align": "left"},
                            {"name": "categories",  "label": "Категорії", "field": "categories",  "align": "left"},
                            {"name": "comment",     "label": "Коментар",  "field": "comment",     "align": "left"},
                        ]
                        rows = [
                            {**r, "categories": ", ".join(str(c) for c in r.get("categories", []))}
                            for r in ab["reports"]
                        ]
                        ui.table(columns=cols, rows=rows, row_key="reported_at").style("width:100%")

        # ── AlienVault OTX ─────────────────────────────────────────────────
        with ui.tab_panel("otx"):
            otx = data.get("alienvault_otx")
            if not otx:
                ui.label("Немає даних OTX").style(f"color:{theme.MUTED}")
            else:
                with ui.element("div").classes("cti-card").style("margin-bottom:12px"):
                    with ui.grid(columns=3).style("gap:12px"):
                        _kv("Pulses",
                            f'<span style="font-size:1.4rem;font-weight:700;'
                            f'color:{theme.DANGER if otx.get("pulse_count",0)>0 else theme.SUCCESS}">'
                            f'{otx.get("pulse_count", 0)}</span>')
                        _kv("Зразки шкідл. ПЗ", str(otx.get("malware_samples", 0)))
                        _kv("Репутація",         str(otx.get("reputation", "—")))
                        _kv("Країна",   otx.get("country") or "—")
                        _kv("Місто",    otx.get("city") or "—")
                        _kv("ASN",      otx.get("asn") or "—")
                for pulse in otx.get("pulses", []):
                    with ui.element("div").style(
                        f"border-left:3px solid {theme.PRIMARY};padding:10px 14px;"
                        f"margin-bottom:10px;background:rgba(59,130,246,0.05);border-radius:0 6px 6px 0"
                    ):
                        ui.label(pulse.get("name") or "—").style("font-weight:600;font-size:0.9rem")
                        if pulse.get("description"):
                            ui.label(pulse["description"]).style(f"font-size:0.78rem;color:{theme.MUTED};margin-top:4px")
                        # attack_ids в пульсі
                        if pulse.get("attack_ids"):
                            with ui.row().style("gap:4px;flex-wrap:wrap;margin-top:6px"):
                                for aid in pulse["attack_ids"][:8]:
                                    tid = aid.get("id", "")
                                    tname = aid.get("name") or tid
                                    url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
                                    color_chip = "#dc2626" if tid.startswith("TA") else TECHNIQUE_COLOR
                                    with ui.element("a").props(f'href="{url}" target="_blank"').style(
                                        f"font-size:0.72rem;padding:2px 7px;"
                                        f"background:rgba(220,38,38,0.08);color:{color_chip};"
                                        f"border:1px solid {color_chip}40;border-radius:4px;"
                                        "text-decoration:none;font-family:monospace;font-weight:600"
                                    ):
                                        ui.label(f"⚔ {tid}")
                        if pulse.get("tags"):
                            with ui.row().style("gap:4px;flex-wrap:wrap;margin-top:4px"):
                                for tag in pulse["tags"][:10]:
                                    ui.html(f'<span style="font-size:10px;padding:1px 6px;'
                                            f'background:rgba(59,130,246,0.1);color:{theme.PRIMARY};'
                                            f'border:1px solid rgba(59,130,246,0.2);border-radius:3px">{tag}</span>')

        # ── MITRE ATT&CK ───────────────────────────────────────────────────
        with ui.tab_panel("mitre"):
            with ui.element("div").style("margin-bottom:16px"):
                with ui.row().style("align-items:center;gap:10px;margin-bottom:16px"):
                    ui.icon("security").style(f"font-size:1.4rem;color:#dc2626")
                    ui.label("MITRE ATT&CK").style("font-size:1.1rem;font-weight:700")
                    ui.html(
                        '<span style="font-size:0.72rem;padding:2px 8px;'
                        'background:rgba(220,38,38,0.1);color:#ef4444;'
                        'border:1px solid rgba(220,38,38,0.3);border-radius:4px">'
                        'via AlienVault OTX</span>'
                    )
            _render_mitre(mitre_ttps)

        # ── URLhaus ────────────────────────────────────────────────────────
        with ui.tab_panel("urlhaus"):
            uh = data.get("urlhaus")
            if not uh:
                ui.label("Немає даних URLhaus").style(f"color:{theme.MUTED}")
            elif not uh.get("found"):
                ui.html('<div style="padding:12px;background:rgba(16,185,129,0.1);'
                        f'color:{theme.SUCCESS};border:1px solid rgba(16,185,129,0.3);border-radius:8px">'
                        "✓ URLhaus: записів не знайдено</div>")
            else:
                with ui.grid(columns=4).style("gap:16px;margin-bottom:16px"):
                    for val_, label_, col_ in [
                        (uh.get("url_count",   0), "URL в базі",   theme.DANGER),
                        (uh.get("urls_online", 0), "Зараз онлайн", theme.DANGER if uh.get("urls_online",0)>0 else theme.SUCCESS),
                        (uh.get("threat") or "—",  "Тип загрози",  theme.TEXT),
                        (uh.get("date_added") or "—", "Перший раз", theme.MUTED),
                    ]:
                        with ui.element("div").classes("cti-card").style("text-align:center"):
                            ui.html(f'<div style="font-size:1.5rem;font-weight:700;color:{col_}">{val_}</div>')
                            ui.label(label_).style(f"font-size:0.8rem;color:{theme.MUTED}")
                if uh.get("recent_urls"):
                    with ui.element("div").classes("cti-card"):
                        ui.label("Останні URL").classes("section-title")
                        cols = [
                            {"name": "url",        "label": "URL",     "field": "url",        "align": "left"},
                            {"name": "status",     "label": "Статус",  "field": "status",     "align": "left"},
                            {"name": "threat",     "label": "Загроза", "field": "threat",     "align": "left"},
                            {"name": "date_added", "label": "Додано",  "field": "date_added", "align": "left"},
                        ]
                        ui.table(columns=cols, rows=uh["recent_urls"], row_key="url").style("width:100%")

        # ── Shodan ─────────────────────────────────────────────────────────
        with ui.tab_panel("shodan"):
            sh = data.get("shodan")
            if not sh:
                ui.label("Дані Shodan доступні тільки для IP-адрес").style(f"color:{theme.MUTED}")
            else:
                with ui.grid(columns=3).style("gap:16px;margin-bottom:16px"):
                    for val_, label_, col_ in [
                        (sh.get("open_ports_count", 0), "Відкритих портів",   theme.WARNING),
                        (sh.get("vuln_count", 0),       "CVE вразливостей",   theme.DANGER if sh.get("vuln_count",0)>0 else theme.SUCCESS),
                        (sh.get("os") or "—",           "Операційна система", theme.TEXT),
                    ]:
                        with ui.element("div").classes("cti-card").style("text-align:center"):
                            ui.html(f'<div style="font-size:1.8rem;font-weight:700;color:{col_}">{val_}</div>')
                            ui.label(label_).style(f"font-size:0.8rem;color:{theme.MUTED}")
                with ui.element("div").classes("cti-card").style("margin-bottom:12px"):
                    with ui.grid(columns=4).style("gap:12px"):
                        _kv("Організація",     sh.get("org") or "—")
                        _kv("ISP",             sh.get("isp") or "—")
                        _kv("ASN",             sh.get("asn") or "—")
                        _kv("Останнє оновлення", sh.get("last_update") or "—")
                if sh.get("ports"):
                    with ui.row().style("flex-wrap:wrap;gap:6px;margin-bottom:12px"):
                        ui.label("Порти:").style(f"color:{theme.MUTED};font-size:0.8rem;align-self:center")
                        for p in sh["ports"]:
                            ui.html(f'<span style="font-size:0.75rem;padding:2px 7px;'
                                    f'background:rgba(59,130,246,0.1);color:{theme.PRIMARY};'
                                    f'border:1px solid rgba(59,130,246,0.2);border-radius:4px">{p}</span>')
                if sh.get("vulnerabilities"):
                    with ui.row().style("flex-wrap:wrap;gap:6px;margin-bottom:12px"):
                        ui.label("CVE:").style(f"color:{theme.MUTED};font-size:0.8rem;align-self:center")
                        for v in sh["vulnerabilities"]:
                            ui.html(f'<span style="font-size:0.75rem;padding:2px 7px;'
                                    f'background:rgba(239,68,68,0.1);color:{theme.DANGER};'
                                    f'border:1px solid rgba(239,68,68,0.2);border-radius:4px">{v}</span>')
                if sh.get("services"):
                    with ui.element("div").classes("cti-card"):
                        ui.label("Сервіси").classes("section-title")
                        cols = [
                            {"name": "port",      "label": "Порт",     "field": "port",      "align": "left"},
                            {"name": "transport", "label": "Протокол", "field": "transport", "align": "left"},
                            {"name": "product",   "label": "Продукт",  "field": "product",   "align": "left"},
                            {"name": "version",   "label": "Версія",   "field": "version",   "align": "left"},
                        ]
                        ui.table(columns=cols, rows=sh["services"], row_key="port").style("width:100%")


def page():
    @ui.page("/search")
    async def search():
        with theme.layout("Аналіз IoC", "/search"):

            with ui.element("div").classes("cti-card").style(
                "text-align:center;padding:28px 32px;margin-bottom:20px;"
                "background:linear-gradient(135deg,#1a2744 0%,#0f172a 100%)"
            ):
                ui.icon("shield_moon").style(f"font-size:2rem;color:{theme.PRIMARY}")
                ui.label("Репутаційний аналіз загроз").style(
                    f"font-size:1.3rem;font-weight:700;margin:8px 0 4px"
                )
                ui.label(
                    "Введіть IP, домен, URL, MD5/SHA1/SHA256 хеш або email"
                ).style(f"color:{theme.MUTED};font-size:0.88rem;margin-bottom:20px")

                with ui.row().style("justify-content:center;gap:0;max-width:680px;margin:0 auto"):
                    q_input = ui.input(
                        placeholder="8.8.8.8  /  evil.com  /  https://...  /  d41d8cd98f00b204..."
                    ).props("outlined dense dark").style(
                        f"flex:1;background:rgba(255,255,255,0.05);"
                        f"border:1px solid rgba(255,255,255,0.12);"
                        f"border-right:none;border-radius:8px 0 0 8px;padding:10px 16px;"
                        f"color:{theme.TEXT};font-family:monospace;font-size:0.95rem"
                    )

                    async def on_search():
                        q = q_input.value.strip()
                        if not q:
                            return
                        btn.props("loading")
                        await _do_search(q, result_area)
                        btn.props(remove="loading")

                    q_input.on("keydown.enter", on_search)
                    btn = ui.button("Аналізувати", icon="search", on_click=on_search).style(
                        "border-radius:0 8px 8px 0"
                    ).props("color=primary unelevated")

            # ← result_area ПОЗА карткою пошуку
            result_area = ui.element("div").style("width:100%")