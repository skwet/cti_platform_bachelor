"""
Сторінка пошуку та аналізу IoC.
"""
from datetime import datetime, timezone
from nicegui import ui

from app.core.detector import detect_type, normalize
from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC, SearchLog, Severity
from app.services.enrichment import enrich
from app.pages import theme


async def _do_search(value: str, container) -> None:
    val = normalize(value)
    ioc_type = detect_type(val)
    if not ioc_type:
        ui.notify("Невідомий тип IoC. Введіть IP, домен, URL, хеш або email.", color="negative")
        return

    data = await enrich(val, ioc_type)

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        existing = (await db.execute(
            select(IoC).where(IoC.value == val)
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

    ioc = {
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

    container.clear()
    with container:
        _render_result(ioc, data)


def _row(label: str, value: str):
    """Проста пара ключ–значення."""
    with ui.row().style("gap:8px; align-items:baseline; margin-bottom:4px"):
        ui.label(label).style(f"font-size:0.75rem; color:{theme.MUTED}; min-width:120px")
        ui.html(str(value) if value else "—").style("font-size:0.88rem")


def _render_result(ioc: dict, data: dict):
    score = ioc["risk_score"]
    color = theme.risk_color(score)
    mitre = data.get("mitre_ttps", [])

    # ── Заголовок результату ──────────────────────────────────────────────────
    with ui.element("div").classes("card"):
        with ui.row().style("gap:16px; align-items:center; flex-wrap:wrap"):
            # Круг з score
            ui.html(
                f'<div style="width:72px;height:72px;border-radius:50%;border:3px solid {color};'
                f'display:flex;align-items:center;justify-content:center;'
                f'font-size:1.3rem;font-weight:700;color:{color};flex-shrink:0">'
                f'{score if score is not None else "?"}</div>'
            )
            with ui.column().style("gap:4px"):
                with ui.row().style("gap:6px; flex-wrap:wrap"):
                    ui.html(theme.type_badge(ioc["ioc_type"]))
                    ui.html(theme.sev_badge(ioc["severity"]))
                    if ioc["is_malicious"] is True:
                        ui.html('<span class="badge badge-critical">✕ Шкідливий</span>')
                    elif ioc["is_malicious"] is False:
                        ui.html('<span class="badge badge-low">✓ Чистий</span>')
                ui.label(ioc["value"]).style(
                    f"font-family:monospace; font-size:0.95rem; color:{theme.TEXT}; word-break:break-all"
                )

    # ── Вкладки ───────────────────────────────────────────────────────────────
    with ui.tabs().style(f"color:{theme.MUTED}; margin-bottom:16px") as tabs:
        t_info   = ui.tab("info",    label="Огляд",       icon="info")
        t_vt     = ui.tab("vt",      label="VirusTotal",  icon="bug_report")
        t_abuse  = ui.tab("abuse",   label="AbuseIPDB",   icon="warning")
        t_otx    = ui.tab("otx",     label="OTX",         icon="rss_feed")
        t_mitre  = ui.tab("mitre",   label="MITRE",       icon="security")
        t_shodan = ui.tab("shodan",  label="Shodan",      icon="dns")

    with ui.tab_panels(tabs, value="info").style("background:transparent"):

        # ── Огляд ────────────────────────────────────────────────────────────
        with ui.tab_panel("info"):
            with ui.element("div").classes("card"):
                _row("Тип",           theme.type_badge(ioc["ioc_type"]))
                _row("Risk Score",    f'<span style="color:{color};font-weight:700">{score}/100</span>')
                _row("Severity",      theme.sev_badge(ioc["severity"]))
                _row("Шкідливий",
                     '<span style="color:#ef4444">Так</span>' if ioc["is_malicious"] is True
                     else '<span style="color:#10b981">Ні</span>' if ioc["is_malicious"] is False
                     else "—")
                _row("Країна",        ioc["country"])
                _row("Джерело",       ioc["source"])
                _row("Перший запит",  ioc["first_seen"])
                _row("Останній",      ioc["last_seen"])
                _row("Кількість пошуків", str(ioc["search_count"]))

                # Короткий підсумок по джерелах
                vt  = data.get("virustotal")
                ab  = data.get("abuseipdb")
                otx = data.get("alienvault_otx")
                sh  = data.get("shodan")
                ui.separator().style("margin:12px 0")
                if vt:  _row("VirusTotal",  f'{vt["malicious"]} виявлень')
                if ab:  _row("AbuseIPDB",   f'Score: {ab["abuse_score"]}%')
                if otx: _row("OTX Pulses",  f'{otx["pulse_count"]} pulses')
                if sh:  _row("Shodan",      f'{sh["open_ports_count"]} відкритих портів')
                if mitre: _row("MITRE TTP", f'{len(mitre)} технік')

        # ── VirusTotal ────────────────────────────────────────────────────────
        with ui.tab_panel("vt"):
            vt = data.get("virustotal")
            if not vt:
                ui.label("Немає даних VirusTotal").style(f"color:{theme.MUTED}")
            else:
                with ui.element("div").classes("card"):
                    with ui.grid(columns=4).style("gap:12px; margin-bottom:16px"):
                        for label, val_, col_ in [
                            ("Шкідливих",   vt.get("malicious",  0), theme.DANGER),
                            ("Підозрілих",  vt.get("suspicious", 0), theme.WARNING),
                            ("Чистих",      vt.get("harmless",   0), theme.SUCCESS),
                            ("Не виявлено", vt.get("undetected", 0), theme.MUTED),
                        ]:
                            with ui.element("div").style("text-align:center"):
                                ui.label(str(val_)).style(
                                    f"font-size:1.8rem; font-weight:700; color:{col_}"
                                )
                                ui.label(label).style(f"font-size:0.8rem; color:{theme.MUTED}")
                    ui.separator().style("margin:8px 0")
                    _row("Репутація",  str(vt.get("reputation", "—")))
                    _row("Країна",     vt.get("country") or "—")
                    _row("AS власник", vt.get("as_owner") or "—")

        # ── AbuseIPDB ─────────────────────────────────────────────────────────
        with ui.tab_panel("abuse"):
            ab = data.get("abuseipdb")
            if not ab:
                ui.label("Дані AbuseIPDB доступні тільки для IP-адрес").style(f"color:{theme.MUTED}")
            else:
                with ui.element("div").classes("card"):
                    _row("Confidence Score", f'{ab.get("abuse_score", 0)}%')
                    _row("Звітів",           str(ab.get("total_reports", 0)))
                    _row("Унікальних юзерів",str(ab.get("distinct_users", 0)))
                    _row("TOR вузол",        "Так" if ab.get("is_tor") else "Ні")
                    _row("Країна",           ab.get("country_code") or "—")
                    _row("ISP",              ab.get("isp") or "—")
                    _row("Тип",              ab.get("usage_type") or "—")
                    _row("Останній звіт",    ab.get("last_reported_at") or "—")

                if ab.get("reports"):
                    with ui.element("div").classes("card"):
                        ui.label("Останні звіти").style(
                            f"font-weight:600; margin-bottom:8px; display:block"
                        )
                        cols = [
                            {"name": "reported_at", "label": "Дата",      "field": "reported_at", "align": "left"},
                            {"name": "categories",  "label": "Категорії", "field": "categories",  "align": "left"},
                            {"name": "comment",     "label": "Коментар",  "field": "comment",     "align": "left"},
                        ]
                        rows = [
                            {**r, "categories": ", ".join(str(c) for c in r.get("categories", []))}
                            for r in ab["reports"]
                        ]
                        ui.table(columns=cols, rows=rows, row_key="reported_at").classes("w-full")

        # ── OTX ───────────────────────────────────────────────────────────────
        with ui.tab_panel("otx"):
            otx = data.get("alienvault_otx")
            if not otx:
                ui.label("Немає даних OTX").style(f"color:{theme.MUTED}")
            else:
                with ui.element("div").classes("card"):
                    _row("Pulses",              str(otx.get("pulse_count", 0)))
                    _row("Зразки шкідл. ПЗ",   str(otx.get("malware_samples", 0)))
                    _row("Репутація",           str(otx.get("reputation", "—")))
                    _row("Країна",              otx.get("country") or "—")
                    _row("Місто",               otx.get("city") or "—")
                    _row("ASN",                 otx.get("asn") or "—")

                for pulse in otx.get("pulses", []):
                    with ui.element("div").style(
                        f"border-left:3px solid {theme.PRIMARY}; padding:10px 14px; "
                        f"margin-bottom:8px; background:rgba(59,130,246,0.05); border-radius:0 6px 6px 0"
                    ):
                        ui.label(pulse.get("name") or "—").style("font-weight:600; font-size:0.9rem")
                        if pulse.get("description"):
                            ui.label(pulse["description"]).style(
                                f"font-size:0.78rem; color:{theme.MUTED}; margin-top:4px"
                            )
                        if pulse.get("tags"):
                            with ui.row().style("gap:4px; flex-wrap:wrap; margin-top:6px"):
                                for tag in pulse["tags"][:8]:
                                    ui.html(
                                        f'<span style="font-size:0.72rem;padding:1px 6px;'
                                        f'background:rgba(59,130,246,0.1);color:{theme.PRIMARY};'
                                        f'border:1px solid rgba(59,130,246,0.2);border-radius:3px">{tag}</span>'
                                    )

        # ── MITRE ATT&CK ──────────────────────────────────────────────────────
        with ui.tab_panel("mitre"):
            if not mitre:
                ui.label("Технік MITRE ATT&CK не знайдено для цього IoC").style(f"color:{theme.MUTED}")
            else:
                ui.label(f"Знайдено {len(mitre)} технік (джерело: OTX)").style(
                    f"color:{theme.MUTED}; font-size:0.85rem; margin-bottom:12px; display:block"
                )
                for t in mitre:
                    tid  = t.get("id", "")
                    name = t.get("name") or tid
                    url  = t.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}")
                    is_sub = t.get("subtechnique", False)
                    color_chip = "#a78bfa" if is_sub else theme.PRIMARY
                    with ui.row().style(
                        f"gap:12px; align-items:center; padding:8px 12px; margin-bottom:6px; "
                        f"background:rgba(59,130,246,0.05); border-radius:6px; "
                        f"border:1px solid rgba(59,130,246,0.15)"
                    ):
                        ui.label(tid).style(
                            f"font-family:monospace; font-weight:700; color:{color_chip}; min-width:80px"
                        )
                        ui.label(name).style(f"color:{theme.TEXT}; font-size:0.88rem; flex:1")
                        ui.html(
                            f'<a href="{url}" target="_blank" style="font-size:0.78rem; '
                            f'color:{theme.MUTED}; text-decoration:none">↗ MITRE</a>'
                        )

        # ── Shodan ────────────────────────────────────────────────────────────
        with ui.tab_panel("shodan"):
            sh = data.get("shodan")
            if not sh:
                ui.label("Дані Shodan доступні тільки для IP-адрес").style(f"color:{theme.MUTED}")
            else:
                with ui.element("div").classes("card"):
                    _row("Відкритих портів",   str(sh.get("open_ports_count", 0)))
                    _row("CVE вразливостей",   str(sh.get("vuln_count", 0)))
                    _row("ОС",                 sh.get("os") or "—")
                    _row("Організація",        sh.get("org") or "—")
                    _row("ISP",                sh.get("isp") or "—")
                    _row("ASN",                sh.get("asn") or "—")
                    _row("Оновлено",           sh.get("last_update") or "—")

                if sh.get("ports"):
                    with ui.row().style("gap:6px; flex-wrap:wrap; margin-top:8px"):
                        ui.label("Порти:").style(f"color:{theme.MUTED}; font-size:0.8rem; align-self:center")
                        for p in sh["ports"]:
                            ui.html(
                                f'<span style="font-size:0.75rem;padding:2px 6px;'
                                f'background:rgba(59,130,246,0.1);color:{theme.PRIMARY};'
                                f'border-radius:4px">{p}</span>'
                            )

                if sh.get("vulnerabilities"):
                    with ui.row().style("gap:6px; flex-wrap:wrap; margin-top:8px"):
                        ui.label("CVE:").style(f"color:{theme.MUTED}; font-size:0.8rem; align-self:center")
                        for v in sh["vulnerabilities"]:
                            ui.html(
                                f'<span style="font-size:0.75rem;padding:2px 6px;'
                                f'background:rgba(239,68,68,0.1);color:{theme.DANGER};'
                                f'border-radius:4px">{v}</span>'
                            )

                if sh.get("services"):
                    ui.label("Сервіси").style(
                        f"font-weight:600; margin:12px 0 8px; display:block"
                    )
                    cols = [
                        {"name": "port",      "label": "Порт",     "field": "port",      "align": "left"},
                        {"name": "transport", "label": "Протокол", "field": "transport", "align": "left"},
                        {"name": "product",   "label": "Продукт",  "field": "product",   "align": "left"},
                        {"name": "version",   "label": "Версія",   "field": "version",   "align": "left"},
                    ]
                    ui.table(columns=cols, rows=sh["services"], row_key="port").classes("w-full")


def page():
    @ui.page("/search")
    async def search():
        with theme.layout("Аналіз IoC", "/search"):

            with ui.element("div").classes("card").style("text-align:center; margin-bottom:16px"):
                ui.label("Репутаційний аналіз загроз").style(
                    "font-size:1.1rem; font-weight:700; margin-bottom:8px; display:block"
                )
                ui.label("Введіть IP, домен, URL, MD5/SHA1/SHA256 або email").style(
                    f"color:{theme.MUTED}; font-size:0.88rem; margin-bottom:16px; display:block"
                )
                with ui.row().style("justify-content:center; gap:8px"):
                    q_input = ui.input(
                        placeholder="8.8.8.8 / evil.com / https://... / d41d8cd98f00b204..."
                    ).props("outlined dense dark").style("width:500px; font-family:monospace")

                    async def on_search():
                        q = q_input.value.strip()
                        if not q:
                            return
                        btn.props("loading")
                        await _do_search(q, result_area)
                        btn.props(remove="loading")

                    q_input.on("keydown.enter", on_search)
                    btn = ui.button("Аналізувати", icon="search", on_click=on_search).props(
                        "color=primary unelevated"
                    )

            result_area = ui.element("div").style("width:100%")
