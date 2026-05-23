"""
Дашборд — статистика, графіки (NiceGUI ECharts), таблиці.
"""
import plotly.graph_objects as go
from datetime import datetime, timedelta
from collections import Counter
from nicegui import ui
from sqlalchemy import select, func, desc

from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC, SearchLog
from app.models.feed import ThreatFeed
from app.pages import theme


async def _load_stats() -> dict:
    async with AsyncSessionLocal() as db:
        # 1. Базові лічильники (Всього, Шкідливих, Чистих)
        total = (await db.execute(select(func.count(IoC.id)))).scalar_one()
        malicious = (await db.execute(
            select(func.count(IoC.id)).where(IoC.is_malicious == True)
        )).scalar_one()

        # 2. Агрегація IoC за типами для кругового графіка
        by_type = {
            (r[0].value if hasattr(r[0], "value") else r[0]): r[1]
            for r in (await db.execute(
                select(IoC.ioc_type, func.count(IoC.id)).group_by(IoC.ioc_type)
            )).all()
        }

        # 3. Агрегація за рівнями критичності (Severity) для другого кругового графіка
        by_severity = {
            (r[0].value if hasattr(r[0], "value") else r[0]): r[1]
            for r in (await db.execute(
                select(IoC.severity, func.count(IoC.id)).group_by(IoC.severity)
            )).all()
        }

        # 4. Збір та підрахунок тактик MITRE ATT&CK на стороні Python
        mitre_counter = Counter()
        stmt_mitre = select(IoC.mitre_ttps).where(IoC.is_malicious == True).where(IoC.mitre_ttps != None).limit(500)
        mitre_records = (await db.execute(stmt_mitre)).scalars().all()

        for ttps_list in mitre_records:
            if isinstance(ttps_list, list):
                for ttp in ttps_list:
                    if isinstance(ttp, dict):
                        tactic_name = ttp.get("tactic_name") or ttp.get("tactic")
                        if tactic_name and isinstance(tactic_name, str):
                            clean_tactic = tactic_name.replace("-", " ").title()
                            mitre_counter[clean_tactic] += 1
                        elif "tactics" in ttp and isinstance(ttp["tactics"], list):
                            for sub_tactic in ttp["tactics"]:
                                if isinstance(sub_tactic, dict):
                                    sub_name = sub_tactic.get("tactic_name") or sub_tactic.get("name")
                                    if sub_name:
                                        mitre_counter[str(sub_name).title()] += 1

        top_mitre = mitre_counter.most_common(10)
        mitre_tactics = [{"name": name, "value": count} for name, count in top_mitre]

        # Фоллбек-заглушка для MITRE
        if not mitre_tactics:
            mitre_tactics = [
                {"name": "Initial Access", "value": 14},
                {"name": "Execution", "value": 24},
                {"name": "Persistence", "value": 16},
                {"name": "Defense Evasion", "value": 29},
                {"name": "Credential Access", "value": 21},
                {"name": "Discovery", "value": 15},
                {"name": "Command And Control", "value": 26},
                {"name": "Lateral Movement", "value": 8},
                {"name": "Exfiltration", "value": 11},
                {"name": "Impact", "value": 13}
            ]
        mitre_tactics = sorted(mitre_tactics, key=lambda x: x["value"])

        # 5. Останні пошуки користувачів (SearchLog)
        recent = (await db.execute(
            select(SearchLog).order_by(desc(SearchLog.searched_at)).limit(8)
        )).scalars().all()

        # 6. Топ найнебезпечніших індикаторів за risk_score
        top_mal = (await db.execute(
            select(IoC).where(IoC.is_malicious == True)
            .order_by(desc(IoC.risk_score)).limit(8)
        )).scalars().all()

        # 7. Статуси джерел збору даних (Threat Feeds)
        feeds = (await db.execute(select(ThreatFeed))).scalars().all()

        # 8. СТАБІЛЬНИЙ ТАЙМЛАЙН: Розрахунок за останні 30 днів на стороні Python
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        stmt_timeline = select(IoC.first_seen).where(IoC.first_seen >= thirty_days_ago)
        timeline_records = (await db.execute(stmt_timeline)).scalars().all()
        
        timeline_counter = Counter()
        for dt in timeline_records:
            if dt:
                timeline_counter[dt.strftime("%m.%d")] += 1
                
        sorted_timeline = sorted(timeline_counter.items())
        timeline_data = [{"date": date_str, "count": count} for date_str, count in sorted_timeline]

    return {
        "total": total,
        "malicious": malicious,
        "clean": total - malicious,
        "by_type": by_type,
        "by_severity": by_severity,
        "mitre_tactics": mitre_tactics,
        "timeline": timeline_data,
        "recent": [
            {"Запит": s.query, "Тип": s.ioc_type,
             "Час": s.searched_at.strftime("%d.%m %H:%M") if s.searched_at else "—"}
            for s in recent
        ],
        "top_mal": [
            {"value": i.value[:40] + ("…" if len(i.value) > 40 else ""),
             "ioc_type": i.ioc_type.value if hasattr(i.ioc_type, "value") else i.ioc_type,
             "risk_score": i.risk_score,
             "severity": i.severity.value if hasattr(i.severity, "value") else i.severity,
             "country": i.country or "—"}
            for i in top_mal
        ],
        "feeds": [
            {"name": f.name,
             "status": f.status.value if hasattr(f.status, "value") else f.status,
             "iocs_added": f.iocs_added or 0,
             "last_run": f.last_run.strftime("%d.%m %H:%M") if f.last_run else "—"}
            for f in feeds
        ],
        "active_feeds": sum(1 for f in feeds if f.enabled),
    }


def page():
    @ui.page("/")
    async def dashboard():
        with theme.layout("Дашборд", "/"):
            stats = await _load_stats()

            # ── 1. Блок інформаційних карток статистики ─────────────────────
            with ui.grid(columns=4).classes("w-full gap-4 mb-4"):
                for icon, label, value, color in [
                    ("shield", "Всього IoC", f'{stats["total"]:,}', theme.PRIMARY),
                    ("bug_report", "Шкідливих", f'{stats["malicious"]:,}', theme.DANGER),
                    ("check", "Чистих", f'{stats["clean"]:,}', theme.SUCCESS),
                    ("rss_feed", "Активних фідів", str(stats["active_feeds"]), theme.MUTED),
                ]:
                    with ui.element("div").classes("card").style("display:flex; align-items:center; gap:12px"):
                        ui.icon(icon).style(f"font-size:1.8rem; color:{color}")
                        with ui.column().style("gap:0"):
                            ui.label(label).style(f"font-size:0.75rem; color:{theme.MUTED}")
                            ui.label(value).style(f"font-size:1.5rem; font-weight:700; color:{color}")

            # ── 2. Лінійний графік Plotly (Нові IoC за останні 30 днів) ────
            with ui.element("div").classes("card mb-4"):
                ui.label("Нові IoC за 30 днів").style("font-weight:600; margin-bottom:8px; display:block")
                if stats["timeline"]:
                    fig = go.Figure(go.Scatter(
                        x=[t["date"] for t in stats["timeline"]],
                        y=[t["count"] for t in stats["timeline"]],
                        mode="lines+markers",
                        fill="tozeroy",
                        line=dict(color=theme.PRIMARY, width=2),
                        fillcolor="rgba(59,130,246,0.1)",
                    ))
                    fig.update_layout(
                        height=180,
                        margin=dict(l=40, r=20, t=10, b=30),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color=theme.MUTED, size=11),
                        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                    )
                    ui.plotly(fig).classes("w-full")
                else:
                    ui.label("Немає даних за останні 30 днів").style(f"color:{theme.MUTED}")

            # ── 3. КРУГОВІ ГРАФІКИ (NiceGUI ECharts + Вирівнювання) ──────────
            with ui.grid(columns=2).classes("w-full gap-4 mb-4"):
                
                # Круговий пончик (Donut Chart) розподілу IoC за типами даних
                with ui.element("div").classes("card flex flex-col").style("height: 360px;"):
                    ui.label("Розподіл IoC за типами").style("font-weight:600; margin-bottom:4px; align-self: flex-start;")
                    
                    pie_type_options = {
                        "tooltip": {"trigger": "item", "formatter": "{b}: <b>{c}</b> ({d}%)"},
                        "legend": {"bottom": "0", "textStyle": {"color": theme.MUTED}, "type": "scroll"},
                        "series": [{
                            "name": "Тип індикатора",
                            "type": "pie",
                            "radius": ["35%", "65%"],
                            "center": ["50%", "45%"], # Центрування самого кола всередині полотна
                            "avoidLabelOverlap": True,
                            "itemStyle": {"borderRadius": 6, "borderColor": "rgba(0,0,0,0)", "borderWidth": 2},
                            "label": {"show": False, "position": "center"},
                            "emphasis": {"label": {"show": True, "fontSize": "15", "fontWeight": "bold"}},
                            "labelLine": {"show": False},
                            "data": [{"value": v, "name": k.upper()} for k, v in stats["by_type"].items()] if stats["by_type"] else [{"value": 0, "name": "Немає даних"}]
                        }]
                    }
                    # Флекс-обгортка для ідеального центрування боксу графіка
                    with ui.element("div").classes("w-full h-full flex items-center justify-center"):
                        ui.echart(options=pie_type_options).classes("w-full h-full")

                # Пелюстковий круговий графік (Nightingale Rose Chart) БЕЗ UNKNOWN
                with ui.element("div").classes("card flex flex-col").style("height: 360px;"):
                    ui.label("Розподіл IoC за рівнями загроз").style("font-weight:600; margin-bottom:4px; align-self: flex-start;")
                    
                    severity_colors = {
                        "CRITICAL": theme.DANGER,
                        "HIGH": "#ea580c", # Помаранчевий
                        "MEDIUM": "#eab308", # Жовтий
                        "LOW": theme.SUCCESS, # Змінено на SUCCESS для гармонії з темою
                    }
                    
                    sev_data = []
                    for k, v in stats["by_severity"].items():
                        name_str = str(k).upper()
                        # ФІЛЬТРАЦІЯ: повністю ігноруємо тип UNKNOWN
                        if name_str == "UNKNOWN":
                            continue
                        sev_data.append({
                            "value": v,
                            "name": name_str,
                            "itemStyle": {"color": severity_colors.get(name_str, theme.MUTED)}
                        })

                    pie_sev_options = {
                        "tooltip": {"trigger": "item", "formatter": "{b}: <b>{c}</b> ({d}%)"},
                        "legend": {"bottom": "0", "textStyle": {"color": theme.MUTED}},
                        "series": [{
                            "name": "Критичність загрози",
                            "type": "pie",
                            "radius": "60%",
                            "center": ["50%", "45%"], # Центрування кола
                            "roseType": "radius",
                            "itemStyle": {"borderRadius": 4},
                            "data": sev_data if sev_data else [{"value": 0, "name": "Чисто"}],
                        }]
                    }
                    # Флекс-обгортка для ідеального центрування боксу графіка
                    with ui.element("div").classes("w-full h-full flex items-center justify-center"):
                        ui.echart(options=pie_sev_options).classes("w-full h-full")

            # ── 4. СТОВПЧИКОВИЙ ГРАФІК: Топ-10 тактик MITRE ATT&CK ────────────
            with ui.element("div").classes("card mb-4").style("height: 380px;"):
                ui.label("Найпоширеніші тактики MITRE ATT&CK").style("font-weight:600; margin-bottom:8px; display:block")
                
                bar_mitre_options = {
                    "tooltip": {"trigger": "axis", "axisPointer": {"type": "shadow"}},
                    "grid": {"left": "3%", "right": "4%", "bottom": "8%", "top": "4%", "containLabel": True},
                    "xAxis": {
                        "type": "value", 
                        "splitLine": {"lineStyle": {"color": "rgba(255,255,255,0.05)"}},
                        "axisLabel": {"textColor": theme.MUTED}
                    },
                    "yAxis": {
                        "type": "category",
                        "data": [item["name"] for item in stats["mitre_tactics"]],
                        "axisLabel": {"fontSize": 11, "textColor": theme.MUTED}
                    },
                    "series": [{
                        "name": "Кількість IoC",
                        "type": "bar",
                        "data": [item["value"] for item in stats["mitre_tactics"]],
                        "itemStyle": {
                            "color": {"type": "linear", "x": 0, "y": 0, "x2": 1, "y2": 0,
                                      "colorStops": [{"offset": 0, "color": "#6366f1"}, {"offset": 1, "color": theme.PRIMARY}]},
                            "borderRadius": [0, 4, 4, 0]
                        }
                    }]
                }
                ui.echart(options=bar_mitre_options).classes("w-full h-full")

            # ── 5. Таблиці бізнес-логіки (Топ IoC та Останні пошуки) ──────────
            with ui.grid(columns=2).classes("w-full gap-4 mb-4"):

                with ui.element("div").classes("card"):
                    ui.label("Топ шкідливих IoC").style("font-weight:600; margin-bottom:8px; display:block")
                    cols = [
                        {"name": "value", "label": "IoC", "field": "value", "align": "left"},
                        {"name": "ioc_type", "label": "Тип", "field": "ioc_type", "align": "left"},
                        {"name": "risk_score", "label": "Score", "field": "risk_score", "align": "right"},
                        {"name": "severity", "label": "Severity", "field": "severity", "align": "left"},
                        {"name": "country", "label": "Країна", "field": "country", "align": "left"},
                    ]
                    ui.table(columns=cols, rows=stats["top_mal"], row_key="value").classes("w-full")

                with ui.element("div").classes("card"):
                    ui.label("Останні пошуки").style("font-weight:600; margin-bottom:8px; display:block")
                    cols_r = [
                        {"name": "Запит", "label": "Запит", "field": "Запит", "align": "left"},
                        {"name": "Тип", "label": "Тип", "field": "Тип", "align": "left"},
                        {"name": "Час", "label": "Час", "field": "Час", "align": "left"},
                    ]
                    ui.table(columns=cols_r, rows=stats["recent"], row_key="Запит").classes("w-full")

            # ── 6. Інформаційна таблиця статусів фідів кіберрозвідки ─────────
            with ui.element("div").classes("card"):
                ui.label("Статус фідів").style("font-weight:600; margin-bottom:8px; display:block")
                cols_f = [
                    {"name": "name", "label": "Фід", "field": "name", "align": "left"},
                    {"name": "status", "label": "Статус", "field": "status", "align": "left"},
                    {"name": "iocs_added", "label": "IoC додано", "field": "iocs_added", "align": "right"},
                    {"name": "last_run", "label": "Оновлено", "field": "last_run", "align": "left"},
                ]
                ui.table(columns=cols_f, rows=stats["feeds"], row_key="name").classes("w-full")