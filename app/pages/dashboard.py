"""Дашборд — статистика, графіки (Plotly), таблиці."""
from collections import Counter
from datetime import datetime, timedelta
import plotly.graph_objects as go
from nicegui import ui
from sqlalchemy import desc, func, select
from app.core.database import AsyncSessionLocal
from app.models.feed import ThreatFeed
from app.models.ioc import IoC, SearchLog
from app.pages import theme

async def _load_stats() -> dict:
    async with AsyncSessionLocal() as db:
        total = (await db.execute(select(func.count(IoC.id)))).scalar_one()
        malicious = (await db.execute(select(func.count(IoC.id)).where(IoC.is_malicious == True))).scalar_one()
        by_type = {(r[0].value if hasattr(r[0], "value") else r[0]): r[1] for r in (await db.execute(select(IoC.ioc_type, func.count(IoC.id)).group_by(IoC.ioc_type))).all()}
        by_severity = {(r[0].value if hasattr(r[0], "value") else r[0]): r[1] for r in (await db.execute(select(IoC.severity, func.count(IoC.id)).group_by(IoC.severity))).all()}
        
        # Топ-5 країн за кількістю шкідливих IoC
        top_countries_res = (await db.execute(
            select(IoC.country, func.count(IoC.id))
            .where(IoC.is_malicious == True)
            .where(IoC.country != None)
            .group_by(IoC.country)
            .order_by(desc(func.count(IoC.id)))
            .limit(5)
        )).all()
        top_countries = [{"country": r[0].upper(), "value": r[1]} for r in top_countries_res]
        top_countries = sorted(top_countries, key=lambda x: x["value"]) # Сортування для правильного відображення в горизонтальному барі

        mitre_counter = Counter()
        for ttps_list in (await db.execute(select(IoC.mitre_ttps).where(IoC.is_malicious == True).where(IoC.mitre_ttps != None).limit(500))).scalars().all():
            if isinstance(ttps_list, list):
                for ttp in ttps_list:
                    if isinstance(ttp, dict) and (tech_name := ttp.get("name") or ttp.get("display_name")):
                        mitre_counter[tech_name] += 1

        mitre_techniques = sorted([{"name": n, "value": c} for n, c in mitre_counter.most_common(10)], key=lambda x: x["value"])

        recent = (await db.execute(select(SearchLog).order_by(desc(SearchLog.searched_at)).limit(8))).scalars().all()
        top_mal = (await db.execute(select(IoC).where(IoC.is_malicious == True).order_by(desc(IoC.risk_score)).limit(8))).scalars().all()
        feeds = (await db.execute(select(ThreatFeed))).scalars().all()
        
        timeline_counter = Counter()
        for dt in (await db.execute(select(IoC.first_seen).where(IoC.first_seen >= datetime.utcnow() - timedelta(days=30)))).scalars().all():
            if dt: timeline_counter[dt.strftime("%m.%d")] += 1
        timeline_data = [{"date": d, "count": c} for d, c in sorted(timeline_counter.items())]

    return {
        "total": total, "malicious": malicious, "clean": total - malicious, "by_type": by_type, "by_severity": by_severity,
        "mitre_techniques": mitre_techniques, "top_countries": top_countries, "timeline": timeline_data, "active_feeds": sum(1 for f in feeds if f.enabled),
        "recent": [{"Запит": s.query, "Тип": s.ioc_type, "Час": s.searched_at.strftime("%d.%m %H:%M") if s.searched_at else "—"} for s in recent],
        "top_mal": [{"value": i.value[:40] + ("…" if len(i.value) > 40 else ""), "ioc_type": i.ioc_type.value if hasattr(i.ioc_type, "value") else i.ioc_type, "risk_score": i.risk_score, "severity": i.severity.value if hasattr(i.severity, "value") else i.severity, "country": i.country or "—"} for i in top_mal],
        "feeds": [{"name": f.name, "status": f.status.value if hasattr(f.status, "value") else f.status, "iocs_added": f.iocs_added or 0, "last_run": f.last_run.strftime("%d.%m %H:%M") if f.last_run else "—"} for f in feeds],
    }

def page():
    @ui.page("/")
    async def dashboard():
        with theme.layout("Дашборд", "/"):
            stats = await _load_stats()
            bg_style = "p-4 bg-[#1a2332] border border-slate-700/50"

            # Інформаційні картки статистики
            with ui.grid(columns=4).classes("w-full gap-4 mb-4"):
                for icon, label, value, color in [
                    ("shield", "Всього IoC", f'{stats["total"]:,}', theme.PRIMARY),
                    ("bug_report", "Шкідливих", f'{stats["malicious"]:,}', theme.DANGER),
                    ("check", "Чистих", f'{stats["clean"]:,}', theme.SUCCESS),
                    ("rss_feed", "Активних фідів", str(stats["active_feeds"]), theme.MUTED),
                ]:
                    with ui.card().classes(f"{bg_style} flex flex-row items-center gap-3"):
                        ui.icon(icon).style(f"font-size:1.8rem; color:{color}")
                        with ui.column().classes("gap-0"):
                            ui.label(label).classes("text-xs text-slate-400")
                            ui.label(value).style(f"color:{color}").classes("text-xl font-bold")

            # Нові IoC за 30 днів
            with ui.card().classes(f"w-full mb-4 {bg_style}"):
                ui.label("Нові IoC за 30 днів").classes("font-semibold mb-2 text-white")
                if stats["timeline"]:
                    fig = go.Figure(go.Scatter(x=[t["date"] for t in stats["timeline"]], y=[t["count"] for t in stats["timeline"]], mode="lines+markers", fill="tozeroy", line=dict(color=theme.PRIMARY, width=2), fillcolor="rgba(59,130,246,0.1)"))
                    fig.update_layout(template="plotly_dark", height=180, margin=dict(l=40, r=20, t=10, b=30), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white", size=11), xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False), yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False))
                    ui.plotly(fig).classes("w-full")
                else:
                    ui.label("Немає даних за останні 30 днів").classes("text-slate-400")

            # Розподіл за типами та рівнями загроз
            with ui.grid(columns=2).classes("w-full gap-4 mb-4"):
                with ui.card().classes(f"w-full h-[360px] {bg_style}"):
                    ui.label("Розподіл IoC за типами").classes("font-semibold mb-2 text-white")
                    fig1 = go.Figure(data=[go.Pie(labels=[k.upper() for k in stats["by_type"].keys()] if stats["by_type"] else ["Немає даних"], values=list(stats["by_type"].values()) if stats["by_type"] else [0], hole=0.4, textinfo="none")])
                    fig1.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h", y=-0.1, font=dict(color="white")))
                    ui.plotly(fig1).classes("w-full h-full")

                with ui.card().classes(f"w-full h-[360px] {bg_style}"):
                    ui.label("Розподіл IoC за рівнями загроз").classes("font-semibold mb-2 text-white")
                    filtered_sev = {k.upper(): v for k, v in stats["by_severity"].items() if k.upper() != "UNKNOWN"}
                    labels = list(filtered_sev.keys()) if filtered_sev else ["Чисто"]
                    colors = [{"CRITICAL": theme.DANGER, "HIGH": "#ea580c", "MEDIUM": "#eab308", "LOW": theme.SUCCESS}.get(l, theme.MUTED) for l in labels]
                    fig2 = go.Figure(data=[go.Pie(labels=labels, values=list(filtered_sev.values()) if filtered_sev else [0], marker=dict(colors=colors, line=dict(color="rgba(0,0,0,0)", width=2)), textinfo="none")])
                    fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h", y=-0.1, font=dict(color="white")))
                    ui.plotly(fig2).classes("w-full h-full")

            # Техніки MITRE та Топ-5 Країн джерел загроз
            with ui.grid(columns=2).classes("w-full gap-4 mb-4"):
                with ui.card().classes(f"w-full h-[380px] {bg_style}"):
                    ui.label("Найпоширеніші техніки MITRE ATT&CK").classes("font-semibold mb-2 text-white")
                    fig_m = go.Figure(data=[go.Bar(x=[item["value"] for item in stats["mitre_techniques"]], y=[item["name"] for item in stats["mitre_techniques"]], orientation="h", marker=dict(color=[item["value"] for item in stats["mitre_techniques"]], colorscale=[[0, "#6366f1"], [1, theme.PRIMARY]], showscale=False))])
                    fig_m.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=10, b=10), xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False), yaxis=dict(tickfont=dict(size=11)))
                    ui.plotly(fig_m).classes("w-full h-full")

                with ui.card().classes(f"w-full h-[380px] {bg_style}"):
                    ui.label("Топ-5 країн (джерела загроз)").classes("font-semibold mb-2 text-white")
                    if stats["top_countries"]:
                        fig_c = go.Figure(data=[go.Bar(x=[item["value"] for item in stats["top_countries"]], y=[item["country"] for item in stats["top_countries"]], orientation="h", marker=dict(color=[item["value"] for item in stats["top_countries"]], colorscale="Reds", showscale=False))])
                        fig_c.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=10, b=10), xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False))
                        ui.plotly(fig_c).classes("w-full h-full")
                    else:
                        ui.label("Немає даних про локації загроз").classes("text-slate-400 m-auto")

            # Топ шкідливих IoC та Останні пошуки
            with ui.grid(columns=2).classes("w-full gap-4 mb-4"):
                with ui.card().classes(bg_style):
                    ui.label("Топ шкідливих IoC").classes("font-semibold mb-2 text-white")
                    ui.table(columns=[{"name": "value", "label": "IoC", "field": "value", "align": "left"}, {"name": "ioc_type", "label": "Тип", "field": "ioc_type", "align": "left"}, {"name": "risk_score", "label": "Score", "field": "risk_score", "align": "right"}, {"name": "severity", "label": "Severity", "field": "severity", "align": "left"}, {"name": "country", "label": "Країна", "field": "country", "align": "left"}], rows=stats["top_mal"], row_key="value").classes("w-full bg-transparent text-white")

                with ui.card().classes(bg_style):
                    ui.label("Останні пошуки").classes("font-semibold mb-2 text-white")
                    ui.table(columns=[{"name": "Запит", "label": "Запит", "field": "Запит", "align": "left"}, {"name": "Тип", "label": "Тип", "field": "Тип", "align": "left"}, {"name": "Час", "label": "Час", "field": "Час", "align": "left"}], rows=stats["recent"], row_key="Запит").classes("w-full bg-transparent text-white")

            # Статус фідів
            with ui.card().classes(f"w-full {bg_style}"):
                ui.label("Статус фідів").classes("font-semibold mb-2 text-white")
                ui.table(columns=[{"name": "name", "label": "Фід", "field": "name", "align": "left"}, {"name": "status", "label": "Статус", "field": "status", "align": "left"}, {"name": "iocs_added", "label": "IoC додано", "field": "iocs_added", "align": "right"}, {"name": "last_run", "label": "Оновлено", "field": "last_run", "align": "left"}], rows=stats["feeds"], row_key="name").classes("w-full bg-transparent text-white")