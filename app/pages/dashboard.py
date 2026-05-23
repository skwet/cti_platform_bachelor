"""
Дашборд — статистика, графіки, таблиці.
"""
import plotly.graph_objects as go
from datetime import datetime
from nicegui import ui
from sqlalchemy import select, func, desc, text

from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC, SearchLog
from app.models.feed import ThreatFeed
from app.pages import theme


async def _load_stats() -> dict:
    async with AsyncSessionLocal() as db:
        total     = (await db.execute(select(func.count(IoC.id)))).scalar_one()
        malicious = (await db.execute(
            select(func.count(IoC.id)).where(IoC.is_malicious == True)
        )).scalar_one()

        by_type = {
            (r[0].value if hasattr(r[0], "value") else r[0]): r[1]
            for r in (await db.execute(
                select(IoC.ioc_type, func.count()).group_by(IoC.ioc_type)
            )).all()
        }

        recent = (await db.execute(
            select(SearchLog).order_by(desc(SearchLog.searched_at)).limit(8)
        )).scalars().all()

        top_mal = (await db.execute(
            select(IoC).where(IoC.is_malicious == True)
            .order_by(desc(IoC.risk_score)).limit(8)
        )).scalars().all()

        feeds = (await db.execute(select(ThreatFeed))).scalars().all()

        timeline_rows = (await db.execute(text(
            """SELECT date_trunc('day', first_seen)::date AS day, COUNT(*) as cnt
               FROM iocs WHERE first_seen >= NOW() - INTERVAL '30 days'
               GROUP BY day ORDER BY day"""
        ))).all()

    return {
        "total":     total,
        "malicious": malicious,
        "clean":     total - malicious,
        "by_type":   by_type,
        "timeline":  [{"date": str(r[0])[5:], "count": r[1]} for r in timeline_rows],
        "recent": [
            {"Запит": s.query, "Тип": s.ioc_type,
             "Час": s.searched_at.strftime("%d.%m %H:%M") if s.searched_at else "—"}
            for s in recent
        ],
        "top_mal": [
            {"value":     i.value[:40] + ("…" if len(i.value) > 40 else ""),
             "ioc_type":  i.ioc_type.value if hasattr(i.ioc_type, "value") else i.ioc_type,
             "risk_score":i.risk_score,
             "severity":  i.severity.value if hasattr(i.severity, "value") else i.severity,
             "country":   i.country or "—"}
            for i in top_mal
        ],
        "feeds": [
            {"name":      f.name,
             "status":    f.status.value if hasattr(f.status, "value") else f.status,
             "iocs_added":f.iocs_added or 0,
             "last_run":  f.last_run.strftime("%d.%m %H:%M") if f.last_run else "—"}
            for f in feeds
        ],
        "active_feeds": sum(1 for f in feeds if f.enabled),
    }


def page():
    @ui.page("/")
    async def dashboard():
        with theme.layout("Дашборд", "/"):
            stats = await _load_stats()

            # ── Stat cards ────────────────────────────────────────────────
            with ui.grid(columns=4).classes("w-full gap-4 mb-4"):
                for icon, label, value, color in [
                    ("shield",     "Всього IoC",     f'{stats["total"]:,}',    theme.PRIMARY),
                    ("bug_report", "Шкідливих",      f'{stats["malicious"]:,}',theme.DANGER),
                    ("check",      "Чистих",          f'{stats["clean"]:,}',    theme.SUCCESS),
                    ("rss_feed",   "Активних фідів", str(stats["active_feeds"]),theme.MUTED),
                ]:
                    with ui.element("div").classes("card").style(
                        "display:flex; align-items:center; gap:12px"
                    ):
                        ui.icon(icon).style(f"font-size:1.8rem; color:{color}")
                        with ui.column().style("gap:0"):
                            ui.label(label).style(f"font-size:0.75rem; color:{theme.MUTED}")
                            ui.label(value).style(f"font-size:1.5rem; font-weight:700; color:{color}")

            # ── Timeline chart ────────────────────────────────────────────
            with ui.element("div").classes("card"):
                ui.label("Нові IoC за 30 днів").style(
                    f"font-weight:600; margin-bottom:8px; display:block"
                )
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
                        height=220,
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

            # ── Two tables ────────────────────────────────────────────────
            with ui.grid(columns=2).classes("w-full gap-4"):

                with ui.element("div").classes("card"):
                    ui.label("Топ шкідливих IoC").style(
                        f"font-weight:600; margin-bottom:8px; display:block"
                    )
                    cols = [
                        {"name": "value",      "label": "IoC",      "field": "value",      "align": "left"},
                        {"name": "ioc_type",   "label": "Тип",      "field": "ioc_type",   "align": "left"},
                        {"name": "risk_score", "label": "Score",    "field": "risk_score", "align": "right"},
                        {"name": "severity",   "label": "Severity", "field": "severity",   "align": "left"},
                        {"name": "country",    "label": "Країна",   "field": "country",    "align": "left"},
                    ]
                    ui.table(columns=cols, rows=stats["top_mal"], row_key="value").classes("w-full")

                with ui.element("div").classes("card"):
                    ui.label("Останні пошуки").style(
                        f"font-weight:600; margin-bottom:8px; display:block"
                    )
                    cols_r = [
                        {"name": "Запит", "label": "Запит", "field": "Запит", "align": "left"},
                        {"name": "Тип",   "label": "Тип",   "field": "Тип",   "align": "left"},
                        {"name": "Час",   "label": "Час",   "field": "Час",   "align": "left"},
                    ]
                    ui.table(columns=cols_r, rows=stats["recent"], row_key="Запит").classes("w-full")

            # ── Feeds status ──────────────────────────────────────────────
            with ui.element("div").classes("card mt-4"):
                ui.label("Статус фідів").style(
                    f"font-weight:600; margin-bottom:8px; display:block"
                )
                cols_f = [
                    {"name": "name",       "label": "Фід",        "field": "name",       "align": "left"},
                    {"name": "status",     "label": "Статус",     "field": "status",     "align": "left"},
                    {"name": "iocs_added", "label": "IoC додано", "field": "iocs_added", "align": "right"},
                    {"name": "last_run",   "label": "Оновлено",   "field": "last_run",   "align": "left"},
                ]
                ui.table(columns=cols_f, rows=stats["feeds"], row_key="name").classes("w-full")
