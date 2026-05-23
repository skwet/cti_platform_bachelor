"""
Dashboard page — stats, charts, top-malicious table, feeds status.
"""
from datetime import datetime
from nicegui import ui
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import select, func, desc, text, cast, case, literal

from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC, SearchLog
from app.models.feed import ThreatFeed, FeedEntry
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

        by_sev = {
            (r[0].value if hasattr(r[0], "value") else r[0]): r[1]
            for r in (await db.execute(
                select(IoC.severity, func.count())
                .where(IoC.severity != "unknown")
                .group_by(IoC.severity)
            )).all()
        }

        recent = (await db.execute(
            select(SearchLog).order_by(desc(SearchLog.searched_at)).limit(10)
        )).scalars().all()

        top_mal = (await db.execute(
            select(IoC).where(IoC.is_malicious == True)
            .order_by(desc(IoC.risk_score)).limit(10)
        )).scalars().all()

        feeds = (await db.execute(select(ThreatFeed))).scalars().all()

        timeline_rows = (await db.execute(text(
            """SELECT date_trunc('day', first_seen)::date AS day, COUNT(*) as cnt
               FROM iocs
               WHERE first_seen >= NOW() - INTERVAL '30 days'
               GROUP BY day ORDER BY day"""
        ))).all()

        countries = (await db.execute(
            select(IoC.country, func.count().label("cnt"))
            .where(IoC.country.isnot(None))
            .where(IoC.is_malicious == True)
            .group_by(IoC.country)
            .order_by(desc("cnt"))
            .limit(8)
        )).all()

        # MITRE ATT&CK — розгортаємо JSON-масив і рахуємо техніки
        mitre_stmt = (
            select(
                func.jsonb_array_elements(
                    case(
                        (func.jsonb_typeof(cast(IoC.mitre_ttps, JSONB)) == "array",
                         cast(IoC.mitre_ttps, JSONB)),
                        else_=literal("[]").cast(JSONB),
                    )
                ).op("->>")(literal("name")).label("technique"),
                func.count().label("cnt"),
            )
            .where(IoC.mitre_ttps.isnot(None))
            .group_by(text("technique"))
            .order_by(desc(text("cnt")))
            .limit(15)
        )
        mitre_rows = (await db.execute(mitre_stmt)).all()

    return {
        "total": total,
        "malicious": malicious,
        "clean": total - malicious,
        "by_type": by_type,
        "by_sev": by_sev,
        "recent": [
            {"query": s.query, "ioc_type": s.ioc_type,
             "searched_at": s.searched_at.strftime("%d.%m %H:%M") if s.searched_at else "—"}
            for s in recent
        ],
        "top_mal": [
            {"value": i.value,
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
             "last_run": f.last_run.strftime("%d.%m %H:%M") if f.last_run else "—",
             "enabled": f.enabled}
            for f in feeds
        ],
        "timeline": [{"date": str(r[0])[5:], "count": r[1]} for r in timeline_rows],
        "countries": [{"country": r[0], "count": r[1]} for r in countries],
        "mitre_techniques": [
            {
                "technique": (
                    __import__("json").loads(r[0]).get("display_name")
                    or __import__("json").loads(r[0]).get("name")
                    or r[0]
                ) if r[0] and r[0].startswith("{") else r[0],
                "count": r[1],
            }
            for r in mitre_rows
        ],
    }


def _stat_card(icon: str, icon_cls: str, label: str, value: str):
    with ui.element("div").classes("stat-card"):
        with ui.element("div").classes(f"stat-icon {icon_cls}"):
            ui.icon(icon)
        with ui.column().style("gap:2px"):
            ui.label(label).style(f"font-size:0.78rem;color:{theme.MUTED};font-weight:600;text-transform:uppercase;letter-spacing:0.4px")
            ui.label(value).style("font-size:1.6rem;font-weight:700;line-height:1")


def page():
    @ui.page("/")
    async def dashboard():
        with theme.layout("Дашборд", "/"):
            stats = await _load_stats()

            # ── 1. STAT CARDS ──
            with ui.grid(columns=4).classes("w-full items-stretch gap-4 mb-6"):
                _stat_card("shield",           "purple", "Всього IoC",     f'{stats["total"]:,}')
                _stat_card("bug_report",       "red",    "Шкідливих",      f'{stats["malicious"]:,}')
                _stat_card("check_circle",     "green",  "Чистих",         f'{stats["clean"]:,}')
                _stat_card("broadcast_on_home","blue",   "Активних фідів", str(sum(1 for f in stats["feeds"] if f["enabled"])))

            # ── 2. CHARTS ROW ──
            with ui.row().classes("w-full items-stretch gap-4 mb-6 no-wrap"):

                with ui.element("div").classes("cti-card").style("flex: 3; min-width: 0;"):
                    ui.label("Нові IoC за 30 днів").classes("section-title")
                    if stats["timeline"]:
                        import plotly.graph_objects as go
                        fig = go.Figure(go.Scatter(
                            x=[t["date"] for t in stats["timeline"]],
                            y=[t["count"] for t in stats["timeline"]],
                            mode="lines+markers",
                            fill="tozeroy",
                            line=dict(color=theme.PRIMARY, width=2),
                            marker=dict(size=4),
                            fillcolor="rgba(59,130,246,0.1)",
                        ))
                        fig.update_layout(
                            height=260, margin=dict(l=40, r=20, t=10, b=30),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(color=theme.MUTED, size=11),
                            xaxis=dict(gridcolor="rgba(255,255,255,0.05)", showline=False),
                            yaxis=dict(gridcolor="rgba(255,255,255,0.05)", showline=False),
                            autosize=True,
                        )
                        ui.plotly(fig).classes("w-full")
                    else:
                        ui.label("Немає даних").style(f"color:{theme.MUTED}")

                with ui.element("div").classes("cti-card").style("flex: 2; min-width: 0;"):
                    ui.label("Розподіл індикаторів").classes("section-title")
                    with ui.row().classes("w-full justify-around items-center h-[260px] no-wrap"):
                        if stats["by_type"]:
                            import plotly.graph_objects as go
                            fig_type = go.Figure(go.Pie(
                                labels=[k.upper() for k in stats["by_type"]],
                                values=list(stats["by_type"].values()),
                                hole=0.55,
                                marker=dict(colors=["#3b82f6","#8b5cf6","#ec4899","#06b6d4","#10b981"]),
                            ))
                            fig_type.update_layout(
                                title=dict(text="ТИПИ", font=dict(color="#94a3b8", size=10), y=0.5, x=0.5, xanchor='center', yanchor='middle'),
                                height=240, margin=dict(l=5, r=5, t=5, b=5),
                                paper_bgcolor="rgba(0,0,0,0)",
                                font=dict(color=theme.MUTED, size=10),
                                showlegend=True,
                                autosize=True,
                            )
                            ui.plotly(fig_type).style("width: 48%; height: 240px")

                        if stats["by_sev"]:
                            import plotly.graph_objects as go
                            sev_order = ["critical", "high", "medium", "low"]
                            keys   = [k for k in sev_order if k in stats["by_sev"]]
                            values = [stats["by_sev"][k] for k in keys]
                            colors = [theme.SEV_COLOR.get(k, "#64748b") for k in keys]
                            fig_sev = go.Figure(go.Pie(
                                labels=[k.upper() for k in keys],
                                values=values,
                                hole=0.55,
                                marker=dict(colors=colors),
                            ))
                            fig_sev.update_layout(
                                title=dict(text="ЗАГРОЗИ", font=dict(color="#94a3b8", size=10), y=0.5, x=0.5, xanchor='center', yanchor='middle'),
                                height=240, margin=dict(l=5, r=5, t=5, b=5),
                                paper_bgcolor="rgba(0,0,0,0)",
                                font=dict(color=theme.MUTED, size=10),
                                showlegend=True,
                                autosize=True,
                            )
                            ui.plotly(fig_sev).style("width: 48%; height: 240px")

            # ── 3. DATA TABLES ROW ──
            with ui.grid(columns=2).classes("w-full items-stretch gap-4 mb-6"):

                with ui.element("div").classes("cti-card"):
                    ui.label("Топ країн-джерел атак").classes("section-title")
                    if stats["countries"]:
                        import plotly.graph_objects as go
                        fig_country = go.Figure(go.Bar(
                            x=[c["country"] for c in stats["countries"]],
                            y=[c["count"] for c in stats["countries"]],
                            marker_color="rgba(239,68,68,0.7)",
                        ))
                        fig_country.update_layout(
                            height=240, margin=dict(l=40, r=10, t=10, b=30),
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font=dict(color=theme.MUTED, size=11),
                            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                            autosize=True,
                        )
                        ui.plotly(fig_country).classes("w-full")

                with ui.element("div").classes("cti-card"):
                    ui.label("Топ-10 шкідливих IoC").classes("section-title")
                    cols = [
                        {"name": "value",      "label": "IoC",      "field": "value",     "align": "left"},
                        {"name": "ioc_type",   "label": "Тип",      "field": "ioc_type",  "align": "left"},
                        {"name": "risk_score", "label": "Score",    "field": "risk_score","align": "right"},
                        {"name": "severity",   "label": "Severity", "field": "severity",  "align": "left"},
                        {"name": "country",    "label": "Країна",   "field": "country",   "align": "left"},
                    ]
                    rows = [
                        {**i, "value": i["value"][:35] + ("…" if len(i["value"]) > 35 else "")}
                        for i in stats["top_mal"]
                    ]
                    table = ui.table(columns=cols, rows=rows, row_key="value").classes("w-full bg-transparent")
                    table.add_slot('body-cell-ioc_type', '''
                        <q-td :props="props">
                            <q-badge :color="props.value === 'ip' ? 'blue' : props.value === 'domain' ? 'purple' : 'pink'" outline>
                                {{ props.value.toUpperCase() }}
                            </q-badge>
                        </q-td>
                    ''')
                    table.add_slot('body-cell-severity', '''
                        <q-td :props="props">
                            <q-badge color="red" v-if="props.value === 'critical'">CRITICAL</q-badge>
                            <q-badge color="orange" v-else-if="props.value === 'high'">HIGH</q-badge>
                            <q-badge color="amber" v-else>{{ props.value.toUpperCase() }}</q-badge>
                        </q-td>
                    ''')

            # ── 4. MITRE ATT&CK TECHNIQUES ──
            with ui.element("div").classes("cti-card w-full mb-6"):
                ui.label("🛡️ Топ MITRE ATT&CK технік").classes("section-title")
                if stats["mitre_techniques"]:
                    import plotly.graph_objects as go
                    techniques = stats["mitre_techniques"]
                    fig_mitre = go.Figure(go.Bar(
                        y=[t["technique"] for t in techniques],
                        x=[t["count"] for t in techniques],
                        orientation="h",
                        marker=dict(
                            color=[t["count"] for t in techniques],
                            colorscale=[[0, "#1d4ed8"], [0.5, "#7c3aed"], [1, "#dc2626"]],
                            showscale=False,
                        ),
                        text=[str(t["count"]) for t in techniques],
                        textposition="outside",
                        textfont=dict(color=theme.MUTED, size=11),
                    ))
                    fig_mitre.update_layout(
                        height=max(280, len(techniques) * 28),
                        margin=dict(l=10, r=60, t=10, b=10),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color=theme.TEXT, size=11),
                        xaxis=dict(
                            gridcolor="rgba(255,255,255,0.06)",
                            showline=False,
                            title="Кількість IoC",
                            title_font=dict(color=theme.MUTED),
                        ),
                        yaxis=dict(
                            gridcolor="rgba(255,255,255,0.0)",
                            showline=False,
                            autorange="reversed",
                            tickfont=dict(size=11, color=theme.TEXT),
                        ),
                        autosize=True,
                    )
                    ui.plotly(fig_mitre).classes("w-full")
                else:
                    with ui.row().classes("items-center gap-3").style(f"color:{theme.MUTED};padding:24px 0"):
                        ui.icon("info").style("font-size:1.4rem")
                        ui.label("MITRE ATT&CK техніки ще не зібрані. Вони з'являться після збагачення IoC через OTX.")

            # ── 5. RECENT SEARCHES + FEEDS ──
            with ui.grid(columns=2).classes("w-full items-stretch gap-4"):
                with ui.element("div").classes("cti-card"):
                    ui.label("Останні пошуки").classes("section-title")
                    cols_recent = [
                        {"name": "query",      "label": "Запит",    "field": "query",      "align": "left"},
                        {"name": "ioc_type",   "label": "Тип",      "field": "ioc_type",   "align": "left"},
                        {"name": "searched_at","label": "Час",      "field": "searched_at","align": "left"},
                    ]
                    ui.table(columns=cols_recent, rows=stats["recent"], row_key="query").classes("w-full bg-transparent")

                with ui.element("div").classes("cti-card"):
                    ui.label("Статус фідів").classes("section-title")
                    cols_feeds = [
                        {"name": "name",       "label": "Фід",        "field": "name",       "align": "left"},
                        {"name": "status",     "label": "Статус",     "field": "status",     "align": "left"},
                        {"name": "iocs_added", "label": "IoC додано", "field": "iocs_added", "align": "right"},
                        {"name": "last_run",   "label": "Оновлено",   "field": "last_run",   "align": "left"},
                    ]
                    ui.table(columns=cols_feeds, rows=stats["feeds"], row_key="name").classes("w-full bg-transparent")