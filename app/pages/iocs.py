"""
IoC database page — фільтри, пагінація, видалення.
"""
from nicegui import ui
from sqlalchemy import select, func, desc, or_

from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC
from app.pages import theme

PER_PAGE = 25


async def _load_iocs(
    page: int = 1,
    q: str = "",
    ioc_type: str = "",
    severity: str = "",
    malicious_only: bool = False,
    sort: str = "last_seen",
) -> dict:
    async with AsyncSessionLocal() as db:
        stmt = select(IoC)
        cnt  = select(func.count(IoC.id))

        filters = []
        if ioc_type:       filters.append(IoC.ioc_type == ioc_type)
        if severity:       filters.append(IoC.severity == severity)
        if malicious_only: filters.append(IoC.is_malicious == True)
        if q:              filters.append(IoC.value.ilike(f"%{q}%"))

        for f in filters:
            stmt = stmt.where(f)
            cnt  = cnt.where(f)

        total = (await db.execute(cnt)).scalar_one()

        order = desc(IoC.last_seen)
        if sort == "risk_score":  order = desc(IoC.risk_score)
        if sort == "first_seen":  order = desc(IoC.first_seen)

        items = (await db.execute(
            stmt.order_by(order).offset((page - 1) * PER_PAGE).limit(PER_PAGE)
        )).scalars().all()

    return {
        "items": [
            {
                "id":           i.id,
                "value":        i.value,
                "ioc_type":     i.ioc_type.value  if hasattr(i.ioc_type,  "value") else i.ioc_type,
                "severity":     i.severity.value  if hasattr(i.severity,  "value") else i.severity,
                "risk_score":   i.risk_score,
                "is_malicious": i.is_malicious,
                "country":      i.country or "—",
                "source":       i.source  or "—",
                "last_seen":    i.last_seen.strftime("%d.%m.%Y %H:%M") if i.last_seen else "—",
            }
            for i in items
        ],
        "total":    total,
        "page":     page,
        "pages":    max(1, -(-total // PER_PAGE)),
    }


async def _delete_ioc(ioc_id: int) -> None:
    async with AsyncSessionLocal() as db:
        ioc = (await db.execute(select(IoC).where(IoC.id == ioc_id))).scalar_one_or_none()
        if ioc:
            await db.delete(ioc)
            await db.commit()


def page():
    @ui.page("/iocs")
    async def iocs():
        state = {
            "page": 1, "q": "", "ioc_type": "",
            "severity": "", "malicious_only": False, "sort": "last_seen",
        }

        with theme.layout("База IoC", "/iocs"):

            # ── Filters row ───────────────────────────────────────────────
            with ui.element("div").classes("cti-card").style("margin-bottom:16px"):
                with ui.row().style("gap:12px;flex-wrap:wrap;align-items:flex-end"):
                    q_inp = ui.input("Пошук IoC", placeholder="IP, домен, хеш…").props("outlined dense dark").style("min-width:220px")
                    type_sel = ui.select(
                        options={"": "Всі типи", "ip": "IP", "domain": "Domain",
                                 "url": "URL", "hash_md5": "MD5", "hash_sha1": "SHA1",
                                 "hash_sha256": "SHA256", "email": "Email"},
                        value=""
                    ).props("outlined dense dark").style("min-width:140px")
                    sev_sel = ui.select(
                        options={"": "Всі рівні", "critical": "Critical", "high": "High",
                                 "medium": "Medium", "low": "Low"},
                        value=""
                    ).props("outlined dense dark").style("min-width:140px")
                    sort_sel = ui.select(
                        options={"last_seen": "Останні", "first_seen": "Перші", "risk_score": "Risk Score"},
                        value="last_seen"
                    ).props("outlined dense dark").style("min-width:150px")
                    mal_chk = ui.checkbox("Тільки шкідливі")

                    table_container = ui.element("div").style("width:100%")

                    async def refresh(reset_page: bool = True):
                        if reset_page:
                            state["page"] = 1
                        state.update(
                            q=q_inp.value,
                            ioc_type=type_sel.value,
                            severity=sev_sel.value,
                            sort=sort_sel.value,
                            malicious_only=mal_chk.value,
                        )
                        data = await _load_iocs(**state)
                        table_container.clear()
                        with table_container:
                            _render_table(data, state, refresh)

                    ui.button("Пошук", icon="search", on_click=refresh).props("color=primary unelevated dense")
                    q_inp.on("keydown.enter", lambda: refresh())

            # initial load
            data = await _load_iocs()
            with table_container:
                _render_table(data, state, refresh)


def _render_table(data: dict, state: dict, refresh_fn):
    with ui.element("div").classes("cti-card"):
        # Header
        with ui.row().style("justify-content:space-between;align-items:center;margin-bottom:12px"):
            ui.label(f"Знайдено: {data['total']:,} IoC").style(
                f"font-size:0.85rem;color:{theme.MUTED}"
            )
            ui.label(f"Сторінка {data['page']} / {data['pages']}").style(
                f"font-size:0.85rem;color:{theme.MUTED}"
            )

        # Table
        cols = [
            {"name": "value",       "label": "IoC",       "field": "value",       "align": "left",  "sortable": False},
            {"name": "ioc_type",    "label": "Тип",       "field": "ioc_type",    "align": "left"},
            {"name": "risk_score",  "label": "Score",     "field": "risk_score",  "align": "right", "sortable": False},
            {"name": "severity",    "label": "Severity",  "field": "severity",    "align": "left"},
            {"name": "is_malicious","label": "Статус",    "field": "is_malicious","align": "left"},
            {"name": "country",     "label": "Країна",    "field": "country",     "align": "left"},
            {"name": "source",      "label": "Джерело",   "field": "source",      "align": "left"},
            {"name": "last_seen",   "label": "Останній",  "field": "last_seen",   "align": "left"},
            {"name": "actions",     "label": "",          "field": "actions",     "align": "center"},
        ]

        tbl_rows = []
        for i in data["items"]:
            row = dict(i)
            row["_display_value"] = i["value"][:52] + ("…" if len(i["value"]) > 52 else "")
            tbl_rows.append(row)

        with ui.table(columns=cols, rows=tbl_rows, row_key="id").style("width:100%") as tbl:
            tbl.add_slot("body-cell-value", """
                <q-td :props="props">
                  <a :href="'/search?q='+encodeURIComponent(props.row.value)"
                     style="color:#60a5fa;text-decoration:none;font-family:monospace;font-size:0.82rem">
                    {{ props.row._display_value }}
                  </a>
                </q-td>
            """)
            tbl.add_slot("body-cell-ioc_type", """
                <q-td :props="props">
                  <span :class="'badge badge-' + (props.row.ioc_type.startsWith('hash') ? 'hash' : props.row.ioc_type)">
                    {{ props.row.ioc_type.replace('hash_','').toUpperCase() }}
                  </span>
                </q-td>
            """)
            tbl.add_slot("body-cell-risk_score", """
                <q-td :props="props" style="text-align:right">
                  <span :style="{color: props.row.risk_score >= 75 ? '#ef4444' :
                                        props.row.risk_score >= 50 ? '#f97316' :
                                        props.row.risk_score >= 25 ? '#f59e0b' : '#10b981',
                                 fontWeight: 700, fontFamily: 'monospace'}">
                    {{ props.row.risk_score ?? '—' }}
                  </span>
                </q-td>
            """)
            tbl.add_slot("body-cell-severity", """
                <q-td :props="props">
                  <span :class="'badge badge-' + (props.row.severity || 'unknown')">
                    {{ (props.row.severity || 'unknown').toUpperCase() }}
                  </span>
                </q-td>
            """)
            tbl.add_slot("body-cell-is_malicious", """
                <q-td :props="props">
                  <span v-if="props.row.is_malicious === true"  class="badge badge-critical">✕ Шкідливий</span>
                  <span v-else-if="props.row.is_malicious === false" class="badge badge-low">✓ Чистий</span>
                  <span v-else class="badge badge-unknown">? Невідомо</span>
                </q-td>
            """)
            tbl.add_slot("body-cell-actions", f"""
                <q-td :props="props" style="text-align:center">
                  <q-btn flat dense round icon="delete" color="negative" size="sm"
                    @click="$parent.$emit('delete', props.row)" />
                </q-td>
            """)

            async def on_delete(e):
                await _delete_ioc(e.args["id"])
                ui.notify(f"IoC видалено", color="positive")
                await refresh_fn()

            tbl.on("delete", on_delete)

        # Pagination
        with ui.row().style("justify-content:center;gap:8px;margin-top:12px"):
            async def go_prev():
                if state["page"] > 1:
                    state["page"] -= 1
                    await refresh_fn(reset_page=False)

            async def go_next():
                if state["page"] < data["pages"]:
                    state["page"] += 1
                    await refresh_fn(reset_page=False)

            ui.button(icon="chevron_left",  on_click=go_prev).props(
                "flat dense color=primary" + (" disabled" if data["page"] <= 1 else "")
            )
            ui.label(f"{data['page']} / {data['pages']}").style(
                f"align-self:center;font-size:0.85rem;color:{theme.MUTED}"
            )
            ui.button(icon="chevron_right", on_click=go_next).props(
                "flat dense color=primary" + (" disabled" if data["page"] >= data["pages"] else "")
            )
