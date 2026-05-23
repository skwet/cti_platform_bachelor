"""
Сторінка бази IoC — фільтри, таблиця, видалення.
"""
from nicegui import ui
from sqlalchemy import select, func, desc

from app.core.database import AsyncSessionLocal
from app.models.ioc import IoC
from app.pages import theme

PER_PAGE = 25


async def _load_iocs(page=1, q="", ioc_type="", severity="", malicious_only=False, sort="last_seen") -> dict:
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
        if sort == "risk_score": order = desc(IoC.risk_score)
        if sort == "first_seen": order = desc(IoC.first_seen)

        items = (await db.execute(
            stmt.order_by(order).offset((page - 1) * PER_PAGE).limit(PER_PAGE)
        )).scalars().all()

    return {
        "total": total,
        "pages": max(1, -(-total // PER_PAGE)),
        "items": [
            {
                "id":       i.id,
                "value":    i.value,
                "ioc_type": i.ioc_type.value  if hasattr(i.ioc_type,  "value") else i.ioc_type,
                "score":    i.risk_score,
                "severity": i.severity.value  if hasattr(i.severity,  "value") else i.severity,
                "malicious":"Так" if i.is_malicious is True else ("Ні" if i.is_malicious is False else "?"),
                "country":  i.country or "—",
                "source":   i.source  or "—",
                "last_seen":i.last_seen.strftime("%d.%m.%Y %H:%M") if i.last_seen else "—",
            }
            for i in items
        ],
    }


async def _delete(ioc_id: int) -> None:
    async with AsyncSessionLocal() as db:
        obj = (await db.execute(select(IoC).where(IoC.id == ioc_id))).scalar_one_or_none()
        if obj:
            await db.delete(obj)
            await db.commit()


def page():
    @ui.page("/iocs")
    async def iocs():
        # Стан фільтрів та пагінації (зберігаємо в closure)
        state = {"page": 1, "q": "", "type": "", "sev": "", "mal": False, "sort": "last_seen"}

        with theme.layout("База IoC", "/iocs"):

            # ── Фільтри ───────────────────────────────────────────────────
            with ui.element("div").classes("card").style("margin-bottom:16px"):
                with ui.row().style("gap:8px; flex-wrap:wrap; align-items:center"):
                    q_inp = ui.input(placeholder="Пошук IoC…").props("outlined dense dark").style("width:240px")
                    type_sel = ui.select(
                        options={"": "Всі типи", "ip": "IP", "domain": "Domain", "url": "URL",
                                 "hash_md5": "MD5", "hash_sha1": "SHA1", "hash_sha256": "SHA256", "email": "Email"},
                        value=""
                    ).props("outlined dense dark").style("width:130px")
                    sev_sel = ui.select(
                        options={"": "Всі рівні", "critical": "Critical", "high": "High",
                                 "medium": "Medium", "low": "Low"},
                        value=""
                    ).props("outlined dense dark").style("width:130px")
                    sort_sel = ui.select(
                        options={"last_seen": "Останні", "first_seen": "Перші", "risk_score": "Risk Score"},
                        value="last_seen"
                    ).props("outlined dense dark").style("width:130px")
                    mal_chk = ui.checkbox("Тільки шкідливі")
                    ui.button("Фільтрувати", icon="filter_list").props(
                        "color=primary unelevated dense"
                    )

            # ── Заголовок + таблиця ───────────────────────────────────────
            info_label  = ui.label("").style(f"color:{theme.MUTED}; font-size:0.85rem; margin-bottom:8px; display:block")
            table_area  = ui.element("div").style("width:100%")
            page_row    = ui.row().style("gap:8px; align-items:center; margin-top:12px")

            TABLE_COLS = [
                {"name": "value",    "label": "IoC",      "field": "value",    "align": "left",  "sortable": True},
                {"name": "ioc_type", "label": "Тип",      "field": "ioc_type", "align": "left"},
                {"name": "score",    "label": "Score",    "field": "score",    "align": "right", "sortable": True},
                {"name": "severity", "label": "Severity", "field": "severity", "align": "left"},
                {"name": "malicious","label": "Шкідл.",   "field": "malicious","align": "center"},
                {"name": "country",  "label": "Країна",   "field": "country",  "align": "left"},
                {"name": "source",   "label": "Джерело",  "field": "source",   "align": "left"},
                {"name": "last_seen","label": "Останній", "field": "last_seen","align": "left"},
                {"name": "actions",  "label": "",         "field": "id",       "align": "right"},
            ]

            async def refresh():
                data = await _load_iocs(
                    page=state["page"],
                    q=state["q"],
                    ioc_type=state["type"],
                    severity=state["sev"],
                    malicious_only=state["mal"],
                    sort=state["sort"],
                )
                info_label.set_text(
                    f'Знайдено: {data["total"]:,} IoC   •   '
                    f'Сторінка {state["page"]} / {data["pages"]}'
                )

                table_area.clear()
                with table_area:
                    tbl = ui.table(
                        columns=TABLE_COLS,
                        rows=data["items"],
                        row_key="id",
                    ).classes("w-full")

                    # Кнопки видалення у колонці actions
                    tbl.add_slot("body-cell-actions", """
                        <q-td :props="props">
                            <q-btn flat dense icon="delete" color="negative" size="sm"
                                @click="$parent.$emit('delete', props.row)" />
                        </q-td>
                    """)

                    async def on_delete(e):
                        await _delete(e.args["id"])
                        ui.notify(f'IoC «{e.args["value"]}» видалено', color="positive")
                        await refresh()

                    tbl.on("delete", on_delete)

                # Пагінація
                page_row.clear()
                with page_row:
                    async def prev_page():
                        state["page"] -= 1
                        await refresh()
                    async def next_page():
                        state["page"] += 1
                        await refresh()

                    ui.button("◀", on_click=prev_page).props(
                        "flat dense"
                    ).set_enabled(state["page"] > 1)
                    ui.label(f'{state["page"]} / {data["pages"]}').style(
                        f"color:{theme.MUTED}; font-size:0.85rem"
                    )
                    ui.button("▶", on_click=next_page).props(
                        "flat dense"
                    ).set_enabled(state["page"] < data["pages"])

            async def on_filter():
                state["page"]  = 1
                state["q"]     = q_inp.value.strip()
                state["type"]  = type_sel.value
                state["sev"]   = sev_sel.value
                state["mal"]   = mal_chk.value
                state["sort"]  = sort_sel.value
                await refresh()

            q_inp.on("keydown.enter", on_filter)

            # Прив'язуємо кнопку після створення refresh
            # (перестворюємо кнопку з правильним on_click)
            await refresh()
