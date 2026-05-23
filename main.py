"""
CTI Platform — NiceGUI entrypoint.
Запуск: python main.py
"""
import asyncio
import logging

from nicegui import app, ui

from app.core.config import settings
from app.core.database import init_db
from app.services.feeds import seed_default_feeds

# ── Register pages ────────────────────────────────────────────────────────────
from app.pages import dashboard, search, iocs

dashboard.page()
search.page()
iocs.page()

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_startup
async def startup():
    logging.basicConfig(level=logging.INFO)
    await init_db()
    await seed_default_feeds()

    # Optional: background feed scheduler
    from app.services.scheduler import start_scheduler
    start_scheduler()

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        host="0.0.0.0",
        port=8000,
        title=settings.APP_TITLE,
        dark=True,
        reload=settings.DEBUG,
        favicon="🛡️",
    )