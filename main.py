"""
CTI Platform — точка входу.
Запуск: python main.py
"""
import logging
import asyncio

from nicegui import ui, app

from app.core.config import settings
from app.core.database import init_db
from app.services.feeds import seed_default_feeds
from app.pages import dashboard, search, iocs

logging.basicConfig(level=logging.INFO)


@app.on_startup
async def startup():
    await init_db()
    await seed_default_feeds()
    from app.services.scheduler import start_scheduler
    start_scheduler()


# Реєструємо сторінки
dashboard.page()
search.page()
iocs.page()

ui.run(
    host="0.0.0.0",
    port=8000,
    title=settings.APP_TITLE,
    dark=True,
    reload=False,
)
