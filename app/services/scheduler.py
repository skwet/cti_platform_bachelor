"""
APScheduler wrapper — runs feed refresh in background.
"""
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.core.config import settings
from datetime import datetime

log = logging.getLogger("cti.scheduler")
_scheduler: AsyncIOScheduler | None = None


def start_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    from app.services.feeds import run_all_feeds

    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        run_all_feeds,
        "interval",
        hours=1,
        id="feed_refresh",
        replace_existing=True,
        next_run_time=datetime.now(),
    )
    _scheduler.start()
    log.info("Scheduler started — feed refresh every 1 hour")