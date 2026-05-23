import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

log = logging.getLogger("cti.db")

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

class Base(DeclarativeBase):
    pass

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    # Import models so SQLAlchemy registers them with Base
    from app.models import ioc, feed  # noqa

    # Retry up to 10 times with 2s delay — handles race condition
    # where backend starts slightly before Postgres is fully ready
    for attempt in range(1, 11):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            log.info("Database initialized successfully")
            return
        except Exception as e:
            if attempt == 10:
                raise
            log.warning("DB not ready (attempt %d/10): %s — retrying in 2s…", attempt, e)
            await asyncio.sleep(2)
