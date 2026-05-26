from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Integer, Boolean, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
import enum
from app.core.database import Base


class FeedType(str, enum.Enum):
    URLHAUS = "urlhaus"
    ABUSEIPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    MALWAREBAZAAR = "malwarebazaar"


class FeedStatus(str, enum.Enum):
    OK = "ok"
    ERROR = "error"
    PENDING = "pending"


def now_utc():
    return datetime.now(timezone.utc)

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    feed_type: Mapped[FeedType] = mapped_column(SAEnum(FeedType), nullable=False)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[FeedStatus] = mapped_column(SAEnum(FeedStatus), default=FeedStatus.PENDING)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    iocs_added: Mapped[int] = mapped_column(Integer, default=0)
    total_fetched: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class FeedEntry(Base):
    __tablename__ = "feed_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    threat_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
