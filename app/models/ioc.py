from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Integer, Float, Boolean, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum
from app.core.database import Base


class IoCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

def now_utc():
    return datetime.now(timezone.utc)

class IoC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    value: Mapped[str] = mapped_column(String(2048), unique=True, index=True, nullable=False)
    ioc_type: Mapped[IoCType] = mapped_column(SAEnum(IoCType), nullable=False, index=True)
    severity: Mapped[Severity]= mapped_column(SAEnum(Severity), default=Severity.UNKNOWN)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    source: Mapped[str | None]= mapped_column(String(128), nullable=True, index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Raw enrichment snapshots
    vt_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    abuse_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    otx_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    urlhaus_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    shodan_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # MITRE ATT&CK TTPs витягнуті з OTX-пульсів
    mitre_ttps: Mapped[list | None] = mapped_column(JSON, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    search_count: Mapped[int] = mapped_column(Integer, default=0)

    history: Mapped[list["SearchLog"]] = relationship("SearchLog", back_populates="ioc", cascade="all, delete-orphan")


class SearchLog(Base):
    __tablename__ = "search_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    query: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    ioc_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    ioc_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("iocs.id"),
        nullable=True
    )

    searched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    ioc: Mapped["IoC | None"] = relationship("IoC", back_populates="history")