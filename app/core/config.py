from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://cti:cti_secret@localhost:5432/cti_db"
    REDIS_URL: str = "redis://localhost:6379/0"

    VIRUSTOTAL_API_KEY: str = "e07225c7fad6c9b7eb9ccd7765a05f73db21774b15558d6a2ad68ef86e5d4bdf"
    ABUSEIPDB_API_KEY: str = "18f6e373aefd73c605d4fc2f9fad8b783edcfcb706f9ee4b7f63be80b82e058eb4f9bad72b94810b"
    ALIENVAULT_API_KEY: str = "db2c0304400c06b5d881cbfcf6ce5a8c4fca9c0c358365ac523c4242b84ff92e"
    SHODAN_API_KEY: str = "w0iQXald5nFBumLU32es6jJzfBOToSun"
    IPINFO_TOKEN: str = ""
    URLHAUS_API_KEY: str = "254a2776120ebbb28da5df5c1f8511a1495385a844c35661"
    URLHAUS_ENABLED: bool = True

    SECRET_KEY: str = "dev-secret"
    CACHE_TTL: int = 3600
    DEBUG: bool = False
    FEED_REFRESH_INTERVAL: int = 60

    APP_TITLE: str = "CTI Platform"
    APP_VERSION: str = "1.0.0"

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
