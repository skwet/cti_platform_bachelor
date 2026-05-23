from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # Системні налаштування та підключення до БД
    DATABASE_URL: str = "postgresql+asyncpg://cti:cti_secret@localhost:5432/cti_db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # API Ключі для сервісів збагачення IoC (Дефолтні значення зачищені для безпеки)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    IPINFO_TOKEN: str = ""
    URLHAUS_API_KEY: str = ""
    URLHAUS_ENABLED: bool = True

    # Конфігурація додатка
    SECRET_KEY: str = "dev-secret"
    CACHE_TTL: int = 3600
    DEBUG: bool = False
    FEED_REFRESH_INTERVAL: int = 60

    APP_TITLE: str = "IoCortex"
    APP_VERSION: str = "1.0.0"

    # ─── СУЧАСНИЙ НАЛАШТУВАЛЬНИК ДЛЯ PYDANTIC V2 ───
    model_config = SettingsConfigDict(
        env_file=".env",          # Вказуємо файл, звідки пріоритетно читати змінні
        env_file_encoding="utf-8", # Кодування файлу налаштувань
        extra="ignore"            # Ігнорувати зайві змінні, які є в .env, але немає в класі
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()