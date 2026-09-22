from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    APP_NAME: str = "HoneyTrap"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8080

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/honeytrap.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # Security
    SECRET_KEY: str = Field(default="", description="Must be set in production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 4

    # Honeypot Ports
    SSH_PORT: int = 2222
    FTP_PORT: int = 2121
    TELNET_PORT: int = 2323
    DB_PORT: int = 9090
    HTTP_HONEYPOT_PORT: int = 8081

    # Detection Thresholds
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW: int = 60
    SCAN_SERVICE_THRESHOLD: int = 3
    SCAN_WINDOW: int = 30
    ANOMALY_SPIKE_THRESHOLD: int = 15
    ANOMALY_WINDOW: int = 60

    # External Services
    REDIS_URL: str = "redis://localhost:6379/0"
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_TO: str = ""

    # Threat Intel
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    ENRICHMENT_CACHE_TTL: int = 3600

    # Paths
    ROOT_DIR: Path = Path(__file__).resolve().parents[2]
    DATA_DIR: Path = Path(__file__).resolve().parents[2] / "data"
    LOG_DIR: Path = Path(__file__).resolve().parents[2] / "logs"
    REPORT_DIR: Path = Path(__file__).resolve().parents[2] / "reports" / "generated"
    DASHBOARD_DIR: Path = Path(__file__).resolve().parents[2] / "dashboard"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for path in (self.DATA_DIR, self.LOG_DIR, self.REPORT_DIR):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()