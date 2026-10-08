"""
Centralised settings loaded from environment variables / .env file.
All secrets must be set via environment — never hardcoded.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ────────────────────────────────────────────────────────────────
    APP_NAME: str = "AI Privacy Shield"
    APP_VERSION: str = "2.4.1"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"  # development | staging | production

    # ── Server ────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://ai-privacy-shield.vercel.app",
    ]

    # ── JWT Auth ──────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # ── Database ──────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://aps_user:aps_pass@localhost:5432/ai_privacy_shield"
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "ai_privacy_shield"

    # ── Redis ─────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 3600          # seconds
    RATE_LIMIT_REQUESTS: int = 60        # per window
    RATE_LIMIT_WINDOW: int = 60          # seconds

    # ── File Storage ──────────────────────────────────────────────────────
    UPLOAD_DIR: str = "uploads"
    OUTPUT_DIR: str = "outputs"
    MAX_UPLOAD_SIZE_MB: int = 20
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/webp", "image/heic"]

    # ── AI / ML ───────────────────────────────────────────────────────────
    ADVERSARIAL_EPSILON_BASIC: float = 0.02       # FGSM epsilon
    ADVERSARIAL_EPSILON_ADVANCED: float = 0.05
    ADVERSARIAL_EPSILON_MAXIMUM: float = 0.10
    ADVERSARIAL_ITERATIONS: int = 10              # PGD steps
    WATERMARK_STRENGTH: float = 0.03
    DCT_BLOCK_SIZE: int = 8
    FACE_CONFIDENCE_THRESHOLD: float = 0.5

    # ── Celery (async task queue) ─────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ── Security ──────────────────────────────────────────────────────────
    BCRYPT_ROUNDS: int = 12
    ENABLE_ANTI_SCRAPING: bool = True
    ENABLE_DATA_POISONING: bool = True
    POISON_RESPONSE_PROBABILITY: float = 0.8   # serve poisoned data 80% of bot requests

    # ── Logging ───────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"   # json | text

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        if v.lower().startswith("replace-"):
            raise ValueError("JWT_SECRET_KEY must be replaced with a randomly generated secret")
        return v

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
