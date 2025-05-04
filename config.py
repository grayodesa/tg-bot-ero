import os
from typing import List

from dotenv import load_dotenv

# Load environment variables from .env file, if present
load_dotenv()

class Config:
    """
    Application configuration loaded from environment variables.
    """
    # Telegram bot token
    TG_TOKEN: str = os.getenv("TG_TOKEN", "")
    # OpenAI API key
    OPENAI_KEY: str = os.getenv("OPENAI_KEY", "")
    # Comma-separated list of admin Telegram user IDs
    ADMIN_IDS: List[int] = [int(i) for i in os.getenv("ADMIN_IDS", "").split(",") if i]
    # Public URL for Telegram webhook
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", "")
    # Secret token for Telegram webhook validation
    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
    # DSN for PostgreSQL via asyncpg (expects postgresql:// scheme)
    _raw_dsn: str = os.getenv("POSTGRES_DSN", "")
    # Allow user to provide SQLAlchemy-style DSN and normalize it
    if _raw_dsn.startswith("postgresql+asyncpg://"):
        POSTGRES_DSN: str = _raw_dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
    else:
        POSTGRES_DSN: str = _raw_dsn
    # Secret key used to sign JWT tokens for admin endpoints
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    # Model name to use for OpenAI API
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    # Log level for application
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")
    # Avatar cache TTL in seconds (default: 1 hour)
    AVATAR_CACHE_TTL: int = int(os.getenv("AVATAR_CACHE_TTL", "3600"))
    # JWT token expiration in seconds (default: 24 hours)
    JWT_EXPIRATION: int = int(os.getenv("JWT_EXPIRATION", "86400"))
    # Redis URL for caching (optional)
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    # JWT refresh token expiration (default: 7 days)
    JWT_REFRESH_EXPIRATION: int = int(os.getenv("JWT_REFRESH_EXPIRATION", "604800"))
    # Rate limit for webhook (requests per minute)
    WEBHOOK_RATE_LIMIT: int = int(os.getenv("WEBHOOK_RATE_LIMIT", "60"))
    # Temporary files directory
    TEMP_DIR: str = os.getenv("TEMP_DIR", "/tmp")

config = Config()