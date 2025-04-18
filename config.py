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

config = Config()