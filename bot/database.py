"""
Database module for PostgreSQL connection and queries.
"""
import json
import logging
import asyncio
from typing import Any, Dict, List, Optional, Tuple

import asyncpg

# Configure logging
logger = logging.getLogger(__name__)


async def create_db_pool(dsn: str, max_retries: int = 10, retry_delay: int = 2) -> Optional[asyncpg.Pool]:
    """
    Create a PostgreSQL connection pool with retries.
    
    Args:
        dsn: PostgreSQL connection string
        max_retries: Maximum number of connection retries
        retry_delay: Delay between retries in seconds
        
    Returns:
        asyncpg connection pool or None if connection failed
    """
    pool = None
    last_error = None
    
    for attempt in range(max_retries):
        try:
            pool = await asyncpg.create_pool(dsn=dsn)
            logger.info("Database connection established")
            break
        except Exception as e:
            last_error = e
            logger.warning(f"Database connection failed (attempt {attempt+1}/{max_retries}): {e}")
            await asyncio.sleep(retry_delay)
    
    if pool is None:
        logger.error(f"Could not connect to database after {max_retries} retries: {last_error}")
        raise last_error
    
    return pool


async def initialize_tables(pool: asyncpg.Pool) -> None:
    """
    Initialize database tables.
    
    Args:
        pool: asyncpg connection pool
    """
    try:
        # Ensure logs table exists and has all required columns
        await pool.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                user_id BIGINT,
                chat_id BIGINT,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                msg_text TEXT,
                link_in_bio BOOLEAN,
                avatar_unsafe BOOLEAN,
                llm_result INT,
                latency_ms INT
            );
            """
        )
        
        # Check if avatar_suspicious column exists, add it if not
        await pool.execute(
            """
            ALTER TABLE logs 
            ADD COLUMN IF NOT EXISTS avatar_suspicious BOOLEAN DEFAULT FALSE;
            """
        )
        logger.info("Ensured avatar_suspicious column exists in logs table")
        
        # Ensure pending-first-message table exists
        await pool.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_first (
                chat_id BIGINT,
                user_id BIGINT,
                PRIMARY KEY (chat_id, user_id)
            );
            """
        )
        
        # Ensure bot_config table exists
        await pool.execute(
            """
            CREATE TABLE IF NOT EXISTS bot_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        
        # Insert default enabled state if not exists
        await pool.execute(
            """
            INSERT INTO bot_config(key, value) 
            VALUES('enabled', 'true') 
            ON CONFLICT(key) DO NOTHING;
            """
        )
        
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        raise


async def log_message(
    pool: asyncpg.Pool,
    user_id: int,
    chat_id: int,
    msg_text: str,
    link_in_bio: bool,
    avatar_unsafe: bool,
    avatar_suspicious: bool,
    llm_result: int,
    latency_ms: int
) -> None:
    """
    Log a message to the database.
    
    Args:
        pool: asyncpg connection pool
        user_id: Telegram user ID
        chat_id: Telegram chat ID
        msg_text: Message text
        link_in_bio: Whether the user has a link in their bio
        avatar_unsafe: Whether the avatar is unsafe
        avatar_suspicious: Whether the avatar is suspicious
        llm_result: LLM classification result (0 or 1)
        latency_ms: LLM latency in milliseconds
    """
    try:
        await pool.execute(
            """
            INSERT INTO logs(user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, llm_result, latency_ms)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, llm_result, latency_ms,
        )
    except Exception as e:
        logger.error(f"Failed to log message: {e}")


async def mark_new_member(pool: asyncpg.Pool, chat_id: int, user_id: int) -> None:
    """
    Mark a new member for first-message check.
    
    Args:
        pool: asyncpg connection pool
        chat_id: Telegram chat ID
        user_id: Telegram user ID
    """
    try:
        await pool.execute(
            "INSERT INTO pending_first(chat_id, user_id) VALUES($1, $2) ON CONFLICT DO NOTHING",  
            chat_id, user_id
        )
    except Exception as e:
        logger.error(f"Failed to mark new member: {e}")


async def check_pending(pool: asyncpg.Pool, chat_id: int, user_id: int) -> bool:
    """
    Check if a user is pending first-message check.
    
    Args:
        pool: asyncpg connection pool
        chat_id: Telegram chat ID
        user_id: Telegram user ID
        
    Returns:
        Whether the user is pending first-message check
    """
    try:
        return await pool.fetchval(
            "SELECT 1 FROM pending_first WHERE chat_id=$1 AND user_id=$2", 
            chat_id, user_id
        ) is not None
    except Exception as e:
        logger.error(f"Failed to check pending status: {e}")
        return False


async def clear_pending(pool: asyncpg.Pool, chat_id: int, user_id: int) -> None:
    """
    Clear pending first-message check for a user.
    
    Args:
        pool: asyncpg connection pool
        chat_id: Telegram chat ID
        user_id: Telegram user ID
    """
    try:
        await pool.execute(
            "DELETE FROM pending_first WHERE chat_id=$1 AND user_id=$2", 
            chat_id, user_id
        )
    except Exception as e:
        logger.error(f"Failed to clear pending status: {e}")


async def get_bot_enabled_state(pool: asyncpg.Pool) -> bool:
    """
    Get the bot enabled state from the database.
    
    Args:
        pool: asyncpg connection pool
        
    Returns:
        Whether the bot is enabled
    """
    try:
        value = await pool.fetchval(
            "SELECT value FROM bot_config WHERE key = 'enabled'"
        )
        return json.loads(value) if value is not None else True
    except Exception as e:
        logger.error(f"Failed to get bot enabled state: {e}")
        return True  # Default to enabled if there's an error


async def set_bot_enabled_state(pool: asyncpg.Pool, enabled: bool) -> None:
    """
    Set the bot enabled state in the database.
    
    Args:
        pool: asyncpg connection pool
        enabled: Whether the bot should be enabled
    """
    try:
        await pool.execute(
            """
            INSERT INTO bot_config(key, value) 
            VALUES('enabled', $1) 
            ON CONFLICT(key) DO UPDATE SET value = $1
            """,
            json.dumps(enabled)
        )
    except Exception as e:
        logger.error(f"Failed to set bot enabled state: {e}")


async def get_stats(pool: asyncpg.Pool) -> Dict[str, int]:
    """
    Get statistics about spam removed and suspicious avatars caught.
    
    Args:
        pool: asyncpg connection pool
        
    Returns:
        Dictionary of statistics
    """
    try:
        rows = await pool.fetch(
            """
            SELECT 
                COUNT(*) FILTER (WHERE llm_result = 1) AS spam_removed,
                COUNT(*) FILTER (WHERE avatar_suspicious = true AND llm_result = 1) AS suspicious_avatars_caught,
                COUNT(*) FILTER (WHERE avatar_unsafe = true AND llm_result = 1) AS unsafe_avatars_caught,
                COUNT(*) FILTER (WHERE avatar_suspicious = true) AS total_suspicious_avatars
            FROM logs
            """
        )
        if rows and len(rows) > 0:
            stats_row = rows[0]
            return {
                "spam_removed": stats_row["spam_removed"],
                "suspicious_avatars_caught": stats_row["suspicious_avatars_caught"], 
                "unsafe_avatars_caught": stats_row["unsafe_avatars_caught"],
                "total_suspicious_avatars": stats_row["total_suspicious_avatars"],
                "period": "all"
            }
        return {
            "spam_removed": 0, 
            "suspicious_avatars_caught": 0, 
            "unsafe_avatars_caught": 0, 
            "total_suspicious_avatars": 0, 
            "period": "all"
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {
            "spam_removed": 0, 
            "suspicious_avatars_caught": 0, 
            "unsafe_avatars_caught": 0, 
            "total_suspicious_avatars": 0, 
            "period": "all",
            "error": str(e)
        }