"""
Main application for the anti-erotic-spam Telegram bot.
"""
import time
import logging
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import telegram
from telegram import Update, Bot
from telegram.error import TelegramError

from openai import OpenAI

from config import config
from bot.security import (
    JWTHandler, WebhookValidator, RateLimitMiddleware,
    verify_jwt_dependency, rate_limit_dependency
)
from bot.database import (
    create_db_pool, initialize_tables, log_message, mark_new_member,
    check_pending, clear_pending, get_bot_enabled_state, set_bot_enabled_state,
    get_stats
)
from bot.telegram_utils import take_action
from bot.cache import cache_manager
from bot.services.spam_detector import SpamDetector
from bot.metrics import (
    timed_execution, increment_counter, set_gauge,
    webhook_requests, webhook_errors, webhook_latency, bot_enabled
)


# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Anti-Erotic Spam Bot",
    description="Telegram bot for detecting and removing erotic spam messages",
    version="1.0.0"
)

# Initialize security components
jwt_handler = JWTHandler(config.JWT_SECRET)
webhook_validator = WebhookValidator()

# Initialize Telegram Bot
bot = Bot(token=config.TG_TOKEN)

# Add middlewares
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    RateLimitMiddleware,
    rate_limit_per_minute=config.WEBHOOK_RATE_LIMIT,
    endpoint_filter=lambda path: path == "/webhook"
)

# Import and include the admin router
from bot.admin.router import router as admin_router
app.include_router(admin_router)


@app.on_event("startup")
async def on_startup():
    """
    Initialize application on startup.
    """
    # Initialize OpenAI client
    app.state.openai_client = OpenAI(api_key=config.OPENAI_KEY)
    
    # Connect to PostgreSQL with retries
    app.state.db = await create_db_pool(config.POSTGRES_DSN)
    
    # Initialize database tables
    await initialize_tables(app.state.db)
    
    # Initialize spam detector service
    app.state.spam_detector = SpamDetector(
        bot=bot,
        openai_client=app.state.openai_client,
        model_name=config.OPENAI_MODEL,
        cache_manager=cache_manager
    )
    
    # Set bot enabled gauge
    enabled = await get_bot_enabled_state(app.state.db)
    set_gauge(bot_enabled, 1 if enabled else 0)


@app.on_event("shutdown")
async def on_shutdown():
    """
    Clean up resources on shutdown.
    """
    if hasattr(app.state, "db") and app.state.db is not None:
        await app.state.db.close()
        logger.info("Database connection pool closed")


@app.post("/webhook", dependencies=[Depends(rate_limit_dependency)])
async def webhook(request: Request):
    """
    Telegram webhook endpoint to receive updates.
    """
    # Increment webhook request counter
    increment_counter(webhook_requests)
    
    # Start timing webhook request
    with timed_execution(webhook_latency):
        # Validate webhook request
        if not webhook_validator.validate_telegram_webhook(request, config.WEBHOOK_SECRET):
            increment_counter(webhook_errors)
            raise HTTPException(status_code=403, detail="Unauthorized")
        
        # Check if bot is enabled
        enabled = await get_bot_enabled_state(app.state.db)
        if not enabled:
            return JSONResponse({"ok": True})
        
        # Parse update
        try:
            data = await webhook_validator.validate_webhook_data(request)
            update = Update.de_json(data, bot)
        except Exception as e:
            logger.error("Failed to parse update: %s", e)
            increment_counter(webhook_errors)
            raise HTTPException(status_code=400, detail="Invalid update payload")
        
        # Process the update
        return await process_update(update)


async def process_update(update: Update):
    """
    Process a Telegram update, separated from webhook for better testing.
    """
    message = update.message
    
    # Handle new chat members: mark for first-message check
    if message and message.new_chat_members:
        for new_member in message.new_chat_members:
            await mark_new_member(app.state.db, message.chat.id, new_member.id)
        return JSONResponse({"ok": True})
    
    # Only process the first message per user after joining
    if not message or not message.text:
        return JSONResponse({"ok": True})
    
    user = message.from_user
    chat = message.chat
    
    # Check pending-first flag
    pending = await check_pending(app.state.db, chat.id, user.id)
    if not pending:
        # Not a first message after join: skip
        return JSONResponse({"ok": True})
    
    # Clear pending flag so we only check once
    await clear_pending(app.state.db, chat.id, user.id)
    
    # Run spam analysis using the service
    result = await app.state.spam_detector.analyze_user(
        user_id=user.id,
        first_name=user.first_name,
        message=message.text
    )
    
    # Take action if spam is detected
    if result['is_spam']:
        await take_action(bot, chat.id, message.message_id, user.id)
    
    # Log message to database
    await log_message(
        app.state.db,
        user.id, chat.id, message.text,
        result['link_in_bio'],
        result['avatar_unsafe'],
        result['avatar_suspicious'], 
        result['llm_result'],
        result['latency_ms']
    )
    
    return JSONResponse({"ok": True})


@app.get("/stats")
async def stats(admin_data: Dict = Depends(verify_jwt_dependency)):
    """
    Return statistics about spam removed and suspicious avatars caught.
    """
    return await get_stats(app.state.db)


@app.post("/toggle")
async def toggle(request: Request, admin_data: Dict = Depends(verify_jwt_dependency)):
    """
    Toggle the bot on or off.
    """
    data = await request.json()
    enabled = data.get("enabled", True)
    
    # Save state to database
    await set_bot_enabled_state(app.state.db, enabled)
    
    # Update metrics
    set_gauge(bot_enabled, 1 if enabled else 0)
    
    return {"enabled": enabled}


@app.post("/refresh-token")
async def refresh_token(request: Request):
    """
    Generate a new access token using a refresh token.
    """
    try:
        data = await request.json()
        refresh_token = data.get("refresh_token")
        
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token is required")
        
        # Generate new access token
        new_token = jwt_handler.refresh_access_token(
            refresh_token, 
            config.ADMIN_IDS,
            config.JWT_EXPIRATION
        )
        
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "expires_in": config.JWT_EXPIRATION
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.get("/health")
async def health_check():
    """
    Health check endpoint for Docker healthcheck.
    Checks database and Redis connections.
    """
    health_status = {
        "status": "ok",
        "services": {
            "database": "ok",
            "redis": "ok" if config.REDIS_URL else "not_configured"
        },
        "timestamp": int(time.time())
    }
    
    # Check database connection
    try:
        if hasattr(app.state, "db"):
            async with app.state.db.acquire() as conn:
                await conn.execute("SELECT 1")
        else:
            health_status["services"]["database"] = "not_connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status["services"]["database"] = "error"
        health_status["status"] = "degraded"
    
    # Check Redis connection if configured
    if config.REDIS_URL:
        try:
            import redis
            r = redis.from_url(config.REDIS_URL)
            r.ping()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            health_status["services"]["redis"] = "error"
            health_status["status"] = "degraded"
    
    status_code = 200 if health_status["status"] == "ok" else 500
    return JSONResponse(content=health_status, status_code=status_code)


def main():
    """
    Run the application with uvicorn.
    """
    import uvicorn
    import os
    
    uvicorn.run(
        "bot.main:app",
        host=os.getenv("UVICORN_HOST", "0.0.0.0"),
        port=int(os.getenv("UVICORN_PORT", "8000")),
        log_level=config.LOG_LEVEL,
    )


if __name__ == "__main__":
    main()