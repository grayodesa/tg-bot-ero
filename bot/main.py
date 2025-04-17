"""
Main application for the anti-erotic-spam Telegram bot.
"""
import os
import re
import tempfile
import time
import hmac
import hashlib
import json
import base64

import logging

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import telegram
from telegram import Update, Bot
from telegram.error import TelegramError

import openai
from nudenet import NudeClassifier
import asyncpg

from config import config

# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI()

# Initialize Telegram Bot and NudeClassifier
bot = Bot(token=config.TG_TOKEN)
classifier = NudeClassifier()

# Security dependency
security = HTTPBearer()

def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verify JWT from Authorization header and ensure the admin_id is allowed.
    """
    token = credentials.credentials
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64.urlsafe_b64decode(signature_b64 + '==')
        expected = hmac.new(config.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid token signature")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
        if payload.get('admin_id') not in config.ADMIN_IDS:
            raise HTTPException(status_code=403, detail="Forbidden")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format or signature")

@app.on_event("startup")
async def on_startup():
    # Configure OpenAI
    openai.api_key = config.OPENAI_KEY
    # Connect to PostgreSQL
    app.state.db = await asyncpg.create_pool(dsn=config.POSTGRES_DSN)
    # Ensure logs table exists
    await app.state.db.execute(
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

@app.on_event("shutdown")
async def on_shutdown():
    await app.state.db.close()

@app.post("/webhook")
async def webhook(request: Request):
    """
    Telegram webhook endpoint to receive updates.
    """
    data = await request.json()
    try:
        update = Update.de_json(data, bot)
    except Exception as e:
        logger.error("Failed to parse update: %s", e)
        raise HTTPException(status_code=400, detail="Invalid update payload")

    message = update.message
    if not message or not message.text:
        return JSONResponse({"ok": True})

    user = message.from_user
    chat = message.chat
    msg_text = message.text

    # Feature: link in bio
    try:
        chat_user = await bot.get_chat(user.id)
        bio = chat_user.bio or ""
    except TelegramError:
        bio = ""
    link_in_bio = bool(re.search(r"https?://|t\\.me/", bio))

    # Feature: avatar unsafe
    avatar_unsafe = False
    try:
        photos = await bot.get_user_profile_photos(user.id, limit=1)
        if photos.total_count > 0:
            file_id = photos.photos[0][-1].file_id
            tg_file = await bot.get_file(file_id)
            with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                await tg_file.download_to_drive(tmp.name)
                result = classifier.classify(tmp.name)
                avatar_unsafe = result.get(tmp.name, {}).get("unsafe", 0) > 0.7
    except Exception as e:
        logger.warning("Avatar check failed: %s", e)

    # If not both features, skip LLM
    if not (link_in_bio and avatar_unsafe):
        await app.state.db.execute(
            """
            INSERT INTO logs(user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, llm_result, latency_ms)
            VALUES($1, $2, $3, $4, $5, $6, $7)
            """,
            user.id, chat.id, msg_text, link_in_bio, avatar_unsafe, 0, 0,
        )
        return JSONResponse({"ok": True})

    # LLM evaluation
    prompt = (
        f"Determine if the profile is erotic spam (0-not, 1-spam).\n"
        f"Name: {user.first_name}\n"
        f"Bio: {bio}\n"
        f"Message: {msg_text}"
    )
    start = time.time()
    try:
        response = await openai.ChatCompletion.acreate(
            model=config.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        answer = response.choices[0].message.content.strip().split()[0]
        llm_result = int(answer)
    except Exception as e:
        logger.error("LLM call failed: %s", e)
        llm_result = 0
    latency_ms = int((time.time() - start) * 1000)

    # Action based on result
    if llm_result == 1:
        try:
            await bot.delete_message(chat.id, message.message_id)
            await bot.ban_chat_member(chat.id, user.id)
        except TelegramError as e:
            logger.error("Failed to take action: %s", e)

    # Log into DB
    await app.state.db.execute(
        """
        INSERT INTO logs(user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, llm_result, latency_ms)
        VALUES($1, $2, $3, $4, $5, $6, $7)
        """,
        user.id, chat.id, msg_text, link_in_bio, avatar_unsafe, llm_result, latency_ms,
    )

    return JSONResponse({"ok": True})

@app.get("/stats")
async def stats(payload: dict = Depends(verify_jwt)):
    """
    Return statistics about spam removed.
    """
    row = await app.state.db.fetchrow(
        "SELECT COUNT(*) AS spam_removed FROM logs WHERE llm_result = 1"
    )
    return {"spam_removed": row["spam_removed"], "period": "all"}

@app.post("/toggle")
async def toggle(request: Request, payload: dict = Depends(verify_jwt)):
    """
    Toggle the bot on or off.
    """
    data = await request.json()
    enabled = data.get("enabled", True)
    # TODO: persist this state to DB or memory
    return {"enabled": enabled}

def main():
    import uvicorn

    uvicorn.run(
        "bot.main:app",
        host=os.getenv("UVICORN_HOST", "0.0.0.0"),
        port=int(os.getenv("UVICORN_PORT", "8000")),
        log_level=config.LOG_LEVEL,
    )

if __name__ == "__main__":
    main()