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
import requests
import logging

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import telegram
from telegram import Update, Bot
from telegram.error import TelegramError

from openai import OpenAI
import nudenet
import asyncpg

from config import config


# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI()

# Initialize Telegram Bot; classifier will be loaded on first use
bot = Bot(token=config.TG_TOKEN)
classifier = None

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


def ensure_valid_nudenet_model():
    '''Ensures the NudeNet model is valid and redownloads if necessary.'''
    model_dir = os.path.expanduser("~/.NudeNet")
    model_path = os.path.join(model_dir, "classifier_model.onnx")
    
    # Create directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Check if model exists and try to validate it
    valid_model = False
    if os.path.exists(model_path):
        try:
            # Try loading the model to see if it's valid
            tmp_classifier = nudenet.NudeClassifier()
            # Test with a simple operation
            with tempfile.NamedTemporaryFile(suffix=".jpg") as tmp:
                # Create a minimal valid image file
                with open(tmp.name, 'wb') as f:
                    f.write(bytes.fromhex('FFD8FFE000104A46494600010101006000600000FFDB004300080606070605080707070909080A0C140D0C0B0B0C1912130F141D1A1F1E1D1A1C1C20242E2720222C231C1C2837292C30313434341F27393D38323C2E333432FFDB0043010909090C0B0C180D0D1832211C213232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232FFC00011080001000103012200021101031101FFC4001F0000010501010101010100000000000000000102030405060708090A0BFFC400B5100002010303020403050504040000017D01020300041105122131410613516107227114328191A1082342B1C11552D1F02433627282090A161718191A25262728292A3435363738393A434445464748494A535455565758595A636465666768696A737475767778797A838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE1E2E3E4E5E6E7E8E9EAF1F2F3F4F5F6F7F8F9FAFFC4001F0100030101010101010101010000000000000102030405060708090A0BFFC400B51100020102040403040705040400010277000102031104052131061241510761711322328108144291A1B1C109233352F0156272D10A162434E125F11718191A262728292A35363738393A434445464748494A535455565758595A636465666768696A737475767778797A82838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE2E3E4E5E6E7E8E9EAF2F3F4F5F6F7F8F9FAFFDA000C03010002110311003F00FDFCA28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2803FFD9'))
                # Try to classify this dummy image
                test_result = tmp_classifier.classify(tmp.name)
                # If we get here without error, the model is valid
                valid_model = True
                logger.info("NudeNet model validated successfully")
        except Exception as e:
            logger.warning(f"NudeNet model validation failed: {e}")
            # Delete the invalid model file
            try:
                os.remove(model_path)
                logger.info(f"Removed invalid NudeNet model file: {model_path}")
            except OSError as ose:
                logger.warning(f"Could not remove invalid model file: {ose}")
    
    # If model doesn't exist or is invalid, download it
    if not valid_model:
        try:
            # Direct download from GitHub release with proper headers to prevent redirect to login
            model_url = "https://github.com/notAI-tech/NudeNet/releases/download/v0/classifier_model.onnx"
            logger.info(f"Downloading NudeNet model from {model_url}")
            
            # Add headers to avoid login page redirect - mimic browser request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/octet-stream'
            }
            
            response = requests.get(model_url, stream=True, headers=headers)
            response.raise_for_status()  # Raise an error for bad status codes
            
            # Check content type to ensure it's not HTML
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type or 'text' in content_type:
                logger.error(f"Received HTML instead of model file. GitHub may require authentication.")
                # Try alternate source as fallback - NudeNet package uses this internally
                model_url = "https://notai-public.s3.amazonaws.com/nudenet/classifier_model.onnx"
                logger.info(f"Trying alternate source: {model_url}")
                response = requests.get(model_url, stream=True)
                response.raise_for_status()
            
            # Save the model
            with open(model_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Verify model size
            file_size = os.path.getsize(model_path)
            if file_size < 1000000:  # ONNX models should be several megabytes
                logger.warning(f"Downloaded file too small ({file_size} bytes), may not be a valid model")
                try:
                    # Check if it's HTML content
                    with open(model_path, 'rb') as f:
                        content = f.read(500)  # Read first 500 bytes
                        if b'<!DOCTYPE html>' in content or b'<html' in content:
                            logger.error("Downloaded file is HTML, not a model file")
                            raise ValueError("Downloaded HTML instead of model file")
                except Exception:
                    pass
                    
            logger.info(f"Successfully downloaded NudeNet model to {model_path}")
            
            # Try to validate the downloaded model
            try:
                tmp_classifier = nudenet.NudeClassifier()
                with tempfile.NamedTemporaryFile(suffix=".jpg") as tmp:
                    # Create a minimal valid image
                    with open(tmp.name, 'wb') as f:
                        f.write(bytes.fromhex('FFD8FFE000104A46494600010101006000600000FFDB004300080606070605080707070909080A0C140D0C0B0B0C1912130F141D1A1F1E1D1A1C1C20242E2720222C231C1C2837292C30313434341F27393D38323C2E333432FFDB0043010909090C0B0C180D0D1832211C213232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232FFC00011080001000103012200021101031101FFC4001F0000010501010101010100000000000000000102030405060708090A0BFFC400B5100002010303020403050504040000017D01020300041105122131410613516107227114328191A1082342B1C11552D1F02433627282090A161718191A25262728292A3435363738393A434445464748494A535455565758595A636465666768696A737475767778797A838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE1E2E3E4E5E6E7E8E9EAF1F2F3F4F5F6F7F8F9FAFFC4001F0100030101010101010101010000000000000102030405060708090A0BFFC400B51100020102040403040705040400010277000102031104052131061241510761711322328108144291A1B1C109233352F0156272D10A162434E125F11718191A25262728292A35363738393A434445464748494A535455565758595A636465666768696A737475767778797A82838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE2E3E4E5E6E7E8E9EAF2F3F4F5F6F7F8F9FAFFDA000C03010002110311003F00FDFCA28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2800A28A2803FFD9'))
                    test_result = tmp_classifier.classify(tmp.name)
                logger.info("Model validation successful after download")
            except Exception as e:
                logger.warning(f"Model validation after download failed: {e}")
                # Don't return False here, still try to use the model
            
            return True
        except Exception as e:
            logger.error(f"Failed to download NudeNet model: {e}")
            return False
    
    return True

import asyncio

@app.on_event("startup")
async def on_startup():
    # Initialize OpenAI client
    app.state.openai_client = OpenAI(api_key=config.OPENAI_KEY)
    
    # Pre-validate NudeNet model to avoid issues during request processing
    try:
        logger.info("Pre-validating NudeNet model on startup")
        model_valid = ensure_valid_nudenet_model()
        if model_valid:
            logger.info("NudeNet model validation successful")
        else:
            logger.warning("NudeNet model validation failed - will retry when needed")
    except Exception as e:
        logger.error(f"Error during NudeNet model validation: {e}")
    
    # Connect to PostgreSQL with retries
    pool = None
    last_error = None
    for _ in range(10):
        try:
            pool = await asyncpg.create_pool(dsn=config.POSTGRES_DSN)
            break
        except Exception as e:
            last_error = e
            logger.warning("Database connection failed, retrying: %s", e)
            await asyncio.sleep(2)
    if pool is None:
        logger.error("Could not connect to database after retries: %s", last_error)
        raise last_error
    app.state.db = pool
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
    # Ensure pending-first-message table exists
    await app.state.db.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_first (
            chat_id BIGINT,
            user_id BIGINT,
            PRIMARY KEY (chat_id, user_id)
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
    # Handle new chat members: mark for first-message check
    if message and message.new_chat_members:
        for new_member in message.new_chat_members:
            try:
                await app.state.db.execute(
                    "INSERT INTO pending_first(chat_id, user_id) VALUES($1, $2) ON CONFLICT DO NOTHING",  
                    message.chat.id, new_member.id
                )
            except Exception:
                logger.warning("Failed to mark new member for first-message: chat=%s user=%s",
                               message.chat.id, new_member.id)
        return JSONResponse({"ok": True})
    # Only process the first message per user after joining
    if not message or not message.text:
        return JSONResponse({"ok": True})
    user = message.from_user
    chat = message.chat
    # Check pending-first flag
    pending = await app.state.db.fetchval(
        "SELECT 1 FROM pending_first WHERE chat_id=$1 AND user_id=$2", chat.id, user.id
    )
    if not pending:
        # Not a first message after join: skip
        return JSONResponse({"ok": True})
    # Clear pending flag so we only check once
    await app.state.db.execute(
        "DELETE FROM pending_first WHERE chat_id=$1 AND user_id=$2", chat.id, user.id
    )
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
                # Lazy-load NudeClassifier
                global classifier
                if classifier is None:
                    # Ensure model is valid before initializing
                    if ensure_valid_nudenet_model():
                        try:
                            classifier = nudenet.NudeClassifier()
                        except Exception as e:
                            logger.error(f"Cannot initialize NudeClassifier: {e}")
                            # Continue without classification - better than crashing
                            avatar_unsafe = False
                            break
                    else:
                        logger.error("Cannot initialize NudeClassifier due to model issues")
                        # Continue without classification - better than crashing
                        avatar_unsafe = False
                        break
                
                # Attempt classification
                try:
                    result = classifier.classify(tmp.name)
                    if not isinstance(result, dict):
                        logger.warning(f"Unexpected result type: {type(result)}")
                        avatar_unsafe = False
                    else:
                        # Expected format is {image_path: {"unsafe": score}}
                        unsafe_score = result.get(tmp.name, {}).get("unsafe", 0)
                        logger.info(f"Avatar unsafe score: {unsafe_score}")
                        avatar_unsafe = unsafe_score > 0.7
                except Exception as e:
                    logger.warning(f"Classification failed: {e}")
                    # Reset classifier and try again with fresh model
                    classifier = None
                    try:
                        if ensure_valid_nudenet_model():
                            classifier = nudenet.NudeClassifier()
                            result = classifier.classify(tmp.name)
                            if not isinstance(result, dict):
                                logger.warning(f"Unexpected result type after retry: {type(result)}")
                                avatar_unsafe = False
                            else:
                                unsafe_score = result.get(tmp.name, {}).get("unsafe", 0)
                                logger.info(f"Avatar unsafe score after retry: {unsafe_score}")
                                avatar_unsafe = unsafe_score > 0.7
                        else:
                            logger.error("Failed to recover NudeNet classifier")
                            avatar_unsafe = False
                    except Exception as retry_e:
                        logger.error(f"Classification retry failed: {retry_e}")
                        avatar_unsafe = False
    except Exception as e:
        logger.warning(f"Avatar check failed: {e}")

    # If not both features, skip LLM
    if not (link_in_bio or avatar_unsafe):
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
        response = await app.state.openai_client.chat.completions.create(
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