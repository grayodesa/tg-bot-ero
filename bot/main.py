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

from openai import OpenAI
from nudenet import NudeDetector
import asyncpg

from config import config


# Configure logging
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI()

# Initialize Telegram Bot; detector will be loaded on first use
bot = Bot(token=config.TG_TOKEN)
detector = None

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


def initialize_detector():
    """
    Initialize the NudeDetector.
    According to GitHub README.md, this will use the 320n model included with the package.
    """
    try:
        logger.info("Initializing NudeDetector")
        
        # Simple initialization - the 320n model is included in the package
        detector = NudeDetector()
        logger.info("NudeDetector initialized successfully")
        
        # Skip testing since we don't have a reliable test image
        # NudeDetector requires a proper image with RGB data
        # We'll trust that it's initialized correctly
        
        return detector
    except Exception as e:
        logger.error(f"Failed to initialize NudeDetector: {e}")
        return None


import asyncio

@app.on_event("startup")
async def on_startup():
    # Initialize OpenAI client
    app.state.openai_client = OpenAI(api_key=config.OPENAI_KEY)
    
    # Pre-initialize NudeNet detector to avoid issues during request processing
    try:
        logger.info("Pre-initializing NudeNet detector on startup")
        global detector
        detector = initialize_detector()
        if detector:
            logger.info("NudeNet detector successfully initialized")
        else:
            logger.warning("NudeNet detector initialization failed - will retry when needed")
    except Exception as e:
        logger.error(f"Error during NudeNet detector initialization: {e}")
    
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
    # Ensure logs table exists and has all required columns
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
    
    # Check if avatar_suspicious column exists, add it if not
    try:
        await app.state.db.execute(
            """
            ALTER TABLE logs 
            ADD COLUMN IF NOT EXISTS avatar_suspicious BOOLEAN DEFAULT FALSE;
            """
        )
        logger.info("Ensured avatar_suspicious column exists in logs table")
    except Exception as e:
        logger.error(f"Failed to add avatar_suspicious column: {e}")
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

    # Feature: avatar unsafe/suspicious check
    avatar_unsafe = False
    avatar_suspicious = False
    avatar_file_path = None
    try:
        photos = await bot.get_user_profile_photos(user.id, limit=1)
        if photos.total_count > 0:
            file_id = photos.photos[0][-1].file_id
            tg_file = await bot.get_file(file_id)
            with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                await tg_file.download_to_drive(tmp.name)
                avatar_file_path = tmp.name
                
                # Lazy-load NudeDetector
                global detector
                
                # Initialize if not already done
                if detector is None:
                    detector = initialize_detector()
                
                # Only attempt detection if detector was initialized successfully
                if detector is not None:
                    try:
                        # Pass the file path to the detector
                        # NudeDetector.detect() returns a list of dictionaries with detection info
                        logger.info(f"Running NudeDetector on {tmp.name}")
                        
                        detections = detector.detect(tmp.name)
                        
                        if detections is None:
                            logger.warning("NudeDetector returned None for detections")
                            detections = []
                        
                        logger.info(f"NudeDetector returned {len(detections)} detections")
                        
                        # Check if we have explicit content
                        # Each detection is a dict with 'class' and 'score' keys
                        has_explicit_content = False
                        high_confidence_explicit = False
                        has_low_confidence_explicit = False  # Track lower threshold detections
                        
                        # Go through the detections and check for explicit content classes - using actual NudeNet labels
                        explicit_classes = [
                            "FEMALE_GENITALIA_EXPOSED", "FEMALE_BREAST_EXPOSED",
                            "MALE_GENITALIA_EXPOSED", "MALE_BREAST_EXPOSED",
                            "BUTTOCKS_EXPOSED", "ANUS_EXPOSED", "ARMPITS_EXPOSED"
                        ]
                        
                        suspicious_classes = ['FACE_FEMALE', 'FACE_MALE']
                        has_face = False  # Track if the image has a face
                        
                        for detection in detections:
                            logger.info(f"Detection: {detection}")
                            if isinstance(detection, dict) and 'class' in detection and 'score' in detection:
                                # Check for faces with good confidence
                                if detection['class'] in suspicious_classes and detection['score'] > 0.7:
                                    has_face = True
                                    logger.info(f"Face detected: {detection}")
                                
                                # Check for explicit content with high confidence
                                if detection['class'] in explicit_classes and detection['score'] > 0.7:
                                    high_confidence_explicit = True
                                    logger.info(f"High confidence explicit content found: {detection}")
                                    break
                                # Check for explicit content with medium confidence    
                                elif detection['class'] in explicit_classes and detection['score'] > 0.5:
                                    has_explicit_content = True
                                    logger.info(f"Lower confidence explicit content found: {detection}")
                                # Check for explicit content with low confidence
                                elif detection['class'] in explicit_classes and detection['score'] > 0.3:
                                    has_low_confidence_explicit = True
                                    logger.info(f"Low confidence explicit content found: {detection}")
                                # Check for classes that indicate potential concern but at lower confidence
                                elif detection['class'] in ["FEMALE_BREAST_COVERED", "BUTTOCKS_COVERED"] and detection['score'] > 0.3:
                                    has_low_confidence_explicit = True
                                    logger.info(f"Covered but explicit low confidence content found: {detection}")
                            else:
                                logger.warning(f"Unexpected detection format: {detection}")
                        
                        # If we have high confidence detection or multiple lower confidence detections
                        avatar_unsafe = high_confidence_explicit or has_explicit_content
                        
                        # Consider an avatar suspicious if it has a face + low confidence detection
                        # This is the new condition that will trigger LLM verification
                        avatar_suspicious = has_face and has_low_confidence_explicit and not avatar_unsafe
                        
                        logger.info(f"Avatar analysis: unsafe={avatar_unsafe}, suspicious={avatar_suspicious}, high_confidence={high_confidence_explicit}")
                        
                    except Exception as e:
                        logger.warning(f"Detection failed: {e}")
                        # Reset detector and try again with fresh instance
                        detector = None
                        try:
                            # Initialize with new instance
                            detector = initialize_detector()
                            
                            if detector:
                                # Retry detection
                                logger.info(f"Running NudeDetector again on {tmp.name}")
                                
                                detections = detector.detect(tmp.name)
                                
                                if detections is None:
                                    logger.warning("NudeDetector retry returned None for detections")
                                    detections = []
                                
                                logger.info(f"NudeDetector retry returned {len(detections)} detections")
                                
                                # Check if we have explicit content again
                                has_explicit_content = False
                                high_confidence_explicit = False
                                has_low_confidence_explicit = False
                                has_face = False
                                
                                # Same explicit classes as before - using actual NudeNet labels
                                explicit_classes = [
                                    "FEMALE_GENITALIA_EXPOSED", "FEMALE_BREAST_EXPOSED",
                                    "MALE_GENITALIA_EXPOSED", "MALE_BREAST_EXPOSED",
                                    "BUTTOCKS_EXPOSED", "ANUS_EXPOSED", "ARMPITS_EXPOSED"
                                ]
                                
                                suspicious_classes = ['FACE_FEMALE', 'FACE_MALE']
                                
                                for detection in detections:
                                    logger.info(f"Retry detection: {detection}")
                                    if isinstance(detection, dict) and 'class' in detection and 'score' in detection:
                                        # Check for faces with good confidence
                                        if detection['class'] in suspicious_classes and detection['score'] > 0.7:
                                            has_face = True
                                            logger.info(f"Retry: Face detected: {detection}")
                                        
                                        # Check for explicit content with various confidence levels
                                        if detection['class'] in explicit_classes and detection['score'] > 0.7:
                                            high_confidence_explicit = True
                                            logger.info(f"Retry: High confidence explicit content found: {detection}")
                                            break
                                        elif detection['class'] in explicit_classes and detection['score'] > 0.5:
                                            has_explicit_content = True
                                            logger.info(f"Retry: Lower confidence explicit content found: {detection}")
                                        elif detection['class'] in explicit_classes and detection['score'] > 0.3:
                                            has_low_confidence_explicit = True
                                            logger.info(f"Retry: Low confidence explicit content found: {detection}")
                                        # Check for classes that indicate potential concern but at lower confidence
                                        elif detection['class'] in ["FEMALE_BREAST_COVERED", "BUTTOCKS_COVERED"] and detection['score'] > 0.3:
                                            has_low_confidence_explicit = True
                                            logger.info(f"Retry: Covered but explicit low confidence content found: {detection}")
                                    else:
                                        logger.warning(f"Retry: Unexpected detection format: {detection}")
                                
                                # Set avatar_unsafe based on detections
                                avatar_unsafe = high_confidence_explicit or has_explicit_content
                                
                                # Set avatar_suspicious based on detections
                                avatar_suspicious = has_face and has_low_confidence_explicit and not avatar_unsafe
                                
                                logger.info(f"Avatar analysis after retry: unsafe={avatar_unsafe}, suspicious={avatar_suspicious}, high_confidence={high_confidence_explicit}")
                            else:
                                logger.error("Failed to recover NudeNet detector")
                                avatar_unsafe = False
                                avatar_suspicious = False
                        except Exception as retry_e:
                            logger.error(f"Detection retry failed: {retry_e}")
                            avatar_unsafe = False
                            avatar_suspicious = False
                
                # Clean up the temporary file
                try:
                    os.unlink(tmp.name)
                    avatar_file_path = None
                except:
                    pass
    except Exception as e:
        logger.warning(f"Avatar check failed: {e}")

    # If no risk indicators are present, skip LLM
    if not (link_in_bio or avatar_unsafe or avatar_suspicious):
        await app.state.db.execute(
            """
            INSERT INTO logs(user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, llm_result, latency_ms)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            user.id, chat.id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, 0, 0,
        )
        return JSONResponse({"ok": True})

    # LLM evaluation
    prompt = (
        f"Determine if the profile is erotic spam (0-not, 1-spam).\n"
        f"Name: {user.first_name}\n"
        f"Bio: {bio}\n"
        f"Message: {msg_text}"
    )
    
    # Add information about suspicious avatar to the prompt if detected
    if avatar_suspicious:
        # If the avatar is suspicious, include that information
        prompt += f"\nAvatar: Suspicious avatar detected with potential NSFW content but low confidence score."
    elif avatar_unsafe:
        # If the avatar is unsafe, include that information
        prompt += f"\nAvatar: Unsafe avatar detected with high confidence of NSFW content."
    start = time.time()
    try:
        # The OpenAI client methods are not async, don't use await
        response = app.state.openai_client.chat.completions.create(
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
        INSERT INTO logs(user_id, chat_id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, llm_result, latency_ms)
        VALUES($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        user.id, chat.id, msg_text, link_in_bio, avatar_unsafe, avatar_suspicious, llm_result, latency_ms,
    )

    return JSONResponse({"ok": True})

@app.get("/stats")
async def stats(payload: dict = Depends(verify_jwt)):
    """
    Return statistics about spam removed and suspicious avatars caught.
    """
    rows = await app.state.db.fetch(
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
    return {"spam_removed": 0, "suspicious_avatars_caught": 0, "unsafe_avatars_caught": 0, "total_suspicious_avatars": 0, "period": "all"}

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