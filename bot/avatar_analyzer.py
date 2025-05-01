"""
Avatar analysis module for detecting NSFW content in user profile pictures.
"""
import os
import time
import tempfile
import logging
from typing import Dict, Tuple, Optional, Any

from telegram import Bot
from telegram.error import TelegramError
from nudenet import NudeDetector

from config import config

# Configure logging
logger = logging.getLogger(__name__)

# In-memory cache for avatar analysis results
AVATAR_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = config.AVATAR_CACHE_TTL  # From config

# NudeNet detector instance (lazy-loaded)
detector = None


def initialize_detector() -> Optional[NudeDetector]:
    """
    Initialize the NudeDetector.
    According to GitHub README.md, this will use the 320n model included with the package.
    """
    try:
        logger.info("Initializing NudeDetector")
        
        # Simple initialization - the 320n model is included in the package
        detector = NudeDetector()
        logger.info("NudeDetector initialized successfully")
        
        return detector
    except Exception as e:
        logger.error(f"Failed to initialize NudeDetector: {e}")
        return None


async def check_avatar(bot: Bot, user_id: int, force_refresh: bool = False) -> Tuple[bool, bool]:
    """
    Check if a user's avatar contains NSFW content.
    
    Args:
        bot: Telegram Bot instance
        user_id: Telegram user ID
        force_refresh: Whether to force a refresh of cached results
        
    Returns:
        Tuple of (avatar_unsafe, avatar_suspicious)
    """
    # Check cache first if not forcing refresh
    cache_key = f"avatar:{user_id}"
    if not force_refresh and cache_key in AVATAR_CACHE:
        if time.time() - AVATAR_CACHE[cache_key]['timestamp'] < CACHE_TTL:
            logger.info(f"Using cached avatar analysis for user {user_id}")
            return AVATAR_CACHE[cache_key]['result']
    
    avatar_unsafe = False
    avatar_suspicious = False
    avatar_file_path = None
    
    try:
        photos = await bot.get_user_profile_photos(user_id, limit=1)
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
                        # Run detection
                        avatar_unsafe, avatar_suspicious = _run_detection(tmp.name)
                    except Exception as e:
                        logger.warning(f"Detection failed: {e}")
                        # Reset detector and try again with fresh instance
                        detector = None
                        try:
                            # Initialize with new instance
                            detector = initialize_detector()
                            
                            if detector:
                                # Retry detection
                                avatar_unsafe, avatar_suspicious = _run_detection(tmp.name)
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
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary file: {e}")
    except Exception as e:
        logger.warning(f"Avatar check failed: {e}")
    
    # Cache the results
    result = (avatar_unsafe, avatar_suspicious)
    AVATAR_CACHE[cache_key] = {
        'timestamp': time.time(),
        'result': result
    }
    
    return result


def _run_detection(image_path: str) -> Tuple[bool, bool]:
    """
    Run NudeNet detection on an image.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        Tuple of (avatar_unsafe, avatar_suspicious)
    """
    global detector
    
    logger.info(f"Running NudeDetector on {image_path}")
    
    detections = detector.detect(image_path)
    
    if detections is None:
        logger.warning("NudeDetector returned None for detections")
        return False, False
    
    logger.info(f"NudeDetector returned {len(detections)} detections")
    
    # Check if we have explicit content
    has_explicit_content = False
    high_confidence_explicit = False
    has_low_confidence_explicit = False
    has_face = False
    
    # Define explicit and suspicious classes
    explicit_classes = [
        "FEMALE_GENITALIA_EXPOSED", "FEMALE_BREAST_EXPOSED",
        "MALE_GENITALIA_EXPOSED", "MALE_BREAST_EXPOSED",
        "BUTTOCKS_EXPOSED", "ANUS_EXPOSED", "ARMPITS_EXPOSED"
    ]
    
    suspicious_classes = ['FACE_FEMALE', 'FACE_MALE']
    
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
    
    # Consider avatar suspicious if it has any low confidence explicit content detection
    avatar_suspicious = has_low_confidence_explicit and not avatar_unsafe
    
    logger.info(f"Avatar analysis: unsafe={avatar_unsafe}, suspicious={avatar_suspicious}, high_confidence={high_confidence_explicit}")
    
    return avatar_unsafe, avatar_suspicious