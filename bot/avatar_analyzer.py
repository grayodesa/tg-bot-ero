"""
Avatar analysis module for detecting NSFW content in user profile pictures.
"""
import threading
import logging
from typing import Dict, Tuple, Optional, Any, ClassVar

from telegram import Bot
from telegram.error import TelegramError
from nudenet import NudeDetector

from config import config
from bot.utils.file_utils import secure_tempfile
from bot.cache import async_cached

# Configure logging
logger = logging.getLogger(__name__)


class NudeNetSingleton:
    """
    Singleton pattern for NudeNet detector to ensure it's initialized only once.
    """
    _instance: ClassVar[Optional['NudeNetSingleton']] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()
    
    detector: Optional[NudeDetector] = None
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                logger.info("Creating NudeNetSingleton instance")
                cls._instance = super(NudeNetSingleton, cls).__new__(cls)
                cls._instance.detector = None
            return cls._instance
    
    def get_detector(self) -> Optional[NudeDetector]:
        """
        Get or initialize the NudeDetector instance.
        """
        if self.detector is None:
            self.initialize_detector()
        return self.detector
    
    def initialize_detector(self) -> Optional[NudeDetector]:
        """
        Initialize the NudeDetector.
        """
        try:
            logger.info("Initializing NudeDetector")
            # Simple initialization - the 320n model is included in the package
            self.detector = NudeDetector()
            logger.info("NudeDetector initialized successfully")
            return self.detector
        except Exception as e:
            logger.error(f"Failed to initialize NudeDetector: {e}")
            self.detector = None
            return None
    
    def reset_detector(self) -> Optional[NudeDetector]:
        """
        Reset the detector instance and reinitialize it.
        """
        self.detector = None
        return self.get_detector()


# Create the singleton instance
nude_net = NudeNetSingleton()


@async_cached("avatar", config.AVATAR_CACHE_TTL)
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
    logger.info(f"Analyzing avatar for user {user_id}")
    avatar_unsafe = False
    avatar_suspicious = False
    
    try:
        photos = await bot.get_user_profile_photos(user_id, limit=1)
        if photos.total_count > 0:
            file_id = photos.photos[0][-1].file_id
            tg_file = await bot.get_file(file_id)
            
            # Use secure_tempfile context manager to ensure cleanup
            with secure_tempfile(suffix=".jpg", prefix=f"avatar_{user_id}_") as temp_path:
                await tg_file.download_to_drive(temp_path)
                
                # Get NudeDetector instance
                detector = nude_net.get_detector()
                
                # Only attempt detection if detector was initialized successfully
                if detector is not None:
                    try:
                        # Run detection
                        avatar_unsafe, avatar_suspicious = _run_detection(temp_path, detector)
                    except Exception as e:
                        logger.warning(f"Detection failed: {e}")
                        # Reset detector and try again with fresh instance
                        detector = nude_net.reset_detector()
                        
                        if detector:
                            # Retry detection
                            avatar_unsafe, avatar_suspicious = _run_detection(temp_path, detector)
                        else:
                            logger.error("Failed to recover NudeNet detector")
                            avatar_unsafe = False
                            avatar_suspicious = False
                else:
                    logger.error("NudeDetector not available")
    except Exception as e:
        logger.warning(f"Avatar check failed: {e}")
    
    return avatar_unsafe, avatar_suspicious


def _run_detection(image_path: str, detector: NudeDetector) -> Tuple[bool, bool]:
    """
    Run NudeNet detection on an image.
    
    Args:
        image_path: Path to the image file
        detector: NudeDetector instance
        
    Returns:
        Tuple of (avatar_unsafe, avatar_suspicious)
    """
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
            elif detection['class'] in ["FEMALE_BREAST_COVERED", "BUTTOCKS_COVERED"] and detection['score'] > 0.2:
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