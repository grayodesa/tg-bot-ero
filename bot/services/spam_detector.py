"""
Spam detection service combining various checks.
"""
import logging
import time
from typing import Dict, Tuple, Optional, Any

from telegram import Bot
from openai import OpenAI

from bot.avatar_analyzer import check_avatar
from bot.spam_classifier import classify_message
from bot.telegram_utils import check_bio_for_links
from bot.cache import CacheManager, async_cached
from bot.metrics import (
    timed_execution, increment_counter,
    spam_detected, avatar_unsafe, avatar_suspicious,
    llm_latency, avatar_check_latency
)

logger = logging.getLogger(__name__)


class SpamDetector:
    """Service for detecting spam in Telegram messages."""
    
    def __init__(self, bot: Bot, openai_client: OpenAI, model_name: str, cache_manager: Optional[CacheManager] = None):
        """
        Initialize the spam detector service.
        
        Args:
            bot: Telegram Bot instance
            openai_client: OpenAI client
            model_name: OpenAI model name to use
            cache_manager: Optional cache manager for caching
        """
        self.bot = bot
        self.openai_client = openai_client
        self.model_name = model_name
        self.cache = cache_manager
    
    async def analyze_user(self, user_id: int, first_name: str, message: str) -> Dict[str, Any]:
        """
        Perform comprehensive spam analysis on a user.
        
        Args:
            user_id: Telegram user ID
            first_name: User's first name
            message: The message to analyze
        
        Returns:
            Dict containing analysis results including spam decision
        """
        # Check bio for links
        bio, link_in_bio = await check_bio_for_links(self.bot, user_id)
        
        # Check avatar for NSFW content
        with timed_execution(avatar_check_latency):
            avatar_unsafe_result, avatar_suspicious_result = await check_avatar(self.bot, user_id)
        
        # Update metrics
        if avatar_unsafe_result:
            increment_counter(avatar_unsafe)
        if avatar_suspicious_result:
            increment_counter(avatar_suspicious)
        
        # If avatar is unsafe, mark as spam immediately
        if avatar_unsafe_result:
            return {
                'is_spam': True,
                'reason': 'unsafe_avatar',
                'avatar_unsafe': avatar_unsafe_result,
                'avatar_suspicious': avatar_suspicious_result,
                'link_in_bio': link_in_bio,
                'llm_result': 1,
                'latency_ms': 0
            }
        
        # If no suspicious indicators, skip LLM
        if not self._needs_classification(link_in_bio, avatar_suspicious_result):
            return {
                'is_spam': False,
                'reason': 'no_indicators',
                'avatar_unsafe': avatar_unsafe_result,
                'avatar_suspicious': avatar_suspicious_result,
                'link_in_bio': link_in_bio,
                'llm_result': 0,
                'latency_ms': 0
            }
        
        # LLM classification
        with timed_execution(llm_latency):
            llm_result, latency_ms = await classify_message(
                self.openai_client,
                self.model_name,
                first_name,
                bio,
                message,
                avatar_suspicious_result,
                avatar_unsafe_result
            )
        
        # Update metrics if spam detected
        if llm_result == 1:
            increment_counter(spam_detected)
        
        return {
            'is_spam': llm_result == 1,
            'reason': 'llm_classification',
            'avatar_unsafe': avatar_unsafe_result,
            'avatar_suspicious': avatar_suspicious_result,
            'link_in_bio': link_in_bio,
            'llm_result': llm_result,
            'latency_ms': latency_ms
        }
    
    def _needs_classification(self, link_in_bio: bool, avatar_suspicious: bool) -> bool:
        """
        Determine if message needs LLM classification based on indicators.
        
        Args:
            link_in_bio: Whether user has links in bio
            avatar_suspicious: Whether avatar is suspicious
            
        Returns:
            Whether to proceed with LLM classification
        """
        return link_in_bio or avatar_suspicious