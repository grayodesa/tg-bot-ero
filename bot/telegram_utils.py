"""
Telegram utilities for bot interaction.
"""
import re
import logging
from typing import Tuple, Optional

from telegram import Bot, Update, User, Chat
from telegram.error import TelegramError

# Configure logging
logger = logging.getLogger(__name__)


async def check_bio_for_links(bot: Bot, user_id: int) -> Tuple[str, bool]:
    """
    Check if a user's bio contains links.
    
    Args:
        bot: Telegram Bot instance
        user_id: Telegram user ID
        
    Returns:
        Tuple of (bio, link_in_bio)
    """
    try:
        chat_user = await bot.get_chat(user_id)
        bio = chat_user.bio or ""
    except TelegramError as e:
        logger.warning(f"Failed to get user bio: {e}")
        bio = ""
    
    link_in_bio = bool(re.search(r"https?://|t\.me/", bio))
    
    return bio, link_in_bio


async def take_action(bot: Bot, chat_id: int, message_id: int, user_id: int) -> bool:
    """
    Take action against a user (delete message and ban).
    
    Args:
        bot: Telegram Bot instance
        chat_id: Telegram chat ID
        message_id: Telegram message ID
        user_id: Telegram user ID
        
    Returns:
        Whether the action was successful
    """
    try:
        await bot.delete_message(chat_id, message_id)
        await bot.ban_chat_member(chat_id, user_id)
        return True
    except TelegramError as e:
        logger.error(f"Failed to take action: {e}")
        return False


def extract_user_and_chat(update: Update) -> Tuple[Optional[User], Optional[Chat]]:
    """
    Extract user and chat from an update.
    
    Args:
        update: Telegram Update object
        
    Returns:
        Tuple of (user, chat)
    """
    if update.message:
        return update.message.from_user, update.message.chat
    elif update.edited_message:
        return update.edited_message.from_user, update.edited_message.chat
    elif update.callback_query and update.callback_query.message:
        return update.callback_query.from_user, update.callback_query.message.chat
    else:
        return None, None