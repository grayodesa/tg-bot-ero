"""
Low-quality spam classification module using OpenAI's GPT models.

Detects messages that are senseless, very short, or don't add meaningful information
to the chat, especially when combined with erotic/NSFW avatars or links in bio.
"""
import time
import logging
from typing import Tuple, Optional

from openai import OpenAI

# Configure logging
logger = logging.getLogger(__name__)


async def classify_message(
    openai_client: OpenAI,
    model: str,
    user_name: str,
    bio: str,
    message: str,
    avatar_suspicious: bool = False,
    avatar_unsafe: bool = False
) -> Tuple[int, int]:
    """
    Classify a message as low-quality spam or not using OpenAI's GPT models.
    
    Detects messages that are senseless, very short, or don't add meaningful information
    to the chat, especially when combined with erotic/NSFW avatars or links in bio.
    
    Args:
        openai_client: OpenAI client instance
        model: Model name to use
        user_name: User's first name
        bio: User's bio
        message: Message text
        avatar_suspicious: Whether the avatar is suspicious
        avatar_unsafe: Whether the avatar is unsafe
        
    Returns:
        Tuple of (llm_result, latency_ms)
    """
    # Build the prompt
    prompt = (
        f"Determine if this message is low-quality spam (0-not spam, 1-spam).\n"
        f"Classify as spam (1) if the message is senseless, very short, or doesn't add any meaningful information to the chat, "
        f"especially when combined with an erotic/NSFW/suspicious avatar and/or there is a link in the bio.\n\n"
        f"Name: {user_name}\n"
        f"Bio: {bio}\n"
        f"Message: {message}"
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
        response = openai_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        content = response.choices[0].message.content.strip()
        # Extract first digit (0 or 1) from response, or default to 0
        answer = next((char for char in content if char in '01'), '0')
        llm_result = int(answer)
    except Exception as e:
        logger.error("LLM call failed: %s", e)
        llm_result = 0
    
    latency_ms = int((time.time() - start) * 1000)
    
    return llm_result, latency_ms


def needs_classification(link_in_bio: bool, avatar_suspicious: bool) -> bool:
    """
    Determine if a message needs classification.
    
    Args:
        link_in_bio: Whether the user has a link in their bio
        avatar_suspicious: Whether the avatar is suspicious
        
    Returns:
        Whether the message needs classification
    """
    return link_in_bio or avatar_suspicious