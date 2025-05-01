"""
Authentication module for JWT verification.
"""
import time
import hmac
import json
import base64
import hashlib
import logging
from typing import Dict, List, Optional

from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Configure logging
logger = logging.getLogger(__name__)

# Security dependency
security = HTTPBearer()


def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    jwt_secret: str = "",
    admin_ids: List[int] = []
) -> Dict:
    """
    Verify JWT from Authorization header and ensure the admin_id is allowed.
    
    Args:
        credentials: HTTP Authorization credentials
        jwt_secret: Secret key for JWT verification
        admin_ids: List of allowed admin IDs
        
    Returns:
        Decoded JWT payload
    """
    token = credentials.credentials
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64.urlsafe_b64decode(signature_b64 + '==')
        expected = hmac.new(jwt_secret.encode(), signing_input, hashlib.sha256).digest()
        
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid token signature")
        
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
        
        # Check if token has expired
        if 'exp' in payload and payload['exp'] < time.time():
            raise HTTPException(status_code=401, detail="Token has expired")
        
        if payload.get('admin_id') not in admin_ids:
            raise HTTPException(status_code=403, detail="Forbidden")
        
        return payload
    except Exception as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token format or signature")


def create_jwt(admin_id: int, jwt_secret: str, expiration_seconds: int = None) -> str:
    """
    Create a JWT token for admin authentication.
    
    Args:
        admin_id: Admin user ID
        jwt_secret: Secret key for JWT signing
        expiration_seconds: Token expiration time in seconds (default: from config)
        
    Returns:
        JWT token string
    """
    from config import config
    if expiration_seconds is None:
        expiration_seconds = config.JWT_EXPIRATION
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "admin_id": admin_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + expiration_seconds
    }
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(jwt_secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def validate_telegram_request(token: str, request_header: Dict) -> bool:
    """
    Validate that a request comes from Telegram.
    
    Args:
        token: Webhook secret token
        request_header: Request headers
        
    Returns:
        Whether the request is valid
    """
    if 'X-Telegram-Bot-Api-Secret-Token' not in request_header:
        return False
    
    secret = request_header.get('X-Telegram-Bot-Api-Secret-Token')
    return hmac.compare_digest(secret, token)