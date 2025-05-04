"""
Enhanced security module for JWT and webhook validation.
"""
import os
import hmac
import hashlib
import logging
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)
security = HTTPBearer()


class JWTHandler:
    """Handler for JWT creation and verification using PyJWT."""
    
    def __init__(self, secret: str, algorithm: str = "HS256"):
        self.secret = secret
        self.algorithm = algorithm
    
    def create_token(self, admin_id: int, expiration_seconds: int = 86400) -> str:
        """Create a JWT token with expiration."""
        now = datetime.now(timezone.utc)
        payload = {
            "admin_id": admin_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expiration_seconds)).timestamp()),
            "jti": os.urandom(16).hex()  # Unique token ID
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)
    
    def create_refresh_token(self, admin_id: int, expiration_seconds: int = 604800) -> str:
        """Create a refresh token with longer expiration (default: 7 days)."""
        now = datetime.now(timezone.utc)
        payload = {
            "admin_id": admin_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expiration_seconds)).timestamp()),
            "jti": os.urandom(16).hex(),  # Unique token ID
            "type": "refresh"
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)
    
    def verify_token(self, token: str, admin_ids: List[int]) -> Dict:
        """Verify JWT token and check if admin_id is authorized."""
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
            
            if payload.get("admin_id") not in admin_ids:
                raise HTTPException(status_code=403, detail="Forbidden")
            
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def refresh_access_token(self, refresh_token: str, admin_ids: List[int], expiration_seconds: int = 86400) -> str:
        """Generate new access token from refresh token."""
        try:
            payload = jwt.decode(refresh_token, self.secret, algorithms=[self.algorithm])
            
            if payload.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid refresh token")
                
            if payload.get("admin_id") not in admin_ids:
                raise HTTPException(status_code=403, detail="Forbidden")
            
            # Create new access token
            return self.create_token(payload["admin_id"], expiration_seconds)
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Refresh token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")


class WebhookValidator:
    """Validator for Telegram webhook requests."""
    
    def validate_telegram_webhook(self, request: Request, secret: str) -> bool:
        """
        Validate that a request comes from Telegram using the secret token.
        
        Args:
            request: FastAPI request object
            secret: Webhook secret token
            
        Returns:
            Whether the request is valid
        """
        if not secret:
            # If no secret configured, skip validation
            return True
            
        if 'X-Telegram-Bot-Api-Secret-Token' not in request.headers:
            logger.warning("Missing Telegram secret token header")
            return False
        
        received_token = request.headers.get('X-Telegram-Bot-Api-Secret-Token')
        return hmac.compare_digest(received_token, secret)
    
    async def validate_webhook_data(self, request: Request) -> Dict:
        """
        Parse and validate webhook request data.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Parsed request data
        
        Raises:
            HTTPException: If validation fails
        """
        try:
            data = await request.json()
            return data
        except Exception as e:
            logger.error(f"Failed to parse webhook data: {e}")
            raise HTTPException(status_code=400, detail="Invalid request data")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for rate limiting endpoints.
    """
    
    def __init__(
        self, 
        app, 
        rate_limit_per_minute: int = 60,
        endpoint_filter: Optional[Callable[[str], bool]] = None
    ):
        super().__init__(app)
        self.rate_limit = rate_limit_per_minute
        self.window = 60  # 1 minute in seconds
        self.endpoint_filter = endpoint_filter or (lambda x: True)
        self.clients: Dict[str, List[float]] = {}
    
    async def dispatch(self, request: Request, call_next):
        """
        Process each request with rate limiting.
        """
        if not self.endpoint_filter(request.url.path):
            # Skip rate limiting for this endpoint
            return await call_next(request)
            
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit
        now = time.time()
        
        # Initialize or update client's request timestamps
        if client_ip not in self.clients:
            self.clients[client_ip] = []
        
        # Remove timestamps older than our window
        self.clients[client_ip] = [ts for ts in self.clients[client_ip] if now - ts < self.window]
        
        # Check if client exceeded rate limit
        if len(self.clients[client_ip]) >= self.rate_limit:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return HTTPException(
                status_code=429, 
                detail="Too many requests. Please try again later."
            ).response
        
        # Add current timestamp
        self.clients[client_ip].append(now)
        
        # Process request
        return await call_next(request)


# Dependency for JWT verification
async def verify_jwt_dependency(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    jwt_secret: str = None,
    admin_ids: List[int] = None
) -> Dict:
    """
    Dependency for verifying JWT tokens in API routes.
    
    Args:
        credentials: HTTP Authorization credentials
        jwt_secret: Secret key for JWT verification
        admin_ids: List of allowed admin IDs
        
    Returns:
        Decoded JWT payload
    """
    if not jwt_secret or not admin_ids:
        from config import config
        jwt_secret = jwt_secret or config.JWT_SECRET
        admin_ids = admin_ids or config.ADMIN_IDS
        
    handler = JWTHandler(jwt_secret)
    return handler.verify_token(credentials.credentials, admin_ids)


# Dependency for rate limiting
async def rate_limit_dependency(request: Request):
    """
    Simple in-memory rate limiter for webhook endpoint.
    """
    # Implementation is handled by RateLimitMiddleware
    pass