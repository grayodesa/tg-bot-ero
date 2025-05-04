"""
Caching module for avatar analysis results and other data.
"""
import time
import json
import logging
from typing import Dict, Any, Optional, Callable, TypeVar, Awaitable
from functools import wraps

import redis
from redis.exceptions import RedisError

from config import config

logger = logging.getLogger(__name__)

T = TypeVar('T')  # For generic return types in decorators


class CacheManager:
    """Manages caching with Redis and in-memory fallback."""
    
    def __init__(self, redis_url: Optional[str] = None, ttl: int = 3600):
        """
        Initialize the cache manager.
        
        Args:
            redis_url: Redis URL for connection (optional)
            ttl: Cache TTL in seconds (default: 1 hour)
        """
        self.ttl = ttl
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.redis_client = None
        
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()
                logger.info("Redis cache initialized")
            except RedisError as e:
                logger.warning(f"Redis connection failed, using memory cache: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found or expired
        """
        # Try Redis first
        if self.redis_client:
            try:
                value = self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except RedisError as e:
                logger.error(f"Redis get error: {e}")
        
        # Fallback to memory cache
        cache_entry = self.memory_cache.get(key)
        if cache_entry and time.time() - cache_entry['timestamp'] < self.ttl:
            return cache_entry['value']
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Optional custom TTL in seconds
        """
        expiry = ttl if ttl is not None else self.ttl
        
        # Set in Redis
        if self.redis_client:
            try:
                self.redis_client.setex(key, expiry, json.dumps(value))
            except RedisError as e:
                logger.error(f"Redis set error: {e}")
        
        # Always set in memory cache
        self.memory_cache[key] = {
            'timestamp': time.time(),
            'value': value
        }
    
    def delete(self, key: str):
        """
        Delete key from cache.
        
        Args:
            key: Cache key
        """
        # Delete from Redis
        if self.redis_client:
            try:
                self.redis_client.delete(key)
            except RedisError as e:
                logger.error(f"Redis delete error: {e}")
        
        # Delete from memory cache
        if key in self.memory_cache:
            del self.memory_cache[key]
    
    def clear_expired(self):
        """
        Clear expired entries from memory cache.
        """
        current_time = time.time()
        self.memory_cache = {
            k: v for k, v in self.memory_cache.items()
            if current_time - v['timestamp'] < self.ttl
        }


# Initialize the cache manager as a singleton
cache_manager = CacheManager(redis_url=config.REDIS_URL, ttl=config.AVATAR_CACHE_TTL)


def cached(key_prefix: str, ttl: Optional[int] = None):
    """
    Decorator for caching function results.
    
    Args:
        key_prefix: Prefix for cache keys
        ttl: Optional TTL override
        
    Returns:
        Decorated function that uses cache
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name, args, and kwargs
            key_parts = [key_prefix, func.__name__]
            
            # Add positional args (skip self/cls for methods)
            skip_first = False
            if args and (
                hasattr(args[0], '__dict__') or 
                isinstance(args[0], type) or 
                str(type(args[0])) == "<class 'module'>"
            ):
                skip_first = True
                
            if skip_first and len(args) > 1:
                key_parts.extend([str(arg) for arg in args[1:]])
            elif not skip_first:
                key_parts.extend([str(arg) for arg in args])
            
            # Add keyword args
            if kwargs:
                for k, v in sorted(kwargs.items()):
                    key_parts.append(f"{k}={v}")
            
            cache_key = ":".join(key_parts)
            
            # Check cache
            cached_value = cache_manager.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_value
            
            # Call original function
            result = func(*args, **kwargs)
            
            # Cache result
            cache_manager.set(cache_key, result, ttl)
            logger.debug(f"Cached result for {cache_key}")
            
            return result
        return wrapper
    return decorator


def async_cached(key_prefix: str, ttl: Optional[int] = None):
    """
    Decorator for caching async function results.
    
    Args:
        key_prefix: Prefix for cache keys
        ttl: Optional TTL override
        
    Returns:
        Decorated async function that uses cache
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key from function name, args, and kwargs
            key_parts = [key_prefix, func.__name__]
            
            # Add positional args (skip self/cls for methods)
            skip_first = False
            if args and (
                hasattr(args[0], '__dict__') or 
                isinstance(args[0], type) or 
                str(type(args[0])) == "<class 'module'>"
            ):
                skip_first = True
                
            if skip_first and len(args) > 1:
                key_parts.extend([str(arg) for arg in args[1:]])
            elif not skip_first:
                key_parts.extend([str(arg) for arg in args])
            
            # Add keyword args
            if kwargs:
                for k, v in sorted(kwargs.items()):
                    key_parts.append(f"{k}={v}")
            
            cache_key = ":".join(key_parts)
            
            # Check cache
            cached_value = cache_manager.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_value
            
            # Call original function
            result = await func(*args, **kwargs)
            
            # Cache result
            cache_manager.set(cache_key, result, ttl)
            logger.debug(f"Cached result for {cache_key}")
            
            return result
        return wrapper
    return decorator