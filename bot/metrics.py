"""
Metrics module for Prometheus metrics collection.
"""
import time
import logging
from typing import Callable, Any, Dict
from contextlib import contextmanager

try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    # Create dummy classes for type hints
    class Counter:
        def inc(self, amount=1): pass
    class Histogram:
        @contextmanager
        def time(self): yield
    class Gauge:
        def set(self, value): pass

# Configure logging
logger = logging.getLogger(__name__)

# Define metrics if Prometheus is available
if PROMETHEUS_AVAILABLE:
    # Counter metrics
    spam_detected = Counter('spam_detected_total', 'Number of spam messages detected')
    avatar_unsafe = Counter('avatar_unsafe_total', 'Number of unsafe avatars detected')
    avatar_suspicious = Counter('avatar_suspicious_total', 'Number of suspicious avatars detected')
    webhook_requests = Counter('webhook_requests_total', 'Number of webhook requests received')
    webhook_errors = Counter('webhook_errors_total', 'Number of webhook errors')
    
    # Histogram metrics
    llm_latency = Histogram('llm_latency_seconds', 'Latency of LLM calls')
    avatar_check_latency = Histogram('avatar_check_latency_seconds', 'Latency of avatar checks')
    webhook_latency = Histogram('webhook_latency_seconds', 'Latency of webhook requests')
    
    # Gauge metrics
    detector_initialized = Gauge('detector_initialized', 'Whether the NudeNet detector is initialized')
    bot_enabled = Gauge('bot_enabled', 'Whether the bot is enabled')
else:
    # Create dummy metrics
    spam_detected = Counter()
    avatar_unsafe = Counter()
    avatar_suspicious = Counter()
    webhook_requests = Counter()
    webhook_errors = Counter()
    
    llm_latency = Histogram()
    avatar_check_latency = Histogram()
    webhook_latency = Histogram()
    
    detector_initialized = Gauge()
    bot_enabled = Gauge()
    
    logger.warning("Prometheus client not available, metrics will not be collected")


@contextmanager
def timed_execution(metric: Histogram):
    """
    Context manager for timing execution of a block of code.
    
    Args:
        metric: Histogram metric to record the time
    """
    if PROMETHEUS_AVAILABLE:
        with metric.time():
            yield
    else:
        start = time.time()
        yield
        duration = time.time() - start
        logger.debug(f"Execution time: {duration:.4f}s")


def increment_counter(metric: Counter, amount: int = 1):
    """
    Increment a counter metric.
    
    Args:
        metric: Counter metric to increment
        amount: Amount to increment by
    """
    if PROMETHEUS_AVAILABLE:
        metric.inc(amount)


def set_gauge(metric: Gauge, value: float):
    """
    Set a gauge metric.
    
    Args:
        metric: Gauge metric to set
        value: Value to set
    """
    if PROMETHEUS_AVAILABLE:
        metric.set(value)