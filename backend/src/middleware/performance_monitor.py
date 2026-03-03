"""
Performance Monitoring Middleware - Advanced Performance Tracking
====================================================================

This middleware provides comprehensive performance monitoring for the DevOps Shield backend,
including request timing, memory usage, database query tracking, and system resource monitoring.
"""

import time
import psutil
import gc
import hashlib
import os
from typing import Dict, Any, Optional, Callable, List, Tuple, cast
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from datetime import datetime, timezone
import threading
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class PerformanceMetrics:
    """Thread-safe performance metrics collector"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._lock = threading.RLock()

        # Request metrics
        self.request_times: deque = deque(maxlen=max_history)
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.status_codes: Dict[int, int] = {}

        # System metrics
        self.memory_usage: deque = deque(maxlen=100)
        self.cpu_usage: deque = deque(maxlen=100)
        self.disk_usage: deque = deque(maxlen=100)

        # Database metrics
        self.db_query_times: deque = deque(maxlen=max_history)
        self.db_connection_count = 0

        # Cache metrics
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_size = 0

        # Performance alerts
        self.slow_requests: deque = deque(maxlen=100)
        self.memory_alerts: deque = deque(maxlen=50)

    def record_request(self, method: str, path: str, status_code: int, duration: float):
        """Record request metrics"""
        with self._lock:
            self.request_times.append(duration)
            self.request_counts[f"{method} {path}"] += 1
            self.status_codes[status_code] = self.status_codes.get(
                status_code, 0) + 1

            if status_code >= 400:
                self.error_counts[f"{method} {path}"] += 1

            # Alert on slow requests
            if duration > 5.0:  # 5 seconds threshold
                self.slow_requests.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'method': method,
                    'path': path,
                    'duration': duration,
                    'status_code': status_code
                })

    def record_system_metrics(self):
        """Record system resource metrics"""
        with self._lock:
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'used_percent': memory.percent,
                'used_mb': memory.used / 1024 / 1024,
                'available_mb': memory.available / 1024 / 1024
            })

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_usage.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'percent': cpu_percent
            })

            # Disk usage
            disk = psutil.disk_usage('/')
            self.disk_usage.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'used_percent': (disk.used / disk.total) * 100,
                'free_gb': disk.free / 1024 / 1024 / 1024
            })

            # Memory alerts
            if memory.percent > 85:
                self.memory_alerts.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'memory_percent': memory.percent,
                    'memory_used_mb': memory.used / 1024 / 1024
                })

    def record_cache_metrics(self, hit: bool, size: int):
        """Record cache metrics"""
        with self._lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1
            self.cache_size = size

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        with self._lock:
            total_requests = sum(self.request_counts.values())
            total_errors = sum(self.error_counts.values())

            # Request statistics
            avg_response_time = sum(
                self.request_times) / len(self.request_times) if self.request_times else 0
            p95_response_time = self._percentile(
                list(self.request_times), 95) if self.request_times else 0
            p99_response_time = self._percentile(
                list(self.request_times), 99) if self.request_times else 0

            # System statistics
            latest_memory = cast(
                list, self.memory_usage)[-1] if self.memory_usage else {}
            latest_cpu = cast(
                list, self.cpu_usage)[-1] if self.cpu_usage else {}
            latest_disk = cast(
                list, self.disk_usage)[-1] if self.disk_usage else {}

            # Cache statistics
            total_cache_requests = self.cache_hits + self.cache_misses
            cache_hit_rate = (self.cache_hits / total_cache_requests *
                              100) if total_cache_requests > 0 else 0

            return {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_metrics': {
                    'total_requests': total_requests,
                    'total_errors': total_errors,
                    'error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
                    'avg_response_time_ms': avg_response_time * 1000,
                    'p95_response_time_ms': p95_response_time * 1000,
                    'p99_response_time_ms': p99_response_time * 1000,
                    'status_codes': self.status_codes,
                    'top_endpoints': self._get_top_endpoints(10)
                },
                'system_metrics': {
                    'memory': latest_memory,
                    'cpu': latest_cpu,
                    'disk': latest_disk
                },
                'cache_metrics': {
                    'hit_rate_percent': cache_hit_rate,
                    'total_hits': self.cache_hits,
                    'total_misses': self.cache_misses,
                    'cache_size_mb': self.cache_size / 1024 / 1024
                },
                'alerts': {
                    'slow_requests_count': len(self.slow_requests),
                    'memory_alerts_count': len(self.memory_alerts),
                    'recent_slow_requests': list(self.slow_requests),
                    'recent_memory_alerts': list(self.memory_alerts)
                }
            }

    def _percentile(self, data: list, percentile: int) -> float:
        """Calculate percentile of data"""
        if not data:
            return 0
        sorted_data = cast(List[float], sorted(data))
        index = int(len(sorted_data) * percentile / 100)
        return cast(List[float], sorted_data)[min(index, len(sorted_data) - 1)]

    def _get_top_endpoints(self, limit: int) -> list:
        """Get top endpoints by request count"""
        result: list = list(self.request_counts.items())
        result.sort(key=lambda x: x[1], reverse=True)  # type: ignore[index]
        return result[:limit]  # type: ignore[return-value]

    def stop_monitoring(self):
        """Stop monitoring hooks cleanly during app shutdown"""
        logger.info("Performance monitoring shutdown requested")


# Global metrics instance
metrics = PerformanceMetrics()


class PerformanceMonitorMiddleware(BaseHTTPMiddleware):
    """Advanced performance monitoring middleware"""

    def __init__(self, app,
                 enable_system_monitoring: bool = True,
                 system_monitoring_interval: int = 30,
                 enable_gc_monitoring: bool = True,
                 gc_threshold: int = 1000):
        super().__init__(app)  # type: ignore[call-arg]
        self.enable_system_monitoring = enable_system_monitoring
        self.system_monitoring_interval = system_monitoring_interval
        self.enable_gc_monitoring = enable_gc_monitoring
        self.gc_threshold = gc_threshold

        # Start background system monitoring
        if enable_system_monitoring:
            self._start_system_monitoring()

        # Request counter for GC triggering
        self.request_counter = 0

        logger.info("Performance monitoring middleware initialized")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Monitor request performance"""
        start_time = time.time()

        # Get client info
        client_ip = self._get_client_ip(request)

        # Generate request ID
        request_id = f"{int(time.time() * 1000)}-{id(request)}"

        # Add request ID to request state
        request.state.request_id = request_id
        request.state.start_time = start_time

        # Log request start
        logger.info(
            f"Request started: {request.method} {request.url.path} "
            f"[{request_id}]"
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Record metrics
            metrics.record_request(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration=duration
            )

            # Add performance headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration:.3f}s"
            response.headers["X-Server-Timestamp"] = datetime.now(
                timezone.utc).isoformat()

            # Add client info to response headers (for debugging)
            if os.getenv("ENVIRONMENT", "development") == "development":
                response.headers["X-Client-IP"] = client_ip

            # Log request completion
            logger.info(
                f"Request completed: {request.method} {request.url.path} "
                f"[{request_id}] - {response.status_code} in {duration:.3f}s"
            )

            # Trigger GC if needed
            self._maybe_trigger_gc()

            return response

        except Exception as e:
            # Calculate duration for failed requests
            duration = time.time() - start_time

            # Record error metrics
            metrics.record_request(
                method=request.method,
                path=request.url.path,
                status_code=500,
                duration=duration
            )

            logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"[{request_id}] - {str(e)} in {duration:.3f}s"
            )
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check various headers for client IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _start_system_monitoring(self):
        """Start background system monitoring"""
        def monitor_system():
            while True:
                try:
                    metrics.record_system_metrics()
                    time.sleep(self.system_monitoring_interval)
                except Exception as e:
                    logger.error(f"System monitoring error: {e}")
                    time.sleep(self.system_monitoring_interval)

        monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        monitor_thread.start()
        logger.info(f"System monitoring started (interval: {
                    self.system_monitoring_interval}s)")

    def _maybe_trigger_gc(self):
        """Trigger garbage collection if threshold reached"""
        if not self.enable_gc_monitoring:
            return

        self.request_counter += 1
        if self.request_counter >= self.gc_threshold:
            gc.collect()
            self.request_counter = 0
            logger.debug("Garbage collection triggered")


class CacheMiddleware(BaseHTTPMiddleware):
    """Intelligent caching middleware with performance tracking"""

    def __init__(self, app,
                 cache_ttl: int = 300,  # 5 minutes
                 max_cache_size: int = 1000,
                 cacheable_methods: list = ["GET"],
                 cacheable_status_codes: list = [200]):
        super().__init__(app)  # type: ignore[call-arg]
        self.cache_ttl = cache_ttl
        self.max_cache_size = max_cache_size
        self.cacheable_methods = set(cacheable_methods)
        self.cacheable_status_codes = set(cacheable_status_codes)

        # In-memory cache with weak references
        self._cache: Dict[str, Any] = {}
        self._cache_access_times: Dict[str, float] = {}
        self._lock = threading.RLock()

        logger.info(f"Cache middleware initialized (TTL: {
                    cache_ttl}s, Max size: {max_cache_size})")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle request with caching"""
        # Only cache GET requests
        if request.method not in self.cacheable_methods:
            return await call_next(request)

        # Generate cache key
        cache_key = self._generate_cache_key(request)

        # Check cache
        cached_response = self._get_cached_response(cache_key)
        if cached_response:
            metrics.record_cache_metrics(hit=True, size=len(self._cache))
            logger.debug(f"Cache hit: {request.method} {request.url.path}")
            return cached_response

        # Process request
        response = await call_next(request)

        # Cache successful responses
        if (response.status_code in self.cacheable_status_codes and
                not self._should_skip_cache(request)):
            self._cache_response(cache_key, response)
            metrics.record_cache_metrics(hit=False, size=len(self._cache))
            logger.debug(f"Cache miss: {request.method} {request.url.path}")

        return response

    def _generate_cache_key(self, request: Request) -> str:
        """Generate cache key for request"""
        # Include method, path, and query parameters
        key_parts = [
            request.method,
            request.url.path,
            str(sorted(request.query_params.items()))
        ]
        return hashlib.md5("|".join(key_parts).encode()).hexdigest()

    def _get_cached_response(self, cache_key: str) -> Optional[Response]:
        """Get cached response if valid"""
        with self._lock:
            if cache_key not in self._cache:
                return None

            cached_data, timestamp = self._cache[cache_key]

            # Check if cache is expired
            if time.time() - timestamp > self.cache_ttl:
                cast(dict, self._cache).pop(cache_key, None)
                cast(dict, self._cache_access_times).pop(cache_key, None)
                return None

            # Update access time
            self._cache_access_times[cache_key] = time.time()

            # Recreate response from cached data
            return Response(
                content=cached_data['content'],
                status_code=cached_data['status_code'],
                headers=cached_data['headers'],
                media_type=cached_data.get('media_type')
            )

    def _cache_response(self, cache_key: str, response: Response):
        """Cache response"""
        with self._lock:
            # Remove oldest entries if cache is full
            if len(self._cache) >= self.max_cache_size:
                self._evict_oldest_entries()

            # Cache response data (only for responses with body attribute)
            if hasattr(response, 'body'):
                self._cache[cache_key] = (
                    {
                        'content': response.body,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'media_type': response.media_type
                    },
                    time.time()
                )
            self._cache_access_times[cache_key] = time.time()

    def _evict_oldest_entries(self):
        """Evict oldest cache entries"""
        # Remove 10% of oldest entries
        entries_to_remove = max(1, self.max_cache_size // 10)

        entries: list = sorted(
            self._cache_access_times.items(),
            key=lambda x: x[1]
        )

        for cache_key, _ in entries[:entries_to_remove]:
            self._cache.pop(cache_key, None)  # type: ignore[arg-type]
            self._cache_access_times.pop(cache_key, None)  # type: ignore[arg-type]

    def _should_skip_cache(self, request: Request) -> bool:
        """Check if request should be skipped from cache"""
        # Skip cache for requests with authorization headers
        if "authorization" in request.headers:
            return True

        # Skip cache for requests with specific query parameters
        skip_params = ["no_cache", "refresh", "bypass"]
        for param in skip_params:
            if param in request.query_params:
                return True

        return False

# Export metrics for external access


def get_performance_metrics() -> Dict[str, Any]:
    """Get current performance metrics"""
    return metrics.get_performance_summary()


def reset_performance_metrics():
    """Reset all performance metrics"""
    global metrics
    metrics = PerformanceMetrics()
    logger.info("Performance metrics reset")
