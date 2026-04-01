"""
Performance Cache Layer
Implements intelligent caching to reduce latency and improve performance
"""

import asyncio
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
import hashlib
import json
from src.utils.logger import get_logger

logger = get_logger(__name__)

class CacheEntry:
    """Cache entry with TTL and metadata"""

    def __init__(self, key: str, value: Any, ttl_seconds: int = 300):
        self.key = key
        self.value = value
        self.created_at = datetime.now(timezone.utc)
        self.ttl_seconds = ttl_seconds
        self.access_count = 0
        self.last_accessed = datetime.now(timezone.utc)

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds() > self.ttl_seconds

    def access(self):
        """Record access to this entry"""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'key': self.key,
            'value': self.value,
            'created_at': self.created_at.isoformat(),
            'ttl_seconds': self.ttl_seconds,
            'access_count': self.access_count,
            'last_accessed': self.last_accessed.isoformat()
        }

class SecurityCache:
    """Intelligent caching for security operations"""

    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def _generate_key(self, operation: str, params: Dict[str, Any]) -> str:
        """Generate cache key from operation and parameters"""
        # Create a stable key by sorting parameters
        key_data = {
            'operation': operation,
            'params': sorted(params.items()) if isinstance(params, dict) else str(params)
        }
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def get(self, operation: str, params: Dict[str, Any]) -> Optional[Any]:
        """Get cached result for operation"""
        key = self._generate_key(operation, params)

        if key in self.cache:
            entry = self.cache[key]
            if not entry.is_expired():
                entry.access()
                self.hits += 1
                logger.debug(f"Cache hit for {operation}")
                return entry.value
            else:
                # Remove expired entry
                del self.cache[key]

        self.misses += 1
        logger.debug(f"Cache miss for {operation}")
        return None

    def set(self, operation: str, params: Dict[str, Any], value: Any, ttl: Optional[int] = None):
        """Cache result for operation"""
        key = self._generate_key(operation, params)

        # Evict if cache is full (LRU)
        if len(self.cache) >= self.max_size:
            self._evict_lru()

        ttl_seconds = ttl or self.default_ttl
        self.cache[key] = CacheEntry(key, value, ttl_seconds)
        logger.debug(f"Cached result for {operation}")

    def _evict_lru(self):
        """Evict least recently used entries"""
        if not self.cache:
            return

        # Find entry with oldest last_accessed
        oldest_key = min(self.cache.keys(),
                        key=lambda k: self.cache[k].last_accessed)

        del self.cache[oldest_key]
        self.evictions += 1
        logger.debug("Evicted LRU cache entry")

    def invalidate_pattern(self, operation_pattern: str):
        """Invalidate cache entries matching operation pattern"""
        keys_to_remove = []
        for key, entry in self.cache.items():
            if operation_pattern in key:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.cache[key]

        if keys_to_remove:
            logger.info(f"Invalidated {len(keys_to_remove)} cache entries for pattern {operation_pattern}")

    def clear(self):
        """Clear all cache entries"""
        self.cache.clear()
        logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0

        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'evictions': self.evictions,
            'default_ttl': self.default_ttl
        }

class AsyncTaskManager:
    """Manages asynchronous security tasks for performance"""

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks: Dict[str, asyncio.Task] = {}
        self.task_results: Dict[str, Any] = {}

    async def run_task(self, task_id: str, coro, timeout: float = 30.0) -> Any:
        """Run an asynchronous task with concurrency control"""
        async with self.semaphore:
            try:
                logger.debug(f"Starting async task {task_id}")
                result = await asyncio.wait_for(coro, timeout=timeout)
                logger.debug(f"Completed async task {task_id}")
                return result
            except asyncio.TimeoutError:
                logger.warning(f"Task {task_id} timed out")
                raise
            except Exception as e:
                logger.error(f"Task {task_id} failed: {e}")
                raise

    async def run_parallel(self, tasks: Dict[str, asyncio.Future]) -> Dict[str, Any]:
        """Run multiple tasks in parallel with concurrency control"""
        async def run_single(task_id: str, coro):
            return task_id, await self.run_task(task_id, coro)

        # Create tasks
        parallel_tasks = [
            run_single(task_id, coro) for task_id, coro in tasks.items()
        ]

        # Run in parallel
        results = await asyncio.gather(*parallel_tasks, return_exceptions=True)

        # Process results
        final_results = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Parallel task failed: {result}")
                continue

            task_id, task_result = result
            final_results[task_id] = task_result

        return final_results

class PerformanceOptimizer:
    """Main performance optimization manager"""

    def __init__(self):
        self.cache = SecurityCache()
        self.async_manager = AsyncTaskManager()
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}

    def cached_operation(self, operation: str, params: Dict[str, Any],
                        compute_func, ttl: Optional[int] = None):
        """Execute operation with caching"""
        # Try cache first
        cached_result = self.cache.get(operation, params)
        if cached_result is not None:
            return cached_result

        # Compute result
        result = compute_func()

        # Cache result
        self.cache.set(operation, params, result, ttl)

        return result

    async def async_cached_operation(self, operation: str, params: Dict[str, Any],
                                   async_compute_func, ttl: Optional[int] = None):
        """Execute async operation with caching"""
        # Try cache first
        cached_result = self.cache.get(operation, params)
        if cached_result is not None:
            return cached_result

        # Compute result asynchronously
        result = await async_compute_func()

        # Cache result
        self.cache.set(operation, params, result, ttl)

        return result

    def circuit_break_operation(self, operation: str, failure_threshold: int = 5,
                              recovery_timeout: int = 60):
        """Execute operation with circuit breaker pattern"""
        if operation not in self.circuit_breakers:
            self.circuit_breakers[operation] = {
                'failures': 0,
                'last_failure': None,
                'state': 'closed'  # closed, open, half_open
            }

        breaker = self.circuit_breakers[operation]
        now = datetime.now(timezone.utc)

        # Check if circuit should be closed (recovery timeout passed)
        if breaker['state'] == 'open':
            if breaker['last_failure'] and \
               (now - breaker['last_failure']).total_seconds() > recovery_timeout:
                breaker['state'] = 'half_open'
                logger.info(f"Circuit breaker for {operation} entering half-open state")
            else:
                raise Exception(f"Circuit breaker for {operation} is OPEN")

        def on_success():
            if breaker['state'] == 'half_open':
                breaker['state'] = 'closed'
                breaker['failures'] = 0
                logger.info(f"Circuit breaker for {operation} closed")

        def on_failure():
            breaker['failures'] += 1
            breaker['last_failure'] = now

            if breaker['failures'] >= failure_threshold:
                breaker['state'] = 'open'
                logger.warning(f"Circuit breaker for {operation} opened after {breaker['failures']} failures")

        # This would be used as a decorator or context manager in practice
        return on_success, on_failure

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            'cache_stats': self.cache.get_stats(),
            'circuit_breakers': self.circuit_breakers,
            'active_tasks': len(self.async_manager.active_tasks),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()