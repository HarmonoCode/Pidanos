"""
Cache Manager Module
~~~~~~~~~~~~~~~~~~~~

Efficient caching system for DNS queries and responses.
"""

import asyncio
import time
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict
import hashlib
import json

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a single cache entry"""
    key: str
    value: Any
    ttl: int
    created_at: float = field(default_factory=time.time)
    hit_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        """Check if the cache entry has expired"""
        return time.time() - self.created_at > self.ttl
        
    @property
    def remaining_ttl(self) -> int:
        """Get remaining TTL in seconds"""
        elapsed = time.time() - self.created_at
        remaining = self.ttl - elapsed
        return max(0, int(remaining))
        
    def access(self):
        """Update access statistics"""
        self.hit_count += 1
        self.last_accessed = time.time()


class CacheManager:
    """Manages DNS query caching with TTL and size limits"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300, 
                 min_ttl: int = 60, max_ttl: int = 86400):
        """
        Initialize cache manager
        
        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds
            min_ttl: Minimum allowed TTL
            max_ttl: Maximum allowed TTL
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0
        }
        self._cleanup_task = None
        
    async def start(self):
        """Start the cache manager and cleanup task"""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(f"Cache manager started (max_size={self.max_size})")
        
    async def stop(self):
        """Stop the cache manager"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Cache manager stopped")
        
    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        async with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats['misses'] += 1
                return None
                
            if entry.is_expired:
                # Remove expired entry
                del self._cache[key]
                self._stats['expirations'] += 1
                self._stats['misses'] += 1
                return None
                
            # Move to end (LRU)
            self._cache.move_to_end(key)
            entry.access()
            self._stats['hits'] += 1
            
            return entry.value
            
    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (optional)
        """
        if ttl is None:
            ttl = self.default_ttl
        else:
            # Enforce TTL limits
            ttl = max(self.min_ttl, min(ttl, self.max_ttl))
            
        async with self._lock:
            # Check if we need to evict entries
            if key not in self._cache and len(self._cache) >= self.max_size:
                # Evict least recently used
                evicted_key = next(iter(self._cache))
                del self._cache[evicted_key]
                self._stats['evictions'] += 1
                
            # Add or update entry
            entry = CacheEntry(key=key, value=value, ttl=ttl)
            self._cache[key] = entry
            self._cache.move_to_end(key)
            
    async def delete(self, key: str) -> bool:
        """
        Delete entry from cache
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False if not found
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
            
    async def clear(self):
        """Clear all cache entries"""
        async with self._lock:
            self._cache.clear()
            logger.info("Cache cleared")
            
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        async with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = 0
            if total_requests > 0:
                hit_rate = (self._stats['hits'] / total_requests) * 100
                
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_rate': round(hit_rate, 2),
                'evictions': self._stats['evictions'],
                'expirations': self._stats['expirations']
            }
            
    async def get_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get cache entries for inspection"""
        async with self._lock:
            entries = []
            for key, entry in list(self._cache.items())[:limit]:
                entries.append({
                    'key': key,
                    'ttl': entry.ttl,
                    'remaining_ttl': entry.remaining_ttl,
                    'hit_count': entry.hit_count,
                    'created_at': entry.created_at,
                    'last_accessed': entry.last_accessed
                })
            return entries
            
    async def _cleanup_loop(self):
        """Background task to cleanup expired entries"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                
    async def _cleanup_expired(self):
        """Remove expired entries"""
        async with self._lock:
            expired_keys = []
            
            for key, entry in self._cache.items():
                if entry.is_expired:
                    expired_keys.append(key)
                    
            for key in expired_keys:
                del self._cache[key]
                self._stats['expirations'] += 1
                
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
    @staticmethod
    def generate_cache_key(domain: str, query_type: str = "A", 
                          client_ip: Optional[str] = None) -> str:
        """
        Generate a cache key for DNS queries
        
        Args:
            domain: Domain name
            query_type: DNS query type
            client_ip: Client IP (optional, for client-specific caching)
            
        Returns:
            Cache key string
        """
        key_parts = [domain.lower(), query_type.upper()]
        
        if client_ip:
            key_parts.append(client_ip)
            
        key_string = ":".join(key_parts)
        
        # Use hash for long keys
        if len(key_string) > 250:
            return hashlib.sha256(key_string.encode()).hexdigest()
            
        return key_string
        
    async def cache_dns_response(self, domain: str, query_type: str, 
                                response_data: bytes, ttl: Optional[int] = None):
        """
        Cache a DNS response
        
        Args:
            domain: Domain name
            query_type: DNS query type
            response_data: Raw DNS response data
            ttl: TTL in seconds
        """
        key = self.generate_cache_key(domain, query_type)
        await self.set(key, response_data, ttl)
        
    async def get_cached_response(self, domain: str, query_type: str) -> Optional[bytes]:
        """
        Get cached DNS response
        
        Args:
            domain: Domain name
            query_type: DNS query type
            
        Returns:
            Cached response data or None
        """
        key = self.generate_cache_key(domain, query_type)
        return await self.get(key)
        
    async def prefetch_domains(self, domains: List[str]):
        """
        Prefetch domains into cache (stub for future implementation)
        
        Args:
            domains: List of domains to prefetch
        """
        # This would be implemented to prefetch popular domains
        logger.debug(f"Prefetch requested for {len(domains)} domains")
        
    async def export_cache(self, filepath: str):
        """
        Export cache to file for persistence
        
        Args:
            filepath: Path to export file
        """
        async with self._lock:
            cache_data = {}
            
            for key, entry in self._cache.items():
                if not entry.is_expired:
                    cache_data[key] = {
                        'value': entry.value.hex() if isinstance(entry.value, bytes) else entry.value,
                        'ttl': entry.remaining_ttl,
                        'hit_count': entry.hit_count
                    }
                    
            try:
                with open(filepath, 'w') as f:
                    json.dump(cache_data, f)
                logger.info(f"Exported {len(cache_data)} cache entries to {filepath}")
            except Exception as e:
                logger.error(f"Failed to export cache: {e}")
                
    async def import_cache(self, filepath: str):
        """
        Import cache from file
        
        Args:
            filepath: Path to import file
        """
        try:
            with open(filepath, 'r') as f:
                cache_data = json.load(f)
                
            imported = 0
            for key, data in cache_data.items():
                value = data['value']
                if isinstance(value, str) and len(value) % 2 == 0:
                    try:
                        # Try to decode hex string
                        value = bytes.fromhex(value)
                    except ValueError:
                        pass
                        
                await self.set(key, value, data.get('ttl', self.default_ttl))
                imported += 1
                
            logger.info(f"Imported {imported} cache entries from {filepath}")
        except Exception as e:
            logger.error(f"Failed to import cache: {e}")