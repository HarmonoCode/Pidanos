"""
Statistics Module
~~~~~~~~~~~~~~~~~

Collect and manage DNS query statistics for Pidanos.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

logger = logging.getLogger(__name__)


@dataclass
class QueryStats:
    """Statistics for a single query"""
    timestamp: float
    domain: str
    query_type: str
    client_ip: str
    blocked: bool
    response_time: float
    upstream_server: Optional[str] = None
    block_reason: Optional[str] = None
    cache_hit: bool = False


@dataclass
class DomainStats:
    """Aggregated statistics for a domain"""
    domain: str
    total_queries: int = 0
    blocked_count: int = 0
    unique_clients: set = field(default_factory=set)
    query_types: Dict[str, int] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    def update(self, query: QueryStats):
        """Update statistics with a new query"""
        self.total_queries += 1
        if query.blocked:
            self.blocked_count += 1
        self.unique_clients.add(query.client_ip)
        self.query_types[query.query_type] = self.query_types.get(query.query_type, 0) + 1
        self.last_seen = query.timestamp


@dataclass 
class ClientStats:
    """Statistics for a client IP"""
    client_ip: str
    total_queries: int = 0
    blocked_queries: int = 0
    unique_domains: set = field(default_factory=set)
    query_rate: deque = field(default_factory=lambda: deque(maxlen=3600))  # Last hour
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    def update(self, query: QueryStats):
        """Update client statistics"""
        self.total_queries += 1
        if query.blocked:
            self.blocked_queries += 1
        self.unique_domains.add(query.domain)
        self.query_rate.append(query.timestamp)
        self.last_seen = query.timestamp


class StatisticsCollector:
    """Collects and manages DNS query statistics"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('statistics_enabled', True)
        self.retention_days = config.get('retention_days', 7)
        self.max_memory_queries = config.get('max_memory_queries', 100000)
        
        # In-memory storage
        self.recent_queries: deque = deque(maxlen=self.max_memory_queries)
        self.domain_stats: Dict[str, DomainStats] = {}
        self.client_stats: Dict[str, ClientStats] = {}
        
        # Time-based aggregates
        self.hourly_stats: defaultdict = defaultdict(lambda: {
            'total': 0, 'blocked': 0, 'cache_hits': 0, 'unique_clients': set()
        })
        self.daily_stats: defaultdict = defaultdict(lambda: {
            'total': 0, 'blocked': 0, 'cache_hits': 0, 'unique_clients': set()
        })
        
        # Global counters
        self.global_stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'average_response_time': 0,
            'uptime_start': time.time()
        }
        
        self._lock = asyncio.Lock()
        self._cleanup_task = None
        
    async def start(self):
        """Start the statistics collector"""
        if self.enabled:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Statistics collector started")
        else:
            logger.info("Statistics collector disabled")
            
    async def stop(self):
        """Stop the statistics collector"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Statistics collector stopped")
        
    async def record_query(self, query_stats: QueryStats):
        """Record a DNS query"""
        if not self.enabled:
            return
            
        async with self._lock:
            # Add to recent queries
            self.recent_queries.append(query_stats)
            
            # Update global stats
            self.global_stats['total_queries'] += 1
            if query_stats.blocked:
                self.global_stats['blocked_queries'] += 1
            if query_stats.cache_hit:
                self.global_stats['cache_hits'] += 1
            else:
                self.global_stats['cache_misses'] += 1
                
            # Update average response time
            current_avg = self.global_stats['average_response_time']
            total = self.global_stats['total_queries']
            new_avg = ((current_avg * (total - 1)) + query_stats.response_time) / total
            self.global_stats['average_response_time'] = new_avg
            
            # Update domain statistics
            if query_stats.domain not in self.domain_stats:
                self.domain_stats[query_stats.domain] = DomainStats(query_stats.domain)
            self.domain_stats[query_stats.domain].update(query_stats)
            
            # Update client statistics
            if query_stats.client_ip not in self.client_stats:
                self.client_stats[query_stats.client_ip] = ClientStats(query_stats.client_ip)
            self.client_stats[query_stats.client_ip].update(query_stats)
            
            # Update time-based aggregates
            hour_key = datetime.fromtimestamp(query_stats.timestamp).strftime('%Y-%m-%d %H:00')
            day_key = datetime.fromtimestamp(query_stats.timestamp).strftime('%Y-%m-%d')
            
            self.hourly_stats[hour_key]['total'] += 1
            if query_stats.blocked:
                self.hourly_stats[hour_key]['blocked'] += 1
            if query_stats.cache_hit:
                self.hourly_stats[hour_key]['cache_hits'] += 1
            self.hourly_stats[hour_key]['unique_clients'].add(query_stats.client_ip)
            
            self.daily_stats[day_key]['total'] += 1
            if query_stats.blocked:
                self.daily_stats[day_key]['blocked'] += 1
            if query_stats.cache_hit:
                self.daily_stats[day_key]['cache_hits'] += 1
            self.daily_stats[day_key]['unique_clients'].add(query_stats.client_ip)
            
    async def get_overview(self) -> Dict[str, Any]:
        """Get statistics overview"""
        async with self._lock:
            uptime_seconds = time.time() - self.global_stats['uptime_start']
            
            total = self.global_stats['total_queries']
            blocked = self.global_stats['blocked_queries']
            block_rate = (blocked / total * 100) if total > 0 else 0
            
            cache_total = self.global_stats['cache_hits'] + self.global_stats['cache_misses']
            cache_hit_rate = (self.global_stats['cache_hits'] / cache_total * 100) if cache_total > 0 else 0
            
            return {
                'total_queries': total,
                'blocked_queries': blocked,
                'block_rate': round(block_rate, 2),
                'cache_hit_rate': round(cache_hit_rate, 2),
                'average_response_time': round(self.global_stats['average_response_time'], 3),
                'unique_domains': len(self.domain_stats),
                'unique_clients': len(self.client_stats),
                'uptime_seconds': int(uptime_seconds),
                'queries_per_second': round(total / uptime_seconds, 2) if uptime_seconds > 0 else 0
            }
            
    async def get_top_domains(self, limit: int = 10, blocked_only: bool = False) -> List[Dict]:
        """Get top queried domains"""
        async with self._lock:
            domains = list(self.domain_stats.values())
            
            if blocked_only:
                domains = [d for d in domains if d.blocked_count > 0]
                domains.sort(key=lambda x: x.blocked_count, reverse=True)
            else:
                domains.sort(key=lambda x: x.total_queries, reverse=True)
                
            return [{
                'domain': d.domain,
                'queries': d.total_queries,
                'blocked': d.blocked_count,
                'unique_clients': len(d.unique_clients),
                'last_seen': d.last_seen
            } for d in domains[:limit]]
            
    async def get_top_clients(self, limit: int = 10) -> List[Dict]:
        """Get top clients by query count"""
        async with self._lock:
            clients = list(self.client_stats.values())
            clients.sort(key=lambda x: x.total_queries, reverse=True)
            
            return [{
                'client_ip': c.client_ip,
                'total_queries': c.total_queries,
                'blocked_queries': c.blocked_queries,
                'unique_domains': len(c.unique_domains),
                'queries_per_minute': self._calculate_query_rate(c),
                'last_seen': c.last_seen
            } for c in clients[:limit]]
            
    def _calculate_query_rate(self, client: ClientStats) -> float:
        """Calculate queries per minute for a client"""
        now = time.time()
        recent_queries = [t for t in client.query_rate if now - t < 60]
        return len(recent_queries)
        
    async def get_time_series(self, hours: int = 24) -> Dict[str, List]:
        """Get time series data for the last N hours"""
        async with self._lock:
            now = datetime.now()
            series_data = {
                'labels': [],
                'total_queries': [],
                'blocked_queries': [],
                'cache_hits': [],
                'unique_clients': []
            }
            
            for i in range(hours - 1, -1, -1):
                hour_time = now - timedelta(hours=i)
                hour_key = hour_time.strftime('%Y-%m-%d %H:00')
                
                series_data['labels'].append(hour_time.strftime('%H:00'))
                
                if hour_key in self.hourly_stats:
                    stats = self.hourly_stats[hour_key]
                    series_data['total_queries'].append(stats['total'])
                    series_data['blocked_queries'].append(stats['blocked'])
                    series_data['cache_hits'].append(stats['cache_hits'])
                    series_data['unique_clients'].append(len(stats['unique_clients']))
                else:
                    series_data['total_queries'].append(0)
                    series_data['blocked_queries'].append(0)
                    series_data['cache_hits'].append(0)
                    series_data['unique_clients'].append(0)
                    
            return series_data
            
    async def get_recent_queries(self, limit: int = 100, 
                               client_ip: Optional[str] = None,
                               blocked_only: bool = False) -> List[Dict]:
        """Get recent queries"""
        async with self._lock:
            queries = list(self.recent_queries)
            
            # Apply filters
            if client_ip:
                queries = [q for q in queries if q.client_ip == client_ip]
            if blocked_only:
                queries = [q for q in queries if q.blocked]
                
            # Sort by timestamp (newest first)
            queries.sort(key=lambda x: x.timestamp, reverse=True)
            
            return [{
                'timestamp': q.timestamp,
                'domain': q.domain,
                'query_type': q.query_type,
                'client_ip': q.client_ip,
                'blocked': q.blocked,
                'block_reason': q.block_reason,
                'response_time': round(q.response_time * 1000, 2),  # Convert to ms
                'cache_hit': q.cache_hit,
                'upstream_server': q.upstream_server
            } for q in queries[:limit]]
            
    async def get_query_type_distribution(self) -> Dict[str, int]:
        """Get distribution of query types"""
        async with self._lock:
            distribution = defaultdict(int)
            
            for domain_stat in self.domain_stats.values():
                for qtype, count in domain_stat.query_types.items():
                    distribution[qtype] += count
                    
            return dict(distribution)
            
    async def _cleanup_loop(self):
        """Periodic cleanup of old statistics"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run hourly
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in statistics cleanup: {e}")
                
    async def _cleanup_old_data(self):
        """Remove old statistics data"""
        async with self._lock:
            cutoff_time = time.time() - (self.retention_days * 86400)
            
            # Clean up hourly stats
            old_hours = [k for k, v in self.hourly_stats.items() 
                        if datetime.strptime(k, '%Y-%m-%d %H:00').timestamp() < cutoff_time]
            for hour in old_hours:
                del self.hourly_stats[hour]
                
            # Clean up daily stats
            old_days = [k for k, v in self.daily_stats.items()
                       if datetime.strptime(k, '%Y-%m-%d').timestamp() < cutoff_time]
            for day in old_days:
                del self.daily_stats[day]
                
            # Clean up inactive domains
            inactive_domains = [k for k, v in self.domain_stats.items()
                              if v.last_seen < cutoff_time]
            for domain in inactive_domains:
                del self.domain_stats[domain]
                
            # Clean up inactive clients
            inactive_clients = [k for k, v in self.client_stats.items()
                              if v.last_seen < cutoff_time]
            for client in inactive_clients:
                del self.client_stats[client]
                
            logger.info(f"Cleaned up old statistics: {len(old_hours)} hours, "
                       f"{len(old_days)} days, {len(inactive_domains)} domains, "
                       f"{len(inactive_clients)} clients")
                       
    async def export_statistics(self, filepath: str):
        """Export statistics to file"""
        async with self._lock:
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'global_stats': self.global_stats.copy(),
                'overview': await self.get_overview(),
                'top_domains': await self.get_top_domains(50),
                'top_blocked': await self.get_top_domains(50, blocked_only=True),
                'top_clients': await self.get_top_clients(50),
                'query_types': await self.get_query_type_distribution()
            }
            
        try:
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Exported statistics to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export statistics: {e}")
            
    async def reset_statistics(self):
        """Reset all statistics"""
        async with self._lock:
            self.recent_queries.clear()
            self.domain_stats.clear()
            self.client_stats.clear()
            self.hourly_stats.clear()
            self.daily_stats.clear()
            
            self.global_stats = {
                'total_queries': 0,
                'blocked_queries': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'average_response_time': 0,
                'uptime_start': time.time()
            }
            
        logger.info("Statistics reset")