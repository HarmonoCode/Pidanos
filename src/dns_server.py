"""
DNS Server Module
~~~~~~~~~~~~~~~~~

Main DNS server implementation for Pidanos.
"""

import asyncio
import socket
import struct
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import signal
import os

from core.blocker import DNSBlocker
from core.dns_parser import DNSParser
from core.cache_manager import CacheManager
from core.statistics import StatisticsCollector, QueryStats
from .logger import PidanosLogger
from .config_manager import ConfigManager

logger = logging.getLogger(__name__)


@dataclass
class DNSServerConfig:
    """DNS Server configuration"""
    listen_addresses: List[str]
    port: int
    upstream_servers: List[str]
    query_timeout: float
    enable_ipv6: bool
    rate_limit_qps: int
    dnssec_enabled: bool
    edns_buffer_size: int
    tcp_enabled: bool
    
    @classmethod
    def from_config(cls, config: Dict) -> 'DNSServerConfig':
        """Create from configuration dictionary"""
        dns_config = config.get('dns', {})
        return cls(
            listen_addresses=dns_config.get('listen_addresses', ['0.0.0.0']),
            port=dns_config.get('port', 53),
            upstream_servers=dns_config.get('upstream_dns', {}).get('primary', ['1.1.1.1', '8.8.8.8']),
            query_timeout=dns_config.get('query_timeout', 5.0),
            enable_ipv6=dns_config.get('ipv6', {}).get('enabled', True),
            rate_limit_qps=dns_config.get('rate_limiting', {}).get('queries_per_second', 1000),
            dnssec_enabled=dns_config.get('dnssec', True),
            edns_buffer_size=dns_config.get('edns_buffer_size', 1232),
            tcp_enabled=dns_config.get('tcp_enabled', True)
        )


class DNSServer:
    """Main DNS server implementation"""
    
    def __init__(self, config_path: str):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()
        self.server_config = DNSServerConfig.from_config(self.config)
        
        # Initialize components
        self.blocker = DNSBlocker(self.config.get('blocking', {}))
        self.cache = CacheManager(
            max_size=self.config.get('cache', {}).get('size', 10000),
            default_ttl=self.config.get('cache', {}).get('default_ttl', 300)
        )
        self.stats = StatisticsCollector(self.config.get('statistics', {}))
        
        # Server state
        self.udp_sockets: List[socket.socket] = []
        self.tcp_sockets: List[socket.socket] = []
        self.running = False
        self.tasks: List[asyncio.Task] = []
        
        # Rate limiting
        self.rate_limiter: Dict[str, List[float]] = {}
        
        # Setup logging
        PidanosLogger.setup_logging(self.config.get('logging', {}))
        
    async def start(self):
        """Start the DNS server"""
        logger.info("Starting Pidanos DNS Server...")
        
        # Initialize components
        await self.blocker.initialize()
        await self.cache.start()
        await self.stats.start()
        
        # Create sockets
        await self._create_sockets()
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Start server tasks
        self.running = True
        
        # UDP listeners
        for sock in self.udp_sockets:
            task = asyncio.create_task(self._udp_listener(sock))
            self.tasks.append(task)
            
        # TCP listeners
        if self.server_config.tcp_enabled:
            for sock in self.tcp_sockets:
                task = asyncio.create_task(self._tcp_listener(sock))
                self.tasks.append(task)
                
        logger.info(f"DNS Server started on port {self.server_config.port}")
        
        # Wait for shutdown
        try:
            await asyncio.gather(*self.tasks)
        except asyncio.CancelledError:
            pass
            
    async def stop(self):
        """Stop the DNS server"""
        logger.info("Stopping DNS Server...")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
            
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Close sockets
        for sock in self.udp_sockets + self.tcp_sockets:
            sock.close()
            
        # Stop components
        await self.cache.stop()
        await self.stats.stop()
        
        logger.info("DNS Server stopped")
        
    async def _create_sockets(self):
        """Create UDP and TCP sockets"""
        for addr in self.server_config.listen_addresses:
            # Determine address family
            try:
                info = socket.getaddrinfo(addr, self.server_config.port, 
                                        socket.AF_UNSPEC, socket.SOCK_DGRAM)[0]
                family = info[0]
            except socket.gaierror:
                logger.error(f"Invalid listen address: {addr}")
                continue
                
            # Create UDP socket
            udp_sock = socket.socket(family, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if family == socket.AF_INET6:
                udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                
            udp_sock.bind((addr, self.server_config.port))
            udp_sock.setblocking(False)
            self.udp_sockets.append(udp_sock)
            
            logger.info(f"UDP socket created on {addr}:{self.server_config.port}")
            
            # Create TCP socket
            if self.server_config.tcp_enabled:
                tcp_sock = socket.socket(family, socket.SOCK_STREAM)
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                if family == socket.AF_INET6:
                    tcp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    
                tcp_sock.bind((addr, self.server_config.port))
                tcp_sock.listen(128)
                tcp_sock.setblocking(False)
                self.tcp_sockets.append(tcp_sock)
                
                logger.info(f"TCP socket created on {addr}:{self.server_config.port}")
                
    async def _udp_listener(self, sock: socket.socket):
        """Handle UDP DNS queries"""
        loop = asyncio.get_event_loop()
        
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(sock, 512)
                
                # Check rate limit
                if not await self._check_rate_limit(addr[0]):
                    continue
                    
                # Process query asynchronously
                asyncio.create_task(self._handle_dns_query(data, addr, sock, 'udp'))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"UDP listener error: {e}")
                
    async def _tcp_listener(self, sock: socket.socket):
        """Handle TCP DNS queries"""
        loop = asyncio.get_event_loop()
        
        while self.running:
            try:
                client_sock, addr = await loop.sock_accept(sock)
                client_sock.setblocking(False)
                
                # Handle client connection
                asyncio.create_task(self._handle_tcp_client(client_sock, addr))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"TCP listener error: {e}")
                
    async def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        """Handle a TCP DNS client"""
        loop = asyncio.get_event_loop()
        
        try:
            # Read length prefix
            length_data = await loop.sock_recv(client_sock, 2)
            if len(length_data) < 2:
                return
                
            length = struct.unpack('!H', length_data)[0]
            
            # Read query data
            data = await loop.sock_recv(client_sock, length)
            if len(data) < length:
                return
                
            # Check rate limit
            if not await self._check_rate_limit(addr[0]):
                return
                
            # Process query
            response = await self._process_dns_query(data, addr)
            
            # Send response
            if response:
                response_length = struct.pack('!H', len(response))
                await loop.sock_sendall(client_sock, response_length + response)
                
        except Exception as e:
            logger.error(f"TCP client handler error: {e}")
        finally:
            client_sock.close()
            
    async def _handle_dns_query(self, data: bytes, addr: Tuple[str, int], 
                               sock: socket.socket, protocol: str):
        """Handle a DNS query"""
        start_time = time.time()
        
        try:
            # Process the query
            response = await self._process_dns_query(data, addr)
            
            if response and protocol == 'udp':
                # Send UDP response
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(sock, response, addr)
                
        except Exception as e:
            logger.error(f"Error handling DNS query from {addr[0]}: {e}")
            
    async def _process_dns_query(self, data: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        """Process a DNS query and return response"""
        start_time = time.time()
        
        try:
            # Parse DNS query
            query = DNSParser.parse_packet(data)
            query_info = DNSParser.extract_query_info(query)
            
            if not query_info:
                return None
                
            domain = query_info['domain']
            query_type = query_info['type']
            client_ip = addr[0]
            
            logger.debug(f"Query: {domain} ({query_type}) from {client_ip}")
            
            # Check cache first
            cache_key = self.cache.generate_cache_key(domain, query_type)
            cached_response = await self.cache.get(cache_key)
            
            if cached_response:
                # Update statistics
                response_time = time.time() - start_time
                await self._record_stats(domain, query_type, client_ip, False, 
                                       response_time, cache_hit=True)
                return cached_response
                
            # Check if domain should be blocked
            block_result = await self.blocker.check_domain(domain, client_ip)
            
            if block_result.blocked:
                # Create blocked response
                response = DNSParser.build_blocked_response(
                    query, 
                    self.config.get('blocking', {}).get('custom_ip', '0.0.0.0')
                )
                
                # Record statistics
                response_time = time.time() - start_time
                await self._record_stats(domain, query_type, client_ip, True, 
                                       response_time, block_reason=block_result.reason)
                
                return response
                
            # Forward to upstream DNS
            response = await self._forward_to_upstream(data, domain, query_type)
            
            if response:
                # Cache the response
                await self.cache.set(cache_key, response, ttl=300)
                
                # Record statistics
                response_time = time.time() - start_time
                await self._record_stats(domain, query_type, client_ip, False, 
                                       response_time, cache_hit=False)
                
            return response
            
        except Exception as e:
            logger.error(f"Error processing DNS query: {e}")
            return None
            
    async def _forward_to_upstream(self, query_data: bytes, domain: str, 
                                  query_type: str) -> Optional[bytes]:
        """Forward query to upstream DNS server"""
        for upstream in self.server_config.upstream_servers:
            try:
                # Create UDP socket for upstream query
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.settimeout(self.server_config.query_timeout)
                
                # Send query
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(sock, query_data, (upstream, 53))
                
                # Wait for response
                response_data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 512),
                    timeout=self.server_config.query_timeout
                )
                
                sock.close()
                return response_data
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout querying upstream {upstream} for {domain}")
                if sock:
                    sock.close()
                continue
            except Exception as e:
                logger.error(f"Error querying upstream {upstream}: {e}")
                if sock:
                    sock.close()
                continue
                
        logger.error(f"All upstream servers failed for {domain}")
        return None
        
    async def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        now = time.time()
        window_start = now - 1.0  # 1 second window
        
        # Clean old entries
        if client_ip in self.rate_limiter:
            self.rate_limiter[client_ip] = [
                t for t in self.rate_limiter[client_ip] if t > window_start
            ]
        else:
            self.rate_limiter[client_ip] = []
            
        # Check limit
        if len(self.rate_limiter[client_ip]) >= self.server_config.rate_limit_qps:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return False
            
        # Add current request
        self.rate_limiter[client_ip].append(now)
        return True
        
    async def _record_stats(self, domain: str, query_type: str, client_ip: str,
                          blocked: bool, response_time: float, 
                          cache_hit: bool = False, block_reason: Optional[str] = None):
        """Record query statistics"""
        stats = QueryStats(
            timestamp=time.time(),
            domain=domain,
            query_type=query_type,
            client_ip=client_ip,
            blocked=blocked,
            response_time=response_time,
            block_reason=block_reason,
            cache_hit=cache_hit
        )
        
        await self.stats.record_query(stats)
        
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            asyncio.create_task(self.stop())
            
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
    async def reload_config(self):
        """Reload configuration without restart"""
        logger.info("Reloading configuration...")
        
        # Reload config
        self.config_manager.reload()
        self.config = self.config_manager.get_config()
        
        # Update components
        await self.blocker.reload_lists()
        
        logger.info("Configuration reloaded")
        
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        return {
            'running': self.running,
            'uptime': time.time() - self.stats.global_stats['uptime_start'],
            'sockets': {
                'udp': len(self.udp_sockets),
                'tcp': len(self.tcp_sockets)
            },
            'config': {
                'port': self.server_config.port,
                'upstream_servers': self.server_config.upstream_servers
            }
        }