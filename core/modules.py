"""
Core Modules and Utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~

Shared utilities and helper functions for Pidanos core functionality.
"""

import asyncio
import hashlib
import json
import logging
import os
import socket
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import aiofiles
import validators
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)


class CoreModules:
    """Collection of core utility modules"""
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate if a string is a valid domain name"""
        if not domain or len(domain) > 253:
            return False
            
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
            
        # Check each label
        labels = domain.split('.')
        if not labels:
            return False
            
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
            if not all(c.isalnum() or c == '-' for c in label):
                return False
                
        return True
        
    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validate if a string is a valid IP address"""
        try:
            ip_address(ip_str)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if an IP address is in a private range"""
        try:
            ip = ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
            
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize a domain name"""
        # Convert to lowercase and remove trailing dot
        domain = domain.lower().strip()
        if domain.endswith('.'):
            domain = domain[:-1]
        return domain
        
    @staticmethod
    def get_domain_parts(domain: str) -> List[str]:
        """Split domain into its component parts"""
        return CoreModules.normalize_domain(domain).split('.')
        
    @staticmethod
    def get_base_domain(domain: str) -> str:
        """Extract base domain from a full domain"""
        parts = CoreModules.get_domain_parts(domain)
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
        
    @staticmethod
    def hash_query(domain: str, query_type: str = "A") -> str:
        """Generate a hash for a DNS query"""
        query_string = f"{domain.lower()}:{query_type}"
        return hashlib.md5(query_string.encode()).hexdigest()
        
    @staticmethod
    async def read_hosts_file(filepath: str) -> List[str]:
        """Read domains from a hosts file format"""
        domains = []
        
        try:
            async with aiofiles.open(filepath, 'r') as f:
                async for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                        
                    # Parse hosts file format
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        domain = parts[1]
                        
                        # Skip localhost entries
                        if domain in ['localhost', 'localhost.localdomain', 'local']:
                            continue
                            
                        # Validate and add domain
                        if CoreModules.validate_domain(domain):
                            domains.append(domain)
                            
        except Exception as e:
            logger.error(f"Error reading hosts file {filepath}: {e}")
            
        return domains
        
    @staticmethod
    async def read_domain_list(filepath: str) -> List[str]:
        """Read domains from a simple list file"""
        domains = []
        
        try:
            async with aiofiles.open(filepath, 'r') as f:
                async for line in f:
                    domain = line.strip()
                    
                    # Skip comments and empty lines
                    if not domain or domain.startswith('#'):
                        continue
                        
                    # Validate and add domain
                    if CoreModules.validate_domain(domain):
                        domains.append(domain)
                        
        except Exception as e:
            logger.error(f"Error reading domain list {filepath}: {e}")
            
        return domains
        
    @staticmethod
    def parse_dns_type(query_type: Union[int, str]) -> str:
        """Convert DNS query type to string representation"""
        type_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            255: "ANY"
        }
        
        if isinstance(query_type, int):
            return type_map.get(query_type, f"TYPE{query_type}")
        return str(query_type).upper()
        
    @staticmethod
    def ip_to_bytes(ip_str: str) -> bytes:
        """Convert IP address string to bytes"""
        try:
            ip = ip_address(ip_str)
            if isinstance(ip, IPv4Address):
                return struct.pack('!I', int(ip))
            else:  # IPv6
                return ip.packed
        except ValueError:
            return b''
            
    @staticmethod
    def bytes_to_ip(ip_bytes: bytes, version: int = 4) -> str:
        """Convert bytes to IP address string"""
        try:
            if version == 4 and len(ip_bytes) == 4:
                return str(IPv4Address(ip_bytes))
            elif version == 6 and len(ip_bytes) == 16:
                return str(IPv6Address(ip_bytes))
        except ValueError:
            pass
        return ""
        
    @staticmethod
    async def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None)
            if result:
                return result[0][4][0]
        except Exception as e:
            logger.error(f"Failed to resolve {hostname}: {e}")
        return None
        
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format bytes to human readable size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
        
    @staticmethod
    def get_time_ago(timestamp: float) -> str:
        """Get human readable time ago string"""
        now = time.time()
        diff = now - timestamp
        
        if diff < 60:
            return f"{int(diff)} seconds ago"
        elif diff < 3600:
            return f"{int(diff / 60)} minutes ago"
        elif diff < 86400:
            return f"{int(diff / 3600)} hours ago"
        else:
            return f"{int(diff / 86400)} days ago"
            
    @staticmethod
    async def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure a directory exists"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
        
    @staticmethod
    async def load_json_file(filepath: str) -> Dict[str, Any]:
        """Load JSON from file"""
        try:
            async with aiofiles.open(filepath, 'r') as f:
                content = await f.read()
                return json.loads(content)
        except Exception as e:
            logger.error(f"Error loading JSON file {filepath}: {e}")
            return {}
            
    @staticmethod
    async def save_json_file(filepath: str, data: Dict[str, Any]):
        """Save JSON to file"""
        try:
            async with aiofiles.open(filepath, 'w') as f:
                content = json.dumps(data, indent=2)
                await f.write(content)
        except Exception as e:
            logger.error(f"Error saving JSON file {filepath}: {e}")
            
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize a filename for safe filesystem usage"""
        # Remove invalid characters
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
            
        # Remove path separators
        filename = filename.replace('/', '_').replace('\\', '_')
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
            
        return filename
        
    @staticmethod
    def parse_url(url: str) -> Dict[str, str]:
        """Parse URL into components"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment
        }
        
    @staticmethod
    def is_valid_port(port: Union[int, str]) -> bool:
        """Check if port number is valid"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
            
    @staticmethod
    def get_system_dns_servers() -> List[str]:
        """Get system configured DNS servers"""
        dns_servers = []
        
        # Try to read from resolv.conf (Linux/Unix)
        if os.path.exists('/etc/resolv.conf'):
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.strip().startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_servers.append(parts[1])
            except Exception as e:
                logger.error(f"Error reading resolv.conf: {e}")
                
        # Fallback to common DNS servers if none found
        if not dns_servers:
            dns_servers = ['1.1.1.1', '8.8.8.8']
            
        return dns_servers
        
    @staticmethod
    def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split a list into chunks of specified size"""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        
    @staticmethod
    async def rate_limiter(key: str, max_requests: int, window_seconds: int, storage: Dict) -> bool:
        """Simple rate limiter implementation"""
        now = time.time()
        window_start = now - window_seconds
        
        # Clean old entries
        if key in storage:
            storage[key] = [t for t in storage[key] if t > window_start]
        else:
            storage[key] = []
            
        # Check rate limit
        if len(storage[key]) >= max_requests:
            return False
            
        # Add current request
        storage[key].append(now)
        return True
        
    @staticmethod
    def extract_domain_from_url(url: str) -> Optional[str]:
        """Extract domain from a full URL"""
        parsed = CoreModules.parse_url(url)
        domain = parsed.get('domain', '')
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        return domain if CoreModules.validate_domain(domain) else None