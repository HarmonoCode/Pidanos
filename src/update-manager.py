"""
Update Manager Module
~~~~~~~~~~~~~~~~~~~~

Manages updates for Pidanos components including blocklists, GeoIP databases, and software updates.
"""

import logging
import asyncio
import aiohttp
import aiofiles
import hashlib
import tempfile
import shutil
import os
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from pathlib import Path
import yaml
import gzip
import tarfile
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class UpdateManager:
    """Manages various update tasks for Pidanos"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_dir = Path(config.get('general', {}).get('data_dir', '/var/lib/pidanos'))
        self.blocklist_dir = self.data_dir / 'blocklists'
        self.geoip_dir = self.data_dir / 'geoip'
        
        # Ensure directories exist
        self.blocklist_dir.mkdir(parents=True, exist_ok=True)
        self.geoip_dir.mkdir(parents=True, exist_ok=True)
        
        # Update status
        self.update_status: Dict[str, Any] = {
            'blocklists': {},
            'geoip': {},
            'software': {}
        }
        
        # Update callbacks
        self.update_callbacks: List[Callable] = []
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Scheduled tasks
        self.scheduled_tasks: List[asyncio.Task] = []
        
    async def start(self):
        """Start the update manager"""
        logger.info("Starting Update Manager...")
        
        # Create HTTP session
        timeout = aiohttp.ClientTimeout(total=300)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Schedule updates
        if self.config.get('blocking', {}).get('gravity', {}).get('auto_update', True):
            task = asyncio.create_task(self._scheduled_blocklist_updates())
            self.scheduled_tasks.append(task)
            
        # Check for software updates on startup
        if self.config.get('updates', {}).get('check_on_startup', True):
            asyncio.create_task(self.check_software_updates())
            
    async def stop(self):
        """Stop the update manager"""
        logger.info("Stopping Update Manager...")
        
        # Cancel scheduled tasks
        for task in self.scheduled_tasks:
            task.cancel()
            
        await asyncio.gather(*self.scheduled_tasks, return_exceptions=True)
        
        # Close HTTP session
        if self.session:
            await self.session.close()
            
    async def update_blocklists(self, force: bool = False) -> Dict[str, Any]:
        """Update all enabled blocklists"""
        logger.info("Starting blocklist update...")
        
        blocklist_config = self.config.get('blocklists', {})
        results = {
            'updated': 0,
            'failed': 0,
            'skipped': 0,
            'total_domains': 0,
            'details': {}
        }
        
        # Get enabled blocklists
        enabled_lists = [
            (name, config) for name, config in blocklist_config.items()
            if isinstance(config, dict) and config.get('enabled', False)
        ]
        
        # Update each blocklist
        for name, list_config in enabled_lists:
            try:
                result = await self._update_single_blocklist(name, list_config, force)
                
                if result['updated']:
                    results['updated'] += 1
                elif result['skipped']:
                    results['skipped'] += 1
                else:
                    results['failed'] += 1
                    
                results['total_domains'] += result.get('domain_count', 0)
                results['details'][name] = result
                
            except Exception as e:
                logger.error(f"Failed to update blocklist {name}: {e}")
                results['failed'] += 1
                results['details'][name] = {'error': str(e)}
                
        # Merge blocklists
        await self._merge_blocklists()
        
        # Notify callbacks
        await self._notify_update('blocklists', results)
        
        return results
        
    async def _update_single_blocklist(self, name: str, config: Dict[str, Any], 
                                     force: bool = False) -> Dict[str, Any]:
        """Update a single blocklist"""
        url = config.get('url')
        if not url:
            return {'error': 'No URL specified', 'updated': False}
            
        # Check if update is needed
        list_file = self.blocklist_dir / f"{name}.txt"
        
        if not force and list_file.exists():
            # Check update frequency
            update_freq = config.get('update_frequency', 'daily')
            last_modified = datetime.fromtimestamp(list_file.stat().st_mtime)
            
            if update_freq == 'daily' and datetime.now() - last_modified < timedelta(days=1):
                return {'skipped': True, 'reason': 'Recently updated'}
            elif update_freq == 'weekly' and datetime.now() - last_modified < timedelta(days=7):
                return {'skipped': True, 'reason': 'Recently updated'}
                
        # Download blocklist
        logger.info(f"Downloading blocklist: {name} from {url}")
        
        try:
            headers = {
                'User-Agent': config.get('user_agent', 'Pidanos/1.0')
            }
            
            # Add authentication if configured
            auth = None
            if 'auth' in config:
                auth = aiohttp.BasicAuth(
                    config['auth'].get('username'),
                    config['auth'].get('password')
                )
                
            async with self.session.get(url, headers=headers, auth=auth) as response:
                response.raise_for_status()
                
                # Download to temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                
                try:
                    size = 0
                    async with aiofiles.open(temp_file.name, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            await f.write(chunk)
                            size += len(chunk)
                            
                    # Process blocklist
                    domain_count = await self._process_blocklist(
                        temp_file.name, 
                        list_file,
                        config.get('format', 'hosts')
                    )
                    
                    return {
                        'updated': True,
                        'size': size,
                        'domain_count': domain_count,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                finally:
                    os.unlink(temp_file.name)
                    
        except Exception as e:
            logger.error(f"Failed to download {name}: {e}")
            return {'error': str(e), 'updated': False}
            
    async def _process_blocklist(self, source_file: str, dest_file: Path, 
                                format_type: str) -> int:
        """Process downloaded blocklist file"""
        domains = set()
        
        # Read and parse blocklist
        async with aiofiles.open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
            async for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                    
                # Parse based on format
                if format_type == 'hosts':
                    # Format: IP domain
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1].lower()
                        if self._is_valid_domain(domain):
                            domains.add(domain)
                            
                elif format_type == 'domains':
                    # Format: domain
                    domain = line.lower()
                    if self._is_valid_domain(domain):
                        domains.add(domain)
                        
                elif format_type == 'adblock':
                    # Basic AdBlock format parsing
                    if line.startswith('||') and line.endswith('^'):
                        domain = line[2:-1].lower()
                        if self._is_valid_domain(domain):
                            domains.add(domain)
                            
        # Write processed domains
        async with aiofiles.open(dest_file, 'w') as f:
            for domain in sorted(domains):
                await f.write(f"{domain}\n")
                
        logger.info(f"Processed {len(domains)} domains from {source_file}")
        return len(domains)
        
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid for blocking"""
        # Skip localhost entries
        if domain in ['localhost', 'localhost.localdomain', 'local']:
            return False
            
        # Skip IP addresses
        if domain.replace('.', '').isdigit():
            return False
            
        # Basic domain validation
        if len(domain) < 4 or len(domain) > 253:
            return False
            
        return True
        
    async def _merge_blocklists(self):
        """Merge all blocklists into a single file"""
        logger.info("Merging blocklists...")
        
        all_domains = set()
        
        # Read all blocklist files
        for list_file in self.blocklist_dir.glob('*.txt'):
            async with aiofiles.open(list_file, 'r') as f:
                async for line in f:
                    domain = line.strip()
                    if domain:
                        all_domains.add(domain)
                        
        # Write merged list
        merged_file = self.data_dir / 'blocklist.txt'
        async with aiofiles.open(merged_file, 'w') as f:
            for domain in sorted(all_domains):
                await f.write(f"{domain}\n")
                
        logger.info(f"Merged {len(all_domains)} unique domains")
        
    async def update_geoip(self) -> Dict[str, Any]:
        """Update GeoIP databases"""
        logger.info("Updating GeoIP databases...")
        
        geoip_config = self.config.get('geoip', {})
        results = {}
        
        # MaxMind GeoLite2 databases
        if geoip_config.get('maxmind', {}).get('enabled', False):
            license_key = geoip_config['maxmind'].get('license_key')
            if license_key:
                for db_type in ['GeoLite2-Country', 'GeoLite2-City', 'GeoLite2-ASN']:
                    if geoip_config['maxmind'].get(db_type.lower(), True):
                        result = await self._download_maxmind_db(db_type, license_key)
                        results[db_type] = result
                        
        await self._notify_update('geoip', results)
        return results
        
    async def _download_maxmind_db(self, db_type: str, license_key: str) -> Dict[str, Any]:
        """Download MaxMind GeoIP database"""
        url = f"https://download.maxmind.com/app/geoip_download"
        params = {
            'edition_id': db_type,
            'license_key': license_key,
            'suffix': 'tar.gz'
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                response.raise_for_status()
                
                # Download to temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz')
                
                try:
                    async with aiofiles.open(temp_file.name, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            await f.write(chunk)
                            
                    # Extract database
                    with tarfile.open(temp_file.name, 'r:gz') as tar:
                        # Find the .mmdb file
                        for member in tar.getmembers():
                            if member.name.endswith('.mmdb'):
                                # Extract to GeoIP directory
                                member.name = os.path.basename(member.name)
                                tar.extract(member, self.geoip_dir)
                                
                                return {
                                    'updated': True,
                                    'file': member.name,
                                    'size': member.size
                                }
                                
                finally:
                    os.unlink(temp_file.name)
                    
        except Exception as e:
            logger.error(f"Failed to download {db_type}: {e}")
            return {'error': str(e), 'updated': False}
            
    async def check_software_updates(self) -> Dict[str, Any]:
        """Check for Pidanos software updates"""
        update_url = self.config.get('updates', {}).get('check_url', 
                                   'https://pidanos.harmonocode.com/api/version')
        current_version = self.config.get('version', '1.0.0')
        
        try:
            async with self.session.get(update_url) as response:
                response.raise_for_status()
                data = await response.json()
                
                latest_version = data.get('version')
                
                result = {
                    'current_version': current_version,
                    'latest_version': latest_version,
                    'update_available': self._compare_versions(current_version, latest_version) < 0,
                    'download_url': data.get('download_url'),
                    'changelog': data.get('changelog'),
                    'release_date': data.get('release_date')
                }
                
                await self._notify_update('software', result)
                return result
                
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {'error': str(e)}
            
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare version strings"""
        # Simple version comparison (major.minor.patch)
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]
        
        for i in range(max(len(parts1), len(parts2))):
            p1 = parts1[i] if i < len(parts1) else 0
            p2 = parts2[i] if i < len(parts2) else 0
            
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
                
        return 0
        
    async def _scheduled_blocklist_updates(self):
        """Run scheduled blocklist updates"""
        while True:
            try:
                # Calculate next update time
                update_time = self.config.get('blocking', {}).get('gravity', {}).get('update_time', '03:00')
                hour, minute = map(int, update_time.split(':'))
                
                now = datetime.now()
                next_update = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                
                if next_update <= now:
                    next_update += timedelta(days=1)
                    
                # Wait until update time
                wait_seconds = (next_update - now).total_seconds()
                logger.info(f"Next blocklist update scheduled at {next_update}")
                
                await asyncio.sleep(wait_seconds)
                
                # Run update
                await self.update_blocklists()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduled update error: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour
                
    async def _notify_update(self, update_type: str, result: Dict[str, Any]):
        """Notify callbacks about update completion"""
        self.update_status[update_type] = {
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        for callback in self.update_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(update_type, result)
                else:
                    callback(update_type, result)
            except Exception as e:
                logger.error(f"Update callback error: {e}")
                
    def register_update_callback(self, callback: Callable):
        """Register callback for update notifications"""
        self.update_callbacks.append(callback)
        
    def get_update_status(self) -> Dict[str, Any]:
        """Get current update status"""
        return self.update_status.copy()