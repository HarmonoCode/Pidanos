"""
Pidanos Source Modules
~~~~~~~~~~~~~~~~~~~~~~

Additional utility modules for the Pidanos application.
"""

import asyncio
import os
import sys
import platform
import psutil
import socket
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import json
import yaml
import aiohttp
import aiofiles
from pathlib import Path

import logging

logger = logging.getLogger(__name__)


class PidanosModules:
    """Collection of utility modules for Pidanos"""
    
    @staticmethod
    async def check_system_requirements() -> Dict[str, Any]:
        """Check if system meets Pidanos requirements"""
        requirements = {
            'python_version': {
                'required': '3.9',
                'current': f"{sys.version_info.major}.{sys.version_info.minor}",
                'met': sys.version_info >= (3, 9)
            },
            'memory': {
                'required_mb': 512,
                'available_mb': psutil.virtual_memory().available // (1024 * 1024),
                'met': psutil.virtual_memory().available >= 512 * 1024 * 1024
            },
            'disk_space': {
                'required_mb': 1024,
                'available_mb': psutil.disk_usage('/').free // (1024 * 1024),
                'met': psutil.disk_usage('/').free >= 1024 * 1024 * 1024
            },
            'ports': {
                'dns_port_53': PidanosModules.is_port_available(53),
                'web_port_8080': PidanosModules.is_port_available(8080),
                'api_port_8081': PidanosModules.is_port_available(8081)
            },
            'permissions': {
                'can_bind_low_ports': os.geteuid() == 0 if platform.system() != 'Windows' else True
            }
        }
        
        requirements['all_met'] = all([
            requirements['python_version']['met'],
            requirements['memory']['met'],
            requirements['disk_space']['met']
        ])
        
        return requirements
    
    @staticmethod
    def is_port_available(port: int, host: str = '0.0.0.0') -> bool:
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, port))
                return True
        except OSError:
            return False
    
    @staticmethod
    async def download_file(url: str, destination: str, 
                          progress_callback=None) -> bool:
        """Download file with progress tracking"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    response.raise_for_status()
                    
                    total_size = int(response.headers.get('Content-Length', 0))
                    downloaded = 0
                    
                    async with aiofiles.open(destination, 'wb') as file:
                        async for chunk in response.content.iter_chunked(8192):
                            await file.write(chunk)
                            downloaded += len(chunk)
                            
                            if progress_callback and total_size > 0:
                                progress = (downloaded / total_size) * 100
                                await progress_callback(progress, downloaded, total_size)
                                
            return True
            
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return False
    
    @staticmethod
    async def verify_checksum(filepath: str, expected_checksum: str, 
                            algorithm: str = 'sha256') -> bool:
        """Verify file checksum"""
        import hashlib
        
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            async with aiofiles.open(filepath, 'rb') as f:
                while chunk := await f.read(8192):
                    hash_func.update(chunk)
                    
            return hash_func.hexdigest() == expected_checksum
            
        except Exception as e:
            logger.error(f"Failed to verify checksum: {e}")
            return False
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get list of network interfaces"""
        interfaces = []
        
        for name, addrs in psutil.net_if_addrs().items():
            interface = {
                'name': name,
                'addresses': []
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interface['addresses'].append({
                        'type': 'ipv4',
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                elif addr.family == socket.AF_INET6:
                    interface['addresses'].append({
                        'type': 'ipv6',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                    
            interfaces.append(interface)
            
        return interfaces
    
    @staticmethod
    async def test_dns_resolution(domain: str = "example.com", 
                                 server: str = "1.1.1.1") -> Dict[str, Any]:
        """Test DNS resolution capability"""
        import dns.resolver
        
        result = {
            'success': False,
            'domain': domain,
            'server': server,
            'response_time': None,
            'error': None
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            start_time = asyncio.get_event_loop().time()
            answers = resolver.resolve(domain, 'A')
            end_time = asyncio.get_event_loop().time()
            
            result['success'] = True
            result['response_time'] = (end_time - start_time) * 1000  # ms
            result['answers'] = [str(rdata) for rdata in answers]
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    @staticmethod
    def create_systemd_service(config: Dict[str, str]) -> str:
        """Generate systemd service file content"""
        template = """[Unit]
Description={description}
After=network.target
Wants=network-online.target

[Service]
Type=notify
User={user}
Group={group}
WorkingDirectory={working_dir}
ExecStart={exec_start}
ExecReload=/bin/kill -USR1 $MAINPID
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={data_dir} {log_dir}

[Install]
WantedBy=multi-user.target
"""
        return template.format(**config)
    
    @staticmethod
    async def backup_data(source_dir: str, backup_path: str, 
                         compress: bool = True) -> bool:
        """Create backup of Pidanos data"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"pidanos_backup_{timestamp}"
            
            if compress:
                # Create tar.gz archive
                import tarfile
                backup_file = f"{backup_path}/{backup_name}.tar.gz"
                
                with tarfile.open(backup_file, "w:gz") as tar:
                    tar.add(source_dir, arcname=os.path.basename(source_dir))
                    
                logger.info(f"Backup created: {backup_file}")
            else:
                # Copy directory
                import shutil
                backup_dir = f"{backup_path}/{backup_name}"
                shutil.copytree(source_dir, backup_dir)
                
                logger.info(f"Backup created: {backup_dir}")
                
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    @staticmethod
    async def restore_backup(backup_path: str, restore_dir: str) -> bool:
        """Restore Pidanos data from backup"""
        try:
            if backup_path.endswith('.tar.gz'):
                # Extract tar.gz archive
                import tarfile
                
                with tarfile.open(backup_path, "r:gz") as tar:
                    tar.extractall(path=restore_dir)
            else:
                # Copy directory
                import shutil
                shutil.copytree(backup_path, restore_dir)
                
            logger.info(f"Backup restored to: {restore_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    @staticmethod
    def parse_hosts_file(content: str) -> List[Tuple[str, str]]:
        """Parse hosts file format"""
        entries = []
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                for domain in parts[1:]:
                    if not domain.startswith('#'):
                        entries.append((ip, domain))
                    else:
                        break
                        
        return entries
    
    @staticmethod
    async def check_for_updates(current_version: str, 
                              update_url: str) -> Dict[str, Any]:
        """Check for Pidanos updates"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(update_url) as response:
                    data = await response.json()
                    
                    latest_version = data.get('version', current_version)
                    
                    return {
                        'update_available': latest_version > current_version,
                        'current_version': current_version,
                        'latest_version': latest_version,
                        'download_url': data.get('download_url'),
                        'changelog': data.get('changelog', '')
                    }
                    
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {
                'update_available': False,
                'current_version': current_version,
                'error': str(e)
            }
    
    @staticmethod
    def validate_config(config_path: str) -> Tuple[bool, List[str]]:
        """Validate Pidanos configuration file"""
        errors = []
        
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    config = yaml.safe_load(f)
                elif config_path.endswith('.json'):
                    config = json.load(f)
                else:
                    errors.append("Unsupported configuration format")
                    return False, errors
                    
            # Check required sections
            required_sections = ['dns', 'web', 'database']
            for section in required_sections:
                if section not in config:
                    errors.append(f"Missing required section: {section}")
                    
            # Validate DNS settings
            if 'dns' in config:
                if 'port' in config['dns']:
                    port = config['dns']['port']
                    if not isinstance(port, int) or port < 1 or port > 65535:
                        errors.append("Invalid DNS port")
                        
            # Validate paths
            for key in ['data_dir', 'log_dir']:
                if key in config.get('general', {}):
                    path = config['general'][key]
                    if not os.path.isabs(path):
                        errors.append(f"{key} must be an absolute path")
                        
            return len(errors) == 0, errors
            
        except Exception as e:
            errors.append(f"Failed to parse configuration: {e}")
            return False, errors
    
    @staticmethod
    async def generate_ssl_certificate(domain: str, output_dir: str) -> bool:
        """Generate self-signed SSL certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pidanos"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            # Write private key
            key_path = Path(output_dir) / "privkey.pem"
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            # Write certificate
            cert_path = Path(output_dir) / "cert.pem"
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                
            logger.info(f"SSL certificate generated for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate SSL certificate: {e}")
            return False
    
    @staticmethod
    def get_process_info() -> Dict[str, Any]:
        """Get current process information"""
        process = psutil.Process()
        
        return {
            'pid': process.pid,
            'memory_usage_mb': process.memory_info().rss / (1024 * 1024),
            'cpu_percent': process.cpu_percent(interval=1),
            'num_threads': process.num_threads(),
            'open_files': len(process.open_files()),
            'connections': len(process.connections()),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
        }