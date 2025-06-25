"""
Configuration Manager Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Manages Pidanos configuration loading, validation, and hot-reloading.
"""

import os
import yaml
import json
import logging
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import asyncio
from datetime import datetime
import copy
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Configuration validation error"""
    pass


class ConfigFileHandler(FileSystemEventHandler):
    """Handles configuration file changes"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        
    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory and event.src_path == self.config_manager.config_path:
            logger.info(f"Configuration file modified: {event.src_path}")
            asyncio.create_task(self.config_manager.reload())


class ConfigManager:
    """Manages Pidanos configuration"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        'general': {
            'mode': 'standalone',
            'data_dir': '/var/lib/pidanos',
            'log_dir': '/var/log/pidanos',
            'daemon': True,
            'pid_file': '/var/run/pidanos.pid',
            'debug': False,
            'log_level': 'INFO'
        },
        'dns': {
            'listen_addresses': ['0.0.0.0'],
            'port': 53,
            'upstream_dns': {
                'primary': ['1.1.1.1', '1.0.0.1'],
                'secondary': ['8.8.8.8', '8.8.4.4']
            },
            'query_timeout': 5,
            'dnssec': True,
            'rate_limiting': {
                'enabled': True,
                'queries_per_second': 1000
            }
        },
        'blocking': {
            'mode': 'null_ip',
            'custom_ip': '127.0.0.1',
            'gravity': {
                'auto_update': True,
                'update_interval': 86400
            }
        },
        'cache': {
            'enabled': True,
            'size': 10000,
            'default_ttl': 300,
            'min_ttl': 60,
            'max_ttl': 86400
        },
        'web': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 8080,
            'session_timeout': 3600
        },
        'api': {
            'enabled': True,
            'endpoint': '/api',
            'rate_limit': {
                'enabled': True,
                'requests_per_minute': 60
            }
        },
        'database': {
            'type': 'sqlite',
            'sqlite': {
                'path': '/var/lib/pidanos/pidanos.db'
            }
        },
        'statistics': {
            'enabled': True,
            'retention_days': 7
        }
    }
    
    def __init__(self, config_path: str):
        self.config_path = os.path.abspath(config_path)
        self.config: Dict[str, Any] = {}
        self.original_config: Dict[str, Any] = {}
        self.load_callbacks: List[callable] = []
        self.observer: Optional[Observer] = None
        
        # Load initial configuration
        self.load()
        
    def load(self):
        """Load configuration from file"""
        try:
            # Start with default config
            self.config = copy.deepcopy(self.DEFAULT_CONFIG)
            
            # Load user configuration
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    if self.config_path.endswith(('.yaml', '.yml')):
                        user_config = yaml.safe_load(f) or {}
                    elif self.config_path.endswith('.json'):
                        user_config = json.load(f)
                    else:
                        raise ConfigValidationError(f"Unsupported config format: {self.config_path}")
                        
                # Merge with defaults
                self._merge_config(self.config, user_config)
                
                # Validate configuration
                self.validate()
                
                # Store original for comparison
                self.original_config = copy.deepcopy(self.config)
                
                logger.info(f"Configuration loaded from {self.config_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_path}, using defaults")
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
            
    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base:
                if isinstance(base[key], dict) and isinstance(value, dict):
                    self._merge_config(base[key], value)
                else:
                    base[key] = value
            else:
                base[key] = value
                
    def validate(self):
        """Validate configuration"""
        errors = []
        
        # Validate paths
        for key in ['data_dir', 'log_dir']:
            path = self.config.get('general', {}).get(key)
            if path and not os.path.isabs(path):
                errors.append(f"{key} must be an absolute path")
                
        # Validate ports
        for section, port_key in [('dns', 'port'), ('web', 'port')]:
            port = self.config.get(section, {}).get(port_key)
            if port:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    errors.append(f"Invalid {section}.{port_key}: {port}")
                    
        # Validate DNS upstream servers
        upstream_dns = self.config.get('dns', {}).get('upstream_dns', {})
        if not upstream_dns.get('primary'):
            errors.append("At least one primary upstream DNS server required")
            
        # Validate database configuration
        db_type = self.config.get('database', {}).get('type')
        if db_type not in ['sqlite', 'postgresql', 'mysql']:
            errors.append(f"Invalid database type: {db_type}")
            
        if errors:
            raise ConfigValidationError(f"Configuration validation failed: {'; '.join(errors)}")
            
    def save(self, backup: bool = True):
        """Save configuration to file"""
        try:
            # Create backup if requested
            if backup and os.path.exists(self.config_path):
                backup_path = f"{self.config_path}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
                os.rename(self.config_path, backup_path)
                logger.info(f"Configuration backed up to {backup_path}")
                
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            # Save configuration
            with open(self.config_path, 'w') as f:
                if self.config_path.endswith(('.yaml', '.yml')):
                    yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
                elif self.config_path.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                    
            logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
            
    async def reload(self):
        """Reload configuration"""
        try:
            # Load new configuration
            old_config = copy.deepcopy(self.config)
            self.load()
            
            # Check what changed
            changes = self._get_config_changes(old_config, self.config)
            
            if changes:
                logger.info(f"Configuration changes detected: {changes}")
                
                # Notify callbacks
                for callback in self.load_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(self.config, changes)
                        else:
                            callback(self.config, changes)
                    except Exception as e:
                        logger.error(f"Configuration reload callback failed: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            # Restore old configuration on error
            self.config = old_config
            
    def _get_config_changes(self, old: Dict, new: Dict, path: str = '') -> List[str]:
        """Get list of changed configuration keys"""
        changes = []
        
        # Check for changes and additions
        for key, new_value in new.items():
            current_path = f"{path}.{key}" if path else key
            
            if key not in old:
                changes.append(f"Added: {current_path}")
            elif isinstance(new_value, dict) and isinstance(old.get(key), dict):
                changes.extend(self._get_config_changes(old[key], new_value, current_path))
            elif old.get(key) != new_value:
                changes.append(f"Modified: {current_path}")
                
        # Check for deletions
        for key in old:
            if key not in new:
                current_path = f"{path}.{key}" if path else key
                changes.append(f"Deleted: {current_path}")
                
        return changes
        
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def set(self, key: str, value: Any):
        """Set configuration value by dot-separated key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    def get_config(self) -> Dict[str, Any]:
        """Get full configuration"""
        return copy.deepcopy(self.config)
        
    def register_reload_callback(self, callback: callable):
        """Register callback for configuration reloads"""
        self.load_callbacks.append(callback)
        
    def start_watching(self):
        """Start watching configuration file for changes"""
        if self.observer:
            return
            
        self.observer = Observer()
        handler = ConfigFileHandler(self)
        self.observer.schedule(handler, os.path.dirname(self.config_path), recursive=False)
        self.observer.start()
        
        logger.info(f"Started watching configuration file: {self.config_path}")
        
    def stop_watching(self):
        """Stop watching configuration file"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
            logger.info("Stopped watching configuration file")
            
    def export_schema(self) -> Dict[str, Any]:
        """Export configuration schema"""
        schema = {
            'type': 'object',
            'properties': {
                'general': {
                    'type': 'object',
                    'properties': {
                        'mode': {'type': 'string', 'enum': ['standalone', 'docker', 'systemd']},
                        'data_dir': {'type': 'string'},
                        'log_dir': {'type': 'string'},
                        'daemon': {'type': 'boolean'},
                        'debug': {'type': 'boolean'},
                        'log_level': {'type': 'string', 'enum': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']}
                    }
                },
                'dns': {
                    'type': 'object',
                    'properties': {
                        'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
                        'listen_addresses': {'type': 'array', 'items': {'type': 'string'}},
                        'query_timeout': {'type': 'number', 'minimum': 0.1}
                    }
                }
                # Add more schema definitions
            }
        }
        
        return schema
        
    def get_environment_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables"""
        overrides = {}
        
        # Map environment variables to config keys
        env_mapping = {
            'PIDANOS_LOG_LEVEL': 'general.log_level',
            'PIDANOS_DNS_PORT': 'dns.port',
            'PIDANOS_WEB_PORT': 'web.port',
            'PIDANOS_DATA_DIR': 'general.data_dir',
            'PIDANOS_LOG_DIR': 'general.log_dir'
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                # Convert value type based on schema
                if config_key.endswith('port'):
                    value = int(value)
                elif config_key.endswith('enabled'):
                    value = value.lower() in ('true', '1', 'yes')
                    
                keys = config_key.split('.')
                current = overrides
                
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                    
                current[keys[-1]] = value
                
        return overrides