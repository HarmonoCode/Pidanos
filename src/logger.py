"""
Logger Module
~~~~~~~~~~~~~

Centralized logging configuration for Pidanos.
"""

import logging
import logging.handlers
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import traceback


class JSONFormatter(logging.Formatter):
    """JSON log formatter"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_path = Path(log_dir)
        
        if log_path.exists():
            for log_file in log_path.glob('*.log*'):
                file_stat = log_file.stat()
                stats['log_files'][log_file.name] = {
                    'size': file_stat.st_size,
                    'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                }
                stats['total_size'] += file_stat.st_size
                
        return stats
        
    @staticmethod
    def rotate_logs():
        """Manually trigger log rotation"""
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.handlers.TimedRotatingFileHandler):
                handler.doRollover()
                
    @staticmethod
    def set_log_level(logger_name: str, level: str):
        """Dynamically change log level"""
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level.upper()))
        
    @staticmethod
    def add_context_filter(logger_name: str, context: Dict[str, Any]):
        """Add context filter to logger"""
        class ContextFilter(logging.Filter):
            def filter(self, record):
                for key, value in context.items():
                    setattr(record, key, value)
                return True
                
        logger = logging.getLogger(logger_name)
        logger.addFilter(ContextFilter())data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields
        if hasattr(record, 'user'):
            log_data['user'] = record.user
        if hasattr(record, 'client_ip'):
            log_data['client_ip'] = record.client_ip
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id
            
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
            
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors"""
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
            
        # Format timestamp
        record.asctime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return super().format(record)


class PidanosLogger:
    """Centralized logger for Pidanos"""
    
    @staticmethod
    def setup_logging(config: Dict[str, Any]):
        """Setup logging configuration"""
        log_config = config.get('logging', {})
        
        # Create log directory
        log_dir = Path(config.get('general', {}).get('log_dir', '/var/log/pidanos'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_config.get('log_level', 'INFO')))
        
        # Remove existing handlers
        root_logger.handlers = []
        
        # Console handler
        if log_config.get('console', {}).get('enabled', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, log_config.get('console', {}).get('level', 'INFO')))
            
            if sys.stdout.isatty():
                # Use colored formatter for TTY
                console_formatter = ColoredFormatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            else:
                console_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)
            
        # File handlers
        handlers_config = {
            'main': {
                'filename': 'pidanos.log',
                'when': 'midnight',
                'interval': 1,
                'backupCount': 30,
                'level': 'INFO'
            },
            'error': {
                'filename': 'error.log',
                'when': 'midnight',
                'interval': 1,
                'backupCount': 30,
                'level': 'ERROR'
            },
            'query': {
                'filename': 'dns-queries.log',
                'when': 'midnight',
                'interval': 1,
                'backupCount': 7,
                'level': 'INFO'
            },
            'blocked': {
                'filename': 'blocked.log',
                'when': 'midnight',
                'interval': 1,
                'backupCount': 7,
                'level': 'INFO'
            },
            'api': {
                'filename': 'api.log',
                'when': 'midnight',
                'interval': 1,
                'backupCount': 7,
                'level': 'INFO'
            }
        }
        
        for handler_name, handler_config in handlers_config.items():
            if log_config.get(handler_name, {}).get('enabled', True):
                log_file = log_dir / handler_config['filename']
                
                # Create rotating file handler
                file_handler = logging.handlers.TimedRotatingFileHandler(
                    filename=str(log_file),
                    when=handler_config['when'],
                    interval=handler_config['interval'],
                    backupCount=handler_config['backupCount']
                )
                
                file_handler.setLevel(getattr(logging, handler_config['level']))
                
                # Use JSON formatter for structured logs
                if log_config.get('json_format', False):
                    file_handler.setFormatter(JSONFormatter())
                else:
                    file_handler.setFormatter(logging.Formatter(
                        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                    ))
                    
                # Add handler to specific logger
                if handler_name == 'main':
                    root_logger.addHandler(file_handler)
                else:
                    specific_logger = logging.getLogger(f'pidanos.{handler_name}')
                    specific_logger.addHandler(file_handler)
                    specific_logger.propagate = False
                    
        # Syslog handler
        if log_config.get('syslog', {}).get('enabled', False):
            syslog_config = log_config['syslog']
            syslog_handler = logging.handlers.SysLogHandler(
                address=(syslog_config.get('server', 'localhost'), 
                        syslog_config.get('port', 514)),
                facility=logging.handlers.SysLogHandler.LOG_DAEMON
            )
            
            syslog_handler.setLevel(getattr(logging, syslog_config.get('level', 'INFO')))
            syslog_handler.setFormatter(logging.Formatter(
                'pidanos[%(process)d]: %(levelname)s - %(message)s'
            ))
            
            root_logger.addHandler(syslog_handler)
            
        # Configure specific loggers
        PidanosLogger._configure_module_loggers(log_config)
        
        logging.info("Logging system initialized")
        
    @staticmethod
    def _configure_module_loggers(log_config: Dict[str, Any]):
        """Configure module-specific loggers"""
        # Silence noisy libraries
        for logger_name in ['urllib3', 'asyncio', 'aiohttp']:
            logging.getLogger(logger_name).setLevel(logging.WARNING)
            
        # Configure Pidanos module loggers
        module_levels = log_config.get('module_levels', {})
        for module, level in module_levels.items():
            logging.getLogger(module).setLevel(getattr(logging, level))
            
    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Get a logger instance"""
        return logging.getLogger(name)
        
    @staticmethod
    def log_query(domain: str, query_type: str, client_ip: str, 
                 blocked: bool = False, block_reason: Optional[str] = None):
        """Log DNS query"""
        query_logger = logging.getLogger('pidanos.query')
        
        log_data = {
            'domain': domain,
            'type': query_type,
            'client': client_ip,
            'blocked': blocked
        }
        
        if blocked and block_reason:
            log_data['reason'] = block_reason
            
        query_logger.info(json.dumps(log_data) if query_logger.handlers else 
                         f"{client_ip} - {domain} ({query_type}) - {'BLOCKED' if blocked else 'ALLOWED'}")
                         
    @staticmethod
    def log_blocked(domain: str, client_ip: str, reason: str):
        """Log blocked domain"""
        blocked_logger = logging.getLogger('pidanos.blocked')
        
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'domain': domain,
            'client': client_ip,
            'reason': reason
        }
        
        blocked_logger.info(json.dumps(log_data) if blocked_logger.handlers else
                           f"{client_ip} - BLOCKED {domain} - {reason}")
                           
    @staticmethod
    def log_api_request(method: str, path: str, status: int, 
                       duration: float, user: Optional[str] = None):
        """Log API request"""
        api_logger = logging.getLogger('pidanos.api')
        
        log_data = {
            'method': method,
            'path': path,
            'status': status,
            'duration_ms': round(duration * 1000, 2)
        }
        
        if user:
            log_data['user'] = user
            
        api_logger.info(json.dumps(log_data) if api_logger.handlers else
                       f"{method} {path} - {status} - {duration:.3f}s")
                       
    @staticmethod
    def log_error(error: Exception, context: Optional[Dict[str, Any]] = None):
        """Log error with context"""
        error_logger = logging.getLogger('pidanos.error')
        
        log_data = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc()
        }
        
        if context:
            log_data['context'] = context
            
        error_logger.error(json.dumps(log_data) if error_logger.handlers else
                          f"{type(error).__name__}: {error}", exc_info=True)
                          
    @staticmethod
    def get_log_stats(log_dir: str = '/var/log/pidanos') -> Dict[str, Any]:
        """Get logging statistics"""
        stats = {
            'log_files': {},
            'total_size': 0,
            'oldest_entry': None,
            'newest_entry': None
        }
        
        log_