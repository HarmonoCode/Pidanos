"""
API Server Module
~~~~~~~~~~~~~~~~~

RESTful API server for Pidanos management.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import time

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
import uvicorn

from core.blocker import DNSBlocker
from core.cache_manager import CacheManager
from core.statistics import StatisticsCollector
from .auth_manager import AuthManager
from .config_manager import ConfigManager
from .logger import PidanosLogger

logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class DomainRequest(BaseModel):
    domain: str
    comment: Optional[str] = None
    
    @validator('domain')
    def validate_domain(cls, v):
        # Basic domain validation
        if not v or len(v) > 253:
            raise ValueError('Invalid domain')
        return v.lower()

class BlocklistRequest(BaseModel):
    name: str
    url: str
    enabled: bool = True
    category: str = "custom"

class QueryFilter(BaseModel):
    client_ip: Optional[str] = None
    blocked_only: bool = False
    limit: int = 100
    
class StatsTimeRange(BaseModel):
    hours: int = 24
    
class SystemInfo(BaseModel):
    version: str
    uptime: int
    status: str
    dns_status: Dict
    cache_stats: Dict
    blocking_stats: Dict

class APIServer:
    """RESTful API server for Pidanos"""
    
    def __init__(self, config_path: str, dns_server=None):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.get_config()
        self.dns_server = dns_server
        
        # Initialize components
        self.auth_manager = AuthManager(self.config.get('security', {}))
        self.app = FastAPI(
            title="Pidanos API",
            description="DNS Filter Management API",
            version="1.0.0",
            docs_url="/api/docs" if self.config.get('api', {}).get('docs', {}).get('enabled', True) else None
        )
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup routes
        self._setup_routes()
        
        # API configuration
        api_config = self.config.get('api', {})
        self.host = self.config.get('web', {}).get('host', '0.0.0.0')
        self.port = api_config.get('port', 8081)
        
    def _setup_middleware(self):
        """Setup API middleware"""
        # CORS
        cors_config = self.config.get('web', {}).get('cors', {})
        if cors_config.get('enabled', True):
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=cors_config.get('origins', ["*"]),
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
        # Request ID middleware
        @self.app.middleware("http")
        async def add_request_id(request: Request, call_next):
            request_id = request.headers.get('X-Request-ID', 
                                           datetime.now().strftime('%Y%m%d%H%M%S%f'))
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
            
        # Logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = datetime.now()
            response = await call_next(request)
            process_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
            return response
            
    def _setup_routes(self):
        """Setup API routes"""
        
        # Authentication endpoints
        @self.app.post("/api/auth/login", response_model=TokenResponse)
        async def login(request: LoginRequest):
            """Authenticate user and return access token"""
            user = await self.auth_manager.authenticate(request.username, request.password)
            if not user:
                raise HTTPException(status_code=401, detail="Invalid credentials")
                
            token = await self.auth_manager.create_token(user)
            return TokenResponse(
                access_token=token['access_token'],
                expires_in=token['expires_in']
            )
            
        @self.app.post("/api/auth/logout")
        async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Logout user"""
            await self.auth_manager.revoke_token(credentials.credentials)
            return {"message": "Logged out successfully"}
            
        @self.app.get("/api/auth/status")
        async def auth_status(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get authentication status"""
            user = await self._get_current_user(credentials)
            return {"authenticated": True, "user": user}
            
        # DNS management endpoints
        @self.app.get("/api/dns/status")
        async def dns_status(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get DNS server status"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                return self.dns_server.get_stats()
            return {"status": "DNS server not connected"}
            
        @self.app.get("/api/dns/queries")
        async def get_queries(
            filter: QueryFilter = Depends(),
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get recent DNS queries"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                queries = await self.dns_server.stats.get_recent_queries(
                    limit=filter.limit,
                    client_ip=filter.client_ip,
                    blocked_only=filter.blocked_only
                )
                return {"queries": queries}
            return {"queries": []}
            
        @self.app.post("/api/dns/flush")
        async def flush_cache(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Flush DNS cache"""
            await self._verify_auth(credentials, required_role='admin')
            
            if self.dns_server:
                await self.dns_server.cache.clear()
                return {"message": "Cache flushed successfully"}
            raise HTTPException(status_code=503, detail="DNS server not available")
            
        # Blocklist management
        @self.app.get("/api/blocklists")
        async def get_blocklists(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get all blocklists"""
            await self._verify_auth(credentials)
            
            # This would fetch from database/config
            return {"blocklists": []}
            
        @self.app.post("/api/blocklists")
        async def add_blocklist(
            blocklist: BlocklistRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Add new blocklist"""
            await self._verify_auth(credentials, required_role='admin')
            
            # Add blocklist logic
            return {"message": "Blocklist added", "id": "new_id"}
            
        @self.app.post("/api/blocklists/update")
        async def update_blocklists(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Update all blocklists"""
            await self._verify_auth(credentials, required_role='admin')
            
            # Trigger blocklist update
            if self.dns_server:
                await self.dns_server.blocker.reload_lists()
                return {"message": "Blocklists update started"}
            raise HTTPException(status_code=503, detail="DNS server not available")
            
        # Whitelist/Blacklist management
        @self.app.get("/api/whitelist")
        async def get_whitelist(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get whitelist entries"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                whitelist = list(self.dns_server.blocker.whitelist)
                return {"whitelist": whitelist}
            return {"whitelist": []}
            
        @self.app.post("/api/whitelist")
        async def add_to_whitelist(
            request: DomainRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Add domain to whitelist"""
            await self._verify_auth(credentials, required_role='admin')
            
            if self.dns_server:
                await self.dns_server.blocker.add_to_whitelist(request.domain)
                return {"message": f"Added {request.domain} to whitelist"}
            raise HTTPException(status_code=503, detail="DNS server not available")
            
        @self.app.delete("/api/whitelist/{domain}")
        async def remove_from_whitelist(
            domain: str,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Remove domain from whitelist"""
            await self._verify_auth(credentials, required_role='admin')
            
            if self.dns_server:
                await self.dns_server.blocker.remove_from_whitelist(domain)
                return {"message": f"Removed {domain} from whitelist"}
            raise HTTPException(status_code=503, detail="DNS server not available")
            
        @self.app.get("/api/blacklist")
        async def get_blacklist(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get blacklist entries"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                blacklist = list(self.dns_server.blocker.blocklist.keys())
                return {"blacklist": blacklist[:1000]}  # Limit response size
            return {"blacklist": []}
            
        @self.app.post("/api/blacklist")
        async def add_to_blacklist(
            request: DomainRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Add domain to blacklist"""
            await self._verify_auth(credentials, required_role='admin')
            
            if self.dns_server:
                await self.dns_server.blocker.add_to_blocklist(request.domain)
                return {"message": f"Added {request.domain} to blacklist"}
            raise HTTPException(status_code=503, detail="DNS server not available")
            
        # Statistics endpoints
        @self.app.get("/api/stats/overview")
        async def stats_overview(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get statistics overview"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                stats = await self.dns_server.stats.get_overview()
                return stats
            return {}
            
        @self.app.get("/api/stats/top-domains")
        async def top_domains(
            limit: int = 10,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get top queried domains"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                domains = await self.dns_server.stats.get_top_domains(limit)
                return {"domains": domains}
            return {"domains": []}
            
        @self.app.get("/api/stats/top-blocked")
        async def top_blocked(
            limit: int = 10,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get top blocked domains"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                domains = await self.dns_server.stats.get_top_domains(limit, blocked_only=True)
                return {"domains": domains}
            return {"domains": []}
            
        @self.app.get("/api/stats/clients")
        async def client_stats(
            limit: int = 10,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get client statistics"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                clients = await self.dns_server.stats.get_top_clients(limit)
                return {"clients": clients}
            return {"clients": []}
            
        @self.app.get("/api/stats/time-series")
        async def time_series(
            range: StatsTimeRange = Depends(),
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get time series data"""
            await self._verify_auth(credentials)
            
            if self.dns_server:
                data = await self.dns_server.stats.get_time_series(range.hours)
                return data
            return {}
            
        # System endpoints
        @self.app.get("/api/system/info", response_model=SystemInfo)
        async def system_info(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get system information"""
            await self._verify_auth(credentials)
            
            info = SystemInfo(
                version="1.0.0",
                uptime=int(time.time() - self.start_time) if hasattr(self, 'start_time') else 0,
                status="running",
                dns_status=self.dns_server.get_stats() if self.dns_server else {},
                cache_stats=await self.dns_server.cache.get_stats() if self.dns_server else {},
                blocking_stats=await self.dns_server.blocker.get_statistics() if self.dns_server else {}
            )
            return info
            
        @self.app.get("/api/system/health")
        async def health_check():
            """Health check endpoint"""
            health = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "api": "healthy",
                    "dns": "healthy" if self.dns_server and self.dns_server.running else "unhealthy",
                    "database": "healthy"  # Check actual database
                }
            }
            
            # Return 503 if any component is unhealthy
            if any(status == "unhealthy" for status in health["components"].values()):
                return JSONResponse(status_code=503, content=health)
                
            return health
            
        @self.app.post("/api/system/restart")
        async def restart_services(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Restart Pidanos services"""
            await self._verify_auth(credentials, required_role='admin')
            
            # Implement restart logic
            return {"message": "Restart initiated"}
            
        @self.app.get("/api/system/logs")
        async def get_logs(
            lines: int = 100,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get system logs"""
            await self._verify_auth(credentials, required_role='admin')
            
            # Read logs
            logs = []
            return {"logs": logs}
            
    async def _verify_auth(self, credentials: HTTPAuthorizationCredentials, 
                          required_role: Optional[str] = None):
        """Verify authentication and authorization"""
        user = await self.auth_manager.verify_token(credentials.credentials)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
            
        if required_role and user.get('role') != required_role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
            
        return user
        
    async def _get_current_user(self, credentials: HTTPAuthorizationCredentials):
        """Get current authenticated user"""
        return await self._verify_auth(credentials)
        
    async def start(self):
        """Start the API server"""
        import time
        self.start_time = time.time()
        
        logger.info(f"Starting API server on {self.host}:{self.port}")
        
        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()
        
    def run(self):
        """Run the API server (blocking)"""
        import time
        self.start_time = time.time()
        
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )