"""
Authentication Manager Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles user authentication and authorization for Pidanos.
"""

import logging
import secrets
import hashlib
import time
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import asyncio
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class User:
    """User model"""
    id: str
    username: str
    password_hash: str
    role: str = "viewer"
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    active: bool = True
    email: Optional[str] = None
    permissions: List[str] = field(default_factory=list)


@dataclass
class Session:
    """User session model"""
    token: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: str
    user_agent: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at


class AuthManager:
    """Manages authentication and authorization"""
    
    # Role hierarchy
    ROLES = {
        'admin': ['manage_users', 'modify_settings', 'view_all', 'modify_blocklists'],
        'editor': ['modify_blocklists', 'view_all'],
        'viewer': ['view_all']
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # JWT settings
        self.jwt_secret = config.get('jwt_secret', self._generate_secret())
        self.jwt_algorithm = config.get('jwt_algorithm', 'HS256')
        self.token_expiry = config.get('session_lifetime', 86400)  # 24 hours
        
        # Session management
        self.sessions: Dict[str, Session] = {}
        self.failed_attempts: Dict[str, List[float]] = {}
        
        # User storage (in production, this would be a database)
        self.users: Dict[str, User] = {}
        
        # Initialize with default admin user
        self._create_default_admin()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_sessions())
        
    def _generate_secret(self) -> str:
        """Generate a secure secret key"""
        return secrets.token_urlsafe(32)
        
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        default_password = self.config.get('default_password', 'changeme')
        
        if not self.users:
            admin_user = User(
                id='admin',
                username='admin',
                password_hash=self.pwd_context.hash(default_password),
                role='admin',
                permissions=self.ROLES['admin']
            )
            self.users[admin_user.username] = admin_user
            logger.warning(f"Created default admin user with password: {default_password}")
            
    async def authenticate(self, username: str, password: str, 
                          ip_address: str = None) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password"""
        # Check rate limiting
        if not await self._check_rate_limit(username, ip_address):
            logger.warning(f"Too many failed attempts for {username} from {ip_address}")
            return None
            
        # Get user
        user = self.users.get(username)
        if not user or not user.active:
            await self._record_failed_attempt(username, ip_address)
            return None
            
        # Verify password
        if not self.pwd_context.verify(password, user.password_hash):
            await self._record_failed_attempt(username, ip_address)
            return None
            
        # Update last login
        user.last_login = datetime.now()
        
        # Clear failed attempts
        if username in self.failed_attempts:
            del self.failed_attempts[username]
            
        logger.info(f"User {username} authenticated successfully")
        
        return {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'permissions': user.permissions,
            'email': user.email
        }
        
    async def create_token(self, user: Dict[str, Any], 
                          ip_address: str = None, 
                          user_agent: str = None) -> Dict[str, Any]:
        """Create JWT token for authenticated user"""
        now = datetime.now()
        expires_at = now + timedelta(seconds=self.token_expiry)
        
        # Token payload
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'permissions': user['permissions'],
            'exp': expires_at,
            'iat': now,
            'jti': secrets.token_urlsafe(16)  # JWT ID
        }
        
        # Generate token
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Create session
        session = Session(
            token=token,
            user_id=user['id'],
            created_at=now,
            expires_at=expires_at,
            ip_address=ip_address or 'unknown',
            user_agent=user_agent
        )
        
        self.sessions[token] = session
        
        return {
            'access_token': token,
            'token_type': 'bearer',
            'expires_in': self.token_expiry,
            'expires_at': expires_at.isoformat()
        }
        
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user info"""
        try:
            # Check if session exists
            session = self.sessions.get(token)
            if not session or session.is_expired:
                return None
                
            # Decode token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Get user
            user = self.users.get(payload['username'])
            if not user or not user.active:
                return None
                
            return {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'permissions': user.permissions
            }
            
        except jwt.ExpiredSignatureError:
            logger.debug("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            return None
            
    async def revoke_token(self, token: str):
        """Revoke a token"""
        if token in self.sessions:
            del self.sessions[token]
            logger.info("Token revoked")
            
    async def create_user(self, username: str, password: str, 
                         role: str = 'viewer', email: Optional[str] = None) -> User:
        """Create a new user"""
        if username in self.users:
            raise ValueError(f"User {username} already exists")
            
        # Validate role
        if role not in self.ROLES:
            raise ValueError(f"Invalid role: {role}")
            
        # Validate password
        self._validate_password(password)
        
        # Create user
        user = User(
            id=secrets.token_urlsafe(16),
            username=username,
            password_hash=self.pwd_context.hash(password),
            role=role,
            email=email,
            permissions=self.ROLES[role]
        )
        
        self.users[username] = user
        logger.info(f"Created user: {username} with role: {role}")
        
        return user
        
    async def update_password(self, username: str, old_password: str, 
                            new_password: str) -> bool:
        """Update user password"""
        user = self.users.get(username)
        if not user:
            return False
            
        # Verify old password
        if not self.pwd_context.verify(old_password, user.password_hash):
            return False
            
        # Validate new password
        self._validate_password(new_password)
        
        # Update password
        user.password_hash = self.pwd_context.hash(new_password)
        
        # Revoke all sessions for this user
        sessions_to_revoke = [
            token for token, session in self.sessions.items()
            if session.user_id == user.id
        ]
        for token in sessions_to_revoke:
            await self.revoke_token(token)
            
        logger.info(f"Password updated for user: {username}")
        return True
        
    async def delete_user(self, username: str) -> bool:
        """Delete a user"""
        if username == 'admin':
            raise ValueError("Cannot delete admin user")
            
        if username in self.users:
            user = self.users[username]
            
            # Revoke all sessions
            sessions_to_revoke = [
                token for token, session in self.sessions.items()
                if session.user_id == user.id
            ]
            for token in sessions_to_revoke:
                await self.revoke_token(token)
                
            del self.users[username]
            logger.info(f"Deleted user: {username}")
            return True
            
        return False
        
    async def list_users(self) -> List[Dict[str, Any]]:
        """List all users"""
        return [
            {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'email': user.email,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'active': user.active
            }
            for user in self.users.values()
        ]
        
    async def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active sessions"""
        active_sessions = []
        
        for session in self.sessions.values():
            if not session.is_expired:
                user = next((u for u in self.users.values() if u.id == session.user_id), None)
                if user:
                    active_sessions.append({
                        'user': user.username,
                        'created_at': session.created_at.isoformat(),
                        'expires_at': session.expires_at.isoformat(),
                        'ip_address': session.ip_address,
                        'user_agent': session.user_agent
                    })
                    
        return active_sessions
        
    def _validate_password(self, password: str):
        """Validate password meets requirements"""
        policy = self.config.get('password_policy', {})
        
        min_length = policy.get('min_length', 8)
        if len(password) < min_length:
            raise ValueError(f"Password must be at least {min_length} characters")
            
        if policy.get('require_uppercase', True) and not any(c.isupper() for c in password):
            raise ValueError("Password must contain uppercase letter")
            
        if policy.get('require_lowercase', True) and not any(c.islower() for c in password):
            raise ValueError("Password must contain lowercase letter")
            
        if policy.get('require_numbers', True) and not any(c.isdigit() for c in password):
            raise ValueError("Password must contain number")
            
        if policy.get('require_special', False):
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                raise ValueError("Password must contain special character")
                
    async def _check_rate_limit(self, username: str, ip_address: str) -> bool:
        """Check if login attempt is rate limited"""
        max_attempts = self.config.get('max_login_attempts', 5)
        window = self.config.get('login_attempt_window', 300)  # 5 minutes
        
        now = time.time()
        key = f"{username}:{ip_address}"
        
        # Clean old attempts
        if key in self.failed_attempts:
            self.failed_attempts[key] = [
                t for t in self.failed_attempts[key] if now - t < window
            ]
            
        # Check limit
        attempts = self.failed_attempts.get(key, [])
        return len(attempts) < max_attempts
        
    async def _record_failed_attempt(self, username: str, ip_address: str):
        """Record failed login attempt"""
        key = f"{username}:{ip_address}"
        
        if key not in self.failed_attempts:
            self.failed_attempts[key] = []
            
        self.failed_attempts[key].append(time.time())
        
    async def _cleanup_expired_sessions(self):
        """Periodically cleanup expired sessions"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run hourly
                
                expired = [
                    token for token, session in self.sessions.items()
                    if session.is_expired
                ]
                
                for token in expired:
                    del self.sessions[token]
                    
                if expired:
                    logger.info(f"Cleaned up {len(expired)} expired sessions")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
                
    def check_permission(self, user: Dict[str, Any], permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in user.get('permissions', [])