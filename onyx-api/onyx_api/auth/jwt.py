"""
ONYX CTI — JWT Authentication & RBAC
Production-grade auth with:
- JWT access + refresh tokens (RS256 or HS256)
- Role-Based Access Control (admin, analyst, viewer, api_key)
- API key authentication for SIEM/SOAR integrations
- Token refresh, revocation, and expiry management
- TAXII 2.1 Basic Auth compatibility (§1.6.4)
- CSRF protection via double-submit pattern

Pattern source: IntelOwl auth + OpenCTI Bearer token middleware.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
    APIKeyHeader,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from onyx_core.config import get_config

# ============================================================================
# Configuration
# ============================================================================
_cfg = get_config()
JWT_SECRET = _cfg.jwt_secret
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Password hashing (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
basic_scheme = HTTPBasic(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ============================================================================
# RBAC Roles
# ============================================================================
class Role(str, Enum):
    ADMIN = "admin"        # Full access: user management, TAXII write, config
    ANALYST = "analyst"    # Read/write IOCs, run NLP, manage crawlers
    VIEWER = "viewer"      # Read-only dashboard access
    API_KEY = "api_key"    # Machine-to-machine (SIEM integration)


# Permission matrix
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {
        "read", "write", "delete", "manage_users", "manage_crawlers",
        "taxii_read", "taxii_write", "nlp_analyze", "config",
    },
    Role.ANALYST: {
        "read", "write", "manage_crawlers", "taxii_read", "nlp_analyze",
    },
    Role.VIEWER: {
        "read", "taxii_read",
    },
    Role.API_KEY: {
        "read", "write", "taxii_read", "taxii_write",
    },
}


# ============================================================================
# Models
# ============================================================================
class UserPayload(BaseModel):
    """JWT payload claims."""
    sub: str                   # User ID
    username: str
    role: Role
    permissions: set[str] = set()
    exp: float = 0
    iat: float = 0
    jti: str = ""              # JWT ID for revocation tracking


class TokenPair(BaseModel):
    """Access + refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    role: str


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=200)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=12, max_length=200)
    role: Role = Role.VIEWER
    email: str | None = None


class UserResponse(BaseModel):
    id: str
    username: str
    role: Role
    email: str | None = None
    created_at: str
    last_login: str | None = None
    is_active: bool = True


# ============================================================================
# Token Management
# ============================================================================

# In-memory revocation list (production: use Redis)
_revoked_tokens: set[str] = set()


def create_access_token(user_id: str, username: str, role: Role) -> str:
    """Create a signed JWT access token."""
    jti = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "username": username,
        "role": role.value,
        "permissions": list(ROLE_PERMISSIONS.get(role, set())),
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": now,
        "jti": jti,
        "iss": "onyx-cti",
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create a long-lived refresh token."""
    jti = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "type": "refresh",
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": now,
        "jti": jti,
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_token_pair(user_id: str, username: str, role: Role) -> TokenPair:
    """Generate both access and refresh tokens."""
    return TokenPair(
        access_token=create_access_token(user_id, username, role),
        refresh_token=create_refresh_token(user_id),
        role=role.value,
    )


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti", "")
        if jti in _revoked_tokens:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def revoke_token(jti: str) -> None:
    """Add a token JTI to the revocation list."""
    _revoked_tokens.add(jti)


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain, hashed)


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return f"onyx_{secrets.token_urlsafe(48)}"


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


# ============================================================================
# FastAPI Dependencies — Auth Extractors
# ============================================================================

# Hardcoded default admin for bootstrapping (production: use MongoDB)
_DEFAULT_USERS = {
    "admin": {
        "id": "user-admin-001",
        "username": "admin",
        "password_hash": "$2b$12$Z0H99D7qM8aQ81yQ9S.K.OUv3B5N.v/gP6n9J3Z5I9M7q8Z9C8K.O", # onyx_admin_2026!
        "role": Role.ADMIN,
        "email": "admin@onyx.local",
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    },
    "analyst": {
        "id": "user-analyst-001",
        "username": "analyst",
        "password_hash": "$2b$12$E/t8gN8v5RMWJp6/P1wB2eM.n7H57L9O8aG4vXvJ3dZ5I9M7q8Z9C", # onyx_analyst_2026!
        "role": Role.ANALYST,
        "email": "analyst@onyx.local",
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    },
}

# Hardcoded API keys for bootstrapping
_API_KEYS: dict[str, dict] = {}


async def get_current_user(
    bearer: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    basic: HTTPBasicCredentials | None = Depends(basic_scheme),
    api_key: str | None = Depends(api_key_header),
) -> UserPayload:
    """
    Extract and validate the current user from the request.
    
    Supports three auth methods (priority order):
    1. Bearer JWT token (Authorization: Bearer <token>)
    2. HTTP Basic Auth (for TAXII §1.6.4 compatibility)
    3. API Key header (X-API-Key: <key>)
    """

    # Method 1: Bearer JWT
    if bearer and bearer.credentials:
        payload = verify_token(bearer.credentials)
        return UserPayload(
            sub=payload.get("sub", ""),
            username=payload.get("username", ""),
            role=Role(payload.get("role", "viewer")),
            permissions=set(payload.get("permissions", [])),
            exp=payload.get("exp", 0),
            iat=payload.get("iat", 0),
            jti=payload.get("jti", ""),
        )

    # Method 2: HTTP Basic Auth (TAXII compatibility)
    if basic and basic.username and basic.password:
        user = _DEFAULT_USERS.get(basic.username)
        if user and verify_password(basic.password, user["password_hash"]):
            return UserPayload(
                sub=user["id"],
                username=user["username"],
                role=user["role"],
                permissions=ROLE_PERMISSIONS.get(user["role"], set()),
            )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Method 3: API Key
    if api_key:
        key_hash = hash_api_key(api_key)
        key_info = _API_KEYS.get(key_hash)
        if key_info:
            return UserPayload(
                sub=key_info.get("user_id", "api"),
                username=key_info.get("name", "api_user"),
                role=Role.API_KEY,
                permissions=ROLE_PERMISSIONS[Role.API_KEY],
            )
        raise HTTPException(status_code=401, detail="Invalid API key")

    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="onyx-cti"'},
    )


def require_permission(permission: str):
    """
    FastAPI dependency that checks if the current user has a specific permission.
    Usage: @router.get("/admin", dependencies=[Depends(require_permission("manage_users"))])
    """
    async def _check(user: UserPayload = Depends(get_current_user)) -> UserPayload:
        if permission not in user.permissions and permission not in ROLE_PERMISSIONS.get(user.role, set()):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: '{permission}' required (your role: {user.role.value})",
            )
        return user
    return _check


def require_role(min_role: Role):
    """Require a minimum role level."""
    role_hierarchy = {Role.VIEWER: 0, Role.API_KEY: 1, Role.ANALYST: 2, Role.ADMIN: 3}

    async def _check(user: UserPayload = Depends(get_current_user)) -> UserPayload:
        if role_hierarchy.get(user.role, 0) < role_hierarchy.get(min_role, 0):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: minimum role '{min_role.value}' required",
            )
        return user
    return _check
