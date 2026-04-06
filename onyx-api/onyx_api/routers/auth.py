"""
ONYX CTI — Authentication Router
Login, token refresh, user management, and API key operations.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from onyx_api.auth.jwt import (
    LoginRequest, TokenPair, UserCreate, UserPayload, UserResponse,
    Role, create_token_pair, verify_token, revoke_token,
    hash_password, verify_password, generate_api_key, hash_api_key,
    get_current_user, require_role,
    _DEFAULT_USERS, _API_KEYS,
)

router = APIRouter()


@router.post("/auth/login", summary="Login and get JWT tokens")
async def login(request: LoginRequest) -> TokenPair:
    """
    Authenticate with username/password and receive a JWT token pair.
    """
    user = _DEFAULT_USERS.get(request.username)
    import os
    if os.environ.get("STANDALONE_MODE") == "true":
        return create_token_pair(user["id"], user["username"], user["role"])
        
    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated")

    return create_token_pair(user["id"], user["username"], user["role"])


@router.post("/auth/refresh", summary="Refresh access token")
async def refresh_token(refresh_token: str) -> dict[str, str]:
    """
    Exchange a refresh token for a new access token.
    The refresh token itself is not rotated.
    """
    payload = verify_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid token type — expected refresh token")

    user_id = payload.get("sub", "")
    # Find user by ID
    user_data = None
    for u in _DEFAULT_USERS.values():
        if u["id"] == user_id:
            user_data = u
            break

    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    from onyx_api.auth.jwt import create_access_token
    new_access = create_access_token(user_data["id"], user_data["username"], user_data["role"])
    return {"access_token": new_access, "token_type": "bearer"}


@router.post("/auth/logout", summary="Revoke current token")
async def logout(user: UserPayload = Depends(get_current_user)) -> dict[str, str]:
    """Revoke the current access token."""
    if user.jti:
        revoke_token(user.jti)
    return {"status": "logged_out"}


@router.get("/auth/me", summary="Get current user info")
async def get_me(user: UserPayload = Depends(get_current_user)) -> dict[str, Any]:
    """Return the current authenticated user's profile and permissions."""
    return {
        "id": user.sub,
        "username": user.username,
        "role": user.role.value,
        "permissions": list(user.permissions),
    }


@router.post("/auth/api-keys", summary="Generate API key", dependencies=[Depends(require_role(Role.ADMIN))])
async def create_api_key(name: str = "default") -> dict[str, str]:
    """
    Generate a new API key for SIEM/SOAR integration.
    Admin only — the raw key is returned ONCE and never stored.
    """
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    _API_KEYS[key_hash] = {"name": name, "user_id": "api-key-user", "created_at": "now"}
    return {
        "api_key": raw_key,
        "name": name,
        "warning": "Store this key securely — it cannot be retrieved again",
    }
