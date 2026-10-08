"""
Security utilities: JWT tokens, password hashing, role-based access control.
"""

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


# ── Roles ─────────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    GUEST = "guest"
    USER = "user"
    PRO = "pro"
    ADMIN = "admin"


ROLE_HIERARCHY = {
    UserRole.GUEST: 0,
    UserRole.USER: 1,
    UserRole.PRO: 2,
    UserRole.ADMIN: 99,
}


# ── Password hashing ──────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── JWT tokens ────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: UserRole = UserRole.USER,
    extra: Optional[dict] = None,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": subject,
        "role": role.value,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": expire,
        **(extra or {}),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str, role: UserRole = UserRole.USER) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": subject,
        "role": role.value,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError as exc:
        logger.warning("JWT decode failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependencies ──────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    """Dependency: extract and validate the Bearer token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    return payload


def require_role(minimum_role: UserRole):
    """Dependency factory: enforce minimum role level."""
    async def _check(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = UserRole(current_user.get("role", UserRole.GUEST))
        if ROLE_HIERARCHY[user_role] < ROLE_HIERARCHY[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role.value}' role or higher",
            )
        return current_user
    return _check


# Convenience role guards
require_user  = require_role(UserRole.USER)
require_pro   = require_role(UserRole.PRO)
require_admin = require_role(UserRole.ADMIN)
