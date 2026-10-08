"""
Authentication routes: register, login, token refresh, profile, logout.
"""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    UserRole, create_access_token, create_refresh_token,
    decode_token, get_current_user, hash_password, verify_password,
)
from app.db.database import get_db
from app.models.image_job import User
from app.schemas.schemas import (
    LoginRequest, MessageResponse, RefreshRequest,
    RegisterRequest, TokenResponse, UserResponse,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Check email uniqueness
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Check username uniqueness
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        id=uuid.uuid4(),
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),
        role=UserRole.USER,
    )
    db.add(user)
    await db.flush()

    logger.info("New user registered: %s (%s) from %s", body.username, body.email, request.client.host)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT tokens",
)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    user: User | None = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning("Failed login attempt for email=%s from %s", body.email, request.client.host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    access_token = create_access_token(str(user.id), role=UserRole(user.role))
    refresh_token = create_refresh_token(str(user.id), role=UserRole(user.role))

    from app.core.config import settings
    logger.info("User logged in: %s from %s", user.username, request.client.host)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange a refresh token for a new access token",
)
async def refresh_token(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    role = UserRole(payload.get("role", UserRole.USER))

    result = await db.execute(select(User).where(User.id == user_id))
    user: User | None = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    from app.core.config import settings
    return TokenResponse(
        access_token=create_access_token(user_id, role=role),
        refresh_token=create_refresh_token(user_id, role=role),
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user["sub"]))
    user: User | None = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout (client-side token invalidation note)",
)
async def logout(current_user: dict = Depends(get_current_user)):
    """
    JWT tokens are stateless — true server-side revocation requires
    a Redis denylist (implemented in the full production version).
    For now, clients should discard their tokens.
    """
    logger.info("User %s logged out", current_user.get("sub"))
    return MessageResponse(message="Logged out successfully. Please discard your tokens.")
