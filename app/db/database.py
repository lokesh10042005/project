"""
Database layer.
- PostgreSQL (via SQLAlchemy + asyncpg): structured relational data (users, sessions, jobs)
- MongoDB (via Motor): flexible document storage (image metadata, processing logs, reports)
"""

import logging
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── PostgreSQL ─────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker] = None


async def init_db() -> None:
    global _engine, _session_factory

    try:
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        _session_factory = async_sessionmaker(
            _engine, expire_on_commit=False, class_=AsyncSession
        )
        # Import models so SQLAlchemy discovers them before create_all
        from app.models import user, image_job  # noqa: F401
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅  PostgreSQL connected and tables created")
    except Exception as exc:
        logger.error("PostgreSQL init failed: %s — running without relational DB", exc)

    await _init_mongo()


async def _init_mongo() -> None:
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)
        await client.server_info()
        app_state.mongo_client = client
        app_state.mongo_db = client[settings.MONGO_DB_NAME]
        # Create indexes
        await _create_mongo_indexes()
        logger.info("✅  MongoDB connected")
    except Exception as exc:
        logger.warning("MongoDB init failed: %s — document storage disabled", exc)


async def _create_mongo_indexes() -> None:
    db = app_state.mongo_db
    if db is None:
        return
    await db.image_jobs.create_index("job_id", unique=True)
    await db.image_jobs.create_index("user_id")
    await db.image_jobs.create_index("created_at")
    await db.processing_logs.create_index("job_id")
    await db.reports.create_index("user_id")
    logger.info("MongoDB indexes created")


async def close_db() -> None:
    if _engine:
        await _engine.dispose()
    if app_state.mongo_client:
        app_state.mongo_client.close()
    logger.info("Database connections closed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield an async DB session."""
    if _session_factory is None:
        raise RuntimeError("Database not initialised")
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Shared app state (lightweight alternative to global vars) ─────────────

class _AppState:
    mongo_client = None
    mongo_db = None


app_state = _AppState()


def get_mongo_db():
    """FastAPI dependency: return the Motor database handle."""
    if app_state.mongo_db is None:
        raise RuntimeError("MongoDB not available")
    return app_state.mongo_db
