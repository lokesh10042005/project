"""
Health and readiness check endpoints.
Used by load balancers, Kubernetes probes, and uptime monitors.
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.schemas.schemas import HealthResponse, ServiceStatus

router = APIRouter()
logger = logging.getLogger(__name__)

_startup_time = time.time()


@router.get("/health", response_model=HealthResponse, summary="Full health check")
async def health_check():
    services = []

    # PostgreSQL
    pg_status = await _check_postgres()
    services.append(pg_status)

    # MongoDB
    mongo_status = await _check_mongo()
    services.append(mongo_status)

    # Redis
    redis_status = await _check_redis()
    services.append(redis_status)

    # AI modules (always available — in-process)
    services.append(ServiceStatus(name="ai_engine", status="ok", latency_ms=0))

    all_ok = all(s.status == "ok" for s in services)
    any_down = any(s.status == "down" for s in services)
    overall = "healthy" if all_ok else ("unhealthy" if any_down else "degraded")

    from app.core.config import settings
    return HealthResponse(
        status=overall,
        version=settings.APP_VERSION,
        uptime_seconds=round(time.time() - _startup_time, 1),
        services=services,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/health/live", summary="Liveness probe (Kubernetes)")
async def liveness():
    """Returns 200 if the process is alive."""
    return {"status": "alive"}


@router.get("/health/ready", summary="Readiness probe (Kubernetes)")
async def readiness():
    """Returns 200 only when the app is ready to serve traffic."""
    pg = await _check_postgres()
    if pg.status == "down":
        return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "database_unavailable"})
    return {"status": "ready"}


# ── Sub-checks ────────────────────────────────────────────────────────────

async def _check_postgres() -> ServiceStatus:
    from app.db.database import _engine
    if _engine is None:
        return ServiceStatus(name="postgresql", status="down", detail="Engine not initialised")
    try:
        start = time.perf_counter()
        async with _engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        ms = (time.perf_counter() - start) * 1000
        return ServiceStatus(name="postgresql", status="ok", latency_ms=round(ms, 1))
    except Exception as exc:
        return ServiceStatus(name="postgresql", status="down", detail=str(exc))


async def _check_mongo() -> ServiceStatus:
    from app.db.database import app_state
    if app_state.mongo_client is None:
        return ServiceStatus(name="mongodb", status="down", detail="Not connected")
    try:
        start = time.perf_counter()
        await app_state.mongo_client.admin.command("ping")
        ms = (time.perf_counter() - start) * 1000
        return ServiceStatus(name="mongodb", status="ok", latency_ms=round(ms, 1))
    except Exception as exc:
        return ServiceStatus(name="mongodb", status="degraded", detail=str(exc))


async def _check_redis() -> ServiceStatus:
    from app.core.rate_limiter import rate_limiter
    if rate_limiter._redis is None:
        return ServiceStatus(name="redis", status="degraded", detail="Using in-process fallback")
    try:
        start = time.perf_counter()
        await rate_limiter._redis.ping()
        ms = (time.perf_counter() - start) * 1000
        return ServiceStatus(name="redis", status="ok", latency_ms=round(ms, 1))
    except Exception as exc:
        return ServiceStatus(name="redis", status="degraded", detail=str(exc))
