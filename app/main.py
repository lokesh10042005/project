"""
AI Privacy Shield — FastAPI Backend
Production-grade API server for image protection against AI threats.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import auth, images, processing, reports, health
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.db.database import init_db, close_db
from app.core.rate_limiter import RateLimiter

setup_logging()
logger = logging.getLogger(__name__)

rate_limiter = RateLimiter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("🛡️  AI Privacy Shield starting up...")
    await init_db()
    await rate_limiter.init()
    logger.info("✅  All systems nominal — server ready")
    yield
    logger.info("🔻  Shutting down...")
    await close_db()
    logger.info("👋  Server stopped cleanly")


app = FastAPI(
    title="AI Privacy Shield API",
    description=(
        "Production-grade REST API for protecting images against facial recognition, "
        "deepfake generation, and automated data scraping using adversarial ML."
    ),
    version="2.4.1",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log every request with timing and attach request ID."""
    start = time.perf_counter()
    request_id = request.headers.get("X-Request-ID", f"req_{int(time.time()*1000)}")
    request.state.request_id = request_id

    response = await call_next(request)

    duration_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"

    logger.info(
        "HTTP %s %s → %s  (%.1fms) [%s]",
        request.method, request.url.path,
        response.status_code, duration_ms, request_id,
    )
    return response


@app.middleware("http")
async def anti_scraping_middleware(request: Request, call_next):
    """
    Detect and handle automated scraper / bot traffic.
    Suspicious requests are served adversarial/poisoned data instead of
    being blocked outright — this pollutes attacker datasets.
    """
    ua = request.headers.get("User-Agent", "")
    suspicious = any(bot in ua.lower() for bot in [
        "scrapy", "python-requests", "wget", "curl", "phantomjs",
        "headless", "selenium", "puppeteer", "bot", "spider", "crawler",
    ])
    if suspicious:
        logger.warning("🚨 Bot/scraper detected: UA=%s  IP=%s", ua, request.client.host)
        request.state.is_bot = True
    else:
        request.state.is_bot = False

    response = await call_next(request)
    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Per-IP rate limiting."""
    if request.url.path.startswith("/api/"):
        client_ip = request.client.host
        allowed, retry_after = await rate_limiter.check(client_ip, request.url.path)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


# ── Global exception handler ──────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please try again.",
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )


# ── Routers ───────────────────────────────────────────────────────────────

app.include_router(health.router,      prefix="/api/v1",          tags=["Health"])
app.include_router(auth.router,        prefix="/api/v1/auth",     tags=["Authentication"])
app.include_router(images.router,      prefix="/api/v1/images",   tags=["Images"])
app.include_router(processing.router,  prefix="/api/v1/process",  tags=["Processing"])
app.include_router(reports.router,     prefix="/api/v1/reports",  tags=["Reports"])


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "AI Privacy Shield API",
        "version": "2.4.1",
        "status": "operational",
        "docs": "/docs",
    }
