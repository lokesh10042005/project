# ── Stage 1: dependency builder ───────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into a venv
COPY requirements.txt .
RUN python -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="AI Privacy Shield <team@ai-privacy-shield.dev>"
LABEL version="2.4.1"
LABEL description="AI Privacy Shield — FastAPI Backend"

# Create non-root user
RUN groupadd -r aps && useradd -r -g aps -d /app -s /sbin/nologin aps

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy venv from builder
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy application code
COPY app/ ./app/

# Create storage directories with correct ownership
RUN mkdir -p uploads outputs logs && chown -R aps:aps /app

# Switch to non-root user
USER aps

# Environment defaults (override via docker run -e or .env)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ENVIRONMENT=production \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# Health check (uses the liveness endpoint)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/live || exit 1

# Entrypoint: uvicorn with production settings
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
