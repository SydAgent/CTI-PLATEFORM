# ============================================================================
# ONYX CTI — API Server Dockerfile
# Multi-stage build: slim Python 3.12 with non-root execution.
# Serves FastAPI via uvicorn with production settings.
# ============================================================================
FROM python:3.12-slim AS base

# System dependencies for async DB drivers
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r onyx && useradd -r -g onyx -d /app -s /sbin/nologin onyx

WORKDIR /app

# --- Dependency Stage ---
FROM base AS deps

# Install core library first (shared dependency)
COPY onyx-core/pyproject.toml /app/onyx-core/pyproject.toml
COPY onyx-core/onyx_core/ /app/onyx-core/onyx_core/
RUN pip install --no-cache-dir /app/onyx-core

# Install API dependencies
COPY onyx-api/pyproject.toml /app/onyx-api/pyproject.toml
COPY onyx-api/onyx_api/ /app/onyx-api/onyx_api/
RUN pip install --no-cache-dir /app/onyx-api

# --- Runtime Stage ---
FROM base AS runtime

COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY --from=deps /app /app

# Install NLP dependencies (heavy, separate layer for caching)
COPY onyx-nlp/pyproject.toml /app/onyx-nlp/pyproject.toml
COPY onyx-nlp/onyx_nlp/ /app/onyx-nlp/onyx_nlp/
RUN pip install --no-cache-dir /app/onyx-nlp 2>/dev/null || true

# Install crawlers
COPY onyx-crawlers/pyproject.toml /app/onyx-crawlers/pyproject.toml
COPY onyx-crawlers/onyx_crawlers/ /app/onyx-crawlers/onyx_crawlers/
RUN pip install --no-cache-dir /app/onyx-crawlers 2>/dev/null || true

# Install connectors
COPY onyx-connectors/pyproject.toml /app/onyx-connectors/pyproject.toml
COPY onyx-connectors/onyx_connectors/ /app/onyx-connectors/onyx_connectors/
RUN pip install --no-cache-dir /app/onyx-connectors 2>/dev/null || true

# Install analyzers
COPY onyx-analyzers/pyproject.toml /app/onyx-analyzers/pyproject.toml
COPY onyx-analyzers/onyx_analyzers/ /app/onyx-analyzers/onyx_analyzers/
RUN pip install --no-cache-dir /app/onyx-analyzers 2>/dev/null || true

# Environment
ENV PYTHONPATH="/app/onyx-api:/app/onyx-core:/app/onyx-nlp:/app/onyx-crawlers:/app/onyx-connectors:/app/onyx-analyzers"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Switch to non-root
USER onyx

EXPOSE 8000

# Health check
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=30s \
    CMD curl -sf http://localhost:8000/api/v1/health || exit 1

# Default: run API server
CMD ["uvicorn", "onyx_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--loop", "uvloop", "--http", "httptools", "--access-log"]
