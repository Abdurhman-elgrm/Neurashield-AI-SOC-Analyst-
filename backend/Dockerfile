# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for asyncpg + argon2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip "setuptools>=68.0" wheel \
    && pip install --no-cache-dir --no-build-isolation "."

# ─── Stage 2: Development ─────────────────────────────────────────────────────
FROM python:3.12-slim AS development

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ─── Stage 3: Production ──────────────────────────────────────────────────────
FROM python:3.12-slim AS production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY app/ ./app/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/
COPY alembic.ini .
COPY ensure_schema.py .
COPY start.sh .

RUN chmod +x start.sh \
    && chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["./start.sh"]
