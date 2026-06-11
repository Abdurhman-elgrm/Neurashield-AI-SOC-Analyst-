#!/bin/sh
# Container startup: apply DB schema then launch the app or worker.

# Worker mode: skip migrations (web service already ran them), start worker directly.
if [ "${WORKER_MODE:-false}" = "true" ]; then
    echo "[startup] ── Worker mode ──────────────────────────────────────────────"
    exec python -m app.workers.main
fi

echo "[startup] ── Database schema ────────────────────────────────────────"

# Attempt 1: standard alembic migration path (works on clean Railway DBs)
if alembic upgrade head 2>&1; then
    echo "[startup] Migrations applied via alembic."
else
    echo "[startup] alembic upgrade head failed (likely tables pre-exist)."
    echo "[startup] Falling back to create_all..."

    # Attempt 2: create_all(checkfirst=True) creates only missing tables/enums.
    # Then stamps alembic_version so future upgrades are no-ops.
    if python ensure_schema.py; then
        echo "[startup] Schema ready via ensure_schema."
    else
        echo "[startup] WARNING: schema setup failed — server starting anyway."
        echo "[startup] Some endpoints may return 500. Check Railway Deploy Logs."
    fi
fi

echo "[startup] ── Starting uvicorn ──────────────────────────────────────"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
