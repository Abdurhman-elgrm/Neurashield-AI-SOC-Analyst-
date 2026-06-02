from __future__ import annotations

import time
from uuid import uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_ctx, tenant_id_ctx

logger = structlog.get_logger(__name__)

# Header name for optional caller-supplied request ID (useful for distributed tracing)
REQUEST_ID_HEADER = "X-Request-ID"
TENANT_ID_HEADER = "X-Tenant-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Assigns a unique request_id to every request, populates ContextVars
    used by structured logging, and logs request/response metadata.

    Placed first in the middleware stack so all downstream code has context.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Accept forwarded request ID or generate a new one
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid4())
        tenant_id = request.headers.get(TENANT_ID_HEADER, "")

        # Set ContextVars — visible to all log calls in this request's call chain
        request_id_token = request_id_ctx.set(request_id)
        tenant_id_token = tenant_id_ctx.set(tenant_id)

        start_time = time.perf_counter()

        logger.info(
            "http_request_started",
            method=request.method,
            path=request.url.path,
            client_ip=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )

        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "http_request_failed",
                method=request.method,
                path=request.url.path,
            )
            raise
        finally:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            request_id_ctx.reset(request_id_token)
            tenant_id_ctx.reset(tenant_id_token)

        logger.info(
            "http_request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        # Propagate request ID to client for correlation
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"
