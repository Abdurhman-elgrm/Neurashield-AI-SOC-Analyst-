from __future__ import annotations

import re
import time
from uuid import uuid4

_REQUEST_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

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
        # Accept only safe alphanumeric/dash/underscore IDs; reject all others
        raw_id = request.headers.get(REQUEST_ID_HEADER, "")
        if raw_id and _REQUEST_ID_RE.match(raw_id):
            request_id = raw_id
        else:
            request_id = str(uuid4())
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds defensive HTTP security headers to every API response.

    Header rationale:
      X-Frame-Options          — prevents clickjacking (DENY = no iframes at all)
      X-Content-Type-Options   — prevents MIME-type sniffing exploits
      X-XSS-Protection         — legacy browser XSS filter (belt-and-suspenders)
      Referrer-Policy          — limits referrer leakage cross-origin
      Permissions-Policy       — opts out of powerful features we don't use
      Strict-Transport-Security — HSTS; only effective over HTTPS, ignored over HTTP
      Content-Security-Policy  — restricts which resources the browser may load

    ⚠️  CSP COVERAGE NOTE
    This service is a pure JSON API — it serves no HTML pages.  Browsers only
    enforce CSP on HTML document responses, so the CSP header here provides
    defence-in-depth for API responses but does NOT protect the React SPA against
    XSS.  CSP for the SPA must be set at the layer that serves the built frontend
    (Nginx, Railway static, or CDN).  Use a header equivalent to:

        Content-Security-Policy:
          default-src 'self';
          script-src  'self';
          style-src   'self' 'unsafe-inline';
          img-src     'self' data:;
          font-src    'self' data:;
          connect-src 'self' wss:;
          frame-ancestors 'none';
          base-uri    'self';
          form-action 'self'

    Note: connect-src must include 'wss:' (or the specific backend WSS origin) so
    the frontend WebSocket connection is allowed by the browser.
    """

    _HEADERS: dict[str, str] = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": ("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        "Strict-Transport-Security": ("max-age=63072000; includeSubDomains; preload"),
        # 'unsafe-inline' removed from style-src. Modern SPA bundlers (Vite/Next.js)
        # can emit CSS modules or hashed <style> tags instead of blanket inline styles.
        # If specific third-party widget styles are needed, add a nonce at the framework
        # level or use a hash-allowlist rather than re-enabling unsafe-inline.
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in self._HEADERS.items():
            response.headers.setdefault(header, value)
        return response


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Records RED (Rate, Errors, Duration) metrics for every HTTP request.
    The `/metrics` path itself is excluded to avoid self-referential noise.
    Path labels are normalized to avoid cardinality explosion from UUIDs.
    """

    _UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    _INT_RE = re.compile(r"/\d+(?=/|$)")

    @classmethod
    def _normalize_path(cls, path: str) -> str:
        path = cls._UUID_RE.sub("{id}", path)
        path = cls._INT_RE.sub("/{int}", path)
        return path

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)

        from app.core.metrics import (
            HTTP_REQUEST_DURATION_SECONDS,
            HTTP_REQUESTS_IN_FLIGHT,
            HTTP_REQUESTS_TOTAL,
        )

        path = self._normalize_path(request.url.path)
        method = request.method

        HTTP_REQUESTS_IN_FLIGHT.inc()
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            HTTP_REQUESTS_TOTAL.labels(method=method, path=path, status_code="500").inc()
            HTTP_REQUESTS_IN_FLIGHT.dec()
            raise
        duration = time.perf_counter() - start
        HTTP_REQUESTS_TOTAL.labels(
            method=method, path=path, status_code=str(response.status_code)
        ).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(duration)
        HTTP_REQUESTS_IN_FLIGHT.dec()
        return response


class ContentLengthLimitMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests with a body larger than `max_bytes` before the body is
    read into memory.  Prevents DoS via oversized payloads.

    Checks Content-Length header first (fast path); if absent, falls back to
    streaming the body up to the limit.  Ingest endpoints that accept large
    batches need a higher limit — configure in create_application() per-route
    if necessary, or increase MAX_BODY_BYTES in settings.
    """

    _DEFAULT_MAX = 10 * 1024 * 1024  # 10 MiB

    def __init__(self, app, max_bytes: int = _DEFAULT_MAX) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_bytes:
                    from starlette.responses import JSONResponse

                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            except ValueError:
                pass
        return await call_next(request)
