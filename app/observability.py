"""Structured logs, request ids, security headers, metrics. No secrets or query strings are
ever logged: /files/<token> paths are redacted and query strings (OAuth codes) are dropped."""
import json
import logging
import re
import time
import uuid
from contextvars import ContextVar
from urllib.parse import urlsplit

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.datastructures import MutableHeaders

from app.config import get_settings

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
log = logging.getLogger("connector")

TOOL_CALLS = Counter("connector_tool_calls_total", "Tool calls", ["tool", "status"])
TOOL_SECONDS = Histogram("connector_tool_seconds", "Tool call duration", ["tool"],
                         buckets=(.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300))
HTTP_REQUESTS = Counter("connector_http_requests_total", "HTTP requests", ["status"])
_RID_OK = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_FILES_PATH = re.compile(r"^/files/.+")


class JsonFormatter(logging.Formatter):
    _SKIP = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
               "level": record.levelname, "logger": record.name, "msg": record.getMessage(),
               "request_id": request_id_var.get()}
        out.update({k: v for k, v in record.__dict__.items() if k not in self._SKIP})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging() -> None:
    root = logging.getLogger()
    if any(getattr(h, "_connector", False) for h in root.handlers):
        return
    h = logging.StreamHandler()
    h._connector = True
    h.setFormatter(JsonFormatter() if get_settings().log_json
                   else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(h)
    root.setLevel(logging.INFO)


def log_event(event: str, **fields) -> None:
    log.info(event, extra={"event": event, **fields})


def record_tool(tool: str, status: str, elapsed_ms: int | None) -> None:
    TOOL_CALLS.labels(tool, status).inc()
    if elapsed_ms is not None:
        TOOL_SECONDS.labels(tool).observe(elapsed_ms / 1000)


def metrics_body() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


def safe_path(path: str) -> str:
    return "/files/[redacted]" if _FILES_PATH.match(path) else path


class RequestContextMiddleware:
    """Pure ASGI (safe for streaming/SSE): request id, security headers, access log."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        incoming = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _RID_OK.match(incoming) else uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        https = get_settings().public_base_url.startswith("https")
        start, status = time.monotonic(), 500

        async def send_wrapper(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                h = MutableHeaders(scope=message)
                h["X-Request-ID"] = rid
                h["X-Content-Type-Options"] = "nosniff"
                h["Referrer-Policy"] = "no-referrer"
                if https:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            HTTP_REQUESTS.labels(str(status)).inc()
            log_event("http_request", method=scope["method"], path=safe_path(scope["path"]),
                      status=status, ms=int((time.monotonic() - start) * 1000),
                      ip=(scope.get("client") or ("-",))[0])
            request_id_var.reset(token)


def allowed_hosts() -> list[str]:
    s = get_settings()
    host = urlsplit(s.public_base_url).hostname or ""
    hosts = [host, *s.allowed_hosts]
    if not s.public_base_url.startswith("https"):    # dev convenience only
        hosts += ["localhost", "127.0.0.1"]
    return [h for h in hosts if h]
