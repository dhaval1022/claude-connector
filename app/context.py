"""Per-request identity, set by the /mcp auth middleware and read by tools and auditing.

Kept in its own module so the audit logger and the tools can share it without import cycles."""
from contextvars import ContextVar

current_user_id: ContextVar[str] = ContextVar("current_user_id")
# Which AI provider is calling (app/providers.py). The default only matters for code paths that
# run outside a real request (tests, CLI); the middleware always sets it for /mcp calls.
current_provider: ContextVar[str] = ContextVar("current_provider", default="claude")
