"""Per-data-source circuit breaker: after repeated CONNECTION failures stop hammering a down
database for a short while. User mistakes (bad SQL) and slow queries do not count."""
import time

from app.config import get_settings

_now = time.monotonic   # patched in tests
_state: dict[str, dict] = {}
# Positive evidence only. Drivers raise OperationalError for plenty of USER mistakes (SQLite and
# MySQL do for an unknown column), so the exception class alone must never open the breaker.
_BENIGN = ("timeout", "timed out", "canceling statement", "max_execution_time", "interrupted",
           "cancelled", "time limit")
_CONNECTION_MARKERS = (
    "connection refused", "could not connect", "unable to connect", "can't connect",
    "connection reset", "connection closed", "server closed the connection",
    "lost connection", "server has gone away", "broken pipe", "no route to host",
    "network is unreachable", "name or service not known", "temporary failure in name",
    "could not translate host", "communication link failure", "ssl syscall",
    "password authentication failed", "access denied for user", "login failed",
    "too many connections", "the database system is starting up")


def is_connection_failure(e: Exception) -> bool:
    msg = str(e).lower()
    if isinstance(e, TimeoutError) or any(b in msg for b in _BENIGN):
        return False
    if getattr(e, "connection_invalidated", False):      # SQLAlchemy: the driver lost the link
        return True
    if isinstance(e, (ConnectionError, OSError)):
        return True
    if type(e).__name__ in ("EndpointConnectionError", "ConnectTimeoutError",
                            "NoCredentialsError"):
        return True
    return any(m in msg for m in _CONNECTION_MARKERS)


def check(source_id: str) -> None:
    st = _state.get(source_id)
    if st and st["open_until"] > _now():
        wait = int(st["open_until"] - _now()) + 1
        raise ValueError(f"This data source is temporarily unavailable after repeated connection "
                         f"failures. Retry in about {wait}s, or check the database is reachable.")


def record_failure(source_id: str, e: Exception) -> None:
    if not is_connection_failure(e):
        return
    s = get_settings()
    st = _state.setdefault(source_id, {"fails": 0, "open_until": 0.0})
    st["fails"] += 1
    if st["fails"] >= s.breaker_failures:
        st["open_until"], st["fails"] = _now() + s.breaker_open_s, 0


def record_success(source_id: str) -> None:
    _state.pop(source_id, None)


def reset() -> None:
    _state.clear()
