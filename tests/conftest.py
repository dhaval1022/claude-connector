import os
import tempfile

from app.config import Settings  # noqa: E402
from app.sources.crypto import generate_key  # noqa: E402

# Hermetic tests: never read a developer's local .env (it would silently change behaviour,
# e.g. ALLOW_LOOPBACK or a bootstrap admin). Settings come only from the variables below.
Settings.model_config["env_file"] = None

os.environ.update({
    "CONNECTOR_MASTER_KEY": generate_key(),
    "CONNECTOR_ENABLE_SQLITE": "true",
    "CONNECTOR_DATA_DIR": tempfile.mkdtemp(prefix="cc_test_data_"),
    # Outside the repo: a sync client (OneDrive/Dropbox) can lock or rewrite a SQLite file
    # mid-test and cause intermittent "no such table" failures.
    "CONNECTOR_DATABASE_URL": "sqlite+aiosqlite:///"
                              + tempfile.mkdtemp(prefix="cc_test_db_").replace("\\", "/")
                              + "/test_connector.db",
    "CONNECTOR_JWT_SECRET": "test-secret-test-secret-test-secret-32",
    "CONNECTOR_PUBLIC_BASE_URL": "http://test",
})


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_limits():
    """Rate limiters and circuit breakers are process-global; isolate every test."""
    from app import breaker, ratelimit
    ratelimit.LIMITER.reset()
    breaker.reset()
    yield
