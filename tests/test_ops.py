"""Operations: migrations match the models, key rotation is safe, CLI works end to end."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, select

from app.auth.passwords import verify_password
from app.db.models import Base, DataSource, User
from app.db.session import SessionLocal, engine
from app.sources.crypto import decrypt_config, encrypt_config, generate_key, parse_key
from app.sources.rotation import RotationError, rotate_master_key

ROOT = Path(__file__).resolve().parent.parent


def cli(args, db_path, **env):
    e = {**os.environ, "CONNECTOR_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}", **env}
    return subprocess.run([sys.executable, "-m", "app.cli", *args], cwd=ROOT, env=e,
                          capture_output=True, text=True, timeout=120)


# ------------------------------------------------------------------ migrations
def test_migration_creates_exactly_the_model_schema(tmp_path):
    db = tmp_path / "m.db"
    r = cli(["migrate"], db)
    assert r.returncode == 0, r.stderr
    sync = create_engine(f"sqlite:///{db}")
    with sync.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models and migrations have drifted: {diff}"   # add a new migration!
    tables = {r[0] for r in sqlite3.connect(db).execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "data_sources", "oauth_clients", "oauth_codes", "refresh_tokens",
            "audit_log", "semantic_items", "exports", "alembic_version"} <= tables


def test_migrate_is_idempotent(tmp_path):
    db = tmp_path / "m.db"
    assert cli(["migrate"], db).returncode == 0
    r = cli(["migrate"], db)
    assert r.returncode == 0 and "up to date" in r.stdout


def test_create_admin_end_to_end(tmp_path):
    db = tmp_path / "a.db"
    assert cli(["create-admin", "boss@x.in", "Boss", "short"], db).returncode != 0
    assert cli(["create-admin", "not-an-email", "Boss", "long-enough-pw"], db).returncode != 0
    r = cli(["create-admin", "Boss@X.in", "Boss", "a-long-password"], db)
    assert r.returncode == 0, r.stderr
    row = sqlite3.connect(db).execute(
        "SELECT email, role, password_hash, must_change_password FROM users").fetchone()
    assert row[0] == "boss@x.in" and row[1] == "admin" and row[3] == 1
    assert row[2].startswith("$argon2") and verify_password("a-long-password", row[2])
    assert cli(["create-admin", "boss@x.in", "Boss", "a-long-password"], db).returncode != 0


def test_cli_key_generators_and_usage(tmp_path):
    k = cli(["gen-key"], tmp_path / "x.db").stdout.strip()
    assert len(parse_key(k)) == 32
    s = cli(["gen-secret"], tmp_path / "x.db").stdout.strip()
    assert len(s) >= 48
    assert cli([], tmp_path / "x.db").returncode != 0
    assert cli(["bogus"], tmp_path / "x.db").returncode != 0


# ------------------------------------------------------------------ key rotation
@pytest_asyncio.fixture
async def sources():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    old = generate_key()
    async with SessionLocal() as s:
        u = User(email="r@x.in", name="R", password_hash="x")
        s.add(u)
        await s.commit()
        ids = []
        for i in range(3):
            d = DataSource(owner_id=u.id, name=f"s{i}", engine="postgres", config_encrypted=b"")
            s.add(d)
            await s.flush()
            d.config_encrypted = encrypt_config({"password": f"pw-{i}", "host": "h"}, d.id,
                                                parse_key(old))
            ids.append(d.id)
        await s.commit()
    return {"old": old, "ids": ids}


async def _blobs():
    async with SessionLocal() as s:
        return {d.id: d.config_encrypted for d in (await s.execute(select(DataSource))).scalars()}


async def test_rotation_reencrypts_everything_and_old_key_stops_working(sources):
    new = generate_key()
    before = await _blobs()
    assert await rotate_master_key(sources["old"], new) == 3
    after = await _blobs()
    for i, sid in enumerate(sources["ids"]):
        assert after[sid] != before[sid]
        assert decrypt_config(after[sid], sid, parse_key(new))["password"] == f"pw-{i}"
        with pytest.raises(Exception):
            decrypt_config(after[sid], sid, parse_key(sources["old"]))


async def test_dry_run_changes_nothing(sources):
    before = await _blobs()
    assert await rotate_master_key(sources["old"], generate_key(), dry_run=True) == 3
    assert await _blobs() == before


async def test_wrong_old_key_aborts_atomically(sources):
    before = await _blobs()
    with pytest.raises(RotationError, match="OLD key"):
        await rotate_master_key(generate_key(), generate_key())
    assert await _blobs() == before


async def test_one_corrupt_record_aborts_the_whole_rotation(sources):
    async with SessionLocal() as s:
        d = await s.get(DataSource, sources["ids"][1])
        d.config_encrypted = b"\x00" * 40
        await s.commit()
    before = await _blobs()
    with pytest.raises(RotationError, match=sources["ids"][1]):
        await rotate_master_key(sources["old"], generate_key())
    assert await _blobs() == before                       # nothing was half-rotated


async def test_rotation_rejects_bad_or_identical_keys(sources):
    with pytest.raises(RotationError, match="identical"):
        await rotate_master_key(sources["old"], sources["old"])
    with pytest.raises(RuntimeError, match="base64|32 bytes"):
        await rotate_master_key(sources["old"], "not-a-key")
    with pytest.raises(RuntimeError, match="32 bytes"):
        await rotate_master_key(sources["old"], "c2hvcnQ=")


def test_rotate_key_cli(tmp_path):
    db = tmp_path / "rk.db"
    assert cli(["migrate"], db).returncode == 0
    old, new = generate_key(), generate_key()
    r = cli(["rotate-key", old, new, "--dry-run"], db)
    assert r.returncode == 0 and "Dry run OK: 0" in r.stdout
    r = cli(["rotate-key", old, new], db)
    assert r.returncode == 0 and "Re-encrypted 0" in r.stdout
    assert cli(["rotate-key", old, old], db).returncode != 0
    assert cli(["rotate-key", "garbage", new], db).returncode != 0


# ------------------------------------------------------------------ migration 0002 on real data
def test_upgrade_backfills_existing_rows_claude_only_and_is_reversible(tmp_path):
    from alembic import command

    from app.db.migrate import _config
    db = tmp_path / "old.db"
    url = f"sqlite+aiosqlite:///{db}"
    command.upgrade(_config(url), "0001")                        # the schema before providers
    c = sqlite3.connect(db)
    c.execute("INSERT INTO users (id,email,name,password_hash,role,is_active,must_change_password,"
              "failed_logins,created_at) VALUES ('u1','a@x.in','A','h','analyst',1,0,0,'2026-01-01')")
    c.execute("INSERT INTO data_sources (id,owner_id,name,engine,config_encrypted,status,created_at) "
              "VALUES ('s1','u1','old source','postgres',x'00','ok','2026-01-01')")
    c.execute("INSERT INTO oauth_clients (client_id,client_name,redirect_uris,created_at) "
              "VALUES ('c1','x','[]','2026-01-01')")
    c.execute("INSERT INTO refresh_tokens (token_hash,client_id,user_id,expires_at,revoked) "
              "VALUES ('t1','c1','u1','2027-01-01',0)")
    c.commit(); c.close()

    command.upgrade(_config(url), "head")
    c = sqlite3.connect(db)
    import json
    assert json.loads(c.execute("SELECT allowed_providers FROM users").fetchone()[0]) == ["claude"]
    assert "allowed_providers" not in {r[1] for r in c.execute("PRAGMA table_info(data_sources)")}
    assert c.execute("SELECT provider FROM refresh_tokens").fetchone()[0] == "claude"
    assert c.execute("SELECT provider_hint FROM oauth_clients").fetchone()[0] == ""
    assert {r[1] for r in c.execute("PRAGMA table_info(api_tokens)")} >= {
        "token_hash", "owner_id", "expires_at", "revoked", "provider"}
    c.close()

    command.downgrade(_config(url), "0001")                      # and it can be rolled back
    c = sqlite3.connect(db)
    cols = {r[1] for r in c.execute("PRAGMA table_info(data_sources)")}
    assert "allowed_providers" not in cols and "allowed_providers" not in {
        r[1] for r in c.execute("PRAGMA table_info(users)")}
    assert c.execute("SELECT name FROM data_sources").fetchone()[0] == "old source"   # data intact
    c.close()


# ------------------------------------------------------------------ migration 0003 on real data
def test_0003_gives_each_user_the_union_of_apps_enabled_on_their_sources(tmp_path):
    import json

    from alembic import command

    from app.db.migrate import _config
    db = tmp_path / "mid.db"
    url = f"sqlite+aiosqlite:///{db}"
    command.upgrade(_config(url), "0002")
    c = sqlite3.connect(db)
    for uid in ("u1", "u2"):
        c.execute("INSERT INTO users (id,email,name,password_hash,role,is_active,must_change_password,"
                  f"failed_logins,created_at) VALUES ('{uid}','{uid}@x.in','A','h','analyst',1,0,0,'2026-01-01')")
    for sid, owner, allowed in (("s1", "u1", '["claude","openai"]'), ("s2", "u1", '["gemini"]'),
                                ("s3", "u2", '["claude"]')):
        c.execute("INSERT INTO data_sources (id,owner_id,name,engine,config_encrypted,status,created_at,"
                  f"allowed_providers) VALUES ('{sid}','{owner}','n','postgres',x'00','ok','2026-01-01','{allowed}')")
    c.commit(); c.close()
    command.upgrade(_config(url), "head")
    c = sqlite3.connect(db)
    got = {r[0]: json.loads(r[1]) for r in c.execute("SELECT id, allowed_providers FROM users")}
    assert got == {"u1": ["claude", "openai", "gemini"], "u2": ["claude"]}
    c.close()
