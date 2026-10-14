"""provider allow-list moves from data sources to users

Revision ID: 0003
Revises: 0002
"""
import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: Union[str, Sequence[str], None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CLAUDE = '["claude"]'


def upgrade() -> None:
    """Backfill so nobody gains access: each user keeps exactly the apps they had enabled on any of
    their sources (the union), and users with no sources stay Claude-only."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('allowed_providers', sa.JSON(),
                                      server_default=sa.text(f"'{_CLAUDE}'"), nullable=False))
    conn = op.get_bind()
    union: dict[str, set] = {}
    for owner, allowed in conn.execute(sa.text("SELECT owner_id, allowed_providers FROM data_sources")):
        got = json.loads(allowed) if isinstance(allowed, str) else (allowed or [])
        union.setdefault(owner, set()).update(got)
    order = ("claude", "openai", "gemini", "other")
    for owner, got in union.items():
        conn.execute(sa.text("UPDATE users SET allowed_providers = :v WHERE id = :i"),
                     {"v": json.dumps([p for p in order if p in got]), "i": owner})
    with op.batch_alter_table('data_sources', schema=None) as batch_op:
        batch_op.drop_column('allowed_providers')


def downgrade() -> None:
    with op.batch_alter_table('data_sources', schema=None) as batch_op:
        batch_op.add_column(sa.Column('allowed_providers', sa.JSON(),
                                      server_default=sa.text(f"'{_CLAUDE}'"), nullable=False))
    conn = op.get_bind()
    for uid, allowed in conn.execute(sa.text("SELECT id, allowed_providers FROM users")):
        conn.execute(sa.text("UPDATE data_sources SET allowed_providers = :v WHERE owner_id = :i"),
                     {"v": allowed if isinstance(allowed, str) else json.dumps(allowed), "i": uid})
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('allowed_providers')
