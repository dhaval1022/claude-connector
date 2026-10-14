"""Master-key rotation: re-encrypt every stored data-source credential under a new key.

All-or-nothing: every record is decrypted with the OLD key and re-encrypted, and each result is
verified by decrypting it again with the NEW key, before a single row is written. A wrong old
key or a corrupt record aborts with nothing changed."""
from sqlalchemy import select

from app.db.models import DataSource
from app.db.session import SessionLocal
from app.sources.crypto import decrypt_config, encrypt_config, parse_key


class RotationError(RuntimeError):
    pass


async def rotate_master_key(old_b64: str, new_b64: str, dry_run: bool = False) -> int:
    old, new = parse_key(old_b64), parse_key(new_b64)
    if old == new:
        raise RotationError("The new key is identical to the old key.")
    async with SessionLocal() as db:
        sources = (await db.execute(select(DataSource))).scalars().all()
        updates = []
        for s in sources:
            try:
                cfg = decrypt_config(s.config_encrypted, s.id, old)
            except Exception:
                raise RotationError(
                    f"Cannot decrypt data source {s.id} with the OLD key; is it the key the "
                    "data was encrypted with? Nothing was changed.")
            blob = encrypt_config(cfg, s.id, new)
            if decrypt_config(blob, s.id, new) != cfg:     # verify before committing anything
                raise RotationError(f"Verification failed for data source {s.id}.")
            updates.append((s, blob))
        if not dry_run:
            for s, blob in updates:
                s.config_encrypted = blob
            await db.commit()
        return len(updates)
