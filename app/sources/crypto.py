"""AES-256-GCM encryption for data-source credentials.

The ciphertext is bound (as AAD) to the source id, so a stored blob can't be swapped
between records. Format: 12-byte nonce || ciphertext+tag."""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings


def parse_key(raw: str) -> bytes:
    if not raw:
        raise RuntimeError("CONNECTOR_MASTER_KEY is not set (32 bytes, base64). "
                           "Generate one with: python -m app.cli gen-key")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        raise RuntimeError("The master key is not valid base64")
    if len(key) != 32:
        raise RuntimeError("The master key must decode to exactly 32 bytes")
    return key


def _key() -> bytes:
    return parse_key(get_settings().master_key)


def generate_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def encrypt_config(config: dict, source_id: str, key: bytes | None = None) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key or _key()).encrypt(nonce, json.dumps(config).encode(), source_id.encode())
    return nonce + ct


def decrypt_config(blob: bytes, source_id: str, key: bytes | None = None) -> dict:
    return json.loads(AESGCM(key or _key()).decrypt(blob[:12], blob[12:], source_id.encode()))
