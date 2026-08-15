from functools import lru_cache

from app.config import get_settings
from app.vault.kms_adapter import KMSAdapter, LocalKMSAdapter


@lru_cache
def get_kms_adapter() -> KMSAdapter:
    return LocalKMSAdapter(get_settings().vault_master_key)


def mask_reference(username: str, secret: str) -> str:
    """A safe-to-display reference — never the secret itself. Shows only
    the username and the secret's length class, e.g. "alice (****)"."""
    tail = secret[-2:] if len(secret) >= 2 else "**"
    return f"{username} (****{tail})"


def encrypt_credential(username: str, secret: str) -> bytes:
    """Encrypts "username\\0secret" as a single envelope so both fields are
    protected at rest; the plaintext secret is never persisted or logged
    on its own.
    """
    payload = f"{username}\0{secret}".encode()
    return get_kms_adapter().encrypt(payload)


def decrypt_credential(encrypted_secret: bytes) -> tuple[str, str]:
    payload = get_kms_adapter().decrypt(encrypted_secret)
    username, secret = payload.decode().split("\0", 1)
    return username, secret
