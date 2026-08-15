from abc import ABC, abstractmethod


class KMSAdapter(ABC):
    """Envelope-encryption primitive for credential secrets (§1.5, §5).
    Swap LocalKMSAdapter for a real AWS KMS / Azure Key Vault / GCP KMS
    adapter in production — application code depends only on this
    interface.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes: ...


class LocalKMSAdapter(KMSAdapter):
    """Fernet-based symmetric encryption keyed by a locally-held master key.

    DEV/TEST ONLY. The key lives in process config (see app.config), which
    is fine for a local Docker Compose stack but is not an acceptable key
    custody model for production — production deployments MUST implement
    KMSAdapter against a real key-management service instead.
    """

    def __init__(self, master_key: str):
        from cryptography.fernet import Fernet

        self._fernet = Fernet(self._normalize_key(master_key))

    @staticmethod
    def _normalize_key(master_key: str) -> bytes:
        import base64
        import hashlib

        # Accept any string as a dev convenience; derive a valid 32-byte
        # urlsafe-base64 Fernet key from it rather than requiring the
        # operator to hand-generate one for local dev.
        digest = hashlib.sha256(master_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)
