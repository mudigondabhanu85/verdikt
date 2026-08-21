"""Real AWS KMS-backed KMSAdapter (§1.5/§9 enterprise hardening) — a
production key-custody model for credential/API-key secrets, replacing
LocalKMSAdapter's dev-only Fernet key. Uses KMS's direct Encrypt/Decrypt
API (not the generate-data-key envelope pattern) since every plaintext
this adapter ever handles (a credential secret, an AI provider API key)
is well under KMS's 4096-byte direct-encrypt limit for symmetric keys —
no need for local envelope encryption on top of KMS's own.
"""

import boto3

from app.vault.kms_adapter import KMSAdapter


class AwsKmsAdapter(KMSAdapter):
    def __init__(self, key_id: str, *, region_name: str = "us-east-1", client=None):
        self._key_id = key_id
        # client is test-only plumbing — lets tests inject a moto-backed
        # boto3 KMS client instead of talking to real AWS.
        self._client = client or boto3.client("kms", region_name=region_name)

    def encrypt(self, plaintext: bytes) -> bytes:
        response = self._client.encrypt(KeyId=self._key_id, Plaintext=plaintext)
        return response["CiphertextBlob"]

    def decrypt(self, ciphertext: bytes) -> bytes:
        # KeyId isn't required for Decrypt (KMS derives it from the
        # ciphertext blob itself), but passing it lets KMS reject a
        # ciphertext encrypted under a different key early and explicitly.
        response = self._client.decrypt(CiphertextBlob=ciphertext, KeyId=self._key_id)
        return response["Plaintext"]
