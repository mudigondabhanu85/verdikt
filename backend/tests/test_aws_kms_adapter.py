import boto3
import pytest
from moto import mock_aws

from app.vault.aws_kms_adapter import AwsKmsAdapter
from app.vault.credential_vault import get_kms_adapter


@pytest.fixture
def clean_kms_adapter_cache():
    """get_kms_adapter() is @lru_cache'd process-wide — any test that
    makes it resolve to something other than the default LocalKMSAdapter
    must clear the cache before AND after, or it silently poisons every
    other test in the suite that touches credential encryption.
    """
    get_kms_adapter.cache_clear()
    yield
    get_kms_adapter.cache_clear()


@mock_aws
def test_aws_kms_adapter_round_trips_real_encrypt_decrypt_calls():
    client = boto3.client("kms", region_name="us-east-1")
    key_id = client.create_key()["KeyMetadata"]["KeyId"]

    adapter = AwsKmsAdapter(key_id, client=client)

    ciphertext = adapter.encrypt(b"admin@site.test\x00correct-horse-battery-staple")
    assert ciphertext != b"admin@site.test\x00correct-horse-battery-staple"

    plaintext = adapter.decrypt(ciphertext)
    assert plaintext == b"admin@site.test\x00correct-horse-battery-staple"


@mock_aws
def test_aws_kms_adapter_rejects_ciphertext_from_a_different_key():
    client = boto3.client("kms", region_name="us-east-1")
    key_a = client.create_key()["KeyMetadata"]["KeyId"]
    key_b = client.create_key()["KeyMetadata"]["KeyId"]

    adapter_a = AwsKmsAdapter(key_a, client=client)
    adapter_b = AwsKmsAdapter(key_b, client=client)

    ciphertext = adapter_a.encrypt(b"secret-for-key-a")

    from botocore.exceptions import ClientError

    try:
        adapter_b.decrypt(ciphertext)
        assert False, "expected an error decrypting with the wrong key"
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "AccessDeniedException"


class _FakeSettings:
    def __init__(self, kms_provider: str, aws_kms_key_id: str | None = None):
        self.kms_provider = kms_provider
        self.aws_kms_key_id = aws_kms_key_id
        self.aws_region = "us-east-1"
        self.vault_master_key = "dev-only-insecure-fernet-key-000000000000="


def test_get_kms_adapter_dispatches_to_aws_when_configured(clean_kms_adapter_cache, monkeypatch):
    monkeypatch.setattr(
        "app.vault.credential_vault.get_settings",
        lambda: _FakeSettings("aws", aws_kms_key_id="alias/verdikt-test"),
    )
    adapter = get_kms_adapter()
    assert isinstance(adapter, AwsKmsAdapter)


def test_get_kms_adapter_requires_key_id_for_aws(clean_kms_adapter_cache, monkeypatch):
    monkeypatch.setattr(
        "app.vault.credential_vault.get_settings", lambda: _FakeSettings("aws", aws_kms_key_id=None)
    )
    try:
        get_kms_adapter()
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "AWS_KMS_KEY_ID" in str(exc)


def test_get_kms_adapter_defaults_to_local(clean_kms_adapter_cache, monkeypatch):
    from app.vault.kms_adapter import LocalKMSAdapter

    monkeypatch.setattr(
        "app.vault.credential_vault.get_settings", lambda: _FakeSettings("local")
    )
    adapter = get_kms_adapter()
    assert isinstance(adapter, LocalKMSAdapter)
