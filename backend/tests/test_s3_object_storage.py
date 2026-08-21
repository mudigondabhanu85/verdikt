import boto3
import pytest
from moto import mock_aws

from app.storage.local_disk import LocalDiskObjectStorage, get_object_storage
from app.storage.s3_storage import S3ObjectStorage


def _make_bucket_and_client() -> boto3.client:
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="verdikt-evidence-test")
    return client


async def test_s3_object_storage_round_trips_real_put_get_calls():
    with mock_aws():
        client = _make_bucket_and_client()
        storage = S3ObjectStorage("verdikt-evidence-test", client=client)

        key = await storage.put(
            "xss-browser-proof/abc/def.png", b"pngbytes", content_type="image/png"
        )
        assert key == "xss-browser-proof/abc/def.png"

        data = await storage.get("xss-browser-proof/abc/def.png")
        assert data == b"pngbytes"


async def test_s3_object_storage_get_missing_key_raises():
    from botocore.exceptions import ClientError

    with mock_aws():
        client = _make_bucket_and_client()
        storage = S3ObjectStorage("verdikt-evidence-test", client=client)

        with pytest.raises(ClientError):
            await storage.get("does/not/exist.png")


def test_s3_object_storage_url_for_returns_s3_uri():
    client = boto3.client("s3", region_name="us-east-1")
    storage = S3ObjectStorage("verdikt-evidence-test", client=client)
    assert storage.url_for("foo/bar.png") == "s3://verdikt-evidence-test/foo/bar.png"


class _FakeSettings:
    def __init__(self, object_storage_provider: str, aws_s3_bucket: str | None = None):
        self.object_storage_provider = object_storage_provider
        self.aws_s3_bucket = aws_s3_bucket
        self.aws_region = "us-east-1"
        self.object_storage_root = "./data/objects"


@pytest.fixture
def clean_object_storage_cache():
    get_object_storage.cache_clear()
    yield
    get_object_storage.cache_clear()


def test_get_object_storage_dispatches_to_s3_when_configured(clean_object_storage_cache, monkeypatch):
    monkeypatch.setattr(
        "app.storage.local_disk.get_settings",
        lambda: _FakeSettings("s3", aws_s3_bucket="verdikt-evidence-test"),
    )
    storage = get_object_storage()
    assert isinstance(storage, S3ObjectStorage)


def test_get_object_storage_requires_bucket_for_s3(clean_object_storage_cache, monkeypatch):
    monkeypatch.setattr(
        "app.storage.local_disk.get_settings", lambda: _FakeSettings("s3", aws_s3_bucket=None)
    )
    with pytest.raises(RuntimeError, match="AWS_S3_BUCKET"):
        get_object_storage()


def test_get_object_storage_defaults_to_local(clean_object_storage_cache, monkeypatch):
    monkeypatch.setattr(
        "app.storage.local_disk.get_settings", lambda: _FakeSettings("local")
    )
    storage = get_object_storage()
    assert isinstance(storage, LocalDiskObjectStorage)
