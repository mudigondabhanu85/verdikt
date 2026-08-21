"""Real AWS S3-backed ObjectStorageAdapter (§9 enterprise hardening) — a
production, multi-instance-safe object store for screenshots,
authorization PDFs, and other evidence, replacing LocalDiskObjectStorage's
single-machine local disk (fine for a dev/single-instance deploy, not for
anything horizontally scaled).
"""

import asyncio

import boto3

from app.storage.adapter import ObjectStorageAdapter


class S3ObjectStorage(ObjectStorageAdapter):
    def __init__(self, bucket: str, *, region_name: str = "us-east-1", client=None):
        self._bucket = bucket
        # client is test-only plumbing — lets tests inject a moto-backed
        # boto3 S3 client instead of talking to real AWS.
        self._client = client or boto3.client("s3", region_name=region_name)

    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> str:
        kwargs = {"Bucket": self._bucket, "Key": key, "Body": data}
        if content_type:
            kwargs["ContentType"] = content_type
        # boto3 is synchronous — offload to a thread so a large evidence
        # upload doesn't block the event loop other requests share.
        await asyncio.to_thread(self._client.put_object, **kwargs)
        return key

    async def get(self, key: str) -> bytes:
        response = await asyncio.to_thread(self._client.get_object, Bucket=self._bucket, Key=key)
        return await asyncio.to_thread(response["Body"].read)

    def url_for(self, key: str) -> str:
        return f"s3://{self._bucket}/{key}"
