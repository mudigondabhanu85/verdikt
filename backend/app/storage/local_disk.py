from functools import lru_cache
from pathlib import Path

from app.config import get_settings
from app.storage.adapter import ObjectStorageAdapter


class LocalDiskObjectStorage(ObjectStorageAdapter):
    def __init__(self, root: str):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        # Reject path traversal — keys come from user-controlled filenames.
        safe_key = key.replace("\\", "/")
        if ".." in safe_key.split("/"):
            raise ValueError(f"invalid object key: {key!r}")
        path = self._root / safe_key
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> str:
        path = self._path_for(key)
        path.write_bytes(data)
        return key

    async def get(self, key: str) -> bytes:
        return self._path_for(key).read_bytes()

    def url_for(self, key: str) -> str:
        return str(self._path_for(key))


@lru_cache
def get_object_storage() -> ObjectStorageAdapter:
    settings = get_settings()
    if settings.object_storage_provider == "s3":
        if not settings.aws_s3_bucket:
            raise RuntimeError("object_storage_provider=s3 requires AWS_S3_BUCKET to be set")
        from app.storage.s3_storage import S3ObjectStorage

        return S3ObjectStorage(settings.aws_s3_bucket, region_name=settings.aws_region)
    return LocalDiskObjectStorage(settings.object_storage_root)
