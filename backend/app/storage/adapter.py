from abc import ABC, abstractmethod


class ObjectStorageAdapter(ABC):
    """Stores raw evidence/traffic/report/attestation files. Default
    implementation is local disk; S3/Azure Blob are swappable
    implementations of this same interface for enterprise deploys.
    """

    @abstractmethod
    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> str:
        """Store data under key, return a reference usable with get()/url_for()."""
        ...

    @abstractmethod
    async def get(self, key: str) -> bytes:
        ...

    @abstractmethod
    def url_for(self, key: str) -> str:
        """Best-effort locator for the stored object (path or URL)."""
        ...
