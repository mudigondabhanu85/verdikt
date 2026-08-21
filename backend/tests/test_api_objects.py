from app.storage.local_disk import get_object_storage
from tests.conftest import register_org_admin


async def test_get_object_returns_stored_bytes(client):
    admin = await register_org_admin(client)

    storage = get_object_storage()
    await storage.put("clickjacking-proof/some-scan/evidence.png", b"\x89PNG-fake-bytes", content_type="image/png")

    resp = await client.get("/objects/clickjacking-proof/some-scan/evidence.png", headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.content == b"\x89PNG-fake-bytes"
    assert resp.headers["content-type"] == "image/png"


async def test_get_missing_object_is_404(client):
    admin = await register_org_admin(client)

    resp = await client.get("/objects/nope/does-not-exist.png", headers=admin["headers"])
    assert resp.status_code == 404


async def test_get_object_requires_auth(client):
    resp = await client.get("/objects/clickjacking-proof/some-scan/evidence.png")
    assert resp.status_code == 401
