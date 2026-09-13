import io
import zipfile

from tests.conftest import register_org_admin


async def test_download_returns_a_real_zip_of_the_extension_source(client):
    admin = await register_org_admin(client)

    resp = await client.get("/browser-extension/download", headers=admin["headers"])

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert 'filename="verdikt-login-macro-recorder.zip"' in resp.headers["content-disposition"]

    archive = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(archive.namelist())
    assert "verdikt-login-macro-recorder/manifest.json" in names
    assert "verdikt-login-macro-recorder/background.js" in names
    assert "verdikt-login-macro-recorder/popup.html" in names

    manifest = archive.read("verdikt-login-macro-recorder/manifest.json").decode()
    assert "Verdikt Login Macro Recorder" in manifest


async def test_download_requires_authentication(client):
    resp = await client.get("/browser-extension/download")
    assert resp.status_code == 401


async def test_download_404s_cleanly_when_source_dir_is_misconfigured(client, monkeypatch):
    from app.config import get_settings

    admin = await register_org_admin(client)
    monkeypatch.setattr(get_settings(), "browser_extension_source_dir", "/does/not/exist")

    resp = await client.get("/browser-extension/download", headers=admin["headers"])

    assert resp.status_code == 404
