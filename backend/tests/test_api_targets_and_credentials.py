from app.agents.macro import MacroStep
from tests.conftest import create_project_and_version, register_org_admin


async def test_target_crud(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    added = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "app.example.test", "port": 443, "base_url": "https://app.example.test"},
        headers=admin["headers"],
    )
    assert added.status_code == 201
    target_id = added.json()["id"]

    listed = await client.get(f"/versions/{version_id}/targets", headers=admin["headers"])
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/versions/{version_id}/targets/{target_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get(f"/versions/{version_id}/targets", headers=admin["headers"])
    assert len(listed_after.json()) == 0


async def test_credential_set_never_returns_plaintext_secret(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "Admin",
            "credential_type": "username_password",
            "username": "alice",
            "secret": "hunter2-super-secret",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "hunter2-super-secret" not in resp.text
    assert body["masked_reference"].startswith("alice")

    listed = await client.get(f"/versions/{version_id}/credentials", headers=admin["headers"])
    assert "hunter2-super-secret" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/versions/{version_id}/credentials/{body['id']}", headers=admin["headers"]
    )
    assert deleted.status_code == 204


async def test_record_macro_stores_steps_against_credential(client, monkeypatch):
    """The actual browser recording mechanism (JS injection, event
    capture, field-role inference) is covered live against a real
    fixture login page in test_macro_recorder.py and test_login.py —
    launching a real headed, blocks-until-closed browser here would hang
    an automated test run. This test instead proves the API route itself
    (RBAC, 404s, persistence, response shape) by substituting a canned
    MacroRecorder.record() result, the same test-double pattern used for
    the AI provider adapters elsewhere in this codebase.
    """
    canned_steps = [
        MacroStep(action="goto", url="https://site.test/login"),
        MacroStep(action="fill", selector="#username", field_role="username"),
        MacroStep(action="fill", selector="#password", field_role="password"),
        MacroStep(action="click", selector="#submit-btn"),
    ]

    async def _fake_record(self, start_url, *, headless=False, drive=None):
        assert start_url == "https://site.test/login"
        return canned_steps

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.record", _fake_record)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    credential = await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "Admin",
            "credential_type": "username_password",
            "username": "alice",
            "secret": "hunter2-super-secret",
        },
        headers=admin["headers"],
    )
    credential_id = credential.json()["id"]

    resp = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["credential_set_id"] == credential_id
    assert body["version_id"] == version_id
    assert body["step_count"] == len(canned_steps)


async def test_list_macros_returns_recorded_macros_for_the_credential(client, monkeypatch):
    canned_steps = [
        MacroStep(action="goto", url="https://site.test/login"),
        MacroStep(action="fill", selector="#username", field_role="username"),
    ]

    async def _fake_record(self, start_url, *, headless=False, drive=None):
        return canned_steps

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.record", _fake_record)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    credential = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2-super-secret"},
        headers=admin["headers"],
    )
    credential_id = credential.json()["id"]

    empty = await client.get(
        f"/versions/{version_id}/credentials/{credential_id}/macros", headers=admin["headers"]
    )
    assert empty.status_code == 200
    assert empty.json() == []

    await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )

    listed = await client.get(
        f"/versions/{version_id}/credentials/{credential_id}/macros", headers=admin["headers"]
    )
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 1
    assert body[0]["step_count"] == len(canned_steps)
    assert body[0]["credential_set_id"] == credential_id


async def test_record_macro_404_for_unknown_credential(client, monkeypatch):
    async def _fake_record(self, start_url, *, headless=False, drive=None):
        raise AssertionError("should not be called for a 404 credential")

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.record", _fake_record)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/credentials/00000000-0000-0000-0000-000000000000/record-macro",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    assert resp.status_code == 404
