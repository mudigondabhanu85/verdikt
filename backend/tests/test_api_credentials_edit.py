import uuid
from datetime import datetime, timezone

from app.models.login_macro import LoginMacro
from app.models.traffic import TrafficInteraction
from app.vault.credential_vault import decrypt_credential
from tests.conftest import create_project_and_version, register_org_admin, session_scope


async def test_patch_updates_only_given_fields_and_preserves_secret_when_omitted(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2-super-secret"},
        headers=admin["headers"],
    )
    credential_id = created.json()["id"]

    patched = await client.patch(
        f"/versions/{version_id}/credentials/{credential_id}",
        json={"label": "Admin (rotated)", "login_endpoint": "https://app.test/api/login"},
        headers=admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["label"] == "Admin (rotated)"
    assert body["login_endpoint"] == "https://app.test/api/login"
    assert "hunter2-super-secret" not in patched.text
    # Username/secret untouched by this PATCH — masked_reference still shows the original username.
    assert body["masked_reference"].startswith("alice")


async def test_patch_rotates_secret_independently_of_username(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "old-secret"},
        headers=admin["headers"],
    )
    credential_id = created.json()["id"]

    patched = await client.patch(
        f"/versions/{version_id}/credentials/{credential_id}",
        json={"secret": "new-rotated-secret"},
        headers=admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert "new-rotated-secret" not in patched.text

    from tests.conftest import session_scope
    from app.models.credential import CredentialSet
    import uuid as uuid_module

    async with session_scope(db_adapter) as session:
        cred = await session.get(CredentialSet, uuid_module.UUID(credential_id))
        username, secret = decrypt_credential(cred.encrypted_secret)
        assert username == "alice"
        assert secret == "new-rotated-secret"


async def test_patch_404_for_unknown_credential(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.patch(
        f"/versions/{version_id}/credentials/00000000-0000-0000-0000-000000000000",
        json={"label": "x"},
        headers=admin["headers"],
    )
    assert resp.status_code == 404


async def test_new_version_carries_forward_credentials_as_independent_copies(client):
    admin = await register_org_admin(client)
    project_id, version_1_id = await create_project_and_version(client, admin["headers"], version_name="v1")

    cred1 = await client.post(
        f"/versions/{version_1_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "v1-secret", "extra_cookies": {"security": "low"}},
        headers=admin["headers"],
    )
    assert cred1.status_code == 201

    version_2 = await client.post(
        f"/projects/{project_id}/versions", json={"name": "v2"}, headers=admin["headers"]
    )
    assert version_2.status_code == 201
    version_2_id = version_2.json()["id"]

    v2_creds = await client.get(f"/versions/{version_2_id}/credentials", headers=admin["headers"])
    assert v2_creds.status_code == 200
    body = v2_creds.json()
    assert len(body) == 1
    assert body[0]["label"] == "Admin"
    assert body[0]["extra_cookies"] == {"security": "low"}
    v2_cred_id = body[0]["id"]
    assert v2_cred_id != cred1.json()["id"]

    # Editing v2's copy must not affect v1's original.
    await client.patch(
        f"/versions/{version_2_id}/credentials/{v2_cred_id}",
        json={"label": "Admin (v2 rotated)"},
        headers=admin["headers"],
    )
    v1_creds_after = await client.get(f"/versions/{version_1_id}/credentials", headers=admin["headers"])
    assert v1_creds_after.json()[0]["label"] == "Admin"


async def test_delete_credential_with_macro_and_traffic_history_succeeds(client, db_adapter):
    """Regression test: login_macros.credential_set_id and
    traffic_interactions.credential_set_id had no ON DELETE behavior, so
    deleting a credential that had ever recorded a login macro or any
    traffic (which any real scan run produces) always failed with a
    ForeignKeyViolation. Fixed via migration 0021 (CASCADE / SET NULL
    respectively) — live-verified against real Postgres, where FK
    constraints are actually enforced. This test's SQLite backend never
    enforces ON DELETE behavior at all (no PRAGMA foreign_keys=ON; see
    app.db.postgres_adapter — turning it on broke ~150 unrelated tests
    that rely on SQLite's lax FK checking, so it's deliberately left
    off), so it can only prove the DELETE itself no longer raises."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2"},
        headers=admin["headers"],
    )
    credential_id = uuid.UUID(created.json()["id"])

    async with session_scope(db_adapter) as session:
        session.add(
            LoginMacro(version_id=uuid.UUID(version_id), credential_set_id=credential_id, steps=[])
        )
        session.add(
            TrafficInteraction(
                version_id=uuid.UUID(version_id),
                credential_set_id=credential_id,
                source="manual",
                timestamp=datetime.now(timezone.utc),
                request_method="GET",
                request_url="http://example.test/",
            )
        )
        await session.commit()

    deleted = await client.delete(
        f"/versions/{version_id}/credentials/{credential_id}", headers=admin["headers"]
    )
    assert deleted.status_code == 204, deleted.text


async def test_new_version_with_no_prior_credentials_starts_empty(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    creds = await client.get(f"/versions/{version_id}/credentials", headers=admin["headers"])
    assert creds.json() == []
