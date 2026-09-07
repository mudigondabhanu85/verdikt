from tests.conftest import create_project_and_version, create_user_with_role, register_org_admin


async def test_archive_hides_project_from_default_list_but_not_include_archived(client):
    admin = await register_org_admin(client)
    project_id, _ = await create_project_and_version(client, admin["headers"])

    archived = await client.post(f"/projects/{project_id}/archive", headers=admin["headers"])
    assert archived.status_code == 204

    default_list = await client.get("/projects", headers=admin["headers"])
    assert project_id not in [p["id"] for p in default_list.json()]

    full_list = await client.get("/projects?include_archived=true", headers=admin["headers"])
    ids = [p["id"] for p in full_list.json()]
    assert project_id in ids
    matching = next(p for p in full_list.json() if p["id"] == project_id)
    assert matching["archived_at"] is not None


async def test_unarchive_restores_project_to_default_list(client):
    admin = await register_org_admin(client)
    project_id, _ = await create_project_and_version(client, admin["headers"])

    await client.post(f"/projects/{project_id}/archive", headers=admin["headers"])
    unarchived = await client.post(f"/projects/{project_id}/unarchive", headers=admin["headers"])
    assert unarchived.status_code == 204

    default_list = await client.get("/projects", headers=admin["headers"])
    assert project_id in [p["id"] for p in default_list.json()]


async def test_hard_delete_requires_delete_permission(client, db_adapter):
    admin = await register_org_admin(client)
    project_id, _ = await create_project_and_version(client, admin["headers"])
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]

    analyst = await create_user_with_role(
        db_adapter, org_id=org_id, role="analyst", email="analyst@acme.io"
    )

    resp = await client.delete(f"/projects/{project_id}", headers=analyst["headers"])
    assert resp.status_code == 403


async def test_hard_delete_removes_project_and_all_dependents_without_fk_errors(client):
    admin = await register_org_admin(client)
    project_id, version_id = await create_project_and_version(client, admin["headers"])

    await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": "example.test", "in_scope": True},
        headers=admin["headers"],
    )
    cred = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2"},
        headers=admin["headers"],
    )
    assert cred.status_code == 201
    target = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "example.test", "base_url": "http://example.test/"},
        headers=admin["headers"],
    )
    assert target.status_code == 201
    scan = await client.post(f"/versions/{version_id}/scan-runs", json={}, headers=admin["headers"])
    assert scan.status_code == 201

    deleted = await client.delete(f"/projects/{project_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    get_after = await client.get(f"/projects/{project_id}", headers=admin["headers"])
    assert get_after.status_code == 404

    versions_after = await client.get(
        f"/projects/{project_id}/versions", headers=admin["headers"]
    )
    assert versions_after.status_code == 404


async def test_hard_delete_removes_project_with_a_vgs_report_draft(client):
    """Regression test: vgs_report_drafts.version_id had no ON DELETE
    CASCADE and _hard_delete_project never cleaned it up, so deleting a
    project that had a VGS report draft on one of its versions used to
    fail with a ForeignKeyViolation on `DELETE FROM versions`."""
    admin = await register_org_admin(client)
    project_id, version_id = await create_project_and_version(client, admin["headers"])

    draft = await client.get(f"/versions/{version_id}/vgs-report-draft", headers=admin["headers"])
    assert draft.status_code == 200

    vuln = await client.post(
        f"/versions/{version_id}/vgs-report-draft/vulnerabilities",
        json={"title": "Ad-hoc XSS", "severity": "High", "description": "desc"},
        headers=admin["headers"],
    )
    assert vuln.status_code == 201
    vuln_id = vuln.json()["id"]

    step = await client.post(
        f"/versions/{version_id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps",
        data={"comment": "step 1"},
        headers=admin["headers"],
    )
    assert step.status_code == 201

    deleted = await client.delete(f"/projects/{project_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    get_after = await client.get(f"/projects/{project_id}", headers=admin["headers"])
    assert get_after.status_code == 404
