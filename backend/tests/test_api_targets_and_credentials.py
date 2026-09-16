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


async def test_adding_a_target_auto_derives_a_matching_scope_entry(client):
    """Regression coverage for a real, repeated failure mode: a Target
    with no matching Scope entry (Scope is an independent, exact
    host+port allow-list — see app.agents.scope.is_in_scope) makes every
    agent crawl nothing while still reporting a 'completed' scan. Adding
    a Target should auto-create its matching in-scope entry so a host
    only ever has to be typed once."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    added = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "app.example.test", "port": 443, "base_url": "https://app.example.test"},
        headers=admin["headers"],
    )
    assert added.status_code == 201

    scope = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    assert scope.status_code == 200
    entries = scope.json()
    assert len(entries) == 1
    assert entries[0]["host"] == "app.example.test"
    assert entries[0]["port"] == 443
    assert entries[0]["in_scope"] is True

    # Adding a second Target for the same host+port must not create a
    # duplicate scope entry.
    added_again = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "app.example.test", "port": 443, "base_url": "https://app.example.test/other"},
        headers=admin["headers"],
    )
    assert added_again.status_code == 201
    scope_after = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    assert len(scope_after.json()) == 1


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


async def test_credential_set_extra_cookies_round_trip(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "Admin",
            "credential_type": "username_password",
            "username": "admin",
            "secret": "password",
            "extra_cookies": {"security": "low"},
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["extra_cookies"] == {"security": "low"}

    listed = await client.get(f"/versions/{version_id}/credentials", headers=admin["headers"])
    assert listed.json()[0]["extra_cookies"] == {"security": "low"}


def _fake_recording_handle(start_url: str = "https://site.test/login"):
    from app.agents.macro import RecordingHandle

    return RecordingHandle(playwright=None, browser=None, page=None, raw_steps=[], start_url=start_url)


async def test_record_macro_start_then_finish_stores_steps_against_credential(client, monkeypatch):
    """The actual browser recording mechanism (JS injection, event
    capture, field-role inference) is covered live against a real
    fixture login page in test_macro_recorder.py and test_login.py —
    launching a real headed browser here would hang an automated test
    run. This test instead proves the API routes themselves (RBAC,
    404s, persistence, response shape) by substituting canned
    MacroRecorder.start()/finish() results, the same test-double pattern
    used for the AI provider adapters elsewhere in this codebase.
    """
    canned_steps = [
        MacroStep(action="goto", url="https://site.test/login"),
        MacroStep(action="fill", selector="#username", field_role="username"),
        MacroStep(action="fill", selector="#password", field_role="password"),
        MacroStep(action="click", selector="#submit-btn"),
    ]

    async def _fake_start(self, start_url, *, headless=False):
        assert start_url == "https://site.test/login"
        return _fake_recording_handle(start_url)

    async def _fake_finish(self, handle):
        return canned_steps

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.start", _fake_start)
    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.finish", _fake_finish)

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

    started = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/start",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    assert started.status_code == 201, started.text
    recording_id = started.json()["recording_id"]

    resp = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/finish",
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["credential_set_id"] == credential_id
    assert body["version_id"] == version_id
    assert body["step_count"] == len(canned_steps)

    # Finishing pops the handle out of the registry — a second finish
    # call on the same recording_id must not silently succeed again.
    replayed = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/finish",
        headers=admin["headers"],
    )
    assert replayed.status_code == 404


async def test_list_macros_returns_recorded_macros_for_the_credential(client, monkeypatch):
    canned_steps = [
        MacroStep(action="goto", url="https://site.test/login"),
        MacroStep(action="fill", selector="#username", field_role="username"),
    ]

    async def _fake_start(self, start_url, *, headless=False):
        return _fake_recording_handle(start_url)

    async def _fake_finish(self, handle):
        return canned_steps

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.start", _fake_start)
    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.finish", _fake_finish)

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

    started = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/start",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    recording_id = started.json()["recording_id"]
    await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/finish",
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


async def test_delete_login_macro_removes_it(client, monkeypatch):
    canned_steps = [MacroStep(action="goto", url="https://site.test/login")]

    async def _fake_start(self, start_url, *, headless=False):
        return _fake_recording_handle(start_url)

    async def _fake_finish(self, handle):
        return canned_steps

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.start", _fake_start)
    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.finish", _fake_finish)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    credential = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2-super-secret"},
        headers=admin["headers"],
    )
    credential_id = credential.json()["id"]

    started = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/start",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    recording_id = started.json()["recording_id"]
    finished = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/finish",
        headers=admin["headers"],
    )
    macro_id = finished.json()["id"]

    deleted = await client.delete(
        f"/versions/{version_id}/credentials/{credential_id}/macros/{macro_id}", headers=admin["headers"]
    )
    assert deleted.status_code == 204

    listed = await client.get(
        f"/versions/{version_id}/credentials/{credential_id}/macros", headers=admin["headers"]
    )
    assert listed.json() == []

    # Deleting the same macro again (or one that never existed) 404s,
    # doesn't silently succeed.
    again = await client.delete(
        f"/versions/{version_id}/credentials/{credential_id}/macros/{macro_id}", headers=admin["headers"]
    )
    assert again.status_code == 404


async def test_record_macro_start_404_for_unknown_credential(client, monkeypatch):
    async def _fake_start(self, start_url, *, headless=False):
        raise AssertionError("should not be called for a 404 credential")

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.start", _fake_start)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/credentials/00000000-0000-0000-0000-000000000000/record-macro/start",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    assert resp.status_code == 404


async def test_cancel_recording_discards_it_without_creating_a_macro(client, monkeypatch):
    async def _fake_start(self, start_url, *, headless=False):
        return _fake_recording_handle(start_url)

    cancel_called = []

    async def _fake_cancel(self, handle):
        cancel_called.append(handle)

    async def _fake_finish(self, handle):
        raise AssertionError("finish should not be called on a cancelled recording")

    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.start", _fake_start)
    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.cancel", _fake_cancel)
    monkeypatch.setattr("app.api.routes.credentials.MacroRecorder.finish", _fake_finish)

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    credential = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "Admin", "username": "alice", "secret": "hunter2-super-secret"},
        headers=admin["headers"],
    )
    credential_id = credential.json()["id"]

    started = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/start",
        json={"start_url": "https://site.test/login"},
        headers=admin["headers"],
    )
    recording_id = started.json()["recording_id"]

    cancelled = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/cancel",
        headers=admin["headers"],
    )
    assert cancelled.status_code == 204
    assert len(cancel_called) == 1

    listed = await client.get(
        f"/versions/{version_id}/credentials/{credential_id}/macros", headers=admin["headers"]
    )
    assert listed.json() == []

    # The recording_id is gone from the registry now — finishing it
    # afterward must 404, not resurrect it.
    finished = await client.post(
        f"/versions/{version_id}/credentials/{credential_id}/record-macro/{recording_id}/finish",
        headers=admin["headers"],
    )
    assert finished.status_code == 404


async def test_credential_login_endpoint_auto_derives_a_scope_entry(client):
    """Regression coverage for a real failure mode: an SSO-fronted app's
    login endpoint is very often a third-party IdP (Okta/Auth0/
    Microsoft), never the target application's own host. Without an
    auto-derived scope entry, app.agents.login.SessionManager.
    _login_explicit's POST to that endpoint hits ScopeViolationError on
    every real scan (and on the Test Login check) — explicitly typing a
    login endpoint is authorization to reach it, the same way adding a
    Target is authorization to crawl it."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "SSO User",
            "username": "user@example.test",
            "secret": "hunter2",
            "login_endpoint": "https://mycompany.okta.com/api/v1/authn",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text

    scope = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    entries = scope.json()
    assert any(e["host"] == "mycompany.okta.com" and e["in_scope"] is True for e in entries), entries
    # §5 scope-leak fix: tagged login_only, not target — every fuzzing
    # agent excludes it (app.agents.scope.filter_out_login_only) even
    # though it's technically in scope for the login POST itself.
    okta_entry = next(e for e in entries if e["host"] == "mycompany.okta.com")
    assert okta_entry["purpose"] == "login_only", okta_entry


async def test_adding_a_target_for_a_login_only_host_upgrades_it(client):
    """If the analyst later adds a real Target for the exact host+port a
    login-only entry was auto-derived for, that's stronger, more
    deliberate authorization than the login-only tag ever was — it
    should win, not stay silently excluded from fuzzing forever."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "SSO User",
            "username": "user@example.test",
            "secret": "hunter2",
            "login_endpoint": "https://idp.example.test/login",
        },
        headers=admin["headers"],
    )

    added = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "idp.example.test", "port": None, "base_url": "https://idp.example.test/"},
        headers=admin["headers"],
    )
    assert added.status_code == 201, added.text

    scope = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    entries = scope.json()
    idp_entries = [e for e in entries if e["host"] == "idp.example.test"]
    assert len(idp_entries) == 1, entries  # upgraded in place, not duplicated
    assert idp_entries[0]["purpose"] == "target", idp_entries[0]


async def test_updating_login_endpoint_auto_derives_a_scope_entry(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/credentials",
        json={"label": "User", "username": "u", "secret": "p"},
        headers=admin["headers"],
    )
    credential_id = created.json()["id"]

    updated = await client.patch(
        f"/versions/{version_id}/credentials/{credential_id}",
        json={"login_endpoint": "https://auth.example-idp.test/login"},
        headers=admin["headers"],
    )
    assert updated.status_code == 200, updated.text

    scope = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    entries = scope.json()
    assert any(e["host"] == "auth.example-idp.test" and e["in_scope"] is True for e in entries), entries
